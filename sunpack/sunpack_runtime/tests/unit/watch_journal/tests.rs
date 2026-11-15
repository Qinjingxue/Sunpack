use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sunpack_watch_journal_{label}_{nonce}.wal"))
}

fn empty_operations() -> JournalPayload {
    JournalPayload::Task(Arc::new(Operations::default()))
}

#[test]
fn journal_frontiers_do_not_revive_closed_streams() {
    let runtime = runtime();
    let stream = unique_path("flush_retire").to_string_lossy().into_owned();
    let owner = runtime.open(stream.clone()).unwrap();
    runtime.seed(&stream, 1).unwrap();
    let ticket = owner.request_flush(1).unwrap();
    owner.close().unwrap();

    assert!(runtime.request_flush(&ticket.stream, 1).is_err());
    assert!(runtime.seed(&stream, 1).is_err());
    assert!(!lock_state(&runtime.shared)
        .streams
        .contains_key(stream.as_str()));
    ticket.wait_for(TicketGoal::Durable).unwrap();
}

#[test]
fn global_flush_keeps_the_original_stream_outcome_after_retirement() {
    // Ticket tests do not cover the global flush snapshot. Coordinate the
    // retirement after admission without sleeps or real storage failures.
    let mut outcomes = Vec::new();
    for reopen in [false, true] {
        for failed in [false, true] {
            let shared = Arc::new(Shared::new());
            let (writer_tx, writer_rx) = mpsc::channel();
            let runtime = JournalRuntime {
                shared: shared.clone(),
                writer_tx,
            };
            let key: Arc<str> = "stream".into();
            lock_state(&shared).streams.insert(
                key.clone(),
                StreamState {
                    owners: 1,
                    written_seq: 1,
                    ..StreamState::new(key.clone())
                },
            );
            let flush = thread::spawn(move || runtime.flush_all());
            let WriterCommand::Barrier { done } = writer_rx.recv().unwrap() else {
                panic!("expected the flush barrier");
            };
            done.send(()).unwrap();

            let mut state = lock_state(&shared);
            while state.streams["stream"].requested_seq != 1 {
                state = shared.cv.wait(state).unwrap();
            }
            let stream = state.streams.get_mut("stream").unwrap();
            stream.owners = 0;
            if failed {
                stream.error = Some("old stream failed".to_string());
            } else {
                stream.durable_seq = 1;
            }
            retire_closed_stream(&mut state, "stream");
            if reopen {
                state.streams.insert(
                    key.clone(),
                    StreamState {
                        owners: 1,
                        written_seq: 1,
                        durable_seq: 1,
                        error: (!failed).then(|| "new stream failed".to_string()),
                        ..StreamState::new(key)
                    },
                );
            }
            shared.cv.notify_all();
            drop(state);
            outcomes.push((reopen, failed, flush.join().unwrap()));
        }
    }
    for (reopen, failed, result) in outcomes {
        let expected = if failed {
            Err("old stream failed".to_string())
        } else {
            Ok(())
        };
        assert_eq!(result, expected, "reopen={reopen}, failed={failed}");
    }
}

#[test]
fn clean_flush_does_not_issue_another_physical_sync() {
    let runtime = runtime();
    let path = unique_path("clean_flush");
    let next_path = unique_path("dirty_flush");
    let stream = path.to_string_lossy().to_string();
    let owner = runtime.open(stream.clone()).unwrap();
    let ticket = runtime
        .submit_append(owner.id(), path.clone(), 1, 1, empty_operations(), false)
        .unwrap();
    ticket.wait_for(TicketGoal::Written).unwrap();
    owner
        .request_flush(1)
        .unwrap()
        .wait_for(TicketGoal::Durable)
        .unwrap();
    let first = {
        let state = lock_state(&runtime.shared);
        state.streams.get(stream.as_str()).unwrap().flush_calls
    };
    owner
        .request_flush(1)
        .unwrap()
        .wait_for(TicketGoal::Durable)
        .unwrap();
    let second = {
        let state = lock_state(&runtime.shared);
        state.streams.get(stream.as_str()).unwrap().flush_calls
    };
    assert_eq!(first, second);
    runtime
        .submit_append(
            owner.id(),
            next_path.clone(),
            2,
            2,
            empty_operations(),
            true,
        )
        .unwrap()
        .wait_for(TicketGoal::Durable)
        .unwrap();
    let third = {
        let state = lock_state(&runtime.shared);
        state.streams.get(stream.as_str()).unwrap().flush_calls
    };
    assert_eq!(third, second + 1);
    owner.close().unwrap();
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(next_path);
}

#[test]
fn seal_waits_for_durable_boundary_and_releases_segment() {
    let runtime = runtime();
    let path = unique_path("seal");
    let stream = path.to_string_lossy().to_string();
    let owner = runtime.open(stream.clone()).unwrap();
    let append = runtime
        .submit_append(owner.id(), path.clone(), 1, 1, empty_operations(), false)
        .unwrap();
    append.wait_for(TicketGoal::Written).unwrap();
    let seal = runtime.submit_seal(owner.id(), path.clone(), 1, 1).unwrap();
    seal.wait_for(TicketGoal::Sealed).unwrap();
    let state = lock_state(&runtime.shared);
    let stream_state = state.streams.get(stream.as_str()).unwrap();
    assert!(stream_state.durable_seq >= 1);
    assert!(stream_state.sealed_seq >= 1);
    assert!(!stream_state.segments.contains_key(&1));
    drop(state);
    owner.close().unwrap();
    let _ = fs::remove_file(path);
}

#[test]
fn writer_batches_already_queued_appends_without_waiting() {
    let shared = Arc::new(Shared::new());
    let (tx, rx) = mpsc::channel();
    let path = unique_path("writer_batch");
    let stream: Arc<str> = path.to_string_lossy().as_ref().into();
    let stream_state = StreamState::new(stream.clone());
    let id = stream_state.id.clone();
    lock_state(&shared)
        .streams
        .insert(stream.clone(), stream_state);
    for seq in 1..=32u64 {
        tx.send(WriterCommand::Append(AppendWorkItem {
            stream: id.clone(),
            path: path.clone(),
            segment_start: 1,
            seq,
            operations: empty_operations(),
            durable: false,
            bytes_written: Arc::new(AtomicU64::new(0)),
        }))
        .unwrap();
    }
    drop(tx);
    writer_loop(shared.clone(), rx);

    let state = lock_state(&shared);
    let stream_state = state.streams.get(stream.as_ref()).unwrap();
    assert_eq!(stream_state.written_seq, 32);
    assert_eq!(stream_state.write_calls, 1);
    drop(state);
    let _ = fs::remove_file(path);
}
