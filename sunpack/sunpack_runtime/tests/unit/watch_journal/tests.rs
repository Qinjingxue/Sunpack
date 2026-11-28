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
    JournalPayload::Task(Arc::new(NativeWatchOperations::empty()))
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
fn retired_flush_tickets_keep_the_original_outcome_after_reopen() {
    for failed in [false, true] {
        let shared = Arc::new(Shared::new());
        let key: Arc<str> = "stream".into();
        let mut old = StreamState::new(Arc::clone(&key));
        let ticket = NativeJournalTicket::new(Arc::clone(&shared), Arc::clone(&old.id), 1, TicketGoal::Durable);
        old.frontier = StreamFrontier {
            written_seq: 1,
            written_bytes: 37,
            durable_seq: u64::from(!failed),
            error: failed.then(|| "old stream failed".into()),
            ..Default::default()
        };
        let mut state = lock_state(&shared);
        state.streams.insert(Arc::clone(&key), old);
        retire_closed_stream(&mut state, &key);
        let mut next = StreamState::new(Arc::clone(&key));
        next.frontier = StreamFrontier {
            written_seq: 1,
            written_bytes: 51,
            durable_seq: 1,
            error: (!failed).then(|| "new stream failed".into()),
            ..Default::default()
        };
        state.streams.insert(key, next);
        drop(state);
        assert_eq!(ticket.wait_for(TicketGoal::Durable),
            if failed { Err("old stream failed".into()) } else { Ok(37) });
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
    assert!(stream_state.frontier.durable_seq >= 1);
    assert!(stream_state.frontier.sealed_seq >= 1);
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
            bytes_written: None,
        }))
        .unwrap();
    }
    drop(tx);
    writer_loop(shared.clone(), rx);

    let state = lock_state(&shared);
    let stream_state = state.streams.get(stream.as_ref()).unwrap();
    assert_eq!(stream_state.frontier.written_seq, 32);
    assert_eq!(stream_state.frontier.written_bytes, fs::metadata(&path).unwrap().len() - wal::FILE_HEADER_BYTES);
    assert_eq!(stream_state.write_calls, 1);
    drop(state);
    let _ = fs::remove_file(path);
}
