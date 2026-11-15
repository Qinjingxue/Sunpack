use super::*;

#[test]
fn replayed_entry_event_keeps_business_failure_kind_and_message() {
    let entry = EntryRecord {
        path: r"C:\input\archive.zip".into(),
        status: "failed_retryable".into(),
        failure_kind: "wrong_password".into(),
        last_error: format!("{}末尾诊断", "密码不在密码列表中".repeat(512)),
        size: 0, mtime: 0.0, file_id: String::new(), change_usn: 0,
        attempt_count: 1, failure_stage: String::new(),
        failure_payload: Map::new(), last_attempt_at: 0.0
    };
    let event = entry_event(&entry);
    assert_eq!(event["error_kind"], "wrong_password");
    assert_eq!(event["error"], entry.last_error);
}

#[test]
fn carrier_outputs_survive_snapshot_and_incremental_replay() {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let snapshot = crate::test_support::temp_file("carrier_owner_snapshot", b"");
    let journal = snapshot.with_extension("wal");
    let base = snapshot.with_extension("outputs");
    let owner = base.join("outer.zip").to_string_lossy().into_owned();
    let task = base.join("nested.data").to_string_lossy().into_owned();
    let container = base.join("carrier").to_string_lossy().into_owned();
    let first = base.join("carrier").join("first").to_string_lossy().into_owned();
    let second = base.join("carrier").join("second").to_string_lossy().into_owned();
    let moved = base.join("relocated").to_string_lossy().into_owned();
    let mut pending = PendingRecord { path: owner.clone(), ..Default::default() };
    pending.change_output(&OutputChange::Start {
        task: task.clone(),
        output: container.clone(),
        identity: "container-id".into(),
    });
    let state = NativeWatchState::new();
    state.apply(&NativeWatchOperations {
        operations: Arc::new(Operations(vec![Operation::PutPending(path_key(&owner), Arc::new(pending))])),
    });
    assert!(state.pending(&owner).unwrap().active_outputs.contains(&task, &container));
    fs::write(&journal, wal::file_header(Kind::TaskWal)).unwrap();
    let append = |seq, changes: Vec<OutputChange>| {
        let operations = Operations(changes.into_iter()
            .map(|change| Operation::Output(path_key(&owner), change)).collect());
        let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
        wal::append_frame(&mut file, &mut Vec::new(), seq, |out| {
            rmp_serde::encode::write(out, &operations).map_err(wal::invalid)
        }).unwrap();
        file.flush().unwrap();
    };
    append(2, vec![
        OutputChange::Start { task: task.clone(), output: first.clone(), identity: "first-id".into() },
        OutputChange::Start { task: task.clone(), output: second.clone(), identity: "second-id".into() },
    ]);
    state.replay_segment(journal.to_string_lossy().into_owned(), 1, 2).unwrap();
    assert_eq!(state.pending(&owner).unwrap().active_outputs.values().count(), 3);
    state.capture(2).write(snapshot.to_string_lossy().into_owned()).unwrap();
    let resumed = NativeWatchState::new();
    assert_eq!(resumed.load_snapshot(snapshot.to_string_lossy().into_owned()).unwrap(), 2);
    assert_eq!(resumed.pending(&owner).unwrap().active_outputs.values().count(), 3);
    append(3, vec![OutputChange::Finish {
        task: task.clone(), output: first.clone(), keep: true, identity: None,
    }]);
    resumed.replay_segment(journal.to_string_lossy().into_owned(), 2, 3).unwrap();
    let pending = resumed.pending(&owner).unwrap();
    assert!(pending.active_outputs.contains(&task, &container));
    assert!(pending.active_outputs.contains(&task, &second));
    assert!(!pending.active_outputs.contains(&task, &first));
    assert!(pending.committed_roots.contains(&container));
    assert!(!pending.completed_sources.contains(&task));
    assert_eq!(pending.output_identities[&container], "container-id");
    // Recovery preserves the carrier holding the committed first segment,
    // but the unfinished sibling remains an independently disposable root.
    assert_eq!(pending.active_outputs.values()
        .filter(|output| !pending.committed_roots.contains(output)).collect::<Vec<_>>(), vec![&second]);
    // Rollback may still discard the committed child after its active
    // reservation is retired. It must preserve the enclosing carrier.
    let rollback = resumed.output_operation(&owner, task.clone(), first.clone(), Some(false), false)
        .unwrap().unwrap();
    resumed.apply(&rollback);
    assert!(resumed.pending(&owner).unwrap().committed_roots.contains(&container));
    append(4, vec![OutputChange::Finish {
        task: task.clone(), output: second.clone(), keep: false, identity: None,
    }, OutputChange::Relocate {
        source: container.clone(), destination: moved.clone(), identity: "moved-id".into(),
    }]);
    resumed.replay_segment(journal.to_string_lossy().into_owned(), 3, 4).unwrap();
    let pending = resumed.pending(&owner).unwrap();
    assert_eq!(pending.active_outputs.iter().collect::<Vec<_>>(), vec![(&task, &moved)]);
    assert!(pending.committed_roots.contains(&moved));
    assert_eq!(pending.output_identities[&moved], "moved-id");
    assert!(!pending.output_identities.contains_key(&second));
    fs::remove_file(snapshot).unwrap();
    fs::remove_file(journal).unwrap();
}

#[test]
fn recovery_publication_orders_concurrent_blocker_changes() {
    // Python-thread tests retain the GIL across native recover, masking the
    // actual native publication gap. Exercise deletion and status change
    // from a real native thread while the snapshot callback is paused.
    for delete in [true, false] {
        let state = Arc::new(NativeWatchState::new());
        let record: EntryRecord = serde_json::from_value(serde_json::json!({
            "path":"c:\\input\\opaque.001", "size":1, "mtime":1.0,
            "file_id":"", "change_usn":0, "status":"failed_password",
            "last_error":"locked", "attempt_count":1, "failure_kind":"",
            "failure_stage":"", "failure_payload":{}, "last_attempt_at":1.0
        }))
        .unwrap();
        let key = path_key(&record.path);
        state.apply_operations(&Operations(vec![Operation::PutEntry(
            key.clone(),
            Arc::new(record.clone()),
        )]));
        let (captured, start) = std::sync::mpsc::channel();
        let (finished, done) = std::sync::mpsc::channel();
        let worker_state = state.clone();
        let worker = std::thread::spawn(move || {
            start.recv().unwrap();
            let operation = if delete {
                Operation::Delete(Collection::Entries, key)
            } else {
                let mut record = record;
                record.status = "suspended_missing_volume".into();
                Operation::PutEntry(key, Arc::new(record))
            };
            worker_state.apply_operations(&Operations(vec![operation]));
            finished.send(()).unwrap();
        });
        state.with_event_projection(|rows| {
            assert_eq!(rows[0]["event"], "failed_password");
            captured.send(()).unwrap();
            assert_eq!(
                done.recv_timeout(std::time::Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            );
        });
        done.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        worker.join().unwrap();
        state.with_event_projection(|rows| {
            if delete {
                assert!(rows.is_empty());
            } else {
                assert_eq!(rows[0]["event"], "suspended_missing_volume");
            }
        });
    }
}

#[test]
fn path_under_requires_a_component_boundary() {
    assert!(is_path_under("c:\\a\\b", "c:\\a"));
    assert!(is_path_under("c:\\a\\b", "c:\\a\\"));
    assert!(!is_path_under("c:\\ab", "c:\\a"));
    assert!(!is_path_under("c:\\a", "c:\\a"));
    assert!(is_path_under("c:\\a", "c:\\"));
}
