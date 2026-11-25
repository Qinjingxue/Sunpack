use super::*;

#[test]
fn replayed_entry_event_keeps_business_failure_kind_and_message() {
    let entry = EntryRecord {
        path: r"C:\input\archive.zip".into(),
        status: "failed_retryable".into(),
        failure_kind: "wrong_password".into(),
        last_error: format!("{}末尾诊断", "密码不在密码列表中".repeat(512)),
        size: 0, mtime: 0.0, file_id: String::new(), change_usn: 0,
        failure_payload: Map::new(), layout_checked_at: 0, last_attempt_at: 0.0
    };
    let event = entry_event(&entry);
    assert_eq!(event["error_kind"], "wrong_password");
    assert_eq!(event["error"], entry.last_error);
}

#[test]
fn finish_binds_the_directory_that_survives_an_earlier_attempt() {
    use std::fs;

    let marker = crate::test_support::temp_file("output_identity_reuse", b"");
    let base = marker.with_extension("outputs");
    let output = base.join("item");
    let old = base.join("previous");
    let owner = base.join("item.zip").to_string_lossy().into_owned();
    let path = output.to_string_lossy().into_owned();
    fs::create_dir_all(&base).unwrap();

    let state = NativeWatchState::new();
    let pending = PendingRecord { path: owner.clone(), ..Default::default() };
    state.apply(&NativeWatchOperations(vec![Operation::PutPending(path_key(&owner), Arc::new(pending))]));
    let started = state.output_operation(&owner, owner.clone(), path.clone(), None, true).unwrap().unwrap();
    state.apply(&started);
    let registered = state.pending(&owner).unwrap().output_identities[&path].clone();

    // Keep the first object alive so even immediate NTFS ID reuse cannot
    // disguise a second attempt that materializes the same output name.
    fs::rename(&output, &old).unwrap();
    fs::create_dir(&output).unwrap();
    let current = crate::filesystem::directory_identity(&path).unwrap();
    assert_ne!(registered, current);
    let completed = state.output_operation(&owner, owner.clone(), path.clone(), Some(true), false)
        .unwrap().unwrap();
    assert_eq!(completed.finished_output_identity(), Some(current.as_str()));
    state.apply(&completed);
    assert_eq!(state.pending(&owner).unwrap().output_identities[&path], current);

    fs::remove_dir(&output).unwrap();
    fs::remove_dir(&old).unwrap();
    fs::remove_dir(&base).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn carrier_outputs_survive_snapshot_and_incremental_replay() {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let snapshot = crate::test_support::temp_file("carrier_owner_snapshot", b"");
    fs::remove_file(&snapshot).unwrap();
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
    state.apply(&NativeWatchOperations(vec![Operation::PutPending(path_key(&owner), Arc::new(pending))]));
    assert!(state.pending(&owner).unwrap().active_outputs.contains(&task, &container));
    fs::write(&journal, wal::file_header(Kind::TaskWal)).unwrap();
    let append = |seq, changes: Vec<OutputChange>| {
        let operations = NativeWatchOperations(changes.into_iter()
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
    state.capture(2).write(&snapshot).unwrap();
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
        source: container.clone(), leaf: container.clone(), destination: moved.clone(), identity: "moved-id".into(),
    }]);
    resumed.replay_segment(journal.to_string_lossy().into_owned(), 3, 4).unwrap();
    let pending = resumed.pending(&owner).unwrap();
    assert_eq!(pending.active_outputs.iter().collect::<Vec<_>>(), vec![(&task, &moved)]);
    assert!(pending.committed_roots.contains(&moved));
    assert_eq!(pending.output_identities[&moved], "moved-id");
    assert!(!pending.output_identities.contains_key(&second));
    drop(pending);
    let mut operations = NativeWatchOperations::empty();
    operations.finish_pending(&owner, None);
    resumed.apply(&operations);
    assert_eq!(resumed.lock().pending.capacity(), 0);
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
            "last_error":"locked", "failure_kind":"", "failure_payload":{}, "last_attempt_at":1.0
        }))
        .unwrap();
        let key = path_key(&record.path);
        state.apply(&NativeWatchOperations(vec![Operation::PutEntry(
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
            worker_state.apply(&NativeWatchOperations(vec![operation]));
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
                assert_eq!(state.lock().entries.capacity(), 0);
            } else {
                assert_eq!(rows[0]["event"], "suspended_missing_volume");
            }
        });
    }
}

#[test]
fn missing_volume_retry_gate_follows_entry_replacement_removal_and_snapshot() {
    let state = NativeWatchState::new();
    let path = r"C:\input\archive.bin";
    let record = |path: &str, status: &str, size| Arc::new(EntryRecord {
        path: path.into(), status: status.into(), size, mtime: 1.0, file_id: String::new(),
        change_usn: 0, last_error: String::new(), failure_kind: String::new(),
        failure_payload: Map::new(), layout_checked_at: 0, last_attempt_at: 1.0,
    });
    let set = |path, status, size| {
        let record = record(path, status, size);
        let mut operations = NativeWatchOperations::empty();
        operations.put_entry(Arc::clone(&record));
        state.apply(&operations);
        record
    };
    set(path, "failed_password", 1);
    assert!(!state.has_volume_waiters());
    let first = set(path, "suspended_missing_volume", 1);
    let key = path_key(path);
    state.record_volume_check(key.clone(), &first, 1, None);
    let refreshed = set(path, "suspended_missing_volume", 1);
    assert!(!state.volume_check_needed(&key, &refreshed, 1, false));
    assert!(state.volume_check_needed(&key, &refreshed, 2, false));
    assert!(state.has_volume_waiters());

    let snapshot = crate::test_support::temp_file("missing_volume_retry_gate", b"");
    let mut damaged = (*record(r"C:\input\multipart.bin", "failed_terminal", 3)).clone();
    damaged.failure_payload.insert("source_group".into(), serde_json::json!({"multipart":true}));
    damaged.layout_checked_at = 42;
    let mut operations = NativeWatchOperations::empty();
    operations.put_entry(Arc::new(damaged));
    state.apply(&operations);
    state.capture(1).write(&snapshot).unwrap();
    let resumed = NativeWatchState::new();
    resumed.load_snapshot(snapshot.to_string_lossy().into_owned()).unwrap();
    assert!(resumed.has_volume_waiters());
    assert!(resumed.volume_check_needed(&key, &resumed.entry(path).unwrap(), 1, false));
    resumed.apply(&NativeWatchOperations::retire_entries([path_key(path)]));
    let restored = resumed.entry(r"C:\input\multipart.bin").unwrap();
    assert!(restored.waits_for_volume());
    assert_eq!(restored.layout_checked_at, 0);
    resumed.apply(&NativeWatchOperations::retire_entries([path_key(&restored.path)]));
    state.apply(&NativeWatchOperations::retire_entries([path_key(&restored.path)]));
    assert!(!resumed.has_volume_waiters());

    let other = set(r"C:\input\other.bin", "suspended_missing_volume", 1);
    let other_key = path_key(&other.path);
    state.record_volume_check(other_key.clone(), &other, 1, None);
    let replaced = set(path, "suspended_missing_volume", 2);
    // A lookup finishing for an older entry cannot mark the replacement checked.
    state.record_volume_check(key.clone(), &refreshed, 1, None);
    assert!(state.volume_check_needed(&key, &replaced, 1, false));
    state.record_volume_check(key.clone(), &replaced, 1, None);
    state.apply(&NativeWatchOperations::retire_entries([key.clone()]));
    assert!(!state.lock().volume_checks.contains_key(&key));
    assert!(!state.volume_check_needed(&other_key, &other, 1, false));
    set(&other.path, "failed_password", 1);
    assert!(!state.has_volume_waiters());
    assert!(state.lock().volume_checks.is_empty());
    std::fs::remove_file(snapshot).unwrap();
}

#[test]
fn path_under_requires_a_component_boundary() {
    assert!(is_path_under("c:\\a\\b", "c:\\a"));
    assert!(is_path_under("c:\\a\\b", "c:\\a\\"));
    assert!(!is_path_under("c:\\ab", "c:\\a"));
    assert!(!is_path_under("c:\\a", "c:\\a"));
    assert!(is_path_under("c:\\a", "c:\\"));
}
