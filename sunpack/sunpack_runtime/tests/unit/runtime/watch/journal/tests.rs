use super::*;
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const CRASH_READY: &str = "sunpack-journal-crash-ready";

fn wait_for_test_process_death() -> ! {
    println!("{CRASH_READY}");
    io::stdout().flush().unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    panic!("the parent must kill the journal owner without unwinding");
}

fn kill_test_journal_owner(test: &str, configure: impl FnOnce(&mut Command)) {
    let module = module_path!().split_once("::").unwrap().1;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", &format!("{module}::{test}"), "--include-ignored", "--nocapture"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    configure(&mut command);
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, ready) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        for line in io::BufReader::new(stdout).lines() {
            if line.unwrap().contains(CRASH_READY) {
                let _ = send.send(());
                return;
            }
        }
    });
    let reached = ready.recv_timeout(Duration::from_secs(30));
    // Kill on timeout too, so a failed boundary cannot strand an owner
    // or its exclusive state lock.
    let killed = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    reached.expect("journal child did not reach the requested crash boundary");
    killed.unwrap();
    assert!(!status.success());
}

#[test]
fn deferred_completion_submits_every_projection_before_waiting() {
    let marker = crate::test_support::temp_file("deferred_journal", b"");
    let dir = marker.with_extension("state");
    let journal = Journal::open(&dir, 7).unwrap();
    let (prepared, durable) = journal.defer_waits(|| {
        for generation in 1..=32 {
            journal.commit(generation % 2 == 1, |_| Ok(NativeWatchOperations::password_generation(
                generation, generation.to_string()))).unwrap();
            DEFERRED.with(|slot| assert_eq!(slot.borrow().as_ref().unwrap().1.len(), generation as usize));
        }
        assert_eq!(journal.state().password_generation(), 32);
        journal.frontier.lock().unwrap().seq
    });
    durable.unwrap();
    assert_eq!(prepared, 32);
    assert_eq!(
        journal.frontier.lock().unwrap().bytes + crate::wal::FILE_HEADER_BYTES,
        fs::metadata(segment_path(&dir, 1)).unwrap().len(),
    );
    assert!(DEFERRED.with(|slot| slot.borrow().is_none()));
    drop(journal);
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 32);
    drop(journal);
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_file(marker);
}

#[test]
fn rootless_shell_releases_receipts_and_replays_snapshot_and_wal() {
    use crate::watch_store::PendingObservation;
    let marker = crate::test_support::temp_file("rootless_journal", b"");
    let dir = marker.with_extension("state");
    let journal = Journal::open(&dir, 7).unwrap();
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(7, "saved".into()))).unwrap();
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    journal.flush().unwrap();
    assert!(dir.join("state.snapshot").exists());
    let paths: Vec<_> = (0..256).map(|index| dir.join(format!("{index}.zip")).to_string_lossy().into_owned()).collect();
    journal.commit(true, |state| Ok(state.pending_operations(paths.iter().map(|path|
        (PendingObservation(path.clone(), 1, 1.0, "id".into(), 1), "root".into(), None)),
        false, "root", true, None))).unwrap();
    let receipt = Arc::downgrade(&journal.state().pending(&paths[0]).unwrap());
    journal.frontier.lock().unwrap().fault = Some("unavailable WAL".into());
    assert!(journal.suspend().is_err());
    assert!(!journal.suspended() && receipt.upgrade().is_some());
    journal.frontier.lock().unwrap().fault = None;
    journal.suspend().unwrap();
    assert!(receipt.upgrade().is_none());
    assert!(journal.state().pending_items().is_empty());
    // The idle shell also gives up the current, unsealed WAL handle.
    drop(OpenOptions::new().read(true).share_mode(0).open(segment_path(&dir, 2)).unwrap());
    // Rootless diagnostics/maintenance never checkpoint the empty view over
    // the saved generation or append work captured by the former scheduler.
    journal.compact().unwrap();
    journal.flush().unwrap();
    journal.rebuild_log().unwrap();
    journal.commit(true, |_| panic!("rootless shell must not prepare state mutations")).unwrap();
    assert!(journal.resume().unwrap());
    assert_eq!(journal.state().pending_items().len(), paths.len());
    assert_eq!(journal.state().password_generation(), 7);
    journal.suspend().unwrap();
    drop(journal);
    let reopened = Journal::open(&dir, 7).unwrap();
    assert_eq!(reopened.state().pending_items().len(), paths.len());
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn configured_retention_applies_before_first_writer_pass() {
    use crate::io::display_store::{utc_us, Store, Manifest, DAY_US};
    let marker = crate::test_support::temp_file("configured_watch_retention", b"");
    let dir = marker.with_extension("state");
    fs::create_dir(&dir).unwrap();
    let path = dir.join("events.json");
    let old = utc_us() - 10 * DAY_US;
    {
        let mut store = Store::open(path.clone()).unwrap();
        let row = serde_json::json!({"event":"done", "path":"old.zip", "ts":old as f64 / 1_000_000.0});
        store.append(&crate::io::display_store::HistoryRecord::new(&row, old, &row).unwrap()).unwrap();
        store.publish().unwrap();
    }
    for (days, expected) in [(30, 1), (7, 0)] {
        let journal = Journal::open(&dir, days).unwrap();
        journal.flush().unwrap();
        let manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(manifest.runs.iter().map(|run| run.count - run.head).sum::<u64>(), expected);
        drop(journal);
    }
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

// Unlike dropping Journal, killing a separate owner cannot finish a
// checkpoint, flush the stream or run destructors on the way out. Cover
// the three durable representations with one coarse recovery scenario.
#[test]
fn hard_process_death_replays_checkpoint_and_retirement_boundaries() {
    const CHILD: &str = "SUNPACK_JOURNAL_CRASH_CHILD";
    const PHASE: &str = "SUNPACK_JOURNAL_CRASH_PHASE";
    if let Some(marker) = std::env::var_os(CHILD) {
        let marker = PathBuf::from(marker);
        let dir = marker.with_extension("state");
        let owned = marker.with_extension("owned");
        fs::create_dir(&owned).unwrap();
        let journal = Journal::open(&dir, 7).unwrap();
        journal.commit(true, |state| {
            let operations = NativeWatchOperations::password_generation(1, "one".into());
            let identity = crate::filesystem::directory_identity(owned.to_str().unwrap())?;
            state.register_output_paths(&[owned.to_string_lossy().into_owned()], &[&identity]);
            Ok(operations)
        }).unwrap();
        journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
        let phase = std::env::var(PHASE).unwrap();
        // Hold SHARE_DELETE closed only in the published/pre-retirement
        // case. Snapshot publication succeeds while its covered WAL stays.
        let _retained = (phase == "published").then(|| {
            OpenOptions::new().read(true).share_mode(3)
                .open(segment_path(&dir, 1)).unwrap()
        });
        if phase != "before_snapshot" {
            journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
            journal.compact().unwrap();
            journal.wait_for_checkpoint().unwrap();
            assert!(dir.join("state.snapshot").is_file());
            assert_eq!(segment_path(&dir, 1).exists(), phase == "published");
        } else {
            assert!(!dir.join("state.snapshot").exists());
        }
        // A tail after the captured prefix must survive both retained and
        // retired covered segments, rather than being discarded on open.
        journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(3, "three".into()))).unwrap();
        wait_for_test_process_death();
    }

    for phase in ["before_snapshot", "published", "retired"] {
        let marker = crate::test_support::temp_file("journal_process_death", b"generation");
        let dir = marker.with_extension("state");
        let owned = marker.with_extension("owned");
        kill_test_journal_owner("hard_process_death_replays_checkpoint_and_retirement_boundaries", |command| {
            command.env(CHILD, &marker).env(PHASE, phase);
        });
        for _ in 0..2 {
            let journal = Journal::open(&dir, 7).unwrap();
            assert_eq!(journal.state().password_generation(), 3, "{phase}");
            assert!(journal.state().active_output_keys().is_empty());
            let mut events = vec![owned.join("nested.zip")];
            journal.filter_owned_events(&mut events, &owned);
            assert_eq!(events.len(), 1, "temporary reservations must not survive their writer");
            if phase != "before_snapshot" {
                assert!(!segment_path(&dir, 1).exists());
            }
        }
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir(&owned).unwrap();
        fs::remove_file(marker).unwrap();
    }
}

#[test]
#[ignore = "requires the real sunpack_gui_tests.exe; run by GUI/runtime CI"]
fn cpp_query_recovers_durable_blocker_after_writer_death() {
    use crate::event_log::gui_contract::{gui_binary, project, Directory};
    use crate::watch_store::EntryRecord;
    use serde_json::json;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    const CHILD: &str = "SUNPACK_GUI_JOURNAL_CRASH_CHILD";
    let binary = gui_binary();
    if let Some(dir) = std::env::var_os(CHILD) {
        let dir = PathBuf::from(dir);
        let journal = Journal::open(&dir, 7).unwrap();
        let path = dir.join("events.json");
        let source = dir.join("disguised.bin");
        journal.log(json!({"event":"processing_started","path":dir.join("interrupted.zip"),"owner":"interrupted"}));
        journal.event_log().flush().unwrap();
        let live = project(&binary, &path, "", "", "", "");
        assert_eq!(live["total"], 3);
        assert!(live["rows"].as_array().unwrap().iter().any(|row| row["status"] == "taskProcessing"));

        // Freeze publication at the old manifest. The production commit
        // path still fsyncs its WAL when the display writer cannot publish.
        // Leave a staged history append on disk at the same time.
        let _held = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path).unwrap();
        journal.log(json!({"event":"done","path":dir.join("unpublished.zip"),"owner":"unpublished"}));
        journal.event_log().flush().unwrap_err();
        journal.commit(true, |_| {
            let mut operations = NativeWatchOperations::empty();
            operations.put_entry(Arc::new(EntryRecord {
                path: source.to_string_lossy().into_owned(),
                size: 1,
                mtime: 1.0,
                file_id: String::new(),
                change_usn: 0,
                status: "suspended_missing_volume".into(),
                last_error: String::new(),
                failure_kind: String::new(),
                failure_payload: Default::default(),
                last_attempt_at: crate::io::display_store::utc_us() as f64 / 1_000_000.0,
            }));
            Ok(operations)
        }).unwrap();
        wait_for_test_process_death();
    }

    let dir = Directory::new("gui_crash");
    let path = dir.0.join("events.json");
    let source = dir.0.join("disguised.bin");
    let member = dir.0.join("disguised.002");
    let journal = Journal::open(&dir.0, 7).unwrap();
    journal.log(json!({"event":"pipeline_sources_claimed","owner":"completed","processing":true,
        "groups":[{"path":source,"name":"retained.rar","members":[source,member]}]}));
    journal.log(json!({"event":"done","owner":"completed","path":source,"output_dirs":["previous-output"]}));
    journal.log(json!({"event":"failed_terminal","owner":"failed","path":dir.0.join("failed.zip")}));
    journal.event_log().flush().unwrap();
    drop(journal);
    let previous = project(&binary, &path, "", "", "", "");
    assert_eq!(previous["total"], 2);
    let completed = previous["rows"].as_array().unwrap().iter()
        .find(|row| row["status"] == "taskSucceeded").unwrap();
    assert_eq!(completed["name"], "disguised.bin");
    assert_eq!(completed["parts"], json!(["disguised.bin", "disguised.002"]));
    assert_eq!(completed["outputs"], json!(["previous-output"]));

    kill_test_journal_owner("cpp_query_recovers_durable_blocker_after_writer_death", |command| {
        command.env(CHILD, &dir.0);
    });
    let manifest: crate::io::display_store::Manifest =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let published_records: u64 = manifest.runs.iter().map(|run| run.count).sum();
    let history_index_bytes: u64 = fs::read_dir(dir.0.join("events.json.store"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("history-") && name.ends_with(".index")
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    assert_eq!(history_index_bytes,
        (published_records + 1) * crate::io::display_store::ENTRY_BYTES as u64);
    assert!(!dir.0.join("events.json.tmp").exists());

    let journal = Journal::open(&dir.0, 7).unwrap();
    journal.event_log().flush().unwrap();
    let restored = project(&binary, &path, "", "", "", "");
    assert_eq!(restored["total"], 3);
    let rows = restored["rows"].as_array().unwrap();
    for earlier in previous["rows"].as_array().unwrap() {
        assert!(rows.contains(earlier), "historical row changed across recovery: {earlier}");
    }
    let waiting = rows.iter().find(|row| row["status"] == "taskWaiting").unwrap();
    assert_eq!(waiting["path"], completed["path"]);
    assert_ne!(waiting["id"], completed["id"]);
    assert_eq!(waiting["statusText"], "等待分卷");
    drop(journal);
    assert!(!dir.0.join("events.json.tmp").exists());
    assert_eq!(project(&binary, &path, "", "", "", ""), restored);
}

// Exercises the durable writer and replay, not just error classification:
// an unavailable snapshot must not lose the sealed WAL or stop appends.
#[test]
fn snapshot_failure_keeps_wal_live_and_retries_above_old_size_limit() {
    let marker = crate::test_support::temp_file("snapshot_retry", b"");
    let dir = marker.with_extension("state");
    let journal = Journal::open(&dir, 7).unwrap();
    let temp = dir.join("state.snapshot.tmp");
    fs::create_dir(&temp).unwrap(); // Fail only snapshot creation, not WAL.
    // Inject the size accounting to exercise the same checkpoint path
    // without allocating, syncing and replaying hundreds of MiB in the test.
    let old_size_limit = 256 * 1024 * 1024;
    journal.frontier.lock().unwrap().bytes = old_size_limit;
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(1, "one".into()))).unwrap();
    journal.wait_for_checkpoint().unwrap();
    assert!(!dir.join("state.snapshot").exists());
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
    journal.flush().unwrap();
    assert_eq!(journal.state().password_generation(), 2);
    assert!(journal.frontier.lock().unwrap().bytes > old_size_limit);
    assert!(!segments(&dir).unwrap().is_empty());
    drop(journal);
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 2);
    fs::remove_dir(&temp).unwrap();
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    // Retry without another append: its current segment starts *after*
    // the snapshot boundary and must not be retired if a writer opens it.
    journal.compact().unwrap();
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(3, "three".into()))).unwrap();
    journal.flush().unwrap();
    assert!(dir.join("state.snapshot").is_file());
    drop(journal);
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 3);
    // Snapshot failures are recoverable; a WAL seal error still poisons
    // persistence and must prevent further mutations.
    let failed = Checkpoint { records: 0, bytes: 0, ready: Arc::new(AtomicBool::new(true)),
        job: thread::spawn(|| Err(io::Error::other("WAL seal failed"))) };
    assert!(journal.harvest_checkpoint(Some(failed)).is_err());
    assert!(journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(4, "four".into()))).is_err());
    drop(journal);
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn retirement_retries_without_republishing_or_polling_and_on_open() {
    use std::sync::atomic::AtomicUsize;
    let marker = crate::test_support::temp_file("retirement_retry", b"");
    let dir = marker.with_extension("state");
    let journal = Journal::open(&dir, 7).unwrap();
    let notifications = Arc::new(AtomicUsize::new(0));
    let notified = Arc::clone(&notifications);
    journal.set_maintenance(Arc::new(move || { notified.fetch_add(1, Ordering::Relaxed); }));
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(1, "one".into()))).unwrap();
    let wal = segment_path(&dir, 1);
    let reader = OpenOptions::new().read(true).share_mode(3).open(&wal).unwrap();
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    journal.compact().unwrap();
    journal.wait_for_checkpoint().unwrap();
    assert_eq!(notifications.load(Ordering::Relaxed), 1);
    assert_eq!(journal.frontier.lock().unwrap().retirement, Some(1));
    let snapshot = fs::read(dir.join("state.snapshot")).unwrap();
    // The idle retry cannot schedule another idle retry while still locked.
    journal.compact().unwrap();
    journal.wait_for_checkpoint().unwrap();
    assert_eq!(notifications.load(Ordering::Relaxed), 1);
    drop(reader);
    journal.compact().unwrap();
    journal.wait_for_checkpoint().unwrap();
    assert!(!wal.exists());
    assert_eq!(notifications.load(Ordering::Relaxed), 2);
    assert!(journal.frontier.lock().unwrap().retirement.is_none());
    assert_eq!(fs::read(dir.join("state.snapshot")).unwrap(), snapshot);
    // Leave another covered segment locked through shutdown. Opening the
    // store after the lock is gone must retire it without another append.
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
    let wal = segment_path(&dir, 2);
    let reader = OpenOptions::new().read(true).share_mode(3).open(&wal).unwrap();
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    journal.compact().unwrap();
    journal.wait_for_checkpoint().unwrap();
    drop(journal);
    drop(reader);
    let stale_snapshot = dir.join(SNAPSHOT_TEMP_NAME);
    fs::write(&stale_snapshot, b"incomplete snapshot").unwrap();
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 2);
    assert!(!wal.exists());
    assert!(!stale_snapshot.exists());
    drop(journal);
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn display_flush_failure_does_not_replace_durable_journal_result() {
    let marker = crate::test_support::temp_file("display_flush", b"");
    let dir = marker.with_extension("state");
    let journal = Journal::open(&dir, 7).unwrap();
    journal.flush().unwrap();
    // A directory at the manifest path causes a terminal display error,
    // unlike a sharing handle that atomic publication waits to release.
    // The WAL and snapshot paths remain writable.
    let manifest = dir.join("events.json");
    let saved = dir.join("events.saved");
    fs::rename(&manifest, &saved).unwrap();
    fs::create_dir(&manifest).unwrap();
    journal.log(serde_json::json!({"event":"service_reload_skipped","reason":"test"}));
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
    assert!(journal.flush().is_ok());
    assert!(journal.log.error().is_some());
    // A persistence fault must still fail the same public flush boundary.
    journal.frontier.lock().unwrap().fault = Some("durability fault".into());
    assert!(journal.flush().unwrap_err().to_string().contains("durability fault"));
    journal.frontier.lock().unwrap().fault = None;
    fs::remove_dir(&manifest).unwrap();
    fs::rename(&saved, &manifest).unwrap();
    journal.flush().unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 2);
    drop(journal);
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn snapshot_sharing_conflict_does_not_hold_flush_or_shutdown() {
    use std::sync::{mpsc, Arc};
    use std::time::Duration;
    let marker = crate::test_support::temp_file("snapshot_sharing", b"");
    let dir = marker.with_extension("state");
    let journal = Arc::new(Journal::open(&dir, 7).unwrap());
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(1, "one".into()))).unwrap();
    journal.flush().unwrap();
    // FILE_SHARE_READ | FILE_SHARE_WRITE, deliberately no SHARE_DELETE.
    let reader = OpenOptions::new().read(true).share_mode(3)
        .open(dir.join("state.snapshot")).unwrap();
    journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
    journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
    let worker_journal = Arc::clone(&journal);
    let (send, receive) = mpsc::channel();
    let worker = thread::spawn(move || { send.send(worker_journal.flush()).unwrap(); });
    let result = receive.recv_timeout(Duration::from_secs(5));
    // Always release before joining, including when the old infinite retry
    // implementation is tested, so a failed assertion cannot hang tests.
    drop(reader);
    worker.join().unwrap();
    assert!(result.expect("flush waited for an external snapshot handle").is_ok());
    journal.flush().unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 7).unwrap();
    assert_eq!(journal.state().password_generation(), 2);
    drop(journal);
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn observer_filter_waits_for_output_publication_without_advancing_the_journal() {
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    let marker = crate::test_support::temp_file("owned_publication", b"");
    let directory = marker.with_extension("watch");
    let alias = marker.with_extension("junction");
    let output = alias.join("output");
    let physical = directory.join("output");
    let state_directory = marker.with_extension("state");
    fs::create_dir_all(&directory).unwrap();
    let junction = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&alias).arg(&directory).output().unwrap();
    assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stderr));
    let journal = Arc::new(Journal::open(&state_directory, 7).unwrap());
    let (start, ready) = mpsc::sync_channel(1);
    let (attempt, entered) = mpsc::sync_channel(1);
    let (finish, filtered) = mpsc::sync_channel(1);
    let reader = Arc::clone(&journal);
    let observed = physical.clone();
    let literal = output.clone();
    let boundary = directory.clone();
    let worker = thread::spawn(move || {
        ready.recv().unwrap();
        attempt.send(()).unwrap();
        let mut paths = vec![boundary.clone(), observed.clone(), observed.join("generated.zip"),
            literal.clone(), literal.join("generated.zip")];
        reader.filter_owned_events(&mut paths, &boundary);
        finish.send(paths).unwrap();
    });
    journal.commit(true, |_| {
        crate::scan::scope::create_output_root_exclusive(&output)?;
        start.send(()).unwrap();
        entered.recv().unwrap();
        assert_eq!(filtered.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout));
        let identity = crate::filesystem::directory_identity(output.to_str().unwrap())?;
        journal.state().register_output_paths(&crate::path_keys::output_path_aliases(&output)?, &[&identity]);
        Ok(NativeWatchOperations::empty())
    }).unwrap();
    assert_eq!(filtered.recv_timeout(Duration::from_secs(5)).unwrap(), vec![directory.clone()]);
    worker.join().unwrap();
    assert!(journal.state().watch_cursors().is_empty());
    drop(journal);
    let journal = Journal::open(&state_directory, 7).unwrap();
    let mut paths = vec![output.join("nested.blob"), physical.join("nested.blob")];
    journal.filter_owned_events(&mut paths, &directory);
    assert_eq!(paths.len(), 2);
    assert!(journal.state().active_output_keys().is_empty());
    assert!(journal.state().watch_cursors().is_empty());
    drop(journal);
    fs::remove_dir(alias).unwrap();
    fs::remove_dir_all(directory).unwrap();
    fs::remove_dir_all(state_directory).unwrap();
    fs::remove_file(marker).unwrap();
}

#[test]
fn checkpoint_replays_append_after_the_sealed_prefix() {
    let marker = crate::test_support::temp_file("active_watch_checkpoint", b"");
    let dir = marker.with_extension("state");
    {
        let journal = Journal::open(&dir, 7).unwrap();
        // Position just below the threshold without doing thousands of
        // unrelated writes. Every subsequent record uses the real writer.
        journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS - 2;
        for generation in 1..=3 {
            journal
                .commit(true, |_| {
                    let operations = NativeWatchOperations::password_generation(
                        generation,
                        generation.to_string(),
                    );
                    Ok(operations)
                })
                .unwrap();
        }
        journal.flush().unwrap();
    }
    let segments = segments(&dir).unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].0, 3);
    {
        let journal = Journal::open(&dir, 7).unwrap();
        assert_eq!(journal.state().password_generation(), 3);
    }
    fs::remove_dir_all(dir).unwrap();
    fs::remove_file(marker).unwrap();
}
