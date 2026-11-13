use super::key;
use crate::event_log::NativeEventLog;
use crate::watch_journal::{
    watch_journal_open, watch_journal_request_flush, watch_journal_seed,
    watch_journal_submit_append, watch_journal_submit_seal, NativeJournalStream,
};
use crate::watch_store::{NativeWatchOperations, NativeWatchState};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

const CHECKPOINT_RECORDS: u64 = 8192;
const CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;
const JOURNAL_HARD_BYTES: u64 = 256 * 1024 * 1024;

struct Frontier {
    seq: u64,
    segment: u64,
    records: u64,
    bytes: u64,
    fault: Option<String>,
    checkpoint_error: Option<String>,
    retirement: Option<u64>,
}

impl Frontier {
    fn needs_checkpoint(&self) -> bool {
        self.records >= CHECKPOINT_RECORDS || self.bytes >= CHECKPOINT_BYTES
    }
}

enum CheckpointResult {
    Published { retirement: Option<u64> },
    SnapshotFailed(io::Error),
}

struct Checkpoint {
    job: JoinHandle<io::Result<CheckpointResult>>,
    records: u64,
    bytes: u64,
    ready: Arc<AtomicBool>,
}

pub(super) struct Journal {
    state: NativeWatchState,
    log: NativeEventLog,
    frontier: Mutex<Frontier>,
    checkpoint: Mutex<Option<Checkpoint>>,
    maintenance: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    snapshot: PathBuf,
    stream_id: String,
    _stream: NativeJournalStream,
    _lock: File,
}

impl Journal {
    pub(super) fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(dir.join("state.runtime.lock"))?;
        let snapshot = dir.join("state.snapshot");
        let state = NativeWatchState::new();
        let checkpoint = match state.load_snapshot(snapshot.to_string_lossy().into_owned()) {
            Ok(checkpoint) => checkpoint,
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        let mut frontier = Frontier {
            seq: checkpoint,
            segment: checkpoint + 1,
            records: 0,
            bytes: 0,
            fault: None,
            checkpoint_error: None,
            retirement: None,
        };
        let mut tail = None;
        let mut retirement_boundary = checkpoint;
        for (start, path) in segments(dir)? {
            let replay = state.replay_segment(
                path.to_string_lossy().into_owned(),
                checkpoint,
                frontier.seq + 1,
            )?;
            if replay.records != 0 {
                retirement_boundary = retirement_boundary.min(start.saturating_sub(1));
                frontier.seq = replay.applied_seq;
                frontier.records += replay.records;
                frontier.bytes += replay.bytes;
            }
            tail = Some((start, path, replay.records, replay.valid_bytes));
        }
        if let Some((start, path, records, valid_bytes)) = tail {
            if records != 0 || start == frontier.seq + 1 {
                NativeWatchState::truncate_journal_tail(
                    path.to_string_lossy().into_owned(),
                    valid_bytes,
                )?;
                frontier.segment = start;
            }
        }
        if retire_segments(dir, retirement_boundary) {
            frontier.retirement = Some(retirement_boundary);
        }
        let stream_id = key(&snapshot);
        let stream = watch_journal_open(stream_id.clone())?;
        watch_journal_seed(&stream_id, frontier.seq)?;
        let log = NativeEventLog::new(dir.join("events.json"), 7, true)?;
        state.attach_events(&log)?;
        log.recover(Some(&state))?;
        Ok(Self {
            state,
            log,
            frontier: Mutex::new(frontier),
            checkpoint: Mutex::default(),
            maintenance: Mutex::default(),
            snapshot,
            stream_id,
            _stream: stream,
            _lock: lock,
        })
    }

    pub(super) fn set_maintenance(&self, notify: Arc<dyn Fn() + Send + Sync>) {
        *self.maintenance.lock().unwrap() = Some(notify);
    }

    pub(super) fn state(&self) -> &NativeWatchState {
        &self.state
    }

    pub(super) fn log(&self, value: Value) {
        if self.log.write(value).is_err() {
            let _ = self.rebuild_log();
        }
    }

    pub(super) fn rebuild_log(&self) -> io::Result<bool> {
        self.log.rebuild()?;
        self.log.recover(Some(&self.state))?;
        self.log.flush()?;
        Ok(self.log.error()?.is_none())
    }

    pub(super) fn set_retention(&self, days: u64) -> io::Result<()> {
        self.log
            .configure_retention(days.min(u32::MAX.into()) as u32)
    }

    pub(super) fn commit(
        &self,
        durable: bool,
        prepare: impl FnOnce(&NativeWatchState) -> io::Result<NativeWatchOperations>,
    ) -> io::Result<()> {
        let ticket = {
            let mut frontier = self.frontier.lock().unwrap();
            ensure_healthy(&frontier)?;
            let operations = prepare(&self.state)?;
            if operations.__len__() == 0 {
                return Ok(());
            }
            let seq = frontier
                .seq
                .checked_add(1)
                .ok_or(io::ErrorKind::InvalidData)?;
            let segment = frontier.segment;
            let ticket = watch_journal_submit_append(
                self.stream_id.clone(),
                segment_path(self.snapshot.parent().unwrap(), segment)
                    .to_string_lossy()
                    .into_owned(),
                segment,
                seq,
                &operations,
                durable,
            )?;
            self.state.apply(&operations);
            frontier.seq = seq;
            frontier.records += 1;
            ticket
        };
        // Other batches can enqueue their mutations during this disk wait.
        // The existing writer combines ready durability barriers.
        let result = if durable {
            ticket.wait()
        } else {
            ticket.wait_written()
        };
        let mut frontier = self.frontier.lock().unwrap();
        if let Err(error) = result {
            frontier.fault.get_or_insert_with(|| error.to_string());
            return Err(error);
        }
        // Count all uncheckpointed WAL, including a segment sealed while
        // this caller was awaiting its append. A failed snapshot retires none.
        frontier.bytes = frontier.bytes.saturating_add(ticket.bytes_written());
        ensure_healthy(&frontier)?;
        let needs_checkpoint = frontier.needs_checkpoint();
        drop(frontier);
        if needs_checkpoint {
            self.compact()?;
        }
        Ok(())
    }

    /// Use the existing publication gate without emitting a WAL record or
    /// advancing a cursor. An output's mkdir and durable registration cannot
    /// be observed halfway through by a directory-notification callback.
    pub(super) fn filter_owned_events(&self, paths: &mut Vec<PathBuf>, boundary: &Path) {
        let records = {
            let frontier = self.frontier.lock().unwrap();
            if frontier.fault.is_some() { return; }
            self.state.owned_event_records(paths)
        };
        self.state.filter_owned_event_records(paths, boundary, records);
    }

    pub(super) fn flush(&self) -> io::Result<()> {
        let ticket = {
            let frontier = self.frontier.lock().unwrap();
            ensure_healthy(&frontier)?;
            watch_journal_request_flush(self.stream_id.clone(), frontier.seq)?
        };
        ticket.wait()?;
        self.wait_for_checkpoint()?;
        self.compact()?;
        self.wait_for_checkpoint()?;
        // Display history is best-effort, unlike the durable journal above.
        // Its writer retains the fault and retries recovery on later writes.
        let _ = self.log.flush();
        Ok(())
    }

    pub(super) fn compact(&self) -> io::Result<()> {
        let mut active = self.checkpoint.lock().unwrap();
        if active.as_ref().is_some_and(|checkpoint| !checkpoint.ready.load(Ordering::Acquire) && !checkpoint.job.is_finished()) {
            return Ok(());
        }
        self.harvest_checkpoint(active.take())?;
        let (checkpoint, seal, boundary, records, bytes) = {
            let mut frontier = self.frontier.lock().unwrap();
            ensure_healthy(&frontier)?;
            if !frontier.needs_checkpoint() {
                if let Some(boundary) = frontier.retirement {
                    let dir = self.snapshot.parent().unwrap().to_owned();
                    let ready = Arc::new(AtomicBool::new(false));
                    let job = thread::Builder::new().name("sunpack-watch-retirement".into())
                        .stack_size(512 * 1024)
                        .spawn(move || Ok(CheckpointResult::Published {
                            retirement: retire_segments(&dir, boundary).then_some(boundary),
                        }))?;
                    *active = Some(Checkpoint { job, records: 0, bytes: 0, ready });
                }
                return Ok(());
            }
            let segment = frontier.segment;
            let seal = watch_journal_submit_seal(
                self.stream_id.clone(),
                segment_path(self.snapshot.parent().unwrap(), segment)
                    .to_string_lossy()
                    .into_owned(),
                segment,
                frontier.seq,
            )?;
            let checkpoint = self.state.capture(frontier.seq);
            frontier.segment = frontier.seq + 1;
            (checkpoint, seal, frontier.seq, frontier.records, frontier.bytes)
        };
        let snapshot = self.snapshot.clone();
        let notify = self.maintenance.lock().unwrap().clone();
        let ready = Arc::new(AtomicBool::new(false));
        let completed = Arc::clone(&ready);
        // The append stream already seals the captured prefix in sequence.
        // Leave serialization and disk I/O off the Watch and extraction paths.
        let job = thread::Builder::new()
            .name("sunpack-watch-checkpoint".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                // A failed WAL seal is a persistence fault, not a snapshot
                // retry: never hide it behind the recoverable publication path.
                seal.wait()?;
                let dir = snapshot.parent().unwrap();
                let temp = dir.join("state.snapshot.tmp");
                let publication = (|| {
                    drop(File::create(&temp)?);
                    checkpoint.write(temp.to_string_lossy().into_owned())?;
                    crate::io::atomic_file::replace_once(&temp, &snapshot)
                })();
                let _ = fs::remove_file(&temp);
                if let Err(error) = publication {
                    return Ok(CheckpointResult::SnapshotFailed(error));
                }
                let retirement = retire_segments(dir, boundary).then_some(boundary);
                // Make the result harvestable before waking idle maintenance:
                // the callback can run before JoinHandle::is_finished flips.
                completed.store(true, Ordering::Release);
                if retirement.is_some() {
                    if let Some(notify) = notify { notify(); }
                }
                Ok(CheckpointResult::Published { retirement })
            });
        match job {
            Ok(job) => *active = Some(Checkpoint { job, records, bytes, ready }),
            Err(error) => self.record_checkpoint_error(error)?,
        }
        Ok(())
    }

    fn wait_for_checkpoint(&self) -> io::Result<()> {
        let mut active = self.checkpoint.lock().unwrap();
        self.harvest_checkpoint(active.take())
    }

    fn harvest_checkpoint(&self, checkpoint: Option<Checkpoint>) -> io::Result<()> {
        let Some(checkpoint) = checkpoint else { return Ok(()); };
        match join_checkpoint(checkpoint.job) {
            Ok(CheckpointResult::Published { retirement }) => {
                let mut frontier = self.frontier.lock().unwrap();
                frontier.records = frontier.records.saturating_sub(checkpoint.records);
                // A late append acknowledgement may conservatively retain a
                // few already checkpointed bytes. Never undercount live WAL.
                frontier.bytes = frontier.bytes.saturating_sub(checkpoint.bytes);
                frontier.checkpoint_error = None;
                frontier.retirement = retirement;
                ensure_healthy(&frontier)
            }
            Ok(CheckpointResult::SnapshotFailed(error)) => self.record_checkpoint_error(error),
            Err(error) => {
                self.frontier.lock().unwrap().fault.get_or_insert_with(|| error.to_string());
                Err(error)
            }
        }
    }

    fn record_checkpoint_error(&self, error: io::Error) -> io::Result<()> {
        let mut frontier = self.frontier.lock().unwrap();
        frontier.checkpoint_error = Some(error.to_string());
        let result = ensure_healthy(&frontier);
        drop(frontier);
        self.log(serde_json::json!({"event":"watch_checkpoint_failed","error":error.to_string()}));
        result
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        if let Ok(active) = self.checkpoint.get_mut() {
            if let Some(checkpoint) = active.take() {
                let _ = join_checkpoint(checkpoint.job);
            }
        }
    }
}

fn join_checkpoint(job: JoinHandle<io::Result<CheckpointResult>>) -> io::Result<CheckpointResult> {
    job.join().map_err(|_| io::Error::other("Watch checkpoint thread failed"))?
}

fn ensure_healthy(frontier: &Frontier) -> io::Result<()> {
    if let Some(error) = &frontier.fault {
        Err(io::Error::other(error.clone()))
    } else if frontier.bytes >= JOURNAL_HARD_BYTES {
        match &frontier.checkpoint_error {
            Some(error) => Err(io::Error::other(format!(
                "Watch state checkpoint failed at the journal safety limit: {error}"))),
            None => Ok(()),
        }
    } else {
        Ok(())
    }
}

// A published snapshot covers this prefix. Failure only leaves redundant WAL;
// retry on an existing idle maintenance or the next open, never on a timer.
fn retire_segments(dir: &Path, boundary: u64) -> bool {
    let Ok(paths) = segments(dir) else { return true; };
    let mut pending = false;
    for (_, path) in paths.into_iter().take_while(|(start, _)| *start <= boundary) {
        if let Err(error) = fs::remove_file(path) {
            pending |= error.kind() != io::ErrorKind::NotFound;
        }
    }
    pending
}

fn segment_path(dir: &Path, start: u64) -> PathBuf {
    dir.join(format!("state.journal.{start:020}.wal"))
}

fn segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(start) = name
            .to_str()
            .and_then(|name| name.strip_prefix("state.journal."))
            .and_then(|name| name.strip_suffix(".wal"))
            .and_then(|number| number.parse::<u64>().ok())
            .filter(|start| *start != 0)
        else {
            continue;
        };
        paths.push((start, entry.path()));
    }
    paths.sort_unstable_by_key(|(start, _)| *start);
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unlike dropping Journal, killing a separate owner cannot finish a
    // checkpoint, flush the stream or run destructors on the way out. Cover
    // the three durable representations with one coarse recovery scenario.
    #[test]
    fn hard_process_death_replays_checkpoint_and_retirement_boundaries() {
        use std::io::{BufRead, Read, Write};
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::Duration;

        const CHILD: &str = "SUNPACK_JOURNAL_CRASH_CHILD";
        const PHASE: &str = "SUNPACK_JOURNAL_CRASH_PHASE";
        const READY: &str = "sunpack-journal-crash-ready";
        if let Some(marker) = std::env::var_os(CHILD) {
            let marker = PathBuf::from(marker);
            let dir = marker.with_extension("state");
            let owned = marker.with_extension("owned");
            fs::create_dir(&owned).unwrap();
            let journal = Journal::open(&dir).unwrap();
            journal.commit(true, |_| {
                let mut operations = NativeWatchOperations::password_generation(1, "one".into());
                let (volume, id, _) = crate::filesystem::watch_path_identity(owned.to_str().unwrap())?;
                operations.extend(NativeWatchOperations::owned_outputs(
                    &[owned.to_string_lossy().into_owned()], &[&format!("{volume}|{id}")],
                ));
                operations.put_promoted(serde_json::from_value(serde_json::json!({
                    "path": marker,
                    "generation": crate::io::reader::capture_file_generation(&marker)?.persisted(),
                }))?);
                Ok(operations)
            }).unwrap();
            journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
            let phase = std::env::var(PHASE).unwrap();
            // Hold SHARE_DELETE closed only in the published/pre-retirement
            // case. Snapshot publication succeeds while its covered WAL stays.
            let retained = (phase == "published").then(|| {
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
            println!("{READY}");
            io::stdout().flush().unwrap();
            let mut byte = [0];
            io::stdin().read_exact(&mut byte).unwrap();
            drop(retained);
            panic!("the parent must kill the journal owner without unwinding");
        }

        for phase in ["before_snapshot", "published", "retired"] {
            let marker = crate::test_support::temp_file("journal_process_death", b"generation");
            let dir = marker.with_extension("state");
            let owned = marker.with_extension("owned");
            let test_name = format!("{}::hard_process_death_replays_checkpoint_and_retirement_boundaries", module_path!().split_once("::").unwrap().1);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env(CHILD, &marker).env(PHASE, phase)
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
                .spawn().unwrap();
            let stdout = child.stdout.take().unwrap();
            let (send, ready) = mpsc::sync_channel(1);
            let reader = thread::spawn(move || {
                for line in io::BufReader::new(stdout).lines() {
                    if line.unwrap().contains(READY) {
                        let _ = send.send(());
                        return;
                    }
                }
            });
            let reached = ready.recv_timeout(Duration::from_secs(30));
            // Kill on timeout too, so a failed boundary does not leave a child
            // or its exclusive state lock behind and hang the remaining suite.
            let killed = child.kill();
            let status = child.wait().unwrap();
            reader.join().unwrap();
            reached.expect("journal child did not reach the requested crash boundary");
            killed.unwrap();
            assert!(!status.success());
            for _ in 0..2 {
                let journal = Journal::open(&dir).unwrap();
                assert_eq!(journal.state().password_generation(), 3, "{phase}");
                assert!(!journal.state().promoted_source(marker.to_str().unwrap()).unwrap().is_replaced());
                assert_eq!(journal.state().runtime_keys("owned|").len(), 1);
                let mut events = vec![owned.join("nested.zip")];
                journal.filter_owned_events(&mut events, &owned);
                assert!(events.is_empty(), "replayed ownership must still filter output events");
                if phase != "before_snapshot" {
                    assert!(!segment_path(&dir, 1).exists());
                }
            }
            fs::remove_dir_all(&dir).unwrap();
            fs::remove_dir(&owned).unwrap();
            fs::remove_file(marker).unwrap();
        }
    }

    // Exercises the durable writer and replay, not just error classification:
    // an unavailable snapshot must not lose the sealed WAL or stop appends.
    #[test]
    fn snapshot_failure_keeps_wal_live_until_retry_or_safety_limit() {
        let marker = crate::test_support::temp_file("snapshot_retry", b"");
        let dir = marker.with_extension("state");
        let journal = Journal::open(&dir).unwrap();
        let temp = dir.join("state.snapshot.tmp");
        fs::create_dir(&temp).unwrap(); // Fail only snapshot creation, not WAL.
        journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
        journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(1, "one".into()))).unwrap();
        journal.wait_for_checkpoint().unwrap();
        assert!(journal.frontier.lock().unwrap().checkpoint_error.is_some());
        journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(2, "two".into()))).unwrap();
        journal.flush().unwrap();
        assert_eq!(journal.state().password_generation(), 2);
        assert!(journal.frontier.lock().unwrap().records >= CHECKPOINT_RECORDS);
        assert!(!segments(&dir).unwrap().is_empty());
        drop(journal);
        let journal = Journal::open(&dir).unwrap();
        assert_eq!(journal.state().password_generation(), 2);
        fs::remove_dir(&temp).unwrap();
        journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS;
        // Retry without another append: its current segment starts *after*
        // the snapshot boundary and must not be retired if a writer opens it.
        journal.compact().unwrap();
        journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(3, "three".into()))).unwrap();
        journal.flush().unwrap();
        assert!(journal.frontier.lock().unwrap().checkpoint_error.is_none());
        drop(journal);
        let journal = Journal::open(&dir).unwrap();
        assert_eq!(journal.state().password_generation(), 3);
        {
            let mut frontier = journal.frontier.lock().unwrap();
            frontier.bytes = JOURNAL_HARD_BYTES - 1;
            frontier.checkpoint_error = Some("snapshot unavailable".into());
            assert!(ensure_healthy(&frontier).is_ok());
            frontier.bytes += 1;
            assert!(ensure_healthy(&frontier).is_err());
            frontier.bytes = 0;
            frontier.checkpoint_error = None;
        }
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
        let journal = Journal::open(&dir).unwrap();
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
        let journal = Journal::open(&dir).unwrap();
        assert_eq!(journal.state().password_generation(), 2);
        assert!(!wal.exists());
        drop(journal);
        fs::remove_dir_all(dir).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn display_flush_failure_does_not_replace_durable_journal_result() {
        let marker = crate::test_support::temp_file("display_flush", b"");
        let dir = marker.with_extension("state");
        let journal = Journal::open(&dir).unwrap();
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
        assert!(journal.log.error().unwrap().is_some());
        // A persistence fault must still fail the same public flush boundary.
        journal.frontier.lock().unwrap().fault = Some("durability fault".into());
        assert!(journal.flush().unwrap_err().to_string().contains("durability fault"));
        journal.frontier.lock().unwrap().fault = None;
        fs::remove_dir(&manifest).unwrap();
        fs::rename(&saved, &manifest).unwrap();
        journal.flush().unwrap();
        drop(journal);
        let journal = Journal::open(&dir).unwrap();
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
        let journal = Arc::new(Journal::open(&dir).unwrap());
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
        let journal = Journal::open(&dir).unwrap();
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
        let journal = Arc::new(Journal::open(&state_directory).unwrap());
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
            let (volume, id, _) = crate::filesystem::watch_path_identity(output.to_str().unwrap())?;
            Ok(NativeWatchOperations::owned_outputs(
                &crate::path_keys::output_path_aliases(&output)?, &[&format!("{volume}|{id}")],
            ))
        }).unwrap();
        assert_eq!(filtered.recv_timeout(Duration::from_secs(5)).unwrap(), vec![directory.clone()]);
        worker.join().unwrap();
        assert_eq!(journal.frontier.lock().unwrap().seq, 1);
        assert!(journal.state().watch_cursors().is_empty());
        drop(journal);
        let journal = Journal::open(&state_directory).unwrap();
        let mut paths = vec![output.join("nested.blob"), physical.join("nested.blob")];
        journal.filter_owned_events(&mut paths, &directory);
        assert!(paths.is_empty());
        assert_eq!(journal.state().runtime_keys("owned|").len(), 2);
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
            let journal = Journal::open(&dir).unwrap();
            // Position just below the threshold without doing thousands of
            // unrelated writes. Every subsequent record uses the real writer.
            journal.frontier.lock().unwrap().records = CHECKPOINT_RECORDS - 2;
            for generation in 1..=3 {
                journal
                    .commit(true, |_| {
                        let mut operations = NativeWatchOperations::password_generation(
                            generation,
                            generation.to_string(),
                        );
                        if generation == 1 {
                            operations.put_promoted(serde_json::from_value(serde_json::json!({
                                "path": marker,
                                "generation": crate::io::reader::capture_file_generation(&marker)?.persisted(),
                            }))?);
                        }
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
            let journal = Journal::open(&dir).unwrap();
            assert_eq!(journal.state().password_generation(), 3);
            let receipt = journal
                .state()
                .promoted_source(marker.to_str().unwrap())
                .unwrap();
            assert_eq!(receipt.path(), marker);
            assert!(!receipt.is_replaced());
            fs::write(&marker, b"replacement data").unwrap();
            assert!(receipt.is_replaced());
        }
        fs::remove_dir_all(dir).unwrap();
        fs::remove_file(marker).unwrap();
    }
}
