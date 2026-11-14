use super::key;
use crate::event_log::NativeEventLog;
use crate::watch_journal::{
    watch_journal_open, watch_journal_request_flush, watch_journal_seed,
    watch_journal_submit_append, watch_journal_submit_seal, NativeJournalStream, NativeJournalTicket,
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

// Scoped to the admitted scheduler stage: worker publications on other
// threads retain their own durable boundary.
thread_local! {
    static DEFERRED: std::cell::RefCell<Option<(usize, Vec<(NativeJournalTicket, bool)>)>> = const { std::cell::RefCell::new(None) };
}

pub(super) struct PendingCommits(Vec<(NativeJournalTicket, bool)>);

struct DeferredScope;
impl Drop for DeferredScope {
    fn drop(&mut self) { DEFERRED.with(|slot| { slot.borrow_mut().take(); }); }
}

const CHECKPOINT_RECORDS: u64 = 8192;
const CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;
const JOURNAL_HARD_BYTES: u64 = 256 * 1024 * 1024;
const SNAPSHOT_TEMP_NAME: &str = "state.snapshot.tmp";

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
    suspended: AtomicBool,
    log: Arc<NativeEventLog>,
    frontier: Mutex<Frontier>,
    checkpoint: Mutex<Option<Checkpoint>>,
    maintenance: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    snapshot: PathBuf,
    stream_id: String,
    _stream: NativeJournalStream,
    _lock: File,
}

impl Journal {
    pub(super) fn open(dir: &Path, retention_days: u64) -> io::Result<Self> {
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
        let frontier = Self::restore_state(&state, dir)?;
        let stream_id = key(&snapshot);
        let stream = watch_journal_open(stream_id.clone())?;
        watch_journal_seed(&stream_id, frontier.seq)?;
        let log = Arc::new(NativeEventLog::new(dir.join("events.json"), retention_days.min(u32::MAX.into()) as u32, true)?);
        state.attach_events(&log)?;
        log.recover(Some(&state))?;
        Ok(Self {
            state,
            suspended: AtomicBool::new(false),
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

    fn restore_state(state: &NativeWatchState, dir: &Path) -> io::Result<Frontier> {
        let snapshot = dir.join("state.snapshot");
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
        Ok(frontier)
    }

    #[cfg(test)]
    pub(super) fn fail_for_test(&self) {
        self.frontier.lock().unwrap().fault = Some("injected unavailable WAL".into());
    }

    pub(super) fn suspended(&self) -> bool {
        self.suspended.load(Ordering::Acquire)
    }

    // The control/logging shell stays alive without roots, but must not retain
    // recovery receipts. WAL is durable before releasing its in-memory views.
    pub(super) fn suspend(&self) -> io::Result<()> {
        if self.suspended() { return Ok(()); }
        self.flush()?;
        let mut checkpoint = self.checkpoint.lock().unwrap();
        self.harvest_checkpoint(checkpoint.take())?;
        let frontier = self.frontier.lock().unwrap();
        watch_journal_request_flush(self.stream_id.clone(), frontier.seq)?.wait()?;
        self.suspended.store(true, Ordering::Release);
        self.state.unload();
        Ok(())
    }

    pub(super) fn resume(&self) -> io::Result<bool> {
        let mut frontier = self.frontier.lock().unwrap();
        if !self.suspended() { return Ok(false); }
        // Load into a temporary state so an IO error cannot publish a partially
        // replayed generation to the live catalog or a later retry.
        let restored = NativeWatchState::new();
        let next = Self::restore_state(&restored, self.snapshot.parent().unwrap())?;
        *self.state.lock() = std::mem::take(&mut *restored.lock());
        *frontier = next;
        self.suspended.store(false, Ordering::Release);
        Ok(true)
    }

    pub(super) fn set_maintenance(&self, notify: Arc<dyn Fn() + Send + Sync>) {
        *self.maintenance.lock().unwrap() = Some(notify);
    }

    pub(super) fn state(&self) -> &NativeWatchState {
        &self.state
    }

    pub(super) fn event_log(&self) -> &Arc<NativeEventLog> {
        &self.log
    }

    pub(super) fn log(&self, value: Value) {
        if self.log.write(value).is_err() {
            let _ = self.rebuild_log();
        }
    }

    pub(super) fn log_failure(&self, value: Value, failure: &crate::pipeline::Failure) {
        if self.log.write_failure(value, failure).is_err() {
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
            // A foreground publication captured before the final root was
            // removed no longer belongs to an active Watch scheduler.
            if self.suspended() { return Ok(()); }
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
        let ticket = DEFERRED.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some((_, tickets)) = slot.as_mut().filter(|(owner, _)| *owner == self as *const Self as usize) {
                tickets.push((ticket, durable));
                None
            } else { Some(ticket) }
        });
        match ticket { Some(ticket) => self.wait_commit(ticket, durable), None => Ok(()) }
    }

    pub(super) fn prepare_waits<T>(&self, prepare: impl FnOnce() -> T) -> (T, PendingCommits) {
        DEFERRED.with(|slot| {
            assert!(slot.borrow().is_none(), "nested Watch journal deferral");
            *slot.borrow_mut() = Some((self as *const Self as usize, Vec::new()));
        });
        let scope = DeferredScope;
        let result = prepare();
        let tickets = DEFERRED.with(|slot| slot.borrow_mut().take().unwrap().1);
        drop(scope);
        (result, PendingCommits(tickets))
    }

    pub(super) fn wait_prepared(&self, tickets: PendingCommits) -> io::Result<()> {
        let mut durable = Ok(());
        for (ticket, required) in tickets.0 {
            if let Err(error) = self.wait_commit(ticket, required) { durable = Err(error); }
        }
        durable
    }

    pub(super) fn defer_waits<T>(&self, prepare: impl FnOnce() -> T) -> (T, io::Result<()>) {
        let (result, tickets) = self.prepare_waits(prepare);
        (result, self.wait_prepared(tickets))
    }

    fn wait_commit(&self, ticket: NativeJournalTicket, durable: bool) -> io::Result<()> {
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
    pub(super) fn owned_event_filter<'a>(
        &self, paths: impl Iterator<Item = &'a Path>, boundary: &Path,
    ) -> Option<crate::watch_store::owned_outputs::OwnedEventFilter> {
        let records = {
            let frontier = self.frontier.lock().unwrap();
            if frontier.fault.is_some() { return None; }
            self.state.owned_event_records(paths)
        };
        self.state.owned_event_filter(boundary, records)
    }

    #[cfg(test)]
    fn filter_owned_events(&self, paths: &mut Vec<PathBuf>, boundary: &Path) {
        if let Some(filter) = self.owned_event_filter(paths.iter().map(PathBuf::as_path), boundary) {
            paths.retain(|path| !filter.contains(path));
        }
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
        if self.suspended() { return Ok(()); }
        let mut active = self.checkpoint.lock().unwrap();
        if active.as_ref().is_some_and(|checkpoint| !checkpoint.ready.load(Ordering::Acquire) && !checkpoint.job.is_finished()) {
            return Ok(());
        }
        self.harvest_checkpoint(active.take())?;
        let (checkpoint, seal, boundary, records, bytes) = {
            let mut frontier = self.frontier.lock().unwrap();
            ensure_healthy(&frontier)?;
            if self.suspended() { return Ok(()); }
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
                let temp = dir.join(SNAPSHOT_TEMP_NAME);
                let publication = (|| {
                    drop(File::create(&temp)?);
                    checkpoint.write(temp.to_string_lossy().into_owned())?;
                    crate::io::atomic_file::replace_once(&temp, &snapshot)?;
                    // Publication must be durable before retiring its WAL prefix.
                    // Windows requires a writable handle for FlushFileBuffers.
                    OpenOptions::new().read(true).write(true).open(&snapshot)?.sync_all()
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
    // A hard stop can leave a large unpublished checkpoint. The journal's
    // exclusive service lock and single active checkpoint own this path.
    let mut pending = fs::remove_file(dir.join(SNAPSHOT_TEMP_NAME))
        .is_err_and(|error| error.kind() != io::ErrorKind::NotFound);
    let Ok(paths) = segments(dir) else { return true; };
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
                journal.commit(true, |_| Ok(NativeWatchOperations::password_generation(
                    generation, generation.to_string()))).unwrap();
                DEFERRED.with(|slot| assert_eq!(slot.borrow().as_ref().unwrap().1.len(), generation as usize));
            }
            assert_eq!(journal.state().password_generation(), 32);
            journal.frontier.lock().unwrap().seq
        });
        durable.unwrap();
        assert_eq!(prepared, 32);
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
            false, "root", true, true, None)?.0)).unwrap();
        let receipt = Arc::downgrade(&journal.state().pending(&paths[0]).unwrap());
        journal.frontier.lock().unwrap().fault = Some("unavailable WAL".into());
        assert!(journal.suspend().is_err());
        assert!(!journal.suspended() && receipt.upgrade().is_some());
        journal.frontier.lock().unwrap().fault = None;
        journal.suspend().unwrap();
        assert!(receipt.upgrade().is_none());
        assert!(journal.state().pending_items().is_empty());
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
            store.append(&serde_json::json!({"event":"done", "path":"old.zip", "ts":old as f64 / 1_000_000.0}), old).unwrap();
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

    #[test]
    #[ignore = "requires the real sunpack_gui_tests.exe; run by GUI/runtime CI"]
    fn cpp_query_recovers_durable_blocker_after_writer_death() {
        use crate::event_log::gui_contract::{gui_binary, project, Directory, DirectoryNotification};
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
            // path still fsyncs its WAL while the display writer is blocked.
            // Leave a real unpublished history append on disk at the same time.
            let _held = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path).unwrap();
            let changed = DirectoryNotification::new(&dir);
            journal.log(json!({"event":"done","path":dir.join("unpublished.zip"),"owner":"unpublished"}));
            changed.wait_for_temp(&dir.join("events.json.tmp"));
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
                    attempt_count: 1,
                    failure_kind: String::new(),
                    failure_stage: String::new(),
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
        assert!(dir.0.join("events.json.tmp").is_file());

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
    fn snapshot_failure_keeps_wal_live_until_retry_or_safety_limit() {
        let marker = crate::test_support::temp_file("snapshot_retry", b"");
        let dir = marker.with_extension("state");
        let journal = Journal::open(&dir, 7).unwrap();
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
        let journal = Journal::open(&dir, 7).unwrap();
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
        let journal = Journal::open(&dir, 7).unwrap();
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
        assert!(journal.log.error().unwrap().is_some());
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
        let journal = Journal::open(&state_directory, 7).unwrap();
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
            let journal = Journal::open(&dir, 7).unwrap();
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
            let journal = Journal::open(&dir, 7).unwrap();
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
