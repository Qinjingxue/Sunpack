use super::key;
use crate::event_log::NativeEventLog;
use crate::watch_journal::{NativeJournalStream, NativeJournalTicket};
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
    static DEFERRED: std::cell::RefCell<Option<(usize, Vec<NativeJournalTicket>)>> = const { std::cell::RefCell::new(None) };
}

pub(super) struct PendingCommits(Vec<NativeJournalTicket>);

struct DeferredScope;
impl Drop for DeferredScope {
    fn drop(&mut self) { DEFERRED.with(|slot| { slot.borrow_mut().take(); }); }
}

const CHECKPOINT_RECORDS: u64 = 8192;
const CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;
const SNAPSHOT_TEMP_NAME: &str = "state.snapshot.tmp";

struct Frontier {
    stream: Option<NativeJournalStream>,
    seq: u64,
    segment: u64,
    records: u64,
    bytes: u64,
    fault: Option<String>,
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
    // Foreground publication checks this while holding the external output
    // gate. It must not acquire the frontier lock just to choose a route.
    suspended: AtomicBool,
    log: Arc<NativeEventLog>,
    frontier: Mutex<Frontier>,
    checkpoint: Mutex<Option<Checkpoint>>,
    maintenance: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    snapshot: PathBuf,
    _lock: File,
}

impl Journal {
    pub(super) fn open(dir: &Path, retention_days: u64) -> io::Result<Self> {
        Self::open_with_outputs(dir, retention_days, Arc::default())
    }

    pub(super) fn open_with_outputs(dir: &Path, retention_days: u64,
        outputs: crate::watch_store::active_outputs::OutputReservations) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(dir.join("state.runtime.lock"))?;
        let snapshot = dir.join("state.snapshot");
        let mut state = NativeWatchState::new();
        state.outputs = outputs;
        let frontier = Self::restore_state(&state, dir)?;
        let log = Arc::new(NativeEventLog::new(dir.join("events.json"), retention_days.min(u32::MAX.into()) as u32, true)?);
        state.attach_events(&log);
        log.recover(&state);
        Ok(Self {
            state,
            suspended: AtomicBool::new(false),
            log,
            frontier: Mutex::new(frontier),
            checkpoint: Mutex::default(),
            maintenance: Mutex::default(),
            snapshot,
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
            stream: None,
            seq: checkpoint,
            segment: checkpoint + 1,
            records: 0,
            bytes: 0,
            fault: None,
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
        frontier.stream = Some(NativeJournalStream::open_seeded(key(&snapshot), frontier.seq)
            .map_err(io::Error::other)?);
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
        let mut frontier = self.frontier.lock().unwrap();
        let Some(stream) = frontier.stream.as_ref() else { return Ok(()); };
        // Foreground work can append between flush and acquiring the lock.
        // Finish that prefix before releasing the idle stream and its handles.
        stream.request_flush(frontier.seq)?.wait()?;
        let released = frontier.stream.take().unwrap().close().map_err(io::Error::other);
        self.suspended.store(true, Ordering::Release);
        self.state.unload();
        released
    }

    pub(super) fn resume(&self) -> io::Result<bool> {
        let mut frontier = self.frontier.lock().unwrap();
        if frontier.stream.is_some() { return Ok(false); }
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
        #[cfg(test)]
        if super::quiet_replay::now().is_some() { return; }
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
        self.log.rebuild();
        self.log.recover(&self.state);
        self.log.flush()?;
        Ok(self.log.error().is_none())
    }

    pub(super) fn set_retention(&self, days: u64) {
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
            let Some(stream) = frontier.stream.as_ref() else { return Ok(()); };
            let operations = prepare(&self.state)?;
            if operations.is_empty() {
                return Ok(());
            }
            let seq = frontier
                .seq
                .checked_add(1)
                .ok_or(io::ErrorKind::InvalidData)?;
            let segment = frontier.segment;
            let ticket = stream.submit_task_append(
                segment_path(self.snapshot.parent().unwrap(), segment),
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
                tickets.push(ticket);
                None
            } else { Some(ticket) }
        });
        match ticket {
            Some(ticket) => self.wait_commits(std::slice::from_ref(&ticket)),
            None => Ok(()),
        }
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
        self.wait_commits(&tickets.0)
    }

    pub(super) fn defer_waits<T>(&self, prepare: impl FnOnce() -> T) -> (T, io::Result<()>) {
        let (result, tickets) = self.prepare_waits(prepare);
        (result, self.wait_prepared(tickets))
    }

    fn wait_commits(&self, tickets: &[NativeJournalTicket]) -> io::Result<()> {
        if tickets.is_empty() {
            return Ok(());
        }
        let result = NativeJournalTicket::wait_appends(tickets);
        let mut frontier = self.frontier.lock().unwrap();
        let bytes = result.inspect_err(|error| {
            frontier.fault.get_or_insert_with(|| error.to_string());
        })?;
        // Count all uncheckpointed WAL, including a segment sealed while
        // this caller was awaiting its append. A failed snapshot retires none.
        frontier.bytes = frontier.bytes.saturating_add(bytes);
        ensure_healthy(&frontier)?;
        let needs_checkpoint = frontier.needs_checkpoint();
        drop(frontier);
        if needs_checkpoint {
            self.compact()?;
        }
        Ok(())
    }

    /// Use the existing publication gate without emitting a WAL record or
    /// advancing a cursor. An output's mkdir and temporary registration cannot
    /// be observed halfway through by a directory-notification callback.
    pub(super) fn owned_event_filter<'a>(
        &self, paths: impl Iterator<Item = &'a Path>, boundary: &Path,
    ) -> Option<crate::watch_store::active_outputs::OwnedEventFilter> {
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
            frontier.stream.as_ref().map(|stream| stream.request_flush(frontier.seq)).transpose()?
        };
        if let Some(ticket) = ticket { ticket.wait()?; }
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
            let Some(stream) = frontier.stream.as_ref() else { return Ok(()); };
            if !frontier.needs_checkpoint() {
                if let Some(boundary) = frontier.retirement {
                    let dir = self.snapshot.parent().unwrap().to_owned();
                    let notify = self.maintenance.lock().unwrap().clone();
                    let ready = Arc::new(AtomicBool::new(false));
                    let completed = Arc::clone(&ready);
                    let job = thread::Builder::new().name("sunpack-watch-retirement".into())
                        .stack_size(512 * 1024)
                        .spawn(move || {
                            let retirement = retire_segments(&dir, boundary).then_some(boundary);
                            // A persistent sharing conflict gets one immediate
                            // retry; only success wakes another maintenance turn.
                            if retirement.is_none() {
                                completed.store(true, Ordering::Release);
                                if let Some(notify) = notify { notify(); }
                            }
                            Ok(CheckpointResult::Published { retirement })
                        })?;
                    *active = Some(Checkpoint { job, records: 0, bytes: 0, ready });
                }
                return Ok(());
            }
            let segment = frontier.segment;
            let seal = stream.submit_seal(
                segment_path(self.snapshot.parent().unwrap(), segment),
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
                    checkpoint.write(&temp)?;
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
                if let Some(notify) = notify { notify(); }
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
        // The sealed WAL remains replayable. Keep it until a durable
        // snapshot is published, even if snapshot publication must retry.
        self.log(serde_json::json!({"event":"watch_checkpoint_failed","error":error.to_string()}));
        ensure_healthy(&self.frontier.lock().unwrap())
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
#[path = "../../../tests/unit/runtime/watch/journal/tests.rs"]
mod tests;
