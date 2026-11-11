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
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

const CHECKPOINT_RECORDS: u64 = 8192;
const CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;

struct Frontier {
    seq: u64,
    segment: u64,
    records: u64,
    bytes: u64,
    fault: Option<String>,
}

impl Frontier {
    fn needs_checkpoint(&self) -> bool {
        self.records >= CHECKPOINT_RECORDS || self.bytes >= CHECKPOINT_BYTES
    }
}

pub(super) struct Journal {
    state: NativeWatchState,
    log: NativeEventLog,
    frontier: Mutex<Frontier>,
    checkpoint: Mutex<Option<JoinHandle<io::Result<()>>>>,
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
        };
        let mut tail = None;
        for (start, path) in segments(dir)? {
            let replay = state.replay_segment(
                path.to_string_lossy().into_owned(),
                checkpoint,
                frontier.seq + 1,
            )?;
            if replay.records != 0 {
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
            snapshot,
            stream_id,
            _stream: stream,
            _lock: lock,
        })
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
        let (ticket, segment) = {
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
            (ticket, segment)
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
        if frontier.segment == segment {
            frontier.bytes += ticket.bytes_written();
        }
        ensure_healthy(&frontier)?;
        let needs_checkpoint = frontier.needs_checkpoint();
        drop(frontier);
        if needs_checkpoint {
            self.compact()?;
        }
        Ok(())
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
        self.log.flush()
    }

    pub(super) fn compact(&self) -> io::Result<()> {
        let mut active = self.checkpoint.lock().unwrap();
        if active.as_ref().is_some_and(|job| !job.is_finished()) {
            return Ok(());
        }
        join_checkpoint(active.take())?;
        let (checkpoint, seal, segment) = {
            let mut frontier = self.frontier.lock().unwrap();
            ensure_healthy(&frontier)?;
            if !frontier.needs_checkpoint() {
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
            frontier.records = 0;
            frontier.bytes = 0;
            (checkpoint, seal, segment)
        };
        let snapshot = self.snapshot.clone();
        // The append stream already seals the captured prefix in sequence.
        // Leave serialization and disk I/O off the Watch and extraction paths.
        *active = Some(
            thread::Builder::new()
                .name("sunpack-watch-checkpoint".into())
                .stack_size(512 * 1024)
                .spawn(move || {
                    seal.wait()?;
                    let dir = snapshot.parent().unwrap();
                    let temp = dir.join("state.snapshot.tmp");
                    drop(File::create(&temp)?);
                    checkpoint.write(temp.to_string_lossy().into_owned())?;
                    crate::io::atomic_file::replace(&temp, &snapshot)?;
                    for (_, path) in segments(dir)?
                        .into_iter()
                        .take_while(|(start, _)| *start <= segment)
                    {
                        let _ = fs::remove_file(path);
                    }
                    Ok(())
                })?,
        );
        Ok(())
    }

    fn wait_for_checkpoint(&self) -> io::Result<()> {
        let mut active = self.checkpoint.lock().unwrap();
        join_checkpoint(active.take())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        if let Ok(active) = self.checkpoint.get_mut() {
            let _ = join_checkpoint(active.take());
        }
    }
}

fn join_checkpoint(active: Option<JoinHandle<io::Result<()>>>) -> io::Result<()> {
    if let Some(job) = active {
        job.join()
            .map_err(|_| io::Error::other("Watch checkpoint thread failed"))??;
    }
    Ok(())
}

fn ensure_healthy(frontier: &Frontier) -> io::Result<()> {
    if let Some(error) = &frontier.fault {
        Err(io::Error::other(error.clone()))
    } else {
        Ok(())
    }
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
