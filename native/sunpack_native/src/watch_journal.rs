use crate::io::resource_lifecycle::TrackedFile;
use crate::wal::{self, Kind};
use crate::watch_store::{NativeWatchOperations, Operations};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const DURABLE_SINGLE_PROBE_MICROS: u64 = 50;
const DURABLE_BURST_COALESCE_MICROS: u64 = 500;
const DURABLE_SLOW_STORAGE_COALESCE_MICROS: u64 = 750;
const DURABLE_SLOW_STORAGE_THRESHOLD_MICROS: u64 = 10_000;
const WRITER_BATCH_MAX_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug)]
enum TicketGoal {
    Written,
    Durable,
    Sealed,
}

#[pyclass(module = "sunpack_native")]
pub(crate) struct NativeJournalTicket {
    shared: Arc<Shared>,
    stream: String,
    seq: u64,
    goal: TicketGoal,
    bytes_written: Option<Arc<AtomicU64>>,
    retired: Arc<OnceLock<StreamFrontier>>,
}

impl NativeJournalTicket {
    fn new(
        shared: Arc<Shared>,
        stream: String,
        seq: u64,
        goal: TicketGoal,
        retired: Arc<OnceLock<StreamFrontier>>,
    ) -> Self {
        Self {
            shared,
            stream,
            seq,
            goal,
            bytes_written: None,
            retired,
        }
    }

    fn wait_for(&self, goal: TicketGoal) -> Result<(), String> {
        self.shared
            .wait_for(&self.stream, &self.retired, self.seq, goal)
    }
}

impl Shared {
    fn wait_for(
        &self,
        key: &str,
        retired: &Arc<OnceLock<StreamFrontier>>,
        seq: u64,
        goal: TicketGoal,
    ) -> Result<(), String> {
        let mut state = lock_state(self);
        loop {
            match state.streams.get(key) {
                Some(stream) if Arc::ptr_eq(&stream.retired, retired) => {
                    if let Some(error) = &stream.error {
                        return Err(error.clone());
                    }
                    let done = match goal {
                        TicketGoal::Written => stream.written_seq >= seq,
                        TicketGoal::Durable => stream.durable_seq >= seq,
                        TicketGoal::Sealed => stream.sealed_seq >= seq,
                    };
                    if done {
                        return Ok(());
                    }
                }
                _ => {
                    let frontier = retired.get().ok_or("Watch journal stream is unavailable")?;
                    if let Some(error) = &frontier.error {
                        return Err(error.clone());
                    }
                    let done = match goal {
                        TicketGoal::Written => frontier.written >= seq,
                        TicketGoal::Durable => frontier.durable >= seq,
                        TicketGoal::Sealed => frontier.sealed >= seq,
                    };
                    return if done {
                        Ok(())
                    } else {
                        Err("Watch journal stream closed before the requested frontier".to_string())
                    };
                }
            }
            state = self
                .cv
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

struct StreamFrontier {
    written: u64,
    durable: u64,
    sealed: u64,
    error: Option<String>,
}

/// A store owns a stream until drain/checkpoint completion. Dropping a store
/// also submits release through the existing writer, without blocking GC.
#[pyclass(module = "sunpack_native")]
pub(crate) struct NativeJournalStream {
    runtime: Arc<JournalRuntime>,
    stream: Option<String>,
}

#[pymethods]
impl NativeJournalStream {
    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(stream) = self.stream.take() {
            py.detach(|| self.runtime.release(stream))
                .map_err(PyRuntimeError::new_err)?;
        }
        Ok(())
    }
}

impl Drop for NativeJournalStream {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = self
                .runtime
                .writer_tx
                .send(WriterCommand::Release { stream, done: None });
        }
    }
}

#[pymethods]
impl NativeJournalTicket {
    fn wait(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.wait_for(self.goal))
            .map_err(PyRuntimeError::new_err)
    }

    fn wait_written(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.wait_for(TicketGoal::Written))
            .map_err(PyRuntimeError::new_err)
    }

    #[getter]
    fn bytes_written(&self) -> u64 {
        self.bytes_written
            .as_ref()
            .map_or(0, |bytes| bytes.load(Ordering::Acquire))
    }
}

struct SegmentState {
    path: PathBuf,
    file: Arc<TrackedFile>,
    last_seq: u64,
    write_epoch: u64,
    flushed_epoch: u64,
    sealed_end: Option<u64>,
}

#[derive(Default)]
struct StreamState {
    owners: usize,
    closing: bool,
    retired: Arc<OnceLock<StreamFrontier>>,
    written_seq: u64,
    durable_seq: u64,
    requested_seq: u64,
    sealed_seq: u64,
    segments: BTreeMap<u64, SegmentState>,
    error: Option<String>,
    write_count: u64,
    write_calls: u64,
    flush_rounds: u64,
    flush_calls: u64,
    last_flush_micros: u64,
    coalesce_micros_total: u64,
}

#[derive(Default)]
struct RuntimeState {
    streams: HashMap<String, StreamState>,
}

struct Shared {
    state: Mutex<RuntimeState>,
    cv: Condvar,
}

impl Shared {
    fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeState::default()),
            cv: Condvar::new(),
        }
    }
}

enum WriterCommand {
    Open {
        stream: String,
        done: mpsc::Sender<()>,
    },
    Release {
        stream: String,
        done: Option<mpsc::Sender<u64>>,
    },
    Append(AppendWorkItem),
    Seal {
        stream: String,
        old_path: PathBuf,
        old_start: u64,
        boundary: u64,
    },
    Barrier {
        done: mpsc::Sender<()>,
    },
}

struct JournalRuntime {
    shared: Arc<Shared>,
    writer_tx: mpsc::Sender<WriterCommand>,
}

impl JournalRuntime {
    fn ticket(
        &self,
        stream: String,
        seq: u64,
        goal: TicketGoal,
    ) -> Result<NativeJournalTicket, String> {
        let retired = lock_state(&self.shared)
            .streams
            .get(&stream)
            .ok_or("Watch journal stream is unavailable")?
            .retired
            .clone();
        Ok(NativeJournalTicket::new(
            self.shared.clone(),
            stream,
            seq,
            goal,
            retired,
        ))
    }

    fn open(self: &Arc<Self>, stream: String) -> Result<NativeJournalStream, String> {
        // Ownership admission shares the writer's ordering with Release. A
        // queued GC release cannot retire a newly opened incarnation, and a
        // failed old stream's queued appends are drained before reopening.
        let (tx, rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::Open {
                stream: stream.clone(),
                done: tx,
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        rx.recv()
            .map_err(|_| "native Watch journal open barrier failed".to_string())?;
        Ok(NativeJournalStream {
            runtime: self.clone(),
            stream: Some(stream),
        })
    }

    fn release(&self, stream: String) -> Result<(), String> {
        let retired = {
            let state = lock_state(&self.shared);
            state.streams.get(&stream).map(|s| s.retired.clone())
        };
        let (tx, rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::Release {
                stream: stream.clone(),
                done: Some(tx),
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        let target = rx
            .recv()
            .map_err(|_| "native Watch journal release barrier failed".to_string())?;
        let Some(retired) = retired else {
            return Ok(());
        };
        // The flusher retires the last owner's stream under the same state
        // lock that publishes durability, so this also waits for retirement.
        self.shared
            .wait_for(&stream, &retired, target, TicketGoal::Durable)
    }

    fn start() -> Arc<Self> {
        let shared = Arc::new(Shared::new());
        let (writer_tx, writer_rx) = mpsc::channel();
        let runtime = Arc::new(Self {
            shared: shared.clone(),
            writer_tx,
        });

        let writer_shared = shared.clone();
        thread::Builder::new()
            .name("sunpack-watch-journal-writer".to_string())
            .spawn(move || writer_loop(writer_shared, writer_rx))
            .expect("failed to start native Watch journal writer");

        thread::Builder::new()
            .name("sunpack-watch-journal-flusher".to_string())
            .spawn(move || flusher_loop(shared))
            .expect("failed to start native Watch journal flusher");

        runtime
    }

    fn submit_append(
        &self,
        stream: String,
        path: PathBuf,
        segment_start: u64,
        seq: u64,
        operations: JournalPayload,
        durable: bool,
    ) -> Result<NativeJournalTicket, String> {
        let goal = if durable {
            TicketGoal::Durable
        } else {
            TicketGoal::Written
        };
        let mut ticket = self.ticket(stream.clone(), seq, goal)?;
        let bytes_written = Arc::new(AtomicU64::new(0));
        ticket.bytes_written = Some(Arc::clone(&bytes_written));
        self.writer_tx
            .send(WriterCommand::Append(AppendWorkItem {
                stream,
                path,
                segment_start,
                seq,
                operations,
                durable,
                bytes_written,
            }))
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        Ok(ticket)
    }

    fn submit_seal(
        &self,
        stream: String,
        old_path: PathBuf,
        old_start: u64,
        boundary: u64,
    ) -> Result<NativeJournalTicket, String> {
        let ticket = self.ticket(stream.clone(), boundary, TicketGoal::Sealed)?;
        self.writer_tx
            .send(WriterCommand::Seal {
                stream,
                old_path,
                old_start,
                boundary,
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        Ok(ticket)
    }

    fn request_flush(
        &self,
        stream: String,
        target_seq: u64,
    ) -> Result<NativeJournalTicket, String> {
        let mut state = lock_state(&self.shared);
        let stream_state = state
            .streams
            .get_mut(&stream)
            .ok_or("Watch journal stream is unavailable")?;
        stream_state.requested_seq = stream_state.requested_seq.max(target_seq);
        // Capture the same stream incarnation while its request is registered.
        let retired = stream_state.retired.clone();
        self.shared.cv.notify_all();
        Ok(NativeJournalTicket::new(
            self.shared.clone(),
            stream,
            target_seq,
            TicketGoal::Durable,
            retired,
        ))
    }

    fn seed(&self, stream: &str, seq: u64) -> Result<(), String> {
        let mut state = lock_state(&self.shared);
        let stream_state = state
            .streams
            .get_mut(stream)
            .filter(|stream| !stream.closing)
            .ok_or("Watch journal stream is unavailable")?;
        if stream_state.write_count == 0 && stream_state.segments.is_empty() {
            stream_state.written_seq = stream_state.written_seq.max(seq);
            stream_state.durable_seq = stream_state.durable_seq.max(seq);
            stream_state.requested_seq = stream_state.requested_seq.max(stream_state.durable_seq);
        } else if seq > stream_state.written_seq {
            return Err(format!(
                "cannot seed active Watch journal stream to {seq} past written frontier {}",
                stream_state.written_seq
            ));
        }
        self.shared.cv.notify_all();
        Ok(())
    }

    fn barrier(&self) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::Barrier { done: tx })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        rx.recv()
            .map_err(|_| "native Watch journal writer barrier failed".to_string())
    }

    fn flush_all(&self) -> Result<(), String> {
        self.barrier()?;
        let targets = {
            let mut state = lock_state(&self.shared);
            let mut targets = Vec::with_capacity(state.streams.len());
            for (key, stream) in state.streams.iter_mut() {
                let target = stream.written_seq;
                stream.requested_seq = stream.requested_seq.max(target);
                targets.push((key.clone(), stream.retired.clone(), target));
            }
            self.shared.cv.notify_all();
            targets
        };

        // Keep each captured incarnation, including its retired outcome. A
        // concurrent close/reopen must not erase errors or replace our target.
        for (key, retired, target) in targets {
            self.shared
                .wait_for(&key, &retired, target, TicketGoal::Durable)?;
        }
        Ok(())
    }
}

static JOURNAL_RUNTIME: OnceLock<Arc<JournalRuntime>> = OnceLock::new();

fn runtime() -> &'static Arc<JournalRuntime> {
    JOURNAL_RUNTIME.get_or_init(JournalRuntime::start)
}

fn lock_state(shared: &Shared) -> MutexGuard<'_, RuntimeState> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn stream_failed(shared: &Shared, stream: &str) -> bool {
    lock_state(shared)
        .streams
        .get(stream)
        .and_then(|state| state.error.as_ref())
        .is_some()
}

fn fail_stream(shared: &Shared, stream: &str, error: impl Into<String>) {
    let mut state = lock_state(shared);
    let stream_state = state.streams.entry(stream.to_string()).or_default();
    if stream_state.error.is_none() {
        stream_state.error = Some(error.into());
    }
    retire_closed_stream(&mut state, stream);
    shared.cv.notify_all();
}

fn retire_closed_stream(state: &mut RuntimeState, key: &str) {
    let ready = state.streams.get(key).is_some_and(|s| {
        s.closing && s.owners == 0 && (s.error.is_some() || s.durable_seq >= s.written_seq)
    });
    if !ready {
        return;
    }
    let stream = state.streams.remove(key).expect("checked stream");
    // Removal uniquely owns publication; tickets only read this terminal state.
    let _ = stream.retired.set(StreamFrontier {
        written: stream.written_seq,
        durable: stream.durable_seq,
        sealed: stream.sealed_seq,
        error: stream.error,
    });
    crate::collections::trim_map(&mut state.streams);
}

fn open_segment(path: &Path, kind: Kind) -> io::Result<TrackedFile> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = TrackedFile::open_with(path, "watch_journal_segment", |options| {
        options.create(true).append(true).read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        }
    })?;
    let length = file.metadata()?.len();
    if length == 0 {
        file.write_all(&wal::file_header(kind))?;
    } else {
        let mut header = [0; 16];
        file.read_exact(&mut header)?;
        if header != wal::file_header(kind) {
            return Err(wal::invalid("unsupported binary WAL header"));
        }
    }
    Ok(file)
}

fn segment_file(
    shared: &Shared,
    stream: &str,
    segment_start: u64,
    path: &Path,
    kind: Kind,
) -> io::Result<Arc<TrackedFile>> {
    {
        let state = lock_state(shared);
        if let Some(segment) = state
            .streams
            .get(stream)
            .and_then(|stream_state| stream_state.segments.get(&segment_start))
        {
            if segment.path != path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Watch journal segment start was reused for a different path",
                ));
            }
            return Ok(segment.file.clone());
        }
    }

    let file = Arc::new(open_segment(path, kind)?);
    let mut state = lock_state(shared);
    let stream_state = state.streams.entry(stream.to_string()).or_default();
    if let Some(existing) = stream_state.segments.get(&segment_start) {
        return Ok(existing.file.clone());
    }
    stream_state.segments.insert(
        segment_start,
        SegmentState {
            path: path.to_path_buf(),
            file: file.clone(),
            last_seq: 0,
            write_epoch: 0,
            flushed_epoch: 0,
            sealed_end: None,
        },
    );
    Ok(file)
}

enum JournalPayload {
    Task(Arc<Operations>),
    Catalog(crate::io::scratch::Blob),
}
impl JournalPayload {
    fn kind(&self) -> Kind {
        match self {
            Self::Task(_) => Kind::TaskWal,
            Self::Catalog(_) => Kind::CatalogWal,
        }
    }
    fn encode(&self, output: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Task(ops) => rmp_serde::encode::write(output, ops.as_ref()).map_err(wal::invalid),
            Self::Catalog(bytes) => output.write_all(bytes),
        }
    }
}

struct AppendWorkItem {
    stream: String,
    path: PathBuf,
    segment_start: u64,
    seq: u64,
    operations: JournalPayload,
    durable: bool,
    bytes_written: Arc<AtomicU64>,
}

fn write_append_batch(shared: &Shared, batch: &[AppendWorkItem]) -> io::Result<()> {
    let first = batch
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty journal batch"))?;
    let mut payload = crate::io::scratch::Spool::default();
    let mut record_sizes = Vec::with_capacity(batch.len());
    for item in batch {
        if item.operations.kind() != first.operations.kind() {
            return Err(wal::invalid("mixed WAL types"));
        }
        let start = payload.len()?;
        wal::append_frame(&mut payload, item.seq, |out| item.operations.encode(out))?;
        record_sizes.push(payload.len()? - start);
    }

    // The writer is the only component that can advance written_seq, so this
    // validation can happen before the single batched write without another
    // serialization lock around the I/O itself.
    {
        let state = lock_state(shared);
        let written = state
            .streams
            .get(&first.stream)
            .map(|stream| stream.written_seq)
            .unwrap_or(0);
        let mut previous = written;
        for item in batch {
            if previous.checked_add(1) != Some(item.seq) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "non-monotonic Watch journal sequence: written={previous}, got={}",
                        item.seq
                    ),
                ));
            }
            previous = item.seq;
        }
    }

    let file = segment_file(
        shared,
        &first.stream,
        first.segment_start,
        &first.path,
        first.operations.kind(),
    )?;
    file.write_shared(&payload.finish()?)?;

    let mut state = lock_state(shared);
    let stream_state = state.streams.entry(first.stream.clone()).or_default();
    let last_seq = batch.last().expect("non-empty batch").seq;
    {
        let segment = stream_state
            .segments
            .get_mut(&first.segment_start)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Watch journal segment disappeared")
            })?;
        segment.last_seq = last_seq;
        segment.write_epoch = segment.write_epoch.saturating_add(batch.len() as u64);
    }
    stream_state.written_seq = last_seq;
    stream_state.write_count = stream_state.write_count.saturating_add(batch.len() as u64);
    stream_state.write_calls = stream_state.write_calls.saturating_add(1);
    if let Some(target) = batch
        .iter()
        .filter(|item| item.durable)
        .map(|item| item.seq)
        .max()
    {
        stream_state.requested_seq = stream_state.requested_seq.max(target);
    }
    for (item, size) in batch.iter().zip(record_sizes) {
        item.bytes_written.store(size as u64, Ordering::Release);
    }
    shared.cv.notify_all();
    Ok(())
}

fn writer_loop(shared: Arc<Shared>, rx: mpsc::Receiver<WriterCommand>) {
    let mut pending: Option<WriterCommand> = None;
    let mut batch = Vec::new();
    loop {
        let command = match pending.take() {
            Some(command) => command,
            None => match rx.recv() {
                Ok(command) => command,
                Err(_) => break,
            },
        };
        match command {
            WriterCommand::Open { stream, done } => {
                let mut state = lock_state(&shared);
                let entry = state.streams.entry(stream).or_default();
                entry.owners += 1;
                entry.closing = false;
                shared.cv.notify_all();
                let _ = done.send(());
            }
            WriterCommand::Release { stream, done } => {
                let mut state = lock_state(&shared);
                let mut target = 0;
                if let Some(entry) = state.streams.get_mut(&stream) {
                    target = entry.written_seq;
                    entry.requested_seq = entry.requested_seq.max(target);
                    entry.owners = entry.owners.saturating_sub(1);
                    if entry.owners == 0 {
                        entry.closing = true;
                    }
                }
                retire_closed_stream(&mut state, &stream);
                shared.cv.notify_all();
                if let Some(done) = done {
                    let _ = done.send(target);
                }
            }
            WriterCommand::Append(first) => {
                batch.push(first);
                // Zero-wait opportunistic batching: once one append is ready,
                // consume only commands that are already queued for the same
                // stream/segment. Never sleep to manufacture a writer batch.
                while batch.len() < WRITER_BATCH_MAX_RECORDS {
                    match rx.try_recv() {
                        Ok(WriterCommand::Append(next))
                            if next.stream == batch[0].stream
                                && next.path == batch[0].path
                                && next.segment_start == batch[0].segment_start =>
                        {
                            batch.push(next);
                        }
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => break,
                    }
                }

                let batch_stream = &batch[0].stream;
                if stream_failed(&shared, batch_stream) {
                    shared.cv.notify_all();
                } else if let Err(error) = write_append_batch(&shared, &batch) {
                    fail_stream(
                        &shared,
                        batch_stream,
                        format!("native Watch journal append failed: {error}"),
                    );
                }
                batch.clear();
            }
            WriterCommand::Seal {
                stream,
                old_path,
                old_start,
                boundary,
            } => {
                if stream_failed(&shared, &stream) {
                    shared.cv.notify_all();
                    continue;
                }
                let mut state = lock_state(&shared);
                let stream_state = state.streams.entry(stream.clone()).or_default();
                if let Some(segment) = stream_state.segments.get_mut(&old_start) {
                    if segment.path != old_path {
                        drop(state);
                        fail_stream(
                            &shared,
                            &stream,
                            "native Watch journal seal path did not match active segment",
                        );
                        continue;
                    }
                    segment.sealed_end = Some(boundary);
                    let already_clean = segment.flushed_epoch >= segment.write_epoch;
                    if stream_state.durable_seq >= boundary && already_clean {
                        stream_state.segments.remove(&old_start);
                        stream_state.sealed_seq = stream_state.sealed_seq.max(boundary);
                    } else {
                        stream_state.requested_seq = stream_state.requested_seq.max(boundary);
                    }
                } else if stream_state.durable_seq >= boundary {
                    // A segment loaded from a previous process has no native handle;
                    // startup seeding already establishes that prefix as durable.
                    stream_state.sealed_seq = stream_state.sealed_seq.max(boundary);
                } else {
                    drop(state);
                    fail_stream(
                        &shared,
                        &stream,
                        format!(
                            "cannot seal unknown non-durable Watch journal segment through {boundary}"
                        ),
                    );
                    continue;
                }
                shared.cv.notify_all();
            }
            WriterCommand::Barrier { done } => {
                let _ = done.send(());
            }
        }
    }
}

struct FlushSnapshot {
    start: u64,
    epoch: u64,
    file: Arc<TrackedFile>,
}

struct FlushWork {
    stream: String,
    retired: Arc<OnceLock<StreamFrontier>>,
    target: u64,
    segments: Vec<FlushSnapshot>,
}

fn close_ready_segments(stream: &mut StreamState) {
    stream.segments.retain(|_, segment| {
        let ready = segment.sealed_end.filter(|&boundary| {
            boundary <= stream.durable_seq && segment.flushed_epoch >= segment.write_epoch
        });
        if let Some(boundary) = ready {
            stream.sealed_seq = stream.sealed_seq.max(boundary);
            return false;
        }
        true
    });
}

fn adaptive_coalesce_window(activity_during_probe: bool, last_flush_micros: u64) -> u64 {
    if !activity_during_probe {
        return DURABLE_SINGLE_PROBE_MICROS;
    }
    if last_flush_micros >= DURABLE_SLOW_STORAGE_THRESHOLD_MICROS {
        DURABLE_SLOW_STORAGE_COALESCE_MICROS
    } else {
        DURABLE_BURST_COALESCE_MICROS
    }
}

fn next_flush_work(shared: &Shared) -> FlushWork {
    let mut state = lock_state(shared);
    loop {
        let candidate = state
            .streams
            .iter()
            .find(|(_, stream)| {
                stream.error.is_none()
                    && stream.requested_seq > stream.durable_seq
                    && stream.written_seq >= stream.requested_seq
            })
            .map(|(key, stream)| (key.clone(), stream.written_seq, stream.requested_seq));

        if let Some((key, initial_written, initial_requested)) = candidate {
            // Probe briefly first. An isolated commit pays only 50us rather than
            // the old fixed 500us. If writer/requested frontiers are still
            // advancing, extend the window so a burst shares one physical flush.
            drop(state);
            thread::sleep(Duration::from_micros(DURABLE_SINGLE_PROBE_MICROS));
            state = lock_state(shared);
            let (activity, window) = {
                let Some(stream) = state.streams.get(&key) else {
                    continue;
                };
                if stream.error.is_some()
                    || stream.requested_seq <= stream.durable_seq
                    || stream.written_seq < stream.requested_seq
                {
                    continue;
                }
                let activity = stream.written_seq > initial_written
                    || stream.requested_seq > initial_requested;
                (
                    activity,
                    adaptive_coalesce_window(activity, stream.last_flush_micros),
                )
            };
            if activity && window > DURABLE_SINGLE_PROBE_MICROS {
                drop(state);
                thread::sleep(Duration::from_micros(window - DURABLE_SINGLE_PROBE_MICROS));
                state = lock_state(shared);
            }

            let Some(stream) = state.streams.get_mut(&key) else {
                continue;
            };
            if stream.error.is_some()
                || stream.requested_seq <= stream.durable_seq
                || stream.written_seq < stream.requested_seq
            {
                continue;
            }
            let target = stream.written_seq;
            let segments: Vec<FlushSnapshot> = stream
                .segments
                .iter()
                .filter(|(_, segment)| {
                    segment.last_seq != 0
                        && segment.last_seq <= target
                        && segment.flushed_epoch < segment.write_epoch
                })
                .map(|(start, segment)| FlushSnapshot {
                    start: *start,
                    epoch: segment.write_epoch,
                    file: segment.file.clone(),
                })
                .collect();

            if segments.is_empty() {
                stream.durable_seq = stream.durable_seq.max(target);
                close_ready_segments(stream);
                retire_closed_stream(&mut state, &key);
                shared.cv.notify_all();
                continue;
            }

            stream.coalesce_micros_total = stream.coalesce_micros_total.saturating_add(window);
            return FlushWork {
                stream: key,
                retired: stream.retired.clone(),
                target,
                segments,
            };
        }

        state = shared
            .cv
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

fn flusher_loop(shared: Arc<Shared>) {
    loop {
        let work = next_flush_work(&shared);
        let FlushWork {
            stream,
            retired,
            target,
            segments,
        } = work;
        let epochs: Vec<(u64, u64)> = segments
            .iter()
            .map(|segment| (segment.start, segment.epoch))
            .collect();
        let flush_started = Instant::now();
        let mut flush_error = None;
        for segment in &segments {
            if let Err(error) = segment.file.sync_all() {
                flush_error = Some(error);
                break;
            }
        }
        let flush_calls = segments.len() as u64;
        let flush_micros = flush_started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        drop(segments);

        let mut state = lock_state(&shared);
        let Some(stream_state) = state.streams.get_mut(&stream) else {
            continue;
        };
        // A failed old stream may have been retired and reopened during fsync.
        if !Arc::ptr_eq(&stream_state.retired, &retired) {
            continue;
        }
        if let Some(error) = flush_error {
            stream_state
                .error
                .get_or_insert_with(|| format!("native Watch journal flush failed: {error}"));
            retire_closed_stream(&mut state, &stream);
            shared.cv.notify_all();
            continue;
        }
        for (start, epoch) in epochs {
            if let Some(segment) = stream_state.segments.get_mut(&start) {
                segment.flushed_epoch = segment.flushed_epoch.max(epoch);
            }
        }
        stream_state.flush_rounds = stream_state.flush_rounds.saturating_add(1);
        stream_state.flush_calls = stream_state.flush_calls.saturating_add(flush_calls);
        stream_state.last_flush_micros = flush_micros;
        stream_state.durable_seq = stream_state.durable_seq.max(target);
        close_ready_segments(stream_state);
        retire_closed_stream(&mut state, &stream);
        shared.cv.notify_all();
    }
}

#[pyfunction]
pub(crate) fn watch_journal_open(py: Python<'_>, stream: String) -> PyResult<NativeJournalStream> {
    py.detach(|| runtime().open(stream))
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_submit_append(
    stream: String,
    path: String,
    segment_start: u64,
    seq: u64,
    operations: PyRef<'_, NativeWatchOperations>,
    durable: bool,
) -> PyResult<NativeJournalTicket> {
    let operations = JournalPayload::Task(Arc::clone(&operations.operations));
    runtime()
        .submit_append(
            stream,
            PathBuf::from(path),
            segment_start,
            seq,
            operations,
            durable,
        )
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_submit_seal(
    stream: String,
    old_path: String,
    old_start: u64,
    boundary: u64,
) -> PyResult<NativeJournalTicket> {
    runtime()
        .submit_seal(stream, PathBuf::from(old_path), old_start, boundary)
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_request_flush(
    stream: String,
    target_seq: u64,
) -> PyResult<NativeJournalTicket> {
    runtime()
        .request_flush(stream, target_seq)
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_seed(stream: &str, seq: u64) -> PyResult<()> {
    runtime().seed(stream, seq).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_flush_all(py: Python<'_>) -> PyResult<()> {
    py.detach(|| runtime().flush_all())
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
pub(crate) fn watch_journal_stats(py: Python<'_>, stream: String) -> PyResult<Py<PyDict>> {
    let state = lock_state(&runtime().shared);
    let snapshot = state.streams.get(&stream);
    let result = PyDict::new(py);
    result.set_item("registered", snapshot.is_some())?;
    result.set_item("owners", snapshot.map_or(0, |s| s.owners))?;
    if let Some(stream) = snapshot {
        result.set_item("written_seq", stream.written_seq)?;
        result.set_item("durable_seq", stream.durable_seq)?;
        result.set_item("requested_seq", stream.requested_seq)?;
        result.set_item("sealed_seq", stream.sealed_seq)?;
        result.set_item("write_count", stream.write_count)?;
        result.set_item("write_calls", stream.write_calls)?;
        result.set_item("flush_rounds", stream.flush_rounds)?;
        result.set_item("flush_calls", stream.flush_calls)?;
        result.set_item("last_flush_micros", stream.last_flush_micros)?;
        result.set_item("coalesce_micros_total", stream.coalesce_micros_total)?;
        result.set_item("segments", stream.segments.len())?;
        result.set_item("error", stream.error.clone())?;
    } else {
        result.set_item("written_seq", 0)?;
        result.set_item("durable_seq", 0)?;
        result.set_item("requested_seq", 0)?;
        result.set_item("sealed_seq", 0)?;
        result.set_item("write_count", 0)?;
        result.set_item("write_calls", 0)?;
        result.set_item("flush_rounds", 0)?;
        result.set_item("flush_calls", 0)?;
        result.set_item("last_flush_micros", 0)?;
        result.set_item("coalesce_micros_total", 0)?;
        result.set_item("segments", 0)?;
        result.set_item("error", Option::<String>::None)?;
    }
    Ok(result.unbind())
}

#[cfg(test)]
mod tests {
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
        let mut owner = runtime.open(stream.clone()).unwrap();
        runtime.seed(&stream, 1).unwrap();
        let ticket = runtime.request_flush(stream.clone(), 1).unwrap();
        runtime.release(owner.stream.take().unwrap()).unwrap();

        assert!(runtime.request_flush(stream.clone(), 1).is_err());
        assert!(runtime.seed(&stream, 1).is_err());
        assert!(!lock_state(&runtime.shared).streams.contains_key(&stream));
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
                lock_state(&shared).streams.insert(
                    "stream".to_string(),
                    StreamState {
                        written_seq: 1,
                        ..StreamState::default()
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
                stream.closing = true;
                if failed {
                    stream.error = Some("old stream failed".to_string());
                } else {
                    stream.durable_seq = 1;
                }
                retire_closed_stream(&mut state, "stream");
                if reopen {
                    state.streams.insert(
                        "stream".to_string(),
                        StreamState {
                            written_seq: 1,
                            durable_seq: 1,
                            error: (!failed).then(|| "new stream failed".to_string()),
                            ..StreamState::default()
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
        let stream = path.to_string_lossy().to_string();
        let mut owner = runtime.open(stream.clone()).unwrap();
        let ticket = runtime
            .submit_append(
                stream.clone(),
                path.clone(),
                1,
                1,
                empty_operations(),
                false,
            )
            .unwrap();
        ticket.wait_for(TicketGoal::Written).unwrap();
        runtime
            .request_flush(stream.clone(), 1)
            .unwrap()
            .wait_for(TicketGoal::Durable)
            .unwrap();
        let first = {
            let state = lock_state(&runtime.shared);
            state.streams.get(&stream).unwrap().flush_calls
        };
        runtime
            .request_flush(stream.clone(), 1)
            .unwrap()
            .wait_for(TicketGoal::Durable)
            .unwrap();
        let second = {
            let state = lock_state(&runtime.shared);
            state.streams.get(&stream).unwrap().flush_calls
        };
        assert_eq!(first, second);
        runtime.release(owner.stream.take().unwrap()).unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn seal_waits_for_durable_boundary_and_releases_segment() {
        let runtime = runtime();
        let path = unique_path("seal");
        let stream = path.to_string_lossy().to_string();
        let mut owner = runtime.open(stream.clone()).unwrap();
        let append = runtime
            .submit_append(
                stream.clone(),
                path.clone(),
                1,
                1,
                empty_operations(),
                false,
            )
            .unwrap();
        append.wait_for(TicketGoal::Written).unwrap();
        let seal = runtime
            .submit_seal(stream.clone(), path.clone(), 1, 1)
            .unwrap();
        seal.wait_for(TicketGoal::Sealed).unwrap();
        let state = lock_state(&runtime.shared);
        let stream_state = state.streams.get(&stream).unwrap();
        assert!(stream_state.durable_seq >= 1);
        assert!(stream_state.sealed_seq >= 1);
        assert!(!stream_state.segments.contains_key(&1));
        drop(state);
        runtime.release(owner.stream.take().unwrap()).unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn adaptive_coalescing_keeps_idle_commit_short_and_extends_bursts() {
        assert_eq!(
            adaptive_coalesce_window(false, 0),
            DURABLE_SINGLE_PROBE_MICROS
        );
        assert_eq!(
            adaptive_coalesce_window(true, 1_000),
            DURABLE_BURST_COALESCE_MICROS
        );
        assert_eq!(
            adaptive_coalesce_window(true, DURABLE_SLOW_STORAGE_THRESHOLD_MICROS),
            DURABLE_SLOW_STORAGE_COALESCE_MICROS
        );
    }

    #[test]
    fn writer_batches_already_queued_appends_without_waiting() {
        let shared = Arc::new(Shared::new());
        let (tx, rx) = mpsc::channel();
        let path = unique_path("writer_batch");
        let stream = path.to_string_lossy().to_string();
        for seq in 1..=32u64 {
            tx.send(WriterCommand::Append(AppendWorkItem {
                stream: stream.clone(),
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
        let stream_state = state.streams.get(&stream).unwrap();
        assert_eq!(stream_state.written_seq, 32);
        assert_eq!(stream_state.write_count, 32);
        assert_eq!(stream_state.write_calls, 1);
        drop(state);
        let _ = fs::remove_file(path);
    }
}

// Catalog cache uses the same ordered writer, on its own stream and files.
pub(crate) fn open_cache(stream: String, seq: u64) -> Result<NativeJournalStream, String> {
    let handle = runtime().open(stream.clone())?;
    runtime().seed(&stream, seq)?;
    Ok(handle)
}
pub(crate) fn append_cache(
    stream: &str,
    path: &Path,
    seq: u64,
    value: crate::io::scratch::Blob,
) -> Result<u64, String> {
    let ticket = runtime().submit_append(
        stream.to_owned(),
        path.to_owned(),
        1,
        seq,
        JournalPayload::Catalog(value),
        false,
    )?;
    ticket.wait_for(TicketGoal::Written)?;
    Ok(ticket.bytes_written())
}
pub(crate) fn flush_cache(stream: &str, seq: u64) -> Result<(), String> {
    runtime()
        .request_flush(stream.to_owned(), seq)?
        .wait_for(TicketGoal::Durable)
}
pub(crate) fn close_cache(handle: &mut NativeJournalStream) -> Result<(), String> {
    if let Some(stream) = handle.stream.take() {
        handle.runtime.release(stream)?;
    }
    Ok(())
}
