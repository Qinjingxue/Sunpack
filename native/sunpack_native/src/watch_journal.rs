use crate::io::resource_lifecycle::TrackedFile;
use crate::watch_state::{extract_json, write_json_value, JsonValue};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
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
    bytes_written: Arc<AtomicU64>,
    retired: Arc<Mutex<Option<StreamFrontier>>>,
}

impl NativeJournalTicket {
    fn new(shared: Arc<Shared>, stream: String, seq: u64, goal: TicketGoal) -> Self {
        let retired = lock_state(&shared)
            .streams
            .entry(stream.clone())
            .or_default()
            .retired
            .clone();
        Self {
            shared,
            stream,
            seq,
            goal,
            bytes_written: Arc::new(AtomicU64::new(0)),
            retired,
        }
    }

    fn wait_for(&self, goal: TicketGoal) -> Result<(), String> {
        let mut state = lock_state(&self.shared);
        loop {
            match state.streams.get(&self.stream) {
                Some(stream) if Arc::ptr_eq(&stream.retired, &self.retired) => {
                    if let Some(error) = &stream.error {
                        return Err(error.clone());
                    }
                    let done = match goal {
                        TicketGoal::Written => stream.written_seq >= self.seq,
                        TicketGoal::Durable => stream.durable_seq >= self.seq,
                        TicketGoal::Sealed => stream.sealed_seq >= self.seq,
                    };
                    if done {
                        return Ok(());
                    }
                }
                _ => {
                    let retired = self.retired.lock().unwrap_or_else(|p| p.into_inner());
                    let frontier = retired
                        .as_ref()
                        .ok_or("Watch journal stream is unavailable")?;
                    if let Some(error) = &frontier.error {
                        return Err(error.clone());
                    }
                    let done = match goal {
                        TicketGoal::Written => frontier.written >= self.seq,
                        TicketGoal::Durable => frontier.durable >= self.seq,
                        TicketGoal::Sealed => frontier.sealed >= self.seq,
                    };
                    return if done {
                        Ok(())
                    } else {
                        Err("Watch journal stream closed before the requested frontier".to_string())
                    };
                }
            }
            state = self
                .shared
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
            py.detach(|| self.runtime.release(stream, true))
                .map_err(PyRuntimeError::new_err)?;
        }
        Ok(())
    }
}

impl Drop for NativeJournalStream {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = self.runtime.release(stream, false);
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
        self.bytes_written.load(Ordering::Acquire)
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
    retired: Arc<Mutex<Option<StreamFrontier>>>,
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
    Append {
        stream: String,
        path: PathBuf,
        segment_start: u64,
        seq: u64,
        operations: JsonValue,
        durable: bool,
        bytes_written: Arc<AtomicU64>,
    },
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

    fn release(&self, stream: String, wait: bool) -> Result<(), String> {
        let retired = {
            let state = lock_state(&self.shared);
            state.streams.get(&stream).map(|s| s.retired.clone())
        };
        let (tx, rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::Release {
                stream: stream.clone(),
                done: wait.then_some(tx),
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        if !wait {
            return Ok(());
        }
        let target = rx
            .recv()
            .map_err(|_| "native Watch journal release barrier failed".to_string())?;
        let Some(retired) = retired else {
            return Ok(());
        };
        let mut state = lock_state(&self.shared);
        loop {
            if let Some(frontier) = retired.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                return match &frontier.error {
                    Some(error) => Err(error.clone()),
                    None => Ok(()),
                };
            }
            if let Some(entry) = state.streams.get(&stream) {
                if let Some(error) = &entry.error {
                    return Err(error.clone());
                }
                if entry.owners != 0 && entry.durable_seq >= target {
                    return Ok(());
                }
            }
            state = self
                .shared
                .cv
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
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
        operations: JsonValue,
        durable: bool,
    ) -> Result<NativeJournalTicket, String> {
        let goal = if durable {
            TicketGoal::Durable
        } else {
            TicketGoal::Written
        };
        let ticket = NativeJournalTicket::new(self.shared.clone(), stream.clone(), seq, goal);
        self.writer_tx
            .send(WriterCommand::Append {
                stream,
                path,
                segment_start,
                seq,
                operations,
                durable,
                bytes_written: ticket.bytes_written.clone(),
            })
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
        let ticket = NativeJournalTicket::new(
            self.shared.clone(),
            stream.clone(),
            boundary,
            TicketGoal::Sealed,
        );
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

    fn request_flush(&self, stream: String, target_seq: u64) -> NativeJournalTicket {
        {
            let mut state = lock_state(&self.shared);
            let stream_state = state.streams.entry(stream.clone()).or_default();
            stream_state.requested_seq = stream_state.requested_seq.max(target_seq);
            self.shared.cv.notify_all();
        }
        NativeJournalTicket::new(self.shared.clone(), stream, target_seq, TicketGoal::Durable)
    }

    fn seed(&self, stream: String, seq: u64) -> Result<(), String> {
        let mut state = lock_state(&self.shared);
        let stream_state = state.streams.entry(stream).or_default();
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
                if let Some(error) = &stream.error {
                    return Err(error.clone());
                }
                let target = stream.written_seq;
                stream.requested_seq = stream.requested_seq.max(target);
                targets.push((key.clone(), target));
            }
            self.shared.cv.notify_all();
            targets
        };

        let mut state = lock_state(&self.shared);
        loop {
            let mut all_done = true;
            for (key, target) in &targets {
                let Some(stream) = state.streams.get(key) else {
                    continue;
                };
                if let Some(error) = &stream.error {
                    return Err(error.clone());
                }
                if stream.durable_seq < *target {
                    all_done = false;
                    break;
                }
            }
            if all_done {
                return Ok(());
            }
            state = self
                .shared
                .cv
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
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
    *stream.retired.lock().unwrap_or_else(|p| p.into_inner()) = Some(StreamFrontier {
        written: stream.written_seq,
        durable: stream.durable_seq,
        sealed: stream.sealed_seq,
        error: stream.error.clone(),
    });
    if state.streams.is_empty() {
        state.streams = HashMap::new();
    } else if state.streams.capacity() > 256.max(state.streams.len().saturating_mul(4)) {
        state
            .streams
            .shrink_to(state.streams.len().saturating_mul(2));
    }
}

fn open_segment(path: &Path) -> io::Result<TrackedFile> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    TrackedFile::open_with(path, "watch_journal_segment", |options| {
        options.create(true).append(true).read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        }
    })
}

fn segment_file(
    shared: &Shared,
    stream: &str,
    segment_start: u64,
    path: &Path,
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

    let file = Arc::new(open_segment(path)?);
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

fn encode_transaction(seq: u64, operations: &JsonValue) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(b"{\"seq\":");
    payload.extend_from_slice(seq.to_string().as_bytes());
    payload.extend_from_slice(b",\"operations\":");
    write_json_value(&mut payload, operations)?;
    payload.extend_from_slice(b"}\n");
    Ok(payload)
}

fn write_file(file: &TrackedFile, payload: &[u8]) -> io::Result<()> {
    file.write_shared(payload)
}

struct AppendWorkItem {
    stream: String,
    path: PathBuf,
    segment_start: u64,
    seq: u64,
    operations: JsonValue,
    durable: bool,
    bytes_written: Arc<AtomicU64>,
}

fn append_work_item(
    stream: String,
    path: PathBuf,
    segment_start: u64,
    seq: u64,
    operations: JsonValue,
    durable: bool,
    bytes_written: Arc<AtomicU64>,
) -> AppendWorkItem {
    AppendWorkItem {
        stream,
        path,
        segment_start,
        seq,
        operations,
        durable,
        bytes_written,
    }
}

fn write_append_batch(shared: &Shared, batch: &[AppendWorkItem]) -> io::Result<()> {
    let first = batch
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty journal batch"))?;
    let mut payload = Vec::with_capacity(batch.len().saturating_mul(512));
    let mut record_sizes = Vec::with_capacity(batch.len());
    for item in batch {
        let encoded = encode_transaction(item.seq, &item.operations)?;
        record_sizes.push(encoded.len());
        payload.extend_from_slice(&encoded);
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
            if item.seq <= previous {
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

    let file = segment_file(shared, &first.stream, first.segment_start, &first.path)?;
    write_file(&file, &payload)?;

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
                        entry.requested_seq = entry.requested_seq.max(entry.written_seq);
                    }
                }
                retire_closed_stream(&mut state, &stream);
                shared.cv.notify_all();
                if let Some(done) = done {
                    let _ = done.send(target);
                }
            }
            WriterCommand::Append {
                stream,
                path,
                segment_start,
                seq,
                operations,
                durable,
                bytes_written,
            } => {
                let batch_stream = stream.clone();
                let batch_path = path.clone();
                let batch_start = segment_start;
                let mut batch = vec![append_work_item(
                    stream,
                    path,
                    segment_start,
                    seq,
                    operations,
                    durable,
                    bytes_written,
                )];

                // Zero-wait opportunistic batching: once one append is ready,
                // consume only commands that are already queued for the same
                // stream/segment. Never sleep to manufacture a writer batch.
                while batch.len() < WRITER_BATCH_MAX_RECORDS {
                    match rx.try_recv() {
                        Ok(WriterCommand::Append {
                            stream,
                            path,
                            segment_start,
                            seq,
                            operations,
                            durable,
                            bytes_written,
                        }) => {
                            if stream == batch_stream
                                && path == batch_path
                                && segment_start == batch_start
                            {
                                batch.push(append_work_item(
                                    stream,
                                    path,
                                    segment_start,
                                    seq,
                                    operations,
                                    durable,
                                    bytes_written,
                                ));
                            } else {
                                pending = Some(WriterCommand::Append {
                                    stream,
                                    path,
                                    segment_start,
                                    seq,
                                    operations,
                                    durable,
                                    bytes_written,
                                });
                                break;
                            }
                        }
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => break,
                    }
                }

                if stream_failed(&shared, &batch_stream) {
                    shared.cv.notify_all();
                    continue;
                }
                if let Err(error) = write_append_batch(&shared, &batch) {
                    fail_stream(
                        &shared,
                        &batch_stream,
                        format!("native Watch journal append failed: {error}"),
                    );
                }
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
    retired: Arc<Mutex<Option<StreamFrontier>>>,
    target: u64,
    segments: Vec<FlushSnapshot>,
}

fn close_ready_segments(stream: &mut StreamState) {
    let ready: Vec<(u64, u64)> = stream
        .segments
        .iter()
        .filter_map(|(start, segment)| {
            let boundary = segment.sealed_end?;
            (boundary <= stream.durable_seq && segment.flushed_epoch >= segment.write_epoch)
                .then_some((*start, boundary))
        })
        .collect();
    for (start, boundary) in ready {
        stream.segments.remove(&start);
        stream.sealed_seq = stream.sealed_seq.max(boundary);
    }
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
    operations: &Bound<'_, PyAny>,
    durable: bool,
) -> PyResult<NativeJournalTicket> {
    let operations = extract_json(operations)?;
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
pub(crate) fn watch_journal_request_flush(stream: String, target_seq: u64) -> NativeJournalTicket {
    runtime().request_flush(stream, target_seq)
}

#[pyfunction]
pub(crate) fn watch_journal_seed(stream: String, seq: u64) -> PyResult<()> {
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
        std::env::temp_dir().join(format!("sunpack_watch_journal_{label}_{nonce}.jsonl"))
    }

    fn empty_operations() -> JsonValue {
        JsonValue::Array(Vec::new())
    }

    #[test]
    fn clean_flush_does_not_issue_another_physical_sync() {
        let runtime = runtime();
        let path = unique_path("clean_flush");
        let stream = path.to_string_lossy().to_string();
        runtime.seed(stream.clone(), 0).unwrap();
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
            .wait_for(TicketGoal::Durable)
            .unwrap();
        let first = {
            let state = lock_state(&runtime.shared);
            state.streams.get(&stream).unwrap().flush_calls
        };
        runtime
            .request_flush(stream.clone(), 1)
            .wait_for(TicketGoal::Durable)
            .unwrap();
        let second = {
            let state = lock_state(&runtime.shared);
            state.streams.get(&stream).unwrap().flush_calls
        };
        assert_eq!(first, second);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn seal_waits_for_durable_boundary_and_releases_segment() {
        let runtime = runtime();
        let path = unique_path("seal");
        let stream = path.to_string_lossy().to_string();
        runtime.seed(stream.clone(), 0).unwrap();
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
            tx.send(WriterCommand::Append {
                stream: stream.clone(),
                path: path.clone(),
                segment_start: 1,
                seq,
                operations: empty_operations(),
                durable: false,
                bytes_written: Arc::new(AtomicU64::new(0)),
            })
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
