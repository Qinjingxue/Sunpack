use crate::io::resource_lifecycle::TrackedFile;
use crate::wal::{self, Kind};
use crate::watch_store::{NativeWatchOperations, Operations};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;

const WRITER_BATCH_MAX_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug)]
enum TicketGoal {
    Written,
    Durable,
    Sealed,
}

pub(crate) struct NativeJournalTicket {
    shared: Arc<Shared>,
    stream: Arc<StreamId>,
    seq: u64,
    goal: TicketGoal,
    bytes_written: Option<Arc<AtomicU64>>,
}

impl NativeJournalTicket {
    fn new(shared: Arc<Shared>, stream: Arc<StreamId>, seq: u64, goal: TicketGoal) -> Self {
        Self {
            shared,
            stream,
            seq,
            goal,
            bytes_written: None,
        }
    }

    fn wait_for(&self, goal: TicketGoal) -> Result<(), String> {
        self.shared.wait_for(&self.stream, self.seq, goal)
    }
}

impl Shared {
    fn wait_for(&self, id: &Arc<StreamId>, seq: u64, goal: TicketGoal) -> Result<(), String> {
        let mut state = lock_state(self);
        loop {
            match state.streams.get(id.key.as_ref()) {
                Some(stream) if Arc::ptr_eq(&stream.id, id) => {
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
                    let frontier = id
                        .retired
                        .get()
                        .ok_or("Watch journal stream is unavailable")?;
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

struct StreamId {
    key: Arc<str>,
    retired: OnceLock<StreamFrontier>,
}

/// A store owns a stream until drain/checkpoint completion. Dropping a store
/// also submits release through the existing writer, without blocking the caller.
pub(crate) struct NativeJournalStream {
    runtime: Arc<JournalRuntime>,
    stream: Option<Arc<StreamId>>,
}

impl NativeJournalStream {
    pub(crate) fn open_seeded(stream: String, seq: u64) -> Result<Self, String> {
        let handle = runtime().open(stream)?;
        handle.runtime.seed(&handle.id().key, seq)?;
        Ok(handle)
    }

    fn id(&self) -> &Arc<StreamId> {
        self.stream.as_ref().expect("open Watch journal stream")
    }

    pub(crate) fn submit_task_append(
        &self,
        path: PathBuf,
        segment_start: u64,
        seq: u64,
        operations: &NativeWatchOperations,
        durable: bool,
    ) -> io::Result<NativeJournalTicket> {
        self.runtime
            .submit_append(
                self.id(),
                path,
                segment_start,
                seq,
                JournalPayload::Task(Arc::clone(&operations.operations)),
                durable,
            )
            .map_err(io::Error::other)
    }

    pub(crate) fn submit_seal(
        &self,
        path: PathBuf,
        segment_start: u64,
        boundary: u64,
    ) -> io::Result<NativeJournalTicket> {
        self.runtime
            .submit_seal(self.id(), path, segment_start, boundary)
            .map_err(io::Error::other)
    }

    pub(crate) fn request_flush(&self, seq: u64) -> io::Result<NativeJournalTicket> {
        self.runtime
            .request_flush(self.id(), seq)
            .map_err(io::Error::other)
    }

    pub(crate) fn append_catalog(
        &self,
        path: PathBuf,
        seq: u64,
        value: crate::io::scratch::Blob,
    ) -> io::Result<u64> {
        let ticket = self
            .runtime
            .submit_append(
                self.id(),
                path,
                1,
                seq,
                JournalPayload::Catalog(value),
                false,
            )
            .map_err(io::Error::other)?;
        ticket.wait()?;
        Ok(ticket.bytes_written())
    }

    pub(crate) fn close(mut self) -> Result<(), String> {
        self.runtime
            .release(self.stream.take().expect("open Watch journal stream"))
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

impl NativeJournalTicket {
    pub(crate) fn wait(&self) -> std::io::Result<()> {
        (self.wait_for(self.goal)).map_err(std::io::Error::other)
    }

    pub(crate) fn wait_appends(tickets: &[Self]) -> io::Result<u64> {
        let Some((last, previous)) = tickets.split_last() else {
            return Ok(0);
        };
        // A task's deferred appends share one stream and are sequenced at
        // submission. Only the latest written and durable targets matter.
        if matches!(last.goal, TicketGoal::Written) {
            if let Some(durable) = previous
                .iter()
                .rfind(|ticket| matches!(ticket.goal, TicketGoal::Durable))
            {
                durable.wait()?;
            }
        }
        last.wait()?;
        Ok(tickets
            .iter()
            .map(Self::bytes_written)
            .fold(0u64, u64::saturating_add))
    }

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
    sealed_end: Option<u64>,
}

struct StreamState {
    owners: usize,
    id: Arc<StreamId>,
    written_seq: u64,
    durable_seq: u64,
    requested_seq: u64,
    sealed_seq: u64,
    segments: BTreeMap<u64, SegmentState>,
    error: Option<String>,
    has_written: bool,
    #[cfg(test)]
    write_calls: u64,
    #[cfg(test)]
    flush_calls: u64,
}

impl StreamState {
    fn new(key: Arc<str>) -> Self {
        Self {
            owners: 0,
            id: Arc::new(StreamId {
                key,
                retired: OnceLock::new(),
            }),
            written_seq: 0,
            durable_seq: 0,
            requested_seq: 0,
            sealed_seq: 0,
            segments: BTreeMap::new(),
            error: None,
            has_written: false,
            #[cfg(test)]
            write_calls: 0,
            #[cfg(test)]
            flush_calls: 0,
        }
    }
}

#[derive(Default)]
struct RuntimeState {
    streams: HashMap<Arc<str>, StreamState>,
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
        key: Arc<str>,
        done: mpsc::Sender<Arc<StreamId>>,
    },
    Release {
        stream: Arc<StreamId>,
        done: Option<mpsc::Sender<u64>>,
    },
    Append(AppendWorkItem),
    Seal {
        stream: Arc<StreamId>,
        old_path: PathBuf,
        old_start: u64,
        boundary: u64,
    },
    #[cfg(test)]
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
                key: stream.into(),
                done: tx,
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        let stream = rx
            .recv()
            .map_err(|_| "native Watch journal open barrier failed".to_string())?;
        Ok(NativeJournalStream {
            runtime: self.clone(),
            stream: Some(stream),
        })
    }

    fn release(&self, stream: Arc<StreamId>) -> Result<(), String> {
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
        // The flusher retires the last owner's stream under the same state
        // lock that publishes durability, so this also waits for retirement.
        self.shared.wait_for(&stream, target, TicketGoal::Durable)
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
        stream: &Arc<StreamId>,
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
        let mut ticket = NativeJournalTicket::new(self.shared.clone(), stream.clone(), seq, goal);
        let bytes_written = Arc::new(AtomicU64::new(0));
        ticket.bytes_written = Some(Arc::clone(&bytes_written));
        self.writer_tx
            .send(WriterCommand::Append(AppendWorkItem {
                stream: stream.clone(),
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
        stream: &Arc<StreamId>,
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
                stream: stream.clone(),
                old_path,
                old_start,
                boundary,
            })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        Ok(ticket)
    }

    fn request_flush(
        &self,
        stream: &Arc<StreamId>,
        target_seq: u64,
    ) -> Result<NativeJournalTicket, String> {
        let mut state = lock_state(&self.shared);
        let stream_state = state
            .streams
            .get_mut(stream.key.as_ref())
            .filter(|state| Arc::ptr_eq(&state.id, stream))
            .ok_or("Watch journal stream is unavailable")?;
        stream_state.requested_seq = stream_state.requested_seq.max(target_seq);
        self.shared.cv.notify_all();
        Ok(NativeJournalTicket::new(
            self.shared.clone(),
            stream.clone(),
            target_seq,
            TicketGoal::Durable,
        ))
    }

    fn seed(&self, stream: &str, seq: u64) -> Result<(), String> {
        let mut state = lock_state(&self.shared);
        let stream_state = state
            .streams
            .get_mut(stream)
            .filter(|stream| stream.owners != 0)
            .ok_or("Watch journal stream is unavailable")?;
        if !stream_state.has_written && stream_state.segments.is_empty() {
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

    #[cfg(test)]
    fn barrier(&self) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::Barrier { done: tx })
            .map_err(|_| "native Watch journal writer is unavailable".to_string())?;
        rx.recv()
            .map_err(|_| "native Watch journal writer barrier failed".to_string())
    }

    #[cfg(test)]
    fn flush_all(&self) -> Result<(), String> {
        self.barrier()?;
        let targets = {
            let mut state = lock_state(&self.shared);
            let mut targets = Vec::with_capacity(state.streams.len());
            for stream in state.streams.values_mut() {
                let target = stream.written_seq;
                stream.requested_seq = stream.requested_seq.max(target);
                targets.push((stream.id.clone(), target));
            }
            self.shared.cv.notify_all();
            targets
        };

        // Keep each captured incarnation, including its retired outcome. A
        // concurrent close/reopen must not erase errors or replace our target.
        for (stream, target) in targets {
            self.shared.wait_for(&stream, target, TicketGoal::Durable)?;
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

fn fail_stream(shared: &Shared, stream: &str, error: impl Into<String>) {
    let mut state = lock_state(shared);
    if let Some(stream_state) = state.streams.get_mut(stream) {
        stream_state.error.get_or_insert_with(|| error.into());
    }
    retire_closed_stream(&mut state, stream);
    shared.cv.notify_all();
}

fn retire_closed_stream(state: &mut RuntimeState, key: &str) {
    let ready = state
        .streams
        .get(key)
        .is_some_and(|s| s.owners == 0 && (s.error.is_some() || s.durable_seq >= s.written_seq));
    if !ready {
        return;
    }
    let stream = state.streams.remove(key).expect("checked stream");
    // Removal uniquely owns publication; tickets only read this terminal state.
    let _ = stream.id.retired.set(StreamFrontier {
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
    let mut file = TrackedFile::open_with(path, |options| {
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
    let stream_state = state
        .streams
        .get_mut(stream)
        .ok_or_else(|| io::Error::other("Watch journal stream is unavailable"))?;
    if let Some(existing) = stream_state.segments.get(&segment_start) {
        return Ok(existing.file.clone());
    }
    stream_state.segments.insert(
        segment_start,
        SegmentState {
            path: path.to_path_buf(),
            file: file.clone(),
            last_seq: 0,
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
    stream: Arc<StreamId>,
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
    let mut previous = {
        let state = lock_state(shared);
        let stream = state
            .streams
            .get(first.stream.key.as_ref())
            .ok_or_else(|| io::Error::other("Watch journal stream is unavailable"))?;
        if stream.error.is_some() {
            return Ok(());
        }
        stream.written_seq
    };
    let mut payload = crate::io::scratch::Spool::default();
    let mut frame_buffer = Vec::new();
    let mut requested = 0;
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
        if item.operations.kind() != first.operations.kind() {
            return Err(wal::invalid("mixed WAL types"));
        }
        let start = payload.len()?;
        wal::append_frame(&mut payload, &mut frame_buffer, item.seq, |out| {
            item.operations.encode(out)
        })?;
        // Only a ticket that reached its written/durable frontier reads this count.
        item.bytes_written
            .store(payload.len()? - start, Ordering::Release);
        if item.durable {
            requested = item.seq;
        }
        previous = item.seq;
    }

    let file = segment_file(
        shared,
        &first.stream.key,
        first.segment_start,
        &first.path,
        first.operations.kind(),
    )?;
    file.write_shared(&payload.finish()?)?;

    let mut state = lock_state(shared);
    let stream_state = state
        .streams
        .get_mut(first.stream.key.as_ref())
        .ok_or_else(|| io::Error::other("Watch journal stream is unavailable"))?;
    let last_seq = batch.last().expect("non-empty batch").seq;
    {
        let segment = stream_state
            .segments
            .get_mut(&first.segment_start)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Watch journal segment disappeared")
            })?;
        segment.last_seq = last_seq;
    }
    stream_state.written_seq = last_seq;
    stream_state.has_written = true;
    #[cfg(test)]
    {
        stream_state.write_calls += 1;
    }
    stream_state.requested_seq = stream_state.requested_seq.max(requested);
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
            WriterCommand::Open { key, done } => {
                let mut state = lock_state(&shared);
                let entry = state
                    .streams
                    .entry(key.clone())
                    .or_insert_with(|| StreamState::new(key));
                entry.owners += 1;
                let id = entry.id.clone();
                shared.cv.notify_all();
                let _ = done.send(id);
            }
            WriterCommand::Release { stream, done } => {
                let mut state = lock_state(&shared);
                let mut target = 0;
                if let Some(entry) = state.streams.get_mut(stream.key.as_ref()) {
                    target = entry.written_seq;
                    entry.requested_seq = entry.requested_seq.max(target);
                    entry.owners = entry.owners.saturating_sub(1);
                }
                retire_closed_stream(&mut state, &stream.key);
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
                            if Arc::ptr_eq(&next.stream, &batch[0].stream)
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

                let batch_stream = &batch[0].stream.key;
                if let Err(error) = write_append_batch(&shared, &batch) {
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
                let mut state = lock_state(&shared);
                let Some(stream_state) = state
                    .streams
                    .get_mut(stream.key.as_ref())
                    .filter(|stream| stream.error.is_none())
                else {
                    continue;
                };
                if let Some(segment) = stream_state.segments.get_mut(&old_start) {
                    if segment.path != old_path {
                        drop(state);
                        fail_stream(
                            &shared,
                            &stream.key,
                            "native Watch journal seal path did not match active segment",
                        );
                        continue;
                    }
                    segment.sealed_end = Some(boundary);
                    let required = segment.last_seq.max(boundary);
                    if required <= stream_state.durable_seq {
                        stream_state.segments.remove(&old_start);
                        stream_state.sealed_seq = stream_state.sealed_seq.max(boundary);
                    } else {
                        stream_state.requested_seq = stream_state.requested_seq.max(required);
                    }
                } else if stream_state.durable_seq >= boundary {
                    // A segment loaded from a previous process has no native handle;
                    // startup seeding already establishes that prefix as durable.
                    stream_state.sealed_seq = stream_state.sealed_seq.max(boundary);
                } else {
                    drop(state);
                    fail_stream(
                        &shared,
                        &stream.key,
                        format!(
                            "cannot seal unknown non-durable Watch journal segment through {boundary}"
                        ),
                    );
                    continue;
                }
                shared.cv.notify_all();
            }
            #[cfg(test)]
            WriterCommand::Barrier { done } => {
                let _ = done.send(());
            }
        }
    }
}

struct FlushWork {
    stream: Arc<StreamId>,
    target: u64,
    files: Vec<Arc<TrackedFile>>,
}

fn close_ready_segments(stream: &mut StreamState) {
    stream.segments.retain(|_, segment| {
        let ready = segment
            .sealed_end
            .filter(|&boundary| segment.last_seq.max(boundary) <= stream.durable_seq);
        if let Some(boundary) = ready {
            stream.sealed_seq = stream.sealed_seq.max(boundary);
            return false;
        }
        true
    });
}

fn next_flush_work(shared: &Shared) -> FlushWork {
    let mut state = lock_state(shared);
    loop {
        let candidate = state
            .streams
            .values_mut()
            .find(|stream| {
                stream.error.is_none()
                    && stream.requested_seq > stream.durable_seq
                    && stream.written_seq >= stream.requested_seq
            });

        if let Some(stream) = candidate {
            let target = stream.written_seq;
            // Coalesce the records already written through this snapshot.
            // Appends published during I/O have a higher sequence than target.
            let files: Vec<_> = stream
                .segments
                .values()
                .filter(|segment| segment.last_seq > stream.durable_seq)
                .map(|segment| segment.file.clone())
                .collect();

            if files.is_empty() {
                stream.durable_seq = stream.durable_seq.max(target);
                close_ready_segments(stream);
                let key = Arc::clone(&stream.id.key);
                retire_closed_stream(&mut state, &key);
                shared.cv.notify_all();
                continue;
            }

            return FlushWork {
                stream: stream.id.clone(),
                target,
                files,
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
            target,
            files,
        } = work;
        #[cfg(test)]
        let flush_calls = files.len() as u64;
        let result = files.into_iter().try_for_each(|file| file.sync_all());

        let mut state = lock_state(&shared);
        let Some(stream_state) = state.streams.get_mut(stream.key.as_ref()) else {
            continue;
        };
        // A failed old stream may have been retired and reopened during fsync.
        if !Arc::ptr_eq(&stream_state.id, &stream) {
            continue;
        }
        if let Err(error) = result {
            stream_state
                .error
                .get_or_insert_with(|| format!("native Watch journal flush failed: {error}"));
            retire_closed_stream(&mut state, &stream.key);
            shared.cv.notify_all();
            continue;
        }
        #[cfg(test)]
        {
            stream_state.flush_calls += flush_calls;
        }
        stream_state.durable_seq = stream_state.durable_seq.max(target);
        close_ready_segments(stream_state);
        retire_closed_stream(&mut state, &stream.key);
        shared.cv.notify_all();
    }
}

#[cfg(test)]
#[path = "../tests/unit/watch_journal/tests.rs"]
mod tests;
