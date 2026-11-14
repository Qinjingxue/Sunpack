//! One multiplexed worker per engine. Each live job retains its result
//! assembly and coalesces byte progress and resource state independently.

use super::{ResourceWait, WorkerUpdates};
#[cfg(test)]
pub(crate) use tests::coalesced_wait_batches;
use crate::core::config::{ProcessMode, WorkerConfig};
use crate::io::cancellation::Cancellation;
use crate::scan::worker_event::{NativeWorkerResultAccumulator, WorkerFrame};
use crate::scan::worker_wire::{encode_worker_frame, NativeWorkerFrameDecoder};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

pub(super) struct Process {
    owner: Option<JoinHandle<()>>,
    child: Arc<Mutex<Option<Child>>>,
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    stderr: Mutex<StderrHistory>,
    changed: Condvar,
    shutting_down: AtomicBool,
}

// Match main's diagnostic tail without allowing an unterminated native line
// to grow memory. UTF-8 needs at most four bytes per retained character.
const STDERR_TAIL_CHARS: usize = 4000;
const STDERR_TAIL_LINES: usize = 40;
const STDERR_TAIL_BYTES: usize = STDERR_TAIL_CHARS * 4;

#[derive(Default)]
struct StderrHistory { bytes: VecDeque<u8> }

impl StderrHistory {
    fn append(&mut self, bytes: &[u8]) {
        let bytes = &bytes[bytes.len().saturating_sub(STDERR_TAIL_BYTES)..];
        let remove = (self.bytes.len() + bytes.len()).saturating_sub(STDERR_TAIL_BYTES);
        self.bytes.drain(..remove);
        self.bytes.extend(bytes.iter().copied());
    }

    fn take(&mut self) -> String {
        let bytes: Vec<_> = self.bytes.drain(..).collect();
        let text = String::from_utf8_lossy(&bytes);
        let start = text.char_indices().rev().nth(STDERR_TAIL_CHARS - 1)
            .map_or(0, |(offset, _)| offset);
        let tail = &text[start..];
        let lines = tail.strip_suffix('\n').unwrap_or(tail);
        let start = lines.rmatch_indices('\n').nth(STDERR_TAIL_LINES - 1)
            .map_or(0, |(offset, _)| offset + 1);
        tail[start..].to_owned()
    }
}

fn pump_stderr(mut pipe: impl Read, shared: &Shared) {
    let mut block = [0; 4096];
    let mut pending = Vec::with_capacity(block.len() + 3);
    loop {
        let count = match pipe.read(&mut block) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        pending.extend_from_slice(&block[..count]);
        let mut consumed = 0;
        // Preserve incomplete UTF-8 across pipe reads. Result publication must
        // not turn a split character into two replacement characters.
        while consumed < pending.len() {
            match std::str::from_utf8(&pending[consumed..]) {
                Ok(_) => {
                    shared.stderr.lock().unwrap().append(&pending[consumed..]);
                    consumed = pending.len();
                }
                Err(error) => {
                    let valid_end = consumed + error.valid_up_to();
                    shared.stderr.lock().unwrap().append(&pending[consumed..valid_end]);
                    consumed = valid_end;
                    let Some(invalid) = error.error_len() else { break; };
                    shared.stderr.lock().unwrap().append("�".as_bytes());
                    consumed += invalid;
                }
            }
        }
        pending.drain(..consumed);
    }
    if !pending.is_empty() { shared.stderr.lock().unwrap().append("�".as_bytes()); }
}

#[derive(Default)]
struct State {
    pid: u32,
    jobs: HashMap<String, Job>,
    parked: VecDeque<(String, Arc<Mailbox>)>,
    ready: bool,
    thread_capacity: usize,
    startup_mode: Option<ProcessMode>,
    startup_command: Option<ProcessMode>,
    ready_waiters: HashMap<u64, Option<Waker>>,
    next_waiter: u64,
    abort_startup: Option<WorkerExit>,
    startup_abandoned: bool,
    applied_mode: Option<ProcessMode>,
    mode_reply: Option<(Option<ProcessMode>, bool)>,
    mode_waiter: Option<Waker>,
    closed: Option<WorkerExit>,
    input_closed: bool,
    writes: VecDeque<InputFrame>,
    completion_epoch: u64,
    claimed_epoch: u64,
}

struct ModeWaiter<'a>(&'a Shared);
impl Drop for ModeWaiter<'_> {
    fn drop(&mut self) { self.0.state.lock().unwrap().mode_waiter.take(); }
}

// One outstanding write per awaiting sender. Queue entries share the sender's
// encoded bytes, including retries; the writer never holds the state lock while
// touching the pipe. Awaiting its receipt gives submit/cancel drain backpressure
// without retaining a scheduler slot or creating a thread per request.
struct InputFrame {
    bytes: Arc<Vec<u8>>,
    completion: Arc<WriteCompletion>,
}

#[derive(Default)]
struct WriteCompletion {
    state: Mutex<WriteState>,
    changed: Condvar,
}

#[derive(Default)]
struct WriteState {
    result: Option<io::Result<()>>,
    waker: Option<Waker>,
}

impl WriteCompletion {
    fn finish(&self, result: io::Result<()>) {
        let wake = {
            let mut state = self.state.lock().unwrap();
            state.result = Some(result);
            state.waker.take()
        };
        self.changed.notify_all();
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result.take() {
            Poll::Ready(result)
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    async fn wait(&self) -> io::Result<()> {
        poll_fn(|cx| self.poll(cx)).await
    }

    // Final shutdown and synchronous transport tests use the same ordered
    // writer as asynchronous submissions and process-mode changes.
    fn wait_blocking(&self) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        let mut state = self
            .changed
            .wait_while(state, |state| state.result.is_none())
            .unwrap();
        state.result.take().unwrap()
    }
}

#[derive(Debug)]
pub(super) struct CommunicationError {
    pub(super) kind: &'static str,
    message: String,
}
impl std::fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) }
}
impl std::error::Error for CommunicationError {}

#[derive(Clone)]
struct WorkerExit {
    failure_kind: &'static str,
    message: String,
    kind: io::ErrorKind,
}

impl WorkerExit {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, CommunicationError { kind: self.failure_kind, message: self.message.clone() })
    }
}

struct Job {
    mailbox: Arc<Mailbox>,
    accumulator: Option<NativeWorkerResultAccumulator>,
    submission_epoch: u64,
    result: Option<io::Result<WorkerFrame>>,
    disk: Episode,
    memory: Episode,
    resources: ResourceWait,
}

impl Job {
    fn new(id: &str, mailbox: Arc<Mailbox>, submission_epoch: u64) -> Self {
        Self {
            mailbox,
            accumulator: Some(NativeWorkerResultAccumulator::new(id.to_owned())),
            submission_epoch,
            result: None,
            disk: Episode::default(),
            memory: Episode::default(),
            resources: ResourceWait::default(),
        }
    }

    fn protocol_error(&mut self, error: io::Error) {
        self.result = Some(Err(io::Error::new(error.kind(), CommunicationError { kind: "process_io", message: error.to_string() })));
        self.accumulator.take();
        // Wake the existing submission waiter to use its ordered cancel write.
        // The result stays private until job_finished stops the native writer.
        self.mailbox.update(|updates| updates.cancel_requested = true);
    }

    fn resource_event(&mut self, event: &str, summary: &Value) -> bool {
        let episode = number(summary, "episode_id");
        let previous = self.resources;
        match event {
            "space_blocked" | "space_status" | "space_resumed" => {
                if self.disk.update(episode, event == "space_resumed") {
                    self.resources.disk = !self.disk.resumed;
                    self.resources.disk_episode = self.disk.id;
                    self.resources.volume_error = (self.resources.disk
                        && summary.get("volume_query_ok").and_then(Value::as_bool) == Some(false))
                    .then(|| number(summary, "volume_query_error"));
                }
            }
            "memory_blocked" | "memory_resumed" => {
                if self.memory.update(episode, event == "memory_resumed") {
                    self.resources.memory = !self.memory.resumed;
                }
            }
            _ => return false,
        }
        if previous != self.resources && self.mailbox.interest != WorkerUpdates::None {
            self.mailbox
                .update(|updates| updates.resources = Some(self.resources));
        }
        true
    }
}

#[derive(Default)]
struct Episode {
    id: u64,
    resumed: bool,
}

impl Episode {
    fn update(&mut self, id: u64, resumed: bool) -> bool {
        // Gate callbacks can leave the gate lock and arrive out of order.
        if id < self.id || (id == self.id && self.resumed) {
            return false;
        }
        self.id = id;
        self.resumed = resumed;
        true
    }
}

#[derive(Default)]
struct Mailbox {
    updates: Mutex<Updates>,
    interest: WorkerUpdates,
}

impl Mailbox {
    fn update(&self, change: impl FnOnce(&mut Updates)) {
        let wake = {
            let mut updates = self.updates.lock().unwrap();
            change(&mut updates);
            updates.waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[derive(Default)]
struct Updates {
    started: bool,
    progress: Option<Progress>,
    resources: Option<ResourceWait>,
    result: Option<io::Result<WorkerFrame>>,
    retry_granted: bool,
    cancel_requested: bool,
    waker: Option<Waker>,
}

pub(super) enum Update {
    Started,
    Progress(Progress),
    ResourceWait(ResourceWait),
}

#[derive(Clone, Copy)]
pub(super) struct Progress {
    pub(super) completed: u64,
    pub(super) total: u64,
}

impl Process {
    pub(super) fn start(path: &Path, config: &WorkerConfig, mode: ProcessMode) -> io::Result<Self> {
        let mut command = Command::new(path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("SUNPACK_NATIVE_PROCESS_MODE", mode_name(mode));
        if let Some(interval) = config.space_poll_interval_ms {
            command.env("SUNPACK_VOLUME_SPACE_POLL_MS", interval.to_string());
        }
        if let Some(interval) = config.space_status_report_interval_ms {
            command.env(
                "SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS",
                interval.to_string(),
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        if let Some(directory) = path.parent().filter(|path| path.is_absolute()) {
            command.current_dir(directory);
        }
        Self::launch(move || command.spawn(), mode)
    }

    fn launch(
        spawn: impl FnOnce() -> io::Result<Child> + Send + 'static,
        mode: ProcessMode,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared::default());
        shared.state.lock().unwrap().startup_mode = Some(mode);
        let child = Arc::new(Mutex::new(None));
        let owner = Arc::clone(&shared);
        let owner_child = Arc::clone(&child);
        // Process creation and the handshake belong to this existing IO owner,
        // not to a request poll. All borrowers await the same retained result.
        let owner = thread::Builder::new()
            .name("sunpack-worker-stdout".into())
            .spawn(move || run_process(spawn, &owner_child, &owner))
            .map_err(|error| io::Error::new(error.kind(), CommunicationError {
                kind: "process_start", message: error.to_string(),
            }))?;
        Ok(Self { owner: Some(owner), child, shared })
    }

    pub(super) fn pid(&self) -> u32 { self.shared.state.lock().unwrap().pid }

    pub(super) fn thread_capacity(&self) -> usize {
        self.shared.state.lock().unwrap().thread_capacity.max(1)
    }

    pub(super) async fn ready(&self, cancellation: &Cancellation) -> io::Result<()> {
        {
            let state = self.shared.state.lock().unwrap();
            if let Some(reason) = &state.closed {
                cancellation.check_io()?;
                return Err(reason.error());
            }
            if state.ready {
                return cancellation.check_io();
            }
        }
        // Register before checking cancellation: even a cancellation between
        // publication and this first poll must retire an unneeded startup.
        let waiter = ReadyWaiter::new(&self.shared);
        let shared = Arc::clone(&self.shared);
        let id = waiter.id;
        let _subscription = cancellation.subscribe(move || {
            let wake = shared.state.lock().unwrap().ready_waiters
                .get_mut(&id).and_then(Option::take);
            if let Some(wake) = wake {
                wake.wake();
            }
        });
        poll_fn(|cx| {
            let mut state = self.shared.state.lock().unwrap();
            if cancellation.cancelled() {
                if state.ready || state.closed.is_some()
                    || (state.ready_waiters.len() > 1 && !state.startup_abandoned)
                {
                    // Retire interest atomically with this decision. Two
                    // concurrent cancellations must not both count each other
                    // as a surviving borrower and skip the final cleanup wait.
                    state.ready_waiters.remove(&waiter.id);
                    return Poll::Ready(cancellation.check_io());
                }
                // The last borrower owns cancellation cleanup, but not a host
                // slot. Keep its future until spawn/child reaping completes so
                // the engine's caller cannot exit before the child is attached
                // to its Windows job or killed. Other borrowers cancel promptly.
                state.abandon_startup();
                self.shared.changed.notify_all();
            } else {
                if let Some(reason) = &state.closed {
                    return Poll::Ready(Err(reason.error()));
                }
                if state.ready {
                    return Poll::Ready(Ok(()));
                }
            }
            *state.ready_waiters.get_mut(&waiter.id).unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }).await
    }

    pub(super) fn startup_abandoned(&self) -> bool {
        self.shared.state.lock().unwrap().startup_abandoned
    }

    pub(super) fn desire_mode(&self, mode: ProcessMode) {
        let mut state = self.shared.state.lock().unwrap();
        if !state.ready {
            state.startup_mode = Some(mode);
        }
    }

    pub(super) fn alive(&self) -> bool {
        self.shared.state.lock().unwrap().closed.is_none()
    }

    /// The engine serializes control commands. Startup and subsequent
    /// transitions share the same acknowledged applied-state cache.
    #[cfg(test)]
    pub(super) fn set_process_mode(&self, mode: ProcessMode) -> io::Result<bool> {
        super::scheduling::block_on(self.set_process_mode_async(mode))
    }

    pub(super) async fn set_process_mode_async(&self, mode: ProcessMode) -> io::Result<bool> {
        let startup = {
            let mut state = self.shared.state.lock().unwrap();
            if let Some(reason) = &state.closed { return Err(reason.error()); }
            if !state.ready {
                // Join startup without becoming a worker borrower. A mode
                // setter must not keep an abandoned startup process alive.
                state.startup_mode = Some(mode);
                self.shared.changed.notify_all();
                true
            } else {
                if state.applied_mode == Some(mode) { return Ok(true); }
                state.mode_reply = None;
                state.applied_mode = None;
                false
            }
        };
        let _waiter = ModeWaiter(&self.shared);
        if !startup {
            let frame = encode_worker_frame(
                &json!({"worker_command":"set_process_mode", "mode":mode_name(mode)}),
            )?;
            self.send(Arc::new(frame)).wait().await?;
        }
        poll_fn(|cx| {
            let mut state = self.shared.state.lock().unwrap();
            if startup {
                if let Some(reason) = &state.closed { return Poll::Ready(Err(reason.error())); }
                if state.ready { return Poll::Ready(Ok(state.applied_mode == Some(mode))); }
            } else {
                if let Some((reply, applied)) = state.mode_reply.take() {
                    return Poll::Ready(if reply == Some(mode) { Ok(applied) } else {
                        Err(io::Error::new(io::ErrorKind::InvalidData,
                            "worker acknowledged a different process mode"))
                    });
                }
                if let Some(reason) = &state.closed { return Poll::Ready(Err(reason.error())); }
            }
            state.mode_waiter = Some(cx.waker().clone());
            Poll::Pending
        }).await
    }

    pub(super) async fn submit(
        &self,
        job_id: &str,
        request: Value,
        cancellation: &Cancellation,
        interest: WorkerUpdates,
        mut on_update: impl FnMut(Update),
    ) -> io::Result<WorkerFrame> {
        let frame = Arc::new(encode_worker_frame(&request)?);
        drop(request);
        let mailbox = Arc::new(Mailbox {
            interest,
            ..Mailbox::default()
        });
        let wake_mailbox = Arc::clone(&mailbox);
        let _subscription = cancellation.subscribe(move || wake_mailbox.update(|_| {}));

        cancellation.check_io()?;
        self.shared.register(job_id, Arc::clone(&mailbox))?;
        let mut active = ActiveSubmission(Some(self));
        let result = async {
            loop {
                self.send(Arc::clone(&frame)).wait().await?;
                let result = self
                    .wait(job_id, &mailbox, cancellation, &mut on_update)
                    .await?;
                if !rejected(&result) {
                    return Ok(result);
                }
                poll_fn(|cx| self.shared.poll_retry(job_id, &mailbox, cancellation, cx)).await?;
            }
        }
        .await;
        active.0 = None;
        result
    }

    async fn wait(
        &self,
        job_id: &str,
        mailbox: &Mailbox,
        cancellation: &Cancellation,
        on_update: &mut impl FnMut(Update),
    ) -> io::Result<WorkerFrame> {
        let mut sent_cancel = false;
        let mut cancel_write: Option<Arc<WriteCompletion>> = None;
        poll_fn(|cx| {
            let (started, progress, resources, result, cancel_requested) = {
                let mut updates = mailbox.updates.lock().unwrap();
                if updates.result.is_none() {
                    updates.waker = Some(cx.waker().clone());
                }
                (
                    std::mem::take(&mut updates.started),
                    updates.progress.take(),
                    updates.resources.take(),
                    updates.result.take(),
                    updates.cancel_requested,
                )
            };
            if started {
                on_update(Update::Started);
            }
            if let Some(progress) = progress {
                on_update(Update::Progress(progress));
            }
            if let Some(resources) = resources {
                on_update(Update::ResourceWait(resources));
            }
            if let Some(result) = result {
                return Poll::Ready(result);
            }
            if !sent_cancel && (cancel_requested || cancellation.cancelled()) {
                let cancel =
                    encode_worker_frame(&json!({"worker_command":"cancel", "job_id":job_id}))?;
                cancel_write = Some(self.send(Arc::new(cancel)));
                // Keep the path/output leases until native writers and callbacks stop.
                sent_cancel = true;
            }
            if let Some(write) = &cancel_write {
                if let Poll::Ready(result) = write.poll(cx) {
                    result?;
                    cancel_write = None;
                }
            }
            // Only one coalesced update per poll. Sustained progress from a
            // large archive must leave room for other requests' stages.
            Poll::Pending
        })
        .await
    }

    fn send(&self, bytes: Arc<Vec<u8>>) -> Arc<WriteCompletion> {
        self.shared.send(bytes)
    }

    fn abort(&self, message: String) {
        stop_child(&self.child);
        self.shared.fail(message, io::ErrorKind::BrokenPipe);
    }
}

struct ActiveSubmission<'a>(Option<&'a Process>);

impl Drop for ActiveSubmission<'_> {
    fn drop(&mut self) {
        if let Some(process) = self.0 {
            // Unwinding a suspended task must stop the native writer before
            // the task's output and source leases can be dropped.
            process.abort("worker submission abandoned".into());
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        if !state.ready || state.closed.is_some() {
            // No job can have entered an unfinished startup. Its IO owner
            // handles abort/reap, including a spawn still in progress. A failed
            // owner has already reaped; do not join its tail on a scheduler poll.
            state.abandon_startup();
            drop(state);
            self.shared.changed.notify_all();
            return;
        }
        drop(state);
        self.shared.shutting_down.store(true, Ordering::Release);
        if let Ok(frame) = encode_worker_frame(&json!({"worker_command":"shutdown"})) {
            let _ = self.send(Arc::new(frame)).wait_blocking();
        }
        self.shared.close_input();
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

struct ReadyWaiter<'a> {
    shared: &'a Shared,
    id: u64,
}

impl<'a> ReadyWaiter<'a> {
    fn new(shared: &'a Shared) -> Self {
        let mut state = shared.state.lock().unwrap();
        let id = state.next_waiter;
        state.next_waiter += 1;
        state.ready_waiters.insert(id, None);
        Self { shared, id }
    }
}

impl Drop for ReadyWaiter<'_> {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        state.ready_waiters.remove(&self.id);
        if state.ready_waiters.capacity() > 256 {
            crate::collections::trim_map(&mut state.ready_waiters);
        }
        if state.ready_waiters.is_empty() {
            state.abandon_startup();
            self.shared.changed.notify_all();
        }
    }
}

fn run_process(
    spawn: impl FnOnce() -> io::Result<Child>,
    child: &Arc<Mutex<Option<Child>>>,
    shared: &Arc<Shared>,
) {
    let mut spawned = match spawn() {
        Ok(child) => child,
        Err(error) => {
            shared.fail_classified(error.to_string(), error.kind(), "process_start");
            return;
        }
    };
    shared.state.lock().unwrap().pid = spawned.id();
    #[cfg(windows)]
    let _job = crate::core::process::KillOnCloseJob::attach(&spawned).ok();
    let input = spawned.stdin.take().expect("worker stdin is piped");
    let output = spawned.stdout.take().expect("worker stdout is piped");
    let stderr = spawned.stderr.take();
    *child.lock().unwrap() = Some(spawned);
    let abandoned = shared.state.lock().unwrap().abort_startup.clone();
    if let Some(reason) = abandoned {
        stop_child(child);
        shared.fail(reason.message, reason.kind);
        return;
    }
    let stderr_owner = match stderr {
        Some(pipe) => {
            let owner = Arc::clone(shared);
            match thread::Builder::new().name("sunpack-worker-stderr".into())
                .spawn(move || pump_stderr(pipe, &owner)) {
                Ok(owner) => Some(owner),
                Err(error) => {
                    stop_child(child);
                    shared.fail(error.to_string(), error.kind());
                    return;
                }
            }
        }
        None => None,
    };
    let owner = Arc::clone(shared);
    let owner_child = Arc::clone(child);
    let writer = match thread::Builder::new()
        .name("sunpack-worker-stdin".into())
        .spawn(move || {
            dispatch_stdin(input, &owner, |error| {
                fail_stdin(&owner_child, &owner, error);
            });
        }) {
        Ok(writer) => writer,
        Err(error) => {
            stop_child(child);
            if let Some(owner) = stderr_owner { let _ = owner.join(); }
            shared.fail(error.to_string(), error.kind());
            return;
        }
    };
    let result = dispatch_stdout(output, shared);
    // EOF or invalid protocol ends every affected attempt. Reap before any
    // result/failure wake can release leases or start a replacement process.
    let mut child_guard = child.lock().unwrap();
    let child = child_guard.as_mut().expect("spawned worker");
    let exited = child.try_wait().ok().flatten();
    if exited.is_none() && (result.is_err() || !shared.shutting_down.load(Ordering::Acquire)) {
        let _ = child.kill();
    }
    let status = exited.map_or_else(|| child.wait(), Ok);
    let out_of_memory = status.ok().and_then(|status| status.code())
        .is_some_and(|code| matches!(code as u32, 0xc0000017 | 0xc000012d));
    // Release the child lock before publication; a failed write may be reaping too.
    drop(child_guard);
    shared.fail_classified(
        result.as_ref().err().map_or_else(
            || "sevenzip_worker exited before job completion".to_owned(),
            |error| format!("sevenzip_worker transport failed: {error}"),
        ),
        if out_of_memory { io::ErrorKind::OutOfMemory } else { io::ErrorKind::BrokenPipe },
        // Main publishes process-level transport failure after wait(): the
        // worker is gone. Job-local protocol errors remain process_io.
        "worker_lost",
    );
    let _ = writer.join();
    if let Some(owner) = stderr_owner { let _ = owner.join(); }
}

impl Shared {
    fn send(&self, bytes: Arc<Vec<u8>>) -> Arc<WriteCompletion> {
        let completion = Arc::new(WriteCompletion::default());
        let mut state = self.state.lock().unwrap();
        if let Some(reason) = &state.closed {
            completion.finish(Err(reason.error()));
        } else if state.input_closed {
            completion.finish(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker input is closed",
            )));
        } else {
            state.writes.push_back(InputFrame {
                bytes,
                completion: Arc::clone(&completion),
            });
            self.changed.notify_all();
        }
        completion
    }

    fn close_input(&self) {
        self.state.lock().unwrap().input_closed = true;
        self.changed.notify_all();
    }

    fn register(&self, job_id: &str, mailbox: Arc<Mailbox>) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(reason) = &state.closed {
            return Err(reason.error());
        }
        let epoch = state.completion_epoch;
        match state.jobs.entry(job_id.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Job::new(job_id, mailbox, epoch));
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(io::Error::other("duplicate native job id"))
            }
        }
        Ok(())
    }

    fn poll_retry(
        &self,
        job_id: &str,
        mailbox: &Mailbox,
        cancellation: &Cancellation,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut updates = mailbox.updates.lock().unwrap();
        if let Err(error) = cancellation.check_io() {
            drop(updates);
            let mut state = self.state.lock().unwrap();
            if state.jobs.remove(job_id).is_some() {
                // No bytes have been sent for the reserved attempt. Pass its
                // slot to the next waiter without waiting for native completion.
                state.grant_retry();
            } else {
                state.parked.retain(|(id, _)| id != job_id);
            }
            return Poll::Ready(Err(error));
        }
        if let Some(result) = updates.result.take() {
            return Poll::Ready(result.map(|_| ()));
        }
        if std::mem::take(&mut updates.retry_granted) {
            Poll::Ready(Ok(()))
        } else {
            updates.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn event(&self, frame: WorkerFrame) {
        let mut state = self.state.lock().unwrap();
        let kind = string(&frame.summary, "type");
        if state.closed.is_some() || state.abort_startup.is_some() {
            return;
        }
        if kind == "worker_ready" {
            state.thread_capacity = usize::try_from(number(&frame.summary, "thread_capacity"))
                .unwrap_or(usize::MAX).max(1);
            if frame.summary.get("process_mode_applied").and_then(Value::as_bool) == Some(true) {
                state.applied_mode = parse_mode(string(&frame.summary, "process_mode"));
            }
            state.advance_startup();
        } else if kind == "process_mode_ack" {
            let applied = frame.summary.get("applied").and_then(Value::as_bool) == Some(true);
            let mode = parse_mode(string(&frame.summary, "mode"));
            state.applied_mode = mode.filter(|_| applied);
            if let Some(expected) = state.startup_command.take() {
                if mode != Some(expected) {
                    state.abort_startup = Some(WorkerExit {
                        failure_kind: "process_io",
                        message: "worker acknowledged a different process mode".into(),
                        kind: io::ErrorKind::InvalidData,
                    });
                } else if state.startup_mode == mode {
                    // applied=false is an acknowledged refusal, not a reason
                    // to retry forever or strand every startup borrower.
                    state.ready = true;
                    state.startup_mode = None;
                } else {
                    state.advance_startup();
                }
            } else {
                state.mode_reply = Some((mode, applied));
            }
        }
        if matches!(kind, "worker_ready" | "process_mode_ack") {
            let mut wakes = if state.ready {
                state.ready_waiters.values_mut().filter_map(Option::take).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            wakes.extend(state.mode_waiter.take());
            drop(state);
            self.changed.notify_all();
            for wake in wakes {
                wake.wake();
            }
            return;
        }
        let job_id = string(&frame.summary, "job_id");
        if kind == "native_event" && string(&frame.summary, "event") == "job_finished" {
            if let Some((job_id, mut job)) = state.jobs.remove_entry(job_id) {
                let result = job.result.take().unwrap_or_else(|| {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native job finished without a result",
                    ))
                });
                if result.as_ref().is_ok_and(rejected) {
                    state.parked.push_back((job_id, Arc::clone(&job.mailbox)));
                    // A completion may have arrived between submission and
                    // rejection. Claim it once, including if other jobs are
                    // paused and cannot produce a second completion.
                    let earliest = state.claimed_epoch.max(job.submission_epoch);
                    if earliest < state.completion_epoch {
                        state.claimed_epoch = earliest + 1;
                        state.grant_retry();
                    } else if state.jobs.is_empty() {
                        // With no outstanding submissions there is nothing to wait for.
                        state.grant_retry();
                    }
                } else {
                    state.completion_epoch += 1;
                    if state.grant_retry() {
                        state.claimed_epoch = state.completion_epoch;
                    }
                }
                job.mailbox.update(|updates| updates.result = Some(result));
                if state.jobs.capacity() > 256 {
                    crate::collections::trim_map(&mut state.jobs);
                }
            }
            return;
        }
        let Some(job) = state.jobs.get_mut(job_id) else {
            return;
        };
        if job.result.is_some() {
            return;
        }
        let event = string(&frame.summary, "event");
        if matches!(kind, "progress" | "native_memory")
            && (job.mailbox.interest == WorkerUpdates::None || job.resource_event(event, &frame.summary)) {
            return;
        }
        match kind {
            "native_event"
                if event == "job_started" && job.mailbox.interest == WorkerUpdates::All =>
            {
                job.mailbox.update(|updates| updates.started = true);
            }
            "protocol_error" => {
                job.protocol_error(io::Error::new(
                    io::ErrorKind::InvalidData,
                    string(&frame.summary, "message"),
                ))
            }
            "progress" if job.mailbox.interest == WorkerUpdates::All => {
                let update = Progress {
                    completed: number(&frame.summary, "completed_bytes"),
                    total: number(&frame.summary, "total_bytes"),
                };
                job.mailbox
                    .update(|updates| updates.progress = Some(update));
            }
            "progress" | "native_memory" => {}
            _ => match job.accumulator.as_mut().expect("active job accumulator").accept(frame) {
                Ok(Some(mut frame)) if string(&frame.summary, "type") == "result" => {
                    let mut stderr = self.stderr.lock().unwrap();
                    if string(&frame.summary, "status") == "ok" || rejected(&frame) {
                        stderr.bytes.clear();
                    } else {
                        let tail = stderr.take();
                        if !tail.is_empty() { frame.summary["stderr_tail"] = Value::String(tail); }
                    }
                    job.result = Some(Ok(frame));
                }
                Ok(_) => {}
                Err(error) => job.protocol_error(error),
            },
        }
    }

    fn fail(&self, message: String, kind: io::ErrorKind) {
        self.fail_classified(message, kind, "process_io");
    }

    fn fail_classified(&self, message: String, kind: io::ErrorKind, failure_kind: &'static str) {
        let mut state = self.state.lock().unwrap();
        if state.closed.is_some() {
            return;
        }
        let exit = state.abort_startup.take().unwrap_or(WorkerExit { message, kind, failure_kind });
        for (_, job) in state.jobs.drain() {
            job.mailbox
                .update(|updates| updates.result = Some(Err(exit.error())));
        }
        for (_, mailbox) in state.parked.drain(..) {
            mailbox.update(|updates| updates.result = Some(Err(exit.error())));
        }
        for write in state.writes.drain(..) {
            write.completion.finish(Err(exit.error()));
        }
        state.input_closed = true;
        state.closed = Some(exit);
        let mut wakes: Vec<_> = state.ready_waiters.values_mut().filter_map(Option::take).collect();
        wakes.extend(state.mode_waiter.take());
        drop(state);
        self.changed.notify_all();
        for wake in wakes {
            wake.wake();
        }
    }
}

impl State {
    fn abandon_startup(&mut self) {
        if !self.ready && self.closed.is_none() && self.abort_startup.is_none() {
            self.startup_abandoned = true;
            self.abort_startup = Some(WorkerExit { failure_kind: "process_io",
                message: "worker startup abandoned".into(),
                kind: io::ErrorKind::BrokenPipe,
            });
        }
    }

    fn advance_startup(&mut self) {
        if self.ready || self.abort_startup.is_some() || self.startup_command.is_some() {
            return;
        }
        let Some(mode) = self.startup_mode else {
            self.ready = true;
            return;
        };
        if self.applied_mode == Some(mode) {
            self.ready = true;
            self.startup_mode = None;
        } else {
            match encode_worker_frame(&json!({"worker_command":"set_process_mode", "mode":mode_name(mode)})) {
                Ok(bytes) => {
                    self.startup_command = Some(mode);
                    self.writes.push_back(InputFrame {
                        bytes: Arc::new(bytes),
                        completion: Arc::new(WriteCompletion::default()),
                    });
                }
                Err(error) => self.abort_startup = Some(WorkerExit { failure_kind: "process_io", message: error.to_string(), kind: error.kind() }),
            }
        }
    }

    fn grant_retry(&mut self) -> bool {
        if let Some((id, mailbox)) = self.parked.pop_front() {
            if self.parked.capacity() > 256 {
                crate::collections::trim_deque(&mut self.parked);
            }
            let job = Job::new(&id, Arc::clone(&mailbox), self.completion_epoch);
            self.jobs.insert(id, job);
            mailbox.update(|updates| updates.retry_granted = true);
            true
        } else {
            false
        }
    }
}

fn stop_child(child: &Mutex<Option<Child>>) {
    if let Some(child) = child.lock().unwrap().as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn fail_stdin(child: &Mutex<Option<Child>>, shared: &Shared, error: &io::Error) {
    // Reap before releasing admitted jobs, and preserve the same classification
    // whichever pipe observes the dead worker first (main's abort/on_error).
    stop_child(child);
    shared.fail_classified(error.to_string(), io::ErrorKind::BrokenPipe, "worker_lost");
}

fn dispatch_stdin(mut input: impl Write, shared: &Shared, failed: impl FnOnce(&io::Error)) {
    loop {
        let write = {
            let state = shared.state.lock().unwrap();
            let mut state = shared
                .changed
                .wait_while(state, |state| state.writes.is_empty() && !state.input_closed && state.abort_startup.is_none())
                .unwrap();
            if let Some(reason) = &state.abort_startup {
                let error = reason.error();
                drop(state);
                failed(&error);
                return;
            }
            let Some(write) = state.writes.pop_front() else {
                return;
            };
            if state.writes.capacity() > 256 {
                crate::collections::trim_deque(&mut state.writes);
            }
            write
        };
        let result = input.write_all(&write.bytes);
        if let Err(error) = &result {
            // Even a partial write may have admitted a native job. The owner
            // reaps the child before any caller can release its output lease.
            failed(error);
            // Publish the same reaped-worker classification to this sender as
            // to queued writes and admitted jobs, not the raw pipe error.
            let classified = shared.state.lock().unwrap().closed.as_ref().map(WorkerExit::error);
            write.completion.finish(classified.map_or(result, Err));
            return;
        }
        write.completion.finish(result);
    }
}

fn dispatch_stdout(mut output: ChildStdout, shared: &Shared) -> io::Result<()> {
    let mut decoder = NativeWorkerFrameDecoder::default();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = output.read(&mut buffer)?;
        if count == 0 {
            return decoder.finish();
        }
        for frame in decoder.feed(&buffer[..count])? {
            shared.event(frame);
        }
        decoder.check()?;
    }
}

fn rejected(frame: &WorkerFrame) -> bool {
    frame.summary.get("retryable").and_then(Value::as_bool) == Some(true)
        && string(&frame.summary, "native_status") == "backpressure"
}

pub(super) fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}

pub(super) fn number(value: &Value, name: &str) -> u64 {
    value.get(name).and_then(Value::as_u64).unwrap_or(0)
}

fn mode_name(mode: ProcessMode) -> &'static str {
    match mode {
        ProcessMode::Normal => "normal",
        ProcessMode::High => "high",
        ProcessMode::Background => "background",
    }
}

fn parse_mode(value: &str) -> Option<ProcessMode> {
    match value {
        "normal" => Some(ProcessMode::Normal),
        "high" => Some(ProcessMode::High),
        "background" => Some(ProcessMode::Background),
        _ => None,
    }
}

#[cfg(test)]
impl Process {
    pub(super) fn with_test_start(spawn: impl FnOnce() -> io::Result<Child> + Send + 'static) -> Arc<Self> {
        Arc::new(Self::launch(spawn, ProcessMode::Normal).unwrap())
    }

    // Exercise the real Process and Engine wait/cleanup paths with controllable
    // pipe writes, without needing the separately built native worker binary.
    pub(super) fn with_test_input(input: impl Write + Send + 'static) -> Arc<Self> {
        let shared = Arc::new(Shared::default());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.wait().unwrap();
        let child = Arc::new(Mutex::new(Some(child)));
        let owner = Arc::clone(&shared);
        let owner_child = Arc::clone(&child);
        let writer = thread::spawn(move || {
            dispatch_stdin(input, &owner, |error| {
                fail_stdin(&owner_child, &owner, error);
            });
        });
        shared.state.lock().unwrap().ready = true;
        Arc::new(Self {
            owner: Some(writer),
            child,
            shared,
        })
    }

    pub(super) fn test_event(&self, summary: Value) {
        let bytes = encode_worker_frame(&summary).unwrap();
        let mut decoder = NativeWorkerFrameDecoder::default();
        for frame in decoder.feed(&bytes).unwrap() {
            self.shared.event(frame);
        }
        decoder.finish().unwrap();
    }

    pub(super) fn test_wait_startup_abandoned(&self) {
        let state = self.shared.state.lock().unwrap();
        let (_state, timeout) = self.shared.changed.wait_timeout_while(
            state, std::time::Duration::from_secs(10), |state| !state.startup_abandoned,
        ).unwrap();
        assert!(!timeout.timed_out());
    }

    pub(super) fn test_exit(&self) {
        self.abort("injected worker exit".into());
    }
}

#[cfg(test)]
mod tests {
    use super::super::{scheduling::Scheduler, Origin};
    use super::*;
    use std::future::Future;
    use std::sync::mpsc;
    use std::time::Duration;

    struct GatedInput {
        entered: mpsc::SyncSender<Vec<u8>>,
        release: mpsc::Receiver<()>,
        barriers: usize,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for GatedInput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.barriers != 0 {
                self.entered.send(bytes.to_vec()).unwrap();
                self.release.recv().unwrap();
                self.barriers -= 1;
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn foreground(
        scheduler: &Arc<Scheduler>,
        request: u64,
    ) -> (JoinHandle<()>, mpsc::Receiver<()>) {
        let scheduler = Arc::clone(scheduler);
        let (done, finished) = mpsc::channel();
        let task = thread::spawn(move || {
            scheduler.run(request, Origin::Foreground, &Cancellation::new(), |_| {
                Box::pin(async move {
                    done.send(()).unwrap();
                })
            });
        });
        (task, finished)
    }

    fn readiness(
        scheduler: &Arc<Scheduler>,
        process: &Arc<Process>,
        cancel: &Cancellation,
        id: u64,
    ) -> (JoinHandle<io::Result<()>>, mpsc::Receiver<()>) {
        let scheduler = Arc::clone(scheduler);
        let process = Arc::clone(process);
        let cancel = cancel.clone();
        let (pending, parked) = mpsc::channel();
        let task = thread::spawn(move || {
            scheduler.run(id, Origin::Watch, &cancel, |_| {
                Box::pin(async {
                    let mut ready = Box::pin(process.ready(&cancel));
                    let mut pending = Some(pending);
                    poll_fn(|cx| {
                        let result = ready.as_mut().poll(cx);
                        if result.is_pending() {
                            if let Some(pending) = pending.take() {
                                let _ = pending.send(());
                            }
                        }
                        result
                    }).await
                })
            })
        });
        (task, parked)
    }

    #[test]
    fn slow_ready_shares_waiters_cancellation_and_startup_mode_without_host_slots() {
        // Transport-write tests start with a ready process and miss both
        // readiness wake fan-out and cancellation losing sibling wakes.
        // One gated handshake also covers desired-mode reconciliation/refusal.
        let timeout = Duration::from_secs(10);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let scheduler = pool.install(Scheduler::new);
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (entered, writing) = mpsc::sync_channel(1);
        let (release, released) = mpsc::channel();
        let process = Process::with_test_input(GatedInput {
            entered, release: released, barriers: 1, bytes: Arc::clone(&bytes),
        });
        {
            let mut state = process.shared.state.lock().unwrap();
            state.ready = false;
            state.startup_mode = Some(ProcessMode::Normal);
        }
        let cancelled = Cancellation::new();
        let (first, first_pending) = readiness(&scheduler, &process, &cancelled, 1);
        first_pending.recv_timeout(timeout).unwrap();
        let (second, second_pending) = readiness(&scheduler, &process, &Cancellation::new(), 2);
        second_pending.recv_timeout(timeout).unwrap();
        let (third, third_pending) = readiness(&scheduler, &process, &Cancellation::new(), 3);
        third_pending.recv_timeout(timeout).unwrap();
        let (independent, finished) = foreground(&scheduler, 4);
        let responsive = finished.recv_timeout(timeout);
        cancelled.cancel();
        assert!(crate::io::cancellation::is_cancellation(&first.join().unwrap().unwrap_err()));
        assert!(process.alive());
        assert!(!process.startup_abandoned());
        assert_eq!(process.shared.state.lock().unwrap().ready_waiters.len(), 2);

        let changing = Arc::clone(&process);
        let control = scheduler.submit(100, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
            changing.set_process_mode_async(ProcessMode::High).await
        }));
        {
            let state = process.shared.state.lock().unwrap();
            let (state, timeout) = process.shared.changed.wait_timeout_while(state, timeout, |state| {
                state.startup_mode != Some(ProcessMode::High)
            }).unwrap();
            assert!(!timeout.timed_out());
            assert_eq!(state.startup_mode, Some(ProcessMode::High));
        }
        process.test_event(json!({
            "type": "worker_ready", "process_mode": "normal", "process_mode_applied": true,
            "thread_capacity": 7,
        }));
        let mode_write = writing.recv_timeout(timeout).unwrap();
        assert_eq!(mode_write, encode_worker_frame(&json!({
            "worker_command": "set_process_mode", "mode": "high",
        })).unwrap());
        assert!(!process.shared.state.lock().unwrap().ready);
        let (during_mode, mode_finished) = foreground(&scheduler, 5);
        let mode_responsive = mode_finished.recv_timeout(timeout);
        release.send(()).unwrap();
        process.test_event(json!({"type":"process_mode_ack", "mode":"high", "applied":false}));
        second.join().unwrap().unwrap();
        third.join().unwrap().unwrap();
        assert_eq!(process.thread_capacity(), 7);
        assert!(!control.join().unwrap().unwrap());
        assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
        assert!(process.shared.state.lock().unwrap().startup_command.is_none());
        independent.join().unwrap();
        during_mode.join().unwrap();
        responsive.expect("slow ready retained the shared host slot");
        mode_responsive.expect("startup mode retained the shared host slot");
        drop(process);
        let shutdown = encode_worker_frame(&json!({"worker_command":"shutdown"})).unwrap();
        assert_eq!(*bytes.lock().unwrap(), [mode_write, shutdown].concat());
    }

    #[test]
    fn process_mode_write_ack_and_exit_do_not_block_shared_control() {
        // The startup test exercises its special handshake path. This covers
        // an already-ready worker: both stdin backpressure and the ACK must
        // suspend control polls, and process exit must wake the pending setter.
        let timeout = Duration::from_secs(10);
        let scheduler = Scheduler::new();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (entered, writing) = mpsc::sync_channel(1);
        let (release, released) = mpsc::channel();
        let process = Process::with_test_input(GatedInput {
            entered, release: released, barriers: 1, bytes,
        });
        let changing = Arc::clone(&process);
        let control = scheduler.submit(100, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
            changing.set_process_mode_async(ProcessMode::High).await
        }));
        writing.recv_timeout(timeout).unwrap();
        let probe = |id| {
            let (send, receive) = mpsc::channel();
            let task = scheduler.submit(id, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
                send.send(()).unwrap();
            }));
            (task, receive.recv_timeout(timeout))
        };
        let (during_write, write_responsive) = probe(101);
        release.send(()).unwrap();
        let (during_ack, ack_responsive) = probe(102);
        process.test_event(json!({"type":"process_mode_ack", "mode":"high", "applied":true}));
        assert!(control.join().unwrap().unwrap());
        during_write.join().unwrap();
        during_ack.join().unwrap();
        write_responsive.expect("process mode write blocked the control driver");
        ack_responsive.expect("process mode ACK blocked the control driver");

        let changing = Arc::clone(&process);
        let (send, pending) = mpsc::channel();
        let control = scheduler.submit(103, Origin::Foreground, &Cancellation::new(), |_| Box::pin(async move {
            let mut change = Box::pin(changing.set_process_mode_async(ProcessMode::Normal));
            let mut send = Some(send);
            poll_fn(|cx| {
                let result = change.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(send) = send.take() { send.send(()).unwrap(); }
                }
                result
            }).await
        }));
        pending.recv_timeout(timeout).unwrap();
        process.test_exit();
        assert!(control.join().unwrap().is_err());
        assert!(process.shared.state.lock().unwrap().mode_waiter.is_none());
    }

    #[test]
    fn last_startup_cancellation_releases_a_waiting_mode_setter() {
        // A mode setter is not a worker borrower. Counting it as one keeps a
        // never-ready worker alive after every actual request has cancelled.
        let timeout = Duration::from_secs(10);
        let scheduler = Scheduler::new();
        let process = Process::with_test_input(Vec::new());
        {
            let mut state = process.shared.state.lock().unwrap();
            state.ready = false;
            state.startup_mode = Some(ProcessMode::Normal);
        }
        let cancel = Cancellation::new();
        let (borrower, pending) = readiness(&scheduler, &process, &cancel, 1);
        pending.recv_timeout(timeout).unwrap();
        let changing = Arc::clone(&process);
        let (completed, completion) = mpsc::channel();
        let control = thread::spawn(move || {
            completed.send(changing.set_process_mode(ProcessMode::High)).unwrap();
        });
        {
            let state = process.shared.state.lock().unwrap();
            let (_state, timed_out) = process.shared.changed.wait_timeout_while(state, timeout, |state| {
                state.startup_mode != Some(ProcessMode::High)
            }).unwrap();
            assert!(!timed_out.timed_out());
        }
        cancel.cancel();
        assert!(crate::io::cancellation::is_cancellation(&borrower.join().unwrap().unwrap_err()));
        let result = completion.recv_timeout(timeout);
        if result.is_err() {
            process.test_exit();
        }
        control.join().unwrap();
        assert!(result.expect("mode setter kept abandoned startup alive").is_err());
        assert!(!process.alive());
        assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
    }

    #[test]
    fn slow_spawn_failure_wakes_all_and_abandoned_owner_reaps_after_drop() {
        // A fake ready event cannot detect blocking Command::spawn, a consumed
        // startup error, or teardown missing a child that did not exist yet.
        let timeout = Duration::from_secs(10);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let scheduler = pool.install(Scheduler::new);
        let (entered, spawning) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (published, process_rx) = mpsc::channel();
        let starter_scheduler = Arc::clone(&scheduler);
        let starter = thread::spawn(move || {
            starter_scheduler.run(1, Origin::Watch, &Cancellation::new(), |_| {
                Box::pin(async move {
                    let process = Process::with_test_start(move || {
                        entered.send(()).unwrap();
                        released.recv().unwrap();
                        Err(io::Error::new(io::ErrorKind::NotFound, "injected spawn failure"))
                    });
                    published.send(Arc::clone(&process)).unwrap();
                    process.ready(&Cancellation::new()).await
                })
            })
        });
        spawning.recv_timeout(timeout).unwrap();
        let process = process_rx.recv_timeout(timeout).expect("spawn blocked its scheduler poll");
        let (second, pending) = readiness(&scheduler, &process, &Cancellation::new(), 2);
        pending.recv_timeout(timeout).unwrap();
        let (independent, completed) = foreground(&scheduler, 3);
        let responsive = completed.recv_timeout(timeout);
        release.send(()).unwrap();
        for result in [starter.join().unwrap(), second.join().unwrap()] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        }
        assert!(!process.alive());
        assert!(process.shared.state.lock().unwrap().ready_waiters.is_empty());
        independent.join().unwrap();
        responsive.expect("slow spawn retained the shared host slot");

        let (entered, spawning) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let process = Process::with_test_start(move || {
            entered.send(()).unwrap();
            released.recv().unwrap();
            Command::new(std::env::current_exe().unwrap()).arg("--list")
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
        });
        spawning.recv_timeout(timeout).unwrap();
        let shared = Arc::clone(&process.shared);
        let child = Arc::clone(&process.child);
        let cancel = Cancellation::new();
        let mut borrower = Box::pin(process.ready(&cancel));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(borrower.as_mut().poll(&mut cx).is_pending());
        cancel.cancel();
        assert!(borrower.as_mut().poll(&mut cx).is_pending(), "last cancellation skipped child cleanup");
        assert!(process.startup_abandoned());
        assert!(process.alive(), "unfinished cleanup became replaceable");
        release.send(()).unwrap();
        let state = shared.state.lock().unwrap();
        let (state, timed_out) = shared.changed.wait_timeout_while(state, timeout, |state| {
            state.closed.is_none()
        }).unwrap();
        assert!(!timed_out.timed_out());
        drop(state);
        assert!(child.lock().unwrap().as_mut().unwrap().try_wait().unwrap().is_some());
        let Poll::Ready(result) = borrower.as_mut().poll(&mut cx) else {
            panic!("reaped startup did not finish cancellation");
        };
        assert!(crate::io::cancellation::is_cancellation(&result.unwrap_err()));
        drop(borrower);
        assert!(shared.state.lock().unwrap().ready_waiters.is_empty());
        drop(process);

        // Engine teardown can also happen before any readiness future is
        // polled. In that case Drop itself must retire the pending startup.
        let (release, released) = mpsc::channel();
        let process = Process::with_test_start(move || {
            released.recv().unwrap();
            Err(io::Error::other("owner dropped before spawn finished"))
        });
        let shared = Arc::clone(&process.shared);
        drop(process);
        assert!(shared.state.lock().unwrap().startup_abandoned);
        release.send(()).unwrap();
        let state = shared.state.lock().unwrap();
        let (_state, timed_out) = shared.changed.wait_timeout_while(state, timeout, |state| {
            state.closed.is_none()
        }).unwrap();
        assert!(!timed_out.timed_out());
    }

    #[test]
    fn stdin_first_worker_death_keeps_worker_lost() {
        struct ClosedPipe;
        impl Write for ClosedPipe {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        // This fixture owns a real, already-reaped child and only an stdin
        // dispatcher, so stdout cannot win publication and hide the regression.
        let process = Process::with_test_input(ClosedPipe);
        let mailbox = register(&process.shared, "admitted");
        let write = process.shared.send(Arc::new(vec![1]));
        let error = write.wait_blocking().unwrap_err();
        assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "worker_lost");
        let error = mailbox.updates.lock().unwrap().result.take().unwrap().err().unwrap();
        assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "worker_lost");
        assert!(process.child.lock().unwrap().as_mut().unwrap().try_wait().unwrap().is_some());
    }

    #[test]
    fn communication_failures_keep_the_report_kind() {
        for kind in ["worker_lost", "process_io"] {
            let error = WorkerExit { message: "worker failed".into(), kind: io::ErrorKind::BrokenPipe, failure_kind: kind }.error();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), "worker failed");
            assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, kind);
        }
    }

    #[test]
    fn job_protocol_errors_cancel_once_and_wait_for_native_completion() {
        for malformed in [
            // A frame boundary and job route survive a malformed event body.
            json!({"type": "progress", "job_id": "bad", "rows": "invalid"}),
            // A valid body can still fail accumulator sequence validation.
            json!({"type": "manifest_chunk", "job_id": "bad", "seq": 1, "rows": []}),
        ] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let (entered, writing) = mpsc::sync_channel(1);
            let (release, released) = mpsc::channel();
            let process = Process::with_test_input(GatedInput {
                entered,
                release: released,
                barriers: 1,
                bytes: Arc::clone(&bytes),
            });
            let mailbox = register(&process.shared, "bad");
            let sibling = register(&process.shared, "sibling");
            let cancellation = Cancellation::new();
            let mut on_update = |_| {};
            let mut waiting = Box::pin(process.wait(
                "bad", &mailbox, &cancellation, &mut on_update,
            ));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(waiting.as_mut().poll(&mut cx).is_pending());
            dispatch(&process.shared, malformed.clone());
            assert!(process.shared.state.lock().unwrap().jobs["bad"].accumulator.is_none());
            assert!(mailbox.updates.lock().unwrap().result.is_none());
            assert!(waiting.as_mut().poll(&mut cx).is_pending());
            let cancel = writing.recv_timeout(Duration::from_secs(10)).unwrap();
            let expected = encode_worker_frame(
                &json!({"worker_command": "cancel", "job_id": "bad"}),
            ).unwrap();
            assert_eq!(cancel, expected);
            // Neither repeated broken events nor user cancellation duplicate it.
            dispatch(&process.shared, malformed);
            cancellation.cancel();
            assert!(waiting.as_mut().poll(&mut cx).is_pending());
            finish(&process.shared, "sibling", false);
            assert!(sibling.updates.lock().unwrap().result.take().unwrap().is_ok());
            assert!(waiting.as_mut().poll(&mut cx).is_pending());
            release.send(()).unwrap();
            finish(&process.shared, "bad", false);
            let Poll::Ready(result) = waiting.as_mut().poll(&mut cx) else {
                panic!("job_finished did not deliver the protocol error");
            };
            let error = result.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.get_ref().unwrap().downcast_ref::<CommunicationError>().unwrap().kind, "process_io");
            drop(waiting);
            drop(process);
            let shutdown = encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap();
            assert_eq!(*bytes.lock().unwrap(), [expected, shutdown].concat());
        }
    }

    #[test]
    fn blocked_submit_and_cancel_release_the_only_host_slot_and_drain_in_order() {
        // Unlike a mailbox-only test, exercise Process::submit and its cancel
        // path on a real one-slot Scheduler. Neither pipe write is released
        // until an independent foreground request has had a chance to run.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let scheduler = pool.install(Scheduler::new);
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (entered, writing) = mpsc::sync_channel(2);
        let (release, released) = mpsc::channel();
        let input = GatedInput {
            entered,
            release: released,
            barriers: 2,
            bytes: Arc::clone(&bytes),
        };
        let process = Process::with_test_input(input);
        let shared = Arc::clone(&process.shared);
        let cancellation = Cancellation::new();
        let watch_cancel = cancellation.clone();
        let watch_process = Arc::clone(&process);
        let watch_scheduler = Arc::clone(&scheduler);
        let request = json!({
            "job_id": "slow", "operation": "extract", "password": "x".repeat(128 * 1024),
        });
        let expected = encode_worker_frame(&request).unwrap();
        let (completed, completion) = mpsc::channel();
        let watch = thread::spawn(move || {
            let result = watch_scheduler.run(1, Origin::Watch, &watch_cancel, |_| {
                Box::pin(watch_process.submit(
                    "slow", request, &watch_cancel, WorkerUpdates::None, |_| {},
                ))
            });
            completed.send(result.is_ok()).unwrap();
            result
        });
        let submitted = writing.recv_timeout(Duration::from_secs(10)).unwrap();
        let (first, first_done) = foreground(&scheduler, 2);
        let submit_independent = first_done.recv_timeout(Duration::from_secs(10));
        cancellation.cancel();
        release.send(()).unwrap();
        let cancel = writing.recv_timeout(Duration::from_secs(10)).unwrap();
        let (second, second_done) = foreground(&scheduler, 3);
        let cancel_independent = second_done.recv_timeout(Duration::from_secs(10));
        let retained_lease = completion.try_recv().is_err();
        release.send(()).unwrap();
        finish(&shared, "slow", false);
        watch.join().unwrap().unwrap();
        first.join().unwrap();
        second.join().unwrap();
        drop(process); // Ordered shutdown, pipe close and writer join.

        submit_independent.expect("blocked submit retained the shared host slot");
        cancel_independent.expect("blocked cancellation retained the shared host slot");
        assert!(
            retained_lease,
            "cancellation returned before native job_finished",
        );
        assert_eq!(submitted, expected);
        let expected_cancel =
            encode_worker_frame(&json!({"worker_command": "cancel", "job_id": "slow"})).unwrap();
        assert_eq!(cancel, expected_cancel);
        let shutdown = encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap();
        assert_eq!(
            *bytes.lock().unwrap(),
            [expected, expected_cancel, shutdown].concat(),
        );
        assert!(shared.state.lock().unwrap().writes.is_empty());
        assert_eq!(
            Arc::strong_count(&shared), 1,
            "writer retained the process after shutdown",
        );
    }

    #[test]
    fn partial_write_failure_reaps_before_waking_senders_and_exit_stops_idle_writer() {
        // Completion/retry tests cannot detect leases released after a partial
        // frame, stranded queued senders, or an idle stdin thread leaked on EOF.
        struct PartialFailure(bool);
        impl Write for PartialFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    Ok(bytes.len().min(2))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "injected partial write",
                    ))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let shared = Arc::new(Shared::default());
        let mailbox = register(&shared, "admitted");
        let first = shared.send(Arc::new(vec![1; 8]));
        let queued = shared.send(Arc::new(vec![2; 8]));
        let (stopping, stopped) = mpsc::channel();
        let (reap, reaped) = mpsc::channel();
        let owner = Arc::clone(&shared);
        let writer = thread::spawn(move || {
            dispatch_stdin(PartialFailure(true), &owner, |error| {
                stopping.send(()).unwrap();
                reaped.recv().unwrap();
                owner.fail(error.to_string(), io::ErrorKind::BrokenPipe);
            });
        });
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.poll(&mut cx).is_pending());
        assert!(queued.poll(&mut cx).is_pending());
        assert!(mailbox.updates.lock().unwrap().result.is_none());
        reap.send(()).unwrap();
        writer.join().unwrap();
        for write in [first, queued, shared.send(Arc::new(vec![3]))] {
            assert_eq!(
                write.wait_blocking().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe,
            );
        }
        assert_eq!(
            mailbox.updates.lock().unwrap().result.take().unwrap().err().unwrap().kind(),
            io::ErrorKind::BrokenPipe,
        );
        assert!(shared.state.lock().unwrap().writes.is_empty());

        let idle = Arc::new(Shared::default());
        let owner = Arc::clone(&idle);
        let (finished, done) = mpsc::channel();
        let writer = thread::spawn(move || {
            dispatch_stdin(Vec::new(), &owner, |_| panic!("unexpected write failure"));
            finished.send(()).unwrap();
        });
        idle.fail("worker stdout exited".into(), io::ErrorKind::BrokenPipe);
        done.recv_timeout(Duration::from_secs(10))
            .expect("EOF left an idle writer asleep");
        writer.join().unwrap();
        assert_eq!(Arc::strong_count(&idle), 1);
    }

    #[test]
    fn structured_results_keep_bounded_stderr_and_drain_between_jobs() {
        let shared = Shared::default();
        // A result may drain stderr between reads of one UTF-8 character.
        // Like main's incremental decoder, retain the unfinished character
        // privately until the next read, without emitting replacements.
        struct SplitCharacter<'a> { shared: &'a Shared, read: usize }
        impl Read for SplitCharacter<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let bytes: &[u8] = match self.read {
                    0 => b"before\xe5\xaf",
                    1 => {
                        assert_eq!(self.shared.stderr.lock().unwrap().take(), "before");
                        b"\x86"
                    },
                    _ => return Ok(0),
                };
                self.read += 1;
                output[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
        }
        pump_stderr(SplitCharacter { shared: &shared, read: 0 }, &shared);
        assert_eq!(shared.stderr.lock().unwrap().take(), "密");
        let first = register(&shared, "first");
        // Read arbitrary blocks, including split UTF-8, through the same pump
        // as the child pipe. A long native line must never grow without bound.
        let text = "密".repeat(STDERR_TAIL_CHARS + 100);
        pump_stderr(io::Cursor::new(text.as_bytes()), &shared);
        assert!(shared.stderr.lock().unwrap().bytes.len() <= STDERR_TAIL_BYTES);
        finish(&shared, "first", false);
        let frame = first.updates.lock().unwrap().result.take().unwrap().unwrap();
        assert_eq!(frame.summary["stderr_tail"].as_str().unwrap(), "密".repeat(STDERR_TAIL_CHARS));
        let second = register(&shared, "second");
        let lines = (0..60).map(|n| format!("line{n}\n")).collect::<String>();
        pump_stderr(io::Cursor::new(lines), &shared);
        finish(&shared, "second", false);
        let frame = second.updates.lock().unwrap().result.take().unwrap().unwrap();
        let text = frame.summary["stderr_tail"].as_str().unwrap();
        assert_eq!(text.lines().count(), STDERR_TAIL_LINES);
        assert!(text.starts_with("line20\n") && text.ends_with("line59\n"));
        let success = register(&shared, "success");
        pump_stderr(io::Cursor::new(b"irrelevant successful-job detail\n"), &shared);
        dispatch(&shared, json!({"type": "result", "job_id": "success", "status": "ok"}));
        dispatch(&shared, json!({"type": "native_event", "event": "job_finished", "job_id": "success"}));
        assert!(success.updates.lock().unwrap().result.take().unwrap().unwrap().summary.get("stderr_tail").is_none());
        let third = register(&shared, "third");
        finish(&shared, "third", false);
        assert!(third.updates.lock().unwrap().result.take().unwrap().unwrap().summary.get("stderr_tail").is_none());
    }

    fn dispatch(shared: &Shared, summary: Value) {
        let bytes = encode_worker_frame(&summary).unwrap();
        let mut decoder = NativeWorkerFrameDecoder::default();
        for frame in decoder.feed(&bytes).unwrap() {
            shared.event(frame);
        }
        decoder.finish().unwrap();
    }

    fn register(shared: &Shared, id: &str) -> Arc<Mailbox> {
        let mailbox = Arc::new(Mailbox::default());
        shared.register(id, Arc::clone(&mailbox)).unwrap();
        mailbox
    }

    fn finish(shared: &Shared, id: &str, backpressure: bool) {
        dispatch(
            shared,
            json!({
                "type": "result", "job_id": id, "retryable": backpressure,
                "native_status": if backpressure { "backpressure" } else { "ok" },
            }),
        );
        dispatch(
            shared,
            json!({"type": "native_event", "event": "job_finished", "job_id": id}),
        );
    }

    fn take_rejection(mailbox: &Mailbox) {
        let result = mailbox
            .updates
            .lock()
            .unwrap()
            .result
            .take()
            .unwrap()
            .unwrap();
        assert!(rejected(&result));
    }

    fn take_retry(
        shared: &Shared,
        id: &str,
        mailbox: &Mailbox,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        match shared.poll_retry(id, mailbox, cancel, &mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("retry should have settled"),
        }
    }

    #[test]
    fn each_completion_grants_one_retry_and_cancellation_passes_its_slot() {
        let shared = Shared::default();
        register(&shared, "active");
        let first = register(&shared, "first");
        let second = register(&shared, "second");
        let third = register(&shared, "third");
        for (id, mailbox) in [("first", &first), ("second", &second), ("third", &third)] {
            finish(&shared, id, true);
            take_rejection(mailbox);
            assert!(!mailbox.updates.lock().unwrap().retry_granted);
        }

        finish(&shared, "active", false);
        assert!(first.updates.lock().unwrap().retry_granted);
        assert!(!second.updates.lock().unwrap().retry_granted);
        assert!(!third.updates.lock().unwrap().retry_granted);

        let cancelled = Cancellation::new();
        cancelled.cancel();
        assert_eq!(
            take_retry(&shared, "first", &first, &cancelled)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other,
        );
        assert!(second.updates.lock().unwrap().retry_granted);
        assert!(!third.updates.lock().unwrap().retry_granted);

        shared.fail("worker exited".into(), io::ErrorKind::BrokenPipe);
        for (id, mailbox) in [("second", &second), ("third", &third)] {
            assert_eq!(
                take_retry(&shared, id, mailbox, &Cancellation::new())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe,
            );
        }
    }

    #[test]
    fn rejection_retries_immediately_when_no_other_job_can_finish() {
        let shared = Shared::default();
        let mailbox = register(&shared, "retry");
        finish(&shared, "retry", true);
        take_rejection(&mailbox);
        assert!(mailbox.updates.lock().unwrap().retry_granted);
        take_retry(&shared, "retry", &mailbox, &Cancellation::new()).unwrap();
        finish(&shared, "retry", false);
        assert!(mailbox
            .updates
            .lock()
            .unwrap()
            .result
            .take()
            .unwrap()
            .is_ok());
    }

    #[test]
    fn completion_before_rejection_can_be_claimed_once() {
        let shared = Shared::default();
        register(&shared, "active");
        register(&shared, "paused");
        let first = register(&shared, "first");
        let second = register(&shared, "second");
        finish(&shared, "active", false);
        finish(&shared, "first", true);
        finish(&shared, "second", true);
        take_rejection(&first);
        take_rejection(&second);
        assert!(first.updates.lock().unwrap().retry_granted);
        assert!(!second.updates.lock().unwrap().retry_granted);
    }

    // Feed real binary frame decoding and mailbox coalescing to CLI tests.
    // One batch represents frames arriving before the submission is polled.
    pub(crate) fn coalesced_wait_batches(batches: &[Vec<Value>]) -> Vec<ResourceWait> {
        let shared = Shared::default();
        let mailbox = register(&shared, "active");
        batches.iter().map(|batch| {
            for summary in batch {
                let mut summary = summary.clone();
                summary["job_id"] = json!("active");
                dispatch(&shared, summary);
            }
            mailbox.updates.lock().unwrap().resources.take().unwrap()
        }).collect()
    }

    #[test]
    fn resource_wait_tracks_independent_episodes_through_binary_frames() {
        let shared = Shared::default();
        let mailbox = register(&shared, "active");
        let take_wait = || mailbox.updates.lock().unwrap().resources.take();
        dispatch(
            &shared,
            json!({
                "type": "progress", "event": "space_blocked", "job_id": "active", "episode_id": 1,
                "volume_query_ok": false, "volume_query_error": 21,
            }),
        );
        dispatch(
            &shared,
            json!({"type": "native_memory", "event": "memory_blocked", "job_id": "active", "episode_id": 3}),
        );
        dispatch(
            &shared,
            json!({"type": "progress", "job_id": "active", "completed_bytes": 4, "total_bytes": 8}),
        );
        assert_eq!(
            take_wait(),
            Some(ResourceWait {
                disk: true,
                disk_episode: 1,
                memory: true,
                volume_error: Some(21)
            }),
        );
        assert_eq!(
            mailbox.updates.lock().unwrap().progress.unwrap().completed,
            4
        );

        for event in ["space_resumed", "space_status", "space_blocked"] {
            dispatch(
                &shared,
                json!({"type": "progress", "event": event, "job_id": "active", "episode_id": 1}),
            );
        }
        dispatch(
            &shared,
            json!({"type": "native_memory", "event": "memory_resumed", "job_id": "active", "episode_id": 2}),
        );
        assert_eq!(
            take_wait(),
            Some(ResourceWait {
                disk: false,
                disk_episode: 1,
                memory: true,
                volume_error: None
            }),
        );
        dispatch(
            &shared,
            json!({"type": "native_memory", "event": "memory_resumed", "job_id": "active", "episode_id": 3}),
        );
        assert_eq!(take_wait(), Some(ResourceWait { disk_episode: 1, ..Default::default() }));
    }
}
