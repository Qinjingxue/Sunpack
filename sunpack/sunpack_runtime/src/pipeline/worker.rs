//! One multiplexed worker per engine. Each live job retains its result
//! assembly and coalesces byte progress and resource state independently.

use super::{ResourceWait, WorkerUpdates};
#[cfg(test)]
pub(crate) use tests::coalesced_wait_batches;
use crate::core::config::{ProcessMode, WorkerConfig};
use crate::io::archive_state::ArchiveInput;
use crate::io::cancellation::{cancelled_io, Cancellation};
use crate::scan::worker_event::{NativeWorkerResultAccumulator, WorkerFrame};
use crate::scan::worker_wire::{encode_worker_frame, small_request, write_request, NativeWorkerFrameDecoder};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

pub(super) struct Process {
    child: Arc<Mutex<ChildState>>,
    shared: Arc<Shared>,
}

#[derive(Default)]
enum ChildState {
    #[default]
    Starting,
    Running(Child),
    Exited(Option<std::process::ExitStatus>),
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    shutting_down: AtomicBool,
}

// Opaque stderr from a DLL or a crashing process is a fallback. Controlled
// worker failures have their own framed diagnostic.
const STDERR_TAIL_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct StderrHistory {
    bytes: VecDeque<u8>,
    discarded: bool,
}

impl StderrHistory {
    fn append(&mut self, bytes: &[u8]) {
        self.discarded |= bytes.len() > STDERR_TAIL_BYTES;
        let bytes = &bytes[bytes.len().saturating_sub(STDERR_TAIL_BYTES)..];
        let remove = (self.bytes.len() + bytes.len()).saturating_sub(STDERR_TAIL_BYTES);
        self.discarded |= remove != 0;
        self.bytes.drain(..remove);
        self.bytes.extend(bytes.iter().copied());
    }

    fn append_diagnostic(mut self, message: &mut String) {
        if self.bytes.is_empty() {
            return;
        }
        message.push_str("\nWorker stderr");
        if self.discarded {
            message.push_str(" (earlier output omitted)");
            while self.bytes.front().is_some_and(|byte| byte & 0xc0 == 0x80) {
                self.bytes.pop_front();
            }
        }
        message.push('\n');
        message.push_str(&String::from_utf8_lossy(self.bytes.make_contiguous()));
    }
}

fn pump_stderr(mut pipe: impl Read) -> StderrHistory {
    let mut history = StderrHistory::default();
    let mut block = [0; 4096];
    loop {
        match pipe.read(&mut block) {
            Ok(0) => return history,
            Ok(count) => history.append(&block[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return history,
        }
    }
}

#[derive(Default)]
struct State {
    pid: u32,
    owner: Option<JoinHandle<()>>,
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
    write_failure: Option<String>,
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
    payload: InputPayload,
    completion: Arc<WriteCompletion>,
}

#[derive(Clone)]
enum InputPayload {
    Frame(Arc<Vec<u8>>),
    Request(Arc<WorkerRequest>, Cancellation),
}

#[derive(Serialize)]
pub(super) struct WorkerRequest {
    pub job_id: String,
    pub operation: &'static str,
    pub origin: &'static str,
    pub output_dir: String,
    pub output_volume_key: String,
    #[serde(serialize_with = "serialize_archive_input")]
    pub archive_input: Arc<ArchiveInput>,
    pub password_candidates: Arc<Vec<Arc<str>>>,
    #[serde(flatten)]
    pub layout_passwords: crate::password::evidence::LayoutPasswords,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Arc<str>>,
    pub password_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codepage: Option<&'static str>,
    pub report_progress: bool,
    pub output_inventory: bool,
}

fn serialize_archive_input<S: Serializer>(input: &ArchiveInput, serializer: S) -> Result<S::Ok, S::Error> {
    input.worker_input().serialize(serializer)
}

#[derive(Default)]
struct WriteCompletion(Mutex<WriteState>);

#[derive(Default)]
struct WriteState {
    result: Option<io::Result<()>>,
    waker: Option<Waker>,
}

impl WriteCompletion {
    fn finish(&self, result: io::Result<()>) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
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
        super::scheduling::block_on(self.wait())
    }
}

#[derive(Debug)]
pub(super) struct CommunicationError {
    pub(super) kind: &'static str,
    message: Arc<str>,
}
impl std::fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) }
}
impl std::error::Error for CommunicationError {}

#[derive(Clone)]
struct WorkerExit {
    failure_kind: &'static str,
    message: Arc<str>,
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
    volume_error: Option<u64>,
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
            volume_error: None,
        }
    }

    fn protocol_error(&mut self, error: io::Error) {
        self.result = Some(Err(io::Error::new(error.kind(), CommunicationError { kind: "process_io", message: error.to_string().into() })));
        self.accumulator.take();
        // Wake the existing submission waiter to use its ordered cancel write.
        // The result stays private until job_finished stops the native writer.
        self.mailbox.update(|updates| updates.cancel_requested = true);
    }

    fn resource_wait(&self) -> ResourceWait {
        ResourceWait {
            disk: self.disk.blocked == Some(true),
            disk_episode: self.disk.id,
            memory: self.memory.blocked == Some(true),
            volume_error: self.volume_error,
        }
    }

    fn resource_event(&mut self, event: &str, summary: &Value) -> bool {
        let (disk, blocked) = match event {
            "space_blocked" | "space_status" => (true, true),
            "space_resumed" => (true, false),
            "memory_blocked" => (false, true),
            "memory_resumed" => (false, false),
            _ => return false,
        };
        let previous = self.resource_wait();
        let current = if disk { &mut self.disk } else { &mut self.memory };
        if !current.update(number(summary, "episode_id"), blocked) {
            return true;
        }
        if disk {
            self.volume_error = (blocked
                && summary.get("volume_query_ok").and_then(Value::as_bool) == Some(false))
            .then(|| number(summary, "volume_query_error"));
        }
        let resources = self.resource_wait();
        if previous != resources {
            self.mailbox.update(|updates| updates.resources = Some(resources));
        }
        true
    }
}

#[derive(Default)]
struct Episode {
    id: u64,
    // None is the unseen state, before the first blocked or resumed frame.
    blocked: Option<bool>,
}

impl Episode {
    fn update(&mut self, id: u64, blocked: bool) -> bool {
        // Gate callbacks can leave the gate lock and arrive out of order.
        if id < self.id || (id == self.id && self.blocked == Some(false)) {
            return false;
        }
        self.id = id;
        self.blocked = Some(blocked);
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
    retry_payload: Option<InputPayload>,
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
        let child = Arc::new(Mutex::new(ChildState::Starting));
        let owner = Arc::clone(&shared);
        let owner_child = Arc::clone(&child);
        // Process creation and the handshake belong to this existing IO owner,
        // not to a request poll. All borrowers await the same retained result.
        let mut state = shared.state.lock().unwrap();
        state.startup_mode = Some(mode);
        state.owner = Some(thread::Builder::new()
            .name("sunpack-worker-stdout".into())
            .spawn(move || run_process(spawn, &owner_child, &owner))
            .map_err(|error| io::Error::new(error.kind(), CommunicationError {
                kind: "process_start", message: error.to_string().into(),
            }))?);
        drop(state);
        Ok(Self { child, shared })
    }

    pub(super) fn pid(&self) -> u32 { self.shared.state.lock().unwrap().pid }

    pub(super) async fn ready(&self, cancellation: &Cancellation) -> io::Result<usize> {
        {
            let state = self.shared.state.lock().unwrap();
            if let Some(reason) = &state.closed {
                cancellation.check_io()?;
                return Err(reason.error());
            }
            if state.ready {
                cancellation.check_io()?;
                return Ok(state.thread_capacity.max(1));
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
                    return Poll::Ready(Err(cancelled_io()));
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
                    return Poll::Ready(Ok(state.thread_capacity.max(1)));
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
        mut request: WorkerRequest,
        cancellation: &Cancellation,
        interest: WorkerUpdates,
        on_update: impl FnMut(Update),
    ) -> io::Result<WorkerFrame> {
        request.report_progress = interest == WorkerUpdates::All;
        cancellation.check_io()?;
        let job_id = request.job_id.clone();
        let payload = match small_request(&request)? {
            Some(bytes) => {
                drop(request);
                InputPayload::Frame(Arc::new(bytes))
            }
            None => InputPayload::Request(Arc::new(request), cancellation.clone()),
        };
        self.submit_payload(&job_id, payload, cancellation, interest, on_update).await
    }

    async fn submit_payload(
        &self,
        job_id: &str,
        payload: InputPayload,
        cancellation: &Cancellation,
        interest: WorkerUpdates,
        mut on_update: impl FnMut(Update),
    ) -> io::Result<WorkerFrame> {
        let mailbox = Arc::new(Mailbox {
            interest,
            updates: Mutex::new(Updates {
                retry_payload: Some(payload),
                ..Updates::default()
            }),
        });
        let wake_mailbox = Arc::clone(&mailbox);
        let _subscription = cancellation.subscribe(move || wake_mailbox.update(|_| {}));

        cancellation.check_io()?;
        self.shared.register(job_id, Arc::clone(&mailbox))?;
        let mut active = ActiveSubmission(Some(self));
        let result = async {
            let mut retry = false;
            loop {
                let payload = mailbox.updates.lock().unwrap().retry_payload.clone();
                let sent = match payload {
                    Some(payload) => self.shared.send_payload(payload).wait().await,
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "worker rejected an accepted job",
                    )),
                };
                if let Err(error) = sent {
                    let mut state = self.shared.state.lock().unwrap();
                    if state.jobs.remove(job_id).is_some() && retry {
                        state.grant_retry();
                    }
                    return Err(error);
                }
                let result = self
                    .wait(job_id, &mailbox, cancellation, &mut on_update)
                    .await?;
                if !rejected(&result) {
                    return Ok(result);
                }
                poll_fn(|cx| self.shared.poll_retry(job_id, &mailbox, cancellation, cx)).await?;
                retry = true;
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
        let _ = reap_child(&self.child, true);
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
        let owner = state.owner.take();
        drop(state);
        self.shared.shutting_down.store(true, Ordering::Release);
        if let Ok(frame) = encode_worker_frame(&json!({"worker_command":"shutdown"})) {
            let _ = self.send(Arc::new(frame)).wait_blocking();
        }
        self.shared.close_input();
        if let Some(owner) = owner {
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
    child: &Arc<Mutex<ChildState>>,
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
    *child.lock().unwrap() = ChildState::Running(spawned);
    let abandoned = shared.state.lock().unwrap().abort_startup.clone();
    if let Some(reason) = abandoned {
        let _ = reap_child(child, true);
        shared.fail_classified(reason.message, reason.kind, reason.failure_kind);
        return;
    }
    let stderr_owner = match stderr {
        Some(pipe) => {
            match thread::Builder::new().name("sunpack-worker-stderr".into())
                .spawn(move || pump_stderr(pipe)) {
                Ok(owner) => Some(owner),
                Err(error) => {
                    let _ = reap_child(child, true);
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
                owner.state.lock().unwrap().write_failure = Some(error.to_string());
                let _ = reap_child(&owner_child, true);
            });
        }) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = reap_child(child, true);
            if let Some(owner) = stderr_owner { let _ = owner.join(); }
            shared.fail(error.to_string(), error.kind());
            return;
        }
    };
    let result = dispatch_stdout(output, shared);
    // EOF or invalid protocol ends every affected attempt. Reap before any
    // result/failure wake can release leases or start a replacement process.
    let terminate = result.is_err() || !shared.shutting_down.load(Ordering::Acquire);
    let status = reap_child(child, terminate);
    let stderr = stderr_owner.and_then(|owner| owner.join().ok());
    let write_failure = shared.state.lock().unwrap().write_failure.take();
    let mut message = match result {
        Err(error) => format!("sevenzip_worker transport failed: {error}"),
        Ok(()) => write_failure.map_or_else(
            || "sevenzip_worker exited before job completion".to_owned(),
            |error| format!("sevenzip_worker input failed: {error}"),
        ),
    };
    if let Some(stderr) = stderr {
        stderr.append_diagnostic(&mut message);
    }
    shared.fail_classified(
        message,
        worker_exit_kind(status),
        "worker_lost",
    );
    let _ = writer.join();
}

impl Shared {
    fn send(&self, bytes: Arc<Vec<u8>>) -> Arc<WriteCompletion> {
        self.send_payload(InputPayload::Frame(bytes))
    }

    fn send_payload(&self, payload: InputPayload) -> Arc<WriteCompletion> {
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
                payload,
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
        let event = string(&frame.summary, "event");
        if kind == "native_event" && event == "job_accepted" {
            // The queued pipe write holds its own reference until it finishes.
            // Acknowledgment only retires the copy reserved for a retry.
            let retired = job.mailbox.updates.lock().unwrap().retry_payload.take();
            drop(state);
            drop(retired);
            return;
        }
        if job.result.is_some() {
            return;
        }
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
                Ok(Some(frame)) if string(&frame.summary, "type") == "result" => job.result = Some(Ok(frame)),
                Ok(_) => {}
                Err(error) => job.protocol_error(error),
            },
        }
    }

    fn fail(&self, message: String, kind: io::ErrorKind) {
        self.fail_classified(message, kind, "process_io");
    }

    fn fail_classified(&self, message: impl Into<Arc<str>>, kind: io::ErrorKind, failure_kind: &'static str) {
        let (jobs, parked, writes, ready, mode) = {
            let mut state = self.state.lock().unwrap();
            if state.closed.is_some() {
                return;
            }
            let exit = state.abort_startup.take().unwrap_or_else(|| WorkerExit { message: message.into(), kind, failure_kind });
            let jobs = std::mem::take(&mut state.jobs);
            let parked = std::mem::take(&mut state.parked);
            let writes = std::mem::take(&mut state.writes);
            // Publish mailbox failures before a competing pipe can observe
            // the closed state and complete its in-flight send.
            for job in jobs.values() {
                job.mailbox.update(|updates| updates.result = Some(Err(exit.error())));
            }
            for (_, mailbox) in &parked {
                mailbox.update(|updates| updates.result = Some(Err(exit.error())));
            }
            for write in &writes {
                write.completion.finish(Err(exit.error()));
            }
            state.input_closed = true;
            state.closed = Some(exit);
            state.pid = 0;
            // A live Process::drop takes this handle to join graceful
            // shutdown. A failed generation does not keep the dead thread.
            drop(state.owner.take());
            (
                jobs,
                parked,
                writes,
                std::mem::take(&mut state.ready_waiters),
                state.mode_waiter.take(),
            )
        };
        drop((jobs, parked, writes));
        self.changed.notify_all();
        for wake in ready.into_values().flatten().chain(mode) {
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
                        payload: InputPayload::Frame(Arc::new(bytes)),
                        completion: Arc::new(WriteCompletion::default()),
                    });
                }
                Err(error) => self.abort_startup = Some(WorkerExit { failure_kind: "process_io", message: error.to_string().into(), kind: error.kind() }),
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

fn reap_child(child: &Mutex<ChildState>, terminate: bool) -> Option<std::process::ExitStatus> {
    // Keep the mutex through reaping so the other pipe cannot publish a
    // failure while the process still owns output handles.
    let mut state = child.lock().unwrap();
    let status = match &mut *state {
        ChildState::Starting => return None,
        ChildState::Exited(status) => return *status,
        ChildState::Running(child) => match child.try_wait() {
            Ok(Some(status)) => Some(status),
            _ => {
                if terminate {
                    let _ = child.kill();
                }
                child.wait().ok()
            }
        },
    };
    // Drop the process handle now and let either pipe classify its exit.
    *state = ChildState::Exited(status);
    status
}

fn worker_exit_kind(status: Option<std::process::ExitStatus>) -> io::ErrorKind {
    if status.and_then(|status| status.code())
        .is_some_and(|code| matches!(code as u32, 0xc0000017 | 0xc000012d))
    {
        io::ErrorKind::OutOfMemory
    } else {
        io::ErrorKind::BrokenPipe
    }
}

#[cfg(test)]
fn fail_stdin(child: &Mutex<ChildState>, shared: &Shared, error: &io::Error) {
    // Reap before releasing admitted jobs, and preserve the same classification
    // whichever pipe observes the dead worker first (main's abort/on_error).
    let status = reap_child(child, true);
    shared.fail_classified(error.to_string(), worker_exit_kind(status), "worker_lost");
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
        let result = match write.payload {
            InputPayload::Frame(bytes) => input.write_all(&bytes).map(Ok),
            InputPayload::Request(request, cancellation) =>
                write_request(&mut input, request.as_ref(), &cancellation),
        };
        if let Err(error) = &result {
            // Even a partial write may have admitted a native job. The owner
            // reaps the child before any caller can release its output lease.
            failed(error);
            // Stdout drains any terminal native diagnostic before publishing
            // one failure to every request, including this in-flight write.
            let state = shared.state.lock().unwrap();
            let state = shared.changed.wait_while(state, |state| state.closed.is_none()).unwrap();
            let failure = state.closed.as_ref().unwrap().error();
            drop(state);
            write.completion.finish(Err(failure));
            return;
        }
        write.completion.finish(result.unwrap());
    }
}

fn dispatch_stdout(mut output: impl Read, shared: &Shared) -> io::Result<()> {
    let mut decoder = NativeWorkerFrameDecoder::default();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = output.read(&mut buffer)?;
        if count == 0 {
            return decoder.finish();
        }
        for frame in decoder.feed(&buffer[..count])? {
            if string(&frame.summary, "type") == "worker_fatal" {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    string(&frame.summary, "message").to_owned()));
            }
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
        let child = Arc::new(Mutex::new(ChildState::Running(child)));
        let owner = Arc::clone(&shared);
        let owner_child = Arc::clone(&child);
        let writer = thread::spawn(move || {
            dispatch_stdin(input, &owner, |error| {
                fail_stdin(&owner_child, &owner, error);
            });
        });
        let mut state = shared.state.lock().unwrap();
        state.ready = true;
        state.owner = Some(writer);
        drop(state);
        Arc::new(Self { child, shared })
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
#[path = "../../tests/unit/pipeline/worker/tests.rs"]
mod tests;
