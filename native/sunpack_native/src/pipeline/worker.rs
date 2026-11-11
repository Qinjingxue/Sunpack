//! One multiplexed worker per engine. Each live job retains its result
//! assembly and coalesces byte progress and resource state independently.

use super::{ResourceWait, WorkerUpdates};
use crate::core::config::{ProcessMode, WorkerConfig};
use crate::io::cancellation::Cancellation;
use crate::scan::worker_event::{NativeWorkerResultAccumulator, WorkerFrame};
use crate::scan::worker_wire::{encode_worker_frame, NativeWorkerFrameDecoder};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

pub(super) struct Process {
    input: Mutex<Option<ChildStdin>>,
    child: Arc<Mutex<Child>>,
    reader: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    #[cfg(windows)]
    _job: Option<crate::core::process::KillOnCloseJob>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    shutting_down: AtomicBool,
}

#[derive(Default)]
struct State {
    jobs: HashMap<String, Job>,
    parked: VecDeque<(String, Arc<Mailbox>)>,
    ready: bool,
    applied_mode: Option<ProcessMode>,
    mode_reply: Option<(Option<ProcessMode>, bool)>,
    closed: Option<WorkerExit>,
    completion_epoch: u64,
    claimed_epoch: u64,
}

struct WorkerExit {
    message: String,
    kind: io::ErrorKind,
}

impl WorkerExit {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

struct Job {
    mailbox: Arc<Mailbox>,
    accumulator: NativeWorkerResultAccumulator,
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
            accumulator: NativeWorkerResultAccumulator::new(id.to_owned()),
            submission_epoch,
            result: None,
            disk: Episode::default(),
            memory: Episode::default(),
            resources: ResourceWait::default(),
        }
    }

    fn resource_event(&mut self, event: &str, summary: &Value) -> bool {
        let episode = number(summary, "episode_id");
        let previous = self.resources;
        match event {
            "space_blocked" | "space_status" | "space_resumed" => {
                if self.disk.update(episode, event == "space_resumed") {
                    self.resources.disk = !self.disk.resumed;
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
            .stderr(Stdio::null())
            .env("SUNPACK_NATIVE_PROCESS_MODE", mode_name(mode))
            .env(
                "SUNPACK_VOLUME_SPACE_POLL_MS",
                config.space_poll_interval_ms.to_string(),
            )
            .env(
                "SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS",
                config.space_status_report_interval_ms.to_string(),
            );
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        if let Some(directory) = path.parent().filter(|path| path.is_absolute()) {
            command.current_dir(directory);
        }
        let mut child = command.spawn()?;
        #[cfg(windows)]
        let job = crate::core::process::KillOnCloseJob::attach(&child).ok();
        let input = child.stdin.take();
        let output = child.stdout.take().expect("worker stdout is piped");
        let child = Arc::new(Mutex::new(child));
        let shared = Arc::new(Shared::default());
        let owner = Arc::clone(&shared);
        let owner_child = Arc::clone(&child);
        let reader = match thread::Builder::new()
            .name("sunpack-worker-stdout".into())
            .spawn(move || {
                let result = dispatch_stdout(output, &owner);
                // EOF or invalid protocol ends every affected attempt. Reap the
                // child first so another request cannot race an old native writer.
                let mut child = owner_child.lock().unwrap();
                let exited = child.try_wait().ok().flatten();
                if exited.is_none()
                    && (result.is_err() || !owner.shutting_down.load(Ordering::Acquire))
                {
                    let _ = child.kill();
                }
                let status = exited.map_or_else(|| child.wait(), Ok);
                drop(child);
                let out_of_memory = status
                    .ok()
                    .and_then(|status| status.code())
                    .is_some_and(|code| matches!(code as u32, 0xc0000017 | 0xc000012d));
                owner.fail(
                    result.err().map_or_else(
                        || "sevenzip_worker exited before job completion".to_owned(),
                        |error| format!("sevenzip_worker transport failed: {error}"),
                    ),
                    if out_of_memory {
                        io::ErrorKind::OutOfMemory
                    } else {
                        io::ErrorKind::BrokenPipe
                    },
                );
            }) {
            Ok(reader) => reader,
            Err(error) => {
                let mut child = child.lock().unwrap();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let process = Self {
            input: Mutex::new(input),
            child,
            reader: Some(reader),
            shared,
            #[cfg(windows)]
            _job: job,
        };
        let state = process.shared.state.lock().unwrap();
        let state = process
            .shared
            .changed
            .wait_while(state, |state| !state.ready && state.closed.is_none())
            .unwrap();
        if let Some(reason) = &state.closed {
            let error = reason.error();
            drop(state);
            process.abort(error.to_string());
            return Err(error);
        }
        drop(state);
        Ok(process)
    }

    pub(super) fn alive(&self) -> bool {
        self.shared.state.lock().unwrap().closed.is_none()
    }

    /// The engine serializes control commands. Startup and subsequent
    /// transitions share the same acknowledged applied-state cache.
    pub(super) fn set_process_mode(&self, mode: ProcessMode) -> io::Result<bool> {
        {
            let mut state = self.shared.state.lock().unwrap();
            if state.applied_mode == Some(mode) {
                return Ok(true);
            }
            state.mode_reply = None;
            state.applied_mode = None;
        }
        let frame = encode_worker_frame(
            &json!({"worker_command":"set_process_mode", "mode":mode_name(mode)}),
        )?;
        self.send(&frame)?;
        let state = self.shared.state.lock().unwrap();
        let mut state = self
            .shared
            .changed
            .wait_while(state, |state| {
                state.mode_reply.is_none() && state.closed.is_none()
            })
            .unwrap();
        if let Some((reply, applied)) = state.mode_reply.take() {
            if reply != Some(mode) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "worker acknowledged a different process mode",
                ));
            }
            return Ok(applied);
        }
        Err(state.closed.as_ref().map_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "worker exited during process mode change",
                )
            },
            WorkerExit::error,
        ))
    }

    pub(super) async fn submit(
        &self,
        job_id: &str,
        request: Value,
        cancellation: &Cancellation,
        interest: WorkerUpdates,
        mut on_update: impl FnMut(Update),
    ) -> io::Result<WorkerFrame> {
        let frame = encode_worker_frame(&request)?;
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
                self.send(&frame)?;
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
        poll_fn(|cx| {
            let (started, progress, resources, result) = {
                let mut updates = mailbox.updates.lock().unwrap();
                if updates.result.is_none() {
                    updates.waker = Some(cx.waker().clone());
                }
                (
                    std::mem::take(&mut updates.started),
                    updates.progress.take(),
                    updates.resources.take(),
                    updates.result.take(),
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
            if !sent_cancel && cancellation.cancelled() {
                let cancel =
                    encode_worker_frame(&json!({"worker_command":"cancel", "job_id":job_id}))?;
                self.send(&cancel)?;
                // Keep the path/output leases until native writers and callbacks stop.
                sent_cancel = true;
            }
            // Only one coalesced update per poll. Sustained progress from a
            // large archive must leave room for other requests' stages.
            Poll::Pending
        })
        .await
    }

    fn send(&self, frame: &[u8]) -> io::Result<()> {
        let result = self
            .input
            .lock()
            .unwrap()
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "worker input is closed"))
            .and_then(|input| input.write_all(frame));
        if let Err(error) = &result {
            // A partial write may have admitted this job. Confirm the process
            // has stopped before releasing any pending caller's output lease.
            self.abort(error.to_string());
        }
        result
    }

    fn abort(&self, message: String) {
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
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
        self.shared.shutting_down.store(true, Ordering::Release);
        if self.alive() {
            if let Ok(frame) = encode_worker_frame(&json!({"worker_command":"shutdown"})) {
                let _ = self.send(&frame);
            }
        }
        self.input.get_mut().unwrap().take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = self.child.lock().unwrap().wait();
    }
}

impl Shared {
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
        if kind == "worker_ready" {
            state.ready = true;
            if frame
                .summary
                .get("process_mode_applied")
                .and_then(Value::as_bool)
                == Some(true)
            {
                state.applied_mode = parse_mode(string(&frame.summary, "process_mode"));
            }
            self.changed.notify_all();
            return;
        }
        if kind == "process_mode_ack" {
            let applied = frame.summary.get("applied").and_then(Value::as_bool) == Some(true);
            let mode = parse_mode(string(&frame.summary, "mode"));
            state.mode_reply = Some((mode, applied));
            state.applied_mode = mode.filter(|_| applied);
            self.changed.notify_all();
            return;
        }
        let job_id = string(&frame.summary, "job_id").to_owned();
        if kind == "native_event" && string(&frame.summary, "event") == "job_finished" {
            if let Some(mut job) = state.jobs.remove(&job_id) {
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
        let Some(job) = state.jobs.get_mut(&job_id) else {
            return;
        };
        if job.result.is_some() {
            return;
        }
        let event = string(&frame.summary, "event");
        if matches!(kind, "progress" | "native_memory") && job.resource_event(event, &frame.summary)
        {
            return;
        }
        match kind {
            "native_event"
                if event == "job_started" && job.mailbox.interest == WorkerUpdates::All =>
            {
                job.mailbox.update(|updates| updates.started = true);
            }
            "protocol_error" => {
                job.result = Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    string(&frame.summary, "message"),
                )))
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
            _ => match job.accumulator.accept(frame) {
                Ok(Some(frame)) if string(&frame.summary, "type") == "result" => {
                    job.result = Some(Ok(frame))
                }
                Ok(_) => {}
                Err(error) => job.result = Some(Err(error)),
            },
        }
    }

    fn fail(&self, message: String, kind: io::ErrorKind) {
        let mut state = self.state.lock().unwrap();
        if state.closed.is_some() {
            return;
        }
        let exit = WorkerExit { message, kind };
        for (_, job) in state.jobs.drain() {
            job.mailbox
                .update(|updates| updates.result = Some(Err(exit.error())));
        }
        for (_, mailbox) in state.parked.drain(..) {
            mailbox.update(|updates| updates.result = Some(Err(exit.error())));
        }
        state.closed = Some(exit);
        self.changed.notify_all();
    }
}

impl State {
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
mod tests {
    use super::*;

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
                memory: true,
                volume_error: None
            }),
        );
        dispatch(
            &shared,
            json!({"type": "native_memory", "event": "memory_resumed", "job_id": "active", "episode_id": 3}),
        );
        assert_eq!(take_wait(), Some(ResourceWait::default()));
    }
}
