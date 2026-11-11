//! One multiplexed worker per engine. Only live jobs retain manifests and
//! each waiting job holds at most one undelivered progress update.

use crate::core::config::{ProcessMode, WorkerConfig};
use crate::io::cancellation::Cancellation;
use crate::scan::worker_event::{NativeWorkerResultAccumulator, WorkerFrame};
use crate::scan::worker_wire::{encode_worker_frame, NativeWorkerFrameDecoder};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
    ready: bool,
    applied_mode: Option<ProcessMode>,
    mode_reply: Option<(Option<ProcessMode>, bool)>,
    closed: Option<WorkerExit>,
    capacity_epoch: u64,
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
    result: Option<io::Result<WorkerFrame>>,
}

#[derive(Default)]
struct Mailbox {
    updates: Mutex<Updates>,
    available: Condvar,
}

#[derive(Default)]
struct Updates {
    progress: Option<Progress>,
    result: Option<io::Result<WorkerFrame>>,
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

    pub(super) fn submit(
        &self,
        job_id: &str,
        request: &Value,
        cancellation: &Cancellation,
        mut on_progress: impl FnMut(Progress),
    ) -> io::Result<WorkerFrame> {
        let frame = encode_worker_frame(request)?;
        let mailbox = Arc::new(Mailbox::default());
        let wake_mailbox = Arc::clone(&mailbox);
        let wake_shared = Arc::clone(&self.shared);
        let _subscription = cancellation.subscribe(move || {
            {
                let _guard = wake_mailbox.updates.lock().unwrap();
                wake_mailbox.available.notify_one();
            }
            let _guard = wake_shared.state.lock().unwrap();
            wake_shared.changed.notify_all();
        });

        loop {
            cancellation.check_io()?;
            let epoch = self.shared.register(job_id, Arc::clone(&mailbox))?;
            self.send(&frame)?;
            let result = self.wait(job_id, &mailbox, cancellation, &mut on_progress)?;
            if !rejected(&result) {
                return Ok(result);
            }
            // Only an admitted job finishing releases capacity. If it already
            // finished during this submission, retry without waiting for more.
            let state = self.shared.state.lock().unwrap();
            let state = self
                .shared
                .changed
                .wait_while(state, |state| {
                    state.capacity_epoch == epoch
                        && !state.jobs.is_empty()
                        && state.closed.is_none()
                        && !cancellation.cancelled()
                })
                .unwrap();
            if let Some(reason) = &state.closed {
                return Err(reason.error());
            }
        }
    }

    fn wait(
        &self,
        job_id: &str,
        mailbox: &Mailbox,
        cancellation: &Cancellation,
        on_progress: &mut impl FnMut(Progress),
    ) -> io::Result<WorkerFrame> {
        let mut sent_cancel = false;
        loop {
            let updates = mailbox.updates.lock().unwrap();
            let mut updates = mailbox
                .available
                .wait_while(updates, |state| {
                    state.result.is_none()
                        && state.progress.is_none()
                        && (sent_cancel || !cancellation.cancelled())
                })
                .unwrap();
            let progress = updates.progress.take();
            let result = updates.result.take();
            drop(updates);
            if let Some(progress) = progress {
                on_progress(progress);
            }
            if let Some(result) = result {
                return result;
            }
            if !sent_cancel && cancellation.cancelled() {
                let cancel =
                    encode_worker_frame(&json!({"worker_command":"cancel", "job_id":job_id}))?;
                self.send(&cancel)?;
                // Keep the path/output leases until native writers and callbacks stop.
                sent_cancel = true;
            }
        }
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
    fn register(&self, job_id: &str, mailbox: Arc<Mailbox>) -> io::Result<u64> {
        let mut state = self.state.lock().unwrap();
        if let Some(reason) = &state.closed {
            return Err(reason.error());
        }
        let job = Job {
            mailbox,
            accumulator: NativeWorkerResultAccumulator::new(job_id.to_owned()),
            result: None,
        };
        match state.jobs.entry(job_id.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(job);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(io::Error::other("duplicate native job id"))
            }
        }
        Ok(state.capacity_epoch)
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
                if !result.as_ref().is_ok_and(rejected) {
                    state.capacity_epoch = state.capacity_epoch.wrapping_add(1);
                }
                job.mailbox.updates.lock().unwrap().result = Some(result);
                job.mailbox.available.notify_one();
                self.changed.notify_all();
            }
            return;
        }
        let Some(job) = state.jobs.get_mut(&job_id) else {
            return;
        };
        if job.result.is_some() {
            return;
        }
        match kind {
            "protocol_error" => {
                job.result = Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    string(&frame.summary, "message"),
                )))
            }
            "progress" => {
                let update = Progress {
                    completed: number(&frame.summary, "completed_bytes"),
                    total: number(&frame.summary, "total_bytes"),
                };
                job.mailbox.updates.lock().unwrap().progress = Some(update);
                job.mailbox.available.notify_one();
            }
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
            job.mailbox.updates.lock().unwrap().result = Some(Err(exit.error()));
            job.mailbox.available.notify_one();
        }
        state.closed = Some(exit);
        self.changed.notify_all();
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
