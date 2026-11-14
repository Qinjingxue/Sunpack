use super::{cli, windows};
use cli::reporting::Reply;
use crate::pipeline::{block_on, stage, AsyncGate};
use std::future::poll_fn;
use std::task::{Poll, Waker};
use crate::core::config::{self, Config, Snapshot};
use crate::core::passwords::BuiltinStore;
use crate::core::resources::{self, FileMutex};
use crate::filesystem;
use crate::io::config_changes::{DirectoryChange, NativeConfigChanges};
use crate::io::reader::PhysicalFileGeneration;
use crate::pipeline::{
    ArchiveResult, Cancellation, Engine, Event, FailureKind, Mode, Observer, Origin, Outcome,
    PromotedSource, Request, InputFailure,
};
use crate::postprocess::{watch_candidate_for_path, WatchCandidateRow};
use crate::scan::directory::{NativeDirectoryScanOptions, NativeWatchCatalog};
use crate::scan::scope::NativeDiscoveryScope;
use crate::watch_store::{is_path_under, watch_path_key};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
#[cfg(test)]
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

mod journal;
mod quiet;
#[cfg(test)]
mod crash_boundaries;
#[cfg(test)]
mod admission_tests;

const ROOTS_FILE: &str = "sunpack_watch_roots.txt";
const WATCH_METADATA: &str = ".sunpack_watch";
const ROOTS_LOCK: &str = "SunPackWatchRoots";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Root {
    path: PathBuf,
    output: Option<PathBuf>,
    recursive: bool,
    deep: bool,
    scanned: bool,
}

impl Root {
    fn same_policy(&self, other: &Self) -> bool {
        let output_key = |root: &Self| {
            root.output.as_deref().or_else(|| (!root.recursive).then_some(root.path.as_path())).map(key)
        };
        self.recursive == other.recursive && self.deep == other.deep
            && output_key(self) == output_key(other)
    }

    fn scope(&self, entries: &[Self], metadata: &[String]) -> NativeDiscoveryScope {
        let mut exclude = metadata.to_vec();
        let own = key(&self.path);
        exclude.extend(entries.iter().filter_map(|entry| {
            let nested = key(&entry.path);
            (nested != own && is_path_under(&nested, &own))
                .then(|| entry.path.to_string_lossy().into_owned())
        }));
        NativeDiscoveryScope::new(
            self.path.to_string_lossy().into_owned(),
            (!self.recursive).then_some(0),
            exclude,
        )
    }
}

fn key(path: &Path) -> String {
    watch_path_key(&path.to_string_lossy())
}

fn resolve_output(root: &Path, value: &str) -> io::Result<PathBuf> {
    // Resolve the current-user home prefix before making a relative output
    // path absolute against its Watch input root.
    if value == "~" || value.starts_with("~/") || value.starts_with("~\\") {
        let home = std::env::var_os("USERPROFILE").or_else(|| {
            let path = std::env::var_os("HOMEPATH")?;
            let mut home = std::env::var_os("HOMEDRIVE").unwrap_or_default();
            home.push(path);
            Some(home)
        });
        if let Some(home) = home {
            let path = PathBuf::from(home).join(value[1..].trim_start_matches(['/', '\\']));
            return cli::resolve(root, &path.to_string_lossy());
        }
    }
    cli::resolve(root, value)
}

fn roots_path(cwd: &Path) -> io::Result<PathBuf> {
    Ok(resources::writable_data_dir(cwd)?.join(ROOTS_FILE))
}

pub(super) fn diagnostic_roots(cwd: &Path) -> io::Result<Vec<PathBuf>> {
    read_roots(&roots_path(cwd)?).map(|roots| roots.into_iter().map(|root| root.path).collect())
}

fn configuration_changes(
    files: &HashMap<String, (bool, bool)>,
    names: Option<&[String]>,
) -> (bool, bool) {
    let Some(names) = names else {
        // Overflow/invalidated subscriptions cannot identify a single source.
        return (true, files.values().any(|(_, passwords)| *passwords));
    };
    names.iter().filter_map(|name| files.get(&crate::path_keys::case_key(name)))
        .fold((false, false), |(reload, passwords), (config, password)|
            (reload || *config, passwords || *password))
}

fn read_roots(path: &Path) -> io::Result<Vec<Root>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Vec::new()),
    };
    let text = String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut roots: Vec<Root> = Vec::new();
    let mut positions = HashMap::new();
    let cwd = std::env::current_dir()?;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('|').map(str::trim);
        let input = fields.next().unwrap();
        if input.is_empty() {
            continue;
        }
        let input = cli::resolve(&cwd, input)?;
        let output = fields
            .next()
            .filter(|output| !output.is_empty())
            .map(|output| resolve_output(&input, output))
            .transpose()?;
        let mut boolean = |field: &str| match fields.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "" | "false" => Ok(false),
            "true" => Ok(true),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {field} must be true or false", path.display(), index + 1),
            )),
        };
        let deep = boolean("deep_detect")?;
        let scanned = boolean("initial_scanned")?;
        let recursive = boolean("recursive")?;
        if fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}:{}: expected input | output | deep_detect | initial_scanned | recursive",
                    path.display(),
                    index + 1
                ),
            ));
        }
        let id = key(&input);
        let mut root = Root {
            path: input,
            output,
            recursive,
            deep,
            scanned,
        };
        if let Some(position) = positions.get(&id).copied() {
            let old: &mut Root = &mut roots[position];
            root.path = old.path.clone();
            *old = root;
        } else {
            positions.insert(id, roots.len());
            roots.push(root);
        }
    }
    Ok(roots)
}

fn write_roots(path: &Path, roots: &[Root]) -> io::Result<()> {
    use std::fmt::Write;
    let mut text = String::new();
    if let Ok(previous) = fs::read_to_string(path) {
        for comment in previous
            .lines()
            .filter(|line| line.trim_start().starts_with('#'))
        {
            writeln!(text, "{comment}").unwrap();
        }
    }
    if !text.is_empty() && !roots.is_empty() {
        text.push('\n');
    }
    for root in roots {
        let output = root
            .output
            .as_ref()
            .map(|path| path.to_string_lossy())
            .unwrap_or_default();
        writeln!(
            text,
            "{} | {} | {} | {} | {}",
            root.path.display(),
            output,
            root.deep,
            root.scanned,
            root.recursive
        )
        .unwrap();
    }
    fs::create_dir_all(path.parent().unwrap())?;
    let suffix = windows::random_bytes::<8>()?;
    let temp = path.with_extension(format!("txt.{:016x}.tmp", u64::from_ne_bytes(suffix)));
    fs::write(&temp, text)?;
    let result = crate::io::atomic_file::replace(&temp, path);
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn state_dir(cwd: &Path) -> io::Result<PathBuf> {
    Ok(resources::writable_data_dir(cwd)?.join(WATCH_METADATA))
}

fn nearest_directory(path: &Path) -> Option<&Path> {
    path.ancestors().find(|ancestor| ancestor.is_dir())
}

struct BrokerLease;

impl BrokerLease {
    fn acquire() -> io::Result<Self> {
        filesystem::watch_broker_acquire()?;
        Ok(Self)
    }
}

impl Drop for BrokerLease {
    fn drop(&mut self) {
        let _ = filesystem::watch_broker_release();
    }
}

// Keep synchronous tests/OS callbacks compatible, while async commands await
// the existing reply cell. Dropping an unserved command always wakes its caller.
enum CommandReply<T> {
    #[cfg(test)]
    Sync(mpsc::SyncSender<io::Result<T>>),
    Async(Option<Arc<Reply<T>>>),
}
impl<T> CommandReply<T> {
    fn send(mut self, value: io::Result<T>) -> io::Result<()> {
        match &mut self {
            #[cfg(test)]
            Self::Sync(send) => send.send(value).map_err(|_| io::Error::other("Watch reply disconnected")),
            Self::Async(reply) => { reply.take().unwrap().complete(value); Ok(()) }
        }
    }
}
impl<T> Drop for CommandReply<T> {
    fn drop(&mut self) {
        if let Self::Async(Some(reply)) = self { reply.complete(Err(io::ErrorKind::Interrupted.into())); }
    }
}
fn command_reply<T: Default>() -> (CommandReply<T>, Arc<Reply<T>>) {
    let reply = Arc::new(Reply::default());
    (CommandReply::Async(Some(Arc::clone(&reply))), reply)
}

// The once caller and a concurrent stop can both observe terminal completion.
#[derive(Default)]
struct RunCompletion(Mutex<(Option<Result<i32, (io::ErrorKind, String)>>, Vec<Waker>)>);
impl RunCompletion {
    fn is_complete(&self) -> bool {
        self.0.lock().unwrap().0.is_some()
    }

    fn complete(&self, result: &io::Result<i32>) {
        let wakes = {
            let mut state = self.0.lock().unwrap();
            state.0 = Some(result.as_ref().copied().map_err(|e| (e.kind(), e.to_string())));
            std::mem::take(&mut state.1)
        };
        for wake in wakes { wake.wake(); }
    }
    async fn wait(&self) -> io::Result<i32> {
        poll_fn(|cx| {
            let mut state = self.0.lock().unwrap();
            if let Some(result) = &state.0 { Poll::Ready(result.clone().map_err(|(kind, text)| io::Error::new(kind, text))) }
            else {
                if !state.1.iter().any(|wake| wake.will_wake(cx.waker())) { state.1.push(cx.waker().clone()); }
                Poll::Pending
            }
        }).await
    }
}
struct FinishRun(Arc<RunCompletion>);
impl Drop for FinishRun {
    fn drop(&mut self) {
        let missing = self.0.0.lock().unwrap().0.is_none();
        if missing { self.0.complete(&Err(io::Error::other("Watch thread failed"))); }
    }
}

pub(super) struct Watch {
    lifecycle: AsyncGate,
    running: Mutex<Option<Running>>,
    wake_host: Arc<dyn Fn() + Send + Sync>,
    external: Arc<Mutex<Option<ExternalOutputs>>>,
    generation: AtomicU64,
    last_error: Arc<Mutex<Option<String>>>,
}

struct ExternalOutputs {
    journal: Weak<journal::Journal>,
    scopes: Arc<[NativeDiscoveryScope]>,
}

impl Watch {
    pub(super) fn new(wake_host: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            lifecycle: AsyncGate::new(),
            running: Mutex::default(),
            wake_host,
            external: Arc::default(),
            generation: AtomicU64::new(0),
            last_error: Arc::default(),
        }
    }

    pub(super) fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|run| !run.thread.is_finished())
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.running.lock().unwrap().as_ref().is_some_and(Running::continuous)
    }

    pub(super) fn foreground_finished(&self, when_unwatched: impl FnOnce()) {
        let running = self.running.lock().unwrap();
        if let Some(run) = running.as_ref().filter(|run| run.continuous()) {
            run.hub.update(|signals| signals.foreground_finished = true);
        } else {
            when_unwatched();
        }
    }

    pub(super) fn generation(&self) -> u64 { self.generation.load(Ordering::Acquire) }

    pub(super) fn status(&self, cwd: &Path) -> io::Result<Value> {
        let slot = self.running.lock().unwrap();
        let run = slot.as_ref().filter(|run| run.continuous());
        Ok(json!({
            "running": run.is_some(), "generation": self.generation.load(Ordering::Relaxed),
            "pending": run.map_or(0, |run| run.hub.pending_count.load(Ordering::Relaxed)),
            "last_error": self.last_error.lock().unwrap().as_deref().unwrap_or(""),
            "state_dir": state_dir(cwd)?,
        }))
    }

    pub(super) async fn start_async(&self, cwd: &Path, engine: Arc<Engine>, tray: bool) -> io::Result<Value> {
        let (lifecycle, previous) = loop {
            let lifecycle = self.lifecycle.lock().await;
            let once = {
                let mut slot = self.running.lock().unwrap();
                if slot.as_ref().is_some_and(Running::continuous) {
                    super::diagnostics::event("watch_start_reused", json!({}));
                    return Ok(json!({"running":true,"started":false,"generation":self.generation.load(Ordering::Relaxed)}));
                }
                match slot.as_ref() {
                    Some(run) if !run.thread.is_finished() && !run.completion.is_complete() => {
                        Arc::clone(&run.completion)
                    }
                    _ => break (lifecycle, slot.take()),
                }
            };
            drop(lifecycle);
            // The one-shot command owns its work. Share the journal only
            // after that command releases it, without stopping its scan.
            let _ = once.wait().await;
        };
        if let Some(previous) = previous { let _ = Self::join_run(previous).await; }
        let (running, ready) = self.spawn_run(cwd, engine, tray, false, Cancellation::default()).await?;
        let hub = Arc::clone(&running.hub);
        *self.running.lock().unwrap() = Some(running);
        let generation = self.generation.load(Ordering::Relaxed);
        super::diagnostics::event("watch_starting", json!({"tray_enabled":tray}));
        // Like main, publish the host-owned service before readiness and allow
        // stop to interrupt startup without cancelling the caller's future.
        drop(lifecycle);
        (self.wake_host)();
        if let Err(error) = ready.wait().await {
            let _lifecycle = self.lifecycle.lock().await;
            let failed = {
                let mut slot = self.running.lock().unwrap();
                if slot.as_ref().is_some_and(|run| Arc::ptr_eq(&run.hub, &hub)) { slot.take() } else { None }
            };
            if let Some(failed) = failed { let _ = Self::join_run(failed).await; }
            return Err(error);
        }
        super::diagnostics::event("watch_started", json!({}));
        Ok(json!({"running":true,"started":true,"generation":generation}))
    }

    async fn spawn_run(&self, cwd: &Path, engine: Arc<Engine>, tray: bool, once: bool,
        cancel: Cancellation) -> io::Result<(Running, Arc<Reply<()>>)> {
        stage("watch_config", &cancel).await?;
        let snapshot = config::load_snapshot(cwd)?;
        // main applies the configured QoS before opening/handshaking the
        // shared engine. Worker acknowledgement is an async wait, not a
        // blocking Watch startup stage. Both once and continuous use this path.
        super::diagnostics::retention(snapshot.config.watch.event_log_retention_days);
        windows::configure_priority_async(&engine, snapshot.config.runtime.process_mode).await;
        engine.worker_ready(&snapshot.config.performance.worker, &cancel).await?;
        let cwd = cwd.to_path_buf();
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let wake = Arc::clone(&self.wake_host);
        let external = Arc::clone(&self.external);
        let last_error = Arc::clone(&self.last_error);
        let (ready, wait) = command_reply();
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        stage("watch_start", &Cancellation::new()).await?;
        if !once { self.generation.fetch_add(1, Ordering::Relaxed); }
        let thread = thread::Builder::new().name("sunpack-watch".into()).spawn(move || {
            let cancel_hub = Arc::clone(&worker_hub);
            let _cancel = cancel.subscribe(move || cancel_hub.cancel());
            let result = match cancel.run(|| {
                cancel.check()?;
                Scheduler::open(cwd, engine, worker_hub, !once, tray, external, snapshot)
            }) {
                Ok(scheduler) => {
                    let _ = ready.send(Ok(()));
                    scheduler.run_service(once, &last_error)
                }
                Err(error) => {
                    let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                    Err(error)
                }
            };
            if let Err(error) = &result {
                if !once && !cancel.cancelled() { *last_error.lock().unwrap() = Some(error.to_string()); }
            }
            if let Err(error) = &result {
                super::diagnostics::event("watch_failed", json!({"error":error.to_string()}));
            }
            finished.0.complete(&result);
            wake();
            result.map(|_| ())
        })?;
        Ok((Running { hub, thread, continuous: !once, completion }, wait))
    }

    async fn join_run(running: Running) -> io::Result<()> {
        let _ = running.completion.wait().await;
        // Completion precedes only thread epilogue. Join/reap is blocking work,
        // never an await on a live scheduler while holding an executor slot.
        stage("watch_close", &Cancellation::new()).await?;
        running.thread.join().map_err(|_| io::Error::other("Watch thread failed"))?
    }

    pub(super) async fn stop_async(&self) -> io::Result<Value> {
        self.stop_running(false).await
    }

    async fn stop_running(&self, include_once: bool) -> io::Result<Value> {
        let lifecycle = self.lifecycle.lock().await;
        let generation = self.generation.load(Ordering::Relaxed);
        let current = self.running.lock().unwrap().as_ref()
            .filter(|run| include_once || run.continuous())
            .map(|run| (Arc::clone(&run.hub), Arc::clone(&run.completion), !run.thread.is_finished()));
        let Some((hub, completion, stopped)) = current else {
            super::diagnostics::event("watch_stop_ignored", json!({}));
            return Ok(json!({"running":false,"stopped":false,"generation":generation}));
        };
        super::diagnostics::event("watch_stopping", json!({}));
        hub.stop();
        // Keep the old service published while it drains, as main does.
        // Concurrent start sees that service; concurrent stop joins the same
        // completion rather than serializing a new lifecycle transaction.
        drop(lifecycle);
        let result = completion.wait().await;
        let _lifecycle = self.lifecycle.lock().await;
        let running = {
            let mut slot = self.running.lock().unwrap();
            if slot.as_ref().is_some_and(|run| Arc::ptr_eq(&run.hub, &hub)) { slot.take() } else { None }
        };
        let joined = if let Some(running) = running { Self::join_run(running).await } else { Ok(()) };
        (self.wake_host)();
        if stopped {
            result?;
            joined?;
        }
        super::diagnostics::event("watch_stopped", json!({}));
        Ok(json!({"running":false,"stopped":stopped,"generation":self.generation.load(Ordering::Relaxed)}))
    }

    pub(super) async fn run_once_async(&self, cwd: &Path, engine: Arc<Engine>, cancel: &Cancellation) -> io::Result<i32> {
        cancel.check()?;
        let lifecycle = self.lifecycle.lock().await;
        let running = self.running.lock().unwrap().as_ref().filter(|run| !run.thread.is_finished())
            .map(|run| (Arc::clone(&run.hub), run.continuous, Arc::clone(&run.completion)));
        if let Some((hub, continuous, completion)) = running {
            drop(lifecycle);
            let cancelled = Arc::new(Reply::<i32>::default());
            let wake = Arc::clone(&cancelled);
            let _cancel = cancel.subscribe(move || wake.complete(Err(crate::io::cancellation::cancelled_io())));
            let mut response = Box::pin(async {
                if !continuous {
                    return completion.wait().await;
                }
                let (send, receive) = command_reply();
                if !hub.queue_once(send) { return Err(io::ErrorKind::Interrupted.into()); }
                receive.wait().await.map(|()| 0)
            });
            let mut interrupted = Box::pin(cancelled.wait());
            use std::future::Future;
            let code = poll_fn(|cx| match response.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(value),
                Poll::Pending => interrupted.as_mut().poll(cx),
            }).await?;
            cancel.check()?;
            return Ok(code);
        }
        let previous = self.running.lock().unwrap().take();
        if let Some(previous) = previous { let _ = Self::join_run(previous).await; }
        let (running, ready) = self.spawn_run(cwd, engine, false, true, cancel.clone()).await?;
        let hub = Arc::clone(&running.hub);
        let completion = Arc::clone(&running.completion);
        *self.running.lock().unwrap() = Some(running);
        drop(lifecycle);
        (self.wake_host)();
        let startup = ready.wait().await;
        let result = completion.wait().await;
        let _lifecycle = self.lifecycle.lock().await;
        let running = {
            let mut slot = self.running.lock().unwrap();
            if slot.as_ref().is_some_and(|run| Arc::ptr_eq(&run.hub, &hub)) { slot.take() } else { None }
        };
        if let Some(running) = running { let _ = Self::join_run(running).await; }
        cancel.check()?;
        startup?;
        result
    }

    pub(super) async fn reload_async(&self) -> io::Result<Value> {
        let result = self.reload_result().await?;
        let running = result.is_some();
        if !running { super::diagnostics::event("watch_reload_ignored", json!({})); }
        let reloaded = result.is_some_and(|result| result.unwrap_or(false));
        Ok(json!({"running":running,"reloaded":reloaded,"generation":self.generation.load(Ordering::Relaxed)}))
    }

    async fn reload_result(&self) -> io::Result<Option<io::Result<bool>>> {
        let hub = self.running.lock().unwrap().as_ref().filter(|run| run.continuous()).map(|run| Arc::clone(&run.hub));
        let Some(hub) = hub else { return Ok(None); };
        let (ready, wait) = command_reply();
        hub.queue_reload(Some(ready));
        Ok(Some(wait.wait().await))
    }

    // Compatibility for non-driver shutdown and existing synchronous tests.
    pub(super) fn stop(&self) -> io::Result<Value> { block_on(self.stop_running(true)) }
    #[cfg(test)]
    pub(super) fn run_once(&self, cwd: &Path, engine: Arc<Engine>, cancel: &Cancellation) -> io::Result<i32> { block_on(self.run_once_async(cwd, engine, cancel)) }
    #[cfg(test)]
    pub(super) fn reload(&self) -> io::Result<Value> { block_on(self.reload_async()) }

    pub(super) fn roots(&self, cwd: &Path) -> io::Result<(PathBuf, Vec<PathBuf>)> {
        let path = roots_path(cwd)?;
        let roots = read_roots(&path)?
            .into_iter()
            .map(|root| root.path)
            .collect();
        Ok((path, roots))
    }

    pub(super) async fn add_async(
        &self,
        cwd: &Path,
        paths: &[PathBuf],
        output: Option<&str>,
        deep: bool,
        recursive: bool,
    ) -> io::Result<Value> {
        stage("watch_directory", &Cancellation::new()).await?;
        let path = roots_path(cwd)?;
        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut rejected = Vec::new();
        let running = self.is_enabled();
        {
            let _lock = FileMutex::lock(&path, ROOTS_LOCK)?;
            let mut roots = read_roots(&path)?;
            for root in paths {
                let id = key(root);
                if let Some(existing) = roots.iter_mut().find(|entry| key(&entry.path) == id) {
                    let changed = (recursive && !existing.recursive) || (deep && !existing.deep);
                    existing.scanned &= !recursive || existing.recursive;
                    existing.recursive |= recursive;
                    existing.deep |= deep;
                    if changed {
                        updated.push(existing.path.clone());
                    }
                    continue;
                }
                roots.push(Root {
                    path: root.clone(),
                    output: output.map(str::trim).filter(|value| !value.is_empty())
                        .map(|value| resolve_output(root, value)).transpose()?,
                    deep,
                    recursive,
                    scanned: false,
                });
                added.push(root.clone());
            }
            if !added.is_empty() || !updated.is_empty() {
                write_roots(&path, &roots)?;
            }
        }
        let changed = !added.is_empty() || !updated.is_empty();
        let apply = self.root_change_status(running, changed).await?;
        if running && changed {
            stage("watch_directory", &Cancellation::new()).await?;
            let retained: HashSet<_> = read_roots(&path)?.iter().map(|root| key(&root.path)).collect();
            for changes in [&mut added, &mut updated] {
                changes.retain(|root| {
                    let keep = retained.contains(&key(root));
                    if !keep {
                        rejected.push(root.clone());
                    }
                    keep
                });
            }
        }
        let apply = apply.map(|(applied, generation)| {
            json!({
                "roots_path":path,"added":added,"updated":updated,"rejected":rejected,
                "applied":applied && (!added.is_empty() || !updated.is_empty()),
                "running":true,"generation":generation,
            })
        });
        if let Some(apply) = &apply {
            super::diagnostics::event("watch_roots_added", json!({"added":added,"updated":updated,"applied":apply["applied"]}));
        }
        Ok(json!({
            "roots_path":path,"added":added,"updated":updated,"rejected":rejected,
            "apply":apply,"start":null,
        }))
    }

    pub(super) async fn remove_async(&self, cwd: &Path, paths: &[PathBuf]) -> io::Result<Value> {
        stage("watch_directory", &Cancellation::new()).await?;
        let path = roots_path(cwd)?;
        let mut removed = Vec::new();
        {
            let _lock = FileMutex::lock(&path, ROOTS_LOCK)?;
            let keys: HashSet<_> = paths.iter().map(|path| key(path)).collect();
            let mut roots = read_roots(&path)?;
            roots.retain(|root| {
                if keys.contains(&key(&root.path)) {
                    removed.push(root.path.clone());
                    false
                } else {
                    true
                }
            });
            if !removed.is_empty() {
                write_roots(&path, &roots)?;
            }
        }
        let apply = self
            .root_change_status(self.is_enabled(), !removed.is_empty()).await?
            .map(|(applied, generation)| {
                json!({
                    "roots_path":path,"removed":removed,"applied":applied,
                    "running":true,"generation":generation,
                })
            });
        if let Some(apply) = &apply {
            super::diagnostics::event("watch_roots_removed", json!({"removed":removed,"applied":apply["applied"]}));
        }
        Ok(json!({"roots_path":path,"removed":removed,"apply":apply}))
    }

    async fn root_change_status(&self, running: bool, changed: bool) -> io::Result<Option<(bool, u64)>> {
        if !running {
            return Ok(None);
        }
        let applied = changed && self.reload_result().await?.transpose()?.is_some();
        Ok(Some((applied, self.generation.load(Ordering::Relaxed))))
    }

    pub(super) async fn rebuild_log_async(&self, cwd: &Path) -> io::Result<bool> {
        let hub = self
            .running
            .lock()
            .unwrap()
            .as_ref()
            .filter(|run| !run.thread.is_finished())
            .map(|run| Arc::clone(&run.hub));
        if let Some(hub) = hub {
            let (send, receive) = command_reply();
            hub.update(|signals| signals.rebuild.push(send));
            return receive.wait().await;
        }
        stage("catalog_maintenance", &Cancellation::new()).await?;
        let dir = state_dir(cwd)?;
        let snapshot = config::load_snapshot(cwd)?;
        Ok(journal::Journal::open(&dir, snapshot.config.watch.event_log_retention_days)
            .and_then(|state| state.rebuild_log()).unwrap_or(false))
    }

    pub(super) async fn cancel_batch_async(&self, id: &str) -> bool {
        let hub = self
            .running
            .lock()
            .unwrap()
            .as_ref()
            .filter(|run| !run.thread.is_finished())
            .map(|run| Arc::clone(&run.hub));
        let Some(hub) = hub else {
            return false;
        };
        let (send, receive) = command_reply();
        hub.update(|signals| signals.cancel.push((id.to_owned(), send)));
        receive.wait().await.unwrap_or(false)
    }
}

impl Watch {
    fn external_journal(&self) -> Option<(Arc<journal::Journal>, Arc<[NativeDiscoveryScope]>)> {
        let external = self.external.lock().unwrap();
        let external = external.as_ref()?;
        Some((external.journal.upgrade()?, Arc::clone(&external.scopes)))
    }

    pub(super) fn register_external_output(&self, path: &Path) -> io::Result<()> {
        if let Some((journal, scopes)) = self.external_journal() {
            // Notification classification takes this same publication gate.
            // Never expose a created output before its owned identity exists.
            journal.commit(true, |state| {
                crate::scan::scope::create_output_root_exclusive(path)
                    .map_err(crate::pipeline::OutputCreateError::wrap)?;
                let paths = crate::path_keys::output_path_aliases(path)?;
                if !paths.iter().any(|path| scopes.iter().any(|scope| scope.intersects_output(path)))
                    || paths.iter().any(|path| state.owned_root(path).is_some())
                {
                    return Ok(crate::watch_store::NativeWatchOperations::empty());
                }
                let identity = output_identity(&path.to_string_lossy())?;
                Ok(crate::watch_store::NativeWatchOperations::owned_outputs(&paths, &[&identity]))
            })?;
        } else {
            crate::scan::scope::create_output_root_exclusive(path)
                .map_err(crate::pipeline::OutputCreateError::wrap)?;
        }
        Ok(())
    }

    pub(super) fn prepare_external_flatten(
        &self,
        output: &Path,
        work: &Path,
        leaf: &Path,
    ) -> io::Result<()> {
        if let Some((journal, scopes)) = self.external_journal() {
            let paths = crate::path_keys::output_path_aliases(output)?;
            if paths.iter().any(|path| scopes.iter().any(|scope| scope.intersects_output(path))) {
                prepare_flatten(&journal, "", output, work, leaf)?;
            }
        }
        Ok(())
    }

    pub(super) fn finish_external_flatten(&self, output: &Path) -> io::Result<()> {
        if let Some((journal, _)) = self.external_journal() {
            finish_flatten(&journal, &output.to_string_lossy())?;
        }
        Ok(())
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn validate_outputs(roots: &[Root]) -> io::Result<()> {
    let output: Vec<_> = roots
        .iter()
        .filter_map(|root| root.output.as_deref().map(|output| (&root.path, output, key(output))))
        .collect();
    for (index, (first_root, first_output, first_key)) in output.iter().enumerate() {
        for (second_root, second_output, second_key) in &output[index + 1..] {
            if first_key != second_key
                && (is_path_under(first_key, second_key) || is_path_under(second_key, first_key))
            {
                return Err(io::Error::other(format!(
                    "watch output roots must not contain one another: {} -> {}; {} -> {}",
                    first_root.display(), first_output.display(),
                    second_root.display(), second_output.display(),
                )));
            }
        }
    }
    Ok(())
}

struct Running {
    hub: Arc<Hub>,
    thread: JoinHandle<io::Result<()>>,
    continuous: bool,
    completion: Arc<RunCompletion>,
}

impl Running {
    fn continuous(&self) -> bool {
        self.continuous && !self.thread.is_finished()
    }
}

// Keep the native volume facts until roots can be selected without filesystem IO.
// Both directions require rearm/checkpoint; only arrival requests directory work.
#[derive(Default)]
struct VolumeChanges {
    affected: u32,
    arrivals: u32,
    initial: bool,
}

impl VolumeChanges {
    fn add(&mut self, mask: u32, arrived: bool) {
        if mask == 0 { self.initial = true; }
        else {
            self.affected |= mask;
            if arrived { self.arrivals |= mask; }
        }
    }
    fn is_empty(&self) -> bool { self.affected == 0 && !self.initial }
    fn disk(path: &Path) -> u32 {
        match path.components().next() {
            Some(std::path::Component::Prefix(prefix)) => match prefix.kind() {
                std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter)
                    if letter.is_ascii_alphabetic() => 1 << (letter.to_ascii_uppercase() - b'A'),
                _ => 0,
            },
            _ => 0,
        }
    }
    fn affects(&self, root: &Path, observed: bool) -> bool {
        self.affected & Self::disk(root) != 0 || (self.initial && !observed)
    }
    fn arrives(&self, root: &Path, observed: bool) -> bool {
        self.arrivals & Self::disk(root) != 0 || (self.initial && !observed)
    }
}

// Only ordinary native notifications carry provenance. Recovery/checkpoint
// observations must not inherit an unrelated event from an earlier burst.
#[derive(Debug, PartialEq, Eq)]
enum CandidateEvent {
    Created,
    Modified,
    Moved(PathBuf),
    Business(&'static str),
}

impl CandidateEvent {
    fn native(action: u32, path: &Path, rename_source: &mut Option<PathBuf>) -> Option<Self> {
        match action {
            1 => Some(Self::Created),
            3 => Some(Self::Modified),
            4 => { *rename_source = Some(path.to_owned()); None }
            5 => rename_source.take().map(Self::Moved),
            _ => None,
        }
    }

    fn kind(&self) -> &'static str {
        match self { Self::Created => "created", Self::Modified => "modified", Self::Moved(_) => "moved", Self::Business(kind) => kind }
    }

    fn source(&self) -> std::borrow::Cow<'_, str> {
        match self { Self::Moved(path) => path.to_string_lossy(), _ => "".into() }
    }
}

#[derive(Default)]
struct Signals {
    changed_roots: HashMap<String, HashSet<PathBuf>>,
    topology_roots: HashSet<String>,
    modified_paths: HashSet<PathBuf>,
    candidate_events: HashMap<PathBuf, CandidateEvent>,
    activities: HashMap<PathBuf, quiet::Activity>,
    reload: bool,
    reload_waiters: Vec<CommandReply<bool>>,
    once: Vec<CommandReply<()>>,
    password_changed: bool,
    foreground_finished: bool,
    maintenance: bool,
    volumes: VolumeChanges,
    rebuild: Vec<CommandReply<bool>>,
    cancel: Vec<(String, CommandReply<bool>)>,
    roots: Vec<RootCompleted>,
    completed: Vec<String>,
    claimed: HashSet<String>,
}

impl Signals {
    fn prepare_root_changes(changed_roots: &mut HashMap<String, HashSet<PathBuf>>,
        topology_roots: &HashSet<String>, modified_paths: &HashSet<PathBuf>) -> bool {
        // Directory modified is not an arrival. Its USN progress is merged
        // by idle maintenance, not a named subtree scan.
        for paths in changed_roots.values_mut() {
            paths.retain(|path| !modified_paths.contains(path) || !path.is_dir());
        }
        !topology_roots.is_empty() || changed_roots.values().any(|paths|
            paths.iter().any(|path| !modified_paths.contains(path) && !path.is_file()))
    }

    fn root_changed(&mut self, id: &str, paths: Option<Vec<PathBuf>>) {
        // Overflow/failure has no path list and invalidates the subscription;
        // named content events need catalog work, not parent identity probes.
        if paths.is_none() {
            self.topology_roots.insert(id.to_owned());
        }
        self.changed_roots.entry(id.to_owned()).or_default()
            .extend(paths.into_iter().flatten());
    }
}

struct Hub {
    stopped: AtomicBool,
    cancelled: AtomicBool,
    signals: Mutex<Signals>,
    wake: std::sync::Condvar,
    claims: Mutex<HashMap<String, Arc<str>>>,
    completed_families: Mutex<CompletedFamilies>,
    activities: Arc<quiet::Activities>,
    pending_count: AtomicUsize,
}

type SourceGenerations = HashMap<String, PhysicalFileGeneration>;

// Like main's completed Watch family cache, this outlives candidate admission but
// remains bounded. Receipt publication can lag behind source lease release.
const COMPLETED_FAMILY_LIMIT: usize = 4096;
type CompletedFamilyKey = (Arc<[String]>, bool);

#[derive(Default)]
struct CompletedFamilies {
    sequence: u64,
    by_family: HashMap<CompletedFamilyKey, u64>,
    ordered: BTreeMap<u64, (CompletedFamilyKey, SourceGenerations, PathBuf)>,
}

impl CompletedFamilies {
    fn remember(&mut self, generations: SourceGenerations, deep: bool, output: &Path) {
        if generations.is_empty() { return; }
        let mut members: Vec<_> = generations.keys().cloned().collect();
        members.sort_unstable();
        let family = (Arc::from(members), deep);
        if let Some(previous) = self.by_family.remove(&family) { self.ordered.remove(&previous); }
        self.sequence += 1;
        self.by_family.insert(family.clone(), self.sequence);
        self.ordered.insert(self.sequence, (family, generations, output.to_owned()));
        while self.ordered.len() > COMPLETED_FAMILY_LIMIT {
            let (_, (family, _, _)) = self.ordered.pop_first().unwrap();
            self.by_family.remove(&family);
        }
    }

    fn output(&mut self, generations: &SourceGenerations, deep: bool) -> Option<PathBuf> {
        let mut members: Vec<_> = generations.keys().cloned().collect();
        members.sort_unstable();
        let sequence = *self.by_family.get(&(Arc::from(members), deep))?;
        let (_, previous, _) = &self.ordered[&sequence];
        if !generations.iter().all(|(path, current)| current.matches_input(&previous[path].persisted())) {
            return None;
        }
        self.refresh_output(sequence).map(Path::to_path_buf)
    }

    fn covers(&mut self, path: &Path, deep: bool) -> bool {
        let path = key(path);
        let matched = self.ordered.iter().find_map(|(sequence, (family, generations, _))| {
            if family.1 != deep || !generations.contains_key(&path) { return None; }
            // Require the entire current family, not only the old request's head.
            generations.iter().all(|(member, previous)| {
                crate::io::reader::capture_file_generation(Path::new(member))
                    .is_ok_and(|current| current.matches_input(&previous.persisted()))
            }).then_some(*sequence)
        });
        matched.is_some_and(|sequence| self.refresh_output(sequence).is_some())
    }

    fn refresh_output(&mut self, sequence: u64) -> Option<&Path> {
        let (family, generations, output) = self.ordered.remove(&sequence)?;
        if !output.is_dir() { self.by_family.remove(&family); return None; }
        self.sequence += 1;
        self.by_family.insert(family.clone(), self.sequence);
        self.ordered.insert(self.sequence, (family, generations, output));
        Some(self.ordered[&self.sequence].2.as_path())
    }
}

impl Hub {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            signals: Mutex::default(),
            wake: std::sync::Condvar::new(),
            claims: Mutex::default(),
            completed_families: Mutex::default(),
            activities: Arc::default(),
            pending_count: AtomicUsize::new(0),
        }
    }

    fn stop(&self) {
        {
            let _guard = self.signals.lock().unwrap();
            self.stopped.store(true, Ordering::Release);
        }
        self.wake.notify_one();
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.stop();
    }

    fn queue_once(&self, waiter: CommandReply<()>) -> bool {
        let mut signals = self.signals.lock().unwrap();
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        signals.once.push(waiter);
        drop(signals);
        self.wake.notify_one();
        true
    }

    fn clear_idle_completed_families(&self) {
        // Drop both entries and their allocated tables at the existing idle
        // maintenance boundary, as main clears completed Watch generations.
        *self.completed_families.lock().unwrap() = CompletedFamilies::default();
    }

    fn root_completed(&self, root: RootCompleted) {
        self.signals.lock().unwrap().roots.push(root);
        self.wake.notify_one();
    }

    fn batch_completed(&self, batch: String) {
        // Intake is stopped before drain, but in-flight completions still own
        // the wake that lets drain finish without polling or blocking joins.
        self.signals.lock().unwrap().completed.push(batch);
        self.wake.notify_one();
    }

    fn wait_drain(&self, cancellation_observed: bool) -> Signals {
        let guard = self.signals.lock().unwrap();
        let mut guard = self.wake.wait_while(guard, |signals| {
            signals.completed.is_empty()
                && signals.roots.is_empty()
                && signals.cancel.is_empty()
                && (cancellation_observed || !self.cancelled.load(Ordering::Acquire))
        }).unwrap();
        // Policy reload drains the old generation without consuming its next
        // configuration/root notifications or callers waiting for a new tick.
        Signals {
            roots: std::mem::take(&mut guard.roots),
            completed: std::mem::take(&mut guard.completed),
            cancel: std::mem::take(&mut guard.cancel),
            ..Signals::default()
        }
    }

    fn update(&self, update: impl FnOnce(&mut Signals)) {
        let mut signals = self.signals.lock().unwrap();
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        update(&mut signals);
        drop(signals);
        self.wake.notify_one();
    }

    fn queue_reload(&self, wait: Option<CommandReply<bool>>) {
        self.update(|signals| {
            signals.reload = true;
            signals.reload_waiters.extend(wait);
        });
    }

    fn wait(&self, deadline: Option<Instant>) -> Signals {
        let guard = self.signals.lock().unwrap();
        let unchanged = |value: &mut Signals| {
            !self.stopped.load(Ordering::Acquire)
                && value.changed_roots.is_empty()
                && !value.reload
                && !value.password_changed
                && !value.maintenance
                && !value.foreground_finished
                && value.volumes.is_empty()
                && value.rebuild.is_empty()
                && value.cancel.is_empty()
                && value.once.is_empty()
                && value.claimed.is_empty()
                && value.completed.is_empty()
                && value.roots.is_empty()
        };
        let mut guard = if let Some(deadline) = deadline {
            self.wake
                .wait_timeout_while(
                    guard,
                    deadline.saturating_duration_since(Instant::now()),
                    unchanged,
                )
                .unwrap()
                .0
        } else {
            self.wake.wait_while(guard, unchanged).unwrap()
        };
        std::mem::take(&mut *guard)
    }
}

fn configuration_targets(paths: &[PathBuf], passwords: &Path) -> io::Result<HashMap<PathBuf, HashMap<String, (bool, bool)>>> {
    let mut targets: HashMap<PathBuf, HashMap<String, (bool, bool)>> = HashMap::new();
    for path in paths.iter().map(PathBuf::as_path).filter(|path| *path != passwords).chain([passwords]) {
        let password = path == passwords;
        // Source selection retains the lexical path so replacement or a new
        // higher-priority file can wake the runtime. Watch its resolved name
        // too when a config file points elsewhere, as main does.
        let resolved: Option<PathBuf> = (!password).then(|| fs::canonicalize(path).ok())
            .flatten()
            .map(|path| PathBuf::from(crate::path_keys::normalize_windows_extended_prefix(path.to_string_lossy().into_owned())))
            .filter(|resolved| key(resolved) != key(path));
        for path in std::iter::once(path).chain(resolved.as_deref()) {
            let parent = path.parent().and_then(nearest_directory).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("No observable configuration directory for {}", path.display()))
            })?;
            let Some(name) = path.strip_prefix(parent).ok().and_then(|path| path.components().next()) else {
                continue;
            };
            let target = targets.entry(parent.to_owned()).or_default().entry(
                crate::path_keys::case_key(&name.as_os_str().to_string_lossy()),
            ).or_default();
            // A missing parent is watched through its nearest ancestor. Its
            // arrival can replace configuration and password sources together.
            target.0 |= !password || parent.join(name.as_os_str()) != path;
            target.1 |= password;
        }
    }
    Ok(targets)
}

pub(super) fn observes_files(paths: &[PathBuf], passwords: &Path, observers: &[ConfigSubscription]) -> bool {
    let Ok(targets) = configuration_targets(paths, passwords) else { return false; };
    targets.len() == observers.len() && observers.iter().all(|subscription| {
        subscription.alive() && targets.get(&subscription.directory.observer.path).is_some_and(|files| {
            subscription.directory.listeners.lock().unwrap().get(&subscription.id)
                .is_some_and(|listener| listener.files == *files)
        })
    })
}

pub(super) fn observe_files(
    paths: &[PathBuf], passwords: &Path,
    notify: impl Fn(bool, bool) + Send + Sync + 'static,
) -> io::Result<Vec<ConfigSubscription>> {
    let targets = configuration_targets(paths, passwords)?;
    let notify = Arc::new(notify);
    targets.into_iter().map(|(dir, files)| {
        let notify = Arc::clone(&notify);
        ConfigSubscription::start(&dir, files, notify)
    }).collect()
}

// Configuration readers share native subscriptions by directory. File filters
// remain per reader, so a Watch reload and a CLI cache invalidation use their
// existing notification paths without duplicating threads and handles.
type ConfigNotify = Arc<dyn Fn(bool, bool) + Send + Sync>;
struct ConfigListener {
    files: HashMap<String, (bool, bool)>,
    notify: ConfigNotify,
}
struct ConfigDirectory {
    observer: FileObserver,
    listeners: Arc<Mutex<HashMap<u64, ConfigListener>>>,
}
pub(super) struct ConfigSubscription {
    directory: Arc<ConfigDirectory>,
    id: u64,
}
impl ConfigSubscription {
    pub(super) fn alive(&self) -> bool { self.directory.observer.alive() }

    fn start(path: &Path, files: HashMap<String, (bool, bool)>, notify: ConfigNotify) -> io::Result<Self> {
        static DIRECTORIES: OnceLock<Mutex<HashMap<String, Weak<ConfigDirectory>>>> = OnceLock::new();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut directories = DIRECTORIES.get_or_init(Mutex::default).lock().unwrap();
        directories.retain(|_, entry| entry.strong_count() != 0);
        let path_key = key(path);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let listener = ConfigListener { files, notify };
        let directory = match directories.get(&path_key).and_then(Weak::upgrade)
            .filter(|entry| entry.observer.alive()) {
            Some(directory) => {
                directory.listeners.lock().unwrap().insert(id, listener);
                directory
            }
            None => {
                let listeners = Arc::new(Mutex::new(HashMap::from([(id, listener)])));
                let events = Arc::clone(&listeners);
                let observer = FileObserver::start(path, false, move |names| {
                    for listener in events.lock().unwrap().values() {
                        let (config, passwords) = configuration_changes(&listener.files, names.as_deref());
                        if config || passwords { (listener.notify)(config, passwords); }
                    }
                })?;
                let directory = Arc::new(ConfigDirectory { observer, listeners });
                directories.insert(path_key, Arc::downgrade(&directory));
                directory
            }
        };
        Ok(Self { directory, id })
    }
}
impl Drop for ConfigSubscription {
    fn drop(&mut self) {
        self.directory.listeners.lock().unwrap().remove(&self.id);
    }
}

pub(super) struct FileObserver {
    path: PathBuf,
    changes: Arc<NativeConfigChanges>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FileObserver {
    pub(super) fn alive(&self) -> bool { !self.stopping.load(Ordering::Acquire) }

    pub(super) fn start(
        path: &Path,
        recursive: bool,
        notify: impl Fn(Option<Vec<String>>) + Send + 'static,
    ) -> io::Result<Self> {
        Self::start_with_filter(path, recursive, 0x01 | 0x02 | 0x08 | 0x10, 4096, move |changes| {
            notify(changes.map(|changes| changes.into_iter().map(|change| change.name).collect()));
        })
    }

    fn start_with_filter(
        path: &Path,
        recursive: bool,
        filter: u32,
        buffer_bytes: usize,
        notify: impl Fn(Option<Vec<DirectoryChange>>) + Send + 'static,
    ) -> io::Result<Self> {
        let changes = Arc::new(NativeConfigChanges::observe(path.to_owned(), recursive, filter, buffer_bytes)?);
        let stopping = Arc::new(AtomicBool::new(false));
        let read = Arc::clone(&changes);
        let stop = Arc::clone(&stopping);
        let thread = thread::Builder::new()
            .name("sunpack-directory-events".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let result = read.read();
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match result {
                        Ok(names) => notify(names),
                        Err(_) => {
                            stop.store(true, Ordering::Release);
                            notify(None);
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            path: path.to_owned(),
            changes,
            stopping,
            thread: Some(thread),
        })
    }
}

impl Drop for FileObserver {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.changes.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct RootObserver {
    observer: FileObserver,
    identity: String,
}

impl RootObserver {
    fn matches(&self, path: &Path) -> bool {
        key(path) == key(&self.observer.path)
            && self.observer.alive()
            && output_identity(&path.to_string_lossy()).is_ok_and(|identity| identity == self.identity)
    }

    fn start(
        directory: &Path,
        root: &Root,
        scope: NativeDiscoveryScope,
        passwords: &Path,
        hub: &Arc<Hub>,
        journal: &Arc<journal::Journal>,
        catalog: &Arc<NativeWatchCatalog>,
    ) -> io::Result<Self> {
        let identity = output_identity(&directory.to_string_lossy())?;
        let id = key(&root.path);
        let watched_dir = directory.to_owned();
        let recursive = root.recursive;
        let password_name = passwords.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let password_path = key(passwords);
        let hub = Arc::clone(hub);
        let journal = Arc::clone(journal);
        let catalog = Arc::clone(catalog);
        // Match watchdog's business-root notifications, including ACL and
        // attributes-only changes that can make an unreadable candidate usable.
        // Use watchdog 6.0.0's exact 64,000-byte business-root buffer; small
        // configuration/ancestor subscriptions keep their 4 KiB allocation.
        let observer = FileObserver::start_with_filter(
            directory, recursive, 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x100, 64_000, move |names| {
            let mut modified = HashSet::new();
            let mut topology = HashSet::new();
            let mut password_changed = false;
            let mut events = HashMap::new();
            let mut rename_source = None;
            let mut paths = names.map(|names| names.into_iter()
                .filter_map(|change| {
                    let path = watched_dir.join(change.name);
                    let event = CandidateEvent::native(change.action, &path, &mut rename_source);
                    if path.file_name().is_some_and(|name| {
                        name.to_string_lossy().eq_ignore_ascii_case(&password_name)
                    }) && key(&path) == password_path {
                        password_changed = true;
                        return None;
                    }
                    if change.action == 3 { modified.insert(path.clone()); }
                    else { topology.insert(path.clone()); }
                    if let Some(event) = event { events.entry(path.clone()).or_insert(event); }
                    Some(path)
                })
                .filter(|path| scope.contains(&path.to_string_lossy())).collect::<Vec<_>>());
            let mut activities = HashMap::new();
            if let Some(paths) = paths.as_mut() {
                for path in paths.iter() {
                    let key = key(path);
                    if hub.claims.lock().unwrap().contains_key(&key) || catalog.is_owned(&path.to_string_lossy()) { continue; }
                    let activity = hub.activities.bind(key.clone(), || {
                        catalog.observation(&path.to_string_lossy())
                            .as_ref().map_or_else(quiet::Activity::default, quiet::Activity::saved)
                    });
                    if activity.capture(path, &hub.claims, &key).unwrap_or(false) {
                        activities.insert(path.clone(), activity);
                    }
                }
                journal.filter_owned_events(paths, &watched_dir);
                let retained: HashSet<_> = paths.iter().collect();
                activities.retain(|path, _| retained.contains(path));
            }
            let root_changed = paths.as_ref().is_none_or(|paths| !paths.is_empty());
            if password_changed || root_changed {
                hub.update(|signals| {
                    signals.activities.extend(activities);
                    signals.password_changed |= password_changed;
                    if !root_changed { return; }
                    if let Some(paths) = &paths {
                        for path in paths {
                            if let Some(event) = events.remove(path) {
                                signals.candidate_events.entry(path.clone()).or_insert(event);
                            }
                            if topology.contains(path) {
                                signals.modified_paths.remove(path);
                            } else if modified.contains(path)
                                && !signals.changed_roots.get(&id).is_some_and(|old| old.contains(path)) {
                                signals.modified_paths.insert(path.clone());
                            }
                        }
                    }
                    signals.root_changed(&id, paths);
                });
            }
        })?;
        Ok(Self { observer, identity })
    }
}

// Retirement, scanning and recovery acknowledge separate parts of a durable
// policy change. Publishing roots must not erase obligations on partial failure.
#[derive(Default)]
struct RootPolicyProgress {
    retirement: bool,
    checkpoint: bool,
    recovery: bool,
}

impl RootPolicyProgress {
    fn observe(&mut self, policy_changed: bool, initialize: bool) -> bool {
        self.checkpoint |= policy_changed;
        self.recovery |= policy_changed;
        self.retirement |= policy_changed || initialize;
        self.retirement
    }

    fn checkpoint_finished(&mut self, result: &io::Result<()>) {
        if result.is_ok() { self.checkpoint = false; }
    }
}

// Matches main's _config_without_tray: these two fields affect the
// service shell/process, not scheduler scan policy.
fn scheduler_configuration_changed(previous: &Config, next: &Config) -> bool {
    let mut normalized = next.clone();
    normalized.watch.tray_enabled = previous.watch.tray_enabled;
    normalized.runtime.process_mode = previous.runtime.process_mode;
    previous != &normalized
}

fn watch_scan_options(config: &Config, has_roots: bool) -> io::Result<Option<NativeDirectoryScanOptions>> {
    if has_roots {
        // Main compiles ordinary rules even when every configured root is deep.
        crate::pipeline::scan_options(config).map(Some)
    } else {
        Ok(None)
    }
}

// Parent notifications are shared; root identities are still checked by each
// root observer when the fanout reaches the scheduler.
struct ParentObserver {
    observer: RootObserver,
    members: Arc<Mutex<HashMap<String, String>>>,
}

fn parent_memberships<'a>(roots: impl Iterator<Item = &'a Root>) -> HashMap<String, (PathBuf, HashMap<String, String>)> {
    let mut desired = HashMap::<String, (PathBuf, HashMap<String, String>)>::new();
    for root in roots {
        if let Some(parent) = root.path.parent().and_then(nearest_directory) {
            let directory = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_owned());
            let event_path = directory.join(root.path.strip_prefix(parent).unwrap_or(&root.path));
            desired.entry(key(&directory)).or_insert_with(|| (directory, HashMap::new()))
                .1.insert(key(&root.path), key(&event_path));
        }
    }
    desired
}

fn affected_parent_roots(members: &HashMap<String, String>, changed: Option<&[String]>) -> Vec<String> {
    members.iter().filter(|(_, target)| changed.is_none_or(|paths| paths.iter().any(|path| {
        path.as_str() == target.as_str() || is_path_under(target.as_str(), path.as_str())
    }))).map(|(root, _)| root.clone()).collect()
}

impl ParentObserver {
    fn start(directory: &Path, members: HashMap<String, String>, hub: &Arc<Hub>) -> io::Result<Self> {
        let identity = output_identity(&directory.to_string_lossy())?;
        let members = Arc::new(Mutex::new(members));
        let watched_members = Arc::clone(&members);
        let watched_dir = directory.to_owned();
        let hub = Arc::clone(hub);
        let observer = FileObserver::start_with_filter(directory, false, 0x01 | 0x02 | 0x08 | 0x10, 4096, move |names| {
            let changed = names.map(|names| names.into_iter()
                .filter(|change| change.action != 3)
                .map(|change| key(&watched_dir.join(change.name))).collect::<Vec<_>>());
            let affected = affected_parent_roots(&watched_members.lock().unwrap(), changed.as_deref());
            if !affected.is_empty() {
                hub.update(|signals| for root in affected {
                    signals.topology_roots.insert(root.clone());
                    signals.changed_roots.entry(root).or_default();
                });
            }
        })?;
        Ok(Self { observer: RootObserver { observer, identity }, members })
    }
}

#[derive(Default)]
struct RootObservers {
    root: Option<RootObserver>,
}

impl RootObservers {
    fn rearm(
        &mut self,
        root: &Root,
        scope: &NativeDiscoveryScope,
        passwords: &Path,
        hub: &Arc<Hub>,
        journal: &Arc<journal::Journal>,
        catalog: &Arc<NativeWatchCatalog>,
    ) -> (bool, Vec<io::Error>) {
        let mut errors = Vec::new();
        // A root can grant access even when its parent only permits traversal.
        // Failure of the extra sentinel must not disable the root subscription.
        let replaced = self.root.as_ref().is_some_and(|observer| !observer.matches(&root.path));
        if replaced {
            self.root.take();
        }
        if self.root.is_none() && root.path.is_dir() {
            match RootObserver::start(&root.path, root, scope.clone(), passwords, hub, journal, catalog) {
                Ok(observer) => self.root = Some(observer),
                Err(error) => errors.push(error),
            }
        }
        (replaced, errors)
    }
}

// Like main's _pop_ready, bound both the readiness probes in this round and
// the temporary key snapshot. Unselected due entries keep their old deadlines.
fn due_admissions(
    due: &BTreeMap<(Instant, String), ()>,
    now: Instant,
    limit: usize,
    mut eligible: impl FnMut(&str) -> bool,
) -> Vec<(Instant, String)> {
    due.keys()
        .take_while(|(deadline, _)| *deadline <= now)
        .filter(|(_, path)| eligible(path))
        .take(limit)
        .cloned()
        .collect()
}

struct Pending {
    // Readiness is reusable only across the current admission checkpoint.
    admission_ready: bool,
    root: String,
    candidate: WatchCandidateRow,
    quiet: quiet::Activity,
    due: Instant,
    force: bool,
    recovery: Option<Arc<Recovery>>,
}

// One bounded history for both admission waits (30s) and observation errors
// (300s), matching main's event/path diagnostic ownership and expiry.
#[derive(Default)]
struct CandidateDiagnostics {
    paths: HashMap<Arc<str>, [Option<Instant>; 3]>,
    order: VecDeque<(Instant, Arc<str>, usize)>,
    next_expiry: Option<Instant>,
}

impl CandidateDiagnostics {
    fn retire_first(&mut self) {
        if let Some((_, path, event)) = self.order.pop_front() {
            let slots = self.paths.get_mut(&path).unwrap();
            slots[event] = None;
            if slots.iter().all(Option::is_none) { self.paths.remove(&path); }
        }
    }

    fn clear_expired(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|expiry| expiry > now) { return; }
        let paths = &mut self.paths;
        self.order.retain(|(expiry, path, event)| {
            if *expiry > now { return true; }
            let slots = paths.get_mut(path).unwrap();
            slots[*event] = None;
            if slots.iter().all(Option::is_none) { paths.remove(path); }
            false
        });
        self.next_expiry = self.order.iter().map(|(expiry, _, _)| *expiry).min();
        if self.order.is_empty() {
            self.paths = HashMap::new();
            self.order = VecDeque::new();
        }
    }

    fn deadline(&self) -> Option<Instant> { self.next_expiry }

    fn admit(&mut self, now: Instant, id: &str, event: usize, seconds: u64) -> bool {
        self.clear_expired(now);
        if self.paths.get(id).is_some_and(|slots| slots[event].is_some()) { return false; }
        if self.order.len() == 2048 { self.retire_first(); }
        let id = self.paths.get_key_value(id).map(|(id, _)| Arc::clone(id))
            .unwrap_or_else(|| Arc::from(id));
        let expiry = now + std::time::Duration::from_secs(seconds);
        self.paths.entry(Arc::clone(&id)).or_insert([None; 3])[event] = Some(expiry);
        self.order.push_back((expiry, id, event));
        self.next_expiry = Some(self.next_expiry.map_or(expiry, |next| next.min(expiry)));
        true
    }

    fn error_type(error: &io::Error) -> &'static str {
        match error.kind() {
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::NotFound => "FileNotFoundError",
            _ => "OSError",
        }
    }

    fn log_observation(&mut self, journal: &journal::Journal, now: Instant,
        id: &str, path: &str, error: &io::Error, event: Option<&CandidateEvent>) {
        if !self.admit(now, id, 2, 300) { return; }
        journal.log(Self::observation_record(path, error, event));
    }

    fn observation_record(path: &str, error: &io::Error, event: Option<&CandidateEvent>) -> Value {
        json!({"event":"candidate_ignored", "path":path,
            "reason":"observation_error", "event_type":event.map_or("unknown", CandidateEvent::kind),
            "src_path":event.map_or_else(|| "".into(), CandidateEvent::source),
            "error":format!("{}: {error}", Self::error_type(error)),
        })
    }

    fn log_wait(&mut self, journal: &journal::Journal, now: Instant, id: &str,
                path: &str, error: Option<&io::Error>) {
        if !self.admit(now, id, usize::from(error.is_some()), 30) { return; }
        match error {
            Some(error) => journal.log(json!({
                "event":"candidate_error", "path":path,
                "error":error.to_string(), "error_type":Self::error_type(error),
            })),
            None => journal.log(json!({"event":"candidate_busy","path":path})),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateAdmission {
    Observe,
    Retry,
    QueuedRecovery,
    CrashRecovery,
    PasswordRetry,
    // Startup USN recovery and pipeline completion errors may clear an
    // interrupted generation even when the content is unchanged.
    ExplicitRetry,
}

// Park only deadlines, retaining the sealed observations for completion and
// durable recovery. A stale notification after release must not park new work.
fn park_claimed_deadlines(
    pending: &HashMap<String, Pending>,
    due: &mut BTreeMap<(Instant, String), ()>,
    claims: &HashMap<String, Arc<str>>,
    paths: HashSet<String>,
) {
    for path in paths {
        if claims.contains_key(&path) {
            if let Some(pending) = pending.get(&path) {
                due.remove(&(pending.due, path));
            }
        }
    }
}

// Claimed siblings cannot be admitted while the owner runs. Transfer their old
// queued observations into its completion. Events during ownership are only
// dirty names, re-observed after completion.
fn consume_claimed_pending(
    pending: &mut HashMap<String, Pending>,
    due: &mut BTreeMap<(Instant, String), ()>,
    unpublished: &mut HashSet<String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
    captured: &HashMap<String, Option<WatchCandidateRow>>,
    inputs: &mut Vec<WatchCandidateRow>,
    quiet: &mut HashMap<String, quiet::Activity>,
) {
    for path in groups.keys() {
        if captured.get(path).and_then(Option::as_ref).is_some_and(|before|
            pending.get(path).is_some_and(|queued| quiet::changed(before, &queued.candidate))) {
            continue;
        }
        if let Some(queued) = pending.remove(path) {
            due.remove(&(queued.due, path.clone()));
            unpublished.remove(path);
            quiet.insert(path.clone(), queued.quiet);
            inputs.push(queued.candidate);
        }
    }
}

// Keep the durable blocker and a generation already queued for regroup under
// the admitting root, retaining the promoted subtree's recovery scope.
fn handoff_promoted_blocker(
    entry: &mut Arc<crate::watch_store::EntryRecord>,
    root_id: &str,
    root: &Root,
    recovery: Recovery,
    pending: Option<&mut Pending>,
) {
    Arc::make_mut(entry).failure_payload.insert("source_input_root".into(), json!(root.path));
    if let Some(pending) = pending {
        pending.root = root_id.to_owned();
        pending.recovery = Some(Arc::new(recovery));
    }
}

#[derive(Debug)]
struct Recovery {
    scope: NativeDiscoveryScope,
    password_scope: PathBuf,
}

impl Recovery {
    fn from_record(scope: &serde_json::Map<String, Value>, password_scope: &str) -> Option<Self> {
        let root = scope.get("root")?.as_str()?.to_owned();
        let depth = scope
            .get("max_depth")
            .and_then(Value::as_u64)
            .map(|depth| depth as usize);
        let excluded = scope
            .get("excluded_subtrees")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        Some(Self {
            scope: NativeDiscoveryScope::new(root, depth, excluded),
            password_scope: PathBuf::from(password_scope),
        })
    }

    fn password_dir<'a>(&'a self, path: &'a Path) -> &'a Path {
        if self.password_scope.as_os_str().is_empty() {
            path.parent().unwrap_or(Path::new(""))
        } else {
            &self.password_scope
        }
    }
}

fn scope_record(scope: &NativeDiscoveryScope) -> serde_json::Map<String, Value> {
    let mut excluded = scope.excluded_subtrees();
    excluded.sort_unstable();
    serde_json::Map::from_iter([
        ("root".to_owned(), json!(scope.root)),
        ("max_depth".to_owned(), json!(scope.max_depth)),
        ("excluded_subtrees".to_owned(), json!(excluded)),
    ])
}

#[derive(Default)]
struct ClaimedSources {
    cancelled: bool,
    candidates: HashMap<String, Option<WatchCandidateRow>>,
    finished: HashSet<String>,
}

impl ClaimedSources {
    fn capture(&mut self, members: &[String]) -> io::Result<()> {
        if self.cancelled {
            return Err(crate::io::cancellation::cancelled_io());
        }
        for member in members {
            let id = watch_path_key(member);
            // Cancellation bookkeeping must not fail an unrelated archive.
            // Retain failed/missing observations too: sampling again on a later
            // claim could mistake a replacement for this request's generation.
            self.candidates.entry(id).or_insert_with(|| {
                watch_candidate_for_path(Path::new(member), None).ok().flatten()
            });
        }
        Ok(())
    }
}

// Final request retirement owns every captured physical claim, including
// ambiguous shared aliases intentionally absent from result projection.
fn completion_claims<'a>(
    task: Option<crate::pipeline::TaskId>,
    groups: &'a HashMap<String, Arc<SourceGroup>>,
    claimed: &'a ClaimedSources,
) -> impl Iterator<Item = &'a String> {
    groups.keys().chain(task.is_none().then_some(&claimed.candidates).into_iter().flat_map(HashMap::keys))
}

struct Active {
    deep: bool,
    root: String,
    recovery: Option<Arc<Recovery>>,
    password_scope: PathBuf,
    passwords: Arc<crate::core::passwords::PasswordSnapshot>,
    inputs: HashMap<String, WatchCandidateRow>,
    quiet: HashMap<String, quiet::Activity>,
    dirty: HashSet<String>,
    cancel: Cancellation,
    groups: Arc<Mutex<SourceGroups>>,
    claimed: Arc<Mutex<ClaimedSources>>,
    toast: Option<super::toast::Activity>,
    request: crate::pipeline::RequestHandle<Completed>,
}

struct BatchCompletion {
    hub: Arc<Hub>,
    batch: Option<String>,
}

impl Drop for BatchCompletion {
    fn drop(&mut self) {
        self.hub.batch_completed(self.batch.take().unwrap());
    }
}

struct RootReportCompletion {
    activity: super::toast::Activity,
    id: crate::pipeline::TaskId,
    failed: bool,
}

impl Drop for RootReportCompletion {
    fn drop(&mut self) { self.activity.report_finished(self.id, self.failed); }
}

struct RootCompleted {
    reply: Arc<super::cli::reporting::Reply<Outcome>>,
    batch: String,
    id: crate::pipeline::TaskId,
    path: PathBuf,
    groups: HashMap<String, Arc<SourceGroup>>,
    completed: Completed,
}

struct CompletionContext {
    deep: bool,
    root: String,
    recovery: Option<Arc<Recovery>>,
    password_scope: PathBuf,
    passwords: Arc<crate::core::passwords::PasswordSnapshot>,
    inputs: Vec<WatchCandidateRow>,
    quiet: HashMap<String, quiet::Activity>,
    dirty: HashSet<String>,
    claimed: Arc<Mutex<ClaimedSources>>,
    groups: HashMap<String, Arc<SourceGroup>>,
    toast: Option<super::toast::Activity>,
    task: Option<crate::pipeline::TaskId>,
}

struct Completed {
    cancelled: bool,
    result: io::Result<Outcome>,
    promoted: HashMap<String, Option<WatchCandidateRow>>,
    outputs: BTreeMap<String, String>,
}

#[derive(serde::Serialize)]
struct SourceGroup {
    path: PathBuf,
    name: String,
    members: Vec<String>,
    multipart: bool,
}

// Logical tasks own groups; physical members may have several live consumers.
#[derive(Default)]
struct SourceGroups {
    planned: HashSet<String>,
    roots: HashMap<String, Arc<SourceGroup>>,
    members: HashMap<String, usize>,
}

impl SourceGroups {
    fn insert(&mut self, group: Arc<SourceGroup>) {
        let root = key(&group.path);
        if let Some(previous) = self.roots.remove(&root) { self.release(&previous); }
        for member in &group.members { *self.members.entry(watch_path_key(member)).or_default() += 1; }
        self.roots.insert(root, group);
    }

    fn into_aliases(self) -> HashMap<String, Arc<SourceGroup>> {
        let mut aliases = self.roots;
        let groups = aliases.values().cloned().collect::<Vec<_>>();
        for group in groups {
            for member in &group.members {
                let id = watch_path_key(member);
                // A physical alias with multiple consumers has an aggregate
                // result, not an arbitrary head chosen by HashMap iteration.
                if self.members.get(&id) == Some(&1) {
                    aliases.entry(id).or_insert_with(|| Arc::clone(&group));
                }
            }
        }
        aliases
    }

    fn release(&mut self, group: &SourceGroup) {
        for member in &group.members {
            let id = watch_path_key(member);
            if let Some(count) = self.members.get_mut(&id) {
                *count -= 1;
                if *count == 0 { self.members.remove(&id); }
            }
        }
    }

    fn take(&mut self, root: &str) -> HashMap<String, Arc<SourceGroup>> {
        self.planned.remove(root);
        let Some(group) = self.roots.remove(root) else { return HashMap::new(); };
        self.release(&group);
        group.members.iter().map(|member| watch_path_key(member))
            // A discovered task retains its durable owner even before claim.
            // An admitted tail with no independent task belongs to its head.
            .filter(|member| member == root || (!self.planned.contains(member) && !self.members.contains_key(member)))
            .map(|member| (member, Arc::clone(&group))).collect()
    }
}

struct Scheduler {
    #[cfg(test)]
    admission_checkpoint: Option<Box<dyn FnOnce(&mut Self) -> io::Result<()> + Send>>,
    candidate_diagnostics: CandidateDiagnostics,
    cwd: PathBuf,
    root_file: PathBuf,
    roots: BTreeMap<String, (Root, NativeDiscoveryScope)>,
    available_roots: HashSet<String>,
    settings: Arc<Config>,
    user_password_signature: String,
    engine: Arc<Engine>,
    journal: Arc<journal::Journal>,
    catalog: Arc<NativeWatchCatalog>,
    options: Option<NativeDirectoryScanOptions>,
    deep_options: NativeDirectoryScanOptions,
    passwords: Arc<BuiltinStore>,
    hub: Arc<Hub>,
    root_observers: HashMap<String, RootObservers>,
    root_progress: RootPolicyProgress,
    parent_observers: HashMap<String, ParentObserver>,
    config_observers: Vec<ConfigSubscription>,
    pending: HashMap<String, Pending>,
    unpublished: HashSet<String>,
    due: BTreeMap<(Instant, String), ()>,
    active: HashMap<String, Active>,
    active_paths: HashMap<String, Arc<str>>,
    continuous: bool,
    tray_enabled: bool,
    tray: Option<super::tray::Tray>,
    monitor: Option<(crate::core::clipboard_monitor::Monitor, bool, usize)>,
    toast: Option<super::toast::Toast>,
    cache_deadline: Option<Instant>,
    external: Arc<Mutex<Option<ExternalOutputs>>>,
    _lease: BrokerLease,
}

impl Scheduler {
    fn open(
        cwd: PathBuf, engine: Arc<Engine>, hub: Arc<Hub>, continuous: bool,
        tray_enabled: bool, external: Arc<Mutex<Option<ExternalOutputs>>>, snapshot: Snapshot,
    ) -> io::Result<Self> {
        let executor = Arc::clone(&engine);
        executor.run_stage("watch_start", Origin::Watch, || {
            Self::open_blocking(cwd, engine, hub, continuous, tray_enabled, external, snapshot)
        })?
    }

    fn open_blocking(
        cwd: PathBuf,
        engine: Arc<Engine>,
        hub: Arc<Hub>,
        continuous: bool,
        tray_enabled: bool,
        external: Arc<Mutex<Option<ExternalOutputs>>>,
        snapshot: Snapshot,
    ) -> io::Result<Self> {
        let lease = BrokerLease::acquire()?;
        let root_file = roots_path(&cwd)?;
        let dir = state_dir(&cwd)?;
        let journal = Arc::new(journal::Journal::open(&dir, snapshot.config.watch.event_log_retention_days)?);
        let maintenance_hub = Arc::downgrade(&hub);
        journal.set_maintenance(Arc::new(move || {
            if let Some(hub) = maintenance_hub.upgrade() {
                hub.update(|signals| signals.maintenance = true);
            }
        }));
        let catalog = Arc::new(NativeWatchCatalog::new(
            journal.state(),
            Some(dir.to_string_lossy().into_owned()),
        ));
        // With no scheduler roots main never compiles scan rules. Reconcile
        // the root policy before activating its scan options below.
        let deep_options =
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())?;
        let passwords = BuiltinStore::shared(&cwd)?;
        // A one-shot scheduler never consumes configuration reload signals.
        let config_observers = if continuous {
            Self::observe_config(&cwd, &snapshot, &root_file, passwords.path(), &hub)?
        } else {
            Vec::new()
        };
        let mut scheduler = Self {
            #[cfg(test)]
            admission_checkpoint: None,
            cwd,
            root_file,
            roots: BTreeMap::new(),
            available_roots: HashSet::new(),
            user_password_signature: user_password_signature(&snapshot.config.user_passwords),
            settings: Arc::new(snapshot.config),
            engine,
            journal,
            catalog,
            options: None,
            deep_options,
            passwords,
            hub,
            root_observers: HashMap::new(),
            root_progress: RootPolicyProgress::default(),
            parent_observers: HashMap::new(),
            config_observers,
            pending: HashMap::new(),
            unpublished: HashSet::new(),
            due: BTreeMap::new(),
            active: HashMap::new(),
            active_paths: HashMap::new(),
            continuous,
            tray_enabled,
            tray: None,
            monitor: None,
            toast: None,
            cache_deadline: None,
            candidate_diagnostics: CandidateDiagnostics::default(),
            external,
            _lease: lease,
        };
        scheduler.reconcile_roots(false)?;
        scheduler.activate_scan_options()?;
        scheduler.retire_missing_entries(None, true)?;
        scheduler.retire_stale_promoted(None, true)?;
        scheduler.reconcile_shell();
        scheduler.recover_pending(None)?;
        if !scheduler.continuous && !scheduler.roots.is_empty()
            && scheduler.settings.watch.clipboard_monitor_enabled {
            scheduler.merge_clipboard(&crate::core::passwords::clipboard_passwords())?;
        }
        scheduler.password_update(true)?;
        scheduler.checkpoint(&HashMap::new(), true, true)?;
        scheduler.root_progress.checkpoint = false;
        scheduler.retry_missing_volumes_with_event(None, "startup_missing_volume_reconcile")?;
        scheduler.root_progress.recovery = false;
        scheduler
            .hub
            .pending_count
            .store(scheduler.pending.len(), Ordering::Relaxed);
        scheduler
            .journal
            .log(json!({"event":"watch_started","roots":scheduler.roots.len()}));
        scheduler.suspend_empty_scheduler()?;
        Ok(scheduler)
    }

    fn suspend_empty_scheduler(&mut self) -> io::Result<()> {
        if !self.roots.is_empty() || self.journal.suspended() { return Ok(()); }
        // Reconciliation has already drained requests and retired removed scopes.
        // Keep only the configuration/tray/log shell; durable recovery belongs to
        // the next scheduler, not to an idle service with no roots.
        self.root_observers.clear();
        self.parent_observers.clear();
        self.monitor.take();
        self.toast.take();
        *self.external.lock().unwrap() = None;
        self.catalog.commit(true);
        self.journal.suspend()?;
        self.catalog.close();
        self.catalog = Arc::new(NativeWatchCatalog::new(self.journal.state(), None));
        self.pending = HashMap::new();
        self.unpublished = HashSet::new();
        self.due.clear();
        self.active = HashMap::new();
        self.active_paths = HashMap::new();
        self.available_roots = HashSet::new();
        self.candidate_diagnostics = CandidateDiagnostics::default();
        self.hub.clear_idle_completed_families();
        self.cache_deadline = None;
        Ok(())
    }

    fn observe_config(
        cwd: &Path,
        snapshot: &Snapshot,
        roots: &Path,
        passwords: &Path,
        hub: &Arc<Hub>,
    ) -> io::Result<Vec<ConfigSubscription>> {
        let mut paths = config::watch_paths(cwd, &snapshot.sources);
        paths.push(roots.to_owned());
        let hub = Arc::clone(hub);
        observe_files(&paths, passwords, move |reload, passwords| {
            hub.update(|signals| {
                signals.reload |= reload;
                signals.password_changed |= passwords;
            });
        })
    }

    fn reconcile_tray(cwd: &Path, settings: &Config, enabled: bool, hub: &Arc<Hub>,
        journal: Weak<journal::Journal>, tray: &mut Option<super::tray::Tray>) {
        let show_tray = enabled && settings.watch.tray_enabled;
        if show_tray && tray.is_none() {
            let hub = Arc::clone(hub);
            let diagnostic = journal.clone();
            match super::tray::Tray::start(cwd, settings.cli.language, move |action| {
                match action {
                    super::tray::Action::Reload => hub.queue_reload(None),
                    super::tray::Action::Stop => hub.stop(),
                }
            }, move |message, error| {
                if let Some(journal) = diagnostic.upgrade() {
                    journal.log(json!({"event":"tray_callback_error", "error":error.to_string(),
                        "error_type":format!("{:?}", error.kind()), "message":message}));
                }
            }) {
                Ok(value) => *tray = Some(value),
                Err(error) => if let Some(journal) = journal.upgrade() {
                    journal.log(json!({"event":"tray_start_failed", "error":error.to_string()}));
                },
            }
        } else if !show_tray {
            tray.take();
        } else if let Some(tray) = tray {
            tray.set_language(settings.cli.language);
        }
    }

    fn reconcile_shell(&mut self) {
        if !self.continuous {
            return;
        }
        Self::reconcile_tray(&self.cwd, &self.settings, self.tray_enabled,
            &self.hub, Arc::downgrade(&self.journal), &mut self.tray);
        if self.options.is_some() && !self.roots.is_empty() && self.settings.watch.toast_enabled {
            if self.toast.is_none() {
                let diagnostic = state_dir(&self.cwd).map(|dir| dir.join("toast-diagnostic.log"));
                let journal = Arc::downgrade(&self.journal);
                match diagnostic.and_then(|path| {
                    super::toast::Toast::start(
                        &self.cwd,
                        Arc::clone(&self.engine),
                        path,
                        self.settings.watch.toast_report_retention_days,
                        move |event, error| {
                            if let Some(journal) = journal.upgrade() {
                                journal.log(json!({"event":event, "error":error.to_string()}));
                            }
                        },
                    )
                }) {
                    Ok(toast) => self.toast = Some(toast),
                    Err(error) => self
                        .journal
                        .log(json!({"event":"toast_start_failed","error":error.to_string()})),
                }
            } else if let Some(toast) = &self.toast {
                toast.set_report_retention(self.settings.watch.toast_report_retention_days);
            }
        } else {
            self.toast.take();
        }
        if self.roots.is_empty() || self.options.is_none() {
            self.monitor.take();
            return;
        }
        let clipboard = self.settings.watch.clipboard_monitor_enabled;
        let clipboard_limit = self.settings.watch.clipboard_builtin_max_entries;
        if self.monitor.is_none()
            || self.monitor.as_ref().is_some_and(|(_, enabled, limit)| {
                *enabled != clipboard || *limit != clipboard_limit
            })
        {
            let hub = Arc::clone(&self.hub);
            let passwords = Arc::clone(&self.passwords);
            let journal = Arc::clone(&self.journal);
            self.monitor.take();
            let monitor =
                crate::core::clipboard_monitor::Monitor::start(clipboard, true, move |change| {
                    match change {
                        crate::core::clipboard_monitor::Notification::Clipboard(values) => {
                            // The window thread owns clipboard persistence, as in main.
                            // Only publish an invalidation to the scheduler after saving.
                            match passwords.merge_clipboard(&values, clipboard_limit) {
                                Ok(true) => hub.update(|signals| signals.password_changed = true),
                                Ok(false) => {},
                                Err(error) => journal.log(json!({
                                    "event":"watch_clipboard_password_save_failed", "error":error.to_string(),
                                })),
                            }
                        }
                        crate::core::clipboard_monitor::Notification::VolumeChanged { unitmask, arrived } => {
                            hub.update(|signals| signals.volumes.add(unitmask, arrived));
                        }
                    }
                });
            match monitor {
                Ok(monitor) => self.monitor = Some((monitor, clipboard, clipboard_limit)),
                Err(error) => self
                    .journal
                    .log(json!({"event":"shell_monitor_failed","error":error.to_string()})),
            }
        }
    }

    fn reconcile_roots(&mut self, restart_scheduler: bool) -> io::Result<(bool, bool)> {
        let engine = Arc::clone(&self.engine);
        let (entries, next, policy_changed) = engine.run_stage("watch_directory", Origin::Watch, || -> io::Result<_> {
        let (entries, rejected) = {
            // Read, classify, and prune the same root policy. GUI and CLI
            // writers share this lock; pruning an older snapshot can remove a
            // root that has since moved back onto a supported filesystem.
            let _guard = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
            let mut entries = read_roots(&self.root_file)?;
            let mut filesystems = HashMap::new();
            let mut rejected = Vec::new();
            entries.retain(|entry| {
                let Some(directory) = nearest_directory(&entry.path) else {
                    return true;
                };
                let filesystem = filesystems.entry(directory.to_owned()).or_insert_with(|| {
                    filesystem::watch_filesystem_type(&directory.to_string_lossy()).ok()
                });
                if let Some(filesystem) = filesystem.as_ref().filter(|name| !name.eq_ignore_ascii_case("NTFS")) {
                    rejected.push((entry.path.clone(), filesystem.clone()));
                    false
                } else {
                    true
                }
            });
            if !rejected.is_empty() {
                write_roots(&self.root_file, &entries)?;
            }
            (entries, rejected)
        };
        if !rejected.is_empty() {
            let paths = rejected.iter().map(|(path, filesystem)| {
                format!("{} ({filesystem})", path.display())
            }).collect::<Vec<_>>().join("\n");
            let message = self.settings.cli.language.translate("watch.non_ntfs_removed", &[("paths", &paths)]);
            self.journal.log(json!({
                "event":"watch_non_ntfs_roots_removed",
                "roots":rejected.iter().map(|(path, _)| path).collect::<Vec<_>>(),
                "message":message,
            }));
            let title = self.settings.cli.language.text("watch.error_title").to_owned();
            if let Err(error) = spawn_error_dialog(&self.journal, move || {
                windows::show_error(&title, &message)
            }) {
                self.journal.log(json!({"event":"watch_error_dialog_failed","error":error.to_string()}));
            }
        }
        validate_outputs(&entries)?;
        let new_directories: HashSet<_> = entries
            .iter()
            .filter(|root| !self.roots.contains_key(&key(&root.path)))
            .filter_map(|root| nearest_directory(&root.path))
            .collect();
        for directory in new_directories {
            filesystem::validate_ntfs_watch_root(&directory.to_string_lossy())?;
        }
        let dir = state_dir(&self.cwd)?;
        let state = dir.to_string_lossy().into_owned();
        let resolved_state = crate::path_keys::resolved_path_key(&dir);
        let is_alias = crate::path_keys::path_key(&state) != resolved_state;
        let mut metadata = vec![state];
        if is_alias { metadata.push(resolved_state); }
        let next = entries
            .iter()
            .map(|root| (key(&root.path), (root.clone(), root.scope(&entries, &metadata))))
            .collect::<BTreeMap<_, _>>();
        let policy_changed = self.roots.len() != next.len()
            || next.iter().any(|(id, (root, _))| {
                self.roots.get(id).is_none_or(|(old, _)| {
                    !old.same_policy(root)
                })
            });
            Ok((entries, next, policy_changed))
        })??;
        if self.journal.resume()? {
            self.catalog = Arc::new(NativeWatchCatalog::new(self.journal.state(),
                Some(state_dir(&self.cwd)?.to_string_lossy().into_owned())));
        }
        // Validate the latest root file before stopping the running scheduler.
        // Draining async requests must never hold a blocking-stage permit.
        if restart_scheduler || policy_changed {
            self.drain_active(&mut Ok(0))?;
            // Main builds its new scheduler from the durable work. In-memory
            // candidates produced by the stop checkpoint must not mask pending
            // output cleanup or promoted recovery under the new policy.
            self.persist_candidates(BTreeMap::new(), true)?;
            self.pending.clear();
            self.due.clear();
            if let Some(toast) = &self.toast {
                toast.reset_batches();
            }
        }
        engine.run_stage("watch_directory", Origin::Watch, || {
        let refresh_catalog = self.root_progress.observe(policy_changed, self.roots.is_empty());
        self.available_roots.retain(|id| next.contains_key(id));
        self.roots = next;
        if !refresh_catalog && !restart_scheduler {
            // A no-op reload still updates initial-scan markers above. The
            // existing observers and output ownership need no reconciliation.
            return Ok((self.root_progress.checkpoint, self.root_progress.recovery));
        }
        // Root policy is already durable. Publish it independently of WAL
        // retirement, and always restore subscriptions even if retirement fails.
        let retirement: io::Result<()> = (|| {
            if refresh_catalog {
                self.catalog.retain_roots(entries.iter()
                    .map(|entry| entry.path.to_string_lossy().into_owned()).collect());
                self.root_observers.clear();
                let scopes = self.roots.values().map(|(_, scope)| scope.clone()).collect::<Vec<_>>();
                *self.external.lock().unwrap() = Some(ExternalOutputs {
                    journal: Arc::downgrade(&self.journal),
                    scopes: scopes.clone().into(),
                });
                self.journal.commit(true, |state| Ok(state.scope_retirement_operations(&scopes)))?;
            }
            self.retire_owned_outputs(None)
        })();
        self.rearm_root_observers_blocking(None);
        retirement?;
        self.root_progress.retirement = false;
        Ok((self.root_progress.checkpoint, self.root_progress.recovery))
        })?
    }

    fn rearm_root_observers(&mut self, changed: Option<&HashSet<String>>) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_rearm", Origin::Watch, || self.rearm_root_observers_blocking(changed))
    }

    fn rearm_root_observers_blocking(&mut self, changed: Option<&HashSet<String>>) {
        // Ordinary content notifications never invalidate these subscriptions.
        // Resolve only topology-invalidated roots; preserve other memberships.
        let desired = parent_memberships(self.roots.iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains(*id)))
            .map(|(_, (root, _))| root));
        for parent in self.parent_observers.values() {
            parent.members.lock().unwrap().retain(|id, _|
                self.roots.contains_key(id) && changed.is_some_and(|changed| !changed.contains(id)));
        }
        for (id, (directory, mut members)) in desired {
            if let Some(parent) = self.parent_observers.get(&id) {
                members.extend(parent.members.lock().unwrap().clone());
            }
            if self.parent_observers.get(&id).is_some_and(|parent| !parent.observer.matches(&directory)) {
                self.parent_observers.remove(&id);
            }
            if let Some(parent) = self.parent_observers.get(&id) {
                *parent.members.lock().unwrap() = members;
            } else {
                match ParentObserver::start(&directory, members, &self.hub) {
                    Ok(parent) => { self.parent_observers.insert(id, parent); }
                    Err(error) => self.journal.log(json!({"event":"watch_parent_unavailable", "path":directory,"error":error.to_string()})),
                }
            }
        }
        self.parent_observers.retain(|_, parent| !parent.members.lock().unwrap().is_empty());
        self.root_observers.retain(|id, _| self.roots.contains_key(id));
        for (id, (root, scope)) in self.roots.iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains(*id)))
        {
            let (replaced, errors) = self.root_observers.entry(id.clone()).or_default()
                .rearm(root, scope, self.passwords.path(), &self.hub, &self.journal, &self.catalog);
            if replaced {
                self.available_roots.remove(id);
            }
            for error in errors {
                self.journal.log(json!({"event":"watch_root_unavailable","root":root.path,"error":error.to_string()}));
            }
        }
    }

    fn reload(&mut self) -> io::Result<bool> {
        let result = self.reload_loaded();
        // Invalid config/root policy or rollback failures may follow a resume.
        // The rootless shell releases that temporary state on every exit path.
        let suspended = self.suspend_empty_scheduler();
        result.and_then(|changed| suspended.map(|()| {
            super::diagnostics::event(if changed { "watch_reloaded" } else { "watch_reload_skipped" }, json!({}));
            changed
        }))
    }

    fn reload_loaded(&mut self) -> io::Result<bool> {
        let snapshot = self.engine.run_stage("watch_config_reload", Origin::Watch, || config::reload_snapshot(&self.cwd))??;
        let config_changed = *self.settings != snapshot.config;
        let scheduler_changed = scheduler_configuration_changed(&self.settings, &snapshot.config);
        let tray_changed = self.settings.watch.tray_enabled != snapshot.config.watch.tray_enabled
            || self.settings.cli.language != snapshot.config.cli.language;
        let process_mode_changed = self.settings.runtime.process_mode != snapshot.config.runtime.process_mode;
        let mut observed_paths = config::watch_paths(&self.cwd, &snapshot.sources);
        observed_paths.push(self.root_file.clone());
        let observers_changed = self.continuous
            && !observes_files(&observed_paths, self.passwords.path(), &self.config_observers);
        // Keep the previous subscriptions alive until apply succeeds. A failed
        // apply must not publish sources or lose the old recovery notifications.
        let observers = observers_changed.then(|| self.engine.run_stage("watch_rearm", Origin::Watch, || Self::observe_config(
            &self.cwd, &snapshot, &self.root_file, self.passwords.path(), &self.hub,
        )).and_then(|result| result)).transpose()?;
        let (roots_changed, root_policy_changed) = match self.reconcile_roots(scheduler_changed) {
            Ok(changed) => changed,
            Err(error) => {
                // Reconciliation can fail after publishing durable root edits.
                // Its subscriptions are repaired before it returns; reconcile
                // root-bound shell resources against that same policy as well.
                self.reconcile_shell();
                return Err(error);
            }
        };
        let scheduler_changed = scheduler_changed || root_policy_changed;
        let previous = config_changed.then(|| {
            self.user_password_signature = user_password_signature(&snapshot.config.user_passwords);
            std::mem::replace(&mut self.settings, Arc::new(snapshot.config))
        });

        let apply = (|| {
            if config_changed || roots_changed {
                self.activate_scan_options()?;
            }
            if config_changed {
                self.journal.set_retention(self.settings.watch.event_log_retention_days)?;
            }
            if scheduler_changed { self.recover_pending(None)?; }
            self.checkpoint_reload(scheduler_changed || roots_changed)?;
            if scheduler_changed {
                // main restarts its scheduler on semantic policy changes,
                // including reconciliation of existing missing-volume blockers.
                self.retry_missing_volumes(None)?;
                self.root_progress.recovery = false;
            }
            if config_changed { self.password_update(false)?; }
            Ok(())
        })();
        if let Err(error) = apply {
            if let Some(settings) = previous {
                self.user_password_signature = user_password_signature(&settings.user_passwords);
                self.settings = settings;
            }
            // Root edits are durable and are never rolled back. Recover
            // ordinary settings against the latest root file, like main.
            let rollback: io::Result<()> = (|| {
                self.journal.set_retention(self.settings.watch.event_log_retention_days)?;
                let (latest_roots_changed, latest_policy_changed) = self.reconcile_roots(false)?;
                self.activate_scan_options()?;
                let restart = scheduler_changed || latest_policy_changed;
                if restart {
                    self.recover_pending(None)?;
                }
                self.checkpoint_reload(restart || roots_changed || latest_roots_changed)?;
                if restart {
                    self.retry_missing_volumes(None)?;
                    self.root_progress.recovery = false;
                }
                Ok(())
            })();
            if let Err(rollback_error) = rollback {
                self.journal.log(json!({"event":"config_reload_rollback_failed", "error":rollback_error.to_string()}));
                // Keep the service listening for a corrected configuration;
                // no scheduler may admit work until its options activate.
            }
            // Shell state/priority were never published, but durable root
            // changes can still require stopping their root-bound resources.
            self.reconcile_shell();
            return Err(error);
        }
        if let Some(observers) = observers { self.config_observers = observers; }
        super::diagnostics::retention(self.settings.watch.event_log_retention_days);
        windows::configure_priority(&self.engine, self.settings.runtime.process_mode);
        self.reconcile_shell();
        let changed = config_changed || roots_changed;
        if changed {
            self.journal.log(json!({"event":"service_reloaded", "state_dir":self.root_file.with_file_name(WATCH_METADATA),
                "roots":self.roots.values().map(|(root, _)| &root.path).collect::<Vec<_>>(),
                "scheduler_restarted":scheduler_changed, "tray_reconciled":tray_changed,
                "runtime_process_mode_changed":process_mode_changed}));
        } else {
            self.journal.log(json!({"event":"service_reload_skipped","reason":"no_semantic_change"}));
        }
        Ok(changed)
    }

    fn checkpoint_reload(&mut self, scheduler_changed: bool) -> io::Result<()> {
        if scheduler_changed || self.root_progress.checkpoint {
            let result = self.checkpoint(&HashMap::new(), true, false);
            self.root_progress.checkpoint_finished(&result);
            result
        } else {
            // Tray/process-priority changes and semantic no-ops only scan
            // pending roots; neither restarts main's scheduler.
            let pending: HashMap<String, HashSet<PathBuf>> = self.roots.iter().filter(|(_, (root, _))| !root.scanned)
                .map(|(id, _)| (id.clone(), HashSet::new())).collect();
            if pending.is_empty() { Ok(()) } else { self.checkpoint(&pending, false, false) }
        }
    }

    // Both shutdown and semantic reload finish submitted work and its root
    // completion/report chain under the old policy. No admission occurs here.
    fn drain_active(&mut self, result: &mut io::Result<i32>) -> io::Result<()> {
        // Match main's stop boundary: checkpoint while directory observers are
        // armed, then join producers before draining submitted requests.
        if !self.root_observers.is_empty() || !self.parent_observers.is_empty() || self.monitor.is_some() {
            if result.is_ok() {
                if let Err(error) = self.checkpoint(&HashMap::new(), true, false) { *result = Err(error); }
            }
            self.root_observers.clear();
            self.parent_observers.clear();
            self.monitor.take();
        }
        let mut cancellation_observed = false;
        let mut failure_observed = false;
        while !self.active.is_empty() {
            if !cancellation_observed && self.hub.cancelled.load(Ordering::Acquire) {
                for batch in self.active.keys().cloned().collect::<Vec<_>>() {
                    self.cancel_batch(&batch);
                }
                cancellation_observed = true;
            }
            if result.is_err() && !failure_observed {
                // An internal failure is not user cancellation. Leave pending
                // WAL intent for restart rather than suppressing its generation.
                for active in self.active.values() {
                    active.cancel.cancel();
                }
                failure_observed = true;
            }
            let signals = self.hub.wait_drain(cancellation_observed);
            for (batch, waiter) in signals.cancel {
                let _ = waiter.send(self.cancel_display_batch(&batch));
            }
            let failed_before_harvest = result.is_err();
            if let Err(error) = self.complete_roots(signals.roots) { *result = Err(error); }
            if failed_before_harvest {
                // Closing an already failed scheduler only releases requests;
                // its untrusted projection must not create new state changes.
                for batch in signals.completed { self.abandon_completed(&batch); }
            } else if let Err(error) = self.complete_requests(signals.completed) { *result = Err(error); }
        }
        // A failed completion may leave durable recovery intent. Do not resume
        // admission with the partially retired in-memory request indexes.
        if result.is_err() { self.options = None; }
        result.as_ref().map(|_| ()).map_err(|error|
            io::Error::new(error.kind(), error.to_string()))
    }

    // The persistent service owns configuration observation and the tray;
    // a failed data scheduler must not take those repair controls down with it.
    fn run_service(mut self, once: bool, last_error: &Mutex<Option<String>>) -> io::Result<i32> {
        loop {
            let result = self.run(once);
            if once || result.is_ok() || self.hub.stopped.load(Ordering::Acquire) { return result; }
            let error = result.unwrap_err();
            *last_error.lock().unwrap() = Some(error.to_string());
            self.journal.log(json!({"event":"scheduler_error","error":error.to_string()}));
            let cwd = self.cwd.clone();
            let engine = Arc::clone(&self.engine);
            let hub = Arc::clone(&self.hub);
            let external = Arc::clone(&self.external);
            let mut settings = Arc::clone(&self.settings);
            let password_path = self.passwords.path().to_owned();
            let journal = Arc::downgrade(&self.journal);
            let roots: Vec<_> = self.roots.values().map(|(root, _)| root.clone()).collect();
            let tray_enabled = self.tray_enabled;
            let mut observers = std::mem::take(&mut self.config_observers);
            let mut tray = self.tray.take();
            // Drop the faulted stream and its lock before reopening; never
            // clear a WAL error in place or write the failed memory projection.
            drop(self);
            hub.pending_count.store(0, Ordering::Relaxed);
            let mut repaired = None;
            while !hub.stopped.load(Ordering::Acquire) {
                let signals = hub.wait(None);
                for ( _, waiter) in signals.cancel { let _ = waiter.send(Ok(false)); }
                for waiter in signals.once { let _ = waiter.send(Err(io::Error::other(error.to_string()))); }
                for waiter in signals.rebuild { let _ = waiter.send(Err(io::Error::other(error.to_string()))); }
                for root in signals.roots { root.reply.complete(Err(io::Error::other(error.to_string()))); }
                if !signals.reload { continue; }
                let reload = (|| {
                    let snapshot = config::reload_snapshot(&cwd)?;
                    let next_roots = read_roots(&roots_path(&cwd)?)?;
                    let changed = scheduler_configuration_changed(&settings, &snapshot.config)
                        || roots.len() != next_roots.len()
                        || roots.iter().any(|root| !next_roots.iter().any(|next| key(&root.path) == key(&next.path) && root.same_policy(next)));
                    let shell_changed = *settings != snapshot.config;
                    if !changed && (signals.reload_waiters.is_empty() || shell_changed) {
                        // A failed scheduler does not disable service-only policy
                        // changes. Keep the existing tray/configuration shell alive.
                        let next_observers = Self::observe_config(&cwd, &snapshot,
                            &roots_path(&cwd)?, &password_path, &hub)?;
                        settings = Arc::new(snapshot.config);
                        super::diagnostics::retention(settings.watch.event_log_retention_days);
                        windows::configure_priority(&engine, settings.runtime.process_mode);
                        Self::reconcile_tray(&cwd, &settings, tray_enabled, &hub,
                            journal.clone(), &mut tray);
                        observers = next_observers;
                        return Ok(shell_changed);
                    }
                    repaired = Some(Self::open(cwd.clone(), Arc::clone(&engine), Arc::clone(&hub),
                        true, false, Arc::clone(&external), snapshot)?);
                    Ok(true)
                })();
                for waiter in signals.reload_waiters {
                    let _ = waiter.send(reload.as_ref().copied()
                        .map_err(|error: &io::Error| io::Error::new(error.kind(), error.to_string())));
                }
                match reload {
                    Ok(changed) => super::diagnostics::event(if changed { "watch_reloaded" } else { "watch_reload_skipped" }, json!({})),
                    Err(error) => { *last_error.lock().unwrap() = Some(error.to_string()); }
                }
                if repaired.is_some() { break; }
            }
            drop(observers);
            drop(tray);
            let Some(mut scheduler) = repaired else { return Ok(0); };
            scheduler.tray_enabled = tray_enabled;
            scheduler.reconcile_shell();
            *last_error.lock().unwrap() = None;
            self = scheduler;
        }
    }

    fn run(&mut self, once: bool) -> io::Result<i32> {
        let mut result = self.run_inner(once);
        if once || result.is_ok() { self.hub.stop(); }
        let _ = self.drain_active(&mut result);
        let signals = if self.hub.stopped.load(Ordering::Acquire) {
            self.hub.wait(None)
        } else { Signals::default() };
        drop(signals.cancel);
        for waiter in signals.reload_waiters {
            let _ = waiter.send(Err(io::ErrorKind::Interrupted.into()));
        }
        for waiter in signals.once {
            let _ = waiter.send(Err(io::ErrorKind::Interrupted.into()));
        }
        for waiter in signals.rebuild {
            let _ = waiter.send(Err(io::ErrorKind::Interrupted.into()));
        }
        *self.external.lock().unwrap() = None;
        *self.hub.claims.lock().unwrap() = HashMap::new();
        self.engine.run_stage("watch_close", Origin::Watch, || {
            self.catalog.commit(true);
            self.catalog.close();
            self.journal.log(json!({"event":"watch_stopped"}));
            self.journal.flush()
        })??;
        if self.hub.cancelled.load(Ordering::Acquire) {
            return Err(crate::io::cancellation::cancelled_io());
        }
        result.map(|_| 0)
    }

    fn run_inner(&mut self, once: bool) -> io::Result<i32> {
        while !self.hub.stopped.load(Ordering::Acquire) {
            self.dispatch_ready()?;
            self.hub
                .pending_count
                .store(self.pending.len(), Ordering::Relaxed);
            // main's --once performs one admission round, then drains only
            // requests submitted in that round. Unready pending is durable,
            // and is intentionally not a reason to keep this command alive.
            if once {
                break;
            }
            if self.active.is_empty() && self.pending.is_empty() {
                self.engine.run_stage("catalog_commit", Origin::Watch, || {
                    // A gap between bursts is not the idle-cache deadline.
                    self.catalog.commit(false);
                    self.journal.compact()
                })??;
            }
            let due = self.next_admission();
            let deadline = match (due, self.cache_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let deadline = deadline.into_iter().chain(self.candidate_diagnostics.deadline()).min();
            let mut signals = self.hub.wait(deadline);
            self.candidate_diagnostics.clear_expired(Instant::now());
            for (batch, waiter) in signals.cancel {
                let _ = waiter.send(self.cancel_display_batch(&batch));
            }
            // Claims arrive from pipeline workers. Remove each queued deadline
            // once; keep its observation for generation-safe completion.
            {
                let claims = self.hub.claims.lock().unwrap();
                park_claimed_deadlines(&self.pending, &mut self.due, &claims, signals.claimed);
            }
            let mut completion_error = None;
            if let Err(error) = self.complete_roots(signals.roots) { completion_error = Some(error); }
            if let Err(error) = self.complete_requests(signals.completed) {
                completion_error = Some(error);
            }
            // Every notification in this taken batch must be harvested, even
            // when an earlier completion failed. Drain cannot wait for a wake
            // that was already removed from the Hub.
            if let Some(error) = completion_error {
                return Err(error);
            }
            for waiter in signals.rebuild {
                let result = self.engine.run_stage("catalog_maintenance", Origin::Watch, || self.journal.rebuild_log()).and_then(|result| result);
                let _ = waiter.send(result);
            }
            if signals.password_changed || !signals.reload_waiters.is_empty() {
                self.password_update(false)?;
            }
            if signals.foreground_finished && !self.roots.is_empty() {
                self.arm_idle_cleanup();
            } else if signals.password_changed && self.cache_deadline.is_none() {
                let path = self.passwords.path().to_string_lossy();
                if self.roots.values().any(|(_, scope)| scope.contains(&path)) {
                    self.arm_idle_cleanup();
                }
            }
            if signals.reload {
                let reload = self.reload();
                if let Err(error) = &reload {
                    self.journal
                        .log(json!({"event":"watch_reload_failed","error":error.to_string()}));
                    if self.config_observers.iter().any(|observer| !observer.alive()) {
                        // Do not advertise a healthy Watch after a failed event
                        // subscription. Startup/restart can report the real error.
                        return Err(io::Error::other(format!("Configuration observer recovery failed: {error}")));
                    }
                }
                for waiter in signals.reload_waiters {
                    let _ = waiter.send(
                        reload.as_ref().copied().map_err(|error| io::Error::new(error.kind(), error.to_string())),
                    );
                }
            }
            if !signals.volumes.is_empty() {
                for (id, (root, _)) in &self.roots {
                    let observed = self.root_observers.get(id).is_some_and(|observers| observers.root.is_some());
                    if signals.volumes.affects(&root.path, observed) {
                        signals.topology_roots.insert(id.clone());
                        signals.changed_roots.entry(id.clone()).or_default();
                        if signals.volumes.arrives(&root.path, observed) {
                            self.available_roots.remove(id);
                        }
                    }
                }
            }
            if !signals.changed_roots.is_empty() || !signals.once.is_empty() {
                // With a live service, --once asks for one ordinary scheduler
                // turn. Only a native topology event or an admission needs a
                // checkpoint; the control request is not a rescan.
                if self.options.is_some() && !signals.topology_roots.is_empty() {
                    self.rearm_root_observers(Some(&signals.topology_roots))?;
                }
                let result = (if signals.changed_roots.is_empty() { Ok(()) } else {
                    self.observe_root_changes(&mut signals.changed_roots, &signals.topology_roots,
                        &signals.modified_paths, &signals.candidate_events)
                }).and_then(|_| {
                        if signals.once.is_empty() {
                            Ok(())
                        } else {
                            self.dispatch_ready()
                        }
                    });
                self.hub
                    .pending_count
                    .store(self.pending.len(), Ordering::Relaxed);
                for waiter in signals.once {
                    let _ = waiter.send(
                        result
                            .as_ref()
                            .map(|_| ())
                            .map_err(|error| io::Error::other(error.to_string())),
                    );
                }
                result?;
            }
            if self
                .cache_deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                self.cache_deadline = None;
                if self.active.is_empty() && self.pending.is_empty() {
                    let engine = Arc::clone(&self.engine);
                    let mut maintenance = Ok(());
                    windows::maintain_when_foreground_idle(&engine, || {
                        maintenance = engine.run_stage("catalog_maintenance", Origin::Watch, || {
                        self.checkpoint(&HashMap::new(), true, false)?;
                        self.catalog.commit(true);
                        let _ = crate::io::reader::clear_reader_resources();
                        self.engine.clear_idle_passwords();
                        self.hub.clear_idle_completed_families();
                        self.journal.state().trim_idle_storage();
                        self.pending.shrink_to_fit();
                        self.unpublished.shrink_to_fit();
                        self.active.shrink_to_fit();
                        self.active_paths.shrink_to_fit();
                        Ok(())
                    }).and_then(|result| result);
                    });
                    maintenance?;
                }
            }
        }
        Ok(0)
    }
}

impl Scheduler {
    fn activate_scan_options(&mut self) -> io::Result<()> {
        self.options = None;
        match watch_scan_options(&self.settings, !self.roots.is_empty()) {
            Ok(options) => { self.options = options; Ok(()) }
            Err(error) => {
                self.root_observers.clear();
                self.parent_observers.clear();
                self.monitor.take();
                Err(error)
            }
        }
    }

    fn scan_options(&self, deep: bool) -> io::Result<&NativeDirectoryScanOptions> {
        let options = self.options.as_ref()
            .ok_or_else(|| io::Error::other("Watch scheduler is not active"))?;
        Ok(if deep { &self.deep_options } else { options })
    }

    fn retire_owned_outputs(&self, paths: Option<&[String]>) -> io::Result<()> {
        let scopes = self.roots.values().map(|(_, scope)| scope.clone()).collect::<Vec<_>>();
        let retirement = self.journal.state().prepare_owned_retirement(&scopes, paths);
        self.journal.commit(true, |state| Ok(retirement.operations(state)))
    }

    fn observe_file_changes_blocking(&mut self, changed: &HashMap<String, HashSet<PathBuf>>, events: &HashMap<PathBuf, CandidateEvent>) -> io::Result<()> {
        if self.options.is_none() { return Ok(()); }
        // Match main's ordinary file-event path: enqueue in memory without
        // refreshing the durable inventory or advancing its USN stamp. The
        // captured burst is reconciled once at admission/recovery instead.
        let mut retried = HashSet::new();
        for (id, paths) in changed {
            let Some((_, scope)) = self.roots.get(id) else { continue };
            let scope = scope.clone();
            for path in paths {
                let event = events.get(path);
                let path = path.to_string_lossy();
                if !scope.contains(&path) || self.catalog.is_owned(&path) { continue; }
                self.observe_candidate_with_event(id, path.to_string(), CandidateAdmission::Observe, None, None, None, event)?;
                self.retry_volume_peers(&scope, &path, &mut retried)?;
            }
        }
        if self.cache_deadline.is_none() { self.arm_idle_cleanup(); }
        Ok(())
    }

    fn observe_root_changes(&mut self, changed: &mut HashMap<String, HashSet<PathBuf>>,
        topology: &HashSet<String>, modified: &HashSet<PathBuf>,
        events: &HashMap<PathBuf, CandidateEvent>) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_directory", Origin::Watch, || {
            if Signals::prepare_root_changes(changed, topology, modified) {
                self.checkpoint_blocking(changed, false, false, events)
            } else {
                self.observe_file_changes_blocking(changed, events)
            }
        })?
    }

    fn checkpoint(&mut self, changed: &HashMap<String, HashSet<PathBuf>>, all_roots: bool, startup: bool) -> io::Result<()> {
        self.checkpoint_with_events(changed, all_roots, startup, &HashMap::new())
    }

    fn checkpoint_with_events(&mut self, changed: &HashMap<String, HashSet<PathBuf>>,
        all_roots: bool, startup: bool, events: &HashMap<PathBuf, CandidateEvent>) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_usn_checkpoint", Origin::Watch, || self.checkpoint_blocking(changed, all_roots, startup, events))?
    }

    fn checkpoint_blocking(
        &mut self,
        changed: &HashMap<String, HashSet<PathBuf>>,
        all_roots: bool,
        startup: bool,
        events: &HashMap<PathBuf, CandidateEvent>,
    ) -> io::Result<()> {
        if self.options.is_none() { return Ok(()); }
        let selected = self
            .roots
            .iter()
            .filter(|(id, _)| all_roots || changed.contains_key(*id))
            .map(|(id, (root, scope))| (id.clone(), root.clone(), scope.clone()))
            .collect::<Vec<_>>();
        let mut groups: HashMap<(String, u64), (i64, i64, Vec<NativeDiscoveryScope>)> =
            HashMap::new();
        let mut probes = Vec::new();
        let mut reopened = HashSet::new();
        for (id, root, scope) in selected {
            if !root.path.is_dir() {
                self.available_roots.remove(&id);
                continue;
            }
            if self.available_roots.insert(id.clone()) && !startup {
                reopened.insert(id.clone());
            }
            // Use the same directory generation to validate and publish this
            // cursor. A rename may replace its path while recovery is running.
            let identity = output_identity(&scope.root).ok();
            let current = filesystem::watch_volume_cursor(&scope.root);
            let arrived = !startup && (reopened.contains(&id) || identity.as_deref()
                .is_some_and(|identity| self.catalog.root_replaced(&scope, identity)));
            let cached = identity.as_deref().and_then(|identity| self.catalog.cursor(&scope, identity));
            if let (Ok((volume, journal, end)), Some((old_volume, old_journal, old_end))) =
                (&current, &cached)
            {
                if volume == old_volume && journal == old_journal && (1..=*end).contains(old_end) {
                    let start = self.journal.state().watch_cursor(volume)
                        .filter(|cursor| {
                            cursor.journal_id == i128::from(*journal)
                                && (1..=i128::from(*end)).contains(&cursor.next_usn)
                        })
                        .map_or(*old_end, |cursor| (*old_end).min(cursor.next_usn as i64));
                    let entry = groups.entry((volume.clone(), *journal)).or_insert((
                        start,
                        *end,
                        Vec::new(),
                    ));
                    entry.0 = entry.0.min(start);
                    entry.1 = entry.1.max(*end);
                    entry.2.push(scope.clone());
                }
            }
            probes.push((id, root, scope, identity, current, cached, arrived));
        }
        if !reopened.is_empty() {
            // Old snapshots can have only an outside literal name while its
            // physical watched volume is offline. Resolve those legacy names
            // once when a root returns, before catalog recovery or admission.
            self.retire_owned_outputs(None)?;
            // A returning root can have durable work with the same inventory
            // and no USN delta. Resume only the affected ownership scopes.
            self.recover_pending(Some(&reopened))?;
            self.retry_missing_volumes(Some(&reopened))?;
            let passwords = self.passwords.snapshot();
            self.retry_password_failures(&passwords, Some(&reopened))?;
        }
        let mut ranges = HashMap::new();
        for ((volume, journal), (start, end, scopes)) in groups {
            let changed = self
                .catalog
                .recover_changes(&scopes, &volume, journal, start, end)
                .map(|mut paths| {
                    paths.sort_unstable_by_key(String::len);
                    paths.into_iter().map(|path| {
                        let id = crate::path_keys::path_key(&path);
                        (path, id)
                    }).collect::<Vec<_>>()
                });
            ranges.insert((volume, journal), (end, changed));
        }
        let mut marks = Vec::new();
        let mut admitted = HashSet::new();
        let mut retried = HashSet::new();
        let mut cursors = Vec::new();
        let mut failures = HashSet::new();
        for (id, root, scope, identity, current, cached, arrived) in probes {
            let range = match (&current, &cached) {
                (Ok((volume, journal, end)), Some((old_volume, old_journal, old_end)))
                    if volume == old_volume
                        && journal == old_journal
                        && (1..=*end).contains(old_end) =>
                {
                    ranges.get(&(volume.clone(), *journal))
                }
                _ => None,
            };
            let mut paths = Vec::new();
            let mut errors = Vec::new();
            let rebuild = !root.scanned || range.is_none_or(|(_, entries)| entries.is_err());
            // An admission checkpoint still covers every root's USN interval,
            // but valid intervals reconcile only paths that actually changed.
            // Root enumeration/topology recovery alone needs the whole subtree.
            let affected = owned_checkpoint_paths(
                &scope, changed.get(&id), range.and_then(|(_, paths)| paths.as_deref().ok()),
                startup || rebuild || arrived,
            );
            if !affected.is_empty() { self.retire_owned_outputs(Some(&affected))?; }
            if rebuild {
                // Only startup without a trusted persisted cursor establishes
                // a conservative baseline. During a running session the in-memory
                // inventory must publish arrivals even if persistence has failed.
                let options = self.scan_options(root.deep)?;
                let scan = if !startup || cached.is_some() {
                    options.catalog_refresh(&self.catalog, &scope, None)
                } else {
                    options.catalog_update(&self.catalog, &scope, None)
                        .map(|errors| (errors, Vec::new()))
                };
                match scan {
                    Ok((failures, arrivals)) => {
                        errors = failures;
                        paths = arrivals;
                    }
                    Err(error) => {
                        self.journal.log(json!({"event":"filesystem_scan_failed","path":root.path,"error":error.to_string()}));
                        if let Ok((volume, _, _)) = current {
                            failures.insert(volume);
                        }
                        continue;
                    }
                }
                self.journal
                    .log(json!({"event":"catalog_rebuilt","root":root.path,"errors":errors}));
                // The catalog compares size and timestamps. Named notifications
                // can also report a replacement or overwrite with identical metadata.
                if let Some(changes) = changed.get(&id) {
                    for path in changes {
                        let path = path.to_string_lossy();
                        if !scope.contains(&path) || self.catalog.is_owned(&path) {
                            continue;
                        }
                        match fs::metadata(path.as_ref()) {
                            Ok(metadata) if metadata.is_file() => paths.push(path.into_owned()),
                            Err(error) if missing_path(&error) => {
                                self.departed(&path, true)?;
                                paths.push(path.into_owned());
                            }
                            _ => {}
                        }
                    }
                }
            } else if let Some((_, Ok(changes))) = range {
                let mut covered = HashSet::new();
                let mut full_refresh = false;
                // A directory notification can arrive before its USN record
                // becomes readable. Visit both sources through the same catalog.
                let mut named = changed.get(&id).into_iter().flatten().collect::<Vec<_>>();
                named.sort_unstable_by_key(|path| path.as_os_str().len());
                let recovered = changes.iter().map(|(path, id)| {
                    (std::borrow::Cow::Borrowed(path.as_str()), std::borrow::Cow::Borrowed(id.as_str()))
                });
                let named = named.into_iter().map(|path| {
                    let path = path.to_string_lossy();
                    let id = crate::path_keys::path_key(&path);
                    (path, std::borrow::Cow::Owned(id))
                });
                for (path, path_id) in recovered.chain(named) {
                    let path = path.as_ref();
                    if !scope.contains_key(path_id.as_ref()) || covered.contains(path_id.as_ref()) {
                        continue;
                    }
                    if self.catalog.is_owned(path) {
                        continue;
                    }
                    let metadata = fs::metadata(path);
                    let missing = metadata.as_ref().is_err_and(missing_path);
                    let recursive_departure =
                        missing && self.catalog.path_is_directory(&scope, path).unwrap_or(true);
                    if !full_refresh && !crate::path_keys::path_ancestors(path_id.as_ref())
                        .skip(1).any(|parent| covered.contains(parent)) {
                        let options = self.scan_options(root.deep)?;
                        let refresh = options.catalog_refresh(&self.catalog, &scope, Some(path));
                        match collect_catalog_arrivals(refresh, &mut paths) {
                            Ok(()) => {}
                            Err(reason) => {
                                full_refresh = true;
                                match options.catalog_refresh(&self.catalog, &scope, None) {
                                    Ok((failed, mut arrivals)) => {
                                        errors = failed;
                                        paths.append(&mut arrivals);
                                        self.journal.log(json!({"event":"catalog_rebuilt","root":root.path,
                                            "reason":reason,"errors":errors}));
                                    }
                                    Err(error) => {
                                        self.journal.log(json!({"event":"filesystem_scan_failed","path":root.path,
                                            "error":error.to_string(),"reason":reason}));
                                        errors.push(("scan".into(), root.path.to_string_lossy().into_owned(), error.to_string()));
                                    }
                                }
                            }
                        }
                    }
                    covered.insert(path_id);
                    if metadata.is_ok_and(|metadata| metadata.is_file()) {
                        paths.push(path.to_owned());
                    } else if missing {
                        self.departed(path, recursive_departure)?;
                        paths.push(path.to_owned());
                    }
                }
            }
            let recovered_paths = paths.len();
            if !root.scanned {
                paths.extend(self.catalog.candidate_paths(&scope, None));
                // The initial scan records a completed directory enumeration.
                // It has its own durable candidate barrier below, even when
                // the USN cursor is temporarily unavailable.
                if errors.is_empty() {
                    marks.push(id.clone());
                }
            }
            for (index, path) in paths.into_iter().enumerate() {
                // Initial inventory is not an explicit retry. Only paths
                // reported by startup recovery bypass an interrupted entry.
                let admission = if startup && index < recovered_paths {
                    if self.journal.state().entry(&path).is_some_and(|entry| {
                        matches!(entry.status.as_str(), "failed_password" | "suspended_missing_volume")
                    }) {
                        continue;
                    }
                    CandidateAdmission::ExplicitRetry
                } else {
                    CandidateAdmission::Observe
                };
                let path_id = watch_path_key(&path);
                if admitted.insert(path_id) {
                    self.observe_candidate_with_event(&id, path.clone(), admission,
                        None, None, None, Some(events.get(Path::new(&path)).unwrap_or(&CandidateEvent::Business(
                            if index >= recovered_paths { "initial_scan" }
                            else if startup { "startup_usn_recovery" } else { "usn_recovery" }))))?;
                    self.retry_volume_peers(&scope, &path, &mut retried)?;
                }
            }
            match (current, identity) {
                (Ok((volume, journal, mut end)), Some(identity)) if errors.is_empty() => {
                    if let Some((current_end, Ok(_))) = range {
                        end = *current_end;
                    }
                    let changed = cached.as_ref().is_none_or(|(old_volume, old_journal, old_end)| {
                        (old_volume, *old_journal, *old_end) != (&volume, journal, end)
                    });
                    cursors.push((changed.then_some((scope, identity)), volume, journal, end));
                }
                (Ok((volume, _, _)), _) => { failures.insert(volume); }
                (Err(error), _) => self.journal.log(json!({"event":"usn_cursor_unavailable","root":root.path,"error":error.to_string()})),
            }
        }
        let mut operations = BTreeMap::new();
        for (_, volume, journal, end) in &cursors {
            if failures.contains(volume) {
                continue;
            }
            let end = i128::from(*end);
            operations
                .entry(volume.clone())
                .and_modify(|cursor: &mut crate::watch_store::Cursor| {
                    cursor.next_usn = cursor.next_usn.min(end);
                })
                .or_insert(crate::watch_store::Cursor {
                    journal_id: i128::from(*journal),
                    next_usn: end,
                });
        }
        operations.retain(|volume, cursor| {
            self.journal.state().watch_cursor(volume).as_ref() != Some(cursor)
        });
        // Recovery/admission owns the durable cursor, never ordinary file
        // notifications. Publish candidates and cursor in one transaction.
        self.persist_candidates(operations, true)?;
        for (changed, volume, journal, end) in cursors {
            if let Some((scope, identity)) = changed.filter(|_| !failures.contains(&volume)) {
                self.catalog.set_cursor(&scope, identity, volume, journal, end);
            }
        }
        if !marks.is_empty() {
            // Candidate/cursor durability above is mandatory. This separate
            // user configuration marker must not stop unrelated roots.
            let marked = (|| -> io::Result<()> {
                let _lock = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
                let mut latest = read_roots(&self.root_file)?;
                let mut dirty = false;
                let mut matched = Vec::new();
                for root in &mut latest {
                    let id = key(&root.path);
                    if marks.contains(&id) {
                        if let Some((current, _)) = self.roots.get_mut(&id) {
                            if root.same_policy(current) {
                                dirty |= !root.scanned;
                                root.scanned = true;
                                matched.push(id);
                            }
                        }
                    }
                }
                if dirty {
                    write_roots(&self.root_file, &latest)?;
                }
                for id in &matched {
                    if let Some((current, _)) = self.roots.get_mut(id) { current.scanned = true; }
                }
                Ok(())
            })();
            match marked {
                Ok(()) => self.journal.log(json!({"event":"initial_scan_completed","roots":marks})),
                Err(error) => self.journal.log(json!({"event":"scheduler_error","error":error.to_string()})),
            }
        }
        if startup || !admitted.is_empty() {
            self.journal.log(
                json!({"event":if startup { "usn_startup_recovered" } else { "usn_checkpoint" },
                "changed":admitted.len(),"queued":self.pending.len()}),
            );
        }
        self.catalog.commit(false);
        if let Some(error) = self.catalog.error() {
            self.journal.log(json!({"event":"catalog_persistence_failed","error":error}));
        }
        Ok(())
    }

    fn retire_missing_entries(&self, path: Option<&str>, recursive: bool) -> io::Result<()> {
        let mut available = HashMap::new();
        let missing = self
            .journal
            .state()
            .entry_paths(path, recursive)
            .into_iter()
            .filter_map(|(id, recorded_path)| {
                let root = self
                    .roots
                    .values()
                    .find_map(|(root, scope)| scope.contains(&recorded_path).then_some(&root.path))
                    .or_else(|| {
                        let entry = self.journal.state().entry(&recorded_path)?;
                        let source = entry.failure_payload.get("source_input_root")?.as_str()?;
                        self.roots
                            .get(&watch_path_key(source))
                            .map(|(root, _)| &root.path)
                    })?;
                (*available.entry(root).or_insert_with(|| root.is_dir())
                    && NativePresence::at(&recorded_path).is_absent())
                .then_some((id, root))
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        // A volume can disappear during the probe. Keep its durable blockers.
        available.clear();
        let keys = missing.into_iter().filter_map(|(id, root)| {
            available
                .entry(root)
                .or_insert_with(|| root.is_dir())
                .then_some(id)
        });
        self.journal.commit(false, |_| {
            Ok(crate::watch_store::NativeWatchOperations::retire_entries(
                keys,
            ))
        })
    }

    fn retire_stale_promoted(&self, path: Option<&str>, recursive: bool) -> io::Result<()> {
        let candidates = self.journal.state().promoted_sources(path, recursive);
        if candidates.is_empty() {
            return Ok(());
        }
        self.journal.commit(false, |state| {
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            for (key, receipt) in candidates {
                let path = receipt.path().to_string_lossy();
                if self
                    .roots
                    .values()
                    .any(|(root, scope)| scope.contains(&path) && root.path.is_dir())
                    && (NativePresence::at(&path).is_absent() || receipt.is_replaced())
                    && state
                        .promoted_source(&path)
                        .is_some_and(|current| Arc::ptr_eq(&receipt, &current))
                {
                    operations.retire_promoted(key);
                }
            }
            Ok(operations)
        })
    }

    fn departed(&mut self, path: &str, recursive: bool) -> io::Result<()> {
        let path_key = watch_path_key(path);
        let is_missing = |pending: &Pending| {
            NativePresence::at(&pending.candidate.path).is_absent()
                && self
                    .roots
                    .get(&pending.root)
                    .is_some_and(|(root, _)| root.path.is_dir())
        };
        let removed: Vec<_> = if recursive {
            self.pending
                .iter()
                .filter(|(key, pending)| {
                    (*key == &path_key || is_path_under(key, &path_key)) && is_missing(pending)
                })
                .map(|(key, _)| key.clone())
                .collect()
        } else {
            self.pending
                .get(&path_key)
                .filter(|pending| is_missing(pending))
                .map(|_| path_key.clone())
                .into_iter()
                .collect()
        };
        for id in removed {
            if let Some(pending) = self.pending.remove(&id) {
                self.due.remove(&(pending.due, id.clone()));
                self.unpublished.remove(&id);
                self.retire_departed_owner(&id, &pending.candidate.path)?;
            }
        }
        self.journal.log(json!({"event":"candidate_departed","path":path,"recursive":recursive}));
        self.catalog.forget_observation(path, recursive, true);
        self.retire_stale_promoted(Some(path), recursive)?;
        self.retire_missing_entries(Some(path), recursive)
    }

    fn retire_departed_owner(&self, id: &str, path: &str) -> io::Result<()> {
        let claimed =
            self.active_paths.contains_key(id) || self.hub.claims.lock().unwrap().contains_key(id);
        if claimed {
            return Ok(());
        }
        self.journal.commit(false, |state| {
            use crate::watch_store::NativeWatchOperations;
            let recoverable = state.pending(path).is_some_and(|record| {
                !record.active_outputs.is_empty()
                    || record.committed_roots.iter().next().is_some()
                    || record.promoted_destinations.iter().next().is_some()
            });
            Ok(if recoverable {
                NativeWatchOperations::empty()
            } else {
                NativeWatchOperations::finish_pending(path, None)
            })
        })
    }

    #[cfg(test)]
    fn enqueue(&mut self, root_id: &str, path: String, admission: CandidateAdmission) -> io::Result<()> {
        self.observe_candidate_with_quiet(root_id, path, admission, None, None, None)
    }

    fn defer_claimed_path(&mut self, id: &str) -> bool {
        let claims = self.hub.claims.lock().unwrap();
        let owner = self.active_paths.get(id).map(AsRef::as_ref)
            .or_else(|| claims.get(id).map(AsRef::as_ref));
        let Some(owner) = owner else { return false; };
        if let Some(active) = self.active.get_mut(owner) {
            active.dirty.insert(id.to_owned());
        }
        true
    }

    fn enqueue_with_recovery(
        &mut self,
        root_id: &str,
        path: String,
        recovery: Option<Arc<Recovery>>,
    ) -> io::Result<()> {
        self.observe_candidate_with_event(root_id, path, CandidateAdmission::Retry, recovery, None, None,
            Some(&CandidateEvent::Business("volume_changed")))
    }

    #[cfg(test)]
    fn observe_candidate_with_quiet(
        &mut self, root_id: &str, path: String, admission: CandidateAdmission,
        recovery: Option<Arc<Recovery>>, captured: Option<&WatchCandidateRow>,
        tracker: Option<quiet::Activity>,
    ) -> io::Result<()> {
        let event = match admission {
            CandidateAdmission::PasswordRetry => Some(CandidateEvent::Business("password_retry")),
            CandidateAdmission::CrashRecovery => Some(CandidateEvent::Business("crash_recovery")),
            _ => None,
        };
        self.observe_candidate_with_event(root_id, path, admission, recovery, captured, tracker, event.as_ref())
    }

    fn observe_candidate_with_event(
        &mut self, root_id: &str, path: String, admission: CandidateAdmission,
        recovery: Option<Arc<Recovery>>, captured: Option<&WatchCandidateRow>,
        tracker: Option<quiet::Activity>, event: Option<&CandidateEvent>,
    ) -> io::Result<()> {
        let Some((_, scope)) = self.roots.get(root_id) else {
            return Ok(());
        };
        if recovery.as_ref().map_or_else(
            || !scope.contains(&path) || self.catalog.is_owned(&path),
            |recovery| !recovery.scope.contains(&path),
        ) {
            return Ok(());
        }
        let id = watch_path_key(&path);
        if self.defer_claimed_path(&id) { return Ok(()); }
        let previous = self.catalog.observation(&path);
        let (blocked, promoted) = self.journal.state().observation_state(&id);
        let interrupted = blocked
            .as_ref()
            .filter(|entry| entry.status == "interrupted");
        let baseline = interrupted
            .map(|entry| entry.change_usn)
            .or_else(|| self.pending.get(&id).map(|entry| entry.candidate.observation.change_usn))
            .or_else(|| captured.map(|value| value.observation.change_usn))
            .or_else(|| previous.as_ref().map(|value| value.change_usn))
            .or_else(|| blocked.as_ref().map(|value| value.change_usn));
        let activity = self.hub.activities.bind(id.clone(), || {
            self.pending.get(&id).map(|pending| pending.quiet.clone())
                .or_else(|| tracker.clone()).unwrap_or_else(|| previous.as_ref()
                    .map_or_else(quiet::Activity::default, quiet::Activity::saved))
        });
        let (candidate, observed_now, observed_at) = match activity.probe(Path::new(&path), baseline) {
            Ok((Some(candidate), now, at)) => (candidate, now, at),
            Ok((None, _, _)) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                self.candidate_diagnostics.log_observation(
                    &self.journal, Instant::now(), &id, &path, &error, event);
                return Ok(());
            }
        };
        // Workers can acquire a sibling while the filesystem probe runs.
        if self.defer_claimed_path(&id) { return Ok(()); }
        if let Some(receipt) = promoted.filter(|receipt| receipt.is_replaced()) {
            self.journal.commit(false, |state| {
                let mut operations = crate::watch_store::NativeWatchOperations::empty();
                if state
                    .promoted_source(&path)
                    .is_some_and(|current| Arc::ptr_eq(&receipt, &current))
                {
                    operations.retire_promoted(id.clone());
                }
                Ok(operations)
            })?;
        }
        let blocked_unchanged = blocked
            .as_ref()
            .is_some_and(|before| !entry_changed(before, &candidate));
        let unchanged = if let Some(before) = self.pending.get(&id).map(|entry| &entry.candidate) {
            !quiet::changed(before, &candidate)
        } else if let Some(before) = captured {
            !quiet::changed(before, &candidate)
        } else if let Some(before) = &previous {
            !quiet::content_changed(
                before.size,
                before.mtime,
                &before.file_id(),
                before.change_usn,
                &candidate,
            )
        } else {
            blocked_unchanged
        };
        let boundary = quiet::is_boundary(&candidate);
        let force = !matches!(admission, CandidateAdmission::Observe | CandidateAdmission::QueuedRecovery);
        if (admission != CandidateAdmission::ExplicitRetry && interrupted.is_some() && blocked_unchanged)
            || (admission == CandidateAdmission::Observe && (unchanged || blocked_unchanged))
        {
            if let Some(before) = blocked.filter(|before| {
                blocked_unchanged
                    && (before.change_usn != candidate.observation.change_usn
                        || before.mtime != candidate.mtime)
            }) {
                self.journal.commit(false, |state| {
                    let mut operations = crate::watch_store::NativeWatchOperations::empty();
                    if state
                        .entry(&candidate.path)
                        .is_some_and(|current| Arc::ptr_eq(&current, &before))
                    {
                        let mut updated = (*before).clone();
                        updated.mtime = candidate.mtime;
                        updated.change_usn = candidate.observation.change_usn;
                        operations.put_entry(Arc::new(updated));
                    }
                    Ok(operations)
                })?;
            }
            if recovery.is_none()
                && previous.as_ref().map_or(captured.is_some(), |before| {
                    before.mtime != candidate.mtime
                        || before.change_usn != candidate.observation.change_usn
                })
            {
                self.catalog.remember_observation(
                    &candidate.path,
                    candidate.size,
                    candidate.mtime,
                    &candidate.observation.file_id,
                    candidate.observation.change_usn,
                    boundary,
                );
            }
            if let Some(pending) = self.pending.get_mut(&id) {
                let now = Instant::now();
                if boundary && baseline != Some(candidate.observation.change_usn) {
                    pending.quiet.metadata(&candidate, observed_now);
                    // CLOSE is a useful hint only if a writer hasn't reopened
                    // the file. Keep short existing waits on their cadence.
                    if pending.due.saturating_duration_since(now).as_millis() >= 100
                        && filesystem::watch_file_is_ready(&candidate.path).unwrap_or(false)
                    {
                        self.due.remove(&(pending.due, id.clone()));
                        pending.quiet.accelerate(observed_now, now);
                        pending.due = now;
                        if !self.active_paths.contains_key(&id)
                            && !self.hub.claims.lock().unwrap().contains_key(&id)
                        {
                            self.due.insert((now, id), ());
                        }
                    }
                }
                pending.candidate = candidate;
            }
            return Ok(());
        }
        if let Some(interrupted) = interrupted {
            self.journal.commit(false, |state| {
                Ok(if state.entry(&candidate.path).is_some_and(|current| Arc::ptr_eq(interrupted, &current)) {
                    crate::watch_store::NativeWatchOperations::retire_entries(std::iter::once(id.clone()))
                } else {
                    crate::watch_store::NativeWatchOperations::empty()
                })
            })?;
        }
        let prior = self.pending.remove(&id);
        let became_active = prior.is_none();
        let new_identity = prior.as_ref().map_or_else(
            || {
                previous.as_ref().map_or_else(
                    || captured.is_some_and(|old| old.observation.file_id != candidate.observation.file_id || old.size > candidate.size),
                    |old| old.file_id() != candidate.observation.file_id || old.size > candidate.size,
                )
            },
            |old| {
                old.candidate.observation.file_id != candidate.observation.file_id
                    || old.candidate.size > candidate.size
            },
        );
        if let Some(old) = prior { self.due.remove(&(old.due, id.clone())); }
        let quiet = activity;
        let retry_unchanged = became_active && match admission {
            CandidateAdmission::PasswordRetry => blocked_unchanged,
            CandidateAdmission::QueuedRecovery | CandidateAdmission::CrashRecovery => unchanged,
            _ => false,
        };
        // Force admission of a stable head when a peer arrives, without
        // learning a write interval from that unchanged input. An already
        // pending candidate keeps main's explicit content observation.
        let forced_content_change = if !force {
            None
        } else if !became_active {
            Some(true)
        } else if unchanged {
            Some(false)
        } else {
            None
        };
        let due = quiet.content_deadline(
            &candidate, observed_now, observed_at, new_identity, retry_unchanged, forced_content_change,
        );
        if recovery.is_none() {
            self.catalog.remember_observation(
                &candidate.path,
                candidate.size,
                candidate.mtime,
                &candidate.observation.file_id,
                candidate.observation.change_usn,
                boundary,
            );
        }
        if became_active {
            self.journal.log(json!({
                "event":"candidate_active", "path":candidate.path, "force":force,
                "event_type":event.map_or("unknown", CandidateEvent::kind),
                "src_path":event.map_or_else(|| "".into(), CandidateEvent::source),
                "size":candidate.size, "mtime":candidate.mtime,
                "quiet_seconds":quiet.summary().0, "pending":self.pending.len() + 1,
            }));
        }
        self.due.insert((due, id.clone()), ());
        self.unpublished.insert(id.clone());
        self.pending.insert(
            id,
            Pending {
                admission_ready: false,
                root: root_id.to_owned(),
                candidate,
                quiet,
                due,
                force,
                recovery,
            },
        );
        self.cache_deadline = None;
        Ok(())
    }

    fn persist_candidates(
        &mut self,
        cursors: BTreeMap<String, crate::watch_store::Cursor>,
        durable: bool,
    ) -> io::Result<()> {
        self.persist_candidates_and_retire(cursors, durable, None, None)
    }

    fn persist_candidates_and_retire(
        &mut self,
        cursors: BTreeMap<String, crate::watch_store::Cursor>,
        durable: bool,
        retire: Option<&str>,
        handoff: Option<crate::watch_store::NativeWatchOperations>,
    ) -> io::Result<()> {
        if self.unpublished.is_empty() && cursors.is_empty() && retire.is_none() && handoff.is_none() {
            return Ok(());
        }
        let keys = &self.unpublished;
        self.journal.commit(durable, |state| {
            use crate::watch_store::PendingObservation;
            let mut ordinary = Vec::new();
            let mut forced = Vec::new();
            let mut recoveries = Vec::new();
            for pending in keys.iter().filter_map(|key| self.pending.get(key)) {
                let Some((root, scope)) = self.roots.get(&pending.root) else {
                    continue;
                };
                let candidate = &pending.candidate;
                let observation = PendingObservation(
                    candidate.path.clone(),
                    candidate.size.min(i64::MAX as u64) as i64,
                    candidate.mtime,
                    candidate.observation.file_id.clone(),
                    candidate.observation.change_usn,
                );
                if let Some(recovery) = &pending.recovery {
                    let update = (
                        observation,
                        root.path.to_string_lossy().into_owned(),
                        Some(scope_record(&recovery.scope)),
                    );
                    recoveries.push((update, pending.force, &recovery.password_scope));
                } else {
                    let target = if pending.force {
                        &mut forced
                    } else {
                        &mut ordinary
                    };
                    target.push((observation, scope.root.clone(), Some(scope_record(scope))));
                }
            }
            let cursors = (!cursors.is_empty()).then_some(cursors);
            let (mut operations, _) =
                state.pending_operations(ordinary, false, "", false, true, cursors)?;
            if !forced.is_empty() {
                let (force, _) = state.pending_operations(forced, true, "", false, true, None)?;
                operations.extend(force);
            }
            for (update, force, password_scope) in recoveries {
                let (recovery, _) = state.pending_operations(
                    std::iter::once(update),
                    force,
                    &password_scope.to_string_lossy(),
                    true,
                    true,
                    None,
                )?;
                operations.extend(recovery);
            }
            if let Some(handoff) = handoff {
                operations.extend(handoff);
            }
            if let Some(owner) = retire {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                    owner,
                    state.entry(owner),
                ));
            }
            Ok(operations)
        })?;
        self.unpublished.clear();
        Ok(())
    }

    fn merge_clipboard(&mut self, clipboard: &[String]) -> io::Result<()> {
        // A notification queued before the last root was removed must not
        // mutate the password history after root-bound monitoring stops.
        if self.roots.is_empty() { return Ok(()); }
        match self.passwords.merge_clipboard(
            clipboard,
            self.settings.watch.clipboard_builtin_max_entries,
        ) {
            Ok(true) => self.password_update(false)?,
            Ok(false) => {}
            Err(error) => self.journal.log(json!({
                "event":"watch_clipboard_password_save_failed", "error":error.to_string(),
            })),
        }
        Ok(())
    }

    fn password_update(&mut self, startup: bool) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("password_reload", Origin::Watch, || self.password_update_blocking(startup))?
    }

    fn password_update_blocking(&mut self, startup: bool) -> io::Result<()> {
        let snapshot = match self.passwords.reload() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.journal
                    .log(json!({"event":"watch_password_reload_failed","error":error.to_string()}));
                return Ok(());
            }
        };
        if self.journal.suspended() { return Ok(()); }
        let signature = password_source_signature(&self.user_password_signature, snapshot.signature());
        let state = self.journal.state();
        let changed = state.password_source_signature() != signature;
        if changed || startup {
            // A prior runtime can publish the password generation before
            // scheduling every affected blocker. Reconcile entries once when
            // taking ownership, even if the global generation is current.
            self.retry_password_failures_with_event(&snapshot, None,
                if startup { "startup_password_reconcile" } else { "password_retry" })?;
            self.persist_candidates(BTreeMap::new(), !changed)?;
        }
        if !changed {
            return Ok(());
        }
        let generation = self.journal.state().password_generation().saturating_add(1);
        self.journal.commit(true, |_| {
            Ok(
                crate::watch_store::NativeWatchOperations::password_generation(
                    generation, signature.to_owned(),
                ),
            )
        })?;
        self.journal
            .log(json!({"event":"password_source_changed","password_generation":generation}));
        Ok(())
    }

    fn retry_password_failures(
        &mut self,
        snapshot: &crate::core::passwords::PasswordSnapshot,
        roots: Option<&HashSet<String>>,
    ) -> io::Result<()> {
        self.retry_password_failures_with_event(snapshot, roots, "password_retry")
    }

    fn retry_password_failures_with_event(&mut self,
        snapshot: &crate::core::passwords::PasswordSnapshot,
        roots: Option<&HashSet<String>>, event: &'static str,
    ) -> io::Result<()> {
        for entry in self.journal.state().entry_items(Some("password")) {
            let Some((root, recovery)) = self.blocker_route(&entry) else {
                continue;
            };
            if roots.is_some_and(|roots| !roots.contains(&root)) {
                continue;
            }
            let directory = candidate_password_scope(self.journal.state(), &entry.path, recovery.as_deref());
            if entry
                .failure_payload
                .get("password_signature")
                .and_then(Value::as_str)
                .is_some_and(|before| before == password_source_signature(&self.user_password_signature, &snapshot.scope_signature(&directory)))
            {
                continue;
            }
            self.observe_candidate_with_event(&root, entry.path.clone(),
                CandidateAdmission::PasswordRetry, recovery, None, None, Some(&CandidateEvent::Business(event)))?;
            self.journal
                .log(json!({"event":"retry_password_failure","path":entry.path}));
        }
        Ok(())
    }

    fn retry_missing_volumes(&mut self, roots: Option<&HashSet<String>>) -> io::Result<()> {
        self.retry_missing_volumes_with_event(roots, "volume_changed")
    }

    fn retry_volume_peers(&mut self, scope: &NativeDiscoveryScope, seed: &str, retried: &mut HashSet<String>) -> io::Result<()> {
        let seed_key = crate::path_keys::path_key(seed);
        for peer in self.catalog.bucket_paths(scope, seed) {
            let id = crate::path_keys::path_key(&peer);
            if id == seed_key || retried.contains(&id) { continue; }
            let Some(entry) = self.journal.state().entry_by_key(&id)
                .filter(|entry| entry.status == "suspended_missing_volume") else { continue };
            if let Some((root, recovery)) = self.blocker_route(&entry) {
                retried.insert(id);
                self.enqueue_with_recovery(&root, peer, recovery)?;
            }
        }
        Ok(())
    }

    fn retry_missing_volumes_with_event(&mut self, roots: Option<&HashSet<String>>, event: &'static str) -> io::Result<()> {
        for entry in self.journal.state().entry_items(Some("missing_volume")) {
            let Some((root, recovery)) = self.blocker_route(&entry) else {
                continue;
            };
            if roots.is_some_and(|roots| !roots.contains(&root)) {
                continue;
            }
            let id = watch_path_key(&entry.path);
            if !self.pending.contains_key(&id) {
                self.observe_candidate_with_event(&root, entry.path.clone(), CandidateAdmission::Retry,
                    recovery, None, None, Some(&CandidateEvent::Business(event)))?;
            }
        }
        self.persist_candidates(BTreeMap::new(), true)
    }

    fn blocker_route(
        &self,
        entry: &crate::watch_store::EntryRecord,
    ) -> Option<(String, Option<Arc<Recovery>>)> {
        route_blocker(entry, &self.roots, |path| self.catalog.is_owned(path))
    }

    fn recover_pending(&mut self, roots: Option<&HashSet<String>>) -> io::Result<()> {
        recover_flattens(&self.journal, |owner| {
            roots.is_none_or(|roots| {
                self.journal.state().pending(owner).is_some_and(|record| {
                    roots.contains(&watch_path_key(&record.source_input_root))
                }) && !self.active_paths.contains_key(&watch_path_key(owner))
                    && !self
                        .hub
                        .claims
                        .lock()
                        .unwrap()
                        .contains_key(&watch_path_key(owner))
            })
        })?;
        let journal = Arc::clone(&self.journal);
        let state = journal.state();
        let flatten_owners: HashSet<_> = state
            .runtime_keys("flatten|")
            .into_iter()
            .filter_map(|key| {
                let record = state.runtime_record(&key)?;
                record["owner"].as_str().map(watch_path_key)
            })
            .collect();
        for pending in self.journal.state().pending_items() {
            let id = watch_path_key(&pending.path);
            if flatten_owners.contains(&id)
                || self.pending.contains_key(&id)
                || self.active_paths.contains_key(&id)
                || self.hub.claims.lock().unwrap().contains_key(&id)
            {
                continue;
            }
            let original = watch_path_key(&pending.source_input_root);
            let root = self
                .roots
                .get(&original)
                .and_then(|(_, scope)| {
                    (pending.internal_recovery || scope.contains(&pending.path)).then_some(original)
                })
                .or_else(|| {
                    self.roots.iter().find_map(|(id, (_, scope))| {
                        scope.contains(&pending.path).then(|| id.clone())
                    })
                });
            let Some(root) = root else {
                continue;
            };
            if roots.is_some_and(|roots| !roots.contains(&root)) {
                continue;
            }
            let Some((source_root, scope)) = self.roots.get(&root) else {
                continue;
            };
            if !source_root.path.is_dir() {
                continue;
            }
            let scope = scope.clone();
            if pending.internal_recovery
                && pending
                    .discovery_scope
                    .get("root")
                    .and_then(Value::as_str)
                    .is_some_and(|root| !Path::new(root).is_dir())
            {
                continue;
            }
            let source = Path::new(&pending.path);
            let entry = state.entry(&pending.path);
            let borrowed = entry.as_ref().and_then(|entry| {
                entry
                    .failure_payload
                    .get("details")?
                    .get("retry_output_dir")?
                    .as_str()
            });
            let checkpoints = input_checkpoints(state, &pending.path).collect::<io::Result<Vec<_>>>()?;
            // Failure recovery may retain a carrier across a retry. Successful
            // work is recovered through the pending output records below.
            let retained_containers = checkpoints.iter()
                .filter_map(crate::pipeline::InputCheckpoint::retained_container)
                .map(key)
                .collect::<HashSet<_>>();
            let mut revisit = BTreeMap::new();
            let mut inspected_outputs = HashSet::new();
            let mut cleanup_failed = false;
            for (task, output) in pending.active_outputs.iter() {
                if pending.committed_roots.contains(output)
                    || borrowed == Some(output.as_str())
                    || (!retained_containers.is_empty()
                        && retained_containers.contains(&watch_path_key(output)))
                {
                    continue;
                }
                if inspected_outputs.insert(watch_path_key(output)) {
                    if recovery_output_matches(state, &pending, output) {
                        if let Err(error) = crate::postprocess::remove_owned_tree(Path::new(output)) {
                            cleanup_failed = true;
                            self.journal.log(json!({"event":"crash_output_cleanup","path":output,"error":error.to_string()}));
                        }
                    } else {
                        self.journal.log(json!({"event":"crash_output_identity_changed","owner_path":pending.path,"output_dir":output}));
                    }
                }
                if Path::new(task).is_file() && !pending.completed_sources.contains(task) {
                    revisit.insert(watch_path_key(task), task.clone());
                }
            }
            if cleanup_failed {
                continue;
            }
            let interrupted = entry.filter(|entry| {
                if entry.status != "interrupted" {
                    return false;
                }
                match watch_candidate_for_path(source, Some(entry.change_usn)) {
                    Ok(Some(current)) => !entry_changed(entry, &current),
                    Ok(None) => false,
                    Err(_) => {
                        entry.file_id == pending.file_id
                            && entry.size == pending.size
                            && entry.change_usn == pending.change_usn
                    }
                }
            });
            if let Some(entry) = interrupted {
                self.journal.commit(true, |_| {
                    Ok(crate::watch_store::NativeWatchOperations::finish_pending(
                        &pending.path,
                        Some(entry),
                    ))
                })?;
                continue;
            }
            let mut destinations_unavailable = false;
            for promoted in pending.promoted_destinations.iter() {
                match crate::watch_store::NativeWatchState::file_presence(promoted) {
                    Some(true) => {
                        revisit.insert(watch_path_key(promoted), promoted.clone());
                    }
                    Some(false) => {}
                    None => destinations_unavailable = true,
                }
            }
            if destinations_unavailable {
                continue;
            }
            let promoted_present = pending
                .promoted_destinations
                .iter()
                .any(|path| revisit.contains_key(&watch_path_key(path)));
            let mut verified = Vec::new();
            let mut missing_output = false;
            let mut unavailable = false;
            for output in pending.committed_roots.iter() {
                if recovery_output_matches(state, &pending, output) {
                    verified.push(output);
                } else {
                    missing_output = true;
                }
            }
            if missing_output && !promoted_present {
                if !source.is_file() {
                    self.journal.log(
                        json!({"event":"crash_committed_output_missing","owner_path":pending.path}),
                    );
                    continue;
                }
                revisit.insert(watch_path_key(&pending.path), pending.path.clone());
            }
            // Missing siblings may require the owner to be rebuilt, but do
            // not replace recovery of unfinished descendants in surviving outputs.
            for output in &verified {
                let output_scope =
                    NativeDiscoveryScope::new((*output).clone(), None, Vec::new());
                match recovery_scan_paths(
                    &self.journal, &pending.path, output,
                    crate::scan::directory::scope_file_paths(&output_scope),
                ) {
                    Ok(paths) => {
                        for path in paths {
                            let path = path.to_string_lossy().into_owned();
                            if !pending.completed_sources.contains(&path)
                                && fs::metadata(&path).is_ok_and(|metadata| metadata.len() > 0)
                            {
                                revisit.insert(watch_path_key(&path), path);
                            }
                        }
                    }
                    _ => {
                        unavailable = true;
                        break;
                    }
                }
            }
            if unavailable {
                continue;
            }
            if revisit.is_empty() && verified.is_empty() {
                if !pending.active_outputs.is_empty() {
                    self.journal.log(json!({"event":"crash_recovery_source_missing","owner_path":pending.path}));
                    continue;
                }
                if source.is_file() {
                    revisit.insert(watch_path_key(&pending.path), pending.path.clone());
                } else if !NativePresence::at(&pending.path).is_absent() {
                    continue;
                }
            }
            let owner = watch_path_key(&pending.path);
            let mut rebase = !revisit.contains_key(&owner);
            let admission = if pending.internal_recovery || !pending.active_outputs.is_empty()
                || pending.committed_roots.iter().next().is_some() || pending.promoted_destinations.iter().next().is_some() {
                CandidateAdmission::CrashRecovery
            } else if pending.force {
                CandidateAdmission::Retry
            } else {
                CandidateAdmission::QueuedRecovery
            };
            for (id, path) in revisit {
                if state.entry(&path).is_some_and(|entry| {
                    matches!(
                        entry.status.as_str(),
                        "failed_password" | "suspended_missing_volume"
                    )
                }) {
                    continue;
                }
                let recovery = if id == owner && !pending.internal_recovery {
                    None
                } else {
                    let nested = verified
                        .iter()
                        .filter(|output| is_path_under(&id, &watch_path_key(output)))
                        .max_by_key(|output| output.len());
                    let recovery = if let Some(output) = nested {
                        Recovery {
                            scope: NativeDiscoveryScope::new((**output).clone(), None, Vec::new()),
                            password_scope: PathBuf::from(&pending.password_scope_dir),
                        }
                    } else {
                        Recovery::from_record(&pending.discovery_scope, &pending.password_scope_dir)
                            .filter(|recovery| recovery.scope.contains(&path))
                            .unwrap_or_else(|| Recovery {
                                scope: if scope.contains(&path) {
                                    scope.clone()
                                } else {
                                    let parent =
                                        Path::new(&path).parent().unwrap_or(Path::new("."));
                                    NativeDiscoveryScope::new(
                                        parent.to_string_lossy().into_owned(),
                                        Some(0),
                                        Vec::new(),
                                    )
                                },
                                password_scope: PathBuf::from(&pending.password_scope_dir),
                            })
                    };
                    Some(Arc::new(recovery))
                };
                self.observe_candidate_with_event(&root, path.clone(), admission, recovery, None, None,
                    Some(&CandidateEvent::Business(if pending.active_outputs.is_empty()
                        && pending.committed_roots.iter().next().is_none()
                        && pending.promoted_destinations.iter().next().is_none() {
                        "recovery"
                    } else { "crash_recovery" })))?;
                if !self.pending.contains_key(&id) && !NativePresence::at(&path).is_absent() {
                    rebase = false;
                }
            }
            self.persist_candidates_and_retire(
                BTreeMap::new(),
                true,
                rebase.then_some(pending.path.as_str()),
                None,
            )?;
        }
        self.persist_candidates(BTreeMap::new(), true)?;
        Ok(())
    }
}

struct NativePresence(Option<bool>);
impl NativePresence {
    fn at(path: &str) -> Self {
        Self(crate::watch_store::NativeWatchState::file_presence(path))
    }

    fn is_absent(&self) -> bool {
        self.0 == Some(false)
    }
}

fn missing_path(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn owned_checkpoint_paths(
    scope: &NativeDiscoveryScope,
    named: Option<&HashSet<PathBuf>>,
    recovered: Option<&[(String, String)]>,
    reconcile_root: bool,
) -> Vec<String> {
    if reconcile_root { return vec![scope.root.clone()]; }
    recovered.into_iter().flatten().filter(|(_, id)| scope.contains_key(id)).map(|(path, _)| path.clone())
        .chain(named.into_iter().flatten().map(|path| path.to_string_lossy().into_owned()))
        .collect()
}

fn output_identity(path: &str) -> io::Result<String> {
    let (volume, identity, _) = filesystem::watch_path_identity(path)?;
    Ok(format!("{volume}|{identity}"))
}

fn user_password_signature(user: &[Arc<str>]) -> String {
    let mut hash = crate::fast_hash_core::Hash128::new();
    hash.update(serde_json::to_string(user).unwrap().as_bytes());
    hash.hexdigest()
}

fn password_source_signature(user: &str, builtin: &str) -> String {
    let mut hash = crate::fast_hash_core::Hash128::new();
    hash.update(user.as_bytes());
    hash.update(builtin.as_bytes());
    hash.hexdigest()
}

fn recovery_output_matches(
    state: &crate::watch_store::NativeWatchState,
    pending: &crate::watch_store::PendingRecord,
    path: &str,
) -> bool {
    let Ok(Some(actual)) = identity_if_present(path) else {
        return false;
    };
    if let Some(record) = state.runtime_record(&format!("owned|{}", watch_path_key(path))) {
        if let Some(ids) = record["identities"]
            .as_array()
            .filter(|ids| !ids.is_empty())
        {
            return ids.iter().any(|id| id.as_str() == Some(&actual));
        }
    }
    pending.output_identities.get(path) == Some(&actual)
}

impl Scheduler {
    fn admission_available(&self) -> usize {
        if self.options.is_none() { return 0; }
        // Main admits one request per candidate. Batching must not turn that
        // candidate window into a batch window. This existing index contains
        // admitted inputs, not discovered claims, and completion removes each
        // settled owner (including aliases) before its siblings finish. Failure
        // while retiring indexes stops admission rather than reusing them.
        crate::pipeline::MAX_PENDING_JOBS.max(rayon::current_num_threads())
            .saturating_sub(self.active_paths.len())
    }

    fn next_admission(&self) -> Option<Instant> {
        if self.admission_available() == 0 {
            // Completions wake the Hub. A full window must not turn an old
            // pending deadline into an idle spin while extraction is parked.
            return None;
        }
        let claims = self.hub.claims.lock().unwrap();
        self.due.keys().find_map(|(due, path)| {
            (!self.active_paths.contains_key(path) && !claims.contains_key(path))
                .then_some(*due)
        })
    }

    fn prepare_ready(&mut self, now: Instant, available: usize) -> io::Result<Vec<(String, Pending)>> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_admission", Origin::Watch, || self.prepare_ready_blocking(now, available))?
    }

    fn prepare_ready_blocking(&mut self, now: Instant, available: usize) -> io::Result<Vec<(String, Pending)>> {
        let ready = {
            let claims = self.hub.claims.lock().unwrap();
            due_admissions(&self.due, now, available, |path| {
                !self.active_paths.contains_key(path) && !claims.contains_key(path)
            })
        };
        let mut prepared = Vec::new();
        for (due, id) in ready {
            if self.hub.stopped.load(Ordering::Acquire) {
                break;
            }
            let Some(mut pending) = self.pending.remove(&id) else {
                continue;
            };
            self.due.remove(&(due, id.clone()));
            if let Some(deadline) = pending.quiet.deadline().filter(|deadline| *deadline > now && *deadline > pending.due) {
                pending.due = deadline;
                self.due.insert((deadline, id.clone()), ());
                self.pending.insert(id, pending);
                continue;
            }
            if pending.admission_ready {
                prepared.push((id, pending));
                continue;
            }
            let path = Path::new(&pending.candidate.path);
            let previous_usn = pending.candidate.observation.change_usn;
            let (current, observed_now, observed_at) = match pending.quiet.probe(path, Some(previous_usn)) {
                Ok((Some(current), observed_now, observed_at)) => (current, observed_now, observed_at),
                Ok((None, _, _)) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(error) if missing_path(&error) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(error) => {
                    self.candidate_diagnostics.log_wait(&self.journal, Instant::now(), &id, &pending.candidate.path, Some(&error));
                    self.delay(id, pending, Instant::now());
                    continue;
                }
            };
            // A callback can arrive while the filesystem readiness probe runs.
            // Read its generation and deadline atomically, not as independent
            // matches/deadline checks that could accept a just-written file.
            let (captured, deadline) = pending.quiet.observation(&current);
            if let Some(deadline) = deadline.filter(|deadline| *deadline > now && *deadline > pending.due) {
                pending.due = deadline;
                self.due.insert((deadline, id.clone()), ());
                self.pending.insert(id, pending);
                continue;
            }
            if quiet::changed(&pending.candidate, &current) && !captured {
                let boundary = quiet::is_boundary(&current);
                pending.quiet.boundary_observation(&current, observed_now, observed_at,
                    self.settings.watch.boundary_confirmation_seconds);
                self.catalog.remember_observation(
                    &current.path,
                    current.size,
                    current.mtime,
                    &current.observation.file_id,
                    current.observation.change_usn,
                    boundary,
                );
                pending.candidate = current;
                self.unpublished.insert(id.clone());
                self.delay(id, pending, now);
                continue;
            }
            if quiet::is_boundary(&current) {
                pending.quiet.metadata(&current, observed_now);
            }
            if pending.recovery.is_none()
                && (current.mtime != pending.candidate.mtime
                    || current.observation.change_usn != previous_usn)
            {
                self.catalog.remember_observation(
                    &current.path,
                    current.size,
                    current.mtime,
                    &current.observation.file_id,
                    current.observation.change_usn,
                    quiet::is_boundary(&current),
                );
            }
            pending.candidate = current;
            match filesystem::watch_file_is_ready(&pending.candidate.path) {
                Ok(true) => {}
                Ok(false) => {
                    self.candidate_diagnostics.log_wait(&self.journal, Instant::now(), &id, &pending.candidate.path, None);
                    self.delay(id, pending, Instant::now());
                    continue;
                }
                Err(error) if missing_path(&error) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(error) => {
                    self.candidate_diagnostics.log_wait(&self.journal, Instant::now(), &id, &pending.candidate.path, Some(&error));
                    self.delay(id, pending, Instant::now());
                    continue;
                }
            }
            prepared.push((id, pending));
        }
        Ok(prepared)
    }

    fn dispatch_ready(&mut self) -> io::Result<()> {
        let available = self.admission_available();
        if available == 0 {
            return Ok(());
        }
        let now = Instant::now();
        if self.due.first_key_value().is_none_or(|((due, _), _)| *due > now) {
            return Ok(());
        }
        let prepared = self.prepare_ready(now, available)?;
        if prepared.is_empty() { return Ok(()); }
        // Keep the already-probed owners available for atomic publication.
        // Checkpoint replaces Pending on a content/forced-recovery change, so
        // only those changed candidates need a new filesystem readiness probe.
        let mut prepared_ids = Vec::with_capacity(prepared.len());
        for (id, mut pending) in prepared {
            pending.admission_ready = true;
            self.due.insert((pending.due, id.clone()), ());
            self.pending.insert(id.clone(), pending);
            prepared_ids.push(id);
        }
        let checkpoint = self.checkpoint(&HashMap::new(), true, false);
        #[cfg(test)]
        let checkpoint = checkpoint.and_then(|()| match self.admission_checkpoint.take() {
            Some(check) => check(self),
            None => Ok(()),
        });
        let prepared = checkpoint.and_then(|()| self.prepare_ready(now, available));
        // A new foreground claim can leave a prepared owner parked. Never
        // retain its readiness into a later tick, including checkpoint errors.
        for id in prepared_ids {
            if let Some(pending) = self.pending.get_mut(&id) {
                pending.admission_ready = false;
            }
        }
        let prepared = prepared?;
        let mut groups = BTreeMap::new();
        for (_, pending) in prepared {
            self.journal.log(json!({
                "event":"candidate_quiet", "path":pending.candidate.path,
                "quiet_seconds":pending.quiet.summary().0,
            }));
            if pending.recovery.is_none() {
                let (seconds, last, cadence, tentative) = pending.quiet.summary();
                self.catalog.retire_observation(
                    &pending.candidate.path,
                    Some(seconds),
                    last,
                    cadence,
                    tentative,
                );
            }
            let recovery_key = pending.recovery.as_ref().map(|recovery| {
                let mut excluded = recovery.scope.excluded_subtrees();
                excluded.sort_unstable();
                (
                    recovery.scope.root.clone(),
                    recovery.scope.max_depth,
                    excluded,
                )
            });
            let password_scope = candidate_password_scope(self.journal.state(),
                &pending.candidate.path, pending.recovery.as_deref());
            let (_, candidates) = groups
                .entry((pending.root, recovery_key, password_scope))
                .or_insert_with(|| (pending.recovery, Vec::new()));
            candidates.push((pending.candidate, pending.quiet));
        }
        for ((root, _, password_scope), (recovery, candidates)) in groups {
            if self.hub.stopped.load(Ordering::Acquire) {
                // These candidates still have durable pending intent. A stop
                // between readiness and submit must not start more requests.
                break;
            }
            self.start_batch(root, candidates, recovery, password_scope)?;
        }
        Ok(())
    }

    fn retire_admission(&mut self, id: &str, pending: &Pending) -> io::Result<()> {
        self.unpublished.remove(id);
        let path = &pending.candidate.path;
        if self
            .roots
            .get(&pending.root)
            .is_some_and(|(root, _)| root.path.is_dir())
            && pending
                .recovery
                .as_ref()
                .is_none_or(|recovery| Path::new(&recovery.scope.root).is_dir())
            && NativePresence::at(path).is_absent()
        {
            self.departed(path, false)?;
            self.retire_departed_owner(id, path)?;
        }
        Ok(())
    }

    fn delay(&mut self, id: String, mut pending: Pending, now: Instant) {
        // Main keeps a fresh/reset quiet window immediately eligible even
        // after a busy or failed probe; do not impose a separate wait floor.
        pending.due = pending.quiet.boundary_deadline(
            now, self.settings.watch.boundary_confirmation_seconds,
        );
        self.due.insert((pending.due, id.clone()), ());
        self.pending.insert(id, pending);
    }

    fn start_batch(&mut self, root_id: String, candidates: Vec<(WatchCandidateRow, quiet::Activity)>, recovery: Option<Arc<Recovery>>, password_scope: PathBuf) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_admission", Origin::Watch, || self.start_batch_blocking(root_id, candidates, recovery, password_scope))?
    }

    fn start_batch_blocking(
        &mut self,
        id: String,
        candidates: Vec<(WatchCandidateRow, quiet::Activity)>,
        recovery: Option<Arc<Recovery>>,
        password_scope: PathBuf,
    ) -> io::Result<()> {
        let Some((root, scope)) = self.roots.get(&id) else {
            return Ok(());
        };
        let mut quiet = HashMap::with_capacity(candidates.len());
        let candidates: Vec<_> = candidates.into_iter().map(|(candidate, tracker)| {
            quiet.insert(watch_path_key(&candidate.path), tracker);
            candidate
        }).collect();
        let mut token = windows::random_bytes::<16>()?;
        // The other half of the token space is reserved for Toast groups.
        token[0] &= 0x7f;
        let batch = token
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let cancel = Cancellation::new();
        let mut request = Request::new(
            candidates
                .iter()
                .map(|input| PathBuf::from(&input.path))
                .collect(),
            Mode::Extract,
        );
        request.origin = Origin::Watch;
        request.cancel = cancel.clone();
        request.config = Arc::clone(&self.settings);
        // A missing-volume promotion visible to ordinary Watch discovery can
        // join peers anywhere in the current watched scope. Its saved local
        // scope still bounds recovery if the destination is outside it.
        let catalog_recovery = recovery.is_some()
            && candidates.iter().all(|candidate| {
                if !scope.contains(&candidate.path) || self.catalog.is_owned(&candidate.path) {
                    return false;
                }
                let (entry, promoted) = self
                    .journal
                    .state()
                    .observation_state(&watch_path_key(&candidate.path));
                promoted.is_some()
                    && entry.is_some_and(|entry| entry.status == "suspended_missing_volume")
            });
        let local_recovery = recovery.as_ref().filter(|_| !catalog_recovery);
        let nested_recovery = local_recovery.is_some_and(|recovery| {
            watch_path_key(&recovery.scope.root) != watch_path_key(&scope.root)
        });
        if !nested_recovery {
            request.output_root = root.output.clone();
        }
        request.max_depth = cli::depth(self.settings.recursive_extract);
        request.deep = root.deep;
        let passwords = self.passwords.snapshot();
        request.passwords = Arc::clone(&self.settings.user_passwords);
        request.password_snapshot = Some(Arc::clone(&passwords));
        request.password_scope = Some(password_scope.clone());
        if let Some(recovery) = local_recovery {
            request.discovery_scope = Some(recovery.scope.clone());
        } else {
            request.discovery_scope = Some(scope.clone());
            request.watch_catalog = Some(Arc::clone(&self.catalog));
        }
        let mut outputs = BTreeMap::new();
        for candidate in &candidates {
            request.checkpoints.extend(restore_checkpoints(
                self.journal.state(), &candidate.path, &mut outputs,
            )?);
            if let Some(entry) = self.journal.state().entry(&candidate.path) {
                if let Some(receipts) = entry.failure_payload.get("promoted_sources") {
                    let sources = Vec::<PromotedSource>::deserialize(receipts)?;
                    request.promoted_sources.extend(sources);
                }
            }
        }
        let engine = Arc::clone(&self.engine);
        let journal = Arc::clone(&self.journal);
        let hub = Arc::clone(&self.hub);
        let send_batch = batch.clone();
        let batch_id: Arc<str> = Arc::from(batch.as_str());
        let worker_batch = Arc::clone(&batch_id);
        let owners = candidates
            .iter()
            .map(|input| (watch_path_key(&input.path), input.path.clone()))
            .collect();
        let output_scopes = self.external.lock().unwrap().as_ref()
            .map(|external| Arc::clone(&external.scopes))
            .unwrap_or_else(|| Arc::from([scope.clone()]));
        let toast = self
            .toast
            .as_ref()
            .map(|toast| toast.register(Arc::clone(&batch_id), self.settings.cli.language));
        let worker_toast = toast.clone();
        let report_path = toast
            .as_ref()
            .and_then(|_| candidates.first())
            .map(|candidate| PathBuf::from(&candidate.path));
        let groups = Arc::new(Mutex::new(SourceGroups::default()));
        let worker_groups = Arc::clone(&groups);
        let claimed = Arc::new(Mutex::new(ClaimedSources::default()));
        let worker_claimed = Arc::clone(&claimed);
        let worker_cancel = cancel.clone();
        self.journal
            .log(json!({"event":"pipeline_request_started","owner":batch,
            "path":candidates.first().map(|entry| &entry.path),"count":candidates.len()}));
        let observer = Arc::new(WatchObserver {
            deep: root.deep,
            journal,
            owners,
            output_scopes,
            outputs: Mutex::new(ObservedOutputs::from(outputs)),
            batch: worker_batch,
            toast: worker_toast,
            hub: Arc::clone(&hub),
            groups: worker_groups,
            claimed: worker_claimed,
            promoted: Mutex::default(),
        });
        let request_handle = engine.submit(request, Arc::clone(&observer), move |result| {
            let cancelled = worker_cancel.cancelled();
            if let (Some(toast), Some(path)) = (&observer.toast, report_path) {
                let claimed = observer.claimed.lock().unwrap();
                let groups = observer.groups.lock().unwrap();
                let groups = &groups.roots;
                let outputs = observer.outputs.lock().unwrap();
                if result.is_err() {
                    let mut reported = HashSet::new();
                    for (source_key, source) in &observer.owners {
                        if claimed.finished.contains(source_key) { continue; }
                        let source = groups.get(source_key).map_or(Path::new(source), |group| group.path.as_path());
                        if reported.insert(key(source)) {
                            toast.record(source, &result, cancelled,
                                |path| completion_owner(path, &outputs.paths, &groups));
                        }
                    }
                } else {
                    toast.record(
                        path.as_path(),
                        &result,
                        cancelled,
                        |path| completion_owner(path, &outputs.paths, &groups),
                    );
                }
            }
            let promoted = std::mem::take(&mut *observer.promoted.lock().unwrap());
            let outputs = std::mem::take(&mut *observer.outputs.lock().unwrap()).paths;
            Completed {
                cancelled,
                result,
                promoted,
                outputs,
            }
        });
        // Like main's task completion callback, notify only after all owned
        // children have joined. A root panic must not make Watch block in join
        // while another child still needs its durable completion reply.
        let completion = BatchCompletion { hub, batch: Some(send_batch) };
        request_handle.on_ready(move || drop(completion));
        for candidate in &candidates {
            self.active_paths.insert(
                watch_path_key(&candidate.path),
                Arc::clone(&batch_id),
            );
        }
        self.active.insert(
            batch,
            Active {
                deep: root.deep,
                root: id,
                recovery,
                password_scope,
                passwords,
                inputs: candidates.into_iter().map(|candidate| (watch_path_key(&candidate.path), candidate)).collect(),
                quiet,
                dirty: HashSet::new(),
                cancel,
                groups,
                claimed,
                toast,
                request: request_handle,
            },
        );
        Ok(())
    }

    fn cancel_display_batch(&mut self, id: &str) -> io::Result<bool> {
        if matches!(id.as_bytes().first(), Some(b'8'..=b'9' | b'a'..=b'f')) {
            let requests = self
                .toast
                .as_ref()
                .map(|toast| toast.stop_group(id))
                .unwrap_or_default();
            // Keep each request's existing durable boundary. An arbitrarily
            // large display group must not become a single WAL record.
            let engine = Arc::clone(&self.engine);
            let journal = Arc::clone(&self.journal);
            let result = engine.run_stage("watch_cancel", Origin::Watch, || {
                let (cancellations, durable) = journal.defer_waits(|| requests.iter()
                    .filter_map(|request| self.prepare_cancel_batch(request)).collect::<Vec<_>>());
                if let Err(error) = durable {
                    journal.log(json!({"event":"watch_cancel_persistence_failed","error":error.to_string()}));
                }
                let stopped = !cancellations.is_empty();
                for cancel in cancellations { cancel.cancel(); }
                stopped
            });
            if let Err(error) = &result {
                journal.log(json!({"event":"watch_cancel_persistence_failed","error":error.to_string()}));
                for request in requests { if let Some(active) = self.active.get(request.as_ref()) { active.cancel.cancel(); } }
            }
            result
        } else {
            Ok(self.cancel_batch(id))
        }
    }

    fn cancel_batch(&mut self, batch: &str) -> bool {
        let Some(cancel) = self.prepare_cancel_batch(batch) else { return false; };
        cancel.cancel();
        true
    }

    fn prepare_cancel_batch(&mut self, batch: &str) -> Option<Cancellation> {
        let Some(active) = self.active.get(batch) else {
            return None;
        };
        if active.request.is_finished() || active.cancel.cancelled() {
            return None;
        }
        let mut claimed = active.claimed.lock().unwrap();
        claimed.cancelled = true;
        let siblings = claimed.candidates.iter()
            .filter(|(path, _)| !active.inputs.contains_key(*path))
            .filter_map(|(_, candidate)| candidate.as_ref());
        let mut interrupted = crate::watch_store::NativeWatchOperations::empty();
        for input in active.inputs.values().chain(siblings) {
            if claimed.finished.contains(&watch_path_key(&input.path))
                || NativePresence::at(&input.path).is_absent() {
                continue;
            }
            let id = watch_path_key(&input.path);
            if self.pending.get(&id).is_some_and(|pending| quiet::changed(input, &pending.candidate)) {
                continue;
            }
            interrupted.put_entry(Arc::new(observed_entry(
                input,
                "interrupted",
                self.journal.state().entry(&input.path).as_deref(),
            )));
            let id = watch_path_key(&input.path);
            if let Some(pending) = self.pending.get(&id) {
                if !quiet::changed(input, &pending.candidate) {
                    let pending = self.pending.remove(&id).unwrap();
                    self.due.remove(&(pending.due, id.clone()));
                    self.unpublished.remove(&id);
                }
            }
        }
        if let Err(error) = self.journal.commit(true, |_| Ok(interrupted)) {
            self.journal.log(json!({"event":"watch_cancel_persistence_failed","owner":batch,"error":error.to_string()}));
        }
        // Stop the workers even when the state volume failed the durable write.
        Some(active.cancel.clone())
    }

    fn abandon_completed(&mut self, batch: &str) {
        if let Some(active) = self.active.remove(batch) {
            // Its completion notification guarantees the join cannot depend
            // on another scheduler turn. Preserve all durable recovery intent.
            let _ = active.request.join();
        }
    }

    fn complete_roots(&mut self, roots: Vec<RootCompleted>) -> io::Result<()> {
        if roots.is_empty() { return Ok(()); }
        let engine = Arc::clone(&self.engine);
        let journal = Arc::clone(&self.journal);
        let waiting: Vec<_> = roots.iter().map(|root| Arc::clone(&root.reply)).collect();
        let result = engine.run_stage("watch_complete_state", Origin::Watch, || {
            let replies = roots.into_iter().filter_map(|root| {
                if !self.active.contains_key(&root.batch) {
                    root.reply.complete(Err(io::Error::other("Watch request already retired")));
                    return None;
                }
                let reply = super::cli::reporting::FailedReply(Arc::clone(&root.reply));
                let toast = self.active.get(&root.batch).and_then(|active| active.toast.clone());
                let id = root.id;
                let (result, tickets) = journal.prepare_waits(|| self.prepare_root(root));
                Some((reply, toast, id, result, tickets))
            }).collect::<Vec<_>>();
            let mut failure = None;
            for (reply, toast, id, result, tickets) in replies {
                let durable = journal.wait_prepared(tickets);
                let result = result.and_then(|outcome| durable.map(|()| outcome));
                match &result {
                    Ok(outcome) => { if let Some(toast) = toast { toast.root_finished(id, outcome); } }
                    Err(error) => { failure = Some(io::Error::new(error.kind(), error.to_string())); }
                }
                reply.0.complete(result);
            }
            failure.map_or(Ok(()), Err)
        });
        if let Err(error) = &result {
            for reply in waiting { reply.complete(Err(io::Error::new(error.kind(), error.to_string()))); }
        }
        result?
    }

    #[cfg(test)]
    fn complete_root(&mut self, root: RootCompleted) -> io::Result<()> {
        self.complete_roots(vec![root])
    }

    fn prepare_root(&mut self, root: RootCompleted) -> io::Result<Outcome> {
        let Some(active) = self.active.get_mut(&root.batch) else {
            return Err(io::Error::other("Watch request already retired"));
        };
        let members: HashSet<_> = root.groups.keys().cloned()
            .chain(std::iter::once(key(&root.path))).collect();
        let mut inputs = Vec::new();
        let mut dirty = HashSet::new();
        for member in &members {
            if active.dirty.remove(member) { dirty.insert(member.clone()); }
        }
        for member in &members {
            if let Some(input) = active.inputs.remove(member) { inputs.push(input); }
        }
        let quiet = members.iter().filter_map(|path| active.quiet.remove(path).map(|tracker| (path.clone(), tracker))).collect();
        let context = CompletionContext {
            deep: active.deep,
            root: active.root.clone(), recovery: active.recovery.clone(), password_scope: active.password_scope.clone(), passwords: Arc::clone(&active.passwords),
            inputs, quiet, dirty, claimed: Arc::clone(&active.claimed), groups: root.groups, toast: active.toast.clone(), task: Some(root.id),
        };
        self.apply_completion(&root.batch, context, root.completed).map(|(outcome, _)| outcome)
    }

    fn complete_requests(&mut self, batches: Vec<String>) -> io::Result<()> {
        if batches.is_empty() { return Ok(()); }
        let engine = Arc::clone(&self.engine);
        let journal = Arc::clone(&self.journal);
        // Hub publishes these only after request completion. Their join cannot
        // wait for a root reply, unlike arbitrary still-active requests.
        let result = engine.run_stage("watch_complete_state", Origin::Watch, || {
            let mut prepared = Vec::new();
            for batch in &batches {
                // main gathers every finished request independently. A failed
                // sibling must not suppress another request's projection.
                prepared.push(journal.prepare_waits(|| self.complete(batch)));
            }
            let mut result = Ok(());
            for (completion, tickets) in prepared {
                let durable = journal.wait_prepared(tickets);
                match completion.and_then(|finish| durable.map(|()| finish)) {
                    Ok(Some(finish)) => finish.publish(),
                    Ok(None) => {},
                    Err(error) => result = Err(error),
                }
            }
            result
        }).and_then(|result| result);
        if result.is_err() {
            for batch in &batches { self.abandon_completed(batch); }
        }
        result
    }

    fn complete(&mut self, batch: &str) -> io::Result<Option<super::toast::Finish>> {
        let Some(active) = self.active.remove(batch) else { return Ok(None); };
        let mut completed = active.request.join()
            .map_err(|_| io::Error::other("Watch extraction request failed"))?;
        completed.cancelled |= active.cancel.cancelled();
        let groups = std::mem::take(&mut *active.groups.lock().unwrap()).into_aliases();
        self.apply_completion(batch, CompletionContext {
            deep: active.deep,
            root: active.root, recovery: active.recovery, password_scope: active.password_scope, passwords: active.passwords,
            inputs: active.inputs.into_values().collect(), quiet: active.quiet, dirty: active.dirty, claimed: active.claimed, groups, toast: active.toast, task: None,
        }, completed).map(|(_, finish)| finish)
    }

    fn apply_completion(&mut self, batch: &str, mut active: CompletionContext, completed: Completed) -> io::Result<(Outcome, Option<super::toast::Finish>)> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_complete_state", Origin::Watch, || {
            consume_claimed_pending(
                &mut self.pending, &mut self.due, &mut self.unpublished,
                &active.groups, &active.claimed.lock().unwrap().candidates, &mut active.inputs, &mut active.quiet,
            );
            let mut quiet = std::mem::take(&mut active.quiet);
            let dirty = std::mem::take(&mut active.dirty);
            let root = active.root.clone();
            let recovery = active.recovery.clone();
            let claimed = Arc::clone(&active.claimed);
            let result = self.apply_completion_blocking(batch, active, completed, &mut quiet)?;
            // Publish the old generation first. An interrupted blocker then
            // suppresses only that generation, not a replacement during claim.
            for path in dirty {
                if !self.pending.contains_key(&path) {
                    let captured = claimed.lock().unwrap().candidates.get(&path).and_then(Option::as_ref).cloned();
                    let tracker = quiet.remove(&path);
                    let admission = if self.journal.state().entry(&path)
                        .is_some_and(|entry| entry.status == "suspended_missing_volume") {
                        CandidateAdmission::Retry
                    } else {
                        CandidateAdmission::Observe
                    };
                    self.observe_candidate_with_event(&root, path, admission, recovery.clone(), captured.as_ref(), tracker,
                        Some(&CandidateEvent::Business("pipeline_claim_released")))?;
                }
            }
            Ok(result)
        })?
    }

    fn apply_completion_blocking(&mut self, batch: &str, active: CompletionContext, mut completed: Completed, quiet: &mut HashMap<String, quiet::Activity>) -> io::Result<(Outcome, Option<super::toast::Finish>)> {
        let mut unfinished = HashSet::new();
        if completed.cancelled {
            let state = self.journal.state();
            for input in &active.inputs {
                let Some(record) = state.pending(&input.path) else {
                    continue;
                };
                if let Some(output) = record.active_outputs.values().find(|output| {
                    !record.committed_roots.contains(output)
                        && !NativePresence::at(output).is_absent()
                }) {
                    unfinished.insert(watch_path_key(&input.path));
                    self.journal
                        .log(json!({"event":"watch_cancel_output_pending","owner":batch,
                        "path":input.path,"output_dir":output}));
                };
            }
        }
        let groups = active.groups;
        let finish = active.toast.as_ref().filter(|_| active.task.is_none()).and_then(|toast| {
            toast.prepare_finish(
                &completed.result,
                completed.cancelled,
                !unfinished.is_empty(),
                |path| completion_owner(path, &completed.outputs, &groups),
            )
        });
        {
            let claimed = active.claimed.lock().unwrap();
            let remaining = self.active.get(batch).map(|active| active.groups.lock().unwrap());
            let mut claims = self.hub.claims.lock().unwrap();
            let mut release = |path: &str| {
                if remaining.as_ref().is_some_and(|groups| groups.members.contains_key(path)) { return; }
                if claims.get(path).is_some_and(|owner| owner.as_ref() == batch) {
                    claims.remove(path);
                }
            };
            for path in completion_claims(active.task, &groups, &claimed).chain(completed.promoted.keys()) { release(path); }
            for input in &active.inputs { release(&watch_path_key(&input.path)); }
            crate::collections::trim_map(&mut claims);
        }
        // Changes observed during ownership are the next generation, not
        // members of the completed request. Restore only their admission keys.
        {
            let claimed = active.claimed.lock().unwrap();
            for path in completion_claims(active.task, &groups, &claimed).chain(completed.promoted.keys()).cloned()
                .chain(active.inputs.iter().map(|candidate| watch_path_key(&candidate.path)))
            {
                if let Some(pending) = self.pending.get(&path) {
                    self.due.insert((pending.due, path), ());
                }
            }
        }
        for candidate in &active.inputs {
            let id = watch_path_key(&candidate.path);
            self.active_paths.remove(&id);
        }
        let outcome = match completed.result {
            Ok(outcome) => outcome,
            Err(error) if completed.cancelled => {
                self.journal.log(json!({"event":"pipeline_request_interrupted","owner":batch,"error":error.to_string()}));
                self.release_display_claims(batch, &groups);
                self.arm_idle_cleanup();
                return Ok((Outcome::default(), finish));
            }
            Err(error) => {
                let mut absent = crate::watch_store::NativeWatchOperations::empty();
                for candidate in &active.inputs {
                    let id = watch_path_key(&candidate.path);
                    if self.pending.contains_key(&id) {
                        continue;
                    }
                    if NativePresence::at(&candidate.path).is_absent() {
                        absent.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                            &candidate.path,
                            None,
                        ));
                        continue;
                    }
                    // main's pipeline_completion_error path re-admits ordinary
                    // request exceptions too (for example a transient sharing
                    // violation), unlike an extraction Outcome failure.
                    self.journal.log(json!({"event":"failed_terminal","path":candidate.path,
                        "owner":batch,"error":error.to_string()}));
                    self.observe_candidate_with_event(
                        &active.root, candidate.path.clone(), CandidateAdmission::ExplicitRetry, active.recovery.clone(),
                        None, quiet.remove(&id), Some(&CandidateEvent::Business("pipeline_completion_error")),
                    )?;
                }
                self.journal.commit(true, |_| Ok(absent))?;
                self.persist_candidates(BTreeMap::new(), true)?;
                self.release_display_claims(batch, &groups);
                self.arm_idle_cleanup();
                return Ok((Outcome::default(), finish));
            }
        };
        let input_failures = outcome.input_failures();
        let by_path = completion_archives(&outcome, &completed.outputs, &groups, &input_failures);
        for archive in &outcome.archives {
            if let Some(failure) = archive
                .failure
                .as_ref()
                .filter(|failure| failure.evidence.is_some())
            {
                // Emit once per logical archive, including carrier segments and
                // recursive children, rather than repeating it for every volume.
                self.journal.log_failure(
                    json!({"event":"archive_failure_evidence","path":archive.path,
                    "owner":batch,"depth":archive.depth,"offset":archive.offset}),
                    failure,
                );
            }
        }
        for cleanup in outcome
            .cleanup_results
            .iter()
            .filter(|cleanup| cleanup.status == crate::pipeline::CleanupStatus::Failed)
        {
            self.journal.log(
                json!({"event":"pipeline_cleanup_failed","path":cleanup.path,
                "owner":batch,"cleanup":cleanup}),
            );
        }
        for error in &outcome.errors {
            if error.kind == crate::pipeline::InputErrorKind::FilesystemScan {
                // Discovery diagnostics do not change extraction completion.
                // Preserve the diagnostic without turning an accepted archive
                // or a retryable blocker into a terminal Watch failure.
                self.journal.log(json!({"event":"filesystem_scan_failed",
                    "path":error.path,"owner":batch,"error":error.message}));
            }
        }
        let error_paths = completion_input_errors(&outcome.errors, &completed.outputs, &groups, &active.inputs);
        let mut operations = crate::watch_store::NativeWatchOperations::empty();
        let current_passwords = self.passwords.snapshot();
        let mut retry = Vec::new();
        let mut published = HashSet::new();
        for archive in outcome
            .archives
            .iter()
            .filter(|archive| promoted_retry(archive, &input_failures))
        {
            let input_failure = &input_failures[&crate::path_keys::path_key(&archive.path.to_string_lossy())];
            let failure = input_failure.failure().expect("promoted input has a retry cause");
            let id = key(&archive.path);
            let Some(candidate) = completed.promoted.remove(&id).flatten() else {
                continue;
            };
            if self.active_paths.contains_key(&id) {
                continue;
            }
            if self.hub.completed_families.lock().unwrap().covers(&archive.path, active.deep) {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(&candidate.path, None));
                continue;
            }
            let regroup = failure.kind == FailureKind::MissingVolume;
            if let Some(pending) = self.pending.get(&id) {
                if quiet::changed(&candidate, &pending.candidate) {
                    continue;
                }
                if !regroup {
                    let pending = self.pending.remove(&id).unwrap();
                    self.due.remove(&(pending.due, id.clone()));
                    self.unpublished.remove(&id);
                }
            }
            let group = SourceGroup {
                path: archive.path.clone(),
                name: archive
                    .path
                    .file_name()
                    .unwrap_or(archive.path.as_os_str())
                    .to_string_lossy()
                    .into_owned(),
                members: archive
                    .source_paths
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
                multipart: archive.source_paths.len() > 1,
            };
            let directory = archive.path.parent().unwrap_or(Path::new(""));
            // A promoted family now lives beside the admitted source. Seal
            // its new discovery boundary while retaining the password scope
            // inherited from that source.
            let recovery = Recovery {
                scope: NativeDiscoveryScope::new(directory.to_string_lossy().into_owned(), Some(0), Vec::new()),
                password_scope: active.password_scope.clone(),
            };
            let mut entry = make_entry(
                &candidate,
                &super::failure::message(failure, self.settings.cli.language),
                Some(input_failure),
                self.journal.state().entry(&candidate.path).as_deref(),
                &active.passwords,
                &self.user_password_signature,
                Some(&group),
                Some(&recovery),
                &active.password_scope,
            );
            let payload = &mut Arc::make_mut(&mut entry).failure_payload;
            payload.insert("details".into(), json!({"promoted_nested_input":true}));
            payload.insert("input_checkpoints".into(), serde_json::to_value(
                promoted_checkpoints(&outcome.checkpoints, &archive.source_paths))?);
            let route_root = &active.root;
            let (root, scope) = &self.roots[route_root];
            payload.insert("source_input_root".into(), json!(scope.root));
            if regroup {
                for path in &group.members {
                    if scope.contains(path) && !self.catalog.is_owned(path) {
                        self.scan_options(root.deep)?.catalog_update(
                            &self.catalog, scope, Some(path),
                        )?;
                    }
                }
            }
            let payload = &entry.failure_payload;
            let password_updated = payload
                .get("password_signature")
                .and_then(Value::as_str)
                .is_some_and(|previous| previous != password_source_signature(&self.user_password_signature, &current_passwords.scope_signature(&recovery.password_scope)));
            let pending = regroup.then(|| self.pending.get_mut(&id)).flatten();
            let handed_off = pending.is_some();
            handoff_promoted_blocker(&mut entry, route_root, root,
                recovery, pending);
            if handed_off {
                self.unpublished.insert(id.clone());
                operations.put_entry(entry);
            } else {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                    &candidate.path,
                    Some(entry),
                ));
            }
            if (regroup && !self.pending.contains_key(&id)) || password_updated {
                retry.push((candidate.path.clone(), if password_updated {
                    CandidateAdmission::PasswordRetry
                } else { CandidateAdmission::Retry }));
            }
        }
        let output_containers = completion_output_containers(&outcome);
        let canonical_inputs: HashMap<_, _> = active.inputs.iter()
            .map(|candidate| (watch_path_key(&candidate.path), candidate.clone())).collect();
        let mut projected_groups = HashSet::new();
        let mut reported_discovery = HashSet::new();
        for candidate in active.inputs {
            let id = watch_path_key(&candidate.path);
            if self.pending.contains_key(&id)

                || unfinished.contains(&id)
            {
                continue;
            }
            let group = groups.get(&id);
            let canonical = group.map_or_else(|| candidate.path.clone(), |group| {
                group.path.to_string_lossy().into_owned()
            });
            let canonical_id = watch_path_key(&canonical);
            let archives = by_path.get(&canonical_id).or_else(|| by_path.get(&id));
            let input_error = error_paths.get(&canonical_id).or_else(|| error_paths.get(&id));
            let discovery_failure = input_error.and_then(|error| error.failure.as_deref());
            let failed_archive = (input_error.is_none() || discovery_failure.is_some())
                .then(|| archives.and_then(|items| completion_failed_archive(items, &input_failures))).flatten();
            let input_failure = failed_archive.and_then(|archive| input_failures
                .get(&crate::path_keys::path_key(&archive.path.to_string_lossy())));
            let failure = discovery_failure.or_else(|| input_failure.and_then(InputFailure::failure));
            let failure_message = failure.map(|failure| super::failure::message(failure, self.settings.cli.language));
            let error = failure_message.as_deref()
                .or_else(|| input_error.map(|error| error.message.as_str()));
            let retryable = input_failure.is_some_and(InputFailure::retryable);
            // A multipart request has one logical result and one blocker.
            // Physical sibling generations only need their pending WAL retired.
            let candidate = if completed.cancelled {
                candidate
            } else {
                if id != canonical_id {
                    operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                        &candidate.path, None,
                    ));
                }
                if self.pending.contains_key(&canonical_id)
                    || !projected_groups.insert(canonical_id.clone())
                {
                    continue;
                }
                if id == canonical_id {
                    candidate
                } else if let Some(head) = canonical_inputs.get(&canonical_id) {
                    head.clone()
                } else if error.is_none() {
                    // Successful source cleanup may already have removed the
                    // head. No blocker observation is needed for a success.
                    let mut head = candidate;
                    head.path = canonical.clone();
                    head
                } else {
                    let Ok(Some(head)) = watch_candidate_for_path(Path::new(&canonical), None) else {
                        continue;
                    };
                    head
                }
            };
            let stale = error.is_some()
                // A promoted terminal child may outlive its successfully
                // consumed outer source. That is still this owner's failure.
                && !failed_archive.is_some_and(|archive| archive.depth > 1)
                && (discovery_failure.is_none() || retryable)
                && (NativePresence::at(&canonical).is_absent()
                    || (!retryable
                        && group.is_some_and(|group| {
                            group.multipart
                                && group.members.iter().any(|path| {
                                    match filesystem::watch_file_is_ready(path) {
                                        Ok(ready) => !ready,
                                        Err(error) => error.kind() == io::ErrorKind::NotFound,
                                    }
                                })
                        })));
            if stale {
                // A sibling can trigger discovery while the selected head is
                // being renamed or consumed by a different request. Its old
                // name no longer represents a live extraction failure.
                let entry = (canonical != candidate.path)
                    .then(|| self.journal.state().entry(&candidate.path))
                    .flatten();
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                    &candidate.path,
                    entry,
                ));
                continue;
            }
            if (retryable || discovery_failure.is_some_and(|failure| failure.kind == FailureKind::MissingVolume || failure.is_password_retry()))
                && self.hub.completed_families.lock().unwrap().covers(Path::new(&canonical), active.deep) {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(&candidate.path, None));
                continue;
            }
            let record = if completed.cancelled {
                // Only the cancelled generation is retired. A generation
                // queued while the batch was in flight is left in the WAL.
                self.journal
                    .state()
                    .entry(&candidate.path)
                    .filter(|entry| entry.status == "interrupted")
            } else {
                error.map(|error| {
                    let record_error = if discovery_failure.is_some() && retryable {
                        input_failure.and_then(InputFailure::failure)
                            .map(|failure| super::failure::message(failure, self.settings.cli.language))
                    } else {
                        None
                    };
                    let mut entry = make_entry(
                        &candidate,
                        record_error.as_deref().unwrap_or(error),
                        input_failure,
                        self.journal.state().entry(&candidate.path).as_deref(),
                        &active.passwords,
                        &self.user_password_signature,
                        group.map(Arc::as_ref),
                        active.recovery.as_deref(),
                        &active.password_scope,
                    );
                    Arc::make_mut(&mut entry).failure_payload.insert("input_checkpoints".into(),
                        serde_json::to_value(promoted_checkpoints(&outcome.checkpoints,
                            &[PathBuf::from(&canonical)])).expect("serializable input checkpoints"));
                    if active.recovery.is_some() {
                        if let Some((root, _)) = self.roots.get(&active.root) {
                            Arc::make_mut(&mut entry)
                                .failure_payload
                                .insert("source_input_root".into(), json!(root.path));
                        }
                    }
                    entry
                })
            };
            if let Some(record) = &record {
                let directory = &active.password_scope;
                if record
                    .failure_payload
                    .get("password_signature")
                    .and_then(Value::as_str)
                    .is_some_and(|before| before != password_source_signature(&self.user_password_signature, &current_passwords.scope_signature(directory)))
                {
                    retry.push((candidate.path.clone(), CandidateAdmission::PasswordRetry));
                }
            }
            let event = if completed.cancelled {
                "pipeline_request_interrupted"
            } else if discovery_failure.is_some() {
                "failed_terminal"
            } else if let Some(record) = &record {
                record.status.as_str()
            } else if archives.is_some() {
                "done"
            } else {
                "no_tasks_found"
            };
            if published.insert(watch_path_key(&canonical)) {
                let outputs = completion_output_dirs(archives.into_iter().flatten()
                    .filter_map(|item| item.output.as_deref()), &output_containers);
                let mut event = json!({"event":event,"path":canonical,"owner":batch,
                    "error":error,"error_kind":failure.map(|failure| failure.kind),
                    "output_dirs":outputs,"retire_group":true});
                if let (Some(input_error), Some(failure)) = (input_error, discovery_failure) {
                    reported_discovery.insert(input_error.path.as_path());
                    event["failures"] = json!([super::failure::report::Report::from_failure(
                        failure, self.settings.cli.language,
                    )]);
                }
                self.journal.log(event);
            }
            operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                &candidate.path,
                record.filter(|entry| entry.status != "failed_terminal"),
            ));
        }
        if !completed.cancelled {
            for error in &outcome.errors {
                let Some(failure) = error.failure.as_deref() else { continue; };
                // Top-level discovery can fail on a peer that was never
                // admitted as a task. Its request still has a terminal failure.
                if !reported_discovery.contains(error.path.as_path()) {
                    self.journal.log(json!({
                        "event":"failed_terminal","path":error.path,"owner":batch,
                        "error":super::failure::message(failure, self.settings.cli.language),
                        "error_kind":failure.kind,"retire_group":true,
                        "failures":[super::failure::report::Report::from_failure(failure, self.settings.cli.language)],
                    }));
                }
            }
        }
        self.journal.commit(true, |state| {
            for archive in outcome
                .archives
                .iter()
                .filter(|archive| archive.failure.is_none())
            {
                for path in &archive.source_paths {
                    let path = path.to_string_lossy();
                    if state.promoted_source(&path).is_some()
                        && NativePresence::at(&path).is_absent()
                    {
                        operations.retire_promoted(watch_path_key(&path));
                    }
                }
            }
            Ok(operations)
        })?;
        self.release_display_claims(batch, &groups);
        for (path, admission) in retry {
            if let Some((root, recovery)) = self.journal.state().entry(&path)
                .and_then(|entry| self.blocker_route(&entry))
            {
                let tracker = quiet.remove(&watch_path_key(&path));
                self.observe_candidate_with_event(&root, path, admission, recovery, None, tracker,
                    Some(&CandidateEvent::Business(if admission == CandidateAdmission::PasswordRetry {
                        "password_retry"
                    } else { "volume_changed" })))?;
            }
        }
        self.persist_candidates(BTreeMap::new(), false)?;
        self.arm_idle_cleanup();
        Ok((outcome, finish))
    }

    fn arm_idle_cleanup(&mut self) {
        if self.active.is_empty() && self.pending.is_empty() && !windows::foreground_active() {
            let idle = self.settings.watch.runtime_cache_cleanup_idle_seconds;
            // main's +infinity deadline never expires. Do not pass it to
            // Duration conversion, where an invalid duration becomes zero.
            self.cache_deadline = idle.is_finite().then(|| quiet::after(Instant::now(), idle));
        }
    }

    fn release_display_claims(&self, batch: &str, groups: &HashMap<String, Arc<SourceGroup>>) {
        if !groups.is_empty() {
            let paths = groups
                .values()
                .map(|group| &group.path)
                .collect::<HashSet<_>>();
            self.journal
                .log(json!({"event":"pipeline_sources_released","owner":batch,"paths":paths}));
        }
    }
}

// Reuse the output ownership captured by the observer. Descendants can finish
// after their source was promoted or removed, so filesystem discovery cannot
// recover their request association at completion time.
fn output_owner<'a>(outputs: &'a BTreeMap<String, String>, path: &str) -> Option<&'a str> {
    let mut boundary = path.len();
    loop {
        if let Some(owner) = outputs.get(&path[..boundary]) {
            return Some(owner);
        }
        boundary = path[..boundary].rfind('\\')?;
    }
}

fn promoted_checkpoints<'a>(
    checkpoints: &'a [crate::pipeline::InputCheckpoint], sources: &[PathBuf],
) -> Vec<&'a crate::pipeline::InputCheckpoint> {
    let sources = sources.iter().map(|source| key(source)).collect::<HashSet<_>>();
    let direct = |checkpoint: &crate::pipeline::InputCheckpoint| {
        checkpoint.source_paths().any(|source| sources.contains(&key(source)))
    };
    let roots = checkpoints.iter().filter(|checkpoint| checkpoint.has_output() && direct(checkpoint))
        .map(|checkpoint| (key(checkpoint.output()), String::new())).collect::<BTreeMap<_, _>>();
    // Descendant receipts still refer to inputs inside the retained segment,
    // not to its moved carrier. Hand off that subtree before retiring its old
    // owner, so a retry cannot duplicate accepted nested recovery output.
    checkpoints.iter().filter(|checkpoint| direct(checkpoint)
        || checkpoint.source_paths().any(|source| output_owner(&roots, &key(source)).is_some()))
        .collect()
}

fn promoted_retry(archive: &ArchiveResult, failures: &HashMap<String, InputFailure<'_>>) -> bool {
    archive.promoted && !archive.partial && failures
        .get(&crate::path_keys::path_key(&archive.path.to_string_lossy()))
        .is_some_and(InputFailure::retryable)
}

// Completion and persisted retry admission share the Watch boundary. Keep
// nested recovery scopes even when their source is an owned output subtree.
fn route_blocker(
    entry: &crate::watch_store::EntryRecord,
    roots: &BTreeMap<String, (Root, NativeDiscoveryScope)>,
    is_owned: impl Fn(&str) -> bool,
) -> Option<(String, Option<Arc<Recovery>>)> {
    let payload = &entry.failure_payload;
    if let Some(root) = payload.get("source_input_root").and_then(Value::as_str) {
        let root = watch_path_key(root);
        let (_, watched_scope) = roots.get(&root)?;
        if let Some(scope) = payload.get("discovery_scope").and_then(Value::as_object) {
            let password_scope = payload
                .get("password_scope_dir")
                .and_then(Value::as_str)
                .unwrap_or("");
            let recovery = Recovery::from_record(scope, password_scope)?;
            if recovery.scope.contains(&entry.path)
                && (watch_path_key(&recovery.scope.root) != root
                    || !watched_scope.contains(&entry.path)
                    || is_owned(&entry.path)
                    || payload.get("details").is_some_and(|details| {
                        details["promoted_nested_input"].as_bool() == Some(true)
                    }))
            {
                return Some((root, Some(Arc::new(recovery))));
            }
        }
    }
    roots
        .iter()
        .find_map(|(id, (_, scope))| scope.contains(&entry.path).then(|| (id.clone(), None)))
}

fn completion_owner(
    path: &Path,
    outputs: &BTreeMap<String, String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
) -> Option<String> {
    let path = key(path);
    if let Some(group) = groups.get(&path) {
        return Some(key(&group.path));
    }
    let owner = watch_path_key(output_owner(outputs, &path)?);
    Some(groups.get(&owner).map(|group| key(&group.path)).unwrap_or(owner))
}

fn completion_input_errors<'a>(
    errors: &'a [crate::pipeline::InputError],
    outputs: &BTreeMap<String, String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
    inputs: &[WatchCandidateRow],
) -> HashMap<String, &'a crate::pipeline::InputError> {
    use crate::scan::catalog::catalog_stem;
    use crate::pipeline::InputErrorKind;
    let mut paths = HashMap::new();
    for error in errors {
        if matches!(error.kind, InputErrorKind::Cleanup | InputErrorKind::FilesystemScan) {
            continue;
        }
        let path = key(&error.path);
        let owner = completion_owner(&error.path, outputs, groups).or_else(|| {
            if error.kind != InputErrorKind::EmbeddedDiscovery
                || inputs.iter().any(|input| watch_path_key(&input.path) == path)
            {
                return None;
            }
            // A residual peer can fail discovery for its catalog bucket
            // without having been explicitly admitted as a source.
            let stem = catalog_stem(&path);
            inputs.iter().find(|input| catalog_stem(&input.path) == stem)
                .map(|input| watch_path_key(&input.path))
        });
        paths.entry(path).or_insert(error);
        if let Some(owner) = owner {
            paths.entry(owner).or_insert(error);
        }
    }
    paths
}

// Receipts retain the physical carrier container even when only one segment
// survived. A common ancestor of logical outputs alone would open that segment.
pub(super) fn completion_output_containers(outcome: &Outcome) -> HashMap<&Path, &Path> {
    outcome.checkpoints.iter()
        .filter_map(|checkpoint| checkpoint.container().map(|container| (checkpoint.output(), container)))
        .collect()
}

fn completion_output_dirs<'a>(
    outputs: impl IntoIterator<Item = &'a Path>, containers: &HashMap<&Path, &Path>,
) -> Vec<PathBuf> {
    crate::pipeline::common_ancestor(outputs.into_iter()
        .map(|output| containers.get(output).copied().unwrap_or(output)))
        .into_iter().collect()
}

fn completion_archives<'a>(
    outcome: &'a Outcome,
    outputs: &BTreeMap<String, String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
    failures: &HashMap<String, InputFailure<'_>>,
) -> HashMap<String, Vec<&'a ArchiveResult>> {
    let mut by_path: HashMap<String, Vec<&ArchiveResult>> = HashMap::new();
    for archive in &outcome.archives {
        for path in archive.source_paths.iter().chain(std::iter::once(&archive.path)) {
            by_path.entry(key(path)).or_default().push(archive);
        }
        if archive.depth > 1 && !archive.partial && archive.failure.is_some() && !promoted_retry(archive, failures)
        {
            // Promoted retry blockers get their own durable entry below. All
            // other nested failures belong to the original top-level card.
            if let Some(owner) = output_owner(outputs, &key(&archive.path)) {
                let owner = watch_path_key(owner);
                let owner = groups.get(&owner).map(|group| key(&group.path)).unwrap_or(owner);
                by_path.entry(owner).or_default().push(archive);
            }
        }
    }
    by_path
}

fn completion_failed_archive<'a>(
    archives: &[&'a ArchiveResult], inputs: &HashMap<String, InputFailure<'_>>,
) -> Option<&'a ArchiveResult> {
    let failures = || archives.iter().copied()
        .filter(|archive| !archive.partial && archive.failure.is_some());
    // Independent terminal children win, while all segments of a physical
    // carrier share its password/missing-volume disposition.
    failures().find(|archive| inputs
        .get(&crate::path_keys::path_key(&archive.path.to_string_lossy()))
        .is_some_and(|input| !input.retryable()))
        .or_else(|| failures().next())
}

// Main fixes the request password directory before discovery can replace a
// tail-volume candidate with the family's head. A saved retry keeps that scope.
fn candidate_password_scope(
    state: &crate::watch_store::NativeWatchState, path: &str, recovery: Option<&Recovery>,
) -> PathBuf {
    if let Some(recovery) = recovery { return recovery.password_dir(Path::new(path)).to_owned(); }
    let entry = state.entry(path);
    let scope = if let Some(entry) = entry.as_ref().filter(|entry|
        matches!(entry.status.as_str(), "failed_password" | "suspended_missing_volume")) {
        entry.failure_payload.get("password_scope_dir").and_then(Value::as_str)
            .filter(|scope| !scope.is_empty()).map(PathBuf::from)
    } else {
        state.pending(path).filter(|pending| !pending.password_scope_dir.is_empty())
            .map(|pending| PathBuf::from(&pending.password_scope_dir))
    };
    scope.unwrap_or_else(|| Path::new(path).parent().unwrap_or(Path::new("")).to_owned())
}

fn make_entry(
    candidate: &WatchCandidateRow,
    error: &str,
    failure: Option<&InputFailure<'_>>,
    previous: Option<&crate::watch_store::EntryRecord>,
    passwords: &crate::core::passwords::PasswordSnapshot,
    user_signature: &str,
    group: Option<&SourceGroup>,
    recovery: Option<&Recovery>,
    password_scope: &Path,
) -> Arc<crate::watch_store::EntryRecord> {
    let kind = failure.and_then(InputFailure::failure).map(|failure| failure.kind);
    let password = failure.is_some_and(|input| input.failed && input.password.is_some());
    let missing = failure.is_some_and(|input| input.failed && input.missing.is_some());
    let status = if missing { "suspended_missing_volume" }
        else if password { "failed_password" } else { "failed_terminal" };
    let mut blockers = Vec::new();
    if missing { blockers.push("missing_volume"); }
    if password { blockers.push("password"); }
    let mut payload = json!({"blockers":blockers});
    if let Some(group) = group {
        payload["source_group"] = json!(group);
    }
    if let Some(recovery) = recovery {
        payload["discovery_scope"] = Value::Object(scope_record(&recovery.scope));
    }
    payload["password_scope_dir"] = json!(password_scope);
    if password {
        payload["password_signature"] = json!(password_source_signature(user_signature, &passwords.scope_signature(password_scope)));
    }
    let kind = serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut entry = observed_entry(candidate, status, previous);
    entry.last_error = error.to_owned();
    entry.failure_kind = kind;
    entry.failure_stage = "extraction".to_owned();
    entry.failure_payload = payload.as_object().unwrap().clone();
    Arc::new(entry)
}

fn observed_entry(
    candidate: &WatchCandidateRow,
    status: &str,
    previous: Option<&crate::watch_store::EntryRecord>,
) -> crate::watch_store::EntryRecord {
    crate::watch_store::EntryRecord {
        path: candidate.path.clone(),
        size: candidate.size.min(i64::MAX as u64) as i64,
        mtime: candidate.mtime,
        file_id: candidate.observation.file_id.clone(),
        change_usn: candidate.observation.change_usn,
        status: status.to_owned(),
        last_error: String::new(),
        attempt_count: previous.map_or(1, |record| record.attempt_count.saturating_add(1)),
        failure_kind: String::new(),
        failure_stage: String::new(),
        failure_payload: serde_json::Map::new(),
        last_attempt_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
    }
}

fn entry_changed(entry: &crate::watch_store::EntryRecord, candidate: &WatchCandidateRow) -> bool {
    quiet::content_changed(
        entry.size.max(0) as u64,
        entry.mtime,
        &entry.file_id,
        entry.change_usn,
        candidate,
    )
}

#[derive(Default)]
struct ObservedOutputs {
    paths: BTreeMap<String, String>,
    owners: HashMap<String, HashSet<String>>,
}

impl From<BTreeMap<String, String>> for ObservedOutputs {
    fn from(paths: BTreeMap<String, String>) -> Self {
        let mut outputs = Self::default();
        for (path, owner) in paths { outputs.insert(path, owner); }
        outputs
    }
}

impl ObservedOutputs {
    fn insert(&mut self, path: String, owner: String) {
        if let Some(previous) = self.paths.insert(path.clone(), owner.clone()) {
            let previous = watch_path_key(&previous);
            if let Some(paths) = self.owners.get_mut(&previous) {
                paths.remove(&path);
                if paths.is_empty() { self.owners.remove(&previous); }
            }
        }
        self.owners.entry(watch_path_key(&owner)).or_default().insert(path);
    }

    fn take_owners(&mut self, owners: &HashSet<String>) -> BTreeMap<String, String> {
        let mut outputs = BTreeMap::new();
        for owner in owners {
            for path in self.owners.remove(owner).into_iter().flatten() {
                if let Some(owner) = self.paths.remove(&path) { outputs.insert(path, owner); }
            }
        }
        outputs
    }
}

struct WatchObserver {
    deep: bool,
    journal: Arc<journal::Journal>,
    owners: HashMap<String, String>,
    output_scopes: Arc<[NativeDiscoveryScope]>,
    outputs: Mutex<ObservedOutputs>,
    batch: Arc<str>,
    toast: Option<super::toast::Activity>,
    hub: Arc<Hub>,
    groups: Arc<Mutex<SourceGroups>>,
    claimed: Arc<Mutex<ClaimedSources>>,
    promoted: Mutex<HashMap<String, Option<WatchCandidateRow>>>,
}

impl WatchObserver {
    fn owner<'a>(&'a self, archive: &'a ArchiveResult) -> Option<String> {
        std::iter::once(&archive.path)
            .chain(archive.source_paths.iter())
            .find_map(|path| self.owners.get(&key(path)).cloned())
            .or_else(|| self.owner_for_path(&archive.path))
    }

    fn owner_for_path(&self, path: &Path) -> Option<String> {
        output_owner(&self.outputs.lock().unwrap().paths, &key(path)).map(str::to_owned)
    }
}

impl Observer for WatchObserver {
    fn roots_planned<'a>(&self, paths: impl Iterator<Item = &'a str>) {
        self.groups.lock().unwrap().planned.extend(paths.map(watch_path_key));
    }

    async fn root_finished(&self, id: crate::pipeline::TaskId, path: &Path, outcome: Outcome) -> io::Result<Outcome> {
        // One admitted tail can discover several independent heads. Its WAL
        // owner and outputs must retain their aggregate until request finish.
        if !self.owners.contains_key(&key(path)) { return Ok(outcome); }
        // Move only this logical owner's state. A shared member stays claimed
        // until its final consumer settles; another admitted root never moves.
        let (groups, outputs, promoted) = {
        let mut claimed = self.claimed.lock().unwrap();
        let groups = self.groups.lock().unwrap().take(&key(path));
        let members: HashSet<_> = groups.keys().cloned().chain(std::iter::once(key(path))).collect();
        claimed.finished.extend(members.iter().cloned());
        drop(claimed);
        let mut shared_outputs = self.outputs.lock().unwrap();
        let outputs = shared_outputs.take_owners(&members);
        drop(shared_outputs);
        let mut shared_promoted = self.promoted.lock().unwrap();
        let mut promoted = HashMap::new();
        for archive in outcome.archives.iter().filter(|archive| archive.promoted) {
            for path in archive.source_paths.iter().chain(std::iter::once(&archive.path)) {
                let key = key(path);
                if let Some(candidate) = shared_promoted.remove(&key) { promoted.insert(key, candidate); }
            }
        }
        drop(shared_promoted);
        (groups, outputs, promoted)
        };
        let reply = Arc::new(super::cli::reporting::Reply::default());
        self.hub.root_completed(RootCompleted {
            reply: Arc::clone(&reply), batch: self.batch.to_string(), id, path: path.to_owned(), groups,
            completed: Completed { cancelled: false, result: Ok(outcome), promoted, outputs },
        });
        let outcome = reply.wait().await?;
        if let Some(toast) = &self.toast {
            let mut completion = RootReportCompletion { activity: toast.clone(), id, failed: true };
            // Match main's broker-backed failure report: synchronous report
            // writes use the shared stage pool, not one thread per batch.
            if toast.needs_root_report(id) {
                crate::pipeline::stage("watch_failure_report", &Cancellation::new()).await?;
                toast.record_root(id, path, &outcome);
            }
            completion.failed = false;
        }
        Ok(Outcome::default())
    }

    fn worker_updates(&self) -> crate::pipeline::WorkerUpdates {
        if self.toast.is_some() {
            crate::pipeline::WorkerUpdates::All
        } else {
            crate::pipeline::WorkerUpdates::None
        }
    }

    fn promoted_source(&self, path: &str) -> Option<PromotedSource> {
        self.journal
            .state()
            .promoted_source(path)
            .map(|receipt| (*receipt).clone())
    }

    fn completed_sources(&self, generations: &SourceGenerations) -> io::Result<Option<PathBuf>> {
        Ok(self.hub.completed_families.lock().unwrap().output(generations, self.deep))
    }

    fn sources_processed(
        &self,
        archives: &[ArchiveResult],
        generations: &SourceGenerations,
        output: Option<&Path>,
    ) -> io::Result<()> {
        let Some(processed) = archives
            .iter()
            .flat_map(|archive| &archive.source_paths)
            .map(|source| {
                let path = key(source);
                generations
                    .get(&path)
                    .map(|generation| (path, generation.clone()))
            })
            .collect::<Option<SourceGenerations>>() else {
                // A metadata read failure must not turn a subset into a
                // completed physical family. Main has no version in this case.
                return Ok(());
            };
        // main only installs source_generation for top-level multi-source Watch jobs.
        if processed.len() < 2 { return Ok(()); }
        if let Some(output) = output {
            self.hub.completed_families.lock().unwrap().remember(processed, self.deep, output);
        }
        Ok(())
    }

    fn before_promotion(
        &self,
        archive: &ArchiveResult,
        moves: &[(PathBuf, PathBuf)],
    ) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Err(io::Error::other("Promoted input has no Watch owner"));
        };
        let sources = moves
            .iter()
            .map(|(source, _)| source.to_string_lossy().into_owned())
            .collect();
        let destinations = moves
            .iter()
            .map(|(_, target)| target.to_string_lossy().into_owned())
            .collect();
        self.journal.commit(true, |state| {
            state
                .promotion_operation(&owner, destinations, sources)
                .ok_or_else(|| io::Error::other("Promoted input owner was retired"))
        })?;
        let mut promoted = self.promoted.lock().unwrap();
        let mut claims = self.hub.claims.lock().unwrap();
        for (_, target) in moves {
            let id = key(target);
            promoted.entry(id.clone()).or_insert(None);
            claims.insert(id, Arc::clone(&self.batch));
        }
        Ok(())
    }

    fn after_promotion(
        &self,
        archive: &ArchiveResult,
        moves: &[(PathBuf, PathBuf)],
        success: bool,
        receipts: &[PromotedSource],
    ) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Ok(());
        };
        if !receipts.is_empty() {
            // Publish before releasing destination leases. Another request
            // can adopt the newly visible family before this batch completes.
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            for receipt in receipts {
                operations.put_promoted(receipt.clone());
            }
            self.journal.commit(true, |_| Ok(operations))?;
        }
        for (_, target) in moves {
            let id = key(target);
            self.outputs
                .lock()
                .unwrap()
                .insert(id.clone(), owner.clone());
            if success {
                if let Ok(Some(candidate)) = watch_candidate_for_path(target, None) {
                    self.promoted.lock().unwrap().insert(id, Some(candidate));
                }
            }
        }
        Ok(())
    }

    fn claim_sources(&self, path: &Path, members: &[String], depth: usize) -> io::Result<()> {
        if depth != 1 {
            return Ok(());
        }
        let mut members = members.to_vec();
        let main = path.to_string_lossy();
        if !members.iter().any(|member| member == &main) {
            members.push(main.into_owned());
        }
        let group = Arc::new(SourceGroup {
            path: path.to_owned(),
            name: path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned(),
            multipart: members.len() > 1,
            members,
        });
        {
            let mut claimed = self.claimed.lock().unwrap();
            // Seal the original generations, never resample on cancellation.
            claimed.capture(&group.members)?;
            let mut aliases = self.groups.lock().unwrap();
            aliases.insert(Arc::clone(&group));
            let mut claims = self.hub.claims.lock().unwrap();
            for member in &group.members {
                let key = watch_path_key(member);
                claims.insert(key, Arc::clone(&self.batch));
            }
        }
        self.hub.update(|signals| {
            signals.claimed.extend(group.members.iter().map(|path| watch_path_key(path)));
        });
        self.journal.log(
            json!({"event":"pipeline_sources_claimed","path":path,"owner":self.batch,
            "processing":true,"groups":[group]}),
        );
        Ok(())
    }

    fn notify(&self, event: Event) {
        if let Some(toast) = &self.toast {
            toast.event(event);
        }
    }

    fn register_output(&self, archive: &ArchiveResult, path: &Path) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Err(io::Error::other("Watch output has no durable input owner"));
        };
        let output = path.to_string_lossy().into_owned();
        let task = archive.path.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            state
                .output_operation(&owner, task, output, None, Some(&self.output_scopes))?
                .ok_or_else(|| io::Error::other("Watch input owner was retired before output"))
        })?;
        self.outputs.lock().unwrap().insert(key(path), owner);
        Ok(())
    }

    fn reuse_output(&self, archive: &ArchiveResult, path: &Path) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Err(io::Error::other("Watch output has no durable input owner"));
        };
        // The retained carrier already owns this child namespace. The existing
        // start operation republishes its identity without exclusive mkdir.
        self.journal.commit(true, |state| {
            state.output_operation(&owner, archive.path.to_string_lossy().into_owned(),
                path.to_string_lossy().into_owned(), None, None)?
                .ok_or_else(|| io::Error::other("Watch input owner was retired before output"))
        })?;
        self.outputs.lock().unwrap().insert(key(path), owner);
        Ok(())
    }

    fn before_flatten(&self, root: &Path, work: &Path, leaf: &Path) -> io::Result<()> {
        let owner = self.owner_for_path(root).unwrap_or_default();
        prepare_flatten(&self.journal, &owner, root, work, leaf)?;
        if !owner.is_empty() {
            self.outputs.lock().unwrap().insert(key(work), owner);
        }
        Ok(())
    }

    fn after_flatten(&self, _id: crate::pipeline::TaskId, _old: &Path, output: &Path) -> io::Result<()> {
        finish_flatten(&self.journal, &output.to_string_lossy())
    }

    fn after_output(&self, archive: &ArchiveResult) -> io::Result<()> {
        let Some(output) = &archive.output else {
            return Ok(());
        };
        let Some(owner) = self.owner(archive) else {
            return Ok(());
        };
        let output = output.to_string_lossy().into_owned();
        finish_flatten(&self.journal, &output)?;
        let task = archive.path.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            Ok(state
                .output_operation(
                    &owner,
                    task,
                    output,
                    Some(archive.failure.is_none() || archive.partial),
                    None,
                )?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty))
        })
    }

    fn discard_output(&self, archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Ok(());
        };
        let task = archive.path.to_string_lossy().into_owned();
        let output = output.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            Ok(state.output_operation(&owner, task, output, Some(false), None)?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty))
        })
    }
}

fn prepare_flatten(
    journal: &journal::Journal,
    owner: &str,
    root: &Path,
    work: &Path,
    leaf: &Path,
) -> io::Result<()> {
    journal.commit(true, |state| {
        let old = output_identity(&root.to_string_lossy())?;
        let new = output_identity(&leaf.to_string_lossy())?;
        let root_paths = crate::path_keys::output_path_aliases(root)?;
        let work_paths = crate::path_keys::output_path_aliases(work)?;
        let mut values = vec![
            json!({"op":"runtime","key":format!("flatten|{}",key(root)),
                "value":{"owner":owner,"root":root,"work":work,"leaf":leaf,"old_identity":old,"new_identity":new,
                    "root_paths":root_paths,"work_paths":work_paths}}),
        ];
        if !owner.is_empty() {
            values.push(json!({"op":"checkpoint_output","owner":owner,"output":root}));
        }
        let mut operations = state.decode_operations(&values)?;
        operations.extend(crate::watch_store::NativeWatchOperations::owned_outputs(
            &root_paths, &[&old, &new],
        ));
        operations.extend(crate::watch_store::NativeWatchOperations::owned_outputs(
            &work_paths, &[&old],
        ));
        Ok(operations)
    })
}

fn finish_flatten(journal: &journal::Journal, root: &str) -> io::Result<()> {
    journal.commit(true, |state| finish_flatten_operations(state, root))
}

fn recover_finish_flatten(journal: &journal::Journal, root: &str) -> io::Result<()> {
    journal.commit(true, |state| {
        match finish_flatten_operations(state, root) {
            Ok(operations) => Ok(operations),
            Err(error) => {
                journal.log(json!({"event":"flatten_recovery_failed","path":root,"error":error.to_string()}));
                Ok(crate::watch_store::NativeWatchOperations::empty())
            }
        }
    })
}

fn finish_flatten_operations(state: &crate::watch_store::NativeWatchState, root: &str)
    -> io::Result<crate::watch_store::NativeWatchOperations>
{
    let record_key = format!("flatten|{}", watch_path_key(root));
    let Some(record) = state.runtime_record(&record_key) else {
        return Ok(crate::watch_store::NativeWatchOperations::empty());
    };
    let (Some(work), Some(leaf)) = (record["work"].as_str(), record["leaf"].as_str()) else {
        return Ok(crate::watch_store::NativeWatchOperations::empty());
    };
    let current = output_identity(root)?;
    let work_paths = record["work_paths"].as_array().map(|paths| {
        paths.iter().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>()
    }).unwrap_or_else(|| state.owned_output_paths(work, record["old_identity"].as_str().unwrap_or_default()));
    let mut work_exists = false;
    for alias in &work_paths {
        work_exists |= Path::new(alias).try_exists()?;
    }
    let published = record["new_identity"].as_str() == Some(&current);
    if !published && (work_exists || record["old_identity"].as_str() != Some(&current)) {
        return Ok(crate::watch_store::NativeWatchOperations::empty());
    }
    let already_rebased = record["outputs_rebased"].as_bool() == Some(true);
    if work_exists && already_rebased {
        return Ok(crate::watch_store::NativeWatchOperations::empty());
    }
    let root_paths = crate::path_keys::output_path_aliases(Path::new(root))?;
    let mut operations = Vec::new();
    if !work_exists {
        operations.push(json!({"op":"runtime","key":record_key}));
    } else {
        let mut next = record.clone();
        next["outputs_rebased"] = Value::Bool(true);
        next["root_paths"] = json!(root_paths);
        next["work_paths"] = json!(work_paths);
        operations.push(json!({"op":"runtime","key":record_key,"value":next}));
    }
    let owner = record["owner"]
        .as_str()
        .filter(|owner| published && !already_rebased && !owner.is_empty());
    if let Some(owner) = owner {
        for source in [work, leaf] {
            operations.push(json!({"op":"relocate_output","owner":owner,"source":source,
                "destination":root,"identity":current}));
        }
    }
    use crate::watch_store::NativeWatchOperations;
    let mut operations = state.decode_operations(&operations)?;
    operations.extend(NativeWatchOperations::owned_outputs(
        &root_paths, &[&current],
    ));
    if !work_exists {
        if let Some(old) = record["old_identity"].as_str() {
            operations.extend(state.remove_owned_output(&work_paths, old));
        }
    }
    Ok(operations)
}

fn restore_checkpoints(
    state: &crate::watch_store::NativeWatchState,
    owner: &str,
    outputs: &mut BTreeMap<String, String>,
) -> io::Result<Vec<crate::pipeline::InputCheckpoint>> {
    let checkpoints = input_checkpoints(state, owner).collect::<io::Result<Vec<_>>>()?;
    // Reusing a receipt deliberately skips register_output's exclusive create.
    // Restore its routing separately, before the engine discovers children.
    for checkpoint in &checkpoints {
        if checkpoint.has_output() {
            outputs.insert(key(checkpoint.output()), owner.to_owned());
        }
    }
    if let Some(pending) = state.pending(owner) {
        // The enclosing output can differ from an individual logical input's
        // output (carrier siblings and completed flatten operations).
        for container in pending.committed_roots.iter() {
            outputs.insert(watch_path_key(container), owner.to_owned());
        }
    }
    Ok(checkpoints)
}

fn input_checkpoints(
    state: &crate::watch_store::NativeWatchState,
    owner: &str,
) -> impl Iterator<Item = io::Result<crate::pipeline::InputCheckpoint>> {
    let values = state.entry(owner)
        .and_then(|entry| entry.failure_payload.get("input_checkpoints").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    values.into_iter().map(|record| serde_json::from_value(record).map_err(io::Error::other))
}

fn recover_flattens(journal: &journal::Journal, eligible: impl Fn(&str) -> bool) -> io::Result<()> {
    for id in journal.state().runtime_keys("flatten|") {
        let Some(record) = journal.state().runtime_record(&id) else {
            continue;
        };
        if !eligible(record["owner"].as_str().unwrap_or_default()) {
            continue;
        }
        let (Some(root), Some(work), Some(leaf), Some(old), Some(new)) = (
            record["root"].as_str(),
            record["work"].as_str(),
            record["leaf"].as_str(),
            record["old_identity"].as_str(),
            record["new_identity"].as_str(),
        ) else {
            continue;
        };
        let root_id = identity_if_present(root);
        let work_id = identity_if_present(work);
        let (Ok(root_id), Ok(work_id)) = (root_id, work_id) else {
            continue;
        };
        if work_id.as_deref().is_some_and(|id| id != old) {
            continue;
        }
        if root_id.as_deref() == Some(old) && work_id.is_none() {
            recover_finish_flatten(journal, root)?;
            continue;
        }
        if root_id.as_deref().is_some_and(|id| id != new)
            || (root_id.is_none() && work_id.is_none())
        {
            continue;
        }
        if root_id.is_none() {
            let Ok(relative) = Path::new(leaf).strip_prefix(root) else {
                continue;
            };
            let candidate = Path::new(work).join(relative);
            if !output_identity(&candidate.to_string_lossy()).is_ok_and(|id| id == new) {
                continue;
            }
        }
        crate::postprocess::flatten_single_branch_directories(
            Path::new(root),
            Path::new(work),
            crate::postprocess::FlattenLeaf::Resume(Path::new(leaf)),
            |_, _, _| Ok(()),
        );
        if identity_if_present(root).is_ok_and(|identity| identity.as_deref() == Some(new)) {
            recover_finish_flatten(journal, root)?;
        }
    }
    Ok(())
}

// Directory enumeration can return readable files alongside local errors.
// Only a whole-scan failure postpones the owner's recovery.
fn recovery_scan_paths(
    journal: &journal::Journal,
    owner: &str,
    root: &str,
    result: io::Result<(Vec<PathBuf>, Vec<crate::io::directory_errors::DirectoryReadError>)>,
) -> io::Result<Vec<PathBuf>> {
    match result {
        Ok((paths, _errors)) => Ok(paths),
        Err(error) => {
            journal.log(json!({"event":"crash_resume_scan_failed", "owner_path":owner,
                "root":root, "error":error.to_string()}));
            Err(error)
        }
    }
}

// A refresh publishes successful rows even when another row failed. Preserve
// its arrivals before fallback: the full refresh may see them as unchanged.
fn collect_catalog_arrivals(
    result: io::Result<(Vec<crate::io::directory_errors::DirectoryReadError>, Vec<String>)>,
    paths: &mut Vec<String>,
) -> Result<(), String> {
    let (errors, mut arrivals) = result.map_err(|error| error.to_string())?;
    paths.append(&mut arrivals);
    if errors.is_empty() { Ok(()) } else { Err(format!("{errors:?}")) }
}

fn identity_if_present(path: &str) -> io::Result<Option<String>> {
    match output_identity(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

// A dismissed/erroring notice may log to the live session, but an open modal
// dialog must never retain that session's exclusive state lock across stop.
fn spawn_error_dialog(
    journal: &Arc<journal::Journal>,
    show: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    let journal = Arc::downgrade(journal);
    thread::Builder::new().name("sunpack-watch-error".into()).spawn(move || {
        if let Err(error) = show() {
            if let Some(journal) = journal.upgrade() {
                journal.log(json!({"event":"watch_error_dialog_failed","error":error.to_string()}));
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn completed_family_requires_full_generation_mode_and_live_output() {
        let directory = std::env::temp_dir().join(format!("sunpack-completed-family-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&directory).unwrap();
        let head = directory.join("archive.001");
        let tail = directory.join("archive.002");
        let output = directory.join("output");
        fs::write(&head, b"head").unwrap();
        fs::write(&tail, b"tail").unwrap();
        fs::create_dir(&output).unwrap();
        let generations: SourceGenerations = [&head, &tail].into_iter().map(|path|
            (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
        let mut cache = CompletedFamilies::default();
        cache.remember(generations.clone(), false, &output);
        assert_eq!(cache.output(&generations, false), Some(output.clone()));
        assert_eq!(cache.output(&generations, true), None);
        let subset = HashMap::from([(key(&head), generations[&key(&head)].clone())]);
        assert_eq!(cache.output(&subset, false), None);
        assert!(cache.covers(&head, false));
        assert!(cache.covers(&tail, false));
        assert!(!cache.covers(&head, true));
        fs::rename(&tail, directory.join("away")).unwrap();
        assert!(!cache.covers(&head, false));
        fs::rename(directory.join("away"), &tail).unwrap();
        assert!(cache.covers(&head, false));
        fs::write(&tail, b"changed tail generation").unwrap();
        assert!(!cache.covers(&head, false));
        let refreshed: SourceGenerations = [&head, &tail].into_iter().map(|path|
            (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
        assert_eq!(cache.output(&refreshed, false), None);
        cache.remember(refreshed.clone(), false, &output);
        assert_eq!(cache.output(&refreshed, false), Some(output.clone()));
        fs::remove_dir(&output).unwrap();
        assert_eq!(cache.output(&refreshed, false), None);
        assert!(!cache.covers(&head, false));
        assert!(cache.by_family.is_empty());
        assert!(cache.ordered.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn idle_completed_families_release_old_output_but_live_requests_reuse_it() {
        let head = crate::test_support::temp_file("idle_family_head", b"head");
        let tail = crate::test_support::temp_file("idle_family_tail", b"tail");
        let output = head.with_extension("output");
        fs::create_dir(&output).unwrap();
        let generations: SourceGenerations = [&head, &tail].into_iter().map(|path|
            (key(path), crate::io::reader::capture_file_generation(path).unwrap())).collect();
        let hub = Hub::new();
        hub.completed_families.lock().unwrap().remember(generations.clone(), false, &output);
        assert_eq!(hub.completed_families.lock().unwrap().output(&generations, false), Some(output.clone()));
        hub.clear_idle_completed_families();
        let mut cache = hub.completed_families.lock().unwrap();
        assert_eq!(cache.output(&generations, false), None);
        assert!(cache.by_family.is_empty());
        assert!(cache.ordered.is_empty());
        drop(cache);
        fs::remove_dir(output).unwrap();
        fs::remove_file(head).unwrap();
        fs::remove_file(tail).unwrap();
    }

    #[test]
    fn completed_family_cache_is_bounded_and_refreshes_lru() {
        let directory = std::env::temp_dir().join(format!("sunpack-family-lru-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&directory).unwrap();
        let head = directory.join("head");
        fs::write(&head, b"head").unwrap();
        let generation = crate::io::reader::capture_file_generation(&head).unwrap();
        let mut cache = CompletedFamilies::default();
        cache.remember(HashMap::from([(key(&head), generation.clone())]), false, &directory);
        for n in 1..COMPLETED_FAMILY_LIMIT {
            cache.remember(HashMap::from([(format!("other-{n}"), generation.clone())]), false, &directory);
        }
        assert!(cache.covers(&head, false));
        cache.remember(HashMap::from([("new".into(), generation)]), false, &directory);
        assert_eq!(cache.ordered.len(), COMPLETED_FAMILY_LIMIT);
        assert_eq!(cache.by_family.len(), COMPLETED_FAMILY_LIMIT);
        assert!(cache.covers(&head, false));
        assert!(!cache.by_family.keys().any(|(members, _)| members.iter().any(|path| path == "other-1")));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_scan_preserves_readable_files_with_local_errors() {
        let marker = crate::test_support::temp_file("recovery_scan_errors", b"archive");
        let directory = marker.with_extension("state");
        let journal = journal::Journal::open(&directory, 7).unwrap();
        let paths = recovery_scan_paths(&journal, "owner.zip", "output",
            Ok((vec![marker.clone()], vec![("read_dir".into(), "output/locked".into(),
                "access denied".into())]))).unwrap();
        assert_eq!(paths, [marker.clone()]);
        let failure = recovery_scan_paths(&journal, "owner.zip", "output",
            Err(io::ErrorKind::PermissionDenied.into())).unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
        journal.flush().unwrap();
        let manifest: crate::io::display_store::Manifest = serde_json::from_slice(
            &fs::read(directory.join("events.json")).unwrap(),
        ).unwrap();
        assert_eq!(manifest.runs.iter().map(|run| run.count - run.head).sum::<u64>(), 1);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn configuration_subscriptions_share_directory_and_preserve_live_intersections() {
        let marker = crate::test_support::temp_file("shared_config_observer", b"");
        let directory = marker.with_extension("directory");
        fs::create_dir(&directory).unwrap();
        let config = directory.join("config.json");
        let passwords = directory.join("passwords.json");
        let first = observe_files(&[config.clone()], &passwords, |_, _| {}).unwrap();
        let second = observe_files(&[config.clone(), directory.join("roots.txt")], &passwords, |_, _| {}).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert!(Arc::ptr_eq(&first[0].directory, &second[0].directory));
        assert!(observes_files(&[config.clone()], &passwords, &first));
        assert!(!observes_files(&[config.clone()], &passwords, &second));
        let weak = Arc::downgrade(&first[0].directory);
        assert_eq!(first[0].directory.listeners.lock().unwrap().len(), 2);
        drop(first);
        assert!(second[0].alive());
        assert_eq!(second[0].directory.listeners.lock().unwrap().len(), 1);
        // Re-arming a changed file set adds a listener, not a native observer.
        let third = observe_files(&[config], &passwords, |_, _| {}).unwrap();
        assert!(Arc::ptr_eq(&second[0].directory, &third[0].directory));
        drop(second);
        drop(third);
        assert!(weak.upgrade().is_none());

        let child = directory.join("new");
        let paths = [child.join("config.json")];
        let ancestor = observe_files(&paths, &passwords, |_, _| {}).unwrap();
        assert!(observes_files(&paths, &passwords, &ancestor));
        fs::create_dir(&child).unwrap();
        assert!(!observes_files(&paths, &passwords, &ancestor));
        let moved = observe_files(&paths, &passwords, |_, _| {}).unwrap();
        assert_eq!(moved.len(), 2);
        assert!(moved.iter().any(|subscription| Arc::ptr_eq(&ancestor[0].directory, &subscription.directory)));
        drop(ancestor);
        assert!(observes_files(&paths, &passwords, &moved));
        drop(moved);
        fs::remove_dir(child).unwrap();
        fs::remove_dir(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn ordinary_observation_diagnostics_preserve_native_event_provenance() {
        let path = Path::new("destination.zip");
        let mut source = None;
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "locked");
        for (action, expected) in [(1, "created"), (3, "modified")] {
            let event = CandidateEvent::native(action, path, &mut source).unwrap();
            let record = CandidateDiagnostics::observation_record("destination.zip", &error, Some(&event));
            assert_eq!(record["event_type"], expected);
            assert_eq!(record["src_path"], "");
            assert_eq!(record["event"], "candidate_ignored");
            assert_eq!(record["reason"], "observation_error");
            assert_eq!(record["error"], "PermissionError: locked");
        }
        assert_eq!(CandidateEvent::native(4, Path::new("source.zip"), &mut source), None);
        let moved = CandidateEvent::native(5, path, &mut source).unwrap();
        let record = CandidateDiagnostics::observation_record("destination.zip", &error, Some(&moved));
        assert_eq!(record["event_type"], "moved");
        assert_eq!(record["src_path"], "source.zip");
        assert_eq!(record["path"], "destination.zip");
        // An unmatched new-name record cannot supply an invented source.
        assert_eq!(CandidateEvent::native(5, path, &mut source), None);
        let recovery = CandidateDiagnostics::observation_record("destination.zip", &error, None);
        assert_eq!(recovery["event_type"], "unknown");
        assert_eq!(recovery["src_path"], "");
        // Coalescing retains the first actual ordinary event, as main's
        // diagnostic throttle would, until this Signals burst is consumed.
        let mut signals = Signals::default();
        signals.candidate_events.entry(path.to_owned()).or_insert(moved);
        signals.candidate_events.entry(path.to_owned()).or_insert(CandidateEvent::Modified);
        assert_eq!(signals.candidate_events[path].kind(), "moved");
        let captured = std::mem::take(&mut signals);
        assert!(signals.candidate_events.is_empty());
        assert_eq!(captured.candidate_events[path].source(), "source.zip");
    }

    #[test]
    fn candidate_wait_history_survives_pending_retirement_and_expires_with_a_bound() {
        let marker = crate::test_support::temp_file("candidate_diagnostics", b"");
        let directory = marker.with_extension("state");
        let journal = journal::Journal::open(&directory, 7).unwrap();
        let now = Instant::now();
        let mut history = CandidateDiagnostics::default();
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "locked");
        // No Pending owner is retained: a same-path re-entry shares history.
        for seconds in [0, 1, 29, 30, 31] {
            let at = now + std::time::Duration::from_secs(seconds);
            history.log_wait(&journal, at, "path", "path", None);
            history.log_wait(&journal, at, "path", "path", Some(&error));
        }
        journal.flush().unwrap();
        let manifest: crate::io::display_store::Manifest = serde_json::from_slice(
            &fs::read(directory.join("events.json")).unwrap(),
        ).unwrap();
        assert_eq!(manifest.runs.iter().map(|run| run.count - run.head).sum::<u64>(), 4);
        // Observation and readiness errors have independent main intervals.
        // A long-lived observation entry must not hide a later 30s expiry.
        let observation_at = now + std::time::Duration::from_secs(31);
        history.log_observation(&journal, observation_at, "observe", "observe", &error, None);
        history.log_wait(&journal, observation_at, "later", "later", Some(&error));
        history.clear_expired(now + std::time::Duration::from_secs(61));
        assert_eq!(history.order.len(), 1);
        assert!(history.paths["observe"][2].is_some());
        assert!(!history.paths.contains_key("later"));
        history.log_observation(&journal, now + std::time::Duration::from_secs(330), "observe", "observe", &error, None);
        assert_eq!(history.order.len(), 1);
        let at = now + std::time::Duration::from_secs(331);
        history.log_observation(&journal, at, "observe", "observe", &error, None);
        assert_eq!(history.deadline(), Some(at + std::time::Duration::from_secs(300)));
        for index in 0..2048 {
            let path = index.to_string();
            history.log_wait(&journal, at, &path, &path, None);
        }
        assert_eq!(history.order.len(), 2048);
        assert_eq!(history.paths.len(), 2048);
        assert!(!history.paths.contains_key("path"));
        history.clear_expired(at + std::time::Duration::from_secs(30));
        assert!(history.paths.is_empty());
        assert!(history.deadline().is_none());
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn root_policy_normalizes_only_equivalent_nonrecursive_output_layouts() {
        let path = PathBuf::from(r"C:\downloads");
        let mut implicit = Root { path: path.clone(), output: None, recursive: false,
            deep: true, scanned: false };
        let mut explicit = implicit.clone();
        explicit.output = Some(path);
        explicit.scanned = true;
        assert!(implicit.same_policy(&explicit));
        assert!(explicit.same_policy(&implicit));
        implicit.recursive = true;
        explicit.recursive = true;
        assert!(!implicit.same_policy(&explicit));
        explicit.output = None;
        assert!(implicit.same_policy(&explicit));
        explicit.deep = false;
        assert!(!implicit.same_policy(&explicit));
    }

    #[test]
    fn partial_catalog_refresh_preserves_arrivals_before_fallback() {
        let mut paths = vec!["previous.zip".to_owned()];
        let errors = vec![("metadata".into(), "locked.zip".into(), "access denied".into())];
        assert!(collect_catalog_arrivals(Ok((errors, vec!["new.zip".into()])), &mut paths).is_err());
        // The catalog already contains new.zip; a successful full retry can
        // legitimately report no arrivals. It must still reach admission.
        collect_catalog_arrivals(Ok((Vec::new(), Vec::new())), &mut paths).unwrap();
        assert_eq!(paths, ["previous.zip", "new.zip"]);
        assert!(collect_catalog_arrivals(Err(io::ErrorKind::PermissionDenied.into()), &mut paths).is_err());
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn standalone_once_does_not_publish_continuous_status() {
        use std::future::Future;

        let watch = Watch::new(Arc::new(|| {}));
        let (release, wait) = mpsc::channel();
        let thread = std::thread::spawn(move || { let _ = wait.recv(); Ok(()) });
        let hub = Arc::new(Hub::new());
        let completion = Arc::new(RunCompletion::default());
        *watch.running.lock().unwrap() = Some(Running {
            hub: Arc::clone(&hub), thread, continuous: false,
            completion: Arc::clone(&completion),
        });
        let cwd = std::env::temp_dir();
        let status = watch.status(&cwd).unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["generation"], 0);
        assert_eq!(status["last_error"], "");
        assert_eq!(status["state_dir"], json!(resources::writable_data_dir(&cwd).unwrap().join(WATCH_METADATA)));
        assert_eq!(block_on(watch.stop_async()).unwrap()["stopped"], false);
        assert_eq!(watch.reload().unwrap()["running"], false);
        assert!(!hub.stopped.load(Ordering::Acquire));

        // A second once caller must share the standalone result. The
        // standalone scheduler never services the continuous tick queue.
        let engine = Arc::new(Engine::new(PathBuf::from("unused-worker")));
        let cancel = Cancellation::new();
        let mut start = Box::pin(watch.start_async(&cwd, Arc::clone(&engine), false));
        let mut second = Box::pin(watch.run_once_async(&cwd, engine, &cancel));
        let mut cx = std::task::Context::from_waker(Waker::noop());
        assert!(start.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert!(hub.signals.lock().unwrap().once.is_empty());
        assert!(!hub.stopped.load(Ordering::Acquire));
        completion.complete(&Ok(0));
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(0))));

        release.send(()).unwrap();
        watch.running.lock().unwrap().take().unwrap().thread.join().unwrap().unwrap();
    }

    #[test]
    fn flatten_recovery_keeps_intent_after_local_probe_failure() {
        let source = crate::test_support::temp_file("flatten_probe_failure", b"owner");
        let directory = source.with_extension("state");
        let root = directory.join("missing");
        let journal = journal::Journal::open(&directory, 7).unwrap();
        let record_key = format!("flatten|{}", key(&root));
        journal.commit(true, |state| state.decode_operations(&[
            json!({"op":"runtime","key":record_key,"value":{
                "owner":"owner","root":root,"work":directory.join("work"),
                "leaf":root.join("leaf"),"old_identity":"old","new_identity":"new"}})
        ])).unwrap();
        assert!(finish_flatten(&journal, root.to_str().unwrap()).is_err());
        recover_finish_flatten(&journal, root.to_str().unwrap()).unwrap();
        assert!(journal.state().runtime_record(&record_key).is_some());
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn modified_directories_wait_for_merged_maintenance_but_topology_recovers() {
        let directory = std::env::temp_dir().join(format!("sunpack-event-action-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("input.zip");
        std::fs::write(&file, b"archive").unwrap();
        let missing = directory.join("departed.zip");
        let mut signals = Signals::default();
        signals.root_changed("root", Some(vec![directory.clone(), file.clone(), missing.clone()]));
        signals.modified_paths.extend([directory.clone(), file.clone(), missing.clone()]);
        assert!(!Signals::prepare_root_changes(&mut signals.changed_roots, &signals.topology_roots, &signals.modified_paths));
        assert!(!signals.changed_roots["root"].contains(&directory));
        assert!(signals.changed_roots["root"].contains(&file));
        for path in [directory.clone(), missing] {
            let mut signals = Signals::default();
            signals.root_changed("root", Some(vec![path]));
            assert!(Signals::prepare_root_changes(&mut signals.changed_roots, &signals.topology_roots, &signals.modified_paths));
        }
        let mut signals = Signals::default();
        signals.root_changed("root", None);
        assert!(Signals::prepare_root_changes(&mut signals.changed_roots, &signals.topology_roots, &signals.modified_paths));
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn completion_opens_physical_container_with_one_or_many_retained_segments() {
        let container = Path::new(r"C:\output\carrier");
        let a = Path::new(r"C:\output\carrier\zip");
        let b = Path::new(r"C:\output\carrier\7z");
        let containers = HashMap::from([(a, container), (b, container)]);
        assert_eq!(completion_output_dirs([a], &containers), vec![container.to_path_buf()]);
        assert_eq!(completion_output_dirs([b, a], &containers), vec![container.to_path_buf()]);
        assert_eq!(completion_output_dirs([a], &HashMap::new()), vec![a.to_path_buf()]);
        assert!(completion_output_dirs([], &containers).is_empty());
    }

    #[test]
    fn volume_notifications_select_only_matching_roots_and_preserve_arrivals() {
        let c = Path::new(r"C:\downloads");
        let d = Path::new(r"D:\downloads");
        let unc = Path::new(r"\\server\share");
        let mut changes = VolumeChanges::default();
        assert!(changes.is_empty());
        changes.add(1 << 2, false);
        assert!(changes.affects(c, true));
        assert!(!changes.arrives(c, true));
        assert!(!changes.affects(d, false));
        assert!(!changes.affects(unc, false));
        changes.add(1 << 3, true);
        changes.add(1 << 3, false);
        assert!(changes.affects(c, true));
        assert!(changes.arrives(d, true));
        let mut initial = VolumeChanges::default();
        initial.add(0, true);
        for root in [c, d, unc] {
            assert!(!initial.affects(root, true));
            assert!(initial.affects(root, false));
            assert!(initial.arrives(root, false));
        }
    }

    #[test]
    fn password_notifications_do_not_reload_unrelated_configuration() {
        let files = HashMap::from([
            ("builtin_passwords.json".into(), (false, true)),
            ("sunpack_config.json".into(), (true, false)),
            // Both sources can live below a missing directory watched through
            // its ancestor: its appearance must rearm all affected sources.
            ("new-directory".into(), (true, true)),
        ]);
        let names = |name: &str| vec![name.to_owned()];
        assert_eq!(configuration_changes(&files, Some(&names("BUILTIN_PASSWORDS.JSON"))), (false, true));
        assert_eq!(configuration_changes(&files, Some(&names("sunpack_config.json"))), (true, false));
        assert_eq!(configuration_changes(&files, Some(&names("unrelated.tmp"))), (false, false));
        assert_eq!(configuration_changes(&files, Some(&names("new-directory"))), (true, true));
        assert_eq!(configuration_changes(&files, None), (true, true));
    }

    #[test]
    fn native_burst_updates_activity_before_scheduler_drains_its_coalesced_signal() {
        use std::io::Write;
        use std::time::Duration;
        let marker = crate::test_support::temp_file("watch_capture", b"");
        let directory = marker.with_extension("work");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let root = Root { path: watched.clone(), output: None, recursive: true, deep: false, scanned: true };
        let state = directory.join("state");
        let journal = Arc::new(journal::Journal::open(&state, 7).unwrap());
        let catalog = Arc::new(NativeWatchCatalog::new(journal.state(), None));
        let hub = Arc::new(Hub::new());
        let source = watched.join("growing.zip");
        let activity = hub.activities.bind(key(&source), quiet::Activity::default);
        let observer = RootObserver::start(&watched, &root, root.scope(&[], &[state.to_string_lossy().into_owned()]),
            &watched.join("builtin_passwords.json"), &hub, &journal, &catalog).unwrap();
        let mut file = fs::File::create(&source).unwrap();
        // Wait for each size to reach the shared activity without draining the
        // scheduler's signals. Cadence confirmation is tested with a controlled clock.
        for size in 1..=4 {
            file.write_all(b"x").unwrap();
            file.flush().unwrap();
            file.sync_data().unwrap();
            let signals = hub.signals.lock().unwrap();
            let (_signals, wait) = hub.wake.wait_timeout_while(signals, Duration::from_secs(5), |signals| {
                !signals.activities.contains_key(&source) || activity.observed_size() != Some(size)
            }).unwrap();
            assert!(!wait.timed_out(), "observer did not publish size {size}");
        }
        let deadline = activity.deadline().unwrap();
        // No scheduler tick has run, so all wakes still occupy one path slot.
        let signals = std::mem::take(&mut *hub.signals.lock().unwrap());
        assert_eq!(signals.changed_roots[&key(&watched)].len(), 1);
        let (candidate, _, _) = activity.probe(&source, None).unwrap();
        assert_eq!(activity.content_deadline(&candidate.unwrap(),
            Instant::now() + Duration::from_secs(60), windows::monotonic_seconds() + 60.0,
            false, false, None), deadline);
        drop(file);
        drop(observer);
        drop(signals);
        drop(catalog);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn business_root_routes_password_file_notification_only_to_password_reload() {
        let marker = crate::test_support::temp_file("watch_password_event", b"");
        let directory = marker.with_extension("work");
        let watched = directory.join("watched");
        fs::create_dir_all(&watched).unwrap();
        let root = Root { path: watched.clone(), output: None, recursive: true, deep: false, scanned: true };
        let state = directory.join("state");
        let journal = Arc::new(journal::Journal::open(&state, 7).unwrap());
        let hub = Arc::new(Hub::new());
        let passwords = watched.join("builtin_passwords.json");
        let observer = RootObserver::start(
            &watched, &root, root.scope(&[], &[state.to_string_lossy().into_owned()]), &passwords, &hub, &journal, &Arc::new(NativeWatchCatalog::new(journal.state(), None)),
        ).unwrap();
        fs::write(&passwords, b"{}").unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let signals = hub.wait(Some(deadline));
        assert!(signals.password_changed);
        assert!(signals.changed_roots.is_empty());
        drop(observer);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn relative_roots_use_process_directory_not_roots_file_directory() {
        let marker = crate::test_support::temp_file("relative_watch_roots", b"");
        fs::write(&marker, "relative-input | child-output | false | true | false\n").unwrap();
        let roots = read_roots(&marker).unwrap();
        let input = std::env::current_dir().unwrap().join("relative-input");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, input);
        assert_eq!(roots[0].output.as_ref().unwrap(), &input.join("child-output"));
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn admission_owned_reconciliation_uses_only_changed_paths() {
        let scope = super::NativeDiscoveryScope::new(r"C:\watched".into(), None, Vec::new());
        let changed = [r"C:\watched\new.zip", r"C:\outside\file.zip"]
            .map(|path| (path.to_owned(), crate::path_keys::path_key(path)));
        assert!(super::owned_checkpoint_paths(&scope, None, Some(&[]), false).is_empty());
        assert_eq!(super::owned_checkpoint_paths(&scope, None, Some(&changed), false),
            [r"C:\watched\new.zip"]);
        assert_eq!(super::owned_checkpoint_paths(&scope, None, Some(&changed), true),
            [r"C:\watched"]);
    }

    use super::*;
    use crate::io::reader::capture_file_generation;
    use crate::watch_store::{NativeWatchOperations, PendingObservation};

    #[test]
    fn open_error_dialog_does_not_retain_watch_state_across_restart() {
        let marker = crate::test_support::temp_file("watch_dialog_restart", b"");
        let directory = marker.with_extension("state");
        let journal = Arc::new(journal::Journal::open(&directory, 7).unwrap());
        let (opened_tx, opened_rx) = mpsc::channel();
        let (dismiss_tx, dismiss_rx) = mpsc::channel();
        let dialog = spawn_error_dialog(&journal, move || {
            opened_tx.send(()).unwrap();
            dismiss_rx.recv().unwrap();
            Err(io::Error::other("dialog unavailable"))
        }).unwrap();
        opened_rx.recv().unwrap();
        let old = Arc::downgrade(&journal);
        drop(journal); // scheduler has stopped, but the modal dialog is still open
        let released = old.upgrade().is_none();
        let restarted = journal::Journal::open(&directory, 7);
        // Release the simulated dialog even if reopening failed.
        dismiss_tx.send(()).unwrap();
        dialog.join().unwrap();
        assert!(released);
        drop(restarted.expect("an undismissed notice must not block watch start"));
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn published_policy_keeps_full_scan_obligation_across_retirement_and_scan_failures() {
        let mut progress = RootPolicyProgress::default();
        // An already-scanned root changes deep=false to deep=true. Retirement
        // fails after its new policy is published; the next compare is equal.
        assert!(progress.observe(true, false));
        assert!(progress.observe(false, false));
        progress.retirement = false; // the retry successfully retires old scope
        assert!(progress.checkpoint); // still must scan all roots, not pending only
        progress.checkpoint_finished(&Err(io::Error::other("checkpoint failed")));
        assert!(!progress.observe(false, false));
        assert!(progress.checkpoint);
        progress.checkpoint_finished(&Ok(()));
        assert!(!progress.checkpoint);
        assert!(progress.recovery); // a scan does not acknowledge pending/blocker recovery
        progress.recovery = false;
        assert!(!progress.observe(false, false));
        assert!(!progress.recovery);
    }

    #[test]
    fn reload_scheduler_policy_excludes_only_tray_and_process_priority() {
        let previous = Config::parse(&json!({})).unwrap();
        let mut next = previous.clone();
        next.watch.tray_enabled = !previous.watch.tray_enabled;
        next.runtime.process_mode = config::ProcessMode::Background;
        assert!(previous != next);
        assert!(!scheduler_configuration_changed(&previous, &next));
        next.watch.toast_enabled = !previous.watch.toast_enabled;
        assert!(scheduler_configuration_changed(&previous, &next));
        next = previous.clone();
        next.cli.language = match previous.cli.language {
            crate::core::i18n::Language::En => crate::core::i18n::Language::Zh,
            crate::core::i18n::Language::Zh => crate::core::i18n::Language::En,
        };
        assert!(scheduler_configuration_changed(&previous, &next));
    }

    #[test]
    fn content_batches_do_not_invalidate_topology_but_overflow_does() {
        let mut signals = Signals::default();
        for _ in 0..100 {
            signals.root_changed("root-a", Some(vec![PathBuf::from("root-a/archive.zip")]));
        }
        assert!(signals.topology_roots.is_empty());
        assert_eq!(signals.changed_roots.len(), 1);
        // A content event batched after an overflow must not erase the rearm.
        signals.root_changed("root-a", None);
        signals.root_changed("root-a", Some(vec![PathBuf::from("root-a/archive.zip")]));
        assert_eq!(signals.topology_roots, HashSet::from(["root-a".to_owned()]));
        assert_eq!(signals.changed_roots["root-a"].len(), 1);
    }

    #[test]
    fn parent_subscription_is_shared_and_routes_only_affected_roots() {
        let temp = std::env::temp_dir().join(format!("sunpack-parent-sharing-{}", std::process::id()));
        std::fs::create_dir_all(&temp).unwrap();
        let roots = ["one", "two", "missing/child"].map(|name| Root {
            path: temp.join(name), output: None, recursive: false, deep: false, scanned: false,
        });
        let groups = parent_memberships(roots.iter());
        assert_eq!(groups.len(), 1); // one sentinel, not one per sibling root
        let (directory, members) = groups.values().next().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(affected_parent_roots(members, Some(&[key(&directory.join("one"))])), vec![key(&roots[0].path)]);
        assert_eq!(affected_parent_roots(members, Some(&[key(&directory.join("missing"))])), vec![key(&roots[2].path)]);
        assert!(affected_parent_roots(members, Some(&[key(&directory.join("unrelated"))])).is_empty());
        assert_eq!(affected_parent_roots(members, None).len(), 3);
        assert!(parent_memberships(std::iter::empty::<&Root>()).is_empty());
        std::fs::remove_dir(&temp).unwrap();
    }

    #[test]
    fn completion_blockers_follow_reloaded_roots_without_losing_recovery_routes() {
        let root = Root { path: r"C:\watch".into(), output: None,
            recursive: true, deep: false, scanned: false };
        let id = key(&root.path);
        let recursive = NativeDiscoveryScope::new(r"C:\watch".into(), None, Vec::new());
        let shallow = NativeDiscoveryScope::new(r"C:\watch".into(), Some(0), Vec::new());
        let candidate = WatchCandidateRow {
            path: r"C:\watch\sub\archive.part1.rar".into(), size: 42, mtime: 1.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: String::new(), change_usn: 0, change_reasons: 0,
                change_reasons_without_close: 0, change_reasons_known: false,
                change_reason_error: String::new(),
            },
        };
        // Both kinds can return from a request admitted before root reload.
        for status in ["failed_password", "suspended_missing_volume"] {
            let mut entry = observed_entry(&candidate, status, None);
            let roots = BTreeMap::from([(id.clone(), (root.clone(), recursive.clone()))]);
            assert!(route_blocker(&entry, &roots, |_| false).is_some());
            assert!(route_blocker(&entry, &BTreeMap::new(), |_| false).is_none());
            let roots = BTreeMap::from([(id.clone(), (root.clone(), shallow.clone()))]);
            assert!(route_blocker(&entry, &roots, |_| false).is_none());
            // A different current root may legitimately own the old input.
            let sub = Root { path: r"C:\watch\sub".into(), ..root.clone() };
            let roots = BTreeMap::from([(key(&sub.path), (sub,
                NativeDiscoveryScope::new(r"C:\watch\sub".into(), None, Vec::new())))]);
            assert!(route_blocker(&entry, &roots, |_| false).is_some());

            // Promoted recovery is intentionally allowed outside the ordinary
            // scan scope, but only while its original input root still exists.
            entry.path = r"D:\output\inner.zip".into();
            entry.failure_payload.insert("source_input_root".into(), json!(root.path));
            entry.failure_payload.insert("discovery_scope".into(), Value::Object(scope_record(
                &NativeDiscoveryScope::new(r"D:\output".into(), Some(0), Vec::new()))));
            entry.failure_payload.insert("password_scope_dir".into(), json!(r"C:\watch"));
            let roots = BTreeMap::from([(id.clone(), (root.clone(), shallow.clone()))]);
            assert!(route_blocker(&entry, &roots, |_| true).unwrap().1.is_some());
            assert!(route_blocker(&entry, &BTreeMap::new(), |_| true).is_none());
        }
    }

    #[test]
    fn promoted_regroup_handoff_persists_the_new_current_root() {
        let marker = crate::test_support::temp_file("watch_rerouted_promotion", b"");
        let directory = marker.with_extension("state");
        let root = Root { path: r"C:\watch".into(), output: None,
            recursive: true, deep: false, scanned: false };
        let root_id = key(&root.path);
        let roots = BTreeMap::from([(root_id.clone(), (root.clone(),
            NativeDiscoveryScope::new(r"C:\watch".into(), None, Vec::new())))]);
        let candidate = WatchCandidateRow {
            path: r"C:\watch\old\inner.part1.rar".into(), size: 42, mtime: 1.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: "promoted-generation".into(), change_usn: 9, change_reasons: 0,
                change_reasons_without_close: 0, change_reasons_known: false,
                change_reason_error: String::new(),
            },
        };
        let recovery = Recovery {
            scope: NativeDiscoveryScope::new(r"C:\watch\old".into(), Some(0), Vec::new()),
            password_scope: r"C:\passwords".into(),
        };
        let mut entry = Arc::new(observed_entry(&candidate, "suspended_missing_volume", None));
        let payload = &mut Arc::make_mut(&mut entry).failure_payload;
        payload.insert("discovery_scope".into(), Value::Object(scope_record(&recovery.scope)));
        payload.insert("password_scope_dir".into(), json!(recovery.password_scope));
        payload.insert("details".into(), json!({"promoted_nested_input":true}));
        let mut pending = Pending {
            admission_ready: false,
            root: watch_path_key(r"C:\watch\old"), candidate,
            quiet: quiet::Activity::default(), due: Instant::now(), force: true, recovery: None,
        };
        let due = pending.due;
        // Old A was removed; current B covers the promoted file. This is the
        // exact fallback route that completion must hand to an existing queue.
        let (route, _) = route_blocker(&entry, &roots, |_| false).unwrap();
        handoff_promoted_blocker(&mut entry, &route, &roots[&route].0,
            recovery, Some(&mut pending));
        assert_eq!(pending.root, root_id);
        assert_eq!(pending.due, due);
        assert_eq!(pending.candidate.observation.change_usn, 9);
        let (current, _) = &roots[&pending.root];
        let recovery = pending.recovery.as_ref().unwrap();
        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            journal.commit(true, |state| {
                let candidate = &pending.candidate;
                let (mut operations, _) = state.pending_operations([(
                    PendingObservation(candidate.path.clone(), candidate.size as i64,
                        candidate.mtime, candidate.observation.file_id.clone(),
                        candidate.observation.change_usn),
                    current.path.to_string_lossy().into_owned(), Some(scope_record(&recovery.scope)),
                )], pending.force, &recovery.password_scope.to_string_lossy(), true, true, None)?;
                operations.put_entry(Arc::clone(&entry));
                Ok(operations)
            }).unwrap();
        }
        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            let record = journal.state().pending(&pending.candidate.path).unwrap();
            assert_eq!(watch_path_key(&record.source_input_root), root_id);
            assert_eq!(record.change_usn, 9);
            assert_eq!(record.password_scope_dir, r"C:\passwords");
            let entry = journal.state().entry(&pending.candidate.path).unwrap();
            let (route, recovery) = route_blocker(&entry, &roots, |_| true).unwrap();
            assert_eq!(route, root_id);
            assert!(recovery.unwrap().scope.contains(&pending.candidate.path));
        }
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn scan_diagnostics_do_not_override_watch_completion() {
        use crate::pipeline::{InputError, InputErrorKind};
        let root = Path::new(r"C:\watch\outer.zip");
        let nested = Path::new(r"C:\watch\outer\unreadable");
        let outputs = BTreeMap::from([
            (key(Path::new(r"C:\watch\outer")), root.to_string_lossy().into_owned()),
        ]);
        let mut errors = vec![
            InputError { path: nested.into(), message: "scan denied".into(),
                kind: InputErrorKind::FilesystemScan,
                failure: None,
                scan_operation: Some("read_directory".into()), scan_count: Some(2) },
            InputError { path: root.into(), message: "cleanup failed".into(),
                kind: InputErrorKind::Cleanup, failure: None, scan_operation: None, scan_count: None },
        ];
        // Neither diagnostic may override a successful archive or its retry
        // cause, even when the diagnostic resolves to that archive's owner.
        assert!(completion_input_errors(&errors, &outputs, &HashMap::new(), &[]).is_empty());
        errors.push(InputError {
            path: nested.into(),
            message: "embedded read failed".into(),
            kind: InputErrorKind::EmbeddedDiscovery,
            failure: Some(Box::new(crate::pipeline::Failure::new(FailureKind::FilesystemError, "embedded read failed"))),
            scan_operation: None,
            scan_count: None,
        });
        let paths = completion_input_errors(&errors, &outputs, &HashMap::new(), &[]);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[&key(root)].failure.as_ref().unwrap().kind, FailureKind::FilesystemError);
        assert_eq!(paths[&key(nested)].message, "embedded read failed");
        // The projection borrows; CLI and diagnostics retain the original data.
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0].scan_count, Some(2));
    }

    pub(super) fn completion_archive(path: &str, depth: usize, kind: Option<FailureKind>) -> ArchiveResult {
        ArchiveResult {
            path: path.into(), format: "zip".into(), output: None,
            failure: kind.map(|kind| crate::pipeline::Failure::new(kind, format!("{kind:?}"))),
            files: 0, bytes: 0, encrypted: None, depth, offset: 0, end_offset: None,
            volume_completeness: None, volume_attempts: None, source_paths: vec![path.into()],
            password: None, discovery_source: crate::pipeline::DiscoverySource::Direct,
            damage_flags: None, partial: false, retained: false, recovered_complete_files: 0,
            promoted: false, promotion_original_path: None, scan_layout: Default::default(),
        }
    }

    #[test]
    fn completion_routes_nested_terminal_failures_to_the_canonical_top_level_group() {
        let head = Path::new(r"C:\watch\outer.part1.zip");
        let alias = Path::new(r"C:\watch\outer.part2.zip");
        let other = Path::new(r"C:\watch\other.zip");
        let group = Arc::new(SourceGroup {
            path: head.into(), name: "outer".into(), multipart: true,
            members: vec![head.to_string_lossy().into(), alias.to_string_lossy().into()],
        });
        let groups = HashMap::from([(key(head), Arc::clone(&group)), (key(alias), group)]);
        let outputs = BTreeMap::from([
            (key(Path::new(r"C:\watch\outer")), alias.to_string_lossy().into_owned()),
            (key(Path::new(r"C:\watch\other")), other.to_string_lossy().into_owned()),
        ]);
        let mut outer = completion_archive(head.to_str().unwrap(), 1, None);
        outer.source_paths.push(alias.into());
        let mut outcome = Outcome::default();
        outcome.archives = vec![outer, completion_archive(other.to_str().unwrap(), 1, None),
            completion_archive(r"C:\watch\outer\inner.zip", 2, Some(FailureKind::Damaged))];
        let failures = outcome.input_failures();
        let projected = completion_archives(&outcome, &outputs, &groups, &failures);
        assert_eq!(completion_failed_archive(&projected[&key(head)], &failures).unwrap().failure.as_ref().unwrap().kind, FailureKind::Damaged);
        assert!(completion_failed_archive(&projected[&key(other)], &failures).is_none());
        assert!(output_owner(&outputs, &key(Path::new(r"C:\watch\outer-other\inner.zip"))).is_none());
        // Error projection uses this same durable owner even after its nested
        // source disappears. No new filesystem observation is involved.
        assert_eq!(output_owner(&outputs, &key(Path::new(r"C:\watch\outer\gone.zip"))), alias.to_str());
    }

    #[test]
    fn admitted_password_scope_survives_family_head_retry_and_promoted_recovery() {
        use crate::watch_store::{NativeWatchState, NativeWatchOperations, PendingObservation};
        let state = NativeWatchState::new();
        let a = Path::new(r"C:\watch\A");
        let b = Path::new(r"C:\watch\B");
        // The admitted path, not the eventual family head, fixes all Watch
        // input forms. Different directories cannot share the dispatch key.
        for filename in ["single.zip", "family.part2.rar", "family.7z.002", "family.z01", "wrapped.enc"] {
            let tail = b.join(filename);
            let head = a.join(filename);
            assert_eq!(candidate_password_scope(&state, tail.to_str().unwrap(), None), b);
            assert_eq!(candidate_password_scope(&state, head.to_str().unwrap(), None), a);
        }
        let path = r"C:\watch\A\family.part1.rar";
        let candidate = WatchCandidateRow {
            path: path.into(), size: 42, mtime: 1.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: String::new(), change_usn: 0, change_reasons: 0,
                change_reasons_without_close: 0, change_reasons_known: false,
                change_reason_error: String::new(),
            },
        };
        let passwords = crate::core::passwords::PasswordSnapshot::default();
        let user_signature = user_password_signature(&[]);
        for kind in [FailureKind::PasswordRequired, FailureKind::MissingVolume] {
            let mut outcome = Outcome::default();
            outcome.archives.push(completion_archive(path, 1, Some(kind)));
            let failures = outcome.input_failures();
            let failure = &failures[&crate::path_keys::path_key(path)];
            let entry = make_entry(&candidate, "blocked", Some(failure), None,
                &passwords, &user_signature, None, None, b);
            assert_eq!(entry.failure_payload["password_scope_dir"], json!(b));
            if failure.password.is_some() {
                assert_eq!(entry.failure_payload["password_signature"],
                    json!(password_source_signature(&user_signature, &passwords.scope_signature(b))));
            }
            let mut operations = NativeWatchOperations::empty();
            operations.put_entry(entry);
            state.apply(&operations);
            // A directory-password update must compare B's signature, and
            // the subsequent retry must retain B even though its path is A.
            assert_eq!(candidate_password_scope(&state, path, None), b);
        }
        let promoted = Recovery {
            scope: NativeDiscoveryScope::new(r"C:\output\nested".into(), Some(0), Vec::new()),
            password_scope: b.to_owned(),
        };
        assert_eq!(candidate_password_scope(&state, r"C:\output\nested\inner.zip", Some(&promoted)), b);
        let pending_path = r"C:\watch\A\pending.zip";
        let (operations, _) = state.pending_operations([(
            PendingObservation(pending_path.into(), 42, 1.0, String::new(), 0),
            r"C:\watch".into(), None,
        )], false, b.to_str().unwrap(), false, true, None).unwrap();
        state.apply(&operations);
        assert_eq!(candidate_password_scope(&state, pending_path, None), b);
        // An existing retry entry takes precedence over pending, as in main.
        let mut entry = observed_entry(&candidate, "failed_password", None);
        entry.path = pending_path.into();
        entry.failure_payload.insert("password_scope_dir".into(), json!(a));
        let mut operations = NativeWatchOperations::empty();
        operations.put_entry(Arc::new(entry));
        state.apply(&operations);
        assert_eq!(candidate_password_scope(&state, pending_path, None), a);
    }

    #[test]
    fn promoted_carrier_segments_share_blockers_without_hiding_independent_terminal_children() {
        let owner = Path::new(r"C:\Watch\outer.zip");
        let promoted_path = r"C:\Watch\carrier.bin";
        let mut partial = completion_archive(promoted_path, 2, Some(FailureKind::MissingVolume));
        partial.partial = true;
        partial.promoted = true;
        let mut terminal = completion_archive(promoted_path, 2, Some(FailureKind::Damaged));
        terminal.promoted = true;
        let mut blocked = completion_archive(promoted_path, 2, Some(FailureKind::PasswordRequired));
        blocked.promoted = true;
        let mut outcome = Outcome::default();
        outcome.archives = vec![completion_archive(owner.to_str().unwrap(), 1, None), partial, terminal, blocked];
        let outputs = BTreeMap::from([
            (key(Path::new(promoted_path)), owner.to_string_lossy().into_owned()),
            (key(Path::new(r"C:\Watch\outer")), owner.to_string_lossy().into_owned()),
        ]);
        let failures = outcome.input_failures();
        let carrier = &failures[&crate::path_keys::path_key(promoted_path)];
        assert!(carrier.retryable());
        assert!(carrier.password.is_some() && carrier.missing.is_some());
        assert_eq!(carrier.failure().unwrap().kind, FailureKind::MissingVolume);
        let candidate = WatchCandidateRow {
            path: promoted_path.into(), size: 42, mtime: 1.0,
            observation: crate::filesystem::WatchFileObservation {
                file_id: String::new(), change_usn: 0, change_reasons: 0,
                change_reasons_without_close: 0, change_reasons_known: false,
                change_reason_error: String::new(),
            },
        };
        let passwords = crate::core::passwords::PasswordSnapshot::default();
        let entry = make_entry(&candidate, "carrier blocked", Some(carrier), None,
            &passwords, &user_password_signature(&[]), None, None, Path::new(promoted_path).parent().unwrap());
        assert_eq!(entry.status, "suspended_missing_volume");
        assert_eq!(entry.failure_payload["blockers"], json!(["missing_volume", "password"]));
        assert_eq!(entry.failure_payload["password_signature"],
            json!(password_source_signature(&user_password_signature(&[]), &passwords.scope_signature(Path::new(promoted_path).parent().unwrap()))));
        let retry_paths = outcome.archives.iter().filter(|archive| promoted_retry(archive, &failures))
            .map(|archive| key(&archive.path)).collect::<HashSet<_>>();
        assert_eq!(retry_paths.len(), 1, "one physical retry retains all logical receipts");
        let projected = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
        assert!(completion_failed_archive(&projected[&key(owner)], &failures).is_none());
        // A terminal failure in another physical child still fails the owner.
        outcome.archives.push(completion_archive(r"C:\Watch\outer\broken.zip", 2, Some(FailureKind::Unsupported)));
        let failures = outcome.input_failures();
        let projected = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
        assert_eq!(completion_failed_archive(&projected[&key(owner)], &failures).unwrap().failure.as_ref().unwrap().kind, FailureKind::Unsupported);
        outcome.archives.pop();
        // Without a successful promotion, retain the owner's retry checkpoint.
        for archive in outcome.archives.iter_mut().skip(1) { archive.promoted = false; }
        let failures = outcome.input_failures();
        let projected = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
        let failed = completion_failed_archive(&projected[&key(owner)], &failures).unwrap();
        assert_eq!(failures[&crate::path_keys::path_key(&failed.path.to_string_lossy())].failure().unwrap().kind, FailureKind::MissingVolume);
        // All-accepted partial evidence is successful, not a new blocker.
        outcome.archives.truncate(2);
        let failures = outcome.input_failures();
        let projected = completion_archives(&outcome, &outputs, &HashMap::new(), &failures);
        assert!(completion_failed_archive(&projected[&key(owner)], &failures).is_none());
        assert!(!failures[&crate::path_keys::path_key(promoted_path)].retryable());
    }

    #[test]
    fn promoted_retry_handoff_keeps_descendant_checkpoints_after_owner_retirement() {
        // The carrier receipt alone cannot prevent a nested accepted partial
        // from being extracted again. Exercise durable handoff and reopen,
        // while ensuring an unrelated output is not kept under this blocker.
        let owner = crate::test_support::temp_file("watch_promotion_handoff", b"outer archive");
        let root = owner.with_extension("state");
        let segment = root.join("retained");
        let child_output = segment.join("nested");
        let unrelated = root.join("unrelated");
        fs::create_dir_all(&child_output).unwrap();
        fs::create_dir_all(&unrelated).unwrap();
        let carrier = root.join("carrier.bin");
        let nested = segment.join("nested.zip");
        fs::write(&carrier, b"carrier archive").unwrap();
        fs::write(&nested, b"nested archive").unwrap();
        let receipt = |source: &Path, output: &Path, partial: bool| {
            let input = crate::io::archive_state::ArchiveInput::file(
                source.to_string_lossy().into_owned(), "zip".into(), "nested".into(),
            );
            serde_json::from_value::<crate::pipeline::InputCheckpoint>(json!({
                "schema_version":1,"carrier":source,
                "input":input,
                "sources":[{"path":source,"generation":capture_file_generation(source).unwrap().persisted()}],
                "output":output,
                "container":null,"files":1,"bytes":4,"encrypted":false,"discovery_source":"direct",
                "failure":partial.then(|| json!({
                    "partial":true,"password_signature":null,
                    "failure":{"kind":"damaged","message":"accepted recovery"},
                    "complete_files":1})),
            })).unwrap()
        };
        let checkpoints = vec![receipt(&carrier, &segment, false), receipt(&nested, &child_output, true),
            receipt(&owner, &unrelated, false)];
        let owner_text = owner.to_str().unwrap();
        let carrier_text = carrier.to_str().unwrap();
        {
            let journal = journal::Journal::open(&root, 7).unwrap();
            journal.commit(true, |state| {
                let (operations, _) = state.pending_operations(
                    [(PendingObservation(owner_text.into(), 13, 1.0, String::new(), 0), String::new(), None)],
                    false, "", false, true, None,
                )?;
                Ok(operations)
            }).unwrap();
            let mut blocker = crate::watch_store::EntryRecord {
                path: carrier_text.into(), size: 15, mtime: 1.0, file_id: String::new(),
                change_usn: 0, status: "failed_password".into(), last_error: "blocked".into(),
                attempt_count: 1, failure_kind: "password_required".into(),
                failure_stage: "extraction".into(),
                failure_payload: json!({"blockers":["password"]}).as_object().unwrap().clone(),
                last_attempt_at: 1.0,
            };
            blocker.failure_payload.insert("input_checkpoints".into(), serde_json::to_value(
                promoted_checkpoints(&checkpoints, &[carrier.clone()])).unwrap());
            journal.commit(true, |_| {
                let mut operations = NativeWatchOperations::empty();
                operations.put_entry(Arc::new(blocker));
                operations.extend(NativeWatchOperations::finish_pending(owner_text, None));
                Ok(operations)
            }).unwrap();
            journal.flush().unwrap();
        }
        {
            let journal = journal::Journal::open(&root, 7).unwrap();
            assert!(input_checkpoints(journal.state(), owner_text).next().is_none());
            let retained = input_checkpoints(journal.state(), carrier_text).collect::<io::Result<Vec<_>>>().unwrap();
            assert_eq!(retained.len(), 2);
            let nested_receipt = retained.iter().find(|checkpoint| checkpoint.entry() == nested).unwrap();
            let nested_receipt = serde_json::to_value(nested_receipt).unwrap();
            assert_eq!(nested_receipt["failure"]["failure"]["kind"], "damaged");
            assert_eq!(nested_receipt["failure"]["partial"], true);
            assert_eq!(nested_receipt["failure"]["complete_files"], 1);
            assert!(!retained.iter().any(|checkpoint| checkpoint.output() == unrelated));
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(owner).unwrap();
    }

    #[test]
    fn configured_passwords_participate_in_watch_blocker_signatures() {
        let builtin = "a55be77812b08557859dab8291a7ac45";
        assert_eq!(password_source_signature(&user_password_signature(&[]), builtin), "1dc1efb66b9a5c864c8abd4d5e769223");
        assert_ne!(password_source_signature(&user_password_signature(&["new password".into()]), builtin),
            password_source_signature(&user_password_signature(&[]), builtin));
        assert_ne!(password_source_signature(&user_password_signature(&["new password".into()]), builtin),
            password_source_signature(&user_password_signature(&["new password".into()]), "changed builtin"));
    }

    #[test]
    fn admission_round_is_bounded_ordered_and_leaves_backlog_untouched() {
        let now = Instant::now();
        let old = now - std::time::Duration::from_secs(1);
        let mut due = (0..8).map(|index| ((old, format!("input-{index}")), ()))
            .collect::<BTreeMap<_, _>>();
        due.insert((now + std::time::Duration::from_secs(1), "future".into()), ());
        let original = due.clone();
        let selected = due_admissions(&due, now, 2, |path| path != "input-0" && path != "input-2");
        assert_eq!(selected.iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>(),
            ["input-1", "input-3"]);
        assert_eq!(due, original, "selection must not remove durable backlog or change its order");
        assert!(due_admissions(&due, now, 0, |_| panic!("full window probed an input")).is_empty());
        for entry in selected { due.remove(&entry); }
        assert_eq!(due_admissions(&due, now, 2, |path| path != "input-0" && path != "input-2")
            .iter().map(|(_, path)| path.as_str()).collect::<Vec<_>>(), ["input-4", "input-5"]);
        assert_eq!(due_admissions(&due, now, usize::MAX, |_| true).len(), 6);
    }

    #[test]
    fn drain_wakes_after_stop_cancellation_and_panicking_batch_completion() {
        let hub = Arc::new(Hub::new());
        hub.stop();
        let (waiter, _) = mpsc::sync_channel(1);
        assert!(!hub.queue_once(CommandReply::Sync(waiter)));
        let (send, receive) = mpsc::channel();
        let worker_hub = Arc::clone(&hub);
        let waiter = thread::spawn(move || {
            let cancelled = worker_hub.wait_drain(false);
            assert!(cancelled.completed.is_empty());
            assert!(worker_hub.cancelled.load(Ordering::Acquire));
            send.send(()).unwrap();
            // An already-observed cancellation must not spin through drain.
            let completed = worker_hub.wait_drain(true);
            assert_eq!(completed.completed, ["panicking-batch"]);
        });
        hub.cancel();
        receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        // Exercise the actual owned-request boundary, not an OS-thread mock:
        // a blocked final report must not block another request, and unwinding
        // its callback must still wake Watch drain after cancellation.
        struct Silent;
        impl Observer for Silent { fn notify(&self, _: Event) {} }
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let cancelled_request = || {
            let mut request = Request::new(Vec::new(), Mode::Extract);
            request.origin = Origin::Watch;
            request.cancel.cancel();
            request
        };
        let completion = BatchCompletion { hub: Arc::clone(&hub), batch: Some("panicking-batch".into()) };
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let failed = engine.submit(cancelled_request(), Arc::new(Silent), move |result| {
            assert!(crate::io::cancellation::is_cancellation(&result.unwrap_err()));
            entered.send(()).unwrap();
            released.recv().unwrap();
            panic!("a batch failed before returning its result");
        });
        failed.on_ready(move || drop(completion));
        entering.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(!failed.is_finished());
        let (progress, progressed) = mpsc::channel();
        let independent = engine.submit(cancelled_request(), Arc::new(Silent), move |_| {
            progress.send(()).unwrap();
        });
        let responsive = progressed.recv_timeout(std::time::Duration::from_secs(5));
        release.send(()).unwrap();
        assert!(failed.join().is_err());
        independent.join().unwrap();
        responsive.expect("a blocked completion report held the shared request driver");
        waiter.join().unwrap();
        let hub = Hub::new();
        hub.cancel();
        assert!(hub.wait_drain(false).completed.is_empty());
    }

    #[test]
    fn empty_watch_defers_rules_until_first_root_activation() {
        let mut raw: Value = serde_json::from_str(include_str!("../../../../sunpack_advanced_config.json")).unwrap();
        raw["filesystem"]["scan_filters_enabled"] = json!(true);
        raw["filesystem"]["scan_filters"] = json!([{
            "name": "blacklist", "enabled": true,
            "full_names": [{"value": "[", "regex": true}]
        }]);
        let config = Config::parse(&raw).unwrap();
        assert!(watch_scan_options(&config, false).unwrap().is_none());
        // Root activation compiles the same ordinary rules for normal and
        // all-deep configurations; removing the last root disables compilation.
        assert!(watch_scan_options(&config, true).is_err());
        assert!(watch_scan_options(&config, false).unwrap().is_none());
        raw["filesystem"]["scan_filters"][0]["full_names"][0]["value"] = json!("valid");
        assert!(watch_scan_options(&Config::parse(&raw).unwrap(), true).unwrap().is_some());
    }

    #[test]
    fn policy_drain_preserves_next_generation_notifications_without_applying_passwords() {
        let hub = Hub::new();
        let (reload, reload_result) = mpsc::sync_channel(1);
        let (once, once_result) = mpsc::sync_channel(1);
        hub.queue_reload(Some(CommandReply::Sync(reload)));
        assert!(hub.queue_once(CommandReply::Sync(once)));
        hub.update(|signals| {
            signals.root_changed("old-root", Some(vec![PathBuf::from("archive.zip")]));
            signals.password_changed = true;
        });
        hub.batch_completed("old-request".into());
        let drained = hub.wait_drain(false);
        assert_eq!(drained.completed, ["old-request"]);
        assert!(!drained.password_changed);
        assert!(!hub.stopped.load(Ordering::Acquire));
        let pending = hub.wait(None);
        assert!(pending.reload);
        assert!(pending.password_changed);
        assert!(pending.changed_roots.contains_key("old-root"));
        assert!(reload_result.try_recv().is_err());
        assert!(once_result.try_recv().is_err());
        pending.reload_waiters.into_iter().next().unwrap().send(Ok(true)).unwrap();
        pending.once.into_iter().next().unwrap().send(Ok(())).unwrap();
        assert!(reload_result.recv().unwrap().unwrap());
        once_result.recv().unwrap().unwrap();
    }

    #[test]
    fn concurrent_stop_keeps_the_draining_generation_visible_to_start() {
        use std::future::Future;
        use std::task::Context;
        let watch = Watch::new(Arc::new(|| {}));
        let hub = Arc::new(Hub::new());
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        let worker_hub = Arc::clone(&hub);
        let (release, released) = mpsc::channel();
        let worker = thread::spawn(move || {
            worker_hub.wait(None);
            released.recv().unwrap();
            finished.0.complete(&Ok(0));
            Ok(())
        });
        watch.generation.store(4, Ordering::Relaxed);
        *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, continuous: true, completion });
        let mut first = Box::pin(watch.stop_async());
        let mut second = Box::pin(watch.stop_async());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        // A missing worker path also proves start never tries to spawn/handshake.
        let start = block_on(watch.start_async(Path::new("."),
            Arc::new(Engine::new(PathBuf::from("unused-worker"))), false)).unwrap();
        assert_eq!(start, json!({"running":true,"started":false,"generation":4}));
        release.send(()).unwrap();
        for response in [block_on(first).unwrap(), block_on(second).unwrap()] {
            assert_eq!(response, json!({"running":false,"stopped":true,"generation":4}));
        }
        assert!(!watch.is_running());
    }

    #[test]
    fn asynchronous_reload_and_stop_release_the_shared_control_driver() {
        let watch = Arc::new(Watch::new(Arc::new(|| {})));
        let hub = Arc::new(Hub::new());
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        let worker_hub = Arc::clone(&hub);
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker = thread::spawn(move || {
            let pending = worker_hub.wait(None);
            entered.send(()).unwrap();
            released.recv().unwrap();
            // A disappearing service must wake an async reply even without send.
            drop(pending);
            worker_hub.wait(None);
            finished.0.complete(&Ok(0));
            Ok(())
        });
        *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, continuous: true, completion });
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let caller = Arc::clone(&watch);
        let reload = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { caller.reload_async().await }).unwrap();
        entering.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let caller = Arc::clone(&watch);
        let stop = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { caller.stop_async().await }).unwrap();
        let (progress, progressed) = mpsc::channel();
        let independent = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move { progress.send(()).unwrap(); }).unwrap();
        let responsive = progressed.recv_timeout(std::time::Duration::from_secs(5));
        release.send(()).unwrap();
        independent.join().unwrap();
        assert_eq!(reload.join().unwrap().unwrap()["reloaded"], false);
        assert_eq!(stop.join().unwrap().unwrap()["stopped"], true);
        responsive.expect("Watch lifecycle wait blocked another control request");
    }

    #[test]
    fn root_apply_ack_accepts_observer_first_noop_but_not_apply_failure() {
        let watch = Watch::new(Arc::new(|| {}));
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        let worker = thread::spawn(move || {
            let finished = finished;
            for result in [Ok(false), Ok(false), Err(io::Error::other("apply failed")), Err(io::Error::other("apply failed"))] {
                let signals = worker_hub.wait(None);
                assert_eq!(signals.reload_waiters.len(), 1);
                signals.reload_waiters.into_iter().next().unwrap().send(result).unwrap();
            }
            worker_hub.wait(None);
            finished.0.complete(&Ok(0));
            Ok(())
        });
        *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, continuous: true, completion });
        // FileObserver already applied the write: explicit reload is a
        // successful no-op, but the changed root command was still applied.
        assert_eq!(block_on(watch.root_change_status(true, true)).unwrap(), Some((true, 0)));
        assert_eq!(watch.reload().unwrap()["reloaded"], false);
        assert_eq!(block_on(watch.root_change_status(true, true)).unwrap_err().to_string(), "apply failed");
        assert_eq!(watch.reload().unwrap()["reloaded"], false);
        assert_eq!(block_on(watch.root_change_status(true, false)).unwrap(), Some((false, 0)));
        watch.stop().unwrap();
    }

    #[test]
    fn cancelling_shared_once_waiter_does_not_stop_continuous_watch() {
        let watch = Arc::new(Watch::new(Arc::new(|| {})));
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let (entered, wait_entered) = mpsc::channel();
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        let worker = thread::spawn(move || {
            let finished = finished;
            let pending = worker_hub.wait(None);
            assert_eq!(pending.once.len(), 1);
            entered.send(()).unwrap();
            worker_hub.wait(None);
            drop(pending);
            finished.0.complete(&Ok(0));
            Ok(())
        });
        *watch.running.lock().unwrap() = Some(Running { hub: Arc::clone(&hub), thread: worker, continuous: true, completion });
        let cancel = Cancellation::new();
        let request_cancel = cancel.clone();
        let caller_watch = Arc::clone(&watch);
        let (reply, response) = mpsc::channel();
        let caller = thread::spawn(move || {
            reply.send(caller_watch.run_once(Path::new("."),
                Arc::new(Engine::new(PathBuf::from("unused-worker"))), &request_cancel)).unwrap();
        });
        wait_entered.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        cancel.cancel();
        assert!(crate::io::cancellation::is_cancellation(&response
            .recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap_err()));
        caller.join().unwrap();
        assert!(!hub.stopped.load(Ordering::Acquire));
        assert!(watch.is_running());
        watch.stop().unwrap();
    }

    #[test]
    fn stopping_watch_allows_worker_foreground_callbacks() {
        let watch = Arc::new(Watch::new(Arc::new(|| {})));
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let worker_watch = Arc::clone(&watch);
        let completion = Arc::new(RunCompletion::default());
        let finished = FinishRun(Arc::clone(&completion));
        let worker = thread::spawn(move || {
            let finished = finished;
            worker_hub.wait(None);
            worker_watch.foreground_finished(|| {});
            finished.0.complete(&Ok(0));
            Ok(())
        });
        *watch.running.lock().unwrap() = Some(Running { hub, thread: worker, continuous: true, completion });
        let (send, receive) = mpsc::channel();
        let stop = thread::spawn(move || {
            let _ = send.send(watch.stop());
        });
        receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();
        stop.join().unwrap();
    }

    #[test]
    fn physical_completion_consumes_claimed_siblings_before_release_reobservation() {
        let group = Arc::new(SourceGroup { path: "split.001".into(), name: "split".into(),
            multipart: true, members: vec!["split.001".into(), "split.002".into(), "split.003".into()] });
        let groups: HashMap<_, _> = group.members.iter()
            .map(|path| (watch_path_key(path), Arc::clone(&group))).collect();
        let now = Instant::now();
        let mut pending = HashMap::new();
        let mut due = BTreeMap::new();
        let mut unpublished = HashSet::new();
        for (index, path) in group.members.iter().enumerate().skip(1) {
            let id = watch_path_key(path);
            let deadline = now + std::time::Duration::from_secs(index as u64);
            pending.insert(id.clone(), Pending { admission_ready: false, root: "root".into(),
                candidate: WatchCandidateRow { path: path.clone(), size: 42, mtime: 1.0,
                    observation: crate::filesystem::WatchFileObservation {
                        file_id: String::new(), change_usn: index as i64, change_reasons: 0,
                        change_reasons_without_close: 0, change_reasons_known: false,
                        change_reason_error: String::new(),
                    } },
                quiet: quiet::Activity::default(), due: deadline, force: false, recovery: None,
            });
            due.insert((deadline, id.clone()), ());
            unpublished.insert(id);
        }
        for pending in pending.values_mut() {
            for at in [0.0, 5.0, 10.0, 15.0, 20.0] {
                pending.quiet.observe(at, false, false, true);
            }
            pending.quiet.end_phase();
        }
        let changed = watch_path_key("split.003");
        let claims = groups.keys().map(|path| (path.clone(), Arc::<str>::from("owner"))).collect();
        park_claimed_deadlines(&pending, &mut due, &claims, groups.keys().cloned().collect());
        assert!(due.is_empty());
        assert_eq!(pending.len(), 2); // observations survive until generation-safe completion
        // A probe may publish just before the worker claims its captured
        // generation. Completion must not consume that newer pending value.
        let mut captured: HashMap<_, _> = pending.iter()
            .map(|(id, pending)| (id.clone(), Some(pending.candidate.clone()))).collect();
        pending.get_mut(&changed).unwrap().candidate.observation.change_usn += 1;
        pending.get_mut(&changed).unwrap().candidate.size += 1;
        let mut inputs = Vec::new();
        let mut trackers = HashMap::new();
        consume_claimed_pending(&mut pending, &mut due, &mut unpublished, &groups, &captured, &mut inputs, &mut trackers);
        let tracker = trackers.remove(&watch_path_key("split.002")).unwrap();
        let learned = tracker.summary().0;
        tracker.observe(23.5, false, false, true);
        tracker.observe(24.5, false, false, true);
        assert_eq!(tracker.summary().2, 5.0);
        assert_eq!(tracker.summary().0, learned);
        assert!(trackers.is_empty());
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "split.002");
        assert_eq!(pending.len(), 1);
        assert_eq!(unpublished, HashSet::from([changed.clone()]));
        assert!(due.is_empty());
        let queued = pending.get(&changed).unwrap();
        // The same sealed observation is also the baseline for dirty siblings
        // with no catalog/pending history. Same generation is not new work.
        let sealed = captured.remove(&changed).unwrap().unwrap();
        assert!(!quiet::changed(&sealed, &sealed));
        assert!(quiet::changed(&sealed, &queued.candidate));
        due.insert((queued.due, changed.clone()), ());
        // A late claim wake cannot remove the now-released new generation.
        park_claimed_deadlines(&pending, &mut due, &HashMap::new(), HashSet::from([changed.clone()]));
        assert_eq!(due.len(), 1);
        assert_eq!(due.keys().next().unwrap().1, changed);
    }

    #[test]
    fn admission_counts_unfinished_candidates_not_batches_or_claimed_members() {
        let marker = crate::test_support::temp_file("watch_candidate_budget", b"");
        let base = marker.with_extension("dir");
        fs::create_dir_all(&base).unwrap();
        let journal = Arc::new(journal::Journal::open(&base.join("state"), 7).unwrap());
        let settings = Arc::new(Config::default());
        let mut scheduler = Scheduler {
            candidate_diagnostics: CandidateDiagnostics::default(), admission_checkpoint: None,
            cwd: base.clone(), root_file: base.join(ROOTS_FILE),
            roots: BTreeMap::new(), available_roots: HashSet::new(),
            user_password_signature: user_password_signature(&settings.user_passwords), settings,
            engine: Arc::new(Engine::new(base.join("unused-worker.exe"))),
            catalog: Arc::new(NativeWatchCatalog::new(journal.state(), None)), journal,
            options: Some(NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap()),
            deep_options: NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
            passwords: BuiltinStore::shared(&base).unwrap(), hub: Arc::new(Hub::new()),
            root_observers: HashMap::new(), root_progress: RootPolicyProgress::default(),
            parent_observers: HashMap::new(), config_observers: Vec::new(),
            pending: HashMap::new(), unpublished: HashSet::new(), due: BTreeMap::new(),
            active: HashMap::new(), active_paths: HashMap::new(), continuous: false, tray_enabled: false,
            tray: None, monitor: None, toast: None, cache_deadline: None,
            external: Arc::new(Mutex::new(None)), _lease: BrokerLease,
        };
        let limit = scheduler.admission_available();
        let driver = crate::pipeline::Scheduler::new();
        let batch = |id, names: Vec<String>, failed: bool| {
            let cancel = Cancellation::new();
            let request = driver.submit(id, Origin::Watch, &cancel, move |_| Box::pin(async move {
                Completed { cancelled: !failed,
                    result: Err(io::Error::other("test request settled")),
                    promoted: HashMap::new(), outputs: BTreeMap::new() }
            }));
            Active {
                deep: false, root: String::new(), recovery: None, password_scope: base.clone(),
                passwords: Arc::default(),
                inputs: names.into_iter().map(|path| (watch_path_key(&path), WatchCandidateRow {
                    path, size: 1, mtime: 1.0,
                    observation: crate::filesystem::WatchFileObservation {
                        file_id: String::new(), change_usn: 0, change_reasons: 0,
                        change_reasons_without_close: 0, change_reasons_known: false,
                        change_reason_error: String::new(),
                    },
                })).collect(),
                quiet: HashMap::new(), dirty: HashSet::new(), cancel,
                groups: Arc::default(), claimed: Arc::default(), toast: None, request,
            }
        };
        let names = (0..limit).map(|index| base.join(format!("{index}.zip")).to_string_lossy().into_owned()).collect::<Vec<_>>();
        scheduler.active_paths.extend(names.iter().map(|path| (watch_path_key(path), Arc::from("first"))));
        scheduler.active.insert("first".into(), batch(1, names.clone(), false));
        assert_eq!(scheduler.admission_available(), 0, "one full batch occupies the whole candidate window");
        assert!(scheduler.next_admission().is_none());
        // A completed head owns two admitted aliases; a third discovered
        // member never consumed an admission slot. Remaining siblings stay live.
        let head = Path::new(&names[0]);
        let discovered = base.join("not-admitted.002");
        scheduler.hub.claims.lock().unwrap().insert(key(&discovered), Arc::from("first"));
        assert_eq!(scheduler.admission_available(), 0, "discovered physical claims do not consume candidate slots");
        let group = Arc::new(SourceGroup { path: head.into(), name: "family".into(), multipart: true,
            members: vec![names[0].clone(), names[1].clone(), discovered.to_string_lossy().into_owned()] });
        let root = || RootCompleted {
            reply: Arc::default(), batch: "first".into(), id: 1, path: head.into(),
            groups: group.members.iter().map(|member| (watch_path_key(member), Arc::clone(&group))).collect(),
            completed: Completed { cancelled: false, result: Ok(Outcome::default()),
                promoted: HashMap::new(), outputs: BTreeMap::new() },
        };
        scheduler.complete_root(root()).unwrap();
        assert_eq!(scheduler.admission_available(), 2);
        assert_eq!(scheduler.active["first"].inputs.len(), limit - 2);
        scheduler.complete_root(root()).unwrap();
        assert_eq!(scheduler.admission_available(), 2, "repeated root notification cannot refund twice");
        scheduler.active_paths.extend(names[..2].iter().map(|path| (watch_path_key(path), Arc::from("second"))));
        scheduler.active.insert("second".into(), batch(2, vec![names[0].clone(), names[1].clone()], true));
        assert_eq!(scheduler.admission_available(), 0, "second batch consumes only the freed candidate slots");
        scheduler.complete_requests(vec!["first".into()]).unwrap();
        assert_eq!(scheduler.admission_available(), limit - 2, "cancellation returns only unfinished siblings");
        scheduler.complete_requests(vec!["second".into()]).unwrap();
        assert_eq!(scheduler.admission_available(), limit, "failed batch returns all remaining owners");
        scheduler.complete_requests(vec!["second".into()]).unwrap();
        assert_eq!(scheduler.admission_available(), limit);
        // A persistence error in the first completion must not abandon the
        // following cancellation projection (which releases its physical claims).
        scheduler.active_paths.insert(watch_path_key(&names[0]), Arc::from("faulted"));
        scheduler.active_paths.insert(watch_path_key(&names[1]), Arc::from("cancelled"));
        scheduler.active.insert("faulted".into(), batch(3, vec![names[0].clone()], true));
        scheduler.active.insert("cancelled".into(), batch(4, vec![names[1].clone()], false));
        scheduler.journal.fail_for_test();
        assert!(scheduler.complete_requests(vec!["faulted".into(), "cancelled".into()]).is_err());
        assert!(scheduler.active_paths.is_empty(), "failed sibling suppressed cancellation projection");
        scheduler.options = None;
        assert_eq!(scheduler.admission_available(), 0);
        drop(scheduler);
        fs::remove_dir_all(base).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn root_completion_wakes_watch_and_drain_before_batch_exit() {
        // A batch completion test cannot detect a root-only wake being ignored
        // while another native task is still running.
        fn root() -> RootCompleted {
            RootCompleted { reply: Arc::default(), batch: "batch".into(), id: 1, path: "a.zip".into(), groups: HashMap::new(),
                completed: Completed { cancelled: false, result: Ok(Outcome::default()),
                    promoted: HashMap::new(), outputs: BTreeMap::new() } }
        }
        let hub = Arc::new(Hub::new());
        let waiting = Arc::clone(&hub);
        let (send, receive) = mpsc::channel();
        let thread = thread::spawn(move || { send.send(waiting.wait(None)).unwrap(); });
        hub.root_completed(root());
        let signals = receive.recv_timeout(std::time::Duration::from_secs(5)).expect("root did not wake Watch");
        assert_eq!(signals.roots.len(), 1);
        assert!(signals.completed.is_empty());
        thread.join().unwrap();
        hub.stop();
        hub.root_completed(root());
        hub.batch_completed("batch".into());
        let signals = hub.wait_drain(true);
        assert_eq!(signals.roots.len(), 1);
        assert_eq!(signals.completed, ["batch"]);
    }

    #[test]
    fn shared_tail_completion_preserves_other_logical_and_not_yet_claimed_owners() {
        let a = Path::new(r"C:\watch\a.001");
        let b = Path::new(r"C:\watch\b.001");
        let tail = Path::new(r"C:\watch\shared.002");
        let group = |head: &Path| Arc::new(SourceGroup { path: head.into(), name: "head".into(),
            multipart: true, members: vec![head.to_string_lossy().into_owned(), tail.to_string_lossy().into_owned()] });
        let mut groups = SourceGroups::default();
        groups.insert(group(a));
        groups.insert(group(b));
        groups.planned.extend([key(a), key(b), key(tail)]);
        let completed = groups.take(&key(a));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[&key(a)].path, a);
        assert_eq!(groups.roots[&key(b)].path, b);
        assert_eq!(groups.members[&key(tail)], 1);

        // The independently admitted tail hasn't reached discovery yet. B
        // cannot retire its pending owner either, despite being last consumer.
        let completed = groups.take(&key(b));
        assert_eq!(completed.len(), 1);
        assert!(!completed.contains_key(&key(tail)));
        assert!(groups.members.is_empty());
        // An unadmitted physical sibling is transferred only by the final
        // consumer; it is never projected through the other head's group.
        groups.planned = HashSet::from([key(a), key(b)]);
        groups.insert(group(a)); groups.insert(group(b));
        assert!(!groups.take(&key(a)).contains_key(&key(tail)));
        assert_eq!(groups.take(&key(b))[&key(tail)].path, b);
        assert!(groups.roots.is_empty());
        assert!(groups.members.is_empty());
        groups.insert(group(a)); groups.insert(group(b));
        let aliases = groups.into_aliases();
        assert!(!aliases.contains_key(&key(tail)));
        assert_eq!(aliases[&key(a)].path, a);
        assert_eq!(aliases[&key(b)].path, b);
        let claimed = ClaimedSources {
            candidates: [(key(a), None), (key(b), None), (key(tail), None)].into_iter().collect(),
            ..Default::default()
        };
        // The shared tail is absent from logical projection, but final
        // retirement must release its claim and rearm any parked generation.
        assert!(completion_claims(None, &aliases, &claimed).any(|path| path == &key(tail)));
        assert!(!completion_claims(Some(1), &aliases, &claimed).any(|path| path == &key(tail)));
    }

    #[test]
    fn root_handoff_preserves_alias_aggregates_and_live_shared_tail_owners() {
        use std::future::Future;
        use std::task::{Context, Poll, Wake, Waker};
        struct NoWake;
        impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
        let marker = crate::test_support::temp_file("root_handoff", b"");
        let directory = marker.with_extension("journal");
        let head = Path::new(r"C:\watch\a.001");
        let alias = Path::new(r"C:\watch\a.002");
        let other = Path::new(r"C:\watch\b.zip");
        let output = Path::new(r"C:\watch\a");
        let other_output = Path::new(r"C:\watch\b");
        let promoted = Path::new(r"C:\watch\nested.zip");
        let group = Arc::new(SourceGroup { path: head.into(), name: "a".into(), multipart: true,
            members: vec![head.to_string_lossy().into_owned(), alias.to_string_lossy().into_owned()] });
        let hub = Arc::new(Hub::new());
        let mut observer = WatchObserver {
            deep: false,
            journal: Arc::new(journal::Journal::open(&directory, 7).unwrap()),
            owners: HashMap::from([(key(alias), alias.to_string_lossy().into_owned())]),
            output_scopes: Arc::from([]),
            outputs: Mutex::new(ObservedOutputs::from(BTreeMap::from([(key(output), alias.to_string_lossy().into_owned()),
                (key(other_output), other.to_string_lossy().into_owned())]))),
            batch: Arc::from("batch"), toast: None, hub: Arc::clone(&hub),
            groups: Arc::new(Mutex::new({ let mut groups = SourceGroups::default(); groups.insert(group); groups })),
            claimed: Arc::default(), promoted: Mutex::new(HashMap::from([(key(promoted), None)])),
        };
        // Cancellation winning the mutex first must not turn an already
        // durable root into an interrupted root when its report comes back.
        observer.claimed.lock().unwrap().cancelled = true;
        let mut outcome = Outcome::default();
        outcome.archives.push(completion_archive(head.to_str().unwrap(), 1, None));
        let mut child = completion_archive(promoted.to_str().unwrap(), 2, Some(FailureKind::WrongPassword));
        child.promoted = true;
        outcome.archives.push(child);
        let allocation = outcome.archives.as_ptr();
        let waker = Waker::from(Arc::new(NoWake));
        // Tail-only admission can discover several heads. Preserve the whole
        // result for request aggregation rather than retiring that alias early.
        let mut deferred = Box::pin(observer.root_finished(1, head, outcome));
        let Poll::Ready(Ok(outcome)) = deferred.as_mut().poll(&mut Context::from_waker(&waker)) else {
            panic!("alias-owned roots must return their aggregate without a handoff");
        };
        assert_eq!(outcome.archives.as_ptr(), allocation);
        drop(deferred);
        assert_eq!(observer.outputs.lock().unwrap().paths.len(), 2);
        assert!(observer.claimed.lock().unwrap().finished.is_empty());
        // Directly admitted roots still settle independently of their peers.
        observer.owners.insert(key(head), head.to_string_lossy().into_owned());
        observer.owners.insert(key(other), other.to_string_lossy().into_owned());
        observer.roots_planned([head.to_str().unwrap(), other.to_str().unwrap()].into_iter());
        observer.groups.lock().unwrap().insert(Arc::new(SourceGroup {
            path: other.into(), name: "b".into(), multipart: true,
            members: vec![other.to_string_lossy().into_owned(), alias.to_string_lossy().into_owned()],
        }));
        *observer.outputs.lock().unwrap() = ObservedOutputs::from(BTreeMap::from([
            (key(output), head.to_string_lossy().into_owned()),
            (key(other_output), other.to_string_lossy().into_owned()),
        ]));
        let mut future = Box::pin(observer.root_finished(1, head, outcome));
        assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let signals = hub.wait(None);
        let root = signals.roots.into_iter().next().unwrap();
        assert_eq!(root.completed.result.as_ref().unwrap().archives.as_ptr(), allocation);
        assert_eq!(root.groups.len(), 1);
        assert_eq!(root.groups[&key(head)].path, head);
        assert_eq!(root.completed.outputs.len(), 1);
        assert_eq!(root.completed.promoted.len(), 1);
        assert_eq!(observer.groups.lock().unwrap().roots[&key(other)].path, other);
        assert_eq!(observer.outputs.lock().unwrap().paths.len(), 1);
        assert!(!observer.claimed.lock().unwrap().finished.contains(&key(alias)));
        assert!(observer.claimed.lock().unwrap().finished.contains(&key(head)));
        root.reply.complete(root.completed.result);
        let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
            panic!("disabled notifications must not enqueue a report wait");
        };
        assert!(result.unwrap().archives.is_empty());
        drop(future);
        drop(observer);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn cancelling_claimed_volumes_preserves_a_replaced_sibling_generation() {
        let head = crate::test_support::temp_file("cancel_head", b"first volume");
        let sibling = crate::test_support::temp_file("cancel_sibling", b"old volume");
        let late = sibling.with_extension("late");
        let unreadable = format!("{}\0", head.display());
        let members = vec![
            head.to_string_lossy().into_owned(),
            sibling.to_string_lossy().into_owned(),
            late.to_string_lossy().into_owned(),
            unreadable.clone(),
        ];
        let mut claimed = ClaimedSources::default();
        claimed.capture(&members).unwrap();
        fs::write(&sibling, b"a newer independently queued volume").unwrap();
        fs::write(&late, b"a volume arriving after the original claim").unwrap();
        // Repeated claims and cancellation must retain the generation the
        // request started with, rather than consuming the replacement.
        claimed.capture(&members).unwrap();
        let current = watch_candidate_for_path(&sibling, None).unwrap().unwrap();
        assert!(quiet::changed(claimed.candidates[&key(&sibling)].as_ref().unwrap(), &current));
        assert!(claimed.candidates[&key(&late)].is_none());
        assert!(claimed.candidates[&watch_path_key(&unreadable)].is_none());
        claimed.cancelled = true;
        assert!(crate::io::cancellation::is_cancellation(&claimed.capture(&members).unwrap_err()));
        fs::remove_file(head).unwrap();
        fs::remove_file(sibling).unwrap();
        fs::remove_file(late).unwrap();
    }

    #[test]
    fn configuration_candidates_remain_subscribed_after_deletion() {
        let marker = crate::test_support::temp_file("config_recreation", b"");
        let directory = marker.with_extension("dir");
        fs::create_dir(&directory).unwrap();
        let config = directory.join("sunpack_advanced_config.json");
        fs::write(&config, b"{}").unwrap();
        let sources = config::ConfigSources::default();
        assert!(config::watch_paths(&directory, &sources).contains(&config));
        fs::remove_file(&config).unwrap();
        let paths = config::watch_paths(&directory, &sources);
        assert!(paths.contains(&config));
        // Arm before recreating: verifies actual notification delivery, with
        // a bounded receive only as a test failure guard, never idle polling.
        let (send, receive) = mpsc::channel();
        let observer = FileObserver::start(&directory, false, move |names| {
            let _ = send.send(names);
        }).unwrap();
        fs::write(&config, b"{}").unwrap();
        let names = receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();
        assert!(names.iter().any(|name| name.eq_ignore_ascii_case("sunpack_advanced_config.json")));
        drop(observer);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn restored_checkpoint_routes_nested_outputs_to_the_durable_owner() {
        let source = crate::test_support::temp_file("watch_checkpoint_owner", b"outer archive");
        let directory = source.with_extension("state");
        let container = directory.join("output");
        let output = container.join("logical-input");
        fs::create_dir_all(&output).unwrap();
        let owner = source.to_str().unwrap();
        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            journal.commit(true, |state| {
                state.pending_operations(
                    [(PendingObservation(owner.to_owned(), 13, 1.0, String::new(), 0),
                        String::new(), None)],
                    false, "", false, true, None,
                ).map(|(operations, _)| operations)
            }).unwrap();
            journal.commit(true, |state| {
                Ok(state.output_operation(owner, owner.to_owned(),
                    container.to_str().unwrap().to_owned(), None, None)?.unwrap())
            }).unwrap();
            journal.commit(true, |state| {
                let mut operations = state.output_operation(owner, owner.to_owned(),
                    container.to_str().unwrap().to_owned(), Some(true), None)?.unwrap();
                let candidate = watch_candidate_for_path(&source, None)?.unwrap();
                let mut blocker = observed_entry(&candidate, "failed_password", None);
                blocker.failure_payload.insert("input_checkpoints".into(), json!([{
                    "schema_version":1,"carrier":source,
                    "input":crate::io::archive_state::ArchiveInput::file(
                        source.to_string_lossy().into_owned(), "zip".into(), "logical-input".into(),
                    ),
                    "sources":[{"path":source,"generation":capture_file_generation(&source)?.persisted()}],
                    "output":output,
                    "container":container,
                    "files":1,"bytes":9,"encrypted":false,"discovery_source":"direct",
                }]));
                operations.put_entry(Arc::new(blocker));
                Ok(operations)
            }).unwrap();
            journal.flush().unwrap();
        }
        {
            let journal = Arc::new(journal::Journal::open(&directory, 7).unwrap());
            let mut outputs = BTreeMap::new();
            let checkpoints = restore_checkpoints(journal.state(), owner, &mut outputs).unwrap();
            assert_eq!(checkpoints.len(), 1);
            let observer = WatchObserver {
                deep: false,
                journal: Arc::clone(&journal),
                owners: HashMap::from([(key(&source), owner.to_owned())]),
                output_scopes: Arc::from([NativeDiscoveryScope::new(directory.to_string_lossy().into_owned(), None, Vec::new())]),
                outputs: Mutex::new(outputs.into()),
                batch: Arc::from("restored"),
                toast: None,
                hub: Arc::new(Hub::new()),
                groups: Arc::default(),
                claimed: Arc::default(),
                promoted: Mutex::default(),
            };
            assert_eq!(observer.owner_for_path(&output.join("nested.zip")).as_deref(), Some(owner));
            // A carrier's enclosing output need not be a logical receipt's
            // output. Restoring it must not attempt an exclusive re-create.
            let nested = container.join("nested.zip");
            let nested_output = container.join("nested");
            fs::write(&nested, b"nested archive").unwrap();
            let archive = ArchiveResult {
                path: nested.clone(), format: "zip".into(), output: None, failure: None,
                files: 0, bytes: 0, encrypted: None, depth: 2, offset: 0,
                end_offset: None, volume_completeness: None, volume_attempts: None,
                source_paths: vec![nested.clone()], password: None,
                discovery_source: crate::pipeline::DiscoverySource::Direct, damage_flags: None,
                partial: false, retained: false, recovered_complete_files: 0,
                promoted: false, promotion_original_path: None, scan_layout: Default::default(),
            };
            observer.register_output(&archive, &nested_output).unwrap();
            assert!(nested_output.is_dir());
            assert_eq!(observer.owner_for_path(&nested_output).as_deref(), Some(owner));
            assert!(journal.state().pending(owner).unwrap().active_outputs
                .values().any(|path| key(Path::new(path)) == key(&nested_output)));

            // main retains zero-verified-file payload on disk but retires its
            // Watch registration with keep=false. It is not a committed tree
            // for legacy crash recovery to recursively discover.
            let failed_output = directory.join("failed-output");
            let mut failed = completion_archive(owner, 1, Some(FailureKind::Damaged));
            observer.register_output(&failed, &failed_output).unwrap();
            fs::write(failed_output.join("unverified.zip"), b"damaged bytes").unwrap();
            failed.output = Some(failed_output.clone());
            observer.after_output(&failed).unwrap();
            assert!(failed_output.join("unverified.zip").is_file());
            let pending = journal.state().pending(owner).unwrap();
            assert!(!pending.active_outputs.values().any(|path| key(Path::new(path)) == key(&failed_output)));
            assert!(!pending.committed_roots.contains(failed_output.to_str().unwrap()));
        }
        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            let failed_output = directory.join("failed-output");
            let pending = journal.state().pending(owner).unwrap();
            assert!(!pending.committed_roots.contains(failed_output.to_str().unwrap()));
            assert!(failed_output.join("unverified.zip").is_file());
        }
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn flatten_recovery_rebases_durable_output_identities() {
        let owner_file = crate::test_support::temp_file("flatten_watch_owner", b"outer archive");
        let directory = owner_file.with_extension("state");
        let real = directory.join("real");
        let alias = directory.join("junction");
        fs::create_dir_all(&real).unwrap();
        let junction = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&real).output().unwrap();
        assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stderr));
        let root = alias.join("output");
        let work = alias.join("work");
        let leaf = root.join("wrapper").join("inner");
        let owner = owner_file.to_str().unwrap();
        let root_text = root.to_str().unwrap();
        fs::create_dir_all(&leaf).unwrap();
        fs::write(leaf.join("nested.zip"), b"inner archive").unwrap();
        fs::create_dir(leaf.join("nested")).unwrap();
        fs::write(leaf.join("nested/payload"), b"extracted").unwrap();

        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            journal
                .commit(true, |state| {
                    let (operations, _) = state.pending_operations(
                        [(
                            PendingObservation(owner.to_owned(), 13, 1.0, String::new(), 0),
                            String::new(),
                            None,
                        )],
                        false,
                        "",
                        false,
                        true,
                        None,
                    )?;
                    Ok(operations)
                })
                .unwrap();
            journal
                .commit(true, |state| {
                    Ok(state
                        .output_operation(
                            owner,
                            owner.to_owned(),
                            root_text.to_owned(),
                            None,
                            None,
                        )?
                        .unwrap())
                })
                .unwrap();
            prepare_flatten(&journal, owner, &root, &work, &leaf).unwrap();
            assert_eq!(journal.state().runtime_keys("owned|").len(), 4);
            fs::rename(&root, &work).unwrap();
            journal.flush().unwrap();
        }

        {
            let journal = journal::Journal::open(&directory, 7).unwrap();
            recover_flattens(&journal, |_| true).unwrap();
            assert_eq!(fs::read(root.join("nested/payload")).unwrap(), b"extracted");
            assert!(!work.exists());
            assert!(journal.state().runtime_keys("flatten|").is_empty());
            assert_eq!(journal.state().runtime_keys("owned|").len(), 2);
            let catalog = NativeWatchCatalog::new(journal.state(), None);
            for output in [&root, &real.join("output")] {
                assert!(catalog.is_owned(output.join("nested.zip").to_str().unwrap()));
            }
            for output in [&work, &real.join("work")] {
                assert!(journal.state().owned_root(output.to_str().unwrap()).is_none());
            }
            let pending = journal.state().pending(owner).unwrap();
            assert_eq!(
                pending
                    .committed_roots
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                [root_text]
            );
            assert!(recovery_output_matches(journal.state(), &pending, root_text));
        }
        fs::remove_dir(alias).unwrap();
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(owner_file).unwrap();
    }

    #[test]
    fn flatten_keeps_physical_work_when_its_literal_junction_disappears() {
        let marker = crate::test_support::temp_file("flatten_detached_work", b"");
        let base = marker.with_extension("outputs");
        let real = base.join("real");
        let alias = base.join("junction");
        let root = real.join("output");
        let leaf = root.join("leaf");
        let work = alias.join("work");
        let physical_work = real.join("work");
        fs::create_dir_all(&leaf).unwrap();
        let junction = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&real).output().unwrap();
        assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stderr));
        let journal = journal::Journal::open(&base.join("state"), 7).unwrap();
        prepare_flatten(&journal, "", &root, &work, &leaf).unwrap();
        // Older intents had no path list. Their persisted owned aliases must
        // still prevent a detached literal path from discarding physical work.
        journal.commit(true, |state| {
            let key = format!("flatten|{}", key(&root));
            let mut record = state.runtime_record(&key).unwrap();
            record.as_object_mut().unwrap().remove("work_paths");
            state.decode_operations(&[json!({"op":"runtime","key":key,"value":record})])
        }).unwrap();
        fs::rename(&root, &work).unwrap();
        fs::rename(physical_work.join("leaf"), &root).unwrap();
        fs::remove_dir(alias).unwrap();
        finish_flatten(&journal, root.to_str().unwrap()).unwrap();
        assert_eq!(journal.state().runtime_keys("flatten|").len(), 1);
        assert!(journal.state().owned_root(physical_work.to_str().unwrap()).is_some());
        journal.commit(true, |state| Ok(state.owned_retirement_operations(
            &[NativeDiscoveryScope::new(real.to_string_lossy().into_owned(), None, Vec::new())], None,
        ))).unwrap();
        fs::remove_dir(&physical_work).unwrap();
        finish_flatten(&journal, root.to_str().unwrap()).unwrap();
        assert!(journal.state().runtime_keys("flatten|").is_empty());
        assert_eq!(journal.state().runtime_keys("owned|").len(), 1);
        drop(journal);
        fs::remove_dir_all(base).unwrap();
        fs::remove_file(marker).unwrap();
    }

}
