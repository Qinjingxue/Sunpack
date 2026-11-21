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
    GeneratedSource, Request, InputFailure,
};
use crate::postprocess::{watch_candidate_for_path, WatchCandidateRow};
use crate::scan::directory::{NativeDirectoryScanOptions, NativeWatchCatalog};
use crate::scan::scope::NativeDiscoveryScope;
use crate::watch_store::{is_path_under, recorded_file_is_absent, watch_path_key};
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
#[cfg(test)]
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod dedup;
mod dedup_hash;
mod continuation;
mod journal;
mod quiet;
#[cfg(test)]
#[path = "../../tests/unit/runtime/watch/crash_boundaries.rs"]
mod crash_boundaries;
#[cfg(test)]
#[path = "../../tests/unit/runtime/watch/admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "../../tests/unit/runtime/watch/quiet_replay.rs"]
mod quiet_replay;
#[cfg(test)]
#[path = "../../tests/unit/runtime/watch/completion_tests.rs"]
mod completion_tests;

const ROOTS_FILE: &str = "sunpack_watch_roots.txt";
const WATCH_METADATA: &str = ".sunpack_watch";
const ROOTS_LOCK: &str = "SunPackWatchRoots";

#[inline]
fn admission_now() -> Instant {
    #[cfg(test)]
    if let Some(now) = quiet_replay::now() { return now; }
    Instant::now()
}

#[inline]
fn admission_readable(path: &str) -> io::Result<bool> {
    #[cfg(test)]
    if let Some(readable) = quiet_replay::readable(path) { return Ok(readable); }
    filesystem::watch_file_is_ready(path)
}

// Seal the admitted observation while the existing readability handle excludes
// writers and renames. A probe made before the last writer closes can carry an
// older USN even when its size/mtime already describe the final contents.
fn admission_candidate(mut candidate: WatchCandidateRow, since_usn: i64) -> io::Result<(WatchCandidateRow, bool)> {
    #[cfg(test)]
    if let Some(readable) = quiet_replay::readable(&candidate.path) { return Ok((candidate, readable)); }
    let Some(snapshot) = filesystem::watch_ready_file_snapshot(
        Path::new(&candidate.path), Some(since_usn), |_, _| Ok(()))? else { return Ok((candidate, false)); };
    candidate.size = snapshot.metadata.len();
    candidate.mtime = crate::postprocess::mtime_seconds(&snapshot.metadata);
    candidate.observation = snapshot.observation();
    Ok((candidate, true))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Root {
    enabled: bool,
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

    fn scope(&self, excluded: Vec<String>) -> NativeDiscoveryScope {
        NativeDiscoveryScope::new(
            self.path.to_string_lossy().into_owned(),
            (!self.recursive).then_some(0),
            excluded,
        )
    }
}

fn root_scopes(entries: &[Root], metadata: &[String]) -> BTreeMap<String, (Root, NativeDiscoveryScope)> {
    let roots: Vec<_> = entries.iter().map(|root| (key(&root.path), root)).collect();
    let positions: HashMap<_, _> = roots.iter().enumerate()
        .map(|(index, (id, _))| (id.trim_end_matches('\\'), index)).collect();
    let mut excluded: Vec<_> = roots.iter().map(|(_, root)| {
        if root.enabled { metadata.to_vec() } else { Vec::new() }
    }).collect();
    for (id, root) in &roots {
        // Disabled roots still fence off their subtree. An explicitly enabled
        // descendant of one gets its own independent scope.
        let parent = crate::path_keys::path_ancestors(id).skip(1)
            .find_map(|ancestor| positions.get(ancestor));
        if let Some(&parent) = parent.filter(|&&index| roots[index].1.enabled) {
            excluded[parent].push(root.path.to_string_lossy().into_owned());
        }
    }
    roots.into_iter().zip(excluded).filter_map(|((id, root), excluded)| {
        root.enabled.then(|| (id, (root.clone(), root.scope(excluded))))
    }).collect()
}

fn configured_root_scopes(cwd: &Path, entries: &[Root]) -> io::Result<BTreeMap<String, (Root, NativeDiscoveryScope)>> {
    let dir = state_dir(cwd)?;
    let state = dir.to_string_lossy().into_owned();
    let resolved_state = crate::path_keys::resolved_path_key(&dir);
    let mut metadata = Vec::with_capacity(2);
    if crate::path_keys::path_key(&state) != resolved_state { metadata.push(resolved_state); }
    metadata.push(state);
    Ok(root_scopes(entries, &metadata))
}

fn root_policy_changed(
    previous: &BTreeMap<String, (Root, NativeDiscoveryScope)>,
    next: &BTreeMap<String, (Root, NativeDiscoveryScope)>,
) -> bool {
    previous.len() != next.len() || next.iter().any(|(id, (root, scope))| {
        previous.get(id).is_none_or(|(old, old_scope)| {
            !old.same_policy(root) || !old_scope.same_exclusions(scope)
        })
    })
}

fn containing_root<'a>(
    roots: &'a BTreeMap<String, (Root, NativeDiscoveryScope)>,
    path_key: &str,
) -> Option<(&'a String, &'a (Root, NativeDiscoveryScope))> {
    if roots.len() <= 1 {
        return roots.first_key_value().filter(|(_, (_, scope))| scope.contains_key(path_key));
    }
    // Keep outermost-first precedence. A drive or share root can have a
    // trailing separator in the Watch map while scope keys omit it.
    crate::path_keys::path_ancestors(path_key).filter_map(|ancestor| {
        roots.get_key_value(ancestor).or_else(|| {
            let prefix = path_key.get(..ancestor.len() + 1)?;
            prefix.ends_with('\\').then(|| roots.get_key_value(prefix)).flatten()
        }).filter(|(_, (_, scope))| scope.contains_key(path_key))
    }).last()
}

fn key(path: &Path) -> String {
    watch_path_key(&path.to_string_lossy())
}

// Expand DOS aliases at the configuration boundary, not during event lookup.
// GetLongPathName preserves junction spellings (canonicalize would redirect
// them). Resolve only the existing prefix so offline/new children stay valid.
fn configured_path(path: &Path) -> Cow<'_, Path> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
        if path.as_os_str().encode_wide().any(|unit| unit == b'~' as u16) {
            for ancestor in path.ancestors() {
                let input: Vec<_> = ancestor.as_os_str().encode_wide().chain(Some(0)).collect();
                let length = unsafe { GetLongPathNameW(input.as_ptr(), std::ptr::null_mut(), 0) };
                if length == 0 { continue; }
                let mut output = vec![0; length as usize];
                let written = unsafe { GetLongPathNameW(input.as_ptr(), output.as_mut_ptr(), length) };
                if written == 0 || written >= length { continue; }
                output.truncate(written as usize);
                let resolved = PathBuf::from(std::ffi::OsString::from_wide(&output));
                if let Ok(suffix) = path.strip_prefix(ancestor) {
                    return Cow::Owned(if suffix.as_os_str().is_empty() { resolved } else { resolved.join(suffix) });
                }
            }
        }
    }
    Cow::Borrowed(path)
}

fn root_key(path: &Path) -> String {
    let mut id = key(path);
    id.truncate(id.trim_end_matches('\\').len());
    id
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
            return cli::resolve(root, &path.to_string_lossy()).map(|path| configured_path(&path).into_owned());
        }
    }
    cli::resolve(root, value).map(|path| configured_path(&path).into_owned())
}

fn roots_path(cwd: &Path) -> io::Result<PathBuf> {
    Ok(resources::writable_data_dir(cwd)?.join(ROOTS_FILE))
}

pub(super) fn diagnostic_roots(cwd: &Path) -> io::Result<Vec<PathBuf>> {
    read_roots(&roots_path(cwd)?).map(|roots| roots.into_iter().map(|root| root.path).collect())
}

fn configuration_changes(
    files: &HashMap<String, (bool, bool)>,
    changes: Option<&[DirectoryChange]>,
) -> (bool, bool) {
    let Some(changes) = changes else {
        // Overflow/invalidated subscriptions cannot identify a single source.
        return (true, files.values().any(|(_, passwords)| *passwords));
    };
    changes.iter().filter_map(|change| files.get(&crate::path_keys::case_key(&change.name)))
        .fold((false, false), |(reload, passwords), (config, password)|
            (reload || *config, passwords || *password))
}

fn read_roots(path: &Path) -> io::Result<Vec<Root>> {
    let mut roots = read_root_records_or_empty(path)?;
    roots.retain(|root| root.enabled);
    Ok(roots)
}

fn read_root_records_or_empty(path: &Path) -> io::Result<Vec<Root>> {
    match read_root_records(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        result => result,
    }
}

fn read_root_records(path: &Path) -> io::Result<Vec<Root>> {
    let text = fs::read_to_string(path)?;
    let mut roots: Vec<Root> = Vec::new();
    let mut positions = HashMap::new();
    let cwd = std::env::current_dir()?;
    for (index, line) in text.trim_start_matches('\u{feff}').lines().flat_map(|line| line.split('\r')).enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('|').map(str::trim);
        let input = fields.next().unwrap();
        if input.is_empty() {
            continue;
        }
        let input = configured_path(&cli::resolve(&cwd, input)?).into_owned();
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
        let enabled = fields.next().and_then(|s| s.to_ascii_lowercase().parse::<bool>().ok());
        if enabled.is_none() || fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}:{}: expected input | output | deep_detect | initial_scanned | recursive | enabled",
                    path.display(),
                    index + 1
                ),
            ));
        }
        let id = root_key(&input);
        let mut root = Root {
            enabled: enabled.unwrap(),
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
        for comment in previous.trim_start_matches('\u{feff}')
            .split(['\r', '\n'])
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
            "{} | {} | {} | {} | {} | {}",
            root.path.display(),
            output,
            root.deep,
            root.scanned,
            root.recursive,
            root.enabled
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
    fn acquire() -> io::Result<Arc<Self>> {
        filesystem::watch_broker_acquire()?;
        Ok(Arc::new(Self))
    }
}

impl Drop for BrokerLease {
    fn drop(&mut self) {
        let _ = filesystem::watch_broker_release();
    }
}

// Dropping an unserved command wakes its caller.
struct CommandReply<T>(Option<Arc<Reply<T>>>);

impl<T> CommandReply<T> {
    fn send(mut self, value: io::Result<T>) {
        self.0.take().unwrap().complete(value);
    }
}
impl<T> Drop for CommandReply<T> {
    fn drop(&mut self) {
        if let Some(reply) = self.0.take() {
            reply.complete(Err(io::ErrorKind::Interrupted.into()));
        }
    }
}
fn command_reply<T: Default>() -> (CommandReply<T>, Arc<Reply<T>>) {
    let reply = Arc::new(Reply::default());
    (CommandReply(Some(Arc::clone(&reply))), reply)
}

// Concurrent stop requests can share terminal completion.
#[derive(Default)]
struct RunCompletion(Mutex<(Option<Result<(), (io::ErrorKind, String)>>, Vec<Waker>)>);
impl RunCompletion {
    fn complete(&self, result: &io::Result<()>) {
        let wakes = {
            let mut state = self.0.lock().unwrap();
            state.0 = Some(result.as_ref().copied().map_err(|e| (e.kind(), e.to_string())));
            std::mem::take(&mut state.1)
        };
        for wake in wakes { wake.wake(); }
    }
    async fn wait(&self) -> io::Result<()> {
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

#[derive(Default)]
struct WatchStatus {
    revision: AtomicU64,
    next: AtomicU64,
    waiters: Mutex<HashMap<u64, Waker>>,
    phase: Mutex<&'static str>,
    shutdown: AtomicBool,
}
impl WatchStatus {
    fn notify(&self) {
        self.revision.fetch_add(1, Ordering::AcqRel);
        let waiters = std::mem::take(&mut *self.waiters.lock().unwrap());
        for wake in waiters.into_values() { wake.wake(); }
    }

    fn remove_waiter(&self, id: u64) -> Option<Waker> {
        let mut waiters = self.waiters.lock().unwrap();
        let wake = waiters.remove(&id);
        if waiters.capacity() > 256 { crate::collections::trim_map(&mut waiters); }
        wake
    }
}
struct StatusWait<'a> { status: &'a WatchStatus, id: u64 }
impl Drop for StatusWait<'_> {
    fn drop(&mut self) { self.status.remove_waiter(self.id); }
}

pub(super) struct Watch {
    lifecycle: AsyncGate,
    status: Arc<WatchStatus>,
    running: Mutex<Option<Running>>,
    wake_host: Arc<dyn Fn() + Send + Sync>,
    external: Arc<OutputPublications>,
    generation: AtomicU64,
    last_error: Arc<Mutex<Option<String>>>,
}

// Reservations follow writer lifetime, including a Watch stop/start while a
// foreground request is still extracting. The current catalog is replaceable.
#[derive(Default)]
struct OutputPublications {
    current: RwLock<Option<ExternalOutputs>>,
    reservations: crate::watch_store::active_outputs::OutputReservations,
}

impl OutputPublications {
    fn retire(&self, journal: &Arc<journal::Journal>) {
        let retired = {
            let mut current = self.current.write().unwrap_or_else(|error| error.into_inner());
            if !current.as_ref().is_some_and(|outputs| outputs.journal.as_ptr() == Arc::as_ptr(journal)) {
                return;
            }
            current.take()
        };
        drop(retired);
    }
}

struct ExternalOutputs {
    journal: Weak<journal::Journal>,
    scopes: Arc<[NativeDiscoveryScope]>,
    catalog: Arc<NativeWatchCatalog>,
    options: NativeDirectoryScanOptions,
    hub: Weak<Hub>,
}

impl ExternalOutputs {
    fn active_journal(&self) -> Option<Arc<journal::Journal>> {
        self.journal.upgrade().filter(|journal| !journal.suspended())
    }
}

impl Watch {
    pub(super) fn new(wake_host: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            lifecycle: AsyncGate::new(),
            status: Arc::default(),
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

    pub(super) fn status_revision(&self) -> u64 { self.status.revision.load(Ordering::Acquire) }
    pub(super) fn shutdown_requested(&self) -> bool { self.status.shutdown.load(Ordering::Acquire) }
    pub(super) async fn wait_status_change(&self, revision: u64, cancel: &Cancellation) -> io::Result<()> {
        let guard = StatusWait { status: &self.status, id: self.status.next.fetch_add(1, Ordering::Relaxed) };
        let status = Arc::downgrade(&self.status);
        let id = guard.id;
        let _subscription = cancel.subscribe(move || {
            if let Some(waker) = status.upgrade().and_then(|status| status.remove_waiter(id)) {
                waker.wake();
            }
        });
        poll_fn(|cx| {
            // Cancellation removes its waiter under this same lock. It
            // either sees the registration or is visible to this check.
            let mut waiters = self.status.waiters.lock().unwrap();
            if let Err(error) = cancel.check_io() { return Poll::Ready(Err(error)); }
            if self.status_revision() != revision { return Poll::Ready(Ok(())); }
            waiters.entry(id).and_modify(|wake| wake.clone_from(cx.waker()))
                .or_insert_with(|| cx.waker().clone());
            Poll::Pending
        }).await
    }

    pub(super) fn foreground_finished(&self, when_unwatched: impl FnOnce()) {
        let running = self.running.lock().unwrap();
        let external = self.external.current.read().unwrap();
        let delivered = running.as_ref().filter(|run| !run.thread.is_finished()).is_some_and(|run| {
            run.hub.update(|signals| signals.foreground_finished = true)
        });
        let defer_priority = delivered && external.as_ref().is_some_and(|external| !external.scopes.is_empty());
        drop(external);
        drop(running);
        if !defer_priority {
            when_unwatched();
        }
    }

    pub(super) fn generation(&self) -> u64 { self.generation.load(Ordering::Acquire) }

    pub(super) fn status(&self, cwd: &Path) -> io::Result<Value> {
        let state_dir = state_dir(cwd)?;
        let slot = self.running.lock().unwrap();
        let run = slot.as_ref().filter(|run| !run.thread.is_finished());
        Ok(json!({
            "running": run.is_some(), "enabled": run.is_some_and(|run| run.hub.enabled.load(Ordering::Acquire)),
            "phase": if run.is_some() { *self.status.phase.lock().unwrap() } else { "stopped" }, "generation": self.generation.load(Ordering::Relaxed),
            "pending": run.map_or(0, |run| run.hub.pending_count.load(Ordering::Relaxed)),
            "last_error": self.last_error.lock().unwrap().as_deref().unwrap_or(""),
            "state_dir": state_dir,
        }))
    }

    pub(super) async fn start_async(&self, cwd: &Path, engine: Arc<Engine>, tray: bool) -> io::Result<Value> {
        self.start_with_intent(cwd, engine, tray, None).await
    }

    async fn start_with_intent(&self, cwd: &Path, engine: Arc<Engine>, tray: bool, intent: Option<bool>) -> io::Result<Value> {
        let lifecycle = self.lifecycle.lock().await;
        let previous = {
            let mut slot = self.running.lock().unwrap();
            if slot.as_ref().is_some_and(|run| !run.thread.is_finished()) {
                super::diagnostics::event("watch_start_reused", || json!({}));
                return Ok(json!({"running":true,"started":false,"generation":self.generation.load(Ordering::Relaxed)}));
            }
            slot.take()
        };
        if let Some(previous) = previous { let _ = Self::join_run(previous).await; }
        let (running, ready) = self.spawn_run(cwd, engine, tray, intent).await?;
        let hub = Arc::clone(&running.hub);
        *self.running.lock().unwrap() = Some(running);
        let generation = self.generation.load(Ordering::Relaxed);
        super::diagnostics::event("watch_starting", || json!({"tray_enabled":tray}));
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
        super::diagnostics::event("watch_started", || json!({}));
        Ok(json!({"running":true,"started":true,"generation":generation}))
    }

    async fn spawn_run(&self, cwd: &Path, engine: Arc<Engine>, tray: bool, intent: Option<bool>) -> io::Result<(Running, Arc<Reply<()>>)> {
        let cancel = Cancellation::new();
        stage("watch_config", &cancel).await?;
        let snapshot = config::load_snapshot(cwd)?;
        // main applies the configured QoS before opening/handshaking the
        // shared engine. Worker acknowledgement is an async wait, not a
        // blocking Watch startup stage.
        super::diagnostics::retention(snapshot.config.watch.event_log_retention_days);
        windows::configure_priority_async(&engine, snapshot.config.runtime.process_mode).await;
        engine.worker_ready(&snapshot.config.performance.worker, &cancel).await?;
        let cwd = cwd.to_path_buf();
        let mut hub = Hub::new();
        hub.status = Arc::clone(&self.status);
        hub.wake_host = Some(Arc::clone(&self.wake_host));
        *hub.initial_enabled.lock().unwrap() = intent;
        hub.set_phase("starting");
        let hub = Arc::new(hub);
        let worker_hub = Arc::clone(&hub);
        let wake = Arc::clone(&self.wake_host);
        let external = Arc::clone(&self.external);
        let last_error = Arc::clone(&self.last_error);
        let (ready, wait) = command_reply();
        let completion = Arc::new(RunCompletion::default());
        let status = Arc::clone(&self.status);
        let finished = FinishRun(Arc::clone(&completion));
        stage("watch_start", &cancel).await?;
        self.generation.fetch_add(1, Ordering::Relaxed);
        let thread = thread::Builder::new().name("sunpack-watch".into()).spawn(move || {
            let result = match Scheduler::open(cwd, engine, worker_hub, tray, external, snapshot) {
                Ok(scheduler) => {
                    ready.send(Ok(()));
                    scheduler.run_service(&last_error)
                }
                Err(error) => {
                    ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                    Err(error)
                }
            };
            if let Err(error) = &result {
                *last_error.lock().unwrap() = Some(error.to_string());
                super::diagnostics::event("watch_failed", || json!({"error":error.to_string()}));
            }
            finished.0.complete(&result);
            status.notify();
            wake();
            result
        })?;
        Ok((Running { hub, thread, completion }, wait))
    }

    async fn join_run(running: Running) -> io::Result<()> {
        let _ = running.completion.wait().await;
        // Completion precedes only thread epilogue. Join/reap is blocking work,
        // never an await on a live scheduler while holding an executor slot.
        stage("watch_close", &Cancellation::new()).await?;
        running.thread.join().map_err(|_| io::Error::other("Watch thread failed"))?
    }

    pub(super) async fn stop_async(&self) -> io::Result<Value> {
        let lifecycle = self.lifecycle.lock().await;
        let generation = self.generation.load(Ordering::Relaxed);
        let current = self.running.lock().unwrap().as_ref()
            .filter(|run| !run.thread.is_finished())
            .map(|run| (Arc::clone(&run.hub), Arc::clone(&run.completion), !run.thread.is_finished()));
        let Some((hub, completion, stopped)) = current else {
            super::diagnostics::event("watch_stop_ignored", || json!({}));
            return Ok(json!({"running":false,"stopped":false,"generation":generation}));
        };
        super::diagnostics::event("watch_stopping", || json!({}));
        hub.set_phase("stopping");
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
        self.status.notify();
        (self.wake_host)();
        if stopped {
            result?;
            joined?;
        }
        super::diagnostics::event("watch_stopped", || json!({}));
        Ok(json!({"running":false,"stopped":stopped,"generation":self.generation.load(Ordering::Relaxed)}))
    }

    pub(super) async fn set_enabled_async(&self, cwd: &Path, engine: Arc<Engine>, enabled: bool) -> io::Result<Value> {
        self.start_with_intent(cwd, engine, true, Some(enabled)).await?;
        let hub = self.running.lock().unwrap().as_ref().map(|run| Arc::clone(&run.hub))
            .ok_or_else(|| io::Error::other("Daemon stopped"))?;
        let (reply, wait) = command_reply();
        hub.update(|signals| signals.monitor_commands.push((enabled, reply)));
        wait.wait().await?;
        self.status(cwd)
    }

    pub(super) async fn reload_async(&self) -> io::Result<Value> {
        let result = self.reload_result().await?;
        let running = result.is_some();
        if !running { super::diagnostics::event("watch_reload_ignored", || json!({})); }
        let reloaded = result.is_some_and(|result| result.unwrap_or(false));
        Ok(json!({"running":running,"reloaded":reloaded,"generation":self.generation.load(Ordering::Relaxed)}))
    }

    async fn reload_result(&self) -> io::Result<Option<io::Result<bool>>> {
        let hub = self.running.lock().unwrap().as_ref().filter(|run| !run.thread.is_finished()).map(|run| Arc::clone(&run.hub));
        let Some(hub) = hub else { return Ok(None); };
        let (ready, wait) = command_reply();
        hub.queue_reload(Some(ready));
        Ok(Some(wait.wait().await))
    }

    // Final shutdown can run after the control driver has stopped.
    pub(super) fn stop(&self) -> io::Result<Value> { block_on(self.stop_async()) }
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
        let running = self.is_running();
        {
            let _lock = FileMutex::lock(&path, ROOTS_LOCK)?;
            let mut roots = read_root_records_or_empty(&path)?;
            let mut positions: HashMap<_, _> = roots.iter().enumerate()
                .map(|(index, root)| (root_key(&root.path), index)).collect();
            for root in paths {
                let root = configured_path(root).into_owned();
                let id = root_key(&root);
                if let Some(&index) = positions.get(&id) {
                    let existing = &mut roots[index];
                    let changed = !existing.enabled || (recursive && !existing.recursive) || (deep && !existing.deep);
                    existing.scanned &= !recursive || existing.recursive;
                    existing.enabled = true;
                    existing.recursive |= recursive;
                    existing.deep |= deep;
                    if changed {
                        updated.push(existing.path.clone());
                    }
                    continue;
                }
                positions.insert(id, roots.len());
                roots.push(Root {
                    enabled: true,
                    path: root.clone(),
                    output: output.map(str::trim).filter(|value| !value.is_empty())
                        .map(|value| resolve_output(&root, value)).transpose()?,
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
            let retained: HashSet<_> = read_roots(&path)?.iter().map(|root| root_key(&root.path)).collect();
            for changes in [&mut added, &mut updated] {
                changes.retain(|root| {
                    let keep = retained.contains(&root_key(&configured_path(root)));
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
            super::diagnostics::event("watch_roots_added", || json!({"added":added,"updated":updated,"applied":apply["applied"]}));
        }
        Ok(json!({
            "roots_path":path,"added":added,"updated":updated,"rejected":rejected,
            "apply":apply,
        }))
    }

    pub(super) async fn remove_async(&self, cwd: &Path, paths: &[PathBuf]) -> io::Result<Value> {
        stage("watch_directory", &Cancellation::new()).await?;
        let path = roots_path(cwd)?;
        let mut removed = Vec::new();
        {
            let _lock = FileMutex::lock(&path, ROOTS_LOCK)?;
            let keys: HashSet<_> = paths.iter().map(|path| root_key(&configured_path(path))).collect();
            let mut roots = read_root_records_or_empty(&path)?;
            roots.retain(|root| {
                if keys.contains(&root_key(&root.path)) {
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
            .root_change_status(self.is_running(), !removed.is_empty()).await?
            .map(|(applied, generation)| {
                json!({
                    "roots_path":path,"removed":removed,"applied":applied,
                    "running":true,"generation":generation,
                })
            });
        if let Some(apply) = &apply {
            super::diagnostics::event("watch_roots_removed", || json!({"removed":removed,"applied":apply["applied"]}));
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
    pub(super) fn register_external_output(&self, path: &Path) -> io::Result<()> {
        self.external_output(path, true)
    }

    pub(super) fn reuse_external_output(&self, path: &Path) -> io::Result<()> {
        self.external_output(path, false)
    }

    fn external_output(&self, path: &Path, exclusive: bool) -> io::Result<()> {
        use crate::watch_store::active_outputs::{covers_path, register, OutputReservations};
        let reserve = |outputs: &OutputReservations| -> io::Result<()> {
            let creation = crate::scan::scope::OutputRootCreation::create(path, exclusive)
                .map_err(crate::pipeline::OutputCreateError::wrap)?;
            let paths = crate::path_keys::output_path_aliases(path)?;
            if !paths.iter().any(|path| covers_path(outputs, path)) {
                register(outputs, &paths, &[&output_identity(&path.to_string_lossy())?]);
            }
            creation.commit();
            Ok(())
        };
        loop {
            let journal = self.external.current.read().unwrap().as_ref()
                .and_then(ExternalOutputs::active_journal);
            if let Some(journal) = journal {
                // mkdir and reservation share the observer publication gate.
                let mut created = false;
                journal.commit(true, |state| {
                    reserve(&state.outputs)?;
                    created = true;
                    Ok(crate::watch_store::NativeWatchOperations::empty())
                })?;
                if created { return Ok(()); }
                // Root removal suspended this journal before the callback.
                // Re-read the publication target without creating twice.
                continue;
            }
            let external = self.external.current.write().unwrap();
            if external.as_ref().and_then(ExternalOutputs::active_journal).is_some() {
                continue;
            }
            // Serialize the rootless check and reservation with attachment and
            // with other rootless output registrations.
            return reserve(&self.external.reservations);
        }
    }

    pub(super) fn finish_external_outputs(&self, paths: &[String]) -> io::Result<()> {
        // Keep the catalog attached until its inventory replaces the
        // reservations. Other lookups can still reach the journal.
        let external = self.external.current.read().unwrap();
        if let Some(external) = external.as_ref() {
            let published = external.catalog.publish_outputs(paths, &external.scopes, &external.options, None)?;
            if let Some(hub) = external.hub.upgrade().filter(|_| !published.is_empty()) {
                hub.update(|signals| signals.published_outputs.extend(published));
            }
        } else {
            let records = crate::watch_store::active_outputs::records(&self.external.reservations, paths);
            crate::watch_store::active_outputs::release(&self.external.reservations, &records);
        }
        Ok(())
    }

    pub(super) fn prepare_external_flatten(
        &self, output: &Path, work: &Path, leaf: &Path, destination: &Path,
    ) -> io::Result<()> {
        let external = self.external.current.write().unwrap();
        if let Some(journal) = external.as_ref().and_then(|external| external.journal.upgrade()) {
            prepare_flatten(&journal, "", output, work, leaf, destination, None)?;
        } else {
            let mut paths = crate::path_keys::output_path_aliases(output)?;
            paths.extend(crate::path_keys::output_path_aliases(work)?);
            if key(output) != key(destination) { paths.extend(crate::path_keys::output_path_aliases(destination)?); }
            crate::watch_store::active_outputs::register(&self.external.reservations, &paths,
                &[&output_identity(&output.to_string_lossy())?, &output_identity(&leaf.to_string_lossy())?]);
        }
        Ok(())
    }

    pub(super) fn finish_external_flatten(&self, output: &Path) -> io::Result<()> {
        let journal = self.external.current.read().unwrap().as_ref()
            .and_then(|external| external.journal.upgrade());
        if let Some(journal) = journal {
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
    let outputs: Vec<_> = roots.iter().filter(|root| root.enabled).filter_map(|root| {
        let output = root.output.as_deref()?;
        Some((root_key(output), &root.path, output))
    }).collect();
    let positions: HashMap<_, _> = outputs.iter().map(|(id, root, output)| (id.as_str(), (root, output))).collect();
    for (id, root, output) in &outputs {
        if let Some((parent, parent_output)) = crate::path_keys::path_ancestors(id).skip(1)
            .find_map(|ancestor| positions.get(ancestor))
        {
            return Err(io::Error::other(format!(
                "watch output roots must not contain one another: {} -> {}; {} -> {}",
                parent.display(), parent_output.display(), root.display(), output.display(),
            )));
        }
    }
    Ok(())
}

struct Running {
    hub: Arc<Hub>,
    thread: JoinHandle<io::Result<()>>,
    completion: Arc<RunCompletion>,
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
    changes: RootChanges,
    reload: bool,
    reload_waiters: Vec<CommandReply<bool>>,
    monitor_commands: Vec<(bool, CommandReply<bool>)>,
    password_changed: bool,
    foreground_finished: bool,
    published_outputs: Vec<(String, String)>,
    maintenance: bool,
    volumes: VolumeChanges,
    rebuild: Vec<CommandReply<bool>>,
    cancel: Vec<(String, CommandReply<bool>)>,
    roots: Vec<RootCompleted>,
    completed: Vec<String>,
    dedup_completed: Vec<(u64, io::Result<()>)>,
    dedup_rebuild: bool,
    claimed: HashSet<String>,
}

#[derive(Default)]
struct RootChanges {
    changed_roots: HashMap<String, HashSet<PathBuf>>,
    topology_roots: HashSet<String>,
    paths: HashMap<PathBuf, PathChange>,
}

type CapturedPath = (quiet::Activity, quiet::Observation);

#[derive(Default)]
struct PathChange {
    modified_only: bool,
    event: Option<CandidateEvent>,
    observation: Option<Box<CapturedPath>>,
}

impl RootChanges {
    fn root_changed(&mut self, id: &str, paths: impl IntoIterator<Item = (PathBuf, PathChange)>) {
        let changed = self.changed_roots.entry(id.to_owned()).or_default();
        for (path, change) in paths {
            let first_for_root = changed.insert(path.clone());
            let current = self.paths.entry(path).or_default();
            current.modified_only = change.modified_only && (first_for_root || current.modified_only);
            if current.event.is_none() { current.event = change.event; }
            // A later notification invalidates the earlier snapshot even
            // when its probe returned no file.
            current.observation = change.observation;
        }
    }

    fn topology_changed(&mut self, id: String) {
        self.topology_roots.insert(id.clone());
        self.changed_roots.entry(id).or_default();
    }
    fn prepare(&mut self, is_known_file: impl Fn(&str, &Path) -> bool) -> Option<HashSet<PathBuf>> {
        let mut checkpoint = !self.topology_roots.is_empty();
        let mut departed = HashSet::new();
        // Directory modified is not an arrival. Its USN progress is merged
        // by idle maintenance, not a named subtree scan.
        for (root, paths) in &mut self.changed_roots {
            paths.retain(|path| {
                let change = self.paths.get(path);
                if change.is_some_and(|change| change.observation.is_some()) { return true; }
                let modified = change.is_some_and(|change| change.modified_only);
                match fs::metadata(path) {
                    Ok(metadata) if metadata.is_dir() && modified => return false,
                    Ok(metadata) if metadata.is_file() => {}
                    Err(error) if missing_path(&error) && is_known_file(root, path) => {
                        departed.insert(path.clone());
                    }
                    _ if modified => {}
                    _ => checkpoint = true,
                }
                true
            });
        }
        (!checkpoint).then_some(departed)
    }

}

struct Hub {
    enabled: AtomicBool,
    initial_enabled: Mutex<Option<bool>>,
    status: Arc<WatchStatus>,
    wake_host: Option<Arc<dyn Fn() + Send + Sync>>,
    stopped: AtomicBool,
    signals: Mutex<Signals>,
    wake: std::sync::Condvar,
    claims: Mutex<HashMap<String, Arc<str>>>,
    completed_families: CompletedFamilies,
    activities: Arc<quiet::Activities>,
    pending_count: AtomicUsize,
}

type SourceGenerations = HashMap<String, PhysicalFileGeneration>;

// Like main's completed Watch family cache, this outlives candidate admission but
// remains bounded. Receipt publication can lag behind source lease release.
const COMPLETED_FAMILY_LIMIT: usize = 4096;
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
enum CompletedMember {
    Object(u64, [u8; 16]),
    Path(String),
}

impl CompletedMember {
    fn new(path: &str, generation: &PhysicalFileGeneration) -> Self {
        generation.object_id().map_or_else(|| Self::Path(path.to_owned()),
            |(volume, file)| Self::Object(volume, file))
    }
}

type CompletedFamilyKey = (Arc<[CompletedMember]>, bool);
type CompletedGenerations = Arc<[(Arc<str>, PhysicalFileGeneration)]>;
type CompletedReceipt = (CompletedGenerations, Arc<Path>);

#[derive(Default)]
struct CompletedFamilies(Mutex<CompletedFamilyCache>);

#[derive(Default)]
struct CompletedFamilyCache {
    receipts: crate::collections::CacheOrder<CompletedFamilyKey, CompletedReceipt>,
    members: HashMap<Arc<str>, crate::collections::SmallOrderedSet<CompletedFamilyKey>>,
}

impl CompletedFamilyCache {
    fn index(&mut self, family: &CompletedFamilyKey, generations: &CompletedGenerations) {
        for (path, _) in generations.iter() {
            self.members.entry(Arc::clone(path))
                .and_modify(|keys| keys.insert(family.clone()))
                .or_insert_with(|| crate::collections::SmallOrderedSet::One(family.clone()));
        }
    }

    fn unindex(&mut self, family: &CompletedFamilyKey, generations: &CompletedGenerations) {
        for (path, _) in generations.iter() {
            if self.members.get_mut(path).expect("indexed receipt member").remove(family) {
                self.members.remove(path);
            }
        }
    }

    fn insert(&mut self, family: CompletedFamilyKey, (generations, output): CompletedReceipt) {
        if let Some((previous, saved_output)) = self.receipts.get_mut(&family) {
            *saved_output = output;
            let previous = std::mem::replace(previous, Arc::clone(&generations));
            if previous.iter().map(|(path, _)| path).ne(generations.iter().map(|(path, _)| path)) {
                self.unindex(&family, &previous);
                self.index(&family, &generations);
            }
        } else {
            self.index(&family, &generations);
            if let Some((evicted, (generations, _))) = self.receipts.insert(family, (generations, output), COMPLETED_FAMILY_LIMIT) {
                self.unindex(&evicted, &generations);
            }
        }
        crate::collections::trim_map(&mut self.members);
    }

    fn validate_output(&mut self, family: &CompletedFamilyKey, output: &Arc<Path>, live: bool) -> bool {
        // An old probe cannot refresh or remove a replacement receipt.
        if !self.receipts.peek_mut(family).is_some_and(|(_, current)| Arc::ptr_eq(output, current)) {
            return false;
        }
        if !live {
            let (generations, _) = self.receipts.remove(family).unwrap();
            self.unindex(family, &generations);
            crate::collections::trim_map(&mut self.members);
        }
        live
    }
}

impl CompletedFamilies {
    fn remember(&self, generations: SourceGenerations, deep: bool, output: &Path) {
        if generations.is_empty() { return; }
        let mut ordered: Vec<_> = generations.into_iter().map(|(path, generation)|
            (CompletedMember::new(&path, &generation), (Arc::<str>::from(path), generation))).collect();
        ordered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let (members, generations): (Vec<_>, Vec<_>) = ordered.into_iter().unzip();
        let family = (Arc::from(members), deep);
        let generations = Arc::from(generations);
        let output = Arc::from(output);
        self.0.lock().unwrap().insert(family, (generations, output));
    }

    fn output(&self, generations: &SourceGenerations, deep: bool) -> Option<PathBuf> {
        // Rename changes a spelling, not an already extracted physical member.
        // Keep the full family and content-generation checks, without another
        // metadata pass or a search through all cached families.
        let mut current: Vec<_> = generations.iter().map(|(path, generation)|
            (CompletedMember::new(path, generation), (path, generation))).collect();
        current.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let (members, current): (Vec<_>, Vec<_>) = current.into_iter().unzip();
        let family = (Arc::from(members), deep);
        let output = {
            let mut cache = self.0.lock().unwrap();
            let (previous, output) = cache.receipts.peek_mut(&family)?;
            if !current.iter().zip(previous.iter()).all(|((_, current), (_, previous))|
                current.matches_input(previous)) {
                return None;
            }
            Arc::clone(output)
        };
        let live = output.is_dir();
        let mut cache = self.0.lock().unwrap();
        if !cache.validate_output(&family, &output, live) { return None; }
        let (previous, _) = cache.receipts.peek_mut(&family).unwrap();
        if current.iter().zip(previous.iter()).any(|((path, _), (stored, _))| stored.as_ref() != path.as_str()) {
            // Keep the validated versions and publish the live names for late
            // completion checks, retaining allocations for unchanged names.
            let renamed = current.iter().zip(previous.iter()).map(|((path, _), (stored, generation))| {
                let path = if stored.as_ref() == path.as_str() { Arc::clone(stored) } else { Arc::from(path.as_str()) };
                (path, generation.clone())
            }).collect::<CompletedGenerations>();
            cache.insert(family, (renamed, Arc::clone(&output)));
        } else {
            cache.receipts.get(&family);
        }
        Some(output.to_path_buf())
    }

    fn covers(&self, path: &Path, deep: bool) -> bool {
        let path = key(path);
        let candidates: Vec<_> = {
            let mut cache = self.0.lock().unwrap();
            let CompletedFamilyCache { receipts, members } = &mut *cache;
            let Some(families) = members.get(path.as_str()) else { return false; };
            families.iter().filter(|family| family.1 == deep)
                .map(|family| (family.clone(), receipts.peek_mut(family).expect("indexed receipt").clone()))
                .collect()
        };
        for (family, (generations, output)) in candidates {
            // Require the entire current family, not only the old request's head.
            if !generations.iter().all(|(member, previous)| {
                crate::io::reader::capture_file_generation(Path::new(member.as_ref()))
                    .is_ok_and(|current| current.matches_input(previous))
            }) { continue; }
            let live = output.is_dir();
            let mut cache = self.0.lock().unwrap();
            if cache.validate_output(&family, &output, live)
                && cache.receipts.peek_mut(&family).is_some_and(|(current, _)| Arc::ptr_eq(current, &generations)) {
                cache.receipts.get(&family);
                return true;
            }
        }
        false
    }
}

impl Hub {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            initial_enabled: Mutex::new(None),
            wake_host: None,
            status: Arc::default(),
            stopped: AtomicBool::new(false),
            signals: Mutex::default(),
            wake: std::sync::Condvar::new(),
            claims: Mutex::default(),
            completed_families: CompletedFamilies::default(),
            activities: Arc::default(),
            pending_count: AtomicUsize::new(0),
        }
    }

    fn publish_status(&self) { self.status.notify(); }
    fn set_phase(&self, phase: &'static str) {
        *self.status.phase.lock().unwrap() = phase;
        self.publish_status();
    }

    fn stop(&self) {
        {
            let _guard = self.signals.lock().unwrap();
            self.stopped.store(true, Ordering::Release);
        }
        self.wake.notify_one();
    }

    fn clear_idle_completed_families(&self) {
        // Drop both entries and their allocated tables at the existing idle
        // maintenance boundary, as main clears completed Watch generations.
        *self.completed_families.0.lock().unwrap() = CompletedFamilyCache::default();
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

    fn wait_drain(&self) -> Signals {
        let guard = self.signals.lock().unwrap();
        let mut guard = self.wake.wait_while(guard, |signals| {
            signals.completed.is_empty()
                && signals.roots.is_empty()
                && signals.cancel.is_empty()
        }).unwrap();
        // Policy reload drains the old generation without consuming its next
        // configuration and root notifications.
        Signals {
            roots: std::mem::take(&mut guard.roots),
            completed: std::mem::take(&mut guard.completed),
            cancel: std::mem::take(&mut guard.cancel),
            ..Signals::default()
        }
    }

    fn update(&self, update: impl FnOnce(&mut Signals)) -> bool {
        let mut signals = self.signals.lock().unwrap();
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        update(&mut signals);
        drop(signals);
        self.wake.notify_one();
        true
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
                && value.changes.changed_roots.is_empty()
                && !value.reload
                && !value.password_changed
                && !value.maintenance
                && !value.foreground_finished
                && value.published_outputs.is_empty()
                && value.volumes.is_empty()
                && value.monitor_commands.is_empty()
                && value.rebuild.is_empty()
                && value.cancel.is_empty()
                && value.claimed.is_empty()
                && value.completed.is_empty()
                && value.dedup_completed.is_empty()
                && !value.dedup_rebuild
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
static CONFIG_DIRECTORIES: OnceLock<Mutex<HashMap<String, Weak<ConfigDirectory>>>> = OnceLock::new();

pub(super) struct ConfigSubscription {
    directory: Arc<ConfigDirectory>,
    id: u64,
}
impl ConfigSubscription {
    pub(super) fn alive(&self) -> bool { self.directory.observer.alive() }

    fn start(path: &Path, files: HashMap<String, (bool, bool)>, notify: ConfigNotify) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut directories = CONFIG_DIRECTORIES.get_or_init(Mutex::default).lock().unwrap();
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
                let observer = FileObserver::start(path, false, 0x01 | 0x02 | 0x08 | 0x10, 4096, move |changes| {
                    for listener in events.lock().unwrap().values() {
                        let (config, passwords) = configuration_changes(&listener.files, changes.as_deref());
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
        let mut listeners = self.directory.listeners.lock().unwrap();
        listeners.remove(&self.id);
        if !listeners.is_empty() { return; }
        drop(listeners);

        let key = key(&self.directory.observer.path);
        let mut directories = CONFIG_DIRECTORIES.get().unwrap().lock().unwrap();
        // Another subscription may have reused this observer or replaced it
        // between locks. Check both its current registration and listeners.
        if directories.get(&key).is_some_and(|entry| std::ptr::eq(entry.as_ptr(), Arc::as_ptr(&self.directory)))
            && self.directory.listeners.lock().unwrap().is_empty()
        {
            directories.remove(&key);
            crate::collections::trim_map(&mut directories);
        }
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

    fn start(
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
        catalog: &Arc<NativeWatchCatalog>, dependency_only: bool,
    ) -> io::Result<Self> {
        let identity = output_identity(&directory.to_string_lossy())?;
        let id = key(&root.path);
        let watched_dir = directory.to_owned();
        let recursive = root.recursive || dependency_only;
        let password_name = passwords.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let password_path = key(passwords);
        let hub = Arc::clone(hub);
        let journal = Arc::clone(journal);
        let catalog = Arc::clone(catalog);
        // Match watchdog's business-root notifications, including ACL and
        // attributes-only changes that can make an unreadable candidate usable.
        // Use watchdog 6.0.0's exact 64,000-byte business-root buffer; small
        // configuration/ancestor subscriptions keep their 4 KiB allocation.
        let observer = FileObserver::start(
            directory, recursive, 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x100, 64_000, move |names| {
            let mut password_changed = false;
            let paths = names.map(|names| {
                let mut changes = HashMap::<_, PathChange>::new();
                let mut rename_source = None;
                for change in names {
                    let path = watched_dir.join(&change.name);
                    let event = CandidateEvent::native(change.action, &path, &mut rename_source);
                    if path.file_name().is_some_and(|name| {
                        name.to_string_lossy().eq_ignore_ascii_case(&password_name)
                    }) && key(&path) == password_path {
                        password_changed = true;
                        continue;
                    }
                    let ordinary = scope.contains(&path.to_string_lossy());
                    if dependency_only && ordinary { continue; }
                    if !ordinary && !catalog.generated_under(&scope, &path.to_string_lossy())
                        && journal.state().entry(&path.to_string_lossy()).is_none() { continue; }
                    let modified = change.action == 3;
                    match changes.entry(path) {
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            let change = entry.get_mut();
                            change.modified_only &= modified;
                            if change.event.is_none() { change.event = event; }
                        }
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(PathChange { modified_only: modified, event, observation: None });
                        }
                    }
                }
                if let Some(filter) = journal.owned_event_filter(changes.keys().map(PathBuf::as_path), &watched_dir) {
                    changes.retain(|path, _| !filter.contains(path));
                }
                for (path, change) in &mut changes {
                    if !scope.contains(&path.to_string_lossy()) { continue; }
                    let key = key(path);
                    if hub.claims.lock().unwrap().contains_key(&key) { continue; }
                    let activity = hub.activities.bind(&key, || {
                        catalog.observation(&path.to_string_lossy())
                            .as_ref().map_or_else(quiet::Activity::default, quiet::Activity::saved)
                    });
                    if let Ok(Some(observation)) = activity.capture(path, &hub.claims, &key) {
                        change.observation = Some(Box::new((activity, observation)));
                    }
                }
                changes
            });
            let root_changed = paths.as_ref().is_none_or(|paths| !paths.is_empty());
            if password_changed || root_changed {
                hub.update(|signals| {
                    signals.password_changed |= password_changed;
                    if !root_changed { return; }
                    if let Some(paths) = paths {
                        signals.changes.root_changed(&id, paths);
                    } else if dependency_only {
                        signals.changes.root_changed(&id, [(watched_dir.clone(), PathChange { modified_only: false, event: None, observation: None })]);
                    } else {
                        signals.changes.topology_changed(id.clone());
                    }
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
    members: Arc<Mutex<ParentMembers>>,
}

// Several configured paths can resolve to the same notification target.
type ParentMembers = BTreeSet<(String, String)>;

fn parent_memberships<'a>(roots: impl Iterator<Item = &'a Root>) -> HashMap<String, (PathBuf, ParentMembers)> {
    let mut desired = HashMap::<String, (PathBuf, ParentMembers)>::new();
    for root in roots {
        if let Some(parent) = root.path.parent().and_then(nearest_directory) {
            let directory = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_owned());
            let event_path = directory.join(root.path.strip_prefix(parent).unwrap_or(&root.path));
            desired.entry(key(&directory)).or_insert_with(|| (directory, BTreeSet::new()))
                .1.insert((key(&event_path), key(&root.path)));
        }
    }
    desired
}

fn affected_parent_roots(members: &ParentMembers, changed: Option<&[String]>) -> Vec<String> {
    let Some(changed) = changed else { return members.iter().map(|(_, root)| root.clone()).collect(); };
    let mut affected = HashSet::new();
    for path in changed {
        let exact = members.range((path.clone(), String::new())..)
            .take_while(|(target, _)| target == path);
        // A target below a missing directory is invalidated when that
        // ancestor appears. The range also handles names containing dots.
        let range = crate::path_keys::descendant_key_range(path);
        let descendants = members.range((range.start, String::new())..(range.end, String::new()));
        affected.extend(exact.chain(descendants).map(|(_, root)| root));
    }
    affected.into_iter().cloned().collect()
}

impl ParentObserver {
    fn start(directory: &Path, members: ParentMembers, hub: &Arc<Hub>) -> io::Result<Self> {
        let identity = output_identity(&directory.to_string_lossy())?;
        let members = Arc::new(Mutex::new(members));
        let watched_members = Arc::clone(&members);
        let watched_dir = directory.to_owned();
        let hub = Arc::clone(hub);
        let observer = FileObserver::start(directory, false, 0x01 | 0x02 | 0x08 | 0x10, 4096, move |names| {
            let changed = names.map(|names| names.into_iter()
                .filter(|change| change.action != 3)
                .map(|change| key(&watched_dir.join(change.name))).collect::<Vec<_>>());
            let affected = affected_parent_roots(&watched_members.lock().unwrap(), changed.as_deref());
            if !affected.is_empty() {
                hub.update(|signals| for root in affected {
                    signals.changes.topology_changed(root);
                });
            }
        })?;
        Ok(Self { observer: RootObserver { observer, identity }, members })
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
    paths: HashMap<Arc<str>, u8>,
    readiness: VecDeque<DiagnosticExpiry>,
    observations: VecDeque<DiagnosticExpiry>,
    sequence: u64,
}

struct DiagnosticExpiry {
    expires: Instant,
    sequence: u64,
    path: Arc<str>,
    flag: u8,
}

impl CandidateDiagnostics {
    fn retire_first(&mut self) {
        let queue = match (self.readiness.front(), self.observations.front()) {
            (Some(wait), Some(observation)) if wait.sequence > observation.sequence => &mut self.observations,
            (Some(_), _) => &mut self.readiness,
            (None, _) => &mut self.observations,
        };
        Self::remove_event(&mut self.paths, queue.pop_front().unwrap());
        if queue.is_empty() { *queue = VecDeque::new(); }
    }

    fn remove_event(paths: &mut HashMap<Arc<str>, u8>, entry: DiagnosticExpiry) {
        let events = paths.get_mut(&entry.path).unwrap();
        *events &= !entry.flag;
        if *events == 0 { paths.remove(&entry.path); }
    }

    fn clear_expired(&mut self, now: Instant) {
        let mut expired = false;
        for queue in [&mut self.readiness, &mut self.observations] {
            if !queue.front().is_some_and(|entry| entry.expires <= now) { continue; }
            while queue.front().is_some_and(|entry| entry.expires <= now) {
                Self::remove_event(&mut self.paths, queue.pop_front().unwrap());
            }
            crate::collections::trim_deque(queue);
            expired = true;
        }
        if expired { crate::collections::trim_map(&mut self.paths); }
    }

    fn retire_path(&mut self, path: &str, recursive: bool) {
        let retired = |candidate: &str| candidate == path || recursive && is_path_under(candidate, path);
        if recursive {
            let before = self.paths.len();
            self.paths.retain(|candidate, _| !retired(candidate));
            if self.paths.len() == before { return; }
        } else if self.paths.remove(path).is_none() {
            return;
        }
        for queue in [&mut self.readiness, &mut self.observations] {
            queue.retain(|entry| !retired(&entry.path));
            crate::collections::trim_deque(queue);
        }
        crate::collections::trim_map(&mut self.paths);
    }

    fn deadline(&self) -> Option<Instant> {
        self.readiness.front().into_iter().chain(self.observations.front())
            .map(|entry| entry.expires).min()
    }

    fn len(&self) -> usize { self.readiness.len() + self.observations.len() }

    fn admit(&mut self, now: Instant, id: &str, event: usize) -> bool {
        self.clear_expired(now);
        let flag = 1 << event;
        if self.paths.get(id).is_some_and(|events| events & flag != 0) { return false; }
        if self.len() == 2048 { self.retire_first(); }
        let id = self.paths.get_key_value(id).map(|(id, _)| Arc::clone(id))
            .unwrap_or_else(|| Arc::from(id));
        *self.paths.entry(Arc::clone(&id)).or_default() |= flag;
        // Each queue has a fixed lifetime, so timestamps from the scheduler
        // keep its expirations ordered even when the two classes interleave.
        let (queue, seconds) = if event < 2 {
            (&mut self.readiness, 30)
        } else {
            (&mut self.observations, 300)
        };
        self.sequence += 1;
        queue.push_back(DiagnosticExpiry {
            expires: now + std::time::Duration::from_secs(seconds),
            sequence: self.sequence,
            path: id,
            flag,
        });
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
        if !self.admit(now, id, 2) { return; }
        journal.log(Self::observation_record(path, error, event));
    }

    fn log_unobservable(&mut self, journal: &journal::Journal, now: Instant, id: &str, path: &str) {
        if self.admit(now, id, 3) {
            journal.log(json!({"event":"candidate_ignored", "path":path,
                "reason":"not_a_file_or_unreadable"}));
        }
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
        if !self.admit(now, id, usize::from(error.is_some())) { return; }
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
// the admitting root, preserving the nested input's original recovery scope.
fn handoff_nested_blocker(
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

#[derive(Clone, Debug)]
struct Recovery {
    max_depth: Option<usize>,
    scope: NativeDiscoveryScope,
    password_scope: PathBuf,
    parent: Option<continuation::Parent>,
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
            max_depth: scope.get("extract_depth").and_then(Value::as_u64).map(|n| n as usize),
            scope: NativeDiscoveryScope::new(root, depth, excluded),
            password_scope: PathBuf::from(password_scope),
            parent: scope.get("parent").and_then(|value| continuation::Parent::deserialize(value).ok()),
        })
    }

    fn record(&self) -> serde_json::Map<String, Value> {
        let mut record = scope_record(&self.scope);
        record.insert("extract_depth".into(), json!(self.max_depth));
        if let Some(parent) = &self.parent { record.insert("parent".into(), json!(parent)); }
        record
    }

    fn start_depth(&self) -> usize { self.parent.as_ref().map_or(1, |parent| parent.depth) }

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
    layout_checked_at: u64,
    cancelled: bool,
    coalesced: bool,
    deduplicated: HashSet<String>,
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
    max_depth: usize,
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
    request: u64,
    reply: Arc<super::cli::reporting::Reply<Outcome>>,
    batch: String,
    id: crate::pipeline::TaskId,
    root_key: String,
    groups: HashMap<String, Arc<SourceGroup>>,
    completed: Completed,
}

struct CompletionContext {
    max_depth: usize,
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
    outputs: BTreeMap<String, String>,
}

struct SourceGroup {
    path: PathBuf,
    members: Vec<String>,
}

impl SourceGroup {
    fn record(&self) -> impl serde::Serialize + '_ {
        source_group_record(&self.path, &self.members, self.members.len() > 1)
    }
}

fn source_group_record<'a, T: serde::Serialize>(
    path: &'a Path, members: &'a [T], multipart: bool,
) -> impl serde::Serialize + 'a {
    #[derive(serde::Serialize)]
    struct Record<'a, T> {
        path: &'a Path,
        members: &'a [T],
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        multipart: bool,
    }
    Record { path, members, multipart }
}

// Logical tasks own groups; physical members may have several live consumers.
#[derive(Default)]
struct SourceGroups {
    planned: HashMap<String, Vec<String>>,
    roots: HashMap<String, Arc<SourceGroup>>,
    members: HashMap<String, usize>,
    shared_owners: HashSet<String>,
}

impl SourceGroups {
    fn plan(&mut self, root: String, members: Vec<String>) {
        self.release_plan(&root);
        for member in &members { *self.members.entry(member.clone()).or_default() += 1; }
        self.planned.insert(root, members);
    }

    fn release_plan(&mut self, root: &str) {
        if let Some(members) = self.planned.remove(root) {
            for member in members { self.release_member(&member); }
        }
    }

    fn insert(&mut self, group: Arc<SourceGroup>) {
        let root = key(&group.path);
        self.release_plan(&root);
        if let Some(previous) = self.roots.remove(&root) { self.release(&previous); }
        for member in &group.members { *self.members.entry(watch_path_key(member)).or_default() += 1; }
        self.roots.insert(root, group);
    }

    fn can_finish_alias(&self, root: &str, owners: &HashMap<String, String>) -> bool {
        let Some(group) = self.roots.get(root) else { return false; };
        let mut has_owner = false;
        for member in &group.members {
            let member = watch_path_key(member);
            if owners.contains_key(&member) {
                if self.shared_owners.contains(&member) || self.members.get(&member) != Some(&1) {
                    return false;
                }
                has_owner = true;
            }
        }
        has_owner
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
            self.release_member(&watch_path_key(member));
        }
    }

    fn release_member(&mut self, id: &str) {
        if let Some(count) = self.members.get_mut(id) {
            *count -= 1;
            if *count == 0 { self.members.remove(id); }
        }
    }

    fn take(&mut self, root: &str) -> HashMap<String, Arc<SourceGroup>> {
        self.release_plan(root);
        let Some(group) = self.roots.remove(root) else { return HashMap::new(); };
        self.release(&group);
        group.members.iter().map(|member| watch_path_key(member))
            // A discovered task retains its durable owner even before claim.
            // An admitted tail with no independent task belongs to its head.
            .filter(|member| member == root || (!self.planned.contains_key(member) && !self.members.contains_key(member)))
            .map(|member| (member, Arc::clone(&group))).collect()
    }
}

struct DedupRebuild {
    id: u64,
    generation: u64,
    cancel: Cancellation,
    handle: Option<crate::pipeline::scheduling::Join<()>>,
    roots: VecDeque<(Root, NativeDiscoveryScope)>,
}
impl Drop for DedupRebuild {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Cancellation interrupts pending IOCP reads and queued stages. Join
        // before releasing/reopening the journal: a cancelled callback must
        // not retain the old service WAL lock across daemon restart.
        if let Some(handle) = self.handle.take() { let _ = handle.join(); }
    }
}

struct Scheduler {
    resuming: bool,
    baseline_roots: HashSet<String>,
    #[cfg(test)]
    admission_checkpoint: Option<Box<dyn FnOnce(&mut Self) -> io::Result<()> + Send>>,
    candidate_diagnostics: CandidateDiagnostics,
    cwd: PathBuf,
    root_file: PathBuf,
    roots: BTreeMap<String, (Root, NativeDiscoveryScope)>,
    root_scope_records: HashMap<String, Arc<serde_json::Map<String, Value>>>,
    available_roots: HashSet<String>,
    settings: Arc<Config>,
    user_password_signature: String,
    engine: Arc<Engine>,
    journal: Arc<journal::Journal>,
    catalog: Arc<NativeWatchCatalog>,
    dedup: Arc<Mutex<dedup::Index>>,
    dedup_rebuild: Option<DedupRebuild>,
    dedup_job_id: u64,
    recovery_ids: HashMap<String, filesystem::DirectoryRecoveryCache>,
    options: Option<NativeDirectoryScanOptions>,
    deep_options: NativeDirectoryScanOptions,
    passwords: Arc<BuiltinStore>,
    hub: Arc<Hub>,
    root_observers: HashMap<String, RootObserver>,
    root_progress: RootPolicyProgress,
    parent_observers: HashMap<String, ParentObserver>,
    dependency_observers: HashMap<(String, String), RootObserver>,
    config_observers: Vec<ConfigSubscription>,
    pending: HashMap<String, Pending>,
    unpublished: HashSet<String>,
    due: BTreeMap<(Instant, String), ()>,
    active: HashMap<String, Active>,
    active_paths: HashMap<String, Arc<str>>,
    tray_enabled: bool,
    tray: Option<super::tray::Tray>,
    monitor: Option<(crate::core::clipboard_monitor::Monitor, bool, usize)>,
    toast: Option<super::toast::Toast>,
    cache_deadline: Option<Instant>,
    external: Arc<OutputPublications>,
    broker_lease: Option<Arc<BrokerLease>>,
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        // Startup can fail after installing the catalog for foreground work.
        self.external.retire(&self.journal);
    }
}

impl Scheduler {
    fn enabled(&self) -> bool { self.hub.enabled.load(Ordering::Acquire) }

    /// A mode/scope rebuild uses the ordinary executor, not the service thread.
    /// Pending proposals keep collecting USN/quiet evidence until this baseline
    /// has been indexed, and control/configuration commands remain responsive.
    fn rebuild_dedup(&mut self, scopes_changed: bool, refresh_journals: bool) -> io::Result<()> {
        if self.settings.watch.deduplication == config::WatchDeduplication::None { return Ok(()); }
        if refresh_journals {
            self.engine.run_stage("watch_dedup_journal", Origin::Watch, || {
                let mut volumes = HashMap::new();
                let stamps = self.roots.values().map(|(_, scope)| {
                    let stamp = filesystem::watch_volume_device(&scope.root).ok().and_then(|volume| {
                        let cursor = volumes.entry(volume.clone()).or_insert_with(|| filesystem::watch_volume_cursor(&volume).ok());
                        cursor.map(|(journal, _)| (volume, journal))
                    }).unwrap_or_default();
                    (scope.key().to_owned(), stamp.0, stamp.1)
                }).collect::<Vec<_>>();
                self.dedup.lock().unwrap().reconcile_journals(&stamps)
            })??;
        }
        let generation = {
            let mut index = self.dedup.lock().unwrap();
            if !scopes_changed && (!index.needs_rebuild()
                || self.dedup_rebuild.as_ref().is_some_and(|job| job.generation == index.generation()))
            {
                return Ok(());
            }
            index.begin_rebuild()?;
            index.generation()
        };
        self.dedup_job_id += 1;
        self.dedup_rebuild = Some(DedupRebuild {
            id: self.dedup_job_id,
            generation,
            cancel: Cancellation::new(), handle: None,
            roots: self.roots.values().cloned().collect(),
        });
        self.advance_dedup_rebuild()
    }

    fn advance_dedup_rebuild(&mut self) -> io::Result<()> {
        let Some(job) = &mut self.dedup_rebuild else { return Ok(()); };
        job.handle.take();
        let Some((root, scope)) = job.roots.pop_front() else {
            let generation = job.generation;
            self.dedup_rebuild.take();
            match self.dedup.lock().unwrap().finish_rebuild_if(generation) {
                Ok(true) => self.journal.log(json!({"event":"watch_dedup_rebuilt","mode":self.settings.watch.deduplication,"scope":self.settings.watch.deduplication_scope,"roots":self.roots.len()})),
                Ok(false) => (),
                Err(error) => self.journal.log(json!({"event":"watch_dedup_rebuild_failed","error":error.to_string()})),
            }
            return Ok(());
        };
        let mut request = Request::with_config(vec![root.path.clone()], Mode::Scan, Arc::clone(&self.settings));
        request.origin = Origin::Watch;
        request.cancel = job.cancel.clone();
        request.recursive = root.recursive;
        request.deep = root.deep;
        request.passwords = Arc::clone(&self.settings.user_passwords);
        request.password_snapshot = Some(self.passwords.snapshot());
        request.password_scope = Some(root.path.clone());
        request.discovery_scope = Some(scope.clone());
        request.watch_catalog = Some(Arc::clone(&self.catalog));
        let index = Arc::clone(&self.dedup);
        let journal = Arc::clone(&self.journal);
        let generation = job.generation;
        let id = job.id;
        let hub = Arc::clone(&self.hub);
        job.handle = Some(self.engine.submit_discovery(request, move |owner, inputs| {
            if inputs.iter().flat_map(|input| input.physical_paths()).any(|path| !scope.contains(path)) { return Ok(()); }
            let result = dedup::consider(&index, &owner.to_string_lossy(), scope.key(), inputs, Some(generation));
            if let Err(error) = result {
                journal.log(json!({"event":"watch_dedup_unavailable","path":owner,"error":error.to_string()}));
            }
            Ok(())
        }, move |result| {
            hub.update(|signals| signals.dedup_completed.push((id, result)));
        }));
        Ok(())
    }

    fn persist_watch_control(journal: &journal::Journal, enabled: bool, baseline_roots: &HashSet<String>) -> io::Result<()> {
        journal.commit(true, |_| {
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            operations.set_runtime("watch_control".into(), Some(json!({"enabled":enabled, "baseline_roots":baseline_roots})));
            Ok(operations)
        })?;
        // A deferred stage must reach the same WAL boundary as a direct commit.
        journal.wait_before_mutation()
    }

    fn set_enabled(&mut self, enabled: bool) -> io::Result<bool> {
        if self.enabled() == enabled { return Ok(false); }
        self.hub.set_phase(if enabled { "enabling" } else { "disabling" });
        let result = if enabled {
            self.resuming = true;
            self.baseline_roots.extend(self.roots.keys().cloned());
            let result: io::Result<()> = (|| {
                if self.journal.resume()? {
                    self.catalog = Arc::new(NativeWatchCatalog::new(self.journal.state(),
                        Some(state_dir(&self.cwd)?.to_string_lossy().into_owned())));
                }
                self.activate_scan_options()?;
                // Subscribe before taking the baseline boundary. Events beyond
                // that boundary remain queued for ordinary enabled admission.
                self.rearm_root_observers(None)?;
                self.checkpoint(&HashMap::new(), true, false)?;
                self.root_progress.checkpoint = false;
                self.recover_pending(None)?;
                self.password_update(true)?;
                self.retry_missing_volumes(None)?;
                self.root_progress.recovery = false;
                Self::persist_watch_control(&self.journal, true, &self.baseline_roots)?;
                self.hub.enabled.store(true, Ordering::Release);
                Ok(())
            })();
            self.resuming = false;
            if result.is_err() {
                self.stop_watch_sources();
                self.release_admission();
            }
            result
        } else {
            (|| {
                // Accepted work survives a pause; new arrivals after this
                // explicit command are not turned into recovery intent.
                self.persist_candidates(BTreeMap::new(), true)?;
                self.journal.resume()?;
                Self::persist_watch_control(&self.journal, false, &self.baseline_roots)?;
                self.hub.enabled.store(false, Ordering::Release);
                self.drain_active(&mut Ok(()))?;
                self.persist_candidates(BTreeMap::new(), true)?;
                self.release_admission();
                Ok(())
            })()
        };
        self.reconcile_shell();
        self.hub.set_phase(if self.enabled() { "running" } else { "disabled" });
        result?;
        self.journal.log(json!({"event":if enabled { "watch_enabled" } else { "watch_disabled" }}));
        self.suspend_empty_scheduler()?;
        if !enabled { self.arm_idle_cleanup(); }
        Ok(true)
    }

    fn open(
        cwd: PathBuf, engine: Arc<Engine>, hub: Arc<Hub>,
        tray_enabled: bool, external: Arc<OutputPublications>, snapshot: Snapshot,
    ) -> io::Result<Self> {
        Self::open_with_lease(cwd, engine, hub, tray_enabled, external, snapshot, None)
    }

    fn open_with_lease(
        cwd: PathBuf, engine: Arc<Engine>, hub: Arc<Hub>,
        tray_enabled: bool, external: Arc<OutputPublications>, snapshot: Snapshot,
        lease: Option<Arc<BrokerLease>>,
    ) -> io::Result<Self> {
        let executor = Arc::clone(&engine);
        executor.run_stage("watch_start", Origin::Watch, || {
            Self::open_blocking(cwd, engine, hub, tray_enabled, external, snapshot, lease)
        })?
    }

    fn open_blocking(
        cwd: PathBuf,
        engine: Arc<Engine>,
        hub: Arc<Hub>,
        tray_enabled: bool,
        external: Arc<OutputPublications>,
        snapshot: Snapshot,
        lease: Option<Arc<BrokerLease>>,
    ) -> io::Result<Self> {
        let root_file = roots_path(&cwd)?;
        let dir = state_dir(&cwd)?;
        let journal = Arc::new(journal::Journal::open_with_outputs(&dir, snapshot.config.watch.event_log_retention_days, Arc::clone(&external.reservations))?);
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
        let config_observers = Self::observe_config(&cwd, &snapshot, &root_file, passwords.path(), &hub)?;
        let control = journal.state().runtime_record("watch_control");
        let baseline_roots = control.as_ref()
            .and_then(|record| record.get("baseline_roots").and_then(Value::as_array))
            .into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
        let saved_enabled = control.as_ref()
            .and_then(|record| record.get("enabled").and_then(Value::as_bool)).unwrap_or(true);
        let requested = hub.initial_enabled.lock().unwrap().take();
        // A cold enable still has to cross the paused baseline barrier below
        // via its queued command; a cold disable must suppress startup recovery.
        let enabled = saved_enabled && requested != Some(false);
        if requested.is_some() && enabled != saved_enabled {
            Self::persist_watch_control(&journal, enabled, &baseline_roots)?;
        }
        hub.enabled.store(enabled, Ordering::Release);
        let dedup = Arc::new(Mutex::new(dedup::Index::open(&dir, snapshot.config.watch.deduplication, snapshot.config.watch.deduplication_scope)?));
        let mut scheduler = Self {
            resuming: false,
            baseline_roots,
            #[cfg(test)]
            admission_checkpoint: None,
            cwd,
            root_file,
            roots: BTreeMap::new(),
            root_scope_records: HashMap::new(),
            available_roots: HashSet::new(),
            user_password_signature: user_password_signature(&snapshot.config.user_passwords),
            settings: Arc::new(snapshot.config),
            engine,
            journal,
            catalog,
            dedup,
            dedup_rebuild: None,
            dedup_job_id: 0,
            recovery_ids: HashMap::new(),
            options: None,
            deep_options,
            passwords,
            hub,
            root_observers: HashMap::new(),
            root_progress: RootPolicyProgress::default(),
            parent_observers: HashMap::new(),
            dependency_observers: HashMap::new(),
            config_observers,
            pending: HashMap::new(),
            unpublished: HashSet::new(),
            due: BTreeMap::new(),
            active: HashMap::new(),
            active_paths: HashMap::new(),
            tray_enabled,
            tray: None,
            monitor: None,
            toast: None,
            cache_deadline: None,
            candidate_diagnostics: CandidateDiagnostics::default(),
            external,
            broker_lease: lease,
        };
        scheduler.reconcile_roots(false)?;
        scheduler.activate_scan_options()?;
        scheduler.retire_missing_entries(None, true)?;
        scheduler.rebuild_dedup(false, true)?;
        scheduler.reconcile_shell();
        if enabled {
            scheduler.recover_pending(None)?;
            scheduler.password_update(true)?;
            scheduler.checkpoint(&HashMap::new(), true, true)?;
            scheduler.root_progress.checkpoint = false;
            scheduler.retry_missing_volumes(None)?;
            scheduler.root_progress.recovery = false;
        }
        scheduler.hub.set_phase(if enabled { "running" } else { "disabled" });
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
        if !self.roots.is_empty() { return Ok(()); }
        if self.journal.suspended() {
            self.broker_lease.take();
            return Ok(());
        }
        // Reconciliation has already drained requests and retired removed scopes.
        // Keep only the configuration/tray/log shell; durable recovery belongs to
        // the next scheduler, not to an idle service with no roots.
        self.stop_watch_sources();
        self.toast.take();
        self.external.retire(&self.journal);
        self.broker_lease.take();
        self.commit_idle_catalog();
        self.journal.suspend()?;
        self.catalog.close();
        self.catalog = Arc::new(NativeWatchCatalog::new(self.journal.state(), None));
        self.release_admission();
        self.active = HashMap::new();
        self.active_paths = HashMap::new();
        self.available_roots = HashSet::new();
        Ok(())
    }

    fn stop_watch_sources(&mut self) {
        self.root_observers = HashMap::new();
        self.dependency_observers = HashMap::new();
        self.parent_observers = HashMap::new();
        self.monitor.take();
    }

    fn release_admission(&mut self) {
        // While paused there is no diagnostic expiry deadline. Release that
        // history and the transient admission tables with the paused queue.
        self.pending = HashMap::new();
        self.unpublished = HashSet::new();
        self.journal.state().clear_volume_checks();
        self.root_scope_records = HashMap::new();
        self.recovery_ids = HashMap::new();
        self.due.clear();
        self.candidate_diagnostics = CandidateDiagnostics::default();
        self.cache_deadline = None;
        self.hub.clear_idle_completed_families();
    }

    fn commit_idle_catalog(&mut self) {
        self.recovery_ids = HashMap::new();
        if let Ok(mut dedup) = self.dedup.try_lock() {
            dedup.release_write_buffer();
        }
        self.catalog.commit(true);
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
        log: &Arc<crate::event_log::NativeEventLog>, tray: &mut Option<super::tray::Tray>) {
        let show_tray = enabled && settings.watch.tray_enabled;
        if show_tray && tray.is_none() {
            let hub = Arc::clone(hub);
            let diagnostic = Arc::downgrade(log);
            match super::tray::Tray::start(cwd, settings.cli.language, move |action| {
                match action {
                    super::tray::Action::Reload => hub.queue_reload(None),
                    super::tray::Action::Monitor(enabled) => {
                        let (reply, _) = command_reply();
                        hub.update(|signals| signals.monitor_commands.push((enabled, reply)));
                    },
                    super::tray::Action::Stop => {
                        hub.status.shutdown.store(true, Ordering::Release);
                        hub.publish_status();
                        if let Some(wake) = &hub.wake_host { wake(); }
                    },
                }
            }, move |message, error| {
                if let Some(log) = diagnostic.upgrade() {
                    let _ = log.write(json!({"event":"tray_callback_error", "error":error.to_string(),
                        "error_type":format!("{:?}", error.kind()), "message":message}));
                }
            }) {
                Ok(value) => *tray = Some(value),
                Err(error) => { let _ = log.write(json!({"event":"tray_start_error", "error":error.to_string()})); }
            }
        } else if !show_tray {
            tray.take();
        } else if let Some(tray) = tray {
            tray.set_language(settings.cli.language);
        }
        if let Some(tray) = tray { tray.set_enabled(hub.enabled.load(Ordering::Acquire)); }
    }

    fn reconcile_shell(&mut self) {
        Self::reconcile_tray(&self.cwd, &self.settings, self.tray_enabled,
            &self.hub, self.journal.event_log(), &mut self.tray);
        if self.options.is_some() && !self.roots.is_empty() && self.settings.watch.toast_enabled {
            if self.toast.is_none() {
                let journal = Arc::downgrade(&self.journal);
                match state_dir(&self.cwd).and_then(|dir| {
                    super::toast::Toast::start(
                        &self.cwd,
                        Arc::clone(&self.engine),
                        dir.join("failures"),
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
        if !self.enabled() || self.roots.is_empty() || self.options.is_none() {
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
                                Ok(true) => { hub.update(|signals| signals.password_changed = true); }
                                Ok(false) => {},
                                Err(error) => journal.log(json!({
                                    "event":"watch_clipboard_password_save_failed", "error":error.to_string(),
                                })),
                            }
                        }
                        crate::core::clipboard_monitor::Notification::ClipboardReadFailed(error) => {
                            journal.log(json!({
                                "event":"watch_clipboard_password_read_failed", "error":error.to_string(),
                            }));
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
        let policy = engine.run_stage("watch_directory", Origin::Watch, || -> io::Result<_> {
        let (entries, rejected) = {
            // Read, classify, and prune the same root policy. GUI and CLI
            // writers share this lock; pruning an older snapshot can remove a
            // root that has since moved back onto a supported filesystem.
            let _guard = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
            let mut entries = match read_root_records(&self.root_file) {
                // An absent file is normal before the first root is added. It
                // carries no authority to retire the previous catalog or WAL.
                Err(error) if self.roots.is_empty() && error.kind() == io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                result => result?,
            };
            let mut filesystems = HashMap::new();
            let mut rejected = Vec::new();
            entries.retain(|entry| {
                if !entry.enabled { return true; }
                let Some(directory) = nearest_directory(&entry.path) else {
                    return true;
                };
                let filesystem = filesystems.entry(directory.to_owned()).or_insert_with(|| {
                    filesystem::watch_filesystem_type(&directory.to_string_lossy()).ok()
                });
                if let Some(filesystem) = filesystem.as_ref().filter(|name| !filesystem::supports_watch_filesystem(name)) {
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
            let message = self.settings.cli.language.translate("watch.unsupported_filesystem_removed", &[("paths", &paths)]);
            self.journal.log(json!({
                "event":"watch_unsupported_filesystem_roots_removed",
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
        let next = configured_root_scopes(&self.cwd, &entries)?;
        // The first root needs the broker for validation and recovery. Keep
        // this lease local until the root policy is published so a failed add
        // cannot leave the rootless service holding a connection.
        let lease = if self.roots.is_empty() && !next.is_empty() && self.broker_lease.is_none() {
            Some(BrokerLease::acquire()?)
        } else {
            None
        };
        let new_directories: HashSet<_> = next
            .iter()
            .filter(|(id, _)| !self.roots.contains_key(*id))
            .filter_map(|(_, (root, _))| nearest_directory(&root.path))
            .collect();
        for directory in new_directories {
            filesystem::validate_watch_root(&directory.to_string_lossy())?;
        }
        let mut baseline_roots = self.baseline_roots.clone();
        baseline_roots.retain(|id| next.get(id).is_some_and(|(root, _)| root.scanned));
        baseline_roots.extend(entries.iter().filter(|root| !root.enabled && root.scanned)
            .map(|root| key(&root.path)));
        let policy_changed = root_policy_changed(&self.roots, &next);
            Ok(Some((next, baseline_roots, policy_changed, lease)))
        })??;
        let Some((next, baseline_roots, policy_changed, lease)) = policy else {
            return Ok((false, false));
        };
        let baseline_changed = self.baseline_roots != baseline_roots;
        if next.is_empty() && self.journal.suspended() && !baseline_changed { return Ok((false, false)); }
        if self.journal.resume()? {
            self.catalog = Arc::new(NativeWatchCatalog::new(self.journal.state(),
                Some(state_dir(&self.cwd)?.to_string_lossy().into_owned())));
        }
        // Validate the latest root file before stopping the running scheduler.
        // Draining async requests must never hold a blocking-stage permit.
        if restart_scheduler || policy_changed {
            self.dedup_rebuild.take();
            self.drain_active(&mut Ok(()))?;
            // Main builds its new scheduler from the durable work. In-memory
            // candidates produced by the stop checkpoint must not mask pending
            // output cleanup or retained recovery under the new policy.
            self.persist_candidates(BTreeMap::new(), true)?;
            self.pending = HashMap::new();
            self.unpublished = HashSet::new();
            self.journal.state().clear_volume_checks();
            self.due.clear();
            if let Some(toast) = &self.toast {
                toast.reset_batches();
            }
        }
        engine.run_stage("watch_directory", Origin::Watch, || {
        if baseline_changed {
            // Publish disabled roots' intent before dropping their checkpoints.
            Self::persist_watch_control(&self.journal, self.enabled(), &baseline_roots)?;
            self.baseline_roots = baseline_roots;
        }
        let refresh_catalog = self.root_progress.observe(policy_changed, self.roots.is_empty());
        self.available_roots.retain(|id| next.contains_key(id));
        if refresh_catalog {
            self.root_scope_records = HashMap::new();
        } else {
            self.root_scope_records.retain(|id, _| {
                self.roots.get(id).zip(next.get(id)).is_some_and(|(old, next)| old.1.root == next.1.root)
            });
        }
        self.roots = next;
        if refresh_catalog && self.settings.watch.deduplication != config::WatchDeduplication::None {
            self.dedup.lock().unwrap().reconcile_scopes(self.roots.values().map(|(_, scope)| scope))?;
        }
        if let Some(lease) = lease {
            self.broker_lease = Some(lease);
        }
        if !refresh_catalog && !restart_scheduler {
            // A no-op reload still updates initial-scan markers above. The
            // existing observers and output ownership need no reconciliation.
            return Ok((self.root_progress.checkpoint, self.root_progress.recovery));
        }
        // Root policy is already durable. Publish it independently of WAL
        // retirement, and always restore subscriptions even if retirement fails.
        let retirement: io::Result<()> = (|| {
            if refresh_catalog {
                self.root_observers.clear();
                self.dependency_observers.clear();
                self.recovery_ids.clear();
                let scopes: Arc<[_]> = self.roots.values()
                    .map(|(_, scope)| scope.clone()).collect::<Vec<_>>().into();
                let mut external = self.external.current.write().unwrap();
                self.catalog.retain_roots(self.roots.values()
                    .map(|(root, _)| root.path.to_string_lossy().into_owned()).collect());
                *external = Some(ExternalOutputs {
                    journal: Arc::downgrade(&self.journal),
                    scopes: Arc::clone(&scopes),
                    catalog: Arc::clone(&self.catalog),
                    options: self.deep_options.clone(),
                    hub: Arc::downgrade(&self.hub),
                });
                drop(external);
                self.journal.commit(true, |state| Ok(state.scope_retirement_operations(&scopes)))?;
            }
            Ok(())
        })();
        self.rearm_root_observers_blocking(None);
        retirement?;
        self.reconcile_generated_sources()?;
        self.root_progress.retirement = false;
        Ok((self.root_progress.checkpoint, self.root_progress.recovery))
        })?
    }

    fn rearm_root_observers(&mut self, changed: Option<&HashSet<String>>) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_rearm", Origin::Watch, || {
            self.rearm_root_observers_blocking(changed);
            self.reconcile_generated_sources()
        })?
    }

    fn rearm_root_observers_blocking(&mut self, changed: Option<&HashSet<String>>) {
        if !self.enabled() && !self.resuming { return; }
        // Ordinary content notifications never invalidate these subscriptions.
        // Resolve only topology-invalidated roots; preserve other memberships.
        let desired = parent_memberships(self.roots.iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains(*id)))
            .map(|(_, (root, _))| root));
        for parent in self.parent_observers.values() {
            parent.members.lock().unwrap().retain(|(_, id)|
                self.roots.contains_key(id) && changed.is_some_and(|changed| !changed.contains(id)));
        }
        for (id, (directory, mut members)) in desired {
            if let Some(parent) = self.parent_observers.get(&id) {
                if parent.observer.matches(&directory) {
                    parent.members.lock().unwrap().extend(members);
                    continue;
                }
                members.extend(parent.members.lock().unwrap().iter().cloned());
                self.parent_observers.remove(&id);
            }
            match ParentObserver::start(&directory, members, &self.hub) {
                Ok(parent) => { self.parent_observers.insert(id, parent); }
                Err(error) => self.journal.log(json!({"event":"watch_parent_unavailable", "path":directory,"error":error.to_string()})),
            }
        }
        self.parent_observers.retain(|_, parent| !parent.members.lock().unwrap().is_empty());
        self.root_observers.retain(|id, _| self.roots.contains_key(id));
        crate::collections::trim_map(&mut self.parent_observers);
        crate::collections::trim_map(&mut self.root_observers);
        for (id, (root, scope)) in self.roots.iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains(*id)))
        {
            // A root may grant access even if its parent sentinel failed to open.
            if let Some(observer) = self.root_observers.get(id) {
                if observer.matches(&root.path) { continue; }
                self.root_observers.remove(id);
                self.available_roots.remove(id);
            }
            if root.path.is_dir() {
                match RootObserver::start(&root.path, root, scope.clone(), self.passwords.path(),
                    &self.hub, &self.journal, &self.catalog, false) {
                    Ok(observer) => { self.root_observers.insert(id.clone(), observer); }
                    Err(error) => self.journal.log(json!({"event":"watch_root_unavailable","root":root.path,"error":error.to_string()})),
                }
            }
        }
    }

    fn reload(&mut self) -> io::Result<bool> {
        let result = self.reload_loaded();
        // Invalid config/root policy or rollback failures may follow a resume.
        // The rootless shell releases that temporary state on every exit path.
        let suspended = self.suspend_empty_scheduler();
        result.and_then(|changed| suspended.map(|()| {
            super::diagnostics::event(if changed { "watch_reloaded" } else { "watch_reload_skipped" }, || json!({}));
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
        let dedup_changed = self.settings.watch.deduplication != snapshot.config.watch.deduplication
            || self.settings.watch.deduplication_scope != snapshot.config.watch.deduplication_scope;
        let mut observed_paths = config::watch_paths(&self.cwd, &snapshot.sources);
        observed_paths.push(self.root_file.clone());
        let observers_changed = !observes_files(&observed_paths, self.passwords.path(), &self.config_observers);
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
            if roots_changed || config_changed { self.journal.state().clear_volume_checks(); }
            if scheduler_changed || roots_changed {
                self.activate_scan_options()?;
            }
            if config_changed {
                self.journal.set_retention(self.settings.watch.event_log_retention_days);
            }
            if dedup_changed {
                self.dedup_rebuild.take();
                self.dedup.lock().unwrap().reset(self.settings.watch.deduplication, self.settings.watch.deduplication_scope)?;
            }
            // A no-op reload can retry an abandoned rebuild, but a running
            // baseline and a ready index already have their journal stamps.
            let retry_dedup = self.dedup_rebuild.is_none() && self.dedup.lock().unwrap().needs_rebuild();
            self.rebuild_dedup(roots_changed, roots_changed || dedup_changed || retry_dedup)?;
            if !self.enabled() { return Ok(()); }
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
                self.journal.set_retention(self.settings.watch.event_log_retention_days);
                if dedup_changed {
                    self.dedup_rebuild.take();
                    self.dedup.lock().unwrap().reset(self.settings.watch.deduplication, self.settings.watch.deduplication_scope)?;
                    self.rebuild_dedup(false, true)?;
                }
                let (latest_roots_changed, latest_policy_changed) = self.reconcile_roots(false)?;
                self.activate_scan_options()?;
                if !self.enabled() { return Ok(()); }
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
        let changed = config_changed || roots_changed;
        if changed {
            super::diagnostics::retention(self.settings.watch.event_log_retention_days);
            windows::configure_priority(&self.engine, self.settings.runtime.process_mode);
        }
        self.reconcile_shell();
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
    fn drain_active(&mut self, result: &mut io::Result<()>) -> io::Result<()> {
        // Match main's stop boundary: checkpoint while directory observers are
        // armed, then join producers before draining submitted requests.
        if !self.roots.is_empty() && (self.enabled() || self.resuming) {
            if result.is_ok() {
                if let Err(error) = self.checkpoint(&HashMap::new(), true, false) { *result = Err(error); }
            }
        }
        self.stop_watch_sources();
        let mut failure_observed = false;
        while !self.active.is_empty() {
            if result.is_err() && !failure_observed {
                // An internal failure is not user cancellation. Leave pending
                // WAL intent for restart rather than suppressing its generation.
                for active in self.active.values() {
                    active.cancel.cancel();
                }
                failure_observed = true;
            }
            let signals = self.hub.wait_drain();
            for (batch, waiter) in signals.cancel {
                waiter.send(self.cancel_display_batch(&batch));
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
    fn run_service(mut self, last_error: &Mutex<Option<String>>) -> io::Result<()> {
        loop {
            let result = self.run();
            if result.is_ok() || self.hub.stopped.load(Ordering::Acquire) { return result; }
            let error = result.unwrap_err();
            *last_error.lock().unwrap() = Some(error.to_string());
            self.hub.set_phase("error");
            self.journal.log(json!({"event":"scheduler_error","error":error.to_string()}));
            let cwd = self.cwd.clone();
            let engine = Arc::clone(&self.engine);
            let hub = Arc::clone(&self.hub);
            let external = Arc::clone(&self.external);
            let mut settings = Arc::clone(&self.settings);
            let password_path = self.passwords.path().to_owned();
            let log = Arc::clone(self.journal.event_log());
            let roots = std::mem::take(&mut self.roots);
            let tray_enabled = self.tray_enabled;
            let mut observers = std::mem::take(&mut self.config_observers);
            let mut tray = self.tray.take();
            // The service shell owns the Broker connection throughout repair.
            // A failed reopen must release its WAL without giving up that lease.
            let lease = self.broker_lease.clone();
            // Drop the faulted stream and its lock before reopening; never
            // clear a WAL error in place or write the failed memory projection.
            drop(self);
            hub.pending_count.store(0, Ordering::Relaxed);
            let mut repaired = None;
            while !hub.stopped.load(Ordering::Acquire) {
                let signals = hub.wait(None);
                for ( _, waiter) in signals.cancel { waiter.send(Ok(false)); }
                if !signals.rebuild.is_empty() {
                    log.rebuild();
                    let rebuilt = log.flush().is_ok();
                    for waiter in signals.rebuild { waiter.send(Ok(rebuilt)); }
                }
                for root in signals.roots { root.reply.complete(Err(io::Error::other(error.to_string()))); }
                for (_, waiter) in signals.monitor_commands {
                    waiter.send(Err(io::Error::other(error.to_string())));
                }
                if !signals.reload { continue; }
                let reload = (|| {
                    let snapshot = config::reload_snapshot(&cwd)?;
                    let root_file = roots_path(&cwd)?;
                    let entries = if roots.is_empty() {
                        read_root_records_or_empty(&root_file)?
                    } else {
                        read_root_records(&root_file)?
                    };
                    let next_roots = configured_root_scopes(&cwd, &entries)?;
                    let changed = scheduler_configuration_changed(&settings, &snapshot.config)
                        || root_policy_changed(&roots, &next_roots);
                    let shell_changed = *settings != snapshot.config;
                    if !changed && (signals.reload_waiters.is_empty() || shell_changed) {
                        // A failed scheduler does not disable service-only policy
                        // changes. Keep the existing tray/configuration shell alive.
                        let next_observers = Self::observe_config(&cwd, &snapshot,
                            &roots_path(&cwd)?, &password_path, &hub)?;
                        settings = Arc::new(snapshot.config);
                        super::diagnostics::retention(settings.watch.event_log_retention_days);
                        log.configure_retention(settings.watch.event_log_retention_days.min(u64::from(u32::MAX)) as u32);
                        windows::configure_priority(&engine, settings.runtime.process_mode);
                        Self::reconcile_tray(&cwd, &settings, tray_enabled, &hub,
                            &log, &mut tray);
                        observers = next_observers;
                        return Ok(shell_changed);
                    }
                    repaired = Some(Self::open_with_lease(cwd.clone(), Arc::clone(&engine), Arc::clone(&hub),
                        false, Arc::clone(&external), snapshot,
                        lease.clone())?);
                    Ok(true)
                })();
                for waiter in signals.reload_waiters {
                    waiter.send(reload.as_ref().copied()
                        .map_err(|error: &io::Error| io::Error::new(error.kind(), error.to_string())));
                }
                match reload {
                    Ok(changed) => super::diagnostics::event(if changed { "watch_reloaded" } else { "watch_reload_skipped" }, || json!({})),
                    Err(error) => { *last_error.lock().unwrap() = Some(error.to_string()); }
                }
                if repaired.is_some() { break; }
            }
            drop(observers);
            drop(tray);
            let Some(mut scheduler) = repaired else { return Ok(()); };
            scheduler.tray_enabled = tray_enabled;
            scheduler.reconcile_shell();
            *last_error.lock().unwrap() = None;
            self = scheduler;
        }
    }

    fn run(&mut self) -> io::Result<()> {
        let mut result = self.run_inner();
        if result.is_ok() { self.hub.stop(); }
        self.dedup_rebuild.take();
        let _ = self.drain_active(&mut result);
        self.journal.state().clear_volume_checks();
        let signals = if self.hub.stopped.load(Ordering::Acquire) {
            self.hub.wait(None)
        } else { Signals::default() };
        drop(signals.cancel);
        for waiter in signals.reload_waiters {
            waiter.send(Err(io::ErrorKind::Interrupted.into()));
        }
        for waiter in signals.rebuild {
            waiter.send(Err(io::ErrorKind::Interrupted.into()));
        }
        self.external.retire(&self.journal);
        *self.hub.claims.lock().unwrap() = HashMap::new();
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_close", Origin::Watch, || {
            self.commit_idle_catalog();
            self.catalog.close();
            self.journal.log(json!({"event":"watch_stopped"}));
            self.journal.flush()
        })??;
        result
    }

    fn run_inner(&mut self) -> io::Result<()> {
        self.arm_idle_cleanup();
        let mut reload_retry = None;
        while !self.hub.stopped.load(Ordering::Acquire) {
            if self.enabled() && self.dedup_rebuild.is_none() { self.dispatch_ready()?; }
            self.hub
                .pending_count
                .store(self.pending.len(), Ordering::Relaxed);
            if self.active.is_empty() && self.pending.is_empty() {
                if self.catalog.commit_pending() || self.journal.compaction_pending() {
                    self.engine.run_stage("catalog_commit", Origin::Watch, || {
                        // A gap between bursts is not the idle-cache deadline.
                        self.catalog.commit(false);
                        self.journal.compact()
                    })??;
                }
                // An idle control or maintenance wake can borrow the stage pool.
                // Return it when the scheduler goes back to sleep.
                if self.cache_deadline.is_none()
                    && self.settings.watch.runtime_cache_cleanup_idle_seconds.is_finite()
                {
                    windows::retire_idle_stage_pool(&self.engine);
                }
            }
            // The resident CLI delegates cache cleanup to a live Watch. Its
            // deadline remains relevant while Watch admission is paused.
            let deadline = if self.enabled() {
                let due = if self.dedup_rebuild.is_none() { self.next_admission() } else { None };
                self.cache_deadline.into_iter().chain(due).chain(self.candidate_diagnostics.deadline()).min()
            } else {
                self.cache_deadline
            };
            let mut signals = self.hub.wait(deadline.into_iter().chain(reload_retry).min());
            self.candidate_diagnostics.clear_expired(Instant::now());
            // The checkpoint already reconciled the journal stamps.
            if signals.dedup_rebuild { self.rebuild_dedup(false, false)?; }
            for (id, result) in signals.dedup_completed.drain(..) {
                if !self.dedup_rebuild.as_ref().is_some_and(|job| job.id == id) { continue; }
                match result {
                    Ok(()) => self.advance_dedup_rebuild()?,
                    Err(error) => {
                        self.dedup_rebuild.take();
                        self.journal.log(json!({"event":"watch_dedup_rebuild_failed","error":error.to_string()}));
                    }
                }
            }
            for (batch, waiter) in signals.cancel {
                waiter.send(self.cancel_display_batch(&batch));
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
            for (enabled, waiter) in std::mem::take(&mut signals.monitor_commands) {
                let result = self.set_enabled(enabled);
                let failure = result.as_ref().err().filter(|_| self.options.is_none())
                    .map(|error| io::Error::new(error.kind(), error.to_string()));
                waiter.send(result);
                // Failed completion/drain invalidates the scheduler projection.
                // Reuse service repair rather than advertising an inactive model.
                if let Some(error) = failure { return Err(error); }
            }
            if self.enabled() && !signals.published_outputs.is_empty() && self.journal.state().has_volume_waiters() {
                let buckets: HashSet<_> = signals.published_outputs.into_iter().map(|(root, output)|
                    (watch_path_key(&root), crate::scan::catalog::catalog_stem(&output))).collect();
                let mut retried = HashSet::new();
                for (root, stem) in buckets {
                    if let Some((_, scope)) = self.roots.get(&root) {
                        self.retry_volume_peers(&scope.clone(), &stem, &mut retried)?;
                    }
                }
            }
            for waiter in signals.rebuild {
                let result = self.engine.run_stage("catalog_maintenance", Origin::Watch, || self.journal.rebuild_log()).and_then(|result| result);
                waiter.send(result);
            }
            if self.enabled() && (signals.password_changed || !signals.reload_waiters.is_empty()) {
                self.password_update(false)?;
            }
            if signals.foreground_finished {
                self.arm_idle_cleanup();
            } else if signals.password_changed && self.cache_deadline.is_none() {
                let path = self.passwords.path().to_string_lossy();
                if containing_root(&self.roots, &crate::path_keys::path_key(&path)).is_some() {
                    self.arm_idle_cleanup();
                }
            }
            if signals.reload || reload_retry.is_some_and(|deadline| deadline <= Instant::now()) {
                let reload = self.reload();
                let retry = reload.as_ref().is_err_and(crate::io::atomic_file::sharing_conflict);
                if let Err(error) = &reload {
                    if reload_retry.is_none() || !retry {
                        self.journal
                            .log(json!({"event":"watch_reload_failed","error":error.to_string()}));
                    }
                    if self.config_observers.iter().any(|observer| !observer.alive()) {
                        // Do not advertise a healthy Watch after a failed event
                        // subscription. Startup/restart can report the real error.
                        return Err(io::Error::other(format!("Configuration observer recovery failed: {error}")));
                    }
                }
                for waiter in signals.reload_waiters {
                    waiter.send(
                        reload.as_ref().copied().map_err(|error| io::Error::new(error.kind(), error.to_string())),
                    );
                }
                // The new name may be visible before the replacement writer
                // releases its handle. Closing it need not produce an event.
                reload_retry = retry.then(|| Instant::now() + Duration::from_millis(100));
            }
            let enabled = self.enabled();
            if enabled && !signals.volumes.is_empty() {
                for (id, (root, _)) in &self.roots {
                    let observed = self.root_observers.contains_key(id);
                    if signals.volumes.affects(&root.path, observed) {
                        signals.changes.topology_changed(id.clone());
                        if signals.volumes.arrives(&root.path, observed) {
                            self.available_roots.remove(id);
                        }
                    }
                }
            }
            if enabled && !signals.changes.changed_roots.is_empty() {
                if self.options.is_some() && !signals.changes.topology_roots.is_empty() {
                    self.rearm_root_observers(Some(&signals.changes.topology_roots))?;
                }
                self.observe_root_changes(&mut signals.changes)?;
                self.hub
                    .pending_count
                    .store(self.pending.len(), Ordering::Relaxed);
            }
            if self
                .cache_deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                self.cache_deadline = None;
                if self.active.is_empty() && self.pending.is_empty() {
                    let engine = Arc::clone(&self.engine);
                    windows::maintain_when_foreground_idle(&engine, || {
                        if !enabled { return Ok(()); }
                        self.checkpoint(&HashMap::new(), true, false)?;
                        engine.run_stage("catalog_maintenance", Origin::Watch, || {
                            self.commit_idle_catalog();
                            self.hub.clear_idle_completed_families();
                        })
                    })?;
                }
            }
        }
        Ok(())
    }
}

impl Scheduler {
    fn activate_scan_options(&mut self) -> io::Result<()> {
        self.options = None;
        match watch_scan_options(&self.settings, !self.roots.is_empty()) {
            Ok(options) => { self.options = options; Ok(()) }
            Err(error) => {
                self.stop_watch_sources();
                Err(error)
            }
        }
    }

    fn scan_options(&self, deep: bool) -> io::Result<&NativeDirectoryScanOptions> {
        let options = self.options.as_ref()
            .ok_or_else(|| io::Error::other("Watch scheduler is not active"))?;
        Ok(if deep { &self.deep_options } else { options })
    }

    fn reconcile_generated_sources(&mut self) -> io::Result<()> {
        let scopes: Vec<_> = self.roots.values().map(|(_, scope)| scope.clone()).collect();
        for scope in scopes {
            let paths = self.catalog.generated_paths(&scope);
            self.ensure_dependency_observers(scope.key(), paths.iter().filter_map(|p| Path::new(p).parent().map(Path::to_owned)))?;
            let invalid = self.validate_generated_sources(&scope, None)?;
            self.retire_recovery(invalid.into_iter())?;
        }
        self.retire_dependency_observers();
        Ok(())
    }

    fn validate_generated_sources(
        &self, scope: &NativeDiscoveryScope, paths: Option<&HashSet<PathBuf>>,
    ) -> io::Result<Vec<String>> {
        let mut deferred = None;
        let invalid = self.catalog.validate_generated_paths(scope, paths, |promotion, path| {
            deferred.get_or_insert_with(HashMap::new).entry(promotion)
                .or_insert_with(Vec::new).push(PathBuf::from(path));
        })?;
        // Subscribe once per conflicting mutation for this batch. Its release
        // resubmits only the affected paths through normal Watch notifications.
        for (promotion, paths) in deferred.into_iter().flatten() {
            let hub = Arc::downgrade(&self.hub);
            let root = scope.key().to_owned();
            promotion.notify(move || {
                if let Some(hub) = hub.upgrade() {
                    hub.update(|signals| signals.changes.root_changed(&root,
                        paths.into_iter().map(|path| (path, PathChange::default()))));
                }
            })?;
        }
        Ok(invalid)
    }

    fn ensure_dependency_observers(&mut self, root_id: &str, directories: impl Iterator<Item = PathBuf>) -> io::Result<()> {
        if !self.enabled() && !self.resuming { return Ok(()); }
        let Some((root, scope)) = self.roots.get(root_id) else { return Ok(()); };
        let mut directories_seen = HashSet::new();
        let mut bases_seen = HashSet::new();
        for directory in directories {
            let directory_key = key(&directory);
            if !directories_seen.insert(directory_key.clone()) { continue; }
            if root.recursive && scope.contains(&directory.to_string_lossy())
                && crate::scan::directory::walk_can_reach(scope.key(), &directory.to_string_lossy()) { continue; }
            let contains = |parent: &Path| directory_key == key(parent) || is_path_under(&directory_key, &key(parent));
            let base = root.output.as_deref().filter(|p| contains(p))
                .or_else(|| contains(&root.path).then_some(root.path.as_path())).unwrap_or(&directory);
            if !bases_seen.insert(key(base)) { continue; }
            let base = match fs::canonicalize(base) {
                Ok(base) => PathBuf::from(crate::path_keys::normalize_windows_extended_prefix(base.to_string_lossy().into_owned())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let id = (root_id.to_owned(), key(&base));
            if self.dependency_observers.get(&id).is_some_and(|observer| observer.matches(&base)) { continue; }
            let observer = RootObserver::start(&base, root, scope.clone(), self.passwords.path(),
                &self.hub, &self.journal, &self.catalog, true)?;
            self.dependency_observers.insert(id, observer);
        }
        Ok(())
    }

    fn retire_dependency_observers(&mut self) {
        self.dependency_observers.retain(|(root, _), observer| self.roots.get(root).is_some_and(|(_, scope)|
            self.catalog.generated_under(scope, &observer.observer.path.to_string_lossy())));
        crate::collections::trim_map(&mut self.dependency_observers);
    }

    fn invalidate_recovery(&mut self, paths: impl Iterator<Item = String>) -> io::Result<()> {
        let mut retired = Vec::new();
        for path in paths {
            let Some(entry) = self.journal.state().entry(&path) else { continue; };
            if self.claimed_continuation(&entry, &watch_path_key(&path)) { continue; }
            let changed = match watch_candidate_for_path(Path::new(&path), Some(entry.change_usn)) {
                Ok(Some(current)) => crate::postprocess::watch_source_changed(entry.size.max(0) as u64,
                    entry.mtime, &entry.file_id, entry.change_usn, &current),
                Ok(None) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Err(_) => continue,
            };
            if changed { retired.push(path); }
        }
        self.retire_recovery(retired.into_iter())
    }

    fn retire_recovery(&mut self, paths: impl Iterator<Item = String>) -> io::Result<()> {
        let mut operations = crate::watch_store::NativeWatchOperations::empty();
        let mut retired = Vec::new();
        for path in paths {
            let id = watch_path_key(&path);
            let entry = self.journal.state().entry_by_key(&id);
            if entry.as_deref().is_some_and(|entry| self.claimed_continuation(entry, &id)) { continue; }
            if !self.pending.contains_key(&id) && entry.is_none()
                && self.journal.state().pending(&path).is_none() { continue; }
            if let Some(pending) = self.pending.remove(&id) { self.due.remove(&(pending.due, id.clone())); }
            self.unpublished.remove(&id);
            operations.finish_pending(&path, None);
            retired.push(path);
        }
        if retired.is_empty() { return Ok(()); }
        self.journal.commit(false, |_| Ok(operations))?;
        for path in retired { self.journal.log(json!({"event":"task_retired", "path":path, "reason":"source_changed"})); }
        Ok(())
    }

    fn observe_file_changes_blocking(
        &mut self,
        changed: &HashMap<String, HashSet<PathBuf>>,
        path_changes: &mut HashMap<PathBuf, PathChange>,
        departed: &HashSet<PathBuf>,
    ) -> io::Result<()> {
        if self.options.is_none() { return Ok(()); }
        // Match main's ordinary file-event path: enqueue in memory without
        // refreshing the durable inventory or advancing its USN stamp. The
        // captured burst is reconciled once at admission/recovery instead.
        let mut retried = HashSet::new();
        let retry_volumes = self.journal.state().has_missing_volume_blockers();
        for (id, paths) in changed {
            let Some((root, scope)) = self.roots.get(id) else { continue };
            let deep = root.deep;
            let scope = scope.clone();
            if self.settings.watch.deduplication != config::WatchDeduplication::None {
                // This fast path does not pass through the USN checkpoint's
                // invalidation. Departures already retire their exact inverse
                // index entries below; check only the remaining named changes.
                let changed: Vec<_> = paths.iter().filter(|path| !departed.contains(*path))
                    .map(|path| path.to_string_lossy().into_owned())
                    .filter(|path| scope.contains(path) && !self.catalog.is_owned(path)).collect();
                dedup::invalidate(&self.dedup, changed.iter().map(String::as_str))?;
            }
            let mut stems = HashSet::new();
            let mut root_available = None;
            for path in paths {
                let source = path.to_string_lossy();
                if !scope.contains(&source) || self.catalog.is_owned(&source) { continue; }
                if departed.contains(path) && *root_available.get_or_insert_with(|| Path::new(&scope.root).is_dir()) {
                    // Like main's file departure, update only the named path.
                    // A missing Broker must not turn a delete into a root scan.
                    self.scan_options(deep)?.catalog_update(&self.catalog, &scope, Some(&source))?;
                    self.departed(&source, false)?;
                }
                let mut change = path_changes.get_mut(path);
                let (tracker, observation) = match change.as_mut().and_then(|change| change.observation.take()) {
                    Some(capture) => (Some(capture.0), Some(capture.1)),
                    None => (None, None),
                };
                let event = change.and_then(|change| change.event.as_ref());
                self.observe_candidate_with_event(id, source.to_string(), CandidateAdmission::Observe,
                    None, None, tracker, event, observation)?;
                if retry_volumes { stems.insert(crate::scan::catalog::catalog_stem(&source)); }
            }
            // Check a stem once against the inventory after this event burst.
            for stem in stems {
                self.retry_volume_peers(&scope, &stem, &mut retried)?;
            }
        }
        if self.cache_deadline.is_none() { self.arm_idle_cleanup(); }
        Ok(())
    }

    fn observe_root_changes(&mut self, changes: &mut RootChanges) -> io::Result<()> {
        if self.settings.watch.deduplication != config::WatchDeduplication::None {
            for root in &changes.topology_roots {
                if let Some((root, _)) = self.roots.get(root) {
                    dedup::invalidate_tree(&self.dedup, &root.path.to_string_lossy())?;
                }
            }
        }
        if !self.baseline_roots.is_empty() {
            let baseline: HashMap<_, _> = changes.changed_roots
                .extract_if(|root, _| self.baseline_roots.contains(root))
                .collect();
            if !baseline.is_empty() {
                changes.topology_roots.retain(|root| !baseline.contains_key(root));
                if changes.changed_roots.is_empty() {
                    changes.paths.clear();
                } else {
                    let remaining: HashSet<&Path> = changes.changed_roots.values()
                        .flatten().map(PathBuf::as_path).collect();
                    changes.paths.retain(|path, _| remaining.contains(path.as_path()));
                }
                self.checkpoint(&baseline, false, false)?;
                if changes.changed_roots.is_empty() { return Ok(()); }
            }
        }
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_directory", Origin::Watch, || {
            for (id, paths) in &changes.changed_roots {
                if let Some((_, scope)) = self.roots.get(id) {
                    let invalid = self.validate_generated_sources(scope, Some(paths))?;
                    self.retire_recovery(invalid.into_iter())?;
                    self.invalidate_recovery(paths.iter().map(|p| p.to_string_lossy().into_owned()))?;
                }
            }
            self.retire_dependency_observers();
            // Dependency-only changes never request ordinary root enumeration.
            changes.changed_roots.retain(|id, paths| {
                // An empty set is an existing topology/full-root invalidation,
                // not an empty dependency notification.
                if paths.is_empty() { return true; }
                paths.retain(|path| self.roots.get(id).is_some_and(|(_, scope)| scope.contains(&path.to_string_lossy())));
                !paths.is_empty()
            });
            let departed = changes.prepare(|id, path| {
                self.roots.get(id).is_some_and(|(_, scope)| {
                    self.catalog.path_is_directory(scope, &path.to_string_lossy()) == Some(false)
                })
            });
            match departed {
                Some(departed) => self.observe_file_changes_blocking(&changes.changed_roots,
                    &mut changes.paths, &departed),
                None => self.checkpoint_blocking(&changes.changed_roots, false, false, &changes.paths),
            }
        })?
    }

    fn checkpoint(&mut self, changed: &HashMap<String, HashSet<PathBuf>>, all_roots: bool, startup: bool) -> io::Result<()> {
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_usn_checkpoint", Origin::Watch, || {
            self.checkpoint_blocking(changed, all_roots, startup, &HashMap::new())
        })?
    }

    fn checkpoint_blocking(
        &mut self,
        changed: &HashMap<String, HashSet<PathBuf>>,
        all_roots: bool,
        startup: bool,
        path_changes: &HashMap<PathBuf, PathChange>,
    ) -> io::Result<()> {
        if self.options.is_none() || (!self.enabled() && !self.resuming) { return Ok(()); }
        use rayon::prelude::*;
        let mut groups: HashMap<String, (u64, i64, i64, Vec<NativeDiscoveryScope>)> =
            HashMap::new();
        let mut probes = Vec::new();
        let mut reopened = HashSet::new();
        for (id, (root, scope)) in self.roots.iter()
            .filter(|(id, _)| all_roots || changed.contains_key(*id))
        {
            if !root.path.is_dir() {
                self.available_roots.remove(id);
                if self.settings.watch.deduplication != config::WatchDeduplication::None {
                    dedup::invalidate_tree(&self.dedup, &scope.root)?;
                }
                continue;
            }
            if self.available_roots.insert(id.clone()) && !startup {
                reopened.insert(id.clone());
            }
            // Use the same directory generation to validate and publish this
            // cursor. A rename may replace its path while recovery is running.
            let identity = output_identity(&scope.root).ok();
            let volume = filesystem::watch_volume_device(&scope.root);
            probes.push((id.clone(), root.clone(), scope.clone(), identity, volume));
        }
        // Mount aliases share one checkpoint boundary per physical volume.
        let volumes: HashSet<_> = probes.iter()
            .filter_map(|(_, _, _, _, volume)| volume.as_deref().ok()).collect();
        let volume_cursors: HashMap<_, _> = volumes.into_par_iter()
            .map(|volume| (volume.to_owned(), filesystem::watch_volume_cursor(volume).map_err(Arc::new)))
            .collect();
        if self.settings.watch.deduplication != config::WatchDeduplication::None {
            let stamps = probes.iter().map(|(_, _, scope, _, volume)| {
                let stamp = volume.as_ref().ok().and_then(|volume|
                    volume_cursors.get(volume).and_then(|cursor| cursor.as_ref().ok()).map(|(journal, _)| (volume.clone(), *journal)))
                    .unwrap_or_default();
                (scope.key().to_owned(), stamp.0, stamp.1)
            }).collect::<Vec<_>>();
            if self.dedup.lock().unwrap().reconcile_journals(&stamps)? {
                self.hub.update(|signals| signals.dedup_rebuild = true);
            }
        }
        if !self.recovery_ids.is_empty() {
            let mounted_roots: HashMap<_, _> = probes.iter()
                .map(|(id, _, _, _, volume)| (id.as_str(), volume.as_deref().ok())).collect();
            // Retire cached directory IDs when a root goes offline or changes volumes.
            // Roots outside this checkpoint keep their last observed availability.
            self.recovery_ids.retain(|volume, cache| {
                cache.roots.keys().all(|root| {
                    self.available_roots.contains(root)
                        && mounted_roots.get(root.as_str()).is_none_or(|current| *current == Some(volume.as_str()))
                })
            });
            crate::collections::trim_map(&mut self.recovery_ids);
        }
        let probes = probes.into_iter().map(|(id, root, scope, identity, volume)| {
            let current = volume.map_err(Arc::new).and_then(|volume| {
                volume_cursors[volume.as_str()].clone().map(|(journal, end)| (volume, journal, end))
            });
            let cached = identity.as_deref().and_then(|identity| self.catalog.cursor(&scope, identity));
            if let (Ok((volume, journal, end)), Some((old_volume, old_journal, old_end))) =
                (&current, &cached)
            {
                if volume == old_volume && journal == old_journal && (0..=*end).contains(old_end) {
                    let start = self.journal.state().watch_cursor(volume)
                        .filter(|cursor| {
                            cursor.journal_id == i128::from(*journal)
                                && (0..=i128::from(*end)).contains(&cursor.next_usn)
                        })
                        .map_or(*old_end, |cursor| (*old_end).min(cursor.next_usn as i64));
                    let (_, first, _, scopes) = groups.entry(volume.clone())
                        .or_insert_with(|| (*journal, start, *end, Vec::new()));
                    *first = (*first).min(start);
                    scopes.push(scope.clone());
                }
            }
            (id, root, scope, identity, current, cached)
        }).collect::<Vec<_>>();
        if !self.resuming && !reopened.is_empty() {
            // Old snapshots can have only an outside literal name while its
            // physical watched volume is offline. Resolve those legacy names
            // once when a root returns, before catalog recovery or admission.
            // A returning root can have durable work with the same inventory
            // and no USN delta. Resume only the affected ownership scopes.
            self.recover_pending(Some(&reopened))?;
            self.retry_missing_volumes(Some(&reopened))?;
            let passwords = self.passwords.snapshot();
            self.retry_password_failures(&passwords, Some(&reopened), "password_retry")?;
        }
        let jobs: Vec<_> = groups.into_iter().map(|(volume, range)| {
            let cache = self.recovery_ids.remove(&volume).unwrap_or_default();
            (volume, range, cache)
        }).collect();
        let catalog = &self.catalog;
        let roots = &self.roots;
        let recovered: Vec<_> = jobs.into_par_iter().map(|(volume, (journal, start, end, scopes), mut cache)| {
            let changed = catalog
                .recover_changes(&scopes, &volume, journal, start, end, &mut cache)
                .map(|paths| {
                    // One volume replay serves several disjoint configured scopes.
                    let mut routed = HashMap::<String, Vec<_>>::new();
                    for (path, path_id) in paths {
                        let Some((root, _)) = containing_root(roots, &path_id) else { continue; };
                        if let Some(changes) = routed.get_mut(root) { changes.push((path, path_id)); }
                        else { routed.insert(root.clone(), vec![(path, path_id)]); }
                    }
                    for changes in routed.values_mut() {
                        changes.sort_unstable_by_key(|(path, _)| path.len());
                    }
                    routed
                });
            (volume, changed, cache)
        }).collect();
        let mut ranges = HashMap::with_capacity(recovered.len());
        for (volume, changed, cache) in recovered {
            if !cache.roots.is_empty() {
                self.recovery_ids.insert(volume.clone(), cache);
            }
            ranges.insert(volume, changed);
        }
        let mut marks = HashSet::new();
        let mut admitted = HashSet::new();
        let mut retried = HashSet::new();
        let retry_volumes = self.journal.state().has_missing_volume_blockers();
        let mut cursors = Vec::new();
        let mut failures = HashSet::new();
        let mut baseline_count = 0;
        for (id, root, scope, identity, current, cached) in probes {
            let baseline = self.resuming || self.baseline_roots.contains(&id);
            let refresh = |options: &NativeDirectoryScanOptions, catalog: &NativeWatchCatalog, path: Option<&str>| {
                if baseline {
                    options.catalog_baseline(catalog, &scope, path).map(|errors| (errors, Vec::new()))
                } else {
                    options.catalog_refresh(catalog, &scope, path)
                }
            };
            let range = match (&current, &cached) {
                (Ok((volume, journal, end)), Some((old_volume, old_journal, old_end)))
                    if volume == old_volume
                        && journal == old_journal
                        && (1..=*end).contains(old_end) =>
                {
                    ranges.get(volume)
                }
                _ => None,
            };
            baseline_count += usize::from(baseline);
            let mut paths = Vec::new();
            let mut errors = Vec::new();
            if !root.scanned || range.is_none_or(|entries| entries.is_err()) {
                // A normal live refresh reports arrivals even without a trusted
                // cursor. Startup with no prior cursor adopts inventory quietly.
                let options = self.scan_options(root.deep)?;
                let scan = if baseline || !startup || cached.is_some() {
                    refresh(options, &self.catalog, None)
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
                            Ok(metadata) if metadata.is_file() && !baseline => paths.push(path.into_owned()),
                            Err(error) if missing_path(&error) => {
                                self.departed(&path, true)?;
                                if !baseline { paths.push(path.into_owned()); }
                            }
                            _ => {}
                        }
                    }
                }
            } else if let Some(Ok(changes)) = range {
                let mut covered = HashSet::new();
                let mut full_refresh = false;
                // A directory notification can arrive before its USN record
                // becomes readable. Visit both sources through the same catalog.
                let mut named = changed.get(&id).into_iter().flatten().collect::<Vec<_>>();
                named.sort_unstable_by_key(|path| path.as_os_str().len());
                let recovered = changes.get(&id).into_iter().flatten().map(|(path, id)| {
                    (std::borrow::Cow::Borrowed(path.as_str()), std::borrow::Cow::Borrowed(id.as_str()))
                });
                let named = named.into_iter().map(|path| {
                    let path = path.to_string_lossy();
                    let id = crate::path_keys::path_key(&path);
                    (path, std::borrow::Cow::Owned(id))
                }).filter(|(_, id)| scope.contains_key(id));
                for (path, path_id) in recovered.chain(named) {
                    let path = path.as_ref();
                    if covered.contains(path_id.as_ref()) {
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
                        match collect_catalog_arrivals(refresh(options, &self.catalog, Some(path)), &mut paths) {
                            Ok(()) => {}
                            Err(reason) => {
                                full_refresh = true;
                                match refresh(options, &self.catalog, None) {
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
                    if missing {
                        self.departed(path, recursive_departure)?;
                    }
                    if !baseline && (missing || metadata.is_ok_and(|metadata| metadata.is_file())) {
                        paths.push(path.to_owned());
                    }
                }
            }
            if self.settings.watch.deduplication != config::WatchDeduplication::None {
                if baseline {
                    // Resume deliberately absorbs offline changes rather than
                    // returning arrivals. Retire stale indexed inputs once at
                    // that same scope boundary, without rehashing live ones.
                    dedup::invalidate_tree(&self.dedup, &scope.root)?;
                } else {
                    dedup::invalidate(&self.dedup, paths.iter().map(String::as_str))?;
                }
            }
            let recovered_paths = paths.len();
            if !root.scanned {
                if !baseline { paths.extend(self.catalog.candidate_paths(&scope)); }
                // The initial scan records a completed directory enumeration.
                // It has its own durable candidate barrier below, even when
                // the USN cursor is temporarily unavailable.
                if errors.is_empty() {
                    marks.insert(id.clone());
                }
            }
            let mut stems = HashSet::new();
            for (index, path) in paths.into_iter().enumerate() {
                // Initial inventory is not an explicit retry. Only paths
                // reported by startup recovery bypass an interrupted entry.
                let admission = if startup && index < recovered_paths {
                    // A blocker belongs to its recorded file generation. Let
                    // ordinary observation reject unchanged failures only after
                    // checking identity; a replaced parent can reuse every name.
                    if self.catalog.observation(&path).is_some()
                        || self.journal.state().entry(&path).is_some_and(|entry| {
                            entry.status == "failed_password" || entry.waits_for_volume()
                        })
                    {
                        CandidateAdmission::Observe
                    } else { CandidateAdmission::ExplicitRetry }
                } else {
                    CandidateAdmission::Observe
                };
                let path_id = watch_path_key(&path);
                if admitted.insert(path_id) {
                    self.observe_candidate_with_event(&id, path.clone(), admission,
                        None, None, None, Some(path_changes.get(Path::new(&path)).and_then(|change| change.event.as_ref()).unwrap_or(&CandidateEvent::Business(
                            if index >= recovered_paths { "initial_scan" }
                            else if startup { "startup_usn_recovery" } else { "usn_recovery" }))), None)?;
                    if retry_volumes { stems.insert(crate::scan::catalog::catalog_stem(&path)); }
                }
            }
            for stem in stems {
                self.retry_volume_peers(&scope, &stem, &mut retried)?;
            }
            match (current, identity) {
                (Ok((volume, journal, end)), Some(identity)) if errors.is_empty() => {
                    let changed = cached.as_ref().is_none_or(|(old_volume, old_journal, old_end)| {
                        (old_volume, *old_journal, *old_end) != (&volume, journal, end)
                    });
                    cursors.push((baseline.then_some(id), changed.then_some((scope, identity)), volume, journal, end));
                }
                (Ok((volume, _, _)), _) => { failures.insert(volume); }
                (Err(error), _) => {
                    if self.resuming { return Err(io::Error::new(error.kind(), error.to_string())); }
                    self.journal.log(json!({"event":"usn_cursor_unavailable","root":root.path,"error":error.to_string()}));
                },
            }
        }
        if self.resuming && !failures.is_empty() {
            return Err(io::Error::other("Cannot establish the resumed Watch baseline"));
        }
        let mut operations = BTreeMap::new();
        for (_, _, volume, journal, end) in &cursors {
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
        let mut baselined = HashSet::new();
        for (baseline, changed, volume, journal, end) in cursors {
            if failures.contains(&volume) { continue; }
            if let Some((scope, identity)) = changed {
                self.catalog.set_cursor(&scope, identity, volume, journal, end);
            }
            baselined.extend(baseline);
        }
        if !marks.is_empty() {
            // Candidate/cursor durability above is mandatory. This separate
            // user configuration marker must not stop unrelated roots.
            let marked = (|| -> io::Result<Vec<PathBuf>> {
                let _lock = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
                let mut latest = read_root_records(&self.root_file)?;
                let mut dirty = false;
                let mut matched = Vec::new();
                for root in &mut latest {
                    let id = key(&root.path);
                    if root.enabled && marks.contains(&id) {
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
                let roots = matched.iter().filter_map(|id| {
                    let (current, _) = self.roots.get_mut(id)?;
                    current.scanned = true;
                    Some(current.path.clone())
                }).collect();
                Ok(roots)
            })();
            match marked {
                Ok(roots) => self.journal.log(json!({"event":"initial_scan_completed","roots":roots})),
                Err(error) => self.journal.log(json!({"event":"scheduler_error","error":error.to_string()})),
            }
        }
        if startup || !admitted.is_empty() {
            self.journal.log(
                json!({"event":if startup { "usn_startup_recovered" } else { "usn_checkpoint" },
                "changed":admitted.len(),"queued":self.pending.len()}),
            );
        }
        if !baselined.is_empty() {
            self.catalog.flush()?;
            let pending = self.baseline_roots.difference(&baselined).cloned().collect();
            // Only an already-enabled scheduler publishes partial root recovery.
            // Explicit resume publishes intent once its complete barrier finishes.
            if self.enabled() { Self::persist_watch_control(&self.journal, true, &pending)?; }
            self.baseline_roots = pending;
        }
        self.catalog.commit(false);
        if let Some(error) = self.catalog.error() {
            if baseline_count != 0 { return Err(io::Error::other(error)); }
            self.journal.log(json!({"event":"catalog_persistence_failed","error":error}));
        }
        if baselined.len() != baseline_count {
            return Err(io::Error::other("Cannot establish the resumed Watch baseline"));
        }
        Ok(())
    }

    fn retire_missing_entries(&self, path_key: Option<&str>, recursive: bool) -> io::Result<()> {
        let mut available = HashMap::new();
        let mut missing = self
            .journal
            .state()
            .entries_in_scope(path_key, recursive)
            .into_iter()
            .filter_map(|entry| {
                let id = crate::path_keys::path_key(&entry.path);
                if self.claimed_continuation(&entry, &id) { return None; }
                let root = containing_root(&self.roots, &id)
                    .map(|(_, (root, _))| &root.path)
                    .or_else(|| {
                        let source = entry.failure_payload.get("source_input_root")?.as_str()?;
                        self.roots
                            .get(&watch_path_key(source))
                            .map(|(root, _)| &root.path)
                    })?;
                (*available.entry(root).or_insert_with(|| root.is_dir())
                    && recorded_file_is_absent(&entry.path))
                .then(|| (watch_path_key(&entry.path), entry, root))
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        missing.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        // A volume can disappear during the probe. Keep its durable blockers.
        available.clear();
        self.journal.commit(false, |state| {
            let keys = missing.into_iter().filter_map(|(id, entry, root)| {
                (*available.entry(root).or_insert_with(|| root.is_dir())
                    && state.entry_by_key(&id).is_some_and(|current| Arc::ptr_eq(&entry, &current)))
                .then_some(id)
            });
            Ok(crate::watch_store::NativeWatchOperations::retire_entries(
                keys,
            ))
        })
    }

    fn claimed_continuation(&self, entry: &crate::watch_store::EntryRecord, key: &str) -> bool {
        entry.continuation().is_some()
            && (self.active_paths.contains_key(key) || self.hub.claims.lock().unwrap().contains_key(key))
    }

    fn departed(&mut self, path: &str, recursive: bool) -> io::Result<()> {
        if self.settings.watch.deduplication != config::WatchDeduplication::None {
            if recursive { dedup::invalidate_tree(&self.dedup, path)?; }
            else { dedup::invalidate(&self.dedup, [path])?; }
        }
        let path_key = watch_path_key(path);
        self.candidate_diagnostics.retire_path(&path_key, recursive);
        self.journal.state().forget_volume_checks(&path_key, recursive);
        let is_missing = |pending: &Pending| {
            recorded_file_is_absent(&pending.candidate.path)
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
        self.catalog.forget_missing_observation(path, recursive);
        self.retire_missing_entries(Some(&path_key), recursive)
    }

    fn retire_departed_owner(&self, id: &str, path: &str) -> io::Result<()> {
        let claimed =
            self.active_paths.contains_key(id) || self.hub.claims.lock().unwrap().contains_key(id);
        if claimed {
            return Ok(());
        }
        self.journal.commit(false, |state| {
            use crate::watch_store::NativeWatchOperations;
            let recoverable = state.pending(path).is_some_and(|record| record.has_output_work());
            let mut operations = NativeWatchOperations::empty();
            if !recoverable { operations.finish_pending(path, None); }
            Ok(operations)
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
        self.observe_candidate_with_event(root_id, path, admission, recovery, captured, tracker, event.as_ref(), None)
    }

    fn observe_candidate_with_event(
        &mut self, root_id: &str, path: String, admission: CandidateAdmission,
        recovery: Option<Arc<Recovery>>, captured: Option<&WatchCandidateRow>,
        tracker: Option<quiet::Activity>, event: Option<&CandidateEvent>,
        observation: Option<quiet::Observation>,
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
        let blocked = self.journal.state().entry_by_key(&id);
        let interrupted = blocked
            .as_ref()
            .filter(|entry| entry.status == "interrupted");
        let baseline = interrupted
            .map(|entry| entry.change_usn)
            .or_else(|| self.pending.get(&id).map(|entry| entry.candidate.observation.change_usn))
            .or_else(|| captured.map(|value| value.observation.change_usn))
            .or_else(|| previous.as_ref().map(|value| value.change_usn))
            .or_else(|| blocked.as_ref().map(|value| value.change_usn));
        let activity = self.hub.activities.bind(&id, || {
            self.pending.get(&id).map(|pending| pending.quiet.clone())
                .or_else(|| tracker.clone()).unwrap_or_else(|| previous.as_ref()
                    .map_or_else(quiet::Activity::default, quiet::Activity::saved))
        });
        // A coalesced capture can cover a shorter USN interval than the
        // scheduler's saved observation. Re-read only when that interval is
        // needed to classify the change against the older generation.
        let current = match observation.filter(|observation| {
            observation.since_usn.unwrap_or(0) == baseline.unwrap_or(0)
                || baseline == Some(observation.candidate.observation.change_usn)
        }) {
            Some(observation) => Ok((Some(observation.candidate), observation.now, observation.at)),
            None => activity.probe(Path::new(&path), baseline),
        };
        let (candidate, observed_now, observed_at) = match current {
            Ok((Some(candidate), now, at)) => (candidate, now, at),
            Ok((None, _, _)) => {
                self.candidate_diagnostics.log_unobservable(
                    &self.journal, admission_now(), &id, &path);
                return Ok(());
            }
            Err(error) if missing_path(&error) => {
                self.candidate_diagnostics.retire_path(&id, false);
                return Ok(());
            }
            Err(error) => {
                self.candidate_diagnostics.log_observation(
                    &self.journal, admission_now(), &id, &path, &error, event);
                return Ok(());
            }
        };
        // Workers can acquire a sibling while the filesystem probe runs.
        if self.defer_claimed_path(&id) { return Ok(()); }
        if recovery.is_some() && blocked.as_ref().is_some_and(|before|
            crate::postprocess::watch_source_changed(before.size.max(0) as u64, before.mtime,
                &before.file_id, before.change_usn, &candidate)) {
            self.retire_recovery(std::iter::once(path))?;
            return Ok(());
        }
        let blocked_unchanged = blocked.as_ref().is_some_and(|before| !entry_changed(before, &candidate));
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
                let now = admission_now();
                if boundary && baseline != Some(candidate.observation.change_usn) {
                    pending.quiet.metadata(&candidate, observed_now);
                    // CLOSE is a useful hint only if a writer hasn't reopened
                    // the file. Keep short existing waits on their cadence.
                    if pending.due.saturating_duration_since(now).as_millis() >= 100
                        && admission_readable(&candidate.path).unwrap_or(false)
                    {
                        self.due.remove(&(pending.due, id.clone()));
                        pending.quiet.accelerate(observed_now, now);
                        pending.due = now;
                        if !self.active_paths.contains_key(&id)
                            && !self.hub.claims.lock().unwrap().contains_key(&id)
                        {
                            self.due.insert((now, id.clone()), ());
                        }
                    }
                }
                if quiet::observation_changed(&pending.candidate, &candidate) {
                    self.unpublished.insert(id);
                    pending.candidate = candidate;
                }
            }
            return Ok(());
        }
        if !unchanged { self.catalog.content_changed(&path); }
        // Retire blockers from the replaced generation before peer recovery
        // can invalidate that old input and discard this new pending arrival.
        if let Some(retired) = interrupted.or_else(|| blocked.as_ref().filter(|_| !blocked_unchanged)) {
            self.journal.commit(false, |state| {
                Ok(if state.entry(&candidate.path).is_some_and(|current| Arc::ptr_eq(retired, &current)) {
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
        self.persist_candidates_and_retire(cursors, durable, None, &[])
    }

    fn persist_candidates_and_retire(
        &mut self,
        cursors: BTreeMap<String, crate::watch_store::Cursor>,
        durable: bool,
        retire: Option<&str>,
        prepared: &[(String, Pending)],
    ) -> io::Result<()> {
        if self.unpublished.is_empty() && cursors.is_empty() && retire.is_none() {
            return Ok(());
        }
        let keys = &self.unpublished;
        let root_scope_records = &mut self.root_scope_records;
        self.journal.commit(durable, |state| {
            use crate::watch_store::PendingObservation;
            let mut ordinary = Vec::new();
            let mut forced = Vec::new();
            let mut recoveries = Vec::new();
            let pending = keys.iter().filter_map(|key| self.pending.get(key))
                .chain(prepared.iter().filter(|(key, _)| keys.contains(key)).map(|(_, pending)| pending));
            for pending in pending {
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
                        Some(Arc::new(recovery.record())),
                    );
                    recoveries.push((update, pending.force, &recovery.password_scope));
                } else {
                    let target = if pending.force {
                        &mut forced
                    } else {
                        &mut ordinary
                    };
                    // All queued observations for this root share the same
                    // immutable scope until reconciliation installs new policy.
                    let record = root_scope_records.get(&pending.root).cloned().unwrap_or_else(|| {
                        let record = Arc::new(scope_record(scope));
                        root_scope_records.insert(pending.root.clone(), Arc::clone(&record));
                        record
                    });
                    target.push((observation, scope.root.clone(), Some(record)));
                }
            }
            let cursors = (!cursors.is_empty()).then_some(cursors);
            let mut operations = state.pending_operations(ordinary, false, "", false, cursors);
            if !forced.is_empty() {
                operations.extend(state.pending_operations(forced, true, "", false, None));
            }
            for (update, force, password_scope) in recoveries {
                operations.extend(state.pending_operations(
                    std::iter::once(update),
                    force,
                    &password_scope.to_string_lossy(),
                    true,
                    None,
                ));
            }
            if let Some(owner) = retire {
                operations.finish_pending(owner, state.entry(owner));
            }
            Ok(operations)
        })?;
        self.unpublished.clear();
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
        if changed { state.clear_volume_checks(); }
        if changed || startup {
            // A prior runtime can publish the password generation before
            // scheduling every affected blocker. Reconcile entries once when
            // taking ownership, even if the global generation is current.
            self.retry_password_failures(&snapshot, None,
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

    fn retry_password_failures(&mut self,
        snapshot: &crate::core::passwords::PasswordSnapshot,
        roots: Option<&HashSet<String>>, event: &'static str,
    ) -> io::Result<()> {
        for entry in self.journal.state().entry_items("password") {
            let route = self.blocker_route(&entry);
            if roots.is_some_and(|roots| !route.as_ref().is_some_and(|(root, _)| roots.contains(root))) {
                continue;
            }
            self.invalidate_recovery(std::iter::once(entry.path.clone()))?;
            if self.journal.state().entry(&entry.path).is_none() { continue; }
            let Some((root, recovery)) = route else {
                continue;
            };
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
                CandidateAdmission::PasswordRetry, recovery, None, None, Some(&CandidateEvent::Business(event)), None)?;
            self.journal
                .log(json!({"event":"retry_password_failure","path":entry.path}));
        }
        Ok(())
    }

    fn retry_volume_peers(&mut self, scope: &NativeDiscoveryScope, stem: &str, retried: &mut HashSet<Arc<str>>) -> io::Result<()> {
        for id in self.catalog.bucket_keys(scope, stem) {
            if retried.contains(&id) { continue; }
            if let Some(entry) = self.journal.state().entry_by_key(&id)
                .filter(|entry| entry.waits_for_volume()) {
                retried.insert(id);
                self.check_volume_waiter(&entry, None)?;
            }
        }
        Ok(())
    }

    fn check_volume_waiter(
        &mut self,
        entry: &crate::watch_store::EntryRecord,
        reconciled_route: Option<(String, Option<Arc<Recovery>>)>,
    ) -> io::Result<()> {
        let retry_incomplete = reconciled_route.is_some();
        let Some((root, recovery)) = reconciled_route.or_else(|| self.blocker_route(entry)) else { return Ok(()); };
        let id = watch_path_key(&entry.path);
        let watched = &self.roots[&root].1;
        let catalog_visible = self.catalog.dependency_contains(watched, &entry.path) && !self.catalog.is_owned(&entry.path);
        let scope = if catalog_visible { watched.clone() }
            else if let Some(recovery) = &recovery { recovery.scope.clone() }
            else { return Ok(()); };
        let (modified, added) = if catalog_visible { self.catalog.bucket_revisions(&scope, &entry.path) } else { (0, 0) };
        let revision = if entry.is_missing_volume() { modified } else {
            if added <= entry.layout_checked_at || self.pending.contains_key(&id) { return Ok(()); }
            added
        };
        if !self.journal.state().volume_check_needed(&id, entry, revision, retry_incomplete) { return Ok(()); }
        self.invalidate_recovery(std::iter::once(entry.path.clone()))?;
        if self.journal.state().entry_by_key(&id).is_none() || self.defer_claimed_path(&id) { return Ok(()); }
        let policy = &self.roots[&root].0;
        let mut request = Request::with_config(vec![PathBuf::from(&entry.path)], Mode::Extract, Arc::clone(&self.settings));
        request.origin = Origin::Watch;
        request.deep = policy.deep;
        request.passwords = Arc::clone(&self.settings.user_passwords);
        request.password_snapshot = Some(self.passwords.snapshot());
        request.password_scope = Some(candidate_password_scope(self.journal.state(), &entry.path, recovery.as_deref()));
        request.discovery_scope = Some(scope);
        if catalog_visible { request.watch_catalog = Some(Arc::clone(&self.catalog)); }
        let engine = Arc::clone(&self.engine);
        let options = if policy.deep { &self.deep_options } else { self.options.as_ref().unwrap_or(&self.deep_options) };
        let lookup = engine.run_stage("volume_lookup", Origin::Watch, || engine.find_watch_volume(&request, options, retry_incomplete))?;
        self.retire_dependency_observers();
        let prepared = match lookup {
            Ok(prepared) => prepared,
            Err(error) => {
                self.journal.log(json!({"event":"volume_lookup_failed","path":entry.path,"error":error.to_string()}));
                return Ok(());
            }
        };
        if prepared.is_some() {
            // A claim or a replacement can arrive during lookup. Keep a
            // prepared plan only while there is an admission to hand it to.
            self.journal.state().forget_volume_checks(&id, false);
            self.observe_candidate_with_event(&root, entry.path.clone(), CandidateAdmission::Retry,
                recovery, None, None, Some(&CandidateEvent::Business("volume_changed")), None)?;
            if !self.pending.contains_key(&id) { return Ok(()); }
        }
        self.journal.state().record_volume_check(id, entry, revision, prepared);
        Ok(())
    }

    fn retry_missing_volumes(&mut self, roots: Option<&HashSet<String>>) -> io::Result<()> {
        for entry in self.journal.state().entry_items("missing_volume") {
            let Some(route) = self.blocker_route(&entry) else { continue; };
            if roots.is_none_or(|roots| roots.contains(&route.0)) {
                // Startup/policy reconciliation deliberately retries incomplete
                // inputs too: a changed content policy may accept retained work.
                self.check_volume_waiter(&entry, Some(route))?;
            }
        }
        self.persist_candidates(BTreeMap::new(), true)
    }

    fn blocker_route(
        &self,
        entry: &crate::watch_store::EntryRecord,
    ) -> Option<(String, Option<Arc<Recovery>>)> {
        route_blocker(entry, &self.roots)
    }

    fn recover_pending(&mut self, roots: Option<&HashSet<String>>) -> io::Result<()> {
        let settled = recover_flattens(&self.journal, |owner| {
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
        self.recover_continuations(roots)?;
        let scopes = self.roots.values().map(|(_, scope)| scope.clone()).collect::<Vec<_>>();
        let published = self.catalog.publish_outputs(&settled, &scopes, &self.deep_options, None)?;
        if !published.is_empty() { self.hub.update(|signals| signals.published_outputs.extend(published)); }
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
        'pending: for pending in self.journal.state().pending_items() {
            let id = watch_path_key(&pending.path);
            if flatten_owners.contains(&id)
                || self.pending.contains_key(&id)
                || self.active_paths.contains_key(&id)
                || self.hub.claims.lock().unwrap().contains_key(&id)
            {
                continue;
            }
            let original = watch_path_key(&pending.source_input_root);
            let path_key = crate::path_keys::path_key(&pending.path);
            let root = self
                .roots
                .get(&original)
                .and_then(|(_, scope)| {
                    (pending.internal_recovery || scope.contains_key(&path_key)).then_some(original)
                })
                .or_else(|| {
                    containing_root(&self.roots, &path_key).map(|(id, _)| id.clone())
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
            if pending.internal_recovery {
                let changed = match watch_candidate_for_path(Path::new(&pending.path), Some(pending.change_usn)) {
                    Ok(Some(current)) => crate::postprocess::watch_source_changed(pending.size.max(0) as u64,
                        pending.mtime, &pending.file_id, pending.change_usn, &current),
                    Ok(None) => true,
                    Err(error) if missing_path(&error) => true,
                    Err(_) => continue,
                };
                if changed {
                    self.retire_recovery(std::iter::once(pending.path.clone()))?;
                    continue;
                }
            }
            let source = Path::new(&pending.path);
            let entry = state.entry(&pending.path);
            // Failure recovery may retain a carrier across a retry. Successful
            // work is recovered through the pending output records below.
            let mut retained_containers = HashSet::new();
            for checkpoint in input_checkpoints(entry.as_deref()) {
                if let Some(container) = checkpoint?.retained_container() {
                    retained_containers.insert(key(container));
                }
            }
            let mut revisit = BTreeMap::new();
            let mut inspected_outputs = HashSet::new();
            let mut cleanup_failed = false;
            let has_active_output = !pending.active_outputs.is_empty();
            for (task, output) in pending.active_outputs.iter() {
                if pending.committed_roots.contains(output) {
                    continue;
                }
                let output_key = watch_path_key(output);
                if retained_containers.contains(&output_key) {
                    continue;
                }
                if inspected_outputs.insert(output_key) {
                    if recovery_output_matches(&pending, output) {
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
                    let mut operations = crate::watch_store::NativeWatchOperations::empty();
                    operations.finish_pending(&pending.path, Some(entry));
                    Ok(operations)
                })?;
                continue;
            }
            if pending.committed_roots.iter().next().is_none()
                && !has_active_output
                && source.is_file()
            {
                revisit.insert(id.clone(), pending.path.clone());
            }
            let mut verified = Vec::new();
            let mut missing_output = false;
            for output in pending.committed_roots.iter() {
                if recovery_output_matches(&pending, output) {
                    verified.push(output);
                } else {
                    missing_output = true;
                }
            }
            if missing_output {
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
            let password_scope = PathBuf::from(&pending.password_scope_dir);
            let mut recoveries = HashMap::with_capacity(verified.len());
            for output in &verified {
                let output_scope = NativeDiscoveryScope::new((*output).clone(), None, Vec::new());
                let Ok(paths) = recovery_scan_paths(
                    &self.journal, &pending.path, output,
                    crate::scan::directory::scope_file_paths(&output_scope),
                ) else {
                    continue 'pending;
                };
                for path in paths {
                    let path = path.to_string_lossy().into_owned();
                    if !pending.completed_sources.contains(&path)
                        && fs::metadata(&path).is_ok_and(|metadata| metadata.len() > 0)
                    {
                        revisit.insert(watch_path_key(&path), path);
                    }
                }
                recoveries.insert(watch_path_key(output).trim_end_matches('\\').to_owned(), Arc::new(Recovery {
                    max_depth: None,
                    scope: output_scope,
                    password_scope: password_scope.clone(),
                    parent: None,
                }));
            }
            if revisit.is_empty() && verified.is_empty() {
                if has_active_output {
                    self.journal.log(json!({"event":"crash_recovery_source_missing","owner_path":pending.path}));
                    continue;
                }
                if source.is_file() {
                    revisit.insert(watch_path_key(&pending.path), pending.path.clone());
                } else if !recorded_file_is_absent(&pending.path) {
                    continue;
                }
            }
            let owner = id;
            let mut rebase = !revisit.contains_key(&owner);
            let has_output_work = pending.has_output_work();
            let admission = if pending.internal_recovery || has_output_work {
                CandidateAdmission::CrashRecovery
            } else if pending.force {
                CandidateAdmission::Retry
            } else {
                CandidateAdmission::QueuedRecovery
            };
            let event = CandidateEvent::Business(if has_output_work { "crash_recovery" } else { "recovery" });
            let saved_recovery = std::cell::OnceCell::new();
            for (id, path) in revisit {
                if state.entry_by_key(&id).is_some_and(|entry| {
                    (entry.status == "failed_password" || entry.waits_for_volume())
                        && !(id == owner && pending.force && entry.waits_for_layout())
                }) {
                    continue;
                }
                let recovery = if id == owner && !pending.internal_recovery {
                    None
                } else {
                    let nested = crate::path_keys::path_ancestors(&id).skip(1)
                        .find_map(|ancestor| recoveries.get(ancestor));
                    let recovery = nested.or_else(|| {
                        saved_recovery.get_or_init(|| {
                            Recovery::from_record(&pending.discovery_scope, &pending.password_scope_dir)
                                .map(Arc::new)
                        }).as_ref().filter(|recovery| recovery.scope.contains(&path))
                    });
                    Some(recovery.cloned().unwrap_or_else(|| Arc::new(Recovery {
                        max_depth: None,
                        scope: if scope.contains(&path) {
                            scope.clone()
                        } else {
                            let parent = Path::new(&path).parent().unwrap_or(Path::new("."));
                            NativeDiscoveryScope::new(
                                parent.to_string_lossy().into_owned(),
                                Some(0),
                                Vec::new(),
                            )
                        },
                        password_scope: password_scope.clone(),
                        parent: None,
                    })))
                };
                self.observe_candidate_with_event(&root, path.clone(), admission, recovery, None, None,
                    Some(&event), None)?;
                if !self.pending.contains_key(&id) && !recorded_file_is_absent(&path) {
                    rebase = false;
                }
            }
            self.persist_candidates_and_retire(
                BTreeMap::new(),
                true,
                rebase.then_some(pending.path.as_str()),
                &[],
            )?;
        }
        self.persist_candidates(BTreeMap::new(), true)?;
        Ok(())
    }
}

fn missing_path(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn output_identity(path: &str) -> io::Result<String> {
    filesystem::directory_identity(path)
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
    pending: &crate::watch_store::PendingRecord,
    path: &str,
) -> bool {
    let Ok(Some(actual)) = identity_if_present(path) else {
        return false;
    };
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
        crate::pipeline::MAX_PENDING_JOBS.saturating_sub(self.active_paths.len())
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
            if self.retire_owned_admission(&id, &pending)? { continue; }
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
                    self.candidate_diagnostics.log_wait(&self.journal, admission_now(), &id, &pending.candidate.path, Some(&error));
                    self.delay(id, pending, admission_now());
                    continue;
                }
            };
            #[cfg(test)]
            admission_tests::before_readiness(&pending.candidate.path);
            let (current, readable) = match admission_candidate(current, previous_usn) {
                Ok(value) => value,
                Err(error) if missing_path(&error) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(error) => {
                    self.candidate_diagnostics.log_wait(&self.journal, admission_now(), &id, &pending.candidate.path, Some(&error));
                    self.delay(id, pending, admission_now());
                    continue;
                }
            };
            // A callback can arrive while the filesystem readiness probe runs.
            // Read its generation and deadline atomically, not as independent
            // matches/deadline checks that could accept a just-written file.
            if pending.recovery.is_some() && crate::postprocess::watch_source_changed(
                pending.candidate.size, pending.candidate.mtime, &pending.candidate.observation.file_id,
                previous_usn, &current) {
                self.retire_recovery(std::iter::once(pending.candidate.path.clone()))?;
                continue;
            }
            let (captured, deadline) = pending.quiet.observation(&current);
            if let Some(deadline) = deadline.filter(|deadline| *deadline > now && *deadline > pending.due) {
                pending.due = deadline;
                self.due.insert((deadline, id.clone()), ());
                self.pending.insert(id, pending);
                continue;
            }
            if quiet::changed(&pending.candidate, &current) && !captured {
                self.catalog.content_changed(&current.path);
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
            if quiet::observation_changed(&pending.candidate, &current) {
                self.unpublished.insert(id.clone());
            }
            pending.candidate = current;
            if !readable {
                self.candidate_diagnostics.log_wait(&self.journal, admission_now(), &id, &pending.candidate.path, None);
                self.delay(id, pending, admission_now());
                continue;
            }
            if let Err(deadline) = pending.quiet.admit(observed_now, admission_now()) {
                pending.due = deadline;
                self.due.insert((deadline, id.clone()), ());
                self.pending.insert(id, pending);
                continue;
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
        if prepared.is_empty() {
            // Retirement during readiness can drain the last pending item
            // without a completion event to arm cache cleanup.
            self.arm_idle_cleanup();
            return Ok(());
        }
        // main persists the first admitted generation before checkpointing the
        // event burst, then submits that same batch without another readiness
        // gate. Events during checkpoint remain independent pending candidates.
        self.persist_candidates_and_retire(BTreeMap::new(), true, None, &prepared)?;
        self.checkpoint(&HashMap::new(), true, false)?;
        #[cfg(test)]
        if let Some(check) = self.admission_checkpoint.take() { check(self)?; }
        let mut groups = BTreeMap::new();
        let mut arrivals = HashSet::new();
        let retry_volumes = self.journal.state().has_volume_waiters();
        for (id, pending) in prepared {
            // main's submit still checks output ownership and active claims;
            // these are not a second quiet/readiness decision.
            if self.retire_owned_admission(&id, &pending)? { continue; }
            if self.active_paths.contains_key(&id) || self.hub.claims.lock().unwrap().contains_key(&id) {
                // A checkpoint event may already have queued a newer generation.
                // Never replace that pending observation with this admitted one.
                let pending = self.pending.entry(id.clone()).or_insert(pending);
                self.due.insert((pending.due, id), ());
                continue;
            }
            if (retry_volumes || !self.active.is_empty()) && pending.recovery.is_none() {
                // A named arrival can be ready before its USN record is visible.
                let (policy, scope) = &self.roots[&pending.root];
                if self.catalog.peer_needs_inventory(scope, &id, &pending.candidate.path) {
                    self.scan_options(policy.deep)?.catalog_update(&self.catalog, scope, Some(&pending.candidate.path))?;
                }
            }
            if self.retire_admitted_observation(&id, &pending) && retry_volumes {
                arrivals.insert((pending.root.clone(), crate::scan::catalog::catalog_stem(&pending.candidate.path)));
            }
            let password_scope = candidate_password_scope(self.journal.state(),
                &pending.candidate.path, pending.recovery.as_deref());
            let source = (pending.candidate, pending.quiet);
            // Local recovery has its own discovery and durable owner. Catalog
            // discovery keeps each relation family's errors inside the batch.
            let recovery_owner = pending.recovery.as_ref().map(|_| source.0.path.clone());
            let (_, candidates) = groups
                .entry((pending.root, password_scope, recovery_owner))
                .or_insert_with(|| (pending.recovery, Vec::new()));
            candidates.push(source);
        }
        let mut retried = HashSet::new();
        for (root, stem) in arrivals {
            let scope = self.roots[&root].1.clone();
            self.retry_volume_peers(&scope, &stem, &mut retried)?;
        }
        if groups.is_empty() {
            self.arm_idle_cleanup();
            return Ok(());
        }
        let engine = Arc::clone(&self.engine);
        engine.run_stage("watch_admission", Origin::Watch, || {
            for ((root, password_scope, _), (recovery, candidates)) in groups {
                if self.hub.stopped.load(Ordering::Acquire) {
                    // These candidates still have durable pending intent.
                    break;
                }
                self.start_batch(root, candidates, recovery, password_scope)?;
            }
            Ok(())
        })?
    }

    #[inline]
    fn retire_admitted_observation(&self, id: &str, pending: &Pending) -> bool {
        let (seconds, last, cadence, tentative) = pending.quiet.summary();
        self.journal.log(json!({
            "event":"candidate_quiet", "path":pending.candidate.path,
            "quiet_seconds":seconds,
        }));
        // A restored blocker already proves that its own head was admitted.
        let newly_available = !pending.force || !self.journal.state().entry_by_key(id).is_some_and(|e| e.waits_for_volume());
        pending.recovery.is_none() && self.catalog.retire_observation(
            &pending.candidate.path, Some(seconds), last, cadence, tentative, newly_available,
        )
    }

    fn retire_owned_admission(&mut self, id: &str, pending: &Pending) -> io::Result<bool> {
        if pending.recovery.is_some() || !self.journal.state().owns_path(&pending.candidate.path) {
            return Ok(false);
        }
        // A checkpoint may have queued another generation under this key.
        // Retiring the admitted generation must not clear that update's WAL work.
        if !self.pending.contains_key(id) {
            self.unpublished.remove(id);
            self.journal.state().forget_volume_checks(id, false);
        }
        self.journal.commit(false, |state| {
            let mut operations = crate::watch_store::NativeWatchOperations::empty();
            if state.pending(&pending.candidate.path).is_some_and(|record| {
                record.matches_observation(&pending.candidate) && !record.has_output_work()
            }) {
                operations.retire_pending(id.to_owned());
            }
            Ok(operations)
        })?;
        self.journal.log(json!({"event":"task_retired","path":pending.candidate.path}));
        Ok(true)
    }

    fn retire_admission(&mut self, id: &str, pending: &Pending) -> io::Result<()> {
        self.unpublished.remove(id);
        self.journal.state().forget_volume_checks(id, false);
        let path = &pending.candidate.path;
        if self
            .roots
            .get(&pending.root)
            .is_some_and(|(root, _)| root.path.is_dir())
            && pending
                .recovery
                .as_ref()
                .is_none_or(|recovery| Path::new(&recovery.scope.root).is_dir())
            && recorded_file_is_absent(path)
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

    fn start_batch(
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
        let mut request = Request::with_config(
            candidates.iter().map(|input| PathBuf::from(&input.path)).collect(),
            Mode::Extract,
            Arc::clone(&self.settings),
        );
        request.origin = Origin::Watch;
        request.cancel = cancel.clone();
        request.cleanup_boundaries = self.roots.values().map(|(root, _)| root.path.clone()).collect();
        // Catalog-backed recovery can join ordinary and generated peers.
        // The local scope remains the fallback when no catalog row is visible.
        let catalog_recovery = recovery.is_some()
            && candidates.iter().all(|candidate| self.catalog.dependency_contains(&scope, &candidate.path)
                && !self.catalog.is_owned(&candidate.path));
        let local_recovery = recovery.as_ref().filter(|_| !catalog_recovery);
        let nested_recovery = recovery.as_ref().is_some_and(|recovery| {
            watch_path_key(&recovery.scope.root) != watch_path_key(&scope.root)
        });
        if !nested_recovery {
            request.output_root = root.output.clone();
        }
        request.max_depth = cli::depth(self.settings.recursive_extract).min(recovery.as_ref().and_then(|r| r.max_depth).unwrap_or(usize::MAX));
        request.start_depth = recovery.as_deref().map_or(1, Recovery::start_depth);
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
        }
        let layout_checked_at = self.journal.state().take_prepared_volumes(candidates.iter().map(|input| input.path.as_str()),
            &mut request.prepared_volumes);
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
        let claimed = Arc::new(Mutex::new(ClaimedSources { layout_checked_at, ..ClaimedSources::default() }));
        let worker_claimed = Arc::clone(&claimed);
        let worker_cancel = cancel.clone();
        self.journal
            .log(json!({"event":"pipeline_request_started","owner":batch,
            "path":candidates.first().map(|entry| &entry.path),"count":candidates.len()}));
        let observer = Arc::new(WatchObserver {
            deep: root.deep,
            dedup: Arc::clone(&self.dedup),
            dedup_enabled: self.settings.watch.deduplication != config::WatchDeduplication::None,
            dedup_scope: scope.clone(),
            catalog: Arc::clone(&self.catalog),
            journal,
            owners,
            outputs: Mutex::new(ObservedOutputs::from(outputs)),
            batch: worker_batch,
            toast: worker_toast,
            hub: Arc::clone(&hub),
            groups: worker_groups,
            claimed: worker_claimed,
        });
        let max_depth = request.max_depth;
        let request_handle = engine.submit(request, Arc::clone(&observer), move |result| {
            let cancelled = worker_cancel.cancelled();
            let report_path = report_path.filter(|_| !result.as_ref().is_ok_and(|outcome| {
                outcome.coalesced_from.is_some()
            }));
            if let (Some(toast), Some(path)) = (&observer.toast, report_path) {
                let claimed = observer.claimed.lock().unwrap();
                let groups = observer.groups.lock().unwrap();
                let groups = &groups.roots;
                let outputs = observer.outputs.lock().unwrap();
                if result.is_err() {
                    let mut reported = HashSet::new();
                    let sources = observer.owners.iter().filter_map(|(source_key, source)| {
                        if claimed.finished.contains(source_key) { return None; }
                        let source = groups.get(source_key).map_or(Path::new(source), |group| group.path.as_path());
                        reported.insert(key(source)).then_some(source)
                    });
                    toast.record(sources, &result, cancelled,
                        |path| completion_owner(path, &outputs.paths, groups));
                } else {
                    toast.record(
                        [path.as_path()],
                        &result,
                        cancelled,
                        |path| completion_owner(path, &outputs.paths, groups),
                    );
                }
            }
            let outputs = std::mem::take(&mut *observer.outputs.lock().unwrap()).paths;
            Completed {
                cancelled,
                result,
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
                max_depth,
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
            let Some(toast) = &self.toast else { return Ok(false); };
            let requests = toast.stop_group(id);
            if requests.is_empty() { return Ok(true); }
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
                for cancel in cancellations { cancel.cancel(); }
            });
            if let Err(error) = &result {
                journal.log(json!({"event":"watch_cancel_persistence_failed","error":error.to_string()}));
                for request in requests { if let Some(active) = self.active.get(request.as_ref()) { active.cancel.cancel(); } }
            }
            result.map(|()| true)
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
        if claimed.coalesced {
            return Some(active.cancel.clone());
        }
        let siblings = claimed.candidates.iter()
            .filter(|(path, _)| !active.inputs.contains_key(*path))
            .filter_map(|(_, candidate)| candidate.as_ref());
        let mut interrupted = crate::watch_store::NativeWatchOperations::empty();
        for input in active.inputs.values().chain(siblings) {
            let id = watch_path_key(&input.path);
            if claimed.finished.contains(&id)
                || self.hub.claims.lock().unwrap().get(&id).is_some_and(|owner| owner.as_ref() != batch)
                || self.pending.get(&id).is_some_and(|pending| quiet::changed(input, &pending.candidate))
                || recorded_file_is_absent(&input.path)
            {
                continue;
            }
            interrupted.put_entry(Arc::new(observed_entry(input, "interrupted")));
            if let Some(pending) = self.pending.remove(&id) {
                self.due.remove(&(pending.due, id.clone()));
                self.unpublished.remove(&id);
            }
        }
        // Claims now see the cancellation flag. The scheduler applies any
        // completion after this commit, so the durable wait needs no claim lock.
        drop(claimed);
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
        self.release_request_display_claims(batch);
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
                let request = root.request;
                let (result, tickets) = journal.prepare_waits(|| self.prepare_root(root));
                Some((reply, toast, id, request, result, tickets))
            }).collect::<Vec<_>>();
            let mut failure = None;
            for (reply, toast, id, request, result, tickets) in replies {
                let durable = journal.wait_prepared(tickets);
                let result = result.and_then(|(outcome, members)| durable.map(|()| {
                    engine.retire_watch_inputs(request, &members);
                    outcome
                }));
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

    fn prepare_root(&mut self, root: RootCompleted) -> io::Result<(Outcome, HashSet<String>)> {
        let Some(active) = self.active.get_mut(&root.batch) else {
            return Err(io::Error::other("Watch request already retired"));
        };
        let members: HashSet<_> = root.groups.keys().cloned()
            .chain(std::iter::once(root.root_key)).collect();
        let mut inputs = Vec::new();
        let mut dirty = HashSet::new();
        let mut quiet = HashMap::new();
        for member in &members {
            if let Some(path) = active.dirty.take(member) { dirty.insert(path); }
            if let Some(input) = active.inputs.remove(member) { inputs.push(input); }
            if let Some((path, tracker)) = active.quiet.remove_entry(member) { quiet.insert(path, tracker); }
        }
        crate::collections::trim_map(&mut active.inputs);
        crate::collections::trim_map(&mut active.quiet);
        let group = root.groups.values().next().cloned();
        let context = CompletionContext {
            max_depth: active.max_depth,
            deep: active.deep,
            root: active.root.clone(), recovery: active.recovery.clone(), password_scope: active.password_scope.clone(), passwords: Arc::clone(&active.passwords),
            inputs, quiet, dirty, claimed: Arc::clone(&active.claimed), groups: root.groups, toast: active.toast.clone(), task: Some(root.id),
        };
        let result = self.apply_completion(&root.batch, context, root.completed);
        if let Some(group) = group {
            self.journal.log(json!({"event":"pipeline_sources_released","owner":root.batch,"path":group.path}));
        }
        let (outcome, _) = result?;
        let active = &self.active[&root.batch];
        let mut claimed = active.claimed.lock().unwrap();
        let groups = active.groups.lock().unwrap();
        let mut retired = members;
        retired.retain(|member| !groups.members.contains_key(member));
        // Completion has consumed the observations, including dirty paths.
        // Keep a shared member's original generation until its last owner settles.
        for member in &retired {
            claimed.candidates.remove(member);
            claimed.deduplicated.remove(member);
        }
        crate::collections::trim_map(&mut claimed.candidates);
        if claimed.deduplicated.capacity() > 256.max(claimed.deduplicated.len().saturating_mul(4)) {
            let remaining = claimed.deduplicated.len();
            claimed.deduplicated.shrink_to(remaining.saturating_mul(2));
        }
        Ok((outcome, retired))
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
        let result = active.request.join()
            .map_err(|_| io::Error::other("Watch extraction request failed"))
            .and_then(|mut completed| {
                completed.cancelled |= active.cancel.cancelled();
                let groups = std::mem::take(&mut *active.groups.lock().unwrap()).into_aliases();
                self.apply_completion(batch, CompletionContext {
                    max_depth: active.max_depth,
                    deep: active.deep,
                    root: active.root, recovery: active.recovery, password_scope: active.password_scope, passwords: active.passwords,
                    inputs: active.inputs.into_values().collect(), quiet: active.quiet, dirty: active.dirty, claimed: active.claimed, groups, toast: active.toast, task: None,
                }, completed).map(|(_, finish)| finish)
            });
        self.release_request_display_claims(batch);
        result
    }

    fn apply_completion(&mut self, batch: &str, mut active: CompletionContext, completed: Completed) -> io::Result<(Outcome, Option<super::toast::Finish>)> {
        // Root and request completion already run on the shared blocking stage.
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
                if let Some(entry) = self.journal.state().entry(&path)
                    .filter(|entry| entry.waits_for_volume()) {
                    self.check_volume_waiter(&entry, None)?;
                    continue;
                }
                let admission = CandidateAdmission::Observe;
                self.observe_candidate_with_event(&root, path, admission, recovery.clone(), captured.as_ref(), tracker,
                    Some(&CandidateEvent::Business("pipeline_claim_released")), None)?;
            }
        }
        Ok(result)
    }

    fn apply_completion_blocking(&mut self, batch: &str, active: CompletionContext, completed: Completed, quiet: &mut HashMap<String, quiet::Activity>) -> io::Result<(Outcome, Option<super::toast::Finish>)> {
        let published_outputs = if completed.outputs.is_empty() {
            Vec::new()
        } else {
            let paths: Vec<_> = completed.outputs.keys().cloned().collect();
            self.ensure_dependency_observers(&active.root, paths.iter().map(PathBuf::from))?;
            let scopes: Vec<_> = self.roots.values().map(|(_, scope)| scope.clone()).collect();
            self.catalog.publish_outputs(&paths, &scopes, &self.deep_options, Some(&active.root))?
        };
        let coalesced_from = completed.result.as_ref().ok().and_then(|outcome| outcome.coalesced_from);
        let mut unfinished = HashSet::new();
        if completed.cancelled && coalesced_from.is_none() {
            let state = self.journal.state();
            for input in &active.inputs {
                let Some(record) = state.pending(&input.path) else {
                    continue;
                };
                if let Some(output) = record.active_outputs.values().find(|output| {
                    !record.committed_roots.contains(output)
                        && !recorded_file_is_absent(output)
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
                completed.cancelled && coalesced_from.is_none(),
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
            for path in completion_claims(active.task, &groups, &claimed) { release(path); }
            for input in &active.inputs { release(&watch_path_key(&input.path)); }
            crate::collections::trim_map(&mut claims);
        }
        // Changes observed during ownership are the next generation, not
        // members of the completed request. Restore only their admission keys.
        {
            let claimed = active.claimed.lock().unwrap();
            for path in completion_claims(active.task, &groups, &claimed) {
                if let Some(pending) = self.pending.get(path) {
                    self.due.insert((pending.due, path.clone()), ());
                }
            }
        }
        for candidate in &active.inputs {
            let id = watch_path_key(&candidate.path);
            self.active_paths.remove(&id);
            if let Some(pending) = self.pending.get(&id) {
                self.due.insert((pending.due, id), ());
            }
        }
        if let Some(owner) = coalesced_from {
            // The leader publishes the physical outcome and its blockers.
            // Retire only follower observations which are still current.
            use crate::watch_store::NativeWatchOperations;
            self.journal.commit(false, |state| {
                let mut operations = NativeWatchOperations::empty();
                for input in &active.inputs {
                    let id = watch_path_key(&input.path);
                    if !self.pending.contains_key(&id) && state.pending(&input.path)
                        .is_some_and(|record| record.matches_observation(input) && !record.has_output_work())
                    {
                        operations.retire_pending(id);
                    }
                }
                Ok(operations)
            })?;
            for input in &active.inputs {
                self.journal.log(json!({"event":"pipeline_request_coalesced",
                    "path":input.path,"owner":batch,"owner_request_id":owner}));
            }
            self.arm_idle_cleanup();
            return Ok((Outcome::default(), finish));
        }
        let outcome = match completed.result {
            Ok(outcome) => outcome,
            Err(error) if completed.cancelled => {
                self.journal.log(json!({"event":"pipeline_request_interrupted","owner":batch,"error":error.to_string()}));
                self.arm_idle_cleanup();
                return Ok((Outcome::default(), finish));
            }
            Err(error) => {
                let mut absent = crate::watch_store::NativeWatchOperations::empty();
                let error_kind = error.kind();
                let error = error.to_string();
                for candidate in &active.inputs {
                    self.retry_pipeline_error(batch, &active.root, active.recovery.as_ref(),
                        &candidate.path, &error, error_kind, quiet, &mut absent)?;
                }
                self.journal.commit(true, |_| Ok(absent))?;
                self.persist_candidates(BTreeMap::new(), true)?;
                self.arm_idle_cleanup();
                return Ok((Outcome::default(), finish));
            }
        };
        self.catalog.retire_consumed(outcome.archives.iter().flat_map(|archive| archive.source_paths.iter().map(PathBuf::as_path))
            .collect::<HashSet<_>>().into_iter());
        let input_failures = outcome.input_failures();
        let (by_path, success_counts) = completion_archives(&outcome, &completed.outputs, &groups, &input_failures);
        for archive in &outcome.archives {
            if let Some(failure) = archive
                .failure
                .as_ref()
                .filter(|failure| failure.evidence.is_some() || matches!(failure.context.as_deref(),
                    Some(crate::pipeline::FailureContext::Discovery { .. })))
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
        for cleanup in &outcome.cleanup_results {
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
        let current_password_signature = std::cell::OnceCell::new();
        let password_updated = |record: &crate::watch_store::EntryRecord, user_signature: &str| {
            record.failure_payload.get("password_signature").and_then(Value::as_str)
                .is_some_and(|before| {
                    before != current_password_signature.get_or_init(||
                        password_source_signature(user_signature, &current_passwords.scope_signature(&active.password_scope)))
                })
        };
        let mut retry = Vec::new();
        let mut regrouped_recoveries = Vec::new();
        let mut published = HashSet::new();
        let start_depth = active.recovery.as_deref().map_or(1, Recovery::start_depth);
        let parent = active.recovery.as_ref().and_then(|recovery| recovery.parent.as_ref())
            .filter(|_| !active.inputs.is_empty());
        let mut resumed = match parent {
            Some(parent) => continuation::Continuation::load(&self.journal, &parent.id)?
                .map(|continuation| (parent.id.clone(), continuation)),
            None => None,
        };
        let mut parents = HashMap::<String, (String, continuation::Continuation)>::new();
        let mut continuations = Vec::new();
        let generated = std::cell::OnceCell::new();
        let layout_checked_at = active.claimed.lock().unwrap().layout_checked_at;
        let recovery_receipts = std::cell::OnceCell::new();
        let recovery_receipts = || recovery_receipts.get_or_init(|| RecoveryReceipts::new(&outcome.checkpoints));
        for archive in outcome
            .archives
            .iter()
            .filter(|archive| archive.depth > start_depth && nested_retry(archive, &input_failures))
        {
            let input_failure = &input_failures[&crate::path_keys::path_key(&archive.path.to_string_lossy())];
            let failure = input_failure.failure().expect("retained input has a retry cause");
            let id = key(&archive.path);
            if !published.insert(id.clone()) { continue; }
            let Some(candidate) = watch_candidate_for_path(&archive.path, None)? else {
                continue;
            };
            // The completion must not grant recovery to a replacement made
            // after this nested input was examined by the pipeline.
            let source = generated.get_or_init(|| outcome.generated_sources.iter()
                .map(|source| (key(source.path()), source)).collect::<HashMap<_, _>>()).get(&id);
            if !source.is_some_and(|source| crate::io::reader::capture_file_generation(&archive.path)
                .is_ok_and(|current| source.matches(&current))) { continue; }
            if self.active_paths.contains_key(&id) {
                continue;
            }
            if self.hub.completed_families.covers(&archive.path, active.deep) {
                operations.finish_pending(&candidate.path, None);
                continue;
            }
            let regroup = failure.kind == FailureKind::MissingVolume || archive.source_paths.len() > 1;
            if let Some(pending) = self.pending.get(&id) {
                if quiet::changed(&candidate, &pending.candidate) {
                    continue;
                }
                if !regroup {
                    let pending = self.pending.remove(&id).unwrap();
                    self.due.remove(&(pending.due, id.clone()));
                    self.unpublished.remove(&id);
                    self.journal.state().forget_volume_checks(&id, false);
                }
            }
            let group = SourceGroup {
                path: archive.path.clone(),
                members: archive
                    .source_paths
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
            };
            let directory = archive.path.parent().unwrap_or(Path::new(""));
            let continuation = resumed.as_mut().or_else(|| {
                let owner = completion_owner(&archive.path, &completed.outputs, &groups)?;
                Some(parents.entry(owner.clone()).or_insert_with(|| {
                    (continuation::Continuation::id(batch, &owner), continuation::Continuation::default())
                }))
            });
            let parent = continuation.map(|(record, continuation)| {
                continuation.block(id.clone());
                continuation::Parent { id: record.clone(), depth: archive.depth }
            });
            // A generated input resumes at its original depth and password scope.
            let recovery = Recovery {
                max_depth: Some(active.max_depth),
                scope: NativeDiscoveryScope::new(directory.to_string_lossy().into_owned(), Some(0), Vec::new()),
                password_scope: active.password_scope.clone(),
                parent,
            };
            let mut entry = make_blocker(
                &candidate,
                &super::failure::message(failure, self.settings.cli.language),
                input_failure,
                &active.passwords,
                &self.user_password_signature,
                Some(&group),
                Some(&recovery),
                &active.password_scope,
            );
            Arc::make_mut(&mut entry).layout_checked_at = layout_checked_at;
            let payload = &mut Arc::make_mut(&mut entry).failure_payload;
            payload.insert("input_checkpoints".into(), serde_json::to_value(
                recovery_receipts().select(archive.source_paths.iter().map(PathBuf::as_path)))?);
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
            let password_updated = password_updated(&entry, &self.user_password_signature);
            let pending = regroup.then(|| self.pending.get_mut(&id)).flatten();
            let handed_off = pending.is_some();
            handoff_nested_blocker(&mut entry, route_root, root,
                recovery, pending);
            if handed_off {
                self.unpublished.insert(id.clone());
                operations.put_entry(entry);
            } else {
                operations.finish_pending(&candidate.path, Some(entry));
            }
            if (regroup && !self.pending.contains_key(&id)) || password_updated {
                retry.push((candidate.path.clone(), if password_updated {
                    CandidateAdmission::PasswordRetry
                } else { CandidateAdmission::Retry }));
            }
        }
        let output_containers = completion_output_containers(&outcome);
        let canonical_inputs = std::cell::OnceCell::new();
        let mut projected_groups = HashSet::new();
        let mut reported_discovery = HashSet::new();
        for candidate in &active.inputs {
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
            if let Some(error) = input_error {
                if let crate::pipeline::InputErrorKind::WatchDiscoveryIo(kind) = error.kind {
                    if !completed.cancelled {
                        self.retry_pipeline_error(batch, &active.root, active.recovery.as_ref(),
                            &candidate.path, &error.message, kind, quiet, &mut operations)?;
                        continue;
                    }
                }
            }
            // One logical result owns the blocker and archive evidence. For
            // the other volumes, retire only their physical pending records.
            if !completed.cancelled {
                if id != canonical_id {
                    if resumed.is_some() {
                        operations.settle_pending(&candidate.path, None);
                    } else {
                        operations.finish_pending(&candidate.path, None);
                    }
                }
                if self.pending.contains_key(&canonical_id)
                    || !projected_groups.insert(canonical_id.clone())
                {
                    continue;
                }
            }
            let discovery_failure = input_error.and_then(|error| error.failure.as_deref());
            let failed_archive = (input_error.is_none() || discovery_failure.is_some())
                .then(|| archives.and_then(|items| completion_failed_archive(items, &input_failures))).flatten();
            let (mut segments, segment_blockers) = archives
                .filter(|_| group.is_some() && !completed.cancelled)
                .and_then(|archives| completion_segments(archives, start_depth, &input_failures, self.settings.cli.language))
                .map_or((None, InputFailure::default()), |(rows, blockers)| (Some(rows), blockers));
            // Keep the physical claim retryable if any segment is blocked,
            // even if another segment finished with a terminal failure.
            let segment_blocker = segment_blockers.retryable().then_some(&segment_blockers);
            let input_failure = segment_blocker.or_else(|| failed_archive.and_then(|archive| input_failures
                .get(&crate::path_keys::path_key(&archive.path.to_string_lossy()))));
            let failure = segment_blocker.and_then(InputFailure::failure).or(discovery_failure)
                .or_else(|| input_failure.and_then(InputFailure::failure));
            let failure_message = failure.map(|failure| super::failure::message(failure, self.settings.cli.language));
            let error = failure_message.as_deref()
                .or_else(|| input_error.map(|error| error.message.as_str()));
            let multipart_failure = failed_archive.is_some_and(|archive| archive.depth == start_depth)
                && group.is_some_and(|group| group.members.len() > 1);
            let blocker = input_failure.filter(|input| watch_retryable(input, multipart_failure));
            let retryable = blocker.is_some();
            let candidate = if completed.cancelled || id == canonical_id {
                std::borrow::Cow::Borrowed(candidate)
            } else if let Some(&head) = canonical_inputs.get_or_init(|| {
                active.inputs.iter().map(|candidate| (watch_path_key(&candidate.path), candidate))
                    .collect::<HashMap<_, _>>()
            }).get(&canonical_id) {
                std::borrow::Cow::Borrowed(head)
            } else if error.is_none() {
                // Successful source cleanup may already have removed the
                // head. No blocker observation is needed for a success.
                let mut head = candidate.clone();
                head.path = canonical.clone();
                std::borrow::Cow::Owned(head)
            } else {
                let Ok(Some(head)) = watch_candidate_for_path(Path::new(&canonical), None) else {
                    continue;
                };
                std::borrow::Cow::Owned(head)
            };
            let stale = error.is_some()
                // A retained terminal child may outlive its successfully
                // consumed outer source. That is still this owner's failure.
                && !failed_archive.is_some_and(|archive| archive.depth > 1)
                && (discovery_failure.is_none() || retryable)
                && (recorded_file_is_absent(&canonical)
                    || (!retryable
                        && group.is_some_and(|group| {
                            group.members.len() > 1
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
                operations.finish_pending(&candidate.path, entry);
                continue;
            }
            if (retryable || discovery_failure.is_some_and(|failure| failure.kind == FailureKind::MissingVolume || failure.is_password_retry()))
                && self.hub.completed_families.covers(Path::new(&canonical), active.deep) {
                operations.finish_pending(&candidate.path, None);
                continue;
            }
            // An ordinary arrival can resolve to a generated head. That is a
            // new top-level attempt; any subsequent blocker stays at that head
            // with this attempt's depth/password context, not the old decision.
            let regrouped_recovery = (retryable && active.recovery.is_none()
                && self.catalog.generated_observation(&candidate.path).is_some()).then(|| Recovery {
                    max_depth: Some(active.max_depth),
                    scope: NativeDiscoveryScope::new(Path::new(&candidate.path).parent().unwrap_or(Path::new(""))
                        .to_string_lossy().into_owned(), Some(0), Vec::new()),
                    password_scope: active.password_scope.clone(),
                    parent: None,
                });
            let deferred = parents.remove(&canonical_id);
            let recovery = active.recovery.as_deref().or(regrouped_recovery.as_ref());
            let linked_recovery = blocker.and_then(|_| resumed.as_ref().or(deferred.as_ref())).map(|(id, _)| {
                let mut recovery = recovery.cloned().unwrap_or_else(|| Recovery {
                    max_depth: Some(active.max_depth),
                    scope: self.roots[&active.root].1.clone(),
                    password_scope: active.password_scope.clone(),
                    parent: None,
                });
                recovery.parent = Some(continuation::Parent { id: id.clone(), depth: start_depth });
                recovery
            });
            let recovery = linked_recovery.as_ref().or(recovery);
            let record = if completed.cancelled {
                // Only the cancelled generation is retired. A generation
                // queued while the batch was in flight is left in the WAL.
                self.journal
                    .state()
                    .entry(&candidate.path)
                    .filter(|entry| entry.status == "interrupted")
            } else if let Some(blocker) = blocker {
                error.map(|error| {
                    let record_error = if discovery_failure.is_some() {
                        blocker.failure()
                            .map(|failure| super::failure::message(failure, self.settings.cli.language))
                    } else {
                        None
                    };
                    let mut entry = make_blocker(
                        &candidate,
                        record_error.as_deref().unwrap_or(error),
                        blocker,
                        &active.passwords,
                        &self.user_password_signature,
                        group.map(Arc::as_ref),
                        recovery,
                        &active.password_scope,
                    );
                    Arc::make_mut(&mut entry).layout_checked_at = layout_checked_at;
                    if let Some(segments) = segments.take() {
                        Arc::make_mut(&mut entry).failure_payload.insert("segments".into(), segments);
                    }
                    Arc::make_mut(&mut entry).failure_payload.insert("input_checkpoints".into(),
                        serde_json::to_value(recovery_receipts().select([Path::new(&canonical)]))
                            .expect("serializable input checkpoints"));
                    if recovery.is_some() {
                        if let Some((root, _)) = self.roots.get(&active.root) {
                            Arc::make_mut(&mut entry)
                                .failure_payload
                                .insert("source_input_root".into(), json!(root.path));
                        }
                    }
                    if regrouped_recovery.is_some() { regrouped_recoveries.push(candidate.path.clone()); }
                    entry
                })
            } else {
                None
            };
            if let Some(record) = &record {
                if password_updated(record, &self.user_password_signature) {
                    retry.push((candidate.path.clone(), CandidateAdmission::PasswordRetry));
                } else if record.waits_for_layout() {
                    // The canonical head can differ from the physical input that
                    // started this request. Reconcile additions during either claim.
                    retry.push((record.path.clone(), CandidateAdmission::Retry));
                }
            }
            if resumed.is_none() && deferred.is_none()
                && record.as_ref().is_some_and(|entry| entry.failure_payload.contains_key("segments"))
            {
                // The entry update publishes the segment cards. No completion
                // event or combined output list is needed for a blocked group.
                if let Some(input_error) = input_error.filter(|_| discovery_failure.is_some()) {
                    reported_discovery.insert(input_error.path.as_path());
                }
                operations.finish_pending(&candidate.path, record);
                continue;
            }
            let event = if completed.cancelled {
                "pipeline_request_interrupted"
            } else if discovery_failure.is_some() && segment_blocker.is_none() {
                "failed_terminal"
            } else if let Some(record) = &record {
                record.status.as_str()
            } else if error.is_some() {
                "failed_terminal"
            } else if archives.is_some() {
                "done"
            } else if active.claimed.lock().unwrap().deduplicated.contains(&canonical_id) {
                "watch_deduplicated"
            } else {
                "no_tasks_found"
            };
            let counts = success_counts.get(&canonical_id).copied().unwrap_or_default();
            if published.insert(canonical_id) {
                let outputs = completion_output_dirs(archives.into_iter().flatten()
                    .filter_map(|item| item.output.as_deref()), &output_containers);
                let mut event = json!({"event":event,"path":canonical,"owner":batch,
                    "error":error,"error_kind":failure.map(|failure| failure.kind),
                    "output_dirs":outputs,"retire_group":true});
                if let Some(segments) = segments {
                    event["segments"] = segments;
                }
                if event["event"] == "done" {
                    counts.write(&mut event);
                }
                if let (Some(input_error), Some(failure)) = (input_error, discovery_failure) {
                    reported_discovery.insert(input_error.path.as_path());
                    event["failures"] = json!([super::failure::report::Report::from_failure(
                        failure, self.settings.cli.language,
                    )]);
                }
                let deferred_completion = resumed.is_some() || deferred.is_some();
                if let Some((_, continuation)) = resumed.as_mut() {
                    if record.is_none() || !retryable {
                        continuation.settle(&event, counts);
                    }
                } else if let Some((id, mut continuation)) = deferred {
                    if record.is_some() && retryable {
                        continuation.block(watch_path_key(&candidate.path));
                        event["event"] = json!("done");
                        event["error"] = Value::Null;
                        event["error_kind"] = Value::Null;
                        counts.write(&mut event);
                        if let Some(segments) = record.as_ref().and_then(|entry| entry.failure_payload.get("segments")) {
                            event["segments"] = segments.clone();
                        }
                    }
                    if let Some(group) = group.filter(|group| group.members.len() > 1 && event.get("segments").is_none()) {
                        event["group"] = json!(group.record());
                    }
                    continuation.begin(&active.root, event);
                    continuations.push((id, continuation));
                } else {
                    self.journal.log(event);
                }
                if deferred_completion && record.is_none() {
                    // Remove the running card. The parent publishes history when
                    // the last blocking input has settled.
                    self.journal.log(json!({"event":"no_tasks_found","path":canonical,
                        "owner":batch,"retire_group":true}));
                }
            }
            if resumed.is_some() {
                operations.settle_pending(&candidate.path, record);
            } else {
                operations.finish_pending(&candidate.path, record);
            }
        }
        if !completed.cancelled {
            for error in &outcome.errors {
                let Some(failure) = error.failure.as_deref() else { continue; };
                // Top-level discovery can fail on a peer that was never
                // admitted as a task. Its request still has a terminal failure.
                if reported_discovery.insert(error.path.as_path()) {
                    self.journal.log(json!({
                        "event":"failed_terminal","path":error.path,"owner":batch,
                        "error":super::failure::message(failure, self.settings.cli.language),
                        "error_kind":failure.kind,"retire_group":true,
                        "failures":[super::failure::report::Report::from_failure(failure, self.settings.cli.language)],
                    }));
                }
            }
        }
        continuations.extend(resumed);
        let mut ready = Vec::new();
        for (id, continuation) in continuations {
            continuation.defer(&self.journal, &id, &outcome.deferred_flatten, &mut operations);
            continuation.store(id.clone(), &mut operations);
            if continuation.ready() { ready.push((id, continuation)); }
        }
        self.journal.commit(true, |_| Ok(operations))?;
        for (id, continuation) in ready { self.finish_continuation(&id, continuation)?; }
        // A change observed during an active retry must not be overwritten
        // by that retry's late completion of the original generation.
        if active.recovery.is_some() || !regrouped_recoveries.is_empty() {
            self.invalidate_recovery(regrouped_recoveries.into_iter().chain(active.inputs.iter()
                .filter(|_| active.recovery.is_some()).map(|candidate| candidate.path.clone())))?;
        }
        self.retire_dependency_observers();
        if !published_outputs.is_empty() {
            self.hub.update(|signals| signals.published_outputs.extend(published_outputs));
        }
        for candidate in &active.inputs {
            if let Some(entry) = self.journal.state().entry(&candidate.path)
                .filter(|entry| entry.is_missing_volume()) {
                self.check_volume_waiter(&entry, None)?;
            }
        }
        for (path, admission) in retry {
            if admission == CandidateAdmission::Retry {
                if let Some(entry) = self.journal.state().entry(&path) { self.check_volume_waiter(&entry, None)?; }
                continue;
            }
            if let Some((root, recovery)) = self.journal.state().entry(&path)
                .and_then(|entry| self.blocker_route(&entry))
            {
                let tracker = quiet.remove(&watch_path_key(&path));
                self.observe_candidate_with_event(&root, path, admission, recovery, None, tracker,
                    Some(&CandidateEvent::Business(if admission == CandidateAdmission::PasswordRetry {
                        "password_retry"
                    } else { "volume_changed" })), None)?;
            }
        }
        let discovery_retry = outcome.errors.iter()
            .any(|error| matches!(error.kind, crate::pipeline::InputErrorKind::WatchDiscoveryIo(_)));
        self.persist_candidates(BTreeMap::new(), discovery_retry)?;
        self.arm_idle_cleanup();
        Ok((outcome, finish))
    }

    fn arm_idle_cleanup(&mut self) {
        // Admission/completion owns the transient tables. Keep a small
        // reusable allocation and discard batch high water as it drains.
        if self.pending.capacity() > 256 {
            crate::collections::trim_map(&mut self.pending);
        }
        if self.unpublished.capacity() > 256.max(self.unpublished.len().saturating_mul(4)) {
            self.unpublished.shrink_to(self.unpublished.len().saturating_mul(2));
        }
        if self.active.capacity() > 256 {
            crate::collections::trim_map(&mut self.active);
        }
        if self.active_paths.capacity() > 256 {
            crate::collections::trim_map(&mut self.active_paths);
        }
        if self.active.is_empty() && self.pending.is_empty() && !windows::foreground_active() {
            let idle = self.settings.watch.runtime_cache_cleanup_idle_seconds;
            // main's +infinity deadline never expires. Do not pass it to
            // Duration conversion, where an invalid duration becomes zero.
            self.cache_deadline = idle.is_finite().then(|| quiet::after(Instant::now(), idle));
        }
    }

    fn retry_pipeline_error(
        &mut self, batch: &str, root: &str, recovery: Option<&Arc<Recovery>>,
        path: &str, error: &str, kind: io::ErrorKind, quiet: &mut HashMap<String, quiet::Activity>,
        operations: &mut crate::watch_store::NativeWatchOperations,
    ) -> io::Result<()> {
        let id = watch_path_key(path);
        if self.pending.contains_key(&id) { return Ok(()); }
        if recorded_file_is_absent(path) {
            operations.finish_pending(path, None);
            return Ok(());
        }
        // Main re-admits an infrastructure/read exception, unlike a
        // terminal archive result or a password/volume blocker.
        // If a file vanished during discovery but its name is present again,
        // the current file still needs admission. Do not attach the old
        // missing-path failure to that newly observed generation.
        let event = if matches!(kind, io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) {
            "pipeline_discovery_retry"
        } else {
            "failed_terminal"
        };
        self.journal.log(json!({"event":event,"path":path,"owner":batch,"error":error}));
        self.observe_candidate_with_event(
            root, path.to_owned(), CandidateAdmission::ExplicitRetry, recovery.cloned(),
            None, quiet.remove(&id), Some(&CandidateEvent::Business("pipeline_completion_error")), None,
        )
    }

    fn release_request_display_claims(&self, batch: &str) {
        self.journal.log(json!({"event":"pipeline_sources_released","owner":batch}));
    }
}

// Reuse the output ownership captured by the observer. Descendants can finish
// after their source was retained or removed, so filesystem discovery cannot
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

struct RecoveryReceipts<'a> {
    checkpoints: &'a [crate::pipeline::InputCheckpoint],
    // Both carrier and source keys select direct receipts. Only physical
    // sources can attach a receipt to another receipt's retained output.
    paths: Vec<(String, usize, bool)>,
}

impl<'a> RecoveryReceipts<'a> {
    fn new(checkpoints: &'a [crate::pipeline::InputCheckpoint]) -> Self {
        let mut paths = Vec::with_capacity(checkpoints.len());
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            let carrier = key(checkpoint.carrier());
            let mut carrier_is_source = false;
            for source in checkpoint.source_paths() {
                let source = key(source);
                carrier_is_source |= source == carrier;
                paths.push((source, index, true));
            }
            if !carrier_is_source {
                paths.push((carrier, index, false));
            }
        }
        paths.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Self { checkpoints, paths }
    }

    fn path_range(&self, key: &str, prefix: bool) -> std::ops::Range<usize> {
        let start = self.paths.partition_point(|(path, _, _)| path.as_str() < key);
        let len = self.paths[start..].partition_point(|(path, _, _)| {
            if prefix { path.starts_with(key) } else { path == key }
        });
        start..start + len
    }

    fn select<'s>(&self, sources: impl IntoIterator<Item = &'s Path>) -> Vec<&'a crate::pipeline::InputCheckpoint> {
        let mut matches = Vec::new();
        for source in sources {
            matches.extend(self.paths[self.path_range(&key(source), false)].iter().map(|(_, index, _)| *index));
        }
        matches.sort_unstable();
        matches.dedup();

        // Hand off descendant receipts under the directly selected outputs,
        // even when their carrier has moved. Keep original receipt order.
        // Merge overlapping ranges so a stack of retained outputs does not
        // repeatedly visit every source below the outermost output.
        let mut ranges = Vec::new();
        for &index in &matches {
            let checkpoint = &self.checkpoints[index];
            if !checkpoint.has_output() { continue; }
            let mut root = key(checkpoint.output());
            ranges.push(self.path_range(&root, false));
            root.push('\\');
            ranges.push(self.path_range(&root, true));
        }
        ranges.sort_unstable_by_key(|range| range.start);
        let mut covered = 0;
        for range in ranges {
            if range.end <= covered { continue; }
            matches.extend(self.paths[range.start.max(covered)..range.end].iter()
                .filter_map(|(_, index, source)| source.then_some(*index)));
            covered = range.end;
        }
        matches.sort_unstable();
        matches.dedup();
        matches.into_iter().map(|index| &self.checkpoints[index]).collect()
    }
}

fn watch_retryable(input: &InputFailure<'_>, multipart: bool) -> bool {
    input.retryable() || (multipart && input.failure().is_some_and(|failure| failure.kind == FailureKind::Damaged))
}

fn nested_retry(archive: &ArchiveResult, failures: &HashMap<String, InputFailure<'_>>) -> bool {
    archive.depth > 1 && !archive.partial && failures
        .get(&crate::path_keys::path_key(&archive.path.to_string_lossy()))
        .is_some_and(|input| watch_retryable(input, archive.source_paths.len() > 1))
}

// Completion and persisted retry admission share the Watch boundary. Keep
// nested recovery scopes even when their source is an owned output subtree.
fn route_blocker(
    entry: &crate::watch_store::EntryRecord,
    roots: &BTreeMap<String, (Root, NativeDiscoveryScope)>,
) -> Option<(String, Option<Arc<Recovery>>)> {
    let payload = &entry.failure_payload;
    if let Some(root) = payload.get("source_input_root").and_then(Value::as_str) {
        let root = watch_path_key(root);
        roots.get(&root)?;
        if let Some(scope) = payload.get("discovery_scope").and_then(Value::as_object) {
            let password_scope = payload
                .get("password_scope_dir")
                .and_then(Value::as_str)
                .unwrap_or("");
            let recovery = Recovery::from_record(scope, password_scope)?;
            if recovery.scope.contains(&entry.path) {
                return Some((root, Some(Arc::new(recovery))));
            }
        }
    }
    containing_root(roots, &crate::path_keys::path_key(&entry.path)).map(|(id, _)| (id.clone(), None))
}

fn completion_owner(
    path: &Path,
    outputs: &BTreeMap<String, String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
) -> Option<String> {
    completion_owner_key(&key(path), outputs, groups)
}

fn completion_owner_key(
    path: &str, outputs: &BTreeMap<String, String>, groups: &HashMap<String, Arc<SourceGroup>>,
) -> Option<String> {
    if let Some(group) = groups.get(path) {
        return Some(key(&group.path));
    }
    let owner = watch_path_key(output_owner(outputs, path)?);
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
    let mut admissions = None;
    for error in errors {
        if error.kind == InputErrorKind::FilesystemScan {
            continue;
        }
        let path = key(&error.path);
        let owner = completion_owner_key(&path, outputs, groups).or_else(|| {
            if error.kind != InputErrorKind::EmbeddedDiscovery {
                return None;
            }
            // A residual peer can fail discovery for its catalog bucket
            // without having been explicitly admitted as a source.
            let (exact, by_stem) = admissions.get_or_insert_with(|| {
                let mut exact = HashSet::with_capacity(inputs.len());
                let mut by_stem = HashMap::new();
                for input in inputs {
                    exact.insert(watch_path_key(&input.path));
                    by_stem.entry(catalog_stem(&input.path)).or_insert(input.path.as_str());
                }
                (exact, by_stem)
            });
            if exact.contains(&path) {
                return None;
            }
            by_stem.get(&catalog_stem(&path)).map(|path| watch_path_key(path))
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

#[derive(Clone, Copy, Default)]
struct CompletionSuccessCounts {
    success_count: usize,
    partial_success_count: usize,
}
impl CompletionSuccessCounts {
    fn write(self, event: &mut Value) {
        event["success_count"] = json!(self.success_count);
        event["partial_success_count"] = json!(self.partial_success_count);
    }
}

fn completion_archives<'a>(
    outcome: &'a Outcome,
    outputs: &BTreeMap<String, String>,
    groups: &HashMap<String, Arc<SourceGroup>>,
    failures: &HashMap<String, InputFailure<'_>>,
) -> (HashMap<String, Vec<&'a ArchiveResult>>, HashMap<String, CompletionSuccessCounts>) {
    let mut by_path: HashMap<String, Vec<&ArchiveResult>> = HashMap::new();
    let mut counts: HashMap<String, CompletionSuccessCounts> = HashMap::new();
    let mut counted: HashMap<(String, usize), (String, bool)> = HashMap::new();
    for archive in &outcome.archives {
        // Main summarizes physical tasks, not carrier segments. Reuse the
        // carrier failure verdict and the display's accepted-partial status.
        let path = key(&archive.path);
        if !failures.get(&crate::path_keys::path_key(&archive.path.to_string_lossy()))
            .is_some_and(|failure| failure.failed)
        {
            let partial = crate::pipeline::TaskStatus::of(archive) == crate::pipeline::TaskStatus::Partial;
            match counted.entry((path.clone(), archive.depth)) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    // Flattening can move the output beyond the original source path.
                    let owner = completion_owner_key(&path, outputs, groups)
                        .or_else(|| archive.output.as_deref().and_then(|output| completion_owner(output, outputs, groups)))
                        .unwrap_or_else(|| path.clone());
                    let count = counts.entry(owner.clone()).or_default();
                    count.success_count += 1;
                    count.partial_success_count += usize::from(partial);
                    entry.insert((owner, partial));
                }
                std::collections::hash_map::Entry::Occupied(mut entry) if partial && !entry.get().1 => {
                    counts.get_mut(&entry.get().0).unwrap().partial_success_count += 1;
                    entry.get_mut().1 = true;
                }
                _ => {}
            }
        }
        for source in archive.source_paths.iter().filter(|source| *source != &archive.path) {
            let source = key(source);
            if source != path { by_path.entry(source).or_default().push(archive); }
        }
        if let Some(owner) = groups.get(&path).filter(|group| group.path != archive.path)
            .map(|group| key(&group.path)).filter(|owner| *owner != path)
        {
            let related = by_path.entry(owner).or_default();
            if related.last().is_none_or(|last| !std::ptr::eq(*last, archive)) {
                related.push(archive);
            }
        }
        if archive.depth > 1 && !archive.partial && archive.failure.is_some() && !nested_retry(archive, failures)
        {
            // Nested retry blockers get their own durable entry below. All
            // other nested failures belong to the original top-level card.
            if let Some(owner) = output_owner(outputs, &path) {
                let owner = watch_path_key(owner);
                let owner = groups.get(&owner).map(|group| key(&group.path)).unwrap_or(owner);
                if owner != path {
                    let related = by_path.entry(owner).or_default();
                    if related.last().is_none_or(|last| !std::ptr::eq(*last, archive)) {
                        related.push(archive);
                    }
                }
            }
        }
        by_path.entry(path).or_default().push(archive);
    }
    (by_path, counts)
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

fn completion_segments<'a>(
    archives: &[&'a ArchiveResult], depth: usize, failures: &HashMap<String, InputFailure<'_>>,
    language: crate::core::i18n::Language,
) -> Option<(Value, InputFailure<'a>)> {
    let inputs = || archives.iter().copied().filter(|archive| archive.depth == depth);
    if inputs().nth(1).is_none() { return None; }
    // Use actual input layouts after selection and recovery. Recursive files
    // keep their own Watch cards when retryable and otherwise affect their parent.
    let mut nested = archives.iter().copied().filter(|archive|
        archive.depth > depth && !archive.partial && archive.failure.is_some()
            && !nested_retry(archive, failures)).peekable();
    let mut segment_outputs = HashMap::new();
    if nested.peek().is_some() {
        segment_outputs.extend(inputs().filter_map(|archive| archive.output.as_ref().map(|path| (key(path), None))));
        for child in nested {
            let path = key(&child.path);
            for ancestor in crate::path_keys::path_ancestors(&path).skip(1) {
                if let Some(failure) = segment_outputs.get_mut(ancestor) {
                    if failure.is_none() { *failure = child.failure.as_ref(); }
                    break;
                }
            }
        }
    }
    let mut blockers = InputFailure::default();
    let rows = inputs().map(|archive| {
        let failure = archive.failure.as_ref().filter(|_| !archive.partial);
        let nested = if segment_outputs.is_empty() {
            None
        } else {
            archive.output.as_ref().and_then(|path| segment_outputs.get(&key(path)).copied().flatten())
        };
        let event = match failure {
            Some(failure) if failure.kind == FailureKind::MissingVolume => {
                blockers.missing.get_or_insert(failure);
                "suspended_missing_volume"
            }
            Some(failure) if failure.is_password_retry() => {
                blockers.password.get_or_insert(failure);
                "failed_password"
            }
            Some(_) => "failed_terminal",
            None if nested.is_some() => "failed_terminal",
            None => "done",
        };
        let multipart = archive.source_paths.len() > 1 || archive.volume_completeness.is_some()
            || archive.volume_attempts.is_some();
        let mut row = json!(source_group_record(&archive.path, &archive.source_paths, multipart));
        row["event"] = json!(event);
        if let Some(output) = &archive.output {
            row["output_dirs"] = json!([output]);
        }
        if event == "failed_terminal" {
            let failure = failure.or(nested).expect("terminal segment failure");
            row["error"] = json!(super::failure::message(failure, language));
            row["error_kind"] = json!(failure.kind);
        }
        row
    }).collect();
    blockers.failed = blockers.missing.is_some() || blockers.password.is_some();
    Some((Value::Array(rows), blockers))
}

// Main fixes the request password directory before discovery can replace a
// tail-volume candidate with the family's head. A saved retry keeps that scope.
fn candidate_password_scope(
    state: &crate::watch_store::NativeWatchState, path: &str, recovery: Option<&Recovery>,
) -> PathBuf {
    if let Some(recovery) = recovery { return recovery.password_dir(Path::new(path)).to_owned(); }
    let entry = state.entry(path);
    let scope = if let Some(entry) = entry.as_ref().filter(|entry|
        entry.status == "failed_password" || entry.waits_for_volume()) {
        entry.failure_payload.get("password_scope_dir").and_then(Value::as_str)
            .filter(|scope| !scope.is_empty()).map(PathBuf::from)
    } else {
        state.pending(path).filter(|pending| !pending.password_scope_dir.is_empty())
            .map(|pending| PathBuf::from(&pending.password_scope_dir))
    };
    scope.unwrap_or_else(|| Path::new(path).parent().unwrap_or(Path::new("")).to_owned())
}

fn make_blocker(
    candidate: &WatchCandidateRow,
    error: &str,
    failure: &InputFailure<'_>,
    passwords: &crate::core::passwords::PasswordSnapshot,
    user_signature: &str,
    group: Option<&SourceGroup>,
    recovery: Option<&Recovery>,
    password_scope: &Path,
) -> Arc<crate::watch_store::EntryRecord> {
    debug_assert!(watch_retryable(failure, group.is_some_and(|g| g.members.len() > 1)));
    let kind = failure.failure().map(|failure| failure.kind);
    let password = failure.password.is_some();
    let missing = failure.missing.is_some();
    let status = if missing { "suspended_missing_volume" } else if password { "failed_password" } else { "failed_terminal" };
    let mut blockers = Vec::new();
    if missing { blockers.push("missing_volume"); }
    if password { blockers.push("password"); }
    if !missing && group.is_some_and(|group| group.members.len() > 1) { blockers.push("volume_candidate"); }
    let mut payload = serde_json::Map::new();
    payload.insert("blockers".into(), json!(blockers));
    if let Some(group) = group {
        payload.insert("source_group".into(), json!(group.record()));
    }
    if let Some(recovery) = recovery {
        payload.insert("discovery_scope".into(), Value::Object(recovery.record()));
    }
    payload.insert("password_scope_dir".into(), json!(password_scope));
    if password {
        payload.insert("password_signature".into(), json!(password_source_signature(user_signature, &passwords.scope_signature(password_scope))));
    }
    let mut entry = observed_entry(candidate, status);
    entry.last_error = error.to_owned();
    if let Ok(Value::String(kind)) = serde_json::to_value(kind) {
        entry.failure_kind = kind;
    }
    entry.failure_payload = payload;
    Arc::new(entry)
}

fn observed_entry(
    candidate: &WatchCandidateRow,
    status: &str,
) -> crate::watch_store::EntryRecord {
    crate::watch_store::EntryRecord {
        path: candidate.path.clone(),
        size: candidate.size.min(i64::MAX as u64) as i64,
        mtime: candidate.mtime,
        file_id: candidate.observation.file_id.clone(),
        change_usn: candidate.observation.change_usn,
        status: status.to_owned(),
        last_error: String::new(),
        failure_kind: String::new(),
        failure_payload: serde_json::Map::new(),
        layout_checked_at: 0,
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
        let mut owners = HashMap::<_, HashSet<_>>::new();
        for (path, owner) in &paths {
            owners.entry(watch_path_key(owner)).or_default().insert(path.clone());
        }
        Self { paths, owners }
    }
}

impl ObservedOutputs {
    fn insert(&mut self, path: String, owner: String) {
        if let Some(previous) = self.paths.insert(path.clone(), owner.clone()) {
            self.remove_owner_path(&path, &previous);
        }
        self.owners.entry(watch_path_key(&owner)).or_default().insert(path);
    }

    fn remove(&mut self, path: &str) {
        if let Some(owner) = self.paths.remove(path) {
            self.remove_owner_path(path, &owner);
        }
    }

    fn remove_owner_path(&mut self, path: &str, owner: &str) {
        let owner = watch_path_key(owner);
        if let Some(paths) = self.owners.get_mut(&owner) {
            paths.remove(path);
            if paths.is_empty() { self.owners.remove(&owner); }
        }
    }

    fn replace_tree(&mut self, root: &str, output: String, owner: String) {
        let prefix = format!("{}\\", root.trim_end_matches('\\'));
        let children: Vec<_> = self.paths.range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix)).map(|(path, _)| path.clone()).collect();
        self.remove(root);
        for path in children { self.remove(&path); }
        self.insert(output, owner);
    }

    fn take_owners<'a>(&mut self, owners: impl Iterator<Item = &'a str>) -> BTreeMap<String, String> {
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
    dedup_enabled: bool,
    dedup: Arc<Mutex<dedup::Index>>,
    dedup_scope: NativeDiscoveryScope,
    catalog: Arc<NativeWatchCatalog>,
    journal: Arc<journal::Journal>,
    owners: HashMap<String, String>,
    outputs: Mutex<ObservedOutputs>,
    batch: Arc<str>,
    toast: Option<super::toast::Activity>,
    hub: Arc<Hub>,
    groups: Arc<Mutex<SourceGroups>>,
    claimed: Arc<Mutex<ClaimedSources>>,
}

impl WatchObserver {
    fn owner<'a>(&'a self, archive: &'a ArchiveResult) -> Option<String> {
        self.owner_for_sources(&archive.path, &archive.source_paths)
    }

    fn owner_for_sources(&self, path: &Path, sources: &[PathBuf]) -> Option<String> {
        std::iter::once(path)
            .chain(sources.iter().map(PathBuf::as_path))
            .find_map(|path| self.owners.get(&key(path)).cloned())
            .or_else(|| self.owner_for_path(path))
    }

    fn owner_for_path(&self, path: &Path) -> Option<String> {
        output_owner(&self.outputs.lock().unwrap().paths, &key(path)).map(str::to_owned)
    }

    fn publish_output(&self, archive: &ArchiveResult, path: &Path, exclusive: bool) -> io::Result<()> {
        let Some(owner) = self.owner(archive).or_else(|| self.owner_for_path(path)) else {
            return Err(io::Error::other("Watch output has no durable input owner"));
        };
        let output = path.to_string_lossy().into_owned();
        let task = archive.path.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            state
                .output_operation(&owner, task, output, None, exclusive)?
                .ok_or_else(|| io::Error::other("Watch input owner was retired before output"))
        })?;
        self.outputs.lock().unwrap().insert(key(path), owner);
        Ok(())
    }
}

impl Observer for WatchObserver {
    const PUBLISHES_ROOTS: bool = true;

    fn input_admission_enabled(&self) -> bool { self.dedup_enabled }

    fn admit_inputs(&self, owner: &Path, inputs: &[&crate::io::archive_state::ArchiveInput], members: &[String], depth: usize) -> io::Result<bool> {
        if depth != 1 || inputs.iter().flat_map(|input| input.physical_paths()).any(|path| !self.dedup_scope.contains(path)) {
            return Ok(true);
        }
        // Rebuilding a disposable index must not revoke already-durable
        // password/output recovery. A merely incomplete new family has no
        // retained work and may still deduplicate once its layout becomes fixed.
        let owner_path = owner.to_string_lossy();
        if self.journal.state().entry(&owner_path).is_some_and(|entry| entry.status == "failed_password"
            || (entry.status == "failed_terminal" && entry.waits_for_volume()))
            || self.journal.state().pending(&owner_path).is_some_and(|pending| pending.has_output_work()) {
            return Ok(true);
        }
        let duplicate = match dedup::consider(&self.dedup, &owner_path, self.dedup_scope.key(), inputs, None) {
            Ok(duplicate) => duplicate,
            Err(error) => {
                self.journal.log(json!({"event":"watch_dedup_unavailable","path":owner,"error":error.to_string()}));
                false
            }
        };
        if duplicate {
            // Claim the physical proposal exactly as an ordinary root does so
            // root_finished retires every pending member. No successful archive
            // result is manufactured and no extraction/cleanup is entered.
            self.claim_sources(owner, members, depth, inputs.iter().copied())?;
            self.claimed.lock().unwrap().deduplicated.insert(key(owner));
        }
        Ok(!duplicate)
    }


    fn coalesced(&self) {
        self.claimed.lock().unwrap().coalesced = true;
    }

    fn roots_planned<'a>(&self, roots: impl Iterator<Item = (&'a str, &'a [String])>) {
        let mut groups = self.groups.lock().unwrap();
        for (path, members) in roots {
            groups.plan(watch_path_key(path), members.iter().map(|path| watch_path_key(path)).collect());
        }
        let groups = &mut *groups;
        groups.shared_owners.extend(groups.members.iter().filter_map(|(path, &count)| {
            (count > 1 && self.owners.contains_key(path)).then(|| path.clone())
        }));
    }

    async fn root_finished(
        &self, id: crate::pipeline::TaskId, path: &Path, outcome: Outcome, request: u64,
    ) -> io::Result<Outcome> {
        let root = key(path);
        // Move only this logical owner's state. A shared member stays claimed
        // until its final consumer settles; another admitted root never moves.
        let (groups, outputs) = {
        let mut claimed = self.claimed.lock().unwrap();
        let mut groups = self.groups.lock().unwrap();
        // A tail can own the WAL and outputs of several independent heads.
        // Keep their aggregate until request finish, even after a peer settles.
        if !self.owners.contains_key(&root) && !groups.can_finish_alias(&root, &self.owners) {
            return Ok(outcome);
        }
        let aliases = groups.take(&root);
        drop(groups);
        let members = aliases.keys().map(String::as_str)
            .chain((!aliases.contains_key(&root)).then_some(root.as_str()));
        claimed.finished.extend(members.clone().map(str::to_owned));
        drop(claimed);
        let mut shared_outputs = self.outputs.lock().unwrap();
        let outputs = shared_outputs.take_owners(members);
        drop(shared_outputs);
        (aliases, outputs)
        };
        let reply = Arc::new(super::cli::reporting::Reply::default());
        self.hub.root_completed(RootCompleted {
            request,
            reply: Arc::clone(&reply), batch: self.batch.to_string(), id, root_key: root, groups,
            completed: Completed { cancelled: false, result: Ok(outcome), outputs },
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

    fn generated_source(&self, path: &str) -> Option<GeneratedSource> {
        let before = self.catalog.generated_observation(path)?;
        // Capture before probing the accepted baseline. A later replacement
        // cannot inherit this receipt; pipeline admission validates its generation.
        let receipt = GeneratedSource::capture(Path::new(path)).ok()?;
        let current = watch_candidate_for_path(Path::new(path), Some(before.change_usn)).ok()??;
        (!crate::postprocess::watch_source_changed(before.size, before.mtime, &before.file_id(), before.change_usn, &current))
            .then_some(receipt)
    }

    fn completed_sources(&self, generations: &SourceGenerations) -> io::Result<Option<PathBuf>> {
        Ok(self.hub.completed_families.output(generations, self.deep))
    }

    fn sources_processed(
        &self,
        generations: SourceGenerations,
        output: Option<&Path>,
    ) -> io::Result<()> {
        if let Some(output) = output {
            self.hub.completed_families.remember(generations, self.deep, output);
        }
        Ok(())
    }

    fn claim_sources<'a>(&self, path: &Path, members: &[String], depth: usize,
        inputs: impl ExactSizeIterator<Item = &'a crate::io::archive_state::ArchiveInput>,
    ) -> io::Result<()> {
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
        let mut record = json!(group.record());
        if inputs.len() > 1 {
            record["segments"] = Value::Array(inputs.map(|input| {
                let path = Path::new(&input.entry_path);
                let members: Vec<_> = input.physical_paths().collect();
                let layout = json!(source_group_record(path, &members, input.mode.structured() || members.len() > 1));
                layout
            }).collect());
        }
        self.journal.log(json!({"event":"pipeline_sources_claimed","path":path,"owner":self.batch,
            "processing":true,"groups":[record]}));
        Ok(())
    }

    fn notify(&self, event: Event) {
        if let Some(toast) = &self.toast {
            toast.event(event);
        }
    }

    fn register_output(&self, archive: &ArchiveResult, path: &Path) -> io::Result<()> {
        self.publish_output(archive, path, true)
    }

    fn reuse_output(&self, archive: &ArchiveResult, path: &Path) -> io::Result<()> {
        // Decryption can replace a provisional tail representative with the
        // actual carrier. Its retained output already routes to the WAL owner.
        self.publish_output(archive, path, false)
    }

    fn before_flatten(&self, root: &Path, work: &Path, leaf: &Path, destination: &Path) -> io::Result<()> {
        let owner = self.owner_for_path(root).unwrap_or_default();
        prepare_flatten(&self.journal, &owner, root, work, leaf, destination, None)?;
        if !owner.is_empty() {
            self.outputs.lock().unwrap().insert(key(work), owner);
        }
        Ok(())
    }

    fn after_flatten(&self, _id: crate::pipeline::TaskId, root: &Path, old: &Path, output: &Path) -> io::Result<()> {
        if old != root {
            finish_flatten(&self.journal, &root.to_string_lossy())?;
            if root != output && key(root) != key(output) {
                let root_key = key(root);
                let mut outputs = self.outputs.lock().unwrap();
                if let Some(owner) = output_owner(&outputs.paths, &root_key).map(str::to_owned) {
                    outputs.replace_tree(&root_key, key(output), owner);
                }
            }
        }
        Ok(())
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
                    Some(archive.failure.is_none() || archive.partial), false)?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty))
        })
    }

    fn discard_output(&self, archive: &Path, sources: &[PathBuf], output: &Path) -> io::Result<()> {
        let Some(owner) = self.owner_for_sources(archive, sources) else {
            return Ok(());
        };
        let task = archive.to_string_lossy().into_owned();
        let output = output.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            Ok(state.output_operation(&owner, task, output, Some(false), false)?
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
    destination: &Path,
    continuation: Option<&str>,
) -> io::Result<()> {
    journal.commit(true, |state| {
        use crate::watch_store::NativeWatchOperations;
        let old = output_identity(&root.to_string_lossy())?;
        let new = output_identity(&leaf.to_string_lossy())?;
        let mut paths = crate::path_keys::output_path_aliases(root)?;
        let work_paths = crate::path_keys::output_path_aliases(work)?;
        let mut record = json!({
            "owner":owner,"root":root,"work":work,"leaf":leaf,"old_identity":old,
            "new_identity":new,"work_paths":work_paths,"destination":destination,
        });
        if let Some(id) = continuation { record["continuation"] = json!(id); }
        if root != destination && key(root) != key(destination) {
            let destination_paths = crate::path_keys::output_path_aliases(destination)?;
            record["root_paths"] = json!(paths);
            record["destination_paths"] = json!(destination_paths);
            paths.extend(destination_paths);
        }
        let mut operations = NativeWatchOperations::empty();
        operations.set_runtime(format!("flatten|{}", key(root)), Some(record));
        if !owner.is_empty() {
            if let Some(checkpoint) = state.protect_output_operation(
                owner, vec![root.to_string_lossy().into_owned()],
            ) {
                operations.extend(checkpoint);
            }
        }
        paths.extend(work_paths);
        state.register_output_paths(&paths, &[&old, &new]);
        Ok(operations)
    })?;
    if continuation.is_some() { journal.wait_before_mutation()?; }
    Ok(())
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
    use crate::watch_store::NativeWatchOperations;
    let record_key = format!("flatten|{}", watch_path_key(root));
    let Some(record) = state.runtime_record(&record_key) else {
        return Ok(NativeWatchOperations::empty());
    };
    let (Some(work), Some(leaf), Some(destination)) =
        (record["work"].as_str(), record["leaf"].as_str(), record["destination"].as_str())
    else {
        return Ok(NativeWatchOperations::empty());
    };
    let work_paths = flatten_work_paths(&record)?;
    let renamed = record.get("destination_paths").is_some();
    let old = record["old_identity"].as_str().unwrap_or_default();
    let expected = record["new_identity"].as_str();
    let mut work_exists = false;
    for alias in work_paths.clone() {
        work_exists |= Path::new(alias).try_exists()?;
    }
    let target = output_identity(destination);
    let published = target.as_ref().is_ok_and(|identity| Some(identity.as_str()) == expected);
    let current = if !published && renamed && !work_exists { output_identity(root)? } else { target? };
    if !published && (work_exists || old != current) {
        return Ok(NativeWatchOperations::empty());
    }
    let already_rebased = record["outputs_rebased"].as_bool() == Some(true);
    if work_exists && already_rebased {
        return Ok(NativeWatchOperations::empty());
    }
    let live = if published { destination } else { root };
    let mut paths = crate::path_keys::output_path_aliases(Path::new(live))?;
    let mut operations = NativeWatchOperations::empty();
    operations.set_runtime(record_key, work_exists.then(|| {
        let mut next = (*record).clone();
        next["outputs_rebased"] = Value::Bool(true);
        next
    }));
    let owner = record["owner"]
        .as_str()
        .filter(|owner| published && !already_rebased && !owner.is_empty());
    if let Some(owner) = owner {
        let relative = Path::new(leaf).strip_prefix(root).map_err(io::Error::other)?;
        let work_leaf = Path::new(work).join(relative).to_string_lossy().into_owned();
        operations.relocate_output(owner, root.to_owned(), leaf.to_owned(), destination.to_owned(), current.clone());
        operations.relocate_output(owner, work.to_owned(), work_leaf, destination.to_owned(), current.clone());
    }
    if published && !already_rebased {
        if let Some(id) = record["continuation"].as_str() {
            continuation::relocate_output(state, id, Path::new(root), Path::new(destination), &mut operations)?;
        }
    }
    if work_exists { paths.extend(work_paths.clone().map(str::to_owned)); }
    state.register_output_paths(&paths, &[&current, old]);
    let retired_aliases = if published { &record["root_paths"] } else { &record["destination_paths"] };
    if let Some(aliases) = retired_aliases.as_array() {
        state.remove_active_output(aliases.iter().filter_map(Value::as_str), old);
    }
    if !work_exists {
        state.remove_active_output(work_paths, old);
    }
    Ok(operations)
}

fn flatten_work_paths(record: &Value) -> io::Result<impl Iterator<Item = &str> + Clone> {
    record["work_paths"].as_array()
        .filter(|paths| !paths.is_empty() && paths.iter().all(Value::is_string))
        .map(|paths| paths.iter().filter_map(Value::as_str))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid flatten work paths"))
}

fn restore_checkpoints(
    state: &crate::watch_store::NativeWatchState,
    owner: &str,
    outputs: &mut BTreeMap<String, String>,
) -> io::Result<Vec<crate::pipeline::InputCheckpoint>> {
    let entry = state.entry(owner);
    let checkpoints = input_checkpoints(entry.as_deref()).collect::<io::Result<Vec<_>>>()?;
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
    entry: Option<&crate::watch_store::EntryRecord>,
) -> impl Iterator<Item = io::Result<crate::pipeline::InputCheckpoint>> + '_ {
    entry.and_then(|entry| entry.failure_payload.get("input_checkpoints"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|record| crate::pipeline::InputCheckpoint::deserialize(record).map_err(io::Error::other))
}

fn recover_flattens(journal: &journal::Journal, eligible: impl Fn(&str) -> bool) -> io::Result<Vec<String>> {
    let mut settled = Vec::new();
    for id in journal.state().runtime_keys("flatten|") {
        let Some(record) = journal.state().runtime_record(&id) else {
            continue;
        };
        if !eligible(record["owner"].as_str().unwrap_or_default()) {
            continue;
        }
        let (Some(root), Some(work), Some(leaf), Some(destination), Some(old), Some(new)) = (
            record["root"].as_str(),
            record["work"].as_str(),
            record["leaf"].as_str(),
            record["destination"].as_str(),
            record["old_identity"].as_str(),
            record["new_identity"].as_str(),
        ) else {
            continue;
        };
        if let Err(error) = flatten_work_paths(&record) {
            journal.log(json!({"event":"flatten_recovery_failed","path":root,"error":error.to_string()}));
            continue;
        }
        let Ok(work_id) = identity_if_present(work) else {
            continue;
        };
        if work_id.as_deref().is_some_and(|id| id != old) {
            continue;
        }
        if work_id.is_none() && identity_if_present(root).is_ok_and(|id| id.as_deref() == Some(old)) {
            recover_finish_flatten(journal, root)?;
            if journal.state().runtime_record(&id).is_none() { settled.push(root.to_owned()); }
            continue;
        }
        let Ok(target_id) = identity_if_present(destination) else { continue; };
        let published = target_id.as_deref() == Some(new);
        if !published && (target_id.is_some() || work_id.is_none())
        {
            continue;
        }
        if !published {
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
            crate::postprocess::FlattenLeaf::Resume { leaf: Path::new(leaf), published },
            Path::new(destination),
            || Ok(()),
        );
        if identity_if_present(destination).is_ok_and(|identity| identity.as_deref() == Some(new)) {
            recover_finish_flatten(journal, root)?;
            if journal.state().runtime_record(&id).is_none() { settled.push(destination.to_owned()); }
        }
    }
    Ok(settled)
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
        Ok((paths, errors)) => {
            for (operation, path, error) in errors {
                journal.log(json!({"event":"crash_resume_scan_failed", "owner_path":owner,
                    "root":root, "operation":operation, "path":path, "error":error}));
            }
            Ok(paths)
        }
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
#[path = "../../tests/unit/runtime/watch/tests.rs"]
mod tests;
