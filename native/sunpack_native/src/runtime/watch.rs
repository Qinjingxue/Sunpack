use super::{cli, windows};
use crate::core::config::{self, Config, Snapshot};
use crate::core::passwords::BuiltinStore;
use crate::core::resources::{self, FileMutex};
use crate::filesystem;
use crate::io::config_changes::NativeConfigChanges;
use crate::io::reader::PhysicalFileGeneration;
use crate::pipeline::{
    ArchiveResult, Cancellation, Engine, Event, FailureKind, Mode, Observer, Origin, Outcome,
    OutputCleanupError, PromotedSource, Request,
};
use crate::postprocess::{watch_candidate_for_path, WatchCandidateRow};
use crate::scan::directory::{NativeDirectoryScanOptions, NativeWatchCatalog};
use crate::scan::scope::NativeDiscoveryScope;
use crate::watch_store::{is_path_under, watch_path_key};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Instant;

mod journal;
mod quiet;

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
    fn scope(&self, entries: &[Self], state_dir: &Path) -> NativeDiscoveryScope {
        let mut exclude = vec![state_dir.to_string_lossy().into_owned()];
        let own = key(&self.path);
        exclude.extend(entries.iter().filter_map(|entry| {
            let nested = key(&entry.path);
            (nested != own && is_path_under(&nested, &own))
                .then(|| entry.path.to_string_lossy().into_owned())
        }));
        exclude.extend(entries.iter().filter_map(|entry| {
            let output = entry.output.as_ref()?;
            let target = key(output);
            (target != own && is_path_under(&target, &own))
                .then(|| output.to_string_lossy().into_owned())
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

fn read_roots(path: &Path) -> io::Result<Vec<Root>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut roots: Vec<Root> = Vec::new();
    let mut positions = HashMap::new();
    let cwd = path.parent().unwrap();
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
        let input = cli::resolve(cwd, input)?;
        let output = fields
            .next()
            .filter(|output| !output.is_empty())
            .map(|output| resolve_output(&input, output))
            .transpose()?;
        let mut boolean = || match fields.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "" | "false" => Ok(false),
            "true" => Ok(true),
            value => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: invalid Boolean {value}", path.display(), index + 1),
            )),
        };
        let deep = boolean()?;
        let scanned = boolean()?;
        let recursive = boolean()?;
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
    Ok(roots_path(cwd)?.parent().unwrap().join(WATCH_METADATA))
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

pub(super) struct Watch {
    lifecycle: Mutex<()>,
    running: Mutex<Option<Running>>,
    wake_host: Arc<dyn Fn() + Send + Sync>,
    external: Arc<Mutex<Option<ExternalOutputs>>>,
    generation: AtomicU64,
    last_error: Arc<Mutex<Option<String>>>,
}

struct ExternalOutputs {
    journal: Weak<journal::Journal>,
    scopes: Vec<NativeDiscoveryScope>,
}

impl Watch {
    pub(super) fn new(wake_host: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            lifecycle: Mutex::new(()),
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

    pub(super) fn foreground_finished(&self) {
        if let Some(run) = self.running.lock().unwrap().as_ref() {
            run.hub.update(|signals| signals.foreground_finished = true);
        }
    }

    pub(super) fn status(&self, cwd: &Path) -> io::Result<Value> {
        let slot = self.running.lock().unwrap();
        let run = slot.as_ref().filter(|run| !run.thread.is_finished());
        Ok(json!({
            "running": run.is_some(), "generation": self.generation.load(Ordering::Relaxed),
            "pending": run.map_or(0, |run| run.hub.pending_count.load(Ordering::Relaxed)),
            "last_error": self.last_error.lock().unwrap().as_deref(),
            "state_dir": state_dir(cwd)?,
        }))
    }

    pub(super) fn start(&self, cwd: &Path, engine: Arc<Engine>, tray: bool) -> io::Result<Value> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        let mut slot = self.running.lock().unwrap();
        if slot
            .as_ref()
            .is_some_and(|running| !running.thread.is_finished())
        {
            return Ok(
                json!({"running":true,"started":false,"generation":self.generation.load(Ordering::Relaxed)}),
            );
        }
        if let Some(previous) = slot.take() {
            let _ = previous.thread.join();
        }
        let cwd = cwd.to_path_buf();
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let wake = Arc::clone(&self.wake_host);
        let external = Arc::clone(&self.external);
        let last_error = Arc::clone(&self.last_error);
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let (ready, wait) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("sunpack-watch".into())
            .spawn(move || {
                let result = match Scheduler::open(cwd, engine, worker_hub, true, tray, external) {
                    Ok(mut scheduler) => {
                        let _ = ready.send(Ok(()));
                        scheduler.run(false).map(|_| ())
                    }
                    Err(error) => {
                        *last_error.lock().unwrap() = Some(error.to_string());
                        let _ = ready.send(Err(error));
                        Ok(())
                    }
                };
                if let Err(error) = &result {
                    *last_error.lock().unwrap() = Some(error.to_string());
                }
                wake();
                result
            })?;
        let startup = wait.recv().map_err(io::Error::other)?;
        if let Err(error) = startup {
            let _ = thread.join();
            return Err(error);
        }
        *slot = Some(Running { hub, thread });
        (self.wake_host)();
        Ok(json!({"running":true,"started":true,"generation":generation}))
    }

    pub(super) fn stop(&self) -> io::Result<Value> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        let mut slot = self.running.lock().unwrap();
        let generation = self.generation.load(Ordering::Relaxed);
        let Some(running) = slot.take() else {
            return Ok(json!({"running":false,"stopped":false,"generation":generation}));
        };
        drop(slot);
        if running.thread.is_finished() {
            let _ = running.thread.join();
            return Ok(json!({"running":false,"stopped":false,"generation":generation}));
        }
        running.hub.stop();
        running
            .thread
            .join()
            .map_err(|_| io::Error::other("Watch thread failed"))??;
        (self.wake_host)();
        Ok(json!({"running":false,"stopped":true,"generation":generation}))
    }

    pub(super) fn run_once(&self, cwd: &Path, engine: Arc<Engine>) -> io::Result<i32> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        let slot = self.running.lock().unwrap();
        if let Some(run) = slot.as_ref().filter(|run| !run.thread.is_finished()) {
            let hub = Arc::clone(&run.hub);
            drop(slot);
            drop(_lifecycle);
            let (send, receive) = mpsc::sync_channel(1);
            hub.update(|signals| signals.once.push(send));
            receive.recv().map_err(io::Error::other)??;
            return Ok(0);
        }
        drop(slot);
        let mut scheduler = Scheduler::open(
            cwd.to_owned(),
            engine,
            Arc::new(Hub::new()),
            false,
            false,
            Arc::clone(&self.external),
        )?;
        scheduler.run(true)
    }

    pub(super) fn reload(&self) -> io::Result<Value> {
        let hub = self
            .running
            .lock()
            .unwrap()
            .as_ref()
            .filter(|run| !run.thread.is_finished())
            .map(|run| Arc::clone(&run.hub));
        let Some(hub) = hub else {
            return Ok(
                json!({"running":false,"reloaded":false,"generation":self.generation.load(Ordering::Relaxed)}),
            );
        };
        let (ready, wait) = mpsc::sync_channel(1);
        hub.queue_reload(Some(ready));
        wait.recv().map_err(io::Error::other)??;
        Ok(
            json!({"running":true,"reloaded":true,"generation":self.generation.load(Ordering::Relaxed)}),
        )
    }

    pub(super) fn roots(&self, cwd: &Path) -> io::Result<(PathBuf, Vec<PathBuf>)> {
        let path = roots_path(cwd)?;
        let roots = read_roots(&path)?
            .into_iter()
            .map(|root| root.path)
            .collect();
        Ok((path, roots))
    }

    pub(super) fn add(
        &self,
        cwd: &Path,
        paths: &[PathBuf],
        output: Option<&str>,
        deep: bool,
        recursive: bool,
    ) -> io::Result<Value> {
        let path = roots_path(cwd)?;
        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut rejected = Vec::new();
        let running = self.is_running();
        {
            let _lock = FileMutex::lock(&path, ROOTS_LOCK)?;
            let mut roots = read_roots(&path)?;
            for root in paths {
                let id = key(root);
                if let Some(existing) = roots.iter_mut().find(|entry| key(&entry.path) == id) {
                    let before = existing.clone();
                    existing.scanned &= !recursive || existing.recursive;
                    existing.recursive |= recursive;
                    existing.deep |= deep;
                    if *existing != before {
                        updated.push(root.clone());
                    }
                    continue;
                }
                if running
                    && filesystem::watch_filesystem_type(&root.to_string_lossy())
                        .is_ok_and(|name| !name.eq_ignore_ascii_case("NTFS"))
                {
                    rejected.push(root.clone());
                    continue;
                }
                roots.push(Root {
                    path: root.clone(),
                    output: output.map(|value| resolve_output(root, value)).transpose()?,
                    deep,
                    recursive,
                    scanned: false,
                });
                added.push(root.clone());
            }
            validate_outputs(&roots)?;
            if !added.is_empty() || !updated.is_empty() {
                write_roots(&path, &roots)?;
            }
        }
        let apply = self.root_change_status(running, !added.is_empty() || !updated.is_empty())?;
        let apply = apply.map(|(applied, generation)| {
            json!({
                "roots_path":path,"added":added,"updated":updated,"rejected":rejected,
                "applied":applied,"running":true,"generation":generation,
            })
        });
        Ok(json!({
            "roots_path":path,"added":added,"updated":updated,"rejected":rejected,
            "apply":apply,"start":null,
        }))
    }

    pub(super) fn remove(&self, cwd: &Path, paths: &[PathBuf]) -> io::Result<Value> {
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
            .root_change_status(self.is_running(), !removed.is_empty())?
            .map(|(applied, generation)| {
                json!({
                    "roots_path":path,"removed":removed,"applied":applied,
                    "running":true,"generation":generation,
                })
            });
        Ok(json!({"roots_path":path,"removed":removed,"apply":apply}))
    }

    fn root_change_status(&self, running: bool, changed: bool) -> io::Result<Option<(bool, u64)>> {
        if !running {
            return Ok(None);
        }
        let applied = changed && self.reload()?["reloaded"] == true;
        Ok(Some((applied, self.generation.load(Ordering::Relaxed))))
    }

    pub(super) fn rebuild_log(&self, cwd: &Path) -> io::Result<bool> {
        let hub = self
            .running
            .lock()
            .unwrap()
            .as_ref()
            .filter(|run| !run.thread.is_finished())
            .map(|run| Arc::clone(&run.hub));
        if let Some(hub) = hub {
            let (send, receive) = mpsc::sync_channel(1);
            hub.update(|signals| signals.rebuild.push(send));
            return receive.recv().map_err(io::Error::other)?;
        }
        let dir = state_dir(cwd)?;
        let state = journal::Journal::open(&dir)?;
        state.rebuild_log()
    }

    pub(super) fn cancel_batch(&self, id: &str) -> bool {
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
        let (send, receive) = mpsc::sync_channel(1);
        hub.update(|signals| signals.cancel.push((id.to_owned(), send)));
        receive.recv().unwrap_or(false)
    }
}

impl Watch {
    fn external_journal(&self, path: &Path) -> Option<Arc<journal::Journal>> {
        let external = self.external.lock().unwrap();
        let external = external.as_ref()?;
        let path = path.to_string_lossy();
        external
            .scopes
            .iter()
            .any(|scope| scope.intersects_output(&path))
            .then(|| external.journal.upgrade())
            .flatten()
    }

    pub(super) fn register_external_output(&self, path: &Path) -> io::Result<()> {
        let journal = self.external_journal(path);
        crate::scan::scope::create_output_root_exclusive(path)
            .map_err(crate::pipeline::OutputCreateError::wrap)?;
        if let Some(journal) = journal {
            let text = path.to_string_lossy();
            let identity = output_identity(&text)?;
            let operation = json!({"op":"runtime","key":format!("owned|{}", key(path)),
                "value":{"path":path,"identities":[identity]}});
            journal.commit(true, |state| state.decode_operations(&[operation]))?;
        }
        Ok(())
    }

    pub(super) fn prepare_external_flatten(
        &self,
        output: &Path,
        work: &Path,
        leaf: &Path,
    ) -> io::Result<()> {
        if let Some(journal) = self.external_journal(output) {
            prepare_flatten(&journal, "", output, work, leaf)?;
        }
        Ok(())
    }

    pub(super) fn finish_external_flatten(&self, output: &Path) -> io::Result<()> {
        if let Some(journal) = self.external_journal(output) {
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
        .filter_map(|root| root.output.as_deref().map(key))
        .collect();
    for (index, outer) in output.iter().enumerate() {
        for inner in &output[index + 1..] {
            if inner != outer && (is_path_under(inner, outer) || is_path_under(outer, inner)) {
                return Err(io::Error::other(
                    "Watch output roots must not contain one another",
                ));
            }
        }
    }
    Ok(())
}

struct Running {
    hub: Arc<Hub>,
    thread: JoinHandle<io::Result<()>>,
}

#[derive(Default)]
struct Signals {
    changed_roots: HashMap<String, HashSet<PathBuf>>,
    reload: bool,
    reload_waiters: Vec<mpsc::SyncSender<io::Result<()>>>,
    once: Vec<mpsc::SyncSender<io::Result<()>>>,
    password_changed: bool,
    foreground_finished: bool,
    clipboard: Option<Vec<String>>,
    volumes_changed: bool,
    rebuild: Vec<mpsc::SyncSender<io::Result<bool>>>,
    cancel: Vec<(String, mpsc::SyncSender<bool>)>,
    completed: Vec<String>,
}

struct Hub {
    stopped: AtomicBool,
    signals: Mutex<Signals>,
    wake: std::sync::Condvar,
    claims: Mutex<HashMap<String, Arc<str>>>,
    seeds: Mutex<HashMap<String, Seed>>,
    pending_count: AtomicUsize,
}

type SourceGenerations = HashMap<String, PhysicalFileGeneration>;

struct Seed {
    owners: u8,
    processed: Option<Arc<SourceGenerations>>,
}

impl Hub {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            signals: Mutex::default(),
            wake: std::sync::Condvar::new(),
            claims: Mutex::default(),
            seeds: Mutex::default(),
            pending_count: AtomicUsize::new(0),
        }
    }

    fn track_seed(&self, path: &str) {
        let mut seeds = self.seeds.lock().unwrap();
        if let Some(seed) = seeds.get_mut(path) {
            seed.owners += 1;
        } else {
            seeds.insert(
                path.to_owned(),
                Seed {
                    owners: 1,
                    processed: None,
                },
            );
        }
    }

    fn retire_seed(&self, path: &str) {
        let mut seeds = self.seeds.lock().unwrap();
        if let Some(seed) = seeds.get_mut(path) {
            seed.owners -= 1;
            if seed.owners == 0 {
                seeds.remove(path);
                crate::collections::trim_map(&mut seeds);
            }
        }
    }

    fn stop(&self) {
        {
            let _guard = self.signals.lock().unwrap();
            self.stopped.store(true, Ordering::Release);
        }
        self.wake.notify_one();
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

    fn queue_reload(&self, wait: Option<mpsc::SyncSender<io::Result<()>>>) {
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
                && !value.foreground_finished
                && value.clipboard.is_none()
                && !value.volumes_changed
                && value.rebuild.is_empty()
                && value.cancel.is_empty()
                && value.once.is_empty()
                && value.completed.is_empty()
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

struct FileObserver {
    path: PathBuf,
    changes: Arc<NativeConfigChanges>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FileObserver {
    fn start(
        path: &Path,
        recursive: bool,
        notify: impl Fn(Option<Vec<String>>) + Send + 'static,
    ) -> io::Result<Self> {
        let changes = Arc::new(NativeConfigChanges::observe(path.to_owned(), recursive)?);
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
            && !self.observer.stopping.load(Ordering::Acquire)
            && output_identity(&path.to_string_lossy()).is_ok_and(|identity| identity == self.identity)
    }

    fn start(
        directory: &Path,
        root: &Root,
        scope: Option<NativeDiscoveryScope>,
        hub: &Arc<Hub>,
    ) -> io::Result<Self> {
        let identity = output_identity(&directory.to_string_lossy())?;
        let id = key(&root.path);
        let watched_dir = directory.to_owned();
        let recursive = scope.is_some() && root.recursive;
        let hub = Arc::clone(hub);
        let observer = FileObserver::start(directory, recursive, move |names| {
            let paths = names.map(|names| {
                names.into_iter().map(|name| watched_dir.join(name)).filter(|path| {
                    scope.as_ref().map_or_else(
                        // A parent sentinel only reacts to the root or a
                        // missing ancestor, never unrelated sibling traffic.
                        || { let path = key(path); path == id || is_path_under(&id, &path) },
                        |scope| scope.contains(&path.to_string_lossy()),
                    )
                }).collect::<Vec<_>>()
            });
            if paths.as_ref().is_none_or(|paths| !paths.is_empty()) {
                hub.update(|signals| {
                    signals.changed_roots.entry(id.clone()).or_default()
                        .extend(paths.into_iter().flatten());
                });
            }
        })?;
        Ok(Self { observer, identity })
    }
}

#[derive(Default)]
struct RootObservers {
    root: Option<RootObserver>,
    parent: Option<RootObserver>,
}

impl RootObservers {
    fn rearm(
        &mut self,
        root: &Root,
        scope: &NativeDiscoveryScope,
        hub: &Arc<Hub>,
    ) -> (bool, Vec<io::Error>) {
        // Arm the parent first. A rename between the identity probe and the
        // root subscription is then replayed through the existing Hub loop.
        let mut errors = Vec::new();
        let parent = root.path.parent().and_then(nearest_directory);
        if self.parent.as_ref().is_some_and(|observer| {
            parent.is_none_or(|path| !observer.matches(path))
        }) {
            self.parent.take();
        }
        if self.parent.is_none() {
            if let Some(parent) = parent {
                match RootObserver::start(parent, root, None, hub) {
                    Ok(observer) => self.parent = Some(observer),
                    Err(error) => errors.push(io::Error::new(error.kind(), format!(
                        "Parent observer {}: {error}", parent.display(),
                    ))),
                }
            }
        }
        // A root can grant access even when its parent only permits traversal.
        // Failure of the extra sentinel must not disable the root subscription.
        let replaced = self.root.as_ref().is_some_and(|observer| !observer.matches(&root.path));
        if replaced {
            self.root.take();
        }
        if self.root.is_none() && root.path.is_dir() {
            match RootObserver::start(&root.path, root, Some(scope.clone()), hub) {
                Ok(observer) => self.root = Some(observer),
                Err(error) => errors.push(error),
            }
        }
        (replaced, errors)
    }
}

struct Pending {
    root: String,
    candidate: WatchCandidateRow,
    quiet: quiet::Quiet,
    due: Instant,
    force: bool,
    recovery: Option<Arc<Recovery>>,
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

struct Active {
    root: String,
    recovery: Option<Arc<Recovery>>,
    passwords: Arc<crate::core::passwords::PasswordSnapshot>,
    inputs: Vec<WatchCandidateRow>,
    touched: HashSet<String>,
    cancel: Cancellation,
    groups: Arc<Mutex<HashMap<String, Arc<SourceGroup>>>>,
    claimed: Arc<Mutex<ClaimedSources>>,
    toast: Option<super::toast::Activity>,
    thread: JoinHandle<Completed>,
}

struct Completed {
    cancelled: bool,
    result: io::Result<Outcome>,
    promoted: HashMap<String, Option<WatchCandidateRow>>,
}

fn output_cleanup_error(result: &io::Result<Outcome>) -> Option<&OutputCleanupError> {
    result.as_ref().err()?.get_ref()?.downcast_ref()
}

#[derive(serde::Serialize)]
struct SourceGroup {
    path: PathBuf,
    name: String,
    members: Vec<String>,
    multipart: bool,
}

struct Scheduler {
    cwd: PathBuf,
    root_file: PathBuf,
    roots: BTreeMap<String, (Root, NativeDiscoveryScope)>,
    available_roots: HashSet<String>,
    settings: Arc<Config>,
    engine: Arc<Engine>,
    journal: Arc<journal::Journal>,
    catalog: Arc<NativeWatchCatalog>,
    options: NativeDirectoryScanOptions,
    deep_options: NativeDirectoryScanOptions,
    passwords: Arc<BuiltinStore>,
    hub: Arc<Hub>,
    root_observers: HashMap<String, RootObservers>,
    config_observers: Vec<FileObserver>,
    pending: HashMap<String, Pending>,
    unpublished: HashSet<String>,
    due: BTreeMap<(Instant, String), ()>,
    active: HashMap<String, Active>,
    active_paths: HashMap<String, (Arc<str>, usize)>,
    continuous: bool,
    tray_enabled: bool,
    tray: Option<super::tray::Tray>,
    monitor: Option<(crate::core::clipboard_monitor::Monitor, bool, usize)>,
    toast: Option<super::toast::Toast>,
    cache_deadline: Option<Instant>,
    failed: usize,
    external: Arc<Mutex<Option<ExternalOutputs>>>,
    _lease: BrokerLease,
}

impl Scheduler {
    fn open(
        cwd: PathBuf,
        engine: Arc<Engine>,
        hub: Arc<Hub>,
        continuous: bool,
        tray_enabled: bool,
        external: Arc<Mutex<Option<ExternalOutputs>>>,
    ) -> io::Result<Self> {
        let lease = BrokerLease::acquire()?;
        let snapshot = config::load_snapshot(&cwd)?;
        let root_file = roots_path(&cwd)?;
        let dir = state_dir(&cwd)?;
        let journal = Arc::new(journal::Journal::open(&dir)?);
        journal.set_retention(snapshot.config.watch.event_log_retention_days)?;
        let catalog = Arc::new(NativeWatchCatalog::new(
            journal.state(),
            Some(dir.to_string_lossy().into_owned()),
        ));
        let options = crate::pipeline::scan_options(&snapshot.config)?;
        let deep_options =
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())?;
        let passwords = BuiltinStore::shared(&cwd)?;
        let config_observers = Self::observe_config(&cwd, &snapshot, &root_file, passwords.path(), &hub)?;
        let mut scheduler = Self {
            cwd,
            root_file,
            roots: BTreeMap::new(),
            available_roots: HashSet::new(),
            settings: Arc::new(snapshot.config),
            engine,
            journal,
            catalog,
            options,
            deep_options,
            passwords,
            hub,
            root_observers: HashMap::new(),
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
            failed: 0,
            external,
            _lease: lease,
        };
        scheduler.reconcile_roots()?;
        scheduler.retire_missing_entries(None, true)?;
        scheduler.retire_stale_promoted(None, true)?;
        scheduler.reconcile_shell();
        windows::configure_priority(&scheduler.engine, scheduler.settings.runtime.process_mode);
        scheduler.recover_pending(None)?;
        if !scheduler.continuous && scheduler.settings.watch.clipboard_monitor_enabled {
            scheduler.merge_clipboard(&crate::core::passwords::clipboard_passwords())?;
        }
        scheduler.password_update()?;
        scheduler.checkpoint(&HashMap::new(), true, true)?;
        scheduler.retry_missing_volumes(None)?;
        scheduler
            .hub
            .pending_count
            .store(scheduler.pending.len(), Ordering::Relaxed);
        scheduler
            .journal
            .log(json!({"event":"watch_started","roots":scheduler.roots.len()}));
        Ok(scheduler)
    }

    fn observe_config(
        cwd: &Path,
        snapshot: &Snapshot,
        roots: &Path,
        passwords: &Path,
        hub: &Arc<Hub>,
    ) -> io::Result<Vec<FileObserver>> {
        let mut targets: HashMap<PathBuf, HashMap<String, bool>> = HashMap::new();
        let paths = config::watch_paths(cwd, &snapshot.sources);
        for path in paths.iter().map(PathBuf::as_path).chain([roots, passwords])
        {
            let parent = path.parent().and_then(nearest_directory).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("No observable configuration directory for {}", path.display()))
            })?;
            let Some(name) = path
                .strip_prefix(parent)
                .ok()
                .and_then(|path| path.components().next())
            else {
                continue;
            };
            let password = targets.entry(parent.to_owned()).or_default().entry(
                name.as_os_str().to_string_lossy().to_lowercase(),
            ).or_default();
            *password |= path == passwords;
        }
        targets
            .into_iter()
            .map(|(dir, files)| {
                let hub = Arc::clone(hub);
                FileObserver::start(&dir, false, move |names| {
                    let mut reload = false;
                    let mut passwords = false;
                    let mut affected = |name: &str| match files.get(&name.to_lowercase()) {
                        Some(true) => {
                            passwords = true;
                            reload = true;
                        }
                        Some(false) => reload = true,
                        None => {}
                    };
                    if let Some(names) = names {
                        for name in &names {
                            affected(name);
                        }
                    } else {
                        for name in files.keys() {
                            affected(name);
                        }
                    }
                    if reload || passwords {
                        hub.update(|signals| {
                            signals.reload |= reload;
                            signals.password_changed |= passwords;
                        });
                    }
                })
            })
            .collect()
    }

    fn reconcile_shell(&mut self) {
        if !self.continuous {
            return;
        }
        let show_tray = self.tray_enabled && self.settings.watch.tray_enabled;
        if show_tray && self.tray.is_none() {
            let hub = Arc::clone(&self.hub);
            let tray =
                super::tray::Tray::start(&self.cwd, self.settings.cli.language, move |action| {
                    match action {
                        super::tray::Action::Reload => hub.queue_reload(None),
                        super::tray::Action::Stop => hub.stop(),
                    }
                });
            match tray {
                Ok(tray) => self.tray = Some(tray),
                Err(error) => self
                    .journal
                    .log(json!({"event":"tray_start_failed","error":error.to_string()})),
            }
        } else if !show_tray {
            self.tray.take();
        } else if let Some(tray) = &self.tray {
            tray.set_language(self.settings.cli.language);
        }
        if self.settings.watch.toast_enabled {
            if self.toast.is_none() {
                let diagnostic = state_dir(&self.cwd).map(|dir| dir.join("toast-diagnostic.log"));
                match diagnostic.and_then(|path| {
                    super::toast::Toast::start(
                        &self.cwd,
                        path,
                        self.settings.watch.toast_report_retention_days,
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
        let clipboard = self.settings.watch.clipboard_monitor_enabled;
        let clipboard_limit = self.settings.watch.clipboard_builtin_max_entries;
        if self.monitor.is_none()
            || self.monitor.as_ref().is_some_and(|(_, enabled, limit)| {
                *enabled != clipboard || *limit != clipboard_limit
            })
        {
            let hub = Arc::clone(&self.hub);
            self.monitor.take();
            let monitor =
                crate::core::clipboard_monitor::Monitor::start(clipboard, true, move |change| {
                    hub.update(|signals| match change {
                        crate::core::clipboard_monitor::Notification::Clipboard(values) => {
                            let pending = signals.clipboard.get_or_insert_with(Vec::new);
                            for value in values {
                                if let Some(index) = pending.iter().position(|item| item == &value)
                                {
                                    pending.remove(index);
                                }
                                pending.push(value);
                            }
                            if pending.len() > clipboard_limit {
                                pending.drain(..pending.len() - clipboard_limit);
                            }
                        }
                        crate::core::clipboard_monitor::Notification::VolumeChanged { .. } => {
                            signals.volumes_changed = true
                        }
                    });
                });
            match monitor {
                Ok(monitor) => self.monitor = Some((monitor, clipboard, clipboard_limit)),
                Err(error) => self
                    .journal
                    .log(json!({"event":"shell_monitor_failed","error":error.to_string()})),
            }
        }
    }

    fn reconcile_roots(&mut self) -> io::Result<()> {
        let mut entries = read_roots(&self.root_file)?;
        validate_outputs(&entries)?;
        let mut rejected = Vec::new();
        entries.retain(|entry| {
            let text = entry.path.to_string_lossy();
            match filesystem::watch_filesystem_type(&text) {
                Ok(fs) if !fs.eq_ignore_ascii_case("NTFS") => {
                    rejected.push(key(&entry.path));
                    self.journal.log(
                        json!({"event":"watch_root_rejected","path":entry.path,"filesystem":fs}),
                    );
                    false
                }
                _ => true, // A missing drive can return later.
            }
        });
        if !rejected.is_empty() {
            let _guard = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
            let mut latest = read_roots(&self.root_file)?;
            latest.retain(|root| !rejected.contains(&key(&root.path)));
            write_roots(&self.root_file, &latest)?;
        }
        let new_directories: HashSet<_> = entries
            .iter()
            .filter(|root| !self.roots.contains_key(&key(&root.path)))
            .filter_map(|root| nearest_directory(&root.path))
            .collect();
        for directory in new_directories {
            filesystem::validate_ntfs_watch_root(&directory.to_string_lossy())?;
        }
        let dir = state_dir(&self.cwd)?;
        let next = entries
            .iter()
            .map(|root| (key(&root.path), (root.clone(), root.scope(&entries, &dir))))
            .collect::<BTreeMap<_, _>>();
        let policy_changed = self.roots.len() != next.len()
            || next.iter().any(|(id, (root, _))| {
                self.roots.get(id).is_none_or(|(old, _)| {
                    old.recursive != root.recursive
                        || old.output.as_deref().map(key) != root.output.as_deref().map(key)
                        || old.deep != root.deep
                })
            });
        if policy_changed {
            let reroute = self
                .pending
                .iter()
                .filter_map(|(id, pending)| {
                    if pending.recovery.is_some() {
                        return (!next.contains_key(&pending.root)).then(|| (id.clone(), None));
                    }
                    if next
                        .get(&pending.root)
                        .is_some_and(|(_, scope)| scope.contains(&pending.candidate.path))
                    {
                        return None;
                    }
                    let root = next.iter().find_map(|(root, (_, scope))| {
                        scope
                            .contains(&pending.candidate.path)
                            .then(|| root.clone())
                    });
                    Some((id.clone(), root))
                })
                .collect::<Vec<_>>();
            for (id, root) in reroute {
                if let Some(root) = root {
                    self.pending.get_mut(&id).unwrap().root = root;
                    self.unpublished.insert(id);
                } else if let Some(pending) = self.pending.remove(&id) {
                    self.hub.retire_seed(&id);
                    self.due.remove(&(pending.due, id.clone()));
                    self.unpublished.remove(&id);
                }
            }
        }
        let catalog_roots = entries
            .iter()
            .map(|entry| entry.path.to_string_lossy().into_owned())
            .collect();
        if policy_changed || self.roots.is_empty() {
            self.catalog.retain_roots(catalog_roots);
            self.root_observers.clear();
            let scopes = next
                .values()
                .map(|(_, scope)| scope.clone())
                .collect::<Vec<_>>();
            self.journal.commit(
                false,
                |state| Ok(state.scope_retirement_operations(&scopes)),
            )?;
            *self.external.lock().unwrap() = Some(ExternalOutputs {
                journal: Arc::downgrade(&self.journal),
                scopes,
            });
        }
        self.available_roots.retain(|id| next.contains_key(id));
        self.roots = next;
        self.rearm_root_observers(None);
        Ok(())
    }

    fn rearm_root_observers(&mut self, changed: Option<&HashMap<String, HashSet<PathBuf>>>) {
        self.root_observers.retain(|id, _| self.roots.contains_key(id));
        for (id, (root, scope)) in self.roots.iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains_key(*id)))
        {
            let (replaced, errors) = self.root_observers.entry(id.clone()).or_default()
                .rearm(root, scope, &self.hub);
            if replaced {
                self.available_roots.remove(id);
            }
            for error in errors {
                self.journal.log(json!({"event":"watch_root_unavailable","root":root.path,"error":error.to_string()}));
            }
        }
    }

    fn reload(&mut self) -> io::Result<()> {
        let snapshot = config::load_snapshot(&self.cwd)?;
        let options = crate::pipeline::scan_options(&snapshot.config)?;
        let config_observers =
            Self::observe_config(&self.cwd, &snapshot, &self.root_file, self.passwords.path(), &self.hub)?;
        self.reconcile_roots()?;
        self.journal
            .set_retention(snapshot.config.watch.event_log_retention_days)?;
        self.settings = Arc::new(snapshot.config);
        windows::configure_priority(&self.engine, self.settings.runtime.process_mode);
        self.options = options;
        self.config_observers = config_observers;
        self.reconcile_shell();
        self.checkpoint(&HashMap::new(), true, false)?;
        Ok(())
    }

    fn run(&mut self, once: bool) -> io::Result<i32> {
        let mut result = self.run_inner(once);
        self.hub.stop();
        while let Some(batch) = self.active.keys().next().cloned() {
            if result.is_ok() {
                if let Err(error) = self.complete(&batch) {
                    result = Err(error);
                }
            } else {
                for active in self.active.values() {
                    active.cancel.cancel();
                }
                for (_, active) in self.active.drain() {
                    let _ = active.thread.join();
                }
            }
        }
        let signals = self.hub.wait(None);
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
        *self.hub.seeds.lock().unwrap() = HashMap::new();
        self.catalog.commit(true);
        self.catalog.close();
        self.journal.log(json!({"event":"watch_stopped"}));
        self.journal.flush()?;
        result
    }

    fn run_inner(&mut self, once: bool) -> io::Result<i32> {
        while !self.hub.stopped.load(Ordering::Acquire) {
            self.dispatch_ready()?;
            self.hub
                .pending_count
                .store(self.pending.len(), Ordering::Relaxed);
            if self.active.is_empty() && self.pending.is_empty() {
                self.catalog.commit(true);
                self.journal.compact()?;
                if once {
                    break;
                }
            }
            let due = {
                let claims = self.hub.claims.lock().unwrap();
                self.due.keys().find_map(|(due, path)| {
                    (!self.active_paths.contains_key(path) && !claims.contains_key(path))
                        .then_some(*due)
                })
            };
            let deadline = match (due, self.cache_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let signals = self.hub.wait(deadline);
            for (batch, waiter) in signals.cancel {
                let _ = waiter.send(self.cancel_display_batch(&batch));
            }
            for completed in signals.completed {
                self.complete(&completed)?;
            }
            for waiter in signals.rebuild {
                let _ = waiter.send(self.journal.rebuild_log());
            }
            if let Some(clipboard) = signals.clipboard {
                self.merge_clipboard(&clipboard)?;
            }
            if signals.password_changed || !signals.reload_waiters.is_empty() {
                self.password_update()?;
            }
            if signals.foreground_finished {
                self.arm_idle_cleanup();
            }
            if signals.reload {
                let reload = self.reload();
                if let Err(error) = &reload {
                    self.journal
                        .log(json!({"event":"watch_reload_failed","error":error.to_string()}));
                    if self.config_observers.iter().any(|observer| observer.stopping.load(Ordering::Acquire)) {
                        // Do not advertise a healthy Watch after a failed event
                        // subscription. Startup/restart can report the real error.
                        return Err(io::Error::other(format!("Configuration observer recovery failed: {error}")));
                    }
                }
                for waiter in signals.reload_waiters {
                    let _ = waiter.send(
                        reload
                            .as_ref()
                            .map(|_| ())
                            .map_err(|error| io::Error::other(error.to_string())),
                    );
                }
            }
            if signals.volumes_changed
                || !signals.changed_roots.is_empty()
                || !signals.once.is_empty()
            {
                let all_roots = signals.volumes_changed || !signals.once.is_empty();
                self.rearm_root_observers((!all_roots).then_some(&signals.changed_roots));
                let result = self
                    .checkpoint(&signals.changed_roots, all_roots, false)
                    .and_then(|_| {
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
                    windows::maintain_when_foreground_idle(|| {
                        let _ = crate::io::reader::clear_reader_resources();
                        self.engine.clear_idle_passwords();
                        self.journal.state().trim_idle_storage();
                        self.pending.shrink_to_fit();
                        self.unpublished.shrink_to_fit();
                        self.active.shrink_to_fit();
                        self.active_paths.shrink_to_fit();
                        self.hub.seeds.lock().unwrap().shrink_to_fit();
                    });
                }
            }
        }
        Ok(i32::from(self.failed > 0))
    }
}

impl Scheduler {
    fn scan_options(&self, deep: bool) -> &NativeDirectoryScanOptions {
        if deep {
            &self.deep_options
        } else {
            &self.options
        }
    }

    fn checkpoint(
        &mut self,
        changed: &HashMap<String, HashSet<PathBuf>>,
        all_roots: bool,
        startup: bool,
    ) -> io::Result<()> {
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
            let current = filesystem::watch_volume_cursor(&scope.root);
            let cached = self.catalog.cursor(&scope);
            if let (Ok((volume, journal, end)), Some((old_volume, old_journal, old_end))) =
                (&current, &cached)
            {
                if volume == old_volume && journal == old_journal && (1..=*end).contains(old_end) {
                    let start = self
                        .journal
                        .state()
                        .watch_cursor(volume)
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
            probes.push((id, root, scope, current, cached));
        }
        if !reopened.is_empty() {
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
                    paths
                });
            ranges.insert((volume, journal), (end, changed));
        }
        let mut marks = Vec::new();
        let mut admitted = HashSet::new();
        let mut cursors = Vec::new();
        let mut failures = HashSet::new();
        for (id, root, scope, current, cached) in probes {
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
            if rebuild {
                // An untrusted history cannot distinguish old files from new
                // arrivals. Rebuild only the baseline; an unscanned root still
                // admits its initial inventory below.
                let scan = self.scan_options(root.deep)
                    .catalog_update(&self.catalog, &scope, None);
                match scan {
                    Ok(failures) => errors = failures,
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
                // A directory notification can arrive before its USN record
                // becomes readable. Visit both sources through the same catalog.
                let mut named = changed.get(&id).into_iter().flatten().collect::<Vec<_>>();
                named.sort_unstable_by_key(|path| path.as_os_str().len());
                for path in changes
                    .iter()
                    .map(|path| std::borrow::Cow::Borrowed(path.as_str()))
                    .chain(named.into_iter().map(|path| path.to_string_lossy()))
                {
                    let path = path.as_ref();
                    if !scope.contains(path) || self.catalog.is_owned(path) {
                        continue;
                    }
                    let path_id = watch_path_key(path);
                    if covered.contains(&path_id) {
                        continue;
                    }
                    let metadata = fs::metadata(path);
                    let missing = metadata.as_ref().is_err_and(missing_path);
                    let recursive_departure =
                        missing && self.catalog.path_is_directory(&scope, path).unwrap_or(true);
                    if !has_covered_parent(&path_id, &covered) {
                        let (failed, mut arrivals) = self.scan_options(root.deep).catalog_refresh(
                            &self.catalog,
                            &scope,
                            Some(path),
                        )?;
                        paths.append(&mut arrivals);
                        errors.extend(failed);
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
            if !root.scanned {
                paths.extend(self.catalog.candidate_paths(&scope, None));
                if errors.is_empty() && current.is_ok() {
                    marks.push(id.clone());
                }
            }
            for path in paths {
                let path_id = watch_path_key(&path);
                if admitted.insert(path_id) {
                    let peers = self.catalog.bucket_paths(&scope, &path);
                    self.enqueue(&id, path.clone(), false)?;
                    for peer in peers.into_iter().filter(|peer| peer != &path) {
                        if self.journal.state().entry(&peer).is_some_and(|entry| {
                            entry
                                .failure_payload
                                .get("blockers")
                                .and_then(Value::as_array)
                                .is_some_and(|blockers| {
                                    blockers.iter().any(|value| value == "missing_volume")
                                })
                        }) {
                            let key = watch_path_key(&peer);
                            if admitted.insert(key) {
                                self.enqueue(&id, peer, true)?;
                            }
                        }
                    }
                }
            }
            match current {
                Ok((volume, journal, mut end)) if errors.is_empty() => {
                    if let Some((current_end, Ok(_))) = range {
                        end = *current_end;
                    }
                    cursors.push((scope, volume, journal, end));
                }
                Ok((volume, _, _)) => { failures.insert(volume); }
                Err(error) => self.journal.log(json!({"event":"usn_cursor_unavailable","root":root.path,"error":error.to_string()})),
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
        // Commit the admissions and cursor together. A recovered cursor never
        // implies ownership of an input whose pending work was still in RAM.
        self.persist_candidates(operations, true)?;
        if !cursors.is_empty() {
            for (scope, volume, journal, end) in cursors {
                if !failures.contains(&volume) {
                    self.catalog.set_cursor(&scope, volume, journal, end);
                }
            }
        }
        if !marks.is_empty() {
            let _lock = FileMutex::lock(&self.root_file, ROOTS_LOCK)?;
            let mut latest = read_roots(&self.root_file)?;
            let mut dirty = false;
            for root in &mut latest {
                let id = key(&root.path);
                if marks.contains(&id) {
                    if let Some((current, _)) = self.roots.get_mut(&id) {
                        if root.output.as_deref().map(key) == current.output.as_deref().map(key)
                            && root.deep == current.deep
                            && root.recursive == current.recursive
                        {
                            dirty |= !root.scanned;
                            root.scanned = true;
                            current.scanned = true;
                        }
                    }
                }
            }
            if dirty {
                write_roots(&self.root_file, &latest)?;
            }
            self.journal
                .log(json!({"event":"initial_scan_completed","roots":marks}));
        }
        if startup || !admitted.is_empty() {
            self.journal.log(
                json!({"event":if startup { "usn_startup_recovered" } else { "usn_checkpoint" },
                "changed":admitted.len(),"queued":self.pending.len()}),
            );
        }
        self.catalog.commit(false);
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
                self.hub.retire_seed(&id);
                self.due.remove(&(pending.due, id.clone()));
                self.unpublished.remove(&id);
                self.retire_departed_owner(&id, &pending.candidate.path)?;
            }
        }
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

    fn enqueue(&mut self, root_id: &str, path: String, force: bool) -> io::Result<()> {
        self.enqueue_with_recovery(root_id, path, force, None)
    }

    fn enqueue_with_recovery(
        &mut self,
        root_id: &str,
        path: String,
        force: bool,
        recovery: Option<Arc<Recovery>>,
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
        let previous = self.catalog.observation(&path);
        let (blocked, promoted) = self.journal.state().observation_state(&id);
        let pending_candidate = self.pending.get(&id).map(|entry| &entry.candidate);
        let active_candidate = self.active_paths.get(&id).and_then(|(batch, index)| {
            self.active
                .get(batch.as_ref())
                .map(|active| &active.inputs[*index])
        });
        let interrupted = blocked
            .as_ref()
            .filter(|entry| entry.status == "interrupted");
        let baseline = interrupted
            .map(|entry| entry.change_usn)
            .or_else(|| pending_candidate.map(|entry| entry.observation.change_usn))
            .or_else(|| previous.as_ref().map(|value| value.change_usn))
            .or_else(|| active_candidate.map(|input| input.observation.change_usn))
            .or_else(|| blocked.as_ref().map(|value| value.change_usn));
        let candidate = match watch_candidate_for_path(Path::new(&path), baseline) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                self.journal
                    .log(json!({"event":"candidate_error","path":path,"error":error.to_string()}));
                return Ok(());
            }
        };
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
        let unchanged = if let Some(before) = pending_candidate {
            !quiet::changed(before, &candidate)
        } else if let Some(before) = &previous {
            !quiet::content_changed(
                before.size,
                before.mtime,
                &before.file_id(),
                before.change_usn,
                &candidate,
            )
        } else if let Some(before) = active_candidate {
            !quiet::changed(before, &candidate)
        } else {
            blocked_unchanged
        };
        let boundary = quiet::is_boundary(&candidate);
        if (interrupted.is_some() && blocked_unchanged)
            || (!force && (unchanged || blocked_unchanged))
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
                && previous.as_ref().is_some_and(|before| {
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
                    pending.quiet.end_phase();
                    // CLOSE is a useful hint only if a writer hasn't reopened
                    // the file. Keep short existing waits on their cadence.
                    if pending.due.saturating_duration_since(now).as_millis() >= 100
                        && filesystem::watch_file_is_ready(&candidate.path).unwrap_or(false)
                    {
                        self.due.remove(&(pending.due, id.clone()));
                        pending.due = now;
                        self.due.insert((now, id), ());
                    }
                }
                pending.candidate = candidate;
            }
            return Ok(());
        }
        let claim = self.hub.claims.lock().unwrap();
        let batch = self
            .active_paths
            .get(&id)
            .map(|(batch, _)| batch.as_ref())
            .or_else(|| claim.get(&id).map(AsRef::as_ref));
        if let Some(active) = batch.and_then(|batch| self.active.get_mut(batch)) {
            // Let the running request finish. A new generation of one source
            // must never interrupt the other sources in its batch.
            active.touched.insert(id.clone());
        }
        drop(claim);
        let now = Instant::now();
        let prior = self.pending.remove(&id);
        if prior.is_none() {
            self.hub.track_seed(&id);
        }
        let new_identity = prior.as_ref().map_or_else(
            || {
                previous.as_ref().is_some_and(|old| {
                    old.file_id() != candidate.observation.file_id || old.size > candidate.size
                })
            },
            |old| {
                old.candidate.observation.file_id != candidate.observation.file_id
                    || old.candidate.size > candidate.size
            },
        );
        let mut quiet = if let Some(old) = prior {
            self.due.remove(&(old.due, id.clone()));
            old.quiet
        } else {
            previous
                .as_ref()
                .map_or_else(quiet::Quiet::default, quiet::Quiet::saved)
        };
        quiet.observe(windows::monotonic_seconds(), boundary, new_identity, true);
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
        let delay = if force && unchanged {
            0.0
        } else if boundary {
            quiet
                .seconds
                .min(self.settings.watch.boundary_confirmation_seconds)
        } else {
            quiet.seconds
        };
        let due = quiet::after(now, delay);
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
        self.persist_candidates_and_retire(cursors, durable, None)
    }

    fn persist_candidates_and_retire(
        &mut self,
        cursors: BTreeMap<String, crate::watch_store::Cursor>,
        durable: bool,
        retire: Option<&str>,
    ) -> io::Result<()> {
        if self.unpublished.is_empty() && cursors.is_empty() && retire.is_none() {
            return Ok(());
        }
        let keys = std::mem::take(&mut self.unpublished);
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
            if let Some(owner) = retire {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                    owner,
                    state.entry(owner),
                ));
            }
            Ok(operations)
        })?;
        Ok(())
    }

    fn merge_clipboard(&mut self, clipboard: &[String]) -> io::Result<()> {
        match self.passwords.merge_clipboard(
            clipboard,
            self.settings.watch.clipboard_builtin_max_entries,
        ) {
            Ok(true) => self.password_update()?,
            Ok(false) => {}
            Err(error) => self.journal.log(json!({
                "event":"watch_clipboard_password_save_failed", "error":error.to_string(),
            })),
        }
        Ok(())
    }

    fn password_update(&mut self) -> io::Result<()> {
        let snapshot = match self.passwords.reload() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.journal
                    .log(json!({"event":"watch_password_reload_failed","error":error.to_string()}));
                return Ok(());
            }
        };
        let signature = snapshot.signature().to_string();
        let state = self.journal.state();
        if state.password_source_signature() == signature {
            return Ok(());
        }
        let generation = state.password_generation().saturating_add(1);
        self.retry_password_failures(&snapshot, None)?;
        self.persist_candidates(BTreeMap::new(), false)?;
        self.journal.commit(true, |_| {
            Ok(
                crate::watch_store::NativeWatchOperations::password_generation(
                    generation, signature,
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
        for entry in self.journal.state().entry_items(Some("password")) {
            let Some((root, recovery)) = self.blocker_route(&entry) else {
                continue;
            };
            if roots.is_some_and(|roots| !roots.contains(&root)) {
                continue;
            }
            let path = Path::new(&entry.path);
            let directory = recovery.as_ref().map_or_else(
                || path.parent().unwrap_or(Path::new("")),
                |recovery| recovery.password_dir(path),
            );
            if entry
                .failure_payload
                .get("password_signature")
                .and_then(Value::as_str)
                .is_some_and(|before| before == snapshot.scope_signature(directory))
            {
                continue;
            }
            self.enqueue_with_recovery(&root, entry.path.clone(), true, recovery)?;
            self.journal
                .log(json!({"event":"retry_password_failure","path":entry.path}));
        }
        Ok(())
    }

    fn retry_missing_volumes(&mut self, roots: Option<&HashSet<String>>) -> io::Result<()> {
        for entry in self.journal.state().entry_items(Some("missing_volume")) {
            let Some((root, recovery)) = self.blocker_route(&entry) else {
                continue;
            };
            if roots.is_some_and(|roots| !roots.contains(&root)) {
                continue;
            }
            let id = watch_path_key(&entry.path);
            if !self.pending.contains_key(&id) {
                self.enqueue_with_recovery(&root, entry.path.clone(), true, recovery)?;
            }
        }
        self.persist_candidates(BTreeMap::new(), true)
    }

    fn blocker_route(
        &self,
        entry: &crate::watch_store::EntryRecord,
    ) -> Option<(String, Option<Arc<Recovery>>)> {
        let payload = &entry.failure_payload;
        if let Some(root) = payload.get("source_input_root").and_then(Value::as_str) {
            let root = watch_path_key(root);
            let (_, watched_scope) = self.roots.get(&root)?;
            if let Some(scope) = payload.get("discovery_scope").and_then(Value::as_object) {
                let password_scope = payload
                    .get("password_scope_dir")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let recovery = Recovery::from_record(scope, password_scope)?;
                if recovery.scope.contains(&entry.path)
                    && (watch_path_key(&recovery.scope.root) != root
                        || !watched_scope.contains(&entry.path)
                        || self.catalog.is_owned(&entry.path))
                {
                    return Some((root, Some(Arc::new(recovery))));
                }
            }
        }
        self.roots
            .iter()
            .find_map(|(id, (_, scope))| scope.contains(&entry.path).then(|| (id.clone(), None)))
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
            let mut revisit = BTreeMap::new();
            let mut cleanup_failed = false;
            for (task, output) in pending.active_outputs.iter() {
                if pending.committed_roots.contains(output) || borrowed == Some(output.as_str()) {
                    continue;
                }
                match recovery_output_matches(state, &pending, output) {
                    Ok(true) => {
                        if let Err(error) = crate::postprocess::remove_owned_tree(Path::new(output)) {
                            cleanup_failed = true;
                            self.journal.log(json!({"event":"crash_output_cleanup","path":output,"error":error.to_string()}));
                            continue;
                        }
                    }
                    Ok(false) => self.journal.log(json!({"event":"crash_output_identity_changed","owner_path":pending.path,"output_dir":output})),
                    Err(_) => {
                        cleanup_failed = true;
                        continue;
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
                match recovery_output_matches(state, &pending, output) {
                    Ok(true) => verified.push(output),
                    Ok(false) => missing_output = true,
                    Err(_) => unavailable = true,
                }
            }
            if unavailable {
                continue;
            }
            let has_checkpoint = source.is_file()
                && !input_checkpoints(state, &pending.path)
                    .collect::<io::Result<Vec<_>>>()?
                    .is_empty();
            if (missing_output && !promoted_present) || has_checkpoint {
                if !source.is_file() {
                    self.journal.log(
                        json!({"event":"crash_committed_output_missing","owner_path":pending.path}),
                    );
                    continue;
                }
                revisit.insert(watch_path_key(&pending.path), pending.path.clone());
            } else {
                // Python's WAL records predate the logical-input receipt. Only
                // scan the verified committed output for unfinished descendants.
                for output in &verified {
                    let output_scope =
                        NativeDiscoveryScope::new((*output).clone(), None, Vec::new());
                    match crate::scan::directory::scope_file_paths(&output_scope) {
                        Ok((paths, errors)) if errors.is_empty() => {
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
            }
            if unavailable {
                continue;
            }
            if revisit.is_empty() && verified.is_empty() {
                if source.is_file() {
                    revisit.insert(watch_path_key(&pending.path), pending.path.clone());
                } else if !pending.active_outputs.is_empty()
                    || !NativePresence::at(&pending.path).is_absent()
                {
                    continue;
                }
            }
            let owner = watch_path_key(&pending.path);
            let mut rebase = !revisit.contains_key(&owner);
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
                self.enqueue_with_recovery(&root, path.clone(), true, recovery)?;
                if !self.pending.contains_key(&id) && !NativePresence::at(&path).is_absent() {
                    rebase = false;
                }
            }
            self.persist_candidates_and_retire(
                BTreeMap::new(),
                true,
                rebase.then_some(pending.path.as_str()),
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

fn has_covered_parent(path: &str, covered: &HashSet<String>) -> bool {
    let mut ancestor = path;
    loop {
        if covered.contains(ancestor) {
            return true;
        }
        let Some((parent, _)) = ancestor.rsplit_once('\\') else {
            return false;
        };
        ancestor = parent;
    }
}

fn output_identity(path: &str) -> io::Result<String> {
    let (volume, identity, _) = filesystem::watch_path_identity(path)?;
    Ok(format!("{volume}|{identity}"))
}

fn recovery_output_matches(
    state: &crate::watch_store::NativeWatchState,
    pending: &crate::watch_store::PendingRecord,
    path: &str,
) -> io::Result<bool> {
    let Some(actual) = identity_if_present(path)? else {
        return Ok(false);
    };
    if let Some(record) = state.runtime_record(&format!("owned|{}", watch_path_key(path))) {
        if let Some(ids) = record["identities"]
            .as_array()
            .filter(|ids| !ids.is_empty())
        {
            return Ok(ids.iter().any(|id| id.as_str() == Some(&actual)));
        }
    }
    Ok(pending.output_identities.get(path) == Some(&actual))
}

impl Scheduler {
    fn dispatch_ready(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let ready = {
            let claims = self.hub.claims.lock().unwrap();
            self.due
                .keys()
                .take_while(|(due, _)| *due <= now)
                .filter(|(_, path)| {
                    !self.active_paths.contains_key(path) && !claims.contains_key(path)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut groups = BTreeMap::new();
        for (due, id) in ready {
            let Some(mut pending) = self.pending.remove(&id) else {
                continue;
            };
            self.due.remove(&(due, id.clone()));
            let path = Path::new(&pending.candidate.path);
            let previous_usn = pending.candidate.observation.change_usn;
            let current = match watch_candidate_for_path(path, Some(previous_usn)) {
                Ok(Some(current)) => current,
                Ok(None) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(error) if missing_path(&error) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(_) => {
                    self.delay(id, pending, now);
                    continue;
                }
            };
            if quiet::changed(&pending.candidate, &current) {
                let boundary = quiet::is_boundary(&current);
                let reset = pending.candidate.size > current.size
                    || pending.candidate.observation.file_id != current.observation.file_id;
                pending
                    .quiet
                    .observe(windows::monotonic_seconds(), boundary, reset, false);
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
                pending.quiet.end_phase();
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
                    self.delay(id, pending, now);
                    continue;
                }
                Err(error) if missing_path(&error) => {
                    self.retire_admission(&id, &pending)?;
                    continue;
                }
                Err(_) => {
                    self.delay(id, pending, now);
                    continue;
                }
            }
            if pending.recovery.is_none() {
                self.catalog.retire_observation(
                    &pending.candidate.path,
                    Some(pending.quiet.seconds),
                    pending.quiet.last,
                    pending.quiet.cadence,
                    pending.quiet.tentative,
                );
            }
            let recovery_key = pending.recovery.as_ref().map(|recovery| {
                let mut excluded = recovery.scope.excluded_subtrees();
                excluded.sort_unstable();
                (
                    recovery.scope.root.clone(),
                    recovery.scope.max_depth,
                    excluded,
                    recovery.password_scope.clone(),
                )
            });
            let (_, candidates) = groups
                .entry((pending.root, recovery_key))
                .or_insert_with(|| (pending.recovery, Vec::new()));
            candidates.push(pending.candidate);
        }
        self.persist_candidates(BTreeMap::new(), false)?;
        for ((root, _), (recovery, candidates)) in groups {
            self.start_batch(root, candidates, recovery)?;
        }
        Ok(())
    }

    fn retire_admission(&mut self, id: &str, pending: &Pending) -> io::Result<()> {
        self.hub.retire_seed(id);
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
        let boundary = self.settings.watch.boundary_confirmation_seconds;
        // An outstanding sharing conflict still needs a readiness boundary
        // when the writer never emits another directory event.
        let seconds = if pending.quiet.seconds > 0.0 {
            pending.quiet.seconds.min(boundary)
        } else {
            boundary
        };
        pending.due = quiet::after(now, seconds);
        self.due.insert((pending.due, id.clone()), ());
        self.pending.insert(id, pending);
    }

    fn start_batch(
        &mut self,
        id: String,
        candidates: Vec<WatchCandidateRow>,
        recovery: Option<Arc<Recovery>>,
    ) -> io::Result<()> {
        let Some((root, scope)) = self.roots.get(&id) else {
            return Ok(());
        };
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
        let nested_recovery = recovery.as_ref().is_some_and(|recovery| {
            watch_path_key(&recovery.scope.root) != watch_path_key(&scope.root)
        });
        if !nested_recovery {
            request.output_root = root.output.clone();
        }
        request.max_depth = cli::depth(self.settings.recursive_extract);
        request.deep = root.deep;
        let passwords = self.passwords.snapshot();
        request.password_snapshot = Some(Arc::clone(&passwords));
        if let Some(recovery) = &recovery {
            request.discovery_scope = Some(recovery.scope.clone());
            request.password_scope = (!recovery.password_scope.as_os_str().is_empty())
                .then(|| recovery.password_scope.clone());
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
        let scope = scope.clone();
        let toast = self
            .toast
            .as_ref()
            .map(|toast| toast.register(Arc::clone(&batch_id), self.settings.cli.language));
        let worker_toast = toast.clone();
        let report_path = toast
            .as_ref()
            .and_then(|_| candidates.first())
            .map(|candidate| PathBuf::from(&candidate.path));
        let groups = Arc::new(Mutex::new(HashMap::new()));
        let worker_groups = Arc::clone(&groups);
        let claimed = Arc::new(Mutex::new(ClaimedSources::default()));
        let worker_claimed = Arc::clone(&claimed);
        let worker_cancel = cancel.clone();
        self.journal
            .log(json!({"event":"pipeline_request_started","owner":batch,
            "path":candidates.first().map(|entry| &entry.path),"count":candidates.len()}));
        let thread = thread::Builder::new()
            .name("sunpack-watch-batch".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let observer = WatchObserver {
                    journal,
                    owners,
                    scope,
                    outputs: Mutex::new(outputs),
                    batch: worker_batch,
                    toast: worker_toast,
                    hub: Arc::clone(&hub),
                    groups: worker_groups,
                    claimed: worker_claimed,
                    promoted: Mutex::default(),
                };
                let result = engine.run_with(request, &observer);
                let cancelled = worker_cancel.cancelled();
                if let (Some(toast), Some(path)) = (&observer.toast, report_path) {
                    let cleanup = output_cleanup_error(&result);
                    toast.record(
                        cleanup.map_or(path.as_path(), |error| error.path.as_path()),
                        &result,
                        cancelled && cleanup.is_none(),
                    );
                }
                let promoted = std::mem::take(&mut *observer.promoted.lock().unwrap());
                hub.update(|signals| signals.completed.push(send_batch));
                Completed {
                    cancelled,
                    result,
                    promoted,
                }
            })?;
        for (index, candidate) in candidates.iter().enumerate() {
            self.active_paths.insert(
                watch_path_key(&candidate.path),
                (Arc::clone(&batch_id), index),
            );
        }
        self.active.insert(
            batch,
            Active {
                root: id,
                recovery,
                passwords,
                inputs: candidates,
                touched: HashSet::new(),
                cancel,
                groups,
                claimed,
                toast,
                thread,
            },
        );
        Ok(())
    }

    fn cancel_display_batch(&mut self, id: &str) -> bool {
        if matches!(id.as_bytes().first(), Some(b'8'..=b'9' | b'a'..=b'f')) {
            let requests = self
                .toast
                .as_ref()
                .map(|toast| toast.stop_group(id))
                .unwrap_or_default();
            // Keep each request's existing durable boundary. An arbitrarily
            // large display group must not become a single WAL record.
            let mut stopped = false;
            for request in requests {
                stopped |= self.cancel_batch(&request);
            }
            stopped
        } else {
            self.cancel_batch(id)
        }
    }

    fn cancel_batch(&mut self, batch: &str) -> bool {
        let Some(active) = self.active.get(batch) else {
            return false;
        };
        if active.thread.is_finished() || active.cancel.cancelled() {
            return false;
        }
        let mut claimed = active.claimed.lock().unwrap();
        claimed.cancelled = true;
        let inputs: HashSet<_> = active.inputs.iter().map(|input| watch_path_key(&input.path)).collect();
        let siblings = claimed.candidates.iter()
            .filter(|(path, _)| !inputs.contains(*path))
            .filter_map(|(_, candidate)| candidate.as_ref());
        let mut interrupted = crate::watch_store::NativeWatchOperations::empty();
        for input in active.inputs.iter().chain(siblings) {
            if NativePresence::at(&input.path).is_absent() {
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
                    self.hub.retire_seed(&id);
                    self.due.remove(&(pending.due, id.clone()));
                    self.unpublished.remove(&id);
                }
            }
        }
        if let Err(error) = self.journal.commit(true, |_| Ok(interrupted)) {
            self.journal.log(json!({"event":"watch_cancel_persistence_failed","owner":batch,"error":error.to_string()}));
        }
        // Stop the workers even when the state volume failed the durable write.
        active.cancel.cancel();
        true
    }

    fn complete(&mut self, batch: &str) -> io::Result<()> {
        let Some(active) = self.active.remove(batch) else {
            return Ok(());
        };
        let mut completed = active
            .thread
            .join()
            .map_err(|_| io::Error::other("Watch extraction thread failed"))?;
        completed.cancelled |= active.cancel.cancelled();
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
                }
            }
        }
        if let Some(toast) = &active.toast {
            toast.finish(
                &completed.result,
                completed.cancelled,
                !unfinished.is_empty() || output_cleanup_error(&completed.result).is_some(),
            );
        }
        let groups = std::mem::take(&mut *active.groups.lock().unwrap());
        {
            let mut claims = self.hub.claims.lock().unwrap();
            for path in groups.keys().chain(completed.promoted.keys()) {
                if claims
                    .get(path)
                    .is_some_and(|owner| owner.as_ref() == batch)
                {
                    claims.remove(path);
                }
            }
            crate::collections::trim_map(&mut claims);
        }
        for candidate in &active.inputs {
            let id = watch_path_key(&candidate.path);
            self.active_paths.remove(&id);
            self.hub.retire_seed(&id);
        }
        let outcome = match completed.result {
            Ok(outcome) => outcome,
            Err(error) if completed.cancelled => {
                self.journal.log(json!({"event":"pipeline_request_interrupted","owner":batch,"error":error.to_string()}));
                self.release_display_claims(batch, &groups);
                self.arm_idle_cleanup();
                return Ok(());
            }
            Err(error) => {
                let mut absent = crate::watch_store::NativeWatchOperations::empty();
                let mut failed = false;
                for candidate in &active.inputs {
                    let id = watch_path_key(&candidate.path);
                    if self.pending.contains_key(&id) || active.touched.contains(&id) {
                        continue;
                    }
                    if NativePresence::at(&candidate.path).is_absent() {
                        absent.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                            &candidate.path,
                            None,
                        ));
                        continue;
                    }
                    failed = true;
                    self.journal
                        .log(json!({"event":"failed_terminal","path":candidate.path,
                        "owner":batch,"error":error.to_string()}));
                }
                self.failed += usize::from(failed);
                self.journal.commit(true, |_| Ok(absent))?;
                self.release_display_claims(batch, &groups);
                self.arm_idle_cleanup();
                return Ok(());
            }
        };
        let mut by_path: HashMap<String, Vec<&ArchiveResult>> = HashMap::new();
        for archive in &outcome.archives {
            if let Some(failure) = archive
                .failure
                .as_ref()
                .filter(|failure| failure.evidence.is_some())
            {
                // Emit once per logical archive, including carrier segments and
                // recursive children, rather than repeating it for every volume.
                self.journal.log(
                    json!({"event":"archive_failure_evidence","path":archive.path,
                    "owner":batch,"depth":archive.depth,"offset":archive.offset,"failure":failure}),
                );
            }
            for input in &archive.source_paths {
                by_path.entry(key(input)).or_default().push(archive);
            }
            by_path.entry(key(&archive.path)).or_default().push(archive);
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
        let error_paths = outcome
            .errors
            .iter()
            .filter(|error| error.kind != crate::pipeline::InputErrorKind::Cleanup)
            .map(|error| (key(&error.path), &error.message))
            .collect::<HashMap<_, _>>();
        let mut operations = crate::watch_store::NativeWatchOperations::empty();
        let current_passwords = self.passwords.snapshot();
        let mut retry = Vec::new();
        let mut published = HashSet::new();
        for archive in outcome
            .archives
            .iter()
            .filter(|archive| archive.promoted && !archive.partial)
        {
            let Some(failure) = &archive.failure else {
                continue;
            };
            let id = key(&archive.path);
            let Some(candidate) = completed.promoted.remove(&id).flatten() else {
                continue;
            };
            if self.active_paths.contains_key(&id) {
                continue;
            }
            let regroup = failure.kind == FailureKind::MissingVolume;
            if let Some(pending) = self.pending.get(&id) {
                if quiet::changed(&candidate, &pending.candidate) {
                    continue;
                }
                if !regroup {
                    let pending = self.pending.remove(&id).unwrap();
                    self.hub.retire_seed(&id);
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
            let mut entry = make_entry(
                &candidate,
                &failure.message,
                Some(failure.kind),
                self.journal.state().entry(&candidate.path).as_deref(),
                &active.passwords,
                Some(&group),
                active.recovery.as_deref(),
            );
            let directory = active.recovery.as_ref().map_or_else(
                || archive.path.parent().unwrap_or(Path::new("")),
                |recovery| recovery.password_dir(&archive.path),
            );
            let payload = &mut Arc::make_mut(&mut entry).failure_payload;
            if let Some((_, scope)) = self.roots.get(&active.root) {
                payload.insert("source_input_root".into(), json!(scope.root));
            }
            let password_updated = payload
                .get("password_signature")
                .and_then(Value::as_str)
                .is_some_and(|previous| previous != current_passwords.scope_signature(directory));
            if regroup && self.pending.contains_key(&id) {
                // Other promoted volumes may already have arrived before this
                // blocker was published. Keep the durable queued generation.
                operations.put_entry(entry);
            } else {
                operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                    &candidate.path,
                    Some(entry),
                ));
            }
            if (regroup && !self.pending.contains_key(&id)) || password_updated {
                retry.push(candidate.path.clone());
            }
            for checkpoint in &outcome.checkpoints {
                if checkpoint.source_paths().any(|source| {
                    archive
                        .source_paths
                        .iter()
                        .any(|path| key(path) == key(source))
                }) {
                    operations.extend(crate::watch_store::NativeWatchOperations::checkpoint(
                        &candidate.path,
                        &checkpoint.output().to_string_lossy(),
                        Some(serde_json::to_value(checkpoint)?),
                    ));
                }
            }
            // Count an unresolved volume failure when the top-level regroup
            // finishes. A successful regroup can satisfy this initial result.
            self.failed += usize::from(!regroup);
        }
        for candidate in active.inputs {
            let id = watch_path_key(&candidate.path);
            if self.pending.contains_key(&id)
                || active.touched.contains(&id)
                || unfinished.contains(&id)
            {
                continue;
            }
            let group = groups.get(&id);
            let canonical = group.map_or(candidate.path.as_str(), |group| {
                group.path.to_str().unwrap_or(&candidate.path)
            });
            let archives = by_path
                .get(&id)
                .or_else(|| by_path.get(&watch_path_key(canonical)));
            let failure = archives.and_then(|items| {
                items
                    .iter()
                    .find_map(|item| (!item.partial).then_some(item.failure.as_ref()).flatten())
            });
            let error = error_paths
                .get(&id)
                .map(|error| error.as_str())
                .or_else(|| failure.map(|failure| failure.message.as_str()));
            let retryable = failure.is_some_and(|failure| {
                matches!(
                    failure.kind,
                    FailureKind::MissingVolume
                        | FailureKind::PasswordRequired
                        | FailureKind::WrongPassword
                        | FailureKind::PasswordInconclusive
                )
            });
            let stale = error.is_some()
                && (NativePresence::at(canonical).is_absent()
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
            let record = if completed.cancelled {
                // Only the cancelled generation is retired. A generation
                // queued while the batch was in flight is left in the WAL.
                self.journal
                    .state()
                    .entry(&candidate.path)
                    .filter(|entry| entry.status == "interrupted")
            } else {
                error.map(|error| {
                    let mut entry = make_entry(
                        &candidate,
                        error,
                        failure.map(|failure| failure.kind),
                        self.journal.state().entry(&candidate.path).as_deref(),
                        &active.passwords,
                        group.map(Arc::as_ref),
                        active.recovery.as_deref(),
                    );
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
                let path = Path::new(&candidate.path);
                let directory = active.recovery.as_ref().map_or_else(
                    || path.parent().unwrap_or(Path::new("")),
                    |recovery| recovery.password_dir(path),
                );
                if record
                    .failure_payload
                    .get("password_signature")
                    .and_then(Value::as_str)
                    .is_some_and(|before| before != current_passwords.scope_signature(directory))
                {
                    retry.push(candidate.path.clone());
                }
            }
            let event = if completed.cancelled {
                "pipeline_request_interrupted"
            } else if let Some(record) = &record {
                self.failed += 1;
                record.status.as_str()
            } else if archives.is_some() {
                "done"
            } else {
                "no_tasks_found"
            };
            if published.insert(watch_path_key(canonical)) {
                let outputs = archives
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.output.as_deref())
                    .collect::<HashSet<_>>();
                self.journal
                    .log(json!({"event":event,"path":canonical,"owner":batch,
                    "error":error,"output_dirs":outputs,"retire_group":true}));
            }
            operations.extend(crate::watch_store::NativeWatchOperations::finish_pending(
                &candidate.path,
                record.filter(|entry| entry.status != "failed_terminal"),
            ));
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
        for path in retry {
            self.enqueue_with_recovery(&active.root, path, true, active.recovery.clone())?;
        }
        self.persist_candidates(BTreeMap::new(), false)?;
        self.arm_idle_cleanup();
        Ok(())
    }

    fn arm_idle_cleanup(&mut self) {
        if self.active.is_empty() && self.pending.is_empty() && !windows::foreground_active() {
            let idle = self.settings.watch.runtime_cache_cleanup_idle_seconds;
            self.cache_deadline = (idle > 0.0).then(|| quiet::after(Instant::now(), idle));
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

fn make_entry(
    candidate: &WatchCandidateRow,
    error: &str,
    kind: Option<FailureKind>,
    previous: Option<&crate::watch_store::EntryRecord>,
    passwords: &crate::core::passwords::PasswordSnapshot,
    group: Option<&SourceGroup>,
    recovery: Option<&Recovery>,
) -> Arc<crate::watch_store::EntryRecord> {
    let (status, blockers) = match kind {
        Some(
            FailureKind::PasswordRequired
            | FailureKind::WrongPassword
            | FailureKind::PasswordInconclusive,
        ) => ("failed_password", vec!["password"]),
        Some(FailureKind::MissingVolume) => ("suspended_missing_volume", vec!["missing_volume"]),
        _ => ("failed_terminal", Vec::new()),
    };
    let mut payload = json!({"blockers":blockers});
    if let Some(group) = group {
        payload["source_group"] = json!(group);
    }
    if let Some(recovery) = recovery {
        payload["discovery_scope"] = Value::Object(scope_record(&recovery.scope));
        payload["password_scope_dir"] = json!(recovery.password_scope);
    }
    if status == "failed_password" {
        let path = Path::new(&candidate.path);
        let dir = recovery.map_or_else(
            || path.parent().unwrap_or(Path::new("")),
            |recovery| recovery.password_dir(path),
        );
        payload["password_scope_dir"] = json!(dir);
        payload["password_signature"] = json!(passwords.scope_signature(dir));
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

struct WatchObserver {
    journal: Arc<journal::Journal>,
    owners: HashMap<String, String>,
    scope: NativeDiscoveryScope,
    outputs: Mutex<BTreeMap<String, String>>,
    batch: Arc<str>,
    toast: Option<super::toast::Activity>,
    hub: Arc<Hub>,
    groups: Arc<Mutex<HashMap<String, Arc<SourceGroup>>>>,
    claimed: Arc<Mutex<ClaimedSources>>,
    promoted: Mutex<HashMap<String, Option<WatchCandidateRow>>>,
}

impl WatchObserver {
    fn owner<'a>(&'a self, archive: &'a ArchiveResult) -> Option<String> {
        archive
            .source_paths
            .iter()
            .chain(std::iter::once(&archive.path))
            .find_map(|path| self.owners.get(&key(path)).cloned())
            .or_else(|| self.owner_for_path(&archive.path))
    }

    fn owner_for_path(&self, path: &Path) -> Option<String> {
        let path = key(path);
        self.outputs
            .lock()
            .unwrap()
            .iter()
            .filter(|(output, _)| path == **output || is_path_under(&path, output))
            .max_by_key(|(path, _)| path.len())
            .map(|(_, owner)| owner.clone())
    }
}

impl Observer for WatchObserver {
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

    fn should_process_sources(
        &self,
        _path: &Path,
        data_paths: &[&str],
        generations: &SourceGenerations,
    ) -> io::Result<bool> {
        if data_paths.len() < 2 {
            return Ok(true);
        }
        let paths = data_paths
            .iter()
            .map(|path| watch_path_key(path))
            .collect::<HashSet<_>>();
        let seeds = self.hub.seeds.lock().unwrap();
        let covered = paths
            .iter()
            .filter_map(|path| seeds.get(path).and_then(|seed| seed.processed.as_deref()))
            .any(|processed| {
                processed.len() == paths.len()
                    && paths.iter().all(|path| {
                        processed
                            .get(path)
                            .is_some_and(|previous| generations.get(path) == Some(previous))
                    })
            });
        Ok(!covered)
    }

    fn sources_processed(
        &self,
        archives: &[ArchiveResult],
        generations: &SourceGenerations,
    ) -> io::Result<()> {
        if generations.len() < 2 {
            return Ok(());
        }
        let processed = archives
            .iter()
            .flat_map(|archive| &archive.source_paths)
            .filter_map(|source| {
                let path = key(source);
                generations
                    .get(&path)
                    .map(|generation| (path, generation.clone()))
            })
            .collect::<SourceGenerations>();
        if processed.len() < 2 {
            return Ok(());
        }
        let processed = Arc::new(processed);
        let mut seeds = self.hub.seeds.lock().unwrap();
        for path in processed.keys() {
            if let Some(seed) = seeds.get_mut(path) {
                seed.processed = Some(Arc::clone(&processed));
            }
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

    fn checkpoint(&self, checkpoint: &crate::pipeline::InputCheckpoint) -> io::Result<()> {
        let Some(owner) = self.owner_for_path(checkpoint.entry()) else {
            return Ok(());
        };
        self.journal.commit(true, |_| {
            Ok(crate::watch_store::NativeWatchOperations::checkpoint(
                &owner,
                &checkpoint.output().to_string_lossy(),
                Some(serde_json::to_value(checkpoint)?),
            ))
        })
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
            let mut claims = self.hub.claims.lock().unwrap();
            for member in &group.members {
                let key = watch_path_key(member);
                aliases.insert(key.clone(), Arc::clone(&group));
                claims.insert(key, Arc::clone(&self.batch));
            }
        }
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
            let owned =
                if self.scope.intersects_output(&output) && state.owned_root(&output).is_none() {
                    vec![output.clone()]
                } else {
                    // Physical output directories still require an exclusive
                    // reservation when a parent is already excluded from Watch.
                    crate::scan::scope::create_output_root_exclusive(path)
                        .map_err(crate::pipeline::OutputCreateError::wrap)?;
                    Vec::new()
                };
            state
                .output_operation(&owner, task, output, None, owned)?
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
                    Vec::new(),
                )?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty))
        })
    }

    fn commit_output(
        &self,
        archive: &ArchiveResult,
        checkpoint: Option<&crate::pipeline::InputCheckpoint>,
    ) -> io::Result<()> {
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
            let mut operations = state
                .output_operation(
                    &owner,
                    task,
                    output.clone(),
                    Some(archive.failure.is_none() || archive.partial),
                    Vec::new(),
                )?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty);
            if let Some(checkpoint) = checkpoint {
                operations.extend(crate::watch_store::NativeWatchOperations::checkpoint(
                    &owner,
                    &output,
                    Some(serde_json::to_value(checkpoint)?),
                ));
            }
            Ok(operations)
        })
    }

    fn discard_output(&self, archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Ok(());
        };
        let task = archive.path.to_string_lossy().into_owned();
        let output = output.to_string_lossy().into_owned();
        self.journal.commit(true, |state| {
            let mut operations = state
                .output_operation(&owner, task, output.clone(), Some(false), Vec::new())?
                .unwrap_or_else(crate::watch_store::NativeWatchOperations::empty);
            operations.extend(crate::watch_store::NativeWatchOperations::checkpoint(
                &owner, &output, None,
            ));
            Ok(operations)
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
    let old = output_identity(&root.to_string_lossy())?;
    let new = output_identity(&leaf.to_string_lossy())?;
    let wrapper = (!owner.is_empty())
        .then(|| crate::io::reader::capture_directory_identity(root))
        .transpose()?;
    let mut operations = vec![
        json!({"op":"runtime","key":format!("flatten|{}",key(root)),
            "value":{"owner":owner,"root":root,"work":work,"leaf":leaf,"old_identity":old,"new_identity":new,
                "checkpoint_wrapper_identity":wrapper}}),
        json!({"op":"runtime","key":format!("owned|{}",key(root)),
            "value":{"path":root,"identities":[old,new]}}),
        json!({"op":"runtime","key":format!("owned|{}",key(work)),
            "value":{"path":work,"identities":[old]}}),
    ];
    if !owner.is_empty() {
        operations.push(json!({"op":"checkpoint_output","owner":owner,"output":root}));
    }
    journal.commit(true, |state| state.decode_operations(&operations))
}

fn finish_flatten(journal: &journal::Journal, root: &str) -> io::Result<()> {
    let record_key = format!("flatten|{}", watch_path_key(root));
    let Some(record) = journal.state().runtime_record(&record_key) else {
        return Ok(());
    };
    let (Some(work), Some(leaf)) = (record["work"].as_str(), record["leaf"].as_str()) else {
        return Ok(());
    };
    let current = output_identity(root)?;
    let work_exists = Path::new(work).try_exists()?;
    let published = record["new_identity"].as_str() == Some(&current);
    if !published && (work_exists || record["old_identity"].as_str() != Some(&current)) {
        return Ok(());
    }
    let already_rebased = record["outputs_rebased"].as_bool() == Some(true);
    if work_exists && already_rebased {
        return Ok(());
    }
    let mut operations = vec![
        json!({"op":"runtime","key":format!("owned|{}",watch_path_key(root)),
        "value":{"path":root,"identities":[current]}}),
    ];
    if !work_exists {
        operations.extend([
            json!({"op":"runtime","key":record_key}),
            json!({"op":"runtime","key":format!("owned|{}",watch_path_key(work))}),
        ]);
    } else {
        let mut next = record.clone();
        next["outputs_rebased"] = Value::Bool(true);
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
    journal.commit(true, |state| {
        use crate::watch_store::NativeWatchOperations;
        let mut operations = state.decode_operations(&operations)?;
        if let Some(owner) = owner {
            let mut checkpoints = input_checkpoints(state, owner).peekable();
            if checkpoints.peek().is_some() {
                let root = Path::new(root);
                let identity = crate::io::reader::capture_directory_identity(root)?;
                let wrapper =
                    serde_json::from_value(record["checkpoint_wrapper_identity"].clone()).ok();
                let mut moved = Vec::new();
                for checkpoint in checkpoints {
                    let mut checkpoint = checkpoint?;
                    let before = checkpoint.output().to_string_lossy().into_owned();
                    if checkpoint.rebase_flatten(
                        root,
                        Path::new(work),
                        Path::new(leaf),
                        wrapper.as_ref(),
                        &identity,
                    ) {
                        let after = checkpoint.output().to_string_lossy();
                        if watch_path_key(&before) != watch_path_key(&after) {
                            operations
                                .extend(NativeWatchOperations::checkpoint(owner, &before, None));
                        }
                        moved.push(NativeWatchOperations::checkpoint(
                            owner,
                            &after,
                            Some(serde_json::to_value(&checkpoint)?),
                        ));
                    }
                }
                // Retire old aliases before publishing any new receipt keys.
                for checkpoint in moved {
                    operations.extend(checkpoint);
                }
            }
        }
        Ok(operations)
    })
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
        outputs.insert(key(checkpoint.output()), owner.to_owned());
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

fn input_checkpoints<'a>(
    state: &'a crate::watch_store::NativeWatchState,
    owner: &str,
) -> impl Iterator<Item = io::Result<crate::pipeline::InputCheckpoint>> + 'a {
    let prefix = format!("checkpoint|{}\0", watch_path_key(owner));
    state
        .runtime_keys(&prefix)
        .into_iter()
        .filter_map(|key| state.runtime_record(&key))
        .map(|record| serde_json::from_value(record).map_err(io::Error::other))
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
            finish_flatten(journal, root)?;
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
            Some(Path::new(work)),
            |_, _, _| Ok(()),
            Some(Path::new(leaf)),
        );
        if identity_if_present(root).is_ok_and(|identity| identity.as_deref() == Some(new)) {
            finish_flatten(journal, root)?;
        }
    }
    Ok(())
}

fn identity_if_present(path: &str) -> io::Result<Option<String>> {
    match output_identity(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::reader::{capture_directory_identity, capture_file_generation};
    use crate::watch_store::{NativeWatchOperations, PendingObservation};

    #[test]
    fn stopping_watch_allows_worker_foreground_callbacks() {
        let watch = Arc::new(Watch::new(Arc::new(|| {})));
        let hub = Arc::new(Hub::new());
        let worker_hub = Arc::clone(&hub);
        let worker_watch = Arc::clone(&watch);
        let worker = thread::spawn(move || {
            worker_hub.wait(None);
            worker_watch.foreground_finished();
            Ok(())
        });
        *watch.running.lock().unwrap() = Some(Running { hub, thread: worker });
        let (send, receive) = mpsc::channel();
        let stop = thread::spawn(move || {
            let _ = send.send(watch.stop());
        });
        receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();
        stop.join().unwrap();
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
            let journal = journal::Journal::open(&directory).unwrap();
            journal.commit(true, |state| {
                state.pending_operations(
                    [(PendingObservation(owner.to_owned(), 13, 1.0, String::new(), 0),
                        String::new(), None)],
                    false, "", false, true, None,
                ).map(|(operations, _)| operations)
            }).unwrap();
            journal.commit(true, |state| {
                Ok(state.output_operation(owner, owner.to_owned(),
                    container.to_str().unwrap().to_owned(), None, Vec::new())?.unwrap())
            }).unwrap();
            journal.commit(true, |state| {
                let mut operations = state.output_operation(owner, owner.to_owned(),
                    container.to_str().unwrap().to_owned(), Some(true), Vec::new())?.unwrap();
                operations.extend(NativeWatchOperations::checkpoint(owner, output.to_str().unwrap(), Some(json!({
                    "schema_version":1,"carrier":source,
                    "input":{"entry":source,"mode":"file","format":"zip","parts":[],"ranges":[]},
                    "sources":[{"path":source,"generation":capture_file_generation(&source)?.persisted()}],
                    "output":{"path":output,"identity":capture_directory_identity(&output)?},
                    "container":{"path":container,"identity":capture_directory_identity(&container)?},
                    "files":1,"bytes":9,"encrypted":false,"discovery_source":"direct",
                    "children_complete":false,"remaining_depth":2,
                }))));
                Ok(operations)
            }).unwrap();
            journal.flush().unwrap();
        }
        {
            let journal = Arc::new(journal::Journal::open(&directory).unwrap());
            let mut outputs = BTreeMap::new();
            let checkpoints = restore_checkpoints(journal.state(), owner, &mut outputs).unwrap();
            assert_eq!(checkpoints.len(), 1);
            let observer = WatchObserver {
                journal: Arc::clone(&journal),
                owners: HashMap::from([(key(&source), owner.to_owned())]),
                scope: NativeDiscoveryScope::new(directory.to_string_lossy().into_owned(), None, Vec::new()),
                outputs: Mutex::new(outputs),
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
                promoted: false, promotion_original_path: None,
            };
            observer.register_output(&archive, &nested_output).unwrap();
            assert!(nested_output.is_dir());
            assert_eq!(observer.owner_for_path(&nested_output).as_deref(), Some(owner));
            assert!(journal.state().pending(owner).unwrap().active_outputs
                .values().any(|path| key(Path::new(path)) == key(&nested_output)));
        }
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn flatten_recovery_rebases_durable_parent_and_nested_receipts() {
        let owner_file = crate::test_support::temp_file("flatten_watch_owner", b"outer archive");
        let directory = owner_file.with_extension("state");
        let root = directory.join("output");
        let work = directory.join("work");
        let leaf = root.join("wrapper").join("inner");
        let work_leaf = work.join("wrapper").join("inner");
        let nested = work_leaf.join("nested.zip");
        let nested_output = work_leaf.join("nested");
        let owner = owner_file.to_str().unwrap();
        let root_text = root.to_str().unwrap();
        fs::create_dir_all(&leaf).unwrap();
        fs::write(leaf.join("nested.zip"), b"inner archive").unwrap();
        fs::create_dir(leaf.join("nested")).unwrap();
        fs::write(leaf.join("nested/payload"), b"extracted").unwrap();

        {
            let journal = journal::Journal::open(&directory).unwrap();
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
                            Vec::new(),
                        )?
                        .unwrap())
                })
                .unwrap();
            prepare_flatten(&journal, owner, &root, &work, &leaf).unwrap();
            fs::rename(&root, &work).unwrap();
            // Simulate a collision after the first rename. The task can finish
            // with a committed output and durable receipts at the work path.
            journal.commit(true, |state| {
                let mut operations = state.output_operation(
                    owner, owner.to_owned(), work.to_str().unwrap().to_owned(), Some(true), Vec::new(),
                )?.unwrap();
                for (source, output) in [(&owner_file, &work), (&nested, &nested_output)] {
                    let value = json!({
                        "schema_version":1,"carrier":source,
                        "input":{"entry":source,"mode":"file","format":"zip","parts":[],"ranges":[]},
                        "sources":[{"path":source,"generation":capture_file_generation(source)?.persisted()}],
                        "output":{"path":output,"identity":capture_directory_identity(output)?},
                        "container":{"path":work,"identity":capture_directory_identity(&work)?},
                        "files":1,"bytes":9,"encrypted":false,"discovery_source":"direct",
                        "children_complete":true,"remaining_depth":1,
                    });
                    operations.extend(NativeWatchOperations::checkpoint(
                        owner, output.to_str().unwrap(), Some(value),
                    ));
                }
                Ok(operations)
            }).unwrap();
            journal.flush().unwrap();
        }

        {
            let journal = journal::Journal::open(&directory).unwrap();
            recover_flattens(&journal, |_| true).unwrap();
            assert_eq!(fs::read(root.join("nested/payload")).unwrap(), b"extracted");
            assert!(!work.exists());
            assert!(journal.state().runtime_keys("flatten|").is_empty());
            let pending = journal.state().pending(owner).unwrap();
            assert_eq!(
                pending
                    .committed_roots
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                [root_text]
            );
            assert!(recovery_output_matches(journal.state(), &pending, root_text).unwrap());
            let checkpoints = input_checkpoints(journal.state(), owner)
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(checkpoints.len(), 2);
            assert!(checkpoints
                .iter()
                .any(|checkpoint| checkpoint.entry() == owner_file && checkpoint.output() == root));
            assert!(checkpoints
                .iter()
                .any(|checkpoint| checkpoint.entry() == root.join("nested.zip")
                    && checkpoint.output() == root.join("nested")));
            let identity =
                serde_json::to_value(capture_directory_identity(&root).unwrap()).unwrap();
            for checkpoint in checkpoints {
                let receipt = serde_json::to_value(checkpoint).unwrap();
                assert_eq!(receipt["container"]["identity"], identity);
            }
        }
        fs::remove_dir_all(directory).unwrap();
        fs::remove_file(owner_file).unwrap();
    }
}
