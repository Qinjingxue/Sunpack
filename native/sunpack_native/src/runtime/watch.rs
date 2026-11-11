use super::{cli, windows};
use crate::core::config::{self, Config, Snapshot};
use crate::core::passwords::BuiltinStore;
use crate::core::resources::{self, FileMutex};
use crate::filesystem;
use crate::io::config_changes::NativeConfigChanges;
use crate::io::reader::PhysicalFileGeneration;
use crate::pipeline::{
    ArchiveResult, Cancellation, Engine, Event, FailureKind, Mode, Observer, Origin, Outcome,
    PromotedSource, Request,
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
            .map(|output| cli::resolve(&input, output))
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
        let mut slot = self.running.lock().unwrap();
        let generation = self.generation.load(Ordering::Relaxed);
        let Some(running) = slot.take() else {
            return Ok(json!({"running":false,"stopped":false,"generation":generation}));
        };
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
        let slot = self.running.lock().unwrap();
        if let Some(run) = slot.as_ref().filter(|run| !run.thread.is_finished()) {
            let hub = Arc::clone(&run.hub);
            drop(slot);
            let (send, receive) = mpsc::sync_channel(1);
            hub.update(|signals| signals.once.push(send));
            receive.recv().map_err(io::Error::other)??;
            return Ok(0);
        }
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
                    output: output.map(|value| cli::resolve(root, value)).transpose()?,
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
        crate::scan::scope::create_output_root_exclusive(path)?;
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
    changed_roots: HashSet<String>,
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
    claims: Mutex<HashMap<String, String>>,
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

struct Pending {
    root: String,
    candidate: WatchCandidateRow,
    quiet: quiet::Quiet,
    due: Instant,
    force: bool,
}

struct Active {
    root: String,
    passwords: Arc<crate::core::passwords::PasswordSnapshot>,
    inputs: Vec<WatchCandidateRow>,
    touched: HashSet<String>,
    cancel: Cancellation,
    groups: Arc<Mutex<HashMap<String, Arc<SourceGroup>>>>,
    thread: JoinHandle<Completed>,
}

struct Completed {
    cancelled: bool,
    result: io::Result<Outcome>,
    promoted: HashMap<String, WatchCandidateRow>,
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
    settings: Arc<Config>,
    engine: Arc<Engine>,
    journal: Arc<journal::Journal>,
    catalog: Arc<NativeWatchCatalog>,
    options: NativeDirectoryScanOptions,
    deep_options: NativeDirectoryScanOptions,
    passwords: Arc<BuiltinStore>,
    hub: Arc<Hub>,
    root_observers: HashMap<String, FileObserver>,
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
        let config_observers = Self::observe_config(&snapshot, &root_file, passwords.path(), &hub);
        let mut scheduler = Self {
            cwd,
            root_file,
            roots: BTreeMap::new(),
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
        scheduler.reconcile_shell();
        windows::configure_priority(&scheduler.engine, scheduler.settings.runtime.process_mode);
        scheduler.recover_pending()?;
        scheduler.password_update()?;
        scheduler.checkpoint(None, true)?;
        scheduler.retry_missing_volumes()?;
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
        snapshot: &Snapshot,
        roots: &Path,
        passwords: &Path,
        hub: &Arc<Hub>,
    ) -> Vec<FileObserver> {
        let mut targets: HashMap<PathBuf, HashMap<String, bool>> = HashMap::new();
        for path in snapshot
            .sources
            .simple
            .iter()
            .chain(snapshot.sources.advanced.iter())
            .chain(snapshot.sources.override_file.iter())
            .map(PathBuf::as_path)
            .chain([roots, passwords])
        {
            let Some(parent) = path.parent().and_then(nearest_directory) else {
                continue;
            };
            let Some(name) = path
                .strip_prefix(parent)
                .ok()
                .and_then(|path| path.components().next())
            else {
                continue;
            };
            targets.entry(parent.to_owned()).or_default().insert(
                name.as_os_str().to_string_lossy().to_lowercase(),
                path == passwords,
            );
        }
        targets
            .into_iter()
            .filter_map(|(dir, files)| {
                let hub = Arc::clone(hub);
                FileObserver::start(&dir, false, move |names| {
                    let mut reload = false;
                    let mut passwords = false;
                    let mut affected = |name: &str| match files.get(&name.to_lowercase()) {
                        Some(true) => passwords = true,
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
                .ok()
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
        let mut next = entries
            .iter()
            .map(|root| (key(&root.path), (root.clone(), root.scope(&entries, &dir))))
            .collect::<BTreeMap<_, _>>();
        let policy_changed = self.roots.len() != next.len()
            || next.iter().any(|(id, (root, _))| {
                self.roots.get(id).is_none_or(|(old, _)| {
                    old.recursive != root.recursive
                        || old.output != root.output
                        || old.deep != root.deep
                })
            });
        for (id, (root, _)) in &mut next {
            if self
                .roots
                .get(id)
                .is_some_and(|(old, _)| old.deep != root.deep)
            {
                root.scanned = false;
            }
        }
        let removed: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| !next.contains_key(&pending.root))
            .map(|(key, _)| key.clone())
            .collect();
        for key in removed {
            if let Some(pending) = self.pending.remove(&key) {
                self.hub.retire_seed(&key);
                self.due.remove(&(pending.due, key.clone()));
                self.unpublished.remove(&key);
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
        self.roots = next;
        self.rearm_root_observers();
        Ok(())
    }

    fn rearm_root_observers(&mut self) {
        self.root_observers.retain(|id, observer| {
            self.roots
                .get(id)
                .and_then(|(root, _)| nearest_directory(&root.path))
                .is_some_and(|path| {
                    path == observer.path && !observer.stopping.load(Ordering::Acquire)
                })
        });
        for (id, (root, scope)) in &self.roots {
            if self.root_observers.contains_key(id) {
                continue;
            }
            let Some(directory) = nearest_directory(&root.path) else {
                continue;
            };
            let recursive = root.recursive && directory == root.path;
            let key = id.clone();
            let filter = (directory == root.path).then(|| scope.clone());
            let directory = directory.to_owned();
            let watched_dir = directory.clone();
            let hub = Arc::clone(&self.hub);
            let observer = FileObserver::start(&directory, recursive, move |names| {
                if let (Some(scope), Some(names)) = (&filter, &names) {
                    if !names
                        .iter()
                        .any(|name| scope.contains(&watched_dir.join(name).to_string_lossy()))
                    {
                        return;
                    }
                }
                hub.update(|signals| {
                    signals.changed_roots.insert(key.clone());
                });
            });
            match observer {
                Ok(observer) => { self.root_observers.insert(id.clone(), observer); }
                Err(error) => self.journal.log(json!({"event":"watch_root_unavailable","root":root.path,"error":error.to_string()})),
            }
        }
    }

    fn reload(&mut self) -> io::Result<()> {
        let snapshot = config::load_snapshot(&self.cwd)?;
        let options = crate::pipeline::scan_options(&snapshot.config)?;
        let config_observers =
            Self::observe_config(&snapshot, &self.root_file, self.passwords.path(), &self.hub);
        self.reconcile_roots()?;
        self.journal
            .set_retention(snapshot.config.watch.event_log_retention_days)?;
        self.settings = Arc::new(snapshot.config);
        windows::configure_priority(&self.engine, self.settings.runtime.process_mode);
        self.options = options;
        self.config_observers = config_observers;
        self.reconcile_shell();
        self.checkpoint(None, false)?;
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
                let _ = waiter.send(self.cancel_batch(&batch));
            }
            for completed in signals.completed {
                self.complete(&completed)?;
            }
            for waiter in signals.rebuild {
                let _ = waiter.send(self.journal.rebuild_log());
            }
            if let Some(clipboard) = signals.clipboard {
                match self.passwords.merge_clipboard(
                    &clipboard,
                    self.settings.watch.clipboard_builtin_max_entries,
                ) {
                    Ok(true) => self.password_update()?,
                    Ok(false) => {}
                    Err(error) => self.journal.log(json!({
                        "event":"watch_clipboard_password_save_failed", "error":error.to_string(),
                    })),
                }
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
                self.rearm_root_observers();
                let changed = (!signals.volumes_changed && signals.once.is_empty())
                    .then_some(&signals.changed_roots);
                let result = self.checkpoint(changed, false).and_then(|_| {
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

    fn checkpoint(&mut self, changed: Option<&HashSet<String>>, startup: bool) -> io::Result<()> {
        let selected = self
            .roots
            .iter()
            .filter(|(id, _)| changed.is_none_or(|changed| changed.contains(*id)))
            .map(|(id, (root, scope))| (id.clone(), root.clone(), scope.clone()))
            .collect::<Vec<_>>();
        let mut groups: HashMap<(String, u64), (i64, i64, Vec<NativeDiscoveryScope>)> =
            HashMap::new();
        let mut probes = Vec::new();
        for (id, root, scope) in selected {
            if !root.path.is_dir() {
                continue;
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
                (Ok((volume, journal, _)), Some((old_volume, old_journal, _)))
                    if volume == old_volume && journal == old_journal =>
                {
                    ranges.get(&(volume.clone(), *journal))
                }
                _ => None,
            };
            let mut paths = Vec::new();
            let mut errors = Vec::new();
            let rebuild = !root.scanned || range.is_none_or(|(_, entries)| entries.is_err());
            if rebuild {
                let scan = if startup && cached.is_none() && root.scanned {
                    self.scan_options(root.deep)
                        .catalog_update(&self.catalog, &scope, None)
                        .map(|errors| (errors, Vec::new()))
                } else {
                    self.scan_options(root.deep)
                        .catalog_refresh(&self.catalog, &scope, None)
                };
                match scan {
                    Ok((failures, entries)) => {
                        errors = failures;
                        paths = entries;
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
            } else if let Some((_, Ok(changes))) = range {
                let mut covered = HashSet::new();
                for path in changes {
                    if !scope.contains(path)
                        || self.catalog.is_owned(path)
                        || has_covered_parent(path, &covered)
                    {
                        continue;
                    }
                    let (failed, mut arrivals) = self.scan_options(root.deep).catalog_refresh(
                        &self.catalog,
                        &scope,
                        Some(path),
                    )?;
                    paths.append(&mut arrivals);
                    errors.extend(failed);
                    covered.insert(watch_path_key(path));
                    if Path::new(path).is_file() {
                        paths.push(path.clone());
                    } else if NativePresence::at(path).is_absent() {
                        self.departed(path)?;
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
                        if root.path == current.path
                            && root.output == current.output
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

    fn departed(&mut self, path: &str) -> io::Result<()> {
        let path_key = watch_path_key(path);
        let removed: Vec<_> = self
            .pending
            .keys()
            .filter(|key| *key == &path_key || is_path_under(key, &path_key))
            .cloned()
            .collect();
        for id in removed {
            if let Some(pending) = self.pending.remove(&id) {
                self.hub.retire_seed(&id);
                self.due.remove(&(pending.due, id.clone()));
                self.unpublished.remove(&id);
                let claimed = self.active_paths.contains_key(&id)
                    || self.hub.claims.lock().unwrap().contains_key(&id);
                if !claimed {
                    self.journal.commit(false, |state| {
                        use crate::watch_store::NativeWatchOperations;
                        let path = &pending.candidate.path;
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
                    })?;
                }
            }
        }
        self.catalog.forget_observation(path, true, true);
        Ok(())
    }

    fn enqueue(&mut self, root_id: &str, path: String, force: bool) -> io::Result<()> {
        let Some((_, scope)) = self.roots.get(root_id) else {
            return Ok(());
        };
        if !scope.contains(&path) || self.catalog.is_owned(&path) {
            return Ok(());
        }
        let id = watch_path_key(&path);
        let previous = self.catalog.observation(&path);
        let blocked = self.journal.state().entry(&path);
        let pending_usn = self
            .pending
            .get(&id)
            .map(|entry| entry.candidate.observation.change_usn);
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
            .or(pending_usn)
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
        if interrupted.is_some_and(|before| !entry_changed(before, &candidate)) {
            return Ok(());
        }
        let unchanged = previous.as_ref().map_or_else(
            || active_candidate.is_some_and(|before| !quiet::changed(before, &candidate)),
            |before| {
                !quiet::content_changed(
                    before.size,
                    before.mtime,
                    &before.file_id(),
                    before.change_usn,
                    &candidate,
                )
            },
        );
        if !force {
            if blocked
                .as_ref()
                .is_some_and(|before| !entry_changed(before, &candidate))
            {
                return Ok(());
            }
            if unchanged {
                if let Some(pending) = self.pending.get_mut(&id) {
                    let boundary = candidate.observation.change_reasons_known
                        && candidate.observation.change_reasons & quiet::CLOSE != 0;
                    if boundary && baseline != Some(candidate.observation.change_usn) {
                        let now = Instant::now();
                        if now < pending.due {
                            self.due.remove(&(pending.due, id.clone()));
                            pending.due = now;
                            self.due.insert((now, id), ());
                        }
                    }
                    pending.candidate = candidate;
                }
                return Ok(());
            }
        }
        let claim = self.hub.claims.lock().unwrap();
        let batch = self
            .active_paths
            .get(&id)
            .map(|(batch, _)| batch.as_ref())
            .or_else(|| claim.get(&id).map(String::as_str));
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
        let boundary = candidate.observation.change_reasons & quiet::CLOSE != 0;
        quiet.observe(windows::monotonic_seconds(), boundary, new_identity, true);
        self.catalog.remember_observation(
            &candidate.path,
            candidate.size,
            candidate.mtime,
            &candidate.observation.file_id,
            candidate.observation.change_usn,
            boundary,
        );
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
        if self.unpublished.is_empty() && cursors.is_empty() {
            return Ok(());
        }
        let keys = std::mem::take(&mut self.unpublished);
        self.journal.commit(durable, |state| {
            use crate::watch_store::PendingObservation;
            let mut ordinary = Vec::new();
            let mut forced = Vec::new();
            for pending in keys.iter().filter_map(|key| self.pending.get(key)) {
                let Some((_, scope)) = self.roots.get(&pending.root) else { continue; };
                let candidate = &pending.candidate;
                let observation = PendingObservation(candidate.path.clone(), candidate.size.min(i64::MAX as u64) as i64,
                    candidate.mtime, candidate.observation.file_id.clone(), candidate.observation.change_usn);
                let metadata = json!({"root":scope.root,"max_depth":scope.max_depth,"excluded_subtrees":scope.excluded_subtrees()});
                let target = if pending.force { &mut forced } else { &mut ordinary };
                target.push((observation, scope.root.clone(), metadata.as_object().cloned()));
            }
            let cursors = (!cursors.is_empty()).then_some(cursors);
            let (mut operations, _) = state.pending_operations(ordinary, false, "", false, true, cursors)?;
            if !forced.is_empty() {
                let (force, _) = state.pending_operations(forced, true, "", false, true, None)?;
                operations.extend(force);
            }
            Ok(operations)
        })?;
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
        let blocked = state.entry_items(Some("password"));
        for entry in blocked {
            let Some((root, _)) = self
                .roots
                .iter()
                .rev()
                .find(|(_, (_, scope))| scope.contains(&entry.path))
            else {
                continue;
            };
            let directory = Path::new(&entry.path).parent().unwrap_or(Path::new(""));
            if entry
                .failure_payload
                .get("password_signature")
                .and_then(Value::as_str)
                .is_some_and(|before| before == snapshot.scope_signature(directory))
            {
                continue;
            }
            let root = root.clone();
            self.enqueue(&root, entry.path.clone(), true)?;
            self.journal
                .log(json!({"event":"retry_password_failure","path":entry.path}));
        }
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

    fn retry_missing_volumes(&mut self) -> io::Result<()> {
        for entry in self.journal.state().entry_items(Some("missing_volume")) {
            let Some((root, _)) = self
                .roots
                .iter()
                .find(|(_, (_, scope))| scope.contains(&entry.path))
            else {
                continue;
            };
            let id = watch_path_key(&entry.path);
            if !self.pending.contains_key(&id) {
                self.enqueue(&root.clone(), entry.path.clone(), true)?;
            }
        }
        self.persist_candidates(BTreeMap::new(), true)
    }

    fn recover_pending(&mut self) -> io::Result<()> {
        recover_flattens(&self.journal)?;
        for pending in self.journal.state().pending_items() {
            let root = self
                .roots
                .iter()
                .find(|(_, (_, scope))| scope.contains(&pending.path))
                .map(|(id, _)| id.clone());
            let Some(root) = root else {
                continue;
            };
            let source = Path::new(&pending.path);
            let source_available = self
                .roots
                .get(&root)
                .is_some_and(|(entry, _)| entry.path.is_dir());
            if !source_available {
                continue;
            }
            let mut revisit = Vec::new();
            let mut cleanup_failed = false;
            for (task, output) in &pending.active_outputs {
                if pending.committed_roots.contains(output) {
                    continue;
                }
                let Some(expected) = pending.output_identities.get(output) else {
                    cleanup_failed = true;
                    continue;
                };
                match output_identity(output) {
                    Ok(identity) if identity == *expected => {
                        if let Err(error) = crate::postprocess::remove_owned_tree(Path::new(output)) {
                            cleanup_failed = true;
                            self.journal.log(json!({"event":"crash_output_cleanup","path":output,"error":error.to_string()}));
                            continue;
                        }
                    }
                    Ok(_) => self.journal.log(json!({"event":"crash_output_identity_changed","owner_path":pending.path,"output_dir":output})),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => {
                        cleanup_failed = true;
                        continue;
                    }
                }
                if Path::new(task).is_file() && !pending.completed_sources.contains(task) {
                    revisit.push(task.clone());
                }
            }
            if cleanup_failed {
                continue;
            }
            let interrupted = self.journal.state().entry(&pending.path).filter(|entry| {
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
            for promoted in pending.promoted_destinations.iter() {
                if Path::new(promoted).is_file() {
                    revisit.push(promoted.clone());
                }
            }
            if !self.checkpoints_for(&pending.path)?.is_empty() && source.is_file() {
                revisit.push(pending.path.clone());
            }
            if pending
                .committed_roots
                .iter()
                .any(|output| !Path::new(output).is_dir())
                || (revisit.is_empty()
                    && pending.committed_roots.iter().next().is_none()
                    && source.is_file())
            {
                revisit.push(pending.path.clone());
            }
            if revisit.is_empty() {
                self.journal.commit(true, |_| {
                    Ok(crate::watch_store::NativeWatchOperations::finish_pending(
                        &pending.path,
                        None,
                    ))
                })?;
            } else {
                for path in revisit {
                    self.enqueue(&root, path, true)?;
                }
            }
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

fn has_covered_parent(path: &str, covered: &HashSet<String>) -> bool {
    let path = watch_path_key(path);
    let mut ancestor = path.as_str();
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
        let mut groups: BTreeMap<String, Vec<WatchCandidateRow>> = BTreeMap::new();
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
                    self.hub.retire_seed(&id);
                    self.departed(&pending.candidate.path)?;
                    self.journal.commit(false, |_| {
                        Ok(crate::watch_store::NativeWatchOperations::finish_pending(
                            &pending.candidate.path,
                            None,
                        ))
                    })?;
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.hub.retire_seed(&id);
                    self.journal.commit(false, |_| {
                        Ok(crate::watch_store::NativeWatchOperations::finish_pending(
                            &pending.candidate.path,
                            None,
                        ))
                    })?;
                    continue;
                }
                Err(_) => {
                    self.delay(id, pending, now);
                    continue;
                }
            };
            if quiet::changed(&pending.candidate, &current) {
                let boundary = current.observation.change_reasons & quiet::CLOSE != 0;
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
            pending.candidate = current;
            match filesystem::watch_file_is_ready(&pending.candidate.path) {
                Ok(true) => {}
                Ok(false) => {
                    self.delay(id, pending, now);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.hub.retire_seed(&id);
                    self.journal.commit(false, |_| {
                        Ok(crate::watch_store::NativeWatchOperations::finish_pending(
                            &pending.candidate.path,
                            None,
                        ))
                    })?;
                    continue;
                }
                Err(_) => {
                    self.delay(id, pending, now);
                    continue;
                }
            }
            self.catalog.retire_observation(
                &pending.candidate.path,
                Some(pending.quiet.seconds),
                pending.quiet.last,
                pending.quiet.cadence,
                pending.quiet.tentative,
            );
            groups
                .entry(pending.root)
                .or_default()
                .push(pending.candidate);
        }
        self.persist_candidates(BTreeMap::new(), false)?;
        for (root, candidates) in groups {
            self.start_batch(root, candidates)?;
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

    fn start_batch(&mut self, id: String, candidates: Vec<WatchCandidateRow>) -> io::Result<()> {
        let Some((root, scope)) = self.roots.get(&id) else {
            return Ok(());
        };
        let batch = windows::random_bytes::<16>()?
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
        request.output_root = root.output.clone();
        request.max_depth = cli::depth(self.settings.recursive_extract);
        request.deep = root.deep;
        let passwords = self.passwords.snapshot();
        request.password_snapshot = Some(Arc::clone(&passwords));
        request.discovery_scope = Some(scope.clone());
        request.watch_catalog = Some(Arc::clone(&self.catalog));
        for candidate in &candidates {
            request
                .checkpoints
                .extend(self.checkpoints_for(&candidate.path)?);
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
        let owners = candidates
            .iter()
            .map(|input| (watch_path_key(&input.path), input.path.clone()))
            .collect();
        let scope = scope.clone();
        let toast = self.toast.as_ref().map(|toast| toast.publisher());
        let language = self.settings.cli.language;
        let groups = Arc::new(Mutex::new(HashMap::new()));
        let worker_groups = Arc::clone(&groups);
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
                    outputs: Mutex::default(),
                    batch: send_batch.clone(),
                    toast,
                    language,
                    began: Instant::now(),
                    hub: Arc::clone(&hub),
                    groups: worker_groups,
                    promoted: Mutex::default(),
                };
                let result = engine.run_with(request, &observer);
                let cancelled = worker_cancel.cancelled();
                observer.finished(result.as_ref().ok(), cancelled);
                let promoted = std::mem::take(&mut *observer.promoted.lock().unwrap());
                hub.update(|signals| signals.completed.push(send_batch));
                Completed {
                    cancelled,
                    result,
                    promoted,
                }
            })?;
        let batch_id: Arc<str> = Arc::from(batch.as_str());
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
                passwords,
                inputs: candidates,
                touched: HashSet::new(),
                cancel,
                groups,
                thread,
            },
        );
        Ok(())
    }

    fn checkpoints_for(&self, owner: &str) -> io::Result<Vec<crate::pipeline::InputCheckpoint>> {
        let prefix = format!("checkpoint|{}\0", watch_path_key(owner));
        self.journal
            .state()
            .runtime_keys(&prefix)
            .into_iter()
            .filter_map(|key| self.journal.state().runtime_record(&key))
            .map(|record| serde_json::from_value(record).map_err(io::Error::other))
            .collect()
    }

    fn cancel_batch(&mut self, batch: &str) -> bool {
        let Some(active) = self.active.get(batch) else {
            return false;
        };
        if active.thread.is_finished() || active.cancel.cancelled() {
            return false;
        }
        let mut seen: HashSet<_> = active
            .inputs
            .iter()
            .map(|input| key(Path::new(&input.path)))
            .collect();
        let siblings = active
            .groups
            .lock()
            .unwrap()
            .keys()
            .filter_map(|path| seen.insert(path.clone()).then(|| path.clone()))
            .collect::<Vec<_>>();
        let siblings = siblings
            .iter()
            .filter_map(|path| {
                let previous = self.catalog.observation(path);
                watch_candidate_for_path(
                    Path::new(path),
                    previous.as_ref().map(|row| row.change_usn),
                )
                .ok()
                .flatten()
            })
            .collect::<Vec<_>>();
        let mut interrupted = crate::watch_store::NativeWatchOperations::empty();
        for input in active.inputs.iter().chain(&siblings) {
            if NativePresence::at(&input.path).is_absent() {
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
        self.hub
            .claims
            .lock()
            .unwrap()
            .retain(|_, owner| owner != batch);
        let groups = std::mem::take(&mut *active.groups.lock().unwrap());
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
            for input in &archive.source_paths {
                by_path.entry(key(input)).or_default().push(archive);
            }
            by_path.entry(key(&archive.path)).or_default().push(archive);
        }
        let error_paths = outcome
            .errors
            .iter()
            .filter(|error| error.kind != crate::pipeline::InputErrorKind::Cleanup)
            .map(|error| (key(&error.path), &error.message))
            .collect::<HashMap<_, _>>();
        let mut operations = crate::watch_store::NativeWatchOperations::empty();
        let current_passwords = self.passwords.snapshot();
        let promoted_sources = outcome
            .promoted_sources
            .iter()
            .map(|source| (key(source.path()), source))
            .collect::<HashMap<_, _>>();
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
            let Some(candidate) = completed.promoted.remove(&id) else {
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
            );
            let directory = archive.path.parent().unwrap_or(Path::new(""));
            let payload = &mut Arc::make_mut(&mut entry).failure_payload;
            if let Some((_, scope)) = self.roots.get(&active.root) {
                payload.insert("source_input_root".into(), json!(scope.root));
            }
            payload.insert("promoted_nested_input".into(), Value::Bool(true));
            record_promoted_sources(payload, &candidate.path, Some(&group), &promoted_sources);
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
            if self.pending.contains_key(&id) || active.touched.contains(&id) {
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
                    );
                    record_promoted_sources(
                        &mut Arc::make_mut(&mut entry).failure_payload,
                        &candidate.path,
                        group.map(Arc::as_ref),
                        &promoted_sources,
                    );
                    entry
                })
            };
            if let Some(record) = &record {
                let directory = Path::new(&candidate.path).parent().unwrap_or(Path::new(""));
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
        self.journal.commit(true, |_| Ok(operations))?;
        self.release_display_claims(batch, &groups);
        for path in retry {
            self.enqueue(&active.root, path, true)?;
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

fn record_promoted_sources(
    payload: &mut serde_json::Map<String, Value>,
    path: &str,
    group: Option<&SourceGroup>,
    receipts: &HashMap<String, &PromotedSource>,
) {
    if receipts.is_empty() {
        return;
    }
    let sources = match group {
        Some(group) => group
            .members
            .iter()
            .filter_map(|path| receipts.get(&watch_path_key(path)).copied())
            .collect::<Vec<_>>(),
        None => receipts
            .get(&watch_path_key(path))
            .copied()
            .into_iter()
            .collect(),
    };
    if !sources.is_empty() {
        payload.insert("promoted_sources".into(), json!(sources));
    }
}

fn make_entry(
    candidate: &WatchCandidateRow,
    error: &str,
    kind: Option<FailureKind>,
    previous: Option<&crate::watch_store::EntryRecord>,
    passwords: &crate::core::passwords::PasswordSnapshot,
    group: Option<&SourceGroup>,
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
    if status == "failed_password" {
        let dir = Path::new(&candidate.path).parent().unwrap_or(Path::new(""));
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
    batch: String,
    toast: Option<super::toast::Publisher>,
    language: crate::core::i18n::Language,
    began: Instant,
    hub: Arc<Hub>,
    groups: Arc<Mutex<HashMap<String, Arc<SourceGroup>>>>,
    promoted: Mutex<HashMap<String, WatchCandidateRow>>,
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

    fn finished(&self, outcome: Option<&Outcome>, cancelled: bool) {
        let Some(toast) = &self.toast else {
            return;
        };
        if cancelled {
            toast.publish(super::toast::Snapshot::cancelled(
                &self.batch,
                self.language,
            ));
        } else if let Some(outcome) = outcome {
            if !outcome.archives.is_empty() || !outcome.errors.is_empty() {
                toast.publish_completed(&self.batch, self.language, outcome, self.began.elapsed());
            }
        }
    }
}

impl Observer for WatchObserver {
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
        let mut claims = self.hub.claims.lock().unwrap();
        for (_, target) in moves {
            claims.insert(key(target), self.batch.clone());
        }
        Ok(())
    }

    fn after_promotion(
        &self,
        archive: &ArchiveResult,
        moves: &[(PathBuf, PathBuf)],
        success: bool,
    ) -> io::Result<()> {
        let Some(owner) = self.owner(archive) else {
            return Ok(());
        };
        for (_, target) in moves {
            let id = key(target);
            self.outputs
                .lock()
                .unwrap()
                .insert(id.clone(), owner.clone());
            if success {
                if let Ok(Some(candidate)) = watch_candidate_for_path(target, None) {
                    self.promoted.lock().unwrap().insert(id, candidate);
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
            let mut aliases = self.groups.lock().unwrap();
            let mut claims = self.hub.claims.lock().unwrap();
            for member in &group.members {
                let key = watch_path_key(member);
                aliases.insert(key.clone(), Arc::clone(&group));
                claims.insert(key, self.batch.clone());
            }
        }
        self.journal.log(
            json!({"event":"pipeline_sources_claimed","path":path,"owner":self.batch,
            "processing":true,"groups":[group]}),
        );
        Ok(())
    }

    fn notify(&self, event: Event) {
        match event {
            Event::Progress {
                path,
                completed_bytes,
                total_bytes,
            } => {
                if let Some(toast) = &self.toast {
                    toast.publish(super::toast::Snapshot::progress(
                        &self.batch,
                        self.language,
                        path,
                        completed_bytes,
                        total_bytes,
                    ));
                }
            }
            _ => {}
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
                    crate::scan::scope::create_output_root_exclusive(path)?;
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
        prepare_flatten(&self.journal, &owner, root, work, leaf)
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
    let mut operations = vec![
        json!({"op":"runtime","key":format!("flatten|{}",key(root)),
            "value":{"owner":owner,"root":root,"work":work,"leaf":leaf,"old_identity":old,"new_identity":new}}),
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
    let Some(work) = record["work"].as_str() else {
        return Ok(());
    };
    let current = output_identity(root)?;
    if Path::new(work).exists()
        || ![
            record["new_identity"].as_str(),
            record["old_identity"].as_str(),
        ]
        .contains(&Some(current.as_str()))
    {
        return Ok(());
    }
    let mut operations = vec![
        json!({"op":"runtime","key":format!("owned|{}",watch_path_key(root)),
            "value":{"path":root,"identities":[current]}}),
        json!({"op":"runtime","key":record_key}),
        json!({"op":"runtime","key":format!("owned|{}",watch_path_key(work))}),
    ];
    if record["new_identity"].as_str() == Some(&current) {
        if let Some(owner) = record["owner"].as_str().filter(|owner| !owner.is_empty()) {
            for source in [Some(work), record["leaf"].as_str()].into_iter().flatten() {
                operations.push(json!({"op":"relocate_output","owner":owner,"source":source,
                    "destination":root,"identity":current}));
            }
        }
    }
    journal.commit(true, |state| state.decode_operations(&operations))
}

fn recover_flattens(journal: &journal::Journal) -> io::Result<()> {
    for id in journal.state().runtime_keys("flatten|") {
        let Some(record) = journal.state().runtime_record(&id) else {
            continue;
        };
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
        let result = crate::postprocess::flatten_single_branch_directories(
            Path::new(root),
            Some(Path::new(work)),
            |_, _, _| Ok(()),
            Some(Path::new(leaf)),
        );
        if result.errors.is_empty() {
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
