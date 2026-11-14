use super::results::RunOutcome as Outcome;
use super::checkpoint::{CheckpointKey, InputCheckpoint, InputRecovery, PromotedSource, ReportState};
use super::discovery::{self, Discovered, LogicalInput, Task};
use super::passwords::{AttemptCache, CandidateSet};
use super::scheduling::{stage, Scheduler, Spawner};
use super::shell_updates::{ShellNotifier, ShellUpdates};
use super::worker::{self, Process};
use super::{
    ArchiveResult, BusyConflict, Cancellation, CleanupResult, CleanupStatus, DiscoverySource,
    Event, Failure, FailureEvidence, FailureKind, FailureRead, InputError, InputErrorKind, Mode,
    Observer, Origin, Outcome as PublicOutcome, Request, ScanTaskFailure, Segment, TaskId,
};
use crate::analysis_native::{analyze_input, NativeAnalysisConfig};
use crate::collections::CacheOrder;
use crate::core::config::{CleanupMode, ContentRequirement, ProcessMode, Recursion, WorkerConfig};
use crate::io::archive_state::{
    archive_input_slices, ArchiveInput, OpenMode, VolumeCompleteness, VolumeSelection,
};
use crate::io::cancellation::is_cancellation;
use crate::io::directory_errors::{directory_error_count, DirectoryReadErrors};
use crate::io::reader::{
    capture_directory_identity, capture_file_generation, PhysicalFileGeneration,
};
#[cfg(test)]
use crate::io::reader::release_reader_resources_under_roots;
use crate::io::resource_lifecycle::Promotion;
use crate::path_keys::{normalize_windows_extended_prefix, path_ancestors, path_key, resolved_path_key};
use crate::postprocess::{
    discover_flatten_leaf, flatten_single_branch_directories, remove_owned_file, remove_owned_tree, FlattenLeaf,
    NativeBlockedInputPromotion,
};
use crate::scan::directory::{
    scan_output_inventory_impl, NativeDirectoryScanOptions, NativeOutputInventory,
};
use crate::scan::worker_event::WorkerFrame;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::future::poll_fn;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{atomic::Ordering, mpsc};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Poll, Waker};

#[derive(Clone)]
pub struct Engine(Arc<EngineState>);

impl std::ops::Deref for Engine {
    type Target = EngineState;
    fn deref(&self) -> &Self::Target { &self.0 }
}

pub struct EngineState {
    worker_path: PathBuf,
    worker: Mutex<WorkerOwner>,
    mode_changes: super::AsyncGate,
    leases: Arc<Leases>,
    password_attempts: AttemptCache,
    scheduler: OnceLock<Arc<Scheduler>>,
    shell: ShellNotifier,
    output_names: Arc<Mutex<OutputNames>>,
}

struct WorkerOwner {
    process: Option<Arc<Process>>,
    desired_mode: ProcessMode,
}

impl Engine {
    pub fn new(worker: PathBuf) -> Self {
        Self(Arc::new(EngineState {
            worker_path: worker,
            worker: Mutex::new(WorkerOwner {
                process: None,
                desired_mode: ProcessMode::Normal,
            }),
            mode_changes: super::AsyncGate::default(),
            leases: Arc::new(Leases::default()),
            password_attempts: AttemptCache::default(),
            scheduler: OnceLock::new(),
            shell: ShellNotifier::default(),
            output_names: Arc::default(),
        }))
    }

    fn next_id(&self) -> u64 {
        self.scheduler.get_or_init(Scheduler::new).next_id()
    }

    pub(crate) fn with_scheduler(worker: PathBuf, scheduler: Arc<Scheduler>) -> Self {
        let engine = Self::new(worker);
        assert!(engine.scheduler.set(scheduler).is_ok());
        engine
    }

    pub(crate) fn spawn_control<T: Send + 'static>(
        &self, origin: Origin, cancel: &Cancellation,
        future: impl std::future::Future<Output = T> + Send + 'static,
    ) -> io::Result<super::scheduling::Join<T>> {
        let (id, prepared) = self.prepare_control()?;
        Ok(prepared.submit(id, origin, cancel, |_| Box::pin(future)))
    }

    pub(crate) fn prepare_control(&self) -> io::Result<(u64, super::scheduling::PreparedSubmit<'_>)> {
        let id = self.next_id();
        Ok((id, self.scheduler.get_or_init(Scheduler::new).prepare_submit()?))
    }

    pub(crate) async fn reserve_foreground_async(
        &self, inputs: &[PathBuf], cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard> {
        let id = self.next_id();
        self.leases.reserve_request_async(id, Origin::Foreground, inputs, cancel).await
    }

    #[cfg(test)]
    pub(crate) async fn reserve_watch_inputs_for_test(
        &self, request: u64, paths: &[PathBuf], cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard> {
        self.leases.reserve_request_async(request, Origin::Watch, paths, cancel).await
    }

    pub(crate) async fn run_reserved_async<O: Observer + 'static>(
        &self, request: Request, observer: Arc<O>, reservation: Arc<RequestClaimGuard>,
    ) -> io::Result<PublicOutcome> {
        debug_assert!(Arc::ptr_eq(&reservation.registry, &self.leases));
        self.submit_with_claim(request, observer, Some(reservation), |result| result).wait().await
    }

    /// Synchronous service work uses the same admission and fixed executor as
    /// archive stages. Nested blocking helpers reuse the admitted stage.
    pub(crate) fn run_stage<T: Send>(
        &self, name: &'static str, origin: Origin, work: impl FnOnce() -> T + Send,
    ) -> io::Result<T> {
        if super::scheduling::in_stage() { return Ok(work()); }
        let cancel = Cancellation::new();
        let id = self.next_id();
        self.scheduler.get_or_init(Scheduler::new).run(id, origin, &cancel, |_| Box::pin(async {
            stage(name, &cancel).await?;
            Ok(work())
        }))
    }

    pub(crate) fn submit<O: Observer + 'static, T: Send + 'static>(
        &self, request: Request, observer: Arc<O>,
        complete: impl FnOnce(io::Result<PublicOutcome>) -> T + Send + 'static,
    ) -> super::scheduling::Join<T> {
        self.submit_with_claim(request, observer, None, complete)
    }

    fn submit_with_claim<O: Observer + 'static, T: Send + 'static>(
        &self, request: Request, observer: Arc<O>, reservation: Option<Arc<RequestClaimGuard>>,
        complete: impl FnOnce(io::Result<PublicOutcome>) -> T + Send + 'static,
    ) -> super::scheduling::Join<T> {
        let request_id = reservation.as_ref().map_or_else(
            || self.next_id(), |claim| claim.id);
        let engine = self.clone();
        let scheduler = self.scheduler.get_or_init(Scheduler::new);
        let prepared = match scheduler.prepare_submit() {
            Ok(prepared) => prepared,
            Err(error) => return super::scheduling::Join::ready(complete(Err(error))),
        };
        prepared.submit(
            request_id, request.origin, &request.cancel.clone(), move |spawner| {
                Box::pin(async move {
                    let result = async {
                        engine.worker(&request.config.performance.worker, &request.cancel).await
                            .map_err(super::startup_error)?;
                        let _claim = if reservation.is_some() {
                            reservation
                        } else if request.mode == Mode::Extract {
                            stage("request_admission", &request.cancel).await?;
                            Some(Arc::new(engine.leases.reserve_request_async(request_id, request.origin,
                                &request.inputs, &request.cancel).await?))
                        } else { None };
                        stage("discovery", &request.cancel).await?;
                        let run = engine.prepare(request, observer, request_id)?;
                        run.execute_request(spawner).await
                    }.await;
                    // Failure to create the executor is an error completion,
                    // not permission to run normal reporting on the driver.
                    match stage("report", &Cancellation::new()).await {
                        Ok(()) => complete(result),
                        Err(error) => complete(Err(error)),
                    }
                })
            })
    }

    fn prepare<O: Observer + 'static>(
        &self, mut request: Request, observer: Arc<O>, request_id: u64,
    ) -> io::Result<Arc<Run<'static, O>>> {
        // Watch supplies its own root mapping, including an empty mapping for
        // nested recovery. Only foreground requests inherit the saved root;
        // their CLI -o overrides root without replacing fixed_root.
        if request.output_root.is_none() && request.origin == Origin::Foreground {
            request.output_root = request.config.output.root.clone();
        }
        if let Some(output) = request.output_root.take() {
            request.output_root = Some(std::path::absolute(output)?);
        }
        let resolve_aliases = request.inputs.len() > 1 && self.leases.has_aliases(request_id);
        let candidates = CandidateSet::new(
            std::mem::take(&mut request.passwords),
            request.password_snapshot.clone(),
            &self.password_attempts,
            request.password_scope.as_deref(),
        );
        let unfiltered = || {
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let options = OnceLock::new();
        let deep_options = request.deep.then(unfiltered).transpose()?;
        let analysis = NativeAnalysisConfig::new(
            request
                .config
                .analysis
                .modules
                .iter()
                .map(|module| (module.name.to_string(), module.enabled)),
        );
        let output_base = request
            .output_root
            .as_ref()
            .filter(|_| request.origin == Origin::Foreground)
            .and_then(|_| {
                request
                    .output_base
                    .take()
                    .or_else(|| common_output_base(&request.inputs))
            });
        let mut checkpoints: RecoveryCheckpointIndex = HashMap::new();
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
        }
        let promoted_sources = request
            .promoted_sources
            .iter().enumerate()
            .map(|(index, source)| (path_key(&source.path().to_string_lossy()), index))
            .collect();
        let target_directories = if request.mode == Mode::Extract && request.max_depth > 0 {
            TargetDirectories::new(&request.inputs)
        } else {
            TargetDirectories::default()
        };
        let request = Arc::new(request);
        Ok(Arc::new(Run {
            engine: self.clone(),
            request: Arc::clone(&request),
            resolve_aliases,
            candidates,
            options,
            deep_options,
            analysis,
            observer: ObserverRef::Owned(observer, std::marker::PhantomData),
            worker_request_id: request_id.to_string(),
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: Arc::clone(&self.output_names), owner: request_id },
            created_outputs: Mutex::default(),
            output_base,
            target_directories,
            checkpoints,
            checkpoint_anchors: OnceLock::new(),
            promoted_sources,
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
            cleanup_tasks: Mutex::default(),
            cleanup_refs: Arc::default(),
        }))
    }

    pub(crate) async fn worker_ready(&self, config: &WorkerConfig, cancel: &Cancellation) -> io::Result<()> {
        self.worker(config, cancel).await.map(|_| ()).map_err(super::startup_error)
    }

    async fn worker(&self, config: &WorkerConfig, cancel: &Cancellation) -> io::Result<Arc<Process>> {
        loop {
            cancel.check_io()?;
            let current = self.worker.lock().unwrap().process.as_ref()
                .filter(|worker| worker.alive()).cloned();
            let process = if let Some(process) = current {
                process
            } else {
                // Replacements after an abandoned handshake resume on the
                // control driver too. Only creation/reaping uses a stage slot.
                stage("worker_start", cancel).await?;
                let mut owner = self.worker.lock().unwrap();
                if let Some(worker) = owner.process.as_ref().filter(|worker| worker.alive()) {
                    Arc::clone(worker)
                } else {
                    let process = Arc::new(Process::start(&self.worker_path, config, owner.desired_mode)?);
                    owner.process = Some(Arc::clone(&process));
                    process
                }
            };
            match process.ready(cancel).await {
                Ok(()) => {
                    self.scheduler.get_or_init(Scheduler::new)
                        .configure_capacity(process.thread_capacity());
                    return Ok(process);
                }
                // A new borrower may arrive while an abandoned generation is
                // reaping. Await that cleanup, then retry instead of inheriting
                // another request's cancellation. Genuine failures still return.
                Err(_) if !cancel.cancelled() && process.startup_abandoned() => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn worker_pid(&self) -> u32 {
        self.worker.lock().unwrap().process.as_ref().map_or(0, |process| process.pid())
    }

    pub(crate) fn set_process_mode(&self, mode: ProcessMode) -> io::Result<bool> {
        super::scheduling::block_on(self.set_process_mode_async(mode))
    }

    pub(crate) async fn set_process_mode_async(&self, mode: ProcessMode) -> io::Result<bool> {
        // Serialize control acknowledgments, but never hold the ownership lock
        // while stdin or its ACK is pending: scheduled jobs need that lock to
        // borrow the live worker. A replacement starts with desired_mode even
        // if the old process exits during this transition.
        let _change = self.mode_changes.lock().await;
        let process = {
            let mut owner = self.worker.lock().unwrap();
            owner.desired_mode = mode;
            let process = owner.process.as_ref().filter(|process| process.alive()).cloned();
            if let Some(process) = &process {
                process.desire_mode(mode);
            }
            process
        };
        match process {
            Some(process) => process.set_process_mode_async(mode).await,
            None => Ok(false),
        }
    }

    pub(crate) fn clear_idle_passwords(&self) {
        self.password_attempts.clear();
        self.output_names.lock().unwrap().clear_history();
    }

    pub(crate) fn recent_passwords(&self) -> Vec<Arc<str>> {
        self.password_attempts.recent()
    }
}

enum ObserverRef<'a, O> {
    #[cfg(test)]
    Borrowed(&'a O),
    Owned(Arc<O>, std::marker::PhantomData<&'a O>),
}

impl<O> std::ops::Deref for ObserverRef<'_, O> {
    type Target = O;
    fn deref(&self) -> &O {
        match self {
            #[cfg(test)]
            Self::Borrowed(value) => value,
            Self::Owned(value, _) => value,
        }
    }
}

type RecoveryCheckpointIndex = HashMap<Arc<str>, HashMap<CheckpointKey, usize>>;
type RecoveryAnchorIndex = HashMap<String, HashMap<(String, u64), Vec<(Arc<str>, usize)>>>;
type SourceGenerations = HashMap<String, PhysicalFileGeneration>;
type WatchGenerations = BTreeMap<String, PhysicalFileGeneration>;

enum TaskAdmission {
    Execute(Option<SourceGenerations>),
    Departed,
    Completed(PathBuf),
}

struct Run<'a, O> {
    engine: Engine,
    request: Arc<Request>,
    resolve_aliases: bool,
    candidates: CandidateSet,
    options: OnceLock<io::Result<NativeDirectoryScanOptions>>,
    deep_options: Option<NativeDirectoryScanOptions>,
    analysis: NativeAnalysisConfig,
    observer: ObserverRef<'a, O>,
    worker_request_id: String,
    recursion: RecursivePrompts,
    output_names: OutputReservationGuard,
    created_outputs: Mutex<CreatedOutputs>,
    output_base: Option<PathBuf>,
    target_directories: TargetDirectories,
    checkpoints: RecoveryCheckpointIndex,
    checkpoint_anchors: OnceLock<RecoveryAnchorIndex>,
    promoted_sources: HashMap<String, usize>,
    scan_errors: Mutex<DirectoryReadErrors>,
    cleanup_tasks: Mutex<CleanupTasks>,
    cleanup_refs: Arc<Mutex<CleanupRefs>>,
}

// Request-local cleanup ownership follows the planned consumers, not the
// duration of an individual worker lease. A failed owner vetoes shared deletion.
#[derive(Default)]
struct CleanupRefs {
    paths: HashMap<String, (usize, bool)>,
}

struct CleanupOwner {
    registry: Arc<Mutex<CleanupRefs>>,
    paths: HashSet<String>,
}

impl CleanupOwner {
    fn new(registry: Arc<Mutex<CleanupRefs>>, paths: &[String]) -> Self {
        let mut owner = Self { registry, paths: HashSet::new() };
        owner.refresh(paths);
        owner
    }

    fn refresh(&mut self, paths: &[String]) {
        if paths.is_empty() && self.paths.is_empty() { return; }
        let paths: HashSet<_> = paths.iter().map(|path| namespace_key(Path::new(path))).collect();
        let mut refs = self.registry.lock().unwrap();
        for key in self.paths.difference(&paths) {
            let entry = refs.paths.get_mut(key).expect("registered cleanup owner");
            entry.0 -= 1;
            if entry.0 == 0 { refs.paths.remove(key); }
        }
        for key in paths.difference(&self.paths) {
            refs.paths.entry(key.clone()).or_default().0 += 1;
        }
        self.paths = paths;
    }

    fn release(&mut self, eligible: bool) -> HashSet<String> {
        let mut allowed = HashSet::new();
        let mut refs = self.registry.lock().unwrap();
        for key in self.paths.drain() {
            let entry = refs.paths.get_mut(&key).expect("registered cleanup owner");
            entry.0 -= 1;
            entry.1 |= !eligible;
            if entry.0 == 0 {
                if !entry.1 { allowed.insert(key.clone()); }
                refs.paths.remove(&key);
            }
        }
        allowed
    }
}

impl Drop for CleanupOwner {
    fn drop(&mut self) {
        if !self.paths.is_empty() { self.release(false); }
    }
}

#[derive(Default)]
struct TargetDirectories {
    first: Option<Arc<Path>>,
    exact: HashMap<String, Arc<Path>>,
    ancestors: HashMap<String, Arc<Path>>,
}

impl TargetDirectories {
    fn new(inputs: &[PathBuf]) -> Self {
        let mut targets = Self::default();
        for input in inputs {
            let Ok(path) = std::path::absolute(input) else { continue };
            let is_dir = path.is_dir();
            let directory: Arc<Path> = if is_dir {
                Arc::from(path.as_path())
            } else {
                Arc::from(path.parent().unwrap_or(Path::new(".")))
            };
            targets.first.get_or_insert_with(|| Arc::clone(&directory));
            if inputs.len() == 1 { break; }
            if is_dir {
                let key = resolved_path_key(&path);
                let stored = targets.ancestors.entry(key.trim_end_matches('\\').to_owned())
                    .or_insert_with(|| Arc::clone(&directory));
                if directory.as_os_str().len() > stored.as_os_str().len() {
                    *stored = Arc::clone(&directory);
                }
            }
            targets.exact.entry(path_key(&path.to_string_lossy())).or_insert(directory);
        }
        targets
    }

    fn directory_for(&self, entry: &Path) -> Arc<Path> {
        if self.exact.is_empty() {
            return self.first.clone()
                .unwrap_or_else(|| Arc::from(entry.parent().unwrap_or(Path::new("."))));
        }
        self.exact.get(&path_key(&entry.to_string_lossy()))
            .or_else(|| {
                if self.ancestors.is_empty() { return None; }
                let key = resolved_path_key(entry);
                let target = path_ancestors(&key).find_map(|ancestor| self.ancestors.get(ancestor));
                target
            })
            .or(self.first.as_ref())
            .cloned()
            .unwrap_or_else(|| Arc::from(entry.parent().unwrap_or(Path::new("."))))
    }
}

struct RecursiveScope {
    password: Option<Arc<Path>>,
    promotion: Arc<Path>,
}

enum RetryOutput<'a> {
    Recreate(&'a Path),
    Existing(&'a Path),
}

#[derive(Default)]
struct CleanupTasks {
    next_id: u64,
    active: HashMap<u64, PendingCleanup>,
    failures: BTreeMap<String, CleanupResult>,
}

impl CleanupTasks {
    fn retire(&mut self, id: u64, failures: Vec<CleanupResult>) -> Vec<CleanupResult> {
        if self.active.remove(&id).is_some() {
            for failure in failures {
                self.record_failure(failure);
            }
            Vec::new()
        } else {
            failures
        }
    }

    fn record_failure(&mut self, failure: CleanupResult) {
        self.failures.insert(namespace_key(&failure.path), failure);
    }

    fn take_failures(&mut self, root: Option<&Path>) -> Vec<CleanupResult> {
        let Some(root) = root else {
            return std::mem::take(&mut self.failures).into_values().collect();
        };
        let key = namespace_key(root);
        let base = key.trim_end_matches('\\');
        // The ASCII successor of '\\' bounds all keys starting with base + '\\'.
        let descendants = format!("{base}\\")..format!("{base}]");
        self.failures.remove(&key).into_iter().chain(
            self.failures.extract_if(descendants, |_, _| true).map(|(_, failure)| failure),
        ).collect()
    }
}

struct PendingCleanup {
    paths: Vec<PathBuf>,
    task: super::scheduling::Join<Vec<CleanupResult>>,
}

/// One shared decision per depth, like main's prompt gates. Only the blocking
/// Observer interaction runs outside Rayon; all archive waiters use the existing
/// scheduler's Pending/Waker path and return their host admission slots.
#[derive(Default)]
struct RecursivePrompts {
    decisions: Arc<Mutex<HashMap<usize, Arc<RecursiveDecision>>>>,
    #[cfg(test)]
    requests: OnceLock<mpsc::Sender<Option<RecursivePrompt>>>,
}

#[cfg(test)]
type RecursivePrompt = (usize, usize, Arc<RecursiveDecision>);

#[derive(Default)]
struct RecursiveDecision(Mutex<RecursiveDecisionState>);

#[derive(Default)]
struct RecursiveDecisionState {
    value: Option<bool>,
    next_waiter: u64,
    waiters: HashMap<u64, Waker>,
}

impl RecursiveDecision {
    fn complete(&self, value: bool) {
        let mut state = self.0.lock().unwrap();
        // Cancellation can settle a gate before a late input answer arrives.
        state.value.get_or_insert(value);
        let waiters = std::mem::take(&mut state.waiters);
        drop(state);
        for waker in waiters.into_values() {
            waker.wake();
        }
    }
}

impl RecursivePrompts {
    #[cfg(test)]
    fn serve<T>(
        &self,
        cancel: &Cancellation,
        prompt: impl Fn(usize, usize) -> bool + Sync,
        execute: impl FnOnce() -> T,
    ) -> T {
        let (send, receive) = mpsc::channel();
        assert!(self.requests.set(send.clone()).is_ok());
        let decisions = Arc::clone(&self.decisions);
        let _cancellation = cancel.subscribe(move || {
            let decisions: Vec<_> = decisions.lock().unwrap().values().cloned().collect();
            for decision in decisions {
                decision.complete(false);
            }
        });
        std::thread::scope(|scope| {
            // This thread belongs to the request, not to each recursive branch.
            // Its scoped join keeps the borrowed Observer alive until it stops.
            let prompt = &prompt;
            scope.spawn(move || {
                let _panic = CancelPromptPanic(cancel);
                while let Ok(Some((depth, pending, decision))) = receive.recv() {
                    let allowed = !cancel.cancelled() && cancel.run(|| prompt(depth, pending));
                    decision.complete(allowed);
                }
            });
            let _close = ClosePrompts { send, cancel };
            execute()
        })
    }

    async fn allow<F: std::future::Future<Output = bool> + Send>(
        &self, depth: usize, pending: usize, cancel: &Cancellation,
        inline: Option<impl FnOnce(usize, usize) -> F + Send>,
    ) -> bool {
        if cancel.cancelled() {
            return false;
        }
        let (decision, first) = {
            let mut decisions = self.decisions.lock().unwrap();
            match decisions.entry(depth) {
                std::collections::hash_map::Entry::Occupied(entry) => (Arc::clone(entry.get()), false),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    (Arc::clone(entry.insert(Arc::default())), true)
                }
            }
        };
        if first {
            if let Some(prompt) = inline {
                let allowed = stage("report", cancel).await.is_ok() && prompt(depth, pending).await;
                decision.complete(allowed);
            } else {
                #[cfg(test)]
                {
                    let request = Some((depth, pending, Arc::clone(&decision)));
                    if self.requests.get().expect("prompt service is running").send(request).is_err() {
                        decision.complete(false);
                    }
                }
                #[cfg(not(test))]
                unreachable!("production prompts use the async observer");
            }
        }
        let mut waiter = None;
        poll_fn(|cx| {
            let mut state = decision.0.lock().unwrap();
            if cancel.cancelled() {
                return Poll::Ready(false);
            }
            if let Some(value) = state.value {
                return Poll::Ready(value);
            }
            let id = *waiter.get_or_insert_with(|| {
                state.next_waiter += 1;
                state.next_waiter
            });
            state.waiters.insert(id, cx.waker().clone());
            Poll::Pending
        }).await
    }
}

#[cfg(test)]
struct ClosePrompts<'a> {
    send: mpsc::Sender<Option<RecursivePrompt>>,
    cancel: &'a Cancellation,
}

#[cfg(test)]
impl Drop for ClosePrompts<'_> {
    fn drop(&mut self) {
        // Also release the receiver if execution unwinds before its result.
        if std::thread::panicking() {
            self.cancel.cancel();
        }
        let _ = self.send.send(None);
    }
}

#[cfg(test)]
struct CancelPromptPanic<'a>(&'a Cancellation);

#[cfg(test)]
impl Drop for CancelPromptPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // A panicking Observer must not leave the scheduler's gates parked.
            self.0.cancel();
        }
    }
}

/// Shared across requests, with the same ownership rule as main's
/// OutputReservationRegistry: only recursive inputs inside this request's
/// generated tree may enter it. Independent siblings must never overlap.
#[derive(Default)]
struct OutputNames {
    indices: CacheOrder<Arc<str>, OutputHistory>,
    slots: HashMap<Arc<str>, HashMap<Arc<str>, usize>>,
    claimed: BTreeMap<String, OutputClaim>,
    owners: HashMap<u64, Vec<String>>,
}

const OUTPUT_HISTORY_LIMIT: usize = 256;

struct OutputHistory {
    next: usize,
    available: BTreeSet<usize>,
    observed: HashSet<Arc<str>>,
}

impl OutputHistory {
    fn take(&mut self) -> usize {
        if self.available.first().is_some_and(|index| *index < self.next) {
            return self.available.pop_first().unwrap();
        }
        let index = self.next;
        self.next += 1;
        self.available.remove(&index);
        index
    }

    fn release(&mut self, index: usize) {
        if self.available.len() >= OUTPUT_HISTORY_LIMIT {
            self.next = self.next.min(index).min(*self.available.first().unwrap());
            self.available.clear();
        } else {
            self.available.insert(index);
        }
    }
}

struct OutputClaim {
    owner: u64,
    source: String,
}

struct OutputReservationGuard {
    registry: Arc<Mutex<OutputNames>>,
    owner: u64,
}

impl Drop for OutputReservationGuard {
    fn drop(&mut self) {
        self.registry.lock().unwrap().release(self.owner);
    }
}

impl OutputNames {
    fn claim(&mut self, key: String, owner: u64, source: String) {
        if !self.claimed.contains_key(&key) {
            self.owners.entry(owner).or_default().push(key.clone());
        }
        self.claimed.insert(key, OutputClaim {
            owner, source,
        });
    }

    fn release_path(&mut self, key: &str, owner: u64) {
        if self.claimed.get(key).is_none_or(|claim| claim.owner != owner) { return; }
        if let Some(paths) = self.owners.get_mut(&owner) {
            paths.retain(|path| path != key);
            if paths.is_empty() { self.owners.remove(&owner); }
        }
        self.release_key(key);
    }

    fn release_key(&mut self, key: &str) {
        self.claimed.remove(key);
        for candidate in crate::path_keys::path_ancestors(key) {
            if let Some(slots) = self.slots.remove(candidate) {
                for (family, index) in slots {
                    if let Some(history) = self.indices.peek_mut(&family) {
                        history.observed.remove(candidate);
                        history.release(index);
                    }
                }
            }
        }
    }

    fn release(&mut self, owner: u64) {
        for key in self.owners.remove(&owner).into_iter().flatten() {
            self.release_key(&key);
        }
        crate::collections::trim_map(&mut self.owners);
        crate::collections::trim_map(&mut self.slots);
    }

    fn clear_history(&mut self) {
        self.indices = CacheOrder::default();
        self.slots = HashMap::new();
    }

    fn next_index(&mut self, family: &Arc<str>) -> usize {
        if let Some(history) = self.indices.get_mut(family) {
            return history.take();
        }
        let history = OutputHistory { next: 2, available: BTreeSet::new(), observed: HashSet::new() };
        if let Some((old, history)) = self.indices.insert(Arc::clone(family), history, OUTPUT_HISTORY_LIMIT) {
            for path in history.observed {
                if let Some(slots) = self.slots.get_mut(&path) {
                    slots.remove(&old);
                    if slots.is_empty() { self.slots.remove(&path); }
                }
            }
        }
        1
    }

    fn observe_slot(&mut self, path: &str, family: &Arc<str>, index: usize) {
        let path: Arc<str> = Arc::from(path);
        self.slots.entry(Arc::clone(&path)).or_default().insert(Arc::clone(family), index);
        self.indices.peek_mut(family).unwrap().observed.insert(path);
    }

    fn has_under(&self, key: &str) -> bool {
        if self.claimed.contains_key(key) {
            return true;
        }
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        self.claimed.range(prefix.clone()..).next()
            .is_some_and(|(path, _)| path.starts_with(&prefix))
    }

    fn conflicting_ancestor<'a>(&self, parent: &'a str, owner: u64, input: Option<&str>) -> Option<&'a str> {
        // Keep the root-most conflict so rerouting leaves every owning tree.
        let mut conflict = None;
        for ancestor in crate::path_keys::path_ancestors(parent) {
            if let Some(claim) = self.claimed.get(ancestor) {
                if claim.owner == owner && input.is_some_and(|input| {
                    input == ancestor || input.strip_prefix(ancestor).is_some_and(|tail| tail.starts_with('\\'))
                }) {
                    continue;
                }
                conflict = Some(ancestor);
            }
        }
        conflict
    }

    fn retain(registry: &Mutex<Self>, path: &Path, owner: u64, source: &Path, input: Option<&Path>) -> bool {
        let key = output_key(path);
        let source = resolved_key(source);
        let input = input.map(output_key);
        let parent = output_key(path.parent().unwrap_or(Path::new(".")));
        let mut names = registry.lock().unwrap();
        // Several continued carrier segments share one container. Only the
        // same physical source in this request may reuse that exact claim.
        if names.claimed.get(&key).is_some_and(|claim| {
            claim.owner == owner && claim.source == source
        }) {
            return true;
        }
        if names.conflicting_ancestor(&parent, owner, input.as_deref()).is_some() || names.has_under(&key) {
            return false;
        }
        names.claim(key, owner, source);
        true
    }

    fn reserve(
        registry: &Mutex<Self>, preferred: PathBuf, result: &ArchiveResult,
        observer: &impl Observer, owner: u64, input: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        loop {
            let (path, claim_key) = match Self::plan_checked(
                registry, preferred.clone(), &result.path, owner, input, Path::try_exists,
            )? {
                Ok(plan) => plan,
                Err(failure) => return Ok(Err(failure)),
            };
            // The memory claim prevents peers selecting this tree. Creation
            // and durable publication have their own exclusive boundary and
            // must not block unrelated Engine name allocations.
            match observer.register_output(result, &path) {
                Ok(()) => return Ok(Ok(path)),
                Err(error) => {
                    registry.lock().unwrap().release_path(&claim_key, owner);
                    let creation_error = error.get_ref().is_some_and(|inner| {
                        inner.is::<super::OutputCreateError>()
                    });
                    if creation_error && error.kind() == io::ErrorKind::AlreadyExists
                        && path.try_exists().unwrap_or(false)
                    {
                        continue;
                    }
                    if !creation_error { return Err(error); }
                    return Ok(Err(output_create_failure(error, &path)));
                }
            }
        }
    }

    fn plan(
        registry: &Mutex<Self>, preferred: PathBuf, source: &Path,
        owner: u64, input: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        Self::plan_checked(registry, preferred, source, owner, input, Path::try_exists)
            .map(|result| result.map(|(path, _)| path))
    }

    fn plan_checked(
        registry: &Mutex<Self>, preferred: PathBuf, source: &Path,
        owner: u64, input: Option<&Path>, mut exists: impl FnMut(&Path) -> io::Result<bool>,
    ) -> io::Result<Result<(PathBuf, String), Failure>> {
        // Resolve aliases before taking the naming lock. All keys below are
        // derived from this namespace; the lock protects only memory claims.
        let mut parent = output_key(preferred.parent().unwrap_or(Path::new(".")));
        let mut preferred_key = Self::candidate_key(&preferred, &parent);
        let source = resolved_key(source);
        let input = input.map(output_key);
        let mut occupied_preferred = None;
        let mut rebased_parent: Option<(PathBuf, String)> = None;
        loop {
            let (path, key, slot, suffix, base_key) = {
                let mut names = registry.lock().unwrap();
                let (base, base_parent, suffix) = match names.conflicting_ancestor(&parent, owner, input.as_deref()) {
                    Some(ancestor) => {
                        let (base, suffix) = conflicting_output_base(&preferred, &preferred_key, ancestor)?;
                        // Number the caller's spelling, which may be a junction
                        // at a different depth from its physical destination.
                        // Resolve that sibling namespace outside the lock, then
                        // recheck the ancestor before choosing a candidate.
                        if rebased_parent.as_ref().is_none_or(|(path, _)| path != base) {
                            drop(names);
                            rebased_parent = Some((base.to_owned(), output_key(base.parent().unwrap_or(Path::new(".")))));
                            continue;
                        }
                        let base_parent = rebased_parent.as_ref().unwrap().1.as_str();
                        if names.conflicting_ancestor(base_parent, owner, input.as_deref()).is_some() {
                            // The alias's containing tree can itself belong to
                            // another request. Rebase that tree before claiming.
                            preferred_key = format!("{}\\{}", Self::candidate_key(base, base_parent), path_key(&suffix.to_string_lossy()));
                            parent = preferred_key.rsplit_once('\\').unwrap().0.to_owned();
                            continue;
                        }
                        (base, base_parent, Some(suffix))
                    }
                    None => (preferred.as_path(), parent.as_str(), None),
                };
                let (path, key, slot) = names.next_available(base, base_parent, occupied_preferred.as_deref());
                (path, key, slot, suffix, Self::candidate_key(base, base_parent))
            };
            // A query must not reserve a tree that may already exist on disk:
            // peers may legitimately create children there. Only the numbered
            // index is taken while IO is in flight; publish after revalidation.
            let checked = exists(&path);
            let mut names = registry.lock().unwrap();
            let occupied = names.has_under(&key);
            let candidate_parent = key.rsplit_once('\\').unwrap().0;
            let conflicting = names.conflicting_ancestor(candidate_parent, owner, input.as_deref()).is_some();
            if let Some((family, index)) = slot {
                // Another request may have evicted this bounded history while
                // we were on the network. Claims, not history, prove exclusivity.
                if names.indices.peek_mut(&family).is_some() {
                    if occupied || matches!(checked, Ok(false)) && !conflicting {
                        names.observe_slot(&key, &family, index);
                    } else if !matches!(checked, Ok(true)) {
                        names.indices.peek_mut(&family).unwrap().release(index);
                    }
                }
            }
            match checked {
                Ok(false) => {
                    if occupied || conflicting {
                        continue;
                    }
                    let (path, key) = if let Some(suffix) = suffix {
                        // A nonexistent ancestor makes its mirrored leaf free.
                        // The leaf's release also returns the ancestor's slot.
                        (path.join(&suffix), format!("{}\\{}", key, path_key(&suffix.to_string_lossy())))
                    } else {
                        (path, key)
                    };
                    names.claim(key.clone(), owner, source);
                    return Ok(Ok((path, key)));
                }
                Ok(true) => occupied_preferred = Some(base_key),
                Err(error) => return Ok(Err(file_failure(error))),
            }
        }
    }

    fn candidate_key(path: &Path, parent: &str) -> String {
        format!("{}\\{}", parent.trim_end_matches('\\'),
            crate::path_keys::case_key(&path.file_name().unwrap().to_string_lossy()))
    }

    // Both a leaf and a rebased ancestor use the same reservation-aware history.
    // Selection takes only an index; plan_checked probes and revalidates the tree.
    fn next_available(&mut self, preferred: &Path, parent: &str, occupied: Option<&str>)
        -> (PathBuf, String, Option<(Arc<str>, usize)>)
    {
        let preferred_key = Self::candidate_key(preferred, parent);
        if occupied != Some(preferred_key.as_str()) && !self.has_under(&preferred_key) {
            return (preferred.to_owned(), preferred_key, None);
        }
        let preferred_key: Arc<str> = Arc::from(preferred_key);
        loop {
            let index = self.next_index(&preferred_key);
            let path = numbered(preferred, index);
            let key = Self::candidate_key(&path, parent);
            if !self.has_under(&key) {
                return (path, key, Some((preferred_key, index)));
            }
            self.observe_slot(&key, &preferred_key, index);
        }
    }
}

fn conflicting_output_base<'a>(
    preferred: &'a Path,
    key: &str,
    ancestor_key: &str,
) -> io::Result<(&'a Path, PathBuf)> {
    let prefix = format!("{}\\", ancestor_key.trim_end_matches('\\'));
    let count = key.strip_prefix(&prefix).map(|tail| tail.split('\\').count())
        .ok_or_else(|| io::Error::other("unable to relocate conflicting output ancestor"))?;
    let base = preferred.ancestors().nth(count).ok_or_else(|| {
        io::Error::other("unable to locate conflicting output ancestor")
    })?;
    let relative = preferred.strip_prefix(base).map_err(io::Error::other)?.to_path_buf();
    Ok((base, relative))
}

/// Canonicalize the existing prefix too: a new leaf below a directory alias
/// must collide with a reservation reached through its physical spelling.
fn output_key(path: &Path) -> String {
    crate::path_keys::resolved_path_key(path)
}

/// Newly created trees only. Continued roots are never registered here; their
/// newly created children are. Completed subtrees retire once no other tracked
/// uncommitted ancestor owns them, before their archive source can be deleted.
#[derive(Default)]
struct CreatedOutputs(BTreeMap<String, CreatedOutput>);

struct CreatedOutput {
    path: PathBuf,
    archive: PathBuf,
    sources: Vec<PathBuf>,
}

impl CreatedOutputs {
    fn register(&mut self, path: &Path, result: &ArchiveResult) {
        self.0.insert(output_key(path), CreatedOutput {
            path: path.to_owned(),
            archive: result.path.clone(),
            sources: result.source_paths.clone(),
        });
    }

    fn commit_if_unowned(&mut self, root: &Path) {
        let key = output_key(root);
        if !crate::path_keys::path_ancestors(&key).skip(1)
            .any(|ancestor| self.0.contains_key(ancestor))
        {
            self.commit(root);
        }
    }

    fn commit(&mut self, root: &Path) {
        let key = output_key(root);
        self.0.remove(&key);
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        let keys: Vec<_> = self.0.range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(key, _)| key.clone()).collect();
        for key in keys {
            self.0.remove(&key);
        }
    }

    fn relocate(&mut self, source: &Path, destination: &Path) {
        let key = output_key(source);
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        let mut keys = Vec::new();
        if self.0.contains_key(&key) {
            keys.push(key);
        }
        keys.extend(self.0.range(prefix.clone()..)
            .take_while(|(item, _)| item.starts_with(&prefix))
            .map(|(item, _)| item.clone()));
        for key in keys {
            if let Some(mut output) = self.0.remove(&key) {
                if let Ok(tail) = output.path.strip_prefix(source) {
                    output.path = destination.join(tail);
                }
                if let Ok(tail) = output.archive.strip_prefix(source) {
                    output.archive = destination.join(tail);
                }
                for path in &mut output.sources {
                    if let Ok(tail) = path.strip_prefix(source) {
                        *path = destination.join(tail);
                    }
                }
                // Flattening a leaf into an already tracked root must retain
                // the original root owner's receipt rather than overwrite it.
                self.0.entry(output_key(&output.path)).or_insert(output);
            }
        }
    }

    fn rollback(&mut self, observer: &impl Observer, outcome: &mut Outcome) -> io::Result<()> {
        let mut visited = HashSet::new();
        let mut roots = HashSet::new();
        for (key, output) in &self.0 {
            if crate::path_keys::path_ancestors(key).any(|ancestor| visited.contains(ancestor)) {
                continue;
            }
            visited.insert(key.clone());
            match cleanup_owned_output(&output.path) {
                Ok(()) => { roots.insert(key.clone()); }
                Err(error) => record_cleanup(outcome, &output.path, "rollback", Err(error)),
            }
        }
        let discarded = |path: &Path| {
            let key = output_key(path);
            let removed = crate::path_keys::path_ancestors(&key).any(|ancestor| roots.contains(ancestor));
            removed
        };
        for archive in &mut outcome.archives {
            if archive.output.as_deref().is_some_and(&discarded) {
                archive.output = None;
                archive.files = 0;
                archive.bytes = 0;
                archive.partial = false;
                archive.recovered_complete_files = 0;
                archive.failure = Some(Failure::new(FailureKind::Cancelled, "Operation interrupted"));
            }
        }
        outcome.archives.refresh();
        outcome.checkpoints.retain(|checkpoint| !checkpoint.has_output() || !discarded(checkpoint.output()));
        // Only retire recovery/WAL ownership for trees actually removed. A
        // journal failure is not a filesystem cleanup failure: propagate it,
        // but still finish independent notifications and outcome accounting.
        let mut observer_error = None;
        self.0.retain(|_, output| {
            if !discarded(&output.path) {
                return true;
            }
            match observer.discard_output(&output.archive, &output.sources, &output.path) {
                Ok(()) => false,
                Err(error) => {
                    if observer_error.is_none() {
                        observer_error = Some(error);
                    }
                    true
                }
            }
        });
        match observer_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

type ParentOutput = (ArchiveResult, Option<NativeOutputInventory>, Arc<ArchiveInput>, TaskId);

struct Executed {
    planned_output: Option<PathBuf>,
    result: ArchiveResult,
    inventory: Option<NativeOutputInventory>,
    input: Arc<ArchiveInput>,
}

impl<'run, O: Observer> Run<'run, O> {
    async fn execute_request(self: &Arc<Self>, spawner: Spawner<'run>) -> io::Result<PublicOutcome> {
        let decisions = Arc::clone(&self.recursion.decisions);
        let _cancellation = self.request.cancel.subscribe(move || {
            let decisions: Vec<_> = decisions.lock().unwrap().values().cloned().collect();
            for decision in decisions { decision.complete(false); }
        });
        self.request.cancel.check_io()?;
        let discovered = discovery::discover(&self.request, self.options_at(1)?, &self.candidates)?;
        let requested = self.watch_generations(&discovered);
        let mut watch = None;
        if let Some(members) = &requested {
            match self.engine.leases.claim_watch(self.output_names.owner, members, &self.request) {
                WatchFamily::Owner(owner) => watch = Some(owner),
                WatchFamily::Follower(key, owner, completion) => {
                    self.observer.coalesced();
                    drop(requested);
                    drop(discovered);
                    self.engine.leases.join_watch(&key, owner, &completion, &self.request.cancel).await?;
                    return Ok(PublicOutcome { coalesced_from: Some(owner), ..PublicOutcome::default() });
                }
            }
        }
        // Request admission covers only the user's original selections, as in
        // main. Discovery may resolve different selections to one volume family;
        // claim_task shares reads within a request and serializes other requests.
        let executed = self.execute_batch(discovered, 1, None, None, spawner, requested).await;
        let result = self.finish(executed).await.map(PublicOutcome::from);
        if let Some(watch) = watch { watch.finish(&result, &self.request.cancel); }
        result
    }

    fn watch_generations(&self, discovered: &Discovered) -> Option<Arc<WatchGenerations>> {
        if self.request.origin != Origin::Watch || self.request.mode != Mode::Extract
            || !self.request.checkpoints.is_empty() || !self.request.promoted_sources.is_empty()
            || !discovered.errors.is_empty() || !discovered.scan_errors.is_empty()
            || !discovered.tasks.iter().any(|task| task.owned_paths.len() > 1)
        {
            return None;
        }
        // Different selections of a shared tail can resolve to multiple heads.
        // Capture each physical path once, regardless of the number of tasks.
        let mut members = BTreeMap::new();
        for path in discovered.tasks.iter().flat_map(|task| &task.owned_paths) {
            if let std::collections::btree_map::Entry::Vacant(entry) = members.entry(path_key(path)) {
                entry.insert(capture_file_generation(Path::new(path)).ok()?);
            }
        }
        Some(Arc::new(members))
    }

    async fn finish(&self, mut executed: io::Result<Outcome>) -> io::Result<Outcome> {
        // Drain background releases before request completion and rollback,
        // without retaining the archive consumer while cleanup runs.
        let mut cleanup = Outcome::default();
        self.drain_cleanup(None, &mut cleanup).await;
        if let Ok(outcome) = &mut executed {
            outcome.cleanup_results.append(&mut cleanup.cleanup_results);
            outcome.errors.append(&mut cleanup.errors);
        }
        // Scheduler completion joins every writer, even on cancellation. Never
        // roll back a tree while a native job or recursive branch can write it.
        if self.request.cancel.cancelled() {
            stage("cancel_cleanup", &Cancellation::new()).await?;
            let mut discarded = Outcome::default();
            self.created_outputs.lock().unwrap().rollback(
                &*self.observer, executed.as_mut().unwrap_or(&mut discarded),
            )?;
        }
        let mut outcome = executed?;
        outcome.errors.extend(
            std::mem::replace(&mut *self.scan_errors.lock().unwrap(), DirectoryReadErrors::report())
                .into_messages()
                .into_iter()
                .map(|error| {
                    let count = directory_error_count(&error);
                    let (operation, path, detail) = error;
                    InputError {
                        path: PathBuf::from(path),
                        message: detail,
                        kind: InputErrorKind::FilesystemScan,
                        scan_operation: Some(operation),
                        scan_count: (count != 1).then_some(count),
                        failure: None,
                    }
                }),
        );
        Ok(outcome)
    }

    async fn drain_cleanup(&self, root: Option<&Path>, outcome: &mut Outcome) {
        let (mut failures, pending) = {
            let mut tasks = self.cleanup_tasks.lock().unwrap();
            let failures = tasks.take_failures(root);
            let ids: Vec<_> = tasks.active.iter().filter_map(|(&id, task)| {
                root.is_none_or(|root| task.paths.iter().any(|path| relative_to(path, root).is_some()))
                    .then_some(id)
            }).collect();
            let pending: Vec<_> = ids.into_iter().filter_map(|id| tasks.active.remove(&id)).map(|task| task.task).collect();
            (failures, pending)
        };
        for pending in pending {
            let mut results = pending.wait().await;
            if let Some(root) = root.filter(|_| !results.is_empty()) {
                let mut tasks = self.cleanup_tasks.lock().unwrap();
                for failure in results.extract_if(.., |failure| relative_to(&failure.path, root).is_none()) {
                    tasks.record_failure(failure);
                }
            }
            failures.append(&mut results);
        }
        for failure in failures {
            record_cleanup_failure(outcome, failure);
        }
    }

    fn filtered_options(&self) -> io::Result<&NativeDirectoryScanOptions> {
        // Deep discovery does not use configured filters. Compile them only
        // when a recursive output actually enters ordinary discovery, sharing
        // the same result across concurrently completed archive outputs.
        self.options.get_or_init(|| discovery::scan_options(&self.request.config))
            .as_ref().map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }

    fn options_at(&self, depth: usize) -> io::Result<&NativeDirectoryScanOptions> {
        if depth == 1 {
            if let Some(options) = &self.deep_options {
                return Ok(options);
            }
        }
        self.filtered_options()
    }

    async fn execute_batch(
        self: &Arc<Self>,
        mut batch: Discovered,
        depth: usize,
        inherited_scope: Option<Arc<RecursiveScope>>,
        parent_id: Option<TaskId>,
        spawner: Spawner<'run>,
        requested: Option<Arc<WatchGenerations>>,
    ) -> io::Result<Outcome> {
        // Scan has no request claim to reveal aliases. Reuse the resolved
        // paths from deduplication for read leases in both modes.
        let resolved_paths = if depth == 1 && batch.tasks.len() > 1
            && (self.resolve_aliases || (self.request.mode == Mode::Scan && self.request.inputs.len() > 1))
        {
            dedup_resolved_plans(&mut batch.tasks)
        } else {
            HashMap::new()
        };
        let mut root_errors = HashMap::new();
        if depth == 1 && self.request.watch_catalog.is_some()
            && batch.errors.iter().any(|error| error.kind == InputErrorKind::EmbeddedDiscovery)
        {
            use crate::scan::catalog::catalog_stem;

            let mut roots = HashMap::new();
            for task in &batch.tasks {
                roots.entry(catalog_stem(&task.entry().entry_path))
                    .or_insert(task.entry().entry_path.as_str());
            }
            for error in std::mem::take(&mut batch.errors) {
                let root = (error.kind == InputErrorKind::EmbeddedDiscovery)
                    .then(|| catalog_stem(&error.path.to_string_lossy()))
                    .and_then(|stem| roots.get(&stem).copied());
                // The request owns residual failures from the same discovery
                // bucket, including when a sibling archive makes it visible.
                if let Some(path) = root {
                    root_errors.entry(path.to_owned()).or_insert_with(Vec::new).push(error);
                } else {
                    batch.errors.push(error);
                }
            }
        }
        let mut outcome = Outcome {
            errors: batch.errors.into(),
            scan_incomplete: self.record_scan_errors(batch.scan_errors),
            ..Outcome::default()
        };
        let children = spawner.clone();
        let owner = Arc::clone(self);
        let has_root_errors = !root_errors.is_empty();
        let root_errors = Mutex::new(root_errors);
        let task_count = batch.tasks.len();
        if depth == 1 {
            self.observer.roots_planned(batch.tasks.iter().map(|task| {
                (task.entry().entry_path.as_str(), task.owned_paths.as_slice())
            }));
        }
        // Register every planned consumer before any one of them can finish.
        let tasks = batch.tasks.into_iter().map(|task| {
            let sources = self.cleanup_owner(&task);
            let keys = (!resolved_paths.is_empty()).then(|| source_lease_keys(&task, &resolved_paths));
            let requested = requested.as_ref().filter(|_| task.owned_paths.len() > 1).cloned();
            (task, sources, keys, requested)
        }).collect();
        drop(resolved_paths);
        let executed = spawner.bounded_map(tasks, move |(task, sources, keys, requested)| {
            let root_errors = has_root_errors
                .then(|| root_errors.lock().unwrap().remove(&task.entry().entry_path))
                .flatten();
            let owner = Arc::clone(&owner);
            let this = Arc::clone(&owner);
            let children = children.clone();
            let scope = inherited_scope.clone();
            Box::pin(async move {
                let entry = task.entry();
                let extent = entry.physical_extents().next();
                // Preserve the cancellation report coordinates without
                // gathering every physical member for every live task.
                let cancelled = ArchiveResult {
                    path: PathBuf::from(&entry.entry_path),
                    format: entry.format_hint.clone(),
                    encrypted: entry.analysis.password_required.then_some(true),
                    depth,
                    offset: extent.map_or(0, |extent| extent.start),
                    end_offset: extent.and_then(|extent| extent.end),
                    discovery_source: task.source,
                    ..ArchiveResult::default()
                };
                let ready = stage("report", &Cancellation::new()).await;
                let id = owner.queue_task(task.entry(), depth, parent_id, || None);
                let mut result = match ready {
                    Ok(()) => owner.execute_task((task, sources, keys, requested), id, depth, scope, children).await,
                    Err(error) => Err(error),
                };
                let unowned_errors = match (&mut result, root_errors) {
                    (Ok(outcome), Some(errors)) => {
                        outcome.errors.extend(errors);
                        None
                    }
                    (_, errors) => errors,
                };
                let result = if depth == 1 { this.finish_root(id, &cancelled.path, result).await } else { result };
                (id, cancelled, result, unowned_errors)
            })
        }).await;
        stage("report", &Cancellation::new()).await?;
        outcome.uncommitted |= executed.len() != task_count;
        let mut first_error = None;
        for (id, mut cancelled, branch, unowned_errors) in executed {
            if let Some(errors) = unowned_errors {
                outcome.errors.extend(errors);
            }
            let mut branch = match branch {
                Ok(branch) => branch,
                Err(error) if is_cancellation(&error) => {
                    cancelled.failure = Some(Failure::new(FailureKind::Cancelled, "Operation interrupted"));
                    self.notify(|| Event::Finished {
                        id, path: cancelled.path.clone(), depth,
                        result: super::TaskCompletion::from_result(&cancelled),
                    });
                    outcome.archives.push(cancelled);
                    continue;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            for mut failed in branch.scan_failures {
                failed.archives.start += outcome.archives.len();
                failed.archives.end += outcome.archives.len();
                outcome.scan_failures.push(failed);
            }
            outcome.archives.append(&mut branch.archives);
            outcome.errors.append(&mut branch.errors);
            outcome.scan_incomplete |= branch.scan_incomplete;
            outcome.uncommitted |= branch.uncommitted;
            outcome.checkpoints.append(&mut branch.checkpoints);
            outcome.cleanup_results.append(&mut branch.cleanup_results);
            outcome
                .promoted_sources
                .append(&mut branch.promoted_sources);
        }
        first_error.map_or(Ok(outcome), Err)
    }

    async fn finish_root(&self, id: TaskId, path: &Path, result: io::Result<Outcome>) -> io::Result<Outcome> {
        if result.as_ref().is_ok_and(Outcome::settled) {
            stage("report", &Cancellation::new()).await?;
            let mut outcome = self.observer.root_finished(id, path, result.unwrap().into(), self.output_names.owner).await?;
            if self.request.mode == Mode::Extract {
                outcome.compact_completed_extract();
            }
            Ok(outcome.into())
        } else { result }
    }

    fn notify(&self, event: impl FnOnce() -> Event) {
        if self.observer.worker_updates() == super::WorkerUpdates::All {
            self.observer.notify(event());
        }
    }

    fn queue_task(
        &self,
        input: &ArchiveInput,
        depth: usize,
        parent: Option<TaskId>,
        segment: impl FnOnce() -> Option<Segment>,
    ) -> TaskId {
        let id = self.engine.next_id();
        self.notify(|| Event::Queued {
            id,
            parent,
            path: PathBuf::from(&input.entry_path),
            depth,
            segment: segment(),
        });
        id
    }

    fn queue_inputs(&self, task: &Task, task_id: TaskId, depth: usize,
        previous: &[Option<&InputCheckpoint>], report_count: usize, has_retained: bool) -> Vec<TaskId> {
        let count = task.inputs.len();
        let position = |index: usize| previous.get(index).copied().flatten()
            .and_then(InputCheckpoint::report_position).unwrap_or(index + 1);
        let register = |index: usize| {
            if count == 1 { return task_id; }
            let input = &task.inputs[index].input;
            let extent = input.physical_extents().next();
            self.queue_task(input, depth, Some(task_id), || Some(Segment {
                format: input.format_hint.clone(), index: position(index), count: report_count,
                offset: extent.map_or(0, |extent| extent.start),
                end_offset: extent.and_then(|extent| extent.end),
            }))
        };
        // Main merges unchanged siblings into the selected display plan and
        // orders that merged plan by its stable positions. Those siblings are
        // already in our task.inputs: only registration order changes, never
        // input execution order. Ordinary and already ordered plans allocate no
        // extra ordering buffer.
        if has_retained && (1..count).any(|index| position(index - 1) > position(index)) {
            let mut order: Vec<_> = (0..count).collect();
            order.sort_by_key(|&index| position(index));
            let mut ids = vec![task_id; count];
            for index in order { ids[index] = register(index); }
            ids
        } else {
            (0..count).map(register).collect()
        }
    }

    fn replan_input(&self, task_id: TaskId, depth: usize, input: &ArchiveInput,
        previous: Option<&InputCheckpoint>) -> (TaskId, Option<TaskId>) {
        self.notify(|| Event::Replanned {
            id: task_id, path: PathBuf::from(&input.entry_path),
        });
        let Some(previous) = previous.filter(|checkpoint| !checkpoint.same_report_input(input)) else {
            return (task_id, None);
        };
        // main task_replanned registers the current input, then merges the
        // retained first attempt by stable position. No execution is queued.
        let segment = |input: &ArchiveInput, index| {
            let extent = input.physical_extents().next();
            Segment { format: input.format_hint.clone(), index, count: 2,
                offset: extent.map_or(0, |extent| extent.start),
                end_offset: extent.and_then(|extent| extent.end) }
        };
        let active = self.queue_task(input, depth, Some(task_id), || Some(segment(input, 1)));
        let retained = self.queue_task(previous.input(), depth, Some(task_id),
            || Some(segment(previous.input(), previous.report_position().unwrap_or(1))));
        if let Some(failure) = previous.failure() {
            self.notify(|| {
                let mut result = super::TaskCompletion::failed(failure);
                result.output = previous.has_output().then(|| previous.output().to_path_buf());
                Event::Finished { id: retained, path: previous.entry().to_path_buf(), depth, result }
            });
        }
        self.notify(|| Event::Started { id: active, path: PathBuf::from(&input.entry_path), depth });
        (active, Some(retained))
    }

    fn record_scan_errors(&self, errors: DirectoryReadErrors) -> bool {
        if errors.is_empty() {
            return false;
        }
        self.scan_errors.lock().unwrap().merge_report(errors);
        true
    }

    fn cleanup_owner(&self, task: &Task) -> CleanupOwner {
        let paths = if self.request.mode == Mode::Extract { task.owned_paths.as_slice() } else { &[] };
        CleanupOwner::new(Arc::clone(&self.cleanup_refs), paths)
    }

    #[cfg(test)]
    fn register_task(&self, task: Task) -> (Task, CleanupOwner, Option<HashSet<String>>, Option<Arc<WatchGenerations>>) {
        let sources = self.cleanup_owner(&task);
        (task, sources, None, None)
    }

    fn execute_task(
        self: &Arc<Self>,
        (mut task, mut sources, keys, requested): (Task, CleanupOwner, Option<HashSet<String>>, Option<Arc<WatchGenerations>>),
        task_id: TaskId,
        depth: usize,
        inherited_scope: Option<Arc<RecursiveScope>>,
        spawner: Spawner<'run>,
    ) -> super::scheduling::Task<'run, io::Result<Outcome>> {
        let owner = Arc::clone(self);
        Box::pin(async move {
            let this = &owner;
            let cancel = &this.request.cancel;
            cancel.check_io()?;
            stage("preflight", cancel).await?;
            let watch_root = depth == 1
                && this.request.origin == Origin::Watch
                && this.request.mode == Mode::Extract;
            let captured = requested.is_none().then(|| this.requested_generation(&task, watch_root)).flatten();
            let mut lease = this.claim_task(&task, keys).await?;
            if super::scheduling::in_stage() {
                cancel.check_io()?;
            } else {
                stage("preflight", cancel).await?;
            }
            let mut outcome = Outcome::default();
            let mut shell = this.engine.shell.branch();
            let (mut generations, missing) = this.capture_generations(&task);
            let discovered = task.source != DiscoverySource::Direct;
            let discovery_scope = task.scope.clone();
            let admission = this.task_admission(&task, &generations, &missing, discovered, watch_root,
                |path| requested.as_ref().and_then(|members| members.get(path))
                    .or_else(|| captured.as_ref().and_then(|members| members.get(path))))?;
            drop((requested, captured));
            let mut completed_family = match admission {
                TaskAdmission::Execute(family) => family,
                TaskAdmission::Departed => {
                    this.notify(|| Event::Skipped { id: task_id });
                    return Ok(outcome);
                }
                TaskAdmission::Completed(output) => {
                    this.reuse_completed_task(&task, task_id, depth, output, &mut outcome);
                    return Ok(outcome);
                }
            };
            this.notify(|| Event::Started {
                id: task_id,
                path: PathBuf::from(&task.entry().entry_path),
                depth,
            });
            let preflight_failures = if task.inputs.len() > 1
                && discovered && !missing.is_empty() {
                task.inputs.iter().map(|logical| logical.failure.clone()).collect::<Vec<_>>()
            } else { Vec::new() };
            this.admit_missing_inputs(&mut task, &missing, discovered);
            this.plan_inputs(&mut task)?;
            this.observer.claim_sources(
                Path::new(&task.entry().entry_path),
                &task.owned_paths,
                depth,
            )?;
            let owner_path = PathBuf::from(&task.entry().entry_path);
            let source_scope = inherited_scope.as_ref().and_then(|scope| scope.password.as_deref())
                .or_else(|| owner_path.parent());
            // Task preflight precedes segment queueing. Keep single missing-
            // volume failures on the existing one-replacement retry path.
            let admission = task.inputs.iter().all(|logical| logical.failure.as_ref().is_some_and(|failure|
                matches!(failure.context.as_deref(), Some(super::FailureContext::InputAdmission { .. }))));
            let discovery_blocked = task.inputs.iter().all(|logical| logical.failure.as_ref().is_some_and(|failure|
                matches!(failure.context.as_deref(), Some(super::FailureContext::Discovery { .. }))));
            let single_volume_retry = task.inputs.len() == 1 && task.inputs[0].failure.as_ref()
                .is_some_and(|failure| failure.contains(FailureKind::MissingVolume));
            if !single_volume_retry && (admission || discovery_blocked) {
                let failure = task.inputs[0].failure.as_ref().expect("task preflight failure");
                // task_started in main registers segment rows even when task
                // preflight prevents execution. Queued here only registers the
                // observer row; no segment is submitted to the scheduler.
                if task.inputs.len() > 1 {
                    for (index, id) in this.queue_inputs(&task, task_id, depth, &[], task.inputs.len(), false).into_iter().enumerate() {
                        let logical = &task.inputs[index];
                        let original = if discovery_blocked { logical.failure.as_ref() }
                            else { preflight_failures.get(index).and_then(Option::as_ref) };
                        this.notify(|| Event::Finished {
                            id, path: PathBuf::from(&logical.input.entry_path), depth,
                            result: original.map_or_else(|| super::TaskCompletion {
                                discovery: None, status: super::TaskStatus::Skipped, failure: None, output: None,
                            }, super::TaskCompletion::failed),
                        });
                    }
                }
                let mut completed: Vec<_> = if this.request.mode == Mode::Scan || discovery_blocked {
                    // main scan_items still projects every original descriptor.
                    task.inputs.iter().enumerate().map(|(index, logical)| {
                        let mut result = receipt(&logical.input, task.source, depth);
                        result.password = logical.password.as_deref().map(str::to_owned);
                        result.volume_attempts = logical.input.volume_attempts.clone();
                        // scan_items gives the original node failure precedence
                        // over the terminal task's admission failure.
                        result.failure = if discovery_blocked { logical.failure.clone() }
                            else { preflight_failures.get(index).cloned().flatten() };
                        result
                    }).collect()
                } else {
                    vec![receipt(task.entry(), task.source, depth)]
                };
                for result in &mut completed {
                    result.failure.get_or_insert_with(|| failure.clone());
                    if this.request.mode == Mode::Extract {
                        if admission { result.source_paths = task.owned_paths.iter().map(PathBuf::from).collect(); }
                        if let Some(scope) = discovery_scope.as_deref() {
                            result.failure.as_mut().unwrap().discovery_scope =
                                Some(Box::new(super::FailureScope::from_scope(scope)));
                        }
                    }
                }
                if this.request.mode == Mode::Extract && depth > 1 && !cancel.cancelled()
                    && completed.iter().any(|result| result.failure.as_ref().is_some_and(|failure|
                        failure.is_password_retry() || failure.contains(FailureKind::MissingVolume)))
                {
                    let destination = this.promotion_directory(&owner_path, inherited_scope.as_deref());
                    drop(lease);
                    lease = this.engine.leases.acquire(
                        task.owned_paths.iter().map(|path| resolved_key(Path::new(path))).collect(),
                        cancel,
                    ).await?;
                    this.promote_blocked(&task.owned_paths, &destination,
                        completed.iter_mut(), &mut outcome, &mut shell).await?;
                }
                outcome.promoted_sources.extend(task.owned_paths.iter().filter_map(|path|
                    this.admitted_promotion(path, &generations, watch_root)));
                drop(lease);
                this.notify(|| {
                    let mut completion = if discovery_blocked {
                        super::TaskCompletion::from_group(&completed)
                    } else { super::TaskCompletion::from_result(&completed[0]) };
                    if admission && this.request.mode == Mode::Scan { completion.failure = Some(failure.clone()); }
                    Event::Finished { id: task_id, path: owner_path.clone(), depth, result: completion }
                });
                if this.request.mode == Mode::Scan {
                    outcome.scan_failures.push(ScanTaskFailure {
                        path: owner_path,
                        archives: 0..completed.len(),
                        preflight: Some(Box::new(failure.clone())),
                    });
                }
                outcome.archives = completed.into();
                if depth == 1 && this.request.mode == Mode::Extract && !cancel.cancelled() {
                    outcome.archives = this.observer.scope_finished(task_id,
                        std::mem::take(&mut outcome.archives).into_vec()).await?.into();
                }
                return Ok(outcome);
            }
            let candidates = this.candidates.with_scope(source_scope);
            let multi = task.inputs.len() > 1;
            let preferred_carrier = (this.request.mode == Mode::Extract && (multi || !this.checkpoints.is_empty()))
                .then(|| this.preferred_output(task.entry(), depth));
            let report_previous = this.select_checkpoints(&owner_path, &task.inputs);
            let mut retained: Vec<_> = task
                .inputs
                .iter().zip(&report_previous)
                .map(|(logical, previous)| {
                    if this.request.mode != Mode::Extract || logical.failure.as_ref().is_some_and(|failure|
                        matches!(failure.context.as_deref(), Some(super::FailureContext::InputAdmission { .. })))
                    { None } else {
                        previous.and_then(|previous| this.checkpoint_for(&logical.input, Some(previous), &generations,
                            preferred_carrier.as_deref().expect("extract recovery has a preferred output"), depth, &candidates))
                    }
                })
                .collect();
            let mut split_input = task.entry().mode.structured() || task.entry().physical_paths().nth(1).is_some();
            let count = task.inputs.len();
            let mut had_checkpoints = report_previous.iter().any(Option::is_some);
            let continued_output = retained.iter().flatten().any(|checkpoint| checkpoint.continuable_output());
            let report_count = if continued_output {
                report_previous.iter().flatten().map(|checkpoint| checkpoint.report_input_count())
                    .max().unwrap_or(0).max(count)
            } else { count };
            let ids = this.queue_inputs(&task, task_id, depth, &report_previous, report_count, retained.iter().any(Option::is_some));
            let mut carrier = if this.request.mode == Mode::Extract && multi {
                let existing = retained
                    .iter()
                    .flatten()
                    .find_map(|checkpoint| checkpoint.retained_container())
                    .map(Path::to_path_buf);
                match existing {
                    Some(path) => Some(path),
                    None if task.inputs.iter().zip(&retained)
                        .any(|(input, checkpoint)| checkpoint.is_none() && input.failure.is_none()) => {
                        let receipt = receipt(task.entry(), task.source, depth);
                        match this.reserve_output(preferred_carrier.expect("carrier has a preferred output"), &receipt, None)? {
                            Ok(path) => {
                                shell.output(&path);
                                Some(path)
                            }
                            Err(failure) => {
                                for logical in &mut task.inputs {
                                    logical.failure.get_or_insert_with(|| failure.clone());
                                }
                                None
                            }
                        }
                    }
                    None => None,
                }
            } else {
                None
            };
            // A retry can invalidate the old result without invalidating its
            // output slot. Main keeps those slots only inside a carrier whose
            // unchanged siblings already justified retaining the root.
            let retry_slots: Vec<_> = task.inputs.iter().zip(&retained).zip(&report_previous)
                .map(|((logical, checkpoint), previous)| {
                    checkpoint.is_none().then(|| carrier.as_deref()
                        .and_then(|root| this.retry_slot_for(&logical.input, *previous, root))).flatten()
                })
                .collect();
            // Reserve logical names in input order before discovery/password
            // failures can return. A planned slot is not a physical output.
            let mut planned_slots = vec![None; count];
            if let Some(root) = carrier.as_deref() {
                for (index, logical) in task.inputs.iter_mut().enumerate() {
                    let previous = retained[index].or(retry_slots[index])
                        .filter(|checkpoint| checkpoint.container() == Some(root))
                        .and_then(InputCheckpoint::output_slot);
                    let slot = previous.filter(|path| OutputNames::retain(&this.output_names.registry,
                        path, this.output_names.owner, Path::new(&logical.input.entry_path), Some(root),
                    ));
                    if let Some(slot) = slot {
                        planned_slots[index] = Some(slot.to_owned());
                    } else {
                        match OutputNames::plan(&this.output_names.registry, root.join(archive_name(&logical.input)), Path::new(&logical.input.entry_path),
                            this.output_names.owner, Some(root))?
                        {
                            Ok(slot) => planned_slots[index] = Some(slot),
                            Err(failure) => { logical.failure.get_or_insert(failure); }
                        }
                    }
                }
            }
            let mut parent_outputs = Vec::with_capacity(count);
            let report_enabled = this.request.mode == Mode::Extract && task.owned_paths.iter()
                .all(|path| generations.contains_key(&path_key(path)));
            let mut report_states = Vec::with_capacity(count);
            let mut replacement_retained = None;
            let mut replacement_rows = None;
            let retry = task.retry.filter(|_| task.inputs.len() == 1);
            let mut replacement_entry = None;
            let mut promotion_sources = task.owned_paths;
            let mut superseded_candidates = HashSet::new();
            for (index, (((logical, checkpoint), retry_slot), &original_id)) in
                task.inputs.into_iter().zip(retained.drain(..)).zip(retry_slots).zip(&ids).enumerate()
            {
                let mut id = original_id;
                if multi {
                    this.notify(|| Event::Started {
                        id,
                        path: PathBuf::from(&logical.input.entry_path),
                        depth,
                    });
                }
                let before_worker = logical.failure.is_some();
                let mut attempted = logical.input.volume_attempts.as_ref().map(|_| {
                    logical
                        .input
                        .physical_paths()
                        .map(path_key)
                        .collect::<Vec<_>>()
                });
                let mut executed = if let Some(checkpoint) = checkpoint {
                    let input = checkpoint.shared_input();
                    let mut result = checkpoint.result(depth);
                    if multi && checkpoint.container() != carrier.as_deref() && result.failure.is_some() {
                        // A purely failed old carrier is not a reusable output
                        // root. Carry its logical failure, not its output slot.
                        result.output = None;
                    }
                    if let Some(failure) = result.failure.as_ref() {
                        // Receipts preserve extraction facts, not the old policy's
                        // acceptance decision. Main reevaluates retained results
                        // after a content-policy reload in either direction.
                        result.partial = result.output.is_some()
                            && accepts_partial_content(
                                this.request.config.extraction.content_requirement,
                                failure.kind, result.recovered_complete_files,
                            );
                    }
                    // Main never rediscovers retained outputs on a sibling retry.
                    // The previous attempt already owned their recursive work.
                    Executed {
                        planned_output: result.output.clone(),
                        input,
                        result,
                        inventory: None,
                    }
                } else {
                    let retry_output = if let Some(previous) = retry_slot {
                        stage("preflight", cancel).await?;
                        let result = previous.result(depth);
                        let slot = previous.output_slot().expect("selected retry slot");
                        let cleared = !previous.has_output()
                            || this.discard_failed_output(&result, slot, &mut outcome)?;
                        // Main records cleanup errors but still executes this
                        // selected input in its fixed slot. Never turn the old
                        // result into a receipt for the changed dependencies.
                        Some(if cleared { RetryOutput::Recreate(slot) }
                             else { RetryOutput::Existing(slot) })
                    } else { planned_slots[index].as_deref().map(RetryOutput::Recreate) };
                    this.execute_input(
                        logical,
                        id,
                        task.source,
                        depth,
                        carrier.as_deref(),
                        retry_output,
                        &candidates,
                        &mut shell,
                        &mut outcome,
                    )
                    .await?
                };
                let mut replacement_checkpoint = None;
                if let Some(context) = retry.as_deref().filter(|_| {
                    !cancel.cancelled()
                        && !multi
                        && (before_worker || this.request.mode == Mode::Extract)
                        && executed
                            .result
                            .failure
                            .as_ref()
                            .is_some_and(|failure| failure.kind == FailureKind::MissingVolume)
                }) {
                    this.notify(|| Event::ResolvingVolumes { id });
                    stage("missing_volume", cancel).await?;
                    if let Some(mut replacement) = discovery::retry_volume(
                        &executed.result,
                        &missing,
                        context,
                        this.options_at(depth)?,
                        &candidates,
                        &this.request,
                    )? {
                        // Main replaces the whole single-input extraction only
                        // after resolving a usable physical family. Until then,
                        // its damaged payload remains available for recovery.
                        let retry_output = executed.planned_output.clone();
                        // checkpoint_inputs runs before the replacement callback
                        // in main. Capture the first attempt with its own lease
                        // generation, not the generation of the replacement.
                        let first_checkpoint = if report_enabled && !before_worker {
                            InputCheckpoint::create(&owner_path, Arc::clone(&executed.input), &executed.result, &generations, carrier.as_deref())
                                .and_then(|mut checkpoint| {
                                    let state = InputCheckpoint::report_state(&executed.input,
                                        &executed.result, retry_output.as_deref(),
                                        report_previous[index], index + 1, report_count)?;
                                    checkpoint.install_report(Some(state));
                                    Some(checkpoint)
                                })
                        } else { None };
                        let cleaned = match retry_output.as_deref() {
                            Some(output) => this.discard_failed_output(&executed.result, output, &mut outcome)?,
                            None => true,
                        };
                        if cleaned {
                            replacement_checkpoint = first_checkpoint;
                            had_checkpoints |= replacement_checkpoint.is_some();
                            executed.result.output = None;
                            this.observer.after_output(&executed.result)?;
                            if this.request.mode == Mode::Extract { sources.refresh(&replacement.owned_paths); }
                            drop(lease);
                            let requested = this.requested_generation(&replacement, watch_root);
                            lease = this.claim_task(&replacement, None).await?;
                            stage("preflight", cancel).await?;
                            let (current_generations, missing) = this.capture_generations(&replacement);
                            generations = current_generations;
                            let admission = this.task_admission(&replacement, &generations, &missing, discovered, watch_root,
                                |path| requested.as_ref().and_then(|members| members.get(path)))?;
                            drop(requested);
                            completed_family = match admission {
                                TaskAdmission::Execute(family) => family,
                                TaskAdmission::Departed => {
                                    this.notify(|| Event::Skipped { id: task_id });
                                    return Ok(outcome);
                                }
                                TaskAdmission::Completed(output) => {
                                    this.reuse_completed_task(&replacement, task_id, depth, output, &mut outcome);
                                    return Ok(outcome);
                                }
                            };
                            this.admit_missing_inputs(&mut replacement, &missing, discovered);
                            this.observer.claim_sources(
                                Path::new(&replacement.entry().entry_path),
                                &replacement.owned_paths,
                                depth,
                            )?;
                            attempted = replacement.entry().volume_attempts.as_ref().map(|_| {
                                replacement
                                    .entry()
                                    .physical_paths()
                                    .map(path_key)
                                    .collect::<Vec<_>>()
                            });
                            split_input = replacement.entry().mode.structured()
                                || replacement.entry().physical_paths().nth(1).is_some();
                            promotion_sources = std::mem::take(&mut replacement.owned_paths);
                            replacement_entry = Some(PathBuf::from(&replacement.entry().entry_path));
                            let (active, retained) = this.replan_input(task_id, depth,
                                replacement.entry(), replacement_checkpoint.as_ref());
                            id = active;
                            replacement_rows = retained.map(|retained| (active, retained));
                            let logical = replacement
                                .inputs
                                .into_iter()
                                .next()
                                .expect("volume retry has one logical input");
                            executed = this
                                .execute_input(
                                    logical,
                                    id,
                                    replacement.source,
                                    depth,
                                    None,
                                    retry_output.as_deref().map(RetryOutput::Recreate),
                                    &candidates,
                                    &mut shell,
                                    &mut outcome,
                                )
                                .await?;
                        }
                    }
                }
                let Executed {
                    planned_output,
                    mut result,
                    inventory,
                    mut input,
                } = executed;
                if this.request.mode == Mode::Scan {
                    result.scan_layout = super::ScanLayout::from_input(&input);
                    result.volume_attempts = Arc::make_mut(&mut input).volume_attempts.take();
                    if result
                        .failure
                        .as_ref()
                        .is_some_and(|failure| failure.kind == FailureKind::MissingVolume)
                    {
                        result.volume_completeness =
                            Some(VolumeCompleteness::Missing.as_str().to_owned());
                    }
                }
                if result.failure.is_none() {
                    superseded_candidates.extend(attempted.into_iter().flatten());
                }
                let replacement_matches = replacement_checkpoint.as_ref()
                    .is_some_and(|previous| previous.same_report_input(&input));
                let state_previous = if replacement_checkpoint.is_some() {
                    replacement_checkpoint.as_ref().filter(|_| replacement_matches)
                } else { report_previous[index].or(checkpoint).or(retry_slot) };
                let keeps_replaced = replacement_checkpoint.is_some() && !replacement_matches;
                if report_enabled && (multi || result.failure.is_some() || keeps_replaced) {
                    // An ordinary successful input cannot be retried from its
                    // own receipt. Nested blockers keep their own checkpoints.
                    let mut state = InputCheckpoint::report_state(&input, &result,
                        planned_output.as_deref().or(planned_slots[index].as_deref()),
                        state_previous, index + 1, report_count);
                    if result.retained && result.output.is_none() && checkpoint.is_some_and(|checkpoint| checkpoint.has_output()) {
                        InputCheckpoint::clear_report_output(&mut state);
                    }
                    report_states.push(state);
                } else {
                    report_states.push(None);
                }
                if keeps_replaced {
                    // A different logical ID leaves the failed first attempt
                    // in the carrier result even when its replacement succeeds.
                    replacement_retained = replacement_checkpoint;
                }
                // Segment progress ends with its own extraction, as main's
                // input_finished does. Physical root completion still waits
                // for every recursive subtree and the final source cleanup.
                if multi || replacement_rows.is_some() {
                    this.notify(|| Event::Finished {
                        id,
                        path: result.path.clone(),
                        depth,
                        result: super::TaskCompletion::from_result(&result),
                    });
                }
                parent_outputs.push((result, inventory, input, id));
            }
            // Preserve checkpoint insertion order without moving later child
            // receipts: the first attempt precedes its replacement in main.
            let replacement_retained = replacement_retained.map(|previous| {
                let index = outcome.checkpoints.len();
                outcome.checkpoints.push(previous);
                index
            });
            this.apply_complete_content_policy(&mut parent_outputs, &mut report_states,
                replacement_retained, &mut outcome)?;
            // Settle physical ownership before any successful sibling descends.
            // Promoted retryable sources remain failures, but no longer block
            // flattening the independent retained output subtree.
            let mut parent_checkpoints: Vec<_> = parent_outputs.iter().enumerate()
                .map(|(index, (result, _, input, _))| {
                    let mut checkpoint = (this.request.mode == Mode::Extract
                        && (multi || result.failure.is_some() || replacement_retained.is_some())).then(||
                            InputCheckpoint::create(&owner_path, Arc::clone(input), result, &generations, carrier.as_deref())).flatten();
                    if let Some(checkpoint) = &mut checkpoint {
                        checkpoint.install_report(report_states[index].take());
                        checkpoint.set_planned_output(planned_slots[index].as_deref());
                        checkpoint.set_password_signature(|| candidates.signature(&input.entry_path));
                    }
                    checkpoint
                }).collect();
            let mut replacement_result = replacement_retained.map(|index| {
                let mut retained = outcome.checkpoints[index].result(depth);
                // These are two logical input IDs of the same replanned carrier,
                // not two independent top-level paths in the result tree.
                if let Some((current, ..)) = parent_outputs.first() { retained.path = current.path.clone(); }
                retained.partial = retained.failure.as_ref().is_some_and(|failure|
                    accepts_partial_content(this.request.config.extraction.content_requirement,
                        failure.kind, retained.recovered_complete_files));
                retained
            });
            let settled = || parent_outputs.iter().map(|(result, ..)| result)
                .chain(replacement_result.iter());
            if !superseded_candidates.is_empty() {
                let retained: HashSet<_> = settled()
                    .flat_map(|result| {
                        result
                            .source_paths
                            .iter()
                            .map(|path| path_key(&path.to_string_lossy()))
                    })
                    .collect();
                promotion_sources.retain(|path| {
                    !superseded_candidates.contains(&path_key(path))
                        || retained.contains(&path_key(path))
                });
                if this.request.mode == Mode::Extract { sources.refresh(&promotion_sources); }
            }
            if depth > 1
                && !cancel.cancelled()
                // Accepted partial segments do not make a carrier successful
                // when a sibling failed. Only an entirely accepted carrier
                // stays in place; promotion retains its sibling outputs.
                && settled().any(|result| result.failure.is_some() && !result.partial)
                && settled().any(|result| {
                    result.failure.as_ref().is_some_and(|failure| {
                        failure.is_password_retry() || failure.contains(FailureKind::MissingVolume)
                    })
                })
            {
                let destination = this.promotion_directory(&owner_path, inherited_scope.as_deref());
                // Release this task's read pin before upgrading. Sibling readers
                // may finish concurrently; publishing a moved source is exclusive.
                drop(lease);
                lease = this.engine.leases.acquire(
                    promotion_sources.iter().map(|path| resolved_key(Path::new(path))).collect(),
                    cancel,
                ).await?;
                let promoted_paths = this.promote_blocked(
                    &promotion_sources,
                    &destination,
                    parent_outputs.iter_mut().map(|(result, ..)| result)
                        .chain(replacement_result.iter_mut()),
                    &mut outcome,
                    &mut shell,
                )
                .await?;
                if let Some(paths) = promoted_paths {
                    for checkpoint in parent_checkpoints.iter_mut().flatten() { checkpoint.promoted(&paths)?; }
                }
            }
            // A replaced attempt is report history after successful cleanup,
            // not a failed input of the replacement's physical execution.
            let physical_complete = parent_outputs.iter()
                .all(|(result, ..)| result.failure.is_none() && !result.partial);
            let promoted = parent_outputs.iter().map(|(result, ..)| result)
                .chain(replacement_result.iter()).all(|result| result.promoted);
            let parent_outputs = parent_outputs.into_iter()
                .map(|(result, inventory, _input, id)| (result, inventory, id));
            // Finish every logical parent before prompting or descending into
            // any segment. Independent output trees share the existing request
            // consumer budget rather than serializing behind the first subtree.
            let parent_output_count = parent_outputs.len();
            let mut recursive = Vec::new();
            let mut descendants = Vec::with_capacity(count);
            for (index, (result, inventory, id)) in parent_outputs.enumerate() {
                if let Some(inventory) = inventory.filter(|_| depth <= this.request.max_depth && !cancel.cancelled()) {
                    recursive.push(((index, result, id), inventory));
                } else {
                    descendants.push((index, Ok((result, Outcome::default(), false))));
                }
            }
            let recursive_spawner = spawner.clone();
            let scope = if recursive.is_empty() {
                None
            } else {
                inherited_scope.clone().or_else(|| Some(Arc::new(RecursiveScope {
                    password: source_scope.map(Arc::from),
                    promotion: this.promotion_directory(
                        replacement_entry.as_deref().unwrap_or(&owner_path), None,
                    ),
                })))
            };
            if !recursive.is_empty() {
                let candidates = this.candidates.with_scope(scope.as_ref().and_then(|scope| scope.password.as_deref()));
                let recursive = this.discover_children_many(recursive.into_iter(), depth, &candidates).await?;
                let descendant_owner = Arc::clone(this);
                let descend = move |((index, result, id), nested, scanned)| -> super::scheduling::Task<'_, _> {
                    let this = Arc::clone(&descendant_owner);
                    let spawner = recursive_spawner.clone();
                    let scope = scope.clone();
                    Box::pin(async move {
                        let branch = if scanned {
                            this.execute_batch(nested, depth + 1, scope, Some(id), spawner, None)
                                .await.map(|descendants| (result, descendants, true))
                        } else {
                            let descendants = Outcome {
                                errors: nested.errors.into(),
                                scan_incomplete: this.record_scan_errors(nested.scan_errors),
                                ..Outcome::default()
                            };
                            Ok((result, descendants, false))
                        };
                        (index, branch)
                    })
                };
                // Single-output archives keep their consumer. Carrier branches
                // share the request's existing recursive consumer budget.
                if recursive.len() == 1 {
                    descendants.push(descend(recursive.into_iter().next().unwrap()).await);
                } else {
                    descendants.extend(spawner.bounded_map(recursive, descend).await);
                }
            }
            // Cancellation may leave recursive outputs undispatched. Their
            // existing carrier receipts must stay owned for request rollback.
            // Join every writer before committing or cleaning up, then restore
            // logical segment order, including segments with no recursive work.
            descendants.sort_unstable_by_key(|(index, _)| *index);
            let mut completed = Vec::with_capacity(count);
            let mut outputs_committed = descendants.len() == parent_output_count;
            let mut carrier_children_complete = outputs_committed;
            let mut children = Outcome::default();
            for (index, descendant) in descendants {
                let (mut result, mut descendants, ran_recursive_children) = descendant?;
                stage("output_state", &Cancellation::new()).await?;
                let mut children_complete = !cancel.cancelled() && descendants.subtree_complete();
                if result.failure.is_none() && children_complete && !cancel.cancelled()
                {
                    if let Some(output) = result.output.as_deref() {
                        if ran_recursive_children {
                            this.drain_cleanup(Some(output), &mut descendants).await;
                            stage("postprocess", cancel).await?;
                        }
                        if output_is_gone(output, ran_recursive_children) {
                            this.observer.discard_output(&result.path, &result.source_paths, output)?;
                            this.created_outputs.lock().unwrap().commit(output);
                            result.output = None;
                        }
                    }
                }
                // A carrier's segments are independent output trees. Their
                // containers must keep the original layout for continuation.
                if !multi
                    && !result.retained
                    && result.failure.is_none()
                    && this.request.config.post_extract.flatten_single_directory
                    && children_complete
                    && !cancel.cancelled()
                {
                    if let Some(output) = result.output.as_deref() {
                        this.drain_cleanup(Some(output), &mut descendants).await;
                    }
                    stage("postprocess", cancel).await?;
                    flatten_result(
                        &*this.observer, task_id, &mut result, &mut descendants, Some(&this.created_outputs), &this.output_names,
                    )?;
                    children_complete &= descendants.subtree_complete();
                }
                carrier_children_complete &= children_complete;
                let mut checkpoint = parent_checkpoints[index].take();
                if let Some(checkpoint) = &mut checkpoint { checkpoint.settle_result(&result); }
                // A cancelled newly created root remains uncommitted until
                // request-level rollback has joined all recursive writers.
                let commit_completed = !cancel.cancelled();
                outputs_committed &= commit_completed || result.retained || result.output.is_none();
                if commit_completed || result.retained {
                    this.observer.after_output(&result)?;
                    // Cancellation after this durable commit must not roll it
                    // back. Match main's commit/check then retire ordering.
                    if commit_completed && !multi && physical_complete {
                        if let Some(output) = result.output.as_deref() {
                            this.created_outputs.lock().unwrap().commit_if_unowned(output);
                        }
                    }
                }
                if let Some(checkpoint) = checkpoint {
                    outcome.checkpoints.push(checkpoint);
                }
                children.checkpoints.append(&mut descendants.checkpoints);
                outcome
                    .promoted_sources
                    .append(&mut descendants.promoted_sources);
                children.archives.append(&mut descendants.archives);
                children.errors.append(&mut descendants.errors);
                children.scan_incomplete |= descendants.scan_incomplete;
                children.uncommitted |= descendants.uncommitted;
                children
                    .cleanup_results
                    .append(&mut descendants.cleanup_results);
                completed.push(result);
            }
            if let Some(retained) = replacement_result { completed.push(retained); }
            // Only the final carrier namespace is flattened. Individual segment
            // layouts remain intact while any input or recursive subtree may resume.
            if multi && outputs_committed && carrier_children_complete
                && (promoted || completed.iter().all(|result| result.failure.is_none()))
                && !continued_output
                && this.request.config.post_extract.flatten_single_directory
                && !cancel.cancelled()
            {
                if let Some(root) = carrier.clone().filter(|_| completed.iter().any(|result| result.output.is_some())) {
                    this.drain_cleanup(Some(&root), &mut children).await;
                    stage("postprocess", cancel).await?;
                    children.archives.append(&mut std::mem::take(&mut completed).into());
                    let has_local_checkpoints = outcome.checkpoints.len() != 0;
                    children.checkpoints.append(&mut outcome.checkpoints);
                    let input = ArchiveInput::file(owner_path.to_string_lossy().into_owned(), String::new(), String::new());
                    let mut container = receipt(&input, task.source, depth);
                    container.output = Some(root.clone());
                    let flattened = flatten_result(&*this.observer, task_id, &mut container, &mut children, Some(&this.created_outputs), &this.output_names);
                    completed = children.archives.take_tail();
                    if has_local_checkpoints {
                        outcome.checkpoints = children.checkpoints.take_tail().into();
                    }
                    carrier = container.output;
                    flattened?;
                }
            }
            if multi && outputs_committed && children.settled()
                && completed.iter().all(|result| !result.failure.as_ref()
                    .is_some_and(|failure| failure.kind == FailureKind::Cancelled))
            {
                if let Some(root) = carrier.as_ref().filter(|_| {
                    completed.iter().any(|result| result.output.is_some())
                }) {
                    // The segments have separate receipts. Retire the carrier
                    // registration too, before its ancestors can commit and
                    // source cleanup can consume the archive.
                    // An accepted segment keeps the shared container's Watch
                    // receipt. A purely failed carrier retains bytes only.
                    let accepted = completed.iter().position(|result|
                        result.output.is_some() && (result.failure.is_none() || result.partial));
                    let index = accepted.or_else(|| completed.iter().position(|result| result.output.is_some()))
                        .expect("carrier has a retained output");
                    let first = &mut completed[index];
                    let segment = first.output.replace(root.clone());
                    let published = this.observer.after_output(first);
                    first.output = segment;
                    published?;
                }
                // Only physical complete success retires rollback ownership
                // early. Accepted partial/salvage bytes survive normal request
                // completion, but a later cancelled sibling must discard them.
                if physical_complete {
                    let mut created = this.created_outputs.lock().unwrap();
                    if let Some(root) = carrier.as_deref() {
                        created.commit_if_unowned(root);
                    }
                    for output in completed.iter().filter_map(|result| result.output.as_deref()) {
                        created.commit_if_unowned(output);
                    }
                }
            }
            if let Some(root) = &carrier {
                if completed.iter().all(|entry| entry.output.is_none()) {
                    if output_is_gone(root, true) {
                        if let Some(result) = completed.first() {
                            this.observer.discard_output(&result.path, &result.source_paths, root)?;
                            this.created_outputs.lock().unwrap().commit(root);
                        }
                    }
                }
            }
            if this.request.mode == Mode::Extract {
                if let Some(scope) = discovery_scope.as_deref() {
                    for failure in completed.iter_mut().filter_map(|result| result.failure.as_mut()) {
                        if failure.discovery_scope.is_none() {
                            failure.discovery_scope = Some(Box::new(super::FailureScope::from_scope(scope)));
                        }
                    }
                }
            }
            if this.request.mode == Mode::Extract && completed.iter().any(|result| result.failure.is_some()) {
                // Receipts have already followed promotion/flatten. Preserve the
                // pre-cleanup facts, but do not reconstruct them from final IO.
                let retry_output = continued_output || ((multi || had_checkpoints) && completed.iter().any(|result|
                    result.output.is_some() && (result.failure.is_none() || result.partial)));
                if let Some(recovery) = InputRecovery::capture(&outcome.checkpoints,
                    &owner_path, completed.first().map(|result| result.path.as_path()),
                    carrier.as_deref(), report_count, had_checkpoints, retry_output)
                {
                    for failure in completed.iter_mut().filter_map(|result| result.failure.as_mut()) {
                        if matches!(failure.context.as_deref(), Some(super::FailureContext::Postprocess { .. })) && !failure.causes.is_empty() {
                            failure.causes[0].recovery = Some(Arc::clone(&recovery));
                        } else {
                            failure.recovery = Some(Arc::clone(&recovery));
                        }
                    }
                }
            }
            // Cleanup belongs to this physical source family, not its output
            // descendants. A failed/partial inner archive must keep its own
            // source, but does not revoke a fully extracted outer source.
            let sources_complete = completed
                .iter()
                .all(|result| result.failure.is_none() && !result.partial)
                && !cancel.cancelled();
            // A Watch request may have been admitted before another batch moved
            // these members. The source leases now cover the actual resolved family.
            let admitted_promoted: Vec<_> = promotion_sources
                .iter()
                .filter_map(|path| {
                    this.admitted_promotion(path, &generations, watch_root)
                        .map(|source| (path, source))
                })
                .collect();
            let mut root_cleanup = None;
            if sources_complete && this.request.mode == Mode::Extract {
                if let Some(family) = completed_family {
                    stage("output_state", &Cancellation::new()).await?;
                    this.observer.sources_processed(family,
                        carrier.as_deref().or_else(|| completed.iter().find_map(|result| result.output.as_deref())))?;
                }
                let cleanup_paths = sources.release(true);
                let mode = if depth > 1 { CleanupMode::Delete }
                    else { this.request.config.post_extract.archive_cleanup_mode };
                let generated: HashSet<_> = admitted_promoted.iter().map(|(path, _)| (*path).clone()).collect();
                let mut deletes = Vec::new();
                let mut recycles = Vec::new();
                for path in &promotion_sources {
                    if !cleanup_paths.contains(&namespace_key(Path::new(path))) { continue; }
                    if mode == CleanupMode::Delete || generated.contains(path) {
                        deletes.push(PathBuf::from(path));
                    } else if mode == CleanupMode::Recycle {
                        recycles.push(PathBuf::from(path));
                    }
                }
                dedup_paths(&mut deletes);
                dedup_paths(&mut recycles);
                if deletes.is_empty() && recycles.is_empty() {
                    drop(lease);
                } else {
                    let paths = (!watch_root).then(|| deletes.iter().chain(&recycles).cloned().collect());
                    let cleanup = Arc::clone(this);
                    let work = async move {
                        // Keep other requests off these sources until cleanup
                        // finishes. CleanupRefs has already released the last
                        // planned owner of each path in this request.
                        let _sources = lease;
                        let mut failures = Vec::new();
                        if stage("background_source_cleanup", &cleanup.request.cancel).await.is_ok() {
                            let mut shell = cleanup.engine.shell.branch();
                            cleanup.cleanup_sources(&recycles, CleanupMode::Recycle, &mut failures, &mut shell);
                            cleanup.cleanup_sources(&deletes, CleanupMode::Delete, &mut failures, &mut shell);
                        }
                        failures
                    };
                    if let Some(paths) = paths {
                        // Register under the same lock used by retirement.
                        let mut tasks = this.cleanup_tasks.lock().unwrap();
                        let id = tasks.next_id;
                        tasks.next_id += 1;
                        let cleanup = Arc::clone(this);
                        let task = spawner.spawn(Box::pin(async move {
                            let failures = work.await;
                            cleanup.cleanup_tasks.lock().unwrap().retire(id, failures)
                        }));
                        tasks.active.insert(id, PendingCleanup { paths, task });
                    } else {
                        root_cleanup = Some(spawner.spawn(Box::pin(work)));
                    }
                }
            } else {
                outcome.promoted_sources.extend(admitted_promoted.into_iter().map(|(_, source)| source));
                drop(lease);
            }
            if this.request.mode == Mode::Extract {
                project_possible_missing_volume(&mut completed, split_input);
            }
            // Refresh segment rows after carrier policy, promotion and flattening,
            // just as main's task_finished refreshes its input_results.
            if multi {
                for (&id, result) in ids.iter().zip(&completed) {
                    this.notify(|| Event::Finished {
                        id, path: result.path.clone(), depth,
                        result: super::TaskCompletion::from_result(result),
                    });
                }
            }
            if let Some((active, retained)) = replacement_rows {
                // The execution result stays first and the retained first
                // attempt is appended to the physical result group.
                for (id, result) in [active, retained].into_iter().zip(&completed) {
                    this.notify(|| Event::Finished { id, path: result.path.clone(), depth,
                        result: super::TaskCompletion::from_result(result) });
                }
            }
            if let Some(result) = completed.first() {
                if this.request.mode == Mode::Scan && completed.iter().any(|result| result.failure.is_some()) {
                    outcome.scan_failures.push(ScanTaskFailure {
                        path: if multi { owner_path.clone() } else { result.path.clone() },
                        archives: 0..completed.len(),
                        preflight: None,
                    });
                }
                this.notify(|| Event::Finished {
                    id: task_id,
                    path: if multi {
                        owner_path
                    } else {
                        result.path.clone()
                    },
                    depth,
                    result: {
                        let mut completion = super::TaskCompletion::from_group(&completed);
                        // A carrier's physical container is not derivable from
                        // the surviving segment paths when only one succeeded.
                        if multi && completion.output.is_some() {
                            completion.output = carrier.clone();
                        }
                        completion
                    },
                });
            }
            // Recovery is local to a physical carrier. Successful, committed
            // subtrees need no input plans retained by their ancestors; blocked
            // descendants and same-carrier success siblings still keep theirs.
            if outputs_committed && !cancel.cancelled()
                && completed.iter().all(|result| result.failure.is_none() && !result.partial)
                && children.subtree_complete() && children.checkpoints.len() == 0
            {
                outcome.checkpoints = Default::default();
            }
            // Capture above visits only this carrier's receipts, never its
            // descendant tree. Splice outstanding descendant ownership last.
            outcome.checkpoints.append(&mut children.checkpoints);
            outcome.archives.append(&mut completed.into());
            outcome.archives.append(&mut children.archives);
            outcome.errors.append(&mut children.errors);
            outcome.scan_incomplete |= children.scan_incomplete;
            outcome
                .cleanup_results
                .append(&mut children.cleanup_results);
            outcome.uncommitted = !outputs_committed || children.uncommitted;
            // Watch releases this root's admission claim after publication.
            // Its source cleanup shares the task lease until it has finished.
            if let Some(cleanup) = root_cleanup {
                for failure in cleanup.wait().await {
                    record_cleanup_failure(&mut outcome, failure);
                }
            }
            if depth == 1 && this.request.mode == Mode::Extract && !cancel.cancelled() {
                outcome.archives = this
                    .observer
                    .scope_finished(task_id, std::mem::take(&mut outcome.archives).into_vec())
                    .await?.into();
            }
            Ok(outcome)
        })
    }

    fn promotion_directory(&self, entry: &Path, inherited: Option<&RecursiveScope>) -> Arc<Path> {
        if let Some(scope) = inherited {
            Arc::clone(&scope.promotion)
        } else {
            self.target_directories.directory_for(entry)
        }
    }

    async fn promote_blocked<'output>(
        &self,
        sources: &[String],
        destination: &Path,
        results: impl Iterator<Item = &'output mut ArchiveResult> + Send,
        outcome: &mut Outcome,
        shell: &mut ShellUpdates<'_>,
    ) -> io::Result<Option<PromotionPaths>> {
        let mut results: Vec<_> = results.collect();
        let representative = results
            .iter()
            .position(|result| result.failure.is_some() && !result.partial)
            .expect("blocked task has an unaccepted failure");
        let promoted: io::Result<(
            Vec<(PathBuf, PathBuf)>,
            Vec<PromotedSource>,
            bool,
            Option<String>,
        )> = async {
            stage("promotion_plan", &self.request.cancel).await?;
            loop {
                self.request.cancel.check_io()?;
                let plan =
                    NativeBlockedInputPromotion::new(sources.to_vec(), destination.to_path_buf())?;
                let keys = plan
                    .moves()
                    .iter()
                    .map(|(_, target)| resolved_key(target))
                    .collect();
                let _destinations = match self.engine.leases
                    .acquire_absent(keys, plan.moves(), &self.request.cancel).await {
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    result => result?,
                };
                stage("promotion", &self.request.cancel).await?;
                let _promotion = Promotion::begin(sources.iter().map(PathBuf::from))?;
                let (residual, error, collision) = plan.execute(|| {
                    self.observer
                        .before_promotion(&results[representative], plan.moves())
                });
                if collision && residual.is_empty() {
                    continue;
                }
                let success = error.is_empty();
                let moves = if success {
                    plan.moves().to_vec()
                } else {
                    residual
                        .into_iter()
                        .map(|(source, target)| (PathBuf::from(source), PathBuf::from(target)))
                        .collect()
                };
                for (source, target) in &moves {
                    shell.parent(source);
                    shell.parent(target);
                }
                let receipts: Vec<_> = moves
                    .iter()
                    .filter_map(|(_, target)| PromotedSource::capture(target).ok())
                    .collect();
                self.observer.after_promotion(
                    &results[representative],
                    &moves,
                    success,
                    &receipts,
                )?;
                return Ok((
                    moves,
                    receipts,
                    success,
                    (!error.is_empty()).then_some(error),
                ));
            }
        }
        .await;
        let mut promoted_paths = None;
        match promoted {
            Ok((moves, receipts, success, error)) => {
                outcome.promoted_sources.append(&mut receipts.into());
                let paths = PromotionPaths::new(&moves);
                for result in results.iter_mut() {
                    if success {
                        result.promotion_original_path = Some(result.path.clone());
                    }
                    paths.remap(&mut result.path);
                    if let Some(failure) = &mut result.failure { paths.remap_failure(failure); }
                    for source in &mut result.source_paths {
                        paths.remap(source);
                    }
                    result.promoted = success;
                    if success {
                        if let Some(failure) = &mut result.failure {
                            failure.discovery_scope = Some(Box::new(super::FailureScope {
                                root: destination.to_string_lossy().into_owned(),
                                max_depth: Some(0), excluded_subtrees: Vec::new(),
                            }));
                        }
                    }
                    if !success {
                        result.failure = Some(Failure::new(
                            FailureKind::FilesystemError,
                            format!(
                                "Unable to promote blocked nested input: {}",
                                error.as_deref().unwrap_or("unknown move failure")
                            ),
                        ).with_context(super::FailureContext::Postprocess { destination: destination.to_owned() })
                            .with_cause(result.failure.take()));
                    }
                }
                for checkpoint in &mut outcome.checkpoints {
                    checkpoint.promoted(&paths)?;
                }
                promoted_paths = Some(paths);
            }
            Err(error) if self.request.cancel.cancelled() => return Err(error),
            Err(error) => {
                results[representative].failure = Some(Failure::new(
                    FailureKind::FilesystemError,
                    format!("Unable to promote blocked nested input: {error}"),
                ).with_context(super::FailureContext::Postprocess { destination: destination.to_owned() })
                    .with_cause(results[representative].failure.take()));
            }
        }
        Ok(promoted_paths)
    }

    fn admitted_promotion(
        &self,
        path: &str,
        generations: &HashMap<String, PhysicalFileGeneration>,
        watch_root: bool,
    ) -> Option<PromotedSource> {
        if !watch_root && self.promoted_sources.is_empty() {
            return None;
        }
        let key = path_key(path);
        let generation = generations.get(&key)?;
        self.promoted_sources
            .get(&key)
            .map(|&index| &self.request.promoted_sources[index])
            .filter(|source| source.matches(generation))
            .cloned()
            .or_else(|| {
                watch_root
                    .then(|| self.observer.promoted_source(path))
                    .flatten()
                    .filter(|source| source.matches(generation))
            })
    }

    fn checkpoint_for<'b>(
        &self,
        input: &ArchiveInput,
        previous: Option<&'b InputCheckpoint>,
        generations: &HashMap<String, PhysicalFileGeneration>,
        preferred_carrier: &Path,
        depth: usize,
        candidates: &CandidateSet,
    ) -> Option<&'b InputCheckpoint> {
        if self.request.mode != Mode::Extract {
            return None;
        }
        let checkpoint = previous?;
        if !checkpoint.valid_for(input, generations)
            || !checkpoint.password_unchanged(|| candidates.signature(&input.entry_path)) {
            return None;
        }
        if !checkpoint.has_output() { return Some(checkpoint); }
        let destination_matches = match checkpoint.container() {
            Some(container) => {
                output_candidate(preferred_carrier, container)
                    || (depth == 1
                        && self
                            .admitted_promotion(
                                &input.entry_path,
                                generations,
                                self.request.origin == Origin::Watch,
                            )
                            .is_some())
            }
            None => output_candidate(&self.preferred_output(input, depth), checkpoint.output()),
        };
        if !destination_matches {
            return None;
        }
        let source = Path::new(&input.entry_path);
        let nested = (depth > 1).then_some(source);
        if let Some(container) = checkpoint.container() {
            // The physical task owns the container even when its logical
            // segments start in different files of the volume family.
            if !OutputNames::retain(&self.output_names.registry, container, self.output_names.owner, checkpoint.carrier(), nested) {
                return None;
            }
        }
        OutputNames::retain(&self.output_names.registry, checkpoint.output(), self.output_names.owner, source,
            checkpoint.container().or(nested)).then_some(checkpoint)
    }

    fn checkpoint_anchor_index(&self) -> &RecoveryAnchorIndex {
        self.checkpoint_anchors.get_or_init(|| {
            let mut index: HashMap<String, HashMap<_, Vec<(Arc<str>, usize)>>> = HashMap::new();
            for (owner, group) in &self.checkpoints {
                for &position in group.values() {
                    let input = self.request.checkpoints[position].input();
                    if !index.contains_key(&input.format_hint) {
                        index.insert(input.format_hint.clone(), HashMap::new());
                    }
                    let anchors = index.get_mut(&input.format_hint).unwrap();
                    for anchor in recovery_anchors(input) {
                        anchors.entry(anchor).or_default().push((Arc::clone(owner), position));
                    }
                }
            }
            index
        })
    }

    /// Recovery belongs to one physical task, not the whole request. A newly
    /// arrived first volume can change its carrier; only a unique old carrier
    /// reached by its physical sources supplies that task's recovery scope.
    fn select_checkpoints(&self, carrier: &Path, inputs: &[LogicalInput]) -> Vec<Option<&InputCheckpoint>> {
        if self.checkpoints.is_empty() { return vec![None; inputs.len()]; }
        let carrier = path_key(&carrier.to_string_lossy());
        let group = self.checkpoints.get_key_value(carrier.as_str()).or_else(|| {
            let index = self.checkpoint_anchor_index();
            let mut owner = None;
            for logical in inputs {
                let input = &logical.input;
                let Some(anchors) = index.get(&input.format_hint) else { continue; };
                for anchor in recovery_anchors(input) {
                    for (candidate_owner, _) in anchors.get(&anchor).into_iter().flatten() {
                        if owner.is_some_and(|owner| owner != candidate_owner) { return None; }
                        owner = Some(candidate_owner);
                    }
                }
            }
            owner.and_then(|owner| self.checkpoints.get_key_value(owner.as_ref()))
        });
        let Some((owner, group)) = group else { return vec![None; inputs.len()]; };
        let mut used = HashSet::new();
        inputs.iter().map(|logical| {
            let input = &logical.input;
            let previous = group.get(&CheckpointKey::for_input(input)).copied().or_else(|| {
                let anchors = self.checkpoint_anchor_index().get(&input.format_hint)?;
                let mut matched = None;
                for anchor in recovery_anchors(input) {
                    for (candidate_owner, candidate) in anchors.get(&anchor).into_iter().flatten() {
                        let candidate = *candidate;
                        if used.contains(&candidate) || candidate_owner != owner { continue; }
                        if matched.is_some_and(|previous| previous != candidate) { return None; }
                        matched = Some(candidate);
                    }
                }
                matched
            });
            if let Some(index) = previous { used.insert(index); }
            previous.map(|index| &self.request.checkpoints[index])
        }).collect()
    }

    fn retry_slot_for<'b>(&self, input: &ArchiveInput, previous: Option<&'b InputCheckpoint>, carrier: &Path) -> Option<&'b InputCheckpoint> {
        let checkpoint = previous?;
        if !checkpoint.output_slot_for(input, carrier) { return None; }
        // The root was retained through an unchanged sibling above.
        OutputNames::retain(&self.output_names.registry,
            checkpoint.output_slot().expect("matching output slot"), self.output_names.owner,
            Path::new(&input.entry_path), Some(carrier),
        ).then_some(checkpoint)
    }

    async fn claim_task(&self, task: &Task, keys: Option<HashSet<String>>) -> io::Result<Lease> {
        let keys = keys.unwrap_or_else(|| source_lease_keys(task, &HashMap::new()));
        self.engine.leases.acquire_shared(keys, self.output_names.owner, &self.request.cancel).await
    }

    fn capture_generations(&self, task: &Task) -> (HashMap<String, PhysicalFileGeneration>, Vec<PathBuf>) {
        // The lease owns this one metadata snapshot. Keep actual NotFound
        // observations separate from permission/read errors; neither is inferred
        // from a missing generation entry or rechecked later with another stat.
        let mut generations = HashMap::new();
        let mut missing = Vec::new();
        for path in &task.owned_paths {
            match capture_file_generation(Path::new(path)) {
                Ok(generation) => { generations.insert(path_key(path), generation); }
                Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(PathBuf::from(path)),
                Err(_) => {}
            }
        }
        // Standalone SFX launchers can belong to cleanup without being read.
        // As in main, only members of the execution plan can block admission.
        if !missing.is_empty() {
            let members: HashSet<_> = task.input_paths().map(path_key).collect();
            missing.retain(|path| members.contains(&path_key(&path.to_string_lossy())));
        }
        (generations, missing)
    }

    fn admit_missing_inputs(&self, task: &mut Task, missing: &[PathBuf], discovered: bool) {
        if !discovered || missing.is_empty() { return; }
        // main has a task-level discovery blocker only when every segment
        // failed discovery. Otherwise admission precedes all segment work.
        if task.inputs.iter().all(|logical| logical.failure.as_ref().is_some_and(|failure|
            matches!(failure.context.as_deref(), Some(super::FailureContext::Discovery { .. }))))
        { return; }
        let failure = Failure::new(FailureKind::MissingVolume,
            crate::core::i18n::Language::En.text("failure.missing_volume"))
            .with_context(super::FailureContext::InputAdmission { missing_paths: missing.to_vec() });
        for logical in &mut task.inputs {
            logical.failure = Some(failure.clone());
        }
    }

    fn requested_generation(&self, task: &Task, watch_root: bool) -> Option<SourceGenerations> {
        if !watch_root || task.owned_paths.len() < 2 { return None; }
        let mut generations = HashMap::new();
        for path in task.input_paths() {
            if let std::collections::hash_map::Entry::Vacant(entry) = generations.entry(path_key(path)) {
                entry.insert(capture_file_generation(Path::new(path)).ok()?);
            }
        }
        (generations.len() > 1).then_some(generations)
    }

    fn task_admission<'a>(
        &self,
        task: &Task,
        generations: &HashMap<String, PhysicalFileGeneration>,
        missing: &[PathBuf],
        discovered: bool,
        watch_root: bool,
        requested: impl Fn(&str) -> Option<&'a PhysicalFileGeneration>,
    ) -> io::Result<TaskAdmission> {
        // Check the resolved physical family only after its lease is acquired.
        // Departed discovery proposals are not successful output reuse.
        if discovered && !missing.is_empty() {
            let departed: HashSet<_> = missing.iter().map(|path| path_key(&path.to_string_lossy())).collect();
            if task.input_paths().all(|path| departed.contains(&path_key(path))) {
                return Ok(TaskAdmission::Departed);
            }
        }
        if watch_root && task.owned_paths.len() > 1 {
            // Cache the execution candidates before the worker narrows them to
            // a winning composition. Cleanup-only companions stay outside this key.
            let members: HashSet<_> = task.input_paths().map(path_key).collect();
            if members.len() < 2 { return Ok(TaskAdmission::Execute(None)); }
            // main retains the complete pre-wait generation when a prior owner
            // consumed members, but only while every surviving member is unchanged.
            let version = if generations.len() == members.len()
                && members.iter().all(|path| generations.contains_key(path)) {
                Some(generations.clone())
            } else {
                let complete = members.iter().all(|path| generations.contains_key(path));
                members.into_iter().map(|path| {
                    let current = generations.get(&path);
                    if complete {
                        Some((path, current.unwrap().clone()))
                    } else {
                        let previous = requested(&path)?;
                        current.is_none_or(|current| current.matches_input(&previous.persisted()))
                            .then(|| (path, previous.clone()))
                    }
                }).collect::<Option<SourceGenerations>>()
            };
            if let Some(output) = version.as_ref().map(|version| self.observer.completed_sources(version)).transpose()?.flatten() {
                return Ok(TaskAdmission::Completed(output));
            }
            return Ok(TaskAdmission::Execute(version));
        }
        Ok(TaskAdmission::Execute(None))
    }

    fn reuse_completed_task(&self, task: &Task, id: TaskId, depth: usize,
        output: PathBuf, outcome: &mut Outcome) {
        // main returns one successful target with the existing output. It does
        // not re-extract/recurse, schedule source cleanup, or publish that
        // existing directory as a newly owned output operation.
        let mut result = receipt(task.entry(), task.source, depth);
        // Watch uses these aliases to settle durable ownership, including
        // cleanup-only companions that are outside the cache key.
        result.source_paths = task.owned_paths.iter().map(PathBuf::from).collect();
        result.output = Some(output);
        self.notify(|| Event::Finished { id, path: result.path.clone(), depth,
            result: super::TaskCompletion::from_result(&result) });
        outcome.archives.push(result);
    }

    fn plan_inputs(&self, task: &mut Task) -> io::Result<()> {
        if task.inputs.len() != 1 || task.inputs[0].failure.is_some() {
            return Ok(());
        }
        let original = &mut task.inputs[0];
        if task.source != DiscoverySource::Direct {
            return Ok(());
        }
        // Detection already walks LZ4 and routes any independent, bounded
        // archive to Embedded. A second analysis cannot recover a new plan.
        let report = match analyze_input(&original.input, &self.analysis) {
            Ok(report) => report,
            // Planning is advisory, as in main. A transient analysis read must
            // not replace the original input with a terminal extraction failure.
            Err(error) if !is_cancellation(&error) && !self.request.cancel.cancelled() => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !report.format_hint.is_empty() {
            original.input.format_hint = report.format_hint.to_string();
        }
        let previous = &original.input.analysis;
        let mut facts = report.facts;
        facts.origin = previous.origin;
        facts.planning_applied = true;
        // Main keeps the descriptor's discovery facts while updating advisory
        // execution/format facts; planning is not a new discovery receipt.
        facts.volume_completeness = previous.volume_completeness;
        facts.zip_eocd_offset = facts.zip_eocd_offset.or(previous.zip_eocd_offset);
        facts.password_required |= previous.password_required;
        facts.structure_complete |= previous.structure_complete;
        facts.status = previous.status;
        facts.damage_flags = previous.damage_flags.clone();
        original.input.analysis = facts;
        let mut selected = report.extractable_segments;
        if selected.is_empty() {
            selected.extend(report.password_segment);
        }
        if selected.is_empty() {
            return Ok(());
        }
        let slices: Vec<_> = selected
            .iter()
            .map(|item| (item.format_hint.as_str(), item.start, item.end))
            .collect();
        let (projected, probe) = archive_input_slices(&original.input, &slices)?;
        let probe_zip_eocd = selected[0].zip_eocd_offset;
        let logical: Vec<_> = projected
            .into_iter()
            .zip(selected)
            .filter_map(|(input, segment)| {
                let mut input = input?;
                input.analysis.origin = crate::io::archive_state::AnalysisOrigin::Planned;
                input.analysis.status = segment.status;
                input.analysis.zip_eocd_offset = segment.zip_eocd_offset;
                input.analysis.password_required = segment.password_required;
                input.analysis.damage_flags = segment.damage_flags;
                input.analysis.structure_complete = input.format_hint == "lz4";
                Some(LogicalInput {
                    input,
                    password_probe: None,
                    password: None,
                    failure: None,
                })
            })
            .collect();
        if !logical.is_empty() {
            task.inputs = logical;
        } else {
            original.password_probe = probe.map(|mut probe| {
                probe.analysis = original.input.analysis.clone();
                probe.analysis.zip_eocd_offset = probe_zip_eocd.or(probe.analysis.zip_eocd_offset);
                Box::new(probe)
            });
        }
        Ok(())
    }

    async fn execute_input(
        &self,
        logical: LogicalInput,
        id: TaskId,
        source: DiscoverySource,
        depth: usize,
        carrier: Option<&Path>,
        retry_output: Option<RetryOutput<'_>>,
        candidates: &CandidateSet,
        shell: &mut ShellUpdates<'_>,
        outcome: &mut Outcome,
    ) -> io::Result<Executed> {
        let LogicalInput {
            mut input,
            password_probe,
            password,
            failure,
        } = logical;
        let mut result = receipt(&input, source, depth);
        result.password = password.as_deref().map(str::to_owned);
        if let Some(failure) = failure {
            result.failure = Some(failure);
            return Ok(Executed {
                planned_output: None,
                result,
                inventory: None,
                input: Arc::new(input),
            });
        }
        if self.request.cancel.cancelled() {
            result.failure = Some(Failure::new(FailureKind::Cancelled, "Operation interrupted"));
            return Ok(Executed { planned_output: None, result, inventory: None, input: Arc::new(input) });
        }
        stage("preflight", &self.request.cancel).await?;
        self.notify(|| Event::Extracting { id });
        let output = if self.request.mode == Mode::Extract {
            let preferred = carrier.map_or_else(
                || self.preferred_output(&input, depth),
                |root| root.join(archive_name(&input)),
            );
            let reserved = match retry_output {
                Some(RetryOutput::Recreate(path)) => self.recreate_reserved_output(path, &result)?,
                Some(RetryOutput::Existing(path)) => {
                    // This was a retained, claimed child slot whose cleanup
                    // failed. Match main's mkdir(exist_ok=True) and start the
                    // current attempt rather than accepting the old receipt.
                    match self.observer.reuse_output(&result, path) {
                        Ok(()) => {
                            self.created_outputs.lock().unwrap().register(path, &result);
                            Ok(path.to_owned())
                        }
                        Err(error) if error.get_ref().is_some_and(|inner| inner.is::<super::OutputCreateError>()) => {
                            Err(output_create_failure(error, path))
                        }
                        Err(error) => return Err(error),
                    }
                }
                None => self.reserve_output(preferred, &result, carrier)?,
            };
            match reserved {
                Ok(path) => {
                    shell.output(&path);
                    Some(path)
                }
                Err(failure) => {
                    let planned_output = match failure.context.as_deref() {
                        Some(super::FailureContext::OutputCreate { path, .. }) => path.clone(),
                        _ => None,
                    };
                    result.failure = Some(failure);
                    return Ok(Executed {
                        planned_output,
                        result,
                        inventory: None,
                        input: Arc::new(input),
                    });
                }
            }
        } else {
            None
        };
        let plan = match candidates.plan(password_probe.as_deref().unwrap_or(&input), password, &self.request.cancel) {
            Ok(Ok(plan)) => plan,
            Ok(Err(failure)) => {
                result.failure = Some(failure.with_context(super::FailureContext::PasswordResolution));
                if let Some(path) = output.as_deref() {
                    if !self.discard_failed_output(&result, path, outcome)? { result.output = Some(path.to_owned()); }
                }
                return Ok(Executed {
                    planned_output: output,
                    result,
                    inventory: None,
                    input: Arc::new(input),
                });
            }
            Err(error) => {
                result.failure = Some(
                    if input.mode.structured() && error.kind() == io::ErrorKind::NotFound {
                        Failure::new(FailureKind::MissingVolume, error.to_string())
                    } else {
                        self.process_or_file_failure(error, false)
                    },
                );
                if let Some(path) = output.as_deref() {
                    if !self.discard_failed_output(&result, path, outcome)? { result.output = Some(path.to_owned()); }
                }
                return Ok(Executed {
                    planned_output: output,
                    result,
                    inventory: None,
                    input: Arc::new(input),
                });
            }
        };
        drop(password_probe);
        if plan.verified {
            result.password = plan.selected.as_deref().map(str::to_owned);
        }
        let codepage = if self.request.mode == Mode::Extract
            && input.format_hint == "zip"
            && input.volume_attempts.is_none()
        {
            crate::formats::zip::analyze_zip_filename_encoding(&input)
                .ok()
                .flatten()
        } else {
            None
        };
        let job_id = format!(
            "{}:{}",
            std::process::id(),
            self.engine.next_id()
        );
        let output_string = output
            .as_ref()
            .map_or_else(String::new, |path| path.to_string_lossy().into_owned());
        let volume_key = if output_string.is_empty() {
            String::new()
        } else {
            crate::filesystem::resolve_output_volume_key(&output_string)
                .unwrap_or_else(|| format!("job:{job_id}"))
        };
        let mut request = json!({
            "job_id": job_id, "operation": if self.request.mode == Mode::Scan { "scan" } else { "extract" },
            "request_id": self.worker_request_id,
            "origin": if self.request.origin == Origin::Watch { "watch" } else { "foreground" },
            "output_dir": output_string, "output_volume_key": volume_key,
            "archive_input": input.worker_input(), "password": plan.selected.as_deref().unwrap_or(""),
            "password_verified": plan.verified, "password_candidates": plan.candidates,
        });
        if let Some(encrypted) = plan.encrypted {
            request["encrypted"] = Value::Bool(encrypted);
        }
        if let Some(codepage) = codepage {
            request["codepage"] = Value::from(codepage);
        }
        self.notify(|| Event::Waiting { id });
        let native = match self.engine.worker(&self.request.config.performance.worker, &self.request.cancel).await {
            Ok(worker) => {
                stage("extract_prepare", &self.request.cancel).await?;
                worker
                    .submit(
                        &job_id,
                        request,
                        &self.request.cancel,
                        self.observer.worker_updates(),
                        |update| {
                            let event = match update {
                                worker::Update::Started => Event::Working { id },
                                worker::Update::Progress(progress) => Event::Progress {
                                    id,
                                    path: result.path.clone(),
                                    completed_bytes: progress.completed,
                                    total_bytes: progress.total,
                                },
                                worker::Update::ResourceWait(state) => Event::ResourceWait {
                                    id,
                                    path: result.path.clone(),
                                    state,
                                },
                            };
                            self.observer.notify(event);
                        },
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        stage("complete_extract", &self.request.cancel).await?;
        self.notify(|| Event::Finalizing { id });
        let mut inventory = None;
        match native {
            Ok(mut frame) => {
                let value = &frame.summary;
                let format = worker::string(value, "archive_type");
                if !format.is_empty()
                    && (self.request.mode == Mode::Extract || result.format.is_empty())
                {
                    result.format = format.to_owned();
                }
                result.encrypted = value
                    .get("encrypted")
                    .and_then(Value::as_bool)
                    .or(plan.encrypted);
                let matched_index = value
                    .get("matched_index")
                    .and_then(Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok());
                let success = worker::string(value, "status") == "ok";
                if success && self.request.mode == Mode::Extract && input.volume_attempts.is_some()
                {
                    let selected = value
                        .get("volume_selection")
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "worker omitted successful volume selection",
                            )
                        })
                        .and_then(|raw| {
                            serde_json::from_value::<VolumeSelection>(raw.clone())
                                .map_err(io::Error::from)
                        });
                    match selected.and_then(|selected| input.select_volumes(&selected)) {
                        Ok(()) => {
                            result.source_paths =
                                input.physical_paths().map(PathBuf::from).collect();
                            result.volume_completeness = Some("complete".to_owned());
                        }
                        Err(error) => {
                            result.failure =
                                Some(Failure::new(FailureKind::ProcessError, error.to_string()));
                        }
                    }
                }
                if success && result.failure.is_none() {
                    let password_verified = self.request.mode == Mode::Extract
                        || plan.verified
                        || flag(value, "password_verified");
                    if result.encrypted == Some(true) && password_verified {
                        result.password = plan
                            .remember_confirmation(matched_index, &self.engine.password_attempts)
                            .map(str::to_owned);
                    }
                    if let Some(output) = &output {
                        let stats = inventory_for(&frame, &output_string);
                        result.files = stats.file_count() as u64;
                        result.bytes = stats.total_size();
                        result.output = Some(output.clone());
                        inventory = Some(stats);
                    }
                } else if result.failure.is_none() {
                    let split = input.mode.structured() || input.physical_paths().nth(1).is_some()
                        || looks_like_split_archive_name(&input.entry_path);
                    let mut failure = classify_worker_failure(value, plan.evidence, split);
                    if matches!(failure.kind, FailureKind::WrongPassword | FailureKind::PasswordInconclusive) {
                        result.password = None;
                    }
                    if failure.kind == FailureKind::Damaged && flag(value, "password_crc_proven") {
                        result.password = plan
                            .remember_confirmation(matched_index, &self.engine.password_attempts)
                            .map(str::to_owned);
                    } else if matches!(
                        failure.kind,
                        FailureKind::WrongPassword | FailureKind::PasswordRequired
                    ) && flag(value, "password_candidates_all_rejected")
                    {
                        plan.remember_rejections(&self.engine.password_attempts);
                    }
                    if failure.kind != FailureKind::PasswordInconclusive
                        && recoverable_content_failure(&frame)
                    {
                        if let Some(output) = &output {
                            let verified_files = recoverable_file_count(&frame);
                            let stats = scan_output_inventory_impl(&output_string);
                            // Retaining damaged payload is not partial success:
                            // main keeps nonempty failed output for manual recovery,
                            // but only verified files authorize recursive processing.
                            if verified_files > 0 || stats.file_count() > 0 {
                                result.recovered_complete_files = recovery_complete_files(&failure, verified_files as u64);
                                result.partial = accepts_partial_content(
                                    self.request.config.extraction.content_requirement,
                                    failure.kind, result.recovered_complete_files,
                                );
                                result.files = stats.file_count() as u64;
                                result.bytes = stats.total_size();
                                result.output = Some(output.clone());
                                if result.partial {
                                    inventory = Some(stats);
                                }
                            }
                        }
                    }
                    failure.evidence = worker_evidence(value, frame.recovery.take(), plan.evidence);
                    let context = if failure.kind == FailureKind::Unknown {
                        super::FailureContext::WorkerWarning
                    } else {
                        super::FailureContext::Extraction
                    };
                    result.failure = Some(failure.with_context(context));
                }
            }
            Err(error) => result.failure = Some(self.process_or_file_failure(error, true)),
        }
        if result.failure.is_some() && result.output.is_none() {
            if let Some(path) = &output {
                self.discard_failed_output(&result, path, outcome)?;
            }
        }
        Ok(Executed {
            planned_output: output,
            result,
            inventory,
            input: Arc::new(input),
        })
    }

    fn apply_complete_content_policy(
        &self, parent_outputs: &mut [ParentOutput], report_states: &mut [Option<ReportState>],
        replacement_retained: Option<usize>, outcome: &mut Outcome,
    ) -> io::Result<()> {
        // Main retains best-effort bytes per input before applying the
        // physical carrier's content policy. A complete sibling keeps
        // failed siblings' salvage, without accepting them for recursion.
        if self.request.config.extraction.content_requirement == ContentRequirement::Complete
            && !parent_outputs.iter().any(|(result, ..)| result.failure.is_none())
        {
            // A replacement can have no output after password/open failure,
            // while main still counts the first attempt's retained complete
            // members as partial output. Do not let its deleted slot survive
            // a Complete-policy rejection in the recovery report.
            let rejected_output = parent_outputs.iter().any(|(result, ..)| result.output.is_some())
                || replacement_retained.is_some_and(|index| outcome.checkpoints[index].has_recovered_members());
            for (index, (result, inventory, ..)) in parent_outputs.iter_mut().enumerate() {
                if let Some(output) = result.output.clone() {
                    if self.discard_failed_output(result, &output, outcome)? {
                        result.output = None;
                        result.files = 0;
                        result.bytes = 0;
                        result.recovered_complete_files = 0;
                        InputCheckpoint::clear_report_output(&mut report_states[index]);
                    }
                }
                *inventory = None;
            }
            if rejected_output && parent_outputs.iter().all(|(result, ..)| result.output.is_none()) {
                for state in report_states.iter_mut() { InputCheckpoint::clear_report_output(state); }
                if let Some(index) = replacement_retained { outcome.checkpoints[index].clear_recovery_output(); }
            }
        }
        Ok(())
    }

    fn discard_failed_output(
        &self, result: &ArchiveResult, path: &Path, outcome: &mut Outcome,
    ) -> io::Result<bool> {
        if let Err(error) = cleanup_owned_output(path) {
            // Physical deletion is local to this failed archive. Keep its
            // durable guard, but do not discard the other logical results.
            record_cleanup(outcome, path, "delete", Err(error));
            return Ok(false);
        }
        self.observer.discard_output(&result.path, &result.source_paths, path)?;
        // No recursive children have started for this worker's failed output.
        // Retire ownership only after both deletion and journal update succeed.
        self.created_outputs.lock().unwrap().commit(path);
        Ok(true)
    }

    fn process_or_file_failure(&self, error: io::Error, worker: bool) -> Failure {
        if crate::io::resource_error::is_memory_error(&error) {
            Failure::new(FailureKind::ResourceUnavailable, error.to_string())
        } else if is_cancellation(&error) {
            Failure::new(FailureKind::Cancelled, "Operation interrupted")
        } else if worker {
            {
                let mut failure = Failure::new(FailureKind::ProcessError, error.to_string())
                    .with_context(super::FailureContext::Extraction);
                let evidence = failure.evidence.get_or_insert_with(Default::default);
                let kind = error.get_ref()
                    .and_then(|error| error.downcast_ref::<super::worker::CommunicationError>())
                    .map_or("process_io", |error| error.kind);
                evidence.native_kind = Some(kind.into());
                evidence.stage = Some(if kind == "process_start" { "worker_start" }
                    else { "worker_communication" }.into());
                failure
            }
        } else {
            file_failure(error)
        }
    }

    async fn discover_children_many<T>(
        &self,
        inventories: impl ExactSizeIterator<Item = (T, NativeOutputInventory)>,
        depth: usize,
        candidates: &CandidateSet,
    ) -> io::Result<Vec<(T, Discovered, bool)>> {
        if depth > self.request.max_depth || self.request.cancel.cancelled() {
            return Ok(inventories.map(|(parent, _)| (parent, Discovered::default(), false)).collect());
        }
        stage("nested_scan", &self.request.cancel).await?;
        let options = self.filtered_options()?;
        let mut results = Vec::with_capacity(inventories.len());
        let mut outputs = Vec::new();
        for (parent, inventory) in inventories {
            self.request.cancel.check_io()?;
            let output = discovery::OutputDiscovery::prepare(inventory, options)?;
            let mut nested = Discovered::default();
            nested.scan_errors.extend(output.scan_errors());
            let has_files = output.has_files();
            results.push((parent, nested, has_files));
            if has_files { outputs.push(output); }
        }
        // Main asks once for this round when any filtered output contains
        // files. Archive detection and password probing start after consent.
        if outputs.is_empty() || !self.allow_recursive(depth + 1, 1).await {
            for (_, _, scan) in &mut results { *scan = false; }
            return Ok(results);
        }
        stage("discovery", &self.request.cancel).await?;
        match discovery::OutputDiscovery::discover_many(outputs, candidates, &self.request) {
            Ok(discovered) => for ((_, current, _), mut nested) in results.iter_mut()
                .filter(|(_, _, scan)| *scan).zip(discovered)
            {
                nested.scan_errors = std::mem::take(&mut current.scan_errors);
                *current = nested;
            },
            Err(error) if is_cancellation(&error) => {},
            Err(error) => return Err(error),
        }
        Ok(results)
    }

    #[cfg(test)]
    async fn discover_children(
        &self,
        inventory: NativeOutputInventory,
        depth: usize,
        candidates: &CandidateSet,
    ) -> io::Result<(Discovered, bool)> {
        let (_, nested, scanned) = self.discover_children_many(
            std::iter::once(((), inventory)), depth, candidates,
        ).await?.pop().unwrap();
        Ok((nested, scanned))
    }

    async fn allow_recursive(&self, depth: usize, pending: usize) -> bool {
        if self.request.config.recursive_extract != Recursion::Prompt {
            return true;
        }
        let inline = Some(|depth, pending| self.observer.allow_recursive_async(depth, pending));
        #[cfg(test)]
        let inline = inline.filter(|_| matches!(self.observer, ObserverRef::Owned(..)));
        self.recursion.allow(depth, pending, &self.request.cancel, inline).await
    }

    fn preferred_output(&self, input: &ArchiveInput, depth: usize) -> PathBuf {
        let path = Path::new(&input.entry_path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut root = parent.to_path_buf();
        if let Some(output_root) = self.request.output_root.as_ref().filter(|_| depth == 1) {
            root = output_root.clone();
            if self.request.origin == Origin::Foreground && !self.request.config.output.fixed_root {
                if let Some(relative) = relative_to(parent, output_root) {
                    root.push(relative);
                } else if let Some(base) = &self.output_base {
                    if let Some(relative) = relative_to(parent, base) {
                        root.push(relative);
                    } else {
                        root.push(mirrored_parent_component(parent));
                    }
                }
            }
        }
        root.join(archive_name(input))
    }

    fn recreate_reserved_output(&self, path: &Path, result: &ArchiveResult) -> io::Result<Result<PathBuf, Failure>> {
        match self.observer.register_output(result, path) {
            Ok(()) => {
                self.created_outputs.lock().unwrap().register(path, result);
                Ok(Ok(path.to_owned()))
            }
            Err(error) if error.get_ref().is_some_and(|inner| inner.is::<super::OutputCreateError>()) => {
                Ok(Err(output_create_failure(error, path)))
            }
            Err(error) => Err(error),
        }
    }

    fn reserve_output(
        &self,
        preferred: PathBuf,
        result: &ArchiveResult,
        carrier: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        // Claim under the naming gate; publish without holding it.
        let input = carrier.or_else(|| (result.depth > 1).then_some(result.path.as_path()));
        let reserved = OutputNames::reserve(&self.output_names.registry,
            preferred, result, &*self.observer, self.output_names.owner, input,
        )?;
        if let Ok(path) = &reserved {
            self.created_outputs.lock().unwrap().register(path, result);
        }
        Ok(reserved)
    }

    fn cleanup_sources(
        &self,
        paths: &[PathBuf],
        cleanup: CleanupMode,
        failures: &mut Vec<CleanupResult>,
        shell: &mut ShellUpdates<'_>,
    ) {
        let mode = match cleanup {
            CleanupMode::Keep => unreachable!("keep needs no source cleanup"),
            CleanupMode::Delete => "delete",
            CleanupMode::Recycle => "recycle",
        };
        let mut existing = Vec::new();
        for path in paths {
            match path.try_exists() {
                Ok(true) => existing.push(path),
                Ok(false) => {}
                Err(error) => failures.extend(cleanup_failure(path, mode, Err(error))),
            }
        }
        if existing.is_empty() {
            return;
        }
        let _promotion = match Promotion::begin(existing.iter().map(|path| (*path).clone())) {
            Ok(promotion) => promotion,
            Err(error) => {
                for path in existing {
                    let copy = error.raw_os_error().map(io::Error::from_raw_os_error)
                        .unwrap_or_else(|| io::Error::new(error.kind(), error.to_string()));
                    failures.extend(cleanup_failure(path, mode, Err(copy)));
                }
                return;
            }
        };
        for path in existing {
            let removed = match cleanup {
                CleanupMode::Delete => remove_owned_file(path),
                CleanupMode::Recycle => super::cleanup::recycle(std::iter::once(path.as_path())),
                CleanupMode::Keep => unreachable!("keep produced receipts without filesystem work"),
            };
            if removed.is_ok() {
                shell.parent(path);
            }
            failures.extend(cleanup_failure(path, mode, removed));
        }
    }
}

fn flatten_result(
    observer: &impl Observer,
    id: TaskId,
    result: &mut ArchiveResult,
    children: &mut Outcome,
    created: Option<&Mutex<CreatedOutputs>>,
    names: &OutputReservationGuard,
) -> io::Result<()> {
    let Some(output) = result.output.as_ref() else {
        return Ok(());
    };
    let Some(leaf) = discover_flatten_leaf(output) else {
        return Ok(());
    };
    let attempt = || -> io::Result<_> {
        let mut work = output.as_os_str().to_os_string();
        work.push(".__sunpack_flatten_work__");
        let work = PathBuf::from(work);
        let available = OutputNames::plan(&names.registry,
            work, &result.path, names.owner, Some(output),
        )?.map_err(|failure| io::Error::other(failure.message))?;
        let attempt = (|| {
            let _promotion = Promotion::begin([output.to_owned()])?;
            Ok(flatten_single_branch_directories(
                output,
                &available,
                FlattenLeaf::Prepared(&leaf),
                |root, work, leaf| observer.before_flatten(root, work, leaf),
            ))
        })();
        let available_key = output_key(&available);
        names.registry.lock().unwrap().release_path(&available_key, names.owner);
        attempt
    };
    let stats = match attempt() {
        Ok(stats) => stats,
        Err(error) if is_cancellation(&error) || error.kind() == io::ErrorKind::Interrupted => {
            return Err(error);
        }
        Err(error) => {
            record_cleanup(children, output, "flatten", Err(io::Error::other(error)));
            return Ok(());
        }
    };
    if !stats.errors.is_empty() {
        let retained = stats.output_dir.as_deref().unwrap_or(output);
        record_cleanup(
            children,
            retained,
            "flatten",
            Err(io::Error::other(stats.errors.join("; "))),
        );
    }
    if let (Some(old), Some(new)) = (stats.source_dir, stats.output_dir) {
        // Settle the durable pre-move receipts before publishing rebased ones.
        observer.after_flatten(id, &old, &new)?;
        // Successful flatten commonly keeps the root spelling unchanged while
        // moving its leaf's descendants. Rebase rollback receipts with the same
        // mapping as checkpoints, before any fallible durable publication.
        if let Some(created) = created {
            created.lock().unwrap().relocate(&old, &new);
        }
        for checkpoint in &mut children.checkpoints {
            checkpoint.relocate_flatten(&old, &new);
        }
        let mut relocated_recoveries = HashMap::new();
        for child in &mut children.archives {
            let mut failures: Vec<_> = child.failure.iter_mut().collect();
            while let Some(failure) = failures.pop() {
                if let Some(recovery) = &mut failure.recovery {
                    let key = Arc::as_ptr(recovery);
                    let relocated = relocated_recoveries.entry(key).or_insert_with(|| {
                        let mut snapshot = recovery.as_ref().clone();
                        snapshot.relocate_flatten(&old, &new);
                        Arc::new(snapshot)
                    });
                    *recovery = Arc::clone(relocated);
                }
                failures.extend(&mut failure.causes);
            }
            if let Some(path) = child.output.as_mut() {
                super::relocate_flatten_output(path, &old, &new);
            }
        }
        for receipt in &mut children.cleanup_results {
            if let Some(suffix) = relative_to(&receipt.path, &old) {
                receipt.path = new.join(suffix);
            }
        }
        for error in &mut children.errors {
            if error.kind == InputErrorKind::Cleanup {
                if let Some(suffix) = relative_to(&error.path, &old) {
                    error.path = new.join(suffix);
                }
            }
        }
        result.output = Some(new);
    }
    Ok(())
}

/// Promotion moves physical files, never directory prefixes. Normalize each
/// source once, then visit each result/checkpoint field once.
pub(super) struct PromotionPaths(HashMap<String, PathBuf>);

impl PromotionPaths {
    pub(super) fn new(moves: &[(PathBuf, PathBuf)]) -> Self {
        Self(moves.iter().map(|(source, target)| (resolved_key(source), target.clone())).collect())
    }

    pub(super) fn target(&self, path: &Path) -> Option<&PathBuf> {
        self.0.get(&resolved_key(path))
    }

    pub(super) fn remap_failure(&self, failure: &mut Failure) {
        let mut pending = vec![failure];
        while let Some(failure) = pending.pop() {
            if let Some(super::FailureContext::Discovery { path, .. }) = failure.context.as_deref_mut() {
                self.remap(path);
            }
            pending.extend(&mut failure.causes);
        }
    }

    pub(super) fn remap(&self, path: &mut PathBuf) -> bool {
        if let Some(target) = self.target(path) {
            *path = target.clone();
            true
        } else {
            false
        }
    }
}

fn record_cleanup(outcome: &mut Outcome, path: &Path, mode: &'static str, removed: io::Result<()>) {
    if let Some(failure) = cleanup_failure(path, mode, removed) {
        record_cleanup_failure(outcome, failure);
    }
}

fn cleanup_failure(path: &Path, mode: &'static str, removed: io::Result<()>) -> Option<CleanupResult> {
    let error = removed.err()?;
    if error.kind() == io::ErrorKind::NotFound {
        return None;
    }
    Some(CleanupResult {
        path: path.to_path_buf(),
        mode,
        status: CleanupStatus::Failed,
        error_code: error.raw_os_error().unwrap_or(0),
        message: error.to_string(),
    })
}

fn record_cleanup_failure(outcome: &mut Outcome, failure: CleanupResult) {
    outcome.errors.push(InputError {
        path: failure.path.clone(),
        message: failure.message.clone(),
        kind: InputErrorKind::Cleanup,
        scan_operation: None,
        scan_count: None,
        failure: None,
    });
    outcome.cleanup_results.push(failure);
}

fn receipt(input: &ArchiveInput, source: DiscoverySource, depth: usize) -> ArchiveResult {
    let extent = input.physical_extents().next();
    let mut source_paths: Vec<_> = input.physical_paths().map(PathBuf::from).collect();
    if source_paths.len() > 1 {
        dedup_paths(&mut source_paths);
    }
    ArchiveResult {
        path: PathBuf::from(&input.entry_path),
        format: input.format_hint.clone(),
        output: None,
        failure: None,
        files: 0,
        bytes: 0,
        encrypted: input.analysis.password_required.then_some(true),
        depth,
        offset: extent.map_or(0, |extent| extent.start),
        end_offset: extent.and_then(|extent| extent.end),
        volume_attempts: None,
        volume_completeness: input
            .analysis
            .volume_completeness
            .map(VolumeCompleteness::as_str)
            .map(str::to_owned),
        source_paths,
        password: None,
        discovery_source: source,
        damage_flags: input.analysis.damage_flags.clone(),
        partial: false,
        retained: false,
        recovered_complete_files: 0,
        promoted: false,
        promotion_original_path: None, scan_layout: super::ScanLayout::from_input(input),
    }
}

fn recovery_anchors(input: &ArchiveInput) -> impl Iterator<Item = (String, u64)> + '_ {
    let plan = input.volume_attempts.as_ref();
    let extents = plan.into_iter().flat_map(|plan| plan.sources.iter())
        .chain(input.ranges.iter().filter(move |_| plan.is_none()))
        .chain(input.parts.iter().filter(move |_| plan.is_none() && input.ranges.is_empty())
            .map(|part| &part.extent));
    let empty = plan.map_or(input.parts.is_empty() && input.ranges.is_empty(), |plan| plan.sources.is_empty());
    extents.map(|extent| (path_key(&extent.path), extent.start))
        .chain(empty.then(|| (path_key(&input.entry_path), 0)))
}

fn output_create_failure(error: io::Error, path: &Path) -> Failure {
    let mut failure = file_failure(error);
    if let Some(super::FailureContext::OutputCreate { path: attempted, .. }) = failure.context.as_deref_mut() {
        *attempted = Some(path.to_owned());
    }
    failure
}

fn file_failure(error: io::Error) -> Failure {
    let original = error.get_ref().and_then(|inner| inner.downcast_ref::<super::OutputCreateError>())
        .map_or(&error, |created| &created.0);
    let kind = if crate::io::resource_error::is_memory_error(original) {
        FailureKind::ResourceUnavailable
    } else {
        FailureKind::FilesystemError
    };
    let failure = Failure::new(kind, error.to_string());
    if error.get_ref().is_some_and(|inner| inner.is::<super::OutputCreateError>()) {
        failure.with_context(super::FailureContext::OutputCreate { error: original.to_string(), path: None })
    } else {
        failure
    }
}

fn flag(result: &Value, name: &str) -> bool {
    result.get(name).and_then(Value::as_bool) == Some(true)
}

fn worker_evidence(
    result: &Value,
    recovery: Option<super::RecoveryPreview>,
    password_evidence: Option<&str>,
) -> Option<Box<FailureEvidence>> {
    let diagnostics = &result["diagnostics"];
    let field = |name: &str| {
        [result, diagnostics].into_iter().find_map(|value| {
            let text = worker::string(value, name);
            (!text.is_empty()).then(|| text.to_owned())
        })
    };
    let hresult = result.get("hresult").or_else(|| diagnostics.get("hresult")).and_then(Value::as_i64);
    // Keep the scalar proof behind the classification, not passwords or the
    // complete worker payload. Main exposes these in its failure details.
    // Explicit rejection takes precedence over fallback evidence in main.
    let weak_failure = !flag(result, "password_candidates_all_rejected")
        && weak_password_failure(result, password_evidence);
    let (classification_evidence, password_crc_proven_items, backend_operation_result) =
        if weak_failure && flag(result, "password_crc_proven") {
            (Some("entry_crc_proven_before_failure".to_owned()),
             Some(worker::number(result, "password_crc_proven_items")), None)
        } else if weak_failure {
            (Some(if password_evidence == Some("empty_password_direct") {
                "empty_password_failed_without_crc_proof"
            } else { "zipcrypto_failure_without_password_proof" }.to_owned()),
             None, Some(worker::string(result, "operation_result_name").to_owned()))
        } else { (None, None, None) };
    let stderr_tail = field("stderr_tail");
    let stage = field("failure_stage");
    let native_kind = field("failure_kind");
    let missing_volume_suspected = flag(result, "missing_volume_suspected")
        || flag(diagnostics, "missing_volume_suspected");
    let missing_volume_name = field("missing_volume_name");
    let missing_volume_evidence = field("missing_volume_evidence");
    let input = diagnostics
        .get("input_trace")
        .unwrap_or(&result["input_trace"]);
    let last = &input["last_read"];
    let path = worker::string(last, "source_path");
    let read_error = flag(input, "read_error");
    let read = (!path.is_empty() || read_error).then(|| FailureRead {
        source_path: path.to_owned(),
        source_offset: worker::number(last, "source_offset"),
        virtual_offset: worker::number(last, "virtual_offset"),
        requested: worker::number(last, "requested"),
        returned: worker::number(last, "returned"),
        win32_error: input["last_win32_error"].as_i64().unwrap_or_default(),
        read_error,
    });
    let recovery = recovery.filter(|preview| !preview.files.is_empty());
    (hresult.is_some() || classification_evidence.is_some() || missing_volume_suspected || stderr_tail.is_some()
        || stage.is_some()
        || native_kind.is_some()
        || missing_volume_name.is_some()
        || missing_volume_evidence.is_some()
        || read.is_some()
        || recovery.is_some())
    .then(|| {
        Box::new(FailureEvidence {
            hresult, classification_evidence, password_crc_proven_items, backend_operation_result,
            missing_volume_suspected,
            stderr_tail,
            stage,
            native_kind,
            missing_volume_name,
            missing_volume_evidence,
            read,
            recovery,
            ..Default::default()
        })
    })
}

fn weak_password_failure(result: &Value, evidence: Option<&str>) -> bool {
    (evidence == Some("zipcrypto_header_byte")
        || (evidence == Some("empty_password_direct") && flag(result, "encrypted")))
        && (matches!(worker::string(result, "operation_result_name"), "wrong_password" | "data_error" | "crc_error")
            || matches!(worker::string(result, "failure_kind"),
                "encrypted_or_wrong_password" | "data_error" | "checksum_error" | "crc_error"))
}

// main also recognizes a split-style filename for conflicting native damage
// and password evidence, even when relation discovery proved a standalone file.
fn looks_like_split_archive_name(path: &str) -> bool {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let name = Path::new(path).file_name().unwrap_or_default().to_string_lossy();
    PATTERN.get_or_init(|| regex::Regex::new(
        r"(?i)(\.part\d+\.rar(?:\.[^.]+)?|\.z\d{2}|\.\d{3}(?:\.[^.]+)?)$").unwrap()).is_match(&name)
}

fn classify_worker_failure(
    result: &Value,
    password_evidence: Option<&str>,
    split: bool,
) -> Failure {
    let native = worker::string(result, "native_status");
    let failure = worker::string(result, "failure_kind");
    let operation = worker::string(result, "operation_result_name");
    let diagnostics = result.get("diagnostics").unwrap_or(&Value::Null);
    let diagnostic_failure = worker::string(diagnostics, "failure_kind");
    let hresult = result
        .get("hresult")
        .or_else(|| diagnostics.get("hresult"))
        .and_then(Value::as_i64)
        .map(|value| value as u32);
    let damaged_kind = |kind| {
        matches!(
            kind,
            "corrupted_data" | "data_error" | "checksum_error" | "crc_error"
        )
    };
    let payload_damage = flag(result, "checksum_error")
        || flag(result, "damaged")
        || native == "damaged"
        || damaged_kind(failure)
        || damaged_kind(diagnostic_failure);
    let kind = if failure == "resource_unavailable"
        || matches!(hresult, Some(0x80070008 | 0x8007000e | 0x800705af))
    {
        FailureKind::ResourceUnavailable
    } else if flag(result, "missing_volume") {
        FailureKind::MissingVolume
    } else if failure == "password_or_volume_inconclusive" {
        FailureKind::PasswordInconclusive
    } else if flag(result, "password_candidates_all_rejected") {
        return Failure::password();
    } else if weak_password_failure(result, password_evidence)
    {
        if flag(result, "password_crc_proven") {
            FailureKind::Damaged
        } else if password_evidence == Some("empty_password_direct") {
            return Failure::password();
        } else {
            FailureKind::PasswordInconclusive
        }
    } else if split && payload_damage {
        FailureKind::Damaged
    } else if flag(result, "wrong_password")
        || flag(result, "password_rejected")
        || native == "wrong_password"
        || operation == "wrong_password"
        || matches!(failure, "wrong_password" | "encrypted_or_wrong_password")
        || matches!(
            diagnostic_failure,
            "wrong_password" | "encrypted_or_wrong_password"
        )
    {
        return Failure::password();
    } else if payload_damage || flag(result, "missing_volume_suspected") {
        FailureKind::Damaged
    } else if flag(result, "unsupported_method") || native == "unsupported" {
        FailureKind::Unsupported
    } else if native == "backend_unavailable" {
        FailureKind::BackendUnavailable
    } else if matches!(native, "cancelled" | "canceled" | "interrupted") {
        FailureKind::Cancelled
    } else {
        FailureKind::Unknown
    };
    let message = worker::string(result, "message");
    let mut classified = Failure::new(
        kind,
        if message.is_empty() {
            format!("{kind:?}")
        } else {
            message.to_owned()
        },
    );
    classified.password_retry = kind == FailureKind::PasswordInconclusive
        && failure == "password_or_volume_inconclusive";
    classified
}

// Report the carrier-level warning without rewriting failure categories used
// by password blockers and recovery. Main retains those causes under its
// extraction_report wrapper too.
fn project_possible_missing_volume(results: &mut [ArchiveResult], split: bool) {
    let confirmed = results.iter().any(|result| result.failure.as_ref()
        .is_some_and(|failure| failure.kind == FailureKind::MissingVolume));
    let partial = results.iter().any(|result| result.partial)
        && results.iter().all(|result| result.failure.is_none() || result.partial);
    let suspected = results.iter().filter_map(|result| result.failure.as_ref())
        .filter_map(|failure| failure.evidence.as_deref())
        .any(|evidence| evidence.missing_volume_suspected
            || evidence.archive_read_fault.as_ref().is_some_and(|fault| fault.possible_missing_volume));
    let warning = split && !confirmed && (partial || suspected);
    for failure in results.iter_mut().filter_map(|result| result.failure.as_mut()) {
        if warning {
            failure.evidence.get_or_insert_with(Default::default).possible_missing_volume = true;
        } else if let Some(evidence) = &mut failure.evidence {
            evidence.possible_missing_volume = false;
        }
    }
}

// Raw successful members may survive for manual recovery. Only main's
// recoverable failure classes grant a checkpoint permission to reuse that root.
fn recovery_complete_files(failure: &Failure, verified_files: u64) -> u64 {
    if matches!(failure.kind, FailureKind::Damaged | FailureKind::MissingVolume)
        && failure.causes.is_empty()
    { verified_files } else { 0 }
}

fn accepts_partial_content(requirement: ContentRequirement, failure: FailureKind, complete_files: u64) -> bool {
    requirement == ContentRequirement::AllowPartial
        && matches!(failure, FailureKind::Damaged | FailureKind::MissingVolume)
        && complete_files > 0
}

fn recoverable_content_failure(frame: &WorkerFrame) -> bool {
    let kind = frame.summary["failure_kind"].as_str().unwrap_or_default();
    let stage = frame.summary["failure_stage"].as_str().unwrap_or_default();
    if matches!(
        kind,
        "output_filesystem"
            | "process_start"
            | "process_timeout"
            | "process_stall"
            | "process_exit"
            | "process_signal"
    ) || !(matches!(
        kind,
        "checksum_error"
            | "corrupted_data"
            | "data_error"
            | "unexpected_end"
            | "input_truncated"
            | "stream_truncated"
    ) || matches!(stage, "item_extract" | "archive_extract" | "archive_read"))
    {
        return false;
    }
    true
}

fn recoverable_file_count(frame: &WorkerFrame) -> usize {
    if !recoverable_content_failure(frame) {
        return 0;
    }
    if let Some(preview) = &frame.recovery {
        return preview.complete_files;
    }
    frame.manifest.as_ref().map_or(0, |manifest| {
        manifest
            .records()
            .iter()
            .filter(|record| record.status == 1)
            .count()
    })
}

fn inventory_for(frame: &WorkerFrame, path: &str) -> NativeOutputInventory {
    let validated = frame
        .summary
        .get("verified_manifest")
        .is_some_and(|value| flag(value, "validated"));
    if let Some(manifest) = frame
        .manifest
        .as_ref()
        .filter(|manifest| validated && manifest.complete())
    {
        manifest.to_output_inventory(path.to_owned())
    } else {
        scan_output_inventory_impl(path)
    }
}

fn output_is_gone(output: &Path, prune_empty: bool) -> bool {
    let regular_directory = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata.is_dir() && !crate::scan::directory::is_reparse_point(&metadata),
        Err(error) => return error.kind() == io::ErrorKind::NotFound,
    };
    if !prune_empty || !regular_directory {
        return false;
    }
    match fs::remove_dir(output) {
        Ok(()) => true,
        Err(error) => error.kind() == io::ErrorKind::NotFound,
    }
}

fn archive_name(input: &ArchiveInput) -> String {
    crate::output_names::output_name_component(&input.logical_name)
}

fn mirrored_parent_component(parent: &Path) -> String {
    let mut components = parent.components();
    let (prefix, tail) = match components.next() {
        Some(std::path::Component::Prefix(prefix)) => {
            (prefix.as_os_str().to_string_lossy(), components.as_path())
        }
        _ => (std::borrow::Cow::Borrowed(""), parent),
    };
    let tail = tail.to_string_lossy();
    let joined = format!(
        "{}_{}",
        prefix.trim_end_matches(':'),
        tail.trim_matches(['\\', '/'])
    );
    let value = joined.trim_matches('_');
    if value.is_empty() {
        return "input".into();
    }
    value
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn common_output_base(inputs: &[PathBuf]) -> Option<PathBuf> {
    let mut base = match common_ancestor(inputs) {
        Some(base) => base,
        None => {
            let mut first = inputs
                .iter()
                .find_map(|path| std::path::absolute(path).ok())?;
            if !first.is_dir() {
                first.pop();
            }
            return Some(first);
        }
    };
    if base.is_file() {
        base.pop();
    }
    Some(base)
}

pub(crate) fn common_ancestor(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Option<PathBuf> {
    let mut paths = paths
        .into_iter()
        .filter_map(|path| std::path::absolute(path).ok());
    let mut base = paths.next()?;
    for path in paths {
        while relative_to(&path, &base).is_none() {
            if !base.pop() || !base.is_absolute() {
                return None;
            }
        }
    }
    Some(base)
}

fn relative_to<'a>(path: &'a Path, root: &Path) -> Option<&'a Path> {
    if let Ok(relative) = path.strip_prefix(root) {
        return Some(relative);
    }
    let path_key = path_key(&path.to_string_lossy());
    let root_key = crate::path_keys::path_key(&root.to_string_lossy());
    let root_key = root_key.trim_end_matches('\\');
    if path_key != root_key
        && !path_key
            .strip_prefix(root_key)
            .is_some_and(|rest| rest.starts_with('\\'))
    {
        return None;
    }
    let mut components = path.components();
    components.nth(root.components().count().checked_sub(1)?)?;
    Some(components.as_path())
}

fn output_candidate(preferred: &Path, actual: &Path) -> bool {
    if resolved_key(preferred) == resolved_key(actual) {
        return true;
    }
    if preferred.parent().map(resolved_key) != actual.parent().map(resolved_key) {
        return false;
    }
    let Some(base) = preferred.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(name) = actual.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let preferred = crate::path_keys::case_key(base);
    let name = crate::path_keys::case_key(name);
    let (base, start) = numbered_suffix(&preferred).unwrap_or((&preferred, 0));
    numbered_suffix(&name).is_some_and(|(actual_base, index)| {
        (actual_base == base && index > start)
            || (actual_base.strip_suffix(' ') == Some(preferred.as_str()) && index > 0)
    })
}

fn numbered(path: &Path, index: usize) -> PathBuf {
    let name = path.file_name().unwrap_or(path.as_os_str());
    if let Some((base, index)) = name
        .to_str()
        .and_then(numbered_suffix)
        .and_then(|(base, start)| start.checked_add(index).map(|index| (base, index)))
    {
        return path.with_file_name(format!("{base}({index})"));
    }
    let mut name = name.to_os_string();
    name.push(format!("({index})"));
    path.with_file_name(name)
}

fn numbered_suffix(name: &str) -> Option<(&str, usize)> {
    let (base, index) = name.strip_suffix(')')?.rsplit_once('(')?;
    if index.is_empty() { return None; }
    let index = index.chars().try_fold(0usize, |value, character| {
        value.checked_mul(10)?.checked_add(crate::core::config::decimal_digit(character)? as usize)
    })?;
    Some((base, index))
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path_key(&path.to_string_lossy())));
}

fn resolved_key(path: &Path) -> String {
    match fs::canonicalize(path) {
        Ok(canonical) => namespace_key(&canonical),
        Err(_) => namespace_key(path),
    }
}

fn source_lease_keys(task: &Task, resolved: &HashMap<String, Arc<str>>) -> HashSet<String> {
    task.owned_paths.iter().map(|path| {
        resolved.get(path).map_or_else(|| resolved_key(Path::new(path)), |key| key.to_string())
    }).collect()
}

fn dedup_resolved_plans(tasks: &mut Vec<Task>) -> HashMap<String, Arc<str>> {
    // Alias paths can have different scan filters. Resolve them after discovery
    // so the path that actually supplied a plan stays eligible for extraction.
    type Extent = (Arc<str>, u64, Option<u64>);
    let mut paths = HashMap::<String, Arc<str>>::new();
    let mut resolved = |path: &str| {
        if let Some(key) = paths.get(path) {
            return Arc::clone(key);
        }
        let key: Arc<str> = resolved_key(Path::new(path)).into();
        paths.insert(path.to_owned(), Arc::clone(&key));
        key
    };
    let mut plans = HashSet::<(OpenMode, String, Box<[Extent]>)>::new();
    tasks.retain_mut(|task| {
        task.inputs.retain(|logical| {
            let input = &logical.input;
            // Main claims every physical plan, including unresolved volume
            // candidates and preflight failures. Leases only serialize aliases;
            // they do not prevent the second alias from executing afterwards.
            let mut extents: Box<[Extent]> = input
                .physical_extents()
                .map(|extent| (resolved(&extent.path), extent.start, extent.end))
                .collect();
            if extents.is_empty() {
                extents = Box::new([(resolved(&input.entry_path), 0, None)]);
            }
            plans.insert((input.mode, input.format_hint.clone(), extents))
        });
        !task.inputs.is_empty()
    });
    paths
}

fn namespace_key(path: &Path) -> String {
    path_key(&normalize_windows_extended_prefix(
        path.to_string_lossy().into_owned(),
    ))
}

fn cleanup_owned_output(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("output root is a reparse point"));
        }
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other("managed output is no longer a directory"));
    }
    let _promotion = Promotion::begin([path.to_owned()])?;
    remove_owned_tree(path)
}

#[derive(Default)]
struct Leases {
    state: Mutex<LeaseState>,
}

#[derive(Default)]
struct LeaseState {
    active: HashMap<String, (Option<u64>, usize)>,
    requests: HashMap<u64, RequestClaim>,
    watch: HashMap<Arc<str>, Vec<ActiveWatchFamily>>,
    next_waiter: u64,
    waiters: HashMap<u64, LeaseWaiter>,
    blocked_by: HashMap<LeaseBlocker, HashSet<u64>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum LeaseBlocker {
    Request(u64),
    Watch(u64),
    Path(String),
}

type WatchSettlement = OnceLock<io::Result<()>>;

struct ActiveWatchFamily {
    id: u64,
    members: Arc<WatchGenerations>,
    request: Arc<Request>,
    settlement: Arc<WatchSettlement>,
}

enum WatchFamily {
    Owner(WatchFamilyOwner),
    Follower(Arc<str>, u64, Arc<WatchSettlement>),
}

struct WatchFamilyOwner {
    leases: Arc<Leases>,
    key: Arc<str>,
    id: u64,
    settlement: Arc<WatchSettlement>,
}

impl WatchFamilyOwner {
    fn finish(self, result: &io::Result<PublicOutcome>, cancel: &Cancellation) {
        // The owner publishes terminal results and interruption. Propagate
        // infrastructure errors without retaining a second discovery plan.
        let settled = match result {
            Ok(_) => Ok(()),
            Err(error) if cancel.cancelled() && is_cancellation(error) => Ok(()),
            Err(error) => Err(copy_io_error(error)),
        };
        let _ = self.settlement.set(settled);
    }
}

fn copy_io_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()), io::Error::from_raw_os_error,
    )
}

impl Drop for WatchFamilyOwner {
    fn drop(&mut self) {
        let mut state = self.leases.state.lock().unwrap();
        let owners = state.watch.get_mut(&self.key).expect("registered Watch family");
        let index = owners.iter().position(|owner| owner.id == self.id).expect("registered Watch owner");
        let removed = owners.swap_remove(index);
        if owners.is_empty() { state.watch.remove(&self.key); }
        crate::collections::trim_map(&mut state.watch);
        let wakes = state.released(&LeaseBlocker::Watch(self.id));
        drop(state);
        drop(removed);
        for wake in wakes { wake.wake(); }
    }
}

struct LeaseWaiter {
    waker: Waker,
    blockers: HashSet<LeaseBlocker>,
}

impl LeaseState {
    fn remove_waiter(&mut self, id: u64) -> Option<Waker> {
        let waiter = self.waiters.remove(&id)?;
        for blocker in waiter.blockers {
            if let Some(ids) = self.blocked_by.get_mut(&blocker) {
                ids.remove(&id);
                if ids.is_empty() { self.blocked_by.remove(&blocker); }
            }
        }
        Some(waiter.waker)
    }

    fn wait(&mut self, id: u64, blockers: HashSet<LeaseBlocker>, waker: &Waker) {
        self.remove_waiter(id);
        for blocker in &blockers {
            self.blocked_by.entry(blocker.clone()).or_default().insert(id);
        }
        self.waiters.insert(id, LeaseWaiter { waker: waker.clone(), blockers });
    }

    fn released(&mut self, blocker: &LeaseBlocker) -> Vec<Waker> {
        let Some(ids) = self.blocked_by.remove(blocker) else { return Vec::new(); };
        ids.into_iter().filter_map(|id| self.remove_waiter(id)).collect()
    }
}

struct RequestClaim {
    origin: Origin,
    paths: HashMap<String, ClaimPath>,
    has_aliases: bool,
    directories: HashSet<String>,
    objects: HashMap<(u64, [u8; 16]), usize>,
}

impl RequestClaim {
    fn new(origin: Origin) -> Self {
        Self {
            origin,
            paths: HashMap::new(),
            has_aliases: false,
            directories: HashSet::new(),
            objects: HashMap::new(),
        }
    }

    fn add(&mut self, input: ClaimedInput) {
        if input.directory {
            self.directories
                .insert(input.key.trim_end_matches('\\').to_owned());
        }
        self.has_aliases |= input.alias;
        match self.paths.entry(input.key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                if let Some(identity) = input.object {
                    *self.objects.entry(identity).or_default() += 1;
                }
                entry.insert(ClaimPath { path: input.path, watch_aliases: Vec::new(), object: input.object });
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if self.origin == Origin::Watch && entry.get().path != input.path {
                    entry.get_mut().watch_aliases.push(input.path);
                }
            }
        }
    }

    fn includes_directory(&self, path: &str) -> bool {
        if self.directories.is_empty() {
            return false;
        }
        let mut current = path.trim_end_matches('\\');
        loop {
            if self.directories.contains(current) {
                return true;
            }
            let Some((parent, _)) = current.rsplit_once('\\') else {
                return false;
            };
            current = parent;
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        if self.objects.keys().any(|id| other.objects.contains_key(id)) {
            return true;
        }
        let (small, large) = if self.paths.len() <= other.paths.len() {
            (self, other)
        } else {
            (other, self)
        };
        small
            .paths
            .keys()
            .any(|path| large.paths.contains_key(path))
            || (!self.directories.is_empty()
                && other.paths.keys().any(|path| self.includes_directory(path)))
            || (!other.directories.is_empty()
                && self.paths.keys().any(|path| other.includes_directory(path)))
    }

    fn conflict(&self) -> BusyConflict {
        let mut paths: Vec<_> = self.paths.values().map(|input| input.path.clone()).collect();
        paths.sort_unstable();
        BusyConflict {
            origin: self.origin,
            paths,
        }
    }
}

struct ClaimPath {
    path: PathBuf,
    watch_aliases: Vec<PathBuf>,
    object: Option<(u64, [u8; 16])>,
}

struct ClaimedInput {
    path: PathBuf,
    key: String,
    directory: bool,
    alias: bool,
    object: Option<(u64, [u8; 16])>,
}

impl ClaimedInput {
    fn new(path: &Path) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let directory = canonical.is_dir();
        let object = if directory {
            capture_directory_identity(&canonical)
                .ok()
                .map(|identity| identity.object_id())
        } else {
            capture_file_generation(&canonical)
                .ok()
                .and_then(|generation| generation.object_id())
        };
        let key = namespace_key(&canonical);
        let spelling = path.to_string_lossy();
        let alias =
            if spelling.is_ascii() && !spelling.starts_with(r"\\?\") && !spelling.contains('/') {
                !key.eq_ignore_ascii_case(&spelling)
            } else {
                key != namespace_key(&path)
            };
        Ok(Self {
            key,
            path,
            directory,
            alias,
            object,
        })
    }
}

pub(crate) struct RequestClaimGuard {
    registry: Arc<Leases>,
    id: u64,
}

impl Engine {
    pub(crate) fn retire_watch_inputs(&self, request: u64, paths: &HashSet<String>) {
        let mut state = self.leases.state.lock().unwrap();
        let Some(claim) = state.requests.get_mut(&request) else { return; };
        if claim.origin != Origin::Watch || !claim.directories.is_empty() { return; }
        let mut changed = false;
        let (claimed, objects) = (&mut claim.paths, &mut claim.objects);
        let mut retire_object = |identity| {
            changed = true;
            if let Some(identity) = identity {
                let count = objects.get_mut(&identity).expect("claimed file identity");
                *count -= 1;
                if *count == 0 { objects.remove(&identity); }
            }
        };
        if claim.has_aliases {
            // Keep the canonical claim until each selected spelling retires.
            claimed.retain(|_, input| {
                input.watch_aliases.retain(|path| !paths.contains(&path_key(&path.to_string_lossy())));
                if !paths.contains(&path_key(&input.path.to_string_lossy())) { return true; }
                if let Some(alias) = input.watch_aliases.pop() {
                    input.path = alias;
                    true
                } else {
                    retire_object(input.object);
                    false
                }
            });
        } else {
            for path in paths {
                if let Some(input) = claimed.remove(path) { retire_object(input.object); }
            }
        }
        if !changed { return; }
        if claim.paths.is_empty() { state.requests.remove(&request); }
        let waiters = state.released(&LeaseBlocker::Request(request));
        drop(state);
        for waiter in waiters { waiter.wake(); }
    }
}

impl Drop for RequestClaimGuard {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock().unwrap();
        state.requests.remove(&self.id);
        crate::collections::trim_map(&mut state.requests);
        let waiters = state.released(&LeaseBlocker::Request(self.id));
        drop(state);
        for waker in waiters { waker.wake(); }
    }
}

struct Lease {
    owner: Arc<Leases>,
    keys: HashSet<String>,
}

impl Leases {
    fn claim_watch(
        self: &Arc<Self>, id: u64, members: &Arc<WatchGenerations>, request: &Arc<Request>,
    ) -> WatchFamily {
        // The first ordered physical path is independent of the selection
        // and task order. Compare the full generation union in its bucket.
        let anchor = members.first_key_value().expect("resolved Watch family").0.as_str();
        let mut state = self.state.lock().unwrap();
        let key = state.watch.get_key_value(anchor).map_or_else(
            || Arc::<str>::from(anchor), |(key, _)| Arc::clone(key));
        let owners = state.watch.entry(Arc::clone(&key)).or_default();
        let active = owners.iter().find(|active| {
            let owner = &active.request;
            // A configuration change can alter output, cleanup or password
            // candidates. Only share a result when it is valid for both runs.
            request.deep == owner.deep && request.max_depth == owner.max_depth
                && request.output_root == owner.output_root && request.password_scope == owner.password_scope
                && request.direct == owner.direct && request.recursive == owner.recursive
                && Arc::ptr_eq(&request.config, &owner.config)
                && match (&request.password_snapshot, &owner.password_snapshot) {
                    (Some(request), Some(owner)) => Arc::ptr_eq(request, owner),
                    (None, None) => true,
                    _ => false,
                } && members == &active.members && !owner.cancel.cancelled()
        });
        if let Some(active) = active {
            return WatchFamily::Follower(key, active.id, Arc::clone(&active.settlement));
        }
        let settlement = Arc::new(WatchSettlement::new());
        owners.push(ActiveWatchFamily {
            id, members: Arc::clone(members), request: Arc::clone(request), settlement: Arc::clone(&settlement),
        });
        WatchFamily::Owner(WatchFamilyOwner { leases: Arc::clone(self), key, id, settlement })
    }

    async fn join_watch(
        self: &Arc<Self>, key: &str, owner: u64, settlement: &WatchSettlement, cancel: &Cancellation,
    ) -> io::Result<()> {
        let mut waiting = LeaseWait { owner: self, id: None };
        let mut subscription = None;
        poll_fn(|cx| {
            if cancel.cancelled() { return Poll::Ready(Ok(())); }
            let mut state = self.state.lock().unwrap();
            if !state.watch.get(key).is_some_and(|owners| owners.iter().any(|active| active.id == owner)) {
                return Poll::Ready(settlement.get().map_or_else(
                    || Err(io::Error::other("Watch extraction request failed")),
                    |result| result.as_ref().copied().map_err(copy_io_error),
                ));
            }
            let id = *waiting.id.get_or_insert_with(|| {
                state.next_waiter += 1;
                state.next_waiter
            });
            state.wait(id, HashSet::from([LeaseBlocker::Watch(owner)]), cx.waker());
            drop(state);
            if subscription.is_none() {
                let leases = Arc::clone(self);
                subscription = cancel.subscribe(move || {
                    let wake = leases.state.lock().unwrap().remove_waiter(id);
                    if let Some(wake) = wake { wake.wake(); }
                });
            }
            Poll::Pending
        }).await
    }

    fn has_aliases(&self, id: u64) -> bool {
        self.state
            .lock()
            .unwrap()
            .requests
            .get(&id)
            .is_some_and(|claim| claim.has_aliases)
    }

    #[cfg(test)]
    fn reserve_request(
        self: &Arc<Self>, id: u64, origin: Origin, paths: &[PathBuf], cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard> {
        super::scheduling::block_on(self.reserve_request_async(id, origin, paths, cancel))
    }

    async fn reserve_request_async(
        self: &Arc<Self>, id: u64, origin: Origin, paths: &[PathBuf], cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard> {
        let inputs = paths.iter().map(|path| ClaimedInput::new(path))
            .collect::<io::Result<Vec<_>>>()?;
        self.admit_request(id, origin, inputs, cancel).await?;
        Ok(RequestClaimGuard { registry: Arc::clone(self), id })
    }

    async fn admit_request(
        self: &Arc<Self>, id: u64, origin: Origin, inputs: Vec<ClaimedInput>, cancel: &Cancellation,
    ) -> io::Result<()> {
        let mut claim = RequestClaim::new(origin);
        for input in inputs { claim.add(input); }
        let mut claim = Some(claim);
        let mut waiting = LeaseWait { owner: self, id: None };
        let mut subscription = None;
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if let Err(error) = cancel.check_io() { return Poll::Ready(Err(error)); }
            let mut blockers = HashSet::new();
            for (&owner, current) in &state.requests {
                if claim.as_ref().unwrap().overlaps(current) {
                    if origin == Origin::Foreground {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::WouldBlock, current.conflict())));
                    }
                    blockers.insert(LeaseBlocker::Request(owner));
                }
            }
            if blockers.is_empty() {
                state.requests.insert(id, claim.take().unwrap());
                return Poll::Ready(Ok(()));
            }
            let waiter = *waiting.id.get_or_insert_with(|| {
                state.next_waiter += 1;
                state.next_waiter
            });
            state.wait(waiter, blockers, cx.waker());
            drop(state);
            if subscription.is_none() {
                let owner = Arc::clone(self);
                subscription = cancel.subscribe(move || {
                    let wake = owner.state.lock().unwrap().remove_waiter(waiter);
                    if let Some(wake) = wake { wake.wake(); }
                });
            }
            Poll::Pending
        }).await
    }

    async fn acquire(
        self: &Arc<Self>,
        keys: HashSet<String>,
        cancel: &Cancellation,
    ) -> io::Result<Lease> {
        self.acquire_paths(keys, &[], None, cancel).await
    }

    async fn acquire_shared(
        self: &Arc<Self>, keys: HashSet<String>, request: u64, cancel: &Cancellation,
    ) -> io::Result<Lease> {
        self.acquire_paths(keys, &[], Some(request), cancel).await
    }

    async fn acquire_absent(
        self: &Arc<Self>,
        keys: HashSet<String>,
        absent: &[(PathBuf, PathBuf)],
        cancel: &Cancellation,
    ) -> io::Result<Lease> {
        self.acquire_paths(keys, absent, None, cancel).await
    }

    async fn acquire_paths(
        self: &Arc<Self>, keys: HashSet<String>, absent: &[(PathBuf, PathBuf)],
        request: Option<u64>, cancel: &Cancellation,
    ) -> io::Result<Lease> {
        let mut waiting = LeaseWait {
            owner: self,
            id: None,
        };
        let mut subscription = None;
        poll_fn(|cx| {
            if !absent.is_empty() {
                if let Err(error) = cancel.check_io() {
                    return Poll::Ready(Err(error));
                }
            }
            for (_, path) in absent {
                match path.try_exists() {
                    Ok(false) => {},
                    Ok(true) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::AlreadyExists, "promotion destination exists"))),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            let mut state = self.state.lock().unwrap();
            if let Err(error) = cancel.check_io() {
                return Poll::Ready(Err(error));
            }
            let blockers: HashSet<_> = keys.iter().filter(|key| {
                state.active.get(*key).is_some_and(|(owner, _)| request.is_none() || *owner != request)
            }).cloned().map(LeaseBlocker::Path).collect();
            if blockers.is_empty() {
                for key in &keys {
                    state.active.entry(key.clone()).or_insert((request, 0)).1 += 1;
                }
                return Poll::Ready(Ok(()));
            }
            let id = *waiting.id.get_or_insert_with(|| {
                state.next_waiter += 1;
                state.next_waiter
            });
            state.wait(id, blockers, cx.waker());
            drop(state);
            if subscription.is_none() {
                let owner = Arc::clone(self);
                subscription = cancel.subscribe(move || {
                    let waker = owner.state.lock().unwrap().remove_waiter(id);
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                });
            }
            Poll::Pending
        })
        .await?;
        Ok(Lease { owner: Arc::clone(self), keys })
    }
}

struct LeaseWait<'a> {
    owner: &'a Leases,
    id: Option<u64>,
}

impl Drop for LeaseWait<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let mut state = self.owner.state.lock().unwrap();
            state.remove_waiter(id);
            if state.waiters.capacity() > 256 {
                crate::collections::trim_map(&mut state.waiters);
            }
            if state.blocked_by.capacity() > 256 {
                crate::collections::trim_map(&mut state.blocked_by);
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap();
        let active = &mut state.active;
        let mut released = Vec::new();
        for key in &self.keys {
            let (_, count) = active.get_mut(key).expect("lease owns its path");
            *count -= 1;
            if *count == 0 { active.remove(key); released.push(key); }
        }
        if active.capacity() > 256.max(active.len().saturating_mul(4)) {
            let target = active.len().saturating_mul(2);
            active.shrink_to(target);
        }
        let waiters: Vec<_> = released.into_iter()
            .flat_map(|key| state.released(&LeaseBlocker::Path(key.clone()))).collect();
        drop(state);
        for waker in waiters { waker.wake(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Outcome {
        fn succeeded(&self) -> usize {
            self.archives.iter().filter(|archive| archive.failure.is_none() || archive.partial).count()
        }
        fn failed(&self) -> usize {
            self.archives.len() - self.succeeded() + self.errors.iter()
                .filter(|error| error.kind != InputErrorKind::Cleanup).map(InputError::count).sum::<usize>()
        }
    }

    #[test]
    fn shared_cleanup_waits_for_every_owner_and_preserves_failed_sources() {
        let registry = Arc::new(Mutex::new(CleanupRefs::default()));
        let paths = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect::<Vec<_>>();
        let key = |path: &str| namespace_key(Path::new(path));
        let mut first = CleanupOwner::new(Arc::clone(&registry), &paths(&["a.001", "tail.002"]));
        let mut second = CleanupOwner::new(Arc::clone(&registry), &paths(&["b.001", "tail.002"]));
        assert_eq!(first.release(true), HashSet::from([key("a.001")]));
        assert_eq!(second.release(true), HashSet::from([key("b.001"), key("tail.002")]));
        assert!(registry.lock().unwrap().paths.is_empty());

        let first = CleanupOwner::new(Arc::clone(&registry), &paths(&["a.001", "tail.002"]));
        let mut second = CleanupOwner::new(Arc::clone(&registry), &paths(&["b.001", "tail.002"]));
        drop(first); // Includes cancelled and never-dispatched batch owners.
        assert_eq!(second.release(true), HashSet::from([key("b.001")]));
        assert!(registry.lock().unwrap().paths.is_empty());

        let mut first = CleanupOwner::new(Arc::clone(&registry), &paths(&["a.001", "old.002"]));
        let mut second = CleanupOwner::new(Arc::clone(&registry), &paths(&["b.001", "new.002"]));
        first.refresh(&paths(&["a.001", "new.002"]));
        assert!(!registry.lock().unwrap().paths.contains_key(&key("old.002")));
        assert_eq!(second.release(true), HashSet::from([key("b.001")]));
        assert_eq!(first.release(true), HashSet::from([key("a.001"), key("new.002")]));
        assert!(registry.lock().unwrap().paths.is_empty());
    }

    #[test]
    fn request_read_pins_share_sources_but_mutation_and_other_requests_wait() {
        use std::future::Future;
        use std::task::{Context, Wake};
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        let leases = Arc::new(Leases::default());
        let cancel = Cancellation::new();
        let keys = || HashSet::from(["tail.002".to_owned()]);
        let first = super::super::scheduling::block_on(leases.acquire_shared(keys(), 1, &cancel)).unwrap();
        let second = super::super::scheduling::block_on(leases.acquire_shared(keys(), 1, &cancel)).unwrap();
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let mut other = Box::pin(leases.acquire_shared(keys(), 2, &cancel));
        let mut mutation = Box::pin(leases.acquire(keys(), &cancel));
        assert!(other.as_mut().poll(&mut cx).is_pending());
        assert!(mutation.as_mut().poll(&mut cx).is_pending());
        drop(first);
        assert!(mutation.as_mut().poll(&mut cx).is_pending());
        drop(second);
        let exclusive = match mutation.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(lease)) => lease,
            _ => panic!("all readers retired"),
        };
        assert!(other.as_mut().poll(&mut cx).is_pending());
        drop(exclusive);
        assert!(matches!(other.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        drop(other);
        drop(mutation);
        let state = leases.state.lock().unwrap();
        assert!(state.active.is_empty() && state.waiters.is_empty() && state.blocked_by.is_empty());
    }

    #[test]
    fn lease_notifications_follow_blockers_and_unregister_cancelled_waiters() {
        use std::future::Future;
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake};

        #[derive(Default)]
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let leases = Arc::new(Leases::default());
        let cancel = Cancellation::new();
        let keys = |paths: &[&str]| paths.iter().map(|path| (*path).to_owned()).collect();
        let first = super::super::scheduling::block_on(leases.acquire(keys(&["a"]), &cancel)).unwrap();
        let second = super::super::scheduling::block_on(leases.acquire(keys(&["b"]), &cancel)).unwrap();
        let unrelated = super::super::scheduling::block_on(leases.acquire(keys(&["c"]), &cancel)).unwrap();
        let wakes = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut waiting = Box::pin(leases.acquire(keys(&["a", "b"]), &cancel));
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        drop(unrelated);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        drop(second);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        let held = match waiting.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(lease)) => lease,
            _ => panic!("released family remained blocked"),
        };
        drop(waiting);

        // Cancellation and dropping a pending future remove both directions
        // of the dependency index, not just its stored waker.
        let stopped = Cancellation::new();
        let mut cancelled = Box::pin(leases.acquire(keys(&["a"]), &stopped));
        assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        stopped.cancel();
        assert!(matches!(cancelled.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        drop(cancelled);
        let mut abandoned = Box::pin(leases.acquire(keys(&["b"]), &cancel));
        assert!(abandoned.as_mut().poll(&mut cx).is_pending());
        drop(abandoned);
        let state = leases.state.lock().unwrap();
        assert!(state.waiters.is_empty());
        assert!(state.blocked_by.is_empty());
        drop(state);
        drop(held);
    }

    #[test]
    fn promotion_collision_does_not_wait_for_destination_lease() {
        use std::future::Future;
        use std::task::{Context, Wake};
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        let leases = Arc::new(Leases::default());
        let cancel = Cancellation::new();
        let target = std::env::temp_dir().join(format!("sunpack-lease-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let keys = [resolved_key(&target)].into_iter().collect();
        let held = super::super::scheduling::block_on(leases.acquire(keys, &cancel)).unwrap();
        std::fs::write(&target, b"occupied").unwrap();
        let moves = [(PathBuf::new(), target.clone())];
        let keys = [resolved_key(&target)].into_iter().collect();
        let mut pending = Box::pin(leases.acquire_absent(keys, &moves, &cancel));
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::AlreadyExists));
        drop(pending);
        std::fs::remove_file(&target).unwrap();

        // A destination created while waiting must be rechecked after wake.
        let keys = [resolved_key(&target)].into_iter().collect();
        let mut pending = Box::pin(leases.acquire_absent(keys, &moves, &cancel));
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        std::fs::write(&target, b"occupied").unwrap();
        drop(held);
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::AlreadyExists));
        drop(pending);
        let state = leases.state.lock().unwrap();
        assert!(state.waiters.is_empty() && state.blocked_by.is_empty());
        drop(state);
        std::fs::remove_file(target).unwrap();
    }

    #[test]
    fn request_notifications_are_separate_from_physical_family_leases() {
        use std::future::Future;
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake};

        #[derive(Default)]
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let leases = Arc::new(Leases::default());
        let cancel = Cancellation::new();
        let first_path = [PathBuf::from("claim-family.7z.001")];
        let other_path = [PathBuf::from("claim-family.7z.002")];
        let first = leases.reserve_request(1, Origin::Foreground, &first_path, &cancel).unwrap();
        let family: HashSet<_> = ["claim-family.7z.001", "claim-family.7z.002"]
            .into_iter().map(str::to_owned).collect();
        let held = super::super::scheduling::block_on(leases.acquire(family.clone(), &cancel)).unwrap();
        // A different original volume remains admissible while the resolved
        // physical family is in use; the same original selection is still busy.
        let other = leases.reserve_request(2, Origin::Foreground, &other_path, &cancel).unwrap();
        assert!(matches!(leases.reserve_request(3, Origin::Foreground, &first_path, &cancel),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        let request_wakes = Arc::new(CountWake::default());
        let request_waker = Waker::from(Arc::clone(&request_wakes));
        let mut request_cx = Context::from_waker(&request_waker);
        let mut request = Box::pin(leases.reserve_request_async(4, Origin::Watch, &first_path, &cancel));
        assert!(request.as_mut().poll(&mut request_cx).is_pending());
        let physical_wakes = Arc::new(CountWake::default());
        let physical_waker = Waker::from(Arc::clone(&physical_wakes));
        let mut physical_cx = Context::from_waker(&physical_waker);
        let mut physical = Box::pin(leases.acquire(family, &cancel));
        assert!(physical.as_mut().poll(&mut physical_cx).is_pending());
        drop(other);
        assert_eq!(request_wakes.0.load(Ordering::SeqCst), 0);
        assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(request_wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 0);
        let claim = match request.as_mut().poll(&mut request_cx) {
            Poll::Ready(Ok(claim)) => claim,
            _ => panic!("released original request remained blocked"),
        };
        drop(held);
        assert_eq!(physical_wakes.0.load(Ordering::SeqCst), 1);
        assert!(matches!(physical.as_mut().poll(&mut physical_cx), Poll::Ready(Ok(_))));
        drop(request);
        drop(physical);
        drop(claim);
        let state = leases.state.lock().unwrap();
        assert!(state.waiters.is_empty());
        assert!(state.blocked_by.is_empty());
    }

    #[test]
    fn worker_failure_proof_survives_json_and_streamed_report() {
        let cases = [
            (json!({"failure_kind":"resource_unavailable", "diagnostics":{"hresult":-2147024882i64}}), None,
                json!({"hresult":-2147024882i64})),
            (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error",
                "password_crc_proven":true, "password_crc_proven_items":2}), Some("zipcrypto_header_byte"),
                json!({"classification_evidence":"entry_crc_proven_before_failure", "password_crc_proven_items":2})),
            (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error"}), Some("zipcrypto_header_byte"),
                json!({"classification_evidence":"zipcrypto_failure_without_password_proof", "backend_operation_result":"crc_error"})),
            (json!({"failure_kind":"checksum_error", "operation_result_name":"crc_error", "encrypted":true}), Some("empty_password_direct"),
                json!({"classification_evidence":"empty_password_failed_without_crc_proof", "backend_operation_result":"crc_error"})),
        ];
        for (worker, proof, expected) in cases {
            let mut failure = classify_worker_failure(&worker, proof, false);
            failure.evidence = worker_evidence(&worker, None, proof);
            let mut report = Vec::new();
            crate::failure_report::stream_json(&mut report, &failure, false, &Cancellation::new()).unwrap();
            let value: Value = serde_json::from_slice(&report).unwrap();
            for (key, expected) in expected.as_object().unwrap() {
                assert_eq!(&value["evidence"][key], expected);
            }
            let restored: Failure = serde_json::from_value(value).unwrap();
            assert_eq!(restored.kind, failure.kind);
            assert_eq!(restored.is_password_retry(), failure.is_password_retry());
        }
    }

    #[test]
    fn worker_stderr_survives_failure_evidence_serialization() {
        let evidence = worker_evidence(&json!({"stderr_tail":"native detail\n"}), None, None).unwrap();
        let encoded = serde_json::to_value(&evidence).unwrap();
        assert_eq!(encoded["stderr_tail"], "native detail\n");
        let decoded: FailureEvidence = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.stderr_tail.as_deref(), Some("native detail\n"));
    }

    #[test]
    fn password_evidence_controls_retry_without_reclassifying_weak_crc_damage() {
        // A kind-only test cannot distinguish the two inconclusive outcomes.
        // Exercise worker classification, retained evidence, serialization and
        // the shared physical-input projection used by Watch and notifications.
        let cases = [
            (serde_json::json!({"failure_kind": "checksum_error", "operation_result_name": "crc_error"}),
                Some("zipcrypto_header_byte"), FailureKind::PasswordInconclusive, false),
            (serde_json::json!({"operation_result_name": "crc_error",
                "diagnostics": {"failure_kind": "password_or_volume_inconclusive"}}),
                Some("zipcrypto_header_byte"), FailureKind::PasswordInconclusive, false),
            (serde_json::json!({"failure_kind": "password_or_volume_inconclusive"}),
                Some("zipcrypto_header_byte"), FailureKind::PasswordInconclusive, true),
            (serde_json::json!({"failure_kind": "checksum_error", "operation_result_name": "crc_error",
                "password_crc_proven": true}),
                Some("zipcrypto_header_byte"), FailureKind::Damaged, false),
            (serde_json::json!({"failure_kind": "checksum_error", "encrypted": true}),
                Some("empty_password_direct"), FailureKind::WrongPassword, true),
            (serde_json::json!({"password_candidates_all_rejected": true}),
                Some("zipcrypto_header_byte"), FailureKind::WrongPassword, true),
            (serde_json::json!({"failure_kind": "checksum_error"}),
                Some("strong_password_proof"), FailureKind::Damaged, false),
        ];
        for (worker, evidence, kind, retry) in cases {
            let mut failure = classify_worker_failure(&worker, evidence, true);
            failure.evidence = worker_evidence(&worker, None, evidence);
            assert_eq!(failure.kind, kind, "{worker}");
            let failure: Failure = serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
            assert_eq!(failure.is_password_retry(), retry, "{worker}");
            let outcome = PublicOutcome {
                archives: vec![ArchiveResult {
                    path: "carrier.bin".into(), format: "zip".into(), output: None,
                    failure: Some(failure), files: 0, bytes: 0, encrypted: Some(true),
                    depth: 1, offset: 123, end_offset: None, volume_completeness: None,
                    volume_attempts: None, source_paths: vec!["carrier.bin".into()],
                    password: None, discovery_source: DiscoverySource::Direct,
                    damage_flags: None, partial: false, retained: false,
                    recovered_complete_files: 0, promoted: false, promotion_original_path: None, scan_layout: Default::default(),
                }],
                ..PublicOutcome::default()
            };
            let failures = outcome.input_failures();
            let failure = failures.values().next().unwrap();
            assert_eq!(failure.retryable(), retry, "{worker}");
            assert_eq!(failure.terminal.is_some(), !retry, "{worker}");
        }
    }

    #[test]
    fn requests_wait_for_startup_even_when_discovery_would_be_empty() {
        use std::time::Duration;
        let timeout = Duration::from_secs(10);
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let process = Process::with_test_start(move || {
            entered.send(()).unwrap();
            gate.recv().unwrap();
            Err(io::Error::new(io::ErrorKind::NotFound, "startup gate failure"))
        });
        started.recv_timeout(timeout).unwrap();
        engine.worker.lock().unwrap().process = Some(process);
        let observer = Arc::new(|_: Event| panic!("discovery preceded the startup handshake"));
        let first = engine.submit(Request::new(Vec::new(), Mode::Scan), Arc::clone(&observer), |result| result);
        let second = engine.submit(Request::new(Vec::new(), Mode::Scan), observer, |result| result);
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        release.send(()).unwrap();
        for handle in [first, second] {
            let error = handle.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }
        let missing = Engine::new(PathBuf::from("sunpack-missing-worker-for-startup-test.exe"));
        let error = missing.submit(Request::new(Vec::new(), Mode::Scan), Arc::new(|_: Event| {}), |result| result)
            .join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn cancelled_startup_is_shared_until_cleanup_then_live_borrowers_retry() {
        use std::future::Future;
        use std::thread;
        use std::time::Duration;

        // Process-only tests cannot catch Engine publishing a second process
        // before cleanup, returning another request's cancellation, or retaining
        // a failed generation forever. Exercise both borrow paths on one slot.
        fn borrow(
            scheduler: &Arc<Scheduler>, engine: &Arc<Engine>, cancel: &Cancellation, id: u64,
        ) -> (thread::JoinHandle<io::Result<Arc<Process>>>, mpsc::Receiver<()>) {
            let scheduler = Arc::clone(scheduler);
            let engine = Arc::clone(engine);
            let cancel = cancel.clone();
            let (pending, parked) = mpsc::channel();
            let task = thread::spawn(move || {
                scheduler.run(id, Origin::Watch, &cancel, |_| {
                    Box::pin(async {
                        let config = WorkerConfig { space_poll_interval_ms: Some(1000), space_status_report_interval_ms: Some(1000) };
                        let mut worker = Box::pin(engine.worker(&config, &cancel));
                        let mut pending = Some(pending);
                        poll_fn(|cx| {
                            let result = worker.as_mut().poll(cx);
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
        let timeout = Duration::from_secs(10);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let scheduler = pool.install(Scheduler::new);
        let worker_path = std::env::temp_dir().join(format!(
            "sunpack_missing_startup_worker_{}_{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        let engine = Arc::new(Engine::new(worker_path));
        let (entered, spawning) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let initial = Process::with_test_start(move || {
            entered.send(()).unwrap();
            released.recv().unwrap();
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "abandoned spawn failure"))
        });
        spawning.recv_timeout(timeout).unwrap();
        engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
        let cancel = Cancellation::new();
        let (first, pending) = borrow(&scheduler, &engine, &cancel, 1);
        pending.recv_timeout(timeout).unwrap();
        cancel.cancel();
        initial.test_wait_startup_abandoned();
        assert!(!first.is_finished(), "last borrower returned before cleanup");
        assert!(initial.startup_abandoned());
        assert!(initial.alive());
        let (next, pending) = borrow(&scheduler, &engine, &Cancellation::new(), 2);
        pending.recv_timeout(timeout).unwrap();
        assert!(Arc::ptr_eq(engine.worker.lock().unwrap().process.as_ref().unwrap(), &initial));
        let (done, finished) = mpsc::channel();
        let independent_scheduler = Arc::clone(&scheduler);
        let independent = thread::spawn(move || {
            independent_scheduler.run(3, Origin::Foreground, &Cancellation::new(), |_| {
                Box::pin(async move { done.send(()).unwrap(); })
            });
        });
        let responsive = finished.recv_timeout(timeout);
        release.send(()).unwrap();
        assert!(is_cancellation(&first.join().unwrap().err().unwrap()));
        let error = next.join().unwrap().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "borrower inherited an abandoned generation");
        let replacement = Arc::clone(engine.worker.lock().unwrap().process.as_ref().unwrap());
        assert!(!Arc::ptr_eq(&initial, &replacement));
        assert!(!initial.alive());
        independent.join().unwrap();
        responsive.expect("abandoned startup cleanup retained the only host slot");

        // Genuine startup errors return to the current request, but do not
        // prevent a later request from starting a fresh generation.
        assert!(!engine.set_process_mode(ProcessMode::High).unwrap());
        let (later, _) = borrow(&scheduler, &engine, &Cancellation::new(), 4);
        assert_eq!(later.join().unwrap().err().unwrap().kind(), io::ErrorKind::NotFound);
        let owner = engine.worker.lock().unwrap();
        assert!(!Arc::ptr_eq(owner.process.as_ref().unwrap(), &replacement));
        assert_eq!(owner.desired_mode, ProcessMode::High);
        drop(owner);
        let ready = Process::with_test_input(Vec::new());
        engine.worker.lock().unwrap().process = Some(Arc::clone(&ready));
        let (later, _) = borrow(&scheduler, &engine, &Cancellation::new(), 5);
        assert!(Arc::ptr_eq(&later.join().unwrap().unwrap(), &ready));
    }

    #[test]
    fn process_mode_waits_do_not_block_worker_borrows_and_survive_replacement() {
        use crate::scan::worker_wire::encode_worker_frame;
        use std::thread;
        use std::time::Duration;

        // Direct Process tests miss the ownership mutex above the transport.
        // Hold both the pipe write and the ACK while a real scheduled poll
        // borrows the worker, then cover serialized changes across replacement.
        struct ModeInput {
            writes: mpsc::Sender<Vec<u8>>,
            release: mpsc::Receiver<()>,
            shutdown: Vec<u8>,
        }
        impl io::Write for ModeInput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes != self.shutdown.as_slice() {
                    self.writes.send(bytes.to_vec()).unwrap();
                    self.release.recv().unwrap();
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        fn process() -> (Arc<Process>, mpsc::Receiver<Vec<u8>>, mpsc::Sender<()>) {
            let (writes, written) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let input = ModeInput {
                writes,
                release: released,
                shutdown: encode_worker_frame(&json!({"worker_command": "shutdown"})).unwrap(),
            };
            (Process::with_test_input(input), written, release)
        }
        fn borrow_on_scheduler(
            scheduler: &Arc<Scheduler>,
            engine: &Arc<Engine>,
            expected: &Arc<Process>,
            id: u64,
        ) -> (thread::JoinHandle<()>, mpsc::Receiver<bool>) {
            let scheduler = Arc::clone(scheduler);
            let engine = Arc::clone(engine);
            let expected = Arc::clone(expected);
            let (borrowed, received) = mpsc::channel();
            let task = thread::spawn(move || {
                scheduler.run(id, Origin::Foreground, &Cancellation::new(), |_| {
                    Box::pin(async move {
                        let process = engine
                            .worker(&WorkerConfig {
                                space_poll_interval_ms: Some(1000),
                                space_status_report_interval_ms: Some(1000),
                            }, &Cancellation::new())
                            .await
                            .unwrap();
                        borrowed.send(Arc::ptr_eq(&process, &expected)).unwrap();
                    })
                });
            });
            (task, received)
        }
        fn change(engine: &Arc<Engine>, mode: ProcessMode) -> thread::JoinHandle<io::Result<bool>> {
            let engine = Arc::clone(engine);
            thread::spawn(move || engine.set_process_mode(mode))
        }
        fn ack(process: &Process, mode: &str) {
            process.test_event(json!({"type": "process_mode_ack", "mode": mode, "applied": true}));
        }
        fn command(mode: &str) -> Vec<u8> {
            encode_worker_frame(&json!({"worker_command": "set_process_mode", "mode": mode})).unwrap()
        }

        let timeout = Duration::from_secs(10);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let scheduler = pool.install(Scheduler::new);
        let engine = Arc::new(Engine::new(PathBuf::from("unused-worker")));
        let (initial, writing, release) = process();
        engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
        let background = change(&engine, ProcessMode::Background);
        assert_eq!(writing.recv_timeout(timeout).unwrap(), command("background"));
        let (first, first_done) = borrow_on_scheduler(&scheduler, &engine, &initial, 1);
        let during_write = first_done.recv_timeout(timeout);
        release.send(()).unwrap();
        let (second, second_done) = borrow_on_scheduler(&scheduler, &engine, &initial, 2);
        let during_ack = second_done.recv_timeout(timeout);
        let high = change(&engine, ProcessMode::High);
        ack(&initial, "background");
        assert!(background.join().unwrap().unwrap());
        assert_eq!(writing.recv_timeout(timeout).unwrap(), command("high"));
        release.send(()).unwrap();
        ack(&initial, "high");
        assert!(high.join().unwrap().unwrap());
        first.join().unwrap();
        second.join().unwrap();
        assert!(during_write.expect("mode write held the worker ownership mutex"));
        assert!(during_ack.expect("mode ACK held the worker ownership mutex"));

        let normal = change(&engine, ProcessMode::Normal);
        assert_eq!(writing.recv_timeout(timeout).unwrap(), command("normal"));
        release.send(()).unwrap();
        let (replacement, replacement_writing, replacement_release) = process();
        {
            // Model worker() publishing its replacement under this same owner
            // lock, using the desired mode already published by the transition.
            let mut owner = engine.worker.lock().unwrap();
            assert!(matches!(owner.desired_mode, ProcessMode::Normal));
            replacement.test_event(json!({
                "type": "worker_ready", "process_mode": "normal", "process_mode_applied": true,
            }));
            owner.process = Some(Arc::clone(&replacement));
            initial.test_exit();
        }
        assert!(normal.join().unwrap().is_err());
        let final_change = change(&engine, ProcessMode::Background);
        assert_eq!(
            replacement_writing.recv_timeout(timeout).unwrap(),
            command("background"),
        );
        replacement_release.send(()).unwrap();
        ack(&initial, "normal"); // An obsolete ACK cannot rewrite the new owner's state.
        ack(&replacement, "background");
        assert!(final_change.join().unwrap().unwrap());
        let (borrowed, received) = borrow_on_scheduler(&scheduler, &engine, &replacement, 3);
        assert!(received.recv_timeout(timeout).unwrap());
        borrowed.join().unwrap();
        let cached_engine = Arc::clone(&engine);
        let (cached_done, cached_result) = mpsc::channel();
        let cached = thread::spawn(move || {
            cached_done.send(cached_engine.set_process_mode(ProcessMode::Background)).unwrap();
        });
        let cached_result = cached_result.recv_timeout(timeout);
        if cached_result.is_err() {
            // A cache regression must fail rather than leave this test's
            // writer/control thread blocked on an unexpected extra command.
            if replacement_writing.recv_timeout(timeout).is_ok() {
                replacement_release.send(()).unwrap();
                ack(&replacement, "background");
            } else {
                replacement.test_exit();
            }
        }
        cached.join().unwrap();
        assert!(cached_result.expect("applied mode cache was lost").unwrap());
        assert!(replacement_writing.try_recv().is_err());
        assert!(matches!(
            engine.worker.lock().unwrap().desired_mode,
            ProcessMode::Background,
        ));
    }

    #[test]
    fn preflight_damage_keeps_a_proven_password_in_scan_and_extract() {
        use std::future::Future;
        use std::task::{Context, Poll, Wake, Waker};
        struct NoWake;
        impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
        for mode in [Mode::Scan, Mode::Extract] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(vec![], mode);
            let observer = |_: Event| {};
            let run = test_run(&engine, &request, &observer);
            let mut input = ArchiveInput::file("damaged.rar".into(), "rar".into(), "damaged".into());
            input.analysis.password_required = true;
            let logical = LogicalInput { password_probe: None, input, password: Some(Arc::from("confirmed")),
                failure: Some(Failure::new(FailureKind::Damaged, "missing ENDARC")) };
            let mut shell = engine.shell.branch();
            let mut outcome = Outcome::default();
            let mut future = Box::pin(run.execute_input(logical, 1, DiscoverySource::Embedded,
                1, None, None, &run.candidates, &mut shell, &mut outcome));
            let waker = Waker::from(Arc::new(NoWake));
            let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
                panic!("preflight failure started worker execution");
            };
            let result = result.unwrap().result;
            assert_eq!(result.password.as_deref(), Some("confirmed"));
            assert_eq!(result.failure.unwrap().kind, FailureKind::Damaged);
            assert!(result.output.is_none());
        }
    }

    #[test]
    fn worker_failure_preserves_only_noncontradicted_strong_password() {
        use crate::scan::worker_wire::NativeWorkerFrameDecoder;
        struct Input(mpsc::Sender<Vec<u8>>);
        impl io::Write for Input {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.0.send(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let source = crate::test_support::temp_file("verified_failure", &encrypted_rar_fixture());
        for (failure, kind, expected) in [
            ("unsupported_method", FailureKind::Unsupported, Some("secret")),
            ("encrypted_or_wrong_password", FailureKind::WrongPassword, None),
        ] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(Vec::new(), Mode::Scan);
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
                Arc::from([Arc::from("secret")]), None, &engine.password_attempts, None,
            );
            let (sent, received) = mpsc::channel();
            let process = Process::with_test_input(Input(sent));
            engine.worker.lock().unwrap().process = Some(Arc::clone(&process));
            let responder = std::thread::spawn(move || {
                let bytes = received.recv().unwrap();
                let mut decoder = NativeWorkerFrameDecoder::default();
                let frames = decoder.feed(&bytes).unwrap();
                decoder.finish().unwrap();
                let request = &frames[0].summary;
                let id = &request["job_id"];
                process.test_event(json!({"type":"result", "job_id":id,
                    "status":"error", "failure_kind":failure,
                    "unsupported_method":failure == "unsupported_method",
                    "failure_stage":"item_extract", "encrypted":true}));
                process.test_event(json!({"type":"native_event", "event":"job_finished", "job_id":id}));
                request.clone()
            });
            let mut input = ArchiveInput::file(source.to_string_lossy().into_owned(), "rar".into(), "encrypted".into());
            input.analysis.password_required = true;
            // No discovery-supplied password: only the real probe's strong
            // plan can populate the failed result, not an existing receipt.
            let logical = LogicalInput { password_probe: None, input, password: None, failure: None };
            let mut shell = engine.shell.branch();
            let mut outcome = Outcome::default();
            let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
                Box::pin(run.execute_input(logical, 1, DiscoverySource::Direct,
                    1, None, None, &run.candidates, &mut shell, &mut outcome))
            }).unwrap().result;
            let submitted = responder.join().unwrap();
            assert_eq!(submitted["password_verified"], true);
            assert_eq!(submitted["request_id"], run.worker_request_id);
            assert_eq!(submitted["password"], "secret");
            assert_eq!(result.failure.unwrap().kind, kind);
            assert_eq!(result.password.as_deref(), expected);
        }
        release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn recovery_selection_uses_unique_physical_anchors_without_io() {
        let source = crate::test_support::temp_file("recovery_anchor", b"existing second volume");
        let mut old = ArchiveInput::file(source.to_string_lossy().into_owned(), "7z".into(), "old".into());
        let generations = HashMap::from([(path_key(&old.entry_path), capture_file_generation(&source).unwrap())]);
        let result = receipt(&old, DiscoverySource::Relations, 1);
        let mut checkpoint = InputCheckpoint::create(&source, Arc::new(old.clone()), &result, &generations, None).unwrap();
        checkpoint.install_report(InputCheckpoint::report_state(&old, &result, None, None, 4, 7));
        let mut arrived = old.clone();
        // Relations can choose an arriving first volume as the new entry while
        // retaining the previous second volume as a physical source anchor.
        arrived.entry_path = source.with_extension("first").to_string_lossy().into_owned();
        arrived.parts = Box::new([crate::io::archive_state::InputPart::range(
            crate::io::archive_state::InputExtent { path: old.entry_path.clone(), start: 0, end: None })]);
        let logical = |input| LogicalInput { password_probe: None, input, password: None, failure: None };
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let observer = |_: Event| {};
        let mut request = Request::new(Vec::new(), Mode::Extract);
        request.checkpoints.push(checkpoint);
        let mut run = test_run(&engine, &request, &observer);
        Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&source.to_string_lossy()))).or_default().insert(request.checkpoints[0].key(), 0);
        let exact = run.select_checkpoints(&source, &[logical(old.clone())]);
        assert_eq!(exact[0].unwrap().report_position(), Some(4));
        assert!(run.checkpoint_anchors.get().is_none(), "exact identity must not build an anchor index");
        let matched = run.select_checkpoints(&source, &[logical(arrived.clone())]);
        assert_eq!(matched[0].unwrap().report_position(), Some(4));
        assert!(!matched[0].unwrap().valid_for(&arrived, &generations), "identity must not bypass layout validation");
        let consumed = run.select_checkpoints(&source, &[logical(old.clone()), logical(arrived.clone())]);
        assert!(consumed[0].is_some() && consumed[1].is_none());
        let mut different_format = arrived.clone(); different_format.format_hint = "zip".into();
        assert!(run.select_checkpoints(&source, &[logical(different_format)])[0].is_none());
        let mut different_offset = arrived.clone(); different_offset.parts[0].extent.start = 1;
        assert!(run.select_checkpoints(&source, &[logical(different_offset)])[0].is_none());
        old.mode = crate::io::archive_state::OpenMode::FileRange;
        assert!(run.select_checkpoints(&source, &[logical(old.clone())])[0].is_some(), "mode is not logical identity");
        // Remapping the descriptor does not replace its stable logical ID.
        let mut remapped_result = receipt(&arrived, DiscoverySource::Relations, 1);
        remapped_result.source_paths = vec![source.clone()];
        let mut remapped = InputCheckpoint::create(&source, Arc::new(arrived.clone()), &remapped_result, &generations, None).unwrap();
        remapped.install_report(InputCheckpoint::report_state(&arrived, &remapped_result, None,
            Some(&request.checkpoints[0]), 1, 1));
        let mut remapped_request = Request::new(Vec::new(), Mode::Extract);
        remapped_request.checkpoints.push(remapped);
        let mut remapped_run = test_run(&engine, &remapped_request, &observer);
        Arc::get_mut(&mut remapped_run).unwrap().checkpoints.entry(Arc::from(path_key(&source.to_string_lossy()))).or_default().insert(remapped_request.checkpoints[0].key(), 0);
        assert_eq!(remapped_run.select_checkpoints(&source, &[logical(old.clone())])[0].unwrap().report_position(), Some(4));
        assert!(remapped_run.checkpoint_anchors.get().is_none());
        let changed_carrier = source.with_extension("arrived-carrier");
        assert_eq!(run.select_checkpoints(&changed_carrier, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(4));
        // Watch batches carry several owners' receipts. Shared bytes never
        // authorize taking another physical task's identity or output slot.
        let other_carrier = source.with_extension("other-carrier");
        let other_result = receipt(&old, DiscoverySource::Relations, 1);
        let mut other_group = InputCheckpoint::create(&other_carrier, Arc::new(old.clone()), &other_result, &generations, None).unwrap();
        other_group.install_report(InputCheckpoint::report_state(&old, &other_result, None, None, 9, 9));
        let mut grouped_request = request.clone();
        grouped_request.checkpoints.push(other_group);
        let mut grouped = test_run(&engine, &grouped_request, &observer);
        for (index, checkpoint) in grouped_request.checkpoints.iter().enumerate() {
            Arc::get_mut(&mut grouped).unwrap().checkpoints
                .entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy())))
                .or_default().insert(checkpoint.key(), index);
        }
        assert_eq!(grouped.select_checkpoints(&source, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(4));
        assert_eq!(grouped.select_checkpoints(&other_carrier, &[logical(arrived.clone())])[0].unwrap().report_position(), Some(9));
        assert!(grouped.select_checkpoints(&changed_carrier, &[logical(arrived.clone())])[0].is_none(),
            "ambiguous prior carrier must not be guessed");
        // Two distinct old logical identities sharing this anchor are ambiguous.
        let mut other = arrived.clone(); other.entry_path.push_str("-other");
        let mut other_result = receipt(&other, DiscoverySource::Relations, 1);
        other_result.source_paths = vec![source.clone()];
        let other = InputCheckpoint::create(&source, Arc::new(other.clone()), &other_result, &generations, None).unwrap();
        request.checkpoints.push(other);
        let mut ambiguous = test_run(&engine, &request, &observer);
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            Arc::get_mut(&mut ambiguous).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
        }
        assert!(ambiguous.select_checkpoints(&source, &[logical(arrived)])[0].is_none());
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn password_failure_keeps_real_planned_output_after_cleanup() {
        let source = crate::test_support::temp_file("password_output_order", &encrypted_rar_fixture());
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(Vec::new(), Mode::Extract);
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let mut input = ArchiveInput::file(source.to_string_lossy().into_owned(), "rar".into(), "encrypted".into());
        input.analysis.password_required = true;
        let logical = LogicalInput { password_probe: None, input, password: None, failure: None };
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let executed = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.execute_input(logical, 1, DiscoverySource::Direct,
                1, None, None, &run.candidates, &mut shell, &mut outcome))
        }).unwrap();
        assert!(matches!(executed.result.failure.as_ref().unwrap().context.as_deref(),
            Some(super::super::FailureContext::PasswordResolution)));
        let output = executed.planned_output.as_ref().expect("output reserved before password resolution");
        assert!(!output.exists(), "failed password output was not cleaned");
        assert!(executed.result.output.is_none());
        assert!(InputCheckpoint::report_state(&executed.input, &executed.result,
            Some(output), None, 1, 1).is_some());
        release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn completed_cleanup_retires_jobs_and_keeps_only_failures() {
        let tasks = Arc::new(Mutex::new(CleanupTasks::default()));
        Scheduler::new().run(1, Origin::Foreground, &Cancellation::new(), |spawner| {
            let tasks = Arc::clone(&tasks);
            Box::pin(async move {
                for id in 0..32 {
                    let completed = Arc::clone(&tasks);
                    let mut pending = tasks.lock().unwrap();
                    let task = spawner.spawn(Box::pin(async move {
                        let failures = if id == 0 {
                            cleanup_failure(Path::new("source.zip"), "delete", Err(io::ErrorKind::PermissionDenied.into()))
                                .into_iter().collect()
                        } else {
                            Vec::new()
                        };
                        completed.lock().unwrap().retire(id, failures)
                    }));
                    pending.active.insert(id, PendingCleanup { paths: vec![PathBuf::from("source.zip")], task });
                }
            })
        });
        let mut tasks = tasks.lock().unwrap();
        assert!(tasks.active.is_empty(), "completed paths must not remain in root-drain scans");
        assert!(tasks.take_failures(Some(Path::new("other"))).is_empty());
        let failures = tasks.take_failures(None);
        let [failure] = failures.as_slice() else { panic!("expected one failed cleanup") };
        assert_eq!(failure.path, Path::new("source.zip"));
        assert_eq!(failure.status, CleanupStatus::Failed);
    }

    fn test_run<'a, O: Observer>(
        engine: &'a Engine,
        request: &'a Request,
        observer: &'a O,
    ) -> Arc<Run<'a, O>> {
        Arc::new(Run {
            engine: engine.clone(),
            request: Arc::new(request.clone()),
            resolve_aliases: false,
            candidates: CandidateSet::new(Arc::from([]), None, &engine.password_attempts, None),
            options: OnceLock::new(),
            deep_options: None,
            analysis: NativeAnalysisConfig::new(Vec::<(String, bool)>::new()),
            observer: ObserverRef::Borrowed(observer),
            worker_request_id: "1".to_owned(),
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: Arc::clone(&engine.output_names), owner: 1 },
            created_outputs: Mutex::default(),
            output_base: None,
            target_directories: TargetDirectories::new(&request.inputs),
            checkpoints: HashMap::new(),
            checkpoint_anchors: OnceLock::new(),
            promoted_sources: HashMap::new(),
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
            cleanup_tasks: Mutex::default(),
            cleanup_refs: Arc::default(),
        })
    }

    #[test]
    fn replacement_worker_spawn_failure_preserves_start_classification() {
        let source = crate::test_support::temp_file("replacement_worker", b"archive");
        let engine = Engine::new(source.with_extension("missing-worker.exe"));
        let initial = Process::with_test_input(Vec::new());
        engine.worker.lock().unwrap().process = Some(Arc::clone(&initial));
        let request = Request::new(vec![source.clone()], Mode::Scan);
        let observer = |event: Event| {
            if matches!(event, Event::Waiting { .. }) { initial.test_exit(); }
        };
        let run = test_run(&engine, &request, &observer);
        let logical = LogicalInput {
            input: ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into()),
            password_probe: None, password: None, failure: None,
        };
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(async {
                // The first borrow and handshake succeed inside this request.
                let started = engine.worker(&request.config.performance.worker, &request.cancel).await.unwrap();
                assert!(Arc::ptr_eq(&started, &initial));
                run.execute_input(logical, 1, DiscoverySource::Direct, 1, None, None,
                    &run.candidates, &mut shell, &mut outcome).await
            })
        }).unwrap().result;
        let failure = result.failure.unwrap();
        assert_eq!(failure.kind, FailureKind::ProcessError);
        let evidence = failure.evidence.unwrap();
        assert_eq!(evidence.native_kind.as_deref(), Some("process_start"));
        assert_eq!(evidence.stage.as_deref(), Some("worker_start"));
        assert!(!failure.message.is_empty());
        assert!(!Arc::ptr_eq(engine.worker.lock().unwrap().process.as_ref().unwrap(), &initial));
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn watch_family_join_preserves_owner_and_propagates_infrastructure_error() {
        use std::future::Future;
        use std::task::Context;

        let first = crate::test_support::temp_file("join_watch_first_head", b"first");
        let second = crate::test_support::temp_file("join_watch_second_head", b"second");
        let tail1 = crate::test_support::temp_file("join_watch_tail1", b"common tail 1");
        let tail2 = crate::test_support::temp_file("join_watch_tail2", b"common tail 2");
        let task = |path: &Path| Task {
            primary: None,
            owned_paths: [path, &tail1, &tail2].into_iter()
                .map(|member| member.to_string_lossy().into_owned()).collect(),
            inputs: vec![LogicalInput { password_probe: None, password: None,
                input: ArchiveInput::file(path.to_string_lossy().into_owned(), "7z".into(), "split".into()),
                failure: None }],
            source: DiscoverySource::Relations, retry: None, scope: None,
        };
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let leases = &engine.leases;
        let mut request = Request::new(vec![tail1.clone()], Mode::Extract);
        request.origin = Origin::Watch;
        let leader = Arc::new(request.clone());
        let follower = Arc::new(Request {
            inputs: vec![tail2.clone()], cancel: Cancellation::new(), ..request.clone()
        });
        let notify = |_: Event| {};
        let members = test_run(&engine, &leader, &notify).watch_generations(&Discovered {
            tasks: vec![task(&first), task(&second)], ..Discovered::default()
        }).expect("two logical roots can share one physical generation union");
        let follower_members = test_run(&engine, &follower, &notify).watch_generations(&Discovered {
            tasks: vec![task(&second), task(&first)], ..Discovered::default()
        }).unwrap();
        assert_eq!(members.len(), 4);
        let mut cx = Context::from_waker(Waker::noop());

        let WatchFamily::Owner(owner) = leases.claim_watch(1, &members, &leader) else {
            panic!("first request owns extraction");
        };
        let different_policy = Arc::new(Request { deep: true, ..request });
        let WatchFamily::Owner(other) = leases.claim_watch(2, &members, &different_policy) else {
            panic!("different policy must execute independently");
        };
        let WatchFamily::Follower(key, id, settlement) = leases.claim_watch(3, &follower_members, &follower) else {
            panic!("equivalent request must join the active owner");
        };
        assert_eq!(id, 1);
        let mut wait = Box::pin(leases.join_watch(&key, id, &settlement, &follower.cancel));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        follower.cancel.cancel();
        assert!(matches!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        drop(wait);
        assert!(!leader.cancel.cancelled());

        let uncancelled = Cancellation::new();
        let mut wait = Box::pin(leases.join_watch(&key, id, &settlement, &uncancelled));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        owner.finish(&Err(io::Error::other("write failed")), &leader.cancel);
        // A replacement owner can register before existing followers wake.
        let WatchFamily::Owner(owner) = leases.claim_watch(4, &members, &leader) else {
            panic!("failed owner must retire");
        };
        let Poll::Ready(Err(error)) = wait.as_mut().poll(&mut cx) else {
            panic!("infrastructure error must propagate to the waiting follower");
        };
        assert_eq!(error.to_string(), "write failed");
        drop(wait);
        drop(owner);
        drop(other);
        let state = leases.state.lock().unwrap();
        assert!(state.watch.is_empty() && state.waiters.is_empty() && state.blocked_by.is_empty());
        drop(state);
        for source in [first, second, tail1, tail2] { fs::remove_file(source).unwrap(); }
    }

    #[test]
    fn completed_watch_family_returns_existing_success_without_extracting_or_reowning_output() {
        struct Reuse {
            output: PathBuf,
            events: Mutex<Vec<Event>>,
            queries: std::sync::atomic::AtomicUsize,
        }
        impl Observer for Reuse {
            fn notify(&self, event: Event) { self.events.lock().unwrap().push(event); }
            fn completed_sources(&self, generations: &HashMap<String, PhysicalFileGeneration>) -> io::Result<Option<PathBuf>> {
                if !self.output.is_dir() { return Ok(None); }
                assert_eq!(generations.len(), 2);
                self.queries.fetch_add(1, Ordering::SeqCst);
                Ok(Some(self.output.clone()))
            }
            fn register_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
                panic!("completed output must not be created again")
            }
            fn reuse_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
                panic!("completed output must not acquire a second durable owner")
            }
            fn after_output(&self, _: &ArchiveResult) -> io::Result<()> {
                panic!("completed output must not be republished")
            }
        }
        let head = crate::test_support::temp_file("completed_family_head", b"head");
        let tail = crate::test_support::temp_file("completed_family_tail", b"tail");
        let launcher = crate::test_support::temp_file("completed_family_launcher", b"standalone executable");
        let output = head.with_extension("existing-output");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("damaged-inner.zip"), b"retained terminal inner failure").unwrap();
        let engine = Engine::new(PathBuf::from("must-not-start-worker.exe"));
        let mut request = Request::new(vec![tail.clone()], Mode::Extract);
        request.origin = Origin::Watch;
        let observer = Reuse { output: output.clone(), events: Mutex::default(), queries: 0.into() };
        let run = test_run(&engine, &request, &observer);
        let mut input = ArchiveInput::file(head.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        input.mode = OpenMode::NativeVolumes;
        input.parts = [&head, &tail].map(|path| crate::io::archive_state::InputPart::range(
            crate::io::archive_state::InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: None },
        )).into();
        let task = Task {
            primary: None, owned_paths: [&head, &tail, &launcher].map(|path| path.to_string_lossy().into_owned()).into(),
            inputs: vec![LogicalInput { password_probe: None,
                input,
                password: None, failure: None }],
            source: DiscoverySource::Relations, retry: None, scope: None,
        };
        let (generations, missing) = run.capture_generations(&task);
        assert_eq!(generations.len(), 3, "launcher remains owned for cleanup");
        assert_eq!(run.requested_generation(&task, true).unwrap().len(), 2);
        // Foreground/nested tasks and incomplete observations do not consume
        // the Watch-only completed family fact.
        assert!(matches!(run.task_admission(&task, &generations, &[], true, false, |_| None).unwrap(), TaskAdmission::Execute(None)));
        let mut partial = generations.clone();
        partial.remove(&path_key(&tail.to_string_lossy()));
        assert!(matches!(run.task_admission(&task, &partial, &[tail.clone()], true, true, |_| None).unwrap(), TaskAdmission::Execute(None)));
        assert!(matches!(run.task_admission(&task, &HashMap::new(), &[head.clone(), tail.clone()], true, true, |_| None).unwrap(), TaskAdmission::Departed));
        let single = Task { primary: None, owned_paths: vec![head.to_string_lossy().into_owned()],
            inputs: vec![LogicalInput { password_probe: None,
                input: ArchiveInput::file(head.to_string_lossy().into_owned(), "zip".into(), "archive".into()),
                password: None, failure: None }],
            source: DiscoverySource::Relations, retry: None, scope: None };
        assert!(matches!(run.task_admission(&single, &partial, &[], true, true, |_| None).unwrap(), TaskAdmission::Execute(None)));
        assert_eq!(observer.queries.load(Ordering::SeqCst), 0);
        assert!(matches!(run.task_admission(&task, &partial, &[tail.clone()], true, true, |path| generations.get(path)).unwrap(),
            TaskAdmission::Completed(ref path) if path == &output));
        assert!(matches!(run.task_admission(&task, &HashMap::new(), &[head.clone(), tail.clone()], true, true,
            |path| generations.get(path)).unwrap(), TaskAdmission::Departed));
        let changed = HashMap::from([(path_key(&head.to_string_lossy()), generations[&path_key(&tail.to_string_lossy())].clone())]);
        assert!(matches!(run.task_admission(&task, &changed, &[tail.clone()], true, true, |path| generations.get(path)).unwrap(), TaskAdmission::Execute(None)));
        assert_eq!(observer.queries.swap(0, Ordering::SeqCst), 1);
        assert!(missing.is_empty());
        // A successful worker can select only two of three candidate sources.
        // The cache must store the complete admitted set and omit the unrelated
        // executable. Do not derive its key from the successful worker output.
        let alternative = crate::test_support::temp_file("completed_family_alternative", b"candidate");
        let mut alternative_input = task.entry().clone();
        alternative_input.volume_attempts = Some(Box::new(crate::io::archive_state::VolumeAttemptPlan {
            sources: [&head, &tail, &alternative].map(|path| crate::io::archive_state::InputExtent {
                path: path.to_string_lossy().into_owned(), start: 0, end: None,
            }).into(),
            layouts: Box::new([]), domains: Box::new([]), head_size_from_total: None,
            minimum_size: None, tail_totals: Box::new([]),
        }));
        let alternative_task = Task {
            primary: None,
            owned_paths: [&head, &tail, &alternative, &launcher].map(|path| path.to_string_lossy().into_owned()).into(),
            inputs: vec![LogicalInput { password_probe: None, input: alternative_input, password: None, failure: None }],
            source: DiscoverySource::Relations, retry: None, scope: None,
        };
        let uncached = Reuse { output: output.join("absent"), events: Mutex::default(), queries: 0.into() };
        let uncached = test_run(&engine, &request, &uncached);
        let (physical, missing) = uncached.capture_generations(&alternative_task);
        let TaskAdmission::Execute(Some(cache_key)) = uncached.task_admission(
            &alternative_task, &physical, &missing, true, true, |_| None,
        ).unwrap() else { panic!("uncached speculative family should execute"); };
        let candidate_paths = [&head, &tail, &alternative].map(|path| path_key(&path.to_string_lossy()));
        assert_eq!(cache_key.len(), candidate_paths.len());
        assert!(candidate_paths.iter().all(|path| cache_key.contains_key(path)));
        fs::remove_file(alternative).unwrap();
        let outcome = Scheduler::new().run(1, Origin::Watch, &request.cancel, |spawner| {
            run.execute_task(run.register_task(task), 1, 1, None, spawner)
        }).unwrap();
        assert_eq!(observer.queries.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.archives.len(), 1);
        let reused = &outcome.archives[0];
        assert_eq!(reused.path, head);
        assert_eq!(reused.output.as_ref(), Some(&output));
        assert_eq!(reused.source_paths, [head.clone(), tail.clone(), launcher.clone()]);
        assert!(reused.failure.is_none() && !reused.partial);
        assert_eq!(reused.files, 0); // No invented member inventory/count.
        assert!(outcome.cleanup_results.is_empty());
        assert!(outcome.checkpoints.is_empty());
        assert!(run.created_outputs.lock().unwrap().0.is_empty());
        assert!(run.cleanup_refs.lock().unwrap().paths.is_empty());
        assert!(matches!(observer.events.lock().unwrap().as_slice(),
            [Event::Finished { id: 1, result, .. }] if result.output.as_ref() == Some(&output)));
        assert_eq!(fs::read(output.join("damaged-inner.zip")).unwrap(), b"retained terminal inner failure");
        assert!(launcher.is_file());
        fs::remove_dir_all(output).unwrap();
        fs::remove_file(head).unwrap();
        fs::remove_file(tail).unwrap();
        fs::remove_file(launcher).unwrap();
    }

    #[test]
    fn advisory_planning_read_error_preserves_the_original_input() {
        // The analysis open fails, but the later extraction path must still
        // receive the original input rather than a fabricated terminal failure.
        let path = crate::test_support::temp_file("planning_read_error", b"archive");
        fs::remove_file(&path).unwrap();
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(vec![path.clone()], Mode::Scan);
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let input = ArchiveInput::file(path.to_string_lossy().into_owned(), "rar".into(), "archive".into());
        let mut task = Task {
            primary: None,
            owned_paths: vec![input.entry_path.clone()],
            inputs: vec![LogicalInput { password_probe: None, input, password: Some(Arc::from("secret")), failure: None }],
            source: DiscoverySource::Direct,
            retry: None,
            scope: None,
        };
        run.plan_inputs(&mut task).unwrap();
        assert_eq!(task.inputs.len(), 1);
        assert_eq!(task.inputs[0].input.entry_path, path.to_string_lossy());
        assert_eq!(task.inputs[0].input.format_hint, "rar");
        assert_eq!(task.inputs[0].password.as_deref(), Some("secret"));
        assert!(task.inputs[0].failure.is_none());
        // Restore a valid archive before the next stage, modelling the end of
        // the transient read failure. Confirm the original logical input reaches
        // the real worker submission path using the existing test transport.
        fs::write(&path, encrypted_rar_fixture()).unwrap();
        struct Input(mpsc::Sender<Vec<u8>>);
        impl io::Write for Input {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.0.send(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let (sent, received) = mpsc::channel();
        let process = Process::with_test_input(Input(sent));
        engine.worker.lock().unwrap().process = Some(Arc::clone(&process));
        struct CancelOnPanic(Cancellation);
        impl Drop for CancelOnPanic {
            fn drop(&mut self) {
                if std::thread::panicking() { self.0.cancel(); }
            }
        }
        let responder_cancel = request.cancel.clone();
        let responder = std::thread::spawn(move || {
            // A transport assertion must wake the awaiting request too, rather
            // than leave the scheduler parked after this thread has unwound.
            let _cancel_on_panic = CancelOnPanic(responder_cancel);
            let bytes = received.recv_timeout(std::time::Duration::from_secs(10))
                .expect("planning error suppressed worker submission");
            let mut decoder = crate::scan::worker_wire::NativeWorkerFrameDecoder::default();
            let frames = decoder.feed(&bytes).unwrap();
            decoder.finish().unwrap();
            let submitted = &frames[0].summary;
            let id = &submitted["job_id"];
            process.test_event(json!({"type":"result", "job_id":id,
                "status":"ok", "archive_type":"rar", "encrypted":true}));
            process.test_event(json!({"type":"native_event", "event":"job_finished", "job_id":id}));
            submitted.clone()
        });
        let logical = task.inputs.remove(0);
        let cancel_input = logical.input.clone();
        let mut shell = engine.shell.branch();
        let mut outcome = Outcome::default();
        let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
            Box::pin(run.execute_input(logical, 1, DiscoverySource::Direct,
                1, None, None, &run.candidates, &mut shell, &mut outcome))
        }).unwrap().result;
        let submitted = responder.join().unwrap();
        assert_eq!(submitted["operation"], "scan");
        assert_eq!(submitted["password"], "secret");
        assert!(result.failure.is_none());
        // With an existing, readable input, this must be a cancellation error,
        // not the earlier NotFound error accidentally satisfying is_err().
        task.inputs.push(LogicalInput { password_probe: None, input: cancel_input, password: None, failure: None });
        request.cancel.cancel();
        let error = request.cancel.run(|| run.plan_inputs(&mut task)).unwrap_err();
        assert!(is_cancellation(&error));
        release_reader_resources_under_roots(vec![path.to_string_lossy().into_owned()]).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn partial_departure_is_an_admission_failure_and_keeps_surviving_generation() {
        let path = crate::test_support::temp_file("partial_departure", b"archive");
        let missing = path.with_extension("missing");
        for (mode, count) in [Mode::Scan, Mode::Extract].into_iter()
            .flat_map(|mode| [1, 2].map(|count| (mode, count))) {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            assert_eq!(engine.next_id(), 1); // Reserve the parent observer ID.
            let request = Request::new(vec![path.clone()], mode);
            let events = Mutex::new(Vec::new());
            let observer = |event: Event| { events.lock().unwrap().push(event); };
            let run = test_run(&engine, &request, &observer);
            let mut input = ArchiveInput::file(path.to_string_lossy().into_owned(), "rar".into(), "archive".into());
            input.mode = OpenMode::NativeVolumes;
            input.parts = [&path, &missing].map(|path| crate::io::archive_state::InputPart::range(
                crate::io::archive_state::InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: None },
            )).into();
            let companion = missing.with_extension("exe");
            let mut task = Task {
                primary: None,
                owned_paths: [&path, &missing, &companion].map(|path| path.to_string_lossy().into_owned()).into(),
                inputs: vec![LogicalInput { password_probe: None,
                    input,
                    password: None, failure: None,
                }],
                source: DiscoverySource::Relations, retry: None,
                scope: Some(Arc::new(crate::scan::scope::NativeDiscoveryScope::new(
                    path.parent().unwrap().to_string_lossy().into_owned(), Some(0), Vec::new()))),
            };
            let (generations, absent) = run.capture_generations(&task);
            assert_eq!(absent, vec![missing.clone()]);
            assert_eq!(generations.len(), 1);
            assert_eq!(generations[&path_key(&path.to_string_lossy())], capture_file_generation(&path).unwrap());
            assert!(matches!(run.task_admission(&task, &generations, &absent, true, false, |_| None).unwrap(), TaskAdmission::Execute(None)));
            run.admit_missing_inputs(&mut task, &absent, false);
            assert!(task.inputs[0].failure.is_none());
            task.inputs[0].failure = Some(Failure::new(FailureKind::Unsupported, "discovery")
                .with_context(super::super::FailureContext::Discovery {
                    discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                    path: path.clone(), error: String::new(),
                }));
            run.admit_missing_inputs(&mut task, &absent, true);
            assert_eq!(task.inputs[0].failure.as_ref().unwrap().kind, FailureKind::Unsupported);
            let input = task.inputs[0].input.clone();
            task.inputs.push(LogicalInput { password_probe: None, input, password: None, failure: None });
            run.admit_missing_inputs(&mut task, &absent, true);
            assert!(task.inputs.iter().all(|logical| matches!(logical.failure.as_ref().unwrap().context.as_deref(),
                Some(super::super::FailureContext::InputAdmission { .. }))));
            task.inputs.pop();
            task.inputs[0].failure = None;
            if count == 2 {
                let input = task.inputs[0].input.clone();
                task.inputs.push(LogicalInput { password_probe: None, input, password: Some(Arc::from("known")), failure: None });
                task.inputs[0].failure = Some(Failure::new(FailureKind::Unsupported, "discovery")
                    .with_context(super::super::FailureContext::Discovery {
                        discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                        path: path.clone(), error: String::new(),
                    }));
            }
            let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
                run.execute_task(run.register_task(task), 1, 1, None, spawner)
            }).unwrap();
            assert_eq!(outcome.archives.len(), if mode == Mode::Scan { count } else { 1 });
            let events = events.lock().unwrap();
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Started { .. })).count(), 1);
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Finished { .. })).count(), if count > 1 { count + 1 } else { 1 });
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Queued { .. })).count(), if count > 1 { count } else { 0 });
            assert!(events.iter().any(|event| matches!(event, Event::Finished { result, .. }
                if result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::MissingVolume))));
            if count == 2 {
                // main keeps a discovery-blocked segment visible and marks
                // the otherwise unexecuted sibling skipped after admission.
                assert!(events.iter().any(|event| matches!(event, Event::Finished { id, result, .. }
                    if *id != 1 && result.status == super::super::TaskStatus::Skipped)));
                assert!(events.iter().any(|event| matches!(event, Event::Finished { id, result, .. }
                    if *id != 1 && result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::Unsupported))));
            }
            if mode == Mode::Scan && count == 2 {
                assert_eq!(outcome.archives[0].failure.as_ref().unwrap().kind, FailureKind::Unsupported);
                assert_eq!(outcome.archives[1].password.as_deref(), Some("known"));
            }
            let failure = outcome.archives.last().unwrap().failure.as_ref().unwrap();
            assert_eq!(failure.kind, FailureKind::MissingVolume);
            assert!(matches!(failure.context.as_deref(), Some(super::super::FailureContext::InputAdmission { missing_paths }) if missing_paths == &[missing.clone()]));
            assert_eq!(failure.discovery_scope.is_some(), mode == Mode::Extract);
            assert!(path.exists());
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn carrier_completion_keeps_postprocess_but_suppresses_segment_aggregate_detail() {
        let input = ArchiveInput::file("carrier.bin".into(), "zip".into(), "archive".into());
        let mut results = vec![receipt(&input, DiscoverySource::Embedded, 1), receipt(&input, DiscoverySource::Embedded, 1)];
        results[0].failure = Some(Failure::new(FailureKind::Damaged, "segment damaged"));
        results[1].failure = Some(Failure::new(FailureKind::Unsupported, "segment unsupported"));
        let completion = super::super::TaskCompletion::from_group(&results);
        assert_eq!(completion.status, super::super::TaskStatus::Failed);
        assert!(completion.failure.is_none());
        results[1].failure.as_mut().unwrap().evidence = Some(Box::new(super::super::FailureEvidence {
            possible_missing_volume: true, ..Default::default()
        }));
        let completion = super::super::TaskCompletion::from_group(&results);
        assert!(completion.failure.as_ref().unwrap().evidence.as_ref().unwrap().possible_missing_volume);
        results[0].failure = Some(Failure::new(FailureKind::FilesystemError, "promotion denied")
            .with_context(super::super::FailureContext::Postprocess { destination: "out".into() }));
        let completion = super::super::TaskCompletion::from_group(&results);
        assert_eq!(completion.failure.as_ref().unwrap().kind, FailureKind::FilesystemError);
        assert_eq!(completion.failure.as_ref().unwrap().message, "promotion denied");
    }

    #[test]
    fn discovery_blocked_tasks_register_display_segments_without_executing_them() {
        let path = crate::test_support::temp_file("discovery_preflight", b"carrier");
        for (mode, count) in [Mode::Scan, Mode::Extract].into_iter()
            .flat_map(|mode| [1, 2].map(|count| (mode, count))) {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            assert_eq!(engine.next_id(), 1); // Reserve the parent observer ID.
            let request = Request::new(vec![path.clone()], mode);
            let events = Mutex::new(Vec::new());
            let observer = |event: Event| { events.lock().unwrap().push(event); };
            let run = test_run(&engine, &request, &observer);
            let inputs = (0..count).map(|index| LogicalInput { password_probe: None,
                input: ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "carrier".into()),
                password: Some(Arc::from("known")),
                failure: Some(Failure::new(if index == 0 { FailureKind::Unsupported } else { FailureKind::Damaged },
                    "discovery detail").with_context(super::super::FailureContext::Discovery {
                        discovery: DiscoverySource::Embedded, reason: "unsupported".into(),
                        path: path.clone(), error: "discovery detail".into(),
                    })),
            }).collect();
            let task = Task {
                primary: None, inputs, owned_paths: vec![path.to_string_lossy().into_owned()],
                source: DiscoverySource::Embedded, retry: None,
                scope: Some(Arc::new(crate::scan::scope::NativeDiscoveryScope::new(
                    path.parent().unwrap().to_string_lossy().into_owned(), Some(0), Vec::new()))),
            };
            let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner|
                run.execute_task(run.register_task(task), 1, 1, None, spawner)).unwrap();
            assert_eq!(outcome.archives.len(), count);
            for (index, result) in outcome.archives.iter().enumerate() {
                assert_eq!(result.failure.as_ref().unwrap().kind,
                    if index == 0 { FailureKind::Unsupported } else { FailureKind::Damaged });
                assert_eq!(result.failure.as_ref().unwrap().discovery_scope.is_some(), mode == Mode::Extract);
                assert_eq!(result.password.as_deref(), Some("known"));
                assert!(result.output.is_none());
            }
            let events = events.lock().unwrap();
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Started { .. })).count(), 1);
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Finished { .. })).count(), if count > 1 { count + 1 } else { 1 });
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Queued { .. })).count(), if count > 1 { count } else { 0 });
            assert!(events.iter().any(|event| matches!(event, Event::Finished { result, .. }
                if result.status == super::super::TaskStatus::Failed)));
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn replacement_display_reuses_parent_or_registers_retained_failure_without_execution() {
        let source = crate::test_support::temp_file("replacement_display", &[0; 16]);
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
        let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
        let mut result = receipt(&input, DiscoverySource::Detection, 1);
        result.failure = Some(Failure::new(FailureKind::MissingVolume, "first attempt"));
        let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
        checkpoint.install_report(InputCheckpoint::report_state(&input, &result, None, None, 1, 1));
        let engine = Engine::new(PathBuf::from("unused-worker"));
        assert_eq!(engine.next_id(), 1);
        let request = Request::new(vec![source.clone()], Mode::Extract);
        let events = Mutex::new(Vec::new());
        let observer = |event: Event| { events.lock().unwrap().push(event); };
        let run = test_run(&engine, &request, &observer);
        assert_eq!(run.replan_input(1, 1, &input, Some(&checkpoint)), (1, None));
        assert!(matches!(events.lock().unwrap().as_slice(), [Event::Replanned { id: 1, .. }]));
        events.lock().unwrap().clear();
        let mut replacement = input.clone();
        replacement.entry_path = source.with_extension("first").to_string_lossy().into_owned();
        let (active, retained) = run.replan_input(1, 1, &replacement, Some(&checkpoint));
        let retained = retained.unwrap();
        assert_ne!(active, 1);
        assert_ne!(active, retained);
        let events = events.lock().unwrap();
        assert!(matches!(&events[0], Event::Replanned { id: 1, .. }));
        assert!(matches!(&events[1], Event::Queued { id, parent: Some(1), .. } if *id == active));
        assert!(matches!(&events[2], Event::Queued { id, parent: Some(1), .. } if *id == retained));
        assert!(matches!(&events[3], Event::Finished { id, result, .. } if *id == retained
            && result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::MissingVolume)));
        assert!(matches!(&events[4], Event::Started { id, .. } if *id == active));
        assert_eq!(events.len(), 5);
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn retry_panel_uses_checkpoint_positions_without_creating_execution_work() {
        let source = crate::test_support::temp_file("panel_retry_positions", &[0; 16]);
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
        let inputs: Vec<_> = archive_input_slices(&input, &[
            ("zip", 0, Some(8)), ("zip", 8, Some(16)),
        ]).unwrap().0.into_iter().map(Option::unwrap).collect();
        let generations = HashMap::from([
            (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
        ]);
        let mut result = receipt(&inputs[0], DiscoverySource::Embedded, 1);
        let output = source.with_extension("out");
        result.output = Some(output.clone());
        let mut checkpoint = InputCheckpoint::create(&source, Arc::new(inputs[0].clone()), &result, &generations, None).unwrap();
        checkpoint.install_report(InputCheckpoint::report_state(&inputs[0], &result,
            Some(&output), None, 4, 7));
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(vec![source.clone()], Mode::Extract);
        let events = Mutex::new(Vec::new());
        let observer = |event: Event| { events.lock().unwrap().push(event); };
        let run = test_run(&engine, &request, &observer);
        let task = Task {
            primary: None, owned_paths: vec![input.entry_path.clone()],
            inputs: inputs.into_iter().map(|input| LogicalInput { password_probe: None, input, password: None, failure: None }).collect(),
            source: DiscoverySource::Embedded, retry: None, scope: None,
        };
        let ids = run.queue_inputs(&task, 1000, 1, &[Some(&checkpoint), None], 7, true);
        assert_eq!(ids.len(), 2);
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        for (event, position) in events.iter().zip([2, 4]) {
            assert!(matches!(event, Event::Queued { parent: Some(1000), segment: Some(segment), .. }
                if segment.index == position && segment.count == 7));
        }
        assert!(matches!(&events[0], Event::Queued { id, .. } if *id == ids[1]));
        assert!(matches!(&events[1], Event::Queued { id, .. } if *id == ids[0]));
        // Both retained and retry candidates have display rows; queue_inputs
        // emits no Started/Finished and never creates worker/scheduler tasks.
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn departed_discovered_tasks_skip_before_started_across_modes_and_depths() {
        // Exercise the real task boundary, not just its predicate: no worker,
        // Started event, or failed receipt may be produced for a stale proposal.
        let path = crate::test_support::temp_file("departed_proposal", b"archive");
        let input = ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        fs::remove_file(&path).unwrap();
        for mode in [Mode::Scan, Mode::Extract] {
            for origin in [Origin::Foreground, Origin::Watch] {
                for depth in [1, 2] {
                    let engine = Engine::new(PathBuf::from("unused-worker"));
                    let mut request = Request::new(vec![path.clone()], mode);
                    request.origin = origin;
                    let events = Mutex::new(Vec::new());
                    let observer = |event: Event| { events.lock().unwrap().push(event); };
                    let run = test_run(&engine, &request, &observer);
                    let task = Task {
                        primary: None,
                        owned_paths: vec![input.entry_path.clone()],
                        inputs: vec![LogicalInput { password_probe: None, input: input.clone(), password: None, failure: None }],
                        source: DiscoverySource::Detection,
                        retry: None,
                        scope: None,
                    };
                    let outcome = Scheduler::new().run(1, origin, &request.cancel, |spawner| {
                        run.execute_task(run.register_task(task), 1, depth, None, spawner)
                    }).unwrap();
                    assert!(outcome.archives.is_empty());
                    assert!(outcome.errors.is_empty());
                    assert!(matches!(events.lock().unwrap().as_slice(), [Event::Skipped { id: 1 }]));
                    // Direct user selections are not stale discovery proposals.
                    let direct = Task {
                        primary: None,
                        owned_paths: vec![input.entry_path.clone()],
                        inputs: vec![LogicalInput { password_probe: None, input: input.clone(), password: None, failure: None }],
                        source: DiscoverySource::Direct,
                        retry: None,
                        scope: None,
                    };
                    assert!(matches!(run.task_admission(&direct, &HashMap::new(), &[path.clone()], false, false, |_| None).unwrap(), TaskAdmission::Execute(None)));
                    // A replacement can be classified Relations while retaining
                    // the original Direct task's no-silent-skip boundary.
                    let mut replacement = direct;
                    replacement.source = DiscoverySource::Relations;
                    assert!(matches!(run.task_admission(&replacement, &HashMap::new(), &[path.clone()], false, false, |_| None).unwrap(), TaskAdmission::Execute(None)));
                    assert!(matches!(run.task_admission(&replacement, &HashMap::new(), &[path.clone()], true, false, |_| None).unwrap(), TaskAdmission::Departed));
                }
            }
        }
    }

    fn output_manifest(files: &[(&str, &[u8])]) -> crate::scan::directory::NativeWorkerManifest {
        use crate::scan::directory::{NativeWorkerManifest, OutputFileRecord};

        let records = files.iter().map(|(path, data)| OutputFileRecord {
            path: (*path).to_owned(),
            size: data.len() as u64,
            status: 1,
            mtime_ns: Some(1),
            magic: Box::from(&data[..data.len().min(512)]),
        }).collect();
        NativeWorkerManifest::from_parts(records, [
            1, files.len() as u64, 0,
            files.iter().map(|(_, data)| data.len() as u64).sum(), 1,
        ]).unwrap()
    }

    #[test]
    #[cfg(windows)]
    fn retained_carrier_outputs_do_not_reenter_recursive_discovery() {
        struct RetainedObserver {
            started: Mutex<Vec<TaskId>>,
            finished: Mutex<Vec<TaskId>>,
        }
        impl Observer for RetainedObserver {
            fn notify(&self, event: Event) {
                match event {
                    Event::Started { id, .. } => self.started.lock().unwrap().push(id),
                    Event::Finished { id, .. } => self.finished.lock().unwrap().push(id),
                    _ => {}
                }
            }
            fn allow_recursive(&self, _: usize, _: usize) -> bool {
                panic!("retained outputs must not request another recursive scan");
            }
        }
        for (count, split_sources) in [(1, false), (2, false), (2, true)] {
            let source = crate::test_support::temp_file("carrier_parent_barrier", &[0; 16]);
            let container = source.with_extension("output");
            fs::create_dir(&container).unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), container.file_name().unwrap().to_string_lossy().into_owned());
            let (segments, _) = archive_input_slices(&input, &[
                ("zip", 0, Some(8)), ("zip", 8, Some(16)),
            ]).unwrap();
            let mut inputs: Vec<_> = segments.into_iter().take(count).map(Option::unwrap).collect();
            let continuation = source.with_extension("part2");
            if split_sources {
                fs::write(&continuation, [0; 16]).unwrap();
                let part = ArchiveInput::file(continuation.to_string_lossy().into_owned(), "zip".into(), "second".into());
                inputs[1] = archive_input_slices(&part, &[("zip", 8, Some(16))]).unwrap().0.remove(0).unwrap();
            }
            let mut generations = HashMap::from([
                (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
            ]);
            if split_sources {
                generations.insert(path_key(&continuation.to_string_lossy()), capture_file_generation(&continuation).unwrap());
            }
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(vec![source.clone()], Mode::Extract);
            request.max_depth = 1;
            Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
            Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
            for (index, input) in inputs.iter().enumerate() {
                let output = container.join(format!("segment-{index}"));
                fs::create_dir(&output).unwrap();
                fs::write(output.join("payload"), b"keep").unwrap();
                let mut result = receipt(input, DiscoverySource::Embedded, 1);
                result.output = Some(output);
                result.files = 1;
                result.bytes = 4;
                request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap());
            }
            let observer = RetainedObserver {
                started: Mutex::new(Vec::new()),
                finished: Mutex::new(Vec::new()),
            };
            let mut run = test_run(&engine, &request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
            }
            let task = Task {
                primary: None,
                owned_paths: inputs.iter().map(|input| input.entry_path.clone()).collect(),
                inputs: inputs.into_iter().map(|input| LogicalInput { password_probe: None, input, password: None, failure: None }).collect(),
                source: DiscoverySource::Embedded,
                retry: None,
                scope: None,
            };
            let scheduler = Scheduler::new();
            let outcome = run.recursion.serve(&request.cancel,
                |depth, pending| observer.allow_recursive(depth, pending),
                || scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| {
                    run.execute_task(run.register_task(task), 1000, 1, None, spawner)
                }),
            ).unwrap();
            assert_eq!(observer.started.lock().unwrap().len(), if count == 1 { 1 } else { count + 1 });
            assert_eq!(observer.finished.lock().unwrap().last(), Some(&1000));
            assert_eq!(outcome.archives.len(), count);
            assert_eq!(outcome.archives.iter().map(|result| result.offset).collect::<Vec<_>>(),
                (0..count).map(|index| (index * 8) as u64).collect::<Vec<_>>());
            assert!(outcome.archives.iter().all(|result| result.retained));
            assert!(source.is_file());
            for index in 0..count {
                assert_eq!(fs::read(container.join(format!("segment-{index}/payload"))).unwrap(), b"keep");
            }
            release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
            fs::remove_dir_all(container).unwrap();
            fs::remove_file(source).unwrap();
            if split_sources { fs::remove_file(continuation).unwrap(); }
        }
    }

    #[test]
    #[cfg(windows)]
    fn changed_carrier_inputs_keep_their_slots_not_their_old_results() {
        use std::os::windows::fs::OpenOptionsExt;
        // Exercise selection, ownership and both physical cleanup outcomes.
        // The worker-level changed-volume case is covered by the Watch blackbox.
        for previously_failed in [false, true] {
            for cleanup_locked in [false, true] {
                let source = crate::test_support::temp_file("changed_carrier_slot", &[0; 16]);
                let container = source.with_extension("output");
                let sibling = container.join("sibling");
                let slot = container.join("segment(2)");
                fs::create_dir_all(&sibling).unwrap();
                fs::create_dir(&slot).unwrap();
                fs::write(sibling.join("keep"), b"unchanged").unwrap();
                fs::write(slot.join("old"), b"previous attempt").unwrap();
                let sibling_before = capture_file_generation(&sibling.join("keep")).unwrap().persisted();
                let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
                    container.file_name().unwrap().to_string_lossy().into_owned());
                let inputs: Vec<_> = archive_input_slices(&input, &[
                    ("zip", 0, Some(4)), ("zip", 4, Some(8)),
                ]).unwrap().0.into_iter().map(Option::unwrap).collect();
                let changed = archive_input_slices(&input, &[("zip", 4, Some(12))])
                    .unwrap().0.remove(0).unwrap();
                let generations = HashMap::from([
                    (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
                ]);
                let mut request = Request::new(vec![source.clone()], Mode::Extract);
                for (index, logical) in inputs.iter().enumerate() {
                    let mut result = receipt(logical, DiscoverySource::Embedded, 1);
                    result.output = Some(if index == 0 { sibling.clone() } else { slot.clone() });
                    result.files = 1;
                    if index == 1 && previously_failed {
                        result.failure = Some(Failure::new(FailureKind::MissingVolume, "old failure"));
                        result.recovered_complete_files = 1;
                        result.partial = true;
                    }
                    request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((logical).clone()), &result, &generations, Some(&container)).unwrap());
                }
                let engine = Engine::new(PathBuf::from("unused-worker"));
                let observer = |_: Event| {};
                let mut run = test_run(&engine, &request, &observer);
                for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                    Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
                }
                let kept = run.checkpoint_for(&inputs[0], Some(&run.request.checkpoints[0]), &generations, &container, 1, &run.candidates).unwrap();
                assert_eq!(kept.retained_container(), Some(container.as_path()));
                assert!(run.checkpoint_for(&changed, Some(&run.request.checkpoints[1]), &generations, &container, 1, &run.candidates).is_none());
                let previous = run.retry_slot_for(&changed, Some(&run.request.checkpoints[1]), &container).unwrap();
                assert_eq!(previous.output(), slot);
                assert!(run.retry_slot_for(&changed, Some(&run.request.checkpoints[1]), &source.with_extension("unrelated")).is_none());
                assert!(!previous.output_slot_for(&changed, &slot), "carrier root is never a child retry slot");
                let held = cleanup_locked.then(|| fs::OpenOptions::new().read(true).share_mode(3)
                    .open(slot.join("old")).unwrap());
                let mut outcome = Outcome::default();
                let cleared = run.discard_failed_output(&previous.result(1), &slot, &mut outcome).unwrap();
                assert_eq!(cleared, !cleanup_locked);
                // Current extraction uses current facts, not the old partial
                // marker or old success, even when best-effort cleanup failed.
                let current = receipt(&changed, DiscoverySource::Embedded, 1);
                if cleared {
                    assert_eq!(run.recreate_reserved_output(&slot, &current).unwrap().unwrap(), slot);
                } else {
                    observer.reuse_output(&current, &slot).unwrap();
                }
                fs::write(slot.join("new"), b"current attempt").unwrap();
                assert_eq!(slot.join("old").exists(), cleanup_locked);
                assert_eq!(fs::read_dir(&container).unwrap().count(), 2);
                assert_eq!(capture_file_generation(&sibling.join("keep")).unwrap().persisted(), sibling_before);
                assert_eq!(fs::read(sibling.join("keep")).unwrap(), b"unchanged");
                drop(held);
                drop(run);
                release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
                fs::remove_dir_all(container).unwrap();
                fs::remove_file(source).unwrap();
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn source_cleanup_runs_after_consumer_finish_and_is_joined_by_request() {
        use std::os::windows::fs::OpenOptionsExt;
        for locked in [false, true] {
        let source = crate::test_support::temp_file("background_source_cleanup", b"archive");
        let held = locked.then(|| fs::OpenOptions::new().read(true).share_mode(1).open(&source).unwrap());
        let output = source.with_extension("output");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("payload"), b"keep").unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), output.file_name().unwrap().to_string_lossy().into_owned());
        let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
        let mut request = Request::new(vec![source.clone()], Mode::Extract);
        request.max_depth = 0;
        let config = Arc::make_mut(&mut request.config);
        config.post_extract.archive_cleanup_mode = CleanupMode::Delete;
        config.post_extract.flatten_single_directory = false;
        let mut result = receipt(&input, DiscoverySource::Embedded, 1);
        result.output = Some(output.clone());
        result.files = 1;
        request.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap());
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let finished = std::sync::atomic::AtomicBool::new(false);
        let observer = |event| {
            if matches!(event, Event::Finished { .. }) {
                assert!(source.exists(), "consumer waited for source cleanup before reporting completion");
                finished.store(true, Ordering::Release);
            }
        };
        let mut run = test_run(&engine, &request, &observer);
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
        }
        let task = Task {
            primary: None, inputs: vec![LogicalInput { password_probe: None, input, password: None, failure: None }],
            owned_paths: vec![source.to_string_lossy().into_owned()], source: DiscoverySource::Embedded, retry: None,
            scope: None,
        };
        let scheduler = Scheduler::new();
        scheduler.configure_capacity(1);
        let source_key = resolved_key(&source);
        let leases = Arc::clone(&engine.leases);
        let outcome = scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| Box::pin(async move {
            let outcome = run.execute_task(run.register_task(task), 1, 1, None, spawner.clone()).await;
            let (checked, check) = mpsc::channel();
            spawner.spawn(Box::pin(async move {
                let cancel = Cancellation::new();
                let mut next = Box::pin(leases.acquire_shared(HashSet::from([source_key]), 2, &cancel));
                let blocked = poll_fn(|cx| {
                    use std::future::Future;
                    Poll::Ready(next.as_mut().poll(cx).is_pending())
                }).await;
                checked.send(blocked).unwrap();
            }));
            // The cleanup child started before this probe, but this poll owns
            // the only blocking stage until the probe observes the lease.
            assert!(check.recv().unwrap(), "another request acquired the source before cleanup");
            run.finish(outcome).await
        })).unwrap();
        assert!(finished.load(Ordering::Acquire));
        assert_eq!(source.exists(), locked, "request returned before background cleanup settled");
        assert_eq!(outcome.cleanup_results.len(), usize::from(locked));
        assert_eq!(outcome.errors.iter().filter(|error| error.kind == InputErrorKind::Cleanup).count(), usize::from(locked));
        assert_eq!(fs::read(output.join("payload")).unwrap(), b"keep");
        drop(held);
        if locked { fs::remove_file(source).unwrap(); }
        fs::remove_dir_all(output).unwrap();
        }
    }

    #[test]
    fn control_driver_start_failure_drops_future_and_allows_retry() {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let scheduler = engine.scheduler.get_or_init(Scheduler::new);
        scheduler.fail_driver.store(true, Ordering::Relaxed);
        let held = Arc::new(());
        let pending = Arc::clone(&held);
        let failed = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async move {
            drop(pending);
        });
        assert!(failed.is_err());
        assert_eq!(Arc::strong_count(&held), 1);
        let next = engine.spawn_control(Origin::Foreground, &Cancellation::new(), async { 42 }).unwrap();
        assert_eq!(next.join().unwrap(), 42);
    }

    #[test]
    fn owned_request_reports_executor_startup_failure_once_and_retries() {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let scheduler = engine.scheduler.get_or_init(Scheduler::new);
        scheduler.fail_pool.store(2, Ordering::Relaxed);
        let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&called);
        let request = Request::new(Vec::new(), Mode::Extract);
        let completion = engine.submit(request, Arc::new(|_: Event| {}), move |result| {
            observed.fetch_add(1, Ordering::Relaxed);
            result
        });
        assert!(completion.join().unwrap().is_err());
        assert_eq!(called.load(Ordering::Relaxed), 1);
        assert_eq!(scheduler.fail_pool.load(Ordering::Relaxed), 0);
        // A service call after the fault must use the newly available executor.
        scheduler.fail_pool.store(0, Ordering::Relaxed);
        assert_eq!(engine.run_stage("report", Origin::Foreground, || 42).unwrap(), 42);
    }

    #[test]
    fn synchronous_service_work_reuses_shared_stage_and_nested_admission() {
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let scheduler = engine.scheduler.get_or_init(Scheduler::new);
        scheduler.configure_capacity(1);
        let value = engine.run_stage("watch_admission", Origin::Watch, || {
            assert!(crate::pipeline::scheduling::in_stage());
            engine.run_stage("watch_usn_checkpoint", Origin::Watch, || {
                assert!(crate::pipeline::scheduling::in_stage());
                42
            })
        });
        assert_eq!(value.unwrap().unwrap(), 42);
        assert!(!crate::pipeline::scheduling::in_stage());
    }

    #[test]
    #[cfg(windows)]
    fn denied_nested_promotion_keeps_archive_cause_and_retry_path() {
        use std::os::windows::fs::OpenOptionsExt;
        let marker = crate::test_support::temp_file("promotion_denied", b"marker");
        let root = marker.with_extension("output");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        for kind in [FailureKind::PasswordRequired, FailureKind::MissingVolume] {
            let source = nested.join("blocked.zip");
            fs::write(&source, b"archive").unwrap();
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(vec![root.clone()], Mode::Extract);
            let change_metadata = std::sync::atomic::AtomicBool::new(false);
            let observer = |event: Event| {
                if matches!(event, Event::Started { .. })
                    && change_metadata.load(std::sync::atomic::Ordering::Relaxed)
                {
                    // Admission already captured the generation. A timestamp
                    // change must not add a promotion veto absent from main.
                    fs::OpenOptions::new().write(true).open(&source).unwrap()
                        .set_times(fs::FileTimes::new().set_modified(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456))).unwrap();
                }
            };
            let run = test_run(&engine, &request, &observer);
            let execute = || {
                let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "blocked".into());
                let task = Task {
                    primary: None,
                    inputs: vec![LogicalInput { password_probe: None, input, password: None,
                        failure: Some(Failure::new(kind, "archive blocked")) }],
                    owned_paths: vec![source.to_string_lossy().into_owned()],
                    source: DiscoverySource::Embedded, retry: None,
                    scope: None,
                };
                Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                    run.execute_task(run.register_task(task), 1, 2, None, spawner)
                }).unwrap()
            };
            // Permit generation reads but deny rename/removal without production hooks.
            let lock = fs::OpenOptions::new().read(true).share_mode(1).open(&source).unwrap();
            let outcome = PublicOutcome::from(execute());
            let failed = outcome.archives.iter().find(|result| result.failure.is_some()).unwrap();
            let failure = failed.failure.as_ref().unwrap();
            assert_eq!(failure.kind, FailureKind::FilesystemError);
            assert_eq!(failure.causes[0].kind, kind);
            assert!(failed.path.is_file());
            assert!(!failed.promoted);
            let failures = outcome.input_failures();
            let input = failures.values().next().unwrap();
            assert!(input.retryable());
            assert!(input.terminal.is_none());
            assert_eq!(failure.is_password_retry(), kind == FailureKind::PasswordRequired);
            let restored: Failure = serde_json::from_value(serde_json::to_value(failure).unwrap()).unwrap();
            assert!(restored.contains(kind));
            drop(lock);
            // The same source can be retried once the external obstruction is removed.
            change_metadata.store(true, std::sync::atomic::Ordering::Relaxed);
            let retry = execute();
            assert!(retry.archives.iter().any(|result| result.promoted));
            fs::remove_file(root.join("blocked.zip")).unwrap();
            fs::create_dir_all(&nested).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn bulk_promotion_mapping_is_exact_and_not_cascading() {
        let moves: Vec<_> = (0..2048).map(|index| (
            PathBuf::from(format!("missing-promotion-source/part-{index}")),
            PathBuf::from(format!("missing-promotion-target/part-{index}")),
        )).collect();
        let paths = PromotionPaths::new(&moves);
        assert_eq!(paths.0.len(), moves.len());
        for (source, target) in &moves {
            let mut path = source.clone();
            assert!(paths.remap(&mut path));
            assert_eq!(&path, target);
            let mut child = source.join("not-a-moved-file");
            assert!(!paths.remap(&mut child));
        }
        let a = PathBuf::from("missing-promotion-a");
        let b = PathBuf::from("missing-promotion-b");
        let c = PathBuf::from("missing-promotion-c");
        let paths = PromotionPaths::new(&[(a.clone(), b.clone()), (b.clone(), c)]);
        let mut path = a;
        paths.remap(&mut path);
        assert_eq!(path, b);
    }

    #[test]
    #[cfg(windows)]
    fn nested_carrier_promotion_preserves_accepted_siblings_for_retry() {
        // Exercise the real task boundary and physical move, not just its
        // predicate: accepted siblings must keep their output and receipts
        // when another segment blocks the carrier, then survive a root retry.
        fn execute(
            engine: &Engine, request: &Request, inputs: &[ArchiveInput],
            blocked: FailureKind, depth: usize,
        ) -> Outcome {
            let observer = |_: Event| {};
            let mut run = test_run(engine, request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
            }
            Arc::get_mut(&mut run).unwrap().promoted_sources = request.promoted_sources.iter().enumerate().map(|(index, source)| {
                (path_key(&source.path().to_string_lossy()), index)
            }).collect();
            let task = Task {
                primary: None,
                inputs: inputs.iter().enumerate().map(|(index, input)| LogicalInput { password_probe: None,
                    input: input.clone(),
                    password: None,
                    failure: (index == 2).then(|| Failure::new(blocked, "blocked segment")),
                }).collect(),
                owned_paths: vec![inputs[0].entry_path.clone()],
                source: DiscoverySource::Embedded,
                retry: None,
                scope: None,
            };
            Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                run.execute_task(run.register_task(task), 1, depth, None, spawner)
            }).unwrap()
        }

        let marker = crate::test_support::temp_file("carrier_partial_promotion", b"marker");
        let root = marker.with_extension("output");
        for origin in [Origin::Foreground, Origin::Watch] {
          for (depth, partial_kind, blocked, accepted, promoted) in [
            (2, FailureKind::Damaged, FailureKind::PasswordRequired, false, true),
            (2, FailureKind::Damaged, FailureKind::MissingVolume, false, true),
            // Main inspects all aggregate causes, including accepted partials.
            (2, FailureKind::MissingVolume, FailureKind::Damaged, false, true),
            // All accepted partials must use main's recoverable categories.
            (2, FailureKind::MissingVolume, FailureKind::Damaged, true, false),
            (2, FailureKind::Damaged, FailureKind::Damaged, false, false),
            (1, FailureKind::Damaged, FailureKind::PasswordRequired, false, false),
          ] {
            let parent = root.join("outer");
            let source = parent.join("carrier.bin");
            let container = parent.join("carrier");
            fs::create_dir_all(&container).unwrap();
            fs::write(&source, [0; 16]).unwrap();
            let input = ArchiveInput::file(
                source.to_string_lossy().into_owned(), "zip".into(), "carrier".into(),
            );
            let (segments, _) = archive_input_slices(&input, &[
                ("zip", 0, Some(4)), ("zip", 4, Some(8)), ("zip", 8, Some(12)),
            ]).unwrap();
            let mut inputs: Vec<_> = segments.into_iter().map(Option::unwrap).collect();
            let generations = HashMap::from([
                (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
            ]);
            let mut request = Request::new(vec![root.clone()], Mode::Extract);
            request.origin = origin;
            request.max_depth = 0;
            Arc::make_mut(&mut request.config).extraction.content_requirement =
                ContentRequirement::AllowPartial;
            for (index, input) in inputs.iter().enumerate().take(if accepted { 3 } else { 2 }) {
                let output = container.join(format!("segment-{index}"));
                fs::create_dir(&output).unwrap();
                fs::write(output.join("payload"), b"keep").unwrap();
                let mut result = receipt(input, DiscoverySource::Embedded, depth);
                result.output = Some(output);
                result.files = 1;
                result.bytes = 4;
                if index != 0 {
                    result.partial = true;
                    result.recovered_complete_files = 1;
                    result.failure = Some(Failure::new(
                        if index == 1 { partial_kind } else { blocked }, "accepted partial",
                    ));
                }
                let mut checkpoint = InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap();
                checkpoint.install_report(InputCheckpoint::report_state(
                    input, &result, result.output.as_deref(), None, index + 1, 3));
                checkpoint.set_password_signature(|| CandidateSet::new(
                    Arc::from([]), None, &AttemptCache::default(), None,
                ).signature(&input.entry_path));
                request.checkpoints.push(checkpoint);
            }
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let outcome = execute(&engine, &request, &inputs, blocked, depth);
            assert_eq!(outcome.archives.len(), 3);
            assert!(outcome.errors.is_empty());
            assert_eq!(outcome.failed(), usize::from(!accepted));
            assert_eq!(outcome.subtree_complete(), promoted);
            let current = if promoted { root.join("carrier.bin") } else { source.clone() };
            assert!(current.is_file());
            assert_eq!(source.is_file(), !promoted);
            assert_eq!(outcome.promoted_sources.len(), usize::from(promoted));
            for result in &outcome.archives {
                assert_eq!(result.path, current);
                assert_eq!(result.source_paths, [current.clone()]);
                assert_eq!(result.promoted, promoted);
                assert_eq!(result.promotion_original_path.as_ref(), promoted.then_some(&source));
            }
            let recovery = outcome.archives.iter().filter_map(|result| result.failure.as_ref())
                .find_map(|failure| failure.recovery.as_deref()).expect("executed failure retains recovery report");
            let report = recovery.report(|failure| json!({"kind": format!("{:?}", failure.kind)}));
            assert_eq!(report["input_count"], 3);
            assert_eq!(report["inputs"].as_array().unwrap().len(), 3);
            for (index, row) in report["inputs"].as_array().unwrap().iter().enumerate() {
                assert_eq!(row["position"], index + 1);
                assert_eq!(row["archive_input"]["entry_path"], json!(current));
            }
            let rediscovered = ArchiveInput::file(
                current.to_string_lossy().into_owned(), "zip".into(),
                crate::scan::directory::filesystem_logical_name(&current.to_string_lossy()),
            );
            inputs = archive_input_slices(&rediscovered, &[
                ("zip", 0, Some(4)), ("zip", 4, Some(8)), ("zip", 8, Some(12)),
            ]).unwrap().0.into_iter().map(Option::unwrap).collect();
            let generations = HashMap::from([
                (path_key(&inputs[0].entry_path), capture_file_generation(&current).unwrap()),
            ]);
            assert_eq!(outcome.checkpoints.iter().filter(|checkpoint| checkpoint.has_output()).count(),
                request.checkpoints.len());
            for (index, checkpoint) in outcome.checkpoints.iter().filter(|checkpoint| checkpoint.has_output()).enumerate() {
                assert_eq!(checkpoint.entry(), current);
                assert_eq!(checkpoint.carrier(), current);
                assert_eq!(checkpoint.container(), Some(container.as_path()));
                assert!(checkpoint.valid_for(&inputs[index], &generations));
                assert_eq!(fs::read(checkpoint.output().join("payload")).unwrap(), b"keep");
            }
            if promoted {
                request.checkpoints = outcome.checkpoints.into_vec();
                request.promoted_sources = outcome.promoted_sources.into_vec();
                let retry = execute(&engine, &request, &inputs, blocked, 1);
                assert_eq!(retry.checkpoints.iter().filter(|checkpoint| checkpoint.has_output()).count(), 2);
                assert!(retry.archives.iter().take(2).all(|result| result.retained));
                assert_eq!(retry.archives[1].failure.as_ref().unwrap().kind, partial_kind);
                assert!(retry.archives[1].partial);
                assert_eq!(retry.archives[1].recovered_complete_files, 1);
                assert_eq!(retry.archives[2].failure.as_ref().unwrap().kind, blocked);
                assert_eq!(retry.archives[0].output.as_ref(), Some(&container.join("segment-0")));
                assert_eq!(retry.archives[1].output.as_ref(), Some(&container.join("segment-1")));
                assert!(current.is_file());
            }
            release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
            fs::remove_dir_all(&root).unwrap();
          }
        }
        fs::remove_file(marker).unwrap();
    }

    fn encrypted_rar_fixture() -> Vec<u8> {
        let hex = "526172211a07010074de7b1c21040000010f7b64253244702e2a32eb93579555a37d38b616cb97898c463d3682920551724ed0c1c974029cc2b8ef8491fc816311daa1b0410f6115608170466e4948a8c6d4f17e28b08c727b4acfc116d3d075ce011963dc0c72e50a803d9036619810e92352e809830c9463ab4a0abdaab61e008218673e9c51409f76b2064bf7982e56d8173f1e387329bd5aca3bac49063545fcbfc19547d2be214b4fe1dae172b250e168f2a258548930b1763fb500c7869d70f2539d86fd19214dcc3bca1363154b0a0f2b0bba7dcc224ec1893cbc31cfa95158ccf5e96d74921de6f268ea4429e2ddf63d49220005742fef059f868372345f071322a7e690d56d5ac17b563fa9e923076fa2c58aa8e88e9843df17b7e79a30ca936d8215c92f6832f86887c3c3160ecfddfcdf7712382f84f39eb8";
        (0..hex.len()).step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect()
    }

    #[test]
    fn recursive_many_outputs_preserve_parent_index_and_prompt_boundary() {
        let source = crate::test_support::temp_file("recursive_many", b"source");
        let root = source.with_extension("outputs");
        fs::create_dir(&root).unwrap();
        let rar = encrypted_rar_fixture();
        for answer in [false, true] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(Vec::new(), Mode::Extract);
            request.max_depth = usize::MAX;
            let config = Arc::make_mut(&mut request.config);
            config.recursive_extract = Recursion::Prompt;
            config.recursive_authorization.enabled = false;
            config.filesystem.scan_filters_enabled = false;
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
                Arc::from([Arc::from("secret")]), None, &engine.password_attempts, None);
            let mut inventories = Vec::new();
            let mut manifests = Vec::new();
            for index in [3, 7, 15] {
                let output = root.join(index.to_string()); fs::create_dir_all(&output).unwrap();
                fs::write(output.join("encrypted.bin"), &rar).unwrap();
                let manifest = output_manifest(&[("encrypted.bin", &rar)]);
                manifests.push(Arc::downgrade(manifest.records()));
                inventories.push((index, manifest.to_output_inventory(output.to_string_lossy().into_owned())));
            }
            let scheduler = Scheduler::new();
            let results = run.recursion.serve(&request.cancel, |depth, _| {
                assert_eq!(depth, 2);
                assert!(manifests.iter().all(|manifest| manifest.upgrade().is_none()));
                assert!(engine.recent_passwords().is_empty());
                answer
            }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
                Box::pin(run.discover_children_many(inventories.into_iter(), 1, &run.candidates))
            })).unwrap();
            assert_eq!(results.len(), 3);
            for (expected, (index, nested, scanned)) in [3, 7, 15].into_iter().zip(results) {
                assert_eq!(index, expected);
                assert_eq!(scanned, answer);
                if answer { assert!(!nested.tasks.is_empty()); }
                else { assert!(nested.tasks.is_empty()); }
                for task in &nested.tasks {
                    assert!(Path::new(&task.entry().entry_path).starts_with(root.join(index.to_string())));
                }
            }
        }
        release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
        fs::remove_dir_all(root).unwrap(); fs::remove_file(source).unwrap();
    }

    #[test]
    fn recursive_discovery_waits_for_consent_and_releases_the_manifest() {
        // Real RAR5 -hp fixture (password "secret"). A real successful probe
        // changes this request's password cache, so this catches discovery moved
        // above the prompt without a mock or process-global test counters.
        let rar = encrypted_rar_fixture();
        let source = crate::test_support::temp_file("recursive_consent", b"source");
        let root = source.with_extension("output");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("encrypted.bin"), &rar).unwrap();
        // A carrier can disappear after its worker manifest was produced.
        // A missing input is a retired proposal, even after consent.
        let carrier = [0; 1024];
        for answer in [false, true] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(Vec::new(), Mode::Extract);
            request.max_depth = usize::MAX;
            let config = Arc::make_mut(&mut request.config);
            config.recursive_extract = Recursion::Prompt;
            config.recursive_authorization.enabled = false;
            config.filesystem.scan_filters_enabled = false;
            config.embedded_scan.enabled = true;
            config.embedded_scan.recursive_candidate_ratio = 0.3;
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            Arc::get_mut(&mut run).unwrap().candidates = CandidateSet::new(
                Arc::from([Arc::from("secret")]), None, &engine.password_attempts, None,
            );
            let manifest = output_manifest(&[("encrypted.bin", &rar), ("carrier.bin", &carrier)]);
            let retained = Arc::downgrade(manifest.records());
            let inventory = manifest.to_output_inventory(root.to_string_lossy().into_owned());
            drop(manifest);
            let prompted = Mutex::new(Vec::new());
            let scheduler = Scheduler::new();
            let (nested, scanned) = run.recursion.serve(&request.cancel, |depth, pending| {
                assert!(retained.upgrade().is_none(), "prompt retained the worker manifest");
                assert!(engine.recent_passwords().is_empty(), "password probe ran before consent");
                prompted.lock().unwrap().push((depth, pending));
                answer
            }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
                Box::pin(run.discover_children(inventory, 1, &run.candidates))
            })).unwrap();
            assert_eq!(*prompted.lock().unwrap(), [(2, 1)]);
            assert_eq!(scanned, answer);
            if answer {
                assert_eq!(engine.recent_passwords().as_slice(), [Arc::<str>::from("secret")]);
                assert!(!nested.tasks.is_empty(), "approved archive was not discovered");
                assert!(nested.scan_errors.is_empty(), "departed carrier reported as unreadable");
            } else {
                assert!(engine.recent_passwords().is_empty());
                assert!(nested.tasks.is_empty());
                assert!(nested.scan_errors.is_empty(), "decline still scanned the carrier");
            }
        }
        release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn recursive_prompt_uses_filtered_outputs_before_candidate_authorization() {
        use crate::core::config::{ScanFilter, ScanFilterKind};
        use std::io::Write;

        // Main's boundary is a filtered file, not an archive candidate. Cover
        // the complementary no-prompt cases and post-prompt policy rejection
        // together so moving either policy to the wrong side is observable.
        let source = crate::test_support::temp_file("recursive_boundaries", b"source");
        let root = source.with_extension("output");
        fs::create_dir_all(root.join("sub")).unwrap();
        let plain = [b'x'; 1024];
        fs::write(root.join("sub/plain.bin"), plain).unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(b"nested payload").unwrap();
        let gzip = gzip.finish().unwrap();
        fs::write(root.join("nested.bin"), &gzip).unwrap();
        for (case, expected_prompt, expected_scan, expected_tasks) in [
            ("empty", false, false, 0),
            ("unreadable", false, false, 0),
            ("filtered", false, false, 0),
            ("depth", false, false, 0),
            ("cancelled", false, false, 0),
            ("plain", true, true, 0),
            ("archive", true, true, 1),
            ("policy_rejected", true, true, 0),
            ("fixed", false, true, 1),
        ] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(Vec::new(), Mode::Extract);
            request.max_depth = if case == "depth" { 0 } else { usize::MAX };
            let config = Arc::make_mut(&mut request.config);
            config.recursive_extract = if case == "fixed" { Recursion::Fixed(2) } else { Recursion::Prompt };
            config.recursive_authorization.enabled = case == "policy_rejected";
            config.recursive_authorization.minimum_authorization_score = 1.0;
            config.embedded_scan.enabled = false;
            config.filesystem.scan_filters_enabled = false;
            if case == "filtered" {
                config.filesystem.scan_filters_enabled = true;
                config.filesystem.scan_filters = Arc::from([ScanFilter {
                    enabled: true,
                    kind: ScanFilterKind::MtimeRange([Some(1), None, None, None, None]),
                }]);
            }
            let files: Vec<(&str, &[u8])> = match case {
                "empty" | "unreadable" => Vec::new(),
                "archive" | "policy_rejected" | "fixed" => vec![
                    ("sub/plain.bin", &plain), ("nested.bin", &gzip),
                ],
                _ => vec![("sub/plain.bin", &plain)],
            };
            let inventory = if case == "unreadable" {
                scan_output_inventory_impl(&root.join("absent").to_string_lossy())
            } else {
                output_manifest(&files).to_output_inventory(root.to_string_lossy().into_owned())
            };
            if case == "cancelled" {
                request.cancel.cancel();
            }
            let observer = |_: Event| {};
            let run = test_run(&engine, &request, &observer);
            let prompted = Mutex::new(Vec::new());
            let scheduler = Scheduler::new();
            let (nested, scanned) = run.recursion.serve(&request.cancel, |depth, pending| {
                prompted.lock().unwrap().push((depth, pending));
                true
            }, || scheduler.run(1, Origin::Foreground, &request.cancel, |_| {
                Box::pin(run.discover_children(inventory, 1, &run.candidates))
            })).unwrap();
            assert_eq!(!prompted.lock().unwrap().is_empty(), expected_prompt, "{case}");
            assert_eq!(scanned, expected_scan, "{case}");
            assert_eq!(nested.tasks.len(), expected_tasks, "{case}");
            assert_eq!(!nested.scan_errors.is_empty(), case == "unreadable", "{case}");
        }
        release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn recursive_prompt_parks_siblings_and_shares_each_depth_decision() {
        use std::time::Duration;

        struct Prompt {
            entered: mpsc::Sender<usize>,
            answer: Mutex<mpsc::Receiver<bool>>,
        }
        impl Observer for Prompt {
            fn notify(&self, _: Event) {}
            fn allow_recursive(&self, depth: usize, _: usize) -> bool {
                self.entered.send(depth).unwrap();
                self.answer.lock().unwrap().recv().unwrap()
            }
        }
        // The generic parked-task test does not exercise the blocking Observer
        // callback or same-depth prompt sharing. Withhold input until unrelated
        // work actually runs on the only host slot, for both yes and no answers.
        for answer in [true, false] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(Vec::new(), Mode::Extract);
            Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
            let (entered, prompts) = mpsc::channel();
            let (respond, responses) = mpsc::channel();
            let observer = Prompt { entered, answer: Mutex::new(responses) };
            let run = test_run(&engine, &request, &observer);
            let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
            let scheduler = pool.install(Scheduler::new);
            std::thread::scope(|scope| {
                let prompted = scope.spawn(|| {
                    run.recursion.serve(
                        &request.cancel,
                        |depth, pending| observer.allow_recursive(depth, pending),
                        || scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| {
                            let run = &run;
                            Box::pin(async move {
                                let results = spawner.bounded_map(vec![(); 8], move |_| {
                                    Box::pin(run.allow_recursive(2, 1))
                                }).await;
                                assert_eq!(run.allow_recursive(2, 1).await, answer);
                                let next_depth = run.allow_recursive(3, 1).await;
                                (results, next_depth)
                            })
                        }),
                    )
                });
                assert_eq!(prompts.recv_timeout(Duration::from_secs(10)).unwrap(), 2);
                let (finished, completed) = mpsc::channel();
                let independent = scope.spawn(|| {
                    scheduler.run(2, Origin::Watch, &Cancellation::new(), |_| {
                        Box::pin(async move { finished.send(()).unwrap() })
                    });
                });
                let admitted = completed.recv_timeout(Duration::from_secs(10));
                // Release the prompt even on a scheduling regression so both
                // requests can join before the assertion reports the failure.
                respond.send(answer).unwrap();
                assert_eq!(prompts.recv_timeout(Duration::from_secs(10)).unwrap(), 3);
                respond.send(!answer).unwrap();
                let (results, next_depth) = prompted.join().unwrap();
                independent.join().unwrap();
                admitted.expect("recursive prompt held the shared host slot");
                assert_eq!(results, vec![answer; 8]);
                assert_eq!(next_depth, !answer);
                assert!(prompts.try_recv().is_err(), "same depth asked more than once");
            });
        }
    }

    #[test]
    fn cancelled_or_panicking_prompt_wakes_siblings_and_joins_its_callback() {
        use std::time::Duration;

        // Verify cancellation wakes every archive independently of a still
        // returning input callback, and a callback panic cannot strand gates.
        for panic in [false, true] {
            let cancel = Cancellation::new();
            let prompts = RecursivePrompts::default();
            let scheduler = Scheduler::new();
            let (entered, entering) = mpsc::channel();
            let (respond, response) = mpsc::channel();
            let response = Mutex::new(response);
            let (finished, completed) = mpsc::channel();
            std::thread::scope(|scope| {
                let request = scope.spawn(|| {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        prompts.serve(&cancel, |_, _| {
                            entered.send(()).unwrap();
                            assert!(!panic, "observer prompt panic");
                            response.lock().unwrap().recv().unwrap()
                        }, || scheduler.run(1, Origin::Foreground, &cancel, |spawner| {
                            let prompts = &prompts;
                            let cancel = &cancel;
                            let finished = &finished;
                            Box::pin(async move {
                                let results = spawner.bounded_map(vec![(); 8], move |_| {
                                    Box::pin(prompts.allow(2, 1, cancel, None::<fn(usize, usize) -> std::future::Ready<bool>>))
                                }).await;
                                finished.send(()).unwrap();
                                results
                            })
                        }))
                    }))
                });
                entering.recv_timeout(Duration::from_secs(10)).unwrap();
                if !panic {
                    cancel.cancel();
                }
                let woke = completed.recv_timeout(Duration::from_secs(10));
                if !panic {
                    // A late yes must not replace the cancellation decision.
                    respond.send(true).unwrap();
                }
                let result = request.join().unwrap();
                woke.expect("cancellation left recursive siblings parked");
                assert!(cancel.cancelled());
                if panic {
                    assert!(result.is_err());
                } else {
                    let results = result.unwrap();
                    assert!(!results.is_empty() && results.len() <= 8);
                    assert!(results.iter().all(|allowed| !allowed));
                }
                for decision in prompts.decisions.lock().unwrap().values() {
                    assert!(decision.0.lock().unwrap().waiters.is_empty());
                }
            });
        }
    }

    #[test]
    fn cancelled_batch_does_not_swallow_unrelated_journal_io_errors() {
        struct JournalFailure(Cancellation, io::ErrorKind);
        impl Observer for JournalFailure {
            fn notify(&self, _: Event) {}
            fn claim_sources(&self, _: &Path, _: &[String], _: usize) -> io::Result<()> {
                self.0.cancel();
                Err(io::Error::new(self.1, "journal failure"))
            }
        }
        // The cancelled-child outcome regression alone would still pass if all
        // IO errors were swallowed whenever the request token was cancelled.
        for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(Vec::new(), Mode::Extract);
            let observer = JournalFailure(request.cancel.clone(), kind);
            let run = test_run(&engine, &request, &observer);
            let batch = Discovered {
                tasks: vec![Task {
                    primary: None,
                    inputs: vec![LogicalInput { password_probe: None,
                        input: ArchiveInput::file("child.zip".into(), "zip".into(), "child".into()),
                        password: None,
                        failure: Some(Failure::new(FailureKind::Damaged, "preflight failure")),
                    }],
                    owned_paths: Vec::new(),
                    source: DiscoverySource::Direct,
                    retry: None,
                    scope: None,
                }],
                errors: Vec::new(),
                scan_errors: DirectoryReadErrors::report(),
                blocked_paths: HashSet::new(),
            };
            let error = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
                Box::pin(run.execute_batch(batch, 2, None, None, spawner, None))
            }).unwrap_err();
            assert!(request.cancel.cancelled());
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "journal failure");
            assert_eq!(run.process_or_file_failure(io::Error::new(kind, "filesystem failure"), false).kind,
                FailureKind::FilesystemError);
            assert_eq!(run.process_or_file_failure(io::Error::new(kind, "worker failure"), true).kind,
                FailureKind::ProcessError);
            assert_eq!(run.process_or_file_failure(request.cancel.check_io().unwrap_err(), false).kind,
                FailureKind::Cancelled);
        }
    }

    #[test]
    #[cfg(windows)]
    fn watch_volume_retry_waits_for_a_late_writer_to_close() {
        use std::io::Write;
        let next_header = [1, 0, 0];
        let mut start_header = [0_u8; 20];
        start_header[..8].copy_from_slice(&45_u64.to_le_bytes());
        start_header[8..16].copy_from_slice(&(next_header.len() as u64).to_le_bytes());
        start_header[16..].copy_from_slice(&crc32fast::hash(&next_header).to_le_bytes());
        let mut head = b"\x37\x7A\xBC\xAF\x27\x1C\x00\x04".to_vec();
        head.extend(crc32fast::hash(&start_header).to_le_bytes());
        head.extend(start_header);
        head.resize(64, 0);
        let marker = crate::test_support::temp_file("late_volume", b"");
        let root = marker.with_extension("volumes");
        fs::create_dir(&root).unwrap();
        let first = root.join("split.7z.001");
        fs::write(&first, head).unwrap();

        let mut request = Request::new(vec![first.clone()], Mode::Extract);
        request.origin = Origin::Watch;
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let candidates = CandidateSet::new(Arc::from([]), None, &engine.password_attempts, None);
        let options = discovery::scan_options(&request.config).unwrap();
        let discovered = discovery::discover(&request, &options, &candidates).unwrap();
        let [task] = discovered.tasks.as_slice() else {
            panic!("expected an incomplete volume group");
        };
        let context = task.retry.as_deref().unwrap();
        let mut original = receipt(task.entry(), task.source, 1);
        let output = root.join("damaged-output");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("damaged.bin"), b"recoverable bytes").unwrap();
        original.output = Some(output.clone());
        original.failure = Some(Failure::new(FailureKind::MissingVolume, "missing"));
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        run.created_outputs.lock().unwrap().register(&output, &original);

        let last = root.join("split.7z.002");
        let mut writer = fs::File::create(&last).unwrap();
        writer.write_all(&[0; 13]).unwrap();
        writer.write_all(&next_header).unwrap();
        assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
            .unwrap().is_none());
        assert!(output.join("damaged.bin").is_file());
        drop(writer);
        assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
            .unwrap().is_some());
        // A live retry cannot replace a member that was still present at
        // admission. Only names admitted as departed may be left behind.
        let departed = root.join("split.7z.002.downloading");
        original.source_paths.push(departed.clone());
        assert!(discovery::retry_volume(&original, &[], context, &options, &candidates, &request)
            .unwrap().is_none());
        assert!(discovery::retry_volume(&original, &[departed], context, &options, &candidates, &request)
            .unwrap().is_some());
        run.discard_failed_output(&original, &output, &mut Outcome::default()).unwrap();
        assert!(!output.exists());
        assert!(run.created_outputs.lock().unwrap().0.is_empty());

        drop(discovered);
        release_reader_resources_under_roots(vec![root.to_string_lossy().into_owned()]).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn mirrored_output_names_keep_the_drive_or_share() {
        assert_eq!(
            mirrored_parent_component(Path::new(r"D:\Data\file set")),
            "D_Data_file_set"
        );
        assert_eq!(
            mirrored_parent_component(Path::new(r"\\server\share\folder")),
            "__server_share_folder"
        );
    }

    #[test]
    fn alias_dedup_covers_candidate_and_preflight_failure_plans() {
        use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan};
        let path = crate::test_support::temp_file("dedup_unresolved", b"physical archive");
        let alias = path.parent().unwrap().join(".").join(path.file_name().unwrap());
        let make = |path: &Path, candidate: bool, blocked: bool| {
            let mut input = ArchiveInput::file(path.to_string_lossy().into_owned(),
                "7z".into(), "archive".into());
            if candidate {
                input.volume_attempts = Some(Box::new(VolumeAttemptPlan {
                    sources: Box::new([InputExtent {
                        path: input.entry_path.clone(), start: 0, end: None,
                    }]),
                    layouts: Box::new([]), domains: Box::new([]),
                    head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
                }));
            }
            Task {
                primary: None,
                owned_paths: vec![input.entry_path.clone()],
                inputs: vec![LogicalInput { password_probe: None, input, password: None,
                    failure: blocked.then(|| Failure::new(FailureKind::MissingVolume, "missing")) }],
                source: DiscoverySource::Direct, retry: None,
                scope: None,
            }
        };
        for (candidate, blocked) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut tasks = vec![make(&path, candidate, blocked), make(&alias, candidate, blocked)];
            dedup_resolved_plans(&mut tasks);
            assert_eq!(tasks.len(), 1, "candidate={candidate}, blocked={blocked}");
        }
        let mut first = make(&path, false, true);
        first.inputs[0].input.mode = OpenMode::FileRange;
        first.inputs[0].input.parts = Box::new([InputPart::range(InputExtent {
            path: path.to_string_lossy().into_owned(), start: 0, end: Some(4),
        })]);
        let mut different = make(&alias, false, true);
        different.inputs[0].input = first.inputs[0].input.clone();
        different.inputs[0].input.parts[0].extent.start = 4;
        different.inputs[0].input.parts[0].extent.end = Some(8);
        let mut tasks = vec![first, different];
        dedup_resolved_plans(&mut tasks);
        assert_eq!(tasks.len(), 2, "distinct physical ranges must remain separate");
        fs::remove_file(path).unwrap();
    }

    // Covers history reuse on ancestor rebases and released descendant slots;
    // the leaf-only allocator tests cannot exercise this ownership path.
    #[test]
    fn ancestor_rebases_share_number_history_and_reuse_released_slots() {
        let source = crate::test_support::temp_file("ancestor_history", b"input");
        let base = source.with_extension("output");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let names = Mutex::new(OutputNames::default());
        assert_eq!(OutputNames::plan(&names, base.clone(), &result.path, 1, None).unwrap().unwrap(), base);
        for index in 1..=32 {
            let wanted = base.join(format!("child-{index}"));
            assert_eq!(OutputNames::plan(&names, wanted, &result.path, index as u64 + 1, None).unwrap().unwrap(),
                numbered(&base, index).join(format!("child-{index}")));
        }
        let family = output_key(&base);
        let guard = names.lock().unwrap();
        let history = guard.indices.peek(family.as_str()).unwrap();
        assert_eq!(history.next, 33);
        assert_eq!(history.observed.len(), 32);
        drop(guard);
        names.lock().unwrap().release(2);
        assert_eq!(OutputNames::plan(&names, base.join("replacement"), &result.path, 99, None).unwrap().unwrap(),
            numbered(&base, 1).join("replacement"));
        assert_eq!(names.lock().unwrap().indices.peek(family.as_str()).unwrap().next, 33);
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn conflicting_output_ancestor_preserves_alias_spelling() {
        for spelling in ["physical", "junction-alias"] {
            let path = PathBuf::from(spelling).join("branch").join("archive");
            let (base, tail) = conflicting_output_base(
                &path, "physical\\branch\\archive", "physical",
            ).unwrap();
            assert_eq!(base, Path::new(spelling));
            assert_eq!(numbered(base, 1).join(tail),
                PathBuf::from(format!("{spelling}(1)")).join("branch").join("archive"));
        }
    }

    // Registration-only tests miss filesystem probes under the naming lock.
    // Inject peers at that exact boundary, including an alias of the same tree;
    // no sleeps or timing assumptions are needed to expose lost reservations.
    #[test]
    fn output_path_queries_release_the_gate_and_keep_alias_ancestor_slots() {
        let source = crate::test_support::temp_file("output_query_gate", b"input");
        let root = source.with_extension("output").join("physical").join("deep");
        let alias = source.with_extension("aliases").join("shortcut");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(alias.parent().unwrap()).unwrap();
        let junction = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"]).arg(&alias).arg(&root).output().unwrap();
        assert!(junction.status.success(), "{}{}", String::from_utf8_lossy(&junction.stdout), String::from_utf8_lossy(&junction.stderr));
        let names = Mutex::new(OutputNames::default());
        let base = root.join("archive");
        let aliased = alias.join("archive");
        assert_eq!(OutputNames::plan(&names, base.clone(), &source, 1, None).unwrap().unwrap(), base);
        fs::create_dir(numbered(&base, 1)).unwrap();
        let mut probes = 0;
        let (output, key) = OutputNames::plan_checked(
            &names, aliased.join("child"), &source, 2, None, |path| {
                drop(names.try_lock().expect("path query held the global naming gate"));
                probes += 1;
                assert_eq!(path, numbered(&aliased, [1, 2, 4][probes - 1]));
                if probes == 1 {
                    let inside = numbered(&base, 1).join("inside");
                    assert_eq!(OutputNames::plan(&names, inside.clone(), &source, 10, None)?.unwrap(), inside,
                        "an unverified candidate must not displace children of an existing directory");
                }
                if probes == 2 {
                    let peer = OutputNames::plan(&names, base.join("peer"), &source, 3, None)?.unwrap();
                    assert_eq!(peer, numbered(&base, 3).join("peer"));
                    let independent = root.join("independent");
                    assert_eq!(OutputNames::plan(&names, independent.clone(), &source, 4, None)?.unwrap(), independent);
                    let child = OutputNames::plan(&names, path.join("nested"), &source, 2, Some(path))?.unwrap();
                    assert_eq!(child, path.join("nested"));
                }
                path.try_exists()
            },
        ).unwrap().unwrap();
        assert_eq!(probes, 3);
        assert_eq!(output, numbered(&aliased, 4).join("child"));
        assert_eq!(key, output_key(&numbered(&base, 4).join("child")));
        names.lock().unwrap().release(2);
        // A failed query must return its numbered ancestor slot, even though
        // the previous probe transferred that slot to a descendant claim.
        let failure = OutputNames::plan_checked(&names, base.join("failed"), &source, 5, None, |path| {
            assert_eq!(path, numbered(&base, 2));
            Err(io::ErrorKind::PermissionDenied.into())
        }).unwrap().unwrap_err();
        assert_eq!(failure.kind, FailureKind::FilesystemError);
        assert!(!names.lock().unwrap().owners.contains_key(&5));
        assert_eq!(OutputNames::plan(&names, base.join("retry"), &source, 5, None).unwrap().unwrap(),
            numbered(&base, 2).join("retry"));
        let mut names = names.lock().unwrap();
        for owner in [1, 3, 4, 5, 10] { names.release(owner); }
        assert!(names.claimed.is_empty() && names.owners.is_empty() && names.slots.is_empty());
        drop(names);
        // When the claimed ancestor is the junction itself, numbering must
        // stay beside the alias, not beside its deeper physical destination.
        let names = Mutex::new(OutputNames::default());
        assert!(OutputNames::retain(&names, &root, 6, &source, None));
        let (moved, key) = OutputNames::plan_checked(&names, alias.join("branch/leaf"),
            &source, 7, None, Path::try_exists).unwrap().unwrap();
        assert_eq!(moved, numbered(&alias, 1).join("branch/leaf"));
        assert_eq!(key, output_key(&moved));
        names.lock().unwrap().release(7);
        assert!(OutputNames::retain(&names, alias.parent().unwrap(), 8, &source, None));
        let (moved, key) = OutputNames::plan_checked(&names, alias.join("branch/leaf"),
            &source, 9, None, Path::try_exists).unwrap().unwrap();
        assert_eq!(moved, numbered(alias.parent().unwrap(), 1).join("shortcut/branch/leaf"));
        assert_eq!(key, output_key(&moved));
        fs::remove_dir(&alias).unwrap();
        fs::remove_dir(alias.parent().unwrap()).unwrap();
        fs::remove_dir_all(source.with_extension("output")).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn output_registration_does_not_hold_naming_gate_and_failure_releases_only_its_claim() {
        struct Register<'a>(&'a Mutex<OutputNames>);
        impl Observer for Register<'_> {
            fn notify(&self, _: Event) {}
            fn register_output(&self, result: &ArchiveResult, path: &Path) -> io::Result<()> {
                drop(self.0.try_lock().expect("registration held the global naming gate"));
                // Simulate a peer selecting the same tree during publication.
                let peer = OutputNames::plan(self.0, path.to_owned(), &result.path, 2, None)?.unwrap();
                assert_ne!(peer, path);
                Err(super::super::OutputCreateError::wrap(io::ErrorKind::PermissionDenied.into()))
            }
        }
        let source = crate::test_support::temp_file("unlocked_output_registration", b"input");
        let preferred = source.with_extension("output");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let names = Mutex::new(OutputNames::default());
        let failure = OutputNames::reserve(&names, preferred.clone(), &result, &Register(&names), 1, None)
            .unwrap().unwrap_err();
        assert!(matches!(failure.context.as_deref(),
            Some(super::super::FailureContext::OutputCreate { path: Some(path), .. }) if path == &preferred));
        assert!(!names.lock().unwrap().owners.contains_key(&1));
        assert_eq!(names.lock().unwrap().claimed.len(), 1);
        assert_eq!(OutputNames::plan(&names, preferred.clone(), &result.path, 3, None).unwrap().unwrap(), preferred);
        names.lock().unwrap().release(2);
        names.lock().unwrap().release(3);
        assert!(names.lock().unwrap().claimed.is_empty());
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn output_creation_collision_retries_without_reusing_external_directory() {
        struct Collision(PathBuf);
        impl Observer for Collision {
            fn notify(&self, _: Event) {}
            fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
                if path == self.0 {
                    fs::create_dir(path)?;
                    fs::write(path.join("user-file"), b"keep")?;
                }
                crate::scan::scope::create_output_root_exclusive(path)
                    .map_err(super::super::OutputCreateError::wrap)
            }
        }
        let source = crate::test_support::temp_file("output_create_collision", b"input");
        let preferred = source.with_extension("output");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let names = Mutex::new(OutputNames::default());
        let output = OutputNames::reserve(&names, preferred.clone(), &result,
            &Collision(preferred.clone()), 1, None).unwrap().unwrap();
        assert_eq!(output, numbered(&preferred, 1));
        assert_eq!(fs::read(preferred.join("user-file")).unwrap(), b"keep");
        assert_eq!(names.lock().unwrap().claimed.len(), 1);
        fs::remove_dir(output).unwrap();
        fs::remove_dir_all(&preferred).unwrap();
        // A dangling directory entry is not a competing created directory.
        // main's mkdir fails once; retrying it must not select the same name.
        let target = source.with_extension("target");
        fs::create_dir(&target).unwrap();
        let junction = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"]).arg(&preferred).arg(&target).output().unwrap();
        assert!(junction.status.success(), "{}", String::from_utf8_lossy(&junction.stdout));
        fs::remove_dir(&target).unwrap();
        let failure = OutputNames::reserve(&names, preferred.clone(), &result,
            &|_: Event| {}, 2, None).unwrap().unwrap_err();
        assert_eq!(failure.kind, FailureKind::FilesystemError);
        assert!(!names.lock().unwrap().owners.contains_key(&2));
        fs::remove_dir(&preferred).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn independent_output_trees_survive_peer_cleanup_and_creation_failure() {
        struct ObserverWithFailure;
        impl Observer for ObserverWithFailure {
            fn notify(&self, _: Event) {}
            fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
                if path.file_name().is_some_and(|name| name == "denied") {
                    return Err(super::super::OutputCreateError::wrap(
                        io::ErrorKind::PermissionDenied.into(),
                    ));
                }
                if path.file_name().is_some_and(|name| name == "journal") {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "journal unavailable"));
                }
                crate::scan::scope::create_output_root_exclusive(path)
                    .map_err(super::super::OutputCreateError::wrap)
            }
        }
        let source = crate::test_support::temp_file("output_isolation", b"input");
        let root = source.with_extension("output");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        // Match main's coarse lifecycle: both orders, same/different request
        // owners, owned recursion, foreign input and continued output refusal.
        for descendant_first in [false, true] {
          for shared_request in [false, true] {
            let registry = Arc::new(Mutex::new(OutputNames::default()));
            let owner = if shared_request { 1 } else { 2 };
            let first = OutputReservationGuard { registry: Arc::clone(&registry), owner: 1 };
            let second = OutputReservationGuard { registry: Arc::clone(&registry), owner };
            let preferred = root.join("a");
            let descendant = preferred.join("sub").join("b");
            let (failed, successful) = if descendant_first {
                let successful = OutputNames::reserve(&registry, descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap();
                (OutputNames::reserve(&registry, preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap(), successful)
            } else {
                let failed = OutputNames::reserve(&registry, preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap();
                (failed, OutputNames::reserve(&registry, descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap())
            };
            assert!(!successful.starts_with(&failed) && !failed.starts_with(&successful));
            fs::write(successful.join("payload"), b"keep").unwrap();
            let generated = successful.join("nested.zip");
            let nested = successful.join("nested");
            assert_eq!(OutputNames::reserve(&registry, nested.clone(), &result, &ObserverWithFailure, owner, Some(&generated))
                .unwrap().unwrap(), nested);
            let foreign = OutputNames::reserve(&registry, successful.join("foreign"), &result, &ObserverWithFailure, 3, Some(&generated))
                .unwrap().unwrap();
            assert!(!foreign.starts_with(&successful));
            assert!(!OutputNames::retain(&registry, &successful.join("continued"), 3, &result.path, None));
            cleanup_owned_output(&failed).unwrap();
            assert_eq!(fs::read(successful.join("payload")).unwrap(), b"keep");
            assert_eq!(OutputNames::reserve(&registry, root.join("denied"), &result, &ObserverWithFailure, owner, None)
                .unwrap().unwrap_err().kind, FailureKind::FilesystemError);
            assert!(OutputNames::reserve(&registry, root.join("journal"), &result, &ObserverWithFailure, owner, None).is_err());
            // Released owners leave bounded family history, not ownership.
            // More families evict history without affecting live claims.
            for short_owner in 10..42 {
                let family = root.join(format!("family-{short_owner}"));
                fs::create_dir(&family).unwrap();
                OutputNames::reserve(&registry, family.clone(), &result, &ObserverWithFailure, short_owner, None)
                    .unwrap().unwrap();
                assert!(registry.lock().unwrap().indices.peek(output_key(&family).as_str()).is_some());
                registry.lock().unwrap().release(short_owner);
                assert!(registry.lock().unwrap().indices.len() <= OUTPUT_HISTORY_LIMIT);
                assert!(!registry.lock().unwrap().owners.contains_key(&short_owner));
            }
            registry.lock().unwrap().release(3);
            drop(second);
            drop(first);
            assert!(registry.lock().unwrap().claimed.is_empty());
            registry.lock().unwrap().clear_history();
            assert_eq!(registry.lock().unwrap().indices.len(), 0);
            fs::remove_dir_all(&root).unwrap();
          }
        }
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn failed_segment_plans_name_without_creating_recoverable_output() {
        let source = crate::test_support::temp_file("planned_segment", b"carrier");
        let root = source.with_extension("output");
        fs::create_dir(&root).unwrap();
        let preferred = root.join("segment");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "segment".into());
        let result = receipt(&input, DiscoverySource::Embedded, 1);
        let names = Mutex::new(OutputNames::default());
        let failed = OutputNames::plan(&names, preferred.clone(), &result.path, 1, None).unwrap().unwrap();
        let sibling = OutputNames::plan(&names, preferred.clone(), &result.path, 1, None).unwrap().unwrap();
        assert_eq!(failed, preferred);
        assert_eq!(sibling, numbered(&preferred, 1));
        assert!(!failed.exists() && !sibling.exists());
        names.lock().unwrap().release(1);
        assert!(OutputNames::retain(&names, &failed, 2, &source, Some(&root)));
        assert!(OutputNames::retain(&names, &sibling, 2, &source, Some(&root)));
        assert_eq!(OutputNames::plan(&names, preferred.clone(), &result.path, 2, None).unwrap().unwrap(), numbered(&preferred, 2));
        fs::remove_dir(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn output_history_survives_requests_rechecks_released_slots_and_stays_bounded() {
        struct Create;
        impl Observer for Create {
            fn notify(&self, _: Event) {}
            fn register_output(&self, _: &ArchiveResult, path: &Path) -> io::Result<()> {
                crate::scan::scope::create_output_root_exclusive(path)
                    .map_err(super::super::OutputCreateError::wrap)
            }
        }
        let source = crate::test_support::temp_file("output_history", b"input");
        let root = source.with_extension("output");
        fs::create_dir(&root).unwrap();
        let preferred = root.join("archive");
        fs::create_dir(&preferred).unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let names = Mutex::new(OutputNames::default());
        let family = output_key(&preferred);
        for owner in 1..=32 {
            let output = OutputNames::reserve(&names, preferred.clone(), &result, &Create, owner, None).unwrap().unwrap();
            assert_eq!(output, numbered(&preferred, owner as usize));
            names.lock().unwrap().release(owner);
            let guard = names.lock().unwrap();
            let history = guard.indices.peek(family.as_str()).unwrap();
            assert_eq!(history.next, owner as usize + 1);
            assert_eq!(history.available.first(), Some(&(owner as usize)));
        }
        // Released reservations remain reusable if their actual output is
        // removed, rather than blindly allocating ever increasing numbers.
        fs::remove_dir(numbered(&preferred, 32)).unwrap();
        assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 33, None).unwrap().unwrap(), numbered(&preferred, 32));
        names.lock().unwrap().release(33);
        fs::remove_dir(&preferred).unwrap();
        assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 34, None).unwrap().unwrap(), preferred);
        names.lock().unwrap().release(34);
        struct Fail;
        impl Observer for Fail {
            fn notify(&self, _: Event) {}
            fn register_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
                Err(super::super::OutputCreateError::wrap(io::ErrorKind::PermissionDenied.into()))
            }
        }
        assert!(OutputNames::reserve(&names, preferred.clone(), &result, &Fail, 35, None).unwrap().is_err());
        assert_eq!(OutputNames::reserve(&names, preferred.clone(), &result, &Create, 36, None).unwrap().unwrap(), numbered(&preferred, 33));
        names.lock().unwrap().release(36);
        for index in 0..(OUTPUT_HISTORY_LIMIT + 1) { names.lock().unwrap().next_index(&Arc::from(format!("family-{index}"))); }
        assert_eq!(names.lock().unwrap().indices.len(), OUTPUT_HISTORY_LIMIT);
        assert!(names.lock().unwrap().indices.peek(family.as_str()).is_none());
        assert!(names.lock().unwrap().slots.values().all(|slots| !slots.contains_key(family.as_str())));
        names.lock().unwrap().clear_history();
        let names = names.lock().unwrap();
        assert_eq!(names.indices.len(), 0);
        assert!(names.slots.is_empty());
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn completed_failures_are_carried_until_their_dependencies_change() {
        let source = crate::test_support::temp_file("failure_receipts", b"archive");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let mut generations = HashMap::from([(
            path_key(&input.entry_path), capture_file_generation(&source).unwrap(),
        )]);
        let mut keys = Vec::new();
        for kind in [None, Some(FailureKind::Damaged), Some(FailureKind::WrongPassword)] {
            let mut result = receipt(&input, DiscoverySource::Direct, 1);
            result.failure = kind.map(|kind| Failure::new(kind, "failed"));
            // Successful receipts do not require opening any output directory.
            if kind.is_none() { result.output = Some(source.with_extension("not-created")); }
            let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
            checkpoint.set_password_signature(|| "before".into());
            let checkpoint: InputCheckpoint = serde_json::from_slice(
                &serde_json::to_vec(&checkpoint).unwrap(),
            ).unwrap();
            assert!(checkpoint.valid_for(&input, &generations));
            assert!(checkpoint.password_unchanged(|| "before".into()));
            assert_eq!(checkpoint.password_unchanged(|| "after".into()), kind != Some(FailureKind::WrongPassword));
            let restored = checkpoint.result(1);
            assert_eq!(restored.failure.as_ref().map(|failure| failure.kind), kind);
            assert_eq!(restored.output, result.output);
            assert!(!restored.partial);
            keys.push(checkpoint);
        }
        fs::write(&source, b"changed generation").unwrap();
        generations.insert(path_key(&input.entry_path), capture_file_generation(&source).unwrap());
        assert!(keys.iter().all(|checkpoint| !checkpoint.valid_for(&input, &generations)));
        fs::remove_file(source).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn complete_carrier_keeps_salvage_only_with_a_complete_sibling() {
        for (complete_sibling, damaged) in [(false, true), (true, true), (true, false)] {
            let source = crate::test_support::temp_file("carrier_salvage", &[0; 16]);
            let container = source.with_extension("output");
            fs::create_dir(&container).unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
                container.file_name().unwrap().to_string_lossy().into_owned());
            let inputs: Vec<_> = archive_input_slices(&input, &[
                ("zip", 0, Some(8)), ("zip", 8, Some(16)),
            ]).unwrap().0.into_iter().map(Option::unwrap).collect();
            let generations = HashMap::from([
                (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
            ]);
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(vec![source.clone()], Mode::Extract);
            request.max_depth = 0;
            Arc::make_mut(&mut request.config).extraction.content_requirement = ContentRequirement::Complete;
            Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
            for (index, input) in inputs.iter().enumerate() {
                let output = container.join(format!("segment-{index}"));
                fs::create_dir(&output).unwrap();
                fs::write(output.join("payload"), b"keep").unwrap();
                let mut result = receipt(input, DiscoverySource::Embedded, 1);
                result.output = Some(output);
                result.files = 1;
                result.bytes = 4;
                if (index != 0 && damaged) || !complete_sibling {
                    result.partial = true;
                    result.recovered_complete_files = 1;
                    result.failure = Some(Failure::new(FailureKind::Damaged, "CRC error"));
                }
                request.checkpoints.push(InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap());
            }
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
            }
            let task = Task {
                primary: None,
                inputs: inputs.into_iter().map(|input| LogicalInput { password_probe: None, input, password: None, failure: None }).collect(),
                owned_paths: vec![source.to_string_lossy().into_owned()],
                source: DiscoverySource::Embedded,
                retry: None,
                scope: None,
            };
            let outcome = Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                run.execute_task(run.register_task(task), 1, 1, None, spawner)
            }).unwrap();
            assert_eq!(outcome.archives.len(), 2);
            assert_eq!(outcome.failed(), if !damaged { 0 } else if complete_sibling { 1 } else { 2 });
            assert_eq!(outcome.checkpoints.len(), if damaged { 2 } else { 0 },
                "successful carrier plans must not survive in ancestor recovery");
            assert!(outcome.archives.iter().all(|result| !result.partial));
            assert!(source.is_file());
            for index in 0..2 {
                assert_eq!(container.join(format!("segment-{index}/payload")).is_file(), complete_sibling);
            }
            release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
            if container.exists() { fs::remove_dir_all(container).unwrap(); }
            fs::remove_file(source).unwrap();
        }
    }

    #[test]
    fn retained_carrier_recomputes_content_policy_without_reexecuting_inputs() {
        // Exercise the real receipt/aggregate path in both policy directions.
        // Missing-volume reload must not freeze the previous acceptance flag;
        // password and unsupported failures never become accepted partials.
        for kind in [FailureKind::Damaged, FailureKind::MissingVolume,
                     FailureKind::WrongPassword, FailureKind::Unsupported] {
            for (complete_files, has_output) in [(1, true), (0, true), (1, false)] {
                let source = crate::test_support::temp_file("retained_policy_reload", &[0; 16]);
                let container = source.with_extension("output");
                fs::create_dir(&container).unwrap();
                let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(),
                    container.file_name().unwrap().to_string_lossy().into_owned());
                let inputs: Vec<_> = archive_input_slices(&input, &[
                    ("zip", 0, Some(8)), ("zip", 8, Some(16)),
                ]).unwrap().0.into_iter().map(Option::unwrap).collect();
                let generations = HashMap::from([
                    (path_key(&input.entry_path), capture_file_generation(&source).unwrap()),
                ]);
                let engine = Engine::new(PathBuf::from("unused-worker"));
                let mut request = Request::new(vec![source.clone()], Mode::Extract);
                request.max_depth = 8;
                Arc::make_mut(&mut request.config).recursive_extract = Recursion::Prompt;
                Arc::make_mut(&mut request.config).filesystem.scan_filters_enabled = false;
                Arc::make_mut(&mut request.config).post_extract.archive_cleanup_mode = CleanupMode::Keep;
                for (index, input) in inputs.iter().enumerate() {
                    let output = container.join(format!("segment-{index}"));
                    fs::create_dir(&output).unwrap();
                    fs::write(output.join("payload"), b"keep").unwrap();
                    let mut result = receipt(input, DiscoverySource::Embedded, 1);
                    result.output = Some(output);
                    result.files = 1;
                    result.bytes = 4;
                    if index == 1 {
                        result.failure = Some(Failure::new(kind, "retained failure"));
                        result.recovered_complete_files = complete_files;
                        if !has_output { result.output = None; }
                    }
                    let mut checkpoint = InputCheckpoint::create(&source, Arc::new((input).clone()), &result, &generations, Some(&container)).unwrap();
                    checkpoint.set_password_signature(|| CandidateSet::new(
                        Arc::from([]), None, &AttemptCache::default(), None,
                    ).signature(&input.entry_path));
                    request.checkpoints.push(checkpoint);
                }
                for requirement in [ContentRequirement::Complete,
                                    ContentRequirement::AllowPartial, ContentRequirement::Complete] {
                    Arc::make_mut(&mut request.config).extraction.content_requirement = requirement;
                    let outcome = {
                        struct RetainedOnly(Mutex<Option<PathBuf>>);
                        impl Observer for RetainedOnly {
                            fn notify(&self, event: Event) {
                                if let Event::Finished { id: 1, result, .. } = event {
                                    *self.0.lock().unwrap() = result.output;
                                }
                            }
                            fn allow_recursive(&self, _: usize, _: usize) -> bool {
                                panic!("retained output must not be scanned or prompt again");
                            }
                        }
                        let observer = RetainedOnly(Mutex::new(None));
                        let mut run = test_run(&engine, &request, &observer);
                        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                            Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy()))).or_default().insert(checkpoint.key(), index);
                        }
                        let task = Task {
                            primary: None,
                            inputs: inputs.iter().cloned().map(|input| LogicalInput { password_probe: None,
                                input, password: None, failure: None,
                            }).collect(),
                            owned_paths: vec![source.to_string_lossy().into_owned()],
                            source: DiscoverySource::Embedded, retry: None,
                            scope: None,
                        };
                        let outcome = run.recursion.serve(&request.cancel,
                            |depth, pending| observer.allow_recursive(depth, pending),
                            || Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                                run.execute_task(run.register_task(task), 1, 1, None, spawner)
                            }),
                        ).unwrap();
                        assert_eq!(observer.0.lock().unwrap().as_deref(), Some(container.as_path()),
                            "one surviving segment must still report its physical carrier root");
                        outcome
                    };
                    let accepted = requirement == ContentRequirement::AllowPartial
                        && matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume)
                        && complete_files > 0 && has_output;
                    assert_eq!(outcome.archives.len(), 2);
                    assert_eq!(outcome.archives[1].partial, accepted);
                    assert_eq!(outcome.failed(), usize::from(!accepted));
                    assert!(outcome.archives.iter().all(|result| result.retained));
                    assert!(outcome.errors.is_empty());
                    for index in 0..2 {
                        assert_eq!(fs::read(container.join(format!("segment-{index}/payload"))).unwrap(), b"keep");
                    }
                    request.checkpoints = outcome.checkpoints.into_vec();
                }
                release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
                fs::remove_dir_all(container).unwrap();
                fs::remove_file(source).unwrap();
            }
        }
    }

    #[test]
    fn split_recovery_warning_preserves_original_failure_and_confirmation() {
        let input = ArchiveInput::file("split.zip.001".into(), "zip".into(), "split".into());
        for (split, partial, kind, suspected, expected) in [
            (true, true, FailureKind::Damaged, false, true),
            (true, false, FailureKind::Damaged, true, true),
            (true, false, FailureKind::Damaged, false, false),
            (false, true, FailureKind::Damaged, true, false),
            (true, true, FailureKind::MissingVolume, true, false),
            (true, false, FailureKind::WrongPassword, false, false),
        ] {
            let mut result = receipt(&input, DiscoverySource::Direct, 1);
            result.partial = partial;
            let mut failure = Failure::new(kind, "native cause");
            failure.evidence = worker_evidence(&json!({"missing_volume_suspected": suspected}), None, None);
            result.failure = Some(failure);
            project_possible_missing_volume(std::slice::from_mut(&mut result), split);
            let failure = result.failure.unwrap();
            assert_eq!(failure.kind, kind);
            assert_eq!(failure.evidence.as_ref().is_some_and(|e| e.possible_missing_volume), expected);
            let restored: Failure = serde_json::from_value(serde_json::to_value(failure).unwrap()).unwrap();
            assert_eq!(restored.evidence.as_ref().is_some_and(|e| e.possible_missing_volume), expected);
        }
        // One confirmed missing-volume cause suppresses a speculative carrier
        // warning, even when another independently recovered segment is damaged.
        let mut first = receipt(&input, DiscoverySource::Direct, 1);
        first.partial = true;
        first.failure = Some(Failure::new(FailureKind::Damaged, "CRC"));
        let mut second = receipt(&input, DiscoverySource::Direct, 1);
        second.partial = true;
        second.failure = Some(Failure::new(FailureKind::MissingVolume, "part2"));
        let mut results = [first, second];
        project_possible_missing_volume(&mut results, true);
        assert!(results.iter().all(|r| !r.failure.as_ref().unwrap().evidence.as_ref()
            .is_some_and(|e| e.possible_missing_volume)));
    }

    #[test]
    fn changed_id_replacement_without_output_clears_rejected_recovery() {
        let source = crate::test_support::temp_file("replacement_rejected_recovery", b"archive");
        let output = source.with_extension("recovery-output");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("complete.txt"), b"complete").unwrap();
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(vec![source.clone()], Mode::Extract);
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let first = ArchiveInput::file(source.to_string_lossy().into_owned(), "".into(), "original".into());
        let generation = crate::io::reader::capture_file_generation(&source).unwrap();
        let generations = HashMap::from([(path_key(&first.entry_path), generation)]);
        let mut failed = receipt(&first, DiscoverySource::Detection, 1);
        failed.failure = Some(Failure::new(FailureKind::MissingVolume, "missing")
            .with_context(super::super::FailureContext::Extraction));
        failed.output = Some(output.clone());
        failed.files = 1;
        failed.bytes = 8;
        failed.recovered_complete_files = 1;
        let mut checkpoint = InputCheckpoint::create(&source, Arc::new(first.clone()), &failed, &generations, None).unwrap();
        checkpoint.install_report(InputCheckpoint::report_state(&first, &failed,
            Some(&output), None, 1, 1));
        run.created_outputs.lock().unwrap().register(&output, &failed);
        let mut outcome = Outcome::default();
        // Exercise real retry cleanup. The second input then fails before
        // writing output, while the original checkpoint still has partial facts.
        assert!(run.discard_failed_output(&failed, &output, &mut outcome).unwrap());
        assert!(!output.exists());
        let mut replacement = first;
        replacement.format_hint = "7z".into();
        assert!(!checkpoint.same_report_input(&replacement));
        let mut second = receipt(&replacement, DiscoverySource::Relations, 1);
        second.failure = Some(Failure::new(FailureKind::WrongPassword, "password")
            .with_context(super::super::FailureContext::PasswordResolution));
        let mut states = vec![InputCheckpoint::report_state(&replacement, &second,
            Some(&output), None, 1, 1)];
        let mut parent_outputs = vec![(second, None, Arc::new(replacement), 1)];
        outcome.checkpoints.push(checkpoint);
        run.apply_complete_content_policy(&mut parent_outputs, &mut states, Some(0), &mut outcome).unwrap();
        assert!(!outcome.checkpoints[0].has_recovered_members());
        assert!(!outcome.checkpoints[0].has_output());
        let (second, _, input, ..) = &parent_outputs[0];
        let mut checkpoint = InputCheckpoint::create(&source, Arc::clone(input), second, &generations, None).unwrap();
        checkpoint.install_report(states[0].take());
        outcome.checkpoints.push(checkpoint);
        let recovery = InputRecovery::capture(&outcome.checkpoints, &source, None,
            None, 1, true, true).unwrap();
        let report = recovery.report(|failure| json!({"kind": format!("{:?}", failure.kind)}));
        assert_eq!(report["output_dir"], "");
        assert!(recovery.retry_output().is_none());
        for checkpoint in report["inputs"].as_array().unwrap() {
            assert_eq!(checkpoint["output_dir"], "");
            assert_eq!(checkpoint["recovered_complete_files"], 0);
            assert_eq!(checkpoint["complete"], false);
        }
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn replacement_recreates_the_original_numbered_reservation() {
        let source = crate::test_support::temp_file("replacement_output", b"source");
        let preferred = source.with_extension("output");
        fs::create_dir(&preferred).unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let request = Request::new(vec![source.clone()], Mode::Extract);
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let observer = |_: Event| {};
        let run = test_run(&engine, &request, &observer);
        let output = run.reserve_output(preferred.clone(), &result, None).unwrap().unwrap();
        assert_ne!(output, preferred);
        fs::write(output.join("old"), b"payload").unwrap();
        assert!(run.discard_failed_output(&result, &output, &mut Outcome::default()).unwrap());
        let recreated = run.recreate_reserved_output(&output, &result).unwrap().unwrap();
        assert_eq!(recreated, output);
        assert!(output.is_dir());
        assert!(!output.join("old").exists());
        assert!(run.output_names.registry.lock().unwrap().claimed.contains_key(&output_key(&output)));
        fs::remove_dir(output).unwrap();
        fs::remove_dir(preferred).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn failed_carrier_recovery_counts_choose_only_eligible_output_roots() {
        for kind in [FailureKind::Unsupported, FailureKind::Damaged, FailureKind::MissingVolume] {
            let source = crate::test_support::temp_file("recovery_count_carrier", &[0; 16]);
            let container = source.with_extension("outputs");
            fs::create_dir(&container).unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "carrier".into());
            let inputs: Vec<_> = archive_input_slices(&input, &[("zip", 0, Some(8)), ("zip", 8, Some(16))])
                .unwrap().0.into_iter().map(Option::unwrap).collect();
            let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
            let mut checkpoints = Vec::new();
            for (index, input) in inputs.iter().enumerate() {
                let mut result = receipt(input, DiscoverySource::Embedded, 1);
                let failure = Failure::new(if index == 0 { kind } else { FailureKind::WrongPassword }, "failed segment");
                result.recovered_complete_files = recovery_complete_files(&failure, u64::from(index == 0));
                result.failure = Some(failure);
                if index == 0 {
                    let output = container.join("salvaged"); fs::create_dir(&output).unwrap();
                    fs::write(output.join("complete.txt"), b"manual recovery").unwrap();
                    result.output = Some(output); result.files = 1;
                }
                let mut checkpoint = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, Some(&container)).unwrap();
                checkpoint.install_report(InputCheckpoint::report_state(input, &result, None, None, index + 1, 2));
                checkpoint.set_password_signature(|| "old".into());
                checkpoints.push(checkpoint);
            }
            // Only B's password change invalidates its receipt. A's physical
            // salvage stays on disk, but Unsupported must not retain its root.
            assert!(checkpoints[0].password_unchanged(|| "new".into()));
            assert!(!checkpoints[1].password_unchanged(|| "new".into()));
            let retained = checkpoints[0].retained_container();
            let eligible = kind != FailureKind::Unsupported;
            assert_eq!(retained, eligible.then_some(container.as_path()));
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let mut request = Request::new(vec![source.clone()], Mode::Extract);
            Arc::make_mut(&mut request.config).extraction.content_requirement = ContentRequirement::AllowPartial;
            let observer = |_: Event| {};
            let run = test_run(&engine, &request, &observer);
            let selected = match retained {
                Some(root) => root.to_path_buf(),
                None => run.reserve_output(container.clone(), &receipt(&inputs[1], DiscoverySource::Embedded, 1), None).unwrap().unwrap(),
            };
            assert_eq!(selected == container, eligible);
            let recovery = InputRecovery::capture(&checkpoints, &source, Some(&container), None, 2, true, eligible).unwrap();
            let report = recovery.report(|failure| json!({"kind": format!("{:?}", failure.kind)}));
            assert_eq!(report["inputs"][0]["recovered_complete_files"], u64::from(eligible));
            assert_eq!(fs::read(container.join("salvaged/complete.txt")).unwrap(), b"manual recovery");
            if selected != container { fs::remove_dir(selected).unwrap(); }
            fs::remove_dir_all(container).unwrap(); fs::remove_file(source).unwrap();
        }
    }

    #[test]
    fn retained_payload_does_not_authorize_partial_success() {
        for (kind, stage, expected) in [
            ("unsupported_method", "item_extract", true),
            ("data_error", "", true),
            ("unsupported_method", "archive_open", false),
            ("output_filesystem", "item_extract", false),
            ("process_exit", "archive_extract", false),
        ] {
            let mut frame: WorkerFrame = serde_json::from_str(&serde_json::json!({
                "failure_kind":kind, "failure_stage":stage,
            }).to_string()).unwrap();
            frame.recovery = Some(super::super::RecoveryPreview {
                complete_files: 2, ..Default::default()
            });
            assert_eq!(recoverable_content_failure(&frame), expected);
            assert_eq!(recoverable_file_count(&frame), if expected { 2 } else { 0 });
        }
        for kind in [FailureKind::Damaged, FailureKind::MissingVolume,
            FailureKind::WrongPassword, FailureKind::Unsupported, FailureKind::PasswordInconclusive] {
            let mut failure = Failure::new(kind, "worker failure");
            assert_eq!(recovery_complete_files(&failure, 2),
                if matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume) { 2 } else { 0 });
            failure.causes.push(Failure::new(FailureKind::Unsupported, "compound cause"));
            assert_eq!(recovery_complete_files(&failure, 2), 0);
            assert_eq!(accepts_partial_content(ContentRequirement::AllowPartial, kind, 2),
                matches!(kind, FailureKind::Damaged | FailureKind::MissingVolume));
            assert!(!accepts_partial_content(ContentRequirement::Complete, kind, 2));
            assert!(!accepts_partial_content(ContentRequirement::AllowPartial, kind, 0));
        }
    }

    #[test]
    fn failed_output_cleanup_is_local_but_journal_failure_propagates() {
        struct Journal { fail: bool }
        impl Observer for Journal {
            fn notify(&self, _: Event) {}
            fn discard_output(&self, _: &Path, _: &[PathBuf], _: &Path) -> io::Result<()> {
                if self.fail { Err(io::Error::other("journal unavailable")) } else { Ok(()) }
            }
        }
        let source = crate::test_support::temp_file("discard_failure", b"archive");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let mut failed = receipt(&input, DiscoverySource::Direct, 1);
        failed.failure = Some(Failure::new(FailureKind::Damaged, "failed"));
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(vec![source.clone()], Mode::Extract);
        let observer = Journal { fail: false };
        let run = test_run(&engine, &request, &observer);
        let mut outcome = Outcome::default();
        outcome.archives.push(receipt(&input, DiscoverySource::Direct, 1));
        // Replaced non-directory output fails independently of ACL privileges.
        run.created_outputs.lock().unwrap().register(&source, &failed);
        assert!(!run.discard_failed_output(&failed, &source, &mut outcome).unwrap());
        assert_eq!(outcome.archives.len(), 1);
        assert_eq!(outcome.cleanup_results.len(), 1);
        assert!(run.created_outputs.lock().unwrap().0.contains_key(&output_key(&source)));
        let output = source.with_extension("output");
        fs::create_dir(&output).unwrap();
        let observer = Journal { fail: true };
        let run = test_run(&engine, &request, &observer);
        assert_eq!(run.discard_failed_output(&failed, &output, &mut outcome)
            .unwrap_err().to_string(), "journal unavailable");
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn rollback_isolates_cleanup_failures_and_preserves_journal_errors() {
        struct Discards {
            fail: bool,
            paths: Mutex<Vec<PathBuf>>,
        }
        impl Observer for Discards {
            fn notify(&self, _: Event) {}
            fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
                self.paths.lock().unwrap().push(output.to_owned());
                if self.fail { Err(io::Error::other("journal unavailable")) } else { Ok(()) }
            }
        }
        let source = crate::test_support::temp_file("rollback_failure", b"source");
        let root = source.with_extension("output");
        let bad = root.join("a-failed");
        let good = root.join("z-cleaned");
        let nested = good.join("child");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let generations = HashMap::from([
            (path_key(&source.to_string_lossy()), capture_file_generation(&source).unwrap()),
        ]);
        for journal_fails in [false, true] {
            fs::create_dir_all(&bad).unwrap();
            fs::create_dir_all(&nested).unwrap();
            fs::write(nested.join("payload"), b"partial data").unwrap();
            let mut created = CreatedOutputs::default();
            let mut outcome = Outcome::default();
            for output in [&bad, &good, &nested] {
                let mut archive = receipt(&input, DiscoverySource::Direct, 1);
                archive.output = Some(output.clone());
                archive.files = 1;
                archive.bytes = 12;
                outcome.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &archive, &generations, None).unwrap());
                created.register(output, &archive);
                outcome.archives.push(archive);
            }
            // Deterministic unsafe-root failure, independent of ACLs/admin rights.
            fs::remove_dir(&bad).unwrap();
            fs::write(&bad, b"replacement must survive").unwrap();
            let observer = Discards { fail: journal_fails, paths: Mutex::default() };
            let result = created.rollback(&observer, &mut outcome);
            if journal_fails {
                assert_eq!(result.unwrap_err().to_string(), "journal unavailable");
                assert_eq!(created.0.len(), 3);
            } else {
                result.unwrap();
                assert_eq!(created.0.len(), 1);
            }
            assert!(created.0.contains_key(&output_key(&bad)));
            assert_eq!(fs::read(&bad).unwrap(), b"replacement must survive");
            assert!(!good.exists());
            assert_eq!(outcome.cleanup_results.len(), 1);
            assert_eq!(outcome.errors[0].kind, InputErrorKind::Cleanup);
            assert_eq!(outcome.errors[0].path, bad);
            assert_eq!(outcome.checkpoints.len(), 1);
            assert_eq!(outcome.checkpoints[0].output(), bad);
            assert_eq!(outcome.archives[0].output.as_ref(), Some(&bad));
            assert!(outcome.archives.iter().skip(1).all(|archive| {
                archive.output.is_none() && archive.files == 0 && archive.bytes == 0
                    && archive.failure.as_ref().unwrap().kind == FailureKind::Cancelled
            }));
            let paths = observer.paths.lock().unwrap();
            assert_eq!(paths.len(), 2);
            assert!(!paths.contains(&bad));
            fs::remove_file(&bad).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn cancellation_joins_nested_writer_then_rolls_back_only_uncommitted_trees() {
        struct Discards(Mutex<Vec<PathBuf>>);
        impl Observer for Discards {
            fn notify(&self, _: Event) {}
            fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
                self.0.lock().unwrap().push(output.to_owned());
                Ok(())
            }
        }
        let source = crate::test_support::temp_file("cancel_output_trees", b"source");
        let root = source.with_extension("output");
        let parent = root.join("parent");
        let nested = parent.join("child");
        let sibling = root.join("completed");
        let retained = root.join("continued");
        let retry_child = retained.join("new-segment");
        let retained_finished = retained.join("finished-carrier");
        let retained_segment = retained_finished.join("segment");
        let retained_source = retained.join("finished-carrier.zip");
        for path in [&nested, &sibling, &retry_child, &retained_segment] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(parent.join("ordinary.txt"), b"parent data").unwrap();
        fs::write(nested.join("partial.txt"), b"in flight").unwrap();
        fs::write(sibling.join("kept.txt"), b"committed").unwrap();
        fs::write(retained.join("old.txt"), b"continued data").unwrap();
        fs::write(retained_source.clone(), b"nested source").unwrap();
        fs::write(retained_segment.join("payload.txt"), b"completed nested data").unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
        // A punctuation sibling sorts between the exact key and descendants.
        // Relocation must scan the separator-prefixed range independently.
        let mut moving = CreatedOutputs::default();
        let old = root.join("a");
        let punctuation = root.join("a (2)");
        let new = root.join("relocated");
        let ownership = receipt(&input, DiscoverySource::Direct, 1);
        for path in [&old, &old.join("child"), &punctuation] {
            moving.register(path, &ownership);
        }
        moving.relocate(&old, &new);
        assert!(moving.0.contains_key(&output_key(&new.join("child"))));
        assert!(!moving.0.contains_key(&output_key(&old.join("child"))));
        assert!(moving.0.contains_key(&output_key(&punctuation)));
        let mut outcome = Outcome::default();
        let mut created = CreatedOutputs::default();
        for path in [&parent, &nested, &sibling, &retry_child, &retained_finished, &retained_segment] {
            let mut archive = receipt(&input, DiscoverySource::Direct, 1);
            archive.output = Some(path.clone());
            created.register(path, &archive);
            outcome.archives.push(archive);
        }
        created.commit_if_unowned(&sibling);
        // A freshly created parent still owns its completed nested output.
        created.commit_if_unowned(&nested);
        assert!(created.0.contains_key(&output_key(&nested)));
        // A retained parent does not own rollback: commit the completed child
        // before deleting its archive source. A later sibling cancellation
        // must not delete the only remaining copy of that child's content.
        created.commit_if_unowned(&retained_finished);
        fs::remove_file(&retained_source).unwrap();
        let cancel = Cancellation::new();
        let gate = Arc::new(Mutex::new((false, None::<Waker>)));
        let (started, entered) = std::sync::mpsc::channel();
        let signal = Arc::clone(&gate);
        let stop = cancel.clone();
        let parent_check = parent.clone();
        let nested_check = nested.clone();
        let stopper = std::thread::spawn(move || {
            entered.recv().unwrap();
            stop.cancel();
            let exists_while_writing = parent_check.join("ordinary.txt").is_file()
                && nested_check.join("partial.txt").is_file();
            let mut signal = signal.lock().unwrap();
            signal.0 = true;
            if let Some(waker) = signal.1.take() {
                waker.wake();
            }
            assert!(exists_while_writing, "rollback ran before the nested writer stopped");
        });
        let nested_writer = nested.clone();
        Scheduler::new().run(1, Origin::Foreground, &cancel, |spawner| {
            Box::pin(async move {
                spawner.spawn(Box::pin(async move {
                    let mut started = Some(started);
                    poll_fn(move |cx| {
                        let mut gate = gate.lock().unwrap();
                        if gate.0 {
                            Poll::Ready(())
                        } else {
                            gate.1 = Some(cx.waker().clone());
                            if let Some(started) = started.take() {
                                started.send(()).unwrap();
                            }
                            Poll::Pending
                        }
                    }).await;
                    fs::write(nested_writer.join("writer-finished.txt"), b"joined").unwrap();
                })).wait().await;
            })
        });
        stopper.join().unwrap();
        assert!(nested.join("writer-finished.txt").is_file());
        let observer = Discards(Mutex::default());
        created.rollback(&observer, &mut outcome).unwrap();
        assert!(!parent.exists());
        assert!(!retry_child.exists());
        assert_eq!(fs::read(sibling.join("kept.txt")).unwrap(), b"committed");
        assert_eq!(fs::read(retained.join("old.txt")).unwrap(), b"continued data");
        assert_eq!(fs::read(retained_segment.join("payload.txt")).unwrap(), b"completed nested data");
        assert!(!retained_source.exists());
        assert!(source.is_file());
        assert_eq!(outcome.archives.iter().filter(|archive| archive.output.is_some()).count(), 3);
        assert!(!observer.0.lock().unwrap().contains(&sibling));
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn request_cancellation_rolls_back_partial_but_not_complete_or_continued_outputs() {
        // Actual worker receipts, task commit, observer boundary and request
        // rollback. Cancel after the task finishes but before the request does;
        // this is the ownership window exposed by a later sibling cancellation.
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let Ok(worker) = crate::core::resources::worker_path(&checkout) else { return; };
        fn zip(damaged: bool) -> Vec<u8> {
            let mut bytes = Vec::new();
            let mut directory = Vec::new();
            for (index, name) in [b"good.txt", b"late.txt"].into_iter().enumerate() {
                let data = b"verified complete member";
                let crc = crc32fast::hash(data) ^ u32::from(damaged && index == 1);
                let offset = bytes.len() as u32;
                bytes.extend(0x04034b50u32.to_le_bytes());
                for value in [20u16, 0, 0, 0, 0] { bytes.extend(value.to_le_bytes()); }
                for value in [crc, data.len() as u32, data.len() as u32] { bytes.extend(value.to_le_bytes()); }
                bytes.extend((name.len() as u16).to_le_bytes()); bytes.extend(0u16.to_le_bytes());
                bytes.extend(name); bytes.extend(data);
                directory.extend(0x02014b50u32.to_le_bytes());
                for value in [20u16, 20, 0, 0, 0, 0] { directory.extend(value.to_le_bytes()); }
                for value in [crc, data.len() as u32, data.len() as u32] { directory.extend(value.to_le_bytes()); }
                for value in [name.len() as u16, 0, 0, 0, 0] { directory.extend(value.to_le_bytes()); }
                directory.extend(0u32.to_le_bytes()); directory.extend(offset.to_le_bytes()); directory.extend(name);
            }
            let offset = bytes.len() as u32;
            let size = directory.len() as u32;
            bytes.extend(directory); bytes.extend(0x06054b50u32.to_le_bytes());
            for value in [0u16, 0, 2, 2] { bytes.extend(value.to_le_bytes()); }
            bytes.extend(size.to_le_bytes()); bytes.extend(offset.to_le_bytes()); bytes.extend(0u16.to_le_bytes());
            bytes
        }
        // Root ID must not collide with the engine-assigned carrier segment
        // IDs: input_finished precedes the physical task commit boundary.
        struct CancelAfterTask { cancel: Cancellation, enabled: bool }
        impl Observer for CancelAfterTask {
            fn notify(&self, event: Event) {
                if self.enabled && matches!(event, Event::Finished { id: 1000, .. }) {
                    self.cancel.cancel();
                }
            }
        }
        for multi in [false, true] {
            for damaged in [false, true] {
                for cancel_after in [false, true] {
                    let first = zip(damaged);
                    let mut bytes = first.clone();
                    if multi { bytes.extend(zip(false)); }
                    let source = crate::test_support::temp_file("partial_request_cancel", &bytes);
                    let output = source.with_extension("output");
                    fs::create_dir(&output).unwrap();
                    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
                    let inputs = if multi {
                        archive_input_slices(&input, &[("zip", 0, Some(first.len() as u64)),
                            ("zip", first.len() as u64, Some(bytes.len() as u64))])
                            .unwrap().0.into_iter().map(Option::unwrap).collect::<Vec<_>>()
                    } else { vec![input] };
                    let engine = Engine::new(worker.clone());
                    let mut request = Request::new(vec![source.clone()], Mode::Extract);
                    request.output_root = Some(output.clone());
                    request.max_depth = 0;
                    let config = Arc::make_mut(&mut request.config);
                    config.extraction.content_requirement = ContentRequirement::AllowPartial;
                    config.post_extract.archive_cleanup_mode = CleanupMode::Keep;
                    config.post_extract.flatten_single_directory = false;
                    let observer = CancelAfterTask { cancel: request.cancel.clone(), enabled: cancel_after };
                    let run = test_run(&engine, &request, &observer);
                    let task = Task { primary: None, inputs: inputs.iter().cloned().map(|input|
                        LogicalInput { input, password_probe: None, password: None, failure: None }).collect(),
                        owned_paths: vec![source.to_string_lossy().into_owned()],
                        source: DiscoverySource::Embedded, retry: None, scope: None };
                    let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
                        let run = Arc::clone(&run);
                        Box::pin(async move {
                        let result = run.execute_task(run.register_task(task), 1000, 1, None, spawner).await;
                        let before = result.as_ref().unwrap();
                        assert_eq!(before.archives.len(), if multi { 2 } else { 1 });
                        assert_eq!(before.archives[0].partial, damaged, "multi={multi} cancel={cancel_after} failure={:?}", before.archives[0].failure);
                        assert!(before.archives[0].output.as_ref().unwrap().join("good.txt").is_file());
                        run.finish(result).await
                    })}).unwrap();
                    assert!(source.is_file());
                    for archive in &outcome.archives {
                        assert_eq!(archive.output.is_some(), !cancel_after || !damaged,
                            "multi={multi} damaged={damaged} cancel={cancel_after} failure={:?}", archive.failure);
                    }
                    if damaged && !cancel_after {
                        // An existing continuation is not newly owned by the
                        // cancelled request and must never be rolled back.
                        let mut continued = request.clone();
                        continued.cancel = Cancellation::new();
                        continued.checkpoints = outcome.checkpoints.into_vec();
                        let observer = CancelAfterTask { cancel: continued.cancel.clone(), enabled: true };
                        let mut run = test_run(&engine, &continued, &observer);
                        for (index, checkpoint) in continued.checkpoints.iter().enumerate() {
                            Arc::get_mut(&mut run).unwrap().checkpoints.entry(Arc::from(path_key(&checkpoint.carrier().to_string_lossy())))
                                .or_default().insert(checkpoint.key(), index);
                        }
                        let task = Task { primary: None, inputs: inputs.into_iter().map(|input|
                            LogicalInput { input, password_probe: None, password: None, failure: None }).collect(),
                            owned_paths: vec![source.to_string_lossy().into_owned()],
                            source: DiscoverySource::Embedded, retry: None, scope: None };
                        let retained = Scheduler::new().run(2, Origin::Foreground, &continued.cancel, |spawner| {
                        let run = Arc::clone(&run);
                        Box::pin(async move {
                            let result = run.execute_task(run.register_task(task), 1000, 1, None, spawner).await;
                            run.finish(result).await
                        })}).unwrap();
                        assert!(retained.archives.iter().all(|archive| archive.retained
                            && archive.output.as_ref().unwrap().join("good.txt").is_file()));
                    }
                    drop(run);
                    drop(engine);
                    release_reader_resources_under_roots(vec![output.to_string_lossy().into_owned(), source.to_string_lossy().into_owned()]).unwrap();
                    fs::remove_dir_all(output).unwrap();
                    fs::remove_file(source).unwrap();
                }
            }
        }
    }

    #[test]
    fn retained_parent_does_not_publish_new_child_before_its_commit_boundary() {
        struct Roots(std::sync::atomic::AtomicUsize);
        impl Observer for Roots {
            fn notify(&self, _: Event) {}
            async fn root_finished(&self, _: TaskId, _: &Path, _: PublicOutcome, _: u64) -> io::Result<PublicOutcome> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(PublicOutcome::default())
            }
        }
        // Exercise the production root handoff and filesystem rollback at the
        // post-worker/pre-commit boundary. Retained parents are not rollback
        // owners, so a new child must independently prove durable completion.
        for partial in [false, true] {
            let source = crate::test_support::temp_file("retained_root_cancel", b"archive");
            let parent = source.with_extension("retained");
            let child = parent.join("child");
            fs::create_dir_all(&child).unwrap();
            fs::write(parent.join("old.txt"), b"old retained data").unwrap();
            fs::write(child.join("new.txt"), b"new extraction").unwrap();
            let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(Vec::new(), Mode::Extract);
            let observer = Roots(std::sync::atomic::AtomicUsize::new(0));
            let run = test_run(&engine, &request, &observer);
            let mut outer = receipt(&input, DiscoverySource::Direct, 1);
            outer.retained = true;
            outer.output = Some(parent.clone());
            let mut nested = receipt(&input, DiscoverySource::Direct, 2);
            nested.output = Some(child.clone());
            nested.partial = partial;
            if partial { nested.failure = Some(Failure::new(FailureKind::Damaged, "accepted files")); }
            run.created_outputs.lock().unwrap().register(&child, &nested);
            let mut outcome = Outcome::default();
            outcome.archives = vec![outer, nested].into();
            outcome.uncommitted = true; // cancellation preceded the child's durable commit
            request.cancel.cancel();
            let mut outcome = Scheduler::new().run(1, Origin::Foreground, &Cancellation::new(), |_| {
                Box::pin(run.finish_root(1, &source, Ok(outcome)))
            }).unwrap();
            assert_eq!(observer.0.load(std::sync::atomic::Ordering::Relaxed), 0);
            run.created_outputs.lock().unwrap().rollback(&observer, &mut outcome).unwrap();
            assert!(parent.join("old.txt").is_file());
            assert!(!child.exists());
            assert_eq!(outcome.archives[1].failure.as_ref().unwrap().kind, FailureKind::Cancelled);
            assert!(!outcome.settled());
            fs::remove_dir_all(parent).unwrap();
            fs::remove_file(source).unwrap();
        }
    }

    #[test]
    fn cancelled_recursive_batch_returns_incomplete_outcome_not_parent_unwind() {
        struct CancelOnQueue(Cancellation);
        impl Observer for CancelOnQueue {
            fn notify(&self, event: Event) {
                if matches!(event, Event::Queued { .. }) {
                    self.0.cancel();
                }
            }
        }
        let engine = Engine::new(PathBuf::from("unused-worker"));
        let request = Request::new(Vec::new(), Mode::Extract);
        let observer = CancelOnQueue(request.cancel.clone());
        let run = test_run(&engine, &request, &observer);
        let input = ArchiveInput::file("parent/child.zip".into(), "zip".into(), "child".into());
        let batch = Discovered {
            tasks: vec![Task {
                primary: None,
                inputs: vec![LogicalInput { password_probe: None, input, password: None, failure: None }],
                owned_paths: Vec::new(),
                source: DiscoverySource::Direct,
                retry: None,
                scope: None,
            }],
            errors: Vec::new(),
            scan_errors: DirectoryReadErrors::report(),
            blocked_paths: HashSet::new(),
        };
        let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
            Box::pin(run.execute_batch(batch, 2, None, Some(1), spawner, None))
        }).expect("cancellation must not bypass the parent's output commit");
        assert_eq!(outcome.archives.len(), 1);
        assert_eq!(outcome.archives[0].failure.as_ref().unwrap().kind, FailureKind::Cancelled);
        assert!(!outcome.subtree_complete());
        assert!(!is_cancellation(&io::Error::other("journal failure")));
        // A fully undispatched recursive batch still carries incompleteness;
        // an empty result cannot authorize a parent/carrier commit.
        let input = ArchiveInput::file("parent/unstarted.zip".into(), "zip".into(), "unstarted".into());
        let batch = Discovered {
            tasks: vec![Task {
                primary: None,
                inputs: vec![LogicalInput { password_probe: None, input, password: None, failure: None }],
                owned_paths: Vec::new(), source: DiscoverySource::Direct, retry: None, scope: None,
            }],
            errors: Vec::new(), scan_errors: DirectoryReadErrors::report(), blocked_paths: HashSet::new(),
        };
        let outcome = Scheduler::new().run(2, Origin::Foreground, &request.cancel, |spawner| {
            Box::pin(run.execute_batch(batch, 2, None, Some(1), spawner, None))
        }).unwrap();
        assert!(outcome.archives.is_empty());
        assert!(outcome.uncommitted);
        assert!(!outcome.subtree_complete());
    }

    #[test]
    fn numbered_outputs_share_unicode_decimal_syntax_with_recursion() {
        for name in ["archive(１)", "archive(١)", "archive(𝟙)"] {
            let path = Path::new(name);
            assert_eq!(numbered(path, 1), PathBuf::from("archive(2)"));
            assert!(output_candidate(path, Path::new("archive(2)")));
        }
        for name in ["archive(²)", "archive(+1)", "archive(1_0)"] {
            assert_eq!(numbered(Path::new(name), 1), PathBuf::from(format!("{name}(1)")));
        }
    }

    #[test]
    fn flatten_work_avoids_unmaterialized_output_claim_and_releases_its_slot() {
        struct Work(Mutex<Option<PathBuf>>);
        impl Observer for Work {
            fn notify(&self, _: Event) {}
            fn before_flatten(&self, _: &Path, work: &Path, _: &Path) -> io::Result<()> {
                *self.0.lock().unwrap() = Some(work.to_owned());
                Ok(())
            }
        }
        let source = crate::test_support::temp_file("flatten_reserved", b"archive");
        let output = source.with_extension("output");
        fs::create_dir_all(output.join("wrapper")).unwrap();
        fs::write(output.join("wrapper/payload.txt"), b"payload").unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "sample".into());
        let mut archive = receipt(&input, DiscoverySource::Direct, 1);
        archive.output = Some(output.clone());
        let mut work = output.as_os_str().to_os_string();
        work.push(".__sunpack_flatten_work__");
        let preferred = PathBuf::from(work);
        let names = OutputReservationGuard { registry: Arc::default(), owner: 1 };
        let reserved = OutputNames::plan(&names.registry, preferred.clone(), &archive.path, 2, None).unwrap().unwrap();
        assert_eq!(reserved, preferred);
        assert!(!reserved.exists()); // Peer has claimed but not created its output.
        let observer = Work(Mutex::default());
        let mut outcome = Outcome::default();
        flatten_result(&observer, 1, &mut archive, &mut outcome, None, &names).unwrap();
        let staging = observer.0.lock().unwrap().clone().unwrap();
        assert_ne!(staging, reserved);
        assert!(outcome.cleanup_results.is_empty());
        assert_eq!(fs::read(output.join("payload.txt")).unwrap(), b"payload");
        let registry = names.registry.lock().unwrap();
        assert!(registry.claimed.contains_key(&output_key(&reserved)));
        assert!(!registry.claimed.contains_key(&output_key(&staging)));
        drop(registry);
        fs::remove_dir_all(output).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn flatten_rebases_rollback_receipts_when_root_spelling_is_unchanged() {
        struct Discards(Mutex<Vec<PathBuf>>);
        impl Observer for Discards {
            fn notify(&self, _: Event) {}
            fn discard_output(&self, _: &Path, _: &[PathBuf], output: &Path) -> io::Result<()> {
                self.0.lock().unwrap().push(output.to_owned());
                Ok(())
            }
        }
        let source = crate::test_support::temp_file("flatten_cancel_receipts", b"input");
        let output = source.with_extension("output");
        let leaf = output.join("wrapper");
        let child = leaf.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(leaf.join("ordinary.txt"), b"keep").unwrap();
        fs::write(child.join("payload.txt"), b"child").unwrap();
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "parent".into());
        let mut archive = receipt(&input, DiscoverySource::Direct, 1);
        archive.output = Some(output.clone());
        let mut nested = receipt(&input, DiscoverySource::Direct, 2);
        nested.output = Some(child.clone());
        let created = Mutex::new(CreatedOutputs::default());
        created.lock().unwrap().register(&output, &archive);
        let mut leaf_archive = receipt(&input, DiscoverySource::Direct, 2);
        leaf_archive.path = output.join("inner.zip");
        created.lock().unwrap().register(&leaf, &leaf_archive);
        created.lock().unwrap().register(&child, &nested);
        let mut children = Outcome::default();
        children.archives.push(nested);
        let observer = Discards(Mutex::default());
        flatten_result(&observer, 1, &mut archive, &mut children, Some(&created), &OutputReservationGuard { registry: Arc::default(), owner: 1 }).unwrap();
        assert_eq!(archive.output.as_ref(), Some(&output));
        assert_eq!(created.lock().unwrap().0.get(&output_key(&output)).unwrap().archive, source);
        let published_child = output.join("child");
        assert!(published_child.join("payload.txt").is_file());
        created.lock().unwrap().rollback(&observer, &mut children).unwrap();
        let discarded = observer.0.lock().unwrap();
        assert!(discarded.contains(&published_child));
        assert!(!discarded.contains(&child));
        assert!(!output.exists());
        fs::remove_file(source).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn flatten_failure_keeps_extraction_successful_and_reports_output() {
        use std::os::windows::fs::OpenOptionsExt;
        let source = crate::test_support::temp_file("flatten_warning", b"input");
        let output = source.with_extension("output");
        let wrapper = output.join("wrapper");
        fs::create_dir_all(&wrapper).unwrap();
        fs::write(wrapper.join("payload.txt"), b"payload").unwrap();
        let input = ArchiveInput::file(
            source.to_string_lossy().into_owned(),
            "zip".into(),
            "sample".into(),
        );
        let mut archive = receipt(&input, DiscoverySource::Direct, 1);
        archive.output = Some(output.clone());
        let mut outcome = Outcome::default();

        // FILE_LIST_DIRECTORY participates in delete sharing; an attributes-only
        // handle does not block rename on Windows. Hold the real root rename
        // failure, distinct from ordinary source-cleanup warnings.
        let held = fs::OpenOptions::new().access_mode(0x1).share_mode(3)
            .custom_flags(0x0200_0000).open(&output).unwrap();
        let result = flatten_result(&|_: Event| {}, 1, &mut archive, &mut outcome, None, &OutputReservationGuard { registry: Arc::default(), owner: 1 });
        let payload = fs::read(wrapper.join("payload.txt"));
        drop(held);
        fs::remove_dir_all(&output).unwrap();
        fs::remove_file(&source).unwrap();

        result.unwrap();
        outcome.archives.push(archive);
        assert_eq!(outcome.succeeded(), 1);
        assert_eq!(outcome.failed(), 0);
        assert!(!outcome.subtree_complete(), "ancestors must not flatten an unsettled child");
        let mut source_warning = Outcome::default();
        record_cleanup(&mut source_warning, &source, "delete", Err(io::ErrorKind::PermissionDenied.into()));
        assert!(source_warning.subtree_complete(), "source cleanup alone does not block ancestors");
        assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
        assert_eq!(payload.unwrap(), b"payload");
        assert!(
            outcome.cleanup_results.len() == 1 && matches!(outcome.cleanup_results.iter().next(), Some(CleanupResult { path, mode: "flatten", status: CleanupStatus::Failed, .. }) if path == &output)
        );
    }

    #[test]
    fn completed_extract_compacts_segments_but_keeps_nested_summary_and_retry_receipts() {
        struct DetailedPublication(std::sync::atomic::AtomicBool);
        impl Observer for DetailedPublication {
            fn notify(&self, _: Event) {}
            async fn root_finished(&self, _: TaskId, _: &Path, outcome: PublicOutcome, _: u64) -> io::Result<PublicOutcome> {
                assert_eq!(outcome.archives.len(), 3);
                assert_eq!(outcome.checkpoints.len(), 3);
                assert!(outcome.archives.iter().all(|entry| !entry.source_paths.is_empty() && entry.password.is_some()));
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(outcome)
            }
        }
        let source = crate::test_support::temp_file("completed_extract_summary", b"source");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "archive".into());
        let generations = HashMap::from([
            (path_key(&source.to_string_lossy()), capture_file_generation(&source).unwrap()),
        ]);
        let output = source.with_extension("output");
        // None: successful physical carrier. Failure/partial: receipts must
        // remain available for CLI retry and durable observer publication.
        for (mode, failure_kind, partial, uncommitted) in [
            (Mode::Extract, None, false, false),
            (Mode::Extract, Some(FailureKind::WrongPassword), false, false),
            (Mode::Extract, Some(FailureKind::Damaged), true, false),
            (Mode::Extract, None, false, true),
            (Mode::Scan, None, false, false),
        ] {
            let mut outcome = Outcome::default();
            for index in 0..3 {
                let mut archive = receipt(&input, DiscoverySource::Embedded, if index == 2 { 2 } else { 1 });
                if index == 2 { archive.path = output.join("nested.zip"); }
                archive.offset = index * 100;
                archive.output = Some(output.join(format!("segment{index}")));
                archive.files = 1;
                archive.bytes = 10;
                archive.password = Some("successful-password".into());
                if index == 1 {
                    archive.partial = partial;
                    archive.failure = failure_kind.map(|kind| {
                        let mut failure = Failure::new(kind, "worker diagnostic");
                        failure.evidence = worker_evidence(&json!({"failure_stage": "item_extract"}), None, None);
                        failure
                    });
                }
                outcome.checkpoints.push(InputCheckpoint::create(&source, Arc::new(input.clone()), &archive, &generations, None).unwrap());
                outcome.archives.push(archive);
            }
            outcome.uncommitted = uncommitted;
            let before = serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap();
            let engine = Engine::new(PathBuf::from("unused-worker"));
            let request = Request::new(Vec::new(), mode);
            let observer = DetailedPublication(std::sync::atomic::AtomicBool::new(false));
            let run = test_run(&engine, &request, &observer);
            let outcome = Scheduler::new().run(1, request.origin, &request.cancel, |_| {
                Box::pin(run.finish_root(1, &source, Ok(outcome)))
            }).unwrap();
            assert_eq!(observer.0.load(std::sync::atomic::Ordering::SeqCst), !uncommitted);
            if uncommitted || mode == Mode::Scan {
                assert_eq!(outcome.archives.len(), 3);
                assert!(outcome.archives.iter().all(|entry| entry.password.is_some()));
                assert_eq!(serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap(), before);
            } else if failure_kind.is_some() {
                assert_eq!(outcome.archives.len(), 3);
                assert_eq!(serde_json::to_value(outcome.checkpoints.iter().collect::<Vec<_>>()).unwrap(), before);
                let failure = outcome.archives[1].failure.as_ref().unwrap();
                assert_eq!(Some(failure.kind), failure_kind);
                assert_eq!(failure.message, "worker diagnostic");
                assert_eq!(failure.evidence.as_ref().unwrap().stage.as_deref(), Some("item_extract"));
                assert_eq!(outcome.archives[1].partial, partial);
                assert!(outcome.archives.iter().all(|entry| entry.source_paths.is_empty() && entry.password.is_none()));
            } else {
                assert!(outcome.checkpoints.is_empty());
                assert_eq!(outcome.checkpoints.capacity(), 0);
                assert_eq!(outcome.archives.len(), 2);
                assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
                assert_eq!((outcome.archives[0].files, outcome.archives[0].bytes), (2, 20));
                assert_eq!(outcome.archives[1].depth, 2);
                assert_eq!(outcome.archives[1].path, output.join("nested.zip"));
                assert_eq!(outcome.succeeded(), 2);
                assert_eq!(outcome.failed(), 0);
                assert!(outcome.archives.iter().all(|entry| entry.source_paths.is_empty() && entry.password.is_none()));
            }
        }
        fs::remove_file(source).unwrap();
    }
}
