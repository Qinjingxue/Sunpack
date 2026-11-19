use super::results::RunOutcome as Outcome;
use super::checkpoint::{CheckpointKey, InputCheckpoint, InputRecovery, GeneratedSource, ReportState};
use super::discovery::{self, Discovered, LogicalInput, Task};
use super::passwords::{CandidateSet, RecentPasswords};
use super::scheduling::{boxed_phase, stage, Scheduler, Spawner};
use super::shell_updates::{ShellNotifier, ShellUpdates};
use super::worker::{self, Process};
use super::{
    ArchiveResult, BusyConflict, Cancellation, CleanupResult, CleanupStatus, DiscoverySource,
    Event, Failure, FailureEvidence, FailureKind, FailureRead, InputError, InputErrorKind, Mode,
    Observer, Origin, Outcome as PublicOutcome, Request, ScanTaskFailure, Segment, TaskId,
};
use crate::collections::{CacheOrder, SmallOrderedSet};
use crate::core::config::{CleanupMode, ContentRequirement, ProcessMode, Recursion, WorkerConfig};
use crate::io::archive_state::{
    ArchiveInput, OpenMode, VolumeCompleteness, VolumeSelection,
};
use crate::io::cancellation::is_cancellation;
use crate::io::directory_errors::DirectoryReadErrors;
use crate::io::reader::{
    capture_directory_identity, capture_file_generation, PhysicalFileGeneration,
};
#[cfg(test)]
use crate::io::reader::release_reader_resources_under_roots;
use crate::io::resource_lifecycle::Promotion;
use crate::path_keys::{descendant_key_range, normalize_windows_extended_prefix, path_key};
use crate::postprocess::{
    discover_flatten_leaf, flatten_single_branch_directories, remove_owned_file, remove_owned_tree,
    FlattenLeaf, FlattenOutcome,
};
use crate::scan::directory::{
    scan_output_stats, NativeDirectoryScanOptions, NativeOutputInventory,
};
use crate::scan::worker_event::WorkerFrame;
use serde::Deserialize;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
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
    recent_passwords: RecentPasswords,
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
            recent_passwords: RecentPasswords::default(),
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
        let cancel = Cancellation::default();
        let id = self.next_id();
        // The scoped scheduler joins its tasks before rethrowing. Return that
        // failure to Watch so it can drain active requests and retain recovery intent.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.scheduler.get_or_init(Scheduler::new).run(id, origin, &cancel, |_| Box::pin(async {
                stage(name, &cancel).await?;
                Ok(work())
            }))
        }))
        .unwrap_or_else(|_| Err(io::Error::other(format!("Watch stage {name} panicked"))))
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
                    match stage("report", &Cancellation::default()).await {
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
            &self.recent_passwords,
            request.password_scope.as_deref(),
        );
        let unfiltered = || {
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let options = OnceLock::new();
        let deep_options = request.deep.then(unfiltered).transpose()?;
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
        let generated_sources = request
            .generated_sources
            .iter().enumerate()
            .map(|(index, source)| (path_key(&source.path().to_string_lossy()), index))
            .collect();
        let cleanup_boundaries = cleanup_boundaries(&request);
        Ok(Arc::new(Run {
            engine: self.clone(),
            request: Arc::new(request),
            resolve_aliases,
            candidates,
            options,
            deep_options,
            observer: ObserverRef::Owned(observer, std::marker::PhantomData),
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: Arc::clone(&self.output_names), owner: request_id },
            created_outputs: Mutex::default(),
            output_base,
            checkpoints,
            checkpoint_anchors: OnceLock::new(),
            generated_sources,
            cleanup_boundaries,
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
            cleanup_tasks: Mutex::default(),
            cleanup_refs: Arc::default(),
        }))
    }

    /// Discover without extraction, then visit plans through the same bounded
    /// consumer pool as extraction. IO/hash work never blocks the Watch driver.
    pub(crate) fn submit_discovery<T: Send + 'static>(
        &self, request: Request,
        visit: impl Fn(&Path, &[&ArchiveInput]) -> io::Result<()> + Send + Sync + 'static,
        complete: impl FnOnce(io::Result<()>) -> T + Send + 'static,
    ) -> super::scheduling::Join<T> {
        let id = self.next_id();
        let scheduler = self.scheduler.get_or_init(Scheduler::new);
        let prepared = match scheduler.prepare_submit() {
            Ok(prepared) => prepared,
            Err(error) => return super::scheduling::Join::ready(complete(Err(error))),
        };
        let engine = self.clone();
        prepared.submit(id, request.origin, &request.cancel.clone(), move |spawner| {
            Box::pin(async move {
                let result = async {
                    stage("discovery", &request.cancel).await?;
                    let candidates = CandidateSet::new(Arc::clone(&request.passwords),
                        request.password_snapshot.clone(), &engine.recent_passwords,
                        request.password_scope.as_deref());
                    let options = if request.deep {
                        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())?
                    } else { discovery::scan_options(&request.config)? };
                    // The dedup visitor consumes projected inputs only. Drop the
                    // discovery inventories as each table finishes projecting.
                    let mut discovered = discovery::discover(&request, &options, &candidates, false)?;
                    drop(candidates);
                    discovered.tasks.retain(|task|
                        !task.inputs.is_empty() && task.inputs.iter().all(|input| input.failure.is_none()));
                    let expected = discovered.tasks.len();
                    let cancel = request.cancel.clone();
                    let visit = Arc::new(visit);
                    let results = spawner.bounded_map(discovered.tasks.into_iter(), move |task| {
                        let cancel = cancel.clone();
                        let visit = Arc::clone(&visit);
                        Box::pin(async move {
                            stage("watch_dedup", &cancel).await?;
                            let path = Path::new(&task.entry().entry_path);
                            if let [logical] = task.inputs.as_slice() {
                                visit(path, &[&logical.input])
                            } else {
                                let inputs: Vec<_> = task.inputs.iter().map(|input| &input.input).collect();
                                visit(path, &inputs)
                            }
                        })
                    }).await;
                    request.cancel.check_io()?;
                    debug_assert_eq!(expected, results.len());
                    for result in results { result?; }
                    if let Some((operation, path, detail)) = discovered.scan_errors.into_messages().into_iter().next() {
                        return Err(io::Error::other(format!("{operation}: {path}: {detail}")));
                    }
                    Ok(())
                }.await;
                complete(result)
            })
        })
    }

    pub(crate) fn find_watch_volume(&self, request: &Request, options: &NativeDirectoryScanOptions, retry_incomplete: bool) -> io::Result<Option<Arc<super::PreparedVolume>>> {
        let candidates = CandidateSet::new(Arc::clone(&request.passwords), request.password_snapshot.clone(),
            &self.recent_passwords, request.password_scope.as_deref());
        discovery::find_watch_volume(request, options, &candidates, retry_incomplete)
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
                Ok(thread_capacity) => {
                    self.scheduler.get_or_init(Scheduler::new)
                        .configure_capacity(thread_capacity);
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

    pub(crate) fn clear_idle_caches(&self) {
        crate::relations::clear_regex_caches();
        self.output_names.lock().unwrap().clear_history();
        self.recent_passwords.clear();
    }

    pub(crate) fn recent_passwords(&self) -> Vec<Arc<str>> {
        self.recent_passwords.recent()
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
    observer: ObserverRef<'a, O>,
    recursion: RecursivePrompts,
    output_names: OutputReservationGuard,
    created_outputs: Mutex<CreatedOutputs>,
    output_base: Option<PathBuf>,
    checkpoints: RecoveryCheckpointIndex,
    checkpoint_anchors: OnceLock<RecoveryAnchorIndex>,
    generated_sources: HashMap<String, usize>,
    cleanup_boundaries: HashSet<String>,
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
    fn new(registry: &Arc<Mutex<CleanupRefs>>, paths: &[String]) -> Self {
        let mut owner = Self { registry: Arc::clone(registry), paths: HashSet::new() };
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
                let remove = !entry.1;
                refs.paths.remove(&key);
                if remove { allowed.insert(key); }
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

struct RecursiveScope {
    password: Option<Arc<Path>>,
}

enum RetryOutput<'a> {
    Recreate(&'a Path),
    Existing(&'a Path),
}

#[derive(Default)]
struct CleanupTasks {
    next_id: u64,
    active: HashMap<u64, PendingCleanup>,
    by_path: BTreeMap<Arc<str>, SmallOrderedSet<u64>>,
    failures: BTreeMap<String, CleanupResult>,
}

impl CleanupTasks {
    fn register(&mut self, id: u64, paths: Vec<Arc<str>>, task: super::scheduling::Join<Vec<CleanupResult>>) {
        for path in &paths {
            self.by_path.entry(Arc::clone(path)).and_modify(|owners| owners.insert(id))
                .or_insert(SmallOrderedSet::One(id));
        }
        self.active.insert(id, PendingCleanup { paths, task });
    }

    fn remove(&mut self, id: u64) -> Option<PendingCleanup> {
        let pending = self.active.remove(&id)?;
        for path in &pending.paths {
            if self.by_path.get_mut(path).is_some_and(|owners| owners.remove(&id)) {
                self.by_path.remove(path);
            }
        }
        if self.active.capacity() > 256 {
            crate::collections::trim_map(&mut self.active);
        }
        Some(pending)
    }

    fn take_pending(&mut self, root: Option<&str>) -> Vec<super::scheduling::Join<Vec<CleanupResult>>> {
        let Some(root) = root else {
            self.by_path.clear();
            return std::mem::take(&mut self.active).into_values().map(|pending| pending.task).collect();
        };
        let range = descendant_key_range(root);
        let ids: HashSet<_> = self.by_path.get(root).into_iter().chain(self.by_path.range::<str, _>((
            std::ops::Bound::Included(range.start.as_str()), std::ops::Bound::Excluded(range.end.as_str()),
        )).map(|(_, owners)| owners)).flat_map(SmallOrderedSet::iter).copied().collect();
        ids.into_iter().filter_map(|id| self.remove(id).map(|pending| pending.task)).collect()
    }

    fn retire(&mut self, id: u64, failures: Vec<CleanupResult>) -> Vec<CleanupResult> {
        if self.remove(id).is_some() {
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

    fn take_failures(&mut self, key: Option<&str>) -> Vec<CleanupResult> {
        let Some(key) = key else {
            return std::mem::take(&mut self.failures).into_values().collect();
        };
        self.failures.remove(key).into_iter().chain(
            self.failures.extract_if(descendant_key_range(key), |_, _| true).map(|(_, failure)| failure),
        ).collect()
    }
}

struct PendingCleanup {
    paths: Vec<Arc<str>>,
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
                decision.complete(prompt(depth, pending).await);
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
    owners: HashMap<u64, HashSet<String>>,
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
            self.owners.entry(owner).or_default().insert(key.clone());
        }
        self.claimed.insert(key, OutputClaim {
            owner, source,
        });
    }

    fn release_path(&mut self, key: &str, owner: u64) {
        if self.claimed.get(key).is_none_or(|claim| claim.owner != owner) { return; }
        if let Some(paths) = self.owners.get_mut(&owner) {
            paths.remove(key);
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
        self.claimed.range::<str, _>((
            std::ops::Bound::Included(prefix.as_str()), std::ops::Bound::Unbounded,
        )).next()
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
            let (path, key, slot, suffix) = {
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
                (path, key, slot, suffix)
            };
            // A query must not reserve a tree that may already exist on disk:
            // peers may legitimately create children there. Only the numbered
            // index is taken while IO is in flight; publish after revalidation.
            let checked = exists(&path);
            let mut names = registry.lock().unwrap();
            let occupied = names.has_under(&key);
            let candidate_parent = key.rsplit_once('\\').unwrap().0;
            let conflicting = names.conflicting_ancestor(candidate_parent, owner, input.as_deref()).is_some();
            if let Some((family, index)) = &slot {
                // Another request may have evicted this bounded history while
                // we were on the network. Claims, not history, prove exclusivity.
                if names.indices.peek_mut(family).is_some() {
                    if occupied || matches!(checked, Ok(false)) && !conflicting {
                        names.observe_slot(&key, family, *index);
                    } else if !matches!(checked, Ok(true)) {
                        names.indices.peek_mut(family).unwrap().release(*index);
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
                Ok(true) => occupied_preferred = Some(slot.map_or(key, |(family, _)| family.to_string())),
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
    fn register(registry: &Mutex<Self>, path: &Path, result: &ArchiveResult) {
        let key = output_key(path);
        let output = CreatedOutput {
            path: path.to_owned(),
            archive: result.path.clone(),
            sources: result.source_paths.clone(),
        };
        registry.lock().unwrap().0.insert(key, output);
    }

    fn commit_if_unowned(registry: &Mutex<Self>, root: &Path) {
        let key = output_key(root);
        let mut outputs = registry.lock().unwrap();
        if !crate::path_keys::path_ancestors(&key).skip(1)
            .any(|ancestor| outputs.0.contains_key(ancestor))
        {
            outputs.commit_key(&key);
        }
    }

    fn commit(registry: &Mutex<Self>, root: &Path) {
        let key = output_key(root);
        registry.lock().unwrap().commit_key(&key);
    }

    fn commit_key(&mut self, key: &str) {
        self.0.remove(key);
        self.0.extract_if(descendant_key_range(key), |_, _| true).for_each(drop);
    }

    fn relocate_flatten(&mut self, root: &Path, source: &Path, destination: &Path) {
        let key = output_key(root);
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
                if !super::relocate_flatten_output(&mut output.path, root, source, destination) {
                    self.0.insert(key, output);
                    continue;
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

enum ExecutedTask<'a> {
    Complete(Outcome),
    Finalize(super::scheduling::Task<'a, io::Result<Outcome>>),
}

enum BatchTaskResult {
    Completed(Outcome),
    Cancelled(TaskId, ArchiveResult),
    Failed(io::Error),
}

impl<'run, O: Observer> Run<'run, O> {
    async fn execute_request(self: &Arc<Self>, spawner: Spawner<'run>) -> io::Result<PublicOutcome> {
        let _cancellation = if self.request.config.recursive_extract == Recursion::Prompt {
            let decisions = Arc::clone(&self.recursion.decisions);
            self.request.cancel.subscribe(move || {
                let decisions: Vec<_> = decisions.lock().unwrap().values().cloned().collect();
                for decision in decisions { decision.complete(false); }
            })
        } else { None };
        self.request.cancel.check_io()?;
        let discovered = discovery::discover(&self.request, self.options_at(1)?, &self.candidates, true)?;
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
            || !self.request.checkpoints.is_empty() || !self.request.generated_sources.is_empty()
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
        }
        // Scheduler completion joins every writer, even on cancellation. Never
        // roll back a tree while a native job or recursive branch can write it.
        let rollback = async {
            if self.request.cancel.cancelled() {
                stage("cancel_cleanup", &Cancellation::default()).await?;
                let mut discarded = Outcome::default();
                self.created_outputs.lock().unwrap().rollback(
                    &*self.observer, executed.as_mut().unwrap_or(&mut discarded),
                )?;
            }
            Ok::<_, io::Error>(())
        }.await;
        let publication = self.observer.outputs_finished(|| {
            self.output_names.registry.lock().unwrap().owners
                .get(&self.output_names.owner).into_iter().flatten().cloned().collect()
        });
        rollback?;
        publication?;
        let mut outcome = executed?;
        outcome.errors.extend(
            std::mem::replace(&mut *self.scan_errors.lock().unwrap(), DirectoryReadErrors::report())
                .into_messages()
                .into_iter()
                .map(|(operation, path, detail)| InputError {
                    path: PathBuf::from(path),
                    message: detail,
                    kind: InputErrorKind::FilesystemScan,
                    scan_operation: Some(operation),
                    failure: None,
                }),
        );
        Ok(outcome)
    }

    async fn drain_cleanup(&self, root: Option<&Path>, outcome: &mut Outcome) {
        let root_key = root.map(namespace_key);
        let (mut failures, pending) = {
            let mut tasks = self.cleanup_tasks.lock().unwrap();
            (tasks.take_failures(root_key.as_deref()), tasks.take_pending(root_key.as_deref()))
        };
        for pending in pending {
            let mut results = pending.wait().await;
            if let Some(root_key) = root_key.as_ref().filter(|_| !results.is_empty()) {
                let descendants = descendant_key_range(root_key);
                let mut tasks = self.cleanup_tasks.lock().unwrap();
                for failure in results.extract_if(.., |failure| {
                    let key = namespace_key(&failure.path);
                    key != *root_key && !descendants.contains(&key)
                }) {
                    tasks.record_failure(failure);
                }
            }
            failures.append(&mut results);
        }
        outcome.cleanup_results.extend(failures);
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
        // Blocked paths are only used while projecting discovery candidates.
        drop(batch.blocked_paths);
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
        let mut sources = (self.request.mode == Mode::Extract).then(|| {
            batch.tasks.iter().map(|task| CleanupOwner::new(&self.cleanup_refs, &task.owned_paths))
                .collect::<Vec<_>>().into_iter()
        });
        let tasks = batch.tasks.into_iter().map(move |task| {
            let sources = sources.as_mut().and_then(Iterator::next);
            (task, sources)
        });
        let executed = spawner.bounded_map(tasks, move |(task, sources)| {
            let keys = (!resolved_paths.is_empty()).then(|| source_lease_keys(&task, &resolved_paths));
            let requested = requested.as_ref().filter(|_| task.owned_paths.len() > 1).cloned();
            let root_errors = has_root_errors
                .then(|| root_errors.lock().unwrap().remove(&task.entry().entry_path))
                .flatten();
            let this = Arc::clone(&owner);
            let children = children.clone();
            let scope = inherited_scope.clone();
            Box::pin(async move {
                let entry = task.entry();
                let extent = entry.physical_extents().next();
                let path = PathBuf::from(&entry.entry_path);
                // Keep only the coordinates needed to report a cancelled task.
                let format = entry.format_hint.clone();
                let encrypted = entry.analysis.password_required.then_some(true);
                let offset = extent.map_or(0, |extent| extent.start);
                let end_offset = extent.and_then(|extent| extent.end);
                let discovery_source = task.source;
                let ready = if this.observer.worker_updates() == super::WorkerUpdates::All {
                    stage("report", &Cancellation::default()).await
                } else {
                    Ok(())
                };
                let id = this.queue_task(task.entry(), parent_id, || None);
                let mut result = match ready {
                    Ok(()) => this.execute_task((task, sources, keys, requested), id, depth, scope, children).await,
                    Err(error) => Err(error),
                };
                let unowned_errors = match (&mut result, root_errors) {
                    (Ok(outcome), Some(errors)) => {
                        outcome.errors.extend(errors);
                        None
                    }
                    (_, errors) => errors,
                };
                let result = if depth == 1 && (this.request.mode == Mode::Extract || O::PUBLISHES_ROOTS) {
                    let publication = boxed_phase(|| this.finish_root(id, &path, result));
                    publication.await
                } else {
                    result
                };
                let result = match result {
                    Ok(outcome) => BatchTaskResult::Completed(outcome),
                    Err(error) if is_cancellation(&error) => BatchTaskResult::Cancelled(
                        id, ArchiveResult {
                            path, format, encrypted, depth, offset, end_offset, discovery_source,
                            failure: Some(Failure::new(FailureKind::Cancelled, "Operation interrupted")),
                            ..ArchiveResult::default()
                        },
                    ),
                    Err(error) => BatchTaskResult::Failed(error),
                };
                (result, unowned_errors)
            })
        }).await;
        stage("report", &Cancellation::default()).await?;
        outcome.uncommitted |= executed.len() != task_count;
        let mut first_error = None;
        for (branch, unowned_errors) in executed {
            if let Some(errors) = unowned_errors {
                outcome.errors.extend(errors);
            }
            let mut branch = match branch {
                BatchTaskResult::Completed(branch) => branch,
                BatchTaskResult::Cancelled(id, cancelled) => {
                    self.notify(|| Event::Finished {
                        id,
                        result: super::TaskCompletion::from_result(&cancelled),
                    });
                    outcome.archives.push(cancelled);
                    continue;
                }
                BatchTaskResult::Failed(error) => {
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
                .generated_sources
                .append(&mut branch.generated_sources);
        }
        first_error.map_or(Ok(outcome), Err)
    }

    async fn finish_root(&self, id: TaskId, path: &Path, result: io::Result<Outcome>) -> io::Result<Outcome> {
        let compact = self.request.mode == Mode::Extract;
        if !compact && !O::PUBLISHES_ROOTS {
            return result;
        }
        if result.as_ref().is_ok_and(Outcome::settled) {
            stage("report", &Cancellation::default()).await?;
            let mut outcome = result.unwrap().into();
            if O::PUBLISHES_ROOTS {
                outcome = self.observer.root_finished(id, path, outcome, self.output_names.owner).await?;
            }
            if compact {
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
        parent: Option<TaskId>,
        segment: impl FnOnce() -> Option<Segment>,
    ) -> TaskId {
        let id = self.engine.next_id();
        self.notify(|| Event::Queued {
            id,
            parent,
            path: PathBuf::from(&input.entry_path),
            segment: segment(),
        });
        id
    }

    fn queue_inputs(&self, task: &Task, task_id: TaskId,
        previous: &[Option<&InputCheckpoint>], has_retained: bool) -> Vec<TaskId> {
        let count = task.inputs.len();
        let position = |index: usize| previous.get(index).copied().flatten()
            .and_then(InputCheckpoint::report_position).unwrap_or(index + 1);
        let register = |index: usize| {
            if count == 1 { return task_id; }
            let input = &task.inputs[index].input;
            let extent = input.physical_extents().next();
            self.queue_task(input, Some(task_id), || Some(Segment {
                format: input.format_hint.clone(), index: position(index),
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

    fn replan_input(&self, task_id: TaskId, input: &ArchiveInput,
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
            Segment { format: input.format_hint.clone(), index,
                offset: extent.map_or(0, |extent| extent.start),
                end_offset: extent.and_then(|extent| extent.end) }
        };
        let active = self.queue_task(input, Some(task_id), || Some(segment(input, 1)));
        let retained = self.queue_task(previous.input(), Some(task_id),
            || Some(segment(previous.input(), previous.report_position().unwrap_or(1))));
        if let Some(failure) = previous.failure() {
            self.notify(|| {
                let mut result = super::TaskCompletion::failed(failure);
                result.output = previous.has_output().then(|| previous.output().to_path_buf());
                Event::Finished { id: retained, result }
            });
        }
        self.notify(|| Event::Started { id: active });
        (active, Some(retained))
    }

    fn record_scan_errors(&self, errors: DirectoryReadErrors) -> bool {
        if errors.is_empty() {
            return false;
        }
        self.scan_errors.lock().unwrap().merge_report(errors);
        true
    }

    #[cfg(test)]
    fn cleanup_owner(&self, task: &Task) -> Option<CleanupOwner> {
        (self.request.mode == Mode::Extract).then(|| CleanupOwner::new(&self.cleanup_refs, &task.owned_paths))
    }

    #[cfg(test)]
    fn register_task(&self, task: Task) -> (Task, Option<CleanupOwner>, Option<HashSet<Arc<str>>>, Option<Arc<WatchGenerations>>) {
        let sources = self.cleanup_owner(&task);
        (task, sources, None, None)
    }

    fn execute_task(
        self: &Arc<Self>,
        (mut task, mut sources, keys, requested): (Task, Option<CleanupOwner>, Option<HashSet<Arc<str>>>, Option<Arc<WatchGenerations>>),
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
            // Stage and lease waiters keep the planned input, without the execution frame.
            let execution = boxed_phase(move || async move {
                let mut outcome = Outcome::default();
                let mut shell = this.engine.shell.branch();
                let (mut generations, missing) = this.capture_generations(&task);
                let (discovery_scope, retry) = task.take_context(this.request.mode == Mode::Extract);
                let admission = this.task_admission(&task, &generations, &missing, watch_root,
                    |path| requested.as_ref().and_then(|members| members.get(path))
                        .or_else(|| captured.as_ref().and_then(|members| members.get(path))))?;
                drop((requested, captured));
                let mut completed_family = match admission {
                    TaskAdmission::Execute(family) => family,
                    TaskAdmission::Departed => {
                        this.notify(|| Event::Skipped { id: task_id });
                        return Ok(ExecutedTask::Complete(outcome));
                    }
                    TaskAdmission::Completed(output) => {
                        this.reuse_completed_task(&task, task_id, depth, output, &mut outcome);
                        return Ok(ExecutedTask::Complete(outcome));
                    }
                };
                if watch_root && this.observer.input_admission_enabled() && !task.inputs.is_empty()
                    && task.inputs.iter().all(|input| input.failure.is_none())
                {
                    let inputs: Vec<_> = task.inputs.iter().map(|input| &input.input).collect();
                    if !this.observer.admit_inputs(Path::new(&task.entry().entry_path),
                        &inputs, &task.owned_paths, depth)?
                    {
                        this.notify(|| Event::Skipped { id: task_id });
                        return Ok(ExecutedTask::Complete(outcome));
                    }
                }
                this.notify(|| Event::Started { id: task_id });
                let preflight_failures = if task.inputs.len() > 1
                    && !missing.is_empty() {
                    task.inputs.iter().map(|logical| logical.failure.clone()).collect::<Vec<_>>()
                } else { Vec::new() };
                this.admit_missing_inputs(&mut task, &missing);
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
                    .is_some_and(|failure| failure.kind == FailureKind::MissingVolume);
                if !single_volume_retry && (admission || discovery_blocked) {
                    let failure = task.inputs[0].failure.as_ref().expect("task preflight failure");
                    // task_started in main registers segment rows even when task
                    // preflight prevents execution. Queued here only registers the
                    // observer row; no segment is submitted to the scheduler.
                    if task.inputs.len() > 1 {
                        for (index, id) in this.queue_inputs(&task, task_id, &[], false).into_iter().enumerate() {
                            let logical = &task.inputs[index];
                            let original = if discovery_blocked { logical.failure.as_ref() }
                                else { preflight_failures.get(index).and_then(Option::as_ref) };
                            this.notify(|| Event::Finished {
                                id,
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
                            if this.request.mode == Mode::Scan {
                                result.scan_layout = super::ScanLayout::from_input(&logical.input);
                            }
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
                    let discovery_scope = discovery_scope.as_deref()
                        .filter(|_| this.request.mode == Mode::Extract)
                        .map(|scope| Arc::new(super::FailureScope::from_scope(scope)));
                    for result in &mut completed {
                        result.failure.get_or_insert_with(|| failure.clone());
                        if this.request.mode == Mode::Extract {
                            if admission { result.source_paths = task.owned_paths.iter().map(PathBuf::from).collect(); }
                            if let Some(scope) = &discovery_scope {
                                result.failure.as_mut().unwrap().discovery_scope = Some(Arc::clone(scope));
                            }
                        }
                    }
                    outcome.generated_sources.extend(task.owned_paths.iter().filter_map(|path|
                        this.generated_source(path, &generations, watch_root, depth)));
                    drop(lease);
                    this.notify(|| {
                        let mut completion = if discovery_blocked {
                            super::TaskCompletion::from_group(&completed)
                        } else { super::TaskCompletion::from_result(&completed[0]) };
                        if admission && this.request.mode == Mode::Scan { completion.failure = Some(failure.clone()); }
                        Event::Finished { id: task_id, result: completion }
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
                        this.observer.scope_finished(task_id, outcome.archives.iter()).await?;
                    }
                    return Ok(ExecutedTask::Complete(outcome));
                }
                let candidates = this.candidates.with_scope(source_scope);
                let multi = task.inputs.len() > 1;
                let preferred_carrier = (this.request.mode == Mode::Extract && (multi || !this.checkpoints.is_empty()))
                    .then(|| this.preferred_output(task.entry(), depth));
                let report_previous = this.select_checkpoints(&owner_path, &task.inputs);
                let retained: Vec<_> = task
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
                let ids = this.queue_inputs(&task, task_id, &report_previous, retained.iter().any(Option::is_some));
                let mut carrier = if this.request.mode == Mode::Extract && multi {
                    let existing = retained
                        .iter()
                        .flatten()
                        .find_map(|checkpoint| checkpoint.retained_container())
                        .map(Path::to_path_buf);
                    match existing {
                        Some(path) => Some(path),
                        None if task.inputs.iter().enumerate()
                            .any(|(index, input)| retained.get(index).is_none_or(Option::is_none) && input.failure.is_none()) => {
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
                let mut planned_slots = Vec::new();
                if let Some(root) = carrier.as_deref() {
                    planned_slots.reserve_exact(count);
                    for (index, logical) in task.inputs.iter_mut().enumerate() {
                        let previous = retained.get(index).copied().flatten()
                            .or_else(|| retry_slots.get(index).copied().flatten())
                            .filter(|checkpoint| checkpoint.container() == Some(root))
                            .and_then(InputCheckpoint::output_slot);
                        let slot = previous.filter(|path| OutputNames::retain(&this.output_names.registry,
                            path, this.output_names.owner, Path::new(&logical.input.entry_path), Some(root),
                        ));
                        let slot = if let Some(slot) = slot {
                            Some(slot.to_owned())
                        } else {
                            match OutputNames::plan(&this.output_names.registry, root.join(archive_name(&logical.input)), Path::new(&logical.input.entry_path),
                                this.output_names.owner, Some(root))?
                            {
                                Ok(slot) => Some(slot),
                                Err(failure) => {
                                    logical.failure.get_or_insert(failure);
                                    None
                                }
                            }
                        };
                        planned_slots.push(slot);
                    }
                }
                let mut parent_outputs = Vec::with_capacity(count);
                let report_enabled = this.request.mode == Mode::Extract && task.owned_paths.iter()
                    .all(|path| generations.contains_key(&path_key(path)));
                let mut report_states = Vec::new();
                let mut replacement_retained = None;
                let mut replacement_rows = None;
                let mut retry = retry.filter(|_| !multi);
                let mut physical_sources = task.owned_paths;
                let mut superseded_candidates = HashSet::new();
                for (index, (logical, &original_id)) in task.inputs.into_iter().zip(&ids).enumerate() {
                    let checkpoint = retained.get(index).copied().flatten();
                    let retry_slot = retry_slots.get(index).copied().flatten();
                    let previous = report_previous.get(index).copied().flatten();
                    let planned_slot = planned_slots.get(index).and_then(Option::as_deref);
                    let mut id = original_id;
                    if multi {
                        this.notify(|| Event::Started { id });
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
                        } else { planned_slot.map(RetryOutput::Recreate) };
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
                    if let Some(context) = retry.take().filter(|_| {
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
                        let replacement = discovery::retry_volume(
                            &executed.result,
                            &missing,
                            &context,
                            this.options_at(depth)?,
                            &candidates,
                            &this.request,
                        )?;
                        drop(context);
                        if let Some(mut replacement) = replacement {
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
                                            previous, index + 1, report_count)?;
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
                                if let Some(sources) = &mut sources { sources.refresh(&replacement.owned_paths); }
                                drop(lease);
                                let requested = this.requested_generation(&replacement, watch_root);
                                lease = this.claim_task(&replacement, None).await?;
                                stage("preflight", cancel).await?;
                                let (current_generations, missing) = this.capture_generations(&replacement);
                                generations = current_generations;
                                let admission = this.task_admission(&replacement, &generations, &missing, watch_root,
                                    |path| requested.as_ref().and_then(|members| members.get(path)))?;
                                drop(requested);
                                completed_family = match admission {
                                    TaskAdmission::Execute(family) => family,
                                    TaskAdmission::Departed => {
                                        this.notify(|| Event::Skipped { id: task_id });
                                        return Ok(ExecutedTask::Complete(outcome));
                                    }
                                    TaskAdmission::Completed(output) => {
                                        this.reuse_completed_task(&replacement, task_id, depth, output, &mut outcome);
                                        return Ok(ExecutedTask::Complete(outcome));
                                    }
                                };
                                this.admit_missing_inputs(&mut replacement, &missing);
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
                                physical_sources = std::mem::take(&mut replacement.owned_paths);
                                let (active, retained) = this.replan_input(task_id,
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
                            result.volume_completeness = Some(VolumeCompleteness::Missing);
                        }
                    }
                    if result.failure.is_none() {
                        superseded_candidates.extend(attempted.into_iter().flatten());
                    }
                    let replacement_matches = replacement_checkpoint.as_ref()
                        .is_some_and(|previous| previous.same_report_input(&input));
                    let state_previous = if replacement_checkpoint.is_some() {
                        replacement_checkpoint.as_ref().filter(|_| replacement_matches)
                    } else { previous.or(checkpoint).or(retry_slot) };
                    let keeps_replaced = replacement_checkpoint.is_some() && !replacement_matches;
                    if report_enabled && (multi || result.failure.is_some() || keeps_replaced) {
                        // An ordinary successful input cannot be retried from its
                        // own receipt. Nested blockers keep their own checkpoints.
                        let mut state = InputCheckpoint::report_state(&input, &result,
                            planned_output.as_deref().or(planned_slot),
                            state_previous, index + 1, report_count);
                        if result.retained && result.output.is_none() && checkpoint.is_some_and(|checkpoint| checkpoint.has_output()) {
                            InputCheckpoint::clear_report_output(&mut state);
                        }
                        report_states.push(state);
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
                            result: super::TaskCompletion::from_result(&result),
                        });
                    }
                    parent_outputs.push((result, inventory, input, id));
                }
                // Reserve post-processing state only after every logical input finishes.
                let postprocess = boxed_phase(move || async move {
                    let _shell = shell;
                    this.apply_complete_content_policy(&mut parent_outputs, &mut report_states,
                        replacement_retained.as_mut(), &mut outcome)?;
                    // Settle physical ownership before any successful sibling descends.
                    // Promoted retryable sources remain failures, but no longer block
                    // flattening the independent retained output subtree.
                    let mut parent_checkpoints: Vec<_> = if this.request.mode == Mode::Extract
                        && (multi || parent_outputs.first().is_some_and(|(result, ..)| result.failure.is_some())
                            || replacement_retained.is_some())
                    {
                        parent_outputs.iter().enumerate().map(|(index, (result, _, input, _))| {
                            let mut checkpoint = InputCheckpoint::create(&owner_path, Arc::clone(input),
                                result, &generations, carrier.as_deref())?;
                            checkpoint.install_report(report_states.get_mut(index).and_then(Option::take));
                            checkpoint.set_planned_output(planned_slots.get(index).and_then(Option::as_deref));
                            checkpoint.set_password_signature(|| candidates.signature(&input.entry_path));
                            Some(checkpoint)
                        }).collect()
                    } else {
                        Vec::new()
                    };
                    let replacement_result = replacement_retained.map(|checkpoint| {
                        let mut retained = checkpoint.result(depth);
                        // First-attempt history precedes the replacement and its children.
                        outcome.checkpoints.push(checkpoint);
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
                        physical_sources.retain(|path| {
                            let key = path_key(path);
                            !superseded_candidates.contains(&key) || retained.contains(&key)
                        });
                        if let Some(sources) = &mut sources { sources.refresh(&physical_sources); }
                    }
                    // A replaced attempt is report history after successful cleanup,
                    // not a failed input of the replacement's physical execution.
                    let physical_complete = parent_outputs.iter()
                        .all(|(result, ..)| result.failure.is_none() && !result.partial);
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
                            password: owner_path.parent().map(Arc::from),
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
                            descendants.extend(spawner.bounded_map(recursive.into_iter(), descend).await);
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
                        stage("output_state", &Cancellation::default()).await?;
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
                                    CreatedOutputs::commit(&this.created_outputs, output);
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
                            if !ran_recursive_children {
                                if let Some(output) = result.output.as_deref() {
                                    this.drain_cleanup(Some(output), &mut descendants).await;
                                }
                                stage("postprocess", cancel).await?;
                            }
                            flatten_result(
                                &*this.observer, task_id, &mut result, &mut descendants, Some(&this.created_outputs), &this.output_names,
                                this.request.config.post_extract.flatten_directory_name,
                            )?;
                            children_complete &= descendants.subtree_complete();
                        }
                        carrier_children_complete &= children_complete;
                        let mut checkpoint = parent_checkpoints.get_mut(index).and_then(Option::take);
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
                                    CreatedOutputs::commit_if_unowned(&this.created_outputs, output);
                                }
                            }
                        }
                        if let Some(checkpoint) = checkpoint {
                            outcome.checkpoints.push(checkpoint);
                        }
                        children.checkpoints.append(&mut descendants.checkpoints);
                        outcome
                            .generated_sources
                            .append(&mut descendants.generated_sources);
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
                        && completed.iter().all(|result| result.failure.is_none())
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
                            let flattened = flatten_result(
                                &*this.observer, task_id, &mut container, &mut children, Some(&this.created_outputs), &this.output_names,
                                this.request.config.post_extract.flatten_directory_name,
                            );
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
                            if let Some(root) = carrier.as_deref() {
                                CreatedOutputs::commit_if_unowned(&this.created_outputs, root);
                            }
                            for output in completed.iter().filter_map(|result| result.output.as_deref()) {
                                CreatedOutputs::commit_if_unowned(&this.created_outputs, output);
                            }
                        }
                    }
                    if let Some(root) = &carrier {
                        if completed.iter().all(|entry| entry.output.is_none()) {
                            if output_is_gone(root, true) {
                                if let Some(result) = completed.first() {
                                    this.observer.discard_output(&result.path, &result.source_paths, root)?;
                                    CreatedOutputs::commit(&this.created_outputs, root);
                                }
                            }
                        }
                    }
                    if this.request.mode == Mode::Extract {
                        if let Some(scope) = discovery_scope.as_deref() {
                            let mut report_scope = None;
                            for failure in completed.iter_mut().filter_map(|result| result.failure.as_mut()) {
                                failure.discovery_scope.get_or_insert_with(|| Arc::clone(
                                    report_scope.get_or_insert_with(|| Arc::new(super::FailureScope::from_scope(scope)))
                                ));
                            }
                        }
                    }
                    if this.request.mode == Mode::Extract && completed.iter().any(|result| result.failure.is_some()) {
                        // Receipts have already followed flattening. Preserve the
                        // pre-cleanup facts, but do not reconstruct them from final IO.
                        let retry_output = continued_output || ((multi || had_checkpoints) && completed.iter().any(|result|
                            result.output.is_some() && (result.failure.is_none() || result.partial)));
                        if let Some(recovery) = InputRecovery::capture(&outcome.checkpoints,
                            &owner_path, completed.first().map(|result| result.path.as_path()),
                            carrier.as_deref(), report_count, had_checkpoints, retry_output)
                        {
                            for failure in completed.iter_mut().filter_map(|result| result.failure.as_mut()) {
                                failure.recovery = Some(Arc::clone(&recovery));
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
                    let mut root_cleanup = None;
                    if let Some(sources) = sources.as_mut().filter(|_| sources_complete) {
                        if let Some(family) = completed_family {
                            stage("output_state", &Cancellation::default()).await?;
                            this.observer.sources_processed(family,
                                carrier.as_deref().or_else(|| completed.iter().find_map(|result| result.output.as_deref())))?;
                        }
                        let cleanup_paths = sources.release(true);
                        let mode = if depth > 1 { CleanupMode::Delete }
                            else { this.request.config.post_extract.archive_cleanup_mode };
                        let mut deletes = Vec::new();
                        let mut recycles = Vec::new();
                        for path in &physical_sources {
                            if !cleanup_paths.contains(&namespace_key(Path::new(path))) { continue; }
                            // Generated Watch inputs still belong to the pipeline
                            // under Keep/Recycle. Probe only when this changes which
                            // cleanup to run for the leased path.
                            if mode == CleanupMode::Delete || this.generated_source(path, &generations, watch_root, depth).is_some() {
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
                            let paths = (!watch_root).then(|| deletes.iter().chain(&recycles)
                                .map(|path| Arc::from(namespace_key(path))).collect());
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
                                tasks.register(id, paths, task);
                            } else {
                                root_cleanup = Some(spawner.spawn(Box::pin(work)));
                            }
                        }
                    } else {
                        outcome.generated_sources.extend(physical_sources.iter().filter_map(|path|
                            this.generated_source(path, &generations, watch_root, depth)));
                        drop(lease);
                    }
                    if this.request.mode == Mode::Extract {
                        project_possible_missing_volume(&mut completed, split_input);
                    }
                    // Refresh segment rows after carrier policy and flattening,
                    // just as main's task_finished refreshes its input_results.
                    if multi {
                        for (&id, result) in ids.iter().zip(&completed) {
                            this.notify(|| Event::Finished {
                                id,
                                result: super::TaskCompletion::from_result(result),
                            });
                        }
                    }
                    if let Some((active, retained)) = replacement_rows {
                        // The execution result stays first and the retained first
                        // attempt is appended to the physical result group.
                        for (id, result) in [active, retained].into_iter().zip(&completed) {
                            this.notify(|| Event::Finished { id,
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
                        outcome.cleanup_results.append(&mut cleanup.wait().await.into());
                    }
                    if depth == 1 && this.request.mode == Mode::Extract && !cancel.cancelled() {
                        this.observer.scope_finished(task_id, outcome.archives.iter()).await?;
                    }
                    Ok(outcome)
                });
                Ok::<_, io::Error>(ExecutedTask::Finalize(postprocess))
            });
            // Finishing execution releases its frame before scheduling post-processing.
            match execution.await? {
                ExecutedTask::Complete(outcome) => Ok(outcome),
                ExecutedTask::Finalize(postprocess) => postprocess.await,
            }
        })
    }

    fn generated_source(
        &self,
        path: &str,
        generations: &HashMap<String, PhysicalFileGeneration>,
        watch_root: bool,
        depth: usize,
    ) -> Option<GeneratedSource> {
        if depth == 1 && !watch_root && self.generated_sources.is_empty() {
            return None;
        }
        let key = path_key(path);
        let generation = generations.get(&key)?;
        if depth > 1 { return Some(GeneratedSource::from_generation(Path::new(path), generation)); }
        self.generated_sources
            .get(&key)
            .map(|&index| &self.request.generated_sources[index])
            .filter(|source| source.matches(generation))
            .cloned()
            .or_else(|| {
                watch_root
                    .then(|| self.observer.generated_source(path))
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
                            .generated_source(
                                &input.entry_path,
                                generations,
                                self.request.origin == Origin::Watch, 1,
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
                    let anchors = if let Some(anchors) = index.get_mut(&input.format_hint) {
                        anchors
                    } else {
                        index.entry(input.format_hint.clone()).or_default()
                    };
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
        if self.checkpoints.is_empty() { return Vec::new(); }
        let carrier = path_key(&carrier.to_string_lossy());
        let group = self.checkpoints.get_key_value(carrier.as_str()).or_else(|| {
            let index = self.checkpoint_anchor_index();
            let mut owner = None;
            for logical in inputs {
                let input = &logical.input;
                let Some(anchors) = index.get(&input.format_hint) else { continue; };
                for anchor in recovery_anchors(input) {
                    if let Some(matches) = anchors.get(&anchor) {
                        // Each carrier contributes one contiguous run to this anchor.
                        let first = &matches.first().unwrap().0;
                        let last = &matches.last().unwrap().0;
                        if first != last || owner.is_some_and(|owner| owner != first) { return None; }
                        owner = Some(first);
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

    async fn claim_task(&self, task: &Task, keys: Option<HashSet<Arc<str>>>) -> io::Result<Lease> {
        let keys = keys.unwrap_or_else(|| source_lease_keys(task, &HashMap::new()));
        self.engine.leases.acquire_shared(keys, self.output_names.owner, &self.request.cancel).await
    }

    fn capture_generations(&self, task: &Task) -> (HashMap<String, PhysicalFileGeneration>, Vec<PathBuf>) {
        // The lease owns this one metadata snapshot. Keep actual NotFound
        // observations separate from permission/read errors; neither is inferred
        // from a missing generation entry or rechecked later with another stat.
        let mut generations = HashMap::new();
        let mut missing = Vec::new();
        let retain_generations = self.request.mode == Mode::Extract || !self.generated_sources.is_empty();
        for path in &task.owned_paths {
            match capture_file_generation(Path::new(path)) {
                Ok(generation) if retain_generations => { generations.insert(path_key(path), generation); }
                Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(PathBuf::from(path)),
                _ => {}
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

    fn admit_missing_inputs(&self, task: &mut Task, missing: &[PathBuf]) {
        if missing.is_empty() { return; }
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
        watch_root: bool,
        requested: impl Fn(&str) -> Option<&'a PhysicalFileGeneration>,
    ) -> io::Result<TaskAdmission> {
        // Check the resolved physical family only after its lease is acquired.
        // Departed discovery proposals are not successful output reuse.
        if !missing.is_empty() {
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
                        current.is_none_or(|current| current.matches_input(previous))
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
        self.notify(|| Event::Finished { id,
            result: super::TaskCompletion::from_result(&result) });
        outcome.archives.push(result);
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
        if !super::scheduling::in_stage() {
            stage("preflight", &self.request.cancel).await?;
        }
        self.notify(|| Event::Extracting { id });
        let output = if self.request.mode == Mode::Extract {
            let reserved = match retry_output {
                Some(RetryOutput::Recreate(path)) => self.recreate_reserved_output(path, &result)?,
                Some(RetryOutput::Existing(path)) => {
                    // This was a retained, claimed child slot whose cleanup
                    // failed. Match main's mkdir(exist_ok=True) and start the
                    // current attempt rather than accepting the old receipt.
                    match self.observer.reuse_output(&result, path) {
                        Ok(()) => {
                            CreatedOutputs::register(&self.created_outputs, path, &result);
                            Ok(path.to_owned())
                        }
                        Err(error) if error.get_ref().is_some_and(|inner| inner.is::<super::OutputCreateError>()) => {
                            Err(output_create_failure(error, path))
                        }
                        Err(error) => return Err(error),
                    }
                }
                None => {
                    let preferred = carrier.map_or_else(
                        || self.preferred_output(&input, depth),
                        |root| root.join(archive_name(&input)),
                    );
                    self.reserve_output(preferred, &result, carrier)?
                }
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
        let mut plan = match candidates.plan(&mut input, password, &self.request.cancel, self.request.mode) {
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
        if let Some(password) = &plan.verified_password {
            result.password = Some(password.to_string());
            if self.request.mode == Mode::Scan && complete_verified_scan_layout(&mut input, &mut result) {
                self.request.cancel.check_io()?;
                result.encrypted = plan.encrypted;
                self.notify(|| Event::Finalizing { id });
                return Ok(Executed {
                    planned_output: None,
                    result,
                    inventory: None,
                    input: Arc::new(input),
                });
            }
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
            .map(|path| path.to_string_lossy())
            .unwrap_or_default();
        self.notify(|| Event::Waiting { id });
        let mut input = Arc::new(input);
        let native = match self.engine.worker(&self.request.config.performance.worker, &self.request.cancel).await {
            Ok(worker) => {
                if super::scheduling::in_stage() {
                    self.request.cancel.check_io()?;
                } else {
                    stage("extract_prepare", &self.request.cancel).await?;
                }
                // Materialize the worker request only when it can be sent.
                // Pending jobs keep their plans without a second JSON copy.
                let volume_key = if output_string.is_empty() {
                    String::new()
                } else {
                    crate::filesystem::resolve_output_volume_key(&output_string)
                        .unwrap_or_else(|| format!("job:{job_id}"))
                };
                let request = worker::WorkerRequest {
                    job_id,
                    operation: if self.request.mode == Mode::Scan { "scan" } else { "extract" },
                    origin: if self.request.origin == Origin::Watch { "watch" } else { "foreground" },
                    output_dir: output_string.to_string(),
                    output_volume_key: volume_key,
                    archive_input: Arc::clone(&input),
                    password_candidates: Arc::clone(&plan.candidates),
                    layout_passwords: std::mem::take(&mut plan.layout_passwords),
                    password: plan.verified_password.clone(),
                    password_verified: plan.verified_password.is_some(),
                    encrypted: plan.encrypted,
                    codepage,
                    report_progress: false,
                    output_inventory: self.request.mode == Mode::Extract && depth <= self.request.max_depth,
                };
                worker
                    .submit(
                        request,
                        &self.request.cancel,
                        self.observer.worker_updates(),
                        |update| {
                            let event = match update {
                                worker::Update::Started => Event::Working { id },
                                worker::Update::Progress(progress) => Event::Progress {
                                    id,
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
                let scan_selection = self.request.mode == Mode::Scan && value.get("volume_selection").is_some();
                // A selected composition already replaces the plan. Resolve
                // its source IDs against the request before any compaction.
                if self.request.mode == Mode::Scan && !scan_selection {
                    if flag(value, "volume_candidates_exhausted")
                        && worker::string(value, "failure_kind") == "missing_volume"
                    {
                        if let Some(plan) = &input.volume_attempts {
                            let empty = plan.with_remaining(Vec::new(), Vec::new());
                            Arc::make_mut(&mut input).volume_attempts = Some(Arc::new(empty));
                        }
                    } else if let Some(plan) = &input.volume_attempts {
                        let first = value.get("first_remaining_volume").map(VolumeSelection::deserialize).transpose()?;
                        let paths: Vec<_> = value.get("discarded_volume_paths").map(Vec::deserialize).transpose()?.unwrap_or_default();
                        let prefixes: Vec<_> = value.get("discarded_volume_prefixes").map(Vec::deserialize).transpose()?.unwrap_or_default();
                        let layouts: Vec<_> = value.get("discarded_volume_layouts").map(Vec::deserialize).transpose()?.unwrap_or_default();
                        if first.is_some() || !paths.is_empty() || !prefixes.is_empty() || !layouts.is_empty() {
                            let remaining = crate::password::evidence::remove_scan_paths(plan, paths, prefixes, layouts, first.as_ref())?;
                            Arc::make_mut(&mut input).volume_attempts = Some(Arc::new(remaining));
                        }
                    }
                }
                if input.volume_attempts.is_some()
                    && (scan_selection || (success && self.request.mode == Mode::Extract)) {
                    let selected = value
                        .get("volume_selection")
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "worker omitted successful volume selection",
                            )
                        })
                        .and_then(|raw| {
                            VolumeSelection::deserialize(raw).map_err(io::Error::from)
                        });
                    let completeness = input.analysis.volume_completeness;
                    match selected.and_then(|selected| Arc::make_mut(&mut input).select_volumes(&selected)) {
                        Ok(()) => {
                            result.source_paths =
                                input.physical_paths().map(PathBuf::from).collect();
                            if scan_selection {
                                // A unique composition can still be missing archive data.
                                Arc::make_mut(&mut input).analysis.volume_completeness = completeness;
                            } else {
                                result.volume_completeness = Some(VolumeCompleteness::Complete);
                            }
                        }
                        Err(error) => {
                            result.failure =
                                Some(Failure::new(FailureKind::ProcessError, error.to_string()));
                        }
                    }
                }
                if success && result.failure.is_none() {
                    let password_verified = self.request.mode == Mode::Extract
                        || plan.verified_password.is_some()
                        || flag(value, "password_verified");
                    if result.encrypted == Some(true) && password_verified {
                        result.password = plan
                            .remember_confirmation(matched_index, &self.engine.recent_passwords)
                            .map(str::to_owned);
                    }
                    if let Some(output) = &output {
                        let collect_rows = depth <= self.request.max_depth;
                        let stats = frame.manifest.take()
                            .and_then(|manifest| manifest.into_output_stats(&output_string, collect_rows))
                            .unwrap_or_else(|| scan_output_stats(&output_string, collect_rows));
                        result.files = stats.file_count;
                        result.bytes = stats.total_size;
                        result.output = Some(output.clone());
                        inventory = stats.inventory;
                    }
                } else if result.failure.is_none() {
                    let split = input.mode.structured() || input.physical_paths().nth(1).is_some()
                        || looks_like_split_archive_name(&input.entry_path);
                    let mut failure = classify_worker_failure(value, plan.evidence, split);
                    if matches!(failure.kind, FailureKind::WrongPassword | FailureKind::PasswordInconclusive) {
                        result.password = None;
                    }
                    let proven_on_scan = self.request.mode == Mode::Scan && failure.kind == FailureKind::MissingVolume
                        && flag(value, "password_verified");
                    if proven_on_scan || (failure.kind == FailureKind::Damaged && worker::number(value, "password_crc_proven_items") != 0) {
                        result.password = plan
                            .remember_confirmation(matched_index, &self.engine.recent_passwords)
                            .map(str::to_owned);
                    }
                    if let Some((output, verified_files)) = output.as_ref().zip(
                        (failure.kind != FailureKind::PasswordInconclusive)
                            .then(|| recoverable_file_count(&frame)).flatten(),
                    ) {
                        let complete_files = recovery_complete_files(&failure, verified_files);
                        let partial = accepts_partial_content(
                            self.request.config.extraction.content_requirement,
                            failure.kind, complete_files,
                        );
                        let stats = scan_output_stats(&output_string, partial && depth <= self.request.max_depth);
                        // Retaining damaged payload is not partial success:
                        // main keeps nonempty failed output for manual recovery,
                        // but only verified files authorize recursive processing.
                        if verified_files > 0 || stats.file_count > 0 {
                            result.recovered_complete_files = complete_files;
                            result.partial = partial;
                            result.files = stats.file_count;
                            result.bytes = stats.total_size;
                            result.output = Some(output.clone());
                            inventory = stats.inventory;
                        }
                    }
                    failure.evidence = worker_evidence(value, plan.evidence);
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
            input,
        })
    }

    fn apply_complete_content_policy(
        &self, parent_outputs: &mut [ParentOutput], report_states: &mut [Option<ReportState>],
        replacement_retained: Option<&mut InputCheckpoint>, outcome: &mut Outcome,
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
                || replacement_retained.as_deref().is_some_and(InputCheckpoint::has_recovered_members);
            for (index, (result, inventory, ..)) in parent_outputs.iter_mut().enumerate() {
                if let Some(output) = result.output.clone() {
                    if self.discard_failed_output(result, &output, outcome)? {
                        result.output = None;
                        result.files = 0;
                        result.bytes = 0;
                        result.recovered_complete_files = 0;
                        if let Some(state) = report_states.get_mut(index) {
                            InputCheckpoint::clear_report_output(state);
                        }
                    }
                }
                *inventory = None;
            }
            if rejected_output && parent_outputs.iter().all(|(result, ..)| result.output.is_none()) {
                for state in report_states.iter_mut() { InputCheckpoint::clear_report_output(state); }
                if let Some(checkpoint) = replacement_retained { checkpoint.clear_recovery_output(); }
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
        CreatedOutputs::commit(&self.created_outputs, path);
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

    async fn discover_children_many<T: Send>(
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
        discovery::OutputDiscovery::prepare_many(
            inventories, options, &self.request.cancel, |item| item,
            |parent, output| {
                let mut nested = Discovered::default();
                nested.scan_errors.extend(output.scan_errors());
                let has_files = output.has_files();
                results.push((parent, nested, has_files));
                if has_files { outputs.push(output); }
            },
        )?;
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
                CreatedOutputs::register(&self.created_outputs, path, result);
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
            CreatedOutputs::register(&self.created_outputs, path, result);
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
                    failures.extend(cleanup_failure(path, mode, Err(copy_io_error(&error))));
                }
                return;
            }
        };
        for path in existing {
            let removed = match cleanup {
                CleanupMode::Delete => remove_owned_file(path),
                CleanupMode::Recycle => super::cleanup::recycle(path),
                CleanupMode::Keep => unreachable!("keep produced receipts without filesystem work"),
            };
            if removed.is_ok() {
                shell.parent(path);
                if let Some(parent) = path.parent().filter(|parent| parent.parent().is_some()) {
                    let protected = !self.cleanup_boundaries.is_empty()
                        && self.cleanup_boundaries.contains(&resolved_key(parent));
                    // RemoveDirectory checks emptiness atomically. Never recurse:
                    // a concurrent arrival, retained sibling or output protects itself.
                    if !protected && fs::remove_dir(parent).is_ok() { shell.parent(parent); }
                }
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
    naming: crate::core::config::FlattenDirectoryName,
) -> io::Result<()> {
    let Some(output) = result.output.as_ref() else {
        return Ok(());
    };
    let Some(leaf) = discover_flatten_leaf(output) else {
        return Ok(());
    };
    let mut destination_claim = None;
    let mut attempt = || -> io::Result<_> {
        use crate::core::config::FlattenDirectoryName;
        let mut destination = output.as_path();
        let mut alias = None;
        if naming == FlattenDirectoryName::Inner {
            let preferred = output.with_file_name(leaf.file_name().expect("flatten leaf has a name"));
            if path_key(&preferred.to_string_lossy()) == path_key(&output.to_string_lossy()) {
                destination = alias.insert(preferred);
            } else {
                destination_claim = Some(OutputNames::plan_checked(
                    &names.registry, preferred, &result.path, names.owner, Some(output), Path::try_exists,
                )?.map_err(|failure| io::Error::other(failure.message))?);
                destination = &destination_claim.as_ref().unwrap().0;
            }
        }
        let mut work = output.as_os_str().to_os_string();
        work.push(".__sunpack_flatten_work__");
        let work = PathBuf::from(work);
        let (available, available_key) = OutputNames::plan_checked(&names.registry,
            work, &result.path, names.owner, Some(output), Path::try_exists,
        )?.map_err(|failure| io::Error::other(failure.message))?;
        let attempt = (|| {
            let _promotion = Promotion::begin(std::iter::once(output.to_owned())
                .chain(destination_claim.as_ref().map(|(path, _)| path.clone())))?;
            Ok(flatten_single_branch_directories(
                output,
                &available,
                FlattenLeaf::Prepared(&leaf),
                destination,
                || observer.before_flatten(output, &available, &leaf, destination),
            ))
        })();
        names.registry.lock().unwrap().release_path(&available_key, names.owner);
        attempt.map(|outcome| (outcome, available, alias))
    };
    let attempted = attempt();
    if let Some((_, key)) = &destination_claim {
        if !matches!(attempted, Ok((FlattenOutcome::Published { .. }, _, _))) {
            names.registry.lock().unwrap().release_path(key, names.owner);
        }
    }
    let (outcome, work, alias) = match attempted {
        Ok(parts) => parts,
        Err(error) if is_cancellation(&error) || error.kind() == io::ErrorKind::Interrupted => {
            return Err(error);
        }
        Err(error) => {
            record_cleanup(children, output, "flatten", Err(io::Error::other(error)));
            return Ok(());
        }
    };
    let (old, new) = match outcome {
        FlattenOutcome::Unmoved(error) => {
            record_cleanup(children, output, "flatten", Err(io::Error::other(error)));
            return Ok(());
        }
        FlattenOutcome::Staged(error) => {
            record_cleanup(children, &work, "flatten", Err(io::Error::other(error)));
            (output.as_path(), work)
        }
        FlattenOutcome::Published { cleanup_error } => {
            let destination = destination_claim.map(|(path, _)| path).or(alias)
                .unwrap_or_else(|| output.clone());
            if let Some(error) = cleanup_error {
                record_cleanup(children, &destination, "flatten", Err(io::Error::other(error)));
            }
            (leaf.as_path(), destination)
        }
    };
    // Rollback follows the payload even if durable publication fails.
    if let Some(created) = created {
        created.lock().unwrap().relocate_flatten(output, old, &new);
    }
    observer.after_flatten(id, output, old, &new)?;
    for checkpoint in &mut children.checkpoints {
        checkpoint.relocate_flatten(output, old, &new);
    }
    let mut relocated_recoveries = HashMap::new();
    for child in &mut children.archives {
        if let Some(failure) = &mut child.failure {
            if let Some(recovery) = &mut failure.recovery {
                let key = Arc::as_ptr(recovery);
                let relocated = relocated_recoveries.entry(key).or_insert_with(|| {
                    let mut snapshot = recovery.as_ref().clone();
                    snapshot.relocate_flatten(output, old, &new);
                    Arc::new(snapshot)
                });
                *recovery = Arc::clone(relocated);
            }
        }
        if let Some(path) = child.output.as_mut() {
            super::relocate_flatten_output(path, output, old, &new);
        }
    }
    for receipt in &mut children.cleanup_results {
        if let Some(suffix) = relative_to(&receipt.path, old) {
            receipt.path = new.join(suffix);
        }
    }
    result.output = Some(new);
    Ok(())
}

fn record_cleanup(outcome: &mut Outcome, path: &Path, mode: &'static str, removed: io::Result<()>) {
    if let Some(failure) = cleanup_failure(path, mode, removed) {
        outcome.cleanup_results.push(failure);
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

fn complete_verified_scan_layout(input: &mut ArchiveInput, result: &mut ArchiveResult) -> bool {
    use crate::io::archive_state::contiguous_volume_prefix;
    let complete = |parts: &[crate::io::archive_state::InputPart]| {
        !parts.is_empty() && contiguous_volume_prefix(parts).len() == parts.len()
    };
    if let Some(plan) = &input.volume_attempts {
        let Some(parts) = plan.sole_parts().filter(|parts| complete(parts)) else { return false; };
        input.parts = parts;
        input.volume_attempts = None;
        result.source_paths = input.physical_paths().map(PathBuf::from).collect();
        return true;
    }
    !input.mode.structured() || complete(&input.parts)
}

fn receipt(input: &ArchiveInput, source: DiscoverySource, depth: usize) -> ArchiveResult {
    let extent = input.physical_extents().next();
    let mut source_paths: Vec<_> = input.physical_paths().map(PathBuf::from).collect();
    dedup_paths(&mut source_paths);
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
        volume_completeness: input.analysis.volume_completeness,
        source_paths,
        password: None,
        discovery_source: source,
        partial: false,
        retained: false,
        recovered_complete_files: 0,

        scan_layout: super::ScanLayout::default(),
    }
}

fn recovery_anchors(input: &ArchiveInput) -> impl Iterator<Item = (String, u64)> + '_ {
    let plan = input.volume_attempts.as_ref();
    let extents = plan.into_iter().flat_map(|plan| plan.sources.iter())
        .chain(input.physical_extents().filter(move |_| plan.is_none()));
    let empty = plan.map_or(input.parts.is_empty(), |plan| plan.sources.is_empty());
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
    password_evidence: Option<&str>,
) -> Option<Box<FailureEvidence>> {
    let field = |name: &str| {
        let text = worker::string(result, name);
        (!text.is_empty()).then(|| text.to_owned())
    };
    let hresult = result["hresult"].as_i64();
    // Keep the scalar proof behind the classification, not passwords or the
    // complete worker payload. Main exposes these in its failure details.
    // Explicit rejection takes precedence over fallback evidence in main.
    let weak_failure = !flag(result, "password_candidates_all_rejected")
        && weak_password_failure(result, password_evidence);
    let proof_count = weak_failure.then(|| worker::number(result, "password_crc_proven_items"))
        .filter(|count| *count != 0);
    let (classification_evidence, password_crc_proven_items, backend_operation_result) =
        if let Some(count) = proof_count {
            (Some("entry_crc_proven_before_failure".to_owned()), Some(count), None)
        } else if weak_failure {
            (Some(match password_evidence {
                Some("empty_password_direct") => "empty_password_failed_without_crc_proof",
                Some("zip_pkware_strong_padding") => "pkware_strong_failure_without_password_proof",
                _ => "zipcrypto_failure_without_password_proof",
            }.to_owned()),
             None, Some(worker::string(result, "operation_result_name").to_owned()))
        } else { (None, None, None) };
    let stage = field("failure_stage");
    let native_kind = field("failure_kind");
    let missing_volume_suspected = flag(result, "missing_volume_suspected");
    let missing_volume_name = field("missing_volume_name");
    let missing_volume_evidence = field("missing_volume_evidence");
    let input = &result["input_trace"];
    let last = &input["last_read"];
    let path = worker::string(last, "source_path");
    let read_error = flag(input, "read_error");
    let read = (!path.is_empty() || read_error).then(|| FailureRead {
        source_path: path.to_owned(),
        source_offset: worker::number(last, "source_offset"),
        virtual_offset: worker::number(last, "virtual_offset"),
        requested: worker::number(last, "requested"),
        win32_error: input["last_win32_error"].as_i64().unwrap_or_default(),
        read_error,
    });
    (hresult.is_some() || classification_evidence.is_some() || missing_volume_suspected
        || stage.is_some()
        || native_kind.is_some()
        || missing_volume_name.is_some()
        || missing_volume_evidence.is_some()
        || read.is_some())
    .then(|| {
        Box::new(FailureEvidence {
            hresult, classification_evidence, password_crc_proven_items, backend_operation_result,
            missing_volume_suspected,
            stage,
            native_kind,
            missing_volume_name,
            missing_volume_evidence,
            read,
            ..Default::default()
        })
    })
}

fn weak_password_failure(result: &Value, evidence: Option<&str>) -> bool {
    (matches!(evidence, Some("zipcrypto_header_byte" | "zip_pkware_strong_padding"))
        || (evidence == Some("empty_password_direct") && flag(result, "encrypted")))
        && (matches!(worker::string(result, "operation_result_name"), "wrong_password" | "data_error" | "crc_error")
            || matches!(worker::string(result, "failure_kind"),
                "encrypted_or_wrong_password" | "data_error" | "checksum_error" | "crc_error"))
}

// main also recognizes a split-style filename for conflicting native damage
// and password evidence, even when relation discovery proved a standalone file.
fn looks_like_split_archive_name(path: &str) -> bool {
    fn has_digits(value: &str, count: usize) -> bool {
        let mut chars = value.chars();
        (0..count).all(|_| chars.next().and_then(crate::core::config::decimal_digit).is_some())
            && chars.next().is_none()
    }
    fn rar_part(stem: &str) -> bool {
        let Some((_, marker)) = stem.rsplit_once('.') else { return false; };
        let Some(prefix) = marker.get(..4) else { return false; };
        let digits = &marker[4..];
        prefix.eq_ignore_ascii_case("part") && !digits.is_empty()
            && digits.chars().all(|c| crate::core::config::decimal_digit(c).is_some())
    }
    let name = Path::new(path).file_name().unwrap_or_default().to_string_lossy();
    let Some((base, suffix)) = name.rsplit_once('.') else { return false; };
    if has_digits(suffix, 3)
        || (suffix.as_bytes().first().is_some_and(|b| b.eq_ignore_ascii_case(&b'z'))
            && has_digits(&suffix[1..], 2))
        || (suffix.eq_ignore_ascii_case("rar") && rar_part(base))
    {
        return true;
    }
    !suffix.is_empty() && base.rsplit_once('.').is_some_and(|(stem, extension)| {
        has_digits(extension, 3) || (extension.eq_ignore_ascii_case("rar") && rar_part(stem))
    })
}

fn classify_worker_failure(
    result: &Value,
    password_evidence: Option<&str>,
    split: bool,
) -> Failure {
    let native = worker::string(result, "native_status");
    let failure = worker::string(result, "failure_kind");
    let operation = worker::string(result, "operation_result_name");
    let hresult = result["hresult"]
        .as_i64()
        .map(|value| value as u32);
    let payload_damage = flag(result, "checksum_error")
        || flag(result, "damaged")
        || native == "damaged"
        || matches!(failure, "corrupted_data" | "data_error" | "checksum_error" | "crc_error");
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
        if worker::number(result, "password_crc_proven_items") != 0 {
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
    { verified_files } else { 0 }
}

fn accepts_partial_content(requirement: ContentRequirement, failure: FailureKind, complete_files: u64) -> bool {
    requirement == ContentRequirement::AllowPartial
        && matches!(failure, FailureKind::Damaged | FailureKind::MissingVolume)
        && complete_files > 0
}

fn recoverable_file_count(frame: &WorkerFrame) -> Option<u64> {
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
        return None;
    }
    Some(worker::number(&frame.summary, "recovered_complete_files"))
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
    if paths.len() < 2 { return; }
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path_key(&path.to_string_lossy())));
}

fn resolved_key(path: &Path) -> String {
    match fs::canonicalize(path) {
        Ok(canonical) => namespace_key(&canonical),
        Err(_) => namespace_key(path),
    }
}

fn source_lease_keys(task: &Task, resolved: &HashMap<String, Arc<str>>) -> HashSet<Arc<str>> {
    task.owned_paths.iter().map(|path| {
        resolved.get(path).map_or_else(|| Arc::from(resolved_key(Path::new(path))), Arc::clone)
    }).collect()
}

fn cleanup_boundaries(request: &Request) -> HashSet<String> {
    // Nested inputs and generated Watch sources can still be deleted in Keep mode.
    if request.mode == Mode::Scan
        || (request.origin == Origin::Foreground
            && request.max_depth == 0
            && request.generated_sources.is_empty()
            && request.config.post_extract.archive_cleanup_mode == CleanupMode::Keep)
    {
        return HashSet::new();
    }
    request.cleanup_boundaries.iter().chain(request.inputs.iter().filter(|path| path.is_dir()))
        .map(|path| resolved_key(path)).collect()
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
    let path = path.to_string_lossy();
    if path.starts_with(r"\\?\") {
        path_key(&normalize_windows_extended_prefix(path.into_owned()))
    } else {
        path_key(&path)
    }
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
    active: HashMap<Arc<str>, (Option<u64>, usize)>,
    requests: HashMap<u64, RequestClaim>,
    watch: HashMap<Arc<str>, Vec<ActiveWatchFamily>>,
    next_waiter: u64,
    waiters: HashMap<u64, LeaseWaiter>,
    blocked_by: HashMap<LeaseBlocker, SmallOrderedSet<u64>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum LeaseBlocker {
    Request(u64),
    Watch(u64),
    Path(Arc<str>),
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
            if self.blocked_by.get_mut(&blocker).is_some_and(|ids| ids.remove(&id)) {
                self.blocked_by.remove(&blocker);
            }
        }
        Some(waiter.waker)
    }

    fn wait(&mut self, id: u64, blockers: HashSet<LeaseBlocker>, waker: &Waker) {
        if let Some(waiter) = self.waiters.get_mut(&id) {
            if waiter.blockers == blockers {
                waiter.waker.clone_from(waker);
                return;
            }
        }
        self.remove_waiter(id);
        for blocker in &blockers {
            self.blocked_by.entry(blocker.clone()).and_modify(|ids| ids.insert(id))
                .or_insert(SmallOrderedSet::One(id));
        }
        self.waiters.insert(id, LeaseWaiter { waker: waker.clone(), blockers });
    }

    fn released(&mut self, blocker: &LeaseBlocker) -> Vec<Waker> {
        let Some(ids) = self.blocked_by.remove(blocker) else { return Vec::new(); };
        ids.iter().filter_map(|id| self.remove_waiter(*id)).collect()
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
        let (few_objects, many_objects) = if self.objects.len() <= other.objects.len() {
            (&self.objects, &other.objects)
        } else {
            (&other.objects, &self.objects)
        };
        if few_objects.keys().any(|id| many_objects.contains_key(id)) {
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
            capture_directory_identity(&canonical, false)
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
        if claim.paths.is_empty() {
            state.requests.remove(&request);
            crate::collections::trim_map(&mut state.requests);
        } else {
            crate::collections::trim_map(&mut claim.paths);
            crate::collections::trim_map(&mut claim.objects);
        }
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
    keys: HashSet<Arc<str>>,
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
                && request.recursive == owner.recursive
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
        let mut claim = RequestClaim::new(origin);
        for path in paths {
            cancel.check_io()?;
            claim.add(ClaimedInput::new(path)?);
        }
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
                return Poll::Ready(Ok(RequestClaimGuard { registry: Arc::clone(self), id }));
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

    #[cfg(test)]
    async fn acquire(
        self: &Arc<Self>,
        keys: HashSet<Arc<str>>,
        cancel: &Cancellation,
    ) -> io::Result<Lease> {
        self.acquire_paths(keys, None, cancel).await
    }

    async fn acquire_shared(
        self: &Arc<Self>, keys: HashSet<Arc<str>>, request: u64, cancel: &Cancellation,
    ) -> io::Result<Lease> {
        self.acquire_paths(keys, Some(request), cancel).await
    }

    async fn acquire_paths(
        self: &Arc<Self>, keys: HashSet<Arc<str>>,
        request: Option<u64>, cancel: &Cancellation,
    ) -> io::Result<Lease> {
        let mut waiting = LeaseWait {
            owner: self,
            id: None,
        };
        let mut subscription = None;
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if let Err(error) = cancel.check_io() {
                return Poll::Ready(Err(error));
            }
            let blockers: HashSet<_> = keys.iter().filter(|key| {
                state.active.get(*key).is_some_and(|(owner, _)| request.is_none() || *owner != request)
            }).cloned().map(LeaseBlocker::Path).collect();
            if blockers.is_empty() {
                for key in &keys {
                    state.active.entry(Arc::clone(key)).or_insert((request, 0)).1 += 1;
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
        let mut waiters = Vec::new();
        for key in self.keys.drain() {
            let (_, count) = state.active.get_mut(&key).expect("lease owns its path");
            *count -= 1;
            if *count == 0 {
                state.active.remove(&key);
                waiters.extend(state.released(&LeaseBlocker::Path(key)));
            }
        }
        if state.active.capacity() > 256 {
            crate::collections::trim_map(&mut state.active);
        }
        drop(state);
        for waker in waiters { waker.wake(); }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/coordinator/tests.rs"]
mod tests;
