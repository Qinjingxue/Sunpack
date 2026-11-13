use super::checkpoint::{CheckpointKey, InputCheckpoint, PromotedSource};
use super::discovery::{self, Discovered, LogicalInput, Task};
use super::passwords::{AttemptCache, CandidateSet};
use super::scheduling::{stage, Scheduler, Spawner};
use super::shell_updates::{ShellNotifier, ShellUpdates};
use super::worker::{self, Process};
use super::{
    ArchiveResult, BusyConflict, Cancellation, CleanupResult, CleanupStatus, DiscoverySource,
    Event, Failure, FailureEvidence, FailureKind, FailureRead, InputError, InputErrorKind, Mode,
    Observer, Origin, Outcome, Request, Segment, TaskId,
};
use crate::analysis_native::{analyze_input, NativeAnalysisConfig};
use crate::core::config::{CleanupMode, ContentRequirement, ProcessMode, Recursion, WorkerConfig};
use crate::io::archive_state::{
    archive_input_slices, ArchiveInput, OpenMode, VolumeCompleteness, VolumeSelection,
};
use crate::io::cancellation::is_cancellation;
use crate::io::directory_errors::{directory_error_count, DirectoryReadErrors};
use crate::io::reader::{
    capture_directory_identity, capture_file_generation, release_reader_resources_under_roots,
    PhysicalFileGeneration,
};
use crate::io::resource_lifecycle::{
    native_begin_promotion, native_end_promotion, native_wait_for_resources,
};
use crate::path_keys::{normalize_windows_extended_prefix, path_key};
use crate::postprocess::{
    flatten_single_branch_directories, remove_owned_file, remove_owned_tree,
    NativeBlockedInputPromotion,
};
use crate::scan::directory::{
    scan_output_inventory_impl, NativeDirectoryScanOptions, NativeOutputInventory,
};
use crate::scan::worker_event::WorkerFrame;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::future::poll_fn;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
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
    ) -> super::scheduling::Join<T> {
        let id = self.next_id();
        self.scheduler.get_or_init(Scheduler::new).submit(id, origin, cancel, |_| Box::pin(future))
    }

    pub(crate) async fn reserve_foreground_async(
        &self, inputs: &[PathBuf], cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard> {
        let id = self.next_id();
        self.leases.reserve_request_async(id, Origin::Foreground, inputs, cancel).await
    }

    pub(crate) async fn run_reserved_async<O: Observer + 'static>(
        &self, request: Request, observer: Arc<O>, reservation: Arc<RequestClaimGuard>,
    ) -> io::Result<Outcome> {
        debug_assert!(Arc::ptr_eq(&reservation.registry, &self.leases));
        self.submit_with_claim(request, observer, Some(reservation), |result| result).wait().await
    }

    /// Synchronous service work uses the same admission and fixed executor as
    /// archive stages. Nested blocking helpers reuse the admitted stage.
    pub(crate) fn run_stage<T: Send>(
        &self, name: &'static str, origin: Origin, work: impl FnOnce() -> T + Send,
    ) -> T {
        if super::scheduling::in_stage() { return work(); }
        let cancel = Cancellation::new();
        let id = self.next_id();
        self.scheduler.get_or_init(Scheduler::new).run(id, origin, &cancel, |_| Box::pin(async {
            stage(name, &cancel).await.expect("uncancelled service stage");
            work()
        }))
    }

    pub fn run(&self, request: Request, notify: impl Fn(Event) + Send + Sync) -> io::Result<Outcome> {
        self.run_with(request, &notify)
    }

    fn run_with(
        &self,
        request: Request,
        observer: &impl Observer,
    ) -> io::Result<Outcome> {
        // main enters its shared pipeline service (including the handshake)
        // before admitting discovery or preflight work.
        super::scheduling::block_on(self.worker(&request.config.performance.worker, &request.cancel))
            .map_err(super::startup_error)?;
        let request_id = self.next_id();
        let _request_claim = if request.mode == Mode::Extract {
            Some(self.leases.reserve_request(
                request_id,
                request.origin,
                &request.inputs,
                &request.cancel,
            )?)
        } else {
            None
        };
        let run = self.prepare(request, ObserverRef::Borrowed(observer), request_id)?;
        let request = &run.request;
        let scheduler = self.scheduler.get_or_init(Scheduler::new);
        let execute = || {
            scheduler.run(request_id, request.origin, &request.cancel, |spawner| {
                Box::pin(run.execute_request(spawner))
            })
        };
        let executed = if request.mode == Mode::Extract
            && request.config.recursive_extract == Recursion::Prompt
        {
            run.recursion.serve(
                &request.cancel,
                |depth, pending| observer.allow_recursive(depth, pending),
                execute,
            )
        } else {
            execute()
        };
        executed
    }

    pub(crate) fn submit<O: Observer + 'static, T: Send + 'static>(
        &self, request: Request, observer: Arc<O>,
        complete: impl FnOnce(io::Result<Outcome>) -> T + Send + 'static,
    ) -> super::scheduling::Join<T> {
        self.submit_with_claim(request, observer, None, complete)
    }

    fn submit_with_claim<O: Observer + 'static, T: Send + 'static>(
        &self, request: Request, observer: Arc<O>, reservation: Option<Arc<RequestClaimGuard>>,
        complete: impl FnOnce(io::Result<Outcome>) -> T + Send + 'static,
    ) -> super::scheduling::Join<T> {
        let request_id = reservation.as_ref().map_or_else(
            || self.next_id(), |claim| claim.id);
        let engine = self.clone();
        self.scheduler.get_or_init(Scheduler::new).submit(
            request_id, request.origin, &request.cancel.clone(), move |spawner| {
                Box::pin(async move {
                    let result = async {
                    engine.worker(&request.config.performance.worker, &request.cancel).await
                        .map_err(super::startup_error)?;
                    stage("request_admission", &request.cancel).await?;
                    let _claim = if reservation.is_some() {
                        reservation
                    } else if request.mode == Mode::Extract {
                        Some(Arc::new(engine.leases.reserve_request_async(request_id, request.origin,
                            &request.inputs, &request.cancel).await?))
                    } else { None };
                    stage("discovery", &request.cancel).await?;
                    let run = engine.prepare(request, ObserverRef::Owned(observer), request_id)?;
                    run.execute_request(spawner).await
                    }.await;
                    stage("report", &Cancellation::new()).await.expect("completion is not cancellable");
                    complete(result)
                })
            })
    }

    fn prepare<'a, O: Observer>(
        &self, mut request: Request, observer: ObserverRef<'a, O>, request_id: u64,
    ) -> io::Result<Arc<Run<'a, O>>> {
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
        let mut checkpoints: HashMap<CheckpointKey, Vec<usize>> = HashMap::new();
        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
            checkpoints.entry(checkpoint.key()).or_default().push(index);
        }
        let promoted_sources = request
            .promoted_sources
            .iter().enumerate()
            .map(|(index, source)| (path_key(&source.path().to_string_lossy()), index))
            .collect();
        let request = Arc::new(request);
        Ok(Arc::new(Run {
            engine: self.clone(),
            request: Arc::clone(&request),
            resolve_aliases,
            candidates,
            options,
            deep_options,
            analysis,
            observer,
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: Arc::clone(&self.output_names), owner: request_id },
            created_outputs: Mutex::default(),
            output_base,
            checkpoints,
            promoted_sources,
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
            cleanup_tasks: Mutex::default(),
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
    Borrowed(&'a O),
    Owned(Arc<O>),
}

impl<O> std::ops::Deref for ObserverRef<'_, O> {
    type Target = O;
    fn deref(&self) -> &O {
        match self { Self::Borrowed(value) => value, Self::Owned(value) => value }
    }
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
    recursion: RecursivePrompts,
    output_names: OutputReservationGuard,
    created_outputs: Mutex<CreatedOutputs>,
    output_base: Option<PathBuf>,
    checkpoints: HashMap<CheckpointKey, Vec<usize>>,
    promoted_sources: HashMap<String, usize>,
    scan_errors: Mutex<DirectoryReadErrors>,
    cleanup_tasks: Mutex<Vec<PendingCleanup>>,
}

enum RetryOutput<'a> {
    Recreate(&'a Path),
    Existing(&'a Path),
}

struct PendingCleanup {
    paths: Vec<PathBuf>,
    task: super::scheduling::Join<Outcome>,
}

/// One shared decision per depth, like main's prompt gates. Only the blocking
/// Observer interaction runs outside Rayon; all archive waiters use the existing
/// scheduler's Pending/Waker path and return their host admission slots.
#[derive(Default)]
struct RecursivePrompts {
    decisions: Arc<Mutex<HashMap<usize, Arc<RecursiveDecision>>>>,
    requests: OnceLock<mpsc::Sender<Option<RecursivePrompt>>>,
}

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
                let request = Some((depth, pending, Arc::clone(&decision)));
                if self.requests.get().expect("prompt service is running").send(request).is_err() {
                    decision.complete(false);
                }
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

struct ClosePrompts<'a> {
    send: mpsc::Sender<Option<RecursivePrompt>>,
    cancel: &'a Cancellation,
}

impl Drop for ClosePrompts<'_> {
    fn drop(&mut self) {
        // Also release the receiver if execution unwinds before its result.
        if std::thread::panicking() {
            self.cancel.cancel();
        }
        let _ = self.send.send(None);
    }
}

struct CancelPromptPanic<'a>(&'a Cancellation);

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
    indices: HashMap<String, OutputHistory>,
    history_order: VecDeque<String>,
    slots: HashMap<String, HashMap<String, usize>>,
    claimed: BTreeMap<String, OutputClaim>,
    owners: HashMap<u64, Vec<String>>,
}

const OUTPUT_HISTORY_LIMIT: usize = 256;

struct OutputHistory {
    next: usize,
    available: BTreeSet<usize>,
    observed: HashSet<String>,
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
    path: PathBuf,
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
    fn claim(&mut self, path: &Path, owner: u64, source: &Path) {
        let key = output_key(path);
        if !self.claimed.contains_key(&key) {
            self.owners.entry(owner).or_default().push(key.clone());
        }
        self.claimed.insert(key, OutputClaim {
            owner, source: resolved_key(source), path: path.to_owned(),
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
                    if let Some(history) = self.indices.get_mut(&family) {
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
        self.indices.clear();
        self.history_order.clear();
        self.slots.clear();
        crate::collections::trim_map(&mut self.indices);
        crate::collections::trim_map(&mut self.slots);
    }

    fn next_index(&mut self, family: &str) -> usize {
        if self.indices.contains_key(family) {
            self.history_order.retain(|key| key != family);
        } else {
            if self.indices.len() == OUTPUT_HISTORY_LIMIT {
                let old = self.history_order.pop_front().unwrap();
                let history = self.indices.remove(&old).unwrap();
                for path in history.observed {
                    if let Some(slots) = self.slots.get_mut(&path) {
                        slots.remove(&old);
                        if slots.is_empty() { self.slots.remove(&path); }
                    }
                }
            }
            self.indices.insert(family.to_owned(), OutputHistory { next: 1, available: BTreeSet::new(), observed: HashSet::new() });
        }
        self.history_order.push_back(family.to_owned());
        self.indices.get_mut(family).unwrap().take()
    }

    fn observe_slot(&mut self, path: &str, family: &str, index: usize) {
        if index != 0 {
            self.slots.entry(path.to_owned()).or_default().insert(family.to_owned(), index);
            self.indices.get_mut(family).unwrap().observed.insert(path.to_owned());
        }
    }

    fn has_under(&self, key: &str) -> bool {
        if self.claimed.contains_key(key) {
            return true;
        }
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        self.claimed.range(prefix.clone()..).next()
            .is_some_and(|(path, _)| path.starts_with(&prefix))
    }

    fn conflicting_ancestor(&self, path: &Path, owner: u64, input: Option<&Path>) -> Option<PathBuf> {
        let parent = output_key(path.parent()?);
        let input = input.map(output_key);
        // Check root-first, so rerouting leaves every unrelated owning tree.
        let ancestors: Vec<_> = crate::path_keys::path_ancestors(&parent).collect();
        for ancestor in ancestors.into_iter().rev() {
            if let Some(claim) = self.claimed.get(ancestor) {
                if claim.owner == owner && input.as_deref().is_some_and(|input| {
                    input == ancestor || input.strip_prefix(ancestor).is_some_and(|tail| tail.starts_with('\\'))
                }) {
                    continue;
                }
                return Some(claim.path.clone());
            }
        }
        None
    }

    fn retain(&mut self, path: &Path, owner: u64, source: &Path, input: Option<&Path>) -> bool {
        let key = output_key(path);
        // Several continued carrier segments share one container. Only the
        // same physical source in this request may reuse that exact claim.
        if self.claimed.get(&key).is_some_and(|claim| {
            claim.owner == owner && claim.source == resolved_key(source)
        }) {
            return true;
        }
        if self.conflicting_ancestor(path, owner, input).is_some() || self.has_under(&key) {
            return false;
        }
        self.claim(path, owner, source);
        true
    }

    fn reserve(
        registry: &Mutex<Self>, preferred: PathBuf, result: &ArchiveResult,
        observer: &impl Observer, owner: u64, input: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        loop {
            let path = match registry.lock().unwrap().plan(preferred.clone(), result, owner, input)? {
                Ok(path) => path,
                Err(failure) => return Ok(Err(failure)),
            };
            let claim_key = output_key(&path);
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
                        && fs::symlink_metadata(&path).is_ok()
                    {
                        continue;
                    }
                    if !creation_error { return Err(error); }
                    return Ok(Err(file_failure(error)));
                }
            }
        }
    }

    fn plan(
        &mut self, mut preferred: PathBuf, result: &ArchiveResult,
        owner: u64, input: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        // A different request may own an ancestor even though this leaf does
        // not exist. Number that ancestor, preserving the mirrored suffix.
        while let Some(ancestor) = self.conflicting_ancestor(&preferred, owner, input) {
            let (base, relative) = conflicting_output_base(
                &preferred, &output_key(&preferred), &output_key(&ancestor),
            )?;
            let mut index = 1;
            let replacement = loop {
                let candidate = numbered(base, index);
                let exists = match candidate.try_exists() {
                    Ok(exists) => exists,
                    Err(error) => return Ok(Err(file_failure(error))),
                };
                if !exists && !self.has_under(&output_key(&candidate)) {
                    break candidate;
                }
                index += 1;
            };
            preferred = replacement.join(relative);
        }
        let preferred_key = output_key(&preferred);
        // Always recheck the preferred unnumbered name, as main does. The
        // history only accelerates numbered alternatives across requests.
        let mut index = 0;
        loop {
            let path = if index == 0 { preferred.clone() } else { numbered(&preferred, index) };
            let candidate_key = output_key(&path);
            if self.has_under(&candidate_key) {
                self.observe_slot(&candidate_key, &preferred_key, index);
                index = self.next_index(&preferred_key);
                continue;
            }
            let exists = match path.try_exists() {
                Ok(exists) => exists,
                Err(error) => {
                    if index != 0 { self.indices.get_mut(&preferred_key).unwrap().release(index); }
                    return Ok(Err(file_failure(error)));
                }
            };
            if !exists {
                self.observe_slot(&candidate_key, &preferred_key, index);
                self.claim(&path, owner, &result.path);
                return Ok(Ok(path));
            }
            index = self.next_index(&preferred_key);
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
struct CreatedOutputs(BTreeMap<String, (PathBuf, ArchiveResult)>);

impl CreatedOutputs {
    fn register(&mut self, path: &Path, result: &ArchiveResult) {
        // Keep a small ownership receipt, not analysis plans, passwords, native
        // handles, or worker futures. Registration precedes worker execution.
        let archive = ArchiveResult {
            path: result.path.clone(),
            format: result.format.clone(),
            output: None,
            failure: None,
            files: 0,
            bytes: 0,
            encrypted: result.encrypted,
            depth: result.depth,
            offset: result.offset,
            end_offset: result.end_offset,
            volume_completeness: None,
            volume_attempts: None,
            source_paths: result.source_paths.clone(),
            password: None,
            discovery_source: result.discovery_source,
            damage_flags: None,
            partial: false,
            retained: false,
            recovered_complete_files: 0,
            promoted: false,
            promotion_original_path: None,
        };
        self.0.insert(output_key(path), (path.to_owned(), archive));
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
            if let Some((path, mut result)) = self.0.remove(&key) {
                let mapped = path.strip_prefix(source).map(|tail| destination.join(tail)).unwrap_or(path);
                if let Ok(tail) = result.path.strip_prefix(source) {
                    result.path = destination.join(tail);
                }
                for path in &mut result.source_paths {
                    if let Ok(tail) = path.strip_prefix(source) {
                        *path = destination.join(tail);
                    }
                }
                // Flattening a leaf into an already tracked root must retain
                // the original root owner's receipt rather than overwrite it.
                self.0.entry(output_key(&mapped)).or_insert((mapped, result));
            }
        }
    }

    fn rollback(&mut self, observer: &impl Observer, outcome: &mut Outcome) -> io::Result<()> {
        let mut visited = HashSet::new();
        let mut roots = HashSet::new();
        for (key, (path, _)) in &self.0 {
            if crate::path_keys::path_ancestors(key).any(|ancestor| visited.contains(ancestor)) {
                continue;
            }
            visited.insert(key.clone());
            match cleanup_owned_output(path) {
                Ok(()) => { roots.insert(key.clone()); }
                Err(error) => record_cleanup(outcome, path, "rollback", Err(error)),
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
        outcome.checkpoints.retain(|checkpoint| !checkpoint.has_output() || !discarded(checkpoint.output()));
        // Only retire recovery/WAL ownership for trees actually removed. A
        // journal failure is not a filesystem cleanup failure: propagate it,
        // but still finish independent notifications and outcome accounting.
        let mut observer_error = None;
        self.0.retain(|_, (path, archive)| {
            if !discarded(path) {
                return true;
            }
            match observer.discard_output(archive, path) {
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

struct Executed {
    planned_output: Option<PathBuf>,
    result: ArchiveResult,
    inventory: Option<NativeOutputInventory>,
    input: ArchiveInput,
}

impl<'run, O: Observer> Run<'run, O> {
    async fn execute_request(self: &Arc<Self>, spawner: Spawner<'run>) -> io::Result<Outcome> {
        let decisions = Arc::clone(&self.recursion.decisions);
        let _cancellation = self.request.cancel.subscribe(move || {
            let decisions: Vec<_> = decisions.lock().unwrap().values().cloned().collect();
            for decision in decisions { decision.complete(false); }
        });
        stage("discovery", &self.request.cancel).await?;
        let mut discovered = discovery::discover(&self.request, self.options_at(1)?, &self.candidates)?;
        if self.resolve_aliases { dedup_resolved_plans(&mut discovered.tasks); }
        // Request admission covers only the user's original selections, as in
        // main. Discovery may resolve different selections to one volume family;
        // claim_task serializes that family without rejecting either request.
        let executed = self.execute_batch(discovered, 1, None, None, spawner).await;
        self.finish(executed).await
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
                    }
                }),
        );
        Ok(outcome)
    }

    async fn drain_cleanup(&self, root: Option<&Path>, outcome: &mut Outcome) {
        let pending = {
            let mut tasks = self.cleanup_tasks.lock().unwrap();
            let mut selected = Vec::new();
            let mut index = 0;
            while index < tasks.len() {
                if root.is_none_or(|root| tasks[index].paths.iter().any(|path| relative_to(path, root).is_some())) {
                    selected.push(tasks.swap_remove(index));
                } else { index += 1; }
            }
            selected
        };
        for pending in pending {
            let mut cleanup = pending.task.wait().await;
            outcome.cleanup_results.append(&mut cleanup.cleanup_results);
            outcome.errors.append(&mut cleanup.errors);
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
        batch: Discovered,
        depth: usize,
        inherited_scope: Option<Arc<Path>>,
        parent: Option<(TaskId, &ArchiveResult)>,
        spawner: Spawner<'run>,
    ) -> io::Result<Outcome> {
        let mut outcome = Outcome {
            errors: batch.errors,
            scan_incomplete: self.record_scan_errors(batch.scan_errors),
            ..Outcome::default()
        };
        let children = spawner.clone();
        let parent_id = parent.map(|(id, _)| id);
        let owner = Arc::clone(self);
        let executed = spawner.bounded_map(batch.tasks, move |task| {
            let owner = Arc::clone(&owner);
            let this = Arc::clone(&owner);
            let children = children.clone();
            let scope = inherited_scope.clone();
            Box::pin(async move {
                // Reporting is part of the same admitted preflight stage.
                let cancelled = receipt(task.entry(), task.source, depth);
                let ready = stage("report", &Cancellation::new()).await;
                let id = owner.queue_task(task.entry(), depth, parent_id, None);
                let result = match ready {
                    Ok(()) => owner.execute_task(task, id, depth, scope, children).await,
                    Err(error) => Err(error),
                };
                let result = if depth == 1 { this.finish_root(id, &cancelled.path, result).await } else { result };
                (id, cancelled, result)
            })
        }).await;
        stage("report", &Cancellation::new()).await?;
        let mut first_error = None;
        for (id, mut cancelled, branch) in executed {
            let mut branch = match branch {
                Ok(branch) => branch,
                Err(error) if is_cancellation(&error) => {
                    cancelled.failure = Some(Failure::new(
                        FailureKind::Cancelled, "Operation interrupted",
                    ));
                    self.observer.notify(Event::Finished {
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
            if let Some(((_, parent), child)) = parent.zip(branch.archives.first()) {
                self.observer.archive_branch(parent, child);
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
            outcome
                .removed_promotion_dirs
                .append(&mut branch.removed_promotion_dirs);
        }
        first_error.map_or(Ok(outcome), Err)
    }

    async fn finish_root(&self, id: TaskId, path: &Path, result: io::Result<Outcome>) -> io::Result<Outcome> {
        if result.as_ref().is_ok_and(Outcome::settled) {
            stage("report", &Cancellation::new()).await?;
            let mut outcome = self.observer.root_finished(id, path, result.unwrap()).await?;
            if self.request.mode == Mode::Extract {
                outcome.compact_completed_extract();
            }
            Ok(outcome)
        } else { result }
    }

    fn queue_task(
        &self,
        input: &ArchiveInput,
        depth: usize,
        parent: Option<TaskId>,
        segment: Option<Segment>,
    ) -> TaskId {
        let id = self.engine.next_id();
        self.observer.notify(Event::Queued {
            id,
            parent,
            path: PathBuf::from(&input.entry_path),
            depth,
            segment,
        });
        id
    }

    fn record_scan_errors(&self, errors: DirectoryReadErrors) -> bool {
        if errors.is_empty() {
            return false;
        }
        self.scan_errors.lock().unwrap().merge_report(errors);
        true
    }

    fn execute_task(
        self: &Arc<Self>,
        mut task: Task,
        task_id: TaskId,
        depth: usize,
        inherited_scope: Option<Arc<Path>>,
        spawner: Spawner<'run>,
    ) -> super::scheduling::Task<'run, io::Result<Outcome>> {
        let owner = Arc::clone(self);
        Box::pin(async move {
            let this = &owner;
            let cancel = &this.request.cancel;
            cancel.check_io()?;
            stage("preflight", cancel).await?;
            let mut lease = this.claim_task(&task).await?;
            stage("preflight", cancel).await?;
            let mut outcome = Outcome::default();
            let mut shell = this.engine.shell.branch();
            let mut generations = this.capture_generations(&task);
            let discovered = task.source != DiscoverySource::Direct;
            let watch_root = depth == 1
                && this.request.origin == Origin::Watch
                && this.request.mode == Mode::Extract;
            if !this.should_process_task(&task, &generations, discovered, watch_root)? {
                this.observer.notify(Event::Skipped { id: task_id });
                return Ok(outcome);
            }
            this.observer.notify(Event::Started {
                id: task_id,
                path: PathBuf::from(&task.entry().entry_path),
                depth,
            });
            this.plan_inputs(&mut task)?;
            this.observer.claim_sources(
                Path::new(&task.entry().entry_path),
                &task.owned_paths,
                depth,
            )?;
            let owner_path = PathBuf::from(&task.entry().entry_path);
            let root_scope = owner_path.parent();
            let source_scope = inherited_scope.as_deref().or(root_scope);
            let candidates = this.candidates.with_scope(source_scope);
            let preferred_carrier = this.preferred_output(task.entry(), depth);
            let mut retained: Vec<_> = task
                .inputs
                .iter()
                .map(|logical| {
                    this.checkpoint_for(&logical.input, &generations, &preferred_carrier, depth, &candidates)
                })
                .collect();
            let mut split_input = task.entry().mode.structured() || task.entry().physical_paths().nth(1).is_some();
            let multi = task.inputs.len() > 1;
            let count = task.inputs.len();
            let ids: Vec<_> = task
                .inputs
                .iter()
                .enumerate()
                .map(|(index, logical)| {
                    if multi {
                        let extent = logical.input.physical_extents().next();
                        this.queue_task(
                            &logical.input,
                            depth,
                            Some(task_id),
                            Some(Segment {
                                format: logical.input.format_hint.clone(),
                                index: index + 1,
                                count,
                                offset: extent.map_or(0, |extent| extent.start),
                                end_offset: extent.and_then(|extent| extent.end),
                            }),
                        )
                    } else {
                        task_id
                    }
                })
                .collect();
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
                        match this.reserve_output(preferred_carrier, &receipt, None)? {
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
            let retry_slots: Vec<_> = task.inputs.iter().zip(&retained)
                .map(|(logical, checkpoint)| {
                    checkpoint.is_none().then(|| carrier.as_deref()
                        .and_then(|root| this.retry_slot_for(&logical.input, root))).flatten()
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
                    let mut names = this.output_names.registry.lock().unwrap();
                    let slot = previous.filter(|path| names.retain(
                        path, this.output_names.owner, Path::new(&logical.input.entry_path), Some(root),
                    ));
                    if let Some(slot) = slot {
                        planned_slots[index] = Some(slot.to_owned());
                    } else {
                        let result = receipt(&logical.input, task.source, depth);
                        match names.plan(root.join(archive_name(&logical.input)), &result,
                            this.output_names.owner, Some(root))?
                        {
                            Ok(slot) => planned_slots[index] = Some(slot),
                            Err(failure) => { logical.failure.get_or_insert(failure); }
                        }
                    }
                }
            }
            let mut completed = Vec::with_capacity(task.inputs.len());
            let mut outputs_committed = true;
            let mut carrier_children_complete = true;
            let mut children = Outcome::default();
            let mut parent_outputs = Vec::with_capacity(count);
            let retry = task.retry.filter(|_| task.inputs.len() == 1);
            let mut promotion_sources = task.owned_paths;
            let mut superseded_candidates = HashSet::new();
            for (index, (((logical, checkpoint), retry_slot), &id)) in
                task.inputs.into_iter().zip(retained.drain(..)).zip(retry_slots).zip(&ids).enumerate()
            {
                if multi {
                    this.observer.notify(Event::Started {
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
                let remaining_depth = this
                    .request
                    .max_depth
                    .saturating_sub(depth.saturating_sub(1));
                let mut children_already_complete = checkpoint
                    .is_some_and(|checkpoint| checkpoint.children_complete(remaining_depth));
                let mut executed = if let Some(checkpoint) = checkpoint {
                    let mut input = logical.input;
                    checkpoint.restore_input(&mut input);
                    let mut result = checkpoint.result(depth);
                    if multi && checkpoint.container() != carrier.as_deref() && result.failure.is_some() {
                        // A purely failed old carrier is not a reusable output
                        // root. Carry its logical failure, not its output slot.
                        result.output = None;
                    }
                    let previously_partial = result.partial;
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
                    if result.partial && !previously_partial {
                        // A rejected retained segment never scanned its children.
                        children_already_complete = false;
                    }
                    let inventory = if children_already_complete || (result.failure.is_some() && !result.partial) {
                        None
                    } else {
                        result
                            .output
                            .as_ref()
                            .map(|path| scan_output_inventory_impl(&path.to_string_lossy()))
                    };
                    Executed {
                        planned_output: result.output.clone(),
                        input,
                        result,
                        inventory,
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
                    stage("missing_volume", cancel).await?;
                    if let Some(mut replacement) = discovery::retry_volume(
                        &executed.result,
                        context,
                        this.options_at(depth)?,
                        &candidates,
                        &this.request,
                    )? {
                        // Main replaces the whole single-input extraction only
                        // after resolving a usable physical family. Until then,
                        // its damaged payload remains available for recovery.
                        let retry_output = executed.planned_output.clone();
                        let cleaned = match retry_output.as_deref() {
                            Some(output) => this.discard_failed_output(&executed.result, output, &mut outcome)?,
                            None => true,
                        };
                        if cleaned {
                            executed.result.output = None;
                            this.observer.after_output(&executed.result)?;
                            drop(lease);
                            lease = this.claim_task(&replacement).await?;
                            stage("preflight", cancel).await?;
                            generations = this.capture_generations(&replacement);
                            if !this.should_process_task(&replacement, &generations, discovered, watch_root)? {
                                this.observer.notify(Event::Skipped { id: task_id });
                                return Ok(outcome);
                            }
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
                    planned_output: _,
                    mut result,
                    inventory,
                    mut input,
                } = executed;
                if this.request.mode == Mode::Scan {
                    result.volume_attempts = input.volume_attempts.take();
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
                // Segment progress ends with its own extraction, as main's
                // input_finished does. Physical root completion still waits
                // for every recursive subtree and the final source cleanup.
                if multi {
                    this.observer.notify(Event::Finished {
                        id,
                        path: result.path.clone(),
                        depth,
                        result: super::TaskCompletion::from_result(&result),
                    });
                }
                parent_outputs.push((result, inventory, input, id, children_already_complete, remaining_depth));
            }
            // Main retains best-effort bytes per input before applying the
            // physical carrier's content policy. A complete sibling keeps
            // failed siblings' salvage, without accepting them for recursion.
            if this.request.config.extraction.content_requirement == ContentRequirement::Complete
                && !parent_outputs.iter().any(|(result, ..)| result.failure.is_none())
            {
                for (result, inventory, ..) in &mut parent_outputs {
                    if let Some(output) = result.output.clone() {
                        if this.discard_failed_output(result, &output, &mut outcome)? {
                            result.output = None;
                            result.files = 0;
                            result.bytes = 0;
                            result.recovered_complete_files = 0;
                        }
                    }
                    *inventory = None;
                }
            }
            // Finish every logical parent before prompting or descending into
            // any segment. Independent output trees share the existing request
            // consumer budget rather than serializing behind the first subtree.
            let mut recursive = Vec::new();
            let mut descendants = Vec::with_capacity(count);
            for (index, (result, inventory, input, id, children_already_complete, remaining_depth)) in parent_outputs.into_iter().enumerate() {
                if inventory.is_some() && depth <= this.request.max_depth && !cancel.cancelled() {
                    recursive.push((index, result, inventory, input, id, children_already_complete, remaining_depth));
                } else {
                    descendants.push((index, Ok((result, input, children_already_complete, remaining_depth, Outcome::default(), false))));
                }
            }
            let recursive_spawner = spawner.clone();
            let scope: Option<Arc<Path>> = source_scope.map(Arc::from);
            let descendant_owner = Arc::clone(this);
            let descend = move |(index, result, inventory, input, id, children_already_complete, remaining_depth): (usize, ArchiveResult, Option<NativeOutputInventory>, ArchiveInput, TaskId, bool, usize)| -> super::scheduling::Task<'_, _> {
                let descendant_owner = Arc::clone(&descendant_owner);
                let spawner = recursive_spawner.clone();
                let scope = scope.clone();
                Box::pin(async move {
                    let this = &descendant_owner;
                    let branch = async {
                        let candidates = this.candidates.with_scope(scope.as_deref());
                        let mut descendants = Outcome::default();
                        let mut ran_recursive_children = false;
                        if let Some(inventory) = inventory {
                            let (nested, scanned) =
                                this.discover_children(inventory, depth, &candidates).await?;
                            ran_recursive_children = scanned;
                            if scanned {
                                descendants = this.execute_batch(
                                    nested, depth + 1, scope.clone(), Some((id, &result)), spawner,
                                ).await?;
                            } else {
                                descendants.errors.extend(nested.errors);
                                descendants.scan_incomplete = this.record_scan_errors(nested.scan_errors);
                            }
                        }
                        Ok::<_, io::Error>((result, input, children_already_complete, remaining_depth, descendants, ran_recursive_children))
                    }.await;
                    (index, branch)
                })
            };
            // A normal single-output archive keeps its existing consumer. Only
            // independently recursive carrier outputs need another batch; failed,
            // already-complete and depth-limited segments consume no extra slots.
            if recursive.len() == 1 {
                descendants.push(descend(recursive.pop().unwrap()).await);
            } else if !recursive.is_empty() {
                descendants.extend(spawner.bounded_map(recursive, descend).await);
            }
            // Join every writer before committing or cleaning up, then restore
            // logical segment order, including segments with no recursive work.
            descendants.sort_unstable_by_key(|(index, _)| *index);
            for (index, descendant) in descendants {
                let (mut result, input, children_already_complete, remaining_depth, mut descendants, ran_recursive_children) = descendant?;
                stage("output_state", &Cancellation::new()).await?;
                let mut children_complete = children_already_complete
                    || (!cancel.cancelled() && subtree_complete(&descendants));
                if ran_recursive_children
                    && result.failure.is_none()
                    && children_complete
                    && !cancel.cancelled()
                {
                    if let Some(output) = result.output.as_deref() {
                        this.drain_cleanup(Some(output), &mut descendants).await;
                        stage("postprocess", cancel).await?;
                        if remove_empty_or_promoted(output, &descendants.removed_promotion_dirs) {
                            this.observer.discard_output(&result, output)?;
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
                        &*this.observer, &mut result, &mut descendants, Some(&this.created_outputs),
                    )?;
                    children_complete &= subtree_complete(&descendants);
                }
                carrier_children_complete &= children_complete;
                let mut checkpoint = if this.request.mode == Mode::Extract {
                    InputCheckpoint::create(
                        &owner_path,
                        &input,
                        &result,
                        &generations,
                        carrier.as_deref(),
                        children_complete,
                        remaining_depth,
                    )
                } else {
                    None
                };
                if let Some(checkpoint) = &mut checkpoint {
                    checkpoint.set_planned_output(planned_slots[index].as_deref());
                    checkpoint.set_password_signature(|| candidates.signature(&input.entry_path));
                }
                // A cancelled newly created root remains uncommitted until
                // request-level rollback has joined all recursive writers.
                let commit_completed = !cancel.cancelled();
                outputs_committed &= commit_completed || result.retained || result.output.is_none();
                if commit_completed || result.retained {
                    this.observer.commit_output(&result, checkpoint.as_ref())?;
                    // Cancellation after this durable commit must not roll it
                    // back. Match main's commit/check then retire ordering.
                    if commit_completed && !multi {
                        if let Some(output) = result.output.as_deref() {
                            this.created_outputs.lock().unwrap().commit_if_unowned(output);
                        }
                    }
                }
                if let Some(checkpoint) = checkpoint {
                    outcome.checkpoints.push(checkpoint);
                }
                outcome.checkpoints.append(&mut descendants.checkpoints);
                outcome
                    .promoted_sources
                    .append(&mut descendants.promoted_sources);
                outcome
                    .removed_promotion_dirs
                    .append(&mut descendants.removed_promotion_dirs);
                children.archives.append(&mut descendants.archives);
                children.errors.append(&mut descendants.errors);
                children.scan_incomplete |= descendants.scan_incomplete;
                children.uncommitted |= descendants.uncommitted;
                children
                    .cleanup_results
                    .append(&mut descendants.cleanup_results);
                completed.push(result);
            }
            // Only the final carrier namespace is flattened. Individual segment
            // layouts remain intact while any input or recursive subtree may resume.
            if multi && outputs_committed && carrier_children_complete
                && completed.iter().all(|result| result.failure.is_none() && !result.retained)
                && this.request.config.post_extract.flatten_single_directory
                && !cancel.cancelled()
            {
                if let Some(root) = carrier.clone().filter(|_| completed.iter().any(|result| result.output.is_some())) {
                    this.drain_cleanup(Some(&root), &mut children).await;
                    stage("postprocess", cancel).await?;
                    let child_count = children.archives.len();
                    children.archives.append(&mut completed);
                    children.checkpoints.append(&mut outcome.checkpoints);
                    let input = ArchiveInput::file(owner_path.to_string_lossy().into_owned(), String::new(), String::new());
                    let mut container = receipt(&input, task.source, depth);
                    container.output = Some(root.clone());
                    let flattened = flatten_result(&*this.observer, &mut container, &mut children, Some(&this.created_outputs));
                    completed = children.archives.split_off(child_count);
                    outcome.checkpoints.append(&mut children.checkpoints);
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
                    let published = this.observer.commit_output(first, None);
                    first.output = segment;
                    published?;
                }
                let mut created = this.created_outputs.lock().unwrap();
                if let Some(root) = carrier.as_deref() {
                    created.commit_if_unowned(root);
                }
                for output in completed.iter().filter_map(|result| result.output.as_deref()) {
                    created.commit_if_unowned(output);
                }
            }
            if !superseded_candidates.is_empty() {
                let retained: HashSet<_> = completed
                    .iter()
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
            }
            if let Some(root) = &carrier {
                if completed.iter().all(|entry| entry.output.is_none()) {
                    if remove_empty_or_promoted(root, &outcome.removed_promotion_dirs) {
                        if let Some(result) = completed.first() {
                            this.observer.discard_output(result, root)?;
                        }
                    }
                }
            }
            if depth > 1
                && !cancel.cancelled()
                // Accepted partial segments do not make a carrier successful
                // when a sibling failed. Only an entirely accepted carrier
                // stays in place; promotion retains its sibling outputs.
                && completed.iter().any(|result| result.failure.is_some() && !result.partial)
                && completed.iter().any(|result| {
                    result.failure.as_ref().is_some_and(|failure| {
                        failure.is_password_retry() || failure.contains(FailureKind::MissingVolume)
                    })
                })
            {
                let destination = this.promotion_directory(source_scope.unwrap_or(Path::new(".")));
                this.promote_blocked(
                    &promotion_sources,
                    &destination,
                    &generations,
                    &mut completed,
                    &mut outcome,
                    &mut shell,
                )
                .await?;
            }
            // Cleanup belongs to this physical source family, not its output
            // descendants. A failed/partial inner archive must keep its own
            // source, but does not revoke a fully extracted outer source.
            let sources_complete = completed
                .iter()
                .all(|result| result.failure.is_none() && !result.partial)
                && !cancel.cancelled();
            let complete = sources_complete && subtree_complete(&children);
            // A Watch request may have been admitted before another batch moved
            // these members. The source leases now cover the actual resolved family.
            let admitted_promoted: Vec<_> = promotion_sources
                .iter()
                .filter_map(|path| {
                    this.admitted_promotion(path, &generations, watch_root)
                        .map(|source| (path, source))
                })
                .collect();
            if sources_complete && this.request.mode == Mode::Extract {
                if watch_root && complete {
                    stage("output_state", &Cancellation::new()).await?;
                    this.observer.sources_processed(&completed, &generations)?;
                }
                let mode = if depth > 1 { CleanupMode::Delete }
                    else { this.request.config.post_extract.archive_cleanup_mode };
                let generated: HashSet<_> = admitted_promoted.iter().map(|(path, _)| (*path).clone()).collect();
                let mut deletes = Vec::new();
                let mut recycles = Vec::new();
                for path in &promotion_sources {
                    if mode == CleanupMode::Delete || generated.contains(path) {
                        deletes.push(PathBuf::from(path));
                    } else if mode == CleanupMode::Recycle {
                        recycles.push(PathBuf::from(path));
                    }
                }
                dedup_paths(&mut deletes);
                dedup_paths(&mut recycles);
                let paths = deletes.iter().chain(&recycles).cloned().collect();
                let cleanup = Arc::clone(&this);
                let task = spawner.spawn(Box::pin(async move {
                    // The family lease outlives its archive consumer, until the
                    // background deletion/recycle has released its sources.
                    let _lease = lease;
                    let mut outcome = Outcome::default();
                    if deletes.is_empty() && recycles.is_empty() { return outcome; }
                    if stage("background_source_cleanup", &cleanup.request.cancel).await.is_err() {
                        return outcome;
                    }
                    let mut shell = cleanup.engine.shell.branch();
                    cleanup.cleanup_sources(&recycles, &generations, CleanupMode::Recycle, &mut outcome, &mut shell);
                    cleanup.cleanup_sources(&deletes, &generations, CleanupMode::Delete, &mut outcome, &mut shell);
                    outcome
                }));
                this.cleanup_tasks.lock().unwrap().push(PendingCleanup { paths, task });
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
                    this.observer.notify(Event::Finished {
                        id, path: result.path.clone(), depth,
                        result: super::TaskCompletion::from_result(result),
                    });
                }
            }
            if let Some(result) = completed.first() {
                this.observer.notify(Event::Finished {
                    id: task_id,
                    path: if multi {
                        owner_path
                    } else {
                        result.path.clone()
                    },
                    depth,
                    result: super::TaskCompletion::from_group(&completed),
                });
            }
            outcome.archives.extend(completed);
            outcome.archives.append(&mut children.archives);
            outcome.errors.append(&mut children.errors);
            outcome.scan_incomplete |= children.scan_incomplete;
            outcome
                .cleanup_results
                .append(&mut children.cleanup_results);
            outcome.uncommitted = !outputs_committed || children.uncommitted;
            if depth == 1 && this.request.mode == Mode::Extract && !cancel.cancelled() {
                outcome.archives = this
                    .observer
                    .scope_finished(task_id, std::mem::take(&mut outcome.archives))
                    .await?;
            }
            Ok(outcome)
        })
    }

    fn promotion_directory(&self, original_directory: &Path) -> PathBuf {
        self.request
            .inputs
            .iter()
            .filter_map(|path| std::path::absolute(path).ok())
            .filter(|path| path.is_dir() && relative_to(original_directory, path).is_some())
            .max_by_key(|path| path.components().count())
            .unwrap_or_else(|| original_directory.to_path_buf())
    }

    async fn promote_blocked(
        &self,
        sources: &[String],
        destination: &Path,
        generations: &HashMap<String, PhysicalFileGeneration>,
        results: &mut [ArchiveResult],
        outcome: &mut Outcome,
        shell: &mut ShellUpdates<'_>,
    ) -> io::Result<()> {
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
            for source in sources {
                let before = generations.get(&path_key(source)).ok_or_else(|| {
                    io::Error::other("promotion source has no admitted generation")
                })?;
                if capture_file_generation(Path::new(source))? != *before {
                    return Err(io::Error::other("promotion source generation changed"));
                }
            }
            loop {
                self.request.cancel.check_io()?;
                let plan =
                    NativeBlockedInputPromotion::new(sources.to_vec(), destination.to_path_buf())?;
                let keys = plan
                    .moves()
                    .iter()
                    .map(|(_, target)| resolved_key(target))
                    .collect();
                let _destinations = self
                    .engine
                    .leases
                    .acquire(keys, &self.request.cancel)
                    .await?;
                stage("promotion", &self.request.cancel).await?;
                let _promotion = Promotion::begin(sources.to_vec())?;
                let (residual, removed, _, error, collision) = plan.execute(|| {
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
                outcome
                    .removed_promotion_dirs
                    .extend(removed.iter().map(|path| path_key(path)));
                return Ok((
                    moves,
                    receipts,
                    success,
                    (!error.is_empty()).then_some(error),
                ));
            }
        }
        .await;
        match promoted {
            Ok((moves, receipts, success, error)) => {
                outcome.promoted_sources.extend(receipts);
                let paths = PromotionPaths::new(&moves);
                for result in results {
                    if success {
                        result.promotion_original_path = Some(result.path.clone());
                    }
                    paths.remap(&mut result.path);
                    for source in &mut result.source_paths {
                        paths.remap(source);
                    }
                    result.promoted = success;
                    if !success {
                        result.failure = Some(Failure::new(
                            FailureKind::FilesystemError,
                            format!(
                                "Unable to promote blocked nested input: {}",
                                error.as_deref().unwrap_or("unknown move failure")
                            ),
                        ).with_cause(result.failure.take()));
                    }
                }
                for checkpoint in &mut outcome.checkpoints {
                    if checkpoint.promoted(&paths)? {
                        self.observer.checkpoint(checkpoint)?;
                    }
                }
            }
            Err(error) if self.request.cancel.cancelled() => return Err(error),
            Err(error) => {
                results[representative].failure = Some(Failure::new(
                    FailureKind::FilesystemError,
                    format!("Unable to promote blocked nested input: {error}"),
                ).with_cause(results[representative].failure.take()));
            }
        }
        Ok(())
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

    fn checkpoint_for(
        &self,
        input: &ArchiveInput,
        generations: &HashMap<String, PhysicalFileGeneration>,
        preferred_carrier: &Path,
        depth: usize,
        candidates: &CandidateSet,
    ) -> Option<&InputCheckpoint> {
        if self.request.mode != Mode::Extract {
            return None;
        }
        let preferred = self.preferred_output(input, depth);
        self.checkpoints
            .get(&CheckpointKey::for_input(input))?
            .iter()
            .find_map(|&index| {
                let checkpoint = &self.request.checkpoints[index];
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
                    None => output_candidate(&preferred, checkpoint.output()),
                };
                if !destination_matches {
                    return None;
                }
                let mut names = self.output_names.registry.lock().unwrap();
                let source = Path::new(&input.entry_path);
                let nested = (depth > 1).then_some(source);
                if let Some(container) = checkpoint.container() {
                    // The physical task owns the container even when its logical
                    // segments start in different files of the volume family.
                    if !names.retain(container, self.output_names.owner, checkpoint.carrier(), nested) {
                        return None;
                    }
                }
                names.retain(checkpoint.output(), self.output_names.owner, source,
                    checkpoint.container().or(nested)).then_some(checkpoint)
            })
    }

    fn retry_slot_for(&self, input: &ArchiveInput, carrier: &Path) -> Option<&InputCheckpoint> {
        self.checkpoints.get(&CheckpointKey::for_input(input))?
            .iter().find_map(|&index| {
                let checkpoint = &self.request.checkpoints[index];
                if !checkpoint.output_slot_for(input, carrier) { return None; }
                // The root was retained through an unchanged sibling above.
                // Claim only this logical child, never delete the carrier root.
                self.output_names.registry.lock().unwrap().retain(
                    checkpoint.output_slot().expect("matching output slot"), self.output_names.owner,
                    Path::new(&input.entry_path), Some(carrier),
                ).then_some(checkpoint)
            })
    }

    async fn claim_task(&self, task: &Task) -> io::Result<Lease> {
        let keys = task
            .owned_paths
            .iter()
            .map(|path| resolved_key(Path::new(path)))
            .collect();
        self.engine.leases.acquire(keys, &self.request.cancel).await
    }

    fn capture_generations(&self, task: &Task) -> HashMap<String, PhysicalFileGeneration> {
        if self.request.mode != Mode::Extract {
            return HashMap::new();
        }
        task.owned_paths
            .iter()
            .filter_map(|path| {
                capture_file_generation(Path::new(path))
                    .ok()
                    .map(|generation| (path_key(path), generation))
            })
            .collect()
    }

    fn should_process_task(
        &self,
        task: &Task,
        generations: &HashMap<String, PhysicalFileGeneration>,
        discovered: bool,
        watch_root: bool,
    ) -> io::Result<bool> {
        // A discovered proposal can depart while waiting for its physical lease.
        // Explicit direct inputs still take the ordinary open/failure path.
        // Keep the original proposal's eligibility through volume replacement;
        // finding a relation later does not turn a Direct task into discovery.
        if discovered && task.owned_paths.iter().all(|path| {
            !generations.contains_key(&path_key(path))
                && Path::new(path).try_exists().is_ok_and(|exists| !exists)
        }) {
            return Ok(false);
        }
        if !watch_root {
            return Ok(true);
        }
        let data_paths: Vec<_> = task
            .inputs
            .iter()
            .flat_map(|logical| {
                let input = &logical.input;
                let whole_file = input.parts.is_empty() && input.ranges.is_empty();
                input
                    .physical_extents()
                    .map(|extent| extent.path.as_str())
                    .chain(whole_file.then_some(input.entry_path.as_str()))
            })
            .collect();
        self.observer.should_process_sources(
            Path::new(&task.entry().entry_path),
            &data_paths,
            generations,
        )
    }

    fn plan_inputs(&self, task: &mut Task) -> io::Result<()> {
        if task.inputs.len() != 1 || task.inputs[0].failure.is_some() {
            return Ok(());
        }
        let original = &mut task.inputs[0];
        let structure_only =
            original.input.format_hint == "lz4" && !original.input.analysis.structure_complete;
        if task.source != DiscoverySource::Direct && !structure_only {
            return Ok(());
        }
        let report = match analyze_input(&original.input, &self.analysis, None, true) {
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
        original.input.analysis = report.facts;
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
        let (projected, _) = archive_input_slices(&original.input, &slices)?;
        let logical: Vec<_> = projected
            .into_iter()
            .zip(selected)
            .filter_map(|(input, segment)| {
                let mut input = input?;
                input.analysis.zip_eocd_offset = segment.zip_eocd_offset;
                input.analysis.password_required = segment.password_required;
                input.analysis.damage_flags = segment.damage_flags;
                input.analysis.structure_complete = input.format_hint == "lz4";
                Some(LogicalInput {
                    input,
                    password: None,
                    failure: None,
                })
            })
            .collect();
        if !logical.is_empty() {
            task.inputs = logical;
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
                input,
            });
        }
        if self.request.cancel.cancelled() {
            result.failure = Some(Failure::new(FailureKind::Cancelled, "Operation interrupted"));
            return Ok(Executed { planned_output: None, result, inventory: None, input });
        }
        stage("preflight", &self.request.cancel).await?;
        let plan = match candidates.plan(&input, password, &self.request.cancel) {
            Ok(Ok(plan)) => plan,
            Ok(Err(failure)) => {
                result.failure = Some(failure);
                return Ok(Executed {
                    planned_output: None,
                    result,
                    inventory: None,
                    input,
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
                return Ok(Executed {
                    planned_output: None,
                    result,
                    inventory: None,
                    input,
                });
            }
        };
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
                            Err(file_failure(error))
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
                    result.failure = Some(failure);
                    return Ok(Executed {
                    planned_output: None,
                        result,
                        inventory: None,
                        input,
                    });
                }
            }
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
        self.observer.notify(Event::Waiting { id });
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
        self.observer.notify(Event::Finalizing { id });
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
                    let split = input.mode.structured() || input.physical_paths().nth(1).is_some();
                    let mut failure = classify_worker_failure(value, plan.evidence, split);
                    if failure.kind == FailureKind::WrongPassword && !plan.has_candidates {
                        failure = Failure::password_required();
                    }
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
                                result.partial = accepts_partial_content(
                                    self.request.config.extraction.content_requirement,
                                    failure.kind, verified_files as u64,
                                );
                                result.files = stats.file_count() as u64;
                                result.recovered_complete_files = verified_files as u64;
                                result.bytes = stats.total_size();
                                result.output = Some(output.clone());
                                if result.partial {
                                    inventory = Some(stats);
                                }
                            }
                        }
                    }
                    failure.evidence = worker_evidence(value, frame.recovery.take(), plan.evidence);
                    result.failure = Some(failure);
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

    fn discard_failed_output(
        &self, result: &ArchiveResult, path: &Path, outcome: &mut Outcome,
    ) -> io::Result<bool> {
        if let Err(error) = cleanup_owned_output(path) {
            // Physical deletion is local to this failed archive. Keep its
            // durable guard, but do not discard the other logical results.
            record_cleanup(outcome, path, "delete", Err(error));
            return Ok(false);
        }
        self.observer.discard_output(result, path)?;
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
            Failure::new(FailureKind::ProcessError, error.to_string())
        } else {
            file_failure(error)
        }
    }

    async fn discover_children(
        &self,
        inventory: NativeOutputInventory,
        depth: usize,
        candidates: &CandidateSet,
    ) -> io::Result<(Discovered, bool)> {
        let mut nested = Discovered::default();
        if depth > self.request.max_depth || self.request.cancel.cancelled() {
            return Ok((nested, false));
        }
        stage("nested_scan", &self.request.cancel).await?;
        let output = discovery::OutputDiscovery::prepare(inventory, self.filtered_options()?)?;
        nested.scan_errors.extend(output.scan_errors());
        // Main asks once per depth when the filtered output has files, even if
        // discovery will find no archives or nested authorization rejects them.
        // Never do relation/embedded detection or password work before consent.
        // One logical output root is pending; its archive count is not known yet.
        let scan = output.has_files() && self.allow_recursive(depth + 1, 1).await;
        if scan {
            stage("discovery", &self.request.cancel).await?;
            if let Err(error) = output.discover(candidates, &self.request, &mut nested) {
                if !is_cancellation(&error) {
                    return Err(error);
                }
                nested.tasks.clear();
            }
        }
        Ok((nested, scan))
    }

    async fn allow_recursive(&self, depth: usize, pending: usize) -> bool {
        if self.request.config.recursive_extract != Recursion::Prompt {
            return true;
        }
        let inline = matches!(self.observer, ObserverRef::Owned(_))
            .then_some(|depth, pending| self.observer.allow_recursive_async(depth, pending));
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
                Ok(Err(file_failure(error)))
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
        generations: &HashMap<String, PhysicalFileGeneration>,
        cleanup: CleanupMode,
        outcome: &mut Outcome,
        shell: &mut ShellUpdates<'_>,
    ) {
        let mode = match cleanup {
            CleanupMode::Keep => unreachable!("keep needs no source cleanup"),
            CleanupMode::Delete => "delete",
            CleanupMode::Recycle => "recycle",
        };
        let mut valid = Vec::new();
        for path in paths {
            match capture_file_generation(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => record_cleanup(outcome, path, mode, Err(error)),
                Ok(current) => {
                    let key = path_key(&path.to_string_lossy());
                    if generations
                        .get(&key)
                        .is_some_and(|before| before == &current)
                    {
                        valid.push(path);
                    }
                }
            }
        }
        if valid.is_empty() {
            return;
        }
        let keys = valid
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let _promotion = match Promotion::begin(keys) {
            Ok(promotion) => promotion,
            Err(error) => {
                for path in valid {
                    let copy = error.raw_os_error().map(io::Error::from_raw_os_error)
                        .unwrap_or_else(|| io::Error::new(error.kind(), error.to_string()));
                    record_cleanup(outcome, path, mode, Err(copy));
                }
                return;
            }
        };
        for path in valid {
            let removed = match cleanup {
                CleanupMode::Delete => remove_owned_file(path),
                CleanupMode::Recycle => super::cleanup::recycle(std::iter::once(path.as_path())),
                CleanupMode::Keep => unreachable!("keep produced receipts without filesystem work"),
            };
            if removed.is_ok() {
                shell.parent(path);
            }
            record_cleanup(outcome, path, mode, removed);
        }
    }
}

fn flatten_result(
    observer: &impl Observer,
    result: &mut ArchiveResult,
    children: &mut Outcome,
    created: Option<&Mutex<CreatedOutputs>>,
) -> io::Result<()> {
    let Some(output) = result.output.as_ref() else {
        return Ok(());
    };
    let attempt = || -> io::Result<_> {
        let mut work = output.as_os_str().to_os_string();
        work.push(".__sunpack_flatten_work__");
        let work = PathBuf::from(work);
        let mut available = work.clone();
        let mut index = 1;
        while available.try_exists()? {
            available = numbered(&work, index);
            index += 1;
        }
        let _promotion = Promotion::begin(vec![output.to_string_lossy().into_owned()])?;
        Ok(flatten_single_branch_directories(
            output,
            Some(&available),
            |root, work, leaf| observer.before_flatten(root, work, leaf),
            None,
        ))
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
        observer.after_flatten(&old, &new)?;
        // Successful flatten commonly keeps the root spelling unchanged while
        // moving its leaf's descendants. Rebase rollback receipts with the same
        // mapping as checkpoints, before any fallible durable publication.
        if let Some(created) = created {
            created.lock().unwrap().relocate(&old, &new);
        }
        for checkpoint in &mut children.checkpoints {
            checkpoint.relocate_flatten(&old, &new);
            observer.checkpoint(checkpoint)?;
        }
        for child in &mut children.archives {
            if let Some(path) = child.output.as_mut() {
                super::relocate_flatten_output(path, &old, &new);
            }
        }
        for receipt in &mut children.cleanup_results {
            if let Ok(suffix) = receipt.path.strip_prefix(&old) {
                receipt.path = new.join(suffix);
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
    let Err(error) = removed else {
        return;
    };
    if error.kind() == io::ErrorKind::NotFound {
        return;
    }
    let message = error.to_string();
    outcome.errors.push(InputError {
        path: path.to_path_buf(),
        message: message.clone(),
        kind: InputErrorKind::Cleanup,
        scan_operation: None,
        scan_count: None,
    });
    outcome.cleanup_results.push(CleanupResult {
        path: path.to_path_buf(),
        mode,
        status: CleanupStatus::Failed,
        error_code: error.raw_os_error().unwrap_or(0),
        message,
    });
}

fn receipt(input: &ArchiveInput, source: DiscoverySource, depth: usize) -> ArchiveResult {
    let extent = input.physical_extents().next();
    let mut source_paths = input.physical_paths().map(PathBuf::from).collect();
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
        promotion_original_path: None,
    }
}

fn file_failure(error: io::Error) -> Failure {
    let original = error.get_ref().and_then(|inner| inner.downcast_ref::<super::OutputCreateError>())
        .map_or(&error, |created| &created.0);
    let kind = if crate::io::resource_error::is_memory_error(original) {
        FailureKind::ResourceUnavailable
    } else {
        FailureKind::FilesystemError
    };
    Failure::new(kind, error.to_string())
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
    let weak_failure = weak_password_failure(result, password_evidence);
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

fn remove_empty_or_promoted(output: &Path, promoted_dirs: &[String]) -> bool {
    match fs::remove_dir(output) {
        Ok(()) => true,
        // The native promotion already removed this exact empty directory.
        // An unrelated disappearance still fails output receipt validation.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            promoted_dirs.contains(&path_key(&output.to_string_lossy()))
        }
        Err(_) => false,
    }
}

fn subtree_complete(outcome: &Outcome) -> bool {
    !outcome.scan_incomplete
        // Source deletion/recycling warnings do not invalidate extraction, but
        // a failed namespace flatten must stop ancestors from flattening it.
        && !outcome.cleanup_results.iter().any(|cleanup|
            cleanup.mode == "flatten" && cleanup.status == CleanupStatus::Failed)
        && !outcome
            .errors
            .iter()
            .any(|error| error.kind != InputErrorKind::Cleanup)
        && outcome
            .archives
            .iter()
            .all(|archive| (archive.failure.is_none() && !archive.partial) || archive.promoted)
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

fn dedup_resolved_plans(tasks: &mut Vec<Task>) {
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
    let _promotion = Promotion::begin(vec![path.to_string_lossy().into_owned()])?;
    remove_owned_tree(path)
}

struct Promotion(u64);

impl Promotion {
    fn begin(paths: Vec<String>) -> io::Result<Self> {
        let guard = Self(native_begin_promotion(paths.clone())?);
        release_reader_resources_under_roots(paths.clone())?;
        native_wait_for_resources(paths, false)?;
        Ok(guard)
    }
}

impl Drop for Promotion {
    fn drop(&mut self) {
        let _ = native_end_promotion(self.0);
    }
}

#[derive(Default)]
struct Leases {
    state: Mutex<LeaseState>,
}

#[derive(Default)]
struct LeaseState {
    active: HashSet<String>,
    requests: HashMap<u64, RequestClaim>,
    next_waiter: u64,
    waiters: HashMap<u64, LeaseWaiter>,
    blocked_by: HashMap<LeaseBlocker, HashSet<u64>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum LeaseBlocker {
    Request(u64),
    Path(String),
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
    paths: HashMap<String, PathBuf>,
    has_aliases: bool,
    directories: HashSet<String>,
    objects: HashSet<(u64, [u8; 16])>,
}

impl RequestClaim {
    fn new(origin: Origin) -> Self {
        Self {
            origin,
            paths: HashMap::new(),
            has_aliases: false,
            directories: HashSet::new(),
            objects: HashSet::new(),
        }
    }

    fn add(&mut self, input: ClaimedInput) {
        if input.directory {
            self.directories
                .insert(input.key.trim_end_matches('\\').to_owned());
        }
        if let Some(identity) = input.object {
            self.objects.insert(identity);
        }
        self.has_aliases |= input.alias;
        self.paths.entry(input.key).or_insert(input.path);
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
        if !self.objects.is_disjoint(&other.objects) {
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
        let mut paths: Vec<_> = self.paths.values().cloned().collect();
        paths.sort_unstable();
        BusyConflict {
            origin: self.origin,
            paths,
        }
    }
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
    fn has_aliases(&self, id: u64) -> bool {
        self.state
            .lock()
            .unwrap()
            .requests
            .get(&id)
            .is_some_and(|claim| claim.has_aliases)
    }

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
            if keys.is_disjoint(&state.active) {
                state.active.extend(keys.iter().cloned());
                return Poll::Ready(Ok(()));
            }
            let id = *waiting.id.get_or_insert_with(|| {
                state.next_waiter += 1;
                state.next_waiter
            });
            let blockers = keys.intersection(&state.active)
                .cloned().map(LeaseBlocker::Path).collect();
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
        for key in &self.keys {
            active.remove(key);
        }
        if active.capacity() > 256.max(active.len().saturating_mul(4)) {
            let target = active.len().saturating_mul(2);
            active.shrink_to(target);
        }
        let waiters: Vec<_> = self.keys.iter()
            .flat_map(|key| state.released(&LeaseBlocker::Path(key.clone()))).collect();
        drop(state);
        for waker in waiters { waker.wake(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


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
            let outcome = Outcome {
                archives: vec![ArchiveResult {
                    path: "carrier.bin".into(), format: "zip".into(), output: None,
                    failure: Some(failure), files: 0, bytes: 0, encrypted: Some(true),
                    depth: 1, offset: 123, end_offset: None, volume_completeness: None,
                    volume_attempts: None, source_paths: vec!["carrier.bin".into()],
                    password: None, discovery_source: DiscoverySource::Direct,
                    damage_flags: None, partial: false, retained: false,
                    recovered_complete_files: 0, promoted: false, promotion_original_path: None,
                }],
                ..Outcome::default()
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
        assert!(missing.run(Request::new(Vec::new(), Mode::Scan), |_| {}).is_err());
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
            let logical = LogicalInput { input, password: Some(Arc::from("confirmed")),
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
            let logical = LogicalInput { input, password: None, failure: None };
            let mut shell = engine.shell.branch();
            let mut outcome = Outcome::default();
            let result = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |_| {
                Box::pin(run.execute_input(logical, 1, DiscoverySource::Direct,
                    1, None, None, &run.candidates, &mut shell, &mut outcome))
            }).unwrap().result;
            let submitted = responder.join().unwrap();
            assert_eq!(submitted["password_verified"], true);
            assert_eq!(submitted["password"], "secret");
            assert_eq!(result.failure.unwrap().kind, kind);
            assert_eq!(result.password.as_deref(), expected);
        }
        release_reader_resources_under_roots(vec![source.to_string_lossy().into_owned()]).unwrap();
        fs::remove_file(source).unwrap();
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
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: Arc::clone(&engine.output_names), owner: 1 },
            created_outputs: Mutex::default(),
            output_base: None,
            checkpoints: HashMap::new(),
            promoted_sources: HashMap::new(),
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
            cleanup_tasks: Mutex::default(),
        })
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
            inputs: vec![LogicalInput { input, password: Some(Arc::from("secret")), failure: None }],
            source: DiscoverySource::Direct,
            retry: None,
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
        task.inputs.push(LogicalInput { input: cancel_input, password: None, failure: None });
        request.cancel.cancel();
        let error = request.cancel.run(|| run.plan_inputs(&mut task)).unwrap_err();
        assert!(is_cancellation(&error));
        release_reader_resources_under_roots(vec![path.to_string_lossy().into_owned()]).unwrap();
        fs::remove_file(path).unwrap();
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
                        inputs: vec![LogicalInput { input: input.clone(), password: None, failure: None }],
                        source: DiscoverySource::Detection,
                        retry: None,
                    };
                    let outcome = Scheduler::new().run(1, origin, &request.cancel, |spawner| {
                        run.execute_task(task, 1, depth, None, spawner)
                    }).unwrap();
                    assert!(outcome.archives.is_empty());
                    assert!(outcome.errors.is_empty());
                    assert!(matches!(events.lock().unwrap().as_slice(), [Event::Skipped { id: 1 }]));
                    // Direct user selections are not stale discovery proposals.
                    let direct = Task {
                        primary: None,
                        owned_paths: vec![input.entry_path.clone()],
                        inputs: vec![LogicalInput { input: input.clone(), password: None, failure: None }],
                        source: DiscoverySource::Direct,
                        retry: None,
                    };
                    assert!(run.should_process_task(&direct, &HashMap::new(), false, false).unwrap());
                    // A replacement can be classified Relations while retaining
                    // the original Direct task's no-silent-skip boundary.
                    let mut replacement = direct;
                    replacement.source = DiscoverySource::Relations;
                    assert!(run.should_process_task(&replacement, &HashMap::new(), false, false).unwrap());
                    assert!(!run.should_process_task(&replacement, &HashMap::new(), true, false).unwrap());
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
    fn carrier_finishes_all_parents_before_recursive_prompt_or_cancellation() {
        // A scheduler-only test cannot detect recursion left inside the logical
        // segment loop. Use real retained outputs and the actual task boundary:
        // both parent segments must be visited before either output asks to scan.
        use std::sync::atomic::AtomicUsize;

        struct ParentBarrier {
            started: Mutex<Vec<TaskId>>,
            finished: Mutex<Vec<TaskId>>,
            cancel: Cancellation,
            stop: bool,
            parents: usize,
            consumers: usize,
            budget: Mutex<Option<(Arc<AtomicUsize>, usize)>>,
        }
        impl Observer for ParentBarrier {
            fn notify(&self, event: Event) {
                match event {
                    Event::Started { id, .. } => self.started.lock().unwrap().push(id),
                    Event::Finished { id, .. } => self.finished.lock().unwrap().push(id),
                    _ => {}
                }
            }
            fn allow_recursive(&self, depth: usize, _: usize) -> bool {
                assert_eq!(depth, 2);
                assert_eq!(self.started.lock().unwrap().len(), self.parents,
                    "recursive prompt ran before all carrier parents finished");
                let finished = self.finished.lock().unwrap();
                assert_eq!(finished.len(), self.parents - 1,
                    "segment completion waited for recursive discovery");
                assert!(!finished.contains(&1000), "root finished before its subtrees");
                let budget = self.budget.lock().unwrap();
                let (remaining, initial) = budget.as_ref().unwrap();
                assert_eq!(remaining.load(Ordering::Acquire), initial - self.consumers,
                    "single-output or completed segments reserved recursive consumers");
                if self.stop { self.cancel.cancel(); }
                false
            }
        }
        for (count, complete, split_sources) in [(1, 0, false), (2, 0, false), (2, 1, false), (2, 1, true)] {
          for stop in [false, true] {
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
                request.checkpoints.push(InputCheckpoint::create(
                    &source, input, &result, &generations, Some(&container), index < complete, 1,
                ).unwrap());
            }
            let observer = ParentBarrier {
                started: Mutex::new(Vec::new()), finished: Mutex::new(Vec::new()), cancel: request.cancel.clone(), stop,
                parents: if count == 1 { 1 } else { count + 1 },
                consumers: if count - complete > 1 { count - complete } else { 0 },
                budget: Mutex::new(None),
            };
            let mut run = test_run(&engine, &request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
            }
            let task = Task {
                primary: None,
                owned_paths: inputs.iter().map(|input| input.entry_path.clone()).collect(),
                inputs: inputs.into_iter().map(|input| LogicalInput { input, password: None, failure: None }).collect(),
                source: DiscoverySource::Embedded,
                retry: None,
            };
            // One host slot also exercises parked recursive siblings without
            // depending on the test machine's CPU count or worker subprocesses.
            let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
            let scheduler = pool.install(Scheduler::new);
            let outcome = run.recursion.serve(&request.cancel,
                |depth, pending| observer.allow_recursive(depth, pending),
                || scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| {
                    let budget = spawner.consumer_budget();
                    let initial = budget.load(Ordering::Acquire);
                    *observer.budget.lock().unwrap() = Some((budget, initial));
                    run.execute_task(task, 1000, 1, None, spawner)
                }),
            ).unwrap();
            assert_eq!(observer.finished.lock().unwrap().last(), Some(&1000));
            assert_eq!(outcome.archives.len(), count);
            assert_eq!(outcome.archives.iter().map(|result| result.offset).collect::<Vec<_>>(),
                (0..count).map(|index| (index * 8) as u64).collect::<Vec<_>>());
            assert!(outcome.archives.iter().all(|result| result.retained));
            assert_eq!(request.cancel.cancelled(), stop);
            assert!(source.is_file(), "recursive cancellation consumed the carrier");
            for index in 0..count {
                assert_eq!(fs::read(container.join(format!("segment-{index}/payload"))).unwrap(), b"keep");
            }
            release_reader_resources_under_roots(vec![container.to_string_lossy().into_owned()]).unwrap();
            fs::remove_dir_all(container).unwrap();
            fs::remove_file(source).unwrap();
            if split_sources { fs::remove_file(continuation).unwrap(); }
          }
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
                    request.checkpoints.push(InputCheckpoint::create(&source, logical, &result,
                        &generations, Some(&container), true, 0).unwrap());
                }
                let engine = Engine::new(PathBuf::from("unused-worker"));
                let observer = |_: Event| {};
                let mut run = test_run(&engine, &request, &observer);
                for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                    Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
                }
                let kept = run.checkpoint_for(&inputs[0], &generations, &container, 1, &run.candidates).unwrap();
                assert_eq!(kept.retained_container(), Some(container.as_path()));
                assert!(run.checkpoint_for(&changed, &generations, &container, 1, &run.candidates).is_none());
                let previous = run.retry_slot_for(&changed, &container).unwrap();
                assert_eq!(previous.output(), slot);
                assert!(run.retry_slot_for(&changed, &source.with_extension("unrelated")).is_none());
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
        request.checkpoints.push(InputCheckpoint::create(&source, &input, &result, &generations, None, true, 1).unwrap());
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
            Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
        }
        let task = Task {
            primary: None, inputs: vec![LogicalInput { input, password: None, failure: None }],
            owned_paths: vec![source.to_string_lossy().into_owned()], source: DiscoverySource::Embedded, retry: None,
        };
        let scheduler = Scheduler::new();
        scheduler.configure_capacity(1);
        let outcome = scheduler.run(1, Origin::Foreground, &request.cancel, |spawner| Box::pin(async {
            let outcome = run.execute_task(task, 1, 1, None, spawner).await;
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
        assert_eq!(value, 42);
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
            let observer = |_: Event| {};
            let run = test_run(&engine, &request, &observer);
            let execute = || {
                let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "blocked".into());
                let task = Task {
                    primary: None,
                    inputs: vec![LogicalInput { input, password: None,
                        failure: Some(Failure::new(kind, "archive blocked")) }],
                    owned_paths: vec![source.to_string_lossy().into_owned()],
                    source: DiscoverySource::Embedded, retry: None,
                };
                Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                    run.execute_task(task, 1, 2, None, spawner)
                }).unwrap()
            };
            // Permit generation reads but deny rename/removal without production hooks.
            let lock = fs::OpenOptions::new().read(true).share_mode(1).open(&source).unwrap();
            let outcome = execute();
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
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
            }
            Arc::get_mut(&mut run).unwrap().promoted_sources = request.promoted_sources.iter().enumerate().map(|(index, source)| {
                (path_key(&source.path().to_string_lossy()), index)
            }).collect();
            let task = Task {
                primary: None,
                inputs: inputs.iter().enumerate().map(|(index, input)| LogicalInput {
                    input: input.clone(),
                    password: None,
                    failure: (index == 2).then(|| Failure::new(blocked, "blocked segment")),
                }).collect(),
                owned_paths: vec![inputs[0].entry_path.clone()],
                source: DiscoverySource::Embedded,
                retry: None,
            };
            Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                run.execute_task(task, 1, depth, None, spawner)
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
                let mut checkpoint = InputCheckpoint::create(
                    &source, input, &result, &generations, Some(&container), true, 0,
                ).unwrap();
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
            assert_eq!(subtree_complete(&outcome), promoted);
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
                request.checkpoints = outcome.checkpoints;
                request.promoted_sources = outcome.promoted_sources;
                let retry = execute(&engine, &request, &inputs, blocked, 1);
                assert_eq!(retry.checkpoints.iter().filter(|checkpoint| checkpoint.has_output()).count(), 2);
                assert!(retry.archives[..2].iter().all(|result| result.retained));
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
                    assert_eq!(result.unwrap(), vec![false; 8]);
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
                    inputs: vec![LogicalInput {
                        input: ArchiveInput::file("child.zip".into(), "zip".into(), "child".into()),
                        password: None,
                        failure: Some(Failure::new(FailureKind::Damaged, "preflight failure")),
                    }],
                    owned_paths: Vec::new(),
                    source: DiscoverySource::Direct,
                    retry: None,
                }],
                errors: Vec::new(),
                scan_errors: DirectoryReadErrors::report(),
                blocked_paths: HashSet::new(),
            };
            let error = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
                Box::pin(run.execute_batch(batch, 2, None, None, spawner))
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
        assert!(discovery::retry_volume(&original, context, &options, &candidates, &request)
            .unwrap().is_none());
        assert!(output.join("damaged.bin").is_file());
        drop(writer);
        assert!(discovery::retry_volume(&original, context, &options, &candidates, &request)
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
                inputs: vec![LogicalInput { input, password: None,
                    failure: blocked.then(|| Failure::new(FailureKind::MissingVolume, "missing")) }],
                source: DiscoverySource::Direct, retry: None,
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

    #[test]
    fn output_registration_does_not_hold_naming_gate_and_failure_releases_only_its_claim() {
        struct Register<'a>(&'a Mutex<OutputNames>);
        impl Observer for Register<'_> {
            fn notify(&self, _: Event) {}
            fn register_output(&self, result: &ArchiveResult, path: &Path) -> io::Result<()> {
                let mut names = self.0.try_lock().expect("registration held the global naming gate");
                // Simulate a peer selecting the same tree during publication.
                let peer = names.plan(path.to_owned(), result, 2, None)?.unwrap();
                assert_ne!(peer, path);
                Err(super::super::OutputCreateError::wrap(io::ErrorKind::PermissionDenied.into()))
            }
        }
        let source = crate::test_support::temp_file("unlocked_output_registration", b"input");
        let preferred = source.with_extension("output");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "a".into());
        let result = receipt(&input, DiscoverySource::Direct, 1);
        let names = Mutex::new(OutputNames::default());
        assert!(OutputNames::reserve(&names, preferred.clone(), &result, &Register(&names), 1, None)
            .unwrap().is_err());
        let mut names = names.lock().unwrap();
        assert!(!names.owners.contains_key(&1));
        assert_eq!(names.claimed.len(), 1);
        assert_eq!(names.plan(preferred.clone(), &result, 3, None).unwrap().unwrap(), preferred);
        names.release(2);
        names.release(3);
        assert!(names.claimed.is_empty());
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
        fs::remove_dir_all(preferred).unwrap();
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
            assert!(!registry.lock().unwrap().retain(&successful.join("continued"), 3, &result.path, None));
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
                assert!(registry.lock().unwrap().indices.contains_key(&output_key(&family)));
                registry.lock().unwrap().release(short_owner);
                assert!(registry.lock().unwrap().indices.len() <= OUTPUT_HISTORY_LIMIT);
                assert!(!registry.lock().unwrap().owners.contains_key(&short_owner));
            }
            registry.lock().unwrap().release(3);
            drop(second);
            drop(first);
            assert!(registry.lock().unwrap().claimed.is_empty());
            registry.lock().unwrap().clear_history();
            assert!(registry.lock().unwrap().indices.is_empty());
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
        let mut names = OutputNames::default();
        let failed = names.plan(preferred.clone(), &result, 1, None).unwrap().unwrap();
        let sibling = names.plan(preferred.clone(), &result, 1, None).unwrap().unwrap();
        assert_eq!(failed, preferred);
        assert_eq!(sibling, numbered(&preferred, 1));
        assert!(!failed.exists() && !sibling.exists());
        names.release(1);
        assert!(names.retain(&failed, 2, &source, Some(&root)));
        assert!(names.retain(&sibling, 2, &source, Some(&root)));
        assert_eq!(names.plan(preferred.clone(), &result, 2, None).unwrap().unwrap(), numbered(&preferred, 2));
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
            let history = &guard.indices[&family];
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
        for index in 0..(OUTPUT_HISTORY_LIMIT + 1) { names.lock().unwrap().next_index(&format!("family-{index}")); }
        assert_eq!(names.lock().unwrap().indices.len(), OUTPUT_HISTORY_LIMIT);
        assert_eq!(names.lock().unwrap().history_order.len(), OUTPUT_HISTORY_LIMIT);
        assert!(!names.lock().unwrap().indices.contains_key(&family));
        assert!(names.lock().unwrap().slots.values().all(|slots| !slots.contains_key(&family)));
        names.lock().unwrap().clear_history();
        let names = names.lock().unwrap();
        assert!(names.indices.is_empty() && names.slots.is_empty());
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
            let mut checkpoint = InputCheckpoint::create(
                &source, &input, &result, &generations, None, true, 0,
            ).unwrap();
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
        for complete_sibling in [false, true] {
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
                if index != 0 || !complete_sibling {
                    result.partial = true;
                    result.recovered_complete_files = 1;
                    result.failure = Some(Failure::new(FailureKind::Damaged, "CRC error"));
                }
                request.checkpoints.push(InputCheckpoint::create(
                    &source, input, &result, &generations, Some(&container), true, 0,
                ).unwrap());
            }
            let observer = |_: Event| {};
            let mut run = test_run(&engine, &request, &observer);
            for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
            }
            let task = Task {
                primary: None,
                inputs: inputs.into_iter().map(|input| LogicalInput { input, password: None, failure: None }).collect(),
                owned_paths: vec![source.to_string_lossy().into_owned()],
                source: DiscoverySource::Embedded,
                retry: None,
            };
            let outcome = Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                run.execute_task(task, 1, 1, None, spawner)
            }).unwrap();
            assert_eq!(outcome.archives.len(), 2);
            assert_eq!(outcome.failed(), if complete_sibling { 1 } else { 2 });
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
                request.max_depth = 0;
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
                    let mut checkpoint = InputCheckpoint::create(
                        &source, input, &result, &generations, Some(&container), true, 0,
                    ).unwrap();
                    checkpoint.set_password_signature(|| CandidateSet::new(
                        Arc::from([]), None, &AttemptCache::default(), None,
                    ).signature(&input.entry_path));
                    request.checkpoints.push(checkpoint);
                }
                for requirement in [ContentRequirement::Complete,
                                    ContentRequirement::AllowPartial, ContentRequirement::Complete] {
                    Arc::make_mut(&mut request.config).extraction.content_requirement = requirement;
                    let outcome = {
                        let observer = |_: Event| {};
                        let mut run = test_run(&engine, &request, &observer);
                        for (index, checkpoint) in request.checkpoints.iter().enumerate() {
                            Arc::get_mut(&mut run).unwrap().checkpoints.entry(checkpoint.key()).or_default().push(index);
                        }
                        let task = Task {
                            primary: None,
                            inputs: inputs.iter().cloned().map(|input| LogicalInput {
                                input, password: None, failure: None,
                            }).collect(),
                            owned_paths: vec![source.to_string_lossy().into_owned()],
                            source: DiscoverySource::Embedded, retry: None,
                        };
                        Scheduler::new().run(1, request.origin, &request.cancel, |spawner| {
                            run.execute_task(task, 1, 1, None, spawner)
                        }).unwrap()
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
                    request.checkpoints = outcome.checkpoints;
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
            fn discard_output(&self, _: &ArchiveResult, _: &Path) -> io::Result<()> {
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
            fn discard_output(&self, _: &ArchiveResult, output: &Path) -> io::Result<()> {
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
                outcome.checkpoints.push(InputCheckpoint::create(
                    &source, &input, &archive, &generations, None, true, 0,
                ).unwrap());
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
            assert!(outcome.archives[1..].iter().all(|archive| {
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
            fn discard_output(&self, _: &ArchiveResult, output: &Path) -> io::Result<()> {
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
    fn retained_parent_does_not_publish_new_child_before_its_commit_boundary() {
        struct Roots(std::sync::atomic::AtomicUsize);
        impl Observer for Roots {
            fn notify(&self, _: Event) {}
            async fn root_finished(&self, _: TaskId, _: &Path, _: Outcome) -> io::Result<Outcome> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Outcome::default())
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
            outcome.archives = vec![outer, nested];
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
        let parent = receipt(&input, DiscoverySource::Direct, 1);
        let batch = Discovered {
            tasks: vec![Task {
                primary: None,
                inputs: vec![LogicalInput { input, password: None, failure: None }],
                owned_paths: Vec::new(),
                source: DiscoverySource::Direct,
                retry: None,
            }],
            errors: Vec::new(),
            scan_errors: DirectoryReadErrors::report(),
            blocked_paths: HashSet::new(),
        };
        let outcome = Scheduler::new().run(1, Origin::Foreground, &request.cancel, |spawner| {
            Box::pin(run.execute_batch(batch, 2, None, Some((1, &parent)), spawner))
        }).expect("cancellation must not bypass the parent's output commit");
        assert_eq!(outcome.archives.len(), 1);
        assert_eq!(outcome.archives[0].failure.as_ref().unwrap().kind, FailureKind::Cancelled);
        assert!(!subtree_complete(&outcome));
        assert!(!is_cancellation(&io::Error::other("journal failure")));
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
    fn flatten_rebases_rollback_receipts_when_root_spelling_is_unchanged() {
        struct Discards(Mutex<Vec<PathBuf>>);
        impl Observer for Discards {
            fn notify(&self, _: Event) {}
            fn discard_output(&self, _: &ArchiveResult, output: &Path) -> io::Result<()> {
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
        flatten_result(&observer, &mut archive, &mut children, Some(&created)).unwrap();
        assert_eq!(archive.output.as_ref(), Some(&output));
        assert_eq!(created.lock().unwrap().0.get(&output_key(&output)).unwrap().1.path, source);
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
        let result = flatten_result(&|_: Event| {}, &mut archive, &mut outcome, None);
        let payload = fs::read(wrapper.join("payload.txt"));
        drop(held);
        fs::remove_dir_all(&output).unwrap();
        fs::remove_file(&source).unwrap();

        result.unwrap();
        outcome.archives.push(archive);
        assert_eq!(outcome.succeeded(), 1);
        assert_eq!(outcome.failed(), 0);
        assert!(!subtree_complete(&outcome), "ancestors must not flatten an unsettled child");
        let mut source_warning = Outcome::default();
        record_cleanup(&mut source_warning, &source, "delete", Err(io::ErrorKind::PermissionDenied.into()));
        assert!(subtree_complete(&source_warning), "source cleanup alone does not block ancestors");
        assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
        assert_eq!(payload.unwrap(), b"payload");
        assert!(
            matches!(&outcome.cleanup_results[..], [CleanupResult { path, mode: "flatten", status: CleanupStatus::Failed, .. }] if path == &output)
        );
    }

    #[test]
    fn completed_extract_compacts_segments_but_keeps_nested_summary_and_retry_receipts() {
        struct DetailedPublication(std::sync::atomic::AtomicBool);
        impl Observer for DetailedPublication {
            fn notify(&self, _: Event) {}
            async fn root_finished(&self, _: TaskId, _: &Path, outcome: Outcome) -> io::Result<Outcome> {
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
                outcome.checkpoints.push(InputCheckpoint::create(
                    &source, &input, &archive, &generations, None, true, 0,
                ).unwrap());
                outcome.archives.push(archive);
            }
            outcome.uncommitted = uncommitted;
            let before = serde_json::to_value(&outcome.checkpoints).unwrap();
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
                assert_eq!(serde_json::to_value(&outcome.checkpoints).unwrap(), before);
            } else if failure_kind.is_some() {
                assert_eq!(outcome.archives.len(), 3);
                assert_eq!(serde_json::to_value(&outcome.checkpoints).unwrap(), before);
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
