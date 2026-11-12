use super::checkpoint::{CheckpointKey, InputCheckpoint, PromotedSource};
use super::discovery::{self, Discovered, LogicalInput, Task};
use super::passwords::{AttemptCache, CandidateSet};
use super::scheduling::{Scheduler, Spawner};
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
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::future::poll_fn;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::task::{Poll, Waker};

pub struct Engine {
    worker_path: PathBuf,
    worker: Mutex<WorkerOwner>,
    mode_changes: Mutex<()>,
    leases: Arc<Leases>,
    next_job: AtomicU64,
    password_attempts: AttemptCache,
    scheduler: OnceLock<Arc<Scheduler>>,
    shell: ShellNotifier,
    output_names: Mutex<OutputNames>,
}

struct WorkerOwner {
    process: Option<Arc<Process>>,
    desired_mode: ProcessMode,
}

impl Engine {
    pub fn new(worker: PathBuf) -> Self {
        Self {
            worker_path: worker,
            worker: Mutex::new(WorkerOwner {
                process: None,
                desired_mode: ProcessMode::Normal,
            }),
            mode_changes: Mutex::new(()),
            leases: Arc::new(Leases::default()),
            next_job: AtomicU64::new(1),
            password_attempts: AttemptCache::default(),
            scheduler: OnceLock::new(),
            shell: ShellNotifier::default(),
            output_names: Mutex::default(),
        }
    }

    pub fn run(&self, request: Request, notify: impl Fn(Event) + Sync) -> io::Result<Outcome> {
        self.run_with(request, &notify)
    }

    pub(crate) fn run_with(
        &self,
        request: Request,
        observer: &impl Observer,
    ) -> io::Result<Outcome> {
        self.run_with_claim(request, observer, None)
    }

    pub(crate) fn reserve_foreground(
        &self,
        inputs: &[PathBuf],
        cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard<'_>> {
        let id = self.next_job.fetch_add(1, Ordering::Relaxed);
        self.leases
            .reserve_request(id, Origin::Foreground, inputs, cancel)
    }

    pub(crate) fn run_reserved(
        &self,
        request: Request,
        observer: &impl Observer,
        reservation: &RequestClaimGuard<'_>,
    ) -> io::Result<Outcome> {
        debug_assert!(std::ptr::eq(reservation.registry, self.leases.as_ref()));
        self.run_with_claim(request, observer, Some(reservation))
    }

    fn run_with_claim(
        &self,
        mut request: Request,
        observer: &impl Observer,
        reservation: Option<&RequestClaimGuard<'_>>,
    ) -> io::Result<Outcome> {
        if let Some(output) = request.output_root.take() {
            request.output_root = Some(std::path::absolute(output)?);
        }
        let request_id = reservation.map_or_else(
            || self.next_job.fetch_add(1, Ordering::Relaxed),
            |reservation| reservation.id,
        );
        let _request_claim = if reservation.is_none() && request.mode == Mode::Extract {
            Some(self.leases.reserve_request(
                request_id,
                request.origin,
                &request.inputs,
                &request.cancel,
            )?)
        } else {
            None
        };
        let resolve_aliases = request.inputs.len() > 1 && self.leases.has_aliases(request_id);
        let candidates = CandidateSet::new(
            std::mem::take(&mut request.passwords),
            request.password_snapshot.as_deref(),
            &self.password_attempts,
            request.password_scope.as_deref(),
        );
        let unfiltered = || {
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let recursive_output = request.mode == Mode::Extract && request.max_depth != 0;
        let (options, deep_options) = match (request.deep, recursive_output) {
            (true, false) => (unfiltered()?, None),
            (true, _) => (discovery::scan_options(&request.config)?, Some(unfiltered()?)),
            (false, _) => (discovery::scan_options(&request.config)?, None),
        };
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
            .iter()
            .map(|source| (path_key(&source.path().to_string_lossy()), source))
            .collect();
        let run = Run {
            engine: self,
            request: &request,
            resolve_aliases,
            candidates,
            options,
            deep_options,
            analysis,
            observer,
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: &self.output_names, owner: request_id },
            created_outputs: Mutex::default(),
            output_base,
            checkpoints,
            promoted_sources,
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
        };
        let scheduler = self.scheduler.get_or_init(Scheduler::new);
        let discovered = scheduler.run(request_id, request.origin, &request.cancel, |_| {
            Box::pin(async {
                request.cancel.check_io()?;
                let mut discovered =
                    discovery::discover(&request, run.options_at(1), &run.candidates)?;
                if run.resolve_aliases {
                    dedup_resolved_plans(&mut discovered.tasks);
                }
                Ok::<_, io::Error>(discovered)
            })
        })?;
        // Watch can wait for a different request's ownership here. The caller
        // owns that wait, so the other request retains access to host slots.
        if request.mode == Mode::Extract {
            self.leases.extend_request(
                request_id,
                request.origin,
                discovered
                    .tasks
                    .iter()
                    .flat_map(|task| task.owned_paths.iter().map(String::as_str)),
                &request.cancel,
            )?;
        }
        let execute = || {
            scheduler.run(request_id, request.origin, &request.cancel, |spawner| {
                Box::pin(run.execute_batch(discovered, 1, None, None, spawner))
            })
        };
        let mut executed = if request.mode == Mode::Extract
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
        // Scheduler completion joins every writer, even on cancellation. Never
        // roll back a tree while a native job or recursive branch can write it.
        if request.cancel.cancelled() {
            let mut discarded = Outcome::default();
            run.created_outputs.lock().unwrap().rollback(
                observer, executed.as_mut().unwrap_or(&mut discarded),
            )?;
        }
        let mut outcome = executed?;
        outcome.errors.extend(
            run.scan_errors
                .into_inner()
                .unwrap()
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

    async fn worker(&self, config: &WorkerConfig, cancel: &Cancellation) -> io::Result<Arc<Process>> {
        loop {
            cancel.check_io()?;
            let process = {
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
                Ok(()) => return Ok(process),
                // A new borrower may arrive while an abandoned generation is
                // reaping. Await that cleanup, then retry instead of inheriting
                // another request's cancellation. Genuine failures still return.
                Err(_) if !cancel.cancelled() && process.startup_abandoned() => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn set_process_mode(&self, mode: ProcessMode) -> io::Result<bool> {
        // Serialize control acknowledgments, but never hold the ownership lock
        // while stdin or its ACK is pending: scheduled jobs need that lock to
        // borrow the live worker. A replacement starts with desired_mode even
        // if the old process exits during this transition.
        let _change = self.mode_changes.lock().unwrap();
        let process = {
            let mut owner = self.worker.lock().unwrap();
            owner.desired_mode = mode;
            let process = owner.process.as_ref().filter(|process| process.alive()).cloned();
            if let Some(process) = &process {
                process.desire_mode(mode);
            }
            process
        };
        process.map_or(Ok(false), |process| process.set_process_mode(mode))
    }

    pub(crate) fn clear_idle_passwords(&self) {
        self.password_attempts.clear();
    }

    pub(crate) fn recent_passwords(&self) -> Vec<Arc<str>> {
        self.password_attempts.recent()
    }
}

struct Run<'a, O> {
    engine: &'a Engine,
    request: &'a Request,
    resolve_aliases: bool,
    candidates: CandidateSet<'a>,
    options: NativeDirectoryScanOptions,
    deep_options: Option<NativeDirectoryScanOptions>,
    analysis: NativeAnalysisConfig,
    observer: &'a O,
    recursion: RecursivePrompts,
    output_names: OutputReservationGuard<'a>,
    created_outputs: Mutex<CreatedOutputs>,
    output_base: Option<PathBuf>,
    checkpoints: HashMap<CheckpointKey, Vec<usize>>,
    promoted_sources: HashMap<String, &'a PromotedSource>,
    scan_errors: Mutex<DirectoryReadErrors>,
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

    async fn allow(&self, depth: usize, pending: usize, cancel: &Cancellation) -> bool {
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
            let request = Some((depth, pending, Arc::clone(&decision)));
            if self.requests.get().expect("prompt service is running").send(request).is_err() {
                decision.complete(false);
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
    indices: HashMap<String, usize>,
    hints: HashMap<u64, HashSet<String>>,
    claimed: BTreeMap<String, OutputClaim>,
    owners: HashMap<u64, Vec<String>>,
}

struct OutputClaim {
    owner: u64,
    source: String,
    path: PathBuf,
}

struct OutputReservationGuard<'a> {
    registry: &'a Mutex<OutputNames>,
    owner: u64,
}

impl Drop for OutputReservationGuard<'_> {
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

    fn release(&mut self, owner: u64) {
        for key in self.hints.remove(&owner).into_iter().flatten() {
            self.indices.remove(&key);
        }
        for key in self.owners.remove(&owner).into_iter().flatten() {
            self.claimed.remove(&key);
            for ancestor in crate::path_keys::path_ancestors(&key) {
                self.indices.remove(ancestor);
            }
        }
        if self.owners.is_empty() {
            self.indices.clear();
            self.claimed.clear();
        }
        crate::collections::trim_map(&mut self.owners);
        crate::collections::trim_map(&mut self.indices);
        crate::collections::trim_map(&mut self.hints);
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
        &mut self,
        mut preferred: PathBuf,
        result: &ArchiveResult,
        observer: &impl Observer,
        owner: u64,
        input: Option<&Path>,
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
        let mut index = *self.indices.get(&preferred_key).unwrap_or(&0);
        loop {
            let path = if index == 0 { preferred.clone() } else { numbered(&preferred, index) };
            if self.has_under(&output_key(&path)) {
                index += 1;
                continue;
            }
            let exists = match path.try_exists() {
                Ok(exists) => exists,
                Err(error) => return Ok(Err(file_failure(error))),
            };
            if !exists {
                match observer.register_output(result, &path) {
                    Ok(()) => {}
                    Err(error) if !error.get_ref().is_some_and(|inner| {
                        inner.is::<super::OutputCreateError>()
                    }) => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if fs::symlink_metadata(&path).is_ok() {
                            index += 1;
                            continue;
                        }
                        return Ok(Err(file_failure(error)));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
                        return Ok(Err(file_failure(error)));
                    }
                    Err(error) if error.get_ref().is_some_and(|inner| {
                        inner.is::<super::OutputCreateError>()
                    }) => return Ok(Err(file_failure(error))),
                    Err(error) => return Err(error),
                }
                if index != 0 {
                    self.indices.insert(preferred_key.clone(), index + 1);
                    self.hints.entry(owner).or_default().insert(preferred_key);
                }
                self.claim(&path, owner, &result.path);
                return Ok(Ok(path));
            }
            index += 1;
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
        outcome.checkpoints.retain(|checkpoint| !discarded(checkpoint.output()));
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
    result: ArchiveResult,
    inventory: Option<NativeOutputInventory>,
    input: ArchiveInput,
}

impl<'run, O: Observer> Run<'run, O> {
    fn options_at(&self, depth: usize) -> &NativeDirectoryScanOptions {
        if depth == 1 {
            self.deep_options.as_ref().unwrap_or(&self.options)
        } else {
            &self.options
        }
    }

    async fn execute_batch<'a>(
        &'a self,
        batch: Discovered,
        depth: usize,
        inherited_scope: Option<Arc<Path>>,
        parent: Option<(TaskId, &ArchiveResult)>,
        spawner: Spawner<'a>,
    ) -> io::Result<Outcome> {
        let mut outcome = Outcome {
            errors: batch.errors,
            scan_incomplete: self.record_scan_errors(batch.scan_errors),
            ..Outcome::default()
        };
        let children = spawner.clone();
        let parent_id = parent.map(|(id, _)| id);
        let executed = spawner.bounded_map(batch.tasks, move |task| {
            let id = self.queue_task(task.entry(), depth, parent_id, None);
            let cancelled = receipt(task.entry(), task.source, depth);
            let branch = self.execute_task(
                task,
                id,
                depth,
                inherited_scope.clone(),
                children.clone(),
            );
            Box::pin(async move { (id, cancelled, branch.await) })
        }).await;
        let mut first_error = None;
        for (id, mut cancelled, branch) in executed {
            let mut branch = match branch {
                Ok(branch) => branch,
                Err(error) if is_cancellation(&error) => {
                    cancelled.failure = Some(Failure::new(
                        FailureKind::Cancelled, "Operation interrupted",
                    ));
                    self.observer.notify(Event::Finished {
                        id, path: cancelled.path.clone(), depth, success: false,
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

    fn queue_task(
        &self,
        input: &ArchiveInput,
        depth: usize,
        parent: Option<TaskId>,
        segment: Option<Segment>,
    ) -> TaskId {
        let id = self.engine.next_job.fetch_add(1, Ordering::Relaxed);
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

    fn execute_task<'a>(
        &'a self,
        mut task: Task,
        task_id: TaskId,
        depth: usize,
        inherited_scope: Option<Arc<Path>>,
        spawner: Spawner<'a>,
    ) -> super::scheduling::Task<'a, io::Result<Outcome>> {
        Box::pin(async move {
            let cancel = &self.request.cancel;
            cancel.check_io()?;
            let mut lease = self.claim_task(&task).await?;
            let mut outcome = Outcome::default();
            let mut shell = self.engine.shell.branch();
            let mut generations = self.capture_generations(&task);
            let watch_root = depth == 1
                && self.request.origin == Origin::Watch
                && self.request.mode == Mode::Extract;
            if watch_root && !self.should_process_watch(&task, &generations)? {
                self.observer.notify(Event::Skipped { id: task_id });
                return Ok(outcome);
            }
            self.observer.notify(Event::Started {
                id: task_id,
                path: PathBuf::from(&task.entry().entry_path),
                depth,
            });
            self.plan_inputs(&mut task)?;
            self.observer.claim_sources(
                Path::new(&task.entry().entry_path),
                &task.owned_paths,
                depth,
            )?;
            let owner_path = PathBuf::from(&task.entry().entry_path);
            let root_scope = owner_path.parent();
            let source_scope = inherited_scope.as_deref().or(root_scope);
            let candidates = self.candidates.with_scope(source_scope);
            let preferred_carrier = self.preferred_output(task.entry(), depth);
            let mut retained: Vec<_> = task
                .inputs
                .iter()
                .map(|logical| {
                    self.checkpoint_for(&logical.input, &generations, &preferred_carrier, depth)
                })
                .collect();
            let multi = task.inputs.len() > 1;
            let count = task.inputs.len();
            let ids: Vec<_> = task
                .inputs
                .iter()
                .enumerate()
                .map(|(index, logical)| {
                    if multi {
                        let extent = logical.input.physical_extents().next();
                        self.queue_task(
                            &logical.input,
                            depth,
                            Some(task_id),
                            Some(Segment {
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
            let carrier = if self.request.mode == Mode::Extract && multi {
                let existing = retained
                    .iter()
                    .flatten()
                    .find_map(|checkpoint| checkpoint.container())
                    .map(Path::to_path_buf);
                match existing {
                    Some(path) => Some(path),
                    None if task.inputs.iter().any(|input| input.failure.is_none()) => {
                        let receipt = receipt(&task.inputs[0].input, task.source, depth);
                        match self.reserve_output(preferred_carrier, &receipt, None)? {
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
            let mut completed = Vec::with_capacity(task.inputs.len());
            let mut children = Outcome::default();
            let retry = task.retry.filter(|_| task.inputs.len() == 1);
            let mut promotion_sources = task.owned_paths;
            let mut superseded_candidates = HashSet::new();
            for ((logical, checkpoint), &id) in
                task.inputs.into_iter().zip(retained.drain(..)).zip(&ids)
            {
                if multi {
                    self.observer.notify(Event::Started {
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
                let remaining_depth = self
                    .request
                    .max_depth
                    .saturating_sub(depth.saturating_sub(1));
                let children_already_complete = checkpoint
                    .is_some_and(|checkpoint| checkpoint.children_complete(remaining_depth));
                let mut executed = if let Some(checkpoint) = checkpoint {
                    let mut input = logical.input;
                    checkpoint.restore_input(&mut input);
                    let mut result = checkpoint.result(depth);
                    if result.partial
                        && self.request.config.extraction.content_requirement
                            == ContentRequirement::Complete
                    {
                        let output = checkpoint.output();
                        shell.parent(output);
                        cleanup_owned_output(output).map_err(|error| {
                            io::Error::other(super::OutputCleanupError {
                                path: output.to_owned(),
                                error,
                            })
                        })?;
                        self.observer.discard_output(&result, output)?;
                        result.output = None;
                        result.partial = false;
                        result.files = 0;
                        result.bytes = 0;
                        result.recovered_complete_files = 0;
                    }
                    let inventory = if children_already_complete {
                        None
                    } else {
                        result
                            .output
                            .as_ref()
                            .map(|path| scan_output_inventory_impl(&path.to_string_lossy()))
                    };
                    Executed {
                        input,
                        result,
                        inventory,
                    }
                } else {
                    self.execute_input(
                        logical,
                        id,
                        task.source,
                        depth,
                        carrier.as_deref(),
                        &candidates,
                        &mut shell,
                    )
                    .await?
                };
                if let Some(context) = retry.as_deref().filter(|_| {
                    !cancel.cancelled()
                        && executed.result.output.is_none()
                        && (before_worker || self.request.mode == Mode::Extract)
                        && executed
                            .result
                            .failure
                            .as_ref()
                            .is_some_and(|failure| failure.kind == FailureKind::MissingVolume)
                }) {
                    if let Some(mut replacement) = discovery::retry_volume(
                        &executed.result,
                        context,
                        self.options_at(depth),
                        &candidates,
                        self.request,
                    )? {
                        self.observer.after_output(&executed.result)?;
                        drop(lease);
                        lease = self.claim_task(&replacement).await?;
                        generations = self.capture_generations(&replacement);
                        if watch_root && !self.should_process_watch(&replacement, &generations)? {
                            self.observer.notify(Event::Skipped { id: task_id });
                            return Ok(outcome);
                        }
                        self.observer.claim_sources(
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
                        promotion_sources = std::mem::take(&mut replacement.owned_paths);
                        let logical = replacement
                            .inputs
                            .into_iter()
                            .next()
                            .expect("volume retry has one logical input");
                        executed = self
                            .execute_input(
                                logical,
                                id,
                                replacement.source,
                                depth,
                                None,
                                &candidates,
                                &mut shell,
                            )
                            .await?;
                    }
                }
                let Executed {
                    mut result,
                    inventory,
                    mut input,
                } = executed;
                if self.request.mode == Mode::Scan {
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
                let mut descendants = Outcome::default();
                let mut ran_recursive_children = false;
                if let Some(inventory) = inventory {
                    let (nested, scanned) =
                        self.discover_children(inventory, depth, &candidates).await?;
                    ran_recursive_children = scanned;
                    if scanned {
                        descendants = self
                            .execute_batch(
                                nested,
                                depth + 1,
                                source_scope.map(Arc::from),
                                Some((id, &result)),
                                spawner.clone(),
                            )
                            .await?;
                    } else {
                        descendants.errors.extend(nested.errors);
                        descendants.scan_incomplete = self.record_scan_errors(nested.scan_errors);
                    }
                }
                let children_complete = children_already_complete
                    || (!cancel.cancelled() && subtree_complete(&descendants));
                if ran_recursive_children
                    && result.failure.is_none()
                    && children_complete
                    && !cancel.cancelled()
                {
                    if let Some(output) = result.output.as_deref() {
                        if remove_empty_or_promoted(output, &descendants.removed_promotion_dirs) {
                            self.observer.discard_output(&result, output)?;
                            result.output = None;
                        }
                    }
                }
                // A carrier's segments are independent output trees. Their
                // containers must keep the original layout for continuation.
                if !multi
                    && !result.retained
                    && result.failure.is_none()
                    && self.request.config.post_extract.flatten_single_directory
                    && children_complete
                    && !cancel.cancelled()
                {
                    flatten_result(
                        self.observer, &mut result, &mut descendants, Some(&self.created_outputs),
                    )?;
                }
                let checkpoint = if self.request.mode == Mode::Extract {
                    InputCheckpoint::create(
                        &owner_path,
                        &input,
                        &result,
                        &generations,
                        carrier.as_deref(),
                        children_complete,
                        remaining_depth,
                    )?
                } else {
                    None
                };
                // A cancelled newly created root remains uncommitted until
                // request-level rollback has joined all recursive writers.
                let commit_completed = !cancel.cancelled();
                if commit_completed || result.retained {
                    self.observer.commit_output(&result, checkpoint.as_ref())?;
                    // Cancellation after this durable commit must not roll it
                    // back. Match main's commit/check then retire ordering.
                    if commit_completed && !multi && result.failure.is_none() {
                        if let Some(output) = result.output.as_deref() {
                            self.created_outputs.lock().unwrap().commit_if_unowned(output);
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
                children
                    .cleanup_results
                    .append(&mut descendants.cleanup_results);
                if multi {
                    self.observer.notify(Event::Finished {
                        id,
                        path: result.path.clone(),
                        depth,
                        success: result.failure.is_none() || result.partial,
                    });
                }
                completed.push(result);
            }
            if multi && !cancel.cancelled()
                && completed.iter().all(|result| result.failure.is_none())
            {
                if let Some(root) = carrier.as_ref().filter(|_| {
                    completed.iter().any(|result| result.output.is_some())
                }) {
                    // The segments have separate receipts. Retire the carrier
                    // registration too, before its ancestors can commit and
                    // source cleanup can consume the archive.
                    let first = completed.first_mut().expect("carrier has logical inputs");
                    let segment = first.output.replace(root.clone());
                    let published = self.observer.commit_output(first, None);
                    first.output = segment;
                    published?;
                }
                let mut created = self.created_outputs.lock().unwrap();
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
                            self.observer.discard_output(result, root)?;
                        }
                    }
                }
            }
            if depth > 1
                && !cancel.cancelled()
                && !completed.iter().any(|result| result.partial)
                && completed.iter().any(|result| {
                    result.failure.as_ref().is_some_and(|failure| {
                        matches!(
                            failure.kind,
                            FailureKind::PasswordRequired
                                | FailureKind::WrongPassword
                                | FailureKind::PasswordInconclusive
                                | FailureKind::MissingVolume
                        )
                    })
                })
            {
                let destination = self.promotion_directory(source_scope.unwrap_or(Path::new(".")));
                self.promote_blocked(
                    &promotion_sources,
                    &destination,
                    &generations,
                    &mut completed,
                    &mut outcome,
                    &mut shell,
                )
                .await?;
            }
            let complete = completed
                .iter()
                .all(|result| result.failure.is_none() && !result.partial)
                && subtree_complete(&children)
                && !cancel.cancelled();
            // A Watch request may have been admitted before another batch moved
            // these members. The source leases now cover the actual resolved family.
            let admitted_promoted: Vec<_> = promotion_sources
                .iter()
                .filter_map(|path| {
                    self.admitted_promotion(path, &generations, watch_root)
                        .map(|source| (path, source))
                })
                .collect();
            if complete && self.request.mode == Mode::Extract {
                if watch_root {
                    self.observer.sources_processed(&completed, &generations)?;
                }
                let mode = if depth > 1 {
                    CleanupMode::Delete
                } else {
                    self.request.config.post_extract.archive_cleanup_mode
                };
                if let Some(first) = completed.first_mut() {
                    if admitted_promoted.is_empty() || mode == CleanupMode::Delete {
                        if mode != CleanupMode::Keep {
                            let mut selected: Vec<_> =
                                promotion_sources.iter().map(PathBuf::from).collect();
                            dedup_paths(&mut selected);
                            self.cleanup_sources(
                                first,
                                &selected,
                                &generations,
                                mode,
                                &mut outcome,
                                &mut shell,
                            )?;
                        }
                    } else {
                        let mut generated: Vec<_> = admitted_promoted
                            .iter()
                            .map(|(path, _)| PathBuf::from(path))
                            .collect();
                        dedup_paths(&mut generated);
                        if mode != CleanupMode::Keep {
                            let generated_keys: HashSet<_> =
                                admitted_promoted.iter().map(|(path, _)| *path).collect();
                            let mut originals: Vec<_> = promotion_sources
                                .iter()
                                .filter(|path| !generated_keys.contains(path))
                                .map(PathBuf::from)
                                .collect();
                            dedup_paths(&mut originals);
                            self.cleanup_sources(
                                first,
                                &originals,
                                &generations,
                                mode,
                                &mut outcome,
                                &mut shell,
                            )?;
                        }
                        self.cleanup_sources(
                            first,
                            &generated,
                            &generations,
                            CleanupMode::Delete,
                            &mut outcome,
                            &mut shell,
                        )?;
                    }
                }
            } else {
                outcome
                    .promoted_sources
                    .extend(admitted_promoted.into_iter().map(|(_, source)| source));
            }
            if let Some(result) = completed.first() {
                self.observer.notify(Event::Finished {
                    id: task_id,
                    path: if multi {
                        owner_path
                    } else {
                        result.path.clone()
                    },
                    depth,
                    success: if multi {
                        complete
                    } else {
                        result.failure.is_none() || result.partial
                    },
                });
            }
            outcome.archives.extend(completed);
            outcome.archives.append(&mut children.archives);
            outcome.errors.append(&mut children.errors);
            outcome.scan_incomplete |= children.scan_incomplete;
            outcome
                .cleanup_results
                .append(&mut children.cleanup_results);
            drop(lease);
            if depth == 1 && self.request.mode == Mode::Extract && !cancel.cancelled() {
                outcome.archives = self
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
            .position(|result| result.failure.is_some())
            .expect("blocked task has a failure");
        let promoted: io::Result<(
            Vec<(PathBuf, PathBuf)>,
            Vec<PromotedSource>,
            bool,
            Option<String>,
        )> = async {
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
                for result in results {
                    if success {
                        result.promotion_original_path = Some(result.path.clone());
                    }
                    map_promoted_path(&mut result.path, &moves);
                    for source in &mut result.source_paths {
                        map_promoted_path(source, &moves);
                    }
                    result.promoted = success;
                    if !success {
                        result.failure = Some(Failure::new(
                            FailureKind::FilesystemError,
                            format!(
                                "Unable to promote blocked nested input: {}",
                                error.as_deref().unwrap_or("unknown move failure")
                            ),
                        ));
                    }
                }
                for checkpoint in &mut outcome.checkpoints {
                    if checkpoint.source_paths().any(|path| {
                        moves
                            .iter()
                            .any(|(source, _)| resolved_key(path) == resolved_key(source))
                    }) {
                        checkpoint.promoted(&moves)?;
                        self.observer.checkpoint(checkpoint)?;
                    }
                }
            }
            Err(error) if self.request.cancel.cancelled() => return Err(error),
            Err(error) => {
                results[representative].failure = Some(Failure::new(
                    FailureKind::FilesystemError,
                    format!("Unable to promote blocked nested input: {error}"),
                ));
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
            .filter(|source| source.matches(generation))
            .map(|source| (*source).clone())
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
                if !destination_matches || !checkpoint.valid_for(input, generations) {
                    return None;
                }
                let mut names = self.output_names.registry.lock().unwrap();
                let source = Path::new(&input.entry_path);
                let nested = (depth > 1).then_some(source);
                if let Some(container) = checkpoint.container() {
                    if !names.retain(container, self.output_names.owner, source, nested) {
                        return None;
                    }
                }
                names.retain(checkpoint.output(), self.output_names.owner, source,
                    checkpoint.container().or(nested)).then_some(checkpoint)
            })
    }

    async fn claim_task(&self, task: &Task) -> io::Result<Lease<'_>> {
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

    fn should_process_watch(
        &self,
        task: &Task,
        generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> io::Result<bool> {
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
        if data_paths.iter().all(|path| {
            !generations.contains_key(&path_key(path))
                && Path::new(path).try_exists().is_ok_and(|exists| !exists)
        }) {
            return Ok(false);
        }
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
            Err(error) if !self.request.cancel.cancelled() => {
                original.failure = Some(file_failure(error));
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
        candidates: &CandidateSet<'_>,
        shell: &mut ShellUpdates<'_>,
    ) -> io::Result<Executed> {
        let LogicalInput {
            mut input,
            password,
            failure,
        } = logical;
        let mut result = receipt(&input, source, depth);
        if let Some(failure) = failure {
            result.failure = Some(failure);
            return Ok(Executed {
                result,
                inventory: None,
                input,
            });
        }
        if self.request.cancel.cancelled() {
            result.failure = Some(Failure::new(FailureKind::Cancelled, "Operation interrupted"));
            return Ok(Executed { result, inventory: None, input });
        }
        let plan = match candidates.plan(&input, password, &self.request.cancel) {
            Ok(Ok(plan)) => plan,
            Ok(Err(failure)) => {
                result.failure = Some(failure);
                return Ok(Executed {
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
                    result,
                    inventory: None,
                    input,
                });
            }
        };
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
            match self.reserve_output(preferred, &result, carrier)? {
                Ok(path) => {
                    shell.output(&path);
                    Some(path)
                }
                Err(failure) => {
                    result.failure = Some(failure);
                    return Ok(Executed {
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
            self.engine.next_job.fetch_add(1, Ordering::Relaxed)
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
                    if self.request.config.extraction.content_requirement
                        == ContentRequirement::AllowPartial
                        && matches!(
                            failure.kind,
                            FailureKind::Damaged | FailureKind::MissingVolume
                        )
                    {
                        if let Some(output) = &output {
                            let verified_files = recoverable_file_count(&frame);
                            if verified_files > 0 {
                                let stats = scan_output_inventory_impl(&output_string);
                                result.partial = true;
                                result.files = stats.file_count() as u64;
                                result.recovered_complete_files = verified_files as u64;
                                result.bytes = stats.total_size();
                                result.output = Some(output.clone());
                                inventory = Some(stats);
                            }
                        }
                    }
                    failure.evidence = worker_evidence(value, frame.recovery.take());
                    result.failure = Some(failure);
                }
            }
            Err(error) => result.failure = Some(self.process_or_file_failure(error, true)),
        }
        if result.failure.is_some() && result.output.is_none() {
            if let Some(path) = output {
                if let Err(error) = cleanup_owned_output(&path) {
                    // Keep the durable guard on a failed deletion so Watch
                    // can finish recovery rather than forgetting the directory.
                    return Err(io::Error::other(super::OutputCleanupError { path, error }));
                }
                self.observer.discard_output(&result, &path)?;
                // This worker has stopped and no recursive children were
                // started for its failed output. Retire the empty receipt now.
                self.created_outputs.lock().unwrap().commit(&path);
            }
        }
        Ok(Executed {
            result,
            inventory,
            input,
        })
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
        candidates: &CandidateSet<'_>,
    ) -> io::Result<(Discovered, bool)> {
        let mut nested = Discovered::default();
        if depth > self.request.max_depth || self.request.cancel.cancelled() {
            return Ok((nested, false));
        }
        let output = discovery::OutputDiscovery::prepare(inventory, &self.options)?;
        nested.scan_errors.extend(output.scan_errors());
        // Main asks once per depth when the filtered output has files, even if
        // discovery will find no archives or nested authorization rejects them.
        // Never do relation/embedded detection or password work before consent.
        // One logical output root is pending; its archive count is not known yet.
        let scan = output.has_files() && self.allow_recursive(depth + 1, 1).await;
        if scan {
            if let Err(error) = output.discover(candidates, self.request, &mut nested) {
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
        self.recursion.allow(depth, pending, &self.request.cancel).await
    }

    fn preferred_output(&self, input: &ArchiveInput, depth: usize) -> PathBuf {
        let path = Path::new(&input.entry_path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut root = parent.to_path_buf();
        if let Some(output_root) = self.request.output_root.as_ref().filter(|_| depth == 1) {
            root = output_root.clone();
            if self.request.origin == Origin::Foreground {
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

    fn reserve_output(
        &self,
        preferred: PathBuf,
        result: &ArchiveResult,
        carrier: Option<&Path>,
    ) -> io::Result<Result<PathBuf, Failure>> {
        // Serialize only the name claim and durable publication, not workers.
        let input = carrier.or_else(|| (result.depth > 1).then_some(result.path.as_path()));
        let reserved = self.output_names.registry.lock().unwrap().reserve(
            preferred, result, self.observer, self.output_names.owner, input,
        )?;
        if let Ok(path) = &reserved {
            self.created_outputs.lock().unwrap().register(path, result);
        }
        Ok(reserved)
    }

    fn cleanup_sources(
        &self,
        result: &mut ArchiveResult,
        paths: &[PathBuf],
        generations: &HashMap<String, PhysicalFileGeneration>,
        cleanup: CleanupMode,
        outcome: &mut Outcome,
        shell: &mut ShellUpdates<'_>,
    ) -> io::Result<()> {
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
            return Ok(());
        }
        let keys = valid
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let _promotion = Promotion::begin(keys)?;
        let old = std::mem::replace(
            &mut result.source_paths,
            valid.iter().map(|path| (*path).clone()).collect(),
        );
        let publish = self.observer.before_cleanup(result);
        result.source_paths = old;
        publish?;
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
        Ok(())
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
        // Successful flatten commonly keeps the root spelling unchanged while
        // moving its leaf's descendants. Rebase rollback receipts with the same
        // mapping as checkpoints, before any fallible durable publication.
        if let Some(created) = created {
            created.lock().unwrap().relocate(&old, &new);
        }
        for checkpoint in &mut children.checkpoints {
            checkpoint.relocate(&old, &new);
            observer.checkpoint(checkpoint)?;
        }
        for child in &mut children.archives {
            if let Some(path) = child.output.as_mut() {
                if let Ok(suffix) = path.strip_prefix(&old) {
                    *path = new.join(suffix);
                }
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

fn map_promoted_path(path: &mut PathBuf, moves: &[(PathBuf, PathBuf)]) {
    let key = resolved_key(path);
    if let Some((_, target)) = moves.iter().find(|(source, _)| resolved_key(source) == key) {
        *path = target.clone();
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
) -> Option<Box<FailureEvidence>> {
    let diagnostics = &result["diagnostics"];
    let field = |name: &str| {
        [result, diagnostics].into_iter().find_map(|value| {
            let text = worker::string(value, name);
            (!text.is_empty()).then(|| text.to_owned())
        })
    };
    let stage = field("failure_stage");
    let native_kind = field("failure_kind");
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
    (stage.is_some()
        || native_kind.is_some()
        || missing_volume_name.is_some()
        || missing_volume_evidence.is_some()
        || read.is_some()
        || recovery.is_some())
    .then(|| {
        Box::new(FailureEvidence {
            stage,
            native_kind,
            missing_volume_name,
            missing_volume_evidence,
            read,
            recovery,
        })
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
    let weak_password = password_evidence == Some("zipcrypto_header_byte")
        || (password_evidence == Some("empty_password_direct") && flag(result, "encrypted"));
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
    } else if weak_password
        && (matches!(operation, "wrong_password" | "data_error" | "crc_error")
            || matches!(
                failure,
                "encrypted_or_wrong_password" | "data_error" | "checksum_error" | "crc_error"
            ))
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
    Failure::new(
        kind,
        if message.is_empty() {
            format!("{kind:?}")
        } else {
            message.to_owned()
        },
    )
}

fn recoverable_file_count(frame: &WorkerFrame) -> usize {
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
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((base, index.parse().ok()?))
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
            if input.volume_attempts.is_some() || logical.failure.is_some() {
                return true;
            }
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
    changed: Condvar,
}

#[derive(Default)]
struct LeaseState {
    active: HashSet<String>,
    requests: HashMap<u64, RequestClaim>,
    next_waiter: u64,
    waiters: HashMap<u64, Waker>,
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

    fn covers(&self, path: &str) -> bool {
        self.paths.contains_key(path) || self.includes_directory(path)
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

pub(crate) struct RequestClaimGuard<'a> {
    registry: &'a Leases,
    id: u64,
}

impl Drop for RequestClaimGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock().unwrap();
        state.requests.remove(&self.id);
        crate::collections::trim_map(&mut state.requests);
        self.registry.changed.notify_all();
    }
}

struct Lease<'a> {
    owner: &'a Leases,
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
        self: &Arc<Self>,
        id: u64,
        origin: Origin,
        paths: &[PathBuf],
        cancel: &Cancellation,
    ) -> io::Result<RequestClaimGuard<'_>> {
        let inputs = paths
            .iter()
            .map(|path| ClaimedInput::new(path))
            .collect::<io::Result<Vec<_>>>()?;
        self.admit_request(id, origin, inputs, cancel)?;
        Ok(RequestClaimGuard { registry: self, id })
    }

    fn extend_request<'a>(
        self: &Arc<Self>,
        id: u64,
        origin: Origin,
        paths: impl Iterator<Item = &'a str>,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let extra: HashSet<_> = {
            let state = self.state.lock().unwrap();
            let Some(claim) = state.requests.get(&id) else {
                return Ok(());
            };
            paths
                .filter(|path| !claim.covers(&path_key(path)))
                .collect()
        };
        if extra.is_empty() {
            return Ok(());
        }
        let inputs = extra
            .into_iter()
            .map(|path| ClaimedInput::new(Path::new(path)))
            .collect::<io::Result<Vec<_>>>()?;
        self.admit_request(id, origin, inputs, cancel)
    }

    fn admit_request(
        self: &Arc<Self>,
        id: u64,
        origin: Origin,
        inputs: Vec<ClaimedInput>,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let wake = Arc::clone(self);
        let _subscription = cancel.subscribe(move || {
            let _state = wake.state.lock().unwrap();
            wake.changed.notify_all();
        });
        let mut state = self.state.lock().unwrap();
        // Expanded ownership is requested before jobs start. Drop this
        // request's old subset before waiting so two Watch requests holding
        // different members cannot deadlock on the same complete group.
        let previous = state.requests.remove(&id);
        if previous.is_some() {
            self.changed.notify_all();
        }
        let mut claim = previous.unwrap_or_else(|| RequestClaim::new(origin));
        for input in inputs {
            claim.add(input);
        }
        loop {
            cancel.check_io()?;
            match state
                .requests
                .values()
                .find(|current| claim.overlaps(current))
            {
                None => break,
                Some(current) if origin == Origin::Foreground => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        current.conflict(),
                    ));
                }
                Some(_) => state = self.changed.wait(state).unwrap(),
            }
        }
        state.requests.insert(id, claim);
        Ok(())
    }

    async fn acquire(
        self: &Arc<Self>,
        keys: HashSet<String>,
        cancel: &Cancellation,
    ) -> io::Result<Lease<'_>> {
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
            state.waiters.insert(id, cx.waker().clone());
            drop(state);
            if subscription.is_none() {
                let owner = Arc::clone(self);
                subscription = cancel.subscribe(move || {
                    let waker = owner.state.lock().unwrap().waiters.remove(&id);
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                });
            }
            Poll::Pending
        })
        .await?;
        Ok(Lease { owner: self, keys })
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
            state.waiters.remove(&id);
            if state.waiters.capacity() > 256 {
                crate::collections::trim_map(&mut state.waiters);
            }
        }
    }
}

impl Drop for Lease<'_> {
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
        let waiters = std::mem::take(&mut state.waiters);
        drop(state);
        for (_, waker) in waiters {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_run<'a, O: Observer>(
        engine: &'a Engine,
        request: &'a Request,
        observer: &'a O,
    ) -> Run<'a, O> {
        Run {
            engine,
            request,
            resolve_aliases: false,
            candidates: CandidateSet::new(Arc::from([]), None, &engine.password_attempts, None),
            options: discovery::scan_options(&request.config).unwrap(),
            deep_options: None,
            analysis: NativeAnalysisConfig::new(Vec::<(String, bool)>::new()),
            observer,
            recursion: RecursivePrompts::default(),
            output_names: OutputReservationGuard { registry: &engine.output_names, owner: 1 },
            created_outputs: Mutex::default(),
            output_base: None,
            checkpoints: HashMap::new(),
            promoted_sources: HashMap::new(),
            scan_errors: Mutex::new(DirectoryReadErrors::report()),
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
    fn recursive_discovery_waits_for_consent_and_releases_the_manifest() {
        // Real RAR5 -hp fixture (password "secret"). A real successful probe
        // changes this request's password cache, so this catches discovery moved
        // above the prompt without a mock or process-global test counters.
        let hex = "526172211a07010074de7b1c21040000010f7b64253244702e2a32eb93579555a37d38b616cb97898c463d3682920551724ed0c1c974029cc2b8ef8491fc816311daa1b0410f6115608170466e4948a8c6d4f17e28b08c727b4acfc116d3d075ce011963dc0c72e50a803d9036619810e92352e809830c9463ab4a0abdaab61e008218673e9c51409f76b2064bf7982e56d8173f1e387329bd5aca3bac49063545fcbfc19547d2be214b4fe1dae172b250e168f2a258548930b1763fb500c7869d70f2539d86fd19214dcc3bca1363154b0a0f2b0bba7dcc224ec1893cbc31cfa95158ccf5e96d74921de6f268ea4429e2ddf63d49220005742fef059f868372345f071322a7e690d56d5ac17b563fa9e923076fa2c58aa8e88e9843df17b7e79a30ca936d8215c92f6832f86887c3c3160ecfddfcdf7712382f84f39eb8";
        let rar: Vec<_> = (0..hex.len()).step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect();
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
            run.candidates = CandidateSet::new(
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
                                    Box::pin(prompts.allow(2, 1, cancel))
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
        let original = receipt(task.entry(), task.source, 1);

        let last = root.join("split.7z.002");
        let mut writer = fs::File::create(&last).unwrap();
        writer.write_all(&[0; 13]).unwrap();
        writer.write_all(&next_header).unwrap();
        assert!(discovery::retry_volume(&original, context, &options, &candidates, &request)
            .unwrap().is_none());
        drop(writer);
        assert!(discovery::retry_volume(&original, context, &options, &candidates, &request)
            .unwrap().is_some());

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
            let registry = Mutex::new(OutputNames::default());
            let owner = if shared_request { 1 } else { 2 };
            let first = OutputReservationGuard { registry: &registry, owner: 1 };
            let second = OutputReservationGuard { registry: &registry, owner };
            let mut names = registry.lock().unwrap();
            let preferred = root.join("a");
            let descendant = preferred.join("sub").join("b");
            let (failed, successful) = if descendant_first {
                let successful = names.reserve(descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap();
                (names.reserve(preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap(), successful)
            } else {
                let failed = names.reserve(preferred.clone(), &result, &ObserverWithFailure, 1, None).unwrap().unwrap();
                (failed, names.reserve(descendant.clone(), &result, &ObserverWithFailure, owner, None).unwrap().unwrap())
            };
            assert!(!successful.starts_with(&failed) && !failed.starts_with(&successful));
            fs::write(successful.join("payload"), b"keep").unwrap();
            let generated = successful.join("nested.zip");
            let nested = successful.join("nested");
            assert_eq!(names.reserve(nested.clone(), &result, &ObserverWithFailure, owner, Some(&generated))
                .unwrap().unwrap(), nested);
            let foreign = names.reserve(successful.join("foreign"), &result, &ObserverWithFailure, 3, Some(&generated))
                .unwrap().unwrap();
            assert!(!foreign.starts_with(&successful));
            assert!(!names.retain(&successful.join("continued"), 3, &result.path, None));
            cleanup_owned_output(&failed).unwrap();
            assert_eq!(fs::read(successful.join("payload")).unwrap(), b"keep");
            assert_eq!(names.reserve(root.join("denied"), &result, &ObserverWithFailure, owner, None)
                .unwrap().unwrap_err().kind, FailureKind::FilesystemError);
            assert!(names.reserve(root.join("journal"), &result, &ObserverWithFailure, owner, None).is_err());
            // A long-lived owner must not retain numbering hints belonging
            // to many short-lived requests with different output families.
            for short_owner in 10..42 {
                let family = root.join(format!("family-{short_owner}"));
                fs::create_dir(&family).unwrap();
                names.reserve(family.clone(), &result, &ObserverWithFailure, short_owner, None)
                    .unwrap().unwrap();
                assert!(names.indices.contains_key(&output_key(&family)));
                names.release(short_owner);
                assert!(!names.indices.contains_key(&output_key(&family)));
                assert!(!names.hints.contains_key(&short_owner));
            }
            names.release(3);
            drop(names);
            drop(second);
            drop(first);
            assert!(registry.lock().unwrap().claimed.is_empty());
            assert!(registry.lock().unwrap().indices.is_empty());
            fs::remove_dir_all(&root).unwrap();
          }
        }
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
                ).unwrap().unwrap());
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
                inputs: vec![LogicalInput { input, password: None, failure: None }],
                owned_paths: Vec::new(),
                source: DiscoverySource::Direct,
                retry: None,
            }],
            errors: Vec::new(),
            scan_errors: DirectoryReadErrors::report(),
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
    fn flatten_failure_keeps_extraction_successful_and_reports_output() {
        struct DenyFlatten;
        impl Observer for DenyFlatten {
            fn notify(&self, _: Event) {}

            fn before_flatten(&self, _: &Path, _: &Path, _: &Path) -> io::Result<()> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }

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

        let result = flatten_result(&DenyFlatten, &mut archive, &mut outcome, None);
        let payload = fs::read(wrapper.join("payload.txt"));
        fs::remove_dir_all(&output).unwrap();
        fs::remove_file(source).unwrap();

        result.unwrap();
        outcome.archives.push(archive);
        assert_eq!(outcome.succeeded(), 1);
        assert_eq!(outcome.failed(), 0);
        assert_eq!(outcome.archives[0].output.as_ref(), Some(&output));
        assert_eq!(payload.unwrap(), b"payload");
        assert!(
            matches!(&outcome.cleanup_results[..], [CleanupResult { path, mode: "flatten", status: CleanupStatus::Failed, .. }] if path == &output)
        );
    }
}
