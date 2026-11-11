use super::checkpoint::{CheckpointKey, InputCheckpoint, PromotedSource};
use super::discovery::{self, Discovered, LogicalInput, Task};
use super::passwords::{AttemptCache, CandidateSet};
use super::worker::{self, Process};
use super::{
    ArchiveResult, BusyConflict, Cancellation, CleanupResult, CleanupStatus, DiscoverySource,
    Event, Failure, FailureKind, InputError, InputErrorKind, Mode, Observer, Origin, Outcome,
    Request,
};
use crate::analysis_native::{analyze_input, NativeAnalysisConfig};
use crate::core::config::{CleanupMode, ContentRequirement, ProcessMode, Recursion, WorkerConfig};
use crate::io::archive_state::{
    archive_input_slices, ArchiveInput, VolumeCompleteness, VolumeSelection,
};
use crate::io::reader::{
    capture_directory_identity, capture_file_generation, release_reader_resources_under_roots,
    NativeArchiveSession, PhysicalFileGeneration,
};
use crate::io::resource_lifecycle::{
    native_begin_promotion, native_end_promotion, native_wait_for_resources,
};
use crate::path_keys::path_key;
use crate::postprocess::{
    flatten_single_branch_directories, remove_owned_file, remove_owned_tree,
    NativeBlockedInputPromotion,
};
use crate::scan::directory::{
    scan_output_inventory_impl, NativeDirectoryScanOptions, NativeOutputInventory,
};
use crate::scan::worker_event::WorkerFrame;
use rayon::prelude::*;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

pub struct Engine {
    worker_path: PathBuf,
    worker: Mutex<WorkerOwner>,
    leases: Arc<Leases>,
    next_job: AtomicU64,
    password_attempts: AttemptCache,
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
            leases: Arc::new(Leases::default()),
            next_job: AtomicU64::new(1),
            password_attempts: AttemptCache::default(),
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
        let candidates = CandidateSet::new(
            std::mem::take(&mut request.passwords),
            request.password_snapshot.as_deref(),
            &self.password_attempts,
        );
        let options = discovery::scan_options(&request.config)?;
        let deep_options = request
            .deep
            .then(|| {
                NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            })
            .transpose()?;
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
            request_id,
            candidates,
            options,
            deep_options,
            analysis,
            observer,
            recursion: Mutex::new(HashMap::new()),
            output_indices: Mutex::new(HashMap::new()),
            output_base,
            checkpoints,
            promoted_sources,
        };
        request.cancel.run(|| {
            request.cancel.check_io()?;
            let discovered = discovery::discover(&request, run.options_at(1), &run.candidates)?;
            run.execute_batch(discovered, 1, None)
        })
    }

    fn worker(&self, config: &WorkerConfig) -> io::Result<Arc<Process>> {
        let mut owner = self.worker.lock().unwrap();
        if let Some(worker) = owner.process.as_ref().filter(|worker| worker.alive()) {
            return Ok(Arc::clone(worker));
        }
        let process = Arc::new(Process::start(
            &self.worker_path,
            config,
            owner.desired_mode,
        )?);
        owner.process = Some(Arc::clone(&process));
        Ok(process)
    }

    pub(crate) fn set_process_mode(&self, mode: ProcessMode) -> io::Result<bool> {
        let mut owner = self.worker.lock().unwrap();
        owner.desired_mode = mode;
        owner
            .process
            .as_ref()
            .filter(|process| process.alive())
            .map_or(Ok(false), |process| process.set_process_mode(mode))
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
    request_id: u64,
    candidates: CandidateSet<'a>,
    options: NativeDirectoryScanOptions,
    deep_options: Option<NativeDirectoryScanOptions>,
    analysis: NativeAnalysisConfig,
    observer: &'a O,
    recursion: Mutex<HashMap<usize, bool>>,
    output_indices: Mutex<HashMap<PathBuf, usize>>,
    output_base: Option<PathBuf>,
    checkpoints: HashMap<CheckpointKey, Vec<usize>>,
    promoted_sources: HashMap<String, &'a PromotedSource>,
}

struct Executed {
    result: ArchiveResult,
    inventory: Option<NativeOutputInventory>,
    input: ArchiveInput,
}

impl<O: Observer> Run<'_, O> {
    fn options_at(&self, depth: usize) -> &NativeDirectoryScanOptions {
        if depth == 1 {
            self.deep_options.as_ref().unwrap_or(&self.options)
        } else {
            &self.options
        }
    }

    fn execute_batch(
        &self,
        batch: Discovered,
        depth: usize,
        inherited_scope: Option<&Path>,
    ) -> io::Result<Outcome> {
        if depth == 1 && self.request.mode == Mode::Extract {
            self.engine.leases.extend_request(
                self.request_id,
                self.request.origin,
                batch
                    .tasks
                    .iter()
                    .flat_map(|task| task.owned_paths.iter().map(String::as_str)),
                &self.request.cancel,
            )?;
        }
        let mut outcome = Outcome {
            errors: batch.errors,
            ..Outcome::default()
        };
        let executed: Vec<_> = batch
            .tasks
            .into_par_iter()
            .map(|task| {
                self.request
                    .cancel
                    .run(|| self.execute_task(task, depth, inherited_scope))
            })
            .collect();
        for branch in executed {
            let mut branch = branch?;
            outcome.archives.append(&mut branch.archives);
            outcome.errors.append(&mut branch.errors);
            outcome.checkpoints.append(&mut branch.checkpoints);
            outcome.cleanup_results.append(&mut branch.cleanup_results);
            outcome
                .promoted_sources
                .append(&mut branch.promoted_sources);
            outcome
                .removed_promotion_dirs
                .append(&mut branch.removed_promotion_dirs);
        }
        Ok(outcome)
    }

    fn execute_task(
        &self,
        mut task: Task,
        depth: usize,
        inherited_scope: Option<&Path>,
    ) -> io::Result<Outcome> {
        let cancel = &self.request.cancel;
        cancel.check_io()?;
        let mut lease = self.claim_task(&task)?;
        let mut outcome = Outcome::default();
        let mut generations = self.capture_generations(&task);
        let watch_root = depth == 1
            && self.request.origin == Origin::Watch
            && self.request.mode == Mode::Extract;
        if watch_root && !self.should_process_watch(&task, &generations)? {
            return Ok(outcome);
        }
        self.plan_inputs(&mut task)?;
        self.observer.claim_sources(
            Path::new(&task.entry().entry_path),
            &task.owned_paths,
            depth,
        )?;
        let owner_path = PathBuf::from(&task.entry().entry_path);
        let root_scope = owner_path.parent();
        let source_scope = inherited_scope.or(root_scope);
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
                    Some(self.reserve_output(preferred_carrier, &receipt)?)
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
        for (logical, checkpoint) in task.inputs.into_iter().zip(retained.drain(..)) {
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
            let children_already_complete =
                checkpoint.is_some_and(|checkpoint| checkpoint.children_complete(remaining_depth));
            let mut executed = if let Some(checkpoint) = checkpoint {
                let mut input = logical.input;
                checkpoint.restore_input(&mut input);
                let result = checkpoint.result(depth);
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
                self.execute_input(logical, task.source, depth, carrier.as_deref(), &candidates)?
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
                    lease = self.claim_task(&replacement)?;
                    generations = self.capture_generations(&replacement);
                    if watch_root && !self.should_process_watch(&replacement, &generations)? {
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
                    executed =
                        self.execute_input(logical, replacement.source, depth, None, &candidates)?;
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
            if let Some(inventory) = inventory.filter(|inventory| inventory.file_count() > 0) {
                if depth <= self.request.max_depth && !cancel.cancelled() {
                    let nested = discovery::discover_output(
                        &inventory,
                        &self.options,
                        &candidates,
                        self.request,
                    )?;
                    drop(inventory);
                    if !nested.tasks.is_empty()
                        && self.allow_recursive(depth + 1, nested.tasks.len())
                    {
                        ran_recursive_children = true;
                        descendants = self.execute_batch(nested, depth + 1, source_scope)?;
                    } else {
                        descendants.errors.extend(nested.errors);
                    }
                }
            }
            let children_complete = children_already_complete || subtree_complete(&descendants);
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
            if !result.retained
                && result.failure.is_none()
                && self.request.config.post_extract.flatten_single_directory
                && children_complete
                && !cancel.cancelled()
            {
                self.flatten(&mut result, &mut descendants)?;
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
            self.observer.commit_output(&result, checkpoint.as_ref())?;
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
            children
                .cleanup_results
                .append(&mut descendants.cleanup_results);
            completed.push(result);
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
            )?;
        }
        let complete = completed
            .iter()
            .all(|result| result.failure.is_none() && !result.partial)
            && subtree_complete(&children)
            && !cancel.cancelled();
        let admitted_promoted = promotion_sources.iter().filter_map(|path| {
            if self.promoted_sources.is_empty() {
                return None;
            }
            let key = path_key(path);
            let source = self.promoted_sources.get(&key)?;
            source.matches(generations.get(&key)?).then_some(*source)
        });
        if complete && self.request.mode == Mode::Extract {
            if watch_root {
                self.observer.sources_processed(&completed, &generations)?;
            }
            let mode = if depth > 1 || admitted_promoted.count() > 0 {
                CleanupMode::Delete
            } else {
                self.request.config.post_extract.archive_cleanup_mode
            };
            if mode != CleanupMode::Keep {
                let mut selected: Vec<_> = promotion_sources.iter().map(PathBuf::from).collect();
                dedup_paths(&mut selected);
                if let Some(first) = completed.first_mut() {
                    self.cleanup_sources(first, &selected, &generations, mode, &mut outcome)?;
                }
            }
        } else {
            outcome.promoted_sources.extend(admitted_promoted.cloned());
        }
        for result in &completed {
            self.observer.notify(Event::Finished {
                path: result.path.clone(),
                depth,
                success: result.failure.is_none() || result.partial,
            });
        }
        outcome.archives.extend(completed);
        outcome.archives.append(&mut children.archives);
        outcome.errors.append(&mut children.errors);
        outcome
            .cleanup_results
            .append(&mut children.cleanup_results);
        drop(lease);
        Ok(outcome)
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

    fn promote_blocked(
        &self,
        sources: &[String],
        destination: &Path,
        generations: &HashMap<String, PhysicalFileGeneration>,
        results: &mut [ArchiveResult],
        outcome: &mut Outcome,
    ) -> io::Result<()> {
        let representative = results
            .iter()
            .position(|result| result.failure.is_some())
            .expect("blocked task has a failure");
        let promoted = (|| -> io::Result<(Vec<(PathBuf, PathBuf)>, bool, Option<String>)> {
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
                let _destinations = self.engine.leases.acquire(keys, &self.request.cancel)?;
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
                self.observer
                    .after_promotion(&results[representative], &moves, success)?;
                outcome
                    .removed_promotion_dirs
                    .extend(removed.iter().map(|path| path_key(path)));
                return Ok((moves, success, (!error.is_empty()).then_some(error)));
            }
        })();
        match promoted {
            Ok((moves, success, error)) => {
                if success {
                    outcome.promoted_sources.extend(
                        moves
                            .iter()
                            .filter_map(|(_, target)| PromotedSource::capture(target).ok()),
                    );
                }
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
                        result.failure = Some(Failure {
                            kind: FailureKind::FilesystemError,
                            message: format!(
                                "Unable to promote blocked nested input: {}",
                                error.as_deref().unwrap_or("unknown move failure")
                            ),
                        });
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
                results[representative].failure = Some(Failure {
                    kind: FailureKind::FilesystemError,
                    message: format!("Unable to promote blocked nested input: {error}"),
                });
            }
        }
        Ok(())
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
                    Some(container) => output_candidate(preferred_carrier, container),
                    None => output_candidate(&preferred, checkpoint.output()),
                };
                (destination_matches && checkpoint.valid_for(input, generations))
                    .then_some(checkpoint)
            })
    }

    fn claim_task(&self, task: &Task) -> io::Result<Lease<'_>> {
        let keys = task
            .owned_paths
            .iter()
            .map(|path| resolved_key(Path::new(path)))
            .collect();
        self.engine.leases.acquire(keys, &self.request.cancel)
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

    fn execute_input(
        &self,
        logical: LogicalInput,
        source: DiscoverySource,
        depth: usize,
        carrier: Option<&Path>,
        candidates: &CandidateSet<'_>,
    ) -> io::Result<Executed> {
        let LogicalInput {
            mut input,
            password,
            failure,
        } = logical;
        let mut result = receipt(&input, source, depth);
        self.observer.notify(Event::Started {
            path: result.path.clone(),
            depth,
        });
        if let Some(failure) = failure {
            result.failure = Some(failure);
            return Ok(Executed {
                result,
                inventory: None,
                input,
            });
        }
        self.request.cancel.check_io()?;
        let sessions = if matches!(input.format_hint.as_str(), "zip" | "rar" | "7z" | "enc")
            && password.is_none()
        {
            open_sessions(&input)
        } else {
            Ok(Vec::new())
        };
        let plan = match sessions
            .and_then(|sessions| candidates.plan(&input, password, &sessions, &self.request.cancel))
        {
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
                        Failure {
                            kind: FailureKind::MissingVolume,
                            message: error.to_string(),
                        }
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
            Some(self.reserve_output(preferred, &result)?)
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
        let native = self
            .engine
            .worker(&self.request.config.performance.worker)
            .and_then(|worker| {
                worker.submit(&job_id, &request, &self.request.cancel, |progress| {
                    self.observer.notify(Event::Progress {
                        path: result.path.clone(),
                        completed_bytes: progress.completed,
                        total_bytes: progress.total,
                    });
                })
            });
        drop(request);
        let mut inventory = None;
        match native {
            Ok(frame) => {
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
                            result.failure = Some(Failure {
                                kind: FailureKind::ProcessError,
                                message: error.to_string(),
                            })
                        }
                    }
                }
                if success && result.failure.is_none() {
                    let password_verified = self.request.mode == Mode::Extract
                        || plan.verified
                        || flag(value, "password_verified");
                    if result.encrypted == Some(true) && password_verified {
                        let index = value
                            .get("matched_index")
                            .and_then(Value::as_u64)
                            .and_then(|index| usize::try_from(index).ok());
                        result.password = plan.selected(index).map(str::to_owned);
                        plan.remember_confirmation(index, &self.engine.password_attempts);
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
                    return Err(io::Error::other(format!("{}: {error}", path.display())));
                }
                self.observer.discard_output(&result, &path)?;
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
            Failure {
                kind: FailureKind::ResourceUnavailable,
                message: error.to_string(),
            }
        } else if self.request.cancel.cancelled() {
            Failure {
                kind: FailureKind::Cancelled,
                message: "Operation interrupted".to_owned(),
            }
        } else if worker {
            Failure {
                kind: FailureKind::ProcessError,
                message: error.to_string(),
            }
        } else {
            file_failure(error)
        }
    }

    fn allow_recursive(&self, depth: usize, pending: usize) -> bool {
        if self.request.config.recursive_extract != Recursion::Prompt {
            return true;
        }
        *self
            .recursion
            .lock()
            .unwrap()
            .entry(depth)
            .or_insert_with(|| self.observer.allow_recursive(depth, pending))
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
                        let key = parent.to_string_lossy();
                        let safe: String = key
                            .trim_matches(['\\', '/'])
                            .chars()
                            .map(|ch| {
                                if ch.is_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                                    ch
                                } else {
                                    '_'
                                }
                            })
                            .collect();
                        root.push(if safe.is_empty() { "input" } else { &safe });
                    }
                }
            }
        }
        root.join(archive_name(input))
    }

    fn reserve_output(&self, preferred: PathBuf, result: &ArchiveResult) -> io::Result<PathBuf> {
        // Serialize only the name claim and durable publication. No worker or
        // recursive scan runs while this allocator is held.
        let mut indices = self.output_indices.lock().unwrap();
        let mut index = *indices.get(&preferred).unwrap_or(&0);
        loop {
            let path = if index == 0 {
                preferred.clone()
            } else {
                numbered(&preferred, index)
            };
            if !path.try_exists()? {
                match self.observer.register_output(result, &path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        index += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                if index != 0 {
                    indices.insert(preferred, index + 1);
                }
                return Ok(path);
            }
            index += 1;
        }
    }

    fn flatten(&self, result: &mut ArchiveResult, children: &mut Outcome) -> io::Result<()> {
        let Some(output) = result.output.as_ref() else {
            return Ok(());
        };
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
        let stats = flatten_single_branch_directories(
            output,
            Some(&available),
            |root, work, leaf| self.observer.before_flatten(root, work, leaf),
            None,
        );
        if !stats.errors.is_empty() {
            result.failure = Some(Failure {
                kind: FailureKind::FilesystemError,
                message: stats.errors.join("\n"),
            });
        }
        if let (Some(old), Some(new)) = (stats.source_dir, stats.output_dir) {
            for checkpoint in &mut children.checkpoints {
                checkpoint.relocate(&old, &new);
                self.observer.checkpoint(checkpoint)?;
            }
            for child in &mut children.archives {
                if let Some(path) = child.output.as_mut() {
                    if let Ok(suffix) = path.strip_prefix(&old) {
                        *path = new.join(suffix);
                    }
                }
            }
            result.output = Some(new);
        }
        Ok(())
    }

    fn cleanup_sources(
        &self,
        result: &mut ArchiveResult,
        paths: &[PathBuf],
        generations: &HashMap<String, PhysicalFileGeneration>,
        cleanup: CleanupMode,
        outcome: &mut Outcome,
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
            record_cleanup(outcome, path, mode, removed);
        }
        Ok(())
    }
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

fn open_sessions(input: &ArchiveInput) -> io::Result<Vec<NativeArchiveSession>> {
    let mut seen = HashSet::new();
    let paths = input
        .physical_extents()
        .map(|extent| extent.path.as_str())
        .chain(std::iter::once(input.entry_path.as_str()));
    paths
        .filter(|path| seen.insert(*path))
        .map(|path| NativeArchiveSession::new(path.to_owned()))
        .collect()
}

fn file_failure(error: io::Error) -> Failure {
    let kind = if crate::io::resource_error::is_memory_error(&error) {
        FailureKind::ResourceUnavailable
    } else {
        FailureKind::FilesystemError
    };
    Failure {
        kind,
        message: error.to_string(),
    }
}

fn flag(result: &Value, name: &str) -> bool {
    result.get(name).and_then(Value::as_bool) == Some(true)
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
    Failure {
        kind,
        message: if message.is_empty() {
            format!("{kind:?}")
        } else {
            message.to_owned()
        },
    }
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
    if let Some(count) = frame.traced_complete_files {
        return count;
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
    !outcome
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
    path_key(
        &fs::canonicalize(path)
            .as_deref()
            .unwrap_or(path)
            .to_string_lossy(),
    )
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
}

struct RequestClaim {
    origin: Origin,
    paths: HashMap<String, PathBuf>,
    directories: HashSet<String>,
    objects: HashSet<(u64, [u8; 16])>,
}

impl RequestClaim {
    fn new(origin: Origin) -> Self {
        Self {
            origin,
            paths: HashMap::new(),
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
        Ok(Self {
            key: resolved_key(&canonical),
            path,
            directory,
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

    fn acquire(
        self: &Arc<Self>,
        keys: HashSet<String>,
        cancel: &Cancellation,
    ) -> io::Result<Lease<'_>> {
        let wake = Arc::clone(self);
        let _subscription = cancel.subscribe(move || {
            let _state = wake.state.lock().unwrap();
            wake.changed.notify_all();
        });
        let state = self.state.lock().unwrap();
        let mut state = self
            .changed
            .wait_while(state, |state| {
                !cancel.cancelled() && !keys.is_disjoint(&state.active)
            })
            .unwrap();
        cancel.check_io()?;
        state.active.extend(keys.iter().cloned());
        Ok(Lease { owner: self, keys })
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
        self.owner.changed.notify_all();
    }
}
