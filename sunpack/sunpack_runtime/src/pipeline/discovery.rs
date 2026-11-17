use super::passwords::CandidateSet;
use super::{DiscoverySource, Failure, FailureKind, InputError, InputErrorKind, Request};
use crate::core::config::{Config, ScanFilterKind};
use crate::io::archive_state::{
    AnalysisOrigin, ArchiveInput, InputExtent, InputPart, OpenMode, VolumeCompleteness,
};
use crate::io::directory_errors::{DirectoryReadError, DirectoryReadErrors};
use crate::io::reader::NativeArchiveSession;
use crate::password::rar::resolve_embedded_rar_boundaries;
use crate::path_keys::{path_ancestors, path_key};
use crate::scan::directory::{
    classify_scan_targets, filesystem_logical_name, walk_can_reach, NativeDirectoryScanOptions,
    NativeDirectorySnapshot, NativeOutputInventory,
};
use crate::scan::discovery::{
    CandidateProjection, EmbeddedPageRow, FileTargets, NativeCandidateTable, NativeEmbeddedBatch,
};
use crate::scan::embedded::{NativeScanResult, RarInputResolution};
use crate::scan::nested_authorization::authorize_nested_candidates;
use crate::scan::scope::NativeDiscoveryScope;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) struct LogicalInput {
    // Password evidence may have a bounded view without a proven extraction end.
    pub input: ArchiveInput,
    pub password: Option<Arc<str>>,
    pub failure: Option<Failure>,
}

pub(super) struct Task {
    pub inputs: Vec<LogicalInput>,
    // Physical ownership is independent of logical execution order.
    pub primary: Option<Box<ArchiveInput>>,
    pub owned_paths: Vec<String>,
    pub source: DiscoverySource,
    pub context: Option<TaskContext>,
}

// A retry snapshot already owns its report scope. Scope-only tasks can drop
// the snapshot as soon as discovery is complete.
pub(super) enum TaskContext {
    Report(Arc<NativeDiscoveryScope>),
    Retry(Arc<RetryScope>),
}

impl Task {
    fn single(
        input: ArchiveInput,
        owned_paths: Vec<String>,
        source: DiscoverySource,
        failure: Option<Failure>,
    ) -> Self {
        Self {
            inputs: vec![LogicalInput {
                input,
                password: None,
                failure,
            }],
            primary: None,
            owned_paths,
            source,
            context: None,
        }
    }

    pub(super) fn entry(&self) -> &ArchiveInput {
        self.primary.as_deref().unwrap_or(&self.inputs[0].input)
    }

    pub(super) fn input_paths(&self) -> impl Iterator<Item = &str> {
        self.inputs.iter().flat_map(|logical| logical.input.physical_paths())
    }

    pub(super) fn take_context(&mut self, report: bool) -> (Option<Arc<NativeDiscoveryScope>>, Option<Arc<RetryScope>>) {
        match self.context.take() {
            Some(TaskContext::Report(scope)) => (report.then_some(scope), None),
            Some(TaskContext::Retry(retry)) => {
                let scope = report.then(|| Arc::clone(&retry.scope));
                (scope, Some(retry))
            }
            None => (None, None),
        }
    }
}

pub(super) struct Discovered {
    pub tasks: Vec<Task>,
    pub errors: Vec<InputError>,
    pub scan_errors: DirectoryReadErrors,
    pub(super) blocked_paths: HashSet<String>,
}

pub(super) struct PreparedVolumePlan {
    path: String,
    generations: Vec<(String, crate::io::reader::PhysicalFileGeneration)>,
    tasks: Vec<Task>,
}

impl Default for Discovered {
    fn default() -> Self {
        Self {
            tasks: Vec::new(),
            errors: Vec::new(),
            scan_errors: DirectoryReadErrors::report(),
            blocked_paths: HashSet::new(),
        }
    }
}

pub(super) struct RetryScope {
    scope: Arc<NativeDiscoveryScope>,
    snapshot: NativeDirectorySnapshot,
    bucket: String,
}

type VerifiedPasswords = HashMap<(String, u64), Arc<str>>;

fn password_key(input: &ArchiveInput) -> (String, u64) {
    let offset = input
        .physical_extents()
        .find(|extent| extent.path == input.entry_path)
        .map_or(0, |extent| extent.start);
    (path_key(&input.entry_path), offset)
}

fn scope_view(
    snapshot: &NativeDirectorySnapshot,
    scope: &NativeDiscoveryScope,
) -> NativeDirectorySnapshot {
    snapshot.view(
        snapshot
            .rows
            .iter()
            .copied()
            .filter(|&row| scope.contains(&snapshot.table.paths[row]))
            .collect(),
    )
}

fn scan_discovery_scope(
    options: &NativeDirectoryScanOptions,
    scope: &NativeDiscoveryScope,
    shared_roots: &HashMap<String, String>,
    snapshots: &mut HashMap<String, (NativeDirectorySnapshot, NativeDirectorySnapshot)>,
) -> io::Result<(NativeDirectorySnapshot, NativeDirectorySnapshot)> {
    let Some(root) = shared_roots.get(scope.key()) else {
        return options.scan_scope(scope);
    };
    if !snapshots.contains_key(root) {
        snapshots.insert(
            root.clone(),
            options.scan_scope(&NativeDiscoveryScope::new(root.clone(), None, Vec::new()))?,
        );
    }
    let (filtered, raw) = &snapshots[root];
    if scope.key() == path_key(root).trim_end_matches('\\') {
        return Ok((filtered.share_rows(), raw.share_rows()));
    }
    Ok((scope_view(filtered, scope), scope_view(raw, scope)))
}



pub(crate) fn scan_options(config: &Config) -> io::Result<NativeDirectoryScanOptions> {
    let mut blacklist = Vec::new();
    let mut whitelist = Vec::new();
    let mut sizes = Vec::new();
    let mut mtimes = Vec::new();
    if config.filesystem.scan_filters_enabled {
        let bounds = |v: &[Option<u64>; 5]| (v[0], v[1], v[2], v[3], v[4]);
        for filter in config
            .filesystem
            .scan_filters
            .iter()
            .filter(|filter| filter.enabled)
        {
            match &filter.kind {
                ScanFilterKind::Blacklist(rule) => blacklist.push(rule.compile()?),
                ScanFilterKind::Whitelist(rule) => whitelist.push(rule.compile()?),
                ScanFilterKind::SizeRange(range) => sizes.push(bounds(range)),
                ScanFilterKind::MtimeRange(range) => mtimes.push(bounds(range)),
                ScanFilterKind::Unknown(name) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown filesystem scan filter: {name}"),
                    ));
                }
            }
        }
    }
    NativeDirectoryScanOptions::new(blacklist, sizes, mtimes, whitelist)
}

pub(super) fn discover(
    request: &Request,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet,
) -> io::Result<Discovered> {
    let mut result = Discovered::default();
    let mut prepared = HashSet::new();
    let mut prepared_tasks = Vec::new();
    for plan in &request.prepared_volumes {
        let plan = plan.0.lock().unwrap().take();
        if let Some(plan) = plan.filter(|plan| plan.generations.iter().all(|(path, before)|
            crate::io::reader::capture_file_generation(Path::new(path)).is_ok_and(|now| now == *before))) {
            prepared.insert(plan.path);
            prepared_tasks.extend(plan.tasks);
        }
    }
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for input in &request.inputs {
        let path = std::path::absolute(input)?.to_string_lossy().into_owned();
        if request
            .discovery_scope
            .as_ref()
            .is_none_or(|scope| scope.contains(&path) || (request.watch_catalog.as_ref().is_some_and(|catalog| catalog.dependency_contains(scope, &path))))
        {
            let key = path_key(&path);
            if !prepared.contains(&key) && seen.insert(key) {
                paths.push(path);
            }
        }
    }
    let (kinds, errors) = classify_scan_targets(&paths);
    result.scan_errors = errors;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for (path, kind) in paths.into_iter().zip(kinds) {
        match kind {
            1 => files.push(path),
            2 => directories.push(path),
            3 => result.errors.push(InputError {
                path: PathBuf::from(path),
                message: "A regular input file is required".to_owned(),
                kind: InputErrorKind::InvalidInput,
                failure: None,
                scan_operation: None,
            }),
            _ => {}
        }
    }
    let max_depth = (!request.recursive).then_some(0);
    let mut seen_roots = HashSet::new();
    let mut scopes: Vec<_> = directories
        .into_iter()
        .filter_map(|directory| {
            let scope = if let Some(scope) = request
                .discovery_scope
                .as_ref()
                .filter(|scope| scope.key() == path_key(&directory).trim_end_matches('\\'))
            {
                scope.clone()
            } else {
                NativeDiscoveryScope::new(directory, max_depth, Vec::new())
            };
            seen_roots.insert(scope.key().to_owned()).then_some(scope)
        })
        .collect();
    drop(seen_roots);
    // Enumeration may be covered by an ancestor target; main still retains
    // every explicitly selected boundary for missing-volume replacement.
    let mut logical_scopes: BTreeMap<_, _> = scopes
        .iter()
        .map(|scope| (scope.key().to_owned(), scope.clone()))
        .collect();
    if request.recursive && scopes.len() > 1 {
        let roots: HashMap<_, _> = scopes.iter().map(|scope| (scope.key(), scope)).collect();
        let covered: Vec<_> = scopes
            .iter()
            .map(|scope| {
                path_ancestors(scope.key()).skip(1).any(|parent| {
                    roots.get(parent).is_some_and(|root| {
                        root.max_depth.is_none() && root.contains_key(scope.key())
                    })
                })
            })
            .collect();
        let mut covered = covered.into_iter();
        scopes.retain(|_| !covered.next().unwrap());
    }
    let roots: HashMap<_, _> = scopes.iter().map(|scope| (scope.key(), scope)).collect();
    let covering_root = |key: &str| {
        path_ancestors(key).any(|parent| {
            roots
                .get(parent)
                .is_some_and(|scope| scope.contains_key(key))
        })
    };
    let mut verified = HashMap::new();
    let mut retry_scopes = Vec::new();
    let mut by_parent = BTreeMap::<_, (_, Vec<_>)>::new();
    let requested_scope = request.discovery_scope.as_ref();
    if let Some(scope) = requested_scope.filter(|_| !files.is_empty()) {
        logical_scopes
            .entry(scope.key().to_owned())
            .or_insert_with(|| scope.clone());
    }
    for path in &files {
        let (key, root) = if let Some(scope) = requested_scope {
            (scope.key().to_owned(), std::borrow::Cow::Borrowed(scope.root.as_str()))
        } else {
            let path = Path::new(path);
            let parent = path.parent().unwrap_or(path).to_string_lossy();
            let mut key = path_key(&parent);
            key.truncate(key.trim_end_matches('\\').len());
            if !logical_scopes.contains_key(&key) {
                let scope = NativeDiscoveryScope::new(parent.as_ref().to_owned(), max_depth, Vec::new());
                logical_scopes.insert(key.clone(), scope);
            }
            (key, parent)
        };
        if !roots.is_empty() && covering_root(&path_key(path)) {
            continue;
        }
        let bucket = if request.watch_catalog.is_some() {
            crate::scan::catalog::catalog_stem(path)
        } else {
            String::new()
        };
        by_parent
            .entry((key, bucket))
            .or_insert_with(|| (root.into_owned(), Vec::new()))
            .1
            .push((path.clone(), filesystem_logical_name(path)));
    }
    // Share physical enumeration, never the logical relation boundary. Each
    // selected file keeps its original parent scope, including replacement retry.
    let mut shared_roots = HashMap::new();
    if request.recursive
        && options.can_share_recursive_context()
        && request.discovery_scope.is_none()
        && request.watch_catalog.is_none()
    {
        let file_roots: HashMap<_, _> = by_parent
            .iter()
            .map(|((key, _), (root, _))| (key.clone(), root.clone()))
            .collect();
        for (key, path) in file_roots
            .iter()
            .map(|(key, path)| (key.as_str(), path.as_str()))
            .chain(
                scopes
                    .iter()
                    .map(|scope| (scope.key(), scope.root.as_str())),
            )
        {
            if let Some((_, root)) = path_ancestors(key)
                .filter_map(|ancestor| file_roots.get_key_value(ancestor))
                .filter(|(root, _)| walk_can_reach(root, path))
                .last()
            {
                shared_roots.insert(key.to_owned(), root.clone());
            }
        }
    }
    let mut shared_snapshots = HashMap::new();
    let mut tables = Vec::new();
    for scope in &scopes {
        request.cancel.check_io()?;
        let (filtered, raw) =
            scan_discovery_scope(options, scope, &shared_roots, &mut shared_snapshots)?;
        if !shared_roots.contains_key(scope.key()) {
            result.scan_errors.extend(filtered.scan_errors());
        }
        let table = directory_table(&filtered, &raw, None, candidates, &mut verified, request)?;
        tables.push(table);
        retry_scopes.push(Arc::new(RetryScope {
            scope: Arc::new(scope.clone()),
            snapshot: raw,
            bucket: String::new(),
        }));
    }
    for ((_, bucket), (parent, targets)) in by_parent {
        request.cancel.check_io()?;
        let scope = request.discovery_scope.clone().unwrap_or_else(|| {
            NativeDiscoveryScope::new(
                parent,
                max_depth,
                Vec::new(),
            )
        });
        let (filtered, raw) = if let Some(catalog) = &request.watch_catalog {
            options.catalog_snapshot(catalog, &scope, &targets[0].0)?
        } else {
            scan_discovery_scope(options, &scope, &shared_roots, &mut shared_snapshots)?
        };
        if !shared_roots.contains_key(scope.key()) {
            result.scan_errors.extend(filtered.scan_errors());
        }
        let mut table = NativeCandidateTable::new();
        table.append_directory(&raw, &filtered, Some(FileTargets::new(targets)), request.deep)?;
        match probe_relations(&mut table, &filtered, &raw, candidates, &mut verified, request) {
            Ok(()) => tables.push(table),
            Err(error) if request.watch_catalog.is_some() && !crate::io::cancellation::is_cancellation(&error) => {
                // Main evaluates each Watch selection independently. On a
                // real probe error, reuse the bucket snapshot to preserve
                // those exact target/alias boundaries. Healthy buckets never
                // rebuild a table or repeat password verification.
                let targets = table.take_file_targets();
                if let Some(path) = targets.only_path() {
                    result.errors.push(watch_discovery_error(path.into(), error));
                    continue;
                }
                let mut successful = NativeCandidateTable::new();
                for (path, target) in targets.into_singles() {
                    request.cancel.check_io()?;
                    match directory_table(&filtered, &raw, Some(target), candidates, &mut verified, request) {
                        Ok(mut single) => successful.extend(&mut single),
                        Err(error) if crate::io::cancellation::is_cancellation(&error) => return Err(error),
                        Err(error) => result.errors.push(watch_discovery_error(path.into(), error)),
                    }
                }
                tables.push(successful);
            }
            Err(error) => return Err(error),
        }
        retry_scopes.push(Arc::new(RetryScope {
            scope: Arc::new(scope),
            snapshot: raw,
            bucket,
        }));
    }
    for (filtered, _) in shared_snapshots.values() {
        result.scan_errors.extend(filtered.scan_errors());
    }
    // Main resolves one combined candidate table. Watch batches already
    // partition file targets by catalog bucket, which stays the read boundary.
    if request.watch_catalog.is_none() {
        if let [first, rest @ ..] = tables.as_mut_slice() {
            for table in rest {
                first.extend(table);
            }
            tables.truncate(1);
        }
    }
    result.project(&mut tables, candidates, &verified, request, false)?;
    retain_logical_retry_scopes(logical_scopes.into_values(), &mut retry_scopes);
    assign_retry_scopes(&mut result.tasks, &retry_scopes);
    if !prepared_tasks.is_empty() {
        suppress_prepared_continuations(&prepared_tasks, &mut result.tasks);
        // Preserve the prepared retry scopes, and coalesce a peer admitted in
        // the same batch through the existing shared-input projection.
        prepared_tasks.append(&mut result.tasks);
        result.tasks = prepared_tasks;
        if result.tasks.len() > 1 { merge_shared_inputs(&mut result.tasks, &mut result.blocked_paths); }
    }
    Ok(result)
}

fn suppress_prepared_continuations(prepared: &[Task], tasks: &mut Vec<Task>) {
    fn headless_missing(task: &Task) -> Option<&ArchiveInput> {
        let [logical] = task.inputs.as_slice() else { return None; };
        let input = &logical.input;
        (task.source == DiscoverySource::Relations
            && logical.failure.as_ref().is_some_and(|failure| matches!(
                failure.context.as_deref(),
                Some(super::FailureContext::Discovery { reason, .. }) if reason == "missing_volume"
            ))
            && input.volume_attempts.is_none()
            && !input.parts.is_empty()
            && input.parts.iter().all(|part| part.volume_number.is_some_and(|number| number > 1)))
            .then_some(input)
    }

    fn covers(claim: &InputExtent, member: &InputExtent) -> bool {
        claim.start <= member.start
            && claim.end.is_none_or(|end| member.end.is_some_and(|member_end| end >= member_end))
    }

    if !tasks.iter().any(|task| headless_missing(task).is_some()) { return; }
    let mut claimed = HashMap::<_, Vec<_>>::new();
    for (plan, logical) in prepared.iter().flat_map(|task| &task.inputs).enumerate() {
        let input = &logical.input;
        if logical.failure.is_some() || !input.mode.structured()
            || input.analysis.volume_completeness != Some(VolumeCompleteness::Complete)
            || input.volume_attempts.is_some()
        {
            continue;
        }
        for extent in input.physical_extents() {
            claimed.entry(path_key(&extent.path)).or_default()
                .push((plan, input.format_hint.as_str(), extent));
        }
    }
    if claimed.is_empty() { return; }
    tasks.retain(|task| {
        let Some(input) = headless_missing(task) else { return true; };
        // A tail-only selection can project a missing-head proposal while
        // the real head's generation-checked plan bypasses this discovery.
        // Require one complete archive to cover every member's byte range.
        let first = &input.parts[0].extent;
        let Some(first_claims) = claimed.get(&path_key(&first.path)) else { return true; };
        let others: Vec<_> = input.parts[1..].iter().map(|part| {
            (claimed.get(&path_key(&part.extent.path)), &part.extent)
        }).collect();
        !first_claims.iter().any(|&(plan, format, claim)| {
            format == input.format_hint && covers(claim, first)
                && others.iter().all(|&(claims, extent)| {
                    claims.is_some_and(|claims| claims.iter().any(|&(owner, _, claim)|
                        owner == plan && covers(claim, extent)
                    ))
                })
        })
    });
}

/// The filtered/raw output snapshot is cheap preparation, not archive discovery.
/// Own it across the prompt so the worker manifest can be dropped before waiting.
pub(super) struct OutputDiscovery {
    root: String,
    filtered: NativeDirectorySnapshot,
    raw: NativeDirectorySnapshot,
}

impl OutputDiscovery {
    pub(super) fn prepare_many<T: Send, U: Send>(
        mut inputs: impl Iterator<Item = T>,
        options: &NativeDirectoryScanOptions,
        cancel: &crate::io::cancellation::Cancellation,
        inventory: impl Fn(T) -> (U, NativeOutputInventory) + Sync,
        mut emit: impl FnMut(U, Self),
    ) -> io::Result<()> {
        let prepare = |input| {
            cancel.run(|| {
                cancel.check_io()?;
                let (key, inventory) = inventory(input);
                let output = Self::prepare(inventory, options)?;
                cancel.check_io()?;
                Ok::<_, io::Error>((key, output))
            })
        };
        while let Some(first) = inputs.next() {
            let Some(second) = inputs.next() else {
                let (key, output) = prepare(first)?;
                emit(key, output);
                break;
            };
            // Overlap filesystem walks and snapshot construction without
            // creating a second pool of file-head readers.
            let (first, second) = crate::analysis_native::volume_anchor::cheap_fast_probe_pool()
                .install(|| rayon::join(|| prepare(first), || prepare(second)));
            let (key, output) = first?;
            emit(key, output);
            let (key, output) = second?;
            emit(key, output);
        }
        Ok(())
    }

    pub(super) fn prepare(
        inventory: NativeOutputInventory,
        options: &NativeDirectoryScanOptions,
    ) -> io::Result<Self> {
        let root = inventory.root().to_owned();
        let (filtered, raw) = inventory.build_directory_snapshots(options)?;
        Ok(Self {
            root,
            filtered,
            raw,
        })
    }

    pub(super) fn has_files(&self) -> bool {
        self.filtered.records().any(|(_, is_dir, _, _)| !is_dir)
    }

    pub(super) fn scan_errors(&self) -> Vec<DirectoryReadError> {
        self.filtered.scan_errors()
    }

    fn authorize(root: String, raw: NativeDirectorySnapshot, request: &Request, result: &mut Discovered) {
        let policy = request.config.recursive_authorization;
        if policy.enabled && !result.tasks.is_empty() {
            let allowed = authorize_nested_candidates(
                &raw,
                Path::new(&root),
                result.tasks.iter().map(|task| {
                    (
                        task.entry().entry_path.as_str(),
                        task.inputs
                            .iter()
                            .flat_map(|logical| logical.input.physical_paths()),
                    )
                }),
                policy,
            );
            let mut allowed = allowed.into_iter();
            result.tasks.retain(|_| allowed.next() == Some(true));
        }
        assign_retry_scopes(
            &mut result.tasks,
            &[Arc::new(RetryScope {
                scope: Arc::new(NativeDiscoveryScope::new(root, None, Vec::new())),
                snapshot: raw,
                bucket: String::new(),
            })],
        );
    }

    pub(super) fn discover_many(outputs: Vec<Self>, candidates: &CandidateSet, request: &Request) -> io::Result<Vec<Discovered>> {
        let mut verified = HashMap::new();
        let mut tables = outputs.iter().map(|output|
            directory_table(&output.filtered, &output.raw, None, candidates, &mut verified, request)
        ).collect::<io::Result<Vec<_>>>()?;
        let mut results = Vec::with_capacity(outputs.len());
        Discovered::project_into(&mut tables, candidates, &verified, request, true, |scoped| results.push(scoped))?;
        for (Self { root, raw, .. }, result) in outputs.into_iter().zip(&mut results) {
            Self::authorize(root, raw, request, result);
        }
        Ok(results)
    }
}

fn retain_logical_retry_scopes(
    logical_scopes: impl IntoIterator<Item = NativeDiscoveryScope>,
    scopes: &mut Vec<Arc<RetryScope>>,
) {
    let mut by_root: HashMap<_, _> = scopes
        .iter()
        .map(|scope| (scope.scope.key().to_owned(), Arc::clone(scope)))
        .collect();
    for scope in logical_scopes {
        if by_root.contains_key(scope.key()) {
            continue;
        }
        let Some(source) = path_ancestors(scope.key()).find_map(|key| {
            by_root
                .get(key)
                .filter(|source| source.scope.contains_key(scope.key()))
        }) else {
            continue;
        };
        let retry = Arc::new(RetryScope {
            // Retry takes a fresh inventory within scope. It uses the old
            // snapshot only to reuse anchors for paths in that inventory.
            snapshot: source.snapshot.share_rows(),
            scope: Arc::new(scope),
            bucket: source.bucket.clone(),
        });
        by_root.insert(retry.scope.key().to_owned(), Arc::clone(&retry));
        scopes.push(retry);
    }
}

fn assign_retry_scopes(tasks: &mut [Task], scopes: &[Arc<RetryScope>]) {
    if scopes.is_empty() {
        return;
    }
    let has_buckets = scopes.iter().any(|scope| !scope.bucket.is_empty());
    let by_root = (!has_buckets && scopes.len() > 1).then(|| scopes.iter()
        .map(|scope| (scope.scope.key(), scope)).collect::<HashMap<_, _>>());
    // Catalog buckets already define membership, including generated files
    // outside the ordinary root. Physical ancestry only defines CLI scopes.
    let by_bucket = has_buckets.then(|| scopes.iter().map(|scope|
        (scope.bucket.as_str(), scope)).collect::<HashMap<_, _>>());
    for task in tasks.iter_mut() {
        let input = task.entry();
        let may_split = input.mode.structured()
            || matches!(input.format_hint.as_str(), "zip" | "rar" | "7z")
            || task.inputs[0]
                .failure
                .as_ref()
                .is_some_and(|failure| failure.kind == FailureKind::MissingVolume);
        let key = path_key(&input.entry_path);
        let bucket = has_buckets.then(|| crate::scan::catalog::catalog_stem(&input.entry_path));
        let selected = if let Some(by_bucket) = &by_bucket {
            bucket.as_deref().and_then(|bucket| by_bucket.get(bucket)).copied()
        } else if let Some(by_root) = &by_root {
            path_ancestors(&key).find_map(|root| {
                by_root.get(root)
                    .filter(|scope| scope.scope.contains_key(&key))
                    .copied()
            })
        } else {
            let scope = &scopes[0];
            scope.scope.contains_key(&key).then_some(scope)
        };
        task.context = selected.map(|scope| {
            if task.inputs.len() == 1 && may_split {
                TaskContext::Retry(Arc::clone(scope))
            } else {
                TaskContext::Report(Arc::clone(&scope.scope))
            }
        });
    }
}

pub(super) fn retry_volume(
    original: &super::ArchiveResult,
    missing: &[PathBuf],
    context: &RetryScope,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet,
    request: &Request,
) -> io::Result<Option<Task>> {
    request.cancel.check_io()?;
    // Only admission can release a previously required name. Use the live
    // snapshot below to find replacements, without redefining the input group
    // from a second set of file existence checks.
    let missing: HashSet<_> = missing.iter().map(|path| path_key(&path.to_string_lossy())).collect();
    let mut surviving = original.source_paths.iter().filter_map(|path| {
        let key = path_key(&path.to_string_lossy());
        (!missing.contains(&key)).then_some((path, key))
    });
    let Some((seed, first)) = surviving.next() else {
        return Ok(None);
    };
    let required: HashSet<_> = std::iter::once(first).chain(surviving.map(|(_, key)| key)).collect();
    let seed = seed.to_string_lossy();
    let (filtered, raw) = options.refresh_relation_bucket(
        &context.scope,
        &seed,
        &context.snapshot,
        request.watch_catalog.as_deref().filter(|_| {
            request
                .discovery_scope
                .as_ref()
                .is_some_and(|scope| path_key(&scope.root) == path_key(&context.scope.root))
        }),
    )?;
    resolve_volume(Path::new(seed.as_ref()), &filesystem_logical_name(&original.path.to_string_lossy()), &original.format, &required, &filtered, &raw, candidates, request)
}

fn resolve_volume(
    original: &Path, logical_name: &str, format: &str, required: &HashSet<String>,
    filtered: &NativeDirectorySnapshot, raw: &NativeDirectorySnapshot,
    candidates: &CandidateSet, request: &Request,
) -> io::Result<Option<Task>> {
    let mut verified = HashMap::new();
    let targets = vec![(original.to_string_lossy().into_owned(), logical_name.to_owned())];
    let table = directory_table(filtered, raw, Some(FileTargets::new(targets)), candidates, &mut verified, request)?;
    for index in table.resolve()?.resolved_relations() {
        let task = project_task(table.project(index)?, DiscoverySource::Relations, &verified);
        let input = task.entry();
        if task.inputs[0].failure.is_none() && input.mode.structured()
            && (format.is_empty() || input.format_hint == format)
            && required.is_subset(&input.physical_paths().map(path_key).collect()) {
            return Ok(Some(task));
        }
    }
    Ok(None)
}

pub(super) fn find_watch_volume(
    request: &Request, options: &NativeDirectoryScanOptions, candidates: &CandidateSet, retry_incomplete: bool,
) -> io::Result<Option<Arc<super::PreparedVolume>>> {
    let (Some(scope), Some(path)) = (&request.discovery_scope, request.inputs.first()) else {
        return Ok(None);
    };
    let path = path.to_string_lossy();
    let (filtered, raw) = if let Some(catalog) = &request.watch_catalog {
        options.catalog_snapshot(catalog, scope, &path)?
    } else {
        options.scan_scope(scope)?
    };
    let mut verified = HashMap::new();
    let targets = FileTargets::new(vec![(path.to_string(), filesystem_logical_name(&path))]);
    let mut table = directory_table(&filtered, &raw, Some(targets), candidates, &mut verified, request)?;
    let mut discovered = Discovered::default();
    // Reuse the complete projection, including embedded members and carriers.
    // This is a dependency lookup for an already admitted source; it neither
    // discovers unrelated arrivals nor traverses any output recursively.
    discovered.project(std::slice::from_mut(&mut table), candidates, &verified, request, false)?;
    if let Some(error) = discovered.errors.first() { return Err(io::Error::other(error.message.clone())); }
    if discovered.tasks.is_empty() || (!retry_incomplete && !discovered.tasks.iter().flat_map(|task| &task.inputs).any(|logical|
        logical.failure.is_none() && (logical.input.mode.structured()
            || logical.input.parts.len() > 1 || logical.input.volume_attempts.is_some()))) {
        return Ok(None);
    }
    let context = Arc::new(RetryScope { scope: Arc::new(scope.clone()), snapshot: raw,
        bucket: crate::scan::catalog::catalog_stem(&path) });
    let mut seen = HashSet::new();
    let mut generations = Vec::new();
    for task in &mut discovered.tasks {
        task.context = Some(if task.inputs.len() == 1 {
            TaskContext::Retry(Arc::clone(&context))
        } else {
            TaskContext::Report(Arc::clone(&context.scope))
        });
        for path in &task.owned_paths {
            if seen.insert(path_key(path)) {
                generations.push((path.clone(), crate::io::reader::capture_file_generation(Path::new(path))?));
            }
        }
    }
    let plan = PreparedVolumePlan { path: path_key(&path), generations, tasks: discovered.tasks };
    Ok(Some(Arc::new(super::PreparedVolume(std::sync::Mutex::new(Some(plan))))))
}

fn watch_discovery_error(path: PathBuf, error: io::Error) -> InputError {
    InputError {
        path, message: error.to_string(), kind: InputErrorKind::WatchDiscoveryIo,
        failure: None, scan_operation: None,
    }
}

fn directory_table(
    filtered: &NativeDirectorySnapshot,
    raw: &NativeDirectorySnapshot,
    targets: Option<FileTargets>,
    candidates: &CandidateSet,
    verified: &mut VerifiedPasswords,
    request: &Request,
) -> io::Result<NativeCandidateTable> {
    let mut table = NativeCandidateTable::new();
    table.append_directory(raw, filtered, targets, request.deep)?;
    probe_relations(&mut table, filtered, raw, candidates, verified, request)?;
    Ok(table)
}

fn probe_relations(
    table: &mut NativeCandidateTable,
    filtered: &NativeDirectorySnapshot,
    raw: &NativeDirectorySnapshot,
    candidates: &CandidateSet,
    verified: &mut VerifiedPasswords,
    request: &Request,
) -> io::Result<()> {
    use rayon::prelude::*;
    if request.deep { return Ok(()); }
    let pending = table.encrypted_rar_anchors();
    if pending.is_empty() { return Ok(()); }
    let resolved = pending.into_par_iter().map(|anchor| request.cancel.run(|| {
        // Open even without password candidates, so a departed member refreshes the family.
        let resolved = NativeArchiveSession::new(anchor.path.clone())
            .and_then(|session| candidates.resolve_relation(&anchor, &session, &request.cancel));
        match resolved {
            Ok((anchor, password)) => Ok((anchor, password, false)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((anchor, None, true)),
            Err(error) => Err(error),
        }
    })).collect::<io::Result<Vec<_>>>()?;
    let mut anchors = Vec::with_capacity(resolved.len());
    let mut refresh = Vec::new();
    for (anchor, password, departed) in resolved {
        if departed { refresh.push(anchor.path.clone()); }
        if let Some(password) = password {
            candidates.remember_verified(password.clone());
            verified.insert((path_key(&anchor.path), anchor.structure_offset.unwrap_or(0)), password);
        }
        anchors.push(anchor);
    }
    table.retry_relations(raw, filtered, anchors, Some(refresh))?;
    Ok(())
}

#[cfg(test)]
thread_local! { static MEASURED_EMBEDDED_PAGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

impl Discovered {
    fn project(
        &mut self,
        tables: &mut [NativeCandidateTable],
        candidates: &CandidateSet,
        verified: &VerifiedPasswords,
        request: &Request,
        recursive: bool,
    ) -> io::Result<()> {
        Self::project_into(tables, candidates, verified, request, recursive, |scoped| {
            self.tasks.extend(scoped.tasks);
            self.blocked_paths.extend(scoped.blocked_paths);
            self.errors.extend(scoped.errors);
        })
    }

    fn project_into(
        tables: &mut [NativeCandidateTable],
        candidates: &CandidateSet,
        verified: &VerifiedPasswords,
        request: &Request,
        recursive: bool,
        mut emit: impl FnMut(Self),
    ) -> io::Result<()> {
        // Keep relation ownership local, but fill each bounded Embedded page
        // across scopes, as main's discover_many_native does.
        let mut scopes = tables
            .iter_mut()
            .map(|table| {
                table.dedupe();
                let mut scoped = Self::default();
                let batch = scoped.prepare(table, verified, request, recursive)?;
                Ok((scoped, batch, Vec::new()))
            })
            .collect::<io::Result<Vec<_>>>()?;
        const PAGE_SIZE: usize = 256;
        let mut first = 0;
        while first < scopes.len() {
            if scopes[first].1.len() == 0 { first += 1; continue; }
            #[cfg(test)]
            MEASURED_EMBEDDED_PAGES.with(|pages| pages.set(pages.get() + 1));
            request.cancel.check_io()?;
            let mut last = first;
            let mut count = scopes[first].1.len();
            while count < PAGE_SIZE && last + 1 < scopes.len() {
                last += 1;
                count += scopes[last].1.len();
            }
            let groups = tables[first..=last].iter_mut()
                .zip(scopes[first..=last].iter_mut())
                .map(|(table, (_, batch, _))| (table, batch)).collect();
            for (group, rows) in NativeEmbeddedBatch::scan_pages(groups, PAGE_SIZE)? {
                let group = first + group;
                let (scoped, _, tasks) = &mut scopes[group];
                scoped.project_rows(&tables[group], rows, tasks, candidates, verified)?;
            }
        }
        for (table, (mut scoped, mut batch, mut embedded_tasks)) in tables.iter_mut().zip(scopes) {
            scoped.finish(table, &mut batch, &mut embedded_tasks, candidates, verified)?;
            emit(scoped);
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        table: &mut NativeCandidateTable,
        verified: &VerifiedPasswords,
        request: &Request,
        recursive: bool,
    ) -> io::Result<NativeEmbeddedBatch> {
        if request.deep {
            return Ok(table.prepare_deep(recursive, request.config.embedded_scan.recursive_candidate_ratio));
        }
        let mut routes = table.resolve()?;
        for &(index, status) in &routes.relation_events {
            if matches!(status, 1 | 2) {
                self.tasks.push(project_task(
                    table.project(index)?,
                    DiscoverySource::Relations,
                    verified,
                ));
            }
        }
        for &index in &routes.detected {
            self.tasks.push(project_task(
                table.project(index)?,
                DiscoverySource::Detection,
                verified,
            ));
        }
        let embedded = request.config.embedded_scan;
        Ok(table.prepare_embedded(
            &mut routes,
            recursive,
            embedded.enabled,
            embedded.recursive_candidate_ratio,
        ))
    }

    fn project_rows(
        &mut self,
        table: &NativeCandidateTable,
        rows: Vec<EmbeddedPageRow>,
        embedded_tasks: &mut Vec<Task>,
        candidates: &CandidateSet,
        verified: &VerifiedPasswords,
    ) -> io::Result<()> {
        for row in rows {
            if let Some(error) = row.error {
                let (path, format) = table.summary(row.index)?;
                let failure = embedded_read_failure(&path, error.to_string());
                if format.is_empty() {
                    self.blocked_paths.extend(table.path_keys(row.index)?);
                    self.errors.push(InputError {
                        path: PathBuf::from(path),
                        message: failure.message.clone(),
                        kind: InputErrorKind::EmbeddedDiscovery,
                        failure: Some(Box::new(failure)),
                        scan_operation: None,
                    });
                } else {
                    let mut task = project_task(
                        table.project(row.index)?,
                        DiscoverySource::Embedded,
                        verified,
                    );
                    task.inputs[0].failure = Some(failure);
                    embedded_tasks.push(task);
                }
            } else if let Some(scan) = row.scan {
                let task = project_task(
                    table.project(row.index)?,
                    DiscoverySource::Embedded,
                    verified,
                );
                if let Some(task) = project_segments(task, &scan, HashMap::new(), candidates)? {
                    embedded_tasks.push(task);
                }
            }
        }
        Ok(())
    }

    fn finish(
        &mut self,
        table: &mut NativeCandidateTable,
        batch: &mut NativeEmbeddedBatch,
        embedded_tasks: &mut Vec<Task>,
        candidates: &CandidateSet,
        verified: &VerifiedPasswords,
    ) -> io::Result<()> {
        let passwords = batch
            .encrypted_volume_paths(table)
            .into_iter()
            .map(|path| {
                let values = candidates.for_embedded(&path);
                (path, values)
            })
            .collect();
        let volumes = batch.resolve_volumes(table, Some(passwords))?;
        let mut replaced = HashSet::new();
        let mut shared_inputs = false;
        // The volume pass can add logical inputs backed by sources that
        // Embedded already projected. Ordinary candidates have been deduped.
        for row in volumes {
            if let Some(scan) = row.scan {
                let task = project_task(
                    table.project(row.index)?,
                    DiscoverySource::Embedded,
                    verified,
                );
                if let Some(task) =
                    project_segments(task, &scan.scan, scan.resolutions, candidates)?
                {
                    embedded_tasks.push(task);
                }
            } else if row.status != 0 {
                let mut task = project_task(
                    table.project(row.index)?,
                    DiscoverySource::Relations,
                    verified,
                );
                if let Some(password) = row.password {
                    task.inputs[0].password = Some(password);
                }
                for path in &task.owned_paths {
                    self.blocked_paths.remove(&path_key(path));
                }
                embedded_tasks.push(task);
            }
        }
        for task in embedded_tasks.iter() {
            let blocked = task.inputs.len() == 1 && task.inputs[0].failure.is_some();
            for path in &task.owned_paths {
                let key = path_key(path);
                if blocked {
                    self.blocked_paths.insert(key.clone());
                }
                shared_inputs |= !replaced.insert(key);
            }
        }
        if !replaced.is_empty() || !self.blocked_paths.is_empty() {
            let is_replaced = |path: &str| {
                let key = path_key(path);
                replaced.contains(&key) || self.blocked_paths.contains(&key)
            };
            self.tasks.retain(|task| {
                if let Some(input) = task
                    .inputs
                    .iter()
                    .find(|input| input.input.volume_attempts.is_some())
                {
                    shared_inputs |= input.input.physical_paths().any(&is_replaced);
                    true
                } else {
                    !task.owned_paths.iter().any(|path| is_replaced(path))
                }
            });
            self.tasks.append(embedded_tasks);
        }
        if shared_inputs && self.tasks.len() > 1 {
            merge_shared_inputs(&mut self.tasks, &mut self.blocked_paths);
        }
        Ok(())
    }
}

fn project_task(
    projected: CandidateProjection<'_>,
    source: DiscoverySource,
    verified: &VerifiedPasswords,
) -> Task {
    match projected {
        CandidateProjection::File {
            path,
            format_hint,
            logical_name,
            ..
        } => Task::single(
            ArchiveInput::file(path.to_owned(), format_hint.to_owned(), logical_name),
            vec![path.to_owned()],
            source,
            None,
        ),
        CandidateProjection::Relation {
            relation,
            ..
        } => {
            let password = (!verified.is_empty())
                .then(|| verified.get(&password_key(&relation.input)).cloned())
                .flatten();
            let reason = relation.failure_reason;
            let failure =
                if relation.standalone && password.is_some() && reason == Some("needs_password") {
                    None
                } else {
                    reason.and_then(|reason| discovery_failure(reason, source, &relation.input.entry_path))
                };
            let mut task = Task::single(relation.input, relation.owned_paths, source, failure);
            task.inputs[0].password = password;
            task
        }
    }
}

fn project_segments(
    mut task: Task,
    scan: &NativeScanResult,
    mut resolutions: HashMap<u64, RarInputResolution>,
    candidates: &CandidateSet,
) -> io::Result<Option<Task>> {
    let path = task.entry().entry_path.clone();
    let name = task.entry().logical_name.clone();
    let mut errors = HashMap::new();
    let unresolved: Vec<_> = scan
        .candidates()
        .iter()
        .filter_map(|item| {
            (item.is_logical_archive()
                && item.volume_anchor.is_none()
                && item.password_required()
                && item.end_offset.is_none()
                && !resolutions.contains_key(&item.offset))
            .then_some(item.offset)
        })
        .collect();
    if !unresolved.is_empty() {
        let passwords = candidates.for_embedded(&path);
        for result in resolve_embedded_rar_boundaries(path.clone(), unresolved, &passwords)? {
            let reason = match result.status {
                "ok" => None,
                "password_required" => Some("embedded_password_required"),
                "wrong_password" => Some("embedded_wrong_password"),
                "truncated" => Some("embedded_truncated"),
                _ => Some("embedded_scan_io_error"),
            };
            if let Some(error) = result.error {
                errors.insert(result.offset, error);
            }
            resolutions.insert(
                result.offset,
                RarInputResolution {
                    end_offset: result.end_offset,
                    password: result.password,
                    failure_reason: reason,
                },
            );
        }
    }
    let mut inputs = Vec::new();
    for item in scan.candidates() {
        let resolution = resolutions.remove(&item.offset);
        let resolved_end = resolution.as_ref().and_then(|result| result.end_offset);
        let end = resolved_end.or(item.end_offset);
        let failure = resolution.as_ref().and_then(|result| result.failure_reason);
        // The validated ENC header admits decryption through EOF without
        // supplying an exact archive boundary.
        let confirmed = item.is_logical_archive()
            && (resolved_end.is_some() || (item.volume_anchor.is_none()
                && (item.end_offset.is_some() || item.format == "enc")));
        if !confirmed && failure.is_none() {
            continue;
        }
        let mut input = ArchiveInput::file(path.clone(), item.format.to_owned(), name.clone());
        if item.offset != 0 || end.is_some_and(|end| end < scan.file_size()) {
            input.mode = OpenMode::FileRange;
            input.parts = Box::new([InputPart::range(InputExtent {
                path: path.clone(),
                start: item.offset,
                end,
            })]);
        }
        input.analysis.origin = AnalysisOrigin::Embedded;
        input.analysis.password_required = item.password_required();
        input.analysis.structure_complete = item.format == "lz4" && end.is_some();
        input.analysis.volume_completeness = Some(if end.is_some() {
            VolumeCompleteness::Complete
        } else {
            VolumeCompleteness::Unknown
        });
        input.analysis.zip_eocd_offset = item
            .zip_eocd_offset
            .and_then(|offset| offset.checked_sub(item.offset));
        let mut failure = failure.and_then(|reason| discovery_failure(reason, DiscoverySource::Embedded, &input.entry_path));
        if let (Some(failure), Some(error)) = (&mut failure, errors.remove(&item.offset)) {
            if let Some(super::FailureContext::Discovery { error: diagnostic, .. }) = failure.context.as_deref_mut() {
                *diagnostic = error.clone();
            }
            failure.message = error;
        }
        inputs.push(LogicalInput {
            input,
            password: resolution.and_then(|result| result.password),
            failure,
        });
    }
    if inputs.is_empty() {
        return Ok(None);
    }
    task.source = DiscoverySource::Embedded;
    task.inputs = inputs;
    Ok(Some(task))
}

fn embedded_read_failure(path: &str, error: String) -> Failure {
    Failure::new(FailureKind::FilesystemError, error.clone()).with_context(
        super::FailureContext::Discovery {
            discovery: DiscoverySource::Embedded,
            reason: "embedded_scan_io_error".to_owned(),
            path: PathBuf::from(path),
            error,
        },
    )
}

fn discovery_failure(reason: &str, source: DiscoverySource, path: &str) -> Option<Failure> {
    let (kind, message) = match reason {
        "needs_password" | "embedded_password_required" => {
            (FailureKind::PasswordRequired, "Password not found in the password list")
        }
        "wrong_password" | "embedded_wrong_password" => (FailureKind::WrongPassword, "Password not found in the password list"),
        "missing_volume" | "ambiguous_volume_mapping" | "structural_conflict" => {
            (FailureKind::MissingVolume, "Missing volume")
        }
        "embedded_truncated" | "corrupt_archive" | "needs_volume_or_tail_damaged" => {
            (FailureKind::Damaged, "Damaged archive")
        }
        "unsupported" => (FailureKind::Unsupported, "Unsupported archive"),
        "embedded_scan_io_error" => (FailureKind::FilesystemError, "Unable to read archive input"),
        _ => return None,
    };
    let mut failure = Failure::new(kind, message).with_context(super::FailureContext::Discovery {
        discovery: source, reason: reason.to_owned(), path: PathBuf::from(path), error: String::new(),
    });
    failure.evidence = Some(Box::new(super::FailureEvidence {
        stage: Some("discovery".into()),
        native_kind: Some(reason.to_owned()),
        ..Default::default()
    }));
    Some(failure)
}

fn merge_shared_inputs(tasks: &mut Vec<Task>, blocked_paths: &mut HashSet<String>) {
    let mut owners = HashMap::new();
    let mut parents: Vec<_> = (0..tasks.len()).collect();
    let mut shared = false;
    for (index, task) in tasks.iter().enumerate() {
        for path in &task.owned_paths {
            if let Some(other) = owners.insert(path_key(path), index) {
                let left = root(&mut parents, index);
                let right = root(&mut parents, other);
                if left != right {
                    parents[left] = right;
                    shared = true;
                }
            }
        }
    }
    if !shared {
        return;
    }
    let mut combined: BTreeMap<usize, (Task, bool)> = BTreeMap::new();
    for (index, task) in std::mem::take(tasks).into_iter().enumerate() {
        let group = root(&mut parents, index);
        match combined.entry(group) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert((task, false));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let (combined, shared) = slot.get_mut();
                *shared = true;
                if combined.primary.is_none() {
                    combined.primary = Some(Box::new(combined.entry().clone()));
                }
                if task.source == DiscoverySource::Relations
                    && combined.source != DiscoverySource::Relations
                {
                    combined.primary = Some(Box::new(task.entry().clone()));
                    combined.source = DiscoverySource::Relations;
                }
                combined.inputs.extend(task.inputs);
                combined.owned_paths.extend(task.owned_paths);
            }
        }
    }
    tasks.extend(combined.into_values().map(|(mut task, shared)| {
        if !shared {
            return task;
        }
        let mut seen = HashSet::new();
        task.owned_paths.retain(|path| {
            let key = path_key(path);
            blocked_paths.remove(&key);
            seen.insert(key)
        });
        task.inputs.sort_by_cached_key(|logical| {
            (
                path_key(&logical.input.entry_path),
                logical
                    .input
                    .physical_extents()
                    .next()
                    .map_or(0, |extent| extent.start),
            )
        });
        task.inputs.dedup_by(|next, previous| {
            let left = &next.input;
            let right = &previous.input;
            let same = path_key(&left.entry_path) == path_key(&right.entry_path)
                && left.mode == right.mode
                && left.format_hint == right.format_hint
                && left.parts == right.parts
                && left.volume_attempts == right.volume_attempts;
            if same {
                if previous.failure.is_some() && next.failure.is_none() {
                    std::mem::swap(previous, next);
                }
                if previous.password.is_none() {
                    previous.password = next.password.take();
                }
            }
            same
        });
        if task.primary.is_some() && task.inputs.len() > 1 {
            task.source = DiscoverySource::Embedded;
        } else if task.inputs.len() == 1 {
            task.primary = None;
        }
        task
    }));
}

fn root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

#[cfg(test)]
#[path = "../../tests/unit/pipeline/discovery/tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "../../../../benchmarks/native/game_tree/probe.rs"]
mod game_tree_bench;
