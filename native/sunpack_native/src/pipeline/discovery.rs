use super::passwords::CandidateSet;
use super::{DiscoverySource, Failure, FailureKind, InputError, InputErrorKind, Origin, Request};
use crate::core::config::{Config, ScanFilterKind};
use crate::io::archive_state::{
    ArchiveInput, InputExtent, InputPart, OpenMode, VolumeCompleteness,
};
use crate::io::directory_errors::{DirectoryReadError, DirectoryReadErrors};
use crate::password::rar::resolve_embedded_rar_boundaries;
use crate::path_keys::{path_ancestors, path_key};
use crate::scan::directory::{
    classify_scan_targets, filesystem_logical_name, is_reparse_point, NativeDirectoryScanOptions,
    NativeDirectorySnapshot, NativeOutputInventory,
};
use crate::scan::discovery::{
    CandidateProjection, EmbeddedPageRow, FileTargets, NativeCandidateTable, NativeEmbeddedBatch,
};
use crate::scan::embedded::{EmbeddedCandidate, NativeScanResult, RarInputResolution};
use crate::scan::nested_authorization::authorize_nested_candidates;
use crate::scan::scope::NativeDiscoveryScope;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) struct LogicalInput {
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
    pub retry: Option<Arc<RetryScope>>,
    pub scope: Option<Arc<NativeDiscoveryScope>>,
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
            retry: None,
            scope: None,
        }
    }

    pub(super) fn entry(&self) -> &ArchiveInput {
        self.primary.as_deref().unwrap_or(&self.inputs[0].input)
    }
}

pub(super) struct Discovered {
    pub tasks: Vec<Task>,
    pub errors: Vec<InputError>,
    pub scan_errors: DirectoryReadErrors,
    pub(super) blocked_paths: HashSet<String>,
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

fn walk_can_reach(root: &str, target: &str) -> bool {
    for path in Path::new(target).ancestors() {
        if path_key(&path.to_string_lossy()).trim_end_matches('\\') == root {
            return true;
        }
        if std::fs::symlink_metadata(path).map_or(true, |meta| is_reparse_point(&meta)) {
            return false;
        }
    }
    false
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
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for input in &request.inputs {
        let path = std::path::absolute(input)?.to_string_lossy().into_owned();
        if request
            .discovery_scope
            .as_ref()
            .is_none_or(|scope| scope.contains(&path))
            && seen.insert(path_key(&path))
        {
            paths.push(path);
        }
    }
    let (kinds, errors) = classify_scan_targets(&paths);
    result.scan_errors = errors;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for (path, kind) in paths.into_iter().zip(kinds) {
        match kind {
            1 => files.push(path),
            2 if !request.direct => directories.push(path),
            2 | 3 => result.errors.push(InputError {
                path: PathBuf::from(path),
                message: "A regular input file is required".to_owned(),
                kind: InputErrorKind::InvalidInput,
                scan_operation: None,
                scan_count: None,
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
    let share_recursive = request.recursive && options.can_share_recursive_context();
    if share_recursive && scopes.len() > 1 {
        let roots: HashMap<_, _> = scopes.iter().map(|scope| (scope.key(), scope)).collect();
        let covered: Vec<_> = scopes
            .iter()
            .map(|scope| {
                path_ancestors(scope.key()).skip(1).any(|parent| {
                    roots.get(parent).is_some_and(|root| {
                        root.max_depth.is_none()
                            && root.contains_key(scope.key())
                            && walk_can_reach(root.key(), &scope.root)
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
    for path in &files {
        let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(path));
        let logical_scope = request.discovery_scope.clone().unwrap_or_else(|| {
            NativeDiscoveryScope::new(
                parent.to_string_lossy().into_owned(),
                if request.direct { Some(0) } else { max_depth },
                Vec::new(),
            )
        });
        logical_scopes
            .entry(logical_scope.key().to_owned())
            .or_insert(logical_scope);
        if !roots.is_empty() {
            let key = path_key(path);
            let parent_path = parent.to_string_lossy();
            if path_ancestors(&key).any(|candidate| {
                roots.get(candidate).is_some_and(|scope| {
                    scope.contains_key(&key)
                        && (scope.key() == path_key(&parent_path).trim_end_matches('\\')
                            || (share_recursive && walk_can_reach(scope.key(), &parent_path)))
                })
            }) {
                continue;
            }
        }
        let parent = request
            .discovery_scope
            .as_ref()
            .map(|scope| scope.root.clone())
            .unwrap_or_else(|| parent.to_string_lossy().into_owned());
        let bucket = if request.watch_catalog.is_some() {
            crate::scan::catalog::catalog_stem(path)
        } else {
            String::new()
        };
        let mut key = path_key(&parent);
        key.truncate(key.trim_end_matches('\\').len());
        by_parent
            .entry((key, bucket))
            .or_insert_with(|| (parent, Vec::new()))
            .1
            .push((path.clone(), filesystem_logical_name(path)));
    }
    // Share physical enumeration, never the logical relation boundary. Each
    // selected file keeps its original parent scope, including replacement retry.
    let mut shared_roots = HashMap::new();
    if share_recursive
        && !request.direct
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
                if request.direct { Some(0) } else { max_depth },
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
        let table = directory_table(
            &filtered,
            &raw,
            Some(FileTargets::new(targets)),
            candidates,
            &mut verified,
            request,
        )?;
        tables.push(table);
        retry_scopes.push(Arc::new(RetryScope {
            scope: Arc::new(scope),
            snapshot: raw,
            bucket,
        }));
    }
    for (filtered, _) in shared_snapshots.values() {
        result.scan_errors.extend(filtered.scan_errors());
    }
    result.project(&mut tables, candidates, &verified, request, false)?;
    if request.origin == Origin::Watch {
        let admitted = |path: &str| {
            let key = path_key(path);
            seen.contains(&key) || (!roots.is_empty() && covering_root(&key))
        };
        let ready = |path: &str| {
            admitted(path) || crate::filesystem::watch_file_is_ready(path).unwrap_or(false)
        };
        // A late launcher-only SFX companion can resolve a complete family,
        // but none of its data volumes belong to this batch. Related data
        // must also have closed before even a provisional blocker is published.
        result.tasks.retain(|task| {
            task.inputs.iter().any(|logical| {
                logical.failure.is_some() || logical.input.physical_paths().any(&admitted)
            }) && task.inputs.iter().all(|logical| {
                ready(&logical.input.entry_path)
                    && logical.input.physical_extents().all(|extent| {
                        extent.path == logical.input.entry_path || ready(&extent.path)
                    })
            })
        });
    }
    if request.direct {
        let covered: HashSet<_> = result
            .tasks
            .iter()
            .flat_map(|task| task.owned_paths.iter().map(|path| path_key(path)))
            .collect();
        for path in files.into_iter().filter(|path| {
            let key = path_key(path);
            !covered.contains(&key) && !result.blocked_paths.contains(&key)
        }) {
            let name = filesystem_logical_name(&path);
            result.tasks.push(Task::single(
                ArchiveInput::file(path.clone(), String::new(), name),
                vec![path],
                DiscoverySource::Direct,
                None,
            ));
        }
    }
    retain_logical_retry_scopes(logical_scopes.into_values(), &mut retry_scopes);
    assign_retry_scopes(&mut result.tasks, &retry_scopes);
    Ok(result)
}

/// The filtered/raw output snapshot is cheap preparation, not archive discovery.
/// Own it across the prompt so the worker manifest can be dropped before waiting.
pub(super) struct OutputDiscovery {
    root: String,
    filtered: NativeDirectorySnapshot,
    raw: NativeDirectorySnapshot,
}

impl OutputDiscovery {
    pub(super) fn prepare(
        inventory: NativeOutputInventory,
        options: &NativeDirectoryScanOptions,
    ) -> io::Result<Self> {
        let (filtered, raw) = inventory.build_directory_snapshots(options)?;
        Ok(Self {
            root: inventory.root().to_owned(),
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

    pub(super) fn discover(
        self,
        candidates: &CandidateSet,
        request: &Request,
        result: &mut Discovered,
    ) -> io::Result<()> {
        let Self {
            root,
            filtered,
            raw,
        } = self;
        let mut verified = HashMap::new();
        let mut table = directory_table(&filtered, &raw, None, candidates, &mut verified, request)?;
        result.project(
            std::slice::from_mut(&mut table),
            candidates,
            &verified,
            request,
            true,
        )?;
        let policy = request.config.recursive_authorization;
        if policy.enabled && !result.tasks.is_empty() {
            let allowed = authorize_nested_candidates(
                &raw,
                Path::new(&root),
                result.tasks.iter().map(|task| {
                    (
                        task.entry().entry_path.as_str(),
                        task.owned_paths.as_slice(),
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
        Ok(())
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
            snapshot: scope_view(&source.snapshot, &scope),
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
    let by_root = (scopes.len() > 1).then(|| {
        scopes
            .iter()
            .map(|scope| ((scope.scope.key(), scope.bucket.as_str()), scope))
            .collect::<HashMap<_, _>>()
    });
    let has_buckets = scopes.iter().any(|scope| !scope.bucket.is_empty());
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
        let selected = if let Some(by_root) = &by_root {
            path_ancestors(&key).find_map(|root| {
                bucket
                    .as_deref()
                    .and_then(|bucket| by_root.get(&(root, bucket)))
                    .or_else(|| by_root.get(&(root, "")))
                    .filter(|scope| scope.scope.contains_key(&key))
                    .map(|scope| Arc::clone(scope))
            })
        } else {
            let scope = &scopes[0];
            (scope.scope.contains_key(&key)
                && (scope.bucket.is_empty() || bucket.as_ref() == Some(&scope.bucket)))
            .then(|| Arc::clone(scope))
        };
        if task.source != DiscoverySource::Direct {
            task.scope = selected.as_ref().map(|scope| Arc::clone(&scope.scope));
        }
        if task.inputs.len() == 1 && may_split { task.retry = selected; }
    }
}

pub(super) fn retry_volume(
    original: &super::ArchiveResult,
    context: &RetryScope,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet,
    request: &Request,
) -> io::Result<Option<Task>> {
    request.cancel.check_io()?;
    let mut surviving = original.source_paths.iter().filter(|path| {
        !std::fs::metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    });
    let Some(seed) = surviving.next() else {
        return Ok(None);
    };
    let required: HashSet<_> = std::iter::once(seed)
        .chain(surviving)
        .map(|path| path_key(&path.to_string_lossy()))
        .collect();
    let seed = seed.to_string_lossy();
    if required.is_empty() {
        return Ok(None);
    }
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
    let mut verified = HashMap::new();
    let targets = vec![(
        seed.into_owned(),
        filesystem_logical_name(&original.path.to_string_lossy()),
    )];
    let table = directory_table(
        &filtered,
        &raw,
        Some(FileTargets::new(targets)),
        candidates,
        &mut verified,
        request,
    )?;
    for index in table.resolve()?.resolved_relations() {
        let task = project_task(table.project(index)?, DiscoverySource::Relations, &verified);
        let input = task.entry();
        if task.inputs[0].failure.is_none()
            && input.mode.structured()
            && (original.format.is_empty() || input.format_hint == original.format)
            && required.is_subset(&input.physical_paths().map(path_key).collect())
            // A live refresh may discover a new volume before the Watch
            // scheduler has admitted it. Let its close event retry the group.
            && (request.origin != Origin::Watch
                || input.physical_paths().all(|path| {
                    required.contains(&path_key(path))
                        || crate::filesystem::watch_file_is_ready(path).unwrap_or(false)
                }))
        {
            return Ok(Some(task));
        }
    }
    Ok(None)
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
    table.append_directory(raw, filtered, targets)?;
    let mut passwords = Vec::new();
    let mut refresh = Vec::new();
    let mut failures = Vec::new();
    for group in table.encrypted_rar_groups() {
        match candidates.plan(&group.input, None, &request.cancel) {
            Ok(Ok(plan)) if plan.verified => {
                let value = plan.selected.unwrap();
                // A standalone RAR4 main header already establishes the layout.
                // A full password proof can unblock it without revisiting its
                // original (encrypted) relation facts or probing a split bucket.
                if !group.standalone {
                    passwords.extend(
                        group
                            .owned_paths
                            .into_iter()
                            .map(|path| (path, value.to_string())),
                    );
                }
                verified.insert(password_key(&group.input), value);
            }
            Ok(Ok(_)) => failures.extend(
                group
                    .owned_paths
                    .into_iter()
                    .map(|path| (path, String::new())),
            ),
            Ok(Err(failure)) => {
                let reason = match failure.kind {
                    FailureKind::WrongPassword => "wrong_password",
                    FailureKind::PasswordRequired => "needs_password",
                    FailureKind::MissingVolume => "missing_volume",
                    FailureKind::Damaged => "corrupt_archive",
                    _ => "",
                };
                failures.extend(
                    group
                        .owned_paths
                        .into_iter()
                        .map(|path| (path, reason.to_owned())),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                refresh.extend(group.owned_paths.iter().cloned());
                failures.extend(
                    group
                        .owned_paths
                        .into_iter()
                        .map(|path| (path, "missing_volume".to_owned())),
                );
            }
            Err(error) => return Err(error),
        }
    }
    if !passwords.is_empty() || !refresh.is_empty() {
        table.retry_relations(raw, filtered, passwords, Some(refresh))?;
    }
    table.record_relation_failures(failures);
    Ok(table)
}

impl Discovered {
    fn project(
        &mut self,
        tables: &mut [NativeCandidateTable],
        candidates: &CandidateSet,
        verified: &VerifiedPasswords,
        request: &Request,
        recursive: bool,
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
        let mut total = 0;
        let ends: Vec<_> = scopes
            .iter()
            .map(|(_, batch, _)| {
                total += batch.len();
                total
            })
            .collect();
        for offset in (0..total).step_by(PAGE_SIZE) {
            request.cancel.check_io()?;
            let first = ends.partition_point(|&end| end <= offset);
            let last = ends.partition_point(|&end| end < (offset + PAGE_SIZE).min(total));
            let local_offset = offset - if first == 0 { 0 } else { ends[first - 1] };
            let groups = tables[first..=last]
                .iter()
                .zip(scopes[first..=last].iter_mut())
                .map(|(table, (_, batch, _))| (table, batch))
                .collect();
            for (group, rows) in NativeEmbeddedBatch::scan_pages(groups, local_offset, PAGE_SIZE)? {
                let group = first + group;
                let (scoped, _, tasks) = &mut scopes[group];
                scoped.project_rows(&tables[group], rows, tasks, candidates, verified)?;
            }
        }
        for (table, (mut scoped, mut batch, mut embedded_tasks)) in tables.iter_mut().zip(scopes) {
            scoped.finish(table, &mut batch, &mut embedded_tasks, candidates, verified)?;
            self.tasks.extend(scoped.tasks);
            self.blocked_paths.extend(scoped.blocked_paths);
            self.scan_errors.merge_report(scoped.scan_errors);
        }
        merge_shared_inputs(&mut self.tasks);
        Ok(())
    }

    fn prepare(
        &mut self,
        table: &mut NativeCandidateTable,
        verified: &VerifiedPasswords,
        request: &Request,
        recursive: bool,
    ) -> io::Result<NativeEmbeddedBatch> {
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
        for &(index, status) in &routes.detection_events {
            if status == 1 {
                let mut task =
                    project_task(table.project(index)?, DiscoverySource::Detection, verified);
                if let Some(analysis) = routes.primary_analysis(index) {
                    task.inputs[0].input.analysis = analysis;
                }
                self.tasks.push(task);
            }
        }
        let embedded = request.config.embedded_scan;
        let force = request.deep && !recursive;
        Ok(table.prepare_embedded(
            &mut routes,
            recursive,
            force,
            embedded.enabled || force,
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
                if format.is_empty() {
                    self.blocked_paths.insert(path_key(&path));
                    self.scan_errors.push_detail(
                        Path::new(&path),
                        "embedded_scan",
                        error.to_string(),
                    );
                } else {
                    let mut task = project_task(
                        table.project(row.index)?,
                        DiscoverySource::Embedded,
                        verified,
                    );
                    task.inputs[0].failure = Some(Failure::new(
                        FailureKind::FilesystemError,
                        error.to_string(),
                    ));
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
        for row in batch.resolve_volumes(table, Some(passwords))? {
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
                embedded_tasks.push(task);
            }
        }
        if !embedded_tasks.is_empty() {
            let replaced: HashSet<_> = embedded_tasks
                .iter()
                .flat_map(|task| task.owned_paths.iter().map(|path| path_key(path)))
                .collect();
            self.tasks.retain(|task| {
                task.inputs
                    .iter()
                    .any(|input| input.input.volume_attempts.is_some())
                    || !task
                        .owned_paths
                        .iter()
                        .any(|path| replaced.contains(&path_key(path)))
            });
            self.tasks.append(embedded_tasks);
        }
        merge_shared_inputs(&mut self.tasks);
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
            failure_reason,
            ..
        } => {
            let password = (!verified.is_empty())
                .then(|| verified.get(&password_key(&relation.input)).cloned())
                .flatten();
            let reason = failure_reason.or(relation.failure_reason);
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
    let split = task.entry().mode.structured();
    let mut errors = HashMap::new();
    let unresolved: Vec<_> = scan
        .candidates()
        .iter()
        .filter_map(|item| {
            (item.candidate_kind == "logical_archive"
                && item.volume_anchor.is_none()
                && password_required(item)
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
        let failure = resolution
            .as_ref()
            .and_then(|result| result.failure_reason)
            .or_else(|| {
                (!split
                    && item.candidate_kind == "logical_archive"
                    && item.volume_anchor.is_none()
                    && item.boundary_kind != "exact"
                    && item.validation == "start_header_crc_truncated_declared_range")
                    .then_some("embedded_truncated")
            });
        let exact = item.candidate_kind == "logical_archive"
            && (resolved_end.is_some()
                || (item.volume_anchor.is_none()
                    && item.boundary_kind == "exact"
                    && item.extractable
                    && end.is_some()));
        if !exact && failure.is_none() {
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
        input.analysis.password_required = password_required(item);
        input.analysis.structure_complete = item.format == "lz4";
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

fn password_required(item: &EmbeddedCandidate) -> bool {
    item.format == "rar"
        && (item
            .validation
            .starts_with("rar4_header_encrypted_main_header_crc")
            || item.validation.starts_with("rar5_encryption_header_crc"))
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

fn merge_shared_inputs(tasks: &mut Vec<Task>) {
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
    let mut combined: BTreeMap<usize, Task> = BTreeMap::new();
    for (index, task) in std::mem::take(tasks).into_iter().enumerate() {
        let group = root(&mut parents, index);
        match combined.entry(group) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(task);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let combined = slot.get_mut();
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
    tasks.extend(combined.into_values().map(|mut task| {
        if task.primary.is_some() {
            task.source = DiscoverySource::Embedded;
        }
        let mut seen = HashSet::new();
        task.owned_paths.retain(|path| seen.insert(path_key(path)));
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
                && left.ranges == right.ranges
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
mod tests {
    use super::*;
    #[test]
    fn embedded_pages_cross_scope_boundaries_without_losing_ownership() {
        let root = std::env::temp_dir().join(format!(
            "sunpack-pages-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut carrier = vec![0x41; 17];
        carrier.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00");
        let mut inputs = Vec::new();
        let mut expected = HashSet::new();
        // A page crosses roots and then splits inside the last root; the empty
        // middle root must not shift the group IDs used for result projection.
        for (scope, count) in [1, 0, 257].into_iter().enumerate() {
            let directory = root.join(scope.to_string());
            std::fs::create_dir_all(&directory).unwrap();
            for index in 0..count {
                let path = directory.join(format!("archive{index}.bin"));
                std::fs::write(&path, &carrier).unwrap();
                expected.insert(path_key(&path.to_string_lossy()));
            }
            inputs.push(directory);
        }
        let options =
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
                .unwrap();
        let candidates = CandidateSet::new(
            Arc::from([]),
            None,
            &super::super::passwords::AttemptCache::default(),
            None,
        );
        let mut request = Request::new(inputs, super::super::Mode::Scan);
        request.deep = true;
        let result = discover(&request, &options, &candidates).unwrap();
        assert!(result.errors.is_empty());
        assert!(result.blocked_paths.is_empty());
        assert_eq!(result.tasks.len(), expected.len());
        for task in result.tasks {
            assert_eq!(task.inputs.len(), 1);
            assert_eq!(task.owned_paths.len(), 1);
            assert!(expected.remove(&path_key(&task.entry().entry_path)));
            let retry = task.retry.as_ref().unwrap();
            assert_eq!(
                retry.scope.key(),
                path_key(
                    &Path::new(&task.entry().entry_path)
                        .parent()
                        .unwrap()
                        .to_string_lossy()
                )
            );
        }
        assert!(expected.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn covered_explicit_targets_keep_their_retry_boundary() {
        let root = std::env::temp_dir().join(format!(
            "sunpack-covered-scope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let child = root.join("child");
        std::fs::create_dir_all(&child).unwrap();
        let archive = child.join("archive.zip");
        // A complete stored ZIP, so discovery needs no worker or passwords.
        std::fs::write(&archive, b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00").unwrap();
        let options =
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
                .unwrap();
        let candidates = CandidateSet::new(
            Arc::from([]),
            None,
            &super::super::passwords::AttemptCache::default(),
            None,
        );
        for target in [&child, &archive] {
            for ancestor_first in [false, true] {
                let inputs = if ancestor_first {
                    vec![root.clone(), target.clone()]
                } else {
                    vec![target.clone(), root.clone()]
                };
                let mut request = Request::new(inputs, super::super::Mode::Scan);
                request.recursive = true;
                let result = discover(&request, &options, &candidates).unwrap();
                assert!(result.errors.is_empty());
                assert_eq!(result.tasks.len(), 1);
                let task = &result.tasks[0];
                assert_eq!(task.inputs.len(), 1);
                assert_eq!(
                    path_key(&task.entry().entry_path),
                    path_key(&archive.to_string_lossy())
                );
                let retry = task.retry.as_ref().unwrap();
                assert_eq!(retry.scope.key(), path_key(&child.to_string_lossy()));
                assert!(retry
                    .snapshot
                    .rows
                    .iter()
                    .all(|&row| { retry.scope.contains(&retry.snapshot.table.paths[row]) }));
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_walk_keeps_child_rows_and_retry_scope_local() {
        let root = std::env::temp_dir().join(format!(
            "sunpack-scope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let child = root.join("child");
        let other = root.join("other");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let head = child.join("split.7z.001");
        std::fs::write(&head, b"head").unwrap();
        std::fs::write(other.join("split.7z.002"), b"tail").unwrap();
        let outer =
            NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), None, Vec::new());
        let inner =
            NativeDiscoveryScope::new(child.to_string_lossy().into_owned(), None, Vec::new());
        let roots = HashMap::from([
            (outer.key().to_owned(), outer.root.clone()),
            (inner.key().to_owned(), outer.root.clone()),
        ]);
        let options =
            NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
                .unwrap();
        let mut snapshots = HashMap::new();
        let (_, outer_raw) =
            scan_discovery_scope(&options, &outer, &roots, &mut snapshots).unwrap();
        let (_, inner_raw) =
            scan_discovery_scope(&options, &inner, &roots, &mut snapshots).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert!(Arc::ptr_eq(&outer_raw.table, &inner_raw.table));
        let paths: Vec<_> = inner_raw
            .rows
            .iter()
            .map(|&row| &inner_raw.table.paths[row])
            .collect();
        assert!(paths
            .iter()
            .any(|path| path_key(path) == path_key(&head.to_string_lossy())));
        assert!(paths.iter().all(|path| inner.contains(path)));
        // Both an explicit child directory and a covered child file's parent
        // remain logical boundaries when only the ancestor was discovered.
        let mut scopes = vec![Arc::new(RetryScope {
            scope: Arc::new(outer.clone()),
            snapshot: outer_raw,
            bucket: String::new(),
        })];
        retain_logical_retry_scopes([outer, inner.clone(), inner.clone()], &mut scopes);
        assert_eq!(scopes.len(), 2);
        assert!(Arc::ptr_eq(
            &scopes[0].snapshot.table,
            &scopes[1].snapshot.table
        ));
        assert_eq!(*scopes[1].snapshot.rows, *inner_raw.rows);
        let head = head.to_string_lossy().into_owned();
        let mut tasks = vec![Task::single(
            ArchiveInput::file(head.clone(), "7z".into(), "split".into()),
            vec![head],
            DiscoverySource::Relations,
            None,
        )];
        assign_retry_scopes(&mut tasks, &scopes);
        assert_eq!(tasks[0].retry.as_ref().unwrap().scope.key(), inner.key());
        assert_eq!(tasks[0].scope.as_ref().unwrap().key(), inner.key());
        // Scope is a discovery fact, not a split-retry capability. A TAR and a
        // multi-input carrier retain it without retaining the retry snapshot.
        tasks[0].retry = None;
        tasks[0].inputs[0].input.format_hint = "tar".into();
        assign_retry_scopes(&mut tasks, &scopes);
        assert!(tasks[0].retry.is_none());
        assert_eq!(tasks[0].scope.as_ref().unwrap().key(), inner.key());
        let input = tasks[0].entry().clone();
        tasks[0].inputs.push(LogicalInput { input, password: None, failure: None });
        assign_retry_scopes(&mut tasks, &scopes);
        assert!(tasks[0].retry.is_none());
        assert_eq!(tasks[0].scope.as_ref().unwrap().key(), inner.key());
        tasks[0].scope = None;
        tasks[0].source = DiscoverySource::Direct;
        assign_retry_scopes(&mut tasks, &scopes);
        assert!(tasks[0].scope.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_logical_order_does_not_replace_relation_primary() {
        // The continuation sorts before the RAR head and also owns a ZIP.
        // Input ordering must not rename the physical owner/container.
        for relation_first in [false, true] {
            let paths = vec!["sample.zzz".to_owned(), "sample.aaa.bin".to_owned()];
            let relation = Task::single(
                ArchiveInput::file(paths[0].clone(), "rar".into(), "sample".into()),
                paths.clone(),
                DiscoverySource::Relations,
                None,
            );
            let embedded = Task::single(
                ArchiveInput::file(paths[1].clone(), "zip".into(), "sample.aaa".into()),
                vec![paths[1].clone()],
                DiscoverySource::Embedded,
                None,
            );
            let mut tasks = if relation_first {
                vec![relation, embedded]
            } else {
                vec![embedded, relation]
            };
            merge_shared_inputs(&mut tasks);
            assert_eq!(tasks.len(), 1);
            let task = &tasks[0];
            assert_eq!(task.entry().entry_path, paths[0]);
            assert_eq!(task.entry().logical_name, "sample");
            assert_eq!(task.inputs[0].input.entry_path, paths[1]);
            assert_eq!(task.source, DiscoverySource::Embedded);
            assert_eq!(task.owned_paths.len(), 2);
        }
    }
}
