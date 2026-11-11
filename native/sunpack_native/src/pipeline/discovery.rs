use super::passwords::CandidateSet;
use super::{DiscoverySource, Failure, FailureKind, InputError, InputErrorKind, Request};
use crate::core::config::{Config, ScanFilterKind};
use crate::io::archive_state::{
    ArchiveInput, InputExtent, InputPart, OpenMode, VolumeCompleteness,
};
use crate::io::directory_errors::DirectoryReadError;
use crate::password::rar::resolve_embedded_rar_boundaries;
use crate::path_keys::path_key;
use crate::scan::directory::{
    classify_scan_targets, filesystem_logical_name, NativeDirectoryScanOptions,
    NativeDirectorySnapshot, NativeOutputInventory,
};
use crate::scan::discovery::{CandidateProjection, NativeCandidateTable, NativeEmbeddedBatch};
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
    pub owned_paths: Vec<String>,
    pub source: DiscoverySource,
    pub retry: Option<Arc<RetryScope>>,
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
            owned_paths,
            source,
            retry: None,
        }
    }

    pub(super) fn entry(&self) -> &ArchiveInput {
        &self.inputs[0].input
    }
}

#[derive(Default)]
pub(super) struct Discovered {
    pub tasks: Vec<Task>,
    pub errors: Vec<InputError>,
}

pub(super) struct RetryScope {
    scope: NativeDiscoveryScope,
    snapshot: NativeDirectorySnapshot,
    bucket: String,
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
                ScanFilterKind::Blacklist(rule) => blacklist.push(rule.compiled()),
                ScanFilterKind::Whitelist(rule) => whitelist.push(rule.compiled()),
                ScanFilterKind::SizeRange(range) => sizes.push(bounds(range)),
                ScanFilterKind::MtimeRange(range) => mtimes.push(bounds(range)),
                ScanFilterKind::Unknown(_) => {}
            }
        }
    }
    NativeDirectoryScanOptions::new(blacklist, sizes, mtimes, whitelist)
}

pub(super) fn discover(
    request: &Request,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet<'_>,
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
    let (kinds, errors) = classify_scan_targets(paths.clone());
    result.add_errors(errors);
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
            }),
            _ => {}
        }
    }
    let max_depth = (!request.recursive).then_some(0);
    let mut scopes: Vec<_> = directories
        .into_iter()
        .map(|directory| {
            if let Some(scope) = request
                .discovery_scope
                .as_ref()
                .filter(|scope| path_key(&scope.root) == path_key(&directory))
            {
                scope.clone()
            } else {
                NativeDiscoveryScope::new(directory, max_depth, Vec::new())
            }
        })
        .collect();
    if request.recursive {
        let superseded: HashSet<_> = scopes
            .iter()
            .enumerate()
            .filter_map(|(index, scope)| {
                scopes
                    .iter()
                    .enumerate()
                    .any(|(i, root)| i != index && root.contains(&scope.root))
                    .then_some(index)
            })
            .collect();
        let mut index = 0;
        scopes.retain(|_| {
            let keep = !superseded.contains(&index);
            index += 1;
            keep
        });
    }
    let mut table = NativeCandidateTable::new();
    let mut verified = HashMap::new();
    let mut retry_scopes = Vec::new();
    for scope in &scopes {
        request.cancel.check_io()?;
        let (filtered, raw) = options.scan_scope(scope)?;
        result.add_errors(filtered.scan_errors());
        table.extend(&mut directory_table(
            &filtered,
            &raw,
            None,
            candidates,
            &mut verified,
            request,
        )?);
        retry_scopes.push(Arc::new(RetryScope {
            scope: scope.clone(),
            snapshot: raw,
            bucket: String::new(),
        }));
    }
    let mut by_parent: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for path in &files {
        if scopes.iter().any(|scope| scope.contains(path)) {
            continue;
        }
        let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(path));
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
        by_parent
            .entry((parent, bucket))
            .or_default()
            .push((path.clone(), filesystem_logical_name(path)));
    }
    for ((parent, bucket), targets) in by_parent {
        request.cancel.check_io()?;
        let scope = request
            .discovery_scope
            .clone()
            .unwrap_or_else(|| NativeDiscoveryScope::new(parent, Some(0), Vec::new()));
        let (filtered, raw) = if let Some(catalog) = &request.watch_catalog {
            options.catalog_snapshot(catalog, &scope, &targets[0].0)?
        } else {
            options.scan_scope(&scope)?
        };
        result.add_errors(filtered.scan_errors());
        table.extend(&mut directory_table(
            &filtered,
            &raw,
            Some(targets),
            candidates,
            &mut verified,
            request,
        )?);
        retry_scopes.push(Arc::new(RetryScope {
            scope,
            snapshot: raw,
            bucket,
        }));
    }
    table.dedupe();
    result.project(&mut table, candidates, &verified, request, false)?;
    if request.direct {
        let covered: HashSet<_> = result
            .tasks
            .iter()
            .flat_map(|task| task.owned_paths.iter().map(|path| path_key(path)))
            .collect();
        for path in files
            .into_iter()
            .filter(|path| !covered.contains(&path_key(path)))
        {
            let name = filesystem_logical_name(&path);
            result.tasks.push(Task::single(
                ArchiveInput::file(path.clone(), String::new(), name),
                vec![path],
                DiscoverySource::Direct,
                None,
            ));
        }
    }
    assign_retry_scopes(&mut result.tasks, &retry_scopes);
    Ok(result)
}

pub(super) fn discover_output(
    inventory: &NativeOutputInventory,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet<'_>,
    request: &Request,
) -> io::Result<Discovered> {
    let (filtered, raw) = inventory.build_directory_snapshots(options)?;
    let mut result = Discovered::default();
    result.add_errors(filtered.scan_errors());
    let mut verified = HashMap::new();
    let mut table = directory_table(&filtered, &raw, None, candidates, &mut verified, request)?;
    result.project(&mut table, candidates, &verified, request, true)?;
    let policy = request.config.recursive_authorization;
    if policy.enabled && !result.tasks.is_empty() {
        let allowed = authorize_nested_candidates(
            &raw,
            Path::new(inventory.root()),
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
            scope: NativeDiscoveryScope::new(inventory.root().to_owned(), None, Vec::new()),
            snapshot: raw,
            bucket: String::new(),
        })],
    );
    Ok(result)
}

fn assign_retry_scopes(tasks: &mut [Task], scopes: &[Arc<RetryScope>]) {
    for task in tasks.iter_mut().filter(|task| task.inputs.len() == 1) {
        let input = task.entry();
        let may_split = input.mode.structured()
            || matches!(input.format_hint.as_str(), "zip" | "rar" | "7z")
            || task.inputs[0]
                .failure
                .as_ref()
                .is_some_and(|failure| failure.kind == FailureKind::MissingVolume);
        if may_split {
            let mut bucket = None;
            task.retry = scopes
                .iter()
                .filter(|scope| {
                    scope.scope.contains(&input.entry_path)
                        && (scope.bucket.is_empty()
                            || scope.bucket
                                == *bucket.get_or_insert_with(|| {
                                    crate::scan::catalog::catalog_stem(&input.entry_path)
                                }))
                })
                .max_by_key(|scope| scope.scope.root.len())
                .cloned();
        }
    }
}

pub(super) fn retry_volume(
    original: &super::ArchiveResult,
    context: &RetryScope,
    options: &NativeDirectoryScanOptions,
    candidates: &CandidateSet<'_>,
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
        Some(targets),
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
        {
            return Ok(Some(task));
        }
    }
    Ok(None)
}

fn directory_table(
    filtered: &NativeDirectorySnapshot,
    raw: &NativeDirectorySnapshot,
    targets: Option<Vec<(String, String)>>,
    candidates: &CandidateSet<'_>,
    verified: &mut HashMap<String, Arc<str>>,
    request: &Request,
) -> io::Result<NativeCandidateTable> {
    let mut table = NativeCandidateTable::new();
    table.append_directory(raw, filtered, targets)?;
    let mut passwords = Vec::new();
    let mut refresh = Vec::new();
    let mut failures = Vec::new();
    for group in table.encrypted_rar_groups() {
        match candidates.plan(&group.input, None, &[], &request.cancel) {
            Ok(Ok(plan)) if plan.verified => {
                let value = plan.selected.unwrap();
                verified.insert(path_key(&group.input.entry_path), value.clone());
                passwords.extend(
                    group
                        .owned_paths
                        .into_iter()
                        .map(|path| (path, value.to_string())),
                );
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
    fn add_errors(&mut self, errors: Vec<DirectoryReadError>) {
        self.errors.extend(
            errors
                .into_iter()
                .map(|(operation, path, detail)| InputError {
                    path: PathBuf::from(path),
                    message: format!("{operation}: {detail}"),
                    kind: if operation == "metadata" {
                        InputErrorKind::InvalidInput
                    } else {
                        InputErrorKind::FilesystemScan
                    },
                }),
        );
    }

    fn project(
        &mut self,
        table: &mut NativeCandidateTable,
        candidates: &CandidateSet<'_>,
        verified: &HashMap<String, Arc<str>>,
        request: &Request,
        recursive: bool,
    ) -> io::Result<()> {
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
        let mut batch = table.prepare_embedded(
            &mut routes,
            recursive,
            request.deep,
            embedded.enabled || request.deep,
            embedded.recursive_candidate_ratio,
        );
        if batch.len() == 0 {
            merge_shared_inputs(&mut self.tasks);
            return Ok(());
        }
        let mut embedded_tasks = Vec::new();
        const PAGE_SIZE: usize = 256;
        for offset in (0..batch.len()).step_by(PAGE_SIZE) {
            request.cancel.check_io()?;
            for (_, rows) in
                NativeEmbeddedBatch::scan_pages(vec![(&*table, &mut batch)], offset, PAGE_SIZE)?
            {
                for row in rows {
                    if let Some(error) = row.error {
                        let (path, format) = table.summary(row.index)?;
                        if format.is_empty() {
                            self.errors.push(InputError {
                                path: PathBuf::from(path),
                                message: error.to_string(),
                                kind: InputErrorKind::FilesystemScan,
                            });
                        } else {
                            let mut task = project_task(
                                table.project(row.index)?,
                                DiscoverySource::Embedded,
                                verified,
                            );
                            task.inputs[0].failure = Some(Failure {
                                kind: FailureKind::FilesystemError,
                                message: error.to_string(),
                            });
                            embedded_tasks.push(task);
                        }
                    } else if let Some(scan) = row.scan {
                        let task = project_task(
                            table.project(row.index)?,
                            DiscoverySource::Embedded,
                            verified,
                        );
                        if let Some(task) =
                            project_segments(task, &scan, HashMap::new(), candidates)?
                        {
                            embedded_tasks.push(task);
                        }
                    }
                }
            }
        }
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
            self.tasks.extend(embedded_tasks);
        }
        merge_shared_inputs(&mut self.tasks);
        Ok(())
    }
}

fn project_task(
    projected: CandidateProjection<'_>,
    source: DiscoverySource,
    verified: &HashMap<String, Arc<str>>,
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
            let password = verified.get(&path_key(&relation.input.entry_path)).cloned();
            let failure = failure_reason
                .or(relation.failure_reason)
                .and_then(discovery_failure);
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
    candidates: &CandidateSet<'_>,
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
        let mut failure = failure.and_then(discovery_failure);
        if let (Some(failure), Some(error)) = (&mut failure, errors.remove(&item.offset)) {
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

pub(super) fn discovery_failure(reason: &str) -> Option<Failure> {
    let (kind, message) = match reason {
        "needs_password" | "embedded_password_required" => {
            return Some(Failure::password_required())
        }
        "wrong_password" | "embedded_wrong_password" => return Some(Failure::password()),
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
    Some(Failure {
        kind,
        message: message.to_owned(),
    })
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
                combined.source = DiscoverySource::Embedded;
                combined.inputs.extend(task.inputs);
                combined.owned_paths.extend(task.owned_paths);
            }
        }
    }
    tasks.extend(combined.into_values().map(|mut task| {
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
