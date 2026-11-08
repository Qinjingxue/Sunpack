use crate::analysis_native::volume_anchor::CheapAnchor;
use crate::path_keys::{case_key, path_key};
use crate::relations::{
    build_native_candidate_groups_from_snapshot,
    build_native_candidate_groups_from_snapshot_cached, relation_group_cached_anchors,
    resolve_embedded_volumes, NativeRelationGroup, RelationCache,
};
use crate::scan::directory::{
    filesystem_logical_name, filesystem_route_name, DirectorySnapshotTable,
    NativeDirectorySnapshot, FILE_ROUTE_DETECTION, FILE_ROUTE_RELATIONS, FILE_ROUTE_RESIDUAL,
};
use crate::scan::embedded::{
    scan_detected_path, scan_embedded_path, NativeScanResult, RarInputResolution,
};
use crate::scan::pe_overlay::{inspect_pe_image_native, PeProbe, PeState};
use pyo3::exceptions::PyIndexError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

enum Candidate {
    File(Arc<DirectorySnapshotTable>, usize),
    // Keep ordinary file rows compact; relation facts live with their candidate.
    Relation(Box<NativeRelationGroup>),
}

impl Candidate {
    fn embedded_source(&self) -> (&str, Option<PeState>) {
        match self {
            Self::File(table, row) => (
                table.paths[*row].as_str(),
                table.relation_anchors[*row]
                    .as_ref()
                    .map(|a| a.anchor().map_or(PeState::None, |a| a.pe_state)),
            ),
            Self::Relation(group) => (
                group.candidate_data().entry_path,
                group.entry_anchor().map(|a| a.pe_state),
            ),
        }
    }
}

#[pyclass(module = "sunpack_native")]
#[derive(Default)]
pub(crate) struct NativeCandidateTable {
    rows: Vec<Candidate>,
    filesystem_routed: bool,
    targets: Option<FileTargets>,
    // Sparse verifier evidence; owned only for this scan, never per-file caches.
    // An empty reason preserves the extraction fallback for inconclusive proof.
    relation_failures: HashMap<String, String>,
    // Shared physical facts; row indices survive only for this discovery scan.
    relation_sources: Vec<NativeDirectorySnapshot>,
}

struct FileTargets {
    names_by_path: HashMap<String, String>,
}

impl FileTargets {
    fn new(targets: Vec<(String, String)>) -> Self {
        Self {
            names_by_path: targets
                .into_iter()
                .map(|(path, name)| (path_key(&path), case_key(&name)))
                .collect(),
        }
    }

    fn select(&self, snapshot: &NativeDirectorySnapshot) -> Option<NativeDirectorySnapshot> {
        let rows: Vec<_> = snapshot
            .rows
            .iter()
            .copied()
            .filter(|&row| {
                self.names_by_path
                    .contains_key(&path_key(&snapshot.table.paths[row]))
            })
            .collect();
        // Preserve logical-name recovery for targets excluded from the view.
        (rows.len() == self.names_by_path.len()).then(|| snapshot.view(rows))
    }

    fn retain(&self, rows: &mut Vec<Candidate>) {
        let mut matched = Vec::with_capacity(rows.len());
        let mut physical_matches = HashSet::new();
        for row in rows.iter() {
            let mut matches = |path: &str| {
                let key = path_key(path);
                if self.names_by_path.contains_key(&key) {
                    physical_matches.insert(key);
                    true
                } else {
                    false
                }
            };
            let contains = match row {
                Candidate::File(table, index) => matches(&table.paths[*index]),
                Candidate::Relation(group) => {
                    let data = group.candidate_data();
                    data.parts()
                        .chain(data.companions.iter().map(String::as_str))
                        .chain([data.carrier_path, data.entry_path])
                        .filter(|path| matches(path))
                        .count()
                        > 0
                }
            };
            matched.push(contains);
        }
        let expected: HashSet<&str> = self
            .names_by_path
            .iter()
            .filter(|(path, _)| !physical_matches.contains(*path))
            .map(|(_, name)| name.as_str())
            .collect();
        let mut selected = matched.into_iter();
        rows.retain(|row| {
            let contains = selected.next().unwrap();
            contains || matches!(row, Candidate::Relation(group) if {
                let data = group.candidate_data();
                data.is_split && Path::new(data.logical_name().as_ref()).file_name()
                    .is_some_and(|name| expected.contains(case_key(&name.to_string_lossy()).as_str()))
            })
        });
    }
}

impl NativeCandidateTable {
    fn append_speculative_files(&mut self, snapshot: &NativeDirectorySnapshot) {
        // The relations-only API projects every row as a group. File routing
        // belongs only to the shared discovery table, including password retry.
        if !self.filesystem_routed {
            return;
        }
        let mut pending: HashSet<_> = self
            .rows
            .iter()
            .filter_map(|row| match row {
                Candidate::Relation(group) => Some(group),
                _ => None,
            })
            .flat_map(|group| {
                let head = group.candidate_data().entry_path;
                group
                    .speculative_paths()
                    .filter(move |path| *path != head)
                    .map(path_key)
            })
            .collect();
        if pending.is_empty() {
            return;
        }
        for row in &self.rows {
            if let Candidate::File(table, row) = row {
                pending.remove(&path_key(&table.paths[*row]));
            }
        }
        if pending.is_empty() {
            return;
        }
        // Password resolution can introduce candidates after filesystem routing.
        // Borrow their original rows; no new enumeration, analysis or file I/O.
        for &row in &snapshot.rows {
            if pending.remove(&path_key(&snapshot.table.paths[row])) {
                self.rows
                    .push(Candidate::File(Arc::clone(&snapshot.table), row));
                if pending.is_empty() {
                    break;
                }
            }
        }
    }

    fn relation_cache(&self) -> RelationCache {
        let mut cache = RelationCache::default();
        for row in &self.rows {
            if let Candidate::Relation(group) = row {
                relation_group_cached_anchors(group, &mut cache);
            }
        }
        cache
    }

    fn relation_groups(
        &self,
        raw: &NativeDirectorySnapshot,
        filtered: &NativeDirectorySnapshot,
        passwords: Option<&[(String, String)]>,
        cached: Option<&RelationCache>,
    ) -> Vec<NativeRelationGroup> {
        let selection = self
            .targets
            .as_ref()
            .and_then(|targets| targets.select(filtered))
            .unwrap_or_else(|| {
                if self.filesystem_routed {
                    filtered.file_route_view(FILE_ROUTE_RELATIONS)
                } else {
                    filtered.view(filtered.rows.clone())
                }
            });
        let mut groups =
            build_native_candidate_groups_from_snapshot_cached(raw, &selection, passwords, cached);
        if self.filesystem_routed {
            let routed: HashSet<_> = selection
                .rows
                .iter()
                .filter(|&&row| selection.table.file_routes[row] == FILE_ROUTE_RELATIONS)
                .map(|&row| path_key(&selection.table.paths[row]))
                .collect();
            groups.retain(|group| match group {
                NativeRelationGroup::Ordinary(..) => {
                    routed.contains(&path_key(group.candidate_data().entry_path))
                }
                _ => true,
            });
        }
        groups
    }

    fn retain_targets(&mut self) {
        if let Some(targets) = &self.targets {
            targets.retain(&mut self.rows);
        }
    }
}

#[pyclass(module = "sunpack_native")]
#[derive(Default)]
pub(crate) struct NativeDiscoveryRoutes {
    scans: HashMap<usize, Result<Arc<NativeScanResult>, Arc<io::Error>>>,
    #[pyo3(get)]
    pub(crate) relation_events: Vec<(usize, u8)>,
    #[pyo3(get)]
    pub(crate) detection_events: Vec<(usize, u8)>,
    #[pyo3(get)]
    pub(crate) relation_resolved: Vec<usize>,
    #[pyo3(get)]
    pub(crate) relation_blocked: Vec<usize>,
    #[pyo3(get)]
    pub(crate) relation_residual: Vec<usize>,
    #[pyo3(get)]
    pub(crate) detection_resolved: Vec<usize>,
    #[pyo3(get)]
    pub(crate) detection_residual: Vec<usize>,
    #[pyo3(get)]
    pub(crate) embedded: Vec<usize>,
}

enum EmbeddedOutcome {
    Residual,
    Failed(Arc<io::Error>),
    Scan(Arc<NativeScanResult>),
}

#[pyclass(module = "sunpack_native")]
#[derive(Default)]
pub(crate) struct NativeEmbeddedBatch {
    relation_cache: RelationCache,
    scans: HashMap<usize, Result<Arc<NativeScanResult>, Arc<io::Error>>>,
    ids: Vec<usize>,
    force_scan: bool,
    pending_volumes: Vec<PendingEmbeddedVolume>,
    excluded: HashSet<String>,
    claimed_ranges: HashMap<String, Vec<(u64, u64)>>,
}

struct PendingEmbeddedVolume {
    index: usize,
    anchor: crate::analysis_native::volume_anchor::VolumeAnchor,
    scan: Option<Arc<NativeScanResult>>,
}

impl NativeEmbeddedBatch {
    fn project_outcomes(
        &mut self,
        py: Python<'_>,
        table: &NativeCandidateTable,
        outcomes: impl Iterator<Item = (usize, EmbeddedOutcome)>,
    ) -> PyResult<Vec<(usize, u8, &'static str, Option<Py<PyDict>>)>> {
        let mut projected = Vec::new();
        for (index, outcome) in outcomes {
            let key = path_key(&table.summary(index)?.0);
            let claimed = self.claimed_ranges.get(&key);
            let row: PyResult<_> = match outcome {
                EmbeddedOutcome::Residual => {
                    unreachable!("residuals are filtered before projection")
                }
                EmbeddedOutcome::Failed(error) => {
                    let detail = PyDict::new(py);
                    detail.set_item("error", error.to_string())?;
                    Ok((index, 2, "embedded_scan_io_error", Some(detail.unbind())))
                }
                EmbeddedOutcome::Scan(scan) => {
                    let mut anchors = scan.relation_anchors();
                    if let Some(claimed) = claimed {
                        // Existing volume hypotheses remain authoritative.
                        // Independent encrypted archives still use the normal
                        // boundary/password resolution before projection.
                        anchors.retain(|a| {
                            a.standalone
                                || (!a.multivolume && a.needs_password)
                                || !claimed.iter().any(|&(start, end)| {
                                    let offset = a.structure_offset.unwrap_or(0);
                                    start <= offset && offset < end
                                })
                        });
                        if anchors.is_empty() && !scan.has_independent_archive() {
                            continue;
                        }
                    }
                    if !anchors.is_empty() {
                        let independent = scan.has_independent_archive();
                        for mut anchor in anchors {
                            anchor.path = table.summary(index)?.0;
                            let retain_scan = anchor.needs_password || independent;
                            self.pending_volumes.push(PendingEmbeddedVolume {
                                index,
                                anchor,
                                scan: retain_scan.then(|| Arc::clone(&scan)),
                            });
                        }
                        Ok((index, 3, "embedded_volume_candidate", None))
                    } else {
                        // A complete peer archive keeps its original ownership.
                        self.excluded.extend(table.path_keys(index)?);
                        Ok((index, 1, "", Some(scan.to_py_dict(py)?)))
                    }
                }
            };
            projected.push(row?);
        }
        Ok(projected)
    }
}

fn scan_embedded_jobs(
    py: Python<'_>,
    groups: &[(&NativeCandidateTable, &NativeEmbeddedBatch)],
    jobs: &[(usize, usize)],
) -> PyResult<Vec<(usize, usize, EmbeddedOutcome)>> {
    let cancellation = crate::io::cancellation::Cancellation::current();
    cancellation.check()?;
    let outcomes = py.detach(|| {
        // File producers also own per-file validation state. Matching jobs
        // continue to share the existing eight-thread IOCP scan pool.
        let parallel_jobs = jobs.len().min(rayon::current_num_threads()).clamp(1, 2);
        let parallel_files = jobs
            .iter()
            .filter(|&&(group, index)| {
                let (table, batch) = groups[group];
                let (path, pe) = table.rows[index].embedded_source();
                !batch.scans.contains_key(&index)
                    && !path.is_empty()
                    && (batch.force_scan || pe != Some(PeState::Confirmed))
            })
            .count()
            .min(parallel_jobs)
            .max(1);
        let next = AtomicUsize::new(0);
        // A fixed number of producers draw from one work list. A large file
        // cannot pin unrelated jobs behind its original root or candidate page.
        // scan_embedded_path divides the IOCP byte budget by parallel_files.
        let mut outcomes: Vec<_> = (0..parallel_jobs)
            .into_par_iter()
            .map(|_| {
                cancellation.run(|| {
                    let mut completed = Vec::new();
                    while !cancellation.cancelled() {
                        let position = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(group, index)) = jobs.get(position) else {
                            break;
                        };
                        let (table, batch) = groups[group];
                        let (path, pe) = table.rows[index].embedded_source();
                        let outcome = match batch.scans.get(&index) {
                            Some(Ok(scan)) => EmbeddedOutcome::Scan(Arc::clone(scan)),
                            Some(Err(error)) => {
                                EmbeddedOutcome::read_error(path, Arc::clone(error))
                            }
                            None => {
                                scan_embedded_candidate(path, batch.force_scan, pe, parallel_files)
                            }
                        };
                        if !matches!(outcome, EmbeddedOutcome::Residual) {
                            completed.push((position, group, index, outcome));
                        }
                    }
                    completed
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();
        outcomes.sort_unstable_by_key(|(position, ..)| *position);
        outcomes
            .into_iter()
            .map(|(_, group, index, outcome)| (group, index, outcome))
            .collect()
    });
    cancellation.check()?;
    Ok(outcomes)
}

impl EmbeddedOutcome {
    fn read_error(path: &str, error: Arc<io::Error>) -> Self {
        // Discovery proposals do not pin physical inputs. A peer may consume
        // one between its snapshot/password proof and any later read. Preserve
        // the typed error until this decision, across detection and policy
        // gates. Confirm the source itself departed: a missing spill/temp file
        // or a newly recreated input must still expose the original I/O error.
        // This extra metadata read occurs only on the NotFound error path.
        if error.kind() == io::ErrorKind::NotFound
            && std::fs::metadata(path)
                .is_err_and(|current| current.kind() == io::ErrorKind::NotFound)
        {
            Self::Residual
        } else {
            Self::Failed(error)
        }
    }
}

#[pymethods]
impl NativeDiscoveryRoutes {
    fn primary_analysis(&self, py: Python<'_>, index: usize) -> PyResult<Option<Py<PyDict>>> {
        self.scans
            .get(&index)
            .and_then(|scan| scan.as_ref().ok())
            .map_or(Ok(None), |scan| scan.primary_analysis(py))
    }
}

#[pymethods]
impl NativeEmbeddedBatch {
    fn __len__(&self) -> usize {
        self.ids.len()
    }

    /// Page only selected jobs across roots, never the original candidate rows.
    /// Root-local policy, relation ownership and password evidence stay in each batch.
    #[staticmethod]
    #[pyo3(signature = (groups, offset=0, limit=256))]
    fn scan_pages(
        py: Python<'_>,
        mut groups: Vec<(
            PyRef<'_, NativeCandidateTable>,
            PyRefMut<'_, NativeEmbeddedBatch>,
        )>,
        offset: usize,
        limit: usize,
    ) -> PyResult<Vec<(usize, Vec<(usize, u8, &'static str, Option<Py<PyDict>>)>)>> {
        let jobs: Vec<_> = groups
            .iter()
            .enumerate()
            .flat_map(|(group, (_, batch))| batch.ids.iter().map(move |&index| (group, index)))
            .skip(offset)
            .take(limit)
            .collect();
        let borrowed: Vec<_> = groups
            .iter()
            .map(|(table, batch)| (&**table, &**batch))
            .collect();
        let outcomes = scan_embedded_jobs(py, &borrowed, &jobs)?;
        let mut by_group: BTreeMap<usize, Vec<_>> = BTreeMap::new();
        for (group, index, outcome) in outcomes {
            by_group.entry(group).or_default().push((index, outcome));
        }
        by_group
            .into_iter()
            .map(|(group, outcomes)| {
                let (table, batch) = &mut groups[group];
                Ok((
                    group,
                    batch.project_outcomes(py, table, outcomes.into_iter())?,
                ))
            })
            .collect()
    }

    fn encrypted_volume_inputs(
        &self,
        table: PyRef<'_, NativeCandidateTable>,
    ) -> PyResult<Vec<(String, u64)>> {
        let mut requests = HashMap::new();
        for pending in &self.pending_volumes {
            if pending.anchor.needs_password {
                requests.insert(
                    pending.anchor.path.clone(),
                    pending.anchor.structure_offset.unwrap_or(0),
                );
            }
        }
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let selected: HashSet<_> = requests.keys().map(|path| path_key(path)).collect();
        let cache = &self.relation_cache;
        for snapshot in &table.relation_sources {
            let stems: HashSet<_> = snapshot
                .rows
                .iter()
                .filter_map(|&row| {
                    let path = &snapshot.table.paths[row];
                    selected.contains(&path_key(path)).then(|| {
                        case_key(crate::relations::first_dot_stem(
                            Path::new(path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or_default(),
                        ))
                    })
                })
                .collect();
            if stems.is_empty() {
                continue;
            }
            for &row in &snapshot.rows {
                if !snapshot.table.relation_member_eligible[row] {
                    continue;
                }
                let path = &snapshot.table.paths[row];
                let key = path_key(path);
                if self.excluded.contains(&key) {
                    continue;
                }
                let name = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if !stems.contains(&case_key(crate::relations::first_dot_stem(name))) {
                    continue;
                }
                let anchor = cache
                    .anchors
                    .get(&key)
                    .or(snapshot.table.relation_anchors[row]
                        .as_ref()
                        .and_then(CheapAnchor::anchor));
                if let Some(anchor) = anchor.filter(|a| a.needs_password) {
                    requests
                        .entry(path.clone())
                        .or_insert(anchor.structure_offset.unwrap_or(0));
                }
            }
        }
        Ok(requests.into_iter().collect())
    }

    /// One directed Relations call per source scope, using native scan facts.
    /// Status 0 returns standalone/sibling scan facts to Embedded.
    #[pyo3(signature = (table, password_candidates=None))]
    fn resolve_volumes(
        &mut self,
        py: Python<'_>,
        mut table: PyRefMut<'_, NativeCandidateTable>,
        password_candidates: Option<Vec<(String, Vec<String>)>>,
    ) -> PyResult<Vec<(usize, u8, Option<Py<PyDict>>, Option<String>)>> {
        use crate::analysis_native::volume_anchor::resolve_encrypted_relation_anchor;
        if self.pending_volumes.is_empty() {
            return Ok(Vec::new());
        }
        let candidates: HashMap<_, _> = password_candidates
            .unwrap_or_default()
            .into_iter()
            .map(|(path, values)| (path_key(&path), values))
            .collect();
        let mut cache = std::mem::take(&mut self.relation_cache);
        let mut pending = std::mem::take(&mut self.pending_volumes);
        let pending_keys: HashSet<_> = pending
            .iter()
            .map(|item| path_key(&item.anchor.path))
            .collect();
        for snapshot in &table.relation_sources {
            for &row in &snapshot.rows {
                let key = path_key(&snapshot.table.paths[row]);
                if candidates.contains_key(&key)
                    && !pending_keys.contains(&key)
                    && !cache.anchors.contains_key(&key)
                {
                    if let Some(anchor) = snapshot.table.relation_anchors[row]
                        .as_ref()
                        .and_then(CheapAnchor::anchor)
                    {
                        cache.anchors.insert(key, anchor.clone());
                    }
                }
            }
        }
        let encrypted: Vec<_> = pending
            .iter_mut()
            .map(|item| &mut item.anchor)
            .chain(
                cache
                    .anchors
                    .iter_mut()
                    .filter_map(|(key, anchor)| (!pending_keys.contains(key)).then_some(anchor)),
            )
            .filter(|anchor| anchor.needs_password)
            .filter_map(|anchor| {
                candidates
                    .get(&path_key(&anchor.path))
                    .map(|values| (anchor, values))
            })
            .collect();
        let cancellation = crate::io::cancellation::Cancellation::current();
        cancellation.check()?;
        let matched = py.detach(|| {
            // Independent headers share the existing Rayon pool. Preserve the
            // request's cancellation on each worker, including expensive KDFs.
            encrypted
                .into_par_iter()
                .map(|(anchor, values)| {
                    cancellation.run(|| -> io::Result<_> {
                        let reader =
                            crate::io::reader::ManagedReader::open(&anchor.path)?.probe_reader();
                        let (resolved, index) =
                            resolve_encrypted_relation_anchor(anchor, &reader, values)?;
                        *anchor = resolved;
                        Ok(index.map(|index| {
                            (
                                (path_key(&anchor.path), anchor.structure_offset.unwrap_or(0)),
                                values[index].clone(),
                            )
                        }))
                    })
                })
                .collect::<io::Result<Vec<_>>>()
                .map(|rows| rows.into_iter().flatten().collect::<HashMap<_, _>>())
        })?;
        cancellation.check()?;
        // Own one scan reference and one sparse resolution table per physical
        // carrier. Project its hits/candidates only after every head is resolved.
        let mut fallback_scans = BTreeMap::new();
        let mut anchors = Vec::new();
        let mut projected = HashSet::new();
        let mut path_counts = HashMap::new();
        for item in &pending {
            *path_counts
                .entry(path_key(&item.anchor.path))
                .or_insert(0usize) += 1;
        }
        for item in pending {
            let key = path_key(&item.anchor.path);
            let mut anchor = item.anchor;
            let match_key = (key.clone(), anchor.structure_offset.unwrap_or(0));
            if anchor.standalone || (!anchor.multivolume && anchor.needs_password) {
                if path_counts[&key] == 1 {
                    self.excluded.insert(key.clone());
                }
                if let Some(scan) = item.scan {
                    let failure_reason = anchor.expected_logical_size.is_none().then(|| {
                        if matched.contains_key(&match_key)
                            || anchor.evidence.contains(&"rar:password_matched_incomplete")
                        {
                            "embedded_truncated"
                        } else if anchor.wrong_password {
                            "embedded_wrong_password"
                        } else {
                            "embedded_password_required"
                        }
                    });
                    let (_, resolutions) = fallback_scans
                        .entry(item.index)
                        .or_insert_with(|| (scan, HashMap::new()));
                    resolutions.insert(
                        anchor.structure_offset.unwrap_or(0),
                        RarInputResolution {
                            end_offset: anchor.expected_logical_size,
                            password: matched.get(&match_key).map(String::as_str),
                            failure_reason,
                        },
                    );
                }
                continue;
            }
            anchor.evidence.push("embedded:volume_candidate");
            anchors.push(anchor);
            // Project once after Relations; Python combines logical inputs
            // sharing this carrier under the existing multi-segment task.
            if let Some(scan) = item
                .scan
                .filter(|scan| projected.insert(item.index) && scan.has_independent_archive())
            {
                fallback_scans
                    .entry(item.index)
                    .or_insert_with(|| (scan, HashMap::new()));
            }
        }
        let mut fallback = fallback_scans
            .into_iter()
            .map(|(index, (scan, resolutions))| {
                Ok((
                    index,
                    0,
                    Some(scan.to_py_dict_with_rar_resolutions(py, &resolutions)?),
                    None,
                ))
            })
            .collect::<PyResult<Vec<_>>>()?;
        if anchors.is_empty() {
            return Ok(fallback);
        }
        let sources = &table.relation_sources;
        // Only these newly discovered slices may re-enter a claimed carrier.
        // Other files retain the existing whole-file ownership exclusion.
        let anchor_paths: HashSet<_> = anchors.iter().map(|a| path_key(&a.path)).collect();
        self.excluded.retain(|key| !anchor_paths.contains(key));
        let excluded = &self.excluded;
        let mut groups = py.detach(|| resolve_embedded_volumes(sources, anchors, excluded, cache));
        // A failed NextHeader inside a carrier can also be damaged standalone
        // data. Require actual peers for this speculative split identity.
        // Index only nominated stems once, rather than rescan scopes per head.
        let stem = |path: &str| {
            case_key(crate::relations::first_dot_stem(
                Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default(),
            ))
        };
        let speculative = |group: &NativeRelationGroup| {
            !group.candidate_data().relation_confirmed
                && group
                    .entry_anchor()
                    .is_some_and(|a| a.evidence.contains(&"7z:carrier_interrupted"))
        };
        let mut peers: HashMap<String, HashSet<String>> = groups
            .iter()
            .filter(|g| speculative(g))
            .map(|g| (stem(g.candidate_data().entry_path), HashSet::new()))
            .collect();
        if !peers.is_empty() {
            for snapshot in sources {
                for &row in &snapshot.rows {
                    if !snapshot.table.relation_member_eligible[row] {
                        continue;
                    }
                    let path = &snapshot.table.paths[row];
                    if let Some(paths) = peers.get_mut(&stem(path)) {
                        // Only two distinct witnesses are needed. Retaining
                        // every peer would duplicate a large bucket's paths.
                        if paths.len() >= 2 {
                            continue;
                        }
                        let key = path_key(path);
                        if !excluded.contains(&key) {
                            paths.insert(key);
                        }
                    }
                }
            }
            groups.retain(|g| {
                !speculative(g)
                    || peers
                        .get(&stem(g.candidate_data().entry_path))
                        .is_some_and(|p| p.len() > 1)
            });
        }
        for group in groups {
            // Keep the decrypted head's password request-local. Execution uses
            // LogicalArchiveInput's existing proof instead of deriving it again.
            let password = group
                .entry_anchor()
                .and_then(|anchor| {
                    matched.get(&(path_key(&anchor.path), anchor.structure_offset.unwrap_or(0)))
                })
                .cloned();
            let index = table.rows.len();
            table.rows.push(Candidate::Relation(Box::new(group)));
            fallback.push((index, 1, None, password));
        }
        Ok(fallback)
    }
}

#[pymethods]
impl NativeCandidateTable {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __len__(&self) -> usize {
        self.rows.len()
    }

    /// Keep relation facts native while Python discovers directory passwords.
    #[pyo3(signature = (raw_snapshot, filtered_snapshot, path_passwords=None))]
    fn append_relations(
        &mut self,
        py: Python<'_>,
        raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        path_passwords: Option<Vec<(String, String)>>,
    ) -> PyResult<()> {
        let raw_snapshot = &*raw_snapshot;
        let filtered_snapshot = &*filtered_snapshot;
        let groups = py.detach(|| {
            build_native_candidate_groups_from_snapshot(
                raw_snapshot,
                filtered_snapshot,
                path_passwords.as_deref(),
            )
        });
        self.rows.extend(
            groups
                .into_iter()
                .map(|group| Candidate::Relation(Box::new(group))),
        );
        self.relation_sources
            .push(raw_snapshot.view(raw_snapshot.rows.clone()));
        Ok(())
    }

    #[pyo3(signature = (raw_snapshot, filtered_snapshot, targets=None))]
    fn append_directory(
        &mut self,
        py: Python<'_>,
        raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        targets: Option<Vec<(String, String)>>,
    ) -> PyResult<()> {
        let raw_snapshot = &*raw_snapshot;
        let filtered_snapshot = &*filtered_snapshot;
        py.detach(|| {
            self.filesystem_routed = true;
            self.targets = targets.map(FileTargets::new);
            let groups = self.relation_groups(raw_snapshot, filtered_snapshot, None, None);
            let selected = self
                .targets
                .as_ref()
                .and_then(|targets| targets.select(filtered_snapshot));
            let filtered_snapshot = selected.as_ref().unwrap_or(filtered_snapshot);
            self.rows
                .reserve(groups.len() + filtered_snapshot.rows.len());
            self.rows.extend(
                groups
                    .into_iter()
                    .map(|group| Candidate::Relation(Box::new(group))),
            );
            for &row in &filtered_snapshot.rows {
                if !filtered_snapshot.table.is_dirs[row]
                    && filtered_snapshot.table.file_routes[row] != FILE_ROUTE_RELATIONS
                {
                    self.rows
                        .push(Candidate::File(Arc::clone(&filtered_snapshot.table), row));
                }
            }
            self.retain_targets();
            self.append_speculative_files(raw_snapshot);
            self.relation_sources
                .push(raw_snapshot.view(raw_snapshot.rows.clone()));
        });
        Ok(())
    }

    /// Only password-blocked relation proposals leave Rust for policy probing.
    fn encrypted_rar_groups(&self, py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
        let mut output = Vec::new();
        for row in &self.rows {
            if let Candidate::Relation(group) = row {
                let data = group.candidate_data();
                if data.format_hint == "rar" && data.needs_password {
                    output.push(group.to_dict(py)?);
                }
            }
        }
        Ok(output)
    }

    fn record_relation_failures(&mut self, failures: Vec<(String, String)>) {
        self.relation_failures.extend(
            failures
                .into_iter()
                .map(|(path, reason)| (path_key(&path), reason)),
        );
    }

    /// Replace the relation evidence for one table after a password is found.
    #[pyo3(signature = (raw_snapshot, filtered_snapshot, path_passwords, refresh_paths=None))]
    fn retry_relations(
        &mut self,
        py: Python<'_>,
        raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        path_passwords: Vec<(String, String)>,
        refresh_paths: Option<Vec<String>>,
    ) -> PyResult<()> {
        let raw_snapshot = &*raw_snapshot;
        let filtered_snapshot = &*filtered_snapshot;
        py.detach(|| {
            let mut cached = RelationCache::default();
            for row in &self.rows {
                if let Candidate::Relation(group) = row {
                    relation_group_cached_anchors(group, &mut cached);
                }
            }
            // A short password probe may start after another request consumed its
            // inputs. Drop only proven departures from that proposal, sharing the
            // original snapshot and surviving anchors instead of scanning again.
            let departed: HashSet<String> = refresh_paths
                .filter(|paths| !paths.is_empty())
                .map(|paths| {
                    paths
                        .into_iter()
                        .filter(|path| {
                            std::fs::metadata(path)
                                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                        })
                        .map(|path| path_key(&path))
                        .collect()
                })
                .unwrap_or_default();
            let current_snapshots = (!departed.is_empty()).then(|| {
                (
                    raw_snapshot.without_path_keys(&departed),
                    filtered_snapshot.without_path_keys(&departed),
                )
            });
            let (raw, filtered) = current_snapshots
                .as_ref()
                .map(|(raw, filtered)| (raw, filtered))
                .unwrap_or((raw_snapshot, filtered_snapshot));
            let groups = self.relation_groups(raw, filtered, Some(&path_passwords), Some(&cached));
            self.rows.retain(|row| matches!(row, Candidate::File(..)));
            let mut replacement = Vec::with_capacity(groups.len() + self.rows.len());
            replacement.extend(
                groups
                    .into_iter()
                    .map(|group| Candidate::Relation(Box::new(group))),
            );
            replacement.append(&mut self.rows);
            self.rows = replacement;
            self.retain_targets();
            self.append_speculative_files(raw);
        });
        Ok(())
    }

    fn extend(&mut self, other: &mut NativeCandidateTable) {
        self.rows.append(&mut other.rows);
        self.relation_sources.append(&mut other.relation_sources);
        self.relation_failures
            .extend(other.relation_failures.drain());
    }

    fn dedupe(&mut self) {
        let mut positions: HashMap<String, usize> = HashMap::new();
        let mut unique = Vec::with_capacity(self.rows.len());
        for row in self.rows.drain(..) {
            let (key, rank) = match &row {
                Candidate::File(table, index) => {
                    (path_key(&table.paths[*index]), (1u8, 0usize, 1usize))
                }
                Candidate::Relation(group) => {
                    let data = group.candidate_data();
                    let key = if data.is_split {
                        let parent = Path::new(data.entry_path)
                            .parent()
                            .unwrap_or_else(|| Path::new(""));
                        let split_family = data.split_family();
                        let family = if split_family.is_empty() {
                            data.format_hint
                        } else {
                            split_family.as_ref()
                        };
                        path_key(
                            &parent
                                .join(format!("{}\x1f{}", case_key(&data.logical_name()), family))
                                .to_string_lossy(),
                        )
                    } else {
                        path_key(data.entry_path)
                    };
                    let rank = (
                        if data.is_split && !data.needs_password {
                            2
                        } else {
                            1
                        },
                        if data.is_split { data.parts_len() } else { 0 },
                        data.parts_len(),
                    );
                    (key, rank)
                }
            };
            if let Some(&position) = positions.get(&key) {
                if rank > candidate_rank(&unique[position]) {
                    unique[position] = row;
                }
            } else {
                positions.insert(key, unique.len());
                unique.push(row);
            }
        }
        self.rows = unique;
    }

    fn project(&self, py: Python<'_>, index: usize) -> PyResult<Py<PyAny>> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| PyIndexError::new_err(index.to_string()))?;
        match row {
            Candidate::File(table, index) => {
                let path = &table.paths[*index];
                let anchor = table.relation_anchors[*index]
                    .as_ref()
                    .and_then(CheapAnchor::anchor);
                let route = table.file_routes[*index];
                Ok((
                    "file",
                    (
                        path,
                        table.sizes[*index],
                        filesystem_route_name(route),
                        anchor.map(|a| a.format.as_str()).unwrap_or(""),
                        table.relation_anchors[*index]
                            .as_ref()
                            .map(CheapAnchor::reject_mask)
                            .unwrap_or(0),
                        filesystem_logical_name(path),
                    ),
                )
                    .into_pyobject(py)?
                    .into_any()
                    .unbind())
            }
            Candidate::Relation(group) => {
                let dict = group.to_dict(py)?;
                let data = group.candidate_data();
                if data.needs_password {
                    if let Some(reason) = self.relation_failures.get(&path_key(data.entry_path)) {
                        if let Some(metadata) = dict.bind(py).get_item("head_metadata")? {
                            metadata
                                .cast::<PyDict>()?
                                .set_item("relation_failure_reason", reason)?;
                        }
                    }
                }
                Ok(("relation", dict).into_pyobject(py)?.into_any().unbind())
            }
        }
    }

    fn summary(&self, index: usize) -> PyResult<(String, String)> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| PyIndexError::new_err(index.to_string()))?;
        Ok(match row {
            Candidate::File(table, index) => (
                table.paths[*index].clone(),
                table.relation_anchors[*index]
                    .as_ref()
                    .and_then(CheapAnchor::anchor)
                    .map(|anchor| anchor.format.clone())
                    .unwrap_or_default(),
            ),
            Candidate::Relation(group) => {
                let data = group.candidate_data();
                (data.entry_path.to_owned(), data.format_hint.to_owned())
            }
        })
    }

    fn path_keys(&self, index: usize) -> PyResult<Vec<String>> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| PyIndexError::new_err(index.to_string()))?;
        Ok(match row {
            Candidate::File(table, index) => vec![path_key(&table.paths[*index])],
            Candidate::Relation(group) => {
                let data = group.candidate_data();
                relation_path_keys(
                    data.parts(),
                    data.companions,
                    data.carrier_path,
                    data.entry_path,
                )
                .into_iter()
                .collect()
            }
        })
    }

    fn resolve(&self, py: Python<'_>) -> PyResult<NativeDiscoveryRoutes> {
        let cancellation = crate::io::cancellation::Cancellation::current();
        cancellation.check()?;
        let mut routes = NativeDiscoveryRoutes::default();
        let mut claimed: HashSet<String> = HashSet::new();
        let mut speculative = HashSet::new();
        let mut blocked: HashSet<String> = HashSet::new();
        for (index, row) in self.rows.iter().enumerate() {
            let Candidate::Relation(group) = row else {
                continue;
            };
            let data = group.candidate_data();
            if !data.relation_confirmed
                && (data.needs_password
                    || (data.multivolume && (data.is_split || data.structural_non_head)))
            {
                blocked.extend(relation_path_keys(
                    data.parts(),
                    data.companions,
                    data.carrier_path,
                    data.entry_path,
                ));
                routes.relation_blocked.push(index);
                routes.relation_events.push((index, 2));
            } else if data.relation_confirmed && matches!(data.format_hint, "rar" | "7z" | "zip") {
                claimed.extend(
                    data.parts()
                        .chain(data.companions.iter().map(String::as_str))
                        .map(|path| path_key(path)),
                );
                speculative.extend(
                    group
                        .speculative_paths()
                        .filter(|path| *path != data.entry_path)
                        .map(path_key),
                );
                routes.relation_resolved.push(index);
                routes.relation_events.push((index, 1));
            } else {
                routes.relation_residual.push(index);
            }
        }
        let detection_indices = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| match row {
                Candidate::File(table, file_index)
                    if table.file_routes[*file_index] == FILE_ROUTE_DETECTION =>
                {
                    Some(index)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        py.detach(|| {
            for batch in detection_indices.chunks(1024) {
                if cancellation.cancelled() {
                    break;
                }
                let parallel_files = batch.len().min(rayon::current_num_threads()).clamp(1, 8);
                let decisions = batch
                    .par_iter()
                    .with_min_len(batch.len().div_ceil(parallel_files))
                    .map(|&index| {
                        cancellation.run(|| {
                            if cancellation.cancelled() {
                                return None;
                            }
                            let Candidate::File(table, file_index) = &self.rows[index] else {
                                return None;
                            };
                            let path = &table.paths[*file_index];
                            let key = path_key(path);
                            if claimed.contains(&key) || blocked.contains(&key) {
                                return None;
                            }
                            let anchor = table.relation_anchors[*file_index]
                                .as_ref()
                                .and_then(CheapAnchor::anchor);
                            let format = anchor.map(|anchor| anchor.format.as_str()).unwrap_or("");
                            let accepted = matches!(
                                format,
                                "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "enc"
                            ) && anchor.is_some_and(|anchor| anchor.standalone);
                            let scan = if accepted && format != "enc" {
                                Some(
                                    scan_detected_path(path, format, parallel_files)
                                        .map(Arc::new)
                                        .map_err(Arc::new),
                                )
                            } else {
                                None
                            };
                            let accepted = accepted
                                && (format == "enc"
                                    || scan
                                        .as_ref()
                                        .and_then(|scan| scan.as_ref().ok())
                                        .is_some_and(|scan| scan.is_primary(format)));
                            Some((
                                index,
                                key,
                                accepted,
                                scan.filter(|_| !accepted || format == "lz4"),
                            ))
                        })
                    })
                    .collect::<Vec<_>>();
                for (index, key, accepted, scan) in decisions.into_iter().flatten() {
                    if claimed.contains(&key) {
                        continue;
                    }
                    if let Some(scan) = scan {
                        routes.scans.insert(index, scan);
                    }
                    if accepted {
                        claimed.insert(key);
                        routes.detection_resolved.push(index);
                        routes.detection_events.push((index, 1));
                    } else {
                        routes.detection_residual.push(index);
                    }
                }
            }
        });
        cancellation.check()?;
        // Preserve the former stage order: filesystem residuals, Relations
        // residuals, then Detection residuals.
        for (index, row) in self.rows.iter().enumerate() {
            if let Candidate::File(table, file_index) = row {
                if speculative.contains(&path_key(&table.paths[*file_index])) {
                    routes.embedded.push(index);
                } else if table.file_routes[*file_index] == FILE_ROUTE_RESIDUAL {
                    let key = path_key(&table.paths[*file_index]);
                    if !claimed.contains(&key) && !blocked.contains(&key) {
                        routes.embedded.push(index);
                    }
                }
            }
        }
        for &index in &routes.relation_residual {
            if let Candidate::Relation(group) = &self.rows[index] {
                let data = group.candidate_data();
                let keys = relation_path_keys(
                    data.parts(),
                    data.companions,
                    data.carrier_path,
                    data.entry_path,
                );
                if keys
                    .iter()
                    .all(|key| !claimed.contains(key) && !blocked.contains(key))
                {
                    routes.embedded.push(index);
                }
            }
        }
        for &index in &routes.detection_residual {
            if let Candidate::File(table, file_index) = &self.rows[index] {
                let key = path_key(&table.paths[*file_index]);
                if !claimed.contains(&key) && !blocked.contains(&key) {
                    routes.embedded.push(index);
                }
            }
        }
        Ok(routes)
    }

    /// Finish primary projection before calling: only embedded/relation rows survive.
    #[pyo3(signature = (routes, recursive=false, force_scan=false, enabled=true, recursive_ratio=0.3))]
    fn prepare_embedded(
        &mut self,
        routes: PyRef<'_, NativeDiscoveryRoutes>,
        recursive: bool,
        force_scan: bool,
        enabled: bool,
        recursive_ratio: f64,
    ) -> NativeEmbeddedBatch {
        let mut ids = routes.embedded.clone();
        let ratio = recursive_ratio.clamp(0.0, 1.0);
        let sized = if enabled && recursive && !force_scan && ratio > 0.0 {
            ids.iter()
                .filter_map(|&index| {
                    let size = match &self.rows[index] {
                        Candidate::File(table, row) => table.sizes[*row],
                        Candidate::Relation(group) => {
                            let data = group.candidate_data();
                            if data.is_split {
                                data.logical_size()
                            } else {
                                data.size()
                            }
                        }
                    }?;
                    (size > 0).then_some((index, size))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let threshold = if recursive && !force_scan && ratio > 0.0 {
            sized.iter().map(|(_, size)| *size as f64).sum::<f64>() * ratio
        } else {
            0.0
        };
        let select_all = enabled && (force_scan || !recursive);
        let selected: HashSet<usize> = if !enabled || select_all {
            HashSet::new()
        } else if ratio <= 0.0 {
            HashSet::new()
        } else {
            sized
                .into_iter()
                .filter(|(_, size)| *size as f64 >= threshold)
                .map(|(index, _)| index)
                .collect()
        };
        // Keep observed errors even when new I/O is disabled. The shared
        // scheduler carries only work selected by this root's original policy.
        ids.retain(|index| {
            select_all
                || selected.contains(index)
                || matches!(routes.scans.get(index), Some(Err(_)))
        });
        if ids.is_empty() {
            // This root has no remaining I/O or cached errors. Its primary
            // decisions are already owned by Python; no recovery can use it.
            *self = Self::default();
            return NativeEmbeddedBatch::default();
        }
        let mut excluded: HashSet<_> = routes.relation_resolved.iter().filter(|&&index| {
            !matches!(&self.rows[index], Candidate::Relation(group) if group.is_incomplete())
        }).chain(&routes.detection_resolved)
            .flat_map(|&index| self.path_keys(index).unwrap_or_default()).collect();
        // Keep only the evidence used by volume recovery, not resolved groups
        // and their execution metadata from every root. Raw snapshots still
        // supply all eligible peers; primary decisions have been projected.
        let relation_cache = self.relation_cache();
        let mut claimed_ranges = HashMap::new();
        let scanned_paths = ids
            .iter()
            .map(|&index| path_key(self.rows[index].embedded_source().0))
            .collect();
        for &index in &routes.relation_resolved {
            if let Candidate::Relation(group) = &self.rows[index] {
                group.collect_source_ranges(&scanned_paths, &mut claimed_ranges);
                // Candidate membership is a lease, not exclusive ownership.
                // Independent heads may need the same peer domains.
                for path in group.speculative_paths() {
                    excluded.remove(&path_key(path));
                }
            }
        }
        let mut scans = HashMap::new();
        if ids.len() == self.rows.len() {
            // A full deep scan already uses every row; do not duplicate its
            // candidate storage merely to reproduce the same indices.
            scans
                .extend(ids.iter().filter_map(|index| {
                    routes.scans.get(index).map(|scan| (*index, scan.clone()))
                }));
        } else {
            let positions: HashMap<_, _> = ids
                .iter()
                .enumerate()
                .map(|(position, &index)| (index, position))
                .collect();
            let mut rows = Vec::with_capacity(ids.len());
            for (index, row) in std::mem::take(&mut self.rows).into_iter().enumerate() {
                if let Some(&position) = positions.get(&index) {
                    let remapped = rows.len();
                    ids[position] = remapped;
                    if let Some(scan) = routes.scans.get(&index) {
                        scans.insert(remapped, scan.clone());
                    }
                    rows.push(row);
                }
            }
            self.rows = rows;
        }
        NativeEmbeddedBatch {
            relation_cache,
            pending_volumes: Vec::new(),
            excluded,
            claimed_ranges,
            scans,
            ids,
            force_scan,
        }
    }
}

fn scan_embedded_candidate(
    path: &str,
    force_scan: bool,
    pe_state: Option<PeState>,
    parallel_files: usize,
) -> EmbeddedOutcome {
    if path.is_empty() {
        return EmbeddedOutcome::Residual;
    }
    if !force_scan {
        // Only residuals reach Embedded. Consume refined native facts; filename
        // extensions never establish executable identity or SFX policy.
        let is_pe = match pe_state {
            Some(PeState::Confirmed) => true,
            Some(PeState::None) => false,
            Some(PeState::Candidate) | None => match inspect_pe_image_native(path) {
                Ok(PeProbe::Confirmed(_)) => true,
                Ok(_) => false,
                Err(error) => return EmbeddedOutcome::read_error(path, Arc::new(error)),
            },
        };
        if is_pe {
            return EmbeddedOutcome::Residual;
        }
    }
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return EmbeddedOutcome::read_error(path, Arc::new(error)),
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return EmbeddedOutcome::Residual;
    }
    match scan_embedded_path(path, parallel_files) {
        Ok(scan) if scan.has_candidates() => EmbeddedOutcome::Scan(Arc::new(scan)),
        Ok(_) => EmbeddedOutcome::Residual,
        Err(error) => EmbeddedOutcome::read_error(path, Arc::new(error)),
    }
}

fn candidate_rank(row: &Candidate) -> (u8, usize, usize) {
    match row {
        Candidate::File(..) => (1, 0, 1),
        Candidate::Relation(group) => {
            let data = group.candidate_data();
            (
                if data.is_split && !data.needs_password {
                    2
                } else {
                    1
                },
                if data.is_split { data.parts_len() } else { 0 },
                data.parts_len(),
            )
        }
    }
}

fn relation_path_keys<'a>(
    parts: impl Iterator<Item = &'a str>,
    companions: &'a [String],
    carrier: &'a str,
    entry: &'a str,
) -> HashSet<String> {
    parts
        .chain(companions.iter().map(String::as_str))
        .chain([carrier, entry])
        .filter(|path| !path.is_empty())
        .map(path_key)
        .collect()
}
