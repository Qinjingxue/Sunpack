use crate::analysis_native::volume_anchor::{
    CheapAnchor, EMBEDDED_VOLUME, RAR_PASSWORD_MATCHED_INCOMPLETE, SEVEN_ZIP_CARRIER_INTERRUPTED,
};
use crate::io::archive_state::AnalysisFacts;
use crate::path_keys::{case_key, path_key};
use crate::relations::{
    build_native_candidate_groups_from_snapshot, collect_relation_cache, resolve_embedded_volumes,
    NativeRelationGroup, RelationCache, RelationProjection,
};
use crate::scan::directory::{
    filesystem_logical_name, DirectorySnapshotTable,
    NativeDirectorySnapshot, FILE_ROUTE_DETECTION, FILE_ROUTE_RELATIONS, FILE_ROUTE_RESIDUAL,
};
use crate::scan::embedded::{
    scan_detected_lz4, scan_embedded_path, NativeScanResult, RarInputResolution,
    ResolvedEmbeddedScan,
};
use crate::scan::pe_overlay::{inspect_pe_image_native, PeProbe, PeState};
use rayon::prelude::*;
use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) enum CandidateProjection<'a> {
    File {
        path: &'a str,
        format_hint: &'a str,
        logical_name: String,
    },
    Relation {
        relation: RelationProjection,
    },
}

pub(crate) struct EmbeddedPageRow {
    pub(crate) index: usize,
    pub(crate) scan: Option<Arc<NativeScanResult>>,
    pub(crate) error: Option<Arc<io::Error>>,
}

pub(crate) struct EmbeddedVolumeOutcome {
    pub(crate) index: usize,
    pub(crate) status: u8,
    pub(crate) scan: Option<ResolvedEmbeddedScan>,
    pub(crate) password: Option<Arc<str>>,
}

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
            Self::Relation(group) => (group.entry_path(), group.entry_anchor().map(|a| a.pe_state)),
        }
    }
}

#[derive(Default)]
pub(crate) struct NativeCandidateTable {
    rows: Vec<Candidate>,
    targets: Option<FileTargets>,
    // Decrypted continuations may outlive their headless proposal. Transfer
    // their existing facts to the same embedded peer frontier, without I/O.
    volume_seeds: Vec<(Arc<DirectorySnapshotTable>, usize, crate::analysis_native::volume_anchor::VolumeAnchor)>,
    // Shared physical facts; row indices survive only for this discovery scan.
    relation_sources: Vec<NativeDirectorySnapshot>,
}

pub(crate) struct FileTargets {
    names_by_path: HashMap<String, String>,
}

impl FileTargets {
    pub(crate) fn new(targets: Vec<(String, String)>) -> Self {
        Self {
            names_by_path: targets
                .into_iter()
                .map(|(path, name)| (path_key(&path), case_key(&name)))
                .collect(),
        }
    }

    pub(crate) fn only_path(&self) -> Option<&str> {
        (self.names_by_path.len() == 1).then(|| self.names_by_path.keys().next().unwrap().as_str())
    }

    pub(crate) fn into_singles(self) -> impl Iterator<Item = (String, Self)> {
        self.names_by_path.into_iter().map(|(path, name)| {
            let target = Self { names_by_path: HashMap::from([(path.clone(), name)]) };
            (path, target)
        })
    }

    fn select(&self, snapshot: &NativeDirectorySnapshot) -> Option<NativeDirectorySnapshot> {
        let mut exact = 0;
        let rows: Vec<_> = snapshot
            .rows
            .iter()
            .copied()
            .filter(|&row| {
                let key = path_key(&snapshot.table.paths[row]);
                if self.names_by_path.contains_key(&key) {
                    exact += 1;
                    true
                } else {
                    false
                }
            })
            .collect();
        // Preserve logical-name recovery for targets excluded from the view.
        (exact == self.names_by_path.len()).then(|| snapshot.view(rows))
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
        let mut pending: HashSet<_> = self
            .rows
            .iter()
            .filter_map(|row| match row {
                Candidate::Relation(group) => Some(group),
                _ => None,
            })
            .flat_map(|group| {
                let head = group.entry_path();
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
        for &row in snapshot.rows.iter() {
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
        collect_relation_cache(self.rows.iter().filter_map(|row| match row {
            Candidate::Relation(group) => Some(group.as_ref()),
            Candidate::File(..) => None,
        }))
    }

    fn relation_groups(
        &self,
        raw: &NativeDirectorySnapshot,
        filtered: &NativeDirectorySnapshot,
        targeted: Option<&NativeDirectorySnapshot>,
        cached: Option<&RelationCache>,
    ) -> Vec<NativeRelationGroup> {
        let routed_view;
        let selection = if let Some(targeted) = targeted {
            targeted
        } else {
            routed_view = filtered.file_route_view(FILE_ROUTE_RELATIONS);
            &routed_view
        };
        let mut groups =
            build_native_candidate_groups_from_snapshot(raw, selection, cached);
        // Only an explicit selection can nominate files on other routes.
        // Relations can claim them as parts, but ordinary results stay on
        // their original route.
        if let Some(targeted) = targeted {
            let routed: HashSet<_> = targeted
                .rows
                .iter()
                .filter(|&&row| targeted.table.file_routes[row] == FILE_ROUTE_RELATIONS)
                .map(|&row| path_key(&targeted.table.paths[row]))
                .collect();
            groups.retain(|group| match group {
                NativeRelationGroup::Ordinary(row, _) => routed.contains(&row.path_key),
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

#[derive(Default)]
pub(crate) struct NativeDiscoveryRoutes {
    scans: HashMap<usize, Result<Arc<NativeScanResult>, Arc<io::Error>>>,
    pub(crate) relation_events: Vec<(usize, u8)>,
    pub(crate) detection_events: Vec<(usize, u8)>,
    embedded: Vec<usize>,
}

impl NativeDiscoveryRoutes {
    pub(crate) fn resolved_relations(&self) -> impl Iterator<Item = usize> + '_ {
        self.relation_events
            .iter()
            .filter_map(|&(index, status)| (status == 1).then_some(index))
    }
}

enum EmbeddedOutcome {
    Residual,
    Failed(Arc<io::Error>),
    Scan(Arc<NativeScanResult>),
}

#[derive(Default)]
pub(crate) struct NativeEmbeddedBatch {
    relation_cache: RelationCache,
    scans: HashMap<usize, Result<Arc<NativeScanResult>, Arc<io::Error>>>,
    ids: Vec<usize>,
    cursor: usize,
    nominated: usize,
    peer_rows: Option<HashMap<(usize, String), Vec<usize>>>,
    seen_paths: HashSet<String>,
    force_scan: bool,
    pending_volumes: Vec<PendingEmbeddedVolume>,
    supplemental: HashSet<usize>,
    excluded: HashSet<String>,
    claimed_ranges: HashMap<String, Vec<(u64, u64)>>,
}

struct PendingEmbeddedVolume {
    index: usize,
    anchor: crate::analysis_native::volume_anchor::VolumeAnchor,
    scan: Option<Arc<NativeScanResult>>,
}

impl NativeEmbeddedBatch {
    pub(crate) fn claims_offset(&self, key: &str, offset: u64) -> bool {
        self.claimed_ranges.get(key).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|&(start, end)| start <= offset && offset < end)
        })
    }

    fn project_outcomes(
        &mut self,

        table: &NativeCandidateTable,
        outcomes: impl Iterator<Item = (usize, EmbeddedOutcome)>,
    ) -> io::Result<Vec<EmbeddedPageRow>> {
        let mut projected = Vec::new();
        for (index, outcome) in outcomes {
            let (scan, error) = match outcome {
                EmbeddedOutcome::Residual => {
                    unreachable!("residuals are filtered before projection")
                }
                EmbeddedOutcome::Failed(error) => (None, Some(error)),
                EmbeddedOutcome::Scan(scan) => {
                    let path = table.rows[index].embedded_source().0;
                    let key = path_key(path);
                    let mut anchors = scan.relation_anchors();
                    if self.claimed_ranges.contains_key(&key) {
                        // Only proven extents (or the identical known anchor)
                        // exclude another head; an opaque chunk's EOF does not.
                        // Independent encrypted archives still use the normal
                        // boundary/password resolution before projection.
                        anchors.retain(|a| {
                            a.standalone
                                || (!a.multivolume && a.needs_password)
                                || !self.claims_offset(&key, a.structure_offset.unwrap_or(0))
                        });
                        if anchors.is_empty() && !scan.has_independent_archive() {
                            continue;
                        }
                    }
                    if !anchors.is_empty() {
                        let independent = scan.has_independent_archive();
                        for mut anchor in anchors {
                            anchor.path = path.to_owned();
                            let retain_scan = anchor.needs_password || independent;
                            self.pending_volumes.push(PendingEmbeddedVolume {
                                index,
                                anchor,
                                scan: retain_scan.then(|| Arc::clone(&scan)),
                            });
                        }
                        (None, None)
                    } else {
                        // A complete peer archive keeps its original ownership.
                        self.excluded.extend(table.path_keys(index)?);
                        (Some(scan), None)
                    }
                }
            };
            projected.push(EmbeddedPageRow {
                index,
                scan,
                error,
            });
        }
        Ok(projected)
    }
}

fn scan_embedded_jobs(
    groups: &[(&NativeCandidateTable, &NativeEmbeddedBatch)],
    jobs: &[(usize, usize)],
) -> std::io::Result<Vec<(usize, usize, EmbeddedOutcome)>> {
    let cancellation = crate::io::cancellation::Cancellation::current();
    cancellation.check()?;
    let outcomes = (|| {
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
    })();
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

impl NativeDiscoveryRoutes {
    pub(crate) fn primary_analysis(&self, index: usize) -> Option<AnalysisFacts> {
        self.scans.get(&index)?.as_ref().ok()?.primary_analysis()
    }
}

impl NativeEmbeddedBatch {
    pub(crate) fn len(&self) -> usize {
        self.ids.len() - self.cursor
    }

    /// Process selected jobs across roots and consume their cached scan evidence.
    /// Root-local policy, relation ownership and password evidence stay in each batch.
    pub(crate) fn scan_pages(
        mut groups: Vec<(&mut NativeCandidateTable, &mut NativeEmbeddedBatch)>,
        limit: usize,
    ) -> io::Result<Vec<(usize, Vec<EmbeddedPageRow>)>> {
        let mut jobs = Vec::new();
        for (group, (table, batch)) in groups.iter_mut().enumerate() {
            batch.enqueue_volume_peers(table);
            let take = (limit - jobs.len()).min(batch.len());
            jobs.extend(batch.ids[batch.cursor..batch.cursor + take].iter()
                .map(|&index| (group, index)));
            batch.cursor += take;
            if jobs.len() == limit { break; }
        }
        let borrowed: Vec<_> = groups.iter().map(|(table, batch)| (&**table, &**batch)).collect();
        let outcomes = scan_embedded_jobs(&borrowed, &jobs)?;
        for (group, index) in jobs {
            let (_, batch) = &mut groups[group];
            if !batch.scans.is_empty() && batch.scans.remove(&index).is_some() && batch.scans.is_empty() {
                batch.scans = HashMap::new();
            }
        }
        let mut by_group: BTreeMap<usize, Vec<_>> = BTreeMap::new();
        for (group, index, outcome) in outcomes {
            by_group.entry(group).or_default().push((index, outcome));
        }
        by_group.into_iter().map(|(group, outcomes)| {
            let (table, batch) = &mut groups[group];
            let mut rows = batch.project_outcomes(table, outcomes.into_iter())?;
            // Supplemental rows supply relation facts, not additional targets.
            rows.retain(|row| !batch.supplemental.contains(&row.index));
            batch.enqueue_volume_peers(table);
            Ok((group, rows))
        }).collect()
    }

    // Volume evidence extends the same physical discovery frontier. Index raw
    // row references only when needed, then consume each source/stem once.
    fn enqueue_volume_peers(&mut self, table: &mut NativeCandidateTable) {
        let mut selected = HashSet::new();
        for item in &self.pending_volumes[self.nominated..] {
            if !item.anchor.multivolume && !item.anchor.needs_password { continue; }
            let stem = crate::scan::catalog::catalog_stem(&item.anchor.path);
            let key = path_key(&item.anchor.path);
            for (source, snapshot) in table.relation_sources.iter().enumerate() {
                let contains = match &table.rows[item.index] {
                    Candidate::File(facts, row) => Arc::ptr_eq(facts, &snapshot.table)
                        && (snapshot.rows.len() == snapshot.table.paths.len() || snapshot.rows.contains(row)),
                    Candidate::Relation(_) => snapshot.rows.iter()
                        .any(|&row| path_key(&snapshot.table.paths[row]) == key),
                };
                if contains { selected.insert((source, stem.clone())); }
            }
        }
        self.nominated = self.pending_volumes.len();
        if selected.is_empty() { return; }
        let index = self.peer_rows.get_or_insert_with(|| {
            self.seen_paths.extend(table.rows.iter().map(|row| path_key(row.embedded_source().0)));
            let mut index: HashMap<(usize, String), Vec<usize>> = HashMap::new();
            // Original candidates already bound every stem this frontier can
            // nominate; appended peers cannot introduce another filename stem.
            // Build this set only if a raw unknown peer actually exists.
            let mut candidate_stems = None;
            for (source, snapshot) in table.relation_sources.iter().enumerate() {
                for &row in snapshot.rows.iter() {
                    if snapshot.table.is_dirs[row] || !snapshot.table.relation_member_eligible[row]
                        || snapshot.table.relation_anchors[row].as_ref().and_then(CheapAnchor::anchor).is_some() {
                        continue;
                    }
                    let path = &snapshot.table.paths[row];
                    let key = path_key(path);
                    if self.seen_paths.contains(&key) || self.excluded.contains(&key)
                        || self.relation_cache.anchors.contains_key(&key) { continue; }
                    let stems = candidate_stems.get_or_insert_with(|| table.rows.iter()
                        .map(|row| crate::scan::catalog::catalog_stem(row.embedded_source().0))
                        .collect::<HashSet<_>>());
                    let stem = crate::scan::catalog::catalog_stem(path);
                    if stems.contains(&stem) { index.entry((source, stem)).or_default().push(row); }
                }
            }
            index
        });
        for (source, stem) in selected {
            let Some(rows) = index.remove(&(source, stem)) else { continue; };
            let snapshot = &table.relation_sources[source];
            for row in rows {
                let key = path_key(&snapshot.table.paths[row]);
                if self.excluded.contains(&key) || !self.seen_paths.insert(key) { continue; }
                let row_index = table.rows.len();
                table.rows.push(Candidate::File(Arc::clone(&snapshot.table), row));
                self.supplemental.insert(row_index);
                self.ids.push(row_index);
            }
        }
    }

    pub(crate) fn encrypted_volume_paths(&self, table: &NativeCandidateTable) -> Vec<String> {
        let mut requests: HashSet<_> = self
            .pending_volumes
            .iter()
            .filter(|pending| pending.anchor.needs_password)
            .map(|pending| pending.anchor.path.as_str())
            .collect();
        if requests.is_empty() {
            return Vec::new();
        }
        let selected: HashSet<_> = requests.iter().map(|path| path_key(path)).collect();
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
            for &row in snapshot.rows.iter() {
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
                if anchor.is_some_and(|a| a.needs_password) {
                    requests.insert(path.as_str());
                }
            }
        }
        requests.into_iter().map(str::to_owned).collect()
    }

    /// One directed Relations call per source scope, using native scan facts.
    /// Status 0 returns standalone/sibling scan facts to Embedded.
    pub(crate) fn resolve_volumes(
        &mut self,

        table: &mut NativeCandidateTable,
        password_candidates: Option<Vec<(String, Vec<Arc<str>>)>>,
    ) -> io::Result<Vec<EmbeddedVolumeOutcome>> {
        use crate::analysis_native::volume_anchor::resolve_encrypted_relation_anchor;
        let mut batch = std::mem::take(self);
        if batch.pending_volumes.is_empty() {
            return Ok(Vec::new());
        }
        let candidates: HashMap<_, _> = password_candidates
            .unwrap_or_default()
            .into_iter()
            .map(|(path, values)| (path_key(&path), values))
            .collect();
        let mut cache = std::mem::take(&mut batch.relation_cache);
        let mut pending = std::mem::take(&mut batch.pending_volumes);
        let requested: HashSet<_> = pending.iter()
            .filter(|item| !batch.supplemental.contains(&item.index))
            .map(|item| path_key(&item.anchor.path)).collect();
        let pending_keys: HashSet<_> = pending
            .iter()
            .map(|item| path_key(&item.anchor.path))
            .collect();
        for snapshot in table
            .relation_sources
            .iter()
            .filter(|_| !candidates.is_empty())
        {
            for &row in snapshot.rows.iter() {
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
        let matched = (|| {
            // Independent headers share the existing Rayon pool. Preserve the
            // request's cancellation on each worker, including expensive KDFs.
            encrypted
                .into_par_iter()
                .map(|(anchor, values)| {
                    cancellation.run(|| -> io::Result<_> {
                        let reader =
                            crate::io::reader::ManagedReader::open(&anchor.path)?.probe_reader();
                        let (resolved, index) =
                            resolve_encrypted_relation_anchor(anchor, &reader, values, true)?;
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
        })()?;
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
                if !anchor.standalone && anchor.rar5_encryption.is_some() {
                    // Relations decides whether these public header facts have
                    // peers. Keep the ordinary fallback until that decision.
                    anchors.push(anchor.clone());
                }
                if path_counts[&key] == 1 {
                    batch.excluded.insert(key);
                }
                if let Some(scan) = item.scan {
                    let failure_reason = anchor.expected_logical_size.is_none().then(|| {
                        if matched.contains_key(&match_key)
                            || anchor.has_any(RAR_PASSWORD_MATCHED_INCOMPLETE)
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
                            password: matched.get(&match_key).cloned(),
                            failure_reason,
                        },
                    );
                }
                continue;
            }
            // Encrypted RAR exposes its split role only after password
            // resolution. Apply the same ownership evidence at that point.
            if !anchor.multivolume
                || !batch.claims_offset(&key, anchor.structure_offset.unwrap_or(0))
            {
                anchor.flags |= EMBEDDED_VOLUME;
                anchors.push(anchor);
            }
            // Project once after Relations; the planner combines logical inputs
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
        let mut fallback: Vec<_> = fallback_scans
            .into_iter()
            .map(|(index, (scan, resolutions))| EmbeddedVolumeOutcome {
                index,
                status: 0,
                scan: Some(ResolvedEmbeddedScan { scan, resolutions }),
                password: None,
            })
            .collect();
        if anchors.is_empty() {
            fallback.retain(|row| !batch.supplemental.contains(&row.index));
            return Ok(fallback);
        }
        let sources = &table.relation_sources;
        // Only these newly discovered slices may re-enter a claimed carrier.
        // Other files retain the existing whole-file ownership exclusion.
        let anchor_paths: HashSet<_> = anchors.iter().map(|a| path_key(&a.path)).collect();
        batch.excluded.retain(|key| !anchor_paths.contains(key));
        let excluded = &batch.excluded;
        let mut groups = resolve_embedded_volumes(sources, anchors, excluded, cache);
        // A lone encrypted file keeps its existing embedded boundary result.
        // Only a real candidate proposal replaces those individual failures.
        groups.retain(|group| group.unresolved_password_group()
            || !group.entry_anchor().is_some_and(|a|
                a.needs_password && !a.multivolume && a.rar5_encryption.is_some()));
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
                    .is_some_and(|a| a.has_any(SEVEN_ZIP_CARRIER_INTERRUPTED))
        };
        let mut peers: HashMap<String, HashSet<String>> = groups
            .iter()
            .filter(|g| speculative(g))
            .map(|g| (stem(g.entry_path()), HashSet::new()))
            .collect();
        if !peers.is_empty() {
            for snapshot in sources {
                for &row in snapshot.rows.iter() {
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
                        .get(&stem(g.entry_path()))
                        .is_some_and(|p| p.len() > 1)
            });
        }
        if !batch.supplemental.is_empty() {
            // Ownership is physical: a related carrier may also hold a second
            // split head. Keep its connected groups before cleanup can own the
            // carrier, without promoting unrelated same-stem archives.
            let mut by_path: HashMap<String, Vec<usize>> = HashMap::new();
            let mut keep = vec![false; groups.len()];
            let mut work = Vec::new();
            for (index, group) in groups.iter().enumerate() {
                let data = group.candidate_data();
                for path in std::iter::once(data.entry_path).chain(data.parts())
                    .chain(data.companions.iter().map(String::as_str)) {
                    let key = path_key(path);
                    if requested.contains(&key) && !keep[index] {
                        keep[index] = true;
                        work.push(index);
                    }
                    by_path.entry(key).or_default().push(index);
                }
            }
            let mut owned = HashSet::new();
            while let Some(index) = work.pop() {
                let data = groups[index].candidate_data();
                for path in std::iter::once(data.entry_path).chain(data.parts())
                    .chain(data.companions.iter().map(String::as_str)) {
                    let key = path_key(path);
                    if let Some(peers) = by_path.remove(&key) {
                        owned.insert(key);
                        for peer in peers {
                            if !keep[peer] {
                                keep[peer] = true;
                                work.push(peer);
                            }
                        }
                    }
                }
            }
            let mut index = 0;
            groups.retain(|_| { let retain = keep[index]; index += 1; retain });
            fallback.retain(|row| !batch.supplemental.contains(&row.index)
                || owned.contains(&path_key(table.rows[row.index].embedded_source().0)));
        }
        let mut grouped_ranges = HashMap::new();
        let mut seen_facts = HashSet::new();
        for group in groups.iter().filter(|group| group.unresolved_password_group()) {
            group.collect_source_ranges(&anchor_paths, &mut grouped_ranges, &mut seen_facts);
        }
        for row in &mut fallback {
            if let Some(scan) = &mut row.scan {
                let key = path_key(table.rows[row.index].embedded_source().0);
                if let Some(ranges) = grouped_ranges.get(&key) {
                    scan.resolutions.retain(|offset, _| !ranges.iter().any(|(start, _)| start == offset));
                }
            }
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
            fallback.push(EmbeddedVolumeOutcome {
                index,
                status: 1,
                scan: None,
                password,
            });
        }
        Ok(fallback)
    }
}

impl NativeCandidateTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn extend(&mut self, other: &mut Self) {
        self.rows.append(&mut other.rows);
        self.relation_sources.append(&mut other.relation_sources);
        self.volume_seeds.append(&mut other.volume_seeds);
    }

    pub(crate) fn append_directory(
        &mut self,

        raw_snapshot: &NativeDirectorySnapshot,
        filtered_snapshot: &NativeDirectorySnapshot,
        targets: Option<FileTargets>,
    ) -> std::io::Result<()> {
        (|| {
            self.targets = targets;
            let selected = self
                .targets
                .as_ref()
                .and_then(|targets| targets.select(filtered_snapshot));
            let groups = self.relation_groups(
                raw_snapshot,
                filtered_snapshot,
                selected.as_ref(),
                None,
            );
            let filtered_snapshot = selected.as_ref().unwrap_or(filtered_snapshot);
            self.rows
                .reserve(groups.len() + filtered_snapshot.rows.len());
            self.rows.extend(
                groups
                    .into_iter()
                    .map(|group| Candidate::Relation(Box::new(group))),
            );
            for &row in filtered_snapshot.rows.iter() {
                if !filtered_snapshot.table.is_dirs[row]
                    && filtered_snapshot.table.file_routes[row] != FILE_ROUTE_RELATIONS
                {
                    self.rows
                        .push(Candidate::File(Arc::clone(&filtered_snapshot.table), row));
                }
            }
            self.retain_targets();
            self.append_speculative_files(raw_snapshot);
            self.relation_sources.push(raw_snapshot.share_rows());
        })();
        Ok(())
    }

    /// Decrypt only nominated RAR families. Until the hidden main header is
    /// read, an encrypted RAR5 file can be either the entry or a continuation.
    /// Keep the resulting byte facts in the same request-local relation cache.
    pub(crate) fn encrypted_rar_anchors(&self) -> Vec<crate::analysis_native::volume_anchor::VolumeAnchor> {
        let stems: HashSet<_> = self.rows.iter().filter_map(|row| match row {
            Candidate::Relation(group) => group.entry_anchor()
                .filter(|a| a.format == "rar" && a.needs_password && !a.standalone)
                .map(|a| crate::scan::catalog::catalog_stem(&a.path)),
            _ => None,
        }).collect();
        let mut anchors: HashMap<_, _> = self.rows.iter().filter_map(|row| match row {
            Candidate::Relation(group) => group.entry_anchor()
                .filter(|a| a.format == "rar" && a.needs_password)
                .map(|a| (path_key(&a.path), a.clone())),
            _ => None,
        }).collect();
        if stems.is_empty() { return anchors.into_values().collect(); }
        for snapshot in &self.relation_sources {
            for &row in snapshot.rows.iter() {
                if !snapshot.table.relation_member_eligible[row] { continue; }
                let Some(anchor) = snapshot.table.relation_anchors[row].as_ref()
                    .and_then(CheapAnchor::anchor)
                    .filter(|a| a.format == "rar" && a.needs_password)
                    .filter(|a| stems.contains(&crate::scan::catalog::catalog_stem(&a.path))) else { continue; };
                anchors.entry(path_key(&anchor.path)).or_insert_with(|| anchor.clone());
            }
        }
        anchors.into_values().collect()
    }

    pub(crate) fn take_file_targets(&mut self) -> FileTargets {
        self.targets.take().expect("file discovery table must have targets")
    }

    /// Replace the relation evidence for one table after a password is found.
    pub(crate) fn retry_relations(
        &mut self,

        raw_snapshot: &NativeDirectorySnapshot,
        filtered_snapshot: &NativeDirectorySnapshot,
        anchors: Vec<crate::analysis_native::volume_anchor::VolumeAnchor>,
        refresh_paths: Option<Vec<String>>,
    ) -> std::io::Result<()> {
        (|| {
            let mut cached = self.relation_cache();
            let mut previous: HashSet<_> = cached.anchors.iter()
                .filter(|(_, a)| a.needs_password && a.rar5_encryption.is_some())
                .map(|(path, _)| path.clone()).collect();
            cached.anchors.extend(anchors.into_iter().map(|a| (path_key(&a.path), a)));
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
            let selected = self
                .targets
                .as_ref()
                .and_then(|targets| targets.select(filtered));
            let groups = self.relation_groups(
                raw,
                filtered,
                selected.as_ref(),
                Some(&cached),
            );
            for group in &groups {
                let data = group.candidate_data();
                for path in data.parts().chain([data.entry_path]) {
                    previous.remove(&path_key(path));
                }
            }
            // A recovered continuation is not a standalone task, but still
            // nominates same-stem opaque carriers when the head is embedded.
            for &row in raw.rows.iter() {
                if previous.is_empty() { break; }
                let key = path_key(&raw.table.paths[row]);
                if previous.remove(&key) && cached.anchors.get(&key).is_some_and(|a|
                    a.multivolume && !a.needs_password && !a.is_volume_entry()) {
                    self.volume_seeds.push((Arc::clone(&raw.table), row, cached.anchors.remove(&key).unwrap()));
                }
            }
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
        })();
        Ok(())
    }

    pub(crate) fn dedupe(&mut self) {
        let mut positions: HashMap<String, usize> = HashMap::new();
        let mut unique_len = 0;
        for index in 0..self.rows.len() {
            let key = match &self.rows[index] {
                Candidate::File(table, index) => path_key(&table.paths[*index]),
                Candidate::Relation(group) => {
                    let data = group.candidate_data();
                    // Encryption-header partitions already have a stable
                    // representative. A filename-family key would erase an
                    // independent encrypted set sharing the same display name.
                    if data.is_split && group.entry_anchor()
                        .is_none_or(|a| a.rar5_encryption.is_none()) {
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
                    }
                }
            };
            match positions.entry(key) {
                Entry::Occupied(existing) => {
                    let position = *existing.get();
                    if candidate_rank(&self.rows[index]) > candidate_rank(&self.rows[position]) {
                        self.rows.swap(position, index);
                    }
                }
                Entry::Vacant(slot) => {
                    slot.insert(unique_len);
                    if unique_len != index {
                        self.rows.swap(unique_len, index);
                    }
                    unique_len += 1;
                }
            }
        }
        self.rows.truncate(unique_len);
    }

    pub(crate) fn project(&self, index: usize) -> io::Result<CandidateProjection<'_>> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| io::Error::other(index.to_string()))?;
        Ok(match row {
            Candidate::File(table, index) => {
                let path = &table.paths[*index];
                let fact = table.relation_anchors[*index].as_ref();
                CandidateProjection::File {
                    path,
                    format_hint: fact
                        .and_then(CheapAnchor::anchor)
                        .map_or("", |anchor| anchor.format),
                    logical_name: filesystem_logical_name(path),
                }
            }
            Candidate::Relation(group) => {
                CandidateProjection::Relation { relation: group.project() }
            }
        })
    }

    pub(crate) fn summary(&self, index: usize) -> std::io::Result<(String, String)> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| std::io::Error::other(index.to_string()))?;
        Ok(match row {
            Candidate::File(table, index) => (
                table.paths[*index].clone(),
                table.relation_anchors[*index]
                    .as_ref()
                    .and_then(CheapAnchor::anchor)
                    .map_or("", |anchor| anchor.format)
                    .to_owned(),
            ),
            Candidate::Relation(group) => {
                let data = group.candidate_data();
                (data.entry_path.to_owned(), data.format_hint.to_owned())
            }
        })
    }

    pub(crate) fn path_keys(&self, index: usize) -> std::io::Result<Vec<String>> {
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| std::io::Error::other(index.to_string()))?;
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

    pub(crate) fn resolve(&self) -> std::io::Result<NativeDiscoveryRoutes> {
        let cancellation = crate::io::cancellation::Cancellation::current();
        cancellation.check()?;
        let mut routes = NativeDiscoveryRoutes::default();
        let mut claimed: HashSet<String> = HashSet::new();
        let mut speculative = HashSet::new();
        let mut blocked: HashSet<String> = HashSet::new();
        let mut relation_residual = Vec::new();
        let mut detection_residual = Vec::new();
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
                routes.relation_events.push((index, 1));
            } else {
                relation_residual.push(index);
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
        (|| {
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
                            let format = anchor.map(|anchor| anchor.format).unwrap_or("");
                            let accepted = matches!(
                                format,
                                "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "enc"
                            ) && anchor.is_some_and(|anchor| anchor.standalone);
                            // The confirmed leading structure admits the whole
                            // file. LZ4 additionally projects its frame plan.
                            let scan = if accepted && format == "lz4" {
                                Some(
                                    scan_detected_lz4(path, parallel_files)
                                        .map(Arc::new)
                                        .map_err(Arc::new),
                                )
                            } else {
                                None
                            };
                            let accepted = accepted
                                && (format != "lz4"
                                    || scan
                                        .as_ref()
                                        .and_then(|scan| scan.as_ref().ok())
                                        .is_some_and(|scan| scan.is_primary_lz4()));
                            Some((index, key, accepted, scan))
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
                        routes.detection_events.push((index, 1));
                    } else {
                        detection_residual.push(index);
                    }
                }
            }
        })();
        cancellation.check()?;
        // Preserve the former stage order: filesystem residuals, Relations
        // residuals, then Detection residuals.
        let has_path_constraints =
            !claimed.is_empty() || !blocked.is_empty() || !speculative.is_empty();
        for (index, row) in self.rows.iter().enumerate() {
            if let Candidate::File(table, file_index) = row {
                let residual = table.file_routes[*file_index] == FILE_ROUTE_RESIDUAL;
                if !has_path_constraints {
                    if residual {
                        routes.embedded.push(index);
                    }
                    continue;
                }
                if !residual && speculative.is_empty() {
                    continue;
                }
                let key = path_key(&table.paths[*file_index]);
                if speculative.contains(&key)
                    || (residual && !claimed.contains(&key) && !blocked.contains(&key))
                {
                    routes.embedded.push(index);
                }
            }
        }
        for index in relation_residual {
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
        for index in detection_residual {
            if let Candidate::File(table, file_index) = &self.rows[index] {
                let key = path_key(&table.paths[*file_index]);
                if !speculative.contains(&key) && !claimed.contains(&key) && !blocked.contains(&key)
                {
                    routes.embedded.push(index);
                }
            }
        }
        Ok(routes)
    }

    /// Finish primary projection before calling: only embedded/relation rows survive.
    pub(crate) fn prepare_embedded(
        &mut self,
        routes: &mut NativeDiscoveryRoutes,
        recursive: bool,
        force_scan: bool,
        enabled: bool,
        recursive_ratio: f64,
    ) -> NativeEmbeddedBatch {
        let mut ids = std::mem::take(&mut routes.embedded);
        let ratio = recursive_ratio.clamp(0.0, 1.0);
        let select_all = enabled && (force_scan || !recursive);
        if !select_all {
            let mut threshold = 0.0;
            let mut sizes = Vec::new();
            if enabled && ratio > 0.0 {
                sizes.reserve_exact(ids.len());
                let mut total = 0.0;
                for &index in &ids {
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
                    }
                    .unwrap_or(0);
                    sizes.push(size);
                    total += size as f64;
                }
                threshold = total * ratio;
            }
            // Sizes follow the candidate order, so selection needs no hash set.
            // Keep observed errors even when policy disables new I/O.
            let mut sizes = sizes.into_iter();
            ids.retain(|index| {
                let size = sizes.next().unwrap_or(0);
                (size > 0 && size as f64 >= threshold)
                    || matches!(routes.scans.get(index), Some(Err(_)))
            });
        }
        if ids.is_empty() && self.volume_seeds.is_empty() {
            // This root has no remaining I/O or cached errors. Its primary
            // decisions are already owned by the caller; no recovery can use it.
            *self = Self::default();
            routes.scans = HashMap::new();
            return NativeEmbeddedBatch::default();
        }
        let mut excluded: HashSet<_> = routes.resolved_relations().filter(|&index| {
            !matches!(&self.rows[index], Candidate::Relation(group) if group.is_incomplete())
        }).chain(routes.detection_events.iter().map(|&(index, _)| index))
            .flat_map(|index| self.path_keys(index).unwrap_or_default()).collect();
        // Keep only the evidence used by volume recovery, not resolved groups
        // and their execution metadata from every root. Raw snapshots still
        // supply all eligible peers; primary decisions have been projected.
        let relation_cache = self.relation_cache();
        let mut claimed_ranges = HashMap::new();
        let mut scanned_paths = None;
        let mut seen_facts = HashSet::new();
        for index in routes.resolved_relations() {
            if let Candidate::Relation(group) = &self.rows[index] {
                let scanned_paths = scanned_paths.get_or_insert_with(|| {
                    ids.iter()
                        .map(|&index| path_key(self.rows[index].embedded_source().0))
                        .collect()
                });
                group.collect_source_ranges(scanned_paths, &mut claimed_ranges, &mut seen_facts);
                // Candidate membership is a lease, not exclusive ownership.
                // Independent heads may need the same peer domains.
                // The confirmed head is not an alternative peer. A genuinely
                // new slice in that carrier re-enters via anchor_paths above.
                let head = group.entry_path();
                for path in group.speculative_paths().filter(|path| *path != head) {
                    excluded.remove(&path_key(path));
                }
            }
        }
        let mut prepass = std::mem::take(&mut routes.scans);
        let scans = if ids.len() == self.rows.len() {
            // A full deep scan already uses every row; do not duplicate its
            // candidate storage or prepass map merely to reproduce the same indices.
            prepass
        } else {
            let mut scans = HashMap::new();
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
                    if let Some(scan) = prepass.remove(&index) {
                        scans.insert(remapped, scan);
                    }
                    rows.push(row);
                }
            }
            self.rows = rows;
            scans
        };
        let mut pending_volumes = Vec::with_capacity(self.volume_seeds.len());
        for (facts, row, anchor) in std::mem::take(&mut self.volume_seeds) {
            let index = self.rows.len();
            self.rows.push(Candidate::File(facts, row));
            pending_volumes.push(PendingEmbeddedVolume { index, anchor, scan: None });
        }
        let mut batch = NativeEmbeddedBatch {
            relation_cache,
            pending_volumes,
            excluded,
            claimed_ranges,
            supplemental: HashSet::new(),
            scans,
            ids,
            cursor: 0,
            nominated: 0,
            peer_rows: None,
            seen_paths: HashSet::new(),
            force_scan,
        };
        if enabled && (select_all || ratio > 0.0) {
            batch.enqueue_volume_peers(self);
        }
        batch
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
    #[cfg(test)]
    peer_scan_tests::record_scan(path);
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

#[cfg(test)]
mod peer_scan_tests {
    use super::*;
    use crate::analysis_native::volume_anchor::VolumeAnchor;
    use crate::scan::directory::DirectoryEntryRecord;

    static SCANS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, usize>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

    pub(super) fn record_scan(path: &str) {
        if let Some(count) = SCANS.lock().unwrap().get_mut(path) { *count += 1; }
    }

    #[test]
    fn targeted_volume_peer_scan_reuses_known_facts_and_ignores_other_stems() {
        let head = crate::test_support::temp_file("volume_peers", b"ordinary bytes");
        let peer = head.with_extension("peer");
        let peers: Vec<_> = std::iter::once(peer.clone())
            .chain((1..257).map(|index| head.with_extension(format!("peer-{index}")))).collect();
        for peer in &peers { std::fs::write(peer, b"ordinary peer bytes").unwrap(); }
        let paths: Vec<_> = [head.clone(), peer.clone(), head.with_extension("cheap"),
            head.with_extension("cached"), head.with_extension("excluded")]
            .into_iter().map(|path| path.to_string_lossy().into_owned()).collect();
        let anchor = VolumeAnchor { path: paths[0].clone(), multivolume: true, ..Default::default() };
        let mut records: Vec<_> = paths.iter().map(|path| DirectoryEntryRecord {
            path: path.clone(), relation_member_eligible: true, ..Default::default()
        }).collect();
        records[2].relation_anchor = Some(CheapAnchor::Full(Arc::new(VolumeAnchor {
            path: paths[2].clone(), multivolume: true, ..Default::default()
        })));
        records.extend(peers.iter().skip(1).map(|path| DirectoryEntryRecord {
            path: path.to_string_lossy().into_owned(), relation_member_eligible: true, ..Default::default()
        }));
        records.extend((0..10_000).map(|index| DirectoryEntryRecord {
            path: format!("unrelated-{index}.bin"), relation_member_eligible: true, ..Default::default()
        }));
        let source = Arc::new(NativeDirectorySnapshot::build_table(records));
        let snapshot = NativeDirectorySnapshot { rows: Arc::new((0..source.paths.len()).collect()), table: Arc::clone(&source) };
        let other_path = head.parent().unwrap().join("other-scope").join(head.file_name().unwrap()).to_string_lossy().into_owned();
        let other_table = Arc::new(NativeDirectorySnapshot::build_table(vec![DirectoryEntryRecord {
            path: other_path.clone(), relation_member_eligible: true, ..Default::default()
        }]));
        let other = NativeDirectorySnapshot { rows: Arc::new(vec![0]), table: other_table };
        let mut table = NativeCandidateTable {
            rows: vec![Candidate::File(Arc::clone(&source), 0)],
            relation_sources: vec![snapshot, other], ..Default::default()
        };
        let mut batch = NativeEmbeddedBatch::default();
        batch.pending_volumes.push(PendingEmbeddedVolume { index: 0, anchor: anchor.clone(), scan: None });
        batch.relation_cache.anchors.insert(path_key(&paths[3]), anchor.clone());
        batch.excluded.insert(path_key(&paths[4]));
        {
            let mut scans = SCANS.lock().unwrap();
            scans.extend(source.paths.iter().cloned().map(|path| (path, 0)));
            scans.insert(other_path.clone(), 0);
        }
        NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
        assert_eq!(batch.supplemental.len(), 257);
        assert_eq!(batch.len(), 1);
        // Only the unselected same-stem source remains indexed; 10,000 other
        // stems never allocate persistent buckets, and this scope cannot scan it.
        assert_eq!(batch.peer_rows.as_ref().unwrap().len(), 1);
        assert_eq!(table.rows[1].embedded_source().0, paths[1]);
        // Re-entering this request reuses its rows, without a second peer job.
        NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
        assert_eq!(table.rows.len(), 258);
        assert_eq!(batch.len(), 0);
        NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
        assert!(table.rows.iter().all(|row| matches!(row, Candidate::File(facts, _) if Arc::ptr_eq(facts, &source))));
        {
            let scans = SCANS.lock().unwrap();
            for peer in &peers { assert_eq!(scans.get(peer.to_string_lossy().as_ref()), Some(&1)); }
            assert_eq!(scans.get(&other_path), Some(&0));
            for path in [&paths[0], &paths[2], &paths[3], &paths[4]] {
                assert_eq!(scans.get(path), Some(&0));
            }
            assert!((0..10_000).all(|index| scans.get(&format!("unrelated-{index}.bin")) == Some(&0)));
        }
        // A directory pass has already scanned all these physical rows.
        table.rows = (0..source.paths.len()).map(|row| Candidate::File(Arc::clone(&source), row)).collect();
        batch.supplemental.clear();
        batch.nominated = 0;
        batch.peer_rows = None;
        batch.seen_paths.clear();
        NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
        assert!(batch.supplemental.is_empty());
        {
            let mut scans = SCANS.lock().unwrap();
            assert_eq!(scans.get(&paths[1]), Some(&1));
            for path in &source.paths { scans.remove(path); }
            scans.remove(&other_path);
        }
        std::fs::remove_file(head).unwrap();
        for peer in peers { std::fs::remove_file(peer).unwrap(); }
    }
}
