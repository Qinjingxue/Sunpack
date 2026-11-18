use crate::analysis_native::volume_anchor::{
    CheapAnchor, EMBEDDED_VOLUME, RAR_PASSWORD_MATCHED_INCOMPLETE, SEVEN_ZIP_CARRIER_INTERRUPTED,
};
use crate::path_keys::{case_key, path_key};
use crate::relations::{
    build_native_candidate_groups_from_snapshot, collect_relation_cache, resolve_embedded_volumes,
    NativeRelationGroup, RelationCache, RelationProjection,
};
use crate::scan::catalog::catalog_stem;
use crate::scan::directory::{
    filesystem_logical_name, DirectorySnapshotTable,
    NativeDirectorySnapshot, FILE_ROUTE_DETECTION, FILE_ROUTE_RELATIONS, FILE_ROUTE_RESIDUAL,
};
use crate::scan::embedded::{
    scan_embedded_path, NativeScanResult, RarInputResolution,
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
    pub(crate) result: Result<Arc<NativeScanResult>, Arc<io::Error>>,
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
    fn path(&self) -> &str {
        match self {
            Self::File(table, row) => &table.paths[*row],
            Self::Relation(group) => group.entry_path(),
        }
    }

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
    // Decrypted continuations may outlive their headless proposal. Transfer
    // their existing facts to the same embedded peer frontier, without I/O.
    volume_seeds: Vec<(Arc<DirectorySnapshotTable>, usize, crate::analysis_native::volume_anchor::VolumeAnchor)>,
    volume_entry_peers: Vec<(Arc<DirectorySnapshotTable>, usize)>,
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
                if let Some((key, _)) = self.names_by_path.get_key_value(&key) {
                    physical_matches.insert(key.as_str());
                    true
                } else {
                    false
                }
            };
            let contains = match row {
                Candidate::File(table, index) => matches(&table.paths[*index]),
                Candidate::Relation(group) => {
                    let mut contains = false;
                    for path in group.related_paths() {
                        contains |= matches(path);
                    }
                    contains
                }
            };
            matched.push(contains);
        }
        if physical_matches.len() == self.names_by_path.len() {
            let mut selected = matched.into_iter();
            rows.retain(|_| selected.next().unwrap());
            return;
        }
        let expected: HashSet<&str> = self
            .names_by_path
            .iter()
            .filter(|(path, _)| !physical_matches.contains(path.as_str()))
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
                .filter(|&&row| targeted.table.file_route(row) == FILE_ROUTE_RELATIONS)
                .map(|&row| path_key(&targeted.table.paths[row]))
                .collect();
            groups.retain(|group| match group {
                NativeRelationGroup::Ordinary(row, _) => routed.contains(&row.path_key),
                _ => true,
            });
        }
        groups
    }

}

#[derive(Default)]
pub(crate) struct NativeDiscoveryRoutes {
    pub(crate) relations: Vec<(usize, bool)>,
    pub(crate) detected: Vec<usize>,
    embedded: Vec<usize>,
}

impl NativeDiscoveryRoutes {
    pub(crate) fn resolved_relations(&self) -> impl Iterator<Item = usize> + '_ {
        self.relations
            .iter()
            .filter_map(|&(index, confirmed)| confirmed.then_some(index))
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
    fn claims_offset(&self, key: &str, offset: u64) -> bool {
        self.claimed_ranges.get(key).is_some_and(|ranges| {
            let preceding = ranges.partition_point(|&(start, _)| start <= offset);
            preceding != 0 && offset < ranges[preceding - 1].1
        })
    }

    fn project_outcomes(
        &mut self,

        table: &NativeCandidateTable,
        outcomes: impl Iterator<Item = (usize, EmbeddedOutcome)>,
    ) -> Vec<EmbeddedPageRow> {
        let mut projected = Vec::new();
        for (index, outcome) in outcomes {
            let result = match outcome {
                EmbeddedOutcome::Residual => {
                    unreachable!("residuals are filtered before projection")
                }
                EmbeddedOutcome::Failed(error) => Err(error),
                EmbeddedOutcome::Scan(scan) => {
                    let path = table.rows[index].path();
                    let key = path_key(path);
                    let mut anchors = scan.relation_anchors();
                    let has_claims = self.claimed_ranges.contains_key(&key);
                    let independent = (has_claims || !anchors.is_empty()) && scan.has_independent_archive();
                    if has_claims {
                        // Only proven extents (or the identical known anchor)
                        // exclude another head; an opaque chunk's EOF does not.
                        // Independent encrypted archives still use the normal
                        // boundary/password resolution before projection.
                        anchors.retain(|a| {
                            a.standalone
                                || (!a.multivolume && a.needs_password)
                                || !self.claims_offset(&key, a.structure_offset.unwrap_or(0))
                        });
                        if anchors.is_empty() && !independent {
                            continue;
                        }
                    }
                    if !anchors.is_empty() {
                        for mut anchor in anchors {
                            anchor.path = path.to_owned();
                            let retain_scan = anchor.needs_password || independent;
                            self.pending_volumes.push(PendingEmbeddedVolume {
                                index,
                                anchor,
                                scan: retain_scan.then(|| Arc::clone(&scan)),
                            });
                        }
                        continue;
                    }
                    // A complete peer archive keeps its original ownership.
                    table.extend_path_keys(index, &mut self.excluded);
                    Ok(scan)
                }
            };
            // Supplemental rows supply relation facts for the original targets.
            if !self.supplemental.contains(&index) {
                projected.push(EmbeddedPageRow { index, result });
            }
        }
        projected
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
                !path.is_empty() && (batch.force_scan || pe != Some(PeState::Confirmed))
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
                        let outcome =
                            scan_embedded_candidate(path, batch.force_scan, pe, parallel_files);
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

impl NativeEmbeddedBatch {
    pub(crate) fn len(&self) -> usize {
        self.ids.len() - self.cursor
    }

    /// Process selected jobs across roots.
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
        // Results follow job order, where each group's rows are contiguous.
        let mut outcomes = outcomes.into_iter().peekable();
        let mut projected = Vec::new();
        for (group, (table, batch)) in groups.into_iter().enumerate() {
            if outcomes.peek().is_some_and(|(selected, _, _)| *selected == group) {
                let ready = std::iter::from_fn(|| {
                    outcomes.next_if(|(selected, _, _)| *selected == group)
                })
                .map(|(_, index, outcome)| (index, outcome));
                let rows = batch.project_outcomes(table, ready);
                batch.enqueue_volume_peers(table);
                if !rows.is_empty() {
                    projected.push((group, rows));
                }
            }
            if batch.len() == 0 {
                // All eligible peers have been enqueued, including any added
                // by this page. Other scopes may still have many pages to scan.
                batch.ids = Vec::new();
                batch.cursor = 0;
                batch.peer_rows = None;
                batch.seen_paths = HashSet::new();
            }
        }
        debug_assert!(outcomes.next().is_none());
        Ok(projected)
    }

    // Volume evidence extends the same physical discovery frontier. Index raw
    // row references only when needed, then consume each source/stem once.
    fn enqueue_volume_peers(&mut self, table: &mut NativeCandidateTable) {
        let mut selected = HashSet::new();
        let mut relations = HashMap::new();
        for item in &self.pending_volumes[self.nominated..] {
            if !item.anchor.multivolume && !item.anchor.needs_password {
                continue;
            }
            let stem = catalog_stem(&item.anchor.path);
            match &table.rows[item.index] {
                Candidate::File(facts, row) => {
                    for (source, snapshot) in table.relation_sources.iter().enumerate() {
                        // Only raw snapshots are kept in relation_sources.
                        // Their scope views preserve the original row order.
                        if Arc::ptr_eq(facts, &snapshot.table)
                            && (snapshot.rows.len() == snapshot.table.paths.len()
                                || snapshot.rows.binary_search(row).is_ok())
                        {
                            selected.insert((source, stem.clone()));
                        }
                    }
                }
                Candidate::Relation(_) => {
                    relations.insert(path_key(&item.anchor.path), stem);
                }
            }
        }
        if !relations.is_empty() {
            // Several relation anchors can come from one carrier or one page.
            // Test their membership together, even when source views overlap.
            let mut matched = HashSet::new();
            for (source, snapshot) in table.relation_sources.iter().enumerate() {
                matched.clear();
                for &row in snapshot.rows.iter() {
                    let key = path_key(&snapshot.table.paths[row]);
                    if let Some((key, stem)) = relations.get_key_value(&key) {
                        if matched.insert(key) {
                            selected.insert((source, stem.clone()));
                        }
                        if matched.len() == relations.len() {
                            break;
                        }
                    }
                }
            }
        }
        self.nominated = self.pending_volumes.len();
        if selected.is_empty() { return; }
        let index = self.peer_rows.get_or_insert_with(|| {
            self.seen_paths.extend(table.rows.iter().map(|row| path_key(row.path())));
            let mut index: HashMap<(usize, String), Vec<usize>> = HashMap::new();
            // Original candidates already bound every stem this frontier can
            // nominate; appended peers cannot introduce another filename stem.
            // Build this set only if a raw unknown peer actually exists.
            let mut candidate_stems = None;
            for (source, snapshot) in table.relation_sources.iter().enumerate() {
                for &row in snapshot.rows.iter() {
                    if snapshot.table.is_dir(row) || !snapshot.table.relation_member_eligible(row)
                        || (!self.force_scan && snapshot.table.relation_anchors[row].as_ref().and_then(CheapAnchor::anchor).is_some()) {
                        continue;
                    }
                    let path = &snapshot.table.paths[row];
                    let key = path_key(path);
                    if self.seen_paths.contains(&key) || self.excluded.contains(&key)
                        || self.relation_cache.anchors.contains_key(&key) { continue; }
                    let stems = candidate_stems.get_or_insert_with(|| table.rows.iter()
                        .map(|row| catalog_stem(row.path()))
                        .collect::<HashSet<_>>());
                    let stem = catalog_stem(path);
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

    fn encrypted_volume_paths<'a>(&'a self, table: &'a NativeCandidateTable) -> HashSet<&'a str> {
        let mut requests: HashSet<_> = self
            .pending_volumes
            .iter()
            .filter(|pending| pending.anchor.needs_password)
            .map(|pending| pending.anchor.path.as_str())
            .collect();
        if requests.is_empty() {
            return requests;
        }
        let selected: HashSet<_> = requests.iter().map(|path| path_key(path)).collect();
        let cache = &self.relation_cache;
        for snapshot in &table.relation_sources {
            let stems: HashSet<_> = snapshot
                .rows
                .iter()
                .filter_map(|&row| {
                    let path = &snapshot.table.paths[row];
                    selected.contains(&path_key(path)).then(|| catalog_stem(path))
                })
                .collect();
            if stems.is_empty() {
                continue;
            }
            for &row in snapshot.rows.iter() {
                if !snapshot.table.relation_member_eligible(row) {
                    continue;
                }
                let direct = snapshot.table.relation_anchors[row]
                    .as_ref()
                    .and_then(CheapAnchor::anchor);
                if cache.anchors.is_empty() && !direct.is_some_and(|anchor| anchor.needs_password) {
                    continue;
                }
                let path = &snapshot.table.paths[row];
                let key = path_key(path);
                if self.excluded.contains(&key) {
                    continue;
                }
                if !stems.contains(&catalog_stem(path)) {
                    continue;
                }
                let anchor = cache.anchors.get(&key).or(direct);
                if anchor.is_some_and(|a| a.needs_password) {
                    requests.insert(path.as_str());
                }
            }
        }
        requests
    }

    /// One directed Relations call per source scope, using native scan facts.
    /// Status 0 returns standalone/sibling scan facts to Embedded.
    pub(crate) fn resolve_volumes(
        &mut self,
        table: &mut NativeCandidateTable,
        mut passwords: impl FnMut(&str) -> Vec<Arc<str>>,
    ) -> io::Result<Vec<EmbeddedVolumeOutcome>> {
        use crate::analysis_native::volume_anchor::resolve_encrypted_relation_anchor;
        let mut batch = std::mem::take(self);
        if batch.pending_volumes.is_empty() {
            return Ok(Vec::new());
        }
        let candidates: HashMap<_, _> = batch.encrypted_volume_paths(table)
            .into_iter()
            .map(|path| (path_key(path), passwords(path)))
            .collect();
        let mut cache = std::mem::take(&mut batch.relation_cache);
        let mut pending = std::mem::take(&mut batch.pending_volumes);
        let pending_keys: HashSet<_> = pending
            .iter()
            .map(|item| path_key(&item.anchor.path))
            .collect();
        // Pending anchors and overrides already own their facts. Only look
        // through raw rows for peer anchors that still need to be imported.
        let mut external: HashSet<&str> = candidates.keys()
            .filter(|key| !pending_keys.contains(*key) && !cache.anchors.contains_key(*key))
            .map(String::as_str)
            .collect();
        'sources: for snapshot in &table.relation_sources {
            if external.is_empty() {
                break;
            }
            for &row in snapshot.rows.iter() {
                let Some(anchor) = snapshot.table.relation_anchors[row]
                    .as_ref()
                    .and_then(CheapAnchor::anchor) else { continue; };
                let key = path_key(&snapshot.table.paths[row]);
                if external.remove(key.as_str()) {
                    cache.anchors.insert(key, anchor.clone());
                    if external.is_empty() {
                        break 'sources;
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
                            resolve_encrypted_relation_anchor(anchor, &reader, values, true, None)?;
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
        let speculative = |group: &NativeRelationGroup| {
            !group.relation_confirmed()
                && group
                    .entry_anchor()
                    .is_some_and(|a| a.has_any(SEVEN_ZIP_CARRIER_INTERRUPTED))
        };
        let mut peers: HashMap<String, HashSet<String>> = groups
            .iter()
            .filter(|g| speculative(g))
            .map(|g| (catalog_stem(g.entry_path()), HashSet::new()))
            .collect();
        if !peers.is_empty() {
            for snapshot in sources {
                for &row in snapshot.rows.iter() {
                    if !snapshot.table.relation_member_eligible(row) {
                        continue;
                    }
                    let path = &snapshot.table.paths[row];
                    if let Some(paths) = peers.get_mut(&catalog_stem(path)) {
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
                        .get(&catalog_stem(g.entry_path()))
                        .is_some_and(|p| p.len() > 1)
            });
        }
        if !batch.supplemental.is_empty() {
            // Ownership is physical: a related carrier may also hold a second
            // split head. Keep its connected groups before cleanup can own the
            // carrier, without promoting unrelated same-stem archives.
            let requested: HashSet<_> = table.rows.iter().enumerate()
                .filter(|(index, _)| !batch.supplemental.contains(index))
                .map(|(_, row)| path_key(row.path())).collect();
            let mut by_path: HashMap<String, Vec<usize>> = HashMap::new();
            let mut keep = vec![false; groups.len()];
            let mut work = Vec::new();
            for (index, group) in groups.iter().enumerate() {
                for path in group.related_paths() {
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
                for path in groups[index].related_paths() {
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
                || owned.contains(&path_key(table.rows[row.index].path())));
        }
        let mut grouped_ranges = HashMap::new();
        let mut seen_facts = HashSet::new();
        for group in groups.iter().filter(|group| group.unresolved_password_group()) {
            group.collect_source_ranges(&anchor_paths, &mut grouped_ranges, &mut seen_facts);
        }
        for ranges in grouped_ranges.values_mut() {
            ranges.sort_unstable();
        }
        for row in &mut fallback {
            if let Some(scan) = &mut row.scan {
                let key = path_key(table.rows[row.index].path());
                if let Some(ranges) = grouped_ranges.get(&key) {
                    scan.resolutions.retain(|offset, _| {
                        ranges.binary_search_by_key(offset, |(start, _)| *start).is_err()
                    });
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
    pub(crate) fn extend(&mut self, other: &mut Self) {
        self.rows.append(&mut other.rows);
        self.relation_sources.append(&mut other.relation_sources);
        self.volume_seeds.append(&mut other.volume_seeds);
        self.volume_entry_peers.append(&mut other.volume_entry_peers);
    }

    pub(crate) fn from_directory(
        raw: &NativeDirectorySnapshot,
        filtered: &NativeDirectorySnapshot,
        targets: Option<&FileTargets>,
        deep: bool,
    ) -> Self {
        debug_assert!(raw.rows.windows(2).all(|pair| pair[0] < pair[1]));
        let mut table = Self::default();
        let selected = targets.and_then(|targets| targets.select(filtered));
        let groups = if deep { Vec::new() } else {
            table.relation_groups(raw, filtered, selected.as_ref(), None)
        };
        // Embedded is the only producer in deep mode. Keep raw peers for
        // directed volume recovery on both discovery paths.
        let selected = selected.as_ref().unwrap_or(filtered);
        table.rows.reserve_exact(groups.len() + selected.rows.len());
        table.rows.extend(groups.into_iter().map(|group| Candidate::Relation(Box::new(group))));
        table.rows.extend(selected.rows.iter().copied()
            .filter(|&row| !selected.table.is_dir(row)
                && (deep || selected.table.file_route(row) != FILE_ROUTE_RELATIONS))
            .map(|row| Candidate::File(Arc::clone(&selected.table), row)));
        if let Some(targets) = targets {
            targets.retain(&mut table.rows);
            if deep {
                table.find_volume_entry_peers(filtered, targets);
            }
        }
        if !deep {
            table.append_speculative_files(raw);
        }
        table.relation_sources.push(raw.share_rows());
        table
    }

    // An explicitly selected raw continuation may have no signature. Use
    // existing split-entry evidence to open the same Embedded peer frontier
    // from the other end, within this target's original scope.
    fn find_volume_entry_peers(&mut self, filtered: &NativeDirectorySnapshot, targets: &FileTargets) {
        if self.rows.is_empty() || self.rows.len() >= filtered.rows.len() {
            return;
        }
        let facts = &filtered.table;
        let mut stems = None;
        for &row in filtered.rows.iter() {
            if !facts.relation_anchors[row].as_ref().and_then(CheapAnchor::anchor)
                .is_some_and(|anchor| anchor.multivolume && anchor.is_volume_entry())
            {
                continue;
            }
            let path = &facts.paths[row];
            if targets.names_by_path.contains_key(&path_key(path)) {
                continue;
            }
            let stems = stems.get_or_insert_with(|| self.rows.iter().filter_map(|candidate| {
                let Candidate::File(facts, row) = candidate else { return None; };
                facts.relation_anchors[*row].as_ref().and_then(CheapAnchor::anchor).is_none()
                    .then(|| catalog_stem(candidate.path()))
            }).collect::<HashSet<_>>());
            if stems.contains(&catalog_stem(path)) {
                self.volume_entry_peers.push((Arc::clone(facts), row));
            }
        }
    }

    /// Decrypt only nominated RAR families. Until the hidden main header is
    /// read, an encrypted RAR5 file can be either the entry or a continuation.
    /// Keep the resulting byte facts in the same request-local relation cache.
    pub(crate) fn encrypted_rar_anchors(&self) -> Vec<crate::analysis_native::volume_anchor::VolumeAnchor> {
        let stems: HashSet<_> = self.rows.iter().filter_map(|row| match row {
            Candidate::Relation(group) => group.entry_anchor()
                .filter(|a| a.format == "rar" && a.needs_password && !a.standalone)
                .map(|a| catalog_stem(&a.path)),
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
                if !snapshot.table.relation_member_eligible(row) { continue; }
                let Some(anchor) = snapshot.table.relation_anchors[row].as_ref()
                    .and_then(CheapAnchor::anchor)
                    .filter(|a| a.format == "rar" && a.needs_password)
                    .filter(|a| stems.contains(&catalog_stem(&a.path))) else { continue; };
                anchors.entry(path_key(&anchor.path)).or_insert_with(|| anchor.clone());
            }
        }
        anchors.into_values().collect()
    }

    /// Replace the relation evidence for one table after a password is found.
    pub(crate) fn retry_relations(
        &mut self,
        raw_snapshot: &NativeDirectorySnapshot,
        filtered_snapshot: &NativeDirectorySnapshot,
        targets: Option<&FileTargets>,
        anchors: Vec<crate::analysis_native::volume_anchor::VolumeAnchor>,
        refresh_paths: Vec<String>,
    ) {
        let mut cached = self.relation_cache();
        let mut previous: HashSet<_> = cached.anchors.iter()
            .filter(|(_, a)| a.needs_password && a.rar5_encryption.is_some())
            .map(|(path, _)| path.clone()).collect();
        cached.anchors.extend(anchors.into_iter().map(|a| (path_key(&a.path), a)));
        // A short password probe may start after another request consumed its
        // inputs. Drop only proven departures from that proposal, sharing the
        // original snapshot and surviving anchors instead of scanning again.
        let departed: HashSet<String> = refresh_paths.into_iter()
            .filter(|path| std::fs::metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound))
            .map(|path| path_key(&path))
            .collect();
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
        let selected = targets.and_then(|targets| targets.select(filtered));
        let groups = self.relation_groups(
            raw,
            filtered,
            selected.as_ref(),
            Some(&cached),
        );
        for group in &groups {
            for path in group.part_paths().chain([group.entry_path()]) {
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
        if let Some(targets) = targets {
            targets.retain(&mut self.rows);
        }
        self.append_speculative_files(raw);
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

    pub(crate) fn summary(&self, index: usize) -> (&str, &str) {
        let row = &self.rows[index];
        let format = match row {
            Candidate::File(table, index) => table.relation_anchors[*index]
                .as_ref()
                .and_then(CheapAnchor::anchor)
                .map_or("", |anchor| anchor.format),
            Candidate::Relation(group) => group.format_hint(),
        };
        (row.path(), format)
    }

    pub(crate) fn extend_path_keys(&self, index: usize, paths: &mut HashSet<String>) {
        match &self.rows[index] {
            Candidate::File(table, index) => {
                paths.insert(path_key(&table.paths[*index]));
            }
            Candidate::Relation(group) => paths.extend(group.related_paths().map(path_key)),
        }
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
                blocked.extend(group.related_paths().map(path_key));
                routes.relations.push((index, false));
            } else if data.relation_confirmed && matches!(data.format_hint, "rar" | "7z" | "zip") {
                claimed.extend(group.owned_paths().map(path_key));
                speculative.extend(
                    group
                        .speculative_paths()
                        .filter(|path| *path != data.entry_path)
                        .map(path_key),
                );
                routes.relations.push((index, true));
            } else {
                relation_residual.push(index);
            }
        }
        // Ordinary detection uses only the leading structure already read by
        // the filesystem probe. Embedded discovery owns carrier boundaries.
        for (index, row) in self.rows.iter().enumerate() {
            let Candidate::File(table, file_index) = row else { continue; };
            if table.file_route(*file_index) != FILE_ROUTE_DETECTION {
                continue;
            }
            cancellation.check()?;
            let accepted = table.relation_anchors[*file_index]
                .as_ref()
                .and_then(CheapAnchor::anchor)
                .is_some_and(|anchor| {
                    anchor.standalone
                        && matches!(anchor.format, "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "enc")
                });
            if accepted {
                let key = path_key(&table.paths[*file_index]);
                if !blocked.contains(&key) && claimed.insert(key) {
                    routes.detected.push(index);
                }
            } else {
                detection_residual.push(index);
            }
        }
        cancellation.check()?;
        // Preserve the former stage order: filesystem residuals, Relations
        // residuals, then Detection residuals.
        let has_path_constraints =
            !claimed.is_empty() || !blocked.is_empty() || !speculative.is_empty();
        for (index, row) in self.rows.iter().enumerate() {
            if let Candidate::File(table, file_index) = row {
                let residual = table.file_route(*file_index) == FILE_ROUTE_RESIDUAL;
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
                if (claimed.is_empty() && blocked.is_empty())
                    || group.related_paths().map(path_key)
                        .all(|key| !claimed.contains(&key) && !blocked.contains(&key))
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

    pub(crate) fn prepare_deep(&mut self, recursive: bool, recursive_ratio: f64) -> NativeEmbeddedBatch {
        if recursive {
            // Deep changes the discovery producer, not the nested scan budget.
            // Reuse selection and row compaction before any full-file I/O.
            let mut routes = NativeDiscoveryRoutes {
                embedded: (0..self.rows.len()).collect(),
                ..NativeDiscoveryRoutes::default()
            };
            let mut batch = self.prepare_embedded(&mut routes, true, true, recursive_ratio);
            batch.force_scan = true;
            return batch;
        }
        let mut batch = NativeEmbeddedBatch {
            ids: (0..self.rows.len()).collect(),
            force_scan: true,
            ..NativeEmbeddedBatch::default()
        };
        if !self.volume_entry_peers.is_empty() {
            let mut seen: HashSet<_> = self.rows.iter().map(|row| path_key(row.path())).collect();
            for (facts, row) in std::mem::take(&mut self.volume_entry_peers) {
                if seen.insert(path_key(&facts.paths[row])) {
                    let index = self.rows.len();
                    self.rows.push(Candidate::File(facts, row));
                    batch.supplemental.insert(index);
                    batch.ids.push(index);
                }
            }
        }
        batch
    }

    /// Finish primary projection before calling: only embedded/relation rows survive.
    pub(crate) fn prepare_embedded(
        &mut self,
        routes: &mut NativeDiscoveryRoutes,
        recursive: bool,
        enabled: bool,
        recursive_ratio: f64,
    ) -> NativeEmbeddedBatch {
        let mut ids = std::mem::take(&mut routes.embedded);
        let scan_candidates = enabled && (!recursive || recursive_ratio < 1.0);
        if !scan_candidates {
            ids.clear();
        } else if recursive && recursive_ratio > 0.0 {
            let mut sizes = Vec::with_capacity(ids.len());
            let mut total = 0.0;
            for &index in &ids {
                let size = match &self.rows[index] {
                    Candidate::File(table, row) => table.sizes[*row],
                    Candidate::Relation(group) => group.logical_size(),
                }
                .unwrap_or(0);
                sizes.push(size);
                total += size as f64;
            }
            let threshold = total * recursive_ratio;
            // Sizes follow the candidate order, so selection needs no hash set.
            let mut sizes = sizes.into_iter();
            ids.retain(|_| {
                let size = sizes.next().unwrap();
                size > 0 && size as f64 >= threshold
            });
        }
        if ids.is_empty() && self.volume_seeds.is_empty() {
            // This root has no remaining I/O. Its primary
            // decisions are already owned by the caller; no recovery can use it.
            *self = Self::default();
            return NativeEmbeddedBatch::default();
        }
        let mut excluded = HashSet::new();
        for index in routes.resolved_relations().filter(|&index| {
            !matches!(&self.rows[index], Candidate::Relation(group) if group.is_incomplete())
        }).chain(routes.detected.iter().copied()) {
            self.extend_path_keys(index, &mut excluded);
        }
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
                        .map(|&index| path_key(self.rows[index].path()))
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
        for ranges in claimed_ranges.values_mut() {
            ranges.sort_unstable();
            // A contained or empty interval cannot extend coverage. Keep
            // increasing ends so the last preceding start answers a lookup.
            let mut end = 0;
            ranges.retain(|&(start, stop)| {
                if stop <= end || stop <= start {
                    return false;
                }
                end = stop;
                true
            });
        }
        if ids.len() != self.rows.len() {
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
                    rows.push(row);
                }
            }
            self.rows = rows;
        }
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
            ids,
            cursor: 0,
            nominated: 0,
            peer_rows: None,
            seen_paths: HashSet::new(),
            force_scan: false,
        };
        if scan_candidates {
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
            let count = data.parts_len();
            (
                if data.is_split && !data.needs_password {
                    2
                } else {
                    1
                },
                if data.is_split { count } else { 0 },
                count,
            )
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/scan/discovery/peer_scan_tests.rs"]
mod peer_scan_tests;
