use crate::analysis_native::confirm_format_identity_native;
use crate::relations::{
    build_native_candidate_groups_from_snapshot,
    build_native_candidate_groups_from_snapshot_cached, relation_group_cached_anchors,
    NativeRelationGroup, RelationCache,
};
use crate::scan::directory::{
    filesystem_logical_name, filesystem_route_name, DirectorySnapshotTable,
    NativeDirectorySnapshot, FILE_ROUTE_DETECTION, FILE_ROUTE_RELATIONS, FILE_ROUTE_RESIDUAL,
};
use crate::scan::embedded::{scan_embedded_path, NativeScanResult};
use pyo3::exceptions::PyIndexError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

enum Candidate {
    File(Arc<DirectorySnapshotTable>, usize),
    // Keep ordinary file rows compact; relation facts live with their candidate.
    Relation(Box<NativeRelationGroup>),
}

#[pyclass(module = "sunpack_native")]
#[derive(Default)]
pub(crate) struct NativeCandidateTable {
    rows: Vec<Candidate>,
}

#[pyclass(module = "sunpack_native")]
#[derive(Default)]
pub(crate) struct NativeDiscoveryRoutes {
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
    Residual(&'static str),
    Scan(NativeScanResult),
}

#[pyclass(module = "sunpack_native")]
pub(crate) struct NativeEmbeddedBatch {
    ids: Vec<usize>,
    selected: HashSet<usize>,
    select_all: bool,
    force_scan: bool,
    include_residual_details: bool,
    skipped_reason: &'static str,
}

#[pymethods]
impl NativeEmbeddedBatch {
    fn __len__(&self) -> usize {
        self.ids.len()
    }

    /// Scan this page against the current files. Repeating a page repeats I/O.
    #[pyo3(signature = (table, offset=0, limit=256))]
    fn scan_page(
        &self,
        py: Python<'_>,
        table: PyRef<'_, NativeCandidateTable>,
        offset: usize,
        limit: usize,
    ) -> PyResult<Vec<(usize, u8, &'static str, Option<Py<PyDict>>)>> {
        let rows = &table.rows;
        let outcomes = py.detach(|| {
            self.ids
                .iter()
                .skip(offset)
                .take(limit)
                .filter_map(|&index| {
                    if !self.select_all && !self.selected.contains(&index) {
                        return self
                            .include_residual_details
                            .then_some((index, EmbeddedOutcome::Residual(self.skipped_reason)));
                    }
                    let path = match &rows[index] {
                        Candidate::File(table, row) => table.paths[*row].as_str(),
                        Candidate::Relation(group) => {
                            let data = group.candidate_data();
                            let outcome = scan_embedded_candidate(data.entry_path, self.force_scan);
                            return (self.include_residual_details
                                || matches!(outcome, EmbeddedOutcome::Scan(_)))
                            .then_some((index, outcome));
                        }
                    };
                    let outcome = scan_embedded_candidate(path, self.force_scan);
                    (self.include_residual_details || matches!(outcome, EmbeddedOutcome::Scan(_)))
                        .then_some((index, outcome))
                })
                .collect::<Vec<_>>()
        });
        outcomes
            .into_iter()
            .map(|(index, outcome)| match outcome {
                EmbeddedOutcome::Residual(reason) => Ok((index, 0, reason, None)),
                EmbeddedOutcome::Scan(scan) => Ok((index, 1, "", Some(scan.to_py_dict(py)?))),
            })
            .collect()
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
        let groups = build_native_candidate_groups_from_snapshot(
            py,
            &raw_snapshot,
            &filtered_snapshot,
            path_passwords.as_deref(),
        )?;
        self.rows.extend(
            groups
                .into_iter()
                .map(|group| Candidate::Relation(Box::new(group))),
        );
        Ok(())
    }

    fn append_directory(
        &mut self,
        py: Python<'_>,
        raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    ) -> PyResult<()> {
        let relation_view = filtered_snapshot.file_route_view(FILE_ROUTE_RELATIONS);
        let groups =
            build_native_candidate_groups_from_snapshot(py, &raw_snapshot, &relation_view, None)?;
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

    /// Replace the relation evidence for one table after a password is found.
    fn retry_relations(
        &mut self,
        py: Python<'_>,
        raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
        path_passwords: Vec<(String, String)>,
    ) -> PyResult<()> {
        let mut cached = RelationCache::default();
        for row in &self.rows {
            if let Candidate::Relation(group) = row {
                relation_group_cached_anchors(group, &mut cached);
            }
        }
        let groups = build_native_candidate_groups_from_snapshot_cached(
            py,
            &raw_snapshot,
            &filtered_snapshot,
            Some(&path_passwords),
            Some(&cached),
        )?;
        self.rows.retain(|row| matches!(row, Candidate::File(..)));
        let mut replacement = Vec::with_capacity(groups.len() + self.rows.len());
        replacement.extend(
            groups
                .into_iter()
                .map(|group| Candidate::Relation(Box::new(group))),
        );
        replacement.append(&mut self.rows);
        self.rows = replacement;
        Ok(())
    }

    fn retain_file_targets(&mut self, targets: Vec<(String, String)>) {
        let selected: HashSet<String> = targets.iter().map(|(path, _)| path_key(path)).collect();
        let mut matched = Vec::with_capacity(self.rows.len());
        let mut physical_matches = HashSet::new();
        for row in &self.rows {
            let contains = match row {
                Candidate::File(table, index) => {
                    let key = path_key(&table.paths[*index]);
                    if selected.contains(&key) {
                        physical_matches.insert(key);
                        true
                    } else {
                        false
                    }
                }
                Candidate::Relation(group) => {
                    let data = group.candidate_data();
                    let contains = data
                        .parts()
                        .chain(data.companions.iter().map(String::as_str))
                        .chain([data.carrier_path, data.entry_path])
                        .filter(|part| {
                            let key = path_key(part);
                            if selected.contains(&key) {
                                physical_matches.insert(key);
                                true
                            } else {
                                false
                            }
                        })
                        .count()
                        > 0;
                    contains
                }
            };
            matched.push(contains);
        }
        let expected: HashSet<String> = targets
            .into_iter()
            .filter(|(path, _)| !physical_matches.contains(&path_key(path)))
            .map(|(_, name)| name.to_lowercase())
            .collect();
        self.rows = self
            .rows
            .drain(..)
            .zip(matched)
            .filter_map(|(row, contains)| {
                let logical_match = matches!(&row, Candidate::Relation(group)
                        if {
                            let data = group.candidate_data();
                            data.is_split
                                && Path::new(data.logical_name().as_ref())
                                    .file_name()
                                    .is_some_and(|name| expected.contains(&name.to_string_lossy().to_lowercase()))
                        });
                (contains || logical_match).then_some(row)
            })
            .collect();
    }

    fn extend(&mut self, other: &mut NativeCandidateTable) {
        self.rows.append(&mut other.rows);
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
                                .join(format!(
                                    "{}\x1f{}",
                                    data.logical_name().to_lowercase(),
                                    family
                                ))
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
                let anchor = table.relation_anchors[*index].as_ref();
                let route = table.file_routes[*index];
                Ok((
                    "file",
                    (
                        path,
                        table.sizes[*index],
                        filesystem_route_name(route),
                        anchor.map(|a| a.format.as_str()).unwrap_or(""),
                        anchor.map(|a| a.format_reject_mask).unwrap_or(0),
                        filesystem_logical_name(path),
                    ),
                )
                    .into_pyobject(py)?
                    .into_any()
                    .unbind())
            }
            Candidate::Relation(group) => Ok(("relation", group.to_dict(py)?)
                .into_pyobject(py)?
                .into_any()
                .unbind()),
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

    #[pyo3(signature = (detection_enabled=true, include_residual_details=true))]
    fn resolve(
        &self,
        py: Python<'_>,
        detection_enabled: bool,
        include_residual_details: bool,
    ) -> PyResult<NativeDiscoveryRoutes> {
        let mut routes = NativeDiscoveryRoutes::default();
        let mut claimed: HashSet<String> = HashSet::new();
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
                routes.relation_resolved.push(index);
                routes.relation_events.push((index, 1));
            } else {
                routes.relation_residual.push(index);
                if include_residual_details {
                    routes.relation_events.push((index, 3));
                }
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
                let decisions = batch
                    .par_iter()
                    .map(|&index| {
                        let Candidate::File(table, file_index) = &self.rows[index] else {
                            return None;
                        };
                        let path = &table.paths[*file_index];
                        let key = path_key(path);
                        if claimed.contains(&key) || blocked.contains(&key) {
                            return None;
                        }
                        let format = table.relation_anchors[*file_index]
                            .as_ref()
                            .map(|anchor| anchor.format.as_str())
                            .unwrap_or("");
                        let accepted = detection_enabled
                            && matches!(format, "tar" | "gzip" | "bzip2" | "xz" | "zstd")
                            && confirm_format_identity_native(path, format);
                        Some((index, key, accepted))
                    })
                    .collect::<Vec<_>>();
                for (index, key, accepted) in decisions.into_iter().flatten() {
                    if claimed.contains(&key) {
                        continue;
                    }
                    if accepted {
                        claimed.insert(key);
                        routes.detection_resolved.push(index);
                        routes.detection_events.push((index, 1));
                    } else {
                        routes.detection_residual.push(index);
                        if include_residual_details {
                            routes.detection_events.push((index, 3));
                        }
                    }
                }
            }
        });
        // Preserve the former stage order: filesystem residuals, Relations
        // residuals, then Detection residuals.
        for (index, row) in self.rows.iter().enumerate() {
            if let Candidate::File(table, file_index) = row {
                if table.file_routes[*file_index] == FILE_ROUTE_RESIDUAL {
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

    #[pyo3(signature = (routes, recursive=false, force_scan=false, enabled=true, recursive_ratio=0.3, include_residual_details=true))]
    fn scan_embedded(
        &self,
        routes: PyRef<'_, NativeDiscoveryRoutes>,
        recursive: bool,
        force_scan: bool,
        enabled: bool,
        recursive_ratio: f64,
        include_residual_details: bool,
    ) -> NativeEmbeddedBatch {
        let ids = routes.embedded.clone();
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
        let skipped_reason = if !enabled {
            "shared_embedded_scan_disabled"
        } else if !select_all && selected.is_empty() {
            "recursive_candidate_ratio_selected_none"
        } else {
            "recursive_candidate_ratio"
        };
        NativeEmbeddedBatch {
            ids,
            selected,
            select_all,
            force_scan,
            include_residual_details,
            skipped_reason,
        }
    }
}

fn scan_embedded_candidate(path: &str, force_scan: bool) -> EmbeddedOutcome {
    if path.is_empty() {
        return EmbeddedOutcome::Residual("missing_or_empty_file");
    }
    if !force_scan && path.to_lowercase().ends_with(".exe") {
        return EmbeddedOutcome::Residual("embedded_executable_skipped");
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return EmbeddedOutcome::Residual("embedded_scan_io_error");
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return EmbeddedOutcome::Residual("missing_or_empty_file");
    }
    match scan_embedded_path(path) {
        Ok(scan) if scan.has_candidates() => EmbeddedOutcome::Scan(scan),
        Ok(_) => EmbeddedOutcome::Residual("no_complete_embedded_archive"),
        Err(_) => EmbeddedOutcome::Residual("embedded_scan_io_error"),
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

fn path_key(path: &str) -> String {
    if path.contains('/') {
        path.replace('/', "\\").to_lowercase()
    } else {
        path.to_lowercase()
    }
}
