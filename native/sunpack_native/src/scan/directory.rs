use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use rayon::prelude::*;
use regex::{RegexSet, RegexSetBuilder};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use crate::analysis_native::volume_anchor::{probe_volume_anchor_paths_cheap, VolumeAnchor};

#[derive(Debug, Clone)]
struct DirectoryEntryRecord {
    path: String,
    is_dir: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
    relation_member_eligible: bool,
    relation_anchor: Option<VolumeAnchor>,
}

#[derive(Debug)]
struct DirectorySnapshotTable {
    paths: Vec<String>,
    is_dirs: Vec<bool>,
    sizes: Vec<Option<u64>>,
    mtimes_ns: Vec<Option<u64>>,
    relation_member_eligible: Vec<bool>,
    relation_anchors: Vec<Option<VolumeAnchor>>,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeDirectorySnapshot {
    table: Arc<DirectorySnapshotTable>,
    rows: Vec<usize>,
}

impl NativeDirectorySnapshot {
    fn from_records(records: Vec<DirectoryEntryRecord>) -> Self {
        let table = Arc::new(Self::build_table(records));
        let rows = (0..table.paths.len()).collect();
        Self { table, rows }
    }

    fn from_views(
        filtered: Vec<DirectoryEntryRecord>,
        raw: Vec<DirectoryEntryRecord>,
    ) -> (Self, Self) {
        let table = Arc::new(Self::build_table(raw));
        let rows_by_path: HashMap<&str, usize> = table
            .paths
            .iter()
            .enumerate()
            .map(|(index, path)| (path.as_str(), index))
            .collect();
        let filtered_rows = filtered
            .iter()
            .filter_map(|record| rows_by_path.get(record.path.as_str()).copied())
            .collect();
        let raw_rows = (0..table.paths.len()).collect();
        (
            Self {
                table: Arc::clone(&table),
                rows: filtered_rows,
            },
            Self {
                table,
                rows: raw_rows,
            },
        )
    }

    fn build_table(records: Vec<DirectoryEntryRecord>) -> DirectorySnapshotTable {
        let mut table = DirectorySnapshotTable {
            paths: Vec::with_capacity(records.len()),
            is_dirs: Vec::with_capacity(records.len()),
            sizes: Vec::with_capacity(records.len()),
            mtimes_ns: Vec::with_capacity(records.len()),
            relation_member_eligible: Vec::with_capacity(records.len()),
            relation_anchors: Vec::with_capacity(records.len()),
        };
        for record in records {
            table.paths.push(record.path);
            table.is_dirs.push(record.is_dir);
            table.sizes.push(record.size);
            table.mtimes_ns.push(record.mtime_ns);
            table
                .relation_member_eligible
                .push(record.relation_member_eligible);
            table.relation_anchors.push(record.relation_anchor);
        }
        table
    }

    pub(crate) fn relation_file_records(
        &self,
    ) -> impl Iterator<Item = (&str, Option<u64>, bool, Option<&VolumeAnchor>)> + '_ {
        self.rows.iter().filter_map(|&row| {
            (!self.table.is_dirs[row]).then_some((
                self.table.paths[row].as_str(),
                self.table.sizes[row],
                self.table.relation_member_eligible[row],
                self.table.relation_anchors[row].as_ref(),
            ))
        })
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = (&str, bool, Option<u64>, Option<u64>)> {
        self.rows.iter().map(|&row| {
            (
                self.table.paths[row].as_str(),
                self.table.is_dirs[row],
                self.table.sizes[row],
                self.table.mtimes_ns[row],
            )
        })
    }
}

struct DirectoryScanRecords {
    filtered: Vec<DirectoryEntryRecord>,
    raw: Vec<DirectoryEntryRecord>,
}

#[derive(Debug, Clone)]
struct OutputFileRecord {
    index: u32,
    path: String,
    abs_path: Option<String>,
    output_path: Option<String>,
    size: u64,
    bytes_written: u64,
    crc32: Option<u32>,
    output_crc32: Option<u32>,
    crc_ok: Option<bool>,
    status: u8,
    mtime_ns: Option<u64>,
    magic: Vec<u8>,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWorkerManifest {
    files: Arc<Vec<OutputFileRecord>>,
    complete: bool,
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    identity_paths: bool,
}

#[pymethods]
impl NativeWorkerManifest {
    #[getter]
    fn complete(&self) -> bool {
        self.complete
    }
    #[getter]
    fn file_count(&self) -> usize {
        self.file_count
    }
    #[getter]
    fn dir_count(&self) -> usize {
        self.dir_count
    }
    #[getter]
    fn total_size(&self) -> u64 {
        self.total_size
    }
    #[getter]
    fn identity_paths(&self) -> bool {
        self.identity_paths
    }
    fn __len__(&self) -> usize {
        self.files.len()
    }
    fn all_complete(&self) -> bool {
        self.files.iter().all(|item| item.status == 1)
    }
    fn materialize_files(&self, py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
        self.files
            .iter()
            .map(|item| output_file_dict(py, item))
            .collect()
    }
    fn to_output_inventory(&self, root: String) -> NativeOutputInventory {
        NativeOutputInventory {
            root,
            exists: true,
            is_dir: true,
            file_count: self.file_count,
            dir_count: self.dir_count,
            total_size: self.total_size,
            transient_file_count: 0,
            unreadable_count: 0,
            files: Arc::clone(&self.files),
            worker_crc_available: !self.files.is_empty(),
            worker_inventory_complete: self.complete && self.all_complete(),
            identity_paths: self.identity_paths,
        }
    }
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeOutputInventory {
    root: String,
    exists: bool,
    is_dir: bool,
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    transient_file_count: usize,
    unreadable_count: usize,
    files: Arc<Vec<OutputFileRecord>>,
    worker_crc_available: bool,
    worker_inventory_complete: bool,
    identity_paths: bool,
}

#[pymethods]
impl NativeOutputInventory {
    #[getter]
    fn root(&self) -> &str {
        &self.root
    }
    #[getter]
    fn exists(&self) -> bool {
        self.exists
    }
    #[getter]
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    #[getter]
    fn file_count(&self) -> usize {
        self.file_count
    }
    #[getter]
    fn dir_count(&self) -> usize {
        self.dir_count
    }
    #[getter]
    fn total_size(&self) -> u64 {
        self.total_size
    }
    #[getter]
    fn transient_file_count(&self) -> usize {
        self.transient_file_count
    }
    #[getter]
    fn unreadable_count(&self) -> usize {
        self.unreadable_count
    }
    #[getter]
    fn worker_crc_available(&self) -> bool {
        self.worker_crc_available
    }
    #[getter]
    fn worker_inventory_complete(&self) -> bool {
        self.worker_inventory_complete
    }
    #[getter]
    fn identity_paths(&self) -> bool {
        self.identity_paths
    }

    fn __len__(&self) -> usize {
        self.files.len()
    }

    fn all_crc_ok(&self) -> bool {
        self.files.iter().all(|item| item.crc_ok != Some(false))
    }

    fn relative_paths(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|item| item.output_path.as_ref().unwrap_or(&item.path).clone())
            .collect()
    }

    fn file_columns(&self) -> (Vec<String>, Vec<u64>) {
        let mut paths = Vec::with_capacity(self.files.len());
        let mut sizes = Vec::with_capacity(self.files.len());
        for item in self.files.iter() {
            paths.push(item.output_path.as_ref().unwrap_or(&item.path).clone());
            sizes.push(item.size);
        }
        (paths, sizes)
    }

    fn file_head_columns(
        &self,
        py: Python<'_>,
    ) -> (Vec<String>, Vec<u64>, Vec<Option<u64>>, Vec<Py<PyBytes>>) {
        let mut paths = Vec::with_capacity(self.files.len());
        let mut sizes = Vec::with_capacity(self.files.len());
        let mut mtimes_ns = Vec::with_capacity(self.files.len());
        let mut magics = Vec::with_capacity(self.files.len());
        for item in self.files.iter() {
            let path = item.abs_path.clone().unwrap_or_else(|| {
                let relative = item.output_path.as_ref().unwrap_or(&item.path);
                path_to_string(&Path::new(&self.root).join(relative))
            });
            paths.push(path);
            sizes.push(item.size);
            mtimes_ns.push(item.mtime_ns);
            magics.push(PyBytes::new(py, &item.magic).unbind());
        }
        (paths, sizes, mtimes_ns, magics)
    }

    #[pyo3(signature = (
        patterns, prune_dir_globs, blocked_extensions, blocked_file_names,
        size_ranges, mtime_ranges, whitelist_rules
    ))]
    fn build_directory_snapshots(
        &self,
        py: Python<'_>,
        patterns: Vec<String>,
        prune_dir_globs: Vec<String>,
        blocked_extensions: Vec<String>,
        blocked_file_names: Vec<String>,
        size_ranges: Vec<NumericRangeTuple>,
        mtime_ranges: Vec<NumericRangeTuple>,
        whitelist_rules: Vec<WhitelistRuleTuple>,
    ) -> PyResult<(Py<NativeDirectorySnapshot>, Py<NativeDirectorySnapshot>)> {
        let options = DirectoryScanOptions::new(
            patterns,
            prune_dir_globs,
            blocked_extensions,
            blocked_file_names,
            size_ranges,
            mtime_ranges,
            whitelist_rules,
        )?;
        let mut records = build_inventory_snapshot_views(&self.root, self.files.as_ref(), &options);
        populate_relation_anchors(&mut records.raw);
        let (filtered, raw) = NativeDirectorySnapshot::from_views(records.filtered, records.raw);
        Ok((
            Py::new(py, filtered)?,
            Py::new(py, raw)?,
        ))
    }

    fn materialize_files(&self, py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
        self.files
            .iter()
            .map(|item| output_file_dict(py, item))
            .collect()
    }
}

fn output_file_dict(py: Python<'_>, item: &OutputFileRecord) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("index", item.index)?;
    dict.set_item("path", &item.path)?;
    if let Some(abs_path) = &item.abs_path {
        dict.set_item("abs_path", abs_path)?;
    }
    if let Some(output_path) = &item.output_path {
        dict.set_item("output_path", output_path)?;
    }
    dict.set_item("size", item.size)?;
    if item.bytes_written != item.size {
        dict.set_item("bytes_written", item.bytes_written)?;
    }
    if let Some(crc32) = item.crc32 {
        dict.set_item("crc32", crc32)?;
        dict.set_item("has_crc", true)?;
    }
    if let Some(output_crc32) = item.output_crc32 {
        dict.set_item("output_crc32", output_crc32)?;
        dict.set_item("has_output_crc", true)?;
    }
    if let Some(crc_ok) = item.crc_ok {
        dict.set_item("crc_ok", crc_ok)?;
    }
    if item.status != 0 {
        dict.set_item(
            "status",
            match item.status {
                1 => "complete",
                2 => "failed",
                _ => "unverified",
            },
        )?;
    }
    dict.set_item("magic", PyBytes::new(py, &item.magic))?;
    if let Some(mtime_ns) = item.mtime_ns {
        dict.set_item("mtime_ns", mtime_ns)?;
    }
    Ok(dict.unbind())
}

#[pymethods]
impl NativeDirectorySnapshot {
    fn __len__(&self) -> usize {
        self.rows.len()
    }

    fn __bool__(&self) -> bool {
        !self.rows.is_empty()
    }

    fn has_files(&self) -> bool {
        self.rows.iter().any(|&row| !self.table.is_dirs[row])
    }

    fn materialize_columns(&self) -> (Vec<String>, Vec<bool>, Vec<Option<u64>>, Vec<Option<u64>>) {
        let mut paths = Vec::with_capacity(self.rows.len());
        let mut is_dirs = Vec::with_capacity(self.rows.len());
        let mut sizes = Vec::with_capacity(self.rows.len());
        let mut mtimes_ns = Vec::with_capacity(self.rows.len());
        for &row in &self.rows {
            paths.push(self.table.paths[row].clone());
            is_dirs.push(self.table.is_dirs[row]);
            sizes.push(self.table.sizes[row]);
            mtimes_ns.push(self.table.mtimes_ns[row]);
        }
        (paths, is_dirs, sizes, mtimes_ns)
    }

    fn file_columns(&self) -> (Vec<String>, Vec<Option<u64>>, Vec<Option<u64>>) {
        let mut paths = Vec::new();
        let mut sizes = Vec::new();
        let mut mtimes_ns = Vec::new();
        for &row in &self.rows {
            if self.table.is_dirs[row] {
                continue;
            }
            paths.push(self.table.paths[row].clone());
            sizes.push(self.table.sizes[row]);
            mtimes_ns.push(self.table.mtimes_ns[row]);
        }
        (paths, sizes, mtimes_ns)
    }

    fn file_columns_for_directories(
        &self,
        directories: Vec<String>,
    ) -> (Vec<String>, Vec<Option<u64>>, Vec<Option<u64>>) {
        let directories: HashSet<String> = directories
            .into_iter()
            .map(|directory| directory.to_ascii_lowercase())
            .collect();
        let mut paths = Vec::new();
        let mut sizes = Vec::new();
        let mut mtimes_ns = Vec::new();
        for &row in &self.rows {
            if self.table.is_dirs[row] {
                continue;
            }
            let parent = Path::new(&self.table.paths[row])
                .parent()
                .map(|value| value.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !directories.contains(&parent) {
                continue;
            }
            paths.push(self.table.paths[row].clone());
            sizes.push(self.table.sizes[row]);
            mtimes_ns.push(self.table.mtimes_ns[row]);
        }
        (paths, sizes, mtimes_ns)
    }

    fn identity_rows(&self) -> Vec<(String, bool, u64, u64)> {
        self.rows.iter().map(|&row| {
                (
                    Path::new(&self.table.paths[row])
                        .file_name()
                        .map(|name| name.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_default(),
                    self.table.is_dirs[row],
                    self.table.sizes[row].unwrap_or(0),
                    self.table.mtimes_ns[row].unwrap_or(0),
                )
            })
            .collect()
    }
}

struct DirectoryScanOptions {
    patterns: RegexSet,
    prune_dir_names: HashSet<String>,
    prune_dir_patterns: RegexSet,
    whitelist_rules: Vec<WhitelistRule>,
    blocked_extensions: HashSet<String>,
    blocked_file_names: HashSet<String>,
    size_ranges: Vec<NativeNumericRange>,
    mtime_ranges: Vec<NativeNumericRange>,
}

struct WhitelistRule {
    path_patterns: RegexSet,
    prune_dir_patterns: RegexSet,
    file_patterns: RegexSet,
    allowed_extensions: HashSet<String>,
}

#[derive(Clone, Copy)]
struct NativeNumericRange {
    gt: Option<u64>,
    gte: Option<u64>,
    lt: Option<u64>,
    lte: Option<u64>,
    eq: Option<u64>,
}

type NumericRangeTuple = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);
type WhitelistRuleTuple = (Vec<String>, Vec<String>, Vec<String>, Vec<String>);

impl NativeNumericRange {
    fn from_tuple(value: NumericRangeTuple) -> Self {
        Self {
            gt: value.0,
            gte: value.1,
            lt: value.2,
            lte: value.3,
            eq: value.4,
        }
    }

    fn allows(&self, value: Option<u64>) -> bool {
        let Some(value) = value else {
            return false;
        };
        self.eq.is_none_or(|expected| value == expected)
            && self.gt.is_none_or(|minimum| value > minimum)
            && self.gte.is_none_or(|minimum| value >= minimum)
            && self.lt.is_none_or(|maximum| value < maximum)
            && self.lte.is_none_or(|maximum| value <= maximum)
    }
}

#[derive(Default)]
struct DirectoryScanProfile {
    directory_enumeration: Duration,
    metadata_reads: Duration,
    path_matching: Duration,
    record_building: Duration,
    traversal_overhead: Duration,
    scan_total: Duration,
    directories_opened: usize,
    entries_seen: usize,
    metadata_read_count: usize,
    accepted_entries: usize,
    pruned_directories: usize,
    rejected_files: usize,
}

#[derive(Clone, Copy)]
enum ProfileBucket {
    DirectoryEnumeration,
    MetadataReads,
    PathMatching,
    RecordBuilding,
    TraversalOverhead,
}

impl DirectoryScanProfile {
    fn add_elapsed(&mut self, bucket: ProfileBucket, started: Instant) {
        let elapsed = started.elapsed();
        match bucket {
            ProfileBucket::DirectoryEnumeration => self.directory_enumeration += elapsed,
            ProfileBucket::MetadataReads => self.metadata_reads += elapsed,
            ProfileBucket::PathMatching => self.path_matching += elapsed,
            ProfileBucket::RecordBuilding => self.record_building += elapsed,
            ProfileBucket::TraversalOverhead => self.traversal_overhead += elapsed,
        }
    }

    fn into_py_dict(
        self,
        py: Python<'_>,
        options_compile: Duration,
        snapshot_building: Duration,
        profiled_call_total: Duration,
    ) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("options_compile_ns", duration_ns(options_compile))?;
        dict.set_item(
            "directory_enumeration_ns",
            duration_ns(self.directory_enumeration),
        )?;
        dict.set_item("metadata_reads_ns", duration_ns(self.metadata_reads))?;
        dict.set_item("path_matching_ns", duration_ns(self.path_matching))?;
        dict.set_item("record_building_ns", duration_ns(self.record_building))?;
        dict.set_item(
            "traversal_overhead_ns",
            duration_ns(self.traversal_overhead),
        )?;
        dict.set_item("scan_total_ns", duration_ns(self.scan_total))?;
        dict.set_item("snapshot_building_ns", duration_ns(snapshot_building))?;
        dict.set_item("profiled_call_total_ns", duration_ns(profiled_call_total))?;
        dict.set_item("directories_opened", self.directories_opened)?;
        dict.set_item("entries_seen", self.entries_seen)?;
        dict.set_item("metadata_read_count", self.metadata_read_count)?;
        dict.set_item("accepted_entries", self.accepted_entries)?;
        dict.set_item("pruned_directories", self.pruned_directories)?;
        dict.set_item("rejected_files", self.rejected_files)?;
        Ok(dict.unbind())
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn measure<const ENABLED: bool, T>(
    profile: &mut Option<&mut DirectoryScanProfile>,
    bucket: ProfileBucket,
    operation: impl FnOnce() -> T,
) -> T {
    if !ENABLED {
        return operation();
    }
    let Some(profile) = profile.as_deref_mut() else {
        return operation();
    };
    let started = Instant::now();
    let result = operation();
    profile.add_elapsed(bucket, started);
    result
}

impl DirectoryEntryRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("is_dir", self.is_dir)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        Ok(dict.unbind())
    }
}

impl DirectoryScanOptions {
    fn new(
        patterns: Vec<String>,
        prune_dir_globs: Vec<String>,
        blocked_extensions: Vec<String>,
        blocked_file_names: Vec<String>,
        size_ranges: Vec<NumericRangeTuple>,
        mtime_ranges: Vec<NumericRangeTuple>,
        whitelist_rules: Vec<WhitelistRuleTuple>,
    ) -> PyResult<Self> {
        let (prune_dir_names, prune_dir_patterns) = compile_prune_dirs(prune_dir_globs)?;
        Ok(Self {
            patterns: compile_case_insensitive_regex_set(patterns)?,
            prune_dir_names,
            prune_dir_patterns,
            whitelist_rules: whitelist_rules
                .into_iter()
                .map(
                    |(path_patterns, prune_dir_patterns, file_patterns, extensions)| {
                        Ok(WhitelistRule {
                            path_patterns: compile_case_insensitive_regex_set(path_patterns)?,
                            prune_dir_patterns: compile_case_insensitive_regex_set(
                                prune_dir_patterns,
                            )?,
                            file_patterns: compile_case_insensitive_regex_set(file_patterns)?,
                            allowed_extensions: normalize_extensions(extensions),
                        })
                    },
                )
                .collect::<PyResult<Vec<_>>>()?,
            blocked_extensions: normalize_extensions(blocked_extensions),
            blocked_file_names: blocked_file_names
                .into_iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
            size_ranges: size_ranges
                .into_iter()
                .map(NativeNumericRange::from_tuple)
                .collect(),
            mtime_ranges: mtime_ranges
                .into_iter()
                .map(NativeNumericRange::from_tuple)
                .collect(),
        })
    }
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, mtime_ranges, whitelist_rules))]
pub(crate) fn scan_directory_snapshot(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    mtime_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<Py<NativeDirectorySnapshot>> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    )?;
    let mut records = scan_directory(root_path, max_depth, &options)?;
    populate_relation_anchors(&mut records);
    Py::new(py, NativeDirectorySnapshot::from_records(records))
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, mtime_ranges, whitelist_rules))]
pub(crate) fn scan_directory_snapshots(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    mtime_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<(Py<NativeDirectorySnapshot>, Py<NativeDirectorySnapshot>)> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    )?;
    let mut records = scan_directory_views(root_path, max_depth, &options)?;
    populate_relation_anchors(&mut records.raw);
    let (filtered, raw) = NativeDirectorySnapshot::from_views(records.filtered, records.raw);
    Ok((
        Py::new(py, filtered)?,
        Py::new(py, raw)?,
    ))
}

#[pyfunction]
#[pyo3(signature = (paths, is_dirs, sizes, mtimes_ns, relation_member_eligible=None))]
pub(crate) fn directory_snapshot_from_columns(
    py: Python<'_>,
    paths: Vec<String>,
    is_dirs: Vec<bool>,
    sizes: Vec<Option<u64>>,
    mtimes_ns: Vec<Option<u64>>,
    relation_member_eligible: Option<Vec<bool>>,
) -> PyResult<Py<NativeDirectorySnapshot>> {
    let length = paths.len();
    if is_dirs.len() != length
        || sizes.len() != length
        || mtimes_ns.len() != length
        || relation_member_eligible
            .as_ref()
            .is_some_and(|values| values.len() != length)
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "directory snapshot columns must have equal lengths",
        ));
    }
    let relation_member_eligible = relation_member_eligible
        .unwrap_or_else(|| vec![true; length]);
    let mut records = paths
        .into_iter()
        .zip(is_dirs)
        .zip(sizes)
        .zip(mtimes_ns)
        .zip(relation_member_eligible)
        .map(
            |((((path, is_dir), size), mtime_ns), relation_member_eligible)| {
                DirectoryEntryRecord {
                    path,
                    is_dir,
                    size,
                    mtime_ns,
                    relation_member_eligible,
                    relation_anchor: None,
                }
            },
        )
        .collect::<Vec<_>>();
    populate_relation_anchors(&mut records);
    Py::new(
        py,
        NativeDirectorySnapshot::from_records(records),
    )
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, mtime_ranges, whitelist_rules))]
pub(crate) fn profile_directory_scan(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    mtime_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<(Py<NativeDirectorySnapshot>, Py<PyDict>)> {
    let call_started = Instant::now();
    let options_started = Instant::now();
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    )?;
    let options_compile = options_started.elapsed();

    let mut profile = DirectoryScanProfile::default();
    let entries =
        scan_directory_impl::<true>(root_path, max_depth, &options, false, Some(&mut profile))?;

    let snapshot_started = Instant::now();
    let snapshot = Py::new(py, NativeDirectorySnapshot::from_records(entries.filtered))?;
    let snapshot_building = snapshot_started.elapsed();
    let profiled_call_total = call_started.elapsed();
    let profile =
        profile.into_py_dict(py, options_compile, snapshot_building, profiled_call_total)?;
    Ok((snapshot, profile))
}

#[pyfunction]
#[pyo3(signature = (root_path, paths, sizes, patterns, prune_dir_globs, blocked_extensions, blocked_file_names, size_ranges, whitelist_rules))]
pub(crate) fn filter_inventory_file_indices(
    root_path: &str,
    paths: Vec<String>,
    sizes: Vec<u64>,
    patterns: Vec<String>,
    prune_dir_globs: Vec<String>,
    blocked_extensions: Vec<String>,
    blocked_file_names: Vec<String>,
    size_ranges: Vec<NumericRangeTuple>,
    whitelist_rules: Vec<WhitelistRuleTuple>,
) -> PyResult<Vec<usize>> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dir_globs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        Vec::new(),
        whitelist_rules,
    )?;
    let root = PathBuf::from(root_path);
    let mut accepted = vec![false; paths.len()];
    let mut size_accepted_split_families = HashSet::new();
    let mut size_deferred = Vec::new();
    let mut directory_rejections = HashMap::new();
    for (index, path) in paths.into_iter().enumerate() {
        let size = sizes.get(index).copied().unwrap_or(0);
        let path = PathBuf::from(path);
        if file_rejected_by_path(&path, &root, &options)
            || file_under_rejected_directory(&path, &root, &options, &mut directory_rejections)
        {
            continue;
        }
        let family_keys = if options.size_ranges.is_empty() {
            Vec::new()
        } else {
            crate::relations::relations_size_filter_split_family_keys(
                path.to_string_lossy().as_ref(),
            )
        };
        if numeric_ranges_allow(&options.size_ranges, Some(size)) {
            accepted[index] = true;
            size_accepted_split_families.extend(family_keys);
        } else if !family_keys.is_empty() {
            size_deferred.push((index, family_keys));
        }
    }
    for (index, family_keys) in size_deferred {
        accepted[index] = family_keys
            .iter()
            .any(|key| size_accepted_split_families.contains(key));
    }
    Ok(accepted
        .into_iter()
        .enumerate()
        .filter_map(|(index, keep)| keep.then_some(index))
        .collect())
}

fn build_inventory_snapshot_views(
    root_path: &str,
    files: &[OutputFileRecord],
    options: &DirectoryScanOptions,
) -> DirectoryScanRecords {
    let root = lexical_normalize_path(Path::new(root_path));
    let mut raw_files = Vec::with_capacity(files.len());
    let mut pre_mtime_accepted = Vec::with_capacity(files.len());
    let mut size_accepted_split_families = HashSet::new();
    let mut size_deferred = Vec::new();
    let mut directory_rejections = HashMap::new();

    for item in files {
        let Some(path) = inventory_file_path(&root, item) else {
            continue;
        };
        let record = DirectoryEntryRecord {
            path: path_to_string(&path),
            is_dir: false,
            size: Some(item.size),
            mtime_ns: item.mtime_ns,
            relation_member_eligible: true,
            relation_anchor: None,
        };
        let index = raw_files.len();
        raw_files.push(record);
        pre_mtime_accepted.push(false);

        if file_rejected_by_path(&path, &root, options)
            || file_under_rejected_directory(&path, &root, options, &mut directory_rejections)
        {
            raw_files[index].relation_member_eligible = false;
            continue;
        }
        let family_keys = if options.size_ranges.is_empty() {
            Vec::new()
        } else {
            crate::relations::relations_size_filter_split_family_keys(
                path.to_string_lossy().as_ref(),
            )
        };
        if numeric_ranges_allow(&options.size_ranges, Some(item.size)) {
            pre_mtime_accepted[index] = true;
            size_accepted_split_families.extend(family_keys);
        } else if !family_keys.is_empty() {
            size_deferred.push((index, family_keys));
            raw_files[index].relation_member_eligible = true;
        } else {
            raw_files[index].relation_member_eligible = true;
        }
    }
    for (index, family_keys) in size_deferred {
        pre_mtime_accepted[index] = family_keys
            .iter()
            .any(|key| size_accepted_split_families.contains(key));
    }

    for (index, record) in raw_files.iter_mut().enumerate() {
        if pre_mtime_accepted[index]
            && !numeric_ranges_allow(&options.mtime_ranges, record.mtime_ns)
        {
            record.relation_member_eligible = false;
        }
    }

    let mut raw = ancestor_directory_records(&root, raw_files.iter());
    raw.extend(raw_files.iter().cloned());

    // Directory entries are derived before mtime filtering to preserve the ordered
    // Python filter semantics: a directory can remain after its last file is rejected
    // by the final mtime stage.
    let mut filtered = ancestor_directory_records(
        &root,
        raw_files
            .iter()
            .enumerate()
            .filter_map(|(index, record)| pre_mtime_accepted[index].then_some(record)),
    );
    filtered.extend(
        raw_files
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| {
                (pre_mtime_accepted[index]
                    && numeric_ranges_allow(&options.mtime_ranges, record.mtime_ns))
                .then_some(record)
            }),
    );
    DirectoryScanRecords { filtered, raw }
}

fn inventory_file_path(root: &Path, item: &OutputFileRecord) -> Option<PathBuf> {
    let raw_path = item.output_path.as_ref().unwrap_or(&item.path);
    let path = Path::new(raw_path);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let normalized = lexical_normalize_path(&joined);
    (normalized != root && path_is_within_root(&normalized, root)).then_some(normalized)
}

fn lexical_normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(windows)]
fn path_is_within_root(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    root.components().all(|root_component| {
        path_components.next().is_some_and(|path_component| {
            path_component.as_os_str().to_string_lossy().to_lowercase()
                == root_component.as_os_str().to_string_lossy().to_lowercase()
        })
    })
}

#[cfg(not(windows))]
fn path_is_within_root(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

fn ancestor_directory_records<'a>(
    root: &Path,
    files: impl Iterator<Item = &'a DirectoryEntryRecord>,
) -> Vec<DirectoryEntryRecord> {
    let mut directories = HashSet::new();
    for file in files {
        let mut parent = Path::new(&file.path).parent();
        while let Some(directory) = parent {
            if directory == root || !path_is_within_root(directory, root) {
                break;
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let mut directories: Vec<PathBuf> = directories.into_iter().collect();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| {
                left.to_string_lossy()
                    .to_lowercase()
                    .cmp(&right.to_string_lossy().to_lowercase())
            })
    });
    directories
        .into_iter()
        .map(|path| DirectoryEntryRecord {
            path: path_to_string(&path),
            is_dir: true,
            size: None,
            mtime_ns: None,
            relation_member_eligible: false,
            relation_anchor: None,
        })
        .collect()
}

#[pyfunction]
pub(crate) fn list_regular_files_in_directory(
    py: Python<'_>,
    directory: &str,
) -> PyResult<Vec<Py<PyDict>>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };
    let mut records = Vec::new();
    for item in entries {
        let Ok(entry) = item else {
            continue;
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        records.push(DirectoryEntryRecord {
            path: path_to_string(&path),
            is_dir: false,
            size: Some(metadata.len()),
            mtime_ns: metadata_mtime_ns(&metadata),
            relation_member_eligible: true,
            relation_anchor: None,
        });
    }
    records
        .into_iter()
        .map(|entry| entry.into_py_dict(py))
        .collect()
}

#[pyfunction]
#[pyo3(signature = (paths, magic_size=16))]
pub(crate) fn batch_file_head_facts(
    py: Python<'_>,
    paths: Vec<String>,
    magic_size: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    let records = py.detach(|| {
        if paths.len() < 2 {
            return paths
                .into_iter()
                .map(|path| file_head_record(path, magic_size))
                .collect::<Vec<_>>();
        }

        let chunk_count = paths.len().min(4);
        let chunk_size = paths.len().div_ceil(chunk_count);
        let mut chunks: Vec<Vec<String>> = Vec::with_capacity(chunk_count);
        let mut chunk = Vec::with_capacity(chunk_size);
        for path in paths {
            chunk.push(path);
            if chunk.len() == chunk_size {
                chunks.push(chunk);
                chunk = Vec::with_capacity(chunk_size);
            }
        }
        if !chunk.is_empty() {
            chunks.push(chunk);
        }

        chunks
            .into_par_iter()
            .map(|chunk| {
                chunk
                    .into_iter()
                    .map(|path| file_head_record(path, magic_size))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    });
    records
        .into_iter()
        .map(|record| record.into_py_dict(py))
        .collect()
}

#[pyfunction]
pub(crate) fn scan_output_tree(py: Python<'_>, output_dir: &str) -> PyResult<Py<PyDict>> {
    let inventory = scan_output_inventory_impl(output_dir);
    let result = PyDict::new(py);
    result.set_item("exists", inventory.exists)?;
    result.set_item("is_dir", inventory.is_dir)?;
    result.set_item("file_count", inventory.file_count)?;
    result.set_item("dir_count", inventory.dir_count)?;
    result.set_item("total_size", inventory.total_size)?;
    result.set_item("transient_file_count", inventory.transient_file_count)?;
    result.set_item("unreadable_count", inventory.unreadable_count)?;
    result.set_item("files", PyList::new(py, inventory.materialize_files(py)?)?)?;
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn scan_output_inventory(py: Python<'_>, output_dir: String) -> NativeOutputInventory {
    py.detach(|| scan_output_inventory_impl(&output_dir))
}

#[pyfunction]
#[pyo3(signature = (
    root, files, exists, is_dir, file_count, dir_count, total_size,
    transient_file_count, unreadable_count, worker_crc_available,
    worker_inventory_complete, identity_paths
))]
pub(crate) fn output_inventory_from_serialized(
    py: Python<'_>,
    root: String,
    files: Vec<Py<PyDict>>,
    exists: bool,
    is_dir: bool,
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    transient_file_count: usize,
    unreadable_count: usize,
    worker_crc_available: bool,
    worker_inventory_complete: bool,
    identity_paths: bool,
) -> PyResult<NativeOutputInventory> {
    let mut records = Vec::with_capacity(files.len());
    for item in files {
        let dict = item.bind(py);
        let path = py_dict_string(dict, "path")?.unwrap_or_default();
        let output_path = py_dict_string(dict, "output_path")?.filter(|value| value != &path);
        let size = py_dict_u64(dict, "size")?.unwrap_or(0);
        let status = match py_dict_string(dict, "status")?.as_deref() {
            Some("complete") => 1,
            Some("failed") => 2,
            _ => 0,
        };
        let has_crc = py_dict_bool(dict, "has_crc")?.unwrap_or(false);
        let has_output_crc = py_dict_bool(dict, "has_output_crc")?.unwrap_or(false);
        records.push(OutputFileRecord {
            index: py_dict_u64(dict, "index")?.unwrap_or(records.len() as u64) as u32,
            path,
            abs_path: None,
            output_path,
            size,
            bytes_written: py_dict_u64(dict, "bytes_written")?.unwrap_or(size),
            crc32: if has_crc {
                py_dict_u64(dict, "crc32")?.map(|value| value as u32)
            } else {
                None
            },
            output_crc32: if has_output_crc {
                py_dict_u64(dict, "output_crc32")?.map(|value| value as u32)
            } else {
                None
            },
            crc_ok: py_dict_bool(dict, "crc_ok")?,
            status,
            mtime_ns: py_dict_u64(dict, "mtime_ns")?,
            magic: dict
                .get_item("magic")?
                .map(|value| value.extract::<Vec<u8>>())
                .transpose()?
                .unwrap_or_default(),
        });
    }
    Ok(NativeOutputInventory {
        root,
        exists,
        is_dir,
        file_count,
        dir_count,
        total_size,
        transient_file_count,
        unreadable_count,
        files: Arc::new(records),
        worker_crc_available,
        worker_inventory_complete,
        identity_paths,
    })
}

#[pyfunction]
#[pyo3(signature = (rows, complete, file_count, dir_count, total_size, identity_paths=false))]
pub(crate) fn worker_manifest_from_rows(
    py: Python<'_>,
    rows: Vec<Py<PyList>>,
    complete: bool,
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    identity_paths: bool,
) -> PyResult<NativeWorkerManifest> {
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.bind(py);
        if row.len() != 14 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "worker manifest v3 row must contain 14 columns",
            ));
        }
        let path = row.get_item(1)?.extract::<String>()?;
        let raw_output_path = row.get_item(2)?.extract::<String>()?;
        let has_crc = row.get_item(5)?.extract::<u8>()? != 0;
        let has_output_crc = row.get_item(7)?.extract::<u8>()? != 0;
        let status = row.get_item(10)?.extract::<u8>()?;
        files.push(OutputFileRecord {
            index: row.get_item(0)?.extract::<u32>()?,
            output_path: (!raw_output_path.is_empty() && raw_output_path != path)
                .then_some(raw_output_path),
            path,
            abs_path: None,
            size: row.get_item(3)?.extract::<u64>()?,
            bytes_written: row.get_item(4)?.extract::<u64>()?,
            crc32: has_crc
                .then(|| row.get_item(6).and_then(|item| item.extract::<u32>()))
                .transpose()?,
            output_crc32: has_output_crc
                .then(|| row.get_item(8).and_then(|item| item.extract::<u32>()))
                .transpose()?,
            crc_ok: Some(row.get_item(9)?.extract::<u8>()? != 0),
            status,
            mtime_ns: if row.get_item(11)?.extract::<u8>()? != 0 {
                Some(row.get_item(12)?.extract::<u64>()?)
            } else {
                None
            },
            magic: decode_hex_bytes(&row.get_item(13)?.extract::<String>()?)?,
        });
    }
    Ok(NativeWorkerManifest {
        files: Arc::new(files),
        complete,
        file_count,
        dir_count,
        total_size,
        identity_paths,
    })
}

fn scan_output_inventory_impl(output_dir: &str) -> NativeOutputInventory {
    let root = PathBuf::from(output_dir);
    let exists = root.exists();
    let is_dir = root.is_dir();
    let mut stats = OutputTreeStats::default();
    if is_dir {
        walk_output_tree(&root, &root, &mut stats);
    }
    NativeOutputInventory {
        root: path_to_string(&root),
        exists,
        is_dir,
        file_count: stats.file_count,
        dir_count: stats.dir_count,
        total_size: stats.total_size,
        transient_file_count: stats.transient_file_count,
        unreadable_count: stats.unreadable_count,
        files: Arc::new(stats.files),
        worker_crc_available: false,
        worker_inventory_complete: false,
        identity_paths: false,
    }
}

fn py_dict_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.str()?.to_string_lossy().into_owned()))
}

fn decode_hex_bytes(value: &str) -> PyResult<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "worker manifest magic must contain complete hex bytes",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("worker manifest magic is not ASCII hex")
            })?;
            u8::from_str_radix(text, 16).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("worker manifest magic is not valid hex")
            })
        })
        .collect()
}

fn py_dict_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(value
        .extract::<u64>()
        .ok()
        .or_else(|| value.extract::<i64>().ok().map(|item| item.max(0) as u64)))
}

fn py_dict_bool(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    value.extract::<bool>().map(Some)
}

struct FileHeadRecord {
    path: String,
    exists: bool,
    is_file: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
    magic: Vec<u8>,
}

impl FileHeadRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("exists", self.exists)?;
        dict.set_item("is_file", self.is_file)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        dict.set_item("magic", pyo3::types::PyBytes::new(py, &self.magic))?;
        Ok(dict.unbind())
    }
}

fn file_head_record(path: String, magic_size: usize) -> FileHeadRecord {
    let path_buf = PathBuf::from(&path);
    let metadata = fs::metadata(&path_buf).ok();
    let is_file = metadata
        .as_ref()
        .map(|item| item.is_file())
        .unwrap_or(false);
    let mut magic = Vec::new();
    if is_file && magic_size > 0 {
        if let Ok(mut handle) =
            crate::io::resource_lifecycle::TrackedFile::open(&path_buf, "directory_probe_file")
        {
            let limit = magic_size.min(1024 * 1024);
            let mut buffer = vec![0u8; limit];
            if let Ok(count) = handle.read(&mut buffer) {
                buffer.truncate(count);
                magic = buffer;
            }
        }
    }
    FileHeadRecord {
        path,
        exists: metadata.is_some(),
        is_file,
        size: metadata.as_ref().map(|item| item.len()),
        mtime_ns: metadata.as_ref().and_then(metadata_mtime_ns),
        magic,
    }
}

#[derive(Default)]
struct OutputTreeStats {
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    transient_file_count: usize,
    unreadable_count: usize,
    files: Vec<OutputFileRecord>,
}

fn walk_output_tree(root: &Path, current: &Path, stats: &mut OutputTreeStats) {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(_) => {
            stats.unreadable_count += 1;
            return;
        }
    };
    for item in entries {
        let Ok(entry) = item else {
            stats.unreadable_count += 1;
            continue;
        };
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                stats.unreadable_count += 1;
                continue;
            }
        };
        if metadata.is_dir() {
            if file_name == ".sunpack" {
                continue;
            }
            stats.dir_count += 1;
            walk_output_tree(root, &path, stats);
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        stats.file_count += 1;
        let size = metadata.len();
        stats.total_size = stats.total_size.saturating_add(size);
        if is_transient_file_name(&file_name) {
            stats.transient_file_count += 1;
        }
        let relative = path
            .strip_prefix(root)
            .map(path_to_string)
            .unwrap_or_else(|_| file_name.clone());
        stats.files.push(OutputFileRecord {
            index: stats.files.len() as u32,
            path: normalize_path_separator(relative),
            abs_path: Some(path_to_string(&path)),
            output_path: None,
            size,
            bytes_written: size,
            crc32: None,
            output_crc32: None,
            crc_ok: None,
            status: 0,
            mtime_ns: metadata_mtime_ns(&metadata),
            magic: Vec::new(),
        });
    }
}

fn is_transient_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".tmp", ".temp", ".part", ".partial", ".crdownload"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn compile_case_insensitive_regex_set(patterns: Vec<String>) -> PyResult<RegexSet> {
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .build()
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))
}

fn compile_prune_dirs(patterns: Vec<String>) -> PyResult<(HashSet<String>, RegexSet)> {
    let mut exact_names = HashSet::new();
    let mut wildcard_patterns = Vec::new();
    for pattern in patterns {
        let normalized = pattern
            .trim()
            .replace('\\', "/")
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            continue;
        }
        if normalized.contains('*') || normalized.contains('?') {
            wildcard_patterns.push(directory_glob_regex(&normalized));
        } else {
            exact_names.insert(normalized.to_ascii_lowercase());
        }
    }
    Ok((
        exact_names,
        compile_case_insensitive_regex_set(wildcard_patterns)?,
    ))
}

fn directory_glob_regex(pattern: &str) -> String {
    let mut result = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => result.push_str("[^/]*"),
            '?' => result.push_str("[^/]"),
            _ => result.push_str(&regex::escape(&character.to_string())),
        }
    }
    result.push('$');
    result
}

fn normalize_extensions(extensions: Vec<String>) -> HashSet<String> {
    extensions
        .into_iter()
        .filter_map(|ext| {
            let ext = ext.trim().to_ascii_lowercase();
            if ext.is_empty() {
                None
            } else if ext.starts_with('.') {
                Some(ext)
            } else {
                Some(format!(".{ext}"))
            }
        })
        .collect()
}

fn scan_directory(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
) -> PyResult<Vec<DirectoryEntryRecord>> {
    Ok(scan_directory_impl::<false>(root_path, max_depth, options, false, None)?.filtered)
}

fn populate_relation_anchors(records: &mut [DirectoryEntryRecord]) {
    let paths: Vec<String> = records
        .iter()
        .filter(|record| !record.is_dir && record.relation_member_eligible)
        .map(|record| record.path.clone())
        .collect();
    if paths.is_empty() {
        return;
    }
    let anchors = probe_volume_anchor_paths_cheap(&paths, None);
    let anchors_by_path: HashMap<String, VolumeAnchor> = anchors
        .into_iter()
        .map(|anchor| (anchor.path.to_ascii_lowercase(), anchor))
        .collect();
    for record in records
        .iter_mut()
        .filter(|record| !record.is_dir && record.relation_member_eligible)
    {
        record.relation_anchor = anchors_by_path
            .get(&record.path.to_ascii_lowercase())
            .cloned();
    }
}

fn scan_directory_views(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
) -> PyResult<DirectoryScanRecords> {
    scan_directory_impl::<false>(root_path, max_depth, options, true, None)
}

fn scan_directory_impl<const PROFILE: bool>(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
    collect_raw: bool,
    mut profile: Option<&mut DirectoryScanProfile>,
) -> PyResult<DirectoryScanRecords> {
    let scan_started = Instant::now();
    let root = PathBuf::from(root_path);
    if !root.exists() {
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.scan_total = scan_started.elapsed();
            }
        }
        return Ok(DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
        });
    }
    if root.is_file() {
        let match_root = root.parent().unwrap_or_else(|| Path::new(""));
        let raw = collect_raw
            .then(|| {
                fs::metadata(&root)
                    .ok()
                    .map(|metadata| DirectoryEntryRecord {
                        path: path_to_string(&root),
                        is_dir: false,
                        size: Some(metadata.len()),
                        mtime_ns: metadata_mtime_ns(&metadata),
                        relation_member_eligible: true,
                        relation_anchor: None,
                    })
            })
            .flatten();
        let filtered = file_record_if_accepted(&root, match_root, options)
            .into_iter()
            .collect();
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.scan_total = scan_started.elapsed();
            }
        }
        return Ok(DirectoryScanRecords {
            filtered,
            raw: raw.into_iter().collect(),
        });
    }

    let mut records = Vec::new();
    let mut raw_records = Vec::new();
    let mut size_accepted_split_families = HashSet::new();
    let mut size_deferred_split_records = Vec::new();
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let read_dir =
            match measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                fs::read_dir(&dir)
            }) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
        if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.directories_opened += 1;
            }
        }
        let mut child_dirs = Vec::new();
        let mut read_dir = read_dir;
        loop {
            let item =
                measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                    read_dir.next()
                });
            let Some(item) = item else {
                break;
            };
            let Ok(entry) = item else {
                continue;
            };
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.entries_seen += 1;
                }
            }
            let path =
                measure::<PROFILE, _>(&mut profile, ProfileBucket::DirectoryEnumeration, || {
                    entry.path()
                });
            let metadata =
                match measure::<PROFILE, _>(&mut profile, ProfileBucket::MetadataReads, || {
                    entry.metadata()
                }) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.metadata_read_count += 1;
                }
            }

            if metadata.is_dir() {
                if collect_raw {
                    raw_records.push(DirectoryEntryRecord {
                        path: path_to_string(&path),
                        is_dir: true,
                        size: None,
                        mtime_ns: None,
                        relation_member_eligible: false,
                        relation_anchor: None,
                    });
                }
                let rejected =
                    measure::<PROFILE, _>(&mut profile, ProfileBucket::PathMatching, || {
                        max_depth.is_some_and(|limit| depth >= limit)
                            || dir_rejected(&path, &root, options)
                    });
                if rejected {
                    if PROFILE {
                        if let Some(profile) = profile.as_deref_mut() {
                            profile.pruned_directories += 1;
                        }
                    }
                    continue;
                }
                measure::<PROFILE, _>(&mut profile, ProfileBucket::RecordBuilding, || {
                    records.push(DirectoryEntryRecord {
                        path: path_to_string(&path),
                        is_dir: true,
                        size: None,
                        mtime_ns: None,
                        relation_member_eligible: false,
                        relation_anchor: None,
                    });
                    child_dirs.push(path);
                });
                if PROFILE {
                    if let Some(profile) = profile.as_deref_mut() {
                        profile.accepted_entries += 1;
                    }
                }
                continue;
            }

            let size = metadata.len();
            let mtime_ns = metadata_mtime_ns(&metadata);
            let raw_file_index = if collect_raw {
                raw_records.push(DirectoryEntryRecord {
                    path: path_to_string(&path),
                    is_dir: false,
                    size: Some(size),
                    mtime_ns,
                    relation_member_eligible: false,
                    relation_anchor: None,
                });
                Some(raw_records.len() - 1)
            } else {
                None
            };
            let hard_rejected =
                measure::<PROFILE, _>(&mut profile, ProfileBucket::PathMatching, || {
                    !metadata.is_file()
                        || file_rejected_by_path(&path, &root, options)
                        || !numeric_ranges_allow(&options.mtime_ranges, mtime_ns)
                });
            if hard_rejected {
                if PROFILE {
                    if let Some(profile) = profile.as_deref_mut() {
                        profile.rejected_files += 1;
                    }
                }
                continue;
            }
            let split_family_keys = if options.size_ranges.is_empty() {
                Vec::new()
            } else {
                crate::relations::relations_size_filter_split_family_keys(
                    path.to_string_lossy().as_ref(),
                )
            };
            if !numeric_ranges_allow(&options.size_ranges, Some(size)) {
                if let Some(index) = raw_file_index {
                    raw_records[index].relation_member_eligible = true;
                }
                if split_family_keys.is_empty() {
                    if PROFILE {
                        if let Some(profile) = profile.as_deref_mut() {
                            profile.rejected_files += 1;
                        }
                    }
                } else {
                    size_deferred_split_records.push((
                        DirectoryEntryRecord {
                            path: path_to_string(&path),
                            is_dir: false,
                            size: Some(size),
                            mtime_ns,
                            relation_member_eligible: true,
                            relation_anchor: None,
                        },
                        split_family_keys,
                    ));
                }
                continue;
            }
            size_accepted_split_families.extend(split_family_keys);
            if let Some(index) = raw_file_index {
                raw_records[index].relation_member_eligible = true;
            }
            measure::<PROFILE, _>(&mut profile, ProfileBucket::RecordBuilding, || {
                records.push(DirectoryEntryRecord {
                    path: path_to_string(&path),
                    is_dir: false,
                    size: Some(size),
                    mtime_ns,
                    relation_member_eligible: true,
                    relation_anchor: None,
                });
            });
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.accepted_entries += 1;
                }
            }
        }

        measure::<PROFILE, _>(&mut profile, ProfileBucket::TraversalOverhead, || {
            child_dirs.sort();
            for child in child_dirs.into_iter().rev() {
                stack.push((child, depth + 1));
            }
        });
    }
    for (record, family_keys) in size_deferred_split_records {
        if family_keys
            .iter()
            .any(|key| size_accepted_split_families.contains(key))
        {
            records.push(record);
            if PROFILE {
                if let Some(profile) = profile.as_deref_mut() {
                    profile.accepted_entries += 1;
                }
            }
        } else if PROFILE {
            if let Some(profile) = profile.as_deref_mut() {
                profile.rejected_files += 1;
            }
        }
    }
    if PROFILE {
        if let Some(profile) = profile.as_deref_mut() {
            profile.scan_total = scan_started.elapsed();
        }
    }
    Ok(DirectoryScanRecords {
        filtered: records,
        raw: raw_records,
    })
}

fn file_record_if_accepted(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
) -> Option<DirectoryEntryRecord> {
    if file_rejected_by_path(path, root, options) {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    let mtime_ns = metadata_mtime_ns(&metadata);
    if !numeric_ranges_allow(&options.size_ranges, Some(size))
        || !numeric_ranges_allow(&options.mtime_ranges, mtime_ns)
    {
        return None;
    }
    Some(DirectoryEntryRecord {
        path: path_to_string(path),
        is_dir: false,
        size: Some(size),
        mtime_ns,
        relation_member_eligible: true,
        relation_anchor: None,
    })
}

fn dir_rejected(path: &Path, root: &Path, options: &DirectoryScanOptions) -> bool {
    let name = normalized_file_name(path);
    if options.prune_dir_names.contains(&name) || options.prune_dir_patterns.is_match(&name) {
        return true;
    }
    let candidates = path_candidates(path, root);
    regex_set_matches(&options.patterns, &candidates)
        || !dir_allowed_by_whitelist(&candidates, options)
}

fn file_rejected_by_path(path: &Path, root: &Path, options: &DirectoryScanOptions) -> bool {
    if options
        .blocked_file_names
        .contains(&normalized_file_name(path))
    {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        let ext = format!(".{}", ext.to_ascii_lowercase());
        if options.blocked_extensions.contains(&ext) {
            return true;
        }
    }
    let candidates = path_candidates(path, root);
    regex_set_matches(&options.patterns, &candidates)
        || !file_allowed_by_whitelist(path, &candidates, options)
}

fn file_under_rejected_directory(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    path.parent()
        .is_some_and(|directory| directory_rejected_cached(directory, root, options, cache))
}

fn directory_rejected_cached(
    directory: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    if directory == root {
        return false;
    }
    if !directory.starts_with(root) {
        return true;
    }
    if let Some(rejected) = cache.get(directory) {
        return *rejected;
    }
    let rejected = directory
        .parent()
        .is_some_and(|parent| directory_rejected_cached(parent, root, options, cache))
        || dir_rejected(directory, root, options);
    cache.insert(directory.to_path_buf(), rejected);
    rejected
}

fn dir_allowed_by_whitelist(candidates: &[String], options: &DirectoryScanOptions) -> bool {
    options.whitelist_rules.iter().all(|rule| {
        regex_field_allows(&rule.path_patterns, candidates)
            && regex_field_allows(&rule.prune_dir_patterns, candidates)
    })
}

fn file_allowed_by_whitelist(
    path: &Path,
    candidates: &[String],
    options: &DirectoryScanOptions,
) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{}", value.to_ascii_lowercase()));
    options.whitelist_rules.iter().all(|rule| {
        regex_field_allows(&rule.path_patterns, candidates)
            && regex_field_allows(&rule.file_patterns, candidates)
            && (rule.allowed_extensions.is_empty()
                || extension
                    .as_ref()
                    .is_some_and(|ext| rule.allowed_extensions.contains(ext)))
    })
}

fn regex_field_allows(regexes: &RegexSet, candidates: &[String]) -> bool {
    regexes.is_empty() || regex_set_matches(regexes, candidates)
}

fn numeric_ranges_allow(ranges: &[NativeNumericRange], value: Option<u64>) -> bool {
    ranges.iter().all(|range| range.allows(value))
}

fn regex_set_matches(regexes: &RegexSet, candidates: &[String]) -> bool {
    candidates
        .iter()
        .any(|candidate| regexes.is_match(candidate))
}

fn normalized_file_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn path_candidates(path: &Path, root: &Path) -> Vec<String> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default();
    let relative = path
        .strip_prefix(root)
        .map(path_to_string)
        .unwrap_or_else(|_| name.clone());
    vec![name, normalize_path_separator(relative)]
}

fn normalize_path_separator(path: String) -> String {
    path.replace('\\', "/")
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_mtime_ns(metadata: &fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_nanos()).ok()
}
