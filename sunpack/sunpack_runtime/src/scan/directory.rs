use crate::io::directory_errors::{DirectoryReadError, DirectoryReadErrors};
use rayon::prelude::*;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::catalog::{catalog_stem, CatalogRow, GeneratedBaseline, NativeWatchObservation, ScopeCatalog};
use super::path_filter::{FilterPath, NativePathRule, PathRule, PathRuleScratch};
use crate::analysis_native::volume_anchor::{
    cheap_fast_probe_pool, probe_volume_anchor_from_head, probe_volume_anchor_path_cheap,
    probe_volume_anchor_record_cheap, CheapAnchor, CheapAnchorCell,
};
use crate::io::resource_lifecycle::{NativeReadScope, PromotionCompletion};

#[derive(Debug, Default, Clone)]
pub(crate) struct DirectoryEntryRecord {
    pub(crate) path: String,
    pub(super) is_dir: bool,
    pub(super) size: Option<u64>,
    pub(super) mtime_ns: Option<u64>,
    pub(super) relation_member_eligible: bool,
    pub(super) relation_anchor: Option<CheapAnchor>,
}

#[derive(Debug)]
pub(crate) struct DirectorySnapshotTable {
    scan_errors: Vec<DirectoryReadError>,
    pub(crate) paths: Vec<String>,
    pub(crate) sizes: Vec<Option<u64>>,
    mtimes_ns: Vec<Option<u64>>,
    pub(crate) relation_anchors: Vec<Option<CheapAnchor>>,
    pub(crate) relation_anchor_cells: Vec<Option<CheapAnchorCell>>,
    routes: Vec<u8>,
}

const DIRECTORY_ROUTE: u8 = 0;
pub(crate) const FILE_ROUTE_RELATIONS: u8 = 1;
pub(crate) const FILE_ROUTE_DETECTION: u8 = 2;
pub(crate) const FILE_ROUTE_RESIDUAL: u8 = 3;
const RELATION_ELIGIBLE: u8 = 1 << 2;
const FORMAT_REJECT_TAR: u32 = 1 << 3;

impl DirectorySnapshotTable {
    pub(crate) fn file_route(&self, row: usize) -> u8 {
        self.routes[row] & !RELATION_ELIGIBLE
    }

    pub(crate) fn is_dir(&self, row: usize) -> bool {
        self.file_route(row) == DIRECTORY_ROUTE
    }

    pub(crate) fn relation_member_eligible(&self, row: usize) -> bool {
        self.routes[row] & RELATION_ELIGIBLE != 0
    }
}

#[derive(Clone)]
pub(crate) struct NativeDirectorySnapshot {
    pub(crate) table: Arc<DirectorySnapshotTable>,
    // An unfiltered snapshot uses the table's implicit row order.
    selected_rows: Option<Arc<Vec<usize>>>,
}

impl NativeDirectorySnapshot {
    pub(crate) fn view(&self, rows: Vec<usize>) -> Self {
        Self {
            table: Arc::clone(&self.table),
            selected_rows: Some(Arc::new(rows)),
        }
    }

    pub(crate) fn rows(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        let selected = self.selected_rows.as_deref();
        (0..selected.map_or(self.table.paths.len(), Vec::len))
            .map(move |index| selected.map_or(index, |rows| rows[index]))
    }

    // Relation views keep their rows in table order.
    pub(crate) fn contains_row(&self, row: usize) -> bool {
        self.selected_rows.as_deref().map_or_else(
            || row < self.table.paths.len(),
            |rows| rows.binary_search(&row).is_ok(),
        )
    }

    pub(crate) fn same_view(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.table, &other.table)
            && match (&self.selected_rows, &other.selected_rows) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }

    pub(crate) fn file_route_view(&self, route: u8) -> Self {
        self.view(
            self.rows()
                .filter(|&row| self.table.file_route(row) == route)
                .collect(),
        )
    }

    pub(super) fn from_views(
        filtered_rows: Vec<usize>,
        raw: impl IntoIterator<Item = DirectoryEntryRecord>,
        errors: DirectoryReadErrors,
        cells: Vec<Option<CheapAnchorCell>>,
    ) -> (Self, Self) {
        let mut table = Self::build_table(raw);
        debug_assert!(cells.is_empty() || cells.len() == table.paths.len());
        table.relation_anchor_cells = cells;
        table.scan_errors = errors.into_messages();
        let table = Arc::new(table);
        (
            Self {
                table: Arc::clone(&table),
                selected_rows: Some(Arc::new(filtered_rows)),
            },
            Self {
                table,
                selected_rows: None,
            },
        )
    }

    pub(crate) fn build_table(
        records: impl IntoIterator<Item = DirectoryEntryRecord>,
    ) -> DirectorySnapshotTable {
        let records = records.into_iter();
        let capacity = records.size_hint().0;
        let mut table = DirectorySnapshotTable {
            scan_errors: Vec::new(),
            paths: Vec::with_capacity(capacity),
            sizes: Vec::with_capacity(capacity),
            mtimes_ns: Vec::with_capacity(capacity),
            relation_anchors: Vec::with_capacity(capacity),
            relation_anchor_cells: Vec::new(),
            routes: Vec::with_capacity(capacity),
        };
        for record in records {
            let route = filesystem_file_route(record.is_dir, record.relation_anchor.as_ref());
            table.paths.push(record.path);
            table.sizes.push(record.size);
            table.mtimes_ns.push(record.mtime_ns);
            table.relation_anchors.push(record.relation_anchor);
            table
                .routes
                .push(route | u8::from(record.relation_member_eligible) * RELATION_ELIGIBLE);
        }
        table
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = (&str, bool, Option<u64>, Option<u64>)> {
        self.rows().map(|row| {
            (
                self.table.paths[row].as_str(),
                self.table.is_dir(row),
                self.table.sizes[row],
                self.table.mtimes_ns[row],
            )
        })
    }

    pub(crate) fn without_path_keys(&self, excluded: &HashSet<String>) -> Self {
        if excluded.is_empty() {
            return self.clone();
        }
        self.view(
            self.rows()
                .filter(|&row| {
                    !excluded.contains(&crate::path_keys::path_key(&self.table.paths[row]))
                })
                .collect(),
        )
    }
}

fn filesystem_file_route(is_dir: bool, fact: Option<&CheapAnchor>) -> u8 {
    if is_dir {
        return DIRECTORY_ROUTE;
    }
    let Some(fact) = fact else {
        return FILE_ROUTE_RESIDUAL;
    };
    let Some(anchor) = fact.anchor() else {
        return if fact.bytes_read() >= 512 && fact.reject_mask() & FORMAT_REJECT_TAR == 0 {
            FILE_ROUTE_DETECTION
        } else {
            FILE_ROUTE_RESIDUAL
        };
    };
    // PE facts authorize Relations refinement; they never terminate discovery.
    if anchor.pe_state != crate::scan::pe_overlay::PeState::None
        || matches!(anchor.format, "rar" | "7z" | "zip")
    {
        return FILE_ROUTE_RELATIONS;
    }
    if matches!(
        anchor.format,
        "tar" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "enc"
    ) {
        return FILE_ROUTE_DETECTION;
    }
    if anchor.bytes_read >= 512 && anchor.format_reject_mask & FORMAT_REJECT_TAR == 0 {
        return FILE_ROUTE_DETECTION;
    }
    FILE_ROUTE_RESIDUAL
}

pub(crate) fn filesystem_logical_name(path: &str) -> String {
    let filename = path
        .rsplit(|ch| ch == '/' || ch == '\\')
        .next()
        .unwrap_or(path);
    // The logical name becomes the output directory name.  Keeping the
    // (possibly disguised) extension would name the directory exactly like
    // the archive beside it and force a numbered collision name.
    let logical = crate::relations::get_logical_name(filename, true);
    if logical.is_empty() {
        filename.to_string()
    } else {
        logical
    }
}

struct DirectoryScanRecords {
    filtered: Vec<usize>,
    raw: Vec<DirectoryEntryRecord>,
    errors: DirectoryReadErrors,
}

#[derive(Debug, Clone)]
pub(crate) struct OutputFileRecord {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) status: u8,
    pub(crate) mtime_ns: Option<u64>,
    pub(crate) magic: Box<[u8]>,
}

pub(crate) struct NativeWorkerManifest {
    files: ManifestFiles,
    complete: bool,
    total_size: u64,
}

enum ManifestFiles {
    Summary(usize),
    Rows(Arc<Vec<OutputFileRecord>>),
}

impl NativeWorkerManifest {
    pub(crate) fn from_parts(
        files: Vec<OutputFileRecord>,
        complete: bool,
        total_size: u64,
    ) -> Self {
        // The immutable table owns this fact. Consumers must not repeatedly
        // walk every row, or trust a complete summary with incomplete rows.
        let complete = complete && files.iter().all(|item| item.status == 1);
        Self {
            files: ManifestFiles::Rows(Arc::new(files)),
            complete,
            total_size,
        }
    }

    pub(super) fn summary(file_count: usize, complete: bool, total_size: u64) -> Self {
        Self { files: ManifestFiles::Summary(file_count), complete, total_size }
    }

    #[cfg(test)]
    pub(crate) fn records(&self) -> Option<&Arc<Vec<OutputFileRecord>>> {
        match &self.files {
            ManifestFiles::Summary(_) => None,
            ManifestFiles::Rows(rows) => Some(rows),
        }
    }

    #[cfg(test)]
    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn into_output_stats(self, root: &str, collect_rows: bool) -> Option<OutputStats> {
        if !self.complete {
            return None;
        }
        let (file_count, inventory) = match self.files {
            ManifestFiles::Summary(count) if !collect_rows => (count, None),
            ManifestFiles::Summary(_) => return None,
            ManifestFiles::Rows(files) => (files.len(), collect_rows.then(|| NativeOutputInventory {
                root: root.to_owned(),
                files: OutputInventoryFiles::Manifest(files),
            })),
        };
        Some(OutputStats { file_count: file_count as u64, total_size: self.total_size, inventory })
    }
}

#[derive(Default)]
pub(crate) struct OutputStats {
    pub(crate) file_count: u64,
    pub(crate) total_size: u64,
    pub(crate) inventory: Option<NativeOutputInventory>,
}

pub(crate) struct NativeOutputInventory {
    root: String,
    files: OutputInventoryFiles,
}

enum OutputInventoryFiles {
    Disk(OutputTreeInventory),
    Manifest(Arc<Vec<OutputFileRecord>>),
}

impl NativeOutputInventory {
    pub(crate) fn root(&self) -> &str {
        &self.root
    }
    pub(crate) fn build_directory_snapshots(
        self,
        options: &NativeDirectoryScanOptions,
    ) -> std::io::Result<(NativeDirectorySnapshot, NativeDirectorySnapshot)> {
        let root = lexical_normalize_path(Path::new(&self.root));
        let (mut files, directory_ends, manifest_rows, deduplicate_paths, errors) = match self.files {
            OutputInventoryFiles::Disk(inventory) => {
                (inventory.files, Some(inventory.directory_ends), None, inventory.lossy_paths, inventory.errors)
            }
            OutputInventoryFiles::Manifest(manifest) => {
                let mut records = Vec::with_capacity(manifest.len());
                let mut item_indices = Vec::with_capacity(manifest.len());
                for (index, item) in manifest.iter().enumerate() {
                    let Some(path) = inventory_file_path(&root, item) else {
                        continue;
                    };
                    records.push(output_file_record(path_to_string(&path), item.size, item.mtime_ns));
                    item_indices.push(index);
                }
                (records, None, Some((manifest, item_indices)), true, DirectoryReadErrors::default())
            }
        };
        let (directories, filtered) = build_inventory_snapshot_views(
            &root,
            &mut files,
            directory_ends,
            manifest_rows,
            &options.options,
            deduplicate_paths,
        );
        populate_relation_anchors_cached(&mut files, &[], Some(&self.root));
        Ok(NativeDirectorySnapshot::from_views(
            filtered,
            // Directory rows precede files in both views. Consume the two
            // buffers directly instead of copying every file into one Vec.
            directories.into_iter().chain(files),
            errors,
            Vec::new(),
        ))
    }
}

impl NativeDirectorySnapshot {
    pub(crate) fn scan_errors(&self) -> Vec<DirectoryReadError> {
        self.table.scan_errors.clone()
    }
}

#[derive(Clone)]
struct DirectoryScanOptions {
    scope: Option<crate::scan::scope::NativeDiscoveryScope>,
    relation_stem: Option<String>,
    blacklist_rules: Vec<Arc<PathRule>>,
    whitelist_rules: Vec<Arc<PathRule>>,
    size_ranges: Vec<NativeNumericRange>,
    mtime_ranges: Vec<NativeNumericRange>,
}

#[derive(Clone, Copy)]
struct NativeNumericRange {
    gt: Option<u64>,
    gte: Option<u64>,
    lt: Option<u64>,
    lte: Option<u64>,
    eq: Option<u64>,
}

pub(crate) type NumericRangeTuple = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);

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

impl DirectoryScanOptions {
    fn has_directory_rules(&self) -> bool {
        self.blacklist_rules
            .iter()
            .chain(&self.whitelist_rules)
            .any(|rule| rule.has_directory_rules())
    }

    fn new(
        blacklist_rules: Vec<NativePathRule>,
        size_ranges: Vec<NumericRangeTuple>,
        mtime_ranges: Vec<NumericRangeTuple>,
        whitelist_rules: Vec<NativePathRule>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            scope: None,
            relation_stem: None,
            blacklist_rules: blacklist_rules
                .iter()
                .map(|rule| Arc::clone(&rule.rule))
                .collect(),
            whitelist_rules: whitelist_rules
                .iter()
                .map(|rule| Arc::clone(&rule.rule))
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

#[derive(Clone)]
pub(crate) struct NativeDirectoryScanOptions {
    options: DirectoryScanOptions,
}

impl NativeDirectoryScanOptions {
    pub(crate) fn can_share_recursive_context(&self) -> bool {
        self.options.size_ranges.is_empty() && !self.options.has_directory_rules()
    }

    pub(crate) fn new(
        blacklist_rules: Vec<NativePathRule>,
        size_ranges: Vec<NumericRangeTuple>,
        mtime_ranges: Vec<NumericRangeTuple>,
        whitelist_rules: Vec<NativePathRule>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            options: DirectoryScanOptions::new(
                blacklist_rules,
                size_ranges,
                mtime_ranges,
                whitelist_rules,
            )?,
        })
    }

    pub(crate) fn catalog_update(
        &self,

        state: &NativeWatchCatalog,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        changed: Option<&str>,
    ) -> std::io::Result<Vec<DirectoryReadError>> {
        Ok(update_catalog(self, state, scope, changed, false, false)?.0)
    }

    pub(crate) fn catalog_refresh(
        &self,

        state: &NativeWatchCatalog,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        changed: Option<&str>,
    ) -> std::io::Result<(Vec<DirectoryReadError>, Vec<String>)> {
        update_catalog(self, state, scope, changed, true, false)
    }

    // Adopt the observed content generation without publishing new candidates.
    // Unlike output publication this keeps ordinary scope/ownership filtering.
    pub(crate) fn catalog_baseline(
        &self, state: &NativeWatchCatalog,
        scope: &crate::scan::scope::NativeDiscoveryScope, changed: Option<&str>,
    ) -> std::io::Result<Vec<DirectoryReadError>> {
        Ok(update_catalog(self, state, scope, changed, false, true)?.0)
    }

    pub(crate) fn catalog_snapshot(
        &self,

        state: &NativeWatchCatalog,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        stem: &str,
        is_target: impl Fn(&str) -> bool,
    ) -> std::io::Result<(NativeDirectorySnapshot, NativeDirectorySnapshot)> {
        state.validate_generated_keys(scope, |table| {
            table.buckets.get(stem).into_iter().flat_map(|bucket| bucket.iter())
                .filter(|key| table.generated.contains_key(key.as_ref())).cloned().collect()
        }, None)?;
        let (filtered, raw) = (|| {
            let root = Path::new(&scope.root);
            let mut filter_scratch = PathFilterScratch::new(&self.options);
            let mut directory_cache = HashMap::new();
            let (mut raw, mut cells): (Vec<_>, Vec<_>) = {
                let mut data = state.catalogs.lock().unwrap_or_else(|e| e.into_inner());
                let mut records = Vec::new();
                let mut cells = Vec::new();
                if let Some(catalog) = data.scopes.get_mut(&crate::path_keys::path_key(&scope.root)) {
                    if let Some(bucket) = catalog.buckets.get(stem) {
                        for key in bucket.iter() {
                            let Some(row) = catalog.rows.get_mut(key) else {
                                continue;
                            };
                            let mut record = row.record();
                            let in_scope = scope.contains_key(key);
                            if (in_scope || catalog.generated.contains_key(key)) && !state.is_owned(&record.path) {
                                let generated_root = Path::new(&record.path).parent().unwrap_or(root);
                                let root = if in_scope { root } else { generated_root };
                                record.relation_member_eligible = !file_under_rejected_directory(
                                    Path::new(&record.path),
                                    root,
                                    &self.options,
                                    &mut filter_scratch,
                                    &mut directory_cache,
                                ) && !file_rejected_by_path(
                                    Path::new(&record.path),
                                    root,
                                    &self.options,
                                    &mut filter_scratch,
                                ) && numeric_ranges_allow(
                                    &self.options.mtime_ranges,
                                    record.mtime_ns,
                                );
                                cells.push(record.relation_member_eligible.then(|| {
                                    Arc::clone(row.cheap_anchor.get_or_insert_with(Default::default))
                                }));
                                records.push(record);
                            }
                        }
                    }
                }
                (records, cells)
            };
            for (record, cell) in raw.iter_mut().zip(&mut cells) {
                if exclude_unready_watch_peer(record, &is_target) {
                    *cell = None;
                }
            }
            let mut accepted = HashSet::new();
            let size_ranges = &self.options.size_ranges;
            if !size_ranges.is_empty() {
                for row in &raw {
                    if row.relation_member_eligible && numeric_ranges_allow(size_ranges, row.size) {
                        accepted.extend(crate::relations::relations_size_filter_split_family_keys(
                            &row.path,
                        ));
                    }
                }
            }
            let filtered = raw
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    r.relation_member_eligible
                        && (numeric_ranges_allow(size_ranges, r.size)
                            || (!accepted.is_empty()
                                && crate::relations::relations_size_filter_split_family_keys(&r.path)
                                    .iter()
                                    .any(|k| accepted.contains(k))))
                })
                .map(|(index, _)| index)
                .collect();
            populate_relation_anchors_cached(&mut raw, &cells, Some(&scope.root));
            NativeDirectorySnapshot::from_views(filtered, raw, DirectoryReadErrors::report(), cells)
        })();
        Ok((filtered, raw))
    }

    /// Watch recovery uses its catalog, including generated dependencies.
    /// Foreground recovery refreshes filesystem names and reuses unchanged heads.
    pub(crate) fn refresh_relation_bucket(
        &self,

        scope: &crate::scan::scope::NativeDiscoveryScope,
        seed: &str,
        previous: &NativeDirectorySnapshot,
        state: Option<&NativeWatchCatalog>,
        watch: bool,
    ) -> std::io::Result<(NativeDirectorySnapshot, NativeDirectorySnapshot)> {
        let stem = catalog_stem(seed);
        let seed_key = watch.then(|| crate::path_keys::path_key(seed));
        let is_target = |key: &str| seed_key.as_deref() == Some(key);
        if let Some(state) = state {
            return self.catalog_snapshot(state, scope, &stem, is_target);
        }
        let (filtered, raw) = (|| {
            let scope = scope.clone();
            let mut options = self.options.clone();
            options.scope = Some(scope.clone());
            options.relation_stem = Some(stem);
            let mut records = scan_directory_views(&scope.root, scope.max_depth, &options)?;
            if watch {
                records.exclude_unready_watch_peers(&is_target);
            }
            let live_paths: HashSet<&str> = records
                .raw
                .iter()
                .filter(|record| record.relation_member_eligible)
                .map(|record| record.path.as_str())
                .collect();
            let old: HashMap<&str, usize> = previous
                .rows()
                .filter(|&row| live_paths.contains(previous.table.paths[row].as_str()))
                .map(|row| (previous.table.paths[row].as_str(), row))
                .collect();
            drop(live_paths);
            for record in &mut records.raw {
                if !record.relation_member_eligible {
                    continue;
                }
                if let Some(&row) = old.get(record.path.as_str()) {
                    if record.size.is_some()
                        && record.mtime_ns.is_some()
                        && record.size == previous.table.sizes[row]
                        && record.mtime_ns == previous.table.mtimes_ns[row]
                    {
                        record.relation_anchor = previous.table.relation_anchors[row]
                            .as_ref()
                            .filter(|anchor| anchor.reusable())
                            .cloned();
                    }
                }
            }
            populate_relation_anchors(&mut records.raw);
            Ok::<_, std::io::Error>(NativeDirectorySnapshot::from_views(
                records.filtered,
                records.raw,
                records.errors,
                Vec::new(),
            ))
        })()?;
        Ok((filtered, raw))
    }

    pub(crate) fn scan_scope(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        watch_target: Option<&dyn Fn(&str) -> bool>,
    ) -> std::io::Result<(NativeDirectorySnapshot, NativeDirectorySnapshot)> {
        let mut options = self.options.clone();
        options.scope = Some(scope.clone());
        let mut records = scan_directory_views(&scope.root, scope.max_depth, &options)?;
        if let Some(is_target) = watch_target {
            records.exclude_unready_watch_peers(is_target);
        }
        populate_relation_anchors_cached(&mut records.raw, &[], Some(&scope.root));
        Ok(NativeDirectorySnapshot::from_views(
            records.filtered,
            records.raw,
            records.errors,
            Vec::new(),
        ))
    }
}

impl DirectoryScanRecords {
    fn exclude_unready_watch_peers(&mut self, is_target: &dyn Fn(&str) -> bool) {
        for record in &mut self.raw {
            exclude_unready_watch_peer(record, is_target);
        }
        self.filtered.retain(|&row| self.raw[row].relation_member_eligible || self.raw[row].is_dir);
    }
}

// A readable peer can supply bytes while its writer is still open. Leave the
// completeness check to archive discovery. A live download under a staging
// name can still be renamed for publication, so wait for its rename or close.
fn exclude_unready_watch_peer(record: &mut DirectoryEntryRecord, is_target: &dyn Fn(&str) -> bool) -> bool {
    if record.is_dir || !record.relation_member_eligible || is_target(&crate::path_keys::path_key(&record.path)) {
        return false;
    }
    let staging = Path::new(&record.path).extension().and_then(|value| value.to_str())
        .is_some_and(|ext| ["crdownload", "downloading", "part", "tmp"]
            .iter().any(|staging| ext.eq_ignore_ascii_case(staging)));
    let unavailable = match crate::filesystem::watch_file_is_readable(&record.path, !staging) {
        Ok(ready) => !ready,
        Err(error) => matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory),
    };
    if unavailable {
        record.relation_member_eligible = false;
        record.relation_anchor = None;
    }
    unavailable
}

/// Filesystem target classification only; archive analysis remains in discovery.
pub(crate) fn classify_scan_targets(paths: &[String]) -> (Vec<u8>, DirectoryReadErrors) {
    let mut kinds = Vec::with_capacity(paths.len());
    let mut errors = DirectoryReadErrors::report();
    for path in paths {
        match fs::metadata(path) {
            Ok(metadata) => kinds.push(if metadata.is_file() {
                1
            } else if metadata.is_dir() {
                2
            } else {
                3
            }),
            Err(error) => {
                kinds.push(0);
                errors.push(Path::new(path), "metadata", error);
            }
        }
    }
    (kinds, errors)
}

fn build_inventory_snapshot_views(
    root: &Path,
    raw_files: &mut [DirectoryEntryRecord],
    directory_ends: Option<Vec<usize>>,
    manifest_rows: Option<(Arc<Vec<OutputFileRecord>>, Vec<usize>)>,
    options: &DirectoryScanOptions,
    deduplicate_paths: bool,
) -> (Vec<DirectoryEntryRecord>, Vec<usize>) {
    let mut pre_mtime_accepted = vec![false; raw_files.len()];
    let mut size_accepted_split_families = HashSet::new();
    let mut size_deferred = Vec::new();
    let mut filter_scratch = PathFilterScratch::new(&options);
    let mut directory_rejections = HashMap::new();
    let check_directories = options.has_directory_rules();

    for (index, record) in raw_files.iter_mut().enumerate() {
        let path = Path::new(&record.path);
        if file_rejected_by_path(path, root, options, &mut filter_scratch)
            || (check_directories
                && file_under_rejected_directory(
                    path,
                    root,
                    options,
                    &mut filter_scratch,
                    &mut directory_rejections,
                ))
        {
            record.relation_member_eligible = false;
            continue;
        }
        let family_keys = if options.size_ranges.is_empty() {
            Vec::new()
        } else {
            crate::relations::relations_size_filter_split_family_keys(&record.path)
        };
        if numeric_ranges_allow(&options.size_ranges, record.size) {
            pre_mtime_accepted[index] = true;
            size_accepted_split_families.extend(family_keys);
        } else if !family_keys.is_empty() {
            size_deferred.push((index, family_keys));
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
        if record.relation_member_eligible && record.size == Some(0) {
            record.relation_anchor = Some(probe_volume_anchor_from_head(&record.path, 0, &[]));
        }
    }

    if let Some((manifest, indices)) = manifest_rows {
        for (record, index) in raw_files.iter_mut().zip(indices) {
            let item = &manifest[index];
            if record.relation_member_eligible
                && record.relation_anchor.is_none()
                && item.magic.len() >= item.size.min(512) as usize
            {
                record.relation_anchor = Some(probe_volume_anchor_from_head(
                    &record.path,
                    item.size,
                    &item.magic,
                ));
            }
        }
        // The path projection and prefix probes now own everything needed
        // from the wire rows. Free them before building the snapshot views.
        drop(manifest);
    }

    // Keep parents of files accepted before the final mtime filter, even
    // when that final filter removes every file in a directory.
    let (directories, mut filtered) = if let Some(directory_ends) = directory_ends {
        let mut start = 0;
        ancestor_directory_records(
            root,
            directory_ends.into_iter().map(|end| {
                let accepted = pre_mtime_accepted[start..end].contains(&true);
                let file = &raw_files[start];
                start = end;
                (file, accepted)
            }),
        )
    } else {
        ancestor_directory_records(
            root,
            raw_files.iter().zip(pre_mtime_accepted.iter().copied()),
        )
    };
    let file_start = directories.len();
    let accepted = raw_files
        .iter()
        .enumerate()
        .filter(|(index, record)| pre_mtime_accepted[*index] && record.relation_member_eligible);
    if !deduplicate_paths {
        filtered.extend(accepted.map(|(index, _)| file_start + index));
    } else {
        // Manifest entries and lossy filesystem paths can collide.
        // Preserve the last-record projection for these aliases.
        let file_rows: HashMap<_, _> = raw_files
            .iter()
            .enumerate()
            .map(|(index, record)| (record.path.as_str(), file_start + index))
            .collect();
        filtered.extend(accepted.map(|(_, record)| file_rows[record.path.as_str()]));
    }
    (directories, filtered)
}

fn output_file_record(path: String, size: u64, mtime_ns: Option<u64>) -> DirectoryEntryRecord {
    DirectoryEntryRecord {
        path,
        is_dir: false,
        size: Some(size),
        mtime_ns,
        relation_member_eligible: true,
        relation_anchor: None,
    }
}

fn inventory_file_path(root: &Path, item: &OutputFileRecord) -> Option<PathBuf> {
    let path = Path::new(&item.path);
    let normalized = if path.is_absolute() {
        lexical_normalize_path(path)
    } else {
        lexical_normalize_path(&root.join(path))
    };
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
    if path.starts_with(root) {
        return true;
    }
    let mut path_components = path.components();
    root.components().all(|root_component| {
        path_components.next().is_some_and(|path_component| {
            crate::path_keys::case_key(&path_component.as_os_str().to_string_lossy())
                == crate::path_keys::case_key(&root_component.as_os_str().to_string_lossy())
        })
    })
}

#[cfg(not(windows))]
fn path_is_within_root(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

fn ancestor_directory_records<'a>(
    root: &Path,
    files: impl Iterator<Item = (&'a DirectoryEntryRecord, bool)>,
) -> (Vec<DirectoryEntryRecord>, Vec<usize>) {
    let mut directories = HashMap::new();
    for (file, accepted) in files {
        for directory in Path::new(&file.path).ancestors().skip(1) {
            if directory == root {
                break;
            }
            match directories.entry(directory) {
                Entry::Vacant(entry) => {
                    if !path_is_within_root(directory, root) {
                        break;
                    }
                    entry.insert(accepted);
                }
                Entry::Occupied(mut entry) if accepted && !*entry.get() => {
                    entry.insert(true);
                }
                // This directory's ancestors already have the same visibility.
                Entry::Occupied(_) => break,
            }
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_cached_key(|(path, _)| {
        (
            path.components().count(),
            crate::path_keys::case_key(&path.to_string_lossy()),
        )
    });
    let mut raw = Vec::with_capacity(directories.len());
    let mut filtered = Vec::new();
    for (path, accepted) in directories {
        if accepted {
            filtered.push(raw.len());
        }
        raw.push(DirectoryEntryRecord {
            path: path_to_string(path),
            is_dir: true,
            ..Default::default()
        });
    }
    (raw, filtered)
}

pub(crate) fn scan_output_stats(output_dir: &str, collect_rows: bool) -> OutputStats {
    let root = Path::new(output_dir);
    let mut stats = OutputStats::default();
    let mut inventory = collect_rows.then(OutputTreeInventory::default);
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => walk_output_tree(root, &mut stats, inventory.as_mut()),
        Ok(_) => {
            if let Some(inventory) = &mut inventory {
                inventory.errors.push(root, "read_dir", std::io::ErrorKind::NotADirectory.into());
            }
        }
        Err(error) => {
            if let Some(inventory) = &mut inventory {
                inventory.errors.push(root, "metadata", error);
            }
        }
    }
    stats.inventory = inventory.map(|inventory| NativeOutputInventory {
        root: output_dir.to_owned(),
        files: OutputInventoryFiles::Disk(inventory),
    });
    stats
}

#[derive(Default)]
struct OutputTreeInventory {
    errors: DirectoryReadErrors,
    files: Vec<DirectoryEntryRecord>,
    directory_ends: Vec<usize>,
    lossy_paths: bool,
}

fn walk_output_tree(root: &Path, stats: &mut OutputStats, mut inventory: Option<&mut OutputTreeInventory>) {
    let normalized_root = inventory.as_ref().map(|_| lexical_normalize_path(root));
    let mut pending = vec![root.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) => {
                if let Some(inventory) = &mut inventory {
                    inventory.errors.push(&current, "read_dir", error);
                }
                continue;
            }
        };
        // Let Path supply the correct separator once for this directory.
        let prefix = normalized_root.as_ref().map(|normalized_root| {
            current.strip_prefix(root)
                .map(|path| lexical_normalize_path(&normalized_root.join(path)))
                .unwrap_or_else(|_| normalized_root.clone())
                .join("")
        });
        let prefix = prefix.as_ref().map(|prefix| prefix.to_string_lossy());
        let first_file = inventory.as_mut().zip(prefix.as_ref()).map(|(inventory, prefix)| {
            inventory.lossy_paths |= matches!(prefix, std::borrow::Cow::Owned(_));
            inventory.files.len()
        });
        for item in entries {
            let entry = match item {
                Ok(entry) => entry,
                Err(error) => {
                    if let Some(inventory) = &mut inventory {
                        inventory.errors.push(&current, "read_dir_entry", error);
                    }
                    continue;
                }
            };
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    if let Some(inventory) = &mut inventory {
                        inventory.errors.push(&entry.path(), "metadata", error);
                    }
                    continue;
                }
            };
            #[cfg(windows)]
            if is_reparse_point(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let size = metadata.len();
            stats.file_count += 1;
            stats.total_size = stats.total_size.saturating_add(size);
            if let Some((inventory, prefix)) = inventory.as_mut().zip(prefix.as_ref()) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                inventory.lossy_paths |= matches!(name, std::borrow::Cow::Owned(_));
                let mut path = String::with_capacity(prefix.len() + name.len());
                path.push_str(prefix);
                path.push_str(&name);
                inventory.files.push(output_file_record(path, size, metadata_mtime_ns(&metadata)));
            }
        }
        if let Some((inventory, _)) = inventory.as_mut().zip(first_file)
            .filter(|(inventory, first_file)| inventory.files.len() != *first_file) {
            // Direct children are contiguous; ancestor projection visits a
            // directory once even if it contains many accepted files.
            inventory.directory_ends.push(inventory.files.len());
        }
    }
}

pub(crate) fn walk_can_reach(root: &str, target: &str) -> bool {
    walk_reachable_keys(target).any(|key| key == root)
}

pub(crate) fn walk_reachable_keys(target: &str) -> impl Iterator<Item = String> + '_ {
    // A scan can start at a reparse point, but cannot reach it from its parent.
    // Check the previous component only when the caller wants to walk higher.
    Path::new(target).ancestors().scan(None::<&Path>, |previous, path| {
        if previous.replace(path).is_some_and(|child| {
            fs::symlink_metadata(child).map_or(true, |metadata| is_reparse_point(&metadata))
        }) {
            return None;
        }
        let mut key = crate::path_keys::path_key(&path.to_string_lossy());
        key.truncate(key.trim_end_matches('\\').len());
        Some(key)
    }).fuse()
}

pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.file_type().is_symlink()
}

fn populate_relation_anchors(records: &mut [DirectoryEntryRecord]) {
    populate_relation_anchors_cached(records, &[], None);
}

fn populate_relation_anchors_cached(
    records: &mut [DirectoryEntryRecord],
    cells: &[Option<CheapAnchorCell>],
    root: Option<&str>,
) {
    let needs_anchor = |record: &DirectoryEntryRecord| {
        !record.is_dir && record.relation_member_eligible && record.relation_anchor.is_none()
    };
    if !records.iter().any(needs_anchor) {
        return;
    }
    let cancellation = crate::io::cancellation::Cancellation::current();
    cheap_fast_probe_pool().install(|| {
        // The calling Rayon worker can run cleanup while waiting for this pool.
        // Keep the guard on the probe worker so cleanup can wait for it safely.
        let scope = root.and_then(|root| NativeReadScope::new(Path::new(root)).ok());
        records
            .par_iter_mut()
            .enumerate()
            .filter(|(_, record)| needs_anchor(record))
            .for_each(|(index, record)| {
                // A worker may steal another root's probe while it prepares
                // its own root. Use the cancellation scope of this probe.
                let anchor = cancellation.run(|| match record.size {
                    Some(size) => probe_volume_anchor_record_cheap(
                        &record.path,
                        size,
                        cells.get(index).and_then(Option::as_ref),
                        scope.as_ref(),
                    ),
                    // Without a size column the full anchor owns the probed size.
                    None => CheapAnchor::Full(Arc::new(probe_volume_anchor_path_cheap(&record.path))),
                });
                record.relation_anchor = Some(anchor);
            });
    });
}

fn scan_directory_views(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
) -> std::io::Result<DirectoryScanRecords> {
    scan_directory_impl(root_path, max_depth, options, None, true)
}

fn scan_directory_impl(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
    known_metadata: Option<fs::Metadata>,
    collect_filtered: bool,
) -> std::io::Result<DirectoryScanRecords> {
    let root = PathBuf::from(root_path);
    let filter_root = options
        .scope
        .as_ref()
        .map(|s| Path::new(&s.root))
        .unwrap_or(&root);
    let mut errors = DirectoryReadErrors::default();
    let metadata = match known_metadata
        .map(Ok)
        .unwrap_or_else(|| fs::metadata(&root))
    {
        Ok(metadata) => Some(metadata),
        Err(error) => {
            errors.push(&root, "metadata", error);
            None
        }
    };
    if metadata.is_none() {
        return Ok(DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
            errors,
        });
    }
    if options
        .scope
        .as_ref()
        .is_some_and(|scope| !scope.contains(root_path))
    {
        return Ok(DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
            errors,
        });
    }
    let mut filter_scratch = PathFilterScratch::new(options);
    let mut directory_cache = HashMap::new();
    if root != filter_root
        && (metadata.as_ref().is_some_and(|metadata| metadata.is_dir())
            && dir_rejected(&root, filter_root, options, &mut filter_scratch)
            || file_under_rejected_directory(
                &root,
                filter_root,
                options,
                &mut filter_scratch,
                &mut directory_cache,
            ))
    {
        return Ok(DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
            errors,
        });
    }
    if metadata.as_ref().is_some_and(|metadata| metadata.is_file()) {
        let metadata = metadata.as_ref().unwrap();
        let match_root = if options.scope.is_some() {
            filter_root
        } else {
            root.parent().unwrap_or_else(|| Path::new(""))
        };
        let size = metadata.len();
        let mtime_ns = metadata_mtime_ns(metadata);
        let eligible = collect_filtered
            && !file_rejected_by_path(&root, match_root, options, &mut filter_scratch)
            && numeric_ranges_allow(&options.mtime_ranges, mtime_ns);
        // Raw and filtered views describe the same observation. File events
        // already supplied metadata; repeated queries can also split the views
        // across two different writes during a download.
        let record = DirectoryEntryRecord {
            path: path_to_string(&root),
            is_dir: false,
            size: Some(size),
            mtime_ns,
            relation_member_eligible: eligible,
            relation_anchor: None,
        };
        let accepted = eligible && numeric_ranges_allow(&options.size_ranges, Some(size));
        let filtered = if accepted { vec![0] } else { Vec::new() };
        return Ok(DirectoryScanRecords {
            filtered,
            raw: vec![record],
            errors,
        });
    }

    let mut records = Vec::new();
    let mut raw_records = Vec::new();
    let mut size_accepted_split_families = HashSet::new();
    let mut size_deferred_split_records = Vec::new();
    let exclusion_scope = options
        .scope
        .as_ref()
        .filter(|scope| scope.has_exclusions());
    let start_depth = options
        .scope
        .as_ref()
        .and_then(|scope| scope.directory_depth(root_path))
        .unwrap_or(0);
    if max_depth.is_some_and(|limit| start_depth > limit) {
        return Ok(DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
            errors,
        });
    }
    let mut stack = vec![(root.clone(), start_depth)];
    while let Some((dir, depth)) = stack.pop() {
        let read_dir = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(&dir, "read_dir", error);
                continue;
            }
        };
        let mut child_dirs = Vec::new();
        for item in read_dir {
            let entry = match item {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(&dir, "read_dir_entry", error);
                    continue;
                }
            };
            let path = entry.path();
            if exclusion_scope.is_some_and(|scope| scope.excludes(&path.to_string_lossy())) {
                continue;
            }
            let outside_relation = options
                .relation_stem
                .as_ref()
                .is_some_and(|stem| catalog_stem(&path.to_string_lossy()) != *stem);
            // Windows caches file_type in the directory entry. Skip unrelated
            // files before building full metadata, but keep directories and
            // unknown types on the existing traversal/reparse-point path.
            // A failed type query also falls back to normal metadata handling.
            if outside_relation && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(&path, "metadata", error);
                    continue;
                }
            };
            #[cfg(windows)]
            if is_reparse_point(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                let rejected = max_depth.is_some_and(|limit| depth >= limit)
                    || dir_rejected(&path, filter_root, options, &mut filter_scratch);
                raw_records.push(DirectoryEntryRecord {
                    path: path_to_string(&path),
                    is_dir: true,
                    size: None,
                    mtime_ns: None,
                    relation_member_eligible: false,
                    relation_anchor: None,
                });
                if !rejected {
                    if collect_filtered {
                        records.push(raw_records.len() - 1);
                    }
                    child_dirs.push(path);
                }
                continue;
            }
            if outside_relation {
                continue;
            }

            let size = metadata.len();
            let mtime_ns = metadata_mtime_ns(&metadata);
            let hard_rejected = !collect_filtered || !metadata.is_file()
                || file_rejected_by_path(&path, filter_root, options, &mut filter_scratch)
                || !numeric_ranges_allow(&options.mtime_ranges, mtime_ns);
            let raw_file_index = raw_records.len();
            raw_records.push(DirectoryEntryRecord {
                path: path_to_string(&path),
                is_dir: false,
                size: Some(size),
                mtime_ns,
                relation_member_eligible: !hard_rejected,
                relation_anchor: None,
            });
            if hard_rejected {
                continue;
            }
            let split_family_keys = if options.size_ranges.is_empty() {
                Vec::new()
            } else {
                crate::relations::relations_size_filter_split_family_keys(
                    &raw_records[raw_file_index].path,
                )
            };
            if numeric_ranges_allow(&options.size_ranges, Some(size)) {
                size_accepted_split_families.extend(split_family_keys);
                records.push(raw_file_index);
            } else if !split_family_keys.is_empty() {
                size_deferred_split_records.push((raw_file_index, split_family_keys));
            }
        }

        child_dirs.sort();
        stack.extend(child_dirs.into_iter().rev().map(|child| (child, depth + 1)));
    }
    for (record, family_keys) in size_deferred_split_records {
        if family_keys
            .iter()
            .any(|key| size_accepted_split_families.contains(key))
        {
            records.push(record);
        }
    }
    Ok(DirectoryScanRecords {
        filtered: records,
        raw: raw_records,
        errors,
    })
}

struct PathFilterScratch {
    blacklist: Vec<PathRuleScratch>,
    whitelist: Vec<PathRuleScratch>,
}
impl PathFilterScratch {
    fn new(options: &DirectoryScanOptions) -> Self {
        Self {
            blacklist: options
                .blacklist_rules
                .iter()
                .map(|_| PathRuleScratch::default())
                .collect(),
            whitelist: options
                .whitelist_rules
                .iter()
                .map(|_| PathRuleScratch::default())
                .collect(),
        }
    }
}
fn dir_rejected(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    scratch: &mut PathFilterScratch,
) -> bool {
    path_rules_reject(path, root, true, options, scratch)
}
fn file_rejected_by_path(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    scratch: &mut PathFilterScratch,
) -> bool {
    path_rules_reject(path, root, false, options, scratch)
}
fn path_rules_reject(
    path: &Path,
    root: &Path,
    is_dir: bool,
    options: &DirectoryScanOptions,
    scratch: &mut PathFilterScratch,
) -> bool {
    if options.blacklist_rules.is_empty() && options.whitelist_rules.is_empty() {
        return false;
    }
    let candidate = FilterPath::new(path, root);
    options
        .blacklist_rules
        .iter()
        .zip(&mut scratch.blacklist)
        .any(|(rule, cache)| rule.rejects(&candidate, is_dir, false, cache))
        || options
            .whitelist_rules
            .iter()
            .zip(&mut scratch.whitelist)
            .any(|(rule, cache)| rule.rejects(&candidate, is_dir, true, cache))
}
fn file_under_rejected_directory(
    path: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    scratch: &mut PathFilterScratch,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    path.parent().is_some_and(|directory| {
        directory_rejected_cached(directory, root, options, scratch, cache)
    })
}
fn directory_rejected_cached(
    directory: &Path,
    root: &Path,
    options: &DirectoryScanOptions,
    scratch: &mut PathFilterScratch,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    if let Some(rejected) = cache.get(directory) {
        return *rejected;
    }
    if directory == root
        || crate::path_keys::path_key(&directory.to_string_lossy())
            == crate::path_keys::path_key(&root.to_string_lossy())
    {
        return false;
    }
    if !path_is_within_root(directory, root) {
        return true;
    }
    let rejected = directory
        .parent()
        .is_some_and(|parent| directory_rejected_cached(parent, root, options, scratch, cache))
        || dir_rejected(directory, root, options, scratch);
    cache.insert(directory.to_path_buf(), rejected);
    rejected
}

fn numeric_ranges_allow(ranges: &[NativeNumericRange], value: Option<u64>) -> bool {
    ranges.iter().all(|range| range.allows(value))
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_mtime_ns(metadata: &fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_nanos()).ok()
}

pub(crate) fn scope_file_paths(
    scope: &crate::scan::scope::NativeDiscoveryScope,
) -> std::io::Result<(Vec<PathBuf>, Vec<DirectoryReadError>)> {
    let mut options = DirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())?;
    options.scope = Some(scope.clone());
    let records = scan_directory_views(&scope.root, scope.max_depth, &options)?;
    Ok((
        records
            .raw
            .into_iter()
            .filter(|r| !r.is_dir)
            .map(|r| PathBuf::from(r.path))
            .collect(),
        records.errors.into_messages(),
    ))
}

/// One native path table with derived filename buckets and a disposable cache WAL.
pub(crate) struct NativeWatchCatalog {
    catalogs: Mutex<CatalogTables>,
    outputs: crate::watch_store::active_outputs::OutputReservations,
    store: Mutex<Option<super::catalog_store::CatalogStore>>,
    error: Mutex<Option<String>>,
}

struct CatalogTables {
    scopes: HashMap<String, ScopeCatalog>,
    revision: u64,
    committed: Option<u64>,
}

impl CatalogTables {
    // Inventory changes can invalidate an in-flight enumeration. Cache fills
    // and capacity changes don't change the inventory observed by the scan.
    fn edit(&mut self) -> &mut HashMap<String, ScopeCatalog> {
        self.revision = self.revision.wrapping_add(1);
        &mut self.scopes
    }
}

impl NativeWatchCatalog {
    pub(crate) fn new(
        outputs: &crate::watch_store::NativeWatchState,
        folder: Option<String>,
    ) -> Self {
        let mut catalogs = HashMap::new();
        let mut error = None;
        let store = folder.and_then(|folder| {
            match (|| super::catalog_store::CatalogStore::open(Path::new(&folder), &mut catalogs))()
            {
                Ok(store) => Some(store),
                Err(e) => {
                    error = Some(e.to_string());
                    None
                }
            }
        });
        Self {
            catalogs: Mutex::new(CatalogTables { scopes: catalogs, revision: 0, committed: None }),
            outputs: Arc::clone(&outputs.outputs),
            store: Mutex::new(store),
            error: Mutex::new(error),
        }
    }

    /// Publish settled output trees as ordinary inventory, never as arrivals.
    /// The catalog lock also excludes concurrent scans until all aliases have
    /// baselines and the process-local reservations have been released.
    pub(crate) fn publish_outputs(
        &self, paths: &[String], scopes: &[crate::scan::scope::NativeDiscoveryScope],
        options: &NativeDirectoryScanOptions, dependency_root: Option<&str>,
    ) -> std::io::Result<Vec<(String, String)>> {
        let records = crate::watch_store::active_outputs::records(&self.outputs, paths);
        if records.is_empty() { return Ok(Vec::new()); }
        let mut tables = self.catalogs.lock().unwrap_or_else(|e| e.into_inner());
        let catalogs = tables.edit();
        let mut published = Vec::new();
        for scope in scopes {
            let mut covered = HashSet::new();
            let root_key = crate::path_keys::path_key(&scope.root);
            let dependency = dependency_root == Some(scope.key());
            for (key, record) in &records {
                let contained = dependency || scope.contains_key(key);
                if !contained && !crate::watch_store::is_path_under(scope.key(), key) {
                    continue;
                }
                let path = record.aliases.iter().find(|path| crate::path_keys::path_key(path) == *key).unwrap().as_str();
                let (target, target_key) = if contained {
                    (path, key.as_str())
                } else {
                    (scope.root.as_str(), root_key.as_str())
                };
                if crate::path_keys::path_ancestors(target_key).any(|parent| covered.contains(parent)) {
                    continue;
                }
                // Ordinary recursive enumeration never descends through an
                // interior junction. Publish the physical alias, not both views.
                if Path::new(target).exists() && !walk_can_reach(scope.key(), target) {
                    // Dependency files use one canonical alias even outside ordinary enumeration.
                    if !dependency || key != &crate::path_keys::resolved_path_key(Path::new(path)) { continue; }
                }
                let prepared = scan_catalog(options, self, scope, target, true)?;
                let (errors, _) = apply_catalog_scan(self, scope, Some(target), false, true, false, prepared, catalogs)?;
                if !errors.is_empty() { return Err(std::io::Error::other(format!("output inventory publication failed: {errors:?}"))); }
                covered.insert(target_key.trim_end_matches('\\'));
                let mut buckets = HashSet::new();
                if let Some(table) = catalogs.get(scope.key()) {
                    for (_, row) in table.rows_at_or_under(target_key) {
                        if !row.is_dir() && buckets.insert(catalog_stem(row.name())) {
                            published.push((scope.root.clone(), row.path()));
                        }
                    }
                }
            }
        }
        // Persist ordinary observations before releasing visibility. A restart
        // can then ignore old USN writes even before the root cursor catches up.
        if let Some(store) = self.store.lock().unwrap().as_mut() { store.commit()?; }
        crate::watch_store::active_outputs::release(&self.outputs, &records);
        Ok(published)
    }

    pub(crate) fn candidate_paths(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
    ) -> Vec<String> {
        let root = crate::path_keys::path_key(&scope.root);
        let mut paths: Vec<_> = {
            let catalogs = self.catalogs.lock().unwrap_or_else(|error| error.into_inner());
            let Some(catalog) = catalogs.scopes.get(&root) else { return Vec::new(); };
            catalog.rows_at_or_under(scope.key())
                .filter(|(key, row)| row.persistent() && !row.is_dir() && scope.contains_key(key))
                .map(|(_, row)| row.path())
                .collect()
        };
        // Admission owns the fresh observation. The catalog supplies
        // paths only, without opening each file before the actual probe.
        paths.retain(|path| !self.is_owned(path));
        paths
    }

    pub(crate) fn generated_observation(&self, path: &str) -> Option<NativeWatchObservation> {
        let key = crate::path_keys::path_key(path);
        self.catalogs.lock().unwrap().scopes.values()
            .find_map(|table| table.generated.get(key.as_str()).map(GeneratedBaseline::observation))
    }
    pub(crate) fn dependency_contains(&self, scope: &crate::scan::scope::NativeDiscoveryScope, path: &str) -> bool {
        let key = crate::path_keys::path_key(path);
        self.catalogs.lock().unwrap().scopes.get(scope.key()).is_some_and(|table| {
            (scope.contains_key(&key) && table.rows.contains_key(key.as_str())) || table.generated.contains_key(key.as_str())
        })
    }

    pub(crate) fn generated_under(&self, scope: &crate::scan::scope::NativeDiscoveryScope, path: &str) -> bool {
        let key = crate::path_keys::path_key(path);
        self.catalogs.lock().unwrap().scopes.get(scope.key())
            .is_some_and(|table| !table.generated.is_empty() && table.generated_keys_under(key).next().is_some())
    }

    pub(crate) fn generated_paths(&self, scope: &crate::scan::scope::NativeDiscoveryScope) -> Vec<String> {
        self.catalogs.lock().unwrap().scopes.get(scope.key()).into_iter()
            .flat_map(|table| table.generated.keys().map(|key| table.rows[key].path())).collect()
    }

    pub(crate) fn validate_generated_paths(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        paths: Option<&HashSet<PathBuf>>,
        mut defer: impl FnMut(PromotionCompletion, String),
    ) -> std::io::Result<Vec<String>> {
        self.validate_generated_keys(scope, |table| {
            let Some(paths) = paths else {
                return table.generated.keys().cloned().collect();
            };
            let mut keys = HashSet::new();
            for path in paths {
                let key = crate::path_keys::path_key(&path.to_string_lossy());
                keys.extend(table.generated_keys_under(key).cloned());
            }
            keys.into_iter().collect()
        }, Some(&mut defer))
    }

    /// Exact-path receipts never follow a rename. Notifications, startup and
    /// dependency lookup all use this validator, including USN content reasons.
    fn validate_generated_keys(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        select_keys: impl FnOnce(&ScopeCatalog) -> Vec<Arc<str>>,
        mut defer: Option<&mut dyn FnMut(PromotionCompletion, String)>,
    ) -> std::io::Result<Vec<String>> {
        let baselines: Vec<_> = {
            let tables = self.catalogs.lock().unwrap();
            let Some(table) = tables.scopes.get(scope.key()) else { return Ok(Vec::new()); };
            if table.generated.is_empty() { return Ok(Vec::new()); }
            select_keys(table).into_iter().filter_map(|key| {
                let baseline = table.generated.get(key.as_ref())?.clone();
                let path = table.rows[&key].path();
                Some((key, path, baseline))
            }).collect()
        };
        let mut stale = Vec::new();
        for (key, path, before) in baselines {
            let invalid = match crate::postprocess::watch_candidate_for_path(Path::new(&path), Some(before.usn)) {
                Ok(Some(current)) => before.source_changed(&current),
                Ok(None) => true,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => true,
                Err(error) => {
                    let Some((promotion, defer)) = PromotionCompletion::from_error(&error).zip(defer.as_deref_mut()) else {
                        return Err(error);
                    };
                    defer(promotion, path);
                    continue;
                }
            };
            if invalid {
                stale.push((key, path, before));
            }
        }
        if stale.is_empty() {
            return Ok(Vec::new());
        }
        let mut guard = self.catalogs.lock().unwrap();
        let tables = guard.edit();
        let Some(table) = tables.get_mut(scope.key()) else { return Ok(Vec::new()); };
        let mut invalidated = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        for (key, path, before) in stale {
            // File I/O ran outside the catalog lock. Apply the result only
            // to the same path and baseline we observed.
            if table.generated.get(key.as_ref()) != Some(&before) || !table.rows[&key].matches_path(&path) {
                continue;
            }
            if scope.contains_key(&key) {
                table.generated.remove(key.as_ref());
                table.touch(&path);
                changed.push(key);
            } else {
                removed.push(key.to_string());
            }
            invalidated.push(path);
        }
        table.remove_many(removed.iter().map(String::as_str));
        if !removed.is_empty() || !changed.is_empty() {
            let rows = changed.iter().filter_map(|key| tables[scope.key()].row_view(key)).collect();
            self.persist(tables, super::catalog_store::DeltaView { scope: scope.key(), removed: &removed,
                rows, stamp: None }, false);
        }
        Ok(invalidated)
    }

    pub(crate) fn retire_consumed<'a>(&self, paths: impl Iterator<Item = &'a Path>) {
        let missing: Vec<_> = paths.filter(|path| matches!(path.try_exists(), Ok(false)))
            .map(|path| crate::path_keys::path_key(&path.to_string_lossy())).collect();
        if missing.is_empty() { return; }
        let mut guard = self.catalogs.lock().unwrap();
        let tables = guard.edit();
        let mut changes = Vec::new();
        for (scope, table) in tables.iter_mut() {
            let removed: Vec<_> = missing.iter().filter(|key| table.rows.contains_key(key.as_str())).cloned().collect();
            table.remove_many(removed.iter().map(String::as_str));
            if !removed.is_empty() { changes.push((scope.clone(), removed)); }
        }
        for (scope, removed) in changes {
            self.persist(tables, super::catalog_store::DeltaView { scope: &scope, removed: &removed, rows: Vec::new(), stamp: None }, false);
        }
    }
    pub(crate) fn observation(&self, path: &str) -> Option<NativeWatchObservation> {
        (|| {
            let key = crate::path_keys::path_key(path);
            self.catalogs.lock().unwrap().scopes.values().find_map(|table| {
                table
                    .rows
                    .get(key.as_str())?
                    .observation
                    .as_deref()
                    .cloned()
            })
        })()
    }

    pub(crate) fn remember_observation(
        &self,

        path: &str,
        size: u64,
        mtime: f64,
        file_id: &str,
        change_usn: i64,
        phase_boundary: bool,
    ) {
        (|| {
            let key = crate::path_keys::path_key(path);
            let mut guard = self.catalogs.lock().unwrap();
            let tables = guard.edit();
            let scope = tables
                .keys()
                .filter(|scope| {
                    !scope.is_empty()
                        && (key == scope.trim_end_matches('\\')
                            || key
                                .strip_prefix(scope.trim_end_matches('\\'))
                                .is_some_and(|tail| tail.starts_with('\\')))
                })
                .max_by_key(|scope| scope.len())
                .cloned()
                .unwrap_or_default();
            let table = tables.entry(scope).or_default();
            if let Some(row) = table.rows.get_mut(key.as_str()) {
                row.remember_observation(size, mtime, file_id, change_usn, phase_boundary);
                return;
            }
            table.insert_transient(
                Arc::from(key.as_str()),
                DirectoryEntryRecord {
                    path: path.to_owned(),
                    is_dir: false,
                    size: Some(size),
                    mtime_ns: Some((mtime * 1e9) as u64),
                    relation_member_eligible: false,
                    relation_anchor: None,
                },
            );
            table
                .rows
                .get_mut(key.as_str())
                .unwrap()
                .remember_observation(size, mtime, file_id, change_usn, phase_boundary);
        })()
    }

    pub(crate) fn content_changed(&self, path: &str) {
        let key = crate::path_keys::path_key(path);
        for table in self.catalogs.lock().unwrap().edit().values_mut() {
            table.generated.remove(key.as_str());
            table.touch(path);
        }
    }

    pub(crate) fn retire_observation(
        &self,

        path: &str,
        quiet_seconds: Option<f64>,
        last_content_event_at: Option<f64>,
        cadence_seconds: f64,
        pending_interval_seconds: f64,
    ) {
        (|| {
            let key = crate::path_keys::path_key(path);
            let mut tables = self.catalogs.lock().unwrap();
            for table in tables.edit().values_mut() {
                if let Some(row) = table.rows.get_mut(key.as_str()) {
                    if !row.persistent() {
                        table.remove(&key);
                        continue;
                    }
                    if let (Some(observation), Some(seconds)) =
                        (row.observation.as_mut(), quiet_seconds)
                    {
                        observation.quiet_seconds = seconds;
                        observation.last_content_event_at = last_content_event_at;
                        observation.cadence_seconds = cadence_seconds;
                        observation.pending_interval_seconds = pending_interval_seconds;
                    }
                }
            }
        })()
    }

    pub(crate) fn forget_missing_observation(&self, path: &str, recursive: bool) {
        let mut key = crate::path_keys::path_key(path);
        key.truncate(key.trim_end_matches('\\').len());
        let prefix = recursive.then(|| format!("{key}\\"));
        let mut observed: Vec<_> = {
            let tables = self.catalogs.lock().unwrap();
            tables.scopes.iter().filter_map(|(scope, table)| {
                let children = prefix.iter().flat_map(|prefix| {
                    table.rows.range::<str, _>((
                        std::ops::Bound::Included(prefix.as_str()),
                        std::ops::Bound::Unbounded,
                    ))
                    .take_while(move |(child, _)| child.starts_with(prefix))
                });
                let rows: Vec<_> = table.rows.get_key_value(key.as_str()).into_iter()
                    .chain(children)
                    .filter_map(|(key, row)| {
                        let before = row.observation.as_deref()?;
                        Some((Arc::clone(key), row.path(), before.clone()))
                    })
                    .collect();
                (!rows.is_empty()).then(|| (scope.clone(), rows))
            }).collect()
        };
        for (_, rows) in &mut observed {
            rows.retain(|(_, path, _)| crate::watch_store::recorded_file_is_absent(path));
        }
        if observed.iter().all(|(_, rows)| rows.is_empty()) {
            return;
        }
        let mut tables = self.catalogs.lock().unwrap();
        let scopes = tables.edit();
        for (scope, rows) in observed {
            let Some(table) = scopes.get_mut(&scope) else { continue; };
            let mut removed = Vec::new();
            for (key, path, before) in rows {
                let Some(row) = table.rows.get_mut(key.as_ref()) else { continue; };
                // A newer observation may have arrived during the metadata read.
                if row.observation.as_deref() != Some(&before) || !row.matches_path(&path) {
                    continue;
                }
                if row.persistent() {
                    row.observation = None;
                } else {
                    removed.push(key);
                }
            }
            table.remove_many(removed.iter().map(AsRef::as_ref));
        }
    }

    pub(crate) fn cursor(
        &self,

        scope: &crate::scan::scope::NativeDiscoveryScope,
        identity: &str,
    ) -> Option<(String, u64, i64)> {
        (|| {
            let store = self.store.lock().unwrap();
            let saved = store
                .as_ref()?
                .stamps
                .get(&crate::path_keys::path_key(&scope.root))?;
            (saved.identity == identity
                && saved.depth == scope.max_depth
                && saved.excluded == Self::catalog_exclusions(scope))
                .then(|| saved.cursor.clone())
                .flatten()
        })()
    }
    pub(crate) fn bucket_revision(&self, scope: &crate::scan::scope::NativeDiscoveryScope, seed: &str) -> u64 {
        self.catalogs.lock().unwrap().scopes.get(scope.key())
            .and_then(|table| table.buckets.get(catalog_stem(seed).as_str())).map_or(0, |bucket| bucket.revision)
    }

    pub(crate) fn bucket_keys(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        stem: &str,
    ) -> Vec<Arc<str>> {
        let tables = self.catalogs.lock().unwrap();
        tables
            .scopes
            .get(&crate::path_keys::path_key(&scope.root))
            .and_then(|table| table.buckets.get(stem))
            .into_iter()
            .flat_map(|bucket| bucket.iter().cloned())
            .collect()
    }

    pub(crate) fn path_is_directory(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
        path: &str,
    ) -> Option<bool> {
        self.catalogs
            .lock()
            .unwrap()
            .scopes
            .get(&crate::path_keys::path_key(&scope.root))?
            .rows
            .get(crate::path_keys::path_key(path).as_str())
            .map(CatalogRow::is_dir)
    }
    pub(crate) fn retain_roots(&self, roots: Vec<String>) {
        let keys: HashSet<_> = roots
            .iter()
            .map(|root| crate::path_keys::path_key(root))
            .collect();
        let mut guard = self.catalogs.lock().unwrap();
        let tables = guard.edit();
        let previous = tables.len();
        tables.retain(|key, _| keys.contains(key));
        let removed_roots = previous != tables.len();
        for key in &keys {
            tables.entry(key.clone()).or_default();
        }
        if removed_roots {
            if let Some(store) = self.store.lock().unwrap().as_mut() {
                store.stamps.retain(|key, _| keys.contains(key));
                store.mark_rebuilt();
            }
        }
    }
    pub(crate) fn recover_changes(
        &self,
        scopes: &[crate::scan::scope::NativeDiscoveryScope],
        volume: &str,
        journal: u64,
        start_usn: i64,
        end_usn: i64,
        cache: &mut crate::filesystem::DirectoryRecoveryCache,
    ) -> std::io::Result<Vec<(String, String)>> {
        if start_usn == end_usn || scopes.is_empty() {
            return Ok(Vec::new());
        }
        let directories: HashSet<_> = scopes.iter()
            .flat_map(|scope| self.directory_paths(scope)).collect();
        let roots: Vec<_> = scopes.iter().map(|scope| scope.root.clone()).collect();
        crate::filesystem::watch_directories_changes_cached_impl(
            directories.into_iter().collect(), &roots, volume, journal, start_usn, end_usn, cache,
        )
    }
    pub(crate) fn set_cursor(
        &self,

        scope: &crate::scan::scope::NativeDiscoveryScope,
        identity: String,
        volume: String,
        journal: u64,
        next_usn: i64,
    ) {
        (|| {
            let stamp = super::catalog_store::Stamp {
                identity,
                depth: scope.max_depth,
                excluded: Self::catalog_exclusions(scope),
                cursor: Some((volume, journal, next_usn)),
            };
            let mut tables = self.catalogs.lock().unwrap();
            self.persist(
                tables.edit(),
                super::catalog_store::DeltaView {
                    scope: &crate::path_keys::path_key(&scope.root),
                    removed: &[],
                    rows: Vec::new(),
                    stamp: Some(stamp),
                },
                false,
            );
        })();
    }
    pub(crate) fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    pub(crate) fn commit_pending(&self) -> bool {
        let tables = self.catalogs.lock().unwrap();
        tables.committed != Some(tables.revision)
    }

    pub(crate) fn commit(&self, idle: bool) {
        (|| {
            let mut tables = self.catalogs.lock().unwrap();
            // Commit is already event-driven. Reclaim deletion high water even
            // when no pipeline completion has armed Watch's idle-maintenance timer.
            for table in tables.scopes.values_mut() {
                table.trim_capacity();
            }
            tables.committed = Some(tables.revision);
            let mut slot = self.store.lock().unwrap();
            if let Some(store) = slot.as_mut() {
                if let Err(error) = store.commit().and_then(|_| {
                    if store.checkpoint_due(idle) {
                        store.checkpoint(&tables.scopes)
                    } else {
                        Ok(())
                    }
                }) {
                    *self.error.lock().unwrap() = Some(error.to_string());
                    *slot = None;
                }
            }
        })();
    }
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        self.commit(false);
        if let Some(error) = self.error() { return Err(std::io::Error::other(error)); }
        if let Some(store) = self.store.lock().unwrap().as_mut() { store.flush()?; }
        Ok(())
    }
    pub(crate) fn close(&self) {
        (|| {
            let tables = self.catalogs.lock().unwrap();
            let mut slot = self.store.lock().unwrap();
            if let Some(mut store) = slot.take() {
                if let Err(error) = store.checkpoint(&tables.scopes) {
                    *self.error.lock().unwrap() = Some(error.to_string());
                }
            }
        })();
    }
}

impl NativeWatchCatalog {
    pub(crate) fn directory_paths(
        &self,
        scope: &crate::scan::scope::NativeDiscoveryScope,
    ) -> Vec<String> {
        if scope.max_depth == Some(0) {
            return vec![scope.root.clone()];
        }
        let mut directories: Vec<_> = {
            let tables = self.catalogs.lock().unwrap();
            std::iter::once(scope.root.clone())
                .chain(tables.scopes.get(&crate::path_keys::path_key(&scope.root))
                    .into_iter()
                    .flat_map(|table| table.rows.values())
                    .filter(|row| row.persistent() && row.is_dir())
                    .map(CatalogRow::path))
                .collect()
        };
        // The root is always queried, including when its children are excluded.
        let mut first = true;
        directories.retain(|path| {
            std::mem::take(&mut first) || (scope.contains(path) && !self.is_owned(path))
        });
        directories
    }
    pub(crate) fn output_roots(&self, under: &str) -> Vec<String> {
        crate::watch_store::active_outputs::owned_roots(&self.outputs, under)
    }

    pub(crate) fn is_owned(&self, path: &str) -> bool {
        crate::watch_store::active_outputs::covers_path(&self.outputs, path)
    }
}

impl NativeWatchCatalog {
    fn catalog_exclusions(scope: &crate::scan::scope::NativeDiscoveryScope) -> Vec<String> {
        let mut excluded = scope.excluded_subtrees();
        excluded.sort_unstable();
        excluded
    }
    fn persist(
        &self,
        tables: &HashMap<String, ScopeCatalog>,
        delta: super::catalog_store::DeltaView<'_>,
        rebuilt: bool,
    ) {
        let mut slot = self.store.lock().unwrap();
        let Some(store) = slot.as_mut() else {
            return;
        };
        let result = if rebuilt {
            store.mark_rebuilt();
            store.checkpoint(tables)
        } else {
            store.append(delta).and_then(|_| {
                if store.checkpoint_due(false) {
                    store.checkpoint(tables)
                } else {
                    Ok(())
                }
            })
        };
        if let Err(error) = result {
            *self.error.lock().unwrap() = Some(error.to_string());
            *slot = None;
        }
    }
}

fn update_catalog(
    options: &NativeDirectoryScanOptions,
    state: &NativeWatchCatalog,
    scope: &crate::scan::scope::NativeDiscoveryScope,
    changed: Option<&str>,
    report_changes: bool,
    adopt_observations: bool,
) -> std::io::Result<(Vec<DirectoryReadError>, Vec<String>)> {
    let target = changed.unwrap_or(&scope.root);
    let scan = || scan_catalog(options, state, scope, target, false);
    let revision = state.catalogs.lock().unwrap_or_else(|e| e.into_inner()).revision;
    let prepared = scan();
    #[cfg(test)]
    AFTER_CATALOG_SCAN.with(|hook| {
        if let Some(hook) = hook.take() { hook(); }
    });
    let mut tables = state.catalogs.lock().unwrap_or_else(|e| e.into_inner());
    let prepared = if tables.revision == revision {
        prepared?
    } else {
        // A concurrent edit may have published a previously excluded output
        // or removed a row. Retry with the original writer ordering, once.
        drop(prepared);
        scan()?
    };
    apply_catalog_scan(state, scope, changed, report_changes, false, adopt_observations, prepared, tables.edit())
}

struct CatalogScan {
    effective: crate::scan::scope::NativeDiscoveryScope,
    raw: Vec<DirectoryEntryRecord>,
    errors: Vec<DirectoryReadError>,
}

fn scan_catalog(
    options: &NativeDirectoryScanOptions,
    state: &NativeWatchCatalog,
    scope: &crate::scan::scope::NativeDiscoveryScope,
    target: &str,
    baseline: bool,
) -> std::io::Result<Option<CatalogScan>> {
    let mut effective = if baseline {
        crate::scan::scope::NativeDiscoveryScope::new(target.to_owned(), None, Vec::new())
    } else { scope.clone() };
    let metadata = fs::metadata(target);
    let target_owned = !baseline && state.is_owned(target);
    if metadata.as_ref().is_ok_and(|m| m.is_dir())
        && effective.contains(target)
        && !target_owned && !baseline
    {
        effective.exclude_roots(state.output_roots(target).into_iter());
    }
    let mut options = options.options.clone();
    options.scope = Some(effective.clone());
    let mut records = if !effective.contains(target) || target_owned {
        DirectoryScanRecords {
            filtered: Vec::new(),
            raw: Vec::new(),
            errors: DirectoryReadErrors::report(),
        }
    } else {
        match &metadata {
            Ok(metadata) => {
                // Catalog rows use raw metadata. Discovery applies file rules
                // later when it builds the filtered view for a relation bucket.
                scan_directory_impl(target, effective.max_depth, &options, Some(metadata.clone()), false)?
            }
            Err(error) => {
                let mut errors = DirectoryReadErrors::default();
                if error.kind() != std::io::ErrorKind::NotFound {
                    errors.push(
                        Path::new(target),
                        "metadata",
                        std::io::Error::new(error.kind(), error.to_string()),
                    );
                }
                DirectoryScanRecords {
                    filtered: Vec::new(),
                    raw: Vec::new(),
                    errors,
                }
            }
        }
    };
    if let Ok(meta) = &metadata {
        if meta.is_dir()
            && crate::path_keys::path_key(target) != crate::path_keys::path_key(&scope.root)
            && effective.contains(target)
            && (baseline || !state.is_owned(target))
        {
            records.raw.push(DirectoryEntryRecord {
                path: target.to_owned(),
                is_dir: true,
                size: None,
                mtime_ns: metadata_mtime_ns(meta),
                relation_member_eligible: false,
                relation_anchor: None,
            });
        }
    }
    // Validate directory/deletion observations before touching resident rows.
    // Existing file updates already prove their root was accessible.
    if (!metadata.as_ref().is_ok_and(|m| m.is_file()) || records.raw.is_empty())
        && !Path::new(&scope.root).is_dir()
    {
        return Ok(None);
    }
    Ok(Some(CatalogScan {
        effective,
        raw: records.raw,
        errors: records.errors.into_messages(),
    }))
}

fn apply_catalog_scan(
    state: &NativeWatchCatalog,
    scope: &crate::scan::scope::NativeDiscoveryScope,
    changed: Option<&str>,
    report_changes: bool,
    baseline: bool,
    adopt_observations: bool,
    prepared: Option<CatalogScan>,
    catalogs: &mut HashMap<String, ScopeCatalog>,
) -> std::io::Result<(Vec<DirectoryReadError>, Vec<String>)> {
    let Some(CatalogScan { effective, raw, errors }) = prepared else {
        return Ok((
            vec![(scope.root.clone(), "metadata".into(), "watch root unavailable".into())],
            Vec::new(),
        ));
    };
    let target = changed.unwrap_or(&scope.root);
    let scope_key = crate::path_keys::path_key(&scope.root);
    let mut target_key = crate::path_keys::path_key(target);
    target_key.truncate(target_key.trim_end_matches('\\').len());
    let catalog = catalogs.entry(scope_key.clone()).or_default();
    let needs_removal = !catalog.rows.is_empty();
    let mut present = HashSet::new();
    let mut changed_paths = Vec::new();
    let mut mutated = false;
    let mut changed_keys = Vec::new();
    for record in raw.into_iter()
        .filter(|r| effective.contains(&r.path) && (!baseline || !r.is_dir || scope.contains(&r.path)))
    {
        let key: Arc<str> = Arc::from(crate::path_keys::path_key(&record.path));
        if needs_removal {
            present.insert(Arc::clone(&key));
        }
        let old = catalog.rows.get(&key);
        let unchanged = old.is_some_and(|old| old.matches(&record));
        // Enumeration cannot prove that an observed path still names the same
        // file. Reuse Watch admission's identity/USN check, retaining its old
        // baseline and leaving unchanged catalog rows and caches untouched.
        if report_changes && !record.is_dir
            && (!unchanged || old.is_some_and(|old| old.observation.is_some()))
        {
            changed_paths.push(record.path.clone());
        }
        let observation = if (baseline || adopt_observations) && !record.is_dir && record.size.is_some_and(|size| size > 0) {
            // Enumeration already supplies size and mtime. Only read the
            // identity/USN once; do not stat every settled output again.
            match crate::filesystem::watch_file_observation_known_kind(Path::new(&record.path), None, false) {
                Ok(observation) => Some((record.size.unwrap(), record.mtime_ns.unwrap_or(0) as f64 / 1e9, observation)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
        } else { None };
        if !unchanged || observation.is_some() {
            mutated = true;
            if changed.is_some() {
                changed_keys.push(Arc::clone(&key));
            }
            catalog.insert_key(Arc::clone(&key), record);
            if let Some((size, mtime, observed)) = observation {
                if baseline { catalog.set_generated(&key, GeneratedBaseline::new(size, mtime, &observed.file_id, observed.change_usn)); }
                let row = catalog.rows.get_mut(key.as_ref()).unwrap();
                if scope.contains(&row.path()) {
                    row.remember_observation(size, mtime, &observed.file_id, observed.change_usn, true);
                }
            }
        }
    }
    let mut removed_keys = Vec::new();
    if needs_removal && errors.is_empty() {
        let removed: Vec<_> = catalog
            .rows
            .range::<str, _>((
                std::ops::Bound::Included(target_key.as_str()),
                std::ops::Bound::Unbounded,
            ))
            .take_while(|(key, _)| key.starts_with(&target_key))
            .filter(|(key, row)| {
                row.persistent()
                    && (key.as_ref() == target_key || key[target_key.len()..].starts_with('\\'))
                    && !present.contains(*key)
                    && (baseline || !catalog.generated.contains_key(*key) || effective.contains(&row.path()))
            })
            .map(|(key, _)| Arc::clone(key))
            .collect();
        catalog.remove_many(removed.iter().map(|key| key.as_ref()));
        removed_keys.extend(removed.iter().map(|key| key.to_string()));
    }
    if mutated || !removed_keys.is_empty() {
        state.persist(
            catalogs,
            super::catalog_store::DeltaView {
                scope: &scope_key,
                removed: &removed_keys,
                rows: changed_keys
                    .iter()
                    .filter_map(|key| catalogs[&scope_key].row_view(key))
                    .collect(),
                stamp: None,
            },
            changed.is_none(),
        );
    }
    Ok((errors, changed_paths))
}

#[cfg(test)]
thread_local! {
    static AFTER_CATALOG_SCAN: std::cell::Cell<Option<Box<dyn FnOnce()>>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "../../tests/unit/scan/directory/watch_cache_lifetime_tests.rs"]
mod watch_cache_lifetime_tests;
