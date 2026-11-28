use super::*;
use crate::analysis_native::volume_anchor::{
    cheap_fast_probe_pool, VolumeAnchor, EMBEDDED_VOLUME,
};
use crate::io::cancellation::Cancellation;
use crate::io::reader::{ManagedReader, PhysicalFileGeneration};
use crate::io::resource_lifecycle::{NativeReadScope, TrackedFile};
use crate::io::view::{MaskBoundaries, ReadView, ViewProbes};
use crate::formats::StreamFormat;
use crate::scan::discovery::ReadScope;
use crate::scan::root::{ArchiveRoot, RootRoute};

use crate::scan::{
    catalog::catalog_stem,
    embedded::scan_embedded_view,
};
use rayon::prelude::*;

#[derive(Default)]
struct Findings {
    anchors: Vec<Arc<VolumeAnchor>>,
    tasks: Vec<Task>,
    peer_tasks: Vec<Task>,
    residual_views: Vec<Arc<ReadView>>,
    verified: VerifiedPasswords,
    error: Option<io::Error>,
}

fn resolve_rar(
    anchor: VolumeAnchor,
    session: &NativeArchiveSession,
    passwords: &CandidateSet,
    cancel: &Cancellation,
    verified: &mut VerifiedPasswords,
) -> io::Result<(VolumeAnchor, Option<RarInputResolution>)> {
    if anchor.format != "rar" || !anchor.needs_password {
        return Ok((anchor, None));
    }
    let (anchor, password) = passwords.resolve_relation(&anchor, session, cancel)?;
    if let Some(password) = &password {
        verified.insert(
            (
                path_key(&anchor.path),
                anchor.structure_offset.unwrap_or(0),
                anchor.view.clone(),
            ),
            password.clone(),
        );
    }
    let resolution = (!anchor.multivolume).then(|| RarInputResolution::from_anchor(&anchor, password));
    Ok((anchor, resolution))
}

fn inspect(
    session: &NativeArchiveSession,
    reader: &ManagedReader,
    prepared: Option<ArchiveRoot>,
    selected: bool,
    embedded: bool,
    parallel_files: usize,
    request: &Request,
    passwords: &CandidateSet,
    found: &mut Findings,
    mut shared_empty: Option<&mut std::ops::Range<u64>>,
) -> io::Result<()> {
    let path = session.path();
    let prepared = match prepared {
        Some(root) => root,
        None => ArchiveRoot::read(reader, path, selected, request.deep, selected && !embedded)?,
    };
    let route = prepared.route();
    let ArchiveRoot {
        anchor: root,
        scan: root_scan,
    } = prepared;
    let stream_task = |root: &VolumeAnchor| {
        let mut task = project_file(path, root.format, Some(reader), root.standalone_truncated(), DiscoverySource::Detection);
        task.apply_content_requirement(request.config.extraction.content_requirement == ContentRequirement::Complete);
        task
    };
    if selected && !request.deep && route == RootRoute::Detection {
        found.tasks.push(stream_task(&root));
        found.anchors.push(Arc::new(root));
        return Ok(());
    }
    if !request.deep && route == RootRoute::PeImage {
        if let Some(sfx) = crate::relations::promote_sfx_archive_anchor(&root, reader) {
            let (sfx, resolution) = resolve_rar(
                sfx,
                session,
                passwords,
                &request.cancel,
                &mut found.verified,
            )?;
            let sfx = Arc::new(sfx);
            if (sfx.standalone || resolution.is_some()) && !sfx.format.is_empty() {
                let relation = crate::relations::NativeRelationGroup::project_standalone(sfx.clone());
                let mut task = project_task(CandidateProjection::Relation { relation }, DiscoverySource::Relations, &found.verified);
                if let Some(result) = resolution {
                    let logical = &mut task.inputs[0];
                    logical.password = result.password;
                    logical.failure = result.failure_reason.and_then(|reason| {
                        discovery_failure(reason, DiscoverySource::Relations, path)
                    });
                }
                found.tasks.push(task);
            }
            found.anchors.push(sfx);
        } else {
            found.anchors.push(Arc::new(root));
        }
        return Ok(());
    }
    // A full scan may supply better boundaries for the same leading anchor.
    let scan = if request.deep && embedded {
        Some(scan_embedded_view(
            reader.clone(),
            parallel_files,
            None,
            shared_empty.as_deref_mut(),
        )?)
    } else if selected || embedded || !root.format.is_empty() {
        match root_scan {
            Some(scan) if !embedded || route == RootRoute::Complete => Some(scan),
            _ if embedded => Some(scan_embedded_view(
                reader.clone(),
                parallel_files,
                None,
                shared_empty.as_deref_mut(),
            )?),
            other => other,
        }
    } else {
        None
    };
    if selected
        && !embedded
        && !request.deep
        && crate::formats::supports_volume_relations(root.format)
        && scan.as_ref().is_none_or(|s| {
            !s.has_independent_archive() || s.candidates().iter().all(|c| c.awaits_zip_tail())
        })
    {
        if root.standalone {
            let anchor = Arc::new(root);
            let relation =
                crate::relations::NativeRelationGroup::project_standalone(anchor.clone());
            let task = project_task(
                CandidateProjection::Relation { relation },
                DiscoverySource::Relations,
                &found.verified,
            );
            found.tasks.push(task);
            found.anchors.push(anchor);
            return Ok(());
        }
    }
    // Keep a supplemental stream for a connected family even when Embedded is
    // disabled and only a deeper view can supply its valid mask boundary.
    if !selected
        && !embedded
        && !request.deep
        && root.detection_stream()
        && scan.as_ref().is_none_or(|s| !s.has_independent_archive())
    {
        found.tasks.push(stream_task(&root));
    }
    record_scan(
        session,
        reader,
        Some(root),
        scan,
        selected,
        request,
        passwords,
        found,
    )
}

fn record_scan(
    session: &NativeArchiveSession,
    reader: &ManagedReader,
    root: Option<VolumeAnchor>,
    scan: Option<NativeScanResult>,
    selected: bool,
    request: &Request,
    passwords: &CandidateSet,
    found: &mut Findings,
) -> io::Result<()> {
    let path = session.path();
    let view = reader.read_view();
    let mut resolutions = HashMap::new();
    let mut anchors = scan.as_ref().map_or_else(Vec::new, |scan| scan.relation_anchors(path, view));
    for anchor in &mut anchors { anchor.flags |= EMBEDDED_VOLUME; }
    if let Some(mut root) = root {
        if !root.multivolume
            && scan.as_ref().is_some_and(|s| {
                s.candidates().iter().any(|c| {
                    c.offset == 0
                        && c.format == root.format
                        && (c.end_offset == Some(reader.len())
                            || c.format == "zip" && c.end_offset.is_some())
                        && c.is_logical_archive()
                        && !c.awaits_zip_tail()
                        && c.volume_anchor.is_none()
                })
            })
        {
            root.standalone = true;
        }
        if !anchors
            .iter()
            .any(|a| a.format == root.format && a.structure_offset == root.structure_offset)
        {
            anchors.push(root);
        }
    }
    for anchor in anchors {
        let (anchor, resolution) = resolve_rar(
            anchor,
            session,
            passwords,
            &request.cancel,
            &mut found.verified,
        )?;
        if let Some(resolution) = resolution {
            resolutions.insert(anchor.structure_offset.unwrap_or(0), resolution);
        }
        found.anchors.push(Arc::new(anchor));
    }
    if let Some(scan) =
        scan.filter(|s| s.has_candidates() && (selected || s.has_independent_archive()))
    {
        let seed = project_file(path, "", Some(reader), false, DiscoverySource::Embedded);
        if let Some(task) = project_segments(seed, &scan, resolutions, passwords)? {
            found.tasks.push(task);
        }
    }
    Ok(())
}

fn source_key(
    path: &str,
    format: &str,
    head: Option<&InputExtent>,
) -> (String, String, u64, Option<Arc<ReadView>>) {
    let view = head.and_then(|extent| {
        extent
            .view
            .as_ref()
            .filter(|v| !extent.end.is_some_and(|end| v.unchanged(extent.start, end)))
            .cloned()
    });
    (
        path_key(path),
        format.to_owned(),
        head.map_or(0, |e| e.start),
        view,
    )
}

fn head_key(input: &ArchiveInput) -> (String, String, u64, Option<Arc<ReadView>>) {
    source_key(
        &input.entry_path,
        &input.format_hint,
        input.parts.first().map(|p| &p.extent),
    )
}

// Another view can cut a known single-disk ZIP inside its EOCD and
// expose a later member as a weak local-header-only missing volume. Use only
// proven ZIP coordinates and identical mapped bytes. A confirmed volume plan
// or a split signature remains independent evidence.
fn clipped_zip_heads<'a>(
    tasks: &[Task],
    facts: impl Iterator<Item = &'a Arc<VolumeAnchor>> + Clone,
) -> HashSet<InputHeadKey> {
    use crate::analysis_native::volume_anchor::ZIP_LOCAL_HEADER;
    use crate::io::archive_state::PhysicalRanges;

    let mut weak = HashMap::<_, Vec<_>>::new();
    for anchor in facts.clone().filter(|a| {
        a.format == "zip"
            && !a.strong
            && !a.multivolume
            && !a.standalone
            && a.zip_directory.is_none()
            && a.carrier_limit.is_none_or(|limit| limit >= a.size)
            && a.has_any(ZIP_LOCAL_HEADER)
    }) {
        weak.entry(anchor.path.as_str())
            .or_default()
            .push(anchor.as_ref());
    }
    let mut excluded = HashSet::new();
    if weak.is_empty() {
        return excluded;
    }
    for anchors in weak.values_mut() {
        anchors.sort_unstable_by_key(|a| a.size);
    }
    for logical in tasks.iter().flat_map(|task| &task.inputs) {
        let input = &logical.input;
        if logical.failure.is_some() || input.format_hint != "zip" || input.mode.structured() {
            continue;
        }
        let Some(anchors) = weak.get(input.entry_path.as_str()) else {
            continue;
        };
        let extent = input.parts.first().map(|p| &p.extent);
        let base = extent.map_or(0, |e| e.start);
        let Some(eocd) = input
            .analysis
            .zip_eocd_offset
            .and_then(|at| base.checked_add(at))
        else {
            continue;
        };
        let source = extent.and_then(|e| e.view.as_deref());
        // A bounded ZIP retains the verified end of its comment. For a plain
        // whole-file task only the fixed portion is known here.
        let tail_end = extent
            .and_then(|e| e.end)
            .unwrap_or(eocd.saturating_add(22))
            .min(eocd.saturating_add(22 + u16::MAX as u64));
        let first = anchors.partition_point(|a| a.size < eocd.saturating_add(4));
        for anchor in anchors[first..].iter().take_while(|a| a.size < tail_end) {
            let Some(at) = anchor.structure_offset.filter(|&at| base < at && at < eocd) else {
                continue;
            };
            let view = anchor.view.as_deref();
            if source != view
                && PhysicalRanges::new(source, at, Some(anchor.size))
                    == PhysicalRanges::new(view, at, Some(anchor.size))
            {
                excluded.insert((path_key(&anchor.path), at, anchor.view.clone()));
            }
        }
    }
    if !excluded.is_empty() {
        for a in facts.filter(|a| {
            a.format == "zip" && (a.strong || a.multivolume || a.zip_directory.is_some())
        }) {
            if let Some(at) = a.structure_offset {
                excluded.remove(&(path_key(&a.path), at, a.view.clone()));
            }
        }
    }
    excluded
}

pub(super) struct FileMasks {
    generation: PhysicalFileGeneration,
    boundaries: MaskBoundaries,
}

fn stream_mask_ends(
    input: &ArchiveInput,
    bounds: &FileMasks,
    deep: bool,
    ends: &mut Vec<u64>,
) -> io::Result<()> {
    ends.clear();
    let Some(format) = StreamFormat::from_name(&input.format_hint) else { return Ok(()); };
    let external = format.uses_external_end();
    if deep && !external { return Ok(()); }
    let extent = input.parts.first().map(|p| &p.extent);
    let start = extent.map_or(0, |e| e.start);
    let view = extent.and_then(|e| e.view.as_ref());
    if input.mode != OpenMode::File && !(input.mode == OpenMode::FileRange
        && (start == 0 || external)
        && extent.is_some_and(|e| e.end.is_none_or(|end| view.is_some_and(|v| end == v.len()))))
    {
        return Ok(());
    }
    let limits = bounds.boundaries.ends(view.map(Arc::as_ref));
    if limits.is_empty() { return Ok(()); }
    let reader = ManagedReader::open(&input.entry_path)?.with_view(view)?.probe_reader();
    if reader.physical_generation() != Some(&bounds.generation) { return Ok(()); }
    let validate = |limit| -> io::Result<Option<u64>> {
        if start >= limit { return Ok(None); }
        let candidate = crate::scan::embedded::bounded_candidate(&reader, &input.format_hint, start, limit)?;
        Ok(candidate
            .filter(|c| c.is_logical_archive() && c.format == input.format_hint)
            .and_then(|c| c.end_offset.or(external.then_some(limit)))
            .filter(|&end| end > start && end <= limit))
    };
    // A stream can cross a declared boundary. Prefer the archive's own framing;
    // only externally bounded streams or inconclusive framing need the alternatives.
    if !external {
        if let Some(end) = validate(reader.len())? {
            if end < reader.len() { ends.push(end); }
            return Ok(());
        }
    }
    for &limit in limits {
        if let Some(end) = validate(limit)? {
            ends.push(end);
        }
    }
    ends.sort_unstable();
    ends.dedup();
    Ok(())
}

pub(super) fn refine_stream_masks(
    tasks: &mut [Task],
    deep: bool,
    masks: &HashMap<&str, FileMasks>,
) -> io::Result<()> {
    if masks.is_empty() { return Ok(()); }
    let mut ends = Vec::new();
    for task in tasks {
        let original_len = task.inputs.len();
        for index in 0..original_len {
            let input = &task.inputs[index].input;
            let Some(bounds) = masks.get(input.entry_path.as_str()) else { continue; };
            match stream_mask_ends(input, bounds, deep, &mut ends) {
                Ok(()) => {},
                Err(e) if crate::io::cancellation::is_cancellation(&e) => return Err(e),
                Err(_) => continue,
            };
            let Some((&first, rest)) = ends.split_first() else { continue; };
            let logical = &mut task.inputs[index];
            let primary = task.primary.as_deref_mut().filter(|p| *p == &logical.input);
            let input = &mut logical.input;
            if input.mode == OpenMode::FileRange {
                input.parts[0].extent.end = Some(first);
            } else {
                input.mode = OpenMode::FileRange;
                input.parts = Box::new([InputPart::range(InputExtent {
                    path: input.entry_path.clone(), start: 0, end: Some(first), view: None,
                })]);
            }
            input.analysis.standalone_truncated = false;
            input.analysis.distinguish_end = !rest.is_empty();
            if let Some(primary) = primary { primary.clone_from(input); }
            if logical.failure.as_ref().is_some_and(|f| f.kind == FailureKind::Damaged) {
                logical.failure = None;
            }
            for &end in rest {
                let original = &task.inputs[index];
                let mut input = original.input.clone();
                input.parts[0].extent.end = Some(end);
                task.inputs.push(LogicalInput { input, password: original.password.clone(), failure: original.failure.clone() });
            }
        }
    }
    Ok(())
}

struct FileViews {
    views: Vec<Arc<ReadView>>,
    roots: Vec<io::Result<ArchiveRoot>>,
    masks: FileMasks,
}

pub(super) fn could_derive(snapshot: &NativeDirectorySnapshot, row: usize, probes: ViewProbes) -> bool {
    let table = &snapshot.table;
    !table.is_dir(row)
        && probes.could_derive(
            table.sizes[row],
            table.relation_anchors[row]
                .as_ref()
                .map_or(0, |a| a.reject_mask()),
        )
}

fn open_views(
    scope: &ReadScope,
    row: usize,
    guard: Option<&NativeReadScope>,
    request: &Request,
) -> io::Result<Option<(NativeArchiveSession, FileViews)>> {
    let path = &scope.raw.table.paths[row];
    let file = match guard {
        Some(guard) => guard.open_reader(path)?,
        None => TrackedFile::open_reader(path)?,
    };
    let size = match scope.raw.table.sizes[row] {
        Some(size) => size,
        None => file.metadata()?.len(),
    };
    // Reject ordinary files cheaply. Once admitted, derive every coordinate
    // from the generation that will also supply the archive bytes.
    let probes = request.config.filesystem.read_views.probes();
    if !probes.could_derive(Some(size), probes.rejections(&file, size, &[])) {
        return Ok(None);
    }
    let session = NativeArchiveSession::from_open_file(path, file)?;
    let generation = session
        .reader()
        .physical_generation()
        .filter(|g| g.len == size)
        .ok_or_else(|| io::Error::other("file changed during read view discovery"))?
        .clone();
    let mut boundaries = MaskBoundaries::default();
    let views = request.config.filesystem.read_views.derive_views(session.reader(), &mut boundaries)?;
    if views.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        session,
        FileViews {
            views,
            roots: Vec::new(),
            masks: FileMasks {
                generation,
                boundaries,
            },
        },
    )))
}

fn verify_unchanged(session: &NativeArchiveSession) -> io::Result<()> {
    let current = crate::io::reader::capture_file_generation(Path::new(session.path()))?;
    if session.reader().physical_generation() != Some(&current) {
        return Err(io::Error::other("file changed during read view discovery"));
    }
    Ok(())
}

fn read_guard(scope: &ReadScope, rows: &[usize]) -> Option<NativeReadScope> {
    let path = &scope.raw.table.paths[*rows.first()?];
    NativeReadScope::new(Path::new(path).parent()?).ok()
}

// Only fractional recursive thresholds need a root inventory before either scanner
// can start. Keep successful mappings and errors, with no open handles.
#[derive(Default)]
pub(super) struct RecursiveViews(Vec<(usize, io::Result<FileViews>)>);

impl RecursiveViews {
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn prepare(scope: &ReadScope, request: &Request) -> Self {
        let rows: Vec<_> = scope
            .selected
            .rows()
            .filter(|&r| could_derive(&scope.raw, r, request.config.filesystem.read_views.probes()))
            .collect();
        let guard = read_guard(scope, &rows);
        Self(cheap_fast_probe_pool().install(|| {
            rows.into_par_iter()
                .filter_map(|row| {
                    request
                        .cancel
                        .run(|| {
                            let Some((session, mut file)) =
                                open_views(scope, row, guard.as_ref(), request)?
                            else {
                                return Ok(None);
                            };
                            if !request.deep {
                                file.roots = file
                                    .views
                                    .iter()
                                    .map(|view| {
                                        ArchiveRoot::read(
                                            &view.bind(session.reader())?,
                                            session.path(),
                                            true,
                                            false,
                                            true,
                                        )
                                    })
                                    .collect();
                            }
                            Ok(Some(file))
                        })
                        .transpose()
                        .map(|r| (row, r))
                })
                .collect()
        }))
    }

    pub(super) fn files<'a>(
        &'a self,
        scope: &'a ReadScope,
    ) -> impl Iterator<Item = (&'a str, u64, bool)> {
        self.0.iter().filter_map(|(row, file)| {
            let file = file.as_ref().ok()?;
            let resolved = file
                .roots
                .iter()
                .flatten()
                .any(|root| root.route() != RootRoute::Residual);
            Some((
                scope.raw.table.paths[*row].as_str(),
                file.masks.generation.len,
                resolved,
            ))
        })
    }
}

pub(super) fn discover<'a>(
    read_scope: &'a ReadScope,
    table: &NativeCandidateTable,
    passwords: &CandidateSet,
    plain_verified: &VerifiedPasswords,
    request: &Request,
    admission: EmbeddedAdmission,
    inventory: Option<RecursiveViews>,
    out: &mut Discovered,
    mask_ends: &mut HashMap<&'a str, FileMasks>,
) -> io::Result<bool> {
    let raw = &read_scope.raw;
    let selected = &read_scope.selected;
    let aliases = read_scope.aliases.as_deref();
    let plain_anchors = &table.plain_volume_anchors;
    let options = &request.config.filesystem.read_views;
    // Both snapshots refer to the same row table; the filtered rows are a subset.
    // A full directory requires neither path hashing nor a filename-stem index.
    debug_assert!(Arc::ptr_eq(&selected.table, &raw.table));
    let all = selected.rows().len() == raw.rows().len();
    let selected_rows: HashSet<_> = if all {
        HashSet::new()
    } else {
        selected.rows().filter(|&r| !raw.table.is_dir(r)).collect()
    };
    if all && inventory.as_ref().is_some_and(|inv| inv.0.is_empty()) {
        return Ok(false);
    }
    if !all && selected_rows.is_empty() && aliases.is_none() {
        return Ok(false);
    }
    let is_selected = |row: usize| all || selected_rows.contains(&row);
    let mut stems: HashSet<_> = selected_rows
        .iter()
        .map(|&r| catalog_stem(&raw.table.paths[r]))
        .collect();
    if let Some(aliases) = aliases {
        stems.extend(aliases.stems.iter().cloned());
    }
    let rows: Vec<_> = raw
        .rows()
        .filter(|&r| {
            !raw.table.is_dir(r)
                && (is_selected(r)
                    || raw.table.relation_member_eligible(r)
                        && stems.contains(&catalog_stem(&raw.table.paths[r])))
        })
        .collect();
    let pool = cheap_fast_probe_pool();
    let embedded = request.deep || request.config.embedded_scan.enabled;
    let parallel_files = rows.len().min(pool.current_num_threads());
    // Deep selects starting files before signature scanning. Smaller files of
    // an admitted stem remain supplemental until Relations confirms ownership.
    let deep_filter = request.deep && matches!(admission, EmbeddedAdmission::MinimumBytes(_));
    let mut admitted_rows = HashSet::new();
    let mut admitted_stems = HashSet::new();
    if deep_filter {
        if options.plain {
            admitted_rows.extend(selected.rows().filter(|&r| {
                !raw.table.is_dir(r) && admission.accepts(raw.table.sizes[r].unwrap_or(0))
            }));
        } else if let Some(inventory) = &inventory {
            admitted_rows.extend(inventory.0.iter().filter_map(|(r, file)| {
                admission
                    .accepts(file.as_ref().ok()?.masks.generation.len)
                    .then_some(*r)
            }));
        }
        admitted_stems.extend(
            admitted_rows
                .iter()
                .map(|&r| catalog_stem(&raw.table.paths[r])),
        );
    }
    let examine = |session: &NativeArchiveSession, row, file: FileViews| {
        let eligible = admission.accepts(file.masks.generation.len);
        let primary = is_selected(row) && (!request.deep || eligible);
        let full_scan = embedded && (eligible || deep_filter || !is_selected(row));
        let mut found = Findings::default();
        let mut empty = if table.empty_middles.is_empty() {
            None
        } else {
            table
                .empty_middles
                .get(&path_key(session.path()))
                .filter(|(g, _)| Some(g) == session.reader().physical_generation())
                .map(|(_, range)| range.clone())
        }
        .unwrap_or(0..0);
        let shared = !empty.is_empty() || file.views.len() > 1;
        let mut roots = file.roots.into_iter();
        for view in file.views {
            let prepared = match roots.next().transpose() {
                Ok(root) => root,
                Err(error) if crate::io::cancellation::is_cancellation(&error) => {
                    return Err(error)
                }
                Err(error) => {
                    found.error.get_or_insert(error);
                    continue;
                }
            };
            if !full_scan
                && embedded
                && matches!(admission, EmbeddedAdmission::MinimumBytes(_))
                && prepared.as_ref().is_some_and(|r| {
                    matches!(r.route(), RootRoute::Residual | RootRoute::ArchivePrefix)
                })
            {
                found.residual_views.push(view.clone());
            }
            let before = found.tasks.len();
            let result = inspect(
                session,
                &view.bind(session.reader())?,
                prepared,
                primary,
                full_scan,
                parallel_files,
                request,
                passwords,
                &mut found,
                shared.then_some(&mut empty),
            );
            if !primary {
                found.peer_tasks.extend(found.tasks.drain(before..));
            }
            if let Err(error) = result {
                if crate::io::cancellation::is_cancellation(&error) {
                    return Err(error);
                }
                found.error.get_or_insert(error);
            }
        }
        verify_unchanged(session)?;
        Ok((found, file.masks))
    };
    let wanted = |row: usize| {
        !request.deep
            || !matches!(admission, EmbeddedAdmission::Disabled)
                && (!deep_filter || admitted_stems.contains(&catalog_stem(&raw.table.paths[row])))
    };
    let prepared = inventory.is_some();
    let guard = if prepared && all {
        None
    } else {
        read_guard(read_scope, &rows)
    };
    let results = pool.install(|| {
        let fresh = rows
            .par_iter()
            .copied()
            .filter(|&r| (!prepared || !is_selected(r)) && could_derive(raw, r, options.probes()) && wanted(r))
            .filter_map(|row| {
                request
                    .cancel
                    .run(|| {
                        open_views(read_scope, row, guard.as_ref(), request)?
                            .map(|(session, file)| examine(&session, row, file))
                            .transpose()
                    })
                    .transpose()
                    .map(|found| (row, found))
            });
        let cached = inventory
            .unwrap_or_default()
            .0
            .into_par_iter()
            .filter_map(|(row, result)| {
                let file = match result {
                    Ok(file) if wanted(row) => file,
                    Ok(_) => return None,
                    Err(err) => return Some((row, Err(err))),
                };
                let result = request.cancel.run(|| {
                    let session = NativeArchiveSession::new(raw.table.paths[row].clone())?;
                    if session.reader().physical_generation() != Some(&file.masks.generation) {
                        return Err(io::Error::other("file changed during read view discovery"));
                    }
                    examine(&session, row, file)
                });
                Some((row, result))
            });
        fresh.chain(cached).collect::<Vec<_>>()
    });
    drop(guard);
    if results.is_empty() {
        return Ok(false);
    }
    let is_selected = |row| is_selected(row) && (!deep_filter || admitted_rows.contains(&row));
    let needs_peers = |a: &VolumeAnchor| a.is_volume_entry() || a.multivolume || a.needs_password;
    let mut nominated: HashSet<_> = results
        .iter()
        .filter(|(_, found)| {
            found
                .as_ref()
                .is_ok_and(|(f, _)| f.anchors.iter().any(|a| needs_peers(a)))
        })
        .map(|(r, _)| catalog_stem(&raw.table.paths[*r]))
        .collect();
    if options.plain {
        // A plain head may be the only volume signature in the family; every
        // admitted view of an opaque continuation still belongs in its domain.
        nominated.extend(
            plain_anchors
                .values()
                .flatten()
                .filter(|a| needs_peers(a))
                .map(|a| catalog_stem(&a.path)),
        );
        nominated.extend(rows.iter().filter_map(|&r| {
            raw.table.relation_anchors[r]
                .as_ref()?
                .anchor()
                .filter(|a| needs_peers(a))
                .map(|_| catalog_stem(&raw.table.paths[r]))
        }));
    }
    // Partition once. A directory with N independent stems must not be walked N times.
    let mut verified = VerifiedPasswords::new();
    let mut added_tasks = false;
    let mut peer_tasks = HashMap::<String, Vec<Task>>::new();
    let mut groups = BTreeMap::<String, (Vec<usize>, Vec<Arc<VolumeAnchor>>)>::new();
    let mut peers = Vec::new();
    let mut primary_roots = HashSet::new();
    let below_threshold = |r: usize| {
        matches!(admission, EmbeddedAdmission::MinimumBytes(_))
            && !admission.accepts(raw.table.sizes[r].unwrap_or(0))
    };
    for (row, result) in results {
        let path = &raw.table.paths[row];
        match result {
            Ok((found, masks)) => {
                if let Some(error) = found.error.filter(|_| is_selected(row)) {
                    out.errors.push(watch_discovery_error(path.into(), error));
                }
                if !found.tasks.is_empty() {
                    added_tasks = true;
                    out.tasks.extend(found.tasks);
                }
                if !found.peer_tasks.is_empty() {
                    peer_tasks.insert(path_key(path), found.peer_tasks);
                }
                if !nominated.is_empty() && !found.anchors.is_empty() {
                    let stem = catalog_stem(path);
                    if nominated.contains(&stem) {
                        if below_threshold(row) && found.anchors.iter().any(|a| needs_peers(a)) {
                            primary_roots.insert(row);
                        }
                        if !found.residual_views.is_empty() {
                            peers.push((
                                stem.clone(),
                                row,
                                Some((masks.generation.clone(), found.residual_views)),
                            ));
                        }
                        verified.extend(found.verified);
                        groups.entry(stem).or_default().1.extend(found.anchors);
                    }
                }
                if !masks.boundaries.is_empty() {
                    mask_ends.insert(path, masks);
                }
            }
            Err(e) if crate::io::cancellation::is_cancellation(&e) => return Err(e),
            Err(e) if is_selected(row) => out.errors.push(watch_discovery_error(path.into(), e)),
            Err(_) => {}
        }
    }
    // A restored volume can nominate ordinary carriers which the physical-only
    // discovery frontier never saw. Scan just the eligible peers of those stems.
    if groups.is_empty() {
        return Ok(added_tasks);
    }
    for row in rows {
        let path = &raw.table.paths[row];
        let stem = catalog_stem(path);
        let Some((scope, facts)) = groups.get_mut(&stem) else {
            continue;
        };
        if options.plain {
            let key = path_key(path);
            let saved = plain_anchors.get(&key);
            let cached = table.plain_peer_scans.get(&key);
            let root = raw.table.relation_anchors[row]
                .as_ref()
                .and_then(|a| a.anchor());
            let supplemental = !is_selected(row) || below_threshold(row);
            if supplemental
                && (root.is_some_and(needs_peers)
                    || saved.is_some_and(|facts| facts.iter().any(|a| needs_peers(a))))
            {
                primary_roots.insert(row);
            }
            if supplemental
                && cached.is_none()
                && (embedded
                    || root.is_some_and(|a| {
                        !a.format.is_empty() || a.pe_state != crate::scan::pe_overlay::PeState::None
                    }))
            {
                peers.push((stem, row, None));
                scope.push(row);
                continue;
            }
            if let Some(Some(scan)) = cached.filter(|_| supplemental) {
                let seed = project_file(path, "", None, false, DiscoverySource::Embedded);
                if let Some(task) = project_segments(seed, scan, HashMap::new(), passwords)? {
                    peer_tasks.entry(key).or_default().push(task);
                }
            }
            if let Some(anchors) = saved {
                facts.extend(anchors.iter().cloned());
            }
            if let Some(fact) = &raw.table.relation_anchors[row] {
                let root = fact.materialize(path, raw.table.sizes[row].unwrap_or(0));
                if !saved.is_some_and(|a| {
                    a.iter().any(|a| {
                        a.format == root.format && a.structure_offset == root.structure_offset
                    })
                }) {
                    facts.push(Arc::new(root));
                }
            }
        }
        scope.push(row);
    }
    if !peers.is_empty() {
        let parallel_files = peers.len().min(pool.current_num_threads());
        let resolved = pool.install(|| {
            peers
                .into_par_iter()
                .map(|(stem, row, mapped)| {
                    let path = &raw.table.paths[row];
                    let result = request.cancel.run(|| {
                        let session = NativeArchiveSession::new(path.clone())?;
                        let mut found = Findings::default();
                        if let Some((generation, views)) = mapped {
                            if session.reader().physical_generation() != Some(&generation) {
                                return Err(io::Error::other(
                                    "file changed during read view discovery",
                                ));
                            }
                            let mut empty = table
                                .empty_middles
                                .get(&path_key(path))
                                .filter(|(g, _)| *g == generation)
                                .map(|(_, range)| range.clone())
                                .unwrap_or(0..0);
                            for view in views {
                                let reader = view.bind(session.reader())?;
                                let scan = scan_embedded_view(
                                    reader.clone(),
                                    parallel_files,
                                    None,
                                    Some(&mut empty),
                                )?;
                                record_scan(
                                    &session,
                                    &reader,
                                    None,
                                    Some(scan),
                                    false,
                                    request,
                                    passwords,
                                    &mut found,
                                )?;
                            }
                            verify_unchanged(&session)?;
                        } else {
                            inspect(
                                &session,
                                session.reader(),
                                None,
                                false,
                                embedded,
                                parallel_files,
                                request,
                                passwords,
                                &mut found,
                                None,
                            )?;
                        }
                        Ok(found)
                    });
                    (stem, row, result)
                })
                .collect::<Vec<_>>()
        });
        for (stem, row, result) in resolved {
            let path = &raw.table.paths[row];
            match result {
                Ok(found) => {
                    groups.get_mut(&stem).unwrap().1.extend(found.anchors);
                    verified.extend(found.verified);
                    if !found.tasks.is_empty() {
                        peer_tasks
                            .entry(path_key(path))
                            .or_default()
                            .extend(found.tasks);
                    }
                }
                Err(e) if crate::io::cancellation::is_cancellation(&e) => return Err(e),
                // A supplemental file is only a candidate. A required missing
                // member is reported by its selected group.
                Err(_) => {
                    if let Some(saved) = plain_anchors.get(&path_key(path)) {
                        groups
                            .get_mut(&stem)
                            .unwrap()
                            .1
                            .extend(saved.iter().cloned());
                    }
                }
            }
        }
    }
    let mut replaced = HashSet::new();
    // A ZIP EOCD fixes one directory for the whole set. The physical-only
    // pass can pair that same tail with a surviving second local header on
    // the head disk. Retire that fixed guess once the full domain owns it.
    let mut plain_zip_tails = HashSet::new();
    let mut required_zip_paths = HashSet::new();
    let mut has_fixed_zip = false;
    let mut has_missing = false;
    let mut has_pending = false;
    for logical in out.tasks.iter().flat_map(|t| &t.inputs) {
        let input = &logical.input;
        has_fixed_zip |= input.format_hint == "zip" && input.parts.len() > 1
            && input.volume_attempts.is_none() && input.analysis.zip_eocd_offset.is_some();
        has_missing |= logical.failure.as_ref().is_some_and(|f| f.kind == FailureKind::MissingVolume);
        has_pending |= input.volume_attempts.is_some();
        if has_fixed_zip && has_missing && has_pending { break; }
    }
    let mut continuations = HashSet::new();
    let mut record_continuation = |extent: &InputExtent| {
        continuations.insert(source_key(&extent.path, "zip", Some(extent)));
        let key = path_key(&extent.path);
        for a in plain_anchors.get(&key).into_iter().flatten() {
            if a.format != "zip"
                || a.strong
                || !a.has_any(crate::analysis_native::volume_anchor::ZIP_LOCAL_HEADER)
            {
                continue;
            }
            let Some(start) = a.structure_offset.filter(|&at| at >= extent.start) else {
                continue;
            };
            let Some(end) = start
                .checked_add(30)
                .filter(|&end| extent.end.is_none_or(|limit| end <= limit))
            else {
                continue;
            };
            // Embedded can nominate a later local header on a mandatory
            // continuation. The same physical header in the selected bytes
            // accounts for that plain missing marker.
            if extent.view.as_ref().is_none_or(|v| v.unchanged(start, end)) {
                continuations.insert((key.clone(), "zip".to_owned(), start, None));
            }
        }
    };
    let mut excluded_heads = HashSet::new();
    // Root discovery can admit a small physical file independently. A disk found
    // only by a supplemental scan must connect to an admitted file.
    let relation_start =
        |row| is_selected(row) && (!below_threshold(row) || primary_roots.contains(&row));
    let clipped = clipped_zip_heads(&out.tasks, groups.values().flat_map(|(_, facts)| facts));
    let clipped_missing = |logical: &LogicalInput| {
        !clipped.is_empty()
            && logical
                .failure
                .as_ref()
                .is_some_and(|f| f.kind == FailureKind::MissingVolume)
            && logical.input.format_hint == "zip"
            && logical.input.volume_attempts.is_none()
            && logical.input.parts.len() == 1
            && clipped.contains(&input_head_key(&logical.input))
    };
    let mut proposals = Vec::new();
    for (rows, mut facts) in groups.into_values() {
        if !facts.iter().any(|a| needs_peers(a)) {
            continue;
        }
        // A user-supplied mask can itself be a disk. Its declared length is
        // an alternative boundary, including on signatureless interior disks.
        // Only nominate prefixes when this family has a ZIP/7z record in a mask.
        let limits = |a: &VolumeAnchor| {
            mask_ends.get(a.path.as_str()).map_or(&[][..], |m| m.boundaries.ends(a.view.as_deref()))
        };
        let mask_family = facts.iter().any(|a| limits(a).iter().any(|&end| a.volume_header_within(end)));
        if mask_family {
            let prefixes: Vec<_> = facts.iter().flat_map(|a| limits(a).iter()
                .filter_map(|&end| a.bounded_prefix(end).map(Arc::new))).collect();
            facts.extend(prefixes);
        }
        if options.plain {
            let plain: HashSet<_> = facts
                .iter()
                .filter(|a| a.view.is_none() && a.structure_offset.is_some())
                .map(|a| (a.path.clone(), a.format, a.structure_offset))
                .collect();
            facts.retain(|a| {
                !a.view.as_ref().is_some_and(|v| {
                    a.structure_offset
                        .zip(a.proven_extent_end().or(a.carrier_limit))
                        .is_some_and(|(start, end)| {
                            v.unchanged(start, end)
                                && plain.contains(&(a.path.clone(), a.format, Some(start)))
                        })
                })
            });
        }
        // Every mapped anchor of this family may describe bytes that the
        // physical pass already owns. With no new range or pending ownership
        // to settle, the original result is final.
        if !has_missing && !has_pending && peer_tasks.is_empty() && !mask_family
            && facts.iter().all(|a| a.view.is_none()) {
            continue;
        }
        // Plain-disabled rows with no admitted view cannot fill an opaque slot.
        let admitted: HashSet<_> = facts.iter().map(|a| path_key(&a.path)).collect();
        let scope = raw.view(
            rows.into_iter()
                .filter(|&r| admitted.contains(&path_key(&raw.table.paths[r])))
                .collect(),
        );
        let has_peers = (!all || matches!(admission, EmbeddedAdmission::MinimumBytes(_)))
            && scope.rows().any(|row| !relation_start(row));
        let requested = has_peers.then(|| {
            scope
                .rows()
                .filter_map(|row| {
                    let path = &raw.table.paths[row];
                    relation_start(row).then(|| path_key(path))
                })
                .collect::<HashSet<_>>()
        });
        let zip_rows: HashMap<_, _> =
            if (has_missing || has_fixed_zip) && facts.iter().any(|a| a.format == "zip") {
                scope
                    .rows()
                    .map(|r| (raw.table.paths[r].as_str(), r))
                    .collect()
            } else {
                HashMap::new()
            };
        let mut relations = crate::relations::resolve_embedded_volumes(
            &[scope],
            facts,
            &HashSet::new(),
            Default::default(),
        );
        if let Some(mut requested) = requested {
            // An excluded target may still name a split family. Only a resolved
            // group can admit carriers; ordinary same-stem archives stay supplemental.
            if let Some(aliases) = aliases {
                for group in &relations {
                    if group
                        .split_alias()
                        .is_some_and(|name| aliases.names.contains(&name))
                    {
                        requested.extend(group.related_paths().map(path_key));
                    }
                }
            }
            crate::relations::retain_connected_groups(&mut relations, &requested);
        }
        if !peer_tasks.is_empty() {
            for path in relations.iter().flat_map(|group| group.related_paths()) {
                if let Some(tasks) = peer_tasks.remove(&path_key(path)) {
                    added_tasks = true;
                    out.tasks.extend(tasks);
                }
            }
        }
        for group in relations {
            if has_missing {
                // A competing, directory-confirmed tail can be optional across
                // layouts. It still accounts for its own headless missing marker.
                for path in group.proven_zip_tails() {
                    if let Some(&row) = zip_rows.get(path) {
                        let root = raw.table.relation_anchors[row]
                            .as_ref()
                            .and_then(|a| a.anchor());
                        if root.is_none_or(|a| {
                            !a.is_volume_entry()
                                || a.has_any(crate::analysis_native::volume_anchor::TERMINAL)
                        }) {
                            required_zip_paths.insert(path_key(path));
                        }
                    }
                }
            }
            excluded_heads.extend(group.excluded_heads().iter().map(|a| {
                (
                    path_key(&a.path),
                    a.format.to_owned(),
                    a.structure_offset.unwrap_or(0),
                    a.view.clone(),
                )
            }));
            let relation = group.project();
            if !relation.input.source_extents().any(|e| {
                e.view.is_some()
                    || mask_family
                        && e.end.is_some_and(|end| mask_ends.get(e.path.as_str())
                            .is_some_and(|m| m.boundaries.ends(None).binary_search(&end).is_ok()))
            }) {
                continue;
            }
            let evidence = if !verified.is_empty()
                && verified.contains_key(&input_head_key(&relation.input))
            {
                &verified
            } else {
                plain_verified
            };
            let task = project_task(
                CandidateProjection::Relation { relation },
                DiscoverySource::Relations,
                evidence,
            );
            if clipped_missing(&task.inputs[0]) {
                continue;
            }
            let input = task.entry();
            if task.inputs[0].failure.is_none() || input.parts.len() > 1 {
                replaced.insert(head_key(input));
                if let Some(plan) = &input.volume_attempts {
                    for head in plan.head_sources() {
                        replaced.insert(source_key(&head.path, &input.format_hint, Some(head)));
                    }
                    if has_fixed_zip && input.format_hint == "zip" {
                        let mut seen = HashSet::new();
                        for layout in &plan.layouts {
                            let Some(last) = layout.slots.last().filter(|s| s.number > 1) else {
                                continue;
                            };
                            if seen.insert(last.domain) {
                                for &i in plan.domains[last.domain].choices.iter() {
                                    let tail = &plan.sources[i];
                                    let path = tail.path.as_str();
                                    if tail.view.is_none() {
                                        let key = (
                                            path_key(&input.entry_path),
                                            path_key(path),
                                            tail.start,
                                        );
                                        if zip_rows
                                            .get(path)
                                            .is_some_and(|&r| raw.table.sizes[r] == tail.end)
                                        {
                                            plain_zip_tails.insert((key.clone(), None));
                                        }
                                        plain_zip_tails.insert((key, tail.end));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // A local ZIP header in a mandatory continuation can look like a
            // missing archive when its other views are absent. Only suppress
            // that fallback when every surviving layout requires this source.
            if has_missing && task.inputs[0].failure.is_none() && input.format_hint == "zip" {
                if let Some(plan) = &input.volume_attempts {
                    let mut common: Option<HashSet<usize>> = None;
                    let mut common_paths: Option<HashSet<&str>> = None;
                    let mut domain_paths = HashMap::new();
                    for layout in &plan.layouts {
                        let min = if layout.minimum_slots == 0 {
                            layout.slots.len()
                        } else {
                            layout.minimum_slots
                        };
                        let mut fixed = HashSet::new();
                        let mut paths = HashSet::new();
                        for slot in layout
                            .slots
                            .iter()
                            .take(min.saturating_sub(1))
                            .chain(layout.slots.last())
                        {
                            let choices = &plan.domains[slot.domain].choices;
                            let path = domain_paths.entry(slot.domain).or_insert_with(|| {
                                let first = plan.sources[*choices.first()?].path.as_str();
                                choices
                                    .iter()
                                    .all(|&i| plan.sources[i].path == first)
                                    .then_some(first)
                            });
                            if let Some(path) = *path {
                                paths.insert(path);
                            }
                            if slot.number > 1 {
                                if let [i] = choices.as_slice() {
                                    fixed.insert(*i);
                                }
                            }
                        }
                        if let Some(common) = &mut common {
                            common.retain(|i| fixed.contains(i));
                        } else {
                            common = Some(fixed);
                        }
                        if let Some(common) = &mut common_paths {
                            common.retain(|p| paths.contains(p));
                        } else {
                            common_paths = Some(paths);
                        }
                        if common.as_ref().is_some_and(HashSet::is_empty)
                            && common_paths.as_ref().is_some_and(HashSet::is_empty)
                        {
                            break;
                        }
                    }
                    // File-mode missing markers can be unlocalized guesses
                    // on any required disk. Preserve an independently rooted
                    // first-volume signature in its own view.
                    for path in common_paths.into_iter().flatten() {
                        if let Some(&row) = zip_rows.get(path) {
                            let root = raw.table.relation_anchors[row]
                                .as_ref()
                                .and_then(|a| a.anchor());
                            if root.is_none_or(|a| {
                                !a.is_volume_entry()
                                    || a.has_any(crate::analysis_native::volume_anchor::TERMINAL)
                            }) {
                                required_zip_paths.insert(path_key(path));
                            }
                        }
                    }
                    for i in common.into_iter().flatten() {
                        let source = &plan.sources[i];
                        record_continuation(source);
                    }
                } else {
                    for part in input
                        .parts
                        .iter()
                        .filter(|p| p.volume_number.is_some_and(|n| n > 1))
                    {
                        record_continuation(&part.extent);
                    }
                }
            }
            proposals.push(task);
        }
    }
    // The expanded domain replaces earlier plain-only volume proposals for the
    // same head. Preserve independent siblings sharing its physical carrier.
    if !replaced.is_empty() || !excluded_heads.is_empty() || !clipped.is_empty() {
        out.tasks.retain_mut(|task| {
            let count = task.inputs.len();
            task.inputs.retain(|logical| {
                let input = &logical.input;
                if !input.mode.structured() && logical.failure.is_none() {
                    return true;
                }
                if !plain_zip_tails.is_empty()
                    && input.volume_attempts.is_none()
                    && input.format_hint == "zip"
                    && input.analysis.zip_eocd_offset.is_some()
                    && input.parts.len() > 1
                    && input.parts.iter().all(|p| p.extent.view.is_none())
                {
                    let tail = &input.parts.last().unwrap().extent;
                    if plain_zip_tails.contains(&(
                        (
                            path_key(&input.entry_path),
                            path_key(&tail.path),
                            tail.start,
                        ),
                        tail.end,
                    )) {
                        return false;
                    }
                }
                if clipped_missing(logical) {
                    return false;
                }
                let key = head_key(input);
                !replaced.contains(&key)
                    && !(input.volume_attempts.is_some() && excluded_heads.contains(&key))
                    && !(logical
                        .failure
                        .as_ref()
                        .is_some_and(|f| f.kind == FailureKind::MissingVolume)
                        && (excluded_heads.contains(&key)
                            || input.format_hint == "zip"
                                && required_zip_paths.contains(&key.0)
                                && (input.mode == OpenMode::File
                                    || input.parts.len() == 1
                                        && key.2 == 0
                                        && key.3.is_none()
                                        && input.parts[0].volume_number.is_some_and(|n| n > 1))
                            || (input.parts.len() <= 1
                                && input.volume_attempts.is_none()
                                && continuations.contains(&key))))
            });
            if task.inputs.is_empty() {
                return false;
            }
            if task.inputs.len() != count {
                task.primary = None;
                let remaining: HashSet<_> = task.input_paths().map(path_key).collect();
                task.owned_paths
                    .retain(|p| remaining.contains(&path_key(p)));
            }
            true
        });
    }
    added_tasks |= !proposals.is_empty();
    out.tasks.extend(proposals);
    Ok(added_tasks)
}
