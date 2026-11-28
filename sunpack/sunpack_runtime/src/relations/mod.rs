use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_reader_at_offset, CheapAnchor, CheapAnchorCell, VolumeAnchor, EMBEDDED_VOLUME, FIRST,
    MEMBER, RAR_END_CHECKED, RAR_OLD_NUMBERING, RAR_PART_NUMBERING, SEVEN_ZIP_NEXT_HEADER_CRC,
    SEVEN_ZIP_STUB, SFX_CHECKED, TERMINAL, UNRESOLVED_VOLUME, WINRAR_STUB, ZIP_CARRIER_CHECKED,
    ZIP_DIRECTORY_MEMBER, ZIP_EOCD_HEAD, ZIP_LOCAL_HEADER, ZIP_SINGLE_DISK, ZIP_SPLIT_END,
    ZIP_AWAITING_TAIL, ZIP_SPLIT_START, ZIP_TAIL_CHECKED, ZIP_TAIL_WITHOUT_HEAD,
};
use crate::io::archive_state::{
    AnalysisOrigin, ArchiveInput, InputExtent, InputPart, InputRole, OpenMode, VolumeCompleteness,
};
use crate::path_keys::{case_key, component_root, path_components, path_key};
use crate::scan::directory::NativeDirectorySnapshot;
use crate::scan::executable_carrier::executable_sfx_stub_profile;
use crate::scan::pe_overlay::{inspect_pe_image_reader, inspect_pe_overlay_reader, PeState};
use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

mod assignment;
mod attempts;
mod bucket;
mod filename;
mod numeric;
mod scope;
mod structural;
mod validate;
use assignment::RelationFailureReason;
use bucket::BucketIndex;
use scope::{CaseKey, RelationScopeIndex, RelationSource};

#[derive(Debug, Clone)]
pub(crate) struct RelationInput {
    path: String,
    pub(crate) path_key: String,
    size: Option<u64>,
    relation_member_eligible: bool,
    // Refine only the facts changed by this relation scope.
    anchor: Option<Arc<VolumeAnchor>>,
    anchor_cell: Option<CheapAnchorCell>,
}

impl RelationInput {
    fn name(&self) -> &str {
        physical_filename(&self.path)
    }

    fn anchor_mut(&mut self) -> Option<&mut VolumeAnchor> {
        self.anchor.as_mut().map(Arc::make_mut)
    }
}

fn physical_filename(path: &str) -> &str {
    Path::new(path).file_name().and_then(|name| name.to_str()).unwrap_or_default()
}

#[derive(Debug)]
struct RelationProposal {
    format: &'static str,
    logical_name: String,
    style: &'static str,
    width: usize,
    // Positive slots are in ascending order. A password-blocked proposal
    // whose physical roles are still hidden has only zero slots.
    volumes: Vec<(String, u32)>,
    companions: Vec<String>,
}

impl RelationProposal {
    fn entry_path(&self) -> &str {
        &self.volumes[0].0
    }

    fn head_path(&self) -> Option<&str> {
        (self.volumes[0].1 == 1).then(|| self.entry_path())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalStatus {
    Valid,
    NeedsPassword,
    Reject,
    Unsupported,
    Inconclusive,
}

#[derive(Debug)]
pub(crate) struct ProposalValidation {
    status: ProposalStatus,
    proposal: RelationProposal,
    facts: Arc<RelationCache>,
    // Several plans can share a bucket while choosing different slices of
    // the same path as their first disk.
    head_override: Option<(String, Arc<VolumeAnchor>)>,
    reason: Option<RelationFailureReason>,
    unresolved: Vec<String>,
    attempts: Option<attempts::VolumeAttempts>,
}

impl ProposalValidation {
    fn anchor(&self, key: &str) -> Option<&VolumeAnchor> {
        self.head_override.as_ref().filter(|(path, _)| path == key).map(|(_, a)| a)
            .or_else(|| self.facts.anchors.get(key)).map(Arc::as_ref)
    }

    fn rar_head(&self) -> Option<&VolumeAnchor> {
        self.proposal.head_path().filter(|_| self.proposal.format == "rar")
            .and_then(|path| self.anchor(&path_key(path)))
    }

    fn any_anchor(&self, mut matches: impl FnMut(&VolumeAnchor) -> bool) -> bool {
        if let Some((path, anchor)) = &self.head_override {
            matches(anchor) || self.facts.anchors.iter().any(|(key, anchor)| key != path && matches(anchor))
        } else {
            self.facts.anchors.values().any(|anchor| matches(anchor))
        }
    }

    fn part_paths(&self) -> impl Iterator<Item = &str> {
        let (volumes, sources) = match &self.attempts {
            Some(plan) => (&[][..], plan.base_sources()),
            None => (self.proposal.volumes.as_slice(), &[][..]),
        };
        volumes
            .iter()
            .map(|part| part.0.as_str())
            .chain(sources.iter().map(|source| source.path.as_str()))
            .chain(self.unresolved.iter().map(String::as_str))
    }

    fn parts_len(&self) -> usize {
        self.attempts
            .as_ref()
            .map_or(self.proposal.volumes.len(), |plan| {
                plan.base_sources().len()
            })
            + self.unresolved.len()
    }
}

/// Structural facts shared by proposals and reused during the same scan.
#[derive(Clone, Debug, Default)]
pub(crate) struct RelationCache {
    pub(crate) anchors: HashMap<String, Arc<VolumeAnchor>>,
    names: HashMap<String, filename::NameFeatures>,
}

#[derive(Debug)]
pub(crate) enum NativeRelationGroup {
    // The discovery table can store either group beside a file row.
    Ordinary(Box<RelationInput>, bool),
    Proposal(Box<ProposalValidation>),
}

pub(crate) struct RelationCandidateData<'a> {
    group: &'a NativeRelationGroup,
    parsed: Option<ParsedVolume>,
    pub(crate) entry_path: &'a str,
    pub(crate) format_hint: &'a str,
    pub(crate) is_split: bool,
    pub(crate) needs_password: bool,
    pub(crate) multivolume: bool,
    pub(crate) relation_confirmed: bool,
    pub(crate) structural_non_head: bool,
}

impl<'a> RelationCandidateData<'a> {
    pub(crate) fn parts_len(&self) -> usize {
        match self.group {
            NativeRelationGroup::Ordinary(..) => 1,
            NativeRelationGroup::Proposal(validation) => validation.parts_len(),
        }
    }

    pub(crate) fn logical_name(&self) -> Cow<'a, str> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => Cow::Owned(
                self.parsed
                    .as_ref()
                    .map(logical_name_from_parsed)
                    .unwrap_or_else(|| get_logical_name(row.name(), true)),
            ),
            NativeRelationGroup::Proposal(validation) => {
                Cow::Borrowed(&validation.proposal.logical_name)
            }
        }
    }

    pub(crate) fn split_family(&self) -> Cow<'a, str> {
        match self.group {
            NativeRelationGroup::Ordinary(_, _) => self
                .parsed
                .as_ref()
                .map(|parsed| {
                    let format = if self.format_hint.is_empty() {
                        parsed.family
                    } else {
                        self.format_hint
                    };
                    split_family_for_proposal(format, parsed.style)
                })
                .unwrap_or(Cow::Borrowed("")),
            NativeRelationGroup::Proposal(validation) => proposal_split_family(
                &validation.proposal,
                validation.rar_head(),
            ),
        }
    }
}

impl NativeRelationGroup {
    pub(crate) fn proven_zip_tails(&self) -> impl Iterator<Item = (&str, Option<&crate::io::view::ReadView>, Option<u64>)> {
        let plan = match self {
            Self::Proposal(v) if v.proposal.format == "zip" && v.status == ProposalStatus::Valid => v.attempts.as_ref(),
            _ => None,
        };
        plan.into_iter().flat_map(|p| p.sources.iter().filter(|s| s.terminal)
            .map(|s| (s.path.as_str(), s.view.as_deref(), s.zip_eocd_offset)))
    }

    pub(crate) fn excluded_heads(&self) -> &[Arc<VolumeAnchor>] {
        match self {
            Self::Proposal(v) => v.attempts.as_ref().map_or(&[], |plan| &plan.excluded_heads),
            Self::Ordinary(..) => &[],
        }
    }

    pub(crate) fn unresolved_password_group(&self) -> bool {
        matches!(self, Self::Proposal(validation) if validation.status == ProposalStatus::NeedsPassword
            && validation.proposal.volumes.iter().all(|(_, number)| *number == 0))
    }

    pub(crate) fn is_incomplete(&self) -> bool {
        matches!(self, Self::Proposal(validation) if matches!(validation.status,
            ProposalStatus::Inconclusive | ProposalStatus::NeedsPassword))
    }

    pub(crate) fn entry_path(&self) -> &str {
        match self {
            Self::Ordinary(row, _) => &row.path,
            Self::Proposal(validation) => validation.proposal.entry_path(),
        }
    }

    pub(crate) fn part_paths(&self) -> impl Iterator<Item = &str> {
        let (ordinary, proposal) = match self {
            Self::Ordinary(row, _) => (Some(row.path.as_str()), None),
            Self::Proposal(validation) => (None, Some(validation.as_ref())),
        };
        ordinary.into_iter().chain(
            proposal.into_iter().flat_map(ProposalValidation::part_paths),
        )
    }

    pub(crate) fn owned_paths(&self) -> impl Iterator<Item = &str> {
        let companions = match self {
            Self::Ordinary(..) => &[][..],
            Self::Proposal(validation) => &validation.proposal.companions,
        };
        self.part_paths().chain(companions.iter().map(String::as_str))
    }

    pub(crate) fn related_paths(&self) -> impl Iterator<Item = &str> {
        // Fixed proposals include the entry among their volumes. An attempt
        // plan supplies the physical members through its base source list.
        let entry = match self {
            Self::Proposal(validation) if validation.attempts.is_some() => {
                Some(validation.proposal.entry_path())
            }
            _ => None,
        };
        self.owned_paths().chain(entry).filter(|path| !path.is_empty())
    }

    pub(crate) fn relation_confirmed(&self) -> bool {
        match self {
            Self::Ordinary(_, confirmed) => *confirmed,
            Self::Proposal(validation) => validation_relation_confirmed(validation),
        }
    }

    pub(crate) fn entry_anchor(&self) -> Option<&VolumeAnchor> {
        match self {
            Self::Ordinary(row, _) => row.anchor.as_deref(),
            Self::Proposal(validation) => validation.anchor(&path_key(validation.proposal.entry_path())),
        }
    }

    pub(crate) fn format_hint(&self) -> &'static str {
        match self {
            Self::Ordinary(row, _) => row.anchor.as_ref().map_or("", |anchor| anchor.format),
            Self::Proposal(validation) => validation.proposal.format,
        }
    }

    pub(crate) fn entry_size(&self) -> Option<u64> {
        match self {
            Self::Ordinary(row, _) => row.size,
            Self::Proposal(_) => self.entry_anchor().map(|a| a.size),
        }
    }

    pub(crate) fn project_standalone(anchor: Arc<VolumeAnchor>) -> RelationProjection {
        let row = RelationInput {
            path: anchor.path.clone(),
            path_key: path_key(&anchor.path),
            size: Some(anchor.size),
            relation_member_eligible: false,
            anchor: Some(anchor),
            anchor_cell: None,
        };
        Self::Ordinary(Box::new(row), true).project()
    }

    pub(crate) fn project(&self) -> RelationProjection {
        let data = self.candidate_data();
        let anchor = self.entry_anchor();
        let mut input = ArchiveInput::file(
            data.entry_path.to_owned(),
            data.format_hint.to_owned(),
            data.logical_name().into_owned(),
        );
        input.analysis.password_required = data.needs_password;
        input.analysis.origin = AnalysisOrigin::Relations;
        input.analysis.standalone_truncated = matches!(self, Self::Ordinary(..))
            && anchor.is_some_and(VolumeAnchor::standalone_truncated);
        let zip_awaits_tail = anchor.is_some_and(|a| a.has_any(ZIP_AWAITING_TAIL))
            && match self {
                Self::Ordinary(..) => true,
                Self::Proposal(validation) => validation.proposal.volumes.len() == 1,
            };
        let failure_reason = match self {
            Self::Proposal(validation) => project_proposal(validation, &mut input),
            Self::Ordinary(..) => {
                if !data.relation_confirmed { input.analysis.origin = AnalysisOrigin::RelationsFallback; }
                if let Some(anchor) = anchor {
                    let start = anchor.structure_offset.unwrap_or(0);
                    if anchor.view.is_some() || start > 0 && (anchor.sfx || data.needs_password || anchor.has_any(EMBEDDED_VOLUME)) {
                        input.mode = OpenMode::FileRange;
                        input.parts = Box::new([InputPart::range(InputExtent {
                            view: anchor.view.clone(),
                            path: data.entry_path.to_owned(),
                            start,
                            end: anchor.expected_logical_size.filter(|end| *end > start).map(|end| end.min(anchor.size)),
                        })]);
                    }
                    if data.format_hint == "zip" {
                        input.analysis.zip_eocd_offset = anchor
                            .zip_eocd_offset
                            .and_then(|end| end.checked_sub(start));
                    }
                }
                if data.needs_password {
                    Some(if anchor.is_some_and(|a| a.wrong_password) {
                        "wrong_password"
                    } else {
                        "needs_password"
                    })
                } else if !data.relation_confirmed
                    && ((data.multivolume && (data.is_split || data.structural_non_head))
                        || anchor
                            .is_some_and(|a| a.has_any(EMBEDDED_VOLUME)))
                {
                    Some("missing_volume")
                } else {
                    None
                }
            }
        };
        RelationProjection {
            input,
            standalone: matches!(self, Self::Ordinary(..))
                && anchor.is_some_and(|anchor| anchor.standalone),
            owned_paths: self.owned_paths().map(str::to_owned).collect(),
            failure_reason: if zip_awaits_tail { Some("corrupt_archive") } else { failure_reason },
        }
    }

    pub(crate) fn speculative_paths(&self) -> impl Iterator<Item = &str> {
        let plan = match self {
            Self::Proposal(validation) => validation.attempts.as_ref(),
            _ => None,
        };
        plan.into_iter().flat_map(|plan| {
            plan.base_sources()
                .iter()
                .map(|source| source.path.as_str())
        })
    }

    pub(crate) fn collect_source_ranges(
        &self,
        paths: &HashSet<String>,
        ranges: &mut HashMap<String, Vec<(u64, u64)>>,
        seen_facts: &mut HashSet<*const RelationCache>,
    ) {
        let mut record = |key: &str, start: u64, end: Option<u64>| {
            if paths.contains(key) {
                // Even an unbounded chunk owns its already known anchor,
                // but cannot suppress a different anchor later in the file.
                let end = end.unwrap_or_else(|| start.saturating_add(1));
                if let Some(extents) = ranges.get_mut(key) {
                    extents.push((start, end));
                } else {
                    ranges.insert(key.to_owned(), vec![(start, end)]);
                }
            }
        };
        match self {
            Self::Proposal(validation) => {
                if let Some(plan) = &validation.attempts {
                    for source in &plan.sources {
                        record(&path_key(&source.path), source.start, source.proven_end);
                    }
                } else if seen_facts.insert(Arc::as_ptr(&validation.facts)) {
                    // Multiple proposals can borrow the same bucket of anchors.
                    // Only ordered attempts carry proposal-specific ranges.
                    for (path, a) in &validation.facts.anchors {
                        record(path, a.structure_offset.unwrap_or(0), a.proven_extent_end());
                    }
                }
            }
            Self::Ordinary(row, _) => {
                if let Some(a) = &row.anchor {
                    record(
                        &row.path_key,
                        a.structure_offset.unwrap_or(0),
                        a.proven_extent_end(),
                    );
                }
            }
        }
    }

    pub(crate) fn split_alias(&self) -> Option<String> {
        let data = self.candidate_data();
        if !data.is_split { return None; }
        Path::new(data.logical_name().as_ref()).file_name().map(|name| case_key(&name.to_string_lossy()))
    }

    pub(crate) fn candidate_data(&self) -> RelationCandidateData<'_> {
        match self {
            Self::Ordinary(row, confirmed) => {
                let anchor = row.anchor.as_deref();
                let parsed = (!confirmed && anchor.is_some_and(anchor_has_split_identity))
                    .then(|| parse_relation_numbered_volume(row.name()))
                    .flatten();
                RelationCandidateData {
                    group: self,
                    is_split: parsed.is_some(),
                    parsed,
                    entry_path: &row.path,
                    format_hint: self.format_hint(),
                    needs_password: anchor.is_some_and(|a| a.needs_password),
                    multivolume: anchor.is_some_and(|a| a.multivolume),
                    relation_confirmed: *confirmed,
                    structural_non_head: anchor.is_some_and(|a| {
                        a.continuation_from_previous
                            || a.internal_volume_number.is_some_and(|number| number > 1)
                            || a.has_any(MEMBER)
                    }),
                }
            }
            Self::Proposal(validation) => {
                let proposal = &validation.proposal;
                let entry_path = proposal.entry_path();
                RelationCandidateData {
                    group: self,
                    parsed: None,
                    entry_path,
                    format_hint: self.format_hint(),
                    is_split: true,
                    needs_password: validation.status == ProposalStatus::NeedsPassword,
                    multivolume: true,
                    relation_confirmed: validation_relation_confirmed(validation),
                    structural_non_head: false,
                }
            }
        }
    }
}

pub(crate) struct RelationProjection {
    pub input: ArchiveInput,
    pub standalone: bool,
    pub owned_paths: Vec<String>,
    pub failure_reason: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct ParsedVolume {
    prefix: String,
    number: u32,
    style: &'static str,
    #[cfg(test)]
    width: usize,
    family: &'static str,
    decorated: bool,
}

pub(crate) fn build_native_candidate_groups_from_snapshot(
    raw_snapshot: &NativeDirectorySnapshot,
    filtered_snapshot: &NativeDirectorySnapshot,
    cached: Option<&RelationCache>,
    prepared_zip_scan: Option<&mut Option<crate::scan::embedded::PreparedZipScan>>,
) -> Vec<NativeRelationGroup> {
    let filtered_keys: HashSet<String> = filtered_snapshot
        .rows()
        .filter(|&row| !filtered_snapshot.table.is_dir(row))
        .map(|row| path_key(&filtered_snapshot.table.paths[row]))
        .collect();
    if filtered_keys.is_empty() {
        return Vec::new();
    }
    build_candidate_groups(raw_snapshot, &filtered_keys, cached, None, prepared_zip_scan)
}

pub(crate) fn collect_relation_cache<'a>(
    groups: impl DoubleEndedIterator<Item = &'a NativeRelationGroup>,
) -> RelationCache {
    let mut cache = RelationCache::default();
    let mut seen = HashSet::new();
    // Visit the last writer first. Several hypotheses can share an entire
    // bucket; copying it again cannot change the winners for any path.
    for group in groups.rev() {
        match group {
            NativeRelationGroup::Ordinary(row, _) => {
                if let Some(anchor) = &row.anchor {
                    cache
                        .anchors
                        .entry(row.path_key.clone())
                        .or_insert_with(|| anchor.clone());
                }
            }
            NativeRelationGroup::Proposal(validation) => {
                if let Some((path, anchor)) = &validation.head_override {
                    cache.anchors.entry(path.clone()).or_insert_with(|| anchor.clone());
                }
                if !seen.insert(Arc::as_ptr(&validation.facts)) {
                    continue;
                }
                for (path, anchor) in &validation.facts.anchors {
                    cache
                        .anchors
                        .entry(path.clone())
                        .or_insert_with(|| anchor.clone());
                }
                for (path, features) in &validation.facts.names {
                    cache
                        .names
                        .entry(path.clone())
                        .or_insert_with(|| features.clone());
                }
            }
        }
    }
    cache
}

/// Re-enter only the original same-stem buckets, borrowing this scan's raw
/// scope and verified anchors. No directory enumeration or Embedded scan.
pub(crate) fn resolve_embedded_volumes(
    snapshots: &[NativeDirectorySnapshot],
    anchors: Vec<Arc<VolumeAnchor>>,
    excluded: &HashSet<String>,
    cache: RelationCache,
) -> Vec<NativeRelationGroup> {
    // A mapped range needs its exact view identity even with just one source per file.
    // Ordinary directories can reuse their one-anchor-per-file cache.
    let mut remaining = HashSet::new();
    let shared = anchors.iter().any(|a| a.view.is_some()
        || a.has_any(crate::analysis_native::volume_anchor::BOUNDED_SOURCE)
        || !remaining.insert(CaseKey::new(&a.path)));
    let mut groups = if shared {
        drop(remaining);
        resolve_shared_carrier_volumes(snapshots, anchors, excluded, cache)
    } else {
        resolve_single_anchor_volumes(snapshots, &anchors, excluded, cache, remaining)
    };
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
                .is_some_and(|a| a.has_any(crate::analysis_native::volume_anchor::SEVEN_ZIP_CARRIER_INTERRUPTED))
    };
    let mut peers: HashMap<String, HashSet<String>> = groups
        .iter()
        .filter(|g| speculative(g))
        .map(|g| (crate::scan::catalog::catalog_stem(g.entry_path()), HashSet::new()))
        .collect();
    if !peers.is_empty() {
        for snapshot in snapshots {
            for row in snapshot.rows() {
                if !snapshot.table.relation_member_eligible(row) {
                    continue;
                }
                let path = &snapshot.table.paths[row];
                if let Some(paths) = peers.get_mut(&crate::scan::catalog::catalog_stem(path)) {
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
                    .get(&crate::scan::catalog::catalog_stem(g.entry_path()))
                    .is_some_and(|p| p.len() > 1)
        });
    }
    groups
}

fn resolve_single_anchor_volumes<'a>(
    snapshots: &'a [NativeDirectorySnapshot],
    anchors: &[Arc<VolumeAnchor>],
    excluded: &HashSet<String>,
    mut cache: RelationCache,
    mut remaining: HashSet<CaseKey<'a>>,
) -> Vec<NativeRelationGroup> {
    cache
        .anchors
        .extend(anchors.iter().map(|a| (path_key(&a.path), Arc::clone(a))));
    let mut output = Vec::new();
    for snapshot in snapshots {
        if remaining.is_empty() {
            break;
        }
        let mut keys = HashSet::new();
        for row in snapshot.rows() {
            let path = &snapshot.table.paths[row];
            if remaining.remove(&CaseKey::new(path)) {
                keys.insert(path_key(path));
                if remaining.is_empty() {
                    break;
                }
            }
        }
        if keys.is_empty() {
            continue;
        }
        output.extend(build_candidate_groups(
            snapshot,
            &keys,
            Some(&cache),
            Some(excluded),
            None,
        ));
    }
    output
}

/// Follow shared physical carriers from the requested paths, keeping each group once.
pub(crate) fn retain_connected_groups(
    groups: &mut Vec<NativeRelationGroup>, requested: &HashSet<String>,
) -> impl Iterator<Item = String> {
    let (mut parents, owners) = path_components(groups.iter().map(NativeRelationGroup::related_paths));
    let mut keep = vec![false; groups.len()];
    for &index in requested.iter().filter_map(|path| owners.get(path)) {
        keep[component_root(&mut parents, index)] = true;
    }
    let mut indexes = 0..groups.len();
    groups.retain(|_| keep[component_root(&mut parents, indexes.next().unwrap())]);
    owners.into_iter().filter_map(move |(path, index)| {
        keep[component_root(&mut parents, index)].then_some(path)
    })
}

/// Resolve logical heads independently while retaining physical snapshot/cache
/// sharing. Conflicting source extents remain speculative until execution.
fn resolve_shared_carrier_volumes(
    snapshots: &[NativeDirectorySnapshot],
    anchors: Vec<Arc<VolumeAnchor>>,
    excluded: &HashSet<String>,
    mut cache: RelationCache,
) -> Vec<NativeRelationGroup> {
    let mut by_path: HashMap<String, Vec<&Arc<VolumeAnchor>>> = HashMap::new();
    for anchor in &anchors {
        by_path
            .entry(path_key(&anchor.path))
            .or_default()
            .push(anchor);
    }
    for (key, values) in &by_path {
        if values.len() == 1 {
            cache.anchors.insert(key.clone(), values[0].clone());
        }
    }
    let selected = by_path.keys().cloned().collect();
    // Materialize only the active stem scopes once, independently of the
    // number of logical heads. Never scan the entire directory per segment.
    let mut proposals = Vec::new();
    let mut mappings = HashSet::new();
    for snapshot in snapshots {
        let source = RelationSource::Snapshot(snapshot, Some(&cache));
        let mut buckets: HashMap<String, Vec<RelationInput>> = HashMap::new();
        for index in RelationScopeIndex::build(&source, &selected, Some(excluded)).rows {
            let row = source.materialize(index);
            buckets.entry(case_key(first_dot_stem(row.name()))).or_default().push(row);
        }
        for scope in buckets.into_values() {
            // A physical row can contain several logical volume slices. Keep
            // all already analyzed anchors before slot/layout construction;
            // never choose a representative anchor and try to repair it later.
            let mut rows = Vec::with_capacity(scope.len());
            for mut row in scope {
                if let Some(options) = by_path.get(&row.path_key) {
                    let (last, previous) = options.split_last().expect("selected path has anchors");
                    row.anchor_cell = None;
                    // A single anchor was already installed in the cache
                    // and copied into this row by materialize().
                    if !previous.is_empty() {
                        row.anchor = None;
                        for anchor in previous {
                            let mut slice = row.clone();
                            slice.size = Some(anchor.size);
                            slice.anchor = Some((*anchor).clone());
                            rows.push(slice);
                        }
                        row.anchor = Some((*last).clone());
                    }
                }
                if let Some(anchor) = &row.anchor { row.size = Some(anchor.size); }
                rows.push(row);
            }
            let name_index = BucketIndex::build(&rows, Some(&selected));
            // Proven logical slices may share a physical lease. Ordinary path
            // arbitration would erase a blocked sibling when another succeeds.
            for validation in resolve_candidate_validations(&mut rows, &name_index, Some(&cache), None) {
                if matches!(validation.status, ProposalStatus::Reject | ProposalStatus::Unsupported) {
                    continue;
                }
                let has_head = validation.proposal.volumes.iter().any(|(_, slot)| *slot == 1);
                let selected = validation.proposal.volumes.iter()
                    .filter(|(_, slot)| *slot == 1 || !has_head && *slot == 0)
                    .any(|(path, _)| {
                        let key = path_key(path);
                        validation.anchor(&key).is_some_and(|head|
                            by_path.get(&key).is_some_and(|anchors| anchors.iter().any(|anchor|
                                anchor.format == validation.proposal.format
                                    && anchor.view == head.view && (anchor.structure_offset == head.structure_offset
                                        || head.has_any(ZIP_DIRECTORY_MEMBER) && anchor.has_any(ZIP_LOCAL_HEADER)
                                            && anchor.structure_offset >= head.structure_offset))))
                    });
                if !selected {
                    continue;
                }
                let mapping: Vec<_> = validation.proposal.volumes.iter().map(|part| {
                    let key = path_key(&part.0);
                    let anchor = validation.anchor(&key);
                    (key, part.1, anchor.and_then(|a| a.structure_offset),
                        anchor.and_then(|a| a.payload_end), anchor.and_then(|a| a.view.clone()))
                }).collect();
                if mappings.insert((validation.proposal.format, mapping, validation.attempts.as_ref().and_then(|p| p.directory_id.clone()))) {
                    proposals.push(validation);
                }
            }
        }
    }
    drop(mappings);
    // Alternative sources are request-owned leases. A successful input only
    // commits its selected extents; overlapping candidates do not erase heads.
    let mut covered = HashSet::new();
    let mut output = Vec::new();
    let weak_zip = |a: &VolumeAnchor| a.view.is_some() && a.has_any(EMBEDDED_VOLUME)
        && a.has_any(ZIP_LOCAL_HEADER) && !a.standalone;
    let has_weak_zip = anchors.iter().any(|a| weak_zip(a));
    let mut zip_disks = HashMap::<String, HashSet<_>>::new();
    for validation in proposals {
        let zip = has_weak_zip && validation.proposal.format == "zip";
        for (path, number) in &validation.proposal.volumes {
            let key = path_key(path);
            if let Some(a) = validation.anchor(&key) {
                if zip && validation.attempts.is_none() && (*number == 1 || a.has_any(TERMINAL)) {
                    zip_disks.entry(key.clone()).or_default().insert((a.view.clone(), a.structure_offset.unwrap_or(0), a.extent_end()));
                }
                covered.insert((key, a.structure_offset, a.view.clone()));
            }
        }
        if let Some(plan) = &validation.attempts {
            covered.extend(plan.excluded_heads.iter().map(|a| (path_key(&a.path), a.structure_offset, a.view.clone())));
            let entry = validation.proposal.entry_path();
            for source in &plan.sources {
                let key = path_key(&source.path);
                if zip && (source.terminal || source.path == entry) {
                    zip_disks.entry(key.clone()).or_default().insert((source.view.clone(), source.start, source.end));
                }
                covered.insert((key, Some(source.start), source.view.clone()));
            }
        }
        output.push(NativeRelationGroup::Proposal(Box::new(validation)));
    }
    let plain_paths: HashSet<_> = if has_weak_zip {
        by_path.into_iter().filter(|(_, options)| options.iter().any(|a| a.view.is_none())).map(|(key, _)| key).collect()
    } else { HashSet::new() };
    for mut anchor in anchors {
        let key = path_key(&anchor.path);
        if covered.contains(&(key.clone(), anchor.structure_offset, anchor.view.clone())) {
            continue;
        }
        // A validated local record with no directory is also an admitted
        // incomplete ZIP. Keep its unknown slot out of numbered assignments.
        let local = weak_zip(&anchor) && anchor.structure_offset.is_some_and(|start| {
                // A recognized ZIP disk can contain a later local member. Its
                // missing marker must refer to the same physical header bytes.
                if let Some(disks) = zip_disks.get(&key) {
                    let end = start.saturating_add(30);
                    let header = crate::io::archive_state::PhysicalRanges::new(anchor.view.as_deref(), start, Some(end));
                    if disks.iter().any(|(v, lo, hi)| *lo <= start && end <= *hi
                        && crate::io::archive_state::PhysicalRanges::new(v.as_deref(), start, Some(end)) == header) {
                        return false;
                    }
                }
                // Plain discovery already owns a local record whose entire
                // remaining slice is an unchanged prefix of that plain input.
                !anchor.view.as_ref().is_some_and(|v| v.unchanged(start, anchor.carrier_limit.unwrap_or(v.len()))
                    && plain_paths.contains(&key))
            });
        let Some(number) = anchor.internal_volume_number.filter(|_| anchor.is_volume_entry())
            .or_else(|| local.then_some(0)) else {
            continue;
        };
        let needs_password = anchor.needs_password || anchor.wrong_password;
        Arc::make_mut(&mut anchor).flags |= UNRESOLVED_VOLUME;
        // Only an entry can retain an unresolved logical input. Orphan slices
        // remain available in the source snapshot for a later entry.
        let path = anchor.path.clone();
        let format = anchor.format;
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let logical_name = get_logical_name(name, true);
        let style = match format {
            "rar" => "rar_part",
            "zip" => "zip_spanned",
            _ => "numeric_suffix",
        };
        output.push(NativeRelationGroup::Proposal(Box::new(ProposalValidation {
            attempts: None,
            status: if needs_password {
                ProposalStatus::NeedsPassword
            } else {
                ProposalStatus::Inconclusive
            },
            proposal: RelationProposal {
                format,
                logical_name,
                style,
                width: 3,
                volumes: vec![(path.clone(), number)],
                companions: Vec::new(),
            },
            facts: Arc::new(RelationCache {
                anchors: HashMap::from([(path_key(&path), anchor)]),
                ..Default::default()
            }),
            head_override: None,
            reason: Some(if needs_password {
                RelationFailureReason::NeedsPassword
            } else {
                RelationFailureReason::MissingVolume
            }),
            unresolved: Vec::new(),
        })));
    }
    output
}

fn resolve_candidate_validations(
    rows: &mut [RelationInput],
    index: &BucketIndex,
    cached: Option<&RelationCache>,
    prepared_zip_scan: Option<&mut Option<crate::scan::embedded::PreparedZipScan>>,
) -> Vec<ProposalValidation> {
    structural::collect(rows, index, prepared_zip_scan);
    let mut validations = assignment::resolve_buckets(rows, index, cached);
    for validation in &mut validations {
        attempts::resolve_carrier_geometry(validation);
        validate::validate(validation);
    }
    validations
}

fn build_candidate_groups(
    snapshot: &NativeDirectorySnapshot,
    filtered_keys: &HashSet<String>,
    cached: Option<&RelationCache>,
    excluded: Option<&HashSet<String>>,
    prepared_zip_scan: Option<&mut Option<crate::scan::embedded::PreparedZipScan>>,
) -> Vec<NativeRelationGroup> {
    let source = RelationSource::Snapshot(snapshot, cached);
    let scope = RelationScopeIndex::build(&source, filtered_keys, excluded);
    let mut output = Vec::new();
    let mut directory_rows: Vec<_> = scope
        .rows
        .into_iter()
        .map(|row| source.materialize(row))
        .collect();
    let name_index = BucketIndex::build(&directory_rows, Some(filtered_keys));
    let validations = resolve_candidate_validations(&mut directory_rows, &name_index, cached, prepared_zip_scan);
    // Arbitration considers every candidate in the active stem bucket,
    // including competitors whose head was not selected by the caller.
    let validation_owned_paths: Vec<HashSet<String>> =
        validations.iter().map(validation_owned_paths).collect();
    let password_conflicted = conflicting_indexes_among(
        &validation_owned_paths,
        validations.iter().enumerate().filter_map(|(index, validation)| {
            (validation.status == ProposalStatus::NeedsPassword).then_some(index)
        }),
    );

    let mut claimed_paths = HashSet::new();
    let mut password_paths = HashSet::new();
    let mut selected_groups = Vec::new();
    for (index, validation) in validations.iter().enumerate() {
        if validation.status != ProposalStatus::Valid {
            continue;
        }
        let owned = &validation_owned_paths[index];
        claimed_paths.extend(owned.iter().map(String::as_str));
        if !owned.is_disjoint(filtered_keys) {
            selected_groups.push(index);
        }
    }

    // Only an unambiguous encrypted proposal is handed to the existing
    // password path.  Ambiguous proposals must not claim the same
    // physical files or suppress their ordinary single-file analysis.
    for (index, validation) in validations.iter().enumerate() {
        if validation.status != ProposalStatus::NeedsPassword {
            continue;
        }
        if password_conflicted.contains(&index) {
            continue;
        }
        let owned = &validation_owned_paths[index];
        if owned.iter().any(|path| claimed_paths.contains(path.as_str())) {
            continue;
        }
        password_paths.extend(owned.iter().map(String::as_str));
        if !owned.is_disjoint(filtered_keys) {
            selected_groups.push(index);
        }
    }

    // A structurally proven volume set that is missing volumes is still
    // one logical archive.  Hand it to Extraction as a split candidate so
    // the worker makes the authoritative missing-volume decision (CLI
    // partial recovery, Watch `suspended_missing_volume`) instead of the
    // set silently vanishing from discovery.
    let incomplete_indexes: Vec<usize> = validations
        .iter()
        .enumerate()
        .filter(|(_, validation)| {
            validation.status == ProposalStatus::Inconclusive
                && validation.reason.is_some_and(|reason| {
                    matches!(
                        reason,
                        RelationFailureReason::MissingVolume
                            | RelationFailureReason::AmbiguousVolumeMapping
                            | RelationFailureReason::StructuralConflict
                    )
                })
        })
        .map(|(index, _)| index)
        .collect();
    let incomplete_conflicted =
        conflicting_indexes_among(&validation_owned_paths, incomplete_indexes.iter().copied());
    for index in incomplete_indexes {
        if incomplete_conflicted.contains(&index) {
            continue;
        }
        let owned = &validation_owned_paths[index];
        if owned
            .iter()
            .any(|path| claimed_paths.contains(path.as_str()) || password_paths.contains(path.as_str()))
        {
            continue;
        }
        claimed_paths.extend(owned.iter().map(String::as_str));
        if !owned.is_disjoint(filtered_keys) {
            selected_groups.push(index);
        }
    }
    // Preserve arbitration order without copying the selected group's
    // anchors, filename features and attempt plan out of the working set.
    let mut validations: Vec<_> = validations.into_iter().map(Some).collect();
    output.extend(
        selected_groups
            .into_iter()
            .map(|index| NativeRelationGroup::Proposal(Box::new(validations[index].take().unwrap()))),
    );

    for row in directory_rows.into_iter().filter(|row| {
        filtered_keys.contains(&row.path_key)
            && !claimed_paths.contains(row.path_key.as_str())
            && !password_paths.contains(row.path_key.as_str())
            && !row.anchor.as_ref().is_some_and(|a| {
                !a.standalone && !a.is_volume_entry()
                    && (a.multivolume || a.continuation_from_previous)
            })
    }) {
        let confirmed = row.anchor.as_deref().is_some_and(anchor_is_relation_archive);
        output.push(NativeRelationGroup::Ordinary(Box::new(row), confirmed));
    }
    output
}

fn anchor_is_relation_archive(anchor: &VolumeAnchor) -> bool {
    let offset = anchor.structure_offset.unwrap_or(0);
    let proven_sfx = offset > 0 && anchor.sfx && anchor.pe_state == PeState::Confirmed;
    if !crate::formats::supports_volume_relations(anchor.format)
        || !anchor.strong
        || !(anchor.standalone || anchor.needs_password || proven_sfx)
    {
        return false;
    }
    offset == 0 || proven_sfx
}

pub(crate) fn promote_sfx_archive_anchor(
    facts: &VolumeAnchor,
    reader: &crate::io::reader::ManagedReader,
) -> Option<VolumeAnchor> {
    if facts.pe_state != PeState::Confirmed {
        return None;
    }
    let Some(image_end) = facts.pe_image_end else {
        return None;
    };
    if image_end == 0 {
        return None;
    }
    let overlay = inspect_pe_overlay_reader(reader, facts.size, image_end);
    if overlay
        .as_ref()
        .is_some_and(|archive| !crate::formats::supports_volume_relations(archive.format))
    {
        return None;
    }

    // Relations only owns genuine self-extracting archives.  A PE with an
    // arbitrary archive overlay is not enough: normal Embedded discovery skips
    // executable carriers, while explicit deep-detect may scan them separately.
    // Prove the decompressor stub first with a bounded image-only probe, then
    // validate the archive at the overlay offset below.
    let sfx_profile = executable_sfx_stub_profile(reader, image_end).ok()?;
    let Some(overlay) = overlay else {
        let stub = match sfx_profile {
            "seven_zip_sfx" => SEVEN_ZIP_STUB,
            "winrar_sfx" => WINRAR_STUB,
            _ => return None,
        };
        let mut anchor = facts.clone();
        anchor.pe_state = PeState::Confirmed;
        anchor.pe_image_end = Some(image_end);
        anchor.sfx = true;
        anchor.flags |= stub;
        return Some(anchor);
    };
    let format = overlay.format;
    let sfx_matches_format = match sfx_profile {
        "seven_zip_sfx" => matches!(format, "7z" | "zip"),
        "winrar_sfx" => matches!(format, "rar" | "zip"),
        _ => false,
    };
    if !sfx_matches_format {
        return None;
    }

    let archive_offset = overlay.offset;

    let mut anchor =
        probe_volume_anchor_reader_at_offset(reader, &facts.path, archive_offset, format)
            .ok()?;
    if anchor.format != format || !anchor.strong {
        return None;
    }
    anchor.pe_state = PeState::Confirmed;
    anchor.pe_image_end = Some(image_end);
    anchor.sfx = true;
    Some(anchor)
}

fn validation_owned_paths(validation: &ProposalValidation) -> HashSet<String> {
    validation
        .part_paths()
        .chain(validation.proposal.companions.iter().map(String::as_str))
        .map(path_key)
        .collect()
}

fn conflicting_indexes_among(
    owned_paths: &[HashSet<String>],
    indexes: impl Iterator<Item = usize>,
) -> HashSet<usize> {
    let mut owner_by_path: HashMap<&str, usize> = HashMap::new();
    let mut conflicted = HashSet::new();
    for index in indexes {
        for path in &owned_paths[index] {
            match owner_by_path.entry(path) {
                std::collections::hash_map::Entry::Occupied(first) => {
                    conflicted.insert(*first.get());
                    conflicted.insert(index);
                }
                std::collections::hash_map::Entry::Vacant(first) => {
                    first.insert(index);
                }
            }
        }
    }
    conflicted
}

fn anchor_has_split_identity(anchor: &VolumeAnchor) -> bool {
    !anchor.standalone
        && (anchor.multivolume || anchor.continuation_from_previous || anchor.continuation_to_next)
}

fn validation_relation_confirmed(validation: &ProposalValidation) -> bool {
    validation.attempts.is_some()
        || (validation.unresolved.is_empty()
            && validation.proposal.volumes.iter().all(|part| part.1 > 0)
            && !validation.reason.is_some_and(|reason| {
                matches!(
                    reason,
                    RelationFailureReason::AmbiguousVolumeMapping
                        | RelationFailureReason::StructuralConflict
                )
            }))
}

fn project_proposal(
    validation: &ProposalValidation,
    input: &mut ArchiveInput,
) -> Option<&'static str> {
    let proposal = &validation.proposal;
    let head = validation.rar_head();
    let style = proposal_split_family(proposal, head);
    input.analysis.zip_spanned = style == "zip_spanned";
    input.analysis.rar_native_volume = head.is_some_and(|head| head.has_any(RAR_OLD_NUMBERING | RAR_PART_NUMBERING));
    input.mode = if style == "rar_sfx_part" {
        OpenMode::SfxWithVolumes
    } else {
        OpenMode::NativeVolumes
    };
    input.analysis.zip_directory_id = validation.attempts.as_ref().and_then(|p| p.directory_id.clone());
    let mut missing_disks = false;
    input.volume_attempts = validation.attempts.as_ref().and_then(|attempts| {
        let mut plan = attempts.project(proposal, &style);
        if input.analysis.zip_spanned {
            missing_disks = plan.prune_missing_zip_layouts();
        }
        (!plan.layouts.is_empty()).then(|| Arc::new(plan))
    });
    // Keep the fixed composition for the Rust password probe. Ordered attempts
    // replace it in the worker request and are materialized only on success.
    let mut zip_position = (proposal.format == "zip" && input.volume_attempts.is_none()).then_some(0u64);
    let mut zip_eocd_offset = None;
    input.parts = proposal
        .volumes
        .iter()
        .map(|(path, number)| {
            let anchor = validation.anchor(&path_key(path));
            if let Some(position) = zip_position {
                zip_position = anchor.and_then(|anchor| {
                    let start = anchor.structure_offset.unwrap_or(0);
                    if let Some(eocd) = anchor.zip_eocd_offset.and_then(|eocd| eocd.checked_sub(start)) {
                        zip_eocd_offset = position.checked_add(eocd);
                        None
                    } else {
                        Some(position.saturating_add(anchor.payload_size()))
                    }
                });
            }
            let terminal = proposal.style == "zip_spanned"
                && anchor.is_some_and(|anchor| anchor.has_any(TERMINAL));
            InputPart {
                role: if *number == 0 { InputRole::Main } else if terminal { InputRole::Terminal } else if *number == 1 { InputRole::First } else { InputRole::Member },
                extent: InputExtent {
                    view: anchor.and_then(|a| a.view.clone()),
                    path: path.clone(),
                    start: anchor.and_then(|a| a.structure_offset).unwrap_or(0),
                    end: anchor.and_then(|a| {
                        let end = a.extent_end();
                        (end < a.size || a.view.is_some() || a.has_any(crate::analysis_native::volume_anchor::BOUNDED_SOURCE)).then_some(end)
                    }),
                },
                volume_number: (*number > 0).then_some(*number),
                canonical_name: if *number == 0 { String::new() } else { canonical_volume_name(
                    &proposal.logical_name,
                    *number,
                    &style,
                    proposal.width,
                    terminal,
                ) },
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    input.volume_style = style.into_owned();
    input.analysis.zip_eocd_offset = zip_eocd_offset;
    let incomplete = missing_disks || validation.status == ProposalStatus::Inconclusive
        || (input.volume_attempts.is_none() && validation.status == ProposalStatus::Valid
            && validation.any_anchor(|anchor| anchor.has_any(UNRESOLVED_VOLUME)));
    input.analysis.volume_completeness = Some(
        if missing_disks {
            VolumeCompleteness::Missing
        } else if input.volume_attempts.is_some() || validation.status == ProposalStatus::NeedsPassword {
            VolumeCompleteness::Unknown
        } else if incomplete {
            VolumeCompleteness::Missing
        } else {
            VolumeCompleteness::Complete
        },
    );
    let reason = match validation.status {
        _ if missing_disks => Some("missing_volume"),
        ProposalStatus::Valid => None,
        ProposalStatus::NeedsPassword => Some(if validation.any_anchor(|a| a.wrong_password) {
            "wrong_password"
        } else { RelationFailureReason::NeedsPassword.as_str() }),
        ProposalStatus::Inconclusive => validation.reason.map(RelationFailureReason::as_str),
        ProposalStatus::Reject | ProposalStatus::Unsupported => {
            unreachable!("only admitted proposals become relation groups")
        }
    };
    if incomplete && reason == Some("missing_volume") {
        input.analysis.missing_volume_evidence = Some("relation_missing_volume".to_owned());
    }
    reason
}

/// Finalize candidate sources with public layout evidence before password
/// selection. The same parse supplies the task-local Rust password material.
pub(crate) fn prepare_volume_candidates(
    input: &mut ArchiveInput,
    sessions: &[crate::io::reader::NativeArchiveSession],
    preparation: &mut crate::password::context::Preparation<'_>,
) -> std::io::Result<()> {
    let (Some(plan), Some(head)) = (input.volume_attempts.as_ref(), input.parts.first()) else {
        return Ok(());
    };
    let material = match input.format_hint.as_str() {
        "7z" => crate::password::seven_zip::prepare_seven_zip_volume_input(&head.extent, plan, sessions),
        "rar" => crate::password::rar::prepare_rar_volume_input(&head.extent, plan, sessions, input.analysis.rar_native_volume),
        _ => return Ok(()),
    };
    crate::io::cancellation::Cancellation::check_current_io()?;
    use crate::password::context::PasswordContext;
    input.analysis.password_required |= match &material {
        Ok(PasswordContext::SevenZip(_)) => true,
        Ok(PasswordContext::Evidence(evidence)) if input.format_hint == "7z" => {
            evidence.unresolved.is_none() && !evidence.alternatives.is_empty()
                && evidence.alternatives.iter().all(|(context, _)| matches!(context, PasswordContext::SevenZip(_)))
        }
        _ => false,
    };
    if let Some(plan) = preparation.prepare_volume_candidates(material)? {
        input.volume_attempts = Some(plan);
    }
    Ok(())
}

fn canonical_volume_name(
    prefix: &str,
    number: u32,
    style: &str,
    width: usize,
    terminal: bool,
) -> String {
    let base = basename(prefix);
    let width = if width == 0 { 3 } else { width };
    match style {
        "rar_part" => format!("{base}.part{number:0width$}.rar"),
        "rar_sfx_part" => {
            let extension = if number == 1 { "exe" } else { "rar" };
            format!("{base}.part{number:0width$}.{extension}")
        }
        "rar_oldstyle" if number == 1 => format!("{base}.rar"),
        "rar_oldstyle" => format!("{base}.r{:02}", number - 2),
        "zip_spanned" if terminal => format!("{base}.zip"),
        "zip_spanned" => format!("{base}.z{number:02}"),
        _ => format!("{base}.{number:03}"),
    }
}

/// Split family used for canonical volume names.  RAR volume names are
/// derived by the handler from the archive's own numbering scheme, so a
/// structurally proven scheme overrides the (possibly disguised) filename
/// style: `x.part1.rar` files of an old-numbering RAR4 set must be exposed as
/// `x.rar`/`x.r00`, and `x.rar`/`x.r00` files of a new-numbering set as parts.
fn proposal_split_family(
    proposal: &RelationProposal,
    head: Option<&VolumeAnchor>,
) -> Cow<'static, str> {
    let style = proposal.style;
    if proposal.format == "rar" && style != "rar_sfx_part" {
        let old_naming = head.is_some_and(|anchor| anchor.has_any(RAR_OLD_NUMBERING));
        let new_naming = head.is_some_and(|anchor| anchor.has_any(RAR_PART_NUMBERING));
        if old_naming && style != "rar_oldstyle" {
            return Cow::Borrowed("rar_oldstyle");
        }
        if new_naming && style == "rar_oldstyle" {
            return Cow::Borrowed("rar_part");
        }
    }
    split_family_for_proposal(proposal.format, style)
}

fn split_family_for_proposal<'a>(format: &str, style: &'a str) -> Cow<'a, str> {
    match (format, style) {
        (_, "zip_spanned" | "rar_part" | "rar_sfx_part" | "rar_oldstyle") => Cow::Borrowed(style),
        (_, "part_numbered") => Cow::Owned(format!("{format}_part")),
        ("7z", _) => Cow::Borrowed("7z_numbered"),
        ("zip", _) => Cow::Borrowed("zip_numbered"),
        _ => Cow::Owned(format!("{format}_numbered")),
    }
}

pub(crate) fn get_logical_name(filename: &str, is_archive: bool) -> String {
    // The display-name fallback also recognizes Unicode decimal digits.
    if filename.bytes().any(|b| b.is_ascii_digit() || !b.is_ascii()) {
        let regexes = regex_cache().acquire();
        if let Some(parsed) = primary_numbered_volume(basename(filename), &regexes) {
            return logical_name_from_parsed(&parsed);
        }
        if let Some(suffix) = regexes
            .zip_zero_numbered_suffix_re()
            .find(filename)
            .or_else(|| regexes.archive_numbered_suffix_re().find(filename))
            .or_else(|| regexes.plain_numeric_suffix_re().find(filename))
        {
            return clean_logical_name(&filename[..suffix.start()]);
        }
    }

    let (base, ext) = split_ext(filename);
    if is_archive
        || [".7z", ".rar", ".zip", ".zipx", ".gz", ".bz2", ".xz", ".exe"]
            .iter()
            .any(|suffix| ext.eq_ignore_ascii_case(suffix))
    {
        return clean_logical_name(base);
    }
    clean_logical_name(filename)
}

fn logical_name_from_parsed(parsed: &ParsedVolume) -> String {
    clean_logical_name(&parsed.prefix)
}

fn parse_relation_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let filename = basename(path);
    has_numbered_suffix(filename)
        .then(|| primary_numbered_volume(filename, &regex_cache().acquire()))
        .flatten()
}

fn primary_numbered_volume(filename: &str, regexes: &RelationRegexes) -> Option<ParsedVolume> {
    parse_volume_candidates_with_regexes(filename, regexes)
        .into_iter()
        .find(|candidate| {
            // Only the marker parser emits these styles with decoration.
            !candidate.decorated
                || matches!(candidate.style, "rar_part" | "rar_sfx_part")
        })
}

/// Return the exact split-family identities a path can participate in.
///
/// This is the sole naming seam exposed to the filesystem scanner. The
/// scanner may retain a size-rejected row when one of these identities has a
/// normally accepted anchor; relations still decides whether the resulting
/// group is a valid archive.
pub(crate) fn relations_size_filter_split_family_keys(path: &str) -> Vec<String> {
    if !may_have_size_deferred_split_identity(path) {
        return Vec::new();
    }
    let mut keys = Vec::new();
    if let Some(parsed) = parse_relation_numbered_volume(path) {
        let scheme = match parsed.style {
            "rar_part" | "rar_sfx_part" => "rar:part",
            "rar_oldstyle" => "rar:oldstyle",
            "zip_spanned" => "zip:spanned",
            "zip_zero_numbered" => "zip:zero-numbered",
            "numeric_suffix" => "archive:numeric",
            "plain_numeric_suffix" => "generic:numeric",
            other => other,
        };
        keys.push(split_size_family_key(scheme, &parsed.prefix));
    }

    // Canonical heads/tails do not themselves carry a numeric suffix, but
    // they can anchor these exact filename families.
    let path = basename(path);
    let (base, ext) = split_ext(path);
    match ext.to_ascii_lowercase().as_str() {
        ".7z" => keys.push(split_size_family_key("archive:numeric", path)),
        ".zip" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("zip:zero-numbered", path));
            keys.push(split_size_family_key("zip:spanned", base));
        }
        ".zipx" => keys.push(split_size_family_key("zip:spanned", base)),
        ".rar" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("rar:oldstyle", base));
        }
        _ => {}
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn may_have_size_deferred_split_identity(path: &str) -> bool {
    let name = basename(path).to_ascii_lowercase();
    if name.ends_with(".7z")
        || name.ends_with(".zip")
        || name.ends_with(".zipx")
        || name.ends_with(".rar")
    {
        return true;
    }
    let suffix = name.rsplit('.').next().unwrap_or_default();
    if (suffix.len() == 3 || suffix.len() == 4) && suffix.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    if suffix.len() >= 3
        && matches!(suffix.as_bytes().first(), Some(b'z' | b'r'))
        && suffix.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    if suffix.len() >= 4
        && suffix.starts_with("zx")
        && suffix.as_bytes()[2..].iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    let has_family_token = ["7z", "zip", "rar", "exe"]
        .iter()
        .any(|token| name.contains(token));
    if has_family_token && (name.contains(".part") || name.contains("vol") || name.contains(".z")) {
        return true;
    }
    // A positive numeric token immediately after "part" also qualifies.
    // The actual family parser runs only after this allocation-free check.
    let fields = name.split_once('.').map_or(name.as_str(), |(_, fields)| fields);
    fields.match_indices("part").any(|(start, marker)| {
        let tail = &fields[start + marker.len()..];
        let end = tail.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(tail.len());
        tail[..end].parse::<u32>().is_ok_and(|number| number > 0)
    })
}

fn split_size_family_key(scheme: &str, prefix: &str) -> String {
    format!("{}\u{001f}{}", scheme, case_key(&prefix.replace('\\', "/")))
}

#[cfg(test)]
fn parse_numbered_volume_name(filename: &str) -> Option<ParsedVolume> {
    filename::NameFeatures::parse(filename)
        .canonical
        .into_iter()
        .next()
}

fn has_numbered_suffix(filename: &str) -> bool {
    filename
        .split_once('.')
        .is_some_and(|(_, suffix)| suffix.bytes().any(|b| b.is_ascii_digit()))
}

/// Parse standard numbering schemes in descending semantic strength.
/// Format-specific offsets stay here; seeded loose recovery uses the linear
/// suffix scanner instead of inventing additional format/number spellings.
///
/// A structural marker such as `part2` deliberately outranks a final numeric
/// token.  For example, `movie.part2.456` is primarily part #2 with `.456` as
/// decoration; the naked-number interpretation remains available only as a
/// weak fallback candidate.
fn parse_volume_candidates_with_regexes(
    filename: &str,
    regexes: &RelationRegexes,
) -> Vec<ParsedVolume> {
    let mut candidates = Vec::new();

    if let Some(parsed) = parse_zip_split_volume(filename, regexes) {
        push_unique_volume_candidate(&mut candidates, parsed);
    }
    if let Some(parsed) = parse_marker_numbered_volume(filename, regexes) {
        push_unique_volume_candidate(&mut candidates, parsed);
    }
    let _ = (|| -> Option<()> {
        if let Some(captures) = regexes.parse_zip_zero_numbered_re().captures(filename) {
            if let Some(raw_number) = captures
                .name("number")
                .and_then(|value| value.as_str().parse::<u32>().ok())
            {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number: raw_number.saturating_add(1),
                        style: "zip_zero_numbered",
                        #[cfg(test)]
                        width: captures.name("number")?.as_str().len(),
                        family: "zip",
                        decorated: captures
                            .name("tail")
                            .is_some_and(|tail| !tail.as_str().is_empty()),
                    },
                );
            }
        }
        if let Some(captures) = regexes.parse_archive_numbered_re().captures(filename) {
            if let (Some(family), Some(raw_number)) = (
                captures
                    .name("format")
                    .and_then(|value| archive_family(value.as_str())),
                captures.name("number"),
            ) {
                if let Some(number) = raw_number
                    .as_str()
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                {
                    push_unique_volume_candidate(
                        &mut candidates,
                        ParsedVolume {
                            prefix: format!("{}.{}", captures.name("prefix")?.as_str(), family),
                            number,
                            style: "numeric_suffix",
                            #[cfg(test)]
                            width: raw_number.as_str().len(),
                            family,
                            decorated: captures
                                .name("tail")
                                .is_some_and(|tail| !tail.as_str().is_empty()),
                        },
                    );
                }
            }
        }
        if let Some(captures) = regexes.parse_rar_part_re().captures(filename) {
            let number = captures.name("number")?.as_str();
            let format = captures.name("format")?.as_str();
            if let Some(number) = number.parse::<u32>().ok().filter(|value| *value > 0) {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number,
                        style: if format.eq_ignore_ascii_case("exe") {
                            "rar_sfx_part"
                        } else {
                            "rar_part"
                        },
                        #[cfg(test)]
                        width: captures.name("number")?.as_str().len(),
                        family: "rar",
                        decorated: false,
                    },
                );
            }
        }
        if let Some(captures) = regexes.parse_old_rar_re().captures(filename) {
            let number = captures.name("number")?.as_str();
            if let Some(number) = number.parse::<u32>().ok() {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number: number.saturating_add(2),
                        style: "rar_oldstyle",
                        #[cfg(test)]
                        width: captures.name("number")?.as_str().len(),
                        family: "rar",
                        decorated: captures
                            .name("tail")
                            .is_some_and(|tail| !tail.as_str().is_empty()),
                    },
                );
            }
        }

        // A final all-numeric token is intentionally last.  It is a discovery
        // hint, not stronger evidence than a marker or an embedded archive token.
        if let Some(captures) = regexes.parse_plain_numbered_re().captures(filename) {
            if let Some(raw_number) = captures.name("number") {
                if let Some(number) = raw_number
                    .as_str()
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                {
                    push_unique_volume_candidate(
                        &mut candidates,
                        ParsedVolume {
                            prefix: captures.name("prefix")?.as_str().to_string(),
                            number,
                            style: "plain_numeric_suffix",
                            #[cfg(test)]
                            width: raw_number.as_str().len(),
                            family: "generic",
                            decorated: false,
                        },
                    );
                }
            }
        }
        Some(())
    })();
    candidates
}

fn parse_zip_split_volume(filename: &str, regexes: &RelationRegexes) -> Option<ParsedVolume> {
    let captures = regexes.parse_zip_split_re().captures(filename)?;
    let raw_number = captures.name("number")?.as_str();
    let number = raw_number.parse::<u32>().ok().filter(|value| *value > 0)?;
    let tail = captures
        .name("tail")
        .map(|value| value.as_str())
        .unwrap_or_default();
    Some(ParsedVolume {
        prefix: captures.name("prefix")?.as_str().to_string(),
        number,
        style: "zip_spanned",
        #[cfg(test)]
        width: raw_number.len(),
        family: "zip",
        decorated: !tail.is_empty(),
    })
}

fn push_unique_volume_candidate(candidates: &mut Vec<ParsedVolume>, candidate: ParsedVolume) {
    if candidates.iter().any(|existing| {
        existing.style == candidate.style
            && existing.family == candidate.family
            && existing.number == candidate.number
            && (existing.prefix == candidate.prefix
                || case_key(&existing.prefix) == case_key(&candidate.prefix))
    }) {
        return;
    }
    candidates.push(candidate);
}

fn parse_marker_numbered_volume(path: &str, regexes: &RelationRegexes) -> Option<ParsedVolume> {
    let captures = regexes.parse_marker_numbered_re().captures(path)?;
    let raw_number = captures.name("number")?.as_str();
    let number = raw_number.parse::<u32>().ok()?;
    if number == 0 {
        return None;
    }

    let raw_prefix = captures.name("prefix")?.as_str();
    let tail = captures
        .name("tail")
        .map(|value| value.as_str())
        .unwrap_or_default();
    let (prefix, trailing_prefix_family) = strip_trailing_archive_token(raw_prefix);
    let mut declared_families = basename(raw_prefix)
        .split('.')
        .filter_map(archive_family)
        .chain(tail.split('.').filter_map(archive_family_hint));
    let family = declared_families
        .next()
        .filter(|first| declared_families.all(|family| family == *first))
        .unwrap_or("generic");
    let prefix_has_exe = raw_prefix
        .rsplit('.')
        .next()
        .is_some_and(|token| token.eq_ignore_ascii_case("exe"));
    let has_exe = prefix_has_exe
        || tail
            .split('.')
            .any(|token| token.eq_ignore_ascii_case("exe"));
    let style = if family == "rar" {
        if has_exe && number == 1 {
            "rar_sfx_part"
        } else {
            "rar_part"
        }
    } else {
        "part_numbered"
    };
    Some(ParsedVolume {
        prefix: if trailing_prefix_family.is_some() {
            prefix.to_string()
        } else {
            raw_prefix.to_string()
        },
        number,
        style,
        #[cfg(test)]
        width: raw_number.len(),
        family,
        decorated: !(tail.eq_ignore_ascii_case(".rar")
            || tail.eq_ignore_ascii_case(".7z")
            || tail.eq_ignore_ascii_case(".zip")
            || tail.eq_ignore_ascii_case(".zipx")
            || (number == 1 && tail.eq_ignore_ascii_case(".exe"))),
    })
}

/// RAR's `partN` token is often the only stable part of a disguised name.
/// Keep this fallback out of the generic filename parser: without a structural
/// RAR anchor, accepting arbitrary `partN` names would merge unrelated files.
fn strip_trailing_archive_token(value: &str) -> (&str, Option<&'static str>) {
    let Some((prefix, token)) = value.rsplit_once('.') else {
        return (value, None);
    };
    archive_family(token)
        .map(|family| (prefix, Some(family)))
        .unwrap_or((value, None))
}

fn archive_family(value: &str) -> Option<&'static str> {
    [("7z", "7z"), ("zip", "zip"), ("zipx", "zip"), ("rar", "rar"), ("exe", "rar")]
        .into_iter()
        .find_map(|(token, family)| value.eq_ignore_ascii_case(token).then_some(family))
}

fn archive_family_hint(value: &str) -> Option<&'static str> {
    if let Some(family) = archive_family(value) {
        return Some(family);
    }
    let lower = value.to_ascii_lowercase();
    match (
        lower.contains("7z"),
        lower.contains("zip"),
        lower.contains("rar") || lower.contains("exe"),
    ) {
        (true, false, false) => Some("7z"),
        (false, true, false) => Some("zip"),
        (false, false, true) => Some("rar"),
        _ => None,
    }
}

pub(crate) fn first_dot_stem(name: &str) -> &str {
    name.split_once('.').map(|(stem, _)| stem).unwrap_or(name)
}

fn split_ext(filename: &str) -> (&str, &str) {
    let basename_start = filename
        .rfind(['\\', '/'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let basename = &filename[basename_start..];
    let Some(dot_in_base) = basename.rfind('.') else {
        return (filename, "");
    };
    if dot_in_base == 0 {
        return (filename, "");
    }
    let dot = basename_start + dot_in_base;
    filename.split_at(dot)
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn clean_logical_name(value: &str) -> String {
    let mut name = value.trim().trim_end_matches('.');
    // Keep archive suffixes in the format/volume attributes, never in the
    // logical filename. Work on borrowed slices even for compound suffixes.
    let basename_start = name.len() - basename(name).len();
    while let Some((stem, suffix)) = name[basename_start..].rsplit_once('.') {
        if stem.is_empty()
            || !(crate::formats::StreamFormat::known_suffix(suffix)
                || ["7z", "rar", "zip", "zipx", "exe"].iter().any(|ext| suffix.eq_ignore_ascii_case(ext)))
        {
            break;
        }
        name = &name[..basename_start + stem.len()];
    }
    let base = basename(name);
    let component = crate::output_names::output_name_component(base);
    if base.len() == name.len() {
        component
    } else {
        format!("{}{component}", &name[..name.len() - base.len()])
    }
}

fn re(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .expect("relation regex should compile")
}

// Each parse owns one generation. Idle cleanup can retire it without waiting
// for active readers; their last Arc drops the search pools when they finish.
#[derive(Default)]
struct RelationRegexCache(RwLock<Option<Arc<RelationRegexes>>>);

impl RelationRegexCache {
    fn acquire(&self) -> Arc<RelationRegexes> {
        {
            let current = self.0.read().unwrap_or_else(|error| error.into_inner());
            if let Some(regexes) = current.as_ref() {
                return Arc::clone(regexes);
            }
        }
        let mut current = self.0.write().unwrap_or_else(|error| error.into_inner());
        Arc::clone(current.get_or_insert_with(|| Arc::new(RelationRegexes::default())))
    }

    fn clear(&self) {
        let retired = self
            .0
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        // Destruction of the potentially large search pools stays outside the lock.
        drop(retired);
    }
}

fn regex_cache() -> &'static RelationRegexCache {
    static CACHE: OnceLock<RelationRegexCache> = OnceLock::new();
    CACHE.get_or_init(RelationRegexCache::default)
}

pub(crate) fn clear_regex_caches() {
    regex_cache().clear()
}

#[derive(Default)]
struct RelationRegexes {
    archive_numbered_suffix_re: OnceLock<Regex>,
    zip_zero_numbered_suffix_re: OnceLock<Regex>,
    plain_numeric_suffix_re: OnceLock<Regex>,
    parse_archive_numbered_re: OnceLock<Regex>,
    parse_zip_zero_numbered_re: OnceLock<Regex>,
    parse_zip_split_re: OnceLock<Regex>,
    parse_rar_part_re: OnceLock<Regex>,
    parse_old_rar_re: OnceLock<Regex>,
    parse_plain_numbered_re: OnceLock<Regex>,
    parse_marker_numbered_re: OnceLock<Regex>,
}

impl RelationRegexes {
    fn archive_numbered_suffix_re(&self) -> &Regex {
        self.archive_numbered_suffix_re
            .get_or_init(|| re(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$"))
    }

    fn zip_zero_numbered_suffix_re(&self) -> &Regex {
        self.zip_zero_numbered_suffix_re
            .get_or_init(|| re(r"\.zip\.\d{4}(?:\.[^.]+)?$"))
    }

    fn plain_numeric_suffix_re(&self) -> &Regex {
        self.plain_numeric_suffix_re.get_or_init(|| re(r"\.\d{3}$"))
    }

    fn parse_archive_numbered_re(&self) -> &Regex {
        self.parse_archive_numbered_re.get_or_init(|| {
            re(r"^(?P<prefix>.+)\.(?P<format>7z|zip|rar)\.(?P<number>\d+)(?P<tail>(?:\.[^.]+)*)$")
        })
    }

    fn parse_zip_zero_numbered_re(&self) -> &Regex {
        self.parse_zip_zero_numbered_re
            .get_or_init(|| re(r"^(?P<prefix>.+\.zip)\.(?P<number>\d{4})(?P<tail>(?:\.[^.]+)*)$"))
    }

    fn parse_zip_split_re(&self) -> &Regex {
        self.parse_zip_split_re
            .get_or_init(|| re(r"^(?P<prefix>.+)\.zx?(?P<number>\d{2,})(?P<tail>(?:\..+)?)$"))
    }

    fn parse_rar_part_re(&self) -> &Regex {
        self.parse_rar_part_re
            .get_or_init(|| re(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.(?P<format>rar|exe)$"))
    }

    fn parse_old_rar_re(&self) -> &Regex {
        self.parse_old_rar_re
            .get_or_init(|| re(r"^(?P<prefix>.+)\.r(?P<number>\d{2,})(?P<tail>(?:\.[^.]+)*)$"))
    }

    fn parse_plain_numbered_re(&self) -> &Regex {
        self.parse_plain_numbered_re
            .get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<number>\d+)$"))
    }

    fn parse_marker_numbered_re(&self) -> &Regex {
        self.parse_marker_numbered_re.get_or_init(|| {
            re(r"^(?P<prefix>.+)\.(?:part|vol(?:ume)?)[-_ ]*(?P<number>\d+)(?:[-_ ][^.]*)?(?P<tail>(?:\.[^.]+)*)$")
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/relations/tests.rs"]
mod tests;
