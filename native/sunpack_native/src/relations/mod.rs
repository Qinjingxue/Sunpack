use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_reader_at_offset, CheapAnchorCell, VolumeAnchor,
};
use crate::io::archive_state::{
    AnalysisOrigin, ArchiveInput, InputExtent, InputPart, InputRole, OpenMode, VolumeCompleteness,
};
use crate::path_keys::{case_key, path_key};
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
use scope::{RelationScopeIndex, RelationSource};

#[derive(Debug, Clone)]
pub(crate) struct RelationInput {
    path: String,
    pub(crate) path_key: String,
    name: String,
    size: Option<u64>,
    relation_member_eligible: bool,
    anchor: Option<VolumeAnchor>,
    anchor_cell: Option<CheapAnchorCell>,
}

#[derive(Debug)]
struct RelationProposal {
    format: String,
    logical_name: String,
    style: String,
    width: usize,
    volumes: Vec<(String, u32)>,
    companions: Vec<String>,
}

impl RelationProposal {
    fn entry_path(&self) -> &str {
        &self
            .volumes
            .iter()
            .find(|(_, number)| *number == 1)
            .unwrap_or(&self.volumes[0])
            .0
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
    reason: Option<RelationFailureReason>,
    unresolved: Vec<String>,
    attempts: Option<attempts::VolumeAttempts>,
}

impl ProposalValidation {
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
    pub(crate) anchors: HashMap<String, VolumeAnchor>,
    names: HashMap<String, filename::NameFeatures>,
}

#[derive(Debug)]
pub(crate) enum NativeRelationGroup {
    Ordinary(RelationInput, bool),
    Proposal(ProposalValidation),
}

pub(crate) struct RelationCandidateData<'a> {
    group: &'a NativeRelationGroup,
    parsed: Option<ParsedVolume>,
    pub(crate) entry_path: &'a str,
    pub(crate) format_hint: &'a str,
    pub(crate) companions: &'a [String],
    pub(crate) carrier_path: &'a str,
    pub(crate) is_split: bool,
    pub(crate) needs_password: bool,
    pub(crate) multivolume: bool,
    pub(crate) relation_confirmed: bool,
    pub(crate) structural_non_head: bool,
}

impl<'a> RelationCandidateData<'a> {
    pub(crate) fn parts(&self) -> impl Iterator<Item = &'a str> {
        let (ordinary, proposal) = match self.group {
            NativeRelationGroup::Ordinary(row, _) => (Some(row.path.as_str()), None),
            NativeRelationGroup::Proposal(validation) => (None, Some(validation)),
        };
        ordinary.into_iter().chain(
            proposal
                .into_iter()
                .flat_map(ProposalValidation::part_paths),
        )
    }

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
                    .unwrap_or_else(|| get_logical_name(&row.name, true)),
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
                    Cow::Owned(split_family_for_proposal(format, parsed.style))
                })
                .unwrap_or(Cow::Borrowed("")),
            NativeRelationGroup::Proposal(validation) => Cow::Owned(proposal_split_family(
                &validation.proposal,
                &validation.facts.anchors,
            )),
        }
    }

    pub(crate) fn size(&self) -> Option<u64> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => row.size,
            NativeRelationGroup::Proposal(validation) => validation
                .facts
                .anchors
                .get(&path_key(self.entry_path))
                .map(|anchor| anchor.size),
        }
    }

    pub(crate) fn logical_size(&self) -> Option<u64> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => row.size,
            NativeRelationGroup::Proposal(validation) => {
                proposal_logical_size(&validation.proposal, &validation.facts.anchors)
            }
        }
    }
}

impl NativeRelationGroup {
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

    pub(crate) fn entry_anchor(&self) -> Option<&VolumeAnchor> {
        match self {
            Self::Ordinary(row, _) => row.anchor.as_ref(),
            Self::Proposal(validation) => validation
                .facts
                .anchors
                .get(&path_key(validation.proposal.entry_path())),
        }
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
        let failure_reason = match self {
            Self::Proposal(validation) => project_proposal(validation, &mut input),
            Self::Ordinary(..) => {
                if !data.relation_confirmed { input.analysis.origin = AnalysisOrigin::RelationsFallback; }
                if let Some(anchor) = anchor {
                    let start = anchor.structure_offset.unwrap_or(0);
                    if start > 0 && (anchor.sfx || data.needs_password) {
                        input.mode = OpenMode::FileRange;
                        input.parts = Box::new([InputPart::range(InputExtent {
                            path: data.entry_path.to_owned(),
                            start,
                            end: anchor.expected_logical_size.filter(|end| *end > start),
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
                            .is_some_and(|a| a.evidence.contains(&"embedded:volume_candidate")))
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
            owned_paths: data
                .parts()
                .chain(data.companions.iter().map(String::as_str))
                .map(str::to_owned)
                .collect(),
            failure_reason,
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
                    if !extents.contains(&(start, end)) {
                        extents.push((start, end));
                    }
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

    pub(crate) fn candidate_data(&self) -> RelationCandidateData<'_> {
        match self {
            Self::Ordinary(row, confirmed) => {
                let anchor = row.anchor.as_ref();
                let parsed = (!confirmed && anchor.is_some_and(anchor_has_split_identity))
                    .then(|| parse_relation_numbered_volume(&row.name))
                    .flatten();
                RelationCandidateData {
                    group: self,
                    is_split: parsed.is_some(),
                    parsed,
                    entry_path: &row.path,
                    format_hint: anchor.map(|a| a.format.as_str()).unwrap_or(""),
                    companions: &[],
                    carrier_path: &row.path,
                    needs_password: anchor.is_some_and(|a| a.needs_password),
                    multivolume: anchor.is_some_and(|a| a.multivolume),
                    relation_confirmed: *confirmed,
                    structural_non_head: anchor.is_some_and(|a| {
                        a.continuation_from_previous
                            || a.internal_volume_number.is_some_and(|number| number > 1)
                            || a.anchor_roles.contains(&"member")
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
                    format_hint: &proposal.format,
                    companions: &proposal.companions,
                    carrier_path: proposal
                        .companions
                        .first()
                        .map(String::as_str)
                        .unwrap_or(entry_path),
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

pub(crate) fn relations_logical_name(filename: &str, is_archive: bool) -> String {
    get_logical_name(filename, is_archive)
}

pub(crate) fn build_native_candidate_groups_from_snapshot(
    raw_snapshot: &NativeDirectorySnapshot,
    filtered_snapshot: &NativeDirectorySnapshot,
    cached: Option<&RelationCache>,
) -> Vec<NativeRelationGroup> {
    let filtered_keys: HashSet<String> = filtered_snapshot
        .rows
        .iter()
        .filter(|&&row| !filtered_snapshot.table.is_dirs[row])
        .map(|&row| path_key(&filtered_snapshot.table.paths[row]))
        .collect();
    if filtered_keys.is_empty() {
        return Vec::new();
    }
    build_candidate_groups_from_source(
        RelationSource::Snapshot(raw_snapshot, cached),
        &filtered_keys,
        cached,
    )
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
    anchors: Vec<VolumeAnchor>,
    excluded: &HashSet<String>,
    mut cache: RelationCache,
) -> Vec<NativeRelationGroup> {
    let mut remaining = HashSet::new();
    if anchors.iter().any(|a| !remaining.insert(path_key(&a.path))) {
        return resolve_shared_carrier_volumes(snapshots, anchors, excluded, cache);
    }
    cache
        .anchors
        .extend(anchors.into_iter().map(|a| (path_key(&a.path), a)));
    let mut output = Vec::new();
    for snapshot in snapshots {
        if remaining.is_empty() {
            break;
        }
        let mut keys = HashSet::new();
        for &row in snapshot.rows.iter() {
            if let Some(key) = remaining.take(&path_key(&snapshot.table.paths[row])) {
                keys.insert(key);
                if remaining.is_empty() {
                    break;
                }
            }
        }
        if keys.is_empty() {
            continue;
        }
        let view = snapshot.without_path_keys(excluded);
        output.extend(build_candidate_groups_from_source(
            RelationSource::Snapshot(&view, Some(&cache)),
            &keys,
            Some(&cache),
        ));
    }
    output
}

/// Resolve logical heads independently while retaining physical snapshot/cache
/// sharing. Conflicting source extents remain speculative until execution.
fn resolve_shared_carrier_volumes(
    snapshots: &[NativeDirectorySnapshot],
    anchors: Vec<VolumeAnchor>,
    excluded: &HashSet<String>,
    mut cache: RelationCache,
) -> Vec<NativeRelationGroup> {
    let mut by_path: HashMap<String, Vec<&VolumeAnchor>> = HashMap::new();
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
    let scopes: Vec<HashMap<String, Vec<RelationInput>>> = snapshots
        .iter()
        .map(|snapshot| {
            let view = snapshot.without_path_keys(excluded);
            let source = RelationSource::Snapshot(&view, Some(&cache));
            let mut buckets: HashMap<String, Vec<RelationInput>> = HashMap::new();
            for index in RelationScopeIndex::build(&source, &selected).rows {
                let row = source.materialize(index);
                buckets
                    .entry(case_key(first_dot_stem(&row.name)))
                    .or_default()
                    .push(row);
            }
            buckets
        })
        .collect();
    let mut proposals = Vec::new();
    let mut mappings = HashSet::new();
    for buckets in &scopes {
        for scope in buckets.values() {
            // A physical row can contain several logical volume slices. Keep
            // all already analyzed anchors before slot/layout construction;
            // never choose a representative anchor and try to repair it later.
            let mut rows = Vec::new();
            for row in scope {
                if let Some(options) = by_path.get(&row.path_key) {
                    for anchor in options {
                        let mut slice = row.clone();
                        slice.anchor = Some((*anchor).clone());
                        slice.anchor_cell = None;
                        rows.push(slice);
                    }
                } else {
                    rows.push(row.clone());
                }
            }
            let name_index = BucketIndex::build(&rows, Some(&selected));
            // Proven logical slices may share a physical lease. Ordinary path
            // arbitration would erase a blocked sibling when another succeeds.
            for validation in resolve_candidate_validations(&mut rows, &name_index, Some(&cache)) {
                let Some((head_path, _)) = validation.proposal.volumes.iter().find(|(_, slot)| *slot == 1) else { continue; };
                let head_key = path_key(head_path);
                let Some(head) = validation.facts.anchors.get(&head_key) else { continue; };
                if !by_path.get(&head_key).is_some_and(|anchors| anchors.iter().any(|anchor|
                    anchor.format == validation.proposal.format
                        && anchor.structure_offset == head.structure_offset)) {
                    continue;
                }
                let group = NativeRelationGroup::Proposal(validation);
                let NativeRelationGroup::Proposal(ref validation) = group else { unreachable!() };
                let mapping: Vec<_> = validation.proposal.volumes.iter().map(|part| {
                    let anchor = validation.facts.anchors.get(&path_key(&part.0));
                    (path_key(&part.0), validation.proposal.format.clone(), part.1, anchor.and_then(|a| a.structure_offset),
                        anchor.and_then(|a| a.payload_end))
                }).collect();
                if mappings.insert(mapping) { proposals.push(group); }
            }
        }
    }
    // Alternative sources are request-owned leases. A successful input only
    // commits its selected extents; overlapping candidates do not erase heads.
    let mut covered = HashSet::new();
    let mut output = Vec::new();
    for group in proposals {
        if let NativeRelationGroup::Proposal(validation) = &group {
            covered.extend(validation.proposal.volumes.iter().filter_map(|part| {
                validation
                    .facts
                    .anchors
                    .get(&path_key(&part.0))
                    .map(|a| (path_key(&a.path), a.structure_offset))
            }));
            if let Some(plan) = &validation.attempts {
                covered.extend(
                    plan.sources
                        .iter()
                        .map(|source| (path_key(&source.path), Some(source.start))),
                );
            }
        }
        output.push(group);
    }
    for mut anchor in anchors {
        if covered.contains(&(path_key(&anchor.path), anchor.structure_offset)) {
            continue;
        }
        let Some(number) = anchor.internal_volume_number.filter(|_| anchor.is_volume_entry()) else {
            continue;
        };
        let needs_password = anchor.needs_password || anchor.wrong_password;
        anchor.evidence.push("embedded:unresolved_volume");
        // Only an entry can retain an unresolved logical input. Orphan slices
        // remain available in the source snapshot for a later entry.
        let path = anchor.path.clone();
        let format = anchor.format.clone();
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let logical_name = get_logical_name(name, true);
        let style = match format.as_str() {
            "rar" => "rar_part",
            "zip" => "zip_spanned",
            _ => "numeric_suffix",
        };
        output.push(NativeRelationGroup::Proposal(ProposalValidation {
            attempts: None,
            status: if needs_password {
                ProposalStatus::NeedsPassword
            } else {
                ProposalStatus::Inconclusive
            },
            proposal: RelationProposal {
                format,
                logical_name,
                style: style.into(),
                width: 3,
                volumes: vec![(path.clone(), number)],
                companions: Vec::new(),
            },
            facts: Arc::new(RelationCache {
                anchors: HashMap::from([(path_key(&path), anchor)]),
                ..Default::default()
            }),
            reason: Some(if needs_password {
                RelationFailureReason::NeedsPassword
            } else {
                RelationFailureReason::MissingVolume
            }),
            unresolved: Vec::new(),
        }));
    }
    output
}

fn resolve_candidate_validations(
    rows: &mut [RelationInput],
    index: &BucketIndex,
    cached: Option<&RelationCache>,
) -> Vec<ProposalValidation> {
    structural::collect(rows, index);
    let mut validations = assignment::resolve_buckets(rows, index, cached);
    for validation in &mut validations {
        attempts::resolve_carrier_geometry(validation);
        validate::validate(validation);
    }
    validations
}

fn build_candidate_groups_from_source(
    source: RelationSource<'_>,
    filtered_keys: &HashSet<String>,
    cached: Option<&RelationCache>,
) -> Vec<NativeRelationGroup> {
    let scope = RelationScopeIndex::build(&source, filtered_keys);
    let mut output = Vec::new();
    let mut directory_rows: Vec<_> = scope
        .rows
        .into_iter()
        .map(|row| source.materialize(row))
        .collect();
    let name_index = BucketIndex::build(&directory_rows, Some(filtered_keys));
    let validations = resolve_candidate_validations(&mut directory_rows, &name_index, cached);
    // Arbitration considers every candidate in the active stem bucket,
    // including competitors whose head was not selected by the caller.
    let validation_owned_paths: Vec<HashSet<String>> =
        validations.iter().map(validation_owned_paths).collect();
    let selected: Vec<_> = validation_owned_paths
        .iter()
        .map(|owned| !owned.is_disjoint(filtered_keys))
        .collect();

    let password_conflicted = conflicting_proposal_indexes(
        &validations,
        &validation_owned_paths,
        ProposalStatus::NeedsPassword,
    );

    let mut claimed_paths = HashSet::new();
    let mut password_paths = HashSet::new();
    let mut selected_groups = Vec::new();
    for (index, validation) in validations.iter().enumerate() {
        if validation.status != ProposalStatus::Valid {
            continue;
        }
        let owned = &validation_owned_paths[index];
        claimed_paths.extend(owned.iter().cloned());
        if selected[index] {
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
        if owned.iter().any(|path| claimed_paths.contains(path)) {
            continue;
        }
        password_paths.extend(owned.iter().cloned());
        if selected[index] {
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
            .any(|path| claimed_paths.contains(path) || password_paths.contains(path))
        {
            continue;
        }
        claimed_paths.extend(owned.iter().cloned());
        if selected[index] {
            selected_groups.push(index);
        }
    }
    // Preserve arbitration order without copying the selected group's
    // anchors, filename features and attempt plan out of the working set.
    let mut validations: Vec<_> = validations.into_iter().map(Some).collect();
    output.extend(
        selected_groups
            .into_iter()
            .map(|index| NativeRelationGroup::Proposal(validations[index].take().unwrap())),
    );

    for row in directory_rows.into_iter().filter(|row| {
        filtered_keys.contains(&row.path_key)
            && !claimed_paths.contains(&row.path_key)
            && !password_paths.contains(&row.path_key)
            && !row.anchor.as_ref().is_some_and(|a| {
                !a.standalone && !a.is_volume_entry()
                    && (a.multivolume || a.continuation_from_previous)
            })
    }) {
        let confirmed = row.anchor.as_ref().is_some_and(anchor_is_relation_archive);
        output.push(NativeRelationGroup::Ordinary(row, confirmed));
    }
    output
}

fn anchor_is_relation_archive(anchor: &VolumeAnchor) -> bool {
    let offset = anchor.structure_offset.unwrap_or(0);
    let proven_sfx = offset > 0 && anchor.sfx && anchor.pe_state == PeState::Confirmed;
    if !matches!(anchor.format.as_str(), "rar" | "7z" | "zip")
        || anchor.confidence != "strong"
        || !(anchor.standalone || anchor.needs_password || proven_sfx)
    {
        return false;
    }
    offset == 0 || proven_sfx
}

fn promote_sfx_archive_anchor(
    row: &RelationInput,
    reader: &crate::io::reader::ManagedReader,
) -> Option<VolumeAnchor> {
    let Some(facts) = row.anchor.as_ref() else {
        return None;
    };
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
        .is_some_and(|archive| !matches!(archive.format, "rar" | "7z" | "zip"))
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
        let evidence = match sfx_profile {
            "seven_zip_sfx" => "sfx:seven_zip_stub",
            "winrar_sfx" => "sfx:winrar_stub",
            _ => return None,
        };
        let mut anchor = row.anchor.clone().unwrap_or_default();
        anchor.pe_state = PeState::Confirmed;
        anchor.pe_image_end = Some(image_end);
        anchor.sfx = true;
        anchor.evidence.push(evidence);
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
        probe_volume_anchor_reader_at_offset(reader, &row.path, archive_offset, format, None)
            .ok()?;
    if anchor.format != format || anchor.confidence != "strong" {
        return None;
    }
    anchor.pe_state = PeState::Confirmed;
    anchor.pe_image_end = Some(image_end);
    anchor.sfx = true;
    anchor.evidence.push("sfx:pe_overlay");
    Some(anchor)
}

fn validation_owned_paths(validation: &ProposalValidation) -> HashSet<String> {
    validation
        .part_paths()
        .chain(validation.proposal.companions.iter().map(String::as_str))
        .map(path_key)
        .collect()
}

fn conflicting_proposal_indexes(
    validations: &[ProposalValidation],
    owned_paths: &[HashSet<String>],
    status: ProposalStatus,
) -> HashSet<usize> {
    debug_assert_eq!(validations.len(), owned_paths.len());

    conflicting_indexes_among(
        owned_paths,
        validations
            .iter()
            .enumerate()
            .filter(|(_, validation)| validation.status == status)
            .map(|(index, _)| index),
    )
}

fn conflicting_indexes_among<T: AsRef<str>>(
    owned_paths: &[HashSet<T>],
    indexes: impl Iterator<Item = usize>,
) -> HashSet<usize> {
    let mut owner_by_path: HashMap<&str, usize> = HashMap::new();
    let mut conflicted = HashSet::new();
    for index in indexes {
        for path in &owned_paths[index] {
            if let Some(previous_index) = owner_by_path.get(path.as_ref()).copied() {
                conflicted.insert(previous_index);
                conflicted.insert(index);
            } else {
                owner_by_path.insert(path.as_ref(), index);
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
    let anchors = &validation.facts.anchors;
    let style = proposal_split_family(proposal, anchors);
    input.analysis.zip_spanned = style == "zip_spanned";
    input.mode = if matches!(style.as_str(), "rar_sfx_part" | "sfx_numeric_suffix") {
        OpenMode::SfxWithVolumes
    } else {
        OpenMode::NativeVolumes
    };
    input.volume_attempts = validation
        .attempts
        .as_ref()
        .map(|attempts| Box::new(attempts.project(proposal, &style)));
    // Keep the fixed composition for the Rust password probe. Ordered attempts
    // replace it in the worker request and are materialized only on success.
    input.parts = proposal
        .volumes
        .iter()
        .filter(|(_, number)| *number > 0)
        .map(|(path, number)| {
            let anchor = anchors.get(&path_key(path));
            let terminal = proposal.style == "zip_spanned"
                && anchor.is_some_and(|anchor| anchor.anchor_roles.contains(&"terminal"));
            InputPart {
                role: if terminal { InputRole::Terminal } else if *number == 1 { InputRole::First } else { InputRole::Member },
                extent: InputExtent {
                    path: path.clone(),
                    start: anchor.and_then(|a| a.structure_offset).unwrap_or(0),
                    end: anchor.and_then(|a| {
                        let end = a.extent_end();
                        (end < a.size).then_some(end)
                    }),
                },
                volume_number: Some(*number),
                canonical_name: canonical_volume_name(
                    &proposal.logical_name,
                    *number,
                    &style,
                    proposal.width,
                    terminal,
                ),
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    input.volume_style = style;
    input.parts.sort_unstable_by_key(|part| part.volume_number);
    if proposal.format == "zip" && input.volume_attempts.is_none() {
        let mut logical_start = 0u64;
        for (path, _) in &proposal.volumes {
            let Some(anchor) = anchors.get(&path_key(path)) else {
                break;
            };
            let start = anchor.structure_offset.unwrap_or(0);
            if let Some(eocd) = anchor
                .zip_eocd_offset
                .and_then(|eocd| eocd.checked_sub(start))
            {
                input.analysis.zip_eocd_offset = logical_start.checked_add(eocd);
                break;
            }
            logical_start = logical_start.saturating_add(anchor.payload_size());
        }
    }
    let incomplete = validation.status == ProposalStatus::Inconclusive
        || anchors
            .values()
            .any(|anchor| anchor.evidence.contains(&"embedded:unresolved_volume"));
    input.analysis.volume_completeness = Some(
        if input.volume_attempts.is_some() || validation.status == ProposalStatus::NeedsPassword {
            VolumeCompleteness::Unknown
        } else if incomplete {
            VolumeCompleteness::Missing
        } else {
            VolumeCompleteness::Complete
        },
    );
    let reason = match validation.status {
        ProposalStatus::Valid => None,
        ProposalStatus::NeedsPassword => Some(if anchors.values().any(|a| a.wrong_password) {
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
        "zip_zero_numbered" => format!("{base}.{:04}", number - 1),
        "sfx_numeric_suffix" if number == 1 => format!("{}.exe", split_ext(base).0),
        "sfx_numeric_suffix" => format!("{base}.{:0width$}", number - 1),
        _ => format!("{base}.{number:03}"),
    }
}

fn proposal_logical_size(
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
) -> Option<u64> {
    proposal.volumes.iter().try_fold(0u64, |total, (path, _)| {
        anchors
            .get(&path_key(path))
            .map(|anchor| total.saturating_add(anchor.payload_size()))
    })
}

/// Split family used for canonical volume names.  RAR volume names are
/// derived by the handler from the archive's own numbering scheme, so a
/// structurally proven scheme overrides the (possibly disguised) filename
/// style: `x.part1.rar` files of an old-numbering RAR4 set must be exposed as
/// `x.rar`/`x.r00`, and `x.rar`/`x.r00` files of a new-numbering set as parts.
fn proposal_split_family(
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
) -> String {
    let style = proposal.style.as_str();
    if proposal.format == "rar" && style != "rar_sfx_part" {
        let head_evidence = proposal
            .volumes
            .iter()
            .find(|(_, number)| *number == 1)
            .and_then(|(path, _)| anchors.get(&path_key(path)))
            .map(|anchor| anchor.evidence.as_slice())
            .unwrap_or(&[]);
        let old_naming = head_evidence.contains(&"rar4:old_volume_naming");
        let new_naming = head_evidence.contains(&"rar4:new_volume_naming")
            || head_evidence.contains(&"rar5:volume_header");
        if old_naming && style != "rar_oldstyle" {
            return "rar_oldstyle".to_string();
        }
        if new_naming && style == "rar_oldstyle" {
            return "rar_part".to_string();
        }
    }
    split_family_for_proposal(&proposal.format, style)
}

fn split_family_for_proposal(format: &str, style: &str) -> String {
    if style == "zip_spanned" {
        return "zip_spanned".to_string();
    }
    if matches!(style, "rar_part" | "rar_sfx_part" | "rar_oldstyle") {
        return style.to_string();
    }
    if style == "part_numbered" {
        return format!("{format}_part");
    }
    format!("{format}_numbered")
}

fn get_logical_name(filename: &str, is_archive: bool) -> String {
    if let Some(parsed) = parse_relation_numbered_volume(filename) {
        return logical_name_from_parsed(&parsed);
    }
    let regexes = regex_cache().acquire();
    if let Some(suffix) = regexes
        .zip_zero_numbered_suffix_re()
        .find(filename)
        .or_else(|| regexes.archive_numbered_suffix_re().find(filename))
        .or_else(|| regexes.plain_numeric_suffix_re().find(filename))
    {
        return clean_logical_name(&filename[..suffix.start()]);
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
    let (_, filename) = split_relation_path(path);
    let regexes = regex_cache().acquire();
    let parsed = parse_volume_candidates_with_regexes(filename, &regexes)
        .into_iter()
        .find(|candidate| {
            !candidate.decorated
                || (candidate.family == "rar"
                    && matches!(candidate.style, "rar_part" | "rar_sfx_part")
                    && regexes.parse_marker_numbered_re().is_match(filename))
        })?;
    Some(parsed)
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
    if filename::NameFeatures::parse(&name)
        .numbers
        .iter()
        .any(|n| n.left.ends_with("part") && n.value > 0)
    {
        return true;
    }
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
    has_family_token && (name.contains(".part") || name.contains("vol") || name.contains(".z"))
}

fn split_size_family_key(scheme: &str, prefix: &str) -> String {
    format!("{}\u{001f}{}", scheme, case_key(&prefix.replace('\\', "/")))
}

#[cfg(test)]
fn parse_numbered_volume_name(filename: &str) -> Option<ParsedVolume> {
    parse_volume_candidates(filename).into_iter().next()
}

/// Parse standard numbering schemes in descending semantic strength.
/// Format-specific offsets stay here; seeded loose recovery uses the linear
/// suffix scanner instead of inventing additional format/number spellings.
///
/// A structural marker such as `part2` deliberately outranks a final numeric
/// token.  For example, `movie.part2.456` is primarily part #2 with `.456` as
/// decoration; the naked-number interpretation remains available only as a
/// weak fallback candidate.
fn parse_volume_candidates(filename: &str) -> Vec<ParsedVolume> {
    parse_volume_candidates_with_regexes(filename, &regex_cache().acquire())
}

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
        case_key(&existing.prefix) == case_key(&candidate.prefix)
            && existing.number == candidate.number
            && existing.style == candidate.style
            && existing.family == candidate.family
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
    let mut declared_families: HashSet<&'static str> = basename(raw_prefix)
        .split('.')
        .filter_map(archive_family)
        .collect();
    declared_families.extend(
        tail.split('.')
            .filter(|token| !token.is_empty())
            .filter_map(archive_family_hint),
    );
    let family = if declared_families.len() == 1 {
        *declared_families.iter().next()?
    } else {
        "generic"
    };
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

fn split_relation_path(path: &str) -> (&str, &str) {
    let Some((separator_index, separator)) = path
        .char_indices()
        .rfind(|(_, character)| matches!(character, '/' | '\\'))
    else {
        return ("", path);
    };
    let filename_index = separator_index + separator.len_utf8();
    (&path[..filename_index], &path[filename_index..])
}

fn archive_family(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "7z" => Some("7z"),
        "zip" | "zipx" => Some("zip"),
        "rar" | "exe" => Some("rar"),
        _ => None,
    }
}

fn archive_family_hint(value: &str) -> Option<&'static str> {
    if let Some(family) = archive_family(value) {
        return Some(family);
    }
    let lower = value.to_ascii_lowercase();
    let mut families = HashSet::new();
    for (token, family) in [("7z", "7z"), ("zip", "zip"), ("rar", "rar"), ("exe", "rar")] {
        if lower.contains(token) {
            families.insert(family);
        }
    }
    (families.len() == 1).then(|| *families.iter().next().expect("one family"))
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
            || ![
                "7z", "rar", "zip", "zipx", "tar", "gz", "gzip", "bz2", "bzip2", "xz", "zst",
                "zstd", "lz4", "tgz", "tbz", "tbz2", "txz", "exe", "enc",
            ]
            .iter()
            .any(|ext| suffix.eq_ignore_ascii_case(ext))
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

    fn clear(&self) -> usize {
        let retired = self
            .0
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        // Destruction of the potentially large search pools stays outside the lock.
        retired
            .as_ref()
            .map_or(0, |regexes| regexes.initialized_count())
    }

    #[cfg(test)]
    fn initialized_count(&self) -> usize {
        self.0
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map_or(0, |regexes| regexes.initialized_count())
    }
}

fn regex_cache() -> &'static RelationRegexCache {
    static CACHE: OnceLock<RelationRegexCache> = OnceLock::new();
    CACHE.get_or_init(RelationRegexCache::default)
}

pub(crate) fn clear_regex_caches() -> usize {
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
    fn initialized_count(&self) -> usize {
        [
            &self.archive_numbered_suffix_re,
            &self.zip_zero_numbered_suffix_re,
            &self.plain_numeric_suffix_re,
            &self.parse_archive_numbered_re,
            &self.parse_zip_zero_numbered_re,
            &self.parse_zip_split_re,
            &self.parse_rar_part_re,
            &self.parse_old_rar_re,
            &self.parse_plain_numbered_re,
            &self.parse_marker_numbered_re,
        ]
        .iter()
        .filter(|value| value.get().is_some())
        .count()
    }

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
mod tests {
    use super::*;
    use crate::analysis_native::volume_anchor::probe_volume_anchor_paths_cheap;

    #[test]
    fn retired_regex_generation_lives_only_until_concurrent_parse_finishes() {
        // Filename outcome tests miss retained pools and concurrent retirement.
        // Without this test, old-generation ownership remains unverified.
        // One synchronized worker covers retirement/reuse without corpus I/O.
        let cache = RelationRegexCache::default();
        let first = cache.acquire();
        let weak = Arc::downgrade(&first);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let parsing = std::thread::spawn(move || {
            assert_eq!(
                parse_volume_candidates_with_regexes("中文.part2.rar.jpg", &first)[0].number,
                2
            );
            ready_tx.send(()).unwrap();
            resume_rx.recv().unwrap();
            assert_eq!(
                parse_volume_candidates_with_regexes("中文.7z.003", &first)[0].number,
                3
            );
        });
        ready_rx.recv().unwrap();
        assert!(cache.clear() > 0);
        assert_eq!(cache.initialized_count(), 0);
        let second = cache.acquire();
        assert!(!Arc::ptr_eq(&weak.upgrade().unwrap(), &second));
        assert_eq!(
            parse_volume_candidates_with_regexes("中文.z02.jpg", &second)[0].number,
            2
        );
        resume_tx.send(()).unwrap();
        parsing.join().unwrap();
        assert!(weak.upgrade().is_none());
        let second_weak = Arc::downgrade(&second);
        drop(second);
        assert!(cache.clear() > 0);
        assert!(second_weak.upgrade().is_none());
        assert_eq!(cache.clear(), 0);
    }

    #[test]
    fn ordinary_words_and_invalid_part_numbers_are_not_volumes() {
        for name in [
            "Counterpart2.zip",
            "Rampart1.rar",
            "apart10.bin",
            "report_part3_final.docx",
            "release.Counterpart2.rar",
            "release.report_part3_final.rar",
            "a.part0.rar",
            "a.part0.rar.hidden",
            "a.rar.part0.hidden",
            "a.part4294967296.rar",
            "a.rar.part4294967296.hidden",
        ] {
            assert!(parse_relation_numbered_volume(name).is_none(), "{name}");
        }
        for (name, family) in [("photo.part2.7z", "7z"), ("a.part1.zip", "zip")] {
            let parsed = parse_relation_numbered_volume(name).unwrap();
            assert_eq!(parsed.family, family);
            assert_eq!(parsed.style, "part_numbered");
        }
        for name in ["a.part4294967295.rar.hidden", "a.rar.part4294967295.hidden"] {
            assert_eq!(
                parse_relation_numbered_volume(name).unwrap().number,
                u32::MAX
            );
        }
        assert_eq!(get_logical_name("Counterpart2.zip", true), "Counterpart2");
        assert_eq!(get_logical_name("Rampart1.rar", true), "Rampart1");
        assert!(!relations_size_filter_split_family_keys("Counterpart2.zip")
            .iter()
            .any(|key| key.starts_with("rar:part")));
    }

    #[test]
    fn size_filter_family_keys_join_numbered_7z_parts_and_exclude_other_prefixes() {
        let first = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.001");
        let tail = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.003");
        let other = relations_size_filter_split_family_keys(r"C:\downloads\other.7z.003");

        assert!(first.iter().any(|key| tail.contains(key)));
        assert!(!first.iter().any(|key| other.contains(key)));
    }

    #[test]
    fn zipx_aliases_share_only_the_standard_zip_spanned_size_family() {
        // Family keys span directories within the active discovery scope.
        let expected = vec![split_size_family_key("zip:spanned", "payload")];
        for name in [
            "payload.zx01",
            "payload.ZX12",
            "payload.zipx",
            "payload.ZIPX",
        ] {
            assert_eq!(
                relations_size_filter_split_family_keys(&format!(r"C:\downloads\{name}")),
                expected,
                "{name}"
            );
        }
        assert_eq!(archive_family("ZIPX"), Some("zip"));
        for name in ["payload.zipx.part02.zipx", "payload.part02.zipx"] {
            let parsed = parse_relation_numbered_volume(name).unwrap();
            assert_eq!(parsed.family, "zip");
            assert_eq!(parsed.prefix, "payload");
        }
        assert_eq!(get_logical_name("payload.zipx", false), "payload");
        for name in [
            "payload.zx0",
            "payload.zx00",
            "payload.zxAA",
            "payload.zx4294967296",
        ] {
            assert!(parse_relation_numbered_volume(name).is_none(), "{name}");
        }
    }

    #[test]
    fn decorated_rar_sfx_head_keeps_exe_token_before_part_marker() {
        let first = parse_numbered_volume_name("shared.bundle.exe.part1.useless.fake").unwrap();
        let second = parse_numbered_volume_name("shared.bundle.rar.part2.useless.fake").unwrap();

        assert_eq!(first.family, "rar");
        assert_eq!(first.style, "rar_sfx_part");
        assert_eq!(first.prefix, "shared.bundle");
        assert_eq!(first.number, 1);
        assert_eq!(second.family, "rar");
        assert_eq!(second.style, "rar_part");
        assert_eq!(second.prefix, "shared.bundle");
        assert_eq!(second.number, 2);
    }

    #[test]
    fn structural_part_marker_outranks_numeric_camouflage_suffix() {
        let candidates = parse_volume_candidates("payload.part2.456");
        assert_eq!(candidates[0].prefix, "payload");
        assert_eq!(candidates[0].number, 2);
        assert_eq!(candidates[0].style, "part_numbered");
        assert_eq!(candidates[0].family, "generic");
        assert!(candidates[0].decorated);
        assert!(candidates.iter().any(|candidate| {
            candidate.style == "plain_numeric_suffix" && candidate.number == 456
        }));
    }

    #[test]
    fn marker_parser_keeps_apparent_format_before_or_after_marker() {
        let before = parse_numbered_volume_name("payload.7z.part0002.photo").unwrap();
        let after = parse_numbered_volume_name("payload.part0002.7z.photo").unwrap();
        for parsed in [before, after] {
            assert_eq!(parsed.prefix, "payload");
            assert_eq!(parsed.number, 2);
            assert_eq!(parsed.style, "part_numbered");
            assert_eq!(parsed.family, "7z");
            assert_eq!(parsed.width, 4);
        }
    }

    #[test]
    fn marker_parser_does_not_treat_partition_words_as_volumes() {
        let parsed = parse_numbered_volume_name("report.partition1.2024").unwrap();
        assert_eq!(parsed.style, "plain_numeric_suffix");
        assert_eq!(parsed.number, 2024);
    }

    #[test]
    fn ordinary_prefix_substrings_do_not_become_format_evidence() {
        let parsed = parse_numbered_volume_name("example.part1.photo").unwrap();
        assert_eq!(parsed.style, "part_numbered");
        assert_eq!(parsed.family, "generic");
    }

    fn validation_with_owned_paths(status: ProposalStatus, paths: &[&str]) -> ProposalValidation {
        ProposalValidation {
            attempts: None,
            status,
            reason: None,
            unresolved: Vec::new(),
            proposal: RelationProposal {
                format: "rar".to_string(),
                logical_name: "test".to_string(),
                style: "rar_part".to_string(),
                width: 2,
                volumes: paths
                    .iter()
                    .enumerate()
                    .map(|(index, path)| ((*path).to_string(), index as u32 + 1))
                    .collect(),
                companions: Vec::new(),
            },
            facts: Arc::default(),
        }
    }

    // A real parsed ENDARC before carrier EOF reaches NativeVolumes with a
    // finite head extent. That physical bound must not invent a scan range.
    #[test]
    fn parsed_rar_head_extent_keeps_native_volume_scan_layout() {
        use crate::analysis_native::volume_anchor::upgrade_relation_rar_end;
        let mut bytes = b"Rar!\x1a\x07\x00".to_vec();
        for (kind, flags, body) in [(0x73, 0x111u16, vec![0; 6]), (0x7b, 1, vec![])] {
            let mut header = vec![0, 0, kind];
            header.extend(flags.to_le_bytes());
            header.extend(((7 + body.len()) as u16).to_le_bytes());
            header.extend(body);
            let crc = crc32fast::hash(&header[2..]) as u16;
            header[..2].copy_from_slice(&crc.to_le_bytes());
            bytes.extend(header);
        }
        let end = bytes.len() as u64;
        bytes.extend([0; 128]);
        let path = crate::test_support::temp_file("scan_native_head", &bytes);
        let path_string = path.to_string_lossy().into_owned();
        let anchor = probe_volume_anchor_paths_cheap(&[path_string.clone()], None).remove(0);
        let anchor = upgrade_relation_rar_end(&anchor, None);
        assert_eq!(anchor.proven_extent_end(), Some(end));
        let mut validation = validation_with_owned_paths(ProposalStatus::Valid, &[&path_string]);
        Arc::make_mut(&mut validation.facts).anchors.insert(path_key(&path_string), anchor);
        let mut input = ArchiveInput::file(path_string, "rar".into(), "test".into());
        input.analysis.origin = AnalysisOrigin::Relations;
        project_proposal(&validation, &mut input);
        assert_eq!(input.mode, OpenMode::NativeVolumes);
        assert_eq!(input.parts[0].extent.start, 0);
        assert_eq!(input.parts[0].extent.end, Some(end));
        let layout = crate::pipeline::ScanLayout::from_input(&input);
        assert!(!layout.range);
        assert!(layout.volumes);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn encrypted_relations_require_readable_anchors_even_with_existing_failure() {
        for reason in [None, Some(RelationFailureReason::MissingVolume)] {
            let path = "archive.part1.rar";
            let mut validation = validation_with_owned_paths(ProposalStatus::Inconclusive, &[path]);
            validation.reason = reason;
            Arc::make_mut(&mut validation.facts).anchors.insert(
                path.into(),
                VolumeAnchor {
                    format: "rar".into(),
                    needs_password: true,
                    ..Default::default()
                },
            );
            validate::validate(&mut validation);
            assert_eq!(validation.status, ProposalStatus::NeedsPassword);
            assert_eq!(
                validate::assignment_status(
                    "rar",
                    false,
                    [(1, validation.facts.anchors.get(path))].into_iter()
                ),
                ProposalStatus::NeedsPassword,
            );

            validation.reason = reason;
            Arc::make_mut(&mut validation.facts)
                .anchors
                .get_mut(path)
                .unwrap()
                .error = "input could not be read".into();
            validate::validate(&mut validation);
            assert_eq!(validation.status, ProposalStatus::Reject);
            assert_eq!(
                validation.reason,
                Some(RelationFailureReason::CorruptArchive)
            );
            assert_eq!(
                validate::assignment_status(
                    "rar",
                    false,
                    [(1, validation.facts.anchors.get(path))].into_iter()
                ),
                ProposalStatus::Reject,
            );
        }
    }

    #[test]
    fn inverted_conflict_index_preserves_status_scoping() {
        let validations = vec![
            validation_with_owned_paths(
                ProposalStatus::Valid,
                &[r"C:\case.part1.rar", r"C:\case.part2.rar"],
            ),
            validation_with_owned_paths(
                ProposalStatus::Valid,
                &[r"C:\case.part2.rar", r"C:\case.part3.rar"],
            ),
            validation_with_owned_paths(ProposalStatus::Valid, &[r"C:\other.part1.rar"]),
            validation_with_owned_paths(ProposalStatus::NeedsPassword, &[r"C:\case.part2.rar"]),
        ];
        let owned_paths: Vec<HashSet<String>> =
            validations.iter().map(validation_owned_paths).collect();

        let valid_conflicts =
            conflicting_proposal_indexes(&validations, &owned_paths, ProposalStatus::Valid);
        let password_conflicts =
            conflicting_proposal_indexes(&validations, &owned_paths, ProposalStatus::NeedsPassword);

        assert_eq!(valid_conflicts, HashSet::from([0, 1]));
        assert!(password_conflicts.is_empty());
    }

    #[test]
    fn inverted_conflict_index_marks_every_candidate_sharing_a_path() {
        let validations = vec![
            validation_with_owned_paths(ProposalStatus::Valid, &[r"C:\shared.bin"]),
            validation_with_owned_paths(ProposalStatus::Valid, &[r"C:\shared.bin"]),
            validation_with_owned_paths(ProposalStatus::Valid, &[r"C:\shared.bin"]),
        ];
        let owned_paths: Vec<HashSet<String>> =
            validations.iter().map(validation_owned_paths).collect();

        let conflicts =
            conflicting_proposal_indexes(&validations, &owned_paths, ProposalStatus::Valid);

        assert_eq!(conflicts, HashSet::from([0, 1, 2]));
    }
}
