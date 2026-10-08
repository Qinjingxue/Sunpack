use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_at_offset, probe_volume_anchor_paths_cheap, VolumeAnchor,
};
use crate::scan::directory::NativeDirectorySnapshot;
use crate::scan::executable_carrier::executable_sfx_stub_profile;
use crate::scan::pe_overlay::{
    inspect_pe_image_native, inspect_pe_overlay_from_image_end, PeState,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

mod assignment;
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
    path_key: String,
    name: String,
    size: Option<u64>,
    relation_member_eligible: bool,
    anchor: Option<VolumeAnchor>,
}

#[derive(Debug, Clone)]
struct RelationProposal {
    format: String,
    logical_name: String,
    style: String,
    volumes: Vec<(String, u32, String, usize, bool)>,
    companions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalStatus {
    Valid,
    NeedsPassword,
    Reject,
    Unsupported,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub(crate) struct ProposalValidation {
    status: ProposalStatus,
    proposal: RelationProposal,
    anchors: HashMap<String, VolumeAnchor>,
    reason: Option<RelationFailureReason>,
    unresolved: Vec<String>,
    name_features: HashMap<String, filename::NameFeatures>,
}

/// Owned by the candidate table's scan lifetime; never a process-wide cache.
#[derive(Default)]
pub(crate) struct RelationCache {
    anchors: HashMap<String, VolumeAnchor>,
    names: HashMap<String, filename::NameFeatures>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum GroupKind {
    Valid,
    Password,
    Incomplete,
}

#[derive(Debug, Clone)]
pub(crate) enum NativeRelationGroup {
    Ordinary(RelationInput, bool),
    Proposal(ProposalValidation, GroupKind),
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
        let ordinary = match self.group {
            NativeRelationGroup::Ordinary(row, _) => Some(row.path.as_str()),
            NativeRelationGroup::Proposal(..) => None,
        };
        let volumes = match self.group {
            NativeRelationGroup::Ordinary(..) => None,
            NativeRelationGroup::Proposal(validation, _) => {
                Some(validation.proposal.volumes.as_slice())
            }
        };
        let unresolved = match self.group {
            NativeRelationGroup::Proposal(validation, _) => validation.unresolved.as_slice(),
            _ => &[],
        };
        ordinary
            .into_iter()
            .chain(
                volumes
                    .into_iter()
                    .flat_map(|volumes| volumes.iter().map(|volume| volume.0.as_str())),
            )
            .chain(unresolved.iter().map(String::as_str))
    }

    pub(crate) fn parts_len(&self) -> usize {
        match self.group {
            NativeRelationGroup::Ordinary(..) => 1,
            NativeRelationGroup::Proposal(validation, _) => {
                validation.proposal.volumes.len() + validation.unresolved.len()
            }
        }
    }

    pub(crate) fn logical_name(&self) -> Cow<'a, str> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => Cow::Owned(
                self.parsed
                    .as_ref()
                    .filter(|_| self.is_split)
                    .map(logical_name_from_parsed)
                    .unwrap_or_else(|| get_logical_name(&row.name, true)),
            ),
            NativeRelationGroup::Proposal(validation, _) => {
                Cow::Borrowed(&validation.proposal.logical_name)
            }
        }
    }

    pub(crate) fn split_family(&self) -> Cow<'a, str> {
        match self.group {
            NativeRelationGroup::Ordinary(_, _) => self
                .parsed
                .as_ref()
                .filter(|_| self.is_split)
                .map(|parsed| {
                    let format = if self.format_hint.is_empty() {
                        parsed.family
                    } else {
                        self.format_hint
                    };
                    Cow::Owned(split_family_for_proposal(format, parsed.style))
                })
                .unwrap_or(Cow::Borrowed("")),
            NativeRelationGroup::Proposal(validation, _) => Cow::Owned(proposal_split_family(
                &validation.proposal,
                &validation.anchors,
            )),
        }
    }

    pub(crate) fn size(&self) -> Option<u64> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => row.size,
            NativeRelationGroup::Proposal(validation, _) => validation
                .anchors
                .get(&self.entry_path.to_ascii_lowercase())
                .map(|anchor| anchor.size),
        }
    }

    pub(crate) fn logical_size(&self) -> Option<u64> {
        match self.group {
            NativeRelationGroup::Ordinary(row, _) => row.size,
            NativeRelationGroup::Proposal(validation, _) => {
                proposal_logical_size(&validation.proposal, &validation.anchors)
            }
        }
    }
}

impl NativeRelationGroup {
    pub(crate) fn entry_anchor(&self) -> Option<&VolumeAnchor> {
        match self {
            Self::Ordinary(row, _) => row.anchor.as_ref(),
            Self::Proposal(validation, _) => validation
                .anchors
                .get(&self.candidate_data().entry_path.to_ascii_lowercase()),
        }
    }

    pub(crate) fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        match self {
            Self::Ordinary(row, confirmed) => ordinary_file_group_to_dict(py, row, *confirmed),
            Self::Proposal(validation, GroupKind::Valid) => {
                validated_proposal_to_dict(py, validation)
            }
            Self::Proposal(validation, GroupKind::Password) => {
                password_error_proposal_to_dict(py, validation)
            }
            Self::Proposal(validation, GroupKind::Incomplete) => {
                incomplete_proposal_to_dict(py, validation)
            }
        }
    }

    pub(crate) fn candidate_data(&self) -> RelationCandidateData<'_> {
        match self {
            Self::Ordinary(row, confirmed) => {
                let parsed = (!confirmed)
                    .then(|| parse_relation_numbered_volume(&row.name))
                    .flatten();
                let hypothesis = !confirmed
                    && parsed.is_some()
                    && row.anchor.as_ref().is_some_and(anchor_has_split_identity);
                let format_hint = row.anchor.as_ref().map(|a| a.format.as_str()).unwrap_or("");
                let anchor = row.anchor.as_ref();
                RelationCandidateData {
                    group: self,
                    parsed,
                    entry_path: &row.path,
                    format_hint,
                    companions: &[],
                    carrier_path: &row.path,
                    is_split: hypothesis,
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
            Self::Proposal(validation, kind) => {
                let proposal = &validation.proposal;
                let head = proposal
                    .volumes
                    .iter()
                    .find(|(_, number, _, _, _)| *number == 1)
                    .unwrap_or(&proposal.volumes[0]);
                RelationCandidateData {
                    group: self,
                    parsed: None,
                    entry_path: &head.0,
                    format_hint: &proposal.format,
                    companions: &proposal.companions,
                    carrier_path: proposal
                        .companions
                        .first()
                        .map(String::as_str)
                        .unwrap_or(&head.0),
                    is_split: true,
                    needs_password: matches!(kind, GroupKind::Password),
                    multivolume: true,
                    relation_confirmed: validation_relation_confirmed(validation),
                    structural_non_head: false,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FileRelationNative {
    filename: String,
    logical_name: String,
    split_role: Option<String>,
    is_split_member: bool,
    has_generic_001_head: bool,
    is_plain_numeric_member: bool,
    has_split_companions: bool,
    is_split_exe_companion: bool,
    is_disguised_split_exe_companion: bool,
    is_split_related: bool,
    match_rar_disguised: bool,
    match_rar_head: bool,
    match_001_head: bool,
    split_family: String,
    split_index: u32,
}

#[derive(Debug, Clone)]
struct ParsedVolume {
    prefix: String,
    number: u32,
    style: &'static str,
    width: usize,
    family: &'static str,
    decorated: bool,
}

#[pyfunction]
pub(crate) fn relations_detect_split_role(filename: &str) -> Option<String> {
    detect_split_role(filename).map(str::to_string)
}

#[pyfunction]
#[pyo3(signature = (filename, is_archive=false))]
pub(crate) fn relations_logical_name(filename: &str, is_archive: bool) -> String {
    get_logical_name(filename, is_archive)
}

#[pyfunction]
pub(crate) fn relations_parse_numbered_volume(
    py: Python<'_>,
    path: &str,
) -> PyResult<Option<Py<PyDict>>> {
    Ok(parse_relation_numbered_volume(path)
        .map(|parsed| parsed_volume_to_dict(py, &parsed))
        .transpose()?)
}

#[pyfunction]
#[pyo3(signature = (raw_snapshot, filtered_snapshot, path_passwords=None))]
pub(crate) fn relations_build_candidate_groups_from_snapshot(
    py: Python<'_>,
    raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    path_passwords: Option<Vec<(String, String)>>,
) -> PyResult<Vec<Py<PyDict>>> {
    let groups = build_native_candidate_groups_from_snapshot(
        py,
        &raw_snapshot,
        &filtered_snapshot,
        path_passwords.as_deref(),
    )?;
    groups.into_iter().map(|group| group.to_dict(py)).collect()
}

pub(crate) fn build_native_candidate_groups_from_snapshot(
    py: Python<'_>,
    raw_snapshot: &NativeDirectorySnapshot,
    filtered_snapshot: &NativeDirectorySnapshot,
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<Vec<NativeRelationGroup>> {
    build_native_candidate_groups_from_snapshot_cached(
        py,
        raw_snapshot,
        filtered_snapshot,
        path_passwords,
        None,
    )
}

pub(crate) fn build_native_candidate_groups_from_snapshot_cached(
    py: Python<'_>,
    raw_snapshot: &NativeDirectorySnapshot,
    filtered_snapshot: &NativeDirectorySnapshot,
    path_passwords: Option<&[(String, String)]>,
    cached: Option<&RelationCache>,
) -> PyResult<Vec<NativeRelationGroup>> {
    let filtered_keys: HashSet<String> = filtered_snapshot
        .rows
        .iter()
        .filter(|&&row| !filtered_snapshot.table.is_dirs[row])
        .map(|&row| filtered_snapshot.table.paths[row].to_ascii_lowercase())
        .collect();
    if filtered_keys.is_empty() {
        return Ok(Vec::new());
    }
    build_candidate_groups_from_source(
        py,
        RelationSource::Snapshot(raw_snapshot, cached),
        &filtered_keys,
        path_passwords,
        cached,
    )
}

pub(crate) fn relation_group_cached_anchors(
    group: &NativeRelationGroup,
    cache: &mut RelationCache,
) {
    match group {
        NativeRelationGroup::Ordinary(row, _) => {
            if let Some(anchor) = &row.anchor {
                cache.anchors.insert(row.path_key.clone(), anchor.clone());
            }
        }
        NativeRelationGroup::Proposal(validation, _) => {
            cache.anchors.extend(
                validation
                    .anchors
                    .iter()
                    .map(|(path, anchor)| (path.clone(), anchor.clone())),
            );
            cache.names.extend(
                validation
                    .name_features
                    .iter()
                    .map(|(path, features)| (path.clone(), features.clone())),
            );
        }
    }
}

fn build_candidate_groups_from_source(
    py: Python<'_>,
    source: RelationSource<'_>,
    filtered_keys: &HashSet<String>,
    path_passwords: Option<&[(String, String)]>,
    cached: Option<&RelationCache>,
) -> PyResult<Vec<NativeRelationGroup>> {
    let scope = RelationScopeIndex::build(&source, filtered_keys);
    let mut output = Vec::new();
    for indices in scope.directories {
        let mut directory_rows: Vec<_> = indices
            .into_iter()
            .map(|row| source.materialize(row))
            .collect();
        let name_index = BucketIndex::build(&directory_rows, Some(filtered_keys));
        structural::collect(py, &mut directory_rows, &name_index, path_passwords)?;
        let mut validations = assignment::resolve_buckets(&directory_rows, &name_index, cached);
        for validation in &mut validations {
            validate::validate(validation);
        }
        // Arbitration considers every candidate in the active stem bucket,
        // including competitors whose head was not selected by the caller.
        let selected: Vec<_> = validations
            .iter()
            .map(|validation| {
                validation
                    .proposal
                    .volumes
                    .iter()
                    .any(|part| filtered_keys.contains(&part.0.to_ascii_lowercase()))
                    || validation
                        .unresolved
                        .iter()
                        .any(|path| filtered_keys.contains(&path.to_ascii_lowercase()))
                    || validation
                        .proposal
                        .companions
                        .iter()
                        .any(|path| filtered_keys.contains(&path.to_ascii_lowercase()))
            })
            .collect();

        let validation_owned_paths: Vec<HashSet<String>> =
            validations.iter().map(validation_owned_paths).collect();

        let conflicted = conflicting_proposal_indexes(
            &validations,
            &validation_owned_paths,
            ProposalStatus::Valid,
        );
        let password_conflicted = conflicting_proposal_indexes(
            &validations,
            &validation_owned_paths,
            ProposalStatus::NeedsPassword,
        );

        let mut claimed_paths = HashSet::new();
        let mut password_paths = HashSet::new();
        for (index, validation) in validations.iter().enumerate() {
            if validation.status != ProposalStatus::Valid || conflicted.contains(&index) {
                continue;
            }
            let owned = &validation_owned_paths[index];
            if owned.iter().any(|path| claimed_paths.contains(path)) {
                continue;
            }
            claimed_paths.extend(owned.iter().cloned());
            if selected[index] {
                output.push(NativeRelationGroup::Proposal(
                    validation.clone(),
                    GroupKind::Valid,
                ));
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
                output.push(NativeRelationGroup::Proposal(
                    validation.clone(),
                    GroupKind::Password,
                ));
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
                output.push(NativeRelationGroup::Proposal(
                    validations[index].clone(),
                    GroupKind::Incomplete,
                ));
            }
        }

        for row in directory_rows.into_iter().filter(|row| {
            filtered_keys.contains(&row.path_key)
                && !claimed_paths.contains(&row.path_key)
                && !password_paths.contains(&row.path_key)
        }) {
            let confirmed = row.anchor.as_ref().is_some_and(anchor_is_relation_archive);
            output.push(NativeRelationGroup::Ordinary(row, confirmed));
        }
    }
    Ok(output)
}

fn cheap_seed_strength(anchor: &VolumeAnchor) -> Option<&'static str> {
    // A structure-proven standalone archive is already a complete logical
    // input.  SFX is a carrier/layout property, not split evidence by itself.
    if anchor.standalone {
        return None;
    }
    if anchor.format.is_empty() && anchor.pe_state != PeState::None {
        return Some("weak");
    }
    if !matches!(anchor.format.as_str(), "rar" | "7z" | "zip") {
        return None;
    }
    if anchor.format == "rar"
        && anchor
            .evidence
            .iter()
            .any(|item| *item == "rar5:encryption_header")
    {
        return Some("weak");
    }
    if anchor.format == "zip" && anchor.confidence == "weak" {
        return Some("weak");
    }
    (anchor.confidence == "strong"
        && (anchor.multivolume
            || anchor.sfx
            || anchor.continuation_from_previous
            || anchor.continuation_to_next
            || anchor.anchor_roles.contains(&"terminal")))
    .then_some("strong")
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
    py: Python<'_>,
    row: &RelationInput,
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<Option<VolumeAnchor>> {
    let Some(facts) = row.anchor.as_ref() else {
        return Ok(None);
    };
    if facts.pe_state != PeState::Confirmed {
        return Ok(None);
    }
    let Some(image_end) = facts.pe_image_end else {
        return Ok(None);
    };
    let overlay = py.detach(|| inspect_pe_overlay_from_image_end(&row.path, facts.size, image_end));
    let archive_like = overlay.archive_like;
    let format = overlay.format;
    if archive_like && !matches!(format, "rar" | "7z" | "zip") {
        return Ok(None);
    }
    let image_end = overlay.overlay_offset;
    if image_end == 0 {
        return Ok(None);
    }

    // Relations only owns genuine self-extracting archives.  A PE with an
    // arbitrary archive overlay is not enough: normal Embedded discovery skips
    // executable carriers, while explicit deep-detect may scan them separately.
    // Prove the decompressor stub first with a bounded image-only probe, then
    // validate the archive at the overlay offset below.
    let sfx_path = row.path.clone();
    let sfx_profile = py.detach(move || executable_sfx_stub_profile(&sfx_path, image_end));
    if !archive_like {
        let evidence = match sfx_profile.as_str() {
            "seven_zip_sfx" => "sfx:seven_zip_stub",
            "winrar_sfx" => "sfx:winrar_stub",
            _ => return Ok(None),
        };
        let mut anchor = row.anchor.clone().unwrap_or_default();
        anchor.pe_state = PeState::Confirmed;
        anchor.pe_image_end = Some(image_end);
        anchor.sfx = true;
        anchor.evidence.push(evidence);
        return Ok(Some(anchor));
    }
    let sfx_matches_format = match sfx_profile.as_str() {
        "seven_zip_sfx" => matches!(format, "7z" | "zip"),
        "winrar_sfx" => matches!(format, "rar" | "zip"),
        _ => false,
    };
    if !sfx_matches_format {
        return Ok(None);
    }

    let archive_offset = overlay.archive_offset;
    if archive_offset == 0 {
        return Ok(None);
    }

    let path = row.path.clone();
    let password = path_passwords.and_then(|items| {
        items
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(&path))
            .map(|(_, password)| password.clone())
    });
    let format_for_probe = format;
    let mut anchor = py.detach(move || {
        probe_volume_anchor_at_offset(
            &path,
            archive_offset,
            &format_for_probe,
            password.as_deref(),
        )
    });
    if anchor.format != format || anchor.confidence != "strong" {
        return Ok(None);
    }
    anchor.pe_state = PeState::Confirmed;
    anchor.pe_image_end = Some(image_end);
    anchor.sfx = true;
    anchor.evidence.push("sfx:pe_overlay");
    Ok(Some(anchor))
}

fn proposal_owned_paths(proposal: &RelationProposal) -> HashSet<String> {
    proposal
        .volumes
        .iter()
        .map(|(path, _, _, _, _)| path.to_ascii_lowercase())
        .chain(
            proposal
                .companions
                .iter()
                .map(|path| path.to_ascii_lowercase()),
        )
        .collect()
}

fn validation_owned_paths(validation: &ProposalValidation) -> HashSet<String> {
    let mut paths = proposal_owned_paths(&validation.proposal);
    paths.extend(validation.unresolved.iter().map(|p| p.to_ascii_lowercase()));
    paths
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

fn ordinary_file_group_to_dict(
    py: Python<'_>,
    row: &RelationInput,
    relation_confirmed: bool,
) -> PyResult<Py<PyDict>> {
    let parsed = parse_relation_numbered_volume(&row.name);
    let archive_numbered_hypothesis = !relation_confirmed
        && parsed
            .as_ref()
            .is_some_and(|_| row.anchor.as_ref().is_some_and(anchor_has_split_identity));
    let relation_format = row
        .anchor
        .as_ref()
        .map(|anchor| anchor.format.as_str())
        .filter(|format| !format.is_empty())
        .or_else(|| parsed.as_ref().map(|value| value.family))
        .unwrap_or("");
    let split_family = if archive_numbered_hypothesis {
        parsed
            .as_ref()
            .map(|value| split_family_for_proposal(relation_format, value.style))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let split_index = parsed
        .as_ref()
        .filter(|_| archive_numbered_hypothesis)
        .map(|value| value.number)
        .unwrap_or(0);
    let relation = FileRelationNative {
        filename: row.name.clone(),
        logical_name: parsed
            .as_ref()
            .filter(|_| archive_numbered_hypothesis)
            .map(logical_name_from_parsed)
            // The logical name names the output directory; a (possibly
            // disguised) extension would collide with the archive itself.
            .unwrap_or_else(|| get_logical_name(&row.name, true)),
        split_role: archive_numbered_hypothesis.then(|| {
            if split_index == 1 {
                "first".to_string()
            } else {
                "member".to_string()
            }
        }),
        is_split_member: archive_numbered_hypothesis,
        has_generic_001_head: archive_numbered_hypothesis
            && split_index == 1
            && parsed
                .as_ref()
                .is_some_and(|value| value.family == "generic"),
        is_plain_numeric_member: archive_numbered_hypothesis
            && parsed
                .as_ref()
                .is_some_and(|value| value.style == "plain_numeric_suffix"),
        has_split_companions: false,
        is_split_exe_companion: false,
        is_disguised_split_exe_companion: false,
        is_split_related: archive_numbered_hypothesis,
        match_rar_disguised: false,
        match_rar_head: false,
        match_001_head: archive_numbered_hypothesis && split_index == 1,
        split_family,
        split_index,
    };
    let dict = PyDict::new(py);
    dict.set_item("head_path", &row.path)?;
    dict.set_item("head_name", &row.name)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, [&row.path])?)?;
    dict.set_item("is_split_candidate", false)?;
    dict.set_item("head_size", row.size)?;
    dict.set_item("logical_size", row.size)?;
    dict.set_item("split_volumes", PyList::empty(py))?;
    let head_metadata = row
        .anchor
        .as_ref()
        .filter(|anchor| anchor_has_relation_evidence(anchor))
        .map(|anchor| {
            if relation_confirmed {
                relation_confirmed_anchor_to_dict(py, anchor)
            } else {
                volume_anchor_to_dict(py, anchor)
            }
        })
        .transpose()?;
    dict.set_item("head_metadata", head_metadata)?;
    dict.set_item(
        "format_reject_mask",
        row.anchor
            .as_ref()
            .map(|anchor| anchor.format_reject_mask)
            .unwrap_or(0),
    )?;
    Ok(dict.unbind())
}

fn validation_relation_confirmed(validation: &ProposalValidation) -> bool {
    validation.unresolved.is_empty()
        && validation.proposal.volumes.iter().all(|part| part.1 > 0)
        && !validation.reason.is_some_and(|reason| {
            matches!(
                reason,
                RelationFailureReason::AmbiguousVolumeMapping
                    | RelationFailureReason::StructuralConflict
            )
        })
}

fn validated_proposal_to_dict(
    py: Python<'_>,
    validation: &ProposalValidation,
) -> PyResult<Py<PyDict>> {
    let proposal = &validation.proposal;
    let head = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
        .unwrap_or(&proposal.volumes[0]);
    let head_path = &head.0;
    let head_anchor = validation.anchors.get(&head_path.to_ascii_lowercase());
    let split_family = proposal_split_family(proposal, &validation.anchors);
    let relation = FileRelationNative {
        filename: basename(head_path).to_string(),
        logical_name: proposal.logical_name.clone(),
        split_role: Some("first".to_string()),
        is_split_member: true,
        has_generic_001_head: false,
        is_plain_numeric_member: false,
        has_split_companions: !proposal.companions.is_empty(),
        is_split_exe_companion: false,
        is_disguised_split_exe_companion: false,
        is_split_related: true,
        match_rar_disguised: proposal.format == "rar",
        match_rar_head: proposal.format == "rar",
        match_001_head: true,
        split_family: split_family.clone(),
        split_index: 1,
    };
    let volume_dicts = proposal_volume_dicts(py, proposal, &split_family, &validation.anchors)?;
    let all_parts: Vec<String> = proposal
        .volumes
        .iter()
        .map(|(path, _, _, _, _)| path.clone())
        .chain(validation.unresolved.iter().cloned())
        .collect();
    let carrier = proposal.companions.first().cloned().unwrap_or_default();
    let carrier_size = (!carrier.is_empty())
        .then(|| {
            validation
                .anchors
                .get(&carrier.to_ascii_lowercase())
                .map(|anchor| anchor.size)
        })
        .flatten();
    let dict = PyDict::new(py);
    dict.set_item("head_path", head_path)?;
    dict.set_item("head_name", basename(head_path))?;
    dict.set_item("logical_name", &proposal.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", true)?;
    dict.set_item("head_size", head_anchor.map(|anchor| anchor.size))?;
    dict.set_item(
        "logical_size",
        proposal_logical_size(proposal, &validation.anchors),
    )?;
    dict.set_item("split_volumes", PyList::new(py, &volume_dicts)?)?;
    let metadata = if let Some(anchor) = head_anchor {
        relation_confirmed_anchor_to_dict(py, anchor)?
    } else {
        let metadata = PyDict::new(py);
        metadata.set_item("format", &proposal.format)?;
        metadata.set_item("confidence", "strong")?;
        metadata.set_item("relation_confirmed", true)?;
        metadata.unbind()
    };
    dict.set_item("head_metadata", metadata)?;
    dict.set_item("companion_paths", &proposal.companions)?;
    dict.set_item("carrier_path", &carrier)?;
    dict.set_item("carrier_size", carrier_size)?;
    dict.set_item(
        "format_reject_mask",
        head_anchor
            .map(|anchor| anchor.format_reject_mask)
            .unwrap_or(0),
    )?;
    Ok(dict.unbind())
}

fn password_error_proposal_to_dict(
    py: Python<'_>,
    validation: &ProposalValidation,
) -> PyResult<Py<PyDict>> {
    let dict = validated_proposal_to_dict(py, validation)?;
    let bound = dict.bind(py);
    if let Some(metadata) = bound.get_item("head_metadata")? {
        let metadata = metadata.cast::<PyDict>()?;
        metadata.set_item(
            "relation_confirmed",
            validation_relation_confirmed(validation),
        )?;
        metadata.set_item("needs_password", true)?;
        metadata.set_item("proposal_paths", validation_owned_paths(validation))?;
        metadata.set_item("password_scope", &validation.proposal.logical_name)?;
        metadata.set_item(
            "relation_failure_reason",
            RelationFailureReason::NeedsPassword.as_str(),
        )?;
    }
    Ok(dict)
}

fn incomplete_proposal_to_dict(
    py: Python<'_>,
    validation: &ProposalValidation,
) -> PyResult<Py<PyDict>> {
    let dict = validated_proposal_to_dict(py, validation)?;
    {
        let bound = dict.bind(py);
        if let Some(metadata) = bound.get_item("head_metadata")? {
            if let Ok(metadata) = metadata.cast::<PyDict>() {
                metadata.set_item("volume_set_incomplete", true)?;
                metadata.set_item(
                    "relation_failure_reason",
                    validation.reason.map(RelationFailureReason::as_str),
                )?;
                metadata.set_item(
                    "relation_confirmed",
                    validation_relation_confirmed(validation),
                )?;
            }
        }
    }
    Ok(dict)
}

fn proposal_logical_size(
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
) -> Option<u64> {
    proposal
        .volumes
        .iter()
        .try_fold(0u64, |total, (path, _, _, _, _)| {
            anchors
                .get(&path.to_ascii_lowercase())
                .map(|anchor| total.saturating_add(anchor.size))
        })
}

fn proposal_volume_dicts(
    py: Python<'_>,
    proposal: &RelationProposal,
    split_family: &str,
    anchors: &HashMap<String, VolumeAnchor>,
) -> PyResult<Vec<Py<PyDict>>> {
    proposal
        .volumes
        .iter()
        .filter(|part| part.1 > 0)
        .map(|(path, number, _style, width, _decorated)| {
            let dict = PyDict::new(py);
            let role = if proposal.style == "zip_spanned"
                && anchors
                    .get(&path.to_ascii_lowercase())
                    .is_some_and(|anchor| anchor.anchor_roles.contains(&"terminal"))
            {
                "terminal"
            } else if *number == 1 {
                "first"
            } else {
                "member"
            };
            dict.set_item("path", path)?;
            dict.set_item("number", number)?;
            dict.set_item("role", role)?;
            // A proposal is emitted only after the format validator has
            // accepted its path union.  The filename interpretation selects
            // the candidate, but it is the structural validation that makes
            // this volume part of the relation contract.
            dict.set_item("source", "structure")?;
            dict.set_item("style", split_family)?;
            dict.set_item("prefix", &proposal.logical_name)?;
            dict.set_item("width", *width)?;
            if let Some(start) = anchors
                .get(&path.to_ascii_lowercase())
                .and_then(|anchor| anchor.structure_offset)
                .filter(|offset| *offset > 0)
            {
                dict.set_item("start", start)?;
            }
            Ok(dict.unbind())
        })
        .collect()
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
            .find(|(_, number, _, _, _)| *number == 1)
            .and_then(|(path, _, _, _, _)| anchors.get(&path.to_ascii_lowercase()))
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

fn anchor_has_relation_evidence(anchor: &VolumeAnchor) -> bool {
    !anchor.format.is_empty()
        || !anchor.confidence.is_empty()
        || anchor.multivolume
        || anchor.encrypted
        || anchor.needs_password
        || anchor.wrong_password
        || !anchor.anchor_roles.is_empty()
        || anchor.internal_volume_number.is_some()
        || anchor.structure_offset.is_some()
        || anchor.expected_logical_size.is_some()
        || anchor.continuation_from_previous
        || anchor.continuation_to_next
        || anchor.sfx
        || !anchor.evidence.is_empty()
        || !anchor.error.is_empty()
}

#[pyfunction]
#[pyo3(signature = (current_paths, candidate_paths, format_hint="", path_passwords=None))]
pub(crate) fn relations_resolve_volume_once(
    py: Python<'_>,
    current_paths: Vec<String>,
    candidate_paths: Vec<String>,
    format_hint: &str,
    path_passwords: Option<Vec<(String, String)>>,
) -> PyResult<Option<Py<PyDict>>> {
    if current_paths.is_empty() || candidate_paths.is_empty() {
        return Ok(None);
    }
    let Some(directory) = single_directory_scope(&current_paths) else {
        return Ok(None);
    };
    let mut visible_paths = current_paths.clone();
    visible_paths.extend(candidate_paths);
    let visible_paths = sorted_unique_paths(
        visible_paths
            .into_iter()
            .filter(|path| parent_directory_key(path) == directory)
            .collect(),
    );
    if visible_paths.is_empty() {
        return Ok(None);
    }
    let anchors = py.detach(|| probe_volume_anchor_paths_cheap(&visible_paths, None));
    let anchor_by_path: HashMap<String, VolumeAnchor> = anchors
        .into_iter()
        .map(|anchor| (anchor.path.to_ascii_lowercase(), anchor))
        .collect();
    let rows: Vec<_> = visible_paths
        .iter()
        .map(|path| RelationInput {
            path: path.clone(),
            path_key: path.to_ascii_lowercase(),
            name: basename(path).to_string(),
            size: anchor_by_path
                .get(&path.to_ascii_lowercase())
                .map(|anchor| anchor.size),
            relation_member_eligible: true,
            anchor: anchor_by_path.get(&path.to_ascii_lowercase()).cloned(),
        })
        .collect();
    let filtered_keys: HashSet<String> = current_paths
        .iter()
        .filter(|path| parent_directory_key(path) == directory)
        .map(|path| path.to_ascii_lowercase())
        .collect();
    let groups = build_candidate_groups_from_source(
        py,
        RelationSource::Physical(&rows),
        &filtered_keys,
        path_passwords.as_deref(),
        None,
    )?;
    let format_hint = normalize_retry_format(format_hint);
    for group in groups {
        let data = group.candidate_data();
        if !data.is_split || !data.relation_confirmed {
            continue;
        }
        if !format_hint.is_empty() && data.format_hint != format_hint {
            continue;
        }
        if current_paths.iter().all(|current| {
            data.parts()
                .chain(data.companions.iter().map(String::as_str))
                .any(|part| part.eq_ignore_ascii_case(current))
        }) {
            return group.to_dict(py).map(Some);
        }
    }
    Ok(None)
}

fn sorted_unique_paths(mut paths: Vec<String>) -> Vec<String> {
    paths.sort_by_key(|path| path.to_ascii_lowercase());
    paths.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    paths
}

fn parent_directory_key(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn single_directory_scope(paths: &[String]) -> Option<String> {
    let directory = parent_directory_key(paths.first()?);
    paths
        .iter()
        .all(|path| parent_directory_key(path) == directory)
        .then_some(directory)
}

fn normalize_retry_format(format_hint: &str) -> &str {
    match format_hint
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .as_str()
    {
        "7z" => "7z",
        "zip" | "zipx" => "zip",
        "rar" => "rar",
        _ => "",
    }
}

pub(crate) fn volume_anchor_to_dict(py: Python<'_>, anchor: &VolumeAnchor) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("path", &anchor.path)?;
    dict.set_item("size", anchor.size)?;
    dict.set_item("format", &anchor.format)?;
    dict.set_item("confidence", &anchor.confidence)?;
    dict.set_item("standalone", anchor.standalone)?;
    dict.set_item("multivolume", anchor.multivolume)?;
    dict.set_item("encrypted", anchor.encrypted)?;
    dict.set_item("needs_password", anchor.needs_password)?;
    dict.set_item("wrong_password", anchor.wrong_password)?;
    dict.set_item("anchor_roles", PyList::new(py, &anchor.anchor_roles)?)?;
    dict.set_item("internal_volume_number", anchor.internal_volume_number)?;
    dict.set_item("structure_offset", anchor.structure_offset)?;
    dict.set_item("expected_logical_size", anchor.expected_logical_size)?;
    dict.set_item(
        "continuation_from_previous",
        anchor.continuation_from_previous,
    )?;
    dict.set_item("continuation_to_next", anchor.continuation_to_next)?;
    dict.set_item("sfx", anchor.sfx)?;
    dict.set_item("pe_structure", anchor.pe_state == PeState::Confirmed)?;
    dict.set_item("evidence", PyList::new(py, &anchor.evidence)?)?;
    dict.set_item("error", &anchor.error)?;
    dict.set_item("bytes_read", anchor.bytes_read)?;
    Ok(dict.unbind())
}

fn relation_confirmed_anchor_to_dict(
    py: Python<'_>,
    anchor: &VolumeAnchor,
) -> PyResult<Py<PyDict>> {
    let dict = volume_anchor_to_dict(py, anchor)?;
    dict.bind(py).set_item("relation_confirmed", true)?;
    Ok(dict)
}

fn relation_to_dict(py: Python<'_>, relation: &FileRelationNative) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("filename", &relation.filename)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("split_role", &relation.split_role)?;
    dict.set_item("is_split_member", relation.is_split_member)?;
    dict.set_item("has_generic_001_head", relation.has_generic_001_head)?;
    dict.set_item("is_plain_numeric_member", relation.is_plain_numeric_member)?;
    dict.set_item("has_split_companions", relation.has_split_companions)?;
    dict.set_item("is_split_exe_companion", relation.is_split_exe_companion)?;
    dict.set_item(
        "is_disguised_split_exe_companion",
        relation.is_disguised_split_exe_companion,
    )?;
    dict.set_item("is_split_related", relation.is_split_related)?;
    dict.set_item("match_rar_disguised", relation.match_rar_disguised)?;
    dict.set_item("match_rar_head", relation.match_rar_head)?;
    dict.set_item("match_001_head", relation.match_001_head)?;
    dict.set_item("split_family", &relation.split_family)?;
    dict.set_item("split_index", relation.split_index)?;
    Ok(dict.unbind())
}

fn parsed_volume_to_dict(py: Python<'_>, parsed: &ParsedVolume) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("prefix", &parsed.prefix)?;
    dict.set_item("number", parsed.number)?;
    dict.set_item("style", parsed.style)?;
    dict.set_item("width", parsed.width)?;
    if parsed.decorated {
        dict.set_item("decorated", true)?;
    }
    Ok(dict.unbind())
}

fn detect_split_role(filename: &str) -> Option<&'static str> {
    if let Some(parsed) = parse_relation_numbered_volume(filename) {
        return Some(if parsed.number == 1 {
            "first"
        } else {
            "member"
        });
    }
    None
}

fn get_logical_name(filename: &str, is_archive: bool) -> String {
    if let Some(parsed) = parse_relation_numbered_volume(filename) {
        return logical_name_from_parsed(&parsed);
    }
    let zero_zip = zip_zero_numbered_suffix_re()
        .replace(filename, "")
        .to_string();
    if zero_zip != filename {
        return clean_logical_name(&zero_zip);
    }

    let second = archive_numbered_suffix_re()
        .replace(&zero_zip, "")
        .to_string();
    if second != zero_zip {
        return clean_logical_name(&second);
    }

    let third = plain_numeric_suffix_re().replace(&second, "").to_string();
    if third != second {
        return clean_logical_name(&third);
    }

    let (base, ext) = split_ext(filename);
    let ext = ext.to_ascii_lowercase();
    if is_archive
        || matches!(
            ext.as_str(),
            ".7z" | ".rar" | ".zip" | ".zipx" | ".gz" | ".bz2" | ".xz" | ".exe"
        )
    {
        return clean_logical_name(&base);
    }
    clean_logical_name(filename)
}

fn logical_name_from_parsed(parsed: &ParsedVolume) -> String {
    clean_logical_name(&parsed.prefix)
}

fn parse_relation_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let (directory, filename) = split_relation_path(path);
    let mut parsed = parse_volume_candidates(filename)
        .into_iter()
        .find(|candidate| {
            !candidate.decorated
                || (candidate.family == "rar"
                    && matches!(candidate.style, "rar_part" | "rar_sfx_part")
                    && parse_marker_numbered_re().is_match(filename))
        })?;
    if !directory.is_empty() {
        parsed.prefix = format!("{directory}{}", parsed.prefix);
    }
    Some(parsed)
}

/// Return the exact split-family identities a path can participate in.
///
/// This is the sole naming seam exposed to the filesystem scanner. The
/// scanner may retain a size-rejected row when one of these identities has a
/// normally accepted anchor; relations still decides whether the resulting
/// group is a valid archive.
#[pyfunction]
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
    let (base, ext) = split_ext(path);
    match ext.to_ascii_lowercase().as_str() {
        ".7z" => keys.push(split_size_family_key("archive:numeric", path)),
        ".zip" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("zip:zero-numbered", path));
            keys.push(split_size_family_key("zip:spanned", &base));
        }
        ".zipx" => keys.push(split_size_family_key("zip:spanned", &base)),
        ".rar" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("rar:oldstyle", &base));
        }
        _ => {}
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[pyfunction]
pub(crate) fn relations_apply_split_size_anchors(
    paths: Vec<String>,
    size_accepted: Vec<bool>,
) -> PyResult<Vec<bool>> {
    if paths.len() != size_accepted.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "split size anchor paths and decisions must have equal lengths",
        ));
    }
    if size_accepted.iter().all(|accepted| *accepted)
        || size_accepted.iter().all(|accepted| !*accepted)
    {
        return Ok(size_accepted);
    }
    let accepted_families: HashSet<String> = paths
        .iter()
        .zip(&size_accepted)
        .filter(|(_, accepted)| **accepted)
        .flat_map(|(path, _)| relations_size_filter_split_family_keys(path))
        .collect();
    Ok(paths
        .iter()
        .zip(size_accepted)
        .map(|(path, accepted)| {
            accepted
                || relations_size_filter_split_family_keys(path)
                    .iter()
                    .any(|key| accepted_families.contains(key))
        })
        .collect())
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
    format!(
        "{}\u{001f}{}",
        scheme,
        prefix.replace('\\', "/").to_ascii_lowercase()
    )
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
    let mut candidates = Vec::new();

    if let Some(parsed) = parse_zip_split_volume(filename) {
        push_unique_volume_candidate(&mut candidates, parsed);
    }
    if let Some(parsed) = parse_marker_numbered_volume(filename) {
        push_unique_volume_candidate(&mut candidates, parsed);
    }
    let _ = (|| -> Option<()> {
        if let Some(captures) = parse_zip_zero_numbered_re().captures(filename) {
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
                        width: captures.name("number")?.as_str().len(),
                        family: "zip",
                        decorated: captures
                            .name("tail")
                            .is_some_and(|tail| !tail.as_str().is_empty()),
                    },
                );
            }
        }
        if let Some(captures) = parse_archive_numbered_re().captures(filename) {
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
        if let Some(captures) = parse_rar_part_re().captures(filename) {
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
                        width: captures.name("number")?.as_str().len(),
                        family: "rar",
                        decorated: false,
                    },
                );
            }
        }
        if let Some(captures) = parse_old_rar_re().captures(filename) {
            let number = captures.name("number")?.as_str();
            if let Some(number) = number.parse::<u32>().ok() {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number: number.saturating_add(2),
                        style: "rar_oldstyle",
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
        if let Some(captures) = parse_plain_numbered_re().captures(filename) {
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

fn parse_zip_split_volume(filename: &str) -> Option<ParsedVolume> {
    let captures = parse_zip_split_re().captures(filename)?;
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
        width: raw_number.len(),
        family: "zip",
        decorated: !tail.is_empty(),
    })
}

fn push_unique_volume_candidate(candidates: &mut Vec<ParsedVolume>, candidate: ParsedVolume) {
    if candidates.iter().any(|existing| {
        existing.prefix.eq_ignore_ascii_case(&candidate.prefix)
            && existing.number == candidate.number
            && existing.style == candidate.style
            && existing.family == candidate.family
    }) {
        return;
    }
    candidates.push(candidate);
}

fn parse_marker_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let captures = parse_marker_numbered_re().captures(path)?;
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

fn first_dot_stem(name: &str) -> &str {
    name.split_once('.').map(|(stem, _)| stem).unwrap_or(name)
}

fn split_ext(filename: &str) -> (String, String) {
    let basename_start = filename
        .rfind(['\\', '/'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let basename = &filename[basename_start..];
    let Some(dot_in_base) = basename.rfind('.') else {
        return (filename.to_string(), String::new());
    };
    if dot_in_base == 0 {
        return (filename.to_string(), String::new());
    }
    let dot = basename_start + dot_in_base;
    (filename[..dot].to_string(), filename[dot..].to_string())
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
                "7z", "rar", "zip", "zipx", "tar", "gz", "gzip", "bz2", "bzip2", "xz",
                "zst", "zstd", "lz4", "tgz", "tbz", "tbz2", "txz", "exe", "enc",
            ]
            .iter()
            .any(|ext| suffix.eq_ignore_ascii_case(ext))
        {
            break;
        }
        name = &name[..basename_start + stem.len()];
    }
    name.to_string()
}

fn re(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .expect("relation regex should compile")
}

fn archive_numbered_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$"))
}

fn zip_zero_numbered_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.zip\.\d{4}(?:\.[^.]+)?$"))
}

fn plain_numeric_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.\d{3}$"))
}

fn parse_archive_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.(?P<format>7z|zip|rar)\.(?P<number>\d+)(?P<tail>(?:\.[^.]+)*)$")
    })
}

fn parse_zip_zero_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+\.zip)\.(?P<number>\d{4})(?P<tail>(?:\.[^.]+)*)$"))
}

fn parse_zip_split_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.zx?(?P<number>\d{2,})(?P<tail>(?:\..+)?)$"))
}

fn parse_rar_part_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.(?P<format>rar|exe)$"))
}

fn parse_old_rar_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.r(?P<number>\d{2,})(?P<tail>(?:\.[^.]+)*)$"))
}

fn parse_plain_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<number>\d+)$"))
}

fn parse_marker_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.(?:part|vol(?:ume)?)[-_ ]*(?P<number>\d+)(?:[-_ ][^.]*)?(?P<tail>(?:\.[^.]+)*)$")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expected = vec![split_size_family_key(
            "zip:spanned",
            r"C:\downloads\payload",
        )];
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
        assert_eq!(normalize_retry_format(".ZIPX"), "zip");
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
            status,
            reason: None,
            unresolved: Vec::new(),
            name_features: HashMap::new(),
            proposal: RelationProposal {
                format: "rar".to_string(),
                logical_name: "test".to_string(),
                style: "rar_part".to_string(),
                volumes: paths
                    .iter()
                    .enumerate()
                    .map(|(index, path)| {
                        (
                            (*path).to_string(),
                            index as u32 + 1,
                            "rar_part".to_string(),
                            2,
                            true,
                        )
                    })
                    .collect(),
                companions: Vec::new(),
            },
            anchors: HashMap::new(),
        }
    }

    #[test]
    fn encrypted_relations_require_readable_anchors_even_with_existing_failure() {
        for reason in [None, Some(RelationFailureReason::MissingVolume)] {
            let path = "archive.part1.rar";
            let mut validation = validation_with_owned_paths(ProposalStatus::Inconclusive, &[path]);
            validation.reason = reason;
            validation.anchors.insert(path.into(), VolumeAnchor {
                format: "rar".into(),
                needs_password: true,
                ..Default::default()
            });
            validate::validate(&mut validation);
            assert_eq!(validation.status, ProposalStatus::NeedsPassword);
            assert_eq!(
                validate::assignment_status("rar", false, [(1, validation.anchors.get(path))].into_iter()),
                ProposalStatus::NeedsPassword,
            );

            validation.reason = reason;
            validation.anchors.get_mut(path).unwrap().error = "input could not be read".into();
            validate::validate(&mut validation);
            assert_eq!(validation.status, ProposalStatus::Reject);
            assert_eq!(validation.reason, Some(RelationFailureReason::CorruptArchive));
            assert_eq!(
                validate::assignment_status("rar", false, [(1, validation.anchors.get(path))].into_iter()),
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
