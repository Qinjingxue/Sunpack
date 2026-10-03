use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_at_offset, probe_volume_anchor_paths_cheap, probe_volume_anchor_paths_deep,
    VolumeAnchor,
};
use crate::analysis_native::{
    probe_rar_path, probe_rar_terminal_with_password, probe_rar_volume_paths,
};
use crate::scan::directory::NativeDirectorySnapshot;
use crate::scan::executable_carrier::executable_sfx_stub_profile;
use crate::scan::pe_overlay::inspect_pe_overlay_structure;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

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
struct NameInterpretation {
    format: String,
    prefix: String,
    number: u32,
    style: String,
    width: usize,
    decorated: bool,
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
        ordinary.into_iter().chain(
            volumes
                .into_iter()
                .flat_map(|volumes| volumes.iter().map(|volume| volume.0.as_str())),
        )
    }

    pub(crate) fn parts_len(&self) -> usize {
        match self.group {
            NativeRelationGroup::Ordinary(..) => 1,
            NativeRelationGroup::Proposal(validation, _) => validation.proposal.volumes.len(),
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
                    && row.anchor.as_ref().is_some_and(|anchor| {
                        matches!(anchor.format.as_str(), "rar" | "7z" | "zip") || anchor.sfx
                    });
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
                    relation_confirmed: true,
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

#[derive(Debug, Default)]
struct DirectoryNameIndex {
    entries_by_path: HashMap<String, DirectoryNameEntry>,
    rows_by_stem: HashMap<String, Vec<usize>>,
    rows_by_family: HashMap<String, HashMap<String, Vec<usize>>>,
}

#[derive(Debug, Default)]
struct DirectoryNameEntry {
    parsed: Vec<ParsedVolume>,
    interpretations: HashMap<String, Vec<NameInterpretation>>,
}

impl DirectoryNameIndex {
    fn build(rows: &[RelationInput]) -> Self {
        let entries_by_path = rows
            .iter()
            .map(|row| {
                let mut parsed = parse_volume_candidates(&row.name);
                // Loose partN spellings are only hypotheses for a structurally
                // identified RAR volume (or password-blocked RAR headers),
                // never for ordinary filename APIs. Proposal validation still
                // decides whether these hypotheses form an actual volume set.
                if row.anchor.as_ref().is_some_and(|anchor| {
                    anchor.format == "rar"
                        && (anchor.multivolume
                            || anchor.needs_password
                            || anchor.continuation_from_previous
                            || anchor.continuation_to_next)
                }) {
                    if let Some(candidate) = parse_loose_rar_part_volume(&row.name) {
                        push_unique_volume_candidate(&mut parsed, candidate);
                    }
                }
                let interpretations = ["", "rar", "7z", "zip"]
                    .into_iter()
                    .map(|target_format| {
                        (
                            target_format.to_string(),
                            name_interpretations_from_candidates(
                                &row.name,
                                &parsed,
                                target_format,
                                row.anchor.as_ref(),
                            ),
                        )
                    })
                    .collect();
                (
                    row.path_key.clone(),
                    DirectoryNameEntry {
                        parsed,
                        interpretations,
                    },
                )
            })
            .collect();
        let mut rows_by_stem: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, row) in rows.iter().enumerate() {
            rows_by_stem
                .entry(first_dot_stem(&row.name).to_ascii_lowercase())
                .or_default()
                .push(index);
        }
        Self {
            entries_by_path,
            rows_by_stem,
            rows_by_family: HashMap::new(),
        }
    }

    fn rows_for_prefix<'a>(
        &'a self,
        rows: &'a [RelationInput],
        prefix: &str,
    ) -> impl Iterator<Item = &'a RelationInput> {
        self.rows_by_stem
            .get(&first_dot_stem(prefix).to_ascii_lowercase())
            .into_iter()
            .flatten()
            .map(|index| &rows[*index])
    }

    fn index_families(&mut self, rows: &[RelationInput]) {
        for (index, row) in rows.iter().enumerate() {
            let entry = &self.entries_by_path[&row.path_key];
            for (format, values) in &entry.interpretations {
                for value in values {
                    let members = self
                        .rows_by_family
                        .entry(format.clone())
                        .or_default()
                        .entry(value.prefix.clone())
                        .or_default();
                    if members.last() != Some(&index) {
                        members.push(index);
                    }
                }
            }
            let name = row.name.to_ascii_lowercase();
            if let Some((prefix, tail)) = name.split_once(".zip") {
                if tail.is_empty() || tail.starts_with('.') {
                    let members = self
                        .rows_by_family
                        .entry("zip".to_string())
                        .or_default()
                        .entry(prefix.to_string())
                        .or_default();
                    if members.last() != Some(&index) {
                        members.push(index);
                    }
                }
            }
            if entry.parsed.is_empty() && row.anchor.as_ref().is_some_and(is_possible_sfx_launcher)
            {
                let members = self
                    .rows_by_family
                    .entry(String::new())
                    .or_default()
                    .entry(first_dot_stem(&name).to_string())
                    .or_default();
                if members.last() != Some(&index) {
                    members.push(index);
                }
            }
        }
    }

    fn rows_for_family<'a>(
        &'a self,
        rows: &'a [RelationInput],
        family: &'a NameInterpretation,
    ) -> impl Iterator<Item = &'a RelationInput> {
        let members = self
            .rows_by_family
            .get(&family.format)
            .and_then(|groups| groups.get(&family.prefix));
        let companions = self
            .rows_by_family
            .get("")
            .and_then(|groups| groups.get(first_dot_stem(&family.prefix)));
        members
            .into_iter()
            .flatten()
            .chain(companions.into_iter().flatten().filter(move |index| {
                !family.format.is_empty()
                    && !self
                        .interpretations(&rows[**index], &family.format)
                        .iter()
                        .any(|value| value.prefix == family.prefix)
            }))
            .map(|index| &rows[*index])
    }

    /// Widen names only after a concrete archive seed exists. Competing
    /// formats or heads keep the existing scheme/prefix interpretations;
    /// opaque members must never be assigned by trying path combinations.
    fn match_seed_buckets(&mut self, rows: &[RelationInput], strengths: &[Option<&str>]) {
        for (stem, indexes) in &self.rows_by_stem {
            if stem.is_empty() {
                continue;
            }
            let mut formats = HashSet::new();
            let mut heads = 0usize;
            let mut zip_spanned = false;
            for index in indexes {
                let row = &rows[*index];
                let Some(anchor) = row.anchor.as_ref().filter(|_| strengths[*index].is_some())
                else {
                    continue;
                };
                if !matches!(anchor.format.as_str(), "7z" | "zip" | "rar") {
                    continue;
                }
                formats.insert(anchor.format.as_str());
                heads += usize::from(
                    anchor.anchor_roles.contains(&"first")
                        || anchor.internal_volume_number == Some(1)
                        || self.entries_by_path[&row.path_key]
                            .parsed
                            .iter()
                            .any(|part| part.number == 1),
                );
                zip_spanned |= anchor.format == "zip"
                    && (anchor.evidence.contains(&"zip:split_marker")
                        || anchor.evidence.contains(&"zip:eocd_split_terminal"));
            }
            if formats.len() != 1 || heads > 1 {
                continue;
            }
            let format = *formats.iter().next().expect("one concrete format");
            let default_style = match format {
                "rar" => "rar_part",
                "zip" if zip_spanned => "zip_spanned",
                _ => "numeric_suffix",
            };
            let mut terminal = None;
            let mut terminal_count = 0usize;
            let mut highest = 0u32;
            let mut common_prefix = None;
            let mut mixed_prefixes = false;
            for index in indexes {
                if let Some(part) = self.entries_by_path[&rows[*index].path_key]
                    .parsed
                    .iter()
                    .find(|part| part.family == format || part.family == "generic")
                {
                    let prefix = logical_name_from_parsed(part).to_ascii_lowercase();
                    mixed_prefixes |= common_prefix
                        .as_ref()
                        .is_some_and(|previous| previous != &prefix);
                    common_prefix = Some(prefix);
                }
            }
            // Keep the existing canonical name when recognized members agree;
            // varying/opaque prefixes use only the first-dot stem.
            let prefix = common_prefix
                .filter(|_| !mixed_prefixes)
                .unwrap_or_else(|| stem.clone());
            for index in indexes {
                let row = &rows[*index];
                let entry = self
                    .entries_by_path
                    .get_mut(&row.path_key)
                    .expect("indexed row");
                let values = entry
                    .interpretations
                    .get_mut(format)
                    .expect("indexed format");
                values.clear();
                if !row.relation_member_eligible
                    || row.anchor.as_ref().is_some_and(|anchor| {
                        (!anchor.format.is_empty() && anchor.format != format)
                            || (anchor.standalone && !anchor.sfx)
                    })
                {
                    continue;
                }
                let parsed = entry
                    .parsed
                    .iter()
                    .find(|part| part.family == format || part.family == "generic");
                if zip_spanned && parsed.is_none() && zip_terminal_name_matches(&row.name, &prefix)
                {
                    terminal = Some(*index);
                    terminal_count += 1;
                    continue;
                }
                let number = row
                    .anchor
                    .as_ref()
                    .filter(|a| format == "zip" && a.anchor_roles.contains(&"terminal"))
                    .and_then(|a| a.internal_volume_number)
                    .or_else(|| parsed.map(|part| part.number))
                    .or_else(|| {
                        suffix_volume_number(
                            &row.name,
                            row.anchor.as_ref().and_then(|a| a.internal_volume_number),
                        )
                    });
                let Some(number) = number.filter(|number| *number > 0) else {
                    if format == "zip"
                        && row
                            .anchor
                            .as_ref()
                            .is_some_and(|a| a.anchor_roles.contains(&"terminal"))
                    {
                        terminal = Some(*index);
                        terminal_count += 1;
                    }
                    continue;
                };
                highest = highest.max(number);
                values.push(NameInterpretation {
                    format: format.to_string(),
                    prefix: prefix.clone(),
                    number,
                    style: if zip_spanned {
                        "zip_spanned"
                    } else if format == "rar"
                        && number == 1
                        && row.anchor.as_ref().is_some_and(|a| a.sfx)
                    {
                        "rar_sfx_part"
                    } else {
                        parsed.map(|part| part.style).unwrap_or(default_style)
                    }
                    .to_string(),
                    width: parsed.map(|part| part.width).unwrap_or(3),
                    decorated: true,
                });
            }
            if let Some(index) = terminal.filter(|_| terminal_count == 1) {
                if let Some(number) = highest.checked_add(1) {
                    self.entries_by_path
                        .get_mut(&rows[index].path_key)
                        .expect("indexed row")
                        .interpretations
                        .get_mut(format)
                        .expect("indexed format")
                        .push(NameInterpretation {
                            format: format.to_string(),
                            prefix: prefix.clone(),
                            number,
                            style: default_style.to_string(),
                            width: 3,
                            decorated: true,
                        });
                }
            }
        }
    }

    fn candidates<'a>(&'a self, row: &RelationInput) -> &'a [ParsedVolume] {
        self.entries_by_path
            .get(&row.path_key)
            .map(|entry| entry.parsed.as_slice())
            .unwrap_or(&[])
    }

    fn interpretations(&self, row: &RelationInput, target_format: &str) -> &[NameInterpretation] {
        self.entries_by_path
            .get(&row.path_key)
            .and_then(|entry| entry.interpretations.get(target_format))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
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
    let filtered_keys: HashSet<String> = filtered_snapshot
        .relation_file_records()
        .map(|(path, _, _, _)| path.to_ascii_lowercase())
        .collect();
    if filtered_keys.is_empty() {
        return Ok(Vec::new());
    }
    let raw_rows: Vec<RelationInput> = raw_snapshot
        .relation_file_records()
        .map(|(path, size, relation_member_eligible, anchor)| {
            let path = path.to_string();
            let path_key = path.to_ascii_lowercase();
            let name = Path::new(&path)
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default();
            RelationInput {
                path,
                path_key,
                name,
                size,
                relation_member_eligible,
                anchor: anchor.cloned(),
            }
        })
        .collect();
    build_candidate_groups_from_physical(py, raw_rows, &filtered_keys, path_passwords)
}

fn build_candidate_groups_from_physical(
    py: Python<'_>,
    rows: Vec<RelationInput>,
    filtered_keys: &HashSet<String>,
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<Vec<NativeRelationGroup>> {
    let mut by_directory: HashMap<String, Vec<RelationInput>> = HashMap::new();
    let mut directory_order = Vec::new();
    for row in rows {
        let directory = parent_directory_key(&row.path);
        if !by_directory.contains_key(&directory) {
            directory_order.push(directory.clone());
        }
        by_directory.entry(directory).or_default().push(row);
    }

    let mut output = Vec::new();
    for directory in directory_order {
        let Some(mut directory_rows) = by_directory.remove(&directory) else {
            continue;
        };
        if path_passwords.is_some() {
            let encrypted_rar_paths: Vec<String> = directory_rows
                .iter()
                .filter(|row| {
                    row.anchor.as_ref().is_some_and(|anchor| {
                        anchor.format == "rar"
                            && anchor.needs_password
                            && anchor.structure_offset.unwrap_or(0) == 0
                    })
                })
                .map(|row| row.path.clone())
                .collect();
            if !encrypted_rar_paths.is_empty() {
                let refreshed = py.detach(|| {
                    probe_volume_anchor_paths_cheap(&encrypted_rar_paths, path_passwords)
                });
                let refreshed: HashMap<String, VolumeAnchor> = refreshed
                    .into_iter()
                    .map(|anchor| (anchor.path.to_ascii_lowercase(), anchor))
                    .collect();
                for row in &mut directory_rows {
                    if let Some(anchor) = refreshed.get(&row.path.to_ascii_lowercase()) {
                        row.anchor = Some(anchor.clone());
                    }
                }
            }
        }

        let sfx_indexes: Vec<usize> = directory_rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                let eligible = filtered_keys.contains(&row.path.to_ascii_lowercase());
                let sfx_seed = row.anchor.as_ref().is_some_and(|anchor| {
                    anchor.sfx
                        && !anchor.pe_structure
                        && anchor.evidence.iter().any(|item| *item == "sfx:pe_header")
                });
                (eligible && sfx_seed).then_some(index)
            })
            .collect();
        for index in sfx_indexes {
            if let Some(anchor) =
                promote_sfx_archive_anchor(py, &directory_rows[index], path_passwords)?
            {
                directory_rows[index].anchor = Some(anchor);
            }
        }

        let zip_candidates: Vec<String> = directory_rows
            .iter()
            .filter(|row| filtered_keys.contains(&row.path.to_ascii_lowercase()))
            .filter(|row| should_upgrade_zip_anchor(row))
            .map(|row| row.path.clone())
            .collect();
        if !zip_candidates.is_empty() {
            let upgraded = py.detach(|| {
                probe_volume_anchor_paths_deep(&zip_candidates, 512, 22 + 65_535, path_passwords)
            });
            let upgraded: HashMap<String, VolumeAnchor> = upgraded
                .into_iter()
                .filter(|anchor| anchor.format == "zip" && anchor.confidence == "strong")
                .map(|anchor| (anchor.path.to_ascii_lowercase(), anchor))
                .collect();
            for row in &mut directory_rows {
                if let Some(anchor) = upgraded.get(&row.path.to_ascii_lowercase()) {
                    row.anchor = Some(anchor.clone());
                }
            }
        }

        let mut name_index = DirectoryNameIndex::build(&directory_rows);
        let sfx_split_heads: Vec<String> = directory_rows
            .iter()
            .filter(|row| is_weak_sfx_split_head(row, &name_index))
            .map(|row| row.path.clone())
            .collect();
        if !sfx_split_heads.is_empty() {
            let deep_anchors = py.detach(|| {
                probe_volume_anchor_paths_deep(&sfx_split_heads, 1024 * 1024, 0, path_passwords)
            });
            let upgraded: HashMap<String, VolumeAnchor> = deep_anchors
                .into_iter()
                .filter_map(|anchor| {
                    let row = directory_rows
                        .iter()
                        .find(|row| row.path.eq_ignore_ascii_case(&anchor.path))?;
                    is_strong_multivolume_first_seed(row, &name_index, &anchor)
                        .then_some((anchor.path.to_ascii_lowercase(), anchor))
                })
                .collect();
            for row in &mut directory_rows {
                if let Some(anchor) = upgraded.get(&row.path.to_ascii_lowercase()) {
                    row.anchor = Some(anchor.clone());
                }
            }
            // The name index stores the anchor-sensitive interpretations, so
            // rebuild it after an MZ seed has been promoted by structure.
            name_index = DirectoryNameIndex::build(&directory_rows);
        }
        let mut strong_suppressed_paths = HashSet::new();
        let mut proposals = Vec::new();
        let mut proposal_keys = HashSet::new();

        let seed_strengths: Vec<Option<&'static str>> = directory_rows
            .iter()
            .map(|row| seed_strength_for_row(row, &directory_rows, &name_index))
            .collect();
        name_index.match_seed_buckets(&directory_rows, &seed_strengths);
        name_index.index_families(&directory_rows);
        let triggered_stems: HashSet<String> = directory_rows
            .iter()
            .filter(|row| filtered_keys.contains(&row.path.to_ascii_lowercase()))
            .map(|row| first_dot_stem(&row.name).to_ascii_lowercase())
            .collect();
        let mut seeded_families = HashSet::new();
        for (seed_index, strength) in seed_strengths
            .iter()
            .enumerate()
            .filter_map(|(index, strength)| (*strength).map(|strength| (index, strength)))
        {
            let seed = &directory_rows[seed_index];
            if !triggered_stems.contains(&first_dot_stem(&seed.name).to_ascii_lowercase()) {
                continue;
            }
            let Some(anchor) = seed.anchor.as_ref() else {
                continue;
            };
            for interpretation in name_index.interpretations(seed, &anchor.format) {
                if !seeded_families.insert((
                    interpretation.format.clone(),
                    interpretation.prefix.clone(),
                    interpretation.style.clone(),
                )) {
                    continue;
                }
                for proposal in
                    name_proposals_for_seed(&name_index, &directory_rows, seed, &interpretation)
                {
                    let key = proposal_key(&proposal);
                    if !proposal_keys.insert(key) {
                        continue;
                    }
                    // Only a concrete multi-file proposal suppresses standalone
                    // fallback. Compute ownership once per family, not per seed.
                    if strength == "strong" {
                        strong_suppressed_paths.extend(proposal_owned_paths(&proposal));
                    }
                    proposals.push(proposal);
                }
            }
        }

        // Resolve ownership before any deep IO. A weak/password-blocked
        // proposal must not lose shared opaque members to whichever format
        // happens to validate first. Equal proposals were deduplicated above.
        let ambiguous = {
            let paths: Vec<HashSet<&str>> = proposals
                .iter()
                .map(|proposal| {
                    proposal
                        .volumes
                        .iter()
                        .map(|part| part.0.as_str())
                        .collect()
                })
                .collect();
            conflicting_indexes_among(&paths, 0..proposals.len())
        };
        let mut validations = Vec::new();
        for (index, proposal) in proposals.into_iter().enumerate() {
            // Selection follows bucket-wide ownership, so an unselected
            // competing seed still protects its possible members from mixing.
            let selected = proposal
                .volumes
                .iter()
                .any(|part| filtered_keys.contains(&part.0.to_ascii_lowercase()))
                || proposal
                    .companions
                    .iter()
                    .any(|path| filtered_keys.contains(&path.to_ascii_lowercase()));
            if ambiguous.contains(&index) || !selected {
                for (path, _, _, _, _) in &proposal.volumes {
                    strong_suppressed_paths.remove(&path.to_ascii_lowercase());
                }
                validations.push(ProposalValidation {
                    status: ProposalStatus::Reject,
                    proposal,
                    anchors: HashMap::new(),
                });
                continue;
            }
            validations.push(validate_relation_proposal(
                py,
                proposal,
                &directory_rows,
                path_passwords,
            )?);
        }

        let validation_owned_paths: Vec<HashSet<String>> = validations
            .iter()
            .map(|validation| proposal_owned_paths(&validation.proposal))
            .collect();

        // A password retry may structurally prove every observed member as a
        // volume while still being inconclusive because the head or terminal
        // volume is absent.  Keep that incomplete proposal out of ordinary
        // fallback.  Standalone encrypted files do not satisfy the all-volume
        // proof and therefore remain ordinary after their proposal is rejected.
        if path_passwords.is_some() {
            for (index, validation) in validations.iter().enumerate() {
                if validation.status != ProposalStatus::Inconclusive
                    || !validation
                        .proposal
                        .volumes
                        .iter()
                        .all(|(path, _, _, _, _)| {
                            validation
                                .anchors
                                .get(&path.to_ascii_lowercase())
                                .is_some_and(|anchor| {
                                    anchor.format == "rar"
                                        && anchor.confidence == "strong"
                                        && (anchor.multivolume
                                            || anchor.continuation_from_previous
                                            || anchor.continuation_to_next)
                                })
                        })
                {
                    continue;
                }
                strong_suppressed_paths.extend(validation_owned_paths[index].iter().cloned());
            }
        }

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
            output.push(NativeRelationGroup::Proposal(
                validation.clone(),
                GroupKind::Valid,
            ));
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
            output.push(NativeRelationGroup::Proposal(
                validation.clone(),
                GroupKind::Password,
            ));
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
                    && is_incomplete_volume_set(validation)
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
            output.push(NativeRelationGroup::Proposal(
                validations[index].clone(),
                GroupKind::Incomplete,
            ));
        }

        for row in directory_rows.iter().filter(|row| {
            let key = row.path.to_ascii_lowercase();
            // Suppression only prevents a numbered member from being treated
            // as a complete archive on its own.  A member that no emitted
            // relation owns is still reported through the ordinary
            // (unconfirmed, therefore blocked) fallback, never dropped.
            let suppressed = strong_suppressed_paths.contains(&key)
                && row.anchor.as_ref().is_some_and(anchor_is_relation_archive);
            filtered_keys.contains(&key)
                && !claimed_paths.contains(&key)
                && !password_paths.contains(&key)
                && !suppressed
        }) {
            let confirmed = row.anchor.as_ref().is_some_and(anchor_is_relation_archive);
            output.push(NativeRelationGroup::Ordinary(row.clone(), confirmed));
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
    if anchor.format.is_empty() && anchor.sfx {
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
    if anchor.format == "zip"
        && anchor
            .evidence
            .iter()
            .any(|item| *item == "zip:local_header")
    {
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

fn seed_strength_for_row(
    row: &RelationInput,
    rows: &[RelationInput],
    name_index: &DirectoryNameIndex,
) -> Option<&'static str> {
    let anchor = row.anchor.as_ref()?;

    // A physically byte-split RAR SFX can still carry a single-archive RAR
    // header in its first chunk.  That header's standalone bit describes the
    // logical RAR stream, not whether this physical file contains the whole
    // stream.  Allow only a structurally confirmed, numbered SFX head with
    // matching numbered siblings to reach the existing proposal validator.
    // No extra probe is performed here; this uses only facts already present
    // in the directory snapshot and anchor.
    let raw_sfx_split_seed = anchor.format == "rar"
        && anchor.confidence == "strong"
        && anchor.sfx
        && anchor.pe_structure
        && anchor.standalone
        && anchor.structure_offset.is_some_and(|offset| offset > 0)
        && name_index.candidates(row).iter().any(|candidate| {
            candidate.number == 1 && candidate.family == "rar" && candidate.style == "rar_sfx_part"
        })
        && strong_seed_related_paths(row, rows, name_index, anchor).len() >= 2;
    if raw_sfx_split_seed {
        return Some("strong");
    }

    let strength = cheap_seed_strength(anchor)?;
    if strength == "weak"
        && anchor.format == "rar"
        && anchor.sfx
        && anchor.pe_structure
        && anchor.encrypted
        && anchor
            .anchor_roles
            .iter()
            .any(|role| *role == "encrypted_volume")
        && anchor.structure_offset.is_some_and(|offset| offset > 0)
        && name_index.candidates(row).iter().any(|candidate| {
            candidate.number == 1
                && candidate.family == "rar"
                && Path::new(&row.name)
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        })
        && strong_seed_related_paths(row, rows, name_index, anchor).len() >= 2
    {
        return Some("strong");
    }
    Some(strength)
}

fn should_upgrade_zip_anchor(row: &RelationInput) -> bool {
    row.anchor.as_ref().is_some_and(|anchor| {
        anchor.format == "zip"
            && anchor.confidence == "weak"
            && anchor.structure_offset.unwrap_or(0) == 0
    })
}

fn anchor_is_relation_archive(anchor: &VolumeAnchor) -> bool {
    let offset = anchor.structure_offset.unwrap_or(0);
    let proven_sfx = offset > 0 && anchor.sfx && anchor.pe_structure;
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
    let overlay = inspect_pe_overlay_structure(
        py,
        &row.path,
        row.size.and_then(|size| i64::try_from(size).ok()),
        None,
    )?;
    let overlay = overlay.bind(py);
    let is_pe = overlay
        .get_item("is_pe")?
        .and_then(|value| value.extract::<bool>().ok())
        .unwrap_or(false);
    let archive_like = overlay
        .get_item("archive_like")?
        .and_then(|value| value.extract::<bool>().ok())
        .unwrap_or(false);
    if !is_pe || !archive_like {
        return Ok(None);
    }

    let format = overlay
        .get_item("format")?
        .and_then(|value| value.extract::<String>().ok())
        .unwrap_or_default();
    if !matches!(format.as_str(), "rar" | "7z" | "zip") {
        return Ok(None);
    }
    let image_end = overlay
        .get_item("overlay_offset")?
        .and_then(|value| value.extract::<u64>().ok())
        .unwrap_or(0);
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
    let sfx_matches_format = match sfx_profile.as_str() {
        "seven_zip_sfx" => matches!(format.as_str(), "7z" | "zip"),
        "winrar_sfx" => matches!(format.as_str(), "rar" | "zip"),
        _ => false,
    };
    if !sfx_matches_format {
        return Ok(None);
    }

    let archive_offset = overlay
        .get_item("archive_offset")?
        .and_then(|value| value.extract::<u64>().ok())
        .unwrap_or(0);
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
    let format_for_probe = format.clone();
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
    anchor.pe_structure = true;
    Ok(Some(anchor))
}

fn is_weak_sfx_split_head(row: &RelationInput, name_index: &DirectoryNameIndex) -> bool {
    let Some(anchor) = row.anchor.as_ref() else {
        return false;
    };
    if !(anchor.format.is_empty()
        && anchor.sfx
        && anchor.evidence.iter().any(|item| *item == "sfx:pe_header"))
    {
        return false;
    }
    Path::new(&row.name)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        && name_index.candidates(row).iter().any(|candidate| {
            candidate.number == 1 && !logical_name_from_parsed(candidate).is_empty()
        })
}

fn is_strong_multivolume_first_seed(
    row: &RelationInput,
    name_index: &DirectoryNameIndex,
    anchor: &VolumeAnchor,
) -> bool {
    let numbered_first = name_index
        .candidates(row)
        .iter()
        .any(|candidate| candidate.number == 1);
    (matches!(anchor.format.as_str(), "rar" | "7z" | "zip")
        && anchor.confidence == "strong"
        && anchor.multivolume
        && (anchor.anchor_roles.iter().any(|role| *role == "first")
            || anchor.internal_volume_number == Some(1)))
        || (anchor.format == "rar"
            && anchor.confidence == "strong"
            && anchor.sfx
            && anchor.encrypted
            && anchor.anchor_roles.contains(&"encrypted_volume")
            && numbered_first)
}

fn strong_seed_related_paths(
    row: &RelationInput,
    rows: &[RelationInput],
    name_index: &DirectoryNameIndex,
    anchor: &VolumeAnchor,
) -> Vec<String> {
    let parsed = name_index
        .candidates(row)
        .iter()
        .filter(|candidate| candidate.number > 0)
        .find(|candidate| {
            candidate.family == anchor.format
                || candidate.family == "generic"
                || (anchor.sfx && candidate.family == "rar")
        });
    let logical_name = parsed
        .map(logical_name_from_parsed)
        .filter(|value| !value.is_empty())
        // The seed is structurally proven, so its extension is not part of the
        // family name even when disguised (`set4.jpg` heads `set4.r00`).
        .unwrap_or_else(|| get_logical_name(&row.name, true));
    if logical_name.is_empty() {
        return Vec::new();
    }
    name_index
        .rows_for_prefix(rows, &logical_name)
        .filter(|candidate_row| candidate_row.relation_member_eligible)
        .filter(|candidate_row| {
            name_index
                .candidates(candidate_row)
                .iter()
                .any(|candidate| {
                    candidate.number > 0
                        && logical_name_from_parsed(candidate).eq_ignore_ascii_case(&logical_name)
                        && (candidate.family == anchor.format
                            || candidate.family == "generic"
                            || (anchor.sfx && candidate.family == "rar"))
                })
        })
        .map(|candidate_row| candidate_row.path.clone())
        .collect()
}

fn name_interpretations_from_candidates(
    name: &str,
    parsed_candidates: &[ParsedVolume],
    target_format: &str,
    anchor: Option<&VolumeAnchor>,
) -> Vec<NameInterpretation> {
    let mut values = Vec::new();
    if !target_format.is_empty()
        && anchor.is_some_and(|value| !value.format.is_empty() && value.format != target_format)
    {
        return values;
    }
    for parsed in parsed_candidates {
        // A split SFX data head commonly keeps the launcher token in the
        // filename (for example `bundle.exe.part1.*`) even when the payload
        // format is 7z or ZIP.  The filename parser quite correctly treats
        // `.exe` as the RAR/SFX spelling when it has no structural context.
        // Once the cheap seed has proved that this exact file is a 7z/ZIP
        // SFX head, reinterpret only that first slot for the seeded format.
        // This is still a hypothesis; the format validator must prove the
        // complete path union before the relation is emitted.
        let sfx_data_head = target_format != "rar"
            && parsed.number == 1
            && parsed.family == "rar"
            && anchor.is_some_and(|value| value.sfx)
            && name.to_ascii_lowercase().contains(".exe.");
        if target_format.is_empty() && !anchor.is_some_and(|value| value.sfx) {
            continue;
        }
        if parsed.family != target_format && parsed.family != "generic" && !sfx_data_head {
            continue;
        }
        let prefix = logical_name_from_parsed(&parsed).to_ascii_lowercase();
        if prefix.is_empty() || parsed.number == 0 {
            continue;
        }
        values.push(NameInterpretation {
            format: target_format.to_string(),
            prefix,
            number: parsed.number,
            style: if sfx_data_head {
                "part_numbered".to_string()
            } else {
                parsed.style.to_string()
            },
            width: parsed.width,
            decorated: parsed.decorated,
        });
    }

    if values.is_empty() {
        let Some(anchor) = anchor.filter(|value| {
            value.format == target_format || (value.format.is_empty() && value.sfx)
        }) else {
            return values;
        };
        let sfx_data_bearing = !anchor.sfx
            || anchor.multivolume
            || anchor.continuation_to_next
            || anchor.continuation_from_previous
            || anchor
                .expected_logical_size
                .is_some_and(|expected| expected > anchor.size);
        let structural_head = if target_format.is_empty() && anchor.format.is_empty() {
            anchor.sfx
        } else if anchor.sfx {
            anchor.anchor_roles.contains(&"first") && sfx_data_bearing
        } else {
            anchor.anchor_roles.contains(&"first")
        };
        let structural_terminal = anchor.anchor_roles.contains(&"terminal");
        if structural_head || structural_terminal {
            let number = anchor
                .internal_volume_number
                .or_else(|| structural_head.then_some(1))
                .unwrap_or(0);
            // Structure proves an archive head/terminal here; a disguised
            // extension must not become part of the family prefix.
            let prefix = get_logical_name(name, true).to_ascii_lowercase();
            if number > 0 && !prefix.is_empty() {
                values.push(NameInterpretation {
                    format: target_format.to_string(),
                    prefix,
                    number,
                    style: "structural_name".to_string(),
                    width: 3,
                    decorated: false,
                });
            }
        }
    }
    values.sort_by(|left, right| {
        left.number
            .cmp(&right.number)
            .then_with(|| left.style.cmp(&right.style))
            .then_with(|| left.prefix.cmp(&right.prefix))
    });
    values.dedup_by(|left, right| {
        left.format == right.format
            && left.prefix == right.prefix
            && left.number == right.number
            && left.style == right.style
    });
    values
}

fn name_proposals_for_seed(
    name_index: &DirectoryNameIndex,
    rows: &[RelationInput],
    seed: &RelationInput,
    seed_interpretation: &NameInterpretation,
) -> Vec<RelationProposal> {
    if !seed_interpretation.format.is_empty() {
        return make_name_proposal(name_index, rows, seed_interpretation)
            .into_iter()
            .collect();
    }

    // An MZ seed has no format fact at the 512-byte cheap boundary.  Use only
    // the same-family filename tokens on other physical rows to nominate a
    // bounded set of concrete formats.  The resulting proposal still goes
    // through exactly one format-specific deep validator.
    let mut formats = HashSet::new();
    for row in name_index
        .rows_for_prefix(rows, &seed_interpretation.prefix)
        .filter(|row| row.relation_member_eligible && !row.path.eq_ignore_ascii_case(&seed.path))
    {
        for parsed in name_index.candidates(row) {
            if !matches!(parsed.family, "rar" | "7z" | "zip")
                || !logical_name_from_parsed(&parsed)
                    .eq_ignore_ascii_case(&seed_interpretation.prefix)
            {
                continue;
            }
            formats.insert(parsed.family);
        }
    }

    // An unknown MZ seed must converge to one filename-declared format before
    // any deep validator is authorized.  A mixed 7z/ZIP/RAR family remains
    // ambiguous and is intentionally left to the ordinary embedded pipeline.
    if formats.len() != 1 {
        return Vec::new();
    }
    let format = formats.into_iter().next().unwrap();
    let mut concrete = seed_interpretation.clone();
    concrete.format = format.to_string();
    concrete.style = if format == "rar" {
        "rar_sfx_part".to_string()
    } else {
        "part_numbered".to_string()
    };
    if let Some(proposal) = make_name_proposal(name_index, rows, &concrete) {
        return vec![proposal];
    }
    Vec::new()
}

fn make_name_proposal(
    name_index: &DirectoryNameIndex,
    rows: &[RelationInput],
    seed_interpretation: &NameInterpretation,
) -> Option<RelationProposal> {
    let mut slots: HashMap<u32, Vec<(String, NameInterpretation)>> = HashMap::new();
    let mut companions = Vec::new();
    for row in name_index
        .rows_for_family(rows, seed_interpretation)
        .filter(|row| row.relation_member_eligible)
    {
        let possible_launcher = row.anchor.as_ref().is_some_and(is_possible_sfx_launcher);
        let numbered_volume_name = name_index
            .candidates(row)
            .iter()
            .any(|candidate| candidate.number > 0);
        let launcher_name_match = !numbered_volume_name
            && (is_launcher_candidate(&row.name, &seed_interpretation.prefix)
                || is_camouflaged_sfx_launcher(&row.name, &seed_interpretation.prefix));
        // An unnumbered MZ/SFX file with the proposal's logical name is a
        // launcher companion, even though the structural fallback below can
        // otherwise reinterpret any SFX seed as volume 1.  Numbered `.exe`
        // members do not match this predicate and remain real volumes.
        if possible_launcher && launcher_name_match {
            companions.push(row.path.clone());
            continue;
        }
        let interpretations = name_index.interpretations(row, &seed_interpretation.format);
        let matching = interpretations.iter().filter(|candidate| {
            candidate.format == seed_interpretation.format
                && candidate.prefix == seed_interpretation.prefix
        });
        let mut matched = false;
        for candidate in matching {
            matched = true;
            slots
                .entry(candidate.number)
                .or_default()
                .push((row.path.clone(), candidate.clone()));
        }
        if matched {
            continue;
        }
    }

    // Native ZIP spanning keeps its terminal volume as `name.zip`, while
    // only the preceding `.zNN` members carry a number.  Treat that terminal
    // name as a proposal slot; the validator still has to prove the EOCD and
    // disk semantics, so this is a filename hypothesis rather than a fact.
    if seed_interpretation.format == "zip" && seed_interpretation.style == "zip_spanned" {
        let next_number = slots.keys().copied().max().unwrap_or(0).saturating_add(1);
        for row in name_index
            .rows_for_family(rows, seed_interpretation)
            .filter(|row| row.relation_member_eligible)
        {
            if !zip_terminal_name_matches(&row.name, &seed_interpretation.prefix) {
                continue;
            }
            if slots
                .values()
                .flatten()
                .any(|(path, _)| path.eq_ignore_ascii_case(&row.path))
            {
                continue;
            }
            slots.entry(next_number).or_default().push((
                row.path.clone(),
                NameInterpretation {
                    format: "zip".to_string(),
                    prefix: seed_interpretation.prefix.clone(),
                    number: next_number,
                    style: "zip_spanned".to_string(),
                    width: 2,
                    decorated: false,
                },
            ));
        }
    }

    let mut volumes = Vec::new();
    for (number, candidates) in &slots {
        let unique_paths: HashSet<String> = candidates
            .iter()
            .map(|(path, _)| path.to_ascii_lowercase())
            .collect();
        if unique_paths.len() != 1 {
            return None;
        }
        let (path, interpretation) = candidates.first()?.clone();
        volumes.push((
            path,
            *number,
            interpretation.style,
            interpretation.width,
            interpretation.decorated,
        ));
    }
    volumes.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    let encrypted_rar_hypothesis = seed_interpretation.format == "rar"
        && volumes.len() >= 2
        // An encrypted RAR SFX part1.exe is already promoted by the narrow
        // structural SFX seed rule above.  Do not let an incomplete filename
        // proposal turn that seed into a watch-dispatchable split candidate
        // before the remaining volumes arrive.
        && !volumes.iter().any(|(path, _, _, _, _)| {
            rows.iter()
                .find(|row| row.path.eq_ignore_ascii_case(path))
                .and_then(|row| row.anchor.as_ref())
                .is_some_and(|anchor| anchor.sfx)
        })
        && volumes.iter().all(|(path, _, _, _, _)| {
            rows.iter()
                .find(|row| row.path.eq_ignore_ascii_case(path))
                .and_then(|row| row.anchor.as_ref())
                .is_some_and(|anchor| {
                    anchor.format == "rar"
                        && anchor.encrypted
                        && anchor.needs_password
                        && !anchor.standalone
                })
        });
    if volumes.len() < 2
        || (!encrypted_rar_hypothesis && !volumes.iter().any(|volume| volume.1 == 1))
    {
        return None;
    }
    // A gap is still a proposal: the validator can never accept it as a
    // complete relation (see `proposal_has_gap`), but a structurally proven
    // head plus later volumes must reach Extraction as an incomplete set
    // instead of disappearing from discovery.
    // A structural fallback is only a placeholder for the unnumbered head;
    // it must not erase a concrete family style supplied by another member.
    // In particular, `archive.rar` may be structurally identified as volume
    // 1 while `archive.r00` carries the actual `rar_oldstyle` contract.
    let style = volumes
        .iter()
        .map(|volume| volume.2.as_str())
        .find(|style| *style != "structural_name")
        .map(str::to_owned)
        .unwrap_or_else(|| seed_interpretation.style.clone());
    Some(RelationProposal {
        format: seed_interpretation.format.clone(),
        logical_name: seed_interpretation.prefix.clone(),
        style,
        volumes,
        companions,
    })
}

fn is_possible_sfx_launcher(anchor: &VolumeAnchor) -> bool {
    let weak_mz_seed = anchor.format.is_empty()
        && anchor.sfx
        && anchor.evidence.iter().any(|item| *item == "sfx:pe_header");
    let cheap_embedded_archive = matches!(anchor.format.as_str(), "rar" | "7z" | "zip")
        && anchor.sfx
        && anchor.standalone
        && anchor.structure_offset.is_some_and(|offset| offset > 0)
        && anchor.anchor_roles.iter().any(|role| *role == "first");
    weak_mz_seed || cheap_embedded_archive
}

fn zip_terminal_name_matches(name: &str, logical_prefix: &str) -> bool {
    let lower_name = basename(name).to_ascii_lowercase();
    let marker = format!("{}.zip", logical_prefix.to_ascii_lowercase());
    lower_name == marker
        || lower_name
            .strip_prefix(&marker)
            .is_some_and(|tail| tail.starts_with('.'))
}

fn proposal_key(proposal: &RelationProposal) -> String {
    let mut paths: Vec<String> = proposal
        .volumes
        .iter()
        .map(|(path, number, _, _, _)| format!("{number}:{}", path.to_ascii_lowercase()))
        .collect();
    paths.sort();
    // Different parser interpretations can describe the same physical
    // proposal (for example `payload.7z.001` can also be read as a generic
    // numeric suffix).  They are not competing relations; keep the first,
    // strongest interpretation and only treat a different path union or
    // format as a distinct proposal.
    format!("{}|{}", proposal.format, paths.join(","))
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

fn is_launcher_candidate(name: &str, logical_name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        && get_logical_name(name, false).eq_ignore_ascii_case(logical_name)
}

fn is_camouflaged_sfx_launcher(name: &str, logical_name: &str) -> bool {
    let Some(extension) = Path::new(name).extension().and_then(|value| value.to_str()) else {
        return false;
    };
    if !extension.eq_ignore_ascii_case("exe") {
        return false;
    }
    let launcher = get_logical_name(name, false).to_ascii_lowercase();
    let candidate = logical_name.to_ascii_lowercase();
    candidate == launcher
        || candidate.starts_with(&format!("{launcher}."))
        || candidate.ends_with(&format!(".{launcher}"))
        || candidate.contains(&format!(".{launcher}."))
}

fn validate_relation_proposal(
    py: Python<'_>,
    mut proposal: RelationProposal,
    rows: &[RelationInput],
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<ProposalValidation> {
    let companion_candidates = std::mem::take(&mut proposal.companions);
    let mut anchors: HashMap<String, VolumeAnchor> = rows
        .iter()
        .filter_map(|row| {
            row.anchor
                .clone()
                .map(|anchor| (row.path.to_ascii_lowercase(), anchor))
        })
        .collect();

    let bounded_raw_zip_relation = proposal.format == "zip"
        && proposal.style != "zip_spanned"
        && proposal
            .volumes
            .iter()
            .find(|(_, number, _, _, _)| *number == 1)
            .and_then(|(path, _, _, _, _)| anchors.get(&path.to_ascii_lowercase()))
            .is_some_and(|anchor| {
                anchor
                    .evidence
                    .iter()
                    .any(|item| *item == "zip:local_header")
            })
        && proposal
            .volumes
            .iter()
            .filter_map(|(path, _, _, _, _)| anchors.get(&path.to_ascii_lowercase()))
            .filter(|anchor| {
                anchor
                    .evidence
                    .iter()
                    .any(|item| *item == "zip:eocd_single_disk_without_local_header")
            })
            .count()
            == 1;

    // Raw byte-split ZIP relations are already proven by two independent
    // bounded anchors: the first local header and the terminal EOCD.  Do not
    // overwrite those relation facts with a physical-file deep probe that
    // cannot validate a central directory spanning multiple chunks.
    if !bounded_raw_zip_relation {
        let mut volume_paths: Vec<String> = proposal
            .volumes
            .iter()
            .map(|(path, _, _, _, _)| path.clone())
            .collect();
        volume_paths.sort_by_key(|path| path.to_ascii_lowercase());
        volume_paths.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        let tail_limit = if proposal.format == "zip" { 65_557 } else { 0 };
        let deep_anchors = py.detach(|| {
            probe_volume_anchor_paths_deep(&volume_paths, 1024 * 1024, tail_limit, path_passwords)
        });
        for anchor in deep_anchors {
            anchors.insert(anchor.path.to_ascii_lowercase(), anchor);
        }
    }

    let status = match proposal.format.as_str() {
        "rar" => validate_rar_proposal(py, &proposal, &anchors, path_passwords),
        "7z" => Ok(validate_seven_zip_proposal(&proposal, &anchors, rows)),
        "zip" => validate_zip_proposal(py, &proposal, &anchors),
        _ => Ok(ProposalStatus::Unsupported),
    }?;
    // Formats without internal volume numbers (RAR4, ZIP, 7z) cannot prove
    // that a missing middle slot is absent, so a gapped physical set is never
    // a complete relation.
    let status = if status == ProposalStatus::Valid && proposal_has_gap(&proposal) {
        ProposalStatus::Inconclusive
    } else {
        status
    };

    // A launcher is an ownership companion, not archive input.  Validate the
    // data proposal first; only a valid relation may claim a companion.  A
    // launcher-only SFX may carry no embedded archive bytes at all, so the
    // companion proof is only a bounded PE header check.
    if status == ProposalStatus::Valid && !companion_candidates.is_empty() {
        let companion_anchors = py.detach(|| {
            probe_volume_anchor_paths_deep(&companion_candidates, 1024 * 1024, 0, path_passwords)
        });
        let mut verified_companions: Vec<VolumeAnchor> = companion_anchors
            .into_iter()
            .filter(|anchor| anchor.pe_structure)
            .collect();
        verified_companions.sort_by_key(|anchor| anchor.path.to_ascii_lowercase());
        verified_companions.dedup_by(|left, right| left.path.eq_ignore_ascii_case(&right.path));
        if verified_companions.len() == 1 {
            let companion = verified_companions.pop().expect("one companion exists");
            proposal.companions.push(companion.path.clone());
            anchors.insert(companion.path.to_ascii_lowercase(), companion);
        }
    }

    Ok(ProposalValidation {
        status,
        proposal,
        anchors,
    })
}

fn validate_rar_proposal(
    py: Python<'_>,
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<ProposalStatus> {
    let mut first_count = 0usize;
    let mut raw_sfx_head = false;
    let mut known_numbers = HashSet::new();
    for (path, number, _, _, _) in &proposal.volumes {
        let Some(anchor) = anchors.get(&path.to_ascii_lowercase()) else {
            return Ok(ProposalStatus::Inconclusive);
        };
        if anchor.needs_password || anchor.wrong_password {
            return Ok(ProposalStatus::NeedsPassword);
        }
        let is_raw_sfx_head = *number == 1
            && anchor.format == "rar"
            && anchor.confidence == "strong"
            && anchor.sfx
            && anchor.standalone
            && anchor.structure_offset.is_some_and(|offset| offset > 0);
        if is_raw_sfx_head {
            raw_sfx_head = true;
            first_count += 1;
            continue;
        }
        if raw_sfx_head && anchor.format.is_empty() {
            // A raw SFX may be split at arbitrary byte boundaries, so later
            // physical chunks have no independent RAR header.  The first
            // deep probe is the structural proof; the bounded filename
            // proposal supplies ordering for these opaque chunks.
            continue;
        }
        if anchor.format != "rar" || anchor.confidence != "strong" || !anchor.multivolume {
            return if anchor.format.is_empty() {
                Ok(ProposalStatus::Inconclusive)
            } else {
                Ok(ProposalStatus::Reject)
            };
        }
        if anchor.anchor_roles.contains(&"first") || anchor.sfx {
            first_count += 1;
        }
        if let Some(internal) = anchor.internal_volume_number {
            if internal != *number || !known_numbers.insert(internal) {
                return Ok(ProposalStatus::Reject);
            }
        }
    }
    if first_count != 1 {
        return Ok(ProposalStatus::Inconclusive);
    }
    if let Some(highest) = known_numbers.iter().copied().max() {
        if (1..=highest).any(|number| !known_numbers.contains(&number)) {
            // Header-encrypted RAR proposals may be formed from a gapped
            // filename family so that password discovery can run.  Once the
            // password exposes internal volume numbers, a gap proves that
            // the current physical set is incomplete; it must not validate
            // as a complete relation.
            return Ok(ProposalStatus::Inconclusive);
        }
    }

    let ordered_paths: Vec<String> = proposal
        .volumes
        .iter()
        .map(|(path, _, _, _, _)| path.clone())
        .collect();
    // An SFX first volume does not by itself imply a raw byte-split stream.
    // WinRAR commonly emits a normal RAR header at the start of every later
    // volume, while other SFX producers split the payload into opaque chunks.
    // Only the latter may be validated through one concatenated view; when a
    // later member has its own RAR anchor, terminal proof must run against
    // that physical last volume.
    let raw_sfx = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
        .and_then(|(path, _, _, _, _)| anchors.get(&path.to_ascii_lowercase()))
        .is_some_and(|anchor| {
            anchor.sfx && anchor.structure_offset.is_some_and(|offset| offset > 0)
        })
        && proposal.volumes.iter().skip(1).all(|(path, _, _, _, _)| {
            anchors
                .get(&path.to_ascii_lowercase())
                .is_some_and(|anchor| anchor.format.is_empty())
        });
    let raw_sfx_start_offset = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
        .and_then(|(path, _, _, _, _)| {
            anchors
                .get(&path.to_ascii_lowercase())
                .and_then(|anchor| anchor.structure_offset)
        })
        .unwrap_or(0);
    let header_encrypted = proposal.volumes.iter().any(|(path, _, _, _, _)| {
        anchors
            .get(&path.to_ascii_lowercase())
            .is_some_and(|anchor| anchor.encrypted)
    });
    let terminal_proof = if header_encrypted {
        let proof_paths = if raw_sfx {
            ordered_paths.clone()
        } else {
            let Some((path, _, _, _, _)) = proposal
                .volumes
                .iter()
                .max_by_key(|(_, number, _, _, _)| *number)
            else {
                return Ok(ProposalStatus::Inconclusive);
            };
            vec![path.clone()]
        };
        let password = path_passwords.and_then(|passwords| {
            proof_paths.iter().find_map(|proof_path| {
                passwords.iter().find_map(|(path, password)| {
                    proof_path
                        .eq_ignore_ascii_case(path)
                        .then_some(password.as_str())
                })
            })
        });
        let Some(password) = password else {
            return Ok(ProposalStatus::NeedsPassword);
        };
        let proof_offset = if raw_sfx {
            raw_sfx_start_offset
        } else {
            anchors
                .get(&proof_paths[0].to_ascii_lowercase())
                .and_then(|anchor| anchor.structure_offset)
                .unwrap_or(0)
        };
        match py
            .detach(|| probe_rar_terminal_with_password(&proof_paths, proof_offset, password, 4096))
        {
            Ok(Some(proof)) => Some((proof.end_block_found, proof.end_block_flags)),
            Ok(None) | Err(_) => return Ok(ProposalStatus::Inconclusive),
        }
    } else {
        None
    };
    if let Some((end_found, end_flags)) = terminal_proof {
        return if end_found && end_flags & 0x01 == 0 {
            Ok(ProposalStatus::Valid)
        } else {
            Ok(ProposalStatus::Inconclusive)
        };
    }
    let terminal = if raw_sfx {
        match probe_rar_volume_paths(py, &ordered_paths, raw_sfx_start_offset, 4096) {
            Ok(result) => result,
            Err(_) => return Ok(ProposalStatus::Inconclusive),
        }
    } else {
        let Some((path, _, _, _, _)) = proposal
            .volumes
            .iter()
            .max_by_key(|(_, number, _, _, _)| *number)
        else {
            return Ok(ProposalStatus::Inconclusive);
        };
        let offset = anchors
            .get(&path.to_ascii_lowercase())
            .and_then(|anchor| anchor.structure_offset)
            .unwrap_or(0);
        match probe_rar_path(py, path, offset, 4096) {
            Ok(result) => result,
            Err(_) => return Ok(ProposalStatus::Inconclusive),
        }
    };
    let terminal = terminal.bind(py);
    if terminal
        .get_item("password_required")?
        .and_then(|value| value.extract::<bool>().ok())
        .unwrap_or(false)
    {
        return Ok(ProposalStatus::NeedsPassword);
    }
    let end_found = terminal
        .get_item("end_block_found")?
        .and_then(|value| value.extract::<bool>().ok())
        .unwrap_or(false);
    let end_flags = terminal
        .get_item("end_block_flags")?
        .and_then(|value| value.extract::<u64>().ok())
        .unwrap_or(0);
    if end_found && end_flags & 0x01 == 0 {
        Ok(ProposalStatus::Valid)
    } else {
        Ok(ProposalStatus::Inconclusive)
    }
}

fn validate_seven_zip_proposal(
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
    rows: &[RelationInput],
) -> ProposalStatus {
    let Some((first_path, _, _, _, _)) = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
    else {
        return ProposalStatus::Reject;
    };
    let Some(first) = anchors.get(&first_path.to_ascii_lowercase()) else {
        return ProposalStatus::Inconclusive;
    };
    if first.format != "7z"
        || first.confidence != "strong"
        || !first.anchor_roles.contains(&"first")
    {
        return if first.format.is_empty() {
            ProposalStatus::Inconclusive
        } else {
            ProposalStatus::Reject
        };
    }
    if first.needs_password || first.wrong_password {
        return ProposalStatus::Inconclusive;
    }
    let Some(expected) = first.expected_logical_size else {
        return ProposalStatus::Inconclusive;
    };
    let physical_size = proposal
        .volumes
        .iter()
        .filter_map(|(path, _, _, _, _)| {
            rows.iter()
                .find(|row| row.path.eq_ignore_ascii_case(path))
                .and_then(|row| row.size)
                .or_else(|| {
                    anchors
                        .get(&path.to_ascii_lowercase())
                        .map(|anchor| anchor.size)
                })
        })
        .sum::<u64>();
    if physical_size == expected {
        ProposalStatus::Valid
    } else if physical_size < expected {
        ProposalStatus::Inconclusive
    } else {
        ProposalStatus::Reject
    }
}

fn validate_zip_proposal(
    _py: Python<'_>,
    proposal: &RelationProposal,
    anchors: &HashMap<String, VolumeAnchor>,
) -> PyResult<ProposalStatus> {
    let Some((first_path, _, _, _, _)) = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
    else {
        return Ok(ProposalStatus::Reject);
    };
    let Some(first) = anchors.get(&first_path.to_ascii_lowercase()) else {
        return Ok(ProposalStatus::Inconclusive);
    };
    if first.format != "zip" || first.confidence == "unsupported" {
        return if first.format.is_empty() {
            Ok(ProposalStatus::Inconclusive)
        } else {
            Ok(ProposalStatus::Reject)
        };
    }

    let terminal_paths: Vec<&String> = proposal
        .volumes
        .iter()
        .filter_map(|(path, _, _, _, _)| {
            anchors
                .get(&path.to_ascii_lowercase())
                .filter(|anchor| anchor.anchor_roles.contains(&"terminal"))
                .map(|_| path)
        })
        .collect();
    if terminal_paths.len() != 1 {
        return Ok(ProposalStatus::Inconclusive);
    }
    let terminal = anchors
        .get(&terminal_paths[0].to_ascii_lowercase())
        .expect("terminal path was collected from anchor map");
    let highest = proposal
        .volumes
        .iter()
        .map(|(_, number, _, _, _)| *number)
        .max()
        .unwrap_or(0);

    if proposal.style == "zip_spanned" {
        let first_is_spanned = first
            .evidence
            .iter()
            .any(|item| *item == "zip:split_marker")
            || (first
                .evidence
                .iter()
                .any(|item| *item == "zip:local_header")
                && first.multivolume
                && first.continuation_to_next);
        let terminal_is_spanned = terminal
            .evidence
            .iter()
            .any(|item| *item == "zip:eocd_split_terminal");
        if !first_is_spanned || !terminal_is_spanned {
            return Ok(ProposalStatus::Reject);
        }
        if terminal.internal_volume_number != Some(highest) {
            return Ok(ProposalStatus::Reject);
        }
    } else {
        let first_is_raw = first
            .evidence
            .iter()
            .any(|item| *item == "zip:local_header");
        let terminal_is_single_disk = terminal
            .evidence
            .iter()
            .any(|item| *item == "zip:eocd_single_disk_without_local_header");
        if !first_is_raw || !terminal_is_single_disk {
            return Ok(ProposalStatus::Inconclusive);
        }
    }

    // The bounded first-header + terminal-EOCD anchors are independent strong
    // evidence for the split relation. Do not concatenate the family and walk
    // the whole central directory/local links a second time; Open/Extract is
    // the canonical completeness and damage parser.
    Ok(ProposalStatus::Valid)
}

fn ordinary_file_group_to_dict(
    py: Python<'_>,
    row: &RelationInput,
    relation_confirmed: bool,
) -> PyResult<Py<PyDict>> {
    let parsed = parse_relation_numbered_volume(&row.name);
    let archive_numbered_hypothesis = !relation_confirmed
        && parsed.as_ref().is_some_and(|_| {
            row.anchor.as_ref().is_some_and(|anchor| {
                matches!(anchor.format.as_str(), "rar" | "7z" | "zip") || anchor.sfx
            })
        });
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
    let proposal = &validation.proposal;
    let head = proposal
        .volumes
        .iter()
        .find(|(_, number, _, _, _)| *number == 1)
        .unwrap_or(&proposal.volumes[0]);
    let anchor = validation.anchors.get(&head.0.to_ascii_lowercase());
    let split_family = proposal_split_family(proposal, &validation.anchors);
    let relation = FileRelationNative {
        filename: basename(&head.0).to_string(),
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
        .collect();
    let carrier = proposal.companions.first().cloned().unwrap_or_default();
    let carrier_size = (!carrier.is_empty())
        .then(|| {
            validation
                .anchors
                .get(&carrier.to_ascii_lowercase())
                .map(|value| value.size)
        })
        .flatten();
    let dict = PyDict::new(py);
    dict.set_item("head_path", &head.0)?;
    dict.set_item("head_name", basename(&head.0))?;
    dict.set_item("logical_name", &proposal.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", true)?;
    dict.set_item("head_size", anchor.map(|value| value.size))?;
    dict.set_item(
        "logical_size",
        proposal_logical_size(proposal, &validation.anchors),
    )?;
    dict.set_item("split_volumes", PyList::new(py, &volume_dicts)?)?;
    let mut metadata = anchor
        .map(|value| relation_confirmed_anchor_to_dict(py, value))
        .transpose()?;
    if metadata.is_none() {
        metadata = Some(PyDict::new(py).unbind());
    }
    if let Some(metadata) = metadata.as_ref() {
        let metadata = metadata.bind(py);
        metadata.set_item("format", &proposal.format)?;
        metadata.set_item("relation_confirmed", true)?;
        metadata.set_item("needs_password", true)?;
        metadata.set_item("proposal_paths", proposal_owned_paths(proposal))?;
        metadata.set_item("password_scope", &proposal.logical_name)?;
    }
    dict.set_item("head_metadata", metadata)?;
    dict.set_item("companion_paths", &proposal.companions)?;
    dict.set_item("carrier_path", &carrier)?;
    dict.set_item("carrier_size", carrier_size)?;
    dict.set_item(
        "format_reject_mask",
        anchor.map(|value| value.format_reject_mask).unwrap_or(0),
    )?;
    Ok(dict.unbind())
}

fn proposal_has_gap(proposal: &RelationProposal) -> bool {
    // Proposals are already sorted and have unique slots. Never walk up to
    // a filename-supplied maximum: it can be u32::MAX for just two files.
    proposal.volumes.first().is_none_or(|part| part.1 != 1)
        || proposal
            .volumes
            .windows(2)
            .any(|pair| pair[0].1.checked_add(1) != Some(pair[1].1))
}

/// Every member is a structurally proven volume of the proposal format and
/// exactly the filename head (slot 1) carries the first-volume role.  Only a
/// missing or truncated member can keep such a proposal inconclusive.
fn is_incomplete_volume_set(validation: &ProposalValidation) -> bool {
    let proposal = &validation.proposal;
    let mut heads = 0usize;
    for (path, number, _, _, _) in &proposal.volumes {
        let Some(anchor) = validation.anchors.get(&path.to_ascii_lowercase()) else {
            return false;
        };
        if anchor.format != proposal.format
            || anchor.confidence != "strong"
            || anchor.needs_password
            || anchor.wrong_password
            || !(anchor.multivolume
                || anchor.continuation_from_previous
                || anchor.continuation_to_next)
        {
            return false;
        }
        if anchor
            .internal_volume_number
            .is_some_and(|internal| internal != *number)
        {
            return false;
        }
        if anchor.anchor_roles.contains(&"first") || anchor.internal_volume_number == Some(1) {
            if *number != 1 {
                return false;
            }
            heads += 1;
        }
    }
    heads == 1
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
    let anchors =
        py.detach(|| probe_volume_anchor_paths_cheap(&visible_paths, path_passwords.as_deref()));
    let anchor_by_path: HashMap<String, VolumeAnchor> = anchors
        .into_iter()
        .map(|anchor| (anchor.path.to_ascii_lowercase(), anchor))
        .collect();
    let rows = visible_paths
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
    let groups: Vec<Py<PyDict>> =
        build_candidate_groups_from_physical(py, rows, &filtered_keys, path_passwords.as_deref())?
            .into_iter()
            .map(|group| group.to_dict(py))
            .collect::<PyResult<_>>()?;
    let format_hint = normalize_retry_format(format_hint);
    for group in groups {
        let Some(is_split) = group
            .bind(py)
            .get_item("is_split_candidate")?
            .and_then(|value| value.extract::<bool>().ok())
        else {
            continue;
        };
        if !is_split {
            continue;
        }
        if !format_hint.is_empty() {
            let metadata_format = group.bind(py).get_item("head_metadata")?.and_then(|value| {
                value
                    .get_item("format")
                    .ok()
                    .and_then(|format| format.extract::<String>().ok())
            });
            if metadata_format.is_some_and(|format| format != format_hint) {
                continue;
            }
        }
        let parts: Vec<String> = group
            .bind(py)
            .get_item("all_parts")?
            .map(|value| value.extract::<Vec<String>>())
            .transpose()?
            .unwrap_or_default();
        if current_paths
            .iter()
            .all(|current| parts.iter().any(|part| part.eq_ignore_ascii_case(current)))
        {
            return Ok(Some(group));
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
        "zip" => "zip",
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
    dict.set_item("pe_structure", anchor.pe_structure)?;
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
            ".7z" | ".rar" | ".zip" | ".gz" | ".bz2" | ".xz" | ".exe"
        )
    {
        return clean_logical_name(&base);
    }
    clean_logical_name(filename)
}

fn logical_name_from_parsed(parsed: &ParsedVolume) -> String {
    if matches!(
        parsed.style,
        "rar_part" | "rar_sfx_part" | "part_numbered" | "rar_oldstyle" | "zip_spanned"
    ) || parsed.family == "generic"
    {
        return clean_logical_name(&parsed.prefix);
    }
    let suffix = format!(".{}", parsed.family);
    let lower = parsed.prefix.to_ascii_lowercase();
    if lower.ends_with(&suffix) {
        return clean_logical_name(&parsed.prefix[..parsed.prefix.len() - suffix.len()]);
    }
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
    if parse_loose_rar_part_volume(&name).is_some() {
        return true;
    }
    if name.ends_with(".7z") || name.ends_with(".zip") || name.ends_with(".rar") {
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

/// Produce every plausible filename interpretation in descending semantic
/// strength.  Callers that still expose the legacy single-result API use the
/// first candidate, while directory grouping can reason about alternatives.
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
                        decorated: false,
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
                            decorated: false,
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
                        decorated: false,
                    },
                );
            }
        }

        if let Some(parsed) = parse_decorated_numbered_volume(filename) {
            push_unique_volume_candidate(&mut candidates, parsed);
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
            || (number == 1 && tail.eq_ignore_ascii_case(".exe"))),
    })
}

/// RAR's `partN` token is often the only stable part of a disguised name.
/// Keep this fallback out of the generic filename parser: without a structural
/// RAR anchor, accepting arbitrary `partN` names would merge unrelated files.
fn parse_loose_rar_part_volume(path: &str) -> Option<ParsedVolume> {
    let captures = rar_loose_part_re().captures(path)?;
    let raw_number = captures.name("number")?.as_str();
    let number = raw_number.parse::<u32>().ok().filter(|value| *value > 0)?;
    let prefix = captures
        .name("prefix")?
        .as_str()
        .trim_end_matches(['.', '_', '-', ' ']);
    let prefix = prefix
        .rsplit_once('.')
        .filter(|(_, noise)| {
            (1..=4).contains(&noise.len())
                && noise
                    .chars()
                    .all(|character| character.is_ascii_uppercase())
        })
        .map(|(base, _)| base)
        .unwrap_or(prefix);
    if prefix.is_empty() {
        return None;
    }
    Some(ParsedVolume {
        prefix: prefix.to_string(),
        number,
        style: "rar_part",
        width: raw_number.len(),
        family: "rar",
        decorated: true,
    })
}

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

fn parse_decorated_numbered_volume(path: &str) -> Option<ParsedVolume> {
    if let Some(captures) = decorated_marker_format_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let format = captures.name("format")?.as_str();
        let family = archive_family(format)?;
        return parsed_decorated_marker(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            format.eq_ignore_ascii_case("exe"),
        );
    }
    if let Some(captures) = decorated_format_marker_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let format = captures.name("format")?.as_str();
        let family = archive_family(format)?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            true,
            format.eq_ignore_ascii_case("exe"),
        );
    }
    if let Some(captures) = decorated_numeric_format_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let family = archive_family(captures.name("format")?.as_str())?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            false,
            false,
        );
    }
    if let Some(captures) = decorated_format_numeric_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let family = archive_family(captures.name("format")?.as_str())?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            false,
            false,
        );
    }
    if let Some(captures) = decorated_old_rar_re().captures(path) {
        let number = captures.name("number")?.as_str();
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: number.parse::<u32>().ok()?.saturating_add(2),
            style: "rar_oldstyle",
            width: number.len(),
            family: "rar",
            decorated: true,
        });
    }
    None
}

fn parsed_decorated_marker(
    prefix: &str,
    raw_number: &str,
    family: &'static str,
    sfx: bool,
) -> Option<ParsedVolume> {
    let number = raw_number.parse::<u32>().ok().filter(|value| *value > 0)?;
    if family == "rar" {
        return Some(ParsedVolume {
            prefix: prefix.to_string(),
            number,
            style: if sfx { "rar_sfx_part" } else { "rar_part" },
            width: raw_number.len(),
            family,
            decorated: true,
        });
    }
    Some(ParsedVolume {
        prefix: format!("{prefix}.{family}"),
        number,
        style: "numeric_suffix",
        width: 3,
        family,
        decorated: true,
    })
}

fn parsed_decorated_numeric(
    prefix: &str,
    raw_number: &str,
    family: &'static str,
    marker_numbered: bool,
    sfx: bool,
) -> Option<ParsedVolume> {
    let mut number: u32 = raw_number.parse().ok()?;
    if marker_numbered && number == 0 {
        return None;
    }
    let style = if family == "zip" && raw_number.len() == 4 && raw_number.starts_with('0') {
        number = number.saturating_add(1);
        "zip_zero_numbered"
    } else if family == "rar" && marker_numbered {
        if sfx {
            "rar_sfx_part"
        } else {
            "rar_part"
        }
    } else {
        "numeric_suffix"
    };
    if number == 0 {
        return None;
    }
    let canonical_prefix = if matches!(style, "rar_part" | "rar_sfx_part") {
        prefix.to_string()
    } else {
        format!("{prefix}.{family}")
    };
    Some(ParsedVolume {
        prefix: canonical_prefix,
        number,
        style,
        width: if style == "numeric_suffix" {
            3
        } else {
            raw_number.len()
        },
        family,
        decorated: true,
    })
}

fn archive_family(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "7z" => Some("7z"),
        "zip" => Some("zip"),
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

/// Filename hints order a seeded proposal; they never prove an archive.
/// Prefer explicit numbering parsed above, then accept one distinct ASCII
/// integer. A structural number may disambiguate decorations, but cannot
/// contradict the only integer present. `7z`'s 7 is not a volume number.
fn suffix_volume_number(name: &str, structural: Option<u32>) -> Option<u32> {
    let suffix = name
        .split_once('.')
        .map(|(_, suffix)| suffix)
        .unwrap_or("")
        .as_bytes();
    let mut position = 0usize;
    let mut number = None;
    let mut ambiguous = false;
    let mut matches_structure = false;
    while position < suffix.len() {
        if !suffix[position].is_ascii_digit() {
            position += 1;
            continue;
        }
        let start = position;
        let mut value = 0u32;
        while position < suffix.len() && suffix[position].is_ascii_digit() {
            value = value
                .checked_mul(10)?
                .checked_add(u32::from(suffix[position] - b'0'))?;
            position += 1;
        }
        if value == 7
            && position == start + 1
            && suffix
                .get(position)
                .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'z'))
        {
            continue;
        }
        if value == 0 {
            return None;
        }
        matches_structure |= structural == Some(value);
        ambiguous |= number.is_some_and(|previous| previous != value);
        number = Some(value);
    }
    match structural {
        Some(value) if matches_structure || number.is_none() => Some(value),
        Some(_) => None,
        None if !ambiguous => number,
        None => None,
    }
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
    value.trim().trim_end_matches('.').to_string()
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
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<format>7z|zip|rar)\.(?P<number>\d+)$"))
}

fn parse_zip_zero_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+\.zip)\.(?P<number>\d{4})$"))
}

fn parse_zip_split_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.z(?P<number>\d{2,})(?P<tail>(?:\..+)?)$"))
}

fn parse_rar_part_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.(?P<format>rar|exe)$"))
}

fn parse_old_rar_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.r(?P<number>\d{2,})$"))
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

fn rar_loose_part_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.*?)part(?P<number>\d+).*$"))
}

// Decorated names preserve only the meaningful token order. Everything surrounding
// the marker, number, and archive-family token is intentionally treated as noise;
// downstream archive structure detection is responsible for rejecting false positives.
fn decorated_marker_format_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d+)(?:[^.\d][^.]*)?\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_format_marker_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d+)(?:[^.\d][^.]*)?(?:\.[^.]+)*$")
    })
}

fn decorated_numeric_format_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*?(?P<number>0\d{2,3})[^.]*\.[^.]*(?P<format>7z|zip|rar)[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_format_numeric_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?P<format>7z|zip|rar)[^.]*\.[^.]*?(?P<number>0\d{2,3})[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_old_rar_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.[^.]*r[^.\d]*(?P<number>\d{2,})[^.]*(?:\.[^.]+)*$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_suffix_numbers_require_an_unambiguous_order() {
        for (name, structural, expected) in [
            ("name2026", None, None),
            ("name.chunk13.noise13", None, Some(13)),
            ("name.7z.chunk7", None, Some(7)),
            ("name.chunk2.build2026", None, None),
            ("name.chunk2.build2026", Some(2), Some(2)),
            ("name.chunk3", Some(2), None),
            ("name.chunk0", None, None),
            ("name.chunk4294967296", None, None),
            ("name.chunk4294967295", None, Some(u32::MAX)),
        ] {
            assert_eq!(suffix_volume_number(name, structural), expected, "{name}");
        }
    }

    #[test]
    fn sparse_huge_volume_numbers_are_checked_without_enumerating_missing_slots() {
        let mut validation = validation_with_owned_paths(ProposalStatus::Valid, &["head", "tail"]);
        assert!(!proposal_has_gap(&validation.proposal));
        validation.proposal.volumes[1].1 = u32::MAX;
        assert!(proposal_has_gap(&validation.proposal));
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
    fn loose_rar_part_names_require_existing_volume_structure() {
        for (multivolume, needs_password) in [(false, false), (true, false), (false, true)] {
            let row = RelationInput {
                path: "payloadAApart2.photo".to_string(),
                path_key: "payloadaapart2.photo".to_string(),
                name: "payloadAApart2.photo".to_string(),
                size: Some(100),
                relation_member_eligible: true,
                anchor: Some(VolumeAnchor {
                    format: "rar".to_string(),
                    multivolume,
                    needs_password,
                    ..VolumeAnchor::default()
                }),
            };
            let index = DirectoryNameIndex::build(std::slice::from_ref(&row));
            assert_eq!(
                !index.candidates(&row).is_empty(),
                multivolume || needs_password
            );
        }
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
    fn noisy_rar_part_names_keep_the_same_declared_family_and_prefix() {
        let first = parse_numbered_volume_name("X.AApart01tail.BBrarCC").unwrap();
        let second = parse_numbered_volume_name("X.DDpart02more.EErarFF").unwrap();

        assert_eq!(first.family, "rar");
        assert_eq!(second.family, "rar");
        assert_eq!(first.style, "rar_part");
        assert_eq!(second.style, "rar_part");
        assert_eq!(first.prefix, "X");
        assert_eq!(second.prefix, "X");
        assert_eq!((first.number, second.number), (1, 2));
        assert!(first.decorated && second.decorated);
    }

    #[test]
    fn noisy_format_tokens_remain_cross_family_incompatible() {
        let seven_zip = parse_numbered_volume_name("X.AA7zZZ.BB001CC").unwrap();
        let zip = parse_numbered_volume_name("X.DDzipYY.EE001FF").unwrap();
        let rar = parse_numbered_volume_name("X.GGpart01noise.HHrarII").unwrap();

        assert_eq!(
            (seven_zip.family, seven_zip.style),
            ("7z", "numeric_suffix")
        );
        assert_eq!((zip.family, zip.style), ("zip", "numeric_suffix"));
        assert_eq!((rar.family, rar.style), ("rar", "rar_part"));
        assert_ne!(seven_zip.family, zip.family);
        assert_ne!(seven_zip.family, rar.family);
        assert_ne!(zip.family, rar.family);
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
    fn weak_sfx_part1_name_is_escalation_candidate() {
        let path = r"C:\watch\case.part1.exe".to_string();
        let row = RelationInput {
            path: path.clone(),
            path_key: path.to_ascii_lowercase(),
            name: "case.part1.exe".to_string(),
            size: Some(100),
            relation_member_eligible: true,
            anchor: Some(VolumeAnchor {
                sfx: true,
                evidence: vec!["sfx:pe_header"],
                ..VolumeAnchor::default()
            }),
        };
        let index = DirectoryNameIndex::build(std::slice::from_ref(&row));
        assert!(is_weak_sfx_split_head(&row, &index));
    }

    #[test]
    fn structurally_confirmed_raw_rar_sfx_head_can_seed_numbered_siblings() {
        let first_path = r"C:\watch\shared.bundle.exe.part1.useless.fake".to_string();
        let second_path = r"C:\watch\shared.bundle.rar.part2.useless.fake".to_string();
        let rows = vec![
            RelationInput {
                path: first_path.clone(),
                path_key: first_path.to_ascii_lowercase(),
                name: "shared.bundle.exe.part1.useless.fake".to_string(),
                size: Some(1024),
                relation_member_eligible: true,
                anchor: Some(VolumeAnchor {
                    format: "rar".to_string(),
                    confidence: "strong".to_string(),
                    standalone: true,
                    structure_offset: Some(256),
                    sfx: true,
                    pe_structure: true,
                    ..VolumeAnchor::default()
                }),
            },
            RelationInput {
                path: second_path.clone(),
                path_key: second_path.to_ascii_lowercase(),
                name: "shared.bundle.rar.part2.useless.fake".to_string(),
                size: Some(1024),
                relation_member_eligible: true,
                anchor: None,
            },
        ];
        let index = DirectoryNameIndex::build(&rows);

        assert_eq!(
            seed_strength_for_row(&rows[0], &rows, &index),
            Some("strong")
        );
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
        let owned_paths: Vec<HashSet<String>> = validations
            .iter()
            .map(|validation| proposal_owned_paths(&validation.proposal))
            .collect();

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
        let owned_paths: Vec<HashSet<String>> = validations
            .iter()
            .map(|validation| proposal_owned_paths(&validation.proposal))
            .collect();

        let conflicts =
            conflicting_proposal_indexes(&validations, &owned_paths, ProposalStatus::Valid);

        assert_eq!(conflicts, HashSet::from([0, 1, 2]));
    }
}
