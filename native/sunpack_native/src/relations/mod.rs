use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_paths_cheap, probe_volume_anchor_paths_deep, VolumeAnchor,
};
use crate::analysis_native::{
    probe_rar_path, probe_rar_terminal_with_password, probe_rar_volume_paths,
    probe_zip_volume_paths,
};
use crate::scan::directory::NativeDirectorySnapshot;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
struct RelationInput {
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
struct ProposalValidation {
    status: ProposalStatus,
    proposal: RelationProposal,
    anchors: HashMap<String, VolumeAnchor>,
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
                let parsed = parse_volume_candidates(&row.name);
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
        Self { entries_by_path }
    }

    fn candidates<'a>(&'a self, row: &RelationInput) -> &'a [ParsedVolume] {
        self.entries_by_path
            .get(&row.path_key)
            .map(|entry| entry.parsed.as_slice())
            .unwrap_or(&[])
    }

    fn interpretations(
        &self,
        row: &RelationInput,
        target_format: &str,
    ) -> &[NameInterpretation] {
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
pub(crate) fn relations_split_sort_key(path: &str) -> (u8, u32, String) {
    split_sort_key(path)
}

#[pyfunction]
#[pyo3(signature = (raw_snapshot, filtered_snapshot, path_passwords=None))]
pub(crate) fn relations_build_candidate_groups_from_snapshot(
    py: Python<'_>,
    raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    filtered_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    path_passwords: Option<Vec<(String, String)>>,
) -> PyResult<Vec<Py<PyDict>>> {
    let filtered_keys: HashSet<String> = filtered_snapshot
        .relation_file_records()
        .map(|(path, _, _, _)| path.to_ascii_lowercase())
        .collect();
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
    build_candidate_groups_from_physical(
        py,
        raw_rows,
        &filtered_keys,
        path_passwords.as_deref(),
    )
}

fn build_candidate_groups_from_physical(
    py: Python<'_>,
    rows: Vec<RelationInput>,
    filtered_keys: &HashSet<String>,
    path_passwords: Option<&[(String, String)]>,
) -> PyResult<Vec<Py<PyDict>>> {
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
    // A password map is only supplied on the retry pass after an encrypted
    // proposal has already been discovered and its password has been
    // verified against at least one member.  If that retry still cannot
    // prove a complete relation (for example because a volume is missing),
    // those physical paths must not fall back to ordinary single-file
    // candidates.  The first pass has no password map, so weak encrypted
    // files retain their normal fail-open behaviour.
    let attempted_password_paths: HashSet<String> = path_passwords
        .unwrap_or(&[])
        .iter()
        .map(|(path, _)| path.to_ascii_lowercase())
        .collect();
    for directory in directory_order {
        let Some(directory_rows) = by_directory.remove(&directory) else {
            continue;
        };
        let name_index = DirectoryNameIndex::build(&directory_rows);
        let mut strong_seed_paths = HashSet::new();
        let mut proposals = Vec::new();
        let mut proposal_keys = HashSet::new();

        for seed in directory_rows.iter().filter(|row| {
            row.anchor
                .as_ref()
                .and_then(cheap_seed_strength)
                .is_some()
        }) {
            let Some(anchor) = seed.anchor.as_ref() else {
                continue;
            };
            let Some(strength) = cheap_seed_strength(anchor) else {
                continue;
            };
            if strength == "strong" {
                strong_seed_paths.insert(seed.path.to_ascii_lowercase());
            }
            for interpretation in name_index.interpretations(seed, &anchor.format) {
                if !has_filtered_family_trigger(
                    &name_index,
                    &directory_rows,
                    filtered_keys,
                    &interpretation,
                ) {
                    continue;
                }
                for proposal in name_proposals_for_seed(
                    &name_index,
                    &directory_rows,
                    filtered_keys,
                    seed,
                    &interpretation,
                ) {
                    let key = proposal_key(&proposal);
                    if !proposal_keys.insert(key) {
                        continue;
                    }
                    proposals.push(proposal);
                }
            }
        }

        let mut validations = Vec::new();
        for proposal in proposals {
            validations.push(validate_relation_proposal(
                py,
                proposal,
                &directory_rows,
                path_passwords,
            )?);
        }

        let valid_indexes: Vec<usize> = validations
            .iter()
            .enumerate()
            .filter_map(|(index, validation)| {
                (validation.status == ProposalStatus::Valid).then_some(index)
            })
            .collect();
        let mut conflicted = HashSet::new();
        for left_index in 0..valid_indexes.len() {
            for right_index in (left_index + 1)..valid_indexes.len() {
                let left = &validations[valid_indexes[left_index]].proposal;
                let right = &validations[valid_indexes[right_index]].proposal;
                if proposal_owned_paths(left)
                    .intersection(&proposal_owned_paths(right))
                    .next()
                    .is_some()
                {
                    conflicted.insert(valid_indexes[left_index]);
                    conflicted.insert(valid_indexes[right_index]);
                }
            }
        }

        let password_indexes: Vec<usize> = validations
            .iter()
            .enumerate()
            .filter_map(|(index, validation)| {
                (validation.status == ProposalStatus::NeedsPassword).then_some(index)
            })
            .collect();
        let mut password_conflicted = HashSet::new();
        for left_index in 0..password_indexes.len() {
            for right_index in (left_index + 1)..password_indexes.len() {
                let left = &validations[password_indexes[left_index]].proposal;
                let right = &validations[password_indexes[right_index]].proposal;
                if proposal_owned_paths(left)
                    .intersection(&proposal_owned_paths(right))
                    .next()
                    .is_some()
                {
                    password_conflicted.insert(password_indexes[left_index]);
                    password_conflicted.insert(password_indexes[right_index]);
                }
            }
        }

        let mut claimed_paths = HashSet::new();
        let mut password_paths = HashSet::new();
        for (index, validation) in validations.iter().enumerate() {
            if validation.status != ProposalStatus::Valid || conflicted.contains(&index) {
                continue;
            }
            let owned = proposal_owned_paths(&validation.proposal);
            if owned.iter().any(|path| claimed_paths.contains(path)) {
                continue;
            }
            claimed_paths.extend(owned);
            output.push(validated_proposal_to_dict(py, validation)?);
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
            let owned = proposal_owned_paths(&validation.proposal);
            if owned.iter().any(|path| claimed_paths.contains(path)) {
                continue;
            }
            password_paths.extend(owned);
            output.push(password_error_proposal_to_dict(py, validation)?);
        }

        for row in directory_rows.iter().filter(|row| {
                let unresolved_encrypted_fragment = row
                    .anchor
                    .as_ref()
                    .is_some_and(|anchor| {
                        is_unresolved_encrypted_volume_fragment(
                            anchor,
                            name_index.candidates(row),
                        )
                    });
                filtered_keys.contains(&row.path.to_ascii_lowercase())
                && !claimed_paths.contains(&row.path.to_ascii_lowercase())
                && !password_paths.contains(&row.path.to_ascii_lowercase())
                && !attempted_password_paths.contains(&row.path.to_ascii_lowercase())
                && !strong_seed_paths.contains(&row.path.to_ascii_lowercase())
                && !unresolved_encrypted_fragment
        }) {
            output.push(ordinary_file_group_to_dict(py, row)?);
        }
    }
    Ok(output)
}

fn cheap_seed_strength(anchor: &VolumeAnchor) -> Option<&'static str> {
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

fn is_unresolved_encrypted_volume_fragment(
    anchor: &VolumeAnchor,
    parsed_names: &[ParsedVolume],
) -> bool {
    // A header-encrypted RAR volume with no standalone proof is not a
    // recoverable single-file archive. When the first volume is absent, or a
    // numbered member is missing, the filename proposal never reaches the
    // validator; allowing these rows to fall through as ordinary candidates
    // would submit every remaining fragment to extraction. Keep this gate
    // structural: weak filename-only encrypted hints remain ordinary.
    anchor.format == "rar"
        && anchor.confidence == "strong"
        && anchor.encrypted
        && (anchor.needs_password || anchor.wrong_password)
        && !anchor.standalone
        && parsed_names
            .iter()
            .any(|parsed| parsed.family == "rar" && parsed.number > 0)
}

fn name_interpretations_from_candidates(
    name: &str,
    parsed_candidates: &[ParsedVolume],
    target_format: &str,
    anchor: Option<&VolumeAnchor>,
) -> Vec<NameInterpretation> {
    let mut values = Vec::new();
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
            value.format == target_format
                || (value.format.is_empty() && value.sfx)
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
            let prefix = get_logical_name(name, false).to_ascii_lowercase();
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
    filtered_keys: &HashSet<String>,
    seed: &RelationInput,
    seed_interpretation: &NameInterpretation,
) -> Vec<RelationProposal> {
    if !seed_interpretation.format.is_empty() {
        return make_name_proposal(name_index, rows, filtered_keys, seed_interpretation)
            .into_iter()
            .collect();
    }

    // An MZ seed has no format fact at the 512-byte cheap boundary.  Use only
    // the same-family filename tokens on other physical rows to nominate a
    // bounded set of concrete formats.  The resulting proposal still goes
    // through exactly one format-specific deep validator.
    let mut formats = HashSet::new();
    for row in rows.iter().filter(|row| {
        row.relation_member_eligible
            && !row.path.eq_ignore_ascii_case(&seed.path)
    }) {
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
    if let Some(proposal) = make_name_proposal(name_index, rows, filtered_keys, &concrete) {
        return vec![proposal];
    }
    Vec::new()
}

fn has_filtered_family_trigger(
    name_index: &DirectoryNameIndex,
    rows: &[RelationInput],
    filtered_keys: &HashSet<String>,
    interpretation: &NameInterpretation,
) -> bool {
    rows.iter().any(|row| {
            filtered_keys.contains(&row.path.to_ascii_lowercase())
            && name_index
                .interpretations(row, &interpretation.format)
                .iter()
                .any(|candidate| {
                    candidate.format == interpretation.format
                        && candidate.prefix == interpretation.prefix
                })
    })
}

fn make_name_proposal(
    name_index: &DirectoryNameIndex,
    rows: &[RelationInput],
    filtered_keys: &HashSet<String>,
    seed_interpretation: &NameInterpretation,
) -> Option<RelationProposal> {
    let mut slots: HashMap<u32, Vec<(String, NameInterpretation)>> = HashMap::new();
    let mut companions = Vec::new();
    for row in rows.iter().filter(|row| row.relation_member_eligible) {
        let possible_launcher = row
            .anchor
            .as_ref()
            .is_some_and(is_possible_sfx_launcher);
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
        let interpretations = name_index.interpretations(
            row,
            &seed_interpretation.format,
        );
        let matching = interpretations
            .iter()
            .filter(|candidate| {
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
        for row in rows.iter().filter(|row| row.relation_member_eligible) {
            if !zip_terminal_name_matches(&row.name, &seed_interpretation.prefix) {
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
    if volumes.len() < 2 || !volumes.iter().any(|volume| volume.1 == 1) {
        return None;
    }
    let highest = volumes.iter().map(|volume| volume.1).max().unwrap_or(0);
    if (1..=highest).any(|number| !volumes.iter().any(|volume| volume.1 == number)) {
        return None;
    }
    let has_filtered_trigger = rows.iter().any(|row| {
            filtered_keys.contains(&row.path.to_ascii_lowercase())
                && name_index
                .interpretations(
                    row,
                    &seed_interpretation.format,
                )
                .iter()
                .any(|candidate| {
                    candidate.format == seed_interpretation.format
                        && candidate.prefix == seed_interpretation.prefix
                })
        });
    if !has_filtered_trigger {
        return None;
    }
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
    let weak_mz_seed = anchor
        .format
        .is_empty()
        && anchor.sfx
        && anchor
            .evidence
            .iter()
            .any(|item| *item == "sfx:pe_header");
    let cheap_embedded_archive = matches!(anchor.format.as_str(), "rar" | "7z" | "zip")
        && (anchor.sfx
            || anchor
                .evidence
                .iter()
                .any(|item| *item == "zip:embedded_local_head"))
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
        .chain(proposal.companions.iter().map(|path| path.to_ascii_lowercase()))
        .collect()
}

fn is_launcher_candidate(name: &str, logical_name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        && get_logical_name(name, false).eq_ignore_ascii_case(logical_name)
}

fn is_camouflaged_sfx_launcher(name: &str, logical_name: &str) -> bool {
    let Some(extension) = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
    else {
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
    let mut anchors: HashMap<String, VolumeAnchor> = rows
        .iter()
        .filter_map(|row| row.anchor.clone().map(|anchor| (row.path.to_ascii_lowercase(), anchor)))
        .collect();

    // A filename-matched `.exe` is only a companion hypothesis.  It may be
    // attached to a split relation after a deep probe proves that it is an
    // MZ/SFX carrier for this exact format.  Unverified name matches must not
    // become owned paths, otherwise an unrelated same-name executable could
    // be claimed and later cleaned with the archive.
    if !proposal.companions.is_empty() {
        let companion_candidates = proposal.companions.clone();
        let companion_anchors = py.detach(|| {
            probe_volume_anchor_paths_deep(
                &companion_candidates,
                1024 * 1024,
                65_557,
                path_passwords,
            )
        });
        let mut verified_companions = Vec::new();
        for anchor in companion_anchors {
            let embedded_verified = anchor.format == proposal.format
                && anchor.confidence == "strong"
                && anchor.sfx
                && anchor.structure_offset.is_some_and(|offset| offset > 0);
            anchors.insert(anchor.path.to_ascii_lowercase(), anchor.clone());
            if embedded_verified {
                verified_companions.push(anchor.path);
            }
        }
        verified_companions.sort_by_key(|path| path.to_ascii_lowercase());
        verified_companions.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        proposal.companions = verified_companions;
        if proposal.companions.len() > 1 {
            return Ok(ProposalValidation {
                status: ProposalStatus::Inconclusive,
                proposal,
                anchors,
            });
        }
    }

    let mut volume_paths: Vec<String> = proposal
        .volumes
        .iter()
        .map(|(path, _, _, _, _)| path.clone())
        .collect();
    volume_paths.sort_by_key(|path| path.to_ascii_lowercase());
    volume_paths.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let tail_limit = if proposal.format == "zip" { 65_557 } else { 0 };
    let deep_anchors = py.detach(|| {
        probe_volume_anchor_paths_deep(
            &volume_paths,
            1024 * 1024,
            tail_limit,
            path_passwords,
        )
    });
    for anchor in deep_anchors {
        anchors.insert(anchor.path.to_ascii_lowercase(), anchor);
    }

    let status = match proposal.format.as_str() {
        "rar" => validate_rar_proposal(py, &proposal, &anchors, path_passwords),
        "7z" => Ok(validate_seven_zip_proposal(&proposal, &anchors, rows)),
        "zip" => validate_zip_proposal(py, &proposal, &anchors),
        _ => Ok(ProposalStatus::Unsupported),
    }?;

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
        .is_some_and(|anchor| anchor.sfx && anchor.structure_offset.is_some_and(|offset| offset > 0))
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
    let password = proposal_password(proposal, path_passwords);
    let header_encrypted = proposal.volumes.iter().any(|(path, _, _, _, _)| {
        anchors
            .get(&path.to_ascii_lowercase())
            .is_some_and(|anchor| anchor.encrypted)
    });
    let terminal_proof = if header_encrypted {
        let Some(password) = password else {
            return Ok(ProposalStatus::NeedsPassword);
        };
        let proof_paths = if raw_sfx {
            ordered_paths.clone()
        } else {
            let Some((path, _, _, _, _)) = proposal.volumes.iter().max_by_key(|(_, number, _, _, _)| *number) else {
                return Ok(ProposalStatus::Inconclusive);
            };
            vec![path.clone()]
        };
        let proof_offset = if raw_sfx { raw_sfx_start_offset } else {
            anchors
                .get(&proof_paths[0].to_ascii_lowercase())
                .and_then(|anchor| anchor.structure_offset)
                .unwrap_or(0)
        };
        match py.detach(|| {
            probe_rar_terminal_with_password(&proof_paths, proof_offset, password, 4096)
        }) {
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
        let Some((path, _, _, _, _)) = proposal.volumes.iter().max_by_key(|(_, number, _, _, _)| *number) else {
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

fn proposal_password<'a>(
    proposal: &RelationProposal,
    path_passwords: Option<&'a [(String, String)]>,
) -> Option<&'a str> {
    let path_passwords = path_passwords?;
    path_passwords.iter().find_map(|(path, password)| {
        proposal
            .volumes
            .iter()
            .any(|(volume_path, _, _, _, _)| volume_path.eq_ignore_ascii_case(path))
            .then_some(password.as_str())
    })
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
    if first.format != "7z" || first.confidence != "strong" || !first.anchor_roles.contains(&"first") {
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
                .or_else(|| anchors.get(&path.to_ascii_lowercase()).map(|anchor| anchor.size))
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
    py: Python<'_>,
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
    let highest = proposal.volumes.iter().map(|(_, number, _, _, _)| *number).max().unwrap_or(0);
    if proposal.style == "zip_spanned" {
        // PKZIP multidisk files commonly begin with a local header and set
        // the continuation bit; other producers put the explicit split
        // marker before that local header.  Both are canonical zero-offset
        // native-spanning starts.  The terminal EOCD/disk proof below is
        // still mandatory.
        let first_is_spanned = first.evidence.iter().any(|item| *item == "zip:split_marker")
            || (first.evidence.iter().any(|item| *item == "zip:local_header")
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
        let first_is_raw = first.evidence.iter().any(|item| *item == "zip:local_header");
        let terminal_is_single_disk = terminal
            .evidence
            .iter()
            .any(|item| *item == "zip:eocd_single_disk_without_local_header");
        if !first_is_raw || !terminal_is_single_disk {
            return Ok(ProposalStatus::Inconclusive);
        }
    }

    // A raw `.zip.001` family is a logical concatenation, not a ZIP
    // multi-disk archive.  Re-run the canonical Rust ZIP view over the
    // concatenated volumes so the EOCD, central directory and every sampled
    // local-header link are proven against the same byte stream.  Spanned
    // ZIPs have their own disk-number proof above and intentionally remain on
    // that path because the strict single-disk ZIP view rejects multi-disk
    // EOCDs by design.
    if proposal.style != "zip_spanned" {
        let ordered_paths: Vec<String> = proposal
            .volumes
            .iter()
            .map(|(path, _, _, _, _)| path.clone())
            .collect();
        let Some(raw) = (match probe_zip_volume_paths(py, &ordered_paths, 4096) {
            Ok(result) => result,
            Err(_) => return Ok(ProposalStatus::Inconclusive),
        }) else {
            return Ok(ProposalStatus::Inconclusive);
        };
        let raw = raw.bind(py);
        let plausible = raw
            .get_item("plausible")?
            .and_then(|value| value.extract::<bool>().ok())
            .unwrap_or(false);
        let archive_starts_at_expected_offset = raw
            .get_item("archive_offset")?
            .and_then(|value| value.extract::<u64>().ok())
            .unwrap_or(u64::MAX)
            == first.structure_offset.unwrap_or(0);
        let central_directory_walk_ok = raw
            .get_item("central_directory_walk_ok")?
            .and_then(|value| value.extract::<bool>().ok())
            .unwrap_or(false);
        let local_header_links_ok = raw
            .get_item("local_header_links_ok")?
            .and_then(|value| value.extract::<bool>().ok())
            .unwrap_or(false);
        let error = raw
            .get_item("error")?
            .and_then(|value| value.extract::<String>().ok())
            .unwrap_or_default();
        if !plausible
            || !archive_starts_at_expected_offset
            || !central_directory_walk_ok
            || !local_header_links_ok
            || !error.is_empty()
        {
            return Ok(ProposalStatus::Inconclusive);
        }
    }
    Ok(ProposalStatus::Valid)
}

fn ordinary_file_group_to_dict(
    py: Python<'_>,
    row: &RelationInput,
) -> PyResult<Py<PyDict>> {
    let relation = FileRelationNative {
        filename: row.name.clone(),
        logical_name: get_logical_name(&row.name, false),
        split_role: None,
        is_split_member: false,
        has_generic_001_head: false,
        is_plain_numeric_member: false,
        has_split_companions: false,
        is_split_exe_companion: false,
        is_disguised_split_exe_companion: false,
        is_split_related: false,
        match_rar_disguised: false,
        match_rar_head: false,
        match_001_head: false,
        split_family: String::new(),
        split_index: 0,
    };
    let dict = PyDict::new(py);
    dict.set_item("head_path", &row.path)?;
    dict.set_item("head_name", &row.name)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, [&row.path])?)?;
    dict.set_item("is_split_candidate", false)?;
    dict.set_item("head_size", row.size)?;
    dict.set_item("split_volumes", PyList::empty(py))?;
    let head_metadata = row
        .anchor
        .as_ref()
        .filter(|anchor| anchor_has_relation_evidence(anchor))
        .map(|anchor| volume_anchor_to_dict(py, anchor))
        .transpose()?;
    dict.set_item("head_metadata", head_metadata)?;
    dict.set_item(
        "format_reject_mask",
        row.anchor.as_ref().map(|anchor| anchor.format_reject_mask).unwrap_or(0),
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
    let split_family = split_family_for_proposal(&proposal.format, &proposal.style);
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
    let carrier_size = (!carrier.is_empty()).then(|| {
        validation
            .anchors
            .get(&carrier.to_ascii_lowercase())
            .map(|anchor| anchor.size)
    }).flatten();
    let dict = PyDict::new(py);
    dict.set_item("head_path", head_path)?;
    dict.set_item("head_name", basename(head_path))?;
    dict.set_item("logical_name", &proposal.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", true)?;
    dict.set_item("head_size", head_anchor.map(|anchor| anchor.size))?;
    dict.set_item("split_volumes", PyList::new(py, &volume_dicts)?)?;
    dict.set_item(
        "head_metadata",
        head_anchor.map(|anchor| volume_anchor_to_dict(py, anchor)).transpose()?,
    )?;
    dict.set_item("companion_paths", &proposal.companions)?;
    dict.set_item("carrier_path", &carrier)?;
    dict.set_item("carrier_size", carrier_size)?;
    dict.set_item(
        "format_reject_mask",
        head_anchor.map(|anchor| anchor.format_reject_mask).unwrap_or(0),
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
    let split_family = split_family_for_proposal(&proposal.format, &proposal.style);
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
    let carrier_size = (!carrier.is_empty()).then(|| {
        validation
            .anchors
            .get(&carrier.to_ascii_lowercase())
            .map(|value| value.size)
    }).flatten();
    let dict = PyDict::new(py);
    dict.set_item("head_path", &head.0)?;
    dict.set_item("head_name", basename(&head.0))?;
    dict.set_item("logical_name", &proposal.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", true)?;
    dict.set_item("head_size", anchor.map(|value| value.size))?;
    dict.set_item("split_volumes", PyList::new(py, &volume_dicts)?)?;
    let mut metadata = anchor.map(|value| volume_anchor_to_dict(py, value)).transpose()?;
    if metadata.is_none() {
        metadata = Some(PyDict::new(py).unbind());
    }
    if let Some(metadata) = metadata.as_ref() {
        metadata.bind(py).set_item("needs_password", true)?;
        metadata.bind(py).set_item("proposal_paths", proposal_owned_paths(proposal))?;
        metadata.bind(py).set_item("password_scope", &proposal.logical_name)?;
    }
    dict.set_item("head_metadata", metadata)?;
    dict.set_item("companion_paths", &proposal.companions)?;
    dict.set_item("carrier_path", &carrier)?;
    dict.set_item("carrier_size", carrier_size)?;
    dict.set_item("format_reject_mask", anchor.map(|value| value.format_reject_mask).unwrap_or(0))?;
    Ok(dict.unbind())
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
                && zip_terminal_name_matches(path, &proposal.logical_name)
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
    let anchors = py.detach(|| {
        probe_volume_anchor_paths_cheap(&visible_paths, path_passwords.as_deref())
    });
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
    let groups = build_candidate_groups_from_physical(
        py,
        rows,
        &filtered_keys,
        path_passwords.as_deref(),
    )?;
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
            let metadata_format = group
                .bind(py)
                .get_item("head_metadata")?
                .and_then(|value| {
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
        if current_paths.iter().all(|current| {
            parts.iter().any(|part| part.eq_ignore_ascii_case(current))
        }) {
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

fn volume_anchor_to_dict(py: Python<'_>, anchor: &VolumeAnchor) -> PyResult<Py<PyDict>> {
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
    dict.set_item("evidence", PyList::new(py, &anchor.evidence)?)?;
    dict.set_item("error", &anchor.error)?;
    dict.set_item("bytes_read", anchor.bytes_read)?;
    Ok(dict.unbind())
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
    let name = rar_part_suffix_re().replace(filename, "").to_string();
    if name != filename {
        return clean_logical_name(&name);
    }

    let zero_zip = zip_zero_numbered_suffix_re().replace(&name, "").to_string();
    if zero_zip != name {
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

fn parse_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let (directory, filename) = split_relation_path(path);
    let mut parsed = parse_numbered_volume_name(filename)?;
    if !directory.is_empty() {
        parsed.prefix = format!("{directory}{}", parsed.prefix);
    }
    Some(parsed)
}

fn parse_relation_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let (directory, filename) = split_relation_path(path);
    let mut parsed = parse_volume_candidates(filename)
        .into_iter()
        .find(|candidate| {
            !candidate.decorated
                || (candidate.family == "rar"
                    && matches!(candidate.style, "rar_part" | "rar_sfx_part"))
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
    } else if let Some(parsed) = parse_loose_rar_part_volume(basename(path)) {
        keys.push(split_size_family_key("rar:part", &parsed.prefix));
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
        if let Some(parsed) = parse_loose_rar_part_volume(filename) {
            push_unique_volume_candidate(&mut candidates, parsed);
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
    let has_exe = tail
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
        decorated: !tail.eq_ignore_ascii_case(".rar")
            && !(number == 1 && tail.eq_ignore_ascii_case(".exe")),
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
                && noise.chars().all(|character| character.is_ascii_uppercase())
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
    let number = raw_number.parse().ok()?;
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

fn split_sort_key(path: &str) -> (u8, u32, String) {
    if let Some(parsed) = parse_numbered_volume(path) {
        return (0, parsed.number, path.to_ascii_lowercase());
    }
    let lower_name = basename(path).to_ascii_lowercase();
    if let Some(captures) = old_rar_member_re().captures(&lower_name) {
        if let Some(number) = captures
            .get(1)
            .and_then(|value| value.as_str().parse::<u32>().ok())
        {
            return (1, number + 2, path.to_ascii_lowercase());
        }
    }
    if lower_name.ends_with(".rar") {
        return (1, 1, path.to_ascii_lowercase());
    }
    (2, 0, path.to_ascii_lowercase())
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

fn rar_part_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.part\d+\.(?:rar|exe)(?:\.[^.]+)?$"))
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
        re(r"^(?P<prefix>.+)\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d{1,6})[^.]*\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_format_marker_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d{1,6})[^.]*(?:\.[^.]+)*$")
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

fn old_rar_member_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.r(\d{2})$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_filter_family_keys_join_numbered_7z_parts_and_exclude_other_prefixes() {
        let first = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.001");
        let tail = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.003");
        let other = relations_size_filter_split_family_keys(r"C:\downloads\other.7z.003");

        assert!(first.iter().any(|key| tail.contains(key)));
        assert!(!first.iter().any(|key| other.contains(key)));
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
    fn ordinary_prefix_substrings_do_not_become_format_evidence() {
        let parsed = parse_numbered_volume_name("example.part1.photo").unwrap();
        assert_eq!(parsed.style, "part_numbered");
        assert_eq!(parsed.family, "generic");
    }

}
