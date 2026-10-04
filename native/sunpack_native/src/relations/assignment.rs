use super::filename::{NameFeatures, NumberChannel};
use super::structural::{NumberingStyle, SfxRole, StructuralFacts, VolumeRole};
use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelationFailureReason {
    MissingVolume,
    AmbiguousVolumeMapping,
    StructuralConflict,
    NeedsPassword,
    CorruptArchive,
    Unsupported,
}

impl RelationFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingVolume => "missing_volume",
            Self::AmbiguousVolumeMapping => "ambiguous_volume_mapping",
            Self::StructuralConflict => "structural_conflict",
            Self::NeedsPassword => "needs_password",
            Self::CorruptArchive => "corrupt_archive",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct VolumeAssignment {
    pub slots: BTreeMap<u32, usize>,
    pub companions: Vec<usize>,
    pub unresolved: Vec<usize>,
}

struct BucketView<'a> {
    rows: &'a [RelationInput],
    indexes: Vec<usize>,
    facts: &'a HashMap<usize, StructuralFacts>,
    features: &'a HashMap<usize, NameFeatures>,
    format: &'a str,
    loose_numeric_allowed: bool,
}

impl BucketView<'_> {
    fn legal(&self, i: usize, n: u32, terminal: Option<u32>) -> bool {
        let f = &self.facts[&i];
        n > 0
            && (f.has_previous != Some(true) || n > 1)
            && (!matches!(f.role, VolumeRole::First | VolumeRole::FirstAndTerminal) || n == 1)
            && terminal.is_none_or(|end| {
                n <= end
                    && (f.has_next != Some(true) || n < end)
                    && (!matches!(f.role, VolumeRole::Terminal | VolumeRole::FirstAndTerminal)
                        || n == end)
            })
    }

    fn terminal(&self) -> Option<u32> {
        self.indexes
            .iter()
            .filter_map(|i| {
                let f = &self.facts[i];
                (f.has_next == Some(false))
                    .then_some(f.exact_slot)
                    .flatten()
            })
            .min()
    }

    fn terminal_for_assignment(&self, fixed: &VolumeAssignment) -> Option<u32> {
        fixed
            .slots
            .iter()
            .filter_map(|(&n, i)| (self.facts[i].has_next == Some(false)).then_some(n))
            .min()
            .or_else(|| self.terminal())
    }

    fn complete(&self, fixed: &VolumeAssignment) -> bool {
        !fixed.unresolved.iter().any(|i| self.facts[i].owned)
            && validate::assignment_status(
                self.format,
                self.spanned(),
                fixed
                    .slots
                    .iter()
                    .map(|(&n, &i)| (n, self.rows[i].anchor.as_ref())),
            ) == ProposalStatus::Valid
    }

    fn spanned(&self) -> bool {
        self.format == "zip"
            && self.indexes.iter().any(|i| {
                self.rows[*i].anchor.as_ref().is_some_and(|a| {
                    a.evidence.contains(&"zip:split_marker")
                        || a.evidence.contains(&"zip:eocd_split_terminal")
                })
            })
    }

    fn fixed(&self) -> Result<VolumeAssignment, RelationFailureReason> {
        let mut out = VolumeAssignment::default();
        let terminal = self.terminal();
        for &i in &self.indexes {
            let f = &self.facts[&i];
            if let Some(n) = f.exact_slot {
                if !self.legal(i, n, terminal) || out.slots.insert(n, i).is_some() {
                    return Err(RelationFailureReason::StructuralConflict);
                }
            } else {
                out.unresolved.push(i);
            }
        }
        // A finite terminal bound is essential. Never infer #2 simply because
        // #1 and one unknown file are present. Inspect sparse gaps, not 1..N.
        if out.unresolved.len() == 1 {
            if let Some(end) = terminal {
                if end as usize == out.slots.len() + 1 {
                    let mut next = 1u32;
                    for &n in out.slots.keys() {
                        if n == next {
                            next += 1;
                        } else {
                            break;
                        }
                    }
                    let i = out.unresolved[0];
                    if self.legal(i, next, terminal) {
                        out.slots.insert(next, i);
                        out.unresolved.clear();
                    }
                }
            }
        }
        Ok(out)
    }

    fn evaluate(
        &self,
        fixed: &VolumeAssignment,
        structural: &VolumeAssignment,
        channel: &NumberChannel,
        generic: bool,
    ) -> Option<VolumeAssignment> {
        let mut out = fixed.clone();
        out.unresolved.clear();
        let terminal = self.terminal_for_assignment(fixed);
        if generic {
            for (&n, &i) in &structural.slots {
                if let Some(features) = self.features.get(&i) {
                    // Unnumbered structural terminals do not nominate a
                    // channel; every numbered structural anchor constrains it.
                    if features.has_number_channel(self.format)
                        && channel.number(features, self.format) != Some(n)
                    {
                        return None;
                    }
                }
            }
        } else {
            for (&n, &i) in &fixed.slots {
                if let Some(value) = self
                    .features
                    .get(&i)
                    .and_then(|f| channel.number(f, self.format))
                {
                    if value != n {
                        return None;
                    }
                }
            }
        }
        let mut inferred = 0;
        for &i in &fixed.unresolved {
            let features = self.features.get(&i)?;
            match channel.number(features, self.format) {
                Some(n) if self.legal(i, n, terminal) => {
                    if out.slots.insert(n, i).is_some() {
                        return None;
                    }
                    inferred += 1;
                }
                _ => out.unresolved.push(i),
            }
        }
        // A channel that assigns nothing is not a successful hypothesis.
        (inferred > 0).then_some(out)
    }

    fn solve_loose_numeric(
        &self,
        fixed: &VolumeAssignment,
    ) -> Result<VolumeAssignment, RelationFailureReason> {
        if !self.loose_numeric_allowed || !fixed.slots.contains_key(&1) {
            return Err(RelationFailureReason::MissingVolume);
        }
        let terminal = self.terminal_for_assignment(fixed);
        // This is only a weak filename bound, never a new structural fact.
        // Missing huge slot numbers remain available in the stronger tiers.
        let maximum =
            terminal.unwrap_or_else(|| u32::try_from(self.indexes.len()).unwrap_or(u32::MAX));
        let mut domains = Vec::with_capacity(fixed.unresolved.len());
        for &i in &fixed.unresolved {
            let mut numbers = BTreeMap::<u32, usize>::new();
            if let Some(features) = self.features.get(&i) {
                for n in &features.numbers {
                    if n.value <= maximum
                        && !(self.format == "7z" && n.seven_zip_literal)
                        && !fixed.slots.contains_key(&n.value)
                        && self.legal(i, n.value, terminal)
                    {
                        numbers
                            .entry(n.value)
                            .and_modify(|width| *width = (*width).min(n.width))
                            .or_insert(n.width);
                    }
                }
            }
            domains.push(numeric::NumericDomain {
                row: i,
                required: self.facts[&i].owned,
                numbers: numbers.into_iter().collect(),
            });
        }
        let mut out = fixed.clone();
        numeric::solve(&mut out, domains)?;
        Ok(out)
    }

    fn solve(&self) -> (VolumeAssignment, Option<RelationFailureReason>) {
        let mut fixed = match self.fixed() {
            Ok(fixed) => fixed,
            Err(reason) => {
                // Preserve each physical member without inventing a slot for
                // conflicts. These paths become blocked relation candidates.
                return (
                    VolumeAssignment {
                        unresolved: self.indexes.clone(),
                        ..Default::default()
                    },
                    Some(reason),
                );
            }
        };
        if fixed.unresolved.is_empty() {
            return (fixed, None);
        }
        let structural = fixed.clone();
        let numbering_style = self
            .indexes
            .iter()
            .find_map(|i| self.facts[i].numbering_style);
        let mut canonical: HashSet<_> = self
            .indexes
            .iter()
            .flat_map(|i| self.features.get(i))
            .flat_map(|f| &f.canonical)
            .filter(|p| p.family == self.format)
            .filter(|p| {
                self.format != "rar"
                    || match numbering_style {
                        Some(NumberingStyle::RarOldStyle) => p.style == "rar_oldstyle",
                        Some(NumberingStyle::RarPart) => p.style != "rar_oldstyle",
                        None => true,
                    }
            })
            .map(|p| NumberChannel::Canonical {
                format: self.format.into(),
                // EXE identifies the carrier, not a competing numbering
                // scheme. Encrypted SFX heads and ordinary RAR parts share
                // one canonical mapping before Main Header decryption.
                style: if p.style == "rar_sfx_part" {
                    "rar_part"
                } else {
                    p.style
                }
                .into(),
                family: None,
            })
            .collect();
        if self.format == "rar"
            && self
                .indexes
                .iter()
                .any(|i| self.facts[i].numbering_style == Some(NumberingStyle::RarPart))
        {
            canonical.insert(NumberChannel::RarPart);
        }
        // Seed hypotheses from a numbered structural anchor, then constrain
        // each by every other anchor. K does not grow with bucket size.
        let seed = structural
            .slots
            .values()
            .chain(fixed.unresolved.iter())
            .find_map(|i| {
                self.features
                    .get(i)
                    .filter(|f| f.has_number_channel(self.format))
            });
        let tokens: HashSet<_> = seed
            .into_iter()
            .flat_map(|f| NumberChannel::tokens(f, self.format))
            .collect();
        for (channels, generic) in [(&canonical, false), (&tokens, true)] {
            let mut mapping: Option<VolumeAssignment> = None;
            for channel in channels {
                let Some(candidate) = self.evaluate(&fixed, &structural, channel, generic) else {
                    continue;
                };
                if mapping
                    .as_ref()
                    .is_some_and(|old| old.slots != candidate.slots)
                {
                    return (fixed, Some(RelationFailureReason::AmbiguousVolumeMapping));
                }
                mapping = Some(candidate);
            }
            if let Some(mapping) = mapping {
                fixed = mapping;
                if fixed.unresolved.is_empty() || self.complete(&fixed) {
                    fixed.unresolved.clear();
                    return (fixed, None);
                }
            }
        }
        // Exact RAR members do not need unrelated opaque same-stem files.
        if !fixed.slots.is_empty()
            && fixed.unresolved.iter().all(|i| !self.facts[i].owned)
            && self.format == "rar"
        {
            return (
                VolumeAssignment {
                    unresolved: Vec::new(),
                    ..fixed
                },
                None,
            );
        }
        match self.solve_loose_numeric(&fixed) {
            Ok(mapping) => (mapping, None),
            Err(reason) => (fixed, Some(reason)),
        }
    }
}

pub(super) fn resolve_buckets(
    rows: &[RelationInput],
    index: &BucketIndex,
    cached: Option<&RelationCache>,
) -> Vec<ProposalValidation> {
    let mut output = Vec::new();
    for (stem, bucket) in &index.rows_by_stem {
        let formats: HashSet<_> = bucket
            .iter()
            .filter_map(|i| rows[*i].anchor.as_ref())
            .filter(|a| !a.standalone && matches!(a.format.as_str(), "rar" | "zip" | "7z"))
            .map(|a| a.format.as_str())
            .collect();
        let mut features = HashMap::new();
        for format in ["rar", "zip", "7z"] {
            if !formats.contains(format) {
                continue;
            }
            let mut members = Vec::new();
            let mut companions = Vec::new();
            let mut facts = HashMap::new();
            for &i in bucket {
                let row = &rows[i];
                if !row.relation_member_eligible {
                    continue;
                }
                let f = StructuralFacts::from_row(row, format);
                if f.sfx_role == SfxRole::LauncherCompanion {
                    companions.push(i);
                    continue;
                }
                if row.anchor.as_ref().is_some_and(|a| {
                    a.standalone
                        || (!a.format.is_empty() && a.format != format)
                        || (a.sfx
                            && f.sfx_role != SfxRole::ArchiveBearingFirst
                            && !a.needs_password)
                }) {
                    continue;
                }
                if formats.len() > 1 && !f.owned {
                    let suffix = row.name.split_once('.').map_or("", |(_, s)| s);
                    if archive_family_hint(suffix) != Some(format) {
                        continue;
                    }
                }
                members.push(i);
                facts.insert(i, f);
            }
            // Encryption hides the Main Header. A lone encrypted file has no
            // split identity until the password reveals volume structure.
            if members.len() == 1
                && rows[members[0]].anchor.as_ref().is_some_and(|a| {
                    a.needs_password
                        && !a.multivolume
                        && !a.continuation_from_previous
                        && !a.continuation_to_next
                })
            {
                continue;
            }
            // A raw ZIP first chunk is proven only by an independent terminal
            // single-disk EOCD in this view, not by a local header alone.
            if format == "zip"
                && members.iter().any(|i| {
                    rows[*i].anchor.as_ref().is_some_and(|a| {
                        a.evidence
                            .contains(&"zip:eocd_single_disk_without_local_header")
                    })
                })
            {
                let heads: Vec<_> = members
                    .iter()
                    .copied()
                    .filter(|i| {
                        rows[*i]
                            .anchor
                            .as_ref()
                            .is_some_and(|a| a.evidence.contains(&"zip:local_header"))
                    })
                    .collect();
                if heads.len() == 1 {
                    facts.get_mut(&heads[0]).unwrap().exact_slot = Some(1);
                }
            }
            let heads = members
                .iter()
                .filter(|i| {
                    facts[i].exact_slot == Some(1)
                        || (format == "zip"
                            && facts[i].exact_slot.is_none()
                            && rows[**i]
                                .anchor
                                .as_ref()
                                .is_some_and(|a| a.evidence.contains(&"zip:local_header")))
                })
                .count();
            // RAR volumes have their own headers. Opaque unrelated files are
            // not required to complete an otherwise exact RAR assignment.
            if format == "rar"
                && members
                    .iter()
                    .filter(|i| facts[i].owned)
                    .all(|i| facts[i].exact_slot.is_some())
            {
                members.retain(|i| facts[i].owned);
            }
            let structural_only = BucketView {
                rows,
                indexes: members.clone(),
                facts: &facts,
                features: &features,
                format,
                loose_numeric_allowed: false,
            };
            let need_names = heads > 1
                || structural_only
                    .fixed()
                    .map_or(false, |a| !a.unresolved.is_empty());
            if need_names {
                for &i in &members {
                    features.entry(i).or_insert_with(|| {
                        cached
                            .and_then(|c| c.names.get(&rows[i].path_key))
                            .cloned()
                            .unwrap_or_else(|| NameFeatures::parse(&rows[i].name))
                    });
                }
            }
            // Multiple heads require a strong format-associated family name.
            // Unknown rows cannot be shared by competing archive families.
            let encrypted_heads: Vec<_> = members
                .iter()
                .copied()
                .filter(|i| {
                    rows[*i].anchor.as_ref().is_some_and(|a| a.needs_password)
                        && features.get(i).is_some_and(|f| {
                            f.canonical
                                .iter()
                                .any(|p| p.family == format && p.number == 1)
                        })
                })
                .collect();
            let head_indexes: HashSet<_> = members
                .iter()
                .copied()
                .filter(|i| {
                    facts[i].exact_slot == Some(1)
                        || (format == "zip"
                            && facts[i].exact_slot.is_none()
                            && rows[*i]
                                .anchor
                                .as_ref()
                                .is_some_and(|a| a.evidence.contains(&"zip:local_header")))
                })
                .chain(encrypted_heads)
                .collect();
            let mut competing_families = false;
            let families: Vec<(String, Vec<usize>)> = if head_indexes.len() > 1 {
                let head_families: HashSet<_> = head_indexes
                    .iter()
                    .filter_map(|i| features.get(i).and_then(|f| f.family(format)))
                    .collect();
                if head_families.len() == head_indexes.len() {
                    let mut grouped: HashMap<String, Vec<usize>> =
                        head_families.into_iter().map(|f| (f, Vec::new())).collect();
                    let mut orphan_owned = false;
                    for &i in &members {
                        if let Some(group) = features
                            .get(&i)
                            .and_then(|f| f.family(format))
                            .and_then(|family| grouped.get_mut(&family))
                        {
                            group.push(i);
                        } else if facts[&i].owned {
                            orphan_owned = true;
                        }
                    }
                    if orphan_owned {
                        competing_families = true;
                        vec![(stem.clone(), members.clone())]
                    } else {
                        grouped.into_iter().collect()
                    }
                } else {
                    competing_families = true;
                    vec![(stem.clone(), members.clone())]
                }
            } else {
                vec![(stem.clone(), members.clone())]
            };
            let mut launchers: HashMap<String, Vec<usize>> = HashMap::new();
            for i in companions {
                let a = rows[i].anchor.as_ref().unwrap();
                let profile_matches = match format {
                    "7z" => a.evidence.contains(&"sfx:seven_zip_stub"),
                    "zip" => {
                        a.evidence.contains(&"sfx:seven_zip_stub")
                            || a.evidence.contains(&"sfx:winrar_stub")
                    }
                    _ => false,
                };
                if profile_matches {
                    launchers
                        .entry(get_logical_name(&rows[i].name, false).to_ascii_lowercase())
                        .or_default()
                        .push(i);
                }
            }
            for (family, indexes) in families {
                // The display name may use canonical spelling even when every
                // slot was structural. This never participates in assignment.
                if let Some(i) = indexes.iter().find(|i| facts[i].exact_slot == Some(1)) {
                    features.entry(*i).or_insert_with(|| {
                        cached
                            .and_then(|c| c.names.get(&rows[*i].path_key))
                            .cloned()
                            .unwrap_or_else(|| NameFeatures::parse(&rows[*i].name))
                    });
                }
                if indexes.is_empty() {
                    continue;
                }
                let view = BucketView {
                    rows,
                    loose_numeric_allowed: !competing_families
                        && indexes.iter().filter(|i| head_indexes.contains(i)).count() == 1,
                    indexes,
                    facts: &facts,
                    features: &features,
                    format,
                };
                let (mut assignment, reason) = if competing_families {
                    (
                        VolumeAssignment {
                            unresolved: view.indexes.clone(),
                            ..Default::default()
                        },
                        Some(RelationFailureReason::AmbiguousVolumeMapping),
                    )
                } else {
                    view.solve()
                };
                let logical = if family == *stem {
                    assignment
                        .slots
                        .get(&1)
                        .and_then(|i| {
                            features
                                .get(i)
                                .map(|f| filename::logical_name(&rows[*i].name, f, format))
                        })
                        .unwrap_or_else(|| family.clone())
                } else {
                    family.clone()
                };
                if reason.is_none() {
                    if let Some(matching) = launchers
                        .get(&logical.to_ascii_lowercase())
                        .filter(|m| m.len() == 1)
                    {
                        assignment.companions = matching.clone();
                    }
                }
                output.extend(materialize(&view, assignment, &logical, reason));
            }
        }
    }
    output.sort_by(|a, b| {
        a.proposal
            .logical_name
            .cmp(&b.proposal.logical_name)
            .then(a.proposal.format.cmp(&b.proposal.format))
    });
    output
}

fn materialize(
    view: &BucketView<'_>,
    assignment: VolumeAssignment,
    logical: &str,
    reason: Option<RelationFailureReason>,
) -> Option<ProposalValidation> {
    let rows = view.rows;
    let spanned = view.spanned();
    let sfx = view.format == "rar"
        && assignment
            .slots
            .get(&1)
            .is_some_and(|i| view.facts[i].sfx_role == SfxRole::ArchiveBearingFirst);
    let old_rar = view.format == "rar"
        && view
            .indexes
            .iter()
            .any(|i| view.facts[i].numbering_style == Some(NumberingStyle::RarOldStyle));
    let style = if spanned {
        "zip_spanned"
    } else if sfx {
        "rar_sfx_part"
    } else if old_rar {
        "rar_oldstyle"
    } else if view.format == "rar" {
        "rar_part"
    } else {
        "numeric_suffix"
    };
    // Sibling names requested by the worker derive their padding from the
    // canonical head; physical filename widths need not agree.
    let family_width = if spanned || old_rar {
        2
    } else {
        assignment
            .slots
            .get(&1)
            .and_then(|i| view.features.get(i))
            .and_then(|f| f.numbers.iter().find(|n| n.value == 1))
            .map_or(3, |n| n.width)
    };
    let mut volumes: Vec<_> = assignment
        .slots
        .iter()
        .map(|(&n, &i)| {
            (
                rows[i].path.clone(),
                n,
                style.to_string(),
                family_width,
                false,
            )
        })
        .collect();
    let mut unresolved: Vec<_> = assignment
        .unresolved
        .iter()
        .filter(|i| view.facts[i].owned)
        .map(|i| rows[*i].path.clone())
        .collect();
    if volumes.is_empty() {
        // Output still needs an entry path. Slot zero explicitly denotes an
        // unresolved identity and is never handed to extraction.
        let i = *view.indexes.iter().find(|i| view.facts[i].owned)?;
        volumes.push((rows[i].path.clone(), 0, style.into(), 3, false));
        unresolved.retain(|p| p != &rows[i].path);
    }
    let anchors = view
        .indexes
        .iter()
        .chain(&assignment.companions)
        .filter_map(|i| {
            rows[*i]
                .anchor
                .clone()
                .map(|a| (rows[*i].path_key.clone(), a))
        })
        .collect();
    Some(ProposalValidation {
        status: ProposalStatus::Inconclusive,
        proposal: RelationProposal {
            format: view.format.into(),
            logical_name: logical.into(),
            style: style.into(),
            volumes,
            companions: assignment
                .companions
                .iter()
                .map(|i| rows[*i].path.clone())
                .collect(),
        },
        anchors,
        reason,
        unresolved,
        name_features: view
            .indexes
            .iter()
            .filter_map(|i| {
                view.features
                    .get(i)
                    .map(|f| (rows[*i].path_key.clone(), f.clone()))
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, format: &str, slot: Option<u32>, terminal: bool) -> RelationInput {
        RelationInput {
            path: name.into(),
            path_key: name.to_ascii_lowercase(),
            name: name.into(),
            size: Some(100),
            relation_member_eligible: true,
            anchor: Some(VolumeAnchor {
                path: name.into(),
                size: 100,
                format: format.into(),
                confidence: if format.is_empty() { "none" } else { "strong" }.into(),
                multivolume: !format.is_empty(),
                internal_volume_number: slot,
                relation_has_next: (!format.is_empty()).then_some(!terminal),
                anchor_roles: if terminal {
                    vec!["terminal"]
                } else if slot == Some(1) {
                    vec!["first"]
                } else {
                    vec!["member"]
                },
                evidence: match format {
                    "rar" => vec!["rar5:volume_header"],
                    "zip" if terminal => vec!["zip:eocd_split_terminal"],
                    "zip" => vec!["zip:split_marker"],
                    _ => vec![],
                },
                ..Default::default()
            }),
        }
    }

    fn resolve(rows: &[RelationInput]) -> Vec<ProposalValidation> {
        resolve_buckets(rows, &BucketIndex::build(rows, None), None)
    }

    fn slots(validation: &ProposalValidation) -> Vec<u32> {
        validation.proposal.volumes.iter().map(|p| p.1).collect()
    }

    #[test]
    fn fixed_structure_ignores_all_camouflaged_numbers() {
        let rows = vec![
            row("same.part99.chunk8", "rar", Some(1), false),
            row("same.part1.chunk7", "rar", Some(2), false),
            row("same.nothing", "rar", Some(3), true),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn repeated_seed_numbers_are_global_channels_not_a_seed_failure() {
        let rows = vec![
            row("same.build1.chunk1.bin", "7z", Some(1), false),
            row("same.build1.chunk002.bin", "", None, false),
            row("same.build1.chunk0003.bin", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn every_structural_anchor_constrains_the_channel() {
        let rows = vec![
            row("same.build1.chunk1", "zip", Some(1), false),
            row("same.build2.chunk2", "", None, false),
            row("same.build3.chunk3", "", None, false),
            row("same.build9.chunk4", "zip", Some(4), true),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3, 4]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn equivalent_channels_deduplicate_by_mapping() {
        let rows = vec![
            row("same.build1.chunk01", "7z", Some(1), false),
            row("same.build2.chunk002", "", None, false),
            row("same.build3.chunk0003", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn distinct_global_mappings_are_ambiguous() {
        let rows = vec![
            row("same.build1.chunk1", "7z", Some(1), false),
            row("same.build2.chunk3", "", None, false),
            row("same.build3.chunk2", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(
            groups[0].reason,
            Some(RelationFailureReason::AmbiguousVolumeMapping)
        );
        assert_eq!(slots(&groups[0]), vec![1]);
    }

    #[test]
    fn loose_numbers_ignore_context_and_ordinal_without_reparsing() {
        let rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.download002foo", "", None, false),
            row("same.zero0.blob0003bar", "", None, false),
            row("same.2024.txt", "", None, false),
            row("same.4294967295.txt", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
        assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
        assert_eq!(groups[0].proposal.volumes[2].0, rows[2].path);
        assert!(!validation_owned_paths(&groups[0]).contains(&rows[3].path));
        assert!(!validation_owned_paths(&groups[0]).contains(&rows[4].path));

        let cache = RelationCache {
            anchors: groups[0].anchors.clone(),
            names: groups[0].name_features.clone(),
        };
        let mut renamed = rows.clone();
        for row in &mut renamed[1..] {
            row.name = "same.no_digits".into();
        }
        let retried = resolve_buckets(&renamed, &BucketIndex::build(&renamed, None), Some(&cache));
        assert_eq!(retried[0].proposal.volumes, groups[0].proposal.volumes);
    }

    #[test]
    fn optional_numeric_slots_do_not_force_a_gap_with_same_stem_noise() {
        let mut rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.x2.y03", "", None, false),
            row("same.z3.w0004", "", None, false),
            row("same.notes", "", None, false),
        ];
        rows[0].anchor.as_mut().unwrap().expected_logical_size = Some(300);
        let mut groups = resolve(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reason, None);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
        assert_eq!(groups[0].proposal.volumes[2].0, rows[2].path);
        assert!(!validation_owned_paths(&groups[0]).contains(&rows[3].path));
        validate::validate(&mut groups[0]);
        assert_eq!(groups[0].status, ProposalStatus::Valid);
    }

    #[test]
    fn numeric_propagation_prevents_shortest_width_from_stealing_a_singleton() {
        let rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.x2.y03", "", None, false),
            row("same.alone02", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, None);
        assert_eq!(groups[0].proposal.volumes[1].0, rows[2].path);
        assert_eq!(groups[0].proposal.volumes[2].0, rows[1].path);
    }

    #[test]
    fn loose_width_arbitration_is_unique_or_ambiguous() {
        for tie in [false, true] {
            let rows = vec![
                row("same.header1", "7z", Some(1), false),
                row("same.a2", "", None, false),
                row(if tie { "same.b2" } else { "same.b002" }, "", None, false),
                row("same.c0002", "", None, false),
            ];
            let groups = resolve(&rows);
            if tie {
                assert_eq!(
                    groups[0].reason,
                    Some(RelationFailureReason::AmbiguousVolumeMapping)
                );
                assert_eq!(slots(&groups[0]), vec![1]);
            } else {
                assert_eq!(groups[0].reason, None);
                assert_eq!(slots(&groups[0]), vec![1, 2]);
                assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
            }
        }
    }

    #[test]
    fn canonical_and_stable_facts_are_monotonic_before_loose_numbers() {
        let rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.7z.002", "", None, false),
            row("same.header3", "", None, false),
            row("same.x2.y4", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, None);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3, 4]);
        for (i, volume) in groups[0].proposal.volumes.iter().enumerate() {
            assert_eq!(volume.0, rows[i].path);
        }
    }

    #[test]
    fn partial_canonical_ambiguity_does_not_fall_through_to_widths() {
        let rows = vec![
            row("same.header1", "zip", Some(1), false),
            row("same.part2.zip", "", None, false),
            row("same.zip.003", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(
            groups[0].reason,
            Some(RelationFailureReason::AmbiguousVolumeMapping)
        );
        assert_eq!(slots(&groups[0]), vec![1]);
    }

    #[test]
    fn encrypted_rar_sfx_and_plain_members_share_one_canonical_channel() {
        let mut rows = vec![
            row("same.part1.exe", "rar", None, false),
            row("same.part2.rar", "rar", None, false),
        ];
        for row in &mut rows {
            let anchor = row.anchor.as_mut().unwrap();
            anchor.needs_password = true;
            anchor.anchor_roles.clear();
            anchor.relation_has_next = None;
            anchor.evidence = vec!["rar5:encryption_header"];
        }
        let head = rows[0].anchor.as_mut().unwrap();
        head.sfx = true;
        head.pe_structure = true;
        head.structure_offset = Some(128);
        let mut groups = resolve(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reason, None);
        assert_eq!(slots(&groups[0]), vec![1, 2]);
        validate::validate(&mut groups[0]);
        assert_eq!(groups[0].status, ProposalStatus::NeedsPassword);
        assert!(validation_relation_confirmed(&groups[0]));
    }

    #[test]
    fn stable_ambiguity_keeps_canonical_facts_even_when_loose_widths_differ() {
        let rows = vec![
            row("same.build1.chunk1", "7z", Some(1), false),
            row("same.7z.002", "", None, false),
            row("same.build003.chunk4", "", None, false),
            row("same.build4.chunk0003", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(
            groups[0].reason,
            Some(RelationFailureReason::AmbiguousVolumeMapping)
        );
        assert_eq!(slots(&groups[0]), vec![1, 2]);
        assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
    }

    #[test]
    fn complete_stronger_mapping_does_not_claim_numeric_residual_noise() {
        let mut rows = vec![
            row("same.7z.001", "7z", Some(1), false),
            row("same.7z.002", "", None, false),
            row("same.x3", "", None, false),
            row("same.2024.txt", "", None, false),
        ];
        rows[0].anchor.as_mut().unwrap().expected_logical_size = Some(200);
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn loose_numbers_respect_format_roles_and_do_not_drop_owned_members() {
        let mut rows = vec![
            row("same.header1", "zip", Some(1), false),
            row("same.x2", "", None, false),
            row("same.y3", "", None, false),
            row("same.z0.a4.b7", "zip", Some(4), true),
            row("same.unassigned", "zip", None, false),
        ];
        rows[4].anchor.as_mut().unwrap().evidence.clear();
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
        assert!(validation_owned_paths(&groups[0]).contains(&rows[4].path));
    }

    #[test]
    fn weak_numeric_seven_zip_literal_and_zero_are_not_slots() {
        let mut rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.7z.blob0", "", None, false),
        ];
        // Put 7 inside the weak domain so this checks literal exclusion,
        // independently of the filename-bound filter.
        for suffix in ['a', 'b', 'c', 'd', 'e', 'f'] {
            rows.push(row(&format!("same.noise{suffix}"), "", None, false));
        }
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1]);
    }

    #[test]
    fn seven_zip_literal_is_a_legal_loose_number_for_other_formats() {
        let rows = vec![
            row("same.header1", "zip", Some(1), false),
            row("same.7z.blob0", "", None, false),
            row("same.end", "zip", Some(8), true),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 7, 8]);
    }

    #[test]
    fn duplicate_numeric_occurrences_collapse_to_one_file_slot_edge() {
        let rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.a002.b2.c03", "", None, false),
            row("same.d03", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, None);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
    }

    #[test]
    fn missing_head_cannot_enable_context_free_inference() {
        let rows = vec![
            row("same.end0", "zip", Some(4), true),
            row("same.x2", "", None, false),
            row("same.y3", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
        assert_eq!(slots(&groups[0]), vec![4]);
    }

    #[test]
    fn singleton_domain_requires_a_structural_terminal_bound() {
        let mut rows = vec![
            row("same.head", "rar", Some(1), false),
            row("same.unknown", "rar", None, false),
        ];
        assert_eq!(
            resolve(&rows)[0].reason,
            Some(RelationFailureReason::MissingVolume)
        );
        rows.push(row("same.end", "rar", Some(3), true));
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn seven_zip_literal_is_only_excluded_for_seven_zip() {
        let f = NameFeatures::parse("same.7z.chunk7");
        assert_eq!(NumberChannel::tokens(&f, "7z").count(), 1);
        assert_eq!(NumberChannel::tokens(&f, "zip").count(), 2);
        assert_eq!(NumberChannel::tokens(&f, "rar").count(), 2);
        assert_eq!(NameFeatures::parse("same.foo2bar.chunk2").numbers.len(), 2);
        assert_eq!(NameFeatures::parse("name2026.chunk2").numbers.len(), 1);
        assert_eq!(NameFeatures::parse("name2026").numbers.len(), 1);
    }

    #[test]
    fn bare_seven_zip_extension_does_not_constrain_a_member_number_channel() {
        let rows = vec![
            row("same.7z", "7z", Some(1), false),
            row("same.chunk2", "", None, false),
            row("same.chunk3", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
        assert_eq!(groups[0].reason, None);
    }

    #[test]
    fn ordinary_unrelated_rows_remain_residual() {
        let rows = vec![
            row("same.7z.001", "7z", Some(1), false),
            row("same.7z.002", "", None, false),
            row("same.notes", "", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2]);
        assert!(!validation_owned_paths(&groups[0]).contains("same.notes"));
    }

    #[test]
    fn structurally_owned_unknown_cannot_be_discarded() {
        let rows = vec![
            row("same.part1.rar", "rar", Some(1), false),
            row("same.unassigned", "rar", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
        assert!(validation_owned_paths(&groups[0]).contains("same.unassigned"));
    }

    #[test]
    fn competing_heads_need_distinct_canonical_families() {
        for canonical in [false, true] {
            let names = if canonical {
                [
                    "same.alpha.7z.001",
                    "same.alpha.7z.002",
                    "same.beta.7z.001",
                    "same.beta.7z.002",
                ]
            } else {
                [
                    "same.alpha.chunk1",
                    "same.alpha.chunk2",
                    "same.beta.chunk1",
                    "same.beta.chunk2",
                ]
            };
            let rows: Vec<_> = names
                .into_iter()
                .enumerate()
                .map(|(i, n)| {
                    row(
                        n,
                        if i % 2 == 0 { "7z" } else { "" },
                        (i % 2 == 0).then_some(1),
                        false,
                    )
                })
                .collect();
            let groups = resolve(&rows);
            if canonical {
                assert_eq!(groups.len(), 2);
                assert!(groups
                    .iter()
                    .all(|g| g.reason.is_none() && slots(g) == vec![1, 2]));
            } else {
                assert_eq!(
                    groups[0].reason,
                    Some(RelationFailureReason::AmbiguousVolumeMapping)
                );
            }
        }
    }

    #[test]
    fn lone_proven_split_member_stays_on_relation_path() {
        let rows = vec![row("same.part2.rar", "rar", Some(2), true)];
        let mut groups = resolve(&rows);
        validate::validate(&mut groups[0]);
        assert_eq!(slots(&groups[0]), vec![2]);
        assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
    }

    #[test]
    fn singleton_encrypted_rar_requires_split_structure() {
        let mut rows = vec![row("same.part1.rar", "rar", None, false)];
        let anchor = rows[0].anchor.as_mut().unwrap();
        anchor.multivolume = false;
        anchor.needs_password = true;
        anchor.relation_has_next = None;
        anchor.anchor_roles.clear();
        assert!(resolve(&rows).is_empty());
        rows[0].anchor.as_mut().unwrap().multivolume = true;
        assert_eq!(resolve(&rows).len(), 1);
    }

    #[test]
    fn family_partition_cannot_orphan_a_structural_member() {
        let rows = vec![
            row("same.alpha.7z.001", "7z", Some(1), false),
            row("same.alpha.7z.002", "", None, false),
            row("same.beta.7z.001", "7z", Some(1), false),
            row("same.beta.7z.002", "", None, false),
            row("same.unassigned", "7z", None, false),
        ];
        let groups = resolve(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].reason,
            Some(RelationFailureReason::AmbiguousVolumeMapping)
        );
        assert!(validation_owned_paths(&groups[0]).contains("same.unassigned"));
    }

    #[test]
    fn virtual_siblings_share_padding_despite_physical_widths() {
        let rows = vec![
            row("same.part1.rar", "rar", Some(1), false),
            row("same.part0002.rar", "rar", Some(2), true),
        ];
        let groups = resolve(&rows);
        assert_eq!(slots(&groups[0]), vec![1, 2]);
        assert!(groups[0].proposal.volumes.iter().all(|p| p.3 == 1));
    }

    #[test]
    fn retry_reuses_collected_filename_features() {
        let rows = vec![
            row("same.build1.chunk1", "7z", Some(1), false),
            row("same.build1.chunk002", "", None, false),
        ];
        let first = resolve(&rows);
        let cache = RelationCache {
            anchors: first[0].anchors.clone(),
            names: first[0].name_features.clone(),
        };
        let mut renamed = rows.clone();
        renamed[1].name = "same.no_numeric_channel".into();
        let retried = resolve_buckets(&renamed, &BucketIndex::build(&renamed, None), Some(&cache));
        assert_eq!(slots(&retried[0]), vec![1, 2]);
        assert_eq!(retried[0].reason, None);
    }

    #[test]
    fn launcher_ownership_respects_the_bucket_and_logical_family() {
        for name in ["same.exe", "same.unrelated.exe", "other.exe"] {
            let mut launcher = row(name, "", None, false);
            let anchor = launcher.anchor.as_mut().unwrap();
            anchor.sfx = true;
            anchor.pe_structure = true;
            anchor.evidence = vec!["sfx:seven_zip_stub"];
            let rows = vec![
                row("same.7z.001", "7z", Some(1), false),
                row("same.7z.002", "", None, false),
                launcher,
            ];
            let groups = resolve(&rows);
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups[0].proposal.companions.len(),
                usize::from(name == "same.exe")
            );
            assert_eq!(slots(&groups[0]), vec![1, 2]);
        }
    }

    #[test]
    fn huge_sparse_slots_do_not_enumerate_domains() {
        let rows = vec![
            row("same.head", "rar", Some(1), false),
            row("same.chunk2", "rar", None, false),
            row("same.tail", "rar", Some(u32::MAX), true),
        ];
        let mut groups = resolve(&rows);
        validate::validate(&mut groups[0]);
        assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
    }
}
