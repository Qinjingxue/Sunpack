use super::filename::{NameFeatures, NameProfile, NumberChannel};
use super::structural::{NumberingStyle, SfxRole, StructuralFacts};
use super::*;
#[cfg(test)]
use crate::analysis_native::volume_anchor::RAR_VERSION_5;
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

pub(super) struct BucketView<'a> {
    pub(super) rows: &'a [RelationInput],
    pub(super) indexes: &'a [usize],
    pub(super) facts: &'a HashMap<usize, StructuralFacts>,
    pub(super) features: &'a HashMap<usize, NameFeatures>,
    pub(super) format: &'static str,
    pub(super) loose_numeric_allowed: bool,
}

impl BucketView<'_> {
    pub(super) fn channel_offset(
        &self,
        head: Option<usize>,
        channel: &NumberChannel,
        profile: &NameProfile<'_>,
    ) -> i64 {
        if matches!(channel, NumberChannel::Token { .. })
            && matches!(self.format, "7z" | "zip")
            && !self.spanned()
        {
            head.and_then(|i| self.features.get(&i))
                .and_then(|f| profile.number(channel, f))
                .map_or(0, |n| 1 - i64::from(n))
        } else {
            0
        }
    }

    pub(super) fn legal(&self, i: usize, n: u32, terminal: Option<u32>) -> bool {
        let f = &self.facts[&i];
        n > 0
            && (!f.continues_from_previous || n > 1)
            && (!f.first || n == 1)
            && terminal.is_none_or(|end| {
                n <= end
                    && (f.has_next != Some(true) || n < end)
                    && (!f.terminal || n == end)
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
                    .map(|(&n, &i)| (n, self.rows[i].anchor.as_deref())),
            ) == ProposalStatus::Valid
    }

    pub(super) fn spanned(&self) -> bool {
        self.format == "zip"
            && self.indexes.iter().any(|i| {
                self.rows[*i].anchor.as_ref().is_some_and(|a| {
                    a.has_any(ZIP_SPLIT_START)
                        || a.has_any(ZIP_SPLIT_END)
                })
            })
    }

    fn fixed(&self) -> Result<VolumeAssignment, RelationFailureReason> {
        let mut out = VolumeAssignment::default();
        let terminal = self.terminal();
        for &i in self.indexes {
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

    fn mapping_roles_legal(&self, mapping: &VolumeAssignment) -> bool {
        let end = mapping
            .slots
            .iter()
            .filter_map(|(&n, i)| (self.facts[i].has_next == Some(false)).then_some(n))
            .min();
        mapping.slots.iter().all(|(&n, &i)| self.legal(i, n, end))
    }

    fn name_terminal(&self, profile: &NameProfile<'_>) -> Option<u32> {
        let mut terminal = None;
        for &i in self.indexes {
            if self.facts[&i].has_next != Some(false) {
                continue;
            }
            let mut numbers = self
                .features
                .get(&i)?
                .numbers
                .iter()
                .filter(|n| n.value > 0 && profile.active(n));
            let value = numbers.next()?.value;
            if numbers.any(|n| n.value != value) || terminal.is_some_and(|old| old != value) {
                return None;
            }
            terminal = Some(value);
        }
        terminal
    }

    /// Only raw chunks may use sparse filename labels as relative order.
    /// Internal RAR/ZIP identities remain fixed. Work on the sparse ordered map,
    /// never enumerate 1..largest_label or try permutations of bucket members.
    pub(super) fn finish_mapping(
        &self,
        mut mapping: VolumeAssignment,
        domain_slack: u64,
    ) -> Option<VolumeAssignment> {
        if !self.mapping_roles_legal(&mapping) {
            return None;
        }
        if self.complete(&mapping)
            || !(self.format == "7z" || (self.format == "zip" && !self.spanned()))
            || mapping.unresolved.iter().any(|i| self.facts[i].owned)
        {
            return Some(mapping);
        }
        if mapping
            .slots
            .keys()
            .copied()
            .zip(1u32..)
            .all(|(label, rank)| label == rank)
        {
            return Some(mapping);
        }
        let mut compact = BTreeMap::new();
        for (&i, rank) in mapping.slots.values().zip(1u32..) {
            if self.facts[&i].exact_slot.is_some_and(|slot| slot != rank) {
                return Some(mapping);
            }
            compact.insert(rank, i);
        }
        // A raw ZIP's directory offsets are logical, while its tail facts are
        // physical. Missing chunks must not become complete merely by renaming.
        if self.format == "zip" {
            let Some((&last, &i)) = compact.last_key_value() else {
                return Some(mapping);
            };
            let Some(tail) = self.rows[i].anchor.as_ref() else {
                return Some(mapping);
            };
            let Some(directory) = tail.zip_directory.as_ref() else {
                return Some(mapping);
            };
            let prefix = compact.range(..last).try_fold(0u64, |sum, (_, &i)| {
                let a = self.rows[i].anchor.as_ref()?;
                sum.checked_add(a.payload_size())
            });
            let logical_end = prefix.and_then(|prefix| {
                prefix.checked_add(
                    tail.zip_eocd_offset?
                        .checked_sub(tail.structure_offset.unwrap_or(0))?,
                )
            });
            if !directory
                .offset
                .checked_add(directory.size)
                .zip(logical_end)
                .is_some_and(|(end, available)| end <= available)
            {
                return Some(mapping);
            }
        }
        let labels = std::mem::replace(&mut mapping.slots, compact);
        // A domain representative uses maximum extents. A different choice
        // may close the byte count; keep that hypothesis without enumerating
        // combinations. Unique mappings have zero slack and retain exact checks.
        let possible_size = domain_slack > 0
            && self.format == "7z"
            && mapping
                .slots
                .get(&1)
                .and_then(|i| self.rows[*i].anchor.as_ref())
                .filter(|head| head.strong)
                .and_then(|head| {
                    head.expected_logical_size?
                        .checked_sub(head.structure_offset.unwrap_or(0))
                })
                .zip(mapping.slots.values().try_fold(0u64, |total, i| {
                    total.checked_add(self.rows[*i].anchor.as_ref()?.payload_size())
                }))
                .is_some_and(|(expected, maximum)| {
                    expected <= maximum && expected >= maximum.saturating_sub(domain_slack)
                });
        if !self.mapping_roles_legal(&mapping) || !(self.complete(&mapping) || possible_size) {
            mapping.slots = labels;
        }
        Some(mapping)
    }

    fn evaluate(
        &self,
        fixed: &VolumeAssignment,
        structural: &VolumeAssignment,
        channel: &NumberChannel,
        generic: bool,
        profile: &NameProfile<'_>,
    ) -> Option<VolumeAssignment> {
        // Raw chunks may be labelled from zero (or another origin). Only a
        // structurally proven head establishes the translation to logical #1;
        // RAR/spanned ZIP internal volume numbers retain their exact meaning.
        let offset = self.channel_offset(structural.slots.get(&1).copied(), channel, profile);
        let number = |features: &NameFeatures| profile.shifted_number(channel, features, offset);
        // Bound the candidate before inserting optional files. A terminal whose
        // slot is inferred by this channel still excludes same-channel noise.
        let terminal = self.terminal_for_assignment(fixed).or_else(|| {
            self.indexes
                .iter()
                .filter(|i| self.facts[i].has_next == Some(false))
                .filter_map(|i| self.features.get(i).and_then(number))
                .min()
        });
        if generic {
            for (&n, &i) in &structural.slots {
                if let Some(features) = self.features.get(&i) {
                    // Only matching fields constrain this channel. Other
                    // filename fields cannot override a structural identity.
                    if number(features).is_some_and(|value| value != n) {
                        return None;
                    }
                }
            }
        } else {
            for (&n, &i) in &fixed.slots {
                if let Some(value) = self.features.get(&i).and_then(number) {
                    if value != n {
                        return None;
                    }
                }
            }
        }
        let mut out = VolumeAssignment {
            slots: fixed.slots.clone(),
            companions: fixed.companions.clone(),
            unresolved: Vec::with_capacity(fixed.unresolved.len()),
        };
        let mut inferred = 0;
        for &i in &fixed.unresolved {
            let features = self.features.get(&i)?;
            match number(features) {
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
        if inferred == 0 {
            return None;
        }
        self.finish_mapping(out, 0)
    }

    fn solve_loose_numeric(
        &self,
        fixed: &VolumeAssignment,
        profile: &NameProfile<'_>,
    ) -> Result<VolumeAssignment, RelationFailureReason> {
        if !self.loose_numeric_allowed || !fixed.slots.contains_key(&1) {
            return Err(RelationFailureReason::MissingVolume);
        }
        let terminal = self
            .terminal_for_assignment(fixed)
            .or_else(|| self.name_terminal(profile));
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
                        && profile.active(n)
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
        if numeric::solve(&mut out, domains)? {
            return Err(RelationFailureReason::AmbiguousVolumeMapping);
        }
        self.finish_mapping(out, 0)
            .ok_or(RelationFailureReason::StructuralConflict)
    }

    pub(super) fn channels(
        &self,
        structural: &VolumeAssignment,
        profile: &NameProfile<'_>,
    ) -> (Vec<NumberChannel>, Vec<NumberChannel>) {
        let numbering_style = self
            .indexes
            .iter()
            .find_map(|i| self.facts[i].numbering_style);
        let mut canonical: std::collections::BTreeSet<_> = self
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
                format: self.format,
                // EXE identifies the carrier, not a competing numbering
                // scheme. Encrypted SFX heads and ordinary RAR parts share
                // one canonical mapping before Main Header decryption.
                style: if p.style == "rar_sfx_part" {
                    "rar_part"
                } else {
                    p.style
                },
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
            .iter()
            .find_map(|(&slot, i)| {
                self.features.get(i).filter(|f| {
                    f.numbers
                        .iter()
                        .any(|n| n.value == slot && profile.active(n))
                })
            })
            .or_else(|| {
                if !structural.slots.contains_key(&1) {
                    return None;
                }
                structural.unresolved.iter().find_map(|i| {
                    self.features
                        .get(i)
                        .filter(|f| f.numbers.iter().any(|n| n.value > 0 && profile.active(n)))
                })
            });
        let tokens: std::collections::BTreeSet<_> = seed
            .into_iter()
            .flat_map(|f| NumberChannel::tokens(f).filter(|c| profile.number(c, f).is_some()))
            .collect();
        (
            canonical.into_iter().collect(),
            tokens.into_iter().collect(),
        )
    }

    fn solve(
        &self,
        fixed: Result<VolumeAssignment, RelationFailureReason>,
    ) -> (VolumeAssignment, Option<RelationFailureReason>) {
        let mut fixed = match fixed {
            Ok(fixed) => fixed,
            Err(reason) => {
                // Preserve each physical member without inventing a slot for
                // conflicts. The attempt planner retains the competing slot domains.
                return (
                    VolumeAssignment {
                        unresolved: self.indexes.to_vec(),
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
        let profile = NameProfile::new(self.indexes.iter().filter_map(|i| self.features.get(i)));
        let (canonical, tokens) = self.channels(&structural, &profile);
        for (channels, generic) in [(&canonical, false), (&tokens, true)] {
            let mut mapping: Option<VolumeAssignment> = None;
            let mut complete = false;
            let mut ambiguous = false;
            for channel in channels {
                let Some(candidate) =
                    self.evaluate(&fixed, &structural, channel, generic, &profile)
                else {
                    continue;
                };
                let candidate_complete = self.complete(&candidate);
                if mapping.is_some() {
                    if complete && !candidate_complete {
                        continue;
                    }
                    if !complete && candidate_complete {
                        ambiguous = false;
                    } else if mapping
                        .as_ref()
                        .is_some_and(|old| old.slots != candidate.slots)
                    {
                        ambiguous = true;
                    }
                }
                complete = candidate_complete;
                mapping = Some(candidate);
            }
            if ambiguous {
                return (fixed, Some(RelationFailureReason::AmbiguousVolumeMapping));
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
        match self.solve_loose_numeric(&fixed, &profile) {
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
    const FORMATS: [&str; 3] = ["rar", "zip", "7z"];
    let mut output = Vec::new();
    for (stem, bucket) in &index.rows_by_stem {
        let mut present = [false; FORMATS.len()];
        for anchor in bucket
            .iter()
            .filter_map(|i| rows[*i].anchor.as_ref())
            .filter(|a| !a.standalone)
        {
            if let Some(index) = FORMATS.iter().position(|&format| format == anchor.format) {
                present[index] = true;
            }
        }
        let require_family_hint = present.iter().filter(|&&found| found).count() > 1 && {
            let mut physical_paths = HashSet::new();
            bucket.iter().all(|i| physical_paths.insert(rows[*i].path_key.as_str()))
        };
        let mut features = HashMap::new();
        for (format, found) in FORMATS.into_iter().zip(present) {
            if !found {
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
                if row.anchor.as_ref().is_some_and(|a| !a.error.is_empty()) {
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
                // Independent slices share a scope, not a filename family.
                // Opaque continuation disks remain candidates just as in each
                // head's original scope; known other formats were excluded above.
                if require_family_hint && !f.owned {
                    let suffix = row.name().split_once('.').map_or("", |(_, s)| s);
                    if archive_family_hint(suffix) != Some(format) {
                        continue;
                    }
                }
                members.push(i);
                facts.insert(i, f);
            }
            // Keep the same candidate partition before and after decryption.
            // RAR volumes carry their own headers; different encryption salts
            // must not compete for the same numbered slots after password retry.
            let mut partitions = HashMap::new();
            if format == "rar" && members.iter().any(|i|
                rows[*i].anchor.as_ref().is_some_and(|a| a.rar5_encryption.is_some()))
            {
                for i in std::mem::take(&mut members) {
                    let identity = rows[i].anchor.as_ref().and_then(|a| a.rar5_encryption.as_deref());
                    partitions.entry(identity).or_insert_with(Vec::new).push(i);
                }
            }
            for mut members in (!members.is_empty()).then_some(members).into_iter().chain(partitions.into_values()) {
                if members.len() > 1 && members.iter().all(|i| rows[*i].anchor.as_ref()
                    .is_some_and(|a| a.needs_password && !a.multivolume && a.rar5_encryption.is_some()))
                {
                    let mut paths = HashSet::new();
                    if members.iter().all(|i| paths.insert(rows[*i].path_key.as_str())) {
                        // A representative is not a proven first volume. Keep
                        // every role unknown and block execution until retry.
                        members.sort_unstable_by(|a, b| rows[*a].path_key.cmp(&rows[*b].path_key));
                        let view = BucketView { rows, indexes: &members, facts: &facts,
                            features: &features, format, loose_numeric_allowed: false };
                        output.push(ProposalValidation {
                            status: ProposalStatus::NeedsPassword,
                            proposal: RelationProposal {
                                format, logical_name: stem.clone(), style: "rar_part",
                                width: 3, volumes: members.iter().map(|i| (rows[*i].path.clone(), 0)).collect(),
                                companions: Vec::new(),
                            },
                            facts: proposal_facts(&view, &[]),
                            reason: Some(RelationFailureReason::NeedsPassword),
                            unresolved: Vec::new(), attempts: None,
                        });
                        continue;
                    }
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
                            a.has_any(ZIP_TAIL_WITHOUT_HEAD)
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
                                .is_some_and(|a| a.has_any(ZIP_LOCAL_HEADER))
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
                                    .is_some_and(|a| a.has_any(ZIP_LOCAL_HEADER)))
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
                // Several analyzed slices can occupy one physical carrier. The
                // unique-file assignment solver intentionally cannot express that;
                // feed the same full structural facts to the existing slot-domain
                // builder instead, before filename families can collapse a slice.
                let mut physical = HashSet::new();
                if members.iter().any(|i| !physical.insert(rows[*i].path_key.as_str())) {
                    for &i in &members {
                        features.entry(i).or_insert_with(|| cached
                            .and_then(|cache| cache.names.get(&rows[i].path_key)).cloned()
                            .unwrap_or_else(|| NameFeatures::parse(rows[i].name())));
                    }
                    let view = BucketView { rows, indexes: &members, facts: &facts,
                        features: &features, format, loose_numeric_allowed: true };
                    let candidates = attempts::build(&view, None);
                    if !candidates.is_empty() {
                        output.extend(candidates);
                        continue;
                    }
                }
                let mut initial_fixed = (heads <= 1).then(|| BucketView {
                    rows,
                    indexes: &members,
                    facts: &facts,
                    features: &features,
                    format,
                    loose_numeric_allowed: false,
                }.fixed());
                let need_names = !matches!(&initial_fixed, Some(Ok(a)) if a.unresolved.is_empty());
                if need_names {
                    for &i in &members {
                        features.entry(i).or_insert_with(|| {
                            cached
                                .and_then(|c| c.names.get(&rows[i].path_key))
                                .cloned()
                                .unwrap_or_else(|| NameFeatures::parse(rows[i].name()))
                        });
                    }
                }
                // Multiple heads require a strong format-associated family name.
                // Unknown rows cannot be shared by competing archive families.
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
                                    .is_some_and(|a| a.has_any(ZIP_LOCAL_HEADER)))
                    })
                    .collect();
                let mut competing_families = false;
                let mut families = None;
                if head_indexes.len() > 1 {
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
                        } else {
                            families = Some(grouped.into_iter().collect());
                        }
                    } else {
                        competing_families = true;
                    }
                }
                // A complete local set is independent even when another directory
                // has a gap. Only the remaining members may pair across directories.
                let mut local_assignments = HashMap::new();
                if competing_families {
                    let mut local: HashMap<String, Vec<usize>> = HashMap::new();
                    for &i in &members {
                        let parent = Path::new(&rows[i].path).parent().unwrap_or(Path::new(""));
                        local
                            .entry(path_key(&parent.to_string_lossy()))
                            .or_default()
                            .push(i);
                    }
                    if local.len() > 1 {
                        let mut complete = HashSet::new();
                        let mut local_families = Vec::new();
                        for indexes in local.into_values() {
                            let view = BucketView {
                                rows,
                                indexes: &indexes,
                                facts: &facts,
                                features: &features,
                                format,
                                loose_numeric_allowed: true,
                            };
                            let (assignment, reason) = view.solve(view.fixed());
                            if reason.is_none() && view.complete(&assignment) {
                                complete.extend(indexes.iter().copied());
                                local_assignments.insert(indexes[0], assignment);
                                local_families.push((stem.clone(), indexes));
                            }
                        }
                        if !complete.is_empty() {
                            let remaining: Vec<_> = members
                                .iter()
                                .copied()
                                .filter(|i| !complete.contains(i))
                                .collect();
                            competing_families = remaining
                                .iter()
                                .filter(|i| head_indexes.contains(i))
                                .count()
                                > 1;
                            if !remaining.is_empty() {
                                local_families.push((stem.clone(), remaining));
                            }
                            families = Some(local_families);
                        }
                    }
                }
                let local_sets = !local_assignments.is_empty();
                let mut launchers: HashMap<String, Vec<usize>> = HashMap::new();
                for &i in &companions {
                    let a = rows[i].anchor.as_ref().unwrap();
                    let profile_matches = match format {
                        "7z" => a.has_any(SEVEN_ZIP_STUB),
                        "zip" => {
                            a.has_any(SEVEN_ZIP_STUB)
                                || a.has_any(WINRAR_STUB)
                        }
                        _ => false,
                    };
                    if profile_matches {
                        launchers
                            .entry(case_key(&get_logical_name(rows[i].name(), false)))
                            .or_default()
                            .push(i);
                    }
                }
                for (family, indexes) in families.unwrap_or_else(|| vec![(stem.clone(), members)]) {
                    // The display name may use canonical spelling even when every
                    // slot was structural. This never participates in assignment.
                    if let Some(i) = indexes.iter().find(|i| facts[i].exact_slot == Some(1)) {
                        features.entry(*i).or_insert_with(|| {
                            cached
                                .and_then(|c| c.names.get(&rows[*i].path_key))
                                .cloned()
                                .unwrap_or_else(|| NameFeatures::parse(rows[*i].name()))
                        });
                    }
                    if indexes.is_empty() {
                        continue;
                    }
                    let view = BucketView {
                        rows,
                        loose_numeric_allowed: !competing_families
                            && indexes.iter().filter(|i| head_indexes.contains(i)).count() == 1,
                        indexes: &indexes,
                        facts: &facts,
                        features: &features,
                        format,
                    };
                    let (mut assignment, reason) =
                        if let Some(assignment) = local_assignments.remove(&view.indexes[0]) {
                            (assignment, None)
                        } else if competing_families {
                            (
                                VolumeAssignment {
                                    unresolved: view.indexes.to_vec(),
                                    ..Default::default()
                                },
                                Some(RelationFailureReason::AmbiguousVolumeMapping),
                            )
                        } else {
                            // A one-head view retains the original membership.
                            // Its fixed slots were already checked before names.
                            view.solve(initial_fixed.take().unwrap_or_else(|| view.fixed()))
                        };
                    let logical = if family == *stem {
                        assignment
                            .slots
                            .get(&1)
                            .and_then(|i| {
                                features
                                    .get(i)
                                    .map(|f| filename::logical_name(rows[*i].name(), f, format))
                            })
                            .unwrap_or_else(|| family.clone())
                    } else {
                        family.clone()
                    };
                    if reason.is_some() {
                        let candidates = attempts::build(&view, Some(&logical));
                        if !candidates.is_empty() {
                            output.extend(candidates);
                            continue;
                        }
                    }
                    if reason.is_none() {
                        if let Some(matching) = launchers.get(&case_key(&logical)) {
                            let matching: Vec<_> = matching
                                .iter()
                                .copied()
                                .filter(|i| {
                                    !local_sets
                                        || Path::new(&rows[*i].path).parent()
                                            == Path::new(&rows[view.indexes[0]].path).parent()
                                })
                                .collect();
                            if matching.len() == 1 {
                                assignment.companions = matching;
                            }
                        }
                    }
                    output.extend(materialize(&view, assignment, &logical, reason, None));
                }
            }
        }
    }
    output.sort_by(|a, b| {
        a.proposal
            .logical_name
            .cmp(&b.proposal.logical_name)
            .then(a.proposal.format.cmp(&b.proposal.format))
            .then(a.proposal.entry_path().cmp(b.proposal.entry_path()))
    });
    output
}

pub(super) fn materialize(
    view: &BucketView<'_>,
    assignment: VolumeAssignment,
    logical: &str,
    reason: Option<RelationFailureReason>,
    shared_facts: Option<&Arc<RelationCache>>,
) -> Option<ProposalValidation> {
    let rows = view.rows;
    if !assignment.slots.values().any(|i| {
        rows[*i].anchor.as_deref().is_some_and(VolumeAnchor::is_volume_entry)
    }) {
        return None;
    }
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
    let volumes: Vec<_> = assignment
        .slots
        .iter()
        .map(|(&n, &i)| (rows[i].path.clone(), n))
        .collect();
    let unresolved: Vec<_> = assignment
        .unresolved
        .iter()
        .filter(|i| view.facts[i].owned)
        .map(|i| rows[*i].path.clone())
        .collect();
    let facts = match shared_facts {
        Some(facts) => Arc::clone(facts),
        None => proposal_facts(view, &assignment.companions),
    };
    Some(ProposalValidation {
        attempts: None,
        status: ProposalStatus::Inconclusive,
        proposal: RelationProposal {
            format: view.format,
            logical_name: logical.into(),
            style,
            width: family_width,
            volumes,
            companions: assignment
                .companions
                .iter()
                .map(|i| rows[*i].path.clone())
                .collect(),
        },
        facts,
        reason,
        unresolved,
    })
}

pub(super) fn proposal_facts(view: &BucketView<'_>, companions: &[usize]) -> Arc<RelationCache> {
    let rows = view.rows;
    Arc::new(RelationCache {
        anchors: view
            .indexes
            .iter()
            .chain(companions)
            .filter_map(|i| {
                rows[*i]
                    .anchor
                    .clone()
                    .map(|a| (rows[*i].path_key.clone(), a))
            })
            .collect(),
        names: view
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
#[path = "../../tests/unit/relations/assignment/tests.rs"]
mod tests;
