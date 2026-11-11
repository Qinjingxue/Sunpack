//! Sparse, ordered hypotheses. Only slot domains cross the execution boundary;
//! their Cartesian product is never allocated or probed during discovery.
use super::assignment::{materialize, proposal_facts, BucketView, VolumeAssignment};
use super::filename::NameProfile;
use super::*;
use crate::io::archive_state::{
    TailTotal, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot,
};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(super) struct VolumeAttempts {
    pub sources: Vec<AttemptSource>,
    // Initial sources are in group path order, one per physical file. Carrier
    // variants append ranges for those same paths without adding group members.
    base_source_count: usize,
    pub layouts: Vec<Vec<(u32, Arc<Vec<usize>>)>>,
    // One maximum prefix and terminal domain represent every admitted length.
    // Zero denotes an ordinary fixed layout.
    pub minimum_slots: Vec<usize>,
    pub head_size_from_total: Option<u64>,
    pub minimum_size: Option<u64>,
    pub tail_totals: Vec<(usize, u64)>,
}

impl VolumeAttempts {
    pub(super) fn base_sources(&self) -> &[AttemptSource] {
        &self.sources[..self.base_source_count]
    }

    // PKZIP disk offsets are relative to each disk, not to the concatenated
    // archive. Reuse the unique mapping's geometry and represent each possible
    // common disk size with ordinary range/domain layouts (no second protocol).
    fn with_spanned_carrier(mut self, head: &VolumeAnchor) -> Self {
        if !head.has_unresolved_carrier_extent() {
            return self;
        }
        let mut domains = Domains::default();
        let mut heads = HashMap::new();
        let mut filtered = HashMap::new();
        for (layout, minimum) in std::mem::take(&mut self.layouts)
            .into_iter()
            .zip(std::mem::take(&mut self.minimum_slots))
        {
            let mut interiors = HashMap::new();
            let mut sizes = None::<HashSet<u64>>;
            for (_, choices) in layout.iter().skip(1) {
                let domain = Arc::as_ptr(choices);
                let std::collections::hash_map::Entry::Vacant(entry) = interiors.entry(domain)
                else {
                    continue;
                };
                let interior = !choices.iter().any(|i| self.sources[*i].terminal);
                entry.insert(interior);
                if !interior {
                    continue;
                }
                let available: HashSet<_> = choices
                    .iter()
                    .map(|i| self.sources[*i].end - self.sources[*i].start)
                    .collect();
                if let Some(sizes) = &mut sizes {
                    sizes.retain(|size| available.contains(size));
                    if sizes.is_empty() {
                        break;
                    }
                } else {
                    sizes = Some(available);
                }
            }
            let from_tail = sizes.is_none();
            let mut sizes: Vec<_> = sizes
                .unwrap_or_else(|| {
                    layout
                        .last()
                        .into_iter()
                        .flat_map(|(_, choices)| choices.iter())
                        .filter_map(|i| self.sources[*i].head_size)
                        .collect()
                })
                .into_iter()
                .collect();
            sizes.sort_unstable();
            for size in sizes {
                let Some(end) = validate::spanned_carrier_end(head, std::iter::once(size)) else {
                    continue;
                };
                let mut trimmed = Vec::with_capacity(layout.len());
                for (number, choices) in &layout {
                    let domain = if *number == 1 {
                        let mut replacements = Vec::new();
                        for &i in choices.iter() {
                            if end > self.sources[i].end {
                                continue;
                            }
                            let index = *heads.entry((i, end)).or_insert_with(|| {
                                let mut source = self.sources[i].clone();
                                source.end = end;
                                if let Some(index) =
                                    self.sources.iter().position(|old| *old == source)
                                {
                                    return index;
                                }
                                self.sources.push(source);
                                self.sources.len() - 1
                            });
                            replacements.push(index);
                        }
                        domains.intern(replacements)
                    } else if interiors[&Arc::as_ptr(choices)] || from_tail {
                        let interior = interiors[&Arc::as_ptr(choices)];
                        let (_, domain) = filtered
                            .entry((Arc::as_ptr(choices), size))
                            .or_insert_with(|| {
                                (
                                    Arc::clone(choices),
                                    domains.intern(
                                        choices
                                            .iter()
                                            .copied()
                                            .filter(|i| {
                                                let source = &self.sources[*i];
                                                if interior {
                                                    source.end - source.start == size
                                                } else {
                                                    source.head_size == Some(size)
                                                }
                                            })
                                            .collect(),
                                    ),
                                )
                            });
                        Arc::clone(domain)
                    } else {
                        Arc::clone(choices)
                    };
                    trimmed.push((*number, domain));
                }
                if trimmed.iter().all(|(_, choices)| !choices.is_empty())
                    && !self.layouts.contains(&trimmed)
                {
                    self.layouts.push(trimmed);
                    self.minimum_slots.push(minimum);
                }
            }
            // Equal disk size is a geometry hypothesis, not format identity.
            // Retain the original for nonuniform disks and unpadded carriers.
            if !self.layouts.contains(&layout) {
                self.layouts.push(layout);
                self.minimum_slots.push(minimum);
            }
        }
        self
    }
}

pub(super) fn resolve_carrier_geometry(validation: &mut ProposalValidation) {
    if validation.proposal.style != "zip_spanned" {
        return;
    }
    if let Some(plan) = validation.attempts.take() {
        let head = &validation.facts.anchors[&path_key(&validation.proposal.volumes[0].0)];
        validation.attempts = Some(plan.with_spanned_carrier(head));
    }
}

// Request/proposal-local interning; order is part of domain identity.
#[derive(Default)]
struct Domains(HashSet<Arc<Vec<usize>>>);
impl Domains {
    fn intern(&mut self, choices: Vec<usize>) -> Arc<Vec<usize>> {
        if let Some(existing) = self.0.get(&choices) {
            return Arc::clone(existing);
        }
        let choices = Arc::new(choices);
        self.0.insert(Arc::clone(&choices));
        choices
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AttemptSource {
    pub path: String,
    pub start: u64,
    pub end: u64,
    pub proven_end: Option<u64>,
    pub terminal: bool,
    pub head_size: Option<u64>,
}
impl AttemptSource {
    fn new(path: &str, anchor: &VolumeAnchor) -> Self {
        Self {
            path: path.into(),
            start: anchor.structure_offset.unwrap_or(0),
            end: anchor
                .carrier_limit
                .map_or(anchor.extent_end(), |limit| limit.min(anchor.extent_end())),
            proven_end: anchor.proven_extent_end(),
            terminal: anchor.anchor_roles.contains(&"terminal"),
            head_size: anchor.zip_head_size,
        }
    }
}

fn zip_total(anchor: &VolumeAnchor) -> Option<u64> {
    let directory = anchor.zip_directory.as_ref()?;
    directory
        .offset
        .checked_add(directory.size)?
        .checked_add(anchor.extent_end().checked_sub(directory.end)?)
}

fn head_geometry(head: &VolumeAnchor, format: &str) -> (Option<u64>, Option<u64>, bool) {
    let trim = head.has_unresolved_carrier_extent();
    let minimum = (format == "7z")
        .then(|| {
            head.expected_logical_size
                .and_then(|end| end.checked_sub(head.structure_offset.unwrap_or(0)))
        })
        .flatten();
    (minimum.filter(|_| trim), minimum, trim)
}

pub(super) fn from_validation(validation: &ProposalValidation) -> VolumeAttempts {
    let proposal = &validation.proposal;
    let head = &validation.facts.anchors[&path_key(&proposal.volumes[0].0)];
    let (head_size_from_total, minimum_size, trim) = head_geometry(head, &proposal.format);
    VolumeAttempts {
        base_source_count: proposal.volumes.len(),
        sources: proposal
            .volumes
            .iter()
            .map(|part| AttemptSource::new(&part.0, &validation.facts.anchors[&path_key(&part.0)]))
            .collect(),
        layouts: vec![proposal
            .volumes
            .iter()
            .enumerate()
            .map(|(i, part)| (part.1, Arc::new(vec![i])))
            .collect()],
        minimum_slots: vec![0],
        head_size_from_total,
        minimum_size,
        tail_totals: if trim && proposal.format == "zip" && proposal.style != "zip_spanned" {
            proposal
                .volumes
                .iter()
                .enumerate()
                .filter_map(|(index, part)| {
                    zip_total(&validation.facts.anchors[&path_key(&part.0)])
                        .map(|total| (index, total))
                })
                .collect()
        } else {
            Vec::new()
        },
    }
}

// Carrier discovery has already analyzed every slice. Expand only compatible
// alternatives at the same proven slot; no new scan or path-only alias model.
pub(super) fn expand_carrier_sources(
    validation: &mut ProposalValidation,
    by_path: &HashMap<String, Vec<&VolumeAnchor>>,
) {
    let head = validation
        .proposal
        .volumes
        .iter()
        .find(|part| part.1 == 1)
        .map(|p| path_key(&p.0));
    let Some(head) = head else {
        return;
    };
    let had_plan = validation.attempts.is_some();
    if !had_plan
        && !validation.proposal.volumes.iter().any(|p| {
            path_key(&p.0) != head
                && by_path
                    .get(&path_key(&p.0))
                    .is_some_and(|options| options.len() > 1)
        })
    {
        return;
    }
    let mut plan = validation
        .attempts
        .take()
        .unwrap_or_else(|| from_validation(validation));
    let original_count = plan.sources.len();
    let mut expanded = HashMap::new();
    for i in 0..original_count {
        let source = &plan.sources[i];
        let key = path_key(&source.path);
        if key == head {
            continue;
        }
        let Some(options) = by_path.get(&key) else {
            continue;
        };
        let anchor = &validation.facts.anchors[&key];
        let replacements: Vec<_> = options
            .iter()
            .filter(|a| {
                a.format == validation.proposal.format
                    && a.internal_volume_number == anchor.internal_volume_number
                    && a.anchor_roles.contains(&"terminal") == source.terminal
                    && a.structure_offset.unwrap_or(0) != source.start
                    && a.internal_volume_number != Some(1)
            })
            .map(|a| (AttemptSource::new(&source.path, a), zip_total(a)))
            .collect();
        if !replacements.is_empty() {
            let mut choices = vec![i];
            for (source, total) in replacements {
                let index = plan
                    .sources
                    .iter()
                    .position(|old| *old == source)
                    .unwrap_or_else(|| {
                        plan.sources.push(source);
                        plan.sources.len() - 1
                    });
                if !plan.tail_totals.is_empty()
                    && !plan.tail_totals.iter().any(|(i, _)| *i == index)
                {
                    if let Some(total) = total {
                        plan.tail_totals.push((index, total));
                    }
                }
                if !choices.contains(&index) {
                    choices.push(index);
                }
            }
            expanded.insert(i, choices);
        }
    }
    if !expanded.is_empty() {
        let mut domains = Domains::default();
        let mut replacements = HashMap::new();
        for layout in &mut plan.layouts {
            for (_, choices) in layout {
                // Retain the key's allocation while replacing its last slot.
                // Otherwise the allocator can reuse its address for a new domain.
                let (_, replacement) =
                    replacements.entry(Arc::as_ptr(choices)).or_insert_with(|| {
                        (
                            Arc::clone(choices),
                            domains.intern(
                                choices
                                    .iter()
                                    .flat_map(|i| {
                                        expanded
                                            .get(i)
                                            .map_or(std::slice::from_ref(i), Vec::as_slice)
                                            .iter()
                                            .copied()
                                    })
                                    .collect(),
                            ),
                        )
                    });
                *choices = Arc::clone(replacement);
            }
        }
        validation.status = ProposalStatus::Valid;
        validation.reason = None;
        validation.attempts = Some(plan);
    } else if had_plan {
        // Preserve an existing plan, including singleton domains.
        validation.attempts = Some(plan);
    }
}

pub(super) fn build(view: &BucketView<'_>, logical: &str) -> Vec<ProposalValidation> {
    let spanned = view.spanned();
    let mut heads: Vec<_> = view
        .indexes
        .iter()
        .copied()
        .filter(|i| view.facts[i].exact_slot == Some(1))
        .collect();
    heads.sort_by(|a, b| view.rows[*a].path_key.cmp(&view.rows[*b].path_key));
    let mut output = Vec::new();
    let mut shared_facts = None;
    for head in heads {
        let indexes: Vec<_> = view
            .indexes
            .iter()
            .copied()
            .filter(|i| *i == head || view.facts[i].exact_slot != Some(1))
            .collect();
        let profile = NameProfile::new(indexes.iter().filter_map(|i| view.features.get(i)));
        let mut fixed = BTreeMap::<u32, Vec<usize>>::new();
        for &i in &indexes {
            if let Some(n) = view.facts[&i].exact_slot {
                if view.legal(i, n, None) {
                    fixed.entry(n).or_default().push(i);
                }
            }
        }
        if !fixed.contains_key(&1) {
            continue;
        }
        let structural = VolumeAssignment {
            slots: fixed.iter().map(|(&n, choices)| (n, choices[0])).collect(),
            unresolved: indexes
                .iter()
                .copied()
                .filter(|i| view.facts[i].exact_slot.is_none())
                .collect(),
            ..Default::default()
        };
        let local = BucketView {
            rows: view.rows,
            indexes: &indexes,
            facts: view.facts,
            features: view.features,
            format: view.format,
            loose_numeric_allowed: true,
        };
        let (canonical, tokens) = local.channels(&structural, &profile);
        let channels: Vec<_> = canonical.into_iter().chain(tokens).collect();
        let mut layouts = Vec::new();
        let mut domains = Domains::default();
        for channel in channels.iter().map(Some).chain(std::iter::once(None)) {
            let offset = channel.map_or(0, |c| view.channel_offset(Some(head), c, &profile));
            // Reuse one channel projection for both terminal bounds and slot
            // domains. The loose tier must obey the same structural end roles.
            let numbers: HashMap<_, Vec<u32>> = indexes
                .iter()
                .map(|&i| {
                    let values = if let Some(n) = view.facts[&i].exact_slot {
                        vec![n]
                    } else if let Some(f) = view.features.get(&i) {
                        if let Some(channel) = channel {
                            profile
                                .shifted_number(channel, f, offset)
                                .into_iter()
                                .collect()
                        } else {
                            f.numbers
                                .iter()
                                .filter(|n| {
                                    profile.active(n)
                                        && n.value > 0
                                        && n.value as usize <= indexes.len()
                                })
                                .map(|n| n.value)
                                .collect()
                        }
                    } else {
                        Vec::new()
                    };
                    (i, values)
                })
                .collect();
            let unnamed_tail = indexes
                .iter()
                .any(|i| view.facts[i].has_next == Some(false) && numbers[i].is_empty());
            let lower = indexes
                .iter()
                .filter(|i| view.facts[i].has_next != Some(false))
                .flat_map(|i| numbers[i].iter().copied())
                .max()
                .unwrap_or(1)
                .checked_add(1);
            let upper = u32::try_from(
                indexes
                    .iter()
                    .filter(|i| view.facts[i].has_next != Some(false))
                    .count(),
            )
            .ok()
            .and_then(|n| n.checked_add(1));
            // Unnumbered same-stem members may be unrelated. Their count bounds
            // the end; it never proves that all of them must be consumed.
            let variable = unnamed_tail
                && !spanned
                && matches!(view.format, "7z" | "zip")
                && lower.zip(upper).is_some_and(|(lo, hi)| lo < hi);
            let inferred_end = unnamed_tail
                .then_some(if variable {
                    upper
                } else {
                    lower.map(|lo| if lo == 2 { upper.unwrap_or(lo) } else { lo })
                })
                .flatten();
            let mut terminals: Vec<_> = indexes
                .iter()
                .filter(|i| view.facts[i].has_next == Some(false))
                .flat_map(|i| numbers[i].iter().copied())
                .chain(inferred_end)
                .filter(|n| *n > 1)
                .map(Some)
                .collect();
            terminals.sort_unstable();
            terminals.dedup();
            if terminals.is_empty() {
                terminals.push(None);
            }
            let width_numbers: HashSet<_> = if channel.is_none() {
                indexes
                    .iter()
                    .filter_map(|i| view.features.get(i))
                    .flat_map(|f| f.numbers.iter())
                    .filter(|n| profile.active(n))
                    .map(|n| n.value)
                    .collect()
            } else {
                HashSet::new()
            };
            let head_parent = Path::new(&view.rows[head].path).parent();
            for candidate_terminal in terminals {
                let mut slots: BTreeMap<_, _> = fixed
                    .iter()
                    .filter_map(|(&n, choices)| {
                        let choices: Vec<_> = choices
                            .iter()
                            .copied()
                            .filter(|i| view.legal(*i, n, candidate_terminal))
                            .collect();
                        (!choices.is_empty()).then(|| (n, Arc::new(choices)))
                    })
                    .collect();
                let fixed_numbers: HashSet<_> = slots.keys().copied().collect();
                for &i in &indexes {
                    if view.facts[&i].exact_slot.is_some() {
                        continue;
                    }
                    let unnamed_terminal = (view.facts[&i].has_next == Some(false)
                        && numbers[&i].is_empty())
                    .then_some(candidate_terminal)
                    .flatten();
                    for n in numbers[&i].iter().copied().chain(unnamed_terminal) {
                        if view.legal(i, n, candidate_terminal) && !fixed_numbers.contains(&n) {
                            Arc::make_mut(slots.entry(n).or_default()).push(i);
                        }
                    }
                }
                // Fill a finite, evidence-bounded gap from otherwise unnumbered
                // members. Never allocate up to a huge filename/terminal number.
                let bound = candidate_terminal.or_else(|| slots.last_key_value().map(|(&n, _)| n));
                if let Some(end) = bound.filter(|end| *end as usize <= indexes.len()) {
                    let assigned: HashSet<_> =
                        slots.values().flat_map(|c| c.iter()).copied().collect();
                    let mut gaps = HashMap::new();
                    for n in 1..=end {
                        if !slots.contains_key(&n) {
                            // legal() only distinguishes first/interior/terminal
                            // positions. Share otherwise unnumbered gap members.
                            let choices = gaps.entry((n == 1, n == end)).or_insert_with(|| {
                                Arc::new(
                                    indexes
                                        .iter()
                                        .copied()
                                        .filter(|i| {
                                            view.facts[i].exact_slot.is_none()
                                                && view.legal(*i, n, Some(end))
                                                && !assigned.contains(i)
                                        })
                                        .collect::<Vec<_>>(),
                                )
                            });
                            if !choices.is_empty() {
                                slots.insert(n, Arc::clone(choices));
                            }
                        }
                    }
                }
                if slots.len() < 2 {
                    continue;
                }
                let mut ordered_domains = HashMap::new();
                for (&number, choices) in &mut slots {
                    let fixed = fixed_numbers.contains(&number);
                    let key = (
                        Arc::as_ptr(choices),
                        number == 1,
                        candidate_terminal == Some(number),
                        fixed,
                        width_numbers.contains(&number).then_some(number),
                    );
                    if let Some((_, ordered)) = ordered_domains.get(&key) {
                        *choices = Arc::clone(ordered);
                        continue;
                    }
                    // Consume one domain at a time: never retain G copies of
                    // U gap members while sorting/interning.
                    let mut ordered = (**choices).clone();
                    if channel.is_none() && !fixed {
                        // Structurally owned unnamed members remain candidates.
                        ordered.extend(indexes.iter().copied().filter(|i| {
                            view.facts[i].owned
                                && view.facts[i].exact_slot.is_none()
                                && view.legal(*i, number, candidate_terminal)
                        }));
                    }
                    ordered.sort_by(|a, b| {
                        let local =
                            |i: &usize| Path::new(&view.rows[*i].path).parent() == head_parent;
                        let width = |i: &usize| {
                            view.features
                                .get(i)
                                .and_then(|f| {
                                    f.numbers
                                        .iter()
                                        .filter(|n| n.value == number && profile.active(n))
                                        .map(|n| n.width)
                                        .min()
                                })
                                .unwrap_or(usize::MAX)
                        };
                        local(b)
                            .cmp(&local(a))
                            .then_with(|| {
                                if channel.is_none() {
                                    width(a).cmp(&width(b))
                                } else {
                                    std::cmp::Ordering::Equal
                                }
                            })
                            .then(view.rows[*a].path_key.cmp(&view.rows[*b].path_key))
                    });
                    ordered.dedup();
                    let ordered = domains.intern(ordered);
                    ordered_domains.insert(key, (Arc::clone(choices), Arc::clone(&ordered)));
                    *choices = ordered;
                }
                let contiguous = slots.keys().copied().zip(1u32..).all(|(n, rank)| n == rank);
                // The variable bound uses filename-label coordinates. Geometry
                // can rank a sparse layout, but only proves that fixed layout;
                // it does not translate the old bound into a new slot count.
                let minimum = if variable && candidate_terminal == upper && contiguous {
                    lower.unwrap() as usize
                } else {
                    0
                };
                if channel.is_some()
                    && (view.format == "7z" || (view.format == "zip" && !spanned))
                    && !contiguous
                {
                    let mut represented = HashSet::new();
                    let mut summaries = HashMap::new();
                    let mut slack = 0u64;
                    let mut representatives = BTreeMap::new();
                    for (&number, choices) in &slots {
                        let (representative, difference) =
                            *summaries.entry(Arc::as_ptr(choices)).or_insert_with(|| {
                                let mut smallest = u64::MAX;
                                let mut largest = 0;
                                let mut representative = choices[0];
                                for &i in choices.iter() {
                                    represented.insert(i);
                                    let size = view.rows[i]
                                        .anchor
                                        .as_ref()
                                        .map_or(0, VolumeAnchor::payload_size);
                                    smallest = smallest.min(size);
                                    if size >= largest {
                                        largest = size;
                                        representative = i;
                                    }
                                }
                                (representative, largest - smallest)
                            });
                        representatives.insert(number, representative);
                        slack = slack.saturating_add(difference);
                    }
                    let mapping = VolumeAssignment {
                        slots: representatives,
                        unresolved: indexes
                            .iter()
                            .copied()
                            .filter(|i| !represented.contains(i))
                            .collect(),
                        ..Default::default()
                    };
                    // ZIP geometry belongs to a particular tail. A larger bad
                    // tail must not veto the feasible domain of another tail.
                    // Check tails only; never enumerate the slot product.
                    let (&last, tails) = slots.last_key_value().unwrap();
                    let can_normalize = tails
                        .iter()
                        .take(if view.format == "zip" { tails.len() } else { 1 })
                        .any(|tail| {
                            let mut representative = mapping.clone();
                            if view.format == "zip" {
                                representative.slots.insert(last, *tail);
                            }
                            local
                                .finish_mapping(representative, slack)
                                .is_some_and(|normalized| {
                                    normalized
                                        .slots
                                        .keys()
                                        .copied()
                                        .zip(1u32..)
                                        .all(|(n, rank)| n == rank)
                                })
                        });
                    if can_normalize
                        && slots.values().zip(1u32..).all(|(choices, rank)| {
                            choices.iter().all(|i| {
                                view.facts[i].exact_slot.is_none_or(|n| n == rank)
                                    && view.legal(*i, rank, Some(slots.len() as u32))
                            })
                        })
                    {
                        slots = slots
                            .into_values()
                            .zip(1u32..)
                            .map(|(choices, rank)| (rank, choices))
                            .collect();
                    }
                }
                let layout: Vec<_> = slots.into_iter().collect();
                if minimum != 0 {
                    let mut family = layout.clone();
                    let tails = &mut family.last_mut().unwrap().1;
                    *tails = domains.intern(
                        tails
                            .iter()
                            .copied()
                            .filter(|i| numbers[i].is_empty())
                            .collect(),
                    );
                    let all_unnamed = tails.as_ref() == layout.last().unwrap().1.as_ref();
                    let has_tails = !tails.is_empty();
                    // Preserve the full-length domain's priority before trying
                    // shorter prefixes with only movable, unnumbered tails.
                    if !all_unnamed
                        && !layouts
                            .iter()
                            .any(|(old, bound)| *bound == 0 && old == &layout)
                    {
                        layouts.push((layout.clone(), 0));
                    }
                    if has_tails
                        && !layouts
                            .iter()
                            .any(|(old, bound)| *bound == minimum && old == &family)
                    {
                        layouts.push((family, minimum));
                    }
                    // A numbered tail only belongs at its stated position;
                    // keep its ordinary layout instead of moving it with the family.
                    continue;
                }
                if !layouts
                    .iter()
                    .any(|(old, bound)| *bound == 0 && old == &layout)
                {
                    layouts.push((layout, 0));
                }
            }
        }
        if layouts.is_empty() {
            continue;
        }
        // Contiguous layouts get first chance; stable sort retains evidence
        // tier priority. Incomplete layouts remain useful for partial recovery.
        layouts.sort_by_key(|(layout, _)| {
            (
                !layout
                    .iter()
                    .zip(1u32..)
                    .all(|((n, _), expected)| *n == expected),
                std::cmp::Reverse(layout.len()),
            )
        });
        let mut sources: Vec<usize> = domains
            .0
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        sources.sort_unstable_by_key(|i| (*i != head, *i));
        let positions: HashMap<_, _> = sources.iter().enumerate().map(|(n, i)| (*i, n)).collect();
        let remapped: HashMap<_, _> = domains
            .0
            .iter()
            .map(|choices| {
                (
                    Arc::as_ptr(choices),
                    Arc::new(choices.iter().map(|i| positions[i]).collect::<Vec<_>>()),
                )
            })
            .collect();
        let assignment = VolumeAssignment {
            slots: BTreeMap::from([(1, head)]),
            ..Default::default()
        };
        let facts = shared_facts.get_or_insert_with(|| proposal_facts(view, &[]));
        let mut proposal = materialize(view, assignment, logical, None, Some(facts)).unwrap();
        // The head identity is confirmed; its volume composition remains a plan.
        // No speculative bytes are parsed again here.
        proposal.status = ProposalStatus::Valid;
        let head_anchor = view.rows[head].anchor.as_ref().unwrap();
        let (head_size_from_total, minimum_size, trim_head) =
            head_geometry(head_anchor, view.format);
        let tail_totals = if trim_head && view.format == "zip" && !spanned {
            sources
                .iter()
                .enumerate()
                .filter_map(|(index, i)| {
                    zip_total(view.rows[*i].anchor.as_ref()?).map(|total| (index, total))
                })
                .collect()
        } else {
            Vec::new()
        };
        proposal.attempts = Some(VolumeAttempts {
            head_size_from_total,
            tail_totals,
            minimum_size,
            base_source_count: sources.len(),
            sources: sources
                .iter()
                .map(|i| {
                    AttemptSource::new(&view.rows[*i].path, view.rows[*i].anchor.as_ref().unwrap())
                })
                .collect(),
            minimum_slots: layouts.iter().map(|(_, minimum)| *minimum).collect(),
            layouts: layouts
                .into_iter()
                .map(|(layout, _)| {
                    layout
                        .into_iter()
                        .map(|(n, choices)| (n, Arc::clone(&remapped[&Arc::as_ptr(&choices)])))
                        .collect()
                })
                .collect(),
        });
        output.push(proposal);
    }
    output
}

impl VolumeAttempts {
    pub(super) fn project(&self, proposal: &RelationProposal, style: &str) -> VolumeAttemptPlan {
        let mut domains = Vec::new();
        let mut domain_indexes = HashMap::new();
        let layouts = self
            .layouts
            .iter()
            .zip(&self.minimum_slots)
            .map(|(layout, &minimum_slots)| {
                let slots = layout
                    .iter()
                    .map(|&(number, ref choices)| {
                        let (domain, terminal) = *domain_indexes
                            .entry(Arc::as_ptr(choices))
                            .or_insert_with(|| {
                                let index = domains.len();
                                domains.push(VolumeDomain {
                                    choices: Arc::clone(choices),
                                });
                                (index, choices.iter().all(|&i| self.sources[i].terminal))
                            });
                        VolumeSlot {
                            number,
                            canonical_name: canonical_volume_name(
                                &proposal.logical_name,
                                number,
                                style,
                                proposal.width,
                                proposal.style == "zip_spanned" && terminal,
                            ),
                            domain,
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
                VolumeLayout {
                    slots,
                    minimum_slots,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        VolumeAttemptPlan {
            sources: self
                .sources
                .iter()
                .map(|extent| InputExtent {
                    path: extent.path.clone(),
                    start: extent.start,
                    end: Some(extent.end),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            domains: domains.into_boxed_slice(),
            layouts,
            head_size_from_total: self.head_size_from_total,
            minimum_size: self.minimum_size,
            tail_totals: self
                .tail_totals
                .iter()
                .map(|&(source, total)| TailTotal { source, total })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}
