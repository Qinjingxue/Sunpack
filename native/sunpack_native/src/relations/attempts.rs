//! Sparse, ordered hypotheses. Only slot domains cross the execution boundary;
//! their Cartesian product is never allocated or probed during discovery.
use super::assignment::{materialize, BucketView, VolumeAssignment};
use super::filename::NameProfile;
use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(super) struct VolumeAttempts {
    pub sources: Vec<AttemptSource>,
    pub layouts: Vec<Vec<(u32, Arc<Vec<usize>>)>>,
    pub head_size_from_total: Option<u64>,
    pub minimum_size: Option<u64>,
    pub tail_totals: Vec<(usize, u64)>,
}

impl VolumeAttempts {
    // PKZIP disk offsets are relative to each disk, not to the concatenated
    // archive. Reuse the unique mapping's geometry and represent each possible
    // common disk size with ordinary range/domain layouts (no second protocol).
    fn with_spanned_carrier(mut self, head: &VolumeAnchor) -> Self {
        if head.payload_end.is_some()
            || (head.carrier_limit.is_none() && head.structure_offset.unwrap_or(0) == 0)
        {
            return self;
        }
        let mut domains = Domains::default();
        let mut heads = HashMap::new();
        let mut filtered = HashMap::new();
        for layout in std::mem::take(&mut self.layouts) {
            let interiors: Vec<_> = layout
                .iter()
                .skip(1)
                .filter(|(_, choices)| choices.iter().all(|i| !self.sources[*i].terminal))
                .collect();
            let mut sizes = None::<HashSet<u64>>;
            for (_, choices) in &interiors {
                let available: HashSet<_> = choices
                    .iter()
                    .map(|i| self.sources[*i].end - self.sources[*i].start)
                    .collect();
                if let Some(sizes) = &mut sizes {
                    sizes.retain(|size| available.contains(size));
                } else {
                    sizes = Some(available);
                }
            }
            let from_tail = interiors.is_empty();
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
                    } else if choices.iter().all(|i| !self.sources[*i].terminal) {
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
                                                self.sources[*i].end - self.sources[*i].start
                                                    == size
                                            })
                                            .collect(),
                                    ),
                                )
                            });
                        Arc::clone(domain)
                    } else if from_tail {
                        domains.intern(
                            choices
                                .iter()
                                .copied()
                                .filter(|i| self.sources[*i].head_size == Some(size))
                                .collect(),
                        )
                    } else {
                        Arc::clone(choices)
                    };
                    trimmed.push((*number, domain));
                }
                if trimmed.iter().all(|(_, choices)| !choices.is_empty())
                    && !self.layouts.contains(&trimmed)
                {
                    self.layouts.push(trimmed);
                }
            }
            // Equal disk size is a geometry hypothesis, not format identity.
            // Retain the original for nonuniform disks and unpadded carriers.
            if !self.layouts.contains(&layout) {
                self.layouts.push(layout);
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
        let head = &validation.anchors[&path_key(&validation.proposal.volumes[0].0)];
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
    let trim = head.payload_end.is_none()
        && (head.carrier_limit.is_some() || head.structure_offset.unwrap_or(0) > 0);
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
    let head = &validation.anchors[&path_key(&proposal.volumes[0].0)];
    let (head_size_from_total, minimum_size, trim) = head_geometry(head, &proposal.format);
    VolumeAttempts {
        sources: proposal
            .volumes
            .iter()
            .map(|part| AttemptSource::new(&part.0, &validation.anchors[&path_key(&part.0)]))
            .collect(),
        layouts: vec![proposal
            .volumes
            .iter()
            .enumerate()
            .map(|(i, part)| (part.1, Arc::new(vec![i])))
            .collect()],
        head_size_from_total,
        minimum_size,
        tail_totals: if trim && proposal.format == "zip" && proposal.style != "zip_spanned" {
            proposal
                .volumes
                .iter()
                .enumerate()
                .filter_map(|(index, part)| {
                    zip_total(&validation.anchors[&path_key(&part.0)]).map(|total| (index, total))
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
        let anchor = &validation.anchors[&key];
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
    let mut heads: Vec<_> = view
        .indexes
        .iter()
        .copied()
        .filter(|i| view.facts[i].exact_slot == Some(1))
        .collect();
    heads.sort_by(|a, b| view.rows[*a].path_key.cmp(&view.rows[*b].path_key));
    let mut output = Vec::new();
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
            indexes: indexes.clone(),
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
            let inferred_end = unnamed_tail
                .then(|| {
                    let last = indexes
                        .iter()
                        .filter(|i| view.facts[i].has_next != Some(false))
                        .flat_map(|i| numbers[i].iter().copied())
                        .max()
                        .unwrap_or(1);
                    if last > 1 {
                        last.checked_add(1)
                    } else {
                        // With no numbered interior, keep the unnumbered members
                        // as shared gap domains. Competing tails occupy one slot.
                        u32::try_from(
                            indexes
                                .iter()
                                .filter(|i| view.facts[i].has_next != Some(false))
                                .count(),
                        )
                        .ok()
                        .and_then(|n| n.checked_add(1))
                    }
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
            for candidate_terminal in terminals {
                let fixed: BTreeMap<u32, Vec<usize>> = fixed
                    .iter()
                    .filter_map(|(&n, choices)| {
                        let choices: Vec<_> = choices
                            .iter()
                            .copied()
                            .filter(|i| view.legal(*i, n, candidate_terminal))
                            .collect();
                        (!choices.is_empty()).then_some((n, choices))
                    })
                    .collect();
                let mut slots: BTreeMap<_, _> = fixed
                    .iter()
                    .map(|(&n, choices)| (n, Arc::new(choices.clone())))
                    .collect();
                for &i in &indexes {
                    if view.facts[&i].exact_slot.is_some() {
                        continue;
                    }
                    let unnamed_terminal = (view.facts[&i].has_next == Some(false)
                        && numbers[&i].is_empty())
                    .then_some(candidate_terminal)
                    .flatten();
                    for n in numbers[&i].iter().copied().chain(unnamed_terminal) {
                        if view.legal(i, n, candidate_terminal) && !fixed.contains_key(&n) {
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
                let mut ordered_domains = HashMap::new();
                for (&number, choices) in &mut slots {
                    let key = (
                        Arc::as_ptr(choices),
                        number == 1,
                        candidate_terminal == Some(number),
                        fixed.contains_key(&number),
                        width_numbers.contains(&number).then_some(number),
                    );
                    if let Some((_, ordered)) = ordered_domains.get(&key) {
                        *choices = Arc::clone(ordered);
                        continue;
                    }
                    // Consume one domain at a time: never retain G copies of
                    // U gap members while sorting/interning.
                    let mut ordered = (**choices).clone();
                    if channel.is_none() && !fixed.contains_key(&number) {
                        // Structurally owned unnamed members remain candidates.
                        ordered.extend(indexes.iter().copied().filter(|i| {
                            view.facts[i].owned
                                && view.facts[i].exact_slot.is_none()
                                && view.legal(*i, number, candidate_terminal)
                        }));
                    }
                    ordered.sort_by(|a, b| {
                        let local = |i: &usize| {
                            Path::new(&view.rows[*i].path).parent()
                                == Path::new(&view.rows[head].path).parent()
                        };
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
                if channel.is_some()
                    && (view.format == "7z" || (view.format == "zip" && !view.spanned()))
                    && slots.keys().copied().zip(1u32..).any(|(n, rank)| n != rank)
                {
                    let represented: HashSet<_> =
                        slots.values().flat_map(|c| c.iter()).copied().collect();
                    let mapping = VolumeAssignment {
                        slots: slots
                            .iter()
                            .map(|(&n, choices)| {
                                (
                                    n,
                                    *choices
                                        .iter()
                                        .max_by_key(|i| {
                                            view.rows[**i]
                                                .anchor
                                                .as_ref()
                                                .map_or(0, |a| a.payload_size())
                                        })
                                        .unwrap(),
                                )
                            })
                            .collect(),
                        unresolved: indexes
                            .iter()
                            .copied()
                            .filter(|i| !represented.contains(i))
                            .collect(),
                        ..Default::default()
                    };
                    let slack = slots.values().fold(0u64, |total, choices| {
                        let sizes = || {
                            choices.iter().map(|i| {
                                view.rows[*i]
                                    .anchor
                                    .as_ref()
                                    .map_or(0, |a| a.payload_size())
                            })
                        };
                        total.saturating_add(sizes().max().unwrap() - sizes().min().unwrap())
                    });
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
                if !layouts.contains(&layout) {
                    layouts.push(layout);
                }
            }
        }
        if layouts.is_empty() {
            continue;
        }
        // Contiguous layouts get first chance; stable sort retains evidence
        // tier priority. Incomplete layouts remain useful for partial recovery.
        layouts.sort_by_key(|layout| {
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
        sources.sort_unstable();
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
            unresolved: sources.iter().copied().filter(|i| *i != head).collect(),
            ..Default::default()
        };
        let mut proposal = materialize(view, assignment, logical, None).unwrap();
        proposal.unresolved = sources
            .iter()
            .filter(|i| **i != head)
            .map(|i| view.rows[*i].path.clone())
            .collect();
        // The head identity is confirmed; its volume composition remains a plan.
        // No speculative bytes are parsed again here.
        proposal.status = ProposalStatus::Valid;
        let head_anchor = view.rows[head].anchor.as_ref().unwrap();
        let (head_size_from_total, minimum_size, trim_head) =
            head_geometry(head_anchor, view.format);
        let tail_totals = if trim_head && view.format == "zip" && !view.spanned() {
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
            sources: sources
                .iter()
                .map(|i| {
                    AttemptSource::new(&view.rows[*i].path, view.rows[*i].anchor.as_ref().unwrap())
                })
                .collect(),
            layouts: layouts
                .into_iter()
                .map(|layout| {
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

pub(super) fn to_dict(py: Python<'_>, validation: &ProposalValidation) -> PyResult<Py<PyDict>> {
    let attempts = validation.attempts.as_ref().unwrap();
    let result = PyDict::new(py);
    if let Some(total) = attempts.head_size_from_total {
        result.set_item("head_size_from_total", total)?;
    }
    if let Some(size) = attempts.minimum_size {
        result.set_item("minimum_size", size)?;
    }
    if !attempts.tail_totals.is_empty() {
        result.set_item("tail_totals", &attempts.tail_totals)?;
    }
    let sources = PyList::empty(py);
    for extent in &attempts.sources {
        let source = PyDict::new(py);
        source.set_item("path", &extent.path)?;
        source.set_item("start", extent.start)?;
        source.set_item("end", extent.end)?;
        sources.append(source)?;
    }
    let layouts = PyList::empty(py);
    let domains = PyList::empty(py);
    let mut domain_indexes = HashMap::new();
    for layout in &attempts.layouts {
        let slots = PyList::empty(py);
        for (number, choices) in layout {
            let slot = PyDict::new(py);
            slot.set_item("number", number)?;
            let (domain, terminal) = match domain_indexes.get(&Arc::as_ptr(choices)) {
                Some(index) => *index,
                None => {
                    let index = domains.len();
                    domains.append(choices.as_ref())?;
                    let info = (index, choices.iter().all(|i| attempts.sources[*i].terminal));
                    domain_indexes.insert(Arc::as_ptr(choices), info);
                    info
                }
            };
            slot.set_item("domain", domain)?;
            slot.set_item(
                "role",
                if validation.proposal.style == "zip_spanned" && terminal {
                    "terminal"
                } else {
                    "member"
                },
            )?;
            slots.append(slot)?;
        }
        layouts.append(slots)?;
    }
    result.set_item("sources", sources)?;
    result.set_item("domains", domains)?;
    result.set_item("layouts", layouts)?;
    Ok(result.unbind())
}
