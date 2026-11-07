//! Sparse, ordered hypotheses. Only slot domains cross the execution boundary;
//! their Cartesian product is never allocated or probed during discovery.
use super::assignment::{materialize, BucketView, VolumeAssignment};
use super::filename::{NameProfile, NumberChannel};
use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(super) struct VolumeAttempts {
    pub sources: Vec<AttemptSource>,
    pub layouts: Vec<Vec<(u32, Vec<usize>)>>,
    pub head_size_from_total: Option<u64>,
    pub minimum_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AttemptSource {
    pub path: String,
    pub start: u64,
    pub end: u64,
    pub terminal: bool,
}
impl AttemptSource {
    fn new(path: &str, anchor: &VolumeAnchor) -> Self {
        Self {
            path: path.into(),
            start: anchor.structure_offset.unwrap_or(0),
            end: anchor.extent_end(),
            terminal: anchor.anchor_roles.contains(&"terminal"),
        }
    }
}

pub(super) fn from_validation(validation: &ProposalValidation) -> VolumeAttempts {
    let proposal = &validation.proposal;
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
            .map(|(i, part)| (part.1, vec![i]))
            .collect()],
        head_size_from_total: None,
        minimum_size: None,
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
            .map(|a| AttemptSource::new(&source.path, a))
            .collect();
        if !replacements.is_empty() {
            let mut choices = vec![i];
            for source in replacements {
                let index = plan
                    .sources
                    .iter()
                    .position(|old| *old == source)
                    .unwrap_or_else(|| {
                        plan.sources.push(source);
                        plan.sources.len() - 1
                    });
                if !choices.contains(&index) {
                    choices.push(index);
                }
            }
            expanded.insert(i, choices);
        }
    }
    if !expanded.is_empty() {
        for layout in &mut plan.layouts {
            for (_, choices) in layout {
                *choices = choices
                    .iter()
                    .flat_map(|i| expanded.get(i).cloned().unwrap_or_else(|| vec![*i]))
                    .collect();
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
        for channel in channels.iter().map(Some).chain(std::iter::once(None)) {
            let offset = if view.format != "rar"
                && !view.spanned()
                && matches!(channel, Some(NumberChannel::Token { .. }))
            {
                view.features
                    .get(&head)
                    .and_then(|f| profile.number(channel.unwrap(), f))
                    .map_or(0, |n| 1 - i64::from(n))
            } else {
                0
            };
            let mut terminals: Vec<_> = indexes
                .iter()
                .filter_map(|i| {
                    let fact = &view.facts[i];
                    if fact.has_next != Some(false) {
                        return None;
                    }
                    fact.exact_slot.or_else(|| {
                        channel.and_then(|channel| {
                            view.features
                                .get(i)
                                .and_then(|f| profile.number(channel, f))
                                .and_then(|n| u32::try_from(i64::from(n) + offset).ok())
                        })
                    })
                })
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
                let mut slots = fixed.clone();
                for &i in &indexes {
                    if view.facts[&i].exact_slot.is_some() {
                        continue;
                    }
                    let Some(f) = view.features.get(&i) else {
                        continue;
                    };
                    let numbers: Vec<u32> = if let Some(channel) = channel {
                        profile
                            .number(channel, f)
                            .and_then(|n| u32::try_from(i64::from(n) + offset).ok())
                            .into_iter()
                            .collect()
                    } else {
                        f.numbers
                            .iter()
                            .filter(|n| profile.active(n) && n.value as usize <= indexes.len())
                            .map(|n| n.value)
                            .collect()
                    };
                    for n in numbers {
                        if view.legal(i, n, candidate_terminal) && !fixed.contains_key(&n) {
                            slots.entry(n).or_default().push(i);
                        }
                    }
                }
                // Fill a finite, evidence-bounded gap from otherwise unnumbered
                // members. Never allocate up to a huge filename/terminal number.
                let bound = candidate_terminal.or_else(|| slots.last_key_value().map(|(&n, _)| n));
                if let Some(end) = bound.filter(|end| *end as usize <= indexes.len()) {
                    let assigned: HashSet<_> = slots.values().flatten().copied().collect();
                    for n in 1..=end {
                        if !slots.contains_key(&n) {
                            let choices: Vec<_> = indexes
                                .iter()
                                .copied()
                                .filter(|i| {
                                    view.facts[i].exact_slot.is_none()
                                        && view.legal(*i, n, Some(end))
                                        && !assigned.contains(i)
                                })
                                .collect();
                            if !choices.is_empty() {
                                slots.insert(n, choices);
                            }
                        }
                    }
                }
                if slots.len() < 2 {
                    continue;
                }
                if channel.is_none() {
                    // A structurally owned, unnumbered member is another choice,
                    // never silently discarded in favour of an opaque named file.
                    for (&number, choices) in &mut slots {
                        if fixed.contains_key(&number) {
                            continue;
                        }
                        choices.extend(indexes.iter().copied().filter(|i| {
                            view.facts[i].owned
                                && view.facts[i].exact_slot.is_none()
                                && view.legal(*i, number, candidate_terminal)
                        }));
                    }
                }
                for (&number, choices) in &mut slots {
                    choices.sort_by(|a, b| {
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
                    choices.dedup();
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
        let mut sources: Vec<usize> = layouts
            .iter()
            .flat_map(|l| l.iter().flat_map(|(_, c)| c.iter().copied()))
            .collect();
        sources.sort_unstable();
        sources.dedup();
        let positions: HashMap<_, _> = sources.iter().enumerate().map(|(n, i)| (*i, n)).collect();
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
        let head_size_from_total = if head_anchor.payload_end.is_none()
            && (head_anchor.carrier_limit.is_some()
                || head_anchor.structure_offset.unwrap_or(0) > 0)
        {
            if view.format == "7z" {
                head_anchor
                    .expected_logical_size
                    .and_then(|end| end.checked_sub(head_anchor.structure_offset.unwrap_or(0)))
            } else if view.format == "zip" && !view.spanned() {
                let mut tails = sources
                    .iter()
                    .filter_map(|i| view.rows[*i].anchor.as_ref())
                    .filter(|a| a.zip_directory.is_some());
                let total = tails.next().and_then(|a| {
                    let d = a.zip_directory.as_ref()?;
                    d.offset
                        .checked_add(d.size)?
                        .checked_add(a.extent_end().checked_sub(d.end)?)
                });
                if tails.next().is_none() {
                    total
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        proposal.attempts = Some(VolumeAttempts {
            head_size_from_total,
            minimum_size: (view.format == "7z")
                .then(|| {
                    head_anchor
                        .expected_logical_size
                        .and_then(|end| end.checked_sub(head_anchor.structure_offset.unwrap_or(0)))
                })
                .flatten(),
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
                        .map(|(n, choices)| {
                            (n, choices.into_iter().map(|i| positions[&i]).collect())
                        })
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
    let sources = PyList::empty(py);
    for extent in &attempts.sources {
        let source = PyDict::new(py);
        source.set_item("path", &extent.path)?;
        source.set_item("start", extent.start)?;
        source.set_item("end", extent.end)?;
        sources.append(source)?;
    }
    let layouts = PyList::empty(py);
    for layout in &attempts.layouts {
        let slots = PyList::empty(py);
        for (number, choices) in layout {
            let slot = PyDict::new(py);
            slot.set_item("number", number)?;
            slot.set_item("choices", choices)?;
            let terminal = choices.iter().all(|i| attempts.sources[*i].terminal);
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
    result.set_item("layouts", layouts)?;
    Ok(result.unbind())
}
