//! Task-local byte dependencies reduce the existing candidate plan directly.
//! Worker layouts carry only the passwords still viable for their bytes.
use super::{context::PasswordContext, PasswordVerification};
use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSelection};
use crate::io::cancellation::Cancellation;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct VolumeProjection {
    pub roots: Vec<[usize; 3]>,
    pub edges: Vec<[usize; 3]>,
    pub ends: Vec<usize>,
}

pub(crate) struct EvidenceContext {
    pub plan: Arc<VolumeAttemptPlan>,
    pub alternatives: Vec<(PasswordContext, Arc<VolumeProjection>)>,
    pub rejected: Vec<Arc<VolumeProjection>>,
    pub public_plan: std::sync::OnceLock<Arc<VolumeAttemptPlan>>,
    pub unresolved: bool,
    pub public_reduced: bool,
    pub rar_anchor: Option<Arc<super::rar::RarPasswordContext>>,
    pub independent_rar: Vec<Option<Arc<super::rar::RarPasswordContext>>>,
}

/// Only allocate per-path indices after a globally viable password is
/// excluded on that path. All indices refer to the final worker list.
#[derive(Default)]
pub(crate) struct CandidateDomains(Vec<Option<Vec<usize>>>);

impl CandidateDomains {
    pub(crate) fn append(&mut self, batch: Vec<Option<Vec<usize>>>, offset: usize, count: usize) {
        if self.0.is_empty() {
            self.0.resize_with(batch.len(), || None);
        }
        let mut next = batch.into_iter();
        for accumulated in &mut self.0 {
            match next.next().flatten() {
                Some(indices) => accumulated
                    .get_or_insert_with(|| (0..offset).collect())
                    .extend(indices.into_iter().map(|i| i + offset)),
                None => {
                    if let Some(indices) = accumulated {
                        indices.extend(offset..offset + count);
                    }
                }
            }
        }
    }

    pub(crate) fn finish(
        self,
        context: &EvidenceContext,
        count: usize,
    ) -> std::io::Result<Option<(VolumeAttemptPlan, LayoutPasswords)>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let mut groups: Vec<Arc<[usize]>> = vec![Arc::default()];
        let mut ids = HashMap::<Arc<[usize]>, usize>::new();
        let mut rules: Vec<_> = context
            .rejected
            .iter()
            .map(|p| (p.as_ref(), None))
            .collect();
        for ((_, path), indices) in context.alternatives.iter().zip(self.0) {
            let Some(indices) = indices else {
                continue;
            };
            let group = if indices.is_empty() {
                None
            } else {
                Some(*ids.entry(indices.into()).or_insert_with_key(|indices| {
                    groups.push(indices.clone());
                    groups.len() - 1
                }))
            };
            rules.push((path, group));
        }
        let (plan, mut layout_groups) = partition(&context.plan, &rules, groups.len())?;
        if layout_groups.iter().all(|&id| id == 0) {
            return Ok(Some((plan, LayoutPasswords::default())));
        }
        // An unreadable path needs the whole list. Most fully resolved
        // layouts only use sparse groups, so materialize it only if reached.
        let mut remap = vec![None; groups.len()];
        let mut used = Vec::new();
        for group in &mut layout_groups {
            let original = *group;
            *group = *remap[original].get_or_insert_with(|| {
                let id = used.len();
                used.push(if original == 0 {
                    (0..count).collect()
                } else {
                    std::mem::take(&mut groups[original])
                });
                id
            });
        }
        Ok(Some((
            plan,
            LayoutPasswords {
                password_domains: used,
                layout_password_domains: layout_groups,
            },
        )))
    }
}

#[derive(Default, serde::Serialize)]
pub(crate) struct LayoutPasswords {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    password_domains: Vec<Arc<[usize]>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    layout_password_domains: Vec<usize>,
}

/// Only repeated KDF parameter sets need candidate slots. Borrow the
/// immutable parameters and allocate their slots on first use in this batch.
pub(super) struct SharedCandidateKeys<K, V>(
    HashMap<K, std::sync::OnceLock<Box<[std::sync::OnceLock<V>]>>>,
);

impl<K: Copy + Eq + std::hash::Hash, V> SharedCandidateKeys<K, V> {
    fn new<'a>(
        alternatives: &'a [(PasswordContext, Arc<VolumeProjection>)],
        identify: impl Fn(&'a PasswordContext) -> Option<K>,
    ) -> Self {
        let mut shared = HashMap::new();
        if alternatives.len() > 1 {
            let mut seen = std::collections::HashSet::new();
            for key in alternatives
                .iter()
                .filter_map(|(context, _)| identify(context))
            {
                if !seen.insert(key) {
                    shared.entry(key).or_default();
                }
            }
        }
        Self(shared)
    }

    pub(super) fn cells(&self, key: &K, count: usize) -> Option<&[std::sync::OnceLock<V>]> {
        Some(
            self.0
                .get(key)?
                .get_or_init(|| (0..count).map(|_| std::sync::OnceLock::new()).collect()),
        )
    }
}

impl EvidenceContext {
    fn public_plan(&self) -> std::io::Result<Option<Arc<VolumeAttemptPlan>>> {
        if self.rejected.is_empty() {
            return Ok(self.public_reduced.then(|| self.plan.clone()));
        }
        if let Some(plan) = self.public_plan.get() {
            return Ok(Some(plan.clone()));
        }
        let rejected: Vec<_> = self.rejected.iter().map(Arc::as_ref).collect();
        let plan = Arc::new(remove_paths(&self.plan, &rejected)?);
        Ok(Some(self.public_plan.get_or_init(|| plan).clone()))
    }
    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        self.verify_batch(candidates, false, true)
    }
    pub(super) fn verify_batch(
        &self,
        candidates: &[Arc<str>],
        fixed: bool,
        complete: bool,
    ) -> std::io::Result<PasswordVerification> {
        if candidates.is_empty() {
            return Ok(PasswordVerification {
                volume_attempts: self.public_plan()?,
                ..PasswordVerification::status(
                    "unknown_needs_final_verifier",
                    "no password candidates supplied",
                )
            });
        }
        let rar_keys = super::rar::RarKeyCache::default();
        if !fixed {
            if let Some(anchor) = &self.rar_anchor {
                let mut anchor_result = anchor.verify_cached(candidates, None, &rar_keys)?;
                let indices = &anchor_result.matched_indices;
                if indices.is_empty() {
                    anchor_result.volume_attempts = self.public_plan()?;
                    return Ok(anchor_result);
                }
                let survivors: Vec<_> = indices.iter().map(|&i| candidates[i].clone()).collect();
                let confirmed = anchor_result.final_confirmation_required == Some(false);
                let mut result = self.verify_inner(&survivors, confirmed, complete, &rar_keys, Some(anchor))?;
                if confirmed {
                    anchor_result.volume_attempts = result.volume_attempts;
                    return Ok(anchor_result);
                }
                if !matches!(result.status, "match" | "no_match") {
                    anchor_result.volume_attempts = result.volume_attempts;
                    return Ok(anchor_result);
                }
                result.matched_index = result.matched_index.map(|i| indices[i]);
                for i in &mut result.matched_indices {
                    *i = indices[*i];
                }
                result.attempts = candidates.len();
                return Ok(result);
            }
        }
        self.verify_inner(candidates, fixed, complete, &rar_keys, None)
    }

    fn verify_inner(
        &self,
        candidates: &[Arc<str>],
        fixed: bool,
        complete: bool,
        rar_keys: &super::rar::RarKeyCache,
        screened_anchor: Option<&Arc<super::rar::RarPasswordContext>>,
    ) -> std::io::Result<PasswordVerification> {
        let cancellation = Cancellation::current();
        cancellation.check_io()?;
        let keys = SharedCandidateKeys::new(&self.alternatives, |context| match context {
            PasswordContext::SevenZip(context) => context.kdf_parameters(),
            _ => None,
        });
        let zip_keys = SharedCandidateKeys::new(&self.alternatives, |context| match context {
            PasswordContext::Zip(context) => context.kdf_parameters(),
            _ => None,
        });
        let results: Vec<_> = self
            .alternatives
            .par_iter()
            .map(|(context, _)| {
                cancellation.run(|| match context {
                    PasswordContext::SevenZip(context) => context
                        .verify_cached(candidates, (self.alternatives.len() > 1).then_some(&keys)),
                    PasswordContext::Zip(context) => context.verify_cached(
                        candidates,
                        (self.alternatives.len() > 1).then_some(&zip_keys),
                    ),
                    PasswordContext::Rar(context) => {
                        if screened_anchor.is_some_and(|anchor| Arc::ptr_eq(context, anchor)) {
                            return Ok(PasswordVerification {
                                attempts: candidates.len(),
                                matched_index: Some(0),
                                matched_indices: (0..candidates.len()).collect(),
                                ..PasswordVerification::status("match", "RAR anchor password candidates already screened")
                            });
                        }
                        context.verify_cached(candidates, None, rar_keys)
                    }
                    PasswordContext::Evidence(context) => {
                        context.verify_batch(candidates, fixed, complete)
                    }
                    _ => context.verify(candidates, None),
                })
            })
            .collect::<std::io::Result<_>>()?;
        cancellation.check_io()?;
        let strong = |result: &PasswordVerification| {
            (result.status == "match" && result.final_confirmation_required == Some(false))
                .then_some(result.matched_index)
                .flatten()
        };
        let survives = |result: &PasswordVerification, index: usize| {
            if let Some(hit) = strong(result) {
                return index == hit;
            }
            !matches!(result.status, "match" | "no_match")
                || index >= result.attempts
                || result.matched_index == Some(index)
                || result.matched_indices.binary_search(&index).is_ok()
        };
        // A strong proof on one possible tail belongs to that tail. Another
        // tail may be a valid archive using a different configured password.
        let confirmed = results.iter().find_map(strong).filter(|&hit| {
            fixed
                || (!self.unresolved
                    && results.iter().all(|result| {
                        strong(result) == Some(hit)
                            || (complete
                                && (0..candidates.len()).all(|i| i == hit || !survives(result, i)))
                    }))
        });
        let mut removed: Vec<&VolumeProjection> = Vec::new();
        if let Some(index) = confirmed.or_else(|| fixed.then_some(0)) {
            // The plan has one confirmed password. Remove volume paths that
            // contradict it; there is no password/volume rule to carry onward.
            for ((_, projection), result) in self.alternatives.iter().zip(&results) {
                if !survives(result, index) {
                    removed.push(projection);
                }
            }
        }
        let native_rejections = if let Some(index) = confirmed.or_else(|| fixed.then_some(0)) {
            let screened: HashMap<_, _> = self.alternatives.iter().zip(&results)
                .filter_map(|((context, _), result)| match context {
                    PasswordContext::Rar(context) => Some((Arc::as_ptr(context) as usize, survives(result, index))),
                    _ => None,
                })
                .collect();
            self.independent_rar
                .par_iter()
                .map(|context| -> std::io::Result<bool> {
                    let Some(context) = context else {
                        return Ok(false);
                    };
                    if screened_anchor.is_some_and(|anchor| Arc::ptr_eq(context, anchor)) {
                        return Ok(false);
                    }
                    if let Some(&kept) = screened.get(&(Arc::as_ptr(context) as usize)) {
                        return Ok(!kept);
                    }
                    cancellation
                        .run(|| context.verify_cached(&candidates[index..=index], None, &rar_keys))
                        .map(|result| result.status == "no_match")
                })
                .collect::<std::io::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let native_proof = native_rejections
            .iter()
            .any(|&bad| bad)
            .then(|| super::rar::native_volumes::rejected_sources(&self.plan, &native_rejections));
        if let Some(proof) = native_proof.as_ref() {
            removed.push(proof);
        }
        let volume_attempts = if !removed.is_empty() {
            removed.extend(self.rejected.iter().map(Arc::as_ref));
            Some(Arc::new(remove_paths(&self.plan, &removed)?))
        } else {
            self.public_plan()?
        };
        if let Some(index) = confirmed {
            let mut result = results
                .into_iter()
                .find(|result| {
                    result.matched_index == Some(index)
                        && result.final_confirmation_required == Some(false)
                })
                .unwrap();
            result.volume_attempts = volume_attempts;
            return Ok(result);
        }
        if self.alternatives.is_empty() {
            return Ok(PasswordVerification {
                volume_attempts,
                ..PasswordVerification::status(
                    "unknown_needs_final_verifier",
                    "no usable password proof",
                )
            });
        }
        let mut possible = vec![self.unresolved; candidates.len()];
        let mut method = None;
        for result in &results {
            if result.status == "match" {
                method = match (method, result.match_evidence) {
                    (None, next) => next,
                    (old, next) if old == next => old,
                    _ => Some("mixed"),
                };
            }
            for (index, possible) in possible.iter_mut().enumerate() {
                *possible |= survives(&result, index);
            }
        }
        let matches: Vec<_> = possible
            .iter()
            .enumerate()
            .filter_map(|(i, &yes)| yes.then_some(i))
            .collect();
        let mut password_domains = Vec::new();
        if !fixed && !matches.is_empty() {
            for (path, result) in results.iter().enumerate() {
                if matches.iter().any(|&index| !survives(result, index)) {
                    if password_domains.is_empty() {
                        password_domains.resize_with(results.len(), || None);
                    }
                    password_domains[path] = Some(
                        matches
                            .iter()
                            .enumerate()
                            .filter_map(|(ordinal, &index)| {
                                survives(result, index).then_some(ordinal)
                            })
                            .collect(),
                    );
                }
            }
        }
        let matched = !matches.is_empty();
        Ok(PasswordVerification {
            password_domains,
            matched_index: matches.first().copied(),
            matched_indices: matches,
            attempts: candidates.len(),
            final_confirmation_required: Some(true),
            match_evidence: if !matched && self.alternatives.len() > 1 {
                Some("password_or_volume_inconclusive")
            } else {
                method
            },
            volume_attempts,
            ..PasswordVerification::status(
                if matched { "match" } else { "no_match" },
                "password candidates screened against available volume evidence",
            )
        })
    }
}

// Subtract only the consumed byte paths. Emit ordinary layouts/domains in
// their original traversal order, sharing untouched choice lists. Unrelated
// slots remain factored: this never enumerates their Cartesian product.
pub(super) fn remove_paths(
    plan: &VolumeAttemptPlan,
    removed: &[&VolumeProjection],
) -> std::io::Result<VolumeAttemptPlan> {
    let rules: Vec<_> = removed
        .iter()
        .map(|&projection| (projection, None))
        .collect();
    Ok(partition(plan, &rules, 1)?.0)
}

/// Worker results use the original request's source IDs. Subtract the actual
/// paths before reporting the plan so independent slot choices cannot recreate
/// a combination the decoder already rejected.
pub(crate) fn remove_scan_paths(
    plan: &VolumeAttemptPlan,
    selections: Vec<VolumeSelection>,
    layouts: Vec<usize>,
    first: Option<&VolumeSelection>,
) -> std::io::Result<VolumeAttemptPlan> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid worker volume result");
    let mut proof = VolumeProjection { roots: Vec::new(), edges: Vec::new(), ends: Vec::new() };
    let mut roots = HashMap::new();
    let mut edges = HashMap::new();
    let mut nodes = 0;
    let mut node = || { nodes += 1; nodes };
    let start = first.map_or(0, |selection| selection.layout);
    let mut dropped = vec![false; plan.layouts.len()];
    for layout in layouts {
        *dropped.get_mut(layout).ok_or_else(invalid)? = true;
    }
    for selection in selections {
        let layout = plan.layouts.get(selection.layout).ok_or_else(invalid)?;
        let count = selection.sources.len();
        let minimum = if layout.minimum_slots == 0 { layout.slots.len() } else { layout.minimum_slots };
        if !(minimum..=layout.slots.len()).contains(&count) {
            return Err(invalid());
        }
        if selection.layout < start || dropped[selection.layout] {
            continue;
        }
        let mut at = *roots.entry((selection.layout, count)).or_insert_with(&mut node);
        for (index, source) in selection.sources.into_iter().enumerate() {
            let slot = if index + 1 == count { layout.slots.last().unwrap() } else { &layout.slots[index] };
            if !plan.domains[slot.domain].choices.contains(&source) {
                return Err(invalid());
            }
            at = *edges.entry((at, source)).or_insert_with(&mut node);
        }
        proof.ends.push(at);
    }
    proof.roots.extend(roots.into_iter().map(|((layout, count), at)| [layout, count, at]));
    proof.edges.extend(edges.into_iter().map(|((from, source), to)| [from, to, source]));
    let (plan, _) = partition_from(plan, &[(&proof, None)], 1, &dropped, first)?;
    Ok(plan)
}

// A terminal either removes a path or assigns its password domain. Prepared
// alternatives partition the byte observations. Paths without readable proof
// use domain zero, which contains every globally surviving candidate.
fn partition(
    plan: &VolumeAttemptPlan,
    rules: &[(&VolumeProjection, Option<usize>)],
    domain_count: usize,
) -> std::io::Result<(VolumeAttemptPlan, Vec<usize>)> {
    partition_from(plan, rules, domain_count, &[], None)
}

fn partition_from(
    plan: &VolumeAttemptPlan,
    rules: &[(&VolumeProjection, Option<usize>)],
    domain_count: usize,
    dropped: &[bool],
    first: Option<&VolumeSelection>,
) -> std::io::Result<(VolumeAttemptPlan, Vec<usize>)> {
    if let Some(first) = first { plan.selected_parts(first)?; }
    type State = Vec<(usize, usize)>;
    let mut edges: HashMap<(usize, usize, usize), Vec<usize>> = HashMap::new();
    let mut ends = HashMap::new();
    let mut roots = HashMap::<(usize, usize), State>::new();
    for (proof, &(projection, group)) in rules.iter().enumerate() {
        for &[from, to, source] in &projection.edges {
            edges.entry((proof, from, source)).or_default().push(to);
        }
        ends.extend(projection.ends.iter().map(|&node| ((proof, node), group)));
        for &[layout, count, node] in &projection.roots {
            roots
                .entry((layout, count))
                .or_default()
                .push((proof, node));
        }
    }
    // Build reachable state transitions top down. Fold them back into shared
    // suffixes using arena indices, so long volume sequences neither recurse
    // nor copy every accumulated suffix at each slot.
    fn subtract(
        choices: &[Arc<Vec<usize>>],
        root: State,
        edges: &HashMap<(usize, usize, usize), Vec<usize>>,
        ends: &HashMap<(usize, usize), Option<usize>>,
        domain_count: usize,
    ) -> std::io::Result<Vec<(Vec<Arc<Vec<usize>>>, usize)>> {
        if root.is_empty() {
            return Ok(vec![(choices.to_vec(), 0)]);
        }
        let cancel = Cancellation::current();
        let mut layer = vec![root];
        let mut layers = Vec::with_capacity(choices.len());
        for domain in choices {
            cancel.check_io()?;
            let mut next = Vec::new();
            let mut ids = HashMap::new();
            let mut steps = Vec::with_capacity(layer.len());
            for state in layer {
                let mut targets = Vec::new();
                if !state.is_empty() {
                    for &source in domain.iter() {
                        let mut target = Vec::new();
                        for &(proof, node) in &state {
                            if let Some(nodes) = edges.get(&(proof, node, source)) {
                                target.extend(nodes.iter().map(|&n| (proof, n)));
                            }
                        }
                        target.sort_unstable();
                        target.dedup();
                        targets.push(*ids.entry(target.clone()).or_insert_with(|| {
                            let id = next.len();
                            next.push(target);
                            id
                        }));
                    }
                }
                steps.push(targets);
            }
            layers.push(steps);
            layer = next;
        }
        let mut suffixes: Vec<Vec<usize>> = layer
            .iter()
            .map(|state| {
                state
                    .iter()
                    .filter_map(|n| ends.get(n))
                    .copied()
                    .min()
                    .unwrap_or(Some(0))
                    .into_iter()
                    .collect()
            })
            .collect();
        // Terminal IDs are password domains. Higher IDs refer to arena entries.
        let mut arena: Vec<(Arc<Vec<usize>>, usize)> = Vec::new();
        let mut unconstrained = 0;
        for (domain, steps) in choices.iter().zip(layers).rev() {
            cancel.check_io()?;
            let mut intern = HashMap::<(Arc<Vec<usize>>, usize), usize>::new();
            let mut node = |choices: Arc<Vec<usize>>, tail| {
                *intern.entry((choices.clone(), tail)).or_insert_with(|| {
                    let id = domain_count + arena.len();
                    arena.push((choices, tail));
                    id
                })
            };
            unconstrained = node(domain.clone(), unconstrained);
            suffixes = steps
                .into_iter()
                .map(|targets| {
                    if targets.is_empty() {
                        return vec![unconstrained];
                    }
                    let mut output = Vec::new();
                    let mut group = Vec::new();
                    let mut common = 0;
                    for (&source, target) in domain.iter().zip(targets) {
                        let tails = &suffixes[target];
                        if tails.is_empty() {
                            continue;
                        }
                        if !group.is_empty() && tails.as_slice() != [common] {
                            output.push(node(Arc::new(std::mem::take(&mut group)), common));
                        }
                        if let [tail] = tails[..] {
                            common = tail;
                            group.push(source);
                        } else {
                            let one = Arc::new(vec![source]);
                            output.extend(tails.iter().map(|&t| node(one.clone(), t)));
                        }
                    }
                    if !group.is_empty() {
                        output.push(node(
                            if group.len() == domain.len() {
                                domain.clone()
                            } else {
                                Arc::new(group)
                            },
                            common,
                        ));
                    }
                    output
                })
                .collect();
        }
        Ok(suffixes
            .pop()
            .unwrap()
            .into_iter()
            .map(|mut id| {
                let mut path = Vec::with_capacity(choices.len());
                while id >= domain_count {
                    let (choices, next) = &arena[id - domain_count];
                    path.push(choices.clone());
                    id = *next;
                }
                (path, id)
            })
            .collect())
    }
    let mut layouts = Vec::new();
    let mut layout_groups = Vec::new();
    let mut domains: Vec<VolumeDomain> = Vec::new();
    let mut domain_ids: HashMap<Arc<Vec<usize>>, usize> = HashMap::new();
    let start = first.map_or(0, |selection| selection.layout);
    for (layout_index, layout) in plan.layouts.iter().enumerate().skip(start) {
        if dropped.get(layout_index) == Some(&true) { continue; }
        let maximum = layout.slots.len();
        let minimum = if layout.minimum_slots == 0 {
            maximum
        } else {
            layout.minimum_slots
        };
        let frontier = first.filter(|selection| selection.layout == layout_index);
        let maximum_count = frontier.map_or(maximum, |selection| selection.sources.len());
        let mut counts = (minimum..=maximum_count).rev().peekable();
        while let Some(count) = counts.next() {
            let state = roots.remove(&(layout_index, count)).unwrap_or_default();
            // A run of untouched counts is already represented by minimum_slots.
            // Keep it factored instead of copying a slot vector for every length.
            let mut lowest = count;
            let frontier = frontier.filter(|selection| selection.sources.len() == count);
            if state.is_empty() && frontier.is_none() {
                while let Some(next) = counts.next_if(|n| !roots.contains_key(&(layout_index, *n)))
                {
                    lowest = next;
                }
            }
            let mut slots = layout.slots[..count].to_vec();
            slots[count - 1].domain = layout.slots[maximum - 1].domain;
            let choices: Vec<_> = slots
                .iter()
                .map(|slot| Arc::clone(&plan.domains[slot.domain].choices))
                .collect();
            let mut keep = |remaining: Vec<Arc<Vec<usize>>>, group| {
                let mut slots = slots.clone();
                for (slot, choices) in slots.iter_mut().zip(remaining) {
                    slot.domain = *domain_ids.entry(choices.clone()).or_insert_with(|| {
                        let index = domains.len();
                        domains.push(VolumeDomain { choices });
                        index
                    });
                }
                layouts.push(VolumeLayout {
                    slots: slots.into(),
                    minimum_slots: if lowest == count { 0 } else { lowest },
                });
                if domain_count > 1 {
                    layout_groups.push(group);
                }
            };
            match frontier {
                None => {
                    for (remaining, group) in subtract(&choices, state, &edges, &ends, domain_count)? {
                        keep(remaining, group);
                    }
                }
                Some(selection) => {
                    for suffix in ordered_suffix(&choices, &selection.sources) {
                        for (remaining, group) in subtract(&suffix, state.clone(), &edges, &ends, domain_count)? {
                            keep(remaining, group);
                        }
                    }
                }
            }
        }
    }
    Ok((plan.with_remaining(layouts, domains), layout_groups))
}

fn ordered_suffix(choices: &[Arc<Vec<usize>>], first: &[usize]) -> Vec<Vec<Arc<Vec<usize>>>> {
    let mut suffix = Vec::new();
    let mut path: Vec<_> = first.iter().map(|source| Arc::new(vec![*source])).collect();
    for index in (0..choices.len()).rev() {
        let domain = &choices[index];
        let position = domain.iter().position(|source| *source == first[index]).unwrap();
        let start = position + usize::from(index + 1 != choices.len());
        if start == domain.len() { continue; }
        path[index + 1..].clone_from_slice(&choices[index + 1..]);
        path[index] = if start == 0 { domain.clone() } else { Arc::new(domain[start..].to_vec()) };
        suffix.push(path.clone());
    }
    suffix
}

#[cfg(test)]
#[path = "../../tests/unit/password/evidence_tests.rs"]
mod tests;
