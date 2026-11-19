//! Task-local byte dependencies reduce the existing candidate plan directly.
//! Worker layouts carry only the passwords still viable for their bytes.
use super::{context::{PasswordContext, PreparedStatus}, PasswordVerification};
use crate::io::archive_state::{DomainMembers, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSelection};
use crate::io::cancellation::Cancellation;
use rayon::prelude::*;
use std::collections::HashMap;
use std::ops::Range;
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
    pub unresolved: Option<PreparedStatus>,
    pub public_reduced: bool,
    pub rar_anchor: Option<Arc<super::rar::RarPasswordContext>>,
    pub independent_rar: Vec<Option<Arc<super::rar::RarPasswordContext>>>,
}

#[derive(Debug, Default)]
pub(crate) struct ScopedRejections(Vec<(Arc<VolumeProjection>, usize)>);

impl ScopedRejections {
    pub(crate) fn is_empty(&self) -> bool { self.0.is_empty() }

    pub(crate) fn push(&mut self, rejected: (Arc<VolumeProjection>, usize)) {
        self.0.push(rejected);
    }

    pub(crate) fn remap(&mut self, map_index: impl Fn(usize) -> Option<usize>) {
        self.0.retain_mut(|(_, index)| {
            if let Some(mapped) = map_index(*index) {
                *index = mapped;
                true
            } else {
                false
            }
        });
    }
}

impl Extend<(Arc<VolumeProjection>, usize)> for ScopedRejections {
    fn extend<I: IntoIterator<Item = (Arc<VolumeProjection>, usize)>>(&mut self, values: I) {
        self.0.extend(values);
    }
}

/// Only allocate per-path indices after a globally viable password is
/// excluded on that path. All indices refer to the final worker list.
#[derive(Default)]
pub(crate) struct CandidateDomains {
    prepared: Vec<Option<Vec<usize>>>,
    scoped: ScopedRejections,
}

impl CandidateDomains {
    pub(crate) fn append(&mut self, batch: Vec<Option<Vec<usize>>>, offset: usize, count: usize) {
        if self.prepared.is_empty() {
            self.prepared.resize_with(batch.len(), || None);
        }
        let mut next = batch.into_iter();
        for accumulated in &mut self.prepared {
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

    pub(crate) fn append_scoped(
        &mut self, mut rejected: ScopedRejections, offset: usize, ordinals: &[usize],
    ) {
        rejected.remap(|index| {
            let &ordinal = ordinals.get(index)?;
            (ordinal != usize::MAX).then(|| offset + ordinal)
        });
        if self.scoped.is_empty() {
            self.scoped = rejected;
        } else {
            self.scoped.0.extend(rejected.0);
        }
    }

    pub(crate) fn finish(
        self,
        context: &EvidenceContext,
        count: usize,
    ) -> std::io::Result<Option<(VolumeAttemptPlan, LayoutPasswords)>> {
        if self.prepared.is_empty() && self.scoped.is_empty() {
            return Ok(None);
        }
        let mut groups: Vec<Arc<[usize]>> = vec![Arc::default()];
        let mut ids = HashMap::<Arc<[usize]>, usize>::new();
        let mut rules: Vec<_> = context
            .rejected
            .iter()
            .map(|p| (p.as_ref(), Rule::Remove))
            .collect();
        for ((_, path), indices) in context.alternatives.iter().zip(self.prepared) {
            let Some(indices) = indices else {
                continue;
            };
            let rule = if indices.is_empty() {
                Rule::Remove
            } else {
                Rule::Domain(*ids.entry(indices.into()).or_insert_with_key(|indices| {
                    groups.push(indices.clone());
                    groups.len() - 1
                }))
            };
            rules.push((path, rule));
        }
        rules.extend(self.scoped.0.iter().map(|(path, index)| (path.as_ref(), Rule::Reject(std::slice::from_ref(index)))));
        let mut rejected = Vec::new();
        let mut allowed = Vec::new();
        let mut terminal = |state: &State, ends: &Ends| -> Option<usize> {
            let mut group = 0;
        let mut first_rejection = None;
            rejected.clear();
            for node in state {
                match ends.get(node) {
                    Some(Rule::Remove | Rule::RemovePrefix) => return None,
                    Some(Rule::Domain(id)) => group = if group == 0 { *id } else { group.min(*id) },
                Some(Rule::Reject(indices)) => {
                    if first_rejection.is_none() {
                        first_rejection = Some(*indices);
                    } else {
                        rejected.extend_from_slice(indices);
                    }
                }
                    None => {}
                }
            }
        let Some(first) = first_rejection else { return Some(group); };
        let excluded = if rejected.is_empty() {
            first
        } else {
            rejected.extend_from_slice(first);
            rejected.sort_unstable();
            rejected.dedup();
            rejected.as_slice()
        };
        if excluded.len() == count { return None; }
            allowed.clear();
        let mut rejected = excluded.iter().copied().peekable();
            let mut retain = |index| {
                while rejected.next_if(|i| *i < index).is_some() {}
                if rejected.next_if_eq(&index).is_none() {
                    allowed.push(index);
                }
            };
            if group == 0 {
                (0..count).for_each(&mut retain);
                if allowed.len() == count { return Some(0); }
            } else {
                groups[group].iter().copied().for_each(retain);
                if allowed.len() == groups[group].len() { return Some(group); }
            }
            if allowed.is_empty() { return None; }
            if let Some(&id) = ids.get(allowed.as_slice()) { return Some(id); }
            Some(*ids.entry(allowed.as_slice().into()).or_insert_with_key(|indices| {
                groups.push(indices.clone());
                groups.len() - 1
            }))
        };
        let (plan, mut layout_groups) = partition_from(&context.plan, &rules, &[], None, &mut terminal)?;
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
    pub(super) fn new<'a, I: IntoIterator<Item = K>>(
        alternatives: &'a [(PasswordContext, Arc<VolumeProjection>)],
        identify: impl Fn(&'a PasswordContext) -> I,
    ) -> Self {
        Self::from_parameters(alternatives.iter().flat_map(|(context, _)| identify(context)))
    }

    pub(super) fn from_parameters(parameters: impl IntoIterator<Item = K>) -> Self {
        let mut shared = Self(HashMap::new());
        shared.include_repeated(parameters);
        shared
    }

    pub(super) fn include_repeated(&mut self, parameters: impl IntoIterator<Item = K>) {
        for_repeated_parameters(parameters, |key| { self.0.entry(key).or_default(); });
    }

    pub(super) fn cells(&self, key: &K, count: usize) -> Option<&[std::sync::OnceLock<V>]> {
        Some(
            self.0
                .get(key)?
                .get_or_init(|| (0..count).map(|_| std::sync::OnceLock::new()).collect()),
        )
    }

    pub(super) fn keep_candidates(&mut self, key: &K, indices: &[usize]) {
        let cell = self.0.get_mut(key).unwrap();
        let values = cell.take().unwrap();
        let mut keep = indices.iter().copied().peekable();
        let _ = cell.set(values.into_vec().into_iter().enumerate()
            .filter_map(|(index, value)| keep.next_if_eq(&index).map(|_| value))
            .collect());
    }
}

pub(super) fn for_repeated_parameters<K: Copy + Eq + std::hash::Hash>(
    parameters: impl IntoIterator<Item = K>,
    mut repeat: impl FnMut(K),
) {
    let mut parameters = parameters.into_iter();
    if let (Some(first), Some(second)) = (parameters.next(), parameters.next()) {
        let mut seen = std::collections::HashSet::from([first]);
        for key in std::iter::once(second).chain(parameters) {
            if !seen.insert(key) { repeat(key); }
        }
    }
}

fn confirmed_password(result: &PasswordVerification) -> Option<usize> {
    (result.status == "match" && result.final_confirmation_required == Some(false))
        .then_some(result.matched_index)
        .flatten()
}

/// A verifier reports sorted surviving indices inside its tested prefix. An
/// ordered probe that stopped early leaves the entire untested suffix viable.
pub(crate) struct SurvivingCandidates<'a> {
    tested: &'a [usize],
    single: Option<usize>,
    untested: Range<usize>,
}

impl<'a> SurvivingCandidates<'a> {
    pub(crate) fn new(result: &'a PasswordVerification, count: usize) -> Self {
        if let Some(index) = confirmed_password(result) {
            return Self { tested: &[], single: Some(index), untested: count..count };
        }
        if !matches!(result.status, "match" | "no_match") {
            return Self { tested: &[], single: None, untested: 0..count };
        }
        let end = result.attempts.min(count);
        let mut tested = result.matched_indices.as_slice();
        if tested.last().is_some_and(|&index| index >= end) {
            tested = &tested[..tested.partition_point(|&index| index < end)];
        }
        // Single-index results need not also allocate a matched-index list.
        debug_assert!(tested.is_empty() || tested.first().copied() == result.matched_index);
        let single = result.matched_index.filter(|&index| index < end && tested.is_empty());
        Self { tested, single, untested: end..count }
    }

    fn len(&self) -> usize {
        self.tested.len() + usize::from(self.single.is_some()) + self.untested.len()
    }

    fn contains(&self, index: usize) -> bool {
        self.untested.contains(&index) || self.single == Some(index)
            || self.tested.binary_search(&index).is_ok()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.tested.iter().copied().chain(self.single).chain(self.untested.clone())
    }

    fn mark_union(&self, union: &mut [bool]) {
        for index in self.tested.iter().copied().chain(self.single) {
            union[index] = true;
        }
        union[self.untested.clone()].fill(true);
    }
}

impl EvidenceContext {
    pub(super) fn zip_key_parameters(&self) -> impl Iterator<Item = super::zip::ZipKeyMaterial<'_>> + '_ {
        self.alternatives.iter().filter_map(|(context, _)| match context {
            PasswordContext::Zip(context) => context.kdf_parameters(),
            _ => None,
        })
    }

    pub(super) fn public_plan(&self) -> std::io::Result<Option<Arc<VolumeAttemptPlan>>> {
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
        self.verify_batch_with_zip_keys(candidates, fixed, complete, None)
    }

    pub(super) fn verify_batch_with_zip_keys(
        &self,
        candidates: &[Arc<str>],
        fixed: bool,
        complete: bool,
        zip_keys: Option<&super::zip::ZipKeyCache<'_>>,
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
        if !self.alternatives.is_empty() && self.alternatives.iter().all(|(context, _)| matches!(
            context, PasswordContext::SevenZip(super::seven_zip::SevenZipPasswordContext::MemberOnly)
        )) {
            let mut result = self.unresolved.as_ref().map_or_else(
                || PasswordVerification::status("unknown_needs_final_verifier", "7z payload requires member verification"),
                PreparedStatus::verification,
            );
            result.volume_attempts = self.public_plan()?;
            return Ok(result);
        }
        let rar_contexts = self.alternatives.iter().filter_map(|(context, _)| match context {
            PasswordContext::Rar(context) => Some(context.as_ref()),
            _ => None,
        });
        let rar_keys = super::rar::RarKeyCache::for_contexts(rar_contexts
            .chain(self.rar_anchor.as_deref())
            .chain(self.independent_rar.iter().filter_map(Option::as_deref)));
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
                let mut result = self.verify_inner(&survivors, confirmed, complete, &rar_keys, Some(anchor), None)?;
                if confirmed {
                    anchor_result.volume_attempts = result.volume_attempts;
                    return Ok(anchor_result);
                }
                if !matches!(result.status, "match" | "no_match") {
                    anchor_result.volume_attempts = result.volume_attempts;
                    return Ok(anchor_result);
                }
                result.restore_indices(indices, candidates.len());
                return Ok(result);
            }
        }
        self.verify_inner(candidates, fixed, complete, &rar_keys, None, zip_keys)
    }

    fn verify_inner(
        &self,
        candidates: &[Arc<str>],
        fixed: bool,
        complete: bool,
        rar_keys: &super::rar::RarKeyCache,
        screened_anchor: Option<&Arc<super::rar::RarPasswordContext>>,
        shared_zip_keys: Option<&super::zip::ZipKeyCache<'_>>,
    ) -> std::io::Result<PasswordVerification> {
        let cancellation = Cancellation::current();
        cancellation.check_io()?;
        let public_plan = self.public_plan()?;
        let plan = public_plan.as_deref().unwrap_or(&self.plan);
        use super::seven_zip::SevenZipVolumeScope;
        let seven_zip_scope = if matches!(&*plan.layouts, [layout] if
            (layout.minimum_slots == 0 || layout.minimum_slots == layout.slots.len()) &&
            layout.slots.iter().all(|slot| plan.domains[slot.domain].choices.len() == 1))
        {
            SevenZipVolumeScope::Unique
        } else if self.alternatives.len() == 1 && self.unresolved.is_none() {
            SevenZipVolumeScope::SharedProjection
        } else {
            SevenZipVolumeScope::SeparateProjections
        };
        let keys = SharedCandidateKeys::new(&self.alternatives, |context| {
            let context = match context {
                PasswordContext::SevenZip(context) => Some(context),
                _ => None,
            };
            context.into_iter().flat_map(|context| context.kdf_parameters())
        });
        let local_zip_keys;
        let zip_keys = if shared_zip_keys.is_some() || self.alternatives.len() <= 1 {
            shared_zip_keys
        } else {
            local_zip_keys = SharedCandidateKeys::from_parameters(self.zip_key_parameters());
            Some(&local_zip_keys)
        };
        let results: Vec<_> = self
            .alternatives
            .par_iter()
            .map(|(context, _)| {
                cancellation.run(|| match context {
                    PasswordContext::SevenZip(context) => context
                        .verify_cached(candidates, Some(&keys), seven_zip_scope),
                    PasswordContext::Zip(context) => context.verify_cached(
                        candidates,
                        zip_keys,
                        seven_zip_scope == SevenZipVolumeScope::Unique,
                    ),
                    PasswordContext::Rar(context) => {
                        if screened_anchor.is_some_and(|anchor| Arc::ptr_eq(context, anchor)) {
                            return Ok(PasswordVerification {
                                matched_index: Some(0),
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
        let survivors = |result| SurvivingCandidates::new(result, candidates.len());
        // A strong proof on one possible tail belongs to that tail. Another
        // tail may be a valid archive using a different configured password.
        let confirmed = results.iter().find_map(confirmed_password).filter(|&hit| {
            fixed
                || (self.unresolved.is_none()
                    && results.iter().all(|result| {
                        if confirmed_password(result) == Some(hit) { return true; }
                        let viable = survivors(result);
                        complete && viable.len() <= usize::from(viable.contains(hit))
                    }))
        });
        let mut removed: Vec<&VolumeProjection> = Vec::new();
        if let Some(index) = confirmed.or_else(|| fixed.then_some(0)) {
            // The plan has one confirmed password. Remove volume paths that
            // contradict it; there is no password/volume rule to carry onward.
            for ((_, projection), result) in self.alternatives.iter().zip(&results) {
                if !survivors(result).contains(index) {
                    removed.push(projection);
                } else {
                    removed.extend(result.scoped_rejections.0.iter().filter_map(|(path, rejected)| {
                        (*rejected == index).then_some(path.as_ref())
                    }));
                }
            }
        }
        let native_rejections = if let Some(index) = confirmed.or_else(|| fixed.then_some(0)) {
            let screened: HashMap<_, _> = self.alternatives.iter().zip(&results)
                .filter_map(|((context, _), result)| match context {
                    PasswordContext::Rar(context) => Some((Arc::as_ptr(context) as usize, survivors(result).contains(index))),
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
            public_plan
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
            let mut result = self.unresolved.as_ref().map_or_else(
                || PasswordVerification::status("unknown_needs_final_verifier", "no usable password proof"),
                PreparedStatus::verification,
            );
            result.volume_attempts = volume_attempts;
            return Ok(result);
        }
        let mut possible = self.unresolved.is_none().then(|| vec![false; candidates.len()]);
        let mut method = None;
        for result in &results {
            if result.status == "match" {
                method = match (method, result.match_evidence) {
                    (None, next) => next,
                    (old, next) if old == next => old,
                    _ => Some("mixed"),
                };
            }
            if let Some(mask) = &mut possible {
                let viable = survivors(result);
                if viable.len() == candidates.len() {
                    possible = None;
                } else {
                    viable.mark_union(mask);
                }
            }
        }
        let matches: Vec<_> = match possible {
            None => (0..candidates.len()).collect(),
            Some(mask) => mask.into_iter().enumerate().filter_map(|(i, yes)| yes.then_some(i)).collect(),
        };
        let mut password_domains = Vec::new();
        if !fixed && !matches.is_empty() {
            let mut ordinals = None;
            for (path, result) in results.iter().enumerate() {
                let viable = survivors(result);
                if viable.len() != matches.len() {
                    if password_domains.is_empty() {
                        password_domains.resize_with(results.len(), || None);
                    }
                    let ordinals = ordinals.get_or_insert_with(|| {
                        let mut ordinals = vec![usize::MAX; candidates.len()];
                        for (ordinal, &index) in matches.iter().enumerate() {
                            ordinals[index] = ordinal;
                        }
                        ordinals
                    });
                    password_domains[path] = Some(viable.iter().map(|index| ordinals[index]).collect());
                }
            }
        }
        let matched = !matches.is_empty();
        let fallback = self.unresolved.as_ref().map(PreparedStatus::verification);
        let message = fallback.as_ref().map(|result| result.message.as_str()).or_else(|| {
            results.iter().find(|result| !matches!(result.status, "match" | "no_match") || result.read_fault.is_some())
                .map(|result| result.message.as_str())
        }).or_else(|| results.iter().find(|result| result.status == "match").map(|result| result.message.as_str()));
        let summary = PasswordVerification::status(
            if matched { "match" } else { "no_match" },
            message.unwrap_or("password candidates screened against available volume evidence"),
        );
        let read_fault = fallback.and_then(|result| result.read_fault)
            .or_else(|| results.iter().find_map(|result| result.read_fault.clone()));
        Ok(PasswordVerification {
            password_domains,
            scoped_rejections: ScopedRejections(results.into_iter().flat_map(|result| result.scoped_rejections.0).collect()),
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
            read_fault,
            ..summary
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
        .map(|&projection| (projection, Rule::Remove))
        .collect();
    Ok(partition_from(plan, &rules, &[], None, &mut remove_terminal)?.0)
}

/// Worker results use the original request's source IDs. Subtract the actual
/// paths before reporting the plan so independent slot choices cannot recreate
/// a combination the decoder already rejected.
pub(crate) fn remove_scan_paths(
    plan: &VolumeAttemptPlan,
    selections: Vec<VolumeSelection>,
    prefixes: Vec<VolumeSelection>,
    layouts: Vec<usize>,
    first: Option<&VolumeSelection>,
) -> std::io::Result<VolumeAttemptPlan> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid worker volume result");
    let mut proof = VolumeProjection { roots: Vec::new(), edges: Vec::new(), ends: Vec::new() };
    let mut roots = HashMap::new();
    let mut edges = HashMap::new();
    let mut members = DomainMembers::default();
    if let Some(first) = first {
        plan.selected_parts_indexed(first, &mut members)?;
    }
    let mut nodes = 0;
    let mut node = || { nodes += 1; nodes };
    let start = first.map_or(0, |selection| selection.layout);
    let mut dropped = vec![false; plan.layouts.len()];
    for layout in layouts {
        *dropped.get_mut(layout).ok_or_else(invalid)? = true;
    }
    for (selection, prefix) in prefixes.into_iter().map(|value| (value, true))
        .chain(selections.into_iter().map(|value| (value, false))) {
        let layout = plan.layouts.get(selection.layout).ok_or_else(invalid)?;
        let used = selection.sources.len();
        let minimum = if layout.minimum_slots == 0 { layout.slots.len() } else { layout.minimum_slots };
        let count = if prefix { layout.slots.len() } else { used };
        if !(minimum..=layout.slots.len()).contains(&count)
            || (prefix && (minimum != count || used == 0 || used >= count)) {
            return Err(invalid());
        }
        if selection.layout < start || dropped[selection.layout] {
            continue;
        }
        let mut at = *roots.entry((selection.layout, count)).or_insert_with(&mut node);
        for (index, source) in selection.sources.into_iter().enumerate() {
            let slot = if index + 1 == count { layout.slots.last().unwrap() } else { &layout.slots[index] };
            if !members.contains(&plan.domains[slot.domain].choices, source) {
                return Err(invalid());
            }
            at = *edges.entry((at, source)).or_insert_with(&mut node);
        }
        proof.ends.push(at);
    }
    proof.roots.extend(roots.into_iter().map(|((layout, count), at)| [layout, count, at]));
    proof.edges.extend(edges.into_iter().map(|((from, source), to)| [from, to, source]));
    let (plan, _) = partition_from(plan, &[(&proof, Rule::RemovePrefix)], &dropped, first, &mut remove_terminal)?;
    Ok(plan)
}

// A terminal either removes a path or assigns its password domain. Prepared
// alternatives partition the byte observations. Paths without readable proof
// use domain zero, which contains every globally surviving candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule<'a> {
    Remove,
    RemovePrefix,
    Domain(usize),
    Reject(&'a [usize]),
}

type State = Vec<(usize, usize)>;
type Ends<'a> = HashMap<(usize, usize), Rule<'a>>;

fn remove_terminal(state: &State, ends: &Ends) -> Option<usize> {
    (!state.iter().any(|node| ends.contains_key(node))).then_some(0)
}

fn partition_from(
    plan: &VolumeAttemptPlan,
    rules: &[(&VolumeProjection, Rule)],
    dropped: &[bool],
    first: Option<&VolumeSelection>,
    terminal: &mut impl FnMut(&State, &Ends) -> Option<usize>,
) -> std::io::Result<(VolumeAttemptPlan, Vec<usize>)> {
    let tracks_domains = rules.iter().any(|(_, rule)| matches!(rule, Rule::Domain(_) | Rule::Reject(_)));
    let removes_prefixes = rules.iter().any(|(_, rule)| *rule == Rule::RemovePrefix);
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
        ends: &Ends,
        removes_prefixes: bool,
        terminal: &mut impl FnMut(&State, &Ends) -> Option<usize>,
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
                // A worker prefix rejects every continuation. Empty targets,
                // by contrast, mean the evidence stopped constraining the path.
                if removes_prefixes && state.iter().any(|node| ends.get(node) == Some(&Rule::RemovePrefix)) {
                    steps.push(None);
                    continue;
                }
                let mut targets = Vec::new();
                if !state.is_empty() {
                    for &source in domain.iter() {
                        #[cfg(test)]
                        PARTITION_EDGE_VISITS.with(|count| count.set(count.get() + 1));
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
                steps.push(Some(targets));
            }
            layers.push(steps);
            layer = next;
        }
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum Suffix {
            Group(usize),
            Node(usize),
        }
        let mut suffixes: Vec<Vec<Suffix>> = layer
            .iter()
            .map(|state| terminal(state, ends).map(Suffix::Group).into_iter().collect())
            .collect();
        let mut arena: Vec<(Arc<Vec<usize>>, Suffix)> = Vec::new();
        let mut unconstrained = Suffix::Group(0);
        for (domain, steps) in choices.iter().zip(layers).rev() {
            cancel.check_io()?;
            let mut intern = HashMap::<(Arc<Vec<usize>>, Suffix), Suffix>::new();
            let mut node = |choices: Arc<Vec<usize>>, tail| {
                *intern.entry((choices.clone(), tail)).or_insert_with(|| {
                    let id = Suffix::Node(arena.len());
                    arena.push((choices, tail));
                    id
                })
            };
            unconstrained = node(domain.clone(), unconstrained);
            suffixes = steps
                .into_iter()
                .map(|targets| {
                    let Some(targets) = targets else { return Vec::new(); };
                    if targets.is_empty() {
                        return vec![unconstrained];
                    }
                    let mut output = Vec::new();
                    let mut group = Vec::new();
                    let mut common = Suffix::Group(0);
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
                while let Suffix::Node(node) = id {
                    let (choices, next) = &arena[node];
                    path.push(choices.clone());
                    id = *next;
                }
                let Suffix::Group(group) = id else { unreachable!() };
                (path, group)
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
            let slots = &layout.slots[..count];
            let choices: Vec<_> = slots[..count - 1].iter()
                .chain(&layout.slots[maximum - 1..])
                .map(|slot| Arc::clone(&plan.domains[slot.domain].choices))
                .collect();
            let mut keep = |remaining: Vec<Arc<Vec<usize>>>, group| {
                let mut slots = slots.to_vec();
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
                if tracks_domains {
                    layout_groups.push(group);
                }
            };
            match frontier {
                None => {
                    for (remaining, group) in subtract(&choices, state, &edges, &ends, removes_prefixes, terminal)? {
                        keep(remaining, group);
                    }
                }
                Some(selection) => {
                    visit_ordered_suffix(&choices, &selection.sources, |suffix| {
                        for (remaining, group) in subtract(suffix, state.clone(), &edges, &ends, removes_prefixes, terminal)? {
                            keep(remaining, group);
                        }
                        Ok(())
                    })?;
                }
            }
        }
    }
    Ok((plan.with_remaining(layouts, domains), layout_groups))
}

fn visit_ordered_suffix(
    choices: &[Arc<Vec<usize>>], first: &[usize],
    mut visit: impl FnMut(&[Arc<Vec<usize>>]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut path: Vec<_> = first.iter().map(|source| Arc::new(vec![*source])).collect();
    let mut restore_end = choices.len();
    for index in (0..choices.len()).rev() {
        let domain = &choices[index];
        let position = domain.iter().position(|source| *source == first[index]).unwrap();
        let start = position + usize::from(index + 1 != choices.len());
        if start == domain.len() { continue; }
        // The previous suffix already restored everything past its pivot.
        let restore = index + 1..restore_end;
        #[cfg(test)]
        FRONTIER_RESTORED_CHOICES.with(|count| count.set(count.get() + restore.len()));
        path[restore.clone()].clone_from_slice(&choices[restore]);
        path[index] = if start == 0 { domain.clone() } else { Arc::new(domain[start..].to_vec()) };
        visit(&path)?;
        restore_end = index + 1;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FRONTIER_RESTORED_CHOICES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PARTITION_EDGE_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "../../tests/unit/password/evidence_tests.rs"]
mod tests;
