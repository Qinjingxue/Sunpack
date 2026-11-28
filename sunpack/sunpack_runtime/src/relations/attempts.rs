//! Sparse, ordered hypotheses. Only slot domains cross the execution boundary;
//! their Cartesian product is never allocated or probed during discovery.
use super::assignment::{materialize, proposal_facts, BucketView, VolumeAssignment};
use super::filename::NameProfile;
use super::*;
use crate::collections::SmallOrderedSet;
use crate::io::archive_state::{
    PhysicalRanges, TailTotal, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot,
};
use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hash, Hasher};

#[cfg(test)]
#[path = "../../tests/unit/relations/attempt_views.rs"]
mod view_tests;

#[derive(Debug)]
pub(super) struct VolumeAttempts {
    pub sources: Vec<AttemptSource>,
    // Initial sources are in group path order, one per physical file. Carrier
    // variants append ranges for those same paths without adding group members.
    base_source_count: usize,
    pub layouts: Vec<AttemptLayout>,
    // Co-located ZIP heads matched by the same directory but eliminated by
    // slot geometry. Discovery uses this proof to retire old missing plans.
    pub excluded_heads: Box<[Arc<VolumeAnchor>]>,
    pub directory_id: Option<Arc<str>>,
    pub head_size_from_total: Option<u64>,
    pub minimum_size: Option<u64>,
    pub tail_totals: Vec<(usize, u64)>,
}

#[derive(Debug)]
pub(super) struct AttemptLayout {
    pub slots: Vec<(u32, Arc<Vec<usize>>)>,
    // One maximum prefix and terminal domain represent every admitted length.
    // Zero denotes an ordinary fixed layout.
    pub minimum_slots: usize,
}

#[derive(Default)]
struct Layouts {
    rows: Vec<AttemptLayout>,
    by_hash: HashMap<u64, SmallOrderedSet<usize>>,
}

impl Layouts {
    fn push(&mut self, slots: Vec<(u32, Arc<Vec<usize>>)>, minimum_slots: usize) {
        // Interned domain identities avoid rehashing large shared slot domains.
        // Keep one index per layout and check equality if hashes coincide.
        let mut hash = self.by_hash.hasher().build_hasher();
        minimum_slots.hash(&mut hash);
        for (number, domain) in &slots {
            number.hash(&mut hash);
            Arc::as_ptr(domain).hash(&mut hash);
        }
        let index = self.rows.len();
        match self.by_hash.entry(hash.finish()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(SmallOrderedSet::One(index));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().iter().any(|&index| {
                    let row = &self.rows[index];
                    row.minimum_slots == minimum_slots && row.slots == slots
                }) {
                    return;
                }
                entry.get_mut().insert(index);
            }
        }
        self.rows.push(AttemptLayout { slots, minimum_slots });
    }
}

impl VolumeAttempts {
    pub(super) fn base_sources(&self) -> &[AttemptSource] {
        &self.sources[..self.base_source_count]
    }

    // Several terminal directories can validate the same logical head. Retain
    // each directory's layouts as alternatives of one input, so a damaged
    // earlier tail cannot retire a later one. Domains stay local to a layout.
    pub(super) fn join_zip_directories(plans: Vec<Self>) -> Self {
        let totals: Vec<HashMap<_, _>> = plans.iter().map(|p| p.tail_totals.iter().copied().collect()).collect();
        let mut sources = Vec::new();
        let mut indexes = HashMap::new();
        let mut tail_totals = Vec::new();
        let mut intern = |p: usize, i: usize| {
            let s = &plans[p].sources[i];
            let total = totals[p].get(&i).copied();
            *indexes.entry((s.key_with_end(s.end), total)).or_insert_with(|| {
                let index = sources.len();
                sources.push(s.clone());
                if let Some(total) = total { tail_totals.push((index, total)); }
                index
            })
        };
        let mut base = HashSet::new();
        for (p, plan) in plans.iter().enumerate() {
            for (i, s) in plan.base_sources().iter().enumerate() {
                if base.insert(&s.path) { intern(p, i); }
            }
        }
        let mut domains = Domains::default();
        let mut layouts = Layouts::default();
        for (p, plan) in plans.iter().enumerate() {
            let remap: Vec<_> = (0..plan.sources.len()).map(|i| intern(p, i)).collect();
            let mut mapped = HashMap::new();
            for layout in &plan.layouts {
                let slots = layout.slots.iter().map(|(n, choices)| {
                    let domain = mapped.entry(Arc::as_ptr(choices)).or_insert_with(|| {
                        let mut indexes: Vec<_> = choices.iter().map(|&i| remap[i]).collect();
                        if indexes.len() > 1 {
                            let mut seen = HashSet::new();
                            indexes.retain(|&i| seen.insert(i));
                        }
                        domains.intern(indexes)
                    });
                    (*n, Arc::clone(domain))
                }).collect();
                layouts.push(slots, layout.minimum_slots);
            }
        }
        Self { directory_id: plans[0].directory_id.clone(), sources, base_source_count: base.len(), layouts: layouts.rows, tail_totals,
            minimum_size: plans.iter().map(|p| p.minimum_size).min().flatten(),
            head_size_from_total: plans[0].head_size_from_total,
            excluded_heads: plans.into_iter().flat_map(|p| p.excluded_heads.into_vec()).collect() }
    }

    // PKZIP disk offsets are relative to each disk, not to the concatenated
    // archive. Reuse the unique mapping's geometry and represent each possible
    // common disk size with ordinary range/domain layouts (no second protocol).
    fn with_spanned_carrier(mut self, head: &VolumeAnchor) -> Self {
        let fixed_head_size = (!head.has_unresolved_carrier_extent()).then(|| head.payload_size());
        let distinct_base_paths = self.base_source_count == self.sources.len();
        if fixed_head_size.is_some() && (distinct_base_paths || !self.layouts.iter().any(|layout| {
            let slots = &layout.slots;
            slots.len() > 2 && slots[1..slots.len() - 1].iter().any(|(_, choices)| choices.len() > 1)
        })) {
            return self;
        }
        let original = std::mem::take(&mut self.layouts);
        let mut domains = Domains::default();
        // Original layouts already share interned domains. Seed the interner
        // so trimmed layouts can reuse an original domain of equal contents.
        let mut original_domains = HashSet::new();
        for (_, domain) in original.iter().flat_map(|layout| &layout.slots) {
            if original_domains.insert(Arc::as_ptr(domain)) {
                domains.0.insert(Arc::clone(domain));
            }
        }
        drop(original_domains);
        let mut layouts = Layouts::default();
        let mut sources_by_extent = None;
        let mut variants = Vec::new();
        let mut disk_domains = HashMap::new();
        for AttemptLayout { slots: layout, minimum_slots } in original {
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
                if !interior || fixed_head_size.is_some() {
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
            let from_tail = sizes.is_none() && fixed_head_size.is_none();
            let mut sizes: Vec<_> = match (fixed_head_size, sizes) {
                (Some(size), _) => vec![size],
                (_, Some(common)) => common.into_iter().collect(),
                _ => layout.last().into_iter().flat_map(|(_, choices)| choices.iter())
                    .filter_map(|i| self.sources[*i].head_size).collect(),
            };
            sizes.sort_unstable();
            sizes.dedup();
            for size in sizes {
                let Some(end) = head.structure_offset.unwrap_or(0).checked_add(size).filter(|_| size > 0) else {
                    continue;
                };
                let mut trimmed = Vec::with_capacity(layout.len());
                for (number, choices) in &layout {
                    let domain = if *number == 1 {
                        let mut replacements = Vec::new();
                        for &i in choices.iter() {
                            let source = &self.sources[i];
                            // A known head can rank equal-sized disks without changing its range.
                            if fixed_head_size.is_some() {
                                if source.end - source.start == size { replacements.push(i); }
                                continue;
                            }
                            if end > source.end {
                                continue;
                            }
                            if distinct_base_paths && end == source.end {
                                replacements.push(i);
                                continue;
                            }
                            // Index all source attributes so equal variants keep
                            // the first index, including an existing base extent.
                            let source_indexes = sources_by_extent.get_or_insert_with(|| {
                                let mut indexes = HashMap::new();
                                if !distinct_base_paths {
                                    for (index, original) in self.sources.iter().enumerate() {
                                        indexes.entry(original.key_with_end(original.end)).or_insert(index);
                                    }
                                }
                                indexes
                            });
                            let index = *source_indexes.entry(source.key_with_end(end)).or_insert_with(|| {
                                let index = self.sources.len() + variants.len();
                                variants.push(AttemptSource { end, ..source.clone() });
                                index
                            });
                            replacements.push(index);
                        }
                        if replacements.is_empty() {
                            break;
                        }
                        domains.intern(replacements)
                    } else if interiors[&Arc::as_ptr(choices)] || from_tail {
                        let interior = interiors[&Arc::as_ptr(choices)];
                        let by_size = disk_domains
                            .entry(Arc::as_ptr(choices))
                            .or_insert_with(|| {
                                let mut by_size = HashMap::<_, Vec<_>>::new();
                                for &i in choices.iter() {
                                    let source = &self.sources[i];
                                    let size = if interior {
                                        Some(source.end - source.start)
                                    } else {
                                        source.head_size
                                    };
                                    if let Some(size) = size.filter(|n| fixed_head_size.is_none_or(|head| head == *n)) {
                                        by_size.entry(size).or_default().push(i);
                                    }
                                }
                                by_size.into_iter().map(|(size, group)| {
                                    (size, domains.intern(group))
                                }).collect::<HashMap<_, _>>()
                            });
                        let Some(domain) = by_size.get(&size) else { break; };
                        Arc::clone(domain)
                    } else {
                        Arc::clone(choices)
                    };
                    trimmed.push((*number, domain));
                }
                if trimmed.len() == layout.len() {
                    layouts.push(trimmed, minimum_slots);
                }
            }
            // Equal disk size is a geometry hypothesis, not format identity.
            // Retain the original for nonuniform disks and unpadded carriers.
            layouts.push(layout, minimum_slots);
        }
        drop(sources_by_extent);
        self.layouts = layouts.rows;
        self.sources.extend(variants);
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

#[derive(Debug, Clone)]
pub(super) struct AttemptSource {
    pub view: Option<Arc<crate::io::view::ReadView>>,
    pub path: String,
    pub start: u64,
    pub end: u64,
    pub proven_end: Option<u64>,
    pub terminal: bool,
    pub head_size: Option<u64>,
}
impl AttemptSource {
    fn key_with_end(&self, end: u64) -> (Option<&crate::io::view::ReadView>, &str, u64, u64, Option<u64>, bool, Option<u64>) {
        (self.view.as_deref(), &self.path, self.start, end, self.proven_end, self.terminal, self.head_size)
    }

    fn new(path: &str, anchor: &VolumeAnchor) -> Self {
        Self {
            view: anchor.view.clone(),
            path: path.into(),
            start: anchor.structure_offset.unwrap_or(0),
            end: anchor
                .carrier_limit
                .map_or(anchor.extent_end(), |limit| limit.min(anchor.extent_end())),
            proven_end: anchor.proven_extent_end(),
            terminal: anchor.has_any(TERMINAL),
            head_size: anchor.zip_head_size,
        }
    }
}

pub(super) fn zip_total(anchor: &VolumeAnchor) -> Option<u64> {
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

fn group_head_views(view: &BucketView<'_>, heads: &mut Vec<(usize, usize)>, raw_zip: bool) -> HashMap<usize, Vec<usize>> {
    // Group only heads at the same logical position with compatible structure.
    let mut equivalent = HashMap::new();
    let mut aliases = HashMap::<usize, Vec<usize>>::new();
    if heads.len() > 1 {
        let mut repeated = HashSet::new();
        let mut paths = HashSet::new();
        let mut rar_ends = HashMap::new();
        let mut zip_markers = HashSet::new();
        for &(i, _) in heads.iter() {
            let a = view.rows[i].anchor.as_ref().unwrap();
            if a.format == "rar" {
                if let Some(end) = a.proven_extent_end() {
                    rar_ends.entry((&view.rows[i].path_key, a.structure_offset)).and_modify(|value| {
                        if *value != Some(end) { *value = None; }
                    }).or_insert(Some(end));
                }
            }
            if a.has_any(ZIP_SPLIT_START) {
                zip_markers.insert((&view.rows[i].path_key, a.structure_offset));
            }
            if !paths.insert(&view.rows[i].path_key) { repeated.insert(&view.rows[i].path_key); }
        }
        heads.retain(|&(i, _)| {
            let a = view.rows[i].anchor.as_ref().unwrap();
            if !repeated.contains(&view.rows[i].path_key) || (a.has_unresolved_carrier_extent() && a.format == "rar") {
                return true;
            }
            let mut rar_prefix = None;
            let mut zip_local = None;
            if a.format == "rar" {
                // In a header-preserving mask, RAR can accept both the exact
                // disk and one with trailing disguise bytes. Compare only the
                // prefix; the rest must map to identical physical positions.
                let start = a.structure_offset.unwrap_or(0);
                let end = a.proven_extent_end().or_else(|| rar_ends
                    .get(&(&view.rows[i].path_key, a.structure_offset)).copied().flatten()).unwrap_or(a.size);
                if end <= start || end > a.size { return true; }
                let prefix_end = start.saturating_add(512).min(end);
                let Ok(bytes) = a.open().and_then(|r| r.read_direct_at(start, (prefix_end - start) as usize)) else { return true };
                let suffix = crate::io::archive_state::PhysicalRanges::new(a.view.as_deref(), prefix_end, Some(end));
                rar_prefix = Some((bytes, suffix));
            } else if zip_markers.contains(&(&view.rows[i].path_key, a.structure_offset)) {
                // The split signature proves the role, the first local record
                // separates different ZIP families at this disk coordinate.
                let Some(at) = a.structure_offset.unwrap_or(0).checked_add(4) else { return true };
                let Ok(Some(key)) = crate::formats::zip::relation_local_key(&a.path, a.view.as_ref(), at) else { return true };
                zip_local = Some(key);
            } else if a.proven_extent_end().is_some() || !(raw_zip
                || a.has_any(ZIP_DIRECTORY_MEMBER) || a.seven_zip_next_header.is_some()) {
                return true;
            }
            let descriptor = a.seven_zip_next_header.as_ref().map(|h| (h.offset, h.size, h.crc));
            let key = (&view.rows[i].path_key, a.structure_offset, a.has_unresolved_carrier_extent(), descriptor, rar_prefix, zip_local);
            match equivalent.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => { entry.insert(i); true }
                std::collections::hash_map::Entry::Occupied(entry) => {
                    aliases.entry(*entry.get()).or_default().push(i);
                    false
                }
            }
        });
    }
    aliases
}

// The directory fixes the bytes preceding its disk. Even the shortest
// distinct raw chunks must fit within that prefix.
fn raw_zip_disk_bound<'a>(view: &BucketView<'_>, indexes: &[usize], heads: impl Iterator<Item = &'a usize>) -> Option<u32> {
    let before = indexes.iter().filter_map(|i| {
        let a = view.rows[*i].anchor.as_ref()?;
        if !a.has_any(TERMINAL) { return None; }
        zip_total(a)?.checked_sub(a.payload_size())
    }).max()?;
    let head_min = heads.map(|i| {
        let a = view.rows[*i].anchor.as_ref().unwrap();
        if a.has_unresolved_carrier_extent() { 1 } else { a.payload_size() }
    }).min()?;
    let mut available = before.saturating_sub(head_min);
    let mut unique = HashSet::new();
    let mut lengths = Vec::new();
    for &i in indexes {
        let Some(a) = &view.rows[i].anchor else { continue };
        if view.facts[&i].exact_slot != Some(1) && !a.has_any(TERMINAL) {
            // Raw continuation sources consume the whole admitted slice. Use
            // the same identity as projection, including bounded prefixes.
            let runs = PhysicalRanges::new(a.view.as_deref(), 0, Some(a.size));
            if unique.insert((&view.rows[i].path, runs)) {
                lengths.push(a.size);
            }
        }
    }
    lengths.sort_unstable();
    let count = lengths.iter().take_while(|&&size| {
        if size > available { return false; }
        available -= size;
        true
    }).count();
    u32::try_from(count).ok()?.checked_add(2)
}

// The directory fixes the prefix sum. Propagate this constraint into each
// slot before password analysis can expand its possible logical offsets.
fn prune_raw_zip_lengths(
    view: &BucketView<'_>, slots: &mut BTreeMap<u32, Arc<Vec<usize>>>, domains: &mut Domains,
) -> bool {
    let last = *slots.last_key_value().unwrap().0;
    let lengths = |number, index: usize| -> Option<(i128, i128)> {
        let a = view.rows[index].anchor.as_ref()?;
        if number == last {
            let preceding = i128::from(zip_total(a)?.checked_sub(a.payload_size())?);
            return Some((-preceding, -preceding));
        }
        let bytes = if number == 1 { a.size.checked_sub(a.structure_offset.unwrap_or(0))? } else { a.size };
        Some((if number == 1 && a.has_unresolved_carrier_extent() { 1 } else { bytes.into() }, bytes.into()))
    };
    let mut bounds = HashMap::new();
    let mut total = (0i128, 0i128);
    for (&number, choices) in slots.iter() {
        let key = (Arc::as_ptr(choices), number == 1, number == last);
        let (lo, hi) = *bounds.entry(key).or_insert_with(|| {
            choices.iter().filter_map(|&i| lengths(number, i)).fold(
                (i128::MAX, i128::MIN), |(lo, hi), (a, b)| (lo.min(a), hi.max(b)))
        });
        if lo > hi { return false; }
        total.0 += lo;
        total.1 += hi;
    }
    if total.0 > 0 || total.1 < 0 { return false; }
    let mut pruned = HashMap::new();
    for (&number, choices) in slots.iter_mut() {
        let key = (Arc::as_ptr(choices), number == 1, number == last);
        let filtered = pruned.entry(key).or_insert_with(|| {
            let (lo, hi) = bounds[&key];
            let allowed = |i| lengths(number, i).is_some_and(|(a,b)| {
                total.0 - lo + a <= 0 && total.1 - hi + b >= 0
            });
            if choices.iter().all(|&i| allowed(i)) { Arc::clone(choices) }
            else { domains.intern(choices.iter().copied().filter(|&i| allowed(i)).collect()) }
        });
        if filtered.is_empty() { return false; }
        *choices = Arc::clone(filtered);
    }
    true
}

pub(super) fn build(
    view: &BucketView<'_>,
    logical: Option<&str>,
    raw_zip_minimum: Option<u64>,
) -> Vec<ProposalValidation> {
    let Some(first) = view.indexes.iter().position(|index| view.facts[index].exact_slot == Some(1)) else {
        return Vec::new();
    };
    let mut heads = vec![(view.indexes[first], first)];
    let mut indexes = view.indexes[..first].to_vec();
    for &index in &view.indexes[first + 1..] {
        if view.facts[&index].exact_slot == Some(1) {
            heads.push((index, indexes.len()));
        } else {
            indexes.push(index);
        }
    }
    if indexes.is_empty() {
        return Vec::new();
    }
    heads.sort_by(|(a, _), (b, _)| view.rows[*a].path_key.cmp(&view.rows[*b].path_key));
    // Keep one slot for the current head. Moving it preserves the source
    // order used by the layout builder without scanning the other heads.
    let mut head_position = indexes.len();
    indexes.push(heads[0].0);
    let spanned = view.spanned();
    let aliases = group_head_views(view, &mut heads, raw_zip_minimum.is_some());
    let mut output = Vec::new();
    let mut shared_facts = None;
    for (head, position) in heads {
        if position < head_position {
            indexes[position..=head_position].rotate_right(1);
        } else if position > head_position {
            indexes[head_position..=position].rotate_left(1);
        }
        head_position = position;
        indexes[position] = head;
        let raw_upper = std::cell::OnceCell::new();
        let profile = NameProfile::new(indexes.iter().filter_map(|i| view.features.get(i)));
        let mut fixed = BTreeMap::<u32, Vec<usize>>::new();
        for &i in &indexes {
            if let Some(n) = view.facts[&i].exact_slot {
                if view.legal(i, n, None) {
                    fixed.entry(n).or_default().push(i);
                }
            }
        }
        let Some(first_choices) = fixed.get_mut(&1) else { continue };
        if let Some(views) = aliases.get(&head) { first_choices.extend_from_slice(views); }
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
        let mut layouts = Layouts::default();
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
            let upper = if unnamed_tail && raw_zip_minimum.is_some() {
                let bound = raw_upper.get_or_init(|| raw_zip_disk_bound(view, &indexes,
                    std::iter::once(&head).chain(aliases.get(&head).into_iter().flatten())));
                upper.map(|n| bound.map_or(n, |bound| n.min(bound)))
            } else { upper };
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
                // A native ZIP terminal fixes the actual disk count. In the
                // loose tier, a name only ranks unanchored disks for a slot.
                let spanned_name_hints = spanned && channel.is_none()
                    && candidate_terminal.is_some_and(|end| {
                        end as usize <= indexes.len()
                            && slots.get(&end).is_some_and(|choices| {
                                choices.iter().any(|i| view.facts[i].terminal)
                            })
                    });
                if !spanned_name_hints {
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
                }
                // Fill a finite, evidence-bounded gap from otherwise unnumbered
                // members. Never allocate up to a huge filename/terminal number.
                let bound = candidate_terminal.or_else(|| slots.last_key_value().map(|(&n, _)| n));
                if let Some(end) = bound.filter(|end| *end as usize <= indexes.len()) {
                    let assigned: HashSet<_> = if spanned_name_hints {
                        HashSet::new()
                    } else {
                        slots.values().flat_map(|c| c.iter()).copied().collect()
                    };
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
                let mut unnamed_interior = None;
                for (&number, choices) in &mut slots {
                    let fixed = fixed_numbers.contains(&number);
                    let first = number == 1;
                    let terminal = candidate_terminal == Some(number);
                    let width_number = width_numbers.contains(&number).then_some(number);
                    let key = (
                        Arc::as_ptr(choices),
                        first,
                        terminal,
                        fixed,
                        width_number,
                    );
                    if let Some((_, ordered)) = ordered_domains.get(&key) {
                        *choices = Arc::clone(ordered);
                        continue;
                    }
                    // Consume one domain at a time: never retain G copies of
                    // U gap members while sorting/interning.
                    let mut ordered = (**choices).clone();
                    if channel.is_none() && !spanned_name_hints && !fixed {
                        // Structurally owned unnamed members remain candidates.
                        let unnamed = || indexes.iter().copied().filter(|i| {
                            view.facts[i].owned
                                && view.facts[i].exact_slot.is_none()
                                && view.legal(*i, number, candidate_terminal)
                        });
                        if first || terminal {
                            ordered.extend(unnamed());
                        } else {
                            // Slots were already bounded by the candidate end.
                            // All interior slots share the same unnamed domain.
                            let candidates = unnamed_interior.get_or_insert_with(|| unnamed().collect::<Vec<_>>());
                            ordered.extend_from_slice(candidates);
                        }
                    }
                    ordered.sort_by(|&a, &b| {
                        let remote = |i: usize| Path::new(&view.rows[i].path).parent() != head_parent;
                        remote(a).cmp(&remote(b)).then_with(|| {
                            let Some(number) = width_number else {
                                return std::cmp::Ordering::Equal;
                            };
                            let width = |i: usize| view.features.get(&i).and_then(|features| {
                                features.numbers.iter()
                                    .filter(|n| n.value == number && profile.active(n))
                                    .map(|n| n.width)
                                    .min()
                            }).unwrap_or(usize::MAX);
                            width(a).cmp(&width(b))
                        }).then_with(|| view.rows[a].path_key.cmp(&view.rows[b].path_key)).then_with(|| a.cmp(&b))
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
                // In a raw ZIP the directory offset fixes the bytes preceding
                // its disk. Competing views can expose identical local records
                // while adding bytes that no layout of the remaining disks fits.
                if raw_zip_minimum.is_some() && minimum == 0 && contiguous
                    && candidate_terminal == slots.last_key_value().map(|(&n, _)| n)
                {
                    if !prune_raw_zip_lengths(view, &mut slots, &mut domains) { continue; }
                }
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
                                    let size = view.rows[i].anchor.as_deref().map_or(0, |a| {
                                        if raw_zip_minimum.is_some() && i != head && !a.has_any(TERMINAL) {
                                            a.size
                                        } else {
                                            a.payload_size()
                                        }
                                    });
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
                                .finish_mapping(representative, slack, raw_zip_minimum.is_some())
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
                    if !all_unnamed {
                        layouts.push(layout, 0);
                    }
                    if has_tails {
                        layouts.push(family, minimum);
                    }
                    // A numbered tail only belongs at its stated position;
                    // keep its ordinary layout instead of moving it with the family.
                    continue;
                }
                layouts.push(layout, 0);
            }
        }
        let Layouts { rows: mut layouts, by_hash } = layouts;
        drop(by_hash);
        if layouts.is_empty() {
            continue;
        }
        // Contiguous layouts get first chance; stable sort retains evidence
        // tier priority. Incomplete layouts remain useful for partial recovery.
        layouts.sort_by_key(|AttemptLayout { slots: layout, .. }| {
            (
                !layout
                    .iter()
                    .zip(1u32..)
                    .all(|((n, _), expected)| *n == expected),
                std::cmp::Reverse(layout.len()),
            )
        });
        // Intermediate domains can lose all their layouts during geometry
        // filtering. Publish only sources reachable from a surviving slot.
        let mut live_domains = HashSet::new();
        let mut sources: Vec<usize> = layouts.iter().flat_map(|layout| &layout.slots)
            .filter_map(|(_, domain)| live_domains.insert(Arc::as_ptr(domain)).then_some(domain))
            .flat_map(|c| c.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        sources.sort_unstable_by_key(|i| (*i != head, *i));
        let mut physical = HashSet::new();
        let mut variants = Vec::new();
        sources.retain(|i| {
            if physical.insert(view.rows[*i].path_key.as_str()) { true }
            else { variants.push(*i); false }
        });
        let base_source_count = sources.len();
        sources.extend(variants);
        let positions: HashMap<_, _> = sources.iter().enumerate().map(|(n, i)| (*i, n)).collect();
        let assignment = VolumeAssignment {
            slots: BTreeMap::from([(1, head)]),
            ..Default::default()
        };
        let facts = shared_facts.get_or_insert_with(|| proposal_facts(view, &[]));
        let head_anchor = view.rows[head].anchor.as_ref().unwrap();
        let head_logical;
        let logical = if let Some(logical) = logical { logical } else {
            head_logical = super::filename::logical_name(view.rows[head].name(),
                &view.features[&head], view.format);
            &head_logical
        };
        let mut proposal = materialize(view, assignment, logical, None, Some(facts)).unwrap();
        // The head identity is confirmed; its volume composition remains a plan.
        // No speculative bytes are parsed again here.
        proposal.status = ProposalStatus::Valid;
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
        let mut remapped = HashMap::new();
        proposal.attempts = Some(VolumeAttempts {
            directory_id: None,
            head_size_from_total,
            excluded_heads: Box::default(),
            tail_totals,
            minimum_size: raw_zip_minimum.or(minimum_size),
            base_source_count,
            sources: sources
                .iter()
                .map(|i| {
                    let anchor = view.rows[*i].anchor.as_ref().unwrap();
                    let mut source = AttemptSource::new(&view.rows[*i].path, anchor);
                    if raw_zip_minimum.is_some() {
                        if view.facts[i].exact_slot == Some(1) && trim_head {
                            // A nested ZIP may begin inside the first chunk.
                            // The selected tail and continuations give the
                            // outer head's end, up to the physical file limit.
                            source.end = anchor.size;
                        } else if view.facts[i].exact_slot != Some(1) && !source.terminal {
                            // A member header inside a raw continuation does
                            // not change the start of that volume.
                            source.start = 0;
                            source.end = anchor.size;
                            source.proven_end = None;
                            source.head_size = None;
                        }
                    }
                    source
                })
                .collect(),
            layouts: layouts
                .into_iter()
                .map(|AttemptLayout { slots: layout, minimum_slots }| AttemptLayout {
                    minimum_slots,
                    slots: layout
                        .into_iter()
                        .map(|(number, choices)| {
                            let mapped = remapped.entry(Arc::as_ptr(&choices)).or_insert_with(|| {
                                Arc::new(choices.iter().map(|i| positions[i]).collect::<Vec<_>>())
                            });
                            (number, Arc::clone(mapped))
                        })
                        .collect(),
                })
                .collect(),
        });
        output.push(proposal);
    }
    output
}

impl VolumeAttempts {
    pub(super) fn project(&self, proposal: &RelationProposal, style: &str) -> VolumeAttemptPlan {
        let zip_spanned = proposal.style == "zip_spanned";
        // Root and embedded facts may normalize to the same disk extent.
        // Intern after carrier geometry so the verifier and the worker see one
        // source per byte sequence and cannot consume its duplicate as a disk.
        let mut sources = Vec::with_capacity(self.sources.len());
        let mut remap = Vec::new();
        let mut tail_totals = Vec::new();
        let mut indexed = HashMap::new();
        let totals: HashMap<_, _> = self.tail_totals.iter().copied().collect();
        let variants = self.sources.len() != self.base_source_count;
        for (i, source) in self.sources.iter().enumerate() {
            let total = totals.get(&i).copied();
            let next = sources.len();
            if variants {
                // A file-level transform may move the same ordered runs to a
                // different logical offset. They still represent one disk.
                let runs = PhysicalRanges::new(
                    source.view.as_deref(), source.start, Some(source.end),
                );
                let key = (&source.path, runs, total);
                let index = *indexed.entry(key).or_insert(next);
                remap.push(index);
                if index != next { continue; }
            }
            if let Some(total) = total { tail_totals.push(TailTotal { source: next, total }); }
            sources.push(InputExtent { path: source.path.clone(), view: source.view.clone(),
                start: source.start, end: Some(source.end) });
        }
        let collapsed = sources.len() < self.sources.len();
        let mut domains = Vec::new();
        let mut domain_indexes = HashMap::new();
        let layouts = self
            .layouts
            .iter()
            .map(|AttemptLayout { slots: layout, minimum_slots }| {
                let slots = layout
                    .iter()
                    .map(|&(number, ref choices)| {
                        let (domain, terminal) = *domain_indexes
                            .entry(Arc::as_ptr(choices))
                            .or_insert_with(|| {
                                let index = domains.len();
                                let mapped = if collapsed {
                                    let mut seen = HashSet::new();
                                    Arc::new(choices.iter().map(|&i| remap[i]).filter(|i| seen.insert(*i)).collect())
                                } else { Arc::clone(choices) };
                                domains.push(VolumeDomain { choices: mapped });
                                (index, zip_spanned && choices.iter().all(|&i| self.sources[i].terminal))
                            });
                        VolumeSlot {
                            number,
                            canonical_name: canonical_volume_name(
                                &proposal.logical_name,
                                number,
                                style,
                                proposal.width,
                                terminal,
                            ),
                            domain,
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
                VolumeLayout {
                    slots,
                    minimum_slots: *minimum_slots,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        VolumeAttemptPlan {
            sources: sources.into_boxed_slice(),
            domains: domains.into_boxed_slice(),
            layouts,
            head_size_from_total: self.head_size_from_total,
            minimum_size: self.minimum_size,
            tail_totals: tail_totals.into_boxed_slice(),
        }
    }
}
