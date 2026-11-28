//! Demand-driven byte evidence over unresolved volume layouts.
//! Paths merge at equal logical positions; only bytes actually requested by a
//! format parser split a projection. Candidate KDFs run after preparation.
use crate::io::archive_state::{InputExtent, VolumeAttemptPlan, VolumeLayout};
use crate::io::cancellation::Cancellation;
use crate::io::reader::{ManagedReader, NativeArchiveSession};
use crate::password::context::PreparedStatus;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, OnceLock};

#[path = "../relations/packed_crc.rs"]
mod packed_crc;
pub(crate) use packed_crc::PackedCrcs;

#[cfg(test)]
thread_local! {
    static EDGE_READS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static DISK_EDGE_VISITS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static LOGICAL_EDGE_VISITS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn count_edge_reads<T>(read: impl FnOnce() -> T) -> (T, usize) {
    EDGE_READS.with(|reads| {
        let previous = reads.replace(Some(0));
        let result = read();
        (result, reads.replace(previous).unwrap())
    })
}

#[cfg(test)]
pub(super) fn count_disk_edges<T>(read: impl FnOnce() -> T) -> (T, usize) {
    DISK_EDGE_VISITS.with(|visits| {
        let previous = visits.replace(Some(0));
        let result = read();
        (result, visits.replace(previous).unwrap())
    })
}

#[cfg(test)]
pub(super) fn count_logical_edges<T>(read: impl FnOnce() -> T) -> (T, usize) {
    LOGICAL_EDGE_VISITS.with(|visits| {
        let previous = visits.replace(Some(0));
        let result = read();
        (result, visits.replace(previous).unwrap())
    })
}

struct AttemptFile {
    path: String,
    reader: OnceLock<Result<ManagedReader, String>>,
}

impl AttemptFile {
    fn open(&self) -> Result<&ManagedReader, &String> {
        self.reader
            .get_or_init(|| ManagedReader::open(&self.path).map_err(|error| error.to_string()))
            .as_ref()
    }
}

struct AttemptSource {
    view: Option<Arc<crate::io::view::ReadView>>,
    file: Arc<AttemptFile>,
    start: u64,
    len: Option<u64>,
}

// Valid only inside this preparation: all sources of one path share the same
// live AttemptFile. A logical source index covers reads spanning several runs.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum EvidenceAddress {
    Physical { file: usize, offset: u64, reverse: bool },
    Logical { source: usize, offset: u64 },
}

impl AttemptSource {
    fn address(&self, source: usize, offset: u64, len: u64) -> EvidenceAddress {
        let file = Arc::as_ptr(&self.file) as usize;
        match &self.view {
            None => EvidenceAddress::Physical { file, offset, reverse: false },
            Some(view) => {
                if self.file.open().is_ok_and(|reader| view.validate_source(reader).is_ok()) {
                    if let Some(run) = view.single_run(offset, len) {
                        return EvidenceAddress::Physical { file, offset: run.start, reverse: run.reverse };
                    }
                }
                EvidenceAddress::Logical { source, offset }
            }
        }
    }

    fn read(&self, reader: &ManagedReader, offset: u64, dest: &mut [u8]) -> io::Result<usize> {
        match &self.view {
            Some(view) => {
                view.validate_source(reader)?;
                view.read(reader, offset, dest, true)
            }
            None => reader.read_direct_into_at(offset, dest),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AttemptGeometry {
    /// Native volume evidence uses (disk, offset); preceding sizes cannot
    /// change where its bytes are read.
    DiskRelative,
    Forward {
        logical_limit: Option<u64>,
    },
    TrimmedHead {
        total: u64,
    },
    TailTotals,
}
#[derive(Default)]
struct Node {
    incoming: Vec<usize>,
    outgoing: Vec<usize>,
}
struct Edge {
    from: usize,
    to: usize,
    source: usize,
    case: usize,
    disk: usize,
    unresolved: bool,
    start: u64,
    end: u64,
}
#[derive(Default)]
struct Topology {
    partitioned: bool,
    packed_by_start: OnceLock<Box<[(u64, usize)]>>,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    roots: Vec<[usize; 3]>,
    ends: Vec<(usize, u64, usize, usize)>,
    ambiguous_ranges: std::sync::OnceLock<Vec<(u64, u64)>>,
    disk_mappings: OnceLock<BTreeMap<usize, DiskMapping>>,
}

struct DiskMapping {
    minimum_length: u64,
    first: usize,
    rest: Vec<usize>,
    different_source: bool,
    different_length: bool,
}

fn ambiguous_logical_ranges<'a>(edges: impl Iterator<Item = &'a Edge>) -> Vec<(u64, u64)> {
    let mut mappings: Vec<_> = edges
        .filter(|edge| !edge.unresolved && edge.start < edge.end)
        .map(|edge| (edge.start, edge.source, edge.end))
        .collect();
    mappings.sort_unstable();
    let mut overlaps: Vec<(u64, u64)> = Vec::new();
    let mut covered_end = 0;
    for same in mappings.chunk_by(|a, b| a.0 == b.0 && a.1 == b.1) {
        let &(start, _, end) = same.last().unwrap();
        let overlap_end = end.min(covered_end);
        if start < overlap_end {
            match overlaps.last_mut() {
                Some((_, last)) if *last >= start => *last = (*last).max(overlap_end),
                _ => overlaps.push((start, overlap_end)),
            }
        }
        covered_end = covered_end.max(end);
    }
    overlaps
}

fn overlaps_range(ranges: &[(u64, u64)], start: u64, size: u64) -> bool {
    let index = ranges.partition_point(|&(_, end)| end <= start);
    size != 0 && ranges.get(index).is_some_and(|&(from, _)| from < start.saturating_add(size))
}

impl Topology {
    // Use the full geometry so method selection stays stable when a parser
    // replays on a narrower projection.
    fn range_is_ambiguous(&self, start: u64, size: u64) -> bool {
        if self.partitioned && size != 0 { return true; }
        let ranges = self.ambiguous_ranges.get_or_init(|| ambiguous_logical_ranges(self.edges.iter()));
        overlaps_range(ranges, start, size)
    }

    fn disk_mappings(&self) -> &BTreeMap<usize, DiskMapping> {
        self.disk_mappings.get_or_init(|| {
            let mut mappings = BTreeMap::<_, DiskMapping>::new();
            for (index, edge) in self.edges.iter().enumerate() {
                mappings.entry(edge.disk).and_modify(|mapping| {
                    let first = &self.edges[mapping.first];
                    mapping.minimum_length = mapping.minimum_length.min(edge.end - edge.start);
                    mapping.different_source |= first.source != edge.source;
                    mapping.different_length |= first.end - first.start != edge.end - edge.start;
                    mapping.rest.push(index);
                }).or_insert(DiskMapping {
                    minimum_length: edge.end - edge.start,
                    first: index, rest: Vec::new(), different_source: false, different_length: false,
                });
            }
            mappings
        })
    }

    fn disk_edges(&self, disk: usize) -> impl Iterator<Item = (usize, &Edge)> + '_ {
        self.disk_mappings().get(&disk).into_iter().flat_map(|mapping| {
            std::iter::once(mapping.first).chain(mapping.rest.iter().copied())
        }).map(|index| {
            #[cfg(test)]
            DISK_EDGE_VISITS.with(|visits| visits.set(visits.get().map(|count| count + 1)));
            (index, &self.edges[index])
        })
    }

    fn disk_range_is_ambiguous(&self, mut disk: usize, mut offset: u64, mut size: u64) -> bool {
        if self.partitioned && size != 0 { return true; }
        let mappings = self.disk_mappings();
        while size != 0 {
            let Some(mapping) = mappings.get(&disk) else { break; };
            if mapping.different_length {
                return true;
            }
            let first = &self.edges[mapping.first];
            let length = first.end - first.start;
            if offset >= length {
                offset -= length;
            } else {
                if mapping.different_source {
                    return true;
                }
                size = size.saturating_sub(length - offset);
                offset = 0;
            }
            disk += 1;
        }
        false
    }

    fn node(&mut self) -> usize {
        self.nodes.push(Node::default());
        self.nodes.len() - 1
    }
    fn edge(
        &mut self,
        from: usize,
        to: usize,
        source: usize,
        start: u64,
        end: u64,
        case: usize,
        disk: usize,
        unresolved: bool,
    ) {
        let index = self.edges.len();
        self.edges.push(Edge {
            from,
            to,
            source,
            case,
            disk,
            unresolved,
            start,
            end,
        });
        self.nodes[from].outgoing.push(index);
        self.nodes[to].incoming.push(index);
    }
}
#[derive(Clone)]
struct Projection {
    topology: Arc<Topology>,
    active: Vec<bool>,
    ends: Vec<bool>,
    len: u64,
}
impl Projection {
    fn proof(&self) -> Arc<crate::password::evidence::VolumeProjection> {
        let graph = &self.topology;
        Arc::new(crate::password::evidence::VolumeProjection {
            roots: graph.roots.clone(),
            edges: graph
                .edges
                .iter()
                .enumerate()
                .filter(|(i, _)| self.active[*i])
                .map(|(_, edge)| [edge.from, edge.to, edge.source])
                .collect(),
            ends: graph
                .ends
                .iter()
                .enumerate()
                .filter(|(i, _)| self.ends[*i])
                .map(|(_, &(node, _, _, _))| node)
                .collect(),
        })
    }

    fn order(&self, plan: &VolumeAttemptPlan) -> Option<Vec<usize>> {
        // Only the first injective path is needed for ordered commit. Do not
        // materialize the Cartesian product represented by this projection.
        let graph = &self.topology;
        let mut best: Option<Vec<usize>> = None;
        let mut stack = Vec::new();
        let mut selected = Vec::new();
        let mut used = vec![false; plan.sources.len()];
        for &[layout, count, root] in &graph.roots {
            let slots = &plan.layouts[layout].slots;
            let omitted = slots.len() - count;
            // Roots follow layout order and decreasing slot count. Only other
            // terminal totals of the same layout and count can beat a match.
            if best.as_ref().is_some_and(|order| (layout, omitted) > (order[0], order[1])) {
                break;
            }
            stack.push((root, 0usize));
            while let Some((node, next)) = stack.last_mut() {
                if selected.len() == count {
                    // The last active edge reaches a terminal kept by prune().
                    let mut order = vec![layout, omitted];
                    for (slot, source) in selected.drain(..).enumerate() {
                        used[source] = false;
                        let domain = slots[if slot + 1 == count { slots.len() - 1 } else { slot }].domain;
                        order.push(plan.domains[domain].choices.iter().position(|&s| s == source).unwrap());
                    }
                    if best.as_ref().is_none_or(|best| order < *best) {
                        best = Some(order);
                    }
                    stack.clear();
                    break;
                } else if let Some(&index) = graph.nodes[*node].outgoing.get(*next) {
                    *next += 1;
                    let edge = &graph.edges[index];
                    if self.active[index] && !used[edge.source] {
                        used[edge.source] = true;
                        selected.push(edge.source);
                        stack.push((edge.to, 0));
                    }
                    continue;
                }
                stack.pop();
                if let Some(source) = selected.pop() {
                    used[source] = false;
                }
            }
        }
        best
    }

    fn prune(&mut self) -> bool {
        let graph = &self.topology;
        let mut forward = vec![false; graph.nodes.len()];
        let mut queue = VecDeque::new();
        for &[_, _, root] in &graph.roots {
            forward[root] = true;
            queue.push_back(root);
        }
        while let Some(node) = queue.pop_front() {
            for &edge in &graph.nodes[node].outgoing {
                let e = &graph.edges[edge];
                if self.active[edge] && !forward[e.to] {
                    forward[e.to] = true;
                    queue.push_back(e.to);
                }
            }
        }
        let mut backward = vec![false; graph.nodes.len()];
        for (index, &(end, _, _, _)) in graph.ends.iter().enumerate() {
            self.ends[index] &= forward[end];
            if self.ends[index] {
                backward[end] = true;
                queue.push_back(end);
            }
        }
        while let Some(node) = queue.pop_front() {
            for &edge in &graph.nodes[node].incoming {
                let e = &graph.edges[edge];
                if self.active[edge] && !backward[e.from] {
                    backward[e.from] = true;
                    queue.push_back(e.from);
                }
            }
        }
        for (index, e) in graph.edges.iter().enumerate() {
            self.active[index] &= forward[e.from] && backward[e.to];
        }
        self.ends.iter().any(|value| *value)
    }
    fn select_disk(&self, all: &[usize], keep: &[usize], missing_cases: &[usize]) -> Option<Arc<Self>> {
        let mut result = self.clone();
        let mut cases = vec![false; result.topology.roots.len()];
        for &case in missing_cases {
            cases[case] = true;
        }
        for &index in all {
            result.active[index] = false;
        }
        for &index in keep {
            result.active[index] = true;
            cases[result.topology.edges[index].case] = true;
        }
        for (index, edge) in result.topology.edges.iter().enumerate() {
            result.active[index] &= cases[edge.case];
        }
        for (index, &(_, _, case, _)) in result.topology.ends.iter().enumerate() {
            result.ends[index] &= cases[case];
        }
        result.prune().then(|| Arc::new(result))
    }

    fn select(
        &self,
        covering: &[usize],
        keep: &[usize],
        short: bool,
        position: u64,
    ) -> Option<Arc<Self>> {
        let mut result = self.clone();
        for &index in covering {
            result.active[index] = false;
        }
        for &index in keep {
            result.active[index] = true;
        }
        for (index, &(_, end, _, _)) in result.topology.ends.iter().enumerate() {
            if (end <= position) != short {
                result.ends[index] = false;
            }
        }
        // Once the read identifies one physical member, any path reusing it
        // in another slot is explicitly illegal (the worker also forbids it).
        if keep.len() == 1 {
            let chosen = &result.topology.edges[keep[0]];
            for (index, e) in result.topology.edges.iter().enumerate() {
                if e.source == chosen.source && (e.start != chosen.start || e.end != chosen.end) {
                    result.active[index] = false;
                }
            }
        }
        result.prune().then(|| Arc::new(result))
    }
}
fn unknown(message: impl Into<String>) -> PreparedStatus {
    PreparedStatus::new("unknown_needs_final_verifier", message)
}

fn read_unavailable(error: io::Error) -> PreparedStatus {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        PreparedStatus::new("needs_volume_or_tail_damaged", error.to_string())
    } else {
        unknown(format!("resource_unavailable: {error}"))
    }
}

pub(crate) struct PreparedEvidence<T> {
    plan: Arc<VolumeAttemptPlan>,
    pub(in crate::password) alternatives: Vec<(T, Arc<crate::password::evidence::VolumeProjection>)>,
    rejected: Vec<Arc<crate::password::evidence::VolumeProjection>>,
    pub(crate) unresolved: Option<PreparedStatus>,
}

impl<T> PreparedEvidence<T> {
    pub(crate) fn values(self) -> impl Iterator<Item = T> {
        self.alternatives.into_iter().map(|(value, _)| value)
    }

    pub(crate) fn reduced_plan(&self) -> Result<Option<Arc<VolumeAttemptPlan>>, PreparedStatus> {
        if self.rejected.is_empty() {
            return Ok(None);
        }
        let paths = self.rejected.iter().map(Arc::as_ref).collect::<Vec<_>>();
        super::super::evidence::remove_paths(&self.plan, &paths)
            .map(|plan| Some(Arc::new(plan)))
            .map_err(|error| unknown(error.to_string()))
    }

    pub(crate) fn into_context(
        self,
        map: impl Fn(T) -> crate::password::context::PasswordContext,
    ) -> crate::password::context::PasswordContext {
        crate::password::context::PasswordContext::Evidence(
            crate::password::evidence::EvidenceContext {
                plan: self.plan,
                public_reduced: false,
                public_plan: Default::default(),
                rar_anchor: None,
                independent_rar: Vec::new(),
                alternatives: self
                    .alternatives
                    .into_iter()
                    .map(|(context, projection)| (map(context), projection))
                    .collect(),
                rejected: self.rejected,
                unresolved: self.unresolved,
            },
        )
    }
}

#[cfg(test)]
pub(crate) fn prepare_attempt_evidence<T: Send>(
    head: &InputExtent,
    plan: &VolumeAttemptPlan,
    sessions: &[NativeArchiveSession],
    geometry: AttemptGeometry,
    prepare: impl Fn(&mut AttemptReader<'_>) -> Result<Option<T>, PreparedStatus> + Sync,
) -> Result<Vec<T>, PreparedStatus> {
    let prepared = prepare_attempt_evidence_partial(head, &Arc::new(plan.clone()), sessions, geometry, prepare)?;
    match prepared.unresolved {
        Some(error) => Err(error),
        None => Ok(prepared.alternatives.into_iter().map(|(context, _)| context).collect()),
    }
}

pub(crate) fn prepare_attempt_evidence_partial<T: Send>(
    head: &InputExtent,
    plan: &Arc<VolumeAttemptPlan>,
    sessions: &[NativeArchiveSession],
    geometry: AttemptGeometry,
    prepare: impl Fn(&mut AttemptReader<'_>) -> Result<Option<T>, PreparedStatus> + Sync,
) -> Result<PreparedEvidence<T>, PreparedStatus> {
    let mut unresolved = None;
    let mut files: HashMap<_, _> = sessions
        .iter()
        .map(|session| {
            let path = session.path();
            (
                path,
                Arc::new(AttemptFile {
                    path: path.to_owned(),
                    reader: OnceLock::from(Ok(session.reader().clone())),
                }),
            )
        })
        .collect();
    let sources: Arc<[_]> = plan
        .sources
        .iter()
        .map(|extent| {
            // Relations usually supplies both boundaries. Opening a known-size
            // source is necessary only when the verifier actually requests bytes.
            let file = files
                .entry(extent.path.as_str())
                .or_insert_with_key(|path| {
                    Arc::new(AttemptFile {
                        path: (*path).to_owned(),
                        reader: OnceLock::new(),
                    })
                })
                .clone();
            let end = match extent.end {
                Some(end) => Some(end),
                None => match file.open() {
                    Ok(reader) => Some(
                        extent
                            .view
                            .as_ref()
                            .map_or_else(|| reader.len(), |v| v.len()),
                    ),
                    Err(error) => {
                        unresolved.get_or_insert_with(|| {
                            unknown(format!("resource_unavailable: {error}"))
                        });
                        None
                    }
                },
            };
            let len = end
                .map(|end| {
                    end.checked_sub(extent.start)
                        .ok_or_else(|| unknown("invalid volume extent"))
                })
                .transpose()?;
            Ok(AttemptSource {
                view: extent.view.clone(),
                file,
                start: extent.start,
                len,
            })
        })
        .collect::<Result<Vec<_>, PreparedStatus>>()?
        .into();
    let declared_head = std::cell::OnceCell::new();
    let is_head = |i: usize| {
        let Some(extent) = plan.sources.get(i) else {
            return false;
        };
        if extent.path != head.path {
            return false;
        }
        if extent == head {
            return true;
        }
        let same_head = |s: &InputExtent| {
            if s.path != head.path || (s.view == head.view && s.start != head.start) { return false; }
            if s == head { return true; }
            let logical_end = |s: &InputExtent| {
                let len = match &s.view {
                    Some(view) => view.len(),
                    None => sources[i].file.open().ok()?.len(),
                };
                Some(s.end.unwrap_or(len).min(len))
            };
            let (Some(end), Some(head_end)) = (logical_end(s), logical_end(head)) else { return false };
            if s.view == head.view { return end == head_end; }
            use crate::io::archive_state::PhysicalRanges;
            end.checked_sub(s.start) == head_end.checked_sub(head.start) &&
                PhysicalRanges::new(s.view.as_deref(), s.start, Some(end)) ==
                PhysicalRanges::new(head.view.as_deref(), head.start, Some(head_end))
        };
        // Interning can retain an equivalent head at a different logical
        // offset. Other masks at our offset require a declared head as before.
        if extent.start != head.start { return same_head(extent); }
        *declared_head.get_or_init(|| plan.head_sources().any(same_head))
    };
    let mut prepared_contexts = Vec::new();
    let mut rejected = Vec::new();
    let mut evaluate = |graph: Topology| {
        evaluate_geometry(
            graph,
            geometry,
            plan,
            &sources,
            &prepare,
            &mut prepared_contexts,
            &mut rejected,
            &mut unresolved,
        )
    };
    let mut graph = Topology::default();
    // A terminal source can appear in several layout lengths. Index the
    // declared total once, retaining the earliest declaration for a source.
    let tail_totals: HashMap<_, _> = if matches!(geometry, AttemptGeometry::TailTotals) {
        plan.tail_totals
            .iter()
            .rev()
            .map(|entry| (entry.source, entry.total))
            .collect()
    } else {
        HashMap::new()
    };
    // Once the required prefix and minimum total are present, suffix lengths
    // cannot change this method's coordinates. Merge those paths immediately.
    let prefix_end = match geometry {
        AttemptGeometry::Forward {
            logical_limit: Some(limit),
        } => Some(limit.max(plan.minimum_size.unwrap_or(0))),
        _ => None,
    };
    for (layout_index, layout) in plan.layouts.iter().enumerate() {
        let maximum = layout.slots.len();
        let minimum = if layout.minimum_slots == 0 {
            maximum
        } else {
            layout.minimum_slots
        };
        if minimum == 0 || minimum > maximum {
            return Err(unknown("invalid volume slot count"));
        }
        let contiguous = layout
            .slots
            .iter()
            .enumerate()
            .take_while(|(i, slot)| slot.number as usize == i + 1)
            .count();
        for count in (minimum..=maximum).rev() {
            Cancellation::current()
                .check_io()
                .map_err(|error| unknown(error.to_string()))?;
            let domain_choices = |slot: usize| -> Result<&[usize], PreparedStatus> {
                let domain = if slot + 1 == count {
                    layout.slots[maximum - 1].domain
                } else {
                    layout.slots[slot].domain
                };
                plan.domains
                    .get(domain)
                    .map(|domain| domain.choices.as_slice())
                    .ok_or_else(|| unknown("invalid volume domain"))
            };
            let mut terminal_groups: BTreeMap<Option<u64>, Vec<usize>> = BTreeMap::new();
            for &source in domain_choices(count - 1)? {
                let total = match geometry {
                    AttemptGeometry::Forward { .. } | AttemptGeometry::DiskRelative => None,
                    AttemptGeometry::TrimmedHead { total } => Some(total),
                    AttemptGeometry::TailTotals => tail_totals
                        .get(&source)
                        .copied()
                        .or(plan.head_size_from_total),
                };
                terminal_groups.entry(total).or_default().push(source);
            }
            for (trim_total, terminal_choices) in terminal_groups {
                let mut choices = (0..count - 1)
                    .map(domain_choices)
                    .collect::<Result<Vec<_>, _>>()?;
                choices.push(&terminal_choices);
                let case = GeometryCase {
                    layout,
                    layout_index,
                    contiguous,
                    choices,
                    trim_total,
                    geometry,
                    prefix_end,
                    minimum: plan.minimum_size.unwrap_or(0),
                };
                // Equal offsets share nodes. When one layer has more distinct
                // coordinates than the input has sources, stream disjoint
                // intervals through the same verifier instead of materializing
                // their product with all the remaining slots.
                let mut cuts = Vec::new();
                let mut pending = Vec::new();
                loop {
                    Cancellation::check_current_io().map_err(|e| unknown(e.to_string()))?;
                    let checkpoint = (
                        graph.nodes.len(),
                        graph.edges.len(),
                        graph.roots.len(),
                        graph.ends.len(),
                    );
                    let split = case.expand(&mut graph, &sources, &is_head, &cuts)?;
                    if let Some((slot, middle)) = split {
                        graph.nodes.truncate(checkpoint.0);
                        graph.edges.truncate(checkpoint.1);
                        graph.roots.truncate(checkpoint.2);
                        graph.ends.truncate(checkpoint.3);
                        graph.partitioned = true;
                        // All later topologies also represent just part of the input.
                        if !graph.roots.is_empty() {
                            evaluate(std::mem::take(&mut graph))?;
                        }
                        graph.partitioned = true;
                        pending.push((cuts.len(), slot, middle + 1));
                        cuts.push((slot, 0, middle));
                        continue;
                    }
                    if !cuts.is_empty() {
                        evaluate(std::mem::take(&mut graph))?;
                        graph.partitioned = true;
                    }
                    let Some((depth, slot, first)) = pending.pop() else {
                        break;
                    };
                    cuts.truncate(depth);
                    cuts.push((slot, first, u64::MAX));
                }
            }
        }
    }
    evaluate(graph)?;
    prepared_contexts.sort_by(|left, right| left.0.cmp(&right.0));
    if prepared_contexts.is_empty() && rejected.is_empty() && unresolved.is_none() {
        return Err(unknown("no usable volume password evidence"));
    }
    Ok(PreparedEvidence {
        plan: Arc::clone(plan),
        alternatives: prepared_contexts
            .into_iter()
            .map(|(_, context, projection)| (context, projection))
            .collect(),
        rejected,
        unresolved,
    })
}

struct GeometryCase<'a> {
    layout: &'a VolumeLayout,
    layout_index: usize,
    contiguous: usize,
    choices: Vec<&'a [usize]>,
    trim_total: Option<u64>,
    geometry: AttemptGeometry,
    prefix_end: Option<u64>,
    minimum: u64,
}

impl GeometryCase<'_> {
    fn expand(
        &self,
        graph: &mut Topology,
        sources: &[AttemptSource],
        is_head: &impl Fn(usize) -> bool,
        cuts: &[(usize, u64, u64)],
    ) -> Result<Option<(usize, u64)>, PreparedStatus> {
        let count = self.choices.len();
        let disk_number = |slot: usize| self.layout.slots[slot].number.saturating_sub(1) as usize;
        let case = graph.roots.len();
        let last_disk = disk_number(count - 1);
        let interval = |slot| {
            cuts.iter()
                .filter(|c| c.0 == slot)
                .fold((0, u64::MAX), |(lo, hi), c| (lo.max(c.1), hi.min(c.2)))
        };
        let split = |slot, layer: &BTreeMap<u64, usize>| {
            (layer.len() > sources.len().max(count)).then(|| {
                let lo = *layer.first_key_value().unwrap().0;
                let hi = *layer.last_key_value().unwrap().0;
                (slot, lo + (hi - lo) / 2)
            })
        };
        match self.trim_total {
            None => {
                // Propagate the remaining capacity backwards before constructing any
                // prefix offsets. A declared size can leave just one viable choice
                // even when the unconstrained prefix has exponentially many sums.
                let required = self.prefix_end.unwrap_or(self.minimum);
                let mut reachable = Vec::new();
                if !matches!(self.geometry, AttemptGeometry::DiskRelative)
                    && (required != 0 || !cuts.is_empty())
                {
                    reachable.resize(count, (0, u64::MAX));
                    let mut bounds = HashMap::new();
                    let mut low = required;
                    let mut high = u64::MAX;
                    for slot in (0..count).rev() {
                        let cut = interval(slot);
                        low = low.max(cut.0);
                        high = high.min(cut.1);
                        if low > high {
                            return Ok(None);
                        }
                        reachable[slot] = (low, high);
                        let domain = self.choices[slot];
                        let (shortest, longest) = *bounds
                            .entry((domain.as_ptr(), domain.len()))
                            .or_insert_with(|| {
                                domain
                                    .iter()
                                    .filter_map(|&i| sources.get(i)?.len)
                                    .fold((u64::MAX, 0), |(lo, hi), n| (lo.min(n), hi.max(n)))
                            });
                        low = low.saturating_sub(longest);
                        if self.prefix_end.is_none_or(|limit| high < limit) && high != u64::MAX {
                            let Some(before) = high.checked_sub(shortest) else {
                                return Ok(None);
                            };
                            high = before;
                        } else {
                            high = u64::MAX;
                        }
                    }
                    if low != 0 {
                        return Ok(None);
                    }
                }
                let root = graph.node();
                graph.roots.push([self.layout_index, count, root]);
                let mut layer = BTreeMap::from([(0u64, root)]);
                for slot in 0..count {
                    let mut next = BTreeMap::new();
                    let (lo_cut, hi_cut) = reachable.get(slot).copied().unwrap_or((0, u64::MAX));
                    for (&offset, &node) in &layer {
                        for &source in self.choices[slot] {
                            if slot == 0 && !is_head(source) {
                                continue;
                            }
                            let range = sources
                                .get(source)
                                .ok_or_else(|| unknown("invalid volume source"))?;
                            let Some(length) = range.len else {
                                continue;
                            };
                            let end = match self.prefix_end {
                                Some(limit) => offset.saturating_add(length).min(limit),
                                None => offset
                                    .checked_add(length)
                                    .ok_or_else(|| unknown("logical volume size overflow"))?,
                            };
                            let next_position =
                                if matches!(self.geometry, AttemptGeometry::DiskRelative) {
                                    0
                                } else {
                                    end
                                };
                            if !(lo_cut..=hi_cut).contains(&next_position) {
                                continue;
                            }
                            let target = *next.entry(next_position).or_insert_with(|| graph.node());
                            if let Some(cut) = split(slot, &next) {
                                return Ok(Some(cut));
                            }
                            graph.edge(
                                node,
                                target,
                                source,
                                offset,
                                end,
                                case,
                                disk_number(slot),
                                slot >= self.contiguous,
                            );
                        }
                    }
                    layer = next;
                }
                graph.ends.extend(
                    layer
                        .into_iter()
                        .map(|(offset, node)| (node, offset, case, last_disk)),
                );
            }
            Some(total) => {
                // A suffix offset must fit the preceding disks. The
                // carrier head may be trimmed to any positive length.
                // Discard impossible sums before allocating graph nodes.
                let Some(head_max) = self.choices[0]
                    .iter()
                    .copied()
                    .filter(|&i| is_head(i))
                    .filter_map(|i| sources.get(i).and_then(|s| s.len))
                    .max()
                    .filter(|&n| n > 0)
                else {
                    return Ok(None);
                };
                let mut prefix = Vec::with_capacity(count);
                prefix.push((1u64, head_max));
                let mut bounds = HashMap::new();
                for slot in 1..count.saturating_sub(1) {
                    let domain = self.choices[slot];
                    let (low, high) = *bounds
                        .entry((domain.as_ptr(), domain.len()))
                        .or_insert_with(|| {
                            domain
                                .iter()
                                .filter_map(|&i| sources.get(i).and_then(|s| s.len))
                                .fold((u64::MAX, 0u64), |(lo, hi), len| (lo.min(len), hi.max(len)))
                        });
                    let (lo, hi) = prefix[slot - 1];
                    prefix.push((lo.saturating_add(low), hi.saturating_add(high)));
                }
                let end = graph.node();
                graph.ends.push((end, total, case, last_disk));
                let mut layer = BTreeMap::from([(total, end)]);
                for slot in (1..count).rev() {
                    let mut next = BTreeMap::new();
                    let (lo_cut, hi_cut) = interval(slot);
                    // Append outgoing edges in domain order, even
                    // though their origins are built from the tail.
                    for &source in self.choices[slot] {
                        let range = sources
                            .get(source)
                            .ok_or_else(|| unknown("invalid volume source"))?;
                        let Some(length) = range.len else {
                            continue;
                        };
                        let (lo, hi) = prefix[slot - 1];
                        let Some(first) = lo.checked_add(length) else {
                            continue;
                        };
                        let first = first.max(lo_cut.saturating_add(length));
                        let last = hi.min(hi_cut).saturating_add(length);
                        if first > last {
                            continue;
                        }
                        for (&offset, &node) in layer.range(first..=last) {
                            let start = offset - length;
                            if start < lo_cut || start > hi_cut {
                                continue;
                            }
                            let origin = *next.entry(start).or_insert_with(|| graph.node());
                            if let Some(cut) = split(slot, &next) {
                                return Ok(Some(cut));
                            }
                            graph.edge(
                                origin,
                                node,
                                source,
                                start,
                                offset,
                                case,
                                disk_number(slot),
                                slot >= self.contiguous,
                            );
                        }
                    }
                    layer = next;
                }
                let root = graph.node();
                graph.roots.push([self.layout_index, count, root]);
                for &source in self.choices[0] {
                    if !is_head(source) {
                        continue;
                    }
                    let Some(available) = sources[source].len.filter(|&len| len != 0) else {
                        continue;
                    };
                    for (&length, &node) in layer.range(1..=available) {
                        graph.edge(
                            root,
                            node,
                            source,
                            0,
                            length,
                            case,
                            disk_number(0),
                            self.contiguous == 0,
                        );
                    }
                }
            }
        }
        Ok(None)
    }
}

fn evaluate_geometry<T: Send>(
    mut graph: Topology,
    geometry: AttemptGeometry,
    plan: &Arc<VolumeAttemptPlan>,
    sources: &Arc<[AttemptSource]>,
    prepare: &(impl Fn(&mut AttemptReader<'_>) -> Result<Option<T>, PreparedStatus> + Sync),
    prepared_contexts: &mut Vec<(
        Vec<usize>,
        T,
        Arc<crate::password::evidence::VolumeProjection>,
    )>,
    rejected: &mut Vec<Arc<crate::password::evidence::VolumeProjection>>,
    unresolved: &mut Option<PreparedStatus>,
) -> Result<(), PreparedStatus> {
    let minimum = match geometry {
        AttemptGeometry::DiskRelative => 0,
        AttemptGeometry::Forward {
            logical_limit: Some(limit),
        } => plan.minimum_size.unwrap_or(0).max(limit),
        _ => plan.minimum_size.unwrap_or(0),
    };
    // These are completed paths, not partially selected slot prefixes. Short
    // files retain declared extent lengths above and fail as real I/O on read.
    graph.ends.retain(|&(_, length, _, _)| length >= minimum);
    let graph = Arc::new(graph);
    let mut lengths: BTreeMap<u64, Option<Vec<usize>>> = BTreeMap::new();
    match geometry {
        AttemptGeometry::DiskRelative => {
            lengths.insert(0, None);
        }
        AttemptGeometry::Forward {
            logical_limit: None,
        }
        | AttemptGeometry::TailTotals => {
            for (index, &(_, length, _, _)) in graph.ends.iter().enumerate() {
                lengths
                    .entry(length)
                    .or_default()
                    .get_or_insert_with(Vec::new)
                    .push(index);
            }
        }
        AttemptGeometry::Forward {
            logical_limit: Some(length),
        }
        | AttemptGeometry::TrimmedHead { total: length } => {
            lengths.insert(length, None);
        }
    }
    let mut seeds = lengths.into_iter().filter_map(|(len, selected)| {
        let mut ends = vec![selected.is_none(); graph.ends.len()];
        if let Some(selected) = selected {
            for index in selected {
                ends[index] = true;
            }
        }
        let mut projection = Projection {
            active: vec![true; graph.edges.len()],
            topology: Arc::clone(&graph),
            ends,
            len,
        };
        projection.prune().then(|| Arc::new(projection))
    });
    let mut pending = Vec::new();
    // Physical observations are not retained in an unbounded byte cache. The
    // prepared format owns its existing Spool; projections retain only edges.
    let cancellation = Cancellation::current();
    let width = rayon::current_num_threads().max(1);
    loop {
        cancellation
            .check_io()
            .map_err(|error| unknown(error.to_string()))?;
        pending.extend(seeds.by_ref().take(width.saturating_sub(pending.len())));
        if pending.is_empty() {
            break;
        }
        let batch_start = pending.len().saturating_sub(width);
        let batch = pending.split_off(batch_start);
        let outcomes: Vec<_> = batch
            .into_par_iter()
            .map(|projection| {
                cancellation.run(|| {
                    let mut reader = AttemptReader::new(sources, projection);
                    let result = prepare(&mut reader);
                    (reader, result)
                })
            })
            .collect();
        cancellation
            .check_io()
            .map_err(|error| unknown(error.to_string()))?;
        for (mut reader, result) in outcomes {
            rejected.append(&mut reader.truncated_choices);
            if let Some(fault) = reader.unresolved_fault.take() {
                unresolved.get_or_insert_with(|| read_unavailable(fault));
            }
            if let Some(fault) = reader.fault {
                unresolved.get_or_insert_with(|| read_unavailable(fault));
                continue;
            }
            if let Some(branches) = reader.pending {
                pending.extend(branches);
                continue;
            }
            match result {
                Ok(Some(context)) => {
                    if let Some(order) = reader.projection.order(plan) {
                        prepared_contexts.push((order, context, reader.projection.proof()));
                    }
                }
                Ok(None) if reader.evidence_fault.is_none() => {
                    rejected.push(reader.projection.proof())
                }
                result => {
                    if let Some(error) = reader.evidence_fault {
                        unresolved.get_or_insert_with(|| read_unavailable(error));
                    } else if let Err(error) = result {
                        unresolved.get_or_insert(error);
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct AttemptReader<'a> {
    sources: &'a Arc<[AttemptSource]>,
    projection: Arc<Projection>,
    position: u64,
    logical_span: Option<(usize, u64)>,
    pending: Option<Vec<Arc<Projection>>>,
    fault: Option<io::Error>,
    evidence_fault: Option<io::Error>,
    unresolved_fault: Option<io::Error>,
    truncated_choices: Vec<Arc<crate::password::evidence::VolumeProjection>>,
    preserve_unreadable: bool,
    missing: bool,
}

#[derive(Clone)]
pub(crate) struct DeferredReads {
    sources: Arc<[AttemptSource]>,
    projection: Arc<Projection>,
    disk_relative: bool,
    proof: Arc<OnceLock<Arc<crate::password::evidence::VolumeProjection>>>,
}

#[derive(Debug)]
pub(crate) enum DeferredReadError {
    Missing,
    Pending,
    Io(io::Error),
    Truncated,
    Cancelled,
}

pub(crate) struct DeferredReader<'a> {
    reader: AttemptReader<'a>,
    disk_relative: bool,
}

impl DeferredReads {
    #[cfg(test)]
    pub(super) fn shares_projection(&self, reader: &DeferredReader<'_>) -> bool {
        Arc::ptr_eq(&self.projection, &reader.reader.projection)
    }

    pub(crate) fn range_is_ambiguous(&self, start: u64, size: u64) -> bool {
        if self.disk_relative {
            self.disk_range_is_ambiguous(0, start, size)
        } else {
            self.projection.topology.range_is_ambiguous(start, size)
        }
    }

    pub(crate) fn has_single_path(&self) -> bool {
        let graph = &self.projection.topology;
        let mut ends = graph.ends.iter().zip(&self.projection.ends).filter(|(_, active)| **active);
        let Some((&(_, _, case, _), _)) = ends.next() else { return false; };
        ends.next().is_none() &&
            self.projection.active.iter().filter(|&&active| active).count() == graph.roots[case][1]
    }

    pub(crate) fn read_single<T>(&self, read: impl FnOnce(&mut DeferredReader<'_>) -> T) -> T {
        let mut reader = AttemptReader::new(&self.sources, Arc::clone(&self.projection));
        reader.preserve_unreadable = true;
        read(&mut DeferredReader { reader, disk_relative: self.disk_relative })
    }

    pub(crate) fn active_ranges_are_ambiguous(
        &self,
        mut ranges: impl Iterator<Item = (u64, u64)>,
    ) -> bool {
        let overlaps = self.active_range_filter();
        ranges.any(|(start, size)| overlaps(start, size))
    }

    pub(crate) fn active_range_filter(&self) -> impl Fn(u64, u64) -> bool + '_ {
        debug_assert!(!self.disk_relative);
        let ranges = std::cell::OnceCell::<Vec<(u64, u64)>>::new();
        move |start, size| {
            if self.projection.topology.partitioned { return size != 0; }
            if let Some(ranges) = ranges.get() {
                return overlaps_range(ranges, start, size);
            }
            self.range_is_ambiguous(start, size)
                && overlaps_range(ranges.get_or_init(|| {
                    // Anchor or descriptor reads may already have removed some mappings.
                    let active = self.projection.topology.edges.iter().zip(&self.projection.active);
                    ambiguous_logical_ranges(active.filter_map(|(edge, &active)| active.then_some(edge)))
                }), start, size)
        }
    }

    pub(crate) fn disk_range_is_ambiguous(&self, disk: usize, offset: u64, size: u64) -> bool {
        self.projection.topology.disk_range_is_ambiguous(disk, offset, size)
    }

    pub(crate) fn evaluate<T>(
        &self, mut verify: impl FnMut(&mut DeferredReader<'_>) -> T,
    ) -> io::Result<Vec<(Arc<crate::password::evidence::VolumeProjection>, T)>> {
        let mut pending = Vec::new();
        let mut current = Some(Arc::clone(&self.projection));
        let mut outcomes = Vec::new();
        let mut branched = false;
        while let Some(projection) = current.take().or_else(|| pending.pop()) {
            Cancellation::check_current_io()?;
            let mut reader = AttemptReader::new(&self.sources, projection);
            reader.preserve_unreadable = true;
            let mut reader = DeferredReader { reader, disk_relative: self.disk_relative };
            let value = verify(&mut reader);
            Cancellation::check_current_io()?;
            if let Some(branches) = reader.reader.pending {
                branched = true;
                pending.extend(branches.into_iter().rev());
            } else {
                let projection = reader.reader.projection;
                let projection = if branched { projection.proof() }
                    else { self.proof.get_or_init(|| projection.proof()).clone() };
                outcomes.push((projection, value));
            }
        }
        Ok(outcomes)
    }

}

impl DeferredReader<'_> {
    pub(crate) fn read_into(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), DeferredReadError> {
        if self.disk_relative {
            bytes.copy_from_slice(&self.read_disk_offset(0, 0, offset, bytes.len())?);
            return Ok(());
        }
        self.load(|reader| {
            reader.seek(SeekFrom::Start(offset))?;
            reader.read_exact(bytes)
        })
    }

    pub(crate) fn read(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, DeferredReadError> {
        if self.disk_relative {
            return self.read_disk_offset(0, 0, offset, len);
        }
        self.load(|reader| {
            reader.seek(SeekFrom::Start(offset))?;
            let mut bytes = crate::io::resource_error::bytes_with_capacity(len)?;
            bytes.resize(len, 0);
            reader.read_exact(&mut bytes)?;
            Ok(bytes)
        })
    }

    pub(crate) fn read_disk_offset(
        &mut self, disk: usize, base: u64, relative: u64, len: usize,
    ) -> Result<Vec<u8>, DeferredReadError> {
        let bytes = self.load(|reader| {
            let Some((disk, offset)) = reader.advance_disk_offset(disk, base, relative)? else {
                return Ok(Vec::new());
            };
            reader.read_disk_spanning(disk, offset, len)
        })?;
        if bytes.len() == len { Ok(bytes) } else { Err(DeferredReadError::Missing) }
    }

    pub(in crate::password) fn load<T>(
        &mut self,
        read: impl FnOnce(&mut AttemptReader<'_>) -> io::Result<T>,
    ) -> Result<T, DeferredReadError> {
        if self.reader.pending.is_some() {
            return Err(DeferredReadError::Pending);
        }
        self.reader.missing = false;
        let result = read(&mut self.reader);
        if self.reader.pending.is_some() {
            return Err(DeferredReadError::Pending);
        }
        if Cancellation::current().cancelled() {
            return Err(DeferredReadError::Cancelled);
        }
        let fault = self.reader.fault.take().or(self.reader.unresolved_fault.take());
        if self.reader.missing {
            return Err(DeferredReadError::Missing);
        }
        if let Some(error) = fault {
            return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                DeferredReadError::Truncated
            } else {
                DeferredReadError::Io(error)
            });
        }
        match result {
            Ok(value) => Ok(value),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(DeferredReadError::Missing),
            Err(error) => Err(DeferredReadError::Io(error)),
        }
    }
}

impl AttemptReader<'_> {
    pub(in crate::password) fn read_native_disk(&mut self, disk: usize, offset: u64, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_domain(Some((disk, offset)), bytes)
    }
    fn new(sources: &Arc<[AttemptSource]>, projection: Arc<Projection>) -> AttemptReader<'_> {
        AttemptReader {
            sources,
            projection,
            position: 0,
            logical_span: None,
            pending: None,
            fault: None,
            evidence_fault: None,
            unresolved_fault: None,
            truncated_choices: Vec::new(),
            preserve_unreadable: false,
            missing: false,
        }
    }

    pub(crate) fn deferred_reads(&self, disk_relative: bool) -> DeferredReads {
        DeferredReads {
            sources: Arc::clone(self.sources),
            projection: Arc::clone(&self.projection),
            disk_relative,
            proof: Arc::default(),
        }
    }

    pub(crate) fn range_is_ambiguous(&self, start: u64, size: u64) -> bool {
        self.projection.topology.range_is_ambiguous(start, size)
    }

    pub(in crate::password) fn disk_range_is_ambiguous(&self, disk: usize, offset: u64, size: u64) -> bool {
        self.projection.topology.disk_range_is_ambiguous(disk, offset, size)
    }

    pub(in crate::password) fn last_ambiguous_native_disk(&self, after: usize) -> Option<usize> {
        self.projection.topology.disk_mappings().range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .rev().find_map(|(&disk, mapping)| mapping.different_source.then_some(disk))
    }

    fn metadata_ready(&self) -> io::Result<()> {
        if self.fault.is_some() {
            return Err(io::Error::other("volume source read failed"));
        }
        if self.pending.is_some() {
            return Err(io::Error::other("volume evidence projection pending"));
        }
        Cancellation::current().check_io()
    }

    pub(crate) fn last_disk(&mut self) -> io::Result<Option<usize>> {
        self.metadata_ready()?;
        let mut disks = std::collections::BTreeSet::new();
        for (index, &(_, _, _, disk)) in self.projection.topology.ends.iter().enumerate() {
            if self.projection.ends[index] {
                disks.insert(disk);
            }
        }
        if disks.len() <= 1 {
            return Ok(disks.into_iter().next());
        }
        let mut branches = Vec::new();
        for disk in disks {
            let mut projection = self.projection.as_ref().clone();
            for (index, &(_, _, _, value)) in projection.topology.ends.iter().enumerate() {
                projection.ends[index] &= value == disk;
            }
            if projection.prune() {
                branches.push(Arc::new(projection));
            }
        }
        self.pending = Some(branches);
        Err(io::Error::other("volume evidence projection pending"))
    }

    /// Partition only on independently usable native evidence. All sources
    /// without this method share one branch, including absent disk numbers.
    pub(crate) fn native_proof(
        &mut self,
        disk: usize,
        identify: impl Fn(usize) -> Option<usize>,
    ) -> io::Result<Option<usize>> {
        self.metadata_ready()?;
        let topology = &self.projection.topology;
        if topology.roots.len() == 1 && topology.disk_mappings().get(&disk).is_none_or(|m| !m.different_source) {
            return Ok(topology.disk_edges(disk).find(|(index, _)| self.projection.active[*index])
                .and_then(|(_, edge)| identify(edge.source)));
        }
        self.partition_disk(disk, None, |edge| identify(edge.source)).map(Option::flatten)
    }

    pub(crate) fn volume_len(&mut self, disk: usize) -> io::Result<Option<u64>> {
        self.volume_len_for_read(disk, None)
    }

    /// A read inside every candidate's bounds needs no exact EOF observation.
    fn volume_len_for_read(&mut self, disk: usize, sufficient: Option<u64>) -> io::Result<Option<u64>> {
        self.metadata_ready()?;
        let topology = &self.projection.topology;
        if topology.roots.len() == 1 {
            let Some(mapping) = topology.disk_mappings().get(&disk) else { return Ok(None) };
            if !mapping.different_length || sufficient.is_some_and(|end| end <= mapping.minimum_length) {
                return Ok(Some(mapping.minimum_length));
            }
        }
        // Ok sorts before Err so a missing volume keeps its previous priority.
        self.partition_disk(disk, Err(()), |edge| Ok(edge.end - edge.start))
            .map(|length| length.and_then(Result::ok))
    }

    fn partition_disk<K: Ord + Copy>(
        &mut self,
        disk: usize,
        missing_key: K,
        identify: impl Fn(&Edge) -> K,
    ) -> io::Result<Option<K>> {
        let projection = &self.projection;
        let topology = &projection.topology;
        let mut groups = BTreeMap::<K, Vec<usize>>::new();
        let mut all = Vec::new();
        let mut present = vec![false; topology.roots.len()];
        for (index, edge) in topology.disk_edges(disk) {
            if projection.active[index] {
                all.push(index);
                present[edge.case] = true;
                groups.entry(identify(edge)).or_default().push(index);
            }
        }
        if groups.is_empty() {
            return Ok(None);
        }
        let mut missing = Vec::new();
        for (&(_, _, case, _), &active) in topology.ends.iter().zip(&projection.ends) {
            if active && !present[case] {
                missing.push(case);
                present[case] = true;
            }
        }
        if !missing.is_empty() {
            groups.entry(missing_key).or_default();
        }
        if groups.len() == 1 {
            return Ok(groups.into_keys().next());
        }
        self.pending = Some(groups.into_iter().filter_map(|(key, edges)| {
            projection.select_disk(&all, &edges, if key == missing_key { &missing } else { &[] })
        }).collect());
        Err(io::Error::other("volume evidence projection pending"))
    }

    pub(crate) fn read_disk_spanning(
        &mut self,
        mut disk: usize,
        mut offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; size];
        let mut written = 0;
        while written < size {
            let requested_end = offset.checked_add((size - written) as u64);
            let Some(length) = self.volume_len_for_read(disk, requested_end)? else {
                break;
            };
            if offset > length {
                break;
            }
            if offset == length {
                disk = disk
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("volume number overflow"))?;
                offset = 0;
                continue;
            }
            let count = (length - offset).min((size - written) as u64) as usize;
            let read =
                self.read_domain(Some((disk, offset)), &mut bytes[written..written + count])?;
            if read == 0 {
                break;
            }
            written += read;
            offset += read as u64;
            if written < size && offset == length {
                disk = disk
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("volume number overflow"))?;
                offset = 0;
            }
        }
        bytes.truncate(written);
        Ok(bytes)
    }

    pub(crate) fn advance_disk_offset(
        &mut self,
        mut disk: usize,
        mut offset: u64,
        mut amount: u64,
    ) -> io::Result<Option<(usize, u64)>> {
        loop {
            let Some(length) = self.volume_len_for_read(disk, offset.checked_add(amount))? else {
                return Ok(None);
            };
            if offset > length {
                return Ok(None);
            }
            let remaining = length - offset;
            if amount <= remaining {
                return Ok(Some((disk, offset + amount)));
            }
            amount -= remaining;
            offset = 0;
            disk = disk
                .checked_add(1)
                .ok_or_else(|| io::Error::other("volume number overflow"))?;
        }
    }

    /// Isolate only independently sufficient evidence, never metadata or a
    /// pending projection. Failed-stream observations cannot restrict a new proof.
    pub(crate) fn independent_evidence<T, E>(
        &mut self,
        load: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let before = (self.pending.is_none() && self.fault.is_none()).then(|| Arc::clone(&self.projection));
        let result = load(self);
        if let Some(before) = before.filter(|_| {
            result.is_err() && self.pending.is_none() && !Cancellation::current().cancelled()
        }) {
            if let Some(error) = self.fault.take() {
                if self.evidence_fault.is_none() {
                    self.evidence_fault = Some(error);
                }
                self.projection = before;
                self.logical_span = None;
            }
        }
        result
    }
    fn read_edge(
        &mut self,
        index: usize,
        bytes: &mut [u8],
        disk_offset: Option<u64>,
    ) -> io::Result<()> {
        #[cfg(test)]
        EDGE_READS.with(|reads| reads.set(reads.get().map(|count| count + 1)));
        let edge = &self.projection.topology.edges[index];
        let source = &self.sources[edge.source];
        let offset = source.start + disk_offset.unwrap_or(self.position.saturating_sub(edge.start));
        let reader = match source.file.open() {
            Ok(reader) => reader,
            Err(error) => {
                self.fault = Some(io::Error::other(error.clone()));
                return Err(io::Error::other("volume source unavailable"));
            }
        };
        let mut read = 0;
        while read < bytes.len() {
            let result = source.read(reader, offset + read as u64, &mut bytes[read..]);
            match result {
                Ok(0) => {
                    self.fault = Some(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "volume source shortened",
                    ));
                    return Err(io::Error::other("volume source shortened"));
                }
                Ok(value) => read += value,
                Err(error) => {
                    // Only a successful zero-byte read proves physical EOF.
                    self.fault = Some(io::Error::other(error));
                    return Err(io::Error::other("volume source read failed"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn len(&self) -> u64 {
        self.projection.len
    }
}
impl AttemptReader<'_> {
    fn read_domain(&mut self, disk: Option<(usize, u64)>, buffer: &mut [u8]) -> io::Result<usize> {
        if self.fault.is_some() {
            return Err(io::Error::other("volume source read failed"));
        }
        if self.pending.is_some() {
            return Err(io::Error::other("volume evidence projection pending"));
        }
        if buffer.is_empty() || (disk.is_none() && self.position >= self.len()) {
            return Ok(0);
        }
        if disk.is_none() {
            if let Some((index, until)) = self.logical_span {
                if self.position < until {
                    let edge_end = self.projection.topology.edges[index].end;
                    let count = (edge_end.min(self.len()) - self.position).min(buffer.len() as u64) as usize;
                    self.read_edge(index, &mut buffer[..count], None)?;
                    self.position += count as u64;
                    return Ok(count);
                }
                self.logical_span = None;
            }
        }
        let mut first = None;
        let mut covering = Vec::new();
        let mut count = if disk.is_some() {
            buffer.len()
        } else {
            (self.len() - self.position).min(buffer.len() as u64) as usize
        };
        let mut consider = |index: usize, edge: &Edge, offset: u64| {
            if !self.projection.active[index] {
                return;
            }
            if offset < edge.end - edge.start {
                if let Some(earlier) = first {
                    if covering.is_empty() {
                        covering.push(earlier);
                    }
                    covering.push(index);
                } else {
                    first = Some(index);
                }
                count = count.min((edge.end - edge.start - offset) as usize);
            }
        };
        let mut next_change = self.len();
        let mut short = false;
        if let Some((disk, offset)) = disk {
            for (index, edge) in self.projection.topology.disk_edges(disk) {
                consider(index, edge, offset);
            }
        } else {
            #[cfg(test)]
            LOGICAL_EDGE_VISITS.with(|visits| {
                visits.set(visits.get().map(|count| count + self.projection.topology.edges.len()));
            });
            for (index, edge) in self.projection.topology.edges.iter().enumerate() {
                if edge.start <= self.position {
                    consider(index, edge, self.position - edge.start);
                } else if edge.start < edge.end && self.projection.active[index] {
                    next_change = next_change.min(edge.start);
                }
            }
            for (index, &(_, end, _, _)) in self.projection.topology.ends.iter().enumerate() {
                if self.projection.ends[index] {
                    next_change = next_change.min(end);
                    if end <= self.position {
                        short = true;
                        break;
                    }
                }
            }
        }
        let covering = if covering.is_empty() { first.as_slice() } else { covering.as_slice() };
        if covering.is_empty() {
            return Ok(0);
        }
        if let [index] = covering {
            let edge = &self.projection.topology.edges[*index];
            if !short && (disk.is_some() || !edge.unresolved) {
                let until = next_change.min(edge.end);
                self.read_edge(*index, &mut buffer[..count], disk.map(|(_, offset)| offset))?;
                if disk.is_none() {
                    // A later read can begin within a new competing range.
                    // Keep the existing read size and recheck at that boundary.
                    self.logical_span = Some((*index, until));
                    self.position += count as u64;
                }
                return Ok(count);
            }
        }
        let beyond_gap: Vec<_> = covering.iter().copied().filter(|&index| {
            disk.is_none() && self.projection.topology.edges[index].unresolved
        }).collect();
        if !beyond_gap.is_empty() {
            self.unresolved_fault = Some(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "logical evidence position depends on a missing volume number",
            ));
            let known: Vec<_> = covering
                .iter()
                .copied()
                .filter(|&i| !self.projection.topology.edges[i].unresolved)
                .collect();
            let mut branches = Vec::new();
            if let Some(branch) = self
                .projection
                .select(covering, &known, false, self.position)
            {
                branches.push(branch);
            }
            if self.preserve_unreadable && (!branches.is_empty() || short) {
                branches.extend(self.projection.select(covering, &beyond_gap, false, self.position));
            }
            if short {
                branches.extend(self.projection.select(covering, &[], true, self.position));
            }
            if branches.is_empty() {
                self.missing = true;
                self.fault = self.unresolved_fault.take();
            } else {
                self.pending = Some(branches);
            }
            return Err(io::Error::other("unresolved logical volume position"));
        }
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut buckets = HashMap::<u32, Vec<usize>>::new();
        #[derive(Clone, Copy)]
        enum Observation {
            Bytes(usize),
            Truncated,
            Unavailable,
        }
        let mut reads = HashMap::<EvidenceAddress, Observation>::new();
        let mut truncated = Vec::new();
        let mut unavailable = Vec::new();
        let mut bytes = vec![0; count];
        let mut comparison = Vec::new();
        let mut compared_group = None;
        for &index in covering {
            let edge = &self.projection.topology.edges[index];
            let source = &self.sources[edge.source];
            let offset = source.start + disk.map(|(_, offset)| offset)
                .unwrap_or(self.position.saturating_sub(edge.start));
            let location = source.address(edge.source, offset, count as u64);
            if let Some(&read) = reads.get(&location) {
                match read {
                    Observation::Bytes(group) => groups[group].1.push(index),
                    Observation::Truncated => truncated.push(index),
                    Observation::Unavailable if self.preserve_unreadable => unavailable.push(index),
                    Observation::Unavailable => {}
                }
                continue;
            }
            if let Err(error) = self.read_edge(index, &mut bytes, disk.map(|(_, offset)| offset)) {
                if Cancellation::current().cancelled() {
                    return Err(error);
                }
                let fault = self.fault.take().unwrap_or(error);
                let observation = if fault.kind() == io::ErrorKind::UnexpectedEof {
                    truncated.push(index);
                    Observation::Truncated
                } else {
                    self.unresolved_fault.get_or_insert(fault);
                    if self.preserve_unreadable {
                        unavailable.push(index);
                    }
                    Observation::Unavailable
                };
                reads.insert(location, observation);
                continue;
            }
            // CRC is only a grouping index, never a format/password proof.
            // Hash collisions always receive a full byte comparison.
            let hash = crc32fast::hash(&bytes);
            let mut matched = None;
            if let Some(possible) = buckets.get(&hash) {
                for &group in possible {
                    let representative = if group == 0 {
                        &buffer[..count]
                    } else {
                        if compared_group != Some(group) {
                            comparison.resize(count, 0);
                            self.read_edge(groups[group].0, &mut comparison, disk.map(|(_, offset)| offset))?;
                            compared_group = Some(group);
                        }
                        comparison.as_slice()
                    };
                    if bytes == representative {
                        matched = Some(group);
                        break;
                    }
                }
            }
            let group = if let Some(group) = matched {
                groups[group].1.push(index);
                group
            } else {
                let group = groups.len();
                if group == 0 {
                    buffer[..count].copy_from_slice(&bytes);
                }
                groups.push((index, vec![index]));
                buckets.entry(hash).or_default().push(group);
                group
            };
            reads.insert(location, Observation::Bytes(group));
        }
        if groups.is_empty() {
            self.fault = self.unresolved_fault.take();
            if self.fault.is_none() && !truncated.is_empty() {
                self.fault = Some(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "all volume sources shortened",
                ));
            }
            return Err(io::Error::other("no readable evidence projection"));
        }
        if !truncated.is_empty() && !self.preserve_unreadable {
            // Another choice supplied this exact logical range. A source that
            // cannot fill its declared extent cannot supply the same evidence.
            let projection = if disk.is_some() {
                self.projection.select_disk(covering, &truncated, &[])
            } else {
                self.projection.select(covering, &truncated, false, self.position)
            };
            if let Some(projection) = projection {
                self.truncated_choices.push(projection.proof());
            }
        }
        if groups.len() > 1 || short || (self.preserve_unreadable && (!unavailable.is_empty() || !truncated.is_empty())) {
            let mut branches = Vec::new();
            let failures = [unavailable, if self.preserve_unreadable { truncated } else { Vec::new() }];
            for edges in groups.into_iter().map(|(_, edges)| edges).chain(failures).filter(|edges| !edges.is_empty()) {
                let branch = if disk.is_some() {
                    self.projection.select_disk(covering, &edges, &[])
                } else {
                    self.projection
                        .select(covering, &edges, false, self.position)
                };
                if let Some(branch) = branch {
                    branches.push(branch);
                }
            }
            if short {
                if let Some(branch) = self.projection.select(covering, &[], true, self.position) {
                    branches.push(branch);
                }
            }
            self.pending = Some(branches);
            return Err(io::Error::other("volume evidence projection pending"));
        }
        let (_, edges) = groups.pop().unwrap();
        if edges.len() != covering.len() {
            let projection = if disk.is_some() {
                self.projection.select_disk(covering, &edges, &[])
            } else {
                self.projection
                    .select(covering, &edges, false, self.position)
            };
            let Some(projection) = projection else {
                self.pending = Some(Vec::new());
                return Err(io::Error::other("invalid repeated volume source"));
            };
            self.projection = projection;
            self.logical_span = None;
        }
        if disk.is_none() {
            self.position += count as u64;
        }
        Ok(count)
    }
}
impl Read for AttemptReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_domain(None, buffer)
    }
}
impl Seek for AttemptReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(value) => i128::from(self.len()) + i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
        };
        let position = u64::try_from(position)
            .map_err(|_| io::Error::other("invalid volume evidence seek"))?;
        if position < self.position {
            self.logical_span = None;
        }
        self.position = position;
        Ok(position)
    }
}
