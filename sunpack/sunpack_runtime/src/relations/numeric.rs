use super::assignment::{RelationFailureReason, VolumeAssignment};
use std::collections::{BTreeMap, VecDeque};

/// Domains are built from the current family's cached numeric occurrences.
/// Empty optional domains stay residual; structural members are mandatory.
pub(super) struct NumericDomain {
    pub row: usize,
    pub required: bool,
    pub numbers: Vec<(u32, usize)>,
}

struct FileNode {
    row: usize,
    required: bool,
    assigned: bool,
    edges: Vec<usize>,
    degree: usize,
    remaining: usize,
}

#[derive(Default)]
struct SlotNode {
    number: u32,
    edges: Vec<usize>,
    degree: usize,
    single_files: usize,
    single_remaining: usize,
}

struct Edge {
    file: usize,
    slot: usize,
    width: usize,
    live: bool,
}

struct NumericSolver {
    files: Vec<FileNode>,
    slots: Vec<SlotNode>,
    edges: Vec<Edge>,
    order: Vec<usize>,
    pending: VecDeque<usize>,
    missing: bool,
}

impl NumericSolver {
    fn new(domains: Vec<NumericDomain>) -> Self {
        let mut graph = Self {
            files: Vec::with_capacity(domains.len()),
            slots: Vec::new(),
            edges: Vec::new(),
            order: Vec::new(),
            pending: VecDeque::new(),
            missing: false,
        };
        let mut by_number = BTreeMap::new();
        for domain in domains {
            let file = graph.files.len();
            let mut node = FileNode {
                row: domain.row,
                required: domain.required,
                assigned: false,
                edges: Vec::with_capacity(domain.numbers.len()),
                degree: domain.numbers.len(),
                remaining: 0,
            };
            for (number, width) in domain.numbers {
                let slot = *by_number.entry(number).or_insert_with(|| {
                    let index = graph.slots.len();
                    graph.slots.push(SlotNode {
                        number,
                        ..Default::default()
                    });
                    index
                });
                let edge = graph.edges.len();
                graph.edges.push(Edge {
                    file,
                    slot,
                    width,
                    live: true,
                });
                node.edges.push(edge);
                node.remaining ^= edge;
                let target = &mut graph.slots[slot];
                target.edges.push(edge);
                target.degree += 1;
            }
            if node.degree == 1 {
                let slot = graph.edges[node.remaining].slot;
                graph.slots[slot].single_files += 1;
                graph.slots[slot].single_remaining ^= node.remaining;
            } else if node.degree == 0 && node.required {
                graph.missing = true;
            }
            graph.files.push(node);
        }
        graph.order = by_number.into_values().collect();
        for &slot in &graph.order {
            if graph.slots[slot].single_files == 1 {
                graph.pending.push_back(slot);
            }
        }
        graph
    }

    fn remove(&mut self, edge: usize) {
        if !self.edges[edge].live {
            return;
        }
        self.edges[edge].live = false;
        let file = self.edges[edge].file;
        let slot = self.edges[edge].slot;
        if self.files[file].degree == 1 && !self.files[file].assigned {
            self.slots[slot].single_files -= 1;
            self.slots[slot].single_remaining ^= edge;
        }
        self.files[file].degree -= 1;
        self.files[file].remaining ^= edge;
        self.slots[slot].degree -= 1;
        if self.slots[slot].single_files == 1 {
            self.pending.push_back(slot);
        }
        if self.files[file].assigned {
            return;
        }
        if self.files[file].degree == 1 {
            let last = self.files[file].remaining;
            let target = self.edges[last].slot;
            self.slots[target].single_files += 1;
            self.slots[target].single_remaining ^= last;
            self.pending.push_back(target);
        } else if self.files[file].degree == 0 && self.files[file].required {
            self.missing = true;
        }
    }

    fn claim(&mut self, edge: usize, assignment: &mut VolumeAssignment) {
        let file = self.edges[edge].file;
        let slot = self.edges[edge].slot;
        if self.files[file].degree == 1 {
            self.slots[slot].single_files -= 1;
            self.slots[slot].single_remaining ^= edge;
        }
        let node = &mut self.files[file];
        node.assigned = true;
        assignment.slots.insert(self.slots[slot].number, node.row);
        // Each edge is removed once. There is no repeated scan of the bucket,
        // and XOR registries find a remaining singleton without an edge scan.
        for index in 0..self.files[file].edges.len() {
            self.remove(self.files[file].edges[index]);
        }
        for index in 0..self.slots[slot].edges.len() {
            self.remove(self.slots[slot].edges[index]);
        }
    }

    fn propagate(&mut self, assignment: &mut VolumeAssignment) {
        while let Some(slot) = self.pending.pop_front() {
            let target = &self.slots[slot];
            if target.single_files == 1 {
                // A file's only remaining slot is forced. A slot's only
                // candidate is not: the number itself can be filename noise.
                // Two singleton files competing for one slot are not both
                // forced. Width arbitration handles that conflict later.
                self.claim(target.single_remaining, assignment);
                if self.missing {
                    return;
                }
            }
        }
    }

    fn run(mut self, assignment: &mut VolumeAssignment) -> Result<bool, RelationFailureReason> {
        if self.missing {
            return Err(RelationFailureReason::MissingVolume);
        }
        let mut cursor = 0;
        let mut alternatives = false;
        loop {
            self.propagate(assignment);
            if self.missing {
                return Err(RelationFailureReason::MissingVolume);
            }
            while cursor < self.order.len() && self.slots[self.order[cursor]].degree == 0 {
                cursor += 1;
            }
            let Some(&slot) = self.order.get(cursor) else {
                break;
            };
            let mut best: Option<usize> = None;
            let mut tied = false;
            for &edge in &self.slots[slot].edges {
                if !self.edges[edge].live {
                    continue;
                }
                let width = self.edges[edge].width;
                match best {
                    Some(old) if self.edges[old].width < width => {}
                    Some(old) if self.edges[old].width == width => tied = true,
                    _ => {
                        best = Some(edge);
                        tied = false;
                    }
                }
            }
            if tied {
                return Err(RelationFailureReason::AmbiguousVolumeMapping);
            }
            alternatives |= self.slots[slot].degree > 1;
            self.claim(best.expect("active numeric slot has an edge"), assignment);
        }
        assignment.unresolved.clear();
        Ok(alternatives)
    }
}

/// O(E log S) construction and O(E + F + S) graph updates, plus ordered output
/// insertions. Slot storage depends on observed occurrences, never a filename's
/// largest value.
/// All nodes and edges are released with this one family resolution.
pub(super) fn solve(
    assignment: &mut VolumeAssignment,
    domains: Vec<NumericDomain>,
) -> Result<bool, RelationFailureReason> {
    NumericSolver::new(domains).run(assignment)
}

#[cfg(test)]
#[path = "../../tests/unit/relations/numeric/tests.rs"]
mod tests;
