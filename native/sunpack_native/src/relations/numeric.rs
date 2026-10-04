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
    remaining: usize,
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
                target.remaining ^= edge;
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
            if graph.slots[slot].degree == 1 || graph.slots[slot].single_files == 1 {
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
        self.slots[slot].remaining ^= edge;
        if self.slots[slot].degree == 1 || self.slots[slot].single_files == 1 {
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
            let edge = if target.degree == 1 {
                Some(target.remaining)
            } else if target.single_files == 1 {
                // Two singleton files competing for one slot are not both
                // forced. Width arbitration handles that conflict later.
                Some(target.single_remaining)
            } else {
                None
            };
            if let Some(edge) = edge {
                self.claim(edge, assignment);
                if self.missing {
                    return;
                }
            }
        }
    }

    fn run(mut self, assignment: &mut VolumeAssignment) -> Result<(), RelationFailureReason> {
        if self.missing {
            return Err(RelationFailureReason::MissingVolume);
        }
        let mut cursor = 0;
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
            self.claim(best.expect("active numeric slot has an edge"), assignment);
        }
        assignment.unresolved.clear();
        Ok(())
    }
}

/// O(E log S) construction and O(E + F + S) graph updates, plus ordered output
/// insertions. Slot
/// storage depends on observed occurrences, never a filename's largest value.
/// All nodes and edges are released with this one family resolution.
pub(super) fn solve(
    assignment: &mut VolumeAssignment,
    domains: Vec<NumericDomain>,
) -> Result<(), RelationFailureReason> {
    NumericSolver::new(domains).run(assignment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagation_handles_a_long_chain_without_repeated_domain_scans() {
        let count = 20_000usize;
        let domains = (0..count)
            .map(|row| {
                let n = row as u32 + 2;
                NumericDomain {
                    row,
                    required: true,
                    numbers: if row + 1 == count {
                        vec![(n, 3)]
                    } else {
                        vec![(n, 3), (n + 1, 1)]
                    },
                }
            })
            .collect();
        let mut assignment = VolumeAssignment::default();
        solve(&mut assignment, domains).unwrap();
        assert_eq!(assignment.slots.len(), count);
        for (&slot, &row) in &assignment.slots {
            assert_eq!(slot, row as u32 + 2);
        }
    }

    #[test]
    fn shortest_width_restarts_propagation_before_the_next_greedy_choice() {
        let domains = vec![
            NumericDomain {
                row: 0,
                required: true,
                numbers: vec![(2, 1), (3, 2)],
            },
            NumericDomain {
                row: 1,
                required: true,
                numbers: vec![(2, 2), (3, 1)],
            },
        ];
        let mut assignment = VolumeAssignment::default();
        solve(&mut assignment, domains).unwrap();
        assert_eq!(assignment.slots, BTreeMap::from([(2, 0), (3, 1)]));
    }

    #[test]
    fn competing_required_members_cannot_be_discarded_by_width_arbitration() {
        let domains = vec![
            NumericDomain {
                row: 0,
                required: true,
                numbers: vec![(2, 1)],
            },
            NumericDomain {
                row: 1,
                required: true,
                numbers: vec![(2, 2)],
            },
        ];
        let mut assignment = VolumeAssignment::default();
        assert_eq!(
            solve(&mut assignment, domains),
            Err(RelationFailureReason::MissingVolume)
        );
    }

    #[test]
    fn sparse_slot_storage_depends_on_occurrences_not_the_largest_number() {
        let domains = vec![NumericDomain {
            row: 0,
            required: true,
            numbers: vec![(u32::MAX, 10)],
        }];
        let graph = NumericSolver::new(domains);
        assert_eq!(graph.slots.len(), 1);
        assert_eq!(graph.edges.len(), 1);
        let mut assignment = VolumeAssignment::default();
        graph.run(&mut assignment).unwrap();
        assert_eq!(assignment.slots, BTreeMap::from([(u32::MAX, 0)]));
    }
}
