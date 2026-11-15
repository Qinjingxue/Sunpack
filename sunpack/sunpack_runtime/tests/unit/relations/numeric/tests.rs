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
