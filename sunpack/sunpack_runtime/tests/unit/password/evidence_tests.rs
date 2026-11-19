use super::*;
use crate::io::archive_state::{InputExtent, VolumeSlot};

#[test]
fn sparse_candidates_and_unchecked_suffix_are_combined_in_order() {
    let proof = PasswordVerification {
        matched_index: Some(1),
        matched_indices: vec![1, 3],
        attempts: 252,
        ..PasswordVerification::status("match", "test")
    };
    let strong = PasswordVerification {
        matched_index: Some(4),
        attempts: 5,
        final_confirmation_required: Some(false),
        ..PasswordVerification::status("match", "test")
    };
    let weak = SurvivingCandidates::new(&proof, 256);
    let confirmed = SurvivingCandidates::new(&strong, 256);
    let mut combined = [false; 256];
    weak.mark_union(&mut combined);
    confirmed.mark_union(&mut combined);
    assert_eq!(weak.iter().collect::<Vec<_>>(), [1, 3, 252, 253, 254, 255]);
    assert_eq!(confirmed.iter().collect::<Vec<_>>(), [4]);
    assert_eq!(combined.into_iter().enumerate().filter_map(|(i, yes)| yes.then_some(i)).collect::<Vec<_>>(),
        [1, 3, 4, 252, 253, 254, 255]);
}

#[test]
fn adding_branch_keys_preserves_initialized_anchor_slots() {
    let mut keys = SharedCandidateKeys::<_, usize>::from_parameters([1, 1]);
    keys.cells(&1, 2).unwrap()[1].set(41).unwrap();
    keys.include_repeated([2, 3, 2]);
    assert!(keys.cells(&3, 2).is_none());
    keys.keep_candidates(&1, &[1]);
    assert_eq!(keys.cells(&1, 1).unwrap()[0].get(), Some(&41));
    assert_eq!(keys.cells(&2, 1).unwrap().len(), 1);
}

#[test]
fn scan_frontier_restores_each_suffix_choice_once() {
    let count = 512;
    let choices: Vec<_> = (0..count).map(|index| Arc::new(vec![2 * index, 2 * index + 1])).collect();
    let first: Vec<_> = (0..count).map(|index| 2 * index).collect();
    let mut pivot = count;
    let mut backing = None;
    FRONTIER_RESTORED_CHOICES.set(0);
    visit_ordered_suffix(&choices, &first, |path| {
        assert_eq!(path.as_ptr(), *backing.get_or_insert(path.as_ptr()));
        pivot -= 1;
        if pivot + 1 == count {
            assert_eq!(*path[pivot], *choices[pivot]);
        } else {
            assert_eq!(*path[pivot], [2 * pivot + 1]);
            assert!(Arc::ptr_eq(&path[pivot + 1], &choices[pivot + 1]));
        }
        if pivot > 0 { assert_eq!(*path[pivot - 1], [first[pivot - 1]]); }
        Ok(())
    }).unwrap();
    assert_eq!(pivot, 0);
    assert_eq!(FRONTIER_RESTORED_CHOICES.get(), count - 1);
}

#[test]
fn scan_discarded_prefix_skips_wide_unvisited_suffixes() {
    let width = 64;
    let count = 48;
    let plan = VolumeAttemptPlan {
        sources: (0..=2 * width).map(|id| InputExtent {
            path: id.to_string(), start: 0, end: Some(1),
        }).collect(),
        domains: [vec![0], (1..=width).collect(), (width + 1..=2 * width).collect()]
            .map(|choices| VolumeDomain { choices: Arc::new(choices) }).into(),
        layouts: Box::new([VolumeLayout {
            minimum_slots: 0,
            slots: (0..count).map(|slot| VolumeSlot {
                number: slot as u32 + 1, canonical_name: String::new(), domain: slot.min(2),
            }).collect(),
        }]),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::new([]),
    };
    let prefixes = (1..width).rev().map(|id| VolumeSelection {
        layout: 0, sources: vec![0, id],
    }).collect();
    PARTITION_EDGE_VISITS.set(0);
    PARTITION_DOMAIN_HASH_CHOICES.set(0);
    let kept = remove_scan_paths(&plan, Vec::new(), prefixes, Vec::new(), None).unwrap();
    assert_eq!(kept.layouts.len(), 1);
    let slots = &kept.layouts[0].slots;
    let choice_paths = |index: usize| kept.domains[slots[index].domain].choices.iter()
        .map(|&id| kept.sources[id].path.as_str()).collect::<Vec<_>>();
    assert_eq!(choice_paths(1), [width.to_string().as_str()]);
    assert_eq!(choice_paths(count - 1).len(), width);
    assert_eq!(PARTITION_EDGE_VISITS.get(), 1 + width);
    assert_eq!(PARTITION_DOMAIN_HASH_CHOICES.get(), width + 3);
}

// A cross-volume failure must preserve either fragment with another partner.
// Check actual serialized candidates and order, not the discarded evidence.
#[test]
fn candidate_removal_preserves_correlations_order_and_unrelated_domains() {
    let plan = VolumeAttemptPlan {
        sources: (0..7)
            .map(|i| InputExtent {
                path: i.to_string(),
                start: 0,
                end: Some(10),
            })
            .collect(),
        domains: [vec![0], vec![1, 2], vec![3, 4], vec![5, 6]]
            .into_iter()
            .map(|choices| VolumeDomain {
                choices: Arc::new(choices),
            })
            .collect(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: (0..4)
                .map(|i| VolumeSlot {
                    number: i as u32 + 1,
                    canonical_name: i.to_string(),
                    domain: i,
                })
                .collect(),
        }]
        .into(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::new([]),
    };
    let projection = VolumeProjection {
        roots: vec![[0, 4, 0]],
        edges: vec![[0, 1, 0], [1, 2, 1], [2, 3, 3], [3, 4, 5], [3, 4, 6]],
        ends: vec![4],
    };
    fn enumerate(plan: &VolumeAttemptPlan) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        for layout in &plan.layouts {
            let max = layout.slots.len();
            let min = if layout.minimum_slots == 0 {
                max
            } else {
                layout.minimum_slots
            };
            for count in (min..=max).rev() {
                let mut paths = vec![Vec::new()];
                for slot in layout.slots[..count - 1].iter().chain(layout.slots.last()) {
                    paths = paths
                        .into_iter()
                        .flat_map(|prefix| {
                            plan.domains[slot.domain]
                                .choices
                                .iter()
                                .map(move |&source| {
                                    let mut path = prefix.clone();
                                    path.push(plan.sources[source].path.clone());
                                    path
                                })
                        })
                        .collect();
                }
                result.extend(paths);
            }
        }
        result
    }
    let remaining = remove_paths(&plan, &[&projection]).unwrap();
    assert_eq!(
        enumerate(&remaining),
        enumerate(&plan)
            .into_iter()
            .filter(|path| !(path[1] == "1" && path[2] == "3"))
            .collect::<Vec<_>>()
    );
    assert_eq!(remaining.layouts.len(), 2);
    assert!(remaining
        .layouts
        .iter()
        .all(|layout| remaining.domains[layout.slots[3].domain].choices.len() == 2));
    let all_first_middle = VolumeProjection {
        roots: vec![[0, 4, 0]],
        edges: vec![
            [0, 1, 0],
            [1, 2, 1],
            [2, 3, 3],
            [2, 3, 4],
            [3, 4, 5],
            [3, 4, 6],
        ],
        ends: vec![4],
    };
    let remaining = remove_paths(&plan, &[&all_first_middle]).unwrap();
    assert_eq!(remaining.layouts.len(), 1);
    assert!(!remaining.sources.iter().any(|source| source.path == "1"));
    assert_eq!(
        enumerate(&remaining),
        enumerate(&plan)
            .into_iter()
            .filter(|path| path[1] != "1")
            .collect::<Vec<_>>()
    );
    let mut variable = plan;
    variable.layouts[0].minimum_slots = 2;
    let remaining = remove_paths(&variable, &[&projection]).unwrap();
    assert_eq!(
        enumerate(&remaining),
        enumerate(&variable)
            .into_iter()
            .filter(|p| p.len() < 4 || p[1] != "1" || p[2] != "3")
            .collect::<Vec<_>>()
    );
    let mut projection = projection;
    // A geometry branch may reach several states for the same source.
    // Either state can reject its own continuation without cross-pairing.
    projection.edges.extend([[1, 5, 1], [5, 6, 4], [6, 4, 5]]);
    let remaining = remove_paths(&variable, &[&projection]).unwrap();
    assert_eq!(
        enumerate(&remaining),
        enumerate(&variable).into_iter()
            .filter(|p| p.len() < 4 || p[1] != "1" || (p[2] == "4" && p[3] != "5"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn different_weak_verifiers_keep_their_passwords_across_batches() {
    use crate::password::zip::ZipPasswordContext;
    let sources: Box<[_]> = ["head", "tailA", "tailB", "unreadable"]
        .map(|path| InputExtent {
            path: path.into(),
            start: 0,
            end: Some(40),
        })
        .into();
    let plan = VolumeAttemptPlan {
        sources,
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: [0, 1]
                .map(|i| VolumeSlot {
                    number: i as u32 + 1,
                    canonical_name: i.to_string(),
                    domain: i,
                })
                .into(),
        }]
        .into(),
        domains: [vec![0], vec![1, 2, 3]]
            .map(|choices| VolumeDomain {
                choices: Arc::new(choices),
            })
            .into(),
        head_size_from_total: None,
        minimum_size: None,
        tail_totals: Box::default(),
    };
    let alternatives = [("first", 1), ("later", 2)]
        .into_iter()
        .map(|(password, source)| {
            let salt = vec![source as u8; 8];
            let mut key = [0; 34];
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), &salt, 1000, &mut key);
            (
                PasswordContext::Zip(ZipPasswordContext::Aes {
                    key_len: 16,
                    salt,
                    verifier: [key[32], key[33]],
                    prefix: None,
                }),
                Arc::new(VolumeProjection {
                    roots: vec![[0, 2, 0]],
                    edges: vec![[0, 1, 0], [1, 2, source]],
                    ends: vec![2],
                }),
            )
        })
        .collect();
    let context = EvidenceContext {
        plan: Arc::new(plan),
        alternatives,
        rejected: vec![],
        unresolved: Some(PreparedStatus::new("unknown_needs_final_verifier", "missing tail evidence")),
        public_reduced: false,
        public_plan: Default::default(),
        rar_anchor: None,
        independent_rar: vec![],
    };
    let mut domains = CandidateDomains::default();
    let mut count = 0;
    let scope = Arc::new(VolumeProjection {
        roots: vec![[0, 2, 0]],
        edges: vec![[0, 1, 0], [1, 2, 3]],
        ends: vec![2],
    });
    for batch in [vec!["wrong", "first"], vec!["later"]] {
        let candidates: Vec<_> = batch.into_iter().map(Arc::from).collect();
        let result = context.verify(&candidates).unwrap();
        assert_eq!(result.matched_indices.len(), candidates.len());
        domains.append(result.password_domains, count, candidates.len());
        // Both batches reject only on the otherwise unreadable tail. They
        // share one byte projection, including duplicate observations.
        let (index, ordinals): (_, &[_]) = if count == 0 {
            (3, &[0, usize::MAX, usize::MAX, 1])
        } else { (0, &[0]) };
        let mut rejected = ScopedRejections::default();
        rejected.extend([(scope.clone(), index), (scope.clone(), index), (scope.clone(), 1)]);
        domains.append_scoped(rejected, count, ordinals);
        count += candidates.len();
    }
    PARTITION_EDGE_VISITS.set(0);
    let (remaining, passwords) = domains.finish(&context, count).unwrap().unwrap();
    assert_eq!(PARTITION_EDGE_VISITS.get(), 3 * (1 + 3));
    let actual: Vec<_> = remaining
        .layouts
        .iter()
        .zip(passwords.layout_password_domains)
        .map(|(layout, group)| {
            let tail = &remaining.domains[layout.slots[1].domain].choices;
            assert_eq!(tail.len(), 1);
            (
                remaining.sources[tail[0]].path.as_str(),
                &passwords.password_domains[group][..],
            )
        })
        .collect();
    assert_eq!(
        actual,
        [
            ("tailA", &[1][..]),
            ("tailB", &[2][..]),
            ("unreadable", &[0][..])
        ]
    );
}
