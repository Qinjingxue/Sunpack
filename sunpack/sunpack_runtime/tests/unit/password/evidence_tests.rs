use super::*;
use crate::io::archive_state::{InputExtent, VolumeSlot};

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
        unresolved: true,
        public_reduced: false,
        public_plan: Default::default(),
        rar_anchor: None,
        independent_rar: vec![],
    };
    let mut domains = CandidateDomains::default();
    let mut count = 0;
    for batch in [vec!["wrong", "first"], vec!["later"]] {
        let candidates: Vec<_> = batch.into_iter().map(Arc::from).collect();
        let result = context.verify(&candidates).unwrap();
        assert_eq!(result.matched_indices.len(), candidates.len());
        domains.append(result.password_domains, count, candidates.len());
        count += candidates.len();
    }
    let (remaining, passwords) = domains.finish(&context, count).unwrap().unwrap();
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
            ("unreadable", &[0, 1, 2][..])
        ]
    );
}
