use super::*;

fn row(name: &str, format: &'static str, slot: Option<u32>, terminal: bool) -> RelationInput {
    RelationInput {
        path: name.into(),
        path_key: name.to_ascii_lowercase(),
        size: Some(100),
        relation_member_eligible: true,
        anchor_cell: None,
        anchor: Some(Arc::new(VolumeAnchor {
            path: name.into(),
            size: 100,
            format,
            strong: !format.is_empty(),
            multivolume: !format.is_empty(),
            internal_volume_number: slot,
            relation_has_next: (!format.is_empty()).then_some(!terminal),
            flags: (if terminal { TERMINAL } else if slot == Some(1) { FIRST } else { MEMBER })
                | match format {
                    "rar" => RAR_VERSION_5 | RAR_PART_NUMBERING,
                    "zip" if terminal => ZIP_SPLIT_END,
                    "zip" => ZIP_SPLIT_START,
                    _ => 0,
                },
            ..Default::default()
        })),
    }
}

fn resolve(rows: &[RelationInput]) -> Vec<ProposalValidation> {
    resolve_buckets(rows, &BucketIndex::build(rows, None), None)
}

fn slots(validation: &ProposalValidation) -> Vec<u32> {
    validation.proposal.volumes.iter().map(|p| p.1).collect()
}

#[test]
fn shared_carrier_keeps_unique_terminal_and_fixed_heads_in_either_slice_order() {
    for reverse in [false, true] {
        let mut shared_head = row("same.shared", "rar", Some(1), false);
        shared_head.anchor_mut().unwrap().structure_offset = Some(10);
        shared_head.anchor_mut().unwrap().payload_end = Some(30);
        let mut shared_tail = row("same.shared", "rar", Some(3), true);
        shared_tail.anchor_mut().unwrap().structure_offset = Some(40);
        shared_tail.anchor_mut().unwrap().payload_end = Some(60);
        let mut shared = vec![shared_head, shared_tail];
        if reverse { shared.reverse(); }
        let mut rows = vec![row("same.game.part1.rar", "rar", Some(1), false),
            row("same.middle", "rar", Some(2), false)];
        rows.extend(shared);
        let groups = resolve(&rows);
        assert_eq!(groups.len(), 2);
        for group in groups {
            if group.proposal.volumes[0].0 == "same.game.part1.rar" {
                assert_eq!(group.proposal.logical_name, "same.game");
            }
            let plan = group.attempts.as_ref().unwrap();
            let head = &group.facts.anchors[&path_key(&group.proposal.volumes[0].0)];
            let mut physical = HashSet::new();
            assert!(plan.base_sources().iter().all(|source| physical.insert(&source.path)));
            assert_eq!(group.parts_len(), physical.len());
            assert!(validation_owned_paths(&group).contains("same.shared"));
            for layout in &plan.layouts {
                let layout = &layout.slots;
                let first = &plan.sources[layout[0].1[0]];
                assert_eq!(first.path, head.path);
                assert_eq!(first.start, head.structure_offset.unwrap_or(0));
                assert_eq!(layout[0].1.len(), 1, "heads cannot mix within a domain");
                let tails = &layout.iter().find(|(number, _)| *number == 3).unwrap().1;
                assert!(tails.iter().any(|&i| plan.sources[i].path == "same.shared"
                    && plan.sources[i].start == 40 && plan.sources[i].terminal));
            }
        }
    }
}

#[test]
fn shared_mixed_heads_keep_opaque_continuation_disks() {
    let rows = vec![
        row("same.001.image", "zip", Some(1), false),
        row("same.001.image", "7z", Some(1), false),
        row("same.z02.image", "", None, false),
        row("same.zip.image", "zip", Some(3), true),
        row("same.7z.002.image", "", None, false),
        row("same.7z.003.image", "7z", Some(3), true),
    ];
    let groups = resolve(&rows);
    let zip = groups.iter().find(|group| group.proposal.format == "zip").unwrap();
    assert!(validation_owned_paths(zip).contains("same.z02.image"));
}

#[test]
fn fixed_structure_ignores_all_camouflaged_numbers() {
    let rows = vec![
        row("same.part99.chunk8", "rar", Some(1), false),
        row("same.part1.chunk7", "rar", Some(2), false),
        row("same.nothing", "rar", Some(3), true),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups.len(), 1);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn competing_terminal_numbers_retain_each_structurally_legal_length() {
    // Equal terminal numbers cannot detect silently clipping a longer
    // archive to another archive's terminal. Keep both lengths, never
    // place a terminal in an intermediate slot.
    let rows = vec![
        row("same.header", "rar", Some(1), false),
        row("same.short", "rar", Some(2), true),
        row("same.middle", "rar", Some(2), false),
        row("same.long", "rar", Some(3), true),
    ];
    let groups = resolve(&rows);
    let plan = groups[0].attempts.as_ref().unwrap();
    assert_eq!(
        plan.layouts.iter().map(|layout| layout.slots.len()).collect::<Vec<_>>(),
        vec![3, 2]
    );
    assert_eq!(plan.sources[plan.layouts[0].slots[1].1[0]].path, "same.middle");
    assert_eq!(plan.sources[plan.layouts[1].slots[1].1[0]].path, "same.short");
}

#[test]
fn spanned_carrier_keeps_ordered_disk_sizes_and_nonuniform_fallback() {
    let mut head = row("same.head", "zip", Some(1), false);
    let anchor = head.anchor_mut().unwrap();
    anchor.size = 200;
    anchor.structure_offset = Some(10);
    anchor.carrier_limit = Some(180);
    let middle = |name, size| {
        let mut row = row(name, "zip", Some(2), false);
        row.size = Some(size);
        let anchor = row.anchor_mut().unwrap();
        anchor.size = size;
        anchor.flags = MEMBER | ZIP_DIRECTORY_MEMBER;
        row
    };
    let rows = [head, middle("same.short", 80), middle("same.long", 100),
        row("same.tail", "zip", Some(3), true)];

    let mut groups = resolve(&rows);
    assert_eq!(groups.len(), 1);
    attempts::resolve_carrier_geometry(&mut groups[0]);
    let plan = groups[0].attempts.as_ref().unwrap();
    let layouts: Vec<_> = plan.layouts.iter().map(|layout| {
        let head = &plan.sources[layout.slots[0].1[0]];
        let mut sizes: Vec<_> = layout.slots[1].1.iter()
            .map(|&i| plan.sources[i].end - plan.sources[i].start).collect();
        sizes.sort_unstable();
        (head.end, sizes)
    }).collect();
    assert_eq!(layouts, [(90, vec![80]), (110, vec![100]), (180, vec![80, 100])]);
}

#[test]
fn unnamed_terminal_family_stays_compact_and_keeps_numbered_tail_fixed() {
    // Many optional members must not allocate one full slot list per end.
    // A second, numbered tail must never migrate to the family's short ends.
    let mut rows = vec![row("same.head", "7z", Some(1), false)];
    for i in 0..=255 {
        let name = format!(
            "same.mid{}{}",
            (b'a' + i / 26) as char,
            (b'a' + i % 26) as char
        );
        rows.push(row(&name, "", None, false));
    }
    rows.push(row("same.tail", "7z", None, true));
    rows.push(row("same.part258", "7z", None, true));
    let groups = resolve(&rows);
    let plan = groups[0].attempts.as_ref().unwrap();
    assert!(plan.layouts.iter().map(|layout| layout.slots.len()).sum::<usize>() <= 3 * rows.len());
    let family = plan.layouts.iter().find(|layout| layout.minimum_slots == 2).unwrap();
    assert_eq!(family.slots.len(), 258);
    assert!(family.slots
        .last()
        .unwrap()
        .1
        .iter()
        .all(|i| plan.sources[*i].path == "same.tail"));
    assert!(plan
        .layouts
        .iter()
        .any(|layout| layout.minimum_slots == 0
            && layout.slots
                .last()
                .unwrap()
                .1
                .iter()
                .any(|i| plan.sources[*i].path == "same.part258")));
}

#[test]
fn repeated_seed_numbers_are_global_channels_not_a_seed_failure() {
    let rows = vec![
        row("same.build1.chunk1.bin", "7z", Some(1), false),
        row("same.build1.chunk002.bin", "", None, false),
        row("same.build1.chunk0003.bin", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn every_structural_anchor_constrains_the_channel() {
    let rows = vec![
        row("same.build1.chunk1", "zip", Some(1), false),
        row("same.build2.chunk2", "", None, false),
        row("same.build3.chunk3", "", None, false),
        row("same.build9.chunk4", "zip", Some(4), true),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3, 4]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn equivalent_channels_deduplicate_by_mapping() {
    let rows = vec![
        row("same.build1.chunk01", "7z", Some(1), false),
        row("same.build2.chunk002", "", None, false),
        row("same.build3.chunk0003", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn distinct_global_mappings_are_ambiguous() {
    let rows = vec![
        row("same.build1.chunk1", "7z", Some(1), false),
        row("same.build2.chunk3", "", None, false),
        row("same.build3.chunk2", "", None, false),
    ];
    let groups = resolve(&rows);
    assert!(groups[0]
        .attempts
        .as_ref()
        .is_some_and(|plan| !plan.layouts.is_empty()));
    assert_eq!(slots(&groups[0]), vec![1]);
}

#[test]
fn loose_numbers_ignore_context_and_ordinal_without_reparsing() {
    let rows = vec![
        row("same.header1", "7z", Some(1), false),
        row("same.download002foo", "", None, false),
        row("same.zero0.blob0003bar", "", None, false),
        row("same.2024.txt", "", None, false),
        row("same.4294967295.txt", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
    assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
    assert_eq!(groups[0].proposal.volumes[2].0, rows[2].path);
    assert!(!validation_owned_paths(&groups[0]).contains(&rows[3].path));
    assert!(!validation_owned_paths(&groups[0]).contains(&rows[4].path));

    let mut cache = RelationCache {
        anchors: groups[0].facts.anchors.clone(),
        names: groups[0].facts.names.clone(),
    };
    let mut renamed = rows.clone();
    // Seed collected features on opaque names so reparsing cannot recover the slots.
    for (member, path) in renamed[1..].iter_mut().zip([
        "same.red", "same.green", "same.blue", "same.yellow",
    ]) {
        let features = cache.names.remove(&member.path_key);
        *member = row(path, "", None, false);
        if let Some(features) = features {
            cache.names.insert(member.path_key.clone(), features);
        }
    }
    let retried = resolve_buckets(&renamed, &BucketIndex::build(&renamed, None), Some(&cache));
    assert_eq!(slots(&retried[0]), vec![1, 2, 3]);
    assert_eq!(retried[0].reason, None);
    assert_eq!(retried[0].proposal.volumes[1].0, renamed[1].path);
    assert_eq!(retried[0].proposal.volumes[2].0, renamed[2].path);
}

#[test]
fn optional_numeric_slots_do_not_force_a_gap_with_same_stem_noise() {
    let mut rows = vec![
        row("same.header1", "7z", Some(1), false),
        row("same.x2.y03", "", None, false),
        row("same.z3.w0004", "", None, false),
        row("same.notes", "", None, false),
    ];
    rows[0].anchor_mut().unwrap().expected_logical_size = Some(300);
    let mut groups = resolve(&rows);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].reason, None);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
    assert_eq!(groups[0].proposal.volumes[2].0, rows[2].path);
    assert!(!validation_owned_paths(&groups[0]).contains(&rows[3].path));
    validate::validate(&mut groups[0]);
    assert_eq!(groups[0].status, ProposalStatus::Valid);
}

#[test]
fn numeric_propagation_prevents_shortest_width_from_stealing_a_singleton() {
    let rows = vec![
        row("same.header1", "7z", Some(1), false),
        row("same.x2.y03", "", None, false),
        row("same.alone02", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups[0].reason, None);
    assert_eq!(groups[0].proposal.volumes[1].0, rows[2].path);
    assert_eq!(groups[0].proposal.volumes[2].0, rows[1].path);
}

#[test]
fn loose_width_arbitration_orders_candidates_without_discarding_them() {
    for tie in [false, true] {
        let rows = vec![
            row("same.header1", "7z", Some(1), false),
            row("same.a2", "", None, false),
            row(if tie { "same.b2" } else { "same.b002" }, "", None, false),
            row("same.c0002", "", None, false),
        ];
        let groups = resolve(&rows);
        let plan = groups[0].attempts.as_ref().unwrap();
        let (_, choices) = &plan.layouts.last().unwrap().slots[1];
        assert_eq!(choices.len(), 3);
        assert_eq!(plan.sources[choices[0]].path, rows[1].path);
    }
}

#[test]
fn canonical_and_stable_facts_are_monotonic_before_loose_numbers() {
    let rows = vec![
        row("same.header1", "7z", Some(1), false),
        row("same.7z.002", "", None, false),
        row("same.header3", "", None, false),
        row("same.x2.y4", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups[0].reason, None);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3, 4]);
    for (i, volume) in groups[0].proposal.volumes.iter().enumerate() {
        assert_eq!(volume.0, rows[i].path);
    }
}

#[test]
fn partial_canonical_ambiguity_does_not_fall_through_to_widths() {
    let rows = vec![
        row("same.header1", "zip", Some(1), false),
        row("same.part2.zip", "", None, false),
        row("same.zip.003", "", None, false),
    ];
    let groups = resolve(&rows);
    assert!(groups[0]
        .attempts
        .as_ref()
        .is_some_and(|plan| !plan.layouts.is_empty()));
    assert_eq!(slots(&groups[0]), vec![1]);
}

#[test]
fn encrypted_rar_sfx_and_plain_members_share_one_canonical_channel() {
    let mut rows = vec![
        row("same.part1.exe", "rar", None, false),
        row("same.part2.rar", "rar", None, false),
    ];
    for row in &mut rows {
        let anchor = row.anchor_mut().unwrap();
        anchor.needs_password = true;
        anchor.relation_has_next = None;
        anchor.flags = RAR_VERSION_5;
    }
    let head = rows[0].anchor_mut().unwrap();
    head.sfx = true;
    head.pe_state = PeState::Confirmed;
    head.structure_offset = Some(128);
    assert!(resolve(&rows).is_empty());
    // Filenames alone cannot invent an entry behind encrypted headers.
    // Once common header resolution proves it, reuse the same channel.
    rows[0].anchor_mut().unwrap().internal_volume_number = Some(1);
    let mut groups = resolve(&rows);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].reason, None);
    assert_eq!(slots(&groups[0]), vec![1, 2]);
    validate::validate(&mut groups[0]);
    assert_eq!(groups[0].status, ProposalStatus::NeedsPassword);
    assert!(validation_relation_confirmed(&groups[0]));
}

#[test]
fn stable_ambiguity_keeps_canonical_facts_even_when_loose_widths_differ() {
    let rows = vec![
        row("same.build1.chunk1", "7z", Some(1), false),
        row("same.7z.002", "", None, false),
        row("same.build003.chunk4", "", None, false),
        row("same.build4.chunk0003", "", None, false),
    ];
    let groups = resolve(&rows);
    let plan = groups[0].attempts.as_ref().unwrap();
    assert_eq!(plan.layouts[0].slots.len(), 4);
    for layout in &plan.layouts {
        if let Some((_, choices)) = layout.slots.iter().find(|(n, _)| *n == 2) {
            assert!(choices
                .iter()
                .all(|i| plan.sources[*i].path == rows[1].path));
        }
    }
}

#[test]
fn complete_stronger_mapping_does_not_claim_numeric_residual_noise() {
    let mut rows = vec![
        row("same.7z.001", "7z", Some(1), false),
        row("same.7z.002", "", None, false),
        row("same.x3", "", None, false),
        row("same.2024.txt", "", None, false),
    ];
    rows[0].anchor_mut().unwrap().expected_logical_size = Some(200);
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn loose_numbers_respect_format_roles_and_do_not_drop_owned_members() {
    let mut rows = vec![
        row("same.header1", "zip", Some(1), false),
        row("same.x2", "", None, false),
        row("same.y3", "", None, false),
        row("same.z0.a4.b7", "zip", Some(4), true),
        row("same.unassigned", "zip", None, false),
    ];
    rows[4].anchor_mut().unwrap().flags &= !ZIP_SPLIT_START;
    let groups = resolve(&rows);
    assert!(groups[0].attempts.is_some());
    assert!(validation_owned_paths(&groups[0]).contains(&rows[4].path));
}

#[test]
fn mixed_alphanumeric_fields_are_legal_loose_numbers() {
    let rows = vec![
        row("same.header1", "zip", Some(1), false),
        row("same.7z.blob0", "", None, false),
        row("same.end", "zip", Some(8), true),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 7, 8]);
}

#[test]
fn duplicate_numeric_occurrences_collapse_to_one_file_slot_edge() {
    let rows = vec![
        row("same.header1", "7z", Some(1), false),
        row("same.a002.b2.c03", "", None, false),
        row("same.d03", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups[0].reason, None);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].proposal.volumes[1].0, rows[1].path);
}

#[test]
fn missing_head_cannot_enable_context_free_inference() {
    let rows = vec![
        row("same.end0", "zip", Some(4), true),
        row("same.x2", "", None, false),
        row("same.y3", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
    assert_eq!(slots(&groups[0]), vec![4]);
}

#[test]
fn singleton_domain_requires_a_structural_terminal_bound() {
    let mut rows = vec![
        row("same.head", "rar", Some(1), false),
        row("same.unknown", "rar", None, false),
    ];
    assert_eq!(
        resolve(&rows)[0].reason,
        Some(RelationFailureReason::MissingVolume)
    );
    rows.push(row("same.end", "rar", Some(3), true));
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn bare_seven_zip_extension_does_not_constrain_a_member_number_channel() {
    let rows = vec![
        row("same.7z", "7z", Some(1), false),
        row("same.chunk2", "", None, false),
        row("same.chunk3", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2, 3]);
    assert_eq!(groups[0].reason, None);
}

#[test]
fn ordinary_unrelated_rows_remain_residual() {
    let rows = vec![
        row("same.7z.001", "7z", Some(1), false),
        row("same.7z.002", "", None, false),
        row("same.notes", "", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2]);
    assert!(!validation_owned_paths(&groups[0]).contains("same.notes"));
}

#[test]
fn structurally_owned_unknown_cannot_be_discarded() {
    let rows = vec![
        row("same.part1.rar", "rar", Some(1), false),
        row("same.unassigned", "rar", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
    assert!(validation_owned_paths(&groups[0]).contains("same.unassigned"));
}

#[test]
fn competing_heads_need_distinct_canonical_families() {
    for canonical in [false, true] {
        let names = if canonical {
            [
                "same.alpha.7z.001",
                "same.alpha.7z.002",
                "same.beta.7z.001",
                "same.beta.7z.002",
            ]
        } else {
            [
                "same.alpha.chunk1",
                "same.alpha.chunk2",
                "same.beta.chunk1",
                "same.beta.chunk2",
            ]
        };
        let rows: Vec<_> = names
            .into_iter()
            .enumerate()
            .map(|(i, n)| {
                row(
                    n,
                    if i % 2 == 0 { "7z" } else { "" },
                    (i % 2 == 0).then_some(1),
                    false,
                )
            })
            .collect();
        let groups = resolve(&rows);
        if canonical {
            assert_eq!(groups.len(), 2);
            assert!(groups
                .iter()
                .all(|g| g.reason.is_none() && slots(g) == vec![1, 2]));
        } else {
            assert_eq!(groups.len(), 2);
            assert!(groups.iter().all(|group| group.attempts.is_some()));
            assert!(Arc::ptr_eq(&groups[0].facts, &groups[1].facts));
        }
    }
}

#[test]
fn lone_proven_split_member_waits_for_an_entry() {
    let rows = vec![row("same.part2.rar", "rar", Some(2), true)];
    assert!(resolve(&rows).is_empty());
}

#[test]
fn singleton_encrypted_rar_requires_split_structure() {
    let mut rows = vec![row("same.part1.rar", "rar", None, false)];
    let anchor = rows[0].anchor_mut().unwrap();
    anchor.multivolume = false;
    anchor.needs_password = true;
    anchor.relation_has_next = None;
    anchor.flags &= !(FIRST | MEMBER | TERMINAL);
    assert!(resolve(&rows).is_empty());
    rows[0].anchor_mut().unwrap().multivolume = true;
    assert!(resolve(&rows).is_empty());
    rows[0].anchor_mut().unwrap().internal_volume_number = Some(1);
    assert_eq!(resolve(&rows).len(), 1);
}

#[test]
fn family_partition_cannot_orphan_a_structural_member() {
    let rows = vec![
        row("same.alpha.7z.001", "7z", Some(1), false),
        row("same.alpha.7z.002", "", None, false),
        row("same.beta.7z.001", "7z", Some(1), false),
        row("same.beta.7z.002", "", None, false),
        row("same.unassigned", "7z", None, false),
    ];
    let groups = resolve(&rows);
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|group| group.attempts.is_some()
        && validation_owned_paths(group).contains("same.unassigned")));
}

#[test]
fn virtual_siblings_share_padding_despite_physical_widths() {
    let rows = vec![
        row("same.part1.rar", "rar", Some(1), false),
        row("same.part0002.rar", "rar", Some(2), true),
    ];
    let groups = resolve(&rows);
    assert_eq!(slots(&groups[0]), vec![1, 2]);
    assert_eq!(groups[0].proposal.width, 1);
}

#[test]
fn launcher_ownership_respects_the_bucket_and_logical_family() {
    for name in ["same.exe", "same.unrelated.exe", "other.exe"] {
        let mut launcher = row(name, "", None, false);
        let anchor = launcher.anchor_mut().unwrap();
        anchor.sfx = true;
        anchor.pe_state = PeState::Confirmed;
        anchor.flags = SEVEN_ZIP_STUB;
        let rows = vec![
            row("same.7z.001", "7z", Some(1), false),
            row("same.7z.002", "", None, false),
            launcher,
        ];
        let groups = resolve(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].proposal.companions.len(),
            usize::from(name == "same.exe")
        );
        assert_eq!(slots(&groups[0]), vec![1, 2]);
    }
}

#[test]
fn huge_sparse_slots_do_not_enumerate_domains() {
    let rows = vec![
        row("same.head", "rar", Some(1), false),
        row("same.chunk2", "rar", None, false),
        row("same.tail", "rar", Some(u32::MAX), true),
    ];
    let mut groups = resolve(&rows);
    validate::validate(&mut groups[0]);
    assert_eq!(groups[0].reason, Some(RelationFailureReason::MissingVolume));
}
