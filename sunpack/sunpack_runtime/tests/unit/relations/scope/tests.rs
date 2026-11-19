use super::*;

fn row(path: &str, seed: bool, eligible: bool) -> RelationInput {
    RelationInput {
        path: path.into(),
        path_key: path_key(path),
        size: Some(17),
        relation_member_eligible: eligible,
        anchor_cell: None,
        anchor: seed.then(|| VolumeAnchor {
            multivolume: true,
            internal_volume_number: Some(1),
            ..VolumeAnchor::default()
        }),
    }
}

fn scope(rows: &[RelationInput], selected: &[usize]) -> RelationScopeIndex {
    let keys = selected.iter().map(|&i| rows[i].path_key.clone()).collect();
    RelationScopeIndex::build(&RelationSource::Physical(rows), &keys, None)
}

#[test]
fn active_bucket_keeps_unselected_competitors_and_excluded_members() {
    let rows = vec![
        row(r"C:\game\Payload.part1.fake", true, true),
        row(r"c:\GAME\payload.7z.001", true, true),
        row(r"C:\game\PAYLOAD.part2.photo", false, true),
        row(r"C:\game\payload.part3.hard_excluded", false, false),
        row(r"C:\game\other.part1.fake", true, true),
    ];
    let index = scope(&rows, &[0]);
    assert_eq!(index.rows, vec![0, 1, 2, 3]);
    let member = RelationSource::Physical(&rows).materialize(3);
    assert!(!member.relation_member_eligible);
    assert_eq!(member.size, Some(17));
}

#[test]
fn selecting_a_member_or_launcher_can_activate_an_unselected_head() {
    let rows = vec![
        row(r"C:\game\payload.part1.disguised", true, true),
        row(r"C:\other\payload.part2.fake", false, true),
        row(r"C:\game\payload.exe", false, true),
    ];
    for selected in [1, 2] {
        assert_eq!(scope(&rows, &[selected]).rows, vec![0, 1, 2]);
    }
}

#[test]
fn selected_rows_preserve_source_order_across_directories() {
    let rows = vec![
        row(r"C:\first\ignored.txt", false, true),
        row(r"C:\second\selected.zip", false, true),
        row(r"C:\first\selected.zip", false, true),
        row(r"C:\unselected\payload.part1.rar", true, true),
    ];
    assert_eq!(scope(&rows, &[1, 2]).rows, vec![1, 2]);
}

#[test]
fn standalone_anchor_does_not_activate_siblings() {
    let mut rows = vec![
        row(r"C:\game\payload.zip", true, true),
        row(r"C:\game\payload.001", false, true),
    ];
    rows[0].anchor.as_mut().unwrap().standalone = true;
    assert_eq!(scope(&rows, &[0]).rows, vec![0]);
    assert!(scope(&rows, &[]).rows.is_empty());
}

#[test]
fn borrowed_keys_follow_windows_case_equality_across_hash_blocks() {
    let upper = format!("{}Ä", "A".repeat(130));
    let lower = format!("{}Ä", "a".repeat(130));
    let unicode_lower = format!("{}ä", "a".repeat(130));
    let keys = HashSet::from([CaseKey::new(&upper)]);
    assert!(keys.contains(&CaseKey::new(&lower)));
    assert_eq!(keys.contains(&CaseKey::new(&unicode_lower)), cfg!(windows));
}
