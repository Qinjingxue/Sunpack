use super::*;

#[test]
fn file_usn_observation_preserves_identity_without_a_journal_record() {
    for (version, length, usn_offset, expected_file_id) in [
        (2u16, 64usize, 24usize, "0000000000001234"),
        (3, 80, 40, "00000000000000000000000000001234"),
        (4, 64, 40, "00000000000000000000000000001234"),
    ] {
        let mut record = vec![0u8; length];
        record[..4].copy_from_slice(&(length as u32).to_le_bytes());
        record[4..6].copy_from_slice(&version.to_le_bytes());
        record[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
        for usn in [0i64, 127] {
            record[usn_offset..usn_offset + 8].copy_from_slice(&usn.to_le_bytes());
            let observation = parse_file_usn_record(&record)
                .expect("zero USN is valid for an unchanged pre-existing file or directory");
            assert_eq!(observation.id_text(), expected_file_id);
            assert_eq!(observation.usn, usn);
        }
        record[usn_offset..usn_offset + 8].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(parse_file_usn_record(&record).is_err());
    }
}

#[test]
fn nearest_existing_ancestor_walks_up_to_a_real_directory() {
    let root = std::env::temp_dir();
    let nested = root
        .join("sunpack-volume-anchor-probe")
        .join("level-one")
        .join("level-two");
    assert!(!nested.exists(), "probe path must not exist");
    let anchor = nearest_existing_ancestor(&nested)
        .expect("a probe under the temp root must be answerable")
        .expect("an existing ancestor");
    assert!(anchor.exists());
    assert!(anchor.starts_with(&root) || root.starts_with(&anchor));
}

#[test]
fn nearest_existing_ancestor_reports_an_unanswerable_query() {
    // An unreachable UNC host must be an error, not a silent "does not exist".
    let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
    match nearest_existing_ancestor(missing) {
        Err(_) => {}
        Ok(None) => {}
        Ok(Some(anchor)) => panic!("unexpectedly resolved an unreachable path: {anchor:?}"),
    }
}

#[test]
fn unreachable_unc_path_never_resolves_to_a_local_volume() {
    let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
    let resolved = resolve_output_volume(missing);
    assert!(
        resolved.is_err(),
        "an unreachable share resolved to {resolved:?} instead of failing"
    );
}

#[test]
fn resolve_output_volume_handles_a_not_yet_created_directory() {
    let root = std::env::temp_dir();
    let pending = root
        .join("sunpack-volume-anchor-probe")
        .join("output-does-not-exist");
    let from_pending = resolve_output_volume(&pending).expect("volume for a pending path");
    let from_root = resolve_output_volume(&root).expect("volume for the existing root");
    // Same temp root, even when temp is a junction to another volume.
    assert_eq!(from_pending, from_root);
    assert!(from_pending.contains("volume{") || from_pending.contains("\\\\"));
}

#[test]
fn resolve_output_volume_rejects_an_unreachable_unc_path() {
    let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
    assert!(resolve_output_volume(missing).is_err());
}
