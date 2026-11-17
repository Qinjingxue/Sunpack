use super::*;

#[test]
fn analysis_parser_confirms_predecoded_header() {
    assert!(predecoded_seven_zip_header_is_supported(&[0x01, 0x00]));
    assert!(!predecoded_seven_zip_header_is_supported(&[0x01, 0xff]));
}

#[test]
fn declared_next_header_beyond_input_requires_a_volume_or_has_damaged_offsets() {
    let mut bytes = [0u8; SEVEN_Z_HEADER_SIZE];
    bytes[..6].copy_from_slice(SEVEN_Z_MAGIC);
    bytes[12..20].copy_from_slice(&64u64.to_le_bytes());
    bytes[20..28].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(
        seven_zip_tail_requirement(&bytes, 64).unwrap_err().field,
        "7z.next_header"
    );
}

#[test]
fn payload_prescreen_preserves_weak_collisions_and_strong_suffix_for_worker() {
    let candidates: Vec<Arc<str>> = ["wrong", "collision", "wrong2", "correct", "later"]
        .into_iter().map(Arc::from).collect();
    let weak = collect_payload_candidates(&candidates, false, |value| Ok(
        if value == "collision" || value == "correct" { SevenZipPrefixCheck::Weak }
        else { SevenZipPrefixCheck::Reject }
    )).unwrap();
    assert_eq!(weak.matched_indices, [1, 3]);
    assert_eq!(weak.attempts, candidates.len());
    assert_eq!(weak.final_confirmation_required, Some(true));
    assert!(!weak.defer_remaining);
    let strong = collect_payload_candidates(&candidates, true, |value| Ok(
        if value == "collision" || value == "correct" { SevenZipPrefixCheck::Strong }
        else { SevenZipPrefixCheck::Reject }
    )).unwrap();
    assert_eq!(strong.matched_index, Some(1));
    assert_eq!(strong.attempts, 2);
    assert!(strong.defer_remaining);
    assert_eq!(strong.final_confirmation_required, Some(true));
    // The ordinary plan must keep the unchecked suffix for a worker rejection
    // of even an extremely unlikely strong-prescreen collision.
    let survivors: Vec<_> = candidates.iter().enumerate().filter(|(i, _)|
        strong.matched_index == Some(*i) || *i >= strong.attempts
    ).map(|(_, value)| value.as_ref()).collect();
    assert_eq!(survivors, ["collision", "wrong2", "correct", "later"]);
    let absent = collect_payload_candidates(&candidates, false, |_| Ok(SevenZipPrefixCheck::Reject)).unwrap();
    assert_eq!(absent.status, "no_match");
    assert_eq!(absent.attempts, candidates.len());
    let fault = collect_payload_candidates(&candidates, false, |value| {
        if value == "wrong2" { Err("resource_unavailable: test".into()) }
        else { Ok(SevenZipPrefixCheck::Reject) }
    }).unwrap();
    assert_eq!(fault.status, "unknown_needs_final_verifier");
    assert_eq!(fault.attempts, 0);
}
