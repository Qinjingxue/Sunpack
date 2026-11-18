use super::*;

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
fn payload_prefix_collisions_survive_until_complete_header_evidence() {
    let candidates: Vec<Arc<str>> = ["wrong", "collision", "wrong2", "correct", "later"]
        .into_iter()
        .map(Arc::from)
        .collect();
    let weak = collect_candidates(&candidates, Some("7z_payload_prefix"), |_, value| {
        Ok(if value == "collision" || value == "correct" {
            SevenZipPrefixCheck::Weak
        } else {
            SevenZipPrefixCheck::Reject
        })
    })
    .unwrap();
    assert_eq!(weak.matched_indices, [1, 3]);
    assert_eq!(weak.attempts, candidates.len());
    assert_eq!(weak.final_confirmation_required, Some(true));
    let confirmed = collect_candidates(&candidates, Some("7z_payload_prefix"), |_, value| {
        Ok(match value {
            "collision" => SevenZipPrefixCheck::Strong,
            "correct" => SevenZipPrefixCheck::Confirmed,
            _ => SevenZipPrefixCheck::Reject,
        })
    })
    .unwrap();
    assert_eq!(confirmed.matched_index, Some(3));
    assert_eq!(confirmed.final_confirmation_required, Some(false));
    let absent =
        collect_candidates(&candidates, Some("7z_payload_prefix"), |_, _| Ok(SevenZipPrefixCheck::Reject))
            .unwrap();
    assert_eq!(absent.status, "no_match");
    assert_eq!(absent.attempts, candidates.len());
    let fault_or_reject = |index, _: &str| {
        if index == 2 {
            Err("resource_unavailable: test".into())
        } else {
            Ok(SevenZipPrefixCheck::Reject)
        }
    };
    for (proof, tested) in [(Some("7z_payload_prefix"), candidates.len()), (None, 3)] {
        let fault = collect_candidates(&candidates, proof, fault_or_reject).unwrap();
        assert_eq!(fault.matched_indices, [2]);
        assert_eq!(fault.attempts, tested);
        assert_eq!(fault.final_confirmation_required, Some(true));
    }
}

#[test]
fn uncertain_7z_tails_use_crc_linked_evidence_but_preserve_unknown_paths() {
    let bytes: &[u8] = &[
        55, 122, 188, 175, 39, 28, 0, 4, 178, 190, 162, 6, 16, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0, 0, 0,
        0, 0, 0, 137, 92, 122, 211, 37, 116, 224, 226, 140, 241, 42, 72, 179, 115, 25, 153, 186,
        152, 193, 102, 1, 4, 6, 0, 1, 9, 16, 0, 7, 11, 1, 0, 2, 36, 6, 241, 7, 1, 18, 83, 15, 90,
        12, 52, 178, 191, 180, 172, 56, 77, 7, 166, 158, 159, 175, 101, 31, 1, 0, 1, 0, 12, 16, 16,
        0, 8, 10, 1, 53, 59, 166, 46, 0, 0, 5, 1, 25, 3, 0, 0, 0, 17, 5, 0, 120, 0, 0, 0, 20, 10,
        1, 0, 100, 53, 227, 238, 121, 118, 221, 1, 21, 6, 1, 0, 32, 0, 0, 0, 0, 0,
    ];
    // The same Copy data, this time with the optional public PackInfo CRC.
    // Both tails have the right NextHeader. Only their packed bytes differ.
    let mut with_digest = bytes.to_vec();
    let digest = crc32fast::hash(&bytes[32..48]);
    with_digest.splice(55..55, [0x0a, 1].into_iter().chain(digest.to_le_bytes()));
    update_descriptor_crc(&mut with_digest);
    let (paths, sources, plan) = uncertain_tail_fixture_at(&with_digest, &[], 32);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(|_| panic!("packed CRC"));
    let result = context.verify(&[Arc::from("secret")], None).unwrap();
    assert!(!result.volume_attempts.unwrap().sources.iter().any(|source| source.path == sources[1].path));
    drop(context);
    for path in paths { std::fs::remove_file(path).unwrap(); }
    let (paths, sources, mut plan) = uncertain_tail_fixture(bytes);
    {
        let context =
            prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(
                |error| match error {
                    PreparedStatus::Status(status, message) => {
                        panic!("valid tail: {status}: {message}")
                    }
                    PreparedStatus::ReadFault(fault) => panic!("valid tail: {fault:?}"),
                },
            );
        let result = context
            .verify(&[Arc::from("wrong"), Arc::from("secret")], None)
            .unwrap();
        // AES + Copy has no compression-prefix proof. Only the public
        // NextHeader CRC can reject a tail; member CRC belongs to the worker.
        assert_eq!(result.status, "unknown_needs_final_verifier");
        let remaining = result.volume_attempts.unwrap();
        assert!(!remaining.sources.iter().any(|source| source.path == sources[1].path));
        assert_eq!(
            context.verify(&[Arc::from("wrong")], None).unwrap().status,
            "unknown_needs_final_verifier"
        );
    }
    // A completed combination shorter than the declared NextHeader cannot be
    // the archive. It must not hide the good tail as an unknown alternative.
    plan.domains[1].choices = Arc::new(vec![2, 3]);
    assert!(prepare_seven_zip_attempts(&sources[0], &plan, &[], None).is_ok());
    // A physical EOF inside the declared extent excludes this choice when
    // another tail supplies the range. An open failure retains its choice.
    plan.sources[3].end = Some((bytes.len() - 48) as u64);
    let unavailable = InputExtent { path: format!("{}.absent", sources[3].path), ..plan.sources[3].clone() };
    plan.sources = plan.sources.iter().cloned().chain([unavailable.clone()]).collect();
    plan.domains[1].choices = Arc::new(vec![2, 3, 4]);
    let uncertain = prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(|_| panic!("retain unsupported paths"));
    let result = uncertain.verify(&[Arc::from("secret")], None).unwrap();
    assert_eq!(result.status, "unknown_needs_final_verifier");
    let remaining = result.volume_attempts.unwrap();
    assert!(!remaining.sources.iter().any(|source| source.path == sources[3].path));
    assert!(remaining.sources.iter().any(|source| source.path == unavailable.path));
    // A fixed-size tail proves the head trim, but does not prove a Copy key.
    plan.domains[1].choices = Arc::new(vec![2]);
    plan.head_size_from_total = Some(bytes.len() as u64);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None)
        .unwrap_or_else(|_| panic!("exact tail geometry proves carrier trim"));
    assert_eq!(
        context
            .verify(&[Arc::from("secret")], None)
            .unwrap()
            .status,
        "unknown_needs_final_verifier"
    );
    drop(context);
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}

// Both tests use the same real two-part layout; only the evidence kind differs.
fn uncertain_tail_fixture(
    bytes: &[u8],
) -> (Vec<std::path::PathBuf>, Vec<InputExtent>, VolumeAttemptPlan) {
    uncertain_tail_fixture_at(bytes, &[], 48)
}

fn uncertain_tail_fixture_at(
    bytes: &[u8],
    suffix: &[u8],
    split: usize,
) -> (Vec<std::path::PathBuf>, Vec<InputExtent>, VolumeAttemptPlan) {
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    let mut bad = bytes[split..].to_vec();
    bad[0] ^= 1;
    let mut good = bytes[split..].to_vec();
    good.extend_from_slice(suffix);
    let paths = [
        crate::test_support::temp_file("attempt_head", &bytes[..split]),
        crate::test_support::temp_file("attempt_bad_tail", &bad),
        crate::test_support::temp_file("attempt_good_tail", &good),
        crate::test_support::temp_file("attempt_short_tail", &[0; 7]),
    ];
    let sources: Vec<_> = paths
        .iter()
        .map(|path| InputExtent {
            path: path.to_string_lossy().into_owned(),
            start: 0,
            end: Some(std::fs::metadata(path).unwrap().len()),
        })
        .collect();
    let plan = VolumeAttemptPlan {
        sources: sources.clone().into_boxed_slice(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: vec![
                VolumeSlot {
                    number: 1,
                    canonical_name: "x.001".into(),
                    domain: 0,
                },
                VolumeSlot {
                    number: 2,
                    canonical_name: "x.002".into(),
                    domain: 1,
                },
            ]
            .into_boxed_slice(),
        }]
        .into_boxed_slice(),
        domains: vec![
            VolumeDomain {
                choices: Arc::new(vec![0]),
            },
            VolumeDomain {
                choices: Arc::new(vec![1, 2]),
            },
        ]
        .into_boxed_slice(),
        head_size_from_total: None,
        minimum_size: Some(bytes.len() as u64),
        tail_totals: Box::new([]),
    };
    (paths.into(), sources, plan)
}

#[test]
fn encrypted_header_alternative_ciphertexts_share_candidate_kdf_and_confirm() {
    // Real 7-Zip AES-encrypted Copy header. Both tails retain exactly the same
    // CRC-valid public descriptor, but the first tail has corrupted ciphertext.
    let bytes: &[u8] = &[
        55, 122, 188, 175, 39, 28, 0, 4, 150, 96, 215, 24, 112, 0, 0, 0, 0, 0, 0, 0, 46, 0, 0, 0,
        0, 0, 0, 0, 69, 149, 29, 212, 3, 225, 66, 163, 147, 140, 91, 232, 1, 22, 148, 68, 77, 132,
        149, 99, 31, 50, 205, 33, 183, 240, 152, 241, 51, 160, 215, 44, 87, 99, 236, 160, 143, 65,
        226, 141, 180, 33, 118, 251, 78, 242, 186, 228, 202, 40, 250, 35, 17, 116, 180, 107, 36,
        102, 94, 237, 143, 161, 155, 45, 69, 113, 130, 168, 147, 181, 132, 123, 233, 44, 115, 11,
        164, 24, 112, 255, 148, 185, 51, 41, 124, 122, 202, 128, 51, 92, 47, 177, 22, 183, 64, 249,
        25, 233, 250, 15, 19, 184, 222, 124, 90, 189, 177, 134, 238, 105, 241, 244, 182, 66, 30,
        132, 23, 6, 16, 1, 9, 96, 0, 7, 11, 1, 0, 1, 36, 6, 241, 7, 1, 18, 83, 15, 136, 73, 242,
        156, 134, 229, 231, 126, 225, 247, 29, 129, 125, 4, 71, 144, 12, 90, 10, 1, 216, 135, 198,
        224, 0, 0,
    ];
    // Remove the optional folder CRC from the same real encoded header.
    // AES -> Copy exposes the Header NID but cannot confirm the password.
    let mut crc_less = bytes.to_vec();
    let crc_field = crc_less.len() - 8;
    assert_eq!(&crc_less[crc_field..crc_field + 2], &[0x0a, 1]);
    crc_less.drain(crc_field..crc_field + 6);
    update_descriptor_crc(&mut crc_less);
    let context = prepare_seven_zip(std::io::Cursor::new(&crc_less), crc_less.len() as u64)
        .unwrap_or_else(|_| panic!("CRC-less header must use prefix evidence"));
    let result = context.verify(&[Arc::from("wrong-first"), Arc::from("secret")]).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.match_evidence, Some("7z_header_prefix"));
    assert_eq!(result.final_confirmation_required, Some(true));
    // The correct tail has trailing carrier junk, unlike the bad-cipher tail.
    // Right-aligning it at NextHeader.end would discard the correct password.
    let (mut paths, mut sources, mut plan) =
        uncertain_tail_fixture_at(bytes, b"trailing carrier junk", 48);
    // Production relation heads spell physical EOF as None, while the plan
    // records the exact same physical boundary as Some(file length).
    let mut fixed_head = sources[0].clone();
    fixed_head.end = None;
    let mut earlier_head = fixed_head.clone();
    earlier_head.end = Some(47);
    assert!(
        prepare_seven_zip_attempts(&earlier_head, &plan, &[], None).is_err(),
        "an earlier explicit boundary is a different logical head"
    );
    let context =
        prepare_seven_zip_attempts(&fixed_head, &plan, &[], None).unwrap_or_else(|error| match error {
            PreparedStatus::Status(status, message) => panic!("header tails: {status}: {message}"),
            PreparedStatus::ReadFault(fault) => panic!("header tails: {fault:?}"),
        });
    let PasswordContext::Evidence(evidence) = &context else {
        panic!("must prepare alternatives")
    };
    assert_eq!(
        evidence.alternatives.len(),
        2,
        "ciphertext damage must not discard the valid public descriptor"
    );
    assert!(evidence.alternatives.iter().all(|(probe, _)| matches!(probe, PasswordContext::SevenZip(SevenZipPasswordContext::Header(_)))));
    let result = context
        .verify(&[
            Arc::from("wrong-first"),
            Arc::from("secret"),
            Arc::from("wrong-last"),
        ], None)
        .unwrap();
    assert_eq!(result.status, "match");
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.final_confirmation_required, Some(false));

    let rejected = context
        .verify(&[Arc::from("wrong-first"), Arc::from("wrong-last")], None)
        .unwrap();
    assert_eq!(rejected.status, "no_match");
    assert_eq!(rejected.attempts, 2);

    drop(context);
    // Re-encrypt the same 90-byte decoded Header with "second-tail", using the
    // original descriptor's AES parameters and CBC padding. Both tail choices
    // now pass the Folder CRC but require different passwords.
    let mut second_tail = bytes[48..].to_vec();
    second_tail[..96].copy_from_slice(&[
        4, 6, 32, 112, 150, 66, 22, 66, 250, 215, 201, 115, 139, 95, 113, 56,
        203, 239, 43, 18, 140, 231, 142, 181, 251, 57, 58, 83, 24, 209, 119, 74,
        85, 91, 179, 210, 154, 187, 108, 144, 223, 1, 53, 216, 173, 135, 15, 42,
        243, 192, 203, 246, 173, 0, 247, 134, 123, 4, 146, 241, 108, 146, 109, 103,
        156, 83, 147, 93, 67, 172, 208, 216, 111, 17, 212, 51, 137, 201, 225, 35,
        160, 112, 147, 151, 76, 80, 117, 37, 103, 180, 233, 252, 59, 8, 199, 27,
    ]);
    std::fs::write(&paths[1], second_tail).unwrap();
    let two = prepare_seven_zip_attempts(&fixed_head, &plan, &[], None)
        .unwrap_or_else(|_| panic!("two valid encrypted tails"));
    let PasswordContext::Evidence(two) = two else { panic!("expected two tail choices") };
    let passwords = ["wrong", "secret", "second-tail"].map(Arc::from);
    let first_batch = two.verify_batch(&passwords[..2], false, false).unwrap();
    assert_eq!(first_batch.matched_indices, [1]);
    assert_eq!(first_batch.final_confirmation_required, Some(true));

    let result = two.verify(&passwords).unwrap();
    assert_eq!(result.matched_indices, [1, 2]);
    assert_eq!(result.final_confirmation_required, Some(true));
    let mut domains = crate::password::evidence::CandidateDomains::default();
    domains.append(result.password_domains, 0, 2);
    let (remaining, bound) = domains.finish(&two, 2).unwrap().unwrap();
    let bound = serde_json::to_value(bound).unwrap();
    assert_eq!(remaining.layouts.len(), 2);
    for (index, layout) in remaining.layouts.iter().enumerate() {
        let tail = &remaining.domains[layout.slots[1].domain].choices;
        assert_eq!(tail.len(), 1);
        let (source, expected) = [(1, 1), (2, 0)][index];
        assert_eq!(remaining.sources[tail[0]].path, sources[source].path);
        let group = bound["layout_password_domains"][index].as_u64().unwrap() as usize;
        assert_eq!(bound["password_domains"][group], serde_json::json!([expected]));
    }
    drop(two);
    // Now the encrypted header straddles a variable-length middle and tail.
    // Two physical ciphertexts share the same length; a third length moves the
    // public descriptor and is excluded by its CRC, without a Cartesian scan.
    let mut damaged_middle = bytes[48..80].to_vec();
    damaged_middle[0] ^= 1;
    let mut shifted_middle = bytes[48..80].to_vec();
    shifted_middle.push(0);
    let mut final_tail = bytes[80..].to_vec();
    final_tail.extend_from_slice(b"carrier suffix");
    for (name, data) in [
        ("middle_bad", damaged_middle.as_slice()),
        ("middle_good", &bytes[48..80]),
        ("middle_wrong_length", shifted_middle.as_slice()),
        ("final_tail", final_tail.as_slice()),
    ] {
        let path = crate::test_support::temp_file(name, data);
        sources.push(InputExtent {
            path: path.to_string_lossy().into_owned(),
            start: 0,
            end: Some(data.len() as u64),
        });
        paths.push(path);
    }
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    plan.sources = sources.clone().into_boxed_slice();
    plan.domains = vec![
        VolumeDomain {
            choices: Arc::new(vec![0]),
        },
        VolumeDomain {
            choices: Arc::new(vec![4, 5, 6]),
        },
        VolumeDomain {
            choices: Arc::new(vec![7]),
        },
    ]
    .into_boxed_slice();
    plan.layouts = vec![VolumeLayout {
        minimum_slots: 2,
        slots: (0..3)
            .map(|index| VolumeSlot {
                number: index as u32 + 1,
                canonical_name: format!("x.{:03}", index + 1),
                domain: index,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    }]
    .into_boxed_slice();
    let middle = prepare_seven_zip_attempts(&fixed_head, &plan, &[], None)
        .unwrap_or_else(|_| panic!("middle evidence projection"));
    let result = middle
        .verify(&[
            Arc::from("wrong-first"),
            Arc::from("secret"),
            Arc::from("wrong-last"),
        ], None)
        .unwrap();
    assert_eq!(result.matched_index, Some(1));

    drop(middle);
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}

fn update_descriptor_crc(bytes: &mut [u8]) {
    let start = 32 + u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    let len = (bytes.len() - start) as u64;
    bytes[20..28].copy_from_slice(&len.to_le_bytes());
    let next_crc = crc32fast::hash(&bytes[start..]);
    bytes[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32fast::hash(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc.to_le_bytes());
}
