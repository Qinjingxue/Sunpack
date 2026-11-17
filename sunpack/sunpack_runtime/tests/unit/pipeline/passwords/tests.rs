use super::*;
use crate::password::attempts::{AttemptCache, MAX_REJECTIONS, MAX_SUCCESSES};

#[test]
fn relations_share_batched_password_proofs_and_skip_single_volume_directory() {
    use crate::password::rar::{rar5_header_decryption_tests::{hex_bytes, SINGLE_HP_HEX}, RAR5_CANDIDATE_THREADS};
    use crate::analysis_native::volume_anchor::probe_volume_anchor_at_offset;
    let bytes = hex_bytes(SINGLE_HP_HEX);
    let source = crate::test_support::temp_file("relations_password_plan", &bytes);
    let path = source.to_string_lossy().into_owned();
    let cache = RecentPasswords::default();
    let wrong: Vec<Arc<str>> = (0..256).map(|n| Arc::from(format!("wrong-{n}"))).collect();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    pool.install(|| {
        let anchor = probe_volume_anchor_at_offset(&path, 0, "rar");
        // The session owns proofs across repeated verification batches.
        let session = NativeArchiveSession::new(path.clone()).unwrap();
        let cancel = Cancellation::new();
        let threads = Arc::new(Mutex::new(Vec::new()));
        RAR5_CANDIDATE_THREADS.with(|value| *value.borrow_mut() = Some(threads.clone()));
        PLANNED_BATCHES.with(|value| *value.borrow_mut() = Some(Vec::new()));
        let candidates = CandidateSet::new(wrong.clone().into(), None, &cache, None);
        let (blocked, password) = candidates.resolve_relation(&anchor, &session, &cancel).unwrap();
        assert!(blocked.wrong_password && password.is_none());
        assert_eq!(threads.lock().unwrap().len(), 256);
        assert!(threads.lock().unwrap().iter().collect::<HashSet<_>>().len() > 1);
        let (blocked, _) = candidates.resolve_relation(&anchor, &session, &cancel).unwrap();
        assert!(blocked.wrong_password);
        assert_eq!(threads.lock().unwrap().len(), 256, "hot retry must skip old KDFs");
        let mut extended = wrong.clone(); extended.push(Arc::from("secret"));
        let candidates = CandidateSet::new(extended.into(), None, &cache, None);
        let (resolved, password) = candidates.resolve_relation(&anchor, &session, &cancel).unwrap();
        assert_eq!(password.as_deref(), Some("secret"));
        assert!(resolved.standalone && !resolved.needs_password);
        assert!(resolved.relation_has_next.is_none(), "standalone must stop after the main header");
        assert_eq!(threads.lock().unwrap().len(), 257);
        PLANNED_BATCHES.with(|value| {
            let value = value.borrow(); let batches = value.as_ref().unwrap();
            assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [256, 1]);
        });
        // Replacing the source invalidates old rejection/proof generations.
        std::fs::write(&source, [&bytes[..], b"tail"].concat()).unwrap();
        let changed = NativeArchiveSession::new(path.clone()).unwrap();
        let candidates = CandidateSet::new(wrong.into(), None, &cache, None);
        assert!(candidates.resolve_relation(&anchor, &changed, &cancel).unwrap().0.wrong_password);
        assert_eq!(threads.lock().unwrap().len(), 513);
        RAR5_CANDIDATE_THREADS.with(|value| *value.borrow_mut() = None);
        PLANNED_BATCHES.with(|value| *value.borrow_mut() = None);
    });
    std::fs::remove_file(source).unwrap();
}

#[test]
fn empty_and_three_configured_passwords_share_the_encrypted_header_batch() {
    // 7-Zip 26.03: 7z a -t7z -mx=0 -mhe=on -pcorrect batch.7z payload
    // The encrypted header has a folder CRC, which the fast verifier
    // needs to prove the password before the worker opens the archive.
    let bytes = [
        0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0xf8, 0xcd, 0x9d, 0x80, 0x80, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0xaf, 0x9b, 0x43,
        0x4a, 0x97, 0x2e, 0x47, 0x3d, 0xd1, 0x5d, 0xe9, 0x9a, 0xd8, 0x48, 0xe3, 0x95, 0x3f, 0x88, 0x67,
        0x9a, 0xba, 0xfa, 0x4d, 0x09, 0xad, 0x69, 0x96, 0xbe, 0xfe, 0xd9, 0xa3, 0xce, 0x40, 0x47, 0xca,
        0x88, 0xb2, 0xba, 0x3b, 0xb1, 0x80, 0x53, 0xb7, 0x68, 0x74, 0xef, 0x93, 0x3b, 0x9d, 0x62, 0xde,
        0xad, 0xb9, 0x9b, 0xf7, 0x43, 0x2a, 0x23, 0x84, 0x58, 0xcc, 0x25, 0xae, 0xa7, 0x71, 0xe2, 0x6f,
        0x3c, 0xf7, 0x17, 0x81, 0x62, 0xb0, 0xde, 0x7f, 0x2a, 0x44, 0x82, 0x33, 0x3d, 0x7c, 0x21, 0xe9,
        0xa6, 0xf6, 0x0c, 0x57, 0x6e, 0xe9, 0x1c, 0x08, 0x90, 0x63, 0x6a, 0x9b, 0xa3, 0xd2, 0x18, 0x4a,
        0x81, 0xac, 0xfb, 0xa8, 0xaa, 0x90, 0x10, 0x2e, 0x20, 0xe7, 0xa5, 0xc4, 0x0a, 0x51, 0x16, 0x4b,
        0x63, 0x95, 0xd5, 0x00, 0x10, 0x42, 0xbe, 0xe2, 0xa9, 0xda, 0x6e, 0x3c, 0x7f, 0xc6, 0x26, 0xfc,
        0x17, 0x06, 0x10, 0x01, 0x09, 0x70, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x01, 0x24, 0x06, 0xf1, 0x07,
        0x01, 0x12, 0x53, 0x0f, 0x43, 0xf9, 0xce, 0x0c, 0x83, 0x81, 0x11, 0x6a, 0x12, 0x6e, 0x4e, 0xe5,
        0xe3, 0x46, 0xa6, 0x12, 0x0c, 0x6a, 0x0a, 0x01, 0x26, 0xac, 0x20, 0x83, 0x00, 0x00,
    ];
    let source = crate::test_support::temp_file("password_batch_7z", &bytes);
    // Relations' header geometry does not declare encryption. Exercise that
    // actual password plan, rather than manually invoking the verifier.
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "7z".into(), "archive".into());
    struct Reset;
    impl Drop for Reset { fn drop(&mut self) { PLANNED_BATCHES.with(|value| *value.borrow_mut() = None); } }
    let _reset = Reset;
    for tail in ["correct", "wrong3"] {
        let cache = RecentPasswords::default();
        let candidates = CandidateSet::new(Arc::from([Arc::from("wrong1"), Arc::from("wrong2"), Arc::from(tail)]), None, &cache, None);
        PLANNED_BATCHES.with(|value| *value.borrow_mut() = Some(Vec::new()));
        let plan = candidates.plan(&input, None, &Cancellation::new()).unwrap();
        PLANNED_BATCHES.with(|value| {
            let borrow = value.borrow(); let batches = borrow.as_ref().unwrap();
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].iter().map(AsRef::as_ref).collect::<Vec<&str>>(), ["", "wrong1", "wrong2", tail]);
        });
        if tail == "correct" {
            let plan = plan.unwrap();
            assert_eq!(plan.verified_password.as_deref(), Some("correct"));
        } else { assert!(matches!(plan, Err(Failure { kind: FailureKind::WrongPassword, .. }))); }
    }
    std::fs::remove_file(source).unwrap();
}

#[test]
fn encrypted_empty_rar_crc_failure_uses_verified_direct_password_plan() {
    // Real RAR5 from Rar.exe -ma5 -pfixture-secret, empty.txt. Only the
    // file CRC is damaged; its enclosing header CRC has been recomputed.
    let source = crate::test_support::temp_file("crc_empty_rar", &[82, 97, 114, 33, 26, 7, 1, 0, 51, 146, 181, 229, 10, 1, 5, 6, 0, 5, 1, 1, 128, 128, 0, 138, 98, 34, 111, 86, 2, 3, 60, 144, 0, 4, 128, 0, 32, 243, 251, 157, 52, 128, 3, 0, 9, 101, 109, 112, 116, 121, 46, 116, 120, 116, 48, 1, 0, 3, 15, 193, 88, 249, 247, 42, 138, 96, 222, 172, 113, 197, 80, 56, 137, 60, 185, 108, 179, 130, 137, 125, 195, 143, 174, 207, 163, 1, 120, 21, 154, 87, 254, 248, 185, 39, 15, 144, 111, 233, 62, 123, 127, 192, 14, 10, 3, 2, 164, 7, 232, 133, 136, 115, 221, 1, 51, 121, 211, 16, 206, 151, 73, 238, 124, 252, 221, 165, 125, 51, 144, 88, 29, 119, 86, 81, 3, 5, 4, 0]);
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "rar".into(), "archive".into());
    let cache = RecentPasswords::default();
    let candidates = CandidateSet::new(Arc::from([Arc::from("fixture-secret")]), None, &cache, None);
    let plan = candidates.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
    assert_eq!(plan.verified_password.as_deref(), Some("fixture-secret"));
    assert!(plan.candidates.is_empty(), "must not use the all-rejected candidate fallback");
    std::fs::remove_file(source).unwrap();
}

#[test]
fn attempt_cache_keeps_batch_proofs_and_individual_negative_lru() {
    // More than 128 archive ranges in one source retain results through a hot retry.
    // Independently exercise the real limits, so raising one context cap
    // cannot hide whole-context eviction of negatives or proofs.
    let cache = AttemptCache::default();
    let key = |index| Key::synthetic(index, None);
    let passwords: Vec<Arc<str>> = (0..4).map(|n| Arc::from(n.to_string())).collect();
    for n in 0..129 {
        cache.reject(key(n), &passwords);
        cache.remember_proof(key(n), Some(Arc::from("good")));
    }
    for n in 0..129 {
        let mut candidates = passwords.clone();
        assert!(cache.remove_rejected(&key(n), &mut candidates));
        assert!(candidates.is_empty());
        assert_eq!(cache.proof(&key(n)).unwrap().as_deref(), Some("good"));
    }
    let sparse: Vec<Arc<str>> = (0..BATCH_SIZE * 2).map(|n| Arc::from(n.to_string())).collect();
    let rejected: Vec<_> = sparse.iter().step_by(2).cloned().collect();
    cache.reject(key(130), &rejected);
    let mut candidates = sparse.iter();
    let mut batch = Vec::new();
    cache.fill_available(&key(130), &mut batch, &mut candidates, &Cancellation::new()).unwrap();
    assert!(batch.iter().eq(sparse.iter().skip(1).step_by(2)));
    assert!(candidates.next().is_none());
    let cache = AttemptCache::default();
    for n in 0..MAX_REJECTIONS as u64 {
        cache.reject(key(n), &[Arc::from("bad")]);
    }
    // Touch one entry and exceed the negative limit: only the oldest pair
    // is removed, not the rest of a context or the independent proof.
    cache.remember_proof(key(1), Some(Arc::from("good")));
    assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("bad")]));
    cache.reject(key(0), &[Arc::from("another")]);
    assert!(!cache.remove_rejected(&key(1), &mut vec![Arc::from("bad")]));
    assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("bad")]));
    assert!(cache.proof(&key(1)).is_some());
    for n in 2..=MAX_SUCCESSES as u64 + 1 {
        cache.remember_proof(key(n), Some(Arc::from("good")));
    }
    assert!(cache.proof(&key(1)).is_none());
    assert!(cache.remove_rejected(&key(0), &mut vec![Arc::from("another")]));

    // Force equal hash summaries for different exact layouts. Neither
    // successful nor negative results may leak across the collision.
    let left = Key::synthetic(0, Some(Arc::from([1u8])));
    let right = Key::synthetic(0, Some(Arc::from([2u8])));
    let hash = |key: &Key| {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hash);
        hash.finish()
    };
    assert_eq!(hash(&left), hash(&right));
    cache.remember_proof(left.clone(), Some(Arc::from("left")));
    cache.reject(left, &[Arc::from("wrong")]);
    assert!(cache.proof(&right).is_none());
    assert!(!cache.remove_rejected(&right, &mut vec![Arc::from("wrong")]));
}

#[test]
fn explicit_watch_scope_survives_family_resolution_and_recursion_but_cli_still_uses_path() {
    let cache = RecentPasswords::default();
    let a = Path::new(r"C:\watch\A");
    let b = Path::new(r"C:\watch\B");
    let watch = CandidateSet::new(Arc::from([]), None, &cache, Some(b));
    let cli = CandidateSet::new(Arc::from([]), None, &cache, None);
    for name in ["single.zip", "family.part1.rar", "family.7z.001", "family.zip", "wrapped.enc"] {
        let head = a.join(name);
        assert_eq!(watch.scope(head.to_str().unwrap()), b);
        assert_eq!(cli.scope(head.to_str().unwrap()), a);
    }
    let nested = watch.with_scope(Some(a));
    assert_eq!(nested.scope(r"C:\output\inner.zip"), b);
    let cli_nested = cli.with_scope(Some(a));
    assert_eq!(cli_nested.scope(r"C:\output\inner.zip"), a);
    assert!(Arc::ptr_eq(watch.inherited_scope.as_ref().unwrap(), nested.inherited_scope.as_ref().unwrap()));
}

#[test]
fn failure_signatures_share_lazy_explicit_digest_without_changing_candidates() {
    let cache = RecentPasswords::default();
    let values = Arc::from([Arc::from(""), Arc::from("first"), Arc::from("second")]);
    let candidates = CandidateSet::new(values, None, &cache, None);
    let inherited = candidates.with_scope(Some(Path::new(r"C:\root")));
    // Successful planning/display does not compute receipt fingerprints.
    assert_eq!(candidates.for_embedded(r"C:\root\input.zip"),
        [Arc::<str>::from(""), Arc::from("first"), Arc::from("second")]);
    assert!(candidates.sources.explicit_signature.get().is_none());
    assert!(Arc::ptr_eq(&candidates.sources, &inherited.sources));
    let signature = candidates.signature(r"C:\root\input.zip");
    let digest = candidates.sources.explicit_signature.get().unwrap().as_ptr();
    for index in 0..256 {
        assert_eq!(inherited.signature(&format!(r"C:\nested\{index}.zip")), signature);
        assert_eq!(inherited.sources.explicit_signature.get().unwrap().as_ptr(), digest);
    }
    let reordered = CandidateSet::new(
        Arc::from([Arc::from(""), Arc::from("second"), Arc::from("first")]), None, &cache, None);
    assert_ne!(signature, reordered.signature(r"C:\root\input.zip"));
    let empty = CandidateSet::new(Arc::from([Arc::from("")]), None, &cache, None);
    let absent = CandidateSet::new(Arc::from([]), None, &cache, None);
    assert_ne!(empty.signature("input.zip"), absent.signature("input.zip"));
    let empty_snapshot = CandidateSet::new(Arc::from([]), Some(Arc::default()), &cache, None);
    assert_eq!(absent.signature("input.zip"), empty_snapshot.signature("input.zip"));
}

#[test]
fn preflight_read_failure_retains_machine_readable_evidence() {
    // Two passwords force the Rust probe, unlike single-candidate worker
    // confirmation. This exercises the terminal planning projection.
    let path = crate::test_support::temp_file("enc_read_fault_evidence", b"short");
    let input = ArchiveInput::file(path.to_string_lossy().into_owned(), "enc".into(), "archive".into());
    let cache = RecentPasswords::default();
    let candidates = CandidateSet::new(Arc::from(["first".into(), "second".into()]), None, &cache, None);
    let failure = candidates.plan(&input, None, &Cancellation::new()).unwrap().err().unwrap();
    assert_eq!(failure.kind, FailureKind::Damaged);
    let json = serde_json::to_value(&failure).unwrap();
    let evidence = &json["evidence"];
    assert_eq!(evidence["stage"], "password_preflight");
    let fault = &evidence["archive_read_fault"];
    assert_eq!(fault["field"], "enc.password_proof");
    assert_eq!(fault["offset"], 0);
    assert_eq!(fault["requested"], 72);
    assert_eq!(fault["actual"], 5);
    assert_eq!(fault["possible_missing_volume"], false);
    assert!(!failure.message.is_empty());
    // An advisory tail hint does not turn this same damaged file into a
    // confirmed missing volume. Relation discovery may confirm it.
    let mut hinted = input.clone();
    hinted.analysis.missing_volume_evidence = Some("seven_zip_start_header_length".into());
    assert_eq!(candidates.plan(&hinted, None, &Cancellation::new()).unwrap().err().unwrap().kind,
        FailureKind::Damaged);
    hinted.analysis.origin = crate::io::archive_state::AnalysisOrigin::Relations;
    assert_eq!(candidates.plan(&hinted, None, &Cancellation::new()).unwrap().err().unwrap().kind,
        FailureKind::MissingVolume);
    let _ = std::fs::remove_file(path);
}

#[test]
fn sole_enc_candidate_after_cached_rejections_uses_worker_confirmation() {
    // A host ENC probe would fail on this header. Planning can proceed
    // because the worker will confirm the sole remaining candidate.
    let path = crate::test_support::temp_file("enc_single_candidate_plan", b"short");
    let name = path.to_string_lossy().into_owned();
    let input = ArchiveInput::file(name.clone(), "enc".into(), "archive".into());
    let sessions = [NativeArchiveSession::new(name).unwrap()];
    let cache = RecentPasswords::default();
    let (key, attempts) = Key::for_input(&input, &sessions).unwrap();
    let rejected: Arc<str> = Arc::from("rejected");
    let proof_lifetime = Arc::downgrade(&rejected);
    attempts.reject(key, &[rejected]);
    let candidates = CandidateSet::new(
        Arc::from(["rejected".into(), "confirm-in-worker".into()]),
        None,
        &cache,
        None,
    );
    let plan = candidates
        .plan(&input, None, &Cancellation::new())
        .unwrap()
        .unwrap();
    assert_eq!(plan.candidates.as_slice(), [Arc::<str>::from("confirm-in-worker")]);
    assert_eq!(plan.encrypted, Some(true));
    assert!(plan.verified_password.is_none());

    assert!(proof_lifetime.upgrade().is_some());
    drop(sessions);
    assert!(proof_lifetime.upgrade().is_none());
    let _ = std::fs::remove_file(path);
}
#[test]
fn explicit_empty_enc_candidate_is_not_absent_or_implicit() {
    let path = crate::test_support::temp_file("enc_empty_candidate_plan", b"short");
    let name = path.to_string_lossy().into_owned();
    let input = ArchiveInput::file(name, "enc".into(), "archive".into());
    let cache = RecentPasswords::default();
    let empty = CandidateSet::new(Arc::from([Arc::from("")]), None, &cache, None);
    let plan = empty.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
    assert_eq!(plan.candidates.as_slice(), [Arc::<str>::from("")]);
    let absent = CandidateSet::new(Arc::from([]), None, &cache, None);
    assert_eq!(absent.plan(&input, None, &Cancellation::new()).unwrap()
        .err().unwrap().kind, FailureKind::PasswordRequired);
    let sessions = open_sessions(&input).unwrap();
    let (key, attempts) = Key::for_input(&input, &sessions).unwrap();
    attempts.reject(key.clone(), &[Arc::from("wrong")]);
    let mixed = CandidateSet::new(Arc::from([Arc::from("wrong"), Arc::from("")]), None, &cache, None);
    let plan = mixed.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
    assert_eq!(plan.candidates.as_slice(), [Arc::<str>::from("")]);
    attempts.remember_proof(key, Some(Arc::from("")));
    let cached = empty.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
    assert_eq!(cached.verified_password.as_deref(), Some(""));
    let known = empty.plan(&input, Some(Arc::from("")), &Cancellation::new()).unwrap().unwrap();
    assert_eq!(known.verified_password.as_deref(), Some(""));
    drop(sessions);
    let _ = std::fs::remove_file(path);
}

#[test]
fn compound_attempts_reuse_exact_layout_and_generation_only() {
    use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan,
        VolumeLayout, VolumeSlot, VolumeDomain};
    let head = crate::test_support::temp_file("password_compound_head", b"head");
    let tail = crate::test_support::temp_file("password_compound_tail", b"tail");
    let mut input = ArchiveInput::file(head.to_string_lossy().into_owned(), "rar".into(), "archive".into());
    input.parts = vec![head.clone(), tail.clone()].into_iter().enumerate().map(|(index, path)| InputPart {
        role: if index == 0 { crate::io::archive_state::InputRole::First } else { crate::io::archive_state::InputRole::Member },
        extent: InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: Some(4) },
        volume_number: Some(index as u32 + 1), canonical_name: format!("part{}.rar", index + 1),
    }).collect();
    let cache = RecentPasswords::default();
    for mode in [OpenMode::NativeVolumes, OpenMode::SfxWithVolumes] {
        input.mode = mode;
        let sessions = open_sessions(&input).unwrap();
        let (key, attempts) = Key::for_input(&input, &sessions).unwrap();
        attempts.reject(key.clone(), &[Arc::from("old-wrong")]);
        let mut candidates = vec![Arc::from("old-wrong"), Arc::from("new")];
        assert!(attempts.remove_rejected(&Key::for_input(&input, &sessions).unwrap().0, &mut candidates));
        assert_eq!(candidates, [Arc::<str>::from("new")]);
        attempts.remember_proof(key.clone(), Some(Arc::from("right")));
        assert_eq!(attempts.proof(&key).unwrap().as_deref(), Some("right"));
        // The invalid header would fail a fresh verifier call; a stored
        // proof must return before parsing/KDF for every compound layout.
        let configured = CandidateSet::new(Arc::from([Arc::from("right")]), None, &cache, None);
        let plan = configured.plan(&input, None, &Cancellation::new()).unwrap().unwrap();
        assert_eq!(plan.verified_password.as_deref(), Some("right"));
        let mut changed = input.clone();
        changed.parts[1].extent.start = 1;
        assert!(attempts.proof(&Key::for_input(&changed, &sessions).unwrap().0).is_none());
        changed = input.clone();
        changed.parts.swap(0, 1);
        assert!(attempts.proof(&Key::for_input(&changed, &sessions).unwrap().0).is_none());
    }
    input.volume_attempts = Some(Box::new(VolumeAttemptPlan {
        sources: input.parts.iter().map(|part| part.extent.clone()).collect(),
        layouts: vec![VolumeLayout { slots: vec![VolumeSlot {
            number: 1, canonical_name: "a.rar".into(), domain: 0,
        }].into(), minimum_slots: 1 }].into(),
        domains: vec![VolumeDomain { choices: Arc::new(vec![0, 1]) }].into(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
    }));
    let sessions = open_sessions(&input).unwrap();
    let (planned, attempts) = Key::for_input(&input, &sessions).unwrap();
    attempts.reject(planned.clone(), &[Arc::from("old-wrong")]);
    let mut changed = input.clone();
    changed.volume_attempts.as_mut().unwrap().domains[0].choices = Arc::new(vec![1, 0]);
    assert!(Key::for_input(&changed, &sessions).unwrap().0 != planned);
    // Optional struct fields must retain their names: compact positional
    // serialization aliases these distinct constraints when values match.
    let mut head_constraint = input.clone();
    head_constraint.volume_attempts.as_mut().unwrap().head_size_from_total = Some(4);
    let mut minimum_constraint = input.clone();
    minimum_constraint.volume_attempts.as_mut().unwrap().minimum_size = Some(4);
    let head_key = Key::for_input(&head_constraint, &sessions).unwrap().0;
    let minimum_key = Key::for_input(&minimum_constraint, &sessions).unwrap().0;
    assert!(head_key != minimum_key);
    attempts.reject(head_key, &[Arc::from("wrong-for-head")]);
    let mut candidates = vec![Arc::from("wrong-for-head")];
    attempts.remove_rejected(&minimum_key, &mut candidates);
    assert_eq!(candidates.len(), 1);
    // This flag chooses ZIP volume verification rather than range verification.
    let mut zip = input.clone();
    zip.format_hint = "zip".into();
    zip.analysis.zip_spanned = false;
    let range_key = Key::for_input(&zip, &sessions).unwrap().0;
    attempts.remember_proof(range_key.clone(), Some(Arc::from("right")));
    zip.analysis.zip_spanned = true;
    let volume_key = Key::for_input(&zip, &sessions).unwrap().0;
    assert!(range_key != volume_key);
    assert!(attempts.proof(&volume_key).is_none());
    drop(sessions);
    crate::io::reader::invalidate_reader_path(&tail);
    let sessions = open_sessions(&input).unwrap();
    assert!(Key::for_input(&input, &sessions).unwrap().0 != planned);
    let (fresh_key, fresh_attempts) = Key::for_input(&input, &sessions).unwrap();
    assert!(fresh_attempts.proof(&fresh_key).is_none());
    let mut fresh_candidates = vec![Arc::from("old-wrong")];
    assert!(!fresh_attempts.remove_rejected(&fresh_key, &mut fresh_candidates));
    drop(sessions);
    let _ = std::fs::remove_file(head);
    let _ = std::fs::remove_file(tail);
}
