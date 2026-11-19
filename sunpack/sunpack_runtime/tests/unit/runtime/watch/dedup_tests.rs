use super::*;
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("sunpack-dedup-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&p).unwrap(); Self(p)
    }
    fn file(&self, name: &str, data: &[u8]) -> ArchiveInput {
        let path = self.0.join(name); fs::write(&path, data).unwrap();
        ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), name.into())
    }
}
impl Drop for Sandbox { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn admit(index: &mut Index, input: &ArchiveInput, baseline: bool) -> bool {
    let Some(prepared) = index.prepare_path(&input.entry_path, "scope", &[input], baseline).unwrap() else { return false; };
    finish(index, prepared)
}
fn finish(index: &mut Index, mut prepared: Prepared) -> bool {
    loop {
        match index.advance(prepared).unwrap() {
            Admission::Finished(duplicate) => return duplicate,
            Admission::Rescan(pending) => prepared = pending,
            Admission::Hash(mut pending) => {
                pending.hash().unwrap();
                prepared = pending;
            }
        }
    }
}
#[test]
fn live_identity_alias_lifetime_and_mode_reset() {
    let dir = Sandbox::new(); let first = dir.file("first.zip", b"confirmed archive bytes");
    let mut alias = first.clone(); alias.entry_path = dir.0.join("alias.zip").to_string_lossy().into_owned();
    fs::hard_link(&first.entry_path, &alias.entry_path).unwrap();
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::FileId, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    let writer = OpenOptions::new().write(true).open(&first.entry_path).unwrap();
    assert!(index.prepare_path(&first.entry_path, "scope", &[&first], true).unwrap().is_none());
    drop(writer);
    assert!(!admit(&mut index, &first, true)); assert!(admit(&mut index, &alias, true));
    index.finish_rebuild().unwrap();
    assert!(!admit(&mut index, &first, false)); assert!(admit(&mut index, &alias, false));
    // Metadata-only link creation must not discard the original representative.
    index.invalidate(&[first.entry_path.clone()]).unwrap(); assert!(admit(&mut index, &alias, false));
    fs::remove_file(&first.entry_path).unwrap(); index.invalidate(&[first.entry_path]).unwrap();
    assert!(!admit(&mut index, &alias, false));
    index.reconcile_scopes(&[]).unwrap();
    assert_eq!(index.records.capacity(), 0); assert!(!index.needs_rebuild());
    index.reset(WatchDeduplication::None, WatchDeduplicationScope::Root).unwrap();
    assert!(!index.path.exists()); assert_eq!(index.records.capacity(), 0); assert!(index.paths.is_empty());
}
#[test]
fn hash_size_prefilter_concurrent_admission_restart_and_torn_cache() {
    let dir = Sandbox::new(); let first = dir.file("first.zip", b"same confirmed bytes"); let copy = dir.file("copy.zip", b"same confirmed bytes");
    let alias = dir.0.join("hardlink.zip"); fs::hard_link(&first.entry_path, &alias).unwrap();
    let folder = dir.0.join("index"); let mut index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    let a = index.prepare_path(&first.entry_path, "scope", &[&first], false).unwrap().unwrap();
    let b = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
    assert!(matches!(index.advance(a).unwrap(), Admission::Finished(false)));
    let Admission::Hash(mut b) = index.advance(b).unwrap() else { panic!("new same-size peer must be compared"); };
    b.hash().unwrap();
    assert!(matches!(index.advance(b).unwrap(), Admission::Finished(true)));
    let linked = ArchiveInput::file(alias.to_string_lossy().into_owned(), "zip".into(), "hardlink.zip".into());
    let cached = index.prepare_path(&linked.entry_path, "scope", &[&linked], true).unwrap().unwrap();
    assert!(cached.record.digest.is_some(), "same physical generation reuses the hash without reading");
    index.finish_rebuild().unwrap(); drop(index);
    let mut index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap(); assert!(!index.needs_rebuild());
    assert!(admit(&mut index, &copy, false));
    index.reconcile_journals(&[("other-scope".into(), "test-volume".into(), 1)]).unwrap();
    // A separately monitored root on the same volume may not be included in
    // the next checkpoint's probe list. Its old journal must still be retired.
    let in_other_scope = index.prepare_path(&linked.entry_path, "other-scope", &[&linked], true).unwrap().unwrap();
    assert!(matches!(index.advance(in_other_scope).unwrap(), Admission::Finished(false)));
    index.finish_rebuild().unwrap();
    let generation = index.generation();
    assert!(!index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap());
    // Secondary indexes can have more slack than the already trimmed record map.
    index.objects.reserve(2048);
    assert!(index.reconcile_journals(&[("scope".into(), "test-volume".into(), 2)]).unwrap());
    assert!(index.records.is_empty() && index.needs_rebuild());
    assert_eq!(index.records.capacity(), 0);
    assert_eq!(index.objects.capacity(), 0);
    assert_eq!(index.journals["other-scope"].1, 2);
    assert!(index.admission_epoch("scope", Some(generation)).is_none());
    assert!(!admit(&mut index, &first, true));
    index.finish_rebuild().unwrap();
    drop(index); OpenOptions::new().append(true).open(folder.join("dedup.wal.bin")).unwrap().write_all(&[1, 2, 3]).unwrap();
    let index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap(); assert!(index.needs_rebuild()); assert!(index.records.is_empty());
}

#[test]
fn hash_admission_rechecks_the_path_after_reading() {
    let dir = Sandbox::new();
    let first = dir.file("first.zip", b"identical archive bytes");
    let copy = dir.file("copy.zip", b"identical archive bytes");
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    assert!(!admit(&mut index, &first, true));

    let prepared = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
    let Admission::Hash(mut pending) = index.advance(prepared).unwrap() else { panic!("must compare content"); };
    let writer = OpenOptions::new().write(true).open(&copy.entry_path).unwrap();
    assert!(pending.hash().is_err(), "the read handle must exclude an active writer");
    drop(writer);
    pending.hash().unwrap();
    fs::rename(&copy.entry_path, dir.0.join("old-copy.zip")).unwrap();
    fs::write(&copy.entry_path, b"different archive bytes").unwrap();
    assert!(matches!(index.advance(pending).unwrap(), Admission::Finished(false)));
    assert_eq!(index.records.len(), 1);
}

#[test]
fn scope_retirement_discards_an_admission_already_in_flight() {
    let dir = Sandbox::new();
    let source = dir.file("input.zip", b"confirmed archive bytes");
    let other = NativeDiscoveryScope::new(
        dir.0.join("other").to_string_lossy().into_owned(), None, vec![],
    );
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[
        ("scope".into(), "test-volume".into(), 1),
        (other.key().into(), "test-volume".into(), 1),
    ]).unwrap();
    let epoch = index.admission_epoch("scope", None).unwrap();
    let record = describe(&source.entry_path, "scope", &[&source]).unwrap().unwrap();
    let prepared = index.prepare(epoch, record.clone(), true).unwrap();

    // There are no resident records to invalidate, but two jobs have already
    // sampled this scope at different points in admission.
    index.reconcile_scopes(&[other]).unwrap();
    assert!(index.prepare(epoch, record, true).is_none());
    assert!(matches!(index.advance(prepared).unwrap(), Admission::Finished(false)));
    assert!(index.records.is_empty());
}

#[test]
fn lazy_admission_continues_when_a_hashed_representative_disappears() {
    let dir = Sandbox::new();
    let first = dir.file("first.zip", b"identical bytes");
    let second = dir.file("second.zip", b"identical bytes");
    let arrival = dir.file("arrival.zip", b"identical bytes");
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    assert!(!admit(&mut index, &first, true));
    assert!(!admit(&mut index, &second, true));
    let prepared = index.prepare_path(&arrival.entry_path, "scope", &[&arrival], false).unwrap().unwrap();
    let Admission::Hash(mut pending) = index.advance(prepared).unwrap() else { panic!("must compare the candidate"); };
    assert_eq!(pending.representative.as_ref().unwrap().owner.as_ref(), path_key(&first.entry_path));
    pending.hash().unwrap();

    fs::remove_file(&first.entry_path).unwrap();
    assert!(finish(&mut index, pending), "the second source still provides a live match");
    assert_eq!(index.records.len(), 2);
}

#[test]
fn stale_bucket_resumes_without_using_an_observation_from_before_unlock() {
    let dir = Sandbox::new();
    let bytes = b"duplicate bytes";
    let arrival = dir.file("arrival.zip", bytes);
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    for n in 0..2 * STALE_BATCH + 1 {
        let peer = dir.file(&format!("peer-{n}.zip"), bytes);
        assert_eq!(admit(&mut index, &peer, false), n != 0);
    }
    for n in 0..2 * STALE_BATCH + 1 {
        if n != STALE_BATCH + 1 {
            fs::remove_file(dir.0.join(format!("peer-{n}.zip"))).unwrap();
        }
    }
    let prepared = index.prepare_path(&arrival.entry_path, "scope", &[&arrival], false).unwrap().unwrap();
    let Admission::Hash(mut pending) = index.advance(prepared).unwrap() else { panic!("must read the candidate"); };
    pending.hash().unwrap();
    let Admission::Rescan(pending) = index.advance(pending).unwrap() else { panic!("the stale bucket needs another pass"); };
    fs::remove_file(&arrival.entry_path).unwrap();
    fs::write(&arrival.entry_path, b"modified bytes!").unwrap();
    assert!(!finish(&mut index, pending));
    assert!(!index.owners.contains_key(path_key(&arrival.entry_path).as_str()));

    let copy = dir.file("copy.zip", bytes);
    assert!(admit(&mut index, &copy, false), "the surviving representative must still be found");
}

/// Abrupt process exit must not rely on Index/File destructors to publish a
/// completed rebuild, and an interrupted rebuild must never become a baseline.
#[test]
fn process_exit_recovers_ready_index_but_rebuilds_unpublished_baseline() {
    const CHILD: &str = "SUNPACK_DEDUP_CRASH_CHILD";
    const PHASE: &str = "SUNPACK_DEDUP_CRASH_PHASE";
    let input = |root: &Path, name: &str| ArchiveInput::file(
        root.join(name).to_string_lossy().into_owned(), "zip".into(), name.into(),
    );
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let first = input(&root, "first.zip");
        let copy = input(&root, "copy.zip");
        let mut index = Index::open(&root.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
        index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
        assert!(!admit(&mut index, &first, true));
        let phase = std::env::var(PHASE).unwrap();
        if phase != "unpublished" {
            index.finish_rebuild().unwrap();
            // This append deliberately follows the durable Ready boundary.
            assert!(admit(&mut index, &copy, false));
            if phase == "scope_pending" {
                index.begin_rebuild().unwrap();
                assert_eq!(index.records.len(), 2);
                assert!(index.records.values().all(|record| record.digest.is_some()));
            }
        }
        std::process::exit(73); // No Rust destructor or explicit final flush.
    }
    let test_name = format!("{}::process_exit_recovers_ready_index_but_rebuilds_unpublished_baseline",
        module_path!().split_once("::").unwrap().1);
    for phase in ["ready", "unpublished", "scope_pending"] {
        let dir = Sandbox::new();
        dir.file("first.zip", b"confirmed archive data for process recovery");
        dir.file("copy.zip", b"confirmed archive data for process recovery");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, &dir.0).env(PHASE, phase).output().unwrap();
        assert_eq!(output.status.code(), Some(73), "{}\n{}",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
        if phase == "ready" {
            assert!(!index.needs_rebuild());
            assert_eq!(index.records.len(), 2);
            assert!(index.records.values().all(|record| record.digest.is_some()));
            let first = input(&dir.0, "first.zip");
            assert!(index.prepare_path(&first.entry_path, "scope", &[&first], false).unwrap().is_none());
            let copy = input(&dir.0, "copy.zip");
            let prepared = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
            assert!(prepared.record.digest.is_some());
            // Persisted content evidence is reusable without another read.
            assert!(matches!(index.advance(prepared).unwrap(), Admission::Finished(true)));
        } else {
            assert!(index.needs_rebuild());
            assert!(index.records.is_empty());
        }
    }
}

#[test]
fn root_and_global_domains_follow_live_scope_ownership() {
    let dir = Sandbox::new();
    let root = dir.0.join("root"); let nested = root.join("nested"); let other = dir.0.join("other");
    fs::create_dir_all(&nested).unwrap(); fs::create_dir_all(&other).unwrap();
    let first_path = root.join("first.zip"); let alias_path = nested.join("alias.zip"); let copy_path = other.join("copy.zip");
    fs::write(&first_path, b"same logical archive data").unwrap();
    fs::hard_link(&first_path, &alias_path).unwrap(); fs::copy(&first_path, &copy_path).unwrap();
    let input = |p: &Path| ArchiveInput::file(p.to_string_lossy().into_owned(), "zip".into(), "archive.zip".into());
    let first = input(&first_path); let alias = input(&alias_path); let copy = input(&copy_path);
    let parent_scope = NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), None, vec![nested.to_string_lossy().into_owned()]);
    let nested_scope = NativeDiscoveryScope::new(nested.to_string_lossy().into_owned(), None, vec![]);
    let other_scope = NativeDiscoveryScope::new(other.to_string_lossy().into_owned(), None, vec![]);
    let stamps = [&parent_scope, &nested_scope, &other_scope].map(|scope| (scope.key().to_owned(), "test-volume".to_owned(), 1));
    let admit_scope = |index: &mut Index, input: &ArchiveInput, scope: &str| {
        let Some(prepared) = index.prepare_path(&input.entry_path, scope, &[input], false).unwrap() else { return false; };
        finish(index, prepared)
    };
    for mode in [WatchDeduplication::FileId, WatchDeduplication::Hash] {
        let folder = dir.0.join(if mode == WatchDeduplication::Hash { "hash-index" } else { "id-index" });
        let mut index = Index::open(&folder, mode, WatchDeduplicationScope::Root).unwrap();
        index.reconcile_journals(&stamps).unwrap();
        assert!(!admit_scope(&mut index, &first, parent_scope.key()));
        assert!(!admit_scope(&mut index, &alias, nested_scope.key()), "same object in another root is independently admitted");
        assert!(!admit_scope(&mut index, &copy, other_scope.key()));
        index.finish_rebuild().unwrap(); drop(index);
        // Identical mode with a different comparison scope must discard its old WAL.
        let mut index = Index::open(&folder, mode, WatchDeduplicationScope::Global).unwrap();
        assert!(index.needs_rebuild() && index.records.is_empty());
        index.reconcile_journals(&stamps).unwrap();
        assert!(!admit_scope(&mut index, &first, parent_scope.key()));
        assert!(admit_scope(&mut index, &alias, nested_scope.key()));
        assert_eq!(admit_scope(&mut index, &copy, other_scope.key()), mode == WatchDeduplication::Hash);
        index.finish_rebuild().unwrap(); drop(index);
        let mut index = Index::open(&folder, mode, WatchDeduplicationScope::Global).unwrap();
        assert!(!index.needs_rebuild());
        // Removing a nested monitoring root does not remove inputs still covered
        // by its parent. Rebinding preserves IDs, cached hashes and owner state.
        let parent_scope = NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), None, vec![]);
        let before = index.records.len();
        index.reconcile_scopes(&[parent_scope.clone(), other_scope.clone()]).unwrap();
        assert_eq!(index.records.len(), before);
        assert!(index.records.values().filter(|r| r.owner.as_ref() == path_key(&alias.entry_path)).all(|r| r.scope.as_ref() == parent_scope.key()));
        if mode == WatchDeduplication::Hash {
            let prepared = index.prepare_path(&alias.entry_path, parent_scope.key(), &[&alias], true).unwrap().unwrap();
            assert!(prepared.record.digest.is_some(), "scope ownership rebinding retains the valid content hash");
        }
        assert!(admit_scope(&mut index, &alias, parent_scope.key()));
        if mode == WatchDeduplication::Hash {
            fs::rename(&nested, dir.0.join("moved-out")).unwrap();
            index.invalidate_tree(nested.to_str().unwrap()).unwrap();
            assert!(!index.owners.contains_key(path_key(&alias.entry_path).as_str()));
            assert!(index.owners.contains_key(path_key(&copy.entry_path).as_str()));
        }
        let generation = index.generation(); index.reset(mode, WatchDeduplicationScope::Root).unwrap();
        assert!(index.generation() != generation && index.records.is_empty() && index.needs_rebuild());
    }
}

#[test]
fn lazy_baseline_exhausts_same_size_candidates_and_hardlinks_need_no_hash() {
    let dir = Sandbox::new();
    let folder = dir.0.join("index");
    let mut index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    let inputs: Vec<_> = [b"aaaaaa", b"bbbbbb", b"cccccc"].iter().enumerate()
        .map(|(i, bytes)| dir.file(&format!("base-{i}.zip"), *bytes)).collect();
    let alias_path = dir.0.join("alias.zip");
    fs::hard_link(&inputs[0].entry_path, &alias_path).unwrap();
    for input in &inputs {
        let prepared = index.prepare_path(&input.entry_path, "scope", &[input], true).unwrap().unwrap();
        assert!(matches!(index.advance(prepared).unwrap(), Admission::Finished(false)));
    }
    index.finish_rebuild().unwrap(); drop(index);
    let mut index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    assert!(!index.needs_rebuild());
    assert!(index.records.values().all(|r| r.digest.is_none()));
    let copy = dir.file("copy-last.zip", b"cccccc");
    assert!(admit(&mut index, &copy, false), "must reach the third pending representative");
    index.invalidate(&[inputs[0].entry_path.clone()]).unwrap();
    assert_eq!(index.records.len(), 4, "unchanged source evidence remains indexed");
    let alias = ArchiveInput::file(alias_path.to_string_lossy().into_owned(), "zip".into(), "alias.zip".into());
    // A new, still-unhashed object must also bypass hash through its File ID.
    let lazy = dir.file("lazy.zip", b"unique-size");
    let path = dir.0.join("lazy-link.zip"); fs::hard_link(&lazy.entry_path, &path).unwrap();
    assert!(!admit(&mut index, &lazy, false));
    let link = ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "lazy-link.zip".into());
    for link in [&alias, &link] {
        let prepared = index.prepare_path(&link.entry_path, "scope", &[link], false).unwrap().unwrap();
        assert!(matches!(index.advance(prepared).unwrap(), Admission::Finished(true)));
    }
}

#[test]
fn byte_stream_identity_ignores_carrier_and_split_boundaries_but_tracks_every_source() {
    use crate::io::archive_state::{InputExtent, InputPart};
    let dir = Sandbox::new();
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    let whole = dir.file("whole.zip", b"ABCDEF");
    assert!(!admit(&mut index, &whole, true));
    let mut carrier = dir.file("carrier.bin", b"junkABCDEFtail");
    carrier.mode = OpenMode::FileRange;
    carrier.parts = vec![InputPart::range(InputExtent { path: carrier.entry_path.clone(), start: 4, end: Some(10) })].into();
    assert!(admit(&mut index, &carrier, false));
    let left = dir.file("part-1", b"ABC"); let right = dir.file("part-2", b"DEF");
    let mut split = left.clone(); split.mode = OpenMode::NativeVolumes;
    split.parts = [left.entry_path.clone(), right.entry_path.clone()].into_iter()
        .map(|path| InputPart::range(InputExtent { path, start: 0, end: None })).collect::<Vec<_>>().into();
    assert!(admit(&mut index, &split, false));
    let one = dir.file("other-1", b"A"); let two = dir.file("other-2", b"BCDEF");
    let mut other = one.clone(); other.mode = OpenMode::NativeVolumes;
    other.parts = [InputExtent { path: one.entry_path.clone(), start: 0, end: Some(1) },
        InputExtent { path: two.entry_path.clone(), start: 0, end: Some(5) }].into_iter().map(InputPart::range).collect();
    assert!(admit(&mut index, &other, false));
    let mut reversed = right.clone(); reversed.mode = OpenMode::NativeVolumes;
    reversed.parts = [InputExtent { path: right.entry_path.clone(), start: 0, end: Some(3) },
        InputExtent { path: left.entry_path.clone(), start: 0, end: Some(3) }].into_iter().map(InputPart::range).collect();
    assert!(!admit(&mut index, &reversed, false));
    // Two independent logical inputs are still compared as the requested ordered stream.
    let multi_owner = dir.0.join("group").to_string_lossy().into_owned();
    let prepared = index.prepare_path(&multi_owner, "scope", &[&one, &two], false).unwrap().unwrap();
    assert!(finish(&mut index, prepared));
    fs::write(&right.entry_path, b"XYZ").unwrap();
    index.invalidate(&[right.entry_path.clone()]).unwrap();
    assert!(!index.owners.contains_key(path_key(&split.entry_path).as_str()));
    assert!(!index.owners.contains_key(path_key(&reversed.entry_path).as_str()));
    assert!(index.owners.contains_key(path_key(&whole.entry_path).as_str()));
    fs::remove_file(&two.entry_path).unwrap(); index.invalidate(&[two.entry_path]).unwrap();
    assert!(!index.owners.contains_key(path_key(&other.entry_path).as_str()));
    assert!(!index.owners.contains_key(path_key(&multi_owner).as_str()));
    fs::remove_file(&carrier.entry_path).unwrap(); index.invalidate(&[carrier.entry_path.clone()]).unwrap();
    assert!(!index.owners.contains_key(path_key(&carrier.entry_path).as_str()));
    assert_eq!(index.records.len(), 1);
}
#[test]
fn recursion_scope_removes_whole_cross_level_input_and_persists_removal() {
    use crate::io::archive_state::{InputExtent, InputPart};
    for scope_mode in [WatchDeduplicationScope::Root, WatchDeduplicationScope::Global] {
        let dir = Sandbox::new(); fs::create_dir_all(dir.0.join("child")).unwrap();
        let head = dir.file("head", b"ABC"); let tail = dir.file("child/tail", b"DEF");
        let mut input = head.clone(); input.mode = OpenMode::NativeVolumes;
        input.parts = [InputExtent { path: head.entry_path.clone(), start: 0, end: Some(3) },
            InputExtent { path: tail.entry_path.clone(), start: 0, end: Some(3) }].into_iter().map(InputPart::range).collect();
        let recursive = NativeDiscoveryScope::new(dir.0.to_string_lossy().into_owned(), None, vec![]);
        let flat = NativeDiscoveryScope::new(dir.0.to_string_lossy().into_owned(), Some(0), vec![]);
        let folder = dir.0.join("index");
        let mut index = Index::open(&folder, WatchDeduplication::Hash, scope_mode).unwrap();
        index.reconcile_journals(&[(recursive.key().into(), "test-volume".into(), 1)]).unwrap();
        let p = index.prepare_path(&input.entry_path, recursive.key(), &[&input], true).unwrap().unwrap();
        assert!(matches!(index.advance(p).unwrap(), Admission::Finished(false))); index.finish_rebuild().unwrap();
        index.reconcile_scopes(&[flat]).unwrap();
        assert!(index.records.is_empty()); assert!(index.paths.is_empty()); drop(index);
        let mut index = Index::open(&folder, WatchDeduplication::Hash, scope_mode).unwrap();
        assert!(!index.needs_rebuild()); assert!(index.records.is_empty());
        index.reconcile_scopes(&[recursive.clone()]).unwrap();
        let p = index.prepare_path(&input.entry_path, recursive.key(), &[&input], true).unwrap().unwrap();
        assert!(matches!(index.advance(p).unwrap(), Admission::Finished(false))); assert_eq!(index.records.len(), 1);
        index.finish_rebuild().unwrap(); drop(index);
        let index = Index::open(&folder, WatchDeduplication::Hash, scope_mode).unwrap();
        assert_eq!(index.records.len(), 1); assert!(index.records.values().all(|r| r.digest.is_none()));
    }
}

#[test]
fn lazy_baseline_aliases_share_one_physical_hash() {
    let dir = Sandbox::new(); let source = dir.file("source", b"AAAAAA");
    let mut aliases = Vec::new();
    for number in 0..8 {
        let path = dir.0.join(format!("alias-{number}")); fs::hard_link(&source.entry_path, &path).unwrap();
        aliases.push(ArchiveInput::file(path.to_string_lossy().into_owned(), "zip".into(), "alias".into()));
    }
    let mut index = Index::open(&dir.0.join("index"), WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap();
    index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap();
    assert!(!admit(&mut index, &source, true));
    for alias in &aliases { assert!(admit(&mut index, alias, true)); }
    assert!(index.records.values().all(|r| r.digest.is_none()));
    let different = dir.file("different", b"BBBBBB");
    let prepared = index.prepare_path(&different.entry_path, "scope", &[&different], false).unwrap().unwrap();
    let Admission::Hash(mut pending) = index.advance(prepared).unwrap() else { panic!("the two physical files must be compared"); };
    pending.hash().unwrap();
    assert!(matches!(index.advance(pending).unwrap(), Admission::Finished(false)), "the remaining aliases reuse the now known digest");
}
