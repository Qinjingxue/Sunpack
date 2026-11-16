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
    let Some(mut p) = index.prepare_path(&input.entry_path, "scope", &[input], baseline).unwrap() else { return false; };
    loop { p.hash().unwrap(); if !index.refresh(&mut p) { return index.commit(p).unwrap(); } }
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
    let mut a = index.prepare_path(&first.entry_path, "scope", &[&first], false).unwrap().unwrap();
    let mut b = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
    assert!(!a.hash && !b.hash); a.hash().unwrap(); assert!(!index.commit(a).unwrap());
    assert!(index.refresh(&mut b)); b.hash().unwrap(); assert!(!index.refresh(&mut b)); assert!(index.commit(b).unwrap());
    let linked = ArchiveInput::file(alias.to_string_lossy().into_owned(), "zip".into(), "hardlink.zip".into());
    let cached = index.prepare_path(&linked.entry_path, "scope", &[&linked], true).unwrap().unwrap();
    assert!(cached.record.digest.is_some(), "same physical generation reuses the hash without reading");
    index.finish_rebuild().unwrap(); drop(index);
    let mut index = Index::open(&folder, WatchDeduplication::Hash, WatchDeduplicationScope::Root).unwrap(); assert!(!index.needs_rebuild());
    assert!(admit(&mut index, &copy, false));
    index.reconcile_journals(&[("other-scope".into(), "test-volume".into(), 1)]).unwrap();
    // A separately monitored root on the same volume may not be included in
    // the next checkpoint's probe list. Its old journal must still be retired.
    let mut in_other_scope = index.prepare_path(&linked.entry_path, "other-scope", &[&linked], true).unwrap().unwrap();
    in_other_scope.hash().unwrap(); assert!(!index.commit(in_other_scope).unwrap());
    index.finish_rebuild().unwrap();
    let generation = index.generation();
    assert!(!index.reconcile_journals(&[("scope".into(), "test-volume".into(), 1)]).unwrap());
    assert!(index.reconcile_journals(&[("scope".into(), "test-volume".into(), 2)]).unwrap());
    assert!(index.records.is_empty() && index.needs_rebuild());
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

    let mut pending = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
    let writer = OpenOptions::new().write(true).open(&copy.entry_path).unwrap();
    assert!(pending.hash().is_err(), "the read handle must exclude an active writer");
    drop(writer);
    pending.hash().unwrap();
    assert!(!index.refresh(&mut pending));
    fs::rename(&copy.entry_path, dir.0.join("old-copy.zip")).unwrap();
    fs::write(&copy.entry_path, b"different archive bytes").unwrap();
    assert!(!index.commit(pending).unwrap());
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
    let mut prepared = index.prepare(epoch, record.clone(), true).unwrap();
    prepared.hash().unwrap();

    // There are no resident records to invalidate, but two jobs have already
    // sampled this scope at different points in admission.
    index.reconcile_scopes(&[other]).unwrap();
    assert!(index.prepare(epoch, record, true).is_none());
    assert!(!index.refresh(&mut prepared));
    assert!(!index.commit(prepared).unwrap());
    assert!(index.records.is_empty());
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
            let mut prepared = index.prepare_path(&copy.entry_path, "scope", &[&copy], false).unwrap().unwrap();
            assert!(prepared.record.digest.is_some());
            assert!(!index.refresh(&mut prepared));
            // Intentionally no Prepared::hash: persisted content evidence is reusable.
            assert!(index.commit(prepared).unwrap());
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
        let Some(mut p) = index.prepare_path(&input.entry_path, scope, &[input], true).unwrap() else { return false; };
        loop { p.hash().unwrap(); if !index.refresh(&mut p) { break index.commit(p).unwrap(); } }
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
