use super::*;

#[test]
fn idle_pool_releases_its_owner_without_interrupting_borrowers() {
    let cache = IdleRayonPool::new();
    let build = || rayon::ThreadPoolBuilder::new().num_threads(1).build().ok();
    let pool = cache.acquire(build).unwrap();
    assert!(Arc::ptr_eq(&pool, &cache.acquire(|| panic!("existing pool")).unwrap()));
    let retired = Arc::downgrade(&pool);

    pool.install(|| cache.clear());
    let overlap = cache.acquire(|| panic!("borrowed pool")).unwrap();
    assert!(Arc::ptr_eq(&pool, &overlap));
    drop(pool);
    assert_eq!(overlap.install(rayon::current_num_threads), 1);
    drop(overlap);
    assert!(retired.upgrade().is_none());

    let rebuilt = cache.acquire(build).unwrap();
    assert_eq!(rebuilt.current_num_threads(), 1);
}

// File-only guards do not cover shared batch lifetime or redirected opens.
// One scope checks close ordering and the existing per-file fallback.
#[test]
fn scoped_readers_keep_promotion_protection_until_handles_close() {
    let root = crate::test_support::temp_file("read_scope_İ_Σ_测试", b"");
    std::fs::remove_file(&root).unwrap();
    std::fs::create_dir(&root).unwrap();
    let path = root.join("inside.fake");
    std::fs::write(&path, b"inside").unwrap();
    // A same-prefix sibling exercises the component boundary as well as
    // the non-ASCII root's shared filesystem case mapping.
    let outside = root.with_extension("sibling");
    std::fs::write(&outside, b"outside").unwrap();
    let scope = NativeReadScope::new(&root).unwrap();
    let id = scope.guard.id;
    let mut inside = scope.open_reader(path.to_str().unwrap()).unwrap();
    let mut fallback = scope.open_reader(outside.to_str().unwrap()).unwrap();
    assert!(matches!(inside._resource, FileResource::Shared { .. }));
    assert!(matches!(fallback._resource, FileResource::Owned { .. }));
    drop(scope);
    assert!(registry()
        .registry
        .lock()
        .unwrap()
        .resources
        .contains_key(&id));
    let mut data = String::new();
    inside.read_to_string(&mut data).unwrap();
    fallback.read_to_string(&mut data).unwrap();
    assert_eq!(data, "insideoutside");
    drop((inside, fallback));
    assert!(!registry()
        .registry
        .lock()
        .unwrap()
        .resources
        .contains_key(&id));
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(root).unwrap();
    std::fs::remove_file(outside).unwrap();
}
