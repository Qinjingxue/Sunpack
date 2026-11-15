#[test]
fn refresh_rescans_when_output_is_published_after_enumeration() {
    use super::*;
    use crate::scan::scope::NativeDiscoveryScope;

    let root = crate::test_support::temp_file("catalog_publish_during_scan", b"");
    fs::remove_file(&root).unwrap();
    fs::create_dir(&root).unwrap();
    let scope = NativeDiscoveryScope::new(root.to_str().unwrap().to_owned(), None, Vec::new());
    let output = root.join("output");
    fs::create_dir(&output).unwrap();
    let file = output.join("result.zip");
    fs::write(&file, b"settled output").unwrap();
    let path = output.to_str().unwrap();

    let state = crate::watch_store::NativeWatchState::new();
    state.register_output_paths(&[path.to_owned()], &[]);
    let catalog = Arc::new(NativeWatchCatalog::new(&state, None));
    let options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    let during = Arc::clone(&catalog);
    let publish_scope = scope.clone();
    let publish_options = options.clone();
    let publish_path = path.to_owned();
    AFTER_CATALOG_SCAN.with(|hook| hook.set(Some(Box::new(move || {
        assert!(during.catalogs.try_lock().is_ok());
        assert!(during.candidate_paths(&publish_scope, None).is_empty());
        let published = during.publish_outputs(&[publish_path], &[publish_scope], &publish_options, None).unwrap();
        assert_eq!(published.len(), 1);
    }))));

    let (errors, arrivals) = options.catalog_refresh(&catalog, &scope, None).unwrap();
    assert!(errors.is_empty() && arrivals.is_empty());
    assert_eq!(catalog.path_is_directory(&scope, path), Some(true));
    assert!(catalog.generated_observation(file.to_str().unwrap()).is_some());
    assert!(!catalog.is_owned(path));
    fs::remove_file(&file).unwrap();
    fs::remove_dir(&output).unwrap();
    fs::remove_dir(&root).unwrap();
}

#[test]
fn ordinary_commit_keeps_usn_identity_cache_until_idle_commit() {
    let state = crate::watch_store::NativeWatchState::new();
    let catalog = super::NativeWatchCatalog::new(&state, None);
    catalog.recovery_ids.lock().unwrap().insert("volume".into(), Default::default());
    catalog.commit(false);
    catalog.commit(false);
    assert_eq!(catalog.recovery_ids.lock().unwrap().len(), 1);
    catalog.commit(true);
    assert!(catalog.recovery_ids.lock().unwrap().is_empty());
}
