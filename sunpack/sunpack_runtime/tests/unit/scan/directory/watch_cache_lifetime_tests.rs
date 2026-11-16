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
    assert!(errors.is_empty());
    // Published output retains its identity baseline for ordinary admission;
    // returning it for observation does not make it a new arrival.
    assert_eq!(arrivals, vec![file.to_str().unwrap().to_owned()]);
    assert_eq!(catalog.path_is_directory(&scope, path), Some(true));
    assert!(catalog.generated_observation(file.to_str().unwrap()).is_some());
    assert!(!catalog.is_owned(path));
    fs::remove_file(&file).unwrap();
    fs::remove_dir(&output).unwrap();
    fs::remove_dir(&root).unwrap();
}

#[test]
fn paused_catalog_baseline_adopts_content_without_claiming_generated_output() {
    use super::*;
    use crate::scan::scope::NativeDiscoveryScope;

    let root = crate::test_support::temp_file("catalog_paused_baseline", b"");
    fs::remove_file(&root).unwrap();
    fs::create_dir(&root).unwrap();
    let file = root.join("kept.zip");
    fs::write(&file, b"completed original").unwrap();
    let scope = NativeDiscoveryScope::new(root.to_str().unwrap().to_owned(), None, Vec::new());
    let state = crate::watch_store::NativeWatchState::new();
    let catalog = NativeWatchCatalog::new(&state, None);
    let options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    options.catalog_baseline(&catalog, &scope, None).unwrap();
    let original = catalog.observation(file.to_str().unwrap()).unwrap();
    fs::write(&file, b"changed while explicitly paused").unwrap();
    options.catalog_baseline(&catalog, &scope, file.to_str()).unwrap();
    let adopted = catalog.observation(file.to_str().unwrap()).unwrap();
    assert_ne!(adopted.size, original.size);
    let current = crate::postprocess::watch_candidate_for_path(&file, Some(adopted.change_usn)).unwrap().unwrap();
    assert!(!crate::postprocess::watch_content_changed(adopted.size, adopted.mtime,
        &adopted.file_id(), adopted.change_usn, &current));
    assert!(!catalog.is_owned(file.to_str().unwrap()));
    assert!(catalog.generated_observation(file.to_str().unwrap()).is_none());
    fs::write(&file, b"a later active edit remains eligible").unwrap();
    let (errors, arrivals) = options.catalog_refresh(&catalog, &scope, file.to_str()).unwrap();
    assert!(errors.is_empty());
    assert_eq!(arrivals, vec![file.to_str().unwrap().to_owned()]);
    let current = crate::postprocess::watch_candidate_for_path(&file, Some(adopted.change_usn)).unwrap().unwrap();
    assert!(crate::postprocess::watch_content_changed(adopted.size, adopted.mtime,
        &adopted.file_id(), adopted.change_usn, &current));
    fs::remove_file(&file).unwrap();
    fs::remove_dir(&root).unwrap();
}
