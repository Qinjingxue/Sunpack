#[test]
fn queued_relation_probe_does_not_block_same_root_promotion() {
    use super::*;
    use crate::io::resource_lifecycle::Promotion;
    use std::sync::{Barrier, mpsc};
    use std::time::Duration;

    let root = crate::test_support::temp_file("queued_relation_probe", b"");
    fs::remove_file(&root).unwrap();
    fs::create_dir(&root).unwrap();
    let source = root.join("source.zip");
    fs::write(&source, b"source bytes").unwrap();

    let caller = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let probes = cheap_fast_probe_pool();
    let entered = Arc::new(Barrier::new(probes.current_num_threads() + 1));
    let resume = Arc::new(Barrier::new(probes.current_num_threads() + 1));
    let queued = Arc::clone(&entered);
    let blocked = Arc::clone(&resume);
    probes.spawn_broadcast(move |_| {
        queued.wait();
        blocked.wait();
    });
    entered.wait();

    let (started, starting) = mpsc::channel();
    let (probe_done, probe_result) = mpsc::channel();
    let root_path = root.to_str().unwrap().to_owned();
    let source_path = source.to_str().unwrap().to_owned();
    caller.spawn(move || {
        let mut record = DirectoryEntryRecord {
            path: source_path,
            is_dir: false,
            size: Some(12),
            mtime_ns: None,
            relation_member_eligible: true,
            relation_anchor: None,
        };
        started.send(()).unwrap();
        populate_relation_anchors_cached(std::slice::from_mut(&mut record), &[], Some(&root_path));
        probe_done.send(record.relation_anchor.is_some()).unwrap();
    });
    starting.recv().unwrap();

    // The caller pool has one worker. It can service this second job only
    // by re-entering while the first waits for the still-blocked probe pool.
    let (reentered, reentry) = mpsc::channel();
    caller.spawn(move || reentered.send(()).unwrap());
    reentry.recv().unwrap();

    let (promotion_done, promotion_result) = mpsc::channel();
    let target = source.clone();
    let promotion = std::thread::spawn(move || {
        let result = Promotion::begin([target]).map(drop);
        promotion_done.send(result).unwrap();
    });
    let before_probe = promotion_result.recv_timeout(Duration::from_secs(5));
    // Always release the probe workers, including when the old ownership
    // causes the promotion to wait. The test can then fail without hanging.
    resume.wait();
    promotion.join().unwrap();
    assert!(probe_result.recv().unwrap());
    fs::remove_file(source).unwrap();
    fs::remove_dir(root).unwrap();
    before_probe.expect("promotion waited on a probe that had not started").unwrap();
}

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
    let cache = root.with_extension("catalog");
    let cache_path = cache.to_str().unwrap();
    let catalog = Arc::new(NativeWatchCatalog::new(&state, Some(cache_path.to_owned())));
    let options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    let during = Arc::clone(&catalog);
    let publish_scope = scope.clone();
    let publish_options = options.clone();
    let publish_path = path.to_owned();
    AFTER_CATALOG_SCAN.with(|hook| hook.set(Some(Box::new(move || {
        assert!(during.catalogs.try_lock().is_ok());
        assert!(during.candidate_paths(&publish_scope).is_empty());
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
    assert_eq!(catalog.candidate_paths(&scope), arrivals);
    let limited_scope = NativeDiscoveryScope::new(scope.root.clone(), Some(0), Vec::new());
    assert!(catalog.candidate_paths(&limited_scope).is_empty());

    catalog.close();
    assert!(catalog.error().is_none());
    let reopened = NativeWatchCatalog::new(&state, Some(cache_path.to_owned()));
    assert!(reopened.generated_under(&scope, &path.to_ascii_uppercase()));
    assert!(reopened.generated_under(&scope, file.to_str().unwrap()));
    assert!(!reopened.generated_under(&scope, root.join("out").to_str().unwrap()));

    fs::remove_file(&file).unwrap();
    reopened.retire_consumed(std::iter::once(file.as_path()));
    reopened.flush().unwrap();
    drop(reopened);
    let reopened = NativeWatchCatalog::new(&state, Some(cache_path.to_owned()));
    assert!(!reopened.generated_under(&scope, path));
    assert_eq!(reopened.path_is_directory(&scope, path), Some(true));
    drop(reopened);
    fs::remove_dir_all(cache).unwrap();
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
