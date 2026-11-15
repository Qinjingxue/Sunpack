use super::*;
#[test]
fn embedded_pages_cross_scope_boundaries_without_losing_ownership() {
    let root = std::env::temp_dir().join(format!(
        "sunpack-pages-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut carrier = vec![0x41; 17];
    carrier.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00");
    let mut inputs = Vec::new();
    let mut expected = HashSet::new();
    // A page crosses roots and then splits inside the last root; the empty
    // middle root must not shift the group IDs used for result projection.
    for (scope, count) in [1, 0, 257].into_iter().enumerate() {
        let directory = root.join(scope.to_string());
        std::fs::create_dir_all(&directory).unwrap();
        for index in 0..count {
            let path = directory.join(format!("archive{index}.bin"));
            std::fs::write(&path, &carrier).unwrap();
            expected.insert(path_key(&path.to_string_lossy()));
        }
        inputs.push(directory);
    }
    let options =
        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let candidates = CandidateSet::new(
        Arc::from([]),
        None,
        &super::super::passwords::AttemptCache::default(),
        None,
    );
    let mut request = Request::new(inputs, super::super::Mode::Scan);
    request.deep = true;
    let result = discover(&request, &options, &candidates).unwrap();
    assert!(result.errors.is_empty());
    assert!(result.blocked_paths.is_empty());
    assert_eq!(result.tasks.len(), expected.len());
    for task in result.tasks {
        assert_eq!(task.inputs.len(), 1);
        assert_eq!(task.owned_paths.len(), 1);
        assert!(expected.remove(&path_key(&task.entry().entry_path)));
        let Some(TaskContext::Retry(retry)) = &task.context else {
            panic!("expected a retained volume resolution context");
        };
        assert_eq!(
            retry.scope.key(),
            path_key(
                &Path::new(&task.entry().entry_path)
                    .parent()
                    .unwrap()
                    .to_string_lossy()
            )
        );
    }
    assert!(expected.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "manual actual-scope batching measurement"]
fn measure_many_small_output_scopes() {
    let root = std::env::temp_dir().join(format!(
        "sunpack-pages-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut carrier = vec![0x41; 17];
    carrier.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00");
    let mut inputs = Vec::new();
    let mut expected = HashSet::new();
    // A page crosses roots and then splits inside the last root; the empty
    // middle root must not shift the group IDs used for result projection.
    for (scope, count) in [4; 32].into_iter().enumerate() {
        let directory = root.join(scope.to_string());
        std::fs::create_dir_all(&directory).unwrap();
        for index in 0..count {
            let path = directory.join(format!("archive{index}.bin"));
            std::fs::write(&path, &carrier).unwrap();
            expected.insert(path_key(&path.to_string_lossy()));
        }
        inputs.push(directory);
    }
    let options =
        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let candidates = CandidateSet::new(
        Arc::from([]),
        None,
        &super::super::passwords::AttemptCache::default(),
        None,
    );
    let mut request = Request::new(inputs, super::super::Mode::Scan);
    request.deep = true;
    let config = Arc::make_mut(&mut request.config);
    config.recursive_authorization.enabled = false;
    config.embedded_scan.enabled = true;
    config.embedded_scan.recursive_candidate_ratio = 0.2;
    let separate = std::env::var_os("SUNPACK_MEASURE_SEPARATE").is_some();
    MEASURED_EMBEDDED_PAGES.with(|pages| pages.set(0));
    let began = std::time::Instant::now();
    for _ in 0..10 {
        let outputs = request.inputs.iter().map(|path| OutputDiscovery::prepare(
            crate::scan::directory::scan_output_inventory_impl(&path.to_string_lossy()), &options
        ).unwrap()).collect::<Vec<_>>();
        let results = if separate {
            outputs.into_iter().map(|output| {
                OutputDiscovery::discover_many(vec![output], &candidates, &request).unwrap().pop().unwrap()
            }).collect()
        } else { OutputDiscovery::discover_many(outputs, &candidates, &request).unwrap() };
        let mut actual = HashSet::new();
        for result in results {
            assert!(result.errors.is_empty());
            for task in result.tasks { assert!(actual.insert(path_key(&task.entry().entry_path))); }
        }
        assert_eq!(actual, expected);
    }
    eprintln!("scope_measure separate={separate} outputs=32 files=128 iterations=10 pages={} wall_ms={}",
        MEASURED_EMBEDDED_PAGES.with(|pages| pages.get()), began.elapsed().as_millis());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn covered_explicit_targets_keep_their_retry_boundary() {
    let root = std::env::temp_dir().join(format!(
        "sunpack-covered-scope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let child = root.join("child");
    std::fs::create_dir_all(&child).unwrap();
    let archive = child.join("archive.zip");
    // A complete stored ZIP, so discovery needs no worker or passwords.
    std::fs::write(&archive, b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00").unwrap();
    let options =
        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let candidates = CandidateSet::new(
        Arc::from([]),
        None,
        &super::super::passwords::AttemptCache::default(),
        None,
    );
    for target in [&child, &archive] {
        for ancestor_first in [false, true] {
            let inputs = if ancestor_first {
                vec![root.clone(), target.clone()]
            } else {
                vec![target.clone(), root.clone()]
            };
            let mut request = Request::new(inputs, super::super::Mode::Scan);
            request.recursive = true;
            let result = discover(&request, &options, &candidates).unwrap();
            assert!(result.errors.is_empty());
            assert_eq!(result.tasks.len(), 1);
            let task = &result.tasks[0];
            assert_eq!(task.inputs.len(), 1);
            assert_eq!(
                path_key(&task.entry().entry_path),
                path_key(&archive.to_string_lossy())
            );
            let Some(TaskContext::Retry(retry)) = &task.context else {
                panic!("expected a retained volume resolution context");
            };
            assert_eq!(retry.scope.key(), path_key(&child.to_string_lossy()));
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_walk_keeps_child_rows_and_retry_scope_local() {
    let root = std::env::temp_dir().join(format!(
        "sunpack-scope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let child = root.join("child");
    let other = root.join("other");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let head = child.join("split.7z.001");
    std::fs::write(&head, b"head").unwrap();
    std::fs::write(other.join("split.7z.002"), b"tail").unwrap();
    let outer =
        NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), None, Vec::new());
    let inner =
        NativeDiscoveryScope::new(child.to_string_lossy().into_owned(), None, Vec::new());
    let roots = HashMap::from([
        (outer.key().to_owned(), outer.root.clone()),
        (inner.key().to_owned(), outer.root.clone()),
    ]);
    let options =
        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let mut snapshots = HashMap::new();
    let (_, outer_raw) =
        scan_discovery_scope(&options, &outer, &roots, &mut snapshots).unwrap();
    let (_, inner_raw) =
        scan_discovery_scope(&options, &inner, &roots, &mut snapshots).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert!(Arc::ptr_eq(&outer_raw.table, &inner_raw.table));
    let paths: Vec<_> = inner_raw
        .rows
        .iter()
        .map(|&row| &inner_raw.table.paths[row])
        .collect();
    assert!(paths
        .iter()
        .any(|path| path_key(path) == path_key(&head.to_string_lossy())));
    assert!(paths.iter().all(|path| inner.contains(path)));
    // Both an explicit child directory and a covered child file's parent
    // remain logical boundaries when only the ancestor was discovered.
    let mut scopes = vec![Arc::new(RetryScope {
        scope: Arc::new(outer.clone()),
        snapshot: outer_raw,
        bucket: String::new(),
    })];
    retain_logical_retry_scopes([outer, inner.clone(), inner.clone()], &mut scopes);
    assert_eq!(scopes.len(), 2);
    assert!(Arc::ptr_eq(
        &scopes[0].snapshot.table,
        &scopes[1].snapshot.table
    ));
    assert!(Arc::ptr_eq(&scopes[0].snapshot.rows, &scopes[1].snapshot.rows));
    let (_, refreshed) = options.refresh_relation_bucket(
        &scopes[1].scope, &head.to_string_lossy(), &scopes[1].snapshot, None,
    ).unwrap();
    assert!(refreshed.records().any(|(path, _, _, _)| path == head.to_string_lossy()));
    assert!(refreshed.records().all(|(path, _, _, _)| inner.contains(path)));
    let head = head.to_string_lossy().into_owned();
    let mut tasks = vec![Task::single(
        ArchiveInput::file(head.clone(), "7z".into(), "split".into()),
        vec![head],
        DiscoverySource::Relations,
        None,
    )];
    assign_retry_scopes(&mut tasks, &scopes);
    let (scope, retry) = tasks[0].take_context(true);
    assert_eq!(retry.unwrap().scope.key(), inner.key());
    assert_eq!(scope.unwrap().key(), inner.key());
    // Scope is a discovery fact, not a split-retry capability. A TAR and a
    // multi-input carrier retain it without retaining the retry snapshot.
    tasks[0].inputs[0].input.format_hint = "tar".into();
    assign_retry_scopes(&mut tasks, &scopes);
    let (scope, retry) = tasks[0].take_context(true);
    assert!(retry.is_none());
    assert_eq!(scope.unwrap().key(), inner.key());
    let input = tasks[0].entry().clone();
    tasks[0].inputs.push(LogicalInput { input, password: None, failure: None });
    assign_retry_scopes(&mut tasks, &scopes);
    let (scope, retry) = tasks[0].take_context(true);
    assert!(retry.is_none());
    assert_eq!(scope.unwrap().key(), inner.key());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_logical_order_does_not_replace_relation_primary() {
    // The continuation sorts before the RAR head and also owns a ZIP.
    // Input ordering must not rename the physical owner/container.
    for relation_first in [false, true] {
        let paths = vec!["sample.zzz".to_owned(), "sample.aaa.bin".to_owned()];
        let relation = Task::single(
            ArchiveInput::file(paths[0].clone(), "rar".into(), "sample".into()),
            paths.clone(),
            DiscoverySource::Relations,
            None,
        );
        let embedded = Task::single(
            ArchiveInput::file(paths[1].clone(), "zip".into(), "sample.aaa".into()),
            vec![paths[1].clone()],
            DiscoverySource::Embedded,
            None,
        );
        let mut tasks = if relation_first {
            vec![relation, embedded]
        } else {
            vec![embedded, relation]
        };
        merge_shared_inputs(&mut tasks, &mut HashSet::new());
        assert_eq!(tasks.len(), 1);
        let task = &tasks[0];
        assert_eq!(task.entry().entry_path, paths[0]);
        assert_eq!(task.entry().logical_name, "sample");
        assert_eq!(task.inputs[0].input.entry_path, paths[1]);
        assert_eq!(task.source, DiscoverySource::Embedded);
        assert_eq!(task.owned_paths.len(), 2);
    }
}
