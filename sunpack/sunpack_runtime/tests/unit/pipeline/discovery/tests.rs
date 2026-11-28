use super::*;

const STORED_ZIP: &[u8] = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00item.txtpayloadPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x15j,B\x07\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00item.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00\x00\x00-\x00\x00\x00\x00\x00";

#[test]
fn zip_carrier_search_keeps_eocd_crossing_the_checked_suffix() {
    use crate::analysis_native::volume_anchor::{
        probe_volume_anchor_path_cheap, upgrade_relation_zip_carrier_tail,
        upgrade_relation_zip_tail, TERMINAL,
    };

    let eocd = STORED_ZIP.len() - 22;
    let mut carrier = STORED_ZIP.to_vec();
    // The bounded suffix begins halfway through the actual EOCD signature.
    carrier.resize(eocd + 2 + crate::formats::zip::EOCD_SEARCH_BYTES as usize, b'A');
    let path = crate::test_support::temp_file("zip_eocd_crossing_suffix", &carrier);
    let anchor = probe_volume_anchor_path_cheap(path.to_str().unwrap());
    let tail = upgrade_relation_zip_tail(&anchor);
    assert!(!tail.has_any(TERMINAL));
    let resolved = upgrade_relation_zip_carrier_tail(&tail, None);
    assert!(resolved.has_any(TERMINAL));
    assert_eq!(resolved.zip_eocd_offset, Some(eocd as u64));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn zip_retry_reuses_negative_tail_only_for_the_same_physical_generation() {
    use crate::analysis_native::volume_anchor::CheapAnchor;

    let root = crate::test_support::temp_file("zip_retry_generation", b"");
    std::fs::remove_file(&root).unwrap();
    std::fs::create_dir(&root).unwrap();
    let archive = root.join("item.bin");
    let replacement = root.join("replacement.bin");
    let mut incomplete = STORED_ZIP.to_vec();
    let eocd = incomplete.len() - 22;
    incomplete[eocd..].fill(0);
    std::fs::write(&archive, incomplete).unwrap();
    let scope = NativeDiscoveryScope::new(root.to_string_lossy().into_owned(), Some(0), Vec::new());
    let peer = root.join("item.blob");
    std::fs::write(&peer, b"bad footer").unwrap();
    let mut options = NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
    options.probe_views = crate::io::view::ConfiguredViews::parse([Some("apate:1")].into_iter()).unwrap().probes();
    let (filtered, raw) = options.scan_scope(&scope, None, true).unwrap();
    let rejects_peer = |snapshot: &NativeDirectorySnapshot| {
        let index = snapshot.rows().find(|&i| Path::new(&snapshot.table.paths[i]) == peer).unwrap();
        crate::io::view::ViewProbes::has_view_rejection(snapshot.table.relation_anchors[index].as_ref().unwrap().reject_mask())
    };
    assert!(rejects_peer(&raw));
    let _ = NativeCandidateTable::from_directory(&raw, &filtered, None, false);
    let refresh = || {
        options.refresh_relation_bucket(&scope, archive.to_str().unwrap(), &raw, None, false).unwrap()
    };
    let has_negative = |snapshot: &NativeDirectorySnapshot| {
        snapshot.rows().any(|row| {
            snapshot.table.relation_anchors[row].as_ref().and_then(CheapAnchor::anchor)
                .is_some_and(|anchor| anchor.zip_eocd_absent_generation().is_some())
        })
    };
    assert!(has_negative(&refresh().1));

    let previous_time = std::fs::metadata(&archive).unwrap().modified().unwrap();
    std::fs::write(&replacement, STORED_ZIP).unwrap();
    std::fs::OpenOptions::new().write(true).open(&replacement).unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(previous_time)).unwrap();
    std::fs::remove_file(&archive).unwrap();
    std::fs::rename(&replacement, &archive).unwrap();
    assert_eq!(std::fs::metadata(&archive).unwrap().modified().unwrap(), previous_time);
    let peer_time = std::fs::metadata(&peer).unwrap().modified().unwrap();
    std::fs::write(&peer, b"abcdef\x01\x00\x00\x00").unwrap();
    std::fs::OpenOptions::new().write(true).open(&peer).unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(peer_time)).unwrap();
    let (filtered, current) = refresh();
    assert!(!has_negative(&current));
    assert!(!rejects_peer(&current));
    let replacement = NativeCandidateTable::from_directory(&current, &filtered, None, false);
    assert_eq!(replacement.resolve().unwrap().resolved_relations().count(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

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
    carrier.extend_from_slice(STORED_ZIP);
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
        &super::super::passwords::RecentPasswords::default(),
        None,
    );
    let mut request = Request::new(inputs, super::super::Mode::Scan);
    request.deep = true;
    let config = Arc::make_mut(&mut request.config);
    config.recursive_authorization.enabled = false;
    config.embedded_scan.recursive_candidate_ratio = 0.0;
    let outputs = request.inputs.iter().map(|path| {
        let inventory = crate::scan::directory::scan_output_stats(&path.to_string_lossy(), true)
            .inventory.unwrap();
        OutputDiscovery::prepare(inventory, &options).unwrap()
    }).collect();
    let results = OutputDiscovery::discover_many(outputs, &candidates, &request).unwrap();
    assert_eq!(results.len(), request.inputs.len());
    for (result, scope) in results.into_iter().zip(&request.inputs) {
        assert!(result.errors.is_empty());
        assert!(result.blocked_paths.is_empty());
        for task in result.tasks {
            assert_eq!(task.inputs.len(), 1);
            assert_eq!(task.owned_paths.len(), 1);
            assert!(expected.remove(&path_key(&task.entry().entry_path)));
            assert_eq!(Path::new(&task.entry().entry_path).parent(), Some(scope.as_path()));
            let Some(TaskContext::Retry(retry)) = &task.context else {
                panic!("expected a retained volume resolution context");
            };
            assert_eq!(retry.scope.key(), path_key(&scope.to_string_lossy()));
        }
    }
    assert!(expected.is_empty());
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
    std::fs::write(&archive, STORED_ZIP).unwrap();
    let options =
        NativeDirectoryScanOptions::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let candidates = CandidateSet::new(
        Arc::from([]),
        None,
        &super::super::passwords::RecentPasswords::default(),
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
            let result = discover(&request, &options, &candidates, true).unwrap();
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
    let mut request = Request::new(vec![root.clone(), archive.clone()], super::super::Mode::Scan);
    request.recursive = true;
    let result = discover(&request, &options, &candidates, false).unwrap();
    let [task] = result.tasks.as_slice() else { panic!("expected one discovered archive"); };
    assert_eq!(Path::new(&task.entry().entry_path), archive);
    assert!(task.context.is_none());
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
        scan_discovery_scope(&options, &outer, true, &roots, &mut snapshots).unwrap();
    let (_, inner_raw) =
        scan_discovery_scope(&options, &inner, true, &roots, &mut snapshots).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert!(Arc::ptr_eq(&outer_raw.table, &inner_raw.table));
    let paths: Vec<_> = inner_raw
        .rows()
        .map(|row| &inner_raw.table.paths[row])
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
    let (_, refreshed) = options.refresh_relation_bucket(
        &scopes[1].scope, &head.to_string_lossy(), &scopes[1].snapshot, None, false,
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
