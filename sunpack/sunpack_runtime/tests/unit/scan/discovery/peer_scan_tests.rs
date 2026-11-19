use super::*;
use crate::analysis_native::volume_anchor::VolumeAnchor;
use crate::scan::directory::DirectoryEntryRecord;

static SCANS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

pub(super) fn record_scan(path: &str) {
    if let Some(count) = SCANS.lock().unwrap().get_mut(path) { *count += 1; }
}

#[test]
fn targeted_volume_peer_scan_reuses_known_facts_and_ignores_other_stems() {
    let head = crate::test_support::temp_file("volume_peers", b"ordinary bytes");
    let peer = head.with_extension("peer");
    let peers: Vec<_> = std::iter::once(peer.clone())
        .chain((1..257).map(|index| head.with_extension(format!("peer-{index}")))).collect();
    for peer in &peers { std::fs::write(peer, b"ordinary peer bytes").unwrap(); }
    let paths: Vec<_> = [head.clone(), peer.clone(), head.with_extension("cheap"),
        head.with_extension("cached"), head.with_extension("excluded")]
        .into_iter().map(|path| path.to_string_lossy().into_owned()).collect();
    let anchor = VolumeAnchor { path: paths[0].clone(), multivolume: true, ..Default::default() };
    let mut records: Vec<_> = paths.iter().map(|path| DirectoryEntryRecord {
        path: path.clone(), relation_member_eligible: true, ..Default::default()
    }).collect();
    records[2].relation_anchor = Some(CheapAnchor::Full(Arc::new(VolumeAnchor {
        path: paths[2].clone(), multivolume: true, ..Default::default()
    })));
    records.extend(peers.iter().skip(1).map(|path| DirectoryEntryRecord {
        path: path.to_string_lossy().into_owned(), relation_member_eligible: true, ..Default::default()
    }));
    records.extend((0..10_000).map(|index| DirectoryEntryRecord {
        path: format!("unrelated-{index}.bin"), relation_member_eligible: true, ..Default::default()
    }));
    let (snapshot, raw) = NativeDirectorySnapshot::from_views(
        (0..records.len() - 1).collect(), records, Default::default(), Vec::new(),
    );
    let source = raw.table;
    let other_path = head.parent().unwrap().join("other-scope").join(head.file_name().unwrap()).to_string_lossy().into_owned();
    let (_, other) = NativeDirectorySnapshot::from_views(
        vec![0], [DirectoryEntryRecord {
            path: other_path.clone(), relation_member_eligible: true, ..Default::default()
        }], Default::default(), Vec::new(),
    );
    let mut table = NativeCandidateTable {
        rows: vec![Candidate::File(Arc::clone(&source), 0)],
        relation_sources: vec![snapshot, other], ..Default::default()
    };
    let mut batch = NativeEmbeddedBatch::default();
    batch.pending_volumes.push(PendingEmbeddedVolume { index: 0, anchor: anchor.clone(), scan: None });
    batch.relation_cache.anchors.insert(path_key(&paths[3]), anchor.clone());
    batch.excluded.insert(path_key(&paths[4]));
    {
        let mut scans = SCANS.lock().unwrap();
        scans.extend(source.paths.iter().cloned().map(|path| (path, 0)));
        scans.insert(other_path.clone(), 0);
    }
    NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
    assert_eq!(batch.supplemental.len(), 257);
    assert_eq!(batch.len(), 1);
    // Only the unselected same-stem source remains indexed; 10,000 other
    // stems never allocate persistent buckets, and this scope cannot scan it.
    assert_eq!(batch.peer_rows.as_ref().unwrap().len(), 1);
    assert_eq!(table.rows[1].path(), paths[1]);
    // Re-entering this request reuses its rows, without a second peer job.
    NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
    assert_eq!(table.rows.len(), 258);
    assert_eq!(batch.len(), 0);
    assert!(batch.peer_rows.is_none());
    assert_eq!(batch.seen_paths.capacity(), 0);
    assert_eq!(batch.ids.capacity(), 0);
    // Draining file jobs must not discard the pending relation evidence.
    assert_eq!(batch.pending_volumes.len(), 1);
    assert!(table.rows.iter().all(|row| matches!(row, Candidate::File(facts, _) if Arc::ptr_eq(facts, &source))));
    {
        let scans = SCANS.lock().unwrap();
        for peer in &peers { assert_eq!(scans.get(peer.to_string_lossy().as_ref()), Some(&1)); }
        assert_eq!(scans.get(&other_path), Some(&0));
        for path in [&paths[0], &paths[2], &paths[3], &paths[4]] {
            assert_eq!(scans.get(path), Some(&0));
        }
        assert!((0..10_000).all(|index| scans.get(&format!("unrelated-{index}.bin")) == Some(&0)));
    }
    // A directory pass has already scanned all these physical rows.
    table.rows = (0..source.paths.len()).map(|row| Candidate::File(Arc::clone(&source), row)).collect();
    batch.supplemental.clear();
    batch.nominated = 0;
    batch.peer_rows = None;
    batch.seen_paths.clear();
    NativeEmbeddedBatch::scan_pages(vec![(&mut table, &mut batch)], 256).unwrap();
    assert!(batch.supplemental.is_empty());
    {
        let mut scans = SCANS.lock().unwrap();
        assert_eq!(scans.get(&paths[1]), Some(&1));
        for path in &source.paths { scans.remove(path); }
        scans.remove(&other_path);
    }
    std::fs::remove_file(head).unwrap();
    for peer in peers { std::fs::remove_file(peer).unwrap(); }
}
