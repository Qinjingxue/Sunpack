use super::*;
use crate::test_support::temp_file;

#[test]
fn input_recovery_ignores_metadata_only_changes_but_receipts_do_not() {
    let path = temp_file("input_generation", b"archive");
    let original = capture_file_generation(&path).unwrap();
    let saved = &original;
    let mut changed = original.clone();
    changed.created = Some((false, 1, 0));
    #[cfg(windows)]
    { changed.windows.change_time = changed.windows.change_time.wrapping_add(1); }
    assert!(changed.matches_input(saved));
    assert_ne!(&changed, saved);
    changed.len += 1;
    assert!(!changed.matches_input(saved));
    changed = original.clone();
    #[cfg(windows)]
    { changed.windows.write_time = changed.windows.write_time.wrapping_add(1); }
    #[cfg(not(windows))]
    { changed.modified = Some((false, 1, 0)); }
    assert!(!changed.matches_input(saved));
    #[cfg(windows)]
    {
        changed = original.clone();
        changed.windows.file_id[0] ^= 1;
        assert!(!changed.matches_input(saved));
        changed = original.clone();
        changed.windows.volume = changed.windows.volume.wrapping_add(1);
        assert!(!changed.matches_input(saved));
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn short_and_exact_reads_preserve_eof_semantics() {
    let path = temp_file("managed_reader_eof", b"abcdef");
    let reader = ManagedReader::open(&path).unwrap();
    assert_eq!(reader.read_at(4, 8).unwrap(), b"ef");
    let mut cursor = reader.cursor();
    cursor.seek(SeekFrom::Start(4)).unwrap();
    assert_eq!(
        cursor.read_exact(&mut [0; 8]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(reader.stats().read_bytes, 4);
    let _ = std::fs::remove_file(path);
}

#[test]
fn independent_reads_enter_the_source_concurrently_with_and_without_request_cache() {
    // Block each source read until every reader can enter. Existing block
    // block-cache tests do not cover serializing the ManagedReader itself.
    struct ConcurrentSource {
        entered: std::sync::mpsc::Sender<u64>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl ByteSource for ConcurrentSource {
        fn len(&self) -> u64 {
            4
        }
        fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            self.entered.send(offset).unwrap();
            let (lock, ready) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            Ok(vec![offset as u8; len])
        }
    }
    for cache_bytes in [0, 8] {
        let (entered, arrivals) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let reader = ManagedReader::new(
            Arc::new(ConcurrentSource {
                entered,
                release: release.clone(),
            }),
            ReaderConfig { cache_bytes },
        );
        std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|offset| {
                    let reader = reader.clone();
                    scope.spawn(move || (offset, reader.read_at(offset, 1).unwrap()))
                })
                .collect::<Vec<_>>();
            // Bound a failed overlap assertion so a reintroduced reader
            // lock reports a failure instead of deadlocking the suite.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut observed = Vec::new();
            for _ in 0..4 {
                match arrivals
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                {
                    Ok(offset) => observed.push(offset),
                    Err(_) => break,
                }
            }
            *release.0.lock().unwrap() = true;
            release.1.notify_all();
            for worker in workers {
                let (offset, bytes) = worker.join().unwrap();
                assert_eq!(bytes, [offset as u8]);
            }
            observed.sort_unstable();
            assert_eq!(observed, [0, 1, 2, 3]);
        });
        assert_eq!(reader.stats().read_bytes, 4);
    }
}

fn cached_source_has_blocks(source_id: u64) -> bool {
    manager().cache_shards.iter().any(|shard| {
        shard.lock().unwrap().by_source.contains_key(&source_id)
    })
}

#[test]
fn directory_walk_releases_its_windows_without_populating_shared_blocks() {
    // Small relation fixtures cannot expose retaining a whole directory
    // after its walk. Check the real retained blocks, without RSS timing.
    use crate::formats::zip::{visit_relation_directory, RelationDirectory};
    let mut record = [0u8; 47];
    record[..4].copy_from_slice(b"PK\x01\x02");
    record[28..30].copy_from_slice(&1u16.to_le_bytes());
    record[46] = b'x';
    let bytes = record.repeat(4096);
    let path = crate::test_support::temp_file("zip_relation_directory_cache", &bytes);
    let directory = RelationDirectory {
        disk: 1,
        cd_disk: 1,
        offset: 0,
        size: bytes.len() as u64,
        entries: 4096,
        disk_entries: 4096,
        end: bytes.len() as u64,
    };
    let mut count = 0;
    let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
    assert!(
        visit_relation_directory(&path.to_string_lossy(), directory, |_, _| count += 1)
            .unwrap()
    );
    let reads = THREAD_PHYSICAL_READS.with(std::cell::Cell::get) - before;
    assert_eq!(count, 4096);
    assert!(reads < 32, "directory walk issued {reads} physical reads");
    let source = manager().open_file(&path).unwrap();
    assert!(!cached_source_has_blocks(source.identity.source_id));
    manager()
        .release_resources_under_roots(&[source.identity.path.to_path_buf()])
        .unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rar_header_walk_releases_windows_without_retaining_shared_blocks() {
    // ZIP's directory walk does not exercise RAR's ENDARC traversal.
    // Check both Relations' cached reader and Embedded's direct reader;
    // dense headers must not become retained blocks or one I/O per field.
    use crate::analysis_native::volume_anchor::{
        upgrade_relation_rar_end_reader, VolumeAnchor,
    };
    for rar5 in [false, true] {
        let mut record = vec![0u8; 32];
        let mut terminal;
        if rar5 {
            record[4..8].copy_from_slice(&[27, 2, 2, 0]);
            let crc = crc32fast::hash(&record[4..]);
            record[..4].copy_from_slice(&crc.to_le_bytes());
            terminal = vec![3, 5, 0, 0];
            let crc = crc32fast::hash(&terminal);
            terminal.splice(..0, crc.to_le_bytes());
        } else {
            record[2] = 0x74;
            record[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
            record[5..7].copy_from_slice(&32u16.to_le_bytes());
            let crc = crc32fast::hash(&record[2..]) as u16;
            record[..2].copy_from_slice(&crc.to_le_bytes());
            terminal = vec![0, 0, 0x7b, 8, 0, 9, 0, 2, 0];
            let crc = crc32fast::hash(&terminal[2..]) as u16;
            terminal[..2].copy_from_slice(&crc.to_le_bytes());
        }
        let mut bytes = vec![0x77; 37];
        bytes.extend(record.repeat(4096));
        bytes.extend(&terminal);
        let end = bytes.len() as u64;
        bytes.extend(b"carrier trailing bytes");
        for direct in [false, true] {
            let path = temp_file("rar_header_walk_cache", &bytes);
            let reader = ManagedReader::open(&path).unwrap();
            let reader = if direct {
                reader.probe_reader()
            } else {
                reader
            };
            let anchor = VolumeAnchor {
                path: path.to_string_lossy().into_owned(),
                size: bytes.len() as u64,
                format: "rar",
                structure_offset: Some(37),
                rar_next_header_offset: Some(37),
                flags: if rar5 { crate::analysis_native::volume_anchor::RAR_VERSION_5 } else { 0 },
                ..Default::default()
            };
            let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
            let resolved = upgrade_relation_rar_end_reader(&anchor, &reader).unwrap();
            let reads = THREAD_PHYSICAL_READS.with(std::cell::Cell::get) - before;
            assert_eq!(resolved.expected_logical_size, Some(end));
            assert_eq!(resolved.relation_has_next, Some(false));
            assert!(resolved.error.is_empty());
            let identity = reader.file_identity().unwrap();
            assert!(!cached_source_has_blocks(identity.source_id), "rar5={rar5}, direct={direct}");
            manager()
                .release_resources_under_roots(&[identity.path.to_path_buf()])
                .unwrap();
            std::fs::remove_file(path).unwrap();
            assert!(reads < 32, "RAR header walk issued {reads} physical reads");
        }
    }
}

#[test]
fn probe_reads_keep_ranges_and_generation_without_retaining_shared_blocks() {
    let data = vec![0x5au8; BLOCK_SIZE * 2 + 3];
    let path = temp_file("managed_reader_probe_scope", &data);
    let reader = ManagedReader::open(&path).unwrap();
    let probe = reader.probe_reader();
    assert!(Arc::ptr_eq(&reader.source, &probe.source));
    assert!(reader.cache.is_none() && probe.cache.is_none());
    assert_eq!(
        reader.file_identity().unwrap(),
        probe.file_identity().unwrap()
    );
    assert_eq!(probe.read_at(BLOCK_SIZE as u64 - 2, 8).unwrap(), [0x5a; 8]);
    assert_eq!(
        &*probe.read_cached_at(BLOCK_SIZE as u64, 4).unwrap(),
        &[0x5a; 4]
    );
    assert_eq!(probe.read_at(data.len() as u64 - 2, 8).unwrap(), [0x5a; 2]);
    let mut cursor = probe.cursor();
    cursor.seek(SeekFrom::Start(3)).unwrap();
    let mut bytes = [0; 4];
    cursor.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0x5a; 4]);
    let identity = reader.file_identity().unwrap();
    assert!(!cached_source_has_blocks(identity.source_id));
    manager()
        .release_resources_under_roots(&[identity.path.to_path_buf()])
        .unwrap();
    let error = probe.read_at(2, 4).unwrap_err();
    let fault = error.get_ref().unwrap().downcast_ref::<ReadFault>().unwrap();
    assert_eq!(fault.code, "io_error");
    assert_eq!(fault.operation, "read_at");
    assert_eq!(fault.offset, 2);
    assert_eq!(fault.requested, 4);
    assert_eq!(fault.actual, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn probe_reuses_existing_request_window() {
    let path = temp_file("managed_reader_probe_request", b"abcdefgh");
    let reader = ManagedReader::open_with_config(
        &path,
        ReaderConfig {
            cache_bytes: BLOCK_SIZE,
        },
    )
    .unwrap();
    let first = reader.read_cached_at(0, 4).unwrap();
    let probe = reader.probe_reader();
    let second = probe.read_cached_at(0, 4).unwrap();
    let (CachedBytes::Slice(first), CachedBytes::Slice(second)) = (first, second) else {
        panic!("request windows must remain shared");
    };
    assert!(first.shares_backing(&second));
    assert_eq!(reader.stats().read_bytes, 4);
    assert_eq!(reader.stats().cache_hits, 1);
    let _ = std::fs::remove_file(path);
}

#[test]
fn scan_probe_windows_preserve_borrowed_ranges_and_generation() {
    // Existing request-cache tests never enable scan windows. This coarse
    // case guards their slicing, eviction lifetime and closed-generation
    // behaviour together, using only three small blocks.
    let bytes = (0..BLOCK_SIZE * 3 + 17)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let path = temp_file("scan_probe_windows", &bytes);
    let reader = ManagedReader::open(&path).unwrap();
    let probe = reader.windowed_probe_reader();
    assert_eq!(
        reader.file_identity().unwrap().path,
        probe.file_identity().unwrap().path
    );
    probe.hint_probe_window(20);
    assert_eq!(&*probe.read_cached_at(20, 30).unwrap(), &bytes[20..50]);
    probe.hint_probe_window(80);
    let retained = probe.read_cached_at(80, 30).unwrap();
    assert_eq!(&*retained, &bytes[80..110]);
    assert_eq!(probe.read_at(90, 30).unwrap(), bytes[90..120]);
    for offset in [
        BLOCK_SIZE - 7,
        BLOCK_SIZE + 10,
        BLOCK_SIZE + 80,
        BLOCK_SIZE * 2 + 10,
        BLOCK_SIZE * 2 + 80,
        bytes.len() - 7,
    ] {
        let end = (offset + 30).min(bytes.len());
        probe.hint_probe_window(offset as u64);
        let mut buffer = [0; 30];
        let n = probe.read_into_at(offset as u64, &mut buffer).unwrap();
        assert_eq!(&buffer[..n], &bytes[offset..end]);
    }
    assert_eq!(&*retained, &bytes[80..110]);
    // Actual parser reads also populate the window; replacing it must
    // preserve outstanding bytes just like speculative block windows.
    probe.hint_probe_window(BLOCK_SIZE as u64 + 150);
    let bulk = probe.read_cached_at(BLOCK_SIZE as u64 + 150, 4096).unwrap();
    probe.hint_probe_window(BLOCK_SIZE as u64 * 2 + 200);
    probe
        .read_cached_at(BLOCK_SIZE as u64 * 2 + 200, 4096)
        .unwrap();
    assert_eq!(&*bulk, &bytes[BLOCK_SIZE + 150..BLOCK_SIZE + 150 + 4096]);
    let mut cursor = probe.cursor();
    cursor.seek(SeekFrom::End(-3)).unwrap();
    assert_eq!(
        cursor.read_exact(&mut [0; 8]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    let root = reader.file_identity().unwrap().path.to_path_buf();
    manager().release_resources_under_roots(&[root]).unwrap();
    assert!(probe
        .read_cached_at(BLOCK_SIZE as u64 * 2 + 200, 30)
        .is_err());
    assert_eq!(&*retained, &bytes[80..110]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn scan_probe_read_ahead_cannot_turn_neighbour_faults_into_requested_eof() {
    // Only speculative windows read before the requested range. A truncated
    // first volume must not hide readable bytes in the next volume.
    let first = temp_file("scan_probe_short_part1", b"abcd");
    let second = temp_file("scan_probe_short_part2", b"efgh");
    let paths = [
        first.to_string_lossy().into_owned(),
        second.to_string_lossy().into_owned(),
    ];
    let reader = ManagedReader::open_volumes(&paths, ReaderConfig::default())
        .unwrap()
        .windowed_probe_reader();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&first)
        .unwrap()
        .set_len(2)
        .unwrap();
    reader.hint_probe_window(4);
    assert_eq!(reader.read_at(4, 2).unwrap(), b"ef");
    reader.hint_probe_window(6);
    assert_eq!(reader.read_at(6, 4).unwrap(), b"gh");
    let mut cursor = reader.cursor();
    cursor.seek(SeekFrom::Start(1)).unwrap();
    assert_eq!(
        cursor.read_exact(&mut [0; 6]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    // Distinct fields of sparse hits must remain exact reads, rather than
    // manufacturing a whole-block read for each tiny rejected header.
    let sparse_source =
        ManagedReader::from_bytes(vec![0x5a; BLOCK_SIZE * 3], ReaderConfig::default());
    let sparse = sparse_source.windowed_probe_reader();
    for offset in [0, BLOCK_SIZE as u64 * 2] {
        sparse.hint_probe_window(offset);
        assert_eq!(sparse.read_at(offset, 16).unwrap(), [0x5a; 16]);
        assert_eq!(sparse.read_at(offset + 16, 8).unwrap(), [0x5a; 8]);
    }
    assert_eq!(sparse_source.stats().read_bytes, 48);
    let _ = std::fs::remove_file(first);
    let _ = std::fs::remove_file(second);
}

#[test]
fn probe_request_cache_reuses_direct_windows_and_survives_release() {
    let path = temp_file("managed_reader_probe_direct_request", b"abcdefgh");
    let reader =
        ManagedReader::open_with_config(&path, ReaderConfig { cache_bytes: 8 }).unwrap();
    let probe = reader.probe_reader();
    let first = probe.read_cached_at(0, 4).unwrap();
    assert_eq!(&*probe.read_cached_at(0, 4).unwrap(), b"abcd");
    assert_eq!(reader.stats().read_bytes, 4);
    assert_eq!(reader.stats().cache_hits, 1);
    let identity = reader.file_identity().unwrap();
    assert!(!cached_source_has_blocks(identity.source_id));
    manager()
        .release_resources_under_roots(&[identity.path.to_path_buf()])
        .unwrap();
    assert_eq!(&*first, b"abcd");
    let _ = std::fs::remove_file(path);
}

#[test]
fn owned_and_buffered_reads_share_the_request_cache() {
    let path = temp_file("managed_reader_into_stats", b"abcdefgh");
    let reader =
        ManagedReader::open_with_config(&path, ReaderConfig { cache_bytes: 8 }).unwrap();
    let mut buffer = [0u8; 4];
    assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
    assert_eq!(&buffer, b"abcd");
    assert_eq!(reader.read_at(0, 4).unwrap(), b"abcd");
    buffer.fill(0);
    assert_eq!(reader.read_into_at(0, &mut buffer).unwrap(), 4);
    assert_eq!(&buffer, b"abcd");
    let stats = reader.stats();
    assert_eq!(stats.read_bytes, 4);
    assert_eq!(stats.cache_hits, 2);
    let _ = std::fs::remove_file(path);
}

#[test]
fn request_cache_reuses_shared_backing_without_payload_copy() {
    let mut source = vec![0u8; BLOCK_SIZE + 1];
    source[..8].copy_from_slice(b"abcdefgh");
    let path = temp_file("managed_reader_shared_request", &source);
    let reader = ManagedReader::open_with_config(
        &path,
        ReaderConfig {
            cache_bytes: BLOCK_SIZE,
        },
    )
    .unwrap();

    let before = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
    let first = reader.read_cached_at(0, 4).unwrap();
    let second = reader.read_cached_at(0, 4).unwrap();
    let after = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);

    let (CachedBytes::Slice(first), CachedBytes::Slice(second)) = (first, second) else {
        panic!("request cache should return shared slices");
    };
    assert_eq!(&*first, b"abcd");
    assert_eq!(&*second, b"abcd");
    assert!(first.shares_backing(&second));
    assert_eq!(after - before, 0);

    let stats = reader.stats();
    assert_eq!(stats.read_bytes, 4);
    assert_eq!(stats.cache_hits, 1);
    let _ = std::fs::remove_file(path);
}

#[test]
fn request_cache_capacity_accounts_for_retained_shared_block() {
    let mut source = vec![0u8; BLOCK_SIZE + 1];
    source[..8].copy_from_slice(b"abcdefgh");
    let path = temp_file("managed_reader_shared_capacity", &source);
    let reader = ManagedReader::open_with_config(
        &path,
        ReaderConfig {
            cache_bytes: BLOCK_SIZE - 1,
        },
    )
    .unwrap();

    assert_eq!(&*reader.read_cached_at(0, 4).unwrap(), b"abcd");
    assert_eq!(&*reader.read_cached_at(0, 4).unwrap(), b"abcd");
    let stats = reader.stats();
    assert_eq!(stats.read_bytes, 8);
    assert_eq!(stats.cache_hits, 0);
    assert_eq!(reader.cache.as_ref().unwrap().lock().unwrap().cache_size, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn shared_slice_remains_valid_after_request_cache_eviction() {
    let mut source = vec![0u8; BLOCK_SIZE * 2];
    source[..4].copy_from_slice(b"keep");
    source[BLOCK_SIZE..BLOCK_SIZE + 4].copy_from_slice(b"next");
    let path = temp_file("managed_reader_shared_eviction", &source);
    let reader = ManagedReader::open_with_config(
        &path,
        ReaderConfig {
            cache_bytes: BLOCK_SIZE,
        },
    )
    .unwrap();

    let first = reader.read_cached_at(0, 4).unwrap();
    assert_eq!(&*first, b"keep");
    let second = reader.read_cached_at(BLOCK_SIZE as u64, 4).unwrap();
    assert_eq!(&*second, b"next");
    assert_eq!(&*first, b"keep");
    assert!(reader.cache.as_ref().unwrap().lock().unwrap().cache_size <= BLOCK_SIZE);

    let _ = std::fs::remove_file(path);
}

#[test]
fn shared_request_data_survives_file_resource_release() {
    let mut source = vec![0u8; BLOCK_SIZE + 1];
    source[..7].copy_from_slice(b"payload");
    let path = temp_file("managed_reader_shared_release", &source);
    let reader = ManagedReader::open_with_config(
        &path,
        ReaderConfig {
            cache_bytes: BLOCK_SIZE,
        },
    )
    .unwrap();

    let data = reader.read_cached_at(0, 7).unwrap();
    let identity = reader.file_identity().unwrap();
    assert!(cached_source_has_blocks(identity.source_id));
    manager()
        .release_resources_under_roots(&[identity.path.to_path_buf()])
        .unwrap();
    assert!(!cached_source_has_blocks(identity.source_id));
    assert_eq!(&*data, b"payload");

    drop(reader);
    let _ = std::fs::remove_file(path);
}

#[test]
fn final_reader_releases_source_and_blocks_without_a_cleanup_event() {
    let path = temp_file("managed_reader_final_borrow", b"payload");
    let first = ManagedReader::open(&path).unwrap();
    let second = ManagedReader::open(&path).unwrap();
    assert!(Arc::ptr_eq(&first.source, &second.source));
    let identity = first.file_identity().unwrap();
    let data = first.read_cached_at(0, 7).unwrap();

    drop(first);
    assert!(cached_source_has_blocks(identity.source_id));
    drop(second);

    assert!(!manager().handles.lock().unwrap().contains_key(&identity.path));
    assert!(!cached_source_has_blocks(identity.source_id));
    assert_eq!(&*data, b"payload");
    let reopened = ManagedReader::open(&path).unwrap();
    assert_ne!(identity, reopened.file_identity().unwrap());
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn tiny_and_empty_blocks_charge_cache_budget() {
    // Large-payload eviction tests cannot expose unlimited empty cache
    // entries. Mix a tiny payload with an empty block at each tier's budget.
    let path = temp_file("managed_reader_tiny_cache", b"x");
    let source = manager().open_file(&path).unwrap();
    let budget = 2 * CACHE_BLOCK_METADATA_BYTES + 1;
    let mut shard = CacheShard::new(budget, budget);
    let source_path = &source.identity.path;
    for (start, tier) in [(0, CacheTier::Hot), (3, CacheTier::General)] {
        let first = BlockKey::new(&source, start);
        let second = BlockKey::new(&source, start + 1);
        let third = BlockKey::new(&source, start + 2);
        shard.insert(first, source_path, Arc::from([]), tier);
        shard.insert(second, source_path, Arc::from([b'x']), tier);
        assert!(shard.entries.contains_key(&first));
        assert!(shard.entries.contains_key(&second));
        shard.insert(third, source_path, Arc::from([]), tier);
        assert!(!shard.entries.contains_key(&first));
        assert!(shard.entries.contains_key(&second));
        assert!(shard.entries.contains_key(&third));
        assert_eq!(shard.queue(tier).bytes, 1);
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn targeted_cache_cleanup_drops_peak_allocations_and_keeps_live_borrows() {
    // Existing release tests check bytes and ownership, but cannot see a
    // sparse shard's retained allocations. Keep this local so parallel
    // readers cannot mask the peak-to-idle transition.
    let path = temp_file("managed_reader_cache_peak", b"payload");
    let source = manager().open_file(&path).unwrap();
    let payload: Arc<[u8]> = Arc::from(&b"payload"[..]);
    let mut shard = CacheShard::new(usize::MAX, usize::MAX);
    let mut keys = Vec::new();
    for generation in 1..=1024 {
        let key = BlockKey {
            source_id: generation,
            index: 0,
        };
        let tier = if generation % 2 == 0 {
            CacheTier::Hot
        } else {
            CacheTier::General
        };
        shard.insert(key, &source.identity.path, Arc::clone(&payload), tier);
        keys.push(key);
    }
    let live = keys.pop().unwrap();
    for key in keys {
        assert!(shard.remove_source(key.source_id));
    }
    shard.compact_stale_orders();
    assert_eq!(shard.entries.len(), 1);
    assert!(shard.entries.capacity() <= 256 && shard.by_source.capacity() <= 256);
    assert!(shard.hot.order.capacity() <= 256 && shard.general.order.capacity() <= 256);
    assert!(Arc::ptr_eq(&shard.entries[&live].data, &payload));
    assert!(shard.remove_source(live.source_id));
    shard.compact_stale_orders();
    assert_eq!(shard.hot.bytes + shard.general.bytes, 0);
    assert_eq!(
        shard.entries.capacity()
            + shard.by_source.capacity()
            + shard.hot.order.capacity()
            + shard.general.order.capacity(),
        0
    );
    assert_eq!(&*payload, b"payload");
    manager()
        .release_resources_under_roots(&[source.identity.path.to_path_buf()])
        .unwrap();
    let _ = std::fs::remove_file(path);
}

#[test]
fn batched_release_removes_only_indexed_file_identities() {
    let first_path = temp_file("managed_reader_release_first", b"abcdefgh");
    let second_path = temp_file("managed_reader_release_second", b"ijklmnop");
    let other_path = temp_file("managed_reader_release_other", b"qrstuvwx");

    let first = manager().open_file(&first_path).unwrap();
    let second = manager().open_file(&second_path).unwrap();
    let other = manager().open_file(&other_path).unwrap();
    assert_eq!(first.read_at(0, 8).unwrap(), b"abcdefgh");
    assert_eq!(second.read_at(0, 8).unwrap(), b"ijklmnop");
    assert_eq!(other.read_at(0, 8).unwrap(), b"qrstuvwx");

    let first_key = BlockKey::new(&first, 0);
    let second_key = BlockKey::new(&second, 0);
    let other_key = BlockKey::new(&other, 0);
    assert!(manager().cached_block(&first_key).unwrap().is_some());
    assert!(manager().cached_block(&second_key).unwrap().is_some());
    assert!(manager().cached_block(&other_key).unwrap().is_some());

    let roots = vec![
        std::fs::canonicalize(&first_path).unwrap_or_else(|_| first_path.clone()),
        std::fs::canonicalize(&second_path).unwrap_or_else(|_| second_path.clone()),
    ];
    manager().release_resources_under_roots(&roots).unwrap();

    assert!(first.closed.load(Ordering::Acquire));
    assert!(second.closed.load(Ordering::Acquire));
    assert!(!manager().cached_block(&first_key).unwrap().is_some());
    assert!(!manager().cached_block(&second_key).unwrap().is_some());
    assert!(manager().cached_block(&other_key).unwrap().is_some());
    assert_eq!(other.read_at(0, 8).unwrap(), b"qrstuvwx");

    let other_root = std::fs::canonicalize(&other_path).unwrap_or_else(|_| other_path.clone());
    manager()
        .release_resources_under_roots(&[other_root])
        .unwrap();
    let _ = std::fs::remove_file(first_path);
    let _ = std::fs::remove_file(second_path);
    let _ = std::fs::remove_file(other_path);
}

#[test]
fn request_cache_coalesces_cross_volume_data_once() {
    let first_path = temp_file("managed_reader_shared_part1", b"abc");
    let second_path = temp_file("managed_reader_shared_part2", b"def");
    let paths = vec![
        first_path.to_string_lossy().into_owned(),
        second_path.to_string_lossy().into_owned(),
    ];
    let reader = ManagedReader::open_volumes(&paths, ReaderConfig { cache_bytes: 16 }).unwrap();

    let before = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
    let first = reader.read_cached_at(2, 3).unwrap();
    let middle = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);
    let second = reader.read_cached_at(2, 3).unwrap();
    let after = THREAD_REQUEST_COALESCES.with(std::cell::Cell::get);

    let (CachedBytes::Slice(first), CachedBytes::Slice(second)) = (first, second) else {
        panic!("cross-volume request should be cached as one shared slice");
    };
    assert_eq!(&*first, b"cde");
    assert_eq!(&*second, b"cde");
    assert!(first.shares_backing(&second));
    assert_eq!(middle - before, 1);
    assert_eq!(after - middle, 0);

    let stats = reader.stats();
    assert_eq!(stats.read_bytes, 3);
    assert_eq!(stats.cache_hits, 1);
    let _ = std::fs::remove_file(first_path);
    let _ = std::fs::remove_file(second_path);
}

#[test]
fn multi_volume_reads_across_boundary() {
    let first = temp_file("managed_reader_part1", b"..abc!");
    let second = temp_file("managed_reader_part2", b".def!!");
    let empty = temp_file("managed_reader_empty_part", b"");
    let first_path = first.to_string_lossy();
    let second_path = second.to_string_lossy();
    let empty_path = empty.to_string_lossy();
    let extents = [
        (empty_path.as_ref(), 0, None),
        (first_path.as_ref(), 2, Some(5)),
        (empty_path.as_ref(), 0, None),
        (second_path.as_ref(), 1, Some(4)),
        (empty_path.as_ref(), 0, None),
    ];
    // One matrix covers all read modes, bounded carrier ranges,
    // zero-length volumes, and clipped EOF.
    let source = MultiVolumeSource::open_extents(extents).unwrap();
    for offset in 0..=7u64 {
        for length in 0..=8usize {
            let start = (offset as usize).min(6);
            let end = start.saturating_add(length).min(6);
            let expected = &b"abcdef"[start..end];
            assert_eq!(source.read_at(offset, length).unwrap(), expected);
            assert_eq!(source.read_direct_at(offset, length).unwrap(), expected);
            let mut buffer = vec![0; length];
            let written = source.read_into_at(offset, &mut buffer).unwrap();
            assert_eq!(&buffer[..written], expected);
            let slices = source.read_slices_at(offset, length).unwrap();
            assert_eq!(
                slices
                    .iter()
                    .flat_map(|slice| slice.iter().copied())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
    let (reader, starts) =
        ManagedReader::open_extents(extents, ReaderConfig::default()).unwrap();
    assert_eq!(starts, [0, 0, 3, 3, 6]);
    assert_eq!(reader.read_at(2, 3).unwrap(), b"cde");
    let mut cursor = reader.cursor();
    cursor.seek(SeekFrom::Start(2)).unwrap();
    let mut data = [0u8; 3];
    cursor.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"cde");
    let _ = std::fs::remove_file(first);
    let _ = std::fs::remove_file(second);
    let _ = std::fs::remove_file(empty);
}

#[test]
fn multi_volume_stops_at_volume_truncated_after_open() {
    let first = temp_file("managed_reader_shrunk_part1", b"abcdef");
    let second = temp_file("managed_reader_shrunk_part2", b"ghi");
    let paths = vec![
        first.to_string_lossy().into_owned(),
        second.to_string_lossy().into_owned(),
    ];
    let reader = ManagedReader::open_volumes(&paths, ReaderConfig::default()).unwrap();
    TrackedFile::open_with(&first, |options| {
        options.write(true);
    })
    .unwrap()
    .set_len(3)
    .unwrap();

    // Bytes of the next volume must never slide into the missing range.
    assert_eq!(reader.read_at(1, 7).unwrap(), b"bc");
    let mut buffer = [0u8; 7];
    assert_eq!(reader.read_direct_into_at(1, &mut buffer).unwrap(), 2);
    assert_eq!(&buffer[..2], b"bc");
    let mut cursor = reader.cursor();
    cursor.seek(SeekFrom::Start(1)).unwrap();
    let mut exact = [0u8; 7];
    assert_eq!(
        cursor.read_exact(&mut exact).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    let _ = std::fs::remove_file(first);
    let _ = std::fs::remove_file(second);
}

#[test]
fn readers_share_file_handle_and_block_cache() {
    let path = temp_file("managed_reader_shared", b"abcdefgh");
    let first = manager().open_file(&path).unwrap();
    assert_eq!(first.read_at(0, 4).unwrap(), b"abcd");
    let key = BlockKey::new(&first, 0);
    assert!(manager()
        .cached_block(&key)
        .unwrap()
        .is_some());
    let second = manager().open_file(&path).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(second.read_at(2, 4).unwrap(), b"cdef");
    let _ = std::fs::remove_file(path);
}

#[test]
fn cached_slices_preserve_requested_bytes() {
    let data = vec![0x5au8; BLOCK_SIZE + 32];
    let path = temp_file("managed_reader_slices", &data);
    let reader = ManagedReader::open(&path).unwrap();
    let slices = reader.read_slices_at(BLOCK_SIZE as u64 - 8, 16).unwrap();
    assert_eq!(slices.len(), 2);
    assert_eq!(slices.iter().map(|slice| slice.len()).sum::<usize>(), 16);
    let cached = reader.read_cached_at(4, 8).unwrap();
    assert!(matches!(cached, CachedBytes::Slice(_)));
    assert_eq!(&*cached, &[0x5a; 8]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn read_block_shares_an_existing_load() {
    let data = vec![0x4du8; BLOCK_SIZE];
    let path = temp_file("managed_reader_read_overlap", &data);
    let source = manager().open_file(&path).unwrap();

    let load = match manager()
        .claim_block_load(&source, &BlockKey::new(&source, 0))
        .unwrap()
    {
        BlockLoadClaim::Owned(load) => load,
        _ => panic!("test block should be newly claimed"),
    };

    let worker_source = Arc::clone(&source);
    let handle = std::thread::spawn(move || {
        let before = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
        let block = manager().read_block(&worker_source, 0).unwrap();
        let after = THREAD_PHYSICAL_READS.with(std::cell::Cell::get);
        (block, after - before)
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while Arc::strong_count(&load) < 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "reader did not join the existing block load"
        );
        std::thread::yield_now();
    }

    let block = source
        .with_file(|file| read_file_at(file, 0, BLOCK_SIZE))
        .unwrap();
    let key = BlockKey::new(&source, 0);
    manager()
        .insert_block(&source, key, Arc::from(block), cache_tier(&source, 0))
        .unwrap();
    manager().finish_block_load(&source, 0, &load).unwrap();

    let (block, worker_reads) = handle.join().unwrap();
    assert_eq!(worker_reads, 0);
    assert_eq!(block.len(), BLOCK_SIZE);
    assert!(block.iter().all(|byte| *byte == 0x4d));
    assert!(source.block_loads.lock().unwrap().is_empty());
    let _ = std::fs::remove_file(path);
}

#[test]
fn failed_read_releases_claimed_block() {
    let data = vec![0x31u8; BLOCK_SIZE * 2];
    let path = temp_file("managed_reader_block_error_cleanup", &data);
    let source = manager().open_file(&path).unwrap();
    source.close().unwrap();

    assert!(manager().read_block(&source, 0).is_err());
    assert!(source.block_loads.lock().unwrap().is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn changed_file_gets_a_new_identity() {
    let path = temp_file("managed_reader_identity", b"old");
    let first = ManagedReader::open(&path).unwrap();
    assert_eq!(first.read_all().unwrap(), b"old");
    std::fs::write(&path, b"new-data").unwrap();
    let second = ManagedReader::open(&path).unwrap();
    assert_eq!(second.read_all().unwrap(), b"new-data");
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
fn restore_generation_test_times(file: &File, metadata: &std::fs::Metadata) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileTime(
            handle: *mut c_void,
            creation: *const u64,
            access: *const u64,
            write: *const u64,
        ) -> i32;
    }
    let created = metadata
        .created()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let ticks = (created.as_secs() + 11_644_473_600) * 10_000_000
        + u64::from(created.subsec_nanos() / 100);
    assert_ne!(
        unsafe {
            SetFileTime(
                file.as_raw_handle(),
                &ticks,
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    file.set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
        .unwrap();
}

#[cfg(windows)]
fn set_generation_test_change_time(file: &File, change_time: i64) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct FileBasicInfo {
        creation_time: i64,
        access_time: i64,
        write_time: i64,
        change_time: i64,
        attributes: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileInformationByHandle(
            handle: *mut c_void,
            class: i32,
            information: *const c_void,
            size: u32,
        ) -> i32;
    }
    let information = FileBasicInfo {
        change_time,
        ..Default::default()
    };
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                0,
                (&information as *const FileBasicInfo).cast(),
                std::mem::size_of::<FileBasicInfo>() as u32,
            )
        },
        0
    );
}

#[test]
#[cfg(windows)]
fn bug_regression_replacement_with_restored_timestamps_uses_new_file_id() {
    let path = temp_file("generation_replace", b"old!");
    let old_path = path.with_extension("old");
    let metadata = std::fs::metadata(&path).unwrap();
    let first = ManagedReader::open(&path).unwrap();
    assert_eq!(first.read_all().unwrap(), b"old!");
    std::fs::rename(&path, &old_path).unwrap();
    std::fs::write(&path, b"new!").unwrap();
    let replacement = TrackedFile::open_with(&path, |options| {
        options.write(true);
    })
    .unwrap();
    restore_generation_test_times(&replacement, &metadata);
    drop(replacement);
    let second = ManagedReader::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        metadata.modified().unwrap()
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().created().unwrap(),
        metadata.created().unwrap()
    );
    assert_ne!(
        first.file_identity().unwrap(),
        second.file_identity().unwrap()
    );
    assert_eq!(second.read_all().unwrap(), b"new!");
    assert_eq!(first.read_all().unwrap(), b"old!");
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(old_path).unwrap();
}

#[test]
#[cfg(windows)]
fn bug_regression_in_place_write_with_restored_mtime_invalidates_blocks() {
    let path = temp_file("generation_overwrite", b"old!");
    let metadata = std::fs::metadata(&path).unwrap();
    // Creation and overwrite can occur in the same Windows clock tick.
    // Start with a historical ChangeTime so the real write/metadata update
    // has a distinct generation without sleeps or altered production I/O.
    let initial = TrackedFile::open_with(&path, |options| {
        options.write(true);
    })
    .unwrap();
    let initial_generation = windows_file_generation(&initial).unwrap();
    set_generation_test_change_time(&initial, initial_generation.change_time - 10_000_000);
    drop(initial);
    let first = ManagedReader::open(&path).unwrap();
    assert_eq!(first.read_all().unwrap(), b"old!");
    std::fs::write(&path, b"new!").unwrap();
    let file = TrackedFile::open_with(&path, |options| {
        options.write(true);
    })
    .unwrap();
    restore_generation_test_times(&file, &metadata);
    drop(file);
    let second = ManagedReader::open(&path).unwrap();
    assert_ne!(
        first.file_identity().unwrap(),
        second.file_identity().unwrap()
    );
    assert_eq!(second.read_all().unwrap(), b"new!");
    let third = ManagedReader::open(&path).unwrap();
    assert_eq!(
        second.file_identity().unwrap(),
        third.file_identity().unwrap()
    );
    assert_eq!(third.read_all().unwrap(), b"new!");

    // The metadata-generation case above cannot expose an event-proven
    // write in the same clock tick, or a late old loader publishing after
    // invalidation. Reuse this tiny lifecycle to cover both boundaries.
    let old_source = manager().open_file(&path).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let old_key = BlockKey::new(&old_source, 0);
    assert!(manager().cache_shards[cache_shard_index(&old_key)]
        .lock()
        .unwrap()
        .remove_source(old_key.source_id));
    std::fs::write(&path, b"last").unwrap();
    let writer = TrackedFile::open_with(&path, |options| {
        options.write(true);
    })
    .unwrap();
    restore_generation_test_times(&writer, &metadata);
    set_generation_test_change_time(&writer, old_source.physical.windows.change_time);
    drop(writer);
    invalidate_reader_path(&path);
    let current = manager().open_file(&path).unwrap();
    assert_eq!(old_source.physical, current.physical);
    manager()
        .insert_block(
            &old_source,
            old_key,
            Arc::from(&b"new!"[..]),
            CacheTier::Hot,
        )
        .unwrap();
    assert_eq!(current.read_at(0, 4).unwrap(), b"last");
    assert_ne!(old_source.identity, current.identity);
    assert!(!old_source.closed.load(Ordering::Acquire));
    assert_eq!(third.read_all().unwrap(), b"new!");
    // The superseded source stays reusable only while an older reader
    // can still address its blocks. Retiring its final borrow must free
    // them without a cache-pressure event or releasing the current file.
    assert!(manager().cached_block(&old_key).unwrap().is_some());
    drop(old_source);
    drop(second);
    drop(third);
    assert!(!manager().cached_block(&old_key).unwrap().is_some());
    assert_eq!(current.read_at(0, 4).unwrap(), b"last");
    std::fs::remove_file(path).unwrap();
}

// Test source for cross-boundary cache and fault injection.
impl ManagedReader {
    pub(crate) fn open_volumes(paths: &[String], config: ReaderConfig) -> io::Result<Self> {
        let source = MultiVolumeSource::open(paths)?;
        Ok(Self::new(Arc::new(source), config))
    }

    pub(crate) fn open_extents<'a>(
        extents: impl IntoIterator<Item = (&'a str, u64, Option<u64>)>,
        config: ReaderConfig,
    ) -> io::Result<(Self, Vec<u64>)> {
        let source = MultiVolumeSource::open_extents(extents)?;
        let disk_starts = source.volumes.iter().map(|volume| volume.start).collect();
        Ok((Self::new(Arc::new(source), config), disk_starts))
    }

}

struct Volume {
    start: u64,
    end: u64,
    physical_start: u64,
    source: Arc<FileSource>,
}

struct MultiVolumeSource {
    len: u64,
    volumes: Vec<Volume>,
}

impl MultiVolumeSource {
    fn read_into_mode(&self, offset: u64, buffer: &mut [u8], direct: bool) -> io::Result<usize> {
        if offset >= self.len || buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len().min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut written = 0usize;
        for volume in &self.volumes[self.overlapping(offset, end)] {
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk_len = (logical_end - logical_start) as usize;
            let target = &mut buffer[written..written + chunk_len];
            let count = if direct {
                volume.source.read_direct_into_at(
                    volume.physical_start + (logical_start - volume.start),
                    target,
                )?
            } else {
                volume.source.read_into_at(
                    volume.physical_start + (logical_start - volume.start),
                    target,
                )?
            };
            written += count;
            if count != chunk_len {
                break;
            }
        }
        Ok(written)
    }

    /// Ordered physical extents share this lookup across every read mode.
    fn overlapping(&self, offset: u64, end: u64) -> std::ops::Range<usize> {
        if offset >= end {
            return 0..0;
        }
        let first = self.volumes.partition_point(|volume| volume.end <= offset);
        let tail = &self.volumes[first..];
        let count = tail.partition_point(|volume| volume.start < end);
        first..first + count
    }

    #[cfg(test)]
    fn open(paths: &[String]) -> io::Result<Self> {
        Self::open_extents(paths.iter().map(|path| (path.as_str(), 0, None)))
    }

    fn open_extents<'a>(
        extents: impl IntoIterator<Item = (&'a str, u64, Option<u64>)>,
    ) -> io::Result<Self> {
        let extents = extents.into_iter();
        let mut cursor = 0u64;
        let mut volumes = Vec::with_capacity(extents.size_hint().0);
        for (path, physical_start, physical_end) in extents {
            let source = manager().open_file(path.as_ref())?;
            let length = physical_end
                .unwrap_or(source.len())
                .min(source.len())
                .checked_sub(physical_start)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid archive extent")
                })?;
            let end = cursor.checked_add(length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "multi-volume size overflow")
            })?;
            volumes.push(Volume {
                start: cursor,
                end,
                physical_start,
                source,
            });
            cursor = end;
        }
        if volumes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multi-volume reader requires at least one volume",
            ));
        }
        Ok(Self {
            len: cursor,
            volumes,
        })
    }
}

impl ByteSource for MultiVolumeSource {
    fn validate_cached_range(&self, offset: u64, len: usize) -> io::Result<()> {
        for volume in &self.volumes[self.overlapping(offset, offset.saturating_add(len as u64))] {
            volume.source.ensure_open()?;
        }
        Ok(())
    }
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let len = len.min(self.len.saturating_sub(offset) as usize);
        let mut output = crate::io::resource_error::zeroed_bytes(len)?;
        let count = self.read_into_mode(offset, &mut output, false)?;
        output.truncate(count);
        Ok(output)
    }

    fn read_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_into_mode(offset, buffer, false)
    }

    fn read_direct_into_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.read_into_mode(offset, buffer, true)
    }

    fn read_slices_at(&self, offset: u64, len: usize) -> io::Result<Vec<CachedSlice>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.len - offset) as usize);
        let end = offset + len as u64;
        let mut slices = Vec::new();
        for volume in &self.volumes[self.overlapping(offset, end)] {
            let logical_start = offset.max(volume.start);
            let logical_end = end.min(volume.end);
            let chunk_len = (logical_end - logical_start) as usize;
            let volume_slices = volume.source.read_slices_at(
                volume.physical_start + (logical_start - volume.start),
                chunk_len,
            )?;
            let produced = volume_slices.iter().map(|slice| slice.len()).sum::<usize>();
            slices.extend(volume_slices);
            if produced != chunk_len {
                break;
            }
        }
        Ok(slices)
    }

    fn read_direct_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let len = len.min(self.len.saturating_sub(offset) as usize);
        let mut output = crate::io::resource_error::zeroed_bytes(len)?;
        let count = self.read_into_mode(offset, &mut output, true)?;
        output.truncate(count);
        Ok(output)
    }
}
