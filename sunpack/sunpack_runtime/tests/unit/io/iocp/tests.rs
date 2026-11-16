use super::*;

#[test]
fn panicking_callbacks_release_scan_resources_and_leave_pool_usable() {
    // Cancellation and successful scans cannot detect a lost worker wake
    // or pending reads freed during callback unwinding. Exercise both
    // callback sites, the inline path and a surviving scan in one lifecycle.
    let path =
        std::env::temp_dir().join(format!("sunpack_iocp_panic_{}.bin", std::process::id(),));
    let size = 32 * 64 * 1024;
    std::fs::write(&path, vec![0x5a; size]).unwrap();
    for (length, worker_panic) in [(size, true), (size, false), (1024, true)] {
        let result = std::panic::catch_unwind(|| {
            scan_file(
                &path,
                length as u64,
                64 * 1024,
                2,
                2,
                11,
                |data, carry, base| {
                    if worker_panic && base == 0 {
                        panic!("scan callback failed");
                    }
                    ScanBatch {
                        results: data.len() - carry,
                        discarded_results: 0,
                    }
                },
                |_| {
                    if !worker_panic {
                        panic!("collect callback failed");
                    }
                    Ok(())
                },
            )
        });
        let panic = match result {
            Err(panic) => panic,
            Ok(_) => panic!("callback panic was swallowed"),
        };
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some(if worker_panic {
                "scan callback failed"
            } else {
                "collect callback failed"
            }),
        );
        // A leaked scan handle would deny this exclusive open.
        use std::os::windows::fs::OpenOptionsExt;
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&path)
                .unwrap(),
        );
    }
    let mut matched = 0;
    scan_file(
        &path,
        size as u64,
        64 * 1024,
        2,
        2,
        11,
        |data, carry, _| ScanBatch {
            results: data.len() - carry,
            discarded_results: 0,
        },
        |count| {
            matched += count;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(matched, size);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn overlapped_offset_supports_files_above_four_gibabytes() {
    let mut slot = IocpSlot::new(16);
    configure_slot(&mut slot, (4u64 << 30) + 123, (4u64 << 30) + 1024, 512, 7).unwrap();
    assert_eq!(slot.overlapped.offset, 116);
    assert_eq!(slot.overlapped.offset_high, 1);
    assert_eq!(slot.read_start, (4u64 << 30) + 116);
}

#[test]
fn keeps_io_slots_independent_of_slow_scan_workers() {
    let chunk_bytes = 64 * 1024usize;
    let data = vec![0x5a; chunk_bytes * 8 + 17];
    let path = std::env::temp_dir().join(format!(
        "sunpack_iocp_slow_worker_{}_{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::write(&path, &data).unwrap();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut actual = Vec::new();
    let output = pool
        .install(|| {
            scan_file(
                &path,
                data.len() as u64,
                chunk_bytes,
                2,
                1,
                0,
                |_, _, base_offset| {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    ScanBatch {
                        results: vec![base_offset],
                        discarded_results: 0,
                    }
                },
                |batch| {
                    actual.extend(batch);
                    Ok(())
                },
            )
        })
        .unwrap();

    let expected = (0..data.len())
        .step_by(chunk_bytes)
        .map(|offset| offset as u64)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    assert_eq!(actual, expected);
    assert_eq!(output.read_operations, expected.len() as u64);
    let _ = std::fs::remove_file(path);
}

#[test]
fn short_job_sets_drain_with_overlap_and_no_spare_tail_buffers() {
    // The slow-worker test uses the full pool. This catches omitted or
    // stalled final completions when fewer real jobs than buffers exist.
    let chunk = 64 * 1024;
    for chunks in [1, 2, 3, 8, 9] {
        let data = (0..chunk * chunks - 17)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let path = std::env::temp_dir().join(format!(
            "sunpack_iocp_short_{}_{}.bin",
            std::process::id(),
            chunks
        ));
        std::fs::write(&path, &data).unwrap();
        let mut pieces = Vec::new();
        let result = scan_file(
            &path,
            data.len() as u64,
            chunk,
            4,
            4,
            11,
            |sample, carry, base| {
                let start = base as usize;
                assert_eq!(sample, &data[start..start + sample.len()]);
                ScanBatch {
                    results: (start + carry, sample[carry..].to_vec()),
                    discarded_results: 0,
                }
            },
            |piece| {
                pieces.push(piece);
                Ok(())
            },
        )
        .unwrap();
        pieces.sort_by_key(|(offset, _)| *offset);
        assert_eq!(
            pieces
                .into_iter()
                .flat_map(|(_, data)| data)
                .collect::<Vec<_>>(),
            data
        );
        assert_eq!(result.read_operations, chunks as u64);
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn reversed_completions_are_hashed_in_range_order_without_unbounded_reordering() {
    use xxhash_rust::xxh3::{xxh3_128, Xxh3};
    let bytes: Vec<u8> = (0..600_037).map(|i| (i * 19 + i / 61) as u8).collect();
    let start = (4u64 << 30) + 37;
    let mut ordered = OrderedReads::new(start);
    let mut hash = Xxh3::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let mut slots = Vec::new();
        for _ in 0..2 {
            if offset == bytes.len() { break; }
            let end = (offset + 131_071).min(bytes.len());
            let mut slot = Box::new(IocpSlot::new(end - offset));
            slot.buffer.copy_from_slice(&bytes[offset..end]);
            slot.read_start = start + offset as u64;
            slot.bytes_read = end - offset;
            slots.push(slot);
            offset = end;
        }
        if slots.len() == 2 {
            ordered.completed(slots.pop().unwrap());
            assert!(ordered.next().is_none(), "later completion must not reach hash first");
        }
        ordered.completed(slots.pop().unwrap());
        while let Some(slot) = ordered.next() {
            hash.update(&slot.buffer[..slot.bytes_read]);
        }
    }
    assert_eq!(ordered.next_offset, start + bytes.len() as u64);
    assert!(ordered.ready.iter().all(Option::is_none));
    assert_eq!(hash.digest128(), xxh3_128(&bytes));
}
