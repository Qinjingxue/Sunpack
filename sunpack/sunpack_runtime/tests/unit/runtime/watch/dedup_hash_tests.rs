use super::*;

#[test]
fn ordered_ranges_match_xxh3_across_read_ahead_and_files() {
    let root = std::env::temp_dir().join(format!(
        "sunpack-dedup-hash-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let a = root.join("a");
    let b = root.join("b");
    let data: Vec<u8> = (0..1_400_019).map(|i| (i * 73 + i / 251) as u8).collect();
    std::fs::write(&a, &data).unwrap();
    std::fs::write(&b, &data[..70_003]).unwrap();
    let ranges = [
        HashRange {
            path: &a,
            offset: 37,
            len: 1_100_013,
        },
        HashRange {
            path: &b,
            offset: 19,
            len: 65_537,
        },
    ];
    let mut expected = data[37..37 + 1_100_013].to_vec();
    expected.extend_from_slice(&data[19..19 + 65_537]);
    assert_eq!(
        hash_ranges(&ranges).unwrap(),
        xxhash_rust::xxh3::xxh3_128(&expected).to_le_bytes()
    );
    assert!(hash_ranges(&[HashRange {
        path: &b,
        offset: 70_000,
        len: 4
    }])
    .is_err());
    assert_eq!(
        hash_ranges(&[]).unwrap(),
        xxhash_rust::xxh3::xxh3_128(&[]).to_le_bytes()
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ordered_read_drains_on_cancel_error_and_unwind_and_detects_replacement() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = std::env::temp_dir().join(format!(
        "sunpack-dedup-drain-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("source");
    let data = vec![42u8; 2 * 1024 * 1024];
    std::fs::write(&path, &data).unwrap();
    for mode in 0..3 {
        let cancellation = crate::io::cancellation::Cancellation::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cancellation.run(|| {
                crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, |_| match mode {
                    0 => {
                        cancellation.cancel();
                        Ok(())
                    }
                    1 => Err(io::Error::other("injected consumer error")),
                    _ => panic!("injected consumer panic"),
                })
            })
        }));
        match result {
            Ok(result) => assert!(result.is_err()),
            Err(_) => assert_eq!(mode, 2),
        }
        // A leaked overlapped reader would deny this exclusive handle.
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&path)
                .unwrap(),
        );
    }
    let mut truncated = false;
    let short = crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, |_| {
        if !truncated {
            truncated = true;
            // The following read-ahead submission is now beyond EOF, even if
            // both originally outstanding reads completed before truncation.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)?
                .set_len(256 * 1024)?;
        }
        Ok(())
    });
    assert!(
        short.is_err(),
        "a truncated stream must never publish a partial digest"
    );
    std::fs::write(&path, &data).unwrap();
    let mut replaced = false;
    let result = crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, |_| {
        if !replaced {
            replaced = true;
            std::fs::rename(&path, root.join("old"))?;
            std::fs::write(&path, &data)?;
        }
        Ok(())
    });
    assert!(
        result.is_err(),
        "replacement must not publish the old object's digest"
    );
    std::fs::remove_dir_all(root).unwrap();
}
