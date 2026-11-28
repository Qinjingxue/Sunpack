use super::*;
use crate::io::reader::capture_file_generation;

fn check_generation(
    expected: &PhysicalFileGeneration,
) -> impl FnOnce(&PhysicalFileGeneration) -> io::Result<()> + '_ {
    |opened| {
        if opened.matches_input(expected) {
            Ok(())
        } else {
            Err(io::Error::other("file changed before streaming range"))
        }
    }
}

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
    let a_generation = capture_file_generation(&a).unwrap();
    let b_generation = capture_file_generation(&b).unwrap();
    let mut hash = StreamHash::new();
    hash.read(&a, 37, 1_100_013, false, check_generation(&a_generation)).unwrap();
    hash.read(&b, 19, 65_537, false, check_generation(&b_generation)).unwrap();
    let mut expected = data[37..37 + 1_100_013].to_vec();
    expected.extend_from_slice(&data[19..19 + 65_537]);
    assert_eq!(
        hash.finish(),
        xxhash_rust::xxh3::xxh3_128(&expected).to_le_bytes()
    );
    let mut hash = StreamHash::new();
    hash.read(&a, 37, 1_100_013, true, check_generation(&a_generation)).unwrap();
    hash.read(&b, 19, 65_537, false, check_generation(&b_generation)).unwrap();
    expected[..1_100_013].reverse();
    assert_eq!(hash.finish(), xxhash_rust::xxh3::xxh3_128(&expected).to_le_bytes());
    assert!(StreamHash::new().read(&b, 70_000, 4, false, check_generation(&b_generation)).is_err());
    assert_eq!(
        StreamHash::new().finish(),
        xxhash_rust::xxh3::xxh3_128(&[]).to_le_bytes()
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ordered_read_drains_on_cancel_error_and_unwind_and_checks_generation() {
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
    let generation = capture_file_generation(&path).unwrap();
    for mode in 0..3 {
        let cancellation = crate::io::cancellation::Cancellation::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cancellation.run(|| {
                crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, false, check_generation(&generation), |_| match mode {
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
    let short = crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, false, check_generation(&generation), |_| {
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
    std::fs::rename(&path, root.join("old")).unwrap();
    std::fs::write(&path, &data).unwrap();
    let result = crate::io::iocp::read_range_ordered(&path, 0, data.len() as u64, false, check_generation(&generation), |_| {
        panic!("the read must check the generation before consuming bytes")
    });
    assert!(
        result.is_err(),
        "a replacement must not be read as the originally observed file"
    );
    std::fs::remove_dir_all(root).unwrap();
}
