use super::*;

#[test]
fn pax_size_streams_long_values_and_preserves_numeric_semantics() {
    // A zero-padded record length can place the value just beyond the prefix.
    let record = format!("{:0250} size=7\n", 258).into_bytes();
    let parsed = pax_size(&mut |start, count| {
        Ok(CachedBytes::Owned(record[start as usize..start as usize + count].to_vec()))
    }, 0, record.len() as u64).unwrap();
    assert!(matches!(parsed, Some(PaxSize::Value(7))));
    // Leading zeros are valid beyond the old quota. Only numeric overflow or
    // invalid digits reject a value; each read stays bounded independently.
    for (suffix, expected) in [(b"7".as_slice(), Some(7)), (b"x", None)] {
        let len = 1024 * 1024 + 17;
        let mut read = |start: u64, count: usize| {
            assert!(count <= 4096);
            let mut bytes = vec![b'0'; count];
            if start + count as u64 == len { bytes[count - 1] = suffix[0]; }
            Ok(CachedBytes::Owned(bytes))
        };
        let parsed = pax_size_value(&mut read, 0, len, b"000").unwrap();
        assert_eq!(match parsed { PaxSize::Value(value) => Some(value), _ => None }, expected);
    }
    for value in ["", "+", "-1", "18446744073709551615", "18446744073709551616",
        "-170141183460469231731687303715884105728", "170141183460469231731687303715884105728"] {
        let parsed = pax_size_value(&mut |_, _| unreachable!(), 0, value.len() as u64, value.as_bytes()).unwrap();
        if value.is_empty() { assert!(matches!(parsed, PaxSize::Empty)); }
        else { assert_eq!(match parsed { PaxSize::Value(value) => Some(value), _ => None },
            value.parse::<i128>().ok().and_then(|value| u64::try_from(value.max(0)).ok())); }
    }
}

fn header_with_base256_size(size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..4].copy_from_slice(b"file");
    header[124] = 0x80;
    header[128..136].copy_from_slice(&size.to_be_bytes());
    header[156] = b'0';
    let checksum = format!("{:06o}\0 ", checksum(&header));
    header[148..156].copy_from_slice(checksum.as_bytes());
    header
}

#[test]
fn gnu_names_skip_payload_reads_but_keep_checked_boundaries() {
    // No body allocation is needed even above the former metadata quota.
    // Checking only ordinary members would miss an early metadata return.
    for kind in [b'L', b'K'] {
        let size = 1024 * 1024 + 1;
        let mut header = header_with_base256_size(size);
        header[156] = kind;
        let total = BLOCK + size + padding(size);
        let mut state = TarState::default();
        let mut read = |_, _| unreachable!("GNU names must not read their payload");
        assert_eq!(
            state
                .advance_validated(&header, size, 0, total, &mut read)
                .unwrap(),
            total
        );
        for (size, offset, total) in [
            (size, 0, total - 1),
            (size, u64::MAX - BLOCK + 1, u64::MAX),
            (u64::MAX - BLOCK + 1, 0, u64::MAX),
            (u64::MAX - BLOCK, 0, u64::MAX),
        ] {
            assert_eq!(
                state
                    .advance_validated(&header, size, offset, total, &mut read)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}

#[test]
fn huge_base256_member_size_is_out_of_range_instead_of_wrapping() {
    // offset(0) + 512 + (2^64 - 512) wraps to 0 without saturation, which
    // would re-walk the same header and report a valid archive.
    let header = header_with_base256_size(u64::MAX - 511);
    let error = TarState::default()
        .advance(&header, 0, 3 * BLOCK, &mut |_, _| {
            unreachable!("truncated member must be rejected before reading its data")
        })
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn local_pax_size_masks_global_only_for_the_next_member() {
    let mut state = TarState::default();
    let mut header = [0u8; 512];
    let total = 2 * BLOCK;
    for (kind, body) in [(b'g', b"10 size=x\n".as_slice()), (b'x', b"8 size=\n")] {
        header[156] = kind;
        state
            .advance_validated(&header, body.len() as u64, 0, total, &mut |start, size| {
                let offset = (start - BLOCK) as usize;
                Ok(CachedBytes::Owned(body[offset..offset + size].to_vec()))
            })
            .unwrap();
    }
    header[156] = b'0';
    let read = &mut |_, _| unreachable!();
    assert_eq!(
        state.advance_validated(&header, 1, 0, total, read).unwrap(),
        total
    );
    assert_eq!(
        state
            .advance_validated(&header, 1, 0, total, read)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

// Generate fixed sparse records on demand: ordinary TAR samples never
// cross the old extension quota; no 32 MiB fixture is retained here.
#[test]
fn sparse_extensions_follow_flags_and_physical_boundaries() {
    let count = 65_537;
    let total = (count + 1) * BLOCK;
    let mut header = [0u8; 512];
    header[482] = 1;
    let mut reads = 0;
    let mut read = |start, size| {
        assert_eq!(size, 512);
        reads += 1;
        let mut block = vec![0u8; size];
        block[504] = u8::from(start + BLOCK < total);
        Ok(CachedBytes::Owned(block))
    };
    assert_eq!(
        sparse_span(&header, 0, total, &mut read).unwrap(),
        (count * BLOCK, 0)
    );
    assert_eq!(reads, count);
    assert_eq!(
        sparse_span(&header, 0, BLOCK, &mut |_, _| unreachable!())
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        sparse_span(
            &header,
            u64::MAX - BLOCK,
            u64::MAX,
            &mut |_, _| unreachable!()
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::UnexpectedEof
    );
}
