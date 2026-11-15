use super::*;

fn record(major: u16, file_id: u128, usn: i64, reason: u32) -> Vec<u8> {
    let (length, file_id_end, usn_offset, reason_offset) = match major {
        2 => (60usize, 16usize, 24usize, 40usize),
        3 => (80usize, 24usize, 40usize, 56usize),
        4 => (64usize, 24usize, 40usize, 48usize),
        _ => unreachable!(),
    };
    let mut record = vec![0u8; length];
    record[0..4].copy_from_slice(&(length as u32).to_le_bytes());
    record[4..6].copy_from_slice(&major.to_le_bytes());
    record[8..file_id_end].copy_from_slice(&file_id.to_le_bytes()[..file_id_end - 8]);
    record[usn_offset..usn_offset + 8].copy_from_slice(&usn.to_le_bytes());
    record[reason_offset..reason_offset + 4].copy_from_slice(&reason.to_le_bytes());
    record
}

#[test]
fn probe_creates_journal_only_for_not_active_error() {
    use std::cell::Cell;
    let queries = Cell::new(0);
    let creates = Cell::new(0);
    let result = query_or_create_journal(
        || {
            queries.set(queries.get() + 1);
            if queries.get() <= 2 {
                Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE))
            } else {
                Ok((42, 100))
            }
        },
        || {
            creates.set(creates.get() + 1);
            Ok(())
        },
    );
    assert_eq!(result.unwrap(), (42, 100));
    assert_eq!((queries.get(), creates.get()), (3, 1));

    assert_eq!(
        query_or_create_journal(|| Ok((7, 50)), || panic!("journal already exists")).unwrap(),
        (7, 50)
    );
    let mut queries = [Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE)), Ok((7, 50))].into_iter();
    assert_eq!(
        query_or_create_journal(|| queries.next().unwrap(), || panic!("another probe created the journal")).unwrap(),
        (7, 50)
    );
    let error = query_or_create_journal(
        || Err(io::Error::from_raw_os_error(5)),
        || panic!("unrelated errors must not create journals"),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));
}

#[test]
fn probe_propagates_create_or_requery_failures() {
    let error = query_or_create_journal(
        || Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE)),
        || Err(io::Error::from_raw_os_error(5)),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));

    let queries = std::cell::Cell::new(0);
    let error = query_or_create_journal(
        || {
            queries.set(queries.get() + 1);
            Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE))
        },
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(queries.get(), 3);
    assert_eq!(error.raw_os_error(), Some(ERROR_JOURNAL_NOT_ACTIVE));
}

#[test]
fn validates_only_volume_guid_device_paths() {
    assert!(validate_volume_guid(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}").is_ok());
    assert!(validate_volume_guid(r"\\.\PhysicalDrive0").is_err());
    assert!(validate_volume_guid(r"C:").is_err());
}

#[test]
fn compares_v2_and_zero_extended_v3_file_ids() {
    let mut expected = [0u8; FILE_ID_BYTES];
    expected[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut record = [0u8; FILE_ID_BYTES];
    record[..8].copy_from_slice(&expected[..8]);
    assert_eq!(file_id_value(&record), file_id_value(&expected[..8]));
    assert_eq!(
        crate::protocol::format_file_id(&record),
        "00000000000000000807060504030201"
    );
}

#[test]
fn parses_v2_v3_and_v4_reason_layouts_with_exclusive_lower_bound() {
    for major in [2u16, 3, 4] {
        let expected = if major == 2 { 0x1234 } else { (7u128 << 64) | 0x1234 };
        let value = record(major, expected, 101, 0x0000_0002);
        assert_eq!(record_change_reason(&value, expected ^ (1u128 << 64), 100, 101).unwrap(), None);
        assert_eq!(
            record_change_reason(&value, expected, 100, 101).unwrap(),
            Some(0x0000_0002)
        );
        assert_eq!(
            record_change_reason(&value, expected, 101, 102).unwrap(),
            None
        );
    }
}

#[test]
fn close_only_reason_is_excluded_from_non_close_aggregate() {
    let mut reasons = ChangeReasons::default();
    reasons.observe(USN_REASON_CLOSE | 0x0000_0001);
    assert_eq!(reasons.all, USN_REASON_CLOSE | 0x0000_0001);
    assert_eq!(reasons.without_close, 0);
    reasons.observe(0x0000_0002);
    assert_eq!(reasons.without_close, 0x0000_0002);
}

#[test]
fn directory_recovery_dispatches_ids_and_requires_reliable_names() {
    // Reason parsing tests never exercise parent dispatch, both rename names,
    // or nameless/unknown records. This one in-memory case covers that gap.
    let mut scratch = Default::default();
    for major in [2, 3] {
        let high = if major == 2 { 0 } else { 7u128 << 64 };
        let parents = HashMap::from([((high | 11).to_le_bytes(), 0), ((high | 22).to_le_bytes(), 1)]);
        let width = if major == 2 { 8 } else { 16 };
        let base = if major == 2 { 60 } else { 76 };
        let length_offset = if major == 2 { 56 } else { 72 };
        for name in ["Old.opaque", "New.001", "新🔐.002"] {
            let mut row = record(major, high | 22, 100, 0x1000);
            row.resize(base, 0);
            row[8 + width..8 + 2 * width].copy_from_slice(&(high | 11).to_le_bytes()[..width]);
            let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            row[length_offset..length_offset + 2]
                .copy_from_slice(&(encoded.len() as u16).to_le_bytes());
            row[length_offset + 2..length_offset + 4]
                .copy_from_slice(&(base as u16).to_le_bytes());
            row.extend_from_slice(&encoded);
            let changes = record_directory_changes(&row, &parents, 100, 101, &mut scratch)
                .unwrap().changes;
            assert_eq!(changes, [Some(&(1, String::new())), Some(&(0, name.to_owned()))]);
            let changes = record_directory_changes(&row, &parents, 99, 100, &mut scratch)
                .unwrap().changes;
            assert_eq!(changes, [None; 2]);
            row[base..base + 2].copy_from_slice(&0xdc00u16.to_le_bytes());
            assert!(record_directory_changes(
                &row,
                &parents,
                100,
                101,
                &mut scratch,
            )
            .is_err());
            row[length_offset..length_offset + 2].copy_from_slice(&1u16.to_le_bytes());
            assert!(record_directory_changes(
                &row,
                &parents,
                100,
                101,
                &mut scratch,
            )
            .is_err());
        }
    }
    let parents = HashMap::from([(11u128.to_le_bytes(), 0)]);
    let mut nameless = record(4, 33, 100, 1);
    nameless[24..40].copy_from_slice(&11u128.to_le_bytes());
    assert!(record_directory_changes(
        &nameless,
        &parents,
        100,
        101,
        &mut scratch,
    )
    .is_err());
    nameless[4..6].copy_from_slice(&5u16.to_le_bytes());
    assert!(record_directory_changes(
        &nameless,
        &parents,
        100,
        101,
        &mut scratch,
    )
    .is_err());
}

#[test]
fn directory_recovery_pages_preserve_names_and_resume_whole_records() {
    // Record-only tests cannot catch lost entries when a reused buffer is
    // drained across journal reads or a response page ends mid-buffer.
    let mut records = Vec::new();
    let mut expected = BTreeSet::from([(1, String::new())]);
    for index in 0..600 {
        let name = format!("{index:04}-{}-新🔐.001", "x".repeat(120));
        expected.insert((0, name.clone()));
        for _ in 0..2 {
            let mut row = record(2, 22, records.len() as i64, 0x1000);
            row[16..24].copy_from_slice(&11u64.to_le_bytes());
            let encoded: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            row[56..58].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
            row[58..60].copy_from_slice(&60u16.to_le_bytes());
            row.extend_from_slice(&encoded);
            let length = row.len() as u32;
            row[..4].copy_from_slice(&length.to_le_bytes());
            records.push(row);
        }
    }
    let end_usn = records.len() as i64;
    let mut cursor = 0;
    let mut actual = BTreeSet::new();
    let mut pages = 0;
    while cursor < end_usn {
        let page = scan_directories_page(
            42,
            &[11u128.to_le_bytes(), 22u128.to_le_bytes()],
            cursor,
            end_usn,
            |start, output| {
                let mut index = start as usize;
                let mut used = 8;
                while let Some(row) = records.get(index) {
                    if used + row.len() > output.len() {
                        break;
                    }
                    output[used..used + row.len()].copy_from_slice(row);
                    used += row.len();
                    index += 1;
                }
                output[..8].copy_from_slice(&(index as i64).to_le_bytes());
                Ok(used)
            },
        )
        .unwrap();
        assert_eq!(page.journal_id, 42);
        assert!(page.next_usn > cursor && page.next_usn <= end_usn);
        assert_eq!(
            page.changes
                .iter()
                .map(|(_, name)| 8 + name.len())
                .sum::<usize>(),
            page.payload_bytes,
        );
        assert!(page.payload_bytes <= MAX_DIRECTORY_RESPONSE_BYTES);
        actual.extend(page.changes);
        cursor = page.next_usn;
        pages += 1;
    }
    assert!(pages > 1);
    assert_eq!(actual, expected);
}

#[test]
fn journal_request_preserves_record_aligned_start_usn() {
    let request = read_usn_journal_request(8_192, 42);
    assert_eq!(request.start_usn, 8_192);
    assert_eq!(request.usn_journal_id, 42);
    // Verify the Windows ABI, including the V1 extension beyond the V0 prefix.
    assert_eq!(std::mem::size_of_val(&request), 48);
    assert_eq!(std::mem::offset_of!(ReadUsnJournalData, min_major_version), 40);
    assert_eq!((request.min_major_version, request.max_major_version), (2, 3));
    assert_eq!((request.timeout, request.bytes_to_wait_for), (0, 0));
}
