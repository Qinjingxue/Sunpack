use super::*;

// New physical-format failures are independent of orchestration tests.
// Removing this loses header/length/CRC and byte-level tear coverage;
// all fixtures stay in memory and cost no fsync or process startup.
#[test]
fn frames_reject_corruption_and_recover_only_incomplete_tails() {
    let mut bytes = file_header(Kind::TaskWal).to_vec();
    let mut previous_header = file_header(Kind::TaskWal);
    previous_header[4..6].copy_from_slice(&1u16.to_le_bytes());
    assert!(Reader::new(Cursor::new(previous_header), Kind::TaskWal).is_err());
    append_frame(&mut bytes, &mut Vec::new(), 7, |out| {
        rmp_serde::encode::write(out, &vec!["雪", "payload"]).map_err(invalid)
    })
    .unwrap();
    let mut reader = Reader::new(Cursor::new(&bytes), Kind::TaskWal).unwrap();
    assert_eq!(reader.next().unwrap(), Some(7));
    assert_eq!(
        decode::<Vec<String>>(&reader.payload).unwrap(),
        ["雪", "payload"]
    );
    assert!(reader.next().unwrap().is_none());
    assert!(!reader.torn);
    for offset in [0, 4, 6, 8, 20, 28, bytes.len() - 1] {
        let mut damaged = bytes.clone();
        damaged[offset] ^= 1;
        let result =
            Reader::new(Cursor::new(damaged), Kind::TaskWal).and_then(|mut r| r.next());
        assert!(result.is_err(), "undetected corruption at {offset}");
    }
    assert!(Reader::new(Cursor::new(&bytes), Kind::CatalogWal).is_err());
    for end in 0..bytes.len() {
        let mut reader = Reader::new(Cursor::new(&bytes[..end]), Kind::TaskWal).unwrap();
        assert!(reader.next().unwrap().is_none());
        assert!(reader.torn || end == 16);
        assert_eq!(reader.valid_end, if end < 16 { 0 } else { 16 });
    }
    let mut oversized = bytes.clone();
    oversized[16..20].copy_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
    assert!(Reader::new(Cursor::new(oversized), Kind::TaskWal)
        .unwrap()
        .next()
        .is_err());
}

// Existing envelope tests use single-frame transactions. This covers
// spilled, fragmented replay followed by small records, plus transaction
// atomicity and payload release on EOF, a torn tail or corruption.
#[test]
fn fragmented_replay_releases_consumed_payload_and_commits_only_complete_transactions() {
    let mut bytes = file_header(Kind::TaskWal).to_vec();
    let mut buffer = Vec::new();
    append_frame(&mut bytes, &mut buffer, 1, |out| out.write_all(b"first")).unwrap();
    let first_end = bytes.len();
    let large = vec![0x5a; crate::io::scratch::MEMORY_BYTES + 17];
    append_frame(&mut bytes, &mut buffer, 2, |out| out.write_all(&large)).unwrap();
    let large_end = bytes.len();
    append_frame(&mut bytes, &mut buffer, 3, |out| out.write_all(b"last")).unwrap();

    let mut reader = Reader::new(Cursor::new(&bytes), Kind::TaskWal).unwrap();
    assert_eq!(reader.next().unwrap(), Some(1));
    assert_eq!(&*reader.payload, b"first");
    assert_eq!(reader.next().unwrap(), Some(2));
    assert_eq!(&*reader.payload, large.as_slice());
    assert_eq!(reader.next().unwrap(), Some(3));
    assert_eq!(&*reader.payload, b"last");
    assert_eq!(reader.next().unwrap(), None);
    assert!(reader.payload.is_empty());
    assert!(!reader.torn);
    assert_eq!(reader.valid_end, bytes.len() as u64);

    let mut torn = Reader::new(Cursor::new(&bytes[..large_end - 1]), Kind::TaskWal).unwrap();
    assert_eq!(torn.next().unwrap(), Some(1));
    assert_eq!(torn.next().unwrap(), None);
    assert!(torn.torn);
    assert!(torn.payload.is_empty());
    assert_eq!(torn.valid_end, first_end as u64);

    bytes[large_end - 1] ^= 1;
    let mut corrupt = Reader::new(Cursor::new(&bytes), Kind::TaskWal).unwrap();
    assert_eq!(corrupt.next().unwrap(), Some(1));
    assert!(corrupt.next().is_err());
    assert!(corrupt.payload.is_empty());
    assert_eq!(corrupt.valid_end, first_end as u64);
}

// No existing test checks checksum coverage of snapshot sequence metadata,
// trailing bytes and wrong file type together. Removing it loses that
// independent binary envelope coverage at negligible in-memory cost.
#[test]
fn snapshots_stream_and_validate_the_entire_envelope() {
    type Payload = (Vec<String>, serde_json::Value);
    let value: Payload = (
        vec!["雪".repeat(BUFFER_BYTES)],
        serde_json::json!({"values": [true, null, 3.25]}),
    );
    let mut file = Cursor::new(Vec::new());
    let len = write_snapshot(&mut file, Kind::TaskSnapshot, 19, &value).unwrap();
    assert_eq!(len, file.get_ref().len() as u64);
    let (seq, restored): (_, Payload) =
        read_snapshot(file.clone(), Kind::TaskSnapshot).unwrap();
    assert_eq!(seq, 19);
    assert_eq!(restored, value);
    assert!(read_snapshot::<_, Payload>(file.clone(), Kind::CatalogSnapshot).is_err());
    for offset in [0, 4, 6, 8, 16, 24, 32, 36, 40, len as usize - 1] {
        let mut damaged = file.clone();
        damaged.get_mut()[offset] ^= 1;
        assert!(read_snapshot::<_, Payload>(damaged, Kind::TaskSnapshot).is_err());
    }
    for end in [0, 15, 39, len as usize - 1] {
        let mut damaged = file.clone();
        damaged.get_mut().truncate(end);
        assert!(read_snapshot::<_, Payload>(damaged, Kind::TaskSnapshot).is_err());
    }
    file.get_mut().push(0);
    assert!(read_snapshot::<_, Payload>(file, Kind::TaskSnapshot).is_err());
}
