use super::*;

fn one_copy_folder(unpack_size: u8, folder_crc: Option<u32>) -> Vec<u8> {
    let mut bytes = vec![
        SZ_FOLDER,
        1,
        0, // one inline folder
        1,
        0x01,
        0x00, // one Copy coder, one input and output
        SZ_CODERS_UNPACK_SIZE,
        unpack_size,
    ];
    if let Some(crc) = folder_crc {
        bytes.extend([SZ_CRC, 1]);
        bytes.extend(crc.to_le_bytes());
    }
    bytes.push(SZ_END);
    bytes
}

fn number(value: u64) -> Vec<u8> {
    let mut out = vec![0xff];
    out.extend(value.to_le_bytes());
    out
}

// The small graph samples cannot expose whole-archive count quotas or
// count-driven allocation from tiny malformed headers. Keep both in one test.
#[test]
fn archive_counts_follow_header_bytes_while_folder_graphs_stay_bounded() {
    let folders = 4_097;
    let mut raw = vec![SZ_UNPACK_INFO, SZ_FOLDER];
    raw.extend(number(folders));
    raw.push(0);
    raw.extend([1, 1, 0].repeat(folders as usize));
    raw.push(SZ_CODERS_UNPACK_SIZE);
    raw.extend(vec![0; folders as usize]);
    raw.extend([SZ_END, SZ_END]);
    let mut streams = SevenZipStreams::default();
    parse_seven_zip_streams_info(&raw, &mut 0, &mut streams, false).unwrap();
    assert_eq!(streams.folders.len(), folders as usize);

    let mut pack = vec![0];
    pack.extend(number(folders));
    pack.push(SZ_SIZE);
    pack.extend(vec![0; folders as usize]);
    pack.push(SZ_END);
    assert_eq!(
        parse_seven_zip_pack_info(&pack, &mut 0, true)
            .unwrap()
            .sizes
            .len(),
        folders as usize
    );

    let unpack = parse_seven_zip_unpack_info(&one_copy_folder(0, None), &mut 0, false).unwrap();
    let mut substreams = vec![SZ_NUM_UNPACK_STREAM];
    substreams.extend(number(100_001));
    substreams.push(SZ_SIZE);
    substreams.extend(vec![0; 100_000]);
    substreams.push(SZ_END);
    let mut pos = 0;
    parse_seven_zip_substreams_info(&substreams, &mut pos, &unpack).unwrap();
    assert_eq!(pos, substreams.len());
    let mut files = number(100_001);
    files.push(SZ_END);
    assert!(parse_seven_zip_files_info(&files, &mut 0).is_ok());

    let mut impossible = vec![SZ_FOLDER];
    impossible.extend(number(u64::MAX));
    impossible.push(0);
    assert!(parse_seven_zip_unpack_info(&impossible, &mut 0, false).is_err());
    assert!(parse_seven_zip_crc_flags(&[0], &mut 0, usize::MAX).is_err());
    assert_eq!(
        seven_zip_vec::<u64>(usize::MAX).unwrap_err(),
        "7z_analysis_resource_limit"
    );
    assert!(parse_seven_zip_folder(&[65], &mut 0, false).is_err());
    // One coder with 65 inputs used to pass the archive-wide 4096 quota.
    assert!(parse_seven_zip_folder(&[1, 0x11, 0, 65, 1], &mut 0, false).is_err());
}

#[test]
fn parses_folder_graph_and_inherited_single_substream_crc() {
    let expected_crc = 0x4433_2211;
    let mut raw = vec![
        SZ_HEADER, SZ_ARCHIVE_PROPERTIES, 0x80, 0x31, 1, 0x02, SZ_END,
        SZ_ADDITIONAL_STREAMS_INFO, SZ_UNPACK_INFO,
    ];
    raw.extend(one_copy_folder(10, None));
    raw.extend([SZ_END, SZ_MAIN_STREAMS_INFO, SZ_PACK_INFO, 0, 1, SZ_SIZE, 10, SZ_END, SZ_UNPACK_INFO]);
    raw.extend(one_copy_folder(20, Some(expected_crc)));
    // The inherited folder CRC leaves no explicit CRC flags or values.
    raw.extend([SZ_SUB_STREAMS_INFO, SZ_CRC, SZ_END, SZ_END, SZ_END]);
    let mut streams = SevenZipStreams::default();
    parse_seven_zip_header_with_data(&raw, &mut streams, true).unwrap();
    assert_eq!(streams.folders.len(), 1);
    assert_eq!(streams.folders[0].unpack_size(0), 20);
    assert_eq!(streams.folders[0].coders[0].method_id, [0]);
    assert_eq!(streams.folders[0].expected_crc.unwrap(), expected_crc);
    assert_eq!(streams.pack.unwrap().sizes, [10]);
}

#[test]
fn parses_multiple_substream_sizes_and_crcs() {
    let mut raw = vec![SZ_UNPACK_INFO];
    raw.extend(one_copy_folder(20, None));
    raw.extend([
        SZ_SUB_STREAMS_INFO,
        SZ_NUM_UNPACK_STREAM,
        2,
        SZ_SIZE,
        7,
        SZ_CRC,
        0,
        // Only the first of the two streams has a CRC. Bits beyond the
        // two streams are padding even when set.
        0b1011_1111,
    ]);
    raw.extend(0x1111_1111u32.to_le_bytes());
    raw.extend([SZ_END, SZ_END]);
    let mut pos = 0;
    let mut streams = SevenZipStreams::default();
    assert_eq!(parse_seven_zip_streams_info(&raw, &mut pos, &mut streams, false).unwrap(), None);
    assert_eq!(pos, raw.len());
    raw.truncate(raw.len() - 3);
    assert_eq!(
        parse_seven_zip_streams_info(&raw, &mut 0, &mut streams, false),
        Err("substreams_info_crc_truncated"),
    );
}

#[test]
fn preserves_folder_info_when_later_substream_graph_is_invalid() {
    let mut raw = vec![SZ_PACK_INFO, 0, 1, SZ_SIZE, 10, SZ_END, SZ_UNPACK_INFO];
    raw.extend(one_copy_folder(20, None));
    raw.extend([
        SZ_SUB_STREAMS_INFO,
        SZ_NUM_UNPACK_STREAM,
        2,
        SZ_SIZE,
        21,
        SZ_END,
    ]);
    let mut pos = 0;
    let mut streams = SevenZipStreams::default();
    assert_eq!(
        parse_seven_zip_streams_info(&raw, &mut pos, &mut streams, false),
        Err("substreams_info_sizes_exceed_folder_unpack_size")
    );
    assert_eq!(streams.folders.len(), 1);
}
