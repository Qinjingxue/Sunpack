struct SevenZipHeader {
    archive_end: usize,
    next_header_start: usize,
    next_header_nid: u8,
}
#[derive(Clone, Copy)]
struct SevenZipVintSpan {
    value: u64,
}
#[derive(Clone, Copy)]
struct SevenZipCrcSpan {
    value: u32,
}

struct SevenZipPackInfoAst {
    pack_pos: SevenZipVintSpan,
    num_streams: usize,
    sizes: Vec<SevenZipVintSpan>,
}

#[derive(Clone)]
struct SevenZipCoderAst {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    num_in_streams: u64,
    num_out_streams: u64,
}

#[derive(Clone)]
struct SevenZipFolderAst {
    coders: Vec<SevenZipCoderAst>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    main_output_stream: u64,
    unpack_size: u64,
    unpack_sizes: Vec<SevenZipVintSpan>,
    expected_crc: Option<SevenZipCrcSpan>,
}

struct SevenZipUnpackInfoAst {
    folders: Vec<SevenZipFolderAst>,
}

#[cfg_attr(not(test), allow(dead_code))]
struct SevenZipSubStreamsInfoAst {
    num_unpack_streams: Vec<usize>,
    unpack_size_values: Vec<u64>,
    crc_values: Vec<Option<SevenZipCrcSpan>>,
}

// These detailed stream fields are consumed by parser unit tests; production
// encryption detection only reads `unpack_info` from the surrounding AST.
#[cfg_attr(not(test), allow(dead_code))]
struct SevenZipStreamsInfoAst {
    pack_info: Option<SevenZipPackInfoAst>,
    unpack_info: Option<SevenZipUnpackInfoAst>,
    substreams_info: Option<SevenZipSubStreamsInfoAst>,
    diagnostics: Vec<String>,
}

struct SevenZipHeaderAst {
    unpack_info: Option<SevenZipUnpackInfoAst>,
    diagnostics: Vec<String>,
}
