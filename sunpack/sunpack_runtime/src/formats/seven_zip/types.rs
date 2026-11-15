struct SevenZipPackInfoAst {
    pack_pos: u64,
    num_streams: usize,
    sizes: Vec<u64>,
}

#[derive(Clone)]
struct SevenZipCoderAst {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    num_in_streams: u64,
    num_out_streams: u64,
}

struct SevenZipFolderAst {
    coders: Vec<SevenZipCoderAst>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    main_output_stream: u64,
    unpack_sizes: SevenZipUnpackSizes,
    expected_crc: Option<u32>,
}

enum SevenZipUnpackSizes {
    Main(u64),
    All(Vec<u64>),
}

impl SevenZipFolderAst {
    fn unpack_size(&self, output: u64) -> u64 {
        match &self.unpack_sizes {
            SevenZipUnpackSizes::Main(size) => *size,
            SevenZipUnpackSizes::All(sizes) => sizes[output as usize],
        }
    }
}

#[derive(Default)]
struct SevenZipStreams {
    pack: Option<SevenZipPackInfoAst>,
    folders: Vec<SevenZipFolderAst>,
}
