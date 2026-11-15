#[derive(Clone, Copy)]
pub(super) enum StructuralStreamKind {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl StructuralStreamKind {
    pub(super) fn from_header(header: &[u8]) -> Option<Self> {
        if header.starts_with(b"\x1f\x8b") {
            Some(Self::Gzip)
        } else if header.starts_with(b"BZh") {
            Some(Self::Bzip2)
        } else if header.starts_with(XZ_MAGIC) {
            Some(Self::Xz)
        } else if header.starts_with(ZSTD_MAGIC) {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    pub(super) fn format(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

pub(super) fn compression_prefix_identity(
    kind: StructuralStreamKind,
    prefix: &[u8],
    file_size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> bool {
    match kind {
        StructuralStreamKind::Gzip => validate_gzip_identity(prefix, file_size, read).is_ok(),
        StructuralStreamKind::Bzip2 => validate_bzip2_identity(prefix, file_size).is_ok(),
        StructuralStreamKind::Xz => {
            validate_xz_identity(prefix, file_size, |size| read(12, size)).is_ok()
        }
        StructuralStreamKind::Zstd => zstd_prefix_identity(prefix, file_size),
    }
}

fn zstd_prefix_identity(data: &[u8], file_size: u64) -> bool {
    if data.len() < 8 {
        return false;
    }
    let descriptor = data[4];
    if descriptor & 0x18 != 0 {
        return false;
    }
    let single = descriptor & 0x20 != 0;
    let dict_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let fcs_size = match descriptor >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let block_header_offset = 5 + usize::from(!single) + dict_size + fcs_size;
    if block_header_offset + 3 > data.len() {
        return false;
    }
    let block_header = u32::from(data[block_header_offset])
        | (u32::from(data[block_header_offset + 1]) << 8)
        | (u32::from(data[block_header_offset + 2]) << 16);
    let block_type = (block_header >> 1) & 0x03;
    let block_size = u64::from(block_header >> 3);
    if block_type == 3 || block_size > 128 * 1024 {
        return false;
    }
    let stored_size = if block_type == 1 { 1 } else { block_size };
    block_header_offset as u64 + 3 + stored_size <= file_size
}
