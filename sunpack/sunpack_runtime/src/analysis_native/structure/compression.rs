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

const IDENTITY_PROBE_MAX_BYTES: u64 = 64 * 1024;

const GZIP_IDENTITY_PAYLOAD_BYTES: usize = 1024;

fn validate_gzip_identity_payload(input: &[u8]) -> bool {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut decoder = Decompress::new(false);
    let mut output = [0; GZIP_IDENTITY_PAYLOAD_BYTES];
    let Ok(status) = decoder.decompress(input, &mut output, FlushDecompress::None) else {
        return false;
    };
    let produced = decoder.total_out() as usize;
    if status == Status::StreamEnd {
        let tail = decoder.total_in() as usize;
        return input[tail..].first_chunk::<8>().is_some_and(|trailer| {
            trailer[..4] == crc32(&output[..produced]).to_le_bytes()
                && trailer[4..] == (produced as u32).to_le_bytes()
        });
    }
    produced != 0
}

pub(super) fn compression_prefix_identity(
    kind: StructuralStreamKind,
    prefix: &[u8],
    file_size: u64,
    read: impl Fn(u64, usize) -> io::Result<Vec<u8>>,
) -> bool {
    match kind {
        StructuralStreamKind::Gzip => {
            let len = file_size.min(IDENTITY_PROBE_MAX_BYTES) as usize;
            let expanded;
            let (payload_start, data) = match gzip_payload_offset_from_slice(prefix, 0) {
                Ok(offset) => (offset, prefix),
                Err(_) if len > prefix.len() && prefix.get(3).is_some_and(|flags| flags & 0x1e != 0) => {
                    let Ok(data) = read(0, len) else { return false; };
                    expanded = data;
                    let Ok(offset) = gzip_payload_offset_from_slice(&expanded, 0) else { return false; };
                    (offset, expanded.as_slice())
                }
                Err(_) => return false,
            };
            let wanted = file_size.saturating_sub(payload_start)
                .min((GZIP_IDENTITY_PAYLOAD_BYTES + 8) as u64) as usize;
            let available = &data[payload_start as usize..];
            if available.len() >= wanted {
                validate_gzip_identity_payload(&available[..wanted])
            } else {
                read(payload_start, wanted).is_ok_and(|bytes| validate_gzip_identity_payload(&bytes))
            }
        }
        StructuralStreamKind::Bzip2 => validate_bzip2_identity(prefix, file_size).is_ok(),
        StructuralStreamKind::Xz => validate_xz_identity(prefix, file_size, |size| read(12, size)).is_ok(),
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
