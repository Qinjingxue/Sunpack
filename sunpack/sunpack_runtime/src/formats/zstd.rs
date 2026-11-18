pub(crate) const MAGIC: u32 = 0xfd2fb528;
pub(crate) const BLOCK_HEADER_SIZE: usize = 3;
pub(crate) const MAX_FRAME_HEADER_SIZE: usize = 14;

pub(crate) fn frame_header_size(descriptor: u8) -> usize {
    let single_segment = descriptor & 0x20 != 0;
    let dictionary_size = [0, 1, 2, 4][usize::from(descriptor & 3)];
    let content_size_len = match (descriptor >> 6, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (flag, _) => 1 << flag,
    };
    1 + usize::from(!single_segment) + dictionary_size + content_size_len
}

pub(crate) struct FrameHeader {
    pub(crate) has_checksum: bool,
    block_max: u64,
}

impl FrameHeader {
    // The descriptor and fields after magic. The callers distinguish missing
    // bytes from invalid syntax using the declared header size.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let &descriptor = bytes.first()?;
        if descriptor & 0x08 != 0 {
            return None;
        }
        let size = frame_header_size(descriptor);
        let single_segment = descriptor & 0x20 != 0;
        let window_size = if single_segment {
            let field_size = 1 << (descriptor >> 6);
            let field = bytes.get(size - field_size..size)?;
            let mut value = [0; 8];
            value[..field_size].copy_from_slice(field);
            u64::from_le_bytes(value) + if field_size == 2 { 256 } else { 0 }
        } else {
            let window = *bytes.get(1)?;
            let base = 1u64 << (10 + (window >> 3));
            base + (base / 8) * u64::from(window & 7)
        };
        Some(Self {
            has_checksum: descriptor & 4 != 0,
            block_max: window_size.min(128 * 1024),
        })
    }

    pub(crate) fn block(&self, header: [u8; BLOCK_HEADER_SIZE]) -> Option<BlockHeader> {
        let [low, mid, high] = header;
        let word = u32::from_le_bytes([low, mid, high, 0]);
        let last = word & 1 != 0;
        let kind = (word >> 1) & 3;
        let size = u64::from(word >> 3);
        // A compressed block contains at least a literals header and a
        // sequence count. Raw and RLE blocks may be empty.
        if kind == 3 || (kind == 2 && size < 2) || size > self.block_max {
            return None;
        }
        Some(BlockHeader {
            last,
            encoded_size: if kind == 1 { 1 } else { size },
        })
    }
}

pub(crate) struct BlockHeader {
    pub(crate) last: bool,
    pub(crate) encoded_size: u64,
}
