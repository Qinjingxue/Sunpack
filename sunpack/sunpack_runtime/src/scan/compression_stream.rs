use crate::formats::zstd::{frame_header_size, FrameHeader, MAGIC as ZSTD_MAGIC, MAX_FRAME_HEADER_SIZE};
use crate::io::reader::{CachedBytes, ManagedReader};
use crc32fast::{hash as crc32, Hasher};
use std::borrow::Cow;
use std::io;

const BUFFER_SIZE: usize = 64 * 1024;
const INITIAL_PROBE_BYTES: usize = 256;
const GZIP_MAGIC: &[u8] = b"\x1f\x8b\x08";
const BZIP2_MAGIC: &[u8] = b"BZh";
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
const XZ_STREAM_HEADER_SIZE: usize = 12;
pub(crate) const MAX_XZ_PREFIX_SIZE: usize = XZ_STREAM_HEADER_SIZE + 1024;

#[derive(Debug)]
pub(crate) enum ValidationError {
    Io(io::Error),
    Invalid(&'static str),
}

impl From<io::Error> for ValidationError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
impl ValidationError {
    fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "os_error",
            Self::Invalid(code) => code,
        }
    }
}

pub(crate) type ValidationResult<T> = Result<T, ValidationError>;

pub(crate) enum StreamReadiness {
    Candidate,
    Truncated,
}

fn invalid<T>(code: &'static str) -> ValidationResult<T> {
    Err(ValidationError::Invalid(code))
}

struct ByteCursor<'a, B = CachedBytes> {
    read: &'a mut dyn FnMut(u64, usize) -> io::Result<B>,
    pos: u64,
    limit: u64,
    buffer_start: u64,
    buffer: B,
}

impl<'a, B: AsRef<[u8]>> ByteCursor<'a, B> {
    fn new(
        read: &'a mut dyn FnMut(u64, usize) -> io::Result<B>,
        pos: u64,
        limit: u64,
        buffer: B,
    ) -> Self {
        Self {
            read,
            pos,
            limit,
            buffer_start: pos,
            buffer,
        }
    }

    fn position(&self) -> u64 {
        self.pos
    }

    fn read_byte(&mut self) -> ValidationResult<u8> {
        let value = self.available()?[0];
        self.pos += 1;
        Ok(value)
    }

    fn available(&mut self) -> ValidationResult<&[u8]> {
        if self.pos >= self.limit {
            return invalid("unexpected_end_of_stream");
        }
        let outside = self.pos < self.buffer_start
            || self.pos >= self.buffer_start + self.buffer.as_ref().len() as u64;
        if outside {
            self.refill()?;
        }
        let start = (self.pos - self.buffer_start) as usize;
        Ok(&self.buffer.as_ref()[start..])
    }

    fn take_buffered_word(&mut self) -> Option<u32> {
        // Only consume bytes already in this cursor window. A short window
        // still uses the byte path and its existing refill and EOF checks.
        let start = self.pos.checked_sub(self.buffer_start)? as usize;
        let word = self.buffer.as_ref().get(start..)?.first_chunk()?;
        self.pos += 4;
        Some(u32::from_be_bytes(*word))
    }

    // Keep refill policy out of the per-byte Huffman/deflate hot path.
    #[inline(never)]
    fn refill(&mut self) -> ValidationResult<()> {
        // Grow after consuming each window so short carrier streams do
        // not jump directly from a tiny probe to a full bulk read.
        let window_size = if self.buffer.as_ref().is_empty() {
            INITIAL_PROBE_BYTES
        } else {
            self.buffer
                .as_ref()
                .len()
                .saturating_mul(4)
                .min(BUFFER_SIZE)
        };
        self.buffer_start = self.pos;
        let count = (window_size as u64).min(self.limit - self.pos) as usize;
        self.buffer = (self.read)(self.pos, count)?;
        if self.buffer.as_ref().is_empty() {
            return invalid("unexpected_end_of_stream");
        }
        Ok(())
    }

    fn check_read_len(&self, count: usize) -> ValidationResult<()> {
        let end = self
            .pos
            .checked_add(count as u64)
            .ok_or(ValidationError::Invalid("stream_offset_overflow"))?;
        if end > self.limit {
            return invalid("unexpected_end_of_stream");
        }
        Ok(())
    }

    fn read_chunks(&mut self, count: usize, mut append: impl FnMut(&[u8])) -> ValidationResult<()> {
        self.check_read_len(count)?;
        let mut remaining = count;
        while remaining > 0 {
            let next = self.available()?;
            let take = remaining.min(next.len());
            append(&next[..take]);
            self.pos += take as u64;
            remaining -= take;
        }
        Ok(())
    }

    fn read_array<const N: usize>(&mut self) -> ValidationResult<[u8; N]> {
        let mut output = [0; N];
        let mut filled = 0;
        self.read_chunks(N, |chunk| {
            output[filled..filled + chunk.len()].copy_from_slice(chunk);
            filled += chunk.len();
        })?;
        Ok(output)
    }

    fn skip_header_string(&mut self, mut crc: Option<&mut Hasher>) -> ValidationResult<()> {
        loop {
            let tail = self.available()?;
            let terminator = memchr::memchr(0, tail);
            let consumed = terminator.map_or(tail.len(), |index| index + 1);
            if let Some(hasher) = crc.as_mut() {
                // The terminating NUL belongs to the RFC 1952 header CRC.
                hasher.update(&tail[..consumed]);
            }
            self.pos += consumed as u64;
            if terminator.is_some() {
                return Ok(());
            }
        }
    }

    fn skip(&mut self, count: u64) -> ValidationResult<()> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or(ValidationError::Invalid("stream_offset_overflow"))?;
        if end > self.limit {
            return invalid("unexpected_end_of_stream");
        }
        self.pos = end;
        Ok(())
    }
}

struct LsbBits<'a, 'b, B = CachedBytes> {
    cursor: &'a mut ByteCursor<'b, B>,
    bits: u64,
    count: u8,
}

impl<'a, 'b, B: AsRef<[u8]>> LsbBits<'a, 'b, B> {
    fn new(cursor: &'a mut ByteCursor<'b, B>) -> Self {
        Self {
            cursor,
            bits: 0,
            count: 0,
        }
    }

    fn read(&mut self, count: u8) -> ValidationResult<u32> {
        while self.count < count {
            self.bits |= u64::from(self.cursor.read_byte()?) << self.count;
            self.count += 8;
        }
        let mask = if count == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << count) - 1
        };
        let value = (self.bits & mask) as u32;
        self.bits >>= count;
        self.count -= count;
        Ok(value)
    }

    fn align_byte(&mut self) {
        // Lookup decoding may have fetched bytes beyond the current block.
        // Drop padding bits, but return every unconsumed whole byte.
        self.cursor.pos -= u64::from(self.count / 8);
        self.bits = 0;
        self.count = 0;
    }

    fn fill_available(&mut self, count: u8) -> ValidationResult<()> {
        while self.count < count && self.cursor.pos < self.cursor.limit {
            self.bits |= u64::from(self.cursor.read_byte()?) << self.count;
            self.count += 8;
        }
        Ok(())
    }
}

struct MsbBits<'a, 'b> {
    cursor: &'a mut ByteCursor<'b>,
    // Unconsumed bits occupy the high end of the word; consumption is one shift.
    bits: u64,
    count: u8,
}

impl<'a, 'b> MsbBits<'a, 'b> {
    fn new(cursor: &'a mut ByteCursor<'b>) -> Self {
        Self {
            cursor,
            bits: 0,
            count: 0,
        }
    }

    fn read(&mut self, count: u8) -> ValidationResult<u32> {
        if count == 0 {
            return Ok(0);
        }
        self.fill_available(count)?;
        if self.count < count {
            return invalid("unexpected_end_of_stream");
        }
        let value = self.peek(count);
        self.consume(count);
        Ok(value)
    }

    fn peek(&self, count: u8) -> u32 {
        (self.bits >> (64 - count)) as u32
    }

    fn consume(&mut self, count: u8) {
        self.bits <<= count;
        self.count -= count;
    }

    fn fill_available(&mut self, count: u8) -> ValidationResult<()> {
        if self.count < count {
            if let Some(word) = self.cursor.take_buffered_word() {
                self.bits |= u64::from(word) << (32 - self.count);
                self.count += 32;
                return Ok(());
            }
        }
        while self.count < count && self.cursor.pos < self.cursor.limit {
            self.bits |= u64::from(self.cursor.read_byte()?) << (56 - self.count);
            self.count += 8;
        }
        Ok(())
    }

    fn align_zero(&mut self) -> ValidationResult<()> {
        let padding = self.count % 8;
        if padding != 0 && self.peek(padding) != 0 {
            return invalid("nonzero_stream_padding");
        }
        self.cursor.pos -= u64::from(self.count / 8);
        self.bits = 0;
        self.count = 0;
        Ok(())
    }
}

const HUFFMAN_LOOKUP_BITS: u8 = 9;
const HUFFMAN_LENGTH_BITS: u8 = 5;
const HUFFMAN_LENGTH_MASK: u16 = (1 << HUFFMAN_LENGTH_BITS) - 1;

#[derive(Clone, Copy)]
enum BitOrder {
    Lsb,
    Msb,
}

#[derive(Clone, Default)]
struct Huffman {
    counts: [u16; 24],
    first_code: [u32; 24],
    first_symbol: [usize; 24],
    symbols: Vec<u16>,
    max_len: usize,
    lookup: Vec<u16>,
    lookup_bits: u8,
}

#[derive(Clone, Copy)]
struct LsbHuffman<'a> {
    counts: &'a [u16; 24],
    first_code: &'a [u32; 24],
    first_symbol: &'a [usize; 24],
    symbols: &'a [u16],
    max_len: usize,
    lookup: &'a [u16],
    lookup_bits: u8,
}

impl Huffman {
    fn new(lengths: &[u8], max_allowed: usize, order: BitOrder) -> ValidationResult<Self> {
        let mut table = Self::default();
        table.rebuild(lengths, max_allowed, order)?;
        Ok(table)
    }

    fn rebuild(
        &mut self,
        lengths: &[u8],
        max_allowed: usize,
        order: BitOrder,
    ) -> ValidationResult<()> {
        debug_assert!(lengths.len() <= 1 << (u16::BITS - u32::from(HUFFMAN_LENGTH_BITS)));
        let mut counts = [0u16; 24];
        let mut max_len = 0usize;
        for &length in lengths {
            let length = usize::from(length);
            if length > max_allowed || length >= counts.len() {
                return invalid("invalid_huffman_code_length");
            }
            if length > 0 {
                counts[length] += 1;
                max_len = max_len.max(length);
            }
        }
        if max_len == 0 {
            return invalid("empty_huffman_tree");
        }
        let mut left = 1i32;
        for &count in counts.iter().take(max_len + 1).skip(1) {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return invalid("oversubscribed_huffman_tree");
            }
        }
        let mut first_code = [0u32; 24];
        let mut first_symbol = [0usize; 24];
        let mut code = 0u32;
        let mut symbol_index = 0usize;
        for length in 1..=max_len {
            code = (code + u32::from(counts[length - 1])) << 1;
            first_code[length] = code;
            first_symbol[length] = symbol_index;
            symbol_index += usize::from(counts[length]);
        }
        // Place each symbol at the next position for its length in one pass.
        self.symbols.clear();
        self.symbols.resize(symbol_index, 0);
        let mut next_symbol = first_symbol;
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let slot = &mut next_symbol[usize::from(length)];
                self.symbols[*slot] = symbol as u16;
                *slot += 1;
            }
        }
        // BZip2's fixed prefix removes a variable shift from each symbol.
        // Each entry stores the full symbol and its code length in 16 bits.
        let lookup_bits = match order {
            BitOrder::Msb => HUFFMAN_LOOKUP_BITS,
            BitOrder::Lsb => HUFFMAN_LOOKUP_BITS.min(max_len as u8),
        };
        self.lookup.clear();
        self.lookup.resize(1usize << lookup_bits, 0);
        for length in 1..=usize::from(lookup_bits) {
            for index in 0..usize::from(counts[length]) {
                let code = first_code[length] + index as u32;
                let symbol = self.symbols[first_symbol[length] + index];
                let entry = (symbol << HUFFMAN_LENGTH_BITS) | length as u16;
                let suffix_bits = usize::from(lookup_bits) - length;
                match order {
                    BitOrder::Msb => {
                        let first = (code as usize) << suffix_bits;
                        self.lookup[first..first + (1 << suffix_bits)].fill(entry);
                    }
                    BitOrder::Lsb => {
                        let first = code.reverse_bits() >> (u32::BITS - length as u32);
                        for slot in self
                            .lookup
                            .iter_mut()
                            .skip(first as usize)
                            .step_by(1 << length)
                        {
                            *slot = entry;
                        }
                    }
                }
            }
        }
        self.counts = counts;
        self.first_code = first_code;
        self.first_symbol = first_symbol;
        self.max_len = max_len;
        self.lookup_bits = lookup_bits;
        Ok(())
    }

    fn lsb(&self) -> LsbHuffman<'_> {
        LsbHuffman {
            counts: &self.counts,
            first_code: &self.first_code,
            first_symbol: &self.first_symbol,
            symbols: &self.symbols,
            max_len: self.max_len,
            lookup: &self.lookup,
            lookup_bits: self.lookup_bits,
        }
    }

    fn decode_lsb(&self, bits: &mut LsbBits<'_, '_, impl AsRef<[u8]>>) -> ValidationResult<u16> {
        self.lsb().decode(bits)
    }

    #[inline(always)]
    fn decode_msb(&self, bits: &mut MsbBits<'_, '_>) -> ValidationResult<u16> {
        const LOOKUP_BITS: u8 = HUFFMAN_LOOKUP_BITS;
        if bits.count < LOOKUP_BITS {
            bits.fill_available(LOOKUP_BITS)?;
            if bits.count < LOOKUP_BITS {
                return self.decode_msb_long(bits, 0, 0);
            }
        }
        let code = bits.peek(LOOKUP_BITS);
        let entry = self.lookup[code as usize];
        if entry != 0 {
            bits.consume((entry & HUFFMAN_LENGTH_MASK) as u8);
            return Ok(entry >> HUFFMAN_LENGTH_BITS);
        }
        // An empty lookup slot rules out every shorter canonical code.
        bits.consume(LOOKUP_BITS);
        self.decode_msb_long(bits, code, usize::from(LOOKUP_BITS))
    }

    #[cold]
    fn decode_msb_long(
        &self,
        bits: &mut MsbBits<'_, '_>,
        mut code: u32,
        matched_bits: usize,
    ) -> ValidationResult<u16> {
        for length in matched_bits + 1..=self.max_len {
            code = (code << 1) | bits.read(1)?;
            let first = self.first_code[length];
            let count = u32::from(self.counts[length]);
            if code >= first && code - first < count {
                return Ok(self.symbols[self.first_symbol[length] + (code - first) as usize]);
            }
        }
        invalid("invalid_huffman_symbol")
    }
}

impl LsbHuffman<'_> {
    fn decode(&self, bits: &mut LsbBits<'_, '_, impl AsRef<[u8]>>) -> ValidationResult<u16> {
        if self.max_len == 0 {
            return invalid("empty_huffman_tree");
        }
        bits.fill_available(self.lookup_bits)?;
        if bits.count >= self.lookup_bits {
            let entry = self.lookup[(bits.bits & ((1u64 << self.lookup_bits) - 1)) as usize];
            if entry != 0 {
                let length = (entry & HUFFMAN_LENGTH_MASK) as u8;
                bits.bits >>= length;
                bits.count -= length;
                return Ok(entry >> HUFFMAN_LENGTH_BITS);
            }
        }
        let mut code = 0u32;
        for length in 1..=self.max_len {
            code = (code << 1) | bits.read(1)?;
            let first = self.first_code[length];
            let count = u32::from(self.counts[length]);
            if code >= first && code - first < count {
                return Ok(self.symbols[self.first_symbol[length] + (code - first) as usize]);
            }
        }
        invalid("invalid_huffman_symbol")
    }
}

// RFC 1951 fixed codes are input-independent protocol constants. Generate
// their lookup entries at compile time and use the same LSB decoder as dynamic
// tables, including its short-code fallback at the physical end of a stream.
const fn fixed_literal_symbols() -> [u16; 288] {
    let mut symbols = [0; 288];
    let mut i = 0;
    while i < symbols.len() {
        symbols[i] = if i < 24 {
            256 + i as u16
        } else if i < 168 {
            (i - 24) as u16
        } else if i < 176 {
            280 + (i - 168) as u16
        } else {
            144 + (i - 176) as u16
        };
        i += 1;
    }
    symbols
}

const fn fixed_lookup<const N: usize>(distance: bool) -> [u16; N] {
    let mut entries = [0; N];
    let mut i = 0;
    while i < N {
        let (length, symbol) = if distance {
            (5, (i as u32).reverse_bits() >> 27)
        } else {
            let code = (i as u32).reverse_bits() >> 23;
            if code >> 2 < 24 {
                (7, 256 + (code >> 2))
            } else if code >> 1 < 192 {
                (8, (code >> 1) - 48)
            } else if code >> 1 < 200 {
                (8, 280 + (code >> 1) - 192)
            } else {
                (9, 144 + code - 400)
            }
        };
        entries[i] = ((symbol as u16) << HUFFMAN_LENGTH_BITS) | length as u16;
        i += 1;
    }
    entries
}

const FIXED_LITERAL_SYMBOLS: [u16; 288] = fixed_literal_symbols();
const FIXED_LITERAL_LOOKUP: [u16; 512] = fixed_lookup::<512>(false);
const FIXED_DISTANCE_LOOKUP: [u16; 32] = fixed_lookup::<32>(true);
const FIXED_LITERAL_TREE: LsbHuffman<'static> = LsbHuffman {
    counts: &[
        0, 0, 0, 0, 0, 0, 0, 24, 152, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    first_code: &[
        0, 0, 0, 0, 0, 0, 0, 0, 48, 400, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    first_symbol: &[
        0, 0, 0, 0, 0, 0, 0, 0, 24, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    symbols: &FIXED_LITERAL_SYMBOLS,
    max_len: 9,
    lookup: &FIXED_LITERAL_LOOKUP,
    lookup_bits: 9,
};
const FIXED_DISTANCE_TREE: LsbHuffman<'static> = LsbHuffman {
    counts: &[
        0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    first_code: &[0; 24],
    first_symbol: &[0; 24],
    symbols: &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ],
    max_len: 5,
    lookup: &FIXED_DISTANCE_LOOKUP,
    lookup_bits: 5,
};

fn dynamic_deflate_trees(
    bits: &mut LsbBits<'_, '_, impl AsRef<[u8]>>,
) -> ValidationResult<(Huffman, Huffman)> {
    let literal_count = bits.read(5)? as usize + 257;
    let distance_count = bits.read(5)? as usize + 1;
    let code_count = bits.read(4)? as usize + 4;
    if literal_count > 286 || distance_count > 32 {
        return invalid("invalid_deflate_dynamic_counts");
    }
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut code_lengths = [0u8; 19];
    for index in 0..code_count {
        code_lengths[ORDER[index]] = bits.read(3)? as u8;
    }
    let code_tree = Huffman::new(&code_lengths, 7, BitOrder::Lsb)?;
    let total = literal_count + distance_count;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        match code_tree.decode_lsb(bits)? {
            value @ 0..=15 => lengths.push(value as u8),
            16 => {
                let previous = *lengths.last().ok_or(ValidationError::Invalid(
                    "deflate_repeat_without_previous_length",
                ))?;
                let repeat = bits.read(2)? as usize + 3;
                if lengths.len() + repeat > total {
                    return invalid("deflate_code_length_repeat_overflow");
                }
                lengths.extend(std::iter::repeat(previous).take(repeat));
            }
            17 => {
                let repeat = bits.read(3)? as usize + 3;
                if lengths.len() + repeat > total {
                    return invalid("deflate_zero_repeat_overflow");
                }
                lengths.extend(std::iter::repeat(0).take(repeat));
            }
            18 => {
                let repeat = bits.read(7)? as usize + 11;
                if lengths.len() + repeat > total {
                    return invalid("deflate_zero_repeat_overflow");
                }
                lengths.extend(std::iter::repeat(0).take(repeat));
            }
            _ => return invalid("invalid_deflate_code_length_symbol"),
        }
    }
    if lengths[256] == 0 {
        return invalid("deflate_end_code_missing");
    }
    Ok((
        Huffman::new(&lengths[..literal_count], 15, BitOrder::Lsb)?,
        // A literal-only block may have no distance codes. Trying to decode
        // a match through the empty tree still fails in the shared decoder.
        if lengths[literal_count..].iter().all(|&length| length == 0) {
            Huffman::default()
        } else {
            Huffman::new(&lengths[literal_count..], 15, BitOrder::Lsb)?
        },
    ))
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const DEFLATE_WINDOW_SIZE: u64 = 32 * 1024;

fn add_decoded_size(size: u64, count: u64) -> ValidationResult<u64> {
    size.checked_add(count)
        .ok_or(ValidationError::Invalid("decoded_size_overflow"))
}

fn parse_deflate(bits: &mut LsbBits<'_, '_, impl AsRef<[u8]>>) -> ValidationResult<u64> {
    let mut decoded_size = 0u64;
    loop {
        let final_block = bits.read(1)? != 0;
        let block_type = bits.read(2)?;
        if block_type == 0 {
            bits.align_byte();
            let length = bits.read(16)? as u16;
            let complement = bits.read(16)? as u16;
            if length != !complement {
                return invalid("deflate_stored_length_mismatch");
            }
            bits.cursor.skip(u64::from(length))?;
            decoded_size = add_decoded_size(decoded_size, u64::from(length))?;
        } else if block_type == 1 || block_type == 2 {
            let dynamic_trees;
            let (literal_tree, distance_tree) = if block_type == 1 {
                (FIXED_LITERAL_TREE, FIXED_DISTANCE_TREE)
            } else {
                dynamic_trees = dynamic_deflate_trees(bits)?;
                (dynamic_trees.0.lsb(), dynamic_trees.1.lsb())
            };
            loop {
                let count = match literal_tree.decode(bits)? {
                    0..=255 => 1,
                    256 => break,
                    symbol @ 257..=285 => {
                        let index = usize::from(symbol - 257);
                        let length = u64::from(LENGTH_BASE[index])
                            + u64::from(bits.read(LENGTH_EXTRA[index])?);
                        let distance_symbol = distance_tree.decode(bits)? as usize;
                        if distance_symbol >= DIST_BASE.len() {
                            return invalid("invalid_deflate_distance_symbol");
                        }
                        let distance = u64::from(DIST_BASE[distance_symbol])
                            + u64::from(bits.read(DIST_EXTRA[distance_symbol])?);
                        if distance > decoded_size.min(DEFLATE_WINDOW_SIZE) {
                            return invalid("deflate_distance_out_of_range");
                        }
                        length
                    }
                    _ => return invalid("invalid_deflate_literal_symbol"),
                };
                decoded_size = add_decoded_size(decoded_size, count)?;
            }
        } else {
            return invalid("reserved_deflate_block_type");
        }
        if final_block {
            bits.align_byte();
            return Ok(decoded_size);
        }
    }
}

pub(crate) fn gzip_fixed_header_flags(fixed: &[u8; 10]) -> ValidationResult<u8> {
    if !fixed.starts_with(GZIP_MAGIC) {
        return invalid("gzip_magic_not_found");
    }
    let flags = fixed[3];
    if flags & 0xe0 != 0 {
        return invalid("gzip_reserved_flags_set");
    }
    Ok(flags)
}

fn gzip_field<T>(result: ValidationResult<T>, field: &'static str) -> ValidationResult<T> {
    result.map_err(|error| match error {
        ValidationError::Invalid(_) => ValidationError::Invalid(field),
        error => error,
    })
}

fn read_gzip_header(input: &mut ByteCursor<'_, impl AsRef<[u8]>>) -> ValidationResult<()> {
    let fixed = gzip_field(input.read_array::<10>(), "short_gzip_header")?;
    let flags = gzip_fixed_header_flags(&fixed)?;
    let has_crc = flags & 0x02 != 0;
    let mut hasher = Hasher::new();
    if has_crc {
        hasher.update(&fixed);
    }
    if flags & 0x04 != 0 {
        let bytes = gzip_field(input.read_array::<2>(), "gzip_extra_length_missing")?;
        if has_crc {
            hasher.update(&bytes);
        }
        let length = u16::from_le_bytes(bytes) as usize;
        let consumed = if has_crc {
            input.read_chunks(length, |bytes| hasher.update(bytes))
        } else {
            input.skip(length as u64)
        };
        gzip_field(consumed, "gzip_extra_out_of_range")?;
    }
    for (flag, error) in [
        (0x08, "gzip_name_unterminated"),
        (0x10, "gzip_comment_unterminated"),
    ] {
        if flags & flag != 0 {
            gzip_field(
                input.skip_header_string(has_crc.then_some(&mut hasher)),
                error,
            )?;
        }
    }
    if has_crc {
        let stored = u16::from_le_bytes(gzip_field(
            input.read_array::<2>(),
            "gzip_header_crc_missing",
        )?);
        if stored != (hasher.finalize() & 0xffff) as u16 {
            return invalid("gzip_header_crc_bad");
        }
    }
    Ok(())
}

pub(crate) fn validate_gzip_identity(
    prefix: &[u8],
    limit: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> ValidationResult<()> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut read = |offset, count| read(offset, count).map(Cow::Owned);
    let mut cursor = ByteCursor::new(&mut read, 0, limit, Cow::Borrowed(prefix));
    read_gzip_header(&mut cursor)?;

    let mut decoder = Decompress::new(false);
    let mut output = [0; 1024];
    loop {
        let next = cursor.available()?;
        let before = decoder.total_in();
        let status = decoder
            .decompress(next, &mut output, FlushDecompress::None)
            .map_err(|_| ValidationError::Invalid("gzip_deflate_invalid"))?;
        let consumed = decoder.total_in() - before;
        cursor.pos += consumed;
        let produced = decoder.total_out() as usize;
        if status == Status::StreamEnd {
            let trailer = cursor.read_array::<8>()?;
            if trailer[..4] != crc32(&output[..produced]).to_le_bytes()
                || trailer[4..] != (produced as u32).to_le_bytes()
            {
                return invalid("gzip_trailer_mismatch");
            }
            return Ok(());
        }
        if produced != 0 {
            return Ok(());
        }
        if consumed == 0 {
            return invalid("gzip_deflate_made_no_progress");
        }
    }
}

pub(crate) fn validate_gzip_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    mut visit: impl FnMut(u64) -> ValidationResult<()>,
) -> ValidationResult<u64> {
    let mut read = |offset, count| reader.read_cached_at(offset, count);
    let mut cursor = ByteCursor::new(&mut read, offset, limit, CachedBytes::default());
    let mut decoded_size = 0u64;
    loop {
        visit(cursor.position())?;
        read_gzip_header(&mut cursor)?;
        let member_size = parse_deflate(&mut LsbBits::new(&mut cursor))?;
        let trailer = cursor.read_array::<8>()?;
        let stored_size = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
        if stored_size != member_size as u32 {
            return invalid("gzip_isize_mismatch");
        }
        decoded_size = add_decoded_size(decoded_size, member_size)?;
        if cursor.position() + 3 > limit {
            break;
        }
        let next = reader.read_cached_at(cursor.position(), 3)?;
        if next.as_slice() != GZIP_MAGIC {
            break;
        }
    }
    Ok(cursor.position())
}

pub(crate) fn bzip2_header_block_limit(header: &[u8; 4]) -> ValidationResult<usize> {
    if !header.starts_with(BZIP2_MAGIC) || !(b'1'..=b'9').contains(&header[3]) {
        return invalid("bzip2_magic_not_found");
    }
    Ok(usize::from(header[3] - b'0') * 100_000)
}

pub(crate) fn bzip2_marker_is_end(marker: u64) -> ValidationResult<bool> {
    match marker {
        0x1772_4538_5090 => Ok(true),
        0x3141_5926_5359 => Ok(false),
        _ => invalid("bzip2_block_marker_invalid"),
    }
}

pub(crate) fn bzip2_prefix_valid(prefix: &[u8; 10]) -> bool {
    read_bzip2_prefix(prefix).is_ok()
}

fn read_bzip2_prefix(prefix: &[u8; 10]) -> ValidationResult<(usize, bool)> {
    let block_limit = bzip2_header_block_limit(prefix[..4].try_into().unwrap())?;
    let marker = prefix[4..].iter().fold(0, |n, b| (n << 8) | u64::from(*b));
    Ok((block_limit, bzip2_marker_is_end(marker)?))
}

// Stream header, marker and CRC (14 bytes), then at most 315 bits through
// the selector count. Detection already has these bytes in its file head.

/// Validate a bounded leading header. The result indicates an empty first stream.
pub(crate) fn validate_bzip2_identity(prefix: &[u8], file_size: u64) -> ValidationResult<bool> {
    let Some(fixed) = prefix.first_chunk::<14>() else {
        return invalid("bzip2_header_invalid");
    };
    let (block_limit, is_end) = read_bzip2_prefix(fixed[..10].try_into().unwrap())?;
    if is_end {
        return if fixed[10..14] == [0; 4] {
            Ok(true)
        } else {
            invalid("bzip2_combined_crc_mismatch")
        };
    }
    let mut position = 14 * 8;
    let (orig_ptr, n_in_use, group_count, selector_count) = read_bzip2_block_header(|count| {
        let end = position + usize::from(count);
        if end > prefix.len() * 8 {
            return invalid("unexpected_end_of_stream");
        }
        let mut value = 0;
        for bit in position..end {
            value = (value << 1) | u32::from((prefix[bit / 8] >> (7 - bit % 8)) & 1);
        }
        position = end;
        Ok(value)
    })?;
    if orig_ptr >= block_limit {
        return invalid("bzip2_orig_ptr_out_of_range");
    }
    // Selectors cost at least one bit each. Each table has a five-bit starting
    // length and at least one bit per symbol (including RUNB/RUNA and EOB).
    // A nonempty block also needs data, EOB, and the eventual stream trailer.
    let minimum_bits = position + selector_count + group_count * (5 + n_in_use + 2) + 2 + 80;
    if file_size < minimum_bits.div_ceil(8) as u64 {
        return invalid("unexpected_end_of_stream");
    }
    Ok(false)
}

fn read_bzip2_block_header(
    mut read: impl FnMut(u8) -> ValidationResult<u32>,
) -> ValidationResult<(usize, usize, usize, usize)> {
    let _randomized = read(1)?;
    let orig_ptr = read(24)? as usize;
    let in_use16 = read(16)?;
    let mut n_in_use = 0usize;
    for group in 0..16 {
        if in_use16 & (1 << (15 - group)) != 0 {
            n_in_use += read(16)?.count_ones() as usize;
        }
    }
    if n_in_use == 0 {
        return invalid("bzip2_empty_symbol_map");
    }
    let group_count = read(3)? as usize;
    let selector_count = read(15)? as usize;
    if !(2..=6).contains(&group_count) || selector_count == 0 {
        return invalid("bzip2_huffman_counts_invalid");
    }
    Ok((orig_ptr, n_in_use, group_count, selector_count))
}

pub(crate) fn validate_bzip2_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    mut visit: impl FnMut(u64) -> ValidationResult<()>,
) -> ValidationResult<u64> {
    let mut read = |offset, count| reader.read_cached_at(offset, count);
    let mut cursor = ByteCursor::new(&mut read, offset, limit, CachedBytes::default());
    let mut selectors = Vec::new();
    let mut tables: [Huffman; 6] = std::array::from_fn(|_| Huffman::default());
    let mut lengths = [0u8; 258];
    loop {
        visit(cursor.position())?;
        let header = cursor.read_array::<4>()?;
        let block_limit = bzip2_header_block_limit(&header)?;
        let mut bits = MsbBits::new(&mut cursor);
        let mut combined_crc = 0u32;
        loop {
            let marker = (u64::from(bits.read(24)?) << 24) | u64::from(bits.read(24)?);
            if bzip2_marker_is_end(marker)? {
                let stored_combined = bits.read(32)?;
                if stored_combined != combined_crc {
                    return invalid("bzip2_combined_crc_mismatch");
                }
                bits.align_zero()?;
                break;
            }
            let block_crc = bits.read(32)?;
            combined_crc = combined_crc.rotate_left(1) ^ block_crc;
            let (orig_ptr, n_in_use, group_count, selector_count) =
                read_bzip2_block_header(|count| bits.read(count))?;
            let alpha_size = n_in_use + 2;
            // bzip2 1.0.8 and 7-Zip consume extra selector records emitted
            // by lbzip2. At most 18,002 can be used by a 900 KB block.
            let retained = selector_count.min(18_002);
            let mut mtf_groups = [0u8, 1, 2, 3, 4, 5];
            selectors.clear();
            selectors.reserve_exact(retained);
            for slot in 0..selector_count {
                let mut index = 0usize;
                while bits.read(1)? != 0 {
                    index += 1;
                    if index >= group_count {
                        return invalid("bzip2_selector_invalid");
                    }
                }
                if slot < retained {
                    let value = mtf_groups[index];
                    mtf_groups.copy_within(..index, 1);
                    mtf_groups[0] = value;
                    selectors.push(value);
                }
            }
            for table in &mut tables[..group_count] {
                let mut current = bits.read(5)? as i32;
                let lengths = &mut lengths[..alpha_size];
                for length in &mut *lengths {
                    while bits.read(1)? != 0 {
                        if bits.read(1)? == 0 {
                            current += 1;
                        } else {
                            current -= 1;
                        }
                        if !(1..=20).contains(&current) {
                            return invalid("bzip2_code_length_invalid");
                        }
                    }
                    *length = current as u8;
                }
                table.rebuild(lengths, 20, BitOrder::Msb)?;
            }

            let eob = (n_in_use + 1) as u16;
            let mut nblock = 0usize;
            let mut weight = 1usize;
            'symbols: {
                // One selector owns up to 50 symbols. A run may continue
                // across selectors, so keep its state outside the group.
                for &selector in &selectors {
                    let table = &tables[usize::from(selector)];
                    for _ in 0..50 {
                        let symbol = table.decode_msb(&mut bits)?;
                        if symbol <= 1 {
                            // Charge each run symbol immediately. Prior symbols
                            // bounded nblock, and weight never exceeds nblock + 1.
                            nblock += weight << symbol;
                            weight <<= 1;
                        } else if symbol == eob {
                            break 'symbols;
                        } else {
                            weight = 1;
                            nblock += 1;
                        }
                        if nblock > block_limit {
                            return invalid("bzip2_block_size_exceeded");
                        }
                    }
                }
                return invalid("bzip2_selector_underflow");
            }
            if nblock == 0 || orig_ptr >= nblock {
                return invalid("bzip2_orig_ptr_out_of_range");
            }
        }
        if cursor.position() + 4 > limit {
            break;
        }
        let next = reader.read_cached_at(cursor.position(), 4)?;
        if next.len() != 4 || !next.starts_with(BZIP2_MAGIC) || !(b'1'..=b'9').contains(&next[3]) {
            break;
        }
    }
    Ok(cursor.position())
}

pub(crate) fn read_vli_slice(data: &[u8], cursor: &mut usize) -> ValidationResult<u64> {
    read_vli(|| {
        let byte = *data
            .get(*cursor)
            .ok_or(ValidationError::Invalid("xz_vli_truncated"))?;
        *cursor += 1;
        Ok(byte)
    })
}

fn read_vli_index(cursor: &mut ByteCursor<'_>, hasher: &mut Hasher) -> ValidationResult<u64> {
    read_vli(|| {
        let byte = cursor.read_byte()?;
        hasher.update(&[byte]);
        Ok(byte)
    })
}

fn read_vli(mut byte: impl FnMut() -> ValidationResult<u8>) -> ValidationResult<u64> {
    let mut value = 0u64;
    for index in 0..9 {
        let byte = byte()?;
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return invalid("xz_vli_noncanonical");
            }
            return Ok(value);
        }
    }
    invalid("xz_vli_overflow")
}

fn xz_check_size(check_id: u8) -> ValidationResult<u64> {
    match check_id {
        0 => Ok(0),
        1 => Ok(4),
        4 => Ok(8),
        10 => Ok(32),
        _ => invalid("xz_check_type_unsupported"),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct XzFooter {
    end: u64,
    flags: [u8; 2],
    index_size: u64,
}

fn read_xz_footer(reader: &ManagedReader, end: u64) -> ValidationResult<XzFooter> {
    let start = end
        .checked_sub(12)
        .ok_or(ValidationError::Invalid("xz_footer_missing"))?;
    let footer = reader.read_cached_at(start, 12)?;
    parse_xz_footer(&footer, end)
}

pub(crate) fn parse_xz_footer(footer: &[u8], end: u64) -> ValidationResult<XzFooter> {
    let footer = xz_footer_fields(footer, end)?;
    xz_check_size(footer.flags[1] & 0x0f)?;
    Ok(footer)
}

pub(crate) fn check_xz_footer(footer: &[u8], end: u64) -> ValidationResult<()> {
    let footer = xz_footer_fields(footer, end)?;
    // The final stream may follow other streams. Its Index must still fit
    // between its minimum possible header position and this footer.
    if footer.index_size < 8 || footer.index_size + 24 > end {
        return invalid("xz_backward_size_out_of_range");
    }
    Ok(())
}

pub(crate) fn xz_has_terminal_footer<B: AsRef<[u8]>>(
    size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<B>,
) -> io::Result<bool> {
    if size < 32 || size % 4 != 0 {
        return Ok(false);
    }
    let mut end = size;
    let mut window = 12;
    while end >= 32 {
        let count = end.min(window) as usize;
        let start = end - count as u64;
        let tail = read(start, count)?;
        let tail = tail.as_ref();
        if tail.len() != count {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let Some(last) = tail.iter().rposition(|&byte| byte != 0) else {
            // Padding has no length field. Only this exceptional path needs
            // larger windows, so the ordinary case reads just the footer.
            end = start;
            window = (window * 4).clamp(INITIAL_PROBE_BYTES as u64, BUFFER_SIZE as u64);
            continue;
        };
        end = start + last as u64 + 1;
        if end < 32 || end % 4 != 0 {
            return Ok(false);
        }
        let before_padding = &tail[..=last];
        if let Some(start) = before_padding.len().checked_sub(12) {
            return Ok(check_xz_footer(&before_padding[start..], end).is_ok());
        }
        let footer = read(end - 12, 12)?;
        if footer.as_ref().len() != 12 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(check_xz_footer(footer.as_ref(), end).is_ok());
    }
    Ok(false)
}

fn xz_footer_fields(footer: &[u8], end: u64) -> ValidationResult<XzFooter> {
    if footer.len() != 12 || &footer[10..12] != b"YZ" {
        return invalid("xz_footer_magic_invalid");
    }
    let flags = [footer[8], footer[9]];
    if flags[0] != 0 || flags[1] & 0xf0 != 0 {
        return invalid("xz_stream_flags_invalid");
    }
    if u32::from_le_bytes(footer[0..4].try_into().unwrap()) != crc32(&footer[4..10]) {
        return invalid("xz_footer_crc_bad");
    }
    Ok(XzFooter {
        end,
        flags,
        index_size: (u64::from(u32::from_le_bytes(footer[4..8].try_into().unwrap())) + 1) * 4,
    })
}

pub(crate) fn resolve_xz_stream_start(
    reader: &ManagedReader,
    minimum_offset: u64,
    end: u64,
) -> ValidationResult<u64> {
    if end < minimum_offset.saturating_add(24) {
        return invalid("xz_header_or_footer_missing");
    }
    read_xz_index_boundary(reader, read_xz_footer(reader, end)?, minimum_offset)
}

fn read_xz_index_boundary(
    reader: &ManagedReader,
    footer: XzFooter,
    minimum_offset: u64,
) -> ValidationResult<u64> {
    let footer_start = footer.end - 12;
    let index_start = footer_start
        .checked_sub(footer.index_size)
        .ok_or(ValidationError::Invalid("xz_backward_size_out_of_range"))?;
    if footer.index_size < 8 || index_start < minimum_offset {
        return invalid("xz_backward_size_out_of_range");
    }
    let index_crc_pos = footer_start - 4;
    let mut read = |offset, count| reader.read_cached_at(offset, count);
    let mut index_cursor = ByteCursor::new(
        &mut read,
        index_start,
        index_crc_pos,
        CachedBytes::default(),
    );
    let mut index_hasher = Hasher::new();
    let indicator = index_cursor.read_byte()?;
    index_hasher.update(&[indicator]);
    if indicator != 0 {
        return invalid("xz_index_indicator_invalid");
    }
    let record_count = read_vli_index(&mut index_cursor, &mut index_hasher)?;
    // Each record needs at least two VLI bytes. This is a physical bound,
    // checked before walking an untrusted count, rather than a record quota.
    if record_count > (index_crc_pos - index_cursor.position()) / 2 {
        return invalid("xz_index_size_mismatch");
    }
    let mut padded_blocks_size = 0u64;
    for _ in 0..record_count {
        let unpadded = read_vli_index(&mut index_cursor, &mut index_hasher)?;
        let _uncompressed = read_vli_index(&mut index_cursor, &mut index_hasher)?;
        if unpadded == 0 {
            return invalid("xz_index_record_invalid");
        }
        let padded = unpadded
            .checked_add((4 - unpadded % 4) % 4)
            .ok_or(ValidationError::Invalid("xz_block_size_overflow"))?;
        padded_blocks_size = padded_blocks_size
            .checked_add(padded)
            .ok_or(ValidationError::Invalid("xz_block_size_overflow"))?;
    }
    if index_crc_pos - index_cursor.position() > 3 {
        return invalid("xz_index_padding_invalid");
    }
    while index_cursor.position() < index_crc_pos {
        let byte = index_cursor.read_byte()?;
        index_hasher.update(&[byte]);
        if byte != 0 {
            return invalid("xz_index_padding_invalid");
        }
    }
    if index_cursor.position() != index_crc_pos {
        return invalid("xz_index_size_mismatch");
    }
    let stored_index_crc = reader.read_cached_at(index_crc_pos, 4)?;
    if stored_index_crc.len() != 4 {
        return invalid("unexpected_end_of_stream");
    }
    if u32::from_le_bytes(stored_index_crc.as_slice().try_into().unwrap())
        != index_hasher.finalize()
    {
        return invalid("xz_index_crc_bad");
    }
    let stream_span = padded_blocks_size
        .checked_add(12)
        .ok_or(ValidationError::Invalid("xz_stream_start_out_of_range"))?;
    let stream_start = index_start
        .checked_sub(stream_span)
        .ok_or(ValidationError::Invalid("xz_stream_start_out_of_range"))?;
    if stream_start < minimum_offset {
        return invalid("xz_stream_start_out_of_range");
    }
    let header = reader.read_cached_at(stream_start, 12)?;
    validate_xz_header(&header)?;
    if header[6..8] != footer.flags {
        return invalid("xz_stream_flags_mismatch");
    }
    Ok(stream_start)
}

pub(crate) fn validate_xz_header(header: &[u8]) -> ValidationResult<()> {
    if header.len() != 12 || !header.starts_with(XZ_MAGIC) {
        return invalid("xz_header_magic_invalid");
    }
    if header[6] != 0 || header[7] & 0xf0 != 0 {
        return invalid("xz_stream_flags_invalid");
    }
    if u32::from_le_bytes(header[8..12].try_into().unwrap()) != crc32(&header[6..8]) {
        return invalid("xz_header_crc_bad");
    }
    Ok(())
}

fn parse_xz_block_header(block_header: &[u8]) -> ValidationResult<(Option<u64>, Option<u64>)> {
    let stored_crc = u32::from_le_bytes(block_header[block_header.len() - 4..].try_into().unwrap());
    if stored_crc != crc32(&block_header[..block_header.len() - 4]) {
        return invalid("xz_block_header_crc_bad");
    }
    let block_flags = block_header[1];
    if block_flags & 0x3c != 0 {
        return invalid("xz_block_flags_invalid");
    }
    let mut field_cursor = 2usize;
    let declared_compressed = if block_flags & 0x40 != 0 {
        Some(read_vli_slice(
            &block_header[..block_header.len() - 4],
            &mut field_cursor,
        )?)
    } else {
        None
    };
    let declared_uncompressed = if block_flags & 0x80 != 0 {
        Some(read_vli_slice(
            &block_header[..block_header.len() - 4],
            &mut field_cursor,
        )?)
    } else {
        None
    };
    for _ in 0..usize::from(block_flags & 0x03) + 1 {
        let _filter_id =
            read_vli_slice(&block_header[..block_header.len() - 4], &mut field_cursor)?;
        let property_size =
            read_vli_slice(&block_header[..block_header.len() - 4], &mut field_cursor)?;
        if property_size > (block_header.len() - 4 - field_cursor) as u64 {
            return invalid("xz_filter_properties_truncated");
        }
        field_cursor += property_size as usize;
    }
    if block_header[field_cursor..block_header.len() - 4]
        .iter()
        .any(|byte| *byte != 0)
    {
        return invalid("xz_block_header_padding_invalid");
    }
    Ok((declared_compressed, declared_uncompressed))
}

fn validate_xz_empty_index(empty: &[u8], flags: &[u8]) -> ValidationResult<()> {
    let footer = xz_footer_fields(&empty[8..], 32)?;
    if empty[..4] != [0; 4]
        || empty[4..8] != crc32(&empty[..4]).to_le_bytes()
        || footer.index_size != 8
        || flags != footer.flags
    {
        return invalid("xz_empty_stream_invalid");
    }
    Ok(())
}

// Returns the exact prefix length still needed, or None once the first
// block header (or the entire empty stream) has been checked.
pub(crate) fn check_xz_prefix(
    prefix: &[u8], packed: Option<u64>, unpacked: Option<u64>,
) -> ValidationResult<Option<usize>> {
    let Some(magic) = prefix.get(..XZ_MAGIC.len()) else { return Ok(Some(XZ_MAGIC.len())); };
    if magic != XZ_MAGIC {
        return invalid("xz_header_magic_invalid");
    }
    if packed.is_some_and(|size| size < 32) {
        return invalid("xz_stream_out_of_range");
    }
    let Some(header) = prefix.get(..XZ_STREAM_HEADER_SIZE) else {
        return Ok(Some(XZ_STREAM_HEADER_SIZE));
    };
    validate_xz_header(header)?;
    let Some(&size) = prefix.get(XZ_STREAM_HEADER_SIZE) else {
        return Ok(Some(XZ_STREAM_HEADER_SIZE + 1));
    };
    if size == 0 {
        let Some(empty) = prefix.get(XZ_STREAM_HEADER_SIZE..32) else { return Ok(Some(32)); };
        validate_xz_empty_index(empty, &header[6..8])?;
        // An empty stream can be followed by another XZ stream.
        return Ok(None);
    }

    let block_end = XZ_STREAM_HEADER_SIZE + (usize::from(size) + 1) * 4;
    // Check length is defined even for IDs without a supported checksum.
    let check = header[7];
    let check_size = if check == 0 { 0 } else { 4u64 << ((check - 1) / 3) };
    let block_overhead = (block_end - XZ_STREAM_HEADER_SIZE) as u64 + check_size;
    // The Stream Header, minimum Index and Stream Footer also occupy space.
    let overhead = block_end as u64 + check_size + 20;
    if packed.is_some_and(|limit| overhead + 4 > limit) {
        return invalid("xz_block_out_of_range");
    }
    let Some(block) = prefix.get(XZ_STREAM_HEADER_SIZE..block_end) else {
        return Ok(Some(block_end));
    };
    let (compressed, uncompressed) = parse_xz_block_header(block)?;
    if compressed.is_some_and(|size| {
        size == 0 || size > i64::MAX as u64 - block_overhead
            || packed.is_some_and(|limit| size.next_multiple_of(4) > limit - overhead)
    }) || uncompressed.zip(unpacked).is_some_and(|(size, limit)| size > limit) {
        return invalid("xz_block_out_of_range");
    }
    Ok(None)
}

pub(crate) fn validate_xz_identity(
    header: &[u8],
    file_size: u64,
    read_header: impl FnOnce(usize) -> io::Result<Vec<u8>>,
) -> ValidationResult<usize> {
    let Some(stream_header) = header.get(..12) else {
        return invalid("xz_header_or_footer_missing");
    };
    validate_xz_header(stream_header)?;
    let check_size = xz_check_size(stream_header[7] & 0x0f)?;
    let Some(&size_byte) = header.get(12) else {
        return invalid("xz_block_header_missing");
    };
    if size_byte == 0 {
        // An empty stream has an eight-byte Index and a matching footer.
        let Some(empty) = header.get(12..32) else {
            return invalid("xz_empty_stream_truncated");
        };
        validate_xz_empty_index(empty, &stream_header[6..8])?;
        return Ok(0);
    }
    let block_size = (usize::from(size_byte) + 1) * 4;
    // At least eight Index bytes and the twelve-byte footer follow the block.
    let overhead = 12 + block_size as u64 + check_size + 20;
    if file_size <= overhead {
        return invalid("xz_block_out_of_range");
    }
    let mut bytes_read = 0;
    let extended;
    let block = if let Some(block) = header.get(12..12 + block_size) {
        block
    } else {
        extended = read_header(block_size)?;
        if extended.len() != block_size {
            return invalid("xz_block_header_truncated");
        }
        bytes_read = block_size;
        &extended
    };
    let (compressed, _) = parse_xz_block_header(block)?;
    if compressed.is_some_and(|size| size == 0 || size > file_size - overhead) {
        return invalid("xz_block_out_of_range");
    }
    Ok(bytes_read)
}

pub(crate) fn validate_zstd_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    visit: impl FnMut(u64) -> ValidationResult<()>,
) -> ValidationResult<u64> {
    let mut read = |offset, count| reader.read_cached_at(offset, count);
    let mut bytes = ByteCursor::new(&mut read, offset, limit, CachedBytes::default());
    walk_zstd_frames(&mut bytes, visit, &mut false)
}

pub(crate) fn zstd_head_extent(
    head: &[u8],
    size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    let mut buffered_end = head.len() as u64;
    let mut sparse = |offset, count: usize| {
        // Dense headers can grow their read window. After a seek past a
        // block payload, start with a small window near the next header.
        let count = if offset == buffered_end { count } else { count.min(INITIAL_PROBE_BYTES) };
        let bytes = read(offset, count)?;
        if bytes.len() != count {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buffered_end = offset + count as u64;
        Ok(Cow::Owned(bytes))
    };
    let mut bytes = ByteCursor::new(&mut sparse, 0, size, Cow::Borrowed(head));
    let mut saw_block = false;
    let extent = walk_zstd_frames(&mut bytes, |_| Ok(()), &mut saw_block);
    saw_block.then(|| match extent {
        Ok(end) if end < size && size - end < 4 => StreamReadiness::Truncated,
        Err(ValidationError::Invalid("unexpected_end_of_stream")) => StreamReadiness::Truncated,
        _ => StreamReadiness::Candidate,
    })
}

fn walk_zstd_frames(
    bytes: &mut ByteCursor<'_, impl AsRef<[u8]>>,
    mut visit: impl FnMut(u64) -> ValidationResult<()>,
    saw_block: &mut bool,
) -> ValidationResult<u64> {
    let mut end = bytes.position();
    let mut has_frame = false;
    while bytes.limit.saturating_sub(end) >= 4 {
        let magic = u32::from_le_bytes(bytes.read_array()?);
        if (0x184d2a50..=0x184d2a5f).contains(&magic) {
            visit(end)?;
            let size = u32::from_le_bytes(bytes.read_array()?);
            bytes.skip(u64::from(size))?;
        } else if magic == ZSTD_MAGIC {
            visit(end)?;
            let descriptor = bytes.read_byte()?;
            if descriptor & 0x18 != 0 {
                return invalid("zstd_reserved_or_unused_bit_set");
            }
            let size = frame_header_size(descriptor);
            let mut header = [0; MAX_FRAME_HEADER_SIZE];
            header[0] = descriptor;
            let mut copied = 1;
            bytes.read_chunks(size - 1, |part| {
                header[copied..copied + part.len()].copy_from_slice(part);
                copied += part.len();
            })?;
            let frame = FrameHeader::parse(&header[..size])
                .ok_or(ValidationError::Invalid("zstd_frame_header_invalid"))?;
            loop {
                let block = frame.block(bytes.read_array()?)
                    .ok_or(ValidationError::Invalid("zstd_block_header_invalid"))?;
                bytes.skip(block.encoded_size)?;
                *saw_block = true;
                if block.last {
                    break;
                }
            }
            if frame.has_checksum {
                bytes.skip(4)?;
            }
            has_frame = true;
        } else {
            break;
        }
        end = bytes.position();
    }
    if !has_frame {
        return invalid("zstd_frame_missing");
    }
    Ok(end)
}

#[cfg(test)]
#[path = "../../tests/unit/scan/compression_stream/tests.rs"]
mod tests;
