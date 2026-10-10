use crate::io::reader::{CachedBytes, ManagedReader};
use crc32fast::{hash as crc32, Hasher};
use std::io;

const BUFFER_SIZE: usize = 64 * 1024;
const INITIAL_PROBE_BYTES: usize = 256;
const MAX_RECORDS: usize = 1_000_000;
const GZIP_MAGIC: &[u8] = b"\x1f\x8b\x08";
const BZIP2_MAGIC: &[u8] = b"BZh";
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
const ZSTD_MAGIC: u32 = 0xfd2fb528;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegrityStatus {
    Verified,
    Failed,
    Deferred,
    NotPresent,
}

impl IntegrityStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Deferred => "deferred",
            Self::NotPresent => "not_present",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StructureValidation {
    pub(crate) end_offset: u64,
    pub(crate) stream_count: usize,
    pub(crate) block_count: usize,
    pub(crate) decoded_size: Option<u64>,
    pub(crate) integrity: IntegrityStatus,
    pub(crate) checksum_present: bool,
}

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

impl ValidationError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "os_error",
            Self::Invalid(code) => code,
        }
    }
}

type ValidationResult<T> = Result<T, ValidationError>;

fn invalid<T>(code: &'static str) -> ValidationResult<T> {
    Err(ValidationError::Invalid(code))
}

struct ByteCursor<'a> {
    reader: &'a ManagedReader,
    pos: u64,
    limit: u64,
    buffer_start: u64,
    buffer: CachedBytes,
}

impl<'a> ByteCursor<'a> {
    fn new(reader: &'a ManagedReader, pos: u64, limit: u64) -> Self {
        Self {
            reader,
            pos,
            limit,
            buffer_start: u64::MAX,
            buffer: CachedBytes::default(),
        }
    }

    fn position(&self) -> u64 {
        self.pos
    }

    fn read_byte(&mut self) -> ValidationResult<u8> {
        if self.pos >= self.limit {
            return invalid("unexpected_end_of_stream");
        }
        let outside = self.buffer_start == u64::MAX
            || self.pos < self.buffer_start
            || self.pos >= self.buffer_start + self.buffer.len() as u64;
        if outside {
            // Most carrier candidates end inside this first small window.
            // Grow only after consuming it; long streams retain bulk reads.
            let window_size = if self.buffer_start == u64::MAX {
                INITIAL_PROBE_BYTES
            } else {
                BUFFER_SIZE
            };
            self.buffer_start = self.pos;
            let count = window_size.min((self.limit - self.pos) as usize);
            self.buffer = self.reader.read_cached_at(self.pos, count)?;
            if self.buffer.is_empty() {
                return invalid("unexpected_end_of_stream");
            }
        }
        let value = self.buffer[(self.pos - self.buffer_start) as usize];
        self.pos += 1;
        Ok(value)
    }

    fn read_exact(&mut self, count: usize) -> ValidationResult<Vec<u8>> {
        let end = self
            .pos
            .checked_add(count as u64)
            .ok_or(ValidationError::Invalid("stream_offset_overflow"))?;
        if end > self.limit {
            return invalid("unexpected_end_of_stream");
        }
        let mut output = Vec::with_capacity(count);
        while output.len() < count {
            // Reuse read_byte's refill/EOF handling, then consume the rest of
            // this window as a slice instead of checking every stored byte.
            output.push(self.read_byte()?);
            let start = (self.pos - self.buffer_start) as usize;
            let available = (count - output.len()).min(self.buffer.len() - start);
            output.extend_from_slice(&self.buffer[start..start + available]);
            self.pos += available as u64;
        }
        Ok(output)
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

struct LsbBits<'a, 'b> {
    cursor: &'a mut ByteCursor<'b>,
    bits: u64,
    count: u8,
}

impl<'a, 'b> LsbBits<'a, 'b> {
    fn new(cursor: &'a mut ByteCursor<'b>) -> Self {
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
        self.fill_available(count)?;
        if self.count < count {
            return invalid("unexpected_end_of_stream");
        }
        self.count -= count;
        let value = (self.bits >> self.count) as u32;
        self.bits &= (1u64 << self.count) - 1;
        Ok(value)
    }

    fn fill_available(&mut self, count: u8) -> ValidationResult<()> {
        while self.count < count && self.cursor.pos < self.cursor.limit {
            self.bits = (self.bits << 8) | u64::from(self.cursor.read_byte()?);
            self.count += 8;
        }
        Ok(())
    }

    fn align_zero(&mut self) -> ValidationResult<()> {
        let padding = self.count % 8;
        if self.bits >> (self.count - padding) != 0 {
            return invalid("nonzero_stream_padding");
        }
        self.cursor.pos -= u64::from(self.count / 8);
        self.bits = 0;
        self.count = 0;
        Ok(())
    }
}

const HUFFMAN_LOOKUP_BITS: u8 = 9;

#[derive(Clone, Copy)]
enum BitOrder {
    Lsb,
    Msb,
}

#[derive(Clone)]
struct Huffman {
    counts: [u16; 24],
    first_code: [u32; 24],
    first_symbol: [usize; 24],
    symbols: Vec<u16>,
    max_len: usize,
    lookup: Box<[u32]>,
    lookup_bits: u8,
}

#[derive(Clone, Copy)]
struct LsbHuffman<'a> {
    counts: &'a [u16; 24],
    first_code: &'a [u32; 24],
    first_symbol: &'a [usize; 24],
    symbols: &'a [u16],
    max_len: usize,
    lookup: &'a [u32],
    lookup_bits: u8,
}

impl Huffman {
    fn new(lengths: &[u8], max_allowed: usize, order: BitOrder) -> ValidationResult<Self> {
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
        let mut symbols = Vec::with_capacity(symbol_index);
        for length in 1..=max_len {
            for (symbol, &candidate) in lengths.iter().enumerate() {
                if usize::from(candidate) == length {
                    symbols.push(symbol as u16);
                }
            }
        }
        // Bounded, block-local decode table; no retained input or shared cache.
        let lookup_bits = HUFFMAN_LOOKUP_BITS.min(max_len as u8);
        let mut lookup = vec![0u32; 1usize << lookup_bits].into_boxed_slice();
        for length in 1..=usize::from(lookup_bits) {
            for index in 0..usize::from(counts[length]) {
                let code = first_code[length] + index as u32;
                let symbol = symbols[first_symbol[length] + index];
                let entry = ((length as u32) << 16) | u32::from(symbol);
                let suffix_bits = usize::from(lookup_bits) - length;
                for suffix in 0..1usize << suffix_bits {
                    let canonical = ((code as usize) << suffix_bits) | suffix;
                    let slot = match order {
                        BitOrder::Msb => canonical,
                        BitOrder::Lsb => {
                            canonical.reverse_bits() >> (usize::BITS - u32::from(lookup_bits))
                        }
                    };
                    lookup[slot] = entry;
                }
            }
        }
        Ok(Self {
            counts,
            first_code,
            first_symbol,
            symbols,
            max_len,
            lookup,
            lookup_bits,
        })
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

    fn decode_lsb(&self, bits: &mut LsbBits<'_, '_>) -> ValidationResult<u16> {
        self.lsb().decode(bits)
    }

    fn decode_msb(&self, bits: &mut MsbBits<'_, '_>) -> ValidationResult<u16> {
        bits.fill_available(self.lookup_bits)?;
        if bits.count >= self.lookup_bits {
            let entry = self.lookup[(bits.bits >> (bits.count - self.lookup_bits)) as usize];
            if entry != 0 {
                bits.count -= (entry >> 16) as u8;
                bits.bits &= (1u64 << bits.count) - 1;
                return Ok(entry as u16);
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

impl LsbHuffman<'_> {
    fn decode(&self, bits: &mut LsbBits<'_, '_>) -> ValidationResult<u16> {
        bits.fill_available(self.lookup_bits)?;
        if bits.count >= self.lookup_bits {
            let entry = self.lookup[(bits.bits & ((1u64 << self.lookup_bits) - 1)) as usize];
            if entry != 0 {
                let length = (entry >> 16) as u8;
                bits.bits >>= length;
                bits.count -= length;
                return Ok(entry as u16);
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

const fn fixed_lookup<const N: usize>(distance: bool) -> [u32; N] {
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
        entries[i] = (length << 16) | symbol;
        i += 1;
    }
    entries
}

const FIXED_LITERAL_SYMBOLS: [u16; 288] = fixed_literal_symbols();
const FIXED_LITERAL_LOOKUP: [u32; 512] = fixed_lookup::<512>(false);
const FIXED_DISTANCE_LOOKUP: [u32; 32] = fixed_lookup::<32>(true);
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

fn dynamic_deflate_trees(bits: &mut LsbBits<'_, '_>) -> ValidationResult<(Huffman, Huffman)> {
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
        Huffman::new(&lengths[literal_count..], 15, BitOrder::Lsb)?,
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

const DEFLATE_WINDOW_SIZE: usize = 32 * 1024;

struct DeflateOutput {
    decoded_size: u64,
    verify_limit: Option<u64>,
    integrity_complete: bool,
    hasher: Hasher,
    pending: Vec<u8>,
    window: Vec<u8>,
    window_pos: usize,
}

impl DeflateOutput {
    fn counting() -> Self {
        Self {
            decoded_size: 0,
            verify_limit: None,
            integrity_complete: false,
            hasher: Hasher::new(),
            pending: Vec::new(),
            window: Vec::new(),
            window_pos: 0,
        }
    }

    fn verifying(limit: u64) -> Self {
        Self {
            decoded_size: 0,
            verify_limit: Some(limit),
            integrity_complete: true,
            hasher: Hasher::new(),
            pending: Vec::with_capacity(BUFFER_SIZE),
            window: vec![0; DEFLATE_WINDOW_SIZE],
            window_pos: 0,
        }
    }

    fn is_verifying(&self) -> bool {
        self.verify_limit.is_some() && self.integrity_complete
    }

    fn disable_integrity(&mut self) {
        self.integrity_complete = false;
        self.pending.clear();
        self.window.clear();
        self.window_pos = 0;
    }

    fn add_count(&mut self, count: u64) -> ValidationResult<()> {
        self.decoded_size = self
            .decoded_size
            .checked_add(count)
            .ok_or(ValidationError::Invalid("decoded_size_overflow"))?;
        Ok(())
    }

    fn flush_pending(&mut self) {
        if !self.pending.is_empty() {
            self.hasher.update(&self.pending);
            self.pending.clear();
        }
    }

    fn write_byte(&mut self, byte: u8) -> ValidationResult<()> {
        if self.is_verifying() {
            let limit = self.verify_limit.unwrap();
            if self.decoded_size >= limit {
                self.disable_integrity();
                return self.add_count(1);
            }
            self.window[self.window_pos] = byte;
            self.window_pos = (self.window_pos + 1) % DEFLATE_WINDOW_SIZE;
            self.pending.push(byte);
            if self.pending.len() == BUFFER_SIZE {
                self.flush_pending();
            }
        }
        self.add_count(1)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> ValidationResult<()> {
        if !self.is_verifying() {
            return self.add_count(bytes.len() as u64);
        }
        if bytes.len() as u64 > self.verify_limit.unwrap().saturating_sub(self.decoded_size) {
            self.disable_integrity();
            return self.add_count(bytes.len() as u64);
        }
        let mut next = 0;
        while next < bytes.len() {
            let count = (bytes.len() - next)
                .min(DEFLATE_WINDOW_SIZE - self.window_pos)
                .min(BUFFER_SIZE - self.pending.len());
            let slice = &bytes[next..next + count];
            self.window[self.window_pos..self.window_pos + count].copy_from_slice(slice);
            self.window_pos = (self.window_pos + count) % DEFLATE_WINDOW_SIZE;
            self.pending.extend_from_slice(slice);
            next += count;
            if self.pending.len() == BUFFER_SIZE {
                self.flush_pending();
            }
        }
        self.add_count(bytes.len() as u64)
    }

    fn repeat(&mut self, distance: u64, length: u64) -> ValidationResult<()> {
        if distance == 0 || distance > self.decoded_size.min(DEFLATE_WINDOW_SIZE as u64) {
            return invalid("deflate_distance_out_of_range");
        }
        if !self.is_verifying() {
            return self.add_count(length);
        }
        if length > self.verify_limit.unwrap().saturating_sub(self.decoded_size) {
            self.disable_integrity();
            return self.add_count(length);
        }
        // DEFLATE matches have at most 258 bytes. Seed their first period
        // from the ring, then expand it with slices, including distance=1
        // and overlapping matches. No heap allocation per match.
        let mut matched = [0u8; 258];
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(matched.len() as u64) as usize;
            let distance = distance as usize;
            let source = (self.window_pos + DEFLATE_WINDOW_SIZE - distance) % DEFLATE_WINDOW_SIZE;
            let period = distance.min(count);
            let first = period.min(DEFLATE_WINDOW_SIZE - source);
            matched[..first].copy_from_slice(&self.window[source..source + first]);
            matched[first..period].copy_from_slice(&self.window[..period - first]);
            let mut filled = period;
            while filled < count {
                let copied = filled.min(count - filled);
                matched.copy_within(..copied, filled);
                filled += copied;
            }
            self.write_bytes(&matched[..count])?;
            remaining -= count as u64;
        }
        Ok(())
    }

    fn decoded_size(&self) -> u64 {
        self.decoded_size
    }

    fn finish_checksum(mut self) -> Option<u32> {
        if !self.is_verifying() {
            return None;
        }
        self.flush_pending();
        Some(self.hasher.finalize())
    }
}

fn parse_deflate(
    bits: &mut LsbBits<'_, '_>,
    output: &mut DeflateOutput,
) -> ValidationResult<usize> {
    let mut block_count = 0usize;
    loop {
        block_count = block_count
            .checked_add(1)
            .ok_or(ValidationError::Invalid("deflate_block_count_overflow"))?;
        let final_block = bits.read(1)? != 0;
        let block_type = bits.read(2)?;
        if block_type == 0 {
            bits.align_byte();
            let length = bits.read(16)? as u16;
            let complement = bits.read(16)? as u16;
            if length != !complement {
                return invalid("deflate_stored_length_mismatch");
            }
            if output.is_verifying() {
                let stored = bits.cursor.read_exact(usize::from(length))?;
                output.write_bytes(&stored)?;
            } else {
                bits.cursor.skip(u64::from(length))?;
                output.add_count(u64::from(length))?;
            }
        } else if block_type == 1 || block_type == 2 {
            let dynamic_trees;
            let (literal_tree, distance_tree) = if block_type == 1 {
                (FIXED_LITERAL_TREE, FIXED_DISTANCE_TREE)
            } else {
                dynamic_trees = dynamic_deflate_trees(bits)?;
                (dynamic_trees.0.lsb(), dynamic_trees.1.lsb())
            };
            loop {
                let symbol = literal_tree.decode(bits)?;
                match symbol {
                    0..=255 => output.write_byte(symbol as u8)?,
                    256 => break,
                    257..=285 => {
                        let index = usize::from(symbol - 257);
                        let length = u64::from(LENGTH_BASE[index])
                            + u64::from(bits.read(LENGTH_EXTRA[index])?);
                        let distance_symbol = distance_tree.decode(bits)? as usize;
                        if distance_symbol >= DIST_BASE.len() {
                            return invalid("invalid_deflate_distance_symbol");
                        }
                        let distance = u64::from(DIST_BASE[distance_symbol])
                            + u64::from(bits.read(DIST_EXTRA[distance_symbol])?);
                        output.repeat(distance, length)?;
                    }
                    _ => return invalid("invalid_deflate_literal_symbol"),
                }
            }
        } else {
            return invalid("reserved_deflate_block_type");
        }
        if final_block {
            bits.align_byte();
            return Ok(block_count);
        }
    }
}

fn gzip_header(cursor: &mut ByteCursor<'_>) -> ValidationResult<()> {
    let fixed = cursor.read_exact(10)?;
    if !fixed.starts_with(GZIP_MAGIC) {
        return invalid("gzip_magic_not_found");
    }
    let flags = fixed[3];
    if flags & 0xe0 != 0 {
        return invalid("gzip_reserved_flags_set");
    }
    let mut hasher = Hasher::new();
    hasher.update(&fixed);
    if flags & 0x04 != 0 {
        let length_bytes = cursor.read_exact(2)?;
        hasher.update(&length_bytes);
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let extra = cursor.read_exact(length)?;
        hasher.update(&extra);
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            loop {
                let byte = cursor.read_byte()?;
                hasher.update(&[byte]);
                if byte == 0 {
                    break;
                }
            }
        }
    }
    if flags & 0x02 != 0 {
        let stored = cursor.read_exact(2)?;
        if u16::from_le_bytes([stored[0], stored[1]]) != (hasher.finalize() & 0xffff) as u16 {
            return invalid("gzip_header_crc_bad");
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct GzipAnalysis {
    pub(crate) structure: StructureValidation,
    pub(crate) first_member_end: u64,
    pub(crate) first_member_compressed_bytes: u64,
    pub(crate) first_member_block_count: usize,
    pub(crate) first_member_decoded_size: u64,
    pub(crate) first_member_stored_crc32: u32,
    pub(crate) first_member_computed_crc32: Option<u32>,
    pub(crate) first_member_stored_size: u32,
}

fn walk_gzip_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    integrity_limit: Option<u64>,
) -> ValidationResult<GzipAnalysis> {
    let mut cursor = ByteCursor::new(reader, offset, limit);
    let mut members = 0usize;
    let mut blocks = 0usize;
    let mut decoded_size = 0u64;
    let mut remaining_integrity = integrity_limit;
    let mut integrity_failed = false;
    let mut integrity_complete = integrity_limit.is_some();
    let mut first_member = None;

    loop {
        gzip_header(&mut cursor)?;
        let deflate_start = cursor.position();
        let mut output = match remaining_integrity {
            Some(remaining) => DeflateOutput::verifying(remaining),
            None => DeflateOutput::counting(),
        };
        let member_blocks = {
            let mut bits = LsbBits::new(&mut cursor);
            parse_deflate(&mut bits, &mut output)?
        };
        let deflate_end = cursor.position();
        let member_size = output.decoded_size();
        let computed_crc = output.finish_checksum();
        let trailer = cursor.read_exact(8)?;
        let stored_crc = u32::from_le_bytes(trailer[0..4].try_into().unwrap());
        let stored_size = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
        if stored_size != member_size as u32 {
            return invalid("gzip_isize_mismatch");
        }

        if let Some(computed) = computed_crc {
            if computed != stored_crc {
                integrity_failed = true;
            }
            if let Some(remaining) = remaining_integrity.as_mut() {
                *remaining = remaining.saturating_sub(member_size);
            }
        } else if integrity_limit.is_some() {
            integrity_complete = false;
            remaining_integrity = Some(0);
        }

        decoded_size = decoded_size
            .checked_add(member_size)
            .ok_or(ValidationError::Invalid("decoded_size_overflow"))?;
        blocks = blocks
            .checked_add(member_blocks)
            .ok_or(ValidationError::Invalid("deflate_block_count_overflow"))?;
        members += 1;

        if first_member.is_none() {
            first_member = Some((
                cursor.position(),
                deflate_end.saturating_sub(deflate_start),
                member_blocks,
                member_size,
                stored_crc,
                computed_crc,
                stored_size,
            ));
        }

        if cursor.position() + 3 > limit {
            break;
        }
        let next = reader.read_cached_at(cursor.position(), 3)?;
        if next.as_slice() != GZIP_MAGIC {
            break;
        }
    }

    let (
        first_member_end,
        first_member_compressed_bytes,
        first_member_block_count,
        first_member_decoded_size,
        first_member_stored_crc32,
        first_member_computed_crc32,
        first_member_stored_size,
    ) = first_member.ok_or(ValidationError::Invalid("gzip_member_missing"))?;

    let integrity = if integrity_failed {
        IntegrityStatus::Failed
    } else if integrity_complete {
        IntegrityStatus::Verified
    } else {
        IntegrityStatus::Deferred
    };

    Ok(GzipAnalysis {
        structure: StructureValidation {
            end_offset: cursor.position(),
            stream_count: members,
            block_count: blocks,
            decoded_size: Some(decoded_size),
            integrity,
            checksum_present: true,
        },
        first_member_end,
        first_member_compressed_bytes,
        first_member_block_count,
        first_member_decoded_size,
        first_member_stored_crc32,
        first_member_computed_crc32,
        first_member_stored_size,
    })
}

pub(crate) fn analyze_gzip_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    integrity_limit: u64,
) -> ValidationResult<GzipAnalysis> {
    walk_gzip_structure(reader, offset, limit, Some(integrity_limit))
}

pub(crate) fn validate_gzip_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
) -> ValidationResult<StructureValidation> {
    Ok(walk_gzip_structure(reader, offset, limit, None)?.structure)
}

fn next_bzip_symbol(
    bits: &mut MsbBits<'_, '_>,
    tables: &[Huffman],
    selectors: &[usize],
    selector_index: &mut usize,
    remaining: &mut usize,
    table_index: &mut usize,
) -> ValidationResult<u16> {
    if *remaining == 0 {
        *table_index = *selectors
            .get(*selector_index)
            .ok_or(ValidationError::Invalid("bzip2_selector_underflow"))?;
        *selector_index += 1;
        *remaining = 50;
    }
    *remaining -= 1;
    tables[*table_index].decode_msb(bits)
}

pub(crate) fn validate_bzip2_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
) -> ValidationResult<StructureValidation> {
    let mut cursor = ByteCursor::new(reader, offset, limit);
    let mut streams = 0usize;
    let mut total_blocks = 0usize;
    loop {
        let header = cursor.read_exact(4)?;
        if !header.starts_with(BZIP2_MAGIC) || !(b'1'..=b'9').contains(&header[3]) {
            return invalid("bzip2_magic_not_found");
        }
        let block_limit = usize::from(header[3] - b'0') * 100_000;
        let mut bits = MsbBits::new(&mut cursor);
        let mut combined_crc = 0u32;
        loop {
            let marker = (u64::from(bits.read(24)?) << 24) | u64::from(bits.read(24)?);
            if marker == 0x1772_4538_5090 {
                let stored_combined = bits.read(32)?;
                if stored_combined != combined_crc {
                    return invalid("bzip2_combined_crc_mismatch");
                }
                bits.align_zero()?;
                break;
            }
            if marker != 0x3141_5926_5359 {
                return invalid("bzip2_block_marker_invalid");
            }
            let block_crc = bits.read(32)?;
            combined_crc = combined_crc.rotate_left(1) ^ block_crc;
            let _randomized = bits.read(1)?;
            let orig_ptr = bits.read(24)? as usize;
            let in_use16 = bits.read(16)?;
            let mut n_in_use = 0usize;
            for group in 0..16 {
                if in_use16 & (1 << (15 - group)) != 0 {
                    n_in_use += bits.read(16)?.count_ones() as usize;
                }
            }
            if n_in_use == 0 {
                return invalid("bzip2_empty_symbol_map");
            }
            let alpha_size = n_in_use + 2;
            let group_count = bits.read(3)? as usize;
            let selector_count = bits.read(15)? as usize;
            if !(2..=6).contains(&group_count) || !(1..=18_002).contains(&selector_count) {
                return invalid("bzip2_huffman_counts_invalid");
            }
            let mut mtf_groups: Vec<usize> = (0..group_count).collect();
            let mut selectors = Vec::with_capacity(selector_count);
            for _ in 0..selector_count {
                let mut index = 0usize;
                while bits.read(1)? != 0 {
                    index += 1;
                    if index >= group_count {
                        return invalid("bzip2_selector_invalid");
                    }
                }
                let value = mtf_groups.remove(index);
                mtf_groups.insert(0, value);
                selectors.push(value);
            }
            let mut tables = Vec::with_capacity(group_count);
            for _ in 0..group_count {
                let mut current = bits.read(5)? as i32;
                let mut lengths = Vec::with_capacity(alpha_size);
                for _ in 0..alpha_size {
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
                    lengths.push(current as u8);
                }
                tables.push(Huffman::new(&lengths, 20, BitOrder::Msb)?);
            }

            let eob = (n_in_use + 1) as u16;
            let mut selector_index = 0usize;
            let mut remaining = 0usize;
            let mut table_index = 0usize;
            let mut nblock = 0usize;
            let mut symbol = next_bzip_symbol(
                &mut bits,
                &tables,
                &selectors,
                &mut selector_index,
                &mut remaining,
                &mut table_index,
            )?;
            while symbol != eob {
                if symbol <= 1 {
                    let mut run = 0usize;
                    let mut weight = 1usize;
                    loop {
                        run = run
                            .checked_add(if symbol == 0 { weight } else { weight * 2 })
                            .ok_or(ValidationError::Invalid("bzip2_run_overflow"))?;
                        weight = weight
                            .checked_mul(2)
                            .ok_or(ValidationError::Invalid("bzip2_run_overflow"))?;
                        symbol = next_bzip_symbol(
                            &mut bits,
                            &tables,
                            &selectors,
                            &mut selector_index,
                            &mut remaining,
                            &mut table_index,
                        )?;
                        if symbol > 1 {
                            break;
                        }
                    }
                    nblock = nblock
                        .checked_add(run)
                        .ok_or(ValidationError::Invalid("bzip2_block_size_overflow"))?;
                } else {
                    if usize::from(symbol - 1) >= n_in_use {
                        return invalid("bzip2_mtf_symbol_invalid");
                    }
                    nblock += 1;
                    symbol = next_bzip_symbol(
                        &mut bits,
                        &tables,
                        &selectors,
                        &mut selector_index,
                        &mut remaining,
                        &mut table_index,
                    )?;
                }
                if nblock > block_limit {
                    return invalid("bzip2_block_size_exceeded");
                }
            }
            if nblock == 0 || orig_ptr >= nblock {
                return invalid("bzip2_orig_ptr_out_of_range");
            }
            total_blocks += 1;
            if total_blocks > MAX_RECORDS {
                return invalid("bzip2_block_count_exceeded");
            }
        }
        streams += 1;
        if cursor.position() + 4 > limit {
            break;
        }
        let next = reader.read_cached_at(cursor.position(), 4)?;
        if next.len() != 4 || !next.starts_with(BZIP2_MAGIC) || !(b'1'..=b'9').contains(&next[3]) {
            break;
        }
    }
    Ok(StructureValidation {
        end_offset: cursor.position(),
        stream_count: streams,
        block_count: total_blocks,
        decoded_size: None,
        integrity: IntegrityStatus::Deferred,
        checksum_present: true,
    })
}

fn read_vli_slice(data: &[u8], cursor: &mut usize) -> ValidationResult<u64> {
    let mut value = 0u64;
    for index in 0..9 {
        let byte = *data
            .get(*cursor)
            .ok_or(ValidationError::Invalid("xz_vli_truncated"))?;
        *cursor += 1;
        if index == 8 && byte > 1 {
            return invalid("xz_vli_overflow");
        }
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

fn read_vli_index(cursor: &mut ByteCursor<'_>, hasher: &mut Hasher) -> ValidationResult<u64> {
    let mut value = 0u64;
    for index in 0..9 {
        let byte = cursor.read_byte()?;
        hasher.update(&[byte]);
        if index == 8 && byte > 1 {
            return invalid("xz_vli_overflow");
        }
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
    pub(crate) end: u64,
    flags: [u8; 2],
    check_size: u64,
    index_size: u64,
}

pub(crate) fn read_xz_footer(reader: &ManagedReader, end: u64) -> ValidationResult<XzFooter> {
    let start = end
        .checked_sub(12)
        .ok_or(ValidationError::Invalid("xz_footer_missing"))?;
    let footer = reader.read_cached_at(start, 12)?;
    if footer.len() != 12 || &footer[10..12] != b"YZ" {
        return invalid("xz_footer_magic_invalid");
    }
    if u32::from_le_bytes(footer[0..4].try_into().unwrap()) != crc32(&footer[4..10]) {
        return invalid("xz_footer_crc_bad");
    }
    let flags = [footer[8], footer[9]];
    if flags[0] != 0 || flags[1] & 0xf0 != 0 {
        return invalid("xz_stream_flags_invalid");
    }
    Ok(XzFooter {
        end,
        flags,
        check_size: xz_check_size(flags[1] & 0x0f)?,
        index_size: (u64::from(u32::from_le_bytes(footer[4..8].try_into().unwrap())) + 1) * 4,
    })
}

pub(crate) fn resolve_xz_boundary_exact(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
    footer_evidence: &[XzFooter],
) -> ValidationResult<StructureValidation> {
    if limit < offset + 24 {
        return invalid("xz_header_or_footer_missing");
    }
    let mut reverse_end = limit;
    let mut streams_reversed = 0usize;
    let mut total_blocks = 0usize;
    let mut checksum_present = false;
    while reverse_end > offset {
        // Proven YZ footers cannot end with a zero padding word. Reuse their
        // independent facts, including on reverse walks of preceding streams.
        let mut known = footer_evidence
            .binary_search_by_key(&reverse_end, |footer| footer.end)
            .ok();
        if known.is_none() {
            while reverse_end >= offset + 4 {
                let word = reader.read_cached_at(reverse_end - 4, 4)?;
                if word.as_slice() != [0, 0, 0, 0] {
                    break;
                }
                reverse_end -= 4;
            }
            known = footer_evidence
                .binary_search_by_key(&reverse_end, |footer| footer.end)
                .ok();
        }
        if reverse_end < offset + 24 {
            return invalid("xz_footer_missing");
        }
        let footer_start = reverse_end - 12;
        let footer = match known {
            Some(index) => footer_evidence[index],
            None => read_xz_footer(reader, reverse_end)?,
        };
        let XzFooter {
            flags,
            check_size,
            index_size,
            ..
        } = footer;
        checksum_present |= check_size != 0;
        let index_start = footer_start
            .checked_sub(index_size)
            .ok_or(ValidationError::Invalid("xz_backward_size_out_of_range"))?;
        if index_size < 8 || index_start < offset {
            return invalid("xz_backward_size_out_of_range");
        }

        let index_crc_pos = footer_start - 4;
        let mut index_cursor = ByteCursor::new(reader, index_start, footer_start);
        let mut index_hasher = Hasher::new();
        let indicator = index_cursor.read_byte()?;
        index_hasher.update(&[indicator]);
        if indicator != 0 {
            return invalid("xz_index_indicator_invalid");
        }
        let record_count = read_vli_index(&mut index_cursor, &mut index_hasher)? as usize;
        if record_count > MAX_RECORDS {
            return invalid("xz_index_record_count_exceeded");
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
        let stored_index_crc = index_cursor.read_exact(4)?;
        if u32::from_le_bytes(stored_index_crc.try_into().unwrap()) != index_hasher.finalize() {
            return invalid("xz_index_crc_bad");
        }

        let stream_start = index_start
            .checked_sub(padded_blocks_size + 12)
            .ok_or(ValidationError::Invalid("xz_stream_start_out_of_range"))?;
        if stream_start < offset {
            return invalid("xz_stream_start_out_of_range");
        }
        let header = reader.read_cached_at(stream_start, 12)?;
        if header.len() != 12 || !header.starts_with(XZ_MAGIC) {
            return invalid("xz_header_magic_invalid");
        }
        if header[6..8] != flags {
            return invalid("xz_stream_flags_mismatch");
        }
        if u32::from_le_bytes(header[8..12].try_into().unwrap()) != crc32(&header[6..8]) {
            return invalid("xz_header_crc_bad");
        }

        total_blocks = total_blocks
            .checked_add(record_count)
            .ok_or(ValidationError::Invalid("xz_block_count_overflow"))?;
        streams_reversed += 1;
        reverse_end = stream_start;
    }
    if reverse_end != offset {
        return invalid("xz_trailing_or_leading_data");
    }
    Ok(StructureValidation {
        end_offset: limit,
        stream_count: streams_reversed,
        block_count: total_blocks,
        decoded_size: None,
        integrity: if checksum_present {
            IntegrityStatus::Deferred
        } else {
            IntegrityStatus::NotPresent
        },
        checksum_present,
    })
}

pub(crate) fn validate_xz_structure_exact(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
) -> ValidationResult<StructureValidation> {
    if limit < offset + 24 {
        return invalid("xz_header_or_footer_missing");
    }
    let mut reverse_end = limit;
    let mut streams_reversed = 0usize;
    let mut total_blocks = 0usize;
    let mut checksum_present = false;
    while reverse_end > offset {
        let mut padding = 0u64;
        while reverse_end >= offset + 4 {
            let word = reader.read_cached_at(reverse_end - 4, 4)?;
            if word.as_slice() != [0, 0, 0, 0] {
                break;
            }
            reverse_end -= 4;
            padding += 4;
        }
        if reverse_end < offset + 24 {
            return invalid("xz_footer_missing");
        }
        let footer_start = reverse_end - 12;
        let XzFooter {
            flags,
            check_size,
            index_size,
            ..
        } = read_xz_footer(reader, reverse_end)?;
        checksum_present |= check_size != 0;
        let index_start = footer_start
            .checked_sub(index_size)
            .ok_or(ValidationError::Invalid("xz_backward_size_out_of_range"))?;
        if index_size < 8 || index_start < offset {
            return invalid("xz_backward_size_out_of_range");
        }
        let index_crc_pos = footer_start - 4;
        let mut index_cursor = ByteCursor::new(reader, index_start, footer_start);
        let mut index_hasher = Hasher::new();
        let indicator = index_cursor.read_byte()?;
        index_hasher.update(&[indicator]);
        if indicator != 0 {
            return invalid("xz_index_indicator_invalid");
        }
        let record_count = read_vli_index(&mut index_cursor, &mut index_hasher)? as usize;
        if record_count > MAX_RECORDS {
            return invalid("xz_index_record_count_exceeded");
        }
        let mut records = Vec::with_capacity(record_count);
        let mut padded_blocks_size = 0u64;
        for _ in 0..record_count {
            let unpadded = read_vli_index(&mut index_cursor, &mut index_hasher)?;
            let uncompressed = read_vli_index(&mut index_cursor, &mut index_hasher)?;
            if unpadded == 0 {
                return invalid("xz_index_record_invalid");
            }
            let padded = unpadded
                .checked_add((4 - unpadded % 4) % 4)
                .ok_or(ValidationError::Invalid("xz_block_size_overflow"))?;
            padded_blocks_size = padded_blocks_size
                .checked_add(padded)
                .ok_or(ValidationError::Invalid("xz_block_size_overflow"))?;
            records.push((unpadded, uncompressed));
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
        let stored_index_crc = index_cursor.read_exact(4)?;
        if u32::from_le_bytes(stored_index_crc.try_into().unwrap()) != index_hasher.finalize() {
            return invalid("xz_index_crc_bad");
        }

        let stream_start = index_start
            .checked_sub(padded_blocks_size + 12)
            .ok_or(ValidationError::Invalid("xz_stream_start_out_of_range"))?;
        if stream_start < offset {
            return invalid("xz_stream_start_out_of_range");
        }
        let header = reader.read_cached_at(stream_start, 12)?;
        if header.len() != 12 || !header.starts_with(XZ_MAGIC) {
            return invalid("xz_header_magic_invalid");
        }
        if header[6..8] != flags {
            return invalid("xz_stream_flags_mismatch");
        }
        if u32::from_le_bytes(header[8..12].try_into().unwrap()) != crc32(&header[6..8]) {
            return invalid("xz_header_crc_bad");
        }

        let mut block_cursor = stream_start + 12;
        for (unpadded, uncompressed) in records {
            let size_byte = reader.read_cached_at(block_cursor, 1)?;
            if size_byte.len() != 1 || size_byte[0] == 0 {
                return invalid("xz_block_header_missing");
            }
            let header_size = (u64::from(size_byte[0]) + 1) * 4;
            if header_size > unpadded || header_size > 1024 {
                return invalid("xz_block_header_size_invalid");
            }
            let block_header = reader.read_cached_at(block_cursor, header_size as usize)?;
            if block_header.len() != header_size as usize {
                return invalid("xz_block_header_truncated");
            }
            let stored_crc =
                u32::from_le_bytes(block_header[block_header.len() - 4..].try_into().unwrap());
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
                    read_vli_slice(&block_header[..block_header.len() - 4], &mut field_cursor)?
                        as usize;
                field_cursor = field_cursor
                    .checked_add(property_size)
                    .ok_or(ValidationError::Invalid("xz_filter_properties_overflow"))?;
                if field_cursor > block_header.len() - 4 {
                    return invalid("xz_filter_properties_truncated");
                }
            }
            if block_header[field_cursor..block_header.len() - 4]
                .iter()
                .any(|byte| *byte != 0)
            {
                return invalid("xz_block_header_padding_invalid");
            }
            let compressed = unpadded
                .checked_sub(header_size + check_size)
                .ok_or(ValidationError::Invalid("xz_index_unpadded_size_invalid"))?;
            if declared_compressed.is_some_and(|value| value != compressed)
                || declared_uncompressed.is_some_and(|value| value != uncompressed)
            {
                return invalid("xz_block_size_mismatch");
            }
            let padded = unpadded + (4 - unpadded % 4) % 4;
            let padding_size = padded - unpadded;
            if padding_size > 0 {
                let padding_offset = block_cursor + header_size + compressed;
                let padding_bytes = reader.read_cached_at(padding_offset, padding_size as usize)?;
                if padding_bytes.len() != padding_size as usize
                    || padding_bytes.iter().any(|byte| *byte != 0)
                {
                    return invalid("xz_block_padding_invalid");
                }
            }
            block_cursor = block_cursor
                .checked_add(padded)
                .ok_or(ValidationError::Invalid("xz_block_offset_overflow"))?;
            total_blocks += 1;
        }
        if block_cursor != index_start {
            return invalid("xz_block_index_boundary_mismatch");
        }
        streams_reversed += 1;
        reverse_end = stream_start;
        let _ = padding;
    }
    if reverse_end != offset {
        return invalid("xz_trailing_or_leading_data");
    }
    Ok(StructureValidation {
        end_offset: limit,
        stream_count: streams_reversed,
        block_count: total_blocks,
        decoded_size: None,
        integrity: if checksum_present {
            IntegrityStatus::Deferred
        } else {
            IntegrityStatus::NotPresent
        },
        checksum_present,
    })
}

fn read_u32(reader: &ManagedReader, offset: u64, limit: u64) -> ValidationResult<u32> {
    if offset + 4 > limit {
        return invalid("unexpected_end_of_stream");
    }
    let bytes = reader.read_cached_at(offset, 4)?;
    if bytes.len() != 4 {
        return invalid("unexpected_end_of_stream");
    }
    Ok(u32::from_le_bytes(bytes.as_slice().try_into().unwrap()))
}

pub(crate) fn validate_zstd_structure(
    reader: &ManagedReader,
    offset: u64,
    limit: u64,
) -> ValidationResult<StructureValidation> {
    let mut cursor = offset;
    let mut frames = 0usize;
    let mut blocks = 0usize;
    let mut checksum_present = false;
    loop {
        let magic = read_u32(reader, cursor, limit)?;
        if (0x184d2a50..=0x184d2a5f).contains(&magic) {
            let size = u64::from(read_u32(reader, cursor + 4, limit)?);
            cursor = cursor
                .checked_add(8 + size)
                .ok_or(ValidationError::Invalid("zstd_skippable_size_overflow"))?;
            if cursor > limit {
                return invalid("zstd_skippable_frame_truncated");
            }
        } else if magic == ZSTD_MAGIC {
            let mut bytes = ByteCursor::new(reader, cursor + 4, limit);
            let descriptor = bytes.read_byte()?;
            if descriptor & 0x18 != 0 {
                return invalid("zstd_reserved_or_unused_bit_set");
            }
            let single_segment = descriptor & 0x20 != 0;
            let has_checksum = descriptor & 0x04 != 0;
            checksum_present |= has_checksum;
            let dictionary_size = match descriptor & 0x03 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            let content_size = match (descriptor >> 6, single_segment) {
                (0, false) => 0,
                (0, true) => 1,
                (1, _) => 2,
                (2, _) => 4,
                _ => 8,
            };
            let window_size = if single_segment {
                None
            } else {
                let value = bytes.read_byte()?;
                let base = 1u64 << (10 + u32::from(value >> 3));
                Some(base + (base / 8) * u64::from(value & 7))
            };
            bytes.skip(dictionary_size)?;
            let content_bytes = bytes.read_exact(content_size as usize)?;
            let mut frame_content_size = if content_size == 0 {
                None
            } else {
                Some(
                    content_bytes
                        .iter()
                        .enumerate()
                        .fold(0u64, |value, (index, byte)| {
                            value | (u64::from(*byte) << (8 * index))
                        }),
                )
            };
            if content_size == 2 {
                frame_content_size = frame_content_size.map(|value| value + 256);
            }
            let window_size = if single_segment {
                frame_content_size.ok_or(ValidationError::Invalid("zstd_content_size_missing"))?
            } else {
                window_size.unwrap()
            };
            loop {
                let header = bytes.read_exact(3)?;
                let value = u32::from(header[0])
                    | (u32::from(header[1]) << 8)
                    | (u32::from(header[2]) << 16);
                let last = value & 1 != 0;
                let block_type = (value >> 1) & 3;
                let block_size = u64::from(value >> 3);
                if block_type == 3 || block_size > window_size.min(128 * 1024) {
                    return invalid("zstd_block_header_invalid");
                }
                bytes.skip(if block_type == 1 { 1 } else { block_size })?;
                blocks += 1;
                if blocks > MAX_RECORDS {
                    return invalid("zstd_block_count_exceeded");
                }
                if last {
                    break;
                }
            }
            if has_checksum {
                bytes.skip(4)?;
            }
            cursor = bytes.position();
            frames += 1;
        } else {
            break;
        }
        if cursor + 4 > limit {
            break;
        }
        let next = read_u32(reader, cursor, limit)?;
        if next != ZSTD_MAGIC && !(0x184d2a50..=0x184d2a5f).contains(&next) {
            break;
        }
    }
    if frames == 0 {
        return invalid("zstd_frame_missing");
    }
    Ok(StructureValidation {
        end_offset: cursor,
        stream_count: frames,
        block_count: blocks,
        decoded_size: None,
        integrity: if checksum_present {
            IntegrityStatus::Deferred
        } else {
            IntegrityStatus::NotPresent
        },
        checksum_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::reader::ReaderConfig;
    use std::io::{Read, Write};

    fn reader(data: Vec<u8>) -> ManagedReader {
        ManagedReader::from_bytes(data, ReaderConfig::default())
    }

    // Independent of archive codecs: cover every fixed symbol, bit alignment,
    // the short-code EOF fallback, and lookahead ownership across probe refill.
    #[test]
    fn fixed_deflate_constants_decode_all_rfc_codes_and_short_eof() {
        for prefix in 0..8 {
            for distance in [false, true] {
                let count = if distance { 32 } else { 288 };
                let mut logical = vec![0u8; prefix];
                for symbol in 0..count {
                    let (code, length) = if distance {
                        (symbol, 5)
                    } else {
                        match symbol {
                            0..=143 => (0x30 + symbol, 8),
                            144..=255 => (0x190 + symbol - 144, 9),
                            256..=279 => (symbol - 256, 7),
                            _ => (0xc0 + symbol - 280, 8),
                        }
                    };
                    for shift in (0..length).rev() {
                        logical.push(((code >> shift) & 1) as u8);
                    }
                }
                let byte_count = logical.len().div_ceil(8);
                let mut data = vec![0u8; byte_count];
                for (index, bit) in logical.iter().enumerate() {
                    data[index / 8] |= bit << (index % 8);
                }
                data.extend_from_slice(&[0xa5, 0x5a]);
                let source = reader(data.clone());
                let mut cursor = ByteCursor::new(&source, 0, data.len() as u64);
                let mut bits = LsbBits::new(&mut cursor);
                bits.read(prefix as u8).unwrap();
                let tree = if distance {
                    FIXED_DISTANCE_TREE
                } else {
                    FIXED_LITERAL_TREE
                };
                for symbol in 0..count {
                    assert_eq!(tree.decode(&mut bits).unwrap(), symbol as u16);
                }
                bits.align_byte();
                assert_eq!(cursor.position(), byte_count as u64);
                assert_eq!(cursor.read_exact(2).unwrap(), [0xa5, 0x5a]);
            }
        }
        let source = reader(vec![0]);
        let mut cursor = ByteCursor::new(&source, 0, 1);
        let mut bits = LsbBits::new(&mut cursor);
        assert_eq!(FIXED_LITERAL_TREE.decode(&mut bits).unwrap(), 256);
        assert_eq!(
            FIXED_LITERAL_TREE.decode(&mut bits).unwrap_err().code(),
            "unexpected_end_of_stream"
        );
    }

    // A short logical stream must fit its read budget even in a large carrier;
    // existing whole-file fixtures do not detect reads of unrelated tail data.
    #[test]
    fn tiny_gzip_boundary_preserves_unrelated_carrier_read_budget() {
        let member = gzip_member(b"");
        let end = member.len() as u64;
        let mut data = member;
        data.extend_from_slice(b"carrier-tail");
        data.resize(2 * BUFFER_SIZE, 0);
        let source = ManagedReader::from_bytes(
            data,
            ReaderConfig {
                max_read_bytes: Some(512),
                ..ReaderConfig::default()
            },
        );
        let result = validate_gzip_structure(&source, 0, source.len()).unwrap();
        assert_eq!(result.end_offset, end);
        assert_eq!(result.stream_count, 1);
        assert_eq!(result.decoded_size, Some(0));
    }

    // The small archive fixtures cannot force every overlapping match across
    // ring/CRC-buffer boundaries. Compare one bounded matrix to a flat output.
    #[test]
    fn deflate_bulk_output_preserves_overlap_ring_crc_and_integrity_limit() {
        let seed = (0..BUFFER_SIZE + 37)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let mut expected = seed.clone();
        for distance in [1, 2, 3, 7, 258, DEFLATE_WINDOW_SIZE] {
            for length in [1, 3, 258] {
                for _ in 0..length {
                    expected.push(expected[expected.len() - distance]);
                }
            }
        }
        for limit in [expected.len() as u64, expected.len() as u64 - 1, 0] {
            let mut output = DeflateOutput::verifying(limit);
            output.write_bytes(&seed).unwrap();
            for distance in [1, 2, 3, 7, 258, DEFLATE_WINDOW_SIZE] {
                for length in [1, 3, 258] {
                    output.repeat(distance as u64, length).unwrap();
                }
            }
            assert_eq!(output.decoded_size(), expected.len() as u64);
            assert_eq!(
                output.finish_checksum(),
                (limit >= expected.len() as u64).then(|| crc32(&expected))
            );
        }
        assert!(DeflateOutput::counting().repeat(1, 1).is_err());
    }

    // Independent coverage: lookahead byte ownership at all bit alignments,
    // short codes at EOF, and 15/20-bit codes absent from the tiny real-stream
    // fixtures. One bounded matrix catches boundary/truncation regressions.
    #[test]
    fn huffman_lookup_preserves_codes_eof_and_following_bytes() {
        for (max_len, order) in [(15, BitOrder::Lsb), (20, BitOrder::Msb)] {
            let mut lengths = (1..=max_len as u8).collect::<Vec<_>>();
            lengths.push(max_len as u8);
            let tree = Huffman::new(&lengths, max_len, order).unwrap();
            for prefix in 0..8 {
                let mut logical = vec![0u8; prefix];
                for (symbol, &length) in lengths.iter().enumerate() {
                    // Complete canonical comb tree: 0, 10, 110, ... , 111... .
                    let code = if symbol == max_len {
                        (1u32 << length) - 1
                    } else {
                        (1u32 << length) - 2
                    };
                    for shift in (0..length).rev() {
                        logical.push(((code >> shift) & 1) as u8);
                    }
                }
                logical.push(0); // shortest code, including insufficient lookup bits at EOF
                let byte_count = logical.len().div_ceil(8);
                let mut data = vec![0u8; byte_count];
                for (index, bit) in logical.iter().enumerate() {
                    let shift = match order {
                        BitOrder::Lsb => index % 8,
                        BitOrder::Msb => 7 - index % 8,
                    };
                    data[index / 8] |= bit << shift;
                }
                for tail in [false, true] {
                    let mut input = data.clone();
                    if tail {
                        input.extend_from_slice(&[0xa5, 0x5a]);
                    }
                    let source = reader(input.clone());
                    let mut cursor = ByteCursor::new(&source, 0, input.len() as u64);
                    match order {
                        BitOrder::Lsb => {
                            let mut bits = LsbBits::new(&mut cursor);
                            bits.read(prefix as u8).unwrap();
                            for symbol in 0..lengths.len() {
                                assert_eq!(tree.decode_lsb(&mut bits).unwrap(), symbol as u16);
                            }
                            assert_eq!(tree.decode_lsb(&mut bits).unwrap(), 0);
                            bits.align_byte();
                        }
                        BitOrder::Msb => {
                            let mut bits = MsbBits::new(&mut cursor);
                            bits.read(prefix as u8).unwrap();
                            for symbol in 0..lengths.len() {
                                assert_eq!(tree.decode_msb(&mut bits).unwrap(), symbol as u16);
                            }
                            assert_eq!(tree.decode_msb(&mut bits).unwrap(), 0);
                            bits.align_zero().unwrap();
                        }
                    }
                    assert_eq!(cursor.position(), byte_count as u64);
                    if tail {
                        assert_eq!(cursor.read_exact(2).unwrap(), [0xa5, 0x5a]);
                    }
                }
            }
            let source = reader(vec![0xff]);
            let mut cursor = ByteCursor::new(&source, 0, 1);
            let error = match order {
                BitOrder::Lsb => tree.decode_lsb(&mut LsbBits::new(&mut cursor)),
                BitOrder::Msb => tree.decode_msb(&mut MsbBits::new(&mut cursor)),
            }
            .unwrap_err();
            assert_eq!(error.code(), "unexpected_end_of_stream");
        }
    }

    #[test]
    fn gzip_token_walk_handles_dynamic_and_concatenated_members() {
        let mut first = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut first, flate2::Compression::default());
            encoder.write_all(&vec![b'A'; 2 * 1024 * 1024]).unwrap();
            encoder.finish().unwrap();
        }
        let mut data = first.clone();
        data.extend_from_slice(&first);
        let source = reader(data.clone());
        let result = validate_gzip_structure(&source, 0, data.len() as u64).unwrap();
        assert_eq!(result.end_offset, data.len() as u64);
        assert_eq!(result.stream_count, 2);
        assert_eq!(result.decoded_size, Some(4 * 1024 * 1024));
    }

    fn gzip_member(payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut data, flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap();
        data
    }

    #[test]
    fn gzip_integrity_walk_verifies_many_small_members_in_one_pass() {
        let member = gzip_member(b"small-member");
        let mut data = Vec::new();
        for _ in 0..128 {
            data.extend_from_slice(&member);
        }
        let source = reader(data.clone());
        let result =
            analyze_gzip_structure(&source, 0, data.len() as u64, 8 * 1024 * 1024).unwrap();
        assert_eq!(result.structure.end_offset, data.len() as u64);
        assert_eq!(result.structure.stream_count, 128);
        assert_eq!(result.structure.integrity, IntegrityStatus::Verified);
        assert!(result.first_member_computed_crc32.is_some());
    }

    #[test]
    fn gzip_integrity_walk_bounds_high_ratio_output_without_losing_boundary() {
        let payload = vec![b'Z'; 16 * 1024 * 1024];
        let data = gzip_member(&payload);
        let source = reader(data.clone());
        let result =
            analyze_gzip_structure(&source, 0, data.len() as u64, 8 * 1024 * 1024).unwrap();
        assert_eq!(result.structure.end_offset, data.len() as u64);
        assert_eq!(result.structure.decoded_size, Some(payload.len() as u64));
        assert_eq!(result.structure.integrity, IntegrityStatus::Deferred);
        assert!(result.first_member_computed_crc32.is_none());
    }

    #[test]
    fn gzip_integrity_walk_checks_later_member_crc() {
        let first = gzip_member(b"first");
        let second = gzip_member(b"second");
        let mut data = first;
        data.extend_from_slice(&second);
        let crc_offset = data.len() - 8;
        data[crc_offset] ^= 0x80;

        let source = reader(data.clone());
        let result =
            analyze_gzip_structure(&source, 0, data.len() as u64, 8 * 1024 * 1024).unwrap();
        assert_eq!(result.structure.end_offset, data.len() as u64);
        assert_eq!(result.structure.stream_count, 2);
        assert_eq!(result.structure.integrity, IntegrityStatus::Failed);
    }

    #[test]
    fn gzip_integrity_walk_stops_before_multi_member_carrier_tail() {
        let first = gzip_member(b"first");
        let second = gzip_member(b"second");
        let mut data = first;
        data.extend_from_slice(&second);
        let archive_end = data.len();
        data.extend_from_slice(b"carrier-tail");

        let source = reader(data.clone());
        let result =
            analyze_gzip_structure(&source, 0, data.len() as u64, 8 * 1024 * 1024).unwrap();
        assert_eq!(result.structure.end_offset, archive_end as u64);
        assert_eq!(result.structure.stream_count, 2);
        assert_eq!(result.structure.integrity, IntegrityStatus::Verified);
    }

    #[test]
    fn bzip2_huffman_walk_reaches_stream_end() {
        let data = bzip2::read::BzEncoder::new(
            &vec![b'B'; 2 * 1024 * 1024][..],
            bzip2::Compression::best(),
        )
        .bytes()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let source = reader(data.clone());
        let result = validate_bzip2_structure(&source, 0, data.len() as u64).unwrap();
        assert_eq!(result.end_offset, data.len() as u64);
        assert!(result.block_count > 0);
    }

    #[test]
    fn zstd_block_walk_rejects_truncation() {
        let data = zstd::stream::encode_all(&vec![b'Z'; 1024 * 1024][..], 3).unwrap();
        let source = reader(data[..data.len() - 1].to_vec());
        assert!(validate_zstd_structure(&source, 0, (data.len() - 1) as u64).is_err());
    }

    #[test]
    fn xz_reverse_index_walk_skips_payload() {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&vec![b'X'; 2 * 1024 * 1024]).unwrap();
        let data = encoder.finish().unwrap();
        let source = reader(data.clone());
        let result = validate_xz_structure_exact(&source, 0, data.len() as u64).unwrap();
        assert_eq!(result.end_offset, data.len() as u64);
        assert_eq!(result.stream_count, 1);
        assert!(result.block_count > 0);
    }
}
