//! Block structure shared by ZIP and 7z. No member symbols are decoded.

const CODE_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
pub(crate) const MAX_DYNAMIC_HEADER_SIZE: usize = (3usize + 14 + 19 * 3 + (288 + 32) * 7).div_ceil(8);

/// Incomplete prefixes leave the candidate eligible for later verification.
pub(crate) fn matches_prefix(
    bytes: &[u8],
    packed_size: Option<u64>,
    unpack_size: Option<u64>,
    deflate64: bool,
) -> bool {
    check_prefix(bytes, packed_size, unpack_size, deflate64).unwrap_or(true)
}

pub(crate) fn check_prefix(
    bytes: &[u8],
    packed_size: Option<u64>,
    unpack_size: Option<u64>,
    deflate64: bool,
) -> Option<bool> {
    check_header(bytes, packed_size, unpack_size, deflate64).map(|header| !matches!(header, Header::Invalid))
}

enum Header {
    Invalid,
    Checked,
    Stored(u16),
}

fn check_header(
    bytes: &[u8], packed_size: Option<u64>, unpack_size: Option<u64>, deflate64: bool,
) -> Option<Header> {
    let first = *bytes.first()?;
    Some(match (first >> 1) & 3 {
        0 => {
            let &[lo, hi, inverse_lo, inverse_hi] = bytes.get(1..)?.first_chunk()?;
            let len = u16::from_le_bytes([lo, hi]);
            let inverse = u16::from_le_bytes([inverse_lo, inverse_hi]);
            if len != !inverse || packed_size.is_some_and(|size| u64::from(len) + 5 > size)
                || unpack_size.is_some_and(|size| u64::from(len) > size) {
                Header::Invalid
            } else if first & 1 == 0 {
                Header::Stored(len)
            } else {
                Header::Checked
            }
        }
        1 => Header::Checked,
        2 if dynamic_tables(bytes, deflate64)? => Header::Checked,
        _ => Header::Invalid,
    })
}

// A non-final Stored block starts and ends its payload on byte boundaries.
// Its successor is reachable by seeking over LEN bytes. Compressed blocks
// require member decoding to locate their successor, so stop at their header.
pub(crate) fn check_successors<E>(
    prefix: &[u8], (packed, mut unpacked): (u64, u64), readable: u64, deflate64: bool,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    mut still_ambiguous: impl FnMut(u64) -> bool,
) -> Result<Option<bool>, E> {
    let mut offset = 0;
    let mut header = [0; MAX_DYNAMIC_HEADER_SIZE];
    loop {
        let available = (readable.saturating_sub(offset).min(MAX_DYNAMIC_HEADER_SIZE as u64)) as usize;
        if available == 0 {
            return Ok(None);
        }
        let cached = usize::try_from(offset).ok().and_then(|at| prefix.get(at..)).unwrap_or_default();
        let cached = &cached[..cached.len().min(available)];
        let check = |bytes| check_header(bytes, Some(packed - offset), Some(unpacked), deflate64);
        let mut verdict = check(cached);
        if verdict.is_none() {
            let mut loaded = cached.len();
            header[..loaded].copy_from_slice(cached);
            if loaded == 0 {
                read(offset, &mut header[..1])?;
                loaded = 1;
            }
            let limit = match header[0] & 6 {
                0 => 5,
                4 => MAX_DYNAMIC_HEADER_SIZE,
                _ => 1,
            }.min(available);
            if loaded < limit {
                read(offset + loaded as u64, &mut header[loaded..limit])?;
                loaded = limit;
            }
            verdict = check(&header[..loaded]);
        }
        match verdict {
            Some(Header::Stored(len)) => {
                let next = offset + 5 + u64::from(len);
                if next >= packed { return Ok(Some(false)); }
                if offset != 0 && !still_ambiguous(next) { return Ok(Some(true)); }
                offset = next;
                unpacked -= u64::from(len);
            }
            Some(Header::Checked) => return Ok(Some(true)),
            Some(Header::Invalid) => return Ok(Some(false)),
            None => return Ok(None),
        }
    }
}

struct PrefixBits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl PrefixBits<'_> {
    fn peek(&self) -> u16 {
        let index = self.position >> 3;
        let low = self.bytes.get(index).copied().unwrap_or(0);
        let high = self.bytes.get(index + 1).copied().unwrap_or(0);
        u16::from_le_bytes([low, high]) >> (self.position & 7)
    }

    fn take(&mut self, count: usize) -> Option<usize> {
        let end = self.position + count;
        if end > self.bytes.len() * 8 {
            return None;
        }
        let bits = usize::from(self.peek()) & ((1 << count) - 1);
        self.position = end;
        Some(bits)
    }
}

fn dynamic_tables(bytes: &[u8], deflate64: bool) -> Option<bool> {
    let mut bits = PrefixBits { bytes, position: 3 };
    let literals = bits.take(5)? + 257;
    let distances = bits.take(5)? + 1;
    // 7-Zip permits all 32 distance entries in Deflate64 only.
    if !deflate64 && distances > 30 {
        return Some(false);
    }
    let count = bits.take(4)? + 4;
    let mut lengths = [0; 19];
    for &index in &CODE_ORDER[..count] {
        lengths[index] = bits.take(3)?;
    }
    let mut length_counts = [0usize; 8];
    for &length in &lengths {
        length_counts[length] += 1;
    }
    let used = (1..=7).map(|len| length_counts[len] << (7 - len)).sum::<usize>();
    if used == 0 || used > 128 {
        return Some(false);
    }
    let mut next_code = [0usize; 8];
    for len in 2..=7 {
        next_code[len] = (next_code[len - 1] + length_counts[len - 1]) << 1;
    }
    let mut table = [0u8; 128];
    for (symbol, length) in lengths.into_iter().enumerate().filter(|&(_, len)| len != 0) {
        let code = (next_code[length] as u8).reverse_bits() >> (8 - length);
        next_code[length] += 1;
        for index in (code as usize..128).step_by(1 << length) {
            table[index] = ((symbol as u8) << 3) | length as u8;
        }
    }
    let mut weights = [0; 2];
    let mut position = 0;
    let mut previous = 0;
    let total = literals + distances;
    while position < total {
        let entry = table[usize::from(bits.peek() & 127)];
        if entry == 0 {
            // A partial code can still resolve when more bytes are available.
            bits.take(7)?;
            return Some(false);
        }
        bits.take(usize::from(entry & 7))?;
        let (length, repeat) = match entry >> 3 {
            16 if position == 0 => return Some(false),
            16 => (previous, bits.take(2)? + 3),
            17 => (0, bits.take(3)? + 3),
            18 => (0, bits.take(7)? + 11),
            length => (length, 1),
        };
        let end = position + repeat;
        if end > total {
            return Some(false);
        }
        if length != 0 {
            let literal_count = end.min(literals).saturating_sub(position);
            let units = 1usize << (15 - length);
            weights[0] += units * literal_count;
            weights[1] += units * (repeat - literal_count);
            if weights.iter().any(|&weight| weight > 1 << 15) {
                return Some(false);
            }
        }
        previous = length;
        position = end;
    }
    Some(true)
}
