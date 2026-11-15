//! Shared TAR member semantics for discovery and analysis.
use crate::io::reader::CachedBytes;
use std::io;

const BLOCK: u64 = 512;
type ReadAt<'a> = dyn FnMut(u64, usize) -> io::Result<CachedBytes> + 'a;

#[derive(Default)]
pub(crate) struct TarState {
    global_size: Option<PaxSize>,
    local_size: Option<PaxSize>,
}

#[derive(Clone, Copy)]
enum PaxSize {
    Empty,
    Value(u64),
    Invalid,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "TAR member payload is truncated",
    )
}

pub(crate) fn number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        if field[0] & 0x40 != 0 {
            return None;
        }
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(*byte as u64)?;
        }
        return Some(value);
    }
    let start = field.iter().position(|b| *b != b' ').unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|b| !matches!(*b, 0 | b' '))
        .map_or(start, |i| i + 1);
    let mut value = 0u64;
    for byte in &field[start..end] {
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
    }
    Some(value)
}

pub(crate) fn checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|b| *b as u64).sum::<u64>()
        + 32 * 8
        + header[156..512].iter().map(|b| *b as u64).sum::<u64>()
}

pub(crate) fn valid_header(header: &[u8]) -> bool {
    header_size(header).is_ok()
}

pub(crate) fn header_size(header: &[u8]) -> Result<u64, &'static str> {
    if header.len() != BLOCK as usize {
        return Err("short_tar_header");
    }
    checked_header_size(
        number(&header[148..156]),
        number(&header[124..136]),
        checksum(header),
    )
}

pub(crate) fn checked_header_size(
    stored_checksum: Option<u64>,
    member_size: Option<u64>,
    computed_checksum: u64,
) -> Result<u64, &'static str> {
    let stored = stored_checksum.ok_or("invalid_checksum_field")?;
    let size = member_size.ok_or("invalid_size_field")?;
    if stored != computed_checksum {
        return Err("checksum_mismatch");
    }
    Ok(size)
}

pub(crate) fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}

fn read_exact(read: &mut ReadAt<'_>, start: u64, size: usize) -> io::Result<CachedBytes> {
    let data = read(start, size)?;
    if data.len() != size {
        return Err(truncated());
    }
    Ok(data)
}

impl TarState {
    pub(crate) fn boundary_context_free(&self) -> bool {
        self.global_size.is_none() && self.local_size.is_none()
    }

    /// Metadata records use their own raw length. Overrides apply only to the
    /// following real member; an empty local value masks its global value.
    pub(crate) fn advance(
        &mut self,
        header: &[u8],
        offset: u64,
        total: u64,
        read: &mut ReadAt<'_>,
    ) -> io::Result<u64> {
        let raw_size = header_size(header).map_err(|_| invalid("invalid TAR member header"))?;
        self.advance_validated(header, raw_size, offset, total, read)
    }

    pub(crate) fn advance_validated(
        &mut self,
        header: &[u8],
        raw_size: u64,
        offset: u64,
        total: u64,
        read: &mut ReadAt<'_>,
    ) -> io::Result<u64> {
        let kind = header[156];
        let (sparse_span, sparse_end) = if kind == b'S' {
            sparse_span(header, offset, total, read)?
        } else {
            (0, 0)
        };
        let start = offset
            .checked_add(BLOCK)
            .and_then(|n| n.checked_add(sparse_span))
            .ok_or_else(truncated)?;
        let metadata = matches!(kind, b'x' | b'g' | b'L' | b'K');
        let physical_size = if metadata {
            raw_size
        } else {
            match self.local_size.or(self.global_size) {
                Some(PaxSize::Value(size)) => size,
                Some(PaxSize::Invalid) => return Err(invalid("invalid TAR extended size: size")),
                Some(PaxSize::Empty) | None => raw_size,
            }
        };
        let next = start
            .checked_add(physical_size)
            .and_then(|n| n.checked_add(padding(physical_size)))
            .filter(|n| *n <= total)
            .ok_or_else(truncated)?;
        if matches!(kind, b'x' | b'g') {
            if let Some(size) = pax_size(read, start, raw_size)? {
                if kind == b'g' {
                    self.global_size = (!matches!(size, PaxSize::Empty)).then_some(size);
                } else {
                    self.local_size = Some(size);
                }
            }
            return Ok(next);
        }
        if matches!(kind, b'L' | b'K') {
            // Names do not affect discovery boundaries; the worker consumes them.
            return Ok(next);
        }
        if kind == b'S' {
            let size = number(&header[483..495])
                .ok_or_else(|| invalid("invalid old GNU sparse logical size"))?;
            if sparse_end > size {
                return Err(invalid("old GNU sparse extent exceeds logical size"));
            }
        }
        self.local_size = None;
        Ok(next)
    }
}

fn pax_size(read: &mut ReadAt<'_>, start: u64, size: u64) -> io::Result<Option<PaxSize>> {
    let mut parsed = None;
    let mut cursor = 0u64;
    while cursor < size {
        let prefix = read_exact(read, start + cursor, (size - cursor).min(256) as usize)?;
        let space = prefix
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| invalid("invalid PAX extended header"))?;
        let length = std::str::from_utf8(&prefix[..space])
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > space as u64 + 2 && *n <= size - cursor)
            .ok_or_else(|| invalid("invalid PAX extended header"))?;
        let end = cursor + length;
        let complete = length <= prefix.len() as u64;
        let last = if complete {
            prefix[length as usize - 1]
        } else {
            read_exact(read, start + end - 1, 1)?[0]
        };
        if last != b'\n' {
            return Err(invalid("invalid PAX extended header"));
        }
        let body = &prefix[space + 1..prefix.len().min(length as usize - 1)];
        if let Some(value) = body.strip_prefix(b"size=") {
            let value_start = cursor + space as u64 + 6;
            // Keep invalid numeric values dormant until this override applies.
            // A later record can mask or replace them before any real member.
            parsed = Some(pax_size_value(read, start + value_start, end - 1 - value_start, value)?);
        } else if complete && !body.contains(&b'=') {
            return Err(invalid("invalid PAX extended header"));
        }
        cursor = end;
    }
    Ok(parsed)
}

fn pax_size_value(read: &mut ReadAt<'_>, start: u64, len: u64, prefix: &[u8]) -> io::Result<PaxSize> {
    if len == 0 { return Ok(PaxSize::Empty); }
    let mut offset = 0;
    let mut magnitude = 0u128;
    let mut negative = false;
    let mut digits = false;
    while offset < len {
        let window;
        let bytes = if offset == 0 && !prefix.is_empty() {
            prefix
        } else {
            window = read_exact(read, start + offset, (len - offset).min(4096) as usize)?;
            &window
        };
        for &byte in bytes {
            let first = offset == 0;
            offset += 1;
            if first && matches!(byte, b'+' | b'-') {
                negative = byte == b'-';
                continue;
            }
            if !byte.is_ascii_digit() { return Ok(PaxSize::Invalid); }
            digits = true;
            let limit = i128::MAX as u128 + u128::from(negative);
            let Some(next) = magnitude.checked_mul(10)
                .and_then(|value| value.checked_add(u128::from(byte - b'0')))
                .filter(|value| *value <= limit) else { return Ok(PaxSize::Invalid); };
            magnitude = next;
        }
    }
    Ok(if !digits { PaxSize::Invalid }
        else if negative { PaxSize::Value(0) }
        else { u64::try_from(magnitude).map_or(PaxSize::Invalid, PaxSize::Value) })
}

fn sparse_span(
    header: &[u8],
    offset: u64,
    total: u64,
    read: &mut ReadAt<'_>,
) -> io::Result<(u64, u64)> {
    let mut previous_end = 0;
    if !sparse_map_valid(header, 386, 4, &mut previous_end) {
        return Err(invalid("invalid old GNU sparse extension map"));
    }
    let mut span = 0u64;
    let mut extended = header[482] != 0 && header[482] != b'0';
    while extended {
        let start = offset
            .checked_add(BLOCK)
            .and_then(|n| n.checked_add(span))
            .filter(|n| n.checked_add(BLOCK).is_some_and(|end| end <= total))
            .ok_or_else(truncated)?;
        let extension = read_exact(read, start, BLOCK as usize)?;
        if !sparse_map_valid(&extension, 0, 21, &mut previous_end) {
            return Err(invalid("invalid old GNU sparse extension map"));
        }
        span += BLOCK;
        extended = extension[504] != 0 && extension[504] != b'0';
    }
    Ok((span, previous_end))
}

fn sparse_map_valid(block: &[u8], start: usize, count: usize, previous_end: &mut u64) -> bool {
    for index in 0..count {
        let base = start + index * 24;
        let Some(offset) = number(&block[base..base + 12]) else {
            return false;
        };
        let Some(length) = number(&block[base + 12..base + 24]) else {
            return false;
        };
        if offset == 0 && length == 0 {
            continue;
        }
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if offset < *previous_end {
            return false;
        }
        *previous_end = end;
    }
    true
}

#[cfg(test)]
#[path = "../../tests/unit/formats/tar/tests.rs"]
mod tests;

pub(crate) fn header_identity(header: &[u8], file_size: u64) -> bool {
    let Ok(size) = header_size(header) else { return false; };
    BLOCK.saturating_add(size).saturating_add(padding(size)) <= file_size
        && header[..100].iter().any(|byte| *byte != 0)
        && (header[156] == 0 || (0x20..0x7f).contains(&header[156]))
        && [100..108, 108..116, 116..124, 136..148].into_iter()
            .all(|field| number(&header[field]).is_some())
}
