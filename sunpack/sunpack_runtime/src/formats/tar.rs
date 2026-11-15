//! Shared TAR member semantics for discovery and analysis.
use crate::io::reader::CachedBytes;
use std::io;

const BLOCK: u64 = 512;
const MAX_METADATA: usize = 1024 * 1024;
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
            let value_len = (end - 1 - value_start) as usize;
            if value_len > MAX_METADATA - "size".len() {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "PAX metadata exceeds metadata budget",
                ));
            }
            let remainder;
            let value = if complete {
                value
            } else {
                remainder = read_exact(read, start + value_start, value_len)?;
                &remainder
            };
            let value =
                std::str::from_utf8(value).map_err(|_| invalid("invalid PAX extended header"))?;
            // Keep invalid numeric values dormant until this override applies.
            // A later record can mask or replace them before any real member.
            parsed = Some(if value.is_empty() {
                PaxSize::Empty
            } else {
                value
                    .parse::<i128>()
                    .ok()
                    .and_then(|size| u64::try_from(size.max(0)).ok())
                    .map_or(PaxSize::Invalid, PaxSize::Value)
            });
        } else if complete && !body.contains(&b'=') {
            return Err(invalid("invalid PAX extended header"));
        }
        cursor = end;
    }
    Ok(parsed)
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
mod tests {
    use super::*;

    fn header_with_base256_size(size: u64) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..4].copy_from_slice(b"file");
        header[124] = 0x80;
        header[128..136].copy_from_slice(&size.to_be_bytes());
        header[156] = b'0';
        let checksum = format!("{:06o}\0 ", checksum(&header));
        header[148..156].copy_from_slice(checksum.as_bytes());
        header
    }

    #[test]
    fn gnu_names_skip_payload_reads_but_keep_checked_boundaries() {
        // No body allocation is needed even above the former metadata quota.
        // Checking only ordinary members would miss an early metadata return.
        for kind in [b'L', b'K'] {
            let size = MAX_METADATA as u64 + 1;
            let mut header = header_with_base256_size(size);
            header[156] = kind;
            let total = BLOCK + size + padding(size);
            let mut state = TarState::default();
            let mut read = |_, _| unreachable!("GNU names must not read their payload");
            assert_eq!(
                state
                    .advance_validated(&header, size, 0, total, &mut read)
                    .unwrap(),
                total
            );
            for (size, offset, total) in [
                (size, 0, total - 1),
                (size, u64::MAX - BLOCK + 1, u64::MAX),
                (u64::MAX - BLOCK + 1, 0, u64::MAX),
                (u64::MAX - BLOCK, 0, u64::MAX),
            ] {
                assert_eq!(
                    state
                        .advance_validated(&header, size, offset, total, &mut read)
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[test]
    fn huge_base256_member_size_is_out_of_range_instead_of_wrapping() {
        // offset(0) + 512 + (2^64 - 512) wraps to 0 without saturation, which
        // would re-walk the same header and report a valid archive.
        let header = header_with_base256_size(u64::MAX - 511);
        let error = TarState::default()
            .advance(&header, 0, 3 * BLOCK, &mut |_, _| {
                unreachable!("truncated member must be rejected before reading its data")
            })
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn local_pax_size_masks_global_only_for_the_next_member() {
        let mut state = TarState::default();
        let mut header = [0u8; 512];
        let total = 2 * BLOCK;
        for (kind, body) in [(b'g', b"10 size=x\n".as_slice()), (b'x', b"8 size=\n")] {
            header[156] = kind;
            state
                .advance_validated(&header, body.len() as u64, 0, total, &mut |start, size| {
                    let offset = (start - BLOCK) as usize;
                    Ok(CachedBytes::Owned(body[offset..offset + size].to_vec()))
                })
                .unwrap();
        }
        header[156] = b'0';
        let read = &mut |_, _| unreachable!();
        assert_eq!(
            state.advance_validated(&header, 1, 0, total, read).unwrap(),
            total
        );
        assert_eq!(
            state
                .advance_validated(&header, 1, 0, total, read)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    // Generate fixed sparse records on demand: ordinary TAR samples never
    // cross the old extension quota; no 32 MiB fixture is retained here.
    #[test]
    fn sparse_extensions_follow_flags_and_physical_boundaries() {
        let count = 65_537;
        let total = (count + 1) * BLOCK;
        let mut header = [0u8; 512];
        header[482] = 1;
        let mut reads = 0;
        let mut read = |start, size| {
            assert_eq!(size, 512);
            reads += 1;
            let mut block = vec![0u8; size];
            block[504] = u8::from(start + BLOCK < total);
            Ok(CachedBytes::Owned(block))
        };
        assert_eq!(
            sparse_span(&header, 0, total, &mut read).unwrap(),
            (count * BLOCK, 0)
        );
        assert_eq!(reads, count);
        assert_eq!(
            sparse_span(&header, 0, BLOCK, &mut |_, _| unreachable!())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            sparse_span(
                &header,
                u64::MAX - BLOCK,
                u64::MAX,
                &mut |_, _| unreachable!()
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
