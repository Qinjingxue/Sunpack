//! Shared TAR member semantics for discovery, analysis and source manifests.
use std::collections::HashMap;
use std::io;

const BLOCK: u64 = 512;
pub(crate) const MAX_METADATA: usize = 1024 * 1024;
type ReadAt<'a> = dyn FnMut(u64, usize) -> io::Result<Vec<u8>> + 'a;

pub(crate) enum TarMetadata<'a> {
    Pax(&'a str, &'a str, usize),
    LongName(&'a str),
    LongLink(&'a str),
}
type Observe<'a> = Option<&'a mut dyn FnMut(TarMetadata<'_>)>;

#[derive(Default)]
pub(crate) struct TarState {
    global: HashMap<String, String>,
    local: HashMap<String, String>,
    long_name: Option<String>,
    long_link: Option<String>,
}

pub(crate) struct TarRecord {
    pub(crate) next: u64,
    pub(crate) payload_start: u64,
    pub(crate) physical_size: u64,
    pub(crate) member: Option<TarMember>,
}

pub(crate) struct TarMember {
    pub(crate) path: Option<String>,
    pub(crate) is_directory: bool,
    pub(crate) is_file: bool,
    pub(crate) size: u64,
    pub(crate) hard_link: Option<String>,
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
    header.len() == 512
        && number(&header[148..156]) == Some(checksum(header))
        && number(&header[124..136]).is_some()
}

pub(crate) fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}

fn text_bytes(field: &[u8]) -> &[u8] {
    &field[..field.iter().position(|b| *b == 0).unwrap_or(field.len())]
}

fn text(field: &[u8]) -> String {
    String::from_utf8_lossy(text_bytes(field)).into_owned()
}

fn read_exact(read: &mut ReadAt<'_>, start: u64, size: usize) -> io::Result<Vec<u8>> {
    let data = read(start, size)?;
    if data.len() != size {
        return Err(truncated());
    }
    Ok(data)
}

impl TarState {
    pub(crate) fn boundary_context_free(&self) -> bool {
        !self.global.contains_key("size") && !self.local.contains_key("size")
    }

    /// Metadata records use their own raw length. Overrides apply only to the
    /// following real member; an empty local value masks its global value.
    pub(crate) fn advance(
        &mut self,
        header: &[u8],
        offset: u64,
        total: u64,
        retain_path: bool,
        read: &mut ReadAt<'_>,
    ) -> io::Result<TarRecord> {
        self.advance_observed(header, offset, total, retain_path, read, None)
    }

    pub(crate) fn advance_observed(
        &mut self,
        header: &[u8],
        offset: u64,
        total: u64,
        retain_path: bool,
        read: &mut ReadAt<'_>,
        mut observe: Observe<'_>,
    ) -> io::Result<TarRecord> {
        if !valid_header(header) {
            return Err(invalid("invalid TAR member header"));
        }
        let raw_size = number(&header[124..136]).unwrap();
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
        let effective = |key: &str| {
            self.local
                .get(key)
                .or_else(|| self.global.get(key))
                .filter(|v| !v.is_empty())
        };
        let physical_size = if metadata {
            raw_size
        } else if let Some(value) = effective("size") {
            let size = value
                .parse::<i128>()
                .map_err(|_| invalid("invalid TAR extended size: size"))?;
            u64::try_from(size.max(0)).map_err(|_| invalid("invalid TAR extended size: size"))?
        } else {
            raw_size
        };
        let next = start
            .checked_add(physical_size)
            .and_then(|n| n.checked_add(padding(physical_size)))
            .filter(|n| *n <= total)
            .ok_or_else(truncated)?;
        if matches!(kind, b'x' | b'g') {
            let parsed = pax(read, start, raw_size, &mut observe)?;
            if kind == b'g' {
                for (key, value) in parsed {
                    if value.is_empty() {
                        self.global.remove(&key);
                    } else {
                        self.global.insert(key, value);
                    }
                }
            } else {
                self.local.extend(parsed);
            }
            return Ok(TarRecord {
                next,
                payload_start: start,
                physical_size,
                member: None,
            });
        }
        if matches!(kind, b'L' | b'K') {
            if raw_size > MAX_METADATA as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "GNU name metadata exceeds metadata budget",
                ));
            }
            let payload = read_exact(read, start, raw_size as usize)?;
            if kind == b'L' {
                let name = text(&payload);
                if let Some(observe) = observe {
                    observe(TarMetadata::LongName(&name));
                }
                self.long_name = Some(name);
            } else {
                let link = text(&payload);
                if let Some(observe) = observe {
                    observe(TarMetadata::LongLink(&link));
                }
                self.long_link = Some(link);
            }
            return Ok(TarRecord {
                next,
                payload_start: start,
                physical_size,
                member: None,
            });
        }

        let extended_path = effective("path").or(self.long_name.as_ref());
        let name = extended_path
            .map(|s| s.as_bytes())
            .unwrap_or_else(|| text_bytes(&header[..100]));
        // Match 7-Zip's old-normal, normal, symlink and GNU dump-directory rules.
        let is_directory = matches!(kind, b'5' | b'D')
            || (matches!(kind, 0 | b'0' | b'2') && name.last() == Some(&b'/'));
        let is_file = !is_directory && !matches!(kind, b'3' | b'4' | b'6') && !name.is_empty();
        let path = retain_path.then(|| {
            if let Some(path) = extended_path {
                return path.clone();
            }
            let name = text(&header[..100]);
            // GNU headers reuse this region for other metadata.
            if &header[257..263] == b"ustar\0" {
                let prefix = text(&header[345..500]);
                if !prefix.is_empty() {
                    return format!("{prefix}/{name}");
                }
            }
            name
        });
        let size = if kind == b'2' {
            effective("linkpath")
                .map(|s| s.len() as u64)
                .or_else(|| self.long_link.as_ref().map(|s| s.len() as u64))
                .unwrap_or_else(|| text_bytes(&header[157..257]).len() as u64)
        } else if kind == b'S' {
            let size = number(&header[483..495])
                .ok_or_else(|| invalid("invalid old GNU sparse logical size"))?;
            if sparse_end > size {
                return Err(invalid("old GNU sparse extent exceeds logical size"));
            }
            size
        } else {
            physical_size
        };
        let hard_link = (kind == b'1').then(|| {
            effective("linkpath")
                .or(self.long_link.as_ref())
                .cloned()
                .unwrap_or_else(|| text(&header[157..257]))
        });
        self.local.clear();
        self.long_name = None;
        self.long_link = None;
        Ok(TarRecord {
            next,
            payload_start: start,
            physical_size,
            member: Some(TarMember {
                path,
                is_directory,
                is_file,
                size,
                hard_link,
            }),
        })
    }
}

fn pax(
    read: &mut ReadAt<'_>,
    start: u64,
    size: u64,
    observe: &mut Observe<'_>,
) -> io::Result<HashMap<String, String>> {
    let mut records = HashMap::<String, String>::new();
    let mut retained = 0usize;
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
        if read_exact(read, start + end - 1, 1)?[0] != b'\n' {
            return Err(invalid("invalid PAX extended header"));
        }
        let body = &prefix[space + 1..prefix.len().min(length as usize - 1)];
        if let Some(equal) = body.iter().position(|b| *b == b'=') {
            if let Ok(key) = std::str::from_utf8(&body[..equal]) {
                let relevant = matches!(key, "path" | "linkpath" | "size");
                let observed = observe.is_some() && size <= 4 * MAX_METADATA as u64;
                if !relevant && !observed {
                    cursor = end;
                    continue;
                }
                let value_start = cursor + space as u64 + equal as u64 + 2;
                let value_len = (end - 1 - value_start) as usize;
                let old = records.get(key).map_or(0, String::len);
                if relevant
                    && (key.len() + value_len > MAX_METADATA
                        || retained.saturating_sub(old) + value_len > MAX_METADATA)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "PAX metadata exceeds metadata budget",
                    ));
                }
                let value = String::from_utf8(read_exact(read, start + value_start, value_len)?)
                    .map_err(|_| invalid("invalid PAX extended header"))?;
                if observed {
                    if let Some(observe) = observe.as_mut() {
                        observe(TarMetadata::Pax(key, &value, length as usize));
                    }
                }
                if relevant {
                    retained = retained.saturating_sub(old) + value.len();
                    records.insert(key.to_string(), value);
                }
            }
        } else if length <= prefix.len() as u64 {
            return Err(invalid("invalid PAX extended header"));
        }
        cursor = end;
    }
    Ok(records)
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
            Ok(block)
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
