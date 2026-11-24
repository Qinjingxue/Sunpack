/// Data following one RAR4 header. LONG_BLOCK stores its low word at offset
/// seven; large file headers extend it with HIGH_PACK_SIZE at offset 32.
/// Callers supply the complete declared header, including decrypted headers.
pub(crate) fn rar4_data_size(header: &[u8]) -> Option<u64> {
    let flags = u16::from_le_bytes(header.get(3..5)?.try_into().ok()?);
    if flags & 0x8000 == 0 {
        return Some(0);
    }
    let low = u32::from_le_bytes(header.get(7..11)?.try_into().ok()?) as u64;
    let high = if header[2] == 0x74 && flags & 0x0100 != 0 {
        // Both high size words belong to the fixed large-file header.
        let large = header.get(32..40)?;
        u64::from(u32::from_le_bytes(large[..4].try_into().ok()?)) << 32
    } else {
        0
    };
    Some(high | low)
}
/// RAR's unsigned, at most 64-bit variable integer. Shared by relation and
/// password readers so malformed fields cannot acquire different identities.
pub(crate) fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in data.get(offset..)?.iter().take(10).enumerate() {
        if index == 9 && byte & 0xfe != 0 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, offset + index + 1));
        }
    }
    None
}

pub(crate) fn rar5_header_len(data: &[u8]) -> Option<usize> {
    let (size, start) = read_vint(data, 4)?;
    start
        .checked_add(usize::try_from(size).ok()?)
        .filter(|&n| n <= 2 * 1024 * 1024)
}

pub(crate) struct Rar5MainHeader {
    pub(crate) archive_flags: u64,
    pub(crate) volume_number: Option<u32>,
    pub(crate) end: usize,
    pub(crate) service_offset: Option<u64>,
}

pub(crate) fn rar5_main_header(data: &[u8], offset: usize) -> Option<Rar5MainHeader> {
    let data = data.get(offset..)?;
    let end = rar5_header_len(data)?;
    let header = data.get(..end)?;
    let stored = u32::from_le_bytes(header.get(..4)?.try_into().ok()?);
    if crc32fast::hash(&header[4..]) != stored {
        return None;
    }
    let (_, start) = read_vint(header, 4)?;
    let fields = rar5_common_fields(header, start)?;
    let (archive_flags, volume_number) = fields.main_volume(header)?;
    let extra_size = usize::try_from(fields.extra_size).ok()?;
    let service_offset = locator_service_offset(&header[header.len() - extra_size..]);
    Some(Rar5MainHeader {
        archive_flags,
        volume_number,
        end: offset + end,
        service_offset,
    })
}

/// Largest nonzero locator offset relative to the main header. An unknown or
/// malformed optional record does not establish a required extent.
fn locator_service_offset(mut extras: &[u8]) -> Option<u64> {
    while !extras.is_empty() {
        let (size, start) = read_vint(extras, 0)?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        let record = extras.get(start..end)?;
        let (kind, cursor) = read_vint(record, 0)?;
        if kind == 1 {
            let (flags, mut cursor) = read_vint(record, cursor)?;
            let mut furthest = 0;
            for flag in [1, 2] {
                if flags & flag != 0 {
                    let (offset, next) = read_vint(record, cursor)?;
                    furthest = furthest.max(offset);
                    cursor = next;
                }
            }
            return (furthest != 0).then_some(furthest);
        }
        extras = &extras[end..];
    }
    None
}

pub(crate) struct Rar5CommonFields {
    pub(crate) kind: u64,
    pub(crate) flags: u64,
    pub(crate) extra_size: u64,
    pub(crate) data_size: u64,
    pub(crate) body: usize,
}

impl Rar5CommonFields {
    /// Reads main-header fields from a complete, CRC-checked header.
    pub(crate) fn main_volume(&self, header: &[u8]) -> Option<(u64, Option<u32>)> {
        if self.kind != 1 {
            return None;
        }
        let extra = usize::try_from(self.extra_size).ok()?;
        let fields = header.get(..header.len().checked_sub(extra)?)?;
        let (archive_flags, cursor) = read_vint(fields, self.body)?;
        let number = if archive_flags & 2 != 0 {
            let n = u32::try_from(read_vint(fields, cursor)?.0).ok()?;
            if archive_flags & 1 == 0 || n == 0 || n.checked_add(1).is_none() {
                return None;
            }
            Some(n)
        } else {
            None
        };
        Some((archive_flags, number))
    }
}

pub(crate) fn rar5_common_fields(header: &[u8], start: usize) -> Option<Rar5CommonFields> {
    let (kind, cursor) = read_vint(header, start)?;
    let (flags, mut body) = read_vint(header, cursor)?;
    let extra_size = if flags & 1 != 0 {
        let (size, next) = read_vint(header, body)?;
        body = next;
        size
    } else {
        0
    };
    let data_size = if flags & 2 != 0 {
        let (size, next) = read_vint(header, body)?;
        body = next;
        size
    } else {
        0
    };
    Some(Rar5CommonFields { kind, flags, extra_size, data_size, body })
}

/// ENDARC optional data CRC precedes the zero-based current volume number.
/// The caller has already validated the complete (possibly decrypted) CRC.
pub(crate) fn rar4_end_volume(header: &[u8]) -> Option<u32> {
    if *header.get(2)? != 0x7b {
        return None;
    }
    let flags = u16::from_le_bytes(header.get(3..5)?.try_into().ok()?);
    if flags & 8 == 0 {
        return None;
    }
    let start = 7 + if flags & 2 != 0 { 4 } else { 0 };
    Some(
        u32::from(u16::from_le_bytes(
            header.get(start..start + 2)?.try_into().ok()?,
        )) + 1,
    )
}
