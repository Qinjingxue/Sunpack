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

pub(crate) fn rar5_main_volume(data: &[u8], offset: usize) -> Option<(u64, Option<u32>)> {
    let data = data.get(offset..)?;
    let end = rar5_header_len(data)?;
    let header = data.get(..end)?;
    let stored = u32::from_le_bytes(header.get(..4)?.try_into().ok()?);
    if crc32fast::hash(&header[4..]) != stored {
        return None;
    }
    let (_, start) = read_vint(header, 4)?;
    let (kind, cursor) = read_vint(header, start)?;
    if kind != 1 {
        return None;
    }
    let (flags, mut cursor) = read_vint(header, cursor)?;
    let extra = if flags & 1 != 0 {
        let (n, next) = read_vint(header, cursor)?;
        cursor = next;
        usize::try_from(n).ok()?
    } else {
        0
    };
    if flags & 2 != 0 {
        cursor = read_vint(header, cursor)?.1;
    }
    // The extra area is not part of the main fields, even though its bytes
    // are covered by the same CRC.
    let fields = header.get(..end.checked_sub(extra)?)?;
    let (archive_flags, cursor) = read_vint(fields, cursor)?;
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
