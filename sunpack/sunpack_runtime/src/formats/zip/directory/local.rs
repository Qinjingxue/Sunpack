/// Cheap fixed-header validation before a relation probe commits variable I/O.
pub(crate) fn relation_local_header_len(data: &[u8], offset: usize) -> Option<usize> {
    let fixed = data.get(offset..offset.checked_add(30)?)?;
    if !fixed.starts_with(LFH_SIG)
        || u16_le(fixed, 4) > 1000
        || u16_le(fixed, 8) > 99
        || u16_le(fixed, 26) == 0
    {
        return None;
    }
    Some(30 + usize::from(u16_le(fixed, 26)) + usize::from(u16_le(fixed, 28)))
}

/// A local-header prefix at a validated older EOCD end is a reason to
/// defer a whole-archive delivery, not proof that an independent ZIP exists.
pub(crate) fn zip_continuation_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 10
        && bytes.starts_with(LFH_SIG)
        && (10..=100).contains(&u16_le(bytes, 4))
        && u16_le(bytes, 6) & 0xc000 == 0
        && (bytes.len() < LOCAL_HEADER_LEN || u16_le(bytes, 26) != 0)
}

/// Local geometry only. The declared payload can extend past the visible file.
pub(crate) struct ZipLocalMember {
    pub(crate) data_start: u64,
    pub(crate) data_end: u64,
    pub(crate) flags: u16,
    pub(crate) method: u16,
}

pub(crate) fn zip_local_fixed_plausible(fixed: &[u8]) -> bool {
    fixed.len() >= LOCAL_HEADER_LEN
        && fixed.starts_with(LFH_SIG)
        && u16_le(fixed, 4) <= 100
        && u16_le(fixed, 6) & 0xc000 == 0
        && u16_le(fixed, 26) != 0
}

pub(crate) fn read_zip_local_member<E, B: AsRef<[u8]>>(
    fixed: &[u8],
    offset: u64,
    size: u64,
    mut read: impl FnMut(u64, usize) -> Result<B, E>,
) -> Result<Option<ZipLocalMember>, E> {
    if !zip_local_fixed_plausible(fixed) {
        return Ok(None);
    }
    let name_len = u64::from(u16_le(fixed, 26));
    let extra_len = usize::from(u16_le(fixed, 28));
    let Some(extra_start) = offset.checked_add(LOCAL_HEADER_LEN as u64 + name_len) else {
        return Ok(None);
    };
    let Some(data_start) = extra_start.checked_add(extra_len as u64).filter(|end| *end <= size) else {
        return Ok(None);
    };
    let compressed_32 = u32_le(fixed, 18);
    let uncompressed_32 = u32_le(fixed, 22);
    let mut compressed_size = u64::from(compressed_32);
    if compressed_32 == u32::MAX || uncompressed_32 == u32::MAX {
        let extra = read(extra_start, extra_len)?;
        let Some(zip64) = zip64::extra_field(extra.as_ref()) else {
            return Ok(None);
        };
        let mut cursor = 0;
        if uncompressed_32 == u32::MAX {
            if zip64.len() < 8 {
                return Ok(None);
            }
            cursor = 8;
        }
        if compressed_32 == u32::MAX {
            let Some(value) = zip64.get(cursor..cursor + 8) else {
                return Ok(None);
            };
            compressed_size = u64::from_le_bytes(value.try_into().unwrap());
        }
    }
    let Some(data_end) = data_start.checked_add(compressed_size) else {
        return Ok(None);
    };
    Ok(Some(ZipLocalMember {
        data_start,
        data_end,
        flags: u16_le(fixed, 6),
        method: u16_le(fixed, 8),
    }))
}

/// Relation probes read a tail window rather than a whole-file slice. Keep
/// the same validated extent and check its physical locator before using IDs.
pub(crate) fn zip64_relation_disk_numbers(
    data: &[u8],
    eocd: usize,
    tail_start: u64,
) -> Option<(u32, u32)> {
    let found = zip64::locate_end_record(eocd as u64, None, |offset, size| {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        Ok(data.get(start..start.saturating_add(size)).unwrap_or_default())
    })
    .ok()??;
    if found.locator.record_offset != tail_start.checked_add(found.offset)?
        || found.locator.record_disk != found.record.disk
        || found.locator.total_disks != found.record.disk.checked_add(1)?
    {
        return None;
    }
    Some((found.record.disk, found.record.cd_disk))
}

struct LocalHeader<'a> {
    flags: u16,
    method: u16,
    crc32: u32,
    name: &'a [u8],
    extra: &'a [u8],
}

fn parse_local_header(data: &[u8]) -> Option<LocalHeader<'_>> {
    if data.len() < LOCAL_HEADER_LEN || !data.starts_with(LFH_SIG) {
        return None;
    }
    let name_end = LOCAL_HEADER_LEN + usize::from(u16_le(data, 26));
    let extra_end = name_end + usize::from(u16_le(data, 28));
    Some(LocalHeader {
        flags: u16_le(data, 6),
        method: u16_le(data, 8),
        crc32: u32_le(data, 14),
        name: data.get(LOCAL_HEADER_LEN..name_end)?,
        extra: data.get(name_end..extra_end)?,
    })
}

fn matching_descriptor_len(
    data: &[u8],
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> Option<usize> {
    for (len, has_sig, zip64) in [
        (16usize, true, false),
        (24, true, true),
        (12, false, false),
        (20, false, true),
    ] {
        if len > data.len() {
            continue;
        }
        let base = if has_sig {
            if !data.starts_with(DD_SIG) {
                continue;
            }
            4
        } else {
            0
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if crc32 == expected_crc32
            && compressed == expected_compressed
            && uncompressed == expected_uncompressed
        {
            return Some(len);
        }
    }
    None
}
