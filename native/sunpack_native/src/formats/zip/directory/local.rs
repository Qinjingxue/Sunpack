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

/// Relation probes read a tail window rather than a whole-file slice. Keep
/// the same validated extent and check its physical locator before using IDs.
pub(crate) fn zip64_relation_disk_numbers(
    data: &[u8],
    eocd: usize,
    tail_start: u64,
) -> Option<(u32, u32)> {
    let found = zip64::locate_end_record(eocd as u64, None, |offset, size| {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        Ok(data
            .get(start..start.saturating_add(size))
            .unwrap_or_default()
            .to_vec())
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
