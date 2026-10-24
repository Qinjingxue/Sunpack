fn parse_local_header(data: &[u8], offset: usize) -> Option<LocalHeader> {
    if offset + LOCAL_HEADER_LEN > data.len() || &data[offset..offset + 4] != LFH_SIG {
        return None;
    }
    let name_len = u16_le(data, offset + 26);
    let extra_len = u16_le(data, offset + 28);
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let data_start = extra_start.checked_add(extra_len as usize)?;
    if data_start > data.len() {
        return None;
    }
    Some(LocalHeader {
        offset,
        flags: u16_le(data, offset + 6),
        method: u16_le(data, offset + 8),
        crc32: u32_le(data, offset + 14),
        compressed_size: u32_le(data, offset + 18),
        uncompressed_size: u32_le(data, offset + 22),
        name: data[name_start..extra_start].to_vec(),
        extra: data[extra_start..data_start].to_vec(),
        extra_offset: extra_start,
        name_len,
        extra_len,
    })
}

fn parse_zip64_extra_tolerant(extra: &[u8], absolute_extra_offset: usize) -> Option<Zip64Extra> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16_le(extra, pos);
        let size = u16_le(extra, pos + 2) as usize;
        let value_start = pos + 4;
        let value_end = value_start.saturating_add(size).min(extra.len());
        if header_id == 0x0001 {
            let mut values = Vec::new();
            let mut cursor = value_start;
            while cursor + 8 <= value_end {
                values.push(u64_le(extra, cursor));
                cursor += 8;
            }
            let (disk_start, disk_start_offset) = if cursor + 4 == value_end {
                (
                    Some(u32_le(extra, cursor)),
                    Some(absolute_extra_offset + cursor),
                )
            } else {
                (None, None)
            };
            return Some(Zip64Extra {
                values,
                disk_start,
                disk_start_offset,
                stored_size: size,
            });
        }
        let next = value_start.saturating_add(size);
        if next <= pos || next > extra.len() {
            break;
        }
        pos = next;
    }
    None
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

impl From<zip64::LocatedEndRecord> for Zip64Eocd {
    fn from(found: zip64::LocatedEndRecord) -> Self {
        Self {
            offset: found.offset as usize,
            end: (found.offset + 12 + found.record.record_size) as usize,
            total_entries: found.record.total_entries,
            cd_size: found.record.cd_size,
            cd_offset: found.record.cd_offset,
        }
    }
}

impl From<zip64::LocatedEndRecord> for Zip64Locator {
    fn from(found: zip64::LocatedEndRecord) -> Self {
        let offset = (found.offset + 12 + found.record.record_size) as usize;
        Self {
            offset,
            end: offset + 20,
            zip64_eocd_offset: found.locator.record_offset,
            total_disks: found.locator.total_disks,
        }
    }
}
