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
                (Some(u32_le(extra, cursor)), Some(absolute_extra_offset + cursor))
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

fn find_zip64_eocd(data: &[u8], before: usize) -> Option<Zip64Eocd> {
    let pos = memmem::rfind(&data[..before.min(data.len())], ZIP64_EOCD_SIG)?;
    if pos + 56 > data.len() {
        return None;
    }
    let record_size = u64_le(data, pos + 4);
    let end = pos
        .checked_add(12)?
        .checked_add(usize::try_from(record_size).ok()?)?;
    if end > data.len() || end < pos + 56 {
        return None;
    }
    Some(Zip64Eocd {
        offset: pos,
        end,
        total_entries: u64_le(data, pos + 32),
        cd_size: u64_le(data, pos + 40),
        cd_offset: u64_le(data, pos + 48),
    })
}

fn find_zip64_locator(data: &[u8], eocd_offset: usize) -> Option<Zip64Locator> {
    let pos = memmem::rfind(&data[..eocd_offset.min(data.len())], ZIP64_LOCATOR_SIG)?;
    if pos + 20 > data.len() {
        return None;
    }
    Some(Zip64Locator {
        offset: pos,
        end: pos + 20,
        zip64_eocd_offset: u64_le(data, pos + 8),
        total_disks: u32_le(data, pos + 16),
    })
}
