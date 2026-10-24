pub(crate) fn find_eocd_record(data: &[u8], allow_trailing_junk: bool) -> Option<EocdInfo> {
    let mut pos = data
        .windows(EOCD_SIG.len())
        .rposition(|window| window == EOCD_SIG)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() && (allow_trailing_junk || end == data.len()) {
                return Some(EocdInfo {
                    offset: pos,
                    end,
                    disk_entries: u16_le(data, pos + 8),
                    total_entries: u16_le(data, pos + 10),
                    cd_size: u32_le(data, pos + 12),
                    cd_offset: u32_le(data, pos + 16),
                });
            }
        }
        if pos == 0 {
            return None;
        }
        pos = data[..pos]
            .windows(EOCD_SIG.len())
            .rposition(|window| window == EOCD_SIG)?;
    }
}

/// Resolved central-directory location for an archive.
///
/// `physical_offset` is where the `PK\x01\x02` signature is actually found,
/// `end` is the observed end of the central directory and `archive_offset`
/// is the SFX/prefix shift between the declared and physical offsets.
#[derive(Clone, Copy)]
struct ResolvedCentralDirectory {
    physical_offset: usize,
    end: usize,
    archive_offset: usize,
    declared_offset: usize,
    declared_size: usize,
    total_entries: u64,
    disk_entries: u64,
    zip64: Option<zip64::LocatedEndRecord>,
}

/// Resolve the central-directory location from the EOCD, honouring ZIP64.
///
/// ZIP64 record geometry is resolved by the shared locator used by file and
/// multi-volume analysis. Prefix shifts are inferred from the physical directory.
fn resolve_central_directory(
    data: &[u8],
    eocd: &EocdInfo,
) -> Result<ResolvedCentralDirectory, &'static str> {
    let mut declared_offset = u64::from(eocd.cd_offset);
    let mut declared_size = u64::from(eocd.cd_size);
    let mut total_entries = u64::from(eocd.total_entries);
    let mut disk_entries = u64::from(eocd.disk_entries);
    let mut directory_end = eocd.offset as u64;
    let zip64 = zip64::locate_end_record(eocd.offset as u64, None, |offset, size| {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        Ok(data
            .get(start..start.saturating_add(size))
            .unwrap_or_default()
            .to_vec())
    })
    .map_err(|error| error.code())?;
    if let Some(found) = zip64 {
        declared_offset = found.record.cd_offset;
        declared_size = found.record.cd_size;
        total_entries = found.record.total_entries;
        disk_entries = found.record.disk_entries;
        directory_end = found.offset;
    }
    let naive = usize::try_from(directory_end.saturating_sub(declared_size))
        .map_err(|_| "central_directory_size_out_of_range")?;
    let declared =
        usize::try_from(declared_offset).map_err(|_| "central_directory_offset_out_of_range")?;
    let declared_size =
        usize::try_from(declared_size).map_err(|_| "central_directory_size_out_of_range")?;
    let physical_offset = if !zip_has_signature_at(data, naive, CD_SIG)
        && zip_has_signature_at(data, declared, CD_SIG)
    {
        declared
    } else {
        naive
    };
    let end = physical_offset
        .saturating_add(declared_size)
        .min(data.len());
    let archive_offset = physical_offset.saturating_sub(declared);
    Ok(ResolvedCentralDirectory {
        physical_offset,
        end,
        archive_offset,
        declared_offset: declared,
        declared_size,
        total_entries,
        disk_entries,
        zip64,
    })
}

struct CentralDirectoryRecord<'a> {
    offset: usize,
    end: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    name: &'a [u8],
    extra: &'a [u8],
    extra_offset: usize,
    disk_number_start: u16,
    local_header_offset: u32,
}

pub(crate) fn central_directory_record_len(header: &[u8]) -> Option<usize> {
    if header.len() < 46 || !header.starts_with(CD_SIG) {
        return None;
    }
    Some(
        46 + u16_le(header, 28) as usize
            + u16_le(header, 30) as usize
            + u16_le(header, 32) as usize,
    )
}

fn parse_central_directory_record(
    data: &[u8],
    offset: usize,
    expected_end: usize,
) -> Option<CentralDirectoryRecord<'_>> {
    if offset >= expected_end
        || offset.checked_add(46)? > data.len()
        || data.get(offset..offset + 4) != Some(CD_SIG)
    {
        return None;
    }
    let name_len = u16_le(data, offset + 28);
    let extra_len = u16_le(data, offset + 30);
    let name_start = offset.checked_add(46)?;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let comment_start = extra_start.checked_add(extra_len as usize)?;
    let record_end = offset.checked_add(central_directory_record_len(&data[offset..])?)?;
    if record_end > data.len() || record_end > expected_end {
        return None;
    }
    Some(CentralDirectoryRecord {
        offset,
        end: record_end,
        flags: u16_le(data, offset + 8),
        method: u16_le(data, offset + 10),
        crc32: u32_le(data, offset + 16),
        compressed_size: u32_le(data, offset + 20),
        uncompressed_size: u32_le(data, offset + 24),
        name_len,
        extra_len,
        name: &data[name_start..extra_start],
        extra: &data[extra_start..comment_start],
        extra_offset: extra_start,
        disk_number_start: u16_le(data, offset + 34),
        local_header_offset: u32_le(data, offset + 42),
    })
}

fn walk_central_directory_range(data: &[u8], offset: usize, expected_end: Option<usize>) -> CdWalk {
    let mut pos = offset;
    let mut count = 0usize;
    while let Some(record) = parse_central_directory_record(data, pos, data.len()) {
        pos = record.end;
        count += 1;
        if expected_end.is_some_and(|end| pos >= end) {
            break;
        }
    }
    CdWalk { end: pos, count }
}

fn parse_central_directory_entries(
    data: &[u8],
    offset: usize,
    expected_end: usize,
) -> Vec<CentralEntry> {
    let mut entries = Vec::new();
    let mut pos = offset;
    while let Some(record) = parse_central_directory_record(data, pos, expected_end) {
        entries.push(CentralEntry {
            offset: record.offset,
            flags: record.flags,
            method: record.method,
            crc32: record.crc32,
            compressed_size: record.compressed_size,
            uncompressed_size: record.uncompressed_size,
            name_len: record.name_len,
            extra_len: record.extra_len,
            name: record.name.to_vec(),
            extra: record.extra.to_vec(),
            extra_offset: record.extra_offset,
            disk_number_start: record.disk_number_start,
            local_header_offset: record.local_header_offset,
        });
        pos = record.end;
    }
    entries
}
