fn find_eocd_record(data: &[u8], allow_trailing_junk: bool) -> Option<EocdInfo> {
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
}

/// Resolve the central-directory location from the EOCD, honouring ZIP64.
///
/// Per APPNOTE 4.3.14/4.3.15 a ZIP64 archive places the Zip64 end of central
/// directory record (56 bytes, size field 44) and its 20-byte locator between
/// the central directory and the plain EOCD.  When that 76-byte block is
/// present, the 8-byte fields in the Zip64 record are authoritative and the
/// central directory ends where the Zip64 record starts, not at the EOCD.
/// Otherwise the plain EOCD fields are used and the directory ends at the
/// EOCD.  When the naive `directory_end - cd_size` position does not carry a
/// central-directory signature but the declared offset does, the declared
/// offset wins (SFX/junk tolerance), mirroring inspect.rs.
fn resolve_central_directory(data: &[u8], eocd: &EocdInfo) -> ResolvedCentralDirectory {
    let mut declared_offset = u64::from(eocd.cd_offset);
    let mut declared_size = u64::from(eocd.cd_size);
    let mut total_entries = u64::from(eocd.total_entries);
    let mut disk_entries = u64::from(eocd.disk_entries);
    let mut directory_end = eocd.offset as u64;
    if eocd.offset >= 76 {
        let block_start = eocd.offset - 76;
        let block = &data[block_start..eocd.offset];
        if &block[..4] == ZIP64_EOCD_SIG
            && u64_le(block, 4) == 44
            && &block[56..60] == ZIP64_LOCATOR_SIG
        {
            declared_offset = u64_le(block, 48);
            declared_size = u64_le(block, 40);
            total_entries = u64_le(block, 32);
            disk_entries = u64_le(block, 24);
            directory_end = block_start as u64;
        }
    }
    let naive = directory_end.saturating_sub(declared_size) as usize;
    let declared = declared_offset as usize;
    let physical_offset = if !zip_has_signature_at(data, naive, CD_SIG)
        && zip_has_signature_at(data, declared, CD_SIG)
    {
        declared
    } else {
        naive
    };
    let end = physical_offset.saturating_add(declared_size as usize).min(data.len());
    let archive_offset = physical_offset.saturating_sub(declared_offset as usize);
    ResolvedCentralDirectory {
        physical_offset,
        end,
        archive_offset,
        declared_offset: declared,
        declared_size: declared_size as usize,
        total_entries,
        disk_entries,
    }
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
    let comment_len = u16_le(data, offset + 32) as usize;
    let name_start = offset.checked_add(46)?;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let comment_start = extra_start.checked_add(extra_len as usize)?;
    let record_end = comment_start.checked_add(comment_len)?;
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
    CdWalk {
        end: pos,
        count,
    }
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

