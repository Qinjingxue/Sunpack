/// Disk-relative directory coordinates retained once with the terminal fact.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelationDirectory {
    pub disk: u32,
    pub cd_disk: u32,
    pub offset: u64,
    pub size: u64,
    pub entries: u64,
    pub disk_entries: u64,
    pub end: u64,
}

/// Read one directory record at a time. No payload reads or directory-sized
/// allocation; callers discard tentative matches if the extent is incomplete.
pub(crate) fn visit_relation_directory(
    path: &str,
    directory: RelationDirectory,
    mut visit: impl FnMut(&super::CentralDirectoryRecord<'_>, super::zip64::CentralValues),
) -> std::io::Result<bool> {
    let reader = crate::io::reader::ManagedReader::open(path)?;
    let count = directory.disk_entries;
    let start = if directory.cd_disk == directory.disk {
        let Some(start) = directory.end.checked_sub(directory.size) else {
            return Ok(false);
        };
        if directory.offset > start {
            return Ok(false);
        }
        if directory.entries != count {
            return Ok(false);
        }
        start
    } else {
        0
    };
    if directory.end > reader.len() || count > (directory.end - start) / 46 {
        return Ok(false);
    }
    let mut cursor = start;
    for _ in 0..count {
        let fixed = reader.read_cached_at(cursor, 46)?;
        let Some(len) = super::central_directory_record_len(&fixed) else {
            return Ok(false);
        };
        if cursor
            .checked_add(len as u64)
            .is_none_or(|end| end > directory.end)
        {
            return Ok(false);
        }
        let full = reader.read_cached_at(cursor, len)?;
        let Some(record) = super::parse_central_directory_record(&full, 0, full.len()) else {
            return Ok(false);
        };
        let Some(values) = super::zip64::central_entry_values(&full, record.extra) else {
            return Ok(false);
        };
        if values.disk > u64::from(directory.disk) {
            return Ok(false);
        }
        visit(&record, values);
        cursor += len as u64;
    }
    super::central_directory_complete(cursor, directory.end, |at, len| {
        reader.read_cached_at(at, len)
    })
}

#[derive(Debug, Clone)]
pub(crate) struct RelationLocalKey {
    pub name: Vec<u8>,
    pub fields: RelationLocalFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RelationLocalFields {
    method: u16,
    flags: u16,
    crc32: u32,
    compressed: u64,
    uncompressed: u64,
}

impl RelationLocalFields {
    pub(crate) fn new(
        method: u16,
        flags: u16,
        crc32: u32,
        compressed: u64,
        uncompressed: u64,
    ) -> Self {
        let descriptor = flags & 8 != 0;
        Self {
            method,
            flags,
            crc32: if descriptor { 0 } else { crc32 },
            compressed: if descriptor { 0 } else { compressed },
            uncompressed: if descriptor { 0 } else { uncompressed },
        }
    }
}

pub(crate) fn relation_local_key(
    path: &str,
    offset: u64,
) -> std::io::Result<Option<RelationLocalKey>> {
    let reader = crate::io::reader::ManagedReader::open(path)?;
    let fixed = reader.read_cached_at(offset, 30)?;
    if fixed.len() < 30 || !fixed.starts_with(b"PK\x03\x04") {
        return Ok(None);
    }
    let Some(len) = super::relation_local_header_len(&fixed, 0) else {
        return Ok(None);
    };
    let bytes = reader.read_cached_at(offset, len)?;
    let Some(local) = super::parse_local_header(&bytes, 0) else {
        return Ok(None);
    };
    // Central-directory encryption may deliberately mask local names.
    if local.flags & 0x2000 != 0 {
        return Ok(None);
    }
    let mut central = [0u8; 46];
    central[20..28].copy_from_slice(&bytes[18..26]);
    let Some(values) = super::zip64::central_entry_values(&central, &local.extra) else {
        return Ok(None);
    };
    Ok(Some(RelationLocalKey {
        name: local.name,
        fields: RelationLocalFields::new(
            local.method,
            local.flags,
            local.crc32,
            values.compressed,
            values.uncompressed,
        ),
    }))
}
