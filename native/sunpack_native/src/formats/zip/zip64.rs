// Shared, allocation-free ZIP64 field parsing. Callers supply already-read
// bytes so all analysis views retain their existing read budgets and layouts.
const OFFSET_LIMIT: u64 = 1 << 63;

#[derive(Clone, Copy)]
pub(crate) struct EndRecord {
    pub record_size: u64,
    pub disk: u32,
    pub cd_disk: u32,
    pub disk_entries: u64,
    pub total_entries: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Locator {
    pub record_disk: u32,
    pub record_offset: u64,
    pub total_disks: u32,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(crate) fn parse_record(bytes: &[u8]) -> Result<EndRecord, &'static str> {
    if bytes.len() < 56 || !bytes.starts_with(b"PK\x06\x06") {
        return Err("zip64_eocd_invalid");
    }
    let record = EndRecord {
        record_size: u64_at(bytes, 4),
        disk: u32_at(bytes, 16),
        cd_disk: u32_at(bytes, 20),
        disk_entries: u64_at(bytes, 24),
        total_entries: u64_at(bytes, 32),
        cd_size: u64_at(bytes, 40),
        cd_offset: u64_at(bytes, 48),
    };
    if record.record_size < 44 || record.record_size >= 1 << 62 {
        return Err("zip64_eocd_size_invalid");
    }
    if record.cd_size >= OFFSET_LIMIT
        || record.cd_offset >= OFFSET_LIMIT
        || record
            .cd_offset
            .checked_add(record.cd_size)
            .is_none_or(|end| end >= OFFSET_LIMIT)
    {
        return Err("zip64_central_directory_overflow");
    }
    Ok(record)
}

pub(crate) fn parse_locator(bytes: &[u8]) -> Result<Locator, &'static str> {
    if bytes.len() < 20 || !bytes.starts_with(b"PK\x06\x07") {
        return Err("zip64_locator_invalid");
    }
    let locator = Locator {
        record_disk: u32_at(bytes, 4),
        record_offset: u64_at(bytes, 8),
        total_disks: u32_at(bytes, 16),
    };
    if locator.record_offset >= OFFSET_LIMIT {
        return Err("zip64_locator_offset_overflow");
    }
    Ok(locator)
}

#[derive(Clone, Copy)]
pub(crate) struct LocatedEndRecord {
    pub offset: u64,
    pub record: EndRecord,
    pub locator: Locator,
}

#[derive(Debug)]
pub(crate) enum LocateError {
    Read(std::io::Error),
    Invalid(&'static str),
}

impl From<std::io::Error> for LocateError {
    fn from(error: std::io::Error) -> Self {
        Self::Read(error)
    }
}

impl LocateError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Read(_) => "zip64_eocd_read_failed",
            Self::Invalid(code) => code,
        }
    }
}

/// One locator/extent model for byte slices, files and logical volume views.
/// Try the disk-relative locator first. SFX/carriers can shift that offset;
/// recover by scanning backwards in bounded windows, accepting only a record
/// whose declared variable extent ends exactly at the adjacent locator.
pub(crate) fn locate_end_record(
    eocd: u64,
    disk_starts: Option<&[u64]>,
    mut read: impl FnMut(u64, usize) -> std::io::Result<Vec<u8>>,
) -> Result<Option<LocatedEndRecord>, LocateError> {
    let Some(locator_offset) = eocd.checked_sub(20) else {
        return Ok(None);
    };
    let bytes = read(locator_offset, 20)?;
    if !bytes.starts_with(b"PK\x06\x07") {
        return Ok(None);
    }
    let locator = parse_locator(&bytes).map_err(LocateError::Invalid)?;
    if locator.total_disks == 0 || locator.record_disk >= locator.total_disks {
        return Err(LocateError::Invalid("zip64_locator_invalid"));
    }
    let base = match disk_starts {
        Some(starts) => *starts
            .get(locator.record_disk as usize)
            .ok_or(LocateError::Invalid(
                "central_directory_disk_offset_out_of_range",
            ))?,
        None => 0,
    };
    let declared = base
        .checked_add(locator.record_offset)
        .ok_or(LocateError::Invalid("zip64_locator_offset_overflow"))?;
    let check = |offset: u64, fixed: &[u8]| -> Result<Option<LocatedEndRecord>, LocateError> {
        if fixed.len() < 56 || !fixed.starts_with(b"PK\x06\x06") {
            return Ok(None);
        }
        if offset
            .checked_add(12)
            .and_then(|start| start.checked_add(u64_at(fixed, 4)))
            != Some(locator_offset)
        {
            return Ok(None);
        }
        // The extent proves this is the actual record, rather than a magic
        // string inside its extension. Reject invalid fields immediately;
        // a malformed directory declaration must not trigger a file scan.
        let record = parse_record(fixed).map_err(LocateError::Invalid)?;
        Ok(Some(LocatedEndRecord {
            offset,
            record,
            locator,
        }))
    };
    let fixed_start = locator_offset.checked_sub(56);
    for offset in [Some(declared), fixed_start].into_iter().flatten() {
        if offset
            .checked_add(56)
            .is_some_and(|end| end <= locator_offset)
        {
            if let Some(found) = check(offset, &read(offset, 56)?)? {
                return Ok(Some(found));
            }
        }
    }
    // 55 bytes of overlap retain fixed headers crossing a window boundary.
    // Extension bytes are never allocated as one object or decoded.
    let mut end = locator_offset;
    while end > base {
        let start = end.saturating_sub(64 * 1024).max(base);
        let stop = end.saturating_add(55).min(locator_offset);
        let window = read(start, (stop - start) as usize)?;
        for index in memchr::memmem::rfind_iter(&window, b"PK\x06\x06") {
            if let Some(found) = check(start + index as u64, &window[index..])? {
                return Ok(Some(found));
            }
        }
        end = start;
    }
    Err(LocateError::Invalid("zip64_eocd_invalid"))
}

/// ZIP64 extra values follow the sentinel fields in this fixed order. All
/// consumers share the same bounds checks instead of skipping fields ad hoc.
pub(crate) struct CentralValues {
    pub uncompressed: u64,
    pub compressed: u64,
    pub local_offset: u64,
    pub disk: u64,
}

pub(crate) fn central_entry_values(header: &[u8], extra: &[u8]) -> Option<CentralValues> {
    if header.len() < 46 {
        return None;
    }
    let mut values = CentralValues {
        uncompressed: u32_at(header, 24) as u64,
        compressed: u32_at(header, 20) as u64,
        local_offset: u32_at(header, 42) as u64,
        disk: u16::from_le_bytes(header[34..36].try_into().ok()?) as u64,
    };
    let sentinels = [
        values.uncompressed == u32::MAX as u64,
        values.compressed == u32::MAX as u64,
        values.local_offset == u32::MAX as u64,
        values.disk == u16::MAX as u64,
    ];
    if !sentinels.iter().any(|value| *value) {
        return Some(values);
    }
    let mut cursor = 0usize;
    while cursor.checked_add(4)? <= extra.len() {
        let id = u16::from_le_bytes(extra[cursor..cursor + 2].try_into().ok()?);
        let size = u16::from_le_bytes(extra[cursor + 2..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;
        let payload = extra.get(cursor..cursor.checked_add(size)?)?;
        if id == 1 {
            let mut at = 0usize;
            for (needed, width, target) in [
                (sentinels[0], 8, &mut values.uncompressed),
                (sentinels[1], 8, &mut values.compressed),
                (sentinels[2], 8, &mut values.local_offset),
                (sentinels[3], 4, &mut values.disk),
            ] {
                if needed {
                    let bytes = payload.get(at..at + width)?;
                    *target = if width == 4 {
                        u32::from_le_bytes(bytes.try_into().ok()?) as u64
                    } else {
                        u64::from_le_bytes(bytes.try_into().ok()?)
                    };
                    at += width;
                }
            }
            return Some(values);
        }
        cursor += size;
    }
    None
}
