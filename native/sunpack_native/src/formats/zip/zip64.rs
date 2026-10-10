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
        record_offset: u64_at(bytes, 8),
        total_disks: u32_at(bytes, 16),
    };
    if locator.record_offset >= OFFSET_LIMIT {
        return Err("zip64_locator_offset_overflow");
    }
    Ok(locator)
}

pub(crate) fn parse_fixed_tail(bytes: &[u8]) -> Result<Option<(EndRecord, Locator)>, &'static str> {
    if bytes.len() != 76 || !bytes.starts_with(b"PK\x06\x06") || &bytes[56..60] != b"PK\x06\x07" {
        return Ok(None);
    }
    let record = parse_record(bytes)?;
    if record.record_size != 44 {
        return Err("zip64_eocd_size_invalid");
    }
    Ok(Some((record, parse_locator(&bytes[56..])?)))
}
