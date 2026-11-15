#[derive(Clone, Copy)]
pub(crate) struct EocdInfo {
    pub(crate) offset: usize,
    pub(crate) end: usize,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
}

pub(crate) fn find_eocd_record(data: &[u8], allow_trailing_junk: bool) -> Option<EocdInfo> {
    let mut pos = memchr::memmem::rfind(data, EOCD_SIG)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() && (allow_trailing_junk || end == data.len()) {
                return Some(EocdInfo {
                    offset: pos,
                    end,
                    total_entries: u16_le(data, pos + 10),
                    cd_size: u32_le(data, pos + 12),
                    cd_offset: u32_le(data, pos + 16),
                });
            }
        }
        if pos == 0 {
            return None;
        }
        pos = memchr::memmem::rfind(&data[..pos], EOCD_SIG)?;
    }
}

pub(crate) struct CentralDirectoryRecord<'a> {
    pub(crate) flags: u16,
    pub(crate) method: u16,
    pub(crate) crc32: u32,
    pub(crate) name: &'a [u8],
    pub(crate) extra: &'a [u8],
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

pub(crate) fn parse_central_directory_record(data: &[u8]) -> Option<CentralDirectoryRecord<'_>> {
    let length = central_directory_record_len(data)?;
    let entry = data.get(..length)?;
    let name_end = 46 + usize::from(u16_le(entry, 28));
    let extra_end = name_end + usize::from(u16_le(entry, 30));
    Some(CentralDirectoryRecord {
        flags: u16_le(entry, 8),
        method: u16_le(entry, 10),
        crc32: u32_le(entry, 16),
        name: &entry[46..name_end],
        extra: &entry[name_end..extra_end],
    })
}
