pub(crate) fn tar_readiness(prefix: &[u8], file_size: u64,
    _read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    crate::formats::tar::header_identity(prefix, file_size).then_some(StreamReadiness::Candidate)
}

pub(crate) fn enc_readiness(prefix: &[u8], file_size: u64,
    _read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    sunpack_enc::Header::parse(prefix, file_size).ok().map(|_| StreamReadiness::Candidate)
}

pub(crate) fn lz4_readiness(prefix: &[u8], file_size: u64,
    read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    crate::formats::lz4::standalone_truncated(prefix, file_size, read)
        .map(|truncated| if truncated { StreamReadiness::Truncated } else { StreamReadiness::Candidate })
}

pub(crate) fn gzip_readiness(prefix: &[u8], file_size: u64,
    read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    gzip_head_extent(prefix, file_size, read).ok()
}

pub(crate) fn bzip2_readiness(prefix: &[u8], file_size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    validate_bzip2_identity(prefix, file_size).ok()?;
    // A standalone strict Bzip2 stream must end with its marker, CRC
    // and at most seven padding bits. Carriers use their own extent.
    let marker = if file_size <= prefix.len() as u64 {
        Some(bzip2_may_end_at(&prefix[..file_size as usize]))
    } else {
        read(file_size.saturating_sub(11), 11).ok()
            .filter(|tail| tail.len() == 11)
            .map(|tail| bzip2_may_end_at(&tail))
    };
    Some(if marker == Some(false) {
        StreamReadiness::Truncated
    } else {
        StreamReadiness::Candidate
    })
}

pub(crate) fn xz_readiness(prefix: &[u8], file_size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    validate_xz_identity(prefix, file_size, |size| read(12, size)).ok()?;
    let footer = xz_has_terminal_footer(file_size, |offset, count| {
        let offset_in_prefix = offset.min(prefix.len() as u64) as usize;
        if let Some(bytes) = prefix.get(offset_in_prefix..offset_in_prefix + count) {
            return Ok(Cow::Borrowed(bytes));
        }
        read(offset, count).map(Cow::Owned)
    });
    Some(if matches!(footer, Ok(false)) {
        StreamReadiness::Truncated
    } else {
        StreamReadiness::Candidate
    })
}
