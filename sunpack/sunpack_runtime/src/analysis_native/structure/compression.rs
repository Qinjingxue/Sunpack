#[derive(Clone, Copy)]
pub(super) enum StructuralStreamKind {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl StructuralStreamKind {
    pub(super) fn from_header(header: &[u8]) -> Option<Self> {
        if header.starts_with(b"\x1f\x8b") {
            Some(Self::Gzip)
        } else if header.starts_with(b"BZh") {
            Some(Self::Bzip2)
        } else if header.starts_with(XZ_MAGIC) {
            Some(Self::Xz)
        } else if header.starts_with(ZSTD_MAGIC) {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    pub(super) fn format(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

pub(super) fn compression_stream_evidence(
    kind: StructuralStreamKind,
    prefix: &[u8],
    file_size: u64,
    mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
) -> Option<StreamReadiness> {
    match kind {
        StructuralStreamKind::Gzip => gzip_head_extent(prefix, file_size, read).ok(),
        StructuralStreamKind::Bzip2 => {
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
        StructuralStreamKind::Xz => {
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
        StructuralStreamKind::Zstd => zstd_head_extent(prefix, file_size, read),
    }
}
