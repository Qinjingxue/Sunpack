const UNIFIED_PREFILTER_ZIP: u32 = 1 << 0;
const UNIFIED_PREFILTER_RAR: u32 = 1 << 1;
const UNIFIED_PREFILTER_SEVEN_ZIP: u32 = 1 << 2;
const UNIFIED_PREFILTER_TAR: u32 = 1 << 3;
const UNIFIED_PREFILTER_COMPRESSION: u32 = 1 << 4;

pub(crate) fn unified_prefilter_mask_from_head(file_size: u64, head: &[u8]) -> u32 {
    let read = head.len().min(TAR_BLOCK_SIZE);
    let head = &head[..read];
    let mut rejected = 0;
    if file_size < TAR_BLOCK_SIZE as u64 {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    if read >= RAR5_SIGNATURE.len()
        && !head.starts_with(RAR4_SIGNATURE)
        && !head.starts_with(RAR5_SIGNATURE)
    {
        rejected |= UNIFIED_PREFILTER_RAR;
    }
    if read >= SEVEN_Z_SIGNATURE.len() && !head.starts_with(SEVEN_Z_SIGNATURE) {
        rejected |= UNIFIED_PREFILTER_SEVEN_ZIP;
    }
    if read >= 4
        && !head.starts_with(b"PK\x03\x04")
        && !head.starts_with(b"PK\x05\x06")
        && !head.starts_with(b"PK\x07\x08")
        && !head.starts_with(b"PK00")
        && !head.starts_with(b"PK\x06\x06")
    {
        rejected |= UNIFIED_PREFILTER_ZIP;
    }
    if read >= XZ_MAGIC.len()
        && !head.starts_with(b"\x1f\x8b\x08")
        && !head.starts_with(b"BZh")
        && !head.starts_with(XZ_MAGIC)
        && !head.starts_with(ZSTD_MAGIC)
        && !crate::formats::lz4::leading(head)
    {
        rejected |= UNIFIED_PREFILTER_COMPRESSION;
    }
    if read == TAR_BLOCK_SIZE
        && (head.iter().all(|byte| *byte == 0) || !crate::formats::tar::valid_header(head))
    {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    rejected
}

pub(crate) fn confirm_compression_format_identity_native(path: &str, format: &str) -> bool {
    let result = inspect_compression_stream_identity_impl(path);
    result.format == format && result.plausible && result.error.is_empty()
}

#[cfg(test)]
fn inspect_compression_stream_structure(
    path: &str,
) -> std::io::Result<StreamObservation> {
    let Ok(reader) = ManagedReader::open(path) else {
        return Ok(compression_empty("os_error", "", false));
    };
    let header = (reader.read_cached_at(0, 32))?;
    inspect_compression_stream_reader(&reader, &header)
}

pub(crate) fn inspect_compression_stream_reader(
    reader: &ManagedReader,
    header: &[u8],
) -> std::io::Result<StreamObservation> {
    if let Some(kind) = StructuralStreamKind::from_header(header) {
        if reader.len() > EAGER_STREAM_INTEGRITY_MAX_BYTES {
            return inspect_structural_stream(reader, kind);
        }
        return match kind {
            StructuralStreamKind::Gzip => inspect_gzip(reader),
            StructuralStreamKind::Bzip2 => inspect_bzip2(reader),
            StructuralStreamKind::Xz => inspect_xz(reader),
            StructuralStreamKind::Zstd => inspect_zstd(reader),
        };
    }
    if crate::formats::lz4::leading(header) {
        let file_size = reader.len();
        let index = crate::formats::lz4::walk(reader, 0, file_size);
        if index.frames == 0 && matches!(index.error, "" | "lz4_magic_not_found") {
            return Ok(compression_empty("ambiguous_skippable_stream", "", false));
        }
        return Ok(StreamObservation {
            format: "lz4".into(), magic_matched: index.magic_matched(),
            plausible: index.frames > 0, error: index.error.into(),
            damage_flags: if index.error.is_empty() { Vec::new() } else { vec![index.error.into()] },
            structure_complete: index.complete, boundary_exact: index.complete,
            segment_end: index.complete.then_some(index.end),
            trailing_bytes: Some(file_size.saturating_sub(index.end)),
            stream_count: index.frames,
        });
    }
    Ok(compression_empty("compression_stream_magic_not_found", "", false))
}

pub(crate) fn has_compression_stream_header(header: &[u8]) -> bool {
    StructuralStreamKind::from_header(header).is_some() || crate::formats::lz4::leading(header)
}
