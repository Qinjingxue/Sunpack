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

#[derive(Clone, Copy)]
pub(crate) enum StreamStructure {
    Complete(&'static str),
    Lz4 { end: u64 },
}

pub(crate) fn inspect_compression_stream_reader(
    reader: &ManagedReader,
    header: &[u8],
) -> std::io::Result<Option<StreamStructure>> {
    if let Some(kind) = StructuralStreamKind::from_header(header) {
        return complete_structural_stream(reader, kind)
            .map(|format| format.map(StreamStructure::Complete));
    }
    if crate::formats::lz4::leading(header) {
        let file_size = reader.len();
        let index = crate::formats::lz4::walk(reader, 0, file_size);
        return Ok(index.complete.then_some(StreamStructure::Lz4 { end: index.end }));
    }
    Ok(None)
}

pub(crate) fn has_compression_stream_header(header: &[u8]) -> bool {
    StructuralStreamKind::from_header(header).is_some() || crate::formats::lz4::leading(header)
}
