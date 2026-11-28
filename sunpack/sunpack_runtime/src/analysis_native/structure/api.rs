use crate::formats::StreamFormat;
const UNIFIED_PREFILTER_ZIP: u32 = 1 << 0;
const UNIFIED_PREFILTER_RAR: u32 = 1 << 1;
const UNIFIED_PREFILTER_SEVEN_ZIP: u32 = 1 << 2;
const UNIFIED_PREFILTER_TAR: u32 = 1 << 3;
const UNIFIED_PREFILTER_COMPRESSION: u32 = 1 << 4;

pub(crate) fn unified_prefilter_mask_from_head(file_size: u64, head: &[u8], stream: Option<StreamFormat>) -> u32 {
    let read = head.len().min(TAR_BLOCK_SIZE);
    let head = &head[..read];
    let mut rejected = 0;
    if file_size < TAR_BLOCK_SIZE as u64 {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    if read >= RAR5.len()
        && !head.starts_with(RAR4)
        && !head.starts_with(RAR5)
    {
        rejected |= UNIFIED_PREFILTER_RAR;
    }
    if read >= SEVEN_ZIP.len() && !head.starts_with(SEVEN_ZIP) {
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
    if read >= StreamFormat::MAX_PREFIX && !stream.is_some_and(|kind| match kind {
        StreamFormat::Tar | StreamFormat::Enc => false,
        StreamFormat::Gzip => head.starts_with(GZIP),
        _ => true,
    }) {
        rejected |= UNIFIED_PREFILTER_COMPRESSION;
    }
    if read == TAR_BLOCK_SIZE
        && (head.iter().all(|byte| *byte == 0) || !crate::formats::tar::valid_header(head))
    {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    rejected
}
