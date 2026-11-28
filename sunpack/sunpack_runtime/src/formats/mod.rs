pub(crate) mod deflate_prefix;
pub(crate) mod lz4;
pub(crate) mod rar;
pub(crate) mod seven_zip;
pub(crate) mod tar;
pub(crate) mod zip;
pub(crate) mod zstd;

pub(crate) mod signatures;
pub(crate) use signatures::StreamFormat;

pub(crate) fn supports_volume_relations(format: &str) -> bool {
    matches!(format, "rar" | "7z" | "zip")
}
