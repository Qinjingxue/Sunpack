
const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP64_EOCD_SIGNATURE: &[u8] = b"PK\x06\x06";
const ZIP64_EOCD_LOCATOR_SIGNATURE: &[u8] = b"PK\x06\x07";
const ZIP_EOCD_MIN_SIZE: usize = 22;
const ZIP_EOCD_MAX_COMMENT: u64 = 65_535;
const ZIP_CENTRAL_DIRECTORY_HEADER_SIZE: usize = 46;
const ZIP64_EOCD_RECORD_SIZE: usize = 56;
const ZIP64_EOCD_LOCATOR_SIZE: usize = 20;
const TAR_BLOCK_SIZE: usize = 512;
const SEVEN_Z_SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const SEVEN_Z_HEADER_SIZE: usize = 32;
const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
const ZSTD_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";
