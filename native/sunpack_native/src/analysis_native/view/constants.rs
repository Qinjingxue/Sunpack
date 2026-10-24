const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP64_EOCD: &[u8] = b"PK\x06\x06";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const LZ4: &[u8] = crate::formats::lz4::MAGIC;
const TAR_USTAR: &[u8] = b"ustar";
const TAR_BLOCK_SIZE: usize = 512;

// The same IDs name retained native hits and drive the window scanner.
// Embedded-only markers have no pattern in the window prepass.
const ANALYSIS_SIGNATURES: &[(&str, Option<&[u8]>)] = &[
    ("zip_local", Some(ZIP_LOCAL)),
    ("zip_eocd", Some(ZIP_EOCD)),
    ("rar4", Some(RAR4)),
    ("rar5", Some(RAR5)),
    ("7z", Some(SEVEN_ZIP)),
    ("gzip", Some(GZIP)),
    ("bzip2", Some(BZIP2)),
    ("xz", Some(XZ)),
    ("zstd", Some(ZSTD)),
    ("lz4", Some(LZ4)),
    ("tar_ustar", Some(TAR_USTAR)),
    ("lz4_skippable", None),
    ("zip_central", None),
];
