//! Archive signatures shared by the root probe, embedded scanner and PE overlay search.
//! Keep lookup on the scan hot path static: a magic comparison has a constant length.
pub(crate) const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
pub(crate) const ZIP_EOCD: &[u8] = b"PK\x05\x06";
pub(crate) const SEVEN_ZIP: &[u8] = super::seven_zip::SEVEN_Z_MAGIC;
pub(crate) const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
pub(crate) const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
pub(crate) const GZIP: &[u8] = b"\x1f\x8b\x08";
pub(crate) const BZIP2: &[u8] = b"BZh";
pub(crate) const XZ: &[u8] = b"\xfd7zXZ\x00";
pub(crate) const ZSTD: &[u8] = &super::zstd::MAGIC.to_le_bytes();
pub(crate) const TAR_USTAR: &[u8] = b"ustar";
pub(crate) const LZ4_SKIP_SUFFIX: &[u8] = b"\x2a\x4d\x18";

use crate::analysis_native::structure as root;
use crate::io::reader::ManagedReader;
use crate::scan::compression_stream::{self as stream, StreamReadiness, ValidationResult};
use crate::scan::embedded;
use std::io;

pub(crate) enum StreamValidation {
    Bzip2, Xz, Lz4, Tar, Enc,
    // One call per frame walk. All reads and block iterations remain inside the format's parser.
    Frames(fn(&ManagedReader, u64, u64, &mut dyn FnMut(u64) -> ValidationResult<()>) -> ValidationResult<u64>),
}
use StreamValidation::Frames;

pub(crate) type PatternSpec = (&'static [u8], &'static str, &'static str);

macro_rules! signatures {
    ($($id:ident => ($magic:expr, $hit:literal, $kind:literal, $overlay:expr)
        $(stream($stream:ident, $root:path, $validation:expr $(,$alias:literal)*))?
        $(archive($archive:path))?;)+) => {
        #[derive(Clone, Copy)]
        pub(crate) enum Signature { $($id,)+ }
        pub(crate) const SIGNATURE_IDS: &[Signature] = &[$(Signature::$id),+];
        pub(crate) const PATTERNS: [PatternSpec; [$(Signature::$id),+].len()] =
            [$(($magic, $hit, $kind)),+];
        const OVERLAYS: [Option<&str>; PATTERNS.len()] = [$($overlay),+];

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum StreamFormat { $($( $stream, )?)+ }
        impl StreamFormat {
            pub(crate) const COUNT: usize = [$( $(Self::$stream,)? )+].len();
            pub(crate) const MAX_PREFIX: usize = {
                let mut len = 0;
                $($(if !matches!(Self::$stream, Self::Tar | Self::Enc) && $magic.len() > len {
                    len = $magic.len();
                })?)+
                len
            };
            pub(crate) fn from_name(name: &str) -> Option<Self> {
                match name { $($( $kind => Some(Self::$stream), )?)+ _ => None }
            }
            pub(crate) const fn name(self) -> &'static str {
                match self { $($( Self::$stream => $kind, )?)+ }
            }
            pub(crate) fn root_readiness(self, prefix: &[u8], size: u64,
                read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
            ) -> Option<StreamReadiness> {
                match self { $($( Self::$stream => $root(prefix, size, read), )?)+ }
            }
            pub(crate) fn validation(self) -> StreamValidation {
                match self { $($( Self::$stream => $validation, )?)+ }
            }
            pub(crate) fn known_suffix(suffix: &str) -> bool {
                false $($( || suffix.eq_ignore_ascii_case($kind) $(|| suffix.eq_ignore_ascii_case($alias))* )?)+
            }
            pub(crate) fn from_header(head: &[u8]) -> Option<Self> {
                // Gzip readiness also recognises a short or damaged fixed header.
                if head.starts_with(&GZIP[..2]) { return Some(Self::Gzip); }
                $($( if Self::$stream != Self::Tar && head.starts_with($magic) {
                    return Some(Self::$stream);
                } )?)+
                if super::lz4::leading(head) { return Some(Self::Lz4); }
                (head.get(257..262) == Some(TAR_USTAR)).then_some(Self::Tar)
            }
        }

        pub(crate) fn validate_archive_candidate(
            reader: &ManagedReader, end: u64, kind: &str, offset: u64,
        ) -> io::Result<Option<embedded::EmbeddedCandidate>> {
            match kind {
                $($( $kind => $archive(reader, end, offset), )?)+
                _ => Ok(None),
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        pub(crate) fn visit_prefix(first: u8, mut visit: impl FnMut(usize, &'static [u8])) {
            $(if first == $magic[0] { visit(Signature::$id as usize, $magic); })+
        }
    };
}

// Append ordinary formats below. Each primary stream entry supplies its root
// readiness proof, bounded validator and filename aliases. Special records
// (directories, skippable frames, TAR markers) keep their own hit identity.
signatures! {
    ZipLocal    => (ZIP_LOCAL, "zip_local", "zip", Some("zip"));
    ZipEocd     => (ZIP_EOCD, "zip_eocd", "zip_eocd", None);
    SevenZip    => (SEVEN_ZIP, "7z", "7z", Some("7z")) archive(embedded::validate_seven_zip);
    Rar4        => (RAR4, "rar4", "rar4", Some("rar")) archive(embedded::validate_rar);
    Rar5        => (RAR5, "rar5", "rar5", Some("rar")) archive(embedded::validate_rar);
    Gzip        => (GZIP, "gzip", "gzip", Some("gzip"))
        stream(Gzip, root::gzip_readiness, Frames(|r, at, end, v| stream::validate_gzip_structure(r, at, end, v)), "gz", "tgz");
    Bzip2       => (BZIP2, "bzip2", "bzip2", Some("bzip2")) stream(Bzip2, root::bzip2_readiness, StreamValidation::Bzip2, "bz2", "tbz", "tbz2");
    Xz          => (XZ, "xz", "xz", Some("xz")) stream(Xz, root::xz_readiness, StreamValidation::Xz, "txz");
    Zstd        => (ZSTD, "zstd", "zstd", Some("zstd"))
        stream(Zstd, stream::zstd_head_extent, Frames(|r, at, end, v| stream::validate_zstd_structure(r, at, end, v)), "zst");
    Tar         => (TAR_USTAR, "tar_ustar", "tar", None) stream(Tar, root::tar_readiness, StreamValidation::Tar);
    Lz4         => (super::lz4::MAGIC, "lz4", "lz4", Some("lz4")) stream(Lz4, root::lz4_readiness, StreamValidation::Lz4);
    Lz4Skip     => (LZ4_SKIP_SUFFIX, "lz4_skippable", "lz4_skippable", None);
    Zip64Eocd   => (b"PK\x06\x06", "zip64_eocd", "zip64_eocd", None);
    Enc         => (sunpack_enc::MAGIC, "enc", "enc", None) stream(Enc, root::enc_readiness, StreamValidation::Enc);
}

impl StreamFormat {
    pub(crate) fn uses_external_end(self) -> bool { self == Self::Enc }
    pub(crate) fn can_require_password(self) -> bool { self == Self::Enc }
}

const fn overlay_count() -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < OVERLAYS.len() {
        n += OVERLAYS[i].is_some() as usize;
        i += 1;
    }
    n
}
pub(crate) const OVERLAY_MAGICS: [(&[u8], &str); overlay_count()] = {
    let mut result = [(&[] as &[u8], ""); overlay_count()];
    let mut i = 0;
    let mut j = 0;
    while i < OVERLAYS.len() {
        if let Some(name) = OVERLAYS[i] {
            result[j] = (PATTERNS[i].0, name);
            j += 1;
        }
        i += 1;
    }
    result
};
