use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use memchr::memmem;
use std::borrow::Cow;
use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;

const OVERLAY_SCAN_WINDOW_BYTES: u64 = 65_536;
const PE_SIGNATURE: &[u8] = b"PE\x00\x00";
const SECTION_HEADER_SIZE: usize = 40;
// The Windows loader accepts at most 96 sections; reject before allocating
// or reading the optional header / section table.
const MAX_PE_SECTIONS: usize = 96;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

use crate::formats::signatures::{LZ4_SKIP_SUFFIX, OVERLAY_MAGICS as ARCHIVE_MAGICS};

/// PE structure facts only; SFX classification belongs to Relations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum PeState {
    #[default]
    None,
    Candidate,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeProbe {
    NotPe,
    NeedMore,
    Confirmed(u64),
}

impl PeProbe {
    pub(crate) fn state(self) -> PeState {
        match self {
            Self::NotPe => PeState::None,
            Self::NeedMore => PeState::Candidate,
            Self::Confirmed(_) => PeState::Confirmed,
        }
    }

    pub(crate) fn image_end(self) -> Option<u64> {
        match self {
            Self::Confirmed(image_end) => Some(image_end),
            _ => None,
        }
    }
}

/// The only PE parser. Prefix and I/O callers supply bytes to the same proof.
/// Missing prefix bytes mean Candidate; out-of-file structure means NotPe.
fn inspect_pe_headers<'a, E>(
    actual_size: u64,
    mut read: impl FnMut(u64, usize) -> Result<Option<Cow<'a, [u8]>>, E>,
) -> Result<PeProbe, E> {
    macro_rules! field {
        ($offset:expr, $len:expr) => {{
            let offset: u64 = $offset;
            let len: usize = $len;
            if offset
                .checked_add(len as u64)
                .is_none_or(|end| end > actual_size)
            {
                return Ok(PeProbe::NotPe);
            }
            let Some(bytes) = read(offset, len)? else {
                return Ok(PeProbe::NeedMore);
            };
            bytes
        }};
    }
    let magic = field!(0, 2);
    if magic.as_ref() != b"MZ" {
        return Ok(PeProbe::NotPe);
    }
    let dos = field!(0, 64);
    let pe_header_offset = u32_le(&dos, 0x3c) as u64;
    if pe_header_offset < 64 {
        return Ok(PeProbe::NotPe);
    }
    let signature = field!(pe_header_offset, 4);
    if signature.as_ref() != PE_SIGNATURE {
        return Ok(PeProbe::NotPe);
    }
    let coff = field!(pe_header_offset, 24);
    if u16_le(&coff, 4) == 0 || u16_le(&coff, 22) & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Ok(PeProbe::NotPe);
    }
    let section_count = u16_le(&coff, 6) as usize;
    let optional_size = u16_le(&coff, 20) as usize;
    if section_count == 0 || section_count > MAX_PE_SECTIONS || optional_size < 64 {
        return Ok(PeProbe::NotPe);
    }
    let optional_offset = pe_header_offset + 24;
    let optional = field!(optional_offset, optional_size);
    let (fixed_size, directory_count_offset) = match u16_le(&optional, 0) {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return Ok(PeProbe::NotPe),
    };
    if optional_size < fixed_size
        || u32_le(&optional, directory_count_offset) as usize > (optional_size - fixed_size) / 8
    {
        return Ok(PeProbe::NotPe);
    }
    let table_offset = optional_offset + optional_size as u64;
    let table_size = section_count * SECTION_HEADER_SIZE;
    let sections = field!(table_offset, table_size);
    let table_end = table_offset + table_size as u64;
    let headers_size = u32_le(&optional, 60) as u64;
    if headers_size < table_end || headers_size > actual_size {
        return Ok(PeProbe::NotPe);
    }
    let mut image_end = headers_size;
    for section in sections.chunks_exact(SECTION_HEADER_SIZE) {
        let raw_size = u32_le(section, 16) as u64;
        let raw_pointer = u32_le(section, 20) as u64;
        if raw_size != 0 {
            let end = raw_pointer + raw_size;
            if raw_pointer < headers_size || end > actual_size {
                return Ok(PeProbe::NotPe);
            }
            image_end = image_end.max(end);
        }
    }
    Ok(PeProbe::Confirmed(image_end))
}

/// Zero I/O: filesystem must only use the bounded prefix it already owns.
pub(crate) fn probe_pe_prefix(prefix: &[u8], actual_size: u64) -> PeProbe {
    inspect_pe_headers::<std::convert::Infallible>(actual_size, |offset, len| {
        Ok(usize::try_from(offset).ok().and_then(|start| {
            start
                .checked_add(len)
                .and_then(|end| prefix.get(start..end))
                .map(Cow::Borrowed)
        }))
    })
    .unwrap()
}

pub(crate) fn inspect_pe_image_reader(reader: &ManagedReader) -> Result<PeProbe, ReadFault> {
    let mut file = reader.cursor();
    let actual_size = reader.len();
    inspect_pe_headers(actual_size, |offset, len| {
        let mut bytes = vec![0; len];
        seek_field(
            &mut file,
            offset,
            actual_size,
            "pe.image_headers",
            FieldLocation::Head,
        )?;
        read_exact_field(
            &mut file,
            &mut bytes,
            actual_size,
            "pe.image_headers",
            FieldLocation::Head,
        )?;
        Ok(Some(Cow::Owned(bytes)))
    })
}

pub(crate) fn inspect_pe_image_native(path: &str) -> std::io::Result<PeProbe> {
    let reader = ManagedReader::open(path)?;
    inspect_pe_image_reader(&reader).map_err(|fault| std::io::Error::new(fault.io_kind, fault))
}

pub(crate) struct ArchiveOverlay {
    pub(crate) format: &'static str,
    pub(crate) offset: u64,
}

/// Relations reuses its reader and confirmed boundary without parsing headers again.
pub(crate) fn inspect_pe_overlay_reader(
    reader: &ManagedReader,
    actual_size: u64,
    pe_end: u64,
) -> Option<ArchiveOverlay> {
    if pe_end == 0 || pe_end >= actual_size {
        return None;
    }
    let sample_size = OVERLAY_SCAN_WINDOW_BYTES.min(actual_size - pe_end);
    // Keep reusable PE header blocks; the overlay search sample is one-shot.
    let mut file = reader.probe_reader().cursor();
    let mut sample = vec![0; sample_size as usize];
    file.seek(SeekFrom::Start(pe_end)).ok()?;
    file.read_exact(&mut sample).ok()?;
    let (format, relative_offset) = find_archive_magic(&sample)?;
    Some(ArchiveOverlay {
        format,
        offset: pe_end + relative_offset as u64,
    })
}

fn find_archive_magic(sample: &[u8]) -> Option<(&'static str, usize)> {
    let mut best: Option<(&'static str, usize)> = None;
    static MATCHERS: OnceLock<[memmem::Finder<'static>; ARCHIVE_MAGICS.len()]> = OnceLock::new();
    let matchers =
        MATCHERS.get_or_init(|| ARCHIVE_MAGICS.map(|(magic, _)| memmem::Finder::new(magic)));
    for ((_, archive_format), matcher) in ARCHIVE_MAGICS.iter().zip(matchers) {
        let Some(index) = matcher.find(sample) else {
            continue;
        };
        if best.is_none_or(|(_, best_index)| index < best_index) {
            best = Some((*archive_format, index));
        }
    }
    if let Some(offset) = memchr::memmem::find_iter(sample, LZ4_SKIP_SUFFIX)
        .filter_map(|offset| offset.checked_sub(1))
        .find(|offset| (0x50..=0x5f).contains(&sample[*offset]))
    {
        if best.is_none_or(|(_, best_index)| offset < best_index) {
            best = Some(("lz4", offset));
        }
    }
    best
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/scan/pe_overlay/tests.rs"]
mod tests;
