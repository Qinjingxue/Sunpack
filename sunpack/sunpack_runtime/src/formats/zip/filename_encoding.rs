use crate::io::archive_state::{ArchiveInput, InputExtent};
use crate::password::input::{parse_ranges, VirtualRangeReader};
use encoding_rs::{DecoderResult, BIG5, GBK, SHIFT_JIS};
use std::io;
use std::sync::OnceLock;

#[cfg(test)]
const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
#[cfg(test)]
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP_UTF8_FLAG: u16 = 0x800;
const ZIP_UNICODE_PATH_EXTRA_FIELD: u16 = 0x7075;
const ZIP64_MARKER: u32 = 0xFFFF_FFFF;
const ZIP_EOCD_LENGTH: usize = 22;
#[cfg(test)]
const ZIP_CENTRAL_HEADER_LENGTH: usize = 46;
const MAX_ZIP_COMMENT_BYTES: u64 = 65_535;

// Derived from CharacterEncodingDetectorTables.h (Copyright 2013 The Android
// Open Source Project, Apache-2.0) by scripts/generate_zip_filename_frequencies.py.
static HAN_FREQUENCIES: &[u8; 0x5200] = include_bytes!("filename_frequencies.bin");
const HAN_RANK_BONUS: [i32; 4] = [0, 3, 4, 5];
const CP437_HIGH: &str =
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
static CP437_TABLE: OnceLock<[char; 128]> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum EncodingKind {
    Cp437,
    Utf8,
    Cp932,
    Cp936,
    Cp950,
}

impl EncodingKind {
    fn codepage(self) -> &'static str {
        match self {
            Self::Cp437 => "437",
            Self::Utf8 => "65001",
            Self::Cp936 => "936",
            Self::Cp950 => "950",
            Self::Cp932 => "932",
        }
    }

    fn han_score(self, ch: char) -> i32 {
        match self {
            Self::Cp437 => 0,
            Self::Utf8 => 4,
            Self::Cp932 | Self::Cp936 | Self::Cp950 => {
                let ranks = HAN_FREQUENCIES[ch as usize - 0x4e00];
                let shift = 2 * (self as u8 - Self::Cp932 as u8);
                2 + HAN_RANK_BONUS[((ranks >> shift) & 3) as usize]
            }
        }
    }
}

pub(crate) fn analyze_zip_filename_encoding(
    archive_input: &ArchiveInput,
) -> io::Result<Option<&'static str>> {
    let mut extents = archive_input.physical_extents().peekable();
    let fallback = extents.peek().is_none().then(|| InputExtent {
        path: archive_input.entry_path.clone(),
        start: 0,
        end: None,
    });
    let ranges = parse_ranges(extents.chain(fallback.as_ref()), &[])?;
    let mut reader = VirtualRangeReader::new(&ranges);
    let disk_starts = archive_input
        .analysis
        .zip_spanned
        .then(|| reader.disk_starts());
    scan_zip_names(&mut reader, disk_starts.as_deref())
}

fn scan_zip_names(
    reader: &mut VirtualRangeReader<'_>,
    disk_starts: Option<&[u64]>,
) -> io::Result<Option<&'static str>> {
    let file_size = reader.len();
    if file_size < ZIP_EOCD_LENGTH as u64 {
        return Ok(None);
    }

    let search_size = file_size.min(MAX_ZIP_COMMENT_BYTES + ZIP_EOCD_LENGTH as u64);
    let tail_start = file_size - search_size;
    let tail = reader.read_at(tail_start, search_size as usize)?;
    let Some(eocd) = super::find_eocd_record(&tail, false) else {
        return Ok(None);
    };

    let mut central_disk = super::u16_le(&tail, eocd.offset + 6) as usize;
    let mut total_entries = eocd.total_entries as u64;
    let mut central_size_u64 = eocd.cd_size as u64;
    let mut central_offset = eocd.cd_offset as u64;
    let eocd_logical_offset = tail_start + eocd.offset as u64;
    let mut directory_end = eocd_logical_offset;
    match super::zip64::locate_end_record(eocd_logical_offset, disk_starts, |at, size| {
        reader.read_at(at, size)
    }) {
        Ok(Some(found)) => {
            central_disk = found.record.cd_disk as usize;
            total_entries = found.record.total_entries;
            central_size_u64 = found.record.cd_size;
            central_offset = found.record.cd_offset;
            directory_end = found.offset;
        }
        Ok(None) => {
            if eocd.cd_offset == ZIP64_MARKER || eocd.cd_size == ZIP64_MARKER {
                return Ok(None);
            }
        }
        Err(_) => return Ok(None),
    }
    if central_size_u64 == 0 && total_entries == 0 {
        return Ok(None);
    }
    let physical_candidate = directory_end.checked_sub(central_size_u64);
    let declared_candidate = match disk_starts {
        Some(starts) => starts
            .get(central_disk)
            .and_then(|start| start.checked_add(central_offset)),
        None if central_disk == 0 => Some(central_offset),
        None => None,
    };
    let mut central_logical_offset = None;
    for candidate in [physical_candidate, declared_candidate]
        .into_iter()
        .flatten()
    {
        if candidate
            .checked_add(central_size_u64)
            .is_none_or(|end| end > file_size)
        {
            continue;
        }
        let has_signature = if candidate >= tail_start {
            tail.get((candidate - tail_start) as usize..)
                .is_some_and(|bytes| bytes.starts_with(super::CD_SIG))
        } else {
            reader.read_at(candidate, super::CD_SIG.len())?.as_slice() == super::CD_SIG
        };
        if has_signature {
            central_logical_offset = Some(candidate);
            break;
        }
    }
    let Some(central_logical_offset) = central_logical_offset else {
        return Ok(None);
    };

    let end = central_logical_offset
        .checked_add(central_size_u64)
        .ok_or_else(|| io::Error::other("ZIP central range overflow"))?;
    let mut cursor = central_logical_offset;
    let mut scoring = None;
    // Small central directories are already in the tail read. Larger ones
    // refill the same buffer starting at the first needed record.
    let mut window_start = tail_start;
    let mut window = tail;
    window.truncate(end.saturating_sub(tail_start) as usize);
    let mut checked = 0u64;
    while checked < total_entries {
        if cursor < window_start || cursor + 46 > window_start + window.len() as u64 {
            window_start = cursor;
            reader.read_at_into(cursor, (end - cursor).min(64 * 1024) as usize, &mut window)?;
        }
        let offset = (cursor - window_start) as usize;
        let Some(fixed) = window.get(offset..offset + 46) else {
            return Ok(None);
        };
        if &fixed[..4] != super::CD_SIG {
            return Ok(None);
        }
        let length = 46
            + super::u16_le(fixed, 28) as usize
            + super::u16_le(fixed, 30) as usize
            + super::u16_le(fixed, 32) as usize;
        if cursor + length as u64 > end {
            return Ok(None);
        }
        if offset + length > window.len() {
            window_start = cursor;
            reader.read_at_into(
                cursor,
                (end - cursor).min((64 * 1024).max(length) as u64) as usize,
                &mut window,
            )?;
        }
        let offset = (cursor - window_start) as usize;
        let Some(record) = super::parse_central_directory_record(&window[offset..]) else {
            return Ok(None);
        };
        // The worker honors the UTF-8 flag even for a malformed name. A legacy
        // code page cannot change those entries, so they supply no evidence.
        if record.flags & ZIP_UTF8_FLAG == 0
            && !record.name.is_ascii()
            && !valid_unicode_path_name(record.name, record.extra)
        {
            scoring
                .get_or_insert_with(FilenameScoring::new)
                .observe(record.name);
        }
        checked += 1;
        cursor += length as u64;
    }
    let Some(scoring) = scoring else {
        return Ok(None);
    };
    if !super::central_directory_complete(cursor, end, |offset, length| {
        reader.read_at(offset, length)
    })? {
        return Ok(None);
    }
    Ok(scoring.finish())
}

struct FilenameScoring {
    candidates: [EncodingCandidate; 5],
    evidence: CharacterEvidence,
    decoded: String,
}

impl FilenameScoring {
    fn new() -> Self {
        Self {
            candidates: [
                EncodingKind::Cp437,
                EncodingKind::Utf8,
                EncodingKind::Cp936,
                EncodingKind::Cp950,
                EncodingKind::Cp932,
            ]
            .map(EncodingCandidate::new),
            evidence: CharacterEvidence::new(),
            decoded: String::new(),
        }
    }

    fn observe(&mut self, raw: &[u8]) {
        for candidate in &mut self.candidates {
            if candidate.valid {
                candidate.observe(raw, &mut self.evidence, &mut self.decoded);
            }
        }
    }

    fn finish(self) -> Option<&'static str> {
        let mut scores = self
            .candidates
            .map(|candidate| (candidate.score(), candidate.kind));
        scores.sort_by(|left, right| right.0.cmp(&left.0));
        let (score, kind) = scores[0];
        (kind == EncodingKind::Cp437 || (score >= 12 && score.saturating_sub(scores[1].0) >= 6))
            .then(|| kind.codepage())
    }
}

// One vote per distinct scored character and candidate across the ZIP. An ASCII
// suffix, another directory level, or repetitions of a short name cannot make
// its characters stronger evidence. Allocate Unicode pages only as needed.
struct CharacterEvidence {
    page_numbers: [u16; 256],
    pages: Vec<[u8; 256]>,
}

impl CharacterEvidence {
    fn new() -> Self {
        Self {
            page_numbers: [0; 256],
            pages: Vec::new(),
        }
    }

    fn insert(&mut self, kind: EncodingKind, ch: char) -> bool {
        // All characters carrying score are in the BMP.
        let code = ch as usize;
        let page_number = &mut self.page_numbers[code >> 8];
        if *page_number == 0 {
            self.pages.push([0; 256]);
            *page_number = self.pages.len() as u16;
        }
        let seen = &mut self.pages[*page_number as usize - 1][code & 0xff];
        let mask = 1 << kind as u8;
        let first = *seen & mask == 0;
        *seen |= mask;
        first
    }
}

struct EncodingCandidate {
    kind: EncodingKind,
    score: i32,
    halfwidth_kana: i32,
    valid: bool,
}

impl EncodingCandidate {
    fn new(kind: EncodingKind) -> Self {
        Self {
            kind,
            score: 4,
            halfwidth_kana: 0,
            valid: true,
        }
    }

    fn score(&self) -> i32 {
        if !self.valid {
            return i32::MIN;
        }
        // A sequence of halfwidth kana can also be two-byte Chinese text.
        // Let it support Japanese without overwhelming other evidence.
        self.score + (self.halfwidth_kana * 3).min(9)
    }

    fn observe(&mut self, raw: &[u8], evidence: &mut CharacterEvidence, decoded: &mut String) {
        let encoding = match self.kind {
            EncodingKind::Cp437 => {
                let table = CP437_TABLE.get_or_init(|| {
                    let mut chars = CP437_HIGH.chars();
                    std::array::from_fn(|_| chars.next().unwrap())
                });
                self.observe_chars(
                    raw.iter().map(|&byte| {
                        if byte.is_ascii() {
                            char::from(byte)
                        } else {
                            table[(byte - 0x80) as usize]
                        }
                    }),
                    evidence,
                );
                return;
            }
            EncodingKind::Utf8 => {
                match std::str::from_utf8(raw) {
                    Ok(name) => self.observe_chars(name.chars(), evidence),
                    Err(_) => self.valid = false,
                }
                return;
            }
            EncodingKind::Cp932 => SHIFT_JIS,
            EncodingKind::Cp936 => GBK,
            EncodingKind::Cp950 => BIG5,
        };
        let mut decoder = encoding.new_decoder_without_bom_handling();
        decoded.clear();
        // ZIP name length is u16, so the decoder's worst-case size fits usize.
        decoded.reserve(
            decoder
                .max_utf8_buffer_length_without_replacement(raw.len())
                .unwrap(),
        );
        let (result, _) = decoder.decode_to_string_without_replacement(raw, decoded, true);
        if result == DecoderResult::InputEmpty {
            self.observe_chars(decoded.chars(), evidence);
        } else {
            // The worker applies one legacy code page to the whole archive.
            // A candidate that fails strict decoding cannot be used globally.
            self.valid = false;
        }
    }

    fn observe_chars(
        &mut self,
        chars: impl Iterator<Item = char>,
        evidence: &mut CharacterEvidence,
    ) {
        for ch in chars {
            let score = match ch {
                '\u{4e00}'..='\u{9fff}' => self.kind.han_score(ch),
                '\u{3040}'..='\u{30ff}' => match self.kind {
                    EncodingKind::Cp437 => 0,
                    EncodingKind::Utf8 => 4,
                    EncodingKind::Cp932 => 6,
                    EncodingKind::Cp936 | EncodingKind::Cp950 => -2,
                },
                '\u{ff66}'..='\u{ff9f}' => match self.kind {
                    EncodingKind::Cp932 => {
                        if evidence.insert(self.kind, ch) {
                            self.halfwidth_kana += 1;
                        }
                        continue;
                    }
                    EncodingKind::Cp936 | EncodingKind::Cp950 => -2,
                    _ => 0,
                },
                '\u{e000}'..='\u{f8ff}' => -8,
                '\u{00a0}'..='\u{00ff}' | '\u{2500}'..='\u{259f}' => {
                    if self.kind == EncodingKind::Cp437 {
                        -3
                    } else {
                        -1
                    }
                }
                '<' | '>' | ':' | '"' | '|' | '?' | '*' => -10,
                '\0'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' => -20,
                _ => 0,
            };
            if score != 0 && evidence.insert(self.kind, ch) {
                self.score += score;
            }
        }
    }
}

#[cfg(test)]
fn select_codepage(raw_names: &[&[u8]]) -> Option<&'static str> {
    let mut scoring = FilenameScoring::new();
    for name in raw_names.iter().filter(|name| !name.is_ascii()) {
        scoring.observe(name);
    }
    scoring.finish()
}

/// Info-ZIP Unicode Path Extra Field (0x7075): version 1, CRC32 of the
/// central-directory raw name, followed by the authoritative UTF-8 name.
fn valid_unicode_path_name(raw_name: &[u8], extra: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 4 <= extra.len() {
        let field_id = read_u16_le(extra, offset);
        let field_len = read_u16_le(extra, offset + 2) as usize;
        let data_start = offset + 4;
        let Some(data_end) = data_start.checked_add(field_len) else {
            return false;
        };
        if data_end > extra.len() {
            return false;
        }
        if field_id == ZIP_UNICODE_PATH_EXTRA_FIELD {
            let data = &extra[data_start..data_end];
            if data.len() >= 6
                && data[0] == 1
                && read_u32_le(data, 1) == crc32fast::hash(raw_name)
                && !data[5..].is_empty()
            {
                if std::str::from_utf8(&data[5..]).is_ok() {
                    return true;
                }
            }
        }
        offset = data_end;
    }
    false
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
#[path = "../../../tests/unit/formats/zip/filename_encoding/tests.rs"]
mod tests;
