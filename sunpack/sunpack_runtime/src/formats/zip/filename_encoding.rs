use crate::io::archive_state::{ArchiveInput, InputExtent};
use crate::io::scratch::SpillSet;
use crate::password::input::{parse_ranges, VirtualRangeReader};
use encoding_rs::{BIG5, GBK, SHIFT_JIS};
use std::borrow::Cow;
use std::collections::HashSet;
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

const SIMPLIFIED_COMMON_CHARS: &str =
    "的一是在不了有和人这中大为上个国我以要他中文说明资料第一章压缩文件测试";
const TRADITIONAL_COMMON_CHARS: &str =
    "的一是在不了有和人這中大為上個國我以要他繁體中文說明資料檔案測試";
const JAPANESE_COMMON_KANJI: &str =
    "日本語説明書第一章画像映像音声写真漫画小説資料設定保存読込名前新旧上下左右大小年月日時分秒人子女男学校会社仕事場所東京大阪京都北海道";
const CP437_HIGH: &str =
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
static CP437_TABLE: OnceLock<Vec<char>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingKind {
    Cp437,
    Utf8,
    Cp936,
    Cp950,
    Cp932,
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
}

struct EncodingScore {
    kind: EncodingKind,
    score: i64,
    has_decoded_name: bool,
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
        if reader.read_at(candidate, super::CD_SIG.len())?.as_slice() == super::CD_SIG {
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
    let mut scoring = FilenameScoring::new();
    let mut authoritative_all = true;
    let mut ascii_only = true;
    let mut window_start = 0u64;
    let mut window = Vec::new();
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
        if !record.name.is_empty() {
            let ascii = record.name.is_ascii();
            let authoritative = if record.flags & ZIP_UTF8_FLAG != 0 {
                ascii || std::str::from_utf8(record.name).is_ok()
            } else {
                valid_unicode_path_name(record.name, record.extra)
            };
            authoritative_all &= authoritative;
            ascii_only &= ascii;
            if !authoritative {
                scoring.observe(record.name, ascii)?;
            }
        }
        checked += 1;
        cursor += length as u64;
    }
    if authoritative_all
        || ascii_only
        || !super::central_directory_complete(cursor, end, |offset, length| {
            reader.read_at(offset, length)
        })?
    {
        return Ok(None);
    }
    Ok(scoring.finish())
}

struct FilenameScoring {
    accumulators: [EncodingAccumulator; 5],
    gbk_big5_units: HashSet<(u8, u8)>,
    shift_jis_units: HashSet<(u8, u8)>,
    has_unflagged_ascii: bool,
}

impl FilenameScoring {
    fn new() -> Self {
        Self {
            accumulators: [
                EncodingKind::Cp437,
                EncodingKind::Utf8,
                EncodingKind::Cp936,
                EncodingKind::Cp950,
                EncodingKind::Cp932,
            ]
            .map(EncodingAccumulator::new),
            gbk_big5_units: HashSet::new(),
            shift_jis_units: HashSet::new(),
            has_unflagged_ascii: false,
        }
    }

    fn observe(&mut self, raw: &[u8], ascii: bool) -> io::Result<()> {
        if ascii {
            self.has_unflagged_ascii = true;
            // ASCII has one interpretation. Compute its common penalties once,
            // while keeping each encoding's component deduplication intact.
            let name = std::str::from_utf8(raw).expect("ASCII ZIP name");
            for part in name.split(['/', '\\']) {
                let score = windows_component_penalty(part);
                if score != 0 {
                    for accumulator in &mut self.accumulators {
                        accumulator.observe_component(part, score)?;
                    }
                }
            }
        } else {
            for accumulator in &mut self.accumulators {
                accumulator.observe(raw)?;
            }
            observe_legacy_units(raw, &mut self.gbk_big5_units, |lead| (0x81..=0xfe).contains(&lead));
            observe_legacy_units(raw, &mut self.shift_jis_units, |lead| {
                (0x81..=0x9f).contains(&lead) || (0xe0..=0xfc).contains(&lead)
            });
        }
        Ok(())
    }

    fn finish(self) -> Option<&'static str> {
        select_scores(self.accumulators.map(|value| {
            let units_score = match value.kind {
                EncodingKind::Cp936 | EncodingKind::Cp950 => legacy_units_score(&self.gbk_big5_units, value.kind),
                EncodingKind::Cp932 => legacy_units_score(&self.shift_jis_units, value.kind),
                _ => 0,
            };
            value.finish(self.has_unflagged_ascii, units_score)
        }))
    }
}

struct EncodingAccumulator {
    kind: EncodingKind,
    score: i64,
    decoded: bool,
    failed_decode: bool,
    components: SpillSet,
}
impl EncodingAccumulator {
    fn new(kind: EncodingKind) -> Self {
        Self {
            kind,
            score: 0,
            decoded: false,
            failed_decode: false,
            components: SpillSet::default(),
        }
    }
    fn observe(&mut self, raw: &[u8]) -> io::Result<()> {
        if let Some(decoded) = decode_bytes(self.kind, raw) {
            self.decoded = true;
            for part in decoded.split(['/', '\\']) {
                self.observe_component(part, score_decoded_name(part, self.kind))?;
            }
        } else {
            self.failed_decode = true;
            self.score = self.score.saturating_sub(12);
        }
        Ok(())
    }
    fn observe_component(&mut self, part: &str, score: i64) -> io::Result<()> {
        if score != 0 && self.components.insert(part)? {
            self.score = self.score.saturating_add(score);
        }
        Ok(())
    }
    fn finish(self, has_ascii: bool, units_score: i64) -> EncodingScore {
        EncodingScore {
            kind: self.kind,
            score: self
                .score
                .saturating_add(units_score)
                .saturating_add(if self.failed_decode { 0 } else { 4 }),
            has_decoded_name: self.decoded || has_ascii,
        }
    }
}

#[cfg(test)]
fn select_codepage(raw_names: &[&[u8]]) -> Option<&'static str> {
    let mut scoring = FilenameScoring::new();
    for name in raw_names {
        scoring.observe(name, name.is_ascii()).unwrap();
    }
    scoring.finish()
}
fn select_scores(mut scores: [EncodingScore; 5]) -> Option<&'static str> {
    scores.sort_by(|left, right| right.score.cmp(&left.score));
    let best = &scores[0];
    let lead = best.score.saturating_sub(scores[1].score);
    (best.kind == EncodingKind::Cp437 || (best.score >= 12 && lead >= 6 && best.has_decoded_name))
        .then(|| best.kind.codepage())
}

fn decode_bytes(encoding: EncodingKind, raw: &[u8]) -> Option<Cow<'_, str>> {
    match encoding {
        EncodingKind::Cp437 => Some(Cow::Owned(decode_cp437(raw))),
        EncodingKind::Utf8 => std::str::from_utf8(raw).ok().map(Cow::Borrowed),
        EncodingKind::Cp936 => GBK.decode_without_bom_handling_and_without_replacement(raw),
        EncodingKind::Cp950 => BIG5.decode_without_bom_handling_and_without_replacement(raw),
        EncodingKind::Cp932 => SHIFT_JIS.decode_without_bom_handling_and_without_replacement(raw),
    }
}

fn decode_cp437(raw: &[u8]) -> String {
    let table = CP437_TABLE.get_or_init(|| CP437_HIGH.chars().collect());
    raw.iter()
        .map(|byte| {
            if *byte < 0x80 {
                *byte as char
            } else {
                table[(*byte - 0x80) as usize]
            }
        })
        .collect()
}

fn observe_legacy_units(raw_name: &[u8], units: &mut HashSet<(u8, u8)>, is_lead: impl Fn(u8) -> bool) {
    let mut index = 0;
    while index + 1 < raw_name.len() {
        let lead = raw_name[index];
        if is_lead(lead) {
            units.insert((lead, raw_name[index + 1]));
            index += 2;
        } else {
            index += 1;
        }
    }
}
fn legacy_units_score(units: &HashSet<(u8, u8)>, encoding: EncodingKind) -> i64 {
    units
        .iter()
        .map(|&(lead, trail)| match encoding {
            EncodingKind::Cp932 => {
                let extension = (lead == 0x87 && (0x40..=0x9c).contains(&trail))
                    || (0xed..=0xee).contains(&lead)
                    || (0xf0..=0xfc).contains(&lead);
                if extension {
                    0
                } else {
                    2
                }
            }
            EncodingKind::Cp936 => {
                if (0xa1..=0xf7).contains(&lead) && (0xa1..=0xfe).contains(&trail) {
                    2
                } else {
                    0
                }
            }
            EncodingKind::Cp950 => {
                let valid_trail = (0x40..=0x7e).contains(&trail) || (0xa1..=0xfe).contains(&trail);
                if (0xa1..=0xf9).contains(&lead) && valid_trail {
                    2
                } else {
                    0
                }
            }
            _ => 0,
        })
        .sum()
}

fn windows_component_penalty(component: &str) -> i64 {
    let mut control = false;
    let mut reserved = false;
    for byte in component.bytes() {
        control |= byte < b' ' && !matches!(byte, b'\t' | b'\n' | b'\r');
        reserved |= matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*');
    }
    -20 * i64::from(control)
        - 10 * i64::from(reserved)
        - 3 * i64::from(matches!(component, "." | ".."))
}

fn score_decoded_name(decoded: &str, encoding: EncodingKind) -> i64 {
    let mut score = windows_component_penalty(decoded);
    // ASCII contributes only the format-independent penalties above.
    // Full-directory scans must not run five Unicode scoring passes over it.
    if decoded.is_ascii() {
        return score;
    }

    let (mut cjk, mut kana, mut halfwidth_kana, mut latin_symbols) = (0, 0, 0, 0);
    for ch in decoded.chars() {
        if ('\u{e000}'..='\u{f8ff}').contains(&ch) {
            score -= 8;
        }
        if ('\u{4e00}'..='\u{9fff}').contains(&ch) {
            cjk += 1;
        }
        if ('\u{3040}'..='\u{30ff}').contains(&ch) {
            kana += 1;
        }
        if ('\u{ff66}'..='\u{ff9f}').contains(&ch) {
            halfwidth_kana += 1;
        }
        if ('\u{00a0}'..='\u{00ff}').contains(&ch) || ('\u{2500}'..='\u{259f}').contains(&ch) {
            latin_symbols += 1;
        }
    }

    match encoding {
        EncodingKind::Cp932 => {
            score += cjk * 3 + kana * 6 + halfwidth_kana * 6;
            score += decoded
                .chars()
                .filter(|ch| JAPANESE_COMMON_KANJI.contains(*ch))
                .count() as i64
                * 4;
            if kana == 0 {
                score -= halfwidth_kana * 3;
            }
        }
        EncodingKind::Cp936 => {
            score += cjk * 3;
            score -= (kana + halfwidth_kana) * 2;
            score += decoded
                .chars()
                .filter(|ch| SIMPLIFIED_COMMON_CHARS.contains(*ch))
                .count() as i64
                * 3;
            score -= decoded
                .chars()
                .filter(|ch| {
                    TRADITIONAL_COMMON_CHARS.contains(*ch) && !SIMPLIFIED_COMMON_CHARS.contains(*ch)
                })
                .count() as i64;
            score -= decoded
                .chars()
                .filter(|ch| {
                    JAPANESE_COMMON_KANJI.contains(*ch) && !SIMPLIFIED_COMMON_CHARS.contains(*ch)
                })
                .count() as i64;
        }
        EncodingKind::Cp950 => {
            score += cjk * 3;
            score -= (kana + halfwidth_kana) * 2;
            score += decoded
                .chars()
                .filter(|ch| TRADITIONAL_COMMON_CHARS.contains(*ch))
                .count() as i64
                * 3;
            score -= decoded
                .chars()
                .filter(|ch| {
                    SIMPLIFIED_COMMON_CHARS.contains(*ch) && !TRADITIONAL_COMMON_CHARS.contains(*ch)
                })
                .count() as i64;
        }
        EncodingKind::Utf8 => {
            score += (cjk + kana) * 4;
        }
        EncodingKind::Cp437 => {
            score -= latin_symbols * 2;
        }
    }
    score - latin_symbols
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
