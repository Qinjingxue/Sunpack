use crate::io::archive_state::{build_segments, Segment};
use crate::io::reader::ManagedReader;
use crate::io::scratch::SpillMap;
use crate::scan::magic::rfind_subslice;
use encoding_rs::{BIG5, GBK, SHIFT_JIS};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::OnceLock;

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

    fn label(self) -> &'static str {
        match self {
            Self::Cp437 => "ZIP default cp437",
            Self::Utf8 => "UTF-8",
            Self::Cp936 => "GBK/CP936",
            Self::Cp950 => "Big5/CP950",
            Self::Cp932 => "Shift-JIS/CP932",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NameStats {
    cjk: usize,
    kana: usize,
    halfwidth_kana: usize,
    latin_symbols: usize,
}

#[derive(Debug, Clone)]
struct EncodingScore {
    kind: EncodingKind,
    score: i64,
    decoded_count: usize,
    stats: NameStats,
}

#[derive(Debug, Clone)]
struct SelectionEvidence {
    best_label: &'static str,
    best_score: i64,
    second_label: &'static str,
    second_score: i64,
    lead: i64,
    stats: NameStats,
}

#[derive(Debug, Clone)]
struct ZipFilenameAnalysis {
    status: &'static str,
    sample_count: usize,
    selected_codepage: Option<&'static str>,
    selected_label: &'static str,
    confidence: f64,
    unicode_count: usize,
    authoritative_all: bool,
    ascii_only: bool,
    evidence: Option<SelectionEvidence>,
}

impl ZipFilenameAnalysis {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            sample_count: 0,
            selected_codepage: None,
            selected_label: "",
            confidence: 0.0,
            unicode_count: 0,
            authoritative_all: false,
            ascii_only: false,
            evidence: None,
        }
    }

    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("status", self.status)?;
        dict.set_item("sample_count", self.sample_count)?;
        dict.set_item("selected_codepage", self.selected_codepage)?;
        dict.set_item("selected_label", self.selected_label)?;
        dict.set_item("confidence", self.confidence)?;
        dict.set_item("unicode_count", self.unicode_count)?;
        dict.set_item("authoritative_all", self.authoritative_all)?;
        dict.set_item("ascii_only", self.ascii_only)?;
        if let Some(evidence) = self.evidence {
            let item = PyDict::new(py);
            item.set_item("best_label", evidence.best_label)?;
            item.set_item("best_score", evidence.best_score)?;
            item.set_item("second_label", evidence.second_label)?;
            item.set_item("second_score", evidence.second_score)?;
            item.set_item("lead", evidence.lead)?;
            item.set_item("cjk_count", evidence.stats.cjk)?;
            item.set_item("kana_count", evidence.stats.kana)?;
            item.set_item("halfwidth_kana_count", evidence.stats.halfwidth_kana)?;
            item.set_item("latin_symbols", evidence.stats.latin_symbols)?;
            dict.set_item("evidence", item)?;
        } else {
            dict.set_item("evidence", py.None())?;
        }
        Ok(dict.unbind())
    }
}

#[derive(Clone)]
struct LogicalSegment {
    reader: ManagedReader,
    physical_start: u64,
    len: u64,
    logical_start: u64,
}

struct ZipLogicalReader {
    segments: Vec<LogicalSegment>,
    len: u64,
    disk_starts: Option<Vec<u64>>,
}

impl ZipLogicalReader {
    fn open(segments: Vec<Segment>, disk_aware: bool) -> io::Result<Self> {
        let mut readers = HashMap::<String, ManagedReader>::new();
        let mut logical_segments = Vec::with_capacity(segments.len());
        let mut starts = Vec::with_capacity(segments.len());
        let mut logical_start = 0u64;

        for segment in segments {
            let Segment::Range { path, start, len } = segment;
            if len == 0 {
                continue;
            }
            let reader = if let Some(reader) = readers.get(&path) {
                reader.clone()
            } else {
                let reader = ManagedReader::open(&path)?;
                readers.insert(path.clone(), reader.clone());
                reader
            };
            starts.push(logical_start);
            logical_segments.push(LogicalSegment {
                reader,
                physical_start: start,
                len,
                logical_start,
            });
            logical_start = logical_start.checked_add(len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ZIP logical input size overflow",
                )
            })?;
        }

        Ok(Self {
            segments: logical_segments,
            len: logical_start,
            disk_starts: disk_aware.then_some(starts),
        })
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn central_logical_offset(&self, disk: usize, offset: u64) -> Option<u64> {
        match &self.disk_starts {
            Some(starts) => starts.get(disk)?.checked_add(offset),
            None if disk == 0 => Some(offset),
            None => None,
        }
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.len || len == 0 {
            return Ok(Vec::new());
        }
        let requested = len.min((self.len - offset) as usize);
        let mut output = vec![0u8; requested];
        let mut cursor = offset;
        let mut written = 0usize;

        while written < requested {
            let index = self
                .segments
                .partition_point(|segment| segment.logical_start + segment.len <= cursor);
            let Some(segment) = self.segments.get(index) else {
                break;
            };
            if cursor < segment.logical_start {
                break;
            }
            let local_offset = cursor - segment.logical_start;
            let available = (segment.len - local_offset) as usize;
            let take = available.min(requested - written);
            let read = segment.reader.read_into_at(
                segment.physical_start + local_offset,
                &mut output[written..written + take],
            )?;
            if read == 0 {
                break;
            }
            written += read;
            cursor += read as u64;
        }
        output.truncate(written);
        Ok(output)
    }
}

#[pyfunction]

pub(crate) fn analyze_zip_filename_encoding(
    py: Python<'_>,
    archive_input: &Bound<'_, PyDict>,
) -> PyResult<Py<PyDict>> {
    let segments = build_segments(archive_input)?;
    let disk_aware = archive_input
        .get_item("volume_style")?
        .map(|value| value.extract::<String>())
        .transpose()?
        .is_some_and(|style| style == "zip_spanned");
    let analysis = py.detach(move || analyze_zip_input(segments, disk_aware))?;
    analysis.into_py_dict(py)
}

fn analyze_zip_input(segments: Vec<Segment>, disk_aware: bool) -> io::Result<ZipFilenameAnalysis> {
    let reader = ZipLogicalReader::open(segments, disk_aware)?;
    scan_zip_names(&reader)
}

fn finish_analysis(
    mut result: ZipFilenameAnalysis,
    accumulators: [EncodingAccumulator; 5],
) -> ZipFilenameAnalysis {
    if result.sample_count == 0 {
        return result;
    }
    if result.authoritative_all {
        result.confidence = 1.0;
        return result;
    }
    if result.ascii_only {
        return result;
    }
    let scores = accumulators.map(EncodingAccumulator::finish);
    let (selection, evidence, confidence) = select_scores(scores);
    result.selected_label = selection.kind.label();
    result.confidence = confidence;
    result.evidence = Some(evidence);
    if matches!(selection.kind, EncodingKind::Cp437)
        || (selection.score >= 12
            && result
                .evidence
                .as_ref()
                .is_some_and(|value| value.lead >= 6)
            && selection.decoded_count > 0)
    {
        result.selected_codepage = Some(selection.kind.codepage());
    }
    result
}

fn scan_zip_names(reader: &ZipLogicalReader) -> io::Result<ZipFilenameAnalysis> {
    let file_size = reader.len();
    if file_size < ZIP_EOCD_LENGTH as u64 {
        return Ok(ZipFilenameAnalysis::status("file_too_small"));
    }

    let search_size = file_size.min(MAX_ZIP_COMMENT_BYTES + ZIP_EOCD_LENGTH as u64);
    let tail_start = file_size - search_size;
    let tail = reader.read_at(tail_start, search_size as usize)?;
    let Some(eocd) = super::find_eocd_record(&tail, false) else {
        let status = rfind_subslice(&tail, ZIP_EOCD_SIGNATURE)
            .filter(|offset| offset.saturating_add(ZIP_EOCD_LENGTH) > tail.len())
            .map(|_| "eocd_incomplete")
            .unwrap_or("eocd_not_found");
        return Ok(ZipFilenameAnalysis::status(status));
    };

    let mut central_disk = super::u16_le(&tail, eocd.offset + 6) as usize;
    let mut total_entries = eocd.total_entries as u64;
    let mut central_size_u64 = eocd.cd_size as u64;
    let mut central_offset = eocd.cd_offset as u64;
    let eocd_logical_offset = tail_start + eocd.offset as u64;
    let mut directory_end = eocd_logical_offset;
    match super::zip64::locate_end_record(
        eocd_logical_offset,
        reader.disk_starts.as_deref(),
        |at, size| reader.read_at(at, size),
    ) {
        Ok(Some(found)) => {
            central_disk = found.record.cd_disk as usize;
            total_entries = found.record.total_entries;
            central_size_u64 = found.record.cd_size;
            central_offset = found.record.cd_offset;
            directory_end = found.offset;
        }
        Ok(None) => {
            if eocd.cd_offset == ZIP64_MARKER || eocd.cd_size == ZIP64_MARKER {
                return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
            }
        }
        Err(_) => return Ok(ZipFilenameAnalysis::status("central_range_invalid")),
    }
    if central_size_u64 == 0 && total_entries == 0 {
        return Ok(ZipFilenameAnalysis::status("ok"));
    }
    let physical_candidate = directory_end.checked_sub(central_size_u64);
    let declared_candidate = reader.central_logical_offset(central_disk, central_offset);
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
        return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
    };

    let end = central_logical_offset
        .checked_add(central_size_u64)
        .ok_or_else(|| io::Error::other("ZIP central range overflow"))?;
    let mut cursor = central_logical_offset;
    let mut accumulators = [
        EncodingKind::Cp437,
        EncodingKind::Utf8,
        EncodingKind::Cp936,
        EncodingKind::Cp950,
        EncodingKind::Cp932,
    ]
    .map(EncodingAccumulator::new);
    let mut result = ZipFilenameAnalysis::status("ok");
    result.authoritative_all = true;
    result.ascii_only = true;
    let mut window_start = 0u64;
    let mut window = Vec::new();
    let mut checked = 0u64;
    while checked < total_entries {
        if cursor < window_start || cursor + 46 > window_start + window.len() as u64 {
            window_start = cursor;
            window = reader.read_at(cursor, (end - cursor).min(64 * 1024) as usize)?;
        }
        let offset = (cursor - window_start) as usize;
        let Some(fixed) = window.get(offset..offset + 46) else {
            return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
        };
        if &fixed[..4] != super::CD_SIG {
            return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
        }
        let length = 46
            + super::u16_le(fixed, 28) as usize
            + super::u16_le(fixed, 30) as usize
            + super::u16_le(fixed, 32) as usize;
        if cursor + length as u64 > end {
            return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
        }
        if offset + length > window.len() {
            window_start = cursor;
            window = reader.read_at(
                cursor,
                (end - cursor).min((64 * 1024).max(length) as u64) as usize,
            )?;
        }
        let offset = (cursor - window_start) as usize;
        let Some(record) = super::parse_central_directory_record(&window, offset, window.len())
        else {
            return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
        };
        if !record.name.is_empty() {
            result.sample_count += 1;
            let unicode = valid_unicode_path_name(record.name, record.extra);
            result.unicode_count += usize::from(unicode);
            let authoritative = if record.flags & ZIP_UTF8_FLAG != 0 {
                std::str::from_utf8(record.name).is_ok()
            } else {
                unicode
            };
            result.authoritative_all &= authoritative;
            result.ascii_only &= record.name.is_ascii();
            if !authoritative {
                for accumulator in &mut accumulators {
                    accumulator.observe(record.name)?;
                }
            }
        }
        checked += 1;
        cursor += length as u64;
    }
    if !super::central_directory_complete(cursor, end, |offset, length| {
        reader.read_at(offset, length)
    })? {
        return Ok(ZipFilenameAnalysis::status("central_range_invalid"));
    }
    Ok(finish_analysis(result, accumulators))
}

struct EncodingAccumulator {
    kind: EncodingKind,
    score: i64,
    decoded_count: usize,
    count: usize,
    components: SpillMap<()>,
    units: HashSet<(u8, u8)>,
    stats: NameStats,
}
impl EncodingAccumulator {
    fn new(kind: EncodingKind) -> Self {
        Self {
            kind,
            score: 0,
            decoded_count: 0,
            count: 0,
            components: SpillMap::default(),
            units: HashSet::new(),
            stats: NameStats::default(),
        }
    }
    fn observe(&mut self, raw: &[u8]) -> io::Result<()> {
        self.count += 1;
        if raw.is_ascii() {
            self.decoded_count += 1;
            return self.observe_components(std::str::from_utf8(raw).unwrap());
        }
        if let Some(decoded) = decode_bytes(self.kind, raw) {
            self.decoded_count += 1;
            self.observe_components(&decoded)?;
        } else {
            self.score = self.score.saturating_sub(12);
        }
        observe_legacy_units(raw, self.kind, &mut self.units);
        Ok(())
    }
    fn observe_components(&mut self, decoded: &str) -> io::Result<()> {
        for part in decoded.split(['/', '\\']).filter(|part| !part.is_empty()) {
            let (score, stats) = score_decoded_name(part, self.kind);
            if score == 0
                && stats.cjk == 0
                && stats.kana == 0
                && stats.halfwidth_kana == 0
                && stats.latin_symbols == 0
            {
                continue;
            }
            if self.components.insert_new(part.to_owned(), ())? {
                self.score = self.score.saturating_add(score);
                self.stats.cjk += stats.cjk;
                self.stats.kana += stats.kana;
                self.stats.halfwidth_kana += stats.halfwidth_kana;
                self.stats.latin_symbols += stats.latin_symbols;
            }
        }
        Ok(())
    }
    fn finish(self) -> EncodingScore {
        EncodingScore {
            kind: self.kind,
            score: self
                .score
                .saturating_add(legacy_units_score(self.units, self.kind))
                .saturating_add(if self.decoded_count == self.count {
                    4
                } else {
                    0
                }),
            decoded_count: self.decoded_count,
            stats: self.stats,
        }
    }
}

#[cfg(test)]
fn select_codepage(raw_names: &[&[u8]]) -> (EncodingScore, SelectionEvidence, f64) {
    let scores = [
        EncodingKind::Cp437,
        EncodingKind::Utf8,
        EncodingKind::Cp936,
        EncodingKind::Cp950,
        EncodingKind::Cp932,
    ]
    .map(|kind| {
        let mut accumulator = EncodingAccumulator::new(kind);
        for name in raw_names {
            accumulator.observe(name).unwrap();
        }
        accumulator.finish()
    });
    select_scores(scores)
}
fn select_scores(mut scores: [EncodingScore; 5]) -> (EncodingScore, SelectionEvidence, f64) {
    scores.sort_by(|left, right| right.score.cmp(&left.score));
    let best = scores[0].clone();
    let second = scores[1].clone();
    let lead = best.score - second.score;
    let score_confidence = (best.score as f64 / 24.0).clamp(0.0, 1.0);
    let lead_confidence = (lead as f64 / 12.0).clamp(0.0, 1.0);
    let confidence = (score_confidence.min(lead_confidence) * 1000.0).round() / 1000.0;
    let evidence = SelectionEvidence {
        best_label: best.kind.label(),
        best_score: best.score,
        second_label: second.kind.label(),
        second_score: second.score,
        lead,
        stats: best.stats.clone(),
    };
    (best, evidence, confidence)
}

fn decode_bytes(encoding: EncodingKind, raw: &[u8]) -> Option<String> {
    match encoding {
        EncodingKind::Cp437 => Some(decode_cp437(raw)),
        EncodingKind::Utf8 => std::str::from_utf8(raw).ok().map(str::to_owned),
        EncodingKind::Cp936 => GBK
            .decode_without_bom_handling_and_without_replacement(raw)
            .map(|value| value.into_owned()),
        EncodingKind::Cp950 => BIG5
            .decode_without_bom_handling_and_without_replacement(raw)
            .map(|value| value.into_owned()),
        EncodingKind::Cp932 => SHIFT_JIS
            .decode_without_bom_handling_and_without_replacement(raw)
            .map(|value| value.into_owned()),
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

fn observe_legacy_units(raw_name: &[u8], encoding: EncodingKind, units: &mut HashSet<(u8, u8)>) {
    if !matches!(
        encoding,
        EncodingKind::Cp932 | EncodingKind::Cp936 | EncodingKind::Cp950
    ) {
        return;
    }
    let mut index = 0;
    while index + 1 < raw_name.len() {
        let lead = raw_name[index];
        let is_lead = match encoding {
            EncodingKind::Cp932 => (0x81..=0x9f).contains(&lead) || (0xe0..=0xfc).contains(&lead),
            _ => (0x81..=0xfe).contains(&lead),
        };
        if is_lead {
            units.insert((lead, raw_name[index + 1]));
            index += 2;
        } else {
            index += 1;
        }
    }
}
fn legacy_units_score(units: HashSet<(u8, u8)>, encoding: EncodingKind) -> i64 {
    units
        .into_iter()
        .map(|(lead, trail)| match encoding {
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

fn score_decoded_name(decoded: &str, encoding: EncodingKind) -> (i64, NameStats) {
    let mut score = 0i64;
    let mut stats = NameStats::default();
    if decoded.is_empty() {
        return (-5, stats);
    }

    if decoded.contains('\0')
        || decoded
            .chars()
            .any(|ch| ch < ' ' && !matches!(ch, '\t' | '\n' | '\r'))
    {
        score -= 20;
    }
    if decoded
        .chars()
        .any(|ch| matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        score -= 10;
    }
    if decoded == "." || decoded == ".." {
        score -= 3;
    }

    // ASCII contributes only the format-independent penalties above.
    // Full-directory scans must not run five Unicode scoring passes over it.
    if decoded.is_ascii() {
        return (score, stats);
    }

    score -= decoded
        .chars()
        .filter(|ch| ('\u{e000}'..='\u{f8ff}').contains(ch))
        .count() as i64
        * 8;

    for ch in decoded.chars() {
        if ('\u{4e00}'..='\u{9fff}').contains(&ch) {
            stats.cjk += 1;
        }
        if ('\u{3040}'..='\u{30ff}').contains(&ch) {
            stats.kana += 1;
        }
        if ('\u{ff66}'..='\u{ff9f}').contains(&ch) {
            stats.halfwidth_kana += 1;
        }
        if ('\u{00a0}'..='\u{00ff}').contains(&ch) || ('\u{2500}'..='\u{259f}').contains(&ch) {
            stats.latin_symbols += 1;
        }
    }

    match encoding {
        EncodingKind::Cp932 => {
            score += stats.cjk as i64 * 3 + stats.kana as i64 * 6 + stats.halfwidth_kana as i64 * 6;
            score += decoded
                .chars()
                .filter(|ch| JAPANESE_COMMON_KANJI.contains(*ch))
                .count() as i64
                * 4;
            if stats.halfwidth_kana > 0 && stats.kana == 0 {
                score -= stats.halfwidth_kana as i64 * 3;
            }
        }
        EncodingKind::Cp936 => {
            score += stats.cjk as i64 * 3;
            score -= (stats.kana + stats.halfwidth_kana) as i64 * 2;
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
            score += stats.cjk as i64 * 3;
            score -= (stats.kana + stats.halfwidth_kana) as i64 * 2;
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
            score += (stats.cjk + stats.kana) as i64 * 4;
        }
        EncodingKind::Cp437 => {
            score -= stats.latin_symbols as i64 * 2;
        }
    }
    score -= stats.latin_symbols as i64;
    (score, stats)
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
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    #[test]
    fn zip_scan_collects_central_directory_names() {
        let raw_name = "中文/说明.txt".as_bytes();
        let local = b"local payload before central directory".to_vec();
        let central_offset = local.len() as u32;
        let mut central = vec![0; ZIP_CENTRAL_HEADER_LENGTH];
        central[0..4].copy_from_slice(ZIP_CENTRAL_DIRECTORY_SIGNATURE);
        central[8..10].copy_from_slice(&ZIP_UTF8_FLAG.to_le_bytes());
        central[28..30].copy_from_slice(&(raw_name.len() as u16).to_le_bytes());
        central.extend_from_slice(raw_name);
        let eocd = [
            ZIP_EOCD_SIGNATURE,
            &[0, 0, 0, 0],
            &1u16.to_le_bytes(),
            &1u16.to_le_bytes(),
            &(central.len() as u32).to_le_bytes(),
            &central_offset.to_le_bytes(),
            &[0, 0],
        ]
        .concat();
        let contents = [local, central, eocd].concat();
        let path = temp_file("zip_names", &contents);
        let reader = ZipLogicalReader::open(
            vec![Segment::Range {
                path: path.to_string_lossy().to_string(),
                start: 0,
                len: contents.len() as u64,
            }],
            false,
        )
        .unwrap();

        let scan = scan_zip_names(&reader).unwrap();

        assert_eq!(scan.status, "ok");
        assert_eq!(scan.sample_count, 1);
        assert!(scan.authoritative_all);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zip_scan_validates_unicode_path_extra_field() {
        let raw_name = "日本語.txt".as_bytes().to_vec();
        let unicode_name = "正しい名前.txt".as_bytes();
        let mut extra = Vec::new();
        extra.extend_from_slice(&ZIP_UNICODE_PATH_EXTRA_FIELD.to_le_bytes());
        extra.extend_from_slice(&((5 + unicode_name.len()) as u16).to_le_bytes());
        extra.push(1);
        extra.extend_from_slice(&crc32fast::hash(&raw_name).to_le_bytes());
        extra.extend_from_slice(unicode_name);

        assert!(valid_unicode_path_name(&raw_name, &extra));
        extra[5] ^= 1;
        assert!(!valid_unicode_path_name(&raw_name, &extra));
    }

    #[test]
    fn scoring_keeps_repeated_shift_jis_parent_from_looking_like_gbk() {
        let parent = "無知_製品0519c";
        let mut owned = Vec::new();
        for index in 0..2500 {
            let value = format!("{parent}/assets/file_{index:04}.bin");
            let (bytes, _, had_errors) = SHIFT_JIS.encode(&value);
            assert!(!had_errors);
            owned.push(bytes.into_owned());
        }
        let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let (selected, _, _) = select_codepage(&refs);
        assert_eq!(selected.kind, EncodingKind::Cp932);
    }

    #[test]
    fn scoring_keeps_shift_jis_kanji_only_name() {
        let (bytes, _, had_errors) = SHIFT_JIS.encode("更新履歴.txt");
        assert!(!had_errors);
        let refs = [bytes.as_ref()];
        let (selected, _, _) = select_codepage(&refs);
        assert_eq!(selected.kind, EncodingKind::Cp932);
    }
}
