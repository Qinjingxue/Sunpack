use crate::io::archive_state::{build_segments, Segment};
use crate::io::reader::ManagedReader;
use crate::scan::magic::rfind_subslice;
use encoding_rs::{BIG5, GBK, SHIFT_JIS};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::OnceLock;

const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP_UTF8_FLAG: u16 = 0x800;
const ZIP_UNICODE_PATH_EXTRA_FIELD: u16 = 0x7075;
const ZIP64_MARKER: u32 = 0xFFFF_FFFF;
const ZIP_EOCD_LENGTH: usize = 22;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZipNameEntry {
    name_start: usize,
    name_end: usize,
    utf8_flag: bool,
    unicode_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZipNameScan {
    status: &'static str,
    central: Vec<u8>,
    entries: Vec<ZipNameEntry>,
    truncated: bool,
}

impl ZipNameScan {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            central: Vec::new(),
            entries: Vec::new(),
            truncated: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingKind {
    Cp437,
    Utf8,
    Cp936,
    Cp950,
    Cp932,
}

impl EncodingKind {
    fn codepage(self) -> Option<&'static str> {
        match self {
            Self::Cp437 => None,
            Self::Utf8 => Some("65001"),
            Self::Cp936 => Some("936"),
            Self::Cp950 => Some("950"),
            Self::Cp932 => Some("932"),
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
    truncated: bool,
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
            truncated: false,
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
        dict.set_item("truncated", self.truncated)?;
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
                io::Error::new(io::ErrorKind::InvalidData, "ZIP logical input size overflow")
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
#[pyo3(signature = (archive_input, max_samples, max_filename_bytes))]
pub(crate) fn analyze_zip_filename_encoding(
    py: Python<'_>,
    archive_input: &Bound<'_, PyDict>,
    max_samples: usize,
    max_filename_bytes: usize,
) -> PyResult<Py<PyDict>> {
    let segments = build_segments(archive_input)?;
    let disk_aware = archive_input
        .get_item("volume_style")?
        .map(|value| value.extract::<String>())
        .transpose()?
        .is_some_and(|style| style == "zip_spanned");
    let analysis = py.detach(move || {
        analyze_zip_input(segments, disk_aware, max_samples, max_filename_bytes)
    })?;
    analysis.into_py_dict(py)
}

fn analyze_zip_input(
    segments: Vec<Segment>,
    disk_aware: bool,
    max_samples: usize,
    max_filename_bytes: usize,
) -> io::Result<ZipFilenameAnalysis> {
    let reader = ZipLogicalReader::open(segments, disk_aware)?;
    let scan = scan_zip_names(&reader, max_samples, max_filename_bytes)?;
    if scan.status != "ok" {
        return Ok(ZipFilenameAnalysis::status(scan.status));
    }

    let sample_count = scan.entries.len();
    let unicode_count = scan
        .entries
        .iter()
        .filter(|entry| entry.unicode_path)
        .count();
    let authoritative_all = !scan.entries.is_empty()
        && scan
            .entries
            .iter()
            .all(|entry| has_authoritative_name(entry, &scan.central));
    let ascii_only = !scan.entries.is_empty()
        && scan.entries.iter().all(|entry| {
            scan.central[entry.name_start..entry.name_end]
                .iter()
                .all(|byte| *byte < 128)
        });

    let mut result = ZipFilenameAnalysis {
        status: "ok",
        truncated: scan.truncated,
        sample_count,
        selected_codepage: None,
        selected_label: "",
        confidence: 0.0,
        unicode_count,
        authoritative_all,
        ascii_only,
        evidence: None,
    };

    if scan.truncated || scan.entries.is_empty() {
        return Ok(result);
    }
    if authoritative_all {
        result.confidence = 1.0;
        return Ok(result);
    }
    if ascii_only {
        return Ok(result);
    }

    let unresolved = scan
        .entries
        .iter()
        .filter(|entry| !has_authoritative_name(entry, &scan.central))
        .map(|entry| &scan.central[entry.name_start..entry.name_end])
        .collect::<Vec<_>>();
    let (selection, evidence, confidence) = select_codepage(&unresolved);
    result.selected_label = selection.kind.label();
    result.confidence = confidence;
    result.evidence = Some(evidence);

    if selection.kind.codepage().is_some()
        && selection.score >= 12
        && result.evidence.as_ref().is_some_and(|value| value.lead >= 6)
        && selection.decoded_count > 0
    {
        result.selected_codepage = selection.kind.codepage();
    }
    Ok(result)
}

fn scan_zip_names(
    reader: &ZipLogicalReader,
    max_samples: usize,
    max_filename_bytes: usize,
) -> io::Result<ZipNameScan> {
    let file_size = reader.len();
    if file_size < ZIP_EOCD_LENGTH as u64 {
        return Ok(ZipNameScan::status("file_too_small"));
    }

    let search_size = file_size.min(MAX_ZIP_COMMENT_BYTES + ZIP_EOCD_LENGTH as u64);
    let tail_start = file_size - search_size;
    let tail = reader.read_at(tail_start, search_size as usize)?;
    let Some(eocd) = super::find_eocd_record(&tail, false) else {
        let status = rfind_subslice(&tail, ZIP_EOCD_SIGNATURE)
            .filter(|offset| offset.saturating_add(ZIP_EOCD_LENGTH) > tail.len())
            .map(|_| "eocd_incomplete")
            .unwrap_or("eocd_not_found");
        return Ok(ZipNameScan::status(status));
    };

    let central_disk = super::u16_le(&tail, eocd.offset + 6) as usize;
    let total_entries = eocd.total_entries as usize;
    let central_size = eocd.cd_size;
    let central_offset = eocd.cd_offset;
    if central_offset == ZIP64_MARKER || central_size == ZIP64_MARKER {
        return Ok(ZipNameScan::status("zip64"));
    }
    if central_size == 0 && total_entries == 0 {
        return Ok(ZipNameScan {
            status: "ok",
            central: Vec::new(),
            entries: Vec::new(),
            truncated: false,
        });
    }

    let central_size_u64 = central_size as u64;
    let eocd_logical_offset = tail_start.saturating_add(eocd.offset as u64);
    let physical_candidate = eocd_logical_offset.checked_sub(central_size_u64);
    let declared_candidate =
        reader.central_logical_offset(central_disk, central_offset as u64);
    let mut central_logical_offset = None;
    for candidate in [physical_candidate, declared_candidate].into_iter().flatten() {
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
        return Ok(ZipNameScan::status("central_range_invalid"));
    };

    let metadata_budget = (ZIP_CENTRAL_HEADER_LENGTH as u64)
        .saturating_mul(max_samples as u64)
        .saturating_add(max_filename_bytes as u64);
    let read_size = central_size_u64.min(metadata_budget);
    let read_size = usize::try_from(read_size).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "ZIP central directory range too large")
    })?;
    let central = reader.read_at(central_logical_offset, read_size)?;
    Ok(collect_zip_names(
        central,
        total_entries,
        max_samples,
        max_filename_bytes,
    ))
}

fn collect_zip_names(
    central: Vec<u8>,
    total_entries: usize,
    max_samples: usize,
    max_filename_bytes: usize,
) -> ZipNameScan {
    let mut entries = Vec::new();
    let mut filename_bytes = 0usize;
    let mut offset = 0usize;
    let expected_entries = if total_entries == 0 {
        max_samples
    } else {
        total_entries.min(max_samples)
    };
    let mut truncated = total_entries > max_samples;

    while entries.len() < expected_entries {
        let Some(record) = super::parse_central_directory_record(&central, offset, central.len()) else {
            if offset
                .checked_add(ZIP_CENTRAL_HEADER_LENGTH)
                .is_some_and(|end| end <= central.len())
                && central.get(offset..offset + 4) == Some(super::CD_SIG)
            {
                truncated = true;
            }
            break;
        };

        if !record.name.is_empty() {
            entries.push(ZipNameEntry {
                name_start: record.offset + 46,
                name_end: record.offset + 46 + record.name.len(),
                utf8_flag: record.flags & ZIP_UTF8_FLAG != 0,
                unicode_path: valid_unicode_path_name(record.name, record.extra),
            });
            filename_bytes = filename_bytes.saturating_add(record.name.len());
        }
        offset = record.end;
        if filename_bytes >= max_filename_bytes {
            truncated = true;
            break;
        }
    }

    if total_entries == 0
        && entries.len() == max_samples
        && super::parse_central_directory_record(&central, offset, central.len()).is_some()
    {
        truncated = true;
    }

    ZipNameScan {
        status: "ok",
        central,
        entries,
        truncated,
    }
}

fn has_authoritative_name(entry: &ZipNameEntry, central: &[u8]) -> bool {
    if entry.utf8_flag {
        std::str::from_utf8(&central[entry.name_start..entry.name_end]).is_ok()
    } else {
        entry.unicode_path
    }
}

fn select_codepage(raw_names: &[&[u8]]) -> (EncodingScore, SelectionEvidence, f64) {
    let mut scores = [
        score_encoding(raw_names, EncodingKind::Cp437),
        score_encoding(raw_names, EncodingKind::Utf8),
        score_encoding(raw_names, EncodingKind::Cp936),
        score_encoding(raw_names, EncodingKind::Cp950),
        score_encoding(raw_names, EncodingKind::Cp932),
    ];
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

fn score_encoding(raw_names: &[&[u8]], encoding: EncodingKind) -> EncodingScore {
    let mut score = 0i64;
    let mut decoded_count = 0usize;
    let mut components = HashSet::<String>::new();

    for raw_name in raw_names {
        let Some(decoded) = decode_bytes(encoding, raw_name) else {
            score -= 12;
            continue;
        };
        decoded_count += 1;
        for component in decoded.split(|ch| ch == '\\' || ch == '/') {
            if !component.is_empty() {
                components.insert(component.to_string());
            }
        }
    }

    let mut total_stats = NameStats::default();
    for component in components {
        let (component_score, stats) = score_decoded_name(&component, encoding);
        score += component_score;
        total_stats.cjk += stats.cjk;
        total_stats.kana += stats.kana;
        total_stats.halfwidth_kana += stats.halfwidth_kana;
        total_stats.latin_symbols += stats.latin_symbols;
    }

    score += score_legacy_code_units(raw_names, encoding);
    if decoded_count == raw_names.len() {
        score += 4;
    }

    EncodingScore {
        kind: encoding,
        score,
        decoded_count,
        stats: total_stats,
    }
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

fn score_legacy_code_units(raw_names: &[&[u8]], encoding: EncodingKind) -> i64 {
    if !matches!(
        encoding,
        EncodingKind::Cp932 | EncodingKind::Cp936 | EncodingKind::Cp950
    ) {
        return 0;
    }

    let mut units = HashSet::<(u8, u8)>::new();
    for raw_name in raw_names {
        let mut index = 0usize;
        while index + 1 < raw_name.len() {
            let lead = raw_name[index];
            let is_lead = match encoding {
                EncodingKind::Cp932 => {
                    (0x81..=0x9f).contains(&lead) || (0xe0..=0xfc).contains(&lead)
                }
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

    units
        .into_iter()
        .map(|(lead, trail)| match encoding {
            EncodingKind::Cp932 => {
                let extension = (lead == 0x87 && (0x40..=0x9c).contains(&trail))
                    || (0xed..=0xee).contains(&lead)
                    || (0xf0..=0xfc).contains(&lead);
                if extension { 0 } else { 2 }
            }
            EncodingKind::Cp936 => {
                if (0xa1..=0xf7).contains(&lead) && (0xa1..=0xfe).contains(&trail) {
                    2
                } else {
                    0
                }
            }
            EncodingKind::Cp950 => {
                let valid_trail =
                    (0x40..=0x7e).contains(&trail) || (0xa1..=0xfe).contains(&trail);
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
        if ('\u{00a0}'..='\u{00ff}').contains(&ch)
            || ('\u{2500}'..='\u{259f}').contains(&ch)
        {
            stats.latin_symbols += 1;
        }
    }

    match encoding {
        EncodingKind::Cp932 => {
            score += stats.cjk as i64 * 3
                + stats.kana as i64 * 6
                + stats.halfwidth_kana as i64 * 6;
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
                    TRADITIONAL_COMMON_CHARS.contains(*ch)
                        && !SIMPLIFIED_COMMON_CHARS.contains(*ch)
                })
                .count() as i64;
            score -= decoded
                .chars()
                .filter(|ch| {
                    JAPANESE_COMMON_KANJI.contains(*ch)
                        && !SIMPLIFIED_COMMON_CHARS.contains(*ch)
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
                    SIMPLIFIED_COMMON_CHARS.contains(*ch)
                        && !TRADITIONAL_COMMON_CHARS.contains(*ch)
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

        let scan = scan_zip_names(&reader, 2000, 1024 * 1024).unwrap();

        assert_eq!(scan.status, "ok");
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(
            &scan.central[scan.entries[0].name_start..scan.entries[0].name_end],
            raw_name
        );
        assert!(scan.entries[0].utf8_flag);
        assert!(!scan.entries[0].unicode_path);
        assert!(!scan.truncated);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zip_name_sample_limit_is_reported_as_truncated() {
        let mut central = Vec::new();
        for raw_name in [b"a.txt".as_slice(), b"b.txt".as_slice()] {
            let mut record = vec![0; ZIP_CENTRAL_HEADER_LENGTH];
            record[0..4].copy_from_slice(ZIP_CENTRAL_DIRECTORY_SIGNATURE);
            record[28..30].copy_from_slice(&(raw_name.len() as u16).to_le_bytes());
            record.extend_from_slice(raw_name);
            central.extend_from_slice(&record);
        }

        let scan = collect_zip_names(central, 2, 1, 1024);

        assert_eq!(scan.entries.len(), 1);
        assert!(scan.truncated);
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
        let parent = "無知ロリと化け物_製品0519c";
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
