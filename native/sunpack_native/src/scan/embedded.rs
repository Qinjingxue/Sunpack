#[cfg(windows)]
use crate::io::iocp;
use crate::io::reader::ManagedReader;
use crate::scan::compression_stream::{
    resolve_xz_boundary_exact, validate_bzip2_structure, validate_gzip_structure,
    validate_zstd_structure, ValidationError,
};
use aho_corasick::{packed, AhoCorasick};
use crc32fast::hash as crc32;
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io;
use std::sync::OnceLock;

use rayon::prelude::*;

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const TAR_USTAR: &[u8] = b"ustar";
const XZ_FOOTER_MAGIC: &[u8] = b"YZ";

type PatternSpec = (&'static [u8], &'static str, &'static str);

const PATTERNS: [PatternSpec; 10] = [
    (ZIP_LOCAL, "zip_local", "zip"),
    (ZIP_EOCD, "zip_eocd", "zip_eocd"),
    (SEVEN_ZIP, "7z", "7z"),
    (RAR4, "rar4", "rar4"),
    (RAR5, "rar5", "rar5"),
    (GZIP, "gzip", "gzip"),
    (BZIP2, "bzip2", "bzip2"),
    (XZ, "xz", "xz"),
    (ZSTD, "zstd", "zstd"),
    (TAR_USTAR, "tar_ustar", "tar"),
];
const XZ_PATTERN_INDEX: usize = 7;
const ZSTD_PATTERN_INDEX: usize = 8;

static EMBEDDED_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();
static EMBEDDED_PACKED_MATCHER: OnceLock<Option<packed::Searcher>> = OnceLock::new();

const DEFAULT_IOCP_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const DEFAULT_IOCP_BUFFERS: usize = 2;
const DEFAULT_IOCP_WORKERS: usize = 4;
const MAX_ARCHIVE_METADATA_RECORDS: usize = 1_000_000;
const MAX_VALIDATION_RAW_HITS: usize = 1_000_000;
#[cfg(test)]
const TEST_IOCP_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
struct EmbeddedCandidate {
    format: &'static str,
    offset: u64,
    end_offset: Option<u64>,
    confidence: f64,
    validation: &'static str,
    candidate_kind: &'static str,
    boundary_kind: &'static str,
    extractable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHit {
    hit_name: &'static str,
    kind: &'static str,
    offset: u64,
}

struct NativeScanResult {
    file_size: u64,
    scan_read_bytes: u64,
    scan_read_operations: u64,
    raw_hits: Vec<RawHit>,
    candidates: Vec<EmbeddedCandidate>,
    logical_resolution_complete: bool,
    raw_hit_count: usize,
    budget_exhausted: bool,
}

/// Scan one physical byte stream once for every supported embedded format.
///
/// Raw signatures are never returned directly: each hit must pass the format's
/// structural header checks. The scan deliberately has no hit or byte budget;
/// callers select which files receive this reliable pass before invoking it.
#[pyfunction]
pub(crate) fn scan_embedded_archives(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
    let owned_path = path.to_owned();
    let reader = py.detach(move || ManagedReader::open(&owned_path))?;
    scan_embedded_archives_with_reader(
        py,
        &reader,
        DEFAULT_IOCP_CHUNK_SIZE,
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
    )
}

pub(crate) fn scan_embedded_archives_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    iocp_chunk_bytes: usize,
    iocp_buffers: usize,
    iocp_workers: usize,
) -> PyResult<Py<PyDict>> {
    let reader = reader.clone();
    let scan = py.detach(move || {
        scan_embedded_archives_native_with_iocp(
            reader,
            iocp_chunk_bytes,
            iocp_buffers,
            iocp_workers,
        )
    })?;

    let result = PyDict::new(py);
    result.set_item("complete", !scan.budget_exhausted)?;
    result.set_item("signature_scan_complete", !scan.budget_exhausted)?;
    result.set_item(
        "logical_resolution_complete",
        scan.logical_resolution_complete,
    )?;
    result.set_item("file_size", scan.file_size)?;
    result.set_item("read_bytes", scan.file_size)?;
    result.set_item("scan_read_bytes", scan.scan_read_bytes)?;
    result.set_item("scan_read_operations", scan.scan_read_operations)?;
    result.set_item("raw_hit_count", scan.raw_hit_count)?;
    result.set_item("budget_exhausted", scan.budget_exhausted)?;
    let hit_rows = PyList::empty(py);
    for hit in scan.raw_hits {
        let row = PyDict::new(py);
        row.set_item("name", hit.hit_name)?;
        row.set_item(
            "offset",
            if hit.kind == "tar" {
                hit.offset + 257
            } else {
                hit.offset
            },
        )?;
        row.set_item("source", "detection_embedded_scan")?;
        hit_rows.append(row)?;
    }
    result.set_item("hits", hit_rows)?;
    let rows = PyList::empty(py);
    for candidate in scan.candidates {
        let row = PyDict::new(py);
        row.set_item("format", candidate.format)?;
        row.set_item("offset", candidate.offset)?;
        row.set_item("end_offset", candidate.end_offset)?;
        row.set_item("confidence", candidate.confidence)?;
        row.set_item("validation", candidate.validation)?;
        row.set_item("candidate_kind", candidate.candidate_kind)?;
        row.set_item("boundary_kind", candidate.boundary_kind)?;
        row.set_item("extractable", candidate.extractable)?;
        rows.append(row)?;
    }
    result.set_item("candidates", rows)?;
    Ok(result.unbind())
}

fn embedded_matcher() -> &'static AhoCorasick {
    EMBEDDED_MATCHER.get_or_init(|| {
        AhoCorasick::new(PATTERNS.iter().map(|(magic, _, _)| *magic))
            .expect("embedded archive signatures are valid")
    })
}

fn embedded_packed_matcher() -> Option<&'static packed::Searcher> {
    EMBEDDED_PACKED_MATCHER
        .get_or_init(|| packed::Searcher::new(PATTERNS.iter().map(|(magic, _, _)| *magic)))
        .as_ref()
}

#[cfg(test)]
fn scan_embedded_archives_native(reader: ManagedReader) -> io::Result<NativeScanResult> {
    scan_embedded_archives_native_with_iocp(
        reader,
        DEFAULT_IOCP_CHUNK_SIZE,
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
    )
}

fn scan_embedded_archives_native_with_iocp(
    reader: ManagedReader,
    iocp_chunk_bytes: usize,
    iocp_buffers: usize,
    iocp_workers: usize,
) -> io::Result<NativeScanResult> {
    let file_size = reader.len();
    let (mut raw_hits, scan_read_bytes, scan_read_operations) = {
        #[cfg(windows)]
        {
            let path = reader.iocp_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IOCP embedded scanning requires a single regular file",
                )
            })?;
            let output = iocp::scan_file(
                path,
                file_size,
                iocp_chunk_bytes,
                iocp_buffers,
                iocp_workers,
                embedded_overlap(),
                scan_sample,
            )?;
            (output.results, output.read_bytes, output.read_operations)
        }
        #[cfg(not(windows))]
        {
            let _ = (
                reader,
                file_size,
                iocp_chunk_bytes,
                iocp_buffers,
                iocp_workers,
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IOCP embedded scanning requires Windows",
            ));
        }
    };
    let mut xz_footer_ends = raw_hits
        .iter()
        .filter(|hit| hit.kind == "xz_footer")
        .map(|hit| hit.offset + XZ_FOOTER_MAGIC.len() as u64)
        .collect::<Vec<_>>();
    xz_footer_ends.sort_unstable();
    raw_hits.retain(|hit| hit.kind != "xz_footer");
    raw_hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
    let raw_hit_count = raw_hits.len();
    if raw_hit_count > MAX_VALIDATION_RAW_HITS {
        return Ok(NativeScanResult {
            file_size,
            raw_hits: Vec::new(),
            candidates: Vec::new(),
            logical_resolution_complete: false,
            raw_hit_count,
            budget_exhausted: true,
            scan_read_bytes,
            scan_read_operations,
        });
    }

    let mut candidates = validate_raw_hits(&reader, file_size, &raw_hits, &xz_footer_ends)?;
    candidates.sort_by_key(|candidate| {
        (
            candidate.offset,
            candidate.format,
            std::cmp::Reverse(candidate_rank(candidate)),
        )
    });
    candidates.dedup_by_key(|candidate| (candidate.offset, candidate.format));
    resolve_logical_candidates(&mut candidates);
    let logical_resolution_complete = candidates
        .iter()
        .filter(|candidate| candidate.candidate_kind == "logical_archive")
        .all(|candidate| candidate.boundary_kind == "exact");

    Ok(NativeScanResult {
        file_size,
        scan_read_bytes,
        scan_read_operations,
        raw_hits,
        candidates,
        logical_resolution_complete,
        raw_hit_count,
        budget_exhausted: false,
    })
}

fn embedded_overlap() -> usize {
    PATTERNS
        .iter()
        .map(|(magic, _, _)| magic.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1)
}

fn validate_raw_hits(
    reader: &ManagedReader,
    file_size: u64,
    raw_hits: &[RawHit],
    xz_footer_ends: &[u64],
) -> io::Result<Vec<EmbeddedCandidate>> {
    let collect_parallel = |hits: Vec<&RawHit>| -> io::Result<Vec<EmbeddedCandidate>> {
        hits.par_iter()
            .map(|hit| validate_candidate(reader, file_size, hit.kind, hit.offset))
            .collect::<io::Result<Vec<_>>>()
            .map(|items| items.into_iter().flatten().collect())
    };

    // EOCD validation walks the central directory and links every member back
    // to its local header.  Validate these logical roots first, then avoid
    // repeating a local-header probe for every member they already cover.
    let mut candidates = collect_parallel(
        raw_hits
            .iter()
            .filter(|hit| hit.kind == "zip_eocd")
            .collect(),
    )?;
    let zip_ranges = candidates
        .iter()
        .filter(|candidate| candidate.format == "zip" && candidate.boundary_kind == "exact")
        .filter_map(|candidate| candidate.end_offset.map(|end| (candidate.offset, end)))
        .collect::<Vec<_>>();

    let mut ordinary = collect_parallel(
        raw_hits
            .iter()
            .filter(|hit| !matches!(hit.kind, "zip_eocd" | "zip" | "tar" | "bzip2" | "xz"))
            .collect(),
    )?;
    candidates.append(&mut ordinary);

    let xz_candidates = raw_hits
        .iter()
        .filter(|hit| hit.kind == "xz")
        .collect::<Vec<_>>()
        .par_iter()
        .map(|hit| validate_xz(reader, file_size, hit.offset, xz_footer_ends))
        .collect::<io::Result<Vec<_>>>()?;
    candidates.extend(xz_candidates.into_iter().flatten());

    // A bzip2 file may be a concatenation of complete streams.  Validation
    // from the first stream walks every immediately adjacent stream, so later
    // BZh hits inside that exact range are member anchors rather than separate
    // logical archives.  Process roots in order to avoid decoding the same
    // suffix repeatedly for large concatenated files.
    let mut bzip2_range_end = None::<u64>;
    for hit in raw_hits.iter().filter(|hit| hit.kind == "bzip2") {
        if bzip2_range_end.is_some_and(|end| hit.offset < end) {
            continue;
        }
        if let Some(candidate) = validate_candidate(reader, file_size, hit.kind, hit.offset)? {
            if let Some(end) = candidate.end_offset {
                bzip2_range_end = Some(end);
            }
            candidates.push(candidate);
        }
    }

    let mut orphan_zip_anchors = collect_parallel(
        raw_hits
            .iter()
            .filter(|hit| {
                hit.kind == "zip"
                    && !zip_ranges
                        .iter()
                        .any(|(start, end)| hit.offset >= *start && hit.offset < *end)
            })
            .collect(),
    )?;
    candidates.append(&mut orphan_zip_anchors);

    // Each TAR member contains another valid ustar signature.  Walking every
    // member to the same double-zero terminator is quadratic.  A successful
    // walk from the earliest uncovered header proves all later member anchors
    // inside that exact archive range.
    let mut tar_ranges = Vec::<(u64, u64)>::new();
    for hit in raw_hits.iter().filter(|hit| hit.kind == "tar") {
        if tar_ranges
            .iter()
            .any(|(start, end)| hit.offset >= *start && hit.offset < *end)
        {
            continue;
        }
        if let Some(candidate) = validate_candidate(reader, file_size, hit.kind, hit.offset)? {
            if let Some(end) = candidate.end_offset {
                tar_ranges.push((candidate.offset, end));
            }
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn candidate_rank(candidate: &EmbeddedCandidate) -> u8 {
    match (candidate.candidate_kind, candidate.boundary_kind) {
        ("logical_archive", "exact") => 3,
        ("logical_archive", _) => 2,
        _ => 1,
    }
}

fn resolve_logical_candidates(candidates: &mut Vec<EmbeddedCandidate>) {
    // Once an exact logical range is proven, every signature strictly inside
    // that range belongs to the archive payload. Nested archives are discovered
    // after extraction by the recursive pipeline, never as peer carrier slices.
    let exact_ranges = candidates
        .iter()
        .filter(|item| item.candidate_kind == "logical_archive")
        .filter_map(|item| item.end_offset.map(|end| (item.offset, end)))
        .collect::<Vec<_>>();
    candidates.retain(|item| {
        !exact_ranges
            .iter()
            .any(|(start, end)| *start < item.offset && item.offset < *end)
    });
}

fn scan_sample(sample: &[u8], carry_len: usize, base_offset: u64) -> Vec<RawHit> {
    let mut hits = Vec::new();
    if let Some(matcher) = embedded_packed_matcher() {
        for matched in matcher.find_iter(sample) {
            let pattern = matched.pattern().as_usize();
            record_raw_hit(
                &mut hits,
                carry_len,
                base_offset,
                pattern,
                matched.start(),
                matched.end(),
            );

            // Packed search is deliberately non-overlapping. The current
            // signature set has exactly one proper suffix/prefix overlap:
            // Zstd ends in FD and XZ begins with FD. Recover that one match
            // explicitly so this path is exactly equivalent to Standard
            // Aho-Corasick overlapping semantics.
            if pattern == ZSTD_PATTERN_INDEX {
                let xz_start = matched.end() - 1;
                let xz_end = xz_start + XZ.len();
                if sample.get(xz_start..xz_end) == Some(XZ) {
                    record_raw_hit(
                        &mut hits,
                        carry_len,
                        base_offset,
                        XZ_PATTERN_INDEX,
                        xz_start,
                        xz_end,
                    );
                }
            }
        }
    } else {
        for matched in embedded_matcher().find_overlapping_iter(sample) {
            record_raw_hit(
                &mut hits,
                carry_len,
                base_offset,
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            );
        }
    }
    for start in memmem::find_iter(sample, XZ_FOOTER_MAGIC) {
        let end = start + XZ_FOOTER_MAGIC.len();
        if end > carry_len {
            hits.push(RawHit {
                hit_name: "xz_footer",
                kind: "xz_footer",
                offset: base_offset + start as u64,
            });
        }
    }
    hits
}

fn record_raw_hit(
    hits: &mut Vec<RawHit>,
    carry_len: usize,
    base_offset: u64,
    pattern: usize,
    start: usize,
    end: usize,
) {
    // A match contained entirely in carry was already owned by the preceding
    // chunk. Cross-boundary matches end in newly read bytes and are retained
    // exactly once.
    if end <= carry_len {
        return;
    }
    let (_, hit_name, kind) = PATTERNS[pattern];
    let absolute = base_offset + start as u64;
    let candidate_offset = if kind == "tar" {
        let Some(value) = absolute.checked_sub(257) else {
            return;
        };
        value
    } else {
        absolute
    };
    hits.push(RawHit {
        hit_name,
        kind,
        offset: candidate_offset,
    });
}

fn validate_candidate(
    file: &ManagedReader,
    file_size: u64,
    kind: &str,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    match kind {
        "zip" => validate_zip(file, file_size, offset),
        "zip_eocd" => validate_zip_eocd(file, file_size, offset),
        "7z" => validate_seven_zip(file, file_size, offset),
        "rar4" => validate_rar4(file, file_size, offset),
        "rar5" => validate_rar5(file, file_size, offset),
        "gzip" => validate_gzip(file, file_size, offset),
        "bzip2" => validate_bzip2(file, file_size, offset),
        "zstd" => validate_zstd(file, file_size, offset),
        "tar" => validate_tar(file, file_size, offset),
        _ => Ok(None),
    }
}

fn validate_zip_eocd(
    file: &ManagedReader,
    size: u64,
    eocd_offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, eocd_offset, 22)?;
    if header.len() < 22 || &header[..4] != ZIP_EOCD {
        return Ok(None);
    }
    let comment_len = u16::from_le_bytes([header[20], header[21]]) as u64;
    let Some(end) = eocd_offset.checked_add(22 + comment_len) else {
        return Ok(None);
    };
    if end > size {
        return Ok(None);
    }
    let disk = u16::from_le_bytes([header[4], header[5]]);
    let cd_disk = u16::from_le_bytes([header[6], header[7]]);
    if disk != 0 || cd_disk != 0 {
        return Ok(None);
    }
    let classic_cd_size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as u64;
    let classic_cd_offset = u32::from_le_bytes(header[16..20].try_into().unwrap()) as u64;
    let classic_entries_on_disk = u16::from_le_bytes(header[8..10].try_into().unwrap()) as u64;
    let classic_entries_total = u16::from_le_bytes(header[10..12].try_into().unwrap()) as u64;
    let needs_zip64 = classic_cd_size == u32::MAX as u64
        || classic_cd_offset == u32::MAX as u64
        || classic_entries_on_disk == u16::MAX as u64
        || classic_entries_total == u16::MAX as u64;
    let zip64 = parse_zip64_end_records(file, eocd_offset)?;
    if needs_zip64 && zip64.is_none() {
        return Ok(None);
    }
    let (directory_end, cd_size, recorded_cd_offset, entries_total, locator_archive_offset) =
        if let Some(zip64) = zip64 {
            if zip64.disk != 0 || zip64.cd_disk != 0 || zip64.entries_on_disk != zip64.entries_total
            {
                return Ok(None);
            }
            (
                zip64.record_offset,
                zip64.cd_size,
                zip64.cd_offset,
                zip64.entries_total,
                zip64
                    .record_offset
                    .checked_sub(zip64.recorded_record_offset),
            )
        } else {
            if classic_entries_on_disk != classic_entries_total {
                return Ok(None);
            }
            (
                eocd_offset,
                classic_cd_size,
                classic_cd_offset,
                classic_entries_total,
                None,
            )
        };
    if entries_total > MAX_ARCHIVE_METADATA_RECORDS as u64 {
        return Ok(None);
    }
    if cd_size > directory_end {
        return Ok(None);
    }
    let actual_cd_start = directory_end - cd_size;
    let Some(archive_offset) = actual_cd_start.checked_sub(recorded_cd_offset) else {
        return Ok(None);
    };
    if locator_archive_offset.is_some_and(|offset| offset != archive_offset) {
        return Ok(None);
    }
    if archive_offset == 0 {
        return Ok(None);
    }
    let cd_magic = read_at(file, actual_cd_start, 4)?;
    if cd_size > 0 && cd_magic.as_slice() != b"PK\x01\x02" {
        return Ok(None);
    }
    if !validate_zip_central_directory(
        file,
        actual_cd_start,
        directory_end,
        archive_offset,
        entries_total as usize,
    )? {
        return Ok(None);
    }
    Ok(Some(candidate(
        "zip",
        archive_offset,
        Some(end),
        1.0,
        if needs_zip64 {
            "zip64_eocd_central_directory_and_local_links"
        } else {
            "eocd_central_directory_and_local_links"
        },
    )))
}

struct Zip64EndRecords {
    record_offset: u64,
    recorded_record_offset: u64,
    disk: u32,
    cd_disk: u32,
    entries_on_disk: u64,
    entries_total: u64,
    cd_size: u64,
    cd_offset: u64,
}

fn parse_zip64_end_records(
    file: &ManagedReader,
    eocd_offset: u64,
) -> io::Result<Option<Zip64EndRecords>> {
    if eocd_offset < 20 {
        return Ok(None);
    }
    let locator = read_at(file, eocd_offset - 20, 20)?;
    if locator.len() != 20 || &locator[..4] != b"PK\x06\x07" {
        return Ok(None);
    }
    let locator_disk = u32::from_le_bytes(locator[4..8].try_into().unwrap());
    let recorded_record_offset = u64::from_le_bytes(locator[8..16].try_into().unwrap());
    let disk_count = u32::from_le_bytes(locator[16..20].try_into().unwrap());
    if locator_disk != 0 || disk_count != 1 || eocd_offset < 32 {
        return Ok(None);
    }

    // The extensible ZIP64 EOCD record is immediately before the locator.
    // Read its fixed tail backwards to obtain the declared record size without
    // trusting the (SFX-relative) locator offset as a physical position.
    let search_start = eocd_offset.saturating_sub(20 + 65_557);
    let search = read_at(
        file,
        search_start,
        (eocd_offset - 20 - search_start) as usize,
    )?;
    let Some(relative) = search.windows(4).rposition(|bytes| bytes == b"PK\x06\x06") else {
        return Ok(None);
    };
    let record_offset = search_start + relative as u64;
    let fixed = read_at(file, record_offset, 56)?;
    if fixed.len() != 56 || &fixed[..4] != b"PK\x06\x06" {
        return Ok(None);
    }
    let record_size = u64::from_le_bytes(fixed[4..12].try_into().unwrap());
    if record_size < 44 || record_offset.checked_add(12 + record_size) != Some(eocd_offset - 20) {
        return Ok(None);
    }
    Ok(Some(Zip64EndRecords {
        record_offset,
        recorded_record_offset,
        disk: u32::from_le_bytes(fixed[16..20].try_into().unwrap()),
        cd_disk: u32::from_le_bytes(fixed[20..24].try_into().unwrap()),
        entries_on_disk: u64::from_le_bytes(fixed[24..32].try_into().unwrap()),
        entries_total: u64::from_le_bytes(fixed[32..40].try_into().unwrap()),
        cd_size: u64::from_le_bytes(fixed[40..48].try_into().unwrap()),
        cd_offset: u64::from_le_bytes(fixed[48..56].try_into().unwrap()),
    }))
}

fn validate_zip_central_directory(
    file: &ManagedReader,
    start: u64,
    end: u64,
    archive_offset: u64,
    entries: usize,
) -> io::Result<bool> {
    let mut cursor = start;
    for _ in 0..entries {
        let fixed = read_at(file, cursor, 46)?;
        if fixed.len() != 46 || &fixed[..4] != b"PK\x01\x02" {
            return Ok(false);
        }
        let name_len = u16::from_le_bytes(fixed[28..30].try_into().unwrap()) as u64;
        let extra_len = u16::from_le_bytes(fixed[30..32].try_into().unwrap()) as u64;
        let comment_len = u16::from_le_bytes(fixed[32..34].try_into().unwrap()) as u64;
        let variable_len = name_len
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len));
        let Some(next) = variable_len.and_then(|value| cursor.checked_add(46 + value)) else {
            return Ok(false);
        };
        if next > end || extra_len > usize::MAX as u64 {
            return Ok(false);
        }
        let compressed = u32::from_le_bytes(fixed[20..24].try_into().unwrap());
        let uncompressed = u32::from_le_bytes(fixed[24..28].try_into().unwrap());
        let disk_start = u16::from_le_bytes(fixed[34..36].try_into().unwrap());
        let local_32 = u32::from_le_bytes(fixed[42..46].try_into().unwrap());
        let local_offset = if local_32 == u32::MAX {
            let extra = read_at(file, cursor + 46 + name_len, extra_len as usize)?;
            let Some(value) = zip64_central_local_offset(
                &extra,
                uncompressed == u32::MAX,
                compressed == u32::MAX,
                disk_start == u16::MAX,
            ) else {
                return Ok(false);
            };
            value
        } else {
            u64::from(local_32)
        };
        let Some(absolute_local) = archive_offset.checked_add(local_offset) else {
            return Ok(false);
        };
        if absolute_local >= start || read_at(file, absolute_local, 4)?.as_slice() != ZIP_LOCAL {
            return Ok(false);
        }
        cursor = next;
    }
    if cursor == end {
        return Ok(true);
    }
    // Optional central-directory digital signature.
    let signature = read_at(file, cursor, 6)?;
    if signature.len() != 6 || &signature[..4] != b"PK\x05\x05" {
        return Ok(false);
    }
    let length = u16::from_le_bytes(signature[4..6].try_into().unwrap()) as u64;
    Ok(cursor.checked_add(6 + length) == Some(end))
}

fn zip64_central_local_offset(
    extra: &[u8],
    has_uncompressed: bool,
    has_compressed: bool,
    has_disk: bool,
) -> Option<u64> {
    let mut field = 0usize;
    while field + 4 <= extra.len() {
        let id = u16::from_le_bytes(extra[field..field + 2].try_into().ok()?);
        let len = u16::from_le_bytes(extra[field + 2..field + 4].try_into().ok()?) as usize;
        field += 4;
        let values = extra.get(field..field.checked_add(len)?)?;
        if id == 0x0001 {
            let mut cursor = 0usize;
            if has_uncompressed {
                cursor = cursor.checked_add(8)?;
            }
            if has_compressed {
                cursor = cursor.checked_add(8)?;
            }
            let value = u64::from_le_bytes(values.get(cursor..cursor + 8)?.try_into().ok()?);
            cursor += 8;
            if has_disk && values.len() < cursor + 4 {
                return None;
            }
            return Some(value);
        }
        field += len;
    }
    None
}

fn read_at(file: &ManagedReader, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.read_at(offset, len)
}

fn validate_zip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 30)?;
    if header.len() < 30 || &header[..4] != ZIP_LOCAL {
        return Ok(None);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let compressed_32 = u32::from_le_bytes(header[18..22].try_into().unwrap());
    let uncompressed_32 = u32::from_le_bytes(header[22..26].try_into().unwrap());
    let name_len = u16::from_le_bytes([header[26], header[27]]) as u64;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as u64;
    let header_end = offset
        .saturating_add(30)
        .saturating_add(name_len)
        .saturating_add(extra_len);
    if version > 100 || flags & 0xc000 != 0 || name_len == 0 || header_end > size {
        return Ok(None);
    }
    let mut compressed_size = compressed_32 as u64;
    let mut validation = "local_header_and_data_range";
    let mut confidence = 0.94;
    if compressed_32 == u32::MAX || uncompressed_32 == u32::MAX {
        let extra_start = offset + 30 + name_len;
        let extra = read_at(file, extra_start, extra_len as usize)?;
        let mut cursor = 0usize;
        let mut zip64 = None;
        while cursor + 4 <= extra.len() {
            let id = u16::from_le_bytes(extra[cursor..cursor + 2].try_into().unwrap());
            let field_size =
                u16::from_le_bytes(extra[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            if cursor + field_size > extra.len() {
                return Ok(None);
            }
            if id == 0x0001 {
                zip64 = Some(&extra[cursor..cursor + field_size]);
                break;
            }
            cursor += field_size;
        }
        let Some(zip64) = zip64 else { return Ok(None) };
        let mut value_cursor = 0usize;
        if uncompressed_32 == u32::MAX {
            if zip64.len() < value_cursor + 8 {
                return Ok(None);
            }
            value_cursor += 8;
        }
        if compressed_32 == u32::MAX {
            if zip64.len() < value_cursor + 8 {
                return Ok(None);
            }
            compressed_size =
                u64::from_le_bytes(zip64[value_cursor..value_cursor + 8].try_into().unwrap());
        }
        validation = "zip64_local_header_and_data_range";
        confidence = 0.99;
    }
    let Some(data_end) = header_end.checked_add(compressed_size) else {
        return Ok(None);
    };
    if flags & 0x0008 == 0 && data_end > size {
        return Ok(None);
    }
    Ok(Some(candidate(
        "zip", offset, None, confidence, validation,
    )))
}

fn validate_seven_zip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 32)?;
    if header.len() < 32 || &header[..6] != SEVEN_ZIP || header[6] != 0 {
        return Ok(None);
    }
    let stored_start_crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if crc32(&header[12..32]) != stored_start_crc {
        return Ok(None);
    }
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let next_crc = u32::from_le_bytes(header[28..32].try_into().unwrap());
    let next_start = offset.saturating_add(32).saturating_add(next_offset);
    let Some(end) = next_start.checked_add(next_size) else {
        return Ok(None);
    };
    if end > size || next_size > usize::MAX as u64 {
        return Ok(Some(logical_candidate(
            "7z",
            offset,
            None,
            0.90,
            "start_header_crc_truncated_next_header",
        )));
    }
    let next = read_at(file, next_start, next_size as usize)?;
    if next.len() != next_size as usize || crc32(&next) != next_crc {
        return Ok(Some(logical_candidate(
            "7z",
            offset,
            None,
            0.90,
            "start_header_crc_damaged_next_header",
        )));
    }
    Ok(Some(candidate(
        "7z",
        offset,
        Some(end),
        1.0,
        "start_and_next_header_crc",
    )))
}

fn validate_rar4(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let mut cursor = offset + RAR4.len() as u64;
    for index in 0..MAX_ARCHIVE_METADATA_RECORDS {
        let fixed = read_at(file, cursor, 7)?;
        if fixed.len() != 7 {
            return Ok(None);
        }
        let stored = u16::from_le_bytes(fixed[..2].try_into().unwrap()) as u32;
        let header_type = fixed[2];
        let flags = u16::from_le_bytes(fixed[3..5].try_into().unwrap());
        let header_size = u16::from_le_bytes(fixed[5..7].try_into().unwrap()) as u64;
        if !matches!(header_type, 0x73..=0x7b) || header_size < 7 {
            return Ok(None);
        }
        let Some(header_end) = cursor.checked_add(header_size) else {
            return Ok(None);
        };
        if header_end > size || header_size > usize::MAX as u64 {
            return Ok(None);
        }
        let header = read_at(file, cursor, header_size as usize)?;
        if header.len() != header_size as usize || crc32(&header[2..]) & 0xffff != stored {
            return Ok(None);
        }
        if index == 0 && header_type != 0x73 {
            return Ok(None);
        }
        if index == 0 && flags & 0x0080 != 0 {
            return Ok(Some(logical_candidate(
                "rar",
                offset,
                None,
                1.0,
                "rar4_header_encrypted_main_header_crc",
            )));
        }
        let add_size = if flags & 0x8000 != 0 {
            if header.len() < 11 {
                return Ok(None);
            }
            u64::from(u32::from_le_bytes(header[7..11].try_into().unwrap()))
        } else {
            0
        };
        let Some(next) = header_end.checked_add(add_size) else {
            return Ok(None);
        };
        if next > size {
            return Ok(None);
        }
        if header_type == 0x7b {
            return Ok(Some(candidate(
                "rar",
                offset,
                Some(next),
                1.0,
                "rar4_complete_block_walk",
            )));
        }
        cursor = next;
    }
    Ok(Some(logical_candidate(
        "rar",
        offset,
        None,
        0.90,
        "rar4_block_walk_limit_reached",
    )))
}

fn validate_rar5(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let mut cursor = offset + RAR5.len() as u64;
    for index in 0..MAX_ARCHIVE_METADATA_RECORDS {
        let prefix = read_at(file, cursor, 16)?;
        if prefix.len() < 6 {
            return Ok(None);
        }
        let stored = u32::from_le_bytes(prefix[..4].try_into().unwrap());
        let Some((header_size, size_len)) = read_vint(&prefix[4..]) else {
            return Ok(None);
        };
        if size_len > 3 || header_size == 0 {
            return Ok(None);
        }
        let Some(total) = 4u64
            .checked_add(size_len as u64)
            .and_then(|value| value.checked_add(header_size))
        else {
            return Ok(None);
        };
        let Some(header_end) = cursor.checked_add(total) else {
            return Ok(None);
        };
        if header_end > size || total > usize::MAX as u64 {
            return Ok(None);
        }
        let full = read_at(file, cursor, total as usize)?;
        if full.len() != total as usize || crc32(&full[4..]) != stored {
            return Ok(None);
        }
        let fields_start = 4 + size_len;
        let Some((header_type, type_len)) = read_vint(&full[fields_start..]) else {
            return Ok(None);
        };
        let flags_start = fields_start + type_len;
        let Some((flags, flags_len)) = read_vint(&full[flags_start..]) else {
            return Ok(None);
        };
        if !matches!(header_type, 1..=5) && flags & 0x0004 == 0 {
            return Ok(None);
        }
        let mut field_cursor = flags_start + flags_len;
        if flags & 0x0001 != 0 {
            let Some((_, len)) = read_vint(&full[field_cursor..]) else {
                return Ok(None);
            };
            field_cursor += len;
        }
        let data_size = if flags & 0x0002 != 0 {
            let Some((value, _)) = read_vint(&full[field_cursor..]) else {
                return Ok(None);
            };
            value
        } else {
            0
        };
        let Some(next) = header_end.checked_add(data_size) else {
            return Ok(None);
        };
        if next > size {
            return Ok(None);
        }
        if index == 0 && header_type == 4 {
            return Ok(Some(logical_candidate(
                "rar",
                offset,
                None,
                1.0,
                "rar5_encryption_header_crc",
            )));
        }
        if index == 0 && header_type != 1 {
            return Ok(None);
        }
        if header_type == 5 {
            return Ok(Some(candidate(
                "rar",
                offset,
                Some(next),
                1.0,
                "rar5_complete_block_walk",
            )));
        }
        cursor = next;
    }
    Ok(Some(logical_candidate(
        "rar",
        offset,
        None,
        0.90,
        "rar5_block_walk_limit_reached",
    )))
}

fn validate_gzip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let structure = match validate_gzip_structure(file, offset, size) {
        Ok(value) => value,
        Err(ValidationError::Invalid(_)) => return Ok(None),
        Err(ValidationError::Io(error)) => return Err(error),
    };
    Ok(Some(candidate(
        "gzip",
        offset,
        Some(structure.end_offset),
        0.99,
        if structure.stream_count > 1 {
            "rfc1952_concatenated_members_complete_deflate_walk"
        } else {
            "rfc1952_complete_deflate_walk"
        },
    )))
}

fn validate_bzip2(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let structure = match validate_bzip2_structure(file, offset, size) {
        Ok(value) => value,
        Err(ValidationError::Invalid(_)) => return Ok(None),
        Err(ValidationError::Io(error)) => return Err(error),
    };
    Ok(Some(candidate(
        "bzip2",
        offset,
        Some(structure.end_offset),
        0.99,
        if structure.stream_count > 1 {
            "bzip2_concatenated_streams_complete_huffman_walk"
        } else {
            "bzip2_complete_huffman_walk_and_crc_chain"
        },
    )))
}

fn validate_xz(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    footer_ends: &[u64],
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 12)?;
    if header.len() < 12
        || &header[..6] != XZ
        || header[6] != 0
        || header[7] & 0xf0 != 0
        || offset + 24 > size
    {
        return Ok(None);
    }
    let stored = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if crc32(&header[6..8]) != stored {
        return Ok(None);
    }
    let first_possible = footer_ends.partition_point(|end| *end < offset + 24);
    let mut structure = None;
    for &end in &footer_ends[first_possible..] {
        if end > size {
            break;
        }
        match validate_xz_structure_exact(file, offset, end) {
            Ok(value) => {
                structure = Some(value);
                break;
            }
            Err(ValidationError::Invalid(_)) => {}
            Err(ValidationError::Io(error)) => return Err(error),
        }
    }
    let Some(structure) = structure else {
        return Ok(None);
    };
    Ok(Some(candidate(
        "xz",
        offset,
        Some(structure.end_offset),
        0.99,
        "xz_header_block_index_footer_structure_walk",
    )))
}

fn validate_zstd(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let structure = match validate_zstd_structure(file, offset, size) {
        Ok(value) => value,
        Err(ValidationError::Invalid(_)) => return Ok(None),
        Err(ValidationError::Io(error)) => return Err(error),
    };
    Ok(Some(candidate(
        "zstd",
        offset,
        Some(structure.end_offset),
        0.99,
        "rfc8878_complete_frame_block_walk",
    )))
}

#[cfg(test)]
fn parse_zstd_prefix(header: &[u8]) -> Option<(usize, u64, u64)> {
    if header.len() < 6 || &header[..4] != ZSTD || header[4] & 0x18 != 0 {
        return None;
    }
    let descriptor = header[4];
    let single_segment = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dictionary_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let content_flag = descriptor >> 6;
    let content_size = match (content_flag, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let frame_header_size = 5usize + usize::from(!single_segment) + dictionary_size + content_size;
    if header.len() < frame_header_size + 3 {
        return None;
    }

    let mut cursor = 5usize;
    let window_size = if single_segment {
        None
    } else {
        let descriptor = header[cursor];
        cursor += 1;
        let exponent = u32::from(descriptor >> 3);
        let mantissa = u64::from(descriptor & 0x07);
        let window_base = 1u64 << (10 + exponent);
        Some(window_base + (window_base / 8) * mantissa)
    };
    cursor += dictionary_size;
    let frame_content_size = match content_size {
        0 => None,
        1 => Some(u64::from(header[cursor])),
        2 => Some(
            u64::from(u16::from_le_bytes(
                header[cursor..cursor + 2].try_into().ok()?,
            )) + 256,
        ),
        4 => Some(u64::from(u32::from_le_bytes(
            header[cursor..cursor + 4].try_into().ok()?,
        ))),
        8 => Some(u64::from_le_bytes(
            header[cursor..cursor + 8].try_into().ok()?,
        )),
        _ => return None,
    };
    let window_size = if single_segment {
        frame_content_size?
    } else {
        window_size?
    };

    let block = &header[frame_header_size..frame_header_size + 3];
    let block_header =
        u32::from(block[0]) | (u32::from(block[1]) << 8) | (u32::from(block[2]) << 16);
    let last_block = block_header & 0x01 != 0;
    let block_type = (block_header >> 1) & 0x03;
    let block_size = (block_header >> 3) as u64;
    let block_max_size = window_size.min(128 * 1024);
    if block_type == 3 || block_size > block_max_size {
        return None;
    }
    if last_block
        && block_type <= 1
        && frame_content_size.is_some_and(|content_size| content_size != block_size)
    {
        return None;
    }
    let encoded_block_size = if block_type == 1 { 1 } else { block_size };
    let checksum_size = u64::from(last_block && checksum) * 4;
    Some((frame_header_size, encoded_block_size, checksum_size))
}

fn validate_tar(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    if offset + 512 > size {
        return Ok(None);
    }
    let header = read_at(file, offset, 512)?;
    if header.len() < 512 || &header[257..262] != TAR_USTAR {
        return Ok(None);
    }
    if !valid_tar_header(&header) {
        return Ok(None);
    }
    let mut cursor = offset;
    for _ in 0..MAX_ARCHIVE_METADATA_RECORDS {
        let current = read_at(file, cursor, 512)?;
        if current.len() != 512 {
            return Ok(None);
        }
        if current.iter().all(|byte| *byte == 0) {
            let second = read_at(file, cursor + 512, 512)?;
            if second.len() != 512 || !second.iter().all(|byte| *byte == 0) {
                return Ok(None);
            }
            return Ok(Some(candidate(
                "tar",
                offset,
                Some(cursor + 1024),
                1.0,
                "member_walk_checksums_and_end_blocks",
            )));
        }
        if !valid_tar_header(&current) {
            return Ok(None);
        }
        let Some(payload_size) = parse_tar_number(&current[124..136]) else {
            return Ok(None);
        };
        let Some(padded) = payload_size.checked_add(511).map(|value| value & !511) else {
            return Ok(None);
        };
        let Some(next) = cursor
            .checked_add(512)
            .and_then(|value| value.checked_add(padded))
        else {
            return Ok(None);
        };
        if next > size {
            return Ok(None);
        }
        cursor = next;
    }
    Ok(Some(logical_candidate(
        "tar",
        offset,
        None,
        0.90,
        "tar_member_walk_limit_reached",
    )))
}

fn valid_tar_header(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    let Some(stored) = parse_tar_number(&header[148..156]) else {
        return false;
    };
    let unsigned = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    stored == unsigned
}

fn parse_tar_number(data: &[u8]) -> Option<u64> {
    if data.first().is_some_and(|byte| byte & 0x80 != 0) {
        if data.first()? & 0x40 != 0 {
            return None;
        }
        let mut value = u64::from(data.first()? & 0x7f);
        for byte in &data[1..] {
            value = value.checked_mul(256)?.checked_add(u64::from(*byte))?;
        }
        Some(value)
    } else {
        parse_octal(data)
    }
}

fn candidate(
    format: &'static str,
    offset: u64,
    end: Option<u64>,
    confidence: f64,
    validation: &'static str,
) -> EmbeddedCandidate {
    let exact = end.is_some();
    EmbeddedCandidate {
        format,
        offset,
        end_offset: end,
        confidence,
        validation,
        candidate_kind: if exact { "logical_archive" } else { "anchor" },
        boundary_kind: if exact { "exact" } else { "unresolved" },
        extractable: exact,
    }
}

fn logical_candidate(
    format: &'static str,
    offset: u64,
    end: Option<u64>,
    confidence: f64,
    validation: &'static str,
) -> EmbeddedCandidate {
    let mut item = candidate(format, offset, end, confidence, validation);
    item.candidate_kind = "logical_archive";
    item
}

fn read_vint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in data.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn parse_octal(data: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(data)
        .ok()?
        .trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return None;
    }
    u64::from_str_radix(text, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use bzip2::write::BzEncoder;
    use bzip2::Compression as BzCompression;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;
    use xz2::write::XzEncoder;

    fn reference_raw_hits(data: &[u8]) -> Vec<RawHit> {
        let mut hits = Vec::new();
        for matched in embedded_matcher().find_overlapping_iter(data) {
            let (_, hit_name, kind) = PATTERNS[matched.pattern().as_usize()];
            let absolute = matched.start() as u64;
            let candidate_offset = if kind == "tar" {
                let Some(value) = absolute.checked_sub(257) else {
                    continue;
                };
                value
            } else {
                absolute
            };
            hits.push(RawHit {
                hit_name,
                kind,
                offset: candidate_offset,
            });
        }
        hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
        hits
    }

    fn optimized_raw_hits(data: &[u8]) -> Vec<RawHit> {
        let mut hits = scan_sample(data, 0, 0);
        hits.retain(|hit| hit.kind != "xz_footer");
        hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
        hits
    }

    fn append_tar_member(data: &mut Vec<u8>, name: &str, payload: &[u8]) {
        let member_start = data.len();
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", payload.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(checksum.as_bytes());
        data.extend_from_slice(&header);
        data.extend_from_slice(payload);
        data.resize(member_start + 512 + payload.len().next_multiple_of(512), 0);
    }

    fn append_zip64_archive(data: &mut Vec<u8>) -> (u64, u64) {
        let archive_start = data.len() as u64;
        let name = b"x";
        data.extend_from_slice(ZIP_LOCAL);
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&crc32(b"x").to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(name);
        data.push(b'x');

        let cd_offset = data.len() as u64 - archive_start;
        let cd_start = data.len();
        data.extend_from_slice(b"PK\x01\x02");
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&crc32(b"x").to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(name);
        let cd_size = (data.len() - cd_start) as u64;

        let zip64_record_offset = data.len() as u64 - archive_start;
        data.extend_from_slice(b"PK\x06\x06");
        data.extend_from_slice(&44u64.to_le_bytes());
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&cd_size.to_le_bytes());
        data.extend_from_slice(&cd_offset.to_le_bytes());
        data.extend_from_slice(b"PK\x06\x07");
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&zip64_record_offset.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(ZIP_EOCD);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        (archive_start, data.len() as u64)
    }

    #[test]
    fn keeps_crc_valid_truncated_7z_as_bounded_logical_candidate() {
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&1024u64.to_le_bytes());
        start_header.extend_from_slice(&16u64.to_le_bytes());
        start_header.extend_from_slice(&0u32.to_le_bytes());

        let mut data = b"carrier-prefix".to_vec();
        let start = data.len() as u64;
        data.extend_from_slice(SEVEN_ZIP);
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(&crc32(&start_header).to_le_bytes());
        data.extend_from_slice(&start_header);
        let path = temp_file("embedded_truncated_7z", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let seven = result
            .candidates
            .iter()
            .find(|candidate| candidate.format == "7z")
            .expect("CRC-valid truncated 7z must remain a logical candidate");

        assert_eq!(seven.offset, start);
        assert_eq!(seven.end_offset, None);
        assert_eq!(seven.candidate_kind, "logical_archive");
        assert_eq!(seven.boundary_kind, "bounded");
        assert_eq!(seven.range_end_offset, Some(data.len() as u64));
        assert!(seven.extractable);
        assert_eq!(seven.validation, "start_header_crc_truncated_next_header");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn aggregates_embedded_zip64_from_locator_eocd_and_local_links() {
        let mut data = b"sfx-prefix".to_vec();
        let (start, end) = append_zip64_archive(&mut data);
        let path = temp_file("embedded_zip64", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let zip = result
            .candidates
            .iter()
            .find(|candidate| candidate.format == "zip")
            .expect("ZIP64 must become one logical candidate");

        assert_eq!(zip.offset, start);
        assert_eq!(zip.end_offset, Some(end));
        assert_eq!(
            zip.validation,
            "zip64_eocd_central_directory_and_local_links"
        );
        assert_eq!(zip.contained_anchor_count, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn aggregates_many_tar_member_anchors_into_one_logical_archive() {
        let mut data = b"carrier-prefix".to_vec();
        let start = data.len() as u64;
        append_tar_member(&mut data, "one.txt", b"one");
        append_tar_member(&mut data, "two.txt", b"two");
        data.extend_from_slice(&[0u8; 1024]);
        let end = data.len() as u64;
        let path = temp_file("embedded_tar_members", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let tar = result
            .candidates
            .iter()
            .filter(|candidate| candidate.format == "tar")
            .collect::<Vec<_>>();

        assert_eq!(tar.len(), 1);
        assert_eq!(tar[0].offset, start);
        assert_eq!(tar[0].end_offset, Some(end));
        assert_eq!(tar[0].contained_anchor_count, 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn aggregates_concatenated_bzip2_streams_into_one_logical_archive() {
        let mut data = b"carrier-prefix".to_vec();
        let start = data.len() as u64;
        let mut first = BzEncoder::new(Vec::new(), BzCompression::fast());
        first.write_all(b"first payload").unwrap();
        data.extend_from_slice(&first.finish().unwrap());
        let mut second = BzEncoder::new(Vec::new(), BzCompression::fast());
        second.write_all(b"second payload").unwrap();
        data.extend_from_slice(&second.finish().unwrap());
        let end = data.len() as u64;
        let path = temp_file("embedded_concatenated_bzip2", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let bzip2 = result
            .candidates
            .iter()
            .filter(|candidate| candidate.format == "bzip2")
            .collect::<Vec<_>>();

        assert_eq!(bzip2.len(), 1);
        assert_eq!(bzip2[0].offset, start);
        assert_eq!(bzip2[0].end_offset, Some(end));
        assert_eq!(bzip2[0].contained_anchor_count, 2);
        assert_eq!(
            bzip2[0].validation,
            "bzip2_concatenated_streams_complete_huffman_walk"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn keeps_bzip2_streams_separate_across_invalid_gap() {
        let mut first = BzEncoder::new(Vec::new(), BzCompression::fast());
        first.write_all(b"first payload").unwrap();
        let mut data = first.finish().unwrap();
        data.extend_from_slice(b"invalid gap");
        let second_start = data.len() as u64;
        let mut second = BzEncoder::new(Vec::new(), BzCompression::fast());
        second.write_all(b"second payload").unwrap();
        data.extend_from_slice(&second.finish().unwrap());
        let path = temp_file("embedded_gapped_bzip2", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let bzip2_offsets = result
            .candidates
            .iter()
            .filter(|candidate| candidate.format == "bzip2")
            .map(|candidate| candidate.offset)
            .collect::<Vec<_>>();

        assert_eq!(bzip2_offsets, [0, second_start]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn packed_search_preserves_every_signature_overlap() {
        let mut data = vec![0x11; 512];
        for (left_index, (left, _, _)) in PATTERNS.iter().enumerate() {
            for (right_index, (right, _, _)) in PATTERNS.iter().enumerate() {
                for overlap in 1..left.len().min(right.len()) {
                    if left[left.len() - overlap..] != right[..overlap] {
                        continue;
                    }
                    let start = data.len();
                    data.extend_from_slice(left);
                    data.extend_from_slice(&right[overlap..]);
                    data.extend_from_slice(&[0x11; 32]);
                    assert_eq!(
                        (left_index, right_index, overlap),
                        (ZSTD_PATTERN_INDEX, XZ_PATTERN_INDEX, 1),
                        "the packed compensation must cover every overlap",
                    );
                    assert!(start > 0);
                }
            }
        }
        assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
    }

    #[test]
    fn packed_search_matches_overlapping_aho_on_randomized_layouts() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut data = vec![0u8; 2 * 1024 * 1024];
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        for round in 0..2048usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pattern = round % PATTERNS.len();
            let magic = PATTERNS[pattern].0;
            let start = 300 + (state as usize % (data.len() - 600 - magic.len()));
            data[start..start + magic.len()].copy_from_slice(magic);
        }
        // Force the only overlap in the set in addition to any accidental
        // overlaps generated by the randomized corpus.
        let overlap = b"\x28\xb5\x2f\xfd7zXZ\x00";
        data[128..128 + overlap.len()].copy_from_slice(overlap);

        assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
    }

    #[test]
    fn finds_multiple_structurally_valid_embedded_streams() {
        let mut data = b"carrier".to_vec();
        let zip_offset = data.len() as u64;
        data.extend_from_slice(ZIP_LOCAL);
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(b'x');
        data.extend_from_slice(b"gap");
        let gzip_offset = data.len() as u64;
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(b"payload").unwrap();
        data.extend_from_slice(&gzip.finish().unwrap());
        let path = temp_file("embedded_multi", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(
                rows.get_item(0)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                zip_offset
            );
            assert_eq!(
                rows.get_item(1)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                gzip_offset
            );
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn finds_primary_and_later_stream_across_invalid_gap() {
        let mut first = GzEncoder::new(Vec::new(), Compression::fast());
        first.write_all(b"first payload").unwrap();
        let first = first.finish().unwrap();
        let gap = b"invalid bytes between valid streams";
        let second_offset = (first.len() + gap.len()) as u64;
        let mut second = GzEncoder::new(Vec::new(), Compression::fast());
        second.write_all(b"second payload").unwrap();

        let mut data = first;
        data.extend_from_slice(gap);
        data.extend_from_slice(&second.finish().unwrap());
        let path = temp_file("embedded_primary_gap_stream", &data);
        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let gzip_offsets = result
            .candidates
            .iter()
            .filter(|candidate| candidate.format == "gzip")
            .map(|candidate| candidate.offset)
            .collect::<Vec<_>>();

        assert_eq!(gzip_offsets, [0, second_offset]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn validates_supported_stream_headers_in_one_pass() {
        let mut data = b"carrier".to_vec();
        let mut bzip = BzEncoder::new(Vec::new(), BzCompression::fast());
        bzip.write_all(b"bzip payload").unwrap();
        data.extend_from_slice(&bzip.finish().unwrap());
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(b"xz payload").unwrap();
        data.extend_from_slice(&xz.finish().unwrap());
        data.extend_from_slice(&zstd::stream::encode_all(&b"zstd payload"[..], 1).unwrap());
        let path = temp_file("embedded_streams", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            let formats: Vec<String> = rows
                .iter()
                .map(|row| row.get_item("format").unwrap().extract::<String>().unwrap())
                .collect();
            assert_eq!(formats, ["bzip2", "xz", "zstd"]);
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_mp4_zstd_false_positive_prefixes_with_oversized_blocks() {
        let oversized_raw = [
            0x28, 0xb5, 0x2f, 0xfd, 0xe2, 0x04, 0xe5, 0xea, 0x82, 0xaa, 0xa3, 0x96, 0x2a, 0x14,
            0x47, 0x61, 0x9e, 0xa6, 0xbf, 0xea, 0x4b,
        ];
        let oversized_rle = [
            0x28, 0xb5, 0x2f, 0xfd, 0x66, 0xad, 0xef, 0x45, 0xf2, 0x0b, 0x32, 0xcd, 0x37, 0x1d,
            0x2c, 0xb3, 0xa5, 0xed, 0xc9, 0x47, 0x0c,
        ];

        assert!(parse_zstd_prefix(&oversized_raw).is_none());
        assert!(parse_zstd_prefix(&oversized_rle).is_none());
    }

    #[test]
    fn zstd_first_block_respects_window_and_rfc_block_limits() {
        let smaller_than_block_window = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x08, 0x49, 0x00, 0x00];
        assert!(parse_zstd_prefix(&smaller_than_block_window).is_none());

        let mut maximum_block = ZSTD.to_vec();
        maximum_block.push(0xe0);
        maximum_block.extend_from_slice(&(128u64 * 1024).to_le_bytes());
        maximum_block.extend_from_slice(&0x10_0001u32.to_le_bytes()[..3]);
        assert!(parse_zstd_prefix(&maximum_block).is_some());

        let mut oversized_block = ZSTD.to_vec();
        oversized_block.push(0xe0);
        oversized_block.extend_from_slice(&(128u64 * 1024 + 1).to_le_bytes());
        oversized_block.extend_from_slice(&0x10_0009u32.to_le_bytes()[..3]);
        assert!(parse_zstd_prefix(&oversized_block).is_none());
    }

    #[test]
    fn validates_zstd_maximum_frame_header_layout() {
        let mut data = ZSTD.to_vec();
        data.push(0xc3);
        data.push(0x00);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&[0x09, 0x00, 0x00]);
        data.push(b'x');
        assert_eq!(data.len(), 22);

        let path = temp_file("embedded_zstd_maximum_header", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let candidate = validate_zstd(&reader, data.len() as u64, 0)
            .unwrap()
            .expect("the full 14-byte RFC frame header must be accepted");
        assert_eq!(candidate.validation, "rfc8878_complete_frame_block_walk");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zstd_last_block_requires_declared_checksum_bytes() {
        let data = [0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x01, 0x09, 0x00, 0x00, b'x'];
        let path = temp_file("embedded_zstd_missing_checksum", &data);
        let reader = ManagedReader::open(&path).unwrap();
        assert!(validate_zstd(&reader, data.len() as u64, 0)
            .unwrap()
            .is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zstd_zero_length_rle_still_requires_its_content_byte() {
        let data = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x03, 0x00, 0x00];
        let path = temp_file("embedded_zstd_empty_rle", &data);
        let reader = ManagedReader::open(&path).unwrap();
        assert!(validate_zstd(&reader, data.len() as u64, 0)
            .unwrap()
            .is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn finds_signature_split_across_reused_buffer_boundary() {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(b"cross-boundary payload").unwrap();
        let gzip_bytes = gzip.finish().unwrap();
        let gzip_offset = TEST_IOCP_CHUNK_SIZE - 2;
        let mut data = vec![b'x'; gzip_offset];
        data.extend_from_slice(&gzip_bytes);
        let path = temp_file("embedded_cross_boundary", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows.get_item(0)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                gzip_offset as u64
            );
        });
        let _ = fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    fn iocp_matches_reference_scan_across_chunk_boundaries() {
        let mut data = vec![0x11; TEST_IOCP_CHUNK_SIZE * 3 + 123];
        let first = TEST_IOCP_CHUNK_SIZE - 2;
        data[first..first + GZIP.len()].copy_from_slice(GZIP);
        let second = TEST_IOCP_CHUNK_SIZE * 2 + 7;
        data[second..second + SEVEN_ZIP.len()].copy_from_slice(SEVEN_ZIP);
        let path = temp_file("embedded_iocp", &data);
        let reader = ManagedReader::open(&path).unwrap();

        let mut expected = reference_raw_hits(&data);
        expected.sort_by_key(|hit| (hit.offset, hit.hit_name));
        let iocp =
            scan_embedded_archives_native_with_iocp(reader, TEST_IOCP_CHUNK_SIZE, 4, 4).unwrap();

        assert_eq!(iocp.raw_hits, expected);
        let _ = fs::remove_file(path);
    }
}
