#[cfg(windows)]
use crate::io::iocp;
use crate::io::reader::{CachedBytes, ManagedReader};
use crate::io::ScanBatch;
use crate::scan::compression_stream::{
    bzip2_header_block_limit, bzip2_prefix_valid, gzip_fixed_header_flags, parse_xz_footer,
    resolve_xz_stream_start, validate_bzip2_structure_observed, validate_gzip_structure_observed,
    validate_xz_header, validate_zstd_structure_observed, ValidationError, ValidationResult,
};
use aho_corasick::{packed, AhoCorasick};
use crc32fast::hash as crc32;
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
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

const PATTERNS: [PatternSpec; 13] = [
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
    (crate::formats::lz4::MAGIC, "lz4", "lz4"),
    (b"\x2a\x4d\x18", "lz4_skippable", "lz4_skippable"),
    (b"PK\x06\x06", "zip64_eocd", "zip64_eocd"),
];

#[cfg(target_arch = "x86_64")]
const SIMD_PREFIX_TABLES: [[u8; 32]; 6] = simd_prefix_tables();

#[cfg(target_arch = "x86_64")]
const fn simd_prefix_tables() -> [[u8; 32]; 6] {
    let mut tables = [[0u8; 32]; 6];
    let mut buckets = [0u8; PATTERNS.len()];
    let mut next_bucket = 0;
    let mut index = 0;
    while index < PATTERNS.len() {
        let magic = PATTERNS[index].0;
        assert!(magic.len() >= 3);
        assert!(magic[0] != XZ_FOOTER_MAGIC[0]);
        let mut bucket = next_bucket;
        let mut prior = 0;
        while prior < index {
            let earlier = PATTERNS[prior].0;
            if earlier[0] == magic[0] && earlier[1] == magic[1] {
                bucket = buckets[prior] as usize;
                break;
            }
            prior += 1;
        }
        if prior == index {
            next_bucket += 1;
            // Fold extra buckets into the same SIMD pass; full magic checks remove false hits.
            bucket %= 8;
        }
        buckets[index] = bucket as u8;
        let bit = 1u8 << bucket;
        let (first, second, third) = (magic[0], magic[1], magic[2]);
        tables[0][(first & 15) as usize] |= bit;
        tables[1][(first >> 4) as usize] |= bit;
        tables[2][(second & 15) as usize] |= bit;
        tables[3][(second >> 4) as usize] |= bit;
        tables[4][(third & 15) as usize] |= bit;
        tables[5][(third >> 4) as usize] |= bit;
        index += 1;
    }
    let mut table = 0;
    while table < 6 {
        let mut nibble = 0;
        while nibble < 16 {
            tables[table][nibble + 16] = tables[table][nibble];
            nibble += 1;
        }
        table += 1;
    }
    tables
}

static EMBEDDED_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();
static EMBEDDED_PACKED_MATCHER: OnceLock<Option<packed::Searcher>> = OnceLock::new();

const DEFAULT_IOCP_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const DEFAULT_IOCP_BUFFERS: usize = 2;
const DEFAULT_IOCP_WORKERS: usize = 4;
const MAX_ARCHIVE_METADATA_RECORDS: usize = 1_000_000;
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
    lz4_index: Option<Box<crate::formats::lz4::Index>>,
    zip_eocd_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHit {
    // Byte alignment keeps all formats' retained hits at 9 bytes instead of
    // 16, without narrowing file offsets or requiring unaligned references.
    location: [u8; 8],
    pattern: u8,
}

impl RawHit {
    fn new(offset: u64, pattern: u8) -> Self {
        Self {
            location: offset.to_ne_bytes(),
            pattern,
        }
    }

    fn offset(&self) -> u64 {
        u64::from_ne_bytes(self.location)
    }

    fn hit_name(&self) -> &'static str {
        PATTERNS
            .get(self.pattern as usize)
            .map_or("xz_footer", |pattern| pattern.1)
    }

    fn kind(&self) -> &'static str {
        PATTERNS
            .get(self.pattern as usize)
            .map_or("xz_footer", |pattern| pattern.2)
    }

    fn format(&self) -> &'static str {
        match self.kind() {
            "zip_eocd" => "zip",
            "rar4" | "rar5" => "rar",
            "lz4_skippable" => "lz4",
            kind => kind,
        }
    }
}

pub(crate) struct NativeScanResult {
    file_size: u64,
    scan_read_bytes: u64,
    scan_read_operations: u64,
    raw_hits: Vec<RawHit>,
    candidates: Vec<EmbeddedCandidate>,
    logical_resolution_complete: bool,
    raw_hit_count: usize,
    budget_exhausted: bool,
    identity_only: bool,
}

impl NativeScanResult {
    pub(crate) fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    pub(crate) fn is_primary(&self, format: &str) -> bool {
        self.identity_only
            || !self
                .candidates
                .iter()
                .any(|item| item.candidate_kind == "logical_archive")
            || (self.candidates.len() == 1
                && self.candidates[0].format == format
                && self.candidates[0].offset == 0
                && (self.candidates[0].end_offset == Some(self.file_size)
                    || self.candidates[0].boundary_kind != "exact"))
    }

    pub(crate) fn primary_analysis(&self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        let Some(index) = self
            .candidates
            .first()
            .and_then(|item| item.lz4_index.as_ref())
        else {
            return Ok(None);
        };
        let facts = index.to_dict(py, self.file_size)?;
        let result = PyDict::new(py);
        result.set_item("stream_plan", facts.get_item("stream_plan")?)?;
        Ok(Some(result.unbind()))
    }

    pub(crate) fn to_py_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("complete", !self.budget_exhausted)?;
        result.set_item("signature_scan_complete", !self.budget_exhausted)?;
        result.set_item(
            "logical_resolution_complete",
            self.logical_resolution_complete,
        )?;
        result.set_item("file_size", self.file_size)?;
        result.set_item("read_bytes", self.file_size)?;
        result.set_item("scan_read_bytes", self.scan_read_bytes)?;
        result.set_item("scan_read_operations", self.scan_read_operations)?;
        result.set_item("raw_hit_count", self.raw_hit_count)?;
        result.set_item("budget_exhausted", self.budget_exhausted)?;
        let hit_rows = PyList::empty(py);
        for hit in &self.raw_hits {
            let row = PyDict::new(py);
            row.set_item("name", hit.hit_name())?;
            row.set_item(
                "offset",
                if hit.kind() == "tar" {
                    hit.offset() + 257
                } else {
                    hit.offset()
                },
            )?;
            row.set_item("source", "detection_embedded_scan")?;
            hit_rows.append(row)?;
        }
        result.set_item("hits", hit_rows)?;
        let rows = PyList::empty(py);
        for candidate in &self.candidates {
            let row = PyDict::new(py);
            row.set_item("format", candidate.format)?;
            row.set_item("offset", candidate.offset)?;
            row.set_item("end_offset", candidate.end_offset)?;
            row.set_item("confidence", candidate.confidence)?;
            row.set_item("validation", candidate.validation)?;
            row.set_item("candidate_kind", candidate.candidate_kind)?;
            row.set_item("boundary_kind", candidate.boundary_kind)?;
            row.set_item("extractable", candidate.extractable)?;
            if let Some(offset) = candidate.zip_eocd_offset {
                row.set_item("eocd_offset", offset)?;
            }
            if let Some(index) = &candidate.lz4_index {
                let facts = index.to_dict(py, self.file_size)?;
                row.set_item("stream_plan", facts.get_item("stream_plan")?)?;
                row.set_item("error", index.error)?;
            }
            rows.append(row)?;
        }
        result.set_item("candidates", rows)?;
        Ok(result.unbind())
    }
}

pub(crate) fn scan_embedded_path(
    path: &str,
    parallel_files: usize,
) -> io::Result<NativeScanResult> {
    let reader = ManagedReader::open(path)?;
    scan_embedded_archives_native_with_iocp(
        reader,
        DEFAULT_IOCP_CHUNK_SIZE / parallel_files.max(1),
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
    )
}

pub(crate) fn scan_detected_path(
    path: &str,
    format: &str,
    parallel_files: usize,
) -> io::Result<NativeScanResult> {
    let reader = ManagedReader::open(path)?;
    scan_native(
        reader,
        DEFAULT_IOCP_CHUNK_SIZE / parallel_files.max(1),
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
        Some(format),
    )
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

    scan.to_py_dict(py)
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
    scan_native(reader, iocp_chunk_bytes, iocp_buffers, iocp_workers, None)
}

fn scan_native(
    reader: ManagedReader,
    iocp_chunk_bytes: usize,
    iocp_buffers: usize,
    iocp_workers: usize,
    primary_format: Option<&str>,
) -> io::Result<NativeScanResult> {
    let file_size = reader.len();
    let (mut raw_hits, discarded, scan_read_bytes, scan_read_operations): (
        Vec<RawHit>,
        usize,
        u64,
        u64,
    ) = {
        #[cfg(windows)]
        {
            let path = reader.iocp_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IOCP embedded scanning requires a single regular file",
                )
            })?;
            // Small streams fit one reader window. Reuse the pooled native
            // handle and matcher rather than opening a completion port for it.
            let output = if file_size <= 64 * 1024 {
                let data = reader
                    .probe_reader()
                    .read_cached_at(0, file_size as usize)?;
                let hits = scan_sample_batch(data.as_slice(), 0, 0);
                iocp::IocpScanOutput {
                    results: hits.results,
                    discarded_results: hits.discarded_results,
                    read_bytes: data.len() as u64,
                    read_operations: u64::from(file_size != 0),
                }
            } else {
                iocp::scan_file(
                    path,
                    file_size,
                    iocp_chunk_bytes,
                    iocp_buffers,
                    iocp_workers,
                    embedded_overlap(),
                    scan_sample_batch,
                )?
            };
            (
                output.results,
                output.discarded_results,
                output.read_bytes,
                output.read_operations,
            )
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
        .filter(|hit| hit.kind() == "xz_footer")
        .map(|hit| hit.offset() + XZ_FOOTER_MAGIC.len() as u64)
        .collect::<Vec<_>>();
    xz_footer_ends.sort_unstable();
    let raw_hit_count = raw_hits
        .iter()
        .filter(|hit| !matches!(hit.kind(), "xz_footer" | "zip64_eocd"))
        .count()
        + discarded;
    raw_hits.retain(|hit| hit.kind() != "xz_footer");
    // Release noisy scan storage before walking structures or retaining a page.
    raw_hits.shrink_to_fit();
    raw_hits.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));

    // Identity alone may dispatch a stream only when this same signature pass
    // proves that no supported peer can be hidden in it. This avoids decoding
    // large ordinary gzip payloads just to rediscover their only header.
    let identity_only = primary_format.is_some_and(|format| {
        format != "lz4"
            && !raw_hits
                .iter()
                .any(|hit| hit.offset() != 0 && !matches!(hit.kind(), "zip64_eocd"))
    });

    // Structural facts survive in the result; transient validation windows
    // share this reader's generation/request state, not the global block cache.
    let probe_reader = reader.probe_reader();
    let mut candidates = if identity_only {
        Vec::new()
    } else {
        validate_raw_hits(&probe_reader, file_size, &raw_hits, &xz_footer_ends)?
    };
    candidates.sort_by_key(|candidate| {
        (
            candidate.offset,
            candidate.format,
            std::cmp::Reverse(candidate_rank(candidate)),
        )
    });
    candidates.dedup_by_key(|candidate| (candidate.offset, candidate.format));
    resolve_logical_candidates(&mut candidates);
    // Only validated root evidence survives in the cached native scan. Noise,
    // inner signatures and consumed directory records have no later users.
    raw_hits.retain(|hit| {
        !matches!(hit.kind(), "zip64_eocd")
            && candidates
                .binary_search_by_key(&(hit.offset(), hit.format()), |candidate| {
                    (candidate.offset, candidate.format)
                })
                .is_ok()
    });
    raw_hits.shrink_to_fit();
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
        identity_only,
    })
}

fn embedded_overlap() -> usize {
    PATTERNS
        .iter()
        .map(|(magic, _, _)| magic.len())
        .max()
        .unwrap_or(1)
        .max(12) // XZ footer CRC/flags precede its two-byte marker.
        .saturating_sub(1)
}

fn validate_raw_hits(
    reader: &ManagedReader,
    file_size: u64,
    raw_hits: &[RawHit],
    xz_footer_ends: &[u64],
) -> io::Result<Vec<EmbeddedCandidate>> {
    let mut suffixes: [FailedSuffixEvidence; 5] = std::array::from_fn(|_| Default::default());
    let mut xz_footers = XzFooterEvidence {
        ends: xz_footer_ends,
        next_unchecked: 0,
        valid: BTreeMap::new(),
    };
    // ZIP64 records were found in the same full-stream pass. Index each once
    // by its declared physical end; fake locators never trigger reverse scans.
    let mut zip64_records = BTreeMap::new();
    for hit in raw_hits.iter().filter(|hit| hit.kind() == "zip64_eocd") {
        let fixed = read_at(reader, hit.offset(), 56)?;
        if let Ok(record) = crate::formats::zip::zip64::parse_record(&fixed) {
            if let Some(end) = hit
                .offset()
                .checked_add(12 + record.record_size)
                .filter(|end| *end <= file_size)
            {
                zip64_records
                    .entry(end)
                    .or_insert_with(Vec::new)
                    .push((hit.offset(), record));
            }
        }
    }
    let mut candidates = raw_hits
        .par_iter()
        .filter(|hit| hit.kind() == "zip_eocd")
        .map_init(DirectoryEvidence::default, |directories, hit| {
            validate_zip_eocd(reader, file_size, hit.offset(), &zip64_records, directories)
        })
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // ZIP EOCD geometry can prove a logical root before its local-header hit is
    // visited. Seed exact ownership with those ranges, then process every other
    // hit in physical order. Once a resolver proves [start,end), signatures
    // inside that interval cannot add a peer carrier boundary and are skipped
    // before invoking any potentially size-proportional parser.
    let mut seeded_ranges = candidates
        .iter()
        .filter(|candidate| candidate.boundary_kind == "exact")
        .filter_map(|candidate| candidate.end_offset.map(|end| (candidate.offset, end)))
        .collect::<Vec<_>>();
    seeded_ranges.sort_unstable();

    let mut range_index = 0usize;
    let mut covered_until = 0u64;
    let mut previous_xz: Option<usize> = None;
    for hit in raw_hits
        .iter()
        .filter(|hit| !matches!(hit.kind(), "zip_eocd" | "zip64_eocd"))
    {
        while range_index < seeded_ranges.len() && seeded_ranges[range_index].0 <= hit.offset() {
            covered_until = covered_until.max(seeded_ranges[range_index].1);
            range_index += 1;
        }
        if hit.offset() < covered_until {
            continue;
        }

        let resolved = if hit.kind() == "xz" {
            validate_xz(reader, file_size, hit.offset(), &mut xz_footers)?
        } else {
            let suffix_index = match hit.kind() {
                "gzip" => 0,
                "bzip2" => 1,
                "zstd" => 2,
                "tar" => 3,
                _ => 4,
            };
            validate_candidate(
                reader,
                file_size,
                hit.kind(),
                hit.offset(),
                &mut suffixes[suffix_index],
            )?
        };
        let Some(candidate) = resolved else {
            continue;
        };
        if let Some(end) = candidate.end_offset {
            if candidate.boundary_kind == "exact" {
                covered_until = covered_until.max(end);
            }
        }
        if candidate.format == "xz" {
            if let Some(previous) = previous_xz {
                if let Some(end) = candidates[previous].end_offset {
                    if xz_stream_padding(reader, end, candidate.offset)? {
                        // Both boundaries were already proved by the shared
                        // footer/index evidence. Reuse them; do not analyze the
                        // payload again or expose TAR fragments as peer inputs.
                        candidates[previous].end_offset = candidate.end_offset;
                        continue;
                    }
                }
            }
            previous_xz = Some(candidates.len());
        }
        candidates.push(candidate);
    }
    Ok(candidates)
}

fn xz_stream_padding(reader: &ManagedReader, mut start: u64, end: u64) -> io::Result<bool> {
    if end < start || (end - start) % 4 != 0 {
        return Ok(false);
    }
    while start < end {
        let size = (end - start).min(64 * 1024) as usize;
        let padding = reader.read_cached_at(start, size)?;
        if padding.len() != size || padding.iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        start += size as u64;
    }
    Ok(true)
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
    // The caller sorts by offset. Delay each same-start group's coverage so
    // equal starts survive the original strict start < offset rule. Ranges
    // from removed candidates still contribute, preserving overlap semantics.
    let mut group_start = None;
    let mut covered_until = 0;
    let mut group_end = 0;
    candidates.retain(|item| {
        if group_start != Some(item.offset) {
            covered_until = covered_until.max(group_end);
            group_start = Some(item.offset);
            group_end = 0;
        }
        if item.candidate_kind == "logical_archive" {
            group_end = group_end.max(item.end_offset.unwrap_or(0));
        }
        item.offset >= covered_until
    });
}

#[cfg(test)]
fn scan_sample(sample: &[u8], carry_len: usize, base_offset: u64) -> Vec<RawHit> {
    scan_sample_batch(sample, carry_len, base_offset).results
}

fn scan_sample_batch(sample: &[u8], carry_len: usize, base_offset: u64) -> ScanBatch<RawHit> {
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        // SAFETY: the feature check guards every AVX2 instruction. The scanner
        // only loads vectors when all 34 accessed bytes belong to `sample`.
        return unsafe { scan_sample_avx2(sample, carry_len, base_offset) };
    }

    scan_sample_packed(sample, carry_len, base_offset)
}

fn signature_overlaps() -> &'static Vec<Vec<(usize, usize)>> {
    static OVERLAPS: OnceLock<Vec<Vec<(usize, usize)>>> = OnceLock::new();
    OVERLAPS.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|(left, _, _)| {
                PATTERNS
                    .iter()
                    .enumerate()
                    .flat_map(|(index, (right, _, _))| {
                        (1..left.len().min(right.len())).filter_map(move |n| {
                            (left[left.len() - n..] == right[..n]).then_some((index, n))
                        })
                    })
                    .collect()
            })
            .collect()
    })
}

fn scan_sample_packed(sample: &[u8], carry_len: usize, base_offset: u64) -> ScanBatch<RawHit> {
    let mut hits = ScanBatch::default();
    if let Some(matcher) = embedded_packed_matcher() {
        for matched in matcher.find_iter(sample) {
            let pattern = matched.pattern().as_usize();
            record_raw_hit(
                &mut hits,
                sample,
                carry_len,
                base_offset,
                pattern,
                matched.start(),
                matched.end(),
            );

            // Recover only proper suffix/prefix overlaps. This table is computed
            // once for the signature set; no additional file pass is needed.
            for &(next, overlap) in &signature_overlaps()[pattern] {
                let begin = matched.end() - overlap;
                let magic = PATTERNS[next].0;
                if sample.get(begin..begin + magic.len()) == Some(magic) {
                    record_raw_hit(
                        &mut hits,
                        sample,
                        carry_len,
                        base_offset,
                        next,
                        begin,
                        begin + magic.len(),
                    );
                }
            }
        }
    } else {
        for matched in embedded_matcher().find_overlapping_iter(sample) {
            record_raw_hit(
                &mut hits,
                sample,
                carry_len,
                base_offset,
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            );
        }
    }
    for start in memmem::find_iter(sample, XZ_FOOTER_MAGIC) {
        record_xz_footer(&mut hits, sample, start, carry_len, base_offset);
    }
    hits
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_sample_avx2(sample: &[u8], carry_len: usize, base_offset: u64) -> ScanBatch<RawHit> {
    use std::arch::x86_64::*;

    let tables = SIMD_PREFIX_TABLES;
    let mut hits = ScanBatch::default();
    let low_first = _mm256_loadu_si256(tables[0].as_ptr().cast());
    let high_first = _mm256_loadu_si256(tables[1].as_ptr().cast());
    let low_second = _mm256_loadu_si256(tables[2].as_ptr().cast());
    let high_second = _mm256_loadu_si256(tables[3].as_ptr().cast());
    let low_third = _mm256_loadu_si256(tables[4].as_ptr().cast());
    let high_third = _mm256_loadu_si256(tables[5].as_ptr().cast());
    let nibble_mask = _mm256_set1_epi8(15);
    let zero = _mm256_setzero_si256();
    let footer_first = _mm256_set1_epi8(XZ_FOOTER_MAGIC[0] as i8);
    let footer_second = _mm256_set1_epi8(XZ_FOOTER_MAGIC[1] as i8);
    let mut start = 0;
    while start + 34 <= sample.len() {
        let first = _mm256_loadu_si256(sample.as_ptr().add(start).cast());
        let second = _mm256_loadu_si256(sample.as_ptr().add(start + 1).cast());
        let third = _mm256_loadu_si256(sample.as_ptr().add(start + 2).cast());
        let first_bits = _mm256_and_si256(
            _mm256_shuffle_epi8(low_first, _mm256_and_si256(first, nibble_mask)),
            _mm256_shuffle_epi8(
                high_first,
                _mm256_and_si256(_mm256_srli_epi16(first, 4), nibble_mask),
            ),
        );
        let second_bits = _mm256_and_si256(
            _mm256_shuffle_epi8(low_second, _mm256_and_si256(second, nibble_mask)),
            _mm256_shuffle_epi8(
                high_second,
                _mm256_and_si256(_mm256_srli_epi16(second, 4), nibble_mask),
            ),
        );
        let third_bits = _mm256_and_si256(
            _mm256_shuffle_epi8(low_third, _mm256_and_si256(third, nibble_mask)),
            _mm256_shuffle_epi8(
                high_third,
                _mm256_and_si256(_mm256_srli_epi16(third, 4), nibble_mask),
            ),
        );
        let header_matches =
            _mm256_and_si256(_mm256_and_si256(first_bits, second_bits), third_bits);
        let footer_matches = _mm256_and_si256(
            _mm256_cmpeq_epi8(first, footer_first),
            _mm256_cmpeq_epi8(second, footer_second),
        );
        let matches = _mm256_or_si256(header_matches, footer_matches);
        let mut mask = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(matches, zero)) as u32);
        while mask != 0 {
            let candidate = start + mask.trailing_zeros() as usize;
            scan_sample_candidate(sample, carry_len, base_offset, candidate, &mut hits);
            mask &= mask - 1;
        }
        start += 32;
    }
    while start < sample.len() {
        scan_sample_candidate(sample, carry_len, base_offset, start, &mut hits);
        start += 1;
    }
    hits
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn scan_sample_candidate(
    sample: &[u8],
    carry_len: usize,
    base_offset: u64,
    start: usize,
    hits: &mut ScanBatch<RawHit>,
) {
    let first = sample[start];
    if first == XZ_FOOTER_MAGIC[0] {
        record_xz_footer(hits, sample, start, carry_len, base_offset);
        return;
    }
    // Direct dispatch keeps dense rejected prefixes cheap. A longer generic
    // loop stops being unrolled by the compiler when new signatures are added.
    macro_rules! check {
        ($index:expr) => {
            if $index < PATTERNS.len() {
                let magic = PATTERNS[$index].0;
                if sample.get(start..start + magic.len()) == Some(magic) {
                    record_raw_hit(
                        hits,
                        sample,
                        carry_len,
                        base_offset,
                        $index,
                        start,
                        start + magic.len(),
                    );
                }
            }
        };
    }
    // ZIP/RAR prefixes dominate rejected candidates in executables and images.
    // Keep these paths outside the sparse dispatch table.
    if first == b'P' {
        check!(0);
        check!(1);
        check!(12);
        return;
    }
    if first == b'R' {
        check!(3);
        check!(4);
        return;
    }
    match first {
        b'7' => check!(2),
        0x1f => check!(5),
        b'B' => check!(6),
        0xfd => check!(7),
        b'(' => check!(8),
        b'u' => check!(9),
        4 => check!(10),
        0x2a => check!(11),
        _ => {}
    }
}

fn record_xz_footer(
    hits: &mut ScanBatch<RawHit>,
    sample: &[u8],
    start: usize,
    carry_len: usize,
    base_offset: u64,
) {
    let end = start + XZ_FOOTER_MAGIC.len();
    if end <= carry_len || start < 10 {
        return;
    }
    let Some(footer) = sample.get(start - 10..end) else {
        return;
    };
    // Reuse the canonical footer parser against the bytes already in the IOCP
    // buffer. Invalid two-byte markers require neither storage nor later I/O.
    if parse_xz_footer(footer, base_offset + end as u64).is_ok() {
        hits.results.push(RawHit::new(
            base_offset + start as u64,
            PATTERNS.len() as u8,
        ));
    }
}

fn record_raw_hit(
    hits: &mut ScanBatch<RawHit>,
    sample: &[u8],
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
    let (_, _, kind) = PATTERNS[pattern];
    let absolute = base_offset + start as u64;
    let candidate_offset = if kind == "lz4_skippable" {
        let Some(value) = absolute.checked_sub(1) else {
            return;
        };
        value
    } else if kind == "tar" {
        let Some(value) = absolute.checked_sub(257) else {
            return;
        };
        value
    } else {
        absolute
    };
    // Count rejected fixed headers without retaining an object per hit. A
    // header crossing a chunk boundary remains eligible for the normal walk.
    if fixed_header_invalid(pattern, &sample[start..]) {
        hits.discarded_results += 1;
        return;
    }
    if kind == "tar" && start >= 257 {
        if sample
            .get(start - 257..start - 257 + 512)
            .is_some_and(|header| !crate::formats::tar::valid_header(header))
        {
            hits.discarded_results += 1;
            return;
        }
    }
    hits.results
        .push(RawHit::new(candidate_offset, pattern as u8));
}

fn fixed_header_invalid(pattern: usize, bytes: &[u8]) -> bool {
    // Reuse the structural parsers on bytes already in the scan buffer. An
    // incomplete header at a chunk edge must remain eligible for validation.
    match pattern {
        0 => bytes
            .get(..30)
            .is_some_and(|header| !zip_local_fixed_plausible(header)),
        1 => bytes
            .get(..22)
            .is_some_and(|header| !zip_eocd_fixed_plausible(header)),
        2 => bytes
            .get(..32)
            .is_some_and(|header| !seven_zip_start_header_valid(header)),
        5 => bytes
            .get(..10)
            .is_some_and(|header| gzip_fixed_header_flags(header.try_into().unwrap()).is_err()),
        6 => bytes.get(..10).map_or_else(
            || {
                bytes.get(..4).is_some_and(|header| {
                    bzip2_header_block_limit(header.try_into().unwrap()).is_err()
                })
            },
            |prefix| !bzip2_prefix_valid(prefix.try_into().unwrap()),
        ),
        7 => bytes
            .get(..12)
            .is_some_and(|header| validate_xz_header(header).is_err()),
        10 => bytes
            .get(..19)
            .is_some_and(|header| crate::formats::lz4::parse_header(header).is_err()),
        _ => false,
    }
}

fn zip_eocd_fixed_plausible(header: &[u8]) -> bool {
    if header.len() < 22 || &header[..4] != ZIP_EOCD {
        return false;
    }
    let disk = u16::from_le_bytes([header[4], header[5]]);
    let cd_disk = u16::from_le_bytes([header[6], header[7]]);
    if disk != 0 || cd_disk != 0 {
        return false;
    }
    let entries_on_disk = u16::from_le_bytes([header[8], header[9]]);
    let entries_total = u16::from_le_bytes([header[10], header[11]]);
    let needs_zip64 = u32::from_le_bytes(header[12..16].try_into().unwrap()) == u32::MAX
        || u32::from_le_bytes(header[16..20].try_into().unwrap()) == u32::MAX
        || entries_on_disk == u16::MAX
        || entries_total == u16::MAX;
    needs_zip64 || entries_on_disk == entries_total
}

fn validate_candidate(
    file: &ManagedReader,
    file_size: u64,
    kind: &str,
    offset: u64,
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    match kind {
        "zip" => validate_zip(file, file_size, offset),
        "7z" => validate_seven_zip(file, file_size, offset),
        "rar4" => validate_rar4(file, file_size, offset),
        "rar5" => validate_rar5(file, file_size, offset),
        "gzip" => validate_gzip(file, file_size, offset, suffixes),
        "bzip2" => validate_bzip2(file, file_size, offset, suffixes),
        "zstd" => validate_zstd(file, file_size, offset, suffixes),
        "tar" => validate_tar(file, file_size, offset, suffixes),
        "lz4" | "lz4_skippable" => {
            if kind == "lz4_skippable" {
                let magic = read_at(file, offset, 4)?;
                if magic.len() != 4
                    || !crate::formats::lz4::skippable(u32::from_le_bytes(
                        magic.as_slice().try_into().unwrap(),
                    ))
                {
                    return Ok(None);
                }
            }
            let mut incomplete = None;
            let resolved = suffixes.validate(offset, true, |visit| {
                let index =
                    crate::formats::lz4::walk_observed(file, offset, file_size, &mut |node| {
                        visit(node).map_err(|_| "known_failed_suffix")
                    });
                if index.complete {
                    Ok(index)
                } else {
                    let error = index.error;
                    incomplete = Some(index);
                    Err(ValidationError::Invalid(error))
                }
            })?;
            let Some(index) = resolved.or(incomplete) else {
                return Ok(None);
            };
            if index.frames == 0 {
                return Ok(None);
            }
            let mut item = logical_candidate(
                "lz4",
                offset,
                index.complete.then_some(index.end),
                if index.complete { 0.98 } else { 0.72 },
                "lz4_frame_structure",
            );
            item.lz4_index = Some(Box::new(index));
            Ok(Some(item))
        }
        _ => Ok(None),
    }
}

#[derive(Clone, Copy)]
struct DirectorySuffix {
    start: u64,
    end: u64,
    entries: usize,
}

#[derive(Default)]
struct DirectoryEvidence {
    // Only directories requested by an EOCD receive an index. Per-Rayon-task
    // suffixes reuse overlapping proposals without a shared lock or a
    // signature object for every possible directory marker in the payload.
    suffixes: Vec<DirectorySuffix>,
}

impl DirectoryEvidence {
    fn find(&self, start: u64) -> Option<DirectorySuffix> {
        self.suffixes
            .binary_search_by_key(&start, |item| item.start)
            .ok()
            .map(|index| self.suffixes[index])
    }

    fn matches(
        &mut self,
        file: &ManagedReader,
        start: u64,
        end: u64,
        entries: usize,
    ) -> io::Result<bool> {
        let observed = if let Some(cached) = self.find(start) {
            cached
        } else {
            let mut source = BufReader::with_capacity(64 * 1024, file.stream_cursor());
            source.seek(SeekFrom::Start(start))?;
            let mut cursor = start;
            let mut path = Vec::new();
            let mut suffix = loop {
                if let Some(cached) = self.find(cursor) {
                    break cached;
                }
                let mut fixed = [0u8; 46];
                let length = if cursor.saturating_add(46) <= file.len() {
                    source.read_exact(&mut fixed)?;
                    crate::formats::zip::central_directory_record_len(&fixed)
                } else {
                    None
                };
                let Some(next) = length
                    .and_then(|length| cursor.checked_add(length as u64))
                    .filter(|next| *next <= file.len())
                else {
                    break DirectorySuffix {
                        start: cursor,
                        end: cursor,
                        entries: 0,
                    };
                };
                if path.len() >= MAX_ARCHIVE_METADATA_RECORDS {
                    return Ok(false);
                }
                path.push(cursor);
                source.seek_relative((next - cursor - 46) as i64)?;
                cursor = next;
            };
            let first_new = self.suffixes.len();
            for start in path.into_iter().rev() {
                suffix = DirectorySuffix {
                    start,
                    end: suffix.end,
                    entries: suffix.entries + 1,
                };
                self.suffixes.push(suffix);
            }
            // A walk appends nodes in reverse physical order. Existing nodes
            // are disjoint from the newly visited path.
            self.suffixes[first_new..].reverse();
            if first_new != 0 {
                self.suffixes.sort_unstable_by_key(|item| item.start);
            }
            suffix
        };
        if observed.entries != entries || observed.end > end {
            return Ok(false);
        }
        if observed.end == end {
            return Ok(true);
        }
        // One optional ZIP directory digital signature belongs to the range.
        let signature = read_at(file, observed.end, 6)?;
        Ok(signature.len() == 6
            && signature.starts_with(b"PK\x05\x05")
            && observed.end + 6 + u16::from_le_bytes([signature[4], signature[5]]) as u64 == end)
    }
}

fn validate_zip_eocd(
    file: &ManagedReader,
    size: u64,
    eocd_offset: u64,
    zip64_records: &BTreeMap<u64, Vec<(u64, crate::formats::zip::zip64::EndRecord)>>,
    directories: &mut DirectoryEvidence,
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
    let zip64 = match parse_zip64_end_records(file, eocd_offset, zip64_records) {
        Ok(records) => records,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(error) => return Err(error),
    };
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
    let cd_magic = read_at(file, actual_cd_start, 4)?;
    if cd_size > 0 && cd_magic.as_slice() != b"PK\x01\x02" {
        return Ok(None);
    }
    if !validate_zip_boundary_evidence(
        file,
        actual_cd_start,
        directory_end,
        archive_offset,
        entries_total as usize,
        directories,
    )? {
        return Ok(None);
    }
    let mut resolved = candidate(
        "zip",
        archive_offset,
        Some(end),
        1.0,
        if needs_zip64 {
            "zip64_eocd_geometry_and_first_local_link"
        } else {
            "eocd_geometry_and_first_local_link"
        },
    );
    resolved.zip_eocd_offset = Some(eocd_offset);
    Ok(Some(resolved))
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
    records: &BTreeMap<u64, Vec<(u64, crate::formats::zip::zip64::EndRecord)>>,
) -> io::Result<Option<Zip64EndRecords>> {
    if eocd_offset < 20 {
        return Ok(None);
    }
    let locator = read_at(file, eocd_offset - 20, 20)?;
    if locator.len() != 20 || &locator[..4] != b"PK\x06\x07" {
        return Ok(None);
    }
    let locator_disk = u32::from_le_bytes(locator[4..8].try_into().unwrap());
    let locator_fields = crate::formats::zip::zip64::parse_locator(&locator)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let recorded_record_offset = locator_fields.record_offset;
    let disk_count = locator_fields.total_disks;
    if locator_disk != 0 || disk_count != 1 || eocd_offset < 32 {
        return Ok(None);
    }

    let Some((record_offset, record)) = records.get(&(eocd_offset - 20)).and_then(|items| {
        items.iter().find(|(offset, record)| {
            record.disk == 0
                && record.cd_disk == 0
                && record.disk_entries == record.total_entries
                && offset.checked_sub(recorded_record_offset)
                    == offset
                        .checked_sub(record.cd_size)
                        .and_then(|start| start.checked_sub(record.cd_offset))
                && *offset >= recorded_record_offset
        })
    }) else {
        return Ok(None);
    };
    Ok(Some(Zip64EndRecords {
        record_offset: *record_offset,
        recorded_record_offset,
        disk: record.disk,
        cd_disk: record.cd_disk,
        entries_on_disk: record.disk_entries,
        entries_total: record.total_entries,
        cd_size: record.cd_size,
        cd_offset: record.cd_offset,
    }))
}

fn validate_zip_boundary_evidence(
    file: &ManagedReader,
    start: u64,
    end: u64,
    archive_offset: u64,
    entries: usize,
    directories: &mut DirectoryEvidence,
) -> io::Result<bool> {
    if entries == 0 {
        return Ok(start == end);
    }
    if !directories.matches(file, start, end, entries)? {
        return Ok(false);
    }
    let fixed = read_at(file, start, 46)?;
    if fixed.len() != 46 || &fixed[..4] != b"PK\x01\x02" {
        return Ok(false);
    }
    let name_len = u16::from_le_bytes(fixed[28..30].try_into().unwrap()) as u64;
    let extra_len = u16::from_le_bytes(fixed[30..32].try_into().unwrap()) as u64;

    let compressed = u32::from_le_bytes(fixed[20..24].try_into().unwrap());
    let uncompressed = u32::from_le_bytes(fixed[24..28].try_into().unwrap());
    let disk_start = u16::from_le_bytes(fixed[34..36].try_into().unwrap());
    if disk_start != 0 && disk_start != u16::MAX {
        return Ok(false);
    }
    let local_32 = u32::from_le_bytes(fixed[42..46].try_into().unwrap());
    let local_offset = if local_32 == u32::MAX {
        let extra = read_at(file, start + 46 + name_len, extra_len as usize)?;
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
    Ok(absolute_local < start && read_at(file, absolute_local, 4)?.as_slice() == ZIP_LOCAL)
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

fn read_at(file: &ManagedReader, offset: u64, len: usize) -> std::io::Result<CachedBytes> {
    file.read_cached_at(offset, len)
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
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let compressed_32 = u32::from_le_bytes(header[18..22].try_into().unwrap());
    let uncompressed_32 = u32::from_le_bytes(header[22..26].try_into().unwrap());
    let name_len = u16::from_le_bytes([header[26], header[27]]) as u64;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as u64;
    let header_end = offset
        .saturating_add(30)
        .saturating_add(name_len)
        .saturating_add(extra_len);
    if !zip_local_fixed_plausible(&header) || header_end > size {
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
    Ok(Some(candidate("zip", offset, None, confidence, validation)))
}

fn zip_local_fixed_plausible(header: &[u8]) -> bool {
    let version = u16::from_le_bytes([header[4], header[5]]);
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let name_len = u16::from_le_bytes([header[26], header[27]]);
    version <= 100 && flags & 0xc000 == 0 && name_len != 0
}

fn validate_seven_zip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 32)?;
    if !seven_zip_start_header_valid(&header) {
        return Ok(None);
    }
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    // An absent next header cannot authorize an intervening payload range.
    if next_size == 0 && next_offset != 0 {
        return Ok(None);
    }
    let Some(next_start) = offset
        .checked_add(32)
        .and_then(|value| value.checked_add(next_offset))
    else {
        return Ok(None);
    };
    let Some(end) = next_start.checked_add(next_size) else {
        return Ok(None);
    };
    if end > size {
        return Ok(Some(logical_candidate(
            "7z",
            offset,
            None,
            0.90,
            "start_header_crc_truncated_declared_range",
        )));
    }
    // A CRC-valid start header proves only a proposed range. Never let an
    // unverified proposal hide independent archives in a carrier. Stream the
    // next header so a large metadata tree does not require a large allocation.
    let mut checksum = crc32fast::Hasher::new();
    let mut cursor = next_start;
    let mut first = None;
    while cursor < end {
        let bytes = read_at(file, cursor, (end - cursor).min(64 * 1024) as usize)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if first.is_none() {
            first = bytes.first().copied();
            if !matches!(first, Some(0x01 | 0x17)) {
                return Ok(None);
            }
        }
        checksum.update(&bytes);
        cursor += bytes.len() as u64;
    }
    if checksum.finalize() != u32::from_le_bytes(header[28..32].try_into().unwrap()) {
        return Ok(None);
    }
    Ok(Some(candidate(
        "7z",
        offset,
        Some(end),
        1.0,
        "start_and_next_header_crc_and_declared_end",
    )))
}

fn seven_zip_start_header_valid(header: &[u8]) -> bool {
    header.len() >= 32
        && header.starts_with(SEVEN_ZIP)
        && header[6] == 0
        && crc32(&header[12..32]) == u32::from_le_bytes(header[8..12].try_into().unwrap())
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
        let Some(add_size) = crate::formats::rar::rar4_data_size(&header) else {
            return Ok(None);
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

// Owned only by this physical-order scan. Facts refer to exact parser-visited
// nodes, never the intervening payload (which may contain independent archives).
#[derive(Default)]
struct FailedSuffixEvidence {
    failed: BTreeSet<u64>,
}

impl FailedSuffixEvidence {
    fn validate<T>(
        &mut self,
        offset: u64,
        join_suffix: bool,
        parse: impl FnOnce(&mut dyn FnMut(u64) -> ValidationResult<()>) -> ValidationResult<T>,
    ) -> io::Result<Option<T>> {
        while self.failed.first().is_some_and(|&node| node < offset) {
            self.failed.pop_first();
        }
        if self.failed.remove(&offset) {
            return Ok(None);
        }
        let mut visited = Vec::new();
        let result = parse(&mut |node| {
            if join_suffix && self.failed.contains(&node) {
                return Err(ValidationError::Invalid("known_failed_suffix"));
            }
            if node > offset {
                visited.push(node);
            }
            Ok(())
        });
        match result {
            Ok(value) => Ok(Some(value)),
            Err(ValidationError::Io(error)) => Err(error),
            Err(ValidationError::Invalid(code)) => {
                // These failures depend on accumulation from the caller's
                // root. A shorter suffix may stay within its own limit.
                if !matches!(
                    code,
                    "bzip2_block_count_exceeded"
                        | "zstd_block_count_exceeded"
                        | "decoded_size_overflow"
                        | "deflate_block_count_overflow"
                        | "lz4_walk_budget_exhausted"
                        | "lz4_size_overflow"
                        | "os_error"
                ) {
                    self.failed.extend(visited);
                }
                Ok(None)
            }
        }
    }
}

fn validate_gzip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let Some(structure) = suffixes.validate(offset, true, |visit| {
        validate_gzip_structure_observed(file, offset, size, visit)
    })?
    else {
        return Ok(None);
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
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let Some(structure) = suffixes.validate(offset, true, |visit| {
        validate_bzip2_structure_observed(file, offset, size, visit)
    })?
    else {
        return Ok(None);
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

// One physical-order analysis owns these facts. Invalid footers and indexes
// are discarded by advancing the cursor; only proven future roots are retained.
// Nothing survives this scan. Read lazily to preserve the existing I/O order.
struct XzFooterEvidence<'a> {
    ends: &'a [u64],
    next_unchecked: usize,
    valid: BTreeMap<u64, u64>,
}

fn validate_xz(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    footers: &mut XzFooterEvidence<'_>,
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
    // Headers arrive in increasing physical order. No later header can need
    // an unchecked footer that precedes this minimum boundary.
    footers.next_unchecked = footers
        .next_unchecked
        .max(footers.ends.partition_point(|end| *end < offset + 24));
    while footers
        .valid
        .first_key_value()
        .is_some_and(|(&start, _)| start < offset)
    {
        footers.valid.pop_first();
    }
    let mut matched_end = footers.valid.remove(&offset);
    loop {
        if let Some(end) = matched_end {
            return Ok(Some(candidate(
                "xz",
                offset,
                Some(end),
                0.99,
                "xz_header_index_footer_boundary",
            )));
        }
        let Some(&end) = footers.ends.get(footers.next_unchecked) else {
            return Ok(None);
        };
        footers.next_unchecked += 1;
        if end > size {
            return Ok(None);
        }
        // Every YZ marker was collected by the scan. The earliest matching
        // footer proves the first stream, including in a concatenation; there
        // is no need to walk preceding streams for each unrelated header.
        match resolve_xz_stream_start(file, offset, end) {
            Ok(start) if start == offset => matched_end = Some(end),
            Ok(start) => {
                footers.valid.entry(start).or_insert(end);
            }
            Err(ValidationError::Invalid(_)) => {}
            Err(ValidationError::Io(error)) => return Err(error),
        }
    }
}

fn validate_zstd(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let Some(structure) = suffixes.validate(offset, true, |visit| {
        validate_zstd_structure_observed(file, offset, size, visit)
    })?
    else {
        return Ok(None);
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
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    // TAR's walk cap accepts an unresolved logical archive. Do not shortcut a
    // joined suffix inside the walk: its failure could be beyond that cap.
    suffixes.validate(offset, false, |visit| {
        walk_tar_candidate(file, size, offset, visit)
    })
}

fn walk_tar_candidate(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    mut visit: impl FnMut(u64) -> ValidationResult<()>,
) -> ValidationResult<EmbeddedCandidate> {
    if offset + 512 > size {
        return Err(ValidationError::Invalid("tar_header_missing"));
    }
    let header = read_at(file, offset, 512)?;
    if header.len() < 512 || &header[257..262] != TAR_USTAR {
        return Err(ValidationError::Invalid("tar_header_invalid"));
    }
    let mut cursor = offset;
    let mut state = crate::formats::tar::TarState::default();
    for _ in 0..MAX_ARCHIVE_METADATA_RECORDS {
        // A PAX size inherited from an earlier header cannot disprove a TAR
        // rooted at this cursor with its own fresh metadata context.
        if state.boundary_context_free() {
            visit(cursor)?;
        }
        let current = read_at(file, cursor, 512)?;
        if current.len() != 512 {
            return Err(ValidationError::Invalid("tar_header_missing"));
        }
        if current.iter().all(|byte| *byte == 0) {
            let second = read_at(file, cursor + 512, 512)?;
            if second.len() != 512 || !second.iter().all(|byte| *byte == 0) {
                return Err(ValidationError::Invalid("tar_end_blocks_missing"));
            }
            return Ok(candidate(
                "tar",
                offset,
                Some(tar_padding_end(file, cursor + 1024, size)?),
                1.0,
                "member_walk_checksums_and_end_blocks",
            ));
        }
        let record = state
            .advance(&current, cursor, size, false, &mut |start, size| {
                Ok(read_at(file, start, size)?.to_vec())
            })
            .map_err(|error| match error.kind() {
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                    ValidationError::Invalid("tar_metadata_invalid")
                }
                _ => ValidationError::Io(error),
            })?;
        cursor = record.next;
    }
    Ok(logical_candidate(
        "tar",
        offset,
        None,
        0.90,
        "tar_member_walk_limit_reached",
    ))
}

fn tar_padding_end(file: &ManagedReader, mut end: u64, size: u64) -> io::Result<u64> {
    while end < size {
        let padding = read_at(file, end, (size - end).min(64 * 1024) as usize)?;
        let zeros = padding
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(padding.len());
        end += zeros as u64;
        if zeros < padding.len() || padding.is_empty() {
            break;
        }
    }
    Ok(end)
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
        lz4_index: None,
        zip_eocd_offset: None,
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

    // Ordinary valid-stream fixtures do not cover tail facts shared by many
    // earlier false headers, or unrelated footer reads after a conclusive match.
    #[test]
    fn xz_footer_evidence_preserves_false_headers_peers_and_lazy_io() {
        use crate::io::reader::ReaderConfig;
        let mut encoder = XzEncoder::new(Vec::new(), 1);
        encoder.write_all(b"xz payload").unwrap();
        let stream = encoder.finish().unwrap();
        let mut data = b"carrier-prefix".to_vec();
        for variant in 0..4 {
            data.extend_from_slice(&stream[..12]);
            data.extend_from_slice(b"broken stream contents");
            let mut footer = stream[stream.len() - 12..].to_vec();
            match variant {
                0 => footer[0] ^= 1,
                1 => footer[8] = 1,
                2 => footer[9] = 2,
                _ => footer[4..8].fill(0),
            }
            if variant != 0 {
                let checksum = crc32(&footer[4..10]);
                footer[..4].copy_from_slice(&checksum.to_le_bytes());
            }
            data.extend_from_slice(&footer);
            data.extend_from_slice(b"invalid gap");
        }
        let mut expected = Vec::new();
        for _ in 0..2 {
            expected.push(data.len() as u64);
            data.extend_from_slice(&stream);
            data.extend_from_slice(b"peer separator");
        }
        let mut hits = scan_sample(&data, 0, 0);
        let mut ends = hits
            .iter()
            .filter(|hit| hit.kind() == "xz_footer")
            .map(|hit| hit.offset() + 2)
            .collect::<Vec<_>>();
        ends.sort_unstable();
        hits.retain(|hit| hit.kind() != "xz_footer");
        hits.sort_unstable_by_key(|hit| hit.offset());
        let source = ManagedReader::from_bytes(data, ReaderConfig::default());
        let candidates = validate_raw_hits(&source, source.len(), &hits, &ends).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|item| item.offset)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(candidates.iter().all(|item| item.boundary_kind == "exact"));

        let mut data = stream.clone();
        data.extend_from_slice(b"unrelated tail");
        for _ in 0..100 {
            data.extend_from_slice(b"bad footerYZ");
        }
        let hits = scan_sample(&data, 0, 0);
        let mut ends = hits
            .iter()
            .filter(|hit| hit.kind() == "xz_footer")
            .map(|hit| hit.offset() + 2)
            .collect::<Vec<_>>();
        ends.sort_unstable();
        let source = ManagedReader::from_bytes(
            data,
            ReaderConfig {
                max_read_bytes: Some(512),
                ..ReaderConfig::default()
            },
        );
        let mut facts = XzFooterEvidence {
            ends: &ends,
            next_unchecked: 0,
            valid: BTreeMap::new(),
        };
        let matched = validate_xz(&source, source.len(), 0, &mut facts)
            .unwrap()
            .unwrap();
        assert_eq!(matched.end_offset, Some(stream.len() as u64));
    }

    // Ordinary LZ4 fixtures cannot catch failed-suffix ownership hiding a real
    // archive in skipped payload, or a root's frame budget poisoning its peers.
    #[test]
    fn lz4_failed_suffixes_keep_payload_roots_and_independent_budgets() {
        use crate::io::reader::ReaderConfig;
        let empty = b"\x04\x22\x4d\x18\x60\x40\x82\0\0\0\0";
        let mut data = b"carrier".to_vec();
        let root = data.len() as u64;
        data.extend_from_slice(&empty.repeat(1024));
        data.extend_from_slice(&empty[..7]);
        data.extend_from_slice(&(0x80000000 | empty.len() as u32).to_le_bytes());
        let inner = data.len() as u64;
        data.extend_from_slice(empty);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"\x04\x22");

        let budget_data = empty.repeat(65_537);
        let budget_end = budget_data.len() as u64;
        for (data, root, inner, inner_end) in [
            (data, root, inner, inner + empty.len() as u64),
            (budget_data, 0, empty.len() as u64, budget_end),
        ] {
            let mut hits = scan_sample(&data, 0, 0);
            hits.sort_unstable_by_key(|hit| hit.offset());
            let source = ManagedReader::from_bytes(
                data.clone(),
                ReaderConfig {
                    max_read_bytes: Some(data.len() as u64 * 3),
                    ..Default::default()
                },
            );
            let candidates = validate_raw_hits(&source, source.len(), &hits, &[]).unwrap();
            assert_eq!(candidates.len(), 2);
            assert_eq!(candidates[0].offset, root);
            assert_eq!(candidates[0].end_offset, None);
            assert_eq!(candidates[1].offset, inner);
            assert_eq!(candidates[1].end_offset, Some(inner_end));
            assert!(source.stats().unwrap().read_bytes <= data.len() as u64 * 3);
        }
    }

    // Ordinary peers do not exercise future roots discovered by an earlier
    // false header, or the finite reader budget consumed by corrupt indexes.
    #[test]
    fn xz_index_evidence_keeps_future_roots_under_read_budget_and_propagates_io() {
        use crate::io::reader::ReaderConfig;
        let mut encoder = XzEncoder::new(Vec::new(), 1);
        encoder.write_all(b"future xz root").unwrap();
        let stream = encoder.finish().unwrap();
        let mut data = b"carrier-prefix".to_vec();
        let mut footer = 1u32.to_le_bytes().to_vec();
        footer.extend_from_slice(&stream[6..8]);
        for _ in 0..64 {
            data.extend_from_slice(&stream[..12]);
            data.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
            data.extend_from_slice(&crc32(&footer).to_le_bytes());
            data.extend_from_slice(&footer);
            data.extend_from_slice(b"YZ");
        }
        let mut expected = Vec::new();
        for gap in [&[0; 8][..], &b"independent peer"[..], &[][..]] {
            expected.push((data.len() as u64, (data.len() + stream.len()) as u64));
            data.extend_from_slice(&stream);
            data.extend_from_slice(gap);
        }
        // Aligned zero padding joins the first two streams. The nonzero gap
        // still leaves the third as an independent archive under the same budget.
        let expected = vec![(expected[0].0, expected[1].1), expected[2]];
        let mut hits = scan_sample(&data, 0, 0);
        let mut ends = hits
            .iter()
            .filter(|hit| hit.kind() == "xz_footer")
            .map(|hit| hit.offset() + 2)
            .collect::<Vec<_>>();
        ends.sort_unstable();
        hits.retain(|hit| hit.kind() != "xz_footer");
        hits.sort_unstable_by_key(|hit| hit.offset());
        let source = ManagedReader::from_bytes(
            data,
            ReaderConfig {
                max_read_bytes: Some(8192),
                ..ReaderConfig::default()
            },
        );
        let candidates = validate_raw_hits(&source, source.len(), &hits, &ends).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|item| (item.offset, item.end_offset.unwrap()))
                .collect::<Vec<_>>(),
            expected
        );

        let source = ManagedReader::from_bytes(
            stream.clone(),
            ReaderConfig {
                max_read_bytes: Some(12),
                ..ReaderConfig::default()
            },
        );
        let mut facts = XzFooterEvidence {
            ends: &[stream.len() as u64],
            next_unchecked: 0,
            valid: BTreeMap::new(),
        };
        assert!(validate_xz(&source, source.len(), 0, &mut facts).is_err());
    }

    // Equal starts, crossing/removed ranges, anchors and zero-width endpoints
    // are independent of stream parsing. Check the strict interval semantics.
    #[test]
    fn linear_candidate_resolution_preserves_strict_interval_ownership() {
        for shift in 0..8 {
            let mut inputs = (0..192u64)
                .map(|i| {
                    let offset = i / 3;
                    let end = (i % 7 != 0).then_some(offset + (i * 17 + shift) % 21);
                    let mut item = candidate("zip", offset, end, 1.0, "matrix");
                    if i % 5 == 0 {
                        item.candidate_kind = "anchor";
                    }
                    item
                })
                .collect::<Vec<_>>();
            let project =
                |item: &EmbeddedCandidate| (item.offset, item.end_offset, item.candidate_kind);
            let expected = inputs
                .iter()
                .filter(|item| {
                    !inputs.iter().any(|owner| {
                        owner.candidate_kind == "logical_archive"
                            && owner
                                .end_offset
                                .is_some_and(|end| owner.offset < item.offset && item.offset < end)
                    })
                })
                .map(project)
                .collect::<Vec<_>>();
            resolve_logical_candidates(&mut inputs);
            assert_eq!(inputs.iter().map(project).collect::<Vec<_>>(), expected);
        }
    }
    fn reference_raw_hits(data: &[u8]) -> Vec<RawHit> {
        // Compare matcher enumeration independently; both paths must apply the
        // same canonical fixed-header policy to each signature.
        let mut hits = ScanBatch::default();
        for matched in embedded_matcher().find_overlapping_iter(data) {
            record_raw_hit(
                &mut hits,
                data,
                0,
                0,
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            );
        }
        hits.results
            .sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        hits.results
    }

    fn optimized_raw_hits(data: &[u8]) -> Vec<RawHit> {
        let mut hits = scan_sample(data, 0, 0);
        hits.retain(|hit| hit.kind() != "xz_footer");
        hits.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        hits
    }

    #[test]
    fn simd_scan_matches_reference_with_footers_and_carry_boundaries() {
        let mut data = vec![0x55; 64 + PATTERNS.len() * 19];
        for (index, (magic, _, _)) in PATTERNS.iter().enumerate() {
            let start = 41 + index * 19;
            data[start..start + magic.len()].copy_from_slice(magic);
        }
        let mut footer = [0u8; 12];
        footer[4..8].copy_from_slice(&1u32.to_le_bytes());
        footer[10..12].copy_from_slice(XZ_FOOTER_MAGIC);
        let checksum = crc32(&footer[4..10]);
        footer[..4].copy_from_slice(&checksum.to_le_bytes());
        data[21..33].copy_from_slice(&footer);
        data[213..225].copy_from_slice(&footer);

        for length in 0..=data.len() {
            for carry_len in [0, 31, 32, 33, 64] {
                let sample = &data[..length];
                let mut expected = ScanBatch::default();
                for matched in embedded_matcher().find_overlapping_iter(sample) {
                    record_raw_hit(
                        &mut expected,
                        sample,
                        carry_len,
                        4096,
                        matched.pattern().as_usize(),
                        matched.start(),
                        matched.end(),
                    );
                }
                for start in memmem::find_iter(sample, XZ_FOOTER_MAGIC) {
                    if start >= 10
                        && start + 2 > carry_len
                        && parse_xz_footer(&sample[start - 10..start + 2], 4096 + start as u64 + 2)
                            .is_ok()
                    {
                        expected
                            .results
                            .push(RawHit::new(4096 + start as u64, PATTERNS.len() as u8));
                    }
                }
                let mut actual = scan_sample(sample, carry_len, 4096);
                expected
                    .results
                    .sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
                actual.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
                assert_eq!(
                    actual, expected.results,
                    "length={length} carry={carry_len}"
                );
            }
        }

        for prefix in [b"PK".as_slice(), b"Rar", b"7z", b"YZ"] {
            let dense = prefix.repeat(4096);
            let mut expected = ScanBatch::default();
            for matched in embedded_matcher().find_overlapping_iter(&dense) {
                record_raw_hit(
                    &mut expected,
                    &dense,
                    0,
                    0,
                    matched.pattern().as_usize(),
                    matched.start(),
                    matched.end(),
                );
            }
            for start in memmem::find_iter(&dense, XZ_FOOTER_MAGIC) {
                if start >= 10
                    && parse_xz_footer(&dense[start - 10..start + 2], start as u64 + 2).is_ok()
                {
                    expected
                        .results
                        .push(RawHit::new(start as u64, PATTERNS.len() as u8));
                }
            }
            let mut actual = scan_sample(&dense, 0, 0);
            expected
                .results
                .sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
            actual.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
            assert_eq!(actual, expected.results, "dense prefix {prefix:?}");
        }
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

    // Failed outer walks must share only their visited heads. Same-format
    // archives inside skipped payload remain independent carrier candidates.
    #[test]
    fn failed_suffixes_keep_inner_archives_under_read_budget_and_propagate_io() {
        use crate::io::reader::ReaderConfig;
        let mut gz = GzEncoder::new(Vec::new(), Compression::none());
        gz.write_all(b"inner gzip").unwrap();
        let inner_gz = gz.finish().unwrap();
        let mut empty = GzEncoder::new(Vec::new(), Compression::fast());
        empty.write_all(b"").unwrap();
        let empty_gz = empty.finish().unwrap();
        let mut outer = GzEncoder::new(Vec::new(), Compression::none());
        outer.write_all(&inner_gz).unwrap();
        let mut bad_gz = outer.finish().unwrap();
        let last = bad_gz.len() - 1;
        bad_gz[last] ^= 1;
        let mut gz_data = empty_gz.repeat(32);
        gz_data.extend_from_slice(&bad_gz);

        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        bz.write_all(b"").unwrap();
        let empty_bz = bz.finish().unwrap();
        let mut bz_data = empty_bz.repeat(32);
        bz_data.extend_from_slice(b"BZh9broken-block");
        bz_data.extend_from_slice(&empty_bz);

        let empty_zs = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0];
        let mut zs_data = empty_zs.repeat(32);
        zs_data.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 9, 72, 0, 0]);
        zs_data.extend_from_slice(&empty_zs); // raw block containing a real frame
        zs_data.extend_from_slice(&[7, 0, 0]); // reserved next block type

        // The outer frame skips all inner heads, but visits the bad suffix.
        // The first inner walk must join that evidence and publish its own
        // heads, otherwise all later inner candidates rewalk the same tail.
        let payload = empty_zs.repeat(32);
        let mut zs_join = vec![0x28, 0xb5, 0x2f, 0xfd, 0x60];
        zs_join.extend_from_slice(&((payload.len() - 256) as u16).to_le_bytes());
        let block = ((payload.len() as u32) << 3) | 1;
        zs_join.extend_from_slice(&block.to_le_bytes()[..3]);
        zs_join.extend_from_slice(&payload);
        zs_join.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 7, 0, 0]);

        let mut inner_tar = Vec::new();
        append_tar_member(&mut inner_tar, "inner", b"payload");
        inner_tar.extend_from_slice(&[0; 1024]);
        let mut tar_data = Vec::new();
        for _ in 0..32 {
            append_tar_member(&mut tar_data, "prefix", b"");
        }
        append_tar_member(&mut tar_data, "outer", &inner_tar);

        for (kind, data, expected_count) in [
            ("gzip", gz_data, 1),
            ("bzip2", bz_data, 1),
            ("zstd", zs_data, 1),
            ("tar", tar_data, 1),
            ("zstd", zs_join, 0),
        ] {
            let mut hits = scan_sample(&data, 0, 0);
            hits.retain(|hit| hit.kind() == kind);
            hits.sort_unstable_by_key(|hit| hit.offset());
            let reference = ManagedReader::from_bytes(data.clone(), ReaderConfig::default());
            let mut expected = Vec::new();
            for hit in &hits {
                if let Some(candidate) = validate_candidate(
                    &reference,
                    reference.len(),
                    kind,
                    hit.offset(),
                    &mut Default::default(),
                )
                .unwrap()
                {
                    expected.push(candidate);
                }
            }
            assert_eq!(expected.len(), expected_count, "{kind}");
            let source = ManagedReader::from_bytes(
                data.clone(),
                ReaderConfig {
                    max_read_bytes: Some((data.len() as u64 * 3).max(8192)),
                    ..Default::default()
                },
            );
            assert_eq!(
                validate_raw_hits(&source, source.len(), &hits, &[])
                    .unwrap_or_else(|error| panic!("{kind}: {error}")),
                expected,
                "{kind}"
            );
            let source = ManagedReader::from_bytes(
                data,
                ReaderConfig {
                    max_read_bytes: Some(1),
                    ..Default::default()
                },
            );
            assert!(
                validate_raw_hits(&source, source.len(), &hits, &[]).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn failed_suffixes_do_not_share_accumulated_zstd_block_limits() {
        use crate::io::reader::ReaderConfig;
        // Each frame is within the real production limit. The concatenation
        // exceeds it, but its second root must still survive.
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 0];
        frame.extend(std::iter::repeat([0, 0, 0]).take(500_000).flatten());
        frame.extend_from_slice(&[1, 0, 0]);
        let second = frame.len() as u64;
        let source = ManagedReader::from_bytes(frame.repeat(2), ReaderConfig::default());
        let hits = [0, second].map(|offset| RawHit::new(offset, 8));
        let candidates = validate_raw_hits(&source, source.len(), &hits, &[]).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            (candidates[0].offset, candidates[0].end_offset),
            (second, Some(source.len()))
        );
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
    fn keeps_crc_valid_truncated_7z_unresolved_and_unextractable() {
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
        assert_eq!(seven.boundary_kind, "unresolved");
        assert!(!seven.extractable);
        assert_eq!(
            seven.validation,
            "start_header_crc_truncated_declared_range"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn exact_7z_range_suppresses_valid_inner_stream_before_validation() {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(b"inner payload").unwrap();
        let inner = gzip.finish().unwrap();
        let next_header = b"\x01";

        let mut start_header = Vec::new();
        start_header.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        start_header.extend_from_slice(&(next_header.len() as u64).to_le_bytes());
        start_header.extend_from_slice(&crc32(next_header).to_le_bytes());

        let mut data = b"carrier-prefix".to_vec();
        let start = data.len() as u64;
        data.extend_from_slice(SEVEN_ZIP);
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(&crc32(&start_header).to_le_bytes());
        data.extend_from_slice(&start_header);
        data.extend_from_slice(&inner);
        data.extend_from_slice(next_header);
        let end = data.len() as u64;
        let path = temp_file("embedded_7z_owns_inner_stream", &data);

        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let logical = result
            .candidates
            .iter()
            .filter(|candidate| candidate.candidate_kind == "logical_archive")
            .collect::<Vec<_>>();

        assert_eq!(logical.len(), 1);
        assert_eq!(logical[0].format, "7z");
        assert_eq!(logical[0].offset, start);
        assert_eq!(logical[0].end_offset, Some(end));
        assert!(!result
            .candidates
            .iter()
            .any(|candidate| candidate.format == "gzip"));
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
        assert_eq!(zip.validation, "zip64_eocd_geometry_and_first_local_link");
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
                    assert!(signature_overlaps()[left_index].contains(&(right_index, overlap)));
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
        // The previous valid-stream check cannot catch noisy storage retention
        // or filtering that hides a real peer after dense rejected headers.
        let mut noise = Vec::new();
        for pattern in [2, 5, 6, 7, 10] {
            let magic = PATTERNS[pattern].0;
            let mut header = [0xff; 32];
            header[..magic.len()].copy_from_slice(magic);
            noise.extend_from_slice(&header);
        }
        // Also exercise a plausible fixed header rejected by the full walk.
        noise.extend_from_slice(b"BZh9broken-block");
        let mut data = noise.repeat(512);
        let mut bzip = BzEncoder::new(Vec::new(), BzCompression::fast());
        bzip.write_all(b"bzip payload").unwrap();
        data.extend_from_slice(&bzip.finish().unwrap());
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(b"xz payload").unwrap();
        data.extend_from_slice(&xz.finish().unwrap());
        data.extend_from_slice(&zstd::stream::encode_all(&b"zstd payload"[..], 1).unwrap());
        let path = temp_file("embedded_streams", &data);
        let scan = scan_embedded_archives_native_with_iocp(
            ManagedReader::open(&path).unwrap(),
            TEST_IOCP_CHUNK_SIZE,
            4,
            4,
        )
        .unwrap();
        assert!(scan.raw_hit_count > 2000);
        assert!(scan.raw_hits.len() <= scan.candidates.len());
        Python::initialize();
        Python::attach(|py| {
            let result = scan.to_py_dict(py).unwrap();
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
        let candidate = validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
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
        assert!(
            validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zstd_zero_length_rle_still_requires_its_content_byte() {
        let data = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x03, 0x00, 0x00];
        let path = temp_file("embedded_zstd_empty_rle", &data);
        let reader = ManagedReader::open(&path).unwrap();
        assert!(
            validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
                .unwrap()
                .is_none()
        );
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
        let mut expected = reference_raw_hits(&data);
        expected.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        let mut output = iocp::scan_file(
            &path,
            data.len() as u64,
            TEST_IOCP_CHUNK_SIZE,
            4,
            4,
            embedded_overlap(),
            scan_sample_batch,
        )
        .unwrap();
        output
            .results
            .sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        assert_eq!(output.results, expected);
        let _ = fs::remove_file(path);
    }
}
