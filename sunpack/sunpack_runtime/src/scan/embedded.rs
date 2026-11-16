use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_reader_at_offset, upgrade_relation_rar_end_reader, VolumeAnchor, FIRST,
    SEVEN_ZIP_CARRIER_INTERRUPTED, ZIP_CARRIER_CHECKED, ZIP_LOCAL_HEADER, ZIP_SPLIT_START,
    ZIP_TAIL_CHECKED,
};
#[cfg(windows)]
use crate::io::iocp;
use crate::io::reader::{CachedBytes, ManagedReader};
use crate::io::ScanBatch;
use crate::scan::compression_stream::{
    bzip2_header_block_limit, bzip2_prefix_valid, gzip_fixed_header_flags, parse_xz_footer,
    resolve_xz_stream_start, validate_bzip2_structure, validate_gzip_structure,
    validate_xz_header, validate_zstd_structure, ValidationError, ValidationResult,
};
use aho_corasick::{packed, AhoCorasick};
use crc32fast::hash as crc32;
use memchr::memmem;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::sync::OnceLock;

use rayon::prelude::*;

#[path = "hit_storage.rs"]
mod hit_storage;
use hit_storage::{Builder as HitBuilder, HitBuffer, HitView};

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
// Discovery shares one byte budget over all file producers, independent of
// root count. Account for both read slots and outstanding matching jobs.
const DISCOVERY_IOCP_BYTE_BUDGET: usize = 4 * 1024 * 1024;
const MAX_DISCOVERY_IOCP_CHUNK_SIZE: usize = 512 * 1024;
const DEFAULT_IOCP_BUFFERS: usize = 2;
const DEFAULT_IOCP_WORKERS: usize = 4;
#[cfg(test)]
const TEST_IOCP_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateKind {
    Archive,
    Anchor,
    SplitZipLocal,
    EncryptedRar,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EmbeddedCandidate {
    pub(crate) format: &'static str,
    pub(crate) offset: u64,
    pub(crate) end_offset: Option<u64>,
    pub(crate) zip_eocd_offset: Option<u64>,
    pub(crate) volume_anchor: Option<Box<VolumeAnchor>>,
    kind: CandidateKind,
}

impl EmbeddedCandidate {
    pub(crate) fn is_logical_archive(&self) -> bool {
        matches!(self.kind, CandidateKind::Archive | CandidateKind::EncryptedRar)
    }

    pub(crate) fn password_required(&self) -> bool {
        self.kind == CandidateKind::EncryptedRar
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
struct RawHit {
    // Decoded hits use absolute offsets. Transient scan batches use four-byte
    // records before immutable block encoding.
    location: [u8; 8],
    pattern: u8,
}

const HIT_OFFSET_BITS: u32 = 28;
const HIT_OFFSET_MASK: u64 = (1 << HIT_OFFSET_BITS) - 1;
// TAR's root may precede its ustar marker by 257 bytes. Keep that lookbehind
// and the scan overlap representable without narrowing absolute u64 offsets.
const HIT_LOOKBEHIND: u64 = 257;
const _: () = assert!(PATTERNS.len() < 16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct PackedHit([u8; 4]);

impl PackedHit {
    fn new(relative: u32, pattern: u8) -> Self {
        debug_assert!(relative as u64 <= HIT_OFFSET_MASK && pattern < 16);
        Self(((relative << 4) | pattern as u32).to_ne_bytes())
    }

    fn unpack(self, base: u64) -> RawHit {
        let value = u32::from_ne_bytes(self.0);
        RawHit::new(base + (value >> 4) as u64, (value & 15) as u8)
    }

    fn key(self) -> (u32, &'static str) {
        let value = u32::from_ne_bytes(self.0);
        (value >> 4, self.unpack(0).hit_name())
    }
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
}

#[derive(Default)]
pub(crate) struct NativeScanResult {
    file_size: u64,
    candidates: Vec<EmbeddedCandidate>,
    #[cfg(test)]
    raw_hit_count: usize,
    zip_eocd_absent: bool,
}

pub(crate) struct RarInputResolution {
    pub end_offset: Option<u64>,
    pub password: Option<std::sync::Arc<str>>,
    pub failure_reason: Option<&'static str>,
}

pub(crate) struct ResolvedEmbeddedScan {
    pub(crate) scan: std::sync::Arc<NativeScanResult>,
    pub(crate) resolutions: HashMap<u64, RarInputResolution>,
}

impl NativeScanResult {
    /// A physical source may contain several independent volume inputs. ZIP
    /// local records without a volume proof still nominate only one hypothesis.
    pub(crate) fn relation_anchors(&self) -> Vec<VolumeAnchor> {
        let mut zip_hypothesis = false;
        // Candidates are in physical order. Advance one shared boundary cursor
        // instead of rescanning every candidate for each logical volume head.
        let mut boundaries = self
            .candidates
            .iter()
            .filter(|c| c.end_offset.is_some() || c.volume_anchor.is_some())
            .peekable();
        self.candidates
            .iter()
            .filter_map(|first| {
                let split = first.kind == CandidateKind::SplitZipLocal;
                if first.volume_anchor.is_none() {
                    if first.format != "zip"
                        || first.end_offset.is_some()
                        || (zip_hypothesis && !split)
                    {
                        return None;
                    }
                    zip_hypothesis = true;
                } else if first.format == "zip" {
                    zip_hypothesis = true;
                }
                let mut anchor =
                    first
                        .volume_anchor
                        .as_deref()
                        .cloned()
                        .unwrap_or_else(|| VolumeAnchor {
                            size: self.file_size,
                            format: "zip",
                            strong: split,
                            multivolume: split,
                            continuation_to_next: split,
                            internal_volume_number: split.then_some(1),
                            structure_offset: Some(first.offset),
                            flags: ZIP_LOCAL_HEADER | if split { FIRST | ZIP_SPLIT_START } else { 0 },
                            ..VolumeAnchor::default()
                        });
                while boundaries.peek().is_some_and(|c| c.offset <= first.offset) {
                    boundaries.next();
                }
                anchor.carrier_limit = boundaries.peek().map(|c| c.offset);
                // The full physical signature pass includes split EOCDs too.
                // Keep only this negative byte fact, not a second hit index.
                if anchor.format == "zip" && self.zip_eocd_absent {
                    anchor.flags |= ZIP_TAIL_CHECKED | ZIP_CARRIER_CHECKED;
                }
                Some(anchor)
            })
            .collect()
    }

    pub(crate) fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    pub(crate) fn has_independent_archive(&self) -> bool {
        self.candidates
            .iter()
            .any(|c| c.volume_anchor.is_none() && c.end_offset.is_some())
    }

    pub(crate) fn is_primary_lz4(&self) -> bool {
        !self
            .candidates
            .iter()
            .any(EmbeddedCandidate::is_logical_archive)
            || (self.candidates.len() == 1
                && self.candidates[0].format == "lz4"
                && self.candidates[0].offset == 0
                && (self.candidates[0].end_offset == Some(self.file_size)
                    || self.candidates[0].end_offset.is_none()))
    }

    pub(crate) fn primary_analysis(&self) -> Option<crate::io::archive_state::AnalysisFacts> {
        let candidate = self.candidates.first().filter(|item| item.format == "lz4")?;
        Some(crate::io::archive_state::AnalysisFacts {
            structure_complete: candidate.end_offset.is_some(),
            ..Default::default()
        })
    }

    pub(crate) fn candidates(&self) -> &[EmbeddedCandidate] {
        &self.candidates
    }

    pub(crate) fn file_size(&self) -> u64 {
        self.file_size
    }
}

pub(crate) fn scan_embedded_path(
    path: &str,
    parallel_files: usize,
) -> io::Result<NativeScanResult> {
    let reader = ManagedReader::open(path)?;
    let parallel_files = parallel_files.clamp(1, 8);
    let workers = (DEFAULT_IOCP_WORKERS / parallel_files).max(1);
    // scan_file owns buffer_count read slots and buffer_count + workers jobs.
    let slots = 2 * DEFAULT_IOCP_BUFFERS + workers;
    let chunk_bytes = if parallel_files == 1 {
        MAX_DISCOVERY_IOCP_CHUNK_SIZE
    } else {
        // Reserve room for the additional producers' readers and validators.
        DISCOVERY_IOCP_BYTE_BUDGET / (parallel_files * slots)
    };
    scan_embedded_archives_native_with_iocp(reader, chunk_bytes, DEFAULT_IOCP_BUFFERS, workers)
}

pub(crate) fn scan_detected_lz4(path: &str, parallel_files: usize) -> io::Result<NativeScanResult> {
    let reader = ManagedReader::open(path)?;
    let file_size = reader.len();
    let index = crate::formats::lz4::walk(&reader.probe_reader(), 0, file_size);
    if index.complete && index.end == file_size {
        return Ok(NativeScanResult {
            file_size,
            candidates: vec![candidate("lz4", 0, Some(file_size), CandidateKind::Archive)],
            ..NativeScanResult::default()
        });
    }
    scan_embedded_archives_native_with_iocp(
        reader,
        DEFAULT_IOCP_CHUNK_SIZE / parallel_files.max(1),
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
    )
}

/// Scan one physical byte stream once for every supported embedded format.
///
/// Raw signatures are never returned directly: each hit must pass the format's
/// structural header checks. The scan deliberately has no hit or byte budget;
/// callers select which files receive this reliable pass before invoking it.
#[cfg(test)]
fn scan_embedded_archives(path: &str) -> io::Result<NativeScanResult> {
    let reader = ManagedReader::open(path)?;
    scan_embedded_archives_with_reader(
        &reader,
        DEFAULT_IOCP_CHUNK_SIZE,
        DEFAULT_IOCP_BUFFERS,
        DEFAULT_IOCP_WORKERS,
    )
}

#[cfg(test)]
fn scan_embedded_archives_with_reader(
    reader: &ManagedReader,
    iocp_chunk_bytes: usize,
    iocp_buffers: usize,
    iocp_workers: usize,
) -> io::Result<NativeScanResult> {
    let cancellation = crate::io::cancellation::Cancellation::current();
    cancellation.check()?;
    let reader = reader.clone();
    let scan = (move || {
        scan_embedded_archives_native_with_iocp(
            reader,
            iocp_chunk_bytes,
            iocp_buffers,
            iocp_workers,
        )
    })();
    cancellation.check()?;
    scan
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
    let cancellation = crate::io::cancellation::Cancellation::current();
    cancellation.check_io()?;
    let file_size = reader.len();
    let chunk_bytes = iocp_chunk_bytes
        .min((HIT_OFFSET_MASK - HIT_LOOKBEHIND) as usize - embedded_overlap())
        .max(64 * 1024);
    let matching_window = if file_size <= chunk_bytes as u64 {
        1
    } else {
        iocp_buffers.clamp(2, 64) + iocp_workers.clamp(1, 8)
    };
    #[cfg(all(test, windows))]
    let capture = benchmark_capture::Capture::open(file_size, chunk_bytes, matching_window)?;
    let mut builder = HitBuilder::new(file_size, chunk_bytes, matching_window)?;
    #[cfg(test)]
    let mut raw_hit_count = 0;
    let mut collect = |batch: Option<hit_storage::Prepared>| -> io::Result<()> {
        let Some(batch) = batch else {
            return Ok(());
        };
        #[cfg(test)]
        {
            raw_hit_count += batch.raw_count;
        }
        builder.push(batch)
    };
    let saw_zip_eocd = std::sync::atomic::AtomicBool::new(false);
    let scan = |sample: &[u8], carry: usize, base: u64| {
        let batch = scan_sample_batch(sample, carry, base);
        #[cfg(all(test, windows))]
        if let Some(capture) = &capture {
            capture.record(&batch.results, base + carry as u64);
        }
        if batch.results.saw_zip_eocd {
            saw_zip_eocd.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        ScanBatch {
            results: (!batch.results.is_empty()).then(|| {
                hit_storage::prepare(batch.results, base + sample.len() as u64 == file_size)
            }),
            #[cfg(test)]
            discarded_results: batch.discarded_results,
        }
    };
    let _output = {
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
                let hits = scan(data.as_slice(), 0, 0);
                collect(hits.results)?;
                iocp::IocpScanOutput {
                    #[cfg(test)]
                    discarded_results: hits.discarded_results,
                    #[cfg(test)]
                    read_operations: u64::from(file_size != 0),
                }
            } else {
                iocp::scan_file(
                    path,
                    file_size,
                    chunk_bytes,
                    iocp_buffers,
                    iocp_workers,
                    embedded_overlap(),
                    |sample, carry, base| {
                        let batch = scan(sample, carry, base);
                        ScanBatch {
                            // Empty read jobs send only a pointer-sized None.
                            // Keep encoded metadata off the IOCP channel's hot
                            // path; the box lives only until this completion.
                            results: batch.results.map(Box::new),
                            #[cfg(test)]
                            discarded_results: batch.discarded_results,
                        }
                    },
                    |batch| collect(batch.map(|batch| *batch)),
                )?
            };
            output
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
    #[cfg(all(test, windows))]
    if let Some(capture) = capture {
        capture.finish()?;
    }
    let storage = builder.finish()?;
    cancellation.check_io()?;
    let raw_hits = storage.view(0);
    let xz_footer_hits = storage.view(1);
    #[cfg(test)]
    {
        raw_hit_count += _output.discarded_results;
    }

    // Structural facts survive in the result; transient validation windows
    // share this reader's generation/request state, not the global block cache.
    let probe_reader = reader.probe_reader();
    let mut candidates = validate_raw_hits(&probe_reader, file_size, raw_hits, xz_footer_hits)?;
    candidates.sort_by_key(|candidate| {
        (
            candidate.offset,
            candidate.format,
            std::cmp::Reverse(candidate_rank(candidate)),
        )
    });
    candidates.dedup_by_key(|candidate| (candidate.offset, candidate.format));
    // A large sibling can make a split 7z's declared length fit the carrier.
    // Retain that failed NextHeader proposal only with independent evidence
    // that another archive interrupts its declared range. No second probe.
    if candidates.iter().any(|c| {
        c.format == "7z"
            && c.volume_anchor.is_some()
            && c.volume_anchor
                .as_ref()
                .and_then(|a| a.expected_logical_size)
                .is_some_and(|end| end <= file_size)
    }) {
        let exact: Vec<_> = candidates
            .iter()
            .filter(|c| c.end_offset.is_some() && c.volume_anchor.is_none())
            .map(|c| c.offset)
            .collect();
        candidates.retain(|c| {
            let Some(anchor) = c.volume_anchor.as_ref().filter(|a| a.format == "7z") else {
                return true;
            };
            let Some(end) = anchor.expected_logical_size.filter(|end| *end <= file_size) else {
                return true;
            };
            exact
                .get(exact.partition_point(|start| *start <= c.offset))
                .is_some_and(|start| *start < end)
        });
    }
    resolve_logical_candidates(&mut candidates);
    cancellation.check_io()?;
    Ok(NativeScanResult {
        file_size,
        candidates,
        #[cfg(test)]
        raw_hit_count,
        zip_eocd_absent: !saw_zip_eocd.load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[cfg(all(test, windows))]
#[path = "../../../../benchmarks/native/hit_index/capture.rs"]
mod benchmark_capture;

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
    raw_hits: HitView<'_>,
    xz_footer_hits: HitView<'_>,
) -> io::Result<Vec<EmbeddedCandidate>> {
    let cancellation = crate::io::cancellation::Cancellation::current();
    let mut suffixes: [FailedSuffixEvidence; 5] = std::array::from_fn(|_| Default::default());
    let mut xz_footers = XzFooterEvidence {
        ends: xz_footer_hits,
        next_unchecked: 0,
        valid: BTreeMap::new(),
    };
    // ZIP64 records were found in the same full-stream pass. Index each once
    // by its declared physical end; fake locators never trigger reverse scans.
    let mut zip64_records = BTreeMap::new();
    let use_windows = raw_hits.len() + xz_footer_hits.len() >= 128;
    let mut windowed = None;
    for hit in raw_hits.iter_mask(1 << 12) {
        let reader: &ManagedReader = if use_windows {
            windowed.get_or_insert_with(|| reader.windowed_probe_reader())
        } else {
            reader
        };
        reader.hint_probe_window(hit.offset());
        let fixed = read_at(reader, hit.offset(), 56)?;
        if let Some(record) = crate::formats::zip::zip64::parse_record(&fixed) {
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
        .par_iter_mask(1 << 1)
        .map_init(DirectoryEvidence::default, |directories, hit| {
            cancellation.run(|| {
                validate_zip_eocd(reader, file_size, hit.offset(), &zip64_records, directories)
            })
        })
        .try_fold(Vec::new, |mut candidates, candidate| -> io::Result<_> {
            if let Some(candidate) = candidate? {
                candidates.push(candidate);
            }
            Ok(candidates)
        })
        .try_reduce(Vec::new, |mut left, mut right| {
            left.append(&mut right);
            Ok(left)
        })?;

    // ZIP EOCD geometry can prove a logical root before its local-header hit is
    // visited. Seed exact ownership with those ranges, then process every other
    // hit in physical order. Once a resolver proves [start,end), signatures
    // inside that interval cannot add a peer carrier boundary and are skipped
    // before invoking any potentially size-proportional parser.
    let mut seeded_ranges = candidates
        .iter()
        .filter_map(|candidate| candidate.end_offset.map(|end| (candidate.offset, end)))
        .collect::<Vec<_>>();
    seeded_ranges.sort_unstable();

    let mut range_index = 0usize;
    let mut covered_until = 0u64;
    let mut previous_xz: Option<usize> = None;
    let mut cursor = raw_hits.iter_mask(!((1 << 1) | (1 << 12)));
    while let Some(hit) = cursor.next() {
        cancellation.check_io()?;
        while range_index < seeded_ranges.len() && seeded_ranges[range_index].0 <= hit.offset() {
            covered_until = covered_until.max(seeded_ranges[range_index].1);
            range_index += 1;
        }
        if hit.offset() < covered_until {
            cursor.seek_ge(covered_until);
            continue;
        }

        // EOCD ownership already skipped ordinary ZIP interiors. Only actual
        // remaining probes pay for a scan-local window source; the common
        // reader/cursor layout and directory fast path stay unchanged.
        let reader: &ManagedReader = if use_windows {
            windowed.get_or_insert_with(|| reader.windowed_probe_reader())
        } else {
            reader
        };
        reader.hint_probe_window(hit.offset());
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
            covered_until = covered_until.max(end);
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
    match (candidate.is_logical_archive(), candidate.end_offset.is_some()) {
        (true, true) => 3,
        (true, false) => 2,
        _ => 1,
    }
}

fn resolve_logical_candidates(candidates: &mut Vec<EmbeddedCandidate>) {
    retain_outer_ranges(candidates, |item| {
        (
            item.offset,
            if item.is_logical_archive() {
                item.end_offset.unwrap_or(item.offset)
            } else {
                item.offset
            },
        )
    });
}

/// Reuse the canonical physical ownership rule for already analyzed ranges.
/// The caller orders by start; a proven outer archive owns inner signatures.
pub(crate) fn retain_outer_ranges<T>(items: &mut Vec<T>, range: impl Fn(&T) -> (u64, u64)) {
    let mut group_start = None;
    let mut covered_until = 0;
    let mut group_end = 0;
    items.retain(|item| {
        let (start, end) = range(item);
        if group_start != Some(start) {
            covered_until = covered_until.max(group_end);
            group_start = Some(start);
            group_end = 0;
        }
        // Suppressed ranges still contribute to coverage, as in the scanner.
        group_end = group_end.max(end);
        start >= covered_until
    });
}

#[cfg(test)]
fn scan_sample(sample: &[u8], carry_len: usize, base_offset: u64) -> Vec<RawHit> {
    scan_sample_batch(sample, carry_len, base_offset)
        .results
        .iter()
        .collect()
}

fn new_hit_batch(base_offset: u64, carry_len: usize, len: usize) -> ScanBatch<HitBuffer> {
    ScanBatch {
        results: HitBuffer::new(
            base_offset.saturating_sub(HIT_LOOKBEHIND),
            base_offset + carry_len as u64,
            base_offset + len as u64,
            embedded_overlap(),
        ),
        #[cfg(test)]
        discarded_results: 0,
    }
}

fn scan_sample_batch(sample: &[u8], carry_len: usize, base_offset: u64) -> ScanBatch<HitBuffer> {
    debug_assert!(sample.len() as u64 + HIT_LOOKBEHIND <= HIT_OFFSET_MASK);
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

fn scan_sample_packed(sample: &[u8], carry_len: usize, base_offset: u64) -> ScanBatch<HitBuffer> {
    let mut hits = new_hit_batch(base_offset, carry_len, sample.len());
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
unsafe fn scan_sample_avx2(
    sample: &[u8],
    carry_len: usize,
    base_offset: u64,
) -> ScanBatch<HitBuffer> {
    use std::arch::x86_64::*;

    let tables = SIMD_PREFIX_TABLES;
    let mut hits = new_hit_batch(base_offset, carry_len, sample.len());
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
        let prefix_matches = _mm256_and_si256(first_bits, second_bits);
        let footer_matches = _mm256_and_si256(
            _mm256_cmpeq_epi8(first, footer_first),
            _mm256_cmpeq_epi8(second, footer_second),
        );
        // Most blocks contain no two-byte prefix at all. Avoid the third
        // unaligned load and both table shuffles on that common path. Dense
        // rejected prefixes still use the same three-byte filter below.
        let possible = _mm256_or_si256(prefix_matches, footer_matches);
        if _mm256_testz_si256(possible, possible) != 0 {
            start += 32;
            continue;
        }
        let third = _mm256_loadu_si256(sample.as_ptr().add(start + 2).cast());
        let third_bits = _mm256_and_si256(
            _mm256_shuffle_epi8(low_third, _mm256_and_si256(third, nibble_mask)),
            _mm256_shuffle_epi8(
                high_third,
                _mm256_and_si256(_mm256_srli_epi16(third, 4), nibble_mask),
            ),
        );
        let header_matches = _mm256_and_si256(prefix_matches, third_bits);
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
    hits: &mut ScanBatch<HitBuffer>,
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
    hits: &mut ScanBatch<HitBuffer>,
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
    hits: &mut ScanBatch<HitBuffer>,
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
    // Standalone validation rejects multi-disk EOCDs below. Their presence
    // must still prevent a negative Relations terminal proof.
    if pattern == 1 {
        hits.results.saw_zip_eocd = true;
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
        #[cfg(test)]
        {
            hits.discarded_results += 1;
        }
        return;
    }
    if kind == "tar" && start >= 257 {
        if sample
            .get(start - 257..start - 257 + 512)
            .is_some_and(|header| !crate::formats::tar::valid_header(header))
        {
            #[cfg(test)]
            {
                hits.discarded_results += 1;
            }
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
        "rar4" | "rar5" => validate_rar(file, file_size, offset),
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
            let Some(index) = suffixes.validate(offset, true, |visit| {
                let index =
                    crate::formats::lz4::walk_observed(file, offset, file_size, &mut |node| {
                        visit(node).map_err(|_| "known_failed_suffix")
                    });
                if index.complete {
                    Ok(index)
                } else {
                    Err(ValidationError::Invalid(index.error))
                }
            })? else {
                return Ok(None);
            };
            if index.frames == 0 {
                return Ok(None);
            }
            Ok(Some(candidate(
                "lz4",
                offset,
                Some(index.end),
                CandidateKind::Archive,
            )))
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
                path.try_reserve(1)
                    .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
                path.push(cursor);
                source.seek_relative((next - cursor - 46) as i64)?;
                cursor = next;
            };
            let first_new = self.suffixes.len();
            self.suffixes
                .try_reserve(path.len())
                .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
            for start in path.into_iter().rev() {
                suffix = DirectorySuffix {
                    start,
                    end: suffix.end,
                    entries: suffix.entries + 1,
                };
                self.suffixes.push(suffix);
            }
            // A walk appends nodes in reverse physical order. Existing nodes
            // are disjoint from the newly visited path. Consecutive ZIPs in a
            // carrier usually append after the preceding directories.
            self.suffixes[first_new..].reverse();
            if first_new != 0
                && self.suffixes.get(first_new).is_some_and(|first| {
                    first.start < self.suffixes[first_new - 1].start
                })
            {
                self.suffixes.sort_unstable_by_key(|item| item.start);
            }
            suffix
        };
        if observed.entries != entries || observed.end > end {
            return Ok(false);
        }
        crate::formats::zip::central_directory_complete(observed.end, end, |offset, length| {
            read_at(file, offset, length)
        })
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
    // Even an empty central-directory entry occupies 46 bytes.
    if entries_total > cd_size / 46 {
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
    let mut resolved = candidate("zip", archive_offset, Some(end), CandidateKind::Archive);
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
    let locator_fields = crate::formats::zip::zip64::parse_locator(&locator)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let recorded_record_offset = locator_fields.record_offset;
    let disk_count = locator_fields.total_disks;
    if locator_fields.record_disk != 0 || disk_count != 1 || eocd_offset < 32 {
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
    }
    let Some(_data_end) = header_end.checked_add(compressed_size) else {
        return Ok(None);
    };
    let split = offset >= 4 && read_at(file, offset - 4, 4)?.as_slice() == b"PK\x07\x08";
    let root = if split { offset - 4 } else { offset };
    Ok(Some(candidate(
        "zip",
        root,
        None,
        if split {
            CandidateKind::SplitZipLocal
        } else {
            CandidateKind::Anchor
        },
    )))
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
    if end <= size {
        if let Some(complete) = validate_seven_zip_next(file, offset, next_start, end, &header)? {
            return Ok(Some(complete));
        }
    }
    if next_size > 0 {
        let mut item = candidate("7z", offset, None, CandidateKind::Archive);
        let next = crate::formats::seven_zip::RelationNextHeader::parse(&header).unwrap();
        item.volume_anchor = Some(Box::new(VolumeAnchor {
            size,
            format: "7z",
            strong: true,
            multivolume: true,
            internal_volume_number: Some(1),
            structure_offset: Some(offset),
            expected_logical_size: Some(end),
            seven_zip_next_header: Some(std::sync::Arc::new(next)),
            continuation_to_next: true,
            flags: FIRST | if end <= size { SEVEN_ZIP_CARRIER_INTERRUPTED } else { 0 },
            ..VolumeAnchor::default()
        }));
        return Ok(Some(item));
    }
    Ok(None)
}

fn validate_seven_zip_next(
    file: &ManagedReader,
    offset: u64,
    next_start: u64,
    end: u64,
    header: &[u8],
) -> io::Result<Option<EmbeddedCandidate>> {
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
        CandidateKind::Archive,
    )))
}

fn seven_zip_start_header_valid(header: &[u8]) -> bool {
    header.len() >= 32
        && header.starts_with(SEVEN_ZIP)
        && header[6] == 0
        && crc32(&header[12..32]) == u32::from_le_bytes(header[8..12].try_into().unwrap())
}

fn validate_rar(
    file: &ManagedReader,
    _size: u64,
    offset: u64,
) -> io::Result<Option<EmbeddedCandidate>> {
    let anchor = probe_volume_anchor_reader_at_offset(file, "", offset, "rar")?;
    if anchor.format != "rar" || !anchor.error.is_empty() {
        return Ok(None);
    }
    let anchor = upgrade_relation_rar_end_reader(&anchor, file)?;
    if !anchor.error.is_empty() {
        return Ok(None);
    }
    let kind = if anchor.needs_password {
        CandidateKind::EncryptedRar
    } else {
        CandidateKind::Archive
    };
    let end = anchor.expected_logical_size;
    if end.is_none() && !anchor.multivolume && !anchor.needs_password {
        return Ok(None);
    }
    let mut item = candidate("rar", offset, end, kind);
    if anchor.multivolume || (anchor.needs_password && !anchor.standalone) {
        item.volume_anchor = Some(Box::new(anchor));
    }
    Ok(Some(item))
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
                    "decoded_size_overflow"
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
    let Some(end) = suffixes.validate(offset, true, |visit| {
        validate_gzip_structure(file, offset, size, visit)
    })?
    else {
        return Ok(None);
    };
    Ok(Some(candidate(
        "gzip",
        offset,
        Some(end),
        CandidateKind::Archive,
    )))
}

fn validate_bzip2(
    file: &ManagedReader,
    size: u64,
    offset: u64,
    suffixes: &mut FailedSuffixEvidence,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let Some(end) = suffixes.validate(offset, true, |visit| {
        validate_bzip2_structure(file, offset, size, visit)
    })?
    else {
        return Ok(None);
    };
    Ok(Some(candidate(
        "bzip2",
        offset,
        Some(end),
        CandidateKind::Archive,
    )))
}

// One physical-order analysis owns these facts. Invalid footers and indexes
// are discarded by advancing the cursor; only proven future roots are retained.
// Nothing survives this scan. Read lazily to preserve the existing I/O order.
struct XzFooterEvidence<'a> {
    ends: HitView<'a>,
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
        .max(footers.ends.lower_bound(offset + 22));
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
                CandidateKind::Archive,
            )));
        }
        let Some(hit) = footers.ends.get(footers.next_unchecked) else {
            return Ok(None);
        };
        let end = hit.offset() + 2;
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
    let Some(end) = suffixes.validate(offset, true, |visit| {
        validate_zstd_structure(file, offset, size, visit)
    })?
    else {
        return Ok(None);
    };
    Ok(Some(candidate(
        "zstd",
        offset,
        Some(end),
        CandidateKind::Archive,
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
    // PAX metadata can change the interpretation of later member sizes.
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
    let mut first_header = Some(header);
    let mut cursor = offset;
    let mut state = crate::formats::tar::TarState::default();
    loop {
        // A PAX size inherited from an earlier header cannot disprove a TAR
        // rooted at this cursor with its own fresh metadata context.
        if state.boundary_context_free() {
            visit(cursor)?;
        }
        let current = match first_header.take() {
            Some(header) => header,
            None => read_at(file, cursor, 512)?,
        };
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
                CandidateKind::Archive,
            ));
        }
        cursor = match state.advance(&current, cursor, size, &mut |start, size| {
            read_at(file, start, size)
        }) {
            Ok(next) => next,
            Err(error) => {
                return Err(match error.kind() {
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                        ValidationError::Invalid("tar_metadata_invalid")
                    }
                    _ => ValidationError::Io(error),
                })
            }
        };
    }
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
    kind: CandidateKind,
) -> EmbeddedCandidate {
    EmbeddedCandidate {
        format,
        offset,
        end_offset: end,
        zip_eocd_offset: None,
        volume_anchor: None,
        kind,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/scan/embedded/tests.rs"]
mod tests;
