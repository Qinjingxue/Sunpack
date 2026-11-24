use std::io::Read;
use std::sync::{Arc, Mutex};

use crc32fast::hash as crc32;
use memchr::memmem;

use crate::analysis_native::structure::{compression_stream_evidence, unified_prefilter_mask_from_head, StructuralStreamKind};
use crate::formats::rar::{rar4_end_volume, rar5_header_len, rar5_main_header, read_vint};
use crate::io::reader::{capture_file_generation, ManagedReader, PhysicalFileGeneration};
use crate::io::resource_lifecycle::{IdleRayonPool, NativeReadScope, TrackedFile};
use crate::password::rar::{
    rar5_archive_encryption_header, rar5_encryption_identity, Rar5EncryptionIdentity,
};
use crate::scan::compression_stream::StreamReadiness;
use crate::scan::pe_overlay::{probe_pe_prefix, PeState};
use std::borrow::Cow;

const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf'\x1c";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP_SPLIT_MARKER: &[u8] = b"PK\x07\x08";
const RAR4_MAIN_HEADER_PASSWORD: u16 = 0x0080;
const CHEAP_FAST_PROBE_THREADS: usize = 8;

pub(crate) const FIRST: u32 = 1 << 0;
pub(crate) const MEMBER: u32 = 1 << 1;
pub(crate) const TERMINAL: u32 = 1 << 2;
pub(crate) const ZIP_SPLIT_START: u32 = 1 << 3;
pub(crate) const ZIP_LOCAL_HEADER: u32 = 1 << 4;
pub(crate) const ZIP_EOCD_HEAD: u32 = 1 << 5;
pub(crate) const ZIP_SPLIT_END: u32 = 1 << 6;
pub(crate) const ZIP_SINGLE_DISK: u32 = 1 << 7;
pub(crate) const ZIP_TAIL_WITHOUT_HEAD: u32 = 1 << 8;
pub(crate) const ZIP_DIRECTORY_MEMBER: u32 = 1 << 9;
pub(crate) const RAR_OLD_NUMBERING: u32 = 1 << 10;
pub(crate) const RAR_PART_NUMBERING: u32 = 1 << 11;
pub(crate) const RAR_VERSION_5: u32 = 1 << 12;
pub(crate) const RAR_PASSWORD_MATCHED_INCOMPLETE: u32 = 1 << 13;
pub(crate) const SEVEN_ZIP_CARRIER_INTERRUPTED: u32 = 1 << 14;
pub(crate) const SEVEN_ZIP_NEXT_HEADER_CRC: u32 = 1 << 15;
pub(crate) const SFX_CHECKED: u32 = 1 << 16;
pub(crate) const RAR_END_CHECKED: u32 = 1 << 17;
pub(crate) const ZIP_TAIL_CHECKED: u32 = 1 << 18;
pub(crate) const ZIP_CARRIER_CHECKED: u32 = 1 << 19;
pub(crate) const SEVEN_ZIP_STUB: u32 = 1 << 20;
pub(crate) const WINRAR_STUB: u32 = 1 << 21;
pub(crate) const EMBEDDED_VOLUME: u32 = 1 << 22;
pub(crate) const UNRESOLVED_VOLUME: u32 = 1 << 23;
pub(crate) const ZIP_AWAITING_TAIL: u32 = 1 << 24;
// The structure of this standalone input requires bytes beyond the observed end.
pub(crate) const STANDALONE_TRUNCATED: u32 = 1 << 25;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct VolumeAnchor {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) format: &'static str,
    pub(crate) strong: bool,
    pub(crate) standalone: bool,
    pub(crate) multivolume: bool,
    pub(crate) encrypted: bool,
    pub(crate) rar5_encryption: Option<Arc<Rar5EncryptionIdentity>>,
    pub(crate) needs_password: bool,
    pub(crate) wrong_password: bool,
    pub(crate) flags: u32,
    pub(crate) internal_volume_number: Option<u32>,
    pub(crate) structure_offset: Option<u64>,
    // Physical extent, separate from the archive's declared logical length.
    pub(crate) payload_end: Option<u64>,
    // A verified sibling bounds this volume but does not locate padding.
    pub(crate) carrier_limit: Option<u64>,
    pub(crate) expected_logical_size: Option<u64>,
    pub(crate) zip_eocd_offset: Option<u64>,
    // A physical suffix already searched for a complete EOCD candidate.
    pub(crate) zip_eocd_absence: Option<Arc<ZipEocdAbsence>>,
    pub(crate) zip_directory: Option<Arc<crate::formats::zip::RelationDirectory>>,
    // A two-disk directory can locate a carrier head without an interior disk.
    pub(crate) zip_head_size: Option<u64>,
    pub(crate) seven_zip_next_header: Option<Arc<crate::formats::seven_zip::RelationNextHeader>>,
    pub(crate) continuation_from_previous: bool,
    pub(crate) continuation_to_next: bool,
    pub(crate) relation_has_next: Option<bool>,
    pub(crate) rar_next_header_offset: Option<u64>,
    // True only after Relations proves an SFX stub/archive or launcher.
    pub(crate) sfx: bool,
    pub(crate) pe_state: PeState,
    pub(crate) pe_image_end: Option<u64>,
    pub(crate) error: String,
    pub(crate) bytes_read: u64,
    pub(crate) format_reject_mask: u32,
}

#[derive(Debug, PartialEq)]
pub(crate) struct ZipEocdAbsence {
    generation: PhysicalFileGeneration,
    start: u64,
}

impl VolumeAnchor {
    pub(crate) fn has_any(&self, flags: u32) -> bool {
        self.flags & flags != 0
    }

    pub(crate) fn standalone_truncated(&self) -> bool {
        self.standalone && self.has_any(STANDALONE_TRUNCATED)
    }

    // Only the exhaustive proof can be promoted into a later inventory.
    pub(crate) fn zip_eocd_absent_generation(&self) -> Option<&PhysicalFileGeneration> {
        self.zip_eocd_absence
            .as_deref()
            .filter(|absence| absence.start == 0 && self.has_any(ZIP_CARRIER_CHECKED))
            .map(|absence| &absence.generation)
    }

    /// A missing natural end makes the existing Embedded pass useful for
    /// Relations too. Keep the backwards tail fast path for a padded ZIP.
    pub(crate) fn zip_carrier_scan_generation(&self) -> Option<&PhysicalFileGeneration> {
        use crate::formats::zip::{read_zip_local_member, EOCD_SEARCH_BYTES};

        let suffix = self.zip_eocd_absence.as_deref().filter(|suffix| suffix.start != 0)?;
        if self.structure_offset != Some(0) || !self.has_any(ZIP_LOCAL_HEADER)
            || self.has_any(ZIP_CARRIER_CHECKED | ZIP_SPLIT_START)
        {
            return None;
        }
        let reader = ManagedReader::open(&self.path).ok()?.probe_reader();
        if reader.physical_generation() != Some(&suffix.generation) {
            return None;
        }
        let mut offset = 0;
        loop {
            let fixed = reader.read_cached_at(offset, 30).ok()?;
            if offset >= suffix.start && fixed.starts_with(b"PK\x01\x02") {
                return Some(&suffix.generation);
            }
            let member = read_zip_local_member(&fixed, offset, reader.len(), |start, len| {
                reader.read_cached_at(start, len)
            }).ok()??;
            // Descriptor-based and masked sizes cannot locate the next field.
            if member.flags & 0x2008 != 0 {
                return None;
            }
            if member.data_end >= reader.len() {
                return Some(&suffix.generation);
            }
            // Avoid a seek per member on densely packed ZIPs. Their existing
            // reverse search remains cheaper than walking the local chain.
            if member.data_end - offset < EOCD_SEARCH_BYTES {
                return None;
            }
            offset = member.data_end;
        }
    }

    pub(crate) fn mark_zip_eocd_absent(&mut self, generation: PhysicalFileGeneration) {
        self.flags |= ZIP_CARRIER_CHECKED;
        self.zip_eocd_absence = Some(Arc::new(ZipEocdAbsence { generation, start: 0 }));
    }

    /// A volume set is discovered from one archive entry, never from an orphan
    /// continuation. Other volumes contribute facts only to that entry's plan.
    pub(crate) fn is_volume_entry(&self) -> bool {
        !self.standalone
            && (self.internal_volume_number == Some(1)
                || self.has_any(FIRST)
                || (self.format == "zip"
                    && (self.has_any(ZIP_LOCAL_HEADER | TERMINAL))))
    }

    pub(crate) fn has_unresolved_carrier_extent(&self) -> bool {
        self.payload_end.is_none()
            && (self.carrier_limit.is_some() || self.structure_offset.unwrap_or(0) > 0)
    }

    fn discard_zip_continuation_head(&mut self) {
        // A local member header plus EOCD does not prove a standalone ZIP.
        // Coordinates beyond this disk may refer to an earlier raw chunk.
        // Reuse the parsed directory; no additional probe or payload reads.
        if self.zip_directory.as_ref().is_some_and(|d| {
            d.disk == 0
                && d.cd_disk == 0
                && d.offset.checked_add(d.size).is_some_and(|end| end > d.end)
        }) {
            self.standalone = false;
            self.structure_offset = None;
            self.flags &= !(FIRST | ZIP_LOCAL_HEADER);
            self.flags |= ZIP_TAIL_WITHOUT_HEAD;
        }
    }

    // Only a parsed physical boundary can exclude another structure. An
    // opaque chunk's EOF is an input limit, not evidence of ownership.
    pub(crate) fn proven_extent_end(&self) -> Option<u64> {
        self.payload_end.or_else(|| {
            (self.format == "rar"
                || (self.format == "zip" && self.has_any(TERMINAL)))
            .then_some(self.expected_logical_size)
            .flatten()
            .map(|end| end.min(self.size))
        })
    }

    pub(crate) fn extent_end(&self) -> u64 {
        self.proven_extent_end().unwrap_or(self.size)
    }

    pub(crate) fn payload_size(&self) -> u64 {
        self.extent_end()
            .saturating_sub(self.structure_offset.unwrap_or(0))
    }
}

/// One password-independent fact per catalog row generation. Relations may
/// refine the cheap head with password-independent tail facts. Contention is per file,
/// never on the catalog lock; failed reads remain retryable.
pub(crate) type CheapAnchorCell = Arc<Mutex<Option<CheapAnchor>>>;

/// Ordinary heads need no duplicate path or empty structural fields. The owning
/// snapshot/catalog generation supplies path and size when Relations selects a row.
#[derive(Debug, Clone)]
pub(crate) enum CheapAnchor {
    Negative { bytes_read: u16, reject_mask: u32 },
    Full(Arc<VolumeAnchor>),
}

impl CheapAnchor {
    fn from_probe(path: &str, mut anchor: VolumeAnchor) -> Self {
        if anchor.format.is_empty()
            && anchor.pe_state == PeState::None
            && anchor.error.is_empty()
            && anchor.flags == 0
            && anchor.bytes_read <= 512
        {
            Self::Negative {
                bytes_read: anchor.bytes_read as u16,
                reject_mask: anchor.format_reject_mask,
            }
        } else {
            anchor.path = path.to_owned();
            Self::Full(Arc::new(anchor))
        }
    }

    pub(crate) fn anchor(&self) -> Option<&VolumeAnchor> {
        self.shared_anchor().map(Arc::as_ref)
    }

    pub(crate) fn shared_anchor(&self) -> Option<&Arc<VolumeAnchor>> {
        match self {
            Self::Full(anchor) => Some(anchor),
            Self::Negative { .. } => None,
        }
    }

    pub(crate) fn materialize(&self, path: &str, size: u64) -> VolumeAnchor {
        match self {
            Self::Full(anchor) => (**anchor).clone(),
            Self::Negative {
                bytes_read,
                reject_mask,
            } => VolumeAnchor {
                path: path.to_owned(),
                size,
                bytes_read: u64::from(*bytes_read),
                format_reject_mask: *reject_mask,
                ..VolumeAnchor::default()
            },
        }
    }

    pub(crate) fn reject_mask(&self) -> u32 {
        match self {
            Self::Full(anchor) => anchor.format_reject_mask,
            Self::Negative { reject_mask, .. } => *reject_mask,
        }
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        match self {
            Self::Full(anchor) => anchor.bytes_read,
            Self::Negative { bytes_read, .. } => u64::from(*bytes_read),
        }
    }

    pub(crate) fn reusable(&self) -> bool {
        self.anchor().is_none_or(|anchor| anchor.error.is_empty())
    }
}

pub(crate) fn probe_volume_anchor_record_cheap(
    path: &str,
    size: u64,
    cell: Option<&CheapAnchorCell>,
    scope: Option<&NativeReadScope>,
) -> CheapAnchor {
    let mut cached = cell.map(|cell| cell.lock().unwrap_or_else(|error| error.into_inner()));
    if let Some(anchor) = cached.as_deref().and_then(Option::as_ref) {
        return anchor.clone();
    }
    let read_len = size.min(512) as usize;
    let mut prefix = [0u8; 512];
    let read = scope
        .map_or_else(|| open_cheap_file(path), |scope| scope.open_reader(path))
        .and_then(|mut file| file.read_exact(&mut prefix[..read_len]));
    let anchor = match read {
        Ok(()) => probe_volume_anchor_from_head(path, size, &prefix[..read_len]),
        Err(error) => CheapAnchor::from_probe(
            path,
            VolumeAnchor {
                size,
                error: error.to_string(),
                ..VolumeAnchor::default()
            },
        ),
    };
    if let Some(cached) = cached.as_deref_mut().filter(|_| anchor.reusable()) {
        *cached = Some(anchor.clone());
    }
    anchor
}

pub(crate) fn probe_volume_anchor_from_head(path: &str, size: u64, head: &[u8]) -> CheapAnchor {
    let prefix_len = head.len().min(size.min(512) as usize);
    let prefix = &head[..prefix_len];
    let result = VolumeAnchor {
        size,
        bytes_read: prefix_len as u64,
        format_reject_mask: unified_prefilter_mask_from_head(size, prefix),
        ..VolumeAnchor::default()
    };
    let mut reader = None;
    CheapAnchor::from_probe(
        path,
        probe_cheap_prefix(result, prefix,
            |offset, len| {
                let reader = match &mut reader {
                    Some(reader) => reader,
                    slot => slot.insert(ManagedReader::open(path)?),
                };
                reader.read_direct_at(offset, len)
            },
        ),
    )
}

static CHEAP_PROBE_POOL: IdleRayonPool = IdleRayonPool::new();

pub(crate) fn cheap_fast_probe_pool() -> Arc<rayon::ThreadPool> {
    CHEAP_PROBE_POOL.acquire(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(CHEAP_FAST_PROBE_THREADS)
            .build()
            .ok()
    }).expect("cheap volume anchor probe pool must build")
}

pub(crate) fn clear_cheap_probe_pool() {
    CHEAP_PROBE_POOL.clear();
}

pub(crate) fn probe_volume_anchor_path_cheap(path: &str) -> VolumeAnchor {
    let mut result = VolumeAnchor {
        path: path.to_string(),
        ..VolumeAnchor::default()
    };
    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            result.error = error.to_string();
            return result;
        }
    };
    let size = reader.len();
    result.size = size;
    let prefix = match reader.read_at(0, size.min(512) as usize) {
        Ok(prefix) => prefix,
        Err(error) => {
            result.error = error.to_string();
            return result;
        }
    };
    result.bytes_read += prefix.len() as u64;
    result.format_reject_mask = unified_prefilter_mask_from_head(size, &prefix);
    probe_cheap_prefix(result, &prefix, |offset, len| reader.read_direct_at(offset, len))
}

fn probe_cheap_prefix(
    mut result: VolumeAnchor,
    prefix: &[u8],
    mut read: impl FnMut(u64, usize) -> std::io::Result<Vec<u8>>,
) -> VolumeAnchor {
    let prefix = complete_anchor_prefix(prefix, &mut result, 0, &mut read);
    let prefix = prefix.as_ref();
    // Relation is a split-volume recovery layer, not a general archive
    // detector.  The cheap pass only keeps structure that can itself seed
    // a split suspicion, plus the leading stream facts that prevent a
    // numbered ordinary archive from being mistaken for a volume.
    if anchored_signature(prefix, RAR5)
        .or_else(|| anchored_signature(prefix, RAR4))
        .is_some_and(|offset| probe_rar(prefix, offset, &mut result))
    {
        return result;
    }
    if anchored_signature(prefix, SEVEN_ZIP)
        .is_some_and(|offset| probe_seven_zip(prefix, offset, result.size, &mut result))
    {
        return result;
    }
    if probe_zip_split_marker(prefix, &mut result) {
        return result;
    }
    if probe_zip_local_head(prefix, &mut result) {
        return result;
    }
    if probe_zip_eocd_head(prefix, &mut result) {
        return result;
    }
    let pe = probe_pe_prefix(prefix, result.size);
    result.pe_state = pe.state();
    result.pe_image_end = pe.image_end();
    probe_standalone_stream(prefix, &mut result, read);
    result
}

fn open_cheap_file(path: &str) -> std::io::Result<TrackedFile> {
    // Cheap probes still use the lifecycle guard, but skip the managed reader's
    // metadata/canonicalization/handle-cache path for this one-shot read.
    TrackedFile::open_reader(path)
}

fn read_anchor_header_from(
    out: &mut VolumeAnchor,
    offset: u64,
    len: usize,
    read: impl FnOnce(u64, usize) -> std::io::Result<Vec<u8>>,
) -> Option<Vec<u8>> {
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > out.size)
    {
        out.error = "archive_header_incomplete".into();
        return None;
    }
    match read(offset, len) {
        Ok(bytes) if bytes.len() == len => {
            out.bytes_read += len as u64;
            Some(bytes)
        }
        Ok(_) => {
            out.error = "archive_header_incomplete".into();
            None
        }
        Err(error) => {
            out.error = error.to_string();
            None
        }
    }
}

/// Complete just the declared leading header. Ordinary rows borrow the 512
/// bytes supplied by the scan; long headers allocate only for this call.
fn complete_anchor_prefix<'a>(
    prefix: &'a [u8],
    out: &mut VolumeAnchor,
    base: u64,
    read: impl FnOnce(u64, usize) -> std::io::Result<Vec<u8>>,
) -> Cow<'a, [u8]> {
    let required = if let Some(at) = anchored_signature(prefix, RAR5) {
        rar5_header_len(&prefix[at + RAR5.len()..]).and_then(|n| (at + RAR5.len()).checked_add(n))
    } else if let Some(at) = anchored_signature(prefix, RAR4) {
        let main = at + RAR4.len();
        u16_le(prefix, main + 5)
            .filter(|&n| n >= 13)
            .map(|n| main + n as usize)
    } else {
        let at = if prefix.starts_with(ZIP_SPLIT_MARKER) {
            Some(4)
        } else {
            anchored_signature(prefix, ZIP_LOCAL)
        };
        at.and_then(|at| {
            crate::formats::zip::relation_local_header_len(prefix, at)
                .and_then(|len| at.checked_add(len))
        })
    };
    let Some(required) = required.filter(|&n| n > prefix.len()) else {
        return Cow::Borrowed(prefix);
    };
    let Some(offset) = base.checked_add(prefix.len() as u64) else {
        return Cow::Borrowed(prefix);
    };
    // A continuation may merely resemble another format's leading header.
    // Failed speculative completion must not exclude that opaque volume.
    let previous_error = std::mem::take(&mut out.error);
    let rest = read_anchor_header_from(out, offset, required - prefix.len(), read);
    out.error = previous_error;
    let Some(rest) = rest else {
        return Cow::Borrowed(prefix);
    };
    let mut full = Vec::with_capacity(required);
    full.extend_from_slice(prefix);
    full.extend(rest);
    Cow::Owned(full)
}

fn merge_rar_volume(out: &mut VolumeAnchor, number: Option<u32>) {
    if let Some(number) = number {
        if out.internal_volume_number.is_some_and(|old| old != number) {
            out.error = "rar_volume_identity_conflict".into();
        } else {
            out.internal_volume_number = Some(number);
        }
    }
}

fn probe_zip_split_marker(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    if !prefix.starts_with(ZIP_SPLIT_MARKER) || !plausible_zip_local(prefix, ZIP_SPLIT_MARKER.len())
    {
        return false;
    }
    out.format = "zip";
    out.strong = true;
    out.multivolume = true;
    out.continuation_to_next = true;
    out.structure_offset = Some(0);
    out.internal_volume_number = Some(1);
    out.flags |= FIRST | ZIP_SPLIT_START;
    true
}

fn probe_zip_local_head(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    if !prefix.starts_with(ZIP_LOCAL) || !plausible_zip_local(prefix, 0) {
        return false;
    }
    out.format = "zip";
    out.strong = false;
    out.structure_offset = Some(0);
    // A local header also occurs on continuation disks. Only a split marker
    // or a paired raw-stream terminal can establish the first volume.
    out.flags |= ZIP_LOCAL_HEADER;
    true
}

fn probe_zip_eocd_head(prefix: &[u8], out: &mut VolumeAnchor) -> bool {
    if !prefix.starts_with(ZIP_EOCD) || prefix.len() < 22 {
        return false;
    }
    out.format = "zip";
    out.strong = false;
    out.structure_offset = Some(0);
    out.flags |= ZIP_EOCD_HEAD;
    true
}

fn probe_rar(prefix: &[u8], offset: usize, out: &mut VolumeAnchor) -> bool {
    if prefix
        .get(offset..)
        .is_some_and(|value| value.starts_with(RAR5))
    {
        let header_offset = offset + RAR5.len();
        let Some(main) = rar5_main_header(prefix, header_offset) else {
            let data = &prefix[offset..];
            let Some((body, end)) = rar5_archive_encryption_header(data) else { return false; };
            initialize_rar_anchor(out, offset);
            out.encrypted = true;
            out.flags |= RAR_VERSION_5;
            out.rar5_encryption = rar5_encryption_identity(data, body, end).map(Arc::new);
            out.needs_password = true;
            return true;
        };
        initialize_rar_anchor(out, offset);
        out.flags |= RAR_VERSION_5;
        out.rar_next_header_offset = Some(main.end as u64);
        out.multivolume = main.archive_flags & 0x01 != 0;
        if out.multivolume {
            out.internal_volume_number = Some(main.volume_number.unwrap_or(0) + 1);
            out.flags |= RAR_PART_NUMBERING | if main.volume_number.is_none() { FIRST } else { MEMBER };
        } else {
            out.standalone = true;
            let available = out.size.saturating_sub(header_offset as u64);
            if main.service_offset.is_some_and(|offset| offset >= available) {
                out.flags |= STANDALONE_TRUNCATED;
            }
        }
    } else if let Some(flags) = rar4_main_flags(prefix, offset + RAR4.len()) {
        initialize_rar_anchor(out, offset);
        out.rar_next_header_offset = u16_le(prefix, offset + RAR4.len() + 5)
            .map(|size| offset as u64 + RAR4.len() as u64 + u64::from(size));
        // RAR4 MHD_VOLUME and MHD_FIRSTVOLUME.
        out.encrypted = flags & RAR4_MAIN_HEADER_PASSWORD != 0;
        out.needs_password = out.encrypted;
        out.multivolume = flags & 0x0001 != 0;
        if out.multivolume {
            out.flags |= if flags & 0x0100 != 0 { FIRST } else { MEMBER };
            out.internal_volume_number = (flags & 0x0100 != 0).then_some(1);
            out.flags |= rar4_numbering(flags);
        } else {
            out.standalone = true;
        }
    } else {
        return false;
    }
    true
}

fn initialize_rar_anchor(out: &mut VolumeAnchor, offset: usize) {
    out.format = "rar";
    out.strong = true;
    out.structure_offset = Some(offset as u64);
}

/// RAR4 MHD_NEWNUMBERING decides how 7-Zip derives the next volume name
/// (`name.partN.rar` versus `name.rNN`), independent of the physical name.
fn rar4_numbering(flags: u16) -> u32 {
    if flags & 0x0010 != 0 {
        RAR_PART_NUMBERING
    } else {
        RAR_OLD_NUMBERING
    }
}

fn rar4_main_flags(data: &[u8], offset: usize) -> Option<u16> {
    let stored_crc = u16_le(data, offset)?;
    let header_type = *data.get(offset + 2)?;
    if header_type != 0x73 {
        return None;
    }
    let header_size = u16_le(data, offset + 5)? as usize;
    if header_size < 13 {
        return None;
    }
    let header = data.get(offset + 2..offset.checked_add(header_size)?)?;
    if (crc32(header) & 0xffff) as u16 != stored_crc {
        return None;
    }
    u16_le(data, offset + 3)
}

fn probe_seven_zip(prefix: &[u8], offset: usize, size: u64, out: &mut VolumeAnchor) -> bool {
    let Some(header) = prefix.get(offset..offset.saturating_add(32)) else {
        return false;
    };
    let stored_crc = u32::from_le_bytes(header[8..12].try_into().unwrap_or_default());
    if crc32(&header[12..32]) != stored_crc {
        return false;
    }
    let Some(next) = crate::formats::seven_zip::RelationNextHeader::parse(header) else {
        return false;
    };
    out.format = "7z";
    out.structure_offset = Some(offset as u64);
    out.flags |= FIRST;
    out.internal_volume_number = Some(1);
    let Some(logical_size) = (offset as u64).checked_add(next.end()) else {
        return false;
    };
    out.seven_zip_next_header = Some(Arc::new(next));
    out.expected_logical_size = Some(logical_size);
    out.strong = true;

    if logical_size <= size {
        out.standalone = true;
    } else {
        out.multivolume = true;
        out.continuation_to_next = true;
    }
    true
}

fn probe_zip_reader(
    prefix: &[u8],
    tail: &[u8],
    tail_start: u64,
    out: &mut VolumeAnchor,
    reader: &ManagedReader,
    base: u64,
) -> bool {
    let eocd = crate::formats::zip::find_eocd_record(tail, true);
    let trailing = eocd.is_some_and(|e| e.end < tail.len());
    let original = trailing.then(|| out.clone());
    if let Some(eocd) = eocd {
        let record = &tail[eocd.offset..eocd.offset + 22];
        let disk = u16_le(record, 4).unwrap();
        let cd_disk = u16_le(record, 6).unwrap();
        let needs64 = disk == u16::MAX
            || cd_disk == u16::MAX
            || u16_le(record, 8) == Some(u16::MAX)
            || u16_le(record, 10) == Some(u16::MAX)
            || u32_le(record, 12) == Some(u32::MAX)
            || u32_le(record, 16) == Some(u32::MAX);
        if needs64 {
            let absolute = base + tail_start + eocd.offset as u64;
            let found =
                crate::formats::zip::zip64::locate_end_record(absolute, None, |offset, len| {
                    let bytes = reader.read_at(offset, len)?;
                    out.bytes_read += bytes.len() as u64;
                    Ok(bytes)
                });
            if let Ok(Some(found)) = found {
                let r = found.record;
                // ZIP64 fills sentinel fields only. Contradictory identities
                // are not a license to overwrite a classic volume number.
                if found.locator.record_disk == r.disk
                    && found.locator.total_disks == r.disk.checked_add(1).unwrap_or(0)
                    && (disk == u16::MAX || u32::from(disk) == r.disk)
                    && (cd_disk == u16::MAX || u32::from(cd_disk) == r.cd_disk)
                {
                    out.zip_directory = Some(Arc::new(crate::formats::zip::RelationDirectory {
                        disk: r.disk,
                        cd_disk: r.cd_disk,
                        offset: r.cd_offset,
                        size: r.cd_size,
                        entries: r.total_entries,
                        disk_entries: r.disk_entries,
                        end: found.offset - base,
                    }));
                }
            }
        }
    }
    let recognized = probe_zip_eocd(prefix, tail, tail_start, out, eocd);
    if trailing
        && out.zip_directory.as_ref().is_none_or(|directory| {
            let mut physical = **directory;
            physical.end += base;
            !matches!(
                crate::formats::zip::visit_relation_directory(&out.path, physical, |_, _| {}),
                Ok(true)
            )
        })
    {
        let bytes_read = out.bytes_read;
        *out = original.unwrap();
        out.bytes_read = bytes_read;
        return false;
    }
    if trailing && out.has_any(ZIP_SINGLE_DISK) {
        if let Some(record) = eocd {
            if crate::formats::zip::zip_continuation_prefix(&tail[record.end..]) {
                out.flags |= ZIP_AWAITING_TAIL;
            }
        }
    }
    recognized
}

#[cfg(test)]
fn probe_zip(prefix: &[u8], tail: &[u8], tail_start: u64, out: &mut VolumeAnchor) -> bool {
    probe_zip_eocd(
        prefix,
        tail,
        tail_start,
        out,
        crate::formats::zip::find_eocd_record(tail, true),
    )
}

fn probe_zip_eocd(
    prefix: &[u8],
    tail: &[u8],
    tail_start: u64,
    out: &mut VolumeAnchor,
    eocd: Option<crate::formats::zip::EocdInfo>,
) -> bool {
    let split_start_offset = prefix
        .starts_with(ZIP_SPLIT_MARKER)
        .then_some(ZIP_SPLIT_MARKER.len())
        .filter(|offset| plausible_zip_local(prefix, *offset));
    let empty_eocd_offset = zip_empty_eocd_offset(prefix);
    let start_offset = split_start_offset.or_else(|| {
        anchored_signature(prefix, ZIP_LOCAL)
            .filter(|offset| plausible_zip_local(prefix, *offset))
            .or(empty_eocd_offset)
    });
    let empty_eocd_start = empty_eocd_offset == Some(0);
    let eocd_index = eocd.map(|record| record.offset);
    if start_offset.is_none() && eocd_index.is_none() {
        return false;
    }
    out.format = "zip";
    out.strong = true;
    if let Some(offset) = start_offset {
        out.structure_offset = Some(if split_start_offset.is_some() {
            0
        } else {
            offset as u64
        });
        out.flags |= FIRST;
        // A local entry can also begin a later disk. Only the split marker
        // proves the physical first disk before EOCD information is known.
        out.internal_volume_number = split_start_offset.map(|_| 1);
        if split_start_offset.is_some() {
            out.flags |= ZIP_SPLIT_START;
        } else if offset == 0 && empty_eocd_offset != Some(offset) {
            out.flags |= ZIP_LOCAL_HEADER;
        }
    }
    let mut split_terminal = false;
    if let Some(index) = eocd_index {
        out.zip_eocd_offset = Some(tail_start + index as u64);
        if let Some(record) = tail.get(index..index + 22) {
            let mut disk = u32::from(u16::from_le_bytes([record[4], record[5]]));
            let mut cd_disk = u32::from(u16::from_le_bytes([record[6], record[7]]));
            if disk == 0xffff || cd_disk == 0xffff {
                // ZIP64 is only needed when the classic disk fields overflow.
                let Some((zip64_disk, zip64_cd_disk)) = out
                    .zip_directory
                    .as_ref()
                    .map(|d| (d.disk, d.cd_disk))
                    .or_else(|| {
                        crate::formats::zip::zip64_relation_disk_numbers(tail, index, tail_start)
                    })
                else {
                    out.error = "zip64_disk_identity_missing".into();
                    out.strong = false;
                    out.flags |= TERMINAL;
                    return true;
                };
                if disk == 0xffff {
                    disk = zip64_disk;
                }
                if cd_disk == 0xffff {
                    cd_disk = zip64_cd_disk;
                }
            }
            if cd_disk > disk {
                out.error = "invalid_zip_multidisk_order".to_string();
                out.strong = false;
                return true;
            }
            if out.zip_directory.is_none() {
                out.zip_directory = Some(Arc::new(crate::formats::zip::RelationDirectory {
                    disk,
                    cd_disk,
                    offset: u64::from(u32_le(record, 16).unwrap()),
                    size: u64::from(u32_le(record, 12).unwrap()),
                    entries: u64::from(u16_le(record, 10).unwrap()),
                    disk_entries: u64::from(u16_le(record, 8).unwrap()),
                    end: tail_start + index as u64,
                }));
            }
            split_terminal = disk != 0 || cd_disk != 0;
            out.flags |= TERMINAL;
            out.flags |= if split_terminal { ZIP_SPLIT_END } else { ZIP_SINGLE_DISK };
            if split_terminal {
                out.internal_volume_number = disk.checked_add(1);
                out.flags &= !FIRST;
                if empty_eocd_start {
                    out.structure_offset = None;
                    out.continuation_to_next = false;
                }
            }
            out.expected_logical_size = Some(
                tail_start
                    + index as u64
                    + 22
                    + u16::from_le_bytes([record[20], record[21]]) as u64,
            );
        }
    }
    let has_first = start_offset.is_some() && !(split_terminal && empty_eocd_start);
    if has_first && eocd_index.is_some() && !split_terminal {
        out.standalone = true;
    } else if eocd_index.is_some() && !split_terminal && start_offset.is_none() {
        // A single-disk EOCD without a visible local header is not enough to
        // prove either standalone content or a split terminal.  Keep it
        // non-multivolume so carrier ZIPs do not block watch, while leaving
        // filename-declared `.zip.00N` members available to Relations.
        out.flags |= ZIP_TAIL_WITHOUT_HEAD;
    } else {
        out.multivolume = true;
        out.continuation_from_previous = eocd_index.is_some();
        out.continuation_to_next = has_first;
    }
    out.discard_zip_continuation_head();
    true
}

/// Upgrade only the missing tail facts; preserve the already parsed head.
/// Opaque 7z chunks also use this bounded pass only when a ZIP family shares
/// their bucket, so physical first/terminal disks are found before naming.
pub(crate) fn upgrade_relation_zip_tail(anchor: &VolumeAnchor) -> VolumeAnchor {
    let mut out = anchor.clone();
    // Most members in a split bucket have no EOCD. Read their bounded
    // tails directly instead of retaining the adjacent shared cache blocks.
    let Ok(reader) = ManagedReader::open(&anchor.path).map(|reader| reader.probe_reader()) else {
        return out;
    };
    let Ok((tail, start)) =
        crate::formats::zip::read_eocd_tail(&reader, 0, reader.len(), &[], &mut out.bytes_read)
    else {
        return out;
    };
    out.flags |= ZIP_TAIL_CHECKED;
    let mut terminal = VolumeAnchor {
        path: anchor.path.clone(),
        size: reader.len(),
        ..Default::default()
    };
    if !probe_zip_reader(&[], &tail, start, &mut terminal, &reader, 0) {
        // A failed directory probe is insufficient. Skip a suffix only when
        // there is no possible fixed record starting anywhere in its bytes.
        if anchor.has_any(ZIP_LOCAL_HEADER)
            && tail.len() as u64 == reader.len() - start
            && memmem::find(
                &tail[..tail.len().saturating_sub(22 - ZIP_EOCD.len())],
                ZIP_EOCD,
            ).is_none()
        {
            out.zip_eocd_absence = reader.physical_generation()
                .filter(|generation| generation.len == anchor.size)
                .map(|generation| Arc::new(ZipEocdAbsence {
                    generation: generation.clone(),
                    start,
                }));
        }
        return out;
    }
    out.format = terminal.format;
    out.strong = terminal.strong;
    out.internal_volume_number = terminal
        .internal_volume_number
        .or(out.internal_volume_number);
    out.expected_logical_size = terminal.expected_logical_size;
    out.zip_eocd_offset = terminal.zip_eocd_offset;
    out.zip_directory = terminal.zip_directory;
    out.continuation_from_previous = terminal.continuation_from_previous;
    out.error = terminal.error;
    out.flags |= terminal.flags;
    if out.has_any(ZIP_SPLIT_END) {
        out.multivolume = true;
        out.flags &= !FIRST;
    } else if anchor.has_any(ZIP_LOCAL_HEADER)
        && out.has_any(TERMINAL)
    {
        out.standalone = true;
        out.multivolume = false;
        out.flags &= !ZIP_TAIL_WITHOUT_HEAD;
    }
    out.discard_zip_continuation_head();
    out
}

/// Only a known ZIP bucket without a terminal enters this fallback. Scan its
/// bytes in fixed windows; verify each candidate using the
/// shared EOCD/directory parsers before accepting a carrier's logical end.
pub(crate) fn upgrade_relation_zip_carrier_tail(
    anchor: &VolumeAnchor,
    known_eocd: Option<(u64, &PhysicalFileGeneration)>,
) -> VolumeAnchor {
    let mut out = anchor.clone();
    if out.has_any(ZIP_CARRIER_CHECKED) {
        return out;
    }
    let Ok(reader) = ManagedReader::open(&out.path).map(|r| r.probe_reader()) else {
        return out;
    };
    // The managed reader already checks a fresh handle for this path.
    let checked_suffix = out.zip_eocd_absence.take().filter(|absence| {
        reader.physical_generation() == Some(&absence.generation)
    });
    let unique_eocd = known_eocd.filter(|(_, generation)| {
        reader.physical_generation() == Some(*generation)
    }).map(|(offset, _)| offset);
    // Keep enough overlap to find a signature straddling the checked suffix.
    let mut end = checked_suffix.as_ref().map_or(reader.len(), |suffix| {
        if suffix.start == 0 { 0 } else { suffix.start + ZIP_EOCD.len() as u64 - 1 }
    });
    if let Some(offset) = unique_eocd {
        end = offset + 22;
    }
    let mut possible_eocd = false;
    while end != 0 {
        let start = unique_eocd.unwrap_or_else(|| end.saturating_sub(64 * 1024));
        let length = (end - start) as usize;
        let Ok(window) = reader.read_cached_at(start, length) else {
            return out;
        };
        if window.len() != length {
            return out;
        }
        out.bytes_read += window.len() as u64;
        for at in memmem::rfind_iter(&window, ZIP_EOCD) {
            let offset = start + at as u64;
            if reader.len() - offset < 22 {
                continue;
            }
            possible_eocd = true;
            let fixed_read;
            let fixed = if let Some(fixed) = window.get(at..at + 22) {
                fixed
            } else if let Ok(bytes) = reader.read_cached_at(offset, 22) {
                fixed_read = bytes;
                &fixed_read
            } else {
                return out;
            };
            let Some(comment) = u16_le(fixed, 20) else {
                continue;
            };
            let len = 22 + usize::from(comment);
            if offset
                .checked_add(len as u64)
                .is_none_or(|stop| stop > reader.len())
            {
                continue;
            }
            let tail_read;
            let tail = if let Some(tail) = window.get(at..at + len) {
                tail
            } else if let Ok(bytes) = reader.read_cached_at(offset, len) {
                tail_read = bytes;
                &tail_read
            } else {
                return out;
            };
            let mut candidate = VolumeAnchor {
                path: out.path.clone(),
                size: reader.len(),
                ..Default::default()
            };
            if !probe_zip_reader(&[], tail, offset, &mut candidate, &reader, 0)
                || !candidate.error.is_empty()
            {
                continue;
            }
            let Some(directory) = candidate.zip_directory.as_ref() else {
                continue;
            };
            if !matches!(
                crate::formats::zip::visit_relation_directory(&out.path, **directory, |_, _| {}),
                Ok(true)
            ) {
                continue;
            }
            // The relation fallback found an older directory outside the
            // ordinary tail window. Carry the same append evidence as Deep;
            // do not make that directory a successful bounded delivery.
            let after = offset + len as u64;
            if candidate.has_any(ZIP_SINGLE_DISK) && reader.len().saturating_sub(after) >= 10 {
                let Ok(next) = reader.read_cached_at(after, 30) else { return out };
                candidate.bytes_read += next.len() as u64;
                if crate::formats::zip::zip_continuation_prefix(&next) {
                    candidate.flags |= ZIP_AWAITING_TAIL;
                }
            }
            out.format = candidate.format;
            out.strong = candidate.strong;
            out.internal_volume_number = candidate
                .internal_volume_number
                .or(out.internal_volume_number);
            out.zip_directory = candidate.zip_directory;
            out.zip_eocd_offset = candidate.zip_eocd_offset;
            out.expected_logical_size = candidate.expected_logical_size;
            out.multivolume |= candidate.multivolume;
            out.continuation_from_previous = candidate.continuation_from_previous;
            out.bytes_read += candidate.bytes_read;
            if out.internal_volume_number != Some(1) {
                out.flags &= !FIRST;
            }
            out.flags |= TERMINAL | candidate.flags | ZIP_CARRIER_CHECKED;
            return out;
        }
        if start == 0 || unique_eocd.is_some() {
            break;
        }
        end = start + 3;
    }
    if unique_eocd.is_some() && !possible_eocd {
        return upgrade_relation_zip_carrier_tail(anchor, None);
    }
    out.flags |= ZIP_CARRIER_CHECKED;
    if !possible_eocd && anchor.has_any(ZIP_LOCAL_HEADER) {
        if let Some(generation) = reader.physical_generation().filter(|generation| {
            generation.len == anchor.size
                && capture_file_generation(std::path::Path::new(&out.path))
                    .is_ok_and(|current| &current == *generation)
        }) {
            out.mark_zip_eocd_absent(generation.clone());
        }
    }
    out
}

/// ENDARC is a separately cached field, not a second main-header probe.
/// Plain ENDARC records are tiny and CRC protected. Encrypted records reuse
/// the existing password parser rather than a Python dictionary round trip.
pub(crate) fn resolve_encrypted_relation_anchor(
    anchor: &VolumeAnchor,
    reader: &ManagedReader,
    passwords: &[std::sync::Arc<str>],
    require_terminal: bool,
    proven_key: Option<&crate::password::rar::RarProvenKey>,
) -> std::io::Result<(VolumeAnchor, Option<usize>)> {
    use crate::password::rar::{probe_header_passwords, HeaderPassword};

    let rar5 = anchor.has_any(RAR_VERSION_5);
    let reader = reader.windowed_probe_reader();
    let mut out = anchor.clone();
    let password = probe_header_passwords(
        &reader, anchor.structure_offset.unwrap_or(0), passwords, require_terminal, proven_key,
    )?;
    if let HeaderPassword::Matched(index, proof) = password {
        if rar5 && proof.main_volume.is_none() {
            out.flags |= RAR_PASSWORD_MATCHED_INCOMPLETE;
            return Ok((out, None));
        }
        out.needs_password = false;
        out.wrong_password = false;
        if let Some((flags, number)) = proof.main_volume {
            out.multivolume = flags & 1 != 0;
            out.standalone = !out.multivolume;
            if out.multivolume {
                out.internal_volume_number = Some(number.unwrap_or(0) + 1);
                out.flags |= RAR_PART_NUMBERING | if number.is_none() { FIRST } else { MEMBER };
            }
        }
        apply_rar_terminal_proof(&mut out, proof);
        return Ok((out, Some(index)));
    }
    out.wrong_password = matches!(password, HeaderPassword::Rejected);
    Ok((out, None))
}

fn apply_rar_terminal_proof(out: &mut VolumeAnchor, proof: crate::password::rar::RarTerminalProof) {
    if let Some(terminal) = proof.terminal {
        out.relation_has_next = Some(terminal.has_next);
        out.expected_logical_size = Some(terminal.offset);
        out.continuation_to_next = terminal.has_next;
        merge_rar_volume(out, terminal.volume_number);
        if !terminal.has_next {
            out.flags |= TERMINAL;
        }
        out.flags |= RAR_END_CHECKED;
    }
}

pub(crate) fn upgrade_relation_rar_end(anchor: &VolumeAnchor) -> VolumeAnchor {
    if anchor.encrypted || anchor.relation_has_next.is_some() || anchor.has_any(RAR_END_CHECKED) {
        return anchor.clone();
    }
    let Ok(reader) = ManagedReader::open(&anchor.path) else {
        return anchor.clone();
    };
    upgrade_relation_rar_end_reader(anchor, &reader).unwrap_or_else(|_| anchor.clone())
}

pub(crate) fn upgrade_relation_rar_end_reader(
    anchor: &VolumeAnchor,
    reader: &ManagedReader,
) -> std::io::Result<VolumeAnchor> {
    let mut out = anchor.clone();
    if out.encrypted || out.relation_has_next.is_some() || out.has_any(RAR_END_CHECKED) {
        return Ok(out);
    }
    // Header walks own one transient window. Dense RAR directories reuse it;
    // sparse payload skips never populate the process-wide physical cache.
    let reader = reader.windowed_probe_reader();
    if let Some(mut cursor) = out.rar_next_header_offset {
        let rar5 = out.has_any(RAR_VERSION_5);
        let mut first_file = true;
        // Walk header spans only; data is skipped, never buffered. Start after
        // the main header whose CRC/identity the cheap probe already verified.
        loop {
            if cursor.checked_add(7).is_none_or(|end| end > reader.len()) {
                break;
            }
            reader.hint_probe_window(cursor);
            let mut header = reader.read_at(cursor, 7)?;
            if header.len() != 7 {
                break;
            }
            out.bytes_read += 7;
            let (header_len, body_start) = if rar5 {
                let Some((size, start)) = read_vint(&header, 4) else {
                    break;
                };
                let Some(end) = start
                    .checked_add(size as usize)
                    .filter(|n| *n <= 2 * 1024 * 1024)
                else {
                    break;
                };
                (end, start)
            } else {
                (usize::from(u16_le(&header, 5).unwrap()), 7)
            };
            if header_len < 7
                || cursor
                    .checked_add(header_len as u64)
                    .is_none_or(|end| end > reader.len())
            {
                break;
            }
            if header_len > 7 {
                let rest = reader.read_at(cursor + 7, header_len - 7)?;
                if rest.len() != header_len - 7 {
                    break;
                }
                out.bytes_read += rest.len() as u64;
                header.extend(rest);
            }
            let data_size;
            if rar5 {
                if u32_le(&header, 0) != Some(crc32(&header[4..])) {
                    out.error = "rar_header_crc_mismatch".into();
                    break;
                }
                let Some((kind, pos)) = read_vint(&header, body_start) else {
                    break;
                };
                let Some((flags, mut pos)) = read_vint(&header, pos) else {
                    break;
                };
                if flags & 1 != 0 {
                    let Some((_, next)) = read_vint(&header, pos) else {
                        break;
                    };
                    pos = next;
                }
                if flags & 2 != 0 {
                    let Some((size, next)) = read_vint(&header, pos) else {
                        break;
                    };
                    data_size = size;
                    pos = next;
                } else {
                    data_size = 0;
                }
                if kind == 2 && first_file {
                    out.continuation_from_previous |= flags & 8 != 0;
                    out.continuation_to_next |= flags & 16 != 0;
                    first_file = false;
                }
                if kind == 5 {
                    let Some((end_flags, _)) = read_vint(&header, pos) else {
                        break;
                    };
                    out.relation_has_next = Some(end_flags & 1 != 0);
                    out.expected_logical_size = cursor.checked_add(header_len as u64);
                    break;
                }
            } else {
                if u16_le(&header, 0) != Some((crc32(&header[2..]) & 0xffff) as u16) {
                    out.error = "rar_header_crc_mismatch".into();
                    break;
                }
                let flags = u16_le(&header, 3).unwrap();
                let kind = header[2];
                let Some(size) = crate::formats::rar::rar4_data_size(&header) else {
                    break;
                };
                data_size = size;
                if kind == 0x74 && first_file {
                    out.continuation_from_previous |= flags & 1 != 0;
                    out.continuation_to_next |= flags & 2 != 0;
                    first_file = false;
                }
                if kind == 0x7b {
                    out.relation_has_next = Some(flags & 1 != 0);
                    out.expected_logical_size = cursor.checked_add(header_len as u64);
                    merge_rar_volume(&mut out, rar4_end_volume(&header));
                    break;
                }
            }
            let Some(next) = cursor
                .checked_add(header_len as u64)
                .and_then(|n| n.checked_add(data_size))
            else {
                break;
            };
            if next > reader.len() {
                break;
            }
            cursor = next;
        }
    }
    // An unchanged plain file cannot acquire ENDARC without a new generation.
    // Read failures return above, so only completed walks are reusable.
    out.flags |= RAR_END_CHECKED;
    if let Some(next) = out.relation_has_next {
        out.continuation_to_next = next;
        if !next {
            out.flags |= TERMINAL;
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) fn probe_volume_anchor_at_offset(
    path: &str,
    offset: u64,
    format: &str,
) -> VolumeAnchor {
    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            return VolumeAnchor {
                path: path.to_string(),
                error: error.to_string(),
                ..VolumeAnchor::default()
            };
        }
    };
    probe_volume_anchor_reader_at_offset(&reader, path, offset, format).unwrap_or_else(
        |error| VolumeAnchor {
            path: path.to_string(),
            size: reader.len(),
            error: error.to_string(),
            ..VolumeAnchor::default()
        },
    )
}

pub(crate) fn probe_volume_anchor_reader_at_offset(
    reader: &ManagedReader,
    path: &str,
    offset: u64,
    format: &str,
) -> std::io::Result<VolumeAnchor> {
    let mut result = VolumeAnchor {
        path: path.to_string(),
        ..VolumeAnchor::default()
    };
    let size = reader.len();
    result.size = size;
    if offset >= size {
        result.error = "archive_offset_out_of_range".to_string();
        return Ok(result);
    }

    let remaining = size - offset;
    let prefix_len = remaining.min(512) as usize;
    let prefix = reader.read_at(offset, prefix_len)?;
    result.bytes_read += prefix.len() as u64;

    let recognized =
        probe_anchor_reader_prefix(reader, offset, format, &prefix, &mut result)?;
    if !recognized {
        result.error = "archive_structure_not_confirmed".to_string();
        return Ok(result);
    }

    if offset > 0 {
        if let Some(directory) = result.zip_directory.as_mut() {
            Arc::make_mut(directory).end += offset;
        }
        if let Some(eocd) = result.zip_eocd_offset.as_mut() {
            *eocd = eocd.saturating_add(offset);
        }
        if let Some(next) = result.rar_next_header_offset.as_mut() {
            *next += offset;
        }
        if let Some(structure_offset) = result.structure_offset.as_mut() {
            *structure_offset = structure_offset.saturating_add(offset);
        } else {
            result.structure_offset = Some(offset);
        }
        if let Some(expected_logical_size) = result.expected_logical_size.as_mut() {
            *expected_logical_size = expected_logical_size.saturating_add(offset);
        }
    }
    Ok(result)
}

fn probe_anchor_reader_prefix(
    reader: &ManagedReader,
    offset: u64,
    format: &str,
    prefix: &[u8],
    result: &mut VolumeAnchor,
) -> std::io::Result<bool> {
    let read = |offset, len| reader.read_at(offset, len);
    let prefix = complete_anchor_prefix(prefix, result, offset, read);
    let prefix = prefix.as_ref();
    let remaining = reader.len().saturating_sub(offset);
    if (format.is_empty() || format == "rar")
        && (prefix.starts_with(RAR4) || prefix.starts_with(RAR5))
        && probe_rar(prefix, 0, result)
    {
        return Ok(true);
    }
    if (format.is_empty() || format == "7z")
        && prefix.starts_with(SEVEN_ZIP)
        && probe_seven_zip(prefix, 0, remaining, result)
    {
        return Ok(true);
    }
    if format.is_empty() && offset == 0 {
        probe_standalone_stream(prefix, result, |offset, len| reader.read_direct_at(offset, len));
        if !result.format.is_empty() {
            return Ok(true);
        }
    }
    if format.is_empty() || format == "zip" {
        let (tail, tail_start) = crate::formats::zip::read_eocd_tail(
            reader,
            offset,
            reader.len(),
            prefix,
            &mut result.bytes_read,
        )?;
        if probe_zip_reader(prefix, &tail, tail_start, result, reader, offset) {
            return Ok(true);
        }
    }
    Ok(!result.format.is_empty())
}

fn probe_standalone_stream(
    prefix: &[u8],
    out: &mut VolumeAnchor,
    mut read: impl FnMut(u64, usize) -> std::io::Result<Vec<u8>>,
) {
    // Confirm the prefix before ruling this file out as a possible volume.
    // Continuation bytes can coincide with a leading stream signature.
    let format = if prefix.starts_with(sunpack_enc::MAGIC) {
        sunpack_enc::Header::parse(prefix, out.size).is_ok().then_some("enc")
    } else if crate::formats::lz4::leading(prefix) {
        crate::formats::lz4::standalone_truncated(prefix, out.size, |offset, count| {
            let bytes = read(offset, count)?;
            out.bytes_read += bytes.len() as u64;
            Ok(bytes)
        }).map(|truncated| {
            if truncated {
                out.flags |= STANDALONE_TRUNCATED;
            }
            "lz4"
        })
    } else if let Some(kind) = StructuralStreamKind::from_header(prefix) {
        compression_stream_evidence(kind, prefix, out.size, |offset, count| {
            let bytes = read(offset, count)?;
            out.bytes_read += bytes.len() as u64;
            Ok(bytes)
        }).map(|readiness| {
            if matches!(readiness, StreamReadiness::Truncated) {
                out.flags |= STANDALONE_TRUNCATED;
            }
            kind.format()
        })
    } else if prefix.get(257..262) == Some(b"ustar") {
        crate::formats::tar::header_identity(prefix, out.size).then_some("tar")
    } else {
        None
    };
    let Some(format) = format else { return; };
    out.format = format;
    out.strong = true;
    out.standalone = true;
    out.flags |= FIRST;
}

fn anchored_signature(data: &[u8], signature: &[u8]) -> Option<usize> {
    data.starts_with(signature).then_some(0)
}

fn zip_empty_eocd_offset(data: &[u8]) -> Option<usize> {
    let offset = anchored_signature(data, ZIP_EOCD)?;
    let record = data.get(offset..offset + 22)?;
    let disk = u16::from_le_bytes([record[4], record[5]]);
    let cd_disk = u16::from_le_bytes([record[6], record[7]]);
    let entries_on_disk = u16::from_le_bytes([record[8], record[9]]);
    let total_entries = u16::from_le_bytes([record[10], record[11]]);
    let cd_size = u32::from_le_bytes(record[12..16].try_into().ok()?);
    let cd_offset = u32::from_le_bytes(record[16..20].try_into().ok()?);
    (disk == 0
        && cd_disk == 0
        && entries_on_disk == 0
        && total_entries == 0
        && cd_size == 0
        && cd_offset == 0)
        .then_some(offset)
}

fn plausible_zip_local(data: &[u8], offset: usize) -> bool {
    crate::formats::zip::relation_local_header_len(data, offset)
        .and_then(|len| offset.checked_add(len))
        .is_some_and(|end| end <= data.len())
}

fn u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_native/volume_anchor/tests.rs"]
mod tests;
