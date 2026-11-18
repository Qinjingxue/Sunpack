use super::PasswordVerification;
use crate::formats::zip::{zip64, RelationDirectory};
use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan};
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, RangeSpec, VirtualRangeReader, VolumeSet,
};
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha1::Sha1;
use std::borrow::Cow;
use std::io::{Read, Seek};
use std::sync::{Arc, OnceLock};

#[path = "zip_strong.rs"]
mod strong;
#[path = "zip_probe.rs"]
mod probe;
use probe::{ZipLocation, ZipPrefix, ZipPrefixKey, ZipRead, ZipReadInput};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const MAX_EOCD_SCAN: usize = 65_557;
const AES_PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD: usize = 256;
const ZIPCRYPTO_HEADER_LEN: usize = 12;

pub(crate) fn zip_fast_verify_passwords_with_reader(
    preparation: &mut Preparation,
    reader: &ManagedReader,
    candidates: &[Arc<str>],
    eocd_offset: Option<u64>,
) -> std::io::Result<PasswordVerification> {
    let key = InputKey::file("zip", reader)?.with_zip_eocd(eocd_offset);
    preparation.verify(key, candidates, || {
        let input = ZipReadInput::Ranges(Arc::from([RangeSpec::entire(reader)]));
        prepare_zip_stream_from(&mut reader.cursor(), reader.len(), eocd_offset, Some(&input))
            .map(PasswordContext::Zip)
    })
}

pub(crate) fn zip_fast_verify_passwords_from_ranges(
    preparation: &mut Preparation,
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    eocd_offset: Option<u64>,
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed: Arc<_> = parse_ranges(ranges.iter().copied(), sessions)?.into_boxed_slice().into();
    let key = ranges_key("zip", &parsed)?.with_zip_eocd(eocd_offset);
    preparation.verify(key, candidates, || {
        let mut reader = VirtualRangeReader::new(&parsed);
        let total_len = reader.len();
        let input = ZipReadInput::Ranges(Arc::clone(&parsed));
        prepare_zip_stream_from(&mut reader, total_len, eocd_offset, Some(&input)).map(PasswordContext::Zip)
    })
}

pub(crate) fn zip_fast_verify_passwords_from_volumes(
    preparation: &mut Preparation,
    parts: &[InputPart],
    candidates: &[Arc<str>],
    eocd_offset: Option<u64>,
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let volumes = Arc::new(VolumeSet::new(parse_volumes(parts, sessions)?));
    preparation.verify(volumes.key("zip")?.with_zip_eocd(eocd_offset), candidates, || {
        prepare_zip_volumes(&volumes, eocd_offset).map(PasswordContext::Zip)
    })
}

pub(crate) fn zip_fast_verify_passwords_from_attempts(
    preparation: &mut Preparation,
    head: &InputExtent,
    plan: &VolumeAttemptPlan,
    candidates: &[Arc<str>],
    spanned: bool,
    eocd_offset: Option<u64>,
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let build = || prepare_zip_attempts(head, plan, spanned, eocd_offset, sessions);
    preparation.verify_local(build(), candidates)
}

fn prepare_zip_attempts(
    head: &InputExtent,
    plan: &VolumeAttemptPlan,
    spanned: bool,
    eocd_offset: Option<u64>,
    sessions: &[NativeArchiveSession],
) -> Result<PasswordContext, PreparedStatus> {
    use super::input::attempts::{prepare_attempt_evidence_partial, AttemptGeometry};
    let anchor = (|| {
    let mut prefix = super::input::prefix::common_attempt_prefix(head, plan, sessions);
    if prefix.is_empty() && plan.head_size_from_total.is_none() && plan.tail_totals.is_empty() {
        prefix.push(head.clone());
    }
    while !prefix.is_empty() {
        if let Ok(ranges) = parse_ranges(prefix.iter(), sessions) {
            let mut reader = VirtualRangeReader::streaming(&ranges);
            let len = reader.len();
            if let Ok(Some(context)) = prepare_zip_anchor(&mut reader, len) {
                return Some(context);
            }
            break;
        }
        prefix.pop();
    }
        None
    })();
    let geometry = if !plan.tail_totals.is_empty() { AttemptGeometry::TailTotals }
        else if let Some(total) = plan.head_size_from_total { AttemptGeometry::TrimmedHead { total } }
        else if spanned { AttemptGeometry::DiskRelative }
        else { AttemptGeometry::Forward { logical_limit: None } };
    let evidence = prepare_attempt_evidence_partial(head, plan, sessions, geometry, |reader| {
        let len = reader.len();
        let directory = reader.independent_evidence(|reader| if spanned {
            let count = reader.last_disk().map_err(|error| ReadFault::from_io(error,
                "zip_disk_count", 0, 0, 0, len).with_field("zip.eocd", FieldLocation::Tail))?
                .and_then(|last| last.checked_add(1)).ok_or_else(invalid_password_directory)?;
            let volumes = CertainZipVolumes { reader: std::cell::RefCell::new(reader), count };
            prepare_zip_volume_directory(&volumes, eocd_offset, anchor.as_ref())
        } else {
            prepare_zip_directory_stream_from(reader, len, eocd_offset, anchor.as_ref(), |reader| {
                Some(ZipReadInput::Projected(Arc::new(reader.deferred_reads(false))))
            })
        });
        match directory {
            Ok(context) => Ok(Some(context)),
            Err(PreparedStatus::Status("invalid_volume_evidence", _)) => Ok(None),
            Err(_) if anchor.is_some() => {
                let anchor = anchor.as_ref().unwrap();
                let input = anchor.context.needs_read().then(|| ZipReadInput::Projected(
                    Arc::new(reader.deferred_reads(spanned))
                ));
                Ok(Some(anchor.context.clone().bind(input, anchor.location())))
            }
            Err(_) => reader.independent_evidence(|reader| {
                let context = if spanned {
                    prepare_zip_local_chain(|offset, size, field| {
                        let load = |reader: &mut super::input::attempts::AttemptReader<'_>| {
                            let location = FieldLocation::Head;
                            let (disk, local) = reader.advance_disk_offset(0, 0, offset).map_err(|error| {
                                ReadFault::from_io(error, "read_volume", offset, size, 0, len).with_field(field, location)
                            })?.ok_or_else(invalid_password_directory)?;
                            let bytes = reader.read_disk_spanning(disk, local, size).map_err(|error| {
                                ReadFault::from_io(error, "read_volume", offset, size, 0, len).with_field(field, location)
                            })?;
                            if bytes.len() != size { return Err(ReadFault::short_read("read_volume", offset, size, bytes.len(), len).with_field(field, location).into()); }
                            Ok(bytes)
                        };
                        load(reader)
                    })?
                } else {
                    prepare_zip_local_chain(|offset, size, field| {
                        let load = |reader: &mut super::input::attempts::AttemptReader<'_>| {
                            read_zip_anchor_field(reader, len, offset, size, field)
                        };
                        load(reader)
                    })?
                };
                let anchor = context.ok_or_else(invalid_password_directory)?;
                let input = anchor.context.needs_read().then(|| ZipReadInput::Projected(
                    Arc::new(reader.deferred_reads(spanned))
                ));
                let location = anchor.location();
                Ok(Some(anchor.context.bind(input, location)))
            }),
        }
    })?;
    match anchor {
        Some(anchor) if evidence.contexts.iter().all(|context| context == &anchor.context) =>
            evidence.with_anchor(PasswordContext::Zip(anchor.context)),
        _ => Ok(evidence.into_context(PasswordContext::Zip)),
    }
}

fn invalid_password_directory() -> PreparedStatus {
    PreparedStatus::new(
        "needs_volume_or_tail_damaged",
        "ZIP central directory crosses its declared extent",
    )
}

fn password_directory(
    record: &[u8; 22],
    offset: u64,
    source_len: u64,
) -> Result<RelationDirectory, PreparedStatus> {
    if !record.starts_with(ZIP_EOCD) {
        return Err(ReadFault::invalid_field(
            "parse_record",
            offset,
            record.len(),
            source_len,
            "invalid ZIP EOCD signature",
        )
        .with_field("zip.eocd", FieldLocation::Tail)
        .into());
    }
    Ok(RelationDirectory {
        disk: u32::from(le_u16(record, 4).unwrap()),
        cd_disk: u32::from(le_u16(record, 6).unwrap()),
        disk_entries: u64::from(le_u16(record, 8).unwrap()),
        entries: u64::from(le_u16(record, 10).unwrap()),
        size: u64::from(le_u32(record, 12).unwrap()),
        offset: u64::from(le_u32(record, 16).unwrap()),
        end: offset,
    })
}

fn password_directory_needs_zip64(directory: &RelationDirectory) -> bool {
    directory.disk == u32::from(u16::MAX)
        || directory.cd_disk == u32::from(u16::MAX)
        || directory.disk_entries == u64::from(u16::MAX)
        || directory.entries == u64::from(u16::MAX)
        || directory.size == u64::from(u32::MAX)
        || directory.offset == u64::from(u32::MAX)
}

fn resolve_password_zip64(
    classic: RelationDirectory,
    volumes: &impl ZipVolumeReader,
    last_disk: usize,
    local_eocd: u64,
) -> Result<Option<(RelationDirectory, (usize, u64))>, PreparedStatus> {
    // APPNOTE 4.4.1.5 puts the locator on the EOCD disk. The record's
    // coordinate system begins at its declared disk, even if earlier disks
    // are missing, have variable lengths, or carry ambiguous candidates.
    let Some(at) = local_eocd.checked_sub(20) else { return Ok(None); };
    let locator_bytes = volumes.read_disk_spanning_field(last_disk, at, 20, "zip.zip64_locator", FieldLocation::Tail)?;
    if !locator_bytes.starts_with(b"PK\x06\x07") { return Ok(None); }
    let locator = zip64::parse_locator(&locator_bytes).map_err(|_| invalid_password_directory())?;
    if locator.total_disks as usize != volumes.len() || locator.record_disk as usize > last_disk {
        return Err(invalid_password_directory());
    }
    let first = locator.record_disk as usize;
    let mut locator_offset = at;
    for disk in first..last_disk {
        locator_offset = locator_offset.checked_add(volumes.volume_len(disk).ok_or_else(invalid_password_directory)?)
            .ok_or_else(invalid_password_directory)?;
    }
    let mut fault = None;
    let found = zip64::locate_record_before(locator_offset, 0, locator, |offset, size| {
        let (disk, local) = volumes.advance_disk_offset(first, 0, offset).ok_or(())?;
        volumes.read_disk_spanning_field(disk, local, size, "zip.zip64_end_record", FieldLocation::Tail).map_err(|error| {
            fault = Some(error);
        })
    }).map_err(|()| fault.map_or_else(invalid_password_directory, PreparedStatus::from))?;
    let boundary = volumes.advance_disk_offset(first, 0, found.offset).ok_or_else(invalid_password_directory)?;
    let record = found.record;
    if ![
        (
            u64::from(classic.disk),
            u64::from(u16::MAX),
            u64::from(record.disk),
        ),
        (
            u64::from(classic.cd_disk),
            u64::from(u16::MAX),
            u64::from(record.cd_disk),
        ),
        (
            classic.disk_entries,
            u64::from(u16::MAX),
            record.disk_entries,
        ),
        (classic.entries, u64::from(u16::MAX), record.total_entries),
        (classic.size, u64::from(u32::MAX), record.cd_size),
        (classic.offset, u64::from(u32::MAX), record.cd_offset),
    ]
    .into_iter()
    .all(|(field, sentinel, wide)| field == sentinel || field == wide)
    {
        return Err(PreparedStatus::new(
            "damaged",
            "ZIP64 end record contradicts the classic EOCD",
        ));
    }
    Ok(Some((
        RelationDirectory {
            disk: record.disk,
            cd_disk: record.cd_disk,
            disk_entries: record.disk_entries,
            entries: record.total_entries,
            size: record.cd_size,
            offset: record.cd_offset,
            end: found.offset,
        },
        boundary,
    )))
}

fn check_password_directory(
    directory: &RelationDirectory,
    fits: bool,
    missing_zip64: bool,
) -> Result<(), PreparedStatus> {
    if fits
        && directory.entries <= directory.size / 46
        && directory.disk_entries <= directory.entries
    {
        return Ok(());
    }
    if missing_zip64 {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            "ZIP central-directory location requires ZIP64",
        ));
    }
    Err(invalid_password_directory())
}

// Share Relations' descriptor/ZIP64 normalization. Only comparable fields
// establish a contradiction; masked local fields are not negative evidence.
fn compare_zip_entry(central: &[u8], central_variable: &[u8], sizes: &zip64::CentralValues, local: &[u8], local_variable: &[u8]) -> Result<(), PreparedStatus> {
    use crate::formats::zip::RelationLocalFields;
    let flags = le_u16(local, 6).unwrap();
    if flags & 0x2000 != 0 {
        return Err(PreparedStatus::new("unsupported_method", "ZIP local fields are masked"));
    }
    let central_name = le_u16(central, 28).unwrap() as usize;
    let local_name = le_u16(local, 26).unwrap() as usize;
    let mut local_sizes = [0; 46];
    if flags & 8 == 0 { local_sizes[20..28].copy_from_slice(&local[18..26]); }
    let lf = zip64::central_entry_values(&local_sizes, &local_variable[local_name..]).ok_or_else(invalid_password_directory)?;
    let expected = RelationLocalFields::new(le_u16(central, 10).unwrap(), le_u16(central, 8).unwrap(),
        le_u32(central, 16).unwrap(), sizes.compressed, sizes.uncompressed);
    let actual = RelationLocalFields::new(le_u16(local, 8).unwrap(), flags, le_u32(local, 14).unwrap(), lf.compressed, lf.uncompressed);
    if central_variable[..central_name] != local_variable[..local_name] || expected != actual {
        return Err(PreparedStatus::new("invalid_volume_evidence", "ZIP directory and local entry contradict each other"));
    }
    Ok(())
}

// The directory parser works in disk coordinates for both concrete volumes
// and determined sparse layouts; no duplicate ZIP directory interpretation.
trait ZipVolumeReader {
    fn len(&self) -> usize;
    fn volume_len(&self, disk: usize) -> Option<u64>;
    fn read_disk_spanning_field(&self, disk: usize, offset: u64, size: usize,
        field: &'static str, location: FieldLocation) -> Result<Vec<u8>, ReadFault>;
    fn deferred(&self, disk: usize, offset: u64) -> Option<ZipRead>;
    fn advance_disk_offset(&self, mut disk: usize, mut offset: u64, mut amount: u64) -> Option<(usize, u64)> {
        loop {
            let length = self.volume_len(disk)?;
            let remaining = length.checked_sub(offset)?;
            if amount <= remaining { return Some((disk, offset + amount)); }
            amount -= remaining;
            disk += 1;
            offset = 0;
        }
    }
    fn read_last_tail_field(&self, size: usize, field: &'static str) -> Result<Vec<u8>, ReadFault> {
        let disk = self.len().saturating_sub(1);
        let length = self.volume_len(disk).unwrap_or(0);
        let size = (size as u64).min(length) as usize;
        self.read_disk_spanning_field(disk, length - size as u64, size, field, FieldLocation::Tail)
    }
}
impl ZipVolumeReader for Arc<VolumeSet> {
    fn len(&self) -> usize { self.last_number() }
    fn volume_len(&self, disk: usize) -> Option<u64> {
        self.ordinal(disk).and_then(|i| VolumeSet::volume_len(self, i))
    }
    fn read_disk_spanning_field(&self, disk: usize, offset: u64, size: usize,
        field: &'static str, location: FieldLocation) -> Result<Vec<u8>, ReadFault> {
        let i = self.ordinal(disk).ok_or_else(|| ReadFault::short_read("read_volume", offset, size, 0, 0)
            .with_field(field, location).with_volume(disk as u32 + 1).with_possible_missing_volume())?;
        VolumeSet::read_disk_spanning_field(self, i, offset, size, field, location)
    }
    fn deferred(&self, disk: usize, offset: u64) -> Option<ZipRead> {
        Some(ZipRead { input: ZipReadInput::Volumes(self.clone()), location: ZipLocation { disk: Some(disk), offset } })
    }
}

struct CertainZipVolumes<'a, 'b> {
    reader: std::cell::RefCell<&'a mut super::input::attempts::AttemptReader<'b>>,
    count: usize,
}
impl ZipVolumeReader for CertainZipVolumes<'_, '_> {
    fn len(&self) -> usize { self.count }
    fn advance_disk_offset(&self, disk: usize, offset: u64, amount: u64) -> Option<(usize, u64)> {
        self.reader.borrow_mut().advance_disk_offset(disk, offset, amount).ok().flatten()
    }
    fn volume_len(&self, disk: usize) -> Option<u64> {
        if disk >= self.count { return None; }
        self.reader.borrow_mut().volume_len(disk).ok().flatten()
    }
    fn read_disk_spanning_field(&self, disk: usize, offset: u64, size: usize,
        field: &'static str, location: FieldLocation) -> Result<Vec<u8>, ReadFault> {
        let mut reader = self.reader.borrow_mut();
        let length = reader.len();
        let load = |reader: &mut super::input::attempts::AttemptReader<'_>| {
            let bytes = reader.read_disk_spanning(disk, offset, size)
                .map_err(|error| ReadFault::from_io(error, "read_volume", offset, size, 0, length)
                    .with_field(field, location).with_volume(disk as u32 + 1))?;
            if bytes.len() != size {
                return Err(ReadFault::short_read("read_volume", offset, size, bytes.len(), length)
                    .with_field(field, location).with_volume(disk as u32 + 1));
            }
            Ok(bytes)
        };
        load(&mut reader)
    }
    fn deferred(&self, disk: usize, offset: u64) -> Option<ZipRead> {
        Some(ZipRead {
            input: ZipReadInput::Projected(Arc::new(self.reader.borrow().deferred_reads(true))),
            location: ZipLocation { disk: Some(disk), offset },
        })
    }
}

fn prepare_zip_volumes(
    volumes: &Arc<VolumeSet>,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let prefix_len = volumes.contiguous_prefix_len();
    let context = prepare_zip_local_chain(|offset, size, field| {
        let location = FieldLocation::Head;
        if offset.checked_add(size as u64).is_none_or(|end| end > prefix_len) {
            return Err(ReadFault::short_read("read_volume", offset, size, 0, prefix_len).with_field(field, location).into());
        }
        let (disk, local) = volumes.advance_disk_offset(0, 0, offset).ok_or_else(invalid_password_directory)?;
        Ok(VolumeSet::read_disk_spanning_field(volumes, disk, local, size, field, location)?)
    });
    if let Ok(Some(anchor)) = context {
        if eocd_offset.is_some() && anchor.context.needs_sizes() {
            if let Ok(context) = prepare_zip_volume_directory(volumes, eocd_offset, Some(&anchor)) {
                if !context.needs_sizes() { return Ok(context); }
            }
        }
        let input = anchor.context.needs_read().then(|| ZipReadInput::Volumes(volumes.clone()));
        let location = anchor.location();
        return Ok(anchor.context.bind(input, location));
    }
    prepare_zip_volume_directory(volumes, eocd_offset, None).or_else(|error| context.and(Err(error)))
}

fn prepare_zip_volume_directory(
    volumes: &impl ZipVolumeReader,
    eocd_offset: Option<u64>,
    anchor: Option<&ZipAnchor>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let last_disk = volumes.len().checked_sub(1).ok_or_else(invalid_password_directory)?;
    let tail_len = volumes.volume_len(last_disk).ok_or_else(invalid_password_directory)?;
    let read_eocd = |offset| volumes.read_disk_spanning_field(last_disk, offset, 22, "zip.eocd", FieldLocation::Tail);
    // A flat offset names an exact position on a single logical disk.
    // For native spanning use the final disk directly, without opening
    // every preceding disk just to translate this hint.
    let exact = if last_disk == 0 {
        eocd_offset.map(|offset| read_eocd(offset).map(|bytes| (bytes, offset))).transpose()?
    } else { None };
    let exact = match exact {
        Some(record) => Some(record),
        None => match tail_len.checked_sub(22) {
            Some(at) => {
                let bytes = read_eocd(at)?;
                (bytes.starts_with(ZIP_EOCD) && le_u16(&bytes, 20) == Some(0)).then_some((bytes, at))
            }
            None => None,
        },
    };
    let (record, local_eocd): ([u8; 22], u64) = if let Some((bytes, at)) = exact {
        (bytes.try_into().unwrap(), at)
    } else {
        let tail = volumes.read_last_tail_field(MAX_EOCD_SCAN, "zip.eocd_search_window")?;
        if tail.len() < 22 {
            return Err(
                ReadFault::short_read("read_record", 0, 22, tail.len(), tail.len() as u64)
                    .with_field("zip.eocd", FieldLocation::Tail)
                    .into(),
            );
        }
        let offset = crate::formats::zip::find_eocd_record(&tail, false)
            .or_else(|| crate::formats::zip::find_eocd_record(&tail, true))
            .map(|record| record.offset)
            .ok_or_else(|| {
                ReadFault::invalid_field(
                    "locate",
                    0,
                    22,
                    tail.len() as u64,
                    "ZIP EOCD was not found",
                )
                .with_field("zip.eocd", FieldLocation::Tail)
            })?;
        let local = tail_len - tail.len() as u64 + offset as u64;
        (tail[offset..offset + 22].try_into().unwrap(), local)
    };
    let mut directory =
        password_directory(&record, local_eocd, tail_len)?;
    let mut boundary = (last_disk, local_eocd);
    let mut missing_zip64 = password_directory_needs_zip64(&directory);
    if missing_zip64 {
        if let Some((resolved, end)) = resolve_password_zip64(directory, volumes, last_disk, local_eocd)? {
            boundary = end;
            directory = resolved;
            missing_zip64 = false;
        }
    }
    if directory.disk as usize != last_disk {
        let fault = ReadFault::invalid_field(
            "validate_field",
            local_eocd + 4,
            2,
            volumes.volume_len(last_disk).ok_or_else(invalid_password_directory)?,
            format!(
                "declared disk count {} does not match available volume count {}",
                u64::from(directory.disk) + 1,
                volumes.len()
            ),
        )
        .with_field("zip.eocd.disk_number", FieldLocation::Tail);
        return Err(fault.into());
    }

    let mut disk = directory.cd_disk as usize;
    let mut offset = directory.offset;
    let directory_end = volumes.advance_disk_offset(disk, offset, directory.size);
    check_password_directory(
        &directory,
        directory_end.is_some_and(|end| end <= boundary),
        missing_zip64,
    )?;
    let mut remaining = directory.size;
    let mut unavailable = None;
    let anchor_entry = anchor.and_then(|anchor| volumes.advance_disk_offset(0, 0, anchor.local_offset));
    for _ in 0..directory.entries {
        let fixed = match volumes.read_disk_spanning_field(
            disk,
            offset,
            46,
            "zip.central_directory.entry_fixed",
            FieldLocation::Tail,
        ) {
            Ok(data) => data,
            Err(fault) => return Err(fault.into()),
        };
        if &fixed[..4] != ZIP_CENTRAL {
            let fault = ReadFault::invalid_field(
                "validate_signature",
                offset,
                4,
                46,
                "invalid ZIP central-directory signature",
            )
            .with_field("zip.central_directory.entry_signature", FieldLocation::Tail);
            return Err(fault.into());
        }
        let flags = le_u16(&fixed, 8).unwrap_or(0);
        let name_len = le_u16(&fixed, 28).unwrap_or(0) as u64;
        let extra_len = le_u16(&fixed, 30).unwrap_or(0) as u64;
        let comment_len = le_u16(&fixed, 32).unwrap_or(0) as u64;
        let record_len = 46 + name_len + extra_len + comment_len;
        remaining = remaining
            .checked_sub(record_len)
            .ok_or_else(invalid_password_directory)?;
        let same_anchor_position = |entry| anchor_entry.is_some_and(|(disk, offset)| {
            (disk, offset) == entry || (disk + 1, 0) == entry && volumes.volume_len(disk) == Some(offset)
        });
        let entry_disk = le_u16(&fixed, 34).unwrap();
        let entry_offset = le_u32(&fixed, 42).unwrap();
        let zip64_position = entry_disk == u16::MAX || entry_offset == u32::MAX;
        let inspect_entry = if anchor.is_some() {
            zip64_position || same_anchor_position((usize::from(entry_disk), u64::from(entry_offset)))
        } else {
            flags & 0x0001 != 0
        };
        if inspect_entry {
            let (variable_disk, variable_offset) = volumes.advance_disk_offset(disk, offset, 46)
                .ok_or_else(invalid_password_directory)?;
            let variable = volumes.read_disk_spanning_field(variable_disk, variable_offset,
                (name_len + extra_len) as usize, "zip.central_directory.name_extra", FieldLocation::Tail)?;
            let values = zip64::central_entry_values(&fixed, &variable[name_len as usize..])
                .ok_or_else(invalid_password_directory)?;
            let entry = (values.disk as usize, values.local_offset);
            // ZIP members may use different passwords. A shared anchor and
            // the directory must refer to the same member.
            if anchor.is_none() || same_anchor_position(entry) {
                match prepare_zip_volume_entry_checked(volumes, entry.0, entry.1, Some((&fixed, &variable, values)), anchor) {
                    Ok(context) => return Ok(context),
                    Err(error @ PreparedStatus::Status("invalid_volume_evidence", _)) if anchor.is_some() => return Err(error),
                    Err(error) => { unavailable.get_or_insert(error); }
                }
            }
        }
        let Some(next) = volumes.advance_disk_offset(disk, offset, record_len) else {
            return Err(PreparedStatus::new("needs_volume_or_tail_damaged", "zip central directory crosses unavailable data; missing volume or damaged tail field"));
        };
        (disk, offset) = next;
    }
    if anchor.is_some() { return Err(unavailable.unwrap_or_else(invalid_password_directory)); }
    Err(unavailable.unwrap_or_else(|| PreparedStatus::new("not_required", "zip has no encrypted entries")))
}

#[cfg(test)]
fn prepare_zip_volume_entry(volumes: &impl ZipVolumeReader, disk: usize, local_offset: u64) -> Result<ZipPasswordContext, PreparedStatus> {
    prepare_zip_volume_entry_checked(volumes, disk, local_offset, None, None)
}

fn prepare_zip_volume_entry_checked(
    volumes: &impl ZipVolumeReader,
    disk: usize,
    local_offset: u64,
    central: Option<(&[u8], &[u8], zip64::CentralValues)>,
    anchor: Option<&ZipAnchor>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let fixed = match volumes.read_disk_spanning_field(
        disk,
        local_offset,
        30,
        "zip.local_header.fixed",
        FieldLocation::Body,
    ) {
        Ok(data) => data,
        Err(fault) => return Err(fault.into()),
    };
    if &fixed[..4] != ZIP_LOCAL {
        if anchor.is_some() {
            return Err(PreparedStatus::new("invalid_volume_evidence", "ZIP directory disagrees with the known local-header position"));
        }
        let fault = ReadFault::invalid_field(
            "validate_signature",
            local_offset,
            4,
            30,
            "invalid ZIP local-header signature",
        )
        .with_field("zip.local_header.signature", FieldLocation::Body);
        return Err(fault.into());
    }
    let name_len = le_u16(&fixed, 26).unwrap_or(0) as u64;
    let extra_len = le_u16(&fixed, 28).unwrap_or(0) as u64;
    let Some((variable_disk, variable_offset)) =
        volumes.advance_disk_offset(disk, local_offset, 30)
    else {
        return Err(PreparedStatus::new(
            "needs_volume_or_tail_damaged",
            "zip local header crosses a missing volume",
        ));
    };
    let variable = match volumes.read_disk_spanning_field(
        variable_disk,
        variable_offset,
        (name_len + extra_len) as usize,
        "zip.local_header.name_extra",
        FieldLocation::Body,
    ) {
        Ok(data) => data,
        Err(fault) => return Err(fault.into()),
    };
    let central_extra = central.as_ref().map(|(fixed, variable, _)| {
        &variable[usize::from(le_u16(fixed, 28).unwrap())..]
    });
    let sizes_and_crc = if let Some((central, central_variable, sizes)) = central {
        compare_zip_entry(central, central_variable, &sizes, &fixed, &variable)?;
        Some((sizes, le_u32(central, 16).unwrap()))
    } else {
        local_zip_sizes(&fixed, &variable[name_len as usize..]).map(|sizes| (sizes, le_u32(&fixed, 14).unwrap()))
    };
    if let Some(anchor) = anchor.filter(|anchor| !anchor.context.needs_read()) {
        return Ok(anchor.context.clone());
    }
    let extra = &variable[name_len as usize..];
    let data_delta = 30 + name_len + extra_len;
    let Some((data_disk, data_offset)) =
        volumes.advance_disk_offset(disk, local_offset, data_delta)
    else {
        return Err(PreparedStatus::new(
            "needs_volume_or_tail_damaged",
            "zip encrypted data starts beyond available volumes",
        ));
    };
    let sizes_and_crc = sizes_and_crc.as_ref().map(|(sizes, crc)| (sizes, *crc));
    let read = |relative, size, field| {
        let (disk, offset) = if relative == 0 { (data_disk, data_offset) } else {
            volumes.advance_disk_offset(data_disk, data_offset, relative).ok_or_else(invalid_password_directory)?
        };
        Ok(volumes.read_disk_spanning_field(disk, offset, size, field, FieldLocation::Body)?)
    };
    let mut context = if let Some(anchor) = anchor {
        anchor.context.clone().with_sizes(sizes_and_crc.map(|(sizes, _)| sizes))
    } else {
        ZipEncryption::from_local(&fixed, extra, central_extra)?.prepare(sizes_and_crc, read)?
    };
    if context.needs_read() {
        if let Some(source) = volumes.deferred(data_disk, data_offset) {
            context.set_read(source);
        }
    }
    Ok(context)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ZipPasswordContext {
    Aes {
        key_len: usize,
        salt: Vec<u8>,
        verifier: [u8; 2],
        prefix: Option<ZipPrefix>,
    },
    ZipCrypto {
        header: [u8; ZIPCRYPTO_HEADER_LEN],
        check_byte: u8,
        prefix: Option<ZipPrefix>,
    },
    Strong(strong::PasswordHeader),
}

impl ZipPasswordContext {
    fn needs_read(&self) -> bool {
        match self {
            Self::Aes { prefix, .. } | Self::ZipCrypto { prefix, .. } => prefix.is_some(),
            Self::Strong(_) => true,
        }
    }

    fn set_read(&mut self, source: ZipRead) {
        match self {
            Self::Aes { prefix, .. } | Self::ZipCrypto { prefix, .. } => {
                if let Some(prefix) = prefix { prefix.bind(source); }
            }
            Self::Strong(header) => header.bind(source),
        }
    }

    fn bind(mut self, input: Option<ZipReadInput>, location: ZipLocation) -> Self {
        if let Some(input) = input { self.set_read(ZipRead { input, location }); }
        self
    }

    fn with_sizes(mut self, sizes: Option<&zip64::CentralValues>) -> Self {
        match &mut self {
            Self::Aes { prefix, .. } | Self::ZipCrypto { prefix, .. } => {
                *prefix = prefix.take().map(|prefix| prefix.with_sizes(sizes));
            }
            Self::Strong(header) => header.set_sizes(sizes),
        }
        self
    }

    fn needs_sizes(&self) -> bool {
        match self {
            Self::Aes { prefix, .. } | Self::ZipCrypto { prefix, .. } => prefix.as_ref().is_some_and(ZipPrefix::needs_size),
            Self::Strong(header) => header.needs_sizes(),
        }
    }

    fn aes(strength: u8, method: u16, flags: u16, sizes: Option<&zip64::CentralValues>, material: Vec<u8>) -> Result<Self, PreparedStatus> {
        let (salt_len, key_len) = aes_lengths(strength).ok_or_else(|| {
            PreparedStatus::new("unsupported_method", "unsupported winzip AES strength")
        })?;
        if material.len() != salt_len + 2 {
            return Err(PreparedStatus::new(
                "damaged",
                "winzip AES salt or password verifier is incomplete",
            ));
        }
        Ok(Self::Aes {
            key_len,
            salt: material[..salt_len].to_vec(),
            verifier: material[salt_len..].try_into().unwrap(),
            prefix: ZipPrefix::new(method, flags, (salt_len + 2) as u64, (salt_len + 12) as u64, sizes),
        })
    }

    pub(super) fn kdf_parameters(&self) -> Option<ZipKeyMaterial<'_>> {
        match self {
            Self::Aes { key_len, salt, .. } => Some(ZipKeyMaterial::Aes(*key_len, salt)),
            Self::ZipCrypto { header, check_byte, .. } => Some(ZipKeyMaterial::ZipCrypto(header, *check_byte)),
            Self::Strong(_) => Some(ZipKeyMaterial::Strong),
        }
    }

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        self.verify_cached(candidates, None)
    }

    pub(super) fn verify_cached(&self, candidates: &[Arc<str>], cache: Option<&ZipKeyCache>) -> std::io::Result<PasswordVerification> {
        match self {
            Self::Aes {
                key_len,
                salt,
                verifier,
                prefix,
            } => verify_winzip_aes_candidates(candidates, *key_len, salt, verifier, prefix.as_ref(), cache),
            Self::ZipCrypto { header, check_byte, prefix } => {
                verify_zipcrypto_material(candidates, header, *check_byte, prefix.as_ref(), cache)
            }
            Self::Strong(header) => header.verify(candidates, cache),
        }
    }
}

struct ZipAnchor {
    local_offset: u64,
    data_offset: u64,
    context: ZipPasswordContext,
}

impl ZipAnchor {
    fn location(&self) -> ZipLocation {
        ZipLocation { disk: None, offset: self.data_offset }
    }
}
fn local_zip_sizes(fixed: &[u8], extra: &[u8]) -> Option<zip64::CentralValues> {
    if le_u16(fixed, 6)? & 8 != 0 {
        return None;
    }
    // ZIP64 sizes occur in the same order as in the central record.
    let mut central = [0; 46];
    central[20..28].copy_from_slice(&fixed[18..26]);
    zip64::central_entry_values(&central, extra)
}

// A known logical anchor can provide password evidence without a tail or
// central directory. Never scan for signatures or guess descriptor boundaries.
fn prepare_zip_local_chain(
    mut read: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, PreparedStatus>,
) -> Result<Option<ZipAnchor>, PreparedStatus> {
    let header = "zip.local_password_proof";
    let mut offset = 0u64;
    let mut unavailable = None;
    loop {
        if Cancellation::current().cancelled() { return Ok(None); }
        let mut bytes = match read(offset, 30, header) {
            Ok(bytes) => bytes,
            Err(error) => {
                if matches!(&error, PreparedStatus::ReadFault(fault) if fault.code == "io_error") { return Err(error); }
                return Err(unavailable.unwrap_or(error));
            }
        };
        if offset == 0 && bytes.starts_with(b"PK\x07\x08") {
            offset = 4;
            bytes = read(offset, 30, header)?;
        }
        let Some(length) = crate::formats::zip::relation_local_header_len(&bytes, 0) else { return unavailable.map_or(Ok(None), Err); };
        if length > bytes.len() {
            let variable = offset.checked_add(bytes.len() as u64).ok_or_else(invalid_password_directory)?;
            bytes.extend_from_slice(&read(variable, length - bytes.len(), header)?);
        }
        let flags = le_u16(&bytes, 6).unwrap();
        let extra = &bytes[30 + usize::from(le_u16(&bytes, 26).unwrap())..];
        let sizes = (flags & 0x2000 == 0).then(|| local_zip_sizes(&bytes, extra)).flatten();
        let data_offset = offset.checked_add(length as u64).ok_or_else(invalid_password_directory)?;
        if flags & 1 != 0 {
            let sizes_and_crc = sizes.as_ref().map(|sizes| (sizes, le_u32(&bytes, 14).unwrap()));
            let context = ZipEncryption::from_local(&bytes, extra, None).and_then(|encryption| encryption.prepare(sizes_and_crc, |relative, size, field| {
                let at = data_offset.checked_add(relative).ok_or_else(invalid_password_directory)?;
                read(at, size, field)
            }));
            match context {
                Ok(context) => return Ok(Some(ZipAnchor { local_offset: offset, data_offset, context })),
                Err(error @ PreparedStatus::Status("unsupported_method" | "unknown_needs_final_verifier" | "damaged", _)) => {
                    unavailable.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        // Only authoritative sizes can advance this local walk. Reuse the
        // same ZIP64 sentinel interpretation as the relation local-key parser.
        let Some(sizes) = sizes else { return unavailable.map_or(Ok(None), Err); };
        offset = data_offset.checked_add(sizes.compressed).ok_or_else(invalid_password_directory)?;
    }
}

enum ZipEncryption {
    Traditional { check_byte: u8, method: u16, flags: u16 },
    Aes { strength: u8, method: u16, flags: u16 },
    Strong { method: u16, flags: u16 },
}

impl ZipEncryption {
    fn from_local(fixed: &[u8], extra: &[u8], central_extra: Option<&[u8]>) -> Result<Self, PreparedStatus> {
        let flags = le_u16(fixed, 6).unwrap();
        if flags & 0x2000 != 0 {
            return Err(PreparedStatus::new("unsupported_method", "ZIP local fields are masked"));
        }
        let method = le_u16(fixed, 8).unwrap();
        if method == 99 {
            let local_aes = parse_winzip_aes_extra(extra)?;
            let central_aes = central_extra.map(parse_winzip_aes_extra).transpose()?.flatten();
            if local_aes.is_some() && central_aes.is_some() && local_aes != central_aes {
                return Err(PreparedStatus::new("unsupported_method", "ZIP AES local and central parameters disagree"));
            }
            if let Some((strength, method)) = central_aes.or(local_aes) {
                if flags & 0x40 != 0 {
                    return Err(PreparedStatus::new("unsupported_method", "conflicting ZIP encryption fields"));
                }
                return Ok(Self::Aes { strength, method, flags });
            }
            // Method 99 is also LZFSE. The handler can select it when the
            // directory confirms that there is no WinZip AES extra. A local
            // header alone cannot rule out an AES extra in the directory.
            if central_extra.is_none() {
                return Err(PreparedStatus::new("unsupported_method", "winzip AES extra field not found"));
            }
        }
        if flags & 0x40 != 0 {
            return Ok(Self::Strong { method, flags });
        }
        let check_byte = if flags & 8 == 0 { fixed[17] } else { fixed[11] };
        Ok(Self::Traditional { check_byte, method, flags })
    }

    fn prepare(self, sizes_and_crc: Option<(&zip64::CentralValues, u32)>, mut read: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, PreparedStatus>) -> Result<ZipPasswordContext, PreparedStatus> {
        match self {
            Self::Aes { strength, method, flags } => {
                let (salt_len, _) = aes_lengths(strength).ok_or_else(||
                    PreparedStatus::new("unsupported_method", "unsupported winzip AES strength"))?;
                ZipPasswordContext::aes(strength, method, flags, sizes_and_crc.map(|(sizes, _)| sizes),
                    read(0, salt_len + 2, "zip.aes.salt_password_verifier")?)
            }
            Self::Traditional { check_byte, method, flags } => {
                let header = read(0, ZIPCRYPTO_HEADER_LEN, "zip.zipcrypto.encryption_header")?.try_into().map_err(|_|
                    PreparedStatus::new("damaged", "zipcrypto password header is incomplete"))?;
                let size = ZIPCRYPTO_HEADER_LEN as u64;
                let prefix = ZipPrefix::new(method, flags, size, size, sizes_and_crc.map(|(sizes, _)| sizes));
                Ok(ZipPasswordContext::ZipCrypto { header, check_byte, prefix })
            }
            Self::Strong { method, flags } => strong::PasswordHeader::read(method, flags, sizes_and_crc, read).map(ZipPasswordContext::Strong),
        }
    }
}

fn prepare_zip_anchor<R: Read + Seek>(file: &mut R, total_len: u64) -> Result<Option<ZipAnchor>, PreparedStatus> {
    prepare_zip_local_chain(|offset, size, field| read_zip_anchor_field(file, total_len, offset, size, field))
}

fn read_zip_anchor_field<R: Read + Seek>(file: &mut R, total_len: u64, offset: u64, size: usize, field: &'static str) -> Result<Vec<u8>, PreparedStatus> {
        let location = FieldLocation::Head;
        if offset.checked_add(size as u64).is_none_or(|end| end > total_len) {
            return Err(ReadFault::short_read("read_volume", offset, size, 0, total_len).with_field(field, location).into());
        }
        seek_field(file, offset, total_len, field, location)?;
        let mut bytes = vec![0; size];
        read_exact_field(file, &mut bytes, total_len, field, location)?;
        Ok(bytes)
}

#[cfg(test)]
fn prepare_zip_stream<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    prepare_zip_stream_from(file, total_len, eocd_offset, None)
}

fn prepare_zip_stream_from<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
    eocd_offset: Option<u64>,
    input: Option<&ZipReadInput>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let context = prepare_zip_anchor(file, total_len);
    if let Ok(Some(anchor)) = context {
        if eocd_offset.is_some() && anchor.context.needs_sizes() {
            if let Ok(context) = prepare_zip_directory_stream_from(file, total_len, eocd_offset,
                Some(&anchor), |_| input.cloned())
            {
                if !context.needs_sizes() { return Ok(context); }
            }
        }
        let location = anchor.location();
        return Ok(anchor.context.bind(input.cloned(), location));
    }
    prepare_zip_directory_stream_from(file, total_len, eocd_offset, None, |_| input.cloned())
        .or_else(|error| context.and(Err(error)))
}

struct ZipStream<'a, R, F> {
    file: std::cell::RefCell<&'a mut R>,
    length: u64,
    input: F,
}

impl<R: Read + Seek, F: Fn(&R) -> Option<ZipReadInput>> ZipVolumeReader for ZipStream<'_, R, F> {
    fn len(&self) -> usize { 1 }

    fn volume_len(&self, disk: usize) -> Option<u64> {
        (disk == 0).then_some(self.length)
    }

    fn read_disk_spanning_field(&self, disk: usize, offset: u64, size: usize,
        field: &'static str, location: FieldLocation) -> Result<Vec<u8>, ReadFault> {
        if disk != 0 {
            return Err(ReadFault::short_read("read_volume", offset, size, 0, 0)
                .with_field(field, location).with_possible_missing_volume());
        }
        let mut file = self.file.borrow_mut();
        seek_field(&mut **file, offset, self.length, field, location)?;
        let mut bytes = vec![0; size];
        read_exact_field(&mut **file, &mut bytes, self.length, field, location)?;
        Ok(bytes)
    }
    fn deferred(&self, disk: usize, offset: u64) -> Option<ZipRead> {
        if disk != 0 { return None; }
        let file = self.file.borrow();
        Some(ZipRead { input: (self.input)(&file)?, location: ZipLocation { disk: None, offset } })
    }
}

#[cfg(test)]
fn prepare_zip_directory_stream<R: Read + Seek>(file: &mut R, total_len: u64, eocd_offset: Option<u64>, anchor: Option<&ZipAnchor>) -> Result<ZipPasswordContext, PreparedStatus> {
    prepare_zip_directory_stream_from(file, total_len, eocd_offset, anchor, |_| None)
}

fn prepare_zip_directory_stream_from<R: Read + Seek>(file: &mut R, total_len: u64,
    eocd_offset: Option<u64>, anchor: Option<&ZipAnchor>,
    input: impl Fn(&R) -> Option<ZipReadInput>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let stream = ZipStream { file: std::cell::RefCell::new(file), length: total_len, input };
    prepare_zip_volume_directory(&stream, eocd_offset, anchor)
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum ZipKeyMaterial<'a> {
    Aes(usize, &'a [u8]),
    ZipCrypto(&'a [u8; ZIPCRYPTO_HEADER_LEN], u8),
    Strong,
}

pub(super) enum ZipKey {
    Aes {
        verifier: [u8; 2],
        encryption: OnceLock<Option<[u8; 32]>>,
    },
    ZipCrypto(ZipCryptoState),
    Strong([u8; 32]),
}

type ZipKeyCache<'a> = super::evidence::SharedCandidateKeys<ZipKeyMaterial<'a>, Option<ZipKey>>;

fn verify_winzip_aes_candidates(
    candidates: &[Arc<str>], key_len: usize, salt: &[u8], verifier: &[u8; 2],
    prefix: Option<&ZipPrefix>,
    cache: Option<&ZipKeyCache>,
) -> std::io::Result<PasswordVerification> {
    let attempts = candidates.len();
    let cancellation = Cancellation::current();
    let slots = cache.and_then(|cache| cache.cells(&ZipKeyMaterial::Aes(key_len, salt), attempts));
    let check = |(index, password): (usize, &Arc<str>)| {
        let derive = || cancellation.run(|| winzip_aes_verifier(&zip_password_bytes(password), salt, key_len));
        let bytes = if let Some(slots) = slots {
            match slots[index].get_or_init(|| derive().map(|verifier| ZipKey::Aes {
                verifier, encryption: OnceLock::new(),
            })) {
                Some(ZipKey::Aes { verifier, .. }) => Some(*verifier),
                _ => None,
            }
        } else {
            derive()
        };
        (bytes == Some(*verifier)).then_some(index)
    };
    let matched_indices: Vec<_> = if attempts >= AES_PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().filter_map(check).collect()
    } else {
        candidates.iter().enumerate().filter_map(check).collect()
    };
    cancellation.check_io()?;
    let mut result = if let Some(first) = matched_indices.first().copied() {
        PasswordVerification {
            matched_index: Some(first),
            matched_indices,
            attempts,
            match_evidence: Some("winzip_aes_password_verifier"),
            ..PasswordVerification::status("match", "winzip aes password verifiers matched")
        }
    } else {
        PasswordVerification {
            attempts,
            ..PasswordVerification::status("no_match", "winzip aes password verifier did not match")
        }
    };
    if let Some(prefix) = prefix.filter(|prefix| prefix.can_screen(result.matched_indices.len(), true)) {
        let mut keys = Vec::with_capacity(result.matched_indices.len());
        for &index in &result.matched_indices {
            let derive = || winzip_aes_encryption_key(&zip_password_bytes(&candidates[index]), salt, key_len);
            let key = if let Some(ZipKey::Aes { encryption, .. }) =
                slots.and_then(|slots| slots[index].get()).and_then(Option::as_ref)
            {
                *encryption.get_or_init(derive)
            } else {
                derive()
            };
            if let Some(key) = key {
                keys.push((index, ZipPrefixKey::Aes { key, len: key_len }));
            }
        }
        cancellation.check_io()?;
        prefix.screen(&keys, &mut result)?;
    }
    Ok(result)
}

fn verify_zipcrypto_material(
    candidates: &[Arc<str>],
    encryption_header: &[u8; ZIPCRYPTO_HEADER_LEN],
    check_byte: u8,
    prefix: Option<&ZipPrefix>,
    cache: Option<&ZipKeyCache>,
) -> std::io::Result<PasswordVerification> {
    let attempts = candidates.len();
    let cancellation = Cancellation::current();
    let slots = cache.and_then(|cache| cache.cells(&ZipKeyMaterial::ZipCrypto(encryption_header, check_byte), attempts));
    let check = |(index, password): (usize, &Arc<str>)| {
        if cancellation.cancelled() { return None; }
        let derive = || zipcrypto_header_state(&zip_password_bytes(password), encryption_header, check_byte);
        let state = if let Some(slots) = slots {
            match slots[index].get_or_init(|| derive().map(ZipKey::ZipCrypto)) {
                Some(ZipKey::ZipCrypto(state)) => Some(*state),
                _ => None,
            }
        } else {
            derive()
        };
        state.map(|state| (index, ZipPrefixKey::ZipCrypto(state)))
    };
    let keys: Vec<_> = if attempts >= ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().filter_map(check).collect()
    } else {
        candidates.iter().enumerate().filter_map(check).collect()
    };
    cancellation.check_io()?;

    let mut result = if let Some(&(first, _)) = keys.first() {
        PasswordVerification {
            matched_index: Some(first),
            matched_indices: keys.iter().map(|&(index, _)| index).collect(),
            attempts,
            match_evidence: Some("zipcrypto_header_byte"),
            ..PasswordVerification::status("match", "zipcrypto password material matched")
        }
    } else {
        PasswordVerification {
            attempts,
            ..PasswordVerification::status("no_match", "zipcrypto password material did not match")
        }
    };
    if let Some(prefix) = prefix.filter(|prefix| prefix.can_screen(keys.len(), false)) {
        prefix.screen(&keys, &mut result)?;
    }
    Ok(result)
}

fn parse_winzip_aes_extra(mut extra: &[u8]) -> Result<Option<(u8, u16)>, PreparedStatus> {
    let malformed = || PreparedStatus::new("unsupported_method", "invalid ZIP AES extra field");
    while !extra.is_empty() {
        let header_id = le_u16(extra, 0).ok_or_else(malformed)?;
        let size = usize::from(le_u16(extra, 2).ok_or_else(malformed)?);
        let (data, rest) = extra[4..].split_at_checked(size).ok_or_else(malformed)?;
        if header_id == 0x9901 {
            if data.len() < 7 || !matches!(le_u16(data, 0), Some(1 | 2))
                || &data[2..4] != b"AE" {
                return Err(malformed());
            }
            return Ok(Some((data[4], le_u16(data, 5).unwrap())));
        }
        extra = rest;
    }
    Ok(None)
}

fn aes_lengths(strength: u8) -> Option<(usize, usize)> {
    match strength {
        1 => Some((8, 16)),
        2 => Some((12, 24)),
        3 => Some((16, 32)),
        _ => None,
    }
}

/// Encode a ZIP password exactly as the 7z.dll extractor does.
///
/// 7-Zip's ZIP handler converts the UTF-16 password with
/// `UnicodeStringToMultiByte2(..., CP_ACP)` (default char `_`) for both
/// ZipCrypto and WinZip AES, so the fast verifier must hash the same bytes or
/// it would reject (or accept) candidates the extractor treats differently.
/// ASCII is identical in every ANSI codepage and stays borrowed.
pub(crate) fn zip_password_bytes(password: &str) -> Cow<'_, [u8]> {
    if password.is_ascii() {
        return Cow::Borrowed(password.as_bytes());
    }
    Cow::Owned(ansi_codepage_bytes(password))
}

#[cfg(windows)]
fn ansi_codepage_bytes(password: &str) -> Vec<u8> {
    #[link(name = "Kernel32")]
    extern "system" {
        fn WideCharToMultiByte(
            code_page: u32,
            flags: u32,
            wide: *const u16,
            wide_len: i32,
            multi: *mut u8,
            multi_len: i32,
            default_char: *const u8,
            used_default_char: *mut i32,
        ) -> i32;
    }
    const CP_ACP: u32 = 0;
    const DEFAULT_CHAR: &[u8; 2] = b"_\0";

    let wide: Vec<u16> = password.encode_utf16().collect();
    let Ok(wide_len) = i32::try_from(wide.len()) else {
        return password.as_bytes().to_vec();
    };
    let mut used_default = 0i32;
    let required = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            wide_len,
            std::ptr::null_mut(),
            0,
            DEFAULT_CHAR.as_ptr(),
            &mut used_default,
        )
    };
    if required <= 0 {
        return password.as_bytes().to_vec();
    }
    let mut output = vec![0u8; required as usize];
    let written = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            wide_len,
            output.as_mut_ptr(),
            required,
            DEFAULT_CHAR.as_ptr(),
            &mut used_default,
        )
    };
    if written <= 0 {
        return password.as_bytes().to_vec();
    }
    output.truncate(written as usize);
    output
}

#[cfg(not(windows))]
fn ansi_codepage_bytes(password: &str) -> Vec<u8> {
    password.as_bytes().to_vec()
}

fn winzip_aes_verifier(
    password: &[u8],
    salt: &[u8],
    key_len: usize,
) -> Option<[u8; 2]> {
    // PBKDF2 output blocks are independent. Only the block containing the
    // two-byte verifier is needed; encryption/authentication keys are unused
    // during candidate filtering. Keep all collisions for the final verifier.
    let offset = key_len * 2;
    let block_index = (offset / 20 + 1) as u32;
    let template = Hmac::<Sha1>::new_from_slice(password).expect("HMAC accepts any key length");
    let derived = winzip_aes_block(&template, salt, block_index)?;
    Some([derived[offset % 20], derived[offset % 20 + 1]])
}

fn winzip_aes_encryption_key(password: &[u8], salt: &[u8], len: usize) -> Option<[u8; 32]> {
    let template = Hmac::<Sha1>::new_from_slice(password).expect("HMAC accepts any key length");
    let mut key = [0; 32];
    for (index, block) in key[..len].chunks_mut(20).enumerate() {
        let derived = winzip_aes_block(&template, salt, index as u32 + 1)?;
        block.copy_from_slice(&derived[..block.len()]);
    }
    Some(key)
}

fn winzip_aes_block(template: &Hmac<Sha1>, salt: &[u8], block_index: u32) -> Option<[u8; 20]> {
    let mut mac = template.clone();
    mac.update(salt);
    mac.update(&block_index.to_be_bytes());
    let mut previous = mac.finalize().into_bytes();
    let mut derived = previous;
    let cancellation = Cancellation::current();
    for round in 1..1000 {
        if round & 63 == 1 && cancellation.cancelled() {
            return None;
        }
        let mut mac = template.clone();
        mac.update(&previous);
        previous = mac.finalize().into_bytes();
        for (value, byte) in derived.iter_mut().zip(previous.iter()) {
            *value ^= byte;
        }
    }
    Some(derived.into())
}

#[cfg(test)]
#[path = "../../tests/unit/password/zip/aes_verifier_tests.rs"]
mod aes_verifier_tests;

fn zipcrypto_header_state(password: &[u8], encrypted_header: &[u8; ZIPCRYPTO_HEADER_LEN], expected: u8) -> Option<ZipCryptoState> {
    let mut state = ZipCryptoState::new();
    for &byte in password { state.update_keys(byte); }
    let mut last = 0;
    for &encrypted in encrypted_header {
        last = state.decrypt(encrypted);
    }
    (last == expected).then_some(state)
}

#[derive(Clone, Copy)]
pub(super) struct ZipCryptoState {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCryptoState {
    fn new() -> Self {
        Self {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        }
    }

    fn update_keys(&mut self, byte: u8) {
        self.key0 = crc32_update(self.key0, byte);
        self.key1 = self.key1.wrapping_add(self.key0 & 0xff);
        self.key1 = self.key1.wrapping_mul(134775813).wrapping_add(1);
        self.key2 = crc32_update(self.key2, (self.key1 >> 24) as u8);
    }

    fn decrypt_byte(&self) -> u8 {
        let temp = (self.key2 | 2) as u16;
        (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xff) as u8
    }

    fn decrypt(&mut self, encrypted: u8) -> u8 {
        let plain = encrypted ^ self.decrypt_byte();
        self.update_keys(plain);
        plain
    }
}

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

fn crc32_update(crc: u32, byte: u8) -> u32 {
    CRC32_TABLE[((crc ^ byte as u32) & 0xff) as usize] ^ (crc >> 8)
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

#[cfg(test)]
#[path = "../../tests/unit/password/zip/password_encoding_tests.rs"]
mod password_encoding_tests;

#[cfg(test)]
#[path = "../../tests/unit/password/zip/zip64_bounded_probe_tests.rs"]
mod zip64_bounded_probe_tests;

#[cfg(test)]
#[path = "../../tests/unit/password/zip/local_anchor_tests.rs"]
mod local_anchor_tests;
