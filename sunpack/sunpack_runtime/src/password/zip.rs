use super::PasswordVerification;
use crate::formats::zip::{zip64, RelationDirectory};
use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan};
use crate::io::cancellation::Cancellation;
use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, VirtualRangeReader, VolumeSet,
};
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha1::Sha1;
use std::borrow::Cow;
use std::io::{Read, Seek};
use std::sync::Arc;

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const MAX_EOCD_SCAN: usize = 65_557;
const AES_PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD: usize = 256;

pub(crate) fn zip_fast_verify_passwords_with_reader(
    preparation: &mut Preparation,
    reader: &ManagedReader,
    candidates: &[Arc<str>],
    eocd_offset: Option<u64>,
) -> std::io::Result<PasswordVerification> {
    let key = InputKey::file("zip", reader)?.with_zip_eocd(eocd_offset);
    preparation.verify(key, candidates, || {
        prepare_zip_stream(&mut reader.cursor(), reader.len(), eocd_offset)
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
    let parsed = parse_ranges(ranges.iter().copied(), sessions)?;
    let key = ranges_key("zip", &parsed)?.with_zip_eocd(eocd_offset);
    preparation.verify(key, candidates, || {
        let mut reader = VirtualRangeReader::new(&parsed);
        let total_len = reader.len();
        prepare_zip_stream(&mut reader, total_len, eocd_offset).map(PasswordContext::Zip)
    })
}

pub(crate) fn zip_fast_verify_passwords_from_volumes(
    preparation: &mut Preparation,
    parts: &[InputPart],
    candidates: &[Arc<str>],
    eocd_offset: Option<u64>,
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let volumes = VolumeSet::new(parse_volumes(parts, sessions)?);
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
            prepare_zip_directory_stream(reader, len, eocd_offset, anchor.as_ref())
        });
        match directory {
            Ok(context) => Ok(Some(context)),
            Err(PreparedStatus::Status("invalid_volume_evidence", _)) => Ok(None),
            Err(_) if anchor.is_some() => Ok(anchor.clone()),
            Err(_) => {
                let context = if spanned {
                    prepare_zip_local_chain(|offset, size| {
                        let (disk, local) = reader.advance_disk_offset(0, 0, offset).ok()??;
                        reader.read_disk_spanning(disk, local, size).ok().filter(|bytes| bytes.len() == size)
                    })
                } else { prepare_zip_anchor(reader, len)? };
                context.map(Some).ok_or_else(|| PreparedStatus::new("unknown_needs_final_verifier", "no usable ZIP password evidence"))
            }
        }
    })?;
    match anchor {
        Some(anchor) if evidence.contexts.iter().all(|context| context == &anchor) =>
            evidence.with_anchor(PasswordContext::Zip(anchor)),
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
fn compare_zip_entry(central: &[u8], central_variable: &[u8], local: &[u8], local_variable: &[u8]) -> Result<(), PreparedStatus> {
    use crate::formats::zip::RelationLocalFields;
    let flags = le_u16(local, 6).unwrap();
    if flags & 0x2000 != 0 {
        return Err(PreparedStatus::new("unsupported_method", "ZIP local fields are masked"));
    }
    let central_name = le_u16(central, 28).unwrap() as usize;
    let local_name = le_u16(local, 26).unwrap() as usize;
    let mut local_sizes = [0; 46];
    if flags & 8 == 0 { local_sizes[20..28].copy_from_slice(&local[18..26]); }
    let cd = zip64::central_entry_values(central, &central_variable[central_name..]).ok_or_else(invalid_password_directory)?;
    let lf = zip64::central_entry_values(&local_sizes, &local_variable[local_name..]).ok_or_else(invalid_password_directory)?;
    let expected = RelationLocalFields::new(le_u16(central, 10).unwrap(), le_u16(central, 8).unwrap(),
        le_u32(central, 16).unwrap(), cd.compressed, cd.uncompressed);
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
impl ZipVolumeReader for VolumeSet {
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
        let bytes = reader.read_disk_spanning(disk, offset, size)
            .map_err(|error| ReadFault::from_io(error, "read_volume", offset, size, 0, length)
                .with_field(field, location).with_volume(disk as u32 + 1))?;
        if bytes.len() != size {
            return Err(ReadFault::short_read("read_volume", offset, size, bytes.len(), length)
                .with_field(field, location).with_volume(disk as u32 + 1));
        }
        Ok(bytes)
    }
}

fn prepare_zip_volumes(
    volumes: &VolumeSet,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    let prefix_len = volumes.contiguous_prefix_len();
    let mut local_fault = None;
    let context = prepare_zip_local_chain(|offset, size| {
        if offset.checked_add(size as u64)? > prefix_len { return None; }
        let (disk, local) = volumes.advance_disk_offset(0, 0, offset)?;
        match volumes.read_disk_spanning_field(disk, local, size, "zip.local_password_proof", FieldLocation::Head) {
            Ok(data) => Some(data),
            Err(fault) => { local_fault = Some(fault); None }
        }
    });
    if let Some(fault) = local_fault { return Err(fault.into()); }
    if let Some(context) = context { return Ok(context); }
    prepare_zip_volume_directory(volumes, eocd_offset, None)
}

fn prepare_zip_volume_directory(
    volumes: &impl ZipVolumeReader,
    eocd_offset: Option<u64>,
    anchor: Option<&ZipPasswordContext>,
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
    let mut fallback = None;
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
        if flags & 0x0001 != 0 {
            let (variable_disk, variable_offset) = volumes.advance_disk_offset(disk, offset, 46)
                .ok_or_else(invalid_password_directory)?;
            let variable = volumes.read_disk_spanning_field(variable_disk, variable_offset,
                (name_len + extra_len) as usize, "zip.central_directory.name_extra", FieldLocation::Tail)?;
            let values = zip64::central_entry_values(&fixed, &variable[name_len as usize..])
                .ok_or_else(invalid_password_directory)?;
            match prepare_zip_volume_entry_checked(volumes, values.disk as usize, values.local_offset, Some((&fixed, &variable))) {
                Ok(context) if anchor == Some(&context) => { fallback = Some(context); }
                Ok(context) => return Ok(context),
                Err(error @ PreparedStatus::Status("invalid_volume_evidence", _)) => return Err(error),
                Err(error) => { unavailable.get_or_insert(error); }
            }
        }
        let Some(next) = volumes.advance_disk_offset(disk, offset, record_len) else {
            return Err(PreparedStatus::new("needs_volume_or_tail_damaged", "zip central directory crosses unavailable data; missing volume or damaged tail field"));
        };
        (disk, offset) = next;
    }
    fallback.ok_or_else(|| unavailable.unwrap_or_else(|| PreparedStatus::new("not_required", "zip has no encrypted entries")))
}

#[cfg(test)]
fn prepare_zip_volume_entry(volumes: &impl ZipVolumeReader, disk: usize, local_offset: u64) -> Result<ZipPasswordContext, PreparedStatus> {
    prepare_zip_volume_entry_checked(volumes, disk, local_offset, None)
}

fn prepare_zip_volume_entry_checked(
    volumes: &impl ZipVolumeReader,
    disk: usize,
    local_offset: u64,
    central: Option<(&[u8], &[u8])>,
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
    if let Some((central, central_variable)) = central {
        compare_zip_entry(central, central_variable, &fixed, &variable)?;
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
    ZipEncryption::from_local(&fixed, extra)?.prepare(|size, field| {
        Ok(volumes.read_disk_spanning_field(data_disk, data_offset, size, field, FieldLocation::Body)?)
    })
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ZipPasswordContext {
    Aes {
        key_len: usize,
        salt: Vec<u8>,
        verifier: [u8; 2],
    },
    ZipCrypto {
        header: [u8; 12],
        check_byte: u8,
    },
}

impl ZipPasswordContext {
    fn aes(strength: u8, material: Vec<u8>) -> Result<Self, PreparedStatus> {
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
        })
    }

    pub(super) fn kdf_parameters(&self) -> Option<(usize, &[u8])> {
        match self {
            Self::Aes { key_len, salt, .. } => Some((*key_len, salt)),
            Self::ZipCrypto { .. } => None,
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
            } => verify_winzip_aes_candidates(candidates, *key_len, salt, verifier, cache),
            Self::ZipCrypto { header, check_byte } => {
                verify_zipcrypto_material(candidates, header, *check_byte)
            }
        }
    }
}

// A known logical anchor can provide password evidence without a tail or
// central directory. Never scan for signatures or guess descriptor boundaries.
fn prepare_zip_local_chain(mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>) -> Option<ZipPasswordContext> {
    let mut offset = 0u64;
    loop {
        if Cancellation::current().cancelled() { return None; }
        let mut fixed = read(offset, 30)?;
        if offset == 0 && fixed.starts_with(b"PK\x07\x08") {
            offset = 4;
            fixed = read(offset, 30)?;
        }
        let length = crate::formats::zip::relation_local_header_len(&fixed, 0)?;
        let bytes = if length == fixed.len() { fixed } else { read(offset, length)? };
        let flags = le_u16(&bytes, 6)?;
        let extra = &bytes[30 + usize::from(le_u16(&bytes, 26)?)..];
        let data_offset = offset.checked_add(length as u64)?;
        if flags & 1 != 0 {
            let encryption = ZipEncryption::from_local(&bytes, extra).ok()?;
            return encryption.prepare(|size, _| read(data_offset, size).ok_or_else(invalid_password_directory)).ok();
        }
        // Only authoritative sizes can advance this local walk. Reuse the
        // same ZIP64 sentinel interpretation as the relation local-key parser.
        if flags & 8 != 0 { return None; }
        let mut central = [0u8; 46];
        central[20..28].copy_from_slice(&bytes[18..26]);
        let size = zip64::central_entry_values(&central, extra)?.compressed;
        offset = data_offset.checked_add(size)?;
    }
}

enum ZipEncryption {
    Traditional(u8),
    Aes(u8),
}

impl ZipEncryption {
    fn from_local(fixed: &[u8], extra: &[u8]) -> Result<Self, PreparedStatus> {
        let flags = le_u16(fixed, 6).unwrap();
        if flags & (0x40 | 0x2000) != 0 {
            return Err(PreparedStatus::new("unsupported_method", "PKWARE strong encryption requires the native verifier"));
        }
        if le_u16(fixed, 8) == Some(99) {
            return parse_winzip_aes_strength(extra).map(Self::Aes).ok_or_else(||
                PreparedStatus::new("unsupported_method", "winzip AES extra field not found"));
        }
        Ok(Self::Traditional(if flags & 8 == 0 { fixed[17] } else { fixed[11] }))
    }

    fn prepare(self, read: impl FnOnce(usize, &'static str) -> Result<Vec<u8>, PreparedStatus>) -> Result<ZipPasswordContext, PreparedStatus> {
        match self {
            Self::Aes(strength) => {
                let (salt_len, _) = aes_lengths(strength).ok_or_else(||
                    PreparedStatus::new("unsupported_method", "unsupported winzip AES strength"))?;
                ZipPasswordContext::aes(strength, read(salt_len + 2, "zip.aes.salt_password_verifier")?)
            }
            Self::Traditional(check_byte) => {
                let header = read(12, "zip.zipcrypto.encryption_header")?.try_into().map_err(|_|
                    PreparedStatus::new("damaged", "zipcrypto password header is incomplete"))?;
                Ok(ZipPasswordContext::ZipCrypto { header, check_byte })
            }
        }
    }
}

fn prepare_zip_anchor<R: Read + Seek>(file: &mut R, total_len: u64) -> Result<Option<ZipPasswordContext>, PreparedStatus> {
    let mut local_fault = None;
    let context = prepare_zip_local_chain(|offset, size| {
        if offset.checked_add(size as u64)? > total_len { return None; }
        let result = (|| {
            seek_field(file, offset, total_len, "zip.local_password_proof", FieldLocation::Head)?;
            let mut bytes = vec![0; size];
            read_exact_field(file, &mut bytes, total_len, "zip.local_password_proof", FieldLocation::Head)?;
            Ok::<_, ReadFault>(bytes)
        })();
        match result {
            Ok(bytes) => Some(bytes),
            Err(fault) => { local_fault = Some(fault); None }
        }
    });
    if let Some(fault) = local_fault { return Err(fault.into()); }
    Ok(context)
}

fn prepare_zip_stream<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    if let Some(context) = prepare_zip_anchor(file, total_len)? { return Ok(context); }
    prepare_zip_directory_stream(file, total_len, eocd_offset, None)
}

struct ZipStream<'a, R> {
    file: std::cell::RefCell<&'a mut R>,
    length: u64,
}

impl<R: Read + Seek> ZipVolumeReader for ZipStream<'_, R> {
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
}

fn prepare_zip_directory_stream<R: Read + Seek>(file: &mut R, total_len: u64, eocd_offset: Option<u64>, anchor: Option<&ZipPasswordContext>) -> Result<ZipPasswordContext, PreparedStatus> {
    let stream = ZipStream { file: std::cell::RefCell::new(file), length: total_len };
    prepare_zip_volume_directory(&stream, eocd_offset, anchor)
}

type ZipKeyCache<'a> = super::evidence::SharedCandidateKeys<(usize, &'a [u8]), Option<[u8; 2]>>;

fn verify_winzip_aes_candidates(
    candidates: &[Arc<str>], key_len: usize, salt: &[u8], verifier: &[u8; 2],
    cache: Option<&ZipKeyCache>,
) -> std::io::Result<PasswordVerification> {
    let attempts = candidates.len();
    let cancellation = Cancellation::current();
    let slots = cache.and_then(|cache| cache.cells(&(key_len, salt), attempts));
    let check = |(index, password): (usize, &Arc<str>)| {
        let derive = || cancellation.run(|| winzip_aes_verifier(&zip_password_bytes(password), salt, key_len));
        let bytes = slots.map_or_else(derive, |slots| *slots[index].get_or_init(derive));
        (bytes.as_ref() == Some(verifier)).then_some(index)
    };
    let matched_indices: Vec<_> = if attempts >= AES_PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().filter_map(check).collect()
    } else {
        candidates.iter().enumerate().filter_map(check).collect()
    };
    cancellation.check_io()?;
    let result = if let Some(first) = matched_indices.first().copied() {
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
    Ok(result)
}

fn verify_zipcrypto_material(
    candidates: &[Arc<str>],
    encryption_header: &[u8; 12],
    check_byte: u8,
) -> std::io::Result<PasswordVerification> {
    let attempts = candidates.len();
    let cancellation = Cancellation::current();
    let check = |(index, password): (usize, &Arc<str>)| {
        (!cancellation.cancelled()
            && zipcrypto_header_matches(&zip_password_bytes(password), encryption_header, check_byte))
            .then_some(index)
    };
    let matched_indices: Vec<_> = if attempts >= ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().filter_map(check).collect()
    } else {
        candidates.iter().enumerate().filter_map(check).collect()
    };
    cancellation.check_io()?;

    let result = if let Some(first) = matched_indices.first().copied() {
        PasswordVerification {
            matched_index: Some(first),
            matched_indices,
            attempts,
            match_evidence: Some("zipcrypto_header_byte"),
            ..PasswordVerification::status("match", "zipcrypto password headers matched")
        }
    } else {
        PasswordVerification {
            attempts,
            ..PasswordVerification::status("no_match", "zipcrypto password header did not match")
        }
    };
    Ok(result)
}

fn parse_winzip_aes_strength(extra: &[u8]) -> Option<u8> {
    let mut offset = 0usize;
    while offset.checked_add(4)? <= extra.len() {
        let header_id = le_u16(extra, offset)?;
        let data_size = le_u16(extra, offset + 2)? as usize;
        let data_offset = offset.checked_add(4)?;
        let next = data_offset.checked_add(data_size)?;
        if next > extra.len() {
            return None;
        }
        if header_id == 0x9901 && data_size >= 7 {
            if !matches!(le_u16(extra, data_offset)?, 1 | 2)
                || extra.get(data_offset + 2..data_offset + 4)? != b"AE" {
                return None;
            }
            return extra.get(data_offset + 4).copied();
        }
        offset = next;
    }
    None
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
    Some([derived[offset % 20], derived[offset % 20 + 1]])
}

#[cfg(test)]
#[path = "../../tests/unit/password/zip/aes_verifier_tests.rs"]
mod aes_verifier_tests;

fn zipcrypto_header_matches(password: &[u8], encrypted_header: &[u8; 12], expected: u8) -> bool {
    let mut state = ZipCryptoState::new();
    for &byte in password { state.update_keys(byte); }
    let mut last = 0;
    for encrypted in encrypted_header {
        last = encrypted ^ state.decrypt_byte();
        state.update_keys(last);
    }
    last == expected
}

struct ZipCryptoState {
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
