use super::PasswordVerification;
use crate::formats::zip::{zip64, RelationDirectory};
use crate::io::archive_state::{InputExtent, InputPart};
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
    let key = InputKey::file("zip", reader)?;
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
    let key = ranges_key("zip", &parsed)?;
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
    preparation.verify(volumes.key("zip")?, candidates, || {
        prepare_zip_volumes(&volumes, eocd_offset).map(PasswordContext::Zip)
    })
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
    eocd: u64,
    disk_starts: Option<&[u64]>,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, ReadFault>,
) -> Result<Option<(RelationDirectory, zip64::Locator)>, PreparedStatus> {
    let mut fault = None;
    let found = zip64::locate_end_record(eocd, disk_starts, |offset, size| {
        read(offset, size).map_err(|error| {
            fault = Some(error);
            std::io::Error::from(std::io::ErrorKind::InvalidData)
        })
    })
    .map_err(|()| {
        fault.map_or_else(
            || PreparedStatus::new("damaged", "invalid ZIP64 locator or end record"),
            PreparedStatus::from,
        )
    })?;
    let Some(found) = found else {
        return Ok(None);
    };
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
        found.locator,
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

fn password_entry_location(
    fixed: &[u8],
    read_extra: impl FnOnce() -> Result<Vec<u8>, PreparedStatus>,
) -> Result<(usize, u64), PreparedStatus> {
    let disk = le_u16(fixed, 34).unwrap();
    let offset = le_u32(fixed, 42).unwrap();
    if disk != u16::MAX && offset != u32::MAX {
        return Ok((usize::from(disk), u64::from(offset)));
    }
    let extra = read_extra()?;
    zip64::central_entry_values(fixed, &extra)
        .map(|values| (values.disk as usize, values.local_offset))
        .ok_or_else(|| PreparedStatus::new("damaged", "invalid ZIP64 central-directory entry"))
}

fn prepare_zip_volumes(
    volumes: &VolumeSet,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    volumes.require_contiguous()?;
    let last_disk = volumes.len() - 1;
    let (record, local_eocd): ([u8; 22], u64) = if let Some(offset) = eocd_offset {
        let (disk, local) = volumes.advance_disk_offset(0, 0, offset).ok_or_else(|| {
            PreparedStatus::new(
                "needs_volume_or_tail_damaged",
                "analyzed ZIP EOCD crosses unavailable volumes",
            )
        })?;
        // advance_disk_offset may return the previous disk's exact end.
        let local = if disk == last_disk {
            local
        } else if disk + 1 == last_disk && volumes.volume_len(disk) == Some(local) {
            0
        } else {
            return Err(PreparedStatus::new(
                "needs_volume_or_tail_damaged",
                "analyzed ZIP EOCD is outside the final volume",
            ));
        };
        let record = volumes.read_disk_spanning_field(
            last_disk,
            local,
            22,
            "zip.eocd",
            FieldLocation::Tail,
        )?;
        (record.as_slice().try_into().unwrap(), local)
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
        let local = volumes.volume_len(last_disk).unwrap() - tail.len() as u64 + offset as u64;
        (tail[offset..offset + 22].try_into().unwrap(), local)
    };
    let mut directory =
        password_directory(&record, local_eocd, volumes.volume_len(last_disk).unwrap())?;
    let mut boundary = (last_disk, local_eocd);
    let mut missing_zip64 = password_directory_needs_zip64(&directory);
    if missing_zip64 {
        let mut start = 0u64;
        let mut starts = Vec::with_capacity(volumes.len());
        for disk in 0..volumes.len() {
            starts.push(start);
            start = start
                .checked_add(volumes.volume_len(disk).unwrap())
                .ok_or_else(|| PreparedStatus::new("damaged", "ZIP volume offsets overflow"))?;
        }
        let absolute_eocd = starts[last_disk] + local_eocd;
        if let Some((resolved, locator)) =
            resolve_password_zip64(directory, absolute_eocd, Some(&starts), |offset, size| {
                let disk = starts.partition_point(|&start| start <= offset) - 1;
                volumes.read_disk_spanning_field(
                    disk,
                    offset - starts[disk],
                    size,
                    "zip.zip64_end_record",
                    FieldLocation::Tail,
                )
            })?
        {
            if locator.total_disks as usize != volumes.len() {
                return Err(PreparedStatus::new(
                    "needs_volume_or_tail_damaged",
                    "ZIP64 locator disk count differs from available volumes",
                ));
            }
            let disk = starts.partition_point(|&start| start <= resolved.end) - 1;
            boundary = (disk, resolved.end - starts[disk]);
            directory = resolved;
            missing_zip64 = false;
        }
    }
    if directory.disk as usize != last_disk {
        let fault = ReadFault::invalid_field(
            "validate_field",
            local_eocd + 4,
            2,
            volumes.volume_len(last_disk).unwrap(),
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
            let (entry_disk, local_offset) = password_entry_location(&fixed, || {
                let (extra_disk, extra_offset) = volumes
                    .advance_disk_offset(disk, offset, 46 + name_len)
                    .ok_or_else(invalid_password_directory)?;
                Ok(volumes.read_disk_spanning_field(
                    extra_disk,
                    extra_offset,
                    extra_len as usize,
                    "zip.central_directory.zip64_extra",
                    FieldLocation::Tail,
                )?)
            })?;
            return prepare_zip_volume_entry(volumes, entry_disk, local_offset);
        }
        let Some(next) = volumes.advance_disk_offset(disk, offset, record_len) else {
            return Err(PreparedStatus::new("needs_volume_or_tail_damaged", "zip central directory crosses unavailable data; missing volume or damaged tail field"));
        };
        (disk, offset) = next;
    }
    Err(PreparedStatus::new(
        "not_required",
        "zip has no encrypted entries",
    ))
}

fn prepare_zip_volume_entry(
    volumes: &VolumeSet,
    disk: usize,
    local_offset: u64,
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
    let flags = le_u16(&fixed, 6).unwrap_or(0);
    let method = le_u16(&fixed, 8).unwrap_or(0);
    let mod_time = le_u16(&fixed, 10).unwrap_or(0);
    let crc32 = le_u32(&fixed, 14).unwrap_or(0);
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
    if method == 99 {
        let Some(strength) = parse_winzip_aes_strength(extra) else {
            return Err(PreparedStatus::new(
                "unsupported_method",
                "winzip AES extra field not found",
            ));
        };
        let Some((salt_len, _)) = aes_lengths(strength) else {
            return Err(PreparedStatus::new(
                "unsupported_method",
                "unsupported winzip AES strength",
            ));
        };
        let material = match volumes.read_disk_spanning_field(
            data_disk,
            data_offset,
            salt_len + 2,
            "zip.aes.salt_password_verifier",
            FieldLocation::Body,
        ) {
            Ok(data) => data,
            Err(fault) => return Err(fault.into()),
        };
        return ZipPasswordContext::aes(strength, material);
    }
    let material = match volumes.read_disk_spanning_field(
        data_disk,
        data_offset,
        12,
        "zip.zipcrypto.encryption_header",
        FieldLocation::Body,
    ) {
        Ok(data) => data,
        Err(fault) => return Err(fault.into()),
    };
    let mut header = [0u8; 12];
    header.copy_from_slice(&material);
    let check_byte = if flags & 0x0008 != 0 {
        (mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    };
    Ok(ZipPasswordContext::ZipCrypto { header, check_byte })
}

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

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        match self {
            Self::Aes {
                key_len,
                salt,
                verifier,
            } => verify_winzip_aes_candidates(candidates, *key_len, salt, verifier),
            Self::ZipCrypto { header, check_byte } => {
                verify_zipcrypto_material(candidates, header, *check_byte)
            }
        }
    }
}

fn prepare_zip_stream<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
    eocd_offset: Option<u64>,
) -> Result<ZipPasswordContext, PreparedStatus> {
    if let Some(mut header) =
        locate_encrypted_entry_from_central_directory(file, total_len, eocd_offset)?
    {
        header.source_len = total_len;
        return prepare_zip_header(file, &header);
    }
    Err(PreparedStatus::new(
        "not_required",
        "ZIP central directory contains no encrypted entries",
    ))
}

fn prepare_zip_header<R: Read + Seek>(
    file: &mut R,
    header: &ZipLocalHeader,
) -> Result<ZipPasswordContext, PreparedStatus> {
    if !header.encrypted {
        return Err(PreparedStatus::new(
            "not_required",
            "zip entry is not encrypted",
        ));
    }
    if header.method == 99 {
        let strength = header.aes_strength.ok_or_else(|| {
            PreparedStatus::new("unsupported_method", "winzip aes extra field not found")
        })?;
        let (salt_len, _) = aes_lengths(strength).ok_or_else(|| {
            PreparedStatus::new("unsupported_method", "unsupported winzip aes strength")
        })?;
        let mut material = vec![0u8; salt_len + 2];
        seek_field(
            file,
            header.data_offset,
            header.source_len,
            "zip.aes.salt_password_verifier",
            FieldLocation::Body,
        )?;
        read_exact_field(
            file,
            &mut material,
            header.source_len,
            "zip.aes.salt_password_verifier",
            FieldLocation::Body,
        )?;
        return ZipPasswordContext::aes(strength, material);
    }
    let mut encryption_header = [0u8; 12];
    seek_field(
        file,
        header.data_offset,
        header.source_len,
        "zip.zipcrypto.encryption_header",
        FieldLocation::Body,
    )?;
    read_exact_field(
        file,
        &mut encryption_header,
        header.source_len,
        "zip.zipcrypto.encryption_header",
        FieldLocation::Body,
    )?;
    Ok(ZipPasswordContext::ZipCrypto {
        header: encryption_header,
        check_byte: header.check_byte,
    })
}

struct ZipLocalHeader {
    encrypted: bool,
    method: u16,
    aes_strength: Option<u8>,
    check_byte: u8,
    data_offset: u64,
    source_len: u64,
}

fn parse_local_header(bytes: &[u8], offset: usize) -> Option<ZipLocalHeader> {
    if offset.checked_add(30)? > bytes.len() {
        return None;
    }
    let flags = le_u16(bytes, offset + 6)?;
    let method = le_u16(bytes, offset + 8)?;
    let mod_time = le_u16(bytes, offset + 10)?;
    let crc32 = le_u32(bytes, offset + 14)?;
    let name_len = le_u16(bytes, offset + 26)? as usize;
    let extra_len = le_u16(bytes, offset + 28)? as usize;
    let extra_offset = offset.checked_add(30)?.checked_add(name_len)?;
    let data_offset = offset
        .checked_add(30)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    if data_offset > bytes.len() {
        return None;
    }
    let aes_strength = parse_winzip_aes_strength(bytes.get(extra_offset..data_offset)?);
    let check_byte = if flags & 0x0008 != 0 {
        (mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    };
    Some(ZipLocalHeader {
        encrypted: flags & 0x0001 != 0,
        method,
        aes_strength,
        check_byte,
        data_offset: data_offset as u64,
        source_len: bytes.len() as u64,
    })
}

fn locate_encrypted_entry_from_central_directory<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
    analyzed_eocd: Option<u64>,
) -> Result<Option<ZipLocalHeader>, PreparedStatus> {
    // Reuse the analyzed logical record; callers before planning share the ZIP locator.
    let (offset, record) = match analyzed_eocd {
        Some(offset) => {
            seek_field(file, offset, total_len, "zip.eocd", FieldLocation::Tail)?;
            let mut record = [0u8; 22];
            read_exact_field(
                file,
                &mut record,
                total_len,
                "zip.eocd",
                FieldLocation::Tail,
            )?;
            (offset, record)
        }
        None => {
            let tail_len = MAX_EOCD_SCAN.min(total_len as usize);
            if tail_len < 22 {
                return Err(
                    ReadFault::short_read("read_record", 0, 22, tail_len, total_len)
                        .with_field("zip.eocd", FieldLocation::Tail)
                        .into(),
                );
            }
            let tail_start = total_len.saturating_sub(tail_len as u64);
            seek_field(
                file,
                tail_start,
                total_len,
                "zip.eocd_search_window",
                FieldLocation::Tail,
            )?;
            let mut tail = vec![0u8; tail_len];
            read_exact_field(
                file,
                &mut tail,
                total_len,
                "zip.eocd_search_window",
                FieldLocation::Tail,
            )?;
            let eocd = crate::formats::zip::find_eocd_record(&tail, false)
                .or_else(|| crate::formats::zip::find_eocd_record(&tail, true))
                .ok_or_else(|| {
                    ReadFault::invalid_field(
                        "locate",
                        tail_start,
                        22,
                        total_len,
                        "ZIP EOCD was not found",
                    )
                    .with_field("zip.eocd", FieldLocation::Tail)
                })?;
            (
                tail_start + eocd.offset as u64,
                tail[eocd.offset..eocd.offset + 22].try_into().unwrap(),
            )
        }
    };
    let mut directory = password_directory(&record, offset, total_len)?;
    let mut missing_zip64 = password_directory_needs_zip64(&directory);
    if missing_zip64 {
        if let Some((resolved, locator)) =
            resolve_password_zip64(directory, offset, None, |at, size| {
                seek_field(
                    file,
                    at,
                    total_len,
                    "zip.zip64_end_record",
                    FieldLocation::Tail,
                )?;
                let mut bytes = vec![0; size];
                read_exact_field(
                    file,
                    &mut bytes,
                    total_len,
                    "zip.zip64_end_record",
                    FieldLocation::Tail,
                )?;
                Ok(bytes)
            })?
        {
            if locator.record_disk != 0 || locator.total_disks != 1 {
                return Err(invalid_password_directory());
            }
            directory = resolved;
            missing_zip64 = false;
        }
    }
    if directory.disk != 0 || directory.cd_disk != 0 {
        return Err(ReadFault::invalid_field(
            "parse_record",
            offset,
            22,
            total_len,
            "invalid single-disk ZIP EOCD",
        )
        .with_field("zip.eocd", FieldLocation::Tail)
        .into());
    }
    check_password_directory(
        &directory,
        directory
            .offset
            .checked_add(directory.size)
            .is_some_and(|end| end <= directory.end),
        missing_zip64,
    )?;
    let mut cursor = directory.offset;
    let mut remaining = directory.size;
    for _ in 0..directory.entries {
        let mut fixed = [0u8; 46];
        seek_field(
            file,
            cursor,
            total_len,
            "zip.central_directory.entry_fixed",
            FieldLocation::Tail,
        )?;
        read_exact_field(
            file,
            &mut fixed,
            total_len,
            "zip.central_directory.entry_fixed",
            FieldLocation::Tail,
        )?;
        if &fixed[..4] != ZIP_CENTRAL {
            return Err(ReadFault::invalid_field(
                "validate_signature",
                cursor,
                4,
                total_len,
                "invalid ZIP central-directory signature",
            )
            .with_field("zip.central_directory.entry_signature", FieldLocation::Tail)
            .into());
        }
        let flags = le_u16(&fixed, 8).unwrap();
        let name_len = le_u16(&fixed, 28).unwrap() as u64;
        let extra_len = le_u16(&fixed, 30).unwrap() as u64;
        let comment_len = le_u16(&fixed, 32).unwrap() as u64;
        let record_len = 46 + name_len + extra_len + comment_len;
        remaining = remaining
            .checked_sub(record_len)
            .ok_or_else(invalid_password_directory)?;
        if flags & 0x0001 != 0 {
            let (disk, local_offset) = password_entry_location(&fixed, || {
                let at = cursor + 46 + name_len;
                seek_field(
                    file,
                    at,
                    total_len,
                    "zip.central_directory.zip64_extra",
                    FieldLocation::Tail,
                )?;
                let mut bytes = vec![0; extra_len as usize];
                read_exact_field(
                    file,
                    &mut bytes,
                    total_len,
                    "zip.central_directory.zip64_extra",
                    FieldLocation::Tail,
                )?;
                Ok(bytes)
            })?;
            if disk != 0 {
                return Err(invalid_password_directory());
            }
            let mut local_fixed = [0u8; 30];
            seek_field(
                file,
                local_offset,
                total_len,
                "zip.local_header.fixed",
                FieldLocation::Body,
            )?;
            read_exact_field(
                file,
                &mut local_fixed,
                total_len,
                "zip.local_header.fixed",
                FieldLocation::Body,
            )?;
            if &local_fixed[..4] != ZIP_LOCAL {
                return Err(ReadFault::invalid_field(
                    "validate_signature",
                    local_offset,
                    4,
                    total_len,
                    "invalid ZIP local-header signature",
                )
                .with_field("zip.local_header.signature", FieldLocation::Body)
                .into());
            }
            let local_name_len = le_u16(&local_fixed, 26).unwrap() as usize;
            let local_extra_len = le_u16(&local_fixed, 28).unwrap() as usize;
            let mut local = Vec::with_capacity(30 + local_name_len + local_extra_len);
            local.extend_from_slice(&local_fixed);
            local.resize(30 + local_name_len + local_extra_len, 0);
            read_exact_field(
                file,
                &mut local[30..],
                total_len,
                "zip.local_header.name_extra",
                FieldLocation::Body,
            )?;
            let mut header = parse_local_header(&local, 0).ok_or_else(|| {
                ReadFault::invalid_field(
                    "parse_record",
                    local_offset,
                    local.len(),
                    total_len,
                    "invalid ZIP local header",
                )
                .with_field("zip.local_header", FieldLocation::Body)
            })?;
            header.data_offset = header.data_offset.saturating_add(local_offset);
            return Ok(Some(header));
        }
        cursor = cursor.checked_add(record_len).ok_or_else(|| {
            ReadFault::invalid_field(
                "advance",
                cursor,
                12,
                total_len,
                "ZIP central-directory entry length overflow",
            )
            .with_field("zip.central_directory.entry_length", FieldLocation::Tail)
        })?;
    }
    Ok(None)
}

fn verify_winzip_aes_candidates(
    candidates: &[Arc<str>],
    key_len: usize,
    salt: &[u8],
    verifier: &[u8; 2],
) -> std::io::Result<PasswordVerification> {
    let attempts = candidates.len();
    let cancellation = Cancellation::current();
    let matched_indices = (|| {
        let mut matched_indices = if candidates.len() >= AES_PARALLEL_PASSWORD_THRESHOLD {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    (!cancellation.cancelled()
                        && cancellation.run(|| {
                            winzip_aes_verifier_matches(
                                &zip_password_bytes(password),
                                salt,
                                verifier,
                                key_len,
                            )
                        }))
                    .then_some(index)
                })
                .collect::<Vec<_>>()
        } else {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    (!cancellation.cancelled()
                        && cancellation.run(|| {
                            winzip_aes_verifier_matches(
                                &zip_password_bytes(password),
                                salt,
                                verifier,
                                key_len,
                            )
                        }))
                    .then_some(index)
                })
                .collect::<Vec<_>>()
        };
        matched_indices.sort_unstable();
        matched_indices
    })();

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
    let matched_indices = (|| {
        let mut matched_indices = if candidates.len() >= ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    (!cancellation.cancelled()
                        && zipcrypto_header_matches(
                            &zip_password_bytes(password),
                            encryption_header,
                            check_byte,
                        ))
                    .then_some(index)
                })
                .collect::<Vec<_>>()
        } else {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    (!cancellation.cancelled()
                        && zipcrypto_header_matches(
                            &zip_password_bytes(password),
                            encryption_header,
                            check_byte,
                        ))
                    .then_some(index)
                })
                .collect::<Vec<_>>()
        };
        matched_indices.sort_unstable();
        matched_indices
    })();

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
            if extra.get(data_offset + 2..data_offset + 4)? != b"AE" {
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

fn winzip_aes_verifier_matches(
    password: &[u8],
    salt: &[u8],
    verifier: &[u8],
    key_len: usize,
) -> bool {
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
            return false;
        }
        let mut mac = template.clone();
        mac.update(&previous);
        previous = mac.finalize().into_bytes();
        for (value, byte) in derived.iter_mut().zip(previous.iter()) {
            *value ^= byte;
        }
    }
    &derived[offset % 20..offset % 20 + 2] == verifier
}

#[cfg(test)]
#[path = "../../tests/unit/password/zip/aes_verifier_tests.rs"]
mod aes_verifier_tests;

fn zipcrypto_header_matches(password: &[u8], encrypted_header: &[u8; 12], expected: u8) -> bool {
    let mut state = ZipCryptoState::new();
    for byte in password {
        state.update_keys(*byte);
    }
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
