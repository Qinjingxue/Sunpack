use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::password::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, ranges_total_len, VirtualRangeReader, VolumeSet,
};
use pbkdf2::pbkdf2_hmac;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use sha1::Sha1;
use std::io::{Read, Seek};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const MAX_PREFIX_SCAN: usize = 1024 * 1024;
const MAX_EOCD_SCAN: usize = 65_557;
const MAX_CENTRAL_SCAN: u64 = 16 * 1024 * 1024;
const AES_PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD: usize = 256;

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let reader = ManagedReader::open(&archive_path)?;
    zip_fast_verify_passwords_with_reader(py, &reader, passwords)
}

pub(crate) fn zip_fast_verify_passwords_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;

    let key = InputKey::file("zip", reader)?;
    verify_prepared(py, key, &candidates, || {
        prepare_zip_stream(&mut reader.cursor(), reader.len()).map(PasswordContext::Zip)
    })
}

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let total_len = ranges_total_len(&parsed);
    let key = ranges_key("zip", &parsed)?;
    verify_prepared(py, key, &candidates, || {
        prepare_zip_stream(&mut VirtualRangeReader::new(parsed.into()), total_len)
            .map(PasswordContext::Zip)
    })
}

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords_from_volumes(
    py: Python<'_>,
    parts: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let volumes = VolumeSet::new(parse_volumes(parts)?);
    verify_prepared(py, volumes.key("zip")?, &candidates, || {
        prepare_zip_volumes(&volumes).map(PasswordContext::Zip)
    })
}

fn prepare_zip_volumes(volumes: &VolumeSet) -> Result<ZipPasswordContext, PreparedStatus> {
    let tail = match volumes.read_last_tail_field(MAX_EOCD_SCAN, "zip.eocd_search_window") {
        Ok(tail) => tail,
        Err(fault) => return Err(fault.into()),
    };
    let Some(eocd_offset) = find_last_signature(&tail, ZIP_EOCD) else {
        let fault =
            ReadFault::invalid_field("locate", 0, 22, tail.len() as u64, "ZIP EOCD was not found")
                .with_field("zip.eocd", FieldLocation::Tail);
        return Err(fault.into());
    };
    if eocd_offset + 22 > tail.len() {
        let fault = ReadFault::short_read(
            "read_record",
            eocd_offset as u64,
            22,
            tail.len().saturating_sub(eocd_offset),
            tail.len() as u64,
        )
        .with_field("zip.eocd", FieldLocation::Tail);
        return Err(fault.into());
    }
    let disk_number = le_u16(&tail, eocd_offset + 4).unwrap_or(u16::MAX) as usize;
    let central_disk = le_u16(&tail, eocd_offset + 6).unwrap_or(u16::MAX) as usize;
    let total_entries = le_u16(&tail, eocd_offset + 10).unwrap_or(u16::MAX) as usize;
    let central_size = le_u32(&tail, eocd_offset + 12).unwrap_or(u32::MAX) as u64;
    let central_offset = le_u32(&tail, eocd_offset + 16).unwrap_or(u32::MAX) as u64;
    if disk_number + 1 != volumes.len() {
        let fault = ReadFault::invalid_field(
            "validate_field",
            eocd_offset as u64 + 4,
            2,
            tail.len() as u64,
            format!(
                "declared disk count {} does not match available volume count {}",
                disk_number + 1,
                volumes.len()
            ),
        )
        .with_field("zip.eocd.disk_number", FieldLocation::Tail);
        return Err(fault.into());
    }
    if total_entries == u16::MAX as usize
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
    {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            "zip64 spanned password probing is not supported",
        ));
    }
    if central_size > MAX_CENTRAL_SCAN {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            "zip central directory exceeds bounded probe budget",
        ));
    }

    let mut disk = central_disk;
    let mut offset = central_offset;
    for _ in 0..total_entries {
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
        let entry_disk = le_u16(&fixed, 34).unwrap_or(u16::MAX) as usize;
        let local_offset = le_u32(&fixed, 42).unwrap_or(u32::MAX) as u64;
        if flags & 0x0001 != 0 {
            if entry_disk == u16::MAX as usize || local_offset == u32::MAX as u64 {
                return Err(PreparedStatus::new(
                    "unknown_needs_final_verifier",
                    "zip64 encrypted entry location requires fallback",
                ));
            }
            return prepare_zip_volume_entry(volumes, entry_disk, local_offset);
        }
        let record_len = 46u64 + name_len + extra_len + comment_len;
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

    pub(crate) fn retained_bytes(&self) -> usize {
        match self {
            Self::Aes { salt, .. } => salt.len() + 2,
            Self::ZipCrypto { .. } => 12,
        }
    }

    pub(crate) fn verify(&self, py: Python<'_>, candidates: &[String]) -> PyResult<Py<PyAny>> {
        match self {
            Self::Aes {
                key_len,
                salt,
                verifier,
            } => verify_winzip_aes_candidates(py, candidates, *key_len, salt, verifier),
            Self::ZipCrypto { header, check_byte } => {
                verify_zipcrypto_material(py, candidates, header, *check_byte)
            }
        }
    }
}

fn prepare_zip_stream<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
) -> Result<ZipPasswordContext, PreparedStatus> {
    zip_tail_requirement(file, total_len)?;
    if let Some(mut header) = locate_encrypted_entry_from_central_directory(file, total_len)? {
        header.source_len = total_len;
        return prepare_zip_header(file, &header);
    }
    seek_field(
        file,
        0,
        total_len,
        "zip.local_header_scan",
        FieldLocation::Head,
    )?;
    let mut prefix = vec![0u8; total_len.min(MAX_PREFIX_SCAN as u64) as usize];
    read_exact_field(
        file,
        &mut prefix,
        total_len,
        "zip.local_header_scan",
        FieldLocation::Head,
    )?;
    let local_offset = find_signature(&prefix, ZIP_LOCAL).ok_or_else(|| {
        PreparedStatus::new("unsupported_method", "zip local header not found in prefix")
    })?;
    let mut header = parse_local_header(&prefix, local_offset).ok_or_else(|| {
        PreparedStatus::new("damaged", "zip local header is incomplete or malformed")
    })?;
    header.source_len = total_len;
    prepare_zip_header(file, &header)
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

fn zip_tail_requirement<R: Read + Seek>(file: &mut R, total_len: u64) -> Result<(), ReadFault> {
    let tail_len = MAX_EOCD_SCAN.min(total_len as usize);
    if tail_len < 22 {
        return Err(
            ReadFault::short_read("read_record", 0, 22, tail_len, total_len)
                .with_field("zip.eocd", FieldLocation::Tail),
        );
    }
    seek_field(
        file,
        total_len - tail_len as u64,
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
    let Some(eocd) = find_last_signature(&tail, ZIP_EOCD) else {
        return Err(ReadFault::invalid_field(
            "locate",
            total_len.saturating_sub(tail_len as u64),
            22,
            total_len,
            "ZIP EOCD was not found",
        )
        .with_field("zip.eocd", FieldLocation::Tail));
    };
    if eocd + 22 > tail.len() {
        return Err(ReadFault::short_read(
            "read_record",
            total_len - tail_len as u64 + eocd as u64,
            22,
            tail.len().saturating_sub(eocd),
            total_len,
        )
        .with_field("zip.eocd", FieldLocation::Tail));
    }
    Ok(())
}

fn locate_encrypted_entry_from_central_directory<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
) -> Result<Option<ZipLocalHeader>, ReadFault> {
    let tail_len = MAX_EOCD_SCAN.min(total_len as usize);
    let tail_start = total_len.saturating_sub(tail_len as u64);
    let mut tail = vec![0u8; tail_len];
    seek_field(
        file,
        tail_start,
        total_len,
        "zip.eocd_search_window",
        FieldLocation::Tail,
    )?;
    read_exact_field(
        file,
        &mut tail,
        total_len,
        "zip.eocd_search_window",
        FieldLocation::Tail,
    )?;
    let eocd = find_last_signature(&tail, ZIP_EOCD).ok_or_else(|| {
        ReadFault::invalid_field(
            "locate",
            tail_start,
            22,
            total_len,
            "ZIP EOCD was not found",
        )
        .with_field("zip.eocd", FieldLocation::Tail)
    })?;
    if eocd + 22 > tail.len()
        || le_u16(&tail, eocd + 4) != Some(0)
        || le_u16(&tail, eocd + 6) != Some(0)
    {
        return Err(ReadFault::short_read(
            "parse_record",
            tail_start + eocd as u64,
            22,
            tail.len().saturating_sub(eocd),
            total_len,
        )
        .with_field("zip.eocd", FieldLocation::Tail));
    }
    let total_entries = le_u16(&tail, eocd + 10).unwrap() as usize;
    let central_size = le_u32(&tail, eocd + 12).unwrap() as u64;
    let central_offset = le_u32(&tail, eocd + 16).unwrap() as u64;
    if total_entries == u16::MAX as usize
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
        || central_size > MAX_CENTRAL_SCAN
    {
        return Err(ReadFault::invalid_field(
            "validate_field",
            tail_start + eocd as u64 + 10,
            12,
            total_len,
            "ZIP central-directory location requires ZIP64 or exceeds the bounded probe",
        )
        .with_field("zip.eocd.central_directory_location", FieldLocation::Tail));
    }
    let mut cursor = central_offset;
    for _ in 0..total_entries {
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
            .with_field("zip.central_directory.entry_signature", FieldLocation::Tail));
        }
        let flags = le_u16(&fixed, 8).unwrap();
        let name_len = le_u16(&fixed, 28).unwrap() as u64;
        let extra_len = le_u16(&fixed, 30).unwrap() as u64;
        let comment_len = le_u16(&fixed, 32).unwrap() as u64;
        if flags & 0x0001 != 0 {
            let local_offset = le_u32(&fixed, 42).unwrap() as u64;
            if local_offset == u32::MAX as u64 {
                return Err(ReadFault::invalid_field(
                    "validate_field",
                    cursor + 42,
                    4,
                    total_len,
                    "ZIP64 local-header offset requires fallback",
                )
                .with_field(
                    "zip.central_directory.local_header_offset",
                    FieldLocation::Tail,
                ));
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
                .with_field("zip.local_header.signature", FieldLocation::Body));
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
        cursor = cursor
            .checked_add(46 + name_len + extra_len + comment_len)
            .ok_or_else(|| {
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
    py: Python<'_>,
    candidates: &[String],
    key_len: usize,
    salt: &[u8],
    verifier: &[u8; 2],
) -> PyResult<Py<PyAny>> {
    let attempts = candidates.len() as i32;
    let matched_indices = py.detach(|| {
        let mut matched_indices = if candidates.len() >= AES_PARALLEL_PASSWORD_THRESHOLD {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    winzip_aes_verifier_matches(password.as_bytes(), salt, verifier, key_len)
                        .then_some(index as i32)
                })
                .collect::<Vec<_>>()
        } else {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    winzip_aes_verifier_matches(password.as_bytes(), salt, verifier, key_len)
                        .then_some(index as i32)
                })
                .collect::<Vec<_>>()
        };
        matched_indices.sort_unstable();
        matched_indices
    });

    let result = PyDict::new(py);
    if let Some(first) = matched_indices.first().copied() {
        result.set_item("status", "match")?;
        result.set_item("matched_index", first)?;
        result.set_item("matched_indices", matched_indices)?;
        result.set_item("attempts", attempts)?;
        result.set_item("match_evidence", "winzip_aes_password_verifier")?;
        result.set_item("message", "winzip aes password verifiers matched")?;
        return Ok(result.into());
    }
    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", "winzip aes password verifier did not match")?;
    Ok(result.into())
}

fn verify_zipcrypto_material(
    py: Python<'_>,
    candidates: &[String],
    encryption_header: &[u8; 12],
    check_byte: u8,
) -> PyResult<Py<PyAny>> {
    let attempts = candidates.len() as i32;
    let matched_indices = py.detach(|| {
        let mut matched_indices = if candidates.len() >= ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD {
            candidates
                .par_iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    zipcrypto_header_matches(password.as_bytes(), encryption_header, check_byte)
                        .then_some(index as i32)
                })
                .collect::<Vec<_>>()
        } else {
            candidates
                .iter()
                .enumerate()
                .filter_map(|(index, password)| {
                    zipcrypto_header_matches(password.as_bytes(), encryption_header, check_byte)
                        .then_some(index as i32)
                })
                .collect::<Vec<_>>()
        };
        matched_indices.sort_unstable();
        matched_indices
    });

    let result = PyDict::new(py);
    if let Some(first) = matched_indices.first().copied() {
        result.set_item("status", "match")?;
        result.set_item("matched_index", first)?;
        result.set_item("matched_indices", matched_indices)?;
        result.set_item("attempts", attempts)?;
        result.set_item("match_evidence", "zipcrypto_header_byte")?;
        result.set_item("message", "zipcrypto password headers matched")?;
        return Ok(result.into());
    }
    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", "zipcrypto password header did not match")?;
    Ok(result.into())
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

fn winzip_aes_verifier_matches(
    password: &[u8],
    salt: &[u8],
    verifier: &[u8],
    key_len: usize,
) -> bool {
    let mut derived = vec![0u8; key_len * 2 + 2];
    pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut derived);
    &derived[key_len * 2..key_len * 2 + 2] == verifier
}

fn zipcrypto_header_matches(password: &[u8], encrypted_header: &[u8; 12], expected: u8) -> bool {
    let mut state = ZipCryptoState::new();
    for byte in password {
        state.update_keys(*byte);
    }
    let mut plain = [0u8; 12];
    for (idx, encrypted) in encrypted_header.iter().enumerate() {
        let decrypted = encrypted ^ state.decrypt_byte();
        state.update_keys(decrypted);
        plain[idx] = decrypted;
    }
    plain[11] == expected
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

fn crc32_update(crc: u32, byte: u8) -> u32 {
    let mut value = crc ^ byte as u32;
    for _ in 0..8 {
        if value & 1 != 0 {
            value = (value >> 1) ^ 0xedb8_8320;
        } else {
            value >>= 1;
        }
    }
    value
}

fn find_signature(bytes: &[u8], signature: &[u8]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .position(|window| window == signature)
}

fn find_last_signature(bytes: &[u8], signature: &[u8]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .rposition(|window| window == signature)
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
