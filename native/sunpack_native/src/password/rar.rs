use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::analysis_native::volume_anchor::rar5_main_volume;
use crate::password::input::{
    parse_ranges, parse_volumes, read_prefix_from_ranges_field, VolumeSet,
};
use crate::password::password_read_fault_status;
use aes::cipher::{
    block_padding::NoPadding, Block, BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit,
};
use aes::{Aes128, Aes256};
use cbc::Decryptor;
use crc32fast::hash as crc32_hash;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::io;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR_INITIAL_PREFIX_SCAN: usize = 16 * 1024;
const MAX_RAR_PREFIX_SCAN: usize = 1024 * 1024;
const RAR3_KDF_ITERATIONS: u32 = 0x40000;
const RAR4_MIN_HEADER_SIZE: usize = 7;
const RAR4_HP_DECRYPT_LIMIT: usize = 4096;
const PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const RAR4_MAIN_HEADER_PASSWORD: u16 = 0x0080;
const RAR4_FILE_PASSWORD: u16 = 0x0004;
const RAR4_FILE_LARGE: u16 = 0x0100;
const RAR4_FILE_SALT: u16 = 0x0400;
const RAR4_LONG_BLOCK: u16 = 0x8000;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcDecryptor = Decryptor<Aes128>;
type Aes256CbcDecryptor = Decryptor<Aes256>;

/// The result of walking a header-encrypted RAR stream far enough to prove
/// whether its ENDARC record is present.  This deliberately contains no
/// member data or Python observation fields: relation validation only needs
/// the terminal proof after the password has already been confirmed.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RarTerminalProof {
    pub(crate) end_block_found: bool,
    pub(crate) end_block_flags: u64,
}

fn decrypt_cbc_block<C>(cipher: &C, previous: &mut [u8; 16], encrypted: &[u8]) -> [u8; 16]
where
    C: BlockCipherDecrypt,
{
    let mut block = Block::<C>::default();
    block.copy_from_slice(encrypted);
    cipher.decrypt_block(&mut block);
    let mut plaintext = [0u8; 16];
    for (index, value) in plaintext.iter_mut().enumerate() {
        *value = block[index] ^ previous[index];
    }
    previous.copy_from_slice(encrypted);
    plaintext
}

fn decrypt_cbc_bytes<C>(cipher: &C, iv: &[u8; 16], encrypted: &[u8]) -> Vec<u8>
where
    C: BlockCipherDecrypt,
{
    let mut previous = *iv;
    encrypted
        .chunks_exact(16)
        .flat_map(|block| decrypt_cbc_block(cipher, &mut previous, block))
        .collect()
}

#[pyfunction]
pub(crate) fn rar_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let reader = ManagedReader::open(&archive_path)?;
    rar_fast_verify_passwords_with_reader(py, &reader, passwords)
}

pub(crate) fn rar_fast_verify_passwords_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let mut data = match py.detach(|| reader.read_at(0, RAR_INITIAL_PREFIX_SCAN)) {
        Ok(data) => data,
        Err(error) => {
            let fault = ReadFault::from_io(
                error,
                "read_at",
                0,
                RAR_INITIAL_PREFIX_SCAN,
                0,
                reader.len(),
            )
            .with_field("rar.header_prefix", FieldLocation::Head);
            return password_read_fault_status(py, &fault);
        }
    };
    if rar5_prefix_needs_extended_scan(&data) {
        data = match py.detach(|| reader.read_at(0, MAX_RAR_PREFIX_SCAN)) {
            Ok(data) => data,
            Err(error) => {
                let fault =
                    ReadFault::from_io(error, "read_at", 0, MAX_RAR_PREFIX_SCAN, 0, reader.len())
                        .with_field("rar.header_prefix", FieldLocation::Head);
                return password_read_fault_status(py, &fault);
            }
        };
    }
    if rar4_prefix_needs_extended_scan(&data) {
        data = match py.detach(|| reader.read_at(0, MAX_RAR_PREFIX_SCAN)) {
            Ok(data) => data,
            Err(error) => {
                let fault = ReadFault::from_io(
                    error,
                    "read_at",
                    0,
                    MAX_RAR_PREFIX_SCAN,
                    0,
                    reader.len(),
                )
                .with_field("rar4.encrypted_header", FieldLocation::Head);
                return password_read_fault_status(py, &fault);
            }
        };
    }
    if let Some(required) = rar4_data_prefix_requirement(&data) {
        if required > data.len() && required <= MAX_RAR_PREFIX_SCAN {
            data = match py.detach(|| reader.read_at(0, required)) {
                Ok(data) => data,
                Err(error) => {
                    let fault = ReadFault::from_io(
                        error,
                        "read_at",
                        0,
                        required,
                        0,
                        reader.len(),
                    )
                    .with_field("rar4.file_data", FieldLocation::Body);
                    return password_read_fault_status(py, &fault);
                }
            };
        }
    }
    verify_rar_data(py, &data, &candidates)
}

fn verify_rar_data(py: Python<'_>, data: &[u8], candidates: &[String]) -> PyResult<Py<PyAny>> {
    if data.starts_with(RAR5_SIGNATURE) {
        return verify_rar5(py, &data, &candidates);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        return verify_rar4(py, &data, &candidates);
    }
    if data.starts_with(b"Rar!") {
        let fault = ReadFault::short_read(
            "read_record",
            0,
            RAR5_SIGNATURE.len(),
            data.len(),
            data.len() as u64,
        )
        .with_field("rar.signature", FieldLocation::Head);
        return password_read_fault_status(py, &fault);
    }
    status(py, "unsupported_method", -1, 0, "rar signature not found")
}

#[pyfunction]
pub(crate) fn rar_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let mut data =
        match read_prefix_from_ranges_field(&parsed, RAR_INITIAL_PREFIX_SCAN, "rar.header_prefix") {
            Ok(data) => data,
            Err(fault) => return password_read_fault_status(py, &fault),
        };
    if rar5_prefix_needs_extended_scan(&data) {
        data = match read_prefix_from_ranges_field(
            &parsed,
            MAX_RAR_PREFIX_SCAN,
            "rar.header_prefix",
        ) {
            Ok(data) => data,
            Err(fault) => return password_read_fault_status(py, &fault),
        };
    }
    if rar4_prefix_needs_extended_scan(&data) {
        data = match read_prefix_from_ranges_field(
            &parsed,
            MAX_RAR_PREFIX_SCAN,
            "rar4.encrypted_header",
        ) {
            Ok(data) => data,
            Err(fault) => return password_read_fault_status(py, &fault),
        };
    }
    if let Some(required) = rar4_data_prefix_requirement(&data) {
        if required > data.len() && required <= MAX_RAR_PREFIX_SCAN {
            data = match read_prefix_from_ranges_field(&parsed, required, "rar4.file_data") {
                Ok(data) => data,
                Err(fault) => return password_read_fault_status(py, &fault),
            };
        }
    }
    verify_rar_data(py, &data, &candidates)
}

#[pyfunction]
pub(crate) fn rar_fast_verify_passwords_from_volumes(
    py: Python<'_>,
    parts: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let volumes = VolumeSet::new(parse_volumes(parts)?);
    let mut data = match py.detach(|| {
        volumes.first_prefix_field(RAR_INITIAL_PREFIX_SCAN, "rar.header_prefix")
    }) {
        Ok(data) => data,
        Err(fault) => return password_read_fault_status(py, &fault),
    };
    if rar5_prefix_needs_extended_scan(&data) {
        data = match py
            .detach(|| volumes.first_prefix_field(MAX_RAR_PREFIX_SCAN, "rar.header_prefix"))
        {
            Ok(data) => data,
            Err(fault) => return password_read_fault_status(py, &fault),
        };
    }
    if rar4_prefix_needs_extended_scan(&data) {
        data = match py
            .detach(|| volumes.first_prefix_field(MAX_RAR_PREFIX_SCAN, "rar4.encrypted_header"))
        {
            Ok(data) => data,
            Err(fault) => return password_read_fault_status(py, &fault),
        };
    }
    if let Some(required) = rar4_data_prefix_requirement(&data) {
        if required > data.len() && required <= MAX_RAR_PREFIX_SCAN {
            data = match py.detach(|| {
                volumes.first_prefix_field(required, "rar4.file_data")
            }) {
                Ok(data) => data,
                Err(fault) => return password_read_fault_status(py, &fault),
            };
        }
    }
    verify_rar_data(py, &data, &candidates)
}

fn rar5_prefix_needs_extended_scan(data: &[u8]) -> bool {
    data.starts_with(RAR5_SIGNATURE) && find_rar5_encryption_header(data).is_none()
}

fn rar4_prefix_needs_extended_scan(data: &[u8]) -> bool {
    data.starts_with(RAR4_SIGNATURE)
        && parse_rar4_block(data, RAR4_SIGNATURE.len())
            .is_some_and(|main| main.flags & RAR4_MAIN_HEADER_PASSWORD != 0)
}

#[derive(Clone, Copy)]
struct Rar4Block {
    header_type: u8,
    flags: u16,
    header_end: usize,
    next_offset: usize,
}

struct Rar4DataProbe {
    encrypted: bool,
    method: u8,
    pack_size: usize,
    unpacked_size: usize,
    file_crc: u32,
    data_offset: usize,
    data_end: usize,
    salt: Option<[u8; 8]>,
}

fn rar4_data_prefix_requirement(data: &[u8]) -> Option<usize> {
    parse_rar4_data_probe(data).map(|probe| probe.data_end)
}

/// Parse only the RAR4 metadata needed by the fast `-p` data verifier.
///
/// RAR4 does not carry a password-check value in an unencrypted file header.
/// The first encrypted file's packed data and CRC are therefore the smallest
/// deterministic verification unit.  This parser deliberately stops at the
/// first file header; it never guesses from arbitrary decrypted bytes.
fn parse_rar4_data_probe(data: &[u8]) -> Option<Rar4DataProbe> {
    if !data.starts_with(RAR4_SIGNATURE) {
        return None;
    }
    let main = parse_rar4_block(data, RAR4_SIGNATURE.len())?;
    if main.header_type != 0x73 || main.flags & RAR4_MAIN_HEADER_PASSWORD != 0 {
        return None;
    }
    if main.next_offset > data.len() {
        return None;
    }

    let mut offset = main.next_offset;
    for _ in 0..64 {
        let block = parse_rar4_block(data, offset)?;
        if block.header_type == 0x74 {
            return parse_rar4_file_probe(data, offset, block);
        }
        if block.header_type == 0x7b
            || block.next_offset <= offset
            || block.next_offset > data.len()
        {
            return None;
        }
        offset = block.next_offset;
    }
    None
}

fn parse_rar4_block(data: &[u8], offset: usize) -> Option<Rar4Block> {
    let header_end = offset.checked_add(RAR4_MIN_HEADER_SIZE)?;
    if header_end > data.len() {
        return None;
    }
    let header_type = data[offset + 2];
    if !(0x72..=0x7b).contains(&header_type) {
        return None;
    }
    let flags = u16::from_le_bytes([data[offset + 3], data[offset + 4]]);
    let header_size = u16::from_le_bytes([data[offset + 5], data[offset + 6]]) as usize;
    let header_end = offset.checked_add(header_size)?;
    if header_size < RAR4_MIN_HEADER_SIZE || header_end > data.len() {
        return None;
    }
    let computed_crc = (crc32(&data[offset + 2..header_end]) & 0xffff) as u16;
    let stored_crc = u16::from_le_bytes([data[offset], data[offset + 1]]);
    if computed_crc != stored_crc {
        return None;
    }
    let data_size = if flags & RAR4_LONG_BLOCK != 0 {
        if header_size < 11 {
            return None;
        }
        u32::from_le_bytes([
            data[offset + 7],
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
        ]) as usize
    } else {
        0
    };
    let next_offset = header_end.checked_add(data_size)?;
    Some(Rar4Block {
        header_type,
        flags,
        header_end,
        next_offset,
    })
}

/// Verify a RAR4 `-hp` password against the first encrypted block header.
///
/// In the normal RAR4 layout the Main Header remains plaintext and carries
/// MHD_PASSWORD; the salt is immediately after that header and all following
/// block headers are AES-CBC encrypted.  A few legacy inputs instead encrypt
/// the first header directly after the signature, so retain that form as a
/// fallback for the existing verifier path.
pub(crate) fn rar4_decrypt_header_flags(data: &[u8], password: &str) -> Option<u16> {
    let main = parse_rar4_block(data, RAR4_SIGNATURE.len());
    if let Some(main) = main.filter(|block| block.header_type == 0x73) {
        if main.flags & RAR4_MAIN_HEADER_PASSWORD == 0 {
            return None;
        }
        let encrypted_offset = main.next_offset.checked_add(8)?;
        let encrypted = data.get(encrypted_offset..)?;
        let first = decrypt_rar4_header(encrypted, password, &data[main.next_offset..])?;
        return (0x72..=0x7b)
            .contains(&first.header_type)
            .then_some(main.flags);
    }

    let payload = data.get(RAR4_SIGNATURE.len()..)?;
    let first = decrypt_rar4_header(payload.get(8..)?, password, &payload[..])?;
    (first.header_type == 0x73).then_some(first.flags)
}

fn decrypt_rar4_header(
    encrypted: &[u8],
    password: &str,
    salt_source: &[u8],
) -> Option<Rar4Block> {
    let salt: &[u8; 8] = salt_source.get(..8)?.try_into().ok()?;
    if encrypted.len() < 16 {
        return None;
    }
    let (key, iv) = derive_rar3_key_iv(password, Some(salt));
    let mut first_block = encrypted[..16].to_vec();
    let first_plaintext = Aes128CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut first_block)
        .ok()?;
    let header_size = u16::from_le_bytes([first_plaintext[5], first_plaintext[6]]) as usize;
    if header_size < RAR4_MIN_HEADER_SIZE {
        return None;
    }
    let decrypt_len = header_size.checked_add(15)? & !0x0f;
    if decrypt_len > encrypted.len() {
        return None;
    }
    let mut plaintext = encrypted[..decrypt_len].to_vec();
    let decrypted = Aes128CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut plaintext)
        .ok()?;
    parse_rar4_block(decrypted, 0)
}

fn parse_rar4_file_probe(
    data: &[u8],
    offset: usize,
    block: Rar4Block,
) -> Option<Rar4DataProbe> {
    if block.header_end < offset + 32 {
        return None;
    }
    let packed_low = u32::from_le_bytes([
        data[offset + 7],
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
    ]) as u64;
    let unpacked_low = u32::from_le_bytes([
        data[offset + 11],
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
    ]) as u64;
    let file_crc = u32::from_le_bytes([
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ]);
    let raw_method = data[offset + 25];
    let method = raw_method.checked_sub(0x30)?;
    let name_size = u16::from_le_bytes([data[offset + 26], data[offset + 27]]) as usize;

    let (packed_high, unpacked_high, name_start) = if block.flags & RAR4_FILE_LARGE != 0 {
        if block.header_end < offset + 40 {
            return None;
        }
        (
            u32::from_le_bytes([
                data[offset + 32],
                data[offset + 33],
                data[offset + 34],
                data[offset + 35],
            ]) as u64,
            u32::from_le_bytes([
                data[offset + 36],
                data[offset + 37],
                data[offset + 38],
                data[offset + 39],
            ]) as u64,
            offset + 40,
        )
    } else {
        (0, 0, offset + 32)
    };
    let name_end = name_start.checked_add(name_size)?;
    if name_end > block.header_end {
        return None;
    }
    if block.flags & RAR4_FILE_LARGE == 0 && unpacked_low == u32::MAX as u64 {
        return None;
    }
    let pack_size = usize::try_from((packed_high << 32) | packed_low).ok()?;
    let unpacked_size = usize::try_from((unpacked_high << 32) | unpacked_low).ok()?;
    let data_offset = block.header_end;
    let data_end = data_offset.checked_add(pack_size)?;
    let salt = if block.flags & RAR4_FILE_SALT != 0 {
        let salt_end = name_end.checked_add(8)?;
        if salt_end > block.header_end {
            return None;
        }
        Some(data[name_end..salt_end].try_into().ok()?)
    } else {
        None
    };
    Some(Rar4DataProbe {
        encrypted: block.flags & RAR4_FILE_PASSWORD != 0,
        method,
        pack_size,
        unpacked_size,
        file_crc,
        data_offset,
        data_end,
        salt,
    })
}

fn verify_rar4_stored_data(
    py: Python<'_>,
    data: &[u8],
    candidates: &[String],
    probe: &Rar4DataProbe,
) -> PyResult<Py<PyAny>> {
    if probe.method != 0 {
        return status(
            py,
            "unknown_needs_final_verifier",
            -1,
            0,
            "rar3/rar4 -p compressed data requires the full RAR decoder",
        );
    }
    if probe.pack_size == 0 || probe.unpacked_size > probe.pack_size {
        return status(
            py,
            "damaged",
            -1,
            0,
            "rar3/rar4 -p stored data has inconsistent packed and unpacked sizes",
        );
    }
    if probe.pack_size % 16 != 0 {
        return status(
            py,
            "damaged",
            -1,
            0,
            "rar3/rar4 -p stored data is not AES block aligned",
        );
    }
    if probe.data_end > MAX_RAR_PREFIX_SCAN {
        return status(
            py,
            "unknown_needs_final_verifier",
            -1,
            0,
            "rar3/rar4 -p stored data exceeds the fast verifier read bound",
        );
    }
    let Some(encrypted) = data.get(probe.data_offset..probe.data_end) else {
        let fault = ReadFault::short_read(
            "read_record",
            probe.data_offset as u64,
            probe.pack_size,
            data.len().saturating_sub(probe.data_offset),
            data.len() as u64,
        )
        .with_field("rar4.file_data", FieldLocation::Body);
        return password_read_fault_status(py, &fault);
    };
    let salt = probe.salt.as_ref();
    let expected_crc = probe.file_crc;
    let unpacked_size = probe.unpacked_size;
    let matched_index = py.detach(|| {
        let matches = |password: &String| {
            rar4_stored_password_matches(
                password,
                salt,
                encrypted,
                unpacked_size,
                expected_crc,
            )
        };
        if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
            candidates.par_iter().position_first(matches)
        } else {
            candidates.iter().position(matches)
        }
    });
    if let Some(index) = matched_index {
        return status_with_details(
            py,
            "match",
            index as i32,
            (index + 1) as i32,
            "rar3/rar4 -p stored file CRC matched",
            Some(false),
            Some("rar4_file_crc"),
        );
    }
    status_with_details(
        py,
        "no_match",
        -1,
        candidates.len() as i32,
        "rar3/rar4 -p stored file CRC did not match",
        Some(false),
        Some("rar4_file_crc"),
    )
}

fn rar4_stored_password_matches(
    password: &str,
    salt: Option<&[u8; 8]>,
    encrypted: &[u8],
    unpacked_size: usize,
    expected_crc: u32,
) -> bool {
    let (key, iv) = derive_rar3_key_iv(password, salt);
    let mut plaintext = encrypted.to_vec();
    let decrypted = match Aes128CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut plaintext)
    {
        Ok(decrypted) => decrypted,
        Err(_) => return false,
    };
    decrypted.len() >= unpacked_size && crc32(&decrypted[..unpacked_size]) == expected_crc
}

fn verify_rar4(py: Python<'_>, data: &[u8], candidates: &[String]) -> PyResult<Py<PyAny>> {
    let payload = &data[RAR4_SIGNATURE.len()..];
    if let Some(probe) = parse_rar4_data_probe(data) {
        if !probe.encrypted {
            return status(
                py,
                "not_required",
                -1,
                0,
                "rar3/rar4 file data is not encrypted",
            );
        }
        return verify_rar4_stored_data(py, data, candidates, &probe);
    }
    if let Some(_main) = parse_rar4_block(data, RAR4_SIGNATURE.len())
        .filter(|block| block.header_type == 0x73)
        .filter(|block| block.flags & RAR4_MAIN_HEADER_PASSWORD != 0)
    {
        let matched_index = py.detach(|| {
            if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
                candidates.par_iter().position_first(|password| {
                    rar4_decrypt_header_flags(data, password).is_some()
                })
            } else {
                candidates
                    .iter()
                    .position(|password| rar4_decrypt_header_flags(data, password).is_some())
            }
        });
        if let Some(index) = matched_index {
            return status_with_details(
                py,
                "match",
                index as i32,
                (index + 1) as i32,
                "rar3/rar4 -hp encrypted header matched",
                Some(true),
                Some("rar4_hp_header_crc16"),
                );
        }
        return status(
            py,
            "no_match",
            -1,
            candidates.len() as i32,
            "rar3/rar4 -hp encrypted header did not match",
        );
    }
    if parse_rar4_plain_header(payload).is_some() {
        return status(
            py,
            "not_required",
            -1,
            0,
            "rar3/rar4 headers are not encrypted; fast verifier only supports -hp encrypted headers",
        );
    }
    if payload.len() < 8 + 16 {
        let fault = ReadFault::short_read(
            "read_record",
            RAR4_SIGNATURE.len() as u64,
            24,
            payload.len(),
            data.len() as u64,
        )
        .with_field("rar4.encrypted_header.salt_block", FieldLocation::Head);
        return password_read_fault_status(py, &fault);
    }

    let mut salt = [0u8; 8];
    salt.copy_from_slice(&payload[..8]);
    let encrypted = &payload[8..];
    let decrypt_len = encrypted.len().min(RAR4_HP_DECRYPT_LIMIT) & !0x0f;
    if decrypt_len == 0 {
        return status(
            py,
            "unknown_needs_final_verifier",
            -1,
            0,
            "rar3/rar4 encrypted header data has no complete AES block",
        );
    }
    let encrypted_prefix = &encrypted[..decrypt_len];

    let matched_index = py.detach(|| {
        if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
            candidates.par_iter().position_first(|password| {
                rar3_hp_password_matches(password, &salt, encrypted_prefix)
            })
        } else {
            candidates
                .iter()
                .position(|password| rar3_hp_password_matches(password, &salt, encrypted_prefix))
        }
    });
    if let Some(index) = matched_index {
        return status_with_details(
            py,
            "match",
            index as i32,
            (index + 1) as i32,
            "rar3/rar4 -hp encrypted header matched",
            Some(true),
            Some("rar4_hp_header_crc16"),
            );
    }
    status(
        py,
        "no_match",
        -1,
        candidates.len() as i32,
        "rar3/rar4 -hp encrypted header did not match",
    )
}

fn rar3_hp_password_matches(password: &str, salt: &[u8; 8], encrypted_prefix: &[u8]) -> bool {
    let (key, iv) = derive_rar3_key_iv(password, Some(salt));
    let mut plaintext = encrypted_prefix.to_vec();
    let decrypted = match Aes128CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut plaintext)
    {
        Ok(decrypted) => decrypted,
        Err(_) => return false,
    };
    parse_rar4_plain_header(decrypted).is_some()
}

fn derive_rar3_key_iv(password: &str, salt: Option<&[u8; 8]>) -> ([u8; 16], [u8; 16]) {
    let mut password_bytes = Vec::with_capacity(password.len() * 2 + salt.map_or(0, |_| 8));
    for unit in password.encode_utf16() {
        password_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        password_bytes.extend_from_slice(salt);
    }

    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..RAR3_KDF_ITERATIONS {
        sha.update(&password_bytes);
        sha.update(&i.to_le_bytes()[..3]);
        if i & 0x3fff == 0 {
            let digest = sha.clone().finalize();
            iv[(i / 0x4000) as usize] = digest[19];
        }
    }
    let digest = sha.finalize();
    let mut key = [0u8; 16];
    for chunk in 0..4 {
        let src = chunk * 4;
        key[src] = digest[src + 3];
        key[src + 1] = digest[src + 2];
        key[src + 2] = digest[src + 1];
        key[src + 3] = digest[src];
    }
    (key, iv)
}

fn parse_rar4_plain_header(data: &[u8]) -> Option<Rar4Header> {
    if data.len() < RAR4_MIN_HEADER_SIZE {
        return None;
    }
    let stored_crc = u16::from_le_bytes([data[0], data[1]]);
    let header_type = data[2];
    if !(0x72..=0x7b).contains(&header_type) {
        return None;
    }
    let header_size = u16::from_le_bytes([data[5], data[6]]) as usize;
    if !(RAR4_MIN_HEADER_SIZE..=data.len()).contains(&header_size) {
        return None;
    }
    let computed_crc = (crc32(&data[2..header_size]) & 0xffff) as u16;
    if computed_crc != stored_crc {
        return None;
    }
    Some(Rar4Header {
        header_type,
        header_size,
    })
}

struct Rar4Header {
    #[allow(dead_code)]
    header_type: u8,
    #[allow(dead_code)]
    header_size: usize,
}

fn verify_rar5(py: Python<'_>, data: &[u8], candidates: &[String]) -> PyResult<Py<PyAny>> {
    let Some(header) = find_rar5_encryption_header(data) else {
        return status(
            py,
            "unknown_needs_final_verifier",
            -1,
            0,
            "rar5 password check header not found",
        );
    };
    if !header.has_password_check {
        return status(
            py,
            "unknown_needs_final_verifier",
            -1,
            0,
            "rar5 encryption header has no password check",
        );
    }
    let matched_index = py.detach(|| find_rar5_password_match(candidates, &header));
    if let Some(index) = matched_index {
        return status_with_details(
            py,
            "match",
            index as i32,
            (index + 1) as i32,
            "rar5 password check matched",
            Some(false),
            Some("rar5_password_check"),
            );
    }
    status(
        py,
        "no_match",
        -1,
        candidates.len() as i32,
        "rar5 password check did not match",
    )
}

fn find_rar5_password_match(candidates: &[String], header: &Rar5EncryptionHeader) -> Option<usize> {
    if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        candidates
            .par_iter()
            .position_first(|password| rar5_password_check_matches(password, header))
    } else {
        candidates
            .iter()
            .position(|password| rar5_password_check_matches(password, header))
    }
}

struct Rar5EncryptionHeader {
    lg2_count: u8,
    salt: [u8; 16],
    has_password_check: bool,
    password_check: [u8; 8],
    header_end: usize,
}

fn find_rar5_encryption_header(data: &[u8]) -> Option<Rar5EncryptionHeader> {
    let mut offset = RAR5_SIGNATURE.len();
    while offset + 6 <= data.len() {
        let stored_crc = le_u32(data, offset)?;
        let crc_start = offset + 4;
        let (header_size, after_size) = read_vint(data, crc_start)?;
        let header_size_vint_len = after_size.checked_sub(crc_start)?;
        let total_crc_bytes = header_size_vint_len.checked_add(header_size as usize)?;
        let crc_end = crc_start.checked_add(total_crc_bytes)?;
        if crc_end > data.len() {
            return None;
        }
        if crc32(&data[crc_start..crc_end]) != stored_crc {
            return None;
        }
        let (header_type, after_type) = read_vint(data, after_size)?;
        let (header_flags, mut cursor) = read_vint(data, after_type)?;
        let extra_area_size = if header_flags & 0x0001 != 0 {
            let (value, next) = read_vint(data, cursor)?;
            cursor = next;
            value
        } else {
            0
        };
        let data_area_size = if header_flags & 0x0002 != 0 {
            let (value, next) = read_vint(data, cursor)?;
            cursor = next;
            value
        } else {
            0
        };
        if header_type == 4 {
            return parse_rar5_encryption_body(data, cursor, crc_end);
        }
        if matches!(header_type, 2 | 3) && extra_area_size != 0 {
            if let Some(header) =
                parse_rar5_file_encryption_extra(data, cursor, crc_end, extra_area_size)
            {
                return Some(header);
            }
        }
        offset = crc_end.checked_add(usize::try_from(data_area_size).ok()?)?;
    }
    None
}

fn parse_rar5_file_encryption_extra(
    data: &[u8],
    mut offset: usize,
    header_end: usize,
    extra_area_size: u64,
) -> Option<Rar5EncryptionHeader> {
    let (file_flags, next) = read_vint_bounded(data, offset, header_end)?;
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Unpacked size.
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Attributes.
    offset = next;
    if file_flags & 0x0002 != 0 {
        offset = offset.checked_add(4)?;
    }
    if file_flags & 0x0004 != 0 {
        offset = offset.checked_add(4)?;
    }
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Compression information.
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Host OS.
    offset = next;
    let (name_size, next) = read_vint_bounded(data, offset, header_end)?;
    offset = next.checked_add(usize::try_from(name_size).ok()?)?;

    let extra_end = offset.checked_add(usize::try_from(extra_area_size).ok()?)?;
    if extra_end > header_end || offset > data.len() {
        return None;
    }
    while offset < extra_end {
        let (record_size, record_body) = read_vint_bounded(data, offset, extra_end)?;
        let record_end = record_body.checked_add(usize::try_from(record_size).ok()?)?;
        if record_end > extra_end {
            return None;
        }
        let (record_type, body) = read_vint_bounded(data, record_body, record_end)?;
        if record_type == 1 {
            return parse_rar5_file_encryption_body(data, body, record_end);
        }
        offset = record_end;
    }
    None
}

fn parse_rar5_file_encryption_body(
    data: &[u8],
    mut offset: usize,
    end: usize,
) -> Option<Rar5EncryptionHeader> {
    let (version, next) = read_vint_bounded(data, offset, end)?;
    if version != 0 {
        return None;
    }
    offset = next;
    let (flags, next) = read_vint_bounded(data, offset, end)?;
    offset = next;
    let lg2_count = *data.get(offset)?;
    offset += 1;
    if offset.checked_add(32)? > end {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[offset..offset + 16]);
    offset += 32; // Salt followed by the file encryption IV.

    let has_password_check = flags & 0x0001 != 0;
    let mut password_check = [0u8; 8];
    if has_password_check {
        if offset.checked_add(12)? > end {
            return None;
        }
        password_check.copy_from_slice(&data[offset..offset + 8]);
    }
    Some(Rar5EncryptionHeader {
        lg2_count,
        salt,
        has_password_check,
        password_check,
        header_end: 0,
    })
}

fn parse_rar5_encryption_body(
    data: &[u8],
    mut offset: usize,
    end: usize,
) -> Option<Rar5EncryptionHeader> {
    let (version, next) = read_vint(data, offset)?;
    if version != 0 {
        return None;
    }
    offset = next;
    let (flags, next) = read_vint(data, offset)?;
    offset = next;
    let lg2_count = *data.get(offset)?;
    offset += 1;
    if offset + 16 > end {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;
    let has_password_check = flags & 0x0001 != 0;
    let mut password_check = [0u8; 8];
    if has_password_check {
        if offset + 12 > end {
            return None;
        }
        password_check.copy_from_slice(&data[offset..offset + 8]);
    }
    Some(Rar5EncryptionHeader {
        lg2_count,
        salt,
        has_password_check,
        password_check,
        header_end: end,
    })
}

fn rar5_password_check_matches(password: &str, header: &Rar5EncryptionHeader) -> bool {
    if !header.has_password_check {
        return false;
    }
    let iterations = 1u32.checked_shl(header.lg2_count as u32).unwrap_or(0);
    if iterations == 0 {
        return false;
    }
    let password_bytes = password.as_bytes();
    let mut salt_extended = [0u8; 20];
    salt_extended[..16].copy_from_slice(&header.salt);
    salt_extended[19] = 1;

    // RAR's PBKDF2 uses the same HMAC key for every round. Clone the
    // precomputed inner/outer SHA-256 states, as the official UnRAR
    // implementation does, instead of rebuilding ipad/opad every time.
    let mac_template = match HmacSha256::new_from_slice(password_bytes) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    let mut mac = mac_template.clone();
    mac.update(&salt_extended);
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
    let mut final_hash = block;
    let round_counts = [iterations, 17, 17];
    let mut result2 = [0u8; 32];
    for (round_index, count) in round_counts.iter().enumerate() {
        for _ in 1..*count {
            let mut mac = mac_template.clone();
            mac.update(&block);
            block = mac.finalize().into_bytes().into();
            for (f, b) in final_hash.iter_mut().zip(block.iter()) {
                *f ^= *b;
            }
        }
        if round_index == 2 {
            result2 = final_hash;
        }
    }
    let mut derived_check = [0u8; 8];
    for (index, byte) in result2.iter().enumerate() {
        derived_check[index % 8] ^= *byte;
    }
    derived_check == header.password_check
}

/// Decrypt the RAR5 archive main header of a header-encrypted (-hp) archive.
///
/// The input must start at the RAR5 signature.  The unencrypted type-4
/// encryption header is followed by a 16-byte AES-256-CBC IV and then the
/// encrypted main header block (CRC + header fields), aligned to a 16-byte
/// boundary.  The AES key is the standard PBKDF2-HMAC-SHA256 of the password
/// with the stored 16-byte salt and 2^lg2_count iterations.
///
/// Returns `(archive_flags, volume_number)` parsed from the decrypted main
/// header, or `None` when no type-4 header exists, the password does not pass
/// the embedded password check, or the decrypted block fails CRC validation.
pub(crate) fn rar5_decrypt_main_header(
    data: &[u8],
    password: &str,
) -> Option<(u64, Option<u32>)> {
    let header = find_rar5_encryption_header(data)?;
    if !header.has_password_check || header.header_end == 0 {
        return None;
    }
    if !rar5_password_check_matches(password, &header) {
        return None;
    }
    let iterations = 1u32.checked_shl(header.lg2_count as u32).unwrap_or(0);
    if iterations == 0 {
        return None;
    }
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &header.salt, iterations, &mut key);

    let iv_offset = header.header_end;
    let iv: [u8; 16] = data.get(iv_offset..iv_offset.checked_add(16)?)?.try_into().ok()?;
    let ct_offset = iv_offset.checked_add(16)?;
    let available = data.len().saturating_sub(ct_offset);
    let block_count = (available / 16).min(8);
    if block_count == 0 {
        return None;
    }
    let decrypt_len = block_count * 16;
    let mut plaintext = data[ct_offset..ct_offset + decrypt_len].to_vec();
    let decrypted = Aes256CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut plaintext)
        .ok()?;
    rar5_main_volume(decrypted, 0)
}

/// Walk a header-encrypted RAR stream with a password that has already been
/// confirmed by the volume-anchor pass.  This is intentionally a relation
/// validator helper, not a second general RAR parser: it only understands the
/// header sizes, data spans, CRCs and ENDARC fields needed to prove terminal
/// completeness.
pub(crate) fn probe_header_encrypted_terminal(
    reader: &ManagedReader,
    start_offset: u64,
    password: &str,
    max_blocks: usize,
) -> io::Result<Option<RarTerminalProof>> {
    let signature = reader.read_at(start_offset, 8)?;
    if signature.starts_with(RAR5_SIGNATURE) {
        return probe_rar5_encrypted_terminal(reader, start_offset, password, max_blocks);
    }
    if signature.starts_with(RAR4_SIGNATURE) {
        return probe_rar4_encrypted_terminal(reader, start_offset, password, max_blocks);
    }
    Ok(None)
}

fn probe_rar5_encrypted_terminal(
    reader: &ManagedReader,
    start_offset: u64,
    password: &str,
    max_blocks: usize,
) -> io::Result<Option<RarTerminalProof>> {
    let block_offset = start_offset
        .checked_add(RAR5_SIGNATURE.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 offset overflow"))?;
    let prefix = reader.read_at(block_offset, 7)?;
    let Some((header_size, after_size)) = read_vint(&prefix, 4) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let size_bytes = after_size.saturating_sub(4);
    let total_size = 4usize
        .checked_add(size_bytes)
        .and_then(|value| value.checked_add(usize::try_from(header_size).ok()?));
    let Some(total_size) = total_size.filter(|size| (7..=2 * 1024 * 1024).contains(size)) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let full = reader.read_at(block_offset, total_size)?;
    if full.len() != total_size {
        return Ok(Some(RarTerminalProof::default()));
    }
    if crc32(&full[4..]) != u32::from_le_bytes([full[0], full[1], full[2], full[3]]) {
        return Ok(Some(RarTerminalProof::default()));
    }
    let Some((header_type, after_type)) = read_vint(&full, after_size) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let Some((_header_flags, after_flags)) = read_vint(&full, after_type) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    if header_type != 4 {
        return Ok(None);
    }
    let Some(header) = parse_rar5_encryption_body(&full, after_flags, full.len()) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    if !header.has_password_check || !rar5_password_check_matches(password, &header) {
        return Ok(None);
    }
    let iterations = 1u32
        .checked_shl(header.lg2_count as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid RAR5 KDF count"))?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &header.salt, iterations, &mut key);
    let encrypted_header_offset = block_offset
        .checked_add(total_size as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 IV offset overflow"))?;
    let cipher = Aes256::new_from_slice(&key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RAR5 AES key"))?;
    Ok(Some(walk_rar5_encrypted_headers(
        reader,
        encrypted_header_offset,
        &cipher,
        max_blocks,
    )?))
}

fn walk_rar5_encrypted_headers(
    reader: &ManagedReader,
    mut block_offset: u64,
    cipher: &Aes256,
    max_blocks: usize,
) -> io::Result<RarTerminalProof> {
    for _ in 0..max_blocks {
        let Some((full, next_header_offset)) =
            read_rar5_encrypted_header(reader, block_offset, cipher)?
        else {
            return Ok(RarTerminalProof::default());
        };
        let stored_crc = u32::from_le_bytes([full[0], full[1], full[2], full[3]]);
        let Some((_header_size, after_size)) = read_vint(&full, 4) else {
            return Ok(RarTerminalProof::default());
        };
        if crc32(&full[4..]) != stored_crc {
            return Ok(RarTerminalProof::default());
        }
        let Some((header_type, after_type)) = read_vint(&full, after_size) else {
            return Ok(RarTerminalProof::default());
        };
        let Some((header_flags, mut field_cursor)) = read_vint(&full, after_type) else {
            return Ok(RarTerminalProof::default());
        };
        if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
            return Ok(RarTerminalProof::default());
        }
        if header_flags & 0x0001 != 0 {
            let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                return Ok(RarTerminalProof::default());
            };
            field_cursor = after_extra;
        }
        let data_size = if header_flags & 0x0002 != 0 {
            let Some((value, _)) = read_vint(&full, field_cursor) else {
                return Ok(RarTerminalProof::default());
            };
            value
        } else {
            0
        };
        if header_type == 5 {
            let end_flags = read_vint(&full, field_cursor)
                .map(|(value, _)| value)
                .unwrap_or(0);
            return Ok(RarTerminalProof {
                end_block_found: true,
                end_block_flags: end_flags,
            });
        }
        block_offset = next_header_offset
            .checked_add(data_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 data offset overflow"))?;
    }
    Ok(RarTerminalProof::default())
}

fn read_rar5_encrypted_header(
    reader: &ManagedReader,
    block_offset: u64,
    cipher: &Aes256,
) -> io::Result<Option<(Vec<u8>, u64)>> {
    let iv = reader.read_at(block_offset, 16)?;
    if iv.len() != 16 {
        return Ok(None);
    }
    let mut iv_array = [0u8; 16];
    iv_array.copy_from_slice(&iv);
    let encrypted_offset = block_offset
        .checked_add(16)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 header offset overflow"))?;
    let first_ciphertext = reader.read_at(encrypted_offset, 16)?;
    if first_ciphertext.len() != 16 {
        return Ok(None);
    }
    let mut previous = iv_array;
    let first_plaintext = decrypt_cbc_block(cipher, &mut previous, &first_ciphertext);
    let Some((header_size, after_size)) = read_vint(&first_plaintext, 4) else {
        return Ok(None);
    };
    let size_bytes = after_size.saturating_sub(4);
    let Some(total_size) = 4usize
        .checked_add(size_bytes)
        .and_then(|value| value.checked_add(usize::try_from(header_size).ok()?))
        .filter(|size| (7..=2 * 1024 * 1024).contains(size))
    else {
        return Ok(None);
    };
    let aligned_size = total_size
        .checked_add(15)
        .map(|value| value & !15)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 header size overflow"))?;
    let encrypted = reader.read_at(encrypted_offset, aligned_size)?;
    if encrypted.len() != aligned_size {
        return Ok(None);
    }
    let plaintext = decrypt_cbc_bytes(cipher, &iv_array, &encrypted);
    Ok(Some((
        plaintext[..total_size].to_vec(),
        encrypted_offset
            .checked_add(aligned_size as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "RAR5 next header offset overflow")
            })?,
    )))
}

fn probe_rar4_encrypted_terminal(
    reader: &ManagedReader,
    start_offset: u64,
    password: &str,
    max_blocks: usize,
) -> io::Result<Option<RarTerminalProof>> {
    let block_offset = start_offset
        .checked_add(RAR4_SIGNATURE.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 offset overflow"))?;
    let prefix = reader.read_at(block_offset, RAR4_MIN_HEADER_SIZE)?;
    let Some(header_size) = prefix
        .get(5..7)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
        .filter(|size| (RAR4_MIN_HEADER_SIZE..=2 * 1024 * 1024).contains(size))
    else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let main_full = reader.read_at(block_offset, header_size)?;
    if main_full.len() != header_size {
        return Ok(Some(RarTerminalProof::default()));
    }
    let Some(main) = parse_rar4_block(&main_full, 0) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    if main.header_type != 0x73 || main.flags & RAR4_MAIN_HEADER_PASSWORD == 0 {
        return Ok(None);
    }
    let encrypted_header_offset = block_offset
        .checked_add(main.next_offset as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 salt offset overflow"))?;
    let salt = reader.read_at(encrypted_header_offset, 8)?;
    if salt.len() != 8 {
        return Ok(Some(RarTerminalProof::default()));
    }
    // A wrong password is rejected by the first decrypted block's type/CRC;
    // returning an inconclusive proof keeps relation fail-open.
    Ok(Some(walk_rar4_encrypted_headers(
        reader,
        encrypted_header_offset,
        password,
        max_blocks,
    )?))
}

fn walk_rar4_encrypted_headers(
    reader: &ManagedReader,
    mut block_offset: u64,
    password: &str,
    max_blocks: usize,
) -> io::Result<RarTerminalProof> {
    for _ in 0..max_blocks {
        let salt = reader.read_at(block_offset, 8)?;
        if salt.len() != 8 {
            return Ok(RarTerminalProof::default());
        }
        let salt: [u8; 8] = salt.try_into().expect("RAR4 salt length checked");
        let (key, iv) = derive_rar3_key_iv(password, Some(&salt));
        let cipher = Aes128::new_from_slice(&key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RAR4 AES key"))?;
        let encrypted_offset = block_offset
            .checked_add(8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 encrypted offset overflow"))?;
        let first_ciphertext = reader.read_at(encrypted_offset, 16)?;
        if first_ciphertext.len() != 16 {
            return Ok(RarTerminalProof::default());
        }
        let mut previous = iv;
        let first_plaintext = decrypt_cbc_block(&cipher, &mut previous, &first_ciphertext);
        let header_size = u16::from_le_bytes([first_plaintext[5], first_plaintext[6]]) as usize;
        if !(RAR4_MIN_HEADER_SIZE..=2 * 1024 * 1024).contains(&header_size) {
            return Ok(RarTerminalProof::default());
        }
        let aligned_size = header_size
            .checked_add(15)
            .map(|value| value & !15)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 header size overflow"))?;
        let encrypted = reader.read_at(encrypted_offset, aligned_size)?;
        if encrypted.len() != aligned_size {
            return Ok(RarTerminalProof::default());
        }
        let plaintext = decrypt_cbc_bytes(&cipher, &iv, &encrypted);
        let full = &plaintext[..header_size];
        let stored_crc = u16::from_le_bytes([full[0], full[1]]);
        let header_type = full[2];
        let header_flags = u16::from_le_bytes([full[3], full[4]]);
        if crc32(&full[2..]) as u16 != stored_crc || !(0x72..=0x7b).contains(&header_type) {
            return Ok(RarTerminalProof::default());
        }
        let data_size = if header_flags & RAR4_LONG_BLOCK != 0 {
            if full.len() < 11 {
                return Ok(RarTerminalProof::default());
            }
            u32::from_le_bytes([full[7], full[8], full[9], full[10]]) as u64
        } else {
            0
        };
        if header_type == 0x7b {
            return Ok(RarTerminalProof {
                end_block_found: true,
                end_block_flags: u64::from(header_flags),
            });
        }
        block_offset = encrypted_offset
            .checked_add(aligned_size as u64)
            .and_then(|value| value.checked_add(data_size))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 data offset overflow"))?;
    }
    Ok(RarTerminalProof::default())
}

fn status(
    py: Python<'_>,
    status: &str,
    matched_index: i32,
    attempts: i32,
    message: &str,
) -> PyResult<Py<PyAny>> {
    status_with_details(py, status, matched_index, attempts, message, None, None)
}

fn status_with_details(
    py: Python<'_>,
    status: &str,
    matched_index: i32,
    attempts: i32,
    message: &str,
    final_confirmation_required: Option<bool>,
    match_evidence: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("matched_index", matched_index)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", message)?;
    if let Some(value) = final_confirmation_required {
        result.set_item("final_confirmation_required", value)?;
    }
    if let Some(value) = match_evidence {
        result.set_item("match_evidence", value)?;
    }
    Ok(result.into())
}

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for index in offset..data.len().min(offset + 10) {
        let byte = data[index];
        if index == offset + 9 && (byte & 0x7E) != 0 {
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn read_vint_bounded(data: &[u8], offset: usize, end: usize) -> Option<(u64, usize)> {
    if offset >= end || end > data.len() {
        return None;
    }
    read_vint(&data[..end], offset)
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32_hash(bytes)
}

#[cfg(test)]
mod rar5_header_decryption_tests {
    use super::*;

    // Real RAR 5.60 -hp encrypted fixtures (password "secret") generated by
    // the bundled Rar.exe.  Single volume plus first/second split volumes.
    const SINGLE_HP_HEX: &str = "526172211a07010074de7b1c21040000010f7b64253244702e2a32eb93579555a37d38b616cb97898c463d3682920551724ed0c1c974029cc2b8ef8491fc816311daa1b0410f6115608170466e4948a8c6d4f17e28b08c727b4acfc116d3d075ce011963dc0c72e50a803d9036619810e92352e809830c9463ab4a0abdaab61e008218673e9c51409f76b2064bf7982e56d8173f1e387329bd5aca3bac49063545fcbfc19547d2be214b4fe1dae172b250e168f2a258548930b1763fb500c7869d70f2539d86fd19214dcc3bca1363154b0a0f2b0bba7dcc224ec1893cbc31cfa95158ccf5e96d74921de6f268ea4429e2ddf63d49220005742fef059f868372345f071322a7e690d56d5ac17b563fa9e923076fa2c58aa8e88e9843df17b7e79a30ca936d8215c92f6832f86887c3c3160ecfddfcdf7712382f84f39eb8";
    const PART1_HP_HEX: &str = "526172211a070100ba274f7921040000010fb5b78bc874c2401abc24a83cef823460c50737df44187dc3fa3a8316028f5a16a7ec9cd527eff412f0bd4f8e579a17b4f089c86869ed79e1eda2749f3ec19c16fa0a126c255e5a0ade47c823d3c82ddc00c1c6caebf6506ef16dd177984ee975d3669ff26194eee05db61c51b12d618f31b63f8edfe5828ad2c512093459f242c0b23a51614fe315c307cbdac485";
    const PART2_HP_HEX: &str = "526172211a070100ba274f7921040000010fb5b78bc874c2401abc24a83cef823460c50737df44187dc3fa3a831619b05ee4bf8e2194083d002591665679b4863aed78506ef5d174ab922c0c6c14e872055e0c440d2288a78fca53664503b46b93be4dc1f58098453bfc79bc498cb0cff26cdfadb5a13581c4bc1ae85166bbf4b013ccbd11873b02c45cbc42b8d64ca2effb581d24eddb503087a1cfb8599789";

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decrypts_real_hp_single_volume_main_header() {
        let data = hex_bytes(SINGLE_HP_HEX);
        let (archive_flags, number) = rar5_decrypt_main_header(&data, "secret").unwrap();
        assert_eq!(archive_flags & 0x0001, 0, "single volume must not be multivolume");
        assert_eq!(number, None);
    }

    #[test]
    fn decrypts_real_hp_split_volume_main_headers() {
        let first = hex_bytes(PART1_HP_HEX);
        let second = hex_bytes(PART2_HP_HEX);
        let (first_flags, first_number) = rar5_decrypt_main_header(&first, "secret").unwrap();
        let (second_flags, second_number) = rar5_decrypt_main_header(&second, "secret").unwrap();
        assert_eq!(first_flags & 0x0001, 0x0001);
        assert_eq!(first_number, None, "first volume has no volume number field");
        assert_eq!(second_flags & 0x0003, 0x0003);
        assert_eq!(second_number, Some(1));
    }

    #[test]
    fn rejects_wrong_password_before_decrypting() {
        let data = hex_bytes(SINGLE_HP_HEX);
        assert!(rar5_decrypt_main_header(&data, "not-the-password").is_none());
    }

    #[test]
    fn encrypted_header_walker_fails_open_on_incomplete_fixture() {
        let data = hex_bytes(PART2_HP_HEX);
        let reader = ManagedReader::from_bytes(data, Default::default());
        let proof = probe_header_encrypted_terminal(&reader, 0, "secret", 4096)
            .unwrap()
            .unwrap();
        assert!(!proof.end_block_found);
    }

}
