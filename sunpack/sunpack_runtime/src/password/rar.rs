use super::PasswordVerification;
use crate::formats::rar::{rar4_end_volume, rar5_header_len, rar5_main_volume, read_vint};
use crate::io::archive_state::{InputExtent, InputPart};
use crate::io::cancellation::{is_cancellation, Cancellation};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::io::scratch::{Blob, Spool};
use crate::password::context::{verify_prepared, InputKey, PasswordContext, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, read_ranges_at_field, VolumeSet,
};
use aes::cipher::{
    block_padding::NoPadding, Block, BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit,
};
use aes::{Aes128, Aes256};
use cbc::Decryptor;
use crc32fast::hash as crc32_hash;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::io;
use std::io::Write;
use std::sync::Arc;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR_INITIAL_PREFIX_SCAN: usize = 16 * 1024;
const RAR3_KDF_ITERATIONS: u32 = 0x40000;
const RAR4_MIN_HEADER_SIZE: usize = 7;
const PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const RAR5_MAX_KDF_LOG: u8 = 24;
const RAR4_MAIN_HEADER_PASSWORD: u16 = 0x0080;
const RAR4_FILE_PASSWORD: u16 = 0x0004;
const RAR4_FILE_LARGE: u16 = 0x0100;
const RAR4_FILE_SALT: u16 = 0x0400;
#[cfg(test)]
const RAR4_LONG_BLOCK: u16 = 0x8000;
const RAR4_FILE_DIRECTORY_MASK: u16 = 0x00e0;
const RAR4_END_NEXT_VOLUME: u16 = 0x0001;
/// Plaintext headers walked before deferring to the final verifier.
/// One read normally covers a whole RAR4 block header.
const RAR4_HEADER_READ_HINT: usize = 512;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcDecryptor = Decryptor<Aes128>;

/// The result of walking a header-encrypted RAR stream far enough to prove
/// whether its ENDARC record is present.  This deliberately contains no
/// member data or diagnostic fields: relation validation only needs
/// the terminal proof after the password has already been confirmed.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RarTerminalProof {
    pub(crate) password_matched: bool,
    pub(crate) password_rejected: bool,
    pub(crate) end_block_found: bool,
    pub(crate) end_block_flags: u64,
    pub(crate) end_offset: Option<u64>,
    pub(crate) volume_number: Option<u32>,
    pub(crate) main_volume: Option<(u64, Option<u32>)>,
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

pub(crate) fn rar_fast_verify_passwords_with_reader(
    reader: &ManagedReader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    verify_prepared(InputKey::file("rar", reader)?, candidates, || {
        prepare_rar(|offset, len, field| {
            reader.read_at(offset, len).map_err(|error| {
                ReadFault::from_io(error, "read_at", offset, len, 0, reader.len())
                    .with_field(field, FieldLocation::Head)
            })
        })
        .map(PasswordContext::Rar)
    })
}

pub(crate) fn rar_fast_verify_passwords_from_ranges(
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed = parse_ranges(ranges, sessions)?;
    verify_prepared(ranges_key("rar", &parsed)?, candidates, || {
        prepare_rar(|offset, len, field| read_ranges_at_field(&parsed, offset, len, field))
            .map(PasswordContext::Rar)
    })
}

pub(crate) fn rar_fast_verify_passwords_from_volumes(
    parts: &[InputPart],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let volumes = VolumeSet::new(parse_volumes(parts, sessions)?);
    verify_prepared(volumes.key("rar")?, candidates, || {
        volumes.require_contiguous()?;
        prepare_rar(|offset, len, field| volumes.first_volume_read_at_field(offset, len, field))
            .map(PasswordContext::Rar)
    })
}

/// `read_at(offset, len, field)` returns fewer than `len` bytes only at the end
/// of the input.
fn prepare_rar(
    mut read_at: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<RarPasswordContext, PreparedStatus> {
    let mut data = read_at(0, RAR_INITIAL_PREFIX_SCAN, "rar.header_prefix")?;
    if data.starts_with(RAR5_SIGNATURE) {
        return prepare_rar5_stream(&mut read_at);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        if let Some(header) = read_rar4_header_at(&data, RAR4_SIGNATURE.len() as u64, &mut read_at)?
        {
            if header.len() + RAR4_SIGNATURE.len() > data.len() {
                data = read_at(0, header.len() + RAR4_SIGNATURE.len(), "rar4.main_header")?;
            }
            if let Some(main) = rar4_plain_main_header(&data) {
                return prepare_rar4_file_data(&data, main, &mut read_at)
                    .map(|material| RarPasswordContext { material });
            }
            // RAR4's encrypted header length is a u16; read one maximum-width
            // header plus salt, independent of archive or payload size.
            if let Some(main) = parse_rar4_block(&data, RAR4_SIGNATURE.len()) {
                data = read_at(
                    0,
                    main.next_offset.saturating_add(8 + 65536),
                    "rar4.encrypted_header",
                )?;
            }
        }
    }
    prepare_rar_data(&data)
}

fn prepare_rar5_stream(
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<RarPasswordContext, PreparedStatus> {
    let unknown = || {
        PreparedStatus::new(
            "unknown_needs_final_verifier",
            "RAR5 encryption metadata is unavailable",
        )
    };
    let mut offset = RAR5_SIGNATURE.len() as u64;
    loop {
        let fixed = read_at(offset, 64, "rar5.block_header")?;
        let (size, after_size) = read_vint(&fixed, 4).ok_or_else(unknown)?;
        if after_size - 4 > 3 {
            return Err(unknown());
        } // RAR5 header-size field width.
        let length = after_size
            .checked_add(usize::try_from(size).map_err(|_| unknown())?)
            .ok_or_else(unknown)?;
        let mut header = if fixed.len() >= length {
            fixed
        } else {
            read_at(offset, length, "rar5.block_header")?
        };
        if header.len() < length || length < after_size {
            return Err(unknown());
        }
        header.truncate(length);
        if crc32(&header[4..]) != le_u32(&header, 0).ok_or_else(unknown)? {
            return Err(PreparedStatus::new("damaged", "RAR5 header CRC mismatch"));
        }
        let (kind, after_type) = read_vint(&header, after_size).ok_or_else(unknown)?;
        let (flags, mut position) = read_vint(&header, after_type).ok_or_else(unknown)?;
        if flags & 1 != 0 {
            position = read_vint(&header, position).ok_or_else(unknown)?.1;
        }
        let data_size = if flags & 2 != 0 {
            read_vint(&header, position).ok_or_else(unknown)?.0
        } else {
            0
        };
        let mut prefixed = Vec::with_capacity(8 + header.len());
        prefixed.extend_from_slice(RAR5_SIGNATURE);
        prefixed.extend_from_slice(&header);
        if let Some(encryption) = find_rar5_encryption_header(&prefixed) {
            if !encryption.has_password_check {
                return Err(unknown());
            }
            return Ok(RarPasswordContext {
                material: RarPasswordMaterial::Rar5(encryption),
            });
        }
        if kind == 5 {
            return Err(PreparedStatus::new(
                "not_required",
                "RAR5 headers contain no encrypted entries",
            ));
        }
        offset = offset
            .checked_add(length as u64)
            .and_then(|value| value.checked_add(data_size))
            .ok_or_else(unknown)?;
    }
}

/// A plaintext RAR4 main header without MHD_PASSWORD: file headers are
/// readable and only per-file `-p` encryption is possible.
fn rar4_plain_main_header(data: &[u8]) -> Option<Rar4Block> {
    if !data.starts_with(RAR4_SIGNATURE) {
        return None;
    }
    parse_rar4_block(data, RAR4_SIGNATURE.len())
        .filter(|block| block.header_type == 0x73 && block.flags & RAR4_MAIN_HEADER_PASSWORD == 0)
}

enum Rar4EncryptionScan {
    /// First encrypted file whose stored payload can prove a password.
    Encrypted { offset: u64, header: Vec<u8> },
    /// The final ENDARC was reached and no file header is encrypted.
    NotEncrypted,
    /// Encryption cannot be decided from bounded header reads.
    Unknown,
}

/// Walk plaintext RAR4 block headers by seeking over payloads.  Only headers
/// are read, so the cost is independent of member sizes; headers inside the
/// already-read prefix cost no I/O at all.
fn scan_rar4_file_encryption(
    prefix: &[u8],
    main: Rar4Block,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<Rar4EncryptionScan, ReadFault> {
    let mut offset = main.next_offset as u64;
    let mut saw_unprovable_encrypted = false;
    loop {
        let Some(header) = read_rar4_header_at(prefix, offset, read_at)? else {
            return Ok(Rar4EncryptionScan::Unknown);
        };
        let Some(block) = parse_rar4_block(&header, 0) else {
            return Ok(Rar4EncryptionScan::Unknown);
        };
        let mut data_size = (block.next_offset - block.header_end) as u64;
        match block.header_type {
            0x74 => {
                if block.flags & RAR4_FILE_LARGE != 0 {
                    let Some(high) = header.get(32..36) else {
                        return Ok(Rar4EncryptionScan::Unknown);
                    };
                    data_size |= (u32::from_le_bytes(high.try_into().unwrap()) as u64) << 32;
                }
                if block.flags & RAR4_FILE_PASSWORD != 0 {
                    // Directories and empty files carry no payload to verify.
                    if data_size > 0
                        && block.flags & RAR4_FILE_DIRECTORY_MASK != RAR4_FILE_DIRECTORY_MASK
                    {
                        return Ok(Rar4EncryptionScan::Encrypted { offset, header });
                    }
                    saw_unprovable_encrypted = true;
                }
            }
            0x7b => {
                return Ok(
                    if block.flags & RAR4_END_NEXT_VOLUME == 0 && !saw_unprovable_encrypted {
                        Rar4EncryptionScan::NotEncrypted
                    } else {
                        Rar4EncryptionScan::Unknown
                    },
                );
            }
            _ => {}
        }
        let Some(next) = offset
            .checked_add(header.len() as u64)
            .and_then(|value| value.checked_add(data_size))
        else {
            return Ok(Rar4EncryptionScan::Unknown);
        };
        offset = next;
    }
}

/// Return exactly one declared RAR4 block header, or `None` at end of input.
fn read_rar4_header_at(
    prefix: &[u8],
    offset: u64,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<Option<Vec<u8>>, ReadFault> {
    // Serve the header from the prefix whenever it is fully inside it.
    let in_prefix = usize::try_from(offset).ok().and_then(|start| {
        Some((
            start,
            prefix.get(start..start.checked_add(RAR4_MIN_HEADER_SIZE)?)?,
        ))
    });
    if let Some((start, fixed)) = in_prefix {
        let header_size = u16::from_le_bytes([fixed[5], fixed[6]]) as usize;
        if header_size < RAR4_MIN_HEADER_SIZE {
            return Ok(None);
        }
        if let Some(header) = prefix.get(start..start + header_size) {
            return Ok(Some(header.to_vec()));
        }
    }
    let mut buffer = read_at(offset, RAR4_HEADER_READ_HINT, "rar4.block_header")?;
    if buffer.len() < RAR4_MIN_HEADER_SIZE {
        return Ok(None);
    }
    let header_size = u16::from_le_bytes([buffer[5], buffer[6]]) as usize;
    if header_size < RAR4_MIN_HEADER_SIZE {
        return Ok(None);
    }
    if buffer.len() < header_size {
        buffer = read_at(offset, header_size, "rar4.block_header")?;
        if buffer.len() < header_size {
            return Ok(None);
        }
    }
    buffer.truncate(header_size);
    Ok(Some(buffer))
}

fn prepare_rar4_file_data(
    prefix: &[u8],
    main: Rar4Block,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<RarPasswordMaterial, PreparedStatus> {
    let (offset, header) = match scan_rar4_file_encryption(prefix, main, read_at)? {
        Rar4EncryptionScan::Encrypted { offset, header } => (offset, header),
        Rar4EncryptionScan::NotEncrypted => {
            return Err(PreparedStatus::new(
                "not_required",
                "rar3/rar4 file headers are not encrypted",
            ))
        }
        Rar4EncryptionScan::Unknown => {
            return Err(PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar3/rar4 file encryption cannot be proven from bounded header reads",
            ))
        }
    };
    let probe = parse_rar4_block(&header, 0)
        .and_then(|block| parse_rar4_file_probe(&header, 0, block))
        .ok_or_else(|| {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar3/rar4 encrypted file header is not supported by the fast verifier",
            )
        })?;
    if probe.method != 0 {
        return Err(PreparedStatus::new(
            "unknown_needs_final_verifier",
            "rar3/rar4 -p compressed data requires the full RAR decoder",
        ));
    }
    if probe.unpacked_size > probe.pack_size {
        return Err(PreparedStatus::new(
            "damaged",
            "rar3/rar4 -p stored data has inconsistent packed and unpacked sizes",
        ));
    }
    if probe.pack_size % 16 != 0 {
        return Err(PreparedStatus::new(
            "damaged",
            "rar3/rar4 -p stored data is not AES block aligned",
        ));
    }
    let data_offset = offset
        .checked_add(probe.data_offset as u64)
        .ok_or_else(|| PreparedStatus::new("damaged", "RAR4 data range overflow"))?;
    let mut encrypted = Spool::default();
    let mut consumed = 0usize;
    while consumed < probe.pack_size {
        let length = (probe.pack_size - consumed).min(64 * 1024);
        let bytes = read_at(data_offset + consumed as u64, length, "rar4.file_data")?;
        if bytes.len() != length {
            return Err(ReadFault::short_read(
                "read_record",
                data_offset + consumed as u64,
                length,
                bytes.len(),
                data_offset + consumed as u64 + bytes.len() as u64,
            )
            .with_field("rar4.file_data", FieldLocation::Body)
            .into());
        }
        encrypted.write_all(&bytes).map_err(|error| {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                format!("resource_unavailable:{error}"),
            )
        })?;
        consumed += length;
    }
    let encrypted = encrypted.finish().map_err(|error| {
        PreparedStatus::new(
            "unknown_needs_final_verifier",
            format!("resource_unavailable:{error}"),
        )
    })?;
    Ok(RarPasswordMaterial::Stored { encrypted, probe })
}

pub(crate) struct RarPasswordContext {
    material: RarPasswordMaterial,
}

enum RarPasswordMaterial {
    Rar5(Rar5EncryptionHeader),
    Stored {
        encrypted: Blob,
        probe: Rar4DataProbe,
    },
    Header {
        salt: [u8; 8],
        encrypted: Vec<u8>,
    },
}

impl RarPasswordContext {
    pub(crate) fn retained_bytes(&self) -> usize {
        match &self.material {
            RarPasswordMaterial::Rar5(_) => std::mem::size_of::<Rar5EncryptionHeader>(),
            RarPasswordMaterial::Stored { encrypted, .. } => encrypted.len(),
            RarPasswordMaterial::Header { encrypted, .. } => encrypted.len(),
        }
    }

    pub(crate) fn verify(&self, candidates: &[Arc<str>]) -> std::io::Result<PasswordVerification> {
        match &self.material {
            RarPasswordMaterial::Rar5(header) => verify_rar5_material(header, candidates),
            RarPasswordMaterial::Stored { encrypted, probe } => {
                verify_rar4_stored_data(encrypted, candidates, probe)
            }
            RarPasswordMaterial::Header { salt, encrypted } => {
                let cancellation = Cancellation::current();
                let matched = (|| {
                    let matches = |password: &Arc<str>| {
                        !cancellation.cancelled()
                            && cancellation
                                .run(|| decrypt_rar4_header(encrypted, password, salt).is_some())
                    };
                    if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
                        candidates.par_iter().position_first(matches)
                    } else {
                        candidates.iter().position(matches)
                    }
                })();
                if let Some(index) = matched {
                    status_with_details(
                        "match",
                        index as i32,
                        (index + 1) as i32,
                        "rar4 -hp encrypted header matched",
                        Some(true),
                        Some("rar4_hp_header_crc16"),
                    )
                } else {
                    status(
                        "no_match",
                        -1,
                        candidates.len() as i32,
                        "rar4 -hp encrypted header did not match",
                    )
                }
            }
        }
    }
}

fn prepare_rar_data(data: &[u8]) -> Result<RarPasswordContext, PreparedStatus> {
    let material = if data.starts_with(RAR5_SIGNATURE) {
        let header = find_rar5_encryption_header(data).ok_or_else(|| {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar5 password check header not found",
            )
        })?;
        if !header.has_password_check {
            return Err(PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar5 encryption header has no password check",
            ));
        }
        RarPasswordMaterial::Rar5(header)
    } else if data.starts_with(RAR4_SIGNATURE) {
        prepare_rar4(data)?
    } else if data.starts_with(b"Rar!") {
        return Err(ReadFault::short_read(
            "read_record",
            0,
            RAR5_SIGNATURE.len(),
            data.len(),
            data.len() as u64,
        )
        .with_field("rar.signature", FieldLocation::Head)
        .into());
    } else {
        return Err(PreparedStatus::new(
            "unsupported_method",
            "rar signature not found",
        ));
    };
    Ok(RarPasswordContext { material })
}

/// RAR4 `-hp` material.  Plaintext main headers are routed to
/// `prepare_rar4_file_data` before this point.
fn prepare_rar4(data: &[u8]) -> Result<RarPasswordMaterial, PreparedStatus> {
    let main = parse_rar4_block(data, RAR4_SIGNATURE.len())
        .filter(|block| block.header_type == 0x73)
        .filter(|block| block.flags & RAR4_MAIN_HEADER_PASSWORD != 0)
        .ok_or_else(|| {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar4 encrypted headers require a CRC-valid plaintext main header",
            )
        })?;
    let offset = main.next_offset;
    let salt_block = data.get(offset..offset.saturating_add(24)).ok_or_else(|| {
        ReadFault::short_read(
            "read_record",
            offset as u64,
            24,
            data.len().saturating_sub(offset),
            data.len() as u64,
        )
        .with_field("rar4.encrypted_header.salt_block", FieldLocation::Head)
    })?;
    let salt = salt_block[..8].try_into().unwrap();
    let encrypted = &data[offset + 8..];
    let len = encrypted.len() & !0x0f;
    Ok(RarPasswordMaterial::Header {
        salt,
        encrypted: encrypted[..len].to_vec(),
    })
}

#[derive(Clone, Copy)]
struct Rar4Block {
    header_type: u8,
    flags: u16,
    header_end: usize,
    next_offset: usize,
}

struct Rar4DataProbe {
    method: u8,
    pack_size: usize,
    unpacked_size: usize,
    file_crc: u32,
    data_offset: usize,
    salt: Option<[u8; 8]>,
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
    let data_size = usize::try_from(crate::formats::rar::rar4_data_size(
        &data[offset..header_end],
    )?)
    .ok()?;
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
/// block headers are AES-CBC encrypted.
fn decrypt_rar4_header(encrypted: &[u8], password: &str, salt_source: &[u8]) -> Option<Rar4Block> {
    let salt: &[u8; 8] = salt_source.get(..8)?.try_into().ok()?;
    let (key, iv) = derive_rar3_key_iv(password, Some(salt))?;
    let cipher = Aes128::new_from_slice(&key).ok()?;
    let first = encrypted.get(..16)?;
    let plain = decrypt_cbc_block(&cipher, &mut iv.clone(), first);
    let size = u16::from_le_bytes([plain[5], plain[6]]) as usize;
    if size < RAR4_MIN_HEADER_SIZE {
        return None;
    }
    let aligned = size.checked_add(15)? & !15;
    let encrypted = encrypted.get(..aligned)?;
    let full = decrypt_cbc_bytes(&cipher, &iv, encrypted);
    parse_rar4_block(&full[..size], 0)
}

fn parse_rar4_file_probe(data: &[u8], offset: usize, block: Rar4Block) -> Option<Rar4DataProbe> {
    if block.header_end < offset + 32 {
        return None;
    }
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

    let (unpacked_high, name_start) = if block.flags & RAR4_FILE_LARGE != 0 {
        if block.header_end < offset + 40 {
            return None;
        }
        (
            u32::from_le_bytes([
                data[offset + 36],
                data[offset + 37],
                data[offset + 38],
                data[offset + 39],
            ]) as u64,
            offset + 40,
        )
    } else {
        (0, offset + 32)
    };
    let name_end = name_start.checked_add(name_size)?;
    if name_end > block.header_end {
        return None;
    }
    if block.flags & RAR4_FILE_LARGE == 0 && unpacked_low == u32::MAX as u64 {
        return None;
    }
    let pack_size = usize::try_from(crate::formats::rar::rar4_data_size(
        &data[offset..block.header_end],
    )?)
    .ok()?;
    let unpacked_size = usize::try_from((unpacked_high << 32) | unpacked_low).ok()?;
    let data_offset = block.header_end;
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
        method,
        pack_size,
        unpacked_size,
        file_crc,
        data_offset,
        salt,
    })
}

fn verify_rar4_stored_data(
    encrypted: &[u8],
    candidates: &[Arc<str>],
    probe: &Rar4DataProbe,
) -> std::io::Result<PasswordVerification> {
    let salt = probe.salt.as_ref();
    let expected_crc = probe.file_crc;
    let unpacked_size = probe.unpacked_size;
    let cancellation = Cancellation::current();
    let matched_index = (|| {
        let matches = |password: &Arc<str>| {
            !cancellation.cancelled()
                && cancellation.run(|| {
                    rar4_stored_password_matches(
                        password,
                        salt,
                        encrypted,
                        unpacked_size,
                        expected_crc,
                    )
                })
        };
        if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
            candidates.par_iter().position_first(matches)
        } else {
            candidates.iter().position(matches)
        }
    })();
    if let Some(index) = matched_index {
        return status_with_details(
            "match",
            index as i32,
            (index + 1) as i32,
            "rar3/rar4 -p stored file CRC matched",
            Some(false),
            Some("rar4_file_crc"),
        );
    }
    status_with_details(
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
    let Some((key, mut iv)) = derive_rar3_key_iv(password, salt) else {
        return false;
    };
    if encrypted.len() % 16 != 0 || encrypted.len() < unpacked_size {
        return false;
    }
    let mut buffer = vec![0; 64 * 1024];
    let mut remaining = unpacked_size;
    let mut hash = crc32fast::Hasher::new();
    for bytes in encrypted.chunks(buffer.len()) {
        if Cancellation::current().cancelled() {
            return false;
        }
        buffer[..bytes.len()].copy_from_slice(bytes);
        if Aes128CbcDecryptor::new(&key.into(), &iv.into())
            .decrypt_padded::<NoPadding>(&mut buffer[..bytes.len()])
            .is_err()
        {
            return false;
        }
        iv.copy_from_slice(&bytes[bytes.len() - 16..]);
        let take = remaining.min(bytes.len());
        hash.update(&buffer[..take]);
        remaining -= take;
    }
    hash.finalize() == expected_crc
}

fn derive_rar3_key_iv(password: &str, salt: Option<&[u8; 8]>) -> Option<([u8; 16], [u8; 16])> {
    let cancellation = Cancellation::current();
    let mut password_bytes =
        Vec::with_capacity(password.len().min(127) * 2 + salt.map_or(0, |_| 8));
    // RAR3 stores at most 127 UTF-16 code units (also used by the worker).
    for unit in password.encode_utf16().take(127) {
        password_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        password_bytes.extend_from_slice(salt);
    }

    if password_bytes.len() > 64 {
        return derive_rar3_long_key_iv(password_bytes);
    }

    // Batch the unchanged SHA1 byte stream, stopping immediately after each
    // IV checkpoint. The workspace belongs only to this password attempt.
    let record_len = password_bytes.len() + 3;
    let batch_size = (4096 / record_len).clamp(1, 64);
    let mut records = vec![0u8; record_len * batch_size];
    for record in records.chunks_exact_mut(record_len) {
        record[..password_bytes.len()].copy_from_slice(&password_bytes);
    }
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    let mut next = 0u32;
    let mut checkpoint_end = 1u32;
    while next < RAR3_KDF_ITERATIONS {
        if cancellation.cancelled() {
            return None;
        }
        let count = (batch_size as u32)
            .min(RAR3_KDF_ITERATIONS - next)
            .min(checkpoint_end - next) as usize;
        for (index, record) in records.chunks_exact_mut(record_len).take(count).enumerate() {
            record[record_len - 3..].copy_from_slice(&(next + index as u32).to_le_bytes()[..3]);
        }
        sha.update(&records[..count * record_len]);
        next += count as u32;
        if next == checkpoint_end {
            let digest = sha.clone().finalize();
            iv[((next - 1) / 0x4000) as usize] = digest[19];
            checkpoint_end += 0x4000;
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
    Some((key, iv))
}

fn derive_rar3_long_key_iv(mut raw: Vec<u8>) -> Option<([u8; 16], [u8; 16])> {
    // RAR3's original SHA1 implementation mutates complete input blocks after
    // the first block boundary. Long passwords must retain that format quirk;
    // batching unchanged records is valid only for raw inputs <= 64 bytes.
    // See the bundled 7-Zip Crypto/RarAes.cpp, UpdatePswDataSha1 / CalcKey.
    let cancellation = Cancellation::current();
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    let mut position = 0usize;
    for counter in 0..RAR3_KDF_ITERATIONS {
        if counter & 63 == 0 && cancellation.cancelled() {
            return None;
        }
        sha.update(&raw);
        let mut offset = 64 - (position & 63);
        while offset + 64 <= raw.len() {
            let block = &mut raw[offset..offset + 64];
            let mut words = [0u32; 80];
            for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
                *word = u32::from_be_bytes(bytes.try_into().unwrap());
            }
            for i in 16..80 {
                words[i] =
                    (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
            }
            for (bytes, word) in block.chunks_exact_mut(4).zip(&words[64..]) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            offset += 64;
        }
        sha.update(&counter.to_le_bytes()[..3]);
        position += raw.len() + 3;
        if counter % 0x4000 == 0 {
            iv[(counter / 0x4000) as usize] = sha.clone().finalize()[19];
        }
    }
    let digest = sha.finalize();
    let mut key = [0u8; 16];
    for (target, source) in key.chunks_exact_mut(4).zip(digest[..16].chunks_exact(4)) {
        target.copy_from_slice(source);
        target.reverse();
    }
    Some((key, iv))
}

fn verify_rar5_material(
    header: &Rar5EncryptionHeader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    let matched_index = find_rar5_password_match(candidates, header);
    if let Some(index) = matched_index {
        return status_with_details(
            "match",
            index as i32,
            (index + 1) as i32,
            "rar5 password check matched",
            Some(false),
            Some("rar5_password_check"),
        );
    }
    status(
        "no_match",
        -1,
        candidates.len() as i32,
        "rar5 password check did not match",
    )
}

fn find_rar5_password_match(
    candidates: &[Arc<str>],
    header: &Rar5EncryptionHeader,
) -> Option<usize> {
    let cancellation = Cancellation::current();
    #[cfg(test)]
    let threads = RAR5_CANDIDATE_THREADS.with(|value| value.borrow().clone());
    let matches = |password: &Arc<str>| {
        #[cfg(test)]
        if let Some(threads) = &threads { threads.lock().unwrap().push(std::thread::current().id()); }
        !cancellation.cancelled()
            && cancellation.run(|| rar5_checked_aes_key(password, header).is_some())
    };
    if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().position_first(matches)
    } else {
        candidates.iter().position(matches)
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static RAR5_CANDIDATE_THREADS: std::cell::RefCell<Option<Arc<std::sync::Mutex<Vec<std::thread::ThreadId>>>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Rar5EncryptionIdentity {
    lg2_count: u8,
    salt: [u8; 16],
    password_check: Option<[u8; 8]>,
}

// The header remains recognizable even when its encryption parameters are
// unsupported. Both discovery and password parsing use these same bounds.
pub(crate) fn rar5_archive_encryption_header(data: &[u8]) -> Option<(usize, usize)> {
    let offset = RAR5_SIGNATURE.len();
    let end = offset.checked_add(rar5_header_len(data.get(offset..)?)?)?;
    let header = data.get(..end)?;
    if crc32(&header[offset + 4..]) != le_u32(header, offset)? { return None; }
    let (_, start) = read_vint(header, offset + 4)?;
    let (kind, cursor) = read_vint(header, start)?;
    if kind != 4 { return None; }
    let (flags, mut cursor) = read_vint(header, cursor)?;
    let extra = if flags & 1 != 0 {
        let (size, next) = read_vint(header, cursor)?;
        cursor = next;
        usize::try_from(size).ok()?
    } else { 0 };
    if flags & 2 != 0 { cursor = read_vint(header, cursor)?.1; }
    (cursor <= end.checked_sub(extra)?).then_some((cursor, end))
}

pub(crate) fn rar5_encryption_identity(data: &[u8], body: usize, end: usize) -> Option<Rar5EncryptionIdentity> {
    let header = parse_rar5_encryption_body(data, body, end, false, false)?;
    Some(Rar5EncryptionIdentity {
        lg2_count: header.lg2_count, salt: header.salt,
        password_check: header.has_password_check.then_some(header.password_check),
    })
}

struct Rar5EncryptionHeader {
    lg2_count: u8,
    salt: [u8; 16],
    has_password_check: bool,
    password_check: [u8; 8],
}

fn find_rar5_encryption_header(data: &[u8]) -> Option<Rar5EncryptionHeader> {
    if let Some((body, end)) = rar5_archive_encryption_header(data) {
        return parse_rar5_encryption_body(data, body, end, false, false);
    }
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
            return parse_rar5_encryption_body(data, cursor, crc_end, false, false);
        }
        if matches!(header_type, 2 | 3) && extra_area_size != 0 {
            if let Some(header) = parse_rar5_file_encryption_extra(
                data,
                cursor,
                crc_end,
                extra_area_size,
                header_type == 3,
            ) {
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
    is_service: bool,
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
            return parse_rar5_encryption_body(data, body, record_end, true, is_service);
        }
        offset = record_end;
    }
    None
}

fn parse_rar5_encryption_body(
    data: &[u8],
    mut offset: usize,
    end: usize,
    include_iv: bool,
    is_service: bool,
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
    if lg2_count > RAR5_MAX_KDF_LOG || offset.checked_add(16 + usize::from(include_iv) * 16)? > end
    {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[offset..offset + 16]);
    offset += 16 + usize::from(include_iv) * 16;
    let mut has_password_check = flags & 0x0001 != 0;
    let mut password_check = [0u8; 8];
    if has_password_check {
        if offset.checked_add(12)? > end {
            return None;
        }
        password_check.copy_from_slice(&data[offset..offset + 8]);
        // RAR5 specifies a four-byte SHA-256 checksum of this eight-byte
        // proof. Invalid checks (including old zeroed service records) cannot
        // reject passwords; let the existing extraction fallback decide.
        has_password_check = Sha256::digest(password_check)[..4] == data[offset + 8..offset + 12]
            && (!is_service || password_check != [0; 8]);
    }
    Some(Rar5EncryptionHeader {
        lg2_count,
        salt,
        has_password_check,
        password_check,
    })
}

fn rar5_checked_aes_key(password: &str, header: &Rar5EncryptionHeader) -> Option<[u8; 32]> {
    if !header.has_password_check {
        return None;
    }
    rar5_aes_key(password, header)
}

fn rar5_aes_key(password: &str, header: &Rar5EncryptionHeader) -> Option<[u8; 32]> {
    let cancellation = Cancellation::current();
    let iterations = 1u32.checked_shl(header.lg2_count as u32).unwrap_or(0);
    if iterations == 0 {
        return None;
    }
    let password_bytes = password.as_bytes();
    let mut salt_extended = [0u8; 20];
    salt_extended[..16].copy_from_slice(&header.salt);
    salt_extended[19] = 1;

    // RAR's PBKDF2 uses the same HMAC key for every round. Clone the
    // precomputed inner/outer SHA-256 states, as the official UnRAR
    // implementation does, instead of rebuilding ipad/opad every time.
    let mac_template = HmacSha256::new_from_slice(password_bytes).ok()?;
    let mut mac = mac_template.clone();
    mac.update(&salt_extended);
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
    let mut final_hash = block;
    let round_counts = [iterations, 17, 17];
    let mut key = [0u8; 32];
    for (round_index, count) in round_counts.iter().enumerate() {
        for round in 1..*count {
            if round & 63 == 1 && cancellation.cancelled() {
                return None;
            }
            let mut mac = mac_template.clone();
            mac.update(&block);
            block = mac.finalize().into_bytes().into();
            for (f, b) in final_hash.iter_mut().zip(block.iter()) {
                *f ^= *b;
            }
        }
        if round_index == 0 {
            // The first PBKDF2 checkpoint is the AES key. The following
            // rounds derive RAR's password check from this same chain.
            key = final_hash;
            if !header.has_password_check {
                // An absent/unusable quick check is not a password rejection.
                // Main/terminal-header callers still validate the decrypted CRC.
                return Some(key);
            }
        }
    }
    let mut derived_check = [0u8; 8];
    for (index, byte) in final_hash.iter().enumerate() {
        derived_check[index % 8] ^= *byte;
    }
    (derived_check == header.password_check).then_some(key)
}

/// Share decrypted main-header and ENDARC facts between Relations and Embedded.
/// A normal RAR5 single volume stops at its main header unless an exact carrier
/// boundary is requested; multipart inputs retain the same terminal walk.
/// An inconclusive structure is distinct from a failed public password check.
pub(crate) fn probe_header_encrypted(
    reader: &ManagedReader,
    start_offset: u64,
    password: &str,
    max_blocks: usize,
    require_terminal: bool,
) -> io::Result<Option<RarTerminalProof>> {
    let signature = reader.read_at(start_offset, 8)?;
    if signature.starts_with(RAR5_SIGNATURE) {
        return probe_rar5_encrypted_terminal(reader, start_offset, password, max_blocks, require_terminal);
    }
    if signature.starts_with(RAR4_SIGNATURE) {
        return probe_rar4_encrypted_terminal(reader, start_offset, password, max_blocks);
    }
    Ok(None)
}

pub(crate) struct RarBoundaryResolution {
    pub(crate) offset: u64,
    pub(crate) status: &'static str,
    pub(crate) end_offset: Option<u64>,
    pub(crate) password: Option<Arc<str>>,
    pub(crate) error: Option<String>,
}

pub(crate) fn resolve_embedded_rar_boundaries(
    archive_path: String,
    offsets: Vec<u64>,
    passwords: &[Arc<str>],
) -> io::Result<Vec<RarBoundaryResolution>> {
    // One reader and one pass over each logical input. A failed segment must
    // not discard earlier facts or classify the unvisited remainder.
    let outcomes = (move || -> io::Result<_> {
        Cancellation::check_current_io()?;
        let reader = match ManagedReader::open(&archive_path) {
            Ok(reader) => reader.windowed_probe_reader(),
            Err(error) if is_cancellation(&error) => return Err(error),
            Err(error) => {
                // A source can disappear between scanning and reopening. Keep
                // this failure local to its unresolved segments, like read errors.
                let message = error.to_string();
                return Ok(offsets.into_iter().map(|offset| {
                    (offset, "error", None, None, Some(message.clone()))
                }).collect());
            }
        };
        let mut outcomes = Vec::with_capacity(offsets.len());
        for offset in offsets {
            Cancellation::check_current_io()?;
            let outcome = (|| -> io::Result<_> {
                if passwords.is_empty() {
                    return Ok(("password_required", None, None));
                }
                let mut rejected = 0;
                for password in passwords {
                    let proof = probe_header_encrypted(
                        &reader,
                        offset,
                        password,
                        usize::try_from(reader.len().saturating_sub(offset) / 8)
                            .unwrap_or(usize::MAX),
                        true,
                    )?;
                    Cancellation::check_current_io()?;
                    let Some(proof) = proof else {
                        continue;
                    };
                    if !proof.password_matched {
                        rejected += usize::from(proof.password_rejected);
                        continue;
                    }
                    if proof.end_block_found {
                        if let Some(end) = proof.end_offset.filter(|end| *end > offset) {
                            return Ok(("ok", Some(end), Some(password.clone())));
                        }
                    }
                    return Ok(("truncated", None, Some(password.clone())));
                }
                Ok((if rejected == passwords.len() { "wrong_password" } else { "password_required" }, None, None))
            })();
            match outcome {
                Ok((status, end, password)) => outcomes.push((offset, status, end, password, None)),
                Err(error) if is_cancellation(&error) => return Err(error),
                Err(error) => outcomes.push((offset, "error", None, None, Some(error.to_string()))),
            }
        }
        Ok(outcomes)
    })()?;
    Ok(outcomes
        .into_iter()
        .map(
            |(offset, status, end_offset, password, error)| RarBoundaryResolution {
                offset,
                status,
                end_offset,
                password,
                error,
            },
        )
        .collect())
}

fn probe_rar5_encrypted_terminal(
    reader: &ManagedReader,
    start_offset: u64,
    password: &str,
    max_blocks: usize,
    require_terminal: bool,
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
    // Discovery, fast verification and the terminal walk share the same
    // CRC-checked common-header cursor, including optional Extra/Data sizes.
    let full = reader.read_at(start_offset, RAR5_SIGNATURE.len() + total_size)?;
    let Some((body, end)) = rar5_archive_encryption_header(&full) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let Some(header) = parse_rar5_encryption_body(&full, body, end, false, false) else {
        return Ok(Some(RarTerminalProof::default()));
    };
    let Some(key) = rar5_aes_key(password, &header) else {
        Cancellation::check_current_io()?;
        return Ok(Some(RarTerminalProof {
            password_rejected: header.has_password_check,
            ..Default::default()
        }));
    };
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
        header.has_password_check,
        require_terminal,
    )?))
}

fn walk_rar5_encrypted_headers(
    reader: &ManagedReader,
    mut block_offset: u64,
    cipher: &Aes256,
    max_blocks: usize,
    password_matched: bool,
    require_terminal: bool,
) -> io::Result<RarTerminalProof> {
    let mut proof = RarTerminalProof {
        password_matched,
        ..Default::default()
    };
    for _ in 0..max_blocks {
        let Some((full, next_header_offset)) =
            read_rar5_encrypted_header(reader, block_offset, cipher)?
        else {
            return Ok(proof);
        };
        let stored_crc = u32::from_le_bytes([full[0], full[1], full[2], full[3]]);
        let Some((_header_size, after_size)) = read_vint(&full, 4) else {
            return Ok(proof);
        };
        if crc32(&full[4..]) != stored_crc {
            return Ok(proof);
        }
        let Some((header_type, after_type)) = read_vint(&full, after_size) else {
            return Ok(proof);
        };
        let Some((header_flags, mut field_cursor)) = read_vint(&full, after_type) else {
            return Ok(proof);
        };
        if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
            return Ok(proof);
        }
        if proof.main_volume.is_none() {
            // Retain the same decrypted main-header facts for Embedded and
            // Relations, so neither derives the key or parses this header again.
            let Some(main) = rar5_main_volume(&full, 0) else {
                return Ok(proof);
            };
            proof.main_volume = Some(main);
            proof.password_matched = true;
            if !require_terminal && main.0 & 1 == 0 {
                return Ok(proof);
            }
        }
        if header_flags & 0x0001 != 0 {
            let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                return Ok(proof);
            };
            field_cursor = after_extra;
        }
        let data_size = if header_flags & 0x0002 != 0 {
            let Some((value, after_data)) = read_vint(&full, field_cursor) else {
                return Ok(proof);
            };
            field_cursor = after_data;
            value
        } else {
            0
        };
        let next = next_header_offset.checked_add(data_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "RAR5 data offset overflow")
        })?;
        if header_type == 5 {
            let end_flags = read_vint(&full, field_cursor)
                .map(|(value, _)| value)
                .unwrap_or(0);
            return Ok(RarTerminalProof {
                password_matched: true,
                password_rejected: false,
                end_block_found: true,
                end_block_flags: end_flags,
                end_offset: Some(next),
                volume_number: None,
                main_volume: proof.main_volume,
            });
        }
        block_offset = next;
    }
    Ok(proof)
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
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RAR5 next header offset overflow",
                )
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
    let mut password_matched = false;
    let incomplete = |matched| RarTerminalProof {
        password_matched: matched,
        ..Default::default()
    };
    for _ in 0..max_blocks {
        let salt = reader.read_at(block_offset, 8)?;
        if salt.len() != 8 {
            return Ok(incomplete(password_matched));
        }
        let salt: [u8; 8] = salt.try_into().expect("RAR4 salt length checked");
        let (key, iv) = derive_rar3_key_iv(password, Some(&salt)).ok_or_else(|| {
            crate::io::cancellation::cancelled_io()
        })?;
        let cipher = Aes128::new_from_slice(&key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RAR4 AES key"))?;
        let encrypted_offset = block_offset.checked_add(8).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "RAR4 encrypted offset overflow")
        })?;
        let first_ciphertext = reader.read_at(encrypted_offset, 16)?;
        if first_ciphertext.len() != 16 {
            return Ok(incomplete(password_matched));
        }
        let mut previous = iv;
        let first_plaintext = decrypt_cbc_block(&cipher, &mut previous, &first_ciphertext);
        let header_size = u16::from_le_bytes([first_plaintext[5], first_plaintext[6]]) as usize;
        if !(RAR4_MIN_HEADER_SIZE..=2 * 1024 * 1024).contains(&header_size) {
            return Ok(incomplete(password_matched));
        }
        let aligned_size = header_size
            .checked_add(15)
            .map(|value| value & !15)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "RAR4 header size overflow")
            })?;
        let encrypted = reader.read_at(encrypted_offset, aligned_size)?;
        if encrypted.len() != aligned_size {
            return Ok(incomplete(password_matched));
        }
        let plaintext = decrypt_cbc_bytes(&cipher, &iv, &encrypted);
        let full = &plaintext[..header_size];
        let stored_crc = u16::from_le_bytes([full[0], full[1]]);
        let header_type = full[2];
        let header_flags = u16::from_le_bytes([full[3], full[4]]);
        if crc32(&full[2..]) as u16 != stored_crc || !(0x72..=0x7b).contains(&header_type) {
            return Ok(incomplete(password_matched));
        }
        password_matched = true;
        let Some(data_size) = crate::formats::rar::rar4_data_size(full) else {
            return Ok(incomplete(true));
        };
        let next = encrypted_offset
            .checked_add(aligned_size as u64)
            .and_then(|value| value.checked_add(data_size))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "RAR4 data offset overflow")
            })?;
        if header_type == 0x7b {
            return Ok(RarTerminalProof {
                password_matched: true,
                password_rejected: false,
                end_block_found: true,
                end_block_flags: u64::from(header_flags),
                end_offset: Some(next),
                volume_number: rar4_end_volume(full),
                main_volume: None,
            });
        }
        block_offset = next;
    }
    Ok(incomplete(password_matched))
}

fn status(
    status: &'static str,
    matched_index: i32,
    attempts: i32,
    message: &str,
) -> std::io::Result<PasswordVerification> {
    status_with_details(status, matched_index, attempts, message, None, None)
}

fn status_with_details(
    status: &'static str,
    matched_index: i32,
    attempts: i32,
    message: &str,
    final_confirmation_required: Option<bool>,
    match_evidence: Option<&'static str>,
) -> std::io::Result<PasswordVerification> {
    Ok(PasswordVerification {
        matched_index: usize::try_from(matched_index).ok(),
        attempts: attempts as usize,
        final_confirmation_required,
        match_evidence,
        ..PasswordVerification::status(status, message)
    })
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
#[path = "../../tests/unit/password/rar/kdf_regression_tests.rs"]
mod kdf_regression_tests;

#[cfg(test)]
#[path = "../../tests/unit/password/rar/rar5_header_decryption_tests.rs"]
pub(crate) mod rar5_header_decryption_tests;

#[cfg(test)]
#[path = "../../tests/unit/password/rar/relation_header_tests.rs"]
mod relation_header_tests;

#[cfg(test)]
#[path = "../../tests/unit/password/rar/rar4_file_encryption_scan_tests.rs"]
mod rar4_file_encryption_scan_tests;
