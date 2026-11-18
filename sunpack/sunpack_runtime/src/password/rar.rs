use super::PasswordVerification;
use crate::formats::rar::{rar4_end_volume, rar5_header_len, rar5_main_volume, read_vint};
use crate::io::archive_state::{InputExtent, InputPart};
use crate::io::cancellation::{is_cancellation, Cancellation};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, read_ranges_at_field, RangeSpec, VirtualRangeReader, VolumeSet,
};
use aes::cipher::{
    Block, BlockCipherDecrypt, KeyInit,
};
use aes::{Aes128, Aes256};
use crc32fast::hash as crc32_hash;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::borrow::Cow;
use std::io;
use std::sync::Arc;

#[path = "rar_volumes.rs"]
pub(super) mod native_volumes;
use native_volumes::VolumeFacts;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR_INITIAL_PREFIX_SCAN: usize = 16 * 1024;
const RAR3_KDF_ITERATIONS: u32 = 0x40000;
const RAR4_MIN_HEADER_SIZE: usize = 7;
const RAR4_HEADER_TYPES: std::ops::RangeInclusive<u8> = 0x72..=0x7b;
const PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const RAR5_MAX_KDF_LOG: u8 = 24;
const RAR4_MAIN_HEADER_PASSWORD: u16 = 0x0080;
const RAR4_FILE_PASSWORD: u16 = 0x0004;
#[cfg(test)]
const RAR4_LONG_BLOCK: u16 = 0x8000;
const RAR4_END_NEXT_VOLUME: u16 = 0x0001;
/// Plaintext headers walked before deferring to the final verifier.
/// One read normally covers a whole RAR4 block header.
const RAR4_HEADER_READ_HINT: usize = 512;

type HmacSha256 = Hmac<Sha256>;

/// The result of walking a header-encrypted RAR stream far enough to prove
/// whether its ENDARC record is present.  This deliberately contains no
/// member data. Relations and Embedded use the same decrypted facts.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RarTerminalProof {
    password_matched: bool,
    pub(crate) terminal: Option<RarTerminal>,
    pub(crate) main_volume: Option<(u64, Option<u32>)>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RarTerminal {
    pub(crate) offset: u64,
    pub(crate) has_next: bool,
    pub(crate) volume_number: Option<u32>,
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

fn decrypt_cbc_header<C>(
    cipher: &C,
    mut previous: [u8; 16],
    first_plaintext: [u8; 16],
    header: &mut [u8],
)
where
    C: BlockCipherDecrypt,
{
    header[..16].copy_from_slice(&first_plaintext);
    for block in header[16..].chunks_exact_mut(16) {
        let plaintext = decrypt_cbc_block(cipher, &mut previous, block);
        block.copy_from_slice(&plaintext);
    }
}

pub(crate) fn rar_fast_verify_passwords_with_reader(
    preparation: &mut Preparation,
    reader: &ManagedReader,
    candidates: &[Arc<str>],
) -> std::io::Result<PasswordVerification> {
    preparation.verify(InputKey::file("rar", reader)?, candidates, || {
        prepare_rar_ranges(&[RangeSpec::entire(reader)])
        .map(|c| PasswordContext::Rar(Arc::new(c)))
    })
}

pub(crate) fn rar_fast_verify_passwords_from_ranges(
    preparation: &mut Preparation,
    ranges: &[&InputExtent],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
) -> std::io::Result<PasswordVerification> {
    let parsed = parse_ranges(ranges.iter().copied(), sessions)?;
    preparation.verify(ranges_key("rar", &parsed)?, candidates, || {
        prepare_rar_ranges(&parsed)
            .map(|c| PasswordContext::Rar(Arc::new(c)))
    })
}

pub(crate) fn rar_fast_verify_passwords_from_volumes(
    preparation: &mut Preparation,
    parts: &[InputPart],
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
    native_volume: bool,
) -> std::io::Result<PasswordVerification> {
    let volumes = VolumeSet::new(parse_volumes(parts, sessions)?);
    preparation.verify(volumes.key(if native_volume { "rar-native" } else { "rar" })?, candidates,
        || prepare_rar_volumes(&volumes, native_volume).map(|c| PasswordContext::Rar(Arc::new(c))))
}

pub(crate) fn rar_fast_verify_passwords_from_attempts(
    preparation: &mut Preparation,
    head: &InputExtent,
    plan: &crate::io::archive_state::VolumeAttemptPlan,
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
    native_volume: bool,
) -> io::Result<PasswordVerification> {
    use super::input::attempts::{prepare_attempt_evidence_partial, AttemptGeometry};
    let build = || {
        if let Some(context) = native_volumes::prepare(head, plan, sessions, native_volume)? { return Ok(context); }
        // A byte-split RAR has a single logical header stream. Native disks
        // above can instead authenticate their own independent records.
        let geometry = if !plan.tail_totals.is_empty() { AttemptGeometry::TailTotals }
            else if let Some(total) = plan.head_size_from_total { AttemptGeometry::TrimmedHead { total } }
            else if plan.minimum_size.is_none() { AttemptGeometry::DiskRelative }
            else { AttemptGeometry::Forward { logical_limit: None } };
        let prefix = std::sync::OnceLock::new();
        let common = || Arc::clone(prefix.get_or_init(|| {
            let mut extents = super::input::prefix::common_attempt_prefix(head, plan, sessions);
            // At most two 3-byte-size RAR5 headers, signature and AES padding.
            let mut remaining = 2 * (1 << 21) + 64u64;
            let count = extents.iter().take_while(|extent| {
                let needed = remaining > 0;
                remaining = remaining.saturating_sub(extent.end.unwrap() - extent.start);
                needed
            }).count();
            extents.truncate(count);
            let paths: std::collections::HashSet<_> = extents.iter().map(|e| e.path.as_str()).collect();
            let sessions = sessions.iter().filter(|s| paths.contains(s.path())).cloned().collect();
            Arc::new(RarCommonPrefix { extents: extents.into_boxed_slice(), sessions })
        }));
        let evidence = prepare_attempt_evidence_partial(head, plan, sessions, geometry, |reader| {
            use std::io::{Read, Seek, SeekFrom};
            let length = reader.len();
            prepare_rar_volume(|offset, size, field| {
                if matches!(geometry, AttemptGeometry::DiskRelative) {
                    return reader.advance_disk_offset(0, 0, offset).and_then(|position| match position {
                        Some((disk, local)) => reader.read_disk_spanning(disk, local, size),
                        None => Ok(Vec::new()),
                    }).map_err(|err| ReadFault::from_io(err, "read_volume", offset, size, 0, length)
                        .with_field(field, FieldLocation::Head));
                }
                let count = (size as u64).min(length.saturating_sub(offset)) as usize;
                let mut bytes = vec![0; count];
                reader.seek(SeekFrom::Start(offset)).and_then(|_| reader.read_exact(&mut bytes))
                    .map_err(|err| ReadFault::from_io(err, "read", offset, size, 0, length)
                        .with_field(field, FieldLocation::Head))?;
                Ok(bytes)
            }, None, RarRanges::Projected(&common)).map(Some)
        })?;
        Ok(evidence.into_context(|c| PasswordContext::Rar(Arc::new(c))))
    };
    preparation.verify_local(build(), candidates)
}

fn prepare_rar_volumes(volumes: &VolumeSet, native_volume: bool) -> Result<RarPasswordContext, PreparedStatus> {
    if !native_volume {
        return prepare_rar_ranges(&volumes.contiguous_ranges());
    }
    let first_disk = volumes.disk_range(0).ok_or_else(||
        PreparedStatus::new("needs_volume_or_tail_damaged", "RAR volume unavailable"))?;
    let first = prepare_rar_ranges(&[first_disk]);
    if first.is_ok() { return first; }
    for disk in 1..volumes.len() {
        if let Some(range) = volumes.disk_range(disk) {
            let result = prepare_rar_ranges(&[range]);
            if result.is_ok() { return result; }
        }
    }
    first
}

// A projected parser may still refer lazily to the physical ranges shared
// by every layout. Bytes outside that prefix belong to its projection.
#[derive(Clone, Copy)]
enum RarRanges<'a> {
    Fixed(&'a [RangeSpec]),
    Projected(&'a (dyn Fn() -> Arc<RarCommonPrefix> + Sync)),
}

#[derive(Default)]
struct RarCommonPrefix {
    extents: Box<[InputExtent]>,
    sessions: Vec<NativeArchiveSession>,
}

fn prepare_rar_ranges(ranges: &[RangeSpec]) -> Result<RarPasswordContext, PreparedStatus> {
    prepare_rar_volume(|offset, size, field| read_ranges_at_field(ranges, offset, size, field), None, RarRanges::Fixed(ranges))
}

/// `read_at(offset, len, field)` returns fewer than `len` bytes only at the end
/// of the input.
#[cfg(test)]
fn prepare_rar(
    mut read_at: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<RarPasswordContext, PreparedStatus> {
    prepare_rar_volume(&mut read_at, None, RarRanges::Projected(&Arc::default))
}

fn prepare_rar_volume(
    mut read_at: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    mut facts: Option<&mut VolumeFacts>,
    ranges: RarRanges<'_>,
) -> Result<RarPasswordContext, PreparedStatus> {
    let signature = read_at(0, RAR5_SIGNATURE.len(), "rar.signature")?;
    if signature.starts_with(RAR5_SIGNATURE) {
        return prepare_rar5_stream(&mut read_at, facts, ranges);
    }
    if !signature.starts_with(RAR4_SIGNATURE) {
        if signature.starts_with(b"Rar!") {
            return Err(ReadFault::short_read(
                "read_record",
                0,
                RAR5_SIGNATURE.len(),
                signature.len(),
                signature.len() as u64,
            )
            .with_field("rar.signature", FieldLocation::Head)
            .into());
        }
        if signature.len() >= 8 { if let Some(f) = facts.as_deref_mut() { f.invalid = true; } }
        return Err(PreparedStatus::new(
            "unsupported_method",
            "rar signature not found",
        ));
    }
    let prefix_size = match ranges {
        RarRanges::Fixed(_) => RAR_INITIAL_PREFIX_SCAN,
        RarRanges::Projected(_) => RAR4_SIGNATURE.len() + RAR4_MIN_HEADER_SIZE,
    };
    let mut data = read_at(0, prefix_size, "rar.header_prefix")?;
    let main_offset = RAR4_SIGNATURE.len() as u64;
    let header_hint = if matches!(ranges, RarRanges::Fixed(_)) { RAR4_HEADER_READ_HINT } else { RAR4_MIN_HEADER_SIZE };
    let main = read_rar4_header_at(&data, main_offset, &mut read_at, header_hint)?
        .and_then(|header| parse_rar4_block(&header, 0))
        .filter(|block| block.header_type == 0x73)
        .ok_or_else(|| {
            PreparedStatus::new(
                "unknown_needs_final_verifier",
                "rar4 encrypted headers require a CRC-valid plaintext main header",
            )
        })?;
    if let Some(facts) = facts.as_deref_mut() {
        facts.version = Some(4);
        facts.native = main.flags & 1 != 0;
        facts.header_encrypted = main.flags & RAR4_MAIN_HEADER_PASSWORD != 0;
        if main.flags & 0x100 != 0 { facts.number = Some(1); }
    }
    let next = main_offset + main.next_offset as u64;
    if main.flags & RAR4_MAIN_HEADER_PASSWORD == 0 {
        return Err(if rar4_members_are_plain(&data, next, &mut read_at, facts, header_hint)? {
            PreparedStatus::new("not_required", "RAR4 file headers are not encrypted")
        } else {
            PreparedStatus::new("unknown_needs_final_verifier", "RAR4 member authentication requires the worker decoder")
        });
    }
    let material = {
        // One header plus salt covers the first verification block.
        let (mut encrypted, available_end) = if data.len() < prefix_size {
            let available_end = data.len() as u64;
            data.drain(..next.min(available_end) as usize);
            (data, available_end)
        } else {
            let encrypted = read_at(next, 8 + 65536, "rar4.encrypted_header")?;
            let available_end = next + encrypted.len() as u64;
            (encrypted, available_end)
        };
        if encrypted.len() < 24 {
            return Err(ReadFault::short_read(
                "read_record",
                next,
                24,
                encrypted.len(),
                available_end,
            )
            .with_field("rar4.encrypted_header.salt_block", FieldLocation::Head)
            .into());
        }
        encrypted.truncate(8 + ((encrypted.len() - 8) & !0x0f));
        RarPasswordMaterial::Header(encrypted)
    };
    Ok(RarPasswordContext { material })
}

fn prepare_rar5_stream(
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    mut facts: Option<&mut VolumeFacts>,
    ranges: RarRanges<'_>,
) -> Result<RarPasswordContext, PreparedStatus> {
    let unknown = || {
        PreparedStatus::new(
            "unknown_needs_final_verifier",
            "RAR5 encryption metadata is unavailable",
        )
    };
    let mut offset = RAR5_SIGNATURE.len() as u64;
    let mut encrypted_seen = false;
    let mut saved = None;
    let scanned = (|| loop {
        let read_hint = if matches!(ranges, RarRanges::Fixed(_)) { 64 } else { 7 };
        let fixed = read_at(offset, read_hint, "rar5.block_header")?;
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
            if let Some(facts) = facts.as_deref_mut() { facts.invalid = true; }
            return Err(PreparedStatus::new("damaged", "RAR5 header CRC mismatch"));
        }
        let fields = rar5_common_fields(&header, after_size).ok_or_else(unknown)?;
        let file = if matches!(fields.kind, 2 | 3) && (fields.extra_size != 0 || facts.is_some()) {
            rar5_file_fields(&header, fields.body, length)
        } else { None };
        let file_crypto = matches!(fields.kind, 2 | 3).then(||
            rar5_file_encryption_extra(&header, fields.extra_size)).flatten();
        let encryption = match fields.kind {
            4 => parse_rar5_encryption_body(&header, fields.body, length, false, false).map(|identity| (identity, 0)),
            2 | 3 => file_crypto.zip(file.as_ref()).and_then(|(record, file)|
                parse_rar5_encryption_body(record, 0, record.len(), true, fields.kind == 3)
                    .map(|identity| (identity, file.compression))),
            _ => None,
        };
        encrypted_seen |= file_crypto.is_some() || fields.kind == 4;
        if fields.kind == 4 && encryption.is_none() {
            return Err(unknown());
        }
        if let Some(facts) = facts.as_deref_mut() {
            facts.version = Some(5);
            if fields.kind == 4 { facts.header_encrypted = true; }
            if fields.kind == 1 {
                if let Some((flags, number)) = rar5_main_volume(&header, 0) {
                    facts.native = flags & 1 != 0;
                    if facts.native { facts.number = Some(number.unwrap_or(0) + 1); }
                }
            }
            if fields.kind == 2 {
                if let Some(file) = &file {
                    facts.file(fields.flags & 8 != 0, fields.flags & 16 != 0, file.name);
                    if fields.flags & 16 != 0 && (file_crypto.is_none()
                        || encryption.as_ref().is_some_and(|(identity, _)| !identity.keyed_hash)) {
                        if let Some(crc) = file.crc {
                            facts.packed(offset + length as u64, fields.data_size, crc);
                        }
                    }
                }
            }
        }
        if let Some((encryption, compression)) = encryption {
            if encryption.password_check.is_none() {
                let data_offset = offset.checked_add(length as u64).ok_or_else(unknown)?;
                let material = if fields.kind == 4 {
                    // RAR5 limits the header-size vint to three bytes. This is
                    // the format's maximum header extent, not a parser budget.
                    let prefix = read_at(data_offset, 32, "rar5.encrypted_header")?
                        .try_into().map_err(|_| unknown())?;
                    let offset = data_offset.checked_add(32).ok_or_else(unknown)?;
                    let source = match ranges {
                        RarRanges::Fixed(ranges) => RarTailSource::Fixed(RangeSpec::covering(ranges, offset, 1 << 21).into()),
                        RarRanges::Projected(common) => RarTailSource::Common(common()),
                    };
                    let tail = Rar5HeaderTail { source, offset };
                    RarPasswordMaterial::Rar5Header { identity: encryption, prefix, tail }
                } else if fields.flags & 8 == 0 && compression & 0x3f <= 1
                    && (1..=5).contains(&((compression >> 7) & 7)) && fields.data_size >= 16 {
                    let encrypted = read_at(data_offset, 16, "rar5.compressed_block")?;
                    let encrypted = encrypted.try_into().map_err(|_| unknown())?;
                    RarPasswordMaterial::Rar5Block { identity: encryption, encrypted }
                } else {
                    // Stored/continuation/unknown methods carry no safe block
                    // prefix. A later independent member can still prove a key.
                    offset = data_offset.checked_add(fields.data_size).ok_or_else(unknown)?;
                    continue;
                };
                if fields.kind == 4 || facts.is_none() { return Ok(RarPasswordContext { material }); }
                if saved.is_none() { saved = Some(material); }
            } else {
                let material = RarPasswordMaterial::Rar5(encryption);
                if facts.is_none() || fields.kind == 4 { return Ok(RarPasswordContext { material }); }
                saved = Some(material);
            }

        }
        if fields.kind == 5 {
            let has_next = read_vint(&header, fields.body).map(|(flags, _)| flags & 1 != 0);
            if let Some(facts) = facts.as_deref_mut() { facts.has_next = has_next; }
            if let Some(material) = saved.take() { return Ok(RarPasswordContext { material }); }
            if encrypted_seen || has_next != Some(false) { return Err(unknown()); }
            return Err(PreparedStatus::new(
                "not_required",
                "RAR5 headers contain no encrypted entries",
            ));
        }
        offset = offset
            .checked_add(length as u64)
            .and_then(|value| value.checked_add(fields.data_size))
            .ok_or_else(unknown)?;
    })();
    // A later short read cannot erase an independently complete earlier proof.
    scanned.or_else(|error| saved.map(|material| RarPasswordContext { material }).ok_or(error))
}

/// Walk plaintext RAR4 block headers by seeking over payloads.  Only headers
/// are read, so the cost is independent of member sizes; headers inside the
/// already-read prefix cost no I/O at all.
fn rar4_members_are_plain(
    prefix: &[u8],
    mut offset: u64,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    mut facts: Option<&mut VolumeFacts>,
    header_hint: usize,
) -> Result<bool, ReadFault> {
    let mut encrypted = false;
    loop {
        let Some(header) = read_rar4_header_at(prefix, offset, read_at, header_hint)? else {
            return Ok(false);
        };
        let Some(block) = parse_rar4_block(&header, 0) else {
            if let Some(facts) = facts.as_deref_mut() {
                facts.invalid = (crc32(&header[2..]) as u16) != u16::from_le_bytes([header[0], header[1]]);
            }
            return Ok(false);
        };
        let data_size = (block.next_offset - block.header_end) as u64;
        let Some(data_offset) = offset.checked_add(block.header_end as u64) else {
            return Ok(false);
        };
        match block.header_type {
            0x74 => {
                encrypted |= block.flags & RAR4_FILE_PASSWORD != 0;
                if let Some(facts) = facts.as_deref_mut() {
                    let start = if block.flags & 0x100 != 0 { 40 } else { 32 };
                    if let Some(size) = header.get(26..28) {
                        let size = u16::from_le_bytes(size.try_into().unwrap()) as usize;
                        if let Some(name) = header.get(start..start + size) {
                            facts.file(block.flags & 1 != 0, block.flags & 2 != 0, name);
                        }
                    }
                    if block.flags & 2 != 0 && header.get(24).is_some_and(|&version| version >= 20) {
                        if let Some(crc) = le_u32(&header, 16).filter(|&crc| crc != u32::MAX) {
                            facts.packed(data_offset, data_size, crc);
                        }
                    }
                } else if encrypted { return Ok(false); }
            }
            0x7b => {
                if let Some(facts) = facts.as_deref_mut() {
                    facts.number = rar4_end_volume(&header).or(facts.number);
                    facts.has_next = Some(block.flags & RAR4_END_NEXT_VOLUME != 0);
                }
                return Ok(!encrypted && block.flags & RAR4_END_NEXT_VOLUME == 0);
            }
            _ => {}
        }
        let Some(next) = data_offset.checked_add(data_size) else {
            return Ok(false);
        };
        offset = next;
    }
}

/// Return exactly one declared RAR4 block header, or `None` at end of input.
fn read_rar4_header_at<'a>(
    prefix: &'a [u8],
    offset: u64,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    read_hint: usize,
) -> Result<Option<Cow<'a, [u8]>>, ReadFault> {
    // Serve the header from the prefix whenever it is fully inside it.
    let in_prefix = usize::try_from(offset).ok().and_then(|start| {
        Some((
            start,
            prefix.get(start..start.checked_add(RAR4_MIN_HEADER_SIZE)?)?,
        ))
    });
    let requested = if let Some((start, fixed)) = in_prefix {
        let header_size = u16::from_le_bytes([fixed[5], fixed[6]]) as usize;
        if header_size < RAR4_MIN_HEADER_SIZE {
            return Ok(None);
        }
        if let Some(header) = prefix.get(start..start + header_size) {
            return Ok(Some(Cow::Borrowed(header)));
        }
        header_size
    } else { read_hint };
    let mut buffer = read_at(offset, requested, "rar4.block_header")?;
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
    Ok(Some(Cow::Owned(buffer)))
}

pub(crate) struct RarPasswordContext {
    material: RarPasswordMaterial,
}

enum RarPasswordMaterial {
    Rar5(Rar5EncryptionIdentity),
    Rar5Header { identity: Rar5EncryptionIdentity, prefix: [u8; 32], tail: Rar5HeaderTail },
    Rar5Block { identity: Rar5EncryptionIdentity, encrypted: [u8; 16] },
    Header(Vec<u8>),
}

struct Rar5HeaderTail {
    source: RarTailSource,
    offset: u64,
}

enum RarTailSource {
    Fixed(Box<[RangeSpec]>),
    Common(Arc<RarCommonPrefix>),
}

impl Rar5HeaderTail {
    fn verify(&self, prefix: &[u8; 32], key: &[u8; 32]) -> Option<bool> {
        let cipher = Aes256::new(key.into());
        let mut previous = prefix[..16].try_into().unwrap();
        let first = decrypt_cbc_block(&cipher, &mut previous, &prefix[16..]);
        let Some(size) = rar5_header_len(&first).filter(|&size| size >= 7) else { return Some(false); };
        let (_, body) = read_vint(&first, 4)?;
        if read_vint(&first, body)?.0 != 1 { return Some(false); }
        let expected = u32::from_le_bytes(first[..4].try_into().unwrap());
        if size <= 16 { return Some(crc32(&first[4..size]) == expected); }
        let mut digest = crc32fast::Hasher::new();
        digest.update(&first[4..]);
        let mut done = 0;
        let rest = ((size + 15) & !15) - 16;
        let opened;
        let ranges = match &self.source {
            RarTailSource::Fixed(ranges) => ranges.as_ref(),
            RarTailSource::Common(common) => {
                opened = super::input::parse_range_prefix(common.extents.iter(), &common.sessions,
                    Some(self.offset.checked_add(rest as u64)?)).ok()?;
                &opened
            }
        };
        let mut reader = VirtualRangeReader::streaming(ranges);
        if reader.len().saturating_sub(self.offset) < rest as u64 { return None; }
        let mut chunk = Vec::new();
        while done < rest {
            let count = (rest - done).min(64 * 1024);
            reader.read_at_into(self.offset + done as u64, count, &mut chunk).ok()?;
            if chunk.len() != count { return None; }
            for block in chunk.chunks_exact_mut(16) {
                let plain = decrypt_cbc_block(&cipher, &mut previous, block);
                block.copy_from_slice(&plain);
            }
            digest.update(&chunk[..count.min(size - 16 - done)]);
            done += count;
        }
        Some(digest.finalize() == expected)
    }
}

type SharedRarKey<T> = Arc<std::sync::OnceLock<Option<T>>>;
#[derive(Default)]
pub(crate) struct RarKeyCache {
    direct: bool,
    rar4: std::sync::Mutex<std::collections::HashMap<([u8; 8], Arc<str>), SharedRarKey<([u8; 16], [u8; 16])>>>,
    rar5: std::sync::Mutex<std::collections::HashMap<(u8, [u8; 16], Arc<str>), SharedRarKey<([u8; 32], [u8; 8])>>>,
}
impl RarKeyCache {
    fn rar4(&self, password: &Arc<str>, salt: &[u8; 8]) -> Option<([u8; 16], [u8; 16])> {
        if self.direct { return derive_rar3_key_iv(password, Some(salt)); }
        let slot = self.rar4.lock().unwrap().entry((*salt, Arc::clone(password))).or_default().clone();
        *slot.get_or_init(|| derive_rar3_key_iv(password, Some(salt)))
    }
    fn rar5(&self, password: &Arc<str>, identity: &Rar5EncryptionIdentity) -> Option<[u8; 32]> {
        if self.direct { return rar5_aes_key(password, identity); }
        let slot = self.rar5.lock().unwrap().entry((identity.lg2_count, identity.salt, Arc::clone(password))).or_default().clone();
        let (key, check) = (*slot.get_or_init(|| derive_rar5_key_check(password, identity)))?;
        identity.password_check.is_none_or(|expected| expected == check).then_some(key)
    }
}

impl RarPasswordContext {
    pub(crate) fn verify(
        &self,
        candidates: &[Arc<str>],
        proven_key: Option<&mut Option<RarProvenKey>>,
    ) -> std::io::Result<PasswordVerification> {
        self.verify_cached(candidates, proven_key, &RarKeyCache { direct: true, ..Default::default() })
    }

    pub(crate) fn verify_cached(&self, candidates: &[Arc<str>],
        proven_key: Option<&mut Option<RarProvenKey>>, keys: &RarKeyCache,
    ) -> io::Result<PasswordVerification> {
        match &self.material {
            RarPasswordMaterial::Rar5(header) => verify_rar5_material(header, candidates, proven_key, keys),
            RarPasswordMaterial::Rar5Header { identity, prefix, tail } => {
                let first_key = std::sync::Mutex::new(None);
                let keep_key = proven_key.is_some();
                let result = verify_rar_structural_candidates(candidates, true, "rar5_header_crc32", |index, password| {
                    let key = keys.rar5(password, identity)?;
                    let matched = tail.verify(prefix, &key)?;
                    if matched && keep_key {
                        let mut slot = first_key.lock().unwrap();
                        if slot.as_ref().is_none_or(|&(earlier, _)| index < earlier) {
                            *slot = Some((index, key));
                        }
                    }
                    Some(matched)
                })?;
                if let (Some(proof), Some((index, key))) = (proven_key, first_key.into_inner().unwrap()) {
                    if result.matched_index == Some(index) {
                        *proof = Some(RarProvenKey::Rar5 { header: *identity, key });
                    }
                }
                Ok(result)
            }
            RarPasswordMaterial::Rar5Block { identity, encrypted } => {
                verify_rar_structural_candidates(candidates, false, "rar5_compressed_block", |_, password| {
                    let Some(key) = keys.rar5(password, identity) else { return Some(false); };
                    let cipher = Aes256::new_from_slice(&key).unwrap();
                    let mut iv = identity.iv;
                    let first = decrypt_cbc_block(&cipher, &mut iv, encrypted);
                    let extra = (first[0] >> 3) & 3;
                    Some(extra < 3 && first[..3 + extra as usize].iter().fold(0u8, |checksum, byte| checksum ^ byte) == 0x5a)
                })
            }
            RarPasswordMaterial::Header(encrypted) => {
                let (salt, encrypted) = encrypted.split_at(8);
                let salt: &[u8; 8] = salt.try_into().unwrap();
                let first_key = std::sync::Mutex::new(None);
                let keep_key = proven_key.is_some();
                let result = verify_rar_structural_candidates(candidates, false, "rar4_hp_header_crc16", |index, password| {
                    let (key, iv) = keys.rar4(password, salt)?;
                    let matched = decrypt_rar4_header(encrypted, key, iv)?.is_some();
                    if matched && keep_key {
                        let mut slot = first_key.lock().unwrap();
                        if slot.as_ref().is_none_or(|&(earlier, _, _)| index < earlier) {
                            *slot = Some((index, key, iv));
                        }
                    }
                    Some(matched)
                })?;
                if let (Some(proof), Some((index, key, iv))) = (proven_key, first_key.into_inner().unwrap()) {
                    if result.matched_index == Some(index) {
                        *proof = Some(RarProvenKey::Rar4 { salt: *salt, key, iv });
                    }
                }
                Ok(result)
            }
        }
    }
}

fn verify_rar_structural_candidates(
    candidates: &[Arc<str>], strong: bool, evidence: &'static str,
    check: impl Fn(usize, &Arc<str>) -> Option<bool> + Sync,
) -> io::Result<PasswordVerification> {
    let cancel = Cancellation::current();
    use std::sync::atomic::{AtomicUsize, Ordering};
    let earliest = AtomicUsize::new(candidates.len());
    let mut indices: Vec<_> = candidates.par_iter().enumerate().filter_map(|(index,password)| {
        if index > earliest.load(Ordering::Relaxed) || cancel.cancelled() { return None; }
        match cancel.run(|| check(index, password)) {
            Some(false) => None,
            Some(true) if strong => { earliest.fetch_min(index, Ordering::Relaxed); Some(index) }
            _ => Some(index),
        }
    }).collect();
    cancel.check_io()?;
    let hit = earliest.into_inner();
    let confirmed = hit < candidates.len();
    if confirmed { indices.clear(); indices.push(hit); }
    let first = indices.first().copied();
    Ok(PasswordVerification {
        matched_index: first, matched_indices: indices,
        attempts: if confirmed { hit + 1 } else { candidates.len() },
        final_confirmation_required: Some(!confirmed),
        match_evidence: Some(if strong && !confirmed && first.is_some() { "rar5_header_prefix" } else { evidence }),
        ..PasswordVerification::status(if first.is_some() { "match" } else { "no_match" }, "RAR structural password evidence")
    })
}

#[derive(Clone, Copy)]
struct Rar4Block {
    header_type: u8,
    flags: u16,
    header_end: usize,
    next_offset: usize,
}

fn parse_rar4_block(data: &[u8], offset: usize) -> Option<Rar4Block> {
    let header_end = offset.checked_add(RAR4_MIN_HEADER_SIZE)?;
    if header_end > data.len() {
        return None;
    }
    let header_type = data[offset + 2];
    if !RAR4_HEADER_TYPES.contains(&header_type) {
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
struct Rar4HeaderMatch {
    header: Vec<u8>,
}

// Both native password plans and embedded boundary discovery use the same
// bounded material and ordered parallel candidate search. Only a successful
// header owns plaintext; implausible type/size rejects before allocating a header.
fn find_rar4_header(
    candidates: &[Arc<str>],
    salt: &[u8],
    encrypted: &[u8],
    known_key: Option<([u8; 16], [u8; 16])>,
    accept: impl Fn(&[u8]) -> bool + Sync,
) -> Option<(usize, Rar4HeaderMatch)> {
    let salt: &[u8; 8] = salt.try_into().ok()?;
    if encrypted.len() < 16 { return None; }
    let cancellation = Cancellation::current();
    let check = |(index, password): (usize, &Arc<str>)| {
        if cancellation.cancelled() { return None; }
        cancellation.run(|| {
            let (key, iv) = if index == 0 {
                known_key.or_else(|| derive_rar3_key_iv(password, Some(salt)))?
            } else { derive_rar3_key_iv(password, Some(salt))? };
            let header = decrypt_rar4_header(encrypted, key, iv)??;
            accept(&header).then_some((index, Rar4HeaderMatch { header }))
        })
    };
    if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().find_map_first(check)
    } else {
        candidates.iter().enumerate().find_map(check)
    }
}

// Outer None means insufficient ciphertext for a plausible header.
fn decrypt_rar4_header(encrypted: &[u8], key: [u8; 16], iv: [u8; 16]) -> Option<Option<Vec<u8>>> {
    let mut previous = iv;
    let cipher = Aes128::new_from_slice(&key).ok()?;
    let plain = decrypt_cbc_block(&cipher, &mut previous, encrypted.get(..16)?);
    let size = u16::from_le_bytes([plain[5], plain[6]]) as usize;
    if size < RAR4_MIN_HEADER_SIZE || !RAR4_HEADER_TYPES.contains(&plain[2]) {
        return Some(None);
    }
    let aligned = size.checked_add(15)? & !15;
    let mut full = encrypted.get(..aligned)?.to_vec();
    decrypt_cbc_header(&cipher, previous, plain, &mut full);
    full.truncate(size);
    Some((crc32(&full[2..]) as u16 == u16::from_le_bytes([full[0], full[1]])).then_some(full))
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
    header: &Rar5EncryptionIdentity,
    candidates: &[Arc<str>],
    proven_key: Option<&mut Option<RarProvenKey>>,
    keys: &RarKeyCache,
) -> std::io::Result<PasswordVerification> {
    if let Some((index, key)) = find_rar5_password_key_cached(candidates, header, keys) {
        if let Some(proof) = proven_key {
            *proof = Some(RarProvenKey::Rar5 { header: *header, key });
        }
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

fn find_rar5_password_key(
    candidates: &[Arc<str>],
    header: &Rar5EncryptionIdentity,
) -> Option<(usize, [u8; 32])> {
    find_rar5_password_key_cached(candidates, header, &RarKeyCache { direct: true, ..Default::default() })
}

fn find_rar5_password_key_cached(candidates: &[Arc<str>], header: &Rar5EncryptionIdentity, keys: &RarKeyCache) -> Option<(usize, [u8; 32])> {
    let cancellation = Cancellation::current();
    #[cfg(test)]
    let threads = RAR5_CANDIDATE_THREADS.with(|value| value.borrow().clone());
    let derive = |(index, password): (usize, &Arc<str>)| {
        #[cfg(test)]
        if let Some(threads) = &threads { threads.lock().unwrap().push(std::thread::current().id()); }
        if cancellation.cancelled() { return None; }
        cancellation.run(|| header.password_check.and_then(|_| keys.rar5(password, header))).map(|key| (index, key))
    };
    if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().find_map_first(derive)
    } else {
        candidates.iter().enumerate().find_map(derive)
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static RAR5_CANDIDATE_THREADS: std::cell::RefCell<Option<Arc<std::sync::Mutex<Vec<std::thread::ThreadId>>>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Rar5EncryptionIdentity {
    keyed_hash: bool,
    iv: [u8; 16],
    lg2_count: u8,
    salt: [u8; 16],
    password_check: Option<[u8; 8]>,
}

pub(crate) enum RarProvenKey {
    Rar5 { header: Rar5EncryptionIdentity, key: [u8; 32] },
    Rar4 { salt: [u8; 8], key: [u8; 16], iv: [u8; 16] },
}

// The header remains recognizable even when its encryption parameters are
// unsupported. Both discovery and password parsing use these same bounds.
pub(crate) fn rar5_archive_encryption_header(data: &[u8]) -> Option<(usize, usize)> {
    let offset = RAR5_SIGNATURE.len();
    let end = offset.checked_add(rar5_header_len(data.get(offset..)?)?)?;
    let header = data.get(..end)?;
    if crc32(&header[offset + 4..]) != le_u32(header, offset)? { return None; }
    let (_, start) = read_vint(header, offset + 4)?;
    let fields = rar5_common_fields(header, start)?;
    let extra = usize::try_from(fields.extra_size).ok()?;
    (fields.kind == 4 && fields.body <= end.checked_sub(extra)?).then_some((fields.body, end))
}

pub(crate) fn rar5_encryption_identity(data: &[u8], body: usize, end: usize) -> Option<Rar5EncryptionIdentity> {
    parse_rar5_encryption_body(data, body, end, false, false)
}

struct Rar5CommonFields {
    kind: u64,
    flags: u64,
    extra_size: u64,
    data_size: u64,
    body: usize,
}

fn rar5_common_fields(header: &[u8], start: usize) -> Option<Rar5CommonFields> {
    let (kind, cursor) = read_vint(header, start)?;
    let (flags, mut body) = read_vint(header, cursor)?;
    let extra_size = if flags & 1 != 0 {
        let (size, next) = read_vint(header, body)?;
        body = next;
        size
    } else {
        0
    };
    let data_size = if flags & 2 != 0 {
        let (size, next) = read_vint(header, body)?;
        body = next;
        size
    } else {
        0
    };
    Some(Rar5CommonFields { kind, flags, extra_size, data_size, body })
}

struct Rar5FileFields<'a> {
    name: &'a [u8], compression: u64, crc: Option<u32>,
}
fn rar5_file_fields(data: &[u8], mut offset: usize, header_end: usize) -> Option<Rar5FileFields<'_>> {
    let (file_flags, next) = read_vint_bounded(data, offset, header_end)?;
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Unpacked size.
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Attributes.
    offset = next;
    if file_flags & 0x0002 != 0 {
        offset = offset.checked_add(4)?;
    }
    let crc = (file_flags & 4 != 0).then(|| le_u32(data, offset)).flatten();
    if file_flags & 0x0004 != 0 {
        offset = offset.checked_add(4)?;
    }
    let (compression, next) = read_vint_bounded(data, offset, header_end)?;
    offset = next;
    let (_, next) = read_vint_bounded(data, offset, header_end)?; // Host OS.
    offset = next;
    let (name_size, next) = read_vint_bounded(data, offset, header_end)?;
    let extra_start = next.checked_add(usize::try_from(name_size).ok()?)?;
    let name = data.get(next..extra_start)?;
    Some(Rar5FileFields { name, compression, crc })

}

fn rar5_file_encryption_extra(data: &[u8], extra_area_size: u64) -> Option<&[u8]> {
    let extra_end = data.len();
    let mut offset = extra_end.checked_sub(usize::try_from(extra_area_size).ok()?)?;
    while offset < extra_end {
        let (record_size, record_body) = read_vint_bounded(data, offset, extra_end)?;
        let record_end = record_body.checked_add(usize::try_from(record_size).ok()?)?;
        if record_end > extra_end {
            return None;
        }
        let (record_type, body) = read_vint_bounded(data, record_body, record_end)?;
        if record_type == 1 {
            return data.get(body..record_end);
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
) -> Option<Rar5EncryptionIdentity> {
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
    let iv = if include_iv { data[offset + 16..offset + 32].try_into().ok()? } else { [0; 16] };
    offset += 16 + usize::from(include_iv) * 16;
    let password_check = if flags & 1 != 0 {
        if offset.checked_add(12)? > end {
            return None;
        }
        let check: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
        // RAR5 specifies a four-byte SHA-256 checksum of this eight-byte
        // proof. Invalid checks (including old zeroed service records) cannot
        // reject passwords; let the existing extraction fallback decide.
        (Sha256::digest(check)[..4] == data[offset + 8..offset + 12]
            && (!is_service || check != [0; 8])).then_some(check)
    } else {
        None
    };
    Some(Rar5EncryptionIdentity { keyed_hash: include_iv && flags & 2 != 0, lg2_count, salt, password_check, iv })
}

fn rar5_aes_key(password: &str, header: &Rar5EncryptionIdentity) -> Option<[u8; 32]> {
    let (key, check) = derive_rar5_key_check(password, header)?;
    header.password_check.is_none_or(|expected| expected == check).then_some(key)
}

fn derive_rar5_key_check(password: &str, header: &Rar5EncryptionIdentity) -> Option<([u8; 32], [u8; 8])> {
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
        }
    }
    let mut derived_check = [0u8; 8];
    for (index, byte) in final_hash.iter().enumerate() {
        derived_check[index % 8] ^= *byte;
    }
    Some((key, derived_check))
}

pub(crate) enum HeaderPassword {
    Matched(usize, RarTerminalProof),
    Rejected,
    Inconclusive,
}

/// Parse each logical input's public headers once and reuse the winning
/// password plan's key for the decrypted-header walk.
pub(crate) fn probe_header_passwords(
    reader: &ManagedReader,
    start_offset: u64,
    passwords: &[Arc<str>],
    require_terminal: bool,
    proven_key: Option<&RarProvenKey>,
) -> io::Result<HeaderPassword> {
    if passwords.is_empty() {
        return Ok(HeaderPassword::Inconclusive);
    }
    Cancellation::check_current_io()?;
    let signature = reader.read_at(start_offset, 8)?;
    let max_blocks = usize::try_from(reader.len().saturating_sub(start_offset) / 8)
        .unwrap_or(usize::MAX);
    if signature.starts_with(RAR5_SIGNATURE) {
        let Some((offset, header)) = prepare_rar5_encrypted_headers(reader, start_offset)? else {
            return Ok(HeaderPassword::Inconclusive);
        };
        let walk = |key: [u8; 32]| {
            walk_rar5_encrypted_headers(
                reader, offset, &Aes256::new(&key.into()), max_blocks,
                header.password_check.is_some(), require_terminal,
            )
        };
        if let Some(RarProvenKey::Rar5 { header: identity, key }) = proven_key {
            if passwords.len() == 1 && *identity == header {
                let proof = walk(*key)?;
                if proof.password_matched { return Ok(HeaderPassword::Matched(0, proof)); }
                return Ok(HeaderPassword::Inconclusive);
            }
        }
        if header.password_check.is_some() {
            let matched = find_rar5_password_key(passwords, &header);
            Cancellation::check_current_io()?;
            return match matched {
                Some((index, key)) => Ok(HeaderPassword::Matched(index, walk(key)?)),
                None => Ok(HeaderPassword::Rejected),
            };
        }
        let Ok(prefix) = reader.read_at(offset, 32)?.try_into() else { return Ok(HeaderPassword::Inconclusive); };
        let context = RarPasswordContext { material: RarPasswordMaterial::Rar5Header {
            identity: header, prefix, tail: Rar5HeaderTail {
                source: RarTailSource::Fixed(Box::new([RangeSpec::entire(reader)])), offset: offset + 32,
            },
        }};
        let mut matched_key = None;
        let result = context.verify(passwords, Some(&mut matched_key))?;
        if let (Some(index), Some(RarProvenKey::Rar5 { key, .. })) = (result.matched_index, matched_key) {
            return Ok(HeaderPassword::Matched(index, walk(key)?));
        }
    }
    if signature.starts_with(RAR4_SIGNATURE) {
        let Some(offset) = prepare_rar4_encrypted_headers(reader, start_offset)? else {
            return Ok(HeaderPassword::Inconclusive);
        };
        // RAR4's u16 header length needs at most 65536 encrypted bytes.
        // Read once, not once per candidate; short or damaged material remains
        // inconclusive rather than a confirmed password rejection.
        let material = reader.read_at(offset, 8 + 65536)?;
        if material.len() < 24 { return Ok(HeaderPassword::Inconclusive); }
        let (salt, encrypted) = material.split_at(8);
        let known_key = match proven_key {
            Some(RarProvenKey::Rar4 { salt: identity, key, iv })
                if passwords.len() == 1 && identity == salt => Some((*key, *iv)),
            _ => None,
        };
        let matched = find_rar4_header(passwords, salt, encrypted, known_key, |_| true);
        Cancellation::check_current_io()?;
        if let Some((index, matched)) = matched {
            let proof = walk_rar4_encrypted_headers(reader, offset, &passwords[index],
                max_blocks, matched.header)?;
            return Ok(HeaderPassword::Matched(index, proof));
        }
    }
    Ok(HeaderPassword::Inconclusive)
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
    // A failed segment must not discard earlier facts or classify the
    // unvisited remainder.
    Cancellation::check_current_io()?;
    let reader = match ManagedReader::open(&archive_path) {
        Ok(reader) => reader.windowed_probe_reader(),
        Err(error) if is_cancellation(&error) => return Err(error),
        Err(error) => {
            let message = error.to_string();
            return Ok(offsets.into_iter().map(|offset| RarBoundaryResolution {
                offset,
                status: "error",
                end_offset: None,
                password: None,
                error: Some(message.clone()),
            }).collect());
        }
    };
    let mut outcomes = Vec::with_capacity(offsets.len());
    for offset in offsets {
        Cancellation::check_current_io()?;
        let result = probe_header_passwords(&reader, offset, passwords, true, None);
        Cancellation::check_current_io()?;
        let mut row = RarBoundaryResolution {
            offset,
            status: "password_required",
            end_offset: None,
            password: None,
            error: None,
        };
        match result {
            Ok(HeaderPassword::Matched(index, proof)) => {
                row.password = Some(Arc::clone(&passwords[index]));
                row.end_offset = proof.terminal.map(|end| end.offset).filter(|end| *end > offset);
                row.status = if row.end_offset.is_some() { "ok" } else { "truncated" };
            }
            Ok(HeaderPassword::Rejected) => row.status = "wrong_password",
            Ok(HeaderPassword::Inconclusive) => {}
            Err(error) if is_cancellation(&error) => return Err(error),
            Err(error) => {
                row.status = "error";
                row.error = Some(error.to_string());
            }
        }
        outcomes.push(row);
    }
    Ok(outcomes)
}

fn prepare_rar5_encrypted_headers(
    reader: &ManagedReader,
    start_offset: u64,
) -> io::Result<Option<(u64, Rar5EncryptionIdentity)>> {
    let block_offset = start_offset
        .checked_add(RAR5_SIGNATURE.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 offset overflow"))?;
    let prefix = reader.read_at(block_offset, 7)?;
    let Some(total_size) = rar5_header_len(&prefix).filter(|size| *size >= 7) else {
        return Ok(None);
    };
    // Use the same CRC-checked common-header cursor as discovery and fast verification.
    let full = reader.read_at(start_offset, RAR5_SIGNATURE.len() + total_size)?;
    let Some((body, end)) = rar5_archive_encryption_header(&full) else {
        return Ok(None);
    };
    let Some(header) = rar5_encryption_identity(&full, body, end) else {
        return Ok(None);
    };
    let encrypted_header_offset = block_offset
        .checked_add(total_size as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 IV offset overflow"))?;
    Ok(Some((encrypted_header_offset, header)))
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
        let Some(fields) = rar5_common_fields(&full, after_size) else {
            return Ok(proof);
        };
        if !matches!(fields.kind, 1..=5) && fields.flags & 0x0004 == 0 {
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
        let next = next_header_offset.checked_add(fields.data_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "RAR5 data offset overflow")
        })?;
        if fields.kind == 5 {
            let end_flags = read_vint(&full, fields.body)
                .map(|(value, _)| value)
                .unwrap_or(0);
            return Ok(RarTerminalProof {
                password_matched: true,
                terminal: Some(RarTerminal {
                    offset: next,
                    has_next: end_flags & 1 != 0,
                    volume_number: None,
                }),
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
    let Some(total_size) = rar5_header_len(&first_plaintext).filter(|size| *size >= 7) else {
        return Ok(None);
    };
    let aligned_size = total_size
        .checked_add(15)
        .map(|value| value & !15)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR5 header size overflow"))?;
    let mut header = if aligned_size == 16 {
        first_ciphertext
    } else {
        reader.read_at(encrypted_offset, aligned_size)?
    };
    if header.len() != aligned_size {
        return Ok(None);
    }
    decrypt_cbc_header(cipher, previous, first_plaintext, &mut header);
    header.truncate(total_size);
    Ok(Some((
        header,
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

fn prepare_rar4_encrypted_headers(
    reader: &ManagedReader,
    start_offset: u64,
) -> io::Result<Option<u64>> {
    let block_offset = start_offset
        .checked_add(RAR4_SIGNATURE.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 offset overflow"))?;
    let prefix = reader.read_at(block_offset, RAR4_MIN_HEADER_SIZE)?;
    let Some(header_size) = prefix
        .get(5..7)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
        .filter(|size| *size >= RAR4_MIN_HEADER_SIZE)
    else {
        return Ok(None);
    };
    let main_full = reader.read_at(block_offset, header_size)?;
    if main_full.len() != header_size {
        return Ok(None);
    }
    let Some(main) = parse_rar4_block(&main_full, 0) else {
        return Ok(None);
    };
    if main.header_type != 0x73 || main.flags & RAR4_MAIN_HEADER_PASSWORD == 0 {
        return Ok(None);
    }
    let encrypted_header_offset = block_offset
        .checked_add(main.next_offset as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 salt offset overflow"))?;
    Ok(Some(encrypted_header_offset))
}

fn walk_rar4_encrypted_headers(
    reader: &ManagedReader,
    mut block_offset: u64,
    password: &str,
    max_blocks: usize,
    first_header: Vec<u8>,
) -> io::Result<RarTerminalProof> {
    let mut first_header = Some(first_header);
    let mut password_matched = false;
    let incomplete = |matched| RarTerminalProof {
        password_matched: matched,
        ..Default::default()
    };
    for _ in 0..max_blocks {
        let header = if let Some(header) = first_header.take() {
            header
        } else {
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
            if header_size < RAR4_MIN_HEADER_SIZE || !RAR4_HEADER_TYPES.contains(&first_plaintext[2]) {
                return Ok(incomplete(password_matched));
            }
            let aligned_size = header_size
                .checked_add(15)
                .map(|value| value & !15)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "RAR4 header size overflow")
                })?;
            let mut header = if aligned_size == 16 {
                first_ciphertext
            } else {
                reader.read_at(encrypted_offset, aligned_size)?
            };
            if header.len() != aligned_size {
                return Ok(incomplete(password_matched));
            }
            decrypt_cbc_header(&cipher, previous, first_plaintext, &mut header);
            header.truncate(header_size);
            if crc32(&header[2..]) as u16 != u16::from_le_bytes([header[0], header[1]]) {
                return Ok(incomplete(password_matched));
            }
            header
        };
        let full = header.as_slice();
        let aligned_size = (full.len() + 15) & !15;
        let encrypted_offset = block_offset.checked_add(8).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "RAR4 encrypted offset overflow")
        })?;
        let header_type = full[2];
        let header_flags = u16::from_le_bytes([full[3], full[4]]);
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
                terminal: Some(RarTerminal {
                    offset: next,
                    has_next: header_flags & RAR4_END_NEXT_VOLUME != 0,
                    volume_number: rar4_end_volume(full),
                }),
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
