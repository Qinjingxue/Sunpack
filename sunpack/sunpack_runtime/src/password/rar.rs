use super::PasswordVerification;
use crate::formats::rar::{rar4_end_volume, rar5_header_len, rar5_main_volume, read_vint};
use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan};
use crate::io::cancellation::{is_cancellation, Cancellation};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use crate::io::reader::NativeArchiveSession;
use crate::password::context::{InputKey, PasswordContext, Preparation, PreparedStatus};
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_key, read_ranges_at_field, RangeSpec, VirtualRangeReader, VolumeSet,
};
use crate::password::evidence::VolumeProjection;
use crate::password::input::attempts::{AttemptGeometry, AttemptReader, DeferredReadError, DeferredReads, prepare_attempt_evidence_partial};
use aes::cipher::{
    Block, BlockCipherDecrypt, BlockModeDecrypt, InnerIvInit, IvState, KeyInit, consts::U16,
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
const RAR4_FILE_SOLID: u16 = 0x0010;
const RAR4_FILE_SALT: u16 = 0x0400;
#[cfg(test)]
const RAR4_FILE_COMMENT: u16 = 0x0008;
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

fn decrypt_cbc_blocks<C>(cipher: &C, previous: &mut [u8; 16], encrypted: &mut [u8])
where
    C: BlockCipherDecrypt<BlockSize = U16> + Clone,
{
    if encrypted.len() >= 128 {
        let mut decryptor = cbc::Decryptor::inner_iv_init(cipher.clone(), &(*previous).into());
        let (blocks, rest) = Block::<C>::slice_as_chunks_mut(encrypted);
        debug_assert!(rest.is_empty());
        decryptor.decrypt_blocks(blocks);
        previous.copy_from_slice(&decryptor.iv_state());
        return;
    }
    for block in encrypted.chunks_exact_mut(16) {
        let plaintext = decrypt_cbc_block(cipher, previous, block);
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
    preparation.verify(volumes.key(if native_volume { "rar-native" } else { "rar" })?, candidates, || {
        if native_volume {
            native_volumes::prepare_fixed(&volumes, parts, sessions)
        } else {
            prepare_rar_ranges(&volumes.contiguous_ranges()).map(|context| PasswordContext::Rar(Arc::new(context)))
        }
    })
}

#[cfg(test)]
fn rar_fast_verify_passwords_from_attempts(
    preparation: &mut Preparation,
    head: &InputExtent,
    plan: &Arc<VolumeAttemptPlan>,
    candidates: &[Arc<str>],
    sessions: &[NativeArchiveSession],
    native_volume: bool,
) -> io::Result<PasswordVerification> {
    preparation.verify_local(prepare_rar_volume_input(head, plan, sessions, native_volume), candidates)
}

pub(crate) fn prepare_rar_volume_input(
    head: &InputExtent,
    plan: &Arc<VolumeAttemptPlan>,
    sessions: &[NativeArchiveSession],
    native_volume: bool,
) -> Result<PasswordContext, PreparedStatus> {
        if let Some(context) = native_volumes::prepare(head, plan, sessions, native_volume)? { return Ok(context); }
        // A byte-split RAR has a single logical header stream. Native disks
        // above can instead authenticate their own independent records.
        let geometry = if !plan.tail_totals.is_empty() { AttemptGeometry::TailTotals }
            else if let Some(total) = plan.head_size_from_total { AttemptGeometry::TrimmedHead { total } }
            else if plan.minimum_size.is_none() { AttemptGeometry::DiskRelative }
            else { AttemptGeometry::Forward { logical_limit: None } };
        let evidence = prepare_attempt_evidence_partial(head, plan, sessions, geometry, |reader| {
            use std::io::{Read, Seek, SeekFrom};
            let length = reader.len();
            let disk_relative = matches!(geometry, AttemptGeometry::DiskRelative);
            let mut context = prepare_rar_volume(|offset, size, field| {
                let load = |reader: &mut AttemptReader<'_>| {
                    if disk_relative {
                        return reader.advance_disk_offset(0, 0, offset).and_then(|position| match position {
                            Some((disk, local)) => reader.read_disk_spanning(disk, local, size),
                            None => Ok(Vec::new()),
                        })
                    }
                    let count = (size as u64).min(length.saturating_sub(offset)) as usize;
                    let mut bytes = vec![0; count];
                    reader.seek(SeekFrom::Start(offset)).and_then(|_| reader.read_exact(&mut bytes))?;
                    Ok(bytes)
                };
                let result = if matches!(field, "rar4.compressed_block" | "rar5.compressed_block") {
                    reader.independent_evidence(load)
                } else {
                    load(reader)
                };
                result.map_err(|err| ReadFault::from_io(err,
                    if disk_relative { "read_volume" } else { "read" }, offset, size, 0, length)
                    .with_field(field, FieldLocation::Head))
            }, None, RarRanges::Projected)?;
            if let Some(source) = context.material.tail_source() {
                *source = RarTailSource::Projected(reader.deferred_reads(disk_relative));
            }
            Ok(Some(context))
        })?;
        Ok(evidence.into_context(|c| PasswordContext::Rar(Arc::new(c))))
}

#[derive(Clone, Copy)]
enum RarRanges<'a> {
    Fixed(&'a [RangeSpec], bool),
    Projected,
}

fn prepare_rar_ranges(ranges: &[RangeSpec]) -> Result<RarPasswordContext, PreparedStatus> {
    prepare_rar_volume(|offset, size, field| read_ranges_at_field(ranges, offset, size, field), None, RarRanges::Fixed(ranges, false))
}

/// `read_at(offset, len, field)` returns fewer than `len` bytes only at the end
/// of the input.
#[cfg(test)]
fn prepare_rar(
    mut read_at: impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
) -> Result<RarPasswordContext, PreparedStatus> {
    prepare_rar_volume(&mut read_at, None, RarRanges::Projected)
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
        RarRanges::Fixed(..) => RAR_INITIAL_PREFIX_SCAN,
        RarRanges::Projected => RAR4_SIGNATURE.len() + RAR4_MIN_HEADER_SIZE,
    };
    let data = read_at(0, prefix_size, "rar.header_prefix")?;
    let main_offset = RAR4_SIGNATURE.len() as u64;
    let header_hint = if matches!(ranges, RarRanges::Fixed(..)) { RAR4_HEADER_READ_HINT } else { RAR4_MIN_HEADER_SIZE };
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
        return prepare_rar4_members(&data, next, &mut read_at, facts, ranges, header_hint);
    }
    let known_prefix = usize::try_from(next).ok().and_then(|at| data.get(at..at.checked_add(24)?));
    let read_prefix;
    let encrypted = if let Some(bytes) = known_prefix {
        bytes
    } else {
        read_prefix = read_at(next, 24, "rar4.encrypted_header.salt_block")?;
        &read_prefix
    };
    let prefix: [u8; 24] = encrypted.try_into().map_err(|_| ReadFault::short_read(
        "read_record", next, 24, encrypted.len(), next.saturating_add(encrypted.len() as u64),
    ).with_field("rar4.encrypted_header.salt_block", FieldLocation::Head))?;
    Ok(RarPasswordContext { material: RarPasswordMaterial::Header(Rar4HeaderProbe {
        prefix,
        offset: next,
        source: ranges.tail_source(next, u64::MAX),
    }) })
}

fn prepare_rar5_stream(
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    facts: Option<&mut VolumeFacts>,
    ranges: RarRanges<'_>,
) -> Result<RarPasswordContext, PreparedStatus> {
    // Scan headers for a short, strong check before touching compressed
    // data. Retain one weak location and only revisit later headers after
    // an actual read failure at that location.
    let mut first = None;
    let mut more = false;
    let result = walk_rar5_stream(read_at, facts, ranges, RAR5_SIGNATURE.len() as u64, |candidate, _| {
        if first.is_some() {
            more = true;
        } else {
            first = Some(candidate);
        }
        None
    });
    let Some(first) = first.filter(|_| result.is_err() && !Cancellation::current().cancelled()) else {
        return result;
    };
    match first.prepare(read_at, ranges) {
        Ok(context) => Ok(context),
        Err(error) if more && !Cancellation::current().cancelled() => {
            walk_rar5_stream(read_at, None, ranges, first.offset + first.packed_size,
                |candidate, read| candidate.prepare(read, ranges).ok()).or(Err(error))
        }
        Err(error) => Err(error),
    }
}

fn walk_rar5_stream<R>(
    read_at: &mut R,
    mut facts: Option<&mut VolumeFacts>,
    ranges: RarRanges<'_>,
    mut offset: u64,
    mut weak: impl FnMut(Rar5BlockStart, &mut R) -> Option<RarPasswordContext>,
) -> Result<RarPasswordContext, PreparedStatus>
where
    R: FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
{
    let unknown = || {
        PreparedStatus::new(
            "unknown_needs_final_verifier",
            "RAR5 encryption metadata is unavailable",
        )
    };
    let stop_at_proof = facts.as_ref().is_none_or(|facts| facts.stop_at_proof);
    let mut encrypted_seen = false;
    let mut saved: Option<RarPasswordMaterial> = None;
    let mut fallback = None;
    let scanned = (|| loop {
        let read_hint = if matches!(ranges, RarRanges::Fixed(..)) { 64 } else { 7 };
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
        let empty_stored = fields.kind == 2 && fields.data_size == 0 && fields.flags & 24 == 0
            && file.as_ref().is_some_and(|file| file.empty_stored);
        let extras = if matches!(fields.kind, 2 | 3) {
            let packed = fields.flags & 16 != 0 && facts.as_ref().is_some_and(|f| f.checks_packed());
            rar5_file_extras(&header, fields.extra_size, packed || empty_stored)
        } else {
            Rar5FileExtras::default()
        };
        let file_crypto = extras.encryption;
        let encryption = match fields.kind {
            4 => parse_rar5_encryption_body(&header, fields.body, length, false, false).map(|identity| (identity, 0)),
            2 | 3 => file_crypto.zip(file.as_ref()).and_then(|(record, file)|
                parse_rar5_encryption_body(record, 0, record.len(), true, fields.kind == 3)
                    .map(|identity| (identity, file.compression))),
            _ => None,
        };
        encrypted_seen |= file_crypto.is_some() || fields.kind == 4;
        if fields.kind == 4 && encryption.is_none() {
            return Err(PreparedStatus::new("unsupported_method", "RAR5 archive encryption parameters are unavailable or unsupported"));
        }
        if file_crypto.is_some() && encryption.is_none() {
            fallback.get_or_insert("RAR5 file encryption parameters are unavailable or unsupported");
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
                    facts.file(fields.flags & 8 != 0 && !file.directory, fields.flags & 16 != 0 && !file.directory, file.name,
                        offset + length as u64, fields.data_size);
                    // Writer-produced non-final fragments have an unkeyed
                    // checksum over these stored bytes, even when encrypted.
                    if fields.flags & 16 != 0 && !extras.keyed_hash {
                        if let Some(crc) = file.crc {
                            facts.packed(offset + length as u64, fields.data_size, native_volumes::PackedDigest::Crc32(crc));
                        } else if let Some(hash) = extras.blake2sp {
                            facts.packed(offset + length as u64, fields.data_size, native_volumes::PackedDigest::Blake2sp(hash));
                        }
                    }
                }
            }
        }
        if let Some((encryption, compression)) = encryption {
            if encryption.password_check.is_none() {
                let data_offset = offset.checked_add(length as u64).ok_or_else(unknown)?;
                let next = data_offset.checked_add(fields.data_size).ok_or_else(unknown)?;
                let empty_mac = (empty_stored && extras.keyed_hash && !extras.redirected)
                    .then(|| Rar5EmptyMac { crc: file.as_ref()?.crc, blake: extras.blake2sp }.into_present()).flatten();
                let material = if fields.kind == 4 {
                    // RAR5 limits the header-size vint to three bytes. This is
                    // the format's maximum header extent, not a parser budget.
                    let prefix = read_at(data_offset, 32, "rar5.encrypted_header")?
                        .try_into().map_err(|_| unknown())?;
                    let offset = data_offset.checked_add(32).ok_or_else(unknown)?;
                    let source = ranges.tail_source(offset, 1 << 21);
                    let tail = Rar5HeaderTail { source, offset };
                    RarPasswordMaterial::Rar5Header { identity: encryption, prefix, tail }
                } else if let Some(mac) = empty_mac {
                    RarPasswordMaterial::Rar5EmptyMac { identity: encryption, mac }
                } else if saved.is_none() && fields.flags & 8 == 0 && compression & 0x3f <= 1
                    && (1..=5).contains(&((compression >> 7) & 7))
                    && (fields.data_size >= 16 || (ranges.native() && fields.flags & 16 != 0)) {
                    if let Some(context) = weak(Rar5BlockStart {
                        identity: encryption,
                        offset: data_offset,
                        packed_size: fields.data_size,
                        split_after: fields.flags & 16 != 0,
                        solid: compression & 0x40 != 0,
                    }, read_at) {
                        return Ok(context);
                    }
                    offset = next;
                    continue;
                } else {
                    // Stored/continuation/unknown methods carry no safe block
                    // prefix. A later independent member can still prove a key.
                    fallback.get_or_insert(if fields.flags & 8 != 0 {
                        "RAR5 compressed stream starts in an earlier volume"
                    } else if (compression >> 7) & 7 == 0 {
                        "RAR5 Stored data has no short password verification field"
                    } else if fields.data_size < 16 {
                        "RAR5 volume does not contain the first encrypted data block"
                    } else {
                        "RAR5 compressed stream has no supported structural check"
                    });
                    offset = next;
                    continue;
                };
                if fields.kind == 4 { return Ok(RarPasswordContext { material }); }
                if stop_at_proof && material.empty_mac_strength() != 0 {
                    return Ok(RarPasswordContext { material });
                }
                if saved.as_ref().is_none_or(|earlier| material.empty_mac_strength() > earlier.empty_mac_strength()) {
                    saved = Some(material);
                }
            } else {
                let material = RarPasswordMaterial::Rar5(encryption);
                if stop_at_proof || fields.kind == 4 { return Ok(RarPasswordContext { material }); }
                if !matches!(saved, Some(RarPasswordMaterial::Rar5(_))) { saved = Some(material); }
            }

        }
        if fields.kind == 5 {
            let has_next = read_vint(&header, fields.body).map(|(flags, _)| flags & 1 != 0);
            if let Some(facts) = facts.as_deref_mut() { facts.has_next = has_next; }
            if let Some(material) = saved.take() { return Ok(RarPasswordContext { material }); }
            if encrypted_seen || has_next != Some(false) {
                return Err(fallback.map_or_else(unknown, |reason|
                    PreparedStatus::new("unknown_needs_final_verifier", reason)));
            }
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

struct Rar5BlockStart {
    identity: Rar5EncryptionIdentity,
    offset: u64,
    packed_size: u64,
    split_after: bool,
    solid: bool,
}

impl Rar5BlockStart {
    fn prepare(
        &self,
        read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
        ranges: RarRanges<'_>,
    ) -> Result<RarPasswordContext, PreparedStatus> {
        let encrypted = (self.packed_size >= 16)
            .then(|| read_compressed_start(read_at, self.offset, "rar5.compressed_block"))
            .transpose()?;
        let next = self.offset.checked_add(16).ok_or_else(|| PreparedStatus::new(
            "unknown_needs_final_verifier", "RAR5 first encrypted block is outside the input"))?;
        let source = ranges.tail_source(next, self.packed_size.saturating_sub(16));
        Ok(RarPasswordContext { material: RarPasswordMaterial::Rar5Block {
            identity: self.identity,
            block: Rar5BlockProbe {
                encrypted,
                offset: self.offset,
                packed_size: self.packed_size,
                split_after: self.split_after,
                solid: self.solid,
                source,
            },
        } })
    }
}

fn read_compressed_start(
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    offset: u64, field: &'static str,
) -> Result<[u8; 16], PreparedStatus> {
    read_at(offset, 16, field)?.try_into().map_err(|bytes: Vec<u8>| ReadFault::short_read(
        "read_record", offset, 16, bytes.len(), offset.saturating_add(bytes.len() as u64),
    ).with_field(field, FieldLocation::Head).into())
}

/// Seek over payloads, reading only plaintext headers and the first available
/// independent compressed prefix. Headers inside the initial read cost no I/O.
fn prepare_rar4_members(
    prefix: &[u8],
    mut offset: u64,
    read_at: &mut impl FnMut(u64, usize, &'static str) -> Result<Vec<u8>, ReadFault>,
    mut facts: Option<&mut VolumeFacts>,
    ranges: RarRanges<'_>,
    header_hint: usize,
) -> Result<RarPasswordContext, PreparedStatus> {
    let unknown = || PreparedStatus::new("unknown_needs_final_verifier",
        "RAR4 metadata has no independent compressed stream start");
    let mut encrypted = false;
    let mut saved = None;
    let mut prefix_failure = None;
    let scanned = (|| loop {
        let Some(header) = read_rar4_header_at(prefix, offset, read_at, header_hint)? else {
            return Err(unknown());
        };
        let Some(block) = parse_rar4_block(&header, 0) else {
            if let Some(facts) = facts.as_deref_mut() {
                facts.invalid = !rar4_header_crc_matches(&header);
            }
            return Err(unknown());
        };
        let data_size = (block.next_offset - block.header_end) as u64;
        let data_offset = offset.checked_add(block.header_end as u64).ok_or_else(unknown)?;
        match block.header_type {
            0x74 => {
                let protected = block.flags & RAR4_FILE_PASSWORD != 0;
                encrypted |= protected;
                if let Some(facts) = facts.as_deref_mut() {
                    let start = if block.flags & 0x100 != 0 { 40 } else { 32 };
                    if let Some(size) = header.get(26..28) {
                        let size = u16::from_le_bytes(size.try_into().unwrap()) as usize;
                        if let Some(name) = header.get(start..start + size) {
                            let file = block.flags & 0xe0 != 0xe0;
                            facts.file(file && block.flags & 1 != 0, file && block.flags & 2 != 0, name, data_offset, data_size);
                        }
                    }
                    if block.flags & 2 != 0 && header.get(24).is_some_and(|&version| version >= 29) {
                        if let Some(crc) = le_u32(&header, 16).filter(|&crc| crc != u32::MAX) {
                            facts.packed(data_offset, data_size, native_volumes::PackedDigest::Crc32(crc));
                        }
                    }
                }
                if protected && saved.is_none() && (data_size >= 16 || (ranges.native() && block.flags & 2 != 0)) {
                    if let Some(salt) = rar4_file_salt(&header, block.flags) {
                        let encrypted = (data_size >= 16).then(|| {
                            let known = usize::try_from(data_offset).ok().and_then(|at|
                                prefix.get(at..at.checked_add(16)?)).and_then(|bytes| bytes.try_into().ok());
                            known.map_or_else(|| read_compressed_start(read_at, data_offset,
                                "rar4.compressed_block"), Ok)
                        }).transpose();
                        match encrypted {
                            Ok(encrypted) => {
                                let next = data_offset.checked_add(16).ok_or_else(unknown)?;
                                let source = ranges.tail_source(next, data_size.saturating_sub(16).min((RAR3_TABLE_WINDOW - 16) as u64));
                                let material = RarPasswordMaterial::Rar4Block(Rar4BlockProbe {
                                    salt, encrypted, next, data_size, split_after: block.flags & 2 != 0, source,
                                });
                                if facts.as_ref().is_none_or(|facts|
                                    facts.stop_at_proof && block.flags & 2 == 0) {
                                    return Ok(RarPasswordContext { material });
                                }
                                saved = Some(material);
                            }
                            Err(error) => { prefix_failure.get_or_insert(error); }
                        }
                    }
                }
            }
            0x7b => {
                if let Some(facts) = facts.as_deref_mut() {
                    facts.number = rar4_end_volume(&header).or(facts.number);
                    facts.has_next = Some(block.flags & RAR4_END_NEXT_VOLUME != 0);
                }
                return Err(if !encrypted && block.flags & RAR4_END_NEXT_VOLUME == 0 {
                    PreparedStatus::new("not_required", "RAR4 file headers contain no encrypted entries")
                } else { unknown() });
            }
            _ => {}
        }
        offset = data_offset.checked_add(data_size).ok_or_else(unknown)?;
    })();
    scanned.or_else(|error| saved.map(|material| RarPasswordContext { material })
        .ok_or_else(|| prefix_failure.unwrap_or(error)))
}

fn rar4_file_salt(header: &[u8], flags: u16) -> Option<Option<[u8; 8]>> {
    // Split continuations start inside CBC and solid streams can reuse tables.
    if flags & (1 | RAR4_FILE_SOLID) != 0 || flags & 0xe0 == 0xe0
        || !(29..=40).contains(header.get(24)?)
        || !(0x31..=0x35).contains(header.get(25)?) {
        return None;
    }
    if flags & RAR4_FILE_SALT == 0 { return Some(None); }
    let name_size = usize::from(u16::from_le_bytes(header.get(26..28)?.try_into().ok()?));
    let salt = 32 + usize::from(flags & 0x100 != 0) * 8 + name_size;
    Some(Some(header.get(salt..salt + 8)?.try_into().ok()?))
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

impl RarPasswordContext {
    pub(super) fn has_local_evidence(&self) -> bool {
        match &self.material {
            RarPasswordMaterial::Rar4Block(block) => block.encrypted.is_some(),
            RarPasswordMaterial::Rar5Block { block, .. } => block.encrypted.is_some(),
            _ => true,
        }
    }

    pub(super) fn can_follow_native(&self) -> bool {
        matches!(&self.material, RarPasswordMaterial::Rar4Block(block) if block.split_after)
            || matches!(&self.material, RarPasswordMaterial::Rar5Block { block, .. } if block.split_after)
    }

    pub(super) fn with_native_tail(
        &self, reader: &mut AttemptReader<'_>, disk: usize, start: &RarContinuationFragment,
        fragments: &Arc<[Option<RarContinuationFragment>]>,
    ) -> io::Result<Option<Self>> {
        let prepare = |reader: &mut AttemptReader<'_>, encrypted, follow_headers| {
            let encrypted = match encrypted {
                Some(encrypted) => Some(encrypted),
                None => reader.independent_evidence(|reader| {
                    read_native_rar(reader, &mut NativeRarPosition::new(disk, start), start, fragments, start.offset, 16)
                })?.try_into().ok(),
            };
            let source = RarTailSource::Native(Box::new(NativeRarTail {
                reads: reader.deferred_reads(true), disk, start: start.clone(), fragments: Arc::clone(fragments),
                last_ambiguous_disk: if follow_headers { reader.last_ambiguous_native_disk(disk) } else { None },
            }));
            Ok::<_, io::Error>((encrypted, source))
        };
        let material = match &self.material {
            RarPasswordMaterial::Rar4Block(block) if block.split_after
                && block.next.checked_sub(16) == Some(start.offset) && block.data_size == start.size =>
                {
                    let (encrypted, source) = prepare(reader, block.encrypted, false)?;
                    let Some(encrypted) = encrypted else { return Ok(None); };
                    RarPasswordMaterial::Rar4Block(Rar4BlockProbe {
                        salt: block.salt, encrypted: Some(encrypted), next: block.next,
                        data_size: block.data_size, split_after: true, source,
                    })
                }
            RarPasswordMaterial::Rar5Block { identity, block } if block.split_after
                && block.offset == start.offset && block.packed_size == start.size =>
                {
                    let (encrypted, source) = prepare(reader, block.encrypted, true)?;
                    let Some(encrypted) = encrypted else { return Ok(None); };
                    RarPasswordMaterial::Rar5Block { identity: *identity, block: Rar5BlockProbe {
                        encrypted: Some(encrypted), offset: block.offset, packed_size: block.packed_size,
                        split_after: true, solid: block.solid, source,
                    } }
                }
            _ => return Ok(None),
        };
        Ok(Some(Self { material }))
    }
}

enum RarPasswordMaterial {
    Rar5(Rar5EncryptionIdentity),
    Rar5Header { identity: Rar5EncryptionIdentity, prefix: [u8; 32], tail: Rar5HeaderTail },
    Rar5Block { identity: Rar5EncryptionIdentity, block: Rar5BlockProbe },
    Rar5EmptyMac { identity: Rar5EncryptionIdentity, mac: Rar5EmptyMac },
    Header(Rar4HeaderProbe),
    Rar4Block(Rar4BlockProbe),
}

impl RarPasswordMaterial {
    fn empty_mac_strength(&self) -> u8 {
        match self {
            Self::Rar5(_) => 3,
            Self::Rar5EmptyMac { mac, .. } => if mac.blake.is_some() { 2 } else { 1 },
            _ => 0,
        }
    }

    fn tail_source(&mut self) -> Option<&mut RarTailSource> {
        match self {
            Self::Rar5(_) | Self::Rar5EmptyMac { .. } => None,
            Self::Rar5Header { tail, .. } => Some(&mut tail.source),
            Self::Rar5Block { block, .. } => Some(&mut block.source),
            Self::Header(header) => Some(&mut header.source),
            Self::Rar4Block(block) => Some(&mut block.source),
        }
    }
}

struct Rar5HeaderTail {
    source: RarTailSource,
    offset: u64,
}

struct Rar5EmptyMac {
    crc: Option<u32>,
    blake: Option<[u8; 32]>,
}

impl Rar5EmptyMac {
    fn into_present(self) -> Option<Self> {
        (self.crc.is_some() || self.blake.is_some()).then_some(self)
    }

    fn verify(&self, key: &[u8; 32]) -> RarProof {
        const EMPTY_BLAKE2SP: [u8; 32] = [
            0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e, 0x25,
            0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f,
        ];
        let mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        if let Some(expected) = self.crc {
            let mut mac = mac.clone();
            mac.update(&[0; 4]); // CRC32 of a known empty byte string.
            let actual = mac.finalize().into_bytes().chunks_exact(4).fold(0, |crc, bytes|
                crc ^ u32::from_le_bytes(bytes.try_into().unwrap()));
            if actual != expected { return RarProof::Reject; }
        }
        if let Some(expected) = self.blake {
            let mut mac = mac;
            mac.update(&EMPTY_BLAKE2SP);
            if mac.finalize().into_bytes().as_slice() != expected { return RarProof::Reject; }
        }
        // A folded 32-bit keyed MAC still authenticates the key with zero data.
        RarProof::Confirmed
    }
}

enum RarTailSource {
    Fixed(Box<[RangeSpec]>),
    Projected(DeferredReads),
    Native(Box<NativeRarTail>),
    PrefixOnly,
}

#[derive(Clone)]
pub(super) struct RarContinuationFragment {
    pub(super) name: Box<[u8]>,
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) split_after: bool,
}

struct NativeRarTail {
    reads: DeferredReads,
    disk: usize,
    start: RarContinuationFragment,
    fragments: Arc<[Option<RarContinuationFragment>]>,
    last_ambiguous_disk: Option<usize>,
}

#[derive(Clone, Copy)]
struct NativeRarPosition<'a> {
    disk: usize,
    logical_start: u64,
    fragment: &'a RarContinuationFragment,
}

impl<'a> NativeRarPosition<'a> {
    fn new(disk: usize, fragment: &'a RarContinuationFragment) -> Self {
        Self { disk, logical_start: fragment.offset, fragment }
    }
}

fn read_native_rar<'a>(
    reader: &mut AttemptReader<'_>, position: &mut NativeRarPosition<'a>, start: &'a RarContinuationFragment,
    fragments: &'a [Option<RarContinuationFragment>], offset: u64, len: usize,
) -> io::Result<Vec<u8>> {
    let mut relative = offset.checked_sub(position.logical_start).ok_or(io::ErrorKind::UnexpectedEof)?;
    let mut current = *position;
    let mut bytes = vec![0; len];
    let mut written = 0;
    loop {
        let fragment = current.fragment;
        if relative < fragment.size {
            if written == 0 { *position = current; }
            let count = (fragment.size - relative).min((len - written) as u64) as usize;
            let at = fragment.offset.checked_add(relative).ok_or(io::ErrorKind::UnexpectedEof)?;
            let actual = reader.read_native_disk(current.disk, at, &mut bytes[written..written + count])?;
            written += actual;
            if written == len {
                return Ok(bytes);
            }
            if actual != count { break; }
            relative = fragment.size;
        }
        if !fragment.split_after {
            break;
        }
        relative -= fragment.size;
        let disk = current.disk.checked_add(1).ok_or(io::ErrorKind::UnexpectedEof)?;
        let Some(id) = reader.native_proof(disk, |source| {
            fragments[source].as_ref().filter(|part| part.name == start.name).map(|_| source)
        })? else { break };
        current = NativeRarPosition {
            disk,
            logical_start: current.logical_start.checked_add(fragment.size).ok_or(io::ErrorKind::UnexpectedEof)?,
            fragment: fragments[id].as_ref().unwrap(),
        };
    }
    bytes.truncate(written);
    Ok(bytes)
}

impl RarRanges<'_> {
    fn native(self) -> bool {
        matches!(self, Self::Fixed(_, true))
    }

    fn tail_source(self, offset: u64, len: u64) -> RarTailSource {
        match self {
            Self::Fixed(ranges, _) => RarTailSource::Fixed(RangeSpec::covering(ranges, offset, len).into()),
            Self::Projected => RarTailSource::PrefixOnly,
        }
    }
}

impl RarTailSource {
    fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }

    fn range_is_ambiguous(&self, offset: u64, size: u64) -> bool {
        matches!(self, Self::Projected(source) if source.range_is_ambiguous(offset, size))
    }

    fn verify(&self, mut check: impl FnMut(&mut RarProbeRead<'_>, &std::cell::Cell<bool>) -> RarProof) -> io::Result<RarCheck> {
        let mut result = RarCheck::from(RarProof::Reject);
        let may_narrow_native = std::cell::Cell::new(false);
        let checks = match self {
            Self::Projected(source) =>
                source.evaluate(|reader| check(&mut |offset, size| reader.read(offset, size), &may_narrow_native))?,
            Self::Native(source) =>
                source.reads.evaluate(|reader| {
                    let start = NativeRarPosition::new(source.disk, &source.start);
                    let mut position = start;
                    may_narrow_native.set(source.last_ambiguous_disk.is_some());
                    check(&mut |offset, size| {
                        if offset < position.logical_start { position = start; }
                        let bytes = reader.load(|reader| read_native_rar(reader, &mut position, &source.start,
                            &source.fragments, offset, size))?;
                        may_narrow_native.set(source.last_ambiguous_disk.is_some_and(|disk| position.disk <= disk));
                        if bytes.len() == size { Ok(bytes) } else { Err(DeferredReadError::Missing) }
                    }, &may_narrow_native)
                })?,
            Self::Fixed(ranges) => {
                let mut reader = VirtualRangeReader::streaming(ranges);
                return Ok(check(&mut |offset, size| {
                    let bytes = reader.read_at(offset, size).map_err(DeferredReadError::Io)?;
                    if bytes.len() != size { return Err(DeferredReadError::Missing); }
                    Ok(bytes)
                }, &may_narrow_native).into());
            }
            Self::PrefixOnly => return Ok(check(&mut |_, _| Err(DeferredReadError::Missing), &may_narrow_native).into()),
        };
        let corroborated = checks.iter().any(|(_, proof)| *proof == RarProof::Successor(true));
        for (projection, proof) in checks {
            let proof = match proof {
                RarProof::Successor(false) if corroborated => RarProof::Reject,
                RarProof::Successor(_) => RarProof::Confirmed,
                proof => proof,
            };
            if proof == RarProof::Reject {
                result.rejected.push(projection);
            } else if result.proof == RarProof::Reject || (result.proof == RarProof::Confirmed && proof != RarProof::Confirmed) {
                // A strong hit on just one alternative cannot confirm a
                // password for the unreadable or weak siblings.
                result.proof = proof;
            }
        }
        Ok(result)
    }
}

type RarProbeRead<'a> = dyn FnMut(u64, usize) -> Result<Vec<u8>, DeferredReadError> + 'a;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RarProof {
    Reject,
    Weak(Option<&'static str>),
    Confirmed,
    Successor(bool),
}

impl RarProof {
    fn fallback(error: DeferredReadError) -> Self {
        Self::Weak(Some(match error {
            DeferredReadError::Missing => "RAR follow-up needs missing bytes",
            DeferredReadError::Pending => "RAR follow-up has multiple byte sources",
            DeferredReadError::Io(_) => "RAR follow-up could not read its source",
            DeferredReadError::Truncated => "RAR follow-up source is truncated",
            DeferredReadError::Cancelled => "RAR follow-up was cancelled",
        }))
    }
}

struct RarCheck {
    proof: RarProof,
    rejected: Vec<Arc<VolumeProjection>>,
}

impl From<RarProof> for RarCheck {
    fn from(proof: RarProof) -> Self {
        Self { proof, rejected: Vec::new() }
    }
}

struct Rar5BlockProbe {
    encrypted: Option<[u8; 16]>,
    offset: u64,
    packed_size: u64,
    split_after: bool,
    solid: bool,
    source: RarTailSource,
}

#[derive(Default)]
struct Rar5BlockWindow {
    start: u64,
    end: u64,
    plain: [u8; 32],
}

struct Rar4BlockProbe {
    salt: Option<[u8; 8]>,
    encrypted: Option<[u8; 16]>,
    next: u64,
    data_size: u64,
    split_after: bool,
    source: RarTailSource,
}

#[derive(PartialEq, Eq)]
enum LevelTable {
    Impossible,
    Incomplete,
    Complete,
}

/// Validate the RAR3 and RAR5 20-entry alphabet without reading member symbols.
fn rar_level_table(data: &[u8], bit: usize, available: usize) -> LevelTable {
    rar_level_lengths(data, bit, available).map_or_else(|status| status, |_| LevelTable::Complete)
}

fn rar_level_lengths(
    data: &[u8], bit: usize, available: usize,
) -> Result<([u8; 20], usize), LevelTable> {
    let mut position = bit;
    let mut next = || {
        let start = position;
        position += 4;
        if position > available || position > data.len() * 8 { return None; }
        let word = u16::from_be_bytes([data[start / 8], data.get(start / 8 + 1).copied().unwrap_or(0)]);
        Some(((word >> (12 - start % 8)) & 15) as usize)
    };
    let mut slots = 1 << 15;
    let mut entries = 20usize;
    let mut lengths = [0; 20];
    while entries != 0 {
        let Some(length) = next() else {
            return Err(if position > available { LevelTable::Impossible } else { LevelTable::Incomplete });
        };
        if length == 15 {
            let Some(run) = next() else {
                return Err(if position > available { LevelTable::Impossible } else { LevelTable::Incomplete });
            };
            if run != 0 {
                entries = entries.saturating_sub(run + 2);
                continue;
            }
        }
        if length != 0 {
            slots -= 1 << (15 - length);
            if slots < 0 { return Err(LevelTable::Impossible); }
        }
        lengths[20 - entries] = length as u8;
        entries -= 1;
    }
    if slots == 0 { Ok((lengths, position)) } else { Err(LevelTable::Impossible) }
}

// The RAR3 LZ block declares four consecutive Huffman trees. Each of the
// 404 lengths costs at most a 15-bit code and 7 extra bits.
const RAR3_TREE_SIZES: [usize; 4] = [299, 60, 17, 28];
const RAR3_TABLE_WINDOW: usize = (2usize + 20 * 8 + 404 * 22).div_ceil(128) * 16;

fn rar3_lz_tables(data: &[u8]) -> LevelTable {
    let (levels, mut bit) = match rar_level_lengths(data, 2, usize::MAX) {
        Ok(levels) => levels,
        Err(state) => return state,
    };
    let mut sorted = [0usize; 20];
    let mut counts = [0usize; 16];
    for &length in levels.iter().filter(|&&length| length != 0) { counts[length as usize] += 1; }
    let mut next = [0usize; 16];
    for length in 2..next.len() {
        next[length] = next[length - 1] + counts[length - 1];
    }
    for (symbol, &length) in levels.iter().enumerate() {
        if length == 0 { continue; }
        let slot = &mut next[length as usize];
        sorted[*slot] = symbol;
        *slot += 1;
    }
    let mut read = |width: usize| {
        let end = bit + width;
        if end > data.len() * 8 { return None; }
        let mut value = 0;
        while bit < end {
            value = (value << 1) | usize::from((data[bit / 8] >> (7 - bit % 8)) & 1);
            bit += 1;
        }
        Some(value)
    };
    let mut remaining = RAR3_TREE_SIZES.into_iter();
    let mut tree_end = remaining.next().unwrap();
    let total: usize = RAR3_TREE_SIZES.iter().sum();
    let mut position = 0;
    let mut units = 0;
    let mut previous = 0;
    while position < total {
        let mut code = 0;
        let mut start = 0;
        let mut symbol = None;
        for &count in &counts[1..] {
            let Some(next) = read(1) else { return LevelTable::Incomplete; };
            code = (code << 1) + next;
            if code < count {
                symbol = Some(sorted[start + code]);
                break;
            }
            code -= count;
            start += count;
        }
        let Some(symbol) = symbol else { return LevelTable::Impossible; };
        let (length, end) = if symbol < 16 {
            (symbol, position + 1)
        } else {
            if symbol < 18 && position == 0 { return LevelTable::Impossible; }
            let extra = 3 + (symbol & 1) * 4;
            let Some(run) = read(extra) else { return LevelTable::Incomplete; };
            let end = (position + run + extra * 2 - 3).min(total);
            (if symbol < 18 { previous } else { 0 }, end)
        };
        previous = length;
        let step = if length == 0 { 0 } else { 1usize << (15 - length) };
        while position < end {
            let stop = tree_end.min(end);
            units += (stop - position) * step;
            if units > 1 << 15 { return LevelTable::Impossible; }
            position = stop;
            if position == tree_end {
                units = 0;
                tree_end += remaining.next().unwrap_or(0);
            }
        }
    }
    LevelTable::Complete
}

impl Rar4BlockProbe {
    fn verify(&self, password: &Arc<str>, keys: &RarKeyCache) -> io::Result<RarCheck> {
        let Some(encrypted) = self.encrypted else {
            return Ok(RarProof::Weak(Some("RAR4 first encrypted block continues in the next volume")).into());
        };
        let Some((key, mut iv)) = keys.rar4(password, self.salt.as_ref()) else {
            return Ok(RarProof::Weak(None).into());
        };
        let cipher = Aes128::new((&key).into());
        let first = decrypt_cbc_block(&cipher, &mut iv, &encrypted);
        let weak = RarProof::Weak(None);
        if first[0] & 0x80 != 0 {
            // A fresh PPM stream must initialize a model with order >= 2.
            let flags = first[0];
            return Ok(if flags & 0x20 != 0 && flags & 0x1f != 0 { weak } else { RarProof::Reject }.into());
        }
        match rar3_lz_tables(&first) {
            LevelTable::Impossible => Ok(RarProof::Reject.into()),
            LevelTable::Complete => Ok(weak.into()),
            LevelTable::Incomplete => self.source.verify(|read, _| {
                let mut plain = [0; RAR3_TABLE_WINDOW];
                plain[..16].copy_from_slice(&first);
                let mut previous = encrypted;
                let end = if self.source.is_native() { plain.len() }
                    else { self.data_size.min(plain.len() as u64) as usize & !15 };
                let mut len = 16;
                while len < end {
                    let next = (len * 2).min(end);
                    let Some(offset) = self.next.checked_add((len - 16) as u64) else { return RarProof::Reject; };
                    let bytes = match read(offset, next - len) {
                        Ok(bytes) => bytes,
                        Err(DeferredReadError::Truncated) => return RarProof::Reject,
                        Err(error) => return RarProof::fallback(error),
                    };
                    for (ciphertext, output) in bytes.chunks_exact(16).zip(plain[len..next].chunks_exact_mut(16)) {
                        output.copy_from_slice(&decrypt_cbc_block(&cipher, &mut previous, ciphertext));
                    }
                    len = next;
                    match rar3_lz_tables(&plain[..len]) {
                        LevelTable::Impossible => return RarProof::Reject,
                        LevelTable::Complete => return weak,
                        LevelTable::Incomplete => {}
                    }
                }
                if self.split_after { RarProof::Weak(Some("RAR4 compressed table continues in the next volume")) }
                else { RarProof::Reject }
            }),
        }
    }

}

struct Rar4HeaderProbe {
    prefix: [u8; 24],
    offset: u64,
    source: RarTailSource,
}

impl Rar4HeaderProbe {
    fn verify(&self, key: [u8; 16], iv: [u8; 16], salt: &[u8; 8],
        password: &Arc<str>, keys: &RarKeyCache) -> io::Result<RarCheck> {
        let cipher = Aes128::new((&key).into());
        let Some(first) = Rar4EncryptedHeader::start(&cipher, iv, &self.prefix[8..]) else {
            return Ok(RarProof::Reject.into());
        };
        let Some(rest_offset) = self.offset.checked_add(24) else { return Ok(RarProof::Reject.into()); };
        self.source.verify(|read, _| {
            let header = match first.finish(&cipher, |size| read(rest_offset, size)) {
                Ok(Some(header)) => header,
                Ok(None) => return RarProof::Reject,
                Err(Rar4TailError::Read(DeferredReadError::Truncated)) => return RarProof::Reject,
                Err(Rar4TailError::Read(error)) => return RarProof::fallback(error),
                Err(Rar4TailError::Incomplete) => return RarProof::Weak(Some("RAR4 header is incomplete")),
            };
            if header[2] == 0x7b { return RarProof::Weak(None); } // ENDARC.
            let Some(offset) = crate::formats::rar::rar4_data_size(&header).and_then(|body|
                rest_offset.checked_add(first.remaining as u64)?.checked_add(body)) else { return RarProof::Weak(None); };
            let next = match read(offset, 24) {
                Ok(next) => next,
                Err(error) => return RarProof::fallback(error),
            };
            let next_salt = next[..8].try_into().unwrap();
            if next_salt == salt { return RarProof::Weak(None); }
            let Some((next_key, next_iv)) = keys.rar4(password, Some(next_salt)) else {
                return RarProof::Weak(None);
            };
            let next_cipher = Aes128::new((&next_key).into());
            let Some(next_header) = Rar4EncryptedHeader::start(&next_cipher, next_iv, &next[8..]) else {
                return RarProof::Weak(None);
            };
            let Some(next_rest) = offset.checked_add(24) else { return RarProof::Weak(None); };
            match next_header.finish(&next_cipher, |size| read(next_rest, size)) {
                Ok(Some(_)) => RarProof::Confirmed,
                Err(Rar4TailError::Read(error)) => RarProof::fallback(error),
                // Older archives can end without ENDARC. An unrecognized
                // optional successor cannot erase an independently checked CRC.
                _ => RarProof::Weak(None),
            }
        })
    }
}

impl Rar5BlockProbe {
    fn verify(&self, cipher: &Aes256, mut previous: [u8; 16]) -> io::Result<RarCheck> {
        let Some(encrypted) = self.encrypted else { return Ok(self.incomplete().into()); };
        let first = decrypt_cbc_block(cipher, &mut previous, &encrypted);
        let weak = RarProof::Weak(None);
        let Some(next) = rar5_block_end(&first) else { return Ok(RarProof::Reject.into()); };
        // A nonempty block needs its own tables at a non-solid entry start.
        // An empty block without a table is accepted by the native decoder.
        let header_len = rar5_block_header_size(first[0]).unwrap();
        let has_table = first[0] & 0x80 != 0;
        let last = first[0] & 0x40 != 0;
        let size = next - header_len;
        let table_bits = size.saturating_sub(1) * 8 + usize::from(first[0] & 7) + 1;
        let table = if !has_table { LevelTable::Complete }
            else if size == 0 { LevelTable::Impossible }
            else { rar_level_table(&first[header_len..], 0, table_bits) };
        if table == LevelTable::Impossible || (!self.solid && !has_table && size != 0) {
            return Ok(RarProof::Reject.into());
        }
        if table == LevelTable::Complete && last {
            return Ok(if next as u64 <= self.packed_size { weak } else { self.incomplete() }.into());
        }
        // Deferred reads may branch on a continuation. The headers wholly in
        // the selected first fragment are shared by every resulting branch.
        let mut common_successor = None;
        self.source.verify(|read, may_narrow_native| {
            let mut prefix = Rar5BlockWindow::default();
            if table == LevelTable::Incomplete {
                let edge = (header_len + table_bits.div_ceil(8).min(20)).next_multiple_of(16);
                let plain = match self.read_cbc_prefix(cipher, previous, &first, 0, edge, read, &mut prefix) {
                    Ok(plain) => plain,
                    Err(proof) => return proof,
                };
                if rar_level_table(&plain[header_len..], 0, table_bits) != LevelTable::Complete {
                    return RarProof::Reject;
                }
            }
            let (mut next, mut last) = common_successor.unwrap_or((next as u64, last));
            let mut checked_successor = common_successor.is_some();
            let mut checked_native_boundary = false;
            loop {
                if next > self.packed_size && !self.source.is_native() { return self.incomplete(); }
                if last { return weak; }
                let available = if self.source.is_native() { u64::MAX - next }
                    else { self.packed_size - next };
                if available < 3 { return self.incomplete(); }
                let cbc_start = (next & !15).saturating_sub(16).max(16);
                let crosses_fragment = next.checked_add(5).and_then(|end| end.checked_next_multiple_of(16))
                    .is_none_or(|end| end > self.packed_size);
                if checked_successor && !may_narrow_native.get()
                    && !(self.source.is_native() && crosses_fragment && !checked_native_boundary)
                    && self.offset.checked_add(cbc_start).is_none_or(|offset|
                        !self.source.range_is_ambiguous(offset, self.packed_size.saturating_sub(cbc_start))) {
                    return weak;
                }
                let count = if let Some(&flags) = usize::try_from(next).ok().and_then(|index| first.get(index)) {
                    let Some(width) = rar5_block_header_size(flags) else { return RarProof::Reject; };
                    if width as u64 > available { return self.incomplete(); }
                    width
                } else {
                    let left = 16 - (next & 15);
                    available.min(if left >= 3 { left.min(5) } else { 5 }) as usize
                };
                let header = match self.read_cbc_prefix(cipher, previous, &first, next, count, read, &mut prefix) {
                    Ok(header) => header,
                    Err(proof) => return proof,
                };
                let Some(width) = rar5_block_header_size(header[0]) else { return RarProof::Reject; };
                if width as u64 > available { return self.incomplete(); }
                let header = if width <= count { header } else {
                    match self.read_cbc_prefix(cipher, previous, &first, next, width, read, &mut prefix) {
                        Ok(header) => header,
                        Err(proof) => return proof,
                    }
                };
                let Some(end) = rar5_block_end(header) else { return RarProof::Reject; };
                let Some(offset) = next.checked_add(end as u64) else { return RarProof::Reject; };
                let flags = header[0];
                let mut proof_end = next + width as u64;
                if flags & 0x80 != 0 {
                    let size = end - width;
                    if size == 0 { return RarProof::Reject; }
                    let bits = (size - 1) * 8 + usize::from(flags & 7) + 1;
                    // Only inspect table bytes already decrypted for the
                    // header. A partial table can disprove, but not confirm.
                    let bytes = if proof_end >= prefix.start && proof_end < prefix.end {
                        &prefix.plain[(proof_end - prefix.start) as usize..(prefix.end - prefix.start) as usize]
                    } else {
                        &first[proof_end.min(16) as usize..]
                    };
                    let bytes = &bytes[..bytes.len().min(bits.div_ceil(8))];
                    if rar_level_table(bytes, 0, bits) == LevelTable::Impossible {
                        return RarProof::Reject;
                    }
                    proof_end += bytes.len() as u64;
                }
                let within_first = proof_end.checked_next_multiple_of(16)
                    .is_some_and(|end| end <= self.packed_size);
                next = offset;
                last = flags & 0x40 != 0;
                checked_successor = true;
                if self.source.is_native() {
                    if within_first { common_successor = Some((next, last)); }
                    else { checked_native_boundary = true; }
                }
            }
        })
    }

    fn incomplete(&self) -> RarProof {
        if self.split_after { RarProof::Weak(Some("RAR5 block continues in the next volume")) }
        else { RarProof::Reject }
    }

    // A CBC jump reads only the previous ciphertext plus the blocks that own
    // the requested structure. The initial block was already decrypted.
    fn read_cbc_prefix<'a>(&self, cipher: &Aes256, mut previous: [u8; 16], first: &'a [u8; 16],
        offset: u64, len: usize, read: &mut RarProbeRead<'_>, window: &'a mut Rar5BlockWindow,
    ) -> Result<&'a [u8], RarProof> {
        let end = offset.checked_add(len as u64).ok_or(RarProof::Reject)?;
        if end <= 16 { return Ok(&first[offset as usize..end as usize]); }
        let aligned_end = end.checked_next_multiple_of(16).ok_or(RarProof::Reject)?;
        if aligned_end > self.packed_size && !self.source.is_native() { return Err(self.incomplete()); }
        if offset < window.start || end > window.end {
            let start = offset & !15;
            let read_start = start.saturating_sub(16).max(16);
            let at = self.offset.checked_add(read_start).ok_or(RarProof::Reject)?;
            let bytes = match read(at, (aligned_end - read_start) as usize) {
                Ok(bytes) => bytes,
                Err(DeferredReadError::Truncated) => return Err(RarProof::Reject),
                Err(error) => return Err(RarProof::fallback(error)),
            };
            let decrypt_start = start.max(16);
            if start == 0 { window.plain[..16].copy_from_slice(first); }
            if read_start < decrypt_start { previous.copy_from_slice(&bytes[..16]); }
            for (i, chunk) in bytes[(decrypt_start - read_start) as usize..].chunks_exact(16).enumerate() {
                let dest = (decrypt_start - start) as usize + i * 16;
                window.plain[dest..dest + 16].copy_from_slice(&decrypt_cbc_block(cipher, &mut previous, chunk));
            }
            window.start = start;
            window.end = aligned_end;
        }
        Ok(&window.plain[(offset - window.start) as usize..(end - window.start) as usize])
    }
}

fn rar5_block_header_size(flags: u8) -> Option<usize> {
    let extra = (flags >> 3) & 3;
    (extra != 3).then_some(3 + extra as usize)
}

/// RAR5 compression blocks start on byte boundaries. Their length excludes
/// the header and may be zero, including for solid streams that reuse tables.
fn rar5_block_end(prefix: &[u8]) -> Option<usize> {
    let header = prefix.get(..rar5_block_header_size(*prefix.first()?)?)?;
    if header.iter().fold(0u8, |checksum, byte| checksum ^ byte) != 0x5a { return None; }
    let mut len = [0; 4];
    len[..header.len() - 2].copy_from_slice(&header[2..]);
    Some(header.len() + u32::from_le_bytes(len) as usize)
}

impl Rar5HeaderTail {
    fn verify(&self, prefix: &[u8; 32], key: &[u8; 32]) -> io::Result<RarCheck> {
        let cipher = Aes256::new(key.into());
        let mut previous = prefix[..16].try_into().unwrap();
        let first = decrypt_cbc_block(&cipher, &mut previous, &prefix[16..]);
        let reject = || Ok(RarProof::Reject.into());
        let Some(size) = rar5_header_len(&first).filter(|&size| size >= 7) else { return reject(); };
        let Some((_, body)) = read_vint(&first, 4) else { return reject(); };
        if read_vint(&first, body).is_none_or(|(kind, _)| kind != 1) { return reject(); }
        let expected = u32::from_le_bytes(first[..4].try_into().unwrap());
        let rest = size.next_multiple_of(16) - 16;
        let next = rar5_common_fields(&first[..size.min(16)], body).and_then(|fields|
            self.offset.checked_add(rest as u64)?.checked_add(fields.data_size))
            .filter(|&offset| self.source.range_is_ambiguous(offset, 32));
        if rest == 0 && next.is_none() {
            return if crc32(&first[4..size]) == expected {
                Ok(RarProof::Confirmed.into())
            } else { reject() };
        }
        self.source.verify(|read, _| {
            let mut previous = previous;
            let mut digest = crc32fast::Hasher::new();
            digest.update(&first[4..size.min(16)]);
            let mut done = 0;
            while done < rest {
                let count = (rest - done).min(64 * 1024);
                let Some(offset) = self.offset.checked_add(done as u64) else { return RarProof::Reject; };
                let mut chunk = match read(offset, count) {
                    Ok(chunk) => chunk,
                    Err(DeferredReadError::Truncated) => return RarProof::Reject,
                    Err(error) => return RarProof::fallback(error),
                };
                decrypt_cbc_blocks(&cipher, &mut previous, &mut chunk);
                digest.update(&chunk[..count.min(size - 16 - done)]);
                done += count;
            }
            if digest.finalize() != expected { return RarProof::Reject; }
            let Some(next) = next else { return RarProof::Confirmed; };
            // Keep the main-header proof if the next record cannot establish
            // anything. A valid later header can distinguish sibling sources
            // whose ciphertext already passed the same main-header proof.
            let plausible_successor = |prefix: &[u8]| {
                read_vint(prefix, 4).and_then(|(_, at)| read_vint(prefix, at))
                    .is_none_or(|(kind, at)| matches!(kind, 2 | 3 | 5)
                        || (!matches!(kind, 1 | 4) && read_vint(prefix, at).is_none_or(|(flags, _)| flags & 4 != 0)))
            };
            match read_rar5_encrypted_header(next, &cipher, read, plausible_successor) {
                Ok(Some((header, _))) => RarProof::Successor(
                    read_vint(&header, 4).and_then(|(_, at)| rar5_common_fields(&header, at))
                        .is_some_and(|fields| (matches!(fields.kind, 2 | 3 | 5) || fields.flags & 4 != 0)
                            && crc32(&header[4..]) == le_u32(&header, 0).unwrap())
                ),
                Ok(None) => RarProof::Successor(false),
                Err(_) => RarProof::Confirmed,
            }
        })
    }
}

type SharedRarKey<T> = Arc<std::sync::OnceLock<Option<T>>>;
type Rar5KeyParameters = (u8, [u8; 16]);
type Rar5PasswordSlots = std::sync::Mutex<std::collections::HashMap<Arc<str>, SharedRarKey<Rar5KeyCheckpoint>>>;
#[derive(Default)]
pub(crate) struct RarKeyCache {
    direct: bool,
    rar4: std::sync::Mutex<std::collections::HashMap<(Option<[u8; 8]>, Arc<str>), SharedRarKey<([u8; 16], [u8; 16])>>>,
    rar5: std::collections::HashMap<Rar5KeyParameters, Rar5PasswordSlots>,
    #[cfg(test)]
    rar5_derivations: std::sync::atomic::AtomicUsize,
}
impl RarKeyCache {
    pub(super) fn for_contexts<'a>(contexts: impl Iterator<Item = &'a RarPasswordContext>) -> Self {
        let mut keys = Self::default();
        super::evidence::for_repeated_parameters(contexts.filter_map(|context| match &context.material {
            RarPasswordMaterial::Rar5(identity) | RarPasswordMaterial::Rar5Header { identity, .. }
            | RarPasswordMaterial::Rar5Block { identity, .. } | RarPasswordMaterial::Rar5EmptyMac { identity, .. } =>
                Some((identity.lg2_count, identity.salt)),
            _ => None,
        }), |parameters| { keys.rar5.entry(parameters).or_default(); });
        keys
    }

    fn rar4(&self, password: &Arc<str>, salt: Option<&[u8; 8]>) -> Option<([u8; 16], [u8; 16])> {
        if self.direct { return derive_rar3_key_iv(password, salt); }
        let slot = self.rar4.lock().unwrap().entry((salt.copied(), Arc::clone(password))).or_default().clone();
        *slot.get_or_init(|| derive_rar3_key_iv(password, salt))
    }
    fn rar5(&self, password: &Arc<str>, identity: &Rar5EncryptionIdentity) -> Option<[u8; 32]> {
        self.with_rar5_key(password, identity, |checkpoint| checkpoint.verify(password, identity.password_check))
    }
    fn rar5_hash_key(&self, password: &Arc<str>, identity: &Rar5EncryptionIdentity) -> Option<[u8; 32]> {
        self.with_rar5_key(password, identity, |checkpoint| Some(checkpoint.hash_key(password)))
    }
    fn with_rar5_key<T>(
        &self,
        password: &Arc<str>,
        identity: &Rar5EncryptionIdentity,
        use_key: impl FnOnce(&Rar5KeyCheckpoint) -> Option<T>,
    ) -> Option<T> {
        let derive = || {
            #[cfg(test)]
            self.rar5_derivations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            derive_rar5_key(password, identity)
        };
        if let Some(slots) = self.rar5.get(&(identity.lg2_count, identity.salt)) {
            // Each identity has its own lock, and only competing probes for
            // that salt ever populate or retain candidate checkpoints.
            let slot = slots.lock().unwrap().entry(Arc::clone(password)).or_default().clone();
            use_key(slot.get_or_init(derive).as_ref()?)
        } else {
            use_key(&derive()?)
        }
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
                let result = verify_rar_structural_candidates(candidates, "rar5_header_prefix", "rar5_header_crc32", |index, password| {
                    let Some(key) = keys.rar5(password, identity) else {
                        return Ok(RarProof::Weak(None).into());
                    };
                    let checked = tail.verify(prefix, &key)?;
                    if checked.proof == RarProof::Confirmed && keep_key {
                        let mut slot = first_key.lock().unwrap();
                        if slot.as_ref().is_none_or(|&(earlier, _)| index < earlier) {
                            *slot = Some((index, key));
                        }
                    }
                    Ok(checked)
                })?;
                if let (Some(proof), Some((index, key))) = (proven_key, first_key.into_inner().unwrap()) {
                    if result.matched_index == Some(index) {
                        *proof = Some(RarProvenKey::Rar5 { header: *identity, key });
                    }
                }
                Ok(result)
            }
            RarPasswordMaterial::Rar5Block { identity, block } => {
                if block.encrypted.is_none() {
                    return Ok(PasswordVerification::status("unknown_needs_final_verifier",
                        "RAR5 first encrypted block continues in the next volume"));
                }
                verify_rar_structural_candidates(candidates, "rar5_compressed_block", "rar5_compressed_block", |_, password| {
                    let Some(key) = keys.rar5(password, identity) else {
                        return Ok(RarProof::Weak(None).into());
                    };
                    block.verify(&Aes256::new((&key).into()), identity.iv)
                })
            }
            RarPasswordMaterial::Rar5EmptyMac { identity, mac } => {
                verify_rar_structural_candidates(candidates, "rar5_empty_member_mac", "rar5_empty_member_mac", |_, password| {
                    let Some(key) = keys.rar5_hash_key(password, identity) else {
                        return Ok(RarProof::Weak(None).into());
                    };
                    Ok(mac.verify(&key).into())
                })
            }
            RarPasswordMaterial::Rar4Block(block) => {
                if block.encrypted.is_none() {
                    return Ok(PasswordVerification::status("unknown_needs_final_verifier",
                        "RAR4 first encrypted block continues in the next volume"));
                }
                verify_rar_structural_candidates(candidates, "rar4_compressed_stream", "rar4_compressed_stream", |_, password|
                    block.verify(password, keys))
            }
            RarPasswordMaterial::Header(probe) => {
                let salt: &[u8; 8] = probe.prefix[..8].try_into().unwrap();
                let first_key = std::sync::Mutex::new(None::<(bool, usize, [u8; 16], [u8; 16])>);
                let keep_key = proven_key.is_some();
                let result = verify_rar_structural_candidates(candidates, "rar4_hp_header_crc16", "rar4_hp_two_header_crc16", |index, password| {
                    let Some((key, iv)) = keys.rar4(password, Some(salt)) else { return Ok(RarProof::Weak(None).into()); };
                    let checked = probe.verify(key, iv, salt, password, keys)?;
                    let confirmed = checked.proof == RarProof::Confirmed;
                    if keep_key && checked.proof != RarProof::Reject {
                        let mut slot = first_key.lock().unwrap();
                        if slot.as_ref().is_none_or(|&(strong, earlier, _, _)| (confirmed && !strong) || (confirmed == strong && index < earlier)) {
                            *slot = Some((confirmed, index, key, iv));
                        }
                    }
                    Ok(checked)
                })?;
                if let (Some(proof), Some((_, index, key, iv))) = (proven_key, first_key.into_inner().unwrap()) {
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
    candidates: &[Arc<str>], weak_evidence: &'static str, strong_evidence: &'static str,
    check: impl Fn(usize, &Arc<str>) -> io::Result<RarCheck> + Sync,
) -> io::Result<PasswordVerification> {
    let cancel = Cancellation::current();
    use std::sync::atomic::{AtomicUsize, Ordering};
    let earliest = AtomicUsize::new(candidates.len());
    let checked = |(index, password)| {
        if index > earliest.load(Ordering::Relaxed) || cancel.cancelled() { return None; }
        match cancel.run(|| check(index, password)) {
            Ok(checked) if checked.proof == RarProof::Reject => None,
            Ok(checked) => {
                if checked.proof == RarProof::Confirmed && checked.rejected.is_empty() {
                    earliest.fetch_min(index, Ordering::Relaxed);
                }
                Some(Ok((index, checked)))
            }
            Err(error) => Some(Err(error)),
        }
    };
    let mut survivors: Vec<_> = if candidates.len() >= PARALLEL_PASSWORD_THRESHOLD {
        candidates.par_iter().enumerate().filter_map(checked).collect::<io::Result<_>>()?
    } else {
        candidates.iter().enumerate().filter_map(checked).collect::<io::Result<_>>()?
    };
    cancel.check_io()?;
    let hit = earliest.into_inner();
    if hit < candidates.len() {
        survivors.retain(|(index, _)| *index == hit);
    } else if let Some((first, _)) = survivors.first() {
        if survivors.iter().all(|(index, checked)| {
            checked.proof == RarProof::Confirmed && candidates[*index] == candidates[*first]
        }) {
            survivors.truncate(1);
        }
    }
    let confirmed = matches!(survivors.as_slice(), [(_, checked)] if checked.proof == RarProof::Confirmed);
    let reason = survivors.iter().find_map(|(_, check)| match check.proof {
        RarProof::Weak(reason) => reason,
        _ => None,
    });
    let mut indices = Vec::with_capacity(survivors.len());
    let mut scoped_rejections = super::evidence::ScopedRejections::default();
    for (index, checked) in survivors {
        indices.push(index);
        scoped_rejections.extend(checked.rejected.into_iter().map(|projection| (projection, index)));
    }
    let first = indices.first().copied();
    Ok(PasswordVerification {
        matched_index: first, matched_indices: indices,
        attempts: if hit < candidates.len() { hit + 1 } else { candidates.len() },
        final_confirmation_required: Some(!confirmed),
        match_evidence: Some(if confirmed { strong_evidence } else { weak_evidence }),
        scoped_rejections,
        ..PasswordVerification::status(if first.is_some() { "match" } else { "no_match" },
            reason.unwrap_or("RAR structural password evidence"))
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
    if !rar4_header_crc_matches(&data[offset..header_end]) {
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

fn rar4_header_crc_matches(header: &[u8]) -> bool {
    let stored = u16::from_le_bytes([header[0], header[1]]);
    let matches_crc = |end| header.get(2..end).is_some_and(|data| crc32(data) as u16 == stored);
    if matches_crc(header.len()) { return true; }
    // Older blocks can keep their comment outside the CRC. Main headers
    // cover only their fixed fields; file headers cover the name, optional
    // high sizes, salt and extended times in the native reader's order.
    let end = match header[2] {
        0x73 => Some(13),
        0x74 => rar4_file_header_crc_end(header),
        _ => None,
    };
    end.is_some_and(|end| end != header.len() && matches_crc(end))
}

fn rar4_file_header_crc_end(header: &[u8]) -> Option<usize> {
    let flags = u16::from_le_bytes(header[3..5].try_into().unwrap());
    let name_size = usize::from(u16::from_le_bytes(header.get(26..28)?.try_into().unwrap()));
    let mut end = 32 + name_size + usize::from(flags & 0x100 != 0) * 8 + usize::from(flags & 0x400 != 0) * 8;
    if flags & 0x1000 != 0 {
        if let Some(times) = header.get(end..end + 2) {
            end += 2;
            let masks = [times[1] >> 4, times[1] & 15, times[0] >> 4];
            for (index, mask) in masks.into_iter().enumerate() {
                if mask & 8 != 0 {
                    end += usize::from(mask & 3) + usize::from(index != 0) * 4;
                }
            }
        }
    }
    Some(end)
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

// Outer None means this header cannot provide a complete password proof.
fn decrypt_rar4_header(encrypted: &[u8], key: [u8; 16], iv: [u8; 16]) -> Option<Option<Vec<u8>>> {
    decrypt_rar4_header_with(encrypted.get(..16)?, key, iv, |remaining| Some(encrypted.get(16..16 + remaining)?.to_vec()))
}

fn decrypt_rar4_header_with(first: &[u8], key: [u8; 16], iv: [u8; 16],
    read: impl FnOnce(usize) -> Option<Vec<u8>>) -> Option<Option<Vec<u8>>> {
    let cipher = Aes128::new((&key).into());
    let Some(header) = Rar4EncryptedHeader::start(&cipher, iv, first) else { return Some(None); };
    header.finish(&cipher, |size| read(size).ok_or(())).ok()
}

struct Rar4EncryptedHeader {
    plain: [u8; 16],
    previous: [u8; 16],
    size: usize,
    remaining: usize,
}

enum Rar4TailError<E> {
    Read(E),
    Incomplete,
}

impl Rar4EncryptedHeader {
    fn start(cipher: &Aes128, mut previous: [u8; 16], first: &[u8]) -> Option<Self> {
        let plain = decrypt_cbc_block(cipher, &mut previous, first);
        let size = u16::from_le_bytes([plain[5], plain[6]]) as usize;
        if size < RAR4_MIN_HEADER_SIZE || !RAR4_HEADER_TYPES.contains(&plain[2]) {
            return None;
        }
        Some(Self { plain, previous, size, remaining: size.next_multiple_of(16) - 16 })
    }

    fn finish<E>(&self, cipher: &Aes128, read: impl FnOnce(usize) -> Result<Vec<u8>, E>)
        -> Result<Option<Vec<u8>>, Rar4TailError<E>> {
        let plain = &self.plain;
        let size = self.size;
        let mut rest = if self.remaining == 0 { Vec::new() } else { read(self.remaining).map_err(Rar4TailError::Read)? };
        if rest.len() != self.remaining { return Err(Rar4TailError::Incomplete); }
        let mut previous = self.previous;
        decrypt_cbc_blocks(cipher, &mut previous, &mut rest);
        rest.truncate(size.saturating_sub(16));
        let mut full = Vec::with_capacity(size);
        full.extend_from_slice(&plain[..size.min(16)]);
        full.extend_from_slice(&rest);
        Ok(rar4_header_crc_matches(&full).then_some(full))
    }
}

fn read_rar4_encrypted_header(offset: u64, mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    key: impl FnOnce(&[u8; 8]) -> Option<([u8; 16], [u8; 16])>) -> io::Result<Option<Vec<u8>>> {
    let prefix = read(offset, 24)?;
    if prefix.len() != 24 { return Ok(None); }
    let salt = prefix[..8].try_into().unwrap();
    let Some((key, iv)) = key(salt) else { return Ok(None); };
    let remaining_offset = offset.checked_add(24).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RAR4 offset overflow"))?;
    let mut result = Ok(());
    let header = decrypt_rar4_header_with(&prefix[8..], key, iv, |remaining| match read(remaining_offset, remaining) {
        Ok(bytes) => Some(bytes),
        Err(error) => { result = Err(error); None }
    }).flatten();
    result?;
    Ok(header)
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
    name: &'a [u8], compression: u64, crc: Option<u32>, empty_stored: bool, directory: bool,
}
fn rar5_file_fields(data: &[u8], mut offset: usize, header_end: usize) -> Option<Rar5FileFields<'_>> {
    let (file_flags, next) = read_vint_bounded(data, offset, header_end)?;
    offset = next;
    let (size, next) = read_vint_bounded(data, offset, header_end)?;
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
    Some(Rar5FileFields { name, compression, crc,
        empty_stored: file_flags & 9 == 0 && size == 0 && compression >> 7 & 7 == 0,
        directory: file_flags & 1 != 0,
    })

}

#[derive(Default)]
struct Rar5FileExtras<'a> {
    encryption: Option<&'a [u8]>,
    blake2sp: Option<[u8; 32]>,
    keyed_hash: bool,
    redirected: bool,
}

fn rar5_file_extras(data: &[u8], extra_area_size: u64, collect_hash: bool) -> Rar5FileExtras<'_> {
    let extra_end = data.len();
    let mut result = Rar5FileExtras::default();
    let Some(mut offset) = usize::try_from(extra_area_size).ok().and_then(|size| extra_end.checked_sub(size)) else { return result; };
    while offset < extra_end {
        let Some((record_size, record_body)) = read_vint_bounded(data, offset, extra_end) else { break; };
        let Some(record_end) = usize::try_from(record_size).ok().and_then(|size| record_body.checked_add(size)) else { break; };
        if record_end > extra_end { break; }
        let Some((record_type, body)) = read_vint_bounded(data, record_body, record_end) else { break; };
        let record = &data[body..record_end];
        match record_type {
            1 if result.encryption.is_none() => {
                result.encryption = Some(record);
                if !collect_hash { break; }
                // Official UnRAR honors the hash-key flag during volume
                // transitions. An unusual flagged non-final fragment must
                // not be rejected solely by a raw digest mismatch.
                result.keyed_hash = read_vint(record, 0)
                    .and_then(|(version, next)| (version == 0).then(|| read_vint(record, next)).flatten())
                    .is_none_or(|(flags, _)| flags & 2 != 0);
            }
            2 if collect_hash && result.blake2sp.is_none() && record.first() == Some(&0) => {
                result.blake2sp = record[1..].try_into().ok();
            }
            5 => result.redirected = true,
            _ => {}
        }
        offset = record_end;
    }
    result
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
    Some(Rar5EncryptionIdentity { lg2_count, salt, password_check, iv })
}

struct Rar5KeyCheckpoint {
    key: [u8; 32],
    block: [u8; 32],
    check: std::sync::OnceLock<[u8; 8]>,
}

impl Rar5KeyCheckpoint {
    fn hash_key(&self, password: &str) -> [u8; 32] {
        let mut block = self.block;
        let mut digest = self.key;
        super::pbkdf::sha256(password.as_bytes()).extend(&mut block, &mut digest, 16, || true);
        digest
    }

    fn verify(&self, password: &str, expected: Option<[u8; 8]>) -> Option<[u8; 32]> {
        let Some(expected) = expected else { return Some(self.key); };
        let check = self.check.get_or_init(|| {
            let mut block = self.block;
            let mut digest = self.key;
            super::pbkdf::sha256(password.as_bytes()).extend(&mut block, &mut digest, 32, || true);
            let mut check = [0; 8];
            for (i, byte) in digest.into_iter().enumerate() { check[i % 8] ^= byte; }
            check
        });
        (*check == expected).then_some(self.key)
    }
}

fn derive_rar5_key(password: &str, header: &Rar5EncryptionIdentity) -> Option<Rar5KeyCheckpoint> {
    let cancellation = Cancellation::current();
    let iterations = 1u32.checked_shl(header.lg2_count as u32)?;
    let template = super::pbkdf::sha256(password.as_bytes());
    let mut block = template.start(&header.salt, 1);
    let mut key = block;
    if !template.extend(&mut block, &mut key, iterations - 1, || !cancellation.cancelled()) {
        return None;
    }
    Some(Rar5KeyCheckpoint { key, block, check: Default::default() })
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
            read_rar5_encrypted_header(block_offset, cipher, |offset, size| reader.read_at(offset, size), |_| true)?
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

fn read_rar5_encrypted_header<E>(
    block_offset: u64,
    cipher: &Aes256,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, E>,
    accept_prefix: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<(Vec<u8>, u64)>, E> {
    let Some(rest_offset) = block_offset.checked_add(32) else { return Ok(None); };
    let mut header = read(block_offset, 32)?;
    if header.len() != 32 { return Ok(None); }
    let mut previous = header[..16].try_into().unwrap();
    let first_plaintext = decrypt_cbc_block(cipher, &mut previous, &header[16..]);
    let Some(total_size) = rar5_header_len(&first_plaintext).filter(|size| *size >= 7) else {
        return Ok(None);
    };
    if !accept_prefix(&first_plaintext[..total_size.min(16)]) { return Ok(None); }
    let rest_size = total_size.next_multiple_of(16) - 16;
    let Some(end) = rest_offset.checked_add(rest_size as u64) else { return Ok(None); };
    header.truncate(16);
    header.copy_from_slice(&first_plaintext);
    if rest_size != 0 {
        let mut rest = read(rest_offset, rest_size)?;
        if rest.len() != rest_size { return Ok(None); }
        decrypt_cbc_blocks(cipher, &mut previous, &mut rest);
        rest.truncate(total_size - 16);
        header.append(&mut rest);
    }
    header.truncate(total_size);
    Ok(Some((header, end)))
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
            let Some(header) = read_rar4_encrypted_header(block_offset, |at, size| reader.read_at(at, size),
                |salt| derive_rar3_key_iv(password, Some(salt)))? else {
                Cancellation::check_current_io()?;
                return Ok(incomplete(password_matched));
            };
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
