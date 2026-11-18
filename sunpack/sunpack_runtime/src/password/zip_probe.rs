use super::{le_u16, PasswordVerification, ZipCryptoState, ZipVolumeReader};
use crate::formats::deflate_prefix;
use crate::formats::seven_zip::{seven_zip_prefix_check, seven_zip_successor_prefix, SevenZipPrefixCheck};
use crate::formats::zip::zip64::CentralValues;
use crate::io::cancellation::Cancellation;
use crate::password::evidence::VolumeProjection;
use crate::password::input::attempts::{DeferredReadError, DeferredReads};
use crate::password::input::{RangeSpec, VirtualRangeReader, VolumeSet};
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use std::io;
use std::sync::Arc;

const MAX_IMPLODE_TABLES: usize = (1 + 256) + 2 * (1 + 64);
const ZSTD_METHOD: &[u8] = &[0x04, 0xf7, 0x11, 0x01];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ZipLocation {
    pub(super) disk: Option<usize>,
    pub(super) offset: u64,
}

#[derive(Clone)]
pub(super) enum ZipReadInput {
    Ranges(Arc<[RangeSpec]>),
    Volumes(Arc<VolumeSet>),
    Projected(Arc<DeferredReads>),
}

impl PartialEq for ZipReadInput {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ranges(a), Self::Ranges(b)) => Arc::ptr_eq(a, b),
            (Self::Volumes(a), Self::Volumes(b)) => Arc::ptr_eq(a, b),
            (Self::Projected(a), Self::Projected(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
impl Eq for ZipReadInput {}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ZipRead {
    pub(super) input: ZipReadInput,
    pub(super) location: ZipLocation,
}

pub(super) type CheckRead<'a> = dyn FnMut(u64, usize) -> Result<Vec<u8>, DeferredReadError> + 'a;
pub(super) type Checked<T> = Vec<(Option<Arc<VolumeProjection>>, T)>;

pub(super) fn read_reason(error: &DeferredReadError) -> String {
    match error {
        DeferredReadError::Missing => "required bytes are unavailable".into(),
        DeferredReadError::Pending => "required bytes depend on a volume choice".into(),
        DeferredReadError::Truncated => "required bytes are truncated".into(),
        DeferredReadError::Cancelled => "read cancelled".into(),
        DeferredReadError::Io(error) => format!("required bytes could not be read ({error})"),
    }
}

impl ZipRead {
    pub(super) fn ambiguous(&self, relative: u64, len: u64) -> bool {
        match (&self.input, self.location.disk) {
            (ZipReadInput::Projected(read), None) =>
                read.range_is_ambiguous(self.location.offset.saturating_add(relative), len),
            (ZipReadInput::Projected(read), Some(disk)) =>
                read.disk_range_is_ambiguous(disk, self.location.offset.saturating_add(relative), len),
            _ => false,
        }
    }

    pub(super) fn evaluate<T>(
        &self,
        mut verify: impl FnMut(&mut CheckRead<'_>) -> T,
    ) -> io::Result<Checked<T>> {
        let ZipLocation { disk, offset } = self.location;
        let read_error = |error: io::Error| match error.kind() {
            io::ErrorKind::UnexpectedEof => DeferredReadError::Truncated,
            _ if Cancellation::current().cancelled() => DeferredReadError::Cancelled,
            _ => DeferredReadError::Io(error),
        };
        let check = |bytes: Vec<u8>, size| {
            if bytes.len() == size { Ok(bytes) } else { Err(DeferredReadError::Missing) }
        };
        let result = match &self.input {
            ZipReadInput::Projected(input) => input.evaluate(|reader| verify(&mut |relative, size| {
                if let Some(disk) = disk {
                    reader.read_disk_offset(disk, offset, relative, size)
                } else {
                    reader.read(offset.checked_add(relative).ok_or(DeferredReadError::Truncated)?, size)
                }
            }))?.into_iter().map(|(scope, evidence)| (Some(scope), evidence)).collect(),
            ZipReadInput::Ranges(ranges) => {
                let mut reader = VirtualRangeReader::streaming(ranges);
                let result = verify(&mut |relative, size| {
                    let at = offset.checked_add(relative).ok_or(DeferredReadError::Truncated)?;
                    check(reader.read_at(at, size).map_err(read_error)?, size)
                });
                vec![(None, result)]
            }
            ZipReadInput::Volumes(volumes) => {
                let result = verify(&mut |relative, size| {
                    let (disk, base, amount) = match disk {
                        Some(disk) => (disk, offset, relative),
                        None => (0, 0, offset.checked_add(relative).ok_or(DeferredReadError::Truncated)?),
                    };
                    let (disk, at) = volumes.advance_disk_offset(disk, base, amount)
                        .ok_or(DeferredReadError::Missing)?;
                    let ordinal = volumes.ordinal(disk)
                        .ok_or(DeferredReadError::Missing)?;
                    check(volumes.read_disk_spanning(ordinal, at, size).map_err(read_error)?, size)
                });
                vec![(None, result)]
            }
        };
        Cancellation::check_current_io()?;
        Ok(result)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZipPrefix {
    method: u16,
    flags: u16,
    start: u64,
    overhead: u64,
    sizes: Option<(u64, u64)>,
    read: Option<ZipRead>,
}

#[derive(Clone, Copy)]
pub(super) enum ZipPrefixKey {
    ZipCrypto(ZipCryptoState),
    Aes { key: [u8; 32], len: usize },
}

impl ZipPrefix {
    pub(super) fn new(method: u16, flags: u16, start: u64, overhead: u64, sizes: Option<&CentralValues>) -> Option<Self> {
        matches!(method, 1 | 6 | 8 | 9 | 12 | 14 | 93 | 95 | 98 | 99).then(|| Self {
            method, flags, start, overhead, sizes: None, read: None,
        }.with_sizes(sizes))
    }

    pub(super) fn with_sizes(mut self, sizes: Option<&CentralValues>) -> Self {
        if let Some(sizes) = sizes {
            self.sizes = sizes.compressed.checked_sub(self.overhead)
                .map(|packed| (packed, sizes.uncompressed));
        }
        self
    }

    pub(super) fn bind(&mut self, read: ZipRead) {
        self.read = Some(read);
    }

    pub(super) fn can_screen(&self, matches: usize, derive_aes_key: bool) -> bool {
        let Some(read) = &self.read else { return false; };
        let size = self.read_size();
        let span = if derive_aes_key && self.method == 93 {
            self.sizes.map_or(size as u64, |(packed, _)| packed)
        } else { size as u64 };
        matches != 0 && size != 0
            && (!derive_aes_key || matches > 1 || read.ambiguous(self.start, span))
    }

    pub(super) fn needs_size(&self) -> bool {
        self.sizes.is_none()
    }

    fn prefix_size(&self) -> usize {
        match self.method {
            1 => 2,
            6 => MAX_IMPLODE_TABLES,
            8 | 9 => deflate_prefix::MAX_DYNAMIC_HEADER_SIZE,
            12 => 10,
            14 => 14,
            93 => 24,
            95 | 99 => 12,
            98 => 6,
            _ => unreachable!(),
        }
    }

    fn minimum_prefix(&self) -> usize {
        match self.method {
            6 | 8 | 9 => 1,
            12 | 93 | 99 => 4,
            14 => 5,
            95 => 6,
            1 | 98 => 2,
            _ => unreachable!(),
        }
    }

    fn read_size(&self) -> usize {
        match self.sizes {
            // An empty Shrink stream has no initial code. With an unknown
            // size those bytes could belong to the following descriptor.
            None if self.method == 1 => 0,
            None => self.prefix_size(),
            Some((packed, _)) => packed.min(self.prefix_size() as u64) as usize,
        }
    }

    pub(super) fn screen(
        &self, keys: &[(usize, ZipPrefixKey)], result: &mut PasswordVerification,
    ) -> io::Result<()> {
        let Some(source) = &self.read else { return Ok(()); };
        let size = self.read_size();
        let zstd_sizes = if self.method == 93 && matches!(keys.first(), Some((_, ZipPrefixKey::Aes { .. }))) {
            self.sizes
        } else { None };
        let zstd_volumes = zstd_sizes.is_some_and(|(packed, _)| source.ambiguous(self.start, packed));
        let initial = size.min(16);
        let minimum = self.minimum_prefix().min(size);
        let first = if zstd_volumes {
            // A skippable frame needs only its 8-byte header before jumping.
            size.min(8)
        } else if initial > minimum && source.ambiguous(self.start, initial as u64) {
            minimum
        } else {
            initial
        };
        let checks = source.evaluate(|read| {
            let mut unavailable = None;
            let mut encrypted = match read(self.start, first) {
                Ok(bytes) => bytes,
                Err(error) => {
                    unavailable = Some(error);
                    if minimum == first { return (vec![None; keys.len()], unavailable); }
                    match read(self.start, minimum) {
                        Ok(bytes) => bytes,
                        Err(error) => return (vec![None; keys.len()], Some(error)),
                    }
                }
            };
            let mut verdicts = if zstd_volumes && unavailable.is_none() { vec![None; keys.len()] }
                else { keys.iter().map(|(_, key)| self.check(key, &encrypted)).collect() };
            while !zstd_volumes && unavailable.is_none() && encrypted.len() < size
                && verdicts.iter().any(Option::is_none) {
                let previous = encrypted.len();
                let next = (2 * previous).max(5).min(size);
                let more = match read(self.start + previous as u64, next - previous) {
                    Ok(bytes) => bytes,
                    Err(error) => { unavailable = Some(error); break; }
                };
                encrypted.extend_from_slice(&more);
                for ((_, key), verdict) in keys.iter().zip(&mut verdicts) {
                    if verdict.is_none() {
                        *verdict = self.check(key, &encrypted);
                    }
                }
            }
            if let Some(sizes) = zstd_sizes.filter(|_| unavailable.is_none() && (
                zstd_volumes || verdicts.iter().filter(|&&v| v != Some(false)).nth(1).is_some()
            )) {
                for ((_, key), verdict) in keys.iter().zip(&mut verdicts) {
                    if *verdict == Some(false) { continue; }
                    let outcome = self.check_aes_zstd_successors(key, &encrypted, sizes, source, read);
                    *verdict = match outcome {
                        Ok(SevenZipPrefixCheck::Reject) => Some(false),
                        Ok(SevenZipPrefixCheck::Weak) => None,
                        Ok(_) => Some(true),
                        Err(DeferredReadError::Truncated) if zstd_volumes => Some(false),
                        Err(error) => {
                            if matches!(error, DeferredReadError::Pending) { break; }
                            unavailable.get_or_insert(error);
                            None
                        }
                    };
                }
            }
            (verdicts, unavailable)
        })?;
        let contradicts = |scope: &Option<Arc<VolumeProjection>>, verdict: Option<bool>, error: Option<&DeferredReadError>| {
            verdict == Some(false) || (verdict.is_none() && scope.is_some() && self.sizes.is_some()
                && matches!(error, Some(DeferredReadError::Truncated)))
        };
        result.matched_indices.clear();
        for (position, &(index, _)) in keys.iter().enumerate() {
            if checks.is_empty() || checks.iter().any(|(scope, (verdicts, error))|
                !contradicts(scope, verdicts[position], error.as_ref())) {
                result.matched_indices.push(index);
                for (scope, (verdicts, error)) in &checks {
                    if contradicts(scope, verdicts[position], error.as_ref()) {
                        if let Some(scope) = scope { result.scoped_rejections.push((scope.clone(), index)); }
                    }
                }
            }
        }
        result.matched_index = result.matched_indices.first().copied();
        if result.matched_index.is_none() {
            result.status = "no_match";
            result.message = "ZIP password candidates contradict the member compression header".into();
            result.match_evidence = None;
        } else if let Some((_, error)) = checks.iter().map(|(_, observation)| observation)
            .find(|(verdicts, _)| verdicts.iter().any(Option::is_none))
        {
            let reason = error.as_ref().map(read_reason)
                .unwrap_or_else(|| "partial compression header is inconclusive".into());
            result.message = format!("ZIP password material matched; {reason}");
        }
        Ok(())
    }

    fn check(&self, key: &ZipPrefixKey, encrypted: &[u8]) -> Option<bool> {
        let mut plain = [0; MAX_IMPLODE_TABLES];
        let plain = &mut plain[..encrypted.len()];
        plain.copy_from_slice(encrypted);
        match *key {
            ZipPrefixKey::ZipCrypto(mut state) => {
                for byte in plain.iter_mut() {
                    *byte = state.decrypt(*byte);
                }
            }
            ZipPrefixKey::Aes { key, len: 16 } => winzip_aes_prefix::<Aes128>(&key[..16], plain),
            ZipPrefixKey::Aes { key, len: 24 } => winzip_aes_prefix::<Aes192>(&key[..24], plain),
            ZipPrefixKey::Aes { key, len: 32 } => winzip_aes_prefix::<Aes256>(&key, plain),
            ZipPrefixKey::Aes { .. } => unreachable!(),
        }
        self.check_plain(plain)
    }

    fn check_aes_zstd_successors(
        &self, key: &ZipPrefixKey, encrypted: &[u8], (packed, unpacked): (u64, u64),
        source: &ZipRead, read: &mut CheckRead<'_>,
    ) -> Result<SevenZipPrefixCheck, DeferredReadError> {
        fn verify<C: KeyInit + BlockCipherEncrypt>(
            prefix: &ZipPrefix, key: &[u8], encrypted: &[u8], packed: u64, unpacked: u64,
            source: &ZipRead, read: &mut CheckRead<'_>,
        ) -> Result<SevenZipPrefixCheck, DeferredReadError> {
            let cipher = C::new_from_slice(key).unwrap();
            let mut plain = [0; 24];
            let plain = &mut plain[..encrypted.len()];
            plain.copy_from_slice(encrypted);
            winzip_aes_ctr(&cipher, 0, plain);
            seven_zip_successor_prefix(ZSTD_METHOD, plain, packed, unpacked, |offset, output| {
                output.copy_from_slice(&read(prefix.start + offset, output.len())?);
                winzip_aes_ctr(&cipher, offset, output);
                Ok(())
            }, |offset| source.ambiguous(prefix.start + offset, packed - offset))
        }
        match key {
            ZipPrefixKey::Aes { key, len: 16 } => verify::<Aes128>(self, &key[..16], encrypted, packed, unpacked, source, read),
            ZipPrefixKey::Aes { key, len: 24 } => verify::<Aes192>(self, &key[..24], encrypted, packed, unpacked, source, read),
            ZipPrefixKey::Aes { key, len: 32 } => verify::<Aes256>(self, key, encrypted, packed, unpacked, source, read),
            _ => unreachable!(),
        }
    }

    pub(super) fn cbc_first_block_offset(&self) -> Option<u64> {
        // The encrypted length includes PKCS7 padding. It is a safe upper
        // bound for compression framing, but cannot be used as an exact size.
        self.sizes
            .is_some_and(|(packed, _)| packed >= 16)
            .then_some(self.start)
    }

    pub(super) fn check_plain(&self, plain: &[u8]) -> Option<bool> {
        let (packed, unpacked) = self.sizes.unzip();
        let codec = match self.method {
            // Shrink starts in nine-bit mode with an empty dictionary. A
            // control code or a dictionary reference cannot start a stream.
            1 => return Some(plain.get(1)? & 1 == 0),
            6 => return implode_tables(plain, self.flags & 4 != 0),
            8 | 9 => return deflate_prefix::check_prefix(plain, packed, unpacked, self.method == 9),
            12 => &[0x04, 0x02, 0x02][..],
            14 => {
                let properties = le_u16(plain, 2)?;
                if properties != 5 || *plain.get(4)? >= 225 {
                    return Some(false);
                }
                let range = plain.get(9..)?;
                if seven_zip_prefix_check(&[0x03, 0x01, 0x01], range, packed.unwrap_or(u64::MAX).saturating_sub(9), unpacked.unwrap_or(u64::MAX)) == SevenZipPrefixCheck::Reject {
                    return Some(false);
                }
                return (range.len() >= 5).then_some(true);
            }
            93 => ZSTD_METHOD,
            95 => {
                if plain.get(..6)? != b"\xfd7zXZ\x00" {
                    return Some(false);
                }
                return Some(crate::scan::compression_stream::validate_xz_header(plain.get(..12)?).is_ok());
            }
            98 => {
                let properties = le_u16(plain, 0)?;
                if properties & 15 == 0 || properties >> 12 > 2 {
                    return Some(false);
                }
                return Some(plain.get(2..6)? != [0xff; 4]);
            }
            99 => return lzfse_block(plain, packed, unpacked),
            _ => unreachable!(),
        };
        match seven_zip_prefix_check(codec, plain, packed.unwrap_or(u64::MAX), unpacked.unwrap_or(u64::MAX)) {
            SevenZipPrefixCheck::Reject => Some(false),
            SevenZipPrefixCheck::Weak => None,
            _ => Some(true),
        }
    }
}

fn implode_tables(mut bytes: &[u8], literals: bool) -> Option<bool> {
    // Implode always begins with length and distance trees. GP bit 2
    // prepends a literal tree. Their run records are byte-aligned.
    let counts: &[usize] = if literals { &[256, 64, 64] } else { &[64, 64] };
    for &symbols in counts {
        let (&size, rest) = bytes.split_first()?;
        let records = usize::from(size) + 1;
        let seen = records.min(rest.len());
        let remaining = records - seen;
        let mut entries = 0;
        let mut weights = 0usize;
        for &record in &rest[..seen] {
            let repeat = usize::from(record >> 4) + 1;
            entries += repeat;
            weights += repeat << (15 - (record & 15));
            if entries > symbols || weights > 1 << 16 {
                return Some(false);
            }
        }
        if entries + remaining > symbols || entries + remaining * 16 < symbols {
            return Some(false);
        }
        if remaining != 0 {
            return None;
        }
        if weights != 1 << 16 {
            return Some(false);
        }
        bytes = &rest[records..];
    }
    Some(true)
}

fn lzfse_block(bytes: &[u8], packed: Option<u64>, unpacked: Option<u64>) -> Option<bool> {
    let magic = bytes.first_chunk::<4>()?;
    match magic {
        b"bvx$" => return Some(unpacked.is_none_or(|size| size == 0)),
        b"bvx-" | b"bvxn" | b"bvx1" | b"bvx2" => {}
        _ => return Some(false),
    }
    let output = u64::from(u32::from_le_bytes(bytes.get(4..8)?.try_into().unwrap()));
    if unpacked.is_some_and(|size| output > size) {
        return Some(false);
    }
    match magic {
        b"bvx-" => Some(packed.is_none_or(|size| output + 12 <= size)),
        b"bvxn" => {
            let encoded = u64::from(u32::from_le_bytes(bytes.get(8..12)?.try_into().unwrap()));
            Some(packed.is_none_or(|size| encoded + 16 <= size))
        }
        _ => Some(true),
    }
}

fn winzip_aes_prefix<C: BlockCipherEncrypt + KeyInit>(key: &[u8], bytes: &mut [u8]) {
    let cipher = C::new_from_slice(key).unwrap();
    winzip_aes_ctr(&cipher, 0, bytes);
}

fn winzip_aes_ctr<C: BlockCipherEncrypt>(cipher: &C, mut offset: u64, mut bytes: &mut [u8]) {
    while !bytes.is_empty() {
        let mut counter = Block::<C>::default();
        counter[..8].copy_from_slice(&(offset / 16 + 1).to_le_bytes());
        cipher.encrypt_block(&mut counter);
        let mask = &counter[(offset % 16) as usize..];
        let len = bytes.len().min(mask.len());
        let (chunk, rest) = bytes.split_at_mut(len);
        for (byte, &mask) in chunk.iter_mut().zip(mask) {
            *byte ^= mask;
        }
        bytes = rest;
        offset += len as u64;
    }
}
