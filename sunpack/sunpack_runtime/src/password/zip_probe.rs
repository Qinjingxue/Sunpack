use super::{le_u16, FixedZipDirectory, PasswordVerification, ZipCryptoState, ZipVolumeReader};
use crate::formats::deflate_prefix;
use crate::formats::seven_zip::{seven_zip_prefix_check, seven_zip_successor_prefix, SevenZipPrefixCheck};
use crate::formats::zip::zip64::CentralValues;
use crate::io::cancellation::Cancellation;
use crate::password::evidence::VolumeProjection;
use crate::password::input::attempts::{DeferredReadError, DeferredReads};
use crate::password::input::{RangeSpec, VirtualRangeReader, VolumeSet};
use crate::scan::compression_stream::{check_xz_footer, check_xz_prefix, MAX_XZ_PREFIX_SIZE};
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use std::borrow::Cow;
use std::io;
use std::sync::Arc;

const MAX_IMPLODE_TABLES: usize = (1 + 256) + 2 * (1 + 64);
const INITIAL_PREFIX_LIMIT: usize = 16;
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
    FixedDirectory(Arc<FixedZipDirectory>),
}

impl PartialEq for ZipReadInput {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ranges(a), Self::Ranges(b)) => Arc::ptr_eq(a, b),
            (Self::Volumes(a), Self::Volumes(b)) => Arc::ptr_eq(a, b),
            (Self::Projected(a), Self::Projected(b)) => Arc::ptr_eq(a, b),
            (Self::FixedDirectory(a), Self::FixedDirectory(b)) => Arc::ptr_eq(a, b),
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
        let input = match &self.input {
            ZipReadInput::FixedDirectory(directory) => directory.input(),
            input => input,
        };
        let result = match input {
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
            ZipReadInput::FixedDirectory(_) => unreachable!("fixed source is already unwrapped"),
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

impl ZipPrefixKey {
    fn decrypt(&mut self, offset: usize, encrypted: &[u8], plain: &mut [u8]) {
        match self {
            Self::ZipCrypto(state) => {
                for (output, &byte) in plain.iter_mut().zip(encrypted) {
                    *output = state.decrypt(byte);
                }
            }
            Self::Aes { key, len } => {
                plain.copy_from_slice(encrypted);
                let offset = offset as u64;
                match *len {
                    16 => winzip_aes_decrypt::<Aes128>(&key[..16], offset, plain),
                    24 => winzip_aes_decrypt::<Aes192>(&key[..24], offset, plain),
                    32 => winzip_aes_decrypt::<Aes256>(key, offset, plain),
                    _ => unreachable!(),
                }
            }
        }
    }
}

pub(super) struct ZipPrefixScratch {
    small: [u8; MAX_IMPLODE_TABLES],
    large: Vec<u8>,
}

impl ZipPrefixScratch {
    pub(super) fn new() -> Self {
        Self { small: [0; MAX_IMPLODE_TABLES], large: Vec::new() }
    }

    pub(super) fn bytes(&mut self, len: usize) -> &mut [u8] {
        self.grow(0, len)
    }

    fn grow(&mut self, previous: usize, len: usize) -> &mut [u8] {
        if len <= self.small.len() { return &mut self.small[..len]; }
        self.large.resize(len, 0);
        if previous <= self.small.len() {
            self.large[..previous].copy_from_slice(&self.small[..previous]);
        }
        &mut self.large
    }
}

struct ZipPrefixProgress {
    position: usize,
    key: ZipPrefixKey,
    len: usize,
    plain: ZipPrefixScratch,
}

impl ZipPrefixProgress {
    fn new(position: usize, key: ZipPrefixKey, prefix: &[u8]) -> Self {
        let mut plain = ZipPrefixScratch::new();
        plain.bytes(prefix.len()).copy_from_slice(prefix);
        Self { position, key, len: prefix.len(), plain }
    }

    fn extend(&mut self, encrypted: &[u8]) -> &[u8] {
        let previous = self.len;
        let plain = self.plain.grow(previous, encrypted.len());
        if previous < encrypted.len() {
            self.key.decrypt(previous, &encrypted[previous..], &mut plain[previous..]);
            self.len = encrypted.len();
        }
        plain
    }
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

    pub(super) fn screening_prefix(&self, matches: usize, derive_aes_key: bool, unique_volumes: bool)
        -> io::Result<Option<(Cow<'_, Self>, usize)>>
    {
        let mut prefix = Cow::Borrowed(self);
        if matches > 1 {
            if let Some(ZipReadInput::FixedDirectory(directory)) = self.read.as_ref().map(|read| &read.input) {
                if let Some((packed, unpacked)) = directory.sizes()? {
                    prefix.to_mut().sizes = packed.checked_sub(self.overhead).map(|packed| (packed, unpacked));
                }
            }
        }
        Ok(prefix.screening_minimum(matches, derive_aes_key, unique_volumes).map(|minimum| (prefix, minimum)))
    }

    fn screening_minimum(&self, matches: usize, derive_aes_key: bool, unique_volumes: bool) -> Option<usize> {
        let read = self.read.as_ref()?;
        let size = self.read_size();
        if matches == 0 || size == 0 { return None; }
        // With one complete layout, extraction can confirm the last candidate.
        // An individual projection can be fixed while other layouts remain.
        let minimum = if unique_volumes { 2 } else { 1 };
        if matches < minimum { return None; }
        if !derive_aes_key || matches > 1 { return Some(minimum); }
        let span = if self.has_aes_successor() {
            self.sizes.map_or(size as u64, |(packed, _)| packed)
        } else { size as u64 };
        (read.ambiguous(self.start, span) || self.xz_tail(read).is_some()).then_some(minimum)
    }

    pub(super) fn needs_size(&self) -> bool {
        self.sizes.is_none()
    }

    fn has_aes_successor(&self) -> bool {
        matches!(self.method, 8 | 9 | 93)
    }

    fn xz_tail(&self, read: &ZipRead) -> Option<(u64, u64)> {
        let sizes = self.sizes?;
        let packed = sizes.0;
        (self.method == 95 && packed >= 32 && packed.is_multiple_of(4)
            && read.ambiguous(self.start + packed - 12, 12)).then_some(sizes)
    }

    pub(super) fn cbc_deflate_probe(&self) -> Option<((u64, u64), bool)> {
        let sizes = self.sizes?;
        (matches!(self.method, 8 | 9) && sizes.0.is_multiple_of(16)).then_some((sizes, self.method == 9))
    }

    fn prefix_size(&self) -> usize {
        match self.method {
            1 => 2,
            6 => MAX_IMPLODE_TABLES,
            8 | 9 => deflate_prefix::MAX_DYNAMIC_HEADER_SIZE,
            12 => 10,
            14 => 14,
            93 => 24,
            95 => MAX_XZ_PREFIX_SIZE,
            99 => 12,
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
        &self, keys: &[(usize, ZipPrefixKey)], minimum_candidates: usize, result: &mut PasswordVerification,
    ) -> io::Result<()> {
        let Some(source) = &self.read else { return Ok(()); };
        let size = self.read_size();
        let successor_sizes = if self.has_aes_successor() && matches!(keys.first(), Some((_, ZipPrefixKey::Aes { .. }))) {
            self.sizes
        } else { None };
        let successor_volumes = successor_sizes.is_some_and(|(packed, _)| source.ambiguous(self.start, packed));
        let xz = self.method == 95;
        let xz_tail = if matches!(keys.first(), Some((_, ZipPrefixKey::Aes { .. }))) {
            self.xz_tail(source)
        } else { None };
        let initial = size.min(match self.method {
            8 | 9 if successor_volumes => 5,
            95 => 13,
            _ => INITIAL_PREFIX_LIMIT,
        });
        let next_size = |read: usize| if xz { size } else { (2 * read).max(5).min(size) };
        let minimum = self.minimum_prefix().min(size);
        let first = if self.method == 93 && successor_volumes {
            // A skippable frame needs only its 8-byte header before jumping.
            size.min(8)
        } else if initial > minimum && source.ambiguous(self.start, initial as u64) {
            minimum
        } else {
            initial
        };
        let mut scratch = None;
        let checks = source.evaluate(|read| {
            let mut unavailable = None;
            let mut encrypted = match read(self.start, first) {
                Ok(bytes) => bytes,
                Err(error) => {
                    unavailable = Some(error);
                    if minimum == first {
                        Vec::new()
                    } else {
                        match read(self.start, minimum) {
                            Ok(bytes) => bytes,
                            Err(error) => { unavailable = Some(error); Vec::new() }
                        }
                    }
                }
            };
            let mut next = next_size(encrypted.len());
            let mut primary = None;
            let mut additional = Vec::new();
            let mut verdicts = if encrypted.is_empty() || (successor_volumes && unavailable.is_none()) {
                vec![None; keys.len()]
            } else {
                let mut buffer = [0; INITIAL_PREFIX_LIMIT];
                keys.iter().enumerate().map(|(position, &(_, mut key))| {
                    let plain = &mut buffer[..encrypted.len()];
                    key.decrypt(0, &encrypted, plain);
                    let verdict = self.check_plain(plain, &mut next);
                    // Keep the common one-candidate continuation on the stack.
                    // Completed prefixes only need storage for successor checks.
                    if unavailable.is_none() && ((verdict.is_none() && encrypted.len() < size) ||
                        (successor_sizes.is_some() && verdict != Some(false))) {
                        let progress = ZipPrefixProgress::new(position, key, plain);
                        if primary.is_none() { primary = Some(progress); }
                        else { additional.push(progress); }
                    }
                    verdict
                }).collect()
            };
            let mut viable = verdicts.iter().filter(|&&verdict| verdict != Some(false)).count();
            while viable >= minimum_candidates && !successor_volumes && unavailable.is_none() && encrypted.len() < size
                && verdicts.iter().any(Option::is_none) {
                let previous = encrypted.len();
                let more = match read(self.start + previous as u64, next - previous) {
                    Ok(bytes) => bytes,
                    Err(error) => { unavailable = Some(error); break; }
                };
                encrypted.extend_from_slice(&more);
                next = next_size(encrypted.len());
                for progress in primary.iter_mut().chain(&mut additional) {
                    let verdict = &mut verdicts[progress.position];
                    if verdict.is_none() {
                        *verdict = self.check_plain(progress.extend(&encrypted), &mut next);
                        if *verdict == Some(false) {
                            viable -= 1;
                            if viable < minimum_candidates { break; }
                        }
                    }
                }
            }
            if let Some(sizes) = successor_sizes.filter(|_| unavailable.is_none() && viable >= minimum_candidates
                && (successor_volumes || viable > 1)) {
                let mut progress = primary.iter_mut().chain(&mut additional).peekable();
                for (position, ((_, key), verdict)) in keys.iter().zip(&mut verdicts).enumerate() {
                    let saved = progress.next_if(|saved| saved.position == position);
                    if *verdict == Some(false) { continue; }
                    let plain = saved.map(|saved| saved.extend(&encrypted));
                    let outcome = self.check_aes_successors(key, &encrypted, plain, sizes, source, read, &mut scratch);
                    *verdict = match outcome {
                        Ok(SevenZipPrefixCheck::Reject) => Some(false),
                        Ok(SevenZipPrefixCheck::Weak) => None,
                        Ok(_) => Some(true),
                        Err(DeferredReadError::Truncated) if successor_volumes => Some(false),
                        Err(error) => {
                            if matches!(error, DeferredReadError::Pending) { break; }
                            unavailable.get_or_insert(error);
                            None
                        }
                    };
                    if *verdict == Some(false) {
                        viable -= 1;
                        if viable < minimum_candidates { break; }
                    }
                }
            }
            if let Some(sizes) = xz_tail.filter(|_| viable >= minimum_candidates
                && !matches!(unavailable, Some(DeferredReadError::Pending)))
            {
                match read(self.start + sizes.0 - 12, 12) {
                    Ok(tail) => {
                        for ((_, key), verdict) in keys.iter().zip(&mut verdicts) {
                            if *verdict == Some(false) { continue; }
                            match self.check_aes_successors(key, &tail, None, sizes, source, read, &mut scratch) {
                                Ok(SevenZipPrefixCheck::Reject) => *verdict = Some(false),
                                Ok(_) => {}
                                Err(DeferredReadError::Pending) => break,
                                Err(error) => {
                                    *verdict = None;
                                    // An unavailable step cannot erase a known short extent.
                                    if !matches!(unavailable, Some(DeferredReadError::Truncated)) {
                                        unavailable = Some(error);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        for verdict in &mut verdicts {
                            if *verdict != Some(false) { *verdict = None; }
                        }
                        if !matches!(unavailable, Some(DeferredReadError::Truncated)) {
                            unavailable = Some(error);
                        }
                    }
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

    fn check_aes_successors(
        &self, key: &ZipPrefixKey, encrypted: &[u8], plain: Option<&[u8]>, sizes: (u64, u64),
        source: &ZipRead, read: &mut CheckRead<'_>, scratch: &mut Option<ZipPrefixScratch>,
    ) -> Result<SevenZipPrefixCheck, DeferredReadError> {
        fn verify<C: KeyInit + BlockCipherEncrypt>(
            prefix: &ZipPrefix, key: &[u8], encrypted: &[u8], plain: Option<&[u8]>,
            (packed, unpacked): (u64, u64), source: &ZipRead, read: &mut CheckRead<'_>,
            scratch: &mut Option<ZipPrefixScratch>,
        ) -> Result<SevenZipPrefixCheck, DeferredReadError> {
            let cipher = C::new_from_slice(key).unwrap();
            if prefix.method == 95 {
                return check_aes_xz_tail(&cipher, prefix.start, packed, encrypted, read);
            }
            let plain = plain.unwrap_or_else(|| {
                let out = scratch.get_or_insert_with(ZipPrefixScratch::new).bytes(encrypted.len());
                out.copy_from_slice(encrypted);
                winzip_aes_ctr(&cipher, 0, out);
                out
            });
            let read_plain = |offset, output: &mut [u8]| {
                output.copy_from_slice(&read(prefix.start + offset, output.len())?);
                winzip_aes_ctr(&cipher, offset, output);
                Ok(())
            };
            let ambiguous = |offset| source.ambiguous(prefix.start + offset, packed - offset);
            if prefix.method == 93 {
                seven_zip_successor_prefix(ZSTD_METHOD, plain, packed, unpacked, packed, read_plain, ambiguous)
            } else {
                deflate_prefix::check_successors(plain, (packed, unpacked), packed, prefix.method == 9, read_plain, ambiguous)
                    .map(|verdict| match verdict {
                        Some(false) => SevenZipPrefixCheck::Reject,
                        Some(true) => SevenZipPrefixCheck::Strong,
                        None => SevenZipPrefixCheck::Weak,
                    })
            }
        }
        match key {
            ZipPrefixKey::Aes { key, len: 16 } => verify::<Aes128>(self, &key[..16], encrypted, plain, sizes, source, read, scratch),
            ZipPrefixKey::Aes { key, len: 24 } => verify::<Aes192>(self, &key[..24], encrypted, plain, sizes, source, read, scratch),
            ZipPrefixKey::Aes { key, len: 32 } => verify::<Aes256>(self, key, encrypted, plain, sizes, source, read, scratch),
            _ => unreachable!(),
        }
    }

    pub(super) fn cbc_probe_range(&self) -> Option<(u64, u64)> {
        // The encrypted length includes PKCS7 padding. It is a safe upper
        // bound for compression framing, but cannot be used as an exact size.
        let (packed, _) = self.sizes?;
        let span = match self.method {
            8 | 9 if packed.is_multiple_of(16) => packed,
            95 => packed.min(MAX_XZ_PREFIX_SIZE.next_multiple_of(16) as u64),
            _ => 16,
        };
        (packed >= 16).then_some((self.start, span))
    }

    pub(super) fn check_plain(&self, plain: &[u8], next: &mut usize) -> Option<bool> {
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
            95 => return match check_xz_prefix(plain, packed, unpacked) {
                Ok(Some(required)) => { *next = (*next).min(required); None }
                Ok(None) => Some(true),
                Err(_) => Some(false),
            },
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

fn check_aes_xz_tail<C: BlockCipherEncrypt>(
    cipher: &C, start: u64, mut end: u64, encrypted: &[u8], read: &mut CheckRead<'_>,
) -> Result<SevenZipPrefixCheck, DeferredReadError> {
    use SevenZipPrefixCheck::{Reject, Strong};
    let mut footer: [u8; 12] = encrypted.try_into().unwrap();
    winzip_aes_ctr(cipher, end - 12, &mut footer);
    if footer.ends_with(b"YZ") {
        return Ok(if check_xz_footer(&footer, end).is_ok() { Strong } else { Reject });
    }

    // Stream Padding consists of zero words. Skip only bytes actually read
    // as zeros; the last stream may differ from the first one.
    let mut bytes: &[u8] = &footer;
    let mut padding;
    let mut read_size = 64;
    loop {
        let at = end - bytes.len() as u64;
        if let Some(last) = bytes.iter().rposition(|&byte| byte != 0) {
            let footer_end = (last + 1).next_multiple_of(4);
            let end = at + footer_end as u64;
            if end < 32 { return Ok(Reject); }
            let verdict = if footer_end >= 12 {
                check_xz_footer(&bytes[footer_end - 12..footer_end], end)
            } else {
                let mut footer = read(start + end - 12, 12)?;
                winzip_aes_ctr(cipher, end - 12, &mut footer);
                check_xz_footer(&footer, end)
            };
            return Ok(if verdict.is_ok() { Strong } else { Reject });
        }
        end = at;
        if end < 32 { return Ok(Reject); }
        let len = end.min(read_size) as usize;
        padding = read(start + end - len as u64, len)?;
        winzip_aes_ctr(cipher, end - len as u64, &mut padding);
        bytes = &padding;
        read_size = (read_size * 4).min(4096);
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

fn winzip_aes_decrypt<C: BlockCipherEncrypt + KeyInit>(key: &[u8], offset: u64, bytes: &mut [u8]) {
    let cipher = C::new_from_slice(key).unwrap();
    winzip_aes_ctr(&cipher, offset, bytes);
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
