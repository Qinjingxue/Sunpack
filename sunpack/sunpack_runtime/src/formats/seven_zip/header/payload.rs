// Data-only screening uses compressed-stream structure. Member CRC/MAC
// verification, including AES/Copy, belongs to the worker decoder.
use crate::password::evidence::VolumeProjection;
use crate::password::input::{
    attempts::{DeferredReadError, DeferredReads},
    RangeSpec, VirtualRangeReader,
};
use crate::formats::deflate_prefix;
use std::sync::Arc;

struct SevenZipPayloadProbe {
    offset: u64,
    properties: Vec<u8>,
    inner_aes: Box<[Vec<u8>]>,
    encrypted: [u8; 16],
    kind: SevenZipPayloadEvidence,
}

pub(crate) struct SevenZipPayloadPrefix {
    plaintext: [u8; 32],
    len: usize,
    inner_keys: Vec<SevenZipAesKey>,
    pub(crate) check: SevenZipPrefixCheck,
}

pub(crate) enum SevenZipPayloadSource {
    Fixed(Arc<[RangeSpec]>),
    Projected(DeferredReads),
}

pub(crate) struct SevenZipPayloadProbes {
    first: SevenZipPayloadProbe,
    /// Only the first usable prefix is materialized before trying passwords.
    rest: Vec<SevenZipPayloadPlan>,
    source: Option<SevenZipPayloadSource>,
}

type SevenZipRead<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), DeferredReadError> + 'a;

impl SevenZipPayloadSource {
    fn validate(
        &self,
        mut check: impl FnMut(&mut SevenZipRead<'_>) -> Result<SevenZipPrefixCheck, String>,
        reject: &mut impl FnMut(Arc<VolumeProjection>),
    ) -> Result<SevenZipPrefixCheck, String> {
        use SevenZipPrefixCheck::{Reject, Weak};
        match self {
            Self::Fixed(ranges) => {
                let mut reader = VirtualRangeReader::new(ranges);
                check(&mut |offset, bytes| {
                    reader.seek(std::io::SeekFrom::Start(offset)).map_err(DeferredReadError::Io)?;
                    reader.read_exact(bytes).map_err(DeferredReadError::Io)
                })
            }
            Self::Projected(ranges) => {
                let outcomes = ranges.evaluate(|reader| check(&mut |offset, bytes| {
                    bytes.copy_from_slice(&reader.read(offset, bytes.len())?);
                    Ok(())
                })).map_err(resource_error)?;
                if outcomes.iter().all(|(_, result)| matches!(result, Ok(Reject)))
                    && !outcomes.is_empty()
                {
                    return Ok(Reject);
                }
                let mut fault = None;
                for (projection, result) in outcomes {
                    match result {
                        Ok(Reject) => reject(projection),
                        Err(error) => { fault.get_or_insert(error); }
                        _ => {}
                    }
                }
                fault.map_or(Ok(Weak), Err)
            }
        }
    }
}

impl SevenZipPayloadProbes {
    pub(crate) fn key_properties(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.first.properties.as_slice())
            .chain(self.first.inner_aes.iter().map(Vec::as_slice))
            .chain(self.rest.iter().flat_map(|plan| {
                std::iter::once(plan.properties.as_slice()).chain(plan.inner_aes.iter().map(Vec::as_slice))
            }))
    }

    pub(crate) fn prescreen<'a>(
        &'a self, first_key: &SevenZipAesKey,
        key: impl FnMut(&'a [u8]) -> Result<SevenZipAesKey, String>,
    ) -> Result<SevenZipPayloadPrefix, String> {
        let inner_keys = self.first.inner_aes.iter().map(Vec::as_slice).map(key)
            .collect::<Result<Vec<_>, _>>()?;
        let (plaintext, len) = self.first.kind.decrypt_prefix_with_inner(&self.first.encrypted, first_key, &inner_keys)?;
        Ok(SevenZipPayloadPrefix {
            check: self.first.kind.check_prefix(&plaintext[..len]), plaintext, len, inner_keys,
        })
    }

    pub(crate) fn has_followup(&self) -> bool {
        self.source.is_some() && (!self.rest.is_empty() || self.first.kind.has_successor())
    }

    pub(crate) fn has_ambiguous_followup(&self) -> bool {
        match &self.source {
            Some(SevenZipPayloadSource::Projected(reads)) => {
                (self.first.kind.has_successor()
                    && reads.range_is_ambiguous(self.first.offset, self.first.kind.followup_span()))
                || self.rest.iter().any(|plan| reads.range_is_ambiguous(
                    plan.offset, if plan.kind.has_successor() { plan.kind.followup_span() } else { 16 },
                ))
            }
            _ => false,
        }
    }

    pub(crate) fn verify_followup<'a>(
        &'a self,
        first_key: &SevenZipAesKey,
        prefix: SevenZipPayloadPrefix,
        mut key: impl FnMut(&'a [u8]) -> Result<SevenZipAesKey, String>,
        mut reject: impl FnMut(Arc<VolumeProjection>),
    ) -> Result<SevenZipPrefixCheck, String> {
        use SevenZipPrefixCheck::Reject;
        let Some(source) = &self.source else { return Ok(prefix.check); };
        source.validate(|read| {
            let mut fault = None;
            match self.first.kind.check_successor(
                self.first.offset, &self.first.encrypted, &prefix.plaintext[..prefix.len],
                first_key, &prefix.inner_keys, read, source,
            ) {
                Ok(Reject) => return Ok(Reject),
                Err(DeferredReadError::Truncated) => return Ok(Reject),
                Err(error @ (DeferredReadError::Pending | DeferredReadError::Cancelled)) =>
                    return Err(seven_zip_deferred_error(error)),
                Err(error) => { fault = Some(seven_zip_deferred_error(error)); }
                _ => {}
            }
            for plan in &self.rest {
                check_password_cancellation()?;
                // Load before deriving a key for a stream that may cross a hole.
                let mut encrypted = [0u8; 16];
                if let Err(error) = read(plan.offset, &mut encrypted) {
                    if matches!(error, DeferredReadError::Truncated) {
                        return Ok(Reject);
                    }
                    if matches!(error, DeferredReadError::Pending | DeferredReadError::Cancelled) {
                        return Err(seven_zip_deferred_error(error));
                    }
                    fault.get_or_insert_with(|| seven_zip_deferred_error(error));
                    continue;
                }
                let candidate = key(&plan.properties)?;
                let inner_keys = plan.inner_aes.iter().map(Vec::as_slice).map(&mut key)
                    .collect::<Result<Vec<_>, _>>()?;
                let (plaintext, length) = plan.kind.decrypt_prefix_with_inner(
                    &encrypted, &candidate, &inner_keys,
                )?;
                if plan.kind.check_prefix(&plaintext[..length]) == Reject {
                    return Ok(Reject);
                }
                match plan.kind.check_successor(
                    plan.offset, &encrypted, &plaintext[..length], &candidate, &inner_keys, read, source,
                ) {
                    Ok(Reject) => return Ok(Reject),
                    Err(DeferredReadError::Truncated) => return Ok(Reject),
                    Err(error @ (DeferredReadError::Pending | DeferredReadError::Cancelled)) =>
                        return Err(seven_zip_deferred_error(error)),
                    Err(error) => { fault.get_or_insert_with(|| seven_zip_deferred_error(error)); }
                    _ => {}
                }
            }
            fault.map_or(Ok(prefix.check), Err)
        }, &mut reject)
    }
}

fn seven_zip_deferred_error(error: DeferredReadError) -> String {
    let reason = match error {
        DeferredReadError::Missing => "missing_volume",
        DeferredReadError::Pending => "pending_volume_projection",
        DeferredReadError::Truncated => "short_volume_extent",
        DeferredReadError::Cancelled => "cancelled",
        DeferredReadError::Io(error) => return resource_error(error),
    };
    format!("7z structural evidence unavailable: {reason}")
}

enum SevenZipPayloadEvidence {
    Header { packed_size: u64 },
    Compressed {
        method: Vec<u8>,
        packed_size: u64,
        unpack_size: u64,
    },
}

impl SevenZipPayloadEvidence {
    fn from_stream(folder: &SevenZipFolderAst, stream: &SevenZipAesStream, header: bool) -> Option<Self> {
        let packed_size = stream.plaintext_size;
        match stream.consumer {
            Some((index, unpack_size)) => Some(Self::Compressed {
                method: folder.coders[index].method_id.clone(),
                packed_size,
                unpack_size,
            }),
            None if header => Some(Self::Header { packed_size }),
            None => None,
        }
    }

    fn followup_span(&self) -> u64 {
        match self {
            Self::Header { packed_size } => *packed_size,
            Self::Compressed { method, packed_size, .. } if seven_zip_is_deflate(method) => {
                (*packed_size).min(deflate_prefix::MAX_DYNAMIC_HEADER_SIZE as u64)
            }
            Self::Compressed { packed_size, .. } => *packed_size,
        }.next_multiple_of(16)
    }

    fn plaintext_prefix_size(&self) -> usize {
        match self {
            Self::Header { packed_size } => (*packed_size).min(16) as usize,
            Self::Compressed { packed_size, .. } => (*packed_size).min(32) as usize,
        }
    }

    #[cfg(test)]
    fn check_encrypted_prefix(
        &self,
        encrypted: &[u8],
        material: &SevenZipAesKey,
    ) -> Result<SevenZipPrefixCheck, String> {
        let (plaintext, len) = self.decrypt_prefix(encrypted, material)?;
        Ok(self.check_prefix(&plaintext[..len]))
    }

    fn decrypt_prefix(
        &self, encrypted: &[u8], material: &SevenZipAesKey,
    ) -> Result<([u8; 32], usize), String> {
        check_password_cancellation()?;
        let len = self.plaintext_prefix_size().min(encrypted.len());
        let mut buffer = [0u8; 32];
        if len == 0 {
            return Ok((buffer, 0));
        }
        let prefix = &mut buffer[..len.div_ceil(16) * 16];
        let encrypted = &encrypted[..prefix.len()];
        prefix.copy_from_slice(encrypted);
        Aes256CbcDec::new(&material.key.into(), &material.iv.into())
            .decrypt_padded::<NoPadding>(prefix)
            .map_err(|_| "encoded_header_payload_crc_bad:aes_block_size".to_string())?;
        Ok((buffer, len))
    }

    fn decrypt_prefix_with_inner(
        &self, encrypted: &[u8], first: &SevenZipAesKey, inner: &[SevenZipAesKey],
    ) -> Result<([u8; 32], usize), String> {
        let (mut bytes, len) = self.decrypt_prefix(encrypted, first)?;
        for material in inner {
            Aes256CbcDec::new(&material.key.into(), &material.iv.into())
                .decrypt_padded::<NoPadding>(&mut bytes[..len.next_multiple_of(16)])
                .expect("the nested CBC prefix covers complete blocks");
        }
        Ok((bytes, len))
    }

    fn check_prefix(&self, plaintext: &[u8]) -> SevenZipPrefixCheck {
        match self {
            Self::Header { packed_size } => seven_zip_plain_header_prefix(plaintext, *packed_size),
            Self::Compressed { method, packed_size, unpack_size } => {
                seven_zip_prefix_check(method, plaintext, *packed_size, *unpack_size)
            }
        }
    }

    fn has_successor(&self) -> bool {
        matches!(self, Self::Compressed { method, .. }
            if seven_zip_has_block_successor(method) || seven_zip_is_deflate(method))
    }

    fn check_successor(
        &self, offset: u64, first_encrypted: &[u8; 16], plaintext: &[u8],
        material: &SevenZipAesKey, inner: &[SevenZipAesKey],
        read: &mut SevenZipRead<'_>, source: &SevenZipPayloadSource,
    ) -> Result<SevenZipPrefixCheck, DeferredReadError> {
        let Self::Compressed { method, packed_size, unpack_size } = self else {
            return Ok(SevenZipPrefixCheck::Weak);
        };
        let mut read_plain = |at: u64, out: &mut [u8]| {
            if let Some(bytes) = usize::try_from(at).ok()
                .and_then(|at| at.checked_add(out.len()).and_then(|end| plaintext.get(at..end)))
            {
                out.copy_from_slice(bytes);
                return Ok(());
            }
            // Each CBC layer needs one preceding block, except at offset zero
            // where it uses the IV. Discard these blocks in place as each layer
            // advances the plaintext window toward the requested offset.
            let block_start = at & !15;
            let predecessors = 16 * (1 + inner.len()) as u64;
            let window = block_start.saturating_sub(predecessors);
            let start = (at - window) as usize;
            let end = (start + out.len()).next_multiple_of(16);
            const WINDOW: usize = (deflate_prefix::MAX_DYNAMIC_HEADER_SIZE + 15).next_multiple_of(16)
                + 16 * SEVEN_Z_MAX_FOLDER_CODERS;
            let mut ciphertext = [0; WINDOW];
            let cached = if window == 0 {
                ciphertext[..16].copy_from_slice(first_encrypted);
                16
            } else {
                0
            };
            if end > cached {
                read(offset + window + cached as u64, &mut ciphertext[cached..end])?;
            }
            let mut from = 0;
            for (layer, material) in std::iter::once(material).chain(inner).enumerate() {
                let next = block_start.saturating_sub(16 * (inner.len() - layer.min(inner.len())) as u64);
                let iv = if next != 0 {
                    let previous = ciphertext[from..from + 16].try_into().unwrap();
                    from += 16;
                    previous
                } else {
                    material.iv
                };
                Aes256CbcDec::new(&material.key.into(), &iv.into())
                    .decrypt_padded::<NoPadding>(&mut ciphertext[from..end])
                    .expect("CBC window is block-aligned");
            }
            out.copy_from_slice(&ciphertext[start..start + out.len()]);
            Ok(())
        };
        if seven_zip_is_deflate(method) {
            let bound = (*packed_size).min(deflate_prefix::MAX_DYNAMIC_HEADER_SIZE as u64) as usize;
            let deflate64 = method[2] == 9;
            let check = |bytes: &[u8]| deflate_prefix::check_prefix(
                bytes, Some(*packed_size), Some(*unpack_size), deflate64,
            );
            if bound <= plaintext.len() || check(plaintext).is_some() {
                return Ok(SevenZipPrefixCheck::Weak);
            }
            let mut header = [0; deflate_prefix::MAX_DYNAMIC_HEADER_SIZE];
            header[..plaintext.len()].copy_from_slice(plaintext);
            read_plain(plaintext.len() as u64, &mut header[plaintext.len()..bound])?;
            return Ok(if check(&header[..bound]) == Some(false) {
                SevenZipPrefixCheck::Reject
            } else {
                SevenZipPrefixCheck::Weak
            });
        }
        if seven_zip_has_block_successor(method) {
            let ambiguous = |next: u64| match source {
                SevenZipPayloadSource::Projected(reads) => {
                    let window = (next & !15u64).saturating_sub(16 * (1 + inner.len()) as u64);
                    reads.range_is_ambiguous(offset + window, self.followup_span() - window)
                }
                SevenZipPayloadSource::Fixed(_) => false,
            };
            seven_zip_successor_prefix(method, plaintext, *packed_size, *unpack_size, read_plain, ambiguous)
        } else {
            Ok(SevenZipPrefixCheck::Weak)
        }
    }
}

fn seven_zip_is_deflate(method: &[u8]) -> bool {
    matches!(method, [0x04, 0x01, 0x08 | 0x09])
}

struct SevenZipPayloadPlan {
    offset: u64,
    properties: Vec<u8>,
    inner_aes: Box<[Vec<u8>]>,
    kind: SevenZipPayloadEvidence,
    cost: u64,
}

pub(crate) enum SevenZipPasswordContext {
    Header(SevenZipPasswordProbe),
    MemberOnly,
    Prefix {
        probe: SevenZipPayloadProbes,
        header: bool,
    },
}

/// When a field is unavailable in one volume, later independent evidence
/// can still be usable. Resolved readers need no projection bookkeeping.
pub(crate) trait SevenZipEvidenceReads<R> {
    fn independent<T, E>(
        &self,
        reader: &mut R,
        read: impl FnOnce(&mut R) -> Result<T, E>,
    ) -> Result<T, E> {
        read(reader)
    }
    fn range_is_ambiguous(&self, _reader: &R, _start: u64, _size: u64) -> bool {
        false
    }
    fn payload_source(&self, _reader: &R) -> Option<SevenZipPayloadSource> {
        None
    }
    fn checks_public_packs(&self) -> bool {
        false
    }
    fn check_packed(
        &self,
        _reader: &mut R,
        _offset: u64,
        _size: u64,
        _expected: u32,
    ) -> Result<(), std::borrow::Cow<'static, str>> {
        Ok(())
    }
}
impl<R> SevenZipEvidenceReads<R> for () {}

fn check_public_packs<'a, R: Read + Seek>(
    reader: &mut R,
    before: u64,
    packs: impl IntoIterator<Item = &'a SevenZipPackInfoAst>,
    evidence: &impl SevenZipEvidenceReads<R>,
) -> Result<(), SevenZipMetadataError> {
    if !evidence.checks_public_packs() { return Ok(()); }
    let mut digests = Vec::new();
    for pack in packs {
        if pack.sizes.len() != pack.num_streams || pack.crcs.is_empty() {
            continue;
        }
        let start = (SEVEN_Z_HEADER_SIZE as u64).checked_add(pack.pack_pos);
        let end = pack.sizes.iter().try_fold(start.unwrap_or(u64::MAX), |offset, &size| {
            offset.checked_add(size)
        });
        let Some(mut offset) = start.filter(|_| end.is_some_and(|end| end <= before)) else { continue };
        for (&size, &crc) in pack.sizes.iter().zip(&pack.crcs) {
            if let Some(expected) = crc {
                if evidence.range_is_ambiguous(reader, offset, size) {
                    digests.push((size, offset, expected));
                }
            }
            offset += size;
        }
    }
    digests.sort_unstable();
    for (size, offset, expected) in digests {
        evidence.check_packed(reader, offset, size, expected)?;
    }
    Ok(())
}

impl SevenZipPasswordContext {
    /// Read and check the public descriptor once. Its tag selects either an
    /// encrypted header graph or the readable tree that locates data evidence.
    pub(crate) fn from_next_header<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        next: RelationNextHeader,
        enabled: bool,
        evidence: &impl SevenZipEvidenceReads<R>,
    ) -> Result<Option<Self>, std::borrow::Cow<'static, str>> {
        let raw = read_seven_zip_probe_range(
            reader,
            reader_len,
            next.offset,
            usize::try_from(next.size).map_err(|_| "7z next header is too large")?,
            "7z.next_header",
            FieldLocation::Tail,
        )
        .map_err(resource_error)?;
        if crc32(&raw) != next.crc {
            return Err("7z next header crc mismatch".into());
        }
        if !enabled && !evidence.checks_public_packs() {
            return Err("7z password probe is disabled".into());
        }
        let raw = if raw.first() == Some(&SZ_ENCODED_HEADER) {
            let (pack, folder) = parse_seven_zip_encoded_header_descriptor(&raw)?;
            drop(raw);
            if folder
                .coders
                .iter()
                .any(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
            {
                if !enabled {
                    check_public_packs(reader, next.offset, [&pack], evidence)?;
                    return Err("7z password probe is disabled".into());
                }
                if seven_zip_probe_folder_supported(&folder) {
                    match evidence.independent(reader, |reader| {
                        read_seven_zip_packed_data(reader, reader_len, next.offset, &pack, &folder, 0)
                    }) {
                        Ok(packed) => {
                            return Ok(Some(Self::Header(SevenZipPasswordProbe::from_parts(
                                packed, folder, SevenZipMetadata::Header,
                            ))))
                        }
                        Err(error) if error.starts_with("resource_unavailable:") => {
                            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                // A distant or unsupported metadata graph may still expose
                // a valid compressor or Header prefix.
                check_public_packs(reader, next.offset, [&pack], evidence)?;
                let streams = SevenZipStreams {
                    pack: Some(pack),
                    folders: vec![folder],
                };
                return Self::from_streams(
                    reader, next.offset, streams, Some(SevenZipMetadata::Header), evidence,
                );
            }
            let packed =
                read_seven_zip_packed_data(reader, reader_len, next.offset, &pack, &folder, 0)?;
            let decoded = decode_seven_zip_encoded_folder(&packed, &folder)
                .map_err(std::borrow::Cow::Owned)?;
            if folder
                .expected_crc
                .is_some_and(|expected| crc32(&decoded) != expected)
            {
                return Err("7z payload probe decoded header crc is invalid".into());
            }
            decoded
        } else {
            raw
        };
        if raw.first() != Some(&SZ_HEADER) {
            return Err("7z payload probe header tree is unsupported".into());
        }
        let mut streams = SevenZipStreams::default();
        let mut additional_streams = SevenZipStreams::default();
        let mut encrypted_metadata = None;
        let mut additional = |streams: &mut SevenZipStreams, index, count| {
            let folder = streams.folders.get(index).ok_or("7z external folder stream index is invalid")?;
            let pack = streams.pack.as_ref().ok_or("7z external folder PackInfo is missing")?;
            let first: usize = streams.folders[..index].iter().map(|folder| folder.packed_streams.len()).sum();
            let encrypted = folder.coders.iter().any(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256);
            if encrypted && !enabled {
                return Err("7z password probe is disabled".into());
            }
            if encrypted && !seven_zip_probe_folder_supported(folder) {
                return Err("7z external folder encryption graph is unsupported".into());
            }
            let packed = evidence.independent(reader, |reader| {
                read_seven_zip_packed_data(reader, reader_len, next.offset, pack, folder, first)
            })?;
            if encrypted {
                let folder = streams.folders.remove(index);
                encrypted_metadata = Some(SevenZipPasswordProbe::from_parts(
                    packed, folder, SevenZipMetadata::Folders(count),
                ));
                return Err("7z external folder data needs password".into());
            }
            let decoded = decode_seven_zip_encoded_folder(&packed, folder)
                .map_err(std::borrow::Cow::Owned)?;
            if folder.expected_crc.is_some_and(|expected| crc32(&decoded) != expected) {
                return Err("7z external folder metadata crc mismatch".into());
            }
            Ok(decoded)
        };
        let parsed = parse_seven_zip_header_with_data(
            &raw, &mut streams, &mut additional_streams, true, Some(&mut additional),
        );
        if parsed.is_ok() || encrypted_metadata.is_some()
            || parsed.as_ref().is_err_and(|error| error == "7z password probe is disabled") {
            // Main PackInfo is public even when an AdditionalStreams folder
            // supplies encrypted names or external Folder definitions.
            check_public_packs(reader, next.offset,
                streams.pack.iter().chain(&additional_streams.pack), evidence)?;
        }
        if !enabled {
            return Err("7z password probe is disabled".into());
        }
        if let Some(metadata) = encrypted_metadata {
            return Ok(Some(Self::Header(metadata)));
        }
        drop(raw);
        if parsed.as_ref().is_err_and(|error| matches!(
            error.as_ref(), "7z packed stream crc mismatch" | "7z external folder metadata crc mismatch"
        )) {
            return parsed.map(|_| None);
        }
        let mut additional_error = None;
        let mut additional_member_only = false;
        if seven_zip_streams_encrypted(&additional_streams) {
            // The archive reader decodes these header streams even when the
            // member graph and its Folder definitions are themselves clear.
            let names = parsed.as_ref().ok().copied().flatten();
            if let Some(probe) = Self::additional_metadata_probe(
                reader, reader_len, next.offset, &mut additional_streams, names, evidence,
            )? {
                return Ok(Some(probe));
            }
            match Self::from_streams(
                reader, next.offset, additional_streams, Some(SevenZipMetadata::Additional), evidence,
            ) {
                Ok(Some(Self::MemberOnly)) => additional_member_only = true,
                Ok(Some(probe)) => return Ok(Some(probe)),
                Ok(None) => {}
                Err(error) => additional_error = Some(error),
            }
        }
        parsed?;
        match Self::from_streams(reader, next.offset, streams, None, evidence)? {
            Some(result) => Ok(Some(result)),
            None if additional_member_only => Ok(Some(Self::MemberOnly)),
            None => additional_error.map_or(Ok(None), Err),
        }
    }

    fn additional_metadata_probe<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        before: u64,
        streams: &mut SevenZipStreams,
        names: Option<(usize, u64)>,
        evidence: &impl SevenZipEvidenceReads<R>,
    ) -> Result<Option<Self>, SevenZipMetadataError> {
        let Some(pack) = &streams.pack else { return Ok(None) };
        let mut first = 0;
        let mut candidates = Vec::new();
        for (index, folder) in streams.folders.iter().enumerate() {
            let end = first + folder.packed_streams.len();
            let Some(sizes) = pack.sizes.get(first..end) else { return Ok(None) };
            let metadata = if folder.expected_crc.is_some() {
                Some(SevenZipMetadata::Additional)
            } else {
                names.filter(|&(folder, _)| folder == index)
                    .map(|(_, count)| SevenZipMetadata::Names(count))
            };
            if let Some(metadata) = metadata.filter(|_| seven_zip_probe_folder_supported(folder)) {
                let (cycles, _, _) = folder.coders.iter()
                    .find(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
                    .and_then(|coder| seven_zip_aes_properties(&coder.properties))
                    .expect("supported encrypted folder");
                let size = sizes.iter().copied().fold(0u64, u64::saturating_add);
                let strong = folder.expected_crc.is_some();
                candidates.push((seven_zip_payload_cost(cycles, size, strong), index, first, metadata));
            }
            first = end;
        }
        candidates.sort_unstable_by_key(|&(cost, index, _, _)| (cost, index));
        for (_, index, first, metadata) in candidates {
            let folder = &streams.folders[index];
            match evidence.independent(reader, |reader| {
                read_seven_zip_packed_data(reader, reader_len, before, pack, folder, first)
            }) {
                Ok(packed) => {
                    let folder = streams.folders.remove(index);
                    return Ok(Some(Self::Header(SevenZipPasswordProbe::from_parts(
                        packed, folder, metadata,
                    ))));
                }
                Err(error) if error.starts_with("resource_unavailable:") => {
                    check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn from_streams<R: Read + Seek>(
        reader: &mut R,
        before: u64,
        streams: SevenZipStreams,
        metadata: Option<SevenZipMetadata>,
        evidence: &impl SevenZipEvidenceReads<R>,
    ) -> Result<Option<Self>, std::borrow::Cow<'static, str>> {
        if streams.folders.is_empty() && streams.pack.is_none() {
            return Ok(None);
        }
        let pack = streams
            .pack
            .as_ref()
            .ok_or("7z payload pack info is missing")?;
        if pack.num_streams != pack.sizes.len() {
            return Err("7z payload pack sizes are missing".into());
        }
        let mut pack_index = 0usize;
        let mut offset = (SEVEN_Z_HEADER_SIZE as u64)
            .checked_add(pack.pack_pos)
            .ok_or("7z payload pack offset overflow")?;
        let mut plans = Vec::new();
        for folder in &streams.folders {
            for &input in &folder.packed_streams {
                let size = *pack
                    .sizes
                    .get(pack_index)
                    .ok_or("7z payload pack stream count mismatch")?;
                let end = offset
                    .checked_add(size)
                    .ok_or("7z payload pack range overflow")?;
                if end > before {
                    return Err("7z payload pack range is unavailable".into());
                }
                let plain_header = matches!(metadata, Some(SevenZipMetadata::Header));
                if let Some(plan) = seven_zip_payload_plan(folder, input, offset, size, plain_header) {
                    let ambiguous = evidence.range_is_ambiguous(reader, plan.offset, 16);
                    plans.push((ambiguous, plan));
                }
                offset = end;
                pack_index += 1;
            }
        }
        if pack_index != pack.sizes.len() {
            return Err("7z payload pack stream count mismatch".into());
        }
        let encrypted = seven_zip_streams_encrypted(&streams);
        drop(streams);
        plans.sort_by_key(|(ambiguous, plan)| (!ambiguous, plan.cost));
        let mut first_error = None;
        let mut plans = plans.into_iter().map(|(_, plan)| plan);
        let mut first = None;
        while let Some(plan) = plans.next() {
            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
            match SevenZipPayloadProbe::load_plan(reader, before, plan, evidence) {
                Ok(probe) => {
                    first = Some(probe);
                    break;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
        }
        if let Some(first) = first {
            let source = evidence.payload_source(reader);
            let rest = if source.is_some() { plans.collect() } else { Vec::new() };
            return Ok(Some(Self::Prefix {
                probe: SevenZipPayloadProbes { first, rest, source },
                header: metadata.is_some(),
            }));
        }
        if !encrypted {
            return Ok(None);
        }
        first_error.map_or(Ok(Some(Self::MemberOnly)), Err)
    }
}

fn seven_zip_streams_encrypted(streams: &SevenZipStreams) -> bool {
    streams.folders.iter().any(|folder| {
        folder.coders.iter().any(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
    })
}

impl SevenZipPayloadProbe {
    fn load_plan<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        plan: SevenZipPayloadPlan,
        evidence: &impl SevenZipEvidenceReads<R>,
    ) -> Result<Self, std::borrow::Cow<'static, str>> {
        let mut encrypted = [0; 16];
        let read = |reader: &mut R, offset, bytes: &mut [u8]| -> std::io::Result<()> {
            let field = "7z.payload.evidence";
            seek_field(reader, offset, reader_len, field, FieldLocation::Body)
                .map_err(|fault| fault.into_io_error())?;
            read_exact_field(reader, bytes, reader_len, field, FieldLocation::Body)
                .map_err(|fault| fault.into_io_error())
        };
        evidence.independent(reader, |reader| read(reader, plan.offset, &mut encrypted))
            .map_err(resource_error)?;
        check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
        Ok(Self {
            offset: plan.offset,
            properties: plan.properties,
            inner_aes: plan.inner_aes,
            encrypted,
            kind: plan.kind,
        })
    }

}

// One shared graph walk for encrypted headers and data-only evidence. Copy
// nodes are transparent; no filter is mistaken for a compressed-stream start.
struct SevenZipAesStream {
    aes_index: usize,
    inner_aes: Vec<usize>,
    plaintext_size: u64,
    consumer: Option<(usize, u64)>,
}

fn seven_zip_aes_stream(
    folder: &SevenZipFolderAst,
    packed_input: u64,
    packed_size: u64,
) -> Option<SevenZipAesStream> {
    let mut input = packed_input;
    let mut aes_index = None;
    let mut inner_aes = Vec::new();
    let mut plaintext_size = 0;
    let mut input_size = packed_size;
    for _ in 0..folder.coders.len() {
        let mut input_base = 0;
        let mut output_base = 0;
        let (index, coder, output) =
            folder
                .coders
                .iter()
                .enumerate()
                .find_map(|(index, coder)| {
                    let found = (input == input_base
                        && coder.num_in_streams == 1
                        && coder.num_out_streams == 1)
                        .then_some((index, coder, output_base));
                    input_base += coder.num_in_streams;
                    output_base += coder.num_out_streams;
                    found
                })?;
        if coder.method_id == EncoderMethod::ID_AES256_SHA256 {
            if aes_index.is_some() {
                inner_aes.push(index);
            } else {
                aes_index = Some(index);
            }
            seven_zip_aes_properties(&coder.properties)?;
            plaintext_size = folder.unpack_size(output);
            if plaintext_size == 0 || input_size % 16 != 0 || plaintext_size > input_size {
                return None;
            }
        } else if coder.method_id == EncoderMethod::ID_COPY && coder.properties.is_empty() {
            if aes_index.is_some() {
                plaintext_size = plaintext_size.min(folder.unpack_size(output));
                if plaintext_size == 0 {
                    return None;
                }
            }
        } else {
            let aes_index = aes_index?;
            if !seven_zip_prefix_is_supported(&coder.method_id) {
                return None;
            }
            return Some(SevenZipAesStream {
                aes_index,
                inner_aes,
                plaintext_size,
                consumer: Some((index, folder.unpack_size(output))),
            });
        }
        if output == folder.main_output_stream {
            return Some(SevenZipAesStream {
                aes_index: aes_index?,
                inner_aes,
                plaintext_size,
                consumer: None,
            });
        }
        input_size = folder.unpack_size(output).min(input_size);
        input = folder
            .bind_pairs
            .iter()
            .find(|(_, upstream)| *upstream == output)?
            .0;
    }
    None
}

fn seven_zip_payload_plan(
    folder: &SevenZipFolderAst,
    packed_input: u64,
    offset: u64,
    packed_size: u64,
    header: bool,
) -> Option<SevenZipPayloadPlan> {
    let stream = seven_zip_aes_stream(folder, packed_input, packed_size)?;
    let aes = &folder.coders[stream.aes_index];
    let kind = SevenZipPayloadEvidence::from_stream(folder, &stream, header)?;
    let size = kind.plaintext_prefix_size().div_ceil(16) as u64 * 16;
    let strong = matches!(&kind, SevenZipPayloadEvidence::Compressed { method, .. } if seven_zip_prefix_is_strong(method));
    let cycles = seven_zip_aes_properties(&aes.properties)?.0;
    let mut cost = seven_zip_payload_cost(cycles, size, strong);
    let inner_aes = stream.inner_aes.iter().map(|&index| {
        let properties = &folder.coders[index].properties;
        let cycles = seven_zip_aes_properties(properties).unwrap().0;
        cost = cost.saturating_add(seven_zip_payload_cost(cycles, size, strong));
        properties.clone()
    }).collect();
    Some(SevenZipPayloadPlan {
        offset,
        properties: aes.properties.clone(),
        inner_aes,
        kind,
        cost,
    })
}

fn seven_zip_payload_cost(cycles: u8, bytes: u64, strong: bool) -> u64 {
    // Approximate KDF input bytes plus evidence bytes. Weak checks have a
    // small tie-break penalty for the additional worker probe.
    let kdf = if cycles == SEVEN_Z_AES_DIRECT_KEY {
        0
    } else {
        (1u64 << cycles) * 40
    };
    kdf.saturating_add(bytes)
        .saturating_add(if strong { 0 } else { 1024 })
}
