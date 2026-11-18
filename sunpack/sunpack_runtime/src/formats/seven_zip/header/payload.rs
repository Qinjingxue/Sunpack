// Data-only screening uses compressed-stream structure. Member CRC/MAC
// verification, including AES/Copy, belongs to the worker decoder.
pub(crate) struct SevenZipPayloadProbe {
    properties: Vec<u8>,
    encrypted: [u8; 32],
    encrypted_len: usize,
    kind: SevenZipPayloadEvidence,
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

    fn plaintext_prefix_size(&self) -> usize {
        match self {
            Self::Header { packed_size } => (*packed_size).min(16) as usize,
            Self::Compressed { method, packed_size, .. } => {
                (*packed_size).min(seven_zip_prefix_read_size(method)) as usize
            }
        }
    }

    fn check_encrypted_prefix(
        &self,
        encrypted: &[u8],
        material: &SevenZipAesKey,
    ) -> Result<SevenZipPrefixCheck, String> {
        check_password_cancellation()?;
        let len = self.plaintext_prefix_size().min(encrypted.len());
        if len == 0 {
            return Ok(SevenZipPrefixCheck::Weak);
        }
        let mut buffer = [0u8; 32];
        let prefix = &mut buffer[..len.div_ceil(16) * 16];
        let encrypted = &encrypted[..prefix.len()];
        prefix.copy_from_slice(encrypted);
        Aes256CbcDec::new(&material.key.into(), &material.iv.into())
            .decrypt_padded::<NoPadding>(prefix)
            .map_err(|_| "encoded_header_payload_crc_bad:aes_block_size".to_string())?;
        let prefix = &prefix[..len];
        Ok(match self {
            Self::Header { packed_size } => seven_zip_plain_header_prefix(prefix, *packed_size),
            Self::Compressed { method, packed_size, unpack_size } => {
                seven_zip_prefix_check(method, prefix, *packed_size, *unpack_size)
            }
        })
    }
}

struct SevenZipPayloadPlan {
    offset: u64,
    size: u64,
    properties: Vec<u8>,
    kind: SevenZipPayloadEvidence,
    cost: u64,
}

pub(crate) enum SevenZipPasswordContext {
    Header(SevenZipPasswordProbe),
    Prefix {
        probe: SevenZipPayloadProbe,
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
        if !enabled {
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
                if folder.expected_crc.is_some() && seven_zip_probe_folder_supported(&folder) {
                    match evidence.independent(reader, |reader| {
                        read_seven_zip_packed_data(reader, reader_len, next.offset, &pack, &folder)
                    }) {
                        Ok(packed) => {
                            return Ok(Some(Self::Header(SevenZipPasswordProbe::from_parts(
                                packed, folder,
                            ))))
                        }
                        Err(error) if error.starts_with("resource_unavailable:") => {
                            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                // A CRC-less header, or one that only the worker can fully
                // decode, may still expose a valid compressor or Header prefix.
                let streams = SevenZipStreams {
                    pack: Some(pack),
                    folders: vec![folder],
                };
                return Self::from_streams(reader, next.offset, streams, true, evidence);
            }
            let packed =
                read_seven_zip_packed_data(reader, reader_len, next.offset, &pack, &folder)?;
            let decoded = decode_seven_zip_encoded_folder(&packed, &folder, None)
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
        parse_seven_zip_header_with_data(&raw, &mut streams, true)?;
        drop(raw);
        Self::from_streams(reader, next.offset, streams, false, evidence)
    }

    fn from_streams<R: Read + Seek>(
        reader: &mut R,
        before: u64,
        streams: SevenZipStreams,
        header: bool,
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
                if let Some(expected) = pack.crcs.get(pack_index).copied().flatten() {
                    evidence.check_packed(reader, offset, size, expected)?;
                }
                if let Some(plan) = seven_zip_payload_plan(folder, input, offset, size, header) {
                    let ambiguous = evidence.range_is_ambiguous(reader, plan.offset, plan.size);
                    plans.push((ambiguous, plan));
                }
                offset = end;
                pack_index += 1;
            }
        }
        if pack_index != pack.sizes.len() {
            return Err("7z payload pack stream count mismatch".into());
        }
        if plans.is_empty()
            && !streams.folders.iter().any(|folder| {
                folder
                    .coders
                    .iter()
                    .any(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
            })
        {
            return Ok(None);
        }
        drop(streams);
        plans.sort_by_key(|(ambiguous, plan)| (!ambiguous, plan.cost));
        let mut first_error = None;
        for (_, plan) in plans {
            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
            match SevenZipPayloadProbe::load_plan(reader, before, plan, evidence) {
                Ok(probe) => return Ok(Some(Self::Prefix { probe, header })),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
            check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
        }
        Err(first_error.unwrap_or_else(|| "7z payload has no supported prescreen evidence".into()))
    }
}

impl SevenZipPayloadProbe {
    fn load_plan<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        plan: SevenZipPayloadPlan,
        evidence: &impl SevenZipEvidenceReads<R>,
    ) -> Result<Self, std::borrow::Cow<'static, str>> {
        let mut encrypted = [0; 32];
        let read = |reader: &mut R, offset, bytes: &mut [u8]| -> std::io::Result<()> {
            let field = "7z.payload.evidence";
            seek_field(reader, offset, reader_len, field, FieldLocation::Body)
                .map_err(|fault| fault.into_io_error())?;
            read_exact_field(reader, bytes, reader_len, field, FieldLocation::Body)
                .map_err(|fault| fault.into_io_error())
        };
        evidence.independent(reader, |reader| read(reader, plan.offset, &mut encrypted[..16]))
            .map_err(resource_error)?;
        let mut encrypted_len = 16;
        if plan.size == 32 {
            // Failure here leaves the first block and its volume projection
            // usable. Pending alternatives still replay in the shared reader.
            if evidence.independent(reader, |reader| {
                read(reader, plan.offset + 16, &mut encrypted[16..])
            }).is_ok() {
                encrypted_len = 32;
            }
        }
        check_password_cancellation().map_err(std::borrow::Cow::Owned)?;
        Ok(Self {
            properties: plan.properties,
            encrypted,
            encrypted_len,
            kind: plan.kind,
        })
    }

    pub(crate) fn key_properties(&self) -> &[u8] {
        &self.properties
    }

    pub(crate) fn test_with_key(
        &self,
        material: &SevenZipAesKey,
    ) -> Result<SevenZipPrefixCheck, String> {
        self.kind.check_encrypted_prefix(&self.encrypted[..self.encrypted_len], material)
    }
}

// One shared graph walk for encrypted headers and data-only evidence. Copy
// nodes are transparent; no filter is mistaken for a compressed-stream start.
struct SevenZipAesStream {
    aes_index: usize,
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
    let mut plaintext_size = 0;
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
                return None;
            }
            seven_zip_aes_properties(&coder.properties)?;
            aes_index = Some(index);
            plaintext_size = folder.unpack_size(output);
            if plaintext_size == 0 || packed_size % 16 != 0 || plaintext_size > packed_size {
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
                plaintext_size,
                consumer: Some((index, folder.unpack_size(output))),
            });
        }
        if output == folder.main_output_stream {
            return Some(SevenZipAesStream {
                aes_index: aes_index?,
                plaintext_size,
                consumer: None,
            });
        }
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
    Some(SevenZipPayloadPlan {
        offset,
        size,
        properties: aes.properties.clone(),
        kind,
        cost: seven_zip_payload_cost(cycles, size, strong),
    })
}

fn seven_zip_prefix_read_size(method: &[u8]) -> u64 {
    if matches!(method, [4, 1, 8] | [4, 1, 9]) {
        5
    } else {
        32
    }
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
