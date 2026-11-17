// Data-only evidence shares the header AST, AES/KDF and bounded spill storage.
// A survivor is never verified here: the worker still confirms it.
pub(crate) struct SevenZipPayloadProbe {
    properties: Vec<u8>,
    encrypted: Blob,
    iv_override: Option<[u8; 16]>,
    kind: SevenZipPayloadEvidence,
}

enum SevenZipPayloadEvidence {
    Prefix {
        coder: SevenZipCoderAst,
        unpack_size: u64,
        plaintext_size: usize,
    },
    Crc {
        skip: usize,
        size: u64,
        expected: u32,
    },
}

struct SevenZipPayloadPlan {
    offset: u64,
    size: u64,
    properties: Vec<u8>,
    preceding_block: bool,
    kind: SevenZipPayloadEvidence,
    cost: u64,
}

impl SevenZipPayloadProbe {
    pub(crate) fn from_header<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        start: &[u8; SEVEN_Z_HEADER_SIZE],
        next: RelationNextHeader,
    ) -> Result<Self, std::borrow::Cow<'static, str>> {
        if crc32(&start[12..32]) != u32_le(start, 8) {
            return Err("7z payload probe start header crc is invalid".into());
        }
        let raw = read_seven_zip_probe_range(
            reader,
            reader_len,
            next.offset,
            usize::try_from(next.size).map_err(|_| "7z payload header is too large")?,
            "7z.next_header",
            FieldLocation::Tail,
        )
        .map_err(resource_error)?;
        if crc32(&raw) != next.crc {
            return Err("7z payload probe next header crc is invalid".into());
        }
        let raw = if raw.first() == Some(&SZ_ENCODED_HEADER) {
            let (pack, folder) = parse_seven_zip_encoded_header_descriptor(&raw)?;
            if folder
                .coders
                .iter()
                .any(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
            {
                return Err("7z payload probe requires a readable header".into());
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
        let mut best: Option<SevenZipPayloadPlan> = None;
        for (folder_index, folder) in streams.folders.iter().enumerate() {
            for &input in &folder.packed_streams {
                let size = *pack
                    .sizes
                    .get(pack_index)
                    .ok_or("7z payload pack stream count mismatch")?;
                let end = offset
                    .checked_add(size)
                    .ok_or("7z payload pack range overflow")?;
                if end > next.offset || end > reader_len {
                    return Err("7z payload pack range is unavailable".into());
                }
                if let Some(plan) = seven_zip_payload_plan(
                    folder,
                    streams
                        .substreams
                        .get(folder_index)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                    input,
                    offset,
                    size,
                ) {
                    if best.as_ref().is_none_or(|old| plan.cost < old.cost) {
                        best = Some(plan);
                    }
                }
                offset = end;
                pack_index += 1;
            }
        }
        if pack_index != pack.sizes.len() {
            return Err("7z payload pack stream count mismatch".into());
        }
        let plan = best.ok_or("7z payload has no supported prescreen evidence")?;
        let mut iv_override = None;
        let mut read_offset = plan.offset;
        let mut read_size = plan.size;
        if plan.preceding_block {
            let mut iv = [0u8; 16];
            seek_field(
                reader,
                read_offset,
                reader_len,
                "7z.payload.iv",
                FieldLocation::Body,
            )
            .map_err(|fault| resource_error(fault.into_io_error()))?;
            read_exact_field(
                reader,
                &mut iv,
                reader_len,
                "7z.payload.iv",
                FieldLocation::Body,
            )
            .map_err(|fault| resource_error(fault.into_io_error()))?;
            iv_override = Some(iv);
            read_offset += 16;
            read_size -= 16;
        }
        let encrypted = read_seven_zip_probe_range(
            reader,
            reader_len,
            read_offset,
            usize::try_from(read_size).map_err(|_| "7z payload evidence is too large")?,
            "7z.payload.evidence",
            FieldLocation::Body,
        )
        .map_err(resource_error)?;
        Ok(Self {
            properties: plan.properties,
            encrypted,
            iv_override,
            kind: plan.kind,
        })
    }

    pub(crate) fn is_strong(&self) -> bool {
        match &self.kind {
            SevenZipPayloadEvidence::Prefix { coder, .. } => {
                seven_zip_prefix_is_strong(&coder.method_id)
            }
            SevenZipPayloadEvidence::Crc { size, .. } => *size >= 4,
        }
    }

    pub(crate) fn test(&self, password: &str) -> Result<SevenZipPrefixCheck, String> {
        check_password_cancellation()?;
        let password = Password::from(password);
        let (key, iv) = seven_zip_aes_key_iv_using(
            &self.properties,
            password.as_slice(),
            derive_seven_zip_aes_key,
        )?;
        let mut iv = self.iv_override.unwrap_or(iv);
        match &self.kind {
            SevenZipPayloadEvidence::Prefix {
                coder,
                unpack_size,
                plaintext_size,
            } => {
                let mut prefix = [0u8; 128];
                prefix[..self.encrypted.len()].copy_from_slice(&self.encrypted);
                Aes256CbcDec::new(&key.into(), &iv.into())
                    .decrypt_padded::<NoPadding>(&mut prefix[..self.encrypted.len()])
                    .map_err(|_| "7z payload AES block size is invalid".to_string())?;
                Ok(seven_zip_prefix_check(
                    &coder.method_id,
                    &coder.properties,
                    &prefix[..*plaintext_size],
                    *unpack_size,
                ))
            }
            SevenZipPayloadEvidence::Crc {
                skip,
                size,
                expected,
            } => {
                let mut hash = crc32fast::Hasher::new();
                let mut buffer =
                    crate::io::resource_error::zeroed_bytes(self.encrypted.len().min(64 * 1024))
                        .map_err(resource_error)?;
                let mut skip = *skip;
                let mut remaining = *size;
                for encrypted in self.encrypted.chunks(buffer.len()) {
                    check_password_cancellation()?;
                    buffer[..encrypted.len()].copy_from_slice(encrypted);
                    Aes256CbcDec::new(&key.into(), &iv.into())
                        .decrypt_padded::<NoPadding>(&mut buffer[..encrypted.len()])
                        .map_err(|_| "7z payload AES block size is invalid".to_string())?;
                    iv.copy_from_slice(&encrypted[encrypted.len() - 16..]);
                    let take = remaining.min((encrypted.len() - skip) as u64) as usize;
                    hash.update(&buffer[skip..skip + take]);
                    remaining -= take as u64;
                    skip = 0;
                }
                Ok(if hash.finalize() != *expected {
                    SevenZipPrefixCheck::Reject
                } else if *size >= 4 {
                    SevenZipPrefixCheck::Strong
                } else {
                    SevenZipPrefixCheck::Weak
                })
            }
        }
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
    substreams: &[SevenZipSubstreamAst],
    packed_input: u64,
    offset: u64,
    packed_size: u64,
) -> Option<SevenZipPayloadPlan> {
    let stream = seven_zip_aes_stream(folder, packed_input, packed_size)?;
    let aes = &folder.coders[stream.aes_index];
    let aes_size = stream.plaintext_size;
    if let Some((index, unpack_size)) = stream.consumer {
        let coder = &folder.coders[index];
        let strong = seven_zip_prefix_is_strong(&coder.method_id);
        // Deflate tree descriptions can extend beyond the first two AES
        // blocks. A slightly larger bounded prefix avoids cheap false
        // positives without allocating a decoder dictionary.
        let prefix_size = seven_zip_prefix_read_size(&coder.method_id);
        let plaintext_size = aes_size.min(prefix_size) as usize;
        let size = (plaintext_size as u64).div_ceil(16) * 16;
        let cycles = seven_zip_aes_properties(&aes.properties)?.0;
        return Some(SevenZipPayloadPlan {
            offset,
            size,
            properties: aes.properties.clone(),
            preceding_block: false,
            kind: SevenZipPayloadEvidence::Prefix {
                coder: coder.clone(),
                unpack_size: unpack_size,
                plaintext_size,
            },
            cost: seven_zip_payload_cost(cycles, size, strong),
        });
    }
    // No decompressor/filter intervened: a substream CRC is directly
    // on AES plaintext. CBC needs just the block before this range.
    let smallest = substreams
        .iter()
        .filter_map(|stream| {
            stream
                .crc
                .filter(|_| stream.size != 0)
                .map(|crc| (stream.offset, stream.size, crc))
        })
        .chain(
            folder
                .expected_crc
                .filter(|_| aes_size != 0)
                .map(|crc| (0, aes_size, crc)),
        )
        .min_by_key(|(start, size, _)| {
            (start % 16 + size).div_ceil(16) + u64::from(*start >= 16)
        })?;
    let (start, bytes, expected) = smallest;
    let end = start.checked_add(bytes)?;
    if end > aes_size {
        return None;
    }
    let first_block = start / 16 * 16;
    let preceding_block = first_block != 0;
    let read_start = first_block.saturating_sub(16);
    let read_end = end.div_ceil(16).checked_mul(16)?;
    if read_end > packed_size {
        return None;
    }
    let size = read_end - read_start;
    let cycles = seven_zip_aes_properties(&aes.properties)?.0;
    return Some(SevenZipPayloadPlan {
        offset: offset.checked_add(read_start)?,
        size,
        properties: aes.properties.clone(),
        preceding_block,
        kind: SevenZipPayloadEvidence::Crc {
            skip: (start - first_block) as usize,
            size: bytes,
            expected,
        },
        cost: seven_zip_payload_cost(cycles, size, bytes >= 4),
    });
}

fn seven_zip_prefix_read_size(method: &[u8]) -> u64 {
    if matches!(method, [4, 1, 8] | [4, 1, 9]) {
        128
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

#[cfg(test)]
mod payload_tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;

    #[test]
    fn copy_payload_uses_smallest_substream_and_cbc_predecessor() {
        // An unaligned one-byte final file must not decrypt the larger first
        // file. Nonzero salt/IV and nonzero padding detect wrong CBC ranges.
        let properties = [0xc1, 0x10, 9, 10, 11];
        let mut plaintext: Vec<u8> = (0..64).map(|index| index as u8 + 1).collect();
        let first_crc = crc32(&plaintext[..51]);
        let last_crc = crc32(&plaintext[51..52]);
        let password = Password::from("secret");
        let (key, iv) = seven_zip_aes_key_iv(&properties, password.as_slice()).unwrap();
        cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut plaintext, 64)
            .unwrap();
        let mut header = vec![
            SZ_HEADER,
            SZ_MAIN_STREAMS_INFO,
            SZ_PACK_INFO,
            0,
            1,
            SZ_SIZE,
            64,
            SZ_END,
            SZ_UNPACK_INFO,
            SZ_FOLDER,
            1,
            0,
            1,
            0x24,
        ];
        header.extend_from_slice(EncoderMethod::ID_AES256_SHA256);
        header.push(properties.len() as u8);
        header.extend_from_slice(&properties);
        header.extend([
            SZ_CODERS_UNPACK_SIZE,
            52,
            SZ_END,
            SZ_SUB_STREAMS_INFO,
            SZ_NUM_UNPACK_STREAM,
            2,
            SZ_SIZE,
            51,
            SZ_CRC,
            1,
        ]);
        header.extend(first_crc.to_le_bytes());
        header.extend(last_crc.to_le_bytes());
        header.extend([SZ_END, SZ_END, SZ_END]);
        let mut start = [0u8; SEVEN_Z_HEADER_SIZE];
        start[..SEVEN_Z_MAGIC.len()].copy_from_slice(SEVEN_Z_MAGIC);
        start[12..20].copy_from_slice(&64u64.to_le_bytes());
        start[20..28].copy_from_slice(&(header.len() as u64).to_le_bytes());
        start[28..32].copy_from_slice(&crc32(&header).to_le_bytes());
        let start_crc = crc32(&start[12..32]);
        start[8..12].copy_from_slice(&start_crc.to_le_bytes());
        let next = RelationNextHeader::checked_fields(&start).unwrap();
        let mut archive = start.to_vec();
        archive.extend(&plaintext);
        archive.extend(header);
        let probe = SevenZipPayloadProbe::from_header(
            &mut Cursor::new(&archive),
            archive.len() as u64,
            &start,
            next,
        )
        .unwrap();
        assert_eq!(probe.encrypted.len(), 16);
        assert_eq!(probe.iv_override.unwrap(), plaintext[32..48]);
        assert!(!probe.is_strong());
        assert_eq!(probe.test("secret").unwrap(), SevenZipPrefixCheck::Weak);
        assert_eq!(probe.test("wrong").unwrap(), SevenZipPrefixCheck::Reject);

        // The next folder is smaller and uses different AES parameters. The
        // selected packed offset and key must both belong to that folder.
        let second_properties = [0xc1, 0x10, 21, 22, 23];
        let mut second = [77u8; 16];
        let (key, iv) = seven_zip_aes_key_iv(&second_properties, password.as_slice()).unwrap();
        cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut second, 16)
            .unwrap();
        let mut header = vec![
            SZ_HEADER,
            SZ_MAIN_STREAMS_INFO,
            SZ_PACK_INFO,
            0,
            2,
            SZ_SIZE,
            64,
            16,
            SZ_END,
            SZ_UNPACK_INFO,
            SZ_FOLDER,
            2,
            0,
        ];
        for props in [&properties, &second_properties] {
            header.extend([1, 0x24]);
            header.extend_from_slice(EncoderMethod::ID_AES256_SHA256);
            header.push(props.len() as u8);
            header.extend(props);
        }
        header.extend([SZ_CODERS_UNPACK_SIZE, 52, 4, SZ_CRC, 1]);
        header.extend(crc32(&(1u8..=52).collect::<Vec<_>>()).to_le_bytes());
        header.extend(crc32(&[77; 4]).to_le_bytes());
        header.extend([SZ_END, SZ_END, SZ_END]);
        start[12..20].copy_from_slice(&80u64.to_le_bytes());
        start[20..28].copy_from_slice(&(header.len() as u64).to_le_bytes());
        start[28..32].copy_from_slice(&crc32(&header).to_le_bytes());
        let start_crc = crc32(&start[12..32]);
        start[8..12].copy_from_slice(&start_crc.to_le_bytes());
        let next = RelationNextHeader::checked_fields(&start).unwrap();
        let mut archive = start.to_vec();
        archive.extend(&plaintext);
        archive.extend(second);
        archive.extend(header);
        let probe = SevenZipPayloadProbe::from_header(
            &mut Cursor::new(&archive),
            archive.len() as u64,
            &start,
            next,
        )
        .unwrap();
        assert_eq!(probe.properties, second_properties);
        assert_eq!(probe.encrypted.as_ref(), &second);
        assert!(probe.is_strong());
        assert_eq!(probe.test("secret").unwrap(), SevenZipPrefixCheck::Strong);
        assert_eq!(probe.test("wrong").unwrap(), SevenZipPrefixCheck::Reject);
    }
}
