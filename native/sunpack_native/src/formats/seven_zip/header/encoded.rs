struct SevenZipEncodedHeaderCoder {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    num_in_streams: u64,
    num_out_streams: u64,
}

struct SevenZipEncodedHeaderFolder {
    coders: Vec<SevenZipEncodedHeaderCoder>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    main_output_stream: u64,
    unpack_size: u64,
    unpack_sizes: Vec<u64>,
    expected_crc: Option<u32>,
}

pub(crate) struct SevenZipPasswordProbe {
    packed_data: Vec<Vec<u8>>,
    folder: SevenZipEncodedHeaderFolder,
}

impl SevenZipPasswordProbe {
    pub(crate) fn from_reader(reader: &crate::io::reader::ManagedReader) -> Result<Self, String> {
        Self::from_seekable(&mut reader.cursor())
    }

    pub(crate) fn from_seekable<R: Read + Seek>(reader: &mut R) -> Result<Self, String> {
        const MAX_PROBE_HEADER_BYTES: usize = 64 * 1024 * 1024;

        let reader_len = reader
            .seek(std::io::SeekFrom::End(0))
            .map_err(|err| format!("7z password probe length read failed: {err}"))?;
        let start = read_seven_zip_probe_range(
            reader,
            reader_len,
            0,
            SEVEN_Z_HEADER_SIZE,
            "7z.start_header",
            FieldLocation::Head,
        )
        .map_err(|err| format!("7z password probe start header read failed: {err}"))?;
        if start.len() != SEVEN_Z_HEADER_SIZE || !start.starts_with(SEVEN_Z_MAGIC) || start[6] != 0
        {
            return Err("7z password probe signature or version is unsupported".to_string());
        }
        let stored_start_crc = u32_le(&start, 8);
        if crc32(&start[12..32]) != stored_start_crc {
            return Err("7z password probe start header crc is invalid".to_string());
        }
        let next_header_offset = u64_le(&start, 12);
        let next_header_size = usize::try_from(u64_le(&start, 20))
            .map_err(|_| "7z password probe next header is too large".to_string())?;
        if next_header_size == 0 || next_header_size > MAX_PROBE_HEADER_BYTES {
            return Err("7z password probe next header size is unsupported".to_string());
        }
        let next_header_start = (SEVEN_Z_HEADER_SIZE as u64)
            .checked_add(next_header_offset)
            .ok_or_else(|| "7z password probe next header offset overflow".to_string())?;
        let next_header_end = next_header_start
            .checked_add(next_header_size as u64)
            .ok_or_else(|| "7z password probe next header end overflow".to_string())?;
        if next_header_end > reader_len {
            return Err("7z password probe next header is truncated".to_string());
        }
        let raw = read_seven_zip_probe_range(
            reader,
            reader_len,
            next_header_start,
            next_header_size,
            "7z.next_header",
            FieldLocation::Tail,
        )
        .map_err(|err| format!("7z password probe next header read failed: {err}"))?;
        if crc32(&raw) != u32_le(&start, 28) {
            return Err("7z password probe next header crc is invalid".to_string());
        }
        let (pack, folder) = parse_seven_zip_encoded_header_descriptor(&raw)?;
        if folder.expected_crc.is_none() || !seven_zip_probe_folder_supported(&folder) {
            return Err("7z password probe coder graph has no safe fast path".to_string());
        }
        if pack.num_streams != pack.sizes.len() || pack.sizes.len() != folder.packed_streams.len() {
            return Err("7z password probe pack stream count mismatch".to_string());
        }
        let mut stream_start = (SEVEN_Z_HEADER_SIZE as u64)
            .checked_add(pack.pack_pos.value)
            .ok_or_else(|| "7z password probe stream offset overflow".to_string())?;
        let mut packed_data = Vec::with_capacity(pack.sizes.len());
        for size in &pack.sizes {
            let stream_end = stream_start
                .checked_add(size.value)
                .ok_or_else(|| "7z password probe stream end overflow".to_string())?;
            if stream_end > next_header_start || size.value > MAX_PROBE_HEADER_BYTES as u64 {
                return Err("7z password probe stream range is invalid".to_string());
            }
            let stream_size = usize::try_from(size.value)
                .map_err(|_| "7z password probe stream is too large".to_string())?;
            packed_data.push(
                read_seven_zip_probe_range(
                    reader,
                    reader_len,
                    stream_start,
                    stream_size,
                    "7z.encoded_header.packed_stream",
                    FieldLocation::Body,
                )
                .map_err(|err| format!("7z password probe stream read failed: {err}"))?,
            );
            stream_start = stream_end;
        }
        Ok(Self {
            packed_data,
            folder,
        })
    }

    pub(crate) fn decoded_header_if_password_matches(&self, password: &str) -> Option<Vec<u8>> {
        let decoded = match decode_seven_zip_encoded_folder(
            &self.packed_data,
            &self.folder,
            Some(password),
        ) {
            Ok(decoded) => decoded,
            Err(_) => return None,
        };
        (decoded.first().copied() == Some(SZ_HEADER)
            && self
                .folder
                .expected_crc
                .is_some_and(|expected| crc32(&decoded) == expected))
        .then_some(decoded)
    }
}

fn read_seven_zip_probe_range<R: Read + Seek>(
    reader: &mut R,
    source_len: u64,
    offset: u64,
    len: usize,
    field: &'static str,
    location: FieldLocation,
) -> std::io::Result<Vec<u8>> {
    seek_field(reader, offset, source_len, field, location)
        .map_err(|fault| fault.into_io_error())?;
    let mut output = vec![0u8; len];
    read_exact_field(reader, &mut output, source_len, field, location)
        .map_err(|fault| fault.into_io_error())?;
    Ok(output)
}

fn parse_seven_zip_encoded_header_descriptor(
    raw: &[u8],
) -> Result<(SevenZipPackInfoAst, SevenZipEncodedHeaderFolder), String> {
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("encoded_header_nid_missing".to_string());
    }
    pos += 1;
    let mut pack_info = None;
    let mut folder = None;
    let mut unpack_info = None;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return Err("encoded_header_tree_truncated".to_string());
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_PACK_INFO => pack_info = Some(parse_seven_zip_pack_info(raw, &mut pos)?),
            SZ_UNPACK_INFO => {
                let parsed = parse_seven_zip_unpack_info(raw, &mut pos)?;
                folder = Some(seven_zip_encoded_folder_from_unpack_info(&parsed)?);
                unpack_info = Some(parsed);
            }
            SZ_SUB_STREAMS_INFO => {
                let unpack = unpack_info
                    .as_ref()
                    .ok_or_else(|| "encoded_header_substreams_require_unpack_info".to_string())?;
                parse_seven_zip_substreams_info(raw, &mut pos, unpack)?;
            }
            _ => {
                return Err(format!(
                    "encoded_header_unsupported_streams_nid_0x{nid:02x}"
                ))
            }
        }
    }
    Ok((
        pack_info.ok_or_else(|| "encoded_header_pack_info_missing".to_string())?,
        folder.ok_or_else(|| "encoded_header_unpack_info_missing".to_string())?,
    ))
}

fn lzma2_dict_size(prop: u8) -> Option<u32> {
    let bits = u32::from(prop);
    if (bits & !0x3f) != 0 || bits > 40 {
        return None;
    }
    if bits == 40 {
        return Some(u32::MAX);
    }
    Some((2 | (bits & 1)) << (bits / 2 + 11))
}

fn decode_seven_zip_encoded_folder(
    packed_data: &[Vec<u8>],
    folder: &SevenZipEncodedHeaderFolder,
    password: Option<&str>,
) -> Result<Vec<u8>, String> {
    if folder.coders.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut visiting = vec![false; folder.coders.len()];
    decode_seven_zip_output(
        folder.main_output_stream,
        packed_data,
        folder,
        password,
        &mut visiting,
    )
}

fn decode_seven_zip_output(
    output_stream: u64,
    packed_data: &[Vec<u8>],
    folder: &SevenZipEncodedHeaderFolder,
    password: Option<&str>,
    visiting: &mut [bool],
) -> Result<Vec<u8>, String> {
    let mut input_base = 0u64;
    let mut output_base = 0u64;
    let mut owner = None;
    for (index, coder) in folder.coders.iter().enumerate() {
        if output_stream >= output_base && output_stream < output_base + coder.num_out_streams {
            owner = Some((index, input_base, output_base));
            break;
        }
        input_base = input_base
            .checked_add(coder.num_in_streams)
            .ok_or_else(|| "encoded_header_stream_count_overflow".to_string())?;
        output_base = output_base
            .checked_add(coder.num_out_streams)
            .ok_or_else(|| "encoded_header_stream_count_overflow".to_string())?;
    }
    let (coder_index, coder_input_base, coder_output_base) =
        owner.ok_or_else(|| "encoded_header_output_stream_unbound".to_string())?;
    let coder = &folder.coders[coder_index];
    if output_stream != coder_output_base || coder.num_out_streams != 1 {
        return Err("encoded_header_decoder_unsupported_multi_output_coder".to_string());
    }
    if visiting[coder_index] {
        return Err("encoded_header_bind_pair_cycle".to_string());
    }
    visiting[coder_index] = true;
    let mut inputs = Vec::with_capacity(usize::try_from(coder.num_in_streams).unwrap_or(0));
    for relative in 0..coder.num_in_streams {
        let input_stream = coder_input_base + relative;
        if let Some((_, upstream_output)) = folder
            .bind_pairs
            .iter()
            .find(|(input, _)| *input == input_stream)
        {
            inputs.push(decode_seven_zip_output(
                *upstream_output,
                packed_data,
                folder,
                password,
                visiting,
            )?);
        } else {
            let packed_index = folder
                .packed_streams
                .iter()
                .position(|stream| *stream == input_stream)
                .ok_or_else(|| "encoded_header_input_stream_unbound".to_string())?;
            inputs.push(
                packed_data
                    .get(packed_index)
                    .cloned()
                    .ok_or_else(|| "encoded_header_pack_stream_missing".to_string())?,
            );
        }
    }
    visiting[coder_index] = false;
    let unpack_size = folder
        .unpack_sizes
        .get(usize::try_from(output_stream).unwrap_or(usize::MAX))
        .copied()
        .unwrap_or(folder.unpack_size);
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ2 {
        if inputs.len() != 4 {
            return Err("encoded_header_bcj2_input_count_invalid".to_string());
        }
        let cursors = inputs.into_iter().map(Cursor::new).collect::<Vec<_>>();
        let mut reader = Bcj2Reader::new(cursors, unpack_size);
        let mut decoded = Vec::with_capacity(
            usize::try_from(unpack_size)
                .unwrap_or(0)
                .min(16 * 1024 * 1024),
        );
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    if inputs.len() != 1 {
        return Err("encoded_header_decoder_unsupported_multi_input_coder".to_string());
    }
    decode_seven_zip_encoded_coder(&inputs[0], coder, password, unpack_size)
}

fn decode_seven_zip_encoded_coder(
    data: &[u8],
    coder: &SevenZipEncodedHeaderCoder,
    password: Option<&str>,
    unpack_size: u64,
) -> Result<Vec<u8>, String> {
    const MAX_ENCODED_HEADER_UNPACK_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_ENCODED_HEADER_DICT_BYTES: u32 = 64 * 1024 * 1024;
    if unpack_size > MAX_ENCODED_HEADER_UNPACK_BYTES {
        return Err("encoded_header_decoder_unsupported_method:unpack_size_too_large".to_string());
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_COPY {
        return Ok(data.to_vec());
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_AES256_SHA256 {
        let mut decrypted = decrypt_seven_zip_aes256_sha256(data, &coder.properties, password)?;
        let unpack_size = usize::try_from(unpack_size)
            .map_err(|_| "encoded_header_decoder_unsupported_method".to_string())?;
        if decrypted.len() < unpack_size {
            return Err("encoded_header_payload_crc_bad:aes_unpack_size".to_string());
        }
        decrypted.truncate(unpack_size);
        return Ok(decrypted);
    }
    let compressed = Cursor::new(data.to_vec());
    let mut decoded = Vec::with_capacity(
        usize::try_from(unpack_size)
            .unwrap_or(0)
            .min(16 * 1024 * 1024),
    );
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA {
        if coder.properties.len() < 5 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        let dict_size = u32::from_le_bytes([
            coder.properties[1],
            coder.properties[2],
            coder.properties[3],
            coder.properties[4],
        ]);
        if dict_size > MAX_ENCODED_HEADER_DICT_BYTES {
            return Err(
                "encoded_header_decoder_unsupported_method:dictionary_too_large".to_string(),
            );
        }
        let mut reader = LzmaReader::new_with_props(
            compressed,
            unpack_size,
            coder.properties[0],
            dict_size,
            None,
        )
        .map_err(|err| format!("encoded_header_decoder_unsupported_method:{err}"))?;
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA2 {
        let Some(prop) = coder.properties.first().copied() else {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        };
        let dict_size = lzma2_dict_size(prop)
            .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
        if dict_size > MAX_ENCODED_HEADER_DICT_BYTES {
            return Err(
                "encoded_header_decoder_unsupported_method:dictionary_too_large".to_string(),
            );
        }
        let mut reader = Lzma2Reader::new(compressed, dict_size, None);
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    macro_rules! decode_bcj {
        ($constructor:expr) => {{
            let mut reader = $constructor;
            reader
                .read_to_end(&mut decoded)
                .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
            return Ok(decoded);
        }};
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_X86 {
        decode_bcj!(BcjReader::new_x86(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM {
        decode_bcj!(BcjReader::new_arm(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM64 {
        decode_bcj!(BcjReader::new_arm64(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM_THUMB {
        decode_bcj!(BcjReader::new_arm_thumb(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_PPC {
        decode_bcj!(BcjReader::new_ppc(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_IA64 {
        decode_bcj!(BcjReader::new_ia64(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_SPARC {
        decode_bcj!(BcjReader::new_sparc(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_RISCV {
        decode_bcj!(BcjReader::new_riscv(compressed, 0));
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_DELTA {
        let distance = coder
            .properties
            .first()
            .copied()
            .unwrap_or(0)
            .wrapping_add(1) as usize;
        let mut reader = DeltaReader::new(compressed, distance);
        reader
            .read_to_end(&mut decoded)
            .map_err(|err| format!("encoded_header_payload_crc_bad:{err}"))?;
        return Ok(decoded);
    }
    Err("encoded_header_decoder_unsupported_method".to_string())
}

fn decrypt_seven_zip_aes256_sha256(
    data: &[u8],
    properties: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>, String> {
    let Some(password) = password.filter(|value| !value.is_empty()) else {
        return Err("encoded_header_decode_password_required".to_string());
    };
    let password_bytes = seven_zip_password(Some(password));
    let (key, iv) = seven_zip_aes_key_iv(properties, password_bytes.as_slice())?;
    if data.len() % 16 != 0 {
        return Err("encoded_header_payload_crc_bad:aes_block_size".to_string());
    }
    let mut output = data.to_vec();
    let decrypted_len = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut output)
        .map_err(|_| "encoded_header_decode_password_rejected".to_string())?
        .len();
    output.truncate(decrypted_len);
    Ok(output)
}

fn seven_zip_aes_key_iv(
    properties: &[u8],
    password: &[u8],
) -> Result<([u8; 32], [u8; 16]), String> {
    if properties.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut expanded;
    let properties = if properties.len() == 1 {
        expanded = vec![0u8; 2];
        expanded[0] = properties[0];
        expanded.as_slice()
    } else {
        properties
    };
    let b0 = properties[0];
    let num_cycles_power = b0 & 63;
    let b1 = properties[1];
    let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 15));
    let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
    if 2 + salt_size + iv_size > properties.len() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let salt = &properties[2..2 + salt_size];
    let mut iv = [0u8; 16];
    iv[..iv_size].copy_from_slice(&properties[2 + salt_size..2 + salt_size + iv_size]);
    if password.is_empty() {
        return Err("encoded_header_decode_password_required".to_string());
    }
    let key = if num_cycles_power == 0x3f {
        let mut key = [0u8; 32];
        key[..salt_size].copy_from_slice(salt);
        let n = password.len().min(key.len().saturating_sub(salt_size));
        key[salt_size..salt_size + n].copy_from_slice(&password[..n]);
        key
    } else {
        let cycles = 1u32
            .checked_shl(u32::from(num_cycles_power))
            .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
        cached_seven_zip_aes_key(cycles, salt, password)
    };
    Ok((key, iv))
}

const SEVEN_ZIP_KDF_CACHE_CAPACITY: usize = 256;

#[derive(PartialEq, Eq)]
struct SevenZipKdfCacheParameters {
    cycles: u32,
    salt: Vec<u8>,
    password: Vec<u8>,
}

struct SevenZipKdfCacheEntry {
    parameters: SevenZipKdfCacheParameters,
    key: [u8; 32],
}

impl SevenZipKdfCacheEntry {
    fn wipe(&mut self) {
        self.parameters.password.fill(0);
        self.parameters.salt.fill(0);
        self.key.fill(0);
    }
}

impl Drop for SevenZipKdfCacheEntry {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn seven_zip_kdf_cache(
) -> &'static std::sync::Mutex<std::collections::VecDeque<SevenZipKdfCacheEntry>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::VecDeque<SevenZipKdfCacheEntry>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

fn cached_seven_zip_aes_key(cycles: u32, salt: &[u8], password: &[u8]) -> [u8; 32] {
    if std::env::var_os("SUNPACK_DISABLE_7Z_KDF_CACHE").is_some() {
        return derive_seven_zip_aes_key(cycles, salt, password);
    }
    let matches = |entry: &SevenZipKdfCacheEntry| {
        entry.parameters.cycles == cycles
            && entry.parameters.salt.as_slice() == salt
            && entry.parameters.password.as_slice() == password
    };
    {
        let mut cache = seven_zip_kdf_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = cache.iter().position(matches) {
            let entry = cache.remove(index).expect("located 7z KDF cache entry");
            let key = entry.key;
            cache.push_front(entry);
            return key;
        }
    }

    let key = derive_seven_zip_aes_key(cycles, salt, password);
    let mut cache = seven_zip_kdf_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = cache.iter().position(matches) {
        let entry = cache.remove(index).expect("located 7z KDF cache entry");
        let cached_key = entry.key;
        cache.push_front(entry);
        return cached_key;
    }
    if cache.len() >= SEVEN_ZIP_KDF_CACHE_CAPACITY {
        if let Some(mut evicted) = cache.pop_back() {
            evicted.wipe();
        }
    }
    let parameters = SevenZipKdfCacheParameters {
        cycles,
        salt: salt.to_vec(),
        password: password.to_vec(),
    };
    cache.push_front(SevenZipKdfCacheEntry { parameters, key });
    key
}

fn derive_seven_zip_aes_key(cycles: u32, salt: &[u8], password: &[u8]) -> [u8; 32] {
    const KDF_RECORDS_PER_UPDATE: usize = 64;
    let mut sha = sha2_11::Sha256::default();
    let record_len = salt.len() + password.len() + 8;
    let mut records = vec![0u8; record_len * KDF_RECORDS_PER_UPDATE];
    let mut counter = 0u64;
    while counter < u64::from(cycles) {
        let remaining = u64::from(cycles) - counter;
        let record_count = usize::try_from(remaining.min(KDF_RECORDS_PER_UPDATE as u64))
            .expect("7z KDF record count is bounded");
        for record_index in 0..record_count {
            let record = &mut records[record_index * record_len..(record_index + 1) * record_len];
            record[..salt.len()].copy_from_slice(salt);
            record[salt.len()..salt.len() + password.len()].copy_from_slice(password);
            record[record_len - 8..]
                .copy_from_slice(&(counter + record_index as u64).to_le_bytes());
        }
        sha2_11::Digest::update(&mut sha, &records[..record_count * record_len]);
        counter += record_count as u64;
    }
    sha2_11::Digest::finalize(sha).into()
}

fn seven_zip_encoded_folder_from_unpack_info(
    unpack: &SevenZipUnpackInfoAst,
) -> Result<SevenZipEncodedHeaderFolder, String> {
    let folder = unpack
        .folders
        .first()
        .ok_or_else(|| "encoded_header_folder_missing".to_string())?;
    if unpack.folders.len() != 1 {
        return Err("encoded_header_folder_not_unique".to_string());
    }
    Ok(SevenZipEncodedHeaderFolder {
        coders: folder
            .coders
            .iter()
            .map(|coder| SevenZipEncodedHeaderCoder {
                method_id: coder.method_id.clone(),
                properties: coder.properties.clone(),
                num_in_streams: coder.num_in_streams,
                num_out_streams: coder.num_out_streams,
            })
            .collect(),
        bind_pairs: folder.bind_pairs.clone(),
        packed_streams: folder.packed_streams.clone(),
        main_output_stream: folder.main_output_stream,
        unpack_size: folder.unpack_size,
        unpack_sizes: folder.unpack_sizes.iter().map(|span| span.value).collect(),
        expected_crc: folder.expected_crc.map(|crc| crc.value),
    })
}

fn seven_zip_probe_folder_supported(folder: &SevenZipEncodedHeaderFolder) -> bool {
    let mut aes_count = 0usize;
    for coder in &folder.coders {
        let method = coder.method_id.as_slice();
        if method == EncoderMethod::ID_AES256_SHA256 {
            aes_count += 1;
            if coder.properties.is_empty() || (coder.properties[0] & 63) > 24 {
                return false;
            }
        } else if method == EncoderMethod::ID_COPY {
        } else if method == EncoderMethod::ID_LZMA {
            if coder.properties.len() < 5 {
                return false;
            }
            let dictionary = u32::from_le_bytes([
                coder.properties[1],
                coder.properties[2],
                coder.properties[3],
                coder.properties[4],
            ]);
            if dictionary > 64 * 1024 * 1024 {
                return false;
            }
        } else if method == EncoderMethod::ID_LZMA2 {
            if coder
                .properties
                .first()
                .and_then(|value| lzma2_dict_size(*value))
                .is_none_or(|dictionary| dictionary > 64 * 1024 * 1024)
            {
                return false;
            }
        } else if method != EncoderMethod::ID_BCJ_X86
            && method != EncoderMethod::ID_BCJ_ARM
            && method != EncoderMethod::ID_BCJ_ARM64
            && method != EncoderMethod::ID_BCJ_ARM_THUMB
            && method != EncoderMethod::ID_BCJ_PPC
            && method != EncoderMethod::ID_BCJ_IA64
            && method != EncoderMethod::ID_BCJ_SPARC
            && method != EncoderMethod::ID_BCJ_RISCV
            && method != EncoderMethod::ID_DELTA
            && method != EncoderMethod::ID_BCJ2
        {
            return false;
        }
    }
    aes_count == 1 && folder.unpack_size <= 64 * 1024 * 1024
}

#[cfg(any())]
fn parse_seven_zip_encoded_header_folder_legacy(
    data: &[u8],
    pos: &mut usize,
) -> Result<
    (
        Vec<SevenZipEncodedHeaderCoder>,
        u64,
        Vec<(u64, u64)>,
        Vec<u64>,
        u64,
    ),
    String,
> {
    let num_folders = read_sz_vint(data, pos)
        .ok_or_else(|| "encoded_header_folder_count_truncated".to_string())?
        .value;
    if num_folders != 1 {
        return Err("encoded_header_folder_not_unique".to_string());
    }
    let external = *data
        .get(*pos)
        .ok_or_else(|| "encoded_header_folder_external_flag_missing".to_string())?;
    *pos += 1;
    if external != 0 {
        return Err("encoded_header_external_folder_unsupported".to_string());
    }
    let num_coders = read_sz_vint(data, pos)
        .ok_or_else(|| "encoded_header_coder_count_truncated".to_string())?
        .value;
    if num_coders == 0 || num_coders > 64 {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut output = Vec::with_capacity(usize::try_from(num_coders).unwrap_or(0));
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flags = *data
            .get(*pos)
            .ok_or_else(|| "encoded_header_coder_flags_missing".to_string())?;
        *pos += 1;
        let id_size = usize::from(flags & 0x0f);
        if id_size == 0 || *pos + id_size > data.len() {
            return Err("encoded_header_coder_id_truncated".to_string());
        }
        let method_id = data[*pos..*pos + id_size].to_vec();
        *pos += id_size;
        let (num_in_streams, num_out_streams) = if flags & 0x10 != 0 {
            let in_streams = read_sz_vint(data, pos)
                .ok_or_else(|| "encoded_header_coder_in_streams_truncated".to_string())?
                .value;
            let out_streams = read_sz_vint(data, pos)
                .ok_or_else(|| "encoded_header_coder_out_streams_truncated".to_string())?
                .value;
            (in_streams, out_streams)
        } else {
            (1, 1)
        };
        total_in = total_in.saturating_add(num_in_streams);
        total_out = total_out.saturating_add(num_out_streams);
        let mut properties = Vec::new();
        if flags & 0x20 != 0 {
            let prop_size = usize::try_from(
                read_sz_vint(data, pos)
                    .ok_or_else(|| "encoded_header_coder_properties_size_truncated".to_string())?
                    .value,
            )
            .unwrap_or(usize::MAX);
            if *pos + prop_size > data.len() {
                return Err("encoded_header_coder_properties_truncated".to_string());
            }
            properties.extend_from_slice(&data[*pos..*pos + prop_size]);
            *pos += prop_size;
        }
        if flags & 0xc0 != 0 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        output.push(SevenZipEncodedHeaderCoder {
            method_id,
            properties,
            num_in_streams,
            num_out_streams,
        });
    }
    if total_in == 0 || total_out == 0 || total_in < total_out.saturating_sub(1) {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let num_bind_pairs = total_out.saturating_sub(1);
    let mut bind_pairs = Vec::with_capacity(usize::try_from(num_bind_pairs).unwrap_or(0));
    for _ in 0..num_bind_pairs {
        let input = read_sz_vint(data, pos)
            .ok_or_else(|| "encoded_header_bind_pair_in_truncated".to_string())?
            .value;
        let output_stream = read_sz_vint(data, pos)
            .ok_or_else(|| "encoded_header_bind_pair_out_truncated".to_string())?
            .value;
        if input >= total_in
            || output_stream >= total_out
            || bind_pairs.iter().any(|(existing_input, existing_output)| {
                *existing_input == input || *existing_output == output_stream
            })
        {
            return Err("encoded_header_bind_pair_invalid".to_string());
        }
        bind_pairs.push((input, output_stream));
    }
    let num_packed_streams = total_in.saturating_sub(num_bind_pairs);
    if num_packed_streams == 0 {
        return Err("encoded_header_pack_stream_missing".to_string());
    }
    let mut packed_streams = Vec::with_capacity(usize::try_from(num_packed_streams).unwrap_or(0));
    if num_packed_streams == 1 {
        let input = (0..total_in)
            .find(|candidate| !bind_pairs.iter().any(|(bound, _)| bound == candidate))
            .ok_or_else(|| "encoded_header_pack_stream_missing".to_string())?;
        packed_streams.push(input);
    } else {
        for _ in 0..num_packed_streams {
            let input = read_sz_vint(data, pos)
                .ok_or_else(|| "encoded_header_packed_stream_truncated".to_string())?
                .value;
            if input >= total_in
                || bind_pairs.iter().any(|(bound, _)| *bound == input)
                || packed_streams.contains(&input)
            {
                return Err("encoded_header_pack_stream_invalid".to_string());
            }
            packed_streams.push(input);
        }
    }
    let main_output_stream = (0..total_out)
        .find(|candidate| !bind_pairs.iter().any(|(_, bound)| bound == candidate))
        .ok_or_else(|| "encoded_header_main_output_missing".to_string())?;
    Ok((
        output,
        total_out,
        bind_pairs,
        packed_streams,
        main_output_stream,
    ))
}

#[cfg(test)]
mod encoded_folder_graph_tests {
    use super::*;

    fn reference_aes_key(properties: &[u8], password: &[u8]) -> [u8; 32] {
        let b0 = properties[0];
        let b1 = properties.get(1).copied().unwrap_or(0);
        let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
        let salt = properties.get(2..2 + salt_size).unwrap_or_default();
        let mut sha = sha2_11::Sha256::default();
        for counter in 0..(1u64 << (b0 & 63)) {
            sha2_11::Digest::update(&mut sha, salt);
            sha2_11::Digest::update(&mut sha, password);
            sha2_11::Digest::update(&mut sha, counter.to_le_bytes());
        }
        sha2_11::Digest::finalize(sha).into()
    }

    #[test]
    fn specialized_7z_kdf_matches_record_by_record_oracle() {
        let password = b"p\0a\0s\0s\0";
        for cycles_power in [0u8, 1, 6, 10] {
            let no_salt = [cycles_power];
            assert_eq!(
                seven_zip_aes_key_iv(&no_salt, password).unwrap().0,
                reference_aes_key(&no_salt, password)
            );

            let with_salt_and_iv = [cycles_power | 0xc0, 0x12, 0x11, 0x22, 0x31, 0x32, 0x33];
            assert_eq!(
                seven_zip_aes_key_iv(&with_salt_and_iv, password).unwrap().0,
                reference_aes_key(&with_salt_and_iv, password)
            );
        }
    }

    #[test]
    fn seven_zip_kdf_cache_is_bounded_and_preserves_keys() {
        seven_zip_kdf_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        for index in 0..SEVEN_ZIP_KDF_CACHE_CAPACITY + 17 {
            let password = format!("cache-password-{index}").into_bytes();
            assert_eq!(
                cached_seven_zip_aes_key(4, b"salt", &password),
                derive_seven_zip_aes_key(4, b"salt", &password)
            );
        }
        assert_eq!(
            seven_zip_kdf_cache()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            SEVEN_ZIP_KDF_CACHE_CAPACITY
        );
    }

    #[test]
    fn decoder_follows_bind_pairs_instead_of_coder_declaration_order() {
        let copy = || SevenZipEncodedHeaderCoder {
            method_id: EncoderMethod::ID_COPY.to_vec(),
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        };
        // Packed input stream 1 -> coder 1/out 1 -> coder 2/in 2 ->
        // coder 2/out 2 -> coder 0/in 0 -> main output 0.
        let folder = SevenZipEncodedHeaderFolder {
            coders: vec![copy(), copy(), copy()],
            bind_pairs: vec![(2, 1), (0, 2)],
            packed_streams: vec![1],
            main_output_stream: 0,
            unpack_size: 4,
            unpack_sizes: vec![4, 4, 4],
            expected_crc: None,
        };
        let decoded = decode_seven_zip_encoded_folder(&[b"test".to_vec()], &folder, None).unwrap();
        assert_eq!(decoded, b"test");
    }

    #[test]
    fn decoder_rejects_bind_pair_cycles() {
        let copy = SevenZipEncodedHeaderCoder {
            method_id: EncoderMethod::ID_COPY.to_vec(),
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        };
        let folder = SevenZipEncodedHeaderFolder {
            coders: vec![copy],
            bind_pairs: vec![(0, 0)],
            packed_streams: Vec::new(),
            main_output_stream: 0,
            unpack_size: 1,
            unpack_sizes: vec![1],
            expected_crc: None,
        };
        let error = decode_seven_zip_encoded_folder(&[], &folder, None).unwrap_err();
        assert_eq!(error, "encoded_header_bind_pair_cycle");
    }
}
