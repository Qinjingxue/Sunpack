use crate::io::scratch::{Blob, Spool};
use std::io::Write;

enum CoderInput<'a> {
    Borrowed(&'a [u8]),
    Owned(Blob),
}
impl AsRef<[u8]> for CoderInput<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(blob) => blob,
        }
    }
}

pub(crate) struct SevenZipPasswordProbe {
    packed_data: Vec<Blob>,
    folder: SevenZipFolderAst,
    aes_index: usize,
    prefix: Option<(usize, SevenZipAesStream)>,
}

impl SevenZipPasswordProbe {
    fn from_parts(packed_data: Vec<Blob>, folder: SevenZipFolderAst) -> Self {
        let aes_index = folder
            .coders
            .iter()
            .position(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
            .expect("supported encrypted folder");
        let prefix = folder
            .packed_streams
            .iter()
            .enumerate()
            .find_map(|(index, &input)| {
                seven_zip_aes_stream(&folder, input, packed_data[index].len() as u64)
                    .map(|stream| (index, stream))
            });
        Self {
            packed_data,
            folder,
            aes_index,
            prefix,
        }
    }

    pub(crate) fn key_properties(&self) -> &[u8] {
        &self.folder.coders[self.aes_index].properties
    }

    pub(crate) fn check_header(&self, key: &SevenZipAesKey) -> Result<bool, String> {
        if let Some((packed, stream)) = &self.prefix {
            if !seven_zip_header_prefix_matches(
                &self.packed_data[*packed],
                &self.folder,
                stream,
                key,
            )? {
                return Ok(false);
            }
        }
        let decoded = match decode_seven_zip_encoded_folder_with_key(
            &self.packed_data,
            &self.folder,
            None,
            Some((self.aes_index, key)),
        ) {
            Ok(decoded) => decoded,
            Err(error) if error.starts_with("resource_unavailable:") => return Err(error),
            Err(_) => return Ok(false),
        };
        Ok(decoded.first().copied() == Some(SZ_HEADER)
            && self
                .folder
                .expected_crc
                .is_some_and(|expected| crc32(&decoded) == expected))
    }
}

pub(crate) struct SevenZipAesKey {
    key: [u8; 32],
    iv: [u8; 16],
}
impl SevenZipAesKey {
    pub(crate) fn with_iv(&self, bytes: &[u8]) -> Self {
        let mut iv = [0; 16];
        iv[..bytes.len()].copy_from_slice(bytes);
        Self { key: self.key, iv }
    }

    pub(crate) fn derive(properties: &[u8], password: &str) -> Result<Self, String> {
        let bytes = Password::from(password);
        let (key, iv) = seven_zip_aes_key_iv(properties, bytes.as_slice())?;
        Ok(Self { key, iv })
    }
}

impl Drop for SevenZipAesKey {
    fn drop(&mut self) {
        self.key.fill(0);
        self.iv.fill(0);
    }
}

fn seven_zip_header_prefix_matches(
    encrypted: &[u8],
    folder: &SevenZipFolderAst,
    stream: &SevenZipAesStream,
    key: &SevenZipAesKey,
) -> Result<bool, String> {
    let limit = stream.consumer.map_or(16, |(index, _)| {
        seven_zip_prefix_read_size(&folder.coders[index].method_id)
    });
    let len = stream.plaintext_size.min(limit) as usize;
    let encrypted_len = len.div_ceil(16) * 16;
    let Some(encrypted) = encrypted.get(..encrypted_len) else {
        return Ok(true);
    };
    let mut prefix = [0u8; 128];
    prefix[..encrypted_len].copy_from_slice(encrypted);
    Aes256CbcDec::new(&key.key.into(), &key.iv.into())
        .decrypt_padded::<NoPadding>(&mut prefix[..encrypted_len])
        .map_err(|_| "encoded_header_payload_crc_bad:aes_block_size".to_string())?;
    Ok(match stream.consumer {
        Some((index, unpack_size)) => {
            let coder = &folder.coders[index];
            seven_zip_prefix_check(
                &coder.method_id,
                &coder.properties,
                &prefix[..len],
                unpack_size,
            ) != SevenZipPrefixCheck::Reject
        }
        None => prefix.first() == Some(&SZ_HEADER),
    })
}

fn read_seven_zip_packed_data<R: Read + Seek>(
    reader: &mut R,
    reader_len: u64,
    before: u64,
    pack: &SevenZipPackInfoAst,
    folder: &SevenZipFolderAst,
) -> Result<Vec<Blob>, std::borrow::Cow<'static, str>> {
    if pack.num_streams != pack.sizes.len() || pack.sizes.len() != folder.packed_streams.len() {
        return Err("7z password probe pack stream count mismatch".into());
    }
    let mut stream_start = (SEVEN_Z_HEADER_SIZE as u64)
        .checked_add(pack.pack_pos)
        .ok_or("7z password probe stream offset overflow")?;
    let mut packed_data = Vec::with_capacity(pack.sizes.len());
    for (index, &size) in pack.sizes.iter().enumerate() {
        let stream_end = stream_start
            .checked_add(size)
            .ok_or("7z password probe stream end overflow")?;
        if stream_end > before {
            return Err("7z password probe stream range is invalid".into());
        }
        let stream_size =
            usize::try_from(size).map_err(|_| "7z password probe stream is too large")?;
        packed_data.push(
            read_seven_zip_probe_range(
                reader,
                reader_len,
                stream_start,
                stream_size,
                "7z.encoded_header.packed_stream",
                FieldLocation::Body,
            )
            .map_err(resource_error)?,
        );
        if pack
            .crcs
            .get(index)
            .copied()
            .flatten()
            .is_some_and(|expected| crc32(packed_data.last().unwrap()) != expected)
        {
            return Err("7z packed stream crc mismatch".into());
        }
        stream_start = stream_end;
    }
    Ok(packed_data)
}

fn read_seven_zip_probe_range<R: Read + Seek>(
    reader: &mut R,
    source_len: u64,
    offset: u64,
    len: usize,
    field: &'static str,
    location: FieldLocation,
) -> std::io::Result<Blob> {
    seek_field(reader, offset, source_len, field, location)
        .map_err(|fault| fault.into_io_error())?;
    if len <= crate::io::scratch::MEMORY_BYTES {
        let mut bytes = crate::io::resource_error::zeroed_bytes(len)?;
        read_exact_field(reader, &mut bytes, source_len, field, location)
            .map_err(|fault| fault.into_io_error())?;
        return Ok(bytes.into());
    }
    let mut output = Spool::default();
    output.spill()?;
    let mut remaining = len;
    let mut bytes = vec![0; 64 * 1024];
    while remaining > 0 {
        crate::io::cancellation::Cancellation::check_current_io()?;
        let take = remaining.min(bytes.len());
        read_exact_field(reader, &mut bytes[..take], source_len, field, location)
            .map_err(|fault| fault.into_io_error())?;
        output.write_all(&bytes[..take])?;
        remaining -= take;
    }
    output.finish()
}

fn parse_seven_zip_encoded_header_descriptor(
    raw: &[u8],
) -> Result<(SevenZipPackInfoAst, SevenZipFolderAst), &'static str> {
    if raw.first() != Some(&SZ_ENCODED_HEADER) {
        return Err("encoded_header_nid_missing");
    }
    let mut pos = 1;
    let mut streams = SevenZipStreams::default();
    parse_seven_zip_streams_info(raw, &mut pos, &mut streams, true)?;
    if streams.folders.len() != 1 {
        return Err("encoded_header_folder_not_unique");
    }
    Ok((
        streams.pack.ok_or("encoded_header_pack_info_missing")?,
        streams
            .folders
            .pop()
            .ok_or("encoded_header_unpack_info_missing")?,
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
    packed_data: &[Blob],
    folder: &SevenZipFolderAst,
    password: Option<&str>,
) -> Result<Blob, String> {
    decode_seven_zip_encoded_folder_with_key(packed_data, folder, password, None)
}

fn decode_seven_zip_encoded_folder_with_key(
    packed_data: &[Blob],
    folder: &SevenZipFolderAst,
    password: Option<&str>,
    key: Option<(usize, &SevenZipAesKey)>,
) -> Result<Blob, String> {
    if folder.coders.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut visiting = [false; SEVEN_Z_MAX_FOLDER_CODERS];
    decode_seven_zip_output(
        folder.main_output_stream,
        packed_data,
        folder,
        password,
        key,
        &mut visiting,
    )
}

fn decode_seven_zip_output(
    output_stream: u64,
    packed_data: &[Blob],
    folder: &SevenZipFolderAst,
    password: Option<&str>,
    key: Option<(usize, &SevenZipAesKey)>,
    visiting: &mut [bool],
) -> Result<Blob, String> {
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
    let mut read_input = |relative| {
        let input_stream = coder_input_base + relative;
        if let Some((_, upstream_output)) = folder
            .bind_pairs
            .iter()
            .find(|(input, _)| *input == input_stream)
        {
            decode_seven_zip_output(
                *upstream_output,
                packed_data,
                folder,
                password,
                key,
                visiting,
            )
            .map(CoderInput::Owned)
        } else {
            let packed_index = folder
                .packed_streams
                .iter()
                .position(|stream| *stream == input_stream)
                .ok_or_else(|| "encoded_header_input_stream_unbound".to_string())?;
            packed_data
                .get(packed_index)
                .map(|data| CoderInput::Borrowed(data))
                .ok_or_else(|| "encoded_header_pack_stream_missing".to_string())
        }
    };
    let unpack_size = folder.unpack_size(output_stream);
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ2 {
        if coder.num_in_streams != 4 {
            return Err("encoded_header_bcj2_input_count_invalid".to_string());
        }
        let cursors = (0..4)
            .map(|index| read_input(index).map(Cursor::new))
            .collect::<Result<Vec<_>, _>>()?;
        visiting[coder_index] = false;
        return collect_decoded(Bcj2Reader::new(cursors, unpack_size), unpack_size);
    }
    if coder.num_in_streams != 1 {
        return Err("encoded_header_decoder_unsupported_multi_input_coder".to_string());
    }
    let input = read_input(0)?;
    visiting[coder_index] = false;
    if let Some((index, key)) = key.filter(|(index, _)| *index == coder_index) {
        debug_assert_eq!(
            folder.coders[index].method_id,
            EncoderMethod::ID_AES256_SHA256
        );
        return decrypt_seven_zip_aes_with_key(input.as_ref(), key, unpack_size);
    }
    decode_seven_zip_encoded_coder(input, coder, password, unpack_size)
}

fn seven_zip_bcj_start_pos(coder: &SevenZipCoderAst) -> Result<usize, String> {
    let method = coder.method_id.as_slice();
    let alignment = if method == EncoderMethod::ID_BCJ_ARM64 {
        3
    } else if method == EncoderMethod::ID_BCJ_RISCV {
        1
    } else if [
        EncoderMethod::ID_BCJ_X86,
        EncoderMethod::ID_BCJ_ARM,
        EncoderMethod::ID_BCJ_ARM_THUMB,
        EncoderMethod::ID_BCJ_PPC,
        EncoderMethod::ID_BCJ_IA64,
        EncoderMethod::ID_BCJ_SPARC,
    ]
    .contains(&method)
        && coder.properties.is_empty()
    {
        return Ok(0);
    } else {
        return Err("encoded_header_decoder_unsupported_method:bcj_properties".to_string());
    };
    let start = match coder.properties.as_slice() {
        [] => 0,
        [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
        _ => return Err("encoded_header_decoder_unsupported_method:bcj_properties".to_string()),
    };
    if start & alignment != 0 {
        return Err("encoded_header_decoder_unsupported_method:bcj_alignment".to_string());
    }
    Ok(start as usize)
}

fn decode_seven_zip_encoded_coder(
    data: CoderInput<'_>,
    coder: &SevenZipCoderAst,
    password: Option<&str>,
    unpack_size: u64,
) -> Result<Blob, String> {
    if coder.method_id.as_slice() == EncoderMethod::ID_COPY {
        return collect_decoded(Cursor::new(data), unpack_size);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_AES256_SHA256 {
        return decrypt_seven_zip_aes256_sha256(
            data.as_ref(),
            &coder.properties,
            password,
            unpack_size,
        );
    }
    if coder.method_id.as_slice() == [0x04, 0xf7, 0x11, 0x04] {
        if coder.properties.len() != 5 {
            return Err("encoded_header_decoder_unsupported_method:lz4_properties".into());
        }
        let mut output = Spool::default();
        crate::formats::lz4::decode_into(
            Cursor::new(data),
            &mut ExactOutput {
                output: &mut output,
                remaining: unpack_size,
            },
        )
        .map_err(decode_error)?;
        let output = output.finish().map_err(resource_error)?;
        if output.len() as u64 != unpack_size {
            return Err("encoded_header_payload_crc_bad:lz4_unpack_size".into());
        }
        return Ok(output);
    }
    if matches!(coder.method_id.as_slice(), method if method == EncoderMethod::ID_LZMA || method == EncoderMethod::ID_LZMA2)
    {
        return decode_lzma(data.as_ref(), coder, unpack_size);
    }
    let compressed = Cursor::new(data);
    macro_rules! decode_bcj {
        ($constructor:path) => {{
            return collect_decoded(
                $constructor(compressed, seven_zip_bcj_start_pos(coder)?),
                unpack_size,
            );
        }};
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_X86 {
        decode_bcj!(BcjReader::new_x86);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM {
        decode_bcj!(BcjReader::new_arm);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM64 {
        decode_bcj!(BcjReader::new_arm64);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_ARM_THUMB {
        decode_bcj!(BcjReader::new_arm_thumb);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_PPC {
        decode_bcj!(BcjReader::new_ppc);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_IA64 {
        decode_bcj!(BcjReader::new_ia64);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_SPARC {
        decode_bcj!(BcjReader::new_sparc);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_BCJ_RISCV {
        decode_bcj!(BcjReader::new_riscv);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_DELTA {
        let [distance] = coder.properties.as_slice() else {
            return Err("encoded_header_decoder_unsupported_method:delta_properties".to_string());
        };
        let distance = usize::from(*distance) + 1;
        return collect_decoded(DeltaReader::new(compressed, distance), unpack_size);
    }
    Err("encoded_header_decoder_unsupported_method".to_string())
}

fn resource_error(error: impl std::fmt::Display) -> String {
    format!("resource_unavailable:{error}")
}
fn decode_error(error: std::io::Error) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
    ) {
        format!("encoded_header_payload_crc_bad:{error}")
    } else {
        resource_error(error)
    }
}
struct ExactOutput<'a> {
    output: &'a mut Spool,
    remaining: u64,
}
impl Write for ExactOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if crate::io::cancellation::Cancellation::current().cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "password probe cancelled",
            ));
        }
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoded size exceeds declared size",
            ));
        }
        self.output.write_all(bytes)?;
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}
// These decoders read immutable memory/mappings, not source files. Some use
// ErrorKind::Other for invalid compressed bytes (e.g. LZMA distance overflow).
// Normalize only decoder reads; spool writes must retain their resource errors.
struct DecoderReader<R>(R);
impl<R: Read> Read for DecoderReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::Other
                && error.raw_os_error().is_none()
                && !crate::io::resource_error::is_memory_error(&error)
            {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
            } else {
                error
            }
        })
    }
}
fn collect_decoded(reader: impl Read, size: u64) -> Result<Blob, String> {
    let mut output = Spool::default();
    std::io::copy(
        &mut DecoderReader(reader).take(size.saturating_add(1)),
        &mut ExactOutput {
            output: &mut output,
            remaining: size,
        },
    )
    .map_err(decode_error)?;
    let output = output.finish().map_err(resource_error)?;
    if output.len() as u64 != size {
        return Err("encoded_header_payload_crc_bad:unpack_size".into());
    }
    Ok(output)
}
fn decrypt_seven_zip_aes256_sha256(
    data: &[u8],
    properties: &[u8],
    password: Option<&str>,
    unpack_size: u64,
) -> Result<Blob, String> {
    let Some(password) = password.filter(|value| !value.is_empty()) else {
        return Err("encoded_header_decode_password_required".into());
    };
    let password_bytes = Password::from(password);
    let (key, iv) = seven_zip_aes_key_iv(properties, password_bytes.as_slice())?;
    decrypt_seven_zip_aes_with_key(data, &SevenZipAesKey { key, iv }, unpack_size)
}

fn decrypt_seven_zip_aes_with_key(
    data: &[u8],
    key: &SevenZipAesKey,
    unpack_size: u64,
) -> Result<Blob, String> {
    let mut iv = key.iv;
    if data.len() % 16 != 0 || unpack_size > data.len() as u64 {
        return Err("encoded_header_payload_crc_bad:aes_block_size".into());
    }
    let mut output = Spool::default();
    let mut remaining = unpack_size;
    let mut buffer = crate::io::resource_error::zeroed_bytes(data.len().clamp(16, 64 * 1024))
        .map_err(resource_error)?;
    for bytes in data.chunks(buffer.len()) {
        check_password_cancellation()?;
        buffer[..bytes.len()].copy_from_slice(bytes);
        Aes256CbcDec::new(&key.key.into(), &iv.into())
            .decrypt_padded::<NoPadding>(&mut buffer[..bytes.len()])
            .map_err(|_| "encoded_header_decode_password_rejected".to_string())?;
        iv.copy_from_slice(&bytes[bytes.len() - 16..]);
        let take = (remaining.min(bytes.len() as u64)) as usize;
        output.write_all(&buffer[..take]).map_err(resource_error)?;
        remaining -= take as u64;
    }
    output.finish().map_err(resource_error)
}
fn decode_lzma(data: &[u8], coder: &SevenZipCoderAst, unpack_size: u64) -> Result<Blob, String> {
    let compressed = Cursor::new(data);
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA {
        if coder.properties.len() < 5 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        let dict_size = u32::from_le_bytes(coder.properties[1..5].try_into().unwrap());
        let reader = LzmaReader::new_with_props(
            compressed,
            unpack_size,
            coder.properties[0],
            dict_size,
            None,
        )
        .map_err(|error| {
            if crate::io::resource_error::is_memory_error(&error) {
                resource_error(error)
            } else {
                format!("encoded_header_decoder_unsupported_method:{error}")
            }
        })?;
        return collect_decoded(reader, unpack_size);
    }
    let dict_size = coder
        .properties
        .first()
        .and_then(|value| lzma2_dict_size(*value))
        .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
    // This folder's complete output size is known, and there is no preset
    // dictionary. No valid backward reference can exceed the bytes produced.
    // Keep the decoder's alignment/minimum; this is not a format size limit.
    let dict_size = u64::from(dict_size).min(unpack_size.max(4096)) as u32;
    collect_decoded(Lzma2Reader::new(compressed, dict_size, None), unpack_size)
}

const SEVEN_Z_AES_MAX_CYCLES_POWER: u8 = 24;
const SEVEN_Z_AES_DIRECT_KEY: u8 = 0x3f;

pub(crate) fn seven_zip_aes_properties(properties: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let Some((&b0, rest)) = properties.split_first() else {
        return Some((0, &[], &[]));
    };
    let num_cycles_power = b0 & 0x3f;
    if num_cycles_power > SEVEN_Z_AES_MAX_CYCLES_POWER && num_cycles_power != SEVEN_Z_AES_DIRECT_KEY
    {
        return None;
    }
    if b0 & 0xc0 == 0 {
        return rest.is_empty().then_some((num_cycles_power, &[], &[]));
    }
    let (&b1, data) = rest.split_first()?;
    let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 15));
    let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
    (data.len() == salt_size + iv_size)
        .then(|| (num_cycles_power, &data[..salt_size], &data[salt_size..]))
}

fn seven_zip_aes_key_iv(
    properties: &[u8],
    password: &[u8],
) -> Result<([u8; 32], [u8; 16]), String> {
    seven_zip_aes_key_iv_using(properties, password, derive_seven_zip_aes_key)
}

// Password keys are candidate-scoped. The caller can carry one key through
// bounded prescreening and complete verification without a global cache.
fn seven_zip_aes_key_iv_using(
    properties: &[u8],
    password: &[u8],
    derive: impl FnOnce(u32, &[u8], &[u8]) -> Result<[u8; 32], String>,
) -> Result<([u8; 32], [u8; 16]), String> {
    let (num_cycles_power, salt, iv_bytes) = seven_zip_aes_properties(properties)
        .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
    let mut iv = [0u8; 16];
    iv[..iv_bytes.len()].copy_from_slice(iv_bytes);
    let key = if num_cycles_power == SEVEN_Z_AES_DIRECT_KEY {
        let mut key = [0u8; 32];
        let salt_size = salt.len();
        key[..salt_size].copy_from_slice(salt);
        let n = password.len().min(key.len().saturating_sub(salt_size));
        key[salt_size..salt_size + n].copy_from_slice(&password[..n]);
        key
    } else {
        let cycles = 1u32 << num_cycles_power;
        derive(cycles, salt, password)?
    };
    Ok((key, iv))
}

fn check_password_cancellation() -> Result<(), String> {
    if crate::io::cancellation::Cancellation::current().cancelled() {
        Err("resource_unavailable:password probe cancelled".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
thread_local! { static SEVEN_ZIP_KDF_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn derive_seven_zip_aes_key(cycles: u32, salt: &[u8], password: &[u8]) -> Result<[u8; 32], String> {
    #[cfg(test)]
    SEVEN_ZIP_KDF_DERIVATIONS.with(|count| count.set(count.get() + 1));
    let cancellation = crate::io::cancellation::Cancellation::current();
    const KDF_RECORDS_PER_UPDATE: usize = 64;
    let mut sha = sha2_11::Sha256::default();
    let record_len = salt.len() + password.len() + 8;
    let mut records = vec![0u8; record_len * KDF_RECORDS_PER_UPDATE];
    // Salt and password are identical in every round. Keep those bytes in
    // the existing batch buffer and rewrite only the counter on each update.
    for record in records
        .chunks_exact_mut(record_len)
        .take((cycles as usize).min(KDF_RECORDS_PER_UPDATE))
    {
        record[..salt.len()].copy_from_slice(salt);
        record[salt.len()..salt.len() + password.len()].copy_from_slice(password);
    }
    let mut counter = 0u64;
    while counter < u64::from(cycles) {
        if cancellation.cancelled() {
            return Err("resource_unavailable:password probe cancelled".into());
        }
        let remaining = u64::from(cycles) - counter;
        let record_count = usize::try_from(remaining.min(KDF_RECORDS_PER_UPDATE as u64))
            .expect("7z KDF record count is bounded");
        for record_index in 0..record_count {
            let record = &mut records[record_index * record_len..(record_index + 1) * record_len];
            record[record_len - 8..]
                .copy_from_slice(&(counter + record_index as u64).to_le_bytes());
        }
        sha2_11::Digest::update(&mut sha, &records[..record_count * record_len]);
        counter += record_count as u64;
    }
    Ok(sha2_11::Digest::finalize(sha).into())
}

fn seven_zip_probe_folder_supported(folder: &SevenZipFolderAst) -> bool {
    let mut aes_count = 0usize;
    for coder in &folder.coders {
        let method = coder.method_id.as_slice();
        let inputs = if method == EncoderMethod::ID_BCJ2 {
            4
        } else {
            1
        };
        if coder.num_in_streams != inputs || coder.num_out_streams != 1 {
            return false;
        }
        if method == EncoderMethod::ID_AES256_SHA256 {
            aes_count += 1;
            if seven_zip_aes_properties(&coder.properties).is_none() {
                return false;
            }
        } else if method == EncoderMethod::ID_COPY {
            if !coder.properties.is_empty() {
                return false;
            }
        } else if method == [0x04, 0xf7, 0x11, 0x04] {
            if coder.properties.len() != 5 {
                return false;
            }
        } else if method == EncoderMethod::ID_LZMA {
            if coder.properties.len() < 5 {
                return false;
            }
        } else if method == EncoderMethod::ID_LZMA2 {
            if coder
                .properties
                .first()
                .and_then(|value| lzma2_dict_size(*value))
                .is_none()
            {
                return false;
            }
        } else if method == EncoderMethod::ID_DELTA {
            if coder.properties.len() != 1 {
                return false;
            }
        } else if method == EncoderMethod::ID_BCJ2 {
            if !coder.properties.is_empty() {
                return false;
            }
        } else if seven_zip_bcj_start_pos(coder).is_err() {
            return false;
        }
    }
    aes_count == 1
}

#[cfg(test)]
#[path = "../../../../tests/unit/formats/seven_zip/header/encoded/encoded_folder_graph_tests.rs"]
mod encoded_folder_graph_tests;
