use std::borrow::Cow;
use crate::io::scratch::{Blob, Spool};
use std::io::Write;

enum CoderInput<'a> { Borrowed(&'a [u8]), Owned(Blob) }
impl AsRef<[u8]> for CoderInput<'_> { fn as_ref(&self)->&[u8] { match self { Self::Borrowed(bytes)=>bytes, Self::Owned(blob)=>blob } } }
impl From<Cow<'_,[u8]>> for CoderInput<'_> { fn from(value: Cow<'_,[u8]>)->Self { CoderInput::Owned(value.into_owned().into()) } }

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
    packed_data: Vec<Blob>,
    folder: SevenZipEncodedHeaderFolder,
}

impl SevenZipPasswordProbe {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.packed_data.iter().map(|data| data.len()).sum()
    }

    pub(crate) fn from_header<R: Read + Seek>(
        reader: &mut R,
        reader_len: u64,
        start: &[u8; SEVEN_Z_HEADER_SIZE],
    ) -> Result<Self, String> {

        if !start.starts_with(SEVEN_Z_MAGIC) || start[6] != 0 {
            return Err("7z password probe signature or version is unsupported".to_string());
        }
        let stored_start_crc = u32_le(start, 8);
        if crc32(&start[12..32]) != stored_start_crc {
            return Err("7z password probe start header crc is invalid".to_string());
        }
        let next_header_offset = u64_le(start, 12);
        let next_header_size = usize::try_from(u64_le(start, 20))
            .map_err(|_| "7z password probe next header is too large".to_string())?;
        if next_header_size == 0 {
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
        .map_err(|err| resource_error(err))?;
        if crc32(&raw) != u32_le(start, 28) {
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
            if stream_end > next_header_start {
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
                .map_err(|err| resource_error(err))?,
            );
            stream_start = stream_end;
        }
        Ok(Self {
            packed_data,
            folder,
        })
    }

    pub(crate) fn decoded_header_if_password_matches(&self, password: &str) -> Result<Option<Blob>, String> {
        let decoded = match decode_seven_zip_encoded_folder(
            &self.packed_data,
            &self.folder,
            Some(password),
        ) {
            Ok(decoded) => decoded,
            Err(error) if error.starts_with("resource_unavailable:") => return Err(error),
            Err(_) => return Ok(None),
        };
        Ok((decoded.first().copied() == Some(SZ_HEADER)
            && self
                .folder
                .expected_crc
                .is_some_and(|expected| crc32(&decoded) == expected))
        .then_some(decoded))
    }
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
    let mut output = Spool::default();
    let mut remaining = len;
    let mut bytes = vec![0; 64*1024];
    while remaining > 0 {
        let take = remaining.min(bytes.len());
        read_exact_field(reader, &mut bytes[..take], source_len, field, location).map_err(|fault| fault.into_io_error())?;
        output.write_all(&bytes[..take])?; remaining -= take;
    }
    output.finish()
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
    packed_data: &[Blob],
    folder: &SevenZipEncodedHeaderFolder,
    password: Option<&str>,
) -> Result<Blob, String> {
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
    packed_data: &[Blob],
    folder: &SevenZipEncodedHeaderFolder,
    password: Option<&str>,
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
    let mut inputs = Vec::with_capacity(usize::try_from(coder.num_in_streams).unwrap_or(0));
    for relative in 0..coder.num_in_streams {
        let input_stream = coder_input_base + relative;
        if let Some((_, upstream_output)) = folder
            .bind_pairs
            .iter()
            .find(|(input, _)| *input == input_stream)
        {
            inputs.push(CoderInput::Owned(decode_seven_zip_output(
                *upstream_output,
                packed_data,
                folder,
                password,
                visiting,
            )?));
        } else {
            let packed_index = folder
                .packed_streams
                .iter()
                .position(|stream| *stream == input_stream)
                .ok_or_else(|| "encoded_header_input_stream_unbound".to_string())?;
            inputs.push(
                packed_data
                    .get(packed_index)
                    .map(|data| CoderInput::Borrowed(data))
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
        let reader = Bcj2Reader::new(cursors, unpack_size);
        return collect_decoded(reader, unpack_size);
    }
    if inputs.len() != 1 {
        return Err("encoded_header_decoder_unsupported_multi_input_coder".to_string());
    }
    decode_seven_zip_encoded_coder(inputs.pop().unwrap(), coder, password, unpack_size)
}

fn seven_zip_bcj_start_pos(coder: &SevenZipEncodedHeaderCoder) -> Result<usize, String> {
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

fn decode_seven_zip_encoded_coder<'a>(
    data: impl Into<CoderInput<'a>>,
    coder: &SevenZipEncodedHeaderCoder,
    password: Option<&str>,
    unpack_size: u64,
) -> Result<Blob, String> {
    let data = data.into();
    if coder.method_id.as_slice() == EncoderMethod::ID_COPY {
        return collect_decoded(Cursor::new(data), unpack_size);
    }
    if coder.method_id.as_slice() == EncoderMethod::ID_AES256_SHA256 {
        return decrypt_seven_zip_aes256_sha256(data.as_ref(), &coder.properties, password, unpack_size);
    }
    if coder.method_id.as_slice() == [0x04, 0xf7, 0x11, 0x04] {
        if coder.properties.len() != 5 { return Err("encoded_header_decoder_unsupported_method:lz4_properties".into()); }
        let mut output = Spool::default();
        crate::formats::lz4::decode_into(Cursor::new(data), &mut ExactOutput { output:&mut output, remaining:unpack_size })
            .map_err(decode_error)?;
        let output = output.finish().map_err(resource_error)?;
        if output.len() as u64 != unpack_size { return Err("encoded_header_payload_crc_bad:lz4_unpack_size".into()); }
        return Ok(output);
    }
    if matches!(coder.method_id.as_slice(), method if method == EncoderMethod::ID_LZMA || method == EncoderMethod::ID_LZMA2) {
        return decode_lzma(data.as_ref(), coder, unpack_size);
    }
    let compressed = Cursor::new(data);
    macro_rules! decode_bcj {
        ($constructor:path) => {{
            return collect_decoded($constructor(compressed, seven_zip_bcj_start_pos(coder)?), unpack_size);
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

fn resource_error(error: impl std::fmt::Display) -> String { format!("resource_unavailable:{error}") }
fn decode_error(error: std::io::Error) -> String {
    if matches!(error.kind(), std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof) { format!("encoded_header_payload_crc_bad:{error}") } else { resource_error(error) }
}
struct ExactOutput<'a> { output:&'a mut Spool, remaining:u64 }
impl Write for ExactOutput<'_> {
    fn write(&mut self, bytes:&[u8])->std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"decoded size exceeds declared size")); }
        self.output.write_all(bytes)?; self.remaining-=bytes.len() as u64; Ok(bytes.len())
    }
    fn flush(&mut self)->std::io::Result<()> { self.output.flush() }
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
fn collect_decoded(reader:impl Read, size:u64)->Result<Blob,String> {
    let mut output=Spool::default();
    std::io::copy(&mut DecoderReader(reader).take(size.saturating_add(1)), &mut ExactOutput {output:&mut output, remaining:size}).map_err(decode_error)?;
    let output=output.finish().map_err(resource_error)?;
    if output.len() as u64 != size { return Err("encoded_header_payload_crc_bad:unpack_size".into()); }
    Ok(output)
}
fn decrypt_seven_zip_aes256_sha256(data:&[u8], properties:&[u8], password:Option<&str>, unpack_size:u64)->Result<Blob,String> {
    let Some(password)=password.filter(|value| !value.is_empty()) else { return Err("encoded_header_decode_password_required".into()); };
    let password_bytes=seven_zip_password(Some(password));
    let (key,mut iv)=seven_zip_aes_key_iv(properties,password_bytes.as_slice())?;
    if data.len()%16!=0 || unpack_size > data.len() as u64 { return Err("encoded_header_payload_crc_bad:aes_block_size".into()); }
    let mut output=Spool::default(); let mut remaining=unpack_size;
    let mut buffer=vec![0;64*1024];
    for bytes in data.chunks(buffer.len()) {
        buffer[..bytes.len()].copy_from_slice(bytes);
        Aes256CbcDec::new(&key.into(),&iv.into()).decrypt_padded::<NoPadding>(&mut buffer[..bytes.len()])
            .map_err(|_| "encoded_header_decode_password_rejected".to_string())?;
        iv.copy_from_slice(&bytes[bytes.len()-16..]);
        let take=(remaining.min(bytes.len() as u64)) as usize;
        output.write_all(&buffer[..take]).map_err(resource_error)?; remaining-=take as u64;
    }
    output.finish().map_err(resource_error)
}
fn decode_lzma(
    data: &[u8],
    coder: &SevenZipEncodedHeaderCoder,
    unpack_size: u64,
) -> Result<Blob, String> {
    let compressed = Cursor::new(data);
    if coder.method_id.as_slice() == EncoderMethod::ID_LZMA {
        if coder.properties.len() < 5 {
            return Err("encoded_header_decoder_unsupported_method".to_string());
        }
        let dict_size = u32::from_le_bytes(coder.properties[1..5].try_into().unwrap());
        let reader = LzmaReader::new_with_props(
            compressed, unpack_size, coder.properties[0], dict_size, None,
        ).map_err(|error| {
            if crate::io::resource_error::is_memory_error(&error) { resource_error(error) }
            else { format!("encoded_header_decoder_unsupported_method:{error}") }
        })?;
        return collect_decoded(reader, unpack_size);
    }
    let dict_size = coder.properties.first().and_then(|value| lzma2_dict_size(*value))
        .ok_or_else(|| "encoded_header_decoder_unsupported_method".to_string())?;
    // This folder's complete output size is known, and there is no preset
    // dictionary. No valid backward reference can exceed the bytes produced.
    // Keep the decoder's alignment/minimum; this is not a format size limit.
    let dict_size = u64::from(dict_size).min(unpack_size.max(4096)) as u32;
    collect_decoded(Lzma2Reader::new(compressed, dict_size, None), unpack_size)
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
            if coder.properties.is_empty() || (coder.properties[0] & 63) > 24 {
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
mod encoded_folder_graph_tests {
    use super::*;

    #[test]
    fn lzma2_encoded_coder_requires_declared_size_and_end_marker() {
        // Raw LZMA2 encoding of "test" repeated 128 times. Existing folder
        // graph tests do not exercise size lies or truncated LZMA2 streams.
        let packed = [
            224, 1, 255, 0, 12, 93, 0, 58, 25, 74, 206, 43, 15, 35, 137, 235, 206, 128, 0, 0,
        ];
        let coder = SevenZipEncodedHeaderCoder {
            method_id: EncoderMethod::ID_LZMA2.to_vec(),
            properties: vec![0],
            num_in_streams: 1,
            num_out_streams: 1,
        };
        let decode = |data: &[u8], size| {
            decode_seven_zip_encoded_coder(Cow::Borrowed(data), &coder, None, size)
        };
        assert_eq!(decode(&packed, 512).unwrap(), b"test".repeat(128));
        for wrong_size in [0, 1, 511, 513] {
            assert!(decode(&packed, wrong_size).is_err());
        }
        assert!(decode(&packed[..packed.len() - 1], 512).is_err());
        // A large advertised dictionary does not imply a large history for a
        // known, complete 512-byte folder. This also covers the maximum prop.
        let mut large_dictionary = coder;
        large_dictionary.properties[0] = 40;
        assert_eq!(
            decode_seven_zip_encoded_coder(Cow::Borrowed(packed.as_slice()), &large_dictionary, None, 512).unwrap(),
            b"test".repeat(128)
        );
    }

    #[test]
    fn lz4_encoded_coder_checks_size_properties_and_checksum() {
        let mut bytes = vec![0x04, 0x22, 0x4d, 0x18, 0x64, 0x40];
        bytes.push((crate::formats::lz4::xxh32(&bytes[4..]) >> 8) as u8);
        bytes.extend_from_slice(&0x80000004u32.to_le_bytes());
        bytes.extend_from_slice(b"test");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&crate::formats::lz4::xxh32(b"test").to_le_bytes());
        let mut coder = SevenZipEncodedHeaderCoder {
            method_id: vec![0x04, 0xf7, 0x11, 0x04],
            properties: vec![1, 10, 1, 0, 0],
            num_in_streams: 1,
            num_out_streams: 1,
        };
        assert_eq!(
            decode_seven_zip_encoded_coder(Cow::Borrowed(bytes.as_slice()), &coder, None, 4).unwrap(),
            b"test"
        );
        for wrong_size in [0, 3, 5, 64 * 1024 * 1024 + 1] {
            assert!(decode_seven_zip_encoded_coder(
                Cow::Borrowed(bytes.as_slice()),
                &coder,
                None,
                wrong_size
            )
            .is_err());
        }
        *bytes.last_mut().unwrap() ^= 1;
        assert!(decode_seven_zip_encoded_coder(Cow::Borrowed(bytes.as_slice()), &coder, None, 4).is_err());
        coder.properties.clear();
        assert!(decode_seven_zip_encoded_coder(Cow::Borrowed(bytes.as_slice()), &coder, None, 4).is_err());
    }

    fn reference_aes_key(properties: &[u8], password: &[u8]) -> [u8; 32] {
        let b0 = properties[0];
        let b1 = properties.get(1).copied().unwrap_or(0);
        let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
        let salt = properties.get(2..2 + salt_size).unwrap_or_default();
        reference_aes_key_bytes(1u64 << (b0 & 63), salt, password)
    }

    fn reference_aes_key_bytes(cycles: u64, salt: &[u8], password: &[u8]) -> [u8; 32] {
        let mut sha = sha2_11::Sha256::default();
        for counter in 0..cycles {
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
        // Whole batches do not expose stale counters in a partial last batch,
        // nor accidental overlap between long passwords and the counter field.
        for password in [b"p\0a\0s\0s\0".to_vec(), vec![0xa5; 300]] {
            for salt in [&[][..], &[0x5a; 16][..]] {
                for cycles in [0, 3, 63, 65, 129] {
                    assert_eq!(
                        derive_seven_zip_aes_key(cycles, salt, &password),
                        reference_aes_key_bytes(u64::from(cycles), salt, &password)
                    );
                }
            }
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
        let decoded = decode_seven_zip_encoded_folder(&[b"test".to_vec().into()], &folder, None).unwrap();
        assert_eq!(decoded, b"test");
    }

    // Real password tests cover malformed plaintext, but cannot inject OOM or
    // OS read failures. This tiny case preserves that independent distinction
    // without large allocations or another archive-generation matrix.
    #[test]
    fn decoder_read_failures_keep_resource_errors_distinct_from_invalid_data() {
        struct FailedRead(Option<std::io::Error>);
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(self.0.take().unwrap())
            }
        }
        for (error, resource) in [
            (std::io::Error::other("invalid compressed distance"), false),
            (std::io::Error::from(std::io::ErrorKind::OutOfMemory), true),
            (std::io::Error::from_raw_os_error(8), true),
            (std::io::Error::from_raw_os_error(5), true),
        ] {
            let error = collect_decoded(FailedRead(Some(error)), 1).unwrap_err();
            assert_eq!(error.starts_with("resource_unavailable:"), resource, "{error}");
        }
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
