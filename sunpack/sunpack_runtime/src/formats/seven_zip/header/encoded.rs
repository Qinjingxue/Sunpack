use crate::io::scratch::{Blob, Spool};
use std::ffi::c_void;
use std::io::Write;
use std::sync::Mutex;

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
    packed: SevenZipHeaderData,
    folder: SevenZipFolderAst,
    prefix: Option<SevenZipHeaderPrefix>,
    metadata: SevenZipMetadata,
}

enum SevenZipHeaderData {
    Ready(Vec<Blob>),
    Deferred(Box<SevenZipDeferredHeader>),
}

// An incomplete source preserves a candidate. A proven extent contradiction
// can eliminate this projection even when another source remains unreadable.
type SevenZipHeaderMaterial = Result<Option<Vec<Blob>>, String>;
type SevenZipHeaderOutcomes = Vec<(Option<Arc<VolumeProjection>>, SevenZipHeaderMaterial)>;

struct SevenZipDeferredHeader {
    source: SevenZipPayloadSource,
    streams: Vec<SevenZipPackedStream>,
    encrypted_prefix: [u8; 32],
    prefix_len: usize,
    material: Mutex<Option<Arc<SevenZipHeaderOutcomes>>>,
    ambiguous: bool,
}

#[derive(Clone, Copy)]
struct SevenZipPackedStream {
    offset: u64,
    size: usize,
    crc: Option<u32>,
}

#[derive(Clone, Copy)]
enum SevenZipMetadata {
    Header,
    Folders(usize),
    Additional,
    Names(u64),
}

struct SevenZipHeaderPrefix {
    packed: usize,
    aes: usize,
    inner_aes: Vec<usize>,
    evidence: SevenZipPayloadEvidence,
}

impl SevenZipPasswordProbe {
    #[cfg(test)]
    fn from_parts(packed_data: Vec<Blob>, folder: SevenZipFolderAst, metadata: SevenZipMetadata) -> Self {
        let prefix = Self::prefix(&folder, metadata, |index| packed_data[index].len() as u64);
        Self { packed: SevenZipHeaderData::Ready(packed_data), folder, prefix, metadata }
    }

    fn prefix(
        folder: &SevenZipFolderAst, metadata: SevenZipMetadata, size: impl Fn(usize) -> u64,
    ) -> Option<SevenZipHeaderPrefix> {
        folder
            .packed_streams
            .iter()
            .enumerate()
            .find_map(|(index, &input)| {
                seven_zip_aes_stream(folder, input, size(index))
                    .and_then(|stream| SevenZipPayloadEvidence::from_stream(
                        &folder, &stream, matches!(metadata, SevenZipMetadata::Header),
                    ).map(|evidence| SevenZipHeaderPrefix {
                        packed: index, aes: stream.aes_index, inner_aes: stream.inner_aes, evidence,
                    }))
            })
    }

    pub(crate) fn key_properties(&self) -> impl Iterator<Item = &[u8]> {
        self.folder.coders.iter()
            .filter(|coder| coder.method_id == EncoderMethod::ID_AES256_SHA256)
            .map(|coder| coder.properties.as_slice())
    }

    pub(crate) fn has_crc(&self) -> bool {
        self.folder.expected_crc.is_some()
    }

    pub(crate) fn has_ambiguous_material(&self) -> bool {
        matches!(&self.packed, SevenZipHeaderData::Deferred(data) if data.ambiguous)
    }

    #[cfg(test)]
    pub(crate) fn check_header<'a>(
        &'a self, key: impl FnMut(&'a [u8]) -> Result<SevenZipAesKey, String>,
    ) -> Result<SevenZipPrefixCheck, String> {
        self.verify_header(key, |_| {})
    }

    pub(crate) fn verify_header<'a>(
        &'a self,
        mut key: impl FnMut(&'a [u8]) -> Result<SevenZipAesKey, String>,
        mut reject: impl FnMut(Arc<VolumeProjection>),
    ) -> Result<SevenZipPrefixCheck, String> {
        use SevenZipPrefixCheck::{Confirmed, Reject, Strong, Weak};
        let mut prepared = None;
        let mut inner = Vec::new();
        if let Some(prefix) = &self.prefix {
            let derived = key(&self.folder.coders[prefix.aes].properties)?;
            inner = prefix.inner_aes.iter().map(|&index| key(&self.folder.coders[index].properties))
                .collect::<Result<Vec<_>, _>>()?;
            let encrypted = match &self.packed {
                SevenZipHeaderData::Ready(data) => data[prefix.packed].as_ref(),
                SevenZipHeaderData::Deferred(data) => &data.encrypted_prefix[..data.prefix_len],
            };
            let (plain, len) = prefix.evidence.decrypt_prefix_with_inner(encrypted, &derived, &inner)?;
            if prefix.evidence.check_prefix(&plain[..len]) == Reject {
                return Ok(Reject);
            }
            prepared = Some((prefix.aes, derived));
        }
        let mut check = |packed_data: &[Blob]| self.check_header_material(packed_data, |coder, properties| {
            if let Some((_, key)) = prepared.as_ref().filter(|(index, _)| *index == coder) {
                return Ok(key.with_iv(&key.iv));
            }
            if let Some(key) = self.prefix.as_ref().and_then(|prefix| {
                prefix.inner_aes.iter().position(|&index| index == coder).map(|index| &inner[index])
            }) {
                return Ok(key.with_iv(&key.iv));
            }
            key(properties).map_err(resource_error)
        });
        match &self.packed {
            SevenZipHeaderData::Ready(packed) => check(packed),
            SevenZipHeaderData::Deferred(data) => {
                let prefix = self.prefix.as_ref().expect("deferred header has a prefix");
                let material = data.material(prefix.packed)?;
                let mut result = Reject;
                let mut unavailable = None;
                for (projection, packed) in material.iter() {
                    let proof = match packed {
                        Ok(Some(packed)) => check(packed),
                        Ok(None) => Ok(Reject),
                        Err(error) => Err(error.clone()),
                    };
                    match proof {
                        Ok(Reject) => {
                            if let Some(projection) = projection { reject(projection.clone()); }
                        }
                        Ok(Confirmed) if result == Reject => result = Confirmed,
                        Ok(Confirmed) => {}
                        Ok(Strong) if result == Reject => result = Strong,
                        Ok(Strong) => {}
                        Ok(Weak) => result = Weak,
                        Err(error) => { unavailable.get_or_insert(error); }
                    }
                }
                unavailable.map_or(Ok(result), Err)
            }
        }
    }

    fn check_header_material<'a>(
        &'a self,
        packed_data: &[Blob],
        mut key: impl FnMut(usize, &'a [u8]) -> Result<SevenZipAesKey, String>,
    ) -> Result<SevenZipPrefixCheck, String> {
        use SevenZipPrefixCheck::{Confirmed, Reject, Strong, Weak};
        let decoded = match decode_seven_zip_encoded_folder_with_keys(
            packed_data,
            &self.folder,
            &mut key,
        ) {
            Ok(decoded) => decoded,
            Err(error) if error.starts_with("resource_unavailable:") => return Err(error),
            Err(_) => return Ok(Reject),
        };
        if matches!(self.metadata, SevenZipMetadata::Header)
            && decoded.first().copied() != Some(SZ_HEADER)
        {
            return Ok(Reject);
        }
        if let Some(expected) = self.folder.expected_crc {
            return Ok(if crc32(&decoded) == expected { Confirmed } else { Reject });
        }
        let syntax = match self.metadata {
            SevenZipMetadata::Header => parse_seven_zip_header_with_data(
                &decoded, &mut SevenZipStreams::default(), &mut SevenZipStreams::default(),
                false, None,
            ).map(|_| ()),
            SevenZipMetadata::Folders(count) => parse_seven_zip_folders(&decoded, &mut 0, count, false)
                .map(|_| ()).map_err(std::borrow::Cow::Borrowed),
            SevenZipMetadata::Additional => return Ok(Weak),
            SevenZipMetadata::Names(count) => {
                // ReadHeader's Name property requires one UTF-16 terminator
                // per file. The SDK merely flags unused trailing name bytes.
                let complete = decoded.chunks_exact(2)
                    .filter(|unit| *unit == [0, 0])
                    .take(usize::try_from(count).unwrap_or(usize::MAX))
                    .count() as u64;
                return Ok(if complete == count { Weak } else { Reject });
            }
        };
        match syntax {
            Ok(()) => Ok(Strong),
            Err(error) if error.contains("unsupported") || error == "folder_coder_reserved_flags_set"
                || error == "folder_stream_count_exceeds_limit" => Ok(Weak),
            Err(error) if error == "7z_analysis_resource_limit" => Err(error.into_owned()),
            Err(_) => Ok(Reject),
        }
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

fn prepare_seven_zip_header<R: Read + Seek>(
    reader: &mut R,
    reader_len: u64,
    before: u64,
    pack: &SevenZipPackInfoAst,
    folder: &SevenZipFolderAst,
    first: usize,
    metadata: SevenZipMetadata,
    evidence: &impl SevenZipEvidenceReads<R>,
) -> Result<(SevenZipHeaderData, Option<SevenZipHeaderPrefix>), SevenZipMetadataError> {
    let streams = seven_zip_packed_streams(before, pack, folder, first)?;
    let prefix = SevenZipPasswordProbe::prefix(folder, metadata, |index| streams[index].size as u64);
    if let Some(check) = prefix.as_ref() {
        let stream = streams[check.packed];
        let prefix_len = check.evidence.plaintext_prefix_size().next_multiple_of(16);
        let has_more = streams.len() > 1 || stream.size > 32 ||
            (stream.size > prefix_len && evidence.range_is_ambiguous(reader, stream.offset, stream.size as u64));
        // Public digests that can rule out volume candidates are checked in
        // the candidate preparation stage. Keep those bytes for the decoder.
        let ambiguous_crc = streams.iter().any(|stream| stream.crc.is_some()
            && evidence.range_is_ambiguous(reader, stream.offset, stream.size as u64));
        if matches!(metadata, SevenZipMetadata::Header) && has_more && !ambiguous_crc && evidence.has_deferred_source() {
            let mut encrypted_prefix = [0; 32];
            evidence.independent(reader, |reader| {
                read_seven_zip_packed_at(reader, reader_len, stream.offset, &mut encrypted_prefix[..prefix_len])
            }).map_err(resource_error)?;
            let source = evidence.payload_source(reader).expect("deferred evidence source");
            let ambiguous = matches!(&source, SevenZipPayloadSource::Projected(source)
                if source.active_ranges_are_ambiguous(streams.iter().map(|stream| (stream.offset, stream.size as u64))));
            let data = SevenZipHeaderData::Deferred(Box::new(SevenZipDeferredHeader {
                source, streams, encrypted_prefix, prefix_len, material: Mutex::default(), ambiguous,
            }));
            return Ok((data, prefix));
        }
    }
    let packed = evidence.independent(reader, |reader| {
        load_seven_zip_packed_data(&streams, None, |offset, bytes| {
            read_seven_zip_packed_at(reader, reader_len, offset, bytes).map_err(resource_error)
        })
    })?;
    Ok((SevenZipHeaderData::Ready(packed), prefix))
}

impl SevenZipDeferredHeader {
    fn material(&self, prefix_stream: usize) -> Result<Arc<SevenZipHeaderOutcomes>, String> {
        let mut slot = self.material.lock().unwrap();
        if let Some(material) = &*slot { return Ok(material.clone()); }
        check_password_cancellation()?;
        let material = Arc::new(self.read_material(prefix_stream)?);
        check_password_cancellation()?;
        *slot = Some(material.clone());
        Ok(material)
    }

    fn read_material(&self, prefix_stream: usize) -> Result<SevenZipHeaderOutcomes, String> {
        let prefix = Some((prefix_stream, &self.encrypted_prefix[..self.prefix_len]));
        let load = |read: &mut SevenZipRead<'_>| load_seven_zip_packed_data(
            &self.streams, prefix,
            |offset, bytes| read(offset, bytes).map_err(seven_zip_deferred_error),
        );
        match &self.source {
            SevenZipPayloadSource::Fixed(ranges) => {
                let mut reader = VirtualRangeReader::streaming(ranges);
                let result = load(&mut |offset, bytes| {
                    reader.seek(std::io::SeekFrom::Start(offset)).map_err(DeferredReadError::Io)?;
                    reader.read_exact(bytes).map_err(DeferredReadError::Io)
                });
                Ok(vec![(None, result.map(Some).map_err(std::borrow::Cow::into_owned))])
            }
            SevenZipPayloadSource::Projected(ranges) => ranges.evaluate(|reader| {
                let mut truncated = false;
                let result = load_seven_zip_packed_data(&self.streams, prefix, |offset, bytes| {
                    reader.read_into(offset, bytes).map_err(|error| {
                        truncated = matches!(error, DeferredReadError::Truncated);
                        seven_zip_deferred_error(error)
                    })
                });
                (result, truncated)
            }).map(|outcomes| outcomes.into_iter().map(|(projection, (result, truncated))| {
                let result = if truncated {
                    Ok(None)
                } else {
                    result.map(Some).map_err(std::borrow::Cow::into_owned)
                };
                (Some(projection), result)
            }).collect()).map_err(resource_error),
        }
    }
}

fn seven_zip_packed_streams(
    before: u64, pack: &SevenZipPackInfoAst, folder: &SevenZipFolderAst, first: usize,
) -> Result<Vec<SevenZipPackedStream>, SevenZipMetadataError> {
    if pack.num_streams != pack.sizes.len() {
        return Err("7z password probe pack stream count mismatch".into());
    }
    let mut stream_start = (SEVEN_Z_HEADER_SIZE as u64)
        .checked_add(pack.pack_pos)
        .ok_or("7z password probe stream offset overflow")?;
    let sizes = pack.sizes.get(first..first + folder.packed_streams.len())
        .ok_or("7z password probe pack stream index out of range")?;
    for &size in &pack.sizes[..first] {
        stream_start = stream_start.checked_add(size)
            .ok_or("7z password probe stream offset overflow")?;
    }
    let mut streams = Vec::with_capacity(sizes.len());
    for (index, &size) in sizes.iter().enumerate() {
        let stream_end = stream_start
            .checked_add(size)
            .ok_or("7z password probe stream end overflow")?;
        if stream_end > before {
            return Err("7z password probe stream range is invalid".into());
        }
        streams.push(SevenZipPackedStream {
            offset: stream_start,
            size: usize::try_from(size).map_err(|_| "7z password probe stream is too large")?,
            crc: pack.crcs.get(first + index).copied().flatten(),
        });
        stream_start = stream_end;
    }
    Ok(streams)
}

fn read_seven_zip_packed_data<R: Read + Seek>(
    reader: &mut R, reader_len: u64, before: u64, pack: &SevenZipPackInfoAst,
    folder: &SevenZipFolderAst, first: usize,
) -> Result<Vec<Blob>, SevenZipMetadataError> {
    let streams = seven_zip_packed_streams(before, pack, folder, first)?;
    load_seven_zip_packed_data(&streams, None, |offset, bytes| {
        read_seven_zip_packed_at(reader, reader_len, offset, bytes).map_err(resource_error)
    })
}

fn read_seven_zip_packed_at(
    reader: &mut (impl Read + Seek), reader_len: u64, offset: u64, bytes: &mut [u8],
) -> std::io::Result<()> {
    let field = "7z.encoded_header.packed_stream";
    seek_field(reader, offset, reader_len, field, FieldLocation::Body)
        .map_err(|fault| fault.into_io_error())?;
    read_exact_field(reader, bytes, reader_len, field, FieldLocation::Body)
        .map_err(|fault| fault.into_io_error())
}

fn load_seven_zip_packed_data(
    streams: &[SevenZipPackedStream], prefix: Option<(usize, &[u8])>,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Result<Vec<Blob>, SevenZipMetadataError> {
    let mut packed_data = Vec::with_capacity(streams.len());
    for (index, stream) in streams.iter().enumerate() {
        let prefix = prefix.filter(|(source, _)| *source == index).map_or(&[][..], |(_, bytes)| bytes);
        let mut offset = stream.offset + prefix.len() as u64;
        let result = read_seven_zip_blob(stream.size, prefix, resource_error, |bytes| {
            read(offset, bytes)?;
            offset += bytes.len() as u64;
            Ok(())
        })?;
        if stream.crc.is_some_and(|expected| crc32(&result) != expected) {
            return Err("7z packed stream crc mismatch".into());
        }
        packed_data.push(result);
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
    read_seven_zip_blob(len, &[], std::convert::identity, |bytes| read_exact_field(reader, bytes, source_len, field, location)
        .map_err(|fault| fault.into_io_error()))
}

fn read_seven_zip_blob<E>(
    len: usize, prefix: &[u8], map_error: impl Fn(std::io::Error) -> E,
    mut read: impl FnMut(&mut [u8]) -> Result<(), E>,
) -> Result<Blob, E> {
    if len <= crate::io::scratch::MEMORY_BYTES {
        let mut bytes = crate::io::resource_error::zeroed_bytes(len).map_err(&map_error)?;
        bytes[..prefix.len()].copy_from_slice(prefix);
        if prefix.len() != len { read(&mut bytes[prefix.len()..])?; }
        return Ok(bytes.into());
    }
    let mut output = Spool::default();
    output.spill().map_err(&map_error)?;
    output.write_all(prefix).map_err(&map_error)?;
    let mut remaining = len - prefix.len();
    let mut bytes = vec![0; 64 * 1024];
    while remaining > 0 {
        crate::io::cancellation::Cancellation::check_current_io().map_err(&map_error)?;
        let take = remaining.min(bytes.len());
        read(&mut bytes[..take])?;
        output.write_all(&bytes[..take]).map_err(&map_error)?;
        remaining -= take;
    }
    output.finish().map_err(map_error)
}

fn parse_seven_zip_encoded_header_descriptor(
    raw: &[u8],
) -> Result<(SevenZipPackInfoAst, SevenZipFolderAst), SevenZipMetadataError> {
    if raw.first() != Some(&SZ_ENCODED_HEADER) {
        return Err("encoded_header_nid_missing".into());
    }
    let mut pos = 1;
    let mut streams = SevenZipStreams::default();
    let substream_crc = parse_seven_zip_streams_info(raw, &mut pos, &mut streams, true, &mut None)?;
    if streams.folders.len() != 1 {
        return Err("encoded_header_folder_not_unique".into());
    }
    let mut folder = streams.folders.pop().unwrap();
    folder.expected_crc = folder.expected_crc.or(substream_crc);
    let pack = streams.pack.ok_or("encoded_header_pack_info_missing")?;
    if pack.num_streams != folder.packed_streams.len() {
        return Err("7z password probe pack stream count mismatch".into());
    }
    Ok((pack, folder))
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
) -> Result<Blob, String> {
    decode_seven_zip_encoded_folder_with_keys(packed_data, folder, &mut |_, _| {
        Err("encoded_header_decode_password_required".into())
    })
}

fn decode_seven_zip_encoded_folder_with_keys<'a>(
    packed_data: &[Blob],
    folder: &'a SevenZipFolderAst,
    key: &mut impl FnMut(usize, &'a [u8]) -> Result<SevenZipAesKey, String>,
) -> Result<Blob, String> {
    if folder.coders.is_empty() {
        return Err("encoded_header_decoder_unsupported_method".to_string());
    }
    let mut visiting = [false; SEVEN_Z_MAX_FOLDER_CODERS];
    decode_seven_zip_output(
        folder.main_output_stream,
        packed_data,
        folder,
        key,
        &mut visiting,
    )
}

fn decode_seven_zip_output<'a>(
    output_stream: u64,
    packed_data: &[Blob],
    folder: &'a SevenZipFolderAst,
    key: &mut impl FnMut(usize, &'a [u8]) -> Result<SevenZipAesKey, String>,
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
    if coder.method_id == EncoderMethod::ID_AES256_SHA256 {
        let key = key(coder_index, &coder.properties)?;
        return decrypt_seven_zip_aes_with_key(input.as_ref(), &key, unpack_size);
    }
    decode_seven_zip_encoded_coder(input, coder, unpack_size)
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
    unpack_size: u64,
) -> Result<Blob, String> {
    if coder.method_id.as_slice() == EncoderMethod::ID_COPY {
        return collect_decoded(Cursor::new(data), unpack_size);
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
    if coder.method_id.as_slice() == [0x03, 0x04, 0x01] {
        return decode_ppmd_header(data.as_ref(), &coder.properties, unpack_size);
    }
    if coder.method_id.as_slice() == [0x04, 0x01, 0x09] {
        let input = data.as_ref();
        return decode_native_header("Deflate64", unpack_size, |context, write| {
            // The decoder uses the complete immutable metadata and the
            // synchronous output callback for the duration of this call.
            unsafe { sunpack_decode_deflate64_header(
                input.as_ptr(), input.len(), unpack_size, context, write,
            ) }
        });
    }
    let compressed = Cursor::new(data);
    match coder.method_id.as_slice() {
        [0x04, 0x01, 0x08] => return collect_decoded(flate2::read::DeflateDecoder::new(compressed), unpack_size),
        [0x04, 0x02, 0x02] => return collect_decoded(bzip2::read::MultiBzDecoder::new(compressed), unpack_size),
        [0x04, 0xf7, 0x11, 0x01] => {
            return collect_decoded(zstd::stream::read::Decoder::new(compressed).map_err(decode_error)?, unpack_size);
        }
        _ => {}
    }
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

fn ppmd_header_properties(properties: &[u8]) -> Option<(u32, u32)> {
    let [order, a, b, c, d, ..] = properties else { return None };
    let memory = u32::from_le_bytes([*a, *b, *c, *d]);
    ((2..=64).contains(order) && ((1 << 11)..=(u32::MAX - 36)).contains(&memory))
        .then_some((u32::from(*order), memory))
}

fn decode_ppmd_header(data: &[u8], properties: &[u8], size: u64) -> Result<Blob, String> {
    let (order, memory) = ppmd_header_properties(properties)
        .ok_or("encoded_header_decoder_unsupported_method:ppmd_properties")?;
    decode_native_header("PPMd", size, |context, write| {
        // The decoder borrows its complete input and output state for this call.
        unsafe { sunpack_decode_ppmd7_header(
            data.as_ptr(), data.len(), memory, order, size, context, write,
        ) }
    })
}

type HeaderWrite = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;

unsafe extern "C" {
    fn sunpack_decode_ppmd7_header(
        data: *const u8,
        len: usize,
        memory: u32,
        order: u32,
        size: u64,
        context: *mut c_void,
        write: HeaderWrite,
    ) -> i32;

    fn sunpack_decode_deflate64_header(
        data: *const u8,
        len: usize,
        size: u64,
        context: *mut c_void,
        write: HeaderWrite,
    ) -> i32;
}

fn decode_native_header(
    codec: &'static str,
    size: u64,
    run: impl FnOnce(*mut c_void, HeaderWrite) -> i32,
) -> Result<Blob, String> {
    use std::io;
    struct Output<'a> {
        exact: ExactOutput<'a>,
        error: Option<io::Error>,
    }
    unsafe extern "C" fn write(context: *mut c_void, bytes: *const u8, len: usize) -> i32 {
        // The synchronous decoder calls this with its current output block
        // and the original Rust state, neither of which escapes this call.
        let output = unsafe { &mut *context.cast::<Output<'_>>() };
        let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };
        if output.error.is_some() {
            return 1;
        }
        let result = if bytes.is_empty() {
            crate::io::cancellation::Cancellation::check_current_io()
        } else {
            output.exact.write_all(bytes)
        };
        match result {
            Ok(()) => 0,
            Err(error) => {
                output.error = Some(error);
                1
            }
        }
    }
    check_password_cancellation()?;
    let mut spool = Spool::default();
    let mut output = Output {
        exact: ExactOutput { output: &mut spool, remaining: size },
        error: None,
    };
    let status = run((&mut output as *mut Output).cast(), write);
    if let Some(error) = output.error {
        return Err(decode_error(error));
    }
    match status {
        0 if output.exact.remaining == 0 => spool.finish().map_err(resource_error),
        2 => Err(resource_error(format!("7z {codec} header allocation failed"))),
        _ => Err(format!("encoded_header_payload_crc_bad:{codec}")),
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
    let mut encrypted = false;
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
            encrypted = true;
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
        } else if matches!(method, [0x04, 0x01, 0x08 | 0x09] | [0x04, 0x02, 0x02] | [0x04, 0xf7, 0x11, 0x01]) {
            // Deflate, Deflate64, BZip2 and Zstd use stream parameters.
        } else if method == [0x03, 0x04, 0x01] {
            if ppmd_header_properties(&coder.properties).is_none() {
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
    encrypted
}

#[cfg(test)]
#[path = "../../../../tests/unit/formats/seven_zip/header/encoded/encoded_folder_graph_tests.rs"]
mod encoded_folder_graph_tests;
