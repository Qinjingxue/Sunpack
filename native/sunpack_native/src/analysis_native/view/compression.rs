fn decompress_sample<R: Read>(
    format: &str,
    reader: R,
    max_output: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut output = Vec::new();
    let result = match format {
        "lz4" => return crate::formats::lz4::sample(reader, max_output),
        "gzip" => GzDecoder::new(reader)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "bzip2" => BzDecoder::new(reader)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "xz" => XzDecoder::new(reader)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "zstd" => {
            let decoder = ZstdDecoder::new(reader).map_err(|_| "zstd_decoder_init_failed")?;
            decoder.take(max_output as u64).read_to_end(&mut output)
        }
        _ => return Err("unsupported_compression_format"),
    };
    result.map_err(|_| "decompression_probe_failed")?;
    Ok(output)
}

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for index in offset..data.len().min(offset + 10) {
        let byte = data[index];
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}
