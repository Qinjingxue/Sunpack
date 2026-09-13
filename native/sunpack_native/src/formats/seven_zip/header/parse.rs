fn read_sz_vint(data: &[u8], pos: &mut usize) -> Option<SevenZipVintSpan> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let mut mask = 0x80u8;
    let mut value = 0u64;
    for extra in 0..8 {
        if first & mask == 0 {
            let low_mask = mask.saturating_sub(1);
            value |= ((first & low_mask) as u64) << (8 * extra);
            return Some(SevenZipVintSpan { value });
        }
        let byte = *data.get(*pos)? as u64;
        *pos += 1;
        value |= byte << (8 * extra);
        mask >>= 1;
    }
    Some(SevenZipVintSpan { value })
}

fn parse_seven_zip_header_ast(
    data: &[u8],
    header: &SevenZipHeader,
) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_HEADER {
        return Err("7z next header is not a plain Header tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z next header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_HEADER) {
        return Err("7z Header NID is missing".to_string());
    }
    pos += 1;
    let mut unpack_info = None;
    let mut diagnostics = Vec::new();
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            diagnostics.push("header_tree_truncated_before_end".to_string());
            break;
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_MAIN_STREAMS_INFO => {
                let streams = parse_seven_zip_streams_info(raw, &mut pos);
                unpack_info = streams.unpack_info;
                diagnostics.extend(streams.diagnostics);
                if !diagnostics.is_empty() {
                    break;
                }
            }
            SZ_FILES_INFO => {
                match parse_seven_zip_files_info(raw, &mut pos) {
                    Ok(()) => {}
                    Err(message) => {
                        diagnostics.push(message);
                        break;
                    }
                }
            }
            _ => {
                diagnostics.push(format!("unsupported_header_nid_0x{nid:02x}"));
                break;
            }
        }
    }
    Ok(SevenZipHeaderAst {
        unpack_info,
        diagnostics,
    })
}

fn parse_seven_zip_encoded_header_ast(
    data: &[u8],
    header: &SevenZipHeader,
) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_ENCODED_HEADER {
        return Err("7z next header is not an EncodedHeader tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("7z EncodedHeader NID is missing".to_string());
    }
    pos += 1;
    let streams = parse_seven_zip_streams_info(raw, &mut pos);
    Ok(SevenZipHeaderAst {
        unpack_info: streams.unpack_info,
        diagnostics: streams.diagnostics,
    })
}

pub(crate) struct SevenZipEncryptionFacts {
    pub(crate) password_required: bool,
    pub(crate) encrypted_header: bool,
    pub(crate) encrypted_payload: bool,
    pub(crate) scan_complete: bool,
}

pub(crate) fn seven_zip_encryption_facts_from_next_header(
    raw: &[u8],
) -> SevenZipEncryptionFacts {
    let Some(&next_header_nid) = raw.first() else {
        return SevenZipEncryptionFacts {
            password_required: false,
            encrypted_header: false,
            encrypted_payload: false,
            scan_complete: false,
        };
    };
    let header = SevenZipHeader {
        archive_end: raw.len(),
        next_header_start: 0,
        next_header_nid,
    };
    let ast = if next_header_nid == SZ_ENCODED_HEADER {
        parse_seven_zip_encoded_header_ast(raw, &header)
    } else if next_header_nid == SZ_HEADER {
        parse_seven_zip_header_ast(raw, &header)
    } else {
        return SevenZipEncryptionFacts {
            password_required: false,
            encrypted_header: false,
            encrypted_payload: false,
            scan_complete: false,
        };
    };
    let Ok(ast) = ast else {
        return SevenZipEncryptionFacts {
            password_required: false,
            encrypted_header: false,
            encrypted_payload: false,
            scan_complete: false,
        };
    };
    let encrypted = ast
        .unpack_info
        .as_ref()
        .is_some_and(|unpack| {
            unpack.folders.iter().any(|folder| {
                folder
                    .coders
                    .iter()
                    .any(|coder| coder.method_id.as_slice() == [0x06, 0xf1, 0x07, 0x01])
            })
        });
    let encrypted_header = next_header_nid == SZ_ENCODED_HEADER && encrypted;
    let encrypted_payload = next_header_nid == SZ_HEADER && encrypted;
    // A plaintext EncodedHeader is only a wrapper around the packed metadata.
    // For data-only encryption (`-p`, without `-mhe`) the AES coder lives in
    // that packed metadata and cannot be inspected without the password.  It
    // is therefore not a proof of an unencrypted archive.  Keep the state
    // unknown so the password resolver can run its bounded verifier/final
    // extraction confirmation instead of short-circuiting to empty password.
    let scan_complete = next_header_nid != SZ_ENCODED_HEADER;
    SevenZipEncryptionFacts {
        password_required: encrypted_header || encrypted_payload,
        encrypted_header,
        encrypted_payload,
        scan_complete: ast.diagnostics.is_empty() && scan_complete,
    }
}

fn parse_seven_zip_streams_info(data: &[u8], pos: &mut usize) -> SevenZipStreamsInfoAst {
    let mut pack_info = None;
    let mut unpack_info = None;
    let mut substreams_info = None;
    let mut diagnostics = Vec::new();
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            diagnostics.push("streams_info_truncated_before_end".to_string());
            break;
        };
        *pos += 1;
        let result = match nid {
            SZ_END => break,
            SZ_PACK_INFO => {
                parse_seven_zip_pack_info(data, pos).map(|value| pack_info = Some(value))
            }
            SZ_UNPACK_INFO => {
                parse_seven_zip_unpack_info(data, pos).map(|value| unpack_info = Some(value))
            }
            SZ_SUB_STREAMS_INFO => match unpack_info.as_ref() {
                Some(unpack) => parse_seven_zip_substreams_info(data, pos, unpack)
                    .map(|value| substreams_info = Some(value)),
                None => Err("substreams_info_requires_unpack_info".to_string()),
            },
            _ => Err(format!("unsupported_streams_info_nid_0x{nid:02x}")),
        };
        if let Err(message) = result {
            diagnostics.push(message);
            break;
        }
    }
    SevenZipStreamsInfoAst {
        pack_info,
        unpack_info,
        substreams_info,
        diagnostics,
    }
}

fn parse_seven_zip_pack_info(data: &[u8], pos: &mut usize) -> Result<SevenZipPackInfoAst, String> {
    let pack_pos =
        read_sz_vint(data, pos).ok_or_else(|| "7z PackInfo PackPos is truncated".to_string())?;
    let num_streams_raw = read_sz_vint(data, pos)
        .ok_or_else(|| "7z PackInfo NumPackStreams is truncated".to_string())?;
    let num_streams = usize::try_from(num_streams_raw.value)
        .map_err(|_| "7z PackInfo stream count is too large".to_string())?;
    if num_streams > SEVEN_Z_MAX_HEADER_STREAMS {
        return Err("7z PackInfo stream count exceeds parser limit".to_string());
    }
    let mut sizes = Vec::new();
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z PackInfo ended before End NID".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_SIZE => {
                sizes.clear();
                for _ in 0..num_streams {
                    let span = read_sz_vint(data, pos)
                        .ok_or_else(|| "7z PackInfo PackSizes is truncated".to_string())?;
                    sizes.push(span);
                }
            }
            SZ_CRC => {
                let defined = parse_seven_zip_bool_vector(data, pos, num_streams)?;
                for is_defined in defined {
                    if is_defined {
                        if *pos + 4 > data.len() {
                            return Err("7z PackInfo CRC values are truncated".to_string());
                        }
                        *pos += 4;
                    }
                }
            }
            _ => return Err(format!("unsupported 7z PackInfo NID 0x{nid:02x}")),
        }
    }
    Ok(SevenZipPackInfoAst {
        pack_pos,
        num_streams,
        sizes,
    })
}

fn parse_seven_zip_unpack_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<SevenZipUnpackInfoAst, String> {
    if data.get(*pos).copied() != Some(SZ_FOLDER) {
        return Err("unpack_info_folder_nid_missing".to_string());
    }
    *pos += 1;
    let num_folders = usize::try_from(
        read_sz_vint(data, pos)
            .ok_or_else(|| "unpack_info_folder_count_truncated".to_string())?
            .value,
    )
    .map_err(|_| "unpack_info_folder_count_too_large".to_string())?;
    if num_folders == 0 || num_folders > SEVEN_Z_MAX_HEADER_STREAMS {
        return Err("unpack_info_folder_count_invalid".to_string());
    }
    let external = *data
        .get(*pos)
        .ok_or_else(|| "unpack_info_external_flag_missing".to_string())?;
    *pos += 1;
    if external != 0 {
        return Err("unpack_info_external_folders_unsupported".to_string());
    }
    let mut folders = Vec::with_capacity(num_folders);
    for _ in 0..num_folders {
        folders.push(parse_seven_zip_folder(data, pos)?);
    }
    if data.get(*pos).copied() != Some(SZ_CODERS_UNPACK_SIZE) {
        return Err("unpack_info_coders_unpack_size_nid_missing".to_string());
    }
    *pos += 1;
    for folder in &mut folders {
        let output_count = folder
            .coders
            .iter()
            .try_fold(0u64, |sum, coder| sum.checked_add(coder.num_out_streams))
            .ok_or_else(|| "folder_output_stream_count_overflow".to_string())?;
        let output_count = usize::try_from(output_count)
            .map_err(|_| "folder_output_stream_count_too_large".to_string())?;
        for _ in 0..output_count {
            folder.unpack_sizes.push(
                read_sz_vint(data, pos)
                    .ok_or_else(|| "unpack_info_coder_unpack_size_truncated".to_string())?,
            );
        }
        folder.unpack_size = folder
            .unpack_sizes
            .get(usize::try_from(folder.main_output_stream).unwrap_or(usize::MAX))
            .ok_or_else(|| "folder_main_output_unpack_size_missing".to_string())?
            .value;
    }
    if data.get(*pos).copied() == Some(SZ_CRC) {
        *pos += 1;
        let defined = parse_seven_zip_bool_vector(data, pos, folders.len())?;
        for (folder, is_defined) in folders.iter_mut().zip(defined) {
            if is_defined {
                if pos.checked_add(4).is_none_or(|end| end > data.len()) {
                    return Err("unpack_info_folder_crc_truncated".to_string());
                }
                folder.expected_crc = Some(SevenZipCrcSpan {
                    value: u32_le(data, *pos),
                });
                *pos += 4;
            }
        }
    }
    if data.get(*pos).copied() != Some(SZ_END) {
        return Err("unpack_info_end_nid_missing".to_string());
    }
    *pos += 1;
    Ok(SevenZipUnpackInfoAst { folders })
}

fn parse_seven_zip_folder(data: &[u8], pos: &mut usize) -> Result<SevenZipFolderAst, String> {
    let num_coders = usize::try_from(
        read_sz_vint(data, pos)
            .ok_or_else(|| "folder_coder_count_truncated".to_string())?
            .value,
    )
    .map_err(|_| "folder_coder_count_too_large".to_string())?;
    if num_coders == 0 || num_coders > 64 {
        return Err("folder_coder_count_invalid".to_string());
    }
    let mut coders = Vec::with_capacity(num_coders);
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flags = *data
            .get(*pos)
            .ok_or_else(|| "folder_coder_flags_missing".to_string())?;
        *pos += 1;
        let id_size = usize::from(flags & 0x0f);
        let id_end = pos
            .checked_add(id_size)
            .ok_or_else(|| "folder_coder_id_overflow".to_string())?;
        if id_size == 0 || id_end > data.len() {
            return Err("folder_coder_id_truncated".to_string());
        }
        let method_id = data[*pos..id_end].to_vec();
        *pos = id_end;
        let (num_in_streams, num_out_streams) = if flags & 0x10 != 0 {
            (
                read_sz_vint(data, pos)
                    .ok_or_else(|| "folder_coder_input_count_truncated".to_string())?
                    .value,
                read_sz_vint(data, pos)
                    .ok_or_else(|| "folder_coder_output_count_truncated".to_string())?
                    .value,
            )
        } else {
            (1, 1)
        };
        if num_in_streams == 0 || num_out_streams == 0 {
            return Err("folder_coder_stream_count_invalid".to_string());
        }
        total_in = total_in
            .checked_add(num_in_streams)
            .ok_or_else(|| "folder_input_stream_count_overflow".to_string())?;
        total_out = total_out
            .checked_add(num_out_streams)
            .ok_or_else(|| "folder_output_stream_count_overflow".to_string())?;
        if total_in > SEVEN_Z_MAX_HEADER_STREAMS as u64
            || total_out > SEVEN_Z_MAX_HEADER_STREAMS as u64
        {
            return Err("folder_stream_count_exceeds_limit".to_string());
        }
        let properties = if flags & 0x20 != 0 {
            let size = usize::try_from(
                read_sz_vint(data, pos)
                    .ok_or_else(|| "folder_coder_properties_size_truncated".to_string())?
                    .value,
            )
            .map_err(|_| "folder_coder_properties_too_large".to_string())?;
            let start = *pos;
            let end = start
                .checked_add(size)
                .ok_or_else(|| "folder_coder_properties_range_overflow".to_string())?;
            if end > data.len() {
                return Err("folder_coder_properties_truncated".to_string());
            }
            *pos = end;
            data[start..end].to_vec()
        } else {
            Vec::new()
        };
        if flags & 0xc0 != 0 {
            return Err("folder_coder_reserved_flags_set".to_string());
        }
        coders.push(SevenZipCoderAst {
            method_id,
            properties,
            num_in_streams,
            num_out_streams,
        });
    }
    if total_out == 0 || total_in < total_out.saturating_sub(1) {
        return Err("folder_stream_graph_counts_invalid".to_string());
    }
    let num_bind_pairs = total_out - 1;
    let mut bind_pairs = Vec::with_capacity(usize::try_from(num_bind_pairs).unwrap_or(0));
    for _ in 0..num_bind_pairs {
        let input = read_sz_vint(data, pos)
            .ok_or_else(|| "folder_bind_pair_input_truncated".to_string())?
            .value;
        let output = read_sz_vint(data, pos)
            .ok_or_else(|| "folder_bind_pair_output_truncated".to_string())?
            .value;
        if input >= total_in
            || output >= total_out
            || bind_pairs
                .iter()
                .any(|(old_in, old_out)| *old_in == input || *old_out == output)
        {
            return Err("folder_bind_pair_invalid".to_string());
        }
        bind_pairs.push((input, output));
    }
    let num_packed_streams = total_in - num_bind_pairs;
    if num_packed_streams == 0 {
        return Err("folder_packed_stream_missing".to_string());
    }
    let mut packed_streams = Vec::with_capacity(usize::try_from(num_packed_streams).unwrap_or(0));
    if num_packed_streams == 1 {
        packed_streams.push(
            (0..total_in)
                .find(|candidate| !bind_pairs.iter().any(|(input, _)| input == candidate))
                .ok_or_else(|| "folder_packed_stream_missing".to_string())?,
        );
    } else {
        for _ in 0..num_packed_streams {
            let input = read_sz_vint(data, pos)
                .ok_or_else(|| "folder_packed_stream_index_truncated".to_string())?
                .value;
            if input >= total_in
                || bind_pairs.iter().any(|(bound, _)| *bound == input)
                || packed_streams.contains(&input)
            {
                return Err("folder_packed_stream_index_invalid".to_string());
            }
            packed_streams.push(input);
        }
    }
    let main_output_stream = (0..total_out)
        .find(|candidate| !bind_pairs.iter().any(|(_, output)| output == candidate))
        .ok_or_else(|| "folder_main_output_missing".to_string())?;
    validate_seven_zip_folder_graph(&coders, &bind_pairs, main_output_stream, total_out)?;
    Ok(SevenZipFolderAst {
        coders,
        bind_pairs,
        packed_streams,
        main_output_stream,
        unpack_size: 0,
        unpack_sizes: Vec::new(),
        expected_crc: None,
    })
}

fn validate_seven_zip_folder_graph(
    coders: &[SevenZipCoderAst],
    bind_pairs: &[(u64, u64)],
    main_output_stream: u64,
    total_out: u64,
) -> Result<(), String> {
    fn visit(
        output: u64,
        coders: &[SevenZipCoderAst],
        bind_pairs: &[(u64, u64)],
        states: &mut [u8],
    ) -> Result<(), String> {
        let output_index = usize::try_from(output).map_err(|_| "folder_output_index_too_large".to_string())?;
        match states.get(output_index).copied() {
            Some(1) => return Err("folder_bind_pair_cycle".to_string()),
            Some(2) => return Ok(()),
            Some(_) => states[output_index] = 1,
            None => return Err("folder_output_index_invalid".to_string()),
        }
        let mut input_base = 0u64;
        let mut output_base = 0u64;
        let mut owner = None;
        for coder in coders {
            if output >= output_base && output < output_base + coder.num_out_streams {
                owner = Some((input_base, coder.num_in_streams));
                break;
            }
            input_base = input_base.checked_add(coder.num_in_streams).ok_or_else(|| "folder_input_stream_count_overflow".to_string())?;
            output_base = output_base.checked_add(coder.num_out_streams).ok_or_else(|| "folder_output_stream_count_overflow".to_string())?;
        }
        let (input_base, input_count) = owner.ok_or_else(|| "folder_output_owner_missing".to_string())?;
        for input in input_base..input_base + input_count {
            if let Some((_, upstream)) = bind_pairs.iter().find(|(bound, _)| *bound == input) {
                visit(*upstream, coders, bind_pairs, states)?;
            }
        }
        states[output_index] = 2;
        Ok(())
    }

    let mut states = vec![0u8; usize::try_from(total_out).map_err(|_| "folder_output_count_too_large".to_string())?];
    visit(main_output_stream, coders, bind_pairs, &mut states)?;
    if states.iter().any(|state| *state != 2) {
        return Err("folder_graph_disconnected".to_string());
    }
    Ok(())
}

fn parse_seven_zip_substreams_info(
    data: &[u8],
    pos: &mut usize,
    unpack: &SevenZipUnpackInfoAst,
) -> Result<SevenZipSubStreamsInfoAst, String> {
    let mut counts = vec![1usize; unpack.folders.len()];
    let mut size_values = Vec::new();
    let mut crc_values = Vec::new();
    let mut nid = *data
        .get(*pos)
        .ok_or_else(|| "substreams_info_truncated".to_string())?;
    if nid == SZ_NUM_UNPACK_STREAM {
        *pos += 1;
        for count in &mut counts {
            *count = usize::try_from(
                read_sz_vint(data, pos)
                    .ok_or_else(|| "substreams_info_count_truncated".to_string())?
                    .value,
            )
            .map_err(|_| "substreams_info_count_too_large".to_string())?;
        }
        nid = *data
            .get(*pos)
            .ok_or_else(|| "substreams_info_truncated_after_counts".to_string())?;
    }
    let total_streams = counts
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
        .ok_or_else(|| "substreams_info_total_count_overflow".to_string())?;
    if total_streams > SEVEN_Z_MAX_HEADER_FILES as usize {
        return Err("substreams_info_total_count_exceeds_limit".to_string());
    }
    if nid == SZ_SIZE {
        *pos += 1;
        for (folder, count) in unpack.folders.iter().zip(&counts) {
            let mut sum = 0u64;
            for _ in 0..count.saturating_sub(1) {
                let span = read_sz_vint(data, pos)
                    .ok_or_else(|| "substreams_info_size_truncated".to_string())?;
                sum = sum
                    .checked_add(span.value)
                    .ok_or_else(|| "substreams_info_size_sum_overflow".to_string())?;
                size_values.push(span.value);
            }
            if *count > 0 {
                size_values.push(folder.unpack_size.checked_sub(sum).ok_or_else(|| {
                    "substreams_info_sizes_exceed_folder_unpack_size".to_string()
                })?);
            }
        }
        nid = *data
            .get(*pos)
            .ok_or_else(|| "substreams_info_truncated_after_sizes".to_string())?;
    } else {
        for (folder, count) in unpack.folders.iter().zip(&counts) {
            if *count == 1 {
                size_values.push(folder.unpack_size);
            } else if *count > 1 {
                return Err("substreams_info_sizes_missing_for_multiple_streams".to_string());
            }
        }
    }
    if nid == SZ_CRC {
        *pos += 1;
        let digest_count = unpack
            .folders
            .iter()
            .zip(&counts)
            .map(|(folder, count)| {
                if *count == 1 && folder.expected_crc.is_some() {
                    0
                } else {
                    *count
                }
            })
            .sum::<usize>();
        let defined = parse_seven_zip_bool_vector(data, pos, digest_count)?;
        let mut defined_index = 0usize;
        for (folder, count) in unpack.folders.iter().zip(&counts) {
            if *count == 1 && folder.expected_crc.is_some() {
                crc_values.push(folder.expected_crc);
                continue;
            }
            for _ in 0..*count {
                if defined[defined_index] {
                    if pos.checked_add(4).is_none_or(|end| end > data.len()) {
                        return Err("substreams_info_crc_truncated".to_string());
                    }
                    crc_values.push(Some(SevenZipCrcSpan {
                        value: u32_le(data, *pos),
                    }));
                    *pos += 4;
                } else {
                    crc_values.push(None);
                }
                defined_index += 1;
            }
        }
        nid = *data
            .get(*pos)
            .ok_or_else(|| "substreams_info_truncated_after_crc".to_string())?;
    } else {
        for (folder, count) in unpack.folders.iter().zip(&counts) {
            if *count == 1 {
                crc_values.push(folder.expected_crc);
            } else {
                crc_values.extend((0..*count).map(|_| None));
            }
        }
    }
    if nid != SZ_END {
        return Err(format!("unsupported_substreams_info_nid_0x{nid:02x}"));
    }
    *pos += 1;
    if size_values.len() != total_streams || crc_values.len() != total_streams {
        return Err("substreams_info_cardinality_mismatch".to_string());
    }
    Ok(SevenZipSubStreamsInfoAst {
        num_unpack_streams: counts,
        unpack_size_values: size_values,
        crc_values,
    })
}

fn parse_seven_zip_bool_vector(
    data: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<bool>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let all_defined = *data
        .get(*pos)
        .ok_or_else(|| "7z boolean vector is truncated".to_string())?;
    *pos += 1;
    if all_defined != 0 {
        return Ok(vec![true; count]);
    }
    let byte_count = (count + 7) / 8;
    if *pos + byte_count > data.len() {
        return Err("7z boolean bitset is truncated".to_string());
    }
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let byte = data[*pos + index / 8];
        output.push((byte & (0x80 >> (index % 8))) != 0);
    }
    *pos += byte_count;
    Ok(output)
}

fn parse_seven_zip_files_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<(), String> {
    let num_files = read_sz_vint(data, pos)
        .ok_or_else(|| "7z FilesInfo file count is truncated".to_string())?;
    if num_files.value > SEVEN_Z_MAX_HEADER_FILES {
        return Err("7z FilesInfo file count exceeds parser limit".to_string());
    }
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z FilesInfo ended before End NID".to_string());
        };
        *pos += 1;
        if nid == SZ_END {
            break;
        }
        let size = read_sz_vint(data, pos)
            .ok_or_else(|| "7z FilesInfo property size is truncated".to_string())?;
        let prop_size = usize::try_from(size.value)
            .map_err(|_| "7z FilesInfo property size is too large".to_string())?;
        let prop_end = (*pos)
            .checked_add(prop_size)
            .ok_or_else(|| "7z FilesInfo property range overflowed".to_string())?;
        if prop_end > data.len() {
            return Err("7z FilesInfo property is truncated".to_string());
        }
        let _ = nid;
        *pos = prop_end;
    }
    Ok(())
}

#[cfg(test)]
mod seven_zip_streams_info_tests {
    use super::*;

    fn one_copy_folder(unpack_size: u8, folder_crc: Option<u32>) -> Vec<u8> {
        let mut bytes = vec![
            SZ_FOLDER,
            1,
            0, // one inline folder
            1,
            0x01,
            0x00, // one Copy coder, one input and output
            SZ_CODERS_UNPACK_SIZE,
            unpack_size,
        ];
        if let Some(crc) = folder_crc {
            bytes.extend([SZ_CRC, 1]);
            bytes.extend(crc.to_le_bytes());
        }
        bytes.push(SZ_END);
        bytes
    }

    #[test]
    fn parses_folder_graph_and_inherited_single_substream_crc() {
        let expected_crc = 0x4433_2211;
        let mut raw = vec![SZ_PACK_INFO, 0, 1, SZ_SIZE, 10, SZ_END, SZ_UNPACK_INFO];
        raw.extend(one_copy_folder(20, Some(expected_crc)));
        raw.extend([SZ_SUB_STREAMS_INFO, SZ_END, SZ_END]);
        let mut pos = 0;
        let streams = parse_seven_zip_streams_info(&raw, &mut pos);
        assert!(streams.diagnostics.is_empty(), "{:?}", streams.diagnostics);
        let unpack = streams.unpack_info.unwrap();
        assert_eq!(unpack.folders.len(), 1);
        assert_eq!(unpack.folders[0].unpack_size, 20);
        assert_eq!(unpack.folders[0].coders[0].method_id, [0]);
        let substreams = streams.substreams_info.unwrap();
        assert_eq!(substreams.num_unpack_streams, [1]);
        assert_eq!(substreams.unpack_size_values, [20]);
        assert_eq!(substreams.crc_values[0].unwrap().value, expected_crc);
    }

    #[test]
    fn parses_multiple_substream_sizes_and_crcs() {
        let mut raw = vec![SZ_UNPACK_INFO];
        raw.extend(one_copy_folder(20, None));
        raw.extend([
            SZ_SUB_STREAMS_INFO,
            SZ_NUM_UNPACK_STREAM,
            2,
            SZ_SIZE,
            7,
            SZ_CRC,
            1,
        ]);
        raw.extend(0x1111_1111u32.to_le_bytes());
        raw.extend(0x2222_2222u32.to_le_bytes());
        raw.extend([SZ_END, SZ_END]);
        let mut pos = 0;
        let streams = parse_seven_zip_streams_info(&raw, &mut pos);
        assert!(streams.diagnostics.is_empty(), "{:?}", streams.diagnostics);
        let substreams = streams.substreams_info.unwrap();
        assert_eq!(substreams.num_unpack_streams, [2]);
        assert_eq!(substreams.unpack_size_values, [7, 13]);
        assert_eq!(
            substreams
                .crc_values
                .iter()
                .filter(|crc| crc.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn preserves_pack_info_when_later_substream_graph_is_invalid() {
        let mut raw = vec![SZ_PACK_INFO, 0, 1, SZ_SIZE, 10, SZ_END, SZ_UNPACK_INFO];
        raw.extend(one_copy_folder(20, None));
        raw.extend([
            SZ_SUB_STREAMS_INFO,
            SZ_NUM_UNPACK_STREAM,
            2,
            SZ_SIZE,
            21,
            SZ_END,
        ]);
        let mut pos = 0;
        let streams = parse_seven_zip_streams_info(&raw, &mut pos);
        assert!(streams.pack_info.is_some());
        assert!(streams.unpack_info.is_some());
        assert_eq!(
            streams.diagnostics,
            ["substreams_info_sizes_exceed_folder_unpack_size"]
        );
    }
}
