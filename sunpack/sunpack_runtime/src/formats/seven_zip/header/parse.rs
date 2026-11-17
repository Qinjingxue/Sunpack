fn read_sz_vint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let mut mask = 0x80u8;
    let mut value = 0u64;
    for extra in 0..8 {
        if first & mask == 0 {
            let low_mask = mask.saturating_sub(1);
            value |= ((first & low_mask) as u64) << (8 * extra);
            return Some(value);
        }
        let byte = *data.get(*pos)? as u64;
        *pos += 1;
        value |= byte << (8 * extra);
        mask >>= 1;
    }
    Some(value)
}

fn parse_seven_zip_header(raw: &[u8], streams: &mut SevenZipStreams) -> Result<(), &'static str> {
    parse_seven_zip_header_with_data(raw, streams, false)
}

fn parse_seven_zip_header_with_data(
    raw: &[u8], streams: &mut SevenZipStreams, retain_decode_data: bool,
) -> Result<(), &'static str> {
    let mut pos = 1;
    loop {
        let nid = *raw.get(pos).ok_or("header_tree_truncated_before_end")?;
        pos += 1;
        match nid {
            SZ_END => return Ok(()),
            SZ_MAIN_STREAMS_INFO => parse_seven_zip_streams_info(raw, &mut pos, streams, retain_decode_data)?,
            SZ_FILES_INFO => parse_seven_zip_files_info(raw, &mut pos)?,
            _ => return Err("unsupported_header_nid"),
        }
    }
}

/// Confirm the decoded tree in place after the password probe validates its CRC.
/// An unsupported tree still requires extraction confirmation.
pub(crate) fn predecoded_seven_zip_header_is_supported(raw: &[u8]) -> bool {
    match raw.first() {
        None => true,
        Some(&SZ_HEADER) => parse_seven_zip_header(raw, &mut SevenZipStreams::default()).is_ok(),
        _ => false,
    }
}

fn parse_seven_zip_streams_info(
    data: &[u8],
    pos: &mut usize,
    streams: &mut SevenZipStreams,
    retain_decode_data: bool,
) -> Result<(), &'static str> {
    // A new StreamsInfo section supersedes the previous section, including
    // when the new section ends early with only partial facts.
    streams.folders = Vec::new();
    streams.substreams = Vec::new();
    loop {
        let nid = *data.get(*pos).ok_or("streams_info_truncated_before_end")?;
        *pos += 1;
        match nid {
            SZ_END => return Ok(()),
            SZ_PACK_INFO => {
                let pack = parse_seven_zip_pack_info(data, pos, retain_decode_data)?;
                if retain_decode_data {
                    streams.pack = Some(pack);
                }
            }
            SZ_UNPACK_INFO => {
                let folders = parse_seven_zip_unpack_info(data, pos, retain_decode_data)?;
                streams.folders = folders;
            }
            SZ_SUB_STREAMS_INFO => {
                if streams.folders.is_empty() {
                    return Err("substreams_info_requires_unpack_info");
                }
                streams.substreams = parse_seven_zip_substreams_info(data, pos, &streams.folders, retain_decode_data)?;
            }
            _ => return Err("unsupported_streams_info_nid"),
        }
    }
}

fn seven_zip_vec<T>(count: usize) -> Result<Vec<T>, &'static str> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| "7z_analysis_resource_limit")?;
    Ok(values)
}

fn parse_seven_zip_pack_info(
    data: &[u8],
    pos: &mut usize,
    retain_sizes: bool,
) -> Result<SevenZipPackInfoAst, &'static str> {
    let pack_pos = read_sz_vint(data, pos).ok_or("7z PackInfo PackPos is truncated")?;
    let num_streams_raw =
        read_sz_vint(data, pos).ok_or("7z PackInfo NumPackStreams is truncated")?;
    let num_streams =
        usize::try_from(num_streams_raw).map_err(|_| "7z PackInfo stream count is too large")?;
    let mut sizes = Vec::new();
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z PackInfo ended before End NID");
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_SIZE => {
                if num_streams > data.len().saturating_sub(*pos) {
                    return Err("7z PackInfo PackSizes is truncated");
                }
                if retain_sizes {
                    sizes = seven_zip_vec(num_streams)?;
                }
                for _ in 0..num_streams {
                    let span =
                        read_sz_vint(data, pos).ok_or("7z PackInfo PackSizes is truncated")?;
                    if retain_sizes {
                        sizes.push(span);
                    }
                }
            }
            SZ_CRC => {
                skip_seven_zip_crcs(
                    data,
                    pos,
                    num_streams,
                    "7z PackInfo CRC values are truncated",
                )?;
            }
            _ => return Err("unsupported 7z PackInfo NID"),
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
    retain_decode_data: bool,
) -> Result<Vec<SevenZipFolderAst>, &'static str> {
    if data.get(*pos).copied() != Some(SZ_FOLDER) {
        return Err("unpack_info_folder_nid_missing");
    }
    *pos += 1;
    let num_folders =
        usize::try_from(read_sz_vint(data, pos).ok_or("unpack_info_folder_count_truncated")?)
            .map_err(|_| "unpack_info_folder_count_too_large")?;
    if num_folders == 0 {
        return Err("unpack_info_folder_count_invalid");
    }
    let external = *data.get(*pos).ok_or("unpack_info_external_flag_missing")?;
    *pos += 1;
    if external != 0 {
        return Err("unpack_info_external_folders_unsupported");
    }
    // Each inline Folder needs at least a coder count, flags and method ID.
    if num_folders > data.len().saturating_sub(*pos) / 3 {
        return Err("unpack_info_folders_truncated");
    }
    let mut folders = seven_zip_vec(num_folders)?;
    for _ in 0..num_folders {
        folders.push(parse_seven_zip_folder(data, pos, retain_decode_data)?);
    }
    if data.get(*pos).copied() != Some(SZ_CODERS_UNPACK_SIZE) {
        return Err("unpack_info_coders_unpack_size_nid_missing");
    }
    *pos += 1;
    for folder in &mut folders {
        let output_count = folder
            .coders
            .iter()
            .map(|coder| coder.num_out_streams)
            .sum::<u64>();
        let mut sizes = if retain_decode_data && output_count > 1 {
            Some(seven_zip_vec(output_count as usize)?)
        } else {
            None
        };
        for output in 0..output_count {
            let size = read_sz_vint(data, pos).ok_or("unpack_info_coder_unpack_size_truncated")?;
            if let Some(sizes) = &mut sizes {
                sizes.push(size);
            } else if output == folder.main_output_stream {
                folder.unpack_sizes = SevenZipUnpackSizes::Main(size);
            }
        }
        if let Some(sizes) = sizes {
            folder.unpack_sizes = SevenZipUnpackSizes::All(sizes);
        }
    }
    if data.get(*pos).copied() == Some(SZ_CRC) {
        *pos += 1;
        let defined = parse_seven_zip_crc_flags(data, pos, folders.len())?;
        for (index, folder) in folders.iter_mut().enumerate() {
            if defined.contains(index) {
                if pos.checked_add(4).is_none_or(|end| end > data.len()) {
                    return Err("unpack_info_folder_crc_truncated");
                }
                folder.expected_crc = Some(u32_le(data, *pos));
                *pos += 4;
            }
        }
    }
    if data.get(*pos).copied() != Some(SZ_END) {
        return Err("unpack_info_end_nid_missing");
    }
    *pos += 1;
    Ok(folders)
}

fn parse_seven_zip_folder(
    data: &[u8],
    pos: &mut usize,
    retain_decode_data: bool,
) -> Result<SevenZipFolderAst, &'static str> {
    let num_coders =
        usize::try_from(read_sz_vint(data, pos).ok_or("folder_coder_count_truncated")?)
            .map_err(|_| "folder_coder_count_too_large")?;
    if num_coders == 0 || num_coders > SEVEN_Z_MAX_FOLDER_CODERS {
        return Err("folder_coder_count_invalid");
    }
    let mut coders = Vec::with_capacity(num_coders);
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flags = *data.get(*pos).ok_or("folder_coder_flags_missing")?;
        *pos += 1;
        let id_size = usize::from(flags & 0x0f);
        let id_end = pos.checked_add(id_size).ok_or("folder_coder_id_overflow")?;
        if id_size == 0 || id_end > data.len() {
            return Err("folder_coder_id_truncated");
        }
        let method_id = data[*pos..id_end].to_vec();
        *pos = id_end;
        let (num_in_streams, num_out_streams) = if flags & 0x10 != 0 {
            (
                read_sz_vint(data, pos).ok_or("folder_coder_input_count_truncated")?,
                read_sz_vint(data, pos).ok_or("folder_coder_output_count_truncated")?,
            )
        } else {
            (1, 1)
        };
        if num_in_streams == 0 || num_out_streams == 0 {
            return Err("folder_coder_stream_count_invalid");
        }
        total_in = total_in
            .checked_add(num_in_streams)
            .ok_or("folder_input_stream_count_overflow")?;
        total_out = total_out
            .checked_add(num_out_streams)
            .ok_or("folder_output_stream_count_overflow")?;
        if total_in > SEVEN_Z_MAX_FOLDER_STREAMS || total_out > SEVEN_Z_MAX_FOLDER_STREAMS {
            return Err("folder_stream_count_exceeds_limit");
        }
        let properties = if flags & 0x20 != 0 {
            let size = usize::try_from(
                read_sz_vint(data, pos).ok_or("folder_coder_properties_size_truncated")?,
            )
            .map_err(|_| "folder_coder_properties_too_large")?;
            let start = *pos;
            let end = start
                .checked_add(size)
                .ok_or("folder_coder_properties_range_overflow")?;
            if end > data.len() {
                return Err("folder_coder_properties_truncated");
            }
            *pos = end;
            if retain_decode_data {
                let mut properties = seven_zip_vec(size)?;
                properties.extend_from_slice(&data[start..end]);
                properties
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if flags & 0xc0 != 0 {
            return Err("folder_coder_reserved_flags_set");
        }
        coders.push(SevenZipCoderAst {
            method_id,
            properties,
            num_in_streams,
            num_out_streams,
        });
    }
    if total_out == 0 || total_in < total_out.saturating_sub(1) {
        return Err("folder_stream_graph_counts_invalid");
    }
    let num_bind_pairs = total_out - 1;
    let mut bind_pairs = Vec::with_capacity(usize::try_from(num_bind_pairs).unwrap_or(0));
    for _ in 0..num_bind_pairs {
        let input = read_sz_vint(data, pos).ok_or("folder_bind_pair_input_truncated")?;
        let output = read_sz_vint(data, pos).ok_or("folder_bind_pair_output_truncated")?;
        if input >= total_in
            || output >= total_out
            || bind_pairs
                .iter()
                .any(|(old_in, old_out)| *old_in == input || *old_out == output)
        {
            return Err("folder_bind_pair_invalid");
        }
        bind_pairs.push((input, output));
    }
    let num_packed_streams = total_in - num_bind_pairs;
    if num_packed_streams == 0 {
        return Err("folder_packed_stream_missing");
    }
    let mut packed_streams = Vec::new();
    if retain_decode_data {
        packed_streams.reserve_exact(num_packed_streams as usize);
    }
    if num_packed_streams == 1 {
        if retain_decode_data {
            // Every bind pair has a unique in-range input. Exactly one input
            // remains when the packed stream count is one.
            packed_streams.push(
                (0..total_in)
                    .find(|candidate| !bind_pairs.iter().any(|(input, _)| input == candidate))
                    .expect("unique unbound packed input"),
            );
        }
    } else {
        let mut seen = 0u64;
        for _ in 0..num_packed_streams {
            let input = read_sz_vint(data, pos).ok_or("folder_packed_stream_index_truncated")?;
            if input >= total_in
                || bind_pairs.iter().any(|(bound, _)| *bound == input)
                || seen & (1 << input) != 0
            {
                return Err("folder_packed_stream_index_invalid");
            }
            seen |= 1 << input;
            if retain_decode_data {
                packed_streams.push(input);
            }
        }
    }
    let main_output_stream = (0..total_out)
        .find(|candidate| !bind_pairs.iter().any(|(_, output)| output == candidate))
        .ok_or("folder_main_output_missing")?;
    validate_seven_zip_folder_graph(&coders, &bind_pairs, main_output_stream, total_out)?;
    Ok(SevenZipFolderAst {
        coders,
        bind_pairs,
        packed_streams,
        main_output_stream,
        unpack_sizes: SevenZipUnpackSizes::Main(0),
        expected_crc: None,
    })
}

fn validate_seven_zip_folder_graph(
    coders: &[SevenZipCoderAst],
    bind_pairs: &[(u64, u64)],
    main_output_stream: u64,
    total_out: u64,
) -> Result<(), &'static str> {
    fn visit(
        output: u64,
        coders: &[SevenZipCoderAst],
        bind_pairs: &[(u64, u64)],
        states: &mut [u8],
    ) -> Result<(), &'static str> {
        let output_index = usize::try_from(output).map_err(|_| "folder_output_index_too_large")?;
        match states.get(output_index).copied() {
            Some(1) => return Err("folder_bind_pair_cycle"),
            Some(2) => return Ok(()),
            Some(_) => states[output_index] = 1,
            None => return Err("folder_output_index_invalid"),
        }
        let mut input_base = 0u64;
        let mut output_base = 0u64;
        let mut owner = None;
        for coder in coders {
            if output >= output_base && output < output_base + coder.num_out_streams {
                owner = Some((input_base, coder.num_in_streams));
                break;
            }
            input_base = input_base
                .checked_add(coder.num_in_streams)
                .ok_or("folder_input_stream_count_overflow")?;
            output_base = output_base
                .checked_add(coder.num_out_streams)
                .ok_or("folder_output_stream_count_overflow")?;
        }
        let (input_base, input_count) = owner.ok_or("folder_output_owner_missing")?;
        for input in input_base..input_base + input_count {
            if let Some((_, upstream)) = bind_pairs.iter().find(|(bound, _)| *bound == input) {
                visit(*upstream, coders, bind_pairs, states)?;
            }
        }
        states[output_index] = 2;
        Ok(())
    }

    let mut states = [0; SEVEN_Z_MAX_FOLDER_STREAMS as usize];
    let states = &mut states[..total_out as usize];
    visit(main_output_stream, coders, bind_pairs, states)?;
    if states.iter().any(|state| *state != 2) {
        return Err("folder_graph_disconnected");
    }
    Ok(())
}

fn parse_seven_zip_substreams_info(
    data: &[u8],
    pos: &mut usize,
    folders: &[SevenZipFolderAst],
    retain: bool,
) -> Result<Vec<Vec<SevenZipSubstreamAst>>, &'static str> {
    let mut counts = Vec::new();
    let mut nid = *data.get(*pos).ok_or("substreams_info_truncated")?;
    if nid == SZ_NUM_UNPACK_STREAM {
        *pos += 1;
        counts = seven_zip_vec(folders.len())?;
        for _ in folders {
            let count = read_sz_vint(data, pos).ok_or("substreams_info_count_truncated")?;
            counts.push(usize::try_from(count).map_err(|_| "substreams_info_count_too_large")?);
        }
        nid = *data.get(*pos).ok_or("substreams_info_truncated_after_counts")?;
    }
    let count_at = |index: usize| counts.get(index).copied().unwrap_or(1);
    let total_streams = (0..folders.len()).try_fold(0usize, |sum, index| sum.checked_add(count_at(index)))
        .ok_or("substreams_info_total_count_overflow")?;
    let explicit_sizes = total_streams - (0..folders.len()).filter(|&index| count_at(index) != 0).count();
    if nid == SZ_SIZE {
        if explicit_sizes > data.len().saturating_sub(*pos + 1) {
            return Err("substreams_info_size_truncated");
        }
        *pos += 1;
    } else if explicit_sizes != 0 {
        return Err("substreams_info_sizes_missing_for_multiple_streams");
    }
    let mut retained = if retain { seven_zip_vec(folders.len())? } else { Vec::new() };
    for (index, folder) in folders.iter().enumerate() {
        let count = count_at(index);
        let mut entries = if retain { seven_zip_vec(count)? } else { Vec::new() };
        let mut sum = 0u64;
        for _ in 0..count.saturating_sub(1) {
            let size = read_sz_vint(data, pos).ok_or("substreams_info_size_truncated")?;
            if retain { entries.push(SevenZipSubstreamAst { offset: sum, size, crc: None }); }
            sum = sum.checked_add(size).ok_or("substreams_info_size_sum_overflow")?;
        }
        let total = folder.unpack_size(folder.main_output_stream);
        if sum > total { return Err("substreams_info_sizes_exceed_folder_unpack_size"); }
        if retain {
            if count != 0 {
                entries.push(SevenZipSubstreamAst { offset: sum, size: total - sum,
                    crc: (count == 1).then_some(folder.expected_crc).flatten() });
            }
            retained.push(entries);
        }
    }
    if nid == SZ_SIZE {
        nid = *data.get(*pos).ok_or("substreams_info_truncated_after_sizes")?;
    }
    if nid == SZ_CRC {
        *pos += 1;
        let inherited = folders.iter().enumerate()
            .filter(|(index, folder)| count_at(*index) == 1 && folder.expected_crc.is_some()).count();
        let crc_count = total_streams - inherited;
        let defined = parse_seven_zip_crc_flags(data, pos, crc_count)?;
        if defined.defined_count(crc_count) > data.len().saturating_sub(*pos) / 4 {
            return Err("substreams_info_crc_truncated");
        }
        let mut crc_index = 0;
        for (index, folder) in folders.iter().enumerate() {
            let count = count_at(index);
            if count == 1 && folder.expected_crc.is_some() { continue; }
            for sub in 0..count {
                if defined.contains(crc_index) {
                    let crc = u32_le(data, *pos);
                    *pos += 4;
                    if retain { retained[index][sub].crc = Some(crc); }
                }
                crc_index += 1;
            }
        }
        nid = *data.get(*pos).ok_or("substreams_info_truncated_after_crc")?;
    }
    if nid != SZ_END { return Err("unsupported_substreams_info_nid"); }
    *pos += 1;
    Ok(retained)
}

enum SevenZipCrcFlags<'a> {
    All,
    Mask(&'a [u8]),
}

impl SevenZipCrcFlags<'_> {
    fn contains(&self, index: usize) -> bool {
        match self {
            Self::All => true,
            Self::Mask(bits) => bits[index / 8] & (0x80 >> (index % 8)) != 0,
        }
    }

    fn defined_count(&self, count: usize) -> usize {
        match self {
            Self::All => count,
            Self::Mask(bits) => {
                let mut defined = bits[..count / 8]
                    .iter()
                    .map(|byte| byte.count_ones() as usize)
                    .sum::<usize>();
                if count % 8 != 0 {
                    defined += (bits[count / 8] >> (8 - count % 8)).count_ones() as usize;
                }
                defined
            }
        }
    }
}

fn parse_seven_zip_crc_flags<'a>(
    data: &'a [u8],
    pos: &mut usize,
    count: usize,
) -> Result<SevenZipCrcFlags<'a>, &'static str> {
    if count == 0 {
        return Ok(SevenZipCrcFlags::All);
    }
    let all_defined = *data.get(*pos).ok_or("7z boolean vector is truncated")?;
    *pos += 1;
    if all_defined != 0 {
        if count > data.len().saturating_sub(*pos) / 4 {
            return Err("7z CRC values are truncated");
        }
        return Ok(SevenZipCrcFlags::All);
    }
    let byte_count = count.div_ceil(8);
    if byte_count > data.len().saturating_sub(*pos) {
        return Err("7z boolean bitset is truncated");
    }
    let mask = &data[*pos..*pos + byte_count];
    *pos += byte_count;
    Ok(SevenZipCrcFlags::Mask(mask))
}

fn skip_seven_zip_crcs(
    data: &[u8],
    pos: &mut usize,
    count: usize,
    truncated: &'static str,
) -> Result<(), &'static str> {
    let defined = parse_seven_zip_crc_flags(data, pos, count)?.defined_count(count);
    if defined > data.len().saturating_sub(*pos) / 4 {
        return Err(truncated);
    }
    *pos += defined * 4;
    Ok(())
}

fn parse_seven_zip_files_info(data: &[u8], pos: &mut usize) -> Result<(), &'static str> {
    let _num_files = read_sz_vint(data, pos).ok_or("7z FilesInfo file count is truncated")?;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z FilesInfo ended before End NID");
        };
        *pos += 1;
        if nid == SZ_END {
            break;
        }
        let size = read_sz_vint(data, pos).ok_or("7z FilesInfo property size is truncated")?;
        let prop_size =
            usize::try_from(size).map_err(|_| "7z FilesInfo property size is too large")?;
        let prop_end = (*pos)
            .checked_add(prop_size)
            .ok_or("7z FilesInfo property range overflowed")?;
        if prop_end > data.len() {
            return Err("7z FilesInfo property is truncated");
        }
        *pos = prop_end;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/formats/seven_zip/header/parse/seven_zip_streams_info_tests.rs"]
mod seven_zip_streams_info_tests;
