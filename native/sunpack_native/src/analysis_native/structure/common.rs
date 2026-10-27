fn dict<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    Ok(PyDict::new(py))
}

fn set_read_fault(
    result: &Bound<'_, PyDict>,
    fault: &ReadFault,
    legacy_error: &str,
) -> PyResult<()> {
    result.set_item("error", legacy_error)?;
    fault.write_python(result)?;
    let mut flags = vec!["read_error"];
    if fault.code == "unexpected_eof" {
        flags.push("input_truncated");
    }
    if fault.possible_missing_volume() {
        flags.push("missing_volume");
    }
    result.set_item("damage_flags", PyList::new(result.py(), flags)?)?;
    Ok(())
}

fn has_central_directory_signature(file: &mut SourceCursor, offset: u64, file_size: u64) -> bool {
    let mut sig = [0u8; 4];
    seek_field(
        file,
        offset,
        file_size,
        "zip.central_directory.signature",
        FieldLocation::Tail,
    )
    .and_then(|_| {
        read_exact_field(
            file,
            &mut sig,
            file_size,
            "zip.central_directory.signature",
            FieldLocation::Tail,
        )
    })
    .is_ok()
        && sig.as_slice() == ZIP_CENTRAL_DIRECTORY_SIGNATURE
}

fn find_eocd(tail: &[u8], file_size: u64, read_size: u64) -> Option<(u64, &[u8])> {
    let mut search_end = tail.len();
    loop {
        let index = rfind_subslice(&tail[..search_end], ZIP_EOCD_SIGNATURE)?;
        if tail.len() - index >= ZIP_EOCD_MIN_SIZE {
            let eocd = &tail[index..index + ZIP_EOCD_MIN_SIZE];
            let comment_length = u16_le(eocd, 20) as u64;
            let eocd_offset = file_size - read_size + index as u64;
            if file_size - eocd_offset - ZIP_EOCD_MIN_SIZE as u64 == comment_length {
                return Some((eocd_offset, eocd));
            }
        }
        if index == 0 {
            return None;
        }
        search_end = index;
    }
}

fn find_eocd_candidate(
    tail: &[u8],
    file_size: u64,
    read_size: u64,
) -> Option<(u64, [u8; ZIP_EOCD_MIN_SIZE], i64)> {
    let index = rfind_subslice(tail, ZIP_EOCD_SIGNATURE)?;
    if tail.len().saturating_sub(index) < ZIP_EOCD_MIN_SIZE {
        return None;
    }
    let mut record = [0u8; ZIP_EOCD_MIN_SIZE];
    record.copy_from_slice(&tail[index..index + ZIP_EOCD_MIN_SIZE]);
    let offset = file_size - read_size + index as u64;
    let available = tail.len().saturating_sub(index + ZIP_EOCD_MIN_SIZE) as i64;
    let declared = u16_le(&record, 20) as i64;
    Some((offset, record, available - declared))
}

fn walk_zip_central_directory(
    file: &mut SourceCursor,
    file_size: u64,
    archive_offset: u64,
    central_directory_offset: u64,
    central_directory_size: u64,
    total_entries: usize,
) -> Result<(usize, bool, usize, bool, &'static str), ReadFault> {
    if total_entries == 0 || central_directory_size == 0 {
        return Ok((
            0,
            total_entries == 0 && central_directory_size == 0,
            0,
            false,
            "",
        ));
    }
    let mut cursor = central_directory_offset;
    let central_end = central_directory_offset + central_directory_size;
    let mut checked = 0;
    for _ in 0..total_entries {
        if cursor + ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 > central_end
            || cursor + ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 > file_size
        {
            return Ok((checked, false, checked, false, "central_entry_out_of_range"));
        }
        let mut header = [0u8; ZIP_CENTRAL_DIRECTORY_HEADER_SIZE];
        seek_field(
            file,
            cursor,
            file_size,
            "zip.central_directory.entry_fixed",
            FieldLocation::Tail,
        )?;
        read_exact_field(
            file,
            &mut header,
            file_size,
            "zip.central_directory.entry_fixed",
            FieldLocation::Tail,
        )?;
        if &header[0..4] != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Ok((
                checked,
                false,
                checked,
                false,
                "bad_central_entry_signature",
            ));
        }
        let filename_len = u16_le(&header, 28) as u64;
        let extra_len = u16_le(&header, 30) as u64;
        let comment_len = u16_le(&header, 32) as u64;
        let disk_start = u16_le(&header, 34);
        let local_header_offset = u32_le(&header, 42) as u64;
        let entry_size =
            ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 + filename_len + extra_len + comment_len;
        if disk_start != 0 {
            return Ok((checked, false, checked, false, "central_entry_multi_disk"));
        }
        if filename_len == 0 {
            return Ok((
                checked,
                false,
                checked,
                false,
                "central_entry_invalid_filename_length",
            ));
        }
        if entry_size <= ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64
            || cursor + entry_size > central_end
        {
            return Ok((
                checked,
                false,
                checked,
                false,
                "central_entry_size_out_of_range",
            ));
        }
        let local_header_position = archive_offset + local_header_offset;
        if local_header_position < archive_offset
            || local_header_position + 4 > central_directory_offset
        {
            return Ok((
                checked,
                false,
                checked,
                false,
                "local_header_offset_out_of_range",
            ));
        }
        let mut sig = [0u8; 4];
        seek_field(
            file,
            local_header_position,
            file_size,
            "zip.local_header.signature",
            FieldLocation::Body,
        )?;
        read_exact_field(
            file,
            &mut sig,
            file_size,
            "zip.local_header.signature",
            FieldLocation::Body,
        )?;
        if &sig != b"PK\x03\x04" {
            return Ok((
                checked,
                false,
                checked,
                false,
                "local_header_link_bad_signature",
            ));
        }
        checked += 1;
        cursor += entry_size;
    }
    let complete =
        crate::formats::zip::central_directory_complete(cursor, central_end, |offset, length| {
            seek_field(
                file,
                offset,
                file_size,
                "zip.central_directory.signature",
                FieldLocation::Tail,
            )?;
            let mut header = vec![0; length];
            read_exact_field(
                file,
                &mut header,
                file_size,
                "zip.central_directory.signature",
                FieldLocation::Tail,
            )?;
            Ok::<_, ReadFault>(header)
        })?;
    Ok((
        checked,
        complete,
        checked,
        complete,
        if complete {
            ""
        } else {
            "central_directory_size_mismatch"
        },
    ))
}

fn zip_eocd_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    for (key, value) in [
        ("plausible", false),
        ("magic_matched", false),
        ("central_directory_present", false),
        ("central_directory_walk_ok", false),
        ("local_header_links_ok", false),
    ] {
        d.set_item(key, value)?;
    }
    d.set_item("error", error)?;
    d.set_item("eocd_candidate_found", false)?;
    d.set_item("eocd_candidate_declared_entry_count_present", false)?;
    d.set_item("eocd_candidate_declared_cd_offset_present", false)?;
    for key in [
        "eocd_offset",
        "central_directory_offset",
        "central_directory_size",
        "archive_offset",
        "total_entries",
        "comment_length",
        "central_directory_entries_checked",
        "local_header_links_checked",
        "eocd_candidate_offset",
        "eocd_candidate_comment_length",
        "eocd_candidate_comment_available_delta",
        "eocd_candidate_total_entries",
        "eocd_candidate_cd_offset",
        "eocd_candidate_cd_size",
    ] {
        d.set_item(key, 0)?;
    }
    Ok(d)
}
