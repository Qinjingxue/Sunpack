#[pyfunction]
pub(crate) fn inspect_zip_local_header(
    py: Python<'_>,
    path: &str,
    offset: i64,
) -> PyResult<Py<PyDict>> {
    let offset = offset.max(0) as u64;
    let result = dict(py)?;
    result.set_item("offset", offset)?;
    result.set_item("magic_matched", false)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;

    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            let fault = ReadFault::from_io(error, "open", offset, 0, 0, 0)
                .with_field("zip.local_header.fixed", FieldLocation::Body);
            set_read_fault(&result, &fault, "os_error")?;
            return Ok(result.unbind());
        }
    };
    let file_size = reader.len();
    let header = match reader.read_exact_at(offset, ZIP_LOCAL_HEADER_LENGTH) {
        Ok(header) => header,
        Err(error) => {
            let fault = ReadFault::from_io(
                error,
                "read_exact_at",
                offset,
                ZIP_LOCAL_HEADER_LENGTH,
                0,
                file_size,
            )
            .with_field("zip.local_header.fixed", FieldLocation::Body);
            set_read_fault(&result, &fault, "short_header")?;
            return Ok(result.unbind());
        }
    };
    if &header[0..4] != b"PK\x03\x04" {
        result.set_item(
            "magic_matched",
            header.starts_with(b"PK\x03\x04")
                || header.starts_with(b"PK\x05\x06")
                || header.starts_with(b"PK\x07\x08"),
        )?;
        result.set_item("error", "bad_signature")?;
        return Ok(result.unbind());
    }

    let version_needed = u16_le(&header, 4);
    let compression_method = u16_le(&header, 8);
    let filename_len = u16_le(&header, 26) as u64;
    let extra_len = u16_le(&header, 28) as u64;
    if version_needed > 63 {
        result.set_item("error", "unsupported_version")?;
        return Ok(result.unbind());
    }
    if !matches!(
        compression_method,
        0 | 1 | 6 | 8 | 9 | 12 | 14 | 95 | 96 | 98 | 99
    ) {
        result.set_item("error", "unknown_compression_method")?;
        return Ok(result.unbind());
    }
    if filename_len == 0 || filename_len > 4096 {
        result.set_item("error", "invalid_filename_length")?;
        return Ok(result.unbind());
    }
    if offset + ZIP_LOCAL_HEADER_LENGTH as u64 + filename_len + extra_len > file_size {
        result.set_item("error", "header_exceeds_file_size")?;
        return Ok(result.unbind());
    }
    result.set_item("magic_matched", true)?;
    result.set_item("plausible", true)?;
    result.set_item("version_needed", version_needed)?;
    result.set_item("compression_method", compression_method)?;
    result.set_item("filename_len", filename_len)?;
    result.set_item("extra_len", extra_len)?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_cd_entries_to_walk=16))]
pub(crate) fn inspect_zip_eocd_structure(
    py: Python<'_>,
    path: &str,
    max_cd_entries_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let mut result = zip_eocd_empty(py, "")?;
    let Ok(reader) = ManagedReader::open(path) else {
        result.set_item("error", "os_error")?;
        return Ok(result.unbind());
    };
    let mut file = reader.cursor();
    let file_size = reader.len();
    if file_size < ZIP_EOCD_MIN_SIZE as u64 {
        result.set_item("error", "file_too_small")?;
        return Ok(result.unbind());
    }
    let read_size = file_size.min(ZIP_EOCD_MIN_SIZE as u64 + ZIP_EOCD_MAX_COMMENT);
    let mut tail = vec![0; read_size as usize];
    let tail_offset = file_size - read_size;
    if let Err(fault) = seek_field(
        &mut file,
        tail_offset,
        file_size,
        "zip.eocd_search_window",
        FieldLocation::Tail,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut tail,
            file_size,
            "zip.eocd_search_window",
            FieldLocation::Tail,
        )
    }) {
        set_read_fault(&result, &fault, "eocd_read_failed")?;
        return Ok(result.unbind());
    }
    if let Some((candidate_offset, candidate, comment_delta)) =
        find_eocd_candidate(&tail, file_size, read_size)
    {
        let candidate_entries = u16_le(&candidate, 10);
        let candidate_cd_size = u32_le(&candidate, 12) as u64;
        let candidate_cd_offset = u32_le(&candidate, 16) as u64;
        result.set_item("magic_matched", true)?;
        result.set_item("eocd_candidate_found", true)?;
        result.set_item("eocd_candidate_offset", candidate_offset)?;
        result.set_item("eocd_candidate_comment_length", u16_le(&candidate, 20))?;
        result.set_item("eocd_candidate_comment_available_delta", comment_delta)?;
        result.set_item(
            "eocd_candidate_declared_entry_count_present",
            candidate_entries > 0,
        )?;
        result.set_item(
            "eocd_candidate_declared_cd_offset_present",
            candidate_cd_offset > 0,
        )?;
        result.set_item("eocd_candidate_total_entries", candidate_entries)?;
        result.set_item("eocd_candidate_cd_offset", candidate_cd_offset)?;
        result.set_item("eocd_candidate_cd_size", candidate_cd_size)?;
    }
    let Some((eocd_offset, eocd)) = find_eocd(&tail, file_size, read_size) else {
        result.set_item("error", "eocd_not_found")?;
        return Ok(result.unbind());
    };
    let disk_number = u16_le(eocd, 4);
    let central_directory_disk = u16_le(eocd, 6);
    let disk_entries = u16_le(eocd, 8);
    let total_entries = u16_le(eocd, 10);
    let central_directory_size = u32_le(eocd, 12) as u64;
    let central_directory_offset = u32_le(eocd, 16) as u64;
    let comment_length = u16_le(eocd, 20) as u64;
    let eocd_end = eocd_offset + ZIP_EOCD_MIN_SIZE as u64 + comment_length;
    let trailing_bytes_after_eocd = file_size.saturating_sub(eocd_end);
    if file_size - eocd_offset - ZIP_EOCD_MIN_SIZE as u64 != comment_length {
        result.set_item("error", "comment_length_mismatch")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("comment_length", comment_length)?;
        result.set_item(
            "declared_central_directory_offset",
            central_directory_offset,
        )?;
        result.set_item("declared_central_directory_size", central_directory_size)?;
        result.set_item("declared_total_entries", total_entries)?;
        result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
        return Ok(result.unbind());
    }

    // APPNOTE 4.3.14/4.3.15: ZIP64 archives place the Zip64 end of central
    // directory record (56 bytes, size field 44) and its locator (20 bytes)
    // between the central directory and the plain EOCD.  When present, the
    // 8-byte fields in the Zip64 record are authoritative and the central
    // directory ends where the Zip64 record starts, not at the EOCD.
    let mut effective_disk_number = u64::from(disk_number);
    let mut effective_central_directory_disk = u64::from(central_directory_disk);
    let mut effective_disk_entries = u64::from(disk_entries);
    let mut effective_total_entries = u64::from(total_entries);
    let mut effective_central_directory_size = central_directory_size;
    let mut effective_central_directory_offset = central_directory_offset;
    let mut directory_end = eocd_offset;
    let mut zip64_eocd_present = false;
    let mut zip64_eocd_offset = 0u64;
    let mut zip64_declared_total_disks = 1u32;
    let tail_offset = file_size - read_size;
    if eocd_offset >= (ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE) as u64 {
        let tail_index = eocd_offset.saturating_sub(tail_offset) as usize;
        let block_len = ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE;
        if tail_index >= block_len && tail_index + ZIP_EOCD_MIN_SIZE <= tail.len() {
            let block = &tail[tail_index - block_len..tail_index];
            if &block[..4] == ZIP64_EOCD_SIGNATURE
                && u64_le(block, 4) == ZIP64_EOCD_RECORD_SIZE as u64 - 12
                && &block[ZIP64_EOCD_RECORD_SIZE..ZIP64_EOCD_RECORD_SIZE + 4]
                    == ZIP64_EOCD_LOCATOR_SIGNATURE
            {
                zip64_eocd_present = true;
                zip64_eocd_offset = eocd_offset - block_len as u64;
                zip64_declared_total_disks = u32_le(block, ZIP64_EOCD_RECORD_SIZE + 16);
                effective_disk_number = u64::from(u32_le(block, 16));
                effective_central_directory_disk = u64::from(u32_le(block, 20));
                effective_disk_entries = u64_le(block, 24);
                effective_total_entries = u64_le(block, 32);
                effective_central_directory_size = u64_le(block, 40);
                effective_central_directory_offset = u64_le(block, 48);
                directory_end = eocd_offset - block_len as u64;
            }
        }
    }

    let is_multi_disk =
        effective_disk_number != 0 || effective_central_directory_disk != 0;
    if is_multi_disk || effective_disk_entries != effective_total_entries {
        result.set_item(
            "error",
            if is_multi_disk {
                "zip_multi_disk"
            } else {
                "entry_count_mismatch"
            },
        )?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item(
            "central_directory_offset",
            effective_central_directory_offset,
        )?;
        result.set_item("central_directory_size", effective_central_directory_size)?;
        result.set_item("total_entries", effective_total_entries)?;
        result.set_item("comment_length", comment_length)?;
        result.set_item(
            "declared_central_directory_offset",
            effective_central_directory_offset,
        )?;
        result.set_item("declared_central_directory_size", effective_central_directory_size)?;
        result.set_item("declared_total_entries", effective_total_entries)?;
        result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
        result.set_item("is_multi_disk", is_multi_disk)?;
        result.set_item("disk_number", effective_disk_number)?;
        result.set_item("central_directory_disk", effective_central_directory_disk)?;
        result.set_item("disk_entries", effective_disk_entries)?;
        result.set_item(
            "declared_total_disks",
            if zip64_eocd_present {
                zip64_declared_total_disks
            } else {
                u32::from(disk_number) + 1
            },
        )?;
        result.set_item("zip64_eocd_present", zip64_eocd_present)?;
        result.set_item("zip64_eocd_offset", zip64_eocd_offset)?;
        return Ok(result.unbind());
    }

    let naive_physical_central_offset = directory_end.saturating_sub(effective_central_directory_size);
    let declared_physical_central_offset = effective_central_directory_offset;
    // Prefer the physically verified declared offset when the naive
    // back-computation misses the signature (same fallback as
    // formats/zip/directory/inspect.rs).  Otherwise keep the naive position
    // so SFX prefixes keep working via archive_offset.
    let physical_central_offset =
        if naive_physical_central_offset != declared_physical_central_offset {
            let naive_ok = has_central_directory_signature(
                &mut file,
                naive_physical_central_offset,
                file_size,
            );
            let declared_ok = has_central_directory_signature(
                &mut file,
                declared_physical_central_offset,
                file_size,
            );
            if !naive_ok && declared_ok {
                declared_physical_central_offset
            } else {
                naive_physical_central_offset
            }
        } else {
            naive_physical_central_offset
        };
    let archive_offset = physical_central_offset.saturating_sub(effective_central_directory_offset);
    result = dict(py)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;
    result.set_item("magic_matched", true)?;
    result.set_item("eocd_offset", eocd_offset)?;
    result.set_item("central_directory_offset", physical_central_offset)?;
    result.set_item("central_directory_size", effective_central_directory_size)?;
    result.set_item(
        "declared_central_directory_offset",
        effective_central_directory_offset,
    )?;
    result.set_item("declared_central_directory_size", effective_central_directory_size)?;
    result.set_item("declared_total_entries", effective_total_entries)?;
    result.set_item("physical_central_directory_offset", physical_central_offset)?;
    result.set_item("inferred_central_directory_offset", physical_central_offset)?;
    result.set_item(
        "inferred_central_directory_size",
        directory_end.saturating_sub(physical_central_offset),
    )?;
    result.set_item(
        "central_directory_offset_delta",
        physical_central_offset as i64 - effective_central_directory_offset as i64,
    )?;
    result.set_item(
        "central_directory_size_delta",
        directory_end.saturating_sub(physical_central_offset) as i64
            - effective_central_directory_size as i64,
    )?;
    result.set_item("entry_count_delta", 0i64)?;
    result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
    result.set_item("archive_offset", archive_offset)?;
    result.set_item("total_entries", effective_total_entries)?;
    result.set_item("is_multi_disk", false)?;
    result.set_item("disk_number", effective_disk_number)?;
    result.set_item("central_directory_disk", effective_central_directory_disk)?;
    result.set_item("disk_entries", effective_disk_entries)?;
    result.set_item(
        "declared_total_disks",
        if zip64_eocd_present {
            zip64_declared_total_disks
        } else {
            1u32
        },
    )?;
    result.set_item("comment_length", comment_length)?;
    result.set_item("zip64_eocd_present", zip64_eocd_present)?;
    result.set_item("zip64_eocd_offset", zip64_eocd_offset)?;
    result.set_item("central_directory_present", false)?;
    result.set_item("central_directory_entries_checked", 0)?;
    result.set_item("central_directory_walk_ok", false)?;
    result.set_item("local_header_links_checked", 0)?;
    result.set_item("local_header_links_ok", false)?;
    result.set_item("local_header_links_ok_count", 0)?;
    result.set_item("local_header_links_error_count", 0)?;
    if physical_central_offset
        .checked_add(effective_central_directory_size)
        .is_none_or(|end| end != directory_end)
    {
        result.set_item("error", "central_directory_size_mismatch")?;
        return Ok(result.unbind());
    }
    if effective_total_entries == 0 && effective_central_directory_size == 0 {
        result.set_item("plausible", true)?;
        result.set_item("central_directory_walk_ok", true)?;
        result.set_item("local_header_links_ok", true)?;
        return Ok(result.unbind());
    }
    if effective_central_directory_size < 4 {
        result.set_item("error", "central_directory_too_small")?;
        return Ok(result.unbind());
    }
    let mut sig = [0u8; 4];
    if let Err(fault) = seek_field(
        &mut file,
        physical_central_offset,
        file_size,
        "zip.central_directory.signature",
        FieldLocation::Tail,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut sig,
            file_size,
            "zip.central_directory.signature",
            FieldLocation::Tail,
        )
    }) {
        set_read_fault(&result, &fault, "central_directory_read_failed")?;
        return Ok(result.unbind());
    }
    if sig != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
        result.set_item("error", "bad_central_directory_signature")?;
        result.set_item(
            "bad_central_directory_signature_offset",
            physical_central_offset,
        )?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item("central_directory_present", true)?;
    let walk = match walk_zip_central_directory(
        &mut file,
        file_size,
        archive_offset,
        physical_central_offset,
        effective_central_directory_size,
        effective_total_entries as usize,
        max_cd_entries_to_walk,
    ) {
        Ok(walk) => walk,
        Err(fault) => {
            set_read_fault(&result, &fault, "central_directory_read_failed")?;
            result.set_item("plausible", false)?;
            return Ok(result.unbind());
        }
    };
    result.set_item("central_directory_entries_checked", walk.0)?;
    result.set_item("central_directory_walk_ok", walk.1)?;
    result.set_item(
        "entry_count_delta",
        walk.0 as i64 - effective_total_entries as i64,
    )?;
    result.set_item("local_header_links_checked", walk.2)?;
    result.set_item("local_header_links_ok", walk.3)?;
    result.set_item("local_header_links_ok_count", walk.2)?;
    result.set_item(
        "local_header_links_error_count",
        if walk.3 { 0usize } else { 1usize },
    )?;
    if !walk.4.is_empty() {
        result.set_item("error", walk.4)?;
        result.set_item("plausible", false)?;
    }
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_entries=128))]
pub(crate) fn inspect_zip_directory_consistency(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    crate::formats::zip::inspect_zip_directory_consistency(py, path, max_entries)
}

#[pyfunction]
#[pyo3(signature = (path, max_entries=128))]
pub(crate) fn inspect_zip_structure_graph(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    crate::formats::zip::inspect_zip_structure_graph(py, path, max_entries)
}

#[pyfunction]
#[pyo3(signature = (path, magic_bytes=None, max_next_header_check_bytes=1048576))]
pub(crate) fn inspect_seven_zip_structure(
    py: Python<'_>,
    path: &str,
    magic_bytes: Option<&[u8]>,
    max_next_header_check_bytes: u64,
) -> PyResult<Py<PyDict>> {
    let Ok(reader) = ManagedReader::open(path) else {
        return Ok(seven_empty(py, "os_error")?.unbind());
    };
    let mut file = reader.cursor();
    let file_size = reader.len();
    let mut header = magic_bytes.unwrap_or(&[]).to_vec();
    if header.len() < SEVEN_Z_HEADER_SIZE {
        header.resize(SEVEN_Z_HEADER_SIZE, 0);
        if let Err(fault) = seek_field(
            &mut file,
            0,
            file_size,
            "7z.start_header",
            FieldLocation::Head,
        )
        .and_then(|_| {
            read_exact_field(
                &mut file,
                &mut header,
                file_size,
                "7z.start_header",
                FieldLocation::Head,
            )
        }) {
            let out = seven_empty(py, "start_header_read_failed")?;
            set_read_fault(&out, &fault, "start_header_read_failed")?;
            return Ok(out.unbind());
        }
    }
    if file_size < SEVEN_Z_HEADER_SIZE as u64 {
        let out = seven_empty(py, "file_too_small")?;
        if header.starts_with(SEVEN_Z_SIGNATURE) {
            out.set_item("magic_matched", true)?;
            out.set_item("format", "7z")?;
            out.set_item("detected_ext", ".7z")?;
            out.set_item("evidence", PyList::new(py, ["7z:signature"])?)?;
        }
        return Ok(out.unbind());
    }
    if !header.starts_with(SEVEN_Z_SIGNATURE) {
        return Ok(seven_empty(py, "7z_signature_not_found")?.unbind());
    }
    let stored_start_crc = u32_le(&header, 8);
    let start_header = &header[12..32];
    let computed_start_crc = crc32(start_header);
    let next_header_offset = u64_le(start_header, 0);
    let next_header_size = u64_le(start_header, 8);
    let next_header_crc = u32_le(start_header, 16);
    let result = dict(py)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;
    result.set_item("magic_matched", true)?;
    result.set_item("format", "7z")?;
    result.set_item("detected_ext", ".7z")?;
    result.set_item("version_major", header[6])?;
    result.set_item("version_minor", header[7])?;
    result.set_item("next_header_offset", next_header_offset)?;
    result.set_item("next_header_size", next_header_size)?;
    result.set_item("next_header_crc", next_header_crc)?;
    result.set_item(
        "start_header_crc_ok",
        stored_start_crc == computed_start_crc,
    )?;
    result.set_item("next_header_crc_checked", false)?;
    result.set_item("next_header_crc_ok", false)?;
    result.set_item("next_header_nid", 0)?;
    result.set_item("next_header_nid_valid", false)?;
    result.set_item("next_header_semantic_ok", false)?;
    result.set_item("strong_accept", false)?;
    result.set_item("confidence", "none")?;
    let evidence = PyList::new(py, ["7z:signature"])?;
    result.set_item("evidence", &evidence)?;
    if header[6] != 0 {
        result.set_item("error", "unsupported_version")?;
        return Ok(result.unbind());
    }
    if stored_start_crc != computed_start_crc {
        result.set_item("error", "start_header_crc_mismatch")?;
        return Ok(result.unbind());
    }
    let Some(next_header_start) = (SEVEN_Z_HEADER_SIZE as u64).checked_add(next_header_offset)
    else {
        result.set_item("error", "next_header_out_of_range")?;
        return Ok(result.unbind());
    };
    if next_header_size == 0 || next_header_start < SEVEN_Z_HEADER_SIZE as u64 {
        result.set_item("error", "invalid_next_header_range")?;
        return Ok(result.unbind());
    }
    let Some(next_header_end) = next_header_start.checked_add(next_header_size) else {
        result.set_item("error", "next_header_out_of_range")?;
        return Ok(result.unbind());
    };
    if next_header_end > file_size {
        result.set_item("error", "next_header_out_of_range")?;
        let fault = ReadFault::short_read(
            "read_declared_range",
            next_header_start,
            next_header_size.min(usize::MAX as u64) as usize,
            file_size.saturating_sub(next_header_start) as usize,
            file_size,
        )
        .with_field("7z.next_header", FieldLocation::Tail);
        set_read_fault(&result, &fault, "next_header_out_of_range")?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item("confidence", "strong")?;
    evidence.append("7z:start_header_crc")?;
    evidence.append("7z:next_header_range")?;
    if next_header_size <= max_next_header_check_bytes {
        let mut next_header = vec![0; next_header_size as usize];
        if let Err(fault) = seek_field(
            &mut file,
            next_header_start,
            file_size,
            "7z.next_header",
            FieldLocation::Tail,
        )
        .and_then(|_| {
            read_exact_field(
                &mut file,
                &mut next_header,
                file_size,
                "7z.next_header",
                FieldLocation::Tail,
            )
        }) {
            set_read_fault(&result, &fault, "next_header_read_failed")?;
            result.set_item("plausible", false)?;
            return Ok(result.unbind());
        }
        let crc_ok = crc32(&next_header) == next_header_crc;
        let nid = next_header.first().copied().unwrap_or(0);
        let nid_valid = nid == 0x01 || nid == 0x17;
        result.set_item("next_header_crc_checked", true)?;
        result.set_item("next_header_crc_ok", crc_ok)?;
        result.set_item("next_header_nid", nid)?;
        result.set_item("next_header_nid_valid", nid_valid)?;
        result.set_item("next_header_semantic_ok", crc_ok && nid_valid)?;
        if crc_ok {
            evidence.append("7z:next_header_crc")?;
            if nid_valid {
                result.set_item("strong_accept", true)?;
                evidence.append("7z:next_header_nid")?;
            } else {
                result.set_item("error", "next_header_nid_unrecognized")?;
            }
        } else {
            result.set_item("error", "next_header_crc_mismatch")?;
        }
    }
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, magic_bytes=None, max_first_header_check_bytes=1048576))]
pub(crate) fn inspect_rar_structure(
    py: Python<'_>,
    path: &str,
    magic_bytes: Option<&[u8]>,
    max_first_header_check_bytes: u64,
) -> PyResult<Py<PyDict>> {
    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            let out = rar_empty(py, "os_error")?;
            let fault = ReadFault::from_io(error, "open", 0, 0, 0, 0)
                .with_field("rar.header_prefix", FieldLocation::Head);
            set_read_fault(&out, &fault, "os_error")?;
            return Ok(out.unbind());
        }
    };
    let mut file = reader.cursor();
    let file_size = reader.len();
    let mut data = magic_bytes.unwrap_or(&[]).to_vec();
    if data.len() < 64 {
        let read_size = file_size.min(64) as usize;
        data.resize(read_size, 0);
        if let Err(fault) = seek_field(
            &mut file,
            0,
            file_size,
            "rar.header_prefix",
            FieldLocation::Head,
        )
        .and_then(|_| {
            read_exact_field(
                &mut file,
                &mut data,
                file_size,
                "rar.header_prefix",
                FieldLocation::Head,
            )
        }) {
            let out = rar_empty(py, "header_prefix_read_failed")?;
            set_read_fault(&out, &fault, "header_prefix_read_failed")?;
            return Ok(out.unbind());
        }
    }
    if data.starts_with(RAR4_SIGNATURE) && data.len() >= RAR4_SIGNATURE.len() + 7 {
        let read_size = file_size.min(max_first_header_check_bytes);
        if data.len() < read_size as usize {
            data.resize(read_size as usize, 0);
            if let Err(fault) = seek_field(
                &mut file,
                0,
                file_size,
                "rar4.first_header",
                FieldLocation::Head,
            )
            .and_then(|_| {
                read_exact_field(
                    &mut file,
                    &mut data,
                    file_size,
                    "rar4.first_header",
                    FieldLocation::Head,
                )
            }) {
                let out = rar_empty(py, "first_header_read_failed")?;
                set_read_fault(&out, &fault, "first_header_read_failed")?;
                return Ok(out.unbind());
            }
        }
    } else if data.starts_with(RAR5_SIGNATURE) {
        if read_vint(&data, RAR5_SIGNATURE.len() + 4).is_some() {
            let read_size = file_size.min(max_first_header_check_bytes);
            if data.len() < read_size as usize {
                data.resize(read_size as usize, 0);
                if let Err(fault) = seek_field(
                    &mut file,
                    0,
                    file_size,
                    "rar5.first_header",
                    FieldLocation::Head,
                )
                .and_then(|_| {
                    read_exact_field(
                        &mut file,
                        &mut data,
                        file_size,
                        "rar5.first_header",
                        FieldLocation::Head,
                    )
                }) {
                    let out = rar_empty(py, "first_header_read_failed")?;
                    set_read_fault(&out, &fault, "first_header_read_failed")?;
                    return Ok(out.unbind());
                }
            }
        }
    }
    if data.starts_with(RAR5_SIGNATURE) {
        let out = inspect_rar5(py, &data, file_size)?;
        return finalize_rar_result(py, out, &data, file_size, 5);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        let out = inspect_rar4(py, &data, file_size)?;
        return finalize_rar_result(py, out, &data, file_size, 4);
    }
    if data.starts_with(b"Rar!") {
        let out = rar_empty(py, "rar_signature_incomplete_or_unknown")?;
        out.set_item("magic_matched", true)?;
        out.set_item("format", "rar")?;
        out.set_item("detected_ext", ".rar")?;
        out.set_item("evidence", PyList::new(py, ["rar:signature"])?)?;
        finish_fields(&out, RAR_FIELDS)?;
        return Ok(out.unbind());
    }
    let out = rar_empty(py, "rar_signature_not_found")?;
    finish_fields(&out, RAR_FIELDS)?;
    Ok(out.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_entries_to_walk=8, start_offset=0, end_offset=None))]
pub(crate) fn inspect_tar_header_structure(
    py: Python<'_>,
    path: &str,
    max_entries_to_walk: usize,
    start_offset: u64,
    end_offset: Option<u64>,
) -> PyResult<Py<PyDict>> {
    let Ok(reader) = ManagedReader::open(path) else {
        let out = tar_empty(py, "os_error")?;
        finish_fields(&out, TAR_FIELDS)?;
        return Ok(out.unbind());
    };
    let mut file = reader.cursor();
    let file_size = reader.len();
    let archive_end = end_offset.unwrap_or(file_size).min(file_size);
    if start_offset.saturating_add(TAR_BLOCK_SIZE as u64) > archive_end {
        let out = tar_empty(py, "file_too_small")?;
        finish_fields(&out, TAR_FIELDS)?;
        return Ok(out.unbind());
    }
    let mut header = vec![0; TAR_BLOCK_SIZE];
    if let Err(fault) = seek_field(
        &mut file,
        start_offset,
        archive_end,
        "tar.member.header",
        FieldLocation::Head,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut header,
            archive_end,
            "tar.member.header",
            FieldLocation::Head,
        )
    }) {
        let out = tar_empty(py, "header_read_failed")?;
        set_read_fault(&out, &fault, "header_read_failed")?;
        finish_fields(&out, TAR_FIELDS)?;
        return Ok(out.unbind());
    }
    let result = tar_empty(py, "")?;
    result.set_item("file_size", file_size)?;
    result.set_item("archive_start", start_offset)?;
    result.set_item("archive_end", archive_end)?;
    if header.iter().all(|b| *b == 0) {
        result.set_item("error", "leading_zero_block")?;
        result.set_item("zero_block", true)?;
        finish_fields(&result, TAR_FIELDS)?;
        return Ok(result.unbind());
    }
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    let computed = tar_checksum(&header);
    let name_nonempty = header[0..100].iter().any(|byte| *byte != 0);
    let numeric_fields_valid = stored_checksum.is_some()
        && member_size.is_some()
        && parse_octal(&header[100..108]).is_some()
        && parse_octal(&header[108..116]).is_some()
        && parse_octal(&header[116..124]).is_some()
        && parse_octal(&header[136..148]).is_some();
    let typeflag = header[156];
    let typeflag_valid = typeflag == 0 || (0x20..0x7f).contains(&typeflag);
    let payload_in_range = member_size
        .is_some_and(|size| start_offset + TAR_BLOCK_SIZE as u64 + size + padding_for_size(size) <= archive_end);
    result.set_item("stored_checksum", stored_checksum.unwrap_or(0))?;
    result.set_item("computed_checksum", computed)?;
    result.set_item("member_size", member_size.unwrap_or(0))?;
    result.set_item(
        "ustar_magic",
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )?;
    result.set_item("fuzzy_name_nonempty", name_nonempty)?;
    result.set_item("fuzzy_numeric_fields_valid", numeric_fields_valid)?;
    result.set_item("fuzzy_typeflag_valid", typeflag_valid)?;
    result.set_item("fuzzy_payload_in_range", payload_in_range)?;
    if stored_checksum.is_none() {
        result.set_item("error", "invalid_checksum_field")?;
        finish_fields(&result, TAR_FIELDS)?;
        return Ok(result.unbind());
    }
    if member_size.is_none() {
        result.set_item("error", "invalid_size_field")?;
        finish_fields(&result, TAR_FIELDS)?;
        return Ok(result.unbind());
    }
    if stored_checksum.unwrap() != computed {
        result.set_item("error", "checksum_mismatch")?;
        finish_fields(&result, TAR_FIELDS)?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item(
        "format",
        if matches!(&header[257..263], b"ustar\x00" | b"ustar ") {
            "ustar"
        } else {
            "tar"
        },
    )?;
    let walk = match walk_tar(&mut file, start_offset, archive_end, max_entries_to_walk) {
        Ok(walk) => walk,
        Err(fault) => {
            set_read_fault(&result, &fault, "member_header_read_failed")?;
            result.set_item("plausible", false)?;
            finish_fields(&result, TAR_FIELDS)?;
            return Ok(result.unbind());
        }
    };
    result.set_item("entries_checked", walk.0)?;
    result.set_item("entry_walk_ok", walk.1)?;
    result.set_item("end_zero_blocks", walk.2)?;
    if !walk.3.is_empty() {
        result.set_item("error", walk.3)?;
        result.set_item("plausible", false)?;
    }
    enrich_tar_semantics(&result, &mut file, start_offset, archive_end, max_entries_to_walk)?;
    Ok(result.unbind())
}

const UNIFIED_PREFILTER_ZIP: u32 = 1 << 0;
const UNIFIED_PREFILTER_RAR: u32 = 1 << 1;
const UNIFIED_PREFILTER_SEVEN_ZIP: u32 = 1 << 2;
const UNIFIED_PREFILTER_TAR: u32 = 1 << 3;
const UNIFIED_PREFILTER_COMPRESSION: u32 = 1 << 4;

pub(crate) fn unified_prefilter_mask_from_head(file_size: u64, head: &[u8]) -> u32 {
    let read = head.len().min(TAR_BLOCK_SIZE);
    let head = &head[..read];
    let mut rejected = 0;
    if file_size < TAR_BLOCK_SIZE as u64 {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    if read >= RAR5_SIGNATURE.len()
        && !head.starts_with(RAR4_SIGNATURE)
        && !head.starts_with(RAR5_SIGNATURE)
    {
        rejected |= UNIFIED_PREFILTER_RAR;
    }
    if read >= SEVEN_Z_SIGNATURE.len() && !head.starts_with(SEVEN_Z_SIGNATURE) {
        rejected |= UNIFIED_PREFILTER_SEVEN_ZIP;
    }
    if read >= 4
        && !head.starts_with(b"PK\x03\x04")
        && !head.starts_with(b"PK\x05\x06")
        && !head.starts_with(b"PK\x07\x08")
        && !head.starts_with(b"PK\x06\x06")
    {
        rejected |= UNIFIED_PREFILTER_ZIP;
    }
    if read >= XZ_MAGIC.len()
        && !head.starts_with(b"\x1f\x8b\x08")
        && !head.starts_with(b"BZh")
        && !head.starts_with(XZ_MAGIC)
        && !head.starts_with(ZSTD_MAGIC)
    {
        rejected |= UNIFIED_PREFILTER_COMPRESSION;
    }
    if read == TAR_BLOCK_SIZE
        && (head.iter().all(|byte| *byte == 0) || !tar_header_plausible(head).1.is_empty())
    {
        rejected |= UNIFIED_PREFILTER_TAR;
    }
    rejected
}

#[pyfunction]
pub(crate) fn inspect_compression_stream_identity(
    py: Python<'_>,
    path: &str,
) -> PyResult<Py<PyDict>> {
    inspect_compression_stream_identity_impl(py, path)
}

#[pyfunction]
pub(crate) fn inspect_compression_stream_structure(
    py: Python<'_>,
    path: &str,
) -> PyResult<Py<PyDict>> {
    let Ok((file_size, header)) = read_at(path, 0, 32) else {
        return compression_empty(py, "os_error", "", "", false);
    };
    if header.starts_with(b"\x1f\x8b") {
        return inspect_gzip(py, path, &header, file_size);
    }
    if header.starts_with(b"BZh") {
        return inspect_bzip2(py, path, &header, file_size);
    }
    if header.starts_with(XZ_MAGIC) {
        return inspect_xz(py, path, &header, file_size);
    }
    if header.starts_with(ZSTD_MAGIC) {
        return inspect_zstd(py, path, &header, file_size);
    }
    compression_empty(py, "compression_stream_magic_not_found", "", "", false)
}
