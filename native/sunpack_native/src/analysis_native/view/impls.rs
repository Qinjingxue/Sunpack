impl AnalysisBinaryView {
    fn ensure_open(&self) -> PyResult<()> {
        if self.closed {
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "analysis binary view is closed",
            ))
        } else {
            Ok(())
        }
    }

    fn read_field_at_bytes(
        &self,
        offset: u64,
        size: usize,
        field: &'static str,
        location: FieldLocation,
    ) -> Result<Vec<u8>, ReadFault> {
        self.reader
            .read_exact_field_at(offset, size, field, location)
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        self.ensure_open()?;
        self.reader
            .read_at(offset, size)
            .map_err(reader_error_to_py)
    }

    fn read_tail_bytes(&self, size: usize) -> PyResult<Vec<u8>> {
        let view_size = self.reader.len();
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        self.read_at_bytes(offset, read_size)
    }

    fn walk_zip_central_directory(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        central_directory_size: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<(usize, bool, usize, bool, usize, &'static str)> {
        let mut cursor = physical_central_offset;
        let end = physical_central_offset + central_directory_size;
        let limit = total_entries.min(max_entries);
        let mut links_checked = 0usize;
        let mut encrypted_entries = 0usize;
        for index in 0..limit {
            if cursor + 46 > end {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    encrypted_entries,
                    "central_directory_entry_out_of_range",
                ));
            }
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    encrypted_entries,
                    "bad_central_directory_entry_signature",
                ));
            }
            if u16_le(&header, 8) & 0x0001 != 0 {
                encrypted_entries += 1;
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let entry_size = 46 + filename_len + extra_len + comment_len;
            if cursor + entry_size > end {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    encrypted_entries,
                    "central_directory_variable_fields_out_of_range",
                ));
            }
            if links_checked < max_entries {
                let local_sig = self.read_at_bytes(archive_offset + local_header_offset, 4)?;
                if local_sig.len() < 4 || local_sig.as_slice() != ZIP_LOCAL {
                    return Ok((
                        index + 1,
                        true,
                        links_checked,
                        false,
                        encrypted_entries,
                        "local_header_link_mismatch",
                    ));
                }
                links_checked += 1;
            }
            cursor += entry_size;
        }
        Ok((limit, true, links_checked, true, encrypted_entries, ""))
    }

    fn zip_content_integrity_warning(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<&'static str> {
        let mut cursor = physical_central_offset;
        for _ in 0..total_entries.min(max_entries).min(8) {
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok("");
            }
            let cd_crc = u32_le(&header, 16);
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let local = self.read_at_bytes(archive_offset + local_header_offset, 30)?;
            if local.len() >= 30 && &local[0..4] == ZIP_LOCAL {
                let flags = u16_le(&local, 6);
                let local_crc = u32_le(&local, 14);
                if flags & 0x0008 != 0 {
                    return Ok("data_descriptor_or_deferred_crc");
                }
                if local_crc != cd_crc {
                    return Ok("local_header_crc_mismatch");
                }
            }
            cursor += 46 + filename_len + extra_len + comment_len;
        }
        Ok("")
    }

    fn probe_rar4(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR4.len() as u64;
        let size = self.reader.len();
        let evidence = PyList::empty(py);
        evidence.append("rar4:signature")?;
        for index in 0..max_blocks {
            if cursor.saturating_add(7) > size {
                result.set_item("blocks_checked", index)?;
                let location = if index == 0 {
                    FieldLocation::Head
                } else {
                    FieldLocation::Tail
                };
                let fault = ReadFault::short_read(
                    "read_record",
                    cursor,
                    7,
                    size.saturating_sub(cursor) as usize,
                    size,
                )
                .with_field("rar4.block.header", location);
                set_view_read_fault(result, &fault, "rar4_block_header_out_of_range")?;
                return Ok(());
            }
            let fixed = self.read_at_bytes(cursor, 7)?;
            let header_crc = u16_le(&fixed, 0);
            let header_type = fixed[2];
            let header_flags = u16_le(&fixed, 3);
            let header_size = u16_le(&fixed, 5) as u64;
            if index == 0 {
                result.set_item("first_header_offset", cursor)?;
                result.set_item("first_header_type", header_type)?;
                result.set_item("first_header_size", header_size)?;
            } else if index == 1 {
                result.set_item("second_block_checked", true)?;
                result.set_item("second_block_type", header_type)?;
                result.set_item("second_block_size", header_size)?;
            }
            if !matches!(header_type, 0x72..=0x7B) {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_unknown_type")?;
                return Ok(());
            }
            if header_size < 7 || cursor.saturating_add(header_size) > size {
                result.set_item("blocks_checked", index)?;
                let location = if index == 0 {
                    FieldLocation::Head
                } else {
                    FieldLocation::Tail
                };
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor,
                    usize::try_from(header_size).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor) as usize,
                    size,
                )
                .with_field("rar4.block.header", location);
                set_view_read_fault(result, &fault, "rar4_block_size_out_of_range")?;
                return Ok(());
            }
            let full_header = self.read_at_bytes(cursor, header_size as usize)?;
            let crc_ok = (crc32(&full_header[2..]) & 0xFFFF) == header_crc as u32;
            if index == 0 {
                result.set_item("header_crc_checked", true)?;
                result.set_item("header_crc_ok", crc_ok)?;
            } else if index == 1 {
                result.set_item("second_block_ok", crc_ok)?;
            }
            if !crc_ok {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_crc_mismatch")?;
                result.set_item("damaged_header_type", header_type)?;
                let flag = match header_type {
                    0x73 => "rar_main_header_crc_bad",
                    0x74 => "rar_file_header_crc_bad",
                    0x7A => "rar_service_header_crc_bad",
                    0x7B => "rar_end_header_crc_bad",
                    _ => "rar_header_crc_bad",
                };
                result.set_item("damage_flags", PyList::new(py, [flag])?)?;
                return Ok(());
            }
            let mut block_size = header_size;
            if header_flags & 0x8000 != 0 {
                if header_size < 11 {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar4_block_add_size_missing")?;
                    return Ok(());
                }
                block_size += u32_le(&full_header, 7) as u64;
            }
            let next_cursor = cursor.saturating_add(block_size);
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor + header_size,
                    usize::try_from(block_size.saturating_sub(header_size)).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor + header_size) as usize,
                    size,
                )
                .with_field("rar4.block.payload", FieldLocation::Tail);
                set_view_read_fault(result, &fault, "rar4_block_payload_out_of_range")?;
                return Ok(());
            }
            if index == 0 && header_type != 0x73 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar4_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar4:main_header")?;
            } else if index == 1 {
                result.set_item("block_walk_ok", true)?;
            }
            // A validated plaintext main header that declares MHD_PASSWORD
            // (0x0080) means every following header is encrypted, so the block
            // walk cannot continue without the password.  Mirror the RAR5
            // encryption-header handling: this is strong structural evidence
            // of a password-protected archive, and reporting a truncated
            // chain here would misclassify a valid encrypted archive.  Stop at
            // the end of the main header (segment_end == 0 tells the caller to
            // derive the segment end from the next archive boundary) and let
            // extraction retry with the password.
            if index == 0 && header_flags & 0x0080 != 0 {
                evidence.append("rar4:encryption_header")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("header_encrypted", true)?;
                result.set_item("password_required", true)?;
                result.set_item("block_walk_ok", true)?;
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("segment_end", 0u64)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            if header_type == 0x7B {
                evidence.append("rar4:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("end_block_flags", u64::from(header_flags))?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar4_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }

    fn probe_rar5(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR5.len() as u64;
        let size = self.reader.len();
        let evidence = PyList::empty(py);
        evidence.append("rar5:signature")?;
        for index in 0..max_blocks {
            if cursor.saturating_add(6) > size {
                result.set_item("blocks_checked", index)?;
                let location = if index == 0 {
                    FieldLocation::Head
                } else {
                    FieldLocation::Tail
                };
                let fault = ReadFault::short_read(
                    "read_record",
                    cursor,
                    6,
                    size.saturating_sub(cursor) as usize,
                    size,
                )
                .with_field("rar5.block.header", location);
                set_view_read_fault(result, &fault, "rar5_block_header_out_of_range")?;
                return Ok(());
            }
            let first = self.read_at_bytes(cursor, 64)?;
            let Some((header_size, after_size)) = read_vint(&first, 4) else {
                result.set_item("blocks_checked", index)?;
                let location = if index == 0 {
                    FieldLocation::Head
                } else {
                    FieldLocation::Tail
                };
                let fault = ReadFault::short_read(
                    "parse_variable_integer",
                    cursor + 4,
                    4,
                    first.len().saturating_sub(4).min(4),
                    size,
                )
                .with_field("rar5.block.header_size", location);
                set_view_read_fault(result, &fault, "rar5_header_size_vint_missing")?;
                return Ok(());
            };
            if after_size.saturating_sub(4) > 3 {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_size_vint_too_long")?;
                return Ok(());
            }
            let header_total_size = 4u64
                .saturating_add((after_size - 4) as u64)
                .saturating_add(header_size);
            if header_size == 0 || cursor.saturating_add(header_total_size) > size {
                result.set_item("blocks_checked", index)?;
                let location = if index == 0 {
                    FieldLocation::Head
                } else {
                    FieldLocation::Tail
                };
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor,
                    usize::try_from(header_total_size).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor) as usize,
                    size,
                )
                .with_field("rar5.block.header", location);
                set_view_read_fault(result, &fault, "rar5_header_size_out_of_range")?;
                return Ok(());
            }
            let full = self.read_at_bytes(cursor, header_total_size as usize)?;
            let Some((header_type, after_type)) = read_vint(&full, after_size) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_type_vint_missing")?;
                return Ok(());
            };
            let Some((header_flags, after_flags)) = read_vint(&full, after_type) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_flags_vint_missing")?;
                return Ok(());
            };
            if index == 0 {
                result.set_item("first_header_offset", cursor)?;
                result.set_item("first_header_type", header_type)?;
                result.set_item("first_header_size", header_size)?;
            } else if index == 1 {
                result.set_item("second_block_checked", true)?;
                result.set_item("second_block_type", header_type)?;
                result.set_item("second_block_size", header_size)?;
            }
            if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_unknown_non_skippable_type")?;
                return Ok(());
            }
            let stored_crc = u32_le(&full, 0);
            let crc_ok = crc32(&full[4..]) == stored_crc;
            if index == 0 {
                result.set_item("header_crc_checked", true)?;
                result.set_item("header_crc_ok", crc_ok)?;
            } else if index == 1 {
                result.set_item("second_block_ok", crc_ok)?;
            }
            if !crc_ok {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_crc_mismatch")?;
                result.set_item("damaged_header_type", header_type)?;
                let flag = match header_type {
                    1 => "rar_main_header_crc_bad",
                    2 => "rar_file_header_crc_bad",
                    3 => "rar_service_header_crc_bad",
                    5 => "rar_end_header_crc_bad",
                    _ => "rar_header_crc_bad",
                };
                result.set_item("damage_flags", PyList::new(py, [flag])?)?;
                return Ok(());
            }
            let mut field_cursor = after_flags;
            if header_flags & 0x0001 != 0 {
                let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_extra_area_size_vint_missing")?;
                    return Ok(());
                };
                field_cursor = after_extra;
            }
            let mut data_size = 0u64;
            if header_flags & 0x0002 != 0 {
                let Some((value, _after_data)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_data_size_vint_missing")?;
                    return Ok(());
                };
                data_size = value;
            }
            let next_cursor = cursor
                .saturating_add(header_total_size)
                .saturating_add(data_size);
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor + header_total_size,
                    usize::try_from(data_size).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor + header_total_size) as usize,
                    size,
                )
                .with_field("rar5.block.payload", FieldLocation::Tail);
                set_view_read_fault(result, &fault, "rar5_block_payload_out_of_range")?;
                return Ok(());
            }
            // With RAR5 header encryption enabled the archive starts with a
            // plaintext encryption header (type 4); the main/file headers
            // that follow are encrypted and cannot be walked without the
            // password.  The encryption header itself is still protected by
            // the normal RAR5 header CRC, which we validated above, so it is
            // strong structural evidence rather than a missing-main-header
            // failure.
            if index == 0 && header_type == 4 && next_cursor + 16 <= size {
                evidence.append("rar5:encryption_header")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("header_encrypted", true)?;
                result.set_item("password_required", true)?;
                result.set_item("block_walk_ok", true)?;
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("segment_end", 0u64)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            if index == 0 && header_type != 1 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar5_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar5:main_header")?;
            } else if index == 1 {
                result.set_item("block_walk_ok", true)?;
            }
            if header_type == 5 {
                let end_flags = read_vint(&full, field_cursor)
                    .map(|(value, _)| value)
                    .unwrap_or(0);
                evidence.append("rar5:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("end_block_flags", end_flags)?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar5_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }

    fn walk_tar<'py>(
        &self,
        py: Python<'py>,
        start_offset: u64,
        max_entries: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "tar")?;
        result.set_item("magic_matched", false)?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("file_size", self.reader.len())?;
        result.set_item("stored_checksum", 0u64)?;
        result.set_item("computed_checksum", 0u64)?;
        result.set_item("member_size", 0u64)?;
        result.set_item("ustar_magic", false)?;
        result.set_item("zero_block", false)?;
        result.set_item("fuzzy_name_nonempty", false)?;
        result.set_item("fuzzy_numeric_fields_valid", false)?;
        result.set_item("fuzzy_typeflag_valid", false)?;
        result.set_item("fuzzy_payload_in_range", false)?;
        result.set_item("entries_checked", 0usize)?;
        result.set_item("entry_walk_ok", false)?;
        result.set_item("walk_complete", false)?;
        result.set_item("walk_budget_exhausted", false)?;
        result.set_item("end_zero_blocks", false)?;
        result.set_item("segment_end", py.None())?;
        result.set_item("boundary_confidence", "none")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;
        result.set_item("damage_flags", PyList::empty(py))?;

        let size = self.reader.len();
        let mut cursor = start_offset;
        let mut checked = 0usize;
        let mut zero_blocks = 0usize;
        if start_offset.saturating_add(TAR_BLOCK_SIZE as u64) > size {
            let fault = ReadFault::short_read(
                "read_record",
                start_offset,
                TAR_BLOCK_SIZE,
                size.saturating_sub(start_offset) as usize,
                size,
            )
            .with_field("tar.member.header", FieldLocation::Head);
            set_view_read_fault(&result, &fault, "short_tar_header")?;
            return Ok(result);
        }
        while (checked < max_entries || (max_entries == 0 && checked == 0))
            && cursor.saturating_add(TAR_BLOCK_SIZE as u64) <= size
        {
            let location = if checked == 0 {
                FieldLocation::Head
            } else {
                FieldLocation::Body
            };
            let header = match self.read_field_at_bytes(
                cursor,
                TAR_BLOCK_SIZE,
                "tar.member.header",
                location,
            ) {
                Ok(data) => data,
                Err(fault) => {
                    set_view_read_fault(&result, &fault, "tar_header_read_failed")?;
                    return Ok(result);
                }
            };
            if header.iter().all(|byte| *byte == 0) {
                if checked == 0 {
                    result.set_item("zero_block", true)?;
                    result.set_item("error", "leading_zero_block")?;
                    return Ok(result);
                }
                zero_blocks += 1;
                cursor += TAR_BLOCK_SIZE as u64;
                if zero_blocks >= 2 {
                    result.set_item("plausible", checked > 0)?;
                    result.set_item("entries_checked", checked)?;
                    result.set_item("entry_walk_ok", checked > 0)?;
                    result.set_item("walk_complete", true)?;
                    result.set_item("end_zero_blocks", true)?;
                    result.set_item("segment_end", cursor)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(
                            py,
                            [
                                "tar:header_checksum",
                                "tar:block_walk",
                                "tar:end_zero_blocks",
                            ],
                        )?,
                    )?;
                    return Ok(result);
                }
                continue;
            }
            // Candidate recognition belongs to the native walker.  This lets
            // Python dispatch damaged TAR files without re-reading or parsing
            // archive bytes as a fallback.
            result.set_item("magic_matched", true)?;
            zero_blocks = 0;
            if checked == 0 {
                let stored_checksum = parse_octal(&header[148..156]);
                let member_size = parse_octal(&header[124..136]);
                let computed_checksum = tar_checksum(&header);
                let ustar_magic = matches!(&header[257..263], b"ustar\x00" | b"ustar ");
                let numeric_fields_valid = stored_checksum.is_some()
                    && member_size.is_some()
                    && parse_octal(&header[100..108]).is_some()
                    && parse_octal(&header[108..116]).is_some()
                    && parse_octal(&header[116..124]).is_some()
                    && parse_octal(&header[136..148]).is_some();
                let typeflag_valid = header[156] == 0 || (0x20..0x7f).contains(&header[156]);
                let payload_in_range = member_size.is_some_and(|member_size| {
                    cursor
                        .saturating_add(TAR_BLOCK_SIZE as u64)
                        .saturating_add(member_size)
                        .saturating_add(tar_padding(member_size))
                        <= size
                });
                result.set_item("stored_checksum", stored_checksum.unwrap_or(0))?;
                result.set_item("computed_checksum", computed_checksum)?;
                result.set_item("member_size", member_size.unwrap_or(0))?;
                result.set_item("ustar_magic", ustar_magic)?;
                result.set_item("format", if ustar_magic { "ustar" } else { "tar" })?;
                result.set_item(
                    "fuzzy_name_nonempty",
                    header[0..100].iter().any(|byte| *byte != 0),
                )?;
                result.set_item("fuzzy_numeric_fields_valid", numeric_fields_valid)?;
                result.set_item("fuzzy_typeflag_valid", typeflag_valid)?;
                result.set_item("fuzzy_payload_in_range", payload_in_range)?;
            }
            let (ok, error, member_size, ustar) = tar_header_plausible(&header);
            if !ok {
                result.set_item("entries_checked", checked)?;
                result.set_item("error", error)?;
                let flag = match header[156] {
                    b'x' | b'g' => "pax_header_bad",
                    b'L' | b'K' => "gnu_longname_bad",
                    b'S' => "sparse_header_bad",
                    _ if error == "checksum_mismatch" => "tar_checksum_bad",
                    _ => "tar_metadata_bad",
                };
                result.set_item("damage_flags", PyList::new(py, [flag])?)?;
                if checked > 0 {
                    result.set_item("plausible", true)?;
                    result.set_item("entry_walk_ok", true)?;
                    result.set_item("segment_end", py.None())?;
                    result.set_item("boundary_confidence", "none")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
                    )?;
                }
                return Ok(result);
            }
            if max_entries == 0 {
                result.set_item("plausible", true)?;
                result.set_item("validation_scope", "format_identity")?;
                result.set_item("identity_strong", true)?;
                result.set_item("entries_checked", 0usize)?;
                result.set_item("entry_walk_ok", false)?;
                result.set_item("end_zero_blocks", false)?;
                result.set_item("damage_flags", PyList::empty(py))?;
                return Ok(result);
            }
            let mut sparse_extension_span = 0u64;
            if header[156] == b'S' {
                let mut previous_end = 0u64;
                let mut extended = header[482] != 0 && header[482] != b'0';
                if !tar_sparse_map_valid(&header, 386, 4, &mut previous_end) {
                    result.set_item("error", "invalid_oldgnu_sparse_map")?;
                    result.set_item("damage_flags", PyList::new(py, ["sparse_header_bad"])?)?;
                    result.set_item("plausible", checked > 0)?;
                    result.set_item("entry_walk_ok", checked > 0)?;
                    return Ok(result);
                }
                while extended {
                    if sparse_extension_span >= (TAR_BLOCK_SIZE as u64) * 65536 {
                        result.set_item("error", "oldgnu_sparse_extension_limit")?;
                        result.set_item("damage_flags", PyList::new(py, ["sparse_header_bad"])?)?;
                        result.set_item("plausible", checked > 0)?;
                        result.set_item("entry_walk_ok", checked > 0)?;
                        return Ok(result);
                    }
                    let extension_offset = cursor
                        .saturating_add(TAR_BLOCK_SIZE as u64)
                        .saturating_add(sparse_extension_span);
                    let extension = match self.read_field_at_bytes(
                        extension_offset,
                        TAR_BLOCK_SIZE,
                        "tar.gnu_sparse.extension",
                        FieldLocation::Body,
                    ) {
                        Ok(data) => data,
                        Err(fault) => {
                            set_view_read_fault(&result, &fault, "invalid_oldgnu_sparse_extension")?;
                            result.set_item("damage_flags", PyList::new(py, ["sparse_header_bad"])?)?;
                            return Ok(result);
                        }
                    };
                    if !tar_sparse_map_valid(&extension, 0, 21, &mut previous_end) {
                        result.set_item("error", "invalid_oldgnu_sparse_extension")?;
                        result.set_item("damage_flags", PyList::new(py, ["sparse_header_bad"])?)?;
                        result.set_item("plausible", checked > 0)?;
                        result.set_item("entry_walk_ok", checked > 0)?;
                        return Ok(result);
                    }
                    sparse_extension_span += TAR_BLOCK_SIZE as u64;
                    extended = extension[504] != 0 && extension[504] != b'0';
                }
                if parse_octal(&header[483..495]).is_some_and(|real_size| previous_end > real_size) {
                    result.set_item("error", "oldgnu_sparse_extent_out_of_range")?;
                    result.set_item("damage_flags", PyList::new(py, ["sparse_header_bad"])?)?;
                    result.set_item("plausible", checked > 0)?;
                    result.set_item("entry_walk_ok", checked > 0)?;
                    return Ok(result);
                }
            }
            let payload_start = cursor
                .saturating_add(TAR_BLOCK_SIZE as u64)
                .saturating_add(sparse_extension_span);
            let next_cursor = payload_start
                .saturating_add(member_size)
                .saturating_add(tar_padding(member_size));
            if next_cursor > size {
                result.set_item("entries_checked", checked)?;
                let requested = member_size.saturating_add(tar_padding(member_size));
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    payload_start,
                    usize::try_from(requested).unwrap_or(usize::MAX),
                    size.saturating_sub(payload_start) as usize,
                    size,
                )
                .with_field("tar.member.payload", FieldLocation::Tail);
                set_view_read_fault(&result, &fault, "member_payload_out_of_range")?;
                if checked > 0 {
                    result.set_item("plausible", true)?;
                    result.set_item("entry_walk_ok", true)?;
                    result.set_item("segment_end", py.None())?;
                    result.set_item("boundary_confidence", "none")?;
                }
                return Ok(result);
            }
            checked += 1;
            cursor = next_cursor;
            result.set_item(
                "evidence",
                PyList::new(
                    py,
                    [
                        "tar:header_checksum",
                        if ustar {
                            "tar:ustar_magic"
                        } else {
                            "tar:v7_header"
                        },
                    ],
                )?,
            )?;
        }
        if checked > 0 && checked >= max_entries && cursor.saturating_add(TAR_BLOCK_SIZE as u64) <= size {
            result.set_item("plausible", true)?;
            result.set_item("entries_checked", checked)?;
            result.set_item("entry_walk_ok", true)?;
            result.set_item("walk_budget_exhausted", true)?;
            result.set_item("segment_end", py.None())?;
            result.set_item("boundary_confidence", "none")?;
            result.set_item("error", "tar_walk_budget_exhausted")?;
            result.set_item("damage_flags", PyList::empty(py))?;
            result.set_item(
                "evidence",
                PyList::new(py, ["tar:header_checksum", "tar:block_walk_sample"])?
            )?;
        } else if checked > 0 && cursor == size {
            result.set_item("plausible", true)?;
            result.set_item("entries_checked", checked)?;
            result.set_item("entry_walk_ok", true)?;
            result.set_item("walk_complete", true)?;
            result.set_item("segment_end", cursor)?;
            result.set_item("boundary_confidence", "medium")?;
            result.set_item("error", "tar_end_zero_blocks_missing_at_eof")?;
            result.set_item("damage_flags", PyList::new(py, ["missing_end_block"])?)?;
            result.set_item(
                "evidence",
                PyList::new(py, ["tar:header_checksum", "tar:block_walk", "tar:eof_boundary"])?
            )?;
        } else if checked > 0 {
            result.set_item("plausible", true)?;
            result.set_item("entries_checked", checked)?;
            result.set_item("entry_walk_ok", true)?;
            result.set_item("segment_end", py.None())?;
            result.set_item("boundary_confidence", "none")?;
            let fault = ReadFault::short_read(
                "read_record",
                cursor,
                TAR_BLOCK_SIZE * 2,
                size.saturating_sub(cursor).min((TAR_BLOCK_SIZE * 2) as u64) as usize,
                size,
            )
            .with_field("tar.archive.end_zero_blocks", FieldLocation::Tail);
            set_view_read_fault(&result, &fault, "tar_end_zero_blocks_not_found")?;
            result.set_item(
                "evidence",
                PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
            )?;
        }
        Ok(result)
    }

    fn probe_compression<'py>(
        &self,
        py: Python<'py>,
        format: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", format)?;
        result.set_item("magic_matched", false)?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("confidence", 0.0f64)?;
        result.set_item("boundary_confidence", "medium")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;
        result.set_item("damage_flags", PyList::empty(py))?;
        let header = self.read_at_bytes(0, 64)?;
        match format {
            "gzip" => {
                if !header.starts_with(GZIP) {
                    result.set_item("error", "gzip_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 10 || header[3] & 0xE0 != 0 {
                    result.set_item("error", "gzip_reserved_flags_set")?;
                    result.set_item(
                        "damage_flags",
                        PyList::new(py, ["gzip_reserved_flags_set"])?,
                    )?;
                    return Ok(result);
                }
                if header[3] & 0x02 != 0 && header.len() >= 12 {
                    let stored_header_crc = u16_le(&header, 10) as u32;
                    if crc32(&header[..10]) & 0xFFFF != stored_header_crc {
                        result.set_item("error", "gzip_header_crc_mismatch")?;
                        result
                            .set_item("damage_flags", PyList::new(py, ["gzip_header_crc_bad"])?)?;
                        return Ok(result);
                    }
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.90f64)?;
                let evidence = PyList::new(
                    py,
                    ["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"],
                )?;
                if self.reader.len() >= 18 {
                    let tail = self.read_tail_bytes(4)?;
                    if tail.len() == 4 {
                        result.set_item("isize", u32_le(&tail, 0))?;
                        evidence.append("gzip:trailer")?;
                    }
                }
                result.set_item("evidence", evidence)?;
            }
            "bzip2" => {
                if !header.starts_with(BZIP2) {
                    result.set_item("error", "bzip2_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                let ok = header.len() >= 10
                    && b"123456789".contains(&header[3])
                    && (&header[4..10] == b"\x31\x41\x59\x26\x53\x59"
                        || &header[4..10] == b"\x17\x72\x45\x38\x50\x90");
                if !ok {
                    result.set_item("error", "bzip2_block_marker_not_found")?;
                    let flag = if header.len() >= 4
                        && header.starts_with(BZIP2)
                        && !b"123456789".contains(&header[3])
                    {
                        "bzip2_block_size_bad"
                    } else {
                        "bzip2_block_bad"
                    };
                    result.set_item("damage_flags", PyList::new(py, [flag])?)?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.92f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["bzip2:magic", "bzip2:block_marker"])?,
                )?;
            }
            "xz" => {
                if !header.starts_with(XZ) {
                    result.set_item("error", "xz_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 12 || u32_le(&header, 8) != crc32(&header[6..8]) {
                    result.set_item("error", "xz_header_crc_mismatch")?;
                    result.set_item("damage_flags", PyList::new(py, ["xz_header_crc_bad"])?)?;
                    return Ok(result);
                }
                let footer = self.read_tail_bytes(12)?;
                if footer.len() == 12 && &footer[10..12] == b"YZ" {
                    if u32_le(&footer, 0) != crc32(&footer[4..10]) || footer[8..10] != header[6..8]
                    {
                        result.set_item("error", "xz_footer_crc_mismatch")?;
                        result.set_item("damage_flags", PyList::new(py, ["xz_footer_crc_bad"])?)?;
                        return Ok(result);
                    }
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.95f64)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["xz:magic", "xz:footer_magic"])?,
                    )?;
                } else {
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.72f64)?;
                    result.set_item("error", "xz_footer_magic_not_found")?;
                    result.set_item("damage_flags", PyList::new(py, ["xz_footer_crc_bad"])?)?;
                    result.set_item("evidence", PyList::new(py, ["xz:magic"])?)?;
                }
            }
            "zstd" => {
                if !header.starts_with(ZSTD) {
                    result.set_item("error", "zstd_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 6 || header[4] & 0x08 != 0 {
                    result.set_item("error", "zstd_reserved_bit_set")?;
                    result.set_item("damage_flags", PyList::new(py, ["zstd_frame_bad"])?)?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.88f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["zstd:magic", "zstd:frame_descriptor"])?,
                )?;
            }
            _ => {
                result.set_item("error", "unsupported_compression_format")?;
            }
        }
        Ok(result)
    }
}

fn zip_archive_start_kind(
    reader: &ManagedReader,
    spanned: bool,
    empty: bool,
    zip64_eocd_offset: Option<u64>,
) -> PyResult<&'static str> {
    // Keep this check on the same ManagedReader as the structural probe.  It
    // therefore shares the existing read budget, concurrency gate, and both
    // request/global caches instead of reopening the source from Python.
    let head = reader.read_at(0, 8).map_err(reader_error_to_py)?;
    if head.starts_with(ZIP_LOCAL) {
        Ok("local_header")
    } else if empty && head.starts_with(ZIP_EOCD) {
        Ok("empty_eocd")
    } else if spanned && head.as_slice() == b"PK\x07\x08PK\x03\x04" {
        Ok("split_marker")
    } else if empty && zip64_eocd_offset == Some(0) && head.starts_with(ZIP64_EOCD) {
        Ok("zip64_eocd")
    } else {
        Ok("")
    }
}

impl AnalysisMultiVolumeView {
    fn ensure_open(&self) -> PyResult<()> {
        if self.closed {
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "analysis multi-volume view is closed",
            ))
        } else {
            Ok(())
        }
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        self.ensure_open()?;
        self.reader
            .read_at(offset, size)
            .map_err(reader_error_to_py)
    }
}
