// Native RAR observation shared by single-file and multi-volume analysis.
// Parsing and I/O run detached; only the completed facts cross into Python.
#[derive(Default)]
struct RarObservation {
    plausible: bool,
    magic_matched: bool,
    strong_accept: bool,
    error: &'static str,
    archive_offset: u64,
    segment_end: u64,
    version: u8,
    blocks_checked: usize,
    end_block_found: bool,
    end_block_flags: u64,
    first_header_offset: u64,
    first_header_size: u64,
    first_header_type: u64,
    header_crc_checked: bool,
    header_crc_ok: bool,
    second_block_checked: bool,
    second_block_ok: bool,
    second_block_type: u64,
    second_block_size: u64,
    block_walk_ok: bool,
    evidence: Vec<&'static str>,
    damage_flags: Vec<&'static str>,
    damaged_header_type: Option<u64>,
    header_encrypted: Option<bool>,
    password_required: Option<bool>,
    read_fault: Option<(ReadFault, &'static str)>,
}

impl RarObservation {
    fn to_python(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "rar")?;
        result.set_item("plausible", &self.plausible)?;
        result.set_item("magic_matched", &self.magic_matched)?;
        result.set_item("strong_accept", &self.strong_accept)?;
        result.set_item("error", &self.error)?;
        result.set_item("archive_offset", &self.archive_offset)?;
        result.set_item("segment_end", &self.segment_end)?;
        result.set_item("version", &self.version)?;
        result.set_item("blocks_checked", &self.blocks_checked)?;
        result.set_item("end_block_found", &self.end_block_found)?;
        result.set_item("end_block_flags", &self.end_block_flags)?;
        result.set_item("first_header_offset", &self.first_header_offset)?;
        result.set_item("first_header_size", &self.first_header_size)?;
        result.set_item("first_header_type", &self.first_header_type)?;
        result.set_item("header_crc_checked", &self.header_crc_checked)?;
        result.set_item("header_crc_ok", &self.header_crc_ok)?;
        result.set_item("second_block_checked", &self.second_block_checked)?;
        result.set_item("second_block_ok", &self.second_block_ok)?;
        result.set_item("second_block_type", &self.second_block_type)?;
        result.set_item("second_block_size", &self.second_block_size)?;
        result.set_item("block_walk_ok", &self.block_walk_ok)?;
        result.set_item("evidence", &self.evidence)?;
        if !self.damage_flags.is_empty() {
            result.set_item("damage_flags", &self.damage_flags)?;
        }
        if let Some(value) = self.damaged_header_type {
            result.set_item("damaged_header_type", value)?;
        }
        if let Some(value) = self.header_encrypted {
            result.set_item("header_encrypted", value)?;
        }
        if let Some(value) = self.password_required {
            result.set_item("password_required", value)?;
        }
        if let Some((fault, legacy)) = &self.read_fault {
            set_view_read_fault(&result, fault, legacy)?;
        }
        Ok(result.unbind())
    }
}

impl AnalysisBinaryView {
    fn probe_rar_native(&self, start_offset: u64) -> PyResult<RarObservation> {
        self.ensure_open()?;
        let mut result = RarObservation {
            archive_offset: start_offset,
            ..Default::default()
        };
        let header = match self.read_field_at_bytes(
            start_offset,
            RAR5.len(),
            "rar.signature",
            FieldLocation::Head,
        ) {
            Ok(data) => data,
            Err(fault) => {
                result.read_fault = Some((fault, "rar_signature_incomplete_or_unknown"));
                return Ok(result);
            }
        };
        if header.starts_with(RAR5) {
            result.magic_matched = true;
            result.version = 5;
            self.probe_rar5(&mut result, start_offset)?;
        } else if header.starts_with(RAR4) {
            result.magic_matched = true;
            result.version = 4;
            self.probe_rar4(&mut result, start_offset)?;
        } else if header.starts_with(b"Rar!") {
            result.magic_matched = true;
            result.error = "rar_signature_incomplete_or_unknown";
        } else {
            result.error = "rar_signature_not_found";
        }
        Ok(result)
    }

    fn probe_rar4(
        &self,
        result: &mut RarObservation,
        start_offset: u64,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR4.len() as u64;
        let size = self.reader.len();
        let mut evidence = Vec::new();
        evidence.push("rar4:signature");
        let mut index = 0;
        loop {
            if cursor.saturating_add(7) > size {
                result.blocks_checked = index;
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
                result.read_fault = Some((fault, "rar4_block_header_out_of_range"));
                return Ok(());
            }
            let fixed = self.read_at_bytes(cursor, 7)?;
            let header_crc = u16_le(&fixed, 0);
            let header_type = fixed[2];
            let header_flags = u16_le(&fixed, 3);
            let header_size = u16_le(&fixed, 5) as u64;
            if index == 0 {
                result.first_header_offset = cursor;
                result.first_header_type = u64::from(header_type);
                result.first_header_size = header_size;
            } else if index == 1 {
                result.second_block_checked = true;
                result.second_block_type = u64::from(header_type);
                result.second_block_size = header_size;
            }
            if !matches!(header_type, 0x72..=0x7B) {
                result.blocks_checked = index;
                result.error = "rar4_block_unknown_type";
                return Ok(());
            }
            if header_size < 7 || cursor.saturating_add(header_size) > size {
                result.blocks_checked = index;
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
                result.read_fault = Some((fault, "rar4_block_size_out_of_range"));
                return Ok(());
            }
            let full_header = self.read_at_bytes(cursor, header_size as usize)?;
            let crc_ok = (crc32(&full_header[2..]) & 0xFFFF) == header_crc as u32;
            if index == 0 {
                result.header_crc_checked = true;
                result.header_crc_ok = crc_ok;
            } else if index == 1 {
                result.second_block_ok = crc_ok;
            }
            if !crc_ok {
                result.blocks_checked = index;
                result.error = "rar4_block_crc_mismatch";
                result.damaged_header_type = Some(header_type as u64);
                let flag = match header_type {
                    0x73 => "rar_main_header_crc_bad",
                    0x74 => "rar_file_header_crc_bad",
                    0x7A => "rar_service_header_crc_bad",
                    0x7B => "rar_end_header_crc_bad",
                    _ => "rar_header_crc_bad",
                };
                result.damage_flags = vec![flag];
                return Ok(());
            }
            let Some(data_size) = crate::formats::rar::rar4_data_size(&full_header) else {
                result.blocks_checked = index;
                result.error = "rar4_block_add_size_missing";
                return Ok(());
            };
            let block_size = header_size.saturating_add(data_size);
            let next_cursor = cursor.saturating_add(block_size);
            if next_cursor > size {
                result.blocks_checked = index;
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor + header_size,
                    usize::try_from(block_size.saturating_sub(header_size)).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor + header_size) as usize,
                    size,
                )
                .with_field("rar4.block.payload", FieldLocation::Tail);
                result.read_fault = Some((fault, "rar4_block_payload_out_of_range"));
                return Ok(());
            }
            if index == 0 && header_type != 0x73 {
                result.blocks_checked = 1usize;
                result.error = "rar4_main_header_missing";
                return Ok(());
            }
            if index == 0 {
                evidence.push("rar4:main_header");
            } else if index == 1 {
                result.block_walk_ok = true;
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
                evidence.push("rar4:encryption_header");
                result.plausible = true;
                result.strong_accept = true;
                result.header_encrypted = Some(true);
                result.password_required = Some(true);
                result.block_walk_ok = true;
                result.blocks_checked = 1usize;
                result.segment_end = 0;
                result.evidence = evidence;
                return Ok(());
            }
            if header_type == 0x7B {
                evidence.push("rar4:end_block");
                result.plausible = true;
                result.strong_accept = true;
                result.blocks_checked = index + 1;
                result.end_block_found = true;
                result.end_block_flags = u64::from(header_flags);
                result.segment_end = next_cursor;
                result.evidence = evidence;
                return Ok(());
            }
            cursor = next_cursor;
            index += 1;
        }
    }

    fn probe_rar5(
        &self,
        result: &mut RarObservation,
        start_offset: u64,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR5.len() as u64;
        let size = self.reader.len();
        let mut evidence = Vec::new();
        evidence.push("rar5:signature");
        let mut index = 0;
        loop {
            if cursor.saturating_add(6) > size {
                result.blocks_checked = index;
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
                result.read_fault = Some((fault, "rar5_block_header_out_of_range"));
                return Ok(());
            }
            let first = self.read_at_bytes(cursor, 64)?;
            let Some((header_size, after_size)) = read_vint(&first, 4) else {
                result.blocks_checked = index;
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
                result.read_fault = Some((fault, "rar5_header_size_vint_missing"));
                return Ok(());
            };
            if after_size.saturating_sub(4) > 3 {
                result.blocks_checked = index;
                result.error = "rar5_header_size_vint_too_long";
                return Ok(());
            }
            let header_total_size = 4u64
                .saturating_add((after_size - 4) as u64)
                .saturating_add(header_size);
            if header_size == 0 || cursor.saturating_add(header_total_size) > size {
                result.blocks_checked = index;
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
                result.read_fault = Some((fault, "rar5_header_size_out_of_range"));
                return Ok(());
            }
            let full = self.read_at_bytes(cursor, header_total_size as usize)?;
            let Some((header_type, after_type)) = read_vint(&full, after_size) else {
                result.blocks_checked = index;
                result.error = "rar5_header_type_vint_missing";
                return Ok(());
            };
            let Some((header_flags, after_flags)) = read_vint(&full, after_type) else {
                result.blocks_checked = index;
                result.error = "rar5_header_flags_vint_missing";
                return Ok(());
            };
            if index == 0 {
                result.first_header_offset = cursor;
                result.first_header_type = header_type;
                result.first_header_size = header_size;
            } else if index == 1 {
                result.second_block_checked = true;
                result.second_block_type = header_type;
                result.second_block_size = header_size;
            }
            if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
                result.blocks_checked = index;
                result.error = "rar5_block_unknown_non_skippable_type";
                return Ok(());
            }
            let stored_crc = u32_le(&full, 0);
            let crc_ok = crc32(&full[4..]) == stored_crc;
            if index == 0 {
                result.header_crc_checked = true;
                result.header_crc_ok = crc_ok;
            } else if index == 1 {
                result.second_block_ok = crc_ok;
            }
            if !crc_ok {
                result.blocks_checked = index;
                result.error = "rar5_block_crc_mismatch";
                result.damaged_header_type = Some(header_type as u64);
                let flag = match header_type {
                    1 => "rar_main_header_crc_bad",
                    2 => "rar_file_header_crc_bad",
                    3 => "rar_service_header_crc_bad",
                    5 => "rar_end_header_crc_bad",
                    _ => "rar_header_crc_bad",
                };
                result.damage_flags = vec![flag];
                return Ok(());
            }
            let mut field_cursor = after_flags;
            if header_flags & 0x0001 != 0 {
                let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                    result.blocks_checked = index;
                    result.error = "rar5_extra_area_size_vint_missing";
                    return Ok(());
                };
                field_cursor = after_extra;
            }
            let mut data_size = 0u64;
            if header_flags & 0x0002 != 0 {
                let Some((value, _after_data)) = read_vint(&full, field_cursor) else {
                    result.blocks_checked = index;
                    result.error = "rar5_data_size_vint_missing";
                    return Ok(());
                };
                data_size = value;
            }
            let next_cursor = cursor
                .saturating_add(header_total_size)
                .saturating_add(data_size);
            if next_cursor > size {
                result.blocks_checked = index;
                let fault = ReadFault::short_read(
                    "read_declared_range",
                    cursor + header_total_size,
                    usize::try_from(data_size).unwrap_or(usize::MAX),
                    size.saturating_sub(cursor + header_total_size) as usize,
                    size,
                )
                .with_field("rar5.block.payload", FieldLocation::Tail);
                result.read_fault = Some((fault, "rar5_block_payload_out_of_range"));
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
                evidence.push("rar5:encryption_header");
                result.plausible = true;
                result.strong_accept = true;
                result.header_encrypted = Some(true);
                result.password_required = Some(true);
                result.block_walk_ok = true;
                result.blocks_checked = 1usize;
                result.segment_end = 0;
                result.evidence = evidence;
                return Ok(());
            }
            if index == 0 && header_type != 1 {
                result.blocks_checked = 1usize;
                result.error = "rar5_main_header_missing";
                return Ok(());
            }
            if index == 0 {
                evidence.push("rar5:main_header");
            } else if index == 1 {
                result.block_walk_ok = true;
            }
            if header_type == 5 {
                let end_flags = read_vint(&full, field_cursor)
                    .map(|(value, _)| value)
                    .unwrap_or(0);
                evidence.push("rar5:end_block");
                result.plausible = true;
                result.strong_accept = true;
                result.blocks_checked = index + 1;
                result.end_block_found = true;
                result.end_block_flags = end_flags;
                result.segment_end = next_cursor;
                result.evidence = evidence;
                return Ok(());
            }
            cursor = next_cursor;
            index += 1;
        }
    }
}
