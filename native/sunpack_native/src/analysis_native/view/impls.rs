impl AnalysisBinaryView {
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

    fn read_at_bytes(&self, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        self.reader.read_at(offset, size).map_err(reader_error)
    }

    fn read_tail_bytes(&self, size: usize) -> std::io::Result<Vec<u8>> {
        let view_size = self.reader.len();
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        self.read_at_bytes(offset, read_size)
    }

    pub(crate) fn locate_zip_eocd_native(
        &self,

        requested_offset: Option<u64>,
    ) -> std::io::Result<DiagnosticFields> {
        let mut result = DiagnosticFields::new();
        result.put("eocd_candidate_found", false)?;
        result.put("eocd_candidate_offset", 0u64)?;
        result.put("eocd_candidate_comment_length", 0u16)?;
        result.put("eocd_candidate_comment_available_delta", 0i64)?;
        result.put("eocd_candidate_declared_entry_count_present", false)?;
        result.put("eocd_candidate_declared_cd_offset_present", false)?;
        result.put("eocd_candidate_total_entries", 0u16)?;
        result.put("eocd_candidate_cd_offset", 0u32)?;
        result.put("eocd_candidate_cd_size", 0u32)?;

        let size = self.reader.len();
        if let Some(offset) = requested_offset {
            let record = self.read_at_bytes(offset, 22)?;
            if record.len() == 22 && record.starts_with(ZIP_EOCD) {
                let available = size
                    .saturating_sub(offset.saturating_add(22))
                    .min(i64::MAX as u64) as i64;
                set_zip_eocd_candidate(&mut result, offset, &record, available)?;
            }
            return Ok(result);
        }

        let read_size = size.min((22 + 65_535) as u64) as usize;
        if read_size < 4 {
            return Ok(result);
        }
        let tail = self.read_tail_bytes(read_size)?;
        let base = size.saturating_sub(tail.len() as u64);
        let mut search_end = tail.len();
        let mut fallback: Option<(u64, [u8; 22], i64)> = None;
        while search_end >= 4 {
            let found = (0..=search_end - 4)
                .rev()
                .find(|&index| &tail[index..index + 4] == ZIP_EOCD);
            let Some(index) = found else {
                break;
            };
            if index + 22 <= tail.len() {
                let mut record = [0u8; 22];
                record.copy_from_slice(&tail[index..index + 22]);
                let available = (tail.len() - index - 22).min(i64::MAX as usize) as i64;
                let offset = base + index as u64;
                if fallback.is_none() {
                    fallback = Some((offset, record, available));
                }
                if available == i64::from(u16_le(&record, 20)) {
                    set_zip_eocd_candidate(&mut result, offset, &record, available)?;
                    return Ok(result);
                }
            }
            if index == 0 {
                break;
            }
            search_end = index;
        }
        if let Some((offset, record, available)) = fallback {
            set_zip_eocd_candidate(&mut result, offset, &record, available)?;
        }
        Ok(result)
    }

    fn probe_zip_with_disk_starts(
        &self,

        eocd_offset: u64,
        disk_starts: Option<&[u64]>,
    ) -> std::io::Result<DiagnosticFields> {
        let mut result = DiagnosticFields::new();
        result.put("format", "zip")?;
        result.put("plausible", false)?;
        result.put("magic_matched", false)?;
        result.put("error", "")?;
        result.put("eocd_offset", eocd_offset)?;
        result.put("archive_offset", 0u64)?;
        result.put("segment_end", 0u64)?;
        result.put("central_directory_offset", 0u64)?;
        result.put("central_directory_size", 0u64)?;
        result.put("total_entries", 0u16)?;
        result.put("is_multi_disk", false)?;
        result.put("disk_number", 0u16)?;
        result.put("central_directory_disk", 0u16)?;
        result.put("disk_entries", 0u16)?;
        result.put("declared_total_disks", 1u32)?;
        result.put("central_directory_present", false)?;
        result.put("central_directory_walk_ok", false)?;
        result.put("central_directory_entries_checked", 0usize)?;
        result.put("central_directory_encrypted_entries", 0usize)?;
        result.put("password_required", false)?;
        result.put("password_state", "unknown")?;
        result.put("encryption_scan_complete", false)?;
        result.put("local_header_links_ok", false)?;
        result.put("local_header_links_checked", 0usize)?;
        result.put("archive_starts_at_zero", false)?;
        result.put("archive_start_kind", "")?;
        result.put("content_integrity_warning", "")?;
        result.put("evidence", Vec::<&str>::new())?;

        let eocd = match self.read_field_at_bytes(eocd_offset, 22, "zip.eocd", FieldLocation::Tail)
        {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&mut result, &fault, "eocd_too_small")?;
                return Ok(result);
            }
        };
        if &eocd[0..4] != ZIP_EOCD {
            result.put("error", "bad_eocd_signature")?;
            return Ok(result);
        }
        result.put("magic_matched", true)?;
        let disk_number = u16_le(&eocd, 4);
        let central_directory_disk = u16_le(&eocd, 6);
        let disk_entries = u16_le(&eocd, 8);
        let total_entries = u16_le(&eocd, 10);
        let central_directory_size = u32_le(&eocd, 12) as u64;
        let central_directory_offset = u32_le(&eocd, 16) as u64;
        let comment_length = u16_le(&eocd, 20) as u64;
        let segment_end = eocd_offset + 22 + comment_length;

        // APPNOTE 4.3.14/4.3.15: a ZIP64 archive places the Zip64 end of
        // central directory record (56 bytes: 4-byte signature + 52 fixed
        // bytes, size field 44) and its locator (20 bytes) between the
        // central directory and the plain EOCD.  When present, the 8-byte
        // fields in the Zip64 record are authoritative and the central
        // directory ends where the Zip64 record starts, not at the EOCD.
        let mut effective_disk_number = u64::from(disk_number);
        let mut effective_central_directory_disk = u64::from(central_directory_disk);
        let mut effective_disk_entries = u64::from(disk_entries);
        let mut effective_total_entries = u64::from(total_entries);
        let mut effective_central_directory_size = central_directory_size;
        let mut effective_central_directory_offset = central_directory_offset;
        let mut directory_end = eocd_offset;
        let mut zip64_present = false;
        let mut zip64_locator_present = false;
        let mut zip64_eocd_offset = 0u64;
        let mut zip64_declared_total_disks = 1u32;
        let zip64 = (|| {
            crate::formats::zip::zip64::locate_end_record(
                eocd_offset,
                disk_starts,
                |offset, size| self.reader.read_at(offset, size),
            )
        })();
        match zip64 {
            Ok(Some(found)) => {
                zip64_present = true;
                zip64_locator_present = true;
                zip64_eocd_offset = found.offset;
                zip64_declared_total_disks = found.locator.total_disks;
                effective_disk_number = u64::from(found.record.disk);
                effective_central_directory_disk = u64::from(found.record.cd_disk);
                effective_disk_entries = found.record.disk_entries;
                effective_total_entries = found.record.total_entries;
                effective_central_directory_size = found.record.cd_size;
                effective_central_directory_offset = found.record.cd_offset;
                directory_end = found.offset;
            }
            Ok(None) => {}
            Err(crate::formats::zip::zip64::LocateError::Invalid(error)) => {
                result.put("zip64", true)?;
                result.put("error", error)?;
                return Ok(result);
            }
            Err(crate::formats::zip::zip64::LocateError::Read(error)) => {
                return Err(reader_error(error));
            }
        }
        result.put("segment_end", segment_end)?;
        result.put("central_directory_size", effective_central_directory_size)?;
        result.put("total_entries", effective_total_entries)?;
        result.put("zip64", zip64_present)?;
        result.put("zip64_locator_present", zip64_locator_present)?;
        result.put("zip64_eocd_present", zip64_present)?;
        result.put("zip64_eocd_offset", zip64_eocd_offset)?;
        result.put(
            "zip64_locator_offset",
            if zip64_present {
                eocd_offset - 20
            } else {
                0u64
            },
        )?;
        let is_multi_disk = effective_disk_number != 0 || effective_central_directory_disk != 0;
        result.put("is_multi_disk", is_multi_disk)?;
        result.put("disk_number", effective_disk_number)?;
        result.put("central_directory_disk", effective_central_directory_disk)?;
        result.put("disk_entries", effective_disk_entries)?;
        result.put(
            "declared_total_disks",
            if zip64_present {
                zip64_declared_total_disks
            } else {
                u32::from(disk_number) + 1
            },
        )?;
        let archive_start_kind = zip_archive_start_kind(
            &self.reader,
            is_multi_disk,
            effective_total_entries == 0 && effective_central_directory_size == 0,
            zip64_present.then_some(zip64_eocd_offset),
        )?;
        result.put("archive_starts_at_zero", !archive_start_kind.is_empty())?;
        result.put("archive_start_kind", archive_start_kind)?;
        if is_multi_disk && disk_starts.is_none() {
            // A single physical input cannot resolve PKZIP disk-relative
            // offsets.  MultiVolumeBinaryView supplies the Rust-owned layout.
            result.put("error", "zip_multi_disk")?;
            let mut evidence = Vec::<&str>::new();
            evidence.push("zip:eocd_multi_disk");
            result.put("evidence", evidence)?;
            return Ok(result);
        }
        if effective_disk_entries != effective_total_entries && !is_multi_disk {
            result.put("error", "entry_count_mismatch")?;
            return Ok(result);
        }
        if let Some(starts) = disk_starts.filter(|_| is_multi_disk) {
            let disk_ok = usize::try_from(effective_disk_number)
                .ok()
                .is_some_and(|disk| disk < starts.len());
            let cd_disk_ok = usize::try_from(effective_central_directory_disk)
                .ok()
                .is_some_and(|disk| disk < starts.len());
            if !disk_ok || !cd_disk_ok {
                result.put("error", "central_directory_disk_offset_out_of_range")?;
                return Ok(result);
            }
            if zip64_present
                && (zip64_declared_total_disks as usize != starts.len()
                    || effective_disk_number as usize + 1 != starts.len())
            {
                result.put("error", "zip64_disk_count_mismatch")?;
                return Ok(result);
            }
        }
        if !is_multi_disk && directory_end < effective_central_directory_size {
            result.put("error", "central_directory_size_out_of_range")?;
            return Ok(result);
        }
        let physical_central_offset = if is_multi_disk {
            let starts = disk_starts.expect("multi-disk ZIP requires a volume layout");
            let Some(offset) = self.zip_logical_offset_for_disk(
                starts,
                effective_central_directory_disk,
                effective_central_directory_offset,
            ) else {
                result.put("error", "central_directory_disk_offset_out_of_range")?;
                return Ok(result);
            };
            offset
        } else {
            let naive_physical_central_offset = directory_end - effective_central_directory_size;
            let declared_physical_central_offset = effective_central_directory_offset;
            // Prefer the physically verified declared offset when the naive
            // back-computation misses the signature. Otherwise keep the
            // naive position so carrier/SFX prefixes retain archive_offset.
            if naive_physical_central_offset != declared_physical_central_offset {
                let naive_ok = self
                    .read_field_at_bytes(
                        naive_physical_central_offset,
                        4,
                        "zip.central_directory.signature",
                        FieldLocation::Tail,
                    )
                    .is_ok_and(|sig| sig.as_slice() == ZIP_CENTRAL);
                let declared_ok = self
                    .read_field_at_bytes(
                        declared_physical_central_offset,
                        4,
                        "zip.central_directory.signature",
                        FieldLocation::Tail,
                    )
                    .is_ok_and(|sig| sig.as_slice() == ZIP_CENTRAL);
                if !naive_ok && declared_ok {
                    declared_physical_central_offset
                } else {
                    naive_physical_central_offset
                }
            } else {
                naive_physical_central_offset
            }
        };
        let archive_offset = if is_multi_disk {
            0
        } else {
            if physical_central_offset < effective_central_directory_offset {
                result.put("error", "archive_offset_underflow")?;
                return Ok(result);
            }
            physical_central_offset - effective_central_directory_offset
        };
        result.put("archive_offset", archive_offset)?;
        result.put("central_directory_offset", physical_central_offset)?;
        if physical_central_offset
            .checked_add(effective_central_directory_size)
            .is_none_or(|end| end != directory_end)
        {
            result.put("error", "central_directory_size_mismatch")?;
            return Ok(result);
        }
        if effective_total_entries == 0 && effective_central_directory_size == 0 {
            result.put("plausible", true)?;
            result.put("central_directory_walk_ok", true)?;
            result.put("local_header_links_ok", true)?;
            result.put("encryption_scan_complete", true)?;
            result.put("password_state", "not_required")?;
            return Ok(result);
        }

        let central_sig = match self.read_field_at_bytes(
            physical_central_offset,
            4,
            "zip.central_directory.signature",
            FieldLocation::Tail,
        ) {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&mut result, &fault, "central_directory_read_failed")?;
                return Ok(result);
            }
        };
        if central_sig.as_slice() != ZIP_CENTRAL {
            result.put("error", "bad_central_directory_signature")?;
            return Ok(result);
        }
        result.put("central_directory_present", true)?;
        let walk = (|| {
            self.walk_zip_central_directory(
                archive_offset,
                physical_central_offset,
                effective_central_directory_size,
                effective_total_entries as usize,
                disk_starts.filter(|_| is_multi_disk),
            )
        })()?;
        let ZipDirectoryWalk {
            entries_checked,
            directory_ok: cd_ok,
            links_checked,
            links_ok,
            encrypted_entries,
            error,
            content_warning,
        } = walk;
        result.put("central_directory_entries_checked", entries_checked)?;
        result.put("central_directory_encrypted_entries", encrypted_entries)?;
        result.put("central_directory_walk_ok", cd_ok)?;
        result.put("local_header_links_checked", links_checked)?;
        result.put("local_header_links_ok", links_ok)?;
        let encryption_scan_complete =
            error.is_empty() && cd_ok && entries_checked == effective_total_entries as usize;
        result.put("encryption_scan_complete", encryption_scan_complete)?;
        result.put("password_required", encrypted_entries > 0)?;
        result.put(
            "password_state",
            if encrypted_entries > 0 {
                "required"
            } else if encryption_scan_complete {
                "not_required"
            } else {
                "unknown"
            },
        )?;
        if error.is_empty() {
            result.put("plausible", true)?;
            result.put("content_integrity_warning", content_warning)?;
            let mut evidence = Vec::<&str>::new();
            evidence.push("zip:eocd");
            evidence.push("zip:central_directory");
            if cd_ok {
                evidence.push("zip:central_directory_walk");
            }
            if links_ok {
                evidence.push("zip:local_header_links");
            }
            if is_multi_disk {
                evidence.push("zip:multi_disk_offsets");
            }
            result.put("evidence", evidence)?;
        } else {
            result.put("error", error)?;
        }
        Ok(result)
    }

    fn zip_logical_offset_for_disk(
        &self,
        disk_starts: &[u64],
        disk_number: u64,
        relative_offset: u64,
    ) -> Option<u64> {
        let disk = usize::try_from(disk_number).ok()?;
        let start = *disk_starts.get(disk)?;
        let end = disk_starts
            .get(disk + 1)
            .copied()
            .unwrap_or_else(|| self.reader.len());
        let logical = start.checked_add(relative_offset)?;
        (logical <= end).then_some(logical)
    }

    fn walk_zip_central_directory(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        central_directory_size: u64,
        total_entries: usize,
        disk_starts: Option<&[u64]>,
    ) -> std::io::Result<ZipDirectoryWalk> {
        // Independent bounded windows retain directory and local-header locality
        // without making a one-pass validation occupy the global block cache.
        let mut directory =
            std::io::BufReader::with_capacity(64 * 1024, self.reader.stream_cursor());
        let mut locals = std::io::BufReader::with_capacity(64 * 1024, self.reader.stream_cursor());
        let mut cursor = physical_central_offset;
        let end = physical_central_offset + central_directory_size;
        let mut walk = ZipDirectoryWalk::default();
        for index in 0..total_entries {
            if cursor.saturating_add(46) > end {
                return Ok(walk.failed(index, false, "central_directory_entry_out_of_range"));
            }
            let header = zip_window_read(&mut directory, cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok(walk.failed(index, false, "bad_central_directory_entry_signature"));
            }
            if u16_le(&header, 8) & 0x0001 != 0 {
                walk.encrypted_entries += 1;
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as usize;
            let comment_len = u16_le(&header, 32) as u64;
            let entry_size = 46 + filename_len + extra_len as u64 + comment_len;
            if cursor.saturating_add(entry_size) > end {
                return Ok(walk.failed(
                    index,
                    false,
                    "central_directory_variable_fields_out_of_range",
                ));
            }
            let extra = if extra_len == 0 {
                Vec::new()
            } else {
                zip_window_read(&mut directory, cursor + 46 + filename_len, extra_len)?
            };
            let Some(location) = crate::formats::zip::zip64::central_entry_values(&header, &extra)
            else {
                return Ok(walk.failed(index + 1, true, "zip64_extra_missing_or_invalid"));
            };
            let local_logical = if let Some(starts) = disk_starts {
                self.zip_logical_offset_for_disk(starts, location.disk, location.local_offset)
            } else {
                archive_offset.checked_add(location.local_offset)
            };
            let Some(local_logical) = local_logical else {
                return Ok(walk.failed(index + 1, true, "local_header_link_mismatch"));
            };
            // Fetch once for both link validation and the existing bounded CRC
            // consistency hint. Later entries only need their four-byte signature.
            let check_crc = index < 8 && walk.content_warning.is_empty();
            let local =
                zip_window_read(&mut locals, local_logical, if check_crc { 30 } else { 4 })?;
            if local.len() < 4 || &local[..4] != ZIP_LOCAL {
                return Ok(walk.failed(index + 1, true, "local_header_link_mismatch"));
            }
            walk.links_checked += 1;
            if check_crc && local.len() >= 30 {
                walk.content_warning = if u16_le(&local, 6) & 0x0008 != 0 {
                    "data_descriptor_or_deferred_crc"
                } else if u32_le(&local, 14) != u32_le(&header, 16) {
                    "local_header_crc_mismatch"
                } else {
                    ""
                };
            }
            cursor += entry_size;
        }
        walk.entries_checked = total_entries;
        walk.directory_ok =
            crate::formats::zip::central_directory_complete(cursor, end, |offset, length| {
                zip_window_read(&mut directory, offset, length)
            })?;
        walk.links_ok = walk.directory_ok;
        if !walk.directory_ok {
            return Ok(walk.failed(total_entries, false, "central_directory_size_mismatch"));
        }
        Ok(walk)
    }

    fn walk_tar(&self, start_offset: u64) -> std::io::Result<DiagnosticFields> {
        let mut result = DiagnosticFields::new();
        result.put("format", "tar")?;
        result.put("magic_matched", false)?;
        result.put("plausible", false)?;
        result.put("error", "")?;
        result.put("file_size", self.reader.len())?;
        result.put("stored_checksum", 0u64)?;
        result.put("computed_checksum", 0u64)?;
        result.put("member_size", 0u64)?;
        result.put("ustar_magic", false)?;
        result.put("zero_block", false)?;
        result.put("fuzzy_name_nonempty", false)?;
        result.put("fuzzy_numeric_fields_valid", false)?;
        result.put("fuzzy_typeflag_valid", false)?;
        result.put("fuzzy_payload_in_range", false)?;
        result.put("entries_checked", 0usize)?;
        result.put("entry_walk_ok", false)?;
        result.put("walk_complete", false)?;
        result.put("end_zero_blocks", false)?;
        result.put("segment_end", Value::Null)?;
        result.put("boundary_confidence", "none")?;
        result.put("integrity_confidence", "unknown")?;
        result.put("evidence", Vec::<&str>::new())?;
        result.put("damage_flags", Vec::<&str>::new())?;

        let size = self.reader.len();
        let mut cursor = start_offset;
        let mut checked = 0usize;
        let mut zero_blocks = 0usize;
        let mut tar_state = crate::formats::tar::TarState::default();
        let mut last_ustar = None;
        if start_offset.saturating_add(TAR_BLOCK_SIZE as u64) > size {
            let fault = ReadFault::short_read(
                "read_record",
                start_offset,
                TAR_BLOCK_SIZE,
                size.saturating_sub(start_offset) as usize,
                size,
            )
            .with_field("tar.member.header", FieldLocation::Head);
            set_view_read_fault(&mut result, &fault, "short_tar_header")?;
            return Ok(result);
        }
        while cursor.saturating_add(TAR_BLOCK_SIZE as u64) <= size {
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
                    set_view_read_fault(&mut result, &fault, "tar_header_read_failed")?;
                    return Ok(result);
                }
            };
            if header.iter().all(|byte| *byte == 0) {
                if checked == 0 {
                    result.put("zero_block", true)?;
                    result.put("error", "leading_zero_block")?;
                    return Ok(result);
                }
                zero_blocks += 1;
                cursor += TAR_BLOCK_SIZE as u64;
                if zero_blocks >= 2 {
                    result.put("plausible", checked > 0)?;
                    result.put("entries_checked", checked)?;
                    result.put("entry_walk_ok", checked > 0)?;
                    result.put("walk_complete", true)?;
                    result.put("end_zero_blocks", true)?;
                    result.put("segment_end", cursor)?;
                    result.put("boundary_confidence", "high")?;
                    result.put(
                        "evidence",
                        [
                            "tar:header_checksum",
                            "tar:block_walk",
                            "tar:end_zero_blocks",
                        ],
                    )?;
                    return Ok(result);
                }
                continue;
            }
            // Candidate recognition belongs to the native walker.  This lets
            // The extraction planner can dispatch damaged TAR files without re-reading or parsing
            // archive bytes as a fallback.
            zero_blocks = 0;
            let first_identity = (checked == 0).then(|| tar_header_identity(&header, cursor, size));
            if let Some(identity) = first_identity {
                result.put(
                    "magic_matched",
                    identity.ustar_magic
                        || (identity.name_nonempty
                            && identity.numeric_fields_valid
                            && identity.typeflag_valid),
                )?;
                result.put("stored_checksum", identity.stored_checksum)?;
                result.put("computed_checksum", identity.computed_checksum)?;
                result.put("member_size", identity.member_size)?;
                result.put("ustar_magic", identity.ustar_magic)?;
                result.put("format", if identity.ustar_magic { "ustar" } else { "tar" })?;
                result.put("fuzzy_name_nonempty", identity.name_nonempty)?;
                result.put("fuzzy_numeric_fields_valid", identity.numeric_fields_valid)?;
                result.put("fuzzy_typeflag_valid", identity.typeflag_valid)?;
                result.put("fuzzy_payload_in_range", identity.payload_in_range)?;
            }
            let member_size = first_identity.map_or_else(
                || crate::formats::tar::header_size(&header),
                |identity| identity.validated_size,
            );
            let member_size = match member_size {
                Ok(size) => size,
                Err(error) => {
                    result.put("entries_checked", checked)?;
                    result.put("error", error)?;
                    let flag = match header[156] {
                        b'x' | b'g' => "pax_header_bad",
                        b'L' | b'K' => "gnu_longname_bad",
                        b'S' => "sparse_header_bad",
                        _ if error == "checksum_mismatch" => "tar_checksum_bad",
                        _ => "tar_metadata_bad",
                    };
                    result.put("damage_flags", [flag])?;
                    if checked > 0 {
                        result.put("plausible", true)?;
                        result.put("entry_walk_ok", true)?;
                        result.put("segment_end", Value::Null)?;
                        result.put("boundary_confidence", "none")?;
                        result.put("evidence", ["tar:header_checksum", "tar:block_walk_prefix"])?;
                    }
                    return Ok(result);
                }
            };
            let record = (|| {
                tar_state.advance_validated(
                    &header,
                    member_size,
                    cursor,
                    size,
                    &mut |start, length| {
                        self.reader
                            .read_cached_at(start, length)
                            .map(|data| data.to_vec())
                    },
                )
            })();
            let next_cursor = match record {
                Ok(record) => record.next,
                Err(error) => {
                    result.put("entries_checked", checked)?;
                    result.put("plausible", checked > 0)?;
                    result.put("entry_walk_ok", checked > 0)?;
                    if error.kind() == io::ErrorKind::OutOfMemory {
                        result.put("plausible", true)?;
                        result.put("entry_walk_ok", false)?;
                        result.put("error", "analysis_resource_limit")?;
                        result.put("structure_status", "incomplete")?;
                        result.put("structure_validation_complete", false)?;
                        result.put("evidence", ["tar:header_checksum"])?;
                    } else if error.kind() == io::ErrorKind::UnexpectedEof {
                        let payload_start = cursor.saturating_add(TAR_BLOCK_SIZE as u64);
                        let fault = ReadFault::short_read(
                            "read_declared_range",
                            payload_start,
                            usize::try_from(member_size.saturating_add(tar_padding(member_size)))
                                .unwrap_or(usize::MAX),
                            size.saturating_sub(payload_start) as usize,
                            size,
                        )
                        .with_field("tar.member.payload", FieldLocation::Tail);
                        set_view_read_fault(&mut result, &fault, "member_payload_out_of_range")?;
                    } else {
                        result.put("error", error.to_string())?;
                        let flag = match header[156] {
                            b'x' | b'g' => "pax_header_bad",
                            b'L' | b'K' => "gnu_longname_bad",
                            b'S' => "sparse_header_bad",
                            _ => "tar_metadata_bad",
                        };
                        result.put("damage_flags", [flag])?;
                    }
                    return Ok(result);
                }
            };
            checked += 1;
            cursor = next_cursor;
            let ustar = matches!(&header[257..263], b"ustar\x00" | b"ustar ");
            if last_ustar != Some(ustar) {
                last_ustar = Some(ustar);
                result.put(
                    "evidence",
                    [
                        "tar:header_checksum",
                        if ustar {
                            "tar:ustar_magic"
                        } else {
                            "tar:v7_header"
                        },
                    ],
                )?;
            }
        }
        if checked > 0 && cursor == size {
            result.put("plausible", true)?;
            result.put("entries_checked", checked)?;
            result.put("entry_walk_ok", true)?;
            result.put("walk_complete", true)?;
            result.put("segment_end", cursor)?;
            result.put("boundary_confidence", "medium")?;
            result.put("error", "tar_end_zero_blocks_missing_at_eof")?;
            result.put("damage_flags", ["missing_end_block"])?;
            result.put(
                "evidence",
                ["tar:header_checksum", "tar:block_walk", "tar:eof_boundary"],
            )?;
        } else if checked > 0 {
            result.put("plausible", true)?;
            result.put("entries_checked", checked)?;
            result.put("entry_walk_ok", true)?;
            result.put("segment_end", Value::Null)?;
            result.put("boundary_confidence", "none")?;
            let fault = ReadFault::short_read(
                "read_record",
                cursor,
                TAR_BLOCK_SIZE * 2,
                size.saturating_sub(cursor).min((TAR_BLOCK_SIZE * 2) as u64) as usize,
                size,
            )
            .with_field("tar.archive.end_zero_blocks", FieldLocation::Tail);
            set_view_read_fault(&mut result, &fault, "tar_end_zero_blocks_not_found")?;
            result.put("evidence", ["tar:header_checksum", "tar:block_walk_prefix"])?;
        }
        Ok(result)
    }
}

fn zip_archive_start_kind(
    reader: &ManagedReader,
    spanned: bool,
    empty: bool,
    zip64_eocd_offset: Option<u64>,
) -> std::io::Result<&'static str> {
    // Keep this check on the same ManagedReader as the structural probe.  It
    // therefore shares the existing read accounting and request/global
    // caches instead of reopening the source.
    let head = reader.read_cached_at(0, 8).map_err(reader_error)?;
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

fn set_zip_eocd_candidate(
    result: &mut DiagnosticFields,
    offset: u64,
    record: &[u8],
    available: i64,
) -> std::io::Result<()> {
    if record.len() < 22 || &record[..4] != ZIP_EOCD {
        return Ok(());
    }
    let comment_length = u16_le(record, 20);
    let total_entries = u16_le(record, 10);
    let cd_offset = u32_le(record, 16);
    let cd_size = u32_le(record, 12);
    result.put("eocd_candidate_found", true)?;
    result.put("eocd_candidate_offset", offset)?;
    result.put("eocd_candidate_comment_length", comment_length)?;
    result.put(
        "eocd_candidate_comment_available_delta",
        available - i64::from(comment_length),
    )?;
    result.put(
        "eocd_candidate_declared_entry_count_present",
        total_entries > 0,
    )?;
    result.put("eocd_candidate_declared_cd_offset_present", cd_offset > 0)?;
    result.put("eocd_candidate_total_entries", total_entries)?;
    result.put("eocd_candidate_cd_offset", cd_offset)?;
    result.put("eocd_candidate_cd_size", cd_size)?;
    Ok(())
}

/// Results of the single bounded directory walk, shared by all ZIP projections.
#[derive(Default)]
struct ZipDirectoryWalk {
    entries_checked: usize,
    directory_ok: bool,
    links_checked: usize,
    links_ok: bool,
    encrypted_entries: usize,
    error: &'static str,
    content_warning: &'static str,
}

impl ZipDirectoryWalk {
    fn failed(mut self, checked: usize, directory_ok: bool, error: &'static str) -> Self {
        self.entries_checked = checked;
        self.directory_ok = directory_ok;
        self.error = error;
        self
    }
}

// seek_relative preserves bytes already buffered when ZIP records are nearby.
fn zip_window_read(
    reader: &mut std::io::BufReader<crate::io::reader::SourceCursor>,
    offset: u64,
    length: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let current = reader.stream_position()?;
    if let Ok(delta) = i64::try_from(i128::from(offset) - i128::from(current)) {
        reader.seek_relative(delta)?;
    } else {
        reader.seek(SeekFrom::Start(offset))?;
    }
    let mut bytes = crate::io::resource_error::zeroed_bytes(length)?;
    let mut used = 0;
    while used < length {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(reader_error(error)),
        }
    }
    bytes.truncate(used);
    Ok(bytes)
}
