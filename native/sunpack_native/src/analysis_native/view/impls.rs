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

    pub(crate) fn probe_zip_local_header_native(
        &self,
        py: Python<'_>,
        offset: u64,
    ) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let result = PyDict::new(py);
        result.set_item("offset", offset)?;
        result.set_item("magic_matched", false)?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("version_needed", 0u16)?;
        result.set_item("compression_method", 0u16)?;
        result.set_item("filename_len", 0u16)?;
        result.set_item("extra_len", 0u16)?;

        let header = self.read_at_bytes(offset, 30)?;
        if header.len() < 30 {
            let fault = ReadFault::short_read(
                "read_exact_at",
                offset,
                30,
                header.len(),
                self.reader.len(),
            )
            .with_field("zip.local_header.fixed", FieldLocation::Body);
            set_view_read_fault(&result, &fault, "short_header")?;
            result.set_item("magic_matched", header.starts_with(b"PK"))?;
            return Ok(result.unbind());
        }
        if &header[..4] != ZIP_LOCAL {
            result.set_item(
                "magic_matched",
                header.starts_with(ZIP_LOCAL)
                    || header.starts_with(ZIP_EOCD)
                    || header.starts_with(b"PK\x07\x08"),
            )?;
            result.set_item("error", "bad_signature")?;
            return Ok(result.unbind());
        }

        let version_needed = u16_le(&header, 4);
        let compression_method = u16_le(&header, 8);
        let filename_len = u16_le(&header, 26);
        let extra_len = u16_le(&header, 28);
        result.set_item("magic_matched", true)?;
        result.set_item("version_needed", version_needed)?;
        result.set_item("compression_method", compression_method)?;
        result.set_item("filename_len", filename_len)?;
        result.set_item("extra_len", extra_len)?;

        if version_needed > 63 {
            result.set_item("error", "unsupported_version")?;
        } else if !matches!(
            compression_method,
            0 | 1 | 6 | 8 | 9 | 12 | 14 | 95 | 96 | 98 | 99
        ) {
            result.set_item("error", "unknown_compression_method")?;
        } else if filename_len == 0 || filename_len > 4096 {
            result.set_item("error", "invalid_filename_length")?;
        } else {
            let header_end = offset
                .checked_add(30)
                .and_then(|value| value.checked_add(u64::from(filename_len)))
                .and_then(|value| value.checked_add(u64::from(extra_len)));
            if header_end.is_none_or(|end| end > self.reader.len()) {
                result.set_item("error", "header_exceeds_file_size")?;
            } else {
                result.set_item("plausible", true)?;
            }
        }
        Ok(result.unbind())
    }

    pub(crate) fn locate_zip_eocd_native(
        &self,
        py: Python<'_>,
        requested_offset: Option<u64>,
    ) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let result = PyDict::new(py);
        result.set_item("eocd_candidate_found", false)?;
        result.set_item("eocd_candidate_offset", 0u64)?;
        result.set_item("eocd_candidate_comment_length", 0u16)?;
        result.set_item("eocd_candidate_comment_available_delta", 0i64)?;
        result.set_item("eocd_candidate_declared_entry_count_present", false)?;
        result.set_item("eocd_candidate_declared_cd_offset_present", false)?;
        result.set_item("eocd_candidate_total_entries", 0u16)?;
        result.set_item("eocd_candidate_cd_offset", 0u32)?;
        result.set_item("eocd_candidate_cd_size", 0u32)?;

        let size = self.reader.len();
        if let Some(offset) = requested_offset {
            let record = self.read_at_bytes(offset, 22)?;
            if record.len() == 22 && record.starts_with(ZIP_EOCD) {
                let available = size
                    .saturating_sub(offset.saturating_add(22))
                    .min(i64::MAX as u64) as i64;
                set_zip_eocd_candidate(&result, offset, &record, available)?;
            }
            return Ok(result.unbind());
        }

        let read_size = size.min((22 + 65_535) as u64) as usize;
        if read_size < 4 {
            return Ok(result.unbind());
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
                    set_zip_eocd_candidate(&result, offset, &record, available)?;
                    return Ok(result.unbind());
                }
            }
            if index == 0 {
                break;
            }
            search_end = index;
        }
        if let Some((offset, record, available)) = fallback {
            set_zip_eocd_candidate(&result, offset, &record, available)?;
        }
        Ok(result.unbind())
    }

    fn probe_zip_with_disk_starts(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
        max_cd_entries_to_walk: usize,
        disk_starts: Option<&[u64]>,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "zip")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("error", "")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("archive_offset", 0u64)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("central_directory_offset", 0u64)?;
        result.set_item("central_directory_size", 0u64)?;
        result.set_item("total_entries", 0u16)?;
        result.set_item("is_multi_disk", false)?;
        result.set_item("disk_number", 0u16)?;
        result.set_item("central_directory_disk", 0u16)?;
        result.set_item("disk_entries", 0u16)?;
        result.set_item("declared_total_disks", 1u32)?;
        result.set_item("central_directory_present", false)?;
        result.set_item("central_directory_walk_ok", false)?;
        result.set_item("central_directory_entries_checked", 0usize)?;
        result.set_item("central_directory_encrypted_entries", 0usize)?;
        result.set_item("password_required", false)?;
        result.set_item("password_state", "unknown")?;
        result.set_item("encryption_scan_complete", false)?;
        result.set_item("local_header_links_ok", false)?;
        result.set_item("local_header_links_checked", 0usize)?;
        result.set_item("archive_starts_at_zero", false)?;
        result.set_item("archive_start_kind", "")?;
        result.set_item("content_integrity_warning", "")?;
        result.set_item("evidence", PyList::empty(py))?;

        let eocd = match self.read_field_at_bytes(eocd_offset, 22, "zip.eocd", FieldLocation::Tail)
        {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&result, &fault, "eocd_too_small")?;
                return Ok(result.unbind());
            }
        };
        if &eocd[0..4] != ZIP_EOCD {
            result.set_item("error", "bad_eocd_signature")?;
            return Ok(result.unbind());
        }
        result.set_item("magic_matched", true)?;
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
        if eocd_offset >= (ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE) as u64 {
            let block_offset =
                eocd_offset - (ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE) as u64;
            if let Ok(block) = self.read_field_at_bytes(
                block_offset,
                ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE,
                "zip.zip64_eocd_tail",
                FieldLocation::Tail,
            ) {
                if block.len() == ZIP64_EOCD_RECORD_SIZE + ZIP64_EOCD_LOCATOR_SIZE
                    && &block[..4] == ZIP64_EOCD
                    && u64_le(&block, 4) == ZIP64_EOCD_RECORD_SIZE as u64 - 12
                    && &block[ZIP64_EOCD_RECORD_SIZE..ZIP64_EOCD_RECORD_SIZE + 4] == ZIP64_LOCATOR
                {
                    zip64_present = true;
                    zip64_locator_present = true;
                    zip64_eocd_offset = block_offset;
                    zip64_declared_total_disks = u32_le(&block, ZIP64_EOCD_RECORD_SIZE + 16);
                    effective_disk_number = u64::from(u32_le(&block, 16));
                    effective_central_directory_disk = u64::from(u32_le(&block, 20));
                    effective_disk_entries = u64_le(&block, 24);
                    effective_total_entries = u64_le(&block, 32);
                    effective_central_directory_size = u64_le(&block, 40);
                    effective_central_directory_offset = u64_le(&block, 48);
                    directory_end = block_offset;
                }
            }
        }
        result.set_item("segment_end", segment_end)?;
        result.set_item("central_directory_size", effective_central_directory_size)?;
        result.set_item("total_entries", effective_total_entries)?;
        result.set_item("zip64", zip64_present)?;
        result.set_item("zip64_locator_present", zip64_locator_present)?;
        result.set_item("zip64_eocd_present", zip64_present)?;
        result.set_item("zip64_eocd_offset", zip64_eocd_offset)?;
        result.set_item(
            "zip64_locator_offset",
            if zip64_present { eocd_offset - 20 } else { 0u64 },
        )?;
        let is_multi_disk =
            effective_disk_number != 0 || effective_central_directory_disk != 0;
        result.set_item("is_multi_disk", is_multi_disk)?;
        result.set_item("disk_number", effective_disk_number)?;
        result.set_item("central_directory_disk", effective_central_directory_disk)?;
        result.set_item("disk_entries", effective_disk_entries)?;
        result.set_item(
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
        result.set_item("archive_starts_at_zero", !archive_start_kind.is_empty())?;
        result.set_item("archive_start_kind", archive_start_kind)?;
        if is_multi_disk && disk_starts.is_none() {
            // A single physical input cannot resolve PKZIP disk-relative
            // offsets.  MultiVolumeBinaryView supplies the Rust-owned layout.
            result.set_item("error", "zip_multi_disk")?;
            let evidence = PyList::empty(py);
            evidence.append("zip:eocd_multi_disk")?;
            result.set_item("evidence", evidence)?;
            return Ok(result.unbind());
        }
        if effective_disk_entries != effective_total_entries && !is_multi_disk {
            result.set_item("error", "entry_count_mismatch")?;
            return Ok(result.unbind());
        }
        if let Some(starts) = disk_starts.filter(|_| is_multi_disk) {
            let disk_ok = usize::try_from(effective_disk_number)
                .ok()
                .is_some_and(|disk| disk < starts.len());
            let cd_disk_ok = usize::try_from(effective_central_directory_disk)
                .ok()
                .is_some_and(|disk| disk < starts.len());
            if !disk_ok || !cd_disk_ok {
                result.set_item("error", "central_directory_disk_offset_out_of_range")?;
                return Ok(result.unbind());
            }
            if zip64_present
                && (zip64_declared_total_disks as usize != starts.len()
                    || effective_disk_number as usize + 1 != starts.len())
            {
                result.set_item("error", "zip64_disk_count_mismatch")?;
                return Ok(result.unbind());
            }
        }
        if !is_multi_disk && directory_end < effective_central_directory_size {
            result.set_item("error", "central_directory_size_out_of_range")?;
            return Ok(result.unbind());
        }
        let physical_central_offset = if is_multi_disk {
            let starts = disk_starts.expect("multi-disk ZIP requires a volume layout");
            let Some(offset) = self.zip_logical_offset_for_disk(
                starts,
                effective_central_directory_disk,
                effective_central_directory_offset,
            ) else {
                result.set_item("error", "central_directory_disk_offset_out_of_range")?;
                return Ok(result.unbind());
            };
            offset
        } else {
            let naive_physical_central_offset =
                directory_end - effective_central_directory_size;
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
                result.set_item("error", "archive_offset_underflow")?;
                return Ok(result.unbind());
            }
            physical_central_offset - effective_central_directory_offset
        };
        result.set_item("archive_offset", archive_offset)?;
        result.set_item("central_directory_offset", physical_central_offset)?;
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
            result.set_item("encryption_scan_complete", true)?;
            result.set_item("password_state", "not_required")?;
            return Ok(result.unbind());
        }

        let central_sig = match self.read_field_at_bytes(
            physical_central_offset,
            4,
            "zip.central_directory.signature",
            FieldLocation::Tail,
        ) {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&result, &fault, "central_directory_read_failed")?;
                return Ok(result.unbind());
            }
        };
        if central_sig.as_slice() != ZIP_CENTRAL {
            result.set_item("error", "bad_central_directory_signature")?;
            return Ok(result.unbind());
        }
        result.set_item("central_directory_present", true)?;
        let (entries_checked, cd_ok, links_checked, links_ok, encrypted_entries, error) = self
            .walk_zip_central_directory(
                archive_offset,
                physical_central_offset,
                effective_central_directory_size,
                effective_total_entries as usize,
                max_cd_entries_to_walk,
                disk_starts.filter(|_| is_multi_disk),
            )?;
        result.set_item("central_directory_entries_checked", entries_checked)?;
        result.set_item("central_directory_encrypted_entries", encrypted_entries)?;
        result.set_item("central_directory_walk_ok", cd_ok)?;
        result.set_item("local_header_links_checked", links_checked)?;
        result.set_item("local_header_links_ok", links_ok)?;
        let encryption_scan_complete =
            error.is_empty() && cd_ok && entries_checked == effective_total_entries as usize;
        result.set_item("encryption_scan_complete", encryption_scan_complete)?;
        result.set_item("password_required", encrypted_entries > 0)?;
        result.set_item(
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
            result.set_item("plausible", true)?;
            result.set_item(
                "content_integrity_warning",
                self.zip_content_integrity_warning(
                    archive_offset,
                    physical_central_offset,
                    effective_total_entries as usize,
                    max_cd_entries_to_walk,
                    disk_starts.filter(|_| is_multi_disk),
                )?,
            )?;
            let evidence = PyList::empty(py);
            evidence.append("zip:eocd")?;
            evidence.append("zip:central_directory")?;
            if cd_ok {
                evidence.append("zip:central_directory_walk")?;
            }
            if links_ok {
                evidence.append("zip:local_header_links")?;
            }
            if is_multi_disk {
                evidence.append("zip:multi_disk_offsets")?;
            }
            result.set_item("evidence", evidence)?;
        } else {
            result.set_item("error", error)?;
        }
        Ok(result.unbind())
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
        max_entries: usize,
        disk_starts: Option<&[u64]>,
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
            let extra = self.read_at_bytes(
                cursor + 46 + filename_len,
                usize::try_from(extra_len).unwrap_or(usize::MAX),
            )?;
            let Some((local_header_offset, disk_start)) =
                resolve_zip64_central_location(&header, &extra)
            else {
                return Ok((
                    index + 1,
                    true,
                    links_checked,
                    false,
                    encrypted_entries,
                    "zip64_extra_missing_or_invalid",
                ));
            };
            let local_logical = if let Some(starts) = disk_starts {
                self.zip_logical_offset_for_disk(starts, disk_start, local_header_offset)
            } else {
                archive_offset.checked_add(local_header_offset)
            };
            let Some(local_logical) = local_logical else {
                return Ok((
                    index + 1,
                    true,
                    links_checked,
                    false,
                    encrypted_entries,
                    "local_header_link_mismatch",
                ));
            };
            if links_checked < max_entries {
                let local_sig = self.read_at_bytes(local_logical, 4)?;
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
        disk_starts: Option<&[u64]>,
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
            let extra = self.read_at_bytes(
                cursor + 46 + filename_len,
                usize::try_from(extra_len).unwrap_or(usize::MAX),
            )?;
            let Some((local_header_offset, disk_start)) =
                resolve_zip64_central_location(&header, &extra)
            else {
                return Ok("");
            };
            let local_logical = if let Some(starts) = disk_starts {
                self.zip_logical_offset_for_disk(starts, disk_start, local_header_offset)
            } else {
                archive_offset.checked_add(local_header_offset)
            };
            let Some(local_logical) = local_logical else {
                return Ok("");
            };
            let local = self.read_at_bytes(local_logical, 30)?;
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

fn set_zip_eocd_candidate(
    result: &Bound<'_, PyDict>,
    offset: u64,
    record: &[u8],
    available: i64,
) -> PyResult<()> {
    if record.len() < 22 || &record[..4] != ZIP_EOCD {
        return Ok(());
    }
    let comment_length = u16_le(record, 20);
    let total_entries = u16_le(record, 10);
    let cd_offset = u32_le(record, 16);
    let cd_size = u32_le(record, 12);
    result.set_item("eocd_candidate_found", true)?;
    result.set_item("eocd_candidate_offset", offset)?;
    result.set_item("eocd_candidate_comment_length", comment_length)?;
    result.set_item(
        "eocd_candidate_comment_available_delta",
        available - i64::from(comment_length),
    )?;
    result.set_item(
        "eocd_candidate_declared_entry_count_present",
        total_entries > 0,
    )?;
    result.set_item(
        "eocd_candidate_declared_cd_offset_present",
        cd_offset > 0,
    )?;
    result.set_item("eocd_candidate_total_entries", total_entries)?;
    result.set_item("eocd_candidate_cd_offset", cd_offset)?;
    result.set_item("eocd_candidate_cd_size", cd_size)?;
    Ok(())
}


fn resolve_zip64_central_location(header: &[u8], extra: &[u8]) -> Option<(u64, u64)> {
    if header.len() < 46 {
        return None;
    }
    let uncompressed_sentinel = u32_le(header, 24) == u32::MAX;
    let compressed_sentinel = u32_le(header, 20) == u32::MAX;
    let local_sentinel = u32_le(header, 42) == u32::MAX;
    let disk_sentinel = u16_le(header, 34) == u16::MAX;
    let mut local_header_offset = u32_le(header, 42) as u64;
    let mut disk_start = u16_le(header, 34) as u64;
    if !local_sentinel && !disk_sentinel {
        return Some((local_header_offset, disk_start));
    }

    let mut cursor = 0usize;
    let mut payload = None;
    while cursor.checked_add(4)? <= extra.len() {
        let field_id = u16_le(extra, cursor);
        let field_size = u16_le(extra, cursor + 2) as usize;
        cursor += 4;
        let end = cursor.checked_add(field_size)?;
        if end > extra.len() {
            return None;
        }
        if field_id == 0x0001 {
            payload = Some(&extra[cursor..end]);
            break;
        }
        cursor = end;
    }
    let payload = payload?;
    let mut pos = 0usize;
    for (needed, width, target) in [
        (uncompressed_sentinel, 8usize, 0u8),
        (compressed_sentinel, 8usize, 1u8),
        (local_sentinel, 8usize, 2u8),
        (disk_sentinel, 4usize, 3u8),
    ] {
        if !needed {
            continue;
        }
        let end = pos.checked_add(width)?;
        let bytes = payload.get(pos..end)?;
        match target {
            2 => local_header_offset = u64::from_le_bytes(bytes.try_into().ok()?),
            3 => disk_start = u32::from_le_bytes(bytes.try_into().ok()?) as u64,
            _ => {}
        }
        pos = end;
    }
    Some((local_header_offset, disk_start))
}
