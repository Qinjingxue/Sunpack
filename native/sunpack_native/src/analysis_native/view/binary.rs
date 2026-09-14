#[pymethods]
impl AnalysisBinaryView {
    #[new]
    #[pyo3(signature = (path, cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn new(
        path: String,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes,
                max_read_bytes,
                max_concurrent_reads,
            },
        )?;
        Ok(Self {
            path,
            reader,
            closed: false,
        })
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        self.ensure_open()?;
        Ok(self.reader.len())
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    #[getter]
    fn closed(&self) -> bool {
        self.closed
    }

    fn close(&mut self) {
        if !self.closed {
            self.reader = ManagedReader::closed();
            self.closed = true;
        }
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.read_at_bytes(offset, size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let view_size = self.reader.len();
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        let data = self.read_at_bytes(offset, read_size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let stats = self.reader.stats()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", stats.read_bytes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (eocd_offset, max_cd_entries_to_walk=64))]
    fn probe_zip(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
        max_cd_entries_to_walk: usize,
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
        if is_multi_disk {
            result.set_item("error", "zip_multi_disk")?;
            let evidence = PyList::empty(py);
            evidence.append("zip:eocd_multi_disk")?;
            result.set_item("evidence", evidence)?;
            return Ok(result.unbind());
        }
        if effective_disk_entries != effective_total_entries {
            result.set_item("error", "entry_count_mismatch")?;
            return Ok(result.unbind());
        }
        if directory_end < effective_central_directory_size {
            result.set_item("error", "central_directory_size_out_of_range")?;
            return Ok(result.unbind());
        }
        let naive_physical_central_offset = directory_end - effective_central_directory_size;
        let declared_physical_central_offset = effective_central_directory_offset;
        // Prefer the physically verified declared offset when the naive
        // back-computation misses the signature (same fallback as
        // formats/zip/directory/inspect.rs).  Otherwise keep the naive
        // position so SFX prefixes keep working via archive_offset.
        let physical_central_offset = if naive_physical_central_offset != declared_physical_central_offset {
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
        };
        if physical_central_offset < effective_central_directory_offset {
            result.set_item("error", "archive_offset_underflow")?;
            return Ok(result.unbind());
        }
        let archive_offset = physical_central_offset - effective_central_directory_offset;
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
            result.set_item("evidence", evidence)?;
        } else {
            result.set_item("error", error)?;
        }
        Ok(result.unbind())
    }

    #[pyo3(signature = (start_offset, max_blocks_to_walk=4096))]
    fn probe_rar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_blocks_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "rar")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("strong_accept", false)?;
        result.set_item("error", "")?;
        result.set_item("archive_offset", start_offset)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("version", 0u8)?;
        result.set_item("blocks_checked", 0usize)?;
        result.set_item("end_block_found", false)?;
        result.set_item("end_block_flags", 0u64)?;
        result.set_item("first_header_offset", 0u64)?;
        result.set_item("first_header_size", 0u64)?;
        result.set_item("first_header_type", 0u64)?;
        result.set_item("header_crc_checked", false)?;
        result.set_item("header_crc_ok", false)?;
        result.set_item("second_block_checked", false)?;
        result.set_item("second_block_ok", false)?;
        result.set_item("second_block_type", 0u64)?;
        result.set_item("second_block_size", 0u64)?;
        result.set_item("block_walk_ok", false)?;
        result.set_item("evidence", PyList::empty(py))?;

        let header = match self.read_field_at_bytes(
            start_offset,
            RAR5.len(),
            "rar.signature",
            FieldLocation::Head,
        ) {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&result, &fault, "rar_signature_incomplete_or_unknown")?;
                return Ok(result.unbind());
            }
        };
        if header.starts_with(RAR5) {
            result.set_item("magic_matched", true)?;
            result.set_item("version", 5u8)?;
            self.probe_rar5(py, &result, start_offset, max_blocks_to_walk)?;
        } else if header.starts_with(RAR4) {
            result.set_item("magic_matched", true)?;
            result.set_item("version", 4u8)?;
            self.probe_rar4(py, &result, start_offset, max_blocks_to_walk)?;
        } else if header.starts_with(b"Rar!") {
            result.set_item("magic_matched", true)?;
            result.set_item("error", "rar_signature_incomplete_or_unknown")?;
        } else {
            result.set_item("error", "rar_signature_not_found")?;
        }
        Ok(result.unbind())
    }

    #[pyo3(signature = (start_offset, max_next_header_check_bytes=1048576))]
    fn probe_seven_zip(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_next_header_check_bytes: u64,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "7z")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("strong_accept", false)?;
        result.set_item("error", "")?;
        result.set_item("archive_offset", start_offset)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("next_header_offset", 0u64)?;
        result.set_item("next_header_size", 0u64)?;
        result.set_item("start_header_crc_ok", false)?;
        result.set_item("next_header_crc_checked", false)?;
        result.set_item("next_header_crc_ok", false)?;
        result.set_item("next_header_nid", 0u8)?;
        result.set_item("next_header_nid_valid", false)?;
        result.set_item("password_required", false)?;
        result.set_item("encrypted_header", false)?;
        result.set_item("encrypted_payload", false)?;
        result.set_item("password_state", "unknown")?;
        result.set_item("encryption_scan_complete", false)?;
        result.set_item("evidence", PyList::empty(py))?;

        let header = match self.read_field_at_bytes(
            start_offset,
            32,
            "7z.start_header",
            FieldLocation::Head,
        ) {
            Ok(data) => data,
            Err(fault) => {
                set_view_read_fault(&result, &fault, "7z_header_too_small")?;
                return Ok(result.unbind());
            }
        };
        if &header[0..6] != SEVEN_ZIP {
            result.set_item("error", "7z_signature_not_found")?;
            return Ok(result.unbind());
        }
        result.set_item("magic_matched", true)?;
        if header[6] != 0 {
            result.set_item("error", "unsupported_version")?;
            return Ok(result.unbind());
        }
        let stored_start_crc = u32_le(&header, 8);
        let start_header = &header[12..32];
        let computed_start_crc = crc32(start_header);
        result.set_item(
            "start_header_crc_ok",
            stored_start_crc == computed_start_crc,
        )?;
        if stored_start_crc != computed_start_crc {
            result.set_item("error", "start_header_crc_mismatch")?;
            return Ok(result.unbind());
        }
        let next_header_offset = u64_le(start_header, 0);
        let next_header_size = u64_le(start_header, 8);
        let next_header_crc = u32_le(start_header, 16);
        let Some(next_header_start) = start_offset
            .checked_add(32)
            .and_then(|value| value.checked_add(next_header_offset))
        else {
            result.set_item("error", "next_header_out_of_range")?;
            return Ok(result.unbind());
        };
        let Some(segment_end) = next_header_start.checked_add(next_header_size) else {
            result.set_item("error", "next_header_out_of_range")?;
            return Ok(result.unbind());
        };
        result.set_item("next_header_offset", next_header_offset)?;
        result.set_item("next_header_size", next_header_size)?;
        result.set_item("segment_end", segment_end)?;
        if next_header_size == 0 {
            result.set_item("error", "invalid_next_header_range")?;
            return Ok(result.unbind());
        }
        let size = self.reader.len();
        if segment_end > size {
            let fault = ReadFault::short_read(
                "read_declared_range",
                next_header_start,
                usize::try_from(next_header_size).unwrap_or(usize::MAX),
                size.saturating_sub(next_header_start) as usize,
                size,
            )
            .with_field("7z.next_header", FieldLocation::Tail);
            set_view_read_fault(&result, &fault, "next_header_out_of_range")?;
            return Ok(result.unbind());
        }
        result.set_item("plausible", true)?;
        let evidence = PyList::empty(py);
        evidence.append("7z:signature")?;
        evidence.append("7z:start_header_crc")?;
        evidence.append("7z:next_header_range")?;
        if next_header_size <= max_next_header_check_bytes {
            let next_header = match self.read_field_at_bytes(
                next_header_start,
                next_header_size as usize,
                "7z.next_header",
                FieldLocation::Tail,
            ) {
                Ok(data) => data,
                Err(fault) => {
                    set_view_read_fault(&result, &fault, "next_header_read_failed")?;
                    result.set_item("plausible", false)?;
                    return Ok(result.unbind());
                }
            };
            let crc_ok = crc32(&next_header) == next_header_crc;
            let nid = next_header.first().copied().unwrap_or(0);
            let nid_valid = nid == 0x01 || nid == 0x17;
            result.set_item("next_header_crc_checked", true)?;
            result.set_item("next_header_crc_ok", crc_ok)?;
            result.set_item("next_header_nid", nid)?;
            result.set_item("next_header_nid_valid", nid_valid)?;
            if crc_ok {
                evidence.append("7z:next_header_crc")?;
                if nid_valid {
                    let encryption =
                        crate::formats::seven_zip::seven_zip_encryption_facts_from_next_header(
                            &next_header,
                        );
                    result.set_item("password_required", encryption.password_required)?;
                    result.set_item("encrypted_header", encryption.encrypted_header)?;
                    result.set_item("encrypted_payload", encryption.encrypted_payload)?;
                    result.set_item(
                        "password_state",
                        if encryption.password_required {
                            "required"
                        } else if encryption.scan_complete {
                            "not_required"
                        } else {
                            "unknown"
                        },
                    )?;
                    result.set_item("encryption_scan_complete", encryption.scan_complete)?;
                    result.set_item("strong_accept", true)?;
                    evidence.append("7z:next_header_nid")?;
                } else {
                    result.set_item("error", "next_header_nid_unrecognized")?;
                }
            } else {
                result.set_item("error", "next_header_crc_mismatch")?;
            }
        }
        result.set_item("evidence", evidence)?;
        Ok(result.unbind())
    }

    #[pyo3(signature = (start_offset=0, max_entries_to_walk=64))]
    fn probe_tar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_entries_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = self.walk_tar(py, start_offset, max_entries_to_walk)?;
        Ok(result.unbind())
    }

    fn probe_compression_stream(&self, py: Python<'_>, format: &str) -> PyResult<Py<PyDict>> {
        let result = self.probe_compression(py, format)?;
        Ok(result.unbind())
    }

    #[pyo3(signature = (format, max_probe_bytes=4194304))]
    fn probe_compressed_tar(
        &self,
        py: Python<'_>,
        format: &str,
        max_probe_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let stream = self.probe_compression(py, format)?;
        stream.set_item("container", format)?;
        stream.set_item("inner_format", "tar")?;
        stream.set_item("inner_tar_verified", false)?;
        stream.set_item("tar_plausible", false)?;
        stream.set_item("tar_probe_error", "")?;
        if !stream
            .get_item("magic_matched")?
            .unwrap()
            .extract::<bool>()?
        {
            return Ok(stream.unbind());
        }
        let input_budget = self.reader.len().min(max_probe_bytes as u64);
        let source = self.reader.stream_cursor().take(input_budget);
        match decompress_sample(format, source, TAR_BLOCK_SIZE * 2) {
            Ok(sample) => {
                if sample.len() < TAR_BLOCK_SIZE {
                    stream.set_item("tar_probe_error", "inner_sample_too_small")?;
                    return Ok(stream.unbind());
                }
                let (ok, error, member_size, ustar) =
                    tar_header_plausible(&sample[..TAR_BLOCK_SIZE]);
                stream.set_item("inner_tar_verified", ok)?;
                stream.set_item("tar_plausible", ok)?;
                stream.set_item("tar_probe_error", error)?;
                stream.set_item("inner_tar_member_size", member_size)?;
                stream.set_item("inner_tar_ustar", ustar)?;
            }
            Err(error) => {
                stream.set_item("tar_probe_error", error)?;
            }
        }
        Ok(stream.unbind())
    }

    #[pyo3(signature = (
        window_bytes=65536,
        max_windows=8,
        max_sample_bytes=1048576,
        entropy_high_threshold=6.8,
        entropy_low_threshold=3.5,
        entropy_jump_threshold=1.25,
        ngram_top_k=8,
        max_ngram_sample_bytes=262144
    ))]
    fn fuzzy_binary_profile(
        &self,
        py: Python<'_>,
        window_bytes: usize,
        max_windows: usize,
        max_sample_bytes: usize,
        entropy_high_threshold: f64,
        entropy_low_threshold: f64,
        entropy_jump_threshold: f64,
        ngram_top_k: usize,
        max_ngram_sample_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let file_size = self.reader.len();
        let window_bytes = window_bytes.max(1024);
        let config = BinaryProfileConfig {
            window_bytes,
            max_windows: max_windows.max(1),
            max_sample_bytes: max_sample_bytes.max(window_bytes),
            entropy_high_threshold,
            entropy_low_threshold,
            entropy_jump_threshold,
            ngram_top_k: ngram_top_k.max(1),
            max_ngram_sample_bytes,
        };
        build_fuzzy_binary_profile(
            py,
            file_size,
            |offset, size| self.read_at_bytes(offset, size),
            config,
        )
    }

    #[pyo3(signature = (head_bytes=1048576, tail_bytes=1048576))]
    fn signature_prepass(
        &self,
        py: Python<'_>,
        head_bytes: usize,
        tail_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let size = self.reader.len();
        let head_len = head_bytes.min(size as usize);
        let tail_len = tail_bytes.min(size as usize);
        let tail_start = size.saturating_sub(tail_len as u64);
        let head_end = head_len as u64;
        let scan_start = 0u64;
        let tail_end = size;
        let (scan_start, scan_len, scanned_head, scanned_tail) = if tail_start <= head_end {
            let end = head_end.max(tail_end);
            (
                scan_start,
                end.saturating_sub(scan_start) as usize,
                head_len,
                tail_len,
            )
        } else {
            (0u64, head_len, head_len, 0usize)
        };

        let mut hits = Vec::new();
        if tail_start <= head_end {
            let data = self.read_at_bytes(scan_start, scan_len)?;
            collect_signature_hits(&mut hits, scan_start, &data);
        } else {
            let mut ranges = self
                .reader
                .read_many(&[(0, head_len), (tail_start, tail_len)])
                .map_err(reader_error_to_py)?;
            let head = ranges.remove(0);
            collect_signature_hits(&mut hits, 0, &head);
            let tail = ranges.remove(0);
            collect_signature_hits(&mut hits, tail_start, &tail);
        }
        hits.sort_by_key(|(_, offset)| *offset);
        hits.dedup();

        let dict = PyDict::new(py);
        let py_hits = PyList::empty(py);
        let mut formats = Vec::new();
        for (name, offset) in hits {
            let hit = PyDict::new(py);
            hit.set_item("name", name)?;
            hit.set_item("offset", offset)?;
            py_hits.append(hit)?;
            let format = format_for_hit(name);
            if !formats.contains(&format) {
                formats.push(format);
            }
        }
        formats.sort();
        dict.set_item("hits", py_hits)?;
        dict.set_item("formats", formats)?;
        dict.set_item("head_bytes", scanned_head)?;
        dict.set_item(
            "tail_bytes",
            if scanned_tail == 0 {
                tail_len
            } else {
                scanned_tail
            },
        )?;
        Ok(dict.unbind())
    }
}
