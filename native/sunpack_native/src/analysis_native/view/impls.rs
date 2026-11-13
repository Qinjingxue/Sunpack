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

    fn locate_zip_eocd_native(&self, offset: u64) -> io::Result<Option<ZipEocdCandidate>> {
        let record = self.read_at_bytes(offset, 22)?;
        Ok((record.len() == 22 && record.starts_with(ZIP_EOCD)).then(|| ZipEocdCandidate {
            offset, comment_length: u64::from(u16_le(&record, 20)),
        }))
    }

    fn probe_zip_with_disk_starts(
        &self,

        eocd_offset: u64,
        disk_starts: Option<&[u64]>,
    ) -> std::io::Result<ZipObservation> {
        let mut result = ZipObservation { eocd_offset, ..Default::default() };

        let eocd = match self.read_field_at_bytes(eocd_offset, 22, "zip.eocd", FieldLocation::Tail)
        {
            Ok(data) => data,
            Err(fault) => {
                result.error = "eocd_too_small".to_owned();
                result.read_fault = Some(fault);
                return Ok(result);
            }
        };
        if &eocd[0..4] != ZIP_EOCD {
            result.error = "bad_eocd_signature".to_owned();
            return Ok(result);
        }
        result.magic_matched = true;
        let disk_number = u16_le(&eocd, 4);
        let central_directory_disk = u16_le(&eocd, 6);
        let disk_entries = u16_le(&eocd, 8);
        let total_entries = u16_le(&eocd, 10);
        let central_directory_size = u32_le(&eocd, 12) as u64;
        let central_directory_offset = u32_le(&eocd, 16) as u64;
        let comment_length = u16_le(&eocd, 20) as u64;
        result.comment_length = comment_length;

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

                result.error = error.to_string();
                return Ok(result);
            }
            Err(crate::formats::zip::zip64::LocateError::Read(error)) => {
                return Err(reader_error(error));
            }
        }

        let is_multi_disk = effective_disk_number != 0 || effective_central_directory_disk != 0;
        result.is_multi_disk = is_multi_disk;

        if is_multi_disk && disk_starts.is_none() {
            // A single physical input cannot resolve PKZIP disk-relative
            // offsets.  MultiVolumeBinaryView supplies the Rust-owned layout.
            result.error = "zip_multi_disk".to_owned();
            return Ok(result);
        }
        if effective_disk_entries != effective_total_entries && !is_multi_disk {
            result.error = "entry_count_mismatch".to_owned();
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
                result.error = "central_directory_disk_offset_out_of_range".to_owned();
                return Ok(result);
            }
            if zip64_present
                && (zip64_declared_total_disks as usize != starts.len()
                    || effective_disk_number as usize + 1 != starts.len())
            {
                result.error = "zip64_disk_count_mismatch".to_owned();
                return Ok(result);
            }
        }
        if !is_multi_disk && directory_end < effective_central_directory_size {
            result.error = "central_directory_size_out_of_range".to_owned();
            return Ok(result);
        }
        let physical_central_offset = if is_multi_disk {
            let starts = disk_starts.expect("multi-disk ZIP requires a volume layout");
            let Some(offset) = self.zip_logical_offset_for_disk(
                starts,
                effective_central_directory_disk,
                effective_central_directory_offset,
            ) else {
                result.error = "central_directory_disk_offset_out_of_range".to_owned();
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
                result.error = "archive_offset_underflow".to_owned();
                return Ok(result);
            }
            physical_central_offset - effective_central_directory_offset
        };
        result.archive_offset = archive_offset;

        if physical_central_offset
            .checked_add(effective_central_directory_size)
            .is_none_or(|end| end != directory_end)
        {
            result.error = "central_directory_size_mismatch".to_owned();
            return Ok(result);
        }
        if effective_total_entries == 0 && effective_central_directory_size == 0 {
            result.plausible = true;
            result.central_directory_walk_ok = true;
            result.local_header_links_ok = true;

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
                result.error = "central_directory_read_failed".to_owned();
                result.read_fault = Some(fault);
                return Ok(result);
            }
        };
        if central_sig.as_slice() != ZIP_CENTRAL {
            result.error = "bad_central_directory_signature".to_owned();
            return Ok(result);
        }

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
            directory_ok: cd_ok,
            links_ok,
            encrypted_entries,
            error,
            content_warning,
        } = walk;

        result.central_directory_walk_ok = cd_ok;

        result.local_header_links_ok = links_ok;
        result.password_required = encrypted_entries > 0;

        if error.is_empty() {
            result.plausible = true;
            result.content_integrity_warning = content_warning.to_owned();
        } else {
            result.error = error.to_string();
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
                return Ok(walk.failed(false, "central_directory_entry_out_of_range"));
            }
            let header = zip_window_read(&mut directory, cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok(walk.failed(false, "bad_central_directory_entry_signature"));
            }
            if u16_le(&header, 8) & 0x0001 != 0 {
                walk.encrypted_entries += 1;
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as usize;
            let comment_len = u16_le(&header, 32) as u64;
            let entry_size = 46 + filename_len + extra_len as u64 + comment_len;
            if cursor.saturating_add(entry_size) > end {
                return Ok(walk.failed(false,
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
                return Ok(walk.failed(true, "zip64_extra_missing_or_invalid"));
            };
            let local_logical = if let Some(starts) = disk_starts {
                self.zip_logical_offset_for_disk(starts, location.disk, location.local_offset)
            } else {
                archive_offset.checked_add(location.local_offset)
            };
            let Some(local_logical) = local_logical else {
                return Ok(walk.failed(true, "local_header_link_mismatch"));
            };
            // Fetch once for both link validation and the existing bounded CRC
            // consistency hint. Later entries only need their four-byte signature.
            let check_crc = index < 8 && walk.content_warning.is_empty();
            let local =
                zip_window_read(&mut locals, local_logical, if check_crc { 30 } else { 4 })?;
            if local.len() < 4 || &local[..4] != ZIP_LOCAL {
                return Ok(walk.failed(true, "local_header_link_mismatch"));
            }
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
        walk.directory_ok =
            crate::formats::zip::central_directory_complete(cursor, end, |offset, length| {
                zip_window_read(&mut directory, offset, length)
            })?;
        walk.links_ok = walk.directory_ok;
        if !walk.directory_ok {
            return Ok(walk.failed(false, "central_directory_size_mismatch"));
        }
        Ok(walk)
    }

    fn walk_tar(&self, start_offset: u64) -> std::io::Result<TarObservation> {
        let mut result = TarObservation::default();

        let size = self.reader.len();
        let mut cursor = start_offset;
        let mut checked = 0usize;
        let mut zero_blocks = 0usize;
        let mut tar_state = crate::formats::tar::TarState::default();
        if start_offset.saturating_add(TAR_BLOCK_SIZE as u64) > size {
            let fault = ReadFault::short_read(
                "read_record",
                start_offset,
                TAR_BLOCK_SIZE,
                size.saturating_sub(start_offset) as usize,
                size,
            )
            .with_field("tar.member.header", FieldLocation::Head);
            result.error = "short_tar_header".to_owned();
            result.read_fault = Some(fault);
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
                    result.error = "tar_header_read_failed".to_owned();
                    result.read_fault = Some(fault);
                    return Ok(result);
                }
            };
            if header.iter().all(|byte| *byte == 0) {
                if checked == 0 {

                    result.error = "leading_zero_block".to_owned();
                    return Ok(result);
                }
                zero_blocks += 1;
                cursor += TAR_BLOCK_SIZE as u64;
                if zero_blocks >= 2 {
                    result.plausible = checked > 0;

                    result.walk_complete = true;

                    result.segment_end = Some(cursor);

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
                result.magic_matched = identity.ustar_magic
                        || (identity.name_nonempty
                            && identity.numeric_fields_valid
                            && identity.typeflag_valid);
            }
            let member_size = first_identity.map_or_else(
                || crate::formats::tar::header_size(&header),
                |identity| identity.validated_size,
            );
            let member_size = match member_size {
                Ok(size) => size,
                Err(error) => {

                    result.error = error.to_string();
                    let flag = match header[156] {
                        b'x' | b'g' => "pax_header_bad",
                        b'L' | b'K' => "gnu_longname_bad",
                        b'S' => "sparse_header_bad",
                        _ if error == "checksum_mismatch" => "tar_checksum_bad",
                        _ => "tar_metadata_bad",
                    };
                    result.damage_flags = [flag].into_iter().map(str::to_owned).collect();
                    if checked > 0 {
                        result.plausible = true;

                        result.segment_end = None;
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

                    result.plausible = checked > 0;

                    if error.kind() == io::ErrorKind::OutOfMemory {
                        result.plausible = true;

                        result.error = "analysis_resource_limit".to_owned();
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
                        result.error = "member_payload_out_of_range".to_owned();
                        result.read_fault = Some(fault);
                    } else {
                        result.error = error.to_string();
                        let flag = match header[156] {
                            b'x' | b'g' => "pax_header_bad",
                            b'L' | b'K' => "gnu_longname_bad",
                            b'S' => "sparse_header_bad",
                            _ => "tar_metadata_bad",
                        };
                        result.damage_flags = [flag].into_iter().map(str::to_owned).collect();
                    }
                    return Ok(result);
                }
            };
            checked += 1;
            cursor = next_cursor;
        }
        if checked > 0 && cursor == size {
            result.plausible = true;

            result.walk_complete = true;
            result.segment_end = Some(cursor);

            result.error = "tar_end_zero_blocks_missing_at_eof".to_owned();
            result.damage_flags = ["missing_end_block"].into_iter().map(str::to_owned).collect();
        } else if checked > 0 {
            result.plausible = true;

            result.segment_end = None;

            let fault = ReadFault::short_read(
                "read_record",
                cursor,
                TAR_BLOCK_SIZE * 2,
                size.saturating_sub(cursor).min((TAR_BLOCK_SIZE * 2) as u64) as usize,
                size,
            )
            .with_field("tar.archive.end_zero_blocks", FieldLocation::Tail);
            result.error = "tar_end_zero_blocks_not_found".to_owned();
            result.read_fault = Some(fault);
        }
        Ok(result)
    }
}

/// Results of the single bounded directory walk, shared by all ZIP projections.
#[derive(Default)]
struct ZipDirectoryWalk {
    directory_ok: bool,
    links_ok: bool,
    encrypted_entries: usize,
    error: &'static str,
    content_warning: &'static str,
}

impl ZipDirectoryWalk {
    fn failed(mut self, directory_ok: bool, error: &'static str) -> Self {
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
