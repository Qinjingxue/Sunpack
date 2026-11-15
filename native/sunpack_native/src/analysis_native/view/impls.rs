impl AnalysisBinaryView {
    fn probe_zip_with_disk_starts(
        &self,
        eocd_offset: u64,
        eocd: &[u8; 22],
        disk_starts: Option<&[u64]>,
    ) -> std::io::Result<ZipObservation> {
        let mut result = ZipObservation {
            eocd_offset,
            ..Default::default()
        };

        let disk_number = u16_le(eocd, 4);
        let central_directory_disk = u16_le(eocd, 6);
        let disk_entries = u16_le(eocd, 8);
        let total_entries = u16_le(eocd, 10);
        let central_directory_size = u32_le(eocd, 12) as u64;
        let central_directory_offset = u32_le(eocd, 16) as u64;
        result.comment_length = u16_le(eocd, 20) as u64;

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
                result.error = error;
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
            result.error = "zip_multi_disk";
            return Ok(result);
        }
        if effective_disk_entries != effective_total_entries && !is_multi_disk {
            result.error = "entry_count_mismatch";
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
                result.error = "central_directory_disk_offset_out_of_range";
                return Ok(result);
            }
            if zip64_present
                && (zip64_declared_total_disks as usize != starts.len()
                    || effective_disk_number as usize + 1 != starts.len())
            {
                result.error = "zip64_disk_count_mismatch";
                return Ok(result);
            }
        }
        if !is_multi_disk && directory_end < effective_central_directory_size {
            result.error = "central_directory_size_out_of_range";
            return Ok(result);
        }
        let physical_central_offset = if is_multi_disk {
            let starts = disk_starts.expect("multi-disk ZIP requires a volume layout");
            let Some(offset) = self.zip_logical_offset_for_disk(
                starts,
                effective_central_directory_disk,
                effective_central_directory_offset,
            ) else {
                result.error = "central_directory_disk_offset_out_of_range";
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
                    .reader
                    .read_cached_at(naive_physical_central_offset, 4)
                    .is_ok_and(|sig| sig.as_slice() == ZIP_CENTRAL);
                if !naive_ok
                    && self
                        .reader
                        .read_cached_at(declared_physical_central_offset, 4)
                        .is_ok_and(|sig| sig.as_slice() == ZIP_CENTRAL)
                {
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
                result.error = "archive_offset_underflow";
                return Ok(result);
            }
            physical_central_offset - effective_central_directory_offset
        };
        result.archive_offset = archive_offset;

        if physical_central_offset
            .checked_add(effective_central_directory_size)
            .is_none_or(|end| end != directory_end)
        {
            result.error = "central_directory_size_mismatch";
            return Ok(result);
        }
        if effective_total_entries == 0 && effective_central_directory_size == 0 {
            result.walk_ok = true;
            return Ok(result);
        }

        match self.reader.read_cached_at(physical_central_offset, 4) {
            Ok(data) if data.as_slice() == ZIP_CENTRAL => {}
            Ok(data) if data.len() == 4 => {
                result.error = "bad_central_directory_signature";
                return Ok(result);
            }
            _ => {
                result.error = "central_directory_read_failed";
                return Ok(result);
            }
        }

        let walk = self.walk_zip_central_directory(
            archive_offset,
            physical_central_offset,
            effective_central_directory_size,
            effective_total_entries as usize,
            disk_starts.filter(|_| is_multi_disk),
        )?;
        result.walk_ok = walk.error.is_empty();
        result.password_required = walk.password_required;
        result.error = walk.error;
        result.content_integrity_warning = result.walk_ok && walk.content_warning;
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
        let mut header = [0u8; 46];
        let mut local = [0u8; 30];
        let mut extra = Vec::new();
        for index in 0..total_entries {
            if cursor.saturating_add(46) > end {
                return Ok(walk.failed("central_directory_entry_out_of_range"));
            }
            let count = zip_window_read(&mut directory, cursor, &mut header)?;
            if count < header.len() || &header[..4] != ZIP_CENTRAL {
                return Ok(walk.failed("bad_central_directory_entry_signature"));
            }
            walk.password_required |= u16_le(&header, 8) & 0x0001 != 0;
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as usize;
            let comment_len = u16_le(&header, 32) as u64;
            let entry_size = 46 + filename_len + extra_len as u64 + comment_len;
            if cursor.saturating_add(entry_size) > end {
                return Ok(walk.failed("central_directory_variable_fields_out_of_range"));
            }
            use crate::formats::zip::zip64::central_entry_values;
            let mut location = central_entry_values(&header, &[]);
            if location.is_none() && extra_len != 0 {
                // Only ZIP64 sentinel fields require the variable extra data.
                if extra.len() < extra_len {
                    extra = crate::io::resource_error::zeroed_bytes(extra_len)?;
                }
                let count = zip_window_read(
                    &mut directory,
                    cursor + 46 + filename_len,
                    &mut extra[..extra_len],
                )?;
                location = central_entry_values(&header, &extra[..count]);
            }
            let Some(location) = location else {
                return Ok(walk.failed("zip64_extra_missing_or_invalid"));
            };
            let local_logical = if let Some(starts) = disk_starts {
                self.zip_logical_offset_for_disk(starts, location.disk, location.local_offset)
            } else {
                archive_offset.checked_add(location.local_offset)
            };
            let Some(local_logical) = local_logical else {
                return Ok(walk.failed("local_header_link_mismatch"));
            };
            // Only a prefixed ZIP can become a carved range here. Ordinary
            // EOCD detection has already ruled out trailing bytes, so its
            // bounded CRC hint would be discarded.
            let check_crc = archive_offset != 0 && index < 8 && !walk.content_warning;
            let length = if check_crc { local.len() } else { 4 };
            let count = zip_window_read(&mut locals, local_logical, &mut local[..length])?;
            if count < 4 || &local[..4] != ZIP_LOCAL {
                return Ok(walk.failed("local_header_link_mismatch"));
            }
            if check_crc && count == local.len() {
                walk.content_warning =
                    u16_le(&local, 6) & 0x0008 != 0 || u32_le(&local, 14) != u32_le(&header, 16);
            }
            cursor += entry_size;
        }
        let complete =
            crate::formats::zip::central_directory_complete(cursor, end, |offset, length| {
                let count = zip_window_read(&mut directory, offset, &mut header[..length])?;
                Ok::<_, io::Error>(header[..count].to_vec())
            })?;
        if !complete {
            return Ok(walk.failed("central_directory_size_mismatch"));
        }
        Ok(walk)
    }

    fn walk_tar(&self) -> io::Result<TarObservation> {
        let size = self.reader.len();
        let mut cursor = 0u64;
        let mut seen_member = false;
        let mut seen_zero = false;
        let mut state = crate::formats::tar::TarState::default();
        while cursor.saturating_add(TAR_BLOCK_SIZE as u64) <= size {
            let header = self.reader.read_cached_at(cursor, TAR_BLOCK_SIZE)?;
            if header.len() != TAR_BLOCK_SIZE {
                return Ok(TarObservation::Unrecognized);
            }
            if header.iter().all(|&byte| byte == 0) {
                if !seen_member {
                    return Ok(TarObservation::Unrecognized);
                }
                cursor += TAR_BLOCK_SIZE as u64;
                if seen_zero {
                    return Ok(TarObservation::Terminated(cursor));
                }
                seen_zero = true;
                continue;
            }
            seen_zero = false;
            let Ok(member_size) = crate::formats::tar::header_size(&header) else {
                break;
            };
            match state.advance_validated(
                &header,
                member_size,
                cursor,
                size,
                &mut |start, length| self.reader.read_at(start, length),
            ) {
                Ok(record) => cursor = record.next,
                Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                    return Ok(TarObservation::Recognized(None));
                }
                Err(_) => break,
            }
            seen_member = true;
        }
        // A member ending at EOF identifies TAR even without its terminator.
        // Otherwise retain the format hint without claiming a bounded range.
        Ok(if seen_member {
            TarObservation::Recognized((cursor == size).then_some(cursor))
        } else {
            TarObservation::Unrecognized
        })
    }
}

/// Results of the single bounded directory walk, shared by all ZIP projections.
#[derive(Default)]
struct ZipDirectoryWalk {
    password_required: bool,
    error: &'static str,
    content_warning: bool,
}

impl ZipDirectoryWalk {
    fn failed(mut self, error: &'static str) -> Self {
        self.error = error;
        self
    }
}

// seek_relative preserves bytes already buffered when ZIP records are nearby.
fn zip_window_read(
    reader: &mut std::io::BufReader<crate::io::reader::SourceCursor>,
    offset: u64,
    bytes: &mut [u8],
) -> io::Result<usize> {
    use std::io::{Seek, SeekFrom};
    let current = reader.stream_position()?;
    if let Ok(delta) = i64::try_from(i128::from(offset) - i128::from(current)) {
        reader.seek_relative(delta)?;
    } else {
        reader.seek(SeekFrom::Start(offset))?;
    }
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(reader_error(error)),
        }
    }
    Ok(used)
}
