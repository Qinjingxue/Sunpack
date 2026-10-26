// Native 7z observations are shared by public probes and report scoring.
#[derive(Default)]
struct SevenZipObservation {
    plausible: bool,
    magic_matched: bool,
    strong_accept: bool,
    error: &'static str,
    archive_offset: u64,
    segment_end: u64,
    next_header_offset: u64,
    next_header_size: u64,
    start_header_crc_ok: bool,
    next_header_crc_checked: bool,
    next_header_crc_ok: bool,
    next_header_nid: u8,
    next_header_nid_valid: bool,
    version_major: u8,
    version_minor: u8,
    password_required: bool,
    encrypted_header: bool,
    encrypted_payload: bool,
    password_state: &'static str,
    encryption_scan_complete: bool,
    evidence: Vec<&'static str>,
    read_fault: Option<(ReadFault, &'static str)>,
}

impl SevenZipObservation {
    fn to_python(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "7z")?;
        result.set_item("plausible", &self.plausible)?;
        result.set_item("magic_matched", &self.magic_matched)?;
        result.set_item("strong_accept", &self.strong_accept)?;
        result.set_item("error", &self.error)?;
        result.set_item("archive_offset", &self.archive_offset)?;
        result.set_item("segment_end", &self.segment_end)?;
        result.set_item("next_header_offset", &self.next_header_offset)?;
        result.set_item("next_header_size", &self.next_header_size)?;
        result.set_item("start_header_crc_ok", &self.start_header_crc_ok)?;
        result.set_item("next_header_crc_checked", &self.next_header_crc_checked)?;
        result.set_item("next_header_crc_ok", &self.next_header_crc_ok)?;
        result.set_item("next_header_nid", &self.next_header_nid)?;
        result.set_item("next_header_nid_valid", &self.next_header_nid_valid)?;
        result.set_item("version_major", &self.version_major)?;
        result.set_item("version_minor", &self.version_minor)?;
        result.set_item("password_required", &self.password_required)?;
        result.set_item("encrypted_header", &self.encrypted_header)?;
        result.set_item("encrypted_payload", &self.encrypted_payload)?;
        result.set_item("password_state", &self.password_state)?;
        result.set_item("encryption_scan_complete", &self.encryption_scan_complete)?;
        result.set_item("evidence", &self.evidence)?;
        if let Some((fault, legacy)) = &self.read_fault {
            set_view_read_fault(&result, fault, legacy)?;
        }
        Ok(result.unbind())
    }
}

impl AnalysisBinaryView {
    fn probe_seven_zip_native(
        &self,
        start_offset: u64,
    ) -> PyResult<SevenZipObservation> {
        self.ensure_open()?;
        let mut result = SevenZipObservation {
            archive_offset: start_offset,
            password_state: "unknown",
            ..Default::default()
        };
        let header = match self.read_field_at_bytes(
            start_offset,
            32,
            "7z.start_header",
            FieldLocation::Head,
        ) {
            Ok(data) => data,
            Err(fault) => {
                result.read_fault = Some((fault, "7z_header_too_small"));
                return Ok(result);
            }
        };
        if &header[0..6] != SEVEN_ZIP {
            result.error = "7z_signature_not_found";
            return Ok(result);
        }
        result.magic_matched = true;
        result.version_major = header[6];
        result.version_minor = header[7];
        if header[6] != 0 {
            result.error = "unsupported_version";
            return Ok(result);
        }
        let stored_start_crc = u32_le(&header, 8);
        let start_header = &header[12..32];
        let computed_start_crc = crc32(start_header);
        result.start_header_crc_ok = stored_start_crc == computed_start_crc;
        if stored_start_crc != computed_start_crc {
            result.error = "start_header_crc_mismatch";
            return Ok(result);
        }
        let next_header_offset = u64_le(start_header, 0);
        let next_header_size = u64_le(start_header, 8);
        let next_header_crc = u32_le(start_header, 16);
        let Some(next_header_start) = start_offset
            .checked_add(32)
            .and_then(|value| value.checked_add(next_header_offset))
        else {
            result.error = "next_header_out_of_range";
            return Ok(result);
        };
        let Some(segment_end) = next_header_start.checked_add(next_header_size) else {
            result.error = "next_header_out_of_range";
            return Ok(result);
        };
        result.next_header_offset = next_header_offset;
        result.next_header_size = next_header_size;
        result.segment_end = segment_end;
        if next_header_size == 0 && next_header_offset != 0 {
            result.error = "invalid_next_header_range";
            return Ok(result);
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
            result.read_fault = Some((fault, "next_header_out_of_range"));
            return Ok(result);
        }
        result.plausible = true;
        let mut evidence = Vec::new();
        evidence.push("7z:signature");
        evidence.push("7z:start_header_crc");
        evidence.push("7z:next_header_range");
        {
            // CRC covers the complete declared range with a fixed working buffer.
            // Spill large headers for shared encryption-fact parsing without
            // allocating the whole declared range on the heap.
            let mut next_header = crate::io::scratch::Spool::default();
            use std::io::Write;
            let mut hash = crc32fast::Hasher::new();
            let mut offset = next_header_start;
            while offset < segment_end {
                let length = (segment_end - offset).min(64 * 1024) as usize;
                let bytes = match self.read_field_at_bytes(
                    offset, length, "7z.next_header", FieldLocation::Tail,
                ) {
                    Ok(bytes) => bytes,
                    Err(fault) => {
                        result.read_fault = Some((fault, "next_header_read_failed"));
                        return Ok(result);
                    }
                };
                hash.update(&bytes);
                next_header.write_all(&bytes)?;
                offset += length as u64;
            }
            let next_header = next_header.finish()?;
            let crc_ok = hash.finalize() == next_header_crc;
            let nid = next_header.first().copied().unwrap_or(0);
            let nid_valid = next_header.is_empty() || nid == 0x01 || nid == 0x17;
            result.next_header_crc_checked = true;
            result.next_header_crc_ok = crc_ok;
            result.next_header_nid = nid;
            result.next_header_nid_valid = nid_valid;
            if crc_ok {
                evidence.push("7z:next_header_crc");
                if nid_valid {
                    let encryption = {
                        crate::formats::seven_zip::seven_zip_encryption_facts_from_next_header(
                            &next_header,
                        )
                    };
                    result.password_required = encryption.password_required;
                    result.encrypted_header = encryption.encrypted_header;
                    result.encrypted_payload = encryption.encrypted_payload;
                    result.password_state = if encryption.password_required {
                        "required"
                    } else if encryption.scan_complete {
                        "not_required"
                    } else {
                        "unknown"
                    };
                    result.encryption_scan_complete = encryption.scan_complete;
                    result.strong_accept = true;
                    evidence.push("7z:next_header_nid");
                } else {
                    result.error = "next_header_nid_unrecognized";
                }
            } else {
                result.error = "next_header_crc_mismatch";
            }
        }
        result.evidence = evidence;
        Ok(result)
    }
}
