pub(crate) fn inspect_zip_directory_consistency(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let result = zip_directory_consistency_empty(py)?;
    let Ok(data) = crate::io::reader::ManagedReader::open(path)
        .and_then(|reader| reader.read_all()) else {
        result.set_item("error", "os_error")?;
        return Ok(result.unbind());
    };
    result.set_item("file_size", data.len())?;
    let Some(eocd) = find_eocd_record(&data, true) else {
        result.set_item("error", "eocd_not_found")?;
        return Ok(result.unbind());
    };
    let resolved = resolve_central_directory(&data, &eocd);
    let physical_cd_offset = resolved.physical_offset;
    let cd_end = resolved.end;
    let archive_offset = resolved.archive_offset;
    result.set_item("eocd_offset", eocd.offset)?;
    result.set_item("declared_central_directory_offset", resolved.declared_offset)?;
    result.set_item("declared_central_directory_size", resolved.declared_size)?;
    result.set_item("declared_total_entries", resolved.total_entries)?;
    result.set_item("physical_central_directory_offset", physical_cd_offset)?;
    result.set_item("archive_offset", archive_offset)?;
    result.set_item(
        "central_directory_offset_delta",
        physical_cd_offset as i64 - resolved.declared_offset as i64,
    )?;
    result.set_item(
        "central_directory_size_delta",
        cd_end.saturating_sub(physical_cd_offset) as i64 - resolved.declared_size as i64,
    )?;
    if physical_cd_offset + 4 > data.len() || data.get(physical_cd_offset..physical_cd_offset + 4) != Some(CD_SIG) {
        result.set_item("error", "bad_central_directory_signature")?;
        result.set_item("bad_central_directory_signature_offset", physical_cd_offset)?;
        return Ok(result.unbind());
    }

    let all_entries = parse_central_directory_entries(&data, physical_cd_offset, cd_end);
    let checked_entries = all_entries.iter().take(max_entries).collect::<Vec<_>>();
    result.set_item("cd_parseable", !all_entries.is_empty())?;
    result.set_item("cd_entries_checked", checked_entries.len())?;
    result.set_item("cd_entries_parseable", all_entries.len())?;
    result.set_item("cd_entries_truncated_by_limit", all_entries.len() > checked_entries.len())?;
    result.set_item(
        "entry_count_delta",
        all_entries.len() as i64 - resolved.total_entries as i64,
    )?;
    if all_entries.is_empty() {
        result.set_item("error", "no_central_directory_entries_parseable")?;
        return Ok(result.unbind());
    }
    let local_candidates = scan_zip_local_headers(&data, physical_cd_offset, max_entries.saturating_mul(4).max(32));
    let local_spans = local_record_spans(&local_candidates, physical_cd_offset);
    let (known_payload_spans, known_descriptor_spans) =
        local_payload_descriptor_spans(&data, &local_candidates, physical_cd_offset);
    let first_local_offset = local_candidates.first().map(|local| local.offset).unwrap_or(0);
    let prefix_len = first_local_offset;

    let mut local_missing = 0usize;
    let mut local_bad_sig = 0usize;
    let mut name_mismatch = 0usize;
    let mut flags_mismatch = 0usize;
    let mut method_mismatch = 0usize;
    let mut crc_mismatch = 0usize;
    let mut compressed_mismatch = 0usize;
    let mut uncompressed_mismatch = 0usize;
    let mut local_extra_len_mismatch = 0usize;
    let mut offset_suspicious = 0usize;
    let mut descriptor_checked = 0usize;
    let mut descriptor_present = 0usize;
    let mut descriptor_missing = 0usize;
    let mut descriptor_flag_mismatch = 0usize;
    let mut descriptor_candidate_span_overlap = 0usize;
    let mut descriptor_payload_end_to_next_local_delta_min: Option<usize> = None;
    let mut cd_compressed_size_points_into_descriptor = 0usize;
    let mut compressed_size_ends_before_descriptor = 0usize;
    let mut compressed_size_ends_inside_descriptor = 0usize;
    let mut compressed_size_ends_after_descriptor = 0usize;
    let mut compressed_size_ends_after_next_local = 0usize;
    let mut compressed_size_ends_before_next_local_gap = 0usize;
    let mut descriptor_span_between_payload_and_next_local = 0usize;
    let mut cd_entry_span_conflict = 0usize;
    let mut wrong_local_header_target = 0usize;
    let mut local_header_offset_points_to_other_entry = 0usize;
    let mut local_header_offset_points_to_descriptor_or_payload = 0usize;
    let mut local_header_offset_points_inside_payload = 0usize;
    let mut local_header_offset_points_inside_descriptor = 0usize;
    let mut local_header_offset_points_outside_archive = 0usize;
    let mut local_header_offset_bad_signature = 0usize;
    let mut descriptor_span_present = 0usize;
    let mut descriptor_span_missing = 0usize;
    let mut descriptor_between_payload_and_next_local = 0usize;
    let mut descriptor_flag_set_but_span_missing = 0usize;
    let mut descriptor_span_present_without_flag = 0usize;
    let mut descriptor_span_conflicts_with_cd_size = 0usize;
    let mut cd_size_points_to_descriptor_start = 0usize;
    let mut cd_size_points_inside_descriptor = 0usize;
    let mut cd_offset_size_joint_conflict = 0usize;
    let mut cd_offset_valid_but_size_conflict = 0usize;
    let mut cd_size_valid_but_offset_conflict = 0usize;
    let mut local_offset_valid_without_prefix = 0usize;
    let mut local_offset_valid_with_prefix = 0usize;
    let mut local_offset_only_valid_with_prefix = 0usize;
    let mut local_offset_invalid_after_prefix_adjustment = 0usize;
    let mut zip64_extra_present = 0usize;
    let mut zip64_extra_size_mismatch = 0usize;
    let mut zip64_extra_value_mismatch = 0usize;
    let mut parsed_payload_spans: Vec<(usize, usize)> = Vec::new();

    for (index, entry) in checked_entries.iter().enumerate() {
        let raw_local_offset = entry.local_header_offset as usize;
        let Some(archive_adjusted_offset) = archive_offset.checked_add(entry.local_header_offset as usize) else {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        };
        let prefix_adjusted_offset = raw_local_offset.saturating_add(prefix_len);
        let local_offset = if prefix_len > 0 {
            prefix_adjusted_offset
        } else {
            archive_adjusted_offset
        };
        let local_offset_outside_archive = local_offset + 4 > data.len();
        let local_offset_has_signature =
            !local_offset_outside_archive && data.get(local_offset..local_offset + 4) == Some(LFH_SIG);
        if local_offset_outside_archive {
            local_header_offset_points_outside_archive += 1;
        } else if !local_offset_has_signature {
            local_header_offset_bad_signature += 1;
            if offset_inside_local_or_data_span(local_offset, &known_descriptor_spans) {
                local_header_offset_points_inside_descriptor += 1;
            } else if offset_inside_local_or_data_span(local_offset, &known_payload_spans) {
                local_header_offset_points_inside_payload += 1;
            }
        }
        let raw_local = parse_local_header(&data, raw_local_offset);
        let archive_adjusted_local = parse_local_header(&data, archive_adjusted_offset);
        let prefix_adjusted_local = if prefix_len > 0 {
            parse_local_header(&data, prefix_adjusted_offset)
        } else {
            None
        };
        if raw_local.is_some() {
            local_offset_valid_without_prefix += 1;
        }
        if prefix_len > 0 {
            if prefix_adjusted_local.is_some() {
                local_offset_valid_with_prefix += 1;
                if raw_local.is_none() {
                    local_offset_only_valid_with_prefix += 1;
                }
            } else {
                local_offset_invalid_after_prefix_adjustment += 1;
            }
        }
        let matched_local = prefix_adjusted_local
            .clone()
            .or_else(|| archive_adjusted_local.clone())
            .or_else(|| raw_local.clone())
            .or_else(|| local_candidates.iter().find(|candidate| candidate.name == entry.name).cloned());
        if raw_local_offset != archive_adjusted_offset
            && archive_adjusted_local.is_none()
            && raw_local.is_some()
        {
            offset_suspicious += 1;
        }
        for candidate_offset in [raw_local_offset, archive_adjusted_offset, prefix_adjusted_offset] {
            if candidate_offset < data.len()
                && data.get(candidate_offset..candidate_offset.saturating_add(4)) != Some(LFH_SIG)
                && offset_inside_local_or_data_span(candidate_offset, &local_spans)
            {
                local_header_offset_points_to_descriptor_or_payload += 1;
            }
        }
        if let Some(local) = matched_local.as_ref() {
            if local.offset != local_offset || local.name != entry.name {
                wrong_local_header_target += 1;
            }
            if local.name != entry.name {
                local_header_offset_points_to_other_entry += 1;
            }
        }
        if local_offset + 4 > data.len() {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        }
        if data.get(local_offset..local_offset + 4) != Some(LFH_SIG) {
            local_bad_sig += 1;
            offset_suspicious += 1;
            if parsed_payload_spans
                .iter()
                .any(|(start, end)| local_offset >= *start && local_offset < end.saturating_add(32))
                || offset_inside_local_or_data_span(local_offset, &local_spans)
            {
                local_header_offset_points_to_descriptor_or_payload += 1;
            }
        }
        let Some(ref local) = matched_local else {
            local_missing += 1;
            continue;
        };
        if local.name != entry.name {
            name_mismatch += 1;
        }
        if local.flags != entry.flags {
            flags_mismatch += 1;
        }
        if local.method != entry.method {
            method_mismatch += 1;
        }
        if local.extra_len != entry.extra_len {
            local_extra_len_mismatch += 1;
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                crc_mismatch += 1;
            }
            if entry.compressed_size != u32::MAX && local.compressed_size != entry.compressed_size {
                compressed_mismatch += 1;
            }
            if entry.uncompressed_size != u32::MAX && local.uncompressed_size != entry.uncompressed_size {
                uncompressed_mismatch += 1;
            }
        }

        let local_zip64 = parse_zip64_extra_tolerant(&local.extra, local.extra_offset);
        let central_zip64 = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset);
        if central_zip64.is_some() || local_zip64.is_some() {
            zip64_extra_present += 1;
        }
        if let Some(central) = central_zip64.as_ref() {
            if central.stored_size != expected_zip64_central_size(entry)
                || (entry.disk_number_start == u16::MAX
                    && (central.disk_start.is_none() || central.disk_start_offset.is_none()))
            {
                zip64_extra_size_mismatch += 1;
            }
            if let Some(local_zip64) = local_zip64.as_ref() {
                let expected = expected_zip64_values(entry, &local, local_zip64)
                    .unwrap_or_else(|| local_zip64.values.clone());
                if central.values.get(..expected.len()) != Some(expected.as_slice()) {
                    zip64_extra_value_mismatch += 1;
                }
            }
        }

        let Some(payload_end) = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .and_then(|value| value.checked_add(entry.compressed_size as usize))
        else {
            continue;
        };
        let payload_start = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .unwrap_or(local.offset);
        parsed_payload_spans.push((payload_start, payload_end));
        let next_boundary = checked_entries
            .get(index + 1)
            .map(|next| next.local_header_offset as usize + prefix_len)
            .or_else(|| checked_entries.get(index + 1).map(|next| next.local_header_offset as usize))
            .unwrap_or(physical_cd_offset)
            .min(data.len());
        let mut entry_descriptor_span: Option<(usize, usize)> = None;
        let mut entry_size_conflict = false;
        if payload_end > next_boundary {
            compressed_size_ends_after_next_local += 1;
            cd_entry_span_conflict += 1;
            entry_size_conflict = true;
        }
        if payload_end < next_boundary {
            if next_boundary.saturating_sub(payload_end) > 32 {
                compressed_size_ends_before_next_local_gap += 1;
            }
            if let Some(descriptor_offset) = find_signature_between(&data, payload_end, next_boundary, DD_SIG) {
                descriptor_span_between_payload_and_next_local += 1;
                descriptor_between_payload_and_next_local += 1;
                let descriptor_end = descriptor_at_impl(
                    &data,
                    descriptor_offset,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or_else(|| descriptor_offset.saturating_add(16).min(next_boundary));
                entry_descriptor_span = Some((descriptor_offset, descriptor_end));
                if payload_end == descriptor_offset {
                    cd_size_points_to_descriptor_start += 1;
                } else if payload_end < descriptor_offset {
                    compressed_size_ends_before_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                } else if payload_end < descriptor_end {
                    compressed_size_ends_inside_descriptor += 1;
                    cd_size_points_inside_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                } else if payload_end > descriptor_end && payload_end <= next_boundary {
                    compressed_size_ends_after_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                }
                let delta = descriptor_offset.saturating_sub(payload_end);
                descriptor_payload_end_to_next_local_delta_min =
                    Some(descriptor_payload_end_to_next_local_delta_min.map_or(delta, |current| current.min(delta)));
            }
        }
        if entry.compressed_size != u32::MAX && payload_end <= data.len() {
            descriptor_checked += 1;
            let has_descriptor = descriptor_at(
                &data,
                payload_end,
                entry.crc32,
                entry.compressed_size as u64,
                entry.uncompressed_size as u64,
            );
            if has_descriptor {
                descriptor_present += 1;
                descriptor_span_present += 1;
                let descriptor_end = descriptor_at_impl(
                    &data,
                    payload_end,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or(payload_end);
                entry_descriptor_span = Some((payload_end, descriptor_end));
            } else if (entry.flags | local.flags) & 0x08 != 0 {
                descriptor_missing += 1;
                descriptor_span_missing += 1;
            }
            if (entry.flags & 0x08) != (local.flags & 0x08) {
                descriptor_flag_mismatch += 1;
            }
            if ((entry.flags | local.flags) & 0x08) != 0 && !has_descriptor {
                descriptor_flag_set_but_span_missing += 1;
            }
            if has_descriptor && ((entry.flags | local.flags) & 0x08) == 0 {
                descriptor_span_present_without_flag += 1;
            }
            if let Some(next_entry) = checked_entries.get(index + 1) {
                if let Some(next_local_offset) = (next_entry.local_header_offset as usize).checked_add(prefix_len) {
                    if next_local_offset > payload_end {
                        let delta = next_local_offset - payload_end;
                        descriptor_payload_end_to_next_local_delta_min =
                            Some(descriptor_payload_end_to_next_local_delta_min.map_or(delta, |current| current.min(delta)));
                        if delta <= 32 {
                            descriptor_candidate_span_overlap += 1;
                            if has_descriptor || delta >= 12 {
                                cd_compressed_size_points_into_descriptor += 1;
                            }
                        }
                    } else if next_local_offset > payload_start {
                        local_header_offset_points_to_descriptor_or_payload += 1;
                    }
                }
            }
        }
        let entry_offset_conflict =
            local_offset_outside_archive || !local_offset_has_signature || matched_local.as_ref().is_some_and(|candidate| {
                candidate.offset != local_offset || candidate.name != entry.name
            });
        if let Some((descriptor_start, descriptor_end)) = entry_descriptor_span {
            if payload_end != descriptor_start {
                descriptor_span_conflicts_with_cd_size += 1;
                entry_size_conflict = true;
            }
            if local_offset > descriptor_start && local_offset < descriptor_end {
                local_header_offset_points_inside_descriptor += 1;
            }
        }
        if entry_offset_conflict && entry_size_conflict {
            cd_offset_size_joint_conflict += 1;
        } else if !entry_offset_conflict && entry_size_conflict {
            cd_offset_valid_but_size_conflict += 1;
        } else if entry_offset_conflict && !entry_size_conflict {
            cd_size_valid_but_offset_conflict += 1;
        }
    }

    result.set_item("local_header_missing_count", local_missing)?;
    result.set_item("local_header_bad_signature_count", local_bad_sig)?;
    result.set_item("central_local_name_mismatch_count", name_mismatch)?;
    result.set_item("central_local_flags_mismatch_count", flags_mismatch)?;
    result.set_item("central_local_method_mismatch_count", method_mismatch)?;
    result.set_item("central_local_crc_mismatch_count", crc_mismatch)?;
    result.set_item("central_local_compressed_size_mismatch_count", compressed_mismatch)?;
    result.set_item("central_local_uncompressed_size_mismatch_count", uncompressed_mismatch)?;
    result.set_item("local_extra_len_mismatch_count", local_extra_len_mismatch)?;
    result.set_item("central_local_offset_suspicious_count", offset_suspicious)?;

    let descriptor = PyDict::new(py);
    descriptor.set_item("descriptor_checked_count", descriptor_checked)?;
    descriptor.set_item("descriptor_present_count", descriptor_present)?;
    descriptor.set_item("descriptor_missing_count", descriptor_missing)?;
    descriptor.set_item("descriptor_flag_mismatch_count", descriptor_flag_mismatch)?;
    descriptor.set_item("descriptor_candidate_span_overlap_count", descriptor_candidate_span_overlap)?;
    descriptor.set_item(
        "descriptor_payload_end_to_next_local_delta_min",
        descriptor_payload_end_to_next_local_delta_min.unwrap_or(0),
    )?;
    descriptor.set_item("cd_compressed_size_points_into_descriptor_count", cd_compressed_size_points_into_descriptor)?;
    descriptor.set_item("compressed_size_ends_before_descriptor_count", compressed_size_ends_before_descriptor)?;
    descriptor.set_item("compressed_size_ends_inside_descriptor_count", compressed_size_ends_inside_descriptor)?;
    descriptor.set_item("compressed_size_ends_after_descriptor_count", compressed_size_ends_after_descriptor)?;
    descriptor.set_item("compressed_size_ends_after_next_local_count", compressed_size_ends_after_next_local)?;
    descriptor.set_item(
        "compressed_size_ends_before_next_local_gap_count",
        compressed_size_ends_before_next_local_gap,
    )?;
    descriptor.set_item("descriptor_span_between_payload_and_next_local_count", descriptor_span_between_payload_and_next_local)?;
    descriptor.set_item("cd_entry_span_conflict_count", cd_entry_span_conflict)?;
    descriptor.set_item("wrong_local_header_target_count", wrong_local_header_target)?;
    descriptor.set_item("local_header_offset_points_to_other_entry_count", local_header_offset_points_to_other_entry)?;
    descriptor.set_item(
        "local_header_offset_points_to_descriptor_or_payload_count",
        local_header_offset_points_to_descriptor_or_payload,
    )?;
    descriptor.set_item("local_header_offset_points_inside_payload_count", local_header_offset_points_inside_payload)?;
    descriptor.set_item(
        "local_header_offset_points_inside_descriptor_count",
        local_header_offset_points_inside_descriptor,
    )?;
    descriptor.set_item("local_header_offset_points_outside_archive_count", local_header_offset_points_outside_archive)?;
    descriptor.set_item("local_header_offset_bad_signature_count", local_header_offset_bad_signature)?;
    descriptor.set_item(
        "local_header_offset_target_conflict_ratio",
        wrong_local_header_target as f64 / checked_entries.len().max(1) as f64,
    )?;
    descriptor.set_item("descriptor_span_present_count", descriptor_span_present)?;
    descriptor.set_item("descriptor_span_missing_count", descriptor_span_missing)?;
    descriptor.set_item(
        "descriptor_between_payload_and_next_local_count",
        descriptor_between_payload_and_next_local,
    )?;
    descriptor.set_item(
        "descriptor_flag_set_but_span_missing_count",
        descriptor_flag_set_but_span_missing,
    )?;
    descriptor.set_item(
        "descriptor_span_present_without_flag_count",
        descriptor_span_present_without_flag,
    )?;
    descriptor.set_item(
        "descriptor_span_conflicts_with_cd_size_count",
        descriptor_span_conflicts_with_cd_size,
    )?;
    descriptor.set_item("cd_size_points_to_descriptor_start_count", cd_size_points_to_descriptor_start)?;
    descriptor.set_item("cd_size_points_inside_descriptor_count", cd_size_points_inside_descriptor)?;
    descriptor.set_item("cd_offset_size_joint_conflict_count", cd_offset_size_joint_conflict)?;
    descriptor.set_item("cd_offset_valid_but_size_conflict_count", cd_offset_valid_but_size_conflict)?;
    descriptor.set_item("cd_size_valid_but_offset_conflict_count", cd_size_valid_but_offset_conflict)?;
    result.set_item("descriptor", descriptor)?;

    let prefix = PyDict::new(py);
    prefix.set_item("first_local_header_found", !local_candidates.is_empty())?;
    prefix.set_item("first_local_header_offset", first_local_offset)?;
    prefix.set_item("prefix_bytes_before_first_local", prefix_len)?;
    prefix.set_item("prefix_has_non_zip_bytes", prefix_len > 0 && data.get(0..4) != Some(LFH_SIG))?;
    prefix.set_item(
        "prefix_has_executable_signature",
        prefix_len >= 2 && (data.get(0..2) == Some(b"MZ") || data.get(0..2) == Some(b"#!")),
    )?;
    prefix.set_item("local_offset_valid_without_prefix_count", local_offset_valid_without_prefix)?;
    prefix.set_item("local_offset_valid_with_prefix_count", local_offset_valid_with_prefix)?;
    prefix.set_item("local_offset_only_valid_with_prefix_count", local_offset_only_valid_with_prefix)?;
    prefix.set_item(
        "local_offset_invalid_after_prefix_adjustment_count",
        local_offset_invalid_after_prefix_adjustment,
    )?;
    prefix.set_item(
        "local_offset_prefix_adjustment_success_ratio",
        local_offset_valid_with_prefix as f64 / checked_entries.len().max(1) as f64,
    )?;
    result.set_item("prefix", prefix)?;

    let zip64 = PyDict::new(py);
    let zip64_eocd = find_zip64_eocd(&data, eocd.offset);
    let zip64_locator = find_zip64_locator(&data, eocd.offset);
    zip64.set_item("zip64_eocd_present", zip64_eocd.is_some())?;
    zip64.set_item("zip64_locator_present", zip64_locator.is_some())?;
    zip64.set_item(
        "zip64_locator_target_valid",
        zip64_locator.is_some_and(|locator| {
            zip64_eocd.is_some_and(|tail| locator.zip64_eocd_offset == tail.offset as u64 && locator.total_disks >= 1)
        }),
    )?;
    zip64.set_item(
        "zip64_eocd_field_mismatch_count",
        zip_inspect_zip64_eocd_mismatch_count(zip64_eocd, physical_cd_offset, cd_end, all_entries.len()),
    )?;
    zip64.set_item("zip64_extra_present_count", zip64_extra_present)?;
    zip64.set_item("zip64_extra_size_mismatch_count", zip64_extra_size_mismatch)?;
    zip64.set_item("zip64_extra_value_mismatch_count", zip64_extra_value_mismatch)?;
    result.set_item("zip64_consistency", zip64)?;
    Ok(result.unbind())
}

pub(crate) fn inspect_zip_structure_graph(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("schema_version", 1)?;
    result.set_item("format", "zip")?;
    result.set_item("error", "")?;
    result.set_item("truncated", false)?;
    let nodes = PyList::empty(py);
    let edges = PyList::empty(py);
    let violations = PyList::empty(py);
    let relation_violations = PyList::empty(py);
    let explanations = PyList::empty(py);
    let summary = PyDict::new(py);
    result.set_item("nodes", &nodes)?;
    result.set_item("edges", &edges)?;
    result.set_item("violations", &violations)?;
    result.set_item("relation_violations", &relation_violations)?;
    result.set_item("explanations", &explanations)?;
    result.set_item("summary", &summary)?;

    let Ok(data) = crate::io::reader::ManagedReader::open(path)
        .and_then(|reader| reader.read_all()) else {
        result.set_item("error", "os_error")?;
        summary.set_item("archive_readable", false)?;
        return Ok(result.unbind());
    };
    let file_size = data.len();
    summary.set_item("archive_readable", true)?;
    summary.set_item("file_size", file_size)?;
    zip_graph_node(py, &nodes, "archive:0", "archive", 0, file_size, "parsed")?;
    zip_graph_node(py, &nodes, "physical_span:archive", "physical_span", 0, file_size, "observed")?;
    zip_graph_edge(py, &edges, "archive:0", "physical_span:archive", "owns_span", "", true, 1.0)?;

    let Some(eocd) = find_eocd_record(&data, true) else {
        result.set_item("error", "eocd_not_found")?;
        summary.set_item("eocd_present", false)?;
        zip_graph_violation(py, &violations, "missing_node", "archive:0", "", "eocd", "", "", 0, "high")?;
        return Ok(result.unbind());
    };
    summary.set_item("eocd_present", true)?;
    let eocd_id = "eocd:0";
    zip_graph_node(py, &nodes, eocd_id, "eocd", eocd.offset, eocd.end, "parsed")?;
    zip_graph_edge(py, &edges, "archive:0", eocd_id, "contains", "", true, 1.0)?;
    let trailing = file_size.saturating_sub(eocd.end);
    summary.set_item("trailing_bytes_after_eocd", trailing)?;
    if trailing > 0 {
        zip_graph_node(py, &nodes, "physical_span:tail", "physical_span", eocd.end, file_size, "observed")?;
        zip_graph_violation(
            py,
            &violations,
            "unexpected_tail",
            eocd_id,
            "physical_span:tail",
            "tail.trailing_bytes",
            "0",
            &trailing.to_string(),
            trailing as i64,
            "medium",
        )?;
        zip_graph_explanation(py, &explanations, "tail_truncation", false, "tail.trailing_bytes", 0, "tail bytes exist after EOCD")?;
    }

    let resolved = resolve_central_directory(&data, &eocd);
    let physical_cd_offset = resolved.physical_offset;
    let cd_end = resolved.end;
    let archive_offset = resolved.archive_offset;
    let cd_id = "central_directory:0";
    summary.set_item("declared_central_directory_offset", resolved.declared_offset)?;
    summary.set_item("declared_central_directory_size", resolved.declared_size)?;
    summary.set_item("physical_central_directory_offset", physical_cd_offset)?;
    summary.set_item(
        "central_directory_offset_delta",
        physical_cd_offset as i64 - resolved.declared_offset as i64,
    )?;
    summary.set_item(
        "central_directory_size_delta",
        cd_end.saturating_sub(physical_cd_offset) as i64 - resolved.declared_size as i64,
    )?;
    zip_graph_node(py, &nodes, cd_id, "central_directory", physical_cd_offset, cd_end, "candidate")?;
    zip_graph_edge(py, &edges, eocd_id, cd_id, "points_to", "central_directory", physical_cd_offset + 4 <= file_size && data.get(physical_cd_offset..physical_cd_offset + 4) == Some(CD_SIG), 1.0)?;
    if physical_cd_offset + 4 > file_size || data.get(physical_cd_offset..physical_cd_offset + 4) != Some(CD_SIG) {
        result.set_item("error", "bad_central_directory_signature")?;
        zip_graph_violation(
            py,
            &violations,
            "bad_signature",
            eocd_id,
            cd_id,
            "eocd.cd_offset",
            "central_directory_signature",
            "missing",
            physical_cd_offset as i64 - resolved.declared_offset as i64,
            "high",
        )?;
    }
    if archive_offset > 0 {
        zip_graph_node(py, &nodes, "physical_span:sfx_prefix", "physical_span", 0, archive_offset, "observed")?;
        zip_graph_explanation(
            py,
            &explanations,
            "sfx_prefix_adjustment",
            physical_cd_offset == archive_offset.saturating_add(resolved.declared_offset),
            "eocd.cd_offset",
            archive_offset as i64,
            "archive offset explains central directory pointer",
        )?;
    }

    let all_entries = parse_central_directory_entries(&data, physical_cd_offset, cd_end);
    let checked_entries = all_entries.iter().take(max_entries).collect::<Vec<_>>();
    result.set_item("truncated", all_entries.len() > checked_entries.len())?;
    summary.set_item("cd_entry_count", all_entries.len())?;
    summary.set_item("cd_entries_checked", checked_entries.len())?;
    summary.set_item(
        "entry_count_delta",
        all_entries.len() as i64 - resolved.total_entries as i64,
    )?;
    let mut eocd_entry_count_mismatch = 0usize;
    if all_entries.len() as u64 != resolved.total_entries {
        eocd_entry_count_mismatch = 1;
        zip_graph_violation(
            py,
            &violations,
            "count_mismatch",
            eocd_id,
            cd_id,
            "eocd.entry_count",
            &resolved.total_entries.to_string(),
            &all_entries.len().to_string(),
            all_entries.len() as i64 - resolved.total_entries as i64,
            "medium",
        )?;
        let declared_entries = resolved.total_entries.to_string();
        let parsed_entries = all_entries.len().to_string();
        let disk_entries = resolved.disk_entries.to_string();
        zip_graph_relation_violation(
            py,
            &relation_violations,
            &violations,
            "eocd_entry_count_mismatch",
            "eocd.entry_count",
            "eocd.entry_count",
            "central_directory.entry_count",
            "counts_entries",
            0,
            resolved.total_entries,
            all_entries.len() as u64,
            "eocd.entry_count",
            0.95,
            "high",
            &[
                ("declared_total_entries", &declared_entries),
                ("declared_disk_entries", &disk_entries),
                ("parsed_central_directory_entries", &parsed_entries),
            ],
        )?;
    }

    let local_candidates = scan_zip_local_headers(&data, physical_cd_offset, max_entries.saturating_mul(4).max(32));
    let local_spans = local_record_spans(&local_candidates, physical_cd_offset);
    let (known_payload_spans, known_descriptor_spans) =
        local_payload_descriptor_spans(&data, &local_candidates, physical_cd_offset);
    summary.set_item("local_header_candidate_count", local_candidates.len())?;
    let first_local_offset = local_candidates.first().map(|local| local.offset).unwrap_or(0);
    let prefix_len = first_local_offset;
    summary.set_item("first_local_header_offset", first_local_offset)?;
    summary.set_item("sfx_prefix_len", prefix_len)?;
    let declared_cd_offset = prefix_len.saturating_add(resolved.declared_offset);
    let declared_cd_walk = if declared_cd_offset + 4 <= file_size
        && data.get(declared_cd_offset..declared_cd_offset + 4) == Some(CD_SIG)
    {
        Some(walk_central_directory_range(&data, declared_cd_offset, Some(resolved.end)))
    } else {
        None
    };
    let parsed_central_directory_size = declared_cd_walk
        .as_ref()
        .filter(|walk| walk.count > 0)
        .map(|walk| walk.end.saturating_sub(declared_cd_offset));
    summary.set_item("parsed_central_directory_size", parsed_central_directory_size.unwrap_or(0))?;
    let mut eocd_cd_size_mismatch = 0usize;
    if let Some(parsed_size) = parsed_central_directory_size {
        if parsed_size != resolved.declared_size {
            eocd_cd_size_mismatch = 1;
            let parsed_size_string = parsed_size.to_string();
            let declared_size_string = resolved.declared_size.to_string();
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "eocd_cd_size_mismatch",
                "eocd.cd_size",
                "eocd.cd_size",
                "central_directory.span",
                "owns_span",
                0,
                resolved.declared_size as u64,
                parsed_size as u64,
                "eocd.cd_size",
                0.95,
                "high",
                &[
                    ("declared_central_directory_size", &declared_size_string),
                    ("parsed_central_directory_size", &parsed_size_string),
                ],
            )?;
        }
    }
    for (index, local) in local_candidates.iter().take(max_entries).enumerate() {
        let local_id = format!("local_header:{index}");
        let end = local_data_start(local).unwrap_or(local.offset).min(file_size);
        zip_graph_node(py, &nodes, &local_id, "local_header_candidate", local.offset, end, "parsed")?;
        zip_graph_edge(py, &edges, "archive:0", &local_id, "contains", "", true, 0.8)?;
    }
    for (index, (start, end)) in known_payload_spans.iter().take(max_entries).enumerate() {
        zip_graph_node(py, &nodes, &format!("payload_span:{index}"), "payload_span", *start, *end, "candidate")?;
    }
    for (index, (start, end)) in known_descriptor_spans.iter().take(max_entries).enumerate() {
        zip_graph_node(py, &nodes, &format!("descriptor_candidate:{index}"), "descriptor_candidate", *start, *end, "candidate")?;
    }

    let mut name_mismatch = 0usize;
    let mut flags_mismatch = 0usize;
    let mut method_mismatch = 0usize;
    let mut crc_mismatch = 0usize;
    let mut compressed_mismatch = 0usize;
    let mut uncompressed_mismatch = 0usize;
    let mut local_offset_violations = 0usize;
    let mut span_conflicts = 0usize;
    let mut descriptor_conflicts = 0usize;
    let mut zip64_extra_present = 0usize;
    let mut zip64_extra_mismatch = 0usize;
    let mut central_local_flags_relation_mismatch = 0usize;
    let mut central_directory_flags_likely_bad = 0usize;
    let mut local_header_flags_likely_bad = 0usize;
    let mut flags_relation_ambiguous = 0usize;
    let mut bad_local_header_target_signature = 0usize;
    let mut local_header_offset_points_to_descriptor_or_payload = 0usize;
    let mut local_header_offset_points_outside_archive = 0usize;
    let mut descriptor_crc_cd_mismatch = 0usize;
    let mut descriptor_crc_payload_mismatch = 0usize;
    let mut descriptor_crc_likely_bad = 0usize;
    let mut descriptor_record_mismatch = 0usize;
    let mut descriptor_size_mismatch = 0usize;
    let mut central_directory_compressed_size_likely_bad = 0usize;
    let mut local_header_compressed_size_likely_bad = 0usize;
    let mut zip64_extra_length_mismatch = 0usize;
    let mut zip64_uncompressed_size_mismatch = 0usize;
    let mut split_volume_missing_range_evidence = 0usize;
    let mut local_header_signature_mismatch = 0usize;
    let mut payload_decode_failure = 0usize;
    let mut payload_crc_mismatch = 0usize;
    let mut local_header_crc_likely_bad = 0usize;
    let mut crc_direction_unresolved = 0usize;
    let mut extra_field_structure_mismatch = 0usize;

    for (index, entry) in checked_entries.iter().enumerate() {
        let cd_entry_id = format!("cd_entry:{index}");
        let cd_entry_end = entry.offset
            .saturating_add(46)
            .saturating_add(entry.name_len as usize)
            .saturating_add(entry.extra_len as usize);
        zip_graph_node(py, &nodes, &cd_entry_id, "cd_entry", entry.offset, cd_entry_end, "parsed")?;
        zip_graph_edge(py, &edges, cd_id, &cd_entry_id, "owns_span", "", true, 1.0)?;
        let raw_local_offset = entry.local_header_offset as usize;
        let archive_adjusted_offset = archive_offset.saturating_add(raw_local_offset);
        let prefix_adjusted_offset = raw_local_offset.saturating_add(prefix_len);
        let declared_local_offset = if prefix_len > 0 { prefix_adjusted_offset } else { archive_adjusted_offset };
        let raw_local = parse_local_header(&data, raw_local_offset);
        let archive_adjusted_local = parse_local_header(&data, archive_adjusted_offset);
        let prefix_adjusted_local = if prefix_len > 0 { parse_local_header(&data, prefix_adjusted_offset) } else { None };
        let raw_local_tolerant = parse_local_header_ignoring_signature(&data, raw_local_offset, entry);
        let archive_adjusted_local_tolerant =
            parse_local_header_ignoring_signature(&data, archive_adjusted_offset, entry);
        let prefix_adjusted_local_tolerant = if prefix_len > 0 {
            parse_local_header_ignoring_signature(&data, prefix_adjusted_offset, entry)
        } else {
            None
        };
        let declared_local_ok = if prefix_len > 0 {
            prefix_adjusted_local.is_some()
        } else {
            archive_adjusted_local.is_some()
        };
        let declared_local_signature_bad = !declared_local_ok
            && if prefix_len > 0 {
                prefix_adjusted_local_tolerant.is_some()
            } else {
                archive_adjusted_local_tolerant.is_some()
            };
        let matched_local = prefix_adjusted_local
            .clone()
            .or_else(|| archive_adjusted_local.clone())
            .or_else(|| raw_local.clone())
            .or_else(|| prefix_adjusted_local_tolerant.clone())
            .or_else(|| archive_adjusted_local_tolerant.clone())
            .or_else(|| raw_local_tolerant.clone())
            .or_else(|| local_candidates.iter().find(|candidate| candidate.name == entry.name).cloned());
        let local_target_id = format!("local_header_target:{index}");
        let local_ok = matched_local.as_ref().is_some_and(|local| local.name == entry.name);
        zip_graph_edge(py, &edges, &cd_entry_id, &local_target_id, "points_to", "local_header_offset", local_ok, if local_ok { 1.0 } else { 0.0 })?;
        if declared_local_signature_bad {
            local_header_signature_mismatch += 1;
            let target_signature = signature_hex_at(&data, declared_local_offset);
            let declared_local_offset_string = declared_local_offset.to_string();
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "local_header_signature_mismatch",
                "local_header.signature",
                "central_directory.local_header_offset",
                "local_header.signature",
                "points_to",
                index,
                entry.local_header_offset as u64,
                declared_local_offset as u64,
                "local_header.signature",
                0.95,
                "high",
                &[
                    ("target_kind", "bad_signature"),
                    ("target_signature", &target_signature),
                    ("expected_signature", "504b0304"),
                    ("offset_is_plausible", "true"),
                    ("declared_local_offset", &declared_local_offset_string),
                ],
            )?;
        } else if !declared_local_ok {
            local_offset_violations += 1;
            bad_local_header_target_signature += 1;
            let observed = if declared_local_offset >= file_size {
                local_header_offset_points_outside_archive += 1;
                "outside_archive"
            } else if offset_inside_local_or_data_span(declared_local_offset, &known_descriptor_spans) {
                local_header_offset_points_to_descriptor_or_payload += 1;
                "inside_descriptor"
            } else if offset_inside_local_or_data_span(declared_local_offset, &known_payload_spans) || offset_inside_local_or_data_span(declared_local_offset, &local_spans) {
                local_header_offset_points_to_descriptor_or_payload += 1;
                "inside_payload_or_entry"
            } else {
                "bad_signature"
            };
            zip_graph_violation(
                py,
                &violations,
                "bad_reference",
                &cd_entry_id,
                &local_target_id,
                "central_directory.local_header_offset",
                "local_header",
                observed,
                declared_local_offset as i64 - archive_adjusted_offset as i64,
                "high",
            )?;
            let target_signature = signature_hex_at(&data, declared_local_offset);
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "local_header_offset_target_mismatch",
                "central_directory.local_header_offset",
                "central_directory.local_header_offset",
                "local_header.signature",
                "points_to",
                index,
                entry.local_header_offset as u64,
                declared_local_offset as u64,
                "central_directory.local_header_offset",
                0.95,
                "high",
                &[("target_kind", observed), ("target_signature", &target_signature), ("expected_signature", "504b0304")],
            )?;
        }
        let Some(local) = matched_local else {
            continue;
        };
        zip_graph_node(py, &nodes, &local_target_id, "local_header_candidate", local.offset, local_data_start(&local).unwrap_or(local.offset), "matched")?;
        if local.name != entry.name {
            name_mismatch += 1;
            zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "central_directory.filename", "cd_name", "local_name", 0, "medium")?;
        }
        let mut flags_likely_bad_side_for_entry = "none";
        if local.flags != entry.flags {
            flags_mismatch += 1;
            let descriptor_present = descriptor_record_for_entry(&data, entry, &local).is_some();
            let cd_bit3 = entry.flags & 0x08 != 0;
            let local_bit3 = local.flags & 0x08 != 0;
            let (likely_bad_side, confidence, severity) = if descriptor_present == local_bit3 && descriptor_present != cd_bit3 {
                ("central_directory.flags", 0.9, "high")
            } else if descriptor_present == cd_bit3 && descriptor_present != local_bit3 {
                ("local_header.flags", 0.9, "high")
            } else {
                ("ambiguous", 0.45, "medium")
            };
            central_local_flags_relation_mismatch += 1;
            match likely_bad_side {
                "central_directory.flags" => central_directory_flags_likely_bad += 1,
                "local_header.flags" => local_header_flags_likely_bad += 1,
                _ => flags_relation_ambiguous += 1,
            }
            flags_likely_bad_side_for_entry = likely_bad_side;
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "field_relation_mismatch",
                if likely_bad_side == "ambiguous" { "central_directory.flags" } else { likely_bad_side },
                "central_directory.flags",
                "local_header.flags",
                "matches_field",
                index,
                entry.flags as u64,
                local.flags as u64,
                likely_bad_side,
                confidence,
                severity,
                &[("source_bit3", if cd_bit3 { "true" } else { "false" }), ("target_bit3", if local_bit3 { "true" } else { "false" }), ("descriptor_present", if descriptor_present { "true" } else { "false" })],
            )?;
        }
        if local.method != entry.method {
            method_mismatch += 1;
            zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.method", &entry.method.to_string(), &local.method.to_string(), local.method as i64 - entry.method as i64, "medium")?;
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                crc_mismatch += 1;
                let payload_crc = payload_crc_for_entry(&data, entry, &local);
                let payload_matches_cd = payload_crc.is_some_and(|value| value == entry.crc32);
                let payload_matches_local = payload_crc.is_some_and(|value| value == local.crc32);
                let (likely_bad_side, confidence) = if payload_matches_local && !payload_matches_cd {
                    ("central_directory.crc", 0.95)
                } else if payload_matches_cd && !payload_matches_local {
                    ("local_header.crc", 0.95)
                } else if payload_crc.is_some() && !payload_matches_cd && !payload_matches_local {
                    ("payload.compressed_data", 0.8)
                } else {
                    ("crc_direction_unresolved", 0.35)
                };
                match likely_bad_side {
                    "local_header.crc" => local_header_crc_likely_bad += 1,
                    "payload.compressed_data" => payload_crc_mismatch += 1,
                    "crc_direction_unresolved" => crc_direction_unresolved += 1,
                    _ => {}
                }
                let central_directory_crc_string = entry.crc32.to_string();
                let local_header_crc_string = local.crc32.to_string();
                let payload_crc_string = payload_crc.map(|value| value.to_string()).unwrap_or_default();
                zip_graph_relation_violation(
                    py,
                    &relation_violations,
                    &violations,
                    "central_local_crc_mismatch",
                    if likely_bad_side == "crc_direction_unresolved" { "central_directory.crc" } else { likely_bad_side },
                    "central_directory.crc",
                    "local_header.crc",
                    "matches_field",
                    index,
                    entry.crc32 as u64,
                    local.crc32 as u64,
                    likely_bad_side,
                    confidence,
                    "high",
                    &[
                        ("central_directory_crc", &central_directory_crc_string),
                        ("local_header_crc", &local_header_crc_string),
                        ("payload_crc", &payload_crc_string),
                        ("payload_matches_cd", if payload_matches_cd { "true" } else { "false" }),
                        ("payload_matches_local", if payload_matches_local { "true" } else { "false" }),
                    ],
                )?;
            }
            if entry.compressed_size != u32::MAX && local.compressed_size != entry.compressed_size {
                compressed_mismatch += 1;
            }
            if entry.uncompressed_size != u32::MAX && local.uncompressed_size != entry.uncompressed_size {
                uncompressed_mismatch += 1;
                zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.uncompressed_size", &entry.uncompressed_size.to_string(), &local.uncompressed_size.to_string(), local.uncompressed_size as i64 - entry.uncompressed_size as i64, "medium")?;
            }
        }
        let data_start = local_data_start(&local).unwrap_or(local.offset);
        let next_boundary = checked_entries
            .get(index + 1)
            .map(|next| next.local_header_offset as usize + prefix_len)
            .or_else(|| checked_entries.get(index + 1).map(|next| next.local_header_offset as usize))
            .unwrap_or(physical_cd_offset)
            .min(file_size);
        let payload_probe = payload_probe_for_entry(&data, entry, &local, next_boundary);
        let payload_end = data_start.saturating_add(entry.compressed_size as usize);
        zip_graph_node(py, &nodes, &format!("payload_span:cd:{index}"), "payload_span", data_start, payload_end.min(file_size), "declared")?;
        zip_graph_edge(py, &edges, &local_target_id, &format!("payload_span:cd:{index}"), "owns_span", "payload", payload_end <= file_size, 0.9)?;
        if entry.method == 8 && payload_probe.is_none() && data_start < next_boundary {
            payload_decode_failure += 1;
            let data_start_string = data_start.to_string();
            let next_boundary_string = next_boundary.to_string();
            let expected_size_string = entry.uncompressed_size.to_string();
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "payload_decode_failure",
                "payload.compressed_data",
                "payload.compressed_data",
                "payload.span",
                "decodes_to",
                index,
                data_start as u64,
                next_boundary as u64,
                "payload.compressed_data",
                0.9,
                "high",
                &[
                    ("method", "deflate"),
                    ("payload_start", &data_start_string),
                    ("payload_next_boundary", &next_boundary_string),
                    ("expected_uncompressed_size", &expected_size_string),
                    ("inflate_error_kind", "deflate_probe_failed"),
                ],
            )?;
        }
        if entry.flags & 0x08 == 0
            && entry.compressed_size != u32::MAX
            && local.compressed_size != entry.compressed_size
        {
            let physical_payload_size = next_boundary.saturating_sub(data_start) as u64;
            let payload_size = match entry.method {
                0 => Some(physical_payload_size),
                8 => payload_probe.map(|probe| probe.consumed as u64),
                _ => None,
            };
            let cd_size = entry.compressed_size as u64;
            let local_size = local.compressed_size as u64;
            let propagated_from_flags = flags_likely_bad_side_for_entry == "central_directory.flags"
                || flags_likely_bad_side_for_entry == "local_header.flags";
            let (likely_bad_side, confidence) = if propagated_from_flags {
                (flags_likely_bad_side_for_entry, 0.65)
            } else if payload_size.is_some_and(|value| value == local_size && value != cd_size) {
                ("central_directory.compressed_size", 0.95)
            } else if payload_size.is_some_and(|value| value == cd_size && value != local_size) {
                ("local_header.compressed_size", 0.95)
            } else if payload_size.is_some_and(|value| value != cd_size && value != local_size) {
                ("payload.span", 0.8)
            } else {
                ("ambiguous", 0.45)
            };
            if likely_bad_side == "central_directory.compressed_size" {
                central_directory_compressed_size_likely_bad += 1;
            } else if likely_bad_side == "local_header.compressed_size" {
                local_header_compressed_size_likely_bad += 1;
            }
            let cd_size_string = cd_size.to_string();
            let local_size_string = local_size.to_string();
            let payload_size_string = payload_size.map(|value| value.to_string()).unwrap_or_default();
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "central_local_compressed_size_mismatch",
                if likely_bad_side == "ambiguous" { "central_directory.compressed_size" } else { likely_bad_side },
                "central_directory.compressed_size",
                "local_header.compressed_size",
                "matches_field",
                index,
                cd_size,
                local_size,
                likely_bad_side,
                confidence,
                "high",
                &[
                    ("central_directory_compressed_size", &cd_size_string),
                    ("local_header_compressed_size", &local_size_string),
                    ("payload_consumed_size", &payload_size_string),
                    ("propagated_symptom", if propagated_from_flags { "true" } else { "false" }),
                    ("propagated_from", if propagated_from_flags { flags_likely_bad_side_for_entry } else { "" }),
                ],
            )?;
        }
        if entry.flags & 0x08 != 0 {
            let expected_descriptor_offset = payload_probe.map(|probe| probe.end).unwrap_or(payload_end);
            let descriptor_at_expected = descriptor_record_at(&data, expected_descriptor_offset, entry, &local);
            let descriptor_has_signature = descriptor_at_expected.is_some_and(|descriptor| descriptor.has_signature);
            if descriptor_at_expected.is_none() {
                let propagated_from_flags = flags_likely_bad_side_for_entry == "central_directory.flags"
                    || flags_likely_bad_side_for_entry == "local_header.flags";
                if !propagated_from_flags {
                    descriptor_record_mismatch += 1;
                }
                let observed_signature = signature_hex_at(&data, expected_descriptor_offset);
                let expected_offset_string = expected_descriptor_offset.to_string();
                zip_graph_relation_violation(
                    py,
                    &relation_violations,
                    &violations,
                    "data_descriptor_record_mismatch",
                    if propagated_from_flags { flags_likely_bad_side_for_entry } else { "data_descriptor.record" },
                    "data_descriptor.record",
                    "payload.span",
                    "describes_payload",
                    index,
                    expected_descriptor_offset as u64,
                    next_boundary as u64,
                    if propagated_from_flags { flags_likely_bad_side_for_entry } else { "data_descriptor.record" },
                    if propagated_from_flags { 0.65 } else { 0.95 },
                    if propagated_from_flags { "medium" } else { "high" },
                    &[
                        ("expected_offset", &expected_offset_string),
                        ("observed_signature", &observed_signature),
                        ("descriptor_expected_by_bit3", "true"),
                        ("descriptor_has_signature", "false"),
                        ("propagated_symptom", if propagated_from_flags { "true" } else { "false" }),
                        ("propagated_from", if propagated_from_flags { flags_likely_bad_side_for_entry } else { "" }),
                    ],
                )?;
            } else if let Some(descriptor) = descriptor_at_expected {
                if descriptor.compressed_size != entry.compressed_size as u64
                    || descriptor.uncompressed_size != entry.uncompressed_size as u64
                    || payload_probe.is_some_and(|probe| {
                        descriptor.compressed_size != probe.consumed as u64
                            || descriptor.uncompressed_size != probe.uncompressed_size
                    })
                {
                    descriptor_size_mismatch += 1;
                    let probe_consumed = payload_probe.map(|probe| probe.consumed).unwrap_or(0).to_string();
                    let probe_uncompressed = payload_probe.map(|probe| probe.uncompressed_size).unwrap_or(0).to_string();
                    let descriptor_compressed = descriptor.compressed_size.to_string();
                    let descriptor_uncompressed = descriptor.uncompressed_size.to_string();
                    let cd_compressed = entry.compressed_size.to_string();
                    let cd_uncompressed = entry.uncompressed_size.to_string();
                    let (likely_bad_side, confidence) = if payload_probe.is_some_and(|probe| {
                        descriptor.compressed_size != probe.consumed as u64
                            || descriptor.uncompressed_size != probe.uncompressed_size
                    }) {
                        ("data_descriptor.size", 0.95)
                    } else if descriptor.compressed_size == local.compressed_size as u64
                        && descriptor.uncompressed_size == local.uncompressed_size as u64
                    {
                        ("central_directory.compressed_size", 0.8)
                    } else {
                        ("ambiguous", 0.45)
                    };
                    zip_graph_relation_violation(
                        py,
                        &relation_violations,
                        &violations,
                        "data_descriptor_size_mismatch",
                        if likely_bad_side == "ambiguous" { "data_descriptor.size" } else { likely_bad_side },
                        "data_descriptor.size",
                        "central_directory.compressed_size",
                        "matches_field",
                        index,
                        descriptor.compressed_size,
                        entry.compressed_size as u64,
                        likely_bad_side,
                        confidence,
                        "high",
                        &[
                            ("descriptor_compressed_size", &descriptor_compressed),
                            ("descriptor_uncompressed_size", &descriptor_uncompressed),
                            ("central_directory_compressed_size", &cd_compressed),
                            ("central_directory_uncompressed_size", &cd_uncompressed),
                            ("payload_consumed_size", &probe_consumed),
                            ("payload_uncompressed_size", &probe_uncompressed),
                            ("descriptor_has_signature", if descriptor_has_signature { "true" } else { "false" }),
                        ],
                    )?;
                }
            }
            if let Some(probe) = payload_probe {
                if entry.compressed_size as usize != probe.consumed {
                    central_directory_compressed_size_likely_bad += 1;
                    let probe_consumed = probe.consumed.to_string();
                    let cd_compressed = entry.compressed_size.to_string();
                    zip_graph_relation_violation(
                        py,
                        &relation_violations,
                        &violations,
                        "central_directory_compressed_size_mismatch",
                        "central_directory.compressed_size",
                        "central_directory.compressed_size",
                        "payload.span",
                        "owns_span",
                        index,
                        entry.compressed_size as u64,
                        probe.consumed as u64,
                        "central_directory.compressed_size",
                        0.95,
                        "high",
                        &[
                            ("central_directory_compressed_size", &cd_compressed),
                            ("payload_consumed_size", &probe_consumed),
                        ],
                    )?;
                }
            }
        }
        if payload_end > next_boundary {
            span_conflicts += 1;
            zip_graph_violation(py, &violations, "span_overlap", &format!("payload_span:cd:{index}"), "next_record", "central_directory.compressed_size", &next_boundary.to_string(), &payload_end.to_string(), payload_end as i64 - next_boundary as i64, "high")?;
        }
        if payload_end < next_boundary {
            if let Some(descriptor_offset) = find_signature_between(&data, payload_end, next_boundary, DD_SIG) {
                let descriptor_end = descriptor_at_impl(
                    &data,
                    descriptor_offset,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or_else(|| descriptor_offset.saturating_add(16).min(next_boundary));
                zip_graph_node(py, &nodes, &format!("descriptor_candidate:cd:{index}"), "descriptor_candidate", descriptor_offset, descriptor_end, "candidate")?;
                zip_graph_edge(py, &edges, &format!("payload_span:cd:{index}"), &format!("descriptor_candidate:cd:{index}"), "adjacent_to", "data_descriptor", payload_end == descriptor_offset, 0.8)?;
                if payload_end != descriptor_offset {
                    descriptor_conflicts += 1;
                    zip_graph_violation(py, &violations, "descriptor_span_gap", &format!("payload_span:cd:{index}"), &format!("descriptor_candidate:cd:{index}"), "data_descriptor.record", &payload_end.to_string(), &descriptor_offset.to_string(), descriptor_offset as i64 - payload_end as i64, "medium")?;
                    zip_graph_explanation(py, &explanations, "descriptor_span_adjustment", true, "central_directory.compressed_size", descriptor_offset as i64 - payload_end as i64, "descriptor candidate explains payload boundary drift")?;
                }
            }
        }
        if let Some(descriptor) = descriptor_record_for_entry(&data, entry, &local) {
            if descriptor.crc32 != entry.crc32 {
                let payload_crc = payload_probe.map(|probe| probe.crc32).or_else(|| payload_crc_for_entry(&data, entry, &local));
                let payload_matches_cd = payload_crc.is_some_and(|value| value == entry.crc32);
                let payload_matches_descriptor = payload_crc.is_some_and(|value| value == descriptor.crc32);
                let (likely_bad_side, confidence) = if payload_matches_cd && !payload_matches_descriptor {
                    ("data_descriptor.crc", 0.95)
                } else if payload_matches_descriptor && !payload_matches_cd {
                    ("central_directory.crc", 0.9)
                } else if payload_crc.is_some() && !payload_matches_cd && !payload_matches_descriptor {
                    ("payload.compressed_data", 0.8)
                } else {
                    ("crc_direction_unresolved", 0.35)
                };
                descriptor_crc_cd_mismatch += 1;
                if payload_crc.is_some() && !payload_matches_descriptor {
                    descriptor_crc_payload_mismatch += 1;
                }
                if likely_bad_side == "data_descriptor.crc" {
                    descriptor_crc_likely_bad += 1;
                } else if likely_bad_side == "payload.compressed_data" {
                    payload_crc_mismatch += 1;
                } else if likely_bad_side == "crc_direction_unresolved" {
                    crc_direction_unresolved += 1;
                }
                let descriptor_crc_string = descriptor.crc32.to_string();
                let central_directory_crc_string = entry.crc32.to_string();
                let payload_crc_string = payload_crc.map(|value| value.to_string()).unwrap_or_default();
                zip_graph_relation_violation(
                    py,
                    &relation_violations,
                    &violations,
                    "data_descriptor_crc_mismatch",
                    if likely_bad_side == "crc_direction_unresolved" { "data_descriptor.crc" } else { likely_bad_side },
                    "data_descriptor.crc",
                    "central_directory.crc",
                    "matches_field",
                    index,
                    descriptor.crc32 as u64,
                    entry.crc32 as u64,
                    likely_bad_side,
                    confidence,
                    "high",
                    &[
                        ("descriptor_crc", &descriptor_crc_string),
                        ("central_directory_crc", &central_directory_crc_string),
                        ("payload_crc", &payload_crc_string),
                        ("descriptor_matches_cd", "false"),
                        ("payload_matches_cd", if payload_matches_cd { "true" } else { "false" }),
                        ("payload_matches_descriptor", if payload_matches_descriptor { "true" } else { "false" }),
                    ],
                )?;
            }
        }
        if parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset).is_some()
            || parse_zip64_extra_tolerant(&local.extra, local.extra_offset).is_some()
        {
            zip64_extra_present += 1;
            zip_graph_explanation(py, &explanations, "zip64_extra_resolution", true, "zip64.extra", 0, "ZIP64 extra fields are present")?;
        }
        for (zip64, location) in [
            (parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset), "central_directory"),
            (parse_zip64_extra_tolerant(&local.extra, local.extra_offset), "local_header"),
        ] {
            if let Some(zip64) = zip64 {
                let expected_zip64_size = zip64.values.len() * 8;
                if zip64.stored_size != expected_zip64_size {
                    zip64_extra_mismatch += 1;
                    zip64_extra_length_mismatch += 1;
                    let expected_size_string = expected_zip64_size.to_string();
                    let stored_size_string = zip64.stored_size.to_string();
                    let parseable_values_string = zip64.values.len().to_string();
                    let expected_values_string = zip64.values.len().to_string();
                    zip_graph_relation_violation(
                        py,
                        &relation_violations,
                        &violations,
                        "zip64_extra_length_mismatch",
                        "zip64.extra_length",
                        "zip64.extra_length",
                        "zip64.extra",
                        "bounds",
                        index,
                        zip64.stored_size as u64,
                        expected_zip64_size as u64,
                        "zip64.extra_length",
                        0.95,
                        "high",
                        &[
                            ("declared_size", &stored_size_string),
                            ("expected_size", &expected_size_string),
                            ("parseable_value_count", &parseable_values_string),
                            ("expected_value_count", &expected_values_string),
                            ("truncated", if zip64.stored_size % 8 != 0 { "true" } else { "false" }),
                            ("overlong", if zip64.stored_size > expected_zip64_size { "true" } else { "false" }),
                            ("zip64_extra_location", location),
                        ],
                    )?;
                }
                if let Some(probe) = payload_probe {
                    if zip64.values.first().is_some_and(|value| *value != probe.uncompressed_size) {
                        zip64_uncompressed_size_mismatch += 1;
                        let zip64_uncompressed = zip64.values.first().copied().unwrap_or(0).to_string();
                        let payload_uncompressed = probe.uncompressed_size.to_string();
                        zip_graph_relation_violation(
                            py,
                            &relation_violations,
                            &violations,
                            "zip64_uncompressed_size_mismatch",
                            "zip64.uncompressed_size",
                            "zip64.uncompressed_size",
                            "payload.span",
                            "matches_payload",
                            index,
                            zip64.values.first().copied().unwrap_or(0),
                            probe.uncompressed_size,
                            "zip64.uncompressed_size",
                            0.95,
                            "high",
                            &[
                                ("zip64_uncompressed_size", &zip64_uncompressed),
                                ("payload_uncompressed_size", &payload_uncompressed),
                                ("zip64_extra_location", location),
                            ],
                        )?;
                    }
                }
            }
        }
        for diagnostic in [
            extra_field_diagnostic(&entry.extra, entry.extra_offset, "central_directory"),
            extra_field_diagnostic(&local.extra, local.extra_offset, "local_header"),
        ]
        .into_iter()
        .flatten()
        {
            extra_field_structure_mismatch += 1;
            let declared_size = diagnostic.declared_size.to_string();
            let parseable_size = diagnostic.parseable_size.to_string();
            let header_id = format!("{:04x}", diagnostic.header_id);
            let offset = diagnostic.offset.to_string();
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "extra_field_structure_mismatch",
                "generic_extra_field",
                diagnostic.theory_field,
                "generic_extra_field",
                "extra_tlv_bounds",
                index,
                diagnostic.declared_size as u64,
                diagnostic.parseable_size as u64,
                "generic_extra_field",
                0.9,
                "high",
                &[
                    ("extra_location", diagnostic.location),
                    ("extra_header_id", &header_id),
                    ("declared_size", &declared_size),
                    ("parseable_size", &parseable_size),
                    ("extra_offset", &offset),
                    ("truncated", if diagnostic.truncated { "true" } else { "false" }),
                    ("overlong", if diagnostic.overlong { "true" } else { "false" }),
                ],
            )?;
        }
    }
    let cd_offset_delta = physical_cd_offset as i64 - resolved.declared_offset as i64;
    if local_offset_violations >= 2
        || (local_offset_violations >= 1 && archive_offset != 0 && eocd_cd_size_mismatch == 0)
        || (cd_offset_delta < 0 && eocd_cd_size_mismatch == 0)
    {
        split_volume_missing_range_evidence = local_offset_violations.max(1);
        let local_offset_violations_string = local_offset_violations.to_string();
        let archive_offset_string = archive_offset.to_string();
        let cd_offset_delta_string = cd_offset_delta.to_string();
        zip_graph_relation_violation(
            py,
            &relation_violations,
            &violations,
            "split_volume_missing_range_evidence",
            "split_volume.missing_range",
            "split_volume.missing_range",
            "central_directory.local_header_offset",
            "propagates_to",
            0,
            split_volume_missing_range_evidence as u64,
            archive_offset as u64,
            "split_volume.missing_range",
            0.75,
            "high",
            &[
                ("local_header_offset_violation_count", &local_offset_violations_string),
                ("archive_offset", &archive_offset_string),
                ("central_directory_offset_delta", &cd_offset_delta_string),
                ("propagated_symptom_field", "central_directory.local_header_offset"),
            ],
        )?;
    }
    summary.set_item("violation_count", violations.len())?;
    summary.set_item("edge_count", edges.len())?;
    summary.set_item("node_count", nodes.len())?;
    summary.set_item("central_local_name_mismatch_count", name_mismatch)?;
    summary.set_item("central_local_flags_mismatch_count", flags_mismatch)?;
    summary.set_item("central_local_method_mismatch_count", method_mismatch)?;
    summary.set_item("central_local_crc_mismatch_count", crc_mismatch)?;
    summary.set_item("central_local_compressed_size_mismatch_count", compressed_mismatch)?;
    summary.set_item("central_local_uncompressed_size_mismatch_count", uncompressed_mismatch)?;
    summary.set_item("eocd_entry_count_mismatch_count", eocd_entry_count_mismatch)?;
    summary.set_item("eocd_cd_size_mismatch_count", eocd_cd_size_mismatch)?;
    summary.set_item("local_header_offset_violation_count", local_offset_violations)?;
    summary.set_item("central_local_flags_relation_mismatch_count", central_local_flags_relation_mismatch)?;
    summary.set_item("central_directory_flags_likely_bad_count", central_directory_flags_likely_bad)?;
    summary.set_item("local_header_flags_likely_bad_count", local_header_flags_likely_bad)?;
    summary.set_item("flags_relation_ambiguous_count", flags_relation_ambiguous)?;
    summary.set_item("bad_local_header_target_signature_count", bad_local_header_target_signature)?;
    summary.set_item("local_header_signature_mismatch_count", local_header_signature_mismatch)?;
    summary.set_item("local_header_offset_points_to_descriptor_or_payload_count", local_header_offset_points_to_descriptor_or_payload)?;
    summary.set_item("local_header_offset_points_outside_archive_count", local_header_offset_points_outside_archive)?;
    summary.set_item("payload_decode_failure_count", payload_decode_failure)?;
    summary.set_item("payload_crc_mismatch_count", payload_crc_mismatch)?;
    summary.set_item("descriptor_crc_cd_mismatch_count", descriptor_crc_cd_mismatch)?;
    summary.set_item("descriptor_crc_payload_mismatch_count", descriptor_crc_payload_mismatch)?;
    summary.set_item("descriptor_crc_likely_bad_count", descriptor_crc_likely_bad)?;
    summary.set_item("local_header_crc_likely_bad_count", local_header_crc_likely_bad)?;
    summary.set_item("crc_direction_unresolved_count", crc_direction_unresolved)?;
    summary.set_item("descriptor_record_mismatch_count", descriptor_record_mismatch)?;
    summary.set_item("descriptor_size_mismatch_count", descriptor_size_mismatch)?;
    summary.set_item("central_directory_compressed_size_likely_bad_count", central_directory_compressed_size_likely_bad)?;
    summary.set_item("local_header_compressed_size_likely_bad_count", local_header_compressed_size_likely_bad)?;
    summary.set_item("extra_field_structure_mismatch_count", extra_field_structure_mismatch)?;
    summary.set_item("span_conflict_count", span_conflicts)?;
    summary.set_item("descriptor_conflict_count", descriptor_conflicts)?;
    summary.set_item("zip64_extra_present_count", zip64_extra_present)?;
    summary.set_item("zip64_extra_mismatch_count", zip64_extra_mismatch)?;
    summary.set_item("zip64_extra_length_mismatch_count", zip64_extra_length_mismatch)?;
    summary.set_item("zip64_uncompressed_size_mismatch_count", zip64_uncompressed_size_mismatch)?;
    summary.set_item("split_volume_missing_range_evidence_count", split_volume_missing_range_evidence)?;
    let zip64_eocd = find_zip64_eocd(&data, eocd.offset);
    let zip64_locator = find_zip64_locator(&data, eocd.offset);
    summary.set_item("zip64_eocd_present", zip64_eocd.is_some())?;
    summary.set_item("zip64_locator_present", zip64_locator.is_some())?;
    let zip64_locator_mismatch = zip64_locator
        .is_some_and(|locator| !zip64_eocd.is_some_and(|tail| locator.zip64_eocd_offset == tail.offset as u64 && locator.total_disks >= 1));
    let zip64_eocd_mismatch = zip_inspect_zip64_eocd_mismatch_count(zip64_eocd, physical_cd_offset, cd_end, all_entries.len());
    summary.set_item("zip64_locator_mismatch_count", if zip64_locator_mismatch { 1 } else { 0 })?;
    summary.set_item("zip64_eocd_mismatch_count", zip64_eocd_mismatch)?;
    if let Some(tail) = zip64_eocd {
        zip_graph_node(py, &nodes, "zip64_eocd:0", "zip64_eocd", tail.offset, tail.end, "parsed")?;
    }
    if let Some(locator) = zip64_locator {
        zip_graph_node(py, &nodes, "zip64_locator:0", "zip64_locator", locator.offset, locator.end, "parsed")?;
        zip_graph_edge(py, &edges, "zip64_locator:0", "zip64_eocd:0", "points_to", "zip64_locator", zip64_eocd.is_some_and(|tail| locator.zip64_eocd_offset == tail.offset as u64), 0.9)?;
        if zip64_locator_mismatch {
            let expected = zip64_eocd.map(|tail| tail.offset as u64).unwrap_or(0);
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "zip64_locator_mismatch",
                "zip64.locator",
                "zip64.locator",
                "zip64.eocd",
                "points_to",
                0,
                locator.zip64_eocd_offset,
                expected,
                "zip64.locator",
                0.98,
                "error",
                &[
                    ("expected_zip64_eocd_offset", &expected.to_string()),
                    ("locator_total_disks", &locator.total_disks.to_string()),
                ],
            )?;
        }
    }
    if let Some(tail) = zip64_eocd {
        if zip64_eocd_mismatch > 0 {
            zip_graph_relation_violation(
                py,
                &relation_violations,
                &violations,
                "zip64_eocd_mismatch",
                "zip64.eocd",
                "zip64.eocd",
                "central_directory.span",
                "describes",
                0,
                tail.cd_size,
                cd_end.saturating_sub(physical_cd_offset) as u64,
                "zip64.eocd",
                0.96,
                "error",
                &[
                    ("zip64_eocd_cd_offset", &tail.cd_offset.to_string()),
                    ("expected_cd_offset", &(physical_cd_offset as u64).to_string()),
                    ("mismatch_count", &zip64_eocd_mismatch.to_string()),
                ],
            )?;
        }
    }
    Ok(result.unbind())
}

fn zip_directory_consistency_empty<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("schema_version", 1)?;
    result.set_item("error", "")?;
    result.set_item("cd_parseable", false)?;
    result.set_item("cd_entries_checked", 0)?;
    result.set_item("cd_entries_parseable", 0)?;
    result.set_item("cd_entries_truncated_by_limit", false)?;
    result.set_item("local_header_missing_count", 0)?;
    result.set_item("local_header_bad_signature_count", 0)?;
    result.set_item("central_local_name_mismatch_count", 0)?;
    result.set_item("central_local_flags_mismatch_count", 0)?;
    result.set_item("central_local_method_mismatch_count", 0)?;
    result.set_item("central_local_crc_mismatch_count", 0)?;
    result.set_item("central_local_compressed_size_mismatch_count", 0)?;
    result.set_item("central_local_uncompressed_size_mismatch_count", 0)?;
    result.set_item("local_extra_len_mismatch_count", 0)?;
    result.set_item("central_local_offset_suspicious_count", 0)?;
    let descriptor = PyDict::new(py);
    for key in [
        "descriptor_checked_count",
        "descriptor_present_count",
        "descriptor_missing_count",
        "descriptor_flag_mismatch_count",
        "spurious_descriptor_candidate_count",
        "descriptor_candidate_span_overlap_count",
        "descriptor_payload_end_to_next_local_delta_min",
        "cd_compressed_size_points_into_descriptor_count",
        "compressed_size_ends_before_descriptor_count",
        "compressed_size_ends_inside_descriptor_count",
        "compressed_size_ends_after_descriptor_count",
        "compressed_size_ends_after_next_local_count",
        "compressed_size_ends_before_next_local_gap_count",
        "descriptor_span_between_payload_and_next_local_count",
        "cd_entry_span_conflict_count",
        "wrong_local_header_target_count",
        "local_header_offset_points_to_other_entry_count",
        "local_header_offset_points_to_descriptor_or_payload_count",
        "local_header_offset_points_inside_payload_count",
        "local_header_offset_points_inside_descriptor_count",
        "local_header_offset_points_outside_archive_count",
        "local_header_offset_bad_signature_count",
        "descriptor_span_present_count",
        "descriptor_span_missing_count",
        "descriptor_between_payload_and_next_local_count",
        "descriptor_flag_set_but_span_missing_count",
        "descriptor_span_present_without_flag_count",
        "descriptor_span_conflicts_with_cd_size_count",
        "cd_size_points_to_descriptor_start_count",
        "cd_size_points_inside_descriptor_count",
        "cd_offset_size_joint_conflict_count",
        "cd_offset_valid_but_size_conflict_count",
        "cd_size_valid_but_offset_conflict_count",
    ] {
        descriptor.set_item(key, 0)?;
    }
    descriptor.set_item("local_header_offset_target_conflict_ratio", 0.0)?;
    result.set_item("descriptor", descriptor)?;
    Ok(result)
}

fn zip_graph_node<'py>(
    py: Python<'py>,
    nodes: &Bound<'py, PyList>,
    id: &str,
    kind: &str,
    start: usize,
    end: usize,
    status: &str,
) -> PyResult<()> {
    let node = PyDict::new(py);
    node.set_item("id", id)?;
    node.set_item("kind", kind)?;
    node.set_item("start", start)?;
    node.set_item("end", end)?;
    node.set_item("size", end.saturating_sub(start))?;
    node.set_item("status", status)?;
    nodes.append(node)
}

fn zip_graph_edge<'py>(
    py: Python<'py>,
    edges: &Bound<'py, PyList>,
    source: &str,
    target: &str,
    kind: &str,
    field: &str,
    valid: bool,
    confidence: f64,
) -> PyResult<()> {
    let edge = PyDict::new(py);
    edge.set_item("source_node", source)?;
    edge.set_item("target_node", target)?;
    edge.set_item("kind", kind)?;
    edge.set_item("field", field)?;
    edge.set_item("valid", valid)?;
    edge.set_item("confidence", confidence)?;
    edges.append(edge)
}

fn zip_graph_violation<'py>(
    py: Python<'py>,
    violations: &Bound<'py, PyList>,
    kind: &str,
    source: &str,
    target: &str,
    field: &str,
    expected: &str,
    observed: &str,
    delta: i64,
    severity: &str,
) -> PyResult<()> {
    let violation = PyDict::new(py);
    violation.set_item("kind", kind)?;
    violation.set_item("source_node", source)?;
    violation.set_item("target_node", target)?;
    violation.set_item("field", field)?;
    violation.set_item("expected", expected)?;
    violation.set_item("observed", observed)?;
    violation.set_item("delta", delta)?;
    violation.set_item("severity", severity)?;
    violations.append(violation)
}

#[allow(clippy::too_many_arguments)]
fn zip_graph_relation_violation<'py>(
    py: Python<'py>,
    relation_violations: &Bound<'py, PyList>,
    violations: &Bound<'py, PyList>,
    kind: &str,
    field: &str,
    source_field: &str,
    target_field: &str,
    relation: &str,
    entry_index: usize,
    source_value: u64,
    target_value: u64,
    likely_bad_side: &str,
    evidence_confidence: f64,
    severity: &str,
    extra: &[(&str, &str)],
) -> PyResult<()> {
    let violation = PyDict::new(py);
    violation.set_item("kind", kind)?;
    violation.set_item("field", field)?;
    violation.set_item("source_field", source_field)?;
    violation.set_item("target_field", target_field)?;
    violation.set_item("relation", relation)?;
    violation.set_item("entry_index", entry_index)?;
    violation.set_item("source_value", source_value)?;
    violation.set_item("target_value", target_value)?;
    violation.set_item("likely_bad_side", likely_bad_side)?;
    violation.set_item("evidence_confidence", evidence_confidence)?;
    violation.set_item("severity", severity)?;
    violation.set_item("valid", false)?;
    for (key, value) in extra {
        if value.is_empty() {
            continue;
        }
        match *value {
            "true" => violation.set_item(*key, true)?,
            "false" => violation.set_item(*key, false)?,
            _ => violation.set_item(*key, *value)?,
        }
    }
    relation_violations.append(&violation)?;
    violations.append(violation)
}

fn zip_graph_explanation<'py>(
    py: Python<'py>,
    explanations: &Bound<'py, PyList>,
    kind: &str,
    applies: bool,
    field: &str,
    delta: i64,
    reason: &str,
) -> PyResult<()> {
    let explanation = PyDict::new(py);
    explanation.set_item("kind", kind)?;
    explanation.set_item("applies", applies)?;
    explanation.set_item("field", field)?;
    explanation.set_item("delta", delta)?;
    explanation.set_item("reason", reason)?;
    explanations.append(explanation)
}

fn scan_zip_local_headers(data: &[u8], before: usize, limit: usize) -> Vec<LocalHeader> {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    let end = before.min(data.len());
    while cursor + LOCAL_HEADER_LEN <= end && output.len() < limit {
        let Some(delta) = memmem::find(&data[cursor..end], LFH_SIG) else {
            break;
        };
        let offset = cursor + delta;
        if let Some(local) = parse_local_header(data, offset) {
            output.push(local);
        }
        cursor = offset.saturating_add(1);
    }
    output
}

fn local_record_spans(locals: &[LocalHeader], cd_offset: usize) -> Vec<(usize, usize)> {
    let mut offsets = locals.iter().map(|local| local.offset).collect::<Vec<_>>();
    offsets.sort_unstable();
    let mut output = Vec::new();
    for local in locals {
        let data_start = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .unwrap_or(local.offset);
        let next_local = offsets
            .iter()
            .copied()
            .find(|offset| *offset > local.offset)
            .unwrap_or(cd_offset);
        output.push((local.offset, next_local.max(data_start).max(local.offset + LOCAL_HEADER_LEN)));
    }
    output
}

fn local_payload_descriptor_spans(
    data: &[u8],
    locals: &[LocalHeader],
    cd_offset: usize,
) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let mut offsets = locals.iter().map(|local| local.offset).collect::<Vec<_>>();
    offsets.sort_unstable();
    let mut payload_spans = Vec::new();
    let mut descriptor_spans = Vec::new();
    for local in locals {
        let Some(data_start) = local_data_start(local) else {
            continue;
        };
        let next_local = offsets
            .iter()
            .copied()
            .find(|offset| *offset > local.offset)
            .unwrap_or(cd_offset)
            .min(data.len());
        if data_start >= next_local {
            continue;
        }
        if let Some(descriptor_offset) = find_signature_between(data, data_start, next_local, DD_SIG) {
            payload_spans.push((data_start, descriptor_offset));
            descriptor_spans.push((descriptor_offset, descriptor_offset.saturating_add(24).min(next_local)));
        } else {
            payload_spans.push((data_start, next_local));
        }
    }
    (payload_spans, descriptor_spans)
}

fn local_data_start(local: &LocalHeader) -> Option<usize> {
    local
        .offset
        .checked_add(LOCAL_HEADER_LEN)?
        .checked_add(local.name_len as usize)?
        .checked_add(local.extra_len as usize)
}

fn descriptor_record_for_entry(
    data: &[u8],
    entry: &CentralEntry,
    local: &LocalHeader,
) -> Option<DataDescriptorRecord> {
    if (entry.flags | local.flags) & 0x08 == 0 {
        return None;
    }
    let payload_end = local_data_start(local)?.checked_add(entry.compressed_size as usize)?;
    descriptor_record_at(data, payload_end, entry, local)
}

fn descriptor_record_at(
    data: &[u8],
    offset: usize,
    entry: &CentralEntry,
    local: &LocalHeader,
) -> Option<DataDescriptorRecord> {
    let zip64 = descriptor_uses_zip64(entry, local);
    let has_signature = data.get(offset..offset.checked_add(4)?) == Some(DD_SIG);
    let values_offset = offset.checked_add(if has_signature { 4 } else { 0 })?;
    if zip64 {
        if values_offset.checked_add(20)? > data.len() || local.flags & 0x08 == 0 {
            return None;
        }
        return Some(DataDescriptorRecord {
            crc32: u32_le(data, values_offset),
            compressed_size: u64_le(data, values_offset + 4),
            uncompressed_size: u64_le(data, values_offset + 12),
            has_signature,
        });
    }
    if local.flags & 0x08 != 0 && values_offset.checked_add(12)? <= data.len() {
        let compressed_size = u32_le(data, values_offset + 4) as u64;
        let uncompressed_size = u32_le(data, values_offset + 8) as u64;
        // A signature gives us an independent structural anchor, so preserve
        // mismatched values for the relation diagnostics above. Without that
        // anchor, require the values to agree with an entry header; otherwise
        // arbitrary bytes at the payload boundary look like a descriptor.
        if !has_signature
            && !descriptor_sizes_match_entry(compressed_size, uncompressed_size, entry, local)
        {
            return None;
        }
        return Some(DataDescriptorRecord {
            crc32: u32_le(data, values_offset),
            compressed_size,
            uncompressed_size,
            has_signature,
        });
    }
    None
}

fn descriptor_sizes_match_entry(
    compressed_size: u64,
    uncompressed_size: u64,
    entry: &CentralEntry,
    local: &LocalHeader,
) -> bool {
    let central_matches = entry.compressed_size as u64 == compressed_size
        && entry.uncompressed_size as u64 == uncompressed_size;
    let local_has_sizes = local.compressed_size != 0 || local.uncompressed_size != 0;
    let local_matches = local_has_sizes
        && local.compressed_size as u64 == compressed_size
        && local.uncompressed_size as u64 == uncompressed_size;
    central_matches || local_matches
}

fn descriptor_uses_zip64(entry: &CentralEntry, local: &LocalHeader) -> bool {
    entry.compressed_size == u32::MAX
        || entry.uncompressed_size == u32::MAX
        || local.compressed_size == u32::MAX
        || local.uncompressed_size == u32::MAX
        || extra_contains_zip64(&entry.extra)
        || extra_contains_zip64(&local.extra)
}

fn extra_contains_zip64(extra: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos.checked_add(4).is_some_and(|end| end <= extra.len()) {
        let header_id = u16_le(extra, pos);
        let size = u16_le(extra, pos + 2) as usize;
        let Some(end) = pos.checked_add(4).and_then(|start| start.checked_add(size)) else {
            return false;
        };
        if end > extra.len() {
            return false;
        }
        if header_id == 0x0001 {
            return true;
        }
        pos = end;
    }
    false
}

#[cfg(test)]
mod data_descriptor_width_tests {
    use super::*;

    fn entry_and_local(zip64: bool) -> (CentralEntry, LocalHeader) {
        let size = if zip64 { u32::MAX } else { 7 };
        let entry = CentralEntry {
            offset: 0, flags: 0x08, method: 0, crc32: 1,
            compressed_size: size, uncompressed_size: size,
            name_len: 1, extra_len: 0, name: vec![b'a'], extra: Vec::new(),
            extra_offset: 0, disk_number_start: 0, local_header_offset: 0,
        };
        let local = LocalHeader {
            offset: 0, flags: 0x08, method: 0, crc32: 0,
            compressed_size: size, uncompressed_size: size,
            name: vec![b'a'], extra: Vec::new(), extra_offset: 0,
            name_len: 1, extra_len: 0,
        };
        (entry, local)
    }

    #[test]
    fn signed_zip64_descriptor_is_read_at_64_bit_width() {
        let (entry, local) = entry_and_local(true);
        let mut bytes = DD_SIG.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0x1_0000_0007u64.to_le_bytes());
        bytes.extend_from_slice(&0x2_0000_0007u64.to_le_bytes());
        let descriptor = descriptor_record_at(&bytes, 0, &entry, &local).unwrap();
        assert_eq!(descriptor.compressed_size, 0x1_0000_0007);
        assert_eq!(descriptor.uncompressed_size, 0x2_0000_0007);
        assert!(descriptor.has_signature);
    }

    #[test]
    fn unsigned_zip32_descriptor_is_not_widened_by_trailing_bytes() {
        let (entry, local) = entry_and_local(false);
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa; 16]);
        let descriptor = descriptor_record_at(&bytes, 0, &entry, &local).unwrap();
        assert_eq!(descriptor.compressed_size, 7);
        assert_eq!(descriptor.uncompressed_size, 7);
        assert!(!descriptor.has_signature);
    }

    #[test]
    fn mismatched_zip32_descriptor_remains_parseable_for_diagnostics() {
        let (entry, local) = entry_and_local(false);
        let mut bytes = DD_SIG.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&7u32.to_le_bytes());
        let descriptor = descriptor_record_at(&bytes, 0, &entry, &local).unwrap();
        assert_eq!(descriptor.compressed_size, 8);
        assert_eq!(descriptor.uncompressed_size, 7);
        assert!(descriptor.has_signature);
    }
}

#[derive(Clone, Copy)]
struct ExtraFieldDiagnostic<'a> {
    location: &'a str,
    theory_field: &'a str,
    header_id: u16,
    declared_size: usize,
    parseable_size: usize,
    offset: usize,
    truncated: bool,
    overlong: bool,
}

fn parse_local_header_ignoring_signature(
    data: &[u8],
    offset: usize,
    entry: &CentralEntry,
) -> Option<LocalHeader> {
    if offset + LOCAL_HEADER_LEN > data.len() {
        return None;
    }
    let name_len = u16_le(data, offset + 26);
    let extra_len = u16_le(data, offset + 28);
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let data_start = extra_start.checked_add(extra_len as usize)?;
    if data_start > data.len() {
        return None;
    }
    let name = data[name_start..extra_start].to_vec();
    if name != entry.name {
        return None;
    }
    Some(LocalHeader {
        offset,
        flags: u16_le(data, offset + 6),
        method: u16_le(data, offset + 8),
        crc32: u32_le(data, offset + 14),
        compressed_size: u32_le(data, offset + 18),
        uncompressed_size: u32_le(data, offset + 22),
        name,
        extra: data[extra_start..data_start].to_vec(),
        extra_offset: extra_start,
        name_len,
        extra_len,
    })
}

fn extra_field_diagnostic<'a>(
    extra: &[u8],
    absolute_extra_offset: usize,
    location: &'a str,
) -> Option<ExtraFieldDiagnostic<'a>> {
    let mut pos = 0usize;
    while pos < extra.len() {
        if pos + 4 > extra.len() {
            return Some(ExtraFieldDiagnostic {
                location,
                theory_field: extra_theory_field_for_location(location),
                header_id: 0,
                declared_size: 4usize.saturating_sub(extra.len().saturating_sub(pos)),
                parseable_size: extra.len().saturating_sub(pos),
                offset: absolute_extra_offset + pos,
                truncated: true,
                overlong: false,
            });
        }
        let header_id = u16_le(extra, pos);
        let declared_size = u16_le(extra, pos + 2) as usize;
        let value_start = pos + 4;
        let value_end = value_start.saturating_add(declared_size);
        if value_end > extra.len() {
            return Some(ExtraFieldDiagnostic {
                location,
                theory_field: extra_theory_field_for_location(location),
                header_id,
                declared_size,
                parseable_size: extra.len().saturating_sub(value_start),
                offset: absolute_extra_offset + pos,
                truncated: true,
                overlong: false,
            });
        }
        if header_id == 0x0001 && declared_size % 8 != 0 {
            return Some(ExtraFieldDiagnostic {
                location,
                theory_field: "zip64.extra",
                header_id,
                declared_size,
                parseable_size: declared_size - (declared_size % 8),
                offset: absolute_extra_offset + pos,
                truncated: false,
                overlong: true,
            });
        }
        pos = value_end;
    }
    None
}

fn extra_theory_field_for_location(location: &str) -> &'static str {
    match location {
        "central_directory" => "central_directory.extra",
        "local_header" => "local_header.extra",
        _ => "zip64.extra",
    }
}

fn payload_probe_for_entry(
    data: &[u8],
    entry: &CentralEntry,
    local: &LocalHeader,
    next_boundary: usize,
) -> Option<PayloadProbe> {
    let start = local_data_start(local)?;
    let end = next_boundary.min(data.len());
    if start >= end {
        return None;
    }
    match entry.method {
        0 => {
            let consumed = if entry.compressed_size != u32::MAX {
                entry.compressed_size as usize
            } else {
                end.saturating_sub(start)
            };
            let payload_end = start.checked_add(consumed)?;
            let payload = data.get(start..payload_end)?;
            Some(PayloadProbe {
                consumed,
                end: payload_end,
                uncompressed_size: payload.len() as u64,
                crc32: crc32_bytes(payload),
            })
        }
        8 => {
            let input = data.get(start..end)?;
            let info = deflate_payload_info(input, None, false)?;
            Some(PayloadProbe {
                consumed: info.consumed,
                end: start + info.consumed,
                uncompressed_size: info.uncompressed_size,
                crc32: info.crc32,
            })
        }
        _ => None,
    }
}

fn payload_crc_for_entry(data: &[u8], entry: &CentralEntry, local: &LocalHeader) -> Option<u32> {
    let start = local_data_start(local)?;
    let end = start.checked_add(entry.compressed_size as usize)?;
    let payload = data.get(start..end)?;
    match entry.method {
        0 => Some(crc32_bytes(payload)),
        8 => deflate_payload_info(payload, Some(entry.uncompressed_size as u64), true).map(|info| info.crc32),
        _ => None,
    }
}

fn deflate_payload_info(input: &[u8], expected_size: Option<u64>, require_exact_input: bool) -> Option<DeflateInfo> {
    let mut decompressor = Decompress::new(false);
    let mut output = vec![0u8; COPY_CHUNK_SIZE.min(64 * 1024)];
    let mut crc = Crc32::new();
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let input_offset = before_in as usize;
        if input_offset > input.len() {
            return None;
        }
        let status = decompressor
            .decompress(&input[input_offset..], &mut output, FlushDecompress::None)
            .ok()?;
        let produced = decompressor.total_out().saturating_sub(before_out) as usize;
        if produced > output.len() {
            return None;
        }
        if produced > 0 {
            crc.update(&output[..produced]);
        }
        if expected_size.is_some_and(|limit| decompressor.total_out() > limit) {
            return None;
        }
        if status == Status::StreamEnd {
            if require_exact_input && decompressor.total_in() as usize != input.len() {
                return None;
            }
            if expected_size.is_some_and(|value| value != decompressor.total_out()) {
                return None;
            }
            return Some(DeflateInfo {
                consumed: decompressor.total_in() as usize,
                uncompressed_size: decompressor.total_out(),
                crc32: crc.finish(),
            });
        }
        if decompressor.total_in() as usize >= input.len() {
            return None;
        }
        if before_in == decompressor.total_in() && before_out == decompressor.total_out() {
            return None;
        }
    }
}


fn signature_hex_at(data: &[u8], offset: usize) -> String {
    data.get(offset..offset.saturating_add(4))
        .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
        .unwrap_or_default()
}

fn offset_inside_local_or_data_span(offset: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|(start, end)| offset > *start && offset < *end)
}

fn find_signature_between(data: &[u8], start: usize, end: usize, signature: &[u8]) -> Option<usize> {
    if start >= end || start >= data.len() {
        return None;
    }
    let bounded_end = end.min(data.len());
    memmem::find(&data[start..bounded_end], signature).map(|delta| start + delta)
}

fn zip_has_signature_at(data: &[u8], offset: usize, signature: &[u8]) -> bool {
    offset + signature.len() <= data.len() && data.get(offset..offset + signature.len()) == Some(signature)
}

fn zip_inspect_zip64_eocd_mismatch_count(
    zip64: Option<Zip64Eocd>,
    cd_offset: usize,
    cd_end: usize,
    entry_count: usize,
) -> usize {
    let Some(zip64) = zip64 else {
        return 0;
    };
    let expected_record_size = (zip64.end - zip64.offset - 12) as u64;
    let mut mismatches = 0usize;
    if expected_record_size != 44 {
        mismatches += 1;
    }
    if zip64.cd_size != cd_end.saturating_sub(cd_offset) as u64 {
        mismatches += 1;
    }
    if zip64.cd_offset != cd_offset as u64 {
        mismatches += 1;
    }
    if zip64.total_entries != entry_count as u64 {
        mismatches += 1;
    }
    if entry_count == 0 {
        mismatches += 1;
    }
    mismatches
}
