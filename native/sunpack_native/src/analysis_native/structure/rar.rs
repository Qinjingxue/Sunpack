fn checked_rar5_header_geometry(
    offset: usize,
    after_size: usize,
    header_size: u64,
) -> Option<(u64, u64)> {
    if header_size == 0 {
        return None;
    }
    let size_field_start = offset.checked_add(4)?;
    let vint_len = after_size.checked_sub(size_field_start)?;
    let total_header = 4u64
        .checked_add(u64::try_from(vint_len).ok()?)?
        .checked_add(header_size)?;
    let header_end = u64::try_from(offset).ok()?.checked_add(total_header)?;
    Some((total_header, header_end))
}

fn checked_usize_end(start: usize, size: usize, limit: usize) -> Option<usize> {
    let end = start.checked_add(size)?;
    (end <= limit).then_some(end)
}

const RAR_FIELDS: &[&str] = &[
    "archive.signature",
    "block.header_crc32",
    "block.header_size",
    "block.header_type",
    "block.header_flags",
    "block.extra_area",
    "block.data_area",
    "block.sequence",
    "main_header.flags",
    "main_header.extra_area",
    "main_header.locator.quick_open_offset",
    "main_header.locator.recovery_offset",
    "file_header.flags",
    "file_header.unpacked_size",
    "file_header.data_crc32",
    "file_header.compression_info",
    "file_header.name_size",
    "file_header.name",
    "file_header.extra_area",
    "file_data.packed_span",
    "file_data.decoded_content",
    "service_header",
    "encryption_header",
    "end_header.flags",
    "volume.parts",
];

fn finalize_rar_result(
    py: Python<'_>,
    out: Py<PyDict>,
    data: &[u8],
    file_size: u64,
    version: u8,
) -> PyResult<Py<PyDict>> {
    let d = out.bind(py);
    d.set_item(
        "archive.signature",
        hex_bytes(if version == 5 {
            data.get(..RAR5_SIGNATURE.len()).unwrap_or(&[])
        } else {
            data.get(..RAR4_SIGNATURE.len()).unwrap_or(&[])
        }),
    )?;
    d.set_item(
        "file_data.decoded_content",
        "not_decoded_by_structure_probe",
    )?;
    d.set_item("volume.parts", "single_or_external_parts_not_loaded")?;
    if version == 5 {
        enrich_rar5_semantics(d, data, file_size)?;
    } else if version == 4 {
        enrich_rar4_semantics(d, data, file_size)?;
    }
    finish_fields(d, RAR_FIELDS)?;
    let error = d
        .get_item("error")?
        .and_then(|item| item.extract::<String>().ok())
        .unwrap_or_default();
    let mut flags = Vec::new();
    if error.contains("header_crc_mismatch") {
        flags.push("rar_main_header_crc_bad");
    }
    if error.contains("second_block_crc_mismatch") {
        flags.push("rar_file_header_crc_bad");
    }
    if d.get_item("end_header.flags")?
        .and_then(|item| item.extract::<String>().ok())
        .as_deref()
        == Some("unavailable")
    {
        flags.push("missing_end_block");
    }
    d.set_item("damage_flags", PyList::new(py, flags)?)?;
    Ok(out)
}

fn enrich_rar5_semantics(d: &Bound<'_, PyDict>, data: &[u8], file_size: u64) -> PyResult<()> {
    let mut offset = RAR5_SIGNATURE.len();
    let mut blocks = 0usize;
    let mut crc_ok = 0usize;
    while checked_usize_end(offset, 6, data.len()).is_some()
        && u64::try_from(offset).map_or(false, |value| value < file_size)
    {
        let stored_crc = u32_le(data, offset);
        let Some(size_field_offset) = offset.checked_add(4) else {
            break;
        };
        let Some((header_size, after_size)) = read_vint(data, size_field_offset) else {
            break;
        };
        if after_size.saturating_sub(size_field_offset) > 3 {
            break;
        }
        let Some((total_header_u64, header_end_u64)) =
            checked_rar5_header_geometry(offset, after_size, header_size)
        else {
            break;
        };
        if header_end_u64 > file_size || header_end_u64 > data.len() as u64 {
            break;
        }
        let Ok(total_header) = usize::try_from(total_header_u64) else {
            break;
        };
        let Ok(header_end) = usize::try_from(header_end_u64) else {
            break;
        };
        let Some(crc_start) = offset.checked_add(4) else {
            break;
        };
        if crc_start > header_end {
            break;
        }

        let Some((header_type, mut cursor)) = read_vint(data, after_size) else {
            break;
        };
        let Some((header_flags, after_flags)) = read_vint(data, cursor) else {
            break;
        };
        cursor = after_flags;
        let extra_size = if header_flags & 0x01 != 0 {
            let Some((value, next)) = read_vint(data, cursor) else {
                break;
            };
            cursor = next;
            value
        } else {
            0
        };
        let data_size = if header_flags & 0x02 != 0 {
            let Some((value, next)) = read_vint(data, cursor) else {
                break;
            };
            cursor = next;
            value
        } else {
            0
        };
        let Ok(extra_size_usize) = usize::try_from(extra_size) else {
            break;
        };
        let Some(body_end) = header_end.checked_sub(extra_size_usize) else {
            break;
        };
        if cursor > body_end {
            break;
        }

        let computed_crc = crc32(&data[crc_start..header_end]);
        if computed_crc == stored_crc {
            crc_ok += 1;
        }
        if blocks == 0 {
            d.set_item("block.header_size", total_header)?;
            d.set_item("block.header_type", header_type)?;
            d.set_item("block.header_flags", header_flags)?;
            d.set_item(
                "block.header_crc32",
                format!(
                    "stored={stored_crc};computed={computed_crc};ok={}",
                    stored_crc == computed_crc
                ),
            )?;
            d.set_item("block.extra_area", extra_size)?;
            d.set_item("block.data_area", data_size)?;
        }

        let header_body = &data[..body_end];
        match header_type {
            1 => {
                let (main_flags, next) =
                    read_vint(header_body, cursor).unwrap_or((0, cursor));
                d.set_item("main_header.flags", main_flags)?;
                d.set_item("main_header.extra_area", extra_size)?;
                d.set_item(
                    "volume.parts",
                    if main_flags & 0x01 != 0 {
                        "volume_chain"
                    } else {
                        "single_volume"
                    },
                )?;
                d.set_item(
                    "main_header.locator.quick_open_offset",
                    "absent_or_unparsed_locator",
                )?;
                d.set_item(
                    "main_header.locator.recovery_offset",
                    "absent_or_unparsed_locator",
                )?;
                let _ = next;
            }
            2 => {
                let (file_flags, next) =
                    read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                let (unpacked, next) =
                    read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                let (_, next) = read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                if file_flags & 0x02 != 0 {
                    let Some(next_cursor) = cursor.checked_add(4) else {
                        break;
                    };
                    if next_cursor > body_end {
                        break;
                    }
                    cursor = next_cursor;
                }
                let file_crc = if file_flags & 0x04 != 0 {
                    let Some(crc_end) = cursor.checked_add(4) else {
                        break;
                    };
                    if crc_end > body_end {
                        break;
                    }
                    let value = u32_le(data, cursor);
                    cursor = crc_end;
                    Some(value)
                } else {
                    None
                };
                let (compression, next) =
                    read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                let (_, next) = read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                let (name_size, next) =
                    read_vint(header_body, cursor).unwrap_or((0, cursor));
                cursor = next;
                if cursor > body_end {
                    break;
                }
                let Ok(name_size_usize) = usize::try_from(name_size) else {
                    break;
                };
                let name_end = cursor
                    .checked_add(name_size_usize)
                    .map(|value| value.min(body_end))
                    .unwrap_or(body_end);
                if name_end < cursor {
                    break;
                }
                d.set_item("file_header.flags", file_flags)?;
                d.set_item("file_header.unpacked_size", unpacked)?;
                d.set_item(
                    "file_header.data_crc32",
                    file_crc
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "absent".into()),
                )?;
                d.set_item("file_header.compression_info", compression)?;
                d.set_item("file_header.name_size", name_size)?;
                d.set_item(
                    "file_header.name",
                    String::from_utf8_lossy(&data[cursor..name_end]).to_string(),
                )?;
                d.set_item("file_header.extra_area", extra_size)?;
                d.set_item(
                    "file_data.packed_span",
                    format!("offset={header_end};size={data_size}"),
                )?;
            }
            3 => {
                d.set_item(
                    "service_header",
                    format!("offset={offset};header={total_header};data={data_size}"),
                )?;
            }
            4 => {
                d.set_item(
                    "encryption_header",
                    format!("offset={offset};size={total_header}"),
                )?;
            }
            5 => {
                let end_flags = read_vint(header_body, cursor).map(|v| v.0).unwrap_or(0);
                d.set_item("end_header.flags", end_flags)?;
            }
            _ => {}
        }
        blocks += 1;
        let Ok(data_size_usize) = usize::try_from(data_size) else {
            break;
        };
        let Some(next) = header_end.checked_add(data_size_usize) else {
            break;
        };
        if next <= offset || next > data.len() {
            break;
        }
        offset = next;
    }
    d.set_item("block.sequence", blocks)?;
    d.set_item("block_crc_valid_count", crc_ok)?;
    Ok(())
}

fn enrich_rar4_semantics(d: &Bound<'_, PyDict>, data: &[u8], file_size: u64) -> PyResult<()> {
    let mut offset = RAR4_SIGNATURE.len();
    let mut blocks = 0usize;
    while checked_usize_end(offset, 7, data.len()).is_some()
        && u64::try_from(offset).map_or(false, |value| value < file_size)
    {
        let stored_crc = u16_le(data, offset) as u32;
        let header_type = data[offset + 2];
        let flags = u16_le(data, offset + 3) as u64;
        let header_size = u16_le(data, offset + 5) as usize;
        let Some(header_end) = checked_usize_end(offset, header_size, data.len()) else {
            break;
        };
        if header_size < 7
            || u64::try_from(header_end).map_or(true, |end| end > file_size)
        {
            break;
        }
        let add_size = if flags & 0x8000 != 0 && header_size >= 11 {
            u32_le(data, offset + 7) as usize
        } else {
            0
        };
        if blocks == 0 {
            d.set_item(
                "block.header_crc32",
                format!(
                    "stored16={stored_crc};computed16={}",
                    crc32(&data[offset + 2..header_end]) & 0xffff
                ),
            )?;
            d.set_item("block.header_size", header_size)?;
            d.set_item("block.header_type", header_type)?;
            d.set_item("block.header_flags", flags)?;
            d.set_item("block.extra_area", 0)?;
            d.set_item("block.data_area", add_size)?;
        }
        match header_type {
            0x73 => {
                d.set_item("main_header.flags", flags)?;
                d.set_item("main_header.extra_area", header_size.saturating_sub(13))?;
            }
            0x74 if header_size >= 32 => {
                let packed = u32_le(data, offset + 7) as u64;
                let unpacked = u32_le(data, offset + 11) as u64;
                let crc = u32_le(data, offset + 16);
                let method = data[offset + 25];
                let name_size = u16_le(data, offset + 26) as usize;
                let Some(name_start) = offset.checked_add(32) else {
                    break;
                };
                if name_start > header_end {
                    break;
                }
                let name_end = name_start
                    .checked_add(name_size)
                    .map(|value| value.min(header_end))
                    .unwrap_or(header_end);
                if name_end < name_start {
                    break;
                }
                d.set_item("file_header.flags", flags)?;
                d.set_item("file_header.unpacked_size", unpacked)?;
                d.set_item("file_header.data_crc32", crc)?;
                d.set_item("file_header.compression_info", method)?;
                d.set_item("file_header.name_size", name_size)?;
                d.set_item(
                    "file_header.name",
                    String::from_utf8_lossy(&data[name_start..name_end]).to_string(),
                )?;
                d.set_item(
                    "file_header.extra_area",
                    header_end.saturating_sub(name_end),
                )?;
                d.set_item(
                    "file_data.packed_span",
                    format!("offset={header_end};size={packed}"),
                )?;
            }
            0x7a => {
                d.set_item(
                    "service_header",
                    format!("offset={offset};size={header_size}"),
                )?;
            }
            0x7b => {
                d.set_item("end_header.flags", flags)?;
            }
            _ => {}
        }
        blocks += 1;
        let Some(next) = header_end.checked_add(add_size) else {
            break;
        };
        if next <= offset || next > data.len() {
            break;
        }
        offset = next;
    }
    d.set_item("block.sequence", blocks)?;
    d.set_item(
        "main_header.locator.quick_open_offset",
        "not_in_rar4_layout",
    )?;
    d.set_item("main_header.locator.recovery_offset", "not_in_rar4_layout")?;
    d.set_item(
        "encryption_header",
        "rar4_encryption_is_flag_or_file_header_based",
    )?;
    Ok(())
}

fn rar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", false)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    for key in [
        "version",
        "first_header_offset",
        "first_header_size",
        "first_header_type",
        "second_block_type",
        "second_block_size",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "header_crc_checked",
        "header_crc_ok",
        "second_block_checked",
        "second_block_ok",
        "block_walk_ok",
        "strong_accept",
    ] {
        d.set_item(key, false)?;
    }
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn inspect_rar4(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR4_SIGNATURE.len();
    let Some(min_header_end) = first_header_offset.checked_add(7) else {
        return Ok(rar_empty(py, "rar4_first_header_too_small")?.unbind());
    };
    if file_size < min_header_end as u64 || data.len() < min_header_end {
        return Ok(rar_empty(py, "rar4_first_header_too_small")?.unbind());
    }
    let header_crc = u16_le(data, first_header_offset);
    let header_type = data[first_header_offset + 2];
    let header_size = u16_le(data, first_header_offset + 5) as u64;
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 4)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar4:signature"])?;
    d.set_item("evidence", &evidence)?;
    if !matches!(header_type, 0x73..=0x7B) {
        d.set_item("error", "rar4_unknown_first_header_type")?;
        return Ok(d.unbind());
    }
    let Some(header_end_u64) = u64::try_from(first_header_offset)
        .ok()
        .and_then(|offset| offset.checked_add(header_size))
    else {
        d.set_item("error", "rar4_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    };
    if header_size < 7 || header_end_u64 > file_size {
        d.set_item("error", "rar4_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    let Ok(header_end) = usize::try_from(header_end_u64) else {
        d.set_item("error", "rar4_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    };
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar4:first_header")?;
    if data.len() >= header_end {
        let full_header = &data[first_header_offset..header_end];
        let crc_ok = (crc32(&full_header[2..]) & 0xFFFF) == header_crc as u32;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar4:header_crc")?;
        } else if header_type == 0x73 {
            d.set_item("error", "rar4_header_crc_mismatch")?;
        }
    }
    let second_offset = header_end;
    if header_type == 0x73
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && header_end_u64 < file_size
    {
        let second = inspect_rar4_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar4:second_block")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 0x73
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (header_end_u64 >= file_size
            || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar4_block(data: &[u8], offset: usize, file_size: u64) -> (bool, u8, u64, &'static str) {
    let Some(min_header_end) = offset.checked_add(7) else {
        return (false, 0, 0, "rar4_second_block_too_small");
    };
    if u64::try_from(offset).map_or(true, |value| value >= file_size)
        || data.len() < min_header_end
    {
        return (false, 0, 0, "rar4_second_block_too_small");
    }
    let header_crc = u16_le(data, offset);
    let header_type = data[offset + 2];
    let header_flags = u16_le(data, offset + 3);
    let header_size = u16_le(data, offset + 5) as u64;
    if !matches!(header_type, 0x73..=0x7B) {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_unknown_type",
        );
    }
    let Some(header_end_u64) = u64::try_from(offset)
        .ok()
        .and_then(|start| start.checked_add(header_size))
    else {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_size_out_of_range",
        );
    };
    let Ok(header_end) = usize::try_from(header_end_u64) else {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_size_out_of_range",
        );
    };
    if header_size < 7 || header_end_u64 > file_size || header_end > data.len() {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_size_out_of_range",
        );
    }
    let full_header = &data[offset..header_end];
    if (crc32(&full_header[2..]) & 0xFFFF) != header_crc as u32 {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_crc_mismatch",
        );
    }
    let mut block_size = header_size;
    if header_flags & 0x8000 != 0 {
        if header_size < 11 {
            return (
                false,
                header_type,
                block_size,
                "rar4_second_block_add_size_missing",
            );
        }
        let add_size = u32_le(full_header, 7) as u64;
        let Some(updated_size) = block_size.checked_add(add_size) else {
            return (
                false,
                header_type,
                block_size,
                "rar4_second_block_payload_out_of_range",
            );
        };
        block_size = updated_size;
        let payload_end = u64::try_from(offset)
            .ok()
            .and_then(|start| start.checked_add(block_size));
        if payload_end.map_or(true, |end| end > file_size) {
            return (
                false,
                header_type,
                block_size,
                "rar4_second_block_payload_out_of_range",
            );
        }
    }
    (true, header_type, block_size, "")
}

fn inspect_rar5(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR5_SIGNATURE.len();
    let Some(min_header_end) = first_header_offset.checked_add(6) else {
        return Ok(rar_empty(py, "rar5_first_header_too_small")?.unbind());
    };
    if file_size < min_header_end as u64 || data.len() < min_header_end {
        return Ok(rar_empty(py, "rar5_first_header_too_small")?.unbind());
    }
    let Some(size_field_offset) = first_header_offset.checked_add(4) else {
        return Ok(rar_empty(py, "rar5_header_size_vint_missing")?.unbind());
    };
    let Some((header_size, after_size)) = read_vint(data, size_field_offset) else {
        return Ok(rar_empty(py, "rar5_header_size_vint_missing")?.unbind());
    };
    if after_size.saturating_sub(size_field_offset) > 3 {
        return Ok(rar_empty(py, "rar5_header_size_vint_too_long")?.unbind());
    }
    let Some((header_type, _)) = read_vint(data, after_size) else {
        return Ok(rar_empty(py, "rar5_header_type_vint_missing")?.unbind());
    };
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 5)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar5:signature"])?;
    d.set_item("evidence", &evidence)?;
    if !matches!(header_type, 1 | 4) {
        d.set_item("error", "rar5_main_or_encryption_header_missing")?;
        return Ok(d.unbind());
    }
    let Some((_first_header_total_size, first_header_end_u64)) =
        checked_rar5_header_geometry(first_header_offset, after_size, header_size)
    else {
        d.set_item("error", "rar5_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    };
    if first_header_end_u64 > file_size {
        d.set_item("error", "rar5_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    let Ok(first_header_end) = usize::try_from(first_header_end_u64) else {
        d.set_item("error", "rar5_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    };
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar5:first_header")?;
    if data.len() >= first_header_end {
        let stored_crc = u32_le(data, first_header_offset);
        let Some(crc_start) = first_header_offset.checked_add(4) else {
            d.set_item("error", "rar5_first_header_size_out_of_range")?;
            return Ok(d.unbind());
        };
        if crc_start > first_header_end {
            d.set_item("error", "rar5_first_header_size_out_of_range")?;
            return Ok(d.unbind());
        }
        let header_data = &data[crc_start..first_header_end];
        let crc_ok = crc32(header_data) == stored_crc;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar5:header_crc")?;
        } else {
            d.set_item("error", "rar5_header_crc_mismatch")?;
        }
    }
    if header_type == 4 && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()? {
        d.set_item("header_encrypted", true)?;
        d.set_item("password_required", true)?;
        d.set_item("strong_accept", true)?;
        d.set_item("block_walk_ok", true)?;
        evidence.append("rar5:archive_encryption_header")?;
        return Ok(d.unbind());
    }
    let second_offset = first_header_end;
    if header_type == 1
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && first_header_end_u64 < file_size
    {
        let second = inspect_rar5_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar5:second_header")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 1
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (first_header_end_u64 >= file_size
            || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar5_block(
    data: &[u8],
    offset: usize,
    file_size: u64,
) -> (bool, u64, u64, &'static str) {
    let Some(min_header_end) = offset.checked_add(6) else {
        return (false, 0, 0, "rar5_second_header_too_small");
    };
    if u64::try_from(offset).map_or(true, |value| value >= file_size)
        || data.len() < min_header_end
    {
        return (false, 0, 0, "rar5_second_header_too_small");
    }
    let Some(size_field_offset) = offset.checked_add(4) else {
        return (false, 0, 0, "rar5_second_header_size_vint_missing");
    };
    let Some((header_size, after_size)) = read_vint(data, size_field_offset) else {
        return (false, 0, 0, "rar5_second_header_size_vint_missing");
    };
    if after_size.saturating_sub(size_field_offset) > 3 {
        return (
            false,
            0,
            header_size,
            "rar5_second_header_size_vint_too_long",
        );
    }
    let Some((header_type, after_type)) = read_vint(data, after_size) else {
        return (
            false,
            0,
            header_size,
            "rar5_second_header_type_vint_missing",
        );
    };
    let Some((header_flags, _)) = read_vint(data, after_type) else {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_flags_vint_missing",
        );
    };
    if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_unknown_type",
        );
    }
    let Some((header_total_size, header_end_u64)) =
        checked_rar5_header_geometry(offset, after_size, header_size)
    else {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    };
    let Ok(header_end) = usize::try_from(header_end_u64) else {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    };
    if header_end_u64 > file_size || header_end > data.len() {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    }
    let Some(crc_start) = offset.checked_add(4) else {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    };
    if crc_start > header_end {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    }
    let stored_crc = u32_le(data, offset);
    let header_data = &data[crc_start..header_end];
    if crc32(header_data) != stored_crc {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_crc_mismatch",
        );
    }
    (true, header_type, header_total_size, "")
}

