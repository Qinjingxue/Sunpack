const TAR_FIELDS: &[&str] = &[
    "member.header.name",
    "member.header.mode",
    "member.header.uid_gid",
    "member.header.size",
    "member.header.mtime",
    "member.header.checksum",
    "member.header.typeflag",
    "member.header.linkname",
    "member.header.magic_version",
    "member.header.prefix",
    "member.payload.span",
    "member.payload.data",
    "member.padding",
    "member.next_header",
    "pax.header.length",
    "pax.header.records",
    "pax.target_member",
    "gnu.longname",
    "gnu.target_member",
    "sparse.map",
    "sparse.payload",
    "archive.end_zero_blocks",
    "archive.trailing_data",
];

fn parse_pax_records(payload: &[u8]) -> Result<Vec<(String, String, usize)>, &'static str> {
    let mut records = Vec::new();
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let Some(space_rel) = payload[cursor..].iter().position(|byte| *byte == b' ') else {
            return Err("pax_record_length_missing");
        };
        let space = cursor + space_rel;
        let length_text = std::str::from_utf8(&payload[cursor..space])
            .map_err(|_| "pax_record_length_not_ascii")?;
        if length_text.is_empty() || !length_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("pax_record_length_invalid");
        }
        let length = length_text.parse::<usize>().map_err(|_| "pax_record_length_overflow")?;
        if length == 0 || cursor.checked_add(length).map_or(true, |end| end > payload.len()) {
            return Err("pax_record_out_of_range");
        }
        let end = cursor + length;
        if payload[end - 1] != b'\n' || space + 1 >= end - 1 {
            return Err("pax_record_terminator_invalid");
        }
        let record = std::str::from_utf8(&payload[space + 1..end - 1])
            .map_err(|_| "pax_record_not_utf8")?;
        let Some((key, value)) = record.split_once('=') else {
            return Err("pax_record_assignment_missing");
        };
        if key.is_empty() {
            return Err("pax_record_keyword_empty");
        }
        records.push((key.to_string(), value.to_string(), length));
        cursor = end;
    }
    Ok(records)
}

fn validate_sparse_map(value: &str) -> bool {
    let fields = value.split(',').collect::<Vec<_>>();
    if fields.is_empty() || fields.len() % 2 != 0 {
        return false;
    }
    let mut previous_end = 0u64;
    for pair in fields.chunks_exact(2) {
        let Ok(offset) = pair[0].parse::<u64>() else { return false; };
        let Ok(length) = pair[1].parse::<u64>() else { return false; };
        let Some(end) = offset.checked_add(length) else { return false; };
        if offset < previous_end {
            return false;
        }
        previous_end = end;
    }
    true
}

fn validate_oldgnu_sparse_block(
    block: &[u8],
    start: usize,
    count: usize,
    previous_end: &mut u64,
) -> bool {
    for index in 0..count {
        let base = start + index * 24;
        let Some(offset) = parse_octal(&block[base..base + 12]) else { return false; };
        let Some(length) = parse_octal(&block[base + 12..base + 24]) else { return false; };
        if offset == 0 && length == 0 {
            continue;
        }
        let Some(end) = offset.checked_add(length) else { return false; };
        if offset < *previous_end {
            return false;
        }
        *previous_end = end;
    }
    true
}

fn tar_text(value: &[u8]) -> String {
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).trim().to_string()
}

fn enrich_tar_semantics(
    d: &Bound<'_, PyDict>,
    file: &mut SourceCursor,
    archive_start: u64,
    archive_end: u64,
    max_entries: usize,
) -> PyResult<()> {
    let mut offset = archive_start;
    let mut entries = 0usize;
    let mut zeros = 0usize;
    let mut pax_lengths = Vec::new();
    let mut pax_records = Vec::new();
    let mut gnu_longname = None::<String>;
    let mut gnu_longlink = None::<String>;
    let mut sparse = Vec::new();
    let mut semantic_flags = Vec::new();
    let limit = max_entries.max(1);
    while entries < limit && offset + TAR_BLOCK_SIZE as u64 <= archive_end {
        let mut header = [0u8; TAR_BLOCK_SIZE];
        if let Err(fault) = seek_field(
            file,
            offset,
            archive_end,
            "tar.member.header",
            FieldLocation::Body,
        )
        .and_then(|_| {
            read_exact_field(
                file,
                &mut header,
                archive_end,
                "tar.member.header",
                FieldLocation::Body,
            )
        }) {
            set_read_fault(d, &fault, "member_header_read_failed")?;
            return Ok(());
        }
        if header.iter().all(|b| *b == 0) {
            zeros += 1;
            offset += TAR_BLOCK_SIZE as u64;
            if zeros >= 2 {
                break;
            }
            continue;
        }
        zeros = 0;
        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let padding = padding_for_size(size);
        let typeflag = header[156];
        let mut sparse_extension_span = 0u64;
        if typeflag == b'S' {
            let mut previous_end = 0u64;
            let mut extended = header[482] != 0 && header[482] != b'0';
            let mut sparse_invalid = false;
            if !validate_oldgnu_sparse_block(&header, 386, 4, &mut previous_end) {
                semantic_flags.push("sparse_header_bad");
                break;
            }
            while extended {
                let extension_offset = offset + TAR_BLOCK_SIZE as u64 + sparse_extension_span;
                let mut extension = [0u8; TAR_BLOCK_SIZE];
                if let Err(fault) = seek_field(
                    file,
                    extension_offset,
                    archive_end,
                    "tar.gnu_sparse.extension",
                    FieldLocation::Body,
                ).and_then(|_| read_exact_field(
                    file,
                    &mut extension,
                    archive_end,
                    "tar.gnu_sparse.extension",
                    FieldLocation::Body,
                )) {
                    set_read_fault(d, &fault, "invalid_oldgnu_sparse_extension")?;
                    semantic_flags.push("sparse_header_bad");
                    sparse_invalid = true;
                    break;
                }
                if !validate_oldgnu_sparse_block(&extension, 0, 21, &mut previous_end) {
                    semantic_flags.push("sparse_header_bad");
                    sparse_invalid = true;
                    break;
                }
                sparse_extension_span += TAR_BLOCK_SIZE as u64;
                extended = extension[504] != 0 && extension[504] != b'0';
            }
            if parse_octal(&header[483..495]).is_some_and(|real_size| previous_end > real_size) {
                semantic_flags.push("sparse_header_bad");
                sparse_invalid = true;
            }
            if sparse_invalid {
                break;
            }
        }
        let payload_start = offset + TAR_BLOCK_SIZE as u64 + sparse_extension_span;
        let next = payload_start.saturating_add(size).saturating_add(padding);
        if entries == 0 {
            let stored = parse_octal(&header[148..156]).unwrap_or(0);
            d.set_item("member.header.name", tar_text(&header[0..100]))?;
            d.set_item(
                "member.header.mode",
                parse_octal(&header[100..108]).unwrap_or(0),
            )?;
            d.set_item(
                "member.header.uid_gid",
                format!(
                    "uid={};gid={}",
                    parse_octal(&header[108..116]).unwrap_or(0),
                    parse_octal(&header[116..124]).unwrap_or(0)
                ),
            )?;
            d.set_item("member.header.size", size)?;
            d.set_item(
                "member.header.mtime",
                parse_octal(&header[136..148]).unwrap_or(0),
            )?;
            d.set_item(
                "member.header.checksum",
                format!(
                    "stored={stored};computed={};ok={}",
                    tar_checksum(&header),
                    stored == tar_checksum(&header)
                ),
            )?;
            d.set_item("member.header.typeflag", typeflag as char as u32)?;
            d.set_item("member.header.linkname", tar_text(&header[157..257]))?;
            d.set_item(
                "member.header.magic_version",
                format!(
                    "magic={};version={}",
                    tar_text(&header[257..263]),
                    tar_text(&header[263..265])
                ),
            )?;
            d.set_item("member.header.prefix", tar_text(&header[345..500]))?;
            d.set_item(
                "member.payload.span",
                format!("offset={payload_start};size={size}"),
            )?;
            d.set_item(
                "member.payload.data",
                format!("bytes={size};available={}", next <= archive_end),
            )?;
            d.set_item("member.padding", padding)?;
            d.set_item("member.next_header", next <= archive_end)?;
        }
        if next > archive_end {
            break;
        }
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K' | b'S') && size <= 4 * 1024 * 1024 {
            let mut payload = vec![0u8; size as usize];
            if let Err(fault) = seek_field(
                file,
                payload_start,
                archive_end,
                "tar.member.payload",
                FieldLocation::Body,
            )
            .and_then(|_| {
                read_exact_field(
                    file,
                    &mut payload,
                    archive_end,
                    "tar.member.payload",
                    FieldLocation::Body,
                )
            }) {
                set_read_fault(d, &fault, "member_payload_read_failed")?;
                return Ok(());
            }
            if matches!(typeflag, b'x' | b'g') {
                match parse_pax_records(&payload) {
                    Ok(records) => for (key, value, length) in records {
                        pax_lengths.push(length as u64);
                        pax_records.push(format!("{}:{}={}", typeflag as char, key, value));
                        if key.starts_with("GNU.sparse.") {
                            if key == "GNU.sparse.map" && !validate_sparse_map(&value) {
                                semantic_flags.push("sparse_header_bad");
                            }
                            sparse.push(format!("{key}={value}"));
                        }
                    },
                    Err(error) => {
                        pax_records.push(format!("invalid:{error}"));
                        semantic_flags.push("pax_header_bad");
                    }
                }
            } else if typeflag == b'L' {
                gnu_longname = Some(tar_text(&payload));
            } else if typeflag == b'K' {
                gnu_longlink = Some(tar_text(&payload));
            } else if typeflag == b'S' {
                sparse.push(format!("gnu_sparse_header_at={offset}"));
            }
        }
        entries += 1;
        offset = next;
    }
    d.set_item(
        "pax.header.length",
        if pax_lengths.is_empty() {
            "absent".into()
        } else {
            pax_lengths.iter().sum::<u64>().to_string()
        },
    )?;
    d.set_item(
        "pax.header.records",
        if pax_records.is_empty() {
            "absent".into()
        } else {
            pax_records.join(";")
        },
    )?;
    d.set_item(
        "pax.target_member",
        if pax_records.is_empty() {
            "absent".to_string()
        } else if pax_records.iter().any(|record| record.starts_with("g:"))
            && pax_records.iter().any(|record| record.starts_with("x:"))
        {
            "global_and_next_member".to_string()
        } else if pax_records.iter().any(|record| record.starts_with("g:")) {
            "all_following_members".to_string()
        } else {
            "next_member".to_string()
        },
    )?;
    d.set_item(
        "gnu.longname",
        match (&gnu_longname, &gnu_longlink) {
            (None, None) => "absent".into(),
            (name, link) => format!(
                "path={};linkpath={}",
                name.as_deref().unwrap_or("absent"),
                link.as_deref().unwrap_or("absent")
            ),
        },
    )?;
    d.set_item(
        "gnu.target_member",
        if gnu_longname.is_some() || gnu_longlink.is_some() {
            "next_member"
        } else {
            "absent"
        },
    )?;
    d.set_item(
        "sparse.map",
        if sparse.is_empty() {
            "absent".into()
        } else {
            sparse.join(";")
        },
    )?;
    d.set_item(
        "sparse.payload",
        if sparse.is_empty() {
            "absent"
        } else {
            "sparse_extents_in_member_payload"
        },
    )?;
    d.set_item("archive.end_zero_blocks", zeros)?;
    let walk_budget_exhausted = entries >= limit
        && zeros < 2
        && offset + TAR_BLOCK_SIZE as u64 <= archive_end;
    let zero_fill = if walk_budget_exhausted { 0 } else { archive_end.saturating_sub(offset) };
    let mut remaining = zero_fill;
    let mut scan_offset = offset;
    let mut nonzero_tail = false;
    let mut first_nonzero_tail = None;
    let mut buffer = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        if let Err(fault) = seek_field(
            file,
            scan_offset,
            archive_end,
            "tar.archive.end_zero_blocks",
            FieldLocation::Tail,
        )
        .and_then(|_| {
            read_exact_field(
                file,
                &mut buffer[..length],
                archive_end,
                "tar.archive.end_zero_blocks",
                FieldLocation::Tail,
            )
        }) {
            set_read_fault(d, &fault, "archive_tail_read_failed")?;
            return Ok(());
        }
        if let Some(index) = buffer[..length].iter().position(|byte| *byte != 0) {
            nonzero_tail = true;
            first_nonzero_tail = Some(scan_offset + index as u64);
            break;
        }
        scan_offset += length as u64;
        remaining -= length as u64;
    }
    let concatenated_offset = first_nonzero_tail.map(|position| position / 512 * 512);
    let concatenated_archive = if zeros >= 2 {
        if let Some(candidate_offset) = concatenated_offset {
            if candidate_offset + TAR_BLOCK_SIZE as u64 <= archive_end {
                let mut candidate = [0u8; TAR_BLOCK_SIZE];
                seek_field(file, candidate_offset, archive_end, "tar.concatenated.header", FieldLocation::Tail)
                    .and_then(|_| read_exact_field(
                        file,
                        &mut candidate,
                        archive_end,
                        "tar.concatenated.header",
                        FieldLocation::Tail,
                    ))
                    .is_ok()
                    && tar_header_plausible(&candidate).0
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    let trailing = if nonzero_tail && !concatenated_archive { zero_fill } else { 0 };
    d.set_item("archive.concatenated", concatenated_archive)?;
    d.set_item(
        "archive.concatenated_offset",
        if concatenated_archive { concatenated_offset } else { None },
    )?;
    d.set_item(
        "archive.zero_fill_after_end",
        if nonzero_tail { 0 } else { zero_fill },
    )?;
    d.set_item("archive.trailing_data", trailing)?;
    let mut flags = semantic_flags;
    if zeros < 2 && !walk_budget_exhausted {
        flags.push("missing_end_block");
    }
    if zeros >= 2 && trailing > 0 {
        flags.push("trailing_junk");
    }
    d.set_item("damage_flags", PyList::new(d.py(), flags)?)?;
    d.set_item("walk_budget_exhausted", walk_budget_exhausted)?;
    finish_fields(d, TAR_FIELDS)?;
    Ok(())
}

fn tar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("format", "")?;
    for key in [
        "stored_checksum",
        "computed_checksum",
        "file_size",
        "member_size",
        "entries_checked",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "ustar_magic",
        "zero_block",
        "entry_walk_ok",
        "end_zero_blocks",
        "fuzzy_name_nonempty",
        "fuzzy_numeric_fields_valid",
        "fuzzy_typeflag_valid",
        "fuzzy_payload_in_range",
    ] {
        d.set_item(key, false)?;
    }
    Ok(d)
}

fn walk_tar(
    file: &mut SourceCursor,
    archive_start: u64,
    archive_end: u64,
    max_entries: usize,
) -> Result<(usize, bool, bool, &'static str), ReadFault> {
    if max_entries == 0 {
        return Ok((0, false, false, ""));
    }
    let mut offset = archive_start;
    let mut zero_blocks = 0usize;
    let mut checked = 0usize;
    while checked < max_entries && offset + TAR_BLOCK_SIZE as u64 <= archive_end {
        let mut header = vec![0; TAR_BLOCK_SIZE];
        seek_field(
            file,
            offset,
            archive_end,
            "tar.member.header",
            FieldLocation::Body,
        )?;
        read_exact_field(
            file,
            &mut header,
            archive_end,
            "tar.member.header",
            FieldLocation::Body,
        )?;
        if header.iter().all(|b| *b == 0) {
            zero_blocks += 1;
            offset += TAR_BLOCK_SIZE as u64;
            if zero_blocks >= 2 {
                return Ok((checked, checked > 0, true, ""));
            }
            continue;
        }
        zero_blocks = 0;
        let (ok, error, member_size, _) = tar_header_plausible(&header);
        if !ok {
            return Ok((checked, false, false, error));
        }
        let mut sparse_extension_span = 0u64;
        if header[156] == b'S' {
            let mut previous_end = 0u64;
            let mut extended = header[482] != 0 && header[482] != b'0';
            if !validate_oldgnu_sparse_block(&header, 386, 4, &mut previous_end) {
                return Ok((checked, false, false, "invalid_oldgnu_sparse_map"));
            }
            while extended {
                let extension_offset = offset + TAR_BLOCK_SIZE as u64 + sparse_extension_span;
                let mut extension = [0u8; TAR_BLOCK_SIZE];
                seek_field(
                    file,
                    extension_offset,
                    archive_end,
                    "tar.gnu_sparse.extension",
                    FieldLocation::Body,
                )?;
                read_exact_field(
                    file,
                    &mut extension,
                    archive_end,
                    "tar.gnu_sparse.extension",
                    FieldLocation::Body,
                )?;
                if !validate_oldgnu_sparse_block(&extension, 0, 21, &mut previous_end) {
                    return Ok((checked, false, false, "invalid_oldgnu_sparse_extension"));
                }
                sparse_extension_span += TAR_BLOCK_SIZE as u64;
                extended = extension[504] != 0 && extension[504] != b'0';
            }
            if parse_octal(&header[483..495]).is_some_and(|real_size| previous_end > real_size) {
                return Ok((checked, false, false, "oldgnu_sparse_extent_out_of_range"));
            }
        }
        // Base-256 size fields can encode values near u64::MAX; saturate so a
        // crafted size lands out of range instead of wrapping back into the file.
        let next_offset = offset
            .saturating_add(TAR_BLOCK_SIZE as u64)
            .saturating_add(sparse_extension_span)
            .saturating_add(member_size)
            .saturating_add(padding_for_size(member_size));
        if next_offset > archive_end {
            return Ok((checked, false, false, "member_payload_out_of_range"));
        }
        checked += 1;
        offset = next_offset;
    }
    Ok((checked, checked > 0, false, ""))
}

fn tar_header_plausible(header: &[u8]) -> (bool, &'static str, u64, bool) {
    if header.len() < TAR_BLOCK_SIZE {
        return (false, "short_header", 0, false);
    }
    if header.iter().all(|b| *b == 0) {
        return (false, "zero_block", 0, false);
    }
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    if stored_checksum.is_none() {
        return (false, "invalid_checksum_field", 0, false);
    }
    if member_size.is_none() {
        return (false, "invalid_size_field", 0, false);
    }
    if stored_checksum.unwrap() != tar_checksum(header) {
        return (false, "checksum_mismatch", member_size.unwrap(), false);
    }
    (
        true,
        "",
        member_size.unwrap(),
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )
}

#[cfg(test)]
mod tar_walk_tests {
    use super::*;
    use crate::io::reader::ReaderConfig;

    fn header_with_base256_size(size: u64) -> [u8; TAR_BLOCK_SIZE] {
        let mut header = [0u8; TAR_BLOCK_SIZE];
        header[..4].copy_from_slice(b"file");
        header[124] = 0x80;
        header[128..136].copy_from_slice(&size.to_be_bytes());
        header[156] = b'0';
        let checksum = format!("{:06o}\0 ", tar_checksum(&header));
        header[148..156].copy_from_slice(checksum.as_bytes());
        header
    }

    #[test]
    fn huge_base256_member_size_is_out_of_range_instead_of_wrapping() {
        // offset(0) + 512 + (2^64 - 512) wraps to 0 without saturation, which
        // would re-walk the same header and report a valid archive.
        let mut data = header_with_base256_size(u64::MAX - 511).to_vec();
        data.extend_from_slice(&[0u8; TAR_BLOCK_SIZE * 2]);
        let archive_end = data.len() as u64;
        let reader = ManagedReader::from_bytes(data, ReaderConfig::default());
        let mut cursor = reader.cursor();

        let (checked, walk_ok, _, error) = walk_tar(&mut cursor, 0, archive_end, 8).unwrap();

        assert_eq!(checked, 0);
        assert!(!walk_ok);
        assert_eq!(error, "member_payload_out_of_range");
    }
}
