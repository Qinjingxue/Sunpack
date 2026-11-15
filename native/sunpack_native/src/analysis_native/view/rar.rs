impl AnalysisBinaryView {
    fn rar4_end(&self) -> io::Result<Option<u64>> {
        let start = RAR4.len() as u64;
        let size = self.reader.len();
        let mut cursor = start;
        while cursor.saturating_add(7) <= size {
            let fixed = self.reader.read_cached_at(cursor, 7)?;
            if fixed.len() != 7 {
                return Ok(None);
            }
            let header_type = fixed[2];
            let header_flags = u16_le(&fixed, 3);
            let header_size = u16_le(&fixed, 5) as u64;
            if !matches!(header_type, 0x72..=0x7b)
                || header_size < 7
                || cursor.saturating_add(header_size) > size
                || (cursor == start && (header_type != 0x73 || header_flags & 0x0080 != 0))
            {
                // Encrypted headers are resolved by discovery and password probing.
                return Ok(None);
            }
            let full_header = self.reader.read_cached_at(cursor, header_size as usize)?;
            if full_header.len() != header_size as usize
                || (crc32(&full_header[2..]) & 0xffff) != u16_le(&fixed, 0) as u32
            {
                return Ok(None);
            }
            let Some(data_size) = crate::formats::rar::rar4_data_size(&full_header) else {
                return Ok(None);
            };
            cursor = cursor.saturating_add(header_size).saturating_add(data_size);
            if cursor > size {
                return Ok(None);
            }
            if header_type == 0x7b {
                return Ok(Some(cursor));
            }
        }
        Ok(None)
    }

    fn rar5_end(&self) -> io::Result<Option<u64>> {
        let start = RAR5.len() as u64;
        let size = self.reader.len();
        let mut cursor = start;
        while cursor.saturating_add(6) <= size {
            let prefix = self.reader.read_cached_at(cursor, 64)?;
            let Some((header_size, after_size)) = read_vint(&prefix, 4) else {
                return Ok(None);
            };
            if after_size - 4 > 3 || header_size == 0 {
                return Ok(None);
            }
            let header_total_size = after_size as u64 + header_size;
            if cursor.saturating_add(header_total_size) > size {
                return Ok(None);
            }
            let full_header;
            let full = if let Some(bytes) = prefix.get(..header_total_size as usize) {
                bytes
            } else {
                full_header = self
                    .reader
                    .read_cached_at(cursor, header_total_size as usize)?;
                if full_header.len() != header_total_size as usize {
                    return Ok(None);
                }
                &full_header[..]
            };
            let Some((header_type, after_type)) = read_vint(full, after_size) else {
                return Ok(None);
            };
            let Some((header_flags, mut field_cursor)) = read_vint(full, after_type) else {
                return Ok(None);
            };
            if (!matches!(header_type, 1..=5) && header_flags & 0x0004 == 0)
                || (cursor == start && header_type != 1)
                || crc32(&full[4..]) != u32_le(full, 0)
            {
                return Ok(None);
            }
            if header_flags & 0x0001 != 0 {
                let Some((_, after_extra)) = read_vint(full, field_cursor) else {
                    return Ok(None);
                };
                field_cursor = after_extra;
            }
            let data_size = if header_flags & 0x0002 != 0 {
                let Some((value, _)) = read_vint(full, field_cursor) else {
                    return Ok(None);
                };
                value
            } else {
                0
            };
            cursor = cursor
                .saturating_add(header_total_size)
                .saturating_add(data_size);
            if cursor > size {
                return Ok(None);
            }
            if header_type == 5 {
                return Ok(Some(cursor));
            }
        }
        Ok(None)
    }
}
