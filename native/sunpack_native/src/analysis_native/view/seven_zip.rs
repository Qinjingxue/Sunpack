#[derive(Default)]
struct SevenZipObservation {
    declared_end: Option<u64>,
    // Only a validated next header can tell planning about a password.
    password_required: Option<bool>,
}

impl AnalysisBinaryView {
    fn probe_seven_zip_native(&self, header: &[u8]) -> io::Result<SevenZipObservation> {
        let mut result = SevenZipObservation::default();
        if header.len() < 32 || header[6] != 0 || u32_le(header, 8) != crc32(&header[12..32]) {
            return Ok(result);
        }
        let next_header_offset = u64_le(header, 12);
        let next_header_size = u64_le(header, 20);
        let next_header_crc = u32_le(header, 28);
        let Some(next_header_start) = 32u64.checked_add(next_header_offset) else {
            return Ok(result);
        };
        let Some(segment_end) = next_header_start.checked_add(next_header_size) else {
            return Ok(result);
        };
        result.declared_end = Some(segment_end);
        if (next_header_size == 0 && next_header_offset != 0) || segment_end > self.reader.len() {
            return Ok(result);
        }

        // Spill large headers for shared encryption-fact parsing without
        // allocating the whole declared range on the heap.
        use std::io::Write;
        let mut next_header = crate::io::scratch::Spool::default();
        let mut hash = crc32fast::Hasher::new();
        let mut offset = next_header_start;
        while offset < segment_end {
            let length = (segment_end - offset).min(64 * 1024) as usize;
            let bytes = self.reader.read_cached_at(offset, length)?;
            if bytes.len() != length {
                return Ok(result);
            }
            hash.update(&bytes);
            next_header.write_all(&bytes)?;
            offset += length as u64;
        }
        let next_header = next_header.finish()?;
        if hash.finalize() == next_header_crc
            && next_header
                .first()
                .is_none_or(|nid| matches!(nid, 0x01 | 0x17))
        {
            let facts = crate::formats::seven_zip::seven_zip_encryption_facts_from_next_header(
                &next_header,
            );
            result.password_required = Some(facts.password_required);
        }
        Ok(result)
    }
}
