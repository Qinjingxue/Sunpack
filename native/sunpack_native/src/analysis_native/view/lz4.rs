impl<'a> ReportContext<'a> {
    fn lz4_module(&mut self) -> io::Result<Evidence> {
        let rows = self.embedded("lz4", true);
        if !rows.is_empty() {
            let mut blocked = false;
            let segments = rows
                .into_iter()
                .map(|row| {
                    let error = row.lz4_index.as_ref().map_or("", |index| index.error);
                    let mut segment =
                        lz4_segment(row.offset, row.end_offset, row.extractable, error);
                    blocked |= !row.extractable;
                    segment.password_required = Some(false);
                    segment
                })
                .collect();
            return Ok(Evidence::new(
                "lz4",
                if blocked { "damaged" } else { "extractable" },
                segments,
                EvidenceDetails::Empty,
            ));
        }

        if self.stream_structure.is_none() {
            let Ok(prefix) = self.view.reader.read_cached_at(0, 4) else {
                return Ok(Evidence::not_found("lz4"));
            };
            if !crate::formats::lz4::leading(prefix.as_slice()) {
                return Ok(Evidence::not_found("lz4"));
            }
        }
        let Some(facts) = self.full_stream_structure()? else {
            return Ok(Evidence::not_found("lz4"));
        };
        if facts.format != "lz4"
            || (facts.stream_count == 0
                && matches!(
                    facts.error.as_str(),
                    "" | "lz4_magic_not_found"
                ))
        {
            return Ok(Evidence::not_found("lz4"));
        }
        let complete = facts.structure_complete;
        let segment = lz4_segment(
            0,
            facts.segment_end,
            complete,
            &facts.error,
        );
        Ok(Evidence::new(
            "lz4",
            if complete { "extractable" } else { "damaged" },
            vec![segment],
            EvidenceDetails::Stream(facts),
        ))
    }
}

fn lz4_segment(offset: u64, end: Option<u64>, complete: bool, error: &str) -> Segment {
    let flags = if error.is_empty() {
        Vec::new()
    } else {
        vec![error.to_owned()]
    };
    let mut segment = Segment::new(offset, end, flags);
    segment.extractable = complete;
    segment
}
