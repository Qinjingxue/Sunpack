impl<'a> ReportContext<'a> {
    fn lz4_module(&mut self) -> io::Result<Option<Evidence>> {
        if self.stream_structure.is_none()
            && !crate::formats::lz4::leading(self.signatures.head.as_slice())
        {
            return Ok(None);
        }
        let Some(facts) = self.full_stream_structure()? else {
            return Ok(None);
        };
        if facts.format != "lz4"
            || !facts.structure_complete
            || (facts.stream_count == 0
                && matches!(facts.error.as_str(), "" | "lz4_magic_not_found"))
        {
            return Ok(None);
        }
        let flags = if !facts.error.is_empty()
            && strict_subrange(0, facts.segment_end, self.view.reader.len())
        {
            vec![facts.error.clone()]
        } else {
            Vec::new()
        };
        let mut evidence = Evidence::new("lz4", Extractable, 0, facts.segment_end, flags);
        evidence.structure_complete = true;
        Ok(Some(evidence))
    }
}
