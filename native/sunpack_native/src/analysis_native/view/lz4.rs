impl<'a> ReportContext<'a> {
    fn lz4_module(&mut self) -> io::Result<Option<Evidence>> {
        if self.stream_structure.is_none()
            && !crate::formats::lz4::leading(self.signatures.head.as_slice())
        {
            return Ok(None);
        }
        let Some(StreamStructure::Lz4 { end }) = self.full_stream_structure()? else {
            return Ok(None);
        };
        let mut evidence = Evidence::new("lz4", Extractable, 0, Some(end), Vec::new());
        evidence.structure_complete = true;
        Ok(Some(evidence))
    }
}
