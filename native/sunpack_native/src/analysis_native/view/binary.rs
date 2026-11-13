impl AnalysisBinaryView {
    fn new(path: &str, cache_bytes: usize) -> io::Result<Self> {
        let reader = ManagedReader::open_with_config(path, ReaderConfig { cache_bytes })?;
        Ok(Self { reader })
    }
}
