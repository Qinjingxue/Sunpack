impl AnalysisBinaryView {
    fn new(path: &str, cache_bytes: usize) -> io::Result<Self> {
        let reader = ManagedReader::open_with_config(path, ReaderConfig { cache_bytes })?;
        Ok(Self { reader })
    }

    fn analyze(
        &self,
        config: &NativeAnalysisConfig,
        initial_prepass: Option<&crate::scan::embedded::NativeScanResult>,
        format_structure: bool,
    ) -> io::Result<AnalysisReport> {
        self.analyze_report(config, initial_prepass, format_structure, None)
    }
}
