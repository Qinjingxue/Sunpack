#[pyclass]
pub(crate) struct AnalysisBinaryView {
    pub(crate) path: String,
    pub(crate) reader: ManagedReader,
    pub(crate) closed: bool,
}

#[pyclass]
pub(crate) struct AnalysisMultiVolumeView {
    view: AnalysisBinaryView,
    volume_starts: Vec<u64>,
}
