#[pymethods]
impl AnalysisMultiVolumeView {
    #[new]
    #[pyo3(signature = (paths, cache_bytes=67108864, max_concurrent_reads=1))]
    fn new(
        paths: Vec<String>,
        cache_bytes: usize,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let paths = paths
            .into_iter()
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "AnalysisMultiVolumeView requires at least one volume",
            ));
        }

        // Keep the physical-volume layout in Rust.  Format parsers consume a
        // single logical byte view and only ZIP needs disk-relative mapping.
        // Python must never reconstruct this layout or parse archive bytes.
        let mut volume_starts = Vec::with_capacity(paths.len());
        let mut logical_start = 0u64;
        for path in &paths {
            volume_starts.push(logical_start);
            logical_start = logical_start
                .checked_add(std::fs::metadata(path)?.len())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err("multi-volume logical size overflow")
                })?;
        }

        let reader = ManagedReader::open_volumes(
            &paths,
            ReaderConfig {
                cache_bytes,
                max_concurrent_reads,
            },
        )?;
        Ok(Self {
            view: AnalysisBinaryView {
                path: paths[0].clone(),
                reader,
                closed: false,
            },
            volume_starts,
        })
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        self.view.size()
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        self.view.path()
    }

    #[getter]
    fn closed(&self) -> bool {
        self.view.closed()
    }

    fn close(&mut self) {
        self.view.close();
        self.volume_starts = Vec::new();
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.view.read_at(py, offset, size)
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        self.view.read_tail(py, size)
    }

    fn probe_zip_local_header(&self, py: Python<'_>, offset: u64) -> PyResult<Py<PyDict>> {
        self.view.probe_zip_local_header_native(py, offset)
    }

    #[pyo3(signature = (eocd_offset=None))]
    fn locate_zip_eocd(&self, py: Python<'_>, eocd_offset: Option<u64>) -> PyResult<Py<PyDict>> {
        self.view.locate_zip_eocd_native(py, eocd_offset)
    }

    #[pyo3(signature = (eocd_offset))]
    fn probe_zip(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        self.view.probe_zip_with_disk_starts(
            py,
            eocd_offset,
            Some(&self.volume_starts),
        )
    }

    #[pyo3(signature = (start_offset))]
    fn probe_rar(
        &self,
        py: Python<'_>,
        start_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        self.view.probe_rar(py, start_offset)
    }

    #[pyo3(signature = (start_offset))]
    fn probe_seven_zip(
        &self,
        py: Python<'_>,
        start_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        self.view.probe_seven_zip(py, start_offset)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.view.stats(py)
    }

    #[pyo3(signature = (config, initial_prepass=None, format_structure=true))]
    fn analyze<'py>(
        &self,
        py: Python<'py>,
        config: PyRef<'py, NativeAnalysisConfig>,
        initial_prepass: Option<Bound<'py, PyDict>>,
        format_structure: bool,
    ) -> PyResult<Py<PyDict>> {
        self.view.analyze_report(
            py,
            &config,
            initial_prepass.as_ref(),
            format_structure,
            Some(&self.volume_starts),
        )
    }

    fn signature_prepass(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.view.signature_prepass(py)
    }
}
