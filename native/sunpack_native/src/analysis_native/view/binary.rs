#[pymethods]
impl AnalysisBinaryView {
    #[new]
    #[pyo3(signature = (path, cache_bytes=67108864, max_concurrent_reads=1))]
    fn new(
        path: String,
        cache_bytes: usize,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let reader = ManagedReader::open_with_config(
            &path,
            ReaderConfig {
                cache_bytes,
                max_concurrent_reads,
            },
        )?;
        Ok(Self {
            path,
            reader,
            closed: false,
        })
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        self.ensure_open()?;
        Ok(self.reader.len())
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    #[getter]
    fn closed(&self) -> bool {
        self.closed
    }

    fn close(&mut self) {
        if !self.closed {
            self.reader = ManagedReader::closed();
            self.closed = true;
        }
    }

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.read_at_bytes_detached(py, offset, size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let view_size = self.reader.len();
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        let data = self.read_at_bytes_detached(py, offset, read_size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn probe_zip_local_header(&self, py: Python<'_>, offset: u64) -> PyResult<Py<PyDict>> {
        self.probe_zip_local_header_native(py, offset)
    }

    #[pyo3(signature = (eocd_offset=None))]
    fn locate_zip_eocd(&self, py: Python<'_>, eocd_offset: Option<u64>) -> PyResult<Py<PyDict>> {
        self.locate_zip_eocd_native(py, eocd_offset)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let stats = self.reader.stats()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", stats.read_bytes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (eocd_offset))]
    fn probe_zip(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        self.probe_zip_with_disk_starts(py, eocd_offset, None)
    }

    #[pyo3(signature = (start_offset))]
    fn probe_rar(
        &self,
        py: Python<'_>,
        start_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        py.detach(|| self.probe_rar_native(start_offset))?
            .to_python(py)
    }

    #[pyo3(signature = (start_offset))]
    pub(crate) fn probe_seven_zip(
        &self,
        py: Python<'_>,
        start_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        py.detach(|| self.probe_seven_zip_native(start_offset))?
            .to_python(py)
    }

    #[pyo3(signature = (start_offset=0))]
    fn probe_tar(
        &self,
        py: Python<'_>,
        start_offset: u64,
    ) -> PyResult<Py<PyDict>> {
        let result = self.walk_tar(py, start_offset)?;
        Ok(result.unbind())
    }

    fn probe_compression_stream(&self, py: Python<'_>, format: &str) -> PyResult<Py<PyDict>> {
        let result = self.probe_compression(py, format)?;
        Ok(result.unbind())
    }

    #[pyo3(signature = (format, max_probe_bytes=4194304))]
    fn probe_compressed_tar(
        &self,
        py: Python<'_>,
        format: &str,
        max_probe_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let stream = self.probe_compression(py, format)?;
        stream.set_item("container", format)?;
        stream.set_item("inner_format", "tar")?;
        stream.set_item("inner_tar_verified", false)?;
        stream.set_item("tar_plausible", false)?;
        stream.set_item("tar_probe_error", "")?;
        if !stream
            .get_item("magic_matched")?
            .unwrap()
            .extract::<bool>()?
        {
            return Ok(stream.unbind());
        }
        let input_budget = self.reader.len().min(max_probe_bytes as u64);
        let source = self.reader.stream_cursor().take(input_budget);
        match py.detach(|| decompress_sample(format, source, TAR_BLOCK_SIZE * 2)) {
            Ok(sample) => {
                if sample.len() < TAR_BLOCK_SIZE {
                    stream.set_item("tar_probe_error", "inner_sample_too_small")?;
                    return Ok(stream.unbind());
                }
                let (ok, error, member_size, ustar) =
                    tar_header_plausible(&sample[..TAR_BLOCK_SIZE]);
                stream.set_item("inner_tar_verified", ok)?;
                stream.set_item("tar_plausible", ok)?;
                stream.set_item("tar_probe_error", error)?;
                stream.set_item("inner_tar_member_size", member_size)?;
                stream.set_item("inner_tar_ustar", ustar)?;
            }
            Err(error) => {
                stream.set_item("tar_probe_error", error)?;
            }
        }
        Ok(stream.unbind())
    }

    #[pyo3(signature = (config, initial_prepass=None, signature_prepass=true, format_structure=true))]
    fn analyze<'py>(
        &self,
        py: Python<'py>,
        config: PyRef<'py, NativeAnalysisConfig>,
        initial_prepass: Option<Bound<'py, PyDict>>,
        signature_prepass: bool,
        format_structure: bool,
    ) -> PyResult<Py<PyDict>> {
        self.analyze_report(
            py,
            &config,
            initial_prepass.as_ref(),
            signature_prepass,
            format_structure,
            None,
            Some(&self.path),
        )
    }

    #[pyo3(signature = (head_bytes=1048576, tail_bytes=1048576))]
    fn signature_prepass(
        &self,
        py: Python<'_>,
        head_bytes: usize,
        tail_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let data = py
            .detach(|| signature_prepass_native(&self.reader, head_bytes, tail_bytes))
            .map_err(reader_error_to_py)?;
        signature_prepass_to_python(py, data)
    }
}
