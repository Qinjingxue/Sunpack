#[pymethods]
impl AnalysisMultiVolumeView {
    #[new]
    #[pyo3(signature = (paths, cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn new(
        paths: Vec<String>,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
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
                    pyo3::exceptions::PyValueError::new_err(
                        "multi-volume logical size overflow",
                    )
                })?;
        }

        let reader = ManagedReader::open_volumes(
            &paths,
            ReaderConfig {
                cache_bytes,
                max_read_bytes,
                max_concurrent_reads,
            },
        )?;
        Ok(Self {
            path: paths[0].clone(),
            reader,
            volume_starts,
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
        let data = self.read_at_bytes(offset, size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let view_size = self.reader.len();
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        let data = self.read_at_bytes(offset, read_size)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (eocd_offset, max_cd_entries_to_walk=64))]
    fn probe_zip(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
        max_cd_entries_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_zip_with_disk_starts(
            py,
            eocd_offset,
            max_cd_entries_to_walk,
            Some(&self.volume_starts),
        )
    }

    #[pyo3(signature = (start_offset, max_blocks_to_walk=4096))]
    fn probe_rar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_blocks_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_rar(py, start_offset, max_blocks_to_walk)
    }

    #[pyo3(signature = (start_offset, max_next_header_check_bytes=1048576))]
    fn probe_seven_zip(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_next_header_check_bytes: u64,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_seven_zip(py, start_offset, max_next_header_check_bytes)
    }

    #[pyo3(signature = (start_offset=0, max_entries_to_walk=64))]
    fn probe_tar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_entries_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_tar(py, start_offset, max_entries_to_walk)
    }

    fn probe_compression_stream(
        &self,
        py: Python<'_>,
        format: &str,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_compression_stream(py, format)
    }

    #[pyo3(signature = (format, max_probe_bytes=4194304))]
    fn probe_compressed_tar(
        &self,
        py: Python<'_>,
        format: &str,
        max_probe_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        AnalysisBinaryView {
            path: self.path.clone(),
            reader: self.reader.clone(),
            closed: self.closed,
        }
        .probe_compressed_tar(py, format, max_probe_bytes)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let stats = self.reader.stats()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", stats.read_bytes)?;
        dict.set_item("cache_hits", stats.cache_hits)?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (head_bytes=1048576, tail_bytes=1048576))]
    fn signature_prepass(
        &self,
        py: Python<'_>,
        head_bytes: usize,
        tail_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let size = self.reader.len();
        let head_len = head_bytes.min(size as usize);
        let tail_len = tail_bytes.min(size as usize);
        let tail_start = size.saturating_sub(tail_len as u64);
        let head_end = head_len as u64;
        let mut hits = Vec::new();
        let scanned_head = head_len;
        let scanned_tail = tail_len;

        if tail_start <= head_end {
            let data = self.read_at_bytes(0, size as usize)?;
            collect_signature_hits(&mut hits, 0, &data);
        } else {
            let mut ranges = self
                .reader
                .read_many(&[(0, head_len), (tail_start, tail_len)])
                .map_err(reader_error_to_py)?;
            let head = ranges.remove(0);
            collect_signature_hits(&mut hits, 0, &head);
            let tail = ranges.remove(0);
            collect_signature_hits(&mut hits, tail_start, &tail);
        }
        hits.sort_by_key(|(_, offset)| *offset);
        hits.dedup();

        let dict = PyDict::new(py);
        let py_hits = PyList::empty(py);
        let mut formats = Vec::new();
        for (name, offset) in hits {
            let hit = PyDict::new(py);
            hit.set_item("name", name)?;
            hit.set_item("offset", offset)?;
            py_hits.append(hit)?;
            let format = format_for_hit(name);
            if !formats.contains(&format) {
                formats.push(format);
            }
        }
        formats.sort();
        dict.set_item("hits", py_hits)?;
        dict.set_item("formats", formats)?;
        dict.set_item("head_bytes", scanned_head)?;
        dict.set_item("tail_bytes", scanned_tail)?;
        Ok(dict.unbind())
    }
}
