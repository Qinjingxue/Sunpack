// Compact immutable rows remain native across report reuse. Python only creates
// a dictionary for a row explicitly inspected by a caller.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SignatureHit {
    offset: [u8; 8],
    pattern: u8,
}

impl SignatureHit {
    fn new(pattern: usize, offset: u64) -> Self {
        Self {
            offset: offset.to_ne_bytes(),
            pattern: pattern as u8,
        }
    }

    fn name(&self) -> &'static str {
        ANALYSIS_SIGNATURES[self.pattern as usize].0
    }
    fn offset(&self) -> u64 {
        u64::from_ne_bytes(self.offset)
    }
}

#[pyclass(frozen, module = "sunpack_native")]
struct NativeSignatureHits {
    rows: Arc<[SignatureHit]>,
}

#[pymethods]
impl NativeSignatureHits {
    fn __len__(&self) -> usize {
        self.rows.len()
    }

    fn __getitem__(&self, py: Python<'_>, index: isize) -> PyResult<Py<PyDict>> {
        let index = if index < 0 {
            self.rows.len() as isize + index
        } else {
            index
        };
        let row = usize::try_from(index)
            .ok()
            .and_then(|index| self.rows.get(index))
            .ok_or_else(|| {
                pyo3::exceptions::PyIndexError::new_err("signature hit index out of range")
            })?;
        let hit = PyDict::new(py);
        hit.set_item("name", row.name())?;
        hit.set_item("offset", row.offset())?;
        Ok(hit.unbind())
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .cast::<Self>()
            .is_ok_and(|other| self.rows == other.get().rows)
    }

    fn __deepcopy__(slf: Py<Self>, _memo: &Bound<'_, PyAny>) -> Py<Self> {
        slf
    }
}

fn signature_hits_from_prepass(prepass: &Bound<'_, PyDict>) -> PyResult<Arc<[SignatureHit]>> {
    if let Some(hits) = prepass.get_item("hits")? {
        if let Ok(hits) = hits.cast::<NativeSignatureHits>() {
            return Ok(Arc::clone(&hits.get().rows));
        }
    }
    // Full embedded scans already project only validated roots. Accept their
    // small dictionaries without expanding native prepass rows back to Python.
    let mut rows = Vec::new();
    for hit in prepass_dicts(prepass, "hits")? {
        let name = str_of(&hit, "name")?;
        let pattern = ANALYSIS_SIGNATURES
            .iter()
            .position(|(item, _)| *item == name)
            .or_else(|| {
                name.starts_with("zip_")
                    .then_some(ANALYSIS_SIGNATURES.len() - 1)
            });
        if let Some(pattern) = pattern {
            rows.push(SignatureHit::new(pattern, u64_of(&hit, "offset")?));
        }
    }
    Ok(rows.into())
}

struct SignaturePrepassData {
    hits: Arc<[SignatureHit]>,
    formats: Vec<&'static str>,
    scanned_head: usize,
    scanned_tail: usize,
}

fn signature_prepass_native(
    reader: &ManagedReader,
    head_bytes: usize,
    tail_bytes: usize,
) -> io::Result<SignaturePrepassData> {
    let size = reader.len();
    let head_len = head_bytes.min(size as usize);
    let tail_len = tail_bytes.min(size as usize);
    let tail_start = size.saturating_sub(tail_len as u64);
    let mut hits = Vec::new();
    if tail_start <= head_len as u64 {
        let data = reader.read_cached_at(0, size as usize)?;
        collect_signature_hits(&mut hits, 0, data.as_slice());
    } else {
        let ranges = reader.read_many(&[(0, head_len), (tail_start, tail_len)])?;
        collect_signature_hits(&mut hits, 0, &ranges[0]);
        collect_signature_hits(&mut hits, tail_start, &ranges[1]);
    }
    hits.sort_unstable_by_key(|hit| (hit.offset(), hit.pattern));
    hits.dedup();
    let mut formats = Vec::new();
    for hit in &hits {
        let format = format_for_hit(hit.name());
        if !formats.contains(&format) {
            formats.push(format);
        }
    }
    formats.sort_unstable();
    Ok(SignaturePrepassData {
        hits: hits.into(),
        formats,
        scanned_head: head_len,
        scanned_tail: tail_len,
    })
}

fn signature_prepass_to_python(py: Python<'_>, data: SignaturePrepassData) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item(
        "hits",
        Py::new(py, NativeSignatureHits { rows: data.hits })?,
    )?;
    dict.set_item("formats", data.formats)?;
    dict.set_item("head_bytes", data.scanned_head)?;
    dict.set_item("tail_bytes", data.scanned_tail)?;
    Ok(dict.unbind())
}

fn collect_signature_hits(target: &mut Vec<SignatureHit>, base: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    for (pattern, &(_name, signature)) in ANALYSIS_SIGNATURES.iter().enumerate() {
        let Some(signature) = signature else { continue };
        let finder = memchr::memmem::Finder::new(signature);
        let mut start = 0;
        while let Some(index) = finder.find(&data[start..]) {
            let index = start + index;
            target.push(SignatureHit::new(pattern, base + index as u64));
            // Keep overlaps; the caller orders and deduplicates once.
            start = index + 1;
        }
    }
}

fn format_for_hit(name: &str) -> &'static str {
    if name.starts_with("zip_") {
        "zip"
    } else if name.starts_with("rar") {
        "rar"
    } else if name == "7z" {
        "7z"
    } else if name == "tar_ustar" {
        "tar"
    } else if name == "gzip" {
        "gzip"
    } else if name == "bzip2" {
        "bzip2"
    } else if name == "xz" {
        "xz"
    } else if name == "zstd" {
        "zstd"
    } else if name == "lz4" {
        "lz4"
    } else {
        ""
    }
}

#[cfg(test)]
mod signature_search_tests {
    use super::*;

    // Public window tests cover only some signatures. Check every name/offset
    // against a byte-by-byte oracle, including short and truncated edges.
    #[test]
    fn signature_byte_search_keeps_all_names_offsets_and_short_edges() {
        let patterns = ANALYSIS_SIGNATURES
            .iter()
            .filter_map(|&(name, signature)| signature.map(|signature| (name, signature)))
            .collect::<Vec<_>>();
        let mut data = (0..65536usize)
            .map(|i| (i * 73 + 19) as u8)
            .collect::<Vec<_>>();
        for (index, (_, signature)) in patterns.iter().enumerate() {
            let start = index * 13;
            data[start..start + signature.len()].copy_from_slice(signature);
        }
        data.extend_from_slice(b"ustarustarPK\x03\x04PK\x05\x06");
        for len in (0..=160).chain([data.len() - 1, data.len()]) {
            let sample = &data[..len];
            let mut expected = Vec::new();
            for index in 0..sample.len() {
                for &(name, signature) in &patterns {
                    if sample.get(index..index + signature.len()) == Some(signature) {
                        expected.push((name, 37 + index as u64));
                    }
                }
            }
            let mut actual = Vec::new();
            collect_signature_hits(&mut actual, 37, sample);
            let mut actual = actual
                .iter()
                .map(|hit| (hit.name(), hit.offset()))
                .collect::<Vec<_>>();
            actual.sort_unstable_by_key(|&(name, offset)| (offset, name));
            expected.sort_unstable_by_key(|&(name, offset)| (offset, name));
            assert_eq!(actual, expected);
        }
    }
}
