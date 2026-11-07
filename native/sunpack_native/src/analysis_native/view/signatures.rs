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

fn signature_prepass_native(reader: &ManagedReader) -> io::Result<SignaturePrepassData> {
    let size = reader.len();
    // This view already represents a logical input. Its origin is zero;
    // embedded discovery supplies its own validated roots through prepass.
    let mut head = reader.read_at(0, size.min(8) as usize)?;
    let zip = head.starts_with(ZIP_LOCAL)
        || head.starts_with(ZIP_EOCD)
        || head.starts_with(ZIP64_EOCD)
        || head.starts_with(b"PK\x07\x08")
        || head.starts_with(b"PK00");
    let header_len = standard_header_len(&head).min(size as usize);
    if header_len > head.len() {
        head.extend(reader.read_at(head.len() as u64, header_len - head.len())?);
    }
    let mut hits = Vec::new();
    for (pattern, &(name, signature)) in ANALYSIS_SIGNATURES.iter().enumerate() {
        let Some(signature) = signature.filter(|_| name != "zip_eocd") else {
            continue;
        };
        let offset = if name == "tar_ustar" { 257 } else { 0 };
        if head.get(offset..offset + signature.len()) == Some(signature) {
            hits.push(SignatureHit::new(pattern, offset as u64));
        }
    }
    if (head.starts_with(b"PK\x07\x08") || head.starts_with(b"PK00"))
        && head.get(4..8) == Some(ZIP_LOCAL)
    {
        hits.push(SignatureHit::new(0, 4));
    }
    if head.starts_with(ZIP64_EOCD) {
        // A ZIP64 empty archive may start with its end record.
        hits.push(SignatureHit::new(ANALYSIS_SIGNATURES.len() - 1, 0));
    }
    let mut tail_bytes = 0;
    if zip {
        let (tail, tail_start) =
            crate::formats::zip::read_eocd_tail(reader, 0, size, &head, &mut tail_bytes)?;
        // No trailing-junk search here. Only the declared comment can follow
        // the EOCD; arbitrary suffixes belong to embedded discovery.
        if let Some(eocd) = crate::formats::zip::find_eocd_record(&tail, false) {
            hits.push(SignatureHit::new(1, tail_start + eocd.offset as u64));
        }
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
        scanned_head: head.len(),
        scanned_tail: tail_bytes as usize,
    })
}

// Initial standard headers only. Variable fields and subsequent records are
// read by the existing format parsers using their declared lengths/offsets.
fn standard_header_len(head: &[u8]) -> usize {
    if head.starts_with(ZIP_LOCAL) {
        30
    } else if head.starts_with(b"PK\x07\x08") || head.starts_with(b"PK00") {
        34
    } else if head.starts_with(ZIP_EOCD) {
        22
    } else if head.starts_with(ZIP64_EOCD) {
        56
    } else if head.starts_with(RAR4) {
        7
    } else if head.starts_with(RAR5) {
        8
    } else if head.starts_with(SEVEN_ZIP) {
        32
    } else if head.starts_with(GZIP) {
        10
    } else if head.starts_with(BZIP2) {
        4
    } else if head.starts_with(XZ) {
        12
    } else if head.starts_with(ZSTD) {
        18
    } else if head.starts_with(LZ4) {
        19
    } else if crate::formats::lz4::leading(head) {
        8
    }
    // TAR has no mandatory magic, including V7. Read one record at the
    // origin and leave checksum/PAX/GNU validation to the canonical walker.
    else {
        TAR_BLOCK_SIZE
    }
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
