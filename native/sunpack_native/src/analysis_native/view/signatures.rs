struct SignaturePrepassData {
    hits: Vec<(&'static str, u64)>,
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
    hits.sort_unstable_by_key(|(_, offset)| *offset);
    hits.dedup();
    let mut formats = Vec::new();
    for (name, _) in &hits {
        let format = format_for_hit(name);
        if !formats.contains(&format) {
            formats.push(format);
        }
    }
    formats.sort_unstable();
    Ok(SignaturePrepassData {
        hits,
        formats,
        scanned_head: head_len,
        scanned_tail: tail_len,
    })
}

fn signature_prepass_to_python(py: Python<'_>, data: SignaturePrepassData) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    let hits = PyList::empty(py);
    for (name, offset) in data.hits {
        let hit = PyDict::new(py);
        hit.set_item("name", name)?;
        hit.set_item("offset", offset)?;
        hits.append(hit)?;
    }
    dict.set_item("hits", hits)?;
    dict.set_item("formats", data.formats)?;
    dict.set_item("head_bytes", data.scanned_head)?;
    dict.set_item("tail_bytes", data.scanned_tail)?;
    Ok(dict.unbind())
}

fn collect_signature_hits(target: &mut Vec<(&'static str, u64)>, base: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    for (index, byte) in data.iter().enumerate() {
        let candidates = signatures_for_first_byte(*byte);
        if candidates.is_empty() {
            continue;
        }
        for (name, signature) in candidates {
            let end = index + signature.len();
            if end <= data.len() && &data[index..end] == *signature {
                target.push((*name, base + index as u64));
            }
        }
    }
}

fn signatures_for_first_byte(byte: u8) -> &'static [(&'static str, &'static [u8])] {
    match byte {
        b'P' => ANALYSIS_SIGNATURES_P,
        b'R' => ANALYSIS_SIGNATURES_R,
        b'7' => ANALYSIS_SIGNATURES_7,
        0x1f => ANALYSIS_SIGNATURES_GZIP,
        b'B' => ANALYSIS_SIGNATURES_BZIP2,
        0xfd => ANALYSIS_SIGNATURES_XZ,
        b'(' => ANALYSIS_SIGNATURES_ZSTD,
        b'u' => ANALYSIS_SIGNATURES_TAR,
        _ => &[],
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
    } else {
        ""
    }
}
