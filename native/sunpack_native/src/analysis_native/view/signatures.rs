// Compact immutable signature observations.
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

fn signature_prepass_native(reader: &ManagedReader) -> io::Result<Arc<[SignatureHit]>> {
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
    Ok(hits.into())
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
