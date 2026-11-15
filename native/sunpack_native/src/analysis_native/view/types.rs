struct AnalysisBinaryView {
    reader: ManagedReader,
}

// Format facts used by selection and extraction planning, not diagnostic maps.
#[derive(Default)]
struct ZipObservation {
    error: &'static str,
    archive_offset: u64,
    eocd_offset: u64,
    comment_length: u64,
    is_multi_disk: bool,
    walk_ok: bool,
    password_required: bool,
    content_integrity_warning: bool,
}

enum TarObservation {
    Unrecognized,
    Recognized(Option<u64>),
    Terminated(u64),
}
