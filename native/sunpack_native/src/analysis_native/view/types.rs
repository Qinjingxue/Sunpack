struct AnalysisBinaryView {
    reader: ManagedReader,
}

// Format facts used by selection and extraction planning, not diagnostic maps.
#[derive(Clone, Default)]
struct ZipObservation {
    plausible: bool,
    magic_matched: bool,
    error: String,
    archive_offset: u64,
    eocd_offset: u64,
    comment_length: u64,
    is_multi_disk: bool,
    central_directory_walk_ok: bool,
    local_header_links_ok: bool,
    password_required: bool,
    content_integrity_warning: String,
    read_fault: Option<ReadFault>,
}

#[derive(Default)]
struct TarObservation {
    plausible: bool,
    magic_matched: bool,
    error: String,
    walk_complete: bool,
    segment_end: Option<u64>,
    damage_flags: Vec<String>,
    read_fault: Option<ReadFault>,
}

struct ZipEocdCandidate {
    offset: u64,
    comment_length: u64,
}
