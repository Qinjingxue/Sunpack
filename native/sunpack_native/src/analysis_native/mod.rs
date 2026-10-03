pub(crate) mod structure;
pub(crate) mod view;
pub(crate) mod volume_anchor;

pub(crate) use structure::{
    confirm_compression_format_identity_native, inspect_compression_stream_identity,
    inspect_compression_stream_structure, inspect_rar_structure, inspect_seven_zip_structure,
    inspect_tar_header_structure, inspect_zip_directory_consistency, inspect_zip_eocd_structure,
    inspect_zip_local_header, inspect_zip_structure_graph,
};
pub(crate) use view::{
    clear_stream_structure_cache, confirm_format_identity, confirm_format_identity_native,
    probe_rar_bytes, release_stream_structure_cache_under_roots, AnalysisBinaryView,
    AnalysisMultiVolumeView, NativeAnalysisConfig,
};
pub(crate) use volume_anchor::probe_volume_anchors;
