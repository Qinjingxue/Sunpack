pub(crate) mod structure;
pub(crate) mod view;
pub(crate) mod volume_anchor;

pub(crate) use structure::{
    inspect_compression_stream_identity, inspect_compression_stream_structure, inspect_rar_structure, inspect_seven_zip_structure,
    inspect_tar_header_structure, inspect_zip_directory_consistency,
    inspect_zip_eocd_structure,
    inspect_zip_local_header, inspect_zip_structure_graph,
};
pub(crate) use view::{
    probe_rar_bytes, probe_rar_path, probe_rar_terminal_with_password, probe_rar_volume_paths,
    AnalysisBinaryView, AnalysisMultiVolumeView,
};
pub(crate) use volume_anchor::probe_volume_anchors;
