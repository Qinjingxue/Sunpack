use formats::carrier::{
    archive_carrier_crop_recovery, archive_nested_payload_salvage, rar_block_chain_trim_recovery,
    rar_end_block_repair,
};
use formats::seven_zip::{seven_zip_atomic_repair, seven_zip_scan_source};
use formats::stream::{
    compression_stream_block_salvage, compression_stream_partial_recovery,
    compression_stream_trailing_junk_trim, gzip_deflate_member_resync_repair,
    gzip_footer_fix_repair, tar_boundary_repair, tar_compressed_partial_recovery,
    tar_truncated_partial_recovery, zstd_frame_salvage_repair,
};
use formats::zip::{
    zip_cd_local_header_reconcile_salvage, zip_conflict_resolver_rebuild,
    zip_deep_partial_recovery, zip_directory_field_repair, zip_rebuild_from_local_headers,
    zip_remove_spurious_data_descriptor, zip_scan_source, zip_verified_entry_salvage,
};
use pyo3::prelude::*;

mod analysis_native;
mod filesystem;
mod formats;
mod io;
mod password;
mod postprocess;
mod relations;
mod scan;
mod verification;

#[cfg(test)]
mod test_support {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sunpack_native_{name}_{nonce}.bin"));
        fs::write(&path, contents).expect("write test file");
        path
    }
}

#[pyfunction]
fn native_available() -> bool {
    true
}

#[pyfunction]
fn scanner_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn sunpack_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_available, m)?)?;
    m.add_function(wrap_pyfunction!(scanner_version, m)?)?;
    m.add_function(wrap_pyfunction!(io::reader::reader_cache_stats, m)?)?;
    m.add_function(wrap_pyfunction!(io::reader::clear_reader_resources, m)?)?;
    m.add_function(wrap_pyfunction!(
        io::resource_lifecycle::native_resource_snapshot,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::resource_lifecycle::native_wait_for_resources,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::resource_lifecycle::native_begin_promotion,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::resource_lifecycle::native_end_promotion,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        formats::seven_zip::seven_zip_runtime_cache_stats,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        formats::seven_zip::clear_seven_zip_runtime_caches,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::reader::release_reader_handles_under,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::reader::release_reader_resources_under,
        m
    )?)?;
    m.add_class::<analysis_native::AnalysisBinaryView>()?;
    m.add_class::<analysis_native::AnalysisMultiVolumeView>()?;
    m.add_function(wrap_pyfunction!(analysis_native::probe_rar_bytes, m)?)?;
    m.add_class::<io::reader::NativeArchiveSession>()?;
    m.add_class::<scan::directory::NativeDirectorySnapshot>()?;
    m.add_class::<scan::directory::NativeOutputInventory>()?;
    m.add_class::<scan::directory::NativeWorkerManifest>()?;
    m.add_function(wrap_pyfunction!(scan::magic::scan_after_markers, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_broker_acquire, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_broker_release, m)?)?;
    m.add_function(wrap_pyfunction!(scan::magic::scan_magics_anywhere, m)?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::fuzzy_binary_profile_for_paths,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(analysis_native::probe_volume_anchors, m)?)?;
    m.add_function(wrap_pyfunction!(scan::embedded::scan_embedded_archives, m)?)?;
    m.add_function(wrap_pyfunction!(
        scan::executable_carrier::executable_runtime_bundle_profile,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::zip_names::scan_zip_central_directory_names,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::scan_directory_snapshot,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::scan_directory_snapshots,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::directory_snapshot_from_columns,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::profile_directory_scan,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::filter_inventory_file_indices,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::list_regular_files_in_directory,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(scan::directory::batch_file_head_facts, m)?)?;
    m.add_function(wrap_pyfunction!(
        scan::nested_authorization::authorize_nested_candidates,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(relations::relations_detect_split_role, m)?)?;
    m.add_function(wrap_pyfunction!(relations::relations_logical_name, m)?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_parse_numbered_volume,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(relations::relations_split_sort_key, m)?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_size_filter_split_family_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_apply_split_size_anchors,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_build_candidate_groups_from_snapshot,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_resolve_volume_once,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(scan::directory::scan_output_tree, m)?)?;
    m.add_function(wrap_pyfunction!(scan::directory::scan_output_inventory, m)?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::output_inventory_from_serialized,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::directory::worker_manifest_from_rows,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        verification::file_crc::compute_directory_crc_manifest,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        verification::file_crc::match_archive_output_crc_coverage,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        verification::file_crc::sample_directory_readability,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_zip_local_header,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_zip_eocd_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_zip_directory_consistency,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_zip_structure_graph,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_seven_zip_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(analysis_native::inspect_rar_structure, m)?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_tar_header_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        analysis_native::inspect_compression_stream_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        scan::pe_overlay::inspect_pe_overlay_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(postprocess::scan_watch_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(postprocess::watch_candidate_for_path, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_filesystem_type, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::validate_ntfs_watch_root, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_file_is_ready, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_broker_is_connected, m)?)?;
    m.add_function(wrap_pyfunction!(filesystem::watch_broker_ping_seconds, m)?)?;
    m.add_function(wrap_pyfunction!(
        postprocess::flatten_single_branch_directories,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(postprocess::delete_files_batch, m)?)?;
    m.add_function(wrap_pyfunction!(
        password::seven_zip::seven_zip_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::seven_zip::seven_zip_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::rar::rar_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::rar::rar_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::rar::rar_fast_verify_passwords_from_volumes,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::zip::zip_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::zip::zip_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password::zip::zip_fast_verify_passwords_from_volumes,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(io::repair::repair_read_file_range, m)?)?;
    m.add_function(wrap_pyfunction!(
        io::repair::repair_concat_ranges_to_bytes,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(io::repair::repair_write_candidate, m)?)?;
    m.add_function(wrap_pyfunction!(io::repair::repair_copy_range_to_file, m)?)?;
    m.add_function(wrap_pyfunction!(
        io::repair::repair_concat_ranges_to_file,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(io::repair::repair_patch_file, m)?)?;
    m.add_function(wrap_pyfunction!(
        io::archive_state::archive_state_to_bytes_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::archive_state::archive_state_size_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::archive_state::archive_state_write_to_file_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::archive_state::archive_state_zip_manifest_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        io::archive_state::archive_state_tar_manifest_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(zip_deep_partial_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(zip_scan_source, m)?)?;
    m.add_function(wrap_pyfunction!(zip_rebuild_from_local_headers, m)?)?;
    m.add_function(wrap_pyfunction!(zip_directory_field_repair, m)?)?;
    m.add_function(wrap_pyfunction!(zip_conflict_resolver_rebuild, m)?)?;
    m.add_function(wrap_pyfunction!(zip_verified_entry_salvage, m)?)?;
    m.add_function(wrap_pyfunction!(zip_cd_local_header_reconcile_salvage, m)?)?;
    m.add_function(wrap_pyfunction!(zip_remove_spurious_data_descriptor, m)?)?;
    m.add_function(wrap_pyfunction!(gzip_footer_fix_repair, m)?)?;
    m.add_function(wrap_pyfunction!(gzip_deflate_member_resync_repair, m)?)?;
    m.add_function(wrap_pyfunction!(zstd_frame_salvage_repair, m)?)?;
    m.add_function(wrap_pyfunction!(tar_boundary_repair, m)?)?;
    m.add_function(wrap_pyfunction!(compression_stream_partial_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(compression_stream_block_salvage, m)?)?;
    m.add_function(wrap_pyfunction!(compression_stream_trailing_junk_trim, m)?)?;
    m.add_function(wrap_pyfunction!(tar_compressed_partial_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(tar_truncated_partial_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(archive_carrier_crop_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(seven_zip_scan_source, m)?)?;
    m.add_function(wrap_pyfunction!(seven_zip_atomic_repair, m)?)?;
    m.add_function(wrap_pyfunction!(archive_nested_payload_salvage, m)?)?;
    m.add_function(wrap_pyfunction!(rar_block_chain_trim_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(rar_end_block_repair, m)?)?;
    Ok(())
}
