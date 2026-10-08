# 测试冗余删减记录

本轮只修改测试及测试辅助代码。删减以能发现功能损坏为目标，不要求每个断言精确定位根因。保留真实输入、最终输出、阻塞/重试、并发与资源生命周期检查。

三项判断适用于下面每一项删除：

1. 合并项的输入或证据变体继续存在于保留测试中；重复项没有识别到必须独立保留的用户功能故障。只有字段形状、精确内部策略或 profiler 自检的项不计独立功能覆盖。
2. 表中给出剩余覆盖；合并不是删除相应场景。不同入口、不同错误证据、并发与生命周期有独立故障风险时保留对应测试。
3. 不再为相同功能结果重复构造 fixture、启动 worker/CLI 或维护模拟流水线；参数和 subtests 共用流程。没有通过等待或降低并发规避问题。

这是根据输入、行为断言与调用链得到的覆盖判断，未进行故障注入或 mutation testing，不声称已量化错误检出率。

保留的重点包括：伪装扩展名及分卷、多层嵌套、正确/错误/未知密码、缺卷、载体前后缀和多段、CLI/watch、并发领取与释放、原生 inventory、分析结果复用及不重复读取。

## 第一批合并与删除

同一行列出的每个原测试采用该行的三项判断；原测试名称保留，便于对照 Git 差异。

| 原测试文件及测试 | 独立故障判断 | 删除后的覆盖 | 成本判断 |
| --- | --- | --- | --- |
| `tests/cli/test_cli_basic.py`<br>`test_scan_help_does_not_expose_rule_internal_min_size_override`<br>`test_inspect_help_documents_archives_only_filter`<br>`test_extract_help_documents_runtime_overrides`<br>`test_extract_direct_file_bypasses_initial_scan`<br>`test_inspect_help_documents_analyze_option`<br>`test_watch_help_documents_watchdog_options`<br>`test_passwords_help_only_shows_password_relevant_options`<br>`test_config_help_only_exposes_show_and_validate` | 输入场景合并，或仅内部诊断/字段自检 | cli/test_command_modules.py::test_command_help_exposes_public_options；CLI 实际 extract/output 行为 | 不值得单独重复执行 |
| `tests/unit/test_output_paths.py`<br>`test_default_output_dir_uses_archive_stem_when_available`<br>`test_output_dir_avoids_existing_same_name_directory`<br>`test_output_dir_increments_when_extracted_directory_exists`<br>`test_output_dir_avoids_existing_same_name_file` | 输入场景合并，或仅内部诊断/字段自检 | test_output_path_reservation_preserves_stem_and_skips_occupied_names | 不值得单独重复执行 |
| `tests/unit/test_output_reservation.py`<br>`test_output_dir_resolver_avoids_existing_output_directory` | 输入场景合并，或仅内部诊断/字段自检 | test_output_paths.py::test_output_path_reservation_preserves_stem_and_skips_occupied_names | 不值得单独重复执行 |
| `tests/unit/test_cli_clipboard_passwords.py`<br>`test_collect_clipboard_passwords_reads_when_config_enabled`<br>`test_collect_clipboard_passwords_splits_multiline_text` | 输入场景合并，或仅内部诊断/字段自检 | test_passwords_command_includes_config_enabled_clipboard_password | 不值得单独重复执行 |
| `tests/unit/test_windows_clipboard.py`<br>`test_read_clipboard_passwords_keeps_multiline_default_behavior` | 输入场景合并，或仅内部诊断/字段自检 | test_cli_clipboard_passwords.py::test_passwords_command_includes_config_enabled_clipboard_password | 不值得单独重复执行 |
| `tests/unit/test_cli_runtime_password_prompt.py`<br>`test_password_prompt_stops_on_empty_line`<br>`test_password_prompt_treats_windows_carriage_return_as_empty_line`<br>`test_password_prompt_removes_windows_carriage_return_from_password`<br>`test_password_prompt_preserves_password_whitespace` | 输入场景合并，或仅内部诊断/字段自检 | test_password_prompt_handles_windows_lines_and_preserves_spaces | 不值得单独重复执行 |
| `tests/unit/test_scanner.py`<br>`test_directory_scanner_records_file_size`<br>`test_directory_scanner_size_range_gte_filters`<br>`test_directory_scanner_does_not_promote_split_shaped_small_files_without_anchor`<br>`test_directory_scanner_directory_prune_prunes_directory`<br>`test_directory_scanner_directory_prune_supports_path_globs`<br>`test_directory_scanner_directory_prune_supports_prune_dir_globs` | 输入场景合并，或仅内部诊断/字段自检 | test_directory_scanner_captures_files_and_directories / test_directory_scanner_size_range_filters_files_outside_range / functional/test_filesystem_directory_prune.py | 不值得单独重复执行 |
| `tests/functional/test_filesystem_directory_prune.py`<br>`test_profiled_scan_matches_normal_scan` | 输入场景合并，或仅内部诊断/字段自检 | 实际目录 prune 测试保留；profile 与普通扫描逐字段比较没有独立用户功能覆盖 | 不值得单独重复执行 |
| `tests/unit/test_watch_quiet_policy.py`<br>`test_policy_uses_lower_initial_growth_curve`<br>`test_fast_and_moderate_writes_complete_quickly` | 输入场景合并，或仅内部诊断/字段自检 | test_representative_writes_avoid_repeated_premature_attempts；冷启动、长间隔、p90 和 metadata 测试保留 | 不值得单独重复执行 |
| `tests/unit/test_global_cache_manager.py`<br>`test_mutable_get_copies_after_releasing_cache_lock` | 输入场景合并，或仅内部诊断/字段自检 | test_mutable_set_copies_before_taking_cache_lock 同时检查读写锁范围 | 不值得单独重复执行 |
| `tests/unit/test_builtin_passwords.py`<br>`test_watch_clipboard_password_block_keeps_most_recent_entries`<br>`test_watch_clipboard_recopy_moves_password_to_most_recent_position`<br>`test_watch_clipboard_password_markers_do_not_change_with_cli_language` | 输入场景合并，或仅内部诊断/字段自检 | test_watch_clipboard_passwords_are_persisted_only_inside_managed_block | 不值得单独重复执行 |
| `tests/unit/test_archive_metadata_encoding.py`<br>`test_shift_jis_zip_scan_selects_cp932`<br>`test_format_hint_scans_disguised_zip_without_renaming_it` | 输入场景合并，或仅内部诊断/字段自检 | test_native_codepage_selection_preserves_known_unicode_families | 不值得单独重复执行 |
| `tests/unit/test_rar_7z_fast_verifier.py`<br>`test_rar_fast_verifier_rejects_wrong_rar3_hp_encrypted_header`<br>`test_rar_fast_verifier_matches_rar5_password_check`<br>`test_rar_fast_verifier_rejects_wrong_rar5_password_check`<br>`test_rar_fast_verifier_rejects_wrong_rar5_file_passwords_without_payload`<br>`test_seven_zip_fast_verifier_matches_encrypted_header_password`<br>`test_seven_zip_fast_verifier_rejects_wrong_encrypted_header_passwords` | 输入场景合并，或仅内部诊断/字段自检 | RAR / 7z parallel_batch_preserves_first_match 同时检查候选匹配、拒绝与证据 | 不值得单独重复执行 |
| `tests/real/plan1_real_archives/test_plan1_format_variants.py`<br>`test_plan1_zip64_archive_structural_and_detection`<br>`test_plan1_7z_nonsolid_archive_extracts_and_detects`<br>`test_plan1_xz_sha256_check_archive_extracts_and_detects` | 输入场景合并，或仅内部诊断/字段自检 | test_plan1_zip64_archive_extracts_and_detects / Plan1 compression_methods / test_plan1_stream_codec_headers_levels_and_checks_extract | 不值得单独重复执行 |
| `tests/unit/test_verification_output_quality.py`<br>`test_complete_unverified_content_with_high_output_quality_accepts`<br>`test_complete_unverified_content_with_low_output_quality_still_accepts`<br>`test_partial_unverified_content_with_output_quality_accepts_partial`<br>`test_complete_unverified_content_with_partial_output_quality_accepts` | 输入场景合并，或仅内部诊断/字段自检 | test_unverified_content_decision_uses_completeness_and_recoverable_output | 不值得单独重复执行 |
| `tests/unit/test_disk_space_cleanup.py`<br>`test_pipeline_artifacts_public_schema_has_no_flatten_queue`<br>`test_cleanup_result_public_schema_is_stable` | 输入场景合并，或仅内部诊断/字段自检 | 字段形状检查删除，实际 cleanup、失败清理与 disk-full 行为测试保留 | 不值得单独重复执行 |
| `tests/integration/test_detection_pipeline.py`<br>`test_archive_task_keeps_physical_path_and_exposes_format_hint`<br>`test_pipeline_can_scan_and_extract_zip` | 输入场景合并，或仅内部诊断/字段自检 | Plan1 普通/伪装输入完整解压矩阵、test_output_paths.py::test_direct_input_keeps_filename_separate_from_disguised_format | 不值得单独重复执行 |
| `tests/unit/test_password_failure_contract.py`<br>`test_verifier_statuses_accept_only_canonical_values` | 输入场景合并，或仅内部诊断/字段自检 | 枚举自迭代常量检查删除，真实候选成功、错误、损坏、inconclusive 分支保留 | 不值得单独重复执行 |

## 后续合并与删除

| 原测试文件及测试 | 独立故障判断 | 删除后的覆盖 | 成本判断 |
| --- | --- | --- | --- |
| `tests/unit/test_watch_scheduler.py::test_usn_data_reason_detects_same_size_in_place_content_change` | 场景迁移或重复功能结果 | test_content_event_during_processing_still_starts_new_epoch_from_latest_metadata; test_password_retry_identity_uses_existing_content_change_rules | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_usn_metadata_reason_does_not_count_as_content_change` | 场景迁移或重复功能结果 | test_metadata_event_during_and_after_processing_does_not_start_new_epoch | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_identical_observation_is_unchanged` | 场景迁移或重复功能结果 | test_event_burst_with_unchanged_usn_does_not_restart_quiet_window | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_successful_watch_task_uses_direct_output_root` | 场景迁移或重复功能结果 | test_partial_result_does_not_self_retry_but_modified_epoch_does; integration/test_watch_root_output_routing.py | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_partial_result_is_rejected_but_direct_output_remains` | 场景迁移或重复功能结果 | test_partial_result_does_not_self_retry_but_modified_epoch_does | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_content_event_during_processing_starts_a_new_active_epoch` | 场景迁移或重复功能结果 | test_content_event_during_processing_still_starts_new_epoch_from_latest_metadata | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_never_recurses_for_current_directory_scan_mode` | 场景迁移或重复功能结果 | test_watch_scheduler_never_recurses_for_recursive_directory_scan_mode | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_sends_quiet_nonstandard_extension_to_main_pipeline` | 场景迁移或重复功能结果 | test_watch_scheduler_processes_direct_quiet_candidate_with_watch_root_common_root | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_timestamp_restore_does_not_reset_content_quiet_window` | 场景迁移或重复功能结果 | integration/test_watch_ntfs_usn.py::test_restoring_an_older_mtime_does_not_restart_content_quiet_window; test_pending_metadata_event_advances_snapshot_without_generation_or_wakeup | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_growth_resets_the_common_quiet_window` | 场景迁移或重复功能结果 | integration/test_watch_ntfs_usn.py::test_slow_writes_busy_handle_move_and_event_storm_reach_ready; test_watch_scheduler_adapts_quiet_window_to_fast_content_writes | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_does_not_log_duplicate_pending_candidate` | 场景迁移或重复功能结果 | test_event_burst_with_unchanged_usn_does_not_restart_quiet_window | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_ignores_nested_paths` | 场景迁移或重复功能结果 | test_watch_scheduler_never_recurses_for_recursive_directory_scan_mode | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_reprocesses_identical_archive_after_it_moves_out_and_back` | 场景迁移或重复功能结果 | real/plan7_watch_downloads/test_plan7_lifecycle.py::test_plan7_replacement_and_reappearance_are_processed | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_processes_same_path_again_after_input_changes` | 场景迁移或重复功能结果 | test_partial_result_does_not_self_retry_but_modified_epoch_does; test_modified_epoch_triggers_even_when_size_mtime_and_file_id_are_unchanged | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_initial_scan_ignores_nested_archives` | 场景迁移或重复功能结果 | test_watch_scheduler_never_recurses_for_recursive_directory_scan_mode | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_does_not_special_case_downloader_suffixes` | 场景迁移或重复功能结果 | real/plan7_watch_downloads/test_plan7_download_modes.py::test_plan7_interleaved_downloads_react_for_every_final_path | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_same_stat_same_usn_event_does_not_reset_quiet_window` | 场景迁移或重复功能结果 | integration/test_watch_ntfs_usn.py::test_duplicate_noise_does_not_restart_generation_but_overwrite_does; test_event_burst_with_unchanged_usn_does_not_restart_quiet_window | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_forces_complete_content_policy_for_pipeline_engine` | 场景迁移或重复功能结果 | test_watch_service_attaches_and_releases_toast_with_watch_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_scheduler_restart_keeps_unchanged_toast_manager` | 场景迁移或重复功能结果 | test_watch_service_attaches_and_releases_toast_with_watch_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_config_observer_wakes_runtime_host_queue` | 场景迁移或重复功能结果 | test_watch_service_config_observer_targets_program_files | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_reload_applies_new_roots_without_restarting_tray` | 场景迁移或重复功能结果 | test_service_reload_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_runtime_mode_reload_does_not_restart_scheduler` | 场景迁移或重复功能结果 | test_service_reload_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_tray_only_reload_does_not_restart_scheduler` | 场景迁移或重复功能结果 | test_service_reload_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_language_reload_refreshes_existing_tray` | 场景迁移或重复功能结果 | test_service_reload_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_reload_skips_unchanged_state` | 场景迁移或重复功能结果 | test_service_reload_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_adding_and_removing_roots_keeps_the_roots_file_unchanged` | 场景迁移或重复功能结果 | test_watch_roots_are_stored_in_program_txt | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_relative_watch_state_path_uses_program_directory_not_process_working_directory` | 场景迁移或重复功能结果 | test_default_watch_state_uses_program_directory_and_output_stays_relative | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_state_falls_back_to_program_directory_without_existing_roots` | 场景迁移或重复功能结果 | test_default_watch_state_uses_program_directory_and_output_stays_relative | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_reads_roots_from_txt_not_config` | 场景迁移或重复功能结果 | test_watch_service_scheduler_receives_root_outputs | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_scheduler_never_recurses` | 场景迁移或重复功能结果 | test_watch_scheduler_never_recurses_for_recursive_directory_scan_mode; test_watch_service_passes_direct_scan_roots_to_scheduler | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_recalculates_deadline_after_scheduler_wakeup` | 场景迁移或重复功能结果 | test_watch_service_deduplicates_unchanged_pending_ticks | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_service_runs_scheduler_when_wakeup_has_no_schedulable_delay` | 场景迁移或重复功能结果 | test_watch_service_deduplicates_unchanged_pending_ticks | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_standalone_rar_and_7z_are_confirmed_by_relations` | 场景迁移或重复功能结果 | real/plan1_real_archives: plain/sfx matrices; real/test_external_structure_corpus.py::test_empty_archive_preserves_output_without_recursive_children | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_standalone_zip_is_confirmed_by_relations` | 场景迁移或重复功能结果 | real/plan1_real_archives: plain/sfx matrices; real/test_external_structure_corpus.py::test_empty_archive_preserves_output_without_recursive_children | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_empty_zip_is_confirmed_by_relations` | 场景迁移或重复功能结果 | real/plan1_real_archives: plain/sfx matrices; real/test_external_structure_corpus.py::test_empty_archive_preserves_output_without_recursive_children | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range` | 场景迁移或重复功能结果 | real/plan1_real_archives: plain/sfx matrices; real/test_external_structure_corpus.py::test_empty_archive_preserves_output_without_recursive_children | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_filename_numbered_7z_without_structural_seed_is_not_grouped` | 场景迁移或重复功能结果 | test_filename_camouflage_without_structure_never_builds_a_group | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_unconfirmed_launcher_does_not_claim_filename_like_data_volumes` | 场景迁移或重复功能结果 | test_filename_camouflage_without_structure_never_builds_a_group | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_rar_part1_exe_remains_a_data_volume` | 场景迁移或重复功能结果 | test_filename_camouflage_without_structure_never_builds_a_group | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_strict_formats_with_same_stem_never_cross_merge` | 场景迁移或重复功能结果 | test_filename_camouflage_without_structure_never_builds_a_group | 不值得独立重复执行 |
| `tests/unit/test_relations.py::test_prefixed_single_disk_zip_carrier_is_resolved_by_embedded_discovery` | 场景迁移或重复功能结果 | real/plan5_embedded_archives/test_plan5_mixed_embedded.py; functional/test_detection_behaviors.py::test_embedded_carrier_with_prefix_and_suffix_is_discovered | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_probe_hp_single_volume_requires_and_accepts_password` | 场景迁移或重复功能结果 | real/plan2_encrypted_archives/test_plan2_plain_encrypted.py; real/plan3_wrong_passwords/test_plan3_plain_wrong_passwords.py; test_two_standalone_hp_rars_in_same_filename_family_return_to_plain_files | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_probe_hp_split_volumes_use_decrypted_numbers` | 场景迁移或重复功能结果 | test_encrypted_unresolved_members_all_receive_the_discovered_password; real/plan6_confused_volumes | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_probe_rar4_hp_split_volumes_decrypts_following_headers` | 场景迁移或重复功能结果 | real/plan2_encrypted_archives | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_single_hp_rar_is_a_plain_file_group_not_a_split` | 场景迁移或重复功能结果 | test_single_hp_rar_with_split_like_filename_remains_a_plain_file_group | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_split_hp_rar_group_is_identified_from_filenames` | 场景迁移或重复功能结果 | test_split_hp_rar_group_accepts_camouflage_around_contiguous_part_token | 不值得独立重复执行 |
| `tests/unit/test_rar_hp_header_decryption.py::test_relations_password_prober_returns_none_without_candidates` | 场景迁移或重复功能结果 | test_relations_password_prober_remembers_success_and_skips_second_probe | 不值得独立重复执行 |
| `tests/unit/test_deep_detection.py::test_force_scan_bypasses_pe_policy` | 场景迁移或重复功能结果 | test_executable_resource_archives.py::test_deep_scan_explicitly_scans_executable_resources | 不值得独立重复执行 |
| `tests/unit/test_deep_detection.py::test_embedded_rar_header_encryption_reaches_canonical_input` | 场景迁移或重复功能结果 | real/plan5_embedded_archives/test_plan5_rar4_header_planning.py; real/plan5_embedded_archives/test_plan5_mixed_embedded.py | 不值得独立重复执行 |
| `tests/unit/test_deep_detection.py::test_embedded_rar_wrong_password_blocks_whole_carrier` | 场景迁移或重复功能结果 | test_password_blocked_carrier_preserves_every_archive_finding | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_failed_result_includes_diagnostics` | 场景迁移或重复功能结果 | test_extraction_scheduler_saves_worker_diagnostics_on_failure; test_native_worker_queue_isolates_failed_job_and_continues | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_candidate_batch_probes_then_extracts_with_selected_password` | 场景迁移或重复功能结果 | test_worker_password_candidates | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_single_candidate_skips_probe_and_extracts_directly` | 场景迁移或重复功能结果 | test_worker_password_candidates | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_single_zipcrypto_collision_probes_only_after_direct_failure` | 场景迁移或重复功能结果 | test_worker_password_candidates | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_candidate_batch_rejects_all_candidates_without_full_extraction` | 场景迁移或重复功能结果 | test_worker_password_candidates | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_compact_worker_manifest_is_parsed_into_native_storage` | 场景迁移或重复功能结果 | test_worker_manifest_protocol | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_manifest_rows_require_inventory` | 场景迁移或重复功能结果 | test_worker_event_rejects_non_objects_and_malformed_rows | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_output_trace_requires_complete_items` | 场景迁移或重复功能结果 | test_worker_event_rejects_non_objects_and_malformed_rows | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_manifest_native_parser_preserves_json_escaped_paths` | 场景迁移或重复功能结果 | test_worker_manifest_protocol | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_manifest_rows_and_inventory_are_order_independent` | 场景迁移或重复功能结果 | test_worker_manifest_protocol | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_applies_format_aware_prefetch_policy` | 只检查 profiler 中的预取策略，没有独立功能结果 | Plan1 TAR 实际解压、test_worker_skips_output_crc_when_source_crc_is_missing | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_disables_prefetch_for_native_rar_volumes` | 只检查内部预取策略，没有独立功能结果 | Plan1 / Plan4 的真实 RAR 分卷、完整输出和缺卷矩阵 | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_omits_input_profile_without_opt_in` | 场景迁移或重复功能结果 | Plan1 / Plan4 实际解压与 worker 成功/失败测试保留；移除内部 profiler、预取策略或静态依赖自检 | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_async_output_extracts_format_without_source_crc` | 场景迁移或重复功能结果 | test_worker_skips_output_crc_when_source_crc_is_missing | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_extraction_scheduler_uses_worker_archive_input_descriptor` | 场景迁移或重复功能结果 | test_extraction_scheduler_uses_worker_for_file_range | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_split_worker_damage_takes_precedence_over_wrong_password_signal` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_worker_wrong_password_evidence_maps_to_wrong_password` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_direct_empty_zip_candidate_failure_without_crc_proof_is_wrong_password` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_direct_empty_zip_candidate_crc_proof_preserves_real_damage` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_zipcrypto_data_or_crc_without_password_proof_is_inconclusive` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_zipcrypto_backend_password_rejection_after_weak_header_match_is_inconclusive` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_worker_candidate_batch_rejection_overrides_weak_zipcrypto_evidence` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_zipcrypto_damage_after_encrypted_entry_crc_proof_is_damaged` | 场景迁移或重复功能结果 | test_zipcrypto_proof_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_structured_missing_volume_keeps_callback_evidence` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_tail_size_suspicion_does_not_become_missing_volume` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_tail_size_suspicion_does_not_override_explicit_wrong_password` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_split_archive_generic_backend_errors_are_damage_without_hard_evidence` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_archive_name_containing_missing_volume_is_not_explicit_backend_evidence` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_extraction_errors.py::test_explicit_backend_missing_volume_line_remains_missing_volume` | 场景迁移或重复功能结果 | test_failure_evidence_contract | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_consumes_embedded_discovery_prepass_for_middle_payload` | 场景迁移或重复功能结果 | test_analysis_reuses_complete_detection_prepass_without_shared_rescan | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_prefers_structural_boundary_over_next_signature` | 场景迁移或重复功能结果 | test_analysis_scheduler_finds_embedded_archive_segments | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_walks_rar_blocks_to_endarc` | 场景迁移或重复功能结果 | test_analysis_scheduler_finds_embedded_archive_segments | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_rar5_header_encrypted_carrier_stays_unresolved_without_password` | 场景迁移或重复功能结果 | test_rar5_header_encrypted_candidate_never_uses_following_archive_as_end | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_uses_7z_start_header_for_segment_end` | 场景迁移或重复功能结果 | test_analysis_scheduler_finds_embedded_archive_segments; test_7z_next_header_damage_does_not_trigger_embedded_revalidation | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_detects_tar` | 场景迁移或重复功能结果 | test_clean_whole_input_formats_use_structure_evidence | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_detects_compression_streams` | 场景迁移或重复功能结果 | test_clean_whole_input_formats_use_structure_evidence | 不值得独立重复执行 |
| `tests/unit/test_analysis_pipeline.py::test_analysis_scheduler_detects_compressed_tar_variants` | 场景迁移或重复功能结果 | test_clean_whole_input_formats_use_structure_evidence | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_writes_extractable_segment_without_switching_task_source` | 场景迁移或重复功能结果 | test_input_planning_stage_plans_real_carrier_segments_in_offset_order; real/plan5_embedded_archives/test_plan5_mixed_embedded.py | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_keeps_sfx_segment_for_standard_archive_extension` | 场景迁移或重复功能结果 | test_input_planning_stage_plans_real_carrier_segments_in_offset_order; real/plan5_embedded_archives/test_plan5_mixed_embedded.py | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_keeps_embedded_scan_ranges_for_neutral_carrier` | 场景迁移或重复功能结果 | test_input_planning_stage_plans_real_carrier_segments_in_offset_order; real/plan5_embedded_archives/test_plan5_mixed_embedded.py | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_records_multiple_segments_on_original_task` | 场景迁移或重复功能结果 | test_input_planning_stage_plans_real_carrier_segments_in_offset_order; real/plan5_embedded_archives/test_plan5_mixed_embedded.py | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_uses_range_input_for_embedded_password_required_archive` | 场景迁移或重复功能结果 | real/plan5_embedded_archives/test_plan5_rar4_header_planning.py; real/plan5_embedded_archives/test_plan5_wrong_password_partial.py | 不值得独立重复执行 |
| `tests/unit/test_input_planning_stage.py::test_input_planning_stage_projects_rar_sfx_volume_password_probe` | 场景迁移或重复功能结果 | real/plan2_encrypted_archives/test_plan2_sfx_encrypted.py; test_input_planning_preserves_structured_password_probe_for_split_segment_at_zero | 不值得独立重复执行 |
| `tests/unit/test_single_archive_extractor_segments.py::test_extractor_runs_analysis_segments_inside_same_task_and_restores_source` | 场景迁移或重复功能结果 | test_embedded_password_probe_and_session_key_follow_active_segment | 不值得独立重复执行 |
| `tests/unit/test_single_archive_extractor_segments.py::test_verifier_accepts_carrier_when_every_embedded_payload_is_complete` | 场景迁移或重复功能结果 | test_single_embedded_segment_exposes_logical_input_for_verification | 不值得独立重复执行 |
| `tests/unit/test_single_archive_extractor_segments.py::test_single_embedded_failure_preserves_child_diagnosis` | 场景迁移或重复功能结果 | test_multiple_embedded_failures_keep_aggregate_diagnosis | 不值得独立重复执行 |
| `tests/unit/test_output_scan_policy.py::test_output_scan_policy_schedules_disguised_archive_for_full_scan` | 场景迁移或重复功能结果 | test_output_scan_policy_reuses_extraction_inventory | 不值得独立重复执行 |
| `tests/unit/test_output_scan_policy.py::test_output_scan_policy_finds_nested_archive_when_initial_scan_is_current_dir_only` | 场景迁移或重复功能结果 | test_output_scan_policy_reuses_extraction_inventory | 不值得独立重复执行 |
| `tests/unit/test_output_scan_policy.py::test_output_scan_policy_projects_normal_archive_as_one_logical_root` | 场景迁移或重复功能结果 | integration/test_pipeline_runner.py::test_output_root_preserves_tree_and_recursive_scan_uses_success_outputs | 不值得独立重复执行 |
| `tests/integration/test_watch_rar_hp_encryption.py::test_watch_single_hp_rar_extracts_with_correct_password` | 场景迁移或重复功能结果 | test_watch_split_hp_rar_recovers_after_wrong_then_correct_password | 不值得独立重复执行 |
| `tests/integration/test_watch_rar_hp_encryption.py::test_watch_single_hp_rar_reports_wrong_password_without_hanging` | 场景迁移或重复功能结果 | test_watch_split_hp_rar_recovers_after_wrong_then_correct_password | 不值得独立重复执行 |
| `tests/integration/test_watch_rar_hp_encryption.py::test_watch_split_hp_rar_extracts_with_correct_password` | 场景迁移或重复功能结果 | test_watch_split_hp_rar_recovers_after_wrong_then_correct_password | 不值得独立重复执行 |
| `tests/integration/test_real_7z_rar_edge_cases.py::test_real_7z_sfx_missing_tail_reports_missing_volume_not_partial_payload` | 场景迁移或重复功能结果 | test_real_7z_missing_volume_priority_survives_irrelevant_wrong_password | 不值得独立重复执行 |
| `tests/integration/test_real_7z_rar_edge_cases.py::test_real_7z_header_encrypted_with_known_password_extracts` | 场景迁移或重复功能结果 | real/plan2_encrypted_archives/test_plan2_plain_encrypted.py | 不值得独立重复执行 |
| `tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_prefixed_carrier_archives_extract` | 场景迁移或重复功能结果 | real/plan5_embedded_archives/test_plan5_mixed_embedded.py; real/plan7_watch_downloads/test_plan7_embedded.py | 不值得独立重复执行 |
| `tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password` | 场景迁移或重复功能结果 | real/plan5_embedded_archives/test_plan5_mixed_embedded.py; real/plan5_embedded_archives/test_plan5_wrong_password_partial.py | 不值得独立重复执行 |
| `tests/unit/test_sevenzip_worker_extraction.py::test_worker_event_per_item_arrays_become_native_tables` | 场景迁移或重复功能结果 | test_native_worker_transport.py::test_interleaved_chunks_preserve_native_tables_and_metadata; test_worker_manifest_protocol | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_unstructured_nested_missing_volume_is_terminal_without_wait_anchor` | 场景迁移或重复功能结果 | test_unstructured_nested_password_failure_is_terminal_without_retry_anchor | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_watch_scheduler_retries_password_failure_after_password_source_change` | 场景迁移或重复功能结果 | test_password_retry_bypasses_learned_quiet_for_unchanged_failed_archive | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_password_retry_wakeup_uses_debounce_deadline_without_pending_candidate` | 场景迁移或重复功能结果 | test_password_retry_debounce_uses_monotonic_clock_when_wall_clock_moves_backward | 不值得独立重复执行 |
| `tests/unit/test_watch_scheduler.py::test_idle_scheduler_has_no_polling_deadline` | 场景迁移或重复功能结果 | test_password_retry_debounce_uses_monotonic_clock_when_wall_clock_moves_backward | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_trusts_validated_unencrypted_structure_without_retesting` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_trusts_validated_encrypted_structure_without_empty_password_test` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_uses_validated_rar_structure_password_marker` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_uses_validated_seven_zip_encryption_fact` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_does_not_recheck_clear_wrong_password_after_encrypted_search` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_preserves_fast_damage_result_without_full_retest` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_store_bounds_initial_recent_success_history` | 场景迁移或重复功能结果 | test_password_store_bounds_recent_success_history | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_records_archive_password_in_session` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle; test_password_resolver_submits_all_inconclusive_candidates_as_one_batch | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_reuses_session_password_without_retesting` | 场景迁移或重复功能结果 | test_validated_structure_password_lifecycle | 不值得独立重复执行 |
| `tests/unit/test_password_store.py::test_password_resolver_preserves_candidate_evidence_across_batch_confirmation` | 场景迁移或重复功能结果 | test_password_resolver_submits_all_inconclusive_candidates_as_one_batch | 不值得独立重复执行 |
| `tests/unit/test_password_scheduler.py::test_password_scheduler_reports_progress_events` | 场景迁移或重复功能结果 | test_password_scheduler_skips_negative_cache_and_reuses_success | 不值得独立重复执行 |
| `tests/unit/test_password_scheduler.py::test_verifier_chain_preserves_weak_candidate_evidence` | 场景迁移或重复功能结果 | test_extraction_plan_preserves_zipcrypto_candidate_evidence | 不值得独立重复执行 |
| `tests/unit/test_password_scheduler.py::test_extraction_plan_preserves_untested_suffix_after_weak_early_match` | 场景迁移或重复功能结果 | test_extraction_plan_caches_only_tested_prefix_before_weak_match | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_add_applies_directly_to_running_service` | 场景迁移或重复功能结果 | test_running_watch_add_forwards_output_dir_and_deep_mode | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_running_watch_service_duplicate_add_is_a_noop` | 场景迁移或重复功能结果 | test_running_watch_service_adds_roots_and_scans_only_new_roots | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_running_watch_service_removes_root_directly` | 场景迁移或重复功能结果 | test_running_watch_service_adds_roots_and_scans_only_new_roots | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_watch_roots_file_gives_every_root_its_own_output_root` | 场景迁移或重复功能结果 | test_watch_roots_file_resolves_relative_output_against_its_input_root | 不值得独立重复执行 |
| `tests/unit/test_watch_service.py::test_remove_unmonitored_root_skips_artifact_cleanup` | 场景迁移或重复功能结果 | test_remove_watch_root_cleans_service_owned_artifacts | 不值得独立重复执行 |
| `tests/unit/test_embedded_7z_backend.py::test_worker_does_not_import_7z_dll` | 场景迁移或重复功能结果 | test_worker_extracts_zip_without_7z_dll | 不值得独立重复执行 |
| `tests/unit/test_output_reservation.py::test_detected_extensions_do_not_rename_source_files` | 场景迁移或重复功能结果 | test_output_paths.py::test_direct_input_keeps_filename_separate_from_disguised_format; real/plan1_real_archives/test_plan1_plain_matrix.py | 不值得独立重复执行 |
| `tests/unit/test_output_reservation.py::test_embedded_carrier_keeps_physical_extension_and_detected_format` | 场景迁移或重复功能结果 | test_output_paths.py::test_direct_input_keeps_filename_separate_from_disguised_format; real/plan5_embedded_archives | 不值得独立重复执行 |

无剩余调用的 fixture、工具函数和重复初始化随测试删除；watch/worker 共有构造器统一复用。

## 验收

使用 `.\run_acceptance_tests.ps1 -NoWait -VerboseOutput`，默认 8 个 worker，x64/ci，保留环境预检和临时 Watch Broker 安装/卸载。

- CLI、unit、functional：1517 passed，1 skipped，51 subtests passed。
- integration、real：725 passed，1 skipped。
- 管理员 VHD disk-full：8 skipped；当前进程不满足管理员执行条件。
- CLI help/passwords/scan/inspect/config smoke checks 全部通过。

验收未测 benchmark；没有修改生产代码。
