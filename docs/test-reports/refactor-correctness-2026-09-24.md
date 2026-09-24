# 重构后正确性测试报告

- 日期：2026-09-24（Asia/Shanghai）
- 测试对象：594f4698226ffc45e2fd0b32fb1ec1593a70f707 之后的 16 个提交（当前工作树）。
- 被测提交：7b5786c2718aeafbfb71f23131a5847d487633ee（Finalize canonical archive input data structures #120）。
- 环境：Windows x64、Python 3.10.11、pytest 9.1.1、uv 0.12.5、8 个 xdist worker。
- 程序代码和测试代码均未修改；本报告是唯一计划提交的文件。

## 执行方式与环境

先执行项目 acceptance runner：run_acceptance_tests.ps1 -NoWait -VerboseOutput。前置检查发现 .venv 无法导入 sunpack_native 且环境清单过期，runner 自动重建 .venv 并编译 Rust 扩展、嵌入式 7-Zip worker 和 toast library。worker 的 6 项 CTest、toast library 的 1 项 CTest 均通过。

环境准备最后执行 sunpack.py inspect --analyze --no-pause -q <probe.zip> 失败，runner 在 pytest 开始前退出：

    SunPack 持久进程未能及时启动。
    运行时进程已退出，退出码为 1。

随后执行 run_acceptance_tests.ps1 -NoWait -SkipEnvironmentRefresh，让已经重建的环境继续进入 pytest。归档生成器检查通过，临时 Watch Broker 服务成功安装和卸载。

## 汇总

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1120 | 1065 | 54 | 1 | 0 |
| integration、real | 347 | 52 | 294 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **pytest 合计** | **1475** | **1117** | **348** | **1** | **9** |

acceptance runner 汇总为 6 个失败步骤：CLI/unit/functional、integration/real，以及 4 个 CLI smoke。CLI help smoke 通过。Administrator VHD disk-full 步骤虽被标为通过，8 个用例实际全部跳过。

### pytest 命令

    python -m pytest -q -n 8 --dist worksteal tests/cli tests/unit tests/functional --durations=20
    python -m pytest -q -n 8 --dist worksteal tests/integration tests/real --ignore tests/integration/test_disk_full_pause_resume.py --durations=20
    python -m pytest -q -n 8 --dist worksteal tests/integration/test_disk_full_pause_resume.py --durations=20

### CLI smoke

sunpack.py --help 通过。下面 4 个命令均退出码 1；重跑后每个命令都输出相同错误：

    SunPack 持久进程未能及时启动。
    运行时进程已退出，退出码为 1。

- sunpack.py passwords --json
- sunpack.py scan <repo>\tests --json
- sunpack.py inspect <repo>\tests --json
- sunpack.py config --json show

### 跳过与范围

- disk-full 的 8 个用例因“需要管理员权限（diskpart 提权）”跳过。
- tests/real/test_game_tree_recursive_scan.py::test_game_tree_resources_are_not_authorized_for_recursive_extraction 因未设置 SUNPACK_RUN_GAME_TREE_TEST=1 跳过；该用例扫描本机 D:\game，测试文件要求显式启用。
- tests/memory/test_watch_growth.py 是 performance 内存稳定性测试，项目要求显式使用 --run-performance；不属于 correctness acceptance runner 默认范围。

## 失败项与 pytest 报错信息

以下按 JUnit 的首行错误信息分组；各失败项和收集错误的完整测试 ID 均列出。

### CLI、unit、functional

#### 7 项 — AssertionError: 1 != 0 : SunPack 持久进程未能及时启动。

- tests.cli.test_cli_basic.CliBasicTests::test_config_show_json_shape (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_extract_direct_file_bypasses_initial_scan (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_extract_out_dir_places_output_below_the_given_root (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_inspect_analyze_json_shape_is_compact (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_inspect_archives_only_filters_output_items (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_scan_json_shape (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_inspect_json_shape (failure)

#### 6 项 — AttributeError: 'ArchiveInputPlanningStage' object has no attribute '_record_planning_state'. Did you mean: '_record_planning_input'?

- tests.unit.test_input_planning_stage::test_input_planning_stage_writes_extractable_segment_without_switching_task_source (failure)
- tests.unit.test_input_planning_stage::test_input_planning_stage_keeps_sfx_segment_for_standard_archive_extension (failure)
- tests.unit.test_input_planning_stage::test_input_planning_stage_does_not_treat_native_zip_recovery_fragments_as_embedded (failure)
- tests.unit.test_input_planning_stage::test_input_planning_stage_keeps_embedded_scan_ranges_for_neutral_carrier (failure)
- tests.unit.test_input_planning_stage::test_input_planning_stage_records_multiple_segments_on_original_task (failure)
- tests.unit.test_input_planning_stage::test_input_planning_stage_maps_split_logical_segment_to_concat_ranges (failure)

#### 5 项 — TypeError: _ActivePipelineRequest.__init__() got an unexpected keyword argument 'group'

- tests.unit.test_watch_task_retry_model::test_generated_password_failure_defers_flatten_until_retry_completes (failure)
- tests.unit.test_watch_task_retry_model::test_generated_password_failure_is_anchored_to_failed_task (failure)
- tests.unit.test_watch_task_retry_model::test_password_retry_can_advance_to_the_next_generated_task (failure)
- tests.unit.test_watch_task_retry_model::test_generated_missing_volume_is_terminal_and_not_suspended (failure)
- tests.unit.test_watch_task_retry_model::test_direct_missing_volume_still_suspends_watch_input (failure)

#### 4 项 — sunpack.core.config.loader.ConfigError: Missing required sunpack_config.json or sunpack_advanced_config.json. Searched: C:\Users\29402\Desktop\sunpack\sunpack\sunpack_config.json, C:\Users\29402\Desktop\sunpack\sunpack\runtime-cwd\direct\sunpack_config.json, C:\Users\29402\Desktop\sunpack\sunpack\runtime-cwd\direct\sunpack-2\sunpack_config.json, C:\Users\29402\Desktop\sunpack\sunpack\sunpack_advanced_config.json, C:\Users\29402\Desktop\sunpack\sunpack\runtime-cwd\direct\sunpack_advanced_config.json, C:\Users\29402\Desktop\sunpack\sunpack\runtime-cwd\direct\sunpack-2\sunpack_advanced_config.json

- tests.functional.test_watch_password_retry::test_watch_retries_real_encrypted_zip_after_password_source_update[directory] (failure)
- tests.functional.test_watch_password_retry::test_watch_retries_real_encrypted_zip_after_password_source_update[watch_clipboard] (failure)
- tests.functional.test_watch_password_retry::test_watch_aggregates_all_zipcrypto_fast_matches[later-success] (failure)
- tests.functional.test_watch_password_retry::test_watch_aggregates_all_zipcrypto_fast_matches[all-candidates-rejected] (failure)

#### 3 项 — AttributeError: 'dict' object has no attribute 'add'

- tests.unit.test_output_reservation::test_output_dir_resolver_disambiguates_duplicate_task_outputs (failure)
- tests.unit.test_output_reservation::test_output_dir_resolver_avoids_existing_output_directory (failure)
- tests.unit.test_output_reservation::test_output_reservations_disambiguate_concurrent_requests_before_directories_exist (failure)

#### 3 项 — ImportError: cannot import name 'entrypoint' from 'sunpack.core.support' (C:\Users\29402\Desktop\sunpack\sunpack\core\support\__init__.py)

- tests.unit.test_toast_host_manager::test_main_runtime_handles_toast_bootstrap_without_starting_engine[--register-toast-register] (failure)
- tests.unit.test_toast_host_manager::test_main_runtime_handles_toast_bootstrap_without_starting_engine[--toast-activated-activate] (failure)
- tests.unit.test_toast_host_manager::test_unregister_toast_current_user_helper_is_dispatched_before_normal_runtime (failure)

#### 2 项 — AssertionError: assert None == '932'

- tests.unit.test_archive_metadata_encoding::test_shift_jis_kanji_only_zip_scan_uses_cp932 (failure)
- tests.unit.test_archive_metadata_encoding::test_shift_jis_zip_scan_returns_decoded_item_paths (failure)

#### 2 项 — json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)

- tests.cli.test_cli_basic.CliBasicTests::test_extract_out_dir_is_resolved_to_an_absolute_path (failure)
- tests.cli.test_cli_basic.CliBasicTests::test_json_mode_rejects_interactive_password_prompt_as_json (failure)

#### 1 项 — AssertionError: 1 != 0

- tests.cli.test_cli_basic.CliBasicTests::test_watch_help_documents_watchdog_options (failure)

#### 1 项 — AssertionError: 1 != 0 : Traceback (most recent call last):

- tests.cli.test_cli_basic.CliBasicTests::test_passwords_json_shape (failure)

#### 1 项 — AssertionError: assert False

- tests.cli.test_command_modules::test_cli_and_gui_packages_have_explicit_boundaries (failure)

#### 1 项 — AssertionError: assert ['C:\\Users\\...ssing.7z.001'] == ['C:\\Users\\...iting.7z.002']

- tests.unit.test_watch_crash_recovery::test_startup_blocker_reconciliation_is_targeted (failure)

#### 1 项 — AssertionError: assert [('file', 'sa...prepass'>})})] == [('file', 'sa...owed': True})]

- tests.unit.test_analysis_facade::test_archive_analyzer_dispatches_file_source_and_request (failure)

#### 1 项 — AssertionError: assert [['bad1', 'bad2']] == []

- tests.unit.test_password_scheduler::test_verifier_chain_prioritizes_fast_verifier_from_extension (failure)

#### 1 项 — AssertionError: assert [] == ['【サンプル】テスト素材.psd']

- tests.unit.test_archive_metadata_encoding::test_unicode_path_extra_field_takes_precedence_over_codepage_guess (failure)

#### 1 项 — AssertionError: untracked file-handle entry points:

- tests.unit.test_resource_lifecycle_static::test_python_business_code_cannot_bypass_tracked_file_entry_points (failure)

#### 1 项 — AttributeError: 'RunState' object has no attribute 'failed_tasks'. Did you mean: 'scan_failed_tasks'?

- tests.unit.test_failed_output_cleanup::test_collect_result_applies_main_pipeline_cleanup_after_diagnostics (failure)

#### 1 项 — AttributeError: 'module' object at sunpack.core.analysis.engine has no attribute 'scan_embedded_archives'

- tests.unit.test_analysis_pipeline::test_analysis_requires_candidate_embedded_scan_authorization (failure)

#### 1 项 — AttributeError: EMBEDDED_SCAN

- tests.unit.test_analysis_facade::test_analysis_request_rejects_capability_over_budget (failure)

#### 1 项 — AttributeError: can't set attribute 'logical_name'

- tests.unit.test_input_planning_stage::test_input_planning_stage_reuses_batch_report_for_equivalent_inputs (failure)

#### 1 项 — E   ImportError: cannot import name 'archive_state_manifest' from 'sunpack.pipeline.verification' (C:\Users\29402\Desktop\sunpack\sunpack\pipeline\verification\__init__.py)

- tests.unit.test_verification_methods (error)

#### 1 项 — FileNotFoundError: [Errno 2] No such file or directory: 'C:\\Users\\29402\\Desktop\\sunpack\\sunpack\\platform\\windows\\startup.py'

- tests.unit.test_windows_installer_contract::test_machine_level_path_context_menu_startup_and_toast_registration (failure)

#### 1 项 — KeyError: 'format'

- tests.unit.test_relations::test_prefixed_single_disk_zip_carrier_is_not_waited_as_missing_tail (failure)

#### 1 项 — KeyError: 'source'

- tests.unit.test_analysis_pipeline::test_analysis_reuses_complete_detection_prepass_without_shared_rescan (failure)

#### 1 项 — NameError: name 'bags' is not defined

- tests.unit.test_filesystem_routing::test_main_scan_routes_only_native_container_candidates_through_relations (failure)

#### 1 项 — StopIteration

- tests.unit.test_analysis_pipeline::test_analysis_defaults_to_shared_full_scan_when_head_and_tail_are_unresolved (failure)

#### 1 项 — TypeError: 'NoneType' object is not subscriptable

- tests.unit.test_real_diagnostics::test_task_snapshot_uses_typed_archive_state_and_knowledge (failure)

#### 1 项 — TypeError: AnalysisEngine.analyze_path() got an unexpected keyword argument 'embedded_scan_allowed'

- tests.unit.test_analysis_pipeline::test_rar5_header_encrypted_candidate_reuses_scanner_bounded_end (failure)

#### 1 项 — ValueError: Catalog key mismatch for zh: missing=['cli.scan.format'] extra=['cli.scan.detected_ext']

- tests.cli.test_command_modules::test_i18n_catalogs_have_matching_keys_and_placeholders (failure)

#### 1 项 — assert 0 == (0, 0)

- tests.unit.test_watch_state::test_prune_missing_records_retains_records_when_presence_is_unknown (failure)

#### 1 项 — assert 0 >= 1

- tests.unit.test_runtime_cache_cleanup::test_clear_all_runtime_caches_clears_python_owned_caches (failure)

### integration、real

#### 152 项 — AttributeError: 'ArchiveTask' object has no attribute 'format'

- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar4_compressed_split_extracts_all_members (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[ppmd] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[xz] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[zstd] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_rar_find_correct_password[rar5-header] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[zip] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[rar] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-7z-lzma2] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-zip-deflate] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[7z] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_rar_find_correct_password[rar5-data] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[tar] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[tar.gz] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-rar-m5] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[tar.bz2] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_rar_find_correct_password[rar4-header] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[tar.xz] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[tar.zst] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[gzip] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[split-7z-lzma2] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[xz] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_rar_find_correct_password[rar4-data] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[split-zip-deflate] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_disguised_archives_extract_and_detect_format[zstd] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[7z] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[split-rar-m5] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[zip] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[header-on] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[rar] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[header-off] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-7z-lzma2] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[nonsolid] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[7z] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-zip-deflate] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[lzma] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[zip] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-rar-m5] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[ppmd] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[rar] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_streaming_zip_uses_data_descriptors_and_extracts (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_7z_find_correct_password[deflate] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_zip64_archive_structural_and_detection (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_zip64_archive_extracts_and_detects (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_real_pkzip_multidisk_archive_extracts_and_detects (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[7z] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-numbered] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_7z_nonsolid_archive_extracts_and_detects (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[zip] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_rar4_legacy_archive_extracts_and_detects (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-numbered-cjk] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[rar] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_rar4_split_archive_extracts_and_detects (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-numbered-long-name] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-plain-numbered] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_multi_member_streams_extract_all_members[gzip] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[7z] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_multi_member_streams_extract_all_members[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_multi_member_streams_extract_all_members[xz] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-part-marker-camouflage] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_multi_member_streams_extract_all_members[zstd] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[zip] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_xz_sha256_check_archive_extracts_and_detects (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-format-before-part-marker] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[gzip-level1-no-name] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[gzip-level9-name] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[rar] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[bzip2-level1] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[7z-format-after-part-marker] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[bzip2-level9] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[xz-crc32] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[xz-crc64] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[zip-numbered] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[xz-sha256] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[zstd-level1-no-check] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[zip-part-marker-camouflage] (failure)
- tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_stream_codec_headers_levels_and_checks_extract[zstd-level19-check] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-numbered] (failure)
- tests.real.plan1_real_archives.test_plan1_mixed_directory::test_plan1_mixed_same_name_plain_formats_in_one_directory (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[zip-numbered-cjk] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-numbered-cjk] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[rar-part-marker] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-numbered-long-name] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[rar-part-marker-padded] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-plain-numbered] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_extract_and_detect_format[rar-camouflaged] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-part-marker-camouflage] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-format-before-part-marker] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_detected_as_one_logical_stream_with_chaotic_names[7z] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_detected_as_one_logical_stream_with_chaotic_names[zip] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[7z-format-after-part-marker] (failure)
- tests.real.plan1_real_archives.test_plan1_split_matrix::test_plan1_split_archives_detected_as_one_logical_stream_with_chaotic_names[rar] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[zip-numbered] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[zipcrypto] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[aes128] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[zip] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[zip-part-marker-camouflage] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[rar] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[aes256] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[deflate64] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[zip-numbered-cjk] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[7z] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[tar] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[tar.gz] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[rar-part-marker] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[tar.bz2] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_plain_encrypted::test_plan2_encrypted_zip_find_correct_password[lzma] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[tar.xz] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[tar.zst] (failure)
- tests.real.plan1_real_archives.test_plan1_plain_matrix::test_plan1_plain_single_archives_extract_and_detect_format[gzip] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[rar-part-marker-padded] (failure)
- tests.real.plan2_encrypted_archives.test_plan2_split_encrypted::test_plan2_encrypted_split_find_correct_password[rar-camouflaged] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-rar] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-some-7z] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-some-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-some-rar] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-all-7z] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-all-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[suffix-junk-all-rar] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[prefix-suffix-junk-all-7z] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[prefix-suffix-junk-all-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_split_confusion::test_plan6_encrypted_split_confused_volumes_extract[prefix-suffix-junk-all-rar] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[lzma-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[ppmd-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[bzip2-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[deflate-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar_compression_levels_and_solid_modes_extract_all_members[store-nonsolid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar_compression_levels_and_solid_modes_extract_all_members[maximum-nonsolid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar_compression_levels_and_solid_modes_extract_all_members[maximum-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar4_compression_modes_extract_all_members[rar4-compressed-nonsolid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_rar4_compression_modes_extract_all_members[rar4-compressed-solid] (failure)
- tests.real.plan6_confused_volumes.test_plan6_mixed_directory::test_plan6_confused_encrypted_groups_mixed_in_one_directory (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-7z] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-rar] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-7z] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-zip] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-rar] (failure)
- tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-7z] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[copy] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[deflate] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[deflate64] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[bzip2] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[lzma] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_zip_compression_methods_extract_all_members[ppmd] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[copy-nonsolid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[lzma2-solid] (failure)
- tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members[lzma2-nonsolid] (failure)

#### 63 项 — AttributeError: 'dict' object has no attribute 'add'

- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_head-rar] (failure)
- tests.integration.test_detection_pipeline.DetectionPipelineTests::test_pipeline_can_scan_and_extract_zip (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[header-off] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[nonsolid] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[lzma] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[ppmd] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[bzip2] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[deflate] (failure)
- tests.integration.test_pipeline_runner::test_pipeline_progress_observer_receives_extract_ready_before_native_progress (failure)
- tests.integration.test_pipeline_runner::test_pipeline_runner_uses_tmp_path_and_applies_success_postprocess (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_reports_password_error[7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_middle-rar] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_reports_password_error[zip] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_reports_password_error[rar] (failure)
- tests.real.plan1_real_archives.test_plan1_mixed_directory::test_plan1_mixed_compressed_formats_in_one_directory (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_split_reports_password_error[7z] (failure)
- tests.integration.test_structure_volume_resolution::test_pipeline_uses_initial_structure_group_without_missing_volume_retry (failure)
- tests.real.plan1_real_archives.test_plan1_mixed_directory::test_plan1_mixed_same_stem_split_formats_in_one_directory (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_split_reports_password_error[zip] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_sfx_wrong_passwords::test_plan3_encrypted_sfx_split_reports_password_error[rar] (failure)
- tests.integration.test_structure_volume_resolution::test_pipeline_middle_volume_target_exposes_resolved_physical_family (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[rar] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-numbered] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_carrier_archives_extract[jpg] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_carrier_archives_extract[png] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-numbered-cjk] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[zipcrypto] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_carrier_archives_extract[pdf] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[aes128] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-numbered-long-name] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_carrier_archives_extract[gif] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[aes256] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_carrier_archives_extract[webp] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-plain-numbered] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[deflate64] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[pdf-zip] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[bzip2] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-part-marker-camouflage] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[webp-7z] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[lzma] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[jpg-rar] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-format-before-part-marker] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_zip_reports_password_error[ppmd] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_rar_reports_password_error[rar5-header] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[7z-format-after-part-marker] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[png-rar] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_rar_reports_password_error[rar5-data] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[zip-numbered] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[gif-rar] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_rar_reports_password_error[rar4-header] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[zip-part-marker-camouflage] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_rar_reports_password_error[rar4-data] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[zip-numbered-cjk] (failure)
- tests.real.plan5_embedded_archives.test_plan5_large_embedded::test_plan5_large_file_extracts_128_real_embedded_archives (failure)
- tests.real.plan3_wrong_passwords.test_plan3_plain_wrong_passwords::test_plan3_encrypted_7z_reports_password_error[header-on] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[rar-part-marker] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[rar-part-marker-padded] (failure)
- tests.real.plan3_wrong_passwords.test_plan3_split_wrong_passwords::test_plan3_encrypted_split_reports_password_error[rar-camouflaged] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_head-rar] (failure)
- tests.real.plan5_embedded_archives.test_plan5_mixed_embedded::test_plan5_mixed_file_extracts_every_embedded_segment_with_correct_password (failure)
- tests.real.plan5_embedded_archives.test_plan5_wrong_password_partial::test_plan5_wrong_passwords_extract_plain_segments_only (failure)
- tests.real.plan7_watch_downloads.test_plan7_nested_extreme_failures::test_plan7_nested_inner_unknown_password_normal_mode (failure)
- tests.real.plan7_watch_downloads.test_plan7_nested_extreme_failures::test_plan7_nested_inner_missing_volume_normal_mode (failure)

#### 38 项 — NameError: name 'recovered' is not defined

- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_head-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_tail-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_tail-rar] (failure)
- tests.integration.test_pipeline_runner::test_pipeline_runner_passes_native_worker_overrides (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_tail-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_middle-zip] (failure)
- tests.integration.test_pipeline_runner::test_pipeline_runner_exposes_recent_passwords_without_password_manager (failure)
- tests.integration.test_pipeline_runner::test_batch_does_not_treat_existing_same_name_directory_as_output (failure)
- tests.integration.test_pipeline_runner::test_output_root_preserves_tree_and_recursive_scan_uses_success_outputs (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_middle-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_middle-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_middle-rar] (failure)
- tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_middle-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_head-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_head-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_head-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_tail-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_tail-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_tail-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_middle-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_middle-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_middle-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_middle-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_head-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_head-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_head-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_head-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_head-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_tail-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_tail-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_tail-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_tail-rar] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_tail-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_tail-7z] (failure)
- tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[missing_head-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_middle-zip] (failure)
- tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[missing_middle-rar] (failure)

#### 34 项 — Failed: watch condition did not settle before timeout: pending=0, entries={}

- tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_do_not_resubmit[7z] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[xz] (failure)
- tests.integration.test_watch_root_output_routing::test_watch_routes_each_root_to_its_output_root_without_input_tree_outputs (failure)
- tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_launcher_first_then_data_volumes_reacts_after_group_completion[7z] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stale_downloading_file_does_not_block_final_file (failure)
- tests.integration.test_watch_rar_hp_encryption::test_watch_single_hp_rar_extracts_with_correct_password (failure)
- tests.real.plan7_watch_downloads.test_plan7_nested_extreme_failures::test_plan7_nested_inner_missing_volume_watch_is_not_outer_volume_blocked (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[tar.bz2] (failure)
- tests.real.plan7_watch_downloads.test_plan7_download_modes::test_plan7_direct_final_path_download_does_not_stall_after_completion (failure)
- tests.integration.test_watch_rar_hp_encryption::test_watch_single_hp_rar_reports_wrong_password_without_hanging (failure)
- tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_do_not_resubmit[zip] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[zstd] (failure)
- tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_launcher_first_then_data_volumes_reacts_after_group_completion[zip] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_split_recovers_when_missing_last_volume_arrives (failure)
- tests.real.plan7_watch_downloads.test_plan7_plain_and_sfx_downloads::test_plan7_plain_and_sfx_downloads_complete_and_record_memory (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[tar.xz] (failure)
- tests.integration.test_watch_rar_hp_encryption::test_watch_split_hp_rar_extracts_with_correct_password (failure)
- tests.real.plan7_watch_downloads.test_plan7_download_modes::test_plan7_interrupted_download_resumes_after_watch_restart (failure)
- tests.real.plan7_watch_downloads.test_plan7_cleanup::test_plan7_sfx_split_success_cleans_unique_validated_launcher (failure)
- tests.real.plan7_watch_downloads.test_plan7_nested_extreme_failures::test_plan7_nested_inner_unknown_password_watch_is_password_blocked (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_same_stem_plain_and_sfx_arrive_interleaved (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[tar.zst] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_incomplete_split_recovers_after_watcher_restart (failure)
- tests.real.plan7_watch_downloads.test_plan7_split_downloads::test_plan7_split_downloads_out_of_order_complete_and_record_memory (failure)
- tests.real.plan7_watch_downloads.test_plan7_embedded::test_plan7_single_format_embedded_downloads_react_for_7z_zip_and_rar (failure)
- tests.real.plan7_watch_downloads.test_plan7_disguised::test_plan7_disguised_extensions_and_carrier_prefixes_react (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_replacement_and_reappearance_are_processed (failure)
- tests.real.plan7_watch_downloads.test_plan7_variants::test_plan7_encryption_and_container_variants_are_processed (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[tar.gz] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[gzip] (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_existing_file_initial_scan_and_quiet_window (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_deleted_partial_download_can_restart_from_scratch (failure)
- tests.real.plan7_watch_downloads.test_plan7_download_modes::test_plan7_interleaved_downloads_react_for_every_final_path (failure)
- tests.real.plan7_watch_downloads.test_plan7_lifecycle::test_plan7_stream_formats_direct_final_path_complete[bzip2] (failure)

#### 3 项 — AttributeError: 'ArchiveInputPlanningStage' object has no attribute '_record_planning_state'. Did you mean: '_record_planning_input'?

- tests.integration.test_native_sfx_split_wrapper::test_input_planned_sfx_uses_rust_password_verifier[7z] (failure)
- tests.integration.test_native_sfx_split_wrapper::test_input_planned_sfx_uses_rust_password_verifier[zip] (failure)
- tests.integration.test_native_sfx_split_wrapper::test_input_planned_sfx_uses_rust_password_verifier[rar] (failure)

#### 1 项 — AssertionError: assert ['C:\\Users\\...useless.fake'] == ['C:\\Users\\...useless.fake']

- tests.integration.test_structure_volume_resolution::test_raw_split_rar_sfx_with_opaque_camouflaged_members_runs_full_pipeline (failure)

#### 1 项 — AssertionError: assert not [SubmissionEvent(at=3530.3068623, paths=('C:\\Users\\29402\\AppData\\Local\\Temp\\pytest-of-29402\\pytest-0\\popen-gw7\\test_plan7_rar_part1_exe_is_re0\\rar_part1\\watch\\p7_order_rar.part1.exe',))]

- tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_rar_part1_exe_is_real_input_when_arriving_as_head (failure)

#### 1 项 — AttributeError: 'ExtractionResult' object has no attribute 'all_parts'

- tests.integration.test_extraction_execution.ExtractionExecutionTests::test_extractor_success_reports_cleanup_parts_not_candidate_run_parts (failure)

#### 1 项 — Failed: watch condition did not settle before timeout: pending=1, entries={}

- tests.integration.test_watch_rar_hp_encryption::test_watch_split_hp_rar_recovers_after_wrong_then_correct_password (failure)

## 我的判断

失败集中在多个跨层接口同时失配：

- 152 项真实归档用例报 ArchiveTask 缺少 format 属性，说明仍有路径依赖旧归档状态字段。
- 66 项输出目录预留调用对 dict 的 .add()，提取批次准备阶段会直接抛 AttributeError。
- 38 项报 recovered 未定义；另有 9 项调用不存在的 _record_planning_state，显示缺失卷处理和输入规划仍有未接通路径。
- 35 项 watch 用例以 pending=0/1、entries={} 超时。多个用例伴随异步 pipeline 异常，这些超时可能是处理崩溃的下游结果；测试结果不足以证明所有超时共享一个原因。
- CLI pytest 中 7 项及 4 个 smoke 命令均遇到持久进程启动后以退出码 1 退出。日志没有揭示该进程更早退出的根因。
- 其余失败还覆盖模块导入、参数签名、数据模型字段、i18n key、路径和编码断言，逐项错误已列在上方。

当前提交未通过正确性验收。本报告记录观察结果，没有修复或改写测试。
