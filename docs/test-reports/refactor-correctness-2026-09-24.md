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

## 最新提交复测（9503b7db）

- 测试提交：`9503b7db8d94b265f58569def7816229bdb52bd4`（`fix: complete canonical contract migration after architecture refactor (#121)`）。本轮在上一轮被测提交 `7b5786c` 之后继续验证。
- 工作区在测试前干净；没有修改程序代码或测试代码。本报告追加本轮结果。
- 使用 `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_windows_dev.ps1 -Arch x64` 强制重建 `.venv`、Rust 扩展、Watch Broker、C++ 7-Zip worker 和 toast DLL。worker 的 6 项 CTest 和 toast 的 1 项 CTest 均通过。
- Rust 单元测试另执行 `cargo test --lib --manifest-path native/sunpack_native/Cargo.toml`：98 passed，0 failed。
- 开发环境脚本最后的 CLI probe 没通过：`[CLI] 运行失败：'archive'`，退出码 3（`sunpack.py inspect --analyze --no-pause -q <probe.zip>`）。编译阶段和 CTest 已完成。为继续验收，随后执行 `run_acceptance_tests.ps1 -NoWait -SkipEnvironmentRefresh`；该 runner 后续 5 项 CLI smoke（help、passwords、scan、inspect、config）全部通过。因此，setup probe 的 `'archive'` 异常与 acceptance smoke 结果不一致，仍应单独追踪。

### 本轮汇总

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1135 | 1129 | 6 | 0 | 0 |
| integration、real | 347 | 309 | 37 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **Python pytest 合计** | **1490** | **1438** | **43** | **0** | **9** |

额外验证：Rust 单元测试 98 项全部通过；C++ worker/toast CTest 7 项全部通过；acceptance CLI smoke 5 项全部通过。Acceptance 的两个 pytest 阶段失败，disk-full 阶段因管理员权限条件跳过全部 8 项。

### 本轮失败项与报错

#### CLI、unit、functional：6 项

- `tests.unit.test_runtime_cache_cleanup::test_clear_all_runtime_caches_clears_python_owned_caches` — `assert 0 >= 1`。`projection_cache.entries` 实际为 0。
- `tests.unit.test_verification_methods::test_manifest_size_match_reports_retry_for_large_manifest_gap` — 实际 issue 集合比预期多 `fail.manifest_named_files_missing`；预期只有 `fail.manifest_file_count_under` 和 `fail.manifest_size_under`。
- `tests.unit.test_input_planning_stage::test_input_planning_stage_does_not_treat_native_zip_recovery_fragments_as_embedded` — 预期 `knowledge_view.source_extractable_segments(task) == []`，实际仍得到 ZIP segment `embedded_01_zip`，`start_offset=13`。
- `tests.unit.test_resource_lifecycle_static::test_python_business_code_cannot_bypass_tracked_file_entry_points` — 静态检查发现未跟踪入口 `sunpack\runtime\cli\commands\version.py:24:read_text`。
- `tests.functional.test_misnamed_volume_consistency::test_filename_only_scan_does_not_absorb_unmarked_fuzzy_parts` — 预期 `archive_input.part_paths()` 为单元素 tuple，实际为单元素 list。
- `tests.functional.test_selected_targets_and_scheduler::test_selected_split_member_without_structural_proof_stays_single_candidate` — 同样预期单元素 tuple，实际为单元素 list。

#### integration、real：37 项

下面 27 项的共同错误是 `AssertionError: container type mismatch: expected pe, got <7z|zip|rar>`。检测到了对应的压缩格式，但测试所构造的 SFX 应被识别为 PE 容器；相同错误横跨普通 SFX、分卷 SFX、加密 SFX 和混淆卷场景。

- 7z（9 项）：
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-7z-lzma2]`
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-7z-lzma2]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[7z]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[7z]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[7z]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[7z]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-7z]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-7z]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-7z]`
- ZIP（9 项）：
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-zip-deflate]`
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-zip-deflate]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[zip]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[zip]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[zip]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[zip]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-zip]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-zip]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-zip]`
- RAR（9 项）：
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-rar-m5]`
  - `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-rar-m5]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_archives_extract_and_detect_format[rar]`
  - `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[rar]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_find_correct_password[rar]`
  - `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[rar]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-rar]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-rar]`
  - `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-rar]`

另外 10 项：

- `tests.integration.test_structure_volume_resolution::test_raw_split_rar_sfx_with_opaque_camouflaged_members_runs_full_pipeline` — 枚举值不符：实际 `file_range`，预期 `sfx_with_volumes`（`assert 'file_range' == 'sfx_with_volumes'`）。
- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_do_not_resubmit[7z]` — 预期 launcher 到达后没有后续提交事件，实际又提交了 `p7_order_7z.exe`。
- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_do_not_resubmit[zip]` — 同上，实际又提交了 `p7_order_zip.exe`。
- `tests.real.plan1_real_archives.test_plan1_format_variants::test_plan1_multi_member_streams_extract_all_members[gzip]` — `ValueError: Native scan_embedded_archives file_size mismatch: expected 32, got 48`。
- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[png-rar]` — `assert False`，wrong-password-then-success 的 `any(...)` 断言未成立。
- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[gif-rar]` — 同一 `assert False`。
- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[jpg-rar]` — 同一 `assert False`。
- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[7z]` — 预期有失败任务，实际 `RunSummary(...).failed_tasks == []`。
- `tests.integration.test_watch_rar_hp_encryption::test_watch_single_hp_rar_reports_wrong_password_without_hanging` — `NameError: name 'BLOCKER_PASSWORD' is not defined`。从异常看，这是测试执行路径引用了未定义名称，不能据此单独认定被测实现行为错误。
- `tests.integration.test_watch_rar_hp_encryption::test_watch_split_hp_rar_recovers_after_wrong_then_correct_password` — `Failed: watch condition did not settle before timeout: pending=0, entries={}`。

### 本轮理解

- 最大的一组剩余问题是 SFX 外层容器类型：27 个 7z/ZIP/RAR 用例都将 PE SFX 报成内部格式。它同时影响检测、加密 SFX 和卷名混淆流程，较像共享的容器类型归一化/证据优先级问题，而不是 27 个互不相关的提取故障。
- 分卷 SFX 的 `file_range`/`sfx_with_volumes` 差异和数据卷先到后 launcher 再到时的重复 watch 提交，分别指向输入关系分类和提交去重状态仍有缺口；目前结果不能证明二者根因相同。
- gzip 用例直接暴露 Rust native 扫描调用的 `file_size` 参数与实际输入长度不一致（32 对 48）。另外，ZIP 恢复片段被报告成 embedded segment、以及两个 `part_paths()` 测试的 list/tuple 差异，显示输入规划/数据模型边界仍有行为或返回契约差异。
- manifest 验证多报 named-files-missing、projection cache 为空、以及 `version.py` 的文件读取静态违规，是三个独立的剩余单测问题。
- 3 个带 carrier 前缀的加密 RAR 用例未满足错误密码后再正确密码的断言；split HP RAR 在密码表更新后没有形成 watch entry。单个 HP RAR 用例则先被 `BLOCKER_PASSWORD` 未定义阻断，需将测试名称错误与实现问题区分。
- 被测结果比上一轮记录的 349 个失败/收集错误少很多，但提交和用例集合都发生了变化，不能把总数差直接解释成逐项回归/修复对应关系。

### 跳过与边界

- disk-full 的 8 项因需要管理员权限执行 diskpart 而跳过。
- `tests.real.test_game_tree_recursive_scan::test_game_tree_resources_are_not_authorized_for_recursive_extraction` 未设置 `SUNPACK_RUN_GAME_TREE_TEST=1`，按测试文件要求跳过本机 `D:\game` 扫描。
- `tests/memory/test_watch_growth.py` 是 opt-in performance 测试，默认 acceptance correctness 流程不执行。
- 本轮报告基于完成的 Rust 单元测试、native CTest、Python acceptance 和 CLI smoke 结果；未修复失败项。
## 修复后复测（1e30a31d）

- 被测提交：`1e30a31d766a451978d41bb82c3fd32a15a1b554`（`Fix remaining post-refactor runtime regressions (#123)`）；包含前一提交 `f2d8be95` 的测试契约调整。
- 本轮没有改程序或测试文件。使用 `scripts/setup_windows_dev.ps1 -Arch x64` 强制重建 Rust 扩展、Watch Broker、C++ 7-Zip worker 和 toast DLL；C++ worker 的 6 项 CTest 与 toast 的 1 项 CTest 全部通过。
- 环境脚本最后的 inspect probe 仍失败，错误已从上一轮的 `'archive'` 变为 `[CLI] 运行失败：'decision'`，退出码 3。随后用已重建的环境执行 `run_acceptance_tests.ps1 -NoWait -SkipEnvironmentRefresh`；其中 5 项 CLI smoke 全部通过。
- Rust 单测执行 `cargo test --lib --manifest-path native/sunpack_native/Cargo.toml`：99 passed，0 failed。

### 本轮汇总

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1139 | 1139 | 0 | 0 | 0 |
| integration、real | 347 | 330 | 16 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **Python pytest 合计** | **1494** | **1469** | **16** | **0** | **9** |

额外验证：Rust 单元测试 99 项全部通过；native CTest 7 项全部通过；5 项 CLI smoke 全部通过。相比上一轮记录的 43 个 pytest 失败，本轮减少到 16 个；CLI/unit/functional 阶段现为全绿。

### 本轮剩余失败项与报错

#### 分卷 SFX 容器类型：12 项

共同报错：`AssertionError: container type mismatch: expected pe, got ''`。这些用例均为 7z/ZIP 分卷 SFX；探测结果没有给出预期的 PE 外层容器类型。

- `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-7z-lzma2]`
- `tests.real.plan1_real_archives.test_plan1_compression_modes::test_plan1_compressed_sfx_and_split_combinations[sfx-split-zip-deflate]`
- `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[7z]`
- `tests.real.plan1_real_archives.test_plan1_sfx_matrix::test_plan1_sfx_split_archives_extract_and_detect_format[zip]`
- `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[7z]`
- `tests.real.plan2_encrypted_archives.test_plan2_sfx_encrypted::test_plan2_encrypted_sfx_split_find_correct_password[zip]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-7z]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-all-zip]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-7z]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[prefix-suffix-junk-all-zip]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-7z]`
- `tests.real.plan6_confused_volumes.test_plan6_sfx_split_confusion::test_plan6_encrypted_sfx_split_confused_volumes_extract[suffix-junk-some-zip]`

#### 其他 4 项

- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_routes_new_launcher_through_pipeline[7z]` — 期望只生成一个 marker，实际断言 `assert 2 == 1`；输出目录出现原目录和 `(1)` 目录两份提取结果。
- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_routes_new_launcher_through_pipeline[zip]` — 同样生成两份结果，`assert 2 == 1`。
- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[7z]` — 预期归档失败任务，实际 `RunSummary(...).failed_tasks == []`。
- `tests.integration.test_structure_volume_resolution::test_raw_split_rar_sfx_with_opaque_camouflaged_members_runs_full_pipeline` — 输入类别不符：实际 `file_range`，预期 `sfx_with_volumes`（`assert 'file_range' == 'sfx_with_volumes'`）。

### 本轮理解

- 相比上一轮，原先的 6 个 CLI/unit/functional 失败全部通过；RAR 单卷/分卷 SFX 的 PE 识别、错误密码后更新候选、HP RAR watch 恢复及 gzip native 长度等失败也不再出现。
- 剩余 12 项集中在 7z/ZIP 的分卷 SFX：单卷 SFX 场景已不在失败项中，但分卷时 PE 外层容器类型变成空值。说明修复缩小了问题面，分卷 SFX 的容器元数据仍未接通。
- 7z/ZIP 数据卷先到、launcher 后到的两项均产生两份解压输出；这更像 launcher 重新入队后与已处理卷组重复触发。需要避免重复产出，同时保留测试要求的 launcher pipeline 路由。
- RAR SFX 的 `file_range` 分类和截断 7z SFX 没有失败记录仍是两项独立输入/状态问题。
- 环境脚本 smoke 的异常字段从 `'archive'` 变为 `'decision'`，而 acceptance 的 CLI smoke 通过。日志仅证明两个调用路径表现不同，暂不足以断定具体根因。

### 跳过与边界

- disk-full 8 项因需要管理员权限执行 diskpart 而跳过。
- `tests.real.test_game_tree_recursive_scan::test_game_tree_resources_are_not_authorized_for_recursive_extraction` 未设置 `SUNPACK_RUN_GAME_TREE_TEST=1`，按测试要求跳过本机 `D:\game` 扫描。
- `tests/memory/test_watch_growth.py` 为 opt-in performance 测试，不在默认 correctness acceptance 范围内。
- 本节记录修复后的测试结果；未修复剩余失败项。
## 再次修复后复测（741f9dec）

- 被测提交：`741f9dec897f335c5cdfdca1cd274e01b77f234c`（`fix: close low-risk post-refactor regressions (#124)`）。
- 本轮未修改程序或测试文件。执行 `scripts/setup_windows_dev.ps1 -Arch x64` 强制重建 Rust 扩展、Watch Broker、C++ 7-Zip worker 和 toast DLL；worker 6 项 CTest 与 toast 1 项 CTest 全部通过。
- 这次开发环境脚本的最终 CLI 检查成功，打印本地 CLI usage 和 `Local development environment is ready.`；acceptance 环境预检也判定环境为 current。
- `run_acceptance_tests.ps1 -NoWait` 完整执行。Rust 单测另执行 `cargo test --lib --manifest-path native/sunpack_native/Cargo.toml`：100 passed，0 failed。

### 本轮汇总

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1140 | 1140 | 0 | 0 | 0 |
| integration、real | 347 | 343 | 3 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **Python pytest 合计** | **1495** | **1483** | **3** | **0** | **9** |

额外验证：Rust 单测 100 项全部通过；native CTest 7 项全部通过；5 项 acceptance CLI smoke 全部通过。与上一轮 16 个 pytest 失败相比，当前剩 3 项。

### 本轮剩余失败项与报错

- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[7z]` — 测试预期截断的 7z SFX 被登记为失败任务，但 `assert summary.failed_tasks` 失败，实际 `RunSummary(...).failed_tasks == []`。捕获输出显示扫描完成时 0 个候选归档、0 个失败任务；输入没有进入可报告的失败路径。
- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_routes_new_launcher_through_pipeline[7z]` — 预期 marker 文件数为 1，实际 `assert 2 == 1`。数据卷先到、launcher 后到后，同一 marker 被解压到原输出目录和带 `(1)` 后缀的第二个输出目录；捕获日志显示同一个 `.7z.001` 被成功提取两次。
- `tests.real.plan7_watch_downloads.test_plan7_arrival_orders::test_plan7_data_volumes_before_launcher_routes_new_launcher_through_pipeline[zip]` — 同样预期 1 个 marker，实际 2 个；同一 `.zip.001` 被成功提取两次并生成第二个输出目录。

### 本轮理解

- 上一轮剩余的 12 个 7z/ZIP 分卷 SFX PE 容器识别失败和 1 个 RAR SFX 输入类别失败，本轮均通过。错误范围继续缩小，构建 probe 也恢复正常。
- 两个 watch 用例都证明 launcher 已进入 pipeline，但同组数据卷已先完成处理；后来重复提取同一数据卷并写出第二份结果。剩余重点是 launcher 到达时的同组任务去重/已完成状态复用。
- 截断 7z SFX 仍未被登记为失败任务：扫描将其视作 0 个候选并正常结束。这与 watch 重复提取是独立问题。
- `tests.real.test_game_tree_recursive_scan::test_game_tree_resources_are_not_authorized_for_recursive_extraction` 因未设置 `SUNPACK_RUN_GAME_TREE_TEST=1` 跳过；disk-full 8 项因需要管理员权限执行 diskpart 而跳过。`tests/memory/test_watch_growth.py` 仍是 opt-in performance 测试，不属于默认 correctness acceptance。
- 本轮只记录结果，未修复剩余失败项。
## 后续修复复测（543c7af5）

- 被测提交：`543c7af59ca0f51321b6cb0e50eee84c5da985ea`（`fix: close final post-refactor regressions (#125)`）。
- 本轮未修改程序或测试文件。再次执行 `scripts/setup_windows_dev.ps1 -Arch x64`，成功重建 Rust 扩展、Watch Broker、C++ 7-Zip worker 和 toast DLL；worker 6 项 CTest 与 toast 1 项 CTest 全部通过。最终 CLI probe 和 acceptance 环境预检均通过。
- `run_acceptance_tests.ps1 -NoWait` 完整执行；Rust 单测另执行 `cargo test --lib --manifest-path native/sunpack_native/Cargo.toml`：100 passed，0 failed。

### 本轮汇总

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1143 | 1143 | 0 | 0 | 0 |
| integration、real | 347 | 343 | 3 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **Python pytest 合计** | **1498** | **1486** | **3** | **0** | **9** |

额外验证：Rust 单测 100 项全部通过；native CTest 7 项全部通过；5 项 CLI smoke 全部通过。

### 本轮剩余失败项与报错

- `tests.integration.test_real_archive_edge_cases::test_real_archive_edge_corrupted_sfx_archives_fail[7z]` — `assert _failure_contains(summary, expected_options)` 失败。与上一轮相比，测试现在确实得到一个 failed task，错误种类为 embedded-segments extraction failure；但失败类别/诊断没有匹配该用例要求的损坏或解压失败选项。
- `tests.real.plan4_missing_volumes.test_plan4_split_missing_volumes::test_plan4_encrypted_split_missing_volumes[only_tail-rar]` — `AssertionError: expected missing-volume error or scan-stage ignore; kinds=['FailureKind.EMBEDDED_SEGMENTS_FAILED']`。只保留 RAR 尾卷时，被识别为 embedded segment 并进入提取，最终给出通用 embedded extraction failure；测试预期缺卷诊断或扫描阶段忽略。
- `tests.real.plan4_missing_volumes.test_plan4_sfx_split_missing_volumes::test_plan4_encrypted_sfx_split_missing_volumes[only_tail-rar]` — 同样报 `expected missing-volume error or scan-stage ignore; kinds=['FailureKind.EMBEDDED_SEGMENTS_FAILED']`，场景为带 SFX 的 RAR 分卷只剩尾卷。

### 本轮理解

- 上一轮两个“数据卷先到、launcher 后到”场景的重复解压失败本轮均通过，说明该修复覆盖了 7z 和 ZIP 两种 watch 输入顺序。
- 截断 7z SFX 现在会产生 failed task，不再是上一轮的 `failed_tasks == []`；剩余差异在失败归类/诊断匹配，测试仍未得到它要求的失败类别。
- 新暴露的两个 RAR `only_tail` 用例表现一致：尾卷被当成可尝试的嵌入归档，随后以 `EMBEDDED_SEGMENTS_FAILED` 结束，没有明确报告缺卷，也没有在扫描阶段忽略。普通 RAR 与 SFX RAR 共用这一失败模式。
- 本轮 pytest 仍有 3 个失败，但失败构成与上一轮不同：两个重复提取问题已通过，截断 SFX 由“无失败任务”推进到“有失败任务但类别不匹配”，同时出现两个 RAR 尾卷缺失场景。

### 跳过与边界

- disk-full 8 项因需要管理员权限执行 diskpart 而跳过。
- `tests.real.test_game_tree_recursive_scan::test_game_tree_resources_are_not_authorized_for_recursive_extraction` 因未设置 `SUNPACK_RUN_GAME_TREE_TEST=1` 跳过；`tests/memory/test_watch_growth.py` 是 opt-in performance 测试，不属于默认 correctness acceptance。
- 本节只记录本轮结果，未修复失败项。
## 最新修复复测（4baa3c02）

- 被测提交：`4baa3c02af5f404dcc5897edc2b5cae68b975bc8`（`fix: preserve final archive failure semantics (#126)`）。
- 本轮未修改程序或测试文件。使用 `scripts/setup_windows_dev.ps1 -Arch x64` 重建 Rust 扩展、Watch Broker、C++ 7-Zip worker 和 toast DLL；构建成功，worker 6 项 CTest、toast 1 项 CTest、最终 CLI probe 均通过。
- `run_acceptance_tests.ps1 -NoWait` 完整执行，环境预检为 current。Rust 单测另执行 `cargo test --lib --manifest-path native/sunpack_native/Cargo.toml`：100 passed，0 failed。

### 本轮结果

| 阶段 | 用例 | 通过 | 失败 | 收集错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| CLI、unit、functional | 1146 | 1146 | 0 | 0 | 0 |
| integration、real | 347 | 346 | 0 | 0 | 1 |
| Administrator VHD disk-full | 8 | 0 | 0 | 0 | 8 |
| **Python pytest 合计** | **1501** | **1492** | **0** | **0** | **9** |

额外验证：Rust 单测 100 项全部通过；native CTest 7 项全部通过；acceptance 的 5 项 CLI smoke 全部通过。Acceptance 所有步骤均通过。

### 跳过与边界

- `tests.real.test_game_tree_recursive_scan::test_game_tree_resources_are_not_authorized_for_recursive_extraction` 未设置 `SUNPACK_RUN_GAME_TREE_TEST=1`，按测试要求跳过本机 `D:\game` 扫描。
- Administrator VHD disk-full 8 项因需要管理员权限执行 diskpart 而跳过。
- `tests/memory/test_watch_growth.py` 是 opt-in performance 测试，不属于默认 correctness acceptance。
- 本轮 acceptance 与 Rust 单测无失败项。