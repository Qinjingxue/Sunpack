# 解压空间保护策略移除清单

本文档记录「解压空间保护策略」在当前工作区的全部落地位置，作为一次性移除的作业清单。**已于本次执行完成，结果见第 7 节。**

## 0. 范围决定

后处理清理压缩包的改进（`ArchiveCleanupResult`、`RunSummary.cleanup_results`、清理重试循环、CLI 与 watch 的清理结果上报）**不属于解压前的空间保护策略，予以保留**，即本文档原 F 组整体保留。

本清单只覆盖解压前的空间保护策略本体、其原生支撑链路，以及为其引入的 Rust 清理身份支撑与全部相关测试。

## 1. 调查基准

| 项 | 值 |
| --- | --- |
| 当前 HEAD | `d84325dbf92ef9487660a6a32b8dfa3212889aa8`（默认空间余量为0） |
| 引入提交 | `56fd335f0f4b694ea66c2cbafdb750d8be75bd49`（改为新空间保护策略） |
| 参数提交 | `d84325dbf92ef9487660a6a32b8dfa3212889aa8`（把默认 `reserve_bytes` 从 `256<<20` 改为 `0`） |
| 中间提交 | `dfdfb964`（增量状态保存）不涉及本功能 |
| 已知无关 | `origin/main` 上的 `7ec28828` / `d2afb05b`「剩余空间管理策略」**未进入本工作区**，见第 6 节 |

`56fd335f` 的改动规模为 38 个文件、+902/−285。该提交在引入新策略的同时删除了旧的 Python 侧实现，因此下面区分「需要删除的现存代码」与「已不存在、无需操作」。

## 2. 分类速览

| 组 | 范围 | 文件数 | 备注 |
| --- | --- | --- | --- |
| A | 整文件删除 | 2 | 原生策略实现与专用测试 |
| B | 原生 C++ / CMake | 6 | 配额查询、扣减、失败分类、JSON 上报 |
| C | Python 配置与传递 | 4 | 配置项、job 字段、runner 策略 |
| D | 失败分类与短路 | 3 | `failure_kind` 走查链 |
| E | Rust 清理身份支撑 | 4 | 仅为「清理重试前校验源文件未变」而引入 |
| G | i18n | 1 | 新增键 + 移除后孤立键 |
| H | 测试与基准 | 5 | 含一个混合文件需拆分 |
| I | 非源码残留 | — | 构建产物与陈旧字节码 |
| — | F 组（清理结果管道） | 10 | **保留**，见第 0 节 |
| — | E/F 交界 | 2 | `postprocess/internal/cleanup.py`、`contracts/results.py` 保留但需去掉身份字段，见 E 组末尾 |

合计需要改动的文件：A 组 2 个删除 + B–E/G/H 组 19 个 + 交界 2 个 = 23 个。

## 3. 移除清单

### A. 整文件删除

| 文件 | 行数 | 说明 |
| --- | --- | --- |
| `native/sevenzip_bridge/src/internal/disk_space.hpp` | 193 | `DiskSpacePolicy` / `DiskSpaceSample` / `DiskSpaceVolume` / `DiskSpaceLease` 与 `current_disk_space_policy`，全部由 `56fd335f` 新增 |
| `native/sevenzip_bridge/tests/disk_space.cpp` | 75 | 该策略的专用测试可执行文件 |

### B. 原生 C++ / CMake

**`native/sevenzip_bridge/CMakeLists.txt`** — 删除 137–141 行：

```cmake
add_executable(sunpack_sevenzip_disk_space tests/disk_space.cpp)
apply_release_optimizations(sunpack_sevenzip_disk_space)
target_link_libraries(sunpack_sevenzip_disk_space PRIVATE sunpack_sevenzip_core)
target_include_directories(sunpack_sevenzip_disk_space PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME sunpack_sevenzip_disk_space COMMAND sunpack_sevenzip_disk_space)
```

**`native/sevenzip_bridge/include/sevenzip_bridge/bridge.hpp`** — 删除 183–186 行（`ExtractArchiveResult` 内）：

```cpp
std::wstring disk_space_volume;
unsigned long long disk_space_available = 0, disk_space_requested = 0;
unsigned long long disk_space_queries = 0, disk_space_grants = 0, disk_space_rejections = 0;
unsigned int disk_space_error = 0;
```

**`native/sevenzip_bridge/src/internal/archive_extract.cpp`** — 删除 512–534 行，即 `archive->Close();`（510 行）之后到 538 行 `if (hr == S_OK && last_op_res == kOpOk) {` 之前的整段：`raw_extract_callback->disk_space()` 采集块，以及依据 `disk_space_error` / `ERROR_DISK_FULL` / `ERROR_HANDLE_DISK_FULL` 把结果改写为 `failure_stage="output_write"`、`failure_kind="disk_space"`（或 `"disk_space_query"`）并提前 `return result` 的判定。538 行的成功/损坏分支保持原样。

**`native/sevenzip_bridge/src/internal/sevenzip_async_output.hpp`**

| 行 | 内容 |
| --- | --- |
| 4 | `#include "disk_space.hpp"` |
| 36 | `JobState::disk_space`（`std::shared_ptr<DiskSpaceLease>`） |
| 129–130 | `FileState::charged_length` 与 `FileState::expected_size`（两者只为配额计算服务） |
| 234 | `make_file` 第 6 参 `UInt64 expected_size = 0` |
| 239–241 | `file->expected_size = expected_size;` 与按需构造 lease |
| 273–284 | `write()` 中 `lease->rounded(accepted + size)` 的配额扣减与超额拦截 |
| 998 | `job->disk_space->written(written);` |

`make_file` 需恢复为 5 参调用（`job, path, item_path, item_index, trace_index`）。注意 `bridge.hpp` 中 `ExtractOutputItemTrace::expected_size` / `has_expected_size` 是既有字段（`56fd335f^` 已存在），**不要删**。

**`native/sevenzip_bridge/src/internal/sevenzip_callbacks.hpp`**

`SynchronousFileOutStream`：

| 行 | 内容 |
| --- | --- |
| 466 | 构造函数初始化列表里的 `disk_space_(std::make_shared<DiskSpaceLease>(path, current_disk_space_policy))` |
| 568–575 | `Write()` 中的配额扣减与 `mark_item_failure` |
| 600 | `disk_space_->written(written);` |
| 666–667 | `disk_space_` 与 `charged_length_` 成员 |

`ExtractToDiskCallback`：

| 行 | 内容 |
| --- | --- |
| 1024 | 构造函数体首行构造 `async_job_->disk_space` |
| 1050 | `std::shared_ptr<DiskSpaceLease> disk_space() const` 访问器 |
| 1204–1209 | `SetTotal()` 中 `!dry_run_ && async_job_ && !async_job_->disk_space->check_total(total)` 的整体积预检（`total_bytes_ = total;` 与后续 `emit("total", …)` 保留） |
| 1444–1445 | `make_file(..., has_expected_size ? expected_size : 0)` 调用恢复为 5 参 |

**`native/sevenzip_bridge/src/worker.cpp`**

| 行 | 内容 |
| --- | --- |
| 916–920 | `current_disk_space_policy = {};` 与读取 `disk_space_reserve_bytes` / `disk_space_quantum_bytes` / `disk_space_sample_ms`（含 `disk_value` 局部变量） |
| 1012 | `if (!direct_ok && result.failure_kind != "disk_space" && result.failure_kind != "disk_space_query")` 恢复为 `if (!direct_ok)` |
| 1047–1054 | `const std::string disk_fields = …` |
| 1103 | 结果行拼接中的 `+ disk_fields` |

### C. Python 配置与传递

**`sunpack/config/fields/extraction.py`** — 删除 `normalize_disk_space`（26–38 行）与 `CONFIG_FIELDS` 首项（42–44 行）。删除后 `advanced_config_value` 仍被 `DEFAULT_EXTRACTION_CONFIG` 使用，导入保留。

**`sunpack_advanced_config.json`** — 删除 `performance.disk_space` 整块（68–72 行，含 `reserve_bytes` / `quantum_bytes` / `sample_ms`）。

**`sunpack/extraction/internal/sevenzip/sevenzip_runner.py`** — 删除 `_apply_native_job_budget`（1432 行起）顶部 1433–1436 行的 `policy = getattr(self, "disk_space_policy", {})` 与三个 `job[...]` 赋值；函数其余部分保持。

**`sunpack/coordinator/engine.py`** — 删除 486 行 `request_runner.disk_space_policy = dict(performance.get("disk_space", {}))`。该行是 F 组保留后 `engine.py` 中唯一需要改动的位置；`_commit_response`、`_postprocess_completed`、`_finalize_response` 的清理结果逻辑一律不动。

### D. 失败分类与短路

**`sunpack/extraction/internal/workflow/errors.py`**

| 行 | 内容 |
| --- | --- |
| 29–30 | `should_retry_extract_failure` 中 `failure_kind in {"disk_space", "disk_space_query"} → False` |
| 67–70 | `classify_extract_failure` 中同集合 → `FailureKind.FILESYSTEM_ERROR` + `failure.insufficient_space` / `failure.space_query` |

**`sunpack/coordinator/extraction_batch.py`** — 删除 504–506 行：失败结果中命中 `disk_space` / `disk_space_query` 时提前返回 `current_outcome`。

**`sunpack/verification/error_classification.py`** — 删除 `_EXECUTION` 集合中的 `"disk_space"`（55 行）与 `"disk_space_query"`（56 行）。

行为提示：`errors.py` 179–180 行在 `56fd335f` 中已把退出码 `8` 的归类从 `failure.insufficient_space` 改为 `failure.process_exit_code`。移除 D 组后，`ERROR_DISK_FULL` 不再有专门分类，会落回通用退出码/损坏判定路径。

### E. Rust 清理身份支撑

`cleanup_file_identity` 整条链路只服务于「清理重试前校验源文件身份未变化」，随本功能引入。注意：F 组保留的是**清理的编排与上报**，`cleanup.py` 中依赖身份校验的那部分（`_identity`、`source_matches`）会随本节一起失效，需同批处理，见下方说明。

| 文件 | 行 | 内容 |
| --- | --- | --- |
| `native/sunpack_native/src/lib.rs` | 238 | `m.add_function(wrap_pyfunction!(postprocess::cleanup_file_identity, m)?)?;` |
| `native/sunpack_native/src/postprocess/mod.rs` | 108–119 | `cleanup_file_identity` 函数本体 |
| `native/sunpack_native/src/filesystem/mod.rs` | 26–37 | `file_identity` 的 `windows` / `not(windows)` 两个分支 |
| `native/sunpack_native/src/filesystem/windows.rs` | 29–47 | `FileTime` 与 `ByHandleFileInformation` 结构体 |
| 同上 | 71 | `fn GetFileInformationByHandle(…) -> i32;` 外部声明 |
| 同上 | 201–244 | `file_identity(path)` 函数本体 |

已验证：`file_identity` 在 `56fd335f^` 的 `windows.rs` 中不存在，且全仓除 `cleanup_file_identity` 外无其他调用点。

**E 组与 F 组保留部分的交界（仅一处，需最小改动）**

`sunpack/postprocess/internal/cleanup.py` 是 F 组文件，但其中身份校验依赖被删的原生函数：

| 行 | 处理 |
| --- | --- |
| 6 | 删除 `from sunpack_native import cleanup_file_identity as _native_cleanup_file_identity` |
| 12–16 | 删除 `_identity` 辅助函数 |
| 54–61 | 删除 `identity = _identity(path)` 与其 `except`/身份比对分支 |
| 62–68 | 保留 `FileNotFoundError → "missing"` 与通用异常 → `"failed"` 两个分支，`identity` 变量改为常量占位或在构造结果时省略 |
| 71, 85, 96, 101, 107 | `pending` 元组中的 `identity` 元素，以及 `ArchiveCleanupResult(..., source_identity=identity)` 的全部实参（含 77–83 行 `except` 分支里的生成器） |
| 75–106 | `delete_files_batch` 的调用与结果映射方式**保持不变**（属 F 组改进） |

`sunpack/contracts/results.py` 的 `ArchiveCleanupResult`（14–37 行）与 `RunSummary.cleanup_results` 字段属 F 组**保留**；但其中 `source_identity` 这个 `InitVar`、`_source_identity`、`retryable` 的 `bool(self._source_identity)` 条件、`source_matches()` 方法在 E 组删除后失去数据来源。建议保留数据类与 `retryable` 属性（`retryable` 仅需改为按 `status`/`error_code` 判定），删除 `source_identity` / `source_matches` 与对应的 `InitVar` 导入。此处是本次范围内唯一需要判断的取舍点。

### G. i18n（`sunpack/i18n/catalog.py`，en 与 zh 各一处）

需随功能删除：

| 键 | en / zh 行 | 说明 |
| --- | --- | --- |
| `failure.space_query` | 3 / 316 | 本次新增，唯一引用为 `errors.py:69` |
| `space.full_keep` | 204 / 517 | 原唯一引用 `space_recovery.py`（已删除） |
| `space.full_no_archives` | 205 / 518 | 同上 |
| `space.freeing` | 206 / 519 | 同上 |
| `failure.insufficient_space` | 269 / 582 | 原唯一引用 `errors.py:69`（D 组删除后孤立） |

**保留**：

| 键 | en / zh 行 | 原因 |
| --- | --- | --- |
| `cleanup.incomplete` | 4 / 317 | F 组保留，仍被 `reporting.py:252` 与 `watcher/scheduler.py:1499` 使用 |
| `cleanup.recycle_failed` / `cleanup.delete_failed` | 199–201 / 512–514 | 清理失败文案，属清理功能 |

### H. 测试与基准

| 文件 | 处理 |
| --- | --- |
| `tests/unit/test_disk_space_cleanup.py` | **混合文件，部分删除**。删除空间保护用例：`test_disk_policy_validation`（126–129）、`test_disk_failures_are_terminal_before_password_or_damage`（116–123）。随之失效的导入（已逐个核对引用点）：`normalize_disk_space`（7 行）、`SimpleNamespace`（3 行）、`should_retry_extract_failure`（11 行，仅 120 行使用）、以及 `from dataclasses import … replace` 中的 `replace`（2 行，`asdict` 仍被 141 行使用）。**保留** `classify_extract_failure`、`pytest`、`asdict`、`RunSummary`、`PipelineArtifacts`/`PipelineResponse`、`DirectOutputCommitter`/`MappedOutputCommitter`、`PostProcessActions`、`cleanup`、`_InlineBroker`，并保留清理管道用例 37–114、132–143。注意 132–143 的 `test_cleanup_result_public_schema_excludes_retry_identity` 会随 E 组末尾的 `ArchiveCleanupResult` 调整同步修改（该用例名中的 `retry_identity` 即指 `source_identity`） |
| `tests/integration/test_extraction_execution.py` | 137–166 行 `test_extractor_retries_unclassified_process_failure_without_space_heuristic`：删除已无用的 `ensure_space` 闭包（143–147）与 `self.assertEqual(calls, [])`（166），并按其实测语义（退出码 8 仍触发重试）改名。该用例验证的是通用瞬态重试，**不删用例本身** |
| `tests/unit/test_extraction_preflight_costs.py` | 12 行用例名 `test_successful_first_attempt_does_not_query_python_disk_space` 仍以空间为主题，按保留语义改名；其余断言不动 |
| `benchmarks/scenarios/extraction_large_archive.py` | 299 行 `_wrap(_child(runtime, "space_guard"), "bind_root", …, "pipeline_space_bind")` —— `space_guard` 已不存在，该行恒为 no-op，删除；482 行残差汇总列表中的 `"pipeline_space_bind"` 一并删除 |
| `tests/unit/test_profile_large_archive_tool.py` | 100 行断言数据中的 `"pipeline_space_bind": [0.01]` 删除 |

**不要动**的测试：`tests/helpers/fake_pipeline_engine.py:69` 的 `summary.cleanup_results = []`、`tests/unit/test_engine_finalize.py` 的 `return []` 与 `previous_cleanup: None` 断言——它们服务于保留的 F 组。

### I. 非源码残留

- `native/sevenzip_bridge/build-x64/` 下 `sunpack_sevenzip_disk_space.*`（`.vcxproj`、`.exe`、`.pdb`、`.obj`、`.tlog`、`.cmake/api` 应答文件）。该目录已被 `.gitignore:69` 的 `native/sevenzip_bridge/build-*/` 忽略，重配 CMake 即自然消失。
- 陈旧字节码：`sunpack/coordinator/__pycache__/space_guard.cpython-310.pyc`、`sunpack/postprocess/__pycache__/space_recovery.cpython-310.pyc`、`tests/unit/__pycache__/test_watch_disk_space_queue.cpython-310-pytest-9.1.1.pyc`（对应源文件均已不存在）。

### 已不存在、无需操作

`56fd335f` 本身已删除，当前工作区确认无这些文件：`sunpack/coordinator/space_guard.py`（`DiskSpaceGuard` / `ExtractionSpaceGuard`）、`sunpack/postprocess/space_recovery.py`（`ArchiveSpaceRecovery`）、`sunpack_extraction` 侧的 `ensure_space` 注入链（`ExtractionScheduler.ensure_space`、`SingleArchiveExtractor.ensure_space`、`ExtractRetryPolicy.needs_space_recheck`、`RetryPolicy` 的空间复检分支）以及若干测试中的 `ensure_space=` 实参。

## 4. 刻意保留

以下项出现在 `56fd335f` 的 diff 中，但**不是**空间保护逻辑，不应随本次移除改动：

| 位置 | 原因 |
| --- | --- |
| F 组全部：`ArchiveCleanupResult`、`RunSummary.cleanup_results`、`cleanup_results` 重试循环、`previous_cleanup` / `_postprocess_completed` 闸门、CLI 与 watch 上报、toast 告警 | 后处理清理压缩包的改进，非解压前空间保护 |
| `sunpack/support/archive_error_signals.py` 的 `has_transient_system_signals`（"no space" / "write error" / "disk full" / "not enough space"） | `56fd335f^` 已存在的通用瞬态错误信号，供重试判定复用 |
| `sunpack/extraction/internal/workflow/errors.py:46` 的 `code in (-100, -101, -102, 8)` | 同上，退出码 8 的通用重试，`56fd335f` 只改了它的**分类文案**，未改重试行为 |
| `native/sunpack_native/src/analysis_native/volume_anchor.rs`、`sunpack/analysis/volume_anchor.py`、`volume_anchor_structure` 事实 | 分卷锚点证据，服务于分卷解压与 RAR5 头解密，与磁盘剩余空间无关 |
| `sunpack/support/global_cache_manager.file_identity` | 缓存身份键，与 E 组的原生 `file_identity` 同名但无关 |
| `output_reservations` / `OutputReservationRegistry` / `reservation_registry` | 输出路径预留，与磁盘空间准入无关 |
| `native_runtime_control.hpp` 的 `memory_admission_paused` / `native_memory_reserve_bytes` | 内存准入预算，另一条独立的资源策略 |

## 5. 执行建议

1. 先做 A + B + C + D（策略本体），此时策略已完全失效，可独立验证与回滚。
2. 再做 E（Rust 身份支撑），并同步处理 `cleanup.py` 与 `ArchiveCleanupResult` 中随 E 失效的身份字段（见 E 组末尾）。此步需重建原生扩展。
3. G 组 i18n 删除需确认 `catalog.py` 的 en / zh 键集合一致性校验不会因此报错。
4. H 组只改测试与基准，其中 `test_disk_space_cleanup.py` 要**按用例拆**，不要整文件删除。
5. 收尾验证：`pytest tests/unit/test_disk_space_cleanup.py tests/unit/test_engine_finalize.py tests/integration/test_extraction_execution.py tests/unit/test_profile_large_archive_tool.py tests/unit/test_extraction_preflight_costs.py`，再按 `docs/development_setup.md` 重建原生部分并跑 `ctest`。

## 6. 范围外提示

`origin/main` 上有两个后续提交对同一主题做了显著扩展，均**未进入当前分支**（`git merge-base --is-ancestor 7ec28828 HEAD` 为假）：

| 提交 | 规模 | 新增内容 |
| --- | --- | --- |
| `7ec28828` 实现初版剩余空间管理策略 | 43 文件，+2108/−177 | `sunpack/coordinator/disk_admission.py`（591 行）、`tests/unit/test_disk_admission.py`、`tests/unit/test_watch_disk_space_queue.py`、`disk_space.hpp` 扩展、watch 队列与 CLI 上报扩展 |
| `d2afb05b` 增强剩余空间管理，修复bug | — | 在上一提交基础上继续加固 |

若后续合并 `origin/main`，本清单需按这两个提交重新扩表；`disk_admission.py` 与 `test_watch_disk_space_queue.py` 会是新的必删项。

## 7. 执行记录

已按第 0 节范围完成全部移除，改动 27 个文件、删除 2 个文件（+22 / −604 行）。

**两处细节按建议处理**

1. `tests/unit/test_disk_space_cleanup.py` 按用例拆分，未整文件删除。删除 `test_disk_policy_validation`、`test_disk_failures_are_terminal_before_password_or_damage` 两个空间保护用例，以及随之失效的 `normalize_disk_space`、`SimpleNamespace`、`should_retry_extract_failure`、`replace` 四处导入；保留全部 F 组清理用例。另因 E 组移除了源文件身份，原 `test_retry_does_not_delete_changed_source` 所测前提已不存在，一并删除；`test_cleanup_result_public_schema_excludes_retry_identity` 更名为 `test_cleanup_result_public_schema_is_stable` 并去掉 `source_identity` 入参。
2. E/F 交界按建议处理：`ArchiveCleanupResult` 保留数据类与 `retryable`，删除 `source_identity` / `source_matches` / `__post_init__` 与 `InitVar` 导入，`retryable` 改为只按 `status` 与 `error_code` 判定；`cleanup.py` 删除 `_identity` 与身份比对分支，存在性检查改用 `os.path.exists`，重试循环、`previous_cleanup`、CLI 与 watch 上报全部保留。

**执行中发现并处理的两点**

- `tests/unit/test_profile_large_archive_tool.py` 的计时残差断言依赖 `pipeline_space_bind` 那 0.01 计入子项之和。该键删除后残差由 0 变 0.01，已把测试数据中的 `pipeline_nested_authorize` 相应调整为 0.02，保持「子项之和 = 父项」的恒等式成立。
- `sunpack/extraction/internal/workflow/single_archive_extractor.py:484` 传入的是**字符串** `"failure.insufficient_space"` 而非 i18n 键名（与 `"retry_exhausted"` 同样都没有对应词条），因此它不是该词条的引用点，也不受本次删除影响：`I18nContext.t()` 对缺失键返回键名本身，该处显示的仍是同一串英文。属既有问题，未在本次范围内改动。

**验证结果**

- `pytest tests -q`：1583 passed, 47 skipped, 0 failed。
- 原生 Rust 扩展 `maturin build --release` 成功；重装 wheel 后确认 `sunpack_native.cleanup_file_identity` 已不存在。
- C++ bridge 全新目录 `cmake` 配置 + Release 构建成功（含 `worker.cpp` 链接），`ctest` 2/2 通过，确认 `disk_space` 测试目标已随 CMakeLists 消失。
- 陈旧构建产物（`build-x64` 下全部 `*disk_space*`、三个过期 `.pyc`）已清理。
- 全仓 `git grep` 复查：除 `repair_training/` 与 `contracts/archive_state.py` 等**无关模块**中的 `source_identity`，以及上述 484 行的既有字符串外，无 `disk_space` / `space_guard` / `space_recovery` / `cleanup_file_identity` 残留。

**执行中修复的环境问题（非代码问题）**：`tools\sunpack_sevenzip.dll` 是 9 月 11 日 9:51 一次**中断的构建**留下的残缺产物（缺少 `sup7z_analyze_archive_resources` 等导出），导致 21 个原生相关测试失败。已用本次全新构建的 DLL 覆盖，该 21 个测试恢复通过。
