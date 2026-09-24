==> Cleaning stale SunPack test artifacts

==> Acceptance environment preflight
Environment refresh required: - environment manifest is missing or does not match current sources/artifacts

==> Environment preflight
Requested architecture: x64
Python/process architecture: x64

==> Preparing local virtual environment
Using CPython 3.10.11 interpreter at: C:\Users\29402\AppData\Local\Programs\Python\Python310\python.exe
Removed virtual environment at: .venv
Creating virtual environment at: .venv
Resolved 19 packages in 0.90ms
Installed 19 packages in 8.89s

- cmake==4.4.2
- colorama==0.4.6
- exceptiongroup==1.3.1
- execnet==2.1.2
- iniconfig==2.3.0
- maturin==1.14.1
- nuitka==4.1.3
- packaging==26.3
- pluggy==1.6.0
- psutil==7.2.2
- pygments==2.21.0
- pytest==9.1.1
- pytest-xdist==3.8.0
- send2trash==2.1.0
- sunpack==1.0.0 (from file:///C:/Users/29402/Desktop/sunpack)
- tomli==2.4.1
- typing-extensions==4.16.0
- watchdog==6.0.0
- zstandard==0.25.0

==> Building and installing Rust native extension
warning: Skipping sunpack-native as it is not installed
warning: No packages to uninstall
cargo 1.94.1 (29ea6fb6a 2026-03-24)
🐍 Found CPython 3.10 at C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe
🔗 Found pyo3 bindings
📡 Using build options bindings from pyproject.toml
Compiling sunpack-native v0.0.0 (C:\Users\29402\Desktop\sunpack\native\sunpack_native)
Finished `release` profile [optimized] target(s) in 55.18s
📦 Built wheel for CPython 3.10 to C:\Users\29402\Desktop\sunpack\build\native-wheels-dev-x64\sunpack_native-0.0.0-cp310-cp310-win_amd64.whl
Resolved 1 package in 8ms
Prepared 1 package in 16ms
Installed 1 package in 6ms

- sunpack-native==0.0.0 (from file:///C:/Users/29402/Desktop/sunpack/build/native-wheels-dev-x64/sunpack_native-0.0.0-cp310-cp310-win_amd64.whl)

==> Building minimal Windows Watch Broker service
Finished `release` profile [optimized] target(s) in 0.02s
Bundled 7-Zip files are already present.
Acceptance archive generator tools are already present.

==> Building embedded 7-Zip worker
-- Using CMake version 4.4.2
-- ZLIB_HEADER_VERSION: 1.3.1
-- ZLIBNG_HEADER_VERSION: 2.3.3
-- Arch detected: 'x86_64'
-- Basearch of 'x86_64' has been detected as: 'x86'
-- Architecture-specific source files: arch/x86/x86_features.c;arch/x86/chunkset_sse2.c;arch/x86/chorba_sse2.c;arch/x86/compare256_sse2.c;arch/x86/slide_hash_sse2.c;arch/x86/adler32_ssse3.c;arch/x86/chunkset_ssse3.c;arch/x86/chorba_sse41.c;arch/x86/adler32_sse42.c;arch/x86/crc32_pclmulqdq.c;arch/x86/slide_hash_avx2.c;arch/x86/chunkset_avx2.c;arch/x86/compare256_avx2.c;arch/x86/adler32_avx2.c;arch/x86/adler32_avx512.c;arch/x86/chunkset_avx512.c;arch/x86/compare256_avx512.c;arch/x86/adler32_avx512_vnni.c;arch/x86/crc32_vpclmulqdq.c
-- The following features have been enabled:

- XSAVE, Support XSAVE intrinsics using ""
- SSSE3_ADLER32, Support SSSE3-accelerated adler32, using ""
- SSE42_CRC, Support SSE4.2 optimized adler32 hash generation, using ""
- PCLMUL_CRC, Support CRC hash generation using PCLMULQDQ, using " "
- AVX2_SLIDEHASH, Support AVX2 optimized slide_hash, using "/arch:AVX2"
- AVX2_CHUNKSET, Support AVX2 optimized chunkset, using "/arch:AVX2"
- AVX2_COMPARE256, Support AVX2 optimized compare256, using "/arch:AVX2"
- AVX2_ADLER32, Support AVX2-accelerated adler32, using "/arch:AVX2"
- AVX512_ADLER32, Support AVX512-accelerated adler32, using "/arch:AVX512"
- AVX512_CHUNKSET, Support AVX512 optimized chunkset, using "/arch:AVX512"
- AVX512_COMPARE256, Support AVX512 optimized compare256, using "/arch:AVX512"
- AVX512VNNI_ADLER32, Support AVX512VNNI adler32, using "/arch:AVX512"
- VPCLMUL_CRC, Support CRC hash generation using VPCLMULQDQ, using " /arch:AVX512"
- WITH_SANITIZER, Enable sanitizer testing support
- WITH_OPTIM, Build with optimisation
- WITH_NEW_STRATEGIES, Use new strategies
- WITH_CRC32_CHORBA, Use optimized CRC32 algorithm Chorba
- WITH_RUNTIME_CPU_DETECTION, Build with runtime CPU detection
- WITH_SSE2, Build with SSE2
- WITH_SSSE3, Build with SSSE3
- WITH_SSE41, Build with SSE41
- WITH_SSE42, Build with SSE42
- WITH_PCLMULQDQ, Build with PCLMULQDQ
- WITH_AVX2, Build with AVX2
- WITH_AVX512, Build with AVX512
- WITH_AVX512VNNI, Build with AVX512 VNNI
- WITH_VPCLMULQDQ, Build with VPCLMULQDQ

-- The following features have been disabled:

- ZLIB_SYMBOL_PREFIX, Publicly exported symbols DO NOT have a custom prefix
- WITH_GZFILEOP, Compile with support for gzFile related functions
- ZLIB_COMPAT, Compile with zlib compatible API
- ZLIB_ALIASES, Compile with zlib compatible CMake targets
- BUILD_TESTING, Build test binaries
- WITH_GTEST, Build tests using Gtest framework
- WITH_FUZZERS, Build test/fuzz
- WITH_BENCHMARKS, Build benchmarks using Google Benchmark framework
- WITH_BENCHMARK_APPS, Build application benchmarks (currently libpng)
- WITH_ALL_FALLBACKS, Build all generic fallback functions
- WITH_NATIVE_INSTRUCTIONS, Instruct the compiler to use the full instruction set on this host (gcc/clang -march=native)
- WITH_MAINTAINER_WARNINGS, Build with project maintainer warnings
- WITH_CODE_COVERAGE, Enable code coverage reporting
- WITH_INFLATE_STRICT, Build with strict inflate distance checking
- WITH_INFLATE_ALLOW_INVALID_DIST, Build with zero fill for inflate invalid distances
- INSTALL_UTILS, Copy minigzip and minideflate during install

-- 7-Zip asm: enabled (x64 MASM) - LzmaDecOpt, 7zCrcOpt, XzCrc64Opt, AesOpt, Sha1Opt, Sha256Opt; Sort/LzFindOpt intentionally omitted
-- Configuring done (0.1s)
-- Generating done (0.2s)
-- Build files have been written to: C:/Users/29402/Desktop/sunpack/native/sevenzip_bridge/build-x64
适用于 .NET Framework MSBuild 版本 17.14.23+b0019275e

Checking File Globs
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip*bridge\7z2603-src\Asm\x86\LzmaDecOpt.asm...
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\7z2603-src\Asm\x86\7zCrcOpt.asm...
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\7z2603-src\Asm\x86\XzCrc64Opt.asm...
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\7z2603-src\Asm\x86\AesOpt.asm...
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\7z2603-src\Asm\x86\Sha1Opt.asm...
Assembling C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\7z2603-src\Asm\x86\Sha256Opt.asm...
sunpack_7zip_asm_objects.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\sunpack_7zip_asm*
objects.dir\Release\sunpack_7zip_asm_objects.lib
sunpack_7zip_objects.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\sunpack_7zip_objects.
dir\Release\sunpack_7zip_objects.lib
sunpack_launcher.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpack_launcher.
exe
zlib-ng.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\zlib-ng\Release\zlibstatic-ng.lib
sunpack_sevenzip_core.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpack_seve
nzip_core.lib
async_output.cpp
正在生成代码
已完成代码的生成
sunpack_sevenzip_async_output.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunp
ack_sevenzip_async_output.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_com_contract.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunp
ack_sevenzip_com_contract.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_smoke.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpack_sev
enzip_smoke.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_space_gate.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpac
k_sevenzip_space_gate.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_space_retry.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpa
ck_sevenzip_space_retry.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_worker.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpack_se
venzip_worker.exe
正在生成代码
已完成代码的生成
sunpack_sevenzip_writer_cost.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\sunpa
ck_sevenzip_writer_cost.exe
正在生成代码
已完成代码的生成
sunpack_zlib_ng_deflate_contract.vcxproj -> C:\Users\29402\Desktop\sunpack\native\sevenzip_bridge\build-x64\Release\s
unpack_zlib_ng_deflate_contract.exe
Test project C:/Users/29402/Desktop/sunpack/native/sevenzip_bridge/build-x64
Start 1: sunpack_sevenzip_smoke
1/6 Test #1: sunpack_sevenzip_smoke ............. Passed 0.01 sec
Start 2: sunpack_sevenzip_async_output
2/6 Test #2: sunpack_sevenzip_async_output ...... Passed 0.32 sec
Start 3: sunpack_sevenzip_space_gate
3/6 Test #3: sunpack_sevenzip_space_gate ........ Passed 0.28 sec
Start 4: sunpack_sevenzip_space_retry
4/6 Test #4: sunpack_sevenzip_space_retry ....... Passed 1.00 sec
Start 5: sunpack_sevenzip_com_contract
5/6 Test #5: sunpack_sevenzip_com_contract ...... Passed 0.01 sec
Start 6: sunpack_zlib_ng_deflate_contract
6/6 Test #6: sunpack_zlib_ng_deflate_contract ... Passed 0.01 sec

100% tests passed out of 6

Total Test time (real) = 1.64 sec
7-Zip asm check passed: LzmaDec_DecodeReal_3 present in sunpack_sevenzip_worker.exe (1 match(es), 32 byte prologue).
7-Zip asm check passed: LzmaDec_DecodeReal_3 present in sunpack_sevenzip_worker.exe (1 match(es), 32 byte prologue).

==> Building in-process Windows toast library
-- Configuring done (0.0s)
-- Generating done (0.0s)
-- Build files have been written to: C:/Users/29402/Desktop/sunpack/native/toast_host/build-x64
适用于 .NET Framework MSBuild 版本 17.14.23+b0019275e

sunpack_toast.vcxproj -> C:\Users\29402\Desktop\sunpack\native\toast_host\build-x64\Release\sunpack_toast.dll
sunpack_toast_self_test.vcxproj -> C:\Users\29402\Desktop\sunpack\native\toast_host\build-x64\Release\sunpack_toast_s
elf_test.exe
Test project C:/Users/29402/Desktop/sunpack/native/toast_host/build-x64
Start 1: sunpack_toast_self_test
1/1 Test #1: sunpack_toast_self_test .......... Passed 0.05 sec

100% tests passed out of 1

Total Test time (real) = 0.05 sec

==> Writing environment manifest

==> Verifying local source execution
用法: sunpack [-h] <command> [command options] [paths...]

sunpack 命令行界面。

位置参数:
{extract,watch,scan,inspect,passwords,config,doctor,version}
extract 执行预检查、扫描、解压和清理。
watch 管理持久监控目录和后台监控服务。
scan 只扫描候选归档，不修改文件系统。
inspect 输出文件检测详情，不修改文件系统。
passwords 查看当前会参与尝试的密码列表。
config 查看或校验 SunPack 有效配置。
doctor 检查当前 SunPack 安装是否具备正常运行的基本条件。
version 输出当前安装的 SunPack 版本号。

选项:
-h, --help 显示此帮助信息并退出

示例：
sunpack extract C:\Archives
sunpack inspect .\fixtures
sunpack passwords --ask-pw
pytest 9.1.1

Local development environment is ready.
Virtual env: C:\Users\29402\Desktop\sunpack\.venv
Activate: C:\Users\29402\Desktop\sunpack\.venv\\Scripts\\Activate.ps1
Acceptance generator tools are present and executable.

==> Installing temporary Watch Broker service

==> Parallel CLI, unit, and functional tests
bringing up nodes...

======================================================= ERRORS ========================================================
**********\*\***********\_\_\_\_**********\*\*********** ERROR collecting gw6 **********\*\*\*\***********\_**********\*\*\*\***********
Different tests were collected between gw1 and gw6. The difference is:
--- gw1

+++ gw6

@@ -530,7 +530,7 @@

tests/unit/test_relations.py::test_standalone_zip_is_confirmed_by_relations
tests/unit/test_relations.py::test_empty_zip_is_confirmed_by_relations
tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[7z\xbc\xaf'\x1c\x00\x04L\x06\xfce\x05\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x1b\xdf\x05\xa5abcde\x01-7-Zip SFX-7z]
-tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[PK\x03\x04\x14\x00\x00\x00\x00\x00\x07\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00inside.txthelloPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x07\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00inside.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x008\x00\x00\x00-\x00\x00\x00\x00\x00-7-Zip SFX-zip]
+tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[PK\x03\x04\x14\x00\x00\x00\x00\x00\x08\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00inside.txthelloPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x08\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00inside.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x008\x00\x00\x00-\x00\x00\x00\x00\x00-7-Zip SFX-zip]
tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[Rar!\x1a\x07\x00\xcf\x90s\x00\x00\r\x00\x00\x00\x00\x00\x00\x00-WinRAR SFX-rar]
tests/unit/test_relations.py::test_arbitrary_pe_zip_overlay_is_left_for_embedded_discovery
tests/unit/test_relations.py::test_filename_numbered_7z_without_structural_seed_is_not_grouped
To see why this happens see 'Known limitations' in documentation for pytest-xdist
**********\*\***********\_\_\_\_**********\*\*********** ERROR collecting gw7 **********\*\*\*\***********\_**********\*\*\*\***********
Different tests were collected between gw1 and gw7. The difference is:
--- gw1

+++ gw7

@@ -530,7 +530,7 @@

tests/unit/test_relations.py::test_standalone_zip_is_confirmed_by_relations
tests/unit/test_relations.py::test_empty_zip_is_confirmed_by_relations
tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[7z\xbc\xaf'\x1c\x00\x04L\x06\xfce\x05\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x1b\xdf\x05\xa5abcde\x01-7-Zip SFX-7z]
-tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[PK\x03\x04\x14\x00\x00\x00\x00\x00\x07\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00inside.txthelloPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x07\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00inside.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x008\x00\x00\x00-\x00\x00\x00\x00\x00-7-Zip SFX-zip]
+tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[PK\x03\x04\x14\x00\x00\x00\x00\x00\x08\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00inside.txthelloPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x08\x049]\x86\xa6\x106\x05\x00\x00\x00\x05\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00inside.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x008\x00\x00\x00-\x00\x00\x00\x00\x00-7-Zip SFX-zip]
tests/unit/test_relations.py::test_known_sfx_stub_is_confirmed_and_projected_as_file_range[Rar!\x1a\x07\x00\xcf\x90s\x00\x00\r\x00\x00\x00\x00\x00\x00\x00-WinRAR SFX-rar]
tests/unit/test_relations.py::test_arbitrary_pe_zip_overlay_is_left_for_embedded_discovery
tests/unit/test_relations.py::test_filename_numbered_7z_without_structural_seed_is_not_grouped
To see why this happens see 'Known limitations' in documentation for pytest-xdist
=============================================== short test summary info ===============================================
ERROR gw6 - Different tests were collected between gw1 and gw6. The difference is:
ERROR gw7 - Different tests were collected between gw1 and gw7. The difference is:
2 errors in 2.27s
FAIL - pytest JUnit report contains 2 failure(s) or error(s)
FAIL (2.66s)
Command: C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe -m pytest -q -n 8 --dist worksteal tests/cli tests/unit tests/functional --durations=20

==> Parallel integration and real tests
bringing up nodes...
.................................................................................F.............................. [ 32%]
...............................F.....F.........F........................F....................................... [ 64%]
............................................................................................................s... [ 96%]
.....F..F.. [100%]
====================================================== FAILURES =======================================================
******\*\*******\_\_\_******\*\******* test_real_archive_edge_corrupted_sfx_archives_fail[7z] ******\*\*******\_\_\_\_******\*\*******
[gw0] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_corrupt0')
archive_format = '7z'

    @pytest.mark.parametrize("archive_format", sfx_format_params())
    def test_real_archive_edge_corrupted_sfx_archives_fail(tmp_path, archive_format):
        require_7z()
        case = FACTORY.create(tmp_path, f"corrupted_sfx_{archive_format}", archive_format, sfx=True, corruption="truncate")

>       assert_failure_contains(case, {"压缩包损坏", "致命错误"})

tests\integration\test_real_archive_edge_cases.py:194:

---

case = ArchiveCase(case_id='corrupted_sfx_7z', archive_dir=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pyt...6ddc454295d8e5'}}, 'payload_profile': 'default', 'compression_method': None, 'compression_level': None, 'solid': None})
expected_options = {'压缩包损坏', '致命错误'}, passwords = None, allow_best_effort_outputs = False

    def assert_failure_contains(
        case: ArchiveCase,
        expected_options: set[str],
        passwords: list[str] | None = None,
        *,
        allow_best_effort_outputs: bool = False,
    ):
        summary = run_pipeline(case.archive_dir, passwords=passwords)

        assert summary.success_count == 0

>       assert summary.failed_tasks
>
> E assert []
> E + where [] = RunSummary(target_results=(), scan_failed_tasks=(), scan_failures=(), policy_skips=(), cleanup_results=(), postprocess_completed=True).failed_tasks

tests\integration\test_real_archive_edge_cases.py:114: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 0 个待处理压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：0 秒
完整成功：0 部分恢复：0 失败：0
所有压缩包均已处理成功。

---

\***\*\_\_\_\_\*\*** test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[jpg-rar] **\*\***\_**\*\***
[gw0] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe7')
carrier = 'jpg', archive_format = 'rar'

    @pytest.mark.parametrize(("carrier", "archive_format"), carrier_archive_case_params())
    def test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password(tmp_path, carrier, archive_format):
        require_7z()
        case = FACTORY.create(tmp_path, f"pwd_prefixed_{carrier}_{archive_format}", archive_format, password=PASSWORD, carrier=carrier)

>       assert_wrong_password_then_success(

            case,
            tmp_path / "runs",
            tmp_path / "runs-out",
        )

tests\integration\test_real_archive_edge_cases.py:210:

---

case = ArchiveCase(case_id='pwd_prefixed_jpg_rar', archive_dir=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402...2c80e6c9ad0a5d'}}, 'payload_profile': 'default', 'compression_method': None, 'compression_level': None, 'solid': None})
run_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe7/runs')
output_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe7/runs-out')

    def assert_wrong_password_then_success(
        case: ArchiveCase,
        run_root: Path,
        output_root: Path,
    ) -> None:
        """Attempt without the password, then with it, in isolated workspaces."""
        without_password = run_pipeline_in_fresh_workspace(
            case, run_root / "without-password", output_root / "without-password"
        )

        assert without_password.success_count == 0

>       assert without_password.failed_tasks
>
> E assert []
> E + where [] = RunSummary(target_results=(), scan_failed_tasks=(), scan_failures=(), policy_skips=(), cleanup_results=(), postprocess_completed=True).failed_tasks

tests\integration\test_real_archive_edge_cases.py:135: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 0 个待处理压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：0 秒
完整成功：0 部分恢复：0 失败：0
所有压缩包均已处理成功。

---

\***\*\_\_\_\_\*\*** test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[png-rar] **\*\***\_**\*\***
[gw0] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe8')
carrier = 'png', archive_format = 'rar'

    @pytest.mark.parametrize(("carrier", "archive_format"), carrier_archive_case_params())
    def test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password(tmp_path, carrier, archive_format):
        require_7z()
        case = FACTORY.create(tmp_path, f"pwd_prefixed_{carrier}_{archive_format}", archive_format, password=PASSWORD, carrier=carrier)

>       assert_wrong_password_then_success(

            case,
            tmp_path / "runs",
            tmp_path / "runs-out",
        )

tests\integration\test_real_archive_edge_cases.py:210:

---

case = ArchiveCase(case_id='pwd_prefixed_png_rar', archive_dir=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402...9f12770b156fff'}}, 'payload_profile': 'default', 'compression_method': None, 'compression_level': None, 'solid': None})
run_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe8/runs')
output_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe8/runs-out')

    def assert_wrong_password_then_success(
        case: ArchiveCase,
        run_root: Path,
        output_root: Path,
    ) -> None:
        """Attempt without the password, then with it, in isolated workspaces."""
        without_password = run_pipeline_in_fresh_workspace(
            case, run_root / "without-password", output_root / "without-password"
        )

        assert without_password.success_count == 0

>       assert without_password.failed_tasks
>
> E assert []
> E + where [] = RunSummary(target_results=(), scan_failed_tasks=(), scan_failures=(), policy_skips=(), cleanup_results=(), postprocess_completed=True).failed_tasks

tests\integration\test_real_archive_edge_cases.py:135: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 0 个待处理压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：0 秒
完整成功：0 部分恢复：0 失败：0
所有压缩包均已处理成功。

---

\***\*\_\_\_\_\*\*** test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[gif-rar] **\*\***\_**\*\***
[gw0] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe9')
carrier = 'gif', archive_format = 'rar'

    @pytest.mark.parametrize(("carrier", "archive_format"), carrier_archive_case_params())
    def test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password(tmp_path, carrier, archive_format):
        require_7z()
        case = FACTORY.create(tmp_path, f"pwd_prefixed_{carrier}_{archive_format}", archive_format, password=PASSWORD, carrier=carrier)

>       assert_wrong_password_then_success(

            case,
            tmp_path / "runs",
            tmp_path / "runs-out",
        )

tests\integration\test_real_archive_edge_cases.py:210:

---

case = ArchiveCase(case_id='pwd_prefixed_gif_rar', archive_dir=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402...540d2b8529e309'}}, 'payload_profile': 'default', 'compression_method': None, 'compression_level': None, 'solid': None})
run_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe9/runs')
output_root = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw0/test_real_archive_edge_prefixe9/runs-out')

    def assert_wrong_password_then_success(
        case: ArchiveCase,
        run_root: Path,
        output_root: Path,
    ) -> None:
        """Attempt without the password, then with it, in isolated workspaces."""
        without_password = run_pipeline_in_fresh_workspace(
            case, run_root / "without-password", output_root / "without-password"
        )

        assert without_password.success_count == 0

>       assert without_password.failed_tasks
>
> E assert []
> E + where [] = RunSummary(target_results=(), scan_failed_tasks=(), scan_failures=(), policy_skips=(), cleanup_results=(), postprocess_completed=True).failed_tasks

tests\integration\test_real_archive_edge_cases.py:135: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 0 个待处理压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：0 秒
完整成功：0 部分恢复：0 失败：0
所有压缩包均已处理成功。

---

******\*\*\*\*******\_******\*\*\*\******* test_plan5_mixed_file_scans_as_single_archive_task ******\*\*\*\*******\_\_******\*\*\*\*******
[gw6] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw6/test_plan5_mixed_file_scans_as0')
plan5_error = {'case_id': 'plan5_mixed', 'file_name': 'plan5_embedded.bin', 'segment_count': 13, 'segments': [{'position': 0, 'forma..., 'encrypted': False, ...}, {'position': 5, 'format': 'bzip2', 'variant': 'bzip2', 'encrypted': False, ...}, ...], ...}

    def test_plan5_mixed_file_scans_as_single_archive_task(tmp_path, plan5_error):
        """扫描层：整个混合文件必须恰好成为一个待处理压缩包任务。"""
        case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
        plan5_error["case_id"] = case.case_id
        plan5_error["file_name"] = case.file_path.name
        plan5_error["segment_count"] = len(case.segments)
        plan5_error["segments"] = _segment_table(case)
        plan5_error["skipped_formats"] = list(case.skipped_formats)

>       assert_plan5_single_task_scan(case, error_info=plan5_error)

tests\real\plan5_embedded_archives\test_plan5_embedded_detection.py:39:

---

case = EmbeddedMixedCase(case_id='plan5_mixed', file_path=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pyte...0de814f458a45a40a1df'), (348, '07228a375f65eb67fe1ce727cd9d1d7ad986e5c6b30f3fa3e160bf2530abe45b')), skipped_formats=())
error_info = {'case_id': 'plan5_mixed', 'file_name': 'plan5_embedded.bin', 'segment_count': 13, 'segments': [{'position': 0, 'forma..., 'encrypted': False, ...}, {'position': 5, 'format': 'bzip2', 'variant': 'bzip2', 'encrypted': False, ...}, ...], ...}

    def assert_plan5_single_task_scan(
        case: EmbeddedMixedCase,
        *,
        error_info: dict[str, Any] | None = None,
    ) -> None:
        """整个混合文件在扫描阶段必须恰好成为一个待处理任务。"""
        from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
        from tests.real.plan1_real_archives.plan1_support import plan1_config

        provider = ArchiveTaskProvider(plan1_config())
        tasks = provider.scan_targets([str(case.file_path.parent)])
        expected = os.path.normcase(os.path.abspath(str(case.file_path)))
        actual = [os.path.normcase(os.path.abspath(str(task.main_path))) for task in tasks]
        if error_info is not None:
            error_info["scan_task_count"] = len(tasks)
            error_info["scan_task_paths"] = actual
            error_info["expected_task_path"] = expected

>       assert actual == [expected], (

            f"expected exactly one scan task for the mixed file, got {actual}"
        )

E AssertionError: expected exactly one scan task for the mixed file, got []

tests\real\plan5_embedded_archives\plan5_support.py:539: AssertionError
******\*\*******\_\_\_******\*\******* test_plan5_wrong_passwords_extract_plain_segments_only ******\*\*******\_\_\_\_******\*\*******
[gw4] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw4/test_plan5_wrong_passwords_ext0')
plan5_error = {'case_id': 'plan5_mixed', 'file_size': 139380, 'segment_count': 13, 'segments': [{'position': 0, 'format': 'zip', 'va..., 'encrypted': False, ...}, {'position': 5, 'format': 'bzip2', 'variant': 'bzip2', 'encrypted': False, ...}, ...], ...}

    def test_plan5_wrong_passwords_extract_plain_segments_only(tmp_path, plan5_error):
        """密码全错时：加密段必须失败并报密码错误，非加密段仍应解出。"""
        case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
        plan5_error["case_id"] = case.case_id
        plan5_error["file_size"] = case.file_path.stat().st_size
        plan5_error["segment_count"] = len(case.segments)
        plan5_error["segments"] = _segment_table(case)
        plan5_error["skipped_formats"] = list(case.skipped_formats)

>       assert_plan5_wrong_password_partial(case, error_info=plan5_error)

tests\real\plan5_embedded_archives\test_plan5_wrong_password_partial.py:19:

---

case = EmbeddedMixedCase(case_id='plan5_mixed', file_path=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pyte...0de814f458a45a40a1df'), (348, '07228a375f65eb67fe1ce727cd9d1d7ad986e5c6b30f3fa3e160bf2530abe45b')), skipped_formats=())
error_info = {'case_id': 'plan5_mixed', 'file_size': 139380, 'segment_count': 13, 'segments': [{'position': 0, 'format': 'zip', 'va..., 'encrypted': False, ...}, {'position': 5, 'format': 'bzip2', 'variant': 'bzip2', 'encrypted': False, ...}, ...], ...}

    def assert_plan5_wrong_password_partial(
        case: EmbeddedMixedCase,
        *,
        error_info: dict[str, Any] | None = None,
    ) -> None:
        """全错密码下：加密段必须失败并报密码错误，非加密段仍应解出。"""
        wrong = [f"wrong-{index:03d}-plan5" for index in range(20)]
        summary = run_plan1_pipeline(case.file_path, passwords=wrong)
        marker_status = _marker_status(case, case.file_path.parent)
        plain_extracted = [
            item for item in marker_status
            if not item["encrypted"] and item["marker_extracted"]
        ]
        encrypted_leaked = [
            item for item in marker_status
            if item["encrypted"] and item["marker_extracted"]
        ]
        if error_info is not None:
            error_info.update({
                "password_list_size": len(wrong),
                "pipeline_success_count": summary.success_count,
                "pipeline_partial_success_count": summary.partial_success_count,
                "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
                "failure_kinds": [str(failure.kind) for failure in summary.failures],
                "password_failure_reported": any(
                    failure.is_password_failure for failure in summary.failures
                ),
                "marker_status": marker_status,
            })

>       assert summary.failed_tasks, "all-wrong passwords must leave failed tasks"
>
> E AssertionError: all-wrong passwords must leave failed tasks

tests\real\plan5_embedded_archives\plan5_support.py:719: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 0 个待处理压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：0 秒
完整成功：0 部分恢复：0 失败：0
所有压缩包均已处理成功。

---

******\*\*******\_\_******\*\******* test_plan5_large_file_extracts_128_real_embedded_archives ******\*\*******\_\_******\*\*******
[gw6] win32 -- Python 3.10.11 C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe

tmp_path = WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/pytest-0/popen-gw6/test_plan5_large_file_extracts0')
plan5_error = {'case_id': 'plan5_large_128', 'file_name': 'plan5_large_128.bin', 'file_size': 186765, 'segment_count': 128, ...}

    def test_plan5_large_file_extracts_128_real_embedded_archives(tmp_path, plan5_error):
        """一个文件中循环嵌入 128 个真实归档，给正确密码后全部可见地解出。"""
        case = build_large_embedded_case(
            tmp_path,
            count=LARGE_SEGMENT_COUNT,
            error_info=plan5_error,
        )
        plan5_error["case_id"] = case.case_id
        plan5_error["file_name"] = case.file_path.name
        plan5_error["file_size"] = case.file_path.stat().st_size
        plan5_error["segment_count"] = len(case.segments)
        plan5_error["format_counts"] = dict(Counter(segment.archive_format for segment in case.segments))
        plan5_error["segments"] = _segment_table(case)

        assert len(case.segments) == LARGE_SEGMENT_COUNT

>       assert_plan5_success(

            case,
            passwords=[case.password],
            error_info=plan5_error,
        )

tests\real\plan5_embedded_archives\test_plan5_large_embedded.py:28:

---

case = EmbeddedMixedCase(case_id='plan5_large_128', file_path=WindowsPath('C:/Users/29402/AppData/Local/Temp/pytest-of-29402/...11be7df1a8a371ee8ad9f'), (26, 'b9ba19aac4b052e3b8ce5dc697a2025417d023a6e0cc1afb5180fefa87927796')), skipped_formats=())
passwords = ['sunpack-plan5-acceptance']
error_info = {'case_id': 'plan5_large_128', 'file_name': 'plan5_large_128.bin', 'file_size': 186765, 'segment_count': 128, ...}
detailed_diagnostics = False

    def assert_plan5_success(
        case: EmbeddedMixedCase,
        *,
        passwords: list[str] | None = None,
        error_info: dict[str, Any] | None = None,
        detailed_diagnostics: bool = False,
    ) -> None:
        """第 5 条主断言：给出正确密码后，所有嵌入压缩段分别解压成功。"""
        effective = list(passwords) if passwords is not None else [case.password]
        diagnostics = (
            error_info.setdefault("diagnostics", {})
            if error_info is not None and detailed_diagnostics
            else None
        )
        if diagnostics is not None:
            diagnostics["environment"] = environment_snapshot()
            diagnostics["case"] = {
                **case_snapshot(case),
                "file_path": str(case.file_path),
                "file_size": case.file_path.stat().st_size,
                "segment_count": len(case.segments),
            }
            diagnostics["passwords"] = password_summary(effective)
            diagnostics["input_before_pipeline"] = snapshot_path(case.file_path.parent)
            try:
                native_scan = scan_embedded_archives(
                    str(case.file_path),
                    expected_size=case.file_path.stat().st_size,
                )
                expected = {
                    (segment.archive_format, segment.offset): segment.variant
                    for segment in case.segments
                }
                diagnostics["native_scan_before_pipeline"] = {
                    "candidate_count": len(native_scan.candidates),
                    "candidates": [
                        {
                            "format": candidate.format,
                            "offset": candidate.offset,
                            "end_offset": candidate.end_offset,
                            "confidence": candidate.confidence,
                            "validation": candidate.validation,
                        }
                        for candidate in native_scan.candidates
                    ],
                    "expected_segments": [
                        {
                            "format": archive_format,
                            "offset": offset,
                            "variant": variant,
                        }
                        for (archive_format, offset), variant in expected.items()
                    ],
                    "missing_expected_segments": [
                        {
                            "format": archive_format,
                            "offset": offset,
                            "variant": variant,
                        }
                        for (archive_format, offset), variant in expected.items()
                        if not any(
                            candidate.format == archive_format
                            and candidate.offset == offset
                            for candidate in native_scan.candidates
                        )
                    ],
                }
            except BaseException as exc:
                record_exception(error_info, "native_scan_before_pipeline", exc)
                raise

        summary = None
        try:
            summary = run_plan1_pipeline(case.file_path, passwords=effective)
        except BaseException as exc:
            if diagnostics is not None:
                record_exception(error_info, "pipeline", exc)
                pipeline_snapshot(
                    error_info,
                    phase="pipeline_exception",
                    roots=(case.file_path.parent,),
                )
            raise

        if diagnostics is not None:
            pipeline_snapshot(
                error_info,
                phase="pipeline_returned",
                summary=summary,
                roots=(case.file_path.parent,),
            )

        try:
            marker_status = _marker_status(
                case,
                case.file_path.parent,
                include_locations=detailed_diagnostics,
            )
        except BaseException as exc:
            if diagnostics is not None:
                record_exception(error_info, "marker_scan", exc)
                pipeline_snapshot(
                    error_info,
                    phase="marker_scan_exception",
                    summary=summary,
                    roots=(case.file_path.parent,),
                )
            raise

        missing_markers = [
            item
            for item in marker_status
            if not item["marker_extracted"]
        ]
        if error_info is not None:
            error_info.update({
                "password_list": effective,
                "pipeline_success_count": summary.success_count,
                "pipeline_partial_success_count": summary.partial_success_count,
                "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
                "failure_kinds": [str(failure.kind) for failure in summary.failures],
                "marker_status": marker_status,
            })
            if diagnostics is not None:
                diagnostics["marker_status"] = marker_status
                pipeline_snapshot(
                    error_info,
                    phase="before_assertions",
                    summary=summary,
                    roots=(case.file_path.parent,),
                )
        assert summary.failed_tasks == [], (
            f"pipeline reported failures: {[str(item) for item in summary.failed_tasks]}"
        )
        # Recursive extraction reports independently successful nested archives as
        # additional successes.  The user-visible contract here is that the
        # carrier succeeds and every marker is present, not a fixed task count.
        assert summary.success_count >= 1, (
            f"expected at least the carrier success, got {summary.success_count}"
        )

>       assert not missing_markers, (

            f"markers missing for segments: "
            f"{[(item['position'], item['variant']) for item in missing_markers]}"
        )

E AssertionError: markers missing for segments: [(21, 'tar-gzip-021'), (22, 'tar-bzip2-022'), (23, 'tar-xz-023'), (24, 'tar-zstd-024'), (55, 'tar-gzip-055'), (56, 'tar-bzip2-056'), (57, 'tar-xz-057'), (58, 'tar-zstd-058'), (89, 'tar-gzip-089'), (90, 'tar-bzip2-090'), (91, 'tar-xz-091'), (92, 'tar-zstd-092'), (123, 'tar-gzip-123'), (124, 'tar-bzip2-124'), (125, 'tar-xz-125'), (126, 'tar-zstd-126')]

tests\real\plan5_embedded_archives\plan5_support.py:684: AssertionError
------------------------------------------------ Captured stdout call -------------------------------------------------
[扫描中] 正在查找压缩包…
[扫描完成] 发现 1 个待处理压缩包
[处理中 0/1] plan5_large_128.bin

[EXTRACT] 开始 embedded segments: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin (128 segments)

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [--------------------] 0% plan5_large_128.bin
[ 正在解压 ] [###-----------------] 19% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[ 正在解压 ] [####################] 100% plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin

[EXTRACT] 开始: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[EXTRACT] embedded segments 成功: C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin
[成功 1/1] plan5_large_128.bin

[清理] 任务完成，配置为保留成功解压的原压缩包。
[递归扫描] 正在检查第 2 层…
[递归扫描] 第 2 层发现 0 个嵌套压缩包

[清理] 任务完成，配置为保留成功解压的原压缩包。
[清理] 没有需要清理的压缩包。

## 处理完成

耗时：4 秒
完整成功：1 部分恢复：0 失败：0
输出位置：C:\Users\29402\AppData\Local\Temp\pytest-of-29402\pytest-0\popen-gw6\test_plan5_large_file_extracts0\plan5_large_mixed\plan5_large_128.bin_01_zip
所有压缩包均已处理成功。

---

================================================ slowest 20 durations =================================================
12.95s call tests/real/plan5_embedded_archives/test_plan5_large_embedded.py::test_plan5_large_file_extracts_128_real_embedded_archives
6.03s call tests/real/plan7_watch_downloads/test_plan7_plain_and_sfx_downloads.py::test_plan7_plain_and_sfx_downloads_complete_and_record_memory
5.76s call tests/integration/test_structure_volume_resolution.py::test_encrypted_plain_and_sfx_volume_matrix_with_shared_stem_and_noisy_suffixes
5.13s call tests/real/plan7_watch_downloads/test_plan7_split_downloads.py::test_plan7_split_downloads_out_of_order_complete_and_record_memory
3.83s call tests/real/plan7_watch_downloads/test_plan7_nested_extreme_failures.py::test_plan7_nested_inner_unknown_password_watch_is_password_blocked
3.48s setup tests/integration/test_structure_volume_resolution.py::test_mixed_camouflaged_real_volumes_are_structure_resolved_and_extractable
2.63s call tests/real/plan3_wrong_passwords/test_plan3_plain_wrong_passwords.py::test_plan3_encrypted_7z_reports_password_error[header-off]
2.12s call tests/real/plan7_watch_downloads/test_plan7_arrival_orders.py::test_plan7_rar_part1_exe_enters_pipeline_as_real_head_before_family_complete
1.89s call tests/integration/test_structure_volume_resolution.py::test_raw_split_rar_sfx_with_opaque_camouflaged_members_runs_full_pipeline
1.88s call tests/real/plan2_encrypted_archives/test_plan2_plain_encrypted.py::test_plan2_encrypted_7z_find_correct_password[header-off]
1.88s call tests/real/plan7_watch_downloads/test_plan7_embedded.py::test_plan7_single_format_embedded_downloads_react_for_7z_zip_and_rar
1.83s call tests/real/plan7_watch_downloads/test_plan7_disguised.py::test_plan7_disguised_extensions_and_carrier_prefixes_react
1.69s call tests/integration/test_structure_volume_resolution.py::test_structure_resolution_recomputes_a_residual_middle_gap
1.65s call tests/integration/test_structure_volume_resolution.py::test_modern_split_zip_with_camouflaged_names_runs_full_pipeline
1.50s call tests/real/plan7_watch_downloads/test_plan7_cleanup.py::test_plan7_sfx_split_success_cleans_unique_validated_launcher
1.49s call tests/real/plan7_watch_downloads/test_plan7_variants.py::test_plan7_encryption_and_container_variants_are_processed
1.40s call tests/real/plan7_watch_downloads/test_plan7_lifecycle.py::test_plan7_replacement_and_reappearance_are_processed
1.35s call tests/real/plan5_embedded_archives/test_plan5_embedded_detection.py::test_plan5_mixed_file_scans_as_single_archive_task
1.34s call tests/integration/test_watch_rar_hp_encryption.py::test_watch_split_hp_rar_recovers_after_wrong_then_correct_password
1.32s call tests/real/plan7_watch_downloads/test_plan7_download_modes.py::test_plan7_interleaved_downloads_react_for_every_final_path
=============================================== short test summary info ===============================================
FAILED tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_corrupted_sfx_archives_fail[7z] - assert []
FAILED tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[jpg-rar] - assert []
FAILED tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[png-rar] - assert []
FAILED tests/integration/test_real_archive_edge_cases.py::test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password[gif-rar] - assert []
FAILED tests/real/plan5_embedded_archives/test_plan5_embedded_detection.py::test_plan5_mixed_file_scans_as_single_archive_task - AssertionError: expected exactly one scan task for the mixed file, got []
FAILED tests/real/plan5_embedded_archives/test_plan5_wrong_password_partial.py::test_plan5_wrong_passwords_extract_plain_segments_only - AssertionError: all-wrong passwords must leave failed tasks
FAILED tests/real/plan5_embedded_archives/test_plan5_large_embedded.py::test_plan5_large_file_extracts_128_real_embedded_archives - AssertionError: markers missing for segments: [(21, 'tar-gzip-021'), (22, 'tar-bzip2-022'), (23, 'tar-xz-023'), (24...
7 failed, 339 passed, 1 skipped in 26.26s
FAIL - pytest JUnit report contains 7 failure(s) or error(s)
FAIL (26.54s)
Command: C:\Users\29402\Desktop\sunpack\.venv\Scripts\python.exe -m pytest -q -n 8 --dist worksteal tests/integration tests/real --ignore tests/integration/test_disk_full_pause_resume.py --durations=20

==> Parallel administrator VHD disk-full tests
bringing up nodes...
ssssssss [100%]
================================================ slowest 20 durations =================================================

(16 durations < 0.005s hidden. Use -vv to show these durations.)
8 skipped in 0.85s
PASS (1.12s)

==> CLI help smoke test
PASS (0.30s)

==> CLI passwords smoke test
PASS (0.40s)

==> CLI scan smoke test
PASS (0.19s)

==> CLI inspect smoke test
PASS (0.19s)

==> CLI config smoke test
PASS (0.21s)

==> Stopping source persistent runtime

==> Uninstalling temporary Watch Broker service

Summary
FAIL Parallel CLI, unit, and functional tests 2.66s (exit 1)
FAIL Parallel integration and real tests 26.54s (exit 1)
PASS Parallel administrator VHD disk-full tests 1.12s
PASS CLI help smoke test 0.30s
PASS CLI passwords smoke test 0.40s
PASS CLI scan smoke test 0.19s
PASS CLI inspect smoke test 0.19s
PASS CLI config smoke test 0.21s

2 acceptance test step(s) failed; all scheduled steps have completed.

2 acceptance test step(s) failed. Press Enter to exit...
