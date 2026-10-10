# 7-Zip 26.04 必要修复同步记录

实施日期：2026-10-10。已完成选择性同步、Rust ZIP64 分析修复、x64 CI 和 Release/LTO 构建及相关回归。源码目录已改为 `native/sevenzip_bridge/7z2604-src/`。

这是保留 SunPack 本地优化的裁剪源码集。26.04 的必要运行时修复已合入；编译器注解、未支持格式及无关行为变化没有整体搬入。前一轮生成的 47 文件 `candidate-upgrade.patch` 仅为完整同步候选，本次没有应用该整包补丁。

## 来源和比较范围

- [官方 26.03 源码包](https://github.com/ip7z/7zip/releases/download/26.03/7z2603-src.7z)
- [官方 26.04 源码包](https://github.com/ip7z/7zip/releases/download/26.04/7z2604-src.7z)
- [官方 26.04 发布记录](https://github.com/ip7z/7zip/releases/tag/26.04)：仅声明修复缺陷和漏洞，没有此次修复的逐项 CVE 映射。以下影响来自实际源码比较。
- 源码版本日期：2026-10-05；发布页面日期：2026-10-06。
- 两版官方文件各 1292 个，109 个内容有变化，无新增/删除。项目保留集合 477 个，其中 47 个有上游变化，20 个带原有本地补丁。
- 比较内容只统一 CRLF/LF，直接比较字节，不计算内容哈希。

本地下载和分析资料保存在被忽略的 `.codex_7z_compare/` 中，包括两版原始源码、[summary.json](../../.codex_7z_compare/summary.json)、[retained.diff](../../.codex_7z_compare/retained.diff)、[local.diff](../../.codex_7z_compare/local.diff) 和同步前的 `before-sync/` 备份。这些是本机审计材料，不是构建依赖。

## 实际合入范围

只修改 vendor 内以下 9 个文件，保留集合不增不减。

| 文件 | 合入内容 |
| --- | --- |
| `CPP/7zip/Archive/Zip/ZipIn.cpp`、`ZipIn.h` | ZIP64 中央目录 size、offset、offset+size 和 locator 偏移的 `2^63` 边界检查，覆盖上游多个读取入口；comment 使用局部 buffer 完成后再赋值。省略新编译器注解。 |
| `C/XzDec.c` | 内存判断改为线程数非零检查和除法，避免乘法溢出。仅人工合并这一条件，保留 SunPack CPU context guard。 |
| `CPP/Common/MyVector.h` | 0-based、size_t 堆排序，消除 `_items - 1` 指针；批量追加边界检查及摊销预留。省略只有裁剪外 NSIS 使用的新 `MoveOneItem`。 |
| `CPP/7zip/Common/LimitedStreams.cpp`、`LimitedStreams.h` | `InitAndSeek` 成功后删除重复 seek，配套删除旧方法。 |
| `C/7zVersion.h`、`DOC/readme.txt`、`DOC/src-history.txt` | 26.04 版本、日期和上游历史记录。 |

MyVector 的小批量追加可以额外预留约当前 size 的 1/4，以减少反复分配；这是上游容量策略，可能增加容量余量，不代表峰值内存必然下降。

XZ 合并后的条件为：

```c
if (!me->mtc.sunpackCpuContext &&
    me->mtc.numStartedThreads != 0 &&
    block->unpackSize > me->props.memUseMax / 2 / me->mtc.numStartedThreads)
```

现有 managed XZ 仍通过 SunPack CPU/资源管理链路控制执行，没有去掉 guard、增加等待或降低并发。该上游判断修复非 managed 路径，不为 managed 路径建立新的内存上限。

未同步的 38 个保留文件变化包括 lifetimebound 编译器注解、相关宏/诊断抑制、字节序宏、外部 filter 的 64 KiB buffer 下限、Ext AUX 属性和无关文档。没有新增 NTFS/WIM/ISO/CAB/NSIS 或上游 UI，也没有重写 USN/watch 服务或 COM 协议。汇编、接口和 GUID 未发生需要同步的上游变化。

## 本地优化保留情况

与同步前备份直接比较确认：20 个本地补丁文件中，除 XzDec.c 的上述条件外，其余 19 个字节一致；XZ 的全文差异也只有该条件。

保留项包括 zlib-ng CRC/Deflate/gzip 路由、MtDec CPU credit 管理、mixer 的 CPU context、BZip2 预算与生命周期、LZMA2/XZ 上下文传递、RAR 解码及线程提示优化。原来三个上游重叠文件 `CoderMixer2.h`、`Rar5Handler.cpp`、`BZip2Decoder.h` 此次只涉及编译器注解，因此直接保留本地文件。

C/C++ 编译单元维持 228；x64 汇编替换 5 个 C fallback 后为 223，CMake 断言和六个汇编输入均保留。Release worker 的 LZMA 汇编选择检查已通过。

CMake、COM 测试 include、两版 README 和许可文档均更新目录/版本引用。许可证内容没有变化。历史性能报告保留测量时版本，内部扩展占位版本不变。

## Rust ZIP64 修复

旧扩展对 176 字节 ZIP64 样本中的 locator 偏移 `2^63` 仍报告 `plausible=true`。已在新扩展中修复。

新增唯一的无 IO、无分配字段解析模块 [zip64.rs](../../native/sunpack_native/src/formats/zip/zip64.rs)，现有入口复用它：

- [view/impls.rs](../../native/sunpack_native/src/analysis_native/view/impls.rs)：单文件及逻辑分卷 probe。
- [structure/api.rs](../../native/sunpack_native/src/analysis_native/structure/api.rs)：现有 EOCD inspector。
- [directory/parse.rs](../../native/sunpack_native/src/formats/zip/directory/parse.rs)、[directory/local.rs](../../native/sunpack_native/src/formats/zip/directory/local.rs)：目录检查和结构关系解析。
- [scan/embedded.rs](../../native/sunpack_native/src/scan/embedded.rs)：载体候选验证，包括可变长度 ZIP64 EOCD 读取路径。

中央目录 size、offset、sum 和 locator 偏移均须小于 `2^63`；sum 使用 checked_add。EOCD record_size 校验保证后续长度运算安全。目录索引转换使用 try_from，拒绝越界后再做物理映射。保留既有 archive-relative、disk-relative 和载体前缀映射，不额外读文件或增加 Python 数据转换。

越界分别输出 `zip64_central_directory_overflow` 或 `zip64_locator_offset_overflow`。载体扫描拒绝该无效候选，实际 IO 故障继续沿原错误链路传播。即使经典 EOCD 字段不是 sentinel，也不会因 ZIP64 无效而退回经典 EOCD 并误报正常。没有在 Python/C++ 增加分析或密码探测。

## 测试和运行产物

新增一个粗粒度参数化用例组：[test_zip_multidisk_metadata.py](../../tests/unit/test_zip_multidisk_metadata.py)。5 个字段组合（正常、locator、size、offset、sum）乘 3 种布局（普通、前后垃圾载体、ZIP64 字段跨 raw split 的载体），共 15 例。普通文件同时检查现有 inspector，一致性由真实 Rust 扩展调用验证。

其独立覆盖是越界声明的误接受及载体/分卷绕过；原有正常 ZIP64 测试无法发现，删除后将失去该覆盖。样本不到 250 字节，只做有界读取，运行成本值得。旧扩展下异常例失败，新扩展下全部通过。

已通过：

- Rust 扩展 `maturin build --locked --profile ci`，在既有 `.venv` 中安装新 wheel。
- x64 CI 构建和 Release/LTO 构建；两种构建各 6 项 CTest 全通过，涵盖 COM、zlib-ng Deflate、提取、异步输出和空间重试。
- x64 Release worker 的独立 CRT 依赖检查和 LZMA 汇编选择检查。
- **328 项 pytest、6 项 subtest**，包括分析、ZIP64 分卷、读故障、worker、密码、真实 7z/RAR、ZIPX、嵌套、载体、缺卷、XZ/BZip2/Tar、并发任务隔离、CLI 以及 foreground/watch 共享执行链路。
- 1 项 opt-in 性能测试按默认规则跳过；没有跑 benchmark 自检。
- `git diff --check`。

pytest 分三组：分析相关 31 项、分析/watch 调度相关 133 项、使用新版 Release worker 的解压和结构回归 164 项。最后一组使用应用实际解析出的 `build-x64/Release/sunpack_sevenzip_worker.exe`；新 worker 也已复制到 `tools/`。

验证范围限制：本机仅执行 x64；ARM64 未构建/运行。watch 的共享调度/提取链路已覆盖，未启动实际 Watch Broker 服务。分发工具 `tools/7z.exe` 仍是原有配套工具，本次升级的是内嵌 worker 源码和构建产物。

codebase-memory 的索引/结构查询及本次 cited-path 覆盖检查返回 `Transport closed`，无法据图确认覆盖；结论依据直接源码读取、完整文件差异、编译和实际回归，不声称图索引完整。
