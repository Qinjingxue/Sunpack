# LZ4 支持与实现说明

## 支持范围

SunPack 支持 LZ4 Frame v1、官方 Legacy 文件流及其混合拼接。压缩等级，包括 LZ4HC，不改变解码入口。

| 能力 | 行为 |
| --- | --- |
| 64 KiB、256 KiB、1 MiB、4 MiB 块 | 全部支持 |
| 独立块、依赖块、未压缩块、空块、空帧 | 全部支持 |
| 可选 Content Size、Dictionary ID | 保留已知值；声明大小为零也会检查 |
| Header / Block / Content Checksum | 解码时校验，不关闭 XXH32 校验 |
| 多帧、16 种 skippable magic | 顺序解码；前置、中间、尾部 skippable 都支持 |
| Legacy | 8 MiB 块、EOF、后续已知帧 magic；兼容零结束标记 |
| 外部字典 | ID 映射、无 ID 默认字典、同一流中逐帧切换字典 |
| `.tar.lz4`、多层嵌套 | 复用现有输出扫描和 TAR 解包 |
| 伪装扩展名、普通载体、PE 载体 | 按内容识别；PE 载体遵循原有 `--deep-detect` 策略 |
| 加密或分卷外层归档包含 LZ4 | 复用外层归档原有密码、分卷和递归流程 |
| 显式拼接输入 | 复用 `concat_ranges`；不引入一种新的 LZ4 原生分卷命名规则 |

Raw LZ4 Block 没有自描述文件头，不能仅凭签名自动识别。Linux PREBOOT 等容器专用尾部布局也不能当成通用 LZ4 文件格式猜测。需要所属容器提供明确上下文；本次未新增这些容器格式。[官方 Frame 规范](https://github.com/lz4/lz4/blob/v1.10.0/doc/lz4_Frame_format.md)、[Linux 解码上下文](https://github.com/torvalds/linux/blob/master/lib/decompress_unlz4.c)

## 字典配置

CLI 和 watch 共用配置中的 `analysis.lz4`：

```json
{
  "analysis": {
    "lz4": {
      "default_dictionary": "C:/dictionaries/default.raw",
      "dictionaries": {
        "0": "C:/dictionaries/id-zero.raw",
        "123": "C:/dictionaries/game.raw",
        "4294967295": "C:/dictionaries/other.raw"
      }
    }
  }
}
```

`default_dictionary` 用于没有有效 ID 映射的无 ID/零 ID 帧；显式配置 ID `0` 时会优先使用该映射。非零 ID 必须有对应映射。ID 必须是十进制 uint32，重复的数值 ID 和空映射路径会被拒绝。

路径在任务配置投影时转为绝对路径，避免 worker 的隔离工作目录改变相对路径含义。长期运行的 watch 建议使用绝对路径。字典由 native 层读取有效尾部，最多 64 KiB；Python 不读取或传输字典字节。缓存仅属于一次解码任务，不跨任务保留；配置字典后可重新提交保留的输入。

## 信息不足和校验证据

Legacy 嵌入流没有独立尾标。如果尾部无法区分下一块、缺失数据和载体杂数据，则报告 `embedded_information_required`，保留源文件，不猜范围。已知 EOF、已知后续帧或显式输入范围会被使用。

缺失或不可读的字典报告 `dictionary_required`。无 ID 帧可能依赖外部字典；没有字典上下文且块无法解码时，报告 `dictionary_or_data`，不直接断言源数据损坏，也不走错误密码重试。错误字典与损坏数据在一些情况下无法区分；提供的 checksum 仍会正常检查。

LZ4 worker 返回紧凑的 `stream_receipt`：实际消费范围、输出字节、完成帧数、Legacy/skippable 数量及校验完成数量。Rust 将其与源结构计划和已完成输出 inventory 比较，不重新解码输入、不重新散列输出。XXH32 不写入 CRC32 字段。

全部真实帧有 Content Checksum 且检查通过时，内容完整性为 `verified_complete`；部分帧有内容校验时为 `verified_partial`；没有内容校验的合法流可以完整解码，但内容校验状态保留为 `unknown`。Block Checksum 检查编码数据，不能冒充完整输出的内容校验。只有 skippable 的流不独立证明 LZ4 身份，因为 Zstandard 使用相同 magic；明确指定格式的 worker 入口可以处理它。

## 架构和性能

- Rust `formats/lz4.rs` 是唯一结构解析实现，路由、结构报告、嵌入扫描和执行计划复用它。
- 结构分析跳过块载荷，只读取帧头、块长度和必要元数据。已确认 LZ4 的规划只请求结构分析，避免再次全量签名扫描。
- `native/lz4_stream/stream.c` 是 Rust 有界 TAR 采样与 C++ 解码共同使用的执行适配器。官方 LZ4 1.10.0 源码保持未修改，两种构建编译同一份 vendor 源码。
- C++ handler 只承担执行，通过现有 worker、输入范围、多卷 reader、异步 writer、取消和调度生命周期工作。
- 字典按 ID 二分查找，结构索引用有序集合去重；不会逐帧线性扫描所有已见字典。
- AVX2 扫描保留单次 SIMD 预筛，新增签名共享筛选表。标量/packed 回退保留交叠签名和跨缓冲边界命中。
- 普通帧适配器使用两个 256 KiB 缓冲；Legacy 按需使用固定 8 MiB 解码缓冲及压缩上界缓冲。内存不随整个输出大小增长。
- 分析沿用读取预算，并限制帧/结构记录数量；预算耗尽不会伪造完整结构或完整内容校验。

Windows x64 Release 本机对比结果（内存微基准，不能代替磁盘端到端吞吐）：

| 场景 | 原入口 / 官方库 | 新入口 / 适配器 |
| --- | --- | --- |
| 32 MiB 随机数据签名扫描 | 11.810 GB/s | 12.614 GB/s |
| 32 MiB 密集 `PKRar` 拒绝候选 | 2.430 GB/s | 2.401 GB/s |
| 压缩数据解码、收集输出并比较 | 1.919 GB/s | 1.834 GB/s |
| 不可压缩数据解码、收集输出并比较 | 1.966 GB/s | 1.804 GB/s |

扫描对比使用相同输入，交替运行，预热后取中位数；原签名候选循环只保留在测试编译中。解码对比两侧都检查 checksum、收集并比较完整输出。另有 1 GiB 稀疏 skippable + TAR 用例，结构分析读取约 2 MiB，解码直接跳过该区段。

## 验证和复现

`native/sevenzip_bridge/tests/lz4.cpp` 原生生成二进制样本并检查解码，覆盖 64 种帧选项组合、LZ4HC、未压缩块、Legacy 多块、碎片读取、字典切换、各类 checksum、取消及实际 worker 输出内容。

`tests/unit/test_lz4_support.py` 验证结构计划、执行回执、最终 inventory、无假 CRC32、缺字典分类、共享 worker 交错任务、显式拼接和大 skippable 区段。`tests/integration/test_lz4_pipeline.py` 验证 CLI、watch 来源、嵌套、字典、载体及加密/分卷外层归档。

最终 Windows x64 验证结果：Rust 215 项通过（1 项手动性能测试默认忽略）；LZ4 专项 121 项通过；完整 unit/CLI 加相关 integration 回归 1570 项通过、1 项跳过。Release worker 和 Rust 扩展构建成功，Windows 构建脚本语法检查通过。

```powershell
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker sunpack_sevenzip_lz4
.venv/Scripts/maturin.exe develop --release --manifest-path native/sunpack_native/Cargo.toml
cargo test -p sunpack-native --manifest-path native/sunpack_native/Cargo.toml --lib
.venv/Scripts/python.exe -m pytest tests/unit/test_lz4_support.py tests/integration/test_lz4_pipeline.py -q
```

手动性能复现：

```powershell
cargo test -p sunpack-native --manifest-path native/sunpack_native/Cargo.toml --lib --release lz4_scan_performance -- --ignored --nocapture
native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_lz4.exe .cache/lz4-benchmark --benchmark
```

本轮验证平台为 Windows x64。watch 来源通过真实 coordinator/worker 验证；未在本轮运行隔离 Watch Broker 服务的完整事件到达测试、ARM64 构建或完整安装包构建。
