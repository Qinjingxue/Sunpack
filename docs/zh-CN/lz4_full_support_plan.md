# SunPack：LZ4 完整支持复杂度与修改方案

分析日期：2026-10-06。依据当前 main 工作区源码、`sunpack新增格式支持计划.md`、LZ4 官方规范与参考实现。LZH/LHA 按当前决定暂缓；本次只做分析，不实现格式支持。

## 1. 结论

**LZ4 适合优先处理。完整支持的总体成本为中等，明显低于完整 LZH/LHA。** 标准文件格式没有密码加密和原生多卷归档；解码有官方库；对象模型是一条解压字节流，可以继续使用现有 worker。无需新增 LZ4 密码探测器或原生分卷 Relations 家族。

但是原计划“分析侧很简单、成本几乎全在 backend”需要修正：接通普通单帧确实不难，完整支持还涉及多帧、skippable、Legacy、外部字典、未知输出长度，以及正确的完整性证据。**不能把成功打开文件、解出第一帧或 worker 返回成功当成完整支持。**

成本可分为以下工作包，评级是工程判断，不是已测工时：

| 工作包 | 复杂度 | 主要原因 |
|---|---|---|
| 标准帧头识别、512B 路由 | 低 | 头部短，校验和可验证 |
| 结构遍历、拼接帧、载体边界 | 中 | 要区分完整流、截断后续帧和载体尾部 |
| 官方库与 IInArchive 集成 | 中 | 首个独立外部格式 handler；已有对象工厂和输出回调可用 |
| XXH32、逐帧完成证据、未知长度 | 中 | 当前 manifest 偏向单项 CRC32 与确定长度 |
| embedded SIMD 与去重 | 中 | 当前 8 个前缀槽已经用满 |
| TAR.LZ4、嵌套、CLI/watch | 低～中 | 复用现有机制，补齐格式入口及 bounded decoder |
| 字典输入、缓存、错误与重试 | 中 | 新的外部解码依赖，不属于密码或分卷 |
| Legacy 兼容 | 中；任意载体场景有固有限制 | 没有标准尾标、没有 checksum |

**完整的文件解压支持可以实现；任意 raw block 或边界缺失的 Legacy 载体，不能承诺仅凭字节自动、唯一还原。** 这是输入信息不足，不是增加解码器就能解决的问题。

## 2. “完整支持”的范围

建议定义产品能力为：**LZ4 标准 Frame 全部现行选项、拼接流、skippable 和 Legacy 文件兼容；字典帧在提供对应字典后可解；边界证据不足时明确报告，保留输入。**

必须覆盖：

- 标准 Frame：独立/依赖块、全部合法块大小、压缩/未压缩块、空帧、空未压缩块、Content Size 有/无、字典 ID 有/无。
- Header / Block / Content 校验；不允许为了性能关闭输入中存在的 checksum。
- 多标准帧，以及标准、Legacy、skippable 的合法拼接；按顺序输出为一个逻辑文件。
- skippable 在前、中、后；仅 skippable 的输入可在明确格式上下文下产生空输出，但无法在伪装扩展名下独立判定为 LZ4。
- Legacy 普通文件、明确输入范围、后接已确认帧边界的情况；Linux 使用的零结束标记作为明确兼容分支测试。
- `.lz4`、`.tar.lz4`、任意伪装扩展名、内层任意格式、外层加密或分卷归档包含 LZ4。
- 当前功能开关允许的载体扫描；不能因新增格式偷偷绕过 EXE 默认扫描开关。
- 截断、坏校验、资源预算耗尽、缺字典、输出写失败与取消均不应错误报完整成功。

压缩强度不产生另一种解码格式：LZ4HC 输出仍使用 LZ4 block 编码，不能漏掉高压缩等级输入。[官方库模块说明](https://github.com/lz4/lz4/blob/v1.10.0/lib/README.md)

Raw LZ4 Block 没有文件封装，解码依赖调用方提供的长度/输出上界等信息。它属于 codec 能力，不能在全盘签名扫描中认作一种自描述归档；其他容器内部用 LZ4，也不意味着这些容器自动得到支持。[Block 规范](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)

## 3. 规范中真正影响架构的地方

以下设计依据 [LZ4 Frame 规范](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md)。本文是实现设计，不复刻规范。

**标准帧边界明确，多帧语义必须额外实现。** 头长 7～19 字节；块带长度，帧有结束标记。一个逻辑 LZ4 文件可有多帧；SunPack 应匹配参考 CLI 按序拼接解码的行为。内容长度可缺省，不能依赖它定位压缩输入终点。

**Checksum 的作用域不同。** Header 验证描述符，Block 验证块的存储字节，Content 验证本帧解压内容。都不是 CRC32。完整性证据要说明验证了什么，不能只用一个布尔值概括。

**Dictionary ID 不携带字典，也不保证携带 ID。** 需提供准确字典；不能假设无 ID 就完全自包含。官方字典解码 API 已存在，真正新增的是 SunPack 的字典传递和依赖生命周期。[官方 API](https://github.com/lz4/lz4/blob/v1.10.0/lib/lz4frame.h)

**Skippable 不是 LZ4 独有标识。** Zstandard 使用兼容的 skippable 封装。只看到 skippable magic 不足以判定 LZ4。[Zstandard 规范](https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#skippable-frames)

**Legacy 边界依赖上下文。** 没有标准 checksum 和独立尾标；通常靠 EOF 或后续已知帧标识终止。Linux 存在相关兼容语义和特定尾部布局，应以实样为准，不能把任何尾部整数视为新通用格式。[官方参考 CLI](https://github.com/lz4/lz4/blob/dev/programs/lz4io.c)、[Linux 解码实现](https://github.com/torvalds/linux/blob/master/lib/decompress_unlz4.c)

## 4. 推荐架构

```text
512B anchor / signatures / embedded
                 ↓
唯一 Rust LZ4 parser + stream index
                 ↓
统一 analysis report + ArchiveInputDescriptor
                 ↓
现有 worker → 新 IInArchive handler → 官方 liblz4
                 ↓
现有输出回调 / progress / native manifest
                 ↓
Rust：输入索引与逐帧解码证据对照 → 现有 verification
                 ↓
现有内层扫描 → TAR 或其他嵌套格式
```

Rust 负责格式身份、结构、边界和提取计划；Python 只投影报告与调度。C++ 的 Open/解码只做执行必需的校验及有限兜底，不新增第二个“归档情况分析器”。

可新增一个小型 Rust `formats/lz4/` 模块，集中 `parse_header`、`walk_stream`、索引/状态类型；也可按项目现有组织放入 `scan/compression_stream.rs`。**重点是一个实现供所有入口复用**，不要在 anchor、view、embedded 各写一套 LZ4 parser。

索引保留必要的逐帧范围、类型、可选输出大小/校验、字典 ID 和完成状态。默认不保留所有块记录；百万块输入要能流式计数。严格区分结构完整、解码完成、校验存在及校验通过。预算耗尽是 incomplete，不能按有效尾边界输出。

不要求先做全格式 registry 重构。先统一 LZ4 的共享原语，避免为这次扩格式引入横跨五个格式的大重构。

## 5. Rust 识别与路由的具体修改

| 当前文件 | 必要修改 |
|---|---|
| `analysis_native/volume_anchor.rs` | `probe_standalone_stream` 接入共享 LZ4 头部探测；标准帧和 Legacy 区分置信证据 |
| `scan/directory.rs` | `filesystem_file_route` 接受 lz4 的 Detection 路由 |
| `scan/discovery.rs` | `NativeCandidateTable.resolve` 的原生 Detection 白名单加 lz4；只改 Python 不够 |
| `pipeline/discovery/detection/scheduler.py` | `CONFIRMABLE_FORMATS` 补齐 lz4 |
| `analysis_native/structure/api.rs` | compression prefilter、identity、structure dispatch 加 lz4 |
| `analysis_native/structure/constants.rs` 与 `compression.rs` | 常量、结构类型、投影接共享 parser；不复制解析 |
| `analysis_native/view/constants.rs`、`signatures.rs` | 标准/Legacy 命中与 canonical 映射；shared skippable 只作中性候选 |
| `analysis_native/view/impls.rs`、`report.rs` | view probe、ModuleKind、identity confirmation、流/复合容器映射接 lz4 |
| `sunpack_advanced_config.json` | 增加 lz4 和 tar_lz4 分析模块 |
| `core/analysis/embedded/result.py`、`core/support/archive_formats.py` | 命中投影与 tar.lz4 canonical 名称对齐 |

以上 Rust 文件位于 `native/sunpack_native/src/`，Python 文件位于 `sunpack/`。

普通标准帧头可在现有 512B 内确认，无须扩大所有文件读取窗口。前导 skippable 的后继帧可能远超 512B：便宜扫描先记录未定候选，后续使用长度跳转做有预算确认。需保留后续确认入口，不能让 routing 把候选丢弃。

标准头检查还要检查首块可用性；只有头匹配可以识别格式，但不足以认定流完整。Legacy 只有 magic 和块长度，没有同等强度头校验，证据应弱于标准帧。

prefilter 是特别容易遗漏的入口：现在 `UNIFIED_PREFILTER_COMPRESSION` 的条件只保留四个现有流格式，没改它会使新模块被提前排除。

## 6. 结构遍历与载体

标准流以块长度跳过 payload，主要读取头部、块长度、尾部，不预解压整文件。Header 的小校验即时完成；Block/Content 校验可延迟至实际解码，让 decoder 一次完成。

遍历完整帧后，再看相邻帧或 skippable；不能为每个内部帧建立独立提取任务。已验证的整条流范围用于去重，减少嵌套扫描重复识别和重复 IO。

边界处理规则：

1. 后续完整合法帧或 skippable 属于同一个流，继续遍历。
2. 后续具有 LZ4 magic 但结构损坏/截断，应记录流未完成或损坏。不能静默截掉后帧，宣称原文件全部成功。
3. 完整流后非帧字节可作为载体后缀，范围计划不包含它；报告保留剩余字节证据。可单独提取已确认前段，但整个输入状态不能掩盖异常。
4. 前导 skippable 的归属以连续链中第一个实际格式帧确认；仅 skippable 的伪装输入保持 ambiguous，避免抢占 Zstd。
5. 帧内 payload/skippable 中的 magic 不自动产生新顶层流；范围压制只依据已验证结构，不能按 raw hit 范围猜测。
6. 连续两个合法 LZ4 帧没有分隔信息时，按拼接流解释；字节本身不能证明它们是两个“原文件”。

Legacy 若到物理 EOF 或可信输入范围终点，或下个合法帧边界，可正常兼容。若后面是任意垃圾，没有可靠终点，不应凭“第一个非法块长度”直接认定完整。缺少最后完整块的 Legacy 甚至可能与合法短文件不可区分。

**全自动处理任意 Legacy 前后缀并保证唯一正确边界，不能作为可兑现的验收承诺。** 有外部范围/长度时可解；无证据时保留 carrier，报告 boundary_unknown。恢复输出与完整成功必须分开。

## 7. Embedded SIMD 的现有约束

`scan/embedded.rs` 当前 10 个 pattern 共 8 个不同的前两字节 bucket，表用 `u8` 位图，`simd_prefix_tables` 有 `assert!(next_bucket <= 8)`。

标准 LZ4 与 Legacy 是两个新的前缀；两者都加入会超限。若 naive 地把 16 个 skippable magic 展成独立前缀，成本进一步放大。

建议先做允许受控 bucket 复用的 prefilter：碰撞只产生候选，最终必须核对完整 magic，所以无漏报；用实测决定是否需要第二组 SIMD 表。shared skippable 采用范围识别/紧凑分派。复用现有 IOCP 扫描读取，不单独再扫描一次文件；不全局关闭 SIMD。

同步处理 Aho-Corasick、packed/scalar fallback、validate dispatch、跨 chunk carry 与 raw hit 映射。标准和 Legacy magic 均在流起点，不需要 LZH 那种 offset-2。

若 PE overlay 快速路径继续服务载体识别，`scan/pe_overlay.rs` 也应接入同一个头部证明；不能只加 magic 就高置信认定合法。EXE 是否扫描继续服从当前开关。

## 8. 解码后端与构建

建议 pin 官方 liblz4 的确定版本/提交，vendor 一份共享源码，CMake 与 Rust 构建共同使用同一来源。已核对 v1.10.0 的稳定字典解码 API；这不是断言其为目前最新版本。

- 常规集成包括 `lz4.c`、`lz4frame.c`、`lz4hc.c`、`xxhash.c` 及配套头文件。不要因产品只解压就直接省去默认 frame 库需要的 lz4hc 链接依赖。
- 使用 library 部分，保留 BSD 2-Clause 许可证和随包 notice。[库许可证](https://github.com/lz4/lz4/blob/v1.10.0/lib/LICENSE)
- 自定义 handler 放在 SunPack 自有源码区，third_party 放在裁剪 7-Zip tree 外。现有 CMake 强制裁剪树 228 个 translation units；不应为了添加自有 handler 改掉这个完整性约束。
- handler 通过现有 CreateArchiver 注册。新增对象文件要像现有 7-Zip objects 一样明确进入目标，避免静态库仅有注册初始化的对象被链接器删除。
- 分配经冲突检查的 handler ID，不把 7z Methods.txt 中的 LZ4 codec 编号误当 archive ID。
- `sevenzip_formats.cpp` 补 hint、扩展名及未知扩展名 fallback；`archive_extract.cpp::format_name_for_guid` 补名字。
- Rust 用 bounded streaming decoder 做 tar probe 时，可通过薄 FFI 使用同一官方 C 源码；不让 Python读二进制。Rust/C++ 各执行必要解码不等于复制两套“情况分析”。
- 注意 XXH 符号隔离，如统一 `XXH_NAMESPACE`，避免与其它 native 依赖冲突。Windows x64/ARM64 均要构建和验证。

Handler 将一条拼接流暴露为一个 item。普通 Frame 用 LZ4F 流式 API；Legacy 需要另外用安全 block decoder 包装，LZ4F 不能自动承担全部 Legacy 兼容。输出无内置文件名/时间等归档元数据，复用当前匿名流命名；输入 manifest 采用相同命名投影。

API 返回当前帧完成时仍可能有未消费输入；必须继续解析后帧，不能丢弃 tail。实际解码保持 checksum 校验，检查声明大小；依赖块按顺序解码，跨任务并发继续使用现有调度。[LZ4F API](https://github.com/lz4/lz4/blob/v1.10.0/lib/lz4frame.h)

## 9. 外部字典：完整支持最主要的新依赖

最小可用设计包括显式 dictionary path，以及 dictID → dictionary 映射；无 ID 帧允许按任务指定字典。拼接流可以每帧更换字典，不能默认整文件只用一个字典。

字典由 native 层读取有效尾部，固定生命周期到该帧结束；配置、输入描述符与 worker 协议传递字典引用。不要将任意大小字典复制为 Python bytes，也不要从候选目录盲扫、试解所有文件。

dictID 是引用标识，不是密码 verifier 或可靠内容指纹。字典正确性仍以显式上下文和可用校验为准。缺字典/不可读可明确分类；错误字典的失败有时无法与损坏区分，无 checksum 时更不能保证诊断准确。

CLI 和 watch 应有一致配置入口。仅要求用户“先用外部 lz4.exe 解一下”不能算完整支持。watch 可复用现有依赖重试基础设施，并扩展字典变更触发；无须把它伪装为 missing_volume 或 wrong_password。

缓存 key 纳入字典身份/配置代次，任务读取期间字典变更要重新验证。按任务拥有 decoder context；共享只读字典缓存有上限，替换/取消后释放，不添加等待或降低并发来绕开竞态。

## 10. 验收和完整性证据

现有 `sevenzip_callbacks.hpp` 将 `kpidCRC` 当成 `source_crc32`；`kOpOk` 后可直接复用该值，甚至无源 CRC 时 `crc_verified` 也可能为 true。`worker.cpp`、Rust worker_event 与 inventory 继续按 CRC32 接收/回读。这些字段不能装 XXH32。

LZ4 不应把 Content Checksum 填进 `kpidCRC`。建议在现有 manifest/protocol 上增加紧凑的 stream completion/integrity 信息，而不是创建第二套 worker：

- Rust 结构索引给出期望输入范围、帧数/类型、每帧可选大小与 Content Checksum。
- decoder 记录实际完成帧、消费输入长度、实际输出长度与逐帧校验状态。frame 数不能按“有输出字节”推导，空帧和 skippable 要区分。
- 用明确的算法与作用域，例如 xxh32/frame-content，而非 crc32/file。多个帧的 checksum 不能当成整个输出文件的一个 checksum。
- 正常成功复用 decoder 已验证证据；需要回读输出时由 Rust 对相应解压输出范围算 XXH32，不对整个拼接输出作一个 CRC32 比较。
- `archive_input_manifest.py` 目前只有 ZIP/TAR source manifest。LZ4 应由同一 Rust index 提供 stream source expectation，不能只相信 worker 自报的 inventory。
- 当前 `ManifestEntry.size` 是确定 u64；无 Content Size 时要保存 unknown/partial-known，不填 0，不用最终已写字节假冒源期望长度。无需为获取大小再完整解压一遍。
- 磁盘不足、writer 未完成、失败后部分输出与取消沿用现有状态，但不能因帧已解码就忽略输出写入失败。

文件完整解码、全部存在的校验通过、无源内容校验，是三种不同信息。合法无 checksum 帧和 Legacy 可以完整解出，但结果不应显示“源 checksum 已验证”。有些数据损坏或字典错误在无 checksum 情况下不可检测。

修改集中在 bridge.hpp / callbacks / worker 协议、worker_event、native manifest 与现有 verification methods 的证据适配；不必为了 LZ4 先把所有旧格式 checksum 重写成新系统。

## 11. TAR.LZ4 与嵌套

现有 `view/compression.rs::decompress_sample` 只有 gzip、bzip2、xz、zstd。加 LZ4 的 bounded streaming decoder，复用 `probe_compressed_tar`、`ModuleKind::CompressedTar`、STREAM_CONTAINERS / COMPOSITE_INNER_FORMATS 与现有 TAR 内层任务。

probe 只用于识别有限 TAR 头，不可标记整条 LZ4 已验证。字典输入同样作用于 probe；多帧前面的空输出/skippable 不能让 TAR probe 提前结束。

实际流程仍是解 LZ4 流，再走现有内层扫描与 TAR 解包；不要为 tar.lz4 再写一个多文件 LZ4 backend。任意 payload 若是 ZIP/7z/其他支持格式，也要按内容而非名字发现。

外层加密或分卷 ZIP/RAR/7z 继续用现有密码/Relations。人为把 LZ4 字节切成多个文件不是原生 LZ4 分卷；若产品另行承诺任意原始切片重组，应单独定义通用 split 输入契约，不能仅按 .001 自动聚合。

## 12. 测试矩阵与完成标准

| 类别 | 必需验证 |
|---|---|
| Frame 参数 | 独立/依赖块，所有 BD 档位，HC 输入，压缩/未压缩，空帧，0x80000000 空块 |
| 长度 | 无大小、有大小、实际不符，0 与 unknown，64-bit 输入/输出计数，算术溢出 |
| 校验 | Header/Block/Content 各有无组合；分别破坏；不得关闭校验 |
| 拼接 | 多普通帧、空帧在前、混合 Legacy、各位置 skippable、最后一帧截断 |
| 字典 | ID 有无、正确/缺失/不可读/错误字典，每帧不同字典，运行期间替换 |
| Legacy | 官方 CLI -l 实样、EOF/明确range/后继帧，Linux兼容实样，尾部垃圾 ambiguous |
| Carrier | 头前任意数据、尾后任意数据、多种格式同载体、payload 内假magic、range extraction |
| 扫描 | SIMD/scalar/packed 等价，跨 IOCP chunk，旧格式无回归，skippable/Zstd 不误判 |
| 嵌套 | tar.lz4、伪装名、LZ4 payload 含其他归档、外层加密/不完整分卷 |
| 执行 | 真 CLI、watch 新建/增长/替换、并发取消、output故障、空输出 |
| 验收 | 只解首帧不能成功；unknown size 不冒充0；XXH32 不冒充CRC32；源索引和输出对照 |
| 性能 | 多小文件识别吞吐、大流逐块IO、密集假签名、不同块档位、并发峰值内存 |

官方 CLI 用作解码 oracle，不当生产依赖。夹具必须固定来源与参数；矩阵中对未知语义使用实样，不只写合成字节测试。Legacy/Linux、跨帧字典和无 checksum 边界是要优先验证的非普通样本。

完成顺序建议：

1. 固定支持契约和上述关键夹具；确定字典配置以及 Legacy carrier 的保守策略。
2. 官方库构建与自有 handler；同时建立 worker 的逐帧完成/校验证据契约。
3. 唯一 Rust parser/index 接通 identity、路由、prefilter、报告、embedded 与 SIMD。
4. 补 source stream expectation、XXH32 验收、字典依赖及 TAR.LZ4 probe。
5. 真 CLI/watch/嵌套/载体和性能验证，再更新支持列表、许可证及打包检查。

这些是内部工作步骤，不是依次发布不完整格式支持。全部约定范围验证通过后才对外宣称完整支持。

## 13. 本次分析的证据边界

使用 codebase-memory 默认 Verify 流程定位并双向追踪 format confirmation 与 stream validator。图 generation 为 2026-10-06T07:52:27Z；36 个相关文件覆盖检查，相关 scope 的覆盖分页已读完。索引对工作区文件普遍报告 metadata_changed，C++ 有 parse_partial，原计划 freshness missing，因此关键结论已回读当前源码，并对指定源码范围作 rg 补查；不以图中缺符号证明全仓库不存在。

当前裁剪源码中，LZ4 只在 Methods.txt 存在 codec 编号文字，未找到 LZ4 handler/decoder 实现。已核对现有注册工厂、格式选择和构建约束。对外部官方库是源码/API核查，没有在本次集成编译，没有生产测试或性能数据。

**本次产物只有本文档；没有修改生产代码。** 后续实施仍需完成实际夹具、字典协议细化和 Windows 构建验证。

