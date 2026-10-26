# 04b2cf19 上限改造审计

基准为 `f0455a1e`，审计对象为 `04b2cf19`。恢复标准：取消原有上限必需的行为保留；不依赖原有上限的算法、策略和判断变化恢复原实现。没有新增测试用例；生产回归通过恢复实现解决，未修改真实归档用例的成功/失败分类断言。

## 恢复的独立改动

| 部分 | 上次提交引入的额外变化 | 本次处理 |
| --- | --- | --- |
| 7z 编码头 | 把既有 `lzma_rust2` LZMA/LZMA2 解码器替换成 `lzma_sys` 原始解码器，改变解码结束及错误判定 | 恢复原来的 `LzmaReader`、`Lzma2Reader`。保留无固定大小上限的输入、输出流式存储，不恢复 64 MiB 限额；删除新增 FFI 解码循环及直接依赖 |
| ZIP 密码快速验证 | 新增 archive-base 推断、改写单卷/分卷的偏移定位和 ZIP64 快速验证路径，改变失败分类 | 恢复原来的中央目录、磁盘、局部头偏移读取及 ZIP64 最终验证回退。保留去除 16 MiB 目录读取预算和无加密目录直接结束的行为 |
| RAR4 密码策略 | 新增分片存储条目、空文件一律退出快速验证的策略 | 删除这两项与 1 MiB 读取上限无关的策略变化，恢复原来条件。保留按实际头遍历、分块读取和 CRC 验证 |
| ZIP 文件名评分 | 增加一套 ASCII 专用评分实现 | 恢复调用原有 `score_decoded_name`。保留全量流式统计和去重索引 |
| 清单名称覆盖 | 从名称列表改为直接读取原生清单时，同时引入逐文件大小、CRC 元数据，改变名称覆盖及进度语义 | 名称覆盖恢复为名称投影；大小、CRC 验证仍使用完整元数据。投影在 Rust 内完成，不重新生成完整 Python 名称列表 |

## 保留的上限相关改动

| 部分 | 与原有上限的依赖关系 |
| --- | --- |
| Reader、递归授权、配置与 GUI 配置目录 | 直接删除总读取预算、绝对数量否决及对应参数/字段 |
| ZIP、TAR、RAR、7z 结构报告 | 从固定项数/头部字节数改为实际格式边界；完整遍历后的目录签名检查仍复用共享实现 |
| 7z、RAR 密码验证的流式输入、分块 AES/CRC、临时存储 | 去除原有 64 MiB/1 MiB 限额后的内存与对象生命周期管理；不要求更换底层解码库 |
| ZIP 文件名统计、ZIP/TAR 清单、输出路径和匹配索引 | 去除样本、名称字节数、清单条目截断后，需要完整统计及有界内存索引；文件名统计的 ZIP64 元数据读取用于获取真实全量计数 |
| USN/Broker | 64 个缓存全部占用时使用临时上下文；总扫描预算改为真实游标推进；帧内分页和请求分批用于保留单帧内存边界 |
| WAL、Catalog | 大于单帧上限的逻辑事务必须分片，并保持完整提交及崩溃恢复边界 |
| CLI | 去除参数总数/请求总量上限后，按已有字段协议分块传输 |
| GUI 显示存储 | 去除单记录限制后，分块压缩、读取、回收和旧记录读取兼容必须配套 |
| `io/scratch.rs` | 上述大清单、记录和事务共用临时存储；使用现有 MessagePack、快速 hash、资源管理及 Windows 文件映射，没有引入 SQLite 或新的第三方库 |

## 已复现问题

首次完整 `run_acceptance_tests.ps1 -NoWait`：CLI/unit/functional 为 1772 通过、1 跳过；integration/real 为 18 失败、821 通过、1 跳过。主要失败是加密 7z 的正确密码被拒绝，以及 ZIP 缺失中间卷被报告为损坏，连带影响 CLI、载体、SFX、分卷和 watch 恢复。

仅恢复原 LZMA/LZMA2 解码器后，现有 7z 加密矩阵的 7 项定向用例通过。恢复 ZIP 定位后，完整验收的 integration/real 为 839 通过、1 跳过，原先 18 项失败均消失。随后继续恢复名称覆盖语义并重新验证。

`lzma-sys` 仍可能由项目原有的 `xz2` 间接依赖；本次删除的是 `04b2cf19` 新增的直接依赖和全部直接调用，未删除原有 XZ 解码能力。

## 完整验收发现的两项原有测试问题

- 管理员 VHD 测试仍要求满盘时 `shutdown` 立即退出。`git blame` 确认 `worker.cpp` 的正常关闭已在基准之前的 `cdfd3e9c` 中改为 `stop(cancel_pending_jobs=false)`，即排空而非取消。本次仅修改该现有测试：发送 shutdown、释放 VHD 空间、断言任务成功和输出字节一致、断言进程正常退出；EOF 与显式 cancel 的现有覆盖仍保留。测试产物选择同时复用 `tests.helpers.native_build.sevenzip_artifact`，不再意外使用其他构建配置的产物。
- 原有 malformed-worker 夹具在握手和接收请求之前退出，存在“提交撞上已关闭进程”的竞态，其有效错误分类是 `process_io`。该测试实际要验证处理请求后的非法输出，因此夹具改为先发送 `worker_ready`、读取请求，再输出非法数据并退出。原 `worker_lost` 断言保持不变，未增加 sleep、重试或降低并发。

## 后续定位的两项根因

重复完整验收时，`test_plan3_encrypted_split_reports_password_error[zip-numbered]` 曾失败一次：目录快照中 5 个物理卷均存在，但管线执行前的 `scan_before_pipeline` 已把 `.002` 漏出候选组，后续据此报告缺卷。该记录位于 `tests/real/error_records/20261026_191433_fe8b8815dac3_001_tests_real_plan3_wrong_passwords_test_plan3_split_wrong_passwords.py__test_plan3_encrypted_split_reports_password_error_zip-numbered_.txt`。

此时尚未进入密码快速验证。`relations` 与 `analysis_native/volume_anchor.rs` 相对 `f0455a1e` 没有改动。此前随机生成 300 组未复现；后续构造有效 ZIP，使 `.002` 正好以 `1f 8b 00` 开头，稳定复现同样的漏卷。根因是 `probe_standalone_stream` 仅凭两字节 gzip 魔数就设置 `strong/standalone`，Relations 因此排除该物理卷。随机加密数据也可能命中短魔数；原失败输入没有保留，因此不能断言其具体命中了哪一种魔数。

修复复用现有 `confirm_format_identity_native` 校验格式身份，保存在原有 anchor 中供 Detection 复用，不新增解析器。没有规范身份校验、也未受 Detection 支持的 `compress` 两字节魔数不再作为排除分卷的依据。原有独立 bzip2 用例的伪头改成真实压缩数据，断言不变。上述 ZIP 现已完整包含 5 卷，通过原管线成功解压，输出全部字节一致。

checkpoint 失败也不是等待时间不足。失败现场为 `applied_seq=3`、磁盘快照不存在、`external_sequence_gap=True`；checkpoint 已被“序列前缀不完整”保护拒绝，所以不会触发测试等待的写入事件。测试在实例上 monkeypatch 方法，撤销时将绑定方法写回实例，形成 `store → bound method → store` 循环引用，并让路径协调器继续存活。pytest 删除、复用同一临时路径后，新 store 读到空磁盘，却从旧协调器取得序号 3。

禁用 GC、复用同一路径连续执行两个参数分支即可稳定复现，无需制造负载。改为在类上 patch 未绑定方法并仅暂停目标实例，消除循环引用；原生产序列保护和测试等待时间均不变。相同条件下连续 20 次交接通过，没有新增 sleep、重试或降低并发，也没有新增测试用例。

## 最终验证结果

两项根因修复后，通过仓库提权流程完整执行 `run_acceptance_tests.ps1 -NoWait`，退出码为 0，记录为 `.cache/audit-acceptance-last.log`：

| 范围 | 结果 |
| --- | --- |
| CLI/unit/functional | 1772 通过、1 跳过，另有 51 个子测试通过 |
| integration/real（含隔离 Broker 服务与 watch 矩阵） | 839 通过、1 跳过；原先 18 项真实归档失败未再出现 |
| 管理员真实 VHD 满盘 | 9 通过 |
| CLI smoke | 5 项均通过 |
| Rust workspace | 293 通过，记录为 `.cache/audit-rust-rootcause.log` |
| 现有验证模块定向用例 | 19 通过 |
| 现有 worker 用例（同步夹具后） | 65 通过，另有 6 个子测试通过 |

此前的 `test_state_handoff_preserves_newer_checkpoint[True]` 失败已按上述方式稳定复现并修复测试对象生命周期。两项修复后的定向现有用例为 119 通过；本次完整验收全部通过，隔离 Broker 服务亦已卸载。

两项常规跳过为显式 opt-in 的性能断言与本机游戏目录扫描；没有跳过此次失败用例，没有降低验收并发。
