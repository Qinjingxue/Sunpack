# CPU credit 与 worker 内存预留

2026-10-27，基于 `9025c031`。默认预留改为：

**128 MiB + 16 MiB × worker 的 nominal CPU credit 数。**

| CPU credit | 自动预留 |
| ---: | ---: |
| 1 | 144 MiB |
| 2 | 160 MiB |
| 4 | 192 MiB |
| 8 | 256 MiB |
| 16 | 384 MiB |
| 32 | 640 MiB |
| 64 | 1152 MiB |
| 128 | 2176 MiB |

worker 启动时用最终 sizing plan 计算一次，包括 thread capacity 覆盖。它不随当前任务或借还 credit 波动，也不修改 CPU credit 额度。外层任务与解码子线程共用该额度，不重复计数。没有新增字节热路径采样、空闲轮询或 Python 调度。

`performance.worker.memory_reserve_bytes` 默认 **0**，环境变量 `SUNPACK_NATIVE_MEMORY_RESERVE_BYTES` 未设置或为 0 均表示自动；正数仍为固定字节覆盖。现有显式 512 MiB 配置不自动迁移，改回 0 才启用自动值。GUI 标签同步说明。`worker_ready.memory_reserve_bytes` 始终报告有效字节数，CLI/watch 共用。

## 不是只有普通 BCJ2

子进程受 Windows Job 内存/CPU 限额、两个逻辑处理器 affinity 限制，通常只允许主机总 CPU 的 1%。64/128 credit 通过专用测试 executable 模拟，并非 64/128 核物理机器实测。安装中的 worker 没有改动。

修改前，128 credit、每 credit 两个任务、独立写入设施时：

| 路径 | 采样未受管私有提交峰值 |
| --- | ---: |
| 普通 BCJ2 | 1346 MiB |
| TAR/Zstd | 824 MiB |
| 7z/BCJ | 697 MiB |
| ZIP/BZip2 | 466 MiB |
| RAR5 | 399 MiB |

这里是 PrivateUsage 减去精确 managed 页提交，不是 RSS。采样可能漏掉短峰值；没有 managed 分配的样本还比较 Job 实际提交峰值。多个格式都有明显增长，单独修普通 BCJ2 不足以保留固定 512 MiB。

进一步补充四个 3 MiB LZMA2 字典，以及四个接近 4 MiB 的 LZMA 字典的合法 BCJ2 组合。后者在 64 credit 下测到 **1547 MiB 未受管峰值**，否决了最初的 `128 + 12 × credit`。

编码器会把部分 LZMA 字典属性向上取整，不能用命令行参数代替解码端大小。测试对未压缩 7z header 的四个属性设置合法的页对齐值、修复两层 header CRC，输入仅使用短距离重复数据；所有输出仍独立比较原始大小和 CRC32。另测四个刚低于 2 MiB 的字典，覆盖纳管后的残余边界。

## 小改动覆盖大的工作区

`LzmaDec_Allocate/FreeDict` 将 **至少 2 MiB 的可变字典**交给既有管理器，LZMA/LZMA2 复用同一入口。没有改变字典尺寸、对齐要求、格式能力或内部并行，也没有把通用阈值改为 2 MiB。固定 1 MiB 缓冲保持原路径。

同一 64-credit 极端样本改后，未受管峰值约 **567 MiB**，约 **1023 MiB 字典提交进入管理器**。这是增加覆盖范围，不声称总内存因此减少 1 GiB。

紧预算测试还发现并修复：

- 写入池原来逐设施判断 8 MiB，许多小池合计很大也不回收。现在只在既有压力路径跨设施求和，合计至少 8 MiB 时整批归还空闲 backing buffers，不触碰进行中的 IOCP 数据，不增加逐 buffer 记账。
- 早期撤销不能覆盖掉前次已观测到的失败工作区。重放保留该需求，仍支持真实容量增长后的低内存试探；不把可选路径的历史成功峰值重新当作门槛。
- 重放临时保留一个每 credit 的小工作区余量，避免整批任务只取得首个字典便再次一起失败。已观测的字典工作区建立后，立即重新采样并归还余量，保留有用并发；额外余量放不下时，仍允许一个满足实际字典需求的任务尝试。

以上沿用既有任务回收/准入，没有新增阶段预测、失败次数上限或 CPU 限流系统。

## 公式依据与性能

固定 128 MiB 根据此前约 77 MiB 的恢复增长及本轮低并发约 28 MiB 的增长保留粗余量。每 credit 16 MiB 覆盖纳管后的高并发工作区；本轮高并发恢复增长最高约 248 MiB，由并行项共同覆盖，不能全部归为固定开销。四个刚低于 2 MiB 的字典在 128 credit 下，采样未受管峰值约 **2019 MiB**、实际 Job 峰值约 **2058 MiB**，对应自动预留 **2176 MiB**。

这是实测工程余量，不是对任意 coder 图、条目数或外部瞬时提交的数学上限。已提交的小内存本来就从系统可用量扣除；预留用于未观测增长和恢复，不会实际分配同等大小的内存块。

五种真实负载交替 A/B 各 10 轮，关闭 2 ms 采样与分配 CSV IO，使用同样的固定预留和 Job 配额。没有稳定吞吐下降。单轮几十毫秒，CPU 计时约 15.6 ms 粒度，不据此声称细微加速。

## 验证结果与边界

- 62 组格式/算法/边界样本，分别运行 4/128 个任务，共 **8184 个任务**，全部独立校验输出大小与 CRC32。覆盖 ZIP、7z、RAR、TAR、五种独立流和 TAR 外层流、ENC 十种 cipher 与 KDF 变体、加密和旧格式样本。最后调整临时余量的归还时机后，又以 128 credit 补测四类 BCJ2，共 **512 个任务**。
- 2/32/128 credit 下进行 **6 轮、352 个任务**的限额收缩/扩张，均实际经历初始受限、扩大、再次收缩、恢复三次限额修改，全部完成并校验输出。覆盖 PPMd 与四字典 BCJ2，不把过快完成、未经历恢复的试验算成功。
- **393 项 Python 测试及 24 个子测试、116 项真实 pipeline 测试、7 项 C++ 测试**通过。包含 CLI/watch、伪装、分卷、密码、载体、嵌套、输入变化、取消、精确输出重放，以及真实 writer 注入磁盘满时的两种资源恢复顺序。新写入池回归验证八个 1 MiB 小池合计回收及回收后重新写入。

主机可用内存保持 11 GiB 以上，没有在主机上耗尽内存。没有新增 VHD 满盘或真实物理低内存实验。

另外，固定 Job 上限仅比预留多 64 MiB 的极端实验并非全部能完成：128-credit worker 的线程、保留记录与设施提交可能吃掉这部分额度，剩余可分配额度约 1.8 MiB，小于任务明确需要的 2/4 MiB，任务正确报告 `memory_blocked` 等待。没有把 watchdog 结束这样的试验算作解压成功，也没有加生产超时失败或为了通过测试缩减预留。可用额度增长后的恢复由上面的动态试验独立验证。

## 复现

原始数据：忽略目录 `reports/worker-credit-reserve-20261027/`。`baseline-*`、`other-formats` 为扩展前测量，`subthreshold-baseline` / `dictionary-after` 为字典覆盖前后，`cpu-ab` 为关闭细密采样的性能对照。早期公式、未完整经历三次限额变化的试验及 watchdog 中止的争抢试验均保留，不计为验收通过。

```powershell
cmake --build native/sevenzip_bridge/build-x64-ci --config Release --target sunpack_sevenzip_memory_probe --parallel 4
.venv/Scripts/python.exe tests/memory/worker_format_probe.py --generate-only --report-dir reports/credit-fixtures
.venv/Scripts/python.exe tests/memory/worker_credit_reserve_probe.py --cases reports/credit-fixtures/cases.json --credits 4 32 64 128 --all-formats --tasks-per-credit 1 --independent-volumes
.venv/Scripts/python.exe tests/memory/worker_credit_reserve_probe.py --cases reports/credit-fixtures/cases.json --credits 2 --case 7z-PPMd --tasks-per-credit 8 --dynamic --cpu-rate 25
```

`--reserve-mib` 指定固定预留对照。处理器数量替身、Job 查询、精确 managed 提交和细密采样均只存在于测试 executable/驱动。独立 writer facility 在同一个测试盘上创建，不表示实际测试了 128 个物理盘。
