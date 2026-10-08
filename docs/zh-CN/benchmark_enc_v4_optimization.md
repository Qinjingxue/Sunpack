# ENC v4 后续优化

## 2026-10-08 方案 A：统一实现与 backend 收口

基线为干净的 `7a3bae84`。本轮目标是减少实现组合、保持已有性能与
CPU 兼容性，不新增 cipher、线程策略或 IO 路径。结果目录为
`benchmarks/results/enc-v4-optimization/20261008-consolidation`。
修改前保存 release examples、worker，以及同一源码的 32B proof 对照。

### 最终实现

- 删除 `parallel-kdf` / `parallel-decrypt` Cargo features 及关闭 feature
  时的生产实现；Rayon 成为必需依赖。CMake、Python native 和 benchmark
  构建均不再传这两个 features。KDF/CTR 复用现有共享 executor。
- 认证解密只留下 `Decoder::decrypt_with_budget`。总额度 1 是正常运行
  状态；动态 broker、executor 容量限制、4 KiB 最小切片及立即归还
  extra credits 的语义保留。KDF 仍最多借 3 个 extra，IO 不持有它们。
- 自定义 cipher 的 ISA 检测集中到 `src/backend.rs` 的 `OnceLock`。
  x64 AVX2 与 SHA/SSSE3/SSE4.1、ARM64 NEON 与 SHA2 独立判断。
  RC6/Serpent/Threefish/SHACAL 在构造时绑定函数指针，热循环不再检测
  自定义 ISA。缓存只包含 CPU flags；函数指针不持有 key、scratch 或 pool。
- RC6/Serpent/Threefish 保留 scalar short/tail。短输入在间接调用前
  直接使用 scalar；不为 32B proof 填满 SIMD lanes。Twofish 八块交错、
  SHACAL 两块 SHA-NI/ARM 四块 SHA2 的算法结构与轮函数不变。
- 上游 AES、Argon2、portable SHACAL compression 保留各自的 runtime
  backend。旧 CPU 的 scalar/portable 路径保留，不提高发布 CPU 下限。
  ARM64 本轮仅修改 dispatch，未编译、执行或测性能。
- 生产保持一个 256 KiB buffer、串行 BLAKE3 和既有 writer；bounded MAC
  仍在 benchmark，writer probe 仍只用于独立诊断构建。无生产 MAC 开关、
  双 buffer、AES 特殊线程策略或 ENC→ZIP 流式分支。

### 32B proof：避免短输入退化

新增 `proof` example，直接复用生产 cipher。每轮 4 MiB 表示独立执行
131072 次 32B CTR；每次使用 offset 0 和新 CTR scratch。排除 KDF、key
expansion、文件读取和密码字符检查，**不是完整密码探测耗时**。
固定 affinity `0,2,4,6`、executor 4；正反顺序 4 次，每进程 9 轮排除
前 2 轮，各有 28 个样本。下表为 `ns_per_proof` 中位数：

| 算法 | 基线 | 收口后 |
| --- | ---: | ---: |
| AES | 243.09 | 239.39 |
| RC6 | 296.99 | 293.77 |
| Serpent | 460.56 | 447.69 |
| Threefish | 385.58 | 382.08 |
| SHACAL | 261.79 | 259.51 |
| C4 | 1366.39 | 1338.84 |

初版所有输入都经过绑定指针，Threefish proof 出现约 4% 退化，因此
最终保留短输入直接 scalar 的入口。复测十算法均未出现这一退化；
约 1～3% 的差异不作为新提速承诺。初版和最终样本均保留于
`proof-paired.json`、`proof-final-paired.json`。

### 大载荷与完整认证

Windows x64 / i9-13980HX / release，固定 affinity `0,2,4,6`、executor 4。
十算法纯 CTR 每轮 32 MiB、256 KiB batch，正反顺序 4 次，每进程 9 轮
排除 2 轮。1 credit 结果变化为约 -2.9%～+0.7%；4 credits 的多数
算法变化在约 ±3.3%，Threefish 首次出现较大差异，另作复测。

复测增加两个指向**同一个最终二进制**的标签，64 MiB、13 轮排除
2 轮、正反顺序 4 次：Threefish 4 credits 的基线/after/same 为
3261.03/4922.19/4231.63 MiB/s。相同最终二进制之间也相差约 16%，
首次 -14.7% 没有稳定复现，不能从这组数据得出稳定增益或退化幅度。
原始记录为 `ctr-final-paired.json`、`ctr-final-repeat.json`，包含全部
样本；不同算法组合的绝对吞吐不直接互比。

原生 null-sink 包含缓存读取、key expansion、MAC、CTR，排除 Open KDF
和写盘。AES/SHACAL/C4 分别使用 64/16/8 MiB 独立 Java 输入；每进程
11 轮排除 2 轮，正反顺序 4 次，共 36 个样本。单位 **MiB/s**：

| 算法 / 总额度 | 基线 | 收口后 | 变化 |
| --- | ---: | ---: | ---: |
| AES / 1 | 2188.20 | 2164.48 | -1.1% |
| AES / 4 | 2295.79 | 2319.78 | +1.0% |
| SHACAL / 1 | 997.83 | 999.28 | +0.1% |
| SHACAL / 4 | 1791.55 | 1734.08 | -3.2% |
| C4 / 1 | 328.79 | 328.12 | -0.2% |
| C4 / 4 | 893.35 | 906.07 | +1.4% |

真实持久 worker 包含最终 KDF、完整认证和写盘；总容量 4、相同 affinity，
每档预热一次，正反顺序交替 11 轮。计时外使用 Rust 验证输出 size/CRC32，
foreground/watch 交错。八任务结果是总吞吐。单位 **MiB/s**：

| 算法 / 任务数 | 基线 | 收口后 | 变化 |
| --- | ---: | ---: | ---: |
| AES / 1 | 1367.52 | 1372.59 | +0.4% |
| AES / 8 | 1020.41 | 985.33 | -3.4% |
| SHACAL / 1 | 200.72 | 198.26 | -1.2% |
| SHACAL / 8 | 449.34 | 441.08 | -1.8% |
| C4 / 1 | 102.87 | 100.57 | -2.2% |
| C4 / 8 | 197.10 | 196.48 | -0.3% |

对应 `decrypt-final-paired.json`、`worker-final-paired.json`。本机完整路径
差异约在 ±3.5%；没有本轮新增大幅提速的证据，也不宣称所有机器严格零退化。

### 验证

无旧 features 的 x64 release worker 构建通过，standalone CRT 检查通过。
`sunpack-enc --release --locked --all-targets`：核心 **19 passed**，
examples 附带 **19 passed**（含重复复用的 cipher tests）。核心覆盖
十算法官方 vectors、KDF 额度 1～4、任意 CTR offset/counter carry、
动态额度、取消/错误/短读及 recovery/MAC 认证。独立 Java worker
大载荷 fixture 已补齐 Serpent，覆盖全部十算法。

Python 扩展已在现有 `.venv` 中以 release/locked 构建安装。完整密码探测
另做前后 sanity check：相同 affinity/executor，1 个调用 job，3 错 + 1
正确候选，每档 21 次排除前 2 次，取剩余 19 次的中位数。单位 **ms**：

| 输入 | 基线 | 收口后 |
| --- | ---: | ---: |
| 296B AES vector | 33.35 | 32.89 |
| Threefish vector | 33.46 | 33.42 |
| 8 MiB C4 | 33.10 | 32.78 |

这是先 before 后 after 的顺序检查，不是交替 A/B；不能据此承诺密码探测
加速，只用于确认本轮没有可见延迟问题。对应 `password-before.json`、
`password-after.json`。

选定 Python/真实 worker 回归：**244 passed, 2 skipped**。覆盖密码调度、
prepared-context 生命周期、十算法大载荷、额度 1/2/3/5/9、executor
1/3 限制、错误密码和 MAC 失败后的并发额度归还、CLI/watch 提交、载体
范围/原始分段及普通递归发现。2 项真实下载 watch 测试因未配置独立
WatchBroker 测试服务而跳过；未安装或改动系统监控服务。ARM64 未验证。

## 2026-10-08 第六轮：流水实验收口与 SHACAL SHA-NI

基线为干净的 `6b9cbb7e`，复用第五轮对应的最终 worker，并在修改前
保存本轮 baseline release examples。结果目录为
`benchmarks/results/enc-v4-optimization/20261008-round6`。
最终生产只保留 SHACAL x64 两块 SHA-NI；MAC/CTR 流水及 AES CTR
单线程策略均撤回，`lib.rs` 与本轮基线一致。writer 只做诊断。

### MAC(next) 与 CTR(current)：完成真实重叠，撤回生产实现

实验使用两个 256 KiB Zeroizing buffer。先认证首块，之后先读下一块，
再临时向既有 broker 借一个 extra credit，用现有 Rayon executor
执行两个独立任务：单线程 MAC(next) 与单线程 CTR(current)。两者完成
立即归还额度，再调用原有 output writer，交换两个 buffer。
没有新增 pool、IO thread、derived-key IPC 或 ENC→ZIP 特殊路径。

只对多 batch 的 AES 使用流水；慢 cipher 保留原来的 CTR 并行。
没有 extra credit 或 executor 只有一个线程时串行执行；progress、
read/write 均不持有额外额度。MAC 顺序涵盖全部 ciphertext/recovery，
quick proof 的 32B 不写出，CTR offset 保持原来的完整 counter 语义。
实验通过全算法多 buffer、MAC/恢复尾部损坏、取消、截断测试。
最终删除生产流水和额外 buffer，实验源、patch、二进制只存结果目录。

Windows x64 / i9-13980HX / release。AES 使用独立 Java/SSE 64 MiB
输入。原生 null-sink 包含缓存读取、MAC、CTR，排除 KDF 和写盘；
固定 affinity `0,2,4,6`、executor 4，每进程 11 轮排除前 2 轮，
正反顺序 4 次取 36 个样本中位数。所有表格单位为 **MiB/s**：

| 总额度 | 原路径 | 双 buffer | 变化 |
| --- | ---: | ---: | ---: |
| 1 | 2146.20 | 2136.01 | -0.5% |
| 2 | 1981.30 | 2466.19 | +24.5% |
| 4 | 2176.64 | 1880.80 | -13.6% |

不设置 affinity/executor 的复测为每进程 21 轮、排除 2 轮、正反顺序
4 次（76 样本）：额度 1 为 1991.73→2006.96，额度 2 为
1684.97→2179.40，额度 4 为 1342.84→2095.71。真实重叠可以改善
某些调度条件下的结果，但没有达到 3.5～4 GiB/s 的筛选目标。
不能把不同 executor/affinity 组的绝对值直接比较。

真实持久 worker 包含最终 KDF、MAC、CTR、写盘；每档预热一次，
正反顺序交替 21 轮，总 CPU 容量 4，不限制 Rayon pool。每轮在
计时外用 Rust 验证全部输出 size/CRC32，foreground/watch 交错：

| 自然调度 / 任务数 | 原路径 | 双 buffer | 变化 |
| --- | ---: | ---: | ---: |
| 第一组 / 1 | 1039.37 | 1470.14 | +41.4% |
| 第一组 / 8 | 2138.98 | 2093.15 | -2.1% |
| 加入串行对照后 / 1 | 952.45 | 1250.50 | +31.3% |
| 加入串行对照后 / 8 | 2803.68 | 2540.60 | -9.4% |

同一组额外构建了“MAC→AES CTR，CTR 始终单线程”的对照：单文件
1308.61、八文件 2394.98。流水单文件反而比这一串行对照低 **4.4%**，
说明原路径的改善不能全部归因于计算阶段重叠。串行 CTR 策略也导致
本组八文件相对原路径回退 **14.6%**，因此同样不保留。

另测固定 affinity、总容量 2：单文件 1375.41→1530.46（+11.3%），
八文件 2221.00→2126.91（-4.2%）。按照本轮“稳定大收益且多任务
不能明显回退”的要求，撤回这套流水。它与上一轮并行 MAC 是不同
实验；这里实测了真正同时运行的 MAC/CTR。原因中的调度/缓存影响
尚未单独 profile，不将其写成已证实的唯一瓶颈。

原始文件：`pipeline-null-paired.json`、`pipeline-null-natural.json`、
`pipeline-worker-natural.json`、`pipeline-worker-controls-natural.json`、
`pipeline-worker-credit2.json`。这是本机、256 KiB 批次、既有共享
executor 的结果，不外推所有 CPU、文件大小或更复杂的流水设计。

### SHACAL：保留两块 SHA-NI，四块没有额外收益

x64 检测 SHA/SSSE3/SSE4.1，使用 SHA-NI 交错处理两个独立 block；
单个完整尾块使用同一 const-generic kernel。SHACAL 不做 SHA 的
feed-forward，输入输出保持大端。复用 ARM 已有的 64 轮展开函数，
每个 cipher 只展开一次；原始 key 和固定 256B schedule 随 cipher
清零。不支持所需 ISA 的机器复用原来 `compress256` 的 fallback。
没有新增 heap、pool 或不同的密码探测链路。

指令语义参考 Rust 官方
[`_mm_sha256rnds2_epu32`](https://doc.rust-lang.org/core/arch/x86_64/fn._mm_sha256rnds2_epu32.html)。
新增 16 组随机 key、0～33 块、非对齐与尾部保护的独立 SHA compression
对照；保留全部官方 ENC vectors、counter carry/offset 测试。

纯 CTR 每轮 64 MiB、256 KiB batch，affinity `0,2,4,6`、executor 4；
9 轮排除 2 轮，正反顺序 4 次，共 28 个有效样本：

| 算法 / 额度 | 基线 | 两块 | 四块 | 两块 / 基线 |
| --- | ---: | ---: | ---: | ---: |
| SHACAL / 1 | 968.08 | 1386.83 | 1376.20 | 1.43× |
| SHACAL / 4 | 3159.11 | 4326.50 | 4237.49 | 1.37× |
| C4 / 1 | 320.30 | 358.10 | 360.00 | 1.12× |
| C4 / 4 | 1054.01 | 1113.92 | 1122.94 | 1.06× |

两块在 SHACAL 自身两档均略快、同时状态数更少，因此选择两块，
不保留四块开关。记录为 `shacal-ways-paired.json`。

最终完整认证 null-sink 使用独立 Java SHACAL 16 MiB、C4 8 MiB，
同样 affinity/executor；11 轮排除 2 轮、正反顺序 4 次（36 样本）：

| 算法 / 额度 | 基线 | 最终版 | 倍率 |
| --- | ---: | ---: | ---: |
| SHACAL / 1 | 633.28 | 984.38 | 1.55× |
| SHACAL / 4 | 1419.72 | 1774.64 | 1.25× |
| C4 / 1 | 280.10 | 340.72 | 1.22× |
| C4 / 4 | 763.27 | 905.05 | 1.19× |

最终真实 worker 总容量 4、同样 affinity，预热一次、交替 11 轮，
计时包括 KDF/写盘，输出验证在计时外：

| 算法 / 同批任务数 | 基线 | 最终版 | 变化 |
| --- | ---: | ---: | ---: |
| SHACAL 16 MiB / 1 | 592.47 | 644.89 | +8.8% |
| SHACAL 16 MiB / 8 | 1124.81 | 1220.12 | +8.5% |
| C4 8 MiB / 1 | 304.67 | 305.05 | +0.1% |
| C4 8 MiB / 8 | 563.74 | 585.14 | +3.8% |
| AES 64 MiB / 1 | 1277.24 | 1299.19 | +1.7% |
| AES 64 MiB / 8 | 2844.12 | 2772.55 | -2.5% |

最终 AES 路径源码完全一致，本组小波动不算 AES 提速或已证实退化。
SHACAL 的纯计算收益不能当成所有文件的端到端收益；C4 没有大幅
真实 worker 提升。记录为 `decrypt-final-paired.json`、
`worker-final-paired.json`。

### AES writer copy：诊断完成，不改生产接口

复用已有 `SUP7Z_ENABLE_WRITER_PROBE` build；同一个二进制分别以
`memory`、`memory-nocopy`、`real` 启动独立持久 worker。前两者
保留解码、认证、KDF、writer staging/queue/capacity 生命周期，但
不调用实际 WriteFile；nocopy 另外跳过 staging memcpy。
每个模式预热一次、交替 21 轮；总容量 4、AES 64 MiB。

| 调度 / 任务数 | memory | memory-nocopy | real | nocopy / memory |
| --- | ---: | ---: | ---: | ---: |
| 自然 / 1 | 1015.16 | 954.45 | 975.64 | 0.94× |
| 自然 / 8 | 2310.27 | 2967.68 | 2421.00 | 1.28× |
| affinity / 1 | 1317.60 | 1406.49 | 1329.39 | 1.07× |
| affinity / 8 | 3596.32 | 3607.33 | 2745.00 | 1.00× |

固定核心的单文件差值不到 10%，多文件自然调度的 28% 没有在
固定核心下复现，不满足稳定超过 30% 再考虑耦合改造的标准。
因此保留现有 Rust buffer→C++ writer memcpy。
自然调度 probe 的 copy 累计中位数约单任务 5.35ms、八任务 29.39ms；
各 job/thread phase 可能重叠，不能直接累加成整个 batch wall time。

扩展原有 `worker_enc_batch_ab` 的 `--writer-mode LABEL=MODE`，显式
标记无输出诊断。memory 模式不校验输出 CRC，检查成功状态、报告
字节数、probe 激活且没有输出文件；real 模式保持完整 Rust size/CRC
验证。它们不是能输出明文的 zero-copy 实现，绝对吞吐也不能当成
真实落盘性能。生产默认不编译 probe。
记录为 `writer-memory-paired.json`、`writer-memory-affinity.json`。

所有文件使用缓存输入、真实输出不 fsync；这些是本机计算/缓存写入
对照，不能解释成冷盘持久吞吐。Python 只调度和处理 JSON 指标，
数据生成、解密及输出校验继续由 Java/Rust/native 完成。

### 验证与 ARM64 范围

最终 ENC release tests：默认 feature 17 个生产测试通过；
`parallel-kdf,parallel-decrypt` 18 个通过；两种配置各有 9 个独立
example 对照通过。x64 worker（含 standalone CRT 检查）及 `.venv`
Rust 扩展重新构建。真实 worker 的独立 Java 大载荷测试加入 algo 8，
覆盖 1/2/3/5/9 额度、1/3 executor、损坏/错误密码、CLI/watch、
伪装载体与非对齐 concat ranges/缺尾；递归嵌套继续走普通输出发现。
最终 Python 回归 **232 passed、2 skipped（34.90s）**。两项跳过为
真实 watch 下载测试缺少已配置的隔离 WatchBroker 测试环境；未为
性能修改安装或切换系统监控服务。覆盖 password scheduler/failure/
lifecycle、ENC pipeline、全部 worker 大载荷、普通递归解密与错误
密码路径。`cargo fmt --check`、`git diff --check` 通过。

遵守此前 ARM64 只修改、不在本机验证的要求，本轮不进行 ARM64
编译、测试或性能验证；已有 ARM backend 不增加新设计。Windows
ARM64 十算法真机 benchmark 仍待具备硬件环境，不能依据本轮 x64
数据宣称 ARM 性能已验证。Twofish、密码探测及 ENC→ZIP 架构不改。

## 2026-10-08 第五轮：Twofish 交错、MAC 实验与 ARM64 后端

基线为干净的 `dc208f41`。本轮保留 Twofish 八块交错和 ARM64 后端，
撤回未取得稳定端到端收益的并行 MAC。结果目录：
`benchmarks/results/enc-v4-optimization/20261008-round5`。
修改前保存了基线 release examples/worker；最终 worker 与扩展重新构建。

### Twofish：保留八块交错

复用已有 4 KiB keyed S-box/MDS table 和 key schedule，每半轮依次处理
多块独立状态，隐藏 table lookup 的依赖延迟。bulk 使用八块，尾部
1～7 块使用同一 const-generic round function；删除原来的逐块完整轮
实现。没有 SIMD gather、额外 keyed table、heap buffer 或线程池。
全部 CTR 切片继续共享一个展开密钥；key/table 在 cipher 释放时清零。

新增独立 RustCrypto Twofish 对照，覆盖 16 组随机 key、0～33 blocks、
非对齐切片和所有尾块数。真实 worker 加入独立 Java/SSE Twofish 大载荷，
覆盖既有额度、executor、错误密码、MAC 损坏、CLI/watch 和载体分段测试。

Windows x64 / i9-13980HX / release / `parallel-kdf,parallel-decrypt`。
新增 `benchmarks.scenarios.enc_compute_ab`，交替执行预先构建的原生
examples。统一 affinity `0,2,4,6`、`RAYON_NUM_THREADS=4`；只改变
benchmark 进程，产品不设置这些参数。每进程 9 轮，排除前 2 轮，
正/反顺序共 4 次，28 个有效样本取中位数。单位均为 MiB/s。
与前轮不同 executor 设置的绝对吞吐不可直接横比。

纯 CTR 每轮 64 MiB，每次仍处理 256 KiB：

| 额度 | 基线逐块 | 四块交错 | 八块交错 | 八块 / 基线 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 318.45 | 605.78 | 640.88 | 2.01× |
| 4 | 1170.02 | 2074.87 | 2197.83 | 1.88× |

八块比四块再快约 6%，因此保留八块。四块仅用于 A/B，没有保留生产
开关或另一套 round function。

完整认证解密包含缓存文件读取、key expansion、MAC 和 CTR，输出到
null sink，排除 Open/KDF/实际写盘。AES 输入 64 MiB，Twofish/C4 为
独立 Java 8 MiB；同样 28 样本的方法：

| 算法 / 额度 | 基线 | 最终版 | 倍率 |
| --- | ---: | ---: | ---: |
| AES / 1 | 2230.75 | 2222.14 | 1.00× |
| AES / 4 | 2331.53 | 2299.75 | 0.99× |
| Twofish / 1 | 294.43 | 541.79 | 1.84× |
| Twofish / 4 | 835.13 | 1299.99 | 1.56× |
| C4 / 1 | 285.23 | 283.85 | 1.00× |
| C4 / 4 | 796.02 | 801.52 | 1.01× |

原始样本为 `twofish-ways-paired.json`、`decrypt-final-paired.json`。
实际 worker 的测量包含最终 KDF 和写盘，收益不能套用纯 CTR 倍率。

最终持久 worker 保持 broker 总额度 4，分别提交 1/8 个任务，交错
foreground/watch origin。每档预热一次，固定 affinity 交替 11 轮，
另做不设置 affinity 的自然调度 21 轮；每次输出在计时外由 Rust 核对
size/CRC32。输入缓存、输出不 fsync，不能解释为冷盘持续吞吐。

| Twofish 8 MiB / 同批任务数 | affinity 基线 | affinity 最终 | 倍率 | 自然调度基线 | 自然调度最终 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 277.71 | 317.13 | 1.14× | 199.69 | 213.79 | 1.07× |
| 8 | 518.49 | 668.76 | 1.29× | 356.43 | 408.91 | 1.15× |

8 MiB 单任务的 KDF/写出成本明显，不能把 cipher 的 2.01× 当作
用户端到端速度。自然调度复测中，AES 64 MiB 单/八任务为基线
1050.60/2132.41、新版 1037.14/2135.25；C4 8 MiB 为基线
187.42/317.91、新版 188.42/316.70，均没有稳定的大幅变化。

第一组 affinity 的 AES 单任务曾从 1352.61 降至 1231.08，随后增加
到 21 轮并同时启动两个相同最终二进制的进程，基线为 1309.13、
两个最终进程为 1316.81/1333.29。因此保留全部样本，不将第一组
差值当成已确认的生产退化或宣称 AES 提速。原始记录为
`worker-final-paired.json`、`worker-aes-repeat.json`、
`worker-final-natural.json`。自然调度 worker peak RSS 约 87.5 MiB，
主要峰值仍来自并行 KDF；256 KiB 流式 buffer 上限不变。

### BLAKE3：完成有界实验，生产保持单线程认证

上游 [`Hasher::update`](https://docs.rs/blake3/latest/blake3/struct.Hasher.html)
始终单线程；`update_rayon` 自行递归分工，接口不接受每次调用的线程
预算。为遵守共享 CPU broker，实验复用上游 hazmat 的 subtree hash
和 keyed merge，不自行实现 hash rounds：每批按实际授予额度生成最多
四个串行 leaf task，使用现有 Rayon executor，一次入队；前缀、最后
partial chunk 和 ROOT 合并遵守原始 BLAKE3 tree shape。

完整解密实验将原有每批 CpuLease 覆盖 MAC 和 CTR 两个连续阶段；
AES 的额外额度优先给 MAC，CTR 单线程。需求上限由数据量及 executor
共同限制；read/progress 在借额之前，write 在归还之后。恢复元数据
也完整认证。未新增 pool、IO task、双 buffer 或密钥 IPC。

单独 MAC 使用 256 KiB 数据块和 ENC 的 56 B nonce/header 前缀，每轮
128 MiB；同一 affinity、4 线程 executor、28 样本。最终可复现的
benchmark-only 实现位于 `benchmarks/native/enc_mac_bounded.rs`：

| 额度 | 上游 serial | bounded | 倍率 |
| --- | ---: | ---: | ---: |
| 1 | 5230.38 | 5148.74 | 0.98× |
| 2 | 5186.59 | 6653.73 | 1.28× |
| 3 | 5136.21 | 7182.84 | 1.40× |
| 4 | 5213.50 | 7137.80 | 1.37× |

本机单线程 MAC 已超过 5 GiB/s，不能预设它只有 2～3 GiB/s。初版
递归 join 的调度成本反而减速，已删除；一次任务计划的版本才取得
上述局部收益。独立上游 Hasher 对照覆盖空输入、1024 B chunk、
64/128/256 KiB 边界、1 MiB、不同前缀/分段及 1/2/3/4/5/9 额度，
并在每次 update 后逐一核对 finalize 结果。

完整认证 A/B 中，AES 1/4 额度分别为基线 2072.18/2191.44，实验
2067.92/2152.64，约 1.00/0.98×。原始记录为
`mac-final-paired.json` 和 `decrypt-bounded-paired.json`。

随后使用真实持久 worker，broker 总额度 4，相同 affinity，不额外
设置 executor 线程数；预热一次、交替 11 轮，计时包含 Open/KDF、
认证和写盘，Rust 在计时外核对每次输出 size/CRC32：

| 输入 / 同批任务数 | 基线 | MAC 实验版 | 倍率 |
| --- | ---: | ---: | ---: |
| AES 64 MiB / 1 | 1245.17 | 1284.73 | 1.03× |
| AES 64 MiB / 8 | 2471.04 | 2315.67 | 0.94× |
| C4 8 MiB / 1 | 318.29 | 321.48 | 1.01× |
| C4 8 MiB / 8 | 564.09 | 559.95 | 0.99× |

记录为 `worker-bounded-paired.json`。单 MAC 的增益没有转化为稳定的
完整解密收益，八任务 AES 还下降约 6.3%，因此撤回生产 MAC 调度
改动，仍由上游 Hasher 顺序认证。保留独立 benchmark 和测量记录；
不会因一个局部数字增加产品复杂度。生产新增 Hasher 的 Zeroizing
释放，正常完成、取消和错误退出时清除临时认证状态。

### ARM64：实现四套后端，仅修改源码

- Serpent：NEON 四块，复用已有 Boolean circuits、轮函数和 key schedule，
  保留 ENC 的 word/byte 反转规则；不足四块继续 scalar。
- RC6：NEON 四 lane，bulk 交错两组共八块，复用已有乘法/加法/可变
  rotate 轮函数和展开密钥；不足四块继续 scalar。
- Threefish-1024：NEON 两块，复用已有 80 轮、rotation/permutation 和
  zero-tweak key schedule；不足两块继续 scalar。
- SHACAL-2：ARMv8 SHA2 指令四块交错，key 的 SHA-256 message schedule
  和 64 个 round constant 只展开一次，直接输出 rounds，不做 feed-forward。
  1～3 尾块也使用硬件路径；无 SHA2 的 CPU 复用原有 compress256 fallback。

入口均通过 runtime feature detection，支持非对齐缓冲；没有第二套
容器/密码分析，CTR offset、载体 ranges 和递归发现链路继续复用原实现。
SHACAL 原有 cipher enum 内的 fallback 已移至统一模块并删除旧实现。
所有展开密钥随 cipher 清零释放，没有新全局缓存或每块 heap 分配。

**按本轮要求，没有做 ARM64 编译、执行或性能验证，也不宣称收益倍数。**
本机通过的官方向量与集成测试只验证 x64 路径；ARM64 类型检查和
硬件正确性/性能仍需要后续在目标机器上执行。

### x64 验证

Rust release 默认 feature 16 项、并行 feature 17 项通过；examples
包含 MAC 上游对照 1 项和 cipher 对照 7 项，两种 feature 配置均通过。
保持原有全算法/Unicode/KDF、完整 counter 进位、任意 offset、短读、
取消、认证恢复数据和额度归还覆盖。最终 x64 worker 与 `.venv` release
扩展重新构建；相关 Python 回归 **220 项通过、2 项跳过**。
覆盖 scheduler/cache/failure/lifecycle、官方 ENC、CLI/watch submission、
嵌套递归、错误密码/MAC 损坏保留源文件、八种独立 Java 大载荷算法，
以及 1/2/3/5/9 broker 容量、1/3 executor、非对齐载体 ranges、缺失尾段
和并发失败后的额度归还。两项真实 watch 下载监听测试因本次没有配置
隔离的临时 Watch Broker 服务而跳过；本轮没有执行 ARM64 验证。

## 2026-10-08 第四轮：CTR 公共层和单候选最终确认

基线为干净的 `c9258e83`。修改源码前保存该版本的 release examples 和
第三轮构建的 x64 worker；新旧版本使用相同 Cargo.lock、构建参数与独立
Java/SSE 输入。RC6/Blowfish 的第三轮实现已在此基线中，本轮不重复计算
它们此前的收益。结果目录：`benchmarks/results/enc-v4-optimization/20261008-round4`。

### 实现与边界

- CTR refill 用满已有 2048 B pad：8/16/32/128 B cipher block 分别最多
  256/128/64/16 blocks。AES adapter 内部分成最多 16 blocks 的组调用
  原有 RustCrypto backend，保留最后一组。没有增加 pad 或引入新 AES 实现。
- 8/16 B counter 分别使用 u64/u128 big-endian wrapping arithmetic 批量
  填充，消除逐 block 动态长度复制和逐 byte 进位。32/128 B counter
  继续使用原有全宽进位。整个 nonce 回绕、任意 offset、跨块/跨 refill
  的分段语义不变。32 B password proof 仍只生成它所需的完整 blocks。
- 流式读取保持 256 KiB 上限；短输入按实际的 ciphertext/recovery 长度
  分配 buffer。例如 296 B ENC 的工作 buffer 从 256 KiB 降至 224 B。
  buffer 仍由 Zeroizing 在本次解密结束时清零并释放。
- 密码调度完成去重、成功缓存和负缓存处理后，若 Rust 输入描述明确为
  ENC 且只剩一个候选，直接复用 worker 已有的单候选 extraction-confirmation
  路径。正确候选只在最终 Decoder::open 运行一次 KDF；成功/明确拒绝后
  才进入既有缓存确认流程。多个候选继续走 Rust fast proof，独立密码探测
  API 不变。损坏等非密码失败仍保留 worker 原有的有界诊断，可能再做 proof。
- 密钥不通过 IPC，也没有新增归档分析、ENC→ZIP 特殊通路、线程池、后台
  缓冲任务或等待。CPU 额度仍按原有每批 acquire/release，写出前归还；
  加密载荷输出为普通文件，继续由递归发现处理 ZIP。

### CTR 与完整认证解密

Windows x64 / i9-13980HX / release / `parallel-kdf,parallel-decrypt`。
为减少混合核心迁移干扰，这组对照进程使用相同 logical CPU affinity
`0,2,4,6`；只作用于 benchmark，不改变产品并发和 CPU broker。每算法
独立进程，顺序为基线→新版→新版→基线，各 9 轮，去掉每组前 2 轮，
共 14 个有效样本取中位数。与第三轮的自然调度绝对吞吐不能直接横比。
纯 CTR 每轮 32 MiB，每次仍处理 256 KiB；单位 MiB/s。

| 算法 | 基线 1 额度 | 新版 1 额度 | 倍率 | 基线 4 额度 | 新版 4 额度 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-256 | 2655.99 | 6201.54 | 2.34× | 6429.97 | 9467.49 | 1.47× |
| RC6 | 1325.93 | 1816.75 | 1.37× | 3784.46 | 4746.52 | 1.25× |
| Serpent | 619.10 | 753.04 | 1.22× | 2038.65 | 2368.59 | 1.16× |
| Blowfish-256 | 536.81 | 712.44 | 1.33× | 1725.92 | 2082.28 | 1.21× |
| Twofish-256 | 287.19 | 298.52 | 1.04× | 1040.08 | 1099.56 | 1.06× |
| GOST | 280.64 | 318.99 | 1.14× | 994.44 | 1087.63 | 1.09× |
| Blowfish-448 | 527.16 | 721.81 | 1.37× | 1833.70 | 2208.08 | 1.20× |
| Threefish-1024 | 1713.53 | 1717.25 | 1.00× | 4171.59 | 4341.94 | 1.04× |
| SHACAL-2 | 1019.71 | 978.56 | 0.96× | 3080.43 | 3005.64 | 0.98× |
| C4 | 279.50 | 323.87 | 1.16× | 919.32 | 1004.24 | 1.09× |

单独放宽 refill 的初测没有取得 AES 大跳；大部分 AES/RC6/Blowfish
收益来自整数 counter fill。SHACAL 本轮略慢，不宣称每个算法都改善。
同 affinity 下纯 AES encrypt_blocks 的中位吞吐约 10276 MiB/s，而新
CTR 约 6202 MiB/s；差值还包含必须执行的 counter fill/XOR，以及不同的
block group/data layout，不等于可免费消除的开销。本轮复用上游 AES
硬件 backend，没有再维护一套 AES-NI/VAES round-key 或 runtime dispatch。

完整认证解密包含文件读取、key expansion、完整 BLAKE3 MAC 和 CTR，输出
到 null sink，排除 Open/KDF。AES 为独立 Java 64 MiB 输入，RC6/两种
Blowfish/C4 为 8 MiB；相同 affinity、交替顺序和中位数方法。

| 算法 | 基线 1 额度 | 新版 1 额度 | 倍率 | 基线 4 额度 | 新版 4 额度 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-256 | 1447.98 | 2049.40 | 1.42× | 1350.05 | 1453.53 | 1.08× |
| RC6 | 902.01 | 1179.28 | 1.31× | 1161.06 | 1264.66 | 1.09× |
| Blowfish-256 | 457.39 | 578.91 | 1.27× | 837.98 | 956.12 | 1.14× |
| Blowfish-448 | 460.74 | 576.87 | 1.25× | 833.74 | 949.19 | 1.14× |
| C4 | 237.56 | 266.63 | 1.12× | 547.93 | 597.13 | 1.09× |

### 真实 worker 和读取批次取舍

新增 `benchmarks.scenarios.worker_enc_batch_ab`，通过原有持久 worker transport
执行真实写出；包含最终 KDF、认证、输出 manifest 和 job 完成。每档预热
一次，再交替顺序测 7 轮；broker 总额度固定为 4，分别提交 1/8 个任务，
并发批次交错 foreground/watch origin。对每次输出在计时外由 Rust 校验
size/CRC32，完成后删除临时输出。缓存输入、不清系统 cache、不 fsync；
测量包含正常写回影响，不能视作冷盘持续吞吐或整个递归链路吞吐。
本次 sweep 使用自然 OS 调度；以下各列只有读取 batch 不同，均包含新版 CTR。

| 输入 / 同批任务数 | 256 KiB | 512 KiB | 1 MiB | 2 MiB | 4 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES 64 MiB / 1 | 1014.6 | 1247.3 | 1204.2 | 1324.9 | 1346.1 |
| AES 64 MiB / 8 | 2842.4 | 2333.3 | 2211.1 | 2712.0 | 1965.8 |
| C4 8 MiB / 1 | 258.6 | 262.3 | 270.8 | 268.7 | 267.4 |
| C4 8 MiB / 8 | 557.2 | 549.4 | 531.5 | 524.4 | 491.2 |

较大 batch 改善单 AES 任务，但没有稳定改善并发吞吐；会增加每个 active
解密的 buffer 和额度持有时间。因此生产保留 256 KiB。worker peak RSS
约 86 MiB，各档差异很小，峰值由并行 KDF 主导；不能把此峰值解释为
更大 buffer 没有逐任务内存成本。修改小输入分配无需抬高大输入内存上限。

另用相同 `0,2,4,6` affinity、基线/最终 256 KiB worker 做 11 轮交替复测：

| 输入 / 同批任务数 | 基线 | 新版 | 倍率 |
| --- | ---: | ---: | ---: |
| AES 64 MiB / 1 | 1079.2 | 1314.7 | 1.22× |
| AES 64 MiB / 8 | 2126.6 | 2301.5 | 1.08× |
| C4 8 MiB / 1 | 272.2 | 282.4 | 1.04× |
| C4 8 MiB / 8 | 463.0 | 509.8 | 1.10× |

自然 OS 调度的独立 11 轮复测中，AES 单/八任务约 1.06/1.09×，C4 约
1.03/1.05×，也保持正收益。真实 worker 的增益小于纯 CTR，不能把 AES
的 2.34× 直接套到实际写盘或嵌套解压。两份完整复测和 sweep JSON 都保留。

### 单密码候选端到端

`benchmarks.scenarios.reader_enc_single_candidate_ab` 从本地 `c9258e83`
载入旧 scheduler，与新 scheduler 交替运行；两侧使用相同 worker 与
原生扩展。每轮创建新的 PipelineEngine/worker，计时 engine.run，包含
ENC 解密成普通文件、发现 ZIP、继续解压和清理流程。每档预热一次，
11 轮取中位数，无 CPU affinity 设置，官方 296 B 伪装 `.mov` 输入。

| origin | 基线 | 新版 | 耗时减少 |
| --- | ---: | ---: | ---: |
| foreground | 55.93 ms | 38.38 ms | 31.4% |
| watch | 54.09 ms | 38.07 ms | 29.6% |

逐轮记录的 host ENC proof 次数由 1 降至 0；正确密码的最终 Open/KDF
仍由 Rust Decoder 执行一次。多候选吞吐及单独 password-probe API 没有
改变；此次收益是去掉重复 KDF，不是削减 Argon2 工作量或传递 derived key。
这里的 watch 是生产 PipelineEngine 的 watch submission path，真实服务
下载监听属于下面单独的验证限制。

### 验证与限制

重新构建 x64 worker 和 `.venv` 中的 release 原生扩展后，Rust 默认 feature
15 项、并行 feature 16 项全部通过。新增独立逐 block counter 对照，覆盖
全部九种基础 cipher、8197 B、多次 2 KiB refill、2047/2048/2049 B 分段、
全 nonce 进位/回绕，以及 proof 不过度生成。原有官方十算法、Unicode、
KDF 参数、超 32 位 offset、短读、取消、写出错误、MAC/recovery 和额度
归还测试继续通过。

Python 相关回归共 208 项通过：包括 scheduler/cache/failure/lifecycle、
官方 ENC、CLI/watch submission、嵌套递归、单候选无 host proof、错误
密码/MAC 损坏保留源文件、独立 Java 大载荷 AES/RC6/两种 Blowfish/
GOST/Threefish/C4，1/2/3/5/9 broker 容量、1/3 executor 线程、非对齐
分段载体及缺失尾段，现有 Plan 2 解密/Plan 3 错误密码行为。2 项真实
watch 下载监听测试因本次没有隔离的临时 Watch Broker 服务而跳过；
当前进程没有管理员 token，没有启动服务安装脚本的交互式提权。

ARM64 的生产 cipher 源码独立 harness cargo check 通过；这不是完整
ARM64 extension/worker 构建或硬件性能验证。本轮改动为可移植 counter
和调度层，保留已有 ARM fallback；没有声称实现或测试 NEON backend。
读/MAC↔CTR 双 buffer 和 BLAKE3 parallel 本轮均未引入。

## 2026-10-08 第三轮：RC6 AVX2 和 Blowfish 八块交错

基线为干净的 `d5038a82`，Windows x64、i9-13980HX、release，启用
`parallel-kdf,parallel-decrypt`。修改源码前构建并保存 baseline examples；
新旧版本使用相同 Cargo.lock、release profile、benchmark 源码和输入。

### 实现与内存

- RC6-32/20/32 每个 AVX2 向量状态含 8 个独立 block，交错两个状态，
  一组处理 16 blocks。寄存器中完成转置、u32 wrapping multiply/add、
  xor 和逐 lane 可变旋转；旋转计数掩码为 31，包括零旋转。CPU/OS
  运行时检测后才进入 AVX2。剩余完整的 8 blocks 使用单状态 AVX2，
  更短尾部和非 AVX2/ARM64 使用同一轮函数的标量路径。round key 仍为
  44 × u32 = 176 B，展开一次后供所有 CTR 任务共享，退出时清零。
- Blowfish-256/448 共享同一实现，每组交错 8 个独立 block 的 16 轮
  table lookup，专门处理 1～7 blocks 的尾组；使用 ENC 原有 big-endian
  block 约定。每个 stream 仍只有一份 18-word P-array 和 4 × 256-word
  keyed S-box，共 4168 B，退出时清零。key expansion 复用同一标量轮
  函数；没有第二份 keyed table，没有全局密钥缓存。
- 原生产 RC6 逐块适配器和 Blowfish 通用 adapter 已移除。两个上游 cipher
  库及 cipher 0.5 接口移至 ENC 的 dev-dependencies，用作独立测试参考。
  复用原有 CTR counter/pad、共享 executor 和 CPU broker；没有新增线程池、
  流式缓冲区、归档分析路径或密钥 IPC。KDF/密码候选调度保持不变。

### 性能

纯 CTR：每算法独立进程，16 MiB、7 轮、256 KiB 原有生产缓冲区。
每档基线→新版→新版→基线，各取 14 轮中位数，单位 MiB/s。

| 算法 | 基线 1 额度 | 新版 1 额度 | 倍率 | 基线 4 额度 | 新版 4 额度 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-256 | 2845.28 | 2857.12 | 1.00× | 4337.78 | 4288.42 | 0.99× |
| RC6 | 484.38 | 1398.97 | 2.89× | 1073.58 | 2303.61 | 2.15× |
| Serpent | 644.33 | 651.56 | 1.01× | 1331.74 | 1327.16 | 1.00× |
| Blowfish-256 | 327.40 | 610.31 | 1.86× | 794.04 | 1448.95 | 1.82× |
| Twofish-256 | 314.80 | 315.55 | 1.00× | 881.29 | 870.65 | 0.99× |
| GOST | 313.57 | 315.88 | 1.01× | 899.89 | 892.89 | 0.99× |
| Blowfish-448 | 324.47 | 602.38 | 1.86× | 800.94 | 1440.52 | 1.80× |
| Threefish-1024 | 1939.12 | 1939.36 | 1.00× | 2583.77 | 2524.09 | 0.98× |
| SHACAL-2 | 1082.62 | 1087.09 | 1.00× | 2429.95 | 2562.59 | 1.05× |
| C4 | 299.91 | 302.53 | 1.01× | 749.99 | 732.48 | 0.98× |

完整认证解密：独立 Java 64 MiB AES、8 MiB RC6/两种 Blowfish/C4。
含读取、key expansion 和完整 BLAKE3 MAC，输出到 null sink，不含 Open/KDF；
同样交替运行两组，每档每版 14 轮中位数，单位 MiB/s。

| 算法 | 基线 1 额度 | 新版 1 额度 | 倍率 | 基线 4 额度 | 新版 4 额度 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-256 | 1506.67 | 1511.34 | 1.00× | 1359.43 | 1347.96 | 0.99× |
| RC6 | 420.65 | 988.03 | 2.35× | 800.96 | 1152.29 | 1.44× |
| Blowfish-256 | 294.98 | 506.92 | 1.72× | 642.73 | 891.16 | 1.39× |
| Blowfish-448 | 294.37 | 513.82 | 1.75× | 640.09 | 890.95 | 1.39× |
| C4 | 251.26 | 253.98 | 1.01× | 561.32 | 547.54 | 0.98× |

单线程 RC6 CTR 约 2.89×、两种 Blowfish 约 1.86×；完整认证解密
分别约 2.35×、1.72/1.75×。未修改算法有小幅双向波动，不把这些差异
认定为本轮收益。中间 A/B 的 RC6 单向量组约 1076～1112 MiB/s，
交错双组约 1348～1377 MiB/s。Blowfish 四块/八块同机交替对照：
单额度分别约 549～551 / 610～614 MiB/s；四额度的 256-bit key 约
1326 / 1440 MiB/s，448-bit key 约 1367 / 1368 MiB/s。因此选择八块，
不宣称每种额度/密钥都能取得相同比例的额外收益。
以上是本机 cached-file/null-sink 测量，不能当作实际写盘或整个递归流程吞吐。

AES 的纯 CTR 单额度约 2857 MiB/s，完整认证路径约 1511 MiB/s；
四额度纯 CTR 约 4288 MiB/s，完整路径却只有 1348 MiB/s，与基线一致。
因此 read/MAC 和调度仍有研究空间，但差值不等于可重叠的独立阶段耗时。
当前不能据此保证双 buffer 的收益；本轮保留原有串行 read+MAC→CTR，
将来实验需要在相同总 CPU 额度下比较，处理借不到 extra credit 的回退、
取消/短读/写出错误、双 buffer 的释放和有序认证，以及多任务吞吐。

### 验证

Rust 默认 feature 14 项、并行 feature 15 项全部通过。RC6 独立对照上游
24 组随机密钥、0～33 blocks、标量/直接 AVX2/dispatcher、非对齐前缀
和保护后缀；覆盖单/双向量组以及全部尾部。Blowfish 两种 key size 各
12 组随机密钥、0～33 blocks，独立对照 key expansion、轮函数和全部
尾组。原有官方十种算法、Unicode、KDF 参数、counter 全宽进位/回绕、
任意 offset/chunking、多缓冲区并行认证、短读、取消、输出失败和 CPU
额度生命周期测试继续通过。

重新构建 x64 worker 和 `.venv` 中的 release 原生扩展后，108 项 ENC
生产单元/集成测试全部通过，无跳过。复用原来的大载荷 worker fixture，
新增 RC6、Blowfish-256、Blowfish-448 三种独立 Java 2 MiB 输入，原有
GOST/Threefish/C4 同时继续验证。覆盖 1/2/3/5/9 CPU broker 容量、
1/3 executor 线程、CLI/watch 混跑、错误候选、MAC 损坏和额度归还。
伪装扩展名、嵌套递归、并发密码候选、分段载体跨非对齐 header/proof/
payload 范围和缺失尾段均通过；准备状态失效和重复正确候选的优先级
规则继续通过。输出比较使用既有 native CRC32/字节比较，没有添加
输出 SHA-256 校验。

安装 `aarch64-pc-windows-msvc` Rust 标准库后，直接引用生产 `cipher.rs`
及其各 backend 的独立 Rust harness 已通过 ARM64 `cargo check`，包含
`parallel-decrypt`。完整 `sunpack-enc` 的 ARM64 检查仍被本机缺少交叉
C 编译器/headers 阻断：BLAKE3 NEON C 源码的 `assert.h` include 失败。
因此只记录 cipher 模块编译通过，不宣称整个 ARM64 库构建或实机运行
通过；本轮没有新增 NEON/ARMv8 专用 cipher 实现。harness 直接引用
生产源码，没有修改生产依赖来绕过该构建错误。

Clippy 无错误，只有原有 Twofish range-loop 和两处 KDF auto-deref 提示。
worker standalone CRT 检查、打包脚本 PowerShell 语法和
`git diff --check` 通过。许可分别保存于 `licenses/rc6-license.txt`、
`licenses/blowfish-license.txt`，接入 notices 和 Windows 打包流程。

原始对照与中间 batch-width A/B 数据保存在
`benchmarks/results/enc-v4-optimization/20261008-round3/`。
完整认证输入由原有 `tests/helpers/EncV4Fixtures.java` 独立生成，位于
`benchmarks/.work/enc/20261008-round3/algorithm-{0,1,3,6}/large.enc`；
C4 继续使用既有 8 MiB 样本。

```powershell
cargo build --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --examples
foreach ($code in 0..9) { & native/target/release/examples/throughput.exe 16 7 1 "$code" }
foreach ($code in 0..9) { & native/target/release/examples/throughput.exe 16 7 4 "$code" }
native/target/release/examples/decrypt.exe benchmarks/.work/enc/20261008-round3/algorithm-0/large.enc sunpack-test 4 7
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc --lib
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --lib
uv run --no-sync pytest tests/unit/test_enc_support.py `
  tests/integration/test_enc_pipeline.py tests/integration/test_enc_parallel_worker.py -q
```

## 2026-10-08 第二轮：Threefish AVX2 和 GOST 交错计算

本轮基线为 `1ff1aac4`，Windows x64、i9-13980HX、release，启用
`parallel-kdf,parallel-decrypt`。基线 example 在修改生产代码前从干净 HEAD
构建并保存；新版使用相同 Cargo.lock、release profile 和 benchmark 程序。

### 实现

- Threefish-1024 使用 ENC 的固定零 tweak，展开一次的 21 组 round key
  共 2688 B，与原依赖的 key schedule 大小相同，所有 CTR 任务共享，退出
  时清零。每八轮展开成常量旋转与固定 permutation，十个周期保留循环。
  AVX2 每组处理 4 个 128 B block；转置在寄存器内完成，支持非对齐地址。
  CPU/OS 运行时检测后才进入 AVX2，余下 1～3 个 block、非 AVX2 CPU 和
  ARM64 使用同一轮函数的标量路径。
- GOST 28147-89 TestSbox 原来已有字节 S-box 表。本轮把 substitution 和
  rotate 合并为 4 × 256 × u32 的固定只读表，共享 4 KiB，不按密码或
  stream 创建表。每组交错计算 4 个独立 block，尾部专门处理 1/2/3 个；
  ENC byte-order 适配直接使用 little-endian 加载/存储。每个密钥只保留
  32 B key words，退出时清零。
- 原生产 GOST/Threefish 通用适配器已删除，两个上游库只作为 block cipher
  的测试参考；Skein KDF 仍使用原来的上游 Threefish 依赖。AES/Blowfish
  的原有批处理移除不再使用的 reverse 分支。没有新增线程池、流式缓冲区、
  密钥 IPC 或归档分析路径；继续复用 Rust CTR、全宽计数器、共享 Rayon、
  CPU broker，以及 CLI/watch 的普通递归解压链路。

### 吞吐

纯 CTR：每个算法在独立进程测量 16 MiB，7 轮，使用原有 256 KiB 缓冲区。
每档以基线→新版→新版→基线运行，各取 14 轮中位数，单位 MiB/s。
完整解密使用既有 8 MiB 官方 Java C4 样本，同样交替测量，每档每版 14 轮；
包含读取和完整 BLAKE3 MAC，输出到 null sink，排除 Open/KDF。

| 算法 | 基线 1 额度 | 新版 1 额度 | 倍率 | 基线 4 额度 | 新版 4 额度 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-256 CTR | 2863.64 | 2839.12 | 0.99× | 4354.53 | 4336.53 | 1.00× |
| RC6 CTR | 480.87 | 482.99 | 1.00× | 1055.42 | 1065.16 | 1.01× |
| Serpent CTR | 637.47 | 653.62 | 1.03× | 1329.46 | 1339.27 | 1.01× |
| Blowfish-256 CTR | 327.77 | 328.06 | 1.00× | 820.56 | 804.70 | 0.98× |
| Twofish-256 CTR | 315.23 | 317.08 | 1.01× | 876.71 | 870.49 | 0.99× |
| GOST CTR | 101.26 | 317.33 | 3.13× | 319.48 | 888.17 | 2.78× |
| Blowfish-448 CTR | 328.17 | 328.56 | 1.00× | 833.76 | 797.32 | 0.96× |
| Threefish-1024 CTR | 436.87 | 1943.88 | 4.45× | 1033.87 | 2505.27 | 2.42× |
| SHACAL-2 CTR | 1076.13 | 1081.36 | 1.00× | 2592.31 | 2450.00 | 0.95× |
| C4 CTR | 199.20 | 303.55 | 1.52× | 532.82 | 746.07 | 1.40× |
| C4 完整认证解密 | 178.16 | 252.68 | 1.42× | 403.87 | 537.42 | 1.33× |

Threefish 单线程约 4.45×，GOST 约 3.13×，C4 完整认证解密约 1.42×。
未修改算法的数据也有双向波动，尤其四额度受 executor 调度和频率影响，
不把这些变化归因于本轮算法优化。这些是本机结果，null sink 吞吐不等于写盘速度。

旧版十种算法在同一进程依次运行时，C4 单线程曾测到约 47 MiB/s，
而独立进程约 199 MiB/s，与完整解密结果一致。运行顺序为何影响旧版
纯 CTR 尚未确定，因此上表统一使用独立进程数据，不采用该异常低值
计算收益；混跑、初测和复测的原始数据全部保留。

### 密码探测与验证

本轮没有调整候选调度、Argon2 参数或 CPU 额度策略。短 proof 同样使用新的
primitive，但主要耗时仍是 KDF，不把大载荷 CTR 倍率套用到密码探测。

生产 `NativeArchiveSession.enc_fast_verify_passwords`，3 个错误候选后接正确
候选、11 轮：296 B 官方 AES 样本中位数 21.80 ms，8 MiB 官方 C4 样本
21.34 ms，两者逻辑读取量均为 72 B。这是当前状态检查，没有同轮旧扩展
对照，不宣称密码探测因本轮改动有上述 CTR 倍率的提升。采样峰值 RSS
增量分别约 41.81/40.22 MiB，结束增量 1.80/0.18 MiB；20 ms 采样可能
遗漏瞬时峰值，既有 KDF 工作区预算和批次结束释放策略不变。

Rust 默认 feature 12 项、并行 feature 13 项全部通过。Threefish 额外独立
对照上游实现：12 组随机密钥、0～17 blocks、非对齐起始、保护前后缀、
标量、SIMD 直调和 dispatcher；GOST 对照 24 组随机密钥、0～33 blocks、
全部尾组和非对齐起始。原有官方十种算法、Unicode、KDF 参数、CTR 任意
chunk/offset、全宽 counter 进位/回绕、recovery、MAC、短读、取消、输出
错误以及 1/2/3/4/5/8/9 额度多缓冲区解密继续通过。

重新构建并安装 `.venv` 中的 release 原生扩展，重新构建 x64 worker 后，
72 项生产 ENC 单元/集成测试全部通过，无跳过。既有 worker 测试扩展至
GOST、Threefish、C4 三种独立 Java 2 MiB 样本，覆盖 1/2/3/5/9 broker
容量、1/3 executor 线程、CLI/watch 并发混跑、错误密码和 MAC 损坏后的
额度归还。载体伪装为 `.mkv`，跨非对齐 header/proof/payload ranges；
完整范围正确输出，缺失尾段返回 damaged。原有伪装扩展名、嵌套递归、
并发候选优先级和准备状态失效测试均通过，输出比较继续使用 native CRC32
和字节比较，不对输出计算 SHA-256。

Clippy 无错误，只有原有 Twofish range-loop 和 KDF auto-deref 提示。
worker 的 standalone CRT 检查、Windows 打包脚本语法解析和
`git diff --check` 通过。ARM64 未在本机编译，标量路径已在 x64 上独立对照。

### 复现

```powershell
cargo build --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --examples
foreach ($code in 0..9) { & native/target/release/examples/throughput.exe 16 7 1 "$code" }
foreach ($code in 0..9) { & native/target/release/examples/throughput.exe 16 7 4 "$code" }
native/target/release/examples/decrypt.exe benchmarks/.work/enc/c4/large.enc sunpack-test 1 7
native/target/release/examples/decrypt.exe benchmarks/.work/enc/c4/large.enc sunpack-test 4 7
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc --lib
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --lib
uv run --no-sync pytest tests/unit/test_enc_support.py `
  tests/integration/test_enc_pipeline.py tests/integration/test_enc_parallel_worker.py -q
```

原始 CSV/JSON 位于 `benchmarks/results/enc-v4-optimization/20261008-round2/`。
改编来源为 RustCrypto threefish 0.5.2 和 magma 0.9.0；完整许可分别保存在
`licenses/threefish-license.txt`、`licenses/magma-license.txt`，并接入 Windows
打包校验与复制流程。

## 2026-10-08：Serpent SIMD、候选调度和最终 KDF

本轮基线为 `d3d5407b`，Windows x64、i9-13980HX、release。纯 CTR 和完整
解密的基线使用该提交的 Rust 源码单独构建，依赖锁定到当前 `native/Cargo.lock`，
采用相同 release profile。以下取墙钟中位数；这些是本机结果。

### 实现

- Serpent 每次使用 AVX2 同时处理 8 个 block，运行时检测 CPU/OS 支持。
  byte-order 适配、输入转置和输出转置在寄存器内完成。未满 8 个 block、
  非 AVX2 CPU 和 ARM64 使用相同 Boolean circuits 的标量路径。标准 key
  schedule 只展开一次，33 组 round key 共 528 B，供所有 CTR 任务共享，
  退出时清零；不创建线程池或增加流式缓冲区。原生产 Serpent 逐块适配器
  已删除，RustCrypto Serpent 仅作为测试参考依赖保留。C4 复用同一路径。
- Rust 密码探测原先已经按四条 KDF lane 分摊 executor，却又将候选数量
  除以四来限制候选任务数，导致 2～4 个候选只有一个工作区依次运行。
  去掉这次重复限制，保留活动批次分摊、原有 64 MiB 工作区预算、每组复用
  工作区和最早候选优先规则。默认参数下，单批 4 个候选最多临时使用
  4 × 10 MiB；不能将采样 RSS 当作实际工作区大小。
- worker 最终 Open/KDF 使用现有 CPU broker 的 base credit，最多借 3 个
  extra credit。只在获得 extra 后初始化共享 Rayon executor；容量较小时
  立即归还多借额度。1/2/3/4 额度对应最多 1/2/3/4 个任务，各任务负责
  自己的 lane，所有任务完成当前 slice 后才开始下一 slice。单额度直接使用
  SIMD 串行计算，无 Rayon 调度。错误返回和成功返回均归还额度，后续
  recovery/framing 读取前已归还。CMake worker 同时启用 `parallel-kdf` 和
  `parallel-decrypt`，选中密码仍在 worker 内独立派生，不引入密钥 IPC。

### 吞吐

纯 CTR：16 MiB、7 轮，算法参数筛选 `2,4,9`，256 KiB 生产缓冲区。
完整解密：既有 8 MiB 官方 Java C4 样本、7 轮，含读取和完整 BLAKE3 MAC，
输出到 null sink，不含 Open/KDF。吞吐单位为 MiB/s。

| 测试 | CPU 额度 | d3d5407b | 本轮 | 倍率 |
| --- | ---: | ---: | ---: | ---: |
| Serpent CTR | 1 | 143.11 | 638.39 | 4.46× |
| Serpent CTR | 4 | 422.79 | 1190.86 | 2.82× |
| Twofish CTR | 1 | 298.46 | 301.00 | 1.01× |
| Twofish CTR | 4 | 843.14 | 859.62 | 1.02× |
| C4 CTR | 1 | 90.98 | 179.93 | 1.98× |
| C4 CTR | 4 | 289.47 | 513.76 | 1.77× |
| C4 完整认证解密 | 1 | 87.03 | 166.97 | 1.92× |
| C4 完整认证解密 | 4 | 263.90 | 435.81 | 1.65× |

这也补齐了上一轮 Twofish 的新数据：`d3d5407b` 已达到约 300 MiB/s 单线程，
本轮没有继续改它。表格中的完整解密仍不是实际写盘速度。

### 密码探测与最终 KDF

通过生产 `NativeArchiveSession.enc_fast_verify_passwords` 测量 296 B 官方 AES
样本，3 个错误候选后接正确候选。基线 7 轮、本轮 11 轮，中位耗时从
50.94 ms 降至 31.30 ms（约 1.63×，耗时减少 38.6%）。逻辑读取量仍为
72 B。默认参数的单批工作区上限仍有效，工作区在本批结束释放。

较大批次的对照原始数据也保留：65 候选单批为 365.88→291.30 ms，8 批并发
为 8281.01→3220.39 ms。但这些负载的候选组数没有因本轮调整而改变，且机器
运行状态波动明显，尤其 8 批基线远慢于 2026-10-07 的数据。因此不把这两项
差异归因于本轮调度优化，也不宣称所有并发负载都有相同收益。8 批并发的
采样峰值 RSS 增量为 224.34→223.61 MiB，结束增量为 3.66→3.60 MiB。

单独测量新的生产 `Decoder::open_with_budget`，每档 11 轮，包含工作区分配、
最终密码 proof、清零释放和 framing 读取，排除 worker 进程启动与正式解密：

| 总 CPU 额度 | Open 中位耗时 ms |
| ---: | ---: |
| 1 | 17.89 |
| 2 | 13.98 |
| 3 | 12.92 |
| 4 | 13.96 |

4 额度相对同一 SIMD 实现的 1 额度耗时减少约 22%。lane 调度和内存带宽使
收益不随额度单调增加；生产仍按实时 broker 授权使用额度，不为短样本降低
其他任务并发。密码探测 RSS 每 20 ms 采样，短调用会漏掉峰值，不能据此
宣称 4 工作区只使用 1.79 MiB。

### 验证和复现

Rust 默认 feature 10 项、并行 feature 11 项测试通过。Serpent 额外对照
RustCrypto：12 组独立密钥、0～33 blocks、不同起始对齐、SIMD 直调和标量
路径；原有官方十种 cipher、Unicode、counter 进位/回绕、非对齐 offset、
多缓冲区、MAC/recovery、短读、取消和输出 I/O 失败测试继续通过。新增测试
对照 1/2/3/4 额度派生结果，并检查密码错误和后续读取前的额度释放。

生产 Python/worker 的 48 项 ENC 测试通过，覆盖 CLI/watch、伪装扩展名、
嵌套、分段 range 密码输入、重复正确候选的优先顺序、错误密码、损坏和并发
任务。新增官方大 C4 载体跨非对齐 header/proof/payload ranges 的完整解密与
缺失尾段失败用例，分别在 CLI/watch 来源验证。worker 在 executor 只有
1/3 个线程时也验证额度归还与官方输出。
输出比较使用原有 native CRC32/字节比较。Clippy 无错误，只有原有 Twofish
range-loop 和 KDF auto-deref 提示。ARM64 未在本机编译，标量算法已独立对照。

```powershell
cargo run --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --example throughput -- 16 7 1 '2,4,9'
cargo run --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --example open -- `
  native/sunpack_enc/tests/data/algorithm_0.mov sunpack-test 4 11
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc --lib
cargo test --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-kdf,parallel-decrypt --lib
uv run --no-sync pytest tests/unit/test_enc_support.py `
  tests/integration/test_enc_pipeline.py tests/integration/test_enc_parallel_worker.py -q
```

原始 CSV/JSON 位于 `benchmarks/results/enc-v4-optimization/20261008/`。
密码性能报告由原有 `reader.enc-password-fast-path` scenario 生成。Serpent
circuits 来源为 [RustCrypto Serpent 0.6 源码](https://docs.rs/serpent/0.6.0/src/serpent/bitslice.rs.html)，
许可保存在 `licenses/serpent-license.txt`。

## 2026-10-07 历史记录

2026-10-07，Windows x64，i9-13980HX（32 个逻辑处理器），release 构建。
基线为 `5aed45e3`。以下数据为本机观测，使用 MiB/s；纯 cipher 测试每项
8 MiB、3 轮，完整解密每项 8 MiB、7 轮，取墙钟中位数。

## 实现

- `argon2 0.6` 的 `parallel-kdf` 仅由 Python 扩展启用。四条 lane 与候选
  计算共用现有 Rayon 池，工作区仍按原有每批 64 MiB 预算分配并在批次退出释放。
  候选分组也按四条 lane 和当前活动批次数分摊 executor 容量，减少嵌套任务
  等待时保留的工作区；不增加线程池，也不保留密码或工作区。活动计数通过
  RAII 在返回/错误时释放。
- Serpent 从 RustCrypto 0.5 升到 0.6，复用上游位切片实现；保留 SSE 的
  key/block 字节序适配，C4 同样受益。
- 正式解密每个 256 KiB 批次重新向 worker CPU-credit broker 申请可用额度。
  取得 `k` 个额外额度就分成 `1+k` 个 CTR 任务，包括 2、3、5、9 等数量。
  后续批次可增减；没有固定 8 线程上限，也没有 AES/其他算法的并行开关。
  每片至少 4 KiB，避免给极小尾块分配无用额度；executor 容量不足时立即归还
  多取的额度。没有获得额外额度时不会为这个批次初始化 Rayon executor。
- 所有任务复用同一个 `apply_at(offset)`，共享展开后的密钥，各自持有 counter/pad。
  C4 每层使用自己的 block size、完整大端 counter 和绝对密文字节偏移。
  counter/pad 退出时清零。计算结束即归还额外额度，读取、写入期间不持有额度。
- worker 使用共享 Rayon executor，不逐任务创建线程池。BLAKE3 保持单线程，
  只占 base credit；没有为哈希引入另一套并行调度。worker 的最终密码 KDF
  仍不启用 lane 并行。CMake 按 package 单独构建，避免 Cargo feature 合并。

## 纯 CTR 吞吐

排除 KDF、认证和磁盘 I/O，使用生产 cipher；256 KiB 缓冲区反复处理。
线程数表示给予这些 CTR 任务的 CPU 额度，任务总数不会超过这份额度。

| 算法 | 基线 1 | 优化 1 | 优化 2 | 优化 4 | 优化 8 | 优化 32 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES | 2404 | 2581 | 3968 | 4030 | 3482 | 8541 |
| RC6 | 425 | 427 | 774 | 1055 | 1347 | 3809 |
| Serpent | 5.01 | 137 | 257 | 412 | 639 | 1199 |
| Blowfish-256 | 287 | 299 | 512 | 766 | 1054 | 2570 |
| Twofish | 3.10 | 3.25 | 6.42 | 12.17 | 22.35 | 49.47 |
| GOST | 92.48 | 96.06 | 181 | 300 | 490 | 869 |
| Blowfish-448 | 295 | 301 | 526 | 731 | 1065 | 2030 |
| Threefish-1024 | 370 | 399 | 801 | 1073 | 1363 | 2454 |
| SHACAL-2 | 935 | 951 | 1669 | 2469 | 2679 | 6696 |
| C4 | 5.10 | 89.76 | 175 | 280 | 443 | 785 |

Serpent 单线程约为基线的 27 倍，C4 单线程约为 18 倍。Twofish 的上游
实现仍是明显瓶颈，收益主要来自获得的 CPU 额度。快速 cipher 的短样本容易
受调度/缓存影响；评估真实磁盘负载应另测 worker，不能把纯 CTR 吞吐当作写盘速度。

## 官方 C4 样本：读取、CTR、MAC、null sink

样本由 SSE Java 实现独立生成。基线使用原提交的 Rust 源码单独编译，
两者都验证整个文件 MAC，不含 Open/KDF，也不写磁盘。

| 实现 / 总 CPU 额度 | 耗时 ms | MiB/s |
| --- | ---: | ---: |
| 基线 1 | 1353.060 | 5.913 |
| 优化 1 | 98.603 | 81.133 |
| 优化 2 | 52.886 | 151.268 |
| 优化 3 | 39.026 | 204.993 |
| 优化 4 | 32.659 | 244.957 |
| 优化 5 | 29.788 | 268.567 |
| 优化 8 | 25.111 | 318.583 |
| 优化 9 | 23.887 | 334.909 |
| 优化 16 | 16.950 | 471.976 |
| 优化 32 | 16.442 | 486.562 |

这些是固定预算的可复现实验；生产 worker 每批次使用实际取得的预算。
没有通过限制其他任务并发或者加入等待来保持测试中的额度。

## 密码探测

通过生产 `NativeArchiveSession.enc_fast_verify_passwords` 测量 296 B 官方样本。
1/4 个候选各 7 轮，65 个候选单批 5 轮，8 批并发各 3 轮。
基线 1/4 候选为本次改动前实测，65 候选沿用前一份报告的数据。

| 候选 / 并发批次 | 基线 ms | 优化 ms | 优化峰值 RSS 增量 MiB | 优化结束 RSS 增量 MiB |
| --- | ---: | ---: | ---: | ---: |
| 1 / 1 | 30.86 | 27.80 | 2.06 | 1.70 |
| 4 / 1 | 110.02 | 71.88 | 11.71 | 1.71 |
| 65 / 1 | 430.74 | 367.51 | 63.41 | 3.39 |
| 65 / 8 | 2523.51 | 2836.25 | 226.42 | 7.29 |

读取量仍为 72 B，不随密码数量和 payload 大小增长。少量候选和单批大候选
有收益；8 批同时探测时，本次测试比前次报告慢约 12%，峰值 RSS 则从
前次的 323.91 MiB 降到 226.42 MiB，约低 30%。仅开启 lane 并行、不调整
候选分组的中间版本峰值为 424.15 MiB，因此没有采用那个分组策略。
每批 64 MiB 的限制保持有效，不能把它理解为整个进程的 64 MiB 上限。
多批次探测仍受内存带宽和 lane 调度影响，不能宣称所有并发负载都更快。
RSS 每 20 ms 采样，短调用可能漏掉峰值，单候选的 2.06 MiB 不是实际
工作区大小；默认工作区仍是 10 MiB。

## 验证与复现

Rust 默认 feature 和并行 feature 都验证十种官方 cipher、Unicode 密码及
KDF 参数；新增测试覆盖 counter 全宽进位/回绕、超过 32 位的 offset、非对齐
切片、多缓冲区、认证 recovery、短读、取消、输出 I/O 失败和额度释放。
同一次解密还模拟额度从 1→2→3→5→7→4→1→6 变化，并比较完整输出。
worker 测试使用独立 Java C4 样本，验证 1/2/3/5/9 的 broker 额度及 executor
容量更小时退还多取额度；CLI/watch 混合任务和 MAC 失败后的后续任务也受验证。
输出使用 native CRC32/字节比较，不增加 SHA-256 输出校验。

```powershell
# 生产 cipher：可使用 256/1024 MiB，1/2/3/4/5/8/9/16/32 额度。
cargo run --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-decrypt --example throughput -- 256 3 5

# 生成独立官方 C4 样本（Java 17+）。
$encJar = 'reference/implementations/SSEFilePC/S.S.E. File Encryptor for PC/ssefenc.jar'
javac --release 17 -cp $encJar -d benchmarks/.work/enc tests/helpers/EncV4Fixtures.java
java -cp "benchmarks/.work/enc;$encJar" EncV4Fixtures benchmarks/.work/enc/c4 9 8
cargo run --manifest-path native/Cargo.toml --release -p sunpack-enc `
  --features parallel-decrypt --example decrypt -- `
  benchmarks/.work/enc/c4/large.enc sunpack-test 5 7

uv run --no-sync python -m benchmarks reader enc-password-fast-path `
  --path native/sunpack_enc/tests/data/algorithm_0.mov --wrong-passwords 3 --rounds 7 --jobs 1

cargo test --manifest-path native/Cargo.toml -p sunpack-enc --release --lib
cargo test --manifest-path native/Cargo.toml -p sunpack-enc --release `
  --features parallel-kdf,parallel-decrypt --lib
uv run --no-sync pytest tests/unit/test_enc_support.py `
  tests/integration/test_enc_pipeline.py tests/integration/test_enc_parallel_worker.py -q
```

Rust 性能入口在 `benchmarks/native/enc_ctr.rs` 和 `enc_decrypt.rs`，通过 crate 的
example target 运行；没有另建 cipher/parser 实现。原始 CSV/探测 JSON 保存在
`benchmarks/results/enc-v4-optimization/20261007/`；探测完整报告也在原有 benchmark
scenario 的结果目录中。

库实现依据：[Argon2 parallel feature](https://docs.rs/crate/argon2/0.6.0/features)，
[RustCrypto Serpent 0.6 源码](https://docs.rs/serpent/0.6.0/src/serpent/lib.rs.html)。
