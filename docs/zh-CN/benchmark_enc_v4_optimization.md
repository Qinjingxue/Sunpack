# ENC v4 后续优化

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
