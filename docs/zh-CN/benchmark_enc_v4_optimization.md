# ENC v4 后续优化

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
