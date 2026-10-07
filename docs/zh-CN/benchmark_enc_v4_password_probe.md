# ENC v4 密码探测

2026-10-07，Windows x64，release 构建。输入由 SSE File Encryptor
17.4.4 的 Java 实现独立生成；密码为 64 个错误候选后接正确候选。
每项运行 3 次，以下为墙钟耗时中位数。测试通过生产
`NativeArchiveSession.enc_fast_verify_passwords` 调用，不启动 worker。

| 输入 | 批次并发 | Rayon | 耗时 | 3 轮合计逻辑读取 | 峰值 RSS 增量 | 结束 RSS 增量 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 296 B | 1 | 默认 | 430.74 ms | 72 B | 62.70 MiB | 2.68 MiB |
| 32 MiB | 1 | 默认 | 437.19 ms | 72 B | 61.05 MiB | 0.12 MiB |
| 32 MiB | 1 | 1 线程 | 1834.09 ms | 72 B | 11.04 MiB | 0.14 MiB |
| 32 MiB | 8 | 默认 | 2523.51 ms | 72 B | 323.91 MiB | 2.93 MiB |

32 MiB 单批次的并行版本约为串行版本的 4.2 倍速度。输入大小不改变
密码探测的读取量；后续轮次和同一输入的并发批次复用现有的
generation-aware 元数据缓存。表中读取量是 native reader 的逻辑请求量，
不是操作系统物理磁盘扇区读取量。

默认 KDF 每个工作区为 10 MiB；每批按 64 MiB 临时工作区预算并行计算。
工作区逐候选复用，计算结束释放，不放入长期缓存。多个批次共享现有
Rayon 池，因此并发场景的总临时内存随同时执行的计算数增长。RSS
增量包含线程栈、分配器和采样开销，不等于 KDF 实际分配量。

完整解密使用 256 KiB 缓冲区，32 MiB 官方明文通过 native CRC32 比对。
文件 MAC 在解密阶段验证；快速探测既不读取完整密文，也不验证 ZIP。

复现命令：

```powershell
uv run --no-sync python -m benchmarks reader enc-password-fast-path `
  --path native/sunpack_enc/tests/data/algorithm_0.mov `
  --path C:\path\to\large.enc --wrong-passwords 64 --rounds 3 --jobs 1
# 在另一个进程设置 RAYON_NUM_THREADS=1，得到串行基线。
# --jobs 8 用于并发批次。
```

完整原始报告保存在 `benchmarks/results/reader.enc-password-fast-path/`。
Java 样本生成器为 `tests/helpers/EncV4Fixtures.java`；它的 32 MiB 样本
为任意普通字节，用于确认 ENC 解密层不依赖 ZIP 内容。
