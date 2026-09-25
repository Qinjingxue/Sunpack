# 可复现的 worker 与 7-Zip 对比测试

本文是根目录 README 简表对应的详细测试记录，说明 SunPack 原生 worker
与配套命令行 `7z.exe` 在所有生成格式上的端到端对比方法。

## 软件和机器

测试软件身份：

| 组件            | 值                                                                            |
| --------------- | ----------------------------------------------------------------------------- |
| SunPack         | v0.7.0                                                                        |
| 仓库 HEAD       | `c3eaec11`                                                                    |
| worker 源码     | commit `c3eaec11`（`perf(bzip2): stream full blocks through one input pass`） |
| BZip2 并行宽度  | 最多 4 个 lane：调用线程加最多 3 个 worker 线程                               |
| worker 二进制   | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe`        |
| 7-Zip CLI       | 7-Zip 26.03 (x64)，`tools/7z.exe`                                             |
| 7-Zip SHA-256   | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`            |
| worker SHA-256  | `8f1a0b1c5ff50b79206101112682b429d2e6349f9a47a630968ecfce5e6fee32`            |
| 测试日期 / JSON | 2026-09-25；`benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json`   |

测试机器：

| 属性             | 值                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------- |
| 操作系统         | Windows 11 专业工作站版，x64，build 26100                                              |
| 电脑             | MSI Vector GP78HX 13VI                                                                 |
| CPU              | 13th Gen Intel Core i9-13980HX，24 个物理核心 / 32 个逻辑处理器                        |
| 内存             | 31.77 GiB                                                                              |
| benchmark 所在盘 | `C:` NTFS，Samsung NVMe MZVL21T0HCLR-00B00，总容量 934.47 GiB，采集时约剩余 197.80 GiB |

复现脚本也会在 JSON 中记录机器清单、当前电源计划、二进制 hash 和
7-Zip 版本。

## corpus 和压缩包特征

测试使用 `few_large` corpus，未压缩 payload 为 314,572,800 bytes（300 MiB），
恰好包含两个成员：

- 一个确定性的 150 MiB 文件，内容为重复的 `sunpack-benchmark\n` 文本；
- 一个使用固定种子 `20260729` 生成的确定性 150 MiB 随机文件。

输入因此一半是高度可压缩数据，一半是不可压缩数据。没有加密、载体数据、
嵌套归档或缺失分卷。corpus builder 使用 `small_files=8`、`large_files=2`、
`large_file_mib=150`；`few_large` 归档只包含两个大文件。

| case             | 压缩方法和构造             | solid / 分卷布局         | 归档大小和比例                                           |
| ---------------- | -------------------------- | ------------------------ | -------------------------------------------------------- |
| 7z split         | LZMA2，7-Zip 默认          | 默认 solid 行为，`-v16m` | 10 卷；总计 157,320,674 bytes                            |
| 7z solid         | LZMA2，`-ms=on`            | solid，单卷              | 157,320,674 bytes；占 payload 50.01%；payload/归档 2.00x |
| 7z non-solid     | LZMA2，`-ms=off`           | 非 solid，单卷           | 157,319,999 bytes；50.01%；2.00x                         |
| ZIP              | Deflate，7-Zip 默认        | 单个 ZIP                 | 157,703,555 bytes；50.13%；1.99x                         |
| RAR5 split       | RAR5 默认方法              | 默认 solid 行为，`-v16m` | 10 卷；总计 157,594,577 bytes                            |
| RAR5 solid       | RAR5 默认方法，`-s`        | solid，单卷              | 157,592,751 bytes；50.10%；2.00x                         |
| RAR5 non-solid   | RAR5 默认方法，`-s-`       | 非 solid，单卷           | 157,295,918 bytes；50.00%；2.00x                         |
| RAR4 solid       | RAR4 默认方法，`-ma4 -s`   | solid，单卷              | 157,769,630 bytes；50.15%；1.99x                         |
| RAR4 non-solid   | RAR4 默认方法，`-ma4 -s-`  | 非 solid，单卷           | 157,365,992 bytes；50.03%；2.00x                         |
| TAR              | 无压缩                     | 单个 TAR                 | 314,575,360 bytes；TAR 元数据/padding 增加 2,560 bytes   |
| Gzip / TGZ       | TAR 外层 Deflate           | 压缩流字节相同           | 157,773,338 bytes；50.15%；1.99x                         |
| BZip2 / TBZ2     | TAR 外层 BZip2             | 压缩流字节相同           | 158,006,051 bytes；50.23%；1.99x                         |
| XZ / TXZ         | TAR 外层 LZMA2             | 压缩流字节相同           | 157,321,248 bytes；50.01%；2.00x                         |
| Zstandard / TZST | TAR 外层 Zstandard level 3 | 压缩流字节相同           | 157,305,941 bytes；50.01%；2.00x                         |

表中的百分比是 `归档 bytes / 300 MiB payload`，第二个比例是
`payload bytes / 归档 bytes`。分卷归档大小为 `archive_catalog.archive_bytes_total`
记录的所有卷大小之和。

7z、ZIP、TAR 和 TAR codec 样本由 7-Zip 生成，RAR4/RAR5 由 `Rar.exe` 生成，
Zstandard 由 `zstd.exe -3` 生成。`tgz`、`tbz2`、`txz` 和 `tzst` 是对应
压缩 TAR 的字节相同副本。

## 测量方法

- 每个 case 测量 5 次，不使用 warmup；
- 每个 case 使用一个持久 native worker，5 次测量复用同一进程；
- 每次 `7z.exe` 参考测试都启动新进程，包含进程启动时间；
- 关闭 worker 诊断字段和预取；
- 两种实现使用同一个生成归档；
- 表格中的耗时为每个 case 的 wall time 中位数，单位为毫秒；
- 每 20 ms 对 native worker 和 `7z.exe` 的进程树采样一次常驻集大小（RSS）。
  每次运行记录采样到的峰值，表格展示每个 case 的 5 次峰值中位数，单位为 MiB。
  RSS 只统计 worker/7-Zip 及其子进程，不含 Python benchmark 主进程。短于采样间隔
  的瞬时峰值可能不会被捕获。

此版本的 BZip2 worker 使用单次输入遍历流式处理完整 block，最多使用 4 个并行
lane。测试是端到端测试，不是纯 decoder 微基准；因此保留了产品中 worker 持久化的
执行方式，同时也保留了命令行参考实现的进程启动开销。压缩 TAR 别名以
`7z.exe` 返回码为 0 且输出有效 TAR 为成功标准；TAR 元数据解释了输出比两个
原始成员多出的 2,560 bytes。

## 结果

### 耗时和峰值 RSS（每 case 中位数）

先并列展示 worker 的耗时和 RSS，再展示 `7z.exe` 的对应数据。耗时比和 RSS
比均为 worker 除以 7-Zip；小于 1 表示该项 worker 更低。

| 格式 / 变体        |     Worker 耗时（ms） |     `7z.exe` 耗时（ms） |    耗时比 |     Worker 峰值 RSS（MiB） |     `7z.exe` 峰值 RSS（MiB） |  RSS 比 |
| -------------- | ----------------: | ------------------: | -----: | ---------------------: | -----------------------: | -----: |
| 7z split       |           151.347 |             209.220 |  0.723 |                469.258 |                  458.383 |  1.024 |
| 7z non-solid   |           192.130 |             249.181 |  0.771 |                319.113 |                  308.051 |  1.036 |
| 7z solid       |           148.431 |             206.594 |  0.718 |                469.215 |                  458.309 |  1.024 |
| BZip2          |         1,752.476 |           2,947.405 |  0.595 |                 43.137 |                   12.637 |  3.414 |
| Gzip           |            67.378 |             195.667 |  0.344 |                 24.992 |                    8.219 |  3.041 |
| RAR5 split     |           224.977 |             780.676 |  0.288 |                 52.066 |                   40.504 |  1.285 |
| RAR4 non-solid |           170.297 |             181.628 |  0.938 |                 24.281 |                   11.605 |  2.092 |
| RAR4 solid     |           630.189 |             655.308 |  0.962 |                 25.020 |                   12.352 |  2.026 |
| RAR5 non-solid |           126.030 |             180.823 |  0.697 |                 52.008 |                   39.609 |  1.313 |
| RAR5 solid     |           192.755 |             756.119 |  0.255 |                 53.059 |                   40.473 |  1.311 |
| TAR            |            72.315 |             118.175 |  0.612 |                 25.000 |                    7.301 |  3.424 |
| TBZ2           |         1,769.768 |           2,972.193 |  0.595 |                 44.023 |                   12.629 |  3.486 |
| TGZ            |            71.309 |             202.180 |  0.353 |                 25.016 |                    8.211 |  3.047 |
| TXZ            |           169.861 |             183.313 |  0.927 |                474.453 |                  458.520 |  1.035 |
| TZST           |            93.847 |             152.214 |  0.617 |                 21.473 |                    9.801 |  2.191 |
| XZ             |           165.727 |             182.915 |  0.906 |                474.484 |                  458.520 |  1.035 |
| ZIP            |            93.797 |             197.793 |  0.474 |                 20.379 |                    7.988 |  2.551 |
| ZST            |            95.207 |             156.096 |  0.610 |                 21.414 |                    9.801 |  2.185 |

18 个 worker case 和 18 个 `7z.exe` case 均成功。各 case 独立耗时中位数之和：
worker 为 6,187.841 ms，`7z.exe` 为 10,527.500 ms（0.588x，约低 41.2%）。
这是各 case 中位数之和，便于概览，不代表一次串行运行。BZip2/TBZ2 worker 峰值
约 43–44 MiB，`7z.exe` 约 12.6 MiB；solid 7z/XZ worker 约 469–474 MiB，
`7z.exe` 约 458 MiB。RSS 是采样到的每 case 峰值中位数，不跨格式求和。

## 复现

```powershell
uv sync --locked --extra dev
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker --parallel
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.0 `
  --worker-source-commit c3eaec11 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json
```

独立脚本入口：

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.0 --worker-source-commit c3eaec11 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json
```

使用 `--metadata-only` 只生成 corpus 和 catalog，不执行解压；使用
`--format zip --runs 1` 可做快速 smoke test。脚本会记录原始样本、7z `-slt`
归档属性、分卷大小、压缩率、机器信息和耗时/RSS 中位数。RSS 每 20 ms
从子进程采样，结果 JSON 保存每次测量的原始峰值。
