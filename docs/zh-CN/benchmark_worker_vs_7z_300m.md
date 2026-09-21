# 可复现的 worker 与 7-Zip 对比测试

本文是根目录 README 简表对应的详细测试记录，说明 SunPack 原生 worker
与配套命令行 `7z.exe` 在所有生成格式上的端到端对比方法。

## 软件和机器

测试软件身份：

| 组件           | 值                                                                     |
| -------------- | ---------------------------------------------------------------------- |
| SunPack        | v0.6.2                                                                 |
| worker 源码    | commit `86587874`                                                      |
| worker 二进制  | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe` |
| 7-Zip CLI      | 7-Zip 26.03 (x64)，`tools/7z.exe`                                      |
| 7-Zip SHA-256  | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`     |
| worker SHA-256 | `38c48d83d3e8d57445192d820334c08d548caf41e9a9a659537102c28af90adb`     |

测试机器：

| 属性             | 值                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------- |
| 操作系统         | Windows 11 专业工作站版，x64，build 26100                                              |
| 电脑             | MSI Vector GP78HX 13VI                                                                 |
| CPU              | 13th Gen Intel Core i9-13980HX，24 个物理核心 / 32 个逻辑处理器                        |
| 内存             | 31.77 GiB                                                                              |
| benchmark 所在盘 | `C:` NTFS，Samsung NVMe MZVL21T0HCLR-00B00，总容量 934.47 GiB，采集时约剩余 240.01 GiB |

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
| 7z split         | LZMA2，7-Zip 默认          | 默认 solid 行为，`-v16m` | 每卷 16 MiB；总大小由 `archive_catalog` 记录             |
| 7z solid         | LZMA2，`-ms=on`            | solid，单卷              | 157,320,673 bytes；占 payload 50.01%；payload/归档 2.00x |
| 7z non-solid     | LZMA2，`-ms=off`           | 非 solid，单卷           | 157,319,998 bytes；50.01%；2.00x                         |
| ZIP              | Deflate，7-Zip 默认        | 单个 ZIP                 | 157,703,555 bytes；50.13%；1.99x                         |
| RAR5 split       | RAR5 默认方法              | 默认 solid 行为，`-v16m` | 每卷 16 MiB；总大小由 `archive_catalog` 记录             |
| RAR5 solid       | RAR5 默认方法，`-s`        | solid，单卷              | 157,592,751 bytes；50.10%；2.00x                         |
| RAR5 non-solid   | RAR5 默认方法，`-s-`       | 非 solid，单卷           | 157,295,918 bytes；50.00%；2.00x                         |
| RAR4 solid       | RAR4 默认方法，`-ma4 -s`   | solid，单卷              | 157,769,630 bytes；50.15%；1.99x                         |
| RAR4 non-solid   | RAR4 默认方法，`-ma4 -s-`  | 非 solid，单卷           | 157,365,992 bytes；50.03%；2.00x                         |
| TAR              | 无压缩                     | 单个 TAR                 | 314,575,360 bytes；TAR 元数据/padding 增加 2,560 bytes   |
| Gzip / TGZ       | TAR 外层 Deflate           | 压缩流字节相同           | 157,773,336 bytes；50.15%；1.99x                         |
| BZip2 / TBZ2     | TAR 外层 BZip2             | 压缩流字节相同           | 158,006,043 bytes；50.23%；1.99x                         |
| XZ / TXZ         | TAR 外层 LZMA2             | 压缩流字节相同           | 157,321,248 bytes；50.01%；2.00x                         |
| Zstandard / TZST | TAR 外层 Zstandard level 3 | 压缩流字节相同           | 157,305,941 bytes；50.01%；2.00x                         |

表中的百分比是 `归档 bytes / 300 MiB payload`，第二个比例是
`payload bytes / 归档 bytes`。旧计时结果对 split case 只保存了第一个分卷，
因此 split 总大小以新运行的 `archive_catalog.archive_bytes_total` 为准。

7z、ZIP、TAR 和 TAR codec 样本由 7-Zip 生成，RAR4/RAR5 由 `Rar.exe` 生成，
Zstandard 由 `zstd.exe -3` 生成。`tgz`、`tbz2`、`txz` 和 `tzst` 是对应
压缩 TAR 的字节相同副本。

## 测量方法

- 每个 case 测量 5 次，不使用 warmup；
- 每个 case 使用一个持久 native worker，5 次测量复用同一进程；
- 每次 `7z.exe` 参考测试都启动新进程，包含进程启动时间；
- 关闭 worker 诊断字段和预取；
- 两种实现使用同一个生成归档；
- 表格使用每个 case 的 wall time 中位数，单位为毫秒。

这是端到端测试，不是纯 decoder 微基准；因此保留了产品中 worker 持久化的
执行方式，同时也保留了命令行参考实现的进程启动开销。压缩 TAR 别名以
`7z.exe` 返回码为 0 且输出有效 TAR 为成功标准；TAR 元数据解释了输出比两个
原始成员多出的 2,560 bytes。

## 结果

| 格式 / 变体    | SunPack worker | `7z.exe` | worker / `7z.exe` |
| -------------- | -------------: | -------: | ----------------: |
| 7z split       |        152.350 |  209.230 |             0.728 |
| 7z non-solid   |        207.955 |  252.429 |             0.824 |
| 7z solid       |        161.992 |  207.314 |             0.781 |
| BZip2          |       2661.051 | 2992.485 |             0.889 |
| Gzip           |         84.008 |  204.110 |             0.412 |
| RAR5 split     |        231.310 |  780.304 |             0.296 |
| RAR4 non-solid |        170.658 |  183.902 |             0.928 |
| RAR4 solid     |        645.206 |  659.011 |             0.979 |
| RAR5 non-solid |        126.918 |  184.521 |             0.688 |
| RAR5 solid     |        212.166 |  759.690 |             0.279 |
| TAR            |         86.768 |  123.733 |             0.701 |
| TBZ2           |       2533.095 | 2975.355 |             0.851 |
| TGZ            |         84.924 |  201.506 |             0.421 |
| TXZ            |        177.336 |  179.254 |             0.989 |
| TZST           |         89.280 |  154.064 |             0.579 |
| XZ             |        178.589 |  182.980 |             0.976 |
| ZIP            |         94.941 |  197.796 |             0.480 |
| ZST            |         96.481 |  155.547 |             0.620 |

各 case 的独立中位数之和：worker 为 7,995.028 ms，`7z.exe` 为 10,603.231 ms，
worker/7z 为 **0.754x**，约低 24.6%。18 个 case 中 worker 都更快；收益最大
的是 RAR5 solid、RAR5 split、Gzip/TGZ 和 ZIP，RAR4 接近持平，XZ/TXZ 基本持平。

## 复现

```powershell
uv sync --locked --extra dev
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.6.2 `
  --worker-source-commit 86587874 `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-reproduced.json
```

独立脚本入口：

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --worker-source-commit 86587874 --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-reproduced.json
```

使用 `--metadata-only` 只生成 corpus 和 catalog，不执行解压；使用
`--format zip --runs 1` 可做快速 smoke test。脚本会记录原始样本、7z `-slt`
归档属性、分卷大小、压缩率、机器信息和派生中位数。
