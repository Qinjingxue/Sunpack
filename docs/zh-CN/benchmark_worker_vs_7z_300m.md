# 可复现的 worker 与 7-Zip 对比测试

本文是根目录 README 简表对应的详细测试记录，说明 SunPack 原生 worker
与配套命令行 `7z.exe` 在所有生成格式上的端到端对比方法。

## 软件和机器

测试软件身份：

| 组件            | 值                                                                            |
| --------------- | ----------------------------------------------------------------------------- |
| SunPack         | v0.7.9                                                                        |
| 仓库 HEAD       | `b9fdfa6d`                                                                    |
| worker 源码     | commit `b9fdfa6d` |
| BZip2 并行宽度  | 最多 4 个 lane：调用线程加最多 3 个 worker 线程                               |
| worker 二进制   | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe`        |
| 7-Zip CLI       | 7-Zip 26.03 (x64)，`tools/7z.exe`                                             |
| 7-Zip SHA-256   | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`            |
| worker SHA-256  | `03b96534876d1e847abf9f00dd73b120880a39a7959889964943e0bec6b56bc4`            |
| 测试日期 / JSON | 2026-10-03；`benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json` |

测试机器：

| 属性             | 值                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------- |
| 操作系统         | Windows 11，x64，build 26200                                              |
| 电脑             | MSI Vector GP78HX 13VI                                                                 |
| CPU              | 13th Gen Intel Core i9-13980HX，24 个物理核心 / 32 个逻辑处理器                        |
| 内存             | 31.77 GiB                                                                              |
| benchmark 所在盘 | `C:` NTFS，Samsung NVMe MZVL21T0HCLR-00B00，总容量 934.47 GiB，采集时约剩余 271.36 GiB |

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
| 7z split         | LZMA2，7-Zip 默认          | 默认 solid 行为，`-v16m` | 10 卷；总计 157,320,673 bytes                            |
| 7z solid         | LZMA2，`-ms=on`            | solid，单卷              | 157,320,673 bytes；占 payload 50.01%；payload/归档 2.00x |
| 7z non-solid     | LZMA2，`-ms=off`           | 非 solid，单卷           | 157,319,998 bytes；50.01%；2.00x                         |
| ZIP              | Deflate，7-Zip 默认        | 单个 ZIP                 | 157,703,555 bytes；50.13%；1.99x                         |
| RAR5 split       | RAR5 默认方法              | 默认 solid 行为，`-v16m` | 10 卷；总计 157,594,577 bytes                            |
| RAR5 solid       | RAR5 默认方法，`-s`        | solid，单卷              | 157,592,751 bytes；50.10%；2.00x                         |
| RAR5 non-solid   | RAR5 默认方法，`-s-`       | 非 solid，单卷           | 157,295,918 bytes；50.00%；2.00x                         |
| RAR4 solid       | RAR4 默认方法，`-ma4 -s`   | solid，单卷              | 157,769,630 bytes；50.15%；1.99x                         |
| RAR4 non-solid   | RAR4 默认方法，`-ma4 -s-`  | 非 solid，单卷           | 157,365,992 bytes；50.03%；2.00x                         |
| TAR              | 无压缩                     | 单个 TAR                 | 314,575,360 bytes；TAR 元数据/padding 增加 2,560 bytes   |
| Gzip / TGZ       | TAR 外层 Deflate           | 压缩流字节相同           | 157,773,338 bytes；50.15%；1.99x                         |
| BZip2 / TBZ2     | TAR 外层 BZip2             | 压缩流字节相同           | 158,006,027 bytes；50.23%；1.99x                         |
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

这是端到端测量，不是纯 decoder 微基准：保留产品执行方式，命令行参考也包含进程启动时间。18 个 worker case 与 18 个 `7z.exe` case 均成功，输出正确。全矩阵 TBZ2 worker 用时呈双峰分布（1,560 至 6,405 ms），因此表中 TBZ2 行采用独立五次配对复测，报告位于 `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-tbz2-confirm-20261003.json`。TAR 元数据解释了输出比两个原始成员多出的 2,560 bytes。

## 结果

### 耗时和峰值 RSS（每 case 中位数）

先并列展示 worker 的耗时和 RSS，再展示 `7z.exe` 的对应数据。耗时比和 RSS
比均为 worker 除以 7-Zip；小于 1 表示该项 worker 更低。

| 格式 / 变体        | Worker 耗时（ms） | `7z.exe` 耗时（ms） | 耗时比   | Worker 峰值 RSS（MiB） | `7z.exe` 峰值 RSS（MiB） | RSS 比 |
| -------------- | :------------ | :-------------- | :---- | :----------------- | :------------------- | :---- |
| 7z split       | 141.886       | 203.605         | 0.697 | 476.199            | 458.379              | 1.039 |
| 7z non-solid   | 188.029       | 250.020         | 0.752 | 324.137            | 308.047              | 1.052 |
| 7z solid       | 142.802       | 204.641         | 0.698 | 475.652            | 458.309              | 1.038 |
| BZip2          | 1,670.859     | 2,914.191       | 0.573 | 43.289             | 12.625               | 3.429 |
| Gzip           | 81.731        | 209.743         | 0.390 | 25.188             | 8.215                | 3.066 |
| RAR5 split     | 172.453       | 768.066         | 0.225 | 54.242             | 40.516               | 1.339 |
| RAR4 non-solid | 80.926        | 185.464         | 0.436 | 27.488             | 11.598               | 2.370 |
| RAR4 solid     | 539.789       | 652.330         | 0.827 | 28.211             | 12.348               | 2.285 |
| RAR5 non-solid | 95.293        | 186.992         | 0.510 | 56.250             | 39.605               | 1.420 |
| RAR5 solid     | 168.938       | 745.597         | 0.227 | 57.289             | 40.477               | 1.415 |
| TAR            | 76.350        | 120.331         | 0.634 | 24.031             | 7.297                | 3.293 |
| TBZ2           | 1,663.736     | 2,890.008       | 0.576 | 44.141             | 12.625               | 3.496 |
| TGZ            | 84.974        | 213.233         | 0.399 | 25.215             | 8.219                | 3.068 |
| TXZ            | 156.893       | 181.328         | 0.865 | 474.617            | 458.523              | 1.035 |
| TZST           | 100.259       | 188.752         | 0.531 | 23.012             | 9.789                | 2.351 |
| XZ             | 169.011       | 183.459         | 0.921 | 474.621            | 458.520              | 1.035 |
| ZIP            | 76.254        | 198.892         | 0.383 | 25.289             | 7.984                | 3.167 |
| ZST            | 104.599       | 181.936         | 0.575 | 23.039             | 9.789                | 2.354 |

将独立 TBZ2 复测与其余 17 个全矩阵 case 合并后，各 case 耗时中位数之和为：
worker 5,714.782 ms，`7z.exe` 10,478.588 ms（0.545x）。这不是一次串行运行。
BZip2/TBZ2 worker 峰值约 43–44 MiB，`7z.exe` 约 12.6 MiB；solid 7z/XZ worker
约 475 MiB，`7z.exe` 约 458 MiB。RSS 是采样到的每 case 峰值中位数，不跨格式求和。

## 复现

```powershell
uv sync --locked --extra dev
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker --parallel
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.9 `
  --worker-source-commit b9fdfa6d `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

独立脚本入口：

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.9 --worker-source-commit b9fdfa6d `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

使用 `--metadata-only` 只生成 corpus 和 catalog，不执行解压；使用
`--format zip --runs 1` 可做快速 smoke test。脚本会记录原始样本、7z `-slt`
归档属性、分卷大小、压缩率、机器信息和耗时/RSS 中位数。RSS 每 20 ms
从子进程采样，结果 JSON 保存每次测量的原始峰值。
