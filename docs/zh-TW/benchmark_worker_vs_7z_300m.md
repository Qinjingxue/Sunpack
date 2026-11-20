# 可重現的 worker 與 7-Zip 對比測試

[简体中文](../zh-CN/benchmark_worker_vs_7z_300m.md) | [English](../benchmark_worker_vs_7z_300m.md) | **繁體中文** | [日本語](../ja/benchmark_worker_vs_7z_300m.md) | [한국어](../ko/benchmark_worker_vs_7z_300m.md)

本文是根目錄 README 簡表對應的詳細測試記錄，說明 SunPack 原生 worker
與配套命令列 `7z.exe` 在所有產生格式上的端到端對比方法。

## 軟體和機器

測試軟體識別資訊：

| 元件            | 值                                                                            |
| --------------- | ----------------------------------------------------------------------------- |
| SunPack         | v0.7.9                                                                        |
| 倉程式庫 HEAD       | `b9fdfa6d`                                                                    |
| worker 原始碼     | commit `b9fdfa6d` |
| BZip2 並行寬度  | 最多 4 個 lane：調用執行緒加最多 3 個 worker 執行緒                               |
| worker 二進位   | `.cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe`       |
| 7-Zip CLI       | 7-Zip 26.03 (x64)，`tools/7z.exe`                                             |
| 7-Zip SHA-256   | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`            |
| worker SHA-256  | `03b96534876d1e847abf9f00dd73b120880a39a7959889964943e0bec6b56bc4`            |
| 測試日期 / JSON | 2026-10-03；`benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json` |

測試機器：

| 屬性             | 值                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------- |
| 操作系統         | Windows 11，x64，build 26200                                              |
| 電腦             | MSI Vector GP78HX 13VI                                                                 |
| CPU              | 13th Gen Intel Core i9-13980HX，24 個物理核心 / 32 個邏輯處理器                        |
| 記憶體             | 31.77 GiB                                                                              |
| benchmark 所在盤 | `C:` NTFS，Samsung NVMe MZVL21T0HCLR-00B00，總容量 934.47 GiB，擷取時約剩余 271.36 GiB |

重現腳本也會在 JSON 中記錄機器清單、目前電源計劃、二進位 hash 和
7-Zip 版本。

## corpus 和壓縮檔特征

測試使用 `few_large` corpus，未壓縮 payload 為 314,572,800 bytes（300 MiB），
恰好包含兩個成員：

- 一個確定性的 150 MiB 檔案，內容為重複的 `sunpack-benchmark\n` 文字；
- 一個使用固定種子 `20260729` 產生的確定性 150 MiB 隨機檔案。

輸入因此一半是高度可壓縮資料，一半是不可壓縮資料。沒有加密、載體資料、
巢狀封存檔或缺失分卷。corpus builder 使用 `small_files=8`、`large_files=2`、
`large_file_mib=150`；`few_large` 封存檔只包含兩個大檔案。

| case             | 壓縮方法和構造             | solid / 分卷配置         | 封存檔大小和比例                                           |
| ---------------- | -------------------------- | ------------------------ | -------------------------------------------------------- |
| 7z split         | LZMA2，7-Zip 預設          | 預設 solid 行為，`-v16m` | 10 卷；總計 157,320,673 bytes                            |
| 7z solid         | LZMA2，`-ms=on`            | solid，單卷              | 157,320,673 bytes；占 payload 50.01%；payload/封存檔 2.00x |
| 7z non-solid     | LZMA2，`-ms=off`           | 非 solid，單卷           | 157,319,998 bytes；50.01%；2.00x                         |
| ZIP              | Deflate，7-Zip 預設        | 單個 ZIP                 | 157,703,555 bytes；50.13%；1.99x                         |
| RAR5 split       | RAR5 預設方法              | 預設 solid 行為，`-v16m` | 10 卷；總計 157,594,577 bytes                            |
| RAR5 solid       | RAR5 預設方法，`-s`        | solid，單卷              | 157,592,751 bytes；50.10%；2.00x                         |
| RAR5 non-solid   | RAR5 預設方法，`-s-`       | 非 solid，單卷           | 157,295,918 bytes；50.00%；2.00x                         |
| RAR4 solid       | RAR4 預設方法，`-ma4 -s`   | solid，單卷              | 157,769,630 bytes；50.15%；1.99x                         |
| RAR4 non-solid   | RAR4 預設方法，`-ma4 -s-`  | 非 solid，單卷           | 157,365,992 bytes；50.03%；2.00x                         |
| TAR              | 無壓縮                     | 單個 TAR                 | 314,575,360 bytes；TAR 中繼資料/padding 增加 2,560 bytes   |
| Gzip / TGZ       | TAR 外層 Deflate           | 壓縮流位元組相同           | 157,773,338 bytes；50.15%；1.99x                         |
| BZip2 / TBZ2     | TAR 外層 BZip2             | 壓縮流位元組相同           | 158,006,027 bytes；50.23%；1.99x                         |
| XZ / TXZ         | TAR 外層 LZMA2             | 壓縮流位元組相同           | 157,321,248 bytes；50.01%；2.00x                         |
| Zstandard / TZST | TAR 外層 Zstandard level 3 | 壓縮流位元組相同           | 157,305,941 bytes；50.01%；2.00x                         |

表中的百分比是 `封存檔大小（位元組） / 300 MiB payload`，第二個比例是
`payload bytes / 封存檔大小（位元組）`。分卷封存檔大小為 `archive_catalog.archive_bytes_total`
記錄的所有卷大小之和。

7z、ZIP、TAR 和 TAR codec 樣本由 7-Zip 產生，RAR4/RAR5 由 `Rar.exe` 產生，
Zstandard 由 `zstd.exe -3` 產生。`tgz`、`tbz2`、`txz` 和 `tzst` 是對應
壓縮 TAR 的位元組相同副本。

## 測量方法

- 每個 case 測量 5 次，不使用 warmup；
- 每個 case 使用一個持久 native worker，5 次測量重用同一程序；
- 每次 `7z.exe` 參考測試都啟動新程序，包含程序啟動時間；
- 關閉 worker 診斷欄位和預取；
- 兩種實現使用同一個產生封存檔；
- 表格中的耗時為每個 case 的 wall time 中位數，單位為毫秒；
- 每 20 ms 對 native worker 和 `7z.exe` 的程序樹取樣一次常駐集大小（RSS）。
  每次執行記錄取樣到的峰值，表格展示每個 case 的 5 次峰值中位數，單位為 MiB。
  RSS 只統計 worker/7-Zip 及其子程序，不含 Python benchmark 主程序。短於取樣間隔
  的瞬時峰值可能不會被捕獲。

這是端到端測量，不是純 decoder 微基準：保留產品執行方式，命令列參考也包含程序啟動時間。18 個 worker case 與 18 個 `7z.exe` case 均成功，輸出正確。全矩陣 TBZ2 worker 用時呈雙峰分布（1,560 至 6,405 ms），因此表中 TBZ2 行採用獨立五次配對復測，報告位於 `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-tbz2-confirm-20261003.json`。TAR 中繼資料解釋了輸出比兩個原始成員多出的 2,560 bytes。

## 結果

### 耗時和峰值 RSS（每 case 中位數）

先並列展示 worker 的耗時和 RSS，再展示 `7z.exe` 的對應資料。耗時比和 RSS
比均為 worker 除以 7-Zip；小於 1 表示該項 worker 更低。

| 格式 / 變體        | Worker 耗時（ms） | `7z.exe` 耗時（ms） | 耗時比   | Worker 峰值 RSS（MiB） | `7z.exe` 峰值 RSS（MiB） | RSS 比 |
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

將獨立 TBZ2 復測與其餘 17 個全矩陣 case 合並後，各 case 耗時中位數之和為：
worker 5,714.782 ms，`7z.exe` 10,478.588 ms（0.545x）。這不是一次串行執行。
BZip2/TBZ2 worker 峰值約 43–44 MiB，`7z.exe` 約 12.6 MiB；solid 7z/XZ worker
約 475 MiB，`7z.exe` 約 458 MiB。RSS 是取樣到的每 case 峰值中位數，不跨格式求和。

## 重現

重現歷史結果請使用 `b9fdfa6d` 原始碼及該提交建置的原生擴充和 worker。
[目前基準入口](../../benchmarks/README.md)測量完整的 SunPack CLI 與 7-Zip。

```powershell
git worktree add --detach ..\sunpack-benchmark-b9fdfa6d b9fdfa6d
Set-Location ..\sunpack-benchmark-b9fdfa6d
.\scripts\setup_windows_dev.ps1
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.9 `
  --worker-source-commit b9fdfa6d `
  --worker .cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

該檢出目錄也支援直接執行腳本：

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.9 --worker-source-commit b9fdfa6d `
  --worker .cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

使用 `--metadata-only` 只產生 corpus 和 catalog，不執行解壓縮；使用
`--format zip --runs 1` 可做快速 smoke test。腳本會記錄原始樣本、7z `-slt`
封存檔屬性、分卷大小、壓縮率、機器資訊和耗時/RSS 中位數。RSS 每 20 ms
從子程序取樣，結果 JSON 儲存每次測量的原始峰值。
