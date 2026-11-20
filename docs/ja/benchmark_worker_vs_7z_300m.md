# worker と 7-Zip の再現可能な比較

[简体中文](../zh-CN/benchmark_worker_vs_7z_300m.md) | [English](../benchmark_worker_vs_7z_300m.md) | [繁體中文](../zh-TW/benchmark_worker_vs_7z_300m.md) | **日本語** | [한국어](../ko/benchmark_worker_vs_7z_300m.md)

SunPack v0.7.9 のネイティブ worker と同梱ツールの `7z.exe` を、生成したすべての形式でエンドツーエンド比較した記録です。現在の CLI 全体を比較する手順は [現行のベンチマーク](../../benchmarks/README.md) を参照してください。

## ソフトウェアと測定環境

| 項目 | 値 |
| --- | --- |
| SunPack | v0.7.9 |
| リポジトリ HEAD | `b9fdfa6d` |
| worker ソース | コミット `b9fdfa6d` |
| BZip2 の並列度 | 最大 4 レーン（呼び出し元と最大 3 worker スレッド） |
| worker バイナリ | `.cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe` |
| 7-Zip CLI | 7-Zip 26.03 (x64), `tools/7z.exe` |
| 7-Zip SHA-256 | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f` |
| Worker SHA-256 | `03b96534876d1e847abf9f00dd73b120880a39a7959889964943e0bec6b56bc4` |
| 実行日 / JSON | 2026-10-03; `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json` |

| 項目 | 値 |
| --- | --- |
| OS | Windows 11, x64, build 26200 |
| コンピューター | MSI Vector GP78HX 13VI |
| CPU | 13th Gen Intel Core i9-13980HX, 物理 24 コア / 論理 32 プロセッサー |
| メモリ | 31.77 GiB |
| 測定ボリューム | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 合計 934.47 GiB、測定時の空き容量は約 271.36 GiB |

再現スクリプトは測定機の構成、電源プラン、バイナリのハッシュ、7-Zip のバージョンも JSON に記録します。

## 入力コーパス

`few_large` の非圧縮データは 314,572,800 バイト（300 MiB）です。 `sunpack-benchmark\n` を繰り返した 150 MiB と、シード `20260729` で生成したランダムデータ 150 MiB を一つずつ含みます。暗号化、埋め込み用の外側データ、入れ子のアーカイブ、不足巻はありません。生成設定は `small_files=8`、`large_files=2`、`large_file_mib=150` ですが、`few_large` には大きい二つだけが入ります。

| ケース | 圧縮方式 | ソリッド / 分割 | サイズと比率 |
| --- | --- | --- | --- |
| 7z split | LZMA2, 7-Zip 既定値 | 既定のソリッド動作, `-v16m` | 10 巻、 157,320,673 バイト（合計） |
| 7z solid | LZMA2, `-ms=on` | ソリッド、単一巻 | 157,320,673 バイト; 50.01%（元データ比）; 2.00x（元データ / アーカイブ） |
| 7z non-solid | LZMA2, `-ms=off` | 非ソリッド、単一巻 | 157,319,998 バイト; 50.01%; 2.00x |
| ZIP | Deflate, 7-Zip 既定値 | 単一 ZIP | 157,703,555 バイト; 50.13%; 1.99x |
| RAR5 split | RAR5 既定方式 | 既定のソリッド動作, `-v16m` | 10 巻、 157,594,577 バイト（合計） |
| RAR5 solid | RAR5 既定方式, `-s` | ソリッド、単一巻 | 157,592,751 バイト; 50.10%; 2.00x |
| RAR5 non-solid | RAR5 既定方式, `-s-` | 非ソリッド、単一巻 | 157,295,918 バイト; 50.00%; 2.00x |
| RAR4 solid | RAR4 既定方式, `-ma4 -s` | ソリッド、単一巻 | 157,769,630 バイト; 50.15%; 1.99x |
| RAR4 non-solid | RAR4 既定方式, `-ma4 -s-` | 非ソリッド、単一巻 | 157,365,992 バイト; 50.03%; 2.00x |
| TAR | 圧縮なし | 単一 TAR | 314,575,360 バイト; TAR のメタデータとパディングで 2,560 バイト増加 |
| Gzip / TGZ | TAR に Deflate | 圧縮ストリームは同一 | 157,773,338 バイト; 50.15%; 1.99x |
| BZip2 / TBZ2 | TAR に BZip2 | 圧縮ストリームは同一 | 158,006,027 バイト; 50.23%; 1.99x |
| XZ / TXZ | TAR に LZMA2 | 圧縮ストリームは同一 | 157,321,248 バイト; 50.01%; 2.00x |
| Zstandard / TZST | TAR に Zstandard レベル 3 | 圧縮ストリームは同一 | 157,305,941 バイト; 50.01%; 2.00x |

百分率はアーカイブサイズ / 300 MiB、倍率は元データ / アーカイブサイズです。分割アーカイブのサイズは `archive_catalog.archive_bytes_total` の全巻合計を使います。7z・ZIP・TAR と TAR の圧縮ストリームは 7-Zip、RAR4/5 は `Rar.exe`、Zstandard は `zstd.exe -3` で生成しました。 `tgz`、`tbz2`、`txz`、`tzst` は対応する圧縮 TAR とバイト単位で同じです。

## 測定方法

- 各ケースをウォームアップなしで 5 回測定しました。worker は同じプロセスを再利用し、`7z.exe` は毎回新しいプロセスを起動しました。 `7z.exe` の時間には起動時間も含まれます。
- 両実装で同一のアーカイブを使用し、worker の診断とプリフェッチを無効化しました。
- 経過時間は 5 回の中央値です。worker または `7z.exe` とその子プロセスの常駐メモリ（RSS）を 20 ms ごとにサンプリングし、各実行のピークの中央値を表示します。ベンチマークを起動した Python のメモリは含みません。20 ms 未満のピークは見逃す場合があります。
- 両実装とも 18 ケースで正しく出力しました。全形式測定の TBZ2 worker 時間は 1,560–6,405 ms の二峰性を示したため、表には独立した 5 回のペア再測定を使います。記録は `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-tbz2-confirm-20261003.json` にあります。

## 結果

時間比と RSS 比は worker / `7z.exe` で、1 未満なら worker 側の値が小さいことを表します。

| 形式 / 変種 | worker 時間 (ms) | 7z.exe 時間 (ms) | 時間比 | worker ピーク RSS (MiB) | 7z.exe ピーク RSS (MiB) | RSS 比 |
| --- | --- | --- | --- | --- | --- | --- |
| 7z split | 141.886 | 203.605 | 0.697 | 476.199 | 458.379 | 1.039 |
| 7z non-solid | 188.029 | 250.020 | 0.752 | 324.137 | 308.047 | 1.052 |
| 7z solid | 142.802 | 204.641 | 0.698 | 475.652 | 458.309 | 1.038 |
| BZip2 | 1,670.859 | 2,914.191 | 0.573 | 43.289 | 12.625 | 3.429 |
| Gzip | 81.731 | 209.743 | 0.390 | 25.188 | 8.215 | 3.066 |
| RAR5 split | 172.453 | 768.066 | 0.225 | 54.242 | 40.516 | 1.339 |
| RAR4 non-solid | 80.926 | 185.464 | 0.436 | 27.488 | 11.598 | 2.370 |
| RAR4 solid | 539.789 | 652.330 | 0.827 | 28.211 | 12.348 | 2.285 |
| RAR5 non-solid | 95.293 | 186.992 | 0.510 | 56.250 | 39.605 | 1.420 |
| RAR5 solid | 168.938 | 745.597 | 0.227 | 57.289 | 40.477 | 1.415 |
| TAR | 76.350 | 120.331 | 0.634 | 24.031 | 7.297 | 3.293 |
| TBZ2 | 1,663.736 | 2,890.008 | 0.576 | 44.141 | 12.625 | 3.496 |
| TGZ | 84.974 | 213.233 | 0.399 | 25.215 | 8.219 | 3.068 |
| TXZ | 156.893 | 181.328 | 0.865 | 474.617 | 458.523 | 1.035 |
| TZST | 100.259 | 188.752 | 0.531 | 23.012 | 9.789 | 2.351 |
| XZ | 169.011 | 183.459 | 0.921 | 474.621 | 458.520 | 1.035 |
| ZIP | 76.254 | 198.892 | 0.383 | 25.289 | 7.984 | 3.167 |
| ZST | 104.599 | 181.936 | 0.575 | 23.039 | 9.789 | 2.354 |

TBZ2 の再測定と残り 17 ケースを使った時間中央値の合計は worker が 5,714.782 ms、`7z.exe` が 10,478.588 ms（0.545 倍）です。各ケースの合計値です。BZip2/TBZ2 の RSS は worker が約 43–44 MiB、`7z.exe` が約 12.6 MiB、ソリッド 7z/XZ は約 475 MiB 対 458 MiB でした。形式間で RSS を合計しません。

## 再現手順

履歴結果を再現するには `b9fdfa6d` とそのコミットでビルドしたネイティブコンポーネントを使います。

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

このチェックアウトでは直接スクリプトを実行することもできます。

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.9 --worker-source-commit b9fdfa6d `
  --worker .cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

`--metadata-only` はコーパスとカタログのみを生成し、`--format zip --runs 1` は短い動作確認に使えます。JSON にはアーカイブ属性、分割サイズ、圧縮比、測定環境、時間と RSS の中央値、および各実行の生のピークを記録します。
