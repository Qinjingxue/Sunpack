# worker와 7-Zip의 재현 가능한 비교

[简体中文](../zh-CN/benchmark_worker_vs_7z_300m.md) | [English](../benchmark_worker_vs_7z_300m.md) | [繁體中文](../zh-TW/benchmark_worker_vs_7z_300m.md) | [日本語](../ja/benchmark_worker_vs_7z_300m.md) | **한국어**

SunPack v0.7.9의 네이티브 worker와 함께 제공되는 `7z.exe`를 생성된 모든 형식에서 종단 간으로 비교한 기록입니다. 현재 CLI 전체를 비교하는 절차는 [현재 벤치마크](../../benchmarks/README.md)를 참고하세요.

## 소프트웨어와 측정 환경

| 구성 요소 | 값 |
| --- | --- |
| SunPack | v0.7.9 |
| 저장소 HEAD | `b9fdfa6d` |
| worker 소스 | 커밋 `b9fdfa6d` |
| BZip2 병렬도 | 최대 4개 lane(호출 스레드와 worker 스레드 최대 3개) |
| worker 바이너리 | `.cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe` |
| 7-Zip CLI | 7-Zip 26.03 (x64), `tools/7z.exe` |
| 7-Zip SHA-256 | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f` |
| Worker SHA-256 | `03b96534876d1e847abf9f00dd73b120880a39a7959889964943e0bec6b56bc4` |
| 실행 날짜 / JSON | 2026-10-03; `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json` |

| 속성 | 값 |
| --- | --- |
| OS | Windows 11, x64, build 26200 |
| 컴퓨터 | MSI Vector GP78HX 13VI |
| CPU | 13th Gen Intel Core i9-13980HX, 물리 코어 24개 / 논리 프로세서 32개 |
| 메모리 | 31.77 GiB |
| 측정 볼륨 | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 전체 934.47 GiB, 측정 시 여유 공간 약 271.36 GiB |

재현 스크립트는 컴퓨터 구성, 현재 전원 계획, 바이너리 해시, 7-Zip 버전도 JSON에 기록합니다.

## 입력 데이터 세트

`few_large`의 압축 전 데이터는 314,572,800바이트(300 MiB)입니다. `sunpack-benchmark\n`을 반복한 150 MiB 파일과 시드 `20260729`로 생성한 의사 난수 150 MiB 파일이 하나씩 있습니다. 암호화, 내장용 외부 데이터, 중첩 압축 파일, 누락된 분할 볼륨은 없습니다. 생성 설정은 `small_files=8`, `large_files=2`, `large_file_mib=150`이며, `few_large`에는 큰 파일 두 개만 들어갑니다.

| 사례 | 압축 방식 | 솔리드 / 분할 | 크기와 비율 |
| --- | --- | --- | --- |
| 7z split | LZMA2, 7-Zip 기본값 | 기본 솔리드 동작, `-v16m` | 볼륨 10개,  157,320,673바이트(합계) |
| 7z solid | LZMA2, `-ms=on` | 솔리드, 단일 볼륨 | 157,320,673바이트; 50.01%(원본 데이터 대비); 2.00x(원본 데이터 / 압축 파일) |
| 7z non-solid | LZMA2, `-ms=off` | 비솔리드, 단일 볼륨 | 157,319,998바이트; 50.01%; 2.00x |
| ZIP | Deflate, 7-Zip 기본값 | 단일 ZIP | 157,703,555바이트; 50.13%; 1.99x |
| RAR5 split | RAR5 기본 방식 | 기본 솔리드 동작, `-v16m` | 볼륨 10개,  157,594,577바이트(합계) |
| RAR5 solid | RAR5 기본 방식, `-s` | 솔리드, 단일 볼륨 | 157,592,751바이트; 50.10%; 2.00x |
| RAR5 non-solid | RAR5 기본 방식, `-s-` | 비솔리드, 단일 볼륨 | 157,295,918바이트; 50.00%; 2.00x |
| RAR4 solid | RAR4 기본 방식, `-ma4 -s` | 솔리드, 단일 볼륨 | 157,769,630바이트; 50.15%; 1.99x |
| RAR4 non-solid | RAR4 기본 방식, `-ma4 -s-` | 비솔리드, 단일 볼륨 | 157,365,992바이트; 50.03%; 2.00x |
| TAR | 압축 없음 | 단일 TAR | 314,575,360바이트; TAR 메타데이터와 패딩에 2,560바이트 추가 |
| Gzip / TGZ | TAR에 Deflate 적용 | 압축 스트림의 바이트가 동일 | 157,773,338바이트; 50.15%; 1.99x |
| BZip2 / TBZ2 | TAR에 BZip2 적용 | 압축 스트림의 바이트가 동일 | 158,006,027바이트; 50.23%; 1.99x |
| XZ / TXZ | TAR에 LZMA2 적용 | 압축 스트림의 바이트가 동일 | 157,321,248바이트; 50.01%; 2.00x |
| Zstandard / TZST | TAR에 Zstandard 레벨 3 적용 | 압축 스트림의 바이트가 동일 | 157,305,941바이트; 50.01%; 2.00x |

백분율은 압축 파일 크기 / 300 MiB, 배율은 원본 데이터 / 압축 파일 크기입니다. 분할 파일 크기는 `archive_catalog.archive_bytes_total`의 모든 볼륨 합계입니다. 7z·ZIP·TAR와 압축된 TAR 스트림은 7-Zip으로, RAR4/5는 `Rar.exe`로, Zstandard는 `zstd.exe -3`으로 생성했습니다. `tgz`, `tbz2`, `txz`, `tzst`의 바이트는 해당 압축 TAR와 동일합니다.

## 측정 방법

- 워밍업 없이 각 사례를 5회 측정했습니다. worker는 하나의 프로세스를 재사용했고 `7z.exe`는 매번 새 프로세스를 실행했습니다. `7z.exe`의 시간에는 시작 시간이 포함됩니다.
- 두 구현은 동일한 압축 파일을 사용했습니다. worker의 진단과 미리 읽기는 끈 상태입니다.
- 경과 시간은 5회 측정값의 중앙값입니다. worker 또는 `7z.exe`와 하위 프로세스의 상주 메모리(RSS)를 20 ms마다 샘플링하고, 실행별 최대치의 중앙값을 표시합니다. 벤치마크를 실행한 Python 프로세스는 포함하지 않습니다. 20 ms보다 짧은 순간 최대치는 샘플링에서 빠질 수 있습니다.
- 두 구현 모두 18개 사례에서 올바른 결과를 냈습니다. 전체 행렬의 TBZ2 worker 시간에는 두 개의 피크가 나타났으므로(1,560–6,405 ms), 표에는 별도의 5회 쌍 비교를 사용했습니다. 기록은 `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-tbz2-confirm-20261003.json`에 있습니다.

## 결과

시간과 RSS 비율은 worker / `7z.exe`이며 1보다 작으면 worker의 값이 더 낮습니다.

| 형식 / 변형 | worker 시간(ms) | 7z.exe 시간(ms) | 시간 비율 | worker 최대 RSS(MiB) | 7z.exe 최대 RSS(MiB) | RSS 비율 |
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

별도의 TBZ2 재측정과 나머지 17개 사례에서 측정 시간 중앙값을 합하면 worker 5,714.782 ms, `7z.exe` 10,478.588 ms(0.545배)입니다. 이 값은 사례별 중앙값의 합입니다. BZip2/TBZ2 RSS는 worker 약 43–44 MiB, `7z.exe` 약 12.6 MiB였으며 솔리드 7z/XZ는 약 475 MiB와 458 MiB였습니다. RSS는 형식 간에 합산하지 않습니다.

## 재현

기록된 결과를 재현하려면 `b9fdfa6d` 소스와 해당 커밋에서 빌드한 네이티브 구성 요소를 사용하세요.

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

이 체크아웃에서는 스크립트를 직접 실행할 수도 있습니다.

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.9 --worker-source-commit b9fdfa6d `
  --worker .cache/native/x64/release/sevenzip_bridge/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

`--metadata-only`는 입력 데이터 세트와 카탈로그만 생성합니다. `--format zip --runs 1`은 빠른 동작 확인에 사용할 수 있습니다. JSON에는 압축 파일 속성, 볼륨 크기, 압축률, 컴퓨터 구성, 시간과 RSS의 중앙값 및 각 실행의 원시 최대치가 기록됩니다.
