<p align="center"><img src="sunpack.png" width="96" alt="SunPack"></p>
<h1 align="center">SunPack</h1>
<p align="center"><b>Windows용 자동 압축 해제 도구입니다. 폴더를 감시하고 백그라운드에서 압축 파일을 자동으로 풉니다.</b></p>

<p align="center"><a href="README.zh-CN.md">简体中文</a> · <a href="README.md">English</a> · <a href="README.zh-TW.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <b>한국어</b> · <a href="https://github.com/Qinjingxue/Sunpack/releases/latest">다운로드</a></p>

<p align="center">
  <a href="https://github.com/Qinjingxue/Sunpack/releases/latest"><img src="https://img.shields.io/github/v/release/Qinjingxue/Sunpack?label=Latest%20release" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20only-2f6070" alt="Windows only">
  <a href="docs/licensing.md"><img src="https://img.shields.io/badge/license-MIT%20%2B%20third--party-blue" alt="라이선스"></a>
</p>

<p align="center"><img src="sunpack_en.gif" width="80%" alt="SunPack 데모(영어 UI)"></p>

## 목차

- [설치](#설치)
- [사용법](#사용법)
  - [관리 화면과 암호](#관리-화면과-암호)
- [주요 기능](#주요-기능)
  - [압축 파일 식별](#압축-파일-식별)
  - [재귀 처리](#재귀-처리)
  - [후처리](#후처리)
  - [Watch 감시](#watch-감시)
  - [안정성과 WAL 복구](#안정성과-wal-복구)
  - [동시 처리와 속도 최적화](#동시-처리와-속도-최적화)
  - [유휴 상태의 자원 사용](#유휴-상태의-자원-사용)
- [설정](#설정)
- [개발 및 테스트](#개발-및-테스트)
  - [아키텍처 개요](#아키텍처-개요)
  - [재현 가능한 worker와 7-Zip 비교](#재현-가능한-worker와-7-zip-비교)
- [알려진 문제](#알려진-문제)
- [기여](#기여)
- [감사의 말](#감사의-말)
- [라이선스](#라이선스)
- [연락처](#연락처)

## 설치

SunPack은 Windows 10 버전 1709 이상과 Windows 11을 지원합니다. Watch에서 감시하는 폴더는 NTFS 또는 ReFS에 있어야 합니다.

1. [GitHub Releases](https://github.com/Qinjingxue/Sunpack/releases/latest)에서 `sunpack-windows-<arch>-<version>-setup.exe`를 받습니다. Intel/AMD 64비트 Windows에서는 `x64`, Windows on ARM에서는 `arm64`를 선택합니다.
2. 설치 프로그램을 실행하고 UAC 요청을 승인합니다. 기본 설치 경로는 `C:\Program Files\SunPack`입니다. Watch Broker 서비스를 설치하려면 관리자 권한이 필요합니다.
3. 필요한 경우 시스템 `PATH`에 추가하거나 탐색기의 마우스 오른쪽 버튼 메뉴와 Windows 로그인 시 Watch 시작을 설정합니다. PATH에 추가했다면 PowerShell을 다시 엽니다.

WinGet으로 설치하려면 다음 명령을 실행합니다.

```powershell
winget install sunpack
```

## 사용법

| 명령 | 별칭 | 기능 |
| --- | --- | --- |
| `extract` | `e` | 압축을 풉니다. |
| `watch` | `w` | 폴더를 감시하고 쓰기가 끝난 파일을 자동으로 처리합니다. |
| `scan` | `s` | 압축 파일을 찾고 압축을 풀지 않은 상태로 암호를 확인합니다. |
| `passwords` | `pw` | 암호 후보의 출처를 표시합니다. |
| `config` | `cfg` | 유효한 설정을 표시하거나 검사합니다. |
| `daemon` | `d` | 백그라운드 프로세스와 로그인 시 시작을 관리합니다. |
| `doctor` | `doc` | 설치 상태와 실행 환경을 읽기 전용으로 검사합니다. |
| `version` | `ver` | 설치된 버전을 표시합니다. |

```powershell
sunpack extract D:\Downloads -o E:\Output -c k
sunpack watch add D:\Downloads -o E:\Output -R
sunpack daemon start
```

인수, 종료 코드 및 JSON 출력은 [CLI 옵션 설명](docs/ko/cli_parameters.md)을 참고하세요. 확장자가 위장된 파일 대부분은 일반 모드에서 찾을 수 있습니다. 일반 모드에서 찾지 못한 파일을 확인할 때 심층 검사(`-d`)를 사용하세요. 항상 켜 두면 의도하지 않은 내장 데이터도 추출될 수 있습니다.

### 관리 화면과 암호

시작 메뉴의 SunPack GUI 또는 Watch 알림 영역 아이콘에서 관리 화면을 엽니다. 이 화면에서 작업 내역, 감시 폴더, 암호 및 설정을 관리합니다. GUI는 네이티브 C++로 구현되어 있으며 창을 닫으면 종료됩니다.

설정 화면에서 한국어를 선택할 수 있습니다. `sunpack_config.json`을 직접 편집할 때는 `cli.language`를 `ko`로 설정합니다.

설치 버전의 암호 파일은 `%ProgramData%\SunPack\builtin_passwords.json`입니다. 암호 관리 화면에서 폴더별 암호를 편집하거나 클립보드 기록을 암호 후보로 저장할 수 있습니다. JSON의 `value`에는 암호를, `enabled`에는 사용 여부를 지정합니다. 선택 항목인 `scopes`에는 절대 경로를 지정하며, 생략하면 모든 폴더에 적용됩니다. Watch는 별도의 `clipboard_history`에 기본적으로 최근 30개 항목을 보관합니다.

CLI의 `-p`, `-P`, 대화형 입력 및 현재 클립보드도 후보가 될 수 있습니다. 최근 성공한 암호는 유효한 후보의 순서를 조정하는 데만 사용됩니다. 암호 후보와 분할 볼륨을 확인하는 동안 진행률이 0%에 머물 수 있습니다. 진행 알림에서 작업을 취소할 수 있습니다.

![SunPack 설정 화면(영어 UI)](docs/images/gui.en.png)

## 주요 기능

### 압축 파일 식별

바이너리 데이터를 분석하여 확장자가 위장된 파일, 다른 파일에 내장된 압축 파일 및 분할 압축 파일을 식별합니다. ZIP, ZIPX, RAR3/4/5, 7z, Zstandard, Gzip, TAR, TBZ2, XZ, LZ4, ENC v4를 지원합니다. WinZip 전용 ZIPX JPEG·MP3·WavPack 방식과 레거시 또는 사전 사용 LZ4는 지원하지 않습니다.

### 재귀 처리

압축 해제 후 결과 폴더에서 추가로 풀어야 할 압축 파일을 기본적으로 재귀 검색하고 처리합니다. 불필요한 재압축 해제를 피하도록 판별합니다.

### 후처리

성공 후 의미 없는 단일 하위 디렉터리의 중첩을 평탄화하고 최상위 폴더를 유지합니다. 원본 압축 파일은 기본적으로 휴지통으로 이동하며 설정에 따라 삭제하거나 유지할 수 있습니다. 실패 시 출력물을 정리하고 오류를 보고합니다. BitTorrent 시딩 등으로 원본이 필요하면 `post_extract.archive_cleanup_mode`를 `k`로 변경하세요.

### Watch 감시

감시 폴더에 추가된 압축 파일을 식별하고 다른 파일은 처리하지 않습니다. 볼륨이나 암호가 부족하면 볼륨 또는 암호 후보가 변경된 후 다시 시도합니다. Windows 알림으로 진행률을 표시하며 감시 폴더마다 출력 경로를 설정할 수 있습니다. 자세한 내용은 [CLI 옵션 설명](docs/ko/cli_parameters.md)을 참고하세요.

### 안정성과 WAL 복구

디스크 공간이 부족하면 일시 중지하고 공간이 확보되면 재개합니다. worker가 완료한 파일을 이용한 선택적 부분 복구를 지원하며, 전체·부분 결과와 원본 정리는 공통 정책을 따릅니다. WAL을 사용해 충돌이나 정전 후 복구하며 복잡한 형식, 동시 처리 및 복구를 테스트합니다.

### 동시 처리와 속도 최적화

여러 압축 파일을 동시에 처리하고 Rust와 C++의 계산·I/O 및 중첩 I/O를 활용합니다. 7-Zip의 Deflate 압축 해제에는 zlib-ng를 사용하고 RAR 및 BZip2 디코딩도 병렬화합니다. 다양한 시나리오의 벤치마크를 바탕으로 최적화합니다.

### 유휴 상태의 자원 사용

처리 후 불필요한 캐시를 해제합니다. 유휴 상태에서는 이벤트 알림으로 대기하여 폴링에 CPU를 사용하지 않습니다.

## 설정

설치 버전에서는 보통 `%ProgramData%\SunPack\sunpack_config.json`을 편집합니다. `sunpack_advanced_config.json`은 나머지 기본값을 제공합니다. 두 파일에 같은 설정이 있으면 일반 설정이 우선하며 설정 항목을 두 파일 사이에서 자유롭게 옮길 수 있습니다. Watch는 변경 사항을 자동으로 다시 읽습니다.

```powershell
sunpack config validate
sunpack config show
```

언어, 검색 필터, 재귀 압축 해제, 중복 제거, 업그레이드 시 설정 이전은 [설정 가이드](docs/ko/configuration.md)를 참고하세요.

## 개발 및 테스트

Windows 10/11 x64 또는 Windows 11 ARM64, PowerShell 5.1 이상, Git for Windows, uv 0.12 이상, rustup 및 Rust MSVC 도구 체인이 필요합니다. Visual Studio 2022 또는 Build Tools 2022에서 C++ 데스크톱 개발 워크로드, MSVC, Windows SDK를 설치합니다. ARM64 빌드에는 해당 MSVC 도구와 Windows용 C++ Clang 도구도 필요합니다. 설치 패키지를 만들려면 Inno Setup 6을 설치합니다.

```powershell
.\scripts\setup_windows_dev.ps1
uv sync --locked --extra test
uv run --locked pytest
.\run_acceptance_tests.ps1
.\scripts\build_windows.ps1
```

ARM64 네이티브 개발과 인수 테스트에는 `-Arch arm64`를, x64에서의 ARM64 교차 빌드에는 `-Arch arm64 -SkipAcceptanceTestTools`를 사용합니다.

Rust가 검색, 형식 분석, 암호 및 볼륨 확인, 처리 계획을 담당하고 7-Zip 소스를 내장한 C++ worker가 압축을 풉니다. [개발 환경과 빌드](docs/ko/development_setup.md), [개발 계층의 책임 범위](docs/ko/development_boundaries.md), [worker와 7-Zip의 재현 가능한 비교](docs/ko/benchmark_worker_vs_7z_300m.md)를 참고하세요. 저장소를 수정할 때는 [AGENTS.md](AGENTS.md)의 개발 규칙을 따르세요. AI를 사용하는 개발자는 변경 전에 AI가 AGENTS.md를 읽고 해당 규칙을 따르도록 해야 합니다. 최초 설정 시 Python, Cargo 의존성과 테스트 도구를 받으려면 네트워크 연결이 필요합니다.

### 아키텍처 개요

```text
CLI / Watch / Explorer (runtime)
  -> pipeline coordinator
     -> filesystem routing
        +-- Relations (RAR / 7z / ZIP, 분할 볼륨 포함)
        +-- Detection (TAR 및 압축 스트림)
        +-- Embedded discovery (미해결 파일)
     -> 재귀 처리 판정 -> 암호 처리 -> 압축 해제
     -> 완료 -> 후처리
```

### 재현 가능한 worker와 7-Zip 비교

[벤치마크 문서](docs/ko/benchmark_worker_vs_7z_300m.md)에 환경, 압축 파일 생성 방법, 압축 방식과 재현 절차가 있습니다.

아래 결과는 SunPack **v0.7.9**, 커밋 `b9fdfa6d` 기준입니다. 2026-10-03에 18개 사례를 워밍업 없이 각각 5회 측정했으며 시간과 프로세스 트리의 최대 RSS 중앙값을 표시합니다. 원본 데이터는 `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json`입니다. 시간 및 RSS 비율은 worker / `7z.exe`입니다.

| Format / variant | Worker time (ms) | `7z.exe` time (ms) | Time ratio | Worker peak RSS (MiB) | `7z.exe` peak RSS (MiB) | RSS ratio |
| ---------------- | :--------------- | :----------------- | :--------- | :-------------------- | :---------------------- | :-------- |
| 7z split         | 141.886          | 203.605            | 0.697      | 476.199               | 458.379                 | 1.039     |
| 7z non-solid     | 188.029          | 250.020            | 0.752      | 324.137               | 308.047                 | 1.052     |
| 7z solid         | 142.802          | 204.641            | 0.698      | 475.652               | 458.309                 | 1.038     |
| BZip2            | 1,670.859        | 2,914.191          | 0.573      | 43.289                | 12.625                  | 3.429     |
| Gzip             | 81.731           | 209.743            | 0.390      | 25.188                | 8.215                   | 3.066     |
| RAR5 split       | 172.453          | 768.066            | 0.225      | 54.242                | 40.516                  | 1.339     |
| RAR4 non-solid   | 80.926           | 185.464            | 0.436      | 27.488                | 11.598                  | 2.370     |
| RAR4 solid       | 539.789          | 652.330            | 0.827      | 28.211                | 12.348                  | 2.285     |
| RAR5 non-solid   | 95.293           | 186.992            | 0.510      | 56.250                | 39.605                  | 1.420     |
| RAR5 solid       | 168.938          | 745.597            | 0.227      | 57.289                | 40.477                  | 1.415     |
| TAR              | 76.350           | 120.331            | 0.634      | 24.031                | 7.297                   | 3.293     |
| TBZ2             | 1,663.736        | 2,890.008          | 0.576      | 44.141                | 12.625                  | 3.496     |
| TGZ              | 84.974           | 213.233            | 0.399      | 25.215                | 8.219                   | 3.068     |
| TXZ              | 156.893          | 181.328            | 0.865      | 474.617               | 458.523                 | 1.035     |
| TZST             | 100.259          | 188.752            | 0.531      | 23.012                | 9.789                   | 2.351     |
| XZ               | 169.011          | 183.459            | 0.921      | 474.621               | 458.520                 | 1.035     |
| ZIP              | 76.254           | 198.892            | 0.383      | 25.289                | 7.984                   | 3.167     |
| ZST              | 104.599          | 181.936            | 0.575      | 23.039                | 9.789                   | 2.354     |

## 알려진 문제

형식에 따라 암호 후보별 검사 비용이 높아 후보가 많으면 진행률이 오랫동안 0%에 머물 수 있습니다. 이 경우 작업을 중단하고 후보를 줄이세요.

## 기여

문제 보고와 제안은 [GitHub Issues](https://github.com/Qinjingxue/Sunpack/issues)에, 코드 변경은 [Pull Request](https://github.com/Qinjingxue/Sunpack/pulls)에 올려 주세요. 필요한 경우 다음 로그를 첨부할 수 있습니다.

- Watch 이벤트: `%ProgramData%\SunPack\.sunpack_watch\events.json` 및 `events.json.store`
- 압축 해제 실패 보고서: `%ProgramData%\SunPack\.sunpack_watch\failures\failed-*.txt`
- 백그라운드 런타임: `%ProgramData%\SunPack\runtime-*.state.events.json` 및 대응하는 `.store`

내역 매니페스트와 이에 대응하는 `.store`를 함께 첨부하세요. 공유하기 전에 암호와 개인 경로를 제거하세요.

## 감사의 말

모든 기여자와 사용자, [Core UI](https://github.com/ghboke/core-ui), [7-Zip](https://www.7-zip.org/), [zlib-ng](https://github.com/zlib-ng/zlib-ng), [LZ4](https://github.com/lz4/lz4), [RustCrypto](https://github.com/RustCrypto) 개발자에게 감사드립니다.

## 라이선스

Worker의 애플리케이션 코드를 포함해 SunPack이 독자적으로 작성한 코드는 [MIT 라이선스](LICENSE)를 따릅니다. Worker는 수정된 7-Zip을, Runtime은 7-Zip의 Deflate64 디코더를 내장합니다. 해당 7-Zip 코드와 그 사용에는 GNU LGPL 2.1 이상이 적용됩니다. 7-Zip, zlib-ng, LZ4, RustCrypto에서 가져온 구현 등 타사 코드와 바이너리에는 각각의 원래 라이선스가 적용됩니다. 구성 요소, 저작권 및 배포에 필요한 자료는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [licenses/](licenses/), [라이선스와 배포](docs/ko/licensing.md)를 참고하세요. 7-Zip 소스 라이선스는 [7zip-source-license.txt](licenses/7zip-source-license.txt), LGPL 2.1 전문은 [LGPL-2.1.txt](licenses/LGPL-2.1.txt)에 있습니다.

입력 프리페치 최적화는 단일 및 동시 작업 모두에서 효과가 유지되지 않아 채택하지 않았습니다.

## 연락처

작성자 이메일: [2940293874wang@gmail.com](mailto:2940293874wang@gmail.com)
