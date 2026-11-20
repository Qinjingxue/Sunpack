# 개발 환경과 빌드

[简体中文](../zh-CN/development_setup.md) | [English](../development_setup.md) | [繁體中文](../zh-TW/development_setup.md) | [日本語](../ja/development_setup.md) | **한국어**

SunPack은 Windows 전용입니다. Cargo는 Rust 런타임과 Watch Broker를 빌드하고, CMake는 네이티브 worker, 실행기, GUI 및 알림 DLL을 빌드합니다. Python 테스트 의존성은 `uv.lock`으로 고정합니다. 필요한 도구는 [README의 개발 및 테스트](../../README.ko.md#개발-및-테스트)를 참고하세요.

## 디렉터리와 빌드 결과물

| 경로 | 용도 |
| --- | --- |
| `sunpack/sunpack_runtime/` | Rust 처리·연산 코어, CLI 및 Watch |
| `sunpack/sunpack_usn_core/` | NTFS/ReFS USN 공용 Rust 코어 |
| `sunpack/sunpack_watch_broker/` | Windows Watch Broker 서비스 |
| `sunpack/sevenzip_bridge/` | CLI 실행기와 7-Zip을 내장한 worker |
| `sunpack/toast_host/` | Windows 알림 DLL |
| `tools/`, `tools/arm64/` | 공용 압축 도구, ARM64용 7-Zip 테스트 도구 |
| `.cache/rust-target/` | 공용 Cargo 빌드 디렉터리 |
| `.cache/native/<arch>/<profile>/<component>/` | CMake 네이티브 빌드 결과물 |
| `.cache/gui-x64/` | x64 GUI CMake 빌드 디렉터리 |

개발, 릴리스, CI는 이 디렉터리를 공유합니다. Cargo 결과물은 대상과 프로필별로 저장합니다. 진단용 `ci`와 LTO가 활성화된 `release`는 서로 다른 곳에 생성합니다. 실행기와 테스트는 선택한 결과물을 직접 사용합니다.

## Python 의존성

`test`에는 pytest와 테스트 데이터 생성 도구가, `build`에는 CMake가 포함됩니다. `dev`는 두 그룹을 모두 포함합니다.

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

처음 `.venv`를 만들 때 uv는 x64 호스트에서 Python 3.11, ARM64 호스트에서 3.12를 고릅니다. 필요하면 인터프리터를 다운로드합니다. 기존 `.venv`는 인터프리터를 유지하고 고정된 의존성을 동기화합니다. 전역 site-packages가 활성화되어 있으면 끕니다.

## 개발 환경 준비

```powershell
.\scripts\setup_windows_dev.ps1
```

1. 선택한 아키텍처의 Rust MSVC 대상을 준비하고 `uv sync --locked --extra dev`로 `.venv`를 동기화합니다.
2. 인수 테스트용 압축 파일 생성 도구를 준비하고 검사합니다.
3. 런타임, Watch Broker, 테스트 데이터 생성기, CLI 실행기, worker 및 알림 DLL을 빌드하여 `.cache`에 저장합니다.
4. `ci` 프로필을 사용하고 빌드 아키텍처가 PowerShell 프로세스와 같으면 worker 및 Toast CTest를 실행합니다.

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
.\scripts\setup_windows_dev.ps1 -Arch arm64 -SkipAcceptanceTestTools
```

x64와 ARM64에 맞는 7-Zip 테스트 도구를 준비합니다. 처음에는 26.04의 `7z.exe`, `7z.dll`, `7zCon.sfx`를 받습니다. 전체 인수 테스트에는 `tools/`의 공용 WinRAR 6.22, zstd 1.5.7 및 [7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4)도 필요합니다. WinRAR는 생성기 두 개와 RAR SFX 모듈 및 라이선스를, 7-Zip-Zstandard는 LZ4 생성기와 DLL 및 라이선스를 사용합니다. 이 도구는 개발과 테스트용입니다.

Windows 11 ARM64에서는 `.\run_acceptance_tests.ps1 -Arch arm64 -NoWait`를 실행합니다. 공용 x64 도구는 Windows 에뮬레이션을 통해 실행합니다. 빌드만 하거나 x64에서 ARM64용으로 교차 빌드할 때는 `-SkipAcceptanceTestTools`로 공용 생성기 준비와 검사를 건너뜁니다.

## USN Watch Broker

Watch는 NTFS/ReFS USN 저널을 사용해 내용 변경과 쓰기 경계를 판단합니다. 볼륨 단위 작업은 공용 Rust 코어와 Watch Broker 서비스가 담당합니다. Watch는 Rust의 파일 관찰 결과와 상태를 사용합니다.

### 서비스와 연결 수명

Watch는 프로세스별 리스를 관리합니다. 첫 리스가 필요할 때 서비스를 시작하고 로컬 명명된 파이프에 연결합니다. 그다음 리스는 연결을 공유하고 마지막 리스를 놓으면 연결을 닫습니다. 첫 클라이언트가 5초 안에 연결되지 않거나 마지막 리스 해제 후 1초가 지나면 서비스가 종료됩니다. 클라이언트와 볼륨 컨텍스트는 각각 최대 64개입니다.

```text
Service: SunPackWatchBroker
Pipe:    \\.\pipe\SunPack.WatchBroker.v1
```

서비스는 로컬 명명된 파이프 클라이언트만 받습니다. 서비스 설치에는 관리자 권한이 필요하며, 설치된 서비스는 일반 사용자 Watch에서 이용할 수 있습니다.

### USN 읽기 범위

Rust에서 메타데이터와 현재 USN을 읽습니다. 현재 값이 이전 값보다 크면 Broker에 다음 범위의 읽기를 요청합니다.

```text
previous_usn < usn <= current_usn
```

관찰 한 번에 읽는 Reason 데이터는 최대 1 MiB입니다. USN 레코드 V2·V3·V4를 처리하며, 전체 Reason과 `CLOSE`를 제외한 Reason을 구분합니다. 덮어쓰기, 확장 및 잘라내기는 내용 변경으로 간주합니다. 메타데이터 변경만으로는 내용 쓰기로 보지 않습니다.

Watch 시작 전에 입력이 NTFS/ReFS에 있고 USN 저널을 읽을 수 있는지 확인합니다. `ERROR_JOURNAL_NOT_ACTIVE`일 때만 기존 32 MiB / 8 MiB 설정으로 저널을 생성하고 다시 조회합니다. 저널 생성·읽기, 볼륨 식별 또는 Broker 연결 실패 시 시작을 중단하고 원인을 표시합니다.

[READ_USN_JOURNAL_DATA_V1 문서](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1)에 따라 볼륨 읽기와 단일 파일 조회에는 V2–V3를 요청합니다. V3 파일과 상위 폴더 ID는 128비트를 모두 보존하고 V2에는 0을 채웁니다. 폴더 복구는 커서 0부터 시작할 수 있으며 저널 ID와 보존 범위를 검사합니다. [ReFS 식별자 요구 사항](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)에 따라 FileIdInfo, 폴더 식별 및 카탈로그에는 전체 ID를 사용합니다. 파일 이름이 없는 V4 범위 레코드는 요청하지 않습니다.

ReFS 회귀 테스트는 상위 64비트가 0이 아닌 파일·상위 폴더 ID가 포함된 V3 레코드를 모의합니다. 기존 저널 생성, 버전 요청, 커서 0, 페이지 단위 복구 테스트를 재사용합니다. 실제 ReFS 볼륨은 로컬 검증에 쓸 수 있으며 CI의 필수 조건은 아닙니다.

### Broker 개별 빌드

```powershell
cargo build --locked --manifest-path sunpack\sunpack_watch_broker\Cargo.toml --release `
  --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\watch-broker
```

ARM64 대상은 `aarch64-pc-windows-msvc`입니다. x64 결과물 경로는 다음과 같습니다.

```text
.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
```

테스트 서비스에는 테스트 전용 접두사를 사용합니다. 관리 스크립트는 릴리스용 표준 서비스 이름을 거부합니다.

```text
Service: SunPackWatchBrokerTest_<id>
Pipe:    \\.\pipe\SunPack.WatchBroker.Test.<id>
```

```powershell
.\scripts\manage_test_watch_service.ps1 -Action Install `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev' `
  -BrokerPath '.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## 네이티브 구성 요소 개별 빌드

### Rust 런타임

```powershell
cargo build --locked --manifest-path sunpack\Cargo.toml -p sunpack-runtime --bin sunpack-runtime --release --target x86_64-pc-windows-msvc
```

### 7-Zip 내장 C++ worker

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

제품 worker에는 7-Zip 소스가 내장되어 있으며, 실행 시 `7z.dll`을 불러오지 않습니다.

### Windows 알림

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\toast_host -B .cache\native\x64\release\toast_host -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\toast_host --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\toast_host -C Release --output-on-failure
```

Watch는 `watch.toast_enabled`에 따라 Windows 진행·완료·실패 알림을 표시합니다. 실패 보고서는 데이터 폴더의 `.sunpack_watch/failures`에 저장합니다.

## 테스트

Rust 워크스페이스, CLI 블랙박스 테스트 및 CI 형식 테스트를 각각 실행할 수 있습니다.

```powershell
cargo test --locked --manifest-path sunpack\Cargo.toml --workspace --profile ci
```

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

```powershell
.\scripts\run_ci_tests.ps1
```

pytest만 실행하면 Broker가 필요한 항목을 건너뜁니다. 전체 인수 테스트는 임시 서비스와 명명된 파이프를 만든 뒤 Rust 테스트와 CLI/Watch 블랙박스 테스트를 실행하고 서비스를 제거합니다. 기존 제품 서비스는 건드리지 않습니다. 권한 상승이 없는 CI에서는 서비스 설치가 즉시 실패합니다.

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

## Windows 릴리스 빌드

```powershell
.\scripts\build_windows.ps1
```

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

Inno Setup 6의 `ISCC.exe`가 필요합니다. `-InnoCompilerPath`로 컴파일러 위치를 지정할 수 있습니다. Cargo와 CMake로 구성 요소를 빌드하고 설정, 암호 목록, 보조 스크립트 및 라이선스를 배치합니다. PE 아키텍처와 패키징된 CLI를 검사한 뒤 Inno Setup으로 설치 프로그램을 생성합니다.

설치 프로그램 동작은 정적 계약 테스트로 검사합니다. 머신 상태에 의존하는 설치·업그레이드·제거 E2E는 실행하지 않습니다. `-SkipTests`는 인수 테스트만 건너뜁니다.
