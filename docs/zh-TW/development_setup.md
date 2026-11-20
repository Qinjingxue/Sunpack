# 開發環境和建置說明

[简体中文](../zh-CN/development_setup.md) | [English](../development_setup.md) | **繁體中文** | [日本語](../ja/development_setup.md) | [한국어](../ko/development_setup.md)

SunPack 是 Windows-only 項目。Cargo 建置 Rust 執行階段和 Watch Broker，CMake 建置原生 worker、啟動器、GUI 與通知 DLL。Python 測試依賴由 `uv.lock` 鎖定。

## 目錄和建置成品

執行開發腳本所需的工具鏈見 [README 的開發環境要求](../../README.zh-TW.md#開發相關)。

項目主要目錄：

```text
sunpack/sunpack_runtime/      Rust 排程與運算核心、CLI 和 Watch
sunpack/sunpack_usn_core/     NTFS/ReFS USN 共用 Rust 核心
sunpack/sunpack_watch_broker/ Windows Watch Broker 服务
sunpack/sevenzip_bridge/      CLI 啟動器與內嵌 7-Zip worker
sunpack/toast_host/           Windows toast DLL
tools/                        共用的外部封存工具
tools/arm64/                  ARM64 版 7-Zip 測試工具
.cache/rust-target/            共用的 Cargo 建置目錄
.cache/native/                 啟動器、worker 和 Toast 的 CMake 建置目錄
.cache/gui-x64/                x64 GUI 的 CMake 建置目錄
```

開發、發行和 CI 入口共用這些目錄。Cargo 按目標三元組和 profile 儲存成品。原生 CMake 使用 `.cache/native/<架构>/<profile>/<组件>/`，讓診斷用的 `ci` 和啟用 LTO 的 `release` 建置並存。原始碼啟動器和測試直接使用所選建置成品。

## Python 依賴

可安裝的 extra：

| Extra | 用途 |
| --- | --- |
| `test` | pytest 與測試資料產生依賴 |
| `build` | CMake |
| `dev` | build 與 test 的並集 |

常用安裝方式：

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

首次建立 `.venv` 時，腳本透過 uv 選擇 Python，x64 主機使用 3.11，ARM64 主機使用 3.12。uv 可以按需下載解釋器。已有 `.venv` 會保留其解釋器並同步鎖定的依賴。如果該環境啟用了全局 site-packages，腳本會關閉該選項。

## 一鍵準備開發環境

```powershell
.\scripts\setup_windows_dev.ps1
```

腳本會：

1. 用 rustup 補齊所選架構的 Rust MSVC target，並用 `uv sync --locked --extra dev` 同步 `.venv`。
2. 準備並檢查驗收封存檔產生器。
3. 建置 Rust runtime、Watch Broker、測試資料產生器、CLI 啟動器、worker 和 Toast DLL，成品留在 `.cache`。
4. 使用 `ci` profile 且建置架構與目前 PowerShell 程序架構相同時，執行 worker 與 Toast 的 CTest 案例。

選項：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
.\scripts\setup_windows_dev.ps1 -Arch arm64 -SkipAcceptanceTestTools
```

x64 和 ARM64 都會準備對應架構的 7-Zip 測試工具，首次下載使用 26.04，只保留 `7z.exe`、`7z.dll` 和 `7zCon.sfx`。完整驗收另外使用 `tools/` 下共用的 WinRAR 6.22、zstd 1.5.7 和 [7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4)。WinRAR 只提取兩個產生器、RAR SFX 模組和授權條款，7-Zip-Zstandard 保留 LZ4 產生器及配套 DLL 和授權條款。這些工具都只供開發和測試使用。

在 Windows 11 ARM64 上執行 `.\run_acceptance_tests.ps1 -Arch arm64 -NoWait`。共用的 x64 產生器由 Windows 仿真執行。`-SkipAcceptanceTestTools` 跳過共用產生器的準備和檢查，適用於僅建置或在 x64 主機上交叉建置 ARM64。

## USN Watch Broker

watch 使用 NTFS/ReFS USN Journal 判斷檔案內容變化和檔案是否已經跨過寫入邊界。需要訪問卷級 Journal 的操作集中在 `sunpack/sunpack_usn_core` 和 `sunpack/sunpack_watch_broker`，Watch 直接消費 Rust 檔案觀察結果和狀態。

### 元件和生命週期

- `sunpack/sunpack_usn_core` 是 Windows-only Rust crate，包含卷標識、Journal 探測、有限範圍的 USN reason 讀取以及命名管道客戶端協議。
- `sunpack/sunpack_watch_broker` 編譯為 `sunpack-watch-broker.exe`，以 Windows service 執行，持有卷級 Journal 訪問能力。
- watch 啟動時先取得一個程序級 lease。第一個 lease 負責按需啟動服務並建立本地 named pipe 連接，同一程序中的後續 lease 重用連接，最後一個 lease 釋放時關閉連接。
- 服務按需啟動。第一個客戶端在 5 秒內未連接時服務退出；最後一個 lease 釋放後等待 1 秒再退出。每個服務最多保留 64 個客戶端和 64 個卷內容。

標準識別資訊為：

```text
Service: SunPackWatchBroker
Pipe:    \\.\pipe\SunPack.WatchBroker.v1
```

服務只接受本機 named pipe 客戶端。安裝服務需要管理員權限；已安裝服務由普通 watch 執行執行個體透過客戶端協議使用。

### USN 讀取邊界

檔案觀察由 Rust 讀取檔案中繼資料和目前 USN。目前 USN 大於上次記錄時，客戶端請求 broker 讀取：

```text
previous_usn < usn <= current_usn
```

每次觀察最多讀取 1 MiB 的 reason 資料，支援 USN record version 2、3、4，並區分全部 reason 與去除 `CLOSE` 後的 reason。涵蓋、擴充、截斷等內容變化會進入 watch 的內容變更路徑；僅中繼資料變化不會被當作內容寫入。

watch 根啟動前會驗證路徑位於 NTFS 或 ReFS 卷且 Journal 可讀。Journal 不存在時，先由 Broker 自動建立，再觀察檔案識別資訊；建立或讀取失敗、卷標識無效或 broker 不可連接時，watch 啟動失敗並報告原因。

### 本地手動建置

x64：

```powershell
cargo build --locked --manifest-path sunpack\sunpack_watch_broker\Cargo.toml --release `
  --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\watch-broker
```

ARM64 使用目標三元組 `aarch64-pc-windows-msvc`。x64 輸出檔案如下。

```text
.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
```

開發測試服務必須使用測試識別資訊前綴：

```text
Service: SunPackWatchBrokerTest_<id>
Pipe:    \\.\pipe\SunPack.WatchBroker.Test.<id>
```

可以用倉程式庫腳本安裝或解除安裝臨時服務；腳本會拒絕標準服務識別資訊，避免測試涵蓋開發機上的發行服務：

```powershell
.\scripts\manage_test_watch_service.ps1 -Action Install `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev' `
  -BrokerPath '.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## 手動建置原生元件

### Rust 執行階段

```powershell
cargo build --locked --manifest-path sunpack\Cargo.toml -p sunpack-runtime --bin sunpack-runtime --release --target x86_64-pc-windows-msvc
```

### C++ 內嵌 7-Zip worker

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

產品 worker 內嵌保留的 7-Zip 原始碼，執行階段不載入 `7z.dll`。

### Windows toast

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\toast_host -B .cache\native\x64\release\toast_host -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\toast_host --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\toast_host -C Release --output-on-failure
```

持續執行的 watch 按 `watch.toast_enabled` 建立 Windows 通知能力，並按設定發送進度、完成和失敗通知。通知失敗報告寫入可寫資料目錄下的 `.sunpack_watch/failures`。

## 驗證

```powershell
cargo test --locked --manifest-path sunpack\Cargo.toml --workspace --profile ci
```

## 測試

完成開發環境建置後可直接執行 CLI 黑箱測試：

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

直接執行 pytest 時，需要 Windows Watch Broker 的案例會被跳過。完整驗收透過 `run_acceptance_tests.ps1` 準備隔離測試服務，執行 Rust 正確性測試和 CLI、Watch 黑箱測試，結束後自動解除安裝測試服務：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

驗收服務使用隨機的測試服務名、named pipe 和臨時環境變量，不會涵蓋已安裝的發行服務。CI 環境未提權時，服務安裝會立即失敗，避免等待交互式 UAC。

項目 CI 風格測試：

```powershell
.\scripts\run_ci_tests.ps1
```

## Windows 發行建置

正式建置入口：

```powershell
.\scripts\build_windows.ps1
```

常用參數：

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

發行成品為 Windows 安裝程式。建置環境必須安裝 Inno Setup 6；缺少 `ISCC.exe` 時會在建置開始前失敗，也可以透過 `-InnoCompilerPath` 指定編譯器路徑。建置會執行 packaged smoke checks，並使用真實 Inno Setup 編譯器產生最終安裝程式；安裝程式行為透過靜態 contract tests 驗證，不再執行依賴電腦狀態的安裝/升級/解除安裝 E2E。`-SkipTests` 只跳過 acceptance suite。

建置過程：

1. 用 Cargo 建置 Rust 執行階段和 Watch Broker
2. 用 CMake 建置 CLI 啟動器、worker、GUI 與 toast DLL
3. 放入設定、密碼表、輔助腳本、授權條款及其他發行檔案
4. 檢查 PE 架構，執行打包後的 CLI smoke tests
5. 按建置參數執行驗收測試，用 Inno Setup 建立安裝程式

### NTFS / ReFS 的 USN 約定

兩種檔案系統共用 Broker 和日誌復原流程。僅當查詢傳回
`ERROR_JOURNAL_NOT_ACTIVE` 時，重用原有 32 MiB / 8 MiB 參數建立日誌，
然後重新查詢；Watch 先完成該步驟，再觀察檔案識別資訊。其他錯誤照常報告，
不增加周期輪詢或常駐索引。

卷讀取按微軟的 [READ_USN_JOURNAL_DATA_V1 說明](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1)
請求 V2–V3，單檔案查詢採用相同版本範圍。V3 的檔案和父目錄 ID 完整保留
128 位，V2 補零匹配；目錄復原允許初始游標為 0，仍驗證日誌 ID 和保留邊界。
現有 FileIdInfo、目錄識別資訊及緊湊 catalog 沿用完整 ID，符合微軟的
[ReFS 識別資訊要求](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)。
不請求缺少檔名的 V4 範圍記錄。

ReFS 回歸涵蓋使用高 64 位非零的檔案及父目錄 ID 構造模擬 V3 記錄，
並重用現有日誌建立、版本請求、零游標和分頁復原測試。不依賴真實 ReFS 卷，
也不要求 CI 有建立 ReFS 卷的權限。真實卷驗證僅作為本地臨時驗證，不納入
項目測試套件或 CI 要求。
