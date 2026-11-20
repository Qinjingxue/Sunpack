# 開発環境とビルド

[简体中文](../zh-CN/development_setup.md) | [English](../development_setup.md) | [繁體中文](../zh-TW/development_setup.md) | **日本語** | [한국어](../ko/development_setup.md)

SunPack は Windows 専用です。Cargo で Rust ランタイムと Watch Broker を、CMake でネイティブ worker、ランチャー、GUI、通知 DLL をビルドします。Python のテスト依存関係は `uv.lock` で固定します。必要なツールは [README の開発とテスト](../../README.ja.md#開発とテスト) を参照してください。

## ディレクトリと成果物

| パス | 用途 |
| --- | --- |
| `sunpack/sunpack_runtime/` | Rust の処理・計算コア、CLI、Watch |
| `sunpack/sunpack_usn_core/` | NTFS/ReFS USN の共有 Rust コア |
| `sunpack/sunpack_watch_broker/` | Windows Watch Broker サービス |
| `sunpack/sevenzip_bridge/` | CLI ランチャーと 7-Zip を組み込んだ worker |
| `sunpack/toast_host/` | Windows 通知 DLL |
| `tools/`、`tools/arm64/` | 共有アーカイブツール、ARM64 用 7-Zip テストツール |
| `.cache/rust-target/` | 共通の Cargo 出力 |
| `.cache/native/<arch>/<profile>/<component>/` | CMake のネイティブ成果物 |
| `.cache/gui-x64/` | x64 GUI の CMake 出力 |

開発、リリース、CI はこれらのディレクトリを共有します。Cargo はターゲットとプロファイルごとに出力します。診断用の `ci` と LTO を有効にした `release` は別の場所に生成し、ランチャーとテストは指定された成果物を直接使います。

## Python 依存関係

`test` は pytest とテストデータ生成、`build` は CMake、`dev` はその両方です。

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

`.venv` を初めて作成する場合、x64 ホストは Python 3.11、ARM64 ホストは 3.12 を uv で選択します。必要なら uv がインタープリターを取得します。既存の `.venv` ではインタープリターを保持し、ロック済み依存関係を同期します。グローバルの site-packages が有効なら無効にします。

## 開発環境のセットアップ

```powershell
.\scripts\setup_windows_dev.ps1
```

1. 指定アーキテクチャの Rust MSVC ターゲットを用意し、`uv sync --locked --extra dev` で `.venv` を同期します。
2. 受け入れテスト用アーカイブ生成ツールを取得・検査します。
3. Runtime、Watch Broker、テストデータ生成ツール、CLI ランチャー、worker、通知 DLL をビルドし、`.cache` に配置します。
4. `ci` プロファイルで PowerShell と同じアーキテクチャの場合は worker と Toast の CTest を実行します。

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
.\scripts\setup_windows_dev.ps1 -Arch arm64 -SkipAcceptanceTestTools
```

x64 と ARM64 それぞれの 7-Zip テストツールを用意します。初回は 26.04 の `7z.exe`、`7z.dll`、`7zCon.sfx` を取得します。完全な受け入れテストには `tools/` にある共有 WinRAR 6.22、zstd 1.5.7、[7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4) も必要です。WinRAR は生成器二つ、RAR SFX モジュール、ライセンスを、7-Zip-Zstandard は LZ4 生成器、DLL、ライセンスを使用します。これらは開発・テスト専用です。

Windows 11 ARM64 では `.\run_acceptance_tests.ps1 -Arch arm64 -NoWait` を使います。共有 x64 ツールは Windows のエミュレーションで動作します。ビルドだけを行う場合や x64 で ARM64 向けにクロスビルドする場合は `-SkipAcceptanceTestTools` で共有ツールの準備と検査を省略できます。

## USN Watch Broker

Watch は NTFS/ReFS の USN Journal を使い、内容の変更と書き込み境界を判断します。巻レベルの操作は共有 Rust コアと Watch Broker サービスに集約されます。Watch は Rust が返した観測結果と状態を利用します。

### サービスと接続の寿命

Watch はプロセスごとにリースを管理します。最初のリースでオンデマンド起動とローカル名前付きパイプへの接続を行い、後続リースで共有します。最後のリースを解放すると切断します。最初のクライアントが 5 秒以内に接続しない場合、または最後のリースを解放して 1 秒が経過した場合はサービスが終了します。クライアント数とボリュームコンテキスト数はそれぞれ最大 64 個です。

```text
Service: SunPackWatchBroker
Pipe:    \\.\pipe\SunPack.WatchBroker.v1
```

サービスはローカルの名前付きパイプクライアントのみ受け入れます。サービスのインストールには管理者権限が必要です。インストール済みのサービスは通常ユーザーの Watch から利用できます。

### USN の読み取り範囲

Rust がメタデータと現在の USN を読みます。現在値が前回値より大きいときに Broker に次の範囲を要求します。

```text
previous_usn < usn <= current_usn
```

観測ごとの Reason データは最大 1 MiB で、USN レコード V2・V3・V4 を扱います。全 Reason と `CLOSE` を除いた Reason を区別し、上書き・拡張・切り詰めを内容変更として扱います。メタデータだけの変更は書き込みとみなしません。

Watch の起動前に入力が NTFS/ReFS 上にあり、USN Journal を読み取れることを確認します。 `ERROR_JOURNAL_NOT_ACTIVE` の場合だけ既存の 32 MiB / 8 MiB パラメーターで作成して再照会します。作成・読み取り、巻 ID、Broker 接続の問題があれば起動を中止して原因を報告します。

[READ_USN_JOURNAL_DATA_V1 の説明](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1) に従って、巻の読み取りと単一ファイルの照会は V2–V3 を要求します。V3 のファイルと親フォルダーは完全な 128 ビット ID を保存し、V2 はゼロを補います。ディレクトリの復旧はカーソル 0 から開始できますが、Journal ID と保持範囲を検証します。[ReFS の識別子要件](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information) に従い、FileIdInfo、フォルダーの同一性とカタログには完全な ID を使います。ファイル名のない V4 範囲レコードは要求しません。

ReFS 回帰テストでは上位 64 ビットが非ゼロのファイル・親 ID を持つ V3 を模擬します。既存の作成、バージョン要求、カーソル 0、ページ単位の復旧テストを再利用します。実 ReFS ボリュームはローカルの検証に使用でき、CI の必須条件ではありません。

### Broker の個別ビルド

```powershell
cargo build --locked --manifest-path sunpack\sunpack_watch_broker\Cargo.toml --release `
  --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\watch-broker
```

ARM64 はターゲットに `aarch64-pc-windows-msvc` を指定します。x64 では次のパスに出力します。

```text
.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
```

テストサービスには専用接頭辞を使います。管理スクリプトはリリース用の標準サービス名を拒否します。

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

## ネイティブコンポーネントの個別ビルド

### Rust ランタイム

```powershell
cargo build --locked --manifest-path sunpack\Cargo.toml -p sunpack-runtime --bin sunpack-runtime --release --target x86_64-pc-windows-msvc
```

### 7-Zip を組み込んだ C++ worker

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

製品版 worker は収録した 7-Zip ソースを組み込むため、実行時に `7z.dll` を読み込みません。

### Windows 通知

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\toast_host -B .cache\native\x64\release\toast_host -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\toast_host --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\toast_host -C Release --output-on-failure
```

Watch は `watch.toast_enabled` に従って進捗、完了、失敗の通知を表示します。失敗レポートはデータフォルダーの `.sunpack_watch/failures` に保存します。

## テスト

Rust ワークスペース、CLI ブラックボックステスト、CI 形式のテストは個別に実行できます。

```powershell
cargo test --locked --manifest-path sunpack\Cargo.toml --workspace --profile ci
```

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

```powershell
.\scripts\run_ci_tests.ps1
```

pytest 単独では Broker が必要なケースをスキップします。完全な受け入れテストでは隔離したサービスと名前付きパイプを一時的に作り、Rust と CLI/Watch のテストを実行した後でサービスを削除します。製品サービスを上書きしません。昇格されていない CI ではサービスのインストールが即座に失敗します。

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

## Windows リリース用ビルド

```powershell
.\scripts\build_windows.ps1
```

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

Inno Setup 6 の `ISCC.exe` が必要です。 `-InnoCompilerPath` で場所を指定できます。ビルドは Cargo と CMake で各コンポーネントを作成し、設定、パスワード、補助スクリプト、ライセンスを配置します。PE のアーキテクチャとパッケージ済み CLI を検証し、Inno Setup で最終インストーラーを作成します。

インストーラーの動作は静的な契約テストで確認します。マシン状態に依存するインストール・更新・削除の E2E は実行しません。 `-SkipTests` が省くのは受け入れテストだけです。
