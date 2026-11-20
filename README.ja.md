<p align="center"><img src="sunpack.png" width="96" alt="SunPack"></p>
<h1 align="center">SunPack</h1>
<p align="center"><b>Windows 向けアーカイブ処理ツール。フォルダーを監視し、アーカイブをバックグラウンドで自動展開します。</b></p>

<p align="center"><a href="README.md">简体中文</a> · <a href="README.en.md">English</a> · <a href="README.zh-TW.md">繁體中文</a> · <b>日本語</b> · <a href="README.ko.md">한국어</a> · <a href="https://github.com/Qinjingxue/Sunpack/releases/latest">ダウンロード</a></p>

<p align="center"><img src="sunpack_en.gif" width="80%" alt="SunPack のデモ（英語 UI）"></p>

## インストール

SunPack は Windows 10 バージョン 1709 以降と Windows 11 に対応します。Watch で監視するフォルダーには NTFS または ReFS が必要です。

1. [GitHub Releases](https://github.com/Qinjingxue/Sunpack/releases/latest) から `sunpack-windows-<arch>-<version>-setup.exe` を取得します。Intel/AMD の 64 ビット版 Windows には `x64`、Windows on ARM には `arm64` を選びます。
2. インストーラーを実行し、UAC の確認を承認します。既定のインストール先は `C:\Program Files\SunPack` です。Watch Broker サービスのインストールには管理者権限が必要です。
3. 必要に応じて、システムの `PATH` への追加、エクスプローラーの右クリックメニューへの登録、Windows サインイン時の Watch 起動を選びます。PATH に追加した場合は PowerShell を開き直します。

## 使い方

| コマンド | 別名 | 用途 |
| --- | --- | --- |
| `extract` | `e` | アーカイブを展開します。 |
| `watch` | `w` | フォルダーを監視し、書き込みが完了したファイルを自動処理します。 |
| `scan` | `s` | アーカイブを検索し、展開せずにパスワードを確認します。 |
| `passwords` | `pw` | パスワード候補の取得元を表示します。 |
| `config` | `cfg` | 有効な設定を表示・検証します。 |
| `daemon` | `d` | バックグラウンドプロセスとサインイン時の起動を管理します。 |
| `doctor` | `doc` | インストール状態と実行環境を読み取り専用で確認します。 |
| `version` | `ver` | インストール済みのバージョンを表示します。 |

```powershell
sunpack extract D:\Downloads -o E:\Output -c k
sunpack watch add D:\Downloads -o E:\Output -R
sunpack daemon start
```

引数、終了コード、JSON 出力は [CLI リファレンス](docs/ja/cli_parameters.md) を参照してください。拡張子を偽装した多くのファイルは通常モードで識別できます。深度検出（`-d`）は通常モードで見つからないファイルを調べる際に使ってください。常時有効にすると意図しない埋め込みデータまで展開する場合があります。

### 管理画面とパスワード

スタートメニューの SunPack GUI または Watch のタスクトレイから管理画面を開きます。タスク履歴、監視フォルダー、パスワード、設定を管理できます。GUI はネイティブ C++ 実装で、ウィンドウを閉じると終了します。

設定画面で日本語を選択できます。`sunpack_config.json` を直接編集する場合は `cli.language` を `ja` にします。

インストール版のパスワードファイルは `%ProgramData%\SunPack\builtin_passwords.json` です。パスワード管理画面でフォルダー別に編集したり、クリップボード履歴から候補を保存したりできます。JSON では `value` にパスワード、`enabled` に有効状態を指定し、任意の `scopes` に絶対パスを指定します。`scopes` を省略すると全フォルダーが対象になります。Watch は別の `clipboard_history` を管理し、既定で最新 30 件を残します。

CLI の `-p`・`-P`・対話入力と、現在のクリップボードも候補になります。直近に成功したパスワードは、有効な候補の順序を調整するために使われます。候補や分割巻を検証している間は 0% の表示が続く場合があります。進捗通知から取り消せます。

![SunPack の設定画面（英語 UI）](docs/images/gui.en.png)

## 主な機能

- **アーカイブの検出**。バイナリ内容に基づき、拡張子を偽装したファイル、他ファイルに埋め込まれたアーカイブ、分割アーカイブを識別します。ZIP、ZIPX、RAR3/4/5、7z（Zstandard、LZ4 を含む）、Zstandard、gzip、bzip2、TAR、XZ、LZ4、単体の ENC v4 に対応します。ZIPX の WinZip 専用 JPEG・MP3・WavPack 方式、および旧式・辞書付き LZ4 は対象外です。
- **再帰展開と後処理**。展開したアーカイブを続けて処理できます。完全に成功した元アーカイブは既定でごみ箱へ移動します。シード中などで元ファイルを残す場合は `post_extract.archive_cleanup_mode` を `k` にします。
- **Watch**。書き込みが安定したファイルを処理し、不足する分割巻が揃ったときやパスワード候補が変わったときに再試行します。監視ルートごとに出力先を設定でき、Windows 通知で進捗を確認できます。
- **障害からの復旧**。空き容量が不足すると処理を一時停止し、容量が回復すると再開します。WAL のチェックポイントを用いて停止後に復旧します。明示的に部分結果を許可した場合は、破損や巻の不足があっても完成したファイルを保持できます。
- **並行処理と省リソース**。Rust と C++ のネイティブコードとオーバーラップ I/O で複数のアーカイブを処理します。アイドル時はイベントで待機し、処理後に不要なキャッシュを解放します。

## 設定

通常はインストール版の `%ProgramData%\SunPack\sunpack_config.json` を編集します。`sunpack_advanced_config.json` は残りの既定値を提供し、同名の設定は通常設定が優先されます。Watch は変更を自動で読み直します。

```powershell
sunpack config validate
sunpack config show
```

[設定ガイド](docs/ja/configuration.md) に、言語、スキャンフィルター、再帰展開、重複排除、アップグレード時の引き継ぎをまとめています。

## 開発とテスト

Windows 10/11 x64 または Windows 11 ARM64、PowerShell 5.1 以降、Git for Windows、uv 0.12 以降、rustup と Rust MSVC ツールチェーンが必要です。Visual Studio 2022 または Build Tools 2022 の「C++ によるデスクトップ開発」、MSVC、Windows SDK を用意します。ARM64 には対応する MSVC ビルドツールと Windows 向け C++ Clang ツールも必要です。インストーラーの生成には Inno Setup 6 を使います。

```powershell
.\scripts\setup_windows_dev.ps1
uv sync --locked --extra test
uv run --locked pytest
.\run_acceptance_tests.ps1
.\scripts\build_windows.ps1
```

ARM64 のネイティブ開発・受け入れ環境には `-Arch arm64` を、x64 での ARM64 クロスビルドには `-Arch arm64 -SkipAcceptanceTestTools` を使用します。

Rust は探索、フォーマット分析、パスワード・分割巻の解決、処理計画を担当し、埋め込み 7-Zip を使う C++ worker が展開します。[開発環境とビルド](docs/ja/development_setup.md)、[開発時の責務境界](docs/ja/development_boundaries.md)、[worker と 7-Zip の再現可能な比較](docs/ja/benchmark_worker_vs_7z_300m.md) を参照してください。このリポジトリを変更する際は [AGENTS.md](AGENTS.md) の開発ルールを守ってください。

## 既知の問題

形式によっては各パスワード候補の検証コストが高く、多数の候補があると進捗が長時間 0% のままになる場合があります。その場合は処理を中止して候補を減らしてください。

## 貢献

問題の報告や提案は [GitHub Issues](https://github.com/Qinjingxue/Sunpack/issues) へ、変更は [Pull Request](https://github.com/Qinjingxue/Sunpack/pulls) へお寄せください。必要に応じて、次のログを添付できます。

- Watch イベント: `%ProgramData%\SunPack\.sunpack_watch\events.json` と `events.json.store`
- 展開失敗レポート: `%ProgramData%\SunPack\.sunpack_watch\failures\failed-*.txt`
- バックグラウンドランタイム: `%ProgramData%\SunPack\runtime-*.state.events.json` と対応する `.store`

履歴のマニフェストと対応する `.store` は一緒に添付してください。共有前にパスワードや私的なパスを除いてください。

## 謝辞とライセンス

貢献者と利用者の皆さま、ならびに [Core UI](https://github.com/ghboke/core-ui)、[7-Zip](https://www.7-zip.org/)、[zlib-ng](https://github.com/zlib-ng/zlib-ng)、[LZ4](https://github.com/lz4/lz4)、[RustCrypto](https://github.com/RustCrypto) の開発者に感謝します。

SunPack が独自に作成したコードは [MIT ライセンス](LICENSE) です。サードパーティーのソースやバイナリには、それぞれの元のライセンスが適用されます。[サードパーティー告知](THIRD_PARTY_NOTICES.md)、[ライセンス原文](licenses/)、[ライセンスと配布](docs/ja/licensing.md) を参照してください。
