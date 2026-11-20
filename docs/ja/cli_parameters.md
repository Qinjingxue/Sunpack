# CLI リファレンス

[简体中文](../zh-CN/cli_parameters.md) | [English](../cli_parameters.md) | [繁體中文](../zh-TW/cli_parameters.md) | **日本語** | [한국어](../ko/cli_parameters.md)

```powershell
sunpack.exe <command> [options] [paths...]
```

| コマンド | 用途 |
| --- | --- |
| `extract`, `e` | スキャン、識別、展開、検証、後処理、元ファイルの整理 |
| `scan`, `s` | 読み取り専用のアーカイブ検索とパスワード確認 |
| `watch`, `w` | フォルダー監視と、安定したファイルの自動処理 |
| `daemon`, `d` | バックグラウンドプロセスとサインイン時起動の管理 |
| `passwords`, `pw` | パスワード候補の取得元の要約 |
| `config`, `cfg` | マージ後の設定の表示・検証 |
| `doctor`, `doc` | 設定・環境の読み取り専用チェック |
| `version`, `ver` | インストール済みバージョンの表示 |

オプションは記載の短い形式を使います。値を持つ引数は `-r 3` のように空白で分けます。特に `-p PASSWORD` の次の引数は、先頭が `-` でもそのままパスワードとして読み取られます。連結書式とイコール書式は使用できません。

## 共通オプション

| オプション | 意味 |
| --- | --- |
| `-R` | 入力フォルダーのサブフォルダーを検索。展開後の再帰展開を制御する `-r` とは独立。 |
| `-j` | JSON 形式で出力。別名を指定しても JSON の `command` は正式名。 |
| `-v` | 検出と診断の詳細を表示。 |
| `-pa` | 終了前にキー入力を待つ。 |
| `-npa` | 終了時にキー入力を待たない。 |

`extract` と `scan` では通常メッセージを標準出力、エラーを標準エラー出力に書きます。`-j` はテキストメッセージの代わりに `command`、`inputs`、`summary`、`errors`、`items`、`tasks`、`logs` を持つ JSON を出力します。スキャンエラーが発生しても、読み取れる入力の処理は続きます。

アーカイブ処理の失敗は `failed_count`、無効な入力は `input_error_count`、ファイルシステムのスキャンエラーは `scan_error_count` に集計されます。スキャン診断の詳細はレポートあたり最大 100 件（ディレクトリあたり最大 20 件）で、超過分は件数だけを報告します。タスク結果はこの上限と独立しています。`extract -j` は `tasks[].failures` に処理と入力の失敗を、`scan -j` は `items[].error` と `items[].error_kind` に論理アーカイブのエラーを出力します。保持した部分出力は `summary.recovered_outputs` に列挙されます。

前景の `extract`・`scan` は高いプロセス優先度で動作します。最後の前景処理が終わると、Watch の稼働中はそのアイドル期限まで優先度を維持し、それ以外は即時に `runtime.process_mode` に戻ります。

## extract

```powershell
sunpack.exe extract [options] <paths...>
sunpack.exe extract D:\A.7z -p 123456 -p secret
sunpack.exe extract D:\Archives -o E:\Unpacked -P .\passwords.txt -c k
sunpack.exe extract D:\Nested -r "*" -nf
sunpack.exe extract -d D:\MaybeArchive.bin
```

| オプション | 意味 |
| --- | --- |
| `-p PASSWORD` | パスワードを指定。複数回指定可能。 |
| `-P PASSWORD_FILE` | 1 行に 1 つのパスワードがあるテキストファイルを読み取る。 |
| `-a` | 端末で対話入力。空行で入力終了。 |
| `-d` | Embedded の全ファイル走査のみを使用。最初のラウンドはファイルシステムフィルターなしで全入力を走査。入れ子のラウンドではフィルター、`embedded_scan.recursive_candidate_ratio`、深さと許可の設定を使用。 |
| `-r VALUE` | 再帰展開を上書き。正の整数はラウンド数、`*` は新たな対象がある限り継続、`?` は各ラウンドの後に確認。 |
| `-c VALUE` | 完全に成功した元アーカイブの処理。 `d` は削除、`r` はごみ箱、`k` は保持。 |
| `-o OUTPUT_DIR` | 出力ルートを指定。相対パスはコマンドの作業フォルダー基準。 |
| `-f` / `-nf` | トップレベルにフォルダーが一つだけあるときの階層の平坦化を有効化／無効化。 |

出力先は通常アーカイブの隣です。`-o` を使うと「出力ルート / 入力の共通ルートからの相対パス / アーカイブ名」に作成します。出力ルート内に作られた入れ子のアーカイブは、自身の場所を基準に出力します。埋め込み区間と入れ子のアーカイブはタスクツリーに個別の進捗・状態・エラーを持ちます。リダイレクト時はルートタスク完了後にツリーを書き出します。

| 終了コード | 意味 |
| --- | --- |
| `0` | 全タスクが完全成功。 |
| `1` | 失敗したタスクあり。 |
| `2` | 引数・パス・設定のエラー。 |
| `3` | 実行時の異常。 |
| `4` | 失敗はないが、部分成功したタスクあり。 |

## scan

```powershell
sunpack.exe scan [options] <paths...>
sunpack.exe scan D:\Downloads -R -v -d -j
```

`extract` と同じ検出・計画・パスワード確認を利用します。実ファイルと論理アーカイブごとに、確認できた形式、バイト範囲、分割巻、パスワード、エラーを表示します。埋め込み範囲は `[開始, 終了)` で、終端が不明なら `?` です。分割巻が未確定の場合は組み合わせを列挙せず `pending`、不足が確認できた場合は `missing` を出力します。

パスワードの確認はアーカイブ全体や分割巻の完全性を保証しません。展開、出力作成、入れ子の再帰処理、元ファイルの整理は行いません。`-d` は通常の Relations/Detection とファイルシステムフィルターを省略し、Embedded でアンカーを検索します。検出後は既存のパスワード・分割巻解決を再利用します。深度検出はリクエスト単位です。

## watch

```powershell
sunpack.exe watch <add|remove|list|enable|disable|reload|relog|status> [options]
sunpack.exe watch add D:\Downloads -o E:\Output -R -d
sunpack.exe watch list
sunpack.exe daemon start
```

監視フォルダーはデータディレクトリの `sunpack_watch_roots.txt` に保存します。列の順序は `入力フォルダー | 出力ルート | deep_detect | initial_scanned | recursive | enabled` です。

```text
C:\Downloads | | false | false | false | true
E:\Archives | E:\Output | false | false | false | true
F:\Incoming | . | true | false | true | true
G:\Incoming | | true | false | false | false
```

出力列を空にするとアーカイブの隣に展開します。相対出力は対応する入力フォルダーを基準に絶対パスとして保存します。監視ルートは NTFS または読み取り可能な USN Journal のある ReFS を使います（NTFS にも読み取り可能な USN Journal が必要です）。`deep_detect` と `recursive` の既定は `false`。深度検出を選んだルートではファイルシステムのスキャンフィルターを無効にし、再帰展開・パスワード再試行・復旧にもそのルートの設定を適用します。

`initial_scanned` が空または `false` のフォルダーは初回スキャンの候補をキューに入れた後で `true` に更新します。入力の変更でリセットし、出力先や深度検出設定だけの変更では保持します。スキャン済みルートの停止中の変化は USN で復旧します。 `enabled=false` は該当フォルダーの監視を停止します。

| サブコマンド | 動作 |
| --- | --- |
| `add PATH...` | 監視ルートを追加。 `-o DIR` は入力が一つの場合だけ使用可。 `-R` は再帰検索、`-d` は既存ルートも含め深度検出を有効化。 |
| `remove PATH...`, `rm` | 入力パスで監視ルートを削除。 |
| `list`, `ls` | 保存済みのルートを表示。 |
| `enable`, `ea` | 監視を再開。 |
| `disable`, `da` | バックグラウンドプロセスとトレイを保ったまま監視を一時停止し、状態を保存。 |
| `reload`, `rl` | 設定と監視ルートを読み直す。 |
| `relog`, `rlg` | ログを再構築。 |
| `status`, `st` | 稼働状態を表示。JSON には保留件数、最後のエラー、ルートも含む。 |

既登録ルートの出力先を変えるには削除してから追加します。異なるルートが同一の出力先を共有することはできますが、出力先同士を親子にすることはできません。再追加時に `-d` を省くと既設定を保持します。深度検出を解除するにはルートファイルの第 3 列を `false` または空にします。監視を再開しても一時停止中の新規変更は投入されません。有効なまま停止・再起動した場合は、停止期間中の変更を復旧します。

書き込み・移動・変更が候補処理を起動します。最初の新規候補に固定の待機はなく、その後は観測された書き込み間隔に応じて静穏期間を調整します。追加分割巻やパスワード候補の変更で該当タスクを再試行します。Watch はパイプラインが作った出力サブツリーを除外し、その中に後から置かれたファイルも無視します。

## daemon（別名 d）

```powershell
sunpack.exe daemon <start|stop|startup>
sunpack.exe daemon startup <enable|disable|status>
```

`start` は保存された監視状態を復元します。 `start -nt` はその起動に限りトレイを無効にします。 `stop` は停止を待ち、監視の設定を変更せず、`-j` と `-h` を受け付けます。 `startup` は現在のユーザーのサインイン時起動を管理します。

## passwords

```powershell
sunpack.exe passwords [-j]
sunpack.exe passwords -P .\passwords.txt -j
```

`-p`、`-P`、`-a` を利用できます。アーカイブパスを受け取らないため、グローバル候補の取得元のみ表示します。展開時は該当する直近の成功候補、範囲付き JSON パスワード、CLI 入力、現在のクリップボード、グローバル JSON パスワード、クリップボード履歴の順です。重複を除き、必要に応じて空のパスワードを先に試します。

## config

```powershell
sunpack.exe config [options] <show|validate>
sunpack.exe config validate -j
```

`show` は有効な設定を出力し、`validate` は JSON、フィールド値、検出ルール名とその設定を確認します。 `-j` で JSON を出力します。[設定ガイド](configuration.md) も参照してください。

## doctor

```powershell
sunpack.exe doctor [-j]
sunpack.exe doc [-j]
```

設定、ネイティブコンポーネント、worker、Windows 通知、監視ルートを読み取り専用で確認します。存在しない監視ルートは警告です。失敗があれば `1`、成功・警告・スキップだけなら `0` を返します。

## version

```powershell
sunpack.exe version
```

実行ファイルと同じフォルダーの `VERSION.txt` を読み、`version=` に続くバージョンを表示します。

## Windows の右クリックメニュー

管理画面の設定または次のコマンドで、現在のユーザーのエクスプローラーメニューを管理します。終了コードが `0` なら成功です。開発ビルドでは `--app-root` と `--cli` を指定できます。

```powershell
.\SunPackGUI.exe --context-menu enable
.\SunPackGUI.exe --context-menu disable
```

フォルダーとその背景のメニューでは直接展開、再帰展開、パスワード入力、監視、再帰監視、監視解除を利用できます。監視は `watch add` の後に `daemon start` を実行し、保存済みの一時停止状態は維持します。ファイルの展開メニューは既定で深度検出を使います。

```text
extract "%1" -d -pa
extract "%1" -a -d -pa
```

同じ再帰監視ルートのサブフォルダーに点在する分割巻は組み合わせの候補になります。別々のルートの巻は組み合わせません。Watch の最初の出力はルートの出力先、CLI の既定の出力はアーカイブ（分割形式ではアンカー巻）の隣です。
