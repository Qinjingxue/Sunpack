# 設定ガイド

[简体中文](../zh-CN/configuration.md) | [English](../configuration.md) | [繁體中文](../zh-TW/configuration.md) | **日本語** | [한국어](../ko/configuration.md)

日常の設定には `sunpack_config.json` を使います。開発版のファイルはプロジェクトのルート、インストール版は `%ProgramData%\SunPack` にあります。`sunpack_advanced_config.json` は既定値を提供し、通常設定は同名の詳細設定に優先します。最後に環境変数 `SUNPACK_CONFIG_OVERRIDES` が適用されます。オブジェクトはフィールド単位、`filesystem.scan_filters` は `name` 単位でマージされます。他の配列は全体が置き換わります。Watch は設定変更を自動で読み直します。

```powershell
sunpack.exe config validate
sunpack.exe config show
```

## よく使う設定

| 項目 | 値 |
| --- | --- |
| `cli.language` | `zh` 簡体字中国語、`en` 英語、`zh-TW` 繁体字中国語、`ja` 日本語、`ko` 韓国語。未対応の値は英語になります。 |
| `recursive_extract` | `"*"` で処理対象がある限り継続、正の整数でラウンド数を指定、`"?"` で各ラウンド後に確認。 |
| `recursive_authorization.enabled` | `true` で入れ子のアーカイブの選択条件を有効化。 |
| `post_extract.archive_cleanup_mode` | 完全成功時に `"r"` でごみ箱、`"k"` で保持、`"d"` で削除。 |
| `post_extract.flatten_single_directory` | `true` で単一のトップレベルフォルダーの内容を一段上に移動。 |
| `post_extract.flatten_directory_name` | 平坦化する出力の名前に `"outer"`（既定、外側）または `"inner"`（内側）を使用。 |
| `passwords.clipboard_passwords_enabled` | 既定は `true`。CLI で現在のクリップボードをパスワード候補にする。 |
| `watch.clipboard_monitor_enabled` | 既定は `true`。Watch がクリップボード履歴を保存。 |
| `watch.clipboard_builtin_max_entries` | クリップボード履歴の保持件数。既定は 30、最小 1。 |
| `watch.toast_report_retention_days` | 失敗レポートの保持日数。既定は 30、最小 1。 |
| `watch.event_log_retention_days` | CLI と Watch が共有するタスク履歴とイベントの保持日数。 |
| `watch.deduplication` | `"none"`、`"file_id"`、`"hash"`。 |
| `watch.deduplication_scope` | `"root"`（既定）または `"global"`。 |
| `extraction.content_requirement` | `"complete"`（既定）は完全結果のみ、`"allow_partial"` は部分結果も保持。 |

設定画面でも言語を選べます。日本語を選び、元アーカイブを保持する設定例です。

```json
{
  "cli": {
    "language": "ja"
  },
  "post_extract": {
    "archive_cleanup_mode": "k"
  }
}
```

入力ファイルの探索は既定で現在の階層だけです。`-R` でサブフォルダーを探索し、`-r` でアーカイブ内の再帰展開を制御します。`-r`、`-c`、`-o` などで一回の動作を上書きできます。[CLI リファレンス](cli_parameters.md) を参照してください。

## 展開結果と部分成功

worker が復号・出力への書き込み・クローズを終えた結果で判定します。有効な空アーカイブやフォルダーだけのアーカイブも完全成功になり得ます。コンテナー構造の警告だけでは、元ファイルの再走査や出力 CRC の再検証を行いません。成功判定は worker に渡した論理入力と処理できたメンバーに対するものです。

`"allow_partial"` では、破損または分割巻不足でも、worker の最終報告に完了済みファイルが一つ以上あれば、そのファイルを保持します。空ファイルも含みます。未完了のファイルや未報告のファイルは含めません。パスワード、プロセス、出力 I/O の障害は失敗です。完全成功した入力だけが元ファイルの整理を許可し、同一ファイルに共有される埋め込みアーカイブに対する保護も適用されます。CLI、Watch、再帰展開は同じチェックポイントと復旧経路を使います。

旧 `verification` 設定はアップグレード時に削除されます。部分結果の保持は `extraction.content_requirement` で設定してください。

## スキャンフィルター

`filesystem.scan_filters_enabled=false` で全フィルターを無効にできます。個別の変更は `filesystem.scan_filters` に対象の `name` を指定します。 `blacklist`、`whitelist`、`size_range`、`mtime_range` が利用できます。拡張子で除外すると、拡張子を偽装したアーカイブが見つからない場合があります。

```json
{
  "filesystem": {
    "scan_filters": [
      { "name": "size_range", "enabled": true, "min_bytes": 1, "max_bytes": null },
      { "name": "mtime_range", "enabled": true, "start_utc": "2024-01-01T00:00Z", "end_utc": "2027-01-01T00:00Z" }
    ]
  }
}
```

GUI は日付を Windows のローカル時刻で入力し、UTC で保存します。サイズ単位に小数を使え、バイト単位に丸めます。比較式、旧フィールド名、秒・小数秒を含む時刻は使用できません。

ブラックリストとホワイトリストの各レコードでは、`paths` はフォルダー、`files` は拡張子を除いた名前、`extensions` は拡張子、`full_names` は完全なファイル名に一致します。

```json
{
  "name": "blacklist",
  "enabled": true,
  "paths": [{ "value": ".git", "regex": false }],
  "files": [{ "value": "レポート*", "regex": false }],
  "extensions": [{ "value": "zip", "regex": false }],
  "full_names": [{ "value": "\\.(?:tmp|log|bak)\\z", "regex": true }]
}
```

- `regex=false` では `*` が任意の文字列、`?` が 1 Unicode 文字に一致し、残りはリテラルです。 `*` はパスの区切り `/` をまたがず、連続したアスタリスクも再帰を表しません。
- `regex=true` では Rust regex の構文で検索します。先読み・後読み、後方参照は使えません。既定ではすべてのフィールドで大文字小文字を区別します。正規表現のインラインフラグは有効です。
- 名前は最後のドットで分割します。 `bundle.part01.rar.jpg` の名前は `bundle.part01.rar`、拡張子は `jpg`。ドットなしの場合は拡張子がありません。末尾ドットは空拡張子、`.zip` は空の名前と拡張子 `zip` です。
- `paths` はファイル名を除いたフォルダーに適用します。単独の名前は任意の階層のフォルダー要素、区切り付きのパターンはスキャンルートからの相対パスに一致します。正規表現には `/` 区切りの相対パスを渡します。 `\Adownloads\z` はルート直下の `downloads` と配下を選択し、スキャンルートそのものは除外しません。ホワイトリストは一致可能なフォルダーへの経路を残します。
- 同じリスト内は OR です。ブラックリストは一つでも該当するフィールドを除外し、ホワイトリストは空でない全フィールドを満たす必要があります。空リストは制限しません。
- GUI では正規表現のチェックボックスを使い、Enter で確定します。青いタグは正規表現を示し、クリックで編集できます。検証失敗時は下書きを保持し、ディスクには保存しません。GUI でバックスラッシュを入力する際は一つでよく、JSON のエスケープは保存時に処理します。

## Watch とパスワード

監視ルートは `sunpack_watch_roots.txt` にあり、GUI または `watch add/remove` で管理します。 `watch enable/disable` で監視を開始・一時停止できます。既存の NTFS/ReFS 以外のパスは起動・再読込時に監視リストから外し、言語設定に従う Windows ダイアログで知らせます。残りの監視の開始を妨げず、実際のフォルダーやファイルは削除しません。一時的にオフラインのルートは保持します。

```powershell
sunpack.exe watch add C:\Downloads -o E:\Output -R
sunpack.exe watch list
```

`-o` を省くと各アーカイブの隣に展開します。 `-R` はルートごとに保存されます。GZIP、BZIP2、XZ、Zstandard、LZ4 は外側のストリームを先に展開し、出力された TAR は通常の再帰展開で処理します。通常の TAR 分析はオフセット 0 からで、他のオフセットの候補は Embedded が検出します。

パスワードは `builtin_passwords.json` に保存します。 `enabled` は真偽値で、`scopes` に指定した絶対フォルダーとその配下に適用されます。省略すると全フォルダーに適用されます。 `clipboard_history` は文字列の配列です。

```json
{
  "passwords": [
    { "value": "共通パスワード", "enabled": true },
    { "value": "フォルダー用パスワード", "enabled": true, "scopes": ["D:/Downloads", "E:/Archives"] }
  ],
  "clipboard_history": []
}
```

現在のクリップボードを CLI で使う設定と、Watch で履歴を収集する設定は独立しています。両方を無効にしても保存済みの履歴は残ります。ファイルには平文で保存されます。

## Watch の重複排除

提供される通常設定の既定は `file_id`、詳細設定と未設定時の既定は `none` です。 `file_id` はファイル ID（ハードリンク）を比較します。 `hash` は一致サイズに対してストリーミング XXH3-128 で内容を比較します。対象は検出済みで論理配置が確定したアーカイブ入力です。分割巻の順序と埋め込み範囲を区別し、展開した内容や CLI の展開には影響しません。

重複が見つかっても元ファイルは削除されず、元タスクの再試行も継続できます。GUI では重複スキップとして表示します。 `global` は別の監視ルートまたはボリュームも比較対象にします。ファイル ID はボリューム ID と組み合わせて比較します。入れ子のルートが同じパスを含んでも一つの入力として扱います。モードや範囲を変更するとインデックスを作り直します。変更のない再起動では永続化済みインデックスを検証して再利用します。

## 自動設定とアップグレード

発見時に実行計画を一度作成します。深度検出は各ラウンドで Embedded を使い、通常検出と同じパスワード・分割巻の解決を使います。共有キャッシュは 64 MiB、worker のタスク別バッファー予算は 32 MiB、キューサイズは 4096 です。空き容量不足からの復旧とアイドル時のキャッシュ整理は自動です。 `watch.runtime_cache_cleanup_idle_seconds` の既定は 10 秒で、イベントと期限で起動します。失敗レポートは `watch.toast_report_retention_days` に従って保持し、新しいレポートを書き込むときに期限切れ分と残った一時レポートを整理します。状態は書き込み可能なデータフォルダーの `.sunpack_watch` に置きます。

インストーラーと `scripts/upgrade_config.ps1` が設定を移行します。1.2.6 以降の既知のインストールでは、現在の通常設定、監視ルート、パスワードと履歴を保持します。ルートの `initial_scanned` を維持し、新フィールドに既定値を補い、廃止された設定を除いて詳細設定を新テンプレートに入れ替えます。フィルターモジュールは名前で照合し、省略したモジュールは復元しません。公開バージョン v1.3.0–v1.3.4 の旧フィルターを変換し、v1.3.5 の形式を使用している設定は維持します。

回復タスク、索引、イベント履歴、キャッシュ、失敗レポートなどはアップグレードでリセットされます。1.2.6 未満は新規インストールとして扱います。既存データがありインストール元バージョンを識別できない場合や設定が壊れている場合は、実行ファイルを置き換える前にアップグレードを停止します。
