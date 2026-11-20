# 設定指南

[简体中文](../zh-CN/configuration.md) | [English](../configuration.md) | **繁體中文** | [日本語](../ja/configuration.md) | [한국어](../ko/configuration.md)

日常設定請修改 `sunpack_config.json`。開發建置使用項目根目錄中的檔案；安裝版使用 `%ProgramData%\SunPack\sunpack_config.json`。`sunpack_advanced_config.json` 提供其餘預設值。

一般設定的同名值優先於進階設定；`SUNPACK_CONFIG_OVERRIDES` 仍是最後一層顯式涵蓋。物件按欄位合並，`filesystem.scan_filters` 按 `name` 合並，其餘陣列整體涵蓋。Watch 會自動重新載入設定變更。

修改後驗證並查看最終設定：

```powershell
sunpack.exe config validate
sunpack.exe config show
```

## 常用設定

| 設定項                                  | 如何設定                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------- |
| `cli.language` | `zh` 簡體中文、`en` 英語、`zh-TW` 繁體中文、`ja` 日語、`ko` 韓語。不支援的值會使用英語。 |
| `recursive_extract`                     | `"*"` 持續處理巢狀封存檔；正整數指定輪數；`"?"` 每輪後詢問。                                  |
| `recursive_authorization.enabled`       | `true` 啟用巢狀封存檔篩選策略；`false` 跳過該策略。                                           |
| `post_extract.archive_cleanup_mode`     | 完整成功後 `"r"` 移至資源回收筒、`"k"` 保留、`"d"` 刪除原封存檔。                                 |
| `post_extract.flatten_single_directory` | `true` 時提升唯一頂層輸出目錄中的內容。                                                     |
| `passwords.clipboard_passwords_enabled` | 預設 `true`，CLI 將目前剪貼簿文字作為密碼候選。                                             |
| `watch.deduplication`                   | `"file_id"` 依硬連結去除重複；進階設定預設 `"none"` 不去除重複；`"hash"` 辨識內容相同的邏輯封存檔輸入。 |
| `watch.deduplication_scope`             | 預設 `"root"` 僅比較目前監控目錄；`"global"` 比較全部監控目錄。                             |
| `watch.clipboard_monitor_enabled`       | 預設 `true`，執行中的 Watch 儲存剪貼簿密碼歷史。                                            |
| `watch.clipboard_builtin_max_entries`   | 預設保留最新 30 條剪貼簿歷史，最小 1。                                                      |
| `watch.toast_report_retention_days`     | 預設保留失敗報告 30 天，最小 1。                                                            |
| `extraction.content_requirement`        | `"complete"` 要求完整結果；`"allow_partial"` 接受部分復原結果。                             |

例如，在主設定中加入以下欄位，可保留原封存檔：

```json
{
  "post_extract": { "archive_cleanup_mode": "k" }
}
```

CLI 的 `-r`、`-c` 和 `-o` 等參數可為單次命令指定解壓縮行為，詳見 [CLI 參數說明](cli_parameters.md)。

目錄發現預設只掃描目前層。`scan`、`extract` 使用 `-R` 發現子目錄，巢狀解壓縮由 `-r` 控制。升級會重置托管執行資料，並按需轉換舊掃描過濾欄位。遷移保留的資料見下文。

## 解壓縮結果與部分成功

worker 完成解碼、輸出寫入和關閉後的最終結果決定解壓縮是否成功。有效空封存檔和僅含目錄的封存檔也可以完整成功。容器結構告警本身不會觸發來源檔案二次遍歷、輸出 CRC 復核或 LZ4 計劃與回報核對。成功針對交給 worker 的邏輯輸入及其處理的成員，不證明損壞的容器已暴露全部原始成員。

`sunpack_config.json` 中的 `extraction.content_requirement` 控制部分接受，預設 `"complete"`。`"allow_partial"` 只在損壞或缺卷結果中，worker 的最終報告明確記錄至少一個已完成檔案時接受部分結果，零位元組檔案也計入。僅寫出位元組、尚未完成的成員和未報告的檔案均不算完成；密碼、程序和輸出 I/O 故障仍為失敗。部分接受保留解壓縮輸出，不會修復或獨立驗證壞檔案。

coordinator 統一負責最終狀態決策、逐輸入 checkpoint 和復原。失敗輸入重試時保留完成的兄弟輸入；只有完整成功可以授權清理來源檔案，並沿用共用載體的所有者保護。CLI、Watch 和巢狀解壓縮使用同一流程。

verification 框架、方法設定、完整度閾值和質量評分已移除，安裝升級會刪除舊 `verification` 設定段。GUI 保留部分成功設定，一般設定的值優先於舊進階設定中的同名欄位。

## 掃描過濾

將 `filesystem.scan_filters_enabled` 設為 `false` 可關閉全部掃描過濾器。只修改一個過濾器時，在 `filesystem.scan_filters` 中按 `name` 新增條目：

```json
{
  "filesystem": {
    "scan_filters": [{ "name": "size_range", "enabled": false }]
  }
}
```

可用過濾器包括 `blacklist`（黑名單）、`whitelist`（白名單）、`size_range` 和 `mtime_range`。在 `sunpack_config.json` 中修改其欄位；隨程式提供的 `sunpack_advanced_config.json` 可作為格式範例。按副檔名過濾可能漏掉偽裝副檔名的封存檔。

黑名單與白名單提供 `paths`（路徑）、`files`（檔名）、`extensions`（副檔名）和 `full_names`（檔名+副檔名）。四個清單均使用物件記錄，例如：

```json
{
  "name": "blacklist",
  "enabled": true,
  "paths": [{ "value": ".git", "regex": false }],
  "files": [{ "value": "報告*", "regex": false }],
  "extensions": [{ "value": "zip", "regex": false }],
  "full_names": [
    { "value": "報告[最終版]+.zip", "regex": false },
    { "value": "\\.(?:tmp|log|bak)\\z", "regex": true }
  ]
}
```

每項獨立設定 `regex`：關閉時僅 `*` 和 `?` 是萬用字元，分別匹配任意數量字元和一個 Unicode 字元，其餘符號按字面匹配；普通項完整匹配所選內容。路徑萬用字元不跨 `/`，連續星號也不表示遞迴。開啟時使用 Rust regex 完整支援的語法（不含前後查找、反向引用），在所選內容中搜索。四個欄位的普通項和規則運算式項目統一預設區分大小寫，直接匹配 Unicode 文字；規則運算式內聯旗標保留其標準語義。

檔名按最後一個點號分割：`bundle.part01.rar.jpg` 的檔名是 `bundle.part01.rar`，副檔名是 `jpg`，檔名+副檔名是完整的 `bundle.part01.rar.jpg`。副檔名規則不帶前導點號。沒有點號時檔名保持完整，副檔名不存在，不參與副檔名匹配；末尾點號表示空副檔名；`.zip` 的檔名為空、副檔名為 `zip`。三個名稱清單只作用於檔案。壓縮檔仍按內容辨識，偽裝副檔名和分卷的辨識流程不變。

`paths` 只匹配目錄，處理檔案時會先去掉最後的檔名；匹配檔名請使用 `files`、`extensions` 或 `full_names`。普通路徑單獨名稱匹配任意層級的目錄元件，含 `/` 或 `\` 的路徑相對掃描根目錄。規則運算式路徑搜索統一使用 `/` 分隔的目錄相對路徑，表達式本身不會被改寫。目錄命中後包含子樹；例如 `\Adownloads\z` 選擇根目錄下的 downloads 目錄及其後代。根目錄本身不被剪枝。規則運算式未錨定時也可能匹配更深的目錄，白名單會保留可能到達匹配項的父目錄。同一清單使用 OR，黑名單任一欄位命中即排除，白名單各非空欄位同時滿足；空清單不限制。

GUI 輸入欄旁的“使用規則運算式”核取方塊設定目前記錄，預設關閉；點擊 Tag 編輯已有記錄，藍色 Tag 表示規則運算式。輸入後按 Enter 提交，驗證失敗保留草稿並保持磁碟設定不變。GUI 中規則運算式輸入一個反斜線即可，JSON 逸出由儲存流程處理。

安裝程式轉換已發行的 v1.3.0–v1.3.4 過濾格式，保留 v1.3.5 的現代格式；不保證相容未打 Tag 的開發版格式。舊完整檔名進入 `full_names`，舊副檔名進入 `extensions`，白名單二者仍在同一個模組內同時滿足。目錄剪枝和黑名單都啟用時合並規則；只有一個啟用時僅保留啟用方規則，丟棄未啟用方，避免靜默啟用舊規則；兩者都關閉時合並保留規則，並保持黑名單關閉。舊路徑 Glob 保留按路徑元件邊界匹配的範圍，必要時轉為規則運算式記錄。舊白名單的兩組路徑規則直接合並為一個 OR 清單，不再保留獨立 AND 條件。執行階段僅使用目前模型。

大小上下限為 0 至 18446744073709551615 的整數位元組，兩端包含；上下限相等表示精確匹配該大小。時間使用 `YYYY-MM-DDTHH:mmZ` 格式的 UTC 分鐘字串，開始包含、結束不包含。`null` 表示該側無限制；涵蓋預設設定時請顯式填寫兩個邊界。例如：

```json
{
  "filesystem": {
    "scan_filters": [
      {
        "name": "size_range",
        "enabled": true,
        "min_bytes": 1,
        "max_bytes": null
      },
      {
        "name": "mtime_range",
        "enabled": true,
        "start_utc": "2024-01-01T00:00Z",
        "end_utc": "2027-01-01T00:00Z"
      }
    ]
  }
}
```

GUI 按 Windows 本地時區編輯時間，儲存時轉成 UTC。大小單位支援小數並精確取整到位元組。不接受比較表達式、歷史別名欄位、秒或小數秒時間戳，也不提供執行階段設定遷移。

## Watch 與密碼

監控目錄儲存在 `sunpack_watch_roots.txt`，透過 GUI 或 `watch add/remove` 管理；監控啟停透過 GUI 或 `watch enable/disable` 控制。已移除無效的 `watch.enabled`、`watch.roots`、`watch.max_folders` 和 `performance.worker.priority_aging_quantum`。

監控輸入目錄支援 NTFS 和 ReFS。後端啟動或重新載入設定時，會自動從監控清單移除確認位於其他檔案系統的路徑，並按 `cli.language` 彈出經典 Windows 錯誤視窗，列出路徑、檔案系統和已移除說明。不必等待快顯視窗確認即可繼續監控其餘目錄；如果清單已空，服務仍可正常啟動並等待新增目錄。此操作不會刪除目錄或檔案，暫時離線的路徑不會因此被移除。

分析只辨識目前層格式。GZIP、BZIP2、XZ、Zstandard、LZ4 先解開外層流，產出的 TAR 再由正常遞迴流程辨識和解壓縮；不提前辨識複合格式。原 `tar_*` 分析模組及全部 `max_probe_bytes` 設定已刪除。普通 TAR 分析僅從偏移 0 開始，其他位置的 TAR 候選只來自統一的 embedded 掃描器。`watch.event_log_retention_days` 控制 CLI 與監控共用的任務歷史和事件保留天數。

使用 `sunpack.exe watch add C:\Downloads` 新增監控目錄，附加 `-o E:\Output` 可指定輸出目錄；留空時解壓縮到各封存檔所在資料夾。`watch list` 可查看目錄。加 `-R` 可遞迴監控子目錄，每個監控根獨立儲存該旗標。

## 自動執行參數

封存檔發現一次產生執行計劃。舊 Direct-file 二次規劃、流報告快取及 `analysis.modules` 開關已刪除。Deep 在每個解壓縮輪次透過完整檔案 Embedded 掃描發現封存檔，普通模式保留快速發現流程；兩者重用現有密碼與分卷解析。共用分析快取仍為 64 MiB，worker 單任務緩沖預算仍為 32 MiB，獨立讀取保留既有快取同步和資源生命週期保護。已刪除的 `input_planning`、`analysis.shared_cache_mb`、`analysis.max_concurrent_reads` 和 `performance.worker.job_buffer_budget_bytes` 參數仍不保留執行階段相容路徑。

原生 worker 和 Python 階段執行緒容量始終採用現有自動策略。佇列上限固定為內部參數 4096，保留原有背壓。記憶體預留自動計算為 128 MiB 加上每個名義 CPU 配額 16 MiB。磁碟空間不足暫停/復原及閒置快取維護始終開啟；`watch.runtime_cache_cleanup_idle_seconds` 仍可設定，預設 10 秒，繼續按事件和截止時間喚醒，不新增閒置輪詢。寫入執行緒由原生 worker 內部管理，預設每卷 4 個。

兩個剪貼簿開關和歷史上限已複製到一般設定，進階範本中也保留。這兩個開關獨立：關閉目前剪貼簿密碼使用不等於關閉 Watch 歷史擷取；兩者都關閉也不會刪除已儲存歷史。歷史以明文儲存在 `builtin_passwords.json`。

失敗報告僅按 `watch.toast_report_retention_days` 保留，數量上限、位元組預算及詳情截斷均已移除。批次詳情由原生程式碼流式寫入磁碟，使用固定緩沖和惰性失敗檢視，不拼接大錯誤文字、不複製整棵失敗樹，也不產生完整逸出 JSON 大型字串。報告任務重用現有工作排程，編碼和 I/O 時釋放 GIL，寫入磁碟不持有通知狀態鎖；取消會等待寫入退出並清理未完成檔案。這裡約束的是報告編碼的額外記憶體，不是解壓縮流程已經持有的診斷和原生清單；遍歷仍需要與巢狀深度成正比的空間。新報告寫入時清理過期報告和遺留臨時報告，不新增定時器。

狀態固定放在可寫資料目錄下的 `.sunpack_watch`，安裝版即 `%ProgramData%\SunPack\.sunpack_watch`，CLI、Watch、GUI 共用。不再提供狀態目錄設定或執行階段切換機制。

升級只由安裝程式和 `scripts/upgrade_config.ps1` 處理。已安裝版本的數字基礎版本從 1.2.6 起，保留一般設定、`sunpack_watch_roots.txt` 和 `builtin_passwords.json`。升級為舊目錄和密碼補上啟用狀態，並保留 `initial_scanned`。安裝程式將密碼清單和剪貼簿歷史各壓縮為一行，保留內容、順序和密碼範圍。以新一般範本確定設定欄位：已有值（包括 `false`、`0`、空值和 `null`）保留，新增欄位補預設值，廢棄欄位移除。過濾模組按名稱匹配，不還原使用者省略的模組；舊過濾欄位及從進階設定移到一般設定的項目只在升級邊界轉換。僅限進階欄位及未知擴充不保留，進階設定直接換成新模板。

低於 1.2.6 的版本按全新安裝清理，包括根目錄、密碼及一般設定。已知版本升級均清除其他托管資料，包括復原任務、目錄索引、任務和事件歷史、快取及失敗報告；自訂 Watch 狀態目錄僅刪除已知 SunPack 記錄。相容根目錄保留初掃標記，清理執行狀態不會要求重新初掃。已有資料卻無法辨識或缺少安裝版本時，停止升級且不改資料；空資料目錄視為新安裝。損壞設定或不安全路徑也會在替換程式前停止準備。

持久化密碼只來自 `builtin_passwords.json`，包括其中的 `clipboard_history`。剪貼簿歷史使用字串陣列。密碼清單中的記錄必須帶布林欄位 `enabled`，停用的記錄保留在檔案中。在 `passwords` 中填寫 `value`，可用 `scopes` 指定一個或多個絕對目錄，對其子目錄也生效；省略 `scopes` 即全局生效。執行階段來源包括顯式輸入（`-p`、`-P` 或密碼提示框）與目前剪貼簿。

```json
{
  "passwords": [
    { "value": "全域密碼", "enabled": true },
    { "value": "資料夾密碼", "enabled": true, "scopes": ["D:/Downloads", "E:/Archives"] }
  ],
  "clipboard_history": []
}
```

## 監控去除重複

在設定或 GUI 中將 `watch.deduplication` 設為 `none`、`file_id` 或 `hash`。隨程式提供的一般設定預設啟用依硬連結去除重複，進階設定和未設定時的後備預設值仍為 `none`，一般設定優先於進階設定。僅已確認是封存檔且邏輯配置確定的輸入進入索引，普通檔案和不確定的分卷組合不參與。邏輯輸入包含有序分卷成員和載體區間，不比較解壓縮後的內容，也不影響 CLI 解壓縮。

`file_id` 比較底層檔案識別資訊；`hash` 先篩選大小，再以流式 XXH3-128 比較內容。Hash 相等是概率性判斷，不是密碼學保證。即使原輸入掛起或失敗，新重複輸入也會跳過，但不會記為解壓縮成功或清理來源檔案，原輸入仍可正常重試。GUI 將跳過記錄歸入成功分類，以綠色“去除重複跳過”標識展示，不代表解壓縮成功。索引僅在輸入檔案仍存在於監控範圍內時有效。

每次切換模式都會清除舊記憶體索引及持久化去除重複索引。`none` 到此結束；`file_id` 掃描已確認輸入並重建，`hash` 還會讀取其內容計算摘要。重建不執行解壓縮或源清理。未切換模式的程序重新啟動會驗證並重用獨立持久化索引，不重新計算全部 Hash。

`watch.deduplication_scope` 在普通和進階設定中均預設為 `root`。設為 `global` 後可跨監控目錄比較：Hash 去除重複可辨識跨目錄、跨卷的相同邏輯輸入內容；依硬連結去除重複比較卷標識和 File ID，不會將不同卷上的相同 File ID 當成同一個檔案。巢狀監控根涵蓋的同一路徑仍是一個輸入，不會與自身重複。切換範圍和切換模式一樣，清除並重建去除重複索引；未啟用去除重複時不建立索引。
