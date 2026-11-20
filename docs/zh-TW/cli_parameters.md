# CLI 參數說明

[简体中文](../zh-CN/cli_parameters.md) | [English](../cli_parameters.md) | **繁體中文** | [日本語](../ja/cli_parameters.md) | [한국어](../ko/cli_parameters.md)

```powershell
sunpack.exe <command> [options] [paths...]
```

頂層命令：

| 命令 | 作用 |
| --- | --- |
| `extract`, `e` | 掃描、辨識、解壓縮、驗證、後處理和清理。 |
| `watch`, `w` | 監控目錄，檔案穩定後自動處理。 |
| `scan`, `s` | 唯讀掃描封存檔並確認密碼。 |
| `passwords`, `pw` | 查看目前命令可用的密碼來源匯總。 |
| `config`, `cfg` | 查看或驗證合並後的有效設定。 |
| `daemon`, `d` | 啟停背景程序及管理登錄啟動項。 |
| `doctor`, `doc` | 唯讀檢查設定和執行環境。 |
| `version`, `ver` | 輸出目前安裝的 SunPack 版本號。 |

命令支援完整名稱和列出的別名，選項僅接受下列短寫，不支援長選項。簡寫輸出的 JSON `command` 仍使用完整命令名。`-p` 是密碼，`-P` 是密碼檔案；`-f` 啟用攤平，`-nf` 關閉攤平。帶值參數推薦分開寫，例如 `-r 3`、`-c r`。

密碼必須寫成 `-p 密碼`，中間用空白分隔，不支援緊貼或等號寫法。`-p` 後的下一個參數按密碼原文讀取，即使以 `-` 開頭。單獨的 `-pa` 控制退出暫停。

常用簡寫範例：

```powershell
sunpack e D:\Downloads -o E:\Output -r "*" -c r -d -P D:\pw.txt -npa
sunpack s D:\Downloads -v -d -j
sunpack w add D:\Downloads -o E:\Output -R -d
sunpack w ls
sunpack w st
```

## 通用輸出參數

這些參數用於 `extract`、`scan`：

| 參數 | 說明 |
| --- | --- |
| `-R` | 遞迴發現輸入子目錄；與巢狀解壓縮的 `-r` 獨立。 |
| `-j` | 以 JSON 格式輸出結果，適合腳本調用。 |
| `-v` | 輸出更多偵測和診斷細節。 |
| `-pa` | 命令結束後等待按鍵退出。 |
| `-npa` | 命令結束後不暫停。 |

`extract` 和 `scan` 在有前景封存檔請求執行期間使用高程序優先順序。最後一個前景請求結束後，如果 Watch 正在執行，則保留前景優先順序直到 Watch 的閒置期限；沒有執行 Watch 時，共用執行階段和原生 worker 立即復原設定中的 `runtime.process_mode`。Watch 快取清理遵循 `watch.runtime_cache_cleanup_idle_seconds`。

`passwords` 只支援 `-j` 以及密碼輸入參數；`config` 支援 `-j`。JSON 結果使用統一外層欄位：`command`、`inputs`、`summary`、`errors`、`items`、`tasks`、`logs`；具體命令按語義填充 `items` 或 `tasks`。

`extract` 和 `scan` 的普通文字寫入 stdout，錯誤寫入 stderr。`[扫描错误]` 表示檔案系統掃描失敗，`[解压失败]` 表示封存檔處理失敗；`[扫描不完整]` 表示部分路徑無法讀取，發現結果可能不完整，其餘可讀取的輸入仍會繼續處理。`-j` 輸出 JSON 結果，不輸出這些文字消息。

JSON 的 `summary.scan_error_count` 統計檔案系統掃描錯誤，包括省略了單獨詳情的錯誤。每份報告最多保留 100 條檔案系統掃描診斷記錄，另加 1 條總省略摘要；單個目錄仍適用原有的 20 條詳情上限。超出報告預算後只累計省略數量，不再保留每條錯誤的路徑或識別資訊。封存檔任務結果獨立於這項診斷預算保留。

`extract -j` 在 `tasks[].failures` 中報告封存檔和輸入失敗。`scan -j` 透過 `items[].error` 和 `items[].error_kind` 報告邏輯封存檔錯誤，不公開內部 worker 證據或復原預覽。scan 按事實稀疏輸出欄位：區間輸入或嵌入區段顯示位元組範圍，實際分卷配置或確認缺卷時才顯示分卷欄位；內部 unknown 完整度不公開，尚未解決的分卷嘗試計劃顯示 `pending`（確認缺卷時為 `missing`）。最終保留的提取輸出列於 `summary.recovered_outputs`。

`extract` 的 `summary.failed_count` 和各輪處理的 `failed_count` 統計封存檔處理失敗；`input_error_count` 單獨統計無效輸入，例如不支援的檔案系統物件，文字中顯示為 `[输入错误]`。各輪處理另有 `scan_error_count` 和 `input_error_count`。受預算限制的檔案系統診斷詳情集中儲存在 `summary.scan_failures`，各輪的 `failures` 儲存封存檔失敗和輸入錯誤。分類依據結構化錯誤類別和目標結果。所有錯誤類別均保留在 `errors` 中，並使退出碼非零，即使其他封存檔處理成功也是如此。

## extract

用法：

```powershell
sunpack.exe extract [options] <paths...>
```

`paths` 可以是一個或多個檔案、目錄。目錄按設定掃描並產生解壓縮任務。

參數：

| 參數 | 說明 |
| --- | --- |
| `-p PASSWORD` | 提供一個解壓縮密碼，可重複傳入。 |
| `-P PASSWORD_FILE` | 從文字檔案讀取密碼，每行一個。 |
| `-a` | 在終端交互輸入密碼，空行結束。 |
| `-d` | 以 Embedded 為唯一封存檔發現入口。首輪關閉檔案系統過濾並掃描全部輸入；遞迴輪次保留檔案系統過濾、`embedded_scan.recursive_candidate_ratio` 比例篩選、遞迴深度和授權。被選中的檔案執行完整檔案掃描。 |
| `-r VALUE` | 涵蓋巢狀解壓縮輪數，接受正整數、`*` 或 `?`。 |
| `-c VALUE` | 涵蓋成功後的原封存檔處理：`d` 刪除，`r` 資源回收筒，`k` 保留。 |
| `-o OUTPUT_DIR` | 指定輸出根目錄；相對路徑按目前命令目錄解析。 |
| `-f` | 解壓縮後提升單一頂層目錄的內容。 |
| `-nf` | 保留解壓縮目錄結構。 |

`-o` 指定後，結果落在“輸出根 / 輸入路徑相對公共根的部分 / 封存檔名”下；未指定時落在封存檔旁邊。巢狀封存檔在輸出根內產生時，子封存檔仍使用自身所在位置計算輸出。

`-r` 的取值：

- `1`、`2`、`3` 等正整數：固定遞迴輪數。
- `*`：只要每輪仍產生新的可處理巢狀封存檔，就持續遞迴。
- `?`：每輪產生新的可處理巢狀封存檔後詢問是否繼續。

範例：

```powershell
sunpack.exe extract D:\Downloads
sunpack.exe extract D:\A.7z -p 123456 -p secret
sunpack.exe extract D:\Archives -P .\passwords.txt -c r
sunpack.exe extract D:\Nested -r * -nf
sunpack.exe extract -d D:\MaybeArchive.bin
sunpack.exe extract D:\Archives -o E:\Unpacked
```

退出碼：

- `0`：所有任務均完整成功。
- `1`：至少一個任務失敗。
- `2`：參數、路徑或設定錯誤。
- `3`：執行階段異常。
- `4`：沒有失敗任務，但至少一個任務只有部分成功。

解壓縮過程按邏輯任務展示樹形範圍，載體內多段和遞迴封存檔各自擁有狀態、進度和錯誤；重定向輸出在根任務結束後按完整樹輸出，最終匯總保持不變。

## scan

用法：

```powershell
sunpack.exe scan [options] <paths...>
```

`scan` 重用 extract 的發現、輸入規劃和密碼確認流程，按物理檔案和邏輯段列出本次取得的格式、範圍、分卷、密碼及錯誤。普通壓縮檔省略範圍；載體標注 `[起點, 終點)`，未知終點用 `?`，多段以樹形展示。未取得的資訊省略；已知加密但未找到密碼時顯示“密碼：未在密碼表中”，不重複輸出密碼回報錯誤，確認的密碼直接顯示。

分卷歧義使用現有卷位候選和配置的緊湊表示，不展開組合，狀態為“等待實際解壓縮驗證”。有限密碼測試不代表整包完整或整套分卷已驗證。scan 不解壓縮、不建立輸出目錄、不遞迴進入尚未解壓縮的內容，也不驗證輸出、攤平或清理來源檔案。

支援與 extract 相同的密碼輸入參數。`-v` 僅增加已有發現來源，不額外分析；`-j` 獨立控制輸出格式。

`-d` 跳過前置 Relations/Detection，僅透過完整檔案 Embedded 掃描發現封存檔，並關閉本次請求的檔案系統過濾；發現錨點後重用現有密碼與分卷解析。目錄範圍由 `-R` 決定。每次 CLI 請求只按自身參數決定是否啟用 deep；即使共用 runtime 正在深度監控同一輸入目錄，也不會影響 CLI 請求。

範例：

```powershell
sunpack.exe scan D:\Downloads
sunpack.exe scan D:\Downloads -d -j
sunpack.exe scan D:\Downloads -v
```

## watch

用法：

```powershell
sunpack.exe watch <add|remove|list|enable|disable|reload|relog|status> [options]
```

監控根目錄儲存在程式資源目錄下的 `sunpack_watch_roots.txt`。格式為 `輸入資料夾 | 輸出根目錄 | deep_detect | initial_scanned | recursive | enabled`。最後一列填 `true` 啟用該目錄，填 `false` 停用。

```text
C:\Downloads | | false | false | false | true
E:\Archives | E:\Output | false | false | false | true
F:\Incoming | . | true | false | true | true
G:\Incoming | | true | false | false | false
```

輸出列留空時，封存檔會解壓縮到封存檔所在資料夾；使用 `-o` 時，相對輸出路徑按該輸入目錄解析並持久化為絕對路徑。輸出根可以跨盤。每個根使用獨立的 `recursive` 旗標，預設 `false`；輸入根需要位於 NTFS 或 ReFS 卷且有可讀取的 USN Journal。

`deep_detect` 接受 `true` 或 `false`，留空時預設為 `false`。模式綁定輸入目錄；多個輸入目錄可共用輸出根，並分別採用不同模式。巢狀解壓縮、密碼重試和當機復原均保留原始輸入目錄，按該目錄的設定執行。啟用 deep 時，該目錄請求的全部 filesystem 掃描過濾模組失效。修改此列會觸發設定重新載入，也可執行 `watch reload` 應用修改。

`initial_scanned` 表示是否完成首次候選掃描，留空時為 `false`。啟動和執行中重新載入會自動掃描值為 `false` 的目錄，候選入隊後回寫 `true`；不必等待解壓縮成功。新增目錄或修改輸入路徑時重置為 `false`，僅修改輸出根或 deep 模式時保留。已掃描目錄的停用期間變化繼續透過 USN 復原。僅修改掃描標記、目錄順序、注釋或等價路徑寫法不會重新啟動排程器。

子命令和參數：

| 子命令 | 參數 | 說明 |
| --- | --- | --- |
| `enable`, `ea` | — | 啟用監控，保留背景程序。 |
| `add PATH...` | `-o DIR` | 新增監控根；只能同時新增一個路徑。 |
| `add PATH...` | `-R` | 為該監控根啟用遞迴發現。 |
| `add PATH...` | `-d` | 將各輸入目錄的 `deep_detect` 寫為 `true`；已登記目錄也會更新。 |
| `remove PATH...`, `rm PATH...` | — | 按輸入目錄移除監控根。 |
| `list`, `ls` | — | 列出持久化的輸入目錄。 |
| `reload`, `rl` | — | 重新讀取設定和監控根。 |
| `relog`, `rlg` | — | 重建日誌。 |
| `disable`, `da` | — | 暫停監控並儲存狀態，不退出背景程序或系統匣。 |
| `status`, `st` | — | 顯示監控服務是否執行。JSON 還包含待處理數量、最後一次錯誤和根目錄。 |

`enable` 復原監控；`disable` 的暫停狀態跨程序重新啟動儲存，復原時不提交暫停期間的新變化。啟用狀態下的程序重新啟動仍復原離線變化。檔案寫入、移動或修改會觸發活躍周期。新候選沒有首次處理延遲；後續內容變化按觀測到的寫入間隔自適應調整靜默視窗，不設固定最短或最長等待時間。檔案準備好後提交處理。新分卷到達或密碼來源變化會重新激活受影響任務。

`add` 的 `-o` 只能和一個輸入目錄一起使用。重複新增同一輸入目錄不會改變已有輸出映射；先 `remove` 再 `add` 才能更新映射。不同監控根的輸出根不能互為嚴格的祖先和子目錄，相同輸出根可以共用。

新增目錄時不傳 `-d`，預設不啟用 deep。重複新增已登記目錄時，不傳該參數會保留已有模式；關閉 deep 可將第三列改為 `false` 或留空。

```powershell
sunpack.exe watch add D:\Downloads -d
sunpack.exe daemon start
```

目錄物件和目錄空白處的右鍵選單都提供直接解壓縮、遞迴解壓縮、輸入密碼解壓縮、監控、遞迴監控和取消監控。檔案物件的兩個解壓縮入口預設啟用 `-d`。

## daemon（簡寫 d）

```powershell
sunpack.exe daemon <start|stop|startup>
sunpack.exe daemon startup <enable|disable|status>
```

`start` 啟動背景程序並復原儲存的監控啟停狀態；`stop` 等待背景退出，不改變監控啟停狀態。`start -nt` 禁用本次背景啟動的系統匣。`startup` 管理目前使用者的登錄啟動項。`stop` 支援 `-j` 和 `-h`。

“監控此目錄”依次執行 `watch add` 和 `daemon start`，不會涵蓋已儲存的暫停狀態。

## passwords

用法：

```powershell
sunpack.exe passwords [options]
```

參數：

| 參數 | 說明 |
| --- | --- |
| `-j` | 以 JSON 輸出密碼來源匯總。 |
| `-p PASSWORD` | 提供密碼，可重複傳入。 |
| `-P PASSWORD_FILE` | 從文字檔案讀取密碼，每行一個。 |
| `-a` | 在終端交互輸入密碼。 |

`passwords` 沒有封存檔路徑，因此僅匯總全局候選。封存檔解壓縮時，最近成功的有效密碼優先，其後依次為 JSON 中匹配範圍的密碼、CLI 輸入、目前剪貼簿、JSON 全局密碼及剪貼簿歷史。重複項會去除重複，必要時先嘗試空密碼。

範例：

```powershell
sunpack.exe passwords
sunpack.exe passwords -p 123456
sunpack.exe passwords -P .\passwords.txt -j
```

## config

用法：

```powershell
sunpack.exe config [options] <show|validate>
```

| 子命令 | 說明 |
| --- | --- |
| `show` | 打印目前讀取到的有效設定。 |
| `validate` | 驗證 JSON、欄位值、偵測規則名和規則設定。 |

參數：

| 參數 | 說明 |
| --- | --- |
| `-j` | 以 JSON 輸出結果。 |

範例：

```powershell
sunpack.exe config show
sunpack.exe config validate
sunpack.exe config validate -j
```

## doctor

用法：

```powershell
sunpack.exe doctor [-j]
sunpack.exe doc [-j]
```

`doctor` 唯讀檢查設定、原生擴充、`7z.dll`、SevenZip worker、Windows 通知能力以及已設定的監控根。不存在的監控根報告為警告；命令不會啟動持續監控或真實解壓縮，也不會修改註冊表。存在失敗項時退出碼為 `1`，只有警告或跳過項時退出碼為 `0`。

## version

用法：

```powershell
sunpack.exe version
```

`version` 讀取目前執行的 SunPack 可執行檔案同目錄下的 `VERSION.txt`，並輸出 `version=` 後的版本號。打包後的程式也可直接使用 `sunpack.exe version`。

## Windows 右鍵選單

可在 SunPack GUI 設定中管理目前使用者的檔案總管右鍵選單，也可在程式目錄中執行以下任一命令。

```powershell
.\SunPackGUI.exe --context-menu enable
.\SunPackGUI.exe --context-menu disable
```

命令以無視窗模式執行，程序退出碼為零表示成功。開發建置可用 `--app-root` 和 `--cli` 指定程式目錄和啟動器。

資料夾物件選單提供“解壓縮該目錄下檔案”“輸入密碼解壓縮該目錄下檔案”，目錄空白處選單提供“解壓縮目錄下檔案”“輸入密碼解壓縮目錄下檔案”；兩者還提供監控和取消監控動作。任意檔案的選單提供“解壓縮該檔案”“輸入密碼解壓縮該檔案”，對應命令分別相當於：

```text
extract "%1" -d -pa
extract "%1" -a -d -pa
```

輸出預設落在封存檔旁邊。

`watch add PATH -R` 啟用該根的遞迴發現；可選列省略時使用預設值。同一範圍內的分卷可分布在不同子目錄，獨立根之間不組合。Watch 首輪輸出直接放在該根映射的輸出目錄下；CLI 預設放在封存檔旁，分卷以錨點卷位置為準。Pipeline 輸出子樹由 Watch 排除，使用者後來放入其中的檔案也會忽略。
