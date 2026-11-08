## Upgrade warning: installed versions below 1.4.0

**Back up `%ProgramData%\SunPack` and any custom Watch state directory before upgrading. The legacy-data reset is irreversible; deleted recovery tasks and history cannot be recovered by downgrading.**

- The installed numeric base version controls this reset: versions below 1.4.0 are reset, including older preview builds. Versions 1.4.0 and newer do not receive the legacy reset. If existing data is found but the installed version cannot be determined, the destructive reset is refused.
- Current ordinary settings survive. The new ordinary template adds missing fields and removes retired fields. Priority is existing ordinary value (including `false`, `0`, empty values and `null`), then a prior advanced value only for settings promoted to ordinary, then the new default. The old advanced configuration is replaced. Advanced-only fields manually copied into ordinary configuration and unknown extensions are not preserved.
- Watch root paths, output paths, `deep_detect`, `recursive` and comments survive. Every root's `initial_scanned` becomes `false`. **Watch rescans and may process existing archives again**, using your retained extraction and archive-cleanup settings.
- `builtin_passwords.json` is retained, removing blank lines left by the old bug without changing nonblank password contents.
- All other managed data under `%ProgramData%\SunPack` is deleted, including recovery tasks, catalog, task/event history, caches and failure reports. A custom Watch state directory outside managed data loses only known SunPack records; unrelated contents are untouched. **Input archives and extraction outputs outside managed data locations are not deleted by this reset.**
- v1.3.0–v1.3.4 scan filters are converted; v1.3.5's modern shape is retained. Old directory-prune and blacklist rules merge when both are enabled. With mixed enabled states, only the active side survives; both disabled sides merge into a disabled blacklist. Old whitelist path groups still merge as OR, not separate AND conditions. Review your filters after upgrading.

## 升级警告：已安装版本低于 1.4.0

**升级前请备份 `%ProgramData%\SunPack` 及自定义 Watch 状态目录。旧版数据重置不可逆，降级也无法找回已删除的恢复任务和历史。**

- 按已安装版本的数字基础版本判断：低于 1.4.0（包括旧版预览版本）执行重置，1.4.0 及以上不执行这次旧版重置。已有数据但无法确定已安装版本时，拒绝破坏性重置。
- 保留当前普通设置，按新普通模板补新增字段、删除废弃字段。优先级为已有普通值（包括 `false`、`0`、空值和 `null`）、已提升为普通设置的旧高级值、新默认值。高级配置换成新模板；手动复制到普通配置中的纯高级字段和未知扩展不保留。
- 保留 Watch 根目录、输出路径、`deep_detect`、`recursive` 和注释，各根的 `initial_scanned` 重置为 `false`。**Watch 会重新扫描，可能按保留的解压和原包清理设置再次处理已有归档。**
- 保留 `builtin_passwords.json`，清除旧缺陷产生的空白行，不修改任何非空密码内容。
- 删除 `%ProgramData%\SunPack` 下其余托管数据，包括恢复任务、目录索引、任务/事件历史、缓存及失败报告。托管目录以外的自定义 Watch 状态目录仅删除已知 SunPack 记录，不触碰无关内容。**本次重置不会删除托管数据位置之外的输入归档和解压输出。**
- 转换 v1.3.0–v1.3.4 扫描过滤格式，保留 v1.3.5 的现代格式。旧目录剪枝和黑名单都启用时合并；启用状态不同时仅保留启用方；两者都关闭时合并并保持关闭。旧白名单路径组仍合并为 OR，而非独立 AND 条件。升级后请检查过滤规则。
