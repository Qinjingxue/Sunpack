# 配置指南

[English](../configuration.md) | **简体中文**

日常设置请修改 `sunpack_config.json`。源码运行时使用项目根目录中的文件；安装版使用 `%ProgramData%\SunPack\sunpack_config.json`。`sunpack_advanced_config.json` 提供其余默认值，只需把想修改的字段写进主配置。

对象按字段合并，`filesystem.scan_filters` 按 `name` 合并，其余数组整体覆盖。Watch 会自动重新加载配置变更。


修改后校验并查看最终配置：

```powershell
python sunpack.py config validate
python sunpack.py config show
```

安装版请将 `python sunpack.py` 换成 `sunpack.exe`。

## 常用设置

| 配置项 | 如何设置 |
| --- | --- |
| `cli.language` | `zh` 为中文，`en` 为英文。 |
| `recursive_extract` | `"*"` 持续处理嵌套归档；正整数指定轮数；`"?"` 每轮后询问。 |
| `recursive_authorization.enabled` | `true` 启用嵌套归档筛选策略；`false` 跳过该策略。 |
| `post_extract.archive_cleanup_mode` | 成功后 `"r"` 移入回收站、`"k"` 保留、`"d"` 删除原归档。 |
| `post_extract.flatten_single_directory` | `true` 时提升唯一顶层输出目录中的内容。 |
| `extraction.content_requirement` | `"complete"` 要求完整结果；`"allow_partial"` 接受部分恢复结果。 |

例如，在主配置中加入以下字段，可保留原归档并扫描子目录：

```json
{
  "post_extract": {"archive_cleanup_mode": "k"}
}
```

CLI 的 `--recur`、`--cleanup` 和 `--out-dir` 等参数可为单次命令指定解压行为，详见 [CLI 参数说明](cli_parameters.md)。

目录发现默认只扫描当前层；`scan`、`inspect`、`extract` 使用 `--recursive` 发现子目录，嵌套解压仍由 `--recur` 控制。1.3.0 起保留配置升级入口和原子提交、失败恢复框架，目前没有迁移规则，不会自动重写配置。

## 扫描过滤

将 `filesystem.scan_filters_enabled` 设为 `false` 可关闭全部扫描过滤器。只修改一个过滤器时，在 `filesystem.scan_filters` 中按 `name` 添加条目：

```json
{
  "filesystem": {
    "scan_filters": [
      {"name": "size_range", "enabled": false}
    ]
  }
}
```

可用过滤器包括 `blacklist`（黑名单）、`whitelist`（白名单）、`size_range` 和 `mtime_range`。在 `sunpack_config.json` 中修改其字段；随程序提供的 `sunpack_advanced_config.json` 可作为格式示例。按扩展名过滤可能漏掉伪装扩展名的归档。

黑白名单提供 `paths`（路径）、`files`（文件名）、`extensions`（扩展名）和 `full_names`（文件名+扩展名）。四个列表均使用对象记录，例如：

```json
{
  "name": "blacklist",
  "enabled": true,
  "paths": [{"value": ".git", "regex": false}],
  "files": [{"value": "报告*", "regex": false}],
  "extensions": [{"value": "zip", "regex": false}],
  "full_names": [
    {"value": "报告[最终版]+.zip", "regex": false},
    {"value": "\\.(?:tmp|log|bak)\\z", "regex": true}
  ]
}
```

每项独立设置 `regex`：关闭时仅 `*` 和 `?` 是通配符，分别匹配任意数量字符和一个 Unicode 字符，其余符号按字面匹配；普通项完整匹配所选内容。路径通配符不跨 `/`，连续星号也不表示递归。开启时使用 Rust regex 完整支持的语法（不含前后查找、反向引用），在所选内容中搜索。默认不区分大小写，保留 Unicode；正则可用内联标志覆盖大小写行为。

文件名按最后一个点号分割：`bundle.part01.rar.jpg` 的文件名是 `bundle.part01.rar`，扩展名是 `jpg`，文件名+扩展名是完整的 `bundle.part01.rar.jpg`。扩展名规则不带前导点号。没有点号时文件名保持完整，扩展名不存在，不参与扩展名匹配；末尾点号表示空扩展名；`.zip` 的文件名为空、扩展名为 `zip`。三个名称列表只作用于文件。压缩包仍按内容识别，伪装扩展名和分卷的识别链路不变。

普通路径单独名称匹配任意层级的组件，含 `/` 或 `\` 的路径相对扫描根目录。正则路径搜索统一使用 `/` 分隔的相对路径，表达式本身不会被改写。目录命中后包含子树；例如 `\Adownloads\z` 选择根目录下的 downloads 目录及其后代。根目录本身不被剪枝。正则未锚定时也可能匹配更深的目录，白名单会保留可能到达匹配项的父目录。同一列表使用 OR，黑名单任一字段命中即排除，白名单各非空字段同时满足；空列表不限制。

GUI 输入框旁的“使用正则表达式”复选框设置当前记录，默认关闭；点击 Tag 编辑已有记录，蓝色 Tag 表示正则。输入后按 Enter 提交，校验失败保留草稿并保持磁盘配置不变。GUI 中正则输入一个反斜杠即可，JSON 转义由保存流程处理。

安装器只迁移已发布的 v1.3.4 配置，不兼容中间未打 Tag 的开发版格式。旧完整文件名进入 `full_names`，旧扩展名进入 `extensions`，白名单二者仍在同一个模块内同时满足。目录剪枝合并到开关状态相同的黑名单中；旧路径 Glob 保留按路径组件边界匹配的范围，必要时转为正则记录。旧白名单的独立路径条件仍按 AND 生效。迁移可重复运行，运行时仅使用当前模型。

大小上下限为 0 至 18446744073709551615 的整数字节，两端包含；上下限相等表示精确匹配该大小。时间使用 `YYYY-MM-DDTHH:mmZ` 格式的 UTC 分钟字符串，开始包含、结束不包含。`null` 表示该侧无限制；覆盖默认配置时请显式填写两个边界。例如：

```json
{
  "filesystem": {
    "scan_filters": [
      {"name": "size_range", "enabled": true, "min_bytes": 1, "max_bytes": null},
      {"name": "mtime_range", "enabled": true, "start_utc": "2024-01-01T00:00Z", "end_utc": "2027-01-01T00:00Z"}
    ]
  }
}
```

GUI 按 Windows 本地时区编辑时间，保存时转成 UTC。大小单位支持小数并精确取整到字节。不接受比较表达式、历史别名字段、秒或小数秒时间戳，也不提供运行时配置迁移。

## Watch 与密码

监控目录保存在 `sunpack_watch_roots.txt`，通过 GUI 或 `watch add/remove` 管理；监控启停通过 GUI 或 `watch start/stop` 控制。已移除无效的 `watch.enabled`、`watch.roots`、`watch.max_folders` 和 `performance.worker.priority_aging_quantum`。

监控输入目录仅支持 NTFS。后端启动或重载配置时，会自动从监控列表移除确认位于非 NTFS 文件系统的路径，并按 `cli.language` 弹出经典 Windows 错误窗口，列出路径、文件系统和已移除说明。无需等待弹窗确认即可继续监控其余目录；如果列表已空，服务仍可正常启动并等待添加目录。此操作不会删除目录或文件，暂时离线的路径不会因此被移除。

分析只识别当前层格式。GZIP、BZIP2、XZ、Zstandard、LZ4 先解开外层流，产出的 TAR 再由正常递归流程识别和解压；不提前识别复合格式。原 `tar_*` 分析模块及全部 `max_probe_bytes` 配置已删除。普通 TAR 分析仅从偏移 0 开始，其他位置的 TAR 候选只来自统一的 embedded 扫描器。`watch.state_dir` 留空仍表示默认状态目录；`memory_reserve_bytes` 和 `job_buffer_budget_bytes` 为 0 时仍使用自动值或工作进程默认值。`watch.event_log_retention_days` 控制 CLI 与监控共用的任务历史和事件保留天数。

使用 `python sunpack.py watch add C:\Downloads` 添加监控目录，附加 `-o E:\Output` 可指定输出目录；留空时解压到各归档所在文件夹。`watch list` 可查看目录。加 `--recursive` 可递归监控子目录，每个监控根独立保存该标志。

持久化密码只来自 `builtin_passwords.json`，包括其中的 `clipboard_history`。在 `passwords` 中填写 `value`，可用 `scopes` 指定一个或多个绝对目录，对其子目录也生效；省略 `scopes` 即全局生效。运行时来源包括显式输入（`-p`、`--pw-file` 或密码提示框）与当前剪贴板。

```json
{
  "passwords": [
    {"value": "全局密码"},
    {"value": "目录密码", "scopes": ["D:/Downloads", "E:/Archives"]}
  ],
  "clipboard_history": []
}
```

其他较少使用的设置可查看 `sunpack_advanced_config.json` 和 `config show`。`SUNPACK_CONFIG_OVERRIDES` 接受内联 JSON 对象或 JSON 文件路径，用于临时覆盖配置。
