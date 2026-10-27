# 配置指南

[English](../configuration.md) | **简体中文**

日常设置请修改 `sunpack_config.json`。源码运行时使用项目根目录中的文件；安装版使用 `%ProgramData%\SunPack\sunpack_config.json`。`sunpack_advanced_config.json` 提供其余默认值，只需把想修改的字段写进主配置。

对象按字段合并，`filesystem.scan_filters` 按 `name` 合并，其余数组整体覆盖。Watch 会自动重新加载配置变更。

覆盖安装低于 1.2.0 的版本时，安装器会整体删除程序目录、`%ProgramData%\SunPack` 及配置指定的自定义 Watch 状态目录，再安装全新默认数据。配置、密码、监控目录、日志和状态全部清空。无法识别或缺少版本号时采用相同策略。重装 1.2.0 及以上版本保留数据目录，程序文件和高级默认配置仍会替换。

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
| `watch.out_dir` | 为兼容配置保留的旧字段；监控目录的输出路径留空时，解压到各归档所在文件夹。 |

例如，在主配置中加入以下字段，可保留原归档并扫描子目录：

```json
{
  "post_extract": {"archive_cleanup_mode": "k"}
}
```

CLI 的 `--recur`、`--cleanup` 和 `--out-dir` 等参数可为单次命令指定解压行为，详见 [CLI 参数说明](cli_parameters.md)。


目录发现默认只扫描当前层；`scan`、`inspect`、`extract` 使用 `--recursive` 发现子目录，嵌套解压仍由 `--recur` 控制。升级 1.2.0 及更新版本时，安装器比较新旧高级配置字段，删除废弃字段，并按普通模板补充新增字段；过滤器、分析模块和验证方法按 `name` 更新，保留用户值、模块顺序和未知扩展项。已有权限保持原样。

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

可用过滤器包括 `directory_prune`（跳过目录）、`whitelist`（只包含指定路径、文件名或扩展名）、`blacklist`（排除指定项）、`size_range` 和 `mtime_range`。在 `sunpack_config.json` 中修改其字段；随程序提供的 `sunpack_advanced_config.json` 可作为格式示例。按扩展名过滤可能漏掉伪装扩展名的归档。

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
