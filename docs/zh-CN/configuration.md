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
| `filesystem.directory_scan_mode` | `"-"` 只扫描所选目录下的文件；`"*"` 连同子目录扫描。 |
| `extraction.content_requirement` | `"complete"` 要求完整结果；`"allow_partial"` 接受部分恢复结果。 |
| `watch.out_dir` | 未单独指定输出路径的 Watch 根目录所用的默认输出目录；`"."` 表示输入目录旁。 |

例如，在主配置中加入以下字段，可保留原归档并扫描子目录：

```json
{
  "post_extract": {"archive_cleanup_mode": "k"},
  "filesystem": {"directory_scan_mode": "*"}
}
```

CLI 的 `--recur`、`--cleanup` 和 `--out-dir` 等参数可为单次命令指定解压行为，详见 [CLI 参数说明](cli_parameters.md)。

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

## Watch 与密码

使用 `python sunpack.py watch add C:\Downloads` 添加监控目录，附加 `-o E:\Output` 可指定输出目录；未指定时使用 `watch.out_dir`。`watch list` 可查看目录。Watch 只监控每个根目录下的直接文件，不递归监控子目录。

在归档旁放置 `sunpack-passwords.txt`，每行一个密码。将 `passwords.directory_passwords_enabled` 设为 `false` 可停止读取该文件；将 `watch.directory_password_file_auto_create` 设为 `false` 可停止 Watch 自动创建该文件。CLI 也可用 `-p` 或 `--pw-file` 提供密码。

其他较少使用的设置可查看 `sunpack_advanced_config.json` 和 `config show`。`SUNPACK_CONFIG_OVERRIDES` 接受内联 JSON 对象或 JSON 文件路径，用于临时覆盖配置。
