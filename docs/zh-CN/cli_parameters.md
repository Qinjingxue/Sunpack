# CLI 参数说明

[English](../cli_parameters.md) | **简体中文**

入口脚本：

```powershell
python sunpack.py <command> [options] [paths...]
```

打包后的 Windows 程序通常可直接使用：

```powershell
sunpack.exe <command> [options] [paths...]
```

顶层命令：

| 命令 | 作用 |
| --- | --- |
| `extract` | 扫描、识别、解压、校验、后处理和清理。 |
| `watch` | 监控目录，文件稳定后自动处理。 |
| `scan` | 只扫描并列出可解压任务，不修改文件。 |
| `inspect` | 输出检测和结构分析细节，不修改文件。 |
| `passwords` | 查看当前命令可用的密码来源汇总。 |
| `config` | 查看或校验合并后的有效配置。 |
| `doctor` | 只读检查配置和运行环境。 |

## 通用输出参数

这些参数用于 `extract`、`scan`、`inspect`：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 格式输出结果，适合脚本调用。 |
| `-q`, `--quiet` | 减少终端输出。 |
| `-v`, `--verbose` | 输出更多检测和诊断细节。 |
| `--pause` | 命令结束后等待按键退出。 |
| `--no-pause` | 命令结束后不暂停。 |

`passwords` 只支持 `--json` 以及密码输入参数；`config` 支持 `--json` 和 `--quiet`。JSON 结果使用统一外层字段：`command`、`inputs`、`summary`、`errors`、`items`、`tasks`、`logs`；具体命令按语义填充 `items` 或 `tasks`。

## extract

用法：

```powershell
python sunpack.py extract [options] <paths...>
```

`paths` 可以是一个或多个文件、目录。目录按配置扫描并生成解压任务。

参数：

| 参数 | 说明 |
| --- | --- |
| `-p PASSWORD`, `--password PASSWORD` | 提供一个解压密码，可重复传入。 |
| `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `--ask-pw` | 在终端交互输入密码，空行结束。 |
| `--no-builtin-pw` | 禁用内置密码表。 |
| `--no-dir-pw` | 禁用归档同目录的 `.sunpack-passwords.txt`。 |
| `--deep-detect` | 对检测未解决的候选启用完整嵌入扫描。 |
| `--recur VALUE` | 覆盖嵌套解压轮数，接受正整数、`*` 或 `?`。 |
| `--cleanup VALUE` | 覆盖成功后的原归档处理：`d` 删除，`r` 回收站，`k` 保留。 |
| `-o OUTPUT_DIR`, `--out-dir OUTPUT_DIR` | 指定输出根目录；相对路径按当前命令目录解析。 |
| `--flatten` | 解压后提升单一顶层目录的内容。 |
| `--no-flatten` | 保留解压目录结构。 |
| `--write-manifest` | 把解压进度清单写入输出目录。 |
| `--allow-partial`, `--ap` | 允许把部分恢复结果作为可接受结果。 |
| `--direct-file` | 将每个输入路径直接作为归档尝试，跳过目录扫描和自动候选发现。 |

`--out-dir` 指定后，结果落在“输出根 / 输入路径相对公共根的部分 / 归档名”下；未指定时落在归档旁边。嵌套归档在输出根内生成时，子归档仍使用自身所在位置计算输出。

`--recur` 的取值：

- `1`、`2`、`3` 等正整数：固定递归轮数。
- `*`：只要每轮仍产生新的可处理嵌套归档，就持续递归。
- `?`：每轮产生新的可处理嵌套归档后询问是否继续。

示例：

```powershell
python sunpack.py extract D:\Downloads
python sunpack.py extract D:\A.7z -p 123456 -p secret
python sunpack.py extract D:\Archives --pw-file .\passwords.txt --cleanup r
python sunpack.py extract D:\Nested --recur * --no-flatten
python sunpack.py extract --direct-file D:\MaybeArchive.bin
python sunpack.py extract D:\Archives -o E:\Unpacked
```

退出码：

- `0`：所有任务均完整成功。
- `1`：至少一个任务失败。
- `2`：参数、路径或配置错误。
- `3`：运行时异常。
- `4`：没有失败任务，但至少一个任务只有部分成功。

## scan

用法：

```powershell
python sunpack.py scan [options] <paths...>
```

`scan` 输出识别到的解压任务、分卷关系、检测扩展名、判定和命中规则，不会解压或清理文件。

`--deep-detect` 会对符合条件但普通检测未解决的候选执行完整嵌入扫描。目录范围受 `filesystem.directory_scan_mode`、`filesystem.scan_filters_enabled` 和 `filesystem.scan_filters` 影响。

示例：

```powershell
python sunpack.py scan D:\Downloads
python sunpack.py scan D:\Downloads --deep-detect --json
python sunpack.py scan D:\Downloads -v
```

## inspect

用法：

```powershell
python sunpack.py inspect [options] <paths...>
```

`inspect` 是只读检测诊断命令，会列出候选文件的判定结果、处理阶段、停止原因和事实错误。

参数：

| 参数 | 说明 |
| --- | --- |
| `--archives-only` | 只显示最终判定为可解压的项目。 |
| `--analyze` | 为可解压或待确认候选附加格式、片段、损坏标记和候选摘要。 |
| `--deep-detect` | 对检测未解决的候选启用完整嵌入扫描。 |

`-v` 会额外打印有效配置、命中规则、评分细节和事实错误；JSON 输出保留对应结构化字段。

示例：

```powershell
python sunpack.py inspect D:\Downloads
python sunpack.py inspect D:\Downloads --archives-only --analyze
python sunpack.py inspect D:\Downloads --deep-detect --json
python sunpack.py inspect D:\Downloads -v
```

## watch

用法：

```powershell
python sunpack.py watch <add|remove|list|start|stop|reload|status|startup> [options]
```

监控根目录保存在程序资源目录下的 `sunpack_watch_roots.txt`。每行可以只写输入目录，也可以用 `|` 指定输出根：

```text
C:\Downloads
E:\Archives | E:\Output
F:\Incoming | .
```

只写输入目录时使用 `watch.out_dir`；相对输出路径按该输入目录解析并持久化为绝对路径。输出根可以跨盘。`watch` 只观察每个根目录的直接文件，不递归监听子目录；输入根需要位于 NTFS 卷且有可读取的 USN Journal。

子命令和参数：

| 子命令 | 参数 | 说明 |
| --- | --- | --- |
| `start` | `--once` | 执行一次监控扫描后退出。 |
| `start` | `--no-tray` | 持续运行时关闭托盘入口。 |
| `start` | `--initial-scan` | 启动时处理已有文件。 |
| `add PATH...` | `-o/--out-dir DIR` | 添加监控根；只能同时添加一个路径。 |
| `add PATH...` | `--start` | 添加后启动持续监控。 |
| `add PATH...` | `--initial-scan` | 添加后对新根执行初始扫描。 |
| `remove PATH...` | — | 按输入目录移除监控根，并清理该根的同目录密码文件。 |
| `list` | — | 列出持久化的输入目录。 |
| `reload` | — | 重新读取配置和监控根。 |
| `stop` | — | 停止持续监控。 |
| `status` | — | 显示运行状态、待处理数量、错误和根目录。 |
| `startup enable\|disable\|status` | — | 管理机器级登录启动项。 |

`start` 会持续运行直到收到停止请求；`start --once` 完成一次当前调度后退出。文件写入、移动或修改会触发活跃周期，文件准备好后按配置的静默策略提交处理。新分卷到达或密码来源变化会重新激活受影响任务。

`add` 的 `-o/--out-dir` 只能和一个输入目录一起使用。重复添加同一输入目录不会改变已有输出映射；先 `remove` 再 `add` 才能更新映射。不同监控根的输出根不能互为严格的祖先和子目录，相同输出根可以共享。

## passwords

用法：

```powershell
python sunpack.py passwords [options]
```

参数：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 输出密码来源汇总。 |
| `-p PASSWORD`, `--password PASSWORD` | 提供密码，可重复传入。 |
| `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `--ask-pw` | 在终端交互输入密码。 |
| `--no-builtin-pw` | 不使用内置密码表。 |
| `--no-dir-pw` | 该命令没有目标归档，不会读取同目录密码文件；在 `extract` 中用于关闭同目录密码。 |

`passwords` 没有归档路径，因此输出命令行输入、最近成功密码、剪贴板密码和内置密码的汇总；它不会为某个目录加载 `.sunpack-passwords.txt`。归档解压时的候选顺序是“最近成功密码 → 同目录密码 → CLI 参数和密码文件 → 剪贴板 → 内置密码”，重复项会去重，必要时会先尝试空密码。

示例：

```powershell
python sunpack.py passwords
python sunpack.py passwords -p 123456 --no-builtin-pw
python sunpack.py passwords --pw-file .\passwords.txt --json
```

## config

用法：

```powershell
python sunpack.py config [options] <show|validate>
```

| 子命令 | 说明 |
| --- | --- |
| `show` | 打印当前读取到的有效配置。 |
| `validate` | 校验 JSON、字段值、检测规则名和规则配置。 |

参数：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 输出结果。 |
| `-q`, `--quiet` | 减少普通文本输出。 |

示例：

```powershell
python sunpack.py config show
python sunpack.py config validate
python sunpack.py config validate --json
```

## doctor

用法：

```powershell
python sunpack.py doctor [--json] [--quiet]
```

`doctor` 只读检查配置、原生扩展、`7z.dll`、SevenZip worker、Windows 通知能力以及已配置的监控根。不存在的监控根报告为警告；命令不会启动持续监控或真实解压，也不会修改注册表。存在失败项时退出码为 `1`，只有警告或跳过项时退出码为 `0`。

## Windows 右键菜单

机器级右键菜单脚本（需要管理员权限的终端）：

```powershell
.\scripts\register_context_menu.ps1
.\scripts\unregister_context_menu.ps1
```

发行包内的注册脚本使用脚本父目录中的 `sunpack.exe`。从源码树运行时，脚本会识别唯一的 `dist/sunpack-*/sunpack.exe`；存在多个构建产物时使用 `-AppPath` 明确指定。找不到打包程序时使用 `python sunpack.py`。

文件夹和目录空白处菜单提供解压、监控和取消监控动作；任意文件菜单提供直接解压和交互输入密码解压，分别相当于：

```text
extract "%1" --pause
extract "%1" --ask-pw --pause
```

输出默认落在归档旁边。
