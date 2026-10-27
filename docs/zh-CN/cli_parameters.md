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
| `extract`, `x` | 扫描、识别、解压、校验、后处理和清理。 |
| `watch`, `w` | 监控目录，文件稳定后自动处理。 |
| `scan`, `s` | 只扫描并列出可解压任务，不修改文件。 |
| `inspect`, `i` | 输出检测和结构分析细节，不修改文件。 |
| `passwords`, `pw` | 查看当前命令可用的密码来源汇总。 |
| `config`, `cfg` | 查看或校验合并后的有效配置。 |
| `doctor`, `d` | 只读检查配置和运行环境。 |
| `version`, `ver` | 输出当前安装的 SunPack 版本号。 |

完整名称和简写都是正式语法；只接受明确列出的简写，不接受任意截断长参数。简写输出的 JSON `command` 仍使用完整命令名。`-m` 接受 `background`/`b`、`normal`/`n`、`high`/`h`。`-p` 是密码，`-P` 是密码文件；`-f` 启用扁平化，`-F` 关闭扁平化。带值参数推荐分开写，例如 `-r 3`、`-c r`。

常用简写示例：

```powershell
sunpack x D:\Downloads -o E:\Output -r "*" -c r -d -P D:\pw.txt -k --no-pause
sunpack i D:\Downloads --analysis -d -j
sunpack w add D:\Downloads -o E:\Output -s -i -d
sunpack w ls
sunpack w st
```

## 通用输出参数

这些参数用于 `extract`、`scan`、`inspect`：

| 参数 | 说明 |
| --- | --- |
| `--recursive` | 递归发现输入子目录；与嵌套解压的 `--recur` 独立。 |
| `-j`, `--json` | 以 JSON 格式输出结果，适合脚本调用。 |
| `-q`, `--quiet` | 减少终端输出。 |
| `-v`, `--verbose` | 输出更多检测和诊断细节。 |
| `--pause` | 命令结束后等待按键退出。 |
| `--no-pause` | 命令结束后不暂停。 |
| `-m MODE`, `--process-mode MODE` | 临时覆盖本次工作负载使用的共享 RuntimeHost/native-worker 进程模式；默认 `high`。 |

对于 `extract`、`scan`、`inspect`，process-mode override 在命令结束后继续有效，直到共享 Runtime 到达现有 Watch 空闲维护时机（`watch.runtime_cache_cleanup_idle_seconds`），随后恢复 `runtime.process_mode`。

`passwords` 只支持 `--json` 以及密码输入参数；`config` 支持 `--json` 和 `--quiet`。JSON 结果使用统一外层字段：`command`、`inputs`、`summary`、`errors`、`items`、`tasks`、`logs`；具体命令按语义填充 `items` 或 `tasks`。

`extract`、`scan` 和 `inspect` 的普通文本写入 stdout，错误写入 stderr。`[扫描错误]` 表示文件系统扫描失败，`[解压失败]` 表示归档处理失败；`[扫描不完整]` 表示部分路径无法读取，发现结果可能不完整，其余可读取的输入仍会继续处理。`--quiet` 隐藏进度，但保留错误和后处理警告；`--json` 输出 JSON 结果，不输出这些文本消息。

JSON 的 `summary.scan_error_count` 统计文件系统扫描错误，包括省略了单独详情的错误。每份报告最多保留 100 条文件系统扫描诊断记录，另加 1 条总省略摘要；单个目录仍适用原有的 20 条详情上限。超出报告预算后只累计省略数量，不再保留每条错误的路径或身份。归档任务结果独立于这项诊断预算保留。

`extract` 的 `summary.failed_count` 和各轮处理的 `failed_count` 统计归档处理失败；`input_error_count` 单独统计无效输入，例如向 `--direct-file` 传入目录，文本中显示为 `[输入错误]`。各轮处理另有 `scan_error_count` 和 `input_error_count`。受预算限制的文件系统诊断详情集中保存在 `summary.scan_failures`，各轮的 `failures` 保存归档失败和输入错误。分类依据结构化错误类别和目标结果。所有错误类别均保留在 `errors` 中，并使退出码非零，即使其他归档处理成功也是如此。

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
| `-P PASSWORD_FILE`, `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `-a`, `--ask-pw` | 在终端交互输入密码，空行结束。 |
| `--no-builtin-pw`, `--no-bpw` | 禁用 JSON 持久化密码及其中的剪贴板历史。 |
| `-d`, `--deep-detect` | 对检测未解决的候选启用完整嵌入扫描，并关闭本次请求的全部 filesystem 扫描过滤模块。 |
| `-r VALUE`, `--recur VALUE` | 覆盖嵌套解压轮数，接受正整数、`*` 或 `?`。 |
| `-c VALUE`, `--cleanup VALUE` | 覆盖成功后的原归档处理：`d` 删除，`r` 回收站，`k` 保留。 |
| `-o OUTPUT_DIR`, `--out-dir OUTPUT_DIR` | 指定输出根目录；相对路径按当前命令目录解析。 |
| `-f`, `--flatten` | 解压后提升单一顶层目录的内容。 |
| `-F`, `--no-flatten` | 保留解压目录结构。 |
| `-k`, `--allow-partial`, `--ap` | 允许把部分恢复结果作为可接受结果。 |
| `--direct-file`, `--direct` | 将每个输入路径直接作为归档尝试，跳过目录扫描和自动候选发现。 |

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

`--deep-detect` 会对普通检测未解决的候选执行完整嵌入扫描，并关闭本次请求的全部 filesystem 扫描过滤模块，包括嵌套输出扫描。目录范围由 `--recursive` 决定。每次 CLI 请求只按自身参数决定是否启用 deep；即使共享 runtime 正在深度监控同一输入目录，也不会影响 CLI 请求。

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
| `--archives-only`, `--archives` | 只显示最终判定为可解压的项目。 |
| `--analyze`, `--analysis` | 为可解压或待确认候选附加格式、片段、损坏标记和候选摘要。 |
| `-d`, `--deep-detect` | 对检测未解决的候选启用完整嵌入扫描，并关闭本次请求的全部 filesystem 扫描过滤模块。 |

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

监控根目录保存在程序资源目录下的 `sunpack_watch_roots.txt`。格式为 `输入目录 | 输出根 | deep_detect | initial_scanned | recursive`，后四列可省略：

```text
C:\Downloads
E:\Archives | E:\Output
F:\Incoming | . | true
G:\Incoming | | true
```

只写输入目录时输出列保持为空，归档会解压到归档所在文件夹；使用 `--out-dir` 时，相对输出路径按该输入目录解析并持久化为绝对路径。输出根可以跨盘。每个根使用独立的 `recursive` 标志，默认 `false`；输入根需要位于 NTFS 卷且有可读取的 USN Journal。

`deep_detect` 接受 `true` 或 `false`，省略或留空时默认为 `false`。模式绑定输入目录；多个输入目录可共用输出根，并分别采用不同模式。嵌套解压、密码重试和崩溃恢复均保留原始输入目录，按该目录的配置执行。启用 deep 时，该目录请求的全部 filesystem 扫描过滤模块失效。修改此列会触发配置重载，也可执行 `watch reload` 应用修改。

`initial_scanned` 表示是否完成首次候选扫描，省略或留空时为 `false`。启动和运行中重载会自动扫描值为 `false` 的目录，候选入队后回写 `true`；无需等待解压成功。新增目录或修改输入路径时重置为 `false`，仅修改输出根或 deep 模式时保留。已扫描目录的停机变化继续通过 USN 恢复。仅修改扫描标记、目录顺序、注释或等价路径写法不会重启调度器。

子命令和参数：

| 子命令 | 参数 | 说明 |
| --- | --- | --- |
| `start` | `--once` | 执行一次监控扫描后退出。 |
| `start` | `--no-tray` | 持续运行时关闭托盘入口。 |
| `add PATH...` | `-o/--out-dir DIR` | 添加监控根；只能同时添加一个路径。 |
| `add PATH...` | `-s`, `--start` | 添加后启动持续监控。 |
| `add PATH...` | `-d`, `--deep-detect` | 将各输入目录的 `deep_detect` 写为 `true`；已登记目录也会更新。 |
| `remove PATH...`, `rm PATH...` | — | 按输入目录移除监控根。 |
| `list`, `ls` | — | 列出持久化的输入目录。 |
| `reload` | — | 重新读取配置和监控根。 |
| `stop` | — | 停止持续监控。 |
| `status`, `st` | — | 显示运行状态、待处理数量、错误和根目录。 |
| `startup enable\|disable\|status` | — | 管理当前用户登录启动项。 |

`start` 会持续运行直到收到停止请求；`start --once` 完成一次当前调度后退出。文件写入、移动或修改会触发活跃周期，文件准备好后按配置的静默策略提交处理。新分卷到达或密码来源变化会重新激活受影响任务。

`add` 的 `-o/--out-dir` 只能和一个输入目录一起使用。重复添加同一输入目录不会改变已有输出映射；先 `remove` 再 `add` 才能更新映射。不同监控根的输出根不能互为严格的祖先和子目录，相同输出根可以共享。

新增目录时不传 `--deep-detect`，默认不启用 deep。重复添加已登记目录时，不传该参数会保留已有模式；关闭 deep 可将第三列改为 `false` 或留空。

```powershell
sunpack.exe watch add D:\Downloads --deep-detect --start
```

目录对象的解压菜单为“解压该目录下文件”“输入密码解压该目录下文件”；目录空白处的解压菜单为“解压目录下文件”“输入密码解压目录下文件”。两种目录菜单还提供“监控此目录”“取消监控此目录”，这些入口不附加 `--deep-detect`。文件对象的两个解压入口默认启用 `--deep-detect`。重新运行 `scripts/register_context_menu.ps1` 会重建菜单并移除过时入口。

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
| `-P PASSWORD_FILE`, `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `-a`, `--ask-pw` | 在终端交互输入密码。 |
| `--no-builtin-pw`, `--no-bpw` | 不使用 JSON 持久化密码及其中的剪贴板历史。 |

`passwords` 没有归档路径，因此仅汇总全局候选。归档解压时，最近成功的有效密码优先，其后依次为 JSON 中匹配作用域的密码、CLI 输入、当前剪贴板、JSON 全局密码及剪贴板历史。重复项会去重，必要时先尝试空密码。

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
python sunpack.py d [-j] [-q]
```

`doctor` 只读检查配置、原生扩展、`7z.dll`、SevenZip worker、Windows 通知能力以及已配置的监控根。不存在的监控根报告为警告；命令不会启动持续监控或真实解压，也不会修改注册表。存在失败项时退出码为 `1`，只有警告或跳过项时退出码为 `0`。

## version

用法：

```powershell
python sunpack.py version
```

`version` 读取当前运行的 SunPack 可执行文件同目录下的 `VERSION.txt`，并输出 `version=` 后的版本号。打包后的程序也可直接使用 `sunpack.exe version`。

## Windows 右键菜单

机器级右键菜单脚本（需要管理员权限的终端）：

```powershell
.\scripts\register_context_menu.ps1
.\scripts\unregister_context_menu.ps1
```

发行包内的注册脚本使用脚本父目录中的 `sunpack.exe`。从源码树运行时，脚本会识别唯一的 `dist/sunpack-*/sunpack.exe`；存在多个构建产物时使用 `-AppPath` 明确指定。找不到打包程序时使用 `python sunpack.py`。

文件夹对象菜单提供“解压该目录下文件”“输入密码解压该目录下文件”，目录空白处菜单提供“解压目录下文件”“输入密码解压目录下文件”；两者还提供监控和取消监控动作。任意文件的菜单提供“解压该文件”“输入密码解压该文件”，对应命令分别相当于：

```text
extract "%1" --deep-detect --pause
extract "%1" --ask-pw --deep-detect --pause
```

输出默认落在归档旁边。

`watch add 目录 --recursive` 启用该根的递归发现；旧的四列或更少列仍为非递归。同一范围内的分卷可分布在不同子目录，独立根之间不组合。Watch 首轮输出直接放在该根映射的输出目录下；CLI 默认放在归档旁，分卷以锚点卷位置为准。Pipeline 输出子树由 Watch 排除，用户后来放入其中的文件也会忽略。
