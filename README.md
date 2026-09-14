# SunPack

SunPack是一个Windows-only的命令行工具，自动化处理压缩文件
交互模式包含右键菜单调用和命令行交互

主要功能是自动化处理压缩包归档文件，省去繁琐的手动处理流程

主要支持7z，rar，zip格式。xz，bzip2，gzip，tar，zstd格式也有实验性支持，其他格式不支持。支持处理分卷，SFX等各种载体压缩包

Sunpack依靠二进制特征识别压缩包，不依靠后缀，在面对混乱后缀分卷时也采用启发式算法识别，具有一定容错能力（不同格式容错能力不同），也能够处理二进制数据类似于[无效数据][压缩数据][无效数据]的文件

使用方式包含直接使用命令处理文件和使用watch模式后台监控

Sunpack包含四部分，前台命令启动器（sunpack.exe），后台常驻程序（sunpack-runtime.exe），压缩包处理程序（sunpack_sevenzip_worker.exe），NTFS文件系统日志监控服务（sunpack-watch-broker.exe），其中因为安装器需要安装读取NTFS卷级日志的服务，需要管理员权限

Sunpack还提供丰富的自动化配置，适配多种需求，详见配置文件

## 命令速览

| 命令        | 说明                                         |
| ----------- | -------------------------------------------- |
| `extract`   | 解压文件                                     |
| `watch`     | 监控目录，发现压缩文件后自动解压             |
| `scan`      | 扫描发现目录下压缩包，可用于识别归档         |
| `inspect`   | 输出详细检测数据，调试命令，支持json诊断输出 |
| `passwords` | 查看本次会参与尝试的密码列表。               |
| `doctor`    | 只读检查配置和运行环境                       |

详细参数见 [CLI 参数说明](docs/cli_parameters.md)。

## 密码管理

Sunpack为达到最大方便性，在使用时会尝试从各处获取密码，高速尝试所有候选密码，在上千候选密码下几乎无感速度，自动找到正确密码并使用，使用的密码来源有：

- 内置密码文件：每次解压均使用，可在watch模式下使用托盘右键菜单打开修改，位于Appdata/Local/Sunpack/builtin_passwords.txt。其中watch模式会自动收集剪贴板历史记录写入该文件，上限配置默认30条
- 用户输入：右键菜单，CLI调出的交互输入密码模式的输入
- 剪贴板：解压前自动读取剪贴板文本作为密码
- 目录下的密码记录文件：自动寻找目录下的.sunpack-passwords.txt，读取每行作为一个密码，watch模式会自动创建

## 递归处理

Sunpack默认递归寻找嵌套压缩包，即在解压成功后的文件夹下寻找是否有明显的需要进一步解压的压缩包并进行递归处理，该算法经过优化，大部分情况下不会误解压不应进一步解压的文件

## 后处理

Sunpack会自动在解压成功后压平无意义嵌套单子目录，只保留顶层文件夹，并将原压缩文件移入回收站或者直接删除（配置："archive_cleanup_mode": "r"调整，默认移入回收站），如果处理出错会自动清理错误输出并报错

## Watch模式监控系统

Sunpack的watch监控系统基于精心设计的识别算法，监控并处理压缩文件
能够迅速监控并识别对应目录新增的压缩文件，不处理非压缩文件
能够识别缺失分卷或密码的场景，并在密码来源或者分卷变化后自动重试。进行处理时使用windows通知来显示进度
每个监控目录可以配置独立的输出根目录，具体命令和持久化格式见 [CLI 参数说明](docs/cli_parameters.md)。

建议监控下载目录使用

## 稳健性

Sunpack在磁盘空间不足时自动暂停解压任务，并能够自动在磁盘空间充足后继续解压，无需手动重试
Sunpack拥有文件验证系统，允许部分损坏文件解压出部分可用文件，而不是一次性失败，完全失败时也能自动清理损坏文件，不会残留需手动清理的遗留文件
Sunpack测试体系拥有丰富的复杂案例，保证程序处理的正确性

## 高并发和速度优化

Sunpack一次性可并发处理大量归档文件，且有一套并发算法来合理分配并发，在多文件解压场景下无需手动单独解压，将文件放入一个目录内即可自动迅速完成解压
Sunpack高性能计算和IO部分使用Rust和C++原生代码处理，且使用overlapped IO，重叠7z解压时的读取，计算和输出部分，拥有较好的资源利用能力，且输出针对机械，NVMe硬盘有区分优化，在跨盘写入时是直写而没有搬运过程
Sunpack针对各种场景有丰富benchmark用例，针对benchmark优化接近可维护性上限

## 后台低资源占用

Sunpack缓存生命周期管理完善，自动在处理文件后释放无用缓存，所有组件典型后台空闲占据活跃工作集内存低于15MB
Sunpack系统大部分采用事件通知，后台空闲无轮询检测占用CPU

## 配置

主配置文件是 `sunpack_config.json`，另有高级配置`sunpack_advanced_config.json`

主配置文件优先覆盖高级配置相同字段配置，高级配置可手动将字段移至主配置

配置校验命令：

```powershell
python sunpack.py config validate
```

完整配置说明见 [配置文件说明](docs/configuration.md)。

## 开发相关

准备开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

构建项目：

```powershell
.\scripts\build_windows.ps1
```

开发环境和构建说明见 [文档](docs/development_setup.md)。
开发边界见文档 [文档](docs\development_boundaries.md)

## 架构速览

```text
app/config
  -> coordinator
     filesystem->relations-> detection -> extraction -> verification
     -> postprocess
```

## 测试

安装测试依赖并运行默认测试：

```powershell
uv sync --locked --extra test
uv run --locked pytest
```

验收测试：

```powershell
.\run_acceptance_tests.ps1
```
