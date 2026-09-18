# SunPack

[English](README.md) | **简体中文**

**SunPack 是一款 Windows-only 的自动化压缩包处理工具，支持命令行、Watch 监控和右键菜单调用。**

它支持 7z、RAR、ZIP 等格式，并实验性支持 XZ、BZip2、Gzip、TAR 和 Zstandard，可处理分卷包、自解压包及嵌入在无效数据中的压缩包。

SunPack 通过二进制特征而非文件扩展名识别压缩包，对混乱后缀和不完整文件名具有一定容错能力。

---

## 内容导航

- [安装说明](#安装说明)
- [使用指南](#使用指南)
  - [命令速览](#命令速览)
  - [密码管理](#密码管理)
- [核心能力](#核心能力)
  - [递归处理](#递归处理)
  - [后处理](#后处理)
  - [Watch模式监控系统](#watch模式监控系统)
  - [稳健性](#稳健性)
  - [高并发和速度优化](#高并发和速度优化)
  - [后台低资源占用](#后台低资源占用)
- [配置](#配置)
- [开发与测试](#开发与测试)
  - [开发相关](#开发相关)
  - [架构速览](#架构速览)
  - [测试](#测试)
- [许可证](#许可证)

## 安装说明

### 系统要求

SunPack 仅支持 Windows 10 版本 1607 及更高版本和 Windows 11。

从 [GitHub Releases](https://github.com/Qinjingxue/Sunpack/releases/latest) 下载最新的 `sunpack-windows-<arch>-<version>-setup.exe`

1. 根据系统架构选择安装包：Intel/AMD 64 位 Windows 选择 `x64`，Windows on ARM 选择 `arm64`。
2. 运行安装器并接受 UAC 提权。默认安装到 `C:\Program Files\SunPack`；安装 Watch Broker 服务需要管理员权限。
3. 按需选择安装向导中的附加项：
   - 将安装目录加入本机 `PATH`。完成安装后请重新打开 PowerShell。
   - 注册资源管理器中的文件夹、文件夹背景右键菜单。
   - 随 Windows 启动 SunPack Watch（默认不启用）。

---

## 使用指南

### 命令速览

| 命令        | 说明                                         |
| ----------- | -------------------------------------------- |
| `extract`   | 解压文件                                     |
| `watch`     | 监控目录，发现压缩文件后自动解压             |
| `scan`      | 扫描发现目录下压缩包，可用于识别归档         |
| `inspect`   | 输出详细检测数据，调试命令，支持json诊断输出 |
| `passwords` | 查看本次会参与尝试的密码列表。               |
| `config`    | 查看或校验当前有效配置                       |
| `doctor`    | 非破坏性检查安装状态和运行环境               |

> 详细参数见 [CLI 参数说明](docs/zh-CN/cli_parameters.md)。

### 密码管理

Sunpack为达到最大方便性，在使用时会尝试从各处获取密码，高速尝试所有候选密码，在上千候选密码下几乎无感速度，自动找到正确密码并使用，使用的密码来源有：

- 内置密码文件：每次解压均使用，可在watch模式下使用托盘右键菜单打开修改，安装版位于%ProgramData%\SunPack\builtin_passwords.txt。其中watch模式会自动收集剪贴板历史记录写入该文件，上限配置默认30条
- 用户输入：右键菜单，CLI调出的交互输入密码模式的输入
- 剪贴板：解压前自动读取剪贴板文本作为密码
- 目录下的密码记录文件：自动寻找目录下的.sunpack-passwords.txt，读取每行作为一个密码，watch模式会自动创建

---

## 核心能力

### 识别能力

- 通过文件二进制数据识别潜在的压缩文件，支持伪装性嵌入载体文件，分卷文件等

### 递归处理

- 默认递归寻找嵌套压缩包，即在解压成功后的文件夹下寻找是否有明显的需要进一步解压的压缩包并进行递归处理，该算法经过优化，大部分情况下不会误解压不应进一步解压的文件

### 后处理

- 自动在解压成功后压平无意义嵌套单子目录，只保留顶层文件夹，并将原压缩文件移入回收站或者直接删除（配置："archive_cleanup_mode": "r"调整，默认移入回收站），如果处理出错会自动清理错误输出并报错

### Watch模式监控系统

- watch监控系统基于精心设计的识别算法，监控并处理压缩文件，能够迅速监控并识别对应目录新增的压缩文件，不处理非压缩文件
- 能够识别缺失分卷或密码的场景，并在密码来源或者分卷变化后自动重试。进行处理时使用windows通知来显示进度
- 每个监控目录可以配置独立的输出根目录，具体命令和持久化格式见 [CLI 参数说明](docs/zh-CN/cli_parameters.md)。

### 稳健性和WAL崩溃恢复

- 在磁盘空间不足时自动暂停解压任务，并能够自动在磁盘空间充足后继续解压，无需手动重试
- 拥有文件验证系统，允许部分损坏文件解压出部分可用文件，而不是一次性失败，完全失败时也能自动清理损坏文件，不会残留需手动清理的遗留文件
- 采用类似数据库的WAL思想，解压处理过程中意外断电或进程崩溃不会留下半成品或损坏状态，程序能正确处理并在恢复后完成任务
- 测试体系拥有丰富的复杂案例，保证程序处理的正确性

### 高并发和速度优化

- 一次性可并发处理大量归档文件，且有一套并发算法来合理分配并发，在多文件解压场景下无需手动单独解压，将文件放入一个目录内即可自动迅速完成解压
- 高性能计算和IO部分使用Rust和C++原生代码处理，且使用overlapped IO，重叠7z解压时的读取，计算和输出部分，拥有较好的资源利用能力，且输出针对机械，NVMe硬盘有区分优化，在跨盘写入时是直写而没有搬运过程
- 针对各种场景有丰富benchmark用例，针对benchmark优化接近可维护性上限

### 后台低资源占用

- 缓存生命周期管理完善，自动在处理文件后释放无用缓存，所有组件典型后台空闲占据活跃工作集内存低于20MB
- 系统空闲时完全事件通知，后台空闲无轮询检测占用CPU

---

## 配置

主配置文件是 `sunpack_config.json`，另有高级配置`sunpack_advanced_config.json`

主配置文件优先覆盖高级配置相同字段配置，高级配置可手动将字段移至主配置

配置校验命令：

```powershell
python sunpack.py config validate
```

完整配置说明见 [配置文件说明](docs/zh-CN/configuration.md)。

---

## 开发与测试

### 开发相关

准备开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

构建项目：

```powershell
.\scripts\build_windows.ps1
```

开发环境和构建说明见 [文档](docs/zh-CN/development_setup.md)。
开发边界见文档 [文档](docs/zh-CN/development_boundaries.md)

### 架构速览

```text
app/config
  -> coordinator
     filesystem->relations-> detection -> extraction -> verification
     -> postprocess
```

### 测试

安装测试依赖并运行默认测试：

```powershell
uv sync --locked --extra test
uv run --locked pytest
```

验收测试：

```powershell
.\run_acceptance_tests.ps1
```

---

## 许可证

SunPack 源代码采用 MIT 许可证，详见 [LICENSE](LICENSE)

发布的软件包中可能包含第三方组件，包括 7-Zip。此类第三方组件仍分别受其各自许可证约束，相关许可证与声明可参见 [licenses/](licenses/) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

随 7-Zip 一并提供的 GNU LGPL 2.1 完整许可证文本可在 [licenses/LGPL-2.1.txt](licenses/LGPL-2.1.txt) 中查看
