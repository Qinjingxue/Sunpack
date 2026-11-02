# 7-Zip 26.05 增量同步记录

合入日期：2026-11-02。对比基线：项目提交 `0cfea5a2`、纯净 26.04、
本地 `reference/implementations/7z2605-src/`。沿用
`native/sevenzip_bridge/7z2604-src/` 目录名，避免改变现有构建和资源定位。

## 合入范围

上游共变更 26 个文件，其中 11 个仍在项目裁剪树内。本次仅修改以下 8 个
vendor 文件，其余 469 个文件与项目基线逐文件比较一致（仅统一换行后比较，
不使用文件哈希）。裁剪树仍为 477 个文件、228 个 C/C++ 编译单元。

| 文件 | 合入内容及本地保留项 |
| --- | --- |
| `C/7zVersion.h` | 上游 26.05 版本和发布日期 |
| `CPP/7zip/Archive/HandlerCont.cpp` | 两处 `pos/size` 初始化；保留项目 Ext 注册和提取异常边界 |
| `CPP/7zip/Compress/ShrinkDecoder.cpp` | 上游解码重写，仅清除新增空白行的尾随空格 |
| `CPP/7zip/Compress/ShrinkDecoder.h` | 上游新布局和构造初始化；删除已无实现的旧 `CodeReal` 声明 |
| `CPP/Common/MyString.h` | 两处等价字符串复制循环改写；保留项目其余修改 |
| `DOC/7zip.wxs` | 同步 26.05；修正原来遗留的 26.03 标记 |
| `DOC/readme.txt` | 同步源码版本 |
| `DOC/src-history.txt` | 追加上游版本记录 |

`ZDecoder.cpp/.h` 仍无裁剪树内的实际消费者；`MyVector.h` 新方法用于未保留的
Mach-O 路径，继续保留项目原实现。裁剪外的 Z/Mach-O/磁盘格式、GUI、macOS
构建改动不引入。RAR 并行解码、CPU credit、内存管理、zlib-ng、LZFSE 修复和
汇编优化相关文件保留原内容。Rust 的统一分析、密码探测及规范输入描述符链路
不变。

## 风险与验证

主要风险为 Shrink 新缓冲区、结束判定、字典清理、进度及取消回调。本轮临时
验证过真实 Shrink 样本和内存流边界，均通过；按项目维护范围要求，验证后删除
本轮新增的专属测试、样本及构建入口。SunPack 不承担老压缩方法本身的可靠性
测试维护，继续使用现有测试验证 CLI/watch 集成链路。

本机 Windows x64 验证结果：

| 检查 | 结果 |
| --- | --- |
| CI / Release 构建，x64 ASM 开启 | 均成功；Release 保持 LTO |
| 两个构建目录的 CTest | 原有 8 项均通过；临时专属测试通过后已删除 |
| `tests/unit tests/functional tests/cli`，xdist 4 workers | 1954 passed，1 skipped，71 subtests passed |
| 分卷、缺卷、载体、密码和取消风险集合，xdist 4 workers | 60 passed，1 skipped |
| 独立临时 Watch Broker 的嵌套生命周期、密码清理、输出路由测试 | 7 passed；测试服务已删除 |

60 项风险集合对应：

```powershell
.venv\Scripts\python.exe -m pytest -q -n 4 --dist worksteal `
  tests/integration/test_real_7z_rar_edge_cases.py `
  tests/integration/test_native_sfx_split_wrapper.py `
  tests/integration/test_carrier_discovery_regressions.py `
  tests/integration/test_volume_naming_and_stream_output_regressions.py `
  tests/integration/test_pipeline_interruption.py `
  tests/integration/test_watch_password_cleanup.py `
  tests/real/test_combined_nested_lifecycle.py `
  tests/real/test_split_zip_failure_classification.py
```

其中直接运行时跳过了需要隔离 Broker 的密码清理测试，随后与
`tests/real/plan7_watch_downloads/test_plan7_combined_nested_lifecycle.py`、
`tests/integration/test_watch_root_output_routing.py` 一起在独立服务下通过。
单元集合跳过项为需显式开启的性能断言。本轮未运行 benchmark，也未测试
Windows ARM64，不能据此宣称 ARM64 运行兼容性或性能无退化。

开发目录 `build-x64`、`build-x64-ci` 已更新，`tools/sunpack_sevenzip_worker.exe`
同步自 Release 构建；这些生成物不纳入 Git。测试使用项目原 `.venv`，未重建环境。
