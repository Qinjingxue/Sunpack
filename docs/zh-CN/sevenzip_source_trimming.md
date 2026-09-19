# 7z 源码裁剪分析（用静态链接替换 7z.dll）

面向目标：把 `native/sevenzip_bridge/7z2603-src` 里真正需要的部分编进
`sunpack_sevenzip.dll` / `sunpack_sevenzip_worker.exe`，不再在运行时加载
`tools\7z.dll`。项目只解压、不压缩，所以大部分编码器、写档处理器和整个 UI 层都可以裁掉。

迁移的三个目的（决定了哪些"能删"的其实不能删，见 §9）：

1. **消掉读 / 解码 / 写重合端的两处 memcpy** —— 把 7z 编进 worker exe，并由 SunPack
   掌握 buffer 生命周期
2. 消掉 worker 内部大量 COM 抽象，简化代码
3. `sunpack_sevenzip.dll` 同样把 7z 编进去，并消掉部分 COM 抽象

结论：需要保留 **230 个编译单元（.c/.cpp）**，物理删除其余 **249 个**；
若把整个源码树都算上（含头文件、makefile、bundles、DOC），实际保留约 **220 / 1292 个文件**。
保留下来的部分已在本机用 MSVC 实际编译、链接并跑通格式矩阵（见文末验证记录）。

> 为什么保留数比"只解压"的直觉多：7z 的注册宏会为每个 handler 生成
> `CreateArcOut`（写档工厂），因此链接一份**完整注册表**时，部分编码器和
> 写档源码会被静态初始化对象拖进来。用 `Z7_EXTRACT_ONLY` 或让链接器做
> 死代码消除可以再砍掉其中约 30 个（见 §3.2）。

---

## 1. 桥接层到底用了 7z 的什么

`native/sevenzip_bridge` 对 7z 的依赖面非常窄，这决定了裁剪下限。

### 1.1 唯一入口

```cpp
CreateObjectFunc = HRESULT (WINAPI *)(const GUID *clsid, const GUID *iid, void **outObject);
```

官方 `7z.dll` 通过 `7z2603-src\CPP\7zip\Archive\Archive2.def` 导出它。
静态链接时只需要提供同名同签名的函数（本机实测：签名完全一致，桥接层调用点零改动）。

`Archive2.def` 里其余导出 `GetHandlerProperty2 / GetNumberOfFormats / GetIsArc /
GetNumberOfMethods / GetMethodProperty / CreateDecoder / CreateEncoder / GetHashers /
SetCodecs / SetLargePageMode* / SetCaseSensitive / GetModuleProp` **项目全部没有使用**，
不需要保留对外符号。

### 1.2 只使用 `IInArchive` 的读接口

桥接层自己声明了最小 COM 子集（`sevenzip_sdk.hpp`），只用到：

- `IInArchive::Open / Close / GetNumberOfItems / GetProperty / Extract /
  GetArchiveProperty`
- 客户端侧实现的回调：`IArchiveOpenCallback`、`IArchiveOpenVolumeCallback`（分卷）、
  `ICryptoGetTextPassword`（加密）、`IArchiveExtractCallback` + `IProgress`（解压）
- 流：`IInStream`、`ISequentialOutStream`

`IOutArchive`、`ISetProperties`、`IArchiveUpdateCallback` 等写档接口**一次都没有出现**，
所以所有 `*HandlerOut.cpp` / `*Out.cpp` / `*Update.cpp` 从产品路径看是死代码。

### 1.3 格式 ID 矩阵（`sevenzip_formats.cpp` → `format_guid(id)`）

| ID | 格式 | 保留 | 说明 |
|----|------|------|------|
| `0x01` | zip | 是 | 含 jar/docx/xlsx/apk、`.zip.001` 分卷 |
| `0x02` | bzip2 | 是 | |
| `0x03` | rar4 | 是 | |
| `0x07` | 7z | 是 | 含 `.7z.001` 分卷、编码头 |
| `0x0C` | xz | 是 | |
| `0x0E` | zstd | 是 | |
| `0xCC` | rar5 | 是 | |
| `0xDD` | PE | 是 | 载体：`[PE][overlay 压缩包]` |
| `0xEA` | Split | 是 | `.001` 裸切分 |
| `0xEE` | tar | 是 | |
| `0xEF` | gzip | 是 | |
| 其余 | p7zip/lzma/ppmd/z/arj/cab/chm/iso/nsis/udf/wim/apfs/apm/ar/avb/base64/com/cpio/cramfs/dmg/elf/ext/fat/flv/gpt/hfs/ihex/lp/lvm/lzh/macho/mbr/mslz/mub/ntfs/qcow/rpm/sparse/squashfs/swf/uefi/vdi/vhd/vhdx/vmdk/xar/coff/te | 否 | 已注册但产品永远不会请求 |

> 注意：**注册表里多留几种格式对正确性无害**（`candidate_formats` 按签名返回 ID，
> 工厂找不到就返回 `CLASS_E_CLASSNOTAVAILABLE` 并继续下一个），只是白占体积。
> 但如果产品以后要让"任意伪装扩展名"真正兜底全格式，就得把对应 handler 加回来。

---

## 2. 可以裁掉的部分

### 2.1 整个目录级删除

| 目录 | 文件数 | 原因 |
|------|--------|------|
| `CPP/7zip/UI/**`（FileManager / Far / Console / GUI / Agent / Explorer / Client7z / Common） | 339 | 7z 自己的 GUI、命令行、Far 插件、外壳扩展 |
| `CPP/7zip/Bundles/**` | 49 | 各变体的 makefile / StdAfx / sfx 与 LzmaCon 独立程序 |
| `CPP/Windows/Control/**` | 21 | MFC 风格控件封装 |
| `C/Util/**` | 32 | 独立小工具（7z、LzmaLib、SfxSetup…） |
| `DOC/**`、`Asm/arm*` | — | 文档与非 x64 汇编 |
| 各目录 `StdAfx.cpp` | 48 | 只在用预编译头时需要 |

### 2.2 压缩侧（encoder）—— 约 30 个

- C 层：`LzmaEnc.c`、`Lzma2Enc.c`、`LzFind.c/Mt.c/Opt.c`、`MtCoder.c`、`XzEnc.c`、
  `Ppmd7Enc.c`、`Ppmd8Enc.c`、`Bcj2Enc.c`、`HuffEnc.c`、`BwtSort.c`、`Sort.c`、
  `7zAlloc.c`、`7zArcIn.c`、`7zBuf.c`、`7zBuf2.c`、`7zDec.c`、`7zFile.c`
  （后 6 个是 `C/7zDec.c` 那套**独立的极简 7z 解码 API**，CPP 层解析器完全不引用）
- `CPP/7zip/Compress`：`BZip2Encoder`、`DeflateEncoder`、`LzmaEncoder`、`Lzma2Encoder`、
  `PpmdEncoder`、`XzEncoder`、`ZlibEncoder`、`Lzma86Dec/Enc`
- 写档路径：`7z{Encode,Out,Update,HandlerOut,FolderInStream,SpecStream}`、
  `Zip{Out,Update,AddCommon,HandlerOut}`、`Tar{Out,Update,HandlerOut}`、
  `HandlerOut.cpp`（Archive/Common）、`InOutTempBuffer`、`MultiOutStream`、`UnpackBlocks`

### 2.3 未使用格式 handler —— 约 40 个

`Apfs/Apm/Ar/Arj/Avb/Base64/Com/Cpio/Cramfs/Dmg/Elf/Ext/Fat/Flv/Gpt/Hfs/Ihex/Lp/Lvm/Lzh/
Lzma/Macho/Mbr/Mslz/Mub/Ntfs/Ppmd/Qcow/Rpm/Sparse/Squashfs/Swf/Uefi/Vdi/Vhd/Vhdx/Vmdk/
Xar/Z`，以及 `Cab/Chm/Iso/Nsis/Udf/Wim` 整目录。

### 2.4 GUI / 平台层未用到的部分 —— 约 100 个

`CPP/Windows` 只保留 `FileDir / FileFind / FileIO / FileName / PropVariant /
PropVariantConv / PropVariantUtils / Synchronization / System / TimeUtils`；
其余 `Clipboard / COM / CommonDialog / Console / DLL / ErrorMsg / FileLink / FileMapping /
FileSystem / MemoryGlobal / MemoryLock / Menu / NationalTime / Net / ProcessMessages /
ProcessUtils / Registry / ResourceString / SecurityUtils / Shell / SystemInfo / Window` 全部可去。

`CPP/Common` 可去 `CommandLineParser / Lang / ListFileUtils / MyWindows / Random /
StdInStream / StdOutStream / TextConfig / C_FileIO / CksumReg`。

---

## 3. 不能裁的部分（裁了会编译/链接/运行失败）

### 3.1 "看起来是压缩、实际被解压路径引用"的文件

这是最容易踩的坑。以下文件虽然服务于编码器，但保留的代码会引用到它们的符号：

- `CPP/7zip/Archive/Common/HandlerOut.cpp`、`ParseProperties.cpp`：被保留的
  `DeflateProps.cpp`、`GzHandler`、`ZipHandler` 直接引用
- `C/7zCrc.c`、`C/7zCrcOpt.c`：`CPP/Common/CRC.cpp` 的 C 回退实现
- `CPP/7zip/Compress/BZip2Crc.cpp`：bzip2 解码器
- `CPP/7zip/Crypto/WzAes.cpp`：含 `CKeyInfo` 共享类型
- `CPP/7zip/Compress/PpmdZip.cpp`：zip 里的 PPMd 方法
- `7zEncode / ZipOut / TarOut` 等：注册宏 `REGISTER_ARC_IO` 会生成
  `CreateArcOut`（`new CHandler`），构造函数引用 `COutHandler::InitProps7z`，
  **只要 handler 被注册就会被拖进来**

### 3.2 注册表机制决定了"链接方式"比"裁哪些文件"更关键

7z 的 handler / coder 全靠静态初始化注册：

```cpp
struct CRegisterArc { CRegisterArc() { RegisterArc(&g_ArcInfo); } };
static CRegisterArc g_RegisterArc;   // 文件内静态链接性，无导出符号
```

- 打成 **静态库** 时，这些只含注册对象的 `.obj` 没有任何被引用的符号，链接器会整体丢弃，
  结果是 `CreateObject` 对任何格式都返回 `CLASS_E_CLASSNOTAVAILABLE`
  （本机实测复现）。
- 正确做法（二选一）：
  1. 把 7z 源码**直接编进目标**（`target_sources` 或 CMake `OBJECT` 库），
     链接器再做 `gc-sections`/`/OPT:REF` 死代码消除；
  2. 或保留静态库但加 `/WHOLEARCHIVE:sz7z.lib`（MSVC）/ `--whole-archive`（GCC）。
     代价是 `/WHOLEARCHIVE` 会把所有对象都拉进来，从而**强制**把 3.1 节那些
     编码器源码也带上，否则出现 `LNK2019`。

### 3.3 其它必须保留的

- `ArchiveExports.cpp` + `DllExports2.cpp`：`RegisterArc` / `CreateArchiver` / `CreateObject`
- `Compress/CodecExports.cpp`：`DllExports2.cpp` 的 `CreateObject` 无条件引用
  `CreateCoder` / `CreateHasher`（即使不需要外部编解码器）
- `Archive/HandlerCont.cpp` + `HandlerCont.h`：`RarHandler` / `Rar5Handler` 的基类；
  其 `GetImgExt()` 引用 `ExtHandler.cpp` 的 `IsArc_Ext`，而后者又引用
  `LzhCrc16Update`（`LzhHandler.cpp`）。**`/WHOLEARCHIVE` 模式下这三者必须一起留**，
  直接编进目标时 `GetImgExt` 会被死代码消除，可以不要 `ExtHandler.cpp`/`LzhHandler.cpp`
- 光秃秃的 `.h` 不用单独管，跟着对应 `.cpp` 留着即可

---

## 4. 集成时必须注意的三点（实测踩到）

### 4.1 `WIN32_LEAN_AND_MEAN` 会打破 7z 源码

项目现有 `CMakeLists.txt` 对 bridge 目标定义了 `WIN32_LEAN_AND_MEAN`。该宏会让
`<Windows.h>` 不再包含 `wtypes.h`/`oleauto.h`，于是 `LPCOLESTR`、`IUnknown`、`PROPID`
全部未定义，7z 的 `MyString.h(674)` 直接编译失败。

两种处理：
- 7z 源码目标**去掉** `WIN32_LEAN_AND_MEAN`（推荐）；或
- 强塞头文件：`/FIobjbase.h /FIoleauto.h`（实测可行，但会让 7z 与 SDK 的
  `COM_DECLSPEC_NOTHROW` 宏定义互相干扰）

### 4.2 `/utf-8` 必须加

bridge 源码里有中文注释，MSVC 默认按 936 代码页解析会产生
"缺少函数标题" 之类的假语法错误。项目现有构建已经加了，新增的 7z 目标也要加。

### 4.3 7z 的 include 根目录不能泄漏给 bridge

若把 `${7z2603-src}` 作为 `PUBLIC` include 目录传给 bridge 目标，bridge 的
`internal/xxx.hpp` 会被 7z 头文件遮蔽，产生一批莫名其妙的语法错误。
必须是 `PRIVATE`。

### 4.4 需要统一的 COM 身份

bridge 自带一份 IID 常量（`sevenzip_sdk.cpp`）。本机逐条比对确认与
`CPP/7zip/Guid.txt`、`IStream.h`、`IArchive.h`、`IProgress.h`、`IPassword.h`
完全一致，`kpid*` 也与 `PropID.h` 枚举一致。**这是静态替换能成立的前提，
后续升级 7z 版本时必须重新比对这两处**。

---

## 5. 关于汇编与性能

`Asm/x86/*.asm` 是官方 Release 版 `7z.dll` 用的热点实现，其中对解压最重要的：

| 文件 | 作用 | 项目是否需要 |
|------|------|--------------|
| `LzmaDecOpt.asm` | `LzmaDec_DecodeReal_3()`，LZMA/LZMA2 主解码循环 | **建议启用**（配合 `-DZ7_LZMA_DEC_OPT`），7z/zip/xz 解压热点 |
| `7zCrcOpt.asm` | CRC32 分片计算 | 建议启用 |
| `Sha256Opt.asm` / `Sha1Opt.asm` | RAR5 / XZ 校验 | 可选 |
| `Sort.asm` / `BwtSort` | bzip2 块排序 | 可选 |
| `AesOpt.asm` | AES-CTR | 可选（加密包解压热点） |

不启用汇编时 C 回退实现（`LzmaDec.c` / `7zCrcOpt.c` / `AesOpt.c` / `Sha256Opt.c` /
`Sha1Opt.c`）保证功能正确，只是慢；本机验证就是走 C 回退路径。
启用汇编需要在 CMake 里 `enable_language(ASM_MASM)` 并加入 `Asm/x86/7zAsm.asm`
作为 include 依赖，`ml64.exe` 在 VS BuildTools 里已存在。

---

## 6. 建议的整合方式

```
native/sevenzip_bridge/
  CMakeLists.txt            # 新增 SUP7Z_USE_BUNDLED_7Z 开关
  7z2603-src/               # 只保留保留集（其余物理删除，便于审计上游 diff）
  src/internal/sevenzip_sdk.cpp   # 保留两个分支：dlopen 或 静态 CreateObject
```

要点：

1. `CreateObjectFunc` 签名不变，只把 `cached_create_object()` 的
   `LoadLibraryW` + `GetProcAddress` 换成内置工厂；`sunpack_sevenzip_worker.exe`
   的 `seven_zip_dll_path` 参数保留但被忽略（或走 `is_backend_available()` 汇报）。
2. **必须把 `archive_open_probe.cpp` / `archive_resources.cpp` /
   `archive_crc_manifest.cpp` 三处的 `ComModule module(...)` 一起改掉**——它们绕过了
   缓存工厂直接 `LoadLibrary`，本机实测这三处不改就会在静态模式下全部返回
   "archive file could not be opened"。
3. Python / Rust 侧的 `seven_zip_dll_path` 参数、`tools\7z.dll` 资源查找、
   `doctor` 检查、打包脚本里的 `7z.dll` 条目可以后续单独清理，不阻塞主改动。

---

## 7. 本机验证记录

用 MSVC 14.44（VS 2022 BuildTools）在临时目录搭了一套等价工程：
保留集源码 + 逐字复制的 bridge 源码（仅替换 `sevenzip_sdk.cpp` 的工厂来源），
未改动仓库任何文件。

- 198 个"只解压够用"的候选 `.c/.cpp` **逐一单独编译，0 失败**（编译层面全部干净）
- 按完整注册表链接补入 32 个被注册宏/静态初始化拖进来的文件后，完整链接出
  `sunpack_sevenzip.dll`（约 1.25 MB，未启用 LTO/汇编）
- 用 bridge 的真实 C ABI（`sup7z_run_operation` / `sup7z_analyze_archive_resources`）
  跑格式矩阵：

| 固化样本 | handler | items | unpacked | method |
|----------|---------|-------|----------|--------|
| `sample_stored.zip` | zip | 4 | 2983 | Store |
| `sample_deflate.zip` | zip | 4 | 2983 | Deflate |
| `sample.tar` | tar | 7（4 文件 3 目录） | 2983 | — |
| `sample.tar.gz` / `plain.txt.gz` | gzip | 1 | 20480 / 560 | — |
| `sample.tar.bz2` / `plain.txt.bz2` | bzip2 | 1 | — | — |
| `sample.tar.xz` / `plain.txt.xz` | xz | 1 | 20480 / 560 | LZMA2:23 CRC64 |
| `sample.tar.zst` / `plain.txt.zst` | zstd | 1 | — | — |

结论：zip（Store/Deflate）、tar、gzip、bzip2、xz、zstd 的打开、条目枚举、
属性读取、资源统计全部正常，且走的是 bridge 生产代码路径。

**尚未覆盖**：7z、rar4、rar5、加密包（密码尝试）、分卷、PE 载体 —— 本地没有
可用的 fixture 生成手段（无 py7zr / rarfile，仓库 `testfiles` 里只有 3 个
几百 MB~3GB 的大包）。这几项需要在真实样本上补测。

---

## 8. 最终清单

按 `.c` / `.cpp` 编译单元统计（已排除 `C/Util/` 与各 `StdAfx.cpp`）：

| 目录 | 原文件数 | 保留 | 裁掉 |
|------|---------|------|------|
| `C/`（顶层） | 112 | 55 | 57 |
| `CPP/Common` | 71 | 25 | 46 |
| `CPP/Windows` | 89 | 10 | 79 |
| `CPP/7zip/Common` | 50 | 21 | 29 |
| `CPP/7zip/Archive` 及子目录 | 106 | 53 | 53 |
| `CPP/7zip/Compress` | 101 | 52 | 49 |
| `CPP/7zip/Crypto` | 28 | 14 | 14 |
| `CPP/7zip/UI` + `Bundles` + `C/Util` 等 | — | 0 | 全部 |
| **合计** | **479** | **230** | **249** |

按源码字节数：保留 3.20 MB / 7.49 MB，**裁掉 57%**。

保留下来的核心是：**7z / zip / rar4 / rar5 / tar / gzip / bzip2 / xz / zstd 九个
handler 的解压侧 + 全部解压编解码器 + 全部解密实现 + 注册机制**；
裁掉的是**未使用格式、整个 UI 层、CLI/SFX bundle、独立工具**。

其中**仍然保留、但纯属编码器/写档**的部分（当前方案里是被链接拖进来的，不是产品需要）：

- C 层编码器：`C/{Lzma,Lzma2,Xz,Ppmd7,Ppmd8,Bcj2}Enc.c`、`C/{LzFind,LzFindMt,LzFindOpt,MtCoder,Sort,BwtSort,HuffEnc}.c`
- `Compress/{BZip2,Deflate,Lzma,Lzma2,Ppmd,Xz,Zlib}Encoder.cpp`
- 写档路径：`7z{Encode,Out,Update,HandlerOut,FolderInStream,SpecStream}`、
  `Zip{Out,Update,AddCommon,HandlerOut}`、`Tar{Out,Update,HandlerOut}`
- 只因为 `/WHOLEARCHIVE` 才被拖进来的：`ExtHandler.cpp`、`LzhHandler.cpp`
  （见 §3.3 的 `HandlerCont::GetImgExt` 依赖链）

这也解释了 §8 的保留数为什么是 230 而不是 198：编译层面 198 个候选全部干净编译通过，
但**完整链接**会通过静态初始化对象额外拖入 32 个编码器/写档文件。
把链接策略换成"源码直接编进目标 + `/OPT:REF`"可以再砍掉它们，
但按 §9.5 的建议，**改造期间先不要压这一刀**。

---

## 9. 针对"消 memcpy + 消 COM"三个目标的裁剪审计

§1–§8 是按"只调用 `CreateObject` / `IInArchive`"这个前提做的裁剪。
但迁移的最终目的是**打开 7z 内部、改 buffer 生命周期、拆掉 COM 层**，
前提变了，所以要重新审计一遍：**裁剪方案有没有砍掉接下来要改的东西。**

### 9.1 结论：没有砍掉关键的，但有三点必须明确

| 判断 | 结论 |
|------|------|
| 要改的 buffer / 解码 / handler 文件 | **全部在保留集内**，没有被裁掉 |
| 会不会因为"要改"而需要把已删的文件加回来 | **不会**。已删的都是编码器、写档、未用格式、UI |
| 风险点 | 有三个文件是"按只调用 API 的前提可以删，按改造前提最好留"（见 9.4） |

### 9.2 当前 memcpy 到底在哪（实测代码定位）

写路径上一共有 **3 处**全量拷贝，其中 2 处是 7z 内部的：

| # | 位置 | 代码 | 触发条件 | 性质 |
|---|------|------|----------|------|
| 1 | zstd 解码器自带窗口 | `Compress/ZstdDecoder.cpp:88,341` | 每个 zstd 流 | 7z 内部 |
| 2 | LZMA/LZMA2 输出缓冲 → 输出流 | `Compress/LzmaDecoder.cpp:178` `WriteStream(outStream, _state.dic + wrPos, ...)` | 每次 `FlushWithCheck()` | 7z 内部，**主要目标** |
| 3 | 桥接层 → 异步写线程暂存缓冲 | `sevenzip_async_output.hpp:426` `std::memcpy(file->staging_buffer->data.get() + previous_size, source + consumed, chunk)` | 每次 `ISequentialOutStream::Write` | SunPack 侧，**主要目标** |

完整调用链（每层都是一次虚函数调用）：

```
CCoderMixer2::CMixerST::Code()                    ← Archive/Common/CoderMixer2.cpp
  └─ CLzmaDecoder::Code()
       └─ CLzOutWindow(=COutBuffer)::FlushWithCheck()   ← Common/OutBuffer.cpp
            └─ WriteStream(outStream, ...)  memcpy #2    ← Compress/LzmaDecoder.cpp:178
                 └─ CFolderOutStream::Write()            ← Archive/7z/7zExtract.cpp:143
                      └─ IArchiveExtractCallback::GetStream()  → AsyncFileOutStream
                           └─ AsyncFileWriter::write()  memcpy #3   ← sevenzip_async_output.hpp:426
                                └─ WriteFile()
```

`kBufferSize = 1U << 20`（`sevenzip_async_output.hpp:219`），所以 1 GB 文件在这条链上
大约走 2048 轮、每轮拷 1 MB，**两处 memcpy 合计 2 GB 的额外内存带宽**。
小文件（≤1 MB）则是一整块一次拷两次。

### 9.3 好消息：7z 已经内置了零拷贝改造所需的挂点

不需要新写缓冲机制，只需要把已有的挂点接上：

| 挂点 | 位置 | 作用 |
|------|------|------|
| `COutBuffer::_buf` / `StreamPos()` / `Flush()` | `CPP/7zip/Common/OutBuffer.h:20,42` | LZMA 窗口就是一块 `MidAlloc` 的裸 buffer，可直接交给 writer |
| `CInBufferBase::SetBuf(Byte *buf, size_t bufSize, size_t end, size_t pos)` | `CPP/7zip/Common/InBuffer.h:56` | 输入侧可直接注入外部 buffer，省掉入队拷贝 |
| `COutBuffer::SetMemStream(Byte*)` | `OutBuffer.h:42` | **注意：这不是零拷贝挂点**，语义是 `memcpy(_buf2, _buf + _streamPos, size)`，是 zip deflate 专用（`DeflateDecoder.cpp:543`），LZMA 用不上 |

也就是说：**改造点集中在"谁提供 buffer、谁负责释放"**，而不是重写解码逻辑。
`CLzOutWindow` / `COutBuffer` / `CInBuffer` 这三块必须原样保留——它们是挂点的宿主。

### 9.4 审计结果：改造会用到的文件，逐个确认

**A. 必须保留，且是改造主战场**（全在保留集内）

| 文件 | 用途 | 为什么不能删 |
|------|------|--------------|
| `Common/OutBuffer.{h,cpp}` | LZMA 窗口宿主，memcpy #2 的起点 | 零拷贝挂点 |
| `Common/InBuffer.{h,cpp}` | 输入侧缓冲 + `SetBuf` 挂点 | 零拷贝挂点 |
| `Compress/LzmaDecoder.cpp` | `WriteStream` 调用点（:178） | memcpy #2 现场 |
| `Compress/Lzma2Decoder.cpp`、`C/LzmaDec.c`、`C/Lzma2Dec.c` | 实际解码 | 核心 |
| `Archive/7z/7zDecode.cpp` | `CDecoder::Decode` + mixer 装配 | 解码编排 |
| `Archive/7z/7zExtract.cpp` | `CFolderOutStream`，substream 切分 | 输出分发 |
| `Archive/7z/7zIn.cpp`、`7zHeader.cpp`、`7zHandler.cpp` | 头解析、属性 | 核心 |
| `Archive/Common/CoderMixer2.{h,cpp}` | `CMixerST`/`CMixerMT` 装配 | **COM 简化主战场**：目前用 `ICompressCoder` + `IUnknown*` 数组装配 coder |
| `Common/CreateCoder.cpp`、`CWrappers.cpp` | COM 工厂 / `ICompressFilter` 包装 | **COM 简化主战场** |
| `Common/FilterCoder.{h,cpp}` | BCJ2/BCJ 过滤器链 | 同上 |
| `Common/StreamBinder.{h,cpp}`、`StreamObjects.{h,cpp}`、`LimitedStreams.{h,cpp}` | coder 之间的流胶水 | 同上 |

**B. 高危裁剪点：改动前先确认连带关系**

下面这些当前都在保留集里（属于 §8 说的"被链接拖入"），
**不要为了让体积好看而删掉**，否则会打断 A 组的依赖：

| 保留文件 | 连带关系 |
|----------|----------|
| `C/MtDec.c` 与 `C/MtCoder.c` **都保留** | 已核实 `Lzma2DecMt.c` 只依赖 `MtDec.h` + `Threads.h`，不引用 `MtCoder`；多线程 LZMA2 解压走的是 `MtDec`。两个都在，无风险 |
| `Compress/LzOutWindow.cpp/h` | `CLzOutWindow : public COutBuffer`，是 memcpy #2 的窗口本体 |
| `Archive/7z/7zFolderInStream.cpp` | 多线程解压时给 coder 逐个喂 pack stream；MT 路径要保留就**必须留** |
| `Crypto/RandGen.cpp` | 编码专用（`ZipStrong` 派生密钥），解压路径不需要；想收口可以删 |
| `Archive/Common/OutStreamWithCRC.cpp`、`InStreamWithCRC.cpp` | CRC 校验参考实现，改造后校验要内联进 writer |

已删文件**没有误伤**，已核实：

| 已删文件 | 核实结论 |
|----------|----------|
| `CPP/7zip/Common/MultiOutStream.cpp` | 保留集里 **0 个文件** include 它的头，安全 |
| `CPP/7zip/Common/FileStreams.cpp` | 保留集里 **0 个文件** include 它的头；桥接层自己用 `CreateFileW/ReadFile` 做流，安全 |
| `C/Bcj2Enc.c` 曾被尝试删除 | 实际上在保留集里（编码器，被链接拖入） |

**C. 一个按只调用 API 可以删、按改造前提建议留的文件**

| 文件 | 当前状态 | 改造时的价值 |
|------|----------|--------------|
| `Compress/ZstdDecoder.cpp` | 保留 | 它自己有 `_inBufSize = 1<<19` 的额外缓冲（memcpy #1）；要连 zstd 的拷也消掉，这里是改造点，不能删 |

### 9.5 对裁剪方案的两条修正建议

1. **不要为了"体积好看"去用 `Z7_EXTRACT_ONLY` 把 `7zDecode.cpp` / `CoderMixer2.cpp`
   里的写档分支剪掉。** §3.2 提到用 `Z7_EXTRACT_ONLY` 能再砍 30 个文件，
   但那个宏在 `GzHandler.cpp` / `ZipHandler.cpp` 上本身就不自洽（本机实测编译失败）。
   改造涉及这些文件时，带一个半残的宏反而增加 diff 噪音。
   建议：**保留集就按 §8 的 230 个定下来，不再压缩**。

2. **物理删除的文件要按"目录"整块删，不要按文件删。** 因为改造时会在
   `Common/`、`Compress/`、`Archive/7z/` 里大量改代码，保留一个干净的目录边界
   比精确到文件更重要。建议整块删除的目录：
   `CPP/7zip/UI/**`、`CPP/7zip/Bundles/**`、`CPP/Windows/Control/**`、
   `C/Util/**`、`DOC/**`、`CPP/7zip/Archive/{Cab,Chm,Iso,Nsis,Udf,Wim}/**`。

3. **改造期间建议保留 `7z2603-src` 为"上游原样 + 一个补丁目录"的结构。**
   既然要改 7z 内部（buffer 生命周期、COM 拆解），把改动限制在少数文件里并
   在 `CMakeLists.txt` 里用 `SUP7Z_PATCHED_*` 开关标记，将来换 7z 版本时
   diff 面可控。项目虽然声明不考虑版本兼容，但 7z 的安全修复更新仍值得跟进。

### 9.6 用改造视角重看"保留 230 个"这件事

按三个目标拆解保留集：

| 目标 | 涉及的保留文件 | 数量 |
|------|----------------|------|
| buffer 生命周期 / 消 memcpy | `OutBuffer`、`InBuffer`、`LzmaDecoder`、`Lzma2Decoder`、`LzOutWindow`、`7zDecode`、`7zExtract`、`ZstdDecoder` + `C/{LzmaDec,Lzma2Dec,ZstdDec}.c` | 约 15 |
| 消 COM 抽象 | `Archive/Common/CoderMixer2`、`Common/CreateCoder`、`CWrappers`、`FilterCoder`、`StreamBinder`、`StreamObjects`、`LimitedStreams`、`sevenzip_callbacks.hpp`（SunPack 侧） | 约 12 |
| 其余（handler、解码器、crypto、公共库） | 保持不变 | 约 200 |

**改造面只占保留集的约 12%**，其余 88% 是"编进去就行、不用动"的部分。
这也说明：裁剪方案本身是安全的，改造的复杂度不在裁剪，而在
**`CoderMixer2` 的 coder 装配 + `CFolderOutStream` 的 substream 切分**
这两处的 COM 拆解。
