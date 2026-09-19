# 7z 源码裁剪分析（用静态链接替换 7z.dll）

面向目标：把 `native/sevenzip_bridge/7z2603-src` 里真正需要的部分编进
`sunpack_sevenzip.dll` / `sunpack_sevenzip_worker.exe`，不再在运行时加载
`tools\7z.dll`。项目只解压、不压缩，所以大部分编码器、写档处理器和整个 UI 层都可以裁掉。

迁移的三个目的（决定了哪些"能删"的其实不能删，见 §9）：

1. **消掉读 / 解码 / 写重合端的两处 memcpy** —— 把 7z 编进 worker exe，并由 SunPack
   掌握 buffer 生命周期
2. 消掉 worker 内部大量 COM 抽象，简化代码
3. `sunpack_sevenzip.dll` 同样把 7z 编进去，并消掉部分 COM 抽象

结论：需要保留 **228 个编译单元（.c/.cpp）**（源码 API 迁移后由 230 减至 228，见 §14），物理删除其余编译单元；
若把整个源码树都算上（含头文件、makefile、bundles、DOC），实际保留 **479 / 1292 个文件**
（保留集包含 228 个编译单元、226 个头文件、12 个 `Asm/` 汇编、11 个 `DOC/`）。
保留下来的部分已在本机用 MSVC 实际编译、链接并跑通格式矩阵（见文末验证记录）。

> **落地状态（本轮已完成）**：源码树已按 §11 物理裁剪，构建已接入
> `sunpack_7zip_objects` OBJECT library，`sunpack_sevenzip.dll` /
> `sunpack_sevenzip_worker.exe` 已不再加载 `7z.dll`。
> 具体改动范围与验证结果见 **§11 落地记录**。

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

`Asm/x86/*.asm` 是官方 Release 版 `7z.dll` 用的热点实现。**不是 12 个全部启用**——官方
26.03 自身的构建也是按用途和架构挑实现，SunPack 只解压，所以范围比官方完整 `7z.exe`
更窄。x64 下真正值得恢复的是 6 个：

| 文件 | 提供的符号 | 作用 | 项目是否需要 |
|------|------------|------|--------------|
| `LzmaDecOpt.asm` | `LzmaDec_DecodeReal_3` | LZMA/LZMA2 主解码循环 | **启用**（配合 `LzmaDec.c` 的 `Z7_LZMA_DEC_OPT`），7z/zip/xz 解压最热的一段 |
| `7zCrcOpt.asm` | `CrcUpdateT12` | CRC32 分片计算 | **启用**，ZIP/7z 等大量使用 |
| `XzCrc64Opt.asm` | `XzCrc64UpdateT12` | CRC64 分片计算 | **启用**，XZ |
| `AesOpt.asm` | `AesCbc_{Decode,Encode}_HW[_256]`、`AesCtr_Code_HW[_256]` | AES-NI / VAES 硬件路径 | **启用**，加密 7z/ZIP |
| `Sha1Opt.asm` | `Sha1_UpdateBlocks_HW` | SHA-1 硬件路径 | **启用** |
| `Sha256Opt.asm` | `Sha256_UpdateBlocks_HW` | SHA-256 硬件路径 | **启用** |
| `Sort.asm` | `HeapSort` | 堆排序 | **不启用**，只被 `HuffEnc.c` / `BwtSort.c` 引用，属压缩侧 |
| `LzFindOpt.asm` | `GetMatchesSpecN_2` | LZ match finder | **不启用**，只被 `LzFindMt.c` 引用，属压缩侧 |

上游没启用的两个并非"可选的解压热点"：`GetMatchesSpecN_2` **只**被 `LzFindMt.c`
（LZMA 编码器的多线程 match finder）调用，`HeapSort` **只**被 `HuffEnc.c`（Huffman
编码）与 `BwtSort.c`（BWT 排序）调用，全在压缩路径上。SunPack 因为 handler 注册依赖
仍然保留这些编码器源码，但产品路径是解压，启用它们只会增加构建复杂度、MASM 攻击面
和测试面积，几乎不带来运行收益。

`Sort.asm` 也**不是** bzip2 热点：bzip2 解码走 `BZip2Decoder.cpp` / `Bz2Handler.cpp`，
`BwtSort.c` 是编码侧的 BWT 排序。文档早期版本把它写成"bzip2 可选热点"是错的，已订正。

不启用汇编时 C 回退实现（`LzmaDec.c` / `7zCrcOpt.c` / `XzCrc64Opt.c` / `AesOpt.c` /
`Sha1Opt.c` / `Sha256Opt.c`）保证功能正确，只是慢。启用汇编的落地细节见 **§17**。

ARM64 这一轮**完全不碰汇编**：官方 Windows ARM64 makefile 对 CRC32/CRC64/AES/SHA1/SHA256
本来就选 C/intrinsics 实现；上游唯一的 ARM64 汇编热点 `Asm/arm64/LzmaDecOpt.S` 是
GNU assembler + 预处理器语法，接不进 MSVC `-A ARM64`。功能完全一致。

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
| **合计** | **479** | **228** | **251** |

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

---

## 11. 落地记录（链接来源替换里程碑）

本轮目标刻意收窄为**纯链接来源替换**：把 7-Zip 源码正式接入项目构建，让
`sunpack_sevenzip.dll` 与 `sunpack_sevenzip_worker.exe` 不再依赖 `7z.dll`。
**不动** zero-copy、buffer 生命周期、`ComModule` 清理、汇编优化。

### 11.1 逻辑关系

```text
之前：                                  之后：
sunpack_sevenzip.dll / worker.exe       sunpack_sevenzip.dll / worker.exe
        ↓                                        ↓
LoadLibrary("7z.dll")                   进程内 CreateObject
        ↓                                        ↓
GetProcAddress("CreateObject")          IInArchive ...（以下全部不变）
        ↓
7-Zip CreateObject
        ↓
IInArchive ...
```

### 11.2 源码树裁剪结果

`native/sevenzip_bridge/7z2603-src`：**1292 → 479 个文件**，删除 813 个。

保留集 = 230 个编译单元 + 226 个被 `#include` 触达的头文件 + 12 个 `Asm/` + 11 个 `DOC/`。
裁剪清单由脚本按 `#include` 闭包生成，不是手抄：任何"没人 include 的头文件"也被剔除。

两处刻意保留：

| 目录 | 理由 |
|------|------|
| `Asm/`（12 个） | `x86/LzmaDecOpt.asm`、`7zCrcOpt.asm` 等是官方 Release 版热点实现；本轮不启用，但删了就得从上游重新取。当前构建**不引用**它们 |
| `DOC/`（11 个） | `DOC/unRarLicense.txt` 是 `Rar1/2/3Decoder.cpp` 头注释援引的强制许可条件；其余是 7-Zip 许可与来源说明 |

删除范围覆盖：`CPP/7zip/UI/**`、`Bundles/**`、`Windows/Control/**`、`C/Util/**`、
未使用的 archive handler、未使用的平台层、全部构建脚本（`.mak`/`.dsp`/`.vcxproj`）、
以及 `C/7zDec.c` 那套独立极简 7z 解码 API（`7zArcIn.c`/`7zBuf.c`/`7zFile.c`/`LzmaLib.c`）。

### 11.3 构建接入

`native/sevenzip_bridge/CMakeLists.txt`：

1. `project(... LANGUAGES C CXX)` —— 保留集里有大量 `.c`，必须真正按 C 编译
2. 新增 `sunpack_7zip_objects` **OBJECT** library，源码用 `GLOB_RECURSE CONFIGURE_DEPENDS`
   从已裁剪的树里取，并加 **sanity check：数量必须是 228**，否则 configure 阶段报错
3. 对象直接进入最终 PE：
   `target_sources(sunpack_sevenzip PRIVATE $<TARGET_OBJECTS:sunpack_7zip_objects>)`，
   worker / smoke 通过 `sup7z_attach_bundled_7z()` 同样注入

三个必须记住的约束：

| 约束 | 原因 |
|------|------|
| 用 OBJECT library，不用 STATIC | handler/coder 靠文件内静态初始化注册，没有可引用符号；静态库的 `.obj` 会被链接器整体丢弃，表现是 `CreateObject()` 一律返回 `CLASS_E_CLASSNOTAVAILABLE` |
| 7z 目标**不定义** `WIN32_LEAN_AND_MEAN` | 该宏让 `<Windows.h>` 不再带 `wtypes.h`/`oleauto.h`，`LPCOLESTR`/`IUnknown`/`PROPID` 全部未定义，`MyString.h(674)` 直接编译失败 |
| 7z 的 include 根必须 `PRIVATE` | `PUBLIC` 会遮蔽 bridge 自己的 `internal/*.hpp`，产生一批假语法错误 |

另外：凡链接 `sunpack_sevenzip_core` 的目标都需要 7z 对象——core 里的
`sevenzip_sdk.obj` 无条件引用 `CreateObject`。所以四个纯 writer 单测也一并注入
（`sup7z_attach_bundled_7z`），否则 `LNK2019`。

### 11.4 C++ 侧改动

| 文件 | 改动 |
|------|------|
| `src/internal/sevenzip_sdk.cpp` | `cached_create_object()` 由 `LoadLibraryW`+`GetProcAddress` 改为 `return &::CreateObject;`；`CreateObjectFunc` 类型**保留不动**，调用方无感 |
| `archive_extract.cpp`（3 处）、`archive_open_probe.cpp`、`archive_resources.cpp`、`archive_crc_manifest.cpp` | 把绕开缓存的 `ComModule module(...)` + `module.create_object()` 全部统一为 `cached_create_object(seven_zip_dll_path)` |
| `operation_dispatch.cpp`、`c_api_passwords.cpp`、`c_api_resources.cpp`、`c_api_crc_manifest.cpp`、`archive_test.cpp` | 去掉 `seven_zip_dll_path` 的必填校验（它是惰性字段），只保留 `archive_path` 必填 |

`ComModule` 类、C ABI 里的 `seven_zip_dll_path` 参数、worker JSON 字段**本轮全部保留**，
作为无语义兼容字段；删除留到后续 COM cleanup。

### 11.5 Python / worker / 打包侧

| 位置 | 改动 |
|------|------|
| `sunpack/support/resources.py` | 删除 `get_7z_dll_path()`（生产包不再知道"7z.dll 资源"这个概念） |
| `sunpack/support/sevenzip_bridge.py` | `available()` 不再要求 7z.dll；`_load()` 删掉 7z.dll 存在性检查 |
| `sunpack/cli/commands/doctor.py` + i18n | 移除 `sevenzip_dll` 检查项（后端已内置，磁盘上无物可查） |
| `scripts/build_windows.ps1`、`setup_windows_dev.ps1` | `Build-SevenZipWrapper` 不再要求 7z.dll；工具清单去掉 `7z.dll` |
| `scripts/verify_windows_package_arch.ps1` | 打包校验**反向要求** `tools\7z.dll` 不存在 |

阶段 1 仍保留 `seven_zip_dll_path` 作为惰性兼容字段；该壳已在 **§12 语义收尾**中删净。

### 11.6 验证结果

| 验证 | 结果 |
|------|------|
| x64 Release 编译 + 链接 | 通过；`sunpack_sevenzip.dll` 1.37 MB、worker 1.70 MB |
| `ctest`（bridge 自带 4 个单测） | 4/4 通过 |
| `pytest tests/unit tests/cli` | 1128 通过 |
| `dumpbin /dependents` | dll 与 worker 的导入表均无 `7z.dll` |
| **无 7z.dll 生存测试** | `tests/unit/test_embedded_7z_backend.py`：把产物放进空目录、确认目录内无 7z.dll 后，worker 真实解压 ZIP 成功、DLL 的 probe/resources 成功；该测试在 `tools\7z.dll` 存在与不存在两种情况下均通过 |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |

### 11.7 刻意没做的事

- 不启用 `Asm/`（`ASM_MASM` / `LzmaDecOpt.asm` / CRC/AES/SHA 汇编）——本轮不求性能对齐，
  等源码后端稳定后单独一个 PR 恢复，便于定位性能变化
- 不引入 `SUP7Z_USE_BUNDLED_7Z` 双后端开关——embedded 是唯一后端
- 不删 `seven_zip_dll_path`（C ABI / JSON / Python 字段）——已在 §12 语义收尾中删净
- 不删 `ComModule` / `DllExports2.cpp` / `CreateObjectFunc`——`ComModule` 已在 §12 删除；
  `DllExports2.cpp` 与 `CreateObjectFunc` 仍按设计保留
- 不碰解码数据路径：prefetch、decoder、async writer、所有 memcpy、所有 COM callback 原样

### 11.8 遗留说明

- 仓库仍保留 `tools\7z.dll`。它属于 `tools\7z.exe`（测试套件用来**生成 fixture** 的
  7-Zip CLI），是构建期工具而非产品运行时依赖；发布包已通过
  `verify_windows_package_arch.ps1` 明确要求它不存在。
- 仓库另有 `tools\7zxa.dll`（7-Zip 官方解压-only 变体），本轮未纳入处理范围。
- ARM64 目标沿用同一套构建配置，但本机只有 x64 工具链，**ARM64 未实测**。

---

## 12. 语义收尾（阶段 1.5）

阶段 1 为了降低迁移风险，把 `seven_zip_dll_path` 留成了"无语义兼容字段"。
源码后端稳定后，本轮把它从整条运行时链路删净：**Python → worker JSON →
C ABI → C++ 内部**，全链路不再出现"7z.dll 路径"这个概念。

### 12.1 两个不变量

**运行时不变量** —— `native/sevenzip_bridge/{src,include}` 内 `7z.dll` 命中数 = **0**：

```text
SunPack runtime 不再：
  查找 7z.dll / 校验 7z.dll / 传递 7z.dll 路径
  JSON 里出现 seven_zip_dll_path
  C ABI 里出现 seven_zip_dll_path
  LoadLibrary / GetProcAddress 7z.dll
```

**测试工具不变量** —— 允许且必须标注清楚：

```text
tests/ benchmarks/ 的 fixture 生成可用 tools\7z.exe + tools\7z.dll + tools\7zCon.sfx
但它是 test generator dependency，不是 runtime dependency
```

### 12.2 C++ 侧删除内容

| 删除对象 | 说明 |
|----------|------|
| `ComModule` | 整个类消失：`HMODULE` / `LoadLibraryW` / `FreeLibrary` / `GetProcAddress` 不再需要 |
| `cached_create_object(path)` | 改名 `embedded_create_object()`，不再接收参数 |
| 服务层形参 | `test_password(s)`、`extract_archive_*`、`probe_archive_open_*`、`analyze_archive_resources_*`、`read_archive_crc_manifest_*`、`is_backend_available` 全部去掉首参 |
| `ArchiveOperationRequest::seven_zip_dll_path` | 结构体字段删除 |
| worker `dll_path` | JSON 读取、局部变量、向下传递全部删除 |
| C ABI 首参 | `sup7z_try_passwords` / `sup7z_test_archive` / `sup7z_analyze_archive_resources` / `sup7z_read_archive_crc_manifest`（含 `_with_parts` 变体）与 `Sup7zOperationRequest` 字段全部去掉 |
| 必填校验 | 各处 `if (!seven_zip_dll_path \|\| !archive_path)` 只保留 archive 部分 |

**保留不动**：`CreateObjectFunc` 函数指针类型、`DllExports2.cpp` / `ArchiveExports.cpp` /
`CreateObject`。归档逻辑仍经由工厂函数指针获取对象，不直接绑定具体实现——
下一阶段拆 archive/coder COM 时再决定这个间接层是否还有价值。

### 12.3 Python 侧

| 位置 | 改动 |
|------|------|
| `NativePasswordTester` | 删除构造参数与实例属性 `seven_zip_dll_path` |
| `_Sup7zOperationRequest` | 删除该字段（与 C 结构体逐字段对齐已复核） |
| 8 个 `argtypes` | 各去掉首个 `c_wchar_p` |
| 5 处 ctypes 调用 | 去掉首参 |
| `_cache_key()` | 键里去掉该字段 |
| `SevenZipRunner` | 删除 `self.seven_zip_dll_path`、`fork()` 复制、`_seven_zip_dll_path()`、job 字段 |
| `sevenzip_bridge_worker.py` | 不再解析 7z.dll，payload 去掉该字段 |

`get_7z_dll_path()` 从生产包迁到 `tests/helpers/tool_config.py` 并改名
**`get_7z_cli_dll_path()`** —— 名字本身就声明"这是 7z.exe 测试工具链的配套模块，
≠ SunPack backend"。28 处 tests/benchmarks 调用点全部改指，payload 字段全部删除。

### 12.4 构建与验收脚本

| 位置 | 改动 |
|------|------|
| `Test-SevenZipWorker`（两个构建脚本） | 原断言 `get_7z_dll_path()` 存在，只是被仓库里的 `tools\7z.dll` 掩盖。改为：断言 worker 存在 + 生成真实 ZIP + 跑 `sunpack.py inspect --analyze`，端到端验证内置后端 |
| `run_acceptance_tests.ps1` | 拆成 **runtime artifacts**（`sunpack_sevenzip.dll`、`worker.exe`）与 **fixture generators**（`7z.exe`、`7z.dll`、`7zCon.sfx`）两组，各自独立报错 |
| 诊断文案 | `"7z.dll did not create a supported archive handler"` / `"7z.dll could not be loaded"` 改为描述内置后端（已确认无测试或 Python/Rust 消费者断言这些字符串） |
| 源码注释 | `sevenzip_streams.hpp`、`bridge.hpp` 中"7z.dll decoder"等表述改为"embedded 7-Zip decoder" |

### 12.5 本轮验证

| 验证 | 结果 |
|------|------|
| x64 Release 编译 + 链接 | 通过 |
| `ctest`（bridge 4 个单测） | 4/4 通过 |
| `pytest tests/unit tests/cli` | 1128 通过 |
| 生产 runtime 源码 `7z.dll` 命中 | **0 处** |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |
| 无 7z.dll 生存测试 | `tests/unit/test_embedded_7z_backend.py` 4/4 通过 |

### 12.6 仍然刻意没做

```text
7-Zip 内部 COM 接口 · IInArchive · ISequentialIn/OutStream
CoderMixer2 · buffer ownership · prefetch · async writer · memcpy · 汇编优化
CreateObjectFunc 间接层
tools\7z.exe / tools\7z.dll（测试 fixture 生成链）
```

前一组属于阶段 3/4 的性能与架构改造；后两项按 §12.1 的不变量明确保留。


---

## 13. 阶段 2 第一步：源码 API 迁移

目标是把"为了调用 7z.dll 而复制出来的 COM ABI 层"换成**直接作为 7-Zip 源码的调用者**。
边界很明确：删 SunPack 自己复制的壳，保留 7-Zip 内部真正的 COM-like 对象协议。

### 13.1 改了什么

| 对象 | 迁移前 | 迁移后 |
|------|--------|--------|
| 头文件 | bridge 手抄 `IInArchive` / `IInStream` / `IArchiveExtractCallback` / … 九套接口 | 直接 `#include "7zip/Archive/IArchive.h"` 等官方头 |
| IID | `sevenzip_sdk.cpp` 里手写 9 个 `const GUID IID_*` | `using ::IID_*`，定义来自上游（`CPP/7zip/Guid.txt` 经接口头） |
| PropID | `kpidPath = 3` 等 10 个手抄数字 | `using ::kpid*`，来自上游 `PropID.h` |
| AskMode | `kTestMode = 1` / `kExtractMode = 0` | `NArchive::NExtract::NAskMode::kTest` / `kExtract` |
| OperationResult | `kOpOk = 0` … `kOpWrongPassword = 9` 手抄 10 个 | `NArchive::NExtract::NOperationResult::*` |
| 工厂 | `CreateObjectFunc` 函数指针 + `embedded_create_object()`，逐层透传 8 个函数签名 | `HRESULT create_in_archive(const GUID&, IInArchive**)` 直调上游 `CreateArchiver` |
| 工厂守卫 | 每层 `if (!create_object) { … BackendUnavailable … }` | 删除（内置于本镜像，必存在；具体格式能否创建由 open 路径汇报） |
| `is_backend_available()` | 探测工厂指针是否为空 | 直接 `true`（Windows） |

`CreateObjectFunc`、`embedded_create_object()`、`create_object` 在 bridge 内已 **0 处残留**。

### 13.2 CMake

`sup7z_attach_bundled_7z(target)` 现在同时做两件事：挂 OBJECT 文件 + 加官方头 include。
include 路径是 **PRIVATE 且只给 `CPP` 子树**：

```cmake
target_include_directories(${target_name} PRIVATE ${SUP7Z_7Z_ROOT}/CPP)
```

不能把 `${SUP7Z_7Z_ROOT}` PUBLIC 出去——会遮蔽 bridge 自己的 `internal/*.hpp`。
`sunpack_sevenzip_core` 只加 include 不加 OBJECT 文件（它是 STATIC，会把注册对象吞掉）。

### 13.3 三个实测确认的前提

| 前提 | 结论 |
|------|------|
| 官方头能否在 `WIN32_LEAN_AND_MEAN` 下编译 | **能**。`sevenzip_sdk.hpp` 先 include `<objbase.h>` / `<oleauto.h>`，再 include 7-Zip 头即可，无需去掉目标上的 `WIN32_LEAN_AND_MEAN` |
| 官方接口带 `throw()` 会不会破坏 override | **不会**。7-Zip 用 `COM_DECLSPEC_NOTHROW`（MSVC 下是 `__declspec(nothrow)`），它不参与重写匹配；bridge 现有 `HRESULT STDMETHODCALLTYPE X(...) override` 全部原样编译通过 |
| `IArchiveOpenVolumeCallback::GetStream` 签名 | 上游也是 `const wchar_t*`，与 bridge 手抄**一致**，无隐藏 bug |

### 13.4 本轮刻意没做（留给后续小步）

**`DllExports2.cpp` 暂时必须留在构建里。** 它虽然不再被调用，但它是**唯一** `#include
"Common/MyInitGuid.h"` 从而定义 `INITGUID` 的编译单元，也就是唯一真正定义 `IID_*`
符号的地方。删掉它必须在自己的某个 TU 里接管 `INITGUID`。这一条已写进
`sevenzip_sdk.cpp` 的注释，避免下次有人直接删了它然后撞上 LNK2001。

其余未做项：

```text
DllExports2.cpp / CodecExports.cpp 裁剪（230 → 228）  → 第二步
ComPtr → CMyComPtr（refcount 语义不同，需同批迁移）    → 第三步
手写 QueryInterface/AddRef/Release → CMyUnknownImp      → 第三步
CoInitializeEx / CoUninitialize / Ole32 退出             → 第三步
IInArchive/ICoder/CoderMixer2/FilterCoder 内部结构       → 不在本阶段范围
buffer ownership / prefetch / async writer / memcpy      → 阶段 3/4
```

### 13.5 验证

| 验证 | 结果 |
|------|------|
| x64 Release 编译 + 链接 | 通过 |
| `ctest`（bridge 4 个单测） | 4/4 通过 |
| `pytest tests/unit tests/cli` | 1128 通过 |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |
| bridge 内 `create_object` / `CreateObjectFunc` / `embedded_create_object` 残留 | 0 处 |
| `sunpack_sevenzip.dll` 导出表 | 9 个 `sup7z_*` 全部在位 |

改动 8 个文件，**业务行为零变化**：解压数据路径、prefetch、async writer、所有 memcpy、
所有 COM callback 语义均未触碰。

---

## 14. 阶段 2 第二、三步：接口类型迁移 + GUID ownership 接管 + DLL export 层裁剪

§13 只完成了"工厂与常量来源"的迁移，九套 C++ interface 类型仍是手抄的。
本节补完那一刀，并顺带把 7z.dll 的对外导出层清掉。

### 14.1 九套手抄接口彻底删除

`sevenzip_sdk.hpp` 里原本还留着 `ISequentialInStream` / `IInStream` / `IProgress` /
`IArchiveOpenCallback` / `IArchiveOpenVolumeCallback` / `ISequentialOutStream` /
`IArchiveExtractCallback` / `ICryptoGetTextPassword` / `IInArchive` 九个 struct。
它们位于 `sunpack::sevenzip`，与上游 `::IInArchive` 是**两套不同的 C++ 类型**，
只是 vtable 恰好一致才没出事。现在全部换成 `using ::IInArchive;` 等九个 alias。

于是 `class FileInStream : public IInStream` 才真的等价于 `: public ::IInStream`，
`create_in_archive()` 也真的收发 `::IInArchive**`，不再靠 `void**` 偷渡。

### 14.2 这一步暴露出的三个真实问题

**① `throw()` 的结论此前确实没有被工程验证。** `override` 现在对着上游接口，
编译立即报 **274 个 C2694 + 10 个 C3668**。上游 `STDMETHOD` 展开为
`COM_DECLSPEC_NOTHROW`（MSVC 下 `__declspec(nothrow)`），MSVC 把它算进签名。
补法：定义一个 `SUP7Z_NOEXCEPT`，53 处 override 全部补上。

两个细节是实测踩出来的，不是推断：

| 坑 | 现象 | 结论 |
|----|------|------|
| 位置 | `f() override noexcept` 报 C2059 "语法错误: noexcept" | 异常规范必须写在 `override` **之前**：`f() noexcept override` |
| 拼写 | `/std:c++17` 下 `throw()` 本身已非法（动态异常规范被移除） | 宏展开为 `noexcept`，不是 `throw()` |
| 可见性 | 宏定义在 `#include` 之后就太晚，`sevenzip_streams.hpp` 先用到 | 宏必须放在 `sevenzip_sdk.hpp` 最前面，早于所有 include |

**② `PROPID` 不是 `UInt32`。** `OpenCallback::GetProperty` 原本写
`GetProperty(UInt32 propID, ...)`，上游是 `GetProperty(PROPID propID, ...)`，而
`PROPID` 是 `ULONG`。在 Windows 上 `unsigned long` 与 `unsigned int` 是**不同类型**，
所以这个 override 根本没匹配上（C3668）。改成 `PROPID` 即通。

**③ `MyInitGuid.h` 之前必须先有 COM 头。** 它一被 include 就立刻定义
`Z7_DEFINE_GUID`，之后所有接口头都在 `INITGUID` 已定义的状态下展开，
所以 `IUnknown` / `PROPID` / `BSTR` 必须在那之前可见。缺了就是 54 个 C2504。

### 14.3 GUID ownership 接管

新增 `src/internal/sevenzip_guid_defs.cpp`，唯一职责就是定义 GUID：

```cpp
#include <objbase.h>
#include <oleauto.h>

#include "Common/MyInitGuid.h"   // 必须最先，且 INITGUID 只在此 TU 生效

#include "7zip/ICoder.h"          // coder IID：解码路径与 mixer 会 QueryInterface
#include "7zip/Archive/IArchive.h"
#include "7zip/IPassword.h"
#include "7zip/IProgress.h"
#include "7zip/IStream.h"

Z7_DEFINE_GUID(CLSID_CArchiveHandler, ...);
```

两点值得记：

- **`ICoder.h` 必须列进来**，尽管 SunPack 从不直接创建 coder：`7zDecode.obj` /
  `CoderMixer2.obj` 会 QueryInterface 找 `IID_ICompressCoder` /
  `IID_ICompressCoder2` / `IID_ICompressFilter`。漏了就是 175 个 LNK2001。
- **`CLSID_CArchiveHandler` 不在任何接口头里**，必须显式定义——`CreateArchiver()`
  用它做格式解析。原来这个 definition 是 `DllExports2.cpp` 顺带产生的。

### 14.4 DLL export 层裁剪

删除 `CPP/7zip/Archive/DllExports2.cpp` 与 `CPP/7zip/Compress/CodecExports.cpp`：

| 文件 | 原职责 | 现状 |
|------|--------|------|
| `DllExports2.cpp` | `DllMain` / `CreateObject` / `SetLargePageMode` / `SetCaseSensitive` / `SetCodecs`，并顺带产生 GUID definition | 全部无调用者；GUID 职责已迁走。`NT_CHECK` 在 `_WIN64 + _UNICODE` 下展开为空操作 |
| `CodecExports.cpp` | 对外 codec factory（`CreateCoder` / `CreateHasher` / `CreateDecoder` / …） | 唯一调用者是 `DllExports2::CreateObject()`，已退出调用链。7-Zip handler 内部走的是 `Common/CreateCoder.cpp` 的 `g_Codecs` registry，不受影响 |

**保留编译单元 230 → 228**，`docs/zh-CN/sevenzip_retained_sources.txt` 已重新生成，
CMake 的 configure 期断言同步改为 228。

### 14.5 验证

| 验证 | 结果 |
|------|------|
| x64 Release 编译 + 链接 | 通过 |
| `ctest`（bridge 4 个单测） | 4/4 通过 |
| `pytest tests/unit tests/cli` | 1128 通过 |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |
| 保留编译单元数 | 228（清单与源码树一致） |
| 53 处 override 对上游接口的真实性 | 由编译器 C3668 反向证明——不匹配就报错 |

### 14.6 收尾后的状态

```text
SunPack
  ↓
#include 官方 7-Zip 头（PRIVATE，仅 CPP 子树）
  ↓
create_in_archive() → ::CreateArchiver()
  ↓
真正的 ::IInArchive / ::IInStream / ::IArchiveExtractCallback ...
```

`CreateObjectFunc` / `embedded_create_object` / `create_object` / 手抄接口 /
手抄 IID / 手抄 PropID / 手抄 operation-result / `ComModule` / `LoadLibrary`
全部退出 bridge。

### 14.7 下一步（架构师列的第四步）

```text
ComPtr → CMyComPtr      注意 refcount 语义不同：ComPtr(raw) 接管已有引用不 AddRef，
                        CMyComPtr(raw) 会 AddRef；必须与 refs_ = 1 的初始语义同批迁移
QueryInterface/AddRef/Release → CMyUnknownImp + Z7_COM_UNKNOWN_IMP_*
CoInitializeEx / CoUninitialize 退出（需先确认无 CoCreateInstance 依赖）
Ole32 链接依赖退出（OleAut32 要留：SysAllocString / PROPVARIANT / VariantClear）
```

本轮刻意停在这里：refcount 语义变更与类型迁移混在一起会让 refcount bug 难以定位。

---

## 16. 修复：IProgress 的 QueryInterface 语义回归

### 16.1 问题

§15.2 把 `ExtractCallback` 与 `ExtractToDiskCallback` 迁成宏时，QI 集合写成：

```cpp
Z7_COM_UNKNOWN_IMP_2(IArchiveExtractCallback, ICryptoGetTextPassword)
```

但重构前这两个类的 `QueryInterface` 明确接受 4 个 IID：

```text
IID_IUnknown                    ← Z7_COM_QI_ENTRY_UNKNOWN 覆盖
IID_IProgress                   ← 丢了
IID_IArchiveExtractCallback
IID_ICryptoGetTextPassword
```

**`Z7_COM_UNKNOWN_IMP_N` 只为传入的 IID 生成 entry，不会沿 C++ 基类向上补全。**
所以 `QI(IID_IProgress)` 由 `S_OK` 变成 `E_NOINTERFACE`。

### 16.2 严重程度：语义回归，不是功能 bug

已核实 **上游 7-Zip 源码中不存在任何针对 `IProgress` 的 `QueryInterface`**
（`grep QueryInterface|IsEqualGUID|== IID_` + `IProgress` 命中 0）。
handler 是通过 `IArchiveExtractCallback*` 的 vtable 直接调用 `SetTotal`/`SetCompleted` 的。
所以 8/8 验收测不到这条路径，行为也没变。

但**契约既然声明过就必须保住**：这类"恰好没人调用"的缺口一旦将来被调用方依赖，
排查成本极高。所以按最小改动修复。

### 16.3 修复

```cpp
Z7_COM_UNKNOWN_IMP_3(IArchiveExtractCallback, IProgress, ICryptoGetTextPassword)
```

两处（`ExtractCallback`、`ExtractToDiskCallback`）。
`IProgress *ti = this;` 合法，因为 `IArchiveExtractCallback` 本身继承 `IProgress`。

### 16.4 新增契约测试：`tests/com_contract.cpp`

`ctest` 第 5 个用例 `sunpack_sevenzip_com_contract`，覆盖：

```text
ExtractCallback          QI(IUnknown/IProgress/IArchiveExtractCallback/ICryptoGetTextPassword) == S_OK
                         QI(无关 IID) == E_NOINTERFACE
                         QI(IProgress) 结果可调用 SetTotal
ExtractToDiskCallback    同上
OpenCallback             QI(IUnknown/IArchiveOpenCallback/IArchiveOpenVolumeCallback/ICryptoGetTextPassword) == S_OK
FileInStream             QI(IUnknown/ISequentialInStream/IInStream) == S_OK
MultiRangeInStream       QI(ISequentialInStream/IInStream) == S_OK
```

两点实现说明：

- 生成的 `QueryInterface` 是 **private**（宏以 `private:` 开头），所以测试统一通过
  `IUnknown*` 调用——这也正是 7-Zip handler 触达它的方式。
- 测试**确实能抓到本次回归**：把宏退回 `_2` 并干净重建后，报 3 项失败
  （`QI(IProgress) == S_OK` ×2 + `SetTotal callable`）。

### 16.5 一个值得记住的构建陷阱

验证过程中出现过"同一份代码，一个二进制通过、另一个失败"的假象，浪费了不少排查时间。
根因是**增量构建没有重新编译 `sunpack_sevenzip_core` 里的 `sevenzip_callbacks.hpp` TU**，
旧 `.obj` 被继续使用。删除整个 `build-x64` 从零重建后行为立刻一致。

结论：**改了 bridge 头文件后，若要验证运行期行为，必须干净重建**，
否则会看到与源码不符的结果。

### 16.6 验证

| 验证 | 结果 |
|------|------|
| 干净全量重建（删除 build-x64） | 通过 |
| `ctest` | 5/5 通过（含新契约测试） |
| `pytest tests/unit tests/cli` | 1128 通过 |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |
| 契约测试抓回归能力 | 回退宏后 3 项失败，符合预期 |

> 附注：本轮验收第一次运行时有 1 个用例失败
> （`test_watch_root_output_routing.py`，`.sunpack-partial-*` 目录缺失），
> 单独与并行重跑均通过，第二次完整验收 8/8 通过——判定为既有竞态 flake，
> 与本次改动无关。本次改动已核实为行为惰性（上游不 QI `IProgress`）。

---

## 17. 阶段 3A：恢复官方 x64 解压汇编

本轮只做一件事：让 x64 构建使用上游 7-Zip 的汇编热点实现。原则与 COM 阶段相同——
**纯性能实现替换，不碰算法语义和数据通路**：archive / buffer / callback / worker
代码零改动，五个 C 回退文件被同符号的 `.asm` 替换，`LzmaDec.c` 只把内核函数外包。

### 17.1 启用集

```text
x64:
  LzmaDecOpt.asm      ON   LzmaDec_DecodeReal_3
  7zCrcOpt.asm        ON   CrcUpdateT12
  XzCrc64Opt.asm      ON   XzCrc64UpdateT12
  AesOpt.asm          ON   AesCbc_{Decode,Encode}_HW[_256] / AesCtr_Code_HW[_256]
  Sha1Opt.asm         ON   Sha1_UpdateBlocks_HW
  Sha256Opt.asm       ON   Sha256_UpdateBlocks_HW

  Sort.asm            OFF  压缩侧（HuffEnc / BwtSort）
  LzFindOpt.asm       OFF  压缩侧（LzFindMt）

ARM64:
  保持 C/intrinsics，不引入新 assembler toolchain
```

### 17.2 两组 OBJECT library，不混

```text
sunpack_7zip_objects        7-Zip C/C++    /O2 /Oi /Ot /GL /Gy /Gw /GF
sunpack_7zip_asm_objects    x64 MASM only  无任何 C/C++ flag
```

`sup7z_attach_bundled_7z(target)` 同时注入两组。汇编单独成库的理由很实际：
`/GL`、`/Oi`、`/Gy` 这些都不是 `ml64.exe` 的合法开关，混进同一个 target 会让 MASM
收到一堆 C/C++ flag。

`7zAsm.asm` **不是编译单元**，它是每个 `.asm` 顶部 `include` 的宏头文件，靠
`target_include_directories(... Asm/x86)` 找到。

### 17.3 两种替换模型

**① 整文件替换（5 个）** —— `.asm` 与 `.c` 提供**完全相同的外部符号**，必须二选一：

| C 回退 | 被替换为 | 符号 |
|--------|----------|------|
| `C/7zCrcOpt.c` | `Asm/x86/7zCrcOpt.asm` | `CrcUpdateT12` |
| `C/XzCrc64Opt.c` | `Asm/x86/XzCrc64Opt.asm` | `XzCrc64UpdateT12` |
| `C/AesOpt.c` | `Asm/x86/AesOpt.asm` | `AesCbc_Decode_HW` / `AesCbc_Decode_HW_256` / `AesCbc_Encode_HW` / `AesCtr_Code_HW` / `AesCtr_Code_HW_256` |
| `C/Sha1Opt.c` | `Asm/x86/Sha1Opt.asm` | `Sha1_UpdateBlocks_HW` |
| `C/Sha256Opt.c` | `Asm/x86/Sha256Opt.asm` | `Sha256_UpdateBlocks_HW` |

**"ASM + C 一起编"不是保守选择，是直接不可行**：两套定义同名外部符号，链接期
`LNK2005`。所以 x64 是**移除** C 回退，不是"加上"汇编。

判定用 `list(FILTER ... EXCLUDE REGEX "/C/<name>$")` 而不是绝对路径 `REMOVE_ITEM`：
`GLOB_RECURSE` 返回的路径分隔符跟随 `SUP7Z_7Z_ROOT` 的写法，精确字符串匹配可能静默
不命中，然后在链接期才以 `LNK2005` 暴露。

**② 部分替换（1 个）** —— `LzmaDec.c` **必须继续编译**，只把内核外包：

```cpp
# 未定义 Z7_LZMA_DEC_OPT        # 定义 Z7_LZMA_DEC_OPT
static int LzmaDec_DecodeReal_3(...)   int LzmaDec_DecodeReal_3(...)   ← 外部 ASM
{ /* C 实现 */ }
```

CMake 用 `set_source_files_properties` 把宏**只**给这一个 TU，不给整个 7-Zip target。

### 17.4 两个数字分开，不合并

configure 期的物理裁剪 sanity check 仍然是 **228**，而且**刻意放在架构选择之前**：

```text
check 1（先执行）  源码树 = 228 个 .c/.cpp           ← "树有没有被意外加删"
check 2（后执行）  x64: 228 - 5 = 223               ← "本架构选中哪个实现"
```

合并成一个数就会把"源码树变了"和"x64 选了 ASM 还是 C"混成同一个症状。
x64 最终实际编译量是 **223 个 C/C++ + 6 个 ASM**，而不是保留集从 228 变成 229。

第三个检查：`SUP7Z_X64_ASM_ENABLED` 时逐个断言 6 个 `.asm` 都存在，避免"半个树
+ 汇编开关"这种最难查的组合。

### 17.5 开关与构建脚本

```cmake
option(SUP7Z_USE_X64_ASM
       "Use upstream 7-Zip x64 assembly hot paths (...)"
       ON)
```

这不是用户功能配置，而是 **benchmark / 回退 / 排障开关**。它的价值在于让
"ASM ON vs OFF"可以落在**同一个 commit**上比较，而不是拿"旧 7z.dll vs 新源码版"
去比——后者因为中间已经改过 COM、factory、source linking、QoS，变量太多。

能生效的前提是目标架构确实是 x64。判定用**编译器上报的架构**，
不是生成器平台名，更不是指针宽度：

```cmake
if(MSVC)
    if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID)      # 权威来源，任何生成器都正确
        set(SUP7Z_TARGET_UARCH "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}")
    elseif(CMAKE_C_COMPILER_ARCHITECTURE_ID)
        ...
    elseif(CMAKE_GENERATOR_PLATFORM)            # 仅 VS 生成器会设置
        ...
    else()
        set(SUP7Z_TARGET_UARCH "unknown")
    endif()
endif()

# 白名单：只有精确等于 x64 / AMD64 才启用，其余一律 OFF
if(SUP7Z_TARGET_UARCH STREQUAL "x64" OR SUP7Z_TARGET_UARCH STREQUAL "AMD64")
```

两个曾经的坑，都记在这里以免回退：

| 写法 | 问题 |
|------|------|
| `CMAKE_GENERATOR_PLATFORM` 优先 | **MSVC + Ninja 下为空**，ARM64 会落到下一步 |
| 回退 `CMAKE_SIZEOF_VOID_P EQUAL 8` | **64 位不等于 x64**。ARM64 也是 64 位，于是 MSVC + Ninja ARM64 会被误判成 x64，去 `enable_language(ASM_MASM)` 并编译 `Asm/x86/*.asm` |

`CMAKE_CXX_COMPILER_ARCHITECTURE_ID` 在 MSVC ABI 下区分 `x64` / `ARM64` / `ARM64EC` /
`X86`，对 Visual Studio 与 Ninja 都给得出正确答案（本机 VS `-A x64` 实测为 `x64`）。
**无法确定的架构一律记作 `unknown` 并关闭汇编**——这是架构特定代码，
宁可少启用，也绝不猜。

判定逻辑做过 12 组真值表验证（用真实 CMake 跑，只喂变量不依赖工具链）：

```text
VS -A x64            → x64      ON     VS -A ARM64        → ARM64    OFF
VS -A ARM64EC        → ARM64EC  OFF    VS -A Win32        → X86      OFF
Ninja x64            → x64      ON     Ninja ARM64        → ARM64    OFF   ← 曾经的 bug
id/plat 都为空       → unknown  OFF    AMD64 拼写         → AMD64    ON
只有 C id            → ARM64    OFF    未知架构串         → RISCV64  OFF
非 MSVC              → unknown  OFF
```

`scripts/build_windows.ps1` 与 `scripts/setup_windows_dev.ps1` 都**显式传**
`-DSUP7Z_USE_X64_ASM=ON`，并在构建后调用共享的

```text
scripts/sevenzip_asm_check.ps1  →  Assert-SevenZipAsmSelection
```

它做三件事：

```text
① 从 sunpack_7zip_asm_objects.dir\Release\LzmaDecOpt.obj 精确解析
   LzmaDec_DecodeReal_3 这个符号（名字必须完全一致，找不到就报错）
② 取它所在的 32 字节 ml64 序言（读 COFF 节表 + 符号表，不依赖 dumpbin，不硬编码字节）
③ 在四个二进制里按字节搜索：
       build\Release\sunpack_sevenzip.dll
       build\Release\sunpack_sevenzip_worker.exe  ← 大文件解压真正跑的进程
       tools\sunpack_sevenzip.dll
       tools\sunpack_sevenzip_worker.exe
```

判定：

```text
x64 且缓存里 SUP7Z_USE_X64_ASM=ON（默认）     → 任一命中 < 1 就 throw，构建失败
x64 且缓存里显式 SUP7Z_USE_X64_ASM=OFF       → 跳过（这是合法的 A/B 配置）
ARM64 / 非 x64                               → 跳过
```

为什么 build 目录和 `tools\` 都要查：`tools\` 那两份才是产品真正加载的，
只查 build 目录会在拷贝步骤出问题时漏检；而 worker 才是大文件解压的执行者，
"只证明 DLL 带汇编"不是完整结论。

COFF 解析里有两个容易写错的地方，已在注释里标明：

| 错误写法 | 真相 |
|----------|------|
| `$bytes[$entryOffset + 17]` 当 name length | 那是 **NumberOfAuxSymbols**。section symbol 都带 1 个 aux，而"取第一个 external function 就返回"恰好因为目标符号排在最后且 `naux=0` 才碰巧正确 |
| aux entry 当普通 symbol 解析 | 索引必须前进 `1 + NumberOfAuxSymbols` |
| 名字 union 判断 | 前 4 字节全 0 → bytes 4..7 是 string table 偏移；否则 0..7 是内联名字、NUL 截断 |
| 循环变量命名 `$symbolName` | **PowerShell 变量名大小写不敏感**，会覆盖 `$SymbolName` 参数，使每次比较都对着刚解析出的名字，等于永远匹配。已改名 `$candidateName` |

成功时输出（四行，对应四个二进制）：

```text
7-Zip asm check passed: LzmaDec_DecodeReal_3 present in sunpack_sevenzip.dll (1 match(es), 32 byte prologue).
7-Zip asm check passed: LzmaDec_DecodeReal_3 present in sunpack_sevenzip_worker.exe (1 match(es), 32 byte prologue).
```

校验强度刻意停在这里：**LZMA 一处代表性最终链接证明已经足够**，再叠加六个符号各一套
PE 扫描只会增加测试复杂度。已有的证据组合（6 个 `.obj` 必须存在 + C twin 必须消失 +
无 LNK2005 + 代表符号在四个产物里命中）覆盖面已经充分。

### 17.6 增量构建与 Release 配置

**构建是增量的。** `Reset-StaleCMakeBuildDir` 只在缓存里的 `CMAKE_HOME_DIRECTORY`
指向别的源码树时才删整个 `build-*` 目录；平台不匹配时只删 `CMakeCache.txt` +
`CMakeFiles`。没有任何 `--clean-first` / `Rebuild` 调用。依赖跟踪交给 MSBuild/Ninja，
源码发现交给 `GLOB_RECURSE ... CONFIGURE_DEPENDS`（每次构建重新 glob 并自动重跑
configure）。实测重复 `cmake --build` 的输出只有 target 名，没有 `Assembling`、
`正在编译`、`正在生成代码`，即全部判定为最新。

**是 Release 优化。** 两个脚本都传 `--config Release`，全部产物落在 `Release\`：

```text
CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
  → /GL（编译期）+ WholeProgramOptimization
  → /LTCG + /OPT:REF + /OPT:ICF（链接期）
apply_release_optimizations() 按目标再加
  → /O2 /Oi /Ot /Gy /Gw /GF
```

生成的 vcxproj 已核对：`sunpack_7zip_objects`（Release）为
`<Optimization>MaxSpeed</Optimization>` + `<IntrinsicFunctions>true</IntrinsicFunctions>`
+ `<WholeProgramOptimization>true</WholeProgramOptimization>`；`sunpack_sevenzip.dll`
为 `LinkTimeCodeGeneration=UseLinkTimeCodeGeneration` +
`OptimizeReferences=true` + `EnableCOMDATFolding=true`。（`Debug|x64` 下这些位是
`<Optimization>Disabled</Optimization>`，所以别用 Debug 做性能判断。）

**唯一没有 Release 优化位的是 `sunpack_7zip_asm_objects`**，这是刻意的：那是手写汇编，
MASM 没有优化开关，而 C/C++ 的 `/O2 /Oi /Ot /GL /Gy /Gw /GF` 会被 ml64 拒绝。
生成的 vcxproj 里它的 Release `<MASM>` 组只有 include 路径、`CMAKE_INTDIR` 和
`GenerateDebugInformation=false` —— 这正是把汇编拆成独立 OBJECT library 的目的。

**切换 `SUP7Z_USE_X64_ASM` 必须换构建目录**，CMake 现在会强制这一点：

```text
build-x64\sup7z_asm_last_selection.txt  记录上次的 SUP7Z_X64_ASM_ENABLED
  同目录下再次 configure 且取值变化 → FATAL_ERROR，提示删除目录或另开 build-asm-off
```

理由：翻转选项会换掉源文件列表，上一次运行的 `.obj` 会留在 `sunpack_7zip_objects.dir`
里。它们不会被链接（列表已重新生成），但 A/B 对比恰恰是最不能容忍"某个对象被悄悄复用"
的场景，所以宁可拒绝配置。本文件 §17.6 的 `build-asm-on` / `build-asm-off` 就是这么做的。

### 17.7 验证

| 验证 | 结果 |
|------|------|
| x64 配置（ASM ON） | 通过；`Found assembler: ml64.exe`，检查 1/2/3 全部通过 |
| x64 Release 编译 + 链接 | 通过，**无 LNK2005**（否则说明某个 C 回退没被移掉） |
| x64 配置（`-DSUP7Z_USE_X64_ASM=OFF`） | 通过；提示 `using upstream C/intrinsics` |
| 两组 ABI 产物 | `sunpack_sevenzip.dll` / worker 均生成 |
| `ctest` ASM ON | 5/5 通过 |
| `ctest` ASM OFF | 5/5 通过 |
| `pytest tests/unit tests/cli` | 1132 通过 |
| `run_acceptance_tests.ps1 -Arch x64` | 8/8 步骤全部 PASS |
| `setup_windows_dev.ps1 -Arch x64` | 通过（含四行 `7-Zip asm check passed`） |
| 架构判定真值表（真实 CMake 跑，12 组） | 12/12 符合预期，仅 `x64` / `AMD64` 为 ON |
| 构建期 asm 断言的分支覆盖 | ON→四个二进制全通过；ARM64→跳过；显式 OFF→跳过；x64 无 MASM 对象→throw；符号名不匹配→throw；产物缺失→throw |
| 符号解析反例 | 请求 `HeapSort` / `CrcUpdateT12` / `AesCbc_Decode_HW` / `LZMADEC_DECODEREAL_3`（大小写不同）一律返回"未找到"，不返回任何随机符号 |
| 负对照（ASM=OFF 的 worker/DLL） | MASM 序言命中 **0**；把它换进 `tools\sunpack_sevenzip_worker.exe` 后断言按预期 throw |

**"汇编真的进去了"的证据链**（不是"配置说要启用"）：

| 环节 | 证据 |
|------|------|
| MASM 真的跑了 | 构建日志 6 条 `Assembling ...Asm\x86\*.asm` |
| 汇编对象真的提供符号 | `dumpbin /symbols` 每个 `.obj` 的 External 表：`LzmaDec_DecodeReal_3`、`CrcUpdateT12`、`XzCrc64UpdateT12`、`AesCbc_Decode_HW[_256]`、`AesCbc_Encode_HW`、`AesCtr_Code_HW[_256]`、`Sha1_UpdateBlocks_HW`、`Sha256_UpdateBlocks_HW` |
| C 回退真的被移掉 | ASM ON 的 obj 目录里 5 个 C 回退 `.obj` **不存在**，C TU 计数 = **223**；ASM OFF 时 228 个全在 |
| **MASM 代码真的在最终产物里** | 在 `LzmaDecOpt.obj` 的 `LzmaDec_DecodeReal_3` 序言中取 32 字节机器码（`53 55 56 57 41 54 41 55 41 56 41 57 48 8D 44 24 80 …`），在 ASM ON 的 **四个**产物里各命中 **1 次**：`sunpack_sevenzip.dll`、`sunpack_sevenzip_worker.exe`（build 目录）与 `tools\` 下同名的两份；在 ASM OFF 的 DLL / worker 里命中 **0 次** |
| 这四条现在是**构建期强制**的 | `scripts/sevenzip_asm_check.ps1` 在两个构建脚本里执行同一套检查，任一产物未命中即 `throw` |

最后一条是决定性的：符号表会被 LTCG 吃掉、section 名会被合并进 `.text`，但编译器
生成的 MASM 序言字节序列不会凭空出现。取 0 次的那两个是负对照。
worker 必须一起查——它是大文件解压真正跑的进程，"只证明 DLL 带汇编"不是完整结论。

### 17.8 预期收益怎么看

不要期望"所有解压 +30%"。更现实的分布：

```text
LZMA decoder core（LzmaDec_DecodeReal_3）  最大提升，官方历史数据约 +30%（仅 decoder core）
端到端 LZMA2                              取决于 I/O、async writer、prefetch，必然低于纯 core
XZ LZMA2                                  LZMA + CRC64
ZIP Deflate                               主 decoder 没换，只得到 CRC32 加速
stored ZIP / TAR                          CRC/IO 可能受益，没有 LZMA ASM 收益
加密包                                     AES 路径可能有较明显提升
Zstd / Bzip2                              基本不受这批 ASM 影响
```

SunPack 已经把读/解码/写重叠得比较激进，decoder 加速后瓶颈很可能进一步往
writer / memcpy / storage 移动——这反而是好事：汇编恢复单变量做完，再做 buffer
ownership 时才能清楚看到 `CPU decoder 瓶颈 → ASM → memory copy/writer 瓶颈 →
zero-copy → I/O 瓶颈` 这条迁移路径，而不是同时改两个变量。

### 17.9 本轮刻意没做

```text
Sort.asm / LzFindOpt.asm                  压缩侧，不解压热点
ARM64 汇编（Asm/arm64/LzmaDecOpt.S）      GNU assembler 语法，接不进 MSVC -A ARM64
Sha512Opt.asm                            上游同样存在，但不在本批 6 个之内
buffer ownership / prefetch / memcpy      阶段 3B/4
COM 层任何改动                            已封板
```
