# SunPack Rust 分卷识别最终重构方案

> 基于当前仓库提交：`74980aa141adcef7a9d0f4a2e638be2fc47d23a3`（`优化分卷识别`）
>
> 目标：把当前偏“文件名先提出 relation proposal、结构后验证”的流程，重构成真正的 **structure-first volume resolution**：结构信息先固定所有确定事实，文件名只补结构无法确定的 slot，最终校验尽量只消费前面已经取得的结构事实，不重复 I/O。

---

## 1. 当前实现基线

当前 Rust 主流程主要集中在：

- `native/sunpack_native/src/scan/directory.rs`
  - `populate_relation_anchors()`：目录扫描阶段批量 cheap probe。
  - `filesystem_file_route()`：`rar / 7z / zip / sfx` 路由到 Relations。
- `native/sunpack_native/src/analysis_native/volume_anchor.rs`
  - cheap / deep `VolumeAnchor` 探测。
  - 已经能输出 `format`、`internal_volume_number`、`anchor_roles`、`continuation_*`、`expected_logical_size`、`structure_offset`、`sfx`、`pe_structure` 等结构事实。
- `native/sunpack_native/src/relations/mod.rs`
  - `DirectoryNameIndex`：按 first-dot stem 建桶，并提前解析文件名候选。
  - `NumberShape`：从单个 seed 推数字位置。
  - `DirectoryNameIndex::proposals()`：当前主要 proposal 构造入口，结构事实和文件名推测交织。
  - `structural_volume_number()` / `resolved_volume_number()` / `loose_volume_number()`：当前卷号决策分散在多层 fallback 中。
  - `make_name_proposal()`：把文件名推测结果组装为 relation proposal。
  - `validate_relation_proposal()`：后置结构验证，会再次 deep probe proposal 内文件。
  - `promote_sfx_archive_anchor()`：PE/SFX 二次提升，验证 stub profile、overlay 和真实归档结构。
  - `seed_strength_for_row()` 当前还包含 raw-byte-split RAR SFX 特判。

当前大致是：

```text
cheap seed
    ↓
first-dot stem bucket
    ↓
文件名候选 / proposal
    ↓
后置 deep structural validation
    ↓
RelationGroup
```

主要问题不是“当前完全没有结构信息”，而是：**结构事实取得得太晚、使用得不集中，文件名 proposal 先行，导致已有结构信息不能自然成为 assignment 的硬约束，并产生重复 probe。**

---

## 2. 重构后的总流程

最终流程统一为：

```text
cheap seed
    ↓
first-dot stem bucket
    ↓
Bucket structural analysis
    ├─ 复用 cheap anchor
    ├─ 只补缺失的结构事实
    ├─ 固定 exact slots / roles / SFX role
    └─ 不做文件名猜测
    ↓
Structural constraints propagation
    └─ 能由现有 slot 唯一推出的 unknown 直接填
    ↓
Filename inference
    ├─ format-specific NumberChannel
    ├─ structural-anchor-derived NumberChannel
    └─ generic global NumberChannel
    ↓
得到 0 / 1 / >1 个不同的最终 path→slot mapping
    ↓
最终结构校验（复用已采集 facts，避免重复读取）
    ↓
RelationGroup / Incomplete / Corrupt
```

核心原则：

> **结构只提供确定事实；文件名只填 unresolved slot；结构确定的 slot 永远不能被文件名覆盖。**

---

## 3. first-dot bucket 规则

继续保留当前 `DirectoryNameIndex::rows_by_stem` 的 first-dot stem 思路，不扩大目录搜索范围。

例如：

```text
shared.part1.foo
shared.part2.bar
shared.part3.bin
```

都进入 `shared` bucket。

### 3.1 bucket 只有一个文件时不能无条件走单文件

原计划中的：

```text
bucket size == 1 → single-file
```

需要改成：

```text
bucket size == 1
    ├─ anchor 没有 multivolume / continuation / split 证据
    │      → single-file path
    │
    └─ anchor 已经结构证明是 multivolume
           → 仍进入 volume relation path
```

原因：只有 `foo.7z.001`、`foo.part1.rar` 等文件存在时，bucket 虽然只有一个成员，但结构已经明确这是分卷的一部分，不能错误降级成 standalone。

单文件 SFX 仍走现有单文件 SFX 路径，不进入分卷 assignment。

---

## 4. 新核心数据模型

建议不要继续让 `ParsedVolume / NumberShape / RelationProposal` 同时承担结构事实、名称事实和最终 assignment。

### 4.1 StructuralFacts

```rust
struct StructuralFacts {
    path: String,
    format: ArchiveFormat,

    exact_slot: Option<u32>,
    role: VolumeRole,

    has_previous: Option<bool>,
    has_next: Option<bool>,

    numbering_style: Option<NumberingStyle>,

    sfx_role: SfxRole,
    structure_offset: Option<u64>,

    expected_logical_size: Option<u64>,

    encrypted: bool,
    needs_password: bool,

    // 原始 VolumeAnchor/evidence 可继续保留，便于最终 validator 使用。
    anchor: Option<VolumeAnchor>,
}
```

建议角色：

```rust
enum VolumeRole {
    First,
    Middle,
    Terminal,
    FirstAndTerminal,
    Unknown,
}

enum SfxRole {
    None,
    ArchiveBearingFirst,
    LauncherCompanion,
    Unknown,
}
```

结构阶段允许“部分成功”：

```text
exact #1
terminal but slot unknown
middle but slot unknown
completely unknown
```

这些都不是结构分析失败，而是留给后续约束传播 / filename inference。

### 4.2 NameFeatures

每个文件名只解析一次：

```rust
struct NameFeatures {
    numeric_occurrences: Vec<NumberOccurrence>,
    format_specific: Vec<FormatNameCandidate>,
}

struct NumberOccurrence {
    value: u32,
    width: usize,
    start: usize,
    end: usize,
    left_context: ...,
    right_context: ...,
}
```

数字范围：

- 默认只解析文件名 **第一个点号之后** 的部分；
- 如果没有点号，则解析完整文件名；
- 每个最大连续数字串是一个 occurrence；
- `chunk2`、`foo2bar`、`.2.` 都产生数字 `2`；
- 不再区分“孤立数字”和“嵌入字母的数字”。

7z 特例只在目标格式为 7z 时生效：

```text
7z token 中的字面量 7 不进入 generic numeric channel
```

ZIP/RAR 不继承这个例外。

### 4.3 NumberChannel

替换当前 `NumberShape`。

```rust
struct NumberChannel {
    kind: ChannelKind,
    occurrence_selector: ...,
    context: ...,
}
```

`NumberChannel` 表示：**整个 bucket 中哪一条稳定的数字通道代表 volume number**。

例如：

```text
shared.build1.chunk1.bin   // structural #1
shared.build1.chunk2.bin
shared.build1.chunk3.bin
```

从第一卷会产生两个候选 channel：

```text
build<N> → 1,1,1 → 全局失败
chunk<N> → 1,2,3 → 全局成功
```

复杂度只需：

```text
O(K × bucket_size)
```

其中 K 是 plausible channel 数量，通常只有 1～4，不做 slot 之间的笛卡尔积。

### 4.4 VolumeAssignment

```rust
struct VolumeAssignment {
    format: ArchiveFormat,
    slots: BTreeMap<u32, usize>, // slot -> row index
    companions: Vec<usize>,
    unresolved: Vec<usize>,
}
```

最终 filename solver 比较的是 **完整 path→slot mapping**，而不是“用了哪条规则”。

不同 channel 如果得到相同 mapping：

```text
A→1, B→2, C→3
```

要 canonicalize / deduplicate，视为同一个解。

---

## 5. 结构分析阶段统一规则

### 5.1 I/O 原则

结构分析必须：

1. 复用 `DirectorySnapshot` 里已有 cheap `VolumeAnchor`；
2. 只对当前 bucket 内、当前格式真正缺失的结构信息追加 probe；
3. 一个 path 的同一结构字段不要在 relation 过程中重复读取；
4. 密码发现后允许对 encrypted facts 做一次“信息升级”，但不是无条件重跑整个 bucket；
5. 最终 validator 应消费缓存的 `StructuralFacts`，而不是再次从头 deep probe 全部 volumes。

---

# 6. RAR5 规则

RAR5 是最适合 structure-first 的格式。

## 6.1 普通 RAR5 volumes

cheap 阶段当前就可能把每一个 RAR5 volume 路由到 Relations。

结构阶段对所有 RAR5 候选卷：

```text
Main Archive Header
→ volume flag
→ volume number
→ exact slot
```

当前 `rar5_main_volume()` 已经具备该能力，内部 number 转换为 SunPack 1-based slot。

因此正常 RAR5：

```text
#1 → exact
#2 → exact
#3 → exact
...
```

所有现存 volume 都有 exact slot 时：

> **完全不进入 filename inference。**

文件名即使完全伪装也不能覆盖结构卷号。

## 6.2 ENDARC

结构阶段同时取得 RAR5 End of Archive 信息，至少保留：

```text
has_next / ENDARC.next_volume
terminal role
```

用于 relation 状态判断。

## 6.3 Header encryption

发现 header-encrypted RAR5：

```text
cheap encrypted fact
→ 调用现有 password probe
→ 解 main header
→ exact slot / relation facts 升级
```

不要因为密码变化把整个目录 relation pipeline 从零再跑；只升级受密码影响的 `StructuralFacts`，然后重新执行纯内存 assignment。

## 6.4 RAR5 SFX

如果 bucket 内存在 `MZ` unknown exe：

不能仅凭 MZ 认作第一卷。

使用当前 `promote_sfx_archive_anchor()` 已有能力：

```text
PE structure
→ SFX stub profile
→ overlay/archive offset
→ probe embedded RAR5 header
→ 结构证明它是 RAR5 SFX first volume
→ exact #1
```

确认后：

```text
SfxRole::ArchiveBearingFirst
exact_slot = 1
```

## 6.5 删除 raw-byte-split SFX 特判

删除当前 `seed_strength_for_row()` 中专门支持“完整 RAR SFX 被再次物理裸切”的 `raw_sfx_split_seed` 分支及对应 synthetic 测试。

这类输入不是主流工具正常生成布局，不再污染主 relation 模型。

---

# 7. RAR4 规则

RAR4 与 RAR5 必须明确分开建模：

> **RAR5：每卷通常有 exact identity；RAR4：第一卷身份强，中间卷通常只有关系信息。**

## 7.1 第一卷

解析 Main Header：

```text
MHD_FIRSTVOLUME
→ exact #1
```

## 7.2 EARC_VOLNUMBER

如果 ENDARC 中真的存在 volume number：

```text
EARC_VOLNUMBER
→ exact slot
```

但它必须降级为：

> **legacy bonus fact，不作为现代 RAR4 正常排序方案的基础。**

不能假定常见 RAR4 每个成员都一定能从 ENDARC 拿 exact number。

## 7.3 EARC_NEXT_VOLUME

解析：

```text
EARC_NEXT_VOLUME
→ has_next
→ terminal / non-terminal role
```

这是结构角色事实，不等价于 exact slot。

## 7.4 MHD_NEWNUMBERING

解析：

```text
MHD_NEWNUMBERING
→ NumberingStyle::RarPart / RarOldStyle
```

只用于后续 filename inference 选择正确的 format-specific channel：

```text
partNN.rar
vs
.rar / .r00 / .r01 ...
```

不能拿它直接推结构 slot。

## 7.5 split-before / split-after

如果当前已有 RAR4 file-header continuation 信息，可保留为：

```text
has_previous
has_next
Middle / Terminal 等角色约束
```

供纯内存 assignment / validator 使用。

## 7.6 RAR4 SFX

与 RAR5 一样：

```text
MZ candidate
→ PE/SFX + embedded RAR4 structure
→ 证明为当前 family 的 SFX first volume
→ exact #1
```

## 7.7 哪些 RAR4 member 进入 filename inference

结构阶段之后：

```text
exact #1
exact #N（若 legacy EARC_VOLNUMBER 存在）
terminal but slot unknown
middle slot unknown
```

只有 slot 仍 unknown 的成员进入 filename inference。

---

# 8. ZIP 规则

ZIP 要区分：

```text
标准 multi-disk ZIP
普通 single-disk ZIP
raw byte-split ZIP stream
SFX launcher + external volume set
```

Relation slot 结构推断重点只使用确定性事实。

## 8.1 第一卷

当前 cheap probe 的 `zip:split_marker` 是强 first-volume evidence：

```text
PK 07 08 + valid local header
→ exact #1
```

但单纯：

```text
PK 03 04 local header
```

只能是 weak first candidate，因为后续 disk 也可能恰好从新的 local entry 开始。

所以：

```text
cheap ZIP candidate
→ 若已有 split marker → exact #1
→ 若只有 local-header weak anchor → 做必要的后续结构提升
→ 只有 first-disk/split-start 被证明后才固定 #1
```

这也与当前 `cheap_seed_strength()` 把 `zip:local_header` 降为 weak 的行为一致。

## 8.2 terminal EOCD

扫描 bucket 内 ZIP 候选尾部。

发现标准 multi-disk EOCD：

```text
this_disk = N (0-based)
→ 当前文件 role = Terminal
→ exact slot = N + 1
```

## 8.3 ZIP64

只有经典 EOCD disk 字段为 ZIP64 sentinel / overflow 时：

```text
→ 再解析 ZIP64 EOCD / locator
→ 获得真实 disk number
```

正常 EOCD 已给有效 disk number 时，不为 relation 排序专门继续解析 ZIP64。

ZIP64 的 `total disks` 可以保留为结构事实或最终 validator 一致性信息，但不是排序必经路径。

## 8.4 Central Directory

Central Directory 的 `disk number start` 对“当前物理文件到底是第几卷”没有足够直接收益。

本次 relation slot solver 不以完整 CD walk 为核心，不为了排序额外引入 CD 扫描成本。

## 8.5 ZIP 中间卷

无法从结构得到 exact slot 的中间 disk：

```text
→ filename inference
```

结构已确定 terminal role 但没有 exact number 的特殊场景，也作为带 role 约束的 unresolved member 进入 solver。

## 8.6 ZIP SFX launcher

当前 SunPack 的 SFX profile 支持：

```text
seven_zip_sfx → 7z / zip
winrar_sfx    → rar / zip
```

对于 split ZIP + MZ candidate：

```text
验证 PE
→ 验证 seven_zip_sfx / winrar_sfx profile
→ 同 bucket 已有结构确认的 external ZIP volume family
→ 证明该 EXE 是当前 family 的 launcher companion
→ 不参与 slot numbering
```

注意：**stub profile 匹配本身不够**，还必须建立它与当前 external ZIP family 的 ownership 关系，防止把同 stem 的独立 SFX EXE 错粘到另一个 ZIP volume set。

单文件 ZIP SFX 走单文件路径，不进入 split assignment。

---

# 9. 7z 规则

7z 分卷本质是一个逻辑 7z stream 的物理切片。

## 9.1 第一卷

有效 7z Start Header：

```text
→ exact #1
```

当前 `probe_seven_zip()` 已经能把第一卷标为 `internal_volume_number = 1`。

同时保留当前已有：

```text
expected_logical_size
```

供最终 validator 使用，不需要再次读取 Start Header。

## 9.2 后续卷

普通 7z continuation chunks 没有独立 volume identity：

```text
#2..#N
→ filename inference
```

不对 opaque continuation volume 反复做无收益 deep probe。

## 9.3 7z SFX launcher

如果 bucket 内存在 MZ candidate：

```text
验证 seven_zip_sfx stub/profile
+ 证明同 bucket 存在 external 7z volume family
→ SfxRole::LauncherCompanion
→ 不占 slot
```

单文件 7z SFX 走单文件路径。

raw-byte-split 整个 SFX 的特殊支持删除。

---

# 10. 结构约束传播

结构阶段结束后，先不进入 filename parser，而是做一次纯内存约束传播。

例如：

```text
A → #1
B → unknown
C → #3
```

B 的合法 slot domain 只有 `{2}`：

```text
→ B = #2
```

可以直接确定，不需要文件名。

但：

```text
A → #1
B → unknown
```

不能因为“只剩一个 unknown”就直接填 `#2`，因为 `#2` 可能本来就缺失，B 也可能是后面的卷。

因此规则必须是：

> **只有 unresolved member 的合法 slot domain 唯一时，才直接结构约束填充。**

不是“只剩一个不知道的文件就直接补连续号”。

---

# 11. 文件名模糊推测最终方案

## 11.1 只处理 unresolved

已经有：

```text
exact_slot = Some(N)
```

的文件永远跳过 filename inference。

SFX launcher companion 同样跳过。

## 11.2 文件名只解析一次

对 bucket 内相关文件统一构造 `NameFeatures`，后面所有格式特异规则和 generic solver 复用。

不要在不同 fallback 中重新 regex / 重新扫描数字。

## 11.3 优先级

最终优先级：

```text
1. structural exact slot
2. format-specific canonical channel
3. structural-anchor-derived global NumberChannel
4. generic global NumberChannel
```

文件名永远不能覆盖结构。

---

# 12. format-specific filename channels

这些是强 filename semantics，但仍然只作用于 unresolved member。

## 12.1 RAR new numbering

如果 `MHD_NEWNUMBERING` 指示 new style：

```text
part1
part02
part003
...
```

识别 `part<N>` channel：

```text
N → volume N
```

不要采用“循环 N 然后找字符串”，直接解析 token value。

## 12.2 RAR old style

old style：

```text
archive.rar → #1
archive.r00 → #2
archive.r01 → #3
...
```

因此 `.rNN` 的映射必须保留旧 RAR 语义，而不是把 `r00` 当 slot 0/1。

## 12.3 ZIP

标准 spanned 命名：

```text
.z01 → #1
.z02 → #2
...
.zip → terminal（slot 优先来自结构 EOCD）
```

对 unresolved `.zNN` 直接形成 ZIP-specific channel。

## 12.4 7z

优先识别 canonical / format-associated numeric suffix，例如：

```text
.7z.001
.7z.002
...
```

在目标格式为 7z 时，`7z` token 中的 `7` 不参与 generic number candidate。

---

# 13. Global NumberChannel 推断

format-specific channel 仍无法完成 assignment 时，进入全局 channel solver。

## 13.1 channel 从所有结构 anchors 生成

不能再像当前 `NumberShape::from_seed()` 一样只依赖单个 first seed。

假设结构已经知道：

```text
A = #1
D = #4
```

任何 NumberChannel 必须同时满足：

```text
channel(A) = 1
channel(D) = 4
```

这样可以快速淘汰大量假数字通道。

## 13.2 示例

```text
shared.build1.chunk1.bin → structural #1
shared.build1.chunk2.bin
shared.build1.chunk3.bin
```

候选：

```text
build<N> → 1,1,1 → reject
chunk<N> → 1,2,3 → valid
```

再例如：

```text
shared.release2026.part1.chunk01
shared.release2026.part2.chunk02
shared.release2026.part3.chunk03
```

不要逐 slot 贪心地“找 2、找 3”。

生成若干稳定 channel，一次评价整个 bucket。

## 13.3 不使用“数字位数最少”作为核心决策

例如：

```text
foo.build2.chunk0002
```

真正 volume channel 完全可能是 `chunk0002`。

所以 width 只能作为 channel 特征 / tie-break 信息，不能成为“更短数字优先”的决定性规则。

---

# 14. Mapping 判定

所有 channel 都必须产生 **完整的候选 assignment**，不允许每个 slot 各自独立选择候选并做笛卡尔组合。

最后 canonicalize：

```text
path A → #1
path B → #2
path C → #3
```

按最终 mapping 去重。

结果：

```text
0 distinct mappings
→ Incomplete / unresolved

1 distinct mapping
→ 接受 assignment

>1 distinct mappings
→ AmbiguousVolumeMapping
→ 外部调度语义按 incomplete / missing-volume 处理
```

也就是说多解不能任选一个，也不进入最终深校验赌结果。

---

# 15. 同桶多 head / 混合格式

### 15.1 多个同格式 head

如果强 format-specific channel 能明确分成不同 family，可以分别处理。

否则 generic inference 产生多个不同 mapping：

```text
→ ambiguous
→ incomplete
```

不选择“看起来最像”的一个。

### 15.2 多个不同格式 head

按目标格式独立建立 `StructuralFacts + assignment`：

```text
RAR bucket view
ZIP bucket view
7z bucket view
```

结构 format evidence 优先决定成员归属。

unknown opaque row 如果无法唯一归属，不要跨格式猜测。

---

# 16. 未被 assignment 采用的 bucket 文件

不能简单“推完连续卷号后，把剩下未知全部踢出桶”。

要分两类：

### 16.1 无结构 ownership 的普通同 stem 文件

如果最终唯一 assignment 不需要它：

```text
→ 不 claim
→ 返回正常后续 discovery / residual 路径
```

### 16.2 已经有当前格式结构证据的文件

如果一个文件已经结构证明属于当前 RAR/ZIP/7z family，却无法放入唯一 slot：

```text
→ 不能静默踢出
→ assignment 应视为 unresolved / ambiguous / conflict
```

否则会出现“真正的分卷成员因为 filename solver 没选中而被当普通文件”的错误。

---

# 17. 最终结构校验

保留 SunPack 现有最终 validator 的职责，但重构输入方式。

旧流程：

```text
name proposal
→ validate_relation_proposal()
→ 对 proposal paths 再 deep probe
```

新流程：

```text
StructuralFacts 已经完成必要 I/O
+ unique VolumeAssignment
→ final validator
```

最终 validator：

1. 复用 `StructuralFacts.anchor` 和已经取得的 format-specific facts；
2. 不重复读取已经验证过的 Main Header / EOCD / Start Header / SFX overlay；
3. 只有当前面尚未取得、且最终校验真正需要的新字段时才追加 I/O；
4. filename mapping 失败 / 多解属于 relation incomplete，不应该被包装成 archive corruption；
5. assignment 已唯一，但结构自相矛盾或归档语法验证失败，才进入 corrupt/reject 类错误。

现有 `ProposalStatus::{Valid, NeedsPassword, Reject, Unsupported, Inconclusive}` 可以暂时保留，再逐步把内部原因细化。

建议内部新增明确 reason：

```rust
enum RelationFailureReason {
    MissingVolume,
    AmbiguousVolumeMapping,
    StructuralConflict,
    NeedsPassword,
    CorruptArchive,
    Unsupported,
}
```

其中 Watch 层可继续把：

```text
MissingVolume
AmbiguousVolumeMapping
```

统一视为“等待目录变化后重试”。

---

# 18. 对当前 Rust 代码的迁移方案

## 18.1 保留

保留并复用：

- `first_dot_stem()` / stem bucket 思路；
- `RelationInput` / `NativeRelationGroup` 公共输出形态（优先避免上层 Python 大改）；
- `VolumeAnchor` 及现有 cheap probe；
- `promote_sfx_archive_anchor()` 的 PE / SFX profile / overlay 验证能力；
- 当前 RAR password probe；
- 当前 format-specific 低层 parser；
- 当前最终 validator 中仍有价值的结构一致性逻辑。

## 18.2 替换

### `DirectoryNameIndex`

保留 `rows_by_stem`，但职责拆开：

```text
BucketIndex
    → 只负责 stem/path/index

NameFeatureIndex
    → 文件名数字和 canonical format token，一次解析
```

不要在建 bucket 时过早形成 volume proposal。

### `NumberShape`

删除，替换成：

```text
NumberChannel + global hypothesis evaluation
```

解决当前“seed 中有多个相同数字位置就直接放弃”的问题。

### `resolved_volume_number()` / `loose_volume_number()`

拆掉“结构 / strict filename / loose filename 混合 fallback”的职责。

改成明确两层：

```text
StructuralFacts.exact_slot
FilenameSolver::resolve_unresolved(...)
```

### `DirectoryNameIndex::proposals()`

替换为类似：

```rust
resolve_bucket(
    bucket,
    structural_facts,
    name_features,
    format,
) -> BucketResolution
```

内部顺序固定：

```text
structure
→ constraint propagation
→ format-specific channels
→ global channels
→ mapping dedupe
```

### `make_name_proposal()`

弱化为最终 output materialization：

```text
VolumeAssignment
→ RelationProposal / NativeRelationGroup
```

它不再负责猜卷号。

### `validate_relation_proposal()`

拆成：

```text
StructuralFactCollector
FinalRelationValidator
```

前者负责所有必要 I/O；后者尽量纯内存消费 facts。

## 18.3 删除

删除：

- `raw_sfx_split_seed` 特判；
- 为“完整 SFX 被固定大小裸切”专门存在的 relation 分支；
- 对应 synthetic integration tests；
- 依赖单 seed `NumberShape` 的 loose recovery 路径；
- 逐 slot / 逐 N 贪心找文件的算法。

---

# 19. 推荐的 Rust 模块拆分

如果 `relations/mod.rs` 已经过大，这次适合顺手拆：

```text
relations/
├─ mod.rs                 // public entry / NativeRelationGroup
├─ bucket.rs              // first-dot buckets
├─ structural.rs          // StructuralFacts collection
├─ sfx.rs                 // SFX role classification
├─ filename.rs            // NameFeatures / NumberChannel
├─ assignment.rs          // constraint + mapping solver
├─ validate.rs            // final validation
└─ output.rs              // RelationProposal / dict materialization
```

不一定一次全部拆完，但逻辑边界应按这个方向形成。

---

# 20. 性能目标

### 文件 I/O

```text
cheap scan：已有，复用
结构补充：每 path / 每必要字段最多一次
密码成功后：只升级受密码影响 facts
最终 validator：优先纯内存
```

### filename

```text
每 filename 只 tokenize 一次
```

### assignment

```text
O(total_filename_length + K × bucket_size)
```

其中 K 为 NumberChannel hypotheses 数量。

禁止：

```text
O(N²) 每 slot 重扫整个目录
笛卡尔积组合 slot candidates
validator 对前面已经分析过的所有文件再次全量 probe
```

---

# 21. 测试迁移方案

## 21.1 应保留/加强的真实测试

优先保留当前已有真实工具生成测试：

- mixed real `7z / zip / rar` volumes；
- RAR structural volume ordering；
- modern split ZIP (`.z01 ... .zip`)；
- encrypted plain + SFX volume matrix；
- SFX launcher + external 7z/ZIP volumes；
- RAR SFX first-volume；
- missing middle / missing tail；
- competing heads / same-stem mixed formats；
- filename camouflage / false numeric markers；
- Watch arrival-order / missing-volume lifecycle。

## 21.2 删除

删除专门构造：

```text
[MZ + complete archive]
→ Python 手工固定大小 byte split
```

的 raw-SFX-split 测试及其特殊实现要求。

## 21.3 新增 NumberChannel 测试

必须覆盖：

```text
build1.chunk1
build1.chunk2
build1.chunk3
```

结构 #1 能选 `chunk<N>`，拒绝 `build<N>`。

以及：

```text
A #1
D #4
```

用两个结构 anchor 同时约束 channel。

还要覆盖：

- 两条不同 channel 产生相同 mapping → 去重为一个解；
- 两条 channel 产生不同 mapping → ambiguous；
- 一个 unresolved 但 slot domain 不唯一 → 不直接补号；
- 一个 unresolved 且 slot domain 唯一 → 不读文件名直接补；
- 7z 文件名中的 `7z` 数字 7 不参与 generic channel；
- `002` / `0002` 宽度不同仍可属于同一数值 channel；
- 同 stem unrelated 文件不被 claim；
- structurally-owned 但无法 assignment 的文件不能被静默踢出。

## 21.4 RAR4 测试

明确分开验证：

```text
MHD_FIRSTVOLUME → #1
MHD_NEWNUMBERING → filename scheme only
EARC_NEXT_VOLUME → relation role
EARC_VOLNUMBER → 如果出现则 exact slot，但不是正常路径依赖
```

---

# 22. 最终状态机

```text
Directory scan
    ↓
cheap anchors
    ↓
Relations seeds
    ↓
first-dot buckets
    ↓
┌─────────────────────────────────────┐
│ bucket size == 1                    │
│                                     │
│ no split structural evidence        │──→ single file
│ split structural evidence           │──→ relation path
└─────────────────────────────────────┘
    ↓
StructuralFactCollector
    ↓
SFX classification
    ├─ archive-bearing RAR first → #1
    ├─ 7z/ZIP launcher → companion
    └─ ordinary member
    ↓
format-specific structural slot discovery
    ↓
constraint propagation
    ↓
unresolved exists?
    ├─ no → assignment
    └─ yes
         ↓
      NameFeatureIndex
         ↓
      format-specific NumberChannel
         ↓
      structural-anchor-derived channels
         ↓
      generic global channels
         ↓
      canonicalize final mappings
         ↓
      0 → incomplete
      1 → assignment
      >1 → ambiguous/incomplete
    ↓
FinalRelationValidator
    ↓
Valid → RelationGroup
NeedsPassword → password flow
Incomplete/Ambiguous → Watch wait/retry
Structural corruption → corrupt/reject
```

---

# 23. 最终设计原则

本次重构最终应满足以下不可破坏的约束：

1. **Structure wins**：结构 exact slot 永远覆盖文件名。
2. **Filename only fills holes**：只有 unresolved 才进入名称推断。
3. **All structural anchors participate**：不能只使用第一卷 seed。
4. **Global mapping, not per-slot greed**：文件名规则必须评价整个 bucket mapping。
5. **No Cartesian search**：候选是 channel，不是 slot 候选组合。
6. **One path, one structural read plan**：同一结构事实不重复读取。
7. **One filename, one parse**：名称数字只 tokenize 一次。
8. **Bucket-local**：关系识别只消费当前 first-dot bucket，不扩大搜索范围。
9. **SFX is layout, not archive format**：先确定 archive-bearing / launcher，再交给 RAR/ZIP/7z resolver。
10. **Ambiguity is not corruption**：多解 / 无解按 incomplete relation 处理；只有唯一 assignment 后结构失败才是 archive corruption。
11. **Do not silently discard structurally owned members**。
12. **Public pipeline contract 尽量保持**：优先让 `NativeRelationGroup` 以上层接口不变，只重写 Rust 内部 relation resolver。

---

## 24. 一句话总结

这次重构不是简单把：

```text
filename → structure validation
```

换成：

```text
structure → filename
```

而是把 Relations 从“**根据文件名提出若干 archive proposal，再用结构判断猜得对不对**”升级为：

> **先把整个 bucket 的结构事实一次性变成硬约束，再把剩余未知卷号建模成一个小规模的全局映射问题；文件名只是求解这个映射的辅助证据，最终 validator 只验证唯一解。**

这应该成为 SunPack 后续分卷识别的稳定长期架构。
