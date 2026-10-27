# 解压 worker 的内存管理

内存状态和准入、回收、恢复均由 C++ worker 持有。Python 只转发诊断与等待提示，CLI 和 watch 使用同一协议。旧的 `NativeMemoryGuard` 和按内存压力缩减 CPU credit 的监控已移除。

## 分配与预算

- 4 MiB 是通用的**分配粒度**，不是格式、文件、输出或字典的大小上限。这个粒度包含 LZ4 的最大合法块缓冲及其校验/历史开销；小分配继续走原分配器，不跟踪单个 1 MiB 写入缓冲。LZMA/LZMA2 可变字典从 2 MiB 起在共用入口纳管；空闲池跨设施合计至少 8 MiB 时整批回收。
- 7-Zip 的 My/Mid/Big allocator、字节缓冲和解码子线程接入同一上下文。仅 worker 可执行文件替换 C++ 大对象分配，覆盖未经过 7-Zip allocator 的大容器。Python 进程没有替换分配器。
- LZ4 通过库提供的 custom allocator 接入，包含独立流和归档内 codec。ENC 的 Rust FFI 使用同一管理器提供的对齐、清零 Argon2 工作区，在 KDF slice 边界响应取消，返回前擦除并释放。共享 Rust 分析 API 仍使用原工作区。
- zlib-ng 的输入、输出缓冲各 512 KiB，Deflate 字典 32 KiB；ENC 的 payload 缓冲 256 KiB；LZ4 的调用端输入、输出缓冲各 256 KiB。这些固定小分配保留原路径，明确内存错误仍由任务边界处理。

每次大分配都在管理锁下检查剩余额度，提交和释放按 Windows 页大小记账，避免多个字典重复消费同一份空间。系统快照最多复用约 250 ms，期间扣除每笔新增的大提交、归还实际释放的提交；额度不足、Windows 低内存通知、真实分配失败、进入恢复队列及缓存回收后立即重新查询。保留大块提交的短临界区，移除普通分配中反复执行的系统查询，没有把监测加入解码字节热路径。

查询物理预算时扣除 worker 预留，默认 **128 MiB + 16 MiB × nominal CPU credit**，再扣除本进程尚未驻留的私有提交量，避免把未触碰的字典误当成空闲内存。系统提交额度保留相同字节数；进程可提交额度仍参与取小。支持 EX2 的系统使用 private working set，旧系统回退到 EX working set。

预留服务于未纳管小分配、线程/CRT、输出设施和恢复提交，不随物理内存容量增长，也不实际分配同等大小的内存块。根据最终 sizing plan 在启动时计算，不随借还 credit 波动。`performance.worker.memory_reserve_bytes` 默认 0 表示自动，正数仍为固定字节覆盖；Python 只转发配置。依据和边界见 [CPU credit 预留测量](worker_memory_cpu_reserve.md)，历史固定预留测量保留备查。Job 查询与细密采样仍只进入专用测试 executable。

SDK 新建解码线程前也复查预算；已处于压力时返回明确的内存错误，交给同一 fallback/重放路径。worker 的线程仍保留原 1 MiB 虚拟栈，初始提交改为 64 KiB，避免只提交默认 4 KiB 时，新线程尚未进入应用代码就因 Windows loader 扩栈失败而终止进程。这不是把线程栈纳入细粒度管理，也不改变线程额度。

恢复以明确失败的申请加上当时仍占用的工作区为依据，包含重新取得字典的需求；历史上可选并行路径的峰值不再永久充当门槛。没有明确申请的外部撤销保留撤销时观测到的占用；外部容量真实增长至少一个 4 MiB 纳管粒度后，也可保留当前实际可用的预算、尝试更省内存的执行。自身释放的提交和未消费 admission 不算外部增长，防止自我释放后反复重放。真实 VirtualAlloc 失败额外保留严格增长条件，失败时先重新查询，避免旧的乐观快照成为无法达到的恢复门槛。

恢复保留的 admission 随实际分配消耗，重放记录不重复收费。早期撤销保留前次已观测的失败需求；重放临时保留一个每 credit 的小工作区余量，已观测字典建立后重新采样、归还余量。余量放不下时仍允许一个满足实际字典需求的任务尝试。没有新增按机器大小或格式猜测的水位，也没有修改 CPU credit、线程容量和磁盘设施配置。

## 回收与恢复

先归还尚未消耗的恢复预算，再成批释放跨写入设施合计不少于 8 MiB 的空闲池，绝不释放 IOCP 仍引用的内存。缓存回收由监控线程执行，写入唤醒在管理锁外执行，避免大容器在持有写入锁时扩容造成锁顺序反转。仍不足时，在任务边界撤销占用最大的一个大型工作区；已有撤销足以覆盖缺口时先等它真正释放，再决定下一次回收。大块分配被拒绝时请求缓存回收，并允许解码器现有的串行 fallback；仅失败的尝试进入重放。解码结束即释放 handler 和缓存字典，随后才排空输出和保存必要的重放记录。

撤销使用独立的 attempt token。原用户取消 token 不会被恢复操作清除。现有磁盘 gate、异步生产者等待和输出排空自然响应 attempt token；解码器、额外 CPU credit、基础 CPU credit、卷设施租约释放后，任务进入 worker 的等待队列。等待不占执行线程，也不占 CPU credit，后续小任务仍可执行。等待任务计入原有队列背压额度，避免无限累积任务状态。

使用 Windows `CreateMemoryResourceNotification` 响应系统低/高内存事件。Windows 的通知存在中间区间，也不支持应用自定的固定预留，因此有活动任务或内存等待时补充每 250 ms 采样。分配侧同时检查快照年龄和低内存通知；空闲 worker 不启动采样定时器。

额度恢复后按实测需求逐个保留预算并回到原 foreground/watch 队列。只有连一个等待任务都无法继续、且没有其他任务在推进时，发送 `memory_blocked`；恢复发送对应 `memory_resumed`。`memory_reclaimed` 保留诊断记录，但不改变 Python 的任务生命周期。内部中断不输出最终失败、密码错误或损坏结论。

任务边界还处理 MSVC `std::thread` 创建资源不足的 `EAGAIN`，记录 `memory_thread_resource_retry` 并沿原路径重试，覆盖不经过 SDK allocator 的写入线程。输出路径准备保留明确的 `bad_alloc` 为 `E_OUTOFMEMORY`，避免被普通路径/写入错误掩盖。其他未识别的异常仍返回明确的任务结果。

## 输出重放

每个文件记录磁盘**成功完成**的字节范围，包括乱序完成、短写和跨失败的空洞。连续范围只保存一个端点，只有空洞使用区间容器。正常完成不额外复制一份输出清单；仅在中断时保存输出路径、已确认范围和必要目录映射。

恢复仍重新解码并验证原格式的校验。已落盘范围只推进逻辑输出位置，不重新写盘；空洞沿原异步写入链路补齐，使用原有输出路径，保持重名、目录冲突和硬链接关系。解码器、字典和输出 buffer 不跨尝试保留。恢复前检查原输入文件的大小和时间；输入改变返回 `input_changed` 要求重新扫描，不混用两个输入的输出收据。这个检查不是第二套格式分析。

该机制是同一 worker 生命周期内的资源恢复，不是程序崩溃后的持久化断点续传。

## 验证与边界

`sunpack_sevenzip_memory_replay` 覆盖并发大块准入、容量收缩/扩张、8/16/32 GiB 按 1:256 缩放后的 2/16/128 credit 自动预留模型、低于历史峰值的恢复、不增长时不重放、页尾提交及整数溢出、乱序与短写后的精确重放、两种磁盘/内存恢复顺序及 CPU credit 归还。缩放模型不代表在三种物理机器上做了实测。

Python 的真实 worker 测试使用 `sunpack_sevenzip_memory_worker`，将真实 Job 剩余提交量作为测试系统提交量；2 credit 的初始额度为 160 + 48 MiB，验证小任务可继续、等待可取消、增加额度自动恢复、输入变化不会继续使用旧收据。协议测试覆盖同步与 asyncio 两条传输以及 CLI/watch 提示；原有 ENC、LZ4、密码、分卷、载体、嵌套和输出正确性测试继续使用。手动格式矩阵和真实分配开销比较见 [本轮测量](worker_memory_optimization.md)。

检查和外部程序提交内存之间不能建立跨进程原子性；Windows 也没有针对应用自定剩余额度的即时通知。本设计用分配前检查、系统通知、活动采样、按并发规模计算的预留和任务重放覆盖正常压力，不保证进程在系统瞬间完全耗尽提交额度时一定能执行恢复代码。该预留也不是任意并发、任意条目数的未纳管总量上限；已提交的小内存本来就在可用量中扣除，预留主要缓冲下一次检查前的增长。

参考：[Windows 内存通知](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-creatememoryresourcenotification)、[进程内存信息](https://learn.microsoft.com/en-us/windows/win32/psapi/process-memory-usage-information)、[Job 提交额度](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)、[Windows 线程栈](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size)、[Velox 内存仲裁与粗粒度任务回收](https://facebookincubator.github.io/velox/develop/memory.html)。格式支持仍以项目的 `reference/specifications` 和已有解码器为准。
