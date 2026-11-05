# 实际写入者调查与覆盖清单

核对日期：2026-11-05。覆盖单位是会改变目标文件可观察历史、内容完整性或可读性的机制，不是软件品牌或随机分布名称。这里追求机制覆盖的系统性，不声称穷尽所有应用和未来行为。每个程序都必须改变范围、调度、阶段、可见性或句柄事实；仅换名字、mtime 标签或 `writer` 编号不算独立覆盖。

## 一手证据

| 编号 | 官方文档或源码 | 已确认的实际机制 |
|---|---|---|
| A | [aria2 手册](https://aria2.github.io/manual/en/html/aria2c.html)，`--split`、`--file-allocation`、`--stream-piece-selector`、`--continue`、`--disk-cache`、`--check-integrity`；[SegmentMan.cc](https://github.com/aria2/aria2/blob/master/src/SegmentMan.cc) | 多源分段、不同选片顺序、分配空间、断点状态、片段重新分配、内存缓存后按偏移写回、损坏片段重下 |
| B | [rclone multi-thread transfers](https://rclone.org/docs/#multi-thread-cutoff)，[local backend](https://rclone.org/local/)，[inplace](https://rclone.org/docs/#inplace) | 多线程直接写不同偏移；Windows 稀疏文件和预分配选项；临时 `.partial` 完成 rename 与直接最终名两种发布方式 |
| C | [Chromium DownloadFileImpl](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/download/internal/common/download_file_impl.cc)，`ValidateAndWriteDataToFile`、`CalculateBytesToWrite`、`AddNewSlice` | 多输入流、接收范围合并、恢复前缀验证、重叠区域处理和文件长度约束；不是“一连接追加到 EOF” |
| D | [BitTorrent 作者设计论文](https://bittorrent.org/bittorrentecon.pdf)，[libtorrent 手册](https://www.libtorrent.org/manual-ref.html)，[缓存机制说明](https://www.libtorrent.org/features.html#disk-caching) | rarest-first 和先完成一片的子块；peer 速率差异、校验与恢复；用户态写缓存可按片或压力集中写回。缓存说明页面标明旧版本，只引用其已存在机制，不当作当前默认配置 |
| E | [Syncthing 同步机制](https://docs.syncthing.net/users/syncing.html)，[rsync inplace/partial/delay-updates](https://rsync.samba.org/ftp/rsync/rsync.1.html) | 本地复用与网络新块混合，临时文件提交；原位增量更新、部分保留和批量 rename。来源说明机制，不要求运行或安装这些客户端 |
| F | [Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)，[curl continue-at](https://curl.se/docs/manpage.html#-C) | 连接中断后恢复到检查点，也可能从头重试；复制后保留时间戳。Robocopy `/MT` 是文件复制并发，不能据此声称单文件分段 |
| G | [yt-dlp FragmentFD](https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/downloader/fragment.py)，`download_and_append_fragments`、`_append_fragment` | 多线程接收片段，按消费次序追加组装，flush 和侧车状态更新；慢的早期片段可阻塞后续已经收到的片段 |
| H | [CreateFileW sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)，[SetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime) | 是否能读由 sharing 和仍打开的句柄决定；close 不等于内容完成，mtime 可被主动恢复 |
| I | [libarchive ZIP writer](https://github.com/libarchive/libarchive/blob/master/libarchive/archive_write_set_format_zip.c)，`archive_write_zip_close`；[7-Zip 7zOut.cpp](https://github.com/ip7z/7zip/blob/main/CPP/7zip/Archive/7z/7zOut.cpp)，`Create_and_WriteStartPrefix`、`WriteStartHeader`；[Update.cpp](https://github.com/ip7z/7zip/blob/main/CPP/7zip/UI/Common/Update.cpp) | ZIP 尾部 central directory/EOCD；7z 起始 32 字节占位后 seek 回填；多输出卷。这里仅复现写入顺序，不实现压缩格式分析 |
| J | [FlushViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-flushviewoffile)，[Windows cache manager](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/subsystem/cache-memory-management/) | 映射修改不保证自动更新 mtime；可见缓存写与刷到存储介质是不同边界 |
| K | [CfHydratePlaceholder](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfhydrateplaceholder) | 占位符已有逻辑长度，但指定范围可能尚未在本地，hydration 可异步补齐 |
| L | [NZBGet download health](https://nzbget.com/documentation/understanding-download-health-in-nzbget/)，[目录和处理阶段](https://nzbget.com/documentation/nzbget-path-and-folder-structure-guide/) | 分段文件先组装，缺失/错误区域之后校验和 PAR2 修复，再发布。复用已有坏块修复、组装和多卷机制，不另造一个只换品牌的场景 |

## 28 个可执行 writer programs

| family | 实际生成的行为 | 独立覆盖／依据 |
|---|---|---|
| segmented_preallocated | EOF 一次到最终长度，2/4/8 个连接分别推进连续范围 | size 不再表示进度；A/B |
| segmented_sparse | 不预设最终 EOF，高偏移流先写会留下洞，其余流继续补齐 | EOF 接近最终值但低位仍缺块；B/C |
| segmented_straggler | 大部分范围快速结束，一个连接慢 15–60 倍，尾部只剩它推进 | 聚合写频率从多流变单流；A/B，速率差为压力参数 |
| segmented_work_stealing | 每个连接有不同完成速度，最早空闲的连接领取下一未分配块 | 动态领取与静态范围分区产生不同完成次序；A 的片段分配机制启发，不宣称逐行仿真 aria2 |
| segmented_retry_overlap | 一个流中途断连等待，其他流继续；恢复后重复写已经收到的跨块重叠区间 | 重试次数不等于新增进度；A/C |
| segmented_resume | 随机半数块已经到达，保存侧车/关闭；长暂停后新连接补剩余洞 | 恢复的是离散范围而非简单 EOF；A |
| segmented_restart | 部分分段已经写入，恢复失败后截断，切换顺序写完整目标 | 字节进度回退、算法旧频率跨阶段残留；A/C，失败路径为合成组合 |
| segmented_finalize_rename | 多连接写监控范围外的临时文件，校验暂停，再 rename 发布目标路径 | 完整内容早于目标可见；B 的发布机制投影，发布差异独立于下载节奏 |
| torrent_rarest_first | 为 12 片生成 peer 可用性，按稀缺度选片，每片四块，实际 writer/偏移依选择改变 | 有选片状态的乱序覆盖，替代简单随机 offset 标签；D |
| torrent_recheck_repair | 若干片段确实写坏，覆盖不计有效；检查后暂停，补写错误块 | 全长、全部位置都写过仍不正确；A/D；L 的修复同样复用此原语 |
| cached_piece_writeback | 网络收包与目标写入分开；每八块按 offset 集中排空用户缓存 | 快写簇与长空档由缓存形成，而非直接造间隔列表；A/D |
| fragment_assembly | 分片并发先到 staging；消费顺序追加到目标，早期慢片阻塞后续片 | 网络活跃但目标静默，之后快速组装；G/L |
| sync_reused_blocks | 大部分正确块快速从本地复制，少量块等待网络，校验后从监控范围外一次发布 | 快本地／慢远端的复合阶段及原子发布；E 的块复用/提交机制投影 |
| sync_inplace_delta | 全长旧文件中仅部分区域已与目标一致；原位更新缺失范围，随后恢复旧 mtime | 长度始终相同、已有块不伪造成新 IO、增量覆盖；E/H |
| copy_restartable | 顺序复制到一半，中断关闭，等待后从检查点边界重传并继续 | 有序前缀恢复区别于分段位图恢复；F |
| copy_restart_from_zero | 中途失败，重新建立文件身份，从零复制，最后恢复 mtime | identity 更替与历史状态退休；F，重建路径为合成失败组合 |
| close_reopen_batches | 每批独占打开、写入、关闭；批间有真正可读的长暂停 | 中间 close/可读不能证明永久结束；H |
| shared_handle_tail | 内容写齐后共享读句柄仍留存，稍后关闭 | 不能把有打开句柄都当忙；H |
| exclusive_commit_tail | 内容写齐后不兼容句柄仍持有，稍后释放 | 首次有效提案必须等到实际能读，等待从到达起计；H |
| archive_directory_last | 顺序写压缩内容，计算阶段静默，最后追加目录与结束记录 | 内容尾部的结构性最后写入；I |
| archive_header_backpatch | 32 字节起始占位，写后续 payload/索引，静默后仅回填起始 32 字节 | 最后正确性取决于小范围覆盖，EOF 不变；I |
| multipart_serial | 每组四卷按序开始、各自渐进写入，前卷可早已静默 | 真实卷间到达间隙和齐卷时刻；I |
| multipart_parallel | 四卷同时推进，共享组时间尺度而成员速度不同；可并发多组 | 齐卷屏障、跨文件交错，区别于单文件多流；B/I 的组合 |
| multipart_late_volume | 三卷先结束，最后一卷中途保存状态、长暂停再补齐 | 已稳定成员不能掩盖迟到成员；A/I 的组合 |
| mapped_page_batches | 全长文件分批覆盖散布页，mtime 保持不变，另有 flush 动作 | 已分类内容变化与 mtime 脱钩；J。只模拟可见性投影，不模拟 mmap 的内核通知生成 |
| cloud_hydration | 完整逻辑长度的占位符先静默，再异步填充散布范围，最后一个范围拖慢 | 逻辑 EOF 与本地数据可用性分离；K。读取主动触发 hydration 不在此回放内 |
| cancelled_holes | 文件全长，留下三个随机洞，保存状态后取消 | 从未完整的有界负例；A/E |
| paused_holes | 同样留下洞并暂停，在观察区间中不恢复 | 不能把录制停止或长静默标为完成；A/F |

上述某些程序是跨实现机制的压力组合，表中已明确标出，不能当成指定软件默认配置的精确重放。尤其不能把所有预分配都等同于设置 EOF：本语料专门选择 EOF 已增长的写法；仅预留物理空间但不增长 EOF 的实现，在观测上归入相应逐步增长程序。

## 参数和因果关系

每个文件有 48 个块（BT 为 12 片 × 4 块），块长从 16/32/64/128/256 KiB 选择。基础写入步长为 `10**Uniform(-3,-0.1)` 秒，各连接或块有额外不同速度；暂停从 0.5/3/30/300/3600 秒级选择并乘 0.7–1.3 抖动。连接数 2/4/8，坏块和未填洞为三个，块复用为四分之三。这些是可复现 stress 范围，不是线上频率估计或经验概率。

阶段会因果约束后续写入：分片没到不能组装；重叠重试只能出现在相关范围已收到之后；截断会清掉超出新长度的有效范围；错误数据不贡献覆盖；缓存尚未排空不算到达；rename 不生成新内容；已读取共享句柄留存不改变内容和可读性。末次同内容重传可以晚于内容完整时刻，评分仍从内容真正写齐开始。

同一 split/seed/family/file 在不同通知通道和并发前缀中共享物理随机流，通知随机性独立。多卷共享组时间尺度；并发组只通过确定的时间线交错，本基准不凭虚拟线程编号宣称测过 OS 争用吞吐。

## 不扩充为独立场景的项目

- `.aria2`、`.ytdl`、临时索引或校验文件活动：作为 writer 控制阶段保留，不冒充目标文件写入，不按侧车种类复制场景。
- BT endgame 重复网络请求、限速、重连、磁盘背压：影响目标写入的部分由重复范围、末尾拖慢、暂停和缓存排空覆盖；不把收到重复网络包等同于重复落盘。
- Usenet PAR2 与其他断点工具：复用错误块修复、分片组装、分卷和发布机制。没有新增品牌同义场景。
- 编辑器保存、压缩包更新、复制临时名提交：其可观察机制归入截断/重建、头尾回填、临时发布和 mtime 恢复，不增加与该静默算法无关的格式笛卡尔积。
- 核心算法看不到扩展名、加密、嵌套深度或载体布局，不把它们做成随机标签扩充计数；实际档案能力仍由原有 Rust 与端到端基准覆盖。

尚不能据此声称完整覆盖内核级 mapped IO 通知、远端 SMB 缓存一致性、cloud provider hydration 回调、设备竞争和所有真实客户端失败路径。需要实际带真值轨迹时，应通过同一轨迹合同导入；不能把无法确认的 OS 行为编造成“实际 Windows 随机丢末次通知”的新场景。
