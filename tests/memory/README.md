# Watch 内存增长测试

解压 worker 的固定预留测量使用独立测试可执行文件和 Windows Job，见 [测量说明](../../docs/worker_memory_reserve.md)。执行示例：

```powershell
cmake --build native/sevenzip_bridge/build-x64-ci --config Release --target sunpack_sevenzip_memory_probe sunpack_sevenzip_memory_worker --parallel 4
.venv/Scripts/python.exe tests/memory/worker_reserve_probe.py <压缩包路径> --format 7z --jobs 8 --dynamic
```

它不属于默认 pytest 收集；需要时手工测量。Job 限额、CPU 限额和 2 ms 采样均只用于测试子进程。

全格式手动矩阵：`.venv/Scripts/python.exe tests/memory/worker_format_probe.py --jobs 32`。
可用 `--corpus <目录>` 加入独立的旧 ZIP/RAR/7z 样本，`--case` 选择执行组。
动态压力 probe 用 `--dynamic`，较快样本加 `--cpu-rate 25`，`--volumes 32` 测独立写入设施的叠加。
当前默认固定预留为 512 MiB；`--reserve-mib 256` 保留旧预留对照。
机制、完整测量与 A/B 命令参数见 [worker 内存优化报告](../../docs/worker_memory_optimization.md)。

运行长期、大量文件的 watch 内存测试：

```powershell
.\.venv\Scripts\python.exe -m pytest --run-performance -s tests/memory/test_watch_growth.py
```

测试默认处理 4 批、每批 2 个 64 MiB 归档；归档内容采用流式生成，不会因为构造测试文件而额外占用同等 Python 内存。可用环境变量缩放测试：

- `SUNPACK_WATCH_MEMORY_BATCHES`
- `SUNPACK_WATCH_MEMORY_FILES_PER_BATCH`
- `SUNPACK_WATCH_MEMORY_PAYLOAD_MIB`
- `SUNPACK_WATCH_MEMORY_PAYLOAD_KIB`
- `SUNPACK_WATCH_MEMORY_INTERVAL_SECONDS`
- `SUNPACK_WATCH_MEMORY_TIMEOUT_SECONDS`
- `SUNPACK_WATCH_MEMORY_MAX_SLOPE_MIB_PER_FILE`
- `SUNPACK_WATCH_MEMORY_MAX_ACTIVE_PIPELINES`（Windows 输出提升出现瞬态访问冲突时可设为 `1`）
- `SUNPACK_WATCH_MEMORY_TRACEMALLOC=1`
- `SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_IDLE_SECONDS`（默认 10）
- `SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_WAIT_SECONDS`（默认 12；设为 0 可关闭等待）
- `SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_ENABLED`（默认 1；设为 0 可运行无清理对照组）

每次运行会在 pytest 的临时目录生成 `watch-memory-report.json`。报告包含每个批次的 RSS、worker RSS、watch 状态规模、队列计数，以及全局缓存、reader cache、projection cache、archive session、关系探测密码缓存、修复检查缓存和持久 worker pool 的快照。
如果启用 cleanup 等待，还会记录 `cache_cleanup_scheduled/started/finished` 次数，以及 Native 7z 和 NTFS volume context 的条目数。
