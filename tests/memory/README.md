# Watch 内存增长测试

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
- `SUNPACK_WATCH_MEMORY_TRACEMALLOC=1`
- `SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_IDLE_SECONDS`（默认 10）
- `SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_WAIT_SECONDS`（默认 12；设为 0 可关闭等待）

每次运行会在 pytest 的临时目录生成 `watch-memory-report.json`。报告包含每个批次的 RSS、worker RSS、watch 状态规模、队列计数，以及 reader cache、projection cache、archive session、关系探测密码缓存、修复检查缓存和持久 worker pool 的快照。
如果启用 cleanup 等待，还会记录 `cache_cleanup_scheduled/started/finished` 次数，以及 Native 7z 和 NTFS volume context 的条目数。
