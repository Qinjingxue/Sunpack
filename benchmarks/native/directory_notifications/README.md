# Directory-notification buffer comparison

This standalone native Rust workload measures Windows `ReadDirectoryChangesW`,
not archive extraction or the complete Sunpack Watch pipeline. It requires no
service, elevation, security-setting change, or third-party dependency. The
writer and observer use a unique NTFS directory under the repository `.cache`;
the executable refuses an existing root and deletes only the root it created.

Run from PowerShell:

```powershell
& benchmarks/native/directory_notifications/run.ps1 -Runs 5
```

The script builds with `rustc -O`, alternates A/B order on each repeat, and writes
raw JSONL under `.cache`. Each size gets five repetitions of:

1. One second idle (no writer).
2. A single producer creating 3,000 one-byte files with 117-character names,
   no injected callback delay.
3. The same producer, with an explicit **10 ms delay after each observer callback**.
   This models a stalled consumer, not an assertion that production callbacks
   normally take 10 ms. It is benchmark-only; no production wait was added.

The asynchronous request is rearmed before callback work, like the Rust observer.
The notification mask is the business-root `0x17f`. Overflow (`0` bytes or
`ERROR_NOTIFY_ENUM_DIR`) triggers a directory enumeration so that missed names can
be recovered and measured. This enumeration is a **benchmark surrogate**, not
Sunpack's USN checkpoint/reconciliation implementation. All emitted names must
converge; a 30-second operator safety budget reports failure rather than silently
counting a partial result. Idle waits and writer/callback pacing are workload
parameters, not application polling.

`observer_cpu_ms` is `GetThreadTimes` for the observer thread; `cpu_ms` includes the
producer and all benchmark threads. Windows CPU accounting is quantized (observed
15.625 ms), so zero is below resolution, not proof of zero work. Latencies run
from immediately before file creation to the first callback/enumeration observing
its name. They are not decompression latency. `wall_ms` includes the producer.

## Verified reference

Main `7aa9770` uses watchdog 6.0.0 (`uv.lock`) via its `_RecoveryEmitter`. The exact
upstream `BUFFER_SIZE` is **64,000 bytes**, not 65,536:

https://github.com/gorakhargosh/watchdog/blob/v6.0.0/src/watchdog/observers/winapi.py#L249-L255

Main's wrapper converts empty/overflow notifications into directory invalidation.
Rust's `NativeConfigChanges::read` already preserves the same overflow signal.
The allocation was 4,096 bytes. Only business-root subscriptions now request
64,000 bytes; configuration and ancestor subscriptions remain 4,096 bytes.

## Lulu results, 2026-11-12

Environment: Windows build 26200, NTFS C:, Intel Core i9-13980HX (32 logical CPUs),
Rust 1.94.1, optimized standalone executable. The machine was not isolated from
other activity; alternate order and repeats reduce but do not remove filesystem,
Defender and scheduling noise. Raw exact-size data and memory samples accompany
this README. A preliminary 65,536-byte probe was excluded from this table.

Ranges in parentheses are min/max across five runs; other figures are medians.

| Workload | Buffer | Overflows | Observer CPU ms | p95 name latency ms | Wall ms |
|---|---:|---:|---:|---:|---:|
| idle 1 s | 4,096 | 0 | 0 | n/a | 1001.7 |
| idle 1 s | 64,000 | 0 | 0 | n/a | 1002.3 |
| 3,000 natural arrivals | 4,096 | 0 | 62.5 (46.9–140.6) | 0.382 (0.300–0.419) | 786.8 (647.5–914.5) |
| 3,000 natural arrivals | 64,000 | 0 | 78.1 (62.5–187.5) | 0.417 (0.380–0.448) | 937.3 (818.7–1134.2) |
| 3,000 arrivals + 10 ms callback delay | 4,096 | 82 (69–96) | 343.8 (234.4–484.4) | 19.085 (15.971–19.435) | 1364.4 (1054.2–1635.5) |
| 3,000 arrivals + 10 ms callback delay | 64,000 | 0 | 0 (0–15.625) | 20.544 (20.457–20.661) | 1082.5 (832.3–1235.7) |

All non-idle runs converged to all 3,000 names. With the delayed consumer the
4,096-byte buffer caused 100,248–137,042 cumulative recovery-enumeration entries
(116,176 median), taking 318.6–617.6 ms (487.9 median); 64,000 caused none.
The small buffer's recovery enumeration can observe newly created names before
the queued normal notification, explaining why its latency percentile can be
lower despite more recovery work. Do not turn that metric into an application
latency claim.

**Conclusion:** the smaller buffer's additional overflow/recovery risk is
reproduced under a constrained consumer. No general latency or throughput benefit
was established for the natural-arrival scenario; those timings are noisy and
actually favored 4,096 in this sample. The reason for the minimal business-root
change is restoring main's burst tolerance, not claiming a universal speedup.
Full Watch USN recovery/CPU/extraction end-to-end performance remains outside this
API-level experiment.

## Allocation cost

The exact user buffer grows by 59,904 bytes per business root; lifetime stays tied
to the observer and cancellation drains before freeing it. An additional five
fresh-process idle pairs measured `PrivateUsage` immediately before starting the
observer and immediately after it armed: 49,152 bytes for 4,096 and 114,688 for
64,000 every time, a 65,536-byte process-private delta in this allocator/run.
These samples include thread/allocator bookkeeping. They are not kernel-pool or
whole-application RSS measurements. Windows also owns a notification buffer for
the directory handle; its kernel allocation was not measured. No new observer,
thread, polling loop or lifetime extension was introduced.

A production-module correctness test covers both capacities: a burst larger than
both buffers, overflow signaling, a subsequent named event and directory-handle
release. It is not a benchmark-as-test and does not impose a performance threshold.
