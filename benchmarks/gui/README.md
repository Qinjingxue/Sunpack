# GUI performance benchmark

`benchmarks/gui/performance.cpp` (CMake target `sunpack_gui_performance`) seeds a temporary
data directory, opens the real `Application` in-process, drives it through the Core UI debug
API and reports wall time and process CPU cycles per action plus the Core UI trace durations
attributed to the action that caused them.

## Build and run

```powershell
pwsh scripts/build_gui.ps1 -SkipTests
cmake --build .cache/gui-x64 --config Release --target sunpack_gui_performance --parallel
.cache/gui-x64/Release/sunpack_gui_performance.exe --rounds 30 > gui-perf.json
```

Options (all optional, each takes a value): `--tasks 5000`, `--passwords 3000`,
`--history 3000`, `--roots 250`, `--rounds 30` (clamped to 5..100). The run takes about a
minute at the defaults and writes a JSON report to stdout; diagnostics go to stderr.

The seeded workload is one watch event log with `tasks` completed/failed entries, one
password file with `passwords` saved records plus `history` clipboard entries, and
`roots` watch-root folders next to the monitored folder. The window is driven at
1120x720 DIP.

## Report

* `actions.<name>.wall_ms` / `process_cpu_million_cycles` – p50/p95/max over the sampled
  rounds; CPU cycles are taken from `QueryProcessCycleTime`, so they include the render
  thread.
* `core_ui_trace.all::<event>` – duration distributions of every Core UI trace event over
  the whole run; `core_ui_trace.<action>::<event>` restricts them to the window of one
  measured action.
* `app_open_ms`, `open_to_ready_ms`, `initial_data_load` – startup split into
  construct/open, first data applied, and the wait between them.
* `memory_mib_after_open|after_data|after_nav|after_ui`, `widgets_after_load|after_nav|after_ui`
  – working set and live widget count at fixed points. The widget count rises once when the
  config/password pages are first shown (lazy row mounting) and is then stable; it is a
  leak check, not a per-switch cost.
* `state_apply_*` – production cost of `ui_page_set_json` for the full 5000-row task list
  and 3000-row password list; `state_query_*` is the same quantity for `ui_page_get_json`
  (used by tests), so it measures the harness, not the app.
* `model_*` – backend projections on the same seeded files, measured after the window is
  gone: event-log parse, task/password/config/directory projections.
* `model_task_rows_phases.{cold,warm,unchanged}.{filter_ms,sort_ms,project_ms}` –
  separate filtered selection/root lookup, sort, and JSON row construction costs.
  The warm run reuses lazy task path/time metadata; unchanged selection skips
  JSON projection entirely (when the worker knows the source has not changed).
* `phase_counts.page_switch*::dispatch_{paints,layouts,draws}` – full window
  paints, root layouts and draw-tree operations inside each synchronous tab
  dispatch. Compare against `core_ui_trace.page_switch*::*duration` to identify
  whether the first-frame cost is an unnecessary synchronous layout or drawing.
* `password_state_query` – harness cost of serializing the 3000-row password state, next to
  the password save measurements.
* `page_switch_baseline_*` / `page_switch_end_*` – the same tab interaction measured at the
  start and at the end of the session; a large difference means state accumulates.

## Measurement rules

Configuration diagnostics also traverse all blocks twice in 96-DIP increments
(`config_traverse_cold`/`config_traverse_warm`), resize the configuration page in
8-DIP steps (`config_resize`), and feed wheel input after each presented frame
until the last block (`config_wheel_traverse`). This includes buffer refills and
large cards that alternating at the tail misses. The wheel scenario uses frame
events, without a pacing sleep. `virtual_refill_duration`,
`virtual_list_layout_duration` and `scroll_layout_duration` separate template
mounting from measurement; the traversal action includes all synchronous work
and message processing, even when layout happens before paint recording.

2026-10-21 local comparison, Release, 100 tasks/passwords/history, 10 roots and
5 rounds, with the same complete configuration and 106 samples per traversal:

| Metric | Before | After |
| --- | ---: | ---: |
| Cold configuration traversal operation p95 | 28.89 ms | 13.83 ms |
| Configuration resize operation p50 | 10.33 ms | 2.93 ms |
| Configuration resize operation maximum | 14.43 ms | 3.95 ms |

The added actual-wheel traversal recorded a 24 ms maximum animation frame
interval in this run. Idle recorded zero paints, widget animation frames and
property animation frames. These are local observations, not timing assertions
or a guarantee for other displays and system loads.

* `wait_for` drains the message queue **before** sampling state. Sampling first made a
  notification that had already been delivered visible only after the next unrelated
  message (caret blink, paint), which reported phantom 0.9–14 s waits.
* Waits query cheap state first (`ready`, `passwordCell`, `recordSaving`) and serialize
  the large arrays only on the poll that can finish.
* `wait_settled` fails after 5 s and prints the widget that keeps the settle predicate
  false, with a frame counter. Do not raise that timeout to hide a stall.

## Pre-optimization baseline (2026-10-20, before commit 1657ef06)

Historical numbers. The benchmark and its workload are unchanged, so they are directly
comparable with the post-optimization table below.

Windows 11 26200, i9-13980HX, 2560x1600 at 240 Hz and 150% DPI (surface 1680x1080), Release.

| Metric | p50 |
| --- | --- |
| `app_open_ms` | 128–148 ms |
| `initial_data_load` | 367–386 ms |
| `open_to_ready_ms` | 500–524 ms |
| apply 5000-row task state | 91–99 ms |
| apply 3000-row password state | 33–35 ms |
| `model_task_rows` (5000 tasks, 251 roots) | 57–120 ms typical (host load dependent) |
| `model_log_refresh` (5000 events) | 27–48 ms |
| tab switch dispatch | 38–68 ms depending on the page pair |
| tab switch until settled | 233–237 ms; ≈480 M cycles (≈160 ms CPU) per switch |
| password editor open / close | 32–50 / 27–43 ms |
| password save: file written | 66–94 ms |
| password save: UI acknowledged | 221–340 ms (incl. ≈32–51 ms harness state query) |
| dropdown open dispatch | 17–29 ms |
| search: type + 1-row result | 4 + 26–44 ms |
| scroll task / password / directory list | 0.4–0.8 ms |
| scroll config list | 4.7–5.3 ms (p95 18 ms) |
| resize + relayout | 1.9–2.2 ms |
| idle CPU over 5 s | 11–15 ms (0.2–0.3 %) |
| memory after open / after data / after UI | 50 / 74–75 / 101 MB |

The model projections and file I/O measures vary with host load (Defender, paging); the
UI-side numbers are stable within about ±15 %.

## Post-optimization result (commit 1657ef06)

Same machine, benchmark and workload: pre = 3 runs, post = 5 runs. The host alternates
between quiet and loaded periods (Defender/compositor) which moves file and interaction
timings by up to ~2x, so ranges are given and the host-independent changes are called out.

| Metric | Pre | Post | Change |
| --- | --- | --- | --- |
| apply 5000-row task state | 91.5–99.3 ms | 25.6–26.7 ms | −72 % |
| apply 3000-row password state | 32.8–34.6 ms | 7.0–7.8 ms | −79 % |
| open → first data (`open_to_ready_ms`) | 500–524 ms | 367–438 ms | −16…−30 % |
| data phase after open (`initial_data_load`) | 367–386 ms | 238–271 ms | −27…−38 % |
| tab switch CPU (`page_switch_settled` cycles) | 306–365 M | 43–58 M | −85 % |
| tab switch dispatch, quiet host | 45.8 ms | 34.0–38.9 ms | −15…−26 % |
| tab switch until settled (wall) | 233–237 ms | 244–249 ms | +3…+5 % |
| password save UI acknowledged | 221–340 ms | 83–165 ms | −40…−63 % |
| idle CPU over 5 s | 33–48 M cycles | 17–25 M cycles | −44…−63 % |
| memory after data / after session | 74.7 / 101.1 MiB | 72.7 / 99.6 MiB | −2…−3 % |
| `model_task_rows` (5000 rows, 251 roots) | 57–61 ms | 55–57 ms | ~0 % |

Confirmed effects:

* `ui_page_set_json` now parses the text once: 3.6× faster on the 5000-row task state and
  4.6× on the 3000-row password state, independent of host state.
* Motion is driven by a 16 ms (≈60 fps) timer instead of the render-thread present chain.
  Transition CPU drops ~85 %; wall time rises 3–5 % because settling is detected on a timer
  tick. No motion stall occurred in any post-fix run, including two 100-round stress runs
  (the previous build stalled in about half of them).
* Watch roots are indexed by path. `task_rows` is now independent of root count (1 and 251
  roots both 55–57 ms); the earlier 118→239 ms A/B was host-load noise, the real saving is
  the removed O(tasks × roots) scan (a few ms on this workload).
* Password replacement is acknowledged with a one-row delta built from the verified write
  snapshot, instead of re-reading and re-projecting the whole 3000-record file.
* Idle now shows 0–1 paint and 0 animation frames in the 5 s sample.

## Second optimization round (commit a8e1aa0f)

Same protocol (`--rounds 30` ×5, `--rounds 100` ×2), same host state caveat. The table
compares against the round-1 medians above.

| Metric | Round 1 | Round 2 | Change |
| --- | --- | --- | --- |
| open → first data | 380 ms | 369 ms | −3 % |
| data phase after open | 245 ms | 238 ms | −3 % |
| apply 5000-row task state | 26.2 ms | 25.9 ms | ~0 % |
| transition until settled (wall) | 245 ms | 166 ms | **−32 %** |
| transition CPU (`settled` cycles) | 55.7 M | 35.3 M | **−37 %** |
| tab switch dispatch | 34–68 ms | 41–49 ms | host-dependent |
| password save UI ack | 83–165 ms | 83–159 ms | ~0 % |
| memory after data / after session | 72.7 / 99.6 MiB | 81.0 / 104.0 MiB | +8.3 / +4.4 MiB |
| task projection (cold / warm / unchanged) | 55–57 / — / — ms | 50.1 / 41.7 / 1.9 ms | — / −17 % / −96 % |

* The 170 ms decorative transition is the largest visible win: the same switch now settles
  in 166 ms (was 245 ms) with 35 M cycles of CPU (was 56 M). The 100-round stress runs show
  the same 168/166 ms and no motion stalls.
* Task projection is now instrumented in phases (`model_task_rows_phases`). The lazy display
  cache removes the path/name/time formatting from repeated projections: 50.1 ms cold →
  41.7 ms warm (−17 %). An unchanged selection skips JSON construction entirely
  (1.9 ms, −96 %), which is what makes broad search keystrokes cheap when the result set
  does not change.
* The cold projection is unchanged (~49 ms of the 50 ms is row JSON construction), so
  startup only moves −3 %: the first projection after a log rebuild or a filter that changes
  the selection still pays it.
* Tab dispatch is not measurably cheaper: the new `phase_counts` show 6.1 full paints and
  2.0 layouts per switch, the same as round 1. The focus/transaction coalescing does not
  reduce the count in this click flow.
* Memory after data rose +8.3 MiB (working set, all 5 runs): the per-task display cache plus
  the retained 5000 selection IDs. That is a trade for the warm/no-op projection savings and
  should be gated if memory is a release criterion.
* In 2 of 5 protocol runs the 5 s idle sample painted 120/403 times (up to 2.2 G cycles);
  4 follow-up runs with the new `idle::*` trace attribution stayed at 0–1 paints and only
  showed plain `paint_reason_4` requests, no animation events. Treat it as an unattributed
  one-batch artifact until it reproduces with the trace on.

## Remaining hotspots after round 2

1. **Task row JSON construction** is now essentially the whole projection: ≈41 ms warm and
   ≈49 ms cold for 5000 rows, in `project_task`/`Json` object building (11 fields per row)
   plus `utf8(key)` and the root lookup. The display cache only removed the path/time part
   (~8 ms). Next options: emit the row JSON text directly instead of building an object tree,
   or cache per-task projected JSON (memory trade-off), or send a delta for filters instead
   of a snapshot.
2. **Tab switch dispatch**: 6 full repaints + 2 layouts, 41–49 ms on this host, unchanged by
   the round-2 coalescing. The transition itself is now 166 ms / 35 M cycles.
3. **Startup**: 369 ms to data = ≈130 ms open + ≈238 ms data (log parse, cold projection
   ≈50 ms, dump+apply ≈35 ms, password/config projections, queue and first paint).
4. **Password save**: ack 83–165 ms, dominated by the file replace wait (48–100 ms).
5. **Memory**: +8.3 MiB after data versus round 1 from the projection cache and selection
   retention; the empty-window baseline (~50 MB) is unchanged.
6. **Test-only**: `ui_page_get_json` still takes ≈98 ms for 5000 rows (and the benchmark's
   `password_state_query` ≈30 ms) because it converts through `expr::Value` before emitting
   JSON. It measures the harness, not the app; a direct `JS_JSONStringify` path would make
   large-state polling cheap.

The `page_switch_baseline` / `page_switch_end` probes showed no session growth in the
100-round runs (baseline 38.2/40.6 ms → end 41.9/33.9 ms; round 1 still had 36–40 → 52 ms),
and the widget count stays at 346 → 689 after the first config/password mount.

## Not hotspots

Idle CPU is 0.1–0.2 % over 5 s (17–25 M cycles, 0–1 paint). Virtual-list scrolling is
sub-millisecond for task, password and directory lists. Resize + relayout is ~2 ms. Search
latency for a filtered result is dominated by the worker round trip, not the virtual list.

## Notes

* Input is injected through `ui_debug_*`, which calls the same handlers as real Win32
  messages but bypasses the message queue and OS repeat/typing delays. Timing is therefore
  the app's own work, not input delivery.
* Motion is capped by a 16 ms animation timer (≈60 fps) since commit 1657ef06; before that
  it repainted at display refresh, so transition CPU scaled with the panel refresh rate.
* The benchmark never starts the watch service or the CLI; it only exercises the manager
  window and its file projections.

## Further optimization trial (2026-10-20)

This branch adds low-allocation, correctness-constrained hot-path changes:

- Filter requests first compute the sorted task ID selection. When IDs are
  unchanged **and no underlying task, root, or language changed**, the worker
  avoids constructing/sending 5000 JSON rows. Real log updates explicitly
  invalidate this shortcut; task `sequence` alone is not a valid mutation
  version for regrouping or departed multipart members.
- Task projections lazily reuse parsed path directory/name and formatted time
  while their source path/timestamp remains identical; per-projection status
  translations are memoized across matching rows. The cache stores only small
  display scalars on existing Task objects, not an extra resident JSON snapshot.
- Core UI skips strictly identical primitive assignments to reactive state,
  avoiding redundant effects/layout invalidation; object and array writes keep
  their original semantics. Decorative page and navigation-indicator transitions
  are now 170 ms (system animation setting still takes precedence).
- The benchmark reports model filtering, sorting and construction separately,
  plus each tab dispatch's repaint/layout/draw count. Use the same `--rounds
  30` x 5 and `--rounds 100` x 2 protocol, with unchanged machine/screen
  settings, and compare cold-start, no-op filter, and warm/full refresh.

**Measured** with the protocol above on this machine (see "Second optimization round"):
transition wall −32 % and CPU −37 %, warm projection −17 %, unchanged selection −96 %,
startup −3 %, dispatch ~0 %, working set +8.3 MiB after data. Existing UI and file-contract
integration suites pass; the changes do not introduce a background poller or new IPC.
