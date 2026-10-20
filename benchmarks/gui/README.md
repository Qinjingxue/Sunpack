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

* `wait_for` drains the message queue **before** sampling state. Sampling first made a
  notification that had already been delivered visible only after the next unrelated
  message (caret blink, paint), which reported phantom 0.9–14 s waits.
* Waits query cheap state first (`ready`, `passwordEditor`, `recordSaving`) and serialize
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

## Remaining hotspots (post-optimization)

1. **Full task projection is the largest data-path cost**: `task_rows` 55–57 ms for 5000
   rows (≈11 µs/row), `Json::dump` 8 ms and `ui_page_set_json` 26 ms, ≈90 ms per broad
   filter/refresh. Root lookup is no longer a factor; the per-row work is path
   UTF-8⇄UTF-16 conversion, `_localtime64_s`+`strftime`, `tr()` lookups, an 11-field JSON
   object and the sort. Reusing projected rows keyed by task sequence/language/root
   generation, or precomputing time text and directory at accept time, is the next step.
   This path runs on startup, on each broad search keystroke, on language changes and on
   log rebuilds.
2. **Tab switch hitch**: 34–68 ms synchronous dispatch before the first transition frame
   (about 6 full repaints and 2 full layouts; the explicit navigation relayout is gone, the
   remaining layouts come from list viewport/paint-time layout requests). The 250 ms
   transition itself is cheap now (43–58 M cycles ≈ 15–20 ms CPU). Shortening the
   synchronous block needs fewer repaints per click or avoiding layout during paint.
3. **Startup**: 367–438 ms from open to first data, split into ≈130–140 ms open (UIX
   compile/window) and ≈240–270 ms data (event-log parse ≈50 ms, task projection ≈55 ms,
   dump+apply ≈35 ms, password/config projections, message queue and first paint).
4. **Password save**: UI ack 83–165 ms, dominated by the 48–100 ms file replace wait
   (disk/AV); the UI update is no longer the bottleneck.
5. **Memory**: unchanged by the fixes — ≈50 MB for an empty window (D2D/DirectWrite/fonts
   plus a 1680x1080 surface) and 97–105 MB after a session with 5000 tasks and 3000
   passwords.
6. **Test-only**: `ui_page_get_json` still takes ≈98 ms for 5000 rows (and the benchmark's
   `password_state_query` ≈30 ms) because it converts through `expr::Value` before emitting
   JSON. It measures the harness, not the app; a direct `JS_JSONStringify` path would make
   large-state polling cheap.

The `page_switch_baseline` / `page_switch_end` probes stayed within host noise (30-round
`config↔tasks`: baseline 34–38 ms, end 27–52 ms; 100-round: baseline 36–40 ms, end 52 ms),
and the widget count stays at 346 → 689 after the first config/password mount. No
per-session leak was found; the end-probe spread is not yet a trend.

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

**Do not infer a numeric speedup from source changes.** Re-run a Windows Release
benchmark and confirm existing UI and file-contract integration suites before
merging. Changes do not introduce a background poller or new IPC.
