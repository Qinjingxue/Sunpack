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

## Baseline (2026-10-20, dev branch before GUI performance fixes)

The measurements below are the **pre-optimization** baseline. Changes on the
`fix/gui-benchmark-hotspots-20261020` branch require a Windows Release rerun
before numerical speedup claims can be made. The benchmark and its workload
remain unchanged for an apples-to-apples comparison.

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

## Hotspots

1. **Full task-list updates cost about 200 ms when many rows match** (`task_rows` 57–120 ms,
   `Json::dump` 8 ms, `ui_page_set_json` 91–99 ms). Two independent causes:
   * `ui_page_set_json` converts the JSON three times: `expr::ParseJson` into a C++ value,
     `EmitJson` back to text, then `JS_ParseJSON`; the app already dumped the same document
     in `apply_pending`, so the text crosses four conversions. Feeding the text to
     `JS_ParseJSON` directly is the obvious fix (`ui/page/page_api.cpp`,
     `ui/page/page_state.cpp`).
   * `indexed_root` scans every watch root per task. Measured back-to-back with the same
     5000 tasks: 118 ms at 1 root, 239 ms at 251 roots. A component-wise hash map lookup
     (walk the path up from the task) or a prefix trie removes the O(tasks × roots) term.
   This path runs on startup, on every filter change (each keystroke with a broad match),
   on language changes and on log rebuilds.
2. **Tab switches**: a 38–68 ms synchronous dispatch (about 7 full repaints and 3 full
   layouts) followed by a 250 ms transition. The aggregate over the
   `config → passwords → tasks` loop is higher (58–68 ms) than `config↔tasks` alone
   (about 40 ms). The transition repaints at display refresh: one switch here draws about
   50 frames and costs ≈480 M cycles (≈160 ms CPU across the UI and render threads,
   including vsync waits). The cost scales with refresh rate and there is no frame-budget
   cap. The redundant layouts come from the explicit `ui_window_relayout` in
   `Application::navigate` plus list viewport/layout requests that fire again during the
   first paint.
3. **Password save round trip**: the file is replaced 66–94 ms after the click, the UI
   acknowledges 221–340 ms after it. The ack re-reads and re-projects the whole 3000-record
   file (33 ms apply plus a 32–51 ms state query in the harness). Publishing a delta for the
   one edited record would avoid re-materializing the list.
4. **Memory**: an empty window costs about +40 MB over the 10 MB process baseline
   (D2D/DirectWrite/fonts plus a 1680x1080 surface), and a session with 5000 tasks and
   3000 passwords peaks at 101 MB. The fixed baseline dominates; the data costs roughly
   3 KB per task/password row.
5. **Intermittent motion stall**: property animations can freeze mid-flight. The diagnostic
   reports e.g. `id=navIndicator opacity=1 x=0 y=11.0162 tab=config center=147.616
   target=180.6`; the indicator stops between two tabs, the window stops posting frames and
   every later `wait_settled` blocks until its 5 s timeout (one earlier run recorded a 28.3 s
   settle sample; the first benchmark version saw 16–28 s "settle" outliers around the
   dropdown tests and switched those measurements to fixed animation windows, which hid the
   symptom). It happened in
   about half of the 100-round stress runs (100 config-list wheel events followed by rapid
   tab switches) and once in a 30-round run; 5-round runs never hit it. When it fires, the
   wait loop receives no window messages at all, so animation progress cannot advance:
   progress is only advanced from `OnPaint`, and the render-thread present →
   animation-frame-message chain has no fallback timer while render-thread present is active
   (`UiWindowImpl::EnsureAnimationTimer`); a frame that is skipped or only prepared does not
   request the next one. This should be fixed before transition numbers are used for
   regression tracking, otherwise a stalled run fails after the 5 s settle timeout.

The `page_switch_baseline` / `page_switch_end` probes measured the same switch at 41.6 vs
53.2 ms in one run and 40.6 vs 39.1 ms in another, so no consistent per-session slowdown was
observed; 100-round runs differ from 30-round runs because of page mix and host load, not
because state accumulates. The widget count rises once from 346 to 689 when the config and
password pages are first shown (lazy row mounting) and then stays there; it is not a leak.

## Not hotspots

Idle CPU is 0.2–0.3 % over 5 s. Virtual-list scrolling is sub-millisecond for task,
password and directory lists. Resize + relayout is ~2 ms. Search latency for a filtered
result is tens of milliseconds, dominated by the worker round trip, not the virtual list.

## Notes

* Input is injected through `ui_debug_*`, which calls the same handlers as real Win32
  messages but bypasses the message queue and OS repeat/typing delays. Timing is therefore
  the app's own work, not input delivery.
* Frame pacing follows the display refresh. Per-frame CPU costs on a 60 Hz panel are about
  a quarter of the numbers above.
* The benchmark never starts the watch service or the CLI; it only exercises the manager
  window and its file projections.
