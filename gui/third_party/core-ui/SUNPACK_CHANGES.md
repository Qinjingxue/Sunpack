# Core UI in SunPack

Upstream: https://github.com/ghboke/core-ui

Imported commit: `126330eefdefe724ec96eb543681f715bd6be252`.
The tracked upstream source files, including its bundled LunaSVG and PlutoVG,
are vendored here. Git metadata, downloaded dependencies and build outputs are
excluded. SunPack builds this directory directly; it does not fetch Core UI or
apply a patch at configure time. Core UI's own upstream version metadata is
preserved.

Local changes:

- Add paint-only UTF-16 find ranges shared by ordinary text controls and native
  TAG surfaces. Reuse DirectWrite shaping/layout caches and expand highlights
  into existing rounded geometry, clips and text commands during recording.
  Expose virtual row offsets/revisions, an after-layout notification and a
  scrollbar decoration callback; the application owns find state/navigation.

- Use Rayburst's default warm neutral ramp for light surfaces: #F2ECF1 window,
  #EAE4E8 controls and #FEF7FC cards, with tonal hover/pressed surfaces.
  Standard light controls and popups read the shared palette instead of white
  literals. Keep SunPack's blue accent and semantic status colors. Tooltip colors
  are shared inverse-surface tokens (#E7E1E5/#322F33), with softened foregrounds.

- Draw hover tooltips above their trigger as arrowed, rounded bubbles, flipping
  below when necessary. Use a light surface with dark text in dark mode and
  a dark surface with light text in light mode, with
  150 ms fade/scale about the arrow tip and shared Material entrance/exit curves.
  Reuse AnimatedFloat, completion-driven presentation and cached text measurement;
  retain only a text/anchor snapshot during exit and release it when motion ends.
  Keep the 500 ms delay and respect the Windows motion preference.

- Bind UIX tooltips through the existing 500 ms hover service and allow
  `tabindex="0"` on compact action labels. Reuse the toast overlay for optional
  closable WinUI-style messages, with a 300 ms fade/scale from the top center,
  hover pause, owner theme
  and Windows motion preference. Replacements release the previous surface;
  holding schedules one deadline and hovering stops timers completely.
  Anchor these messages 12 DIP below the visible window top (including the native
  caption) and refresh on owner geometry
  events without restarting their lifetime. Pure moves reuse measured content;
  scale frames reuse the notification's D2D surface and text format.

- Size auto-width ComboBoxes to the widest localized item using the existing
  bounded DirectWrite measurement cache, with room for padding and the arrow.
  Explicit widths (including compact range operators/units) remain authoritative.
- Compare consecutive display lists and replay/present a conservative dirty
  rectangle. Include both alternating swap-chain buffers' changes; resize,
  screenshots, prepared frames, backdrop sampling and SVG text runs retain full
  replay. Resource ownership moves with the previous list and clears on target
  release. Text/SVG damage uses the active clip to preserve overhangs.
- Cache DirectWrite draw layouts (512 entries / 65536 UTF-16 units), SVG documents
  (64 entries / 128 KiB XML), brushes and opacity/rounded-clip layers with bounded
  lifetimes. Snapshot fonts/fallback/rendering mode in each submitted frame and
  invalidate dependent caches when they change.
- Retain at most 64 ordered geometry command spans for one stable opacity
  animation subtree. Replay text at its live fractional transform to preserve
  DirectWrite glyph snapping; release retained spans when content/target changes
  or the animation ends. No raster scaling or change to animation timing.
- Coalesce pointer invalidations through the existing posted frame scheduler;
  preserve the existing independent animation submission cadence. Unchanged
  pointer input no longer paints or scans the entire tree: open combos register weak handles,
  scroll hover follows old/new hit ancestry, and pointer leave clears only hover
  state without synthesizing a drag. Transactions/resize keep their barriers.
- Set the shared DXGI device's maximum driver frame latency to one. The default
  three queued frames caused uneven Present completion intervals with cheaper
  cached animation frames on the measured 240 Hz display. Keep Present(1), the
  existing completion-driven animation host, durations and easing unchanged.
- Reuse surviving virtual rows' layouts only during viewport refill. Data changes,
  font changes and ordinary root/resize layouts still measure the actual controls;
  the cache contains only mounted rows with weak identities.

- Deliver loop-scoped mouse-down offsets through label/icon children to the
  interactive ancestor, and disconnect the hook when a virtual row unmounts.
  TextInputWidget can place its caret using the existing text hit test with a
  supplied display offset, including a head-ellipsized directory cell.
- Skip equal TextInput/TextArea value bindings so input echoes preserve the
  caret, selection and horizontal scroll instead of resetting them to the end.

- Smooth wheel travel uses the existing finite, VSync-paced animation host.
  Accumulate repeated input, reverse from the visual position, and cancel on
  thumb/track input or programmatic positioning. Keep virtual anchors independent
  of the remaining travel and supply the renderer's measurer on animation frames.
  Weak frame-local animation targets tolerate virtual rows unmounting mid-frame;
  completed/hidden motion releases frame requests without polling.

- Release the temporary root handle after attaching a prepared/opened page to
  its window. Repeated date popup creation now releases each page tree on close.

- Wire QuickJS `@change` / `@input` on ComboBox to its integer selection
  callback in both ordinary and loop scopes. Range comparison/unit selectors
  use the existing UIX controls and autosave flow.

- Add `VirtualList` for one keyed `v-for` inside a ScrollView: viewport-only
  mounting, small overscan, focused-editor retention, variable measured row
  heights, Fenwick position lookup and scroll-anchor correction. Viewport
  updates reuse cached list data and existing iteration bindings; unmount
  disposes callbacks, effects and closures. Wheel input supplies the text
  measurer for newly mounted rows.
- Preserve measured virtual row heights by iteration key across array
  replacements, including autosave receipts and file notifications. Remapping
  uses temporary indices derived from the existing JS snapshots, retaining no
  additional item/key cache. Surviving visible keys anchor list reorders;
  mounted rows still remeasure actual content changes during normal layout.

- Add opt-in `immutable-items="true"` to VirtualList. Lists that replace changed
  row objects keep untouched rows' binding effects instead of disposing and
  rebuilding them on every delta. Global dependencies remain reactive; nested
  loop scopes and changed declared indices still rebind normally.
- Skip unchanged bound label/button text, IDs, CSS classes, visibility and
  enabled state. Changed IDs refresh descendant selectors directly; changed
  classes still cascade normally. Avoid repeated CSS work and animation-host
  scans during log streams and saving-state updates.

- Honor `text-align` on text buttons, retaining centered text by default;
  task filename links use left alignment with the directory text below them.
- Clear hover state on reactively hidden subtrees, keeping visible ancestors
  intact so inline replacements do not inherit a stale underline or tooltip.
- Allow programmatic focus without the keyboard navigation ring for inline
  replacements; retain each input's native background and accent underline.
- Wire focus, blur and submit handlers inside keyed loop scopes as well as
  ordinary templates, allowing inline settings to commit at edit completion.
- Sample finite animations with a monotonic high precision clock and continue
  interrupted animations from their current visual position.
- Pace visible motion on the existing render thread with vertical sync. Request
  the next animation frame after presentation, carrying window identity rather
  than widget pointers across threads. Remove the competing 16 ms widget/property
  timer and its 60 fps cap; follow the display refresh rate. Prepared frames
  resume after commit and hidden frames on show/restore. Stop on completion,
  hide or destruction without idle wakeups.
- Add paint-only translation and Windows Fluent entrance/point-to-point easing.
- Give ToggleSwitch separate movement, color and hover/pressed shape animations,
  keyboard handling, dark-theme thumb contrast and system animation preference.
- Keep layout geometry stable while drawing translated subtrees.
- Animate ComboBox popup entrance/exit, including upward opening and interrupted
  motion, on the same finite paint-only animation host. Respect system settings.
- Remove the redundant ScrollView layout during wheel dispatch: scrolling already
  shifts arranged rectangles, and the extra layout lost the text measure context.
- Unify thumb and wheel view changes on presentation frames. Coalesce pending
  input while the current scroll frame presents; never synchronously paint/wait
  for each mouse packet. Generation checks cover superseded frames, device loss,
  hidden windows and the final non-animated position/pressed-state frame.
- Replace per-packet restarted wheel easing with integrated exponential inertia
  and additive velocity, respecting system scroll lines/pages and reduced motion.
  Thumb tracking stays direct, with no release inertia or stationary frame loop.
  Preserve sub-millisecond QPC samples for scrolling on high-refresh displays.
- Separate virtual-row realization from row measurement. Keep the existing
  bounded 160-DIP overscan with refill hysteresis; pure offset updates never call
  row layout. Resize, data changes and buffer refills still measure normally and
  preserve virtual anchors and focused editors.
- Route scrollbar presses through the actual hit widget's ancestor chain instead
  of sweeping all ScrollViews. Hidden pages with stale bounds cannot capture a
  visible scrollbar's drag; nested scrollbars respect clipping and stacking.
- Cache intrinsic text widths across layout passes/resizes, keyed by exact text
  and DWrite format. Keep at most 1024 scalar results and 65536 UTF-16 characters;
  clear on font/fallback changes, factory reinitialization and target release.
  No retained text layouts or background work.

- Disconnect virtual-row callbacks before releasing their JS scope, and retain
  the current JS function/arguments until reentrant handlers return. Focus changes
  keep both widgets alive and publish the new focus before blur callbacks. This
  prevents use-after-free when a save or external snapshot removes an edited row.
- Shared `:ellipsis-start` rendering for directory labels, previews and dropdown
  labels. Preserve the right-hand path suffix and UTF-16 code point boundaries;
  cache up to two measured suffixes in the existing bounded width cache.
  Cache reset follows the renderer's font/factory lifecycle; no retained layouts.
- Emit TextInput text-change events after Ctrl+V/Ctrl+X, matching ordinary input.
  Multi-line paste reaches the password table as one event and one atomic batch.
- Keep wrapped labels at least as tall as their measured DWrite text. Estimated
  line counts can understate long paragraphs and let text overflow an auto row.

- Reuse intrinsic main-axis measurements within each HBox/VBox layout pass,
  skip unchanged ScrollView final allocations and stable virtual-row passes.
  Realization refills settle within their own ScrollView; preexisting page
  invalidations and unconverged layout retain the root fallback. Resize dispatch
  only ensures dirty layout when a JavaScript resize handler actually exists.
- Share parameterized loop binding/handler functions by filename and full
  source in each ScriptRuntime. Bound the cache to 512 entries/128 KiB source
  and release functions before the JS context; retain no row values or widgets.
- Add static focus-indicator="underline"/"none" for controls with their own
  selection feedback. Clear surviving children's parent pointers when a root
  wrapper is destroyed, including page roots retained until page teardown.

The framework is MIT licensed; see [LICENSE](LICENSE). The original license and
copyright notices are preserved, including [LunaSVG](third_party/lunasvg/LICENSE),
[PlutoVG](third_party/lunasvg/plutovg/LICENSE), and the additional notices in their
source files (including FreeType and stb). Built distributions include the
framework, LunaSVG, PlutoVG, QuickJS and JSON library licenses.

Motion references:

- https://learn.microsoft.com/en-us/windows/apps/design/motion/
- https://learn.microsoft.com/en-us/windows/apps/design/motion/page-transitions
- https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/CommonStyles/ToggleSwitch_themeresources.xaml
- https://github.com/microsoft/microsoft-ui-xaml/blob/main/dxaml/xcp/dxaml/lib/ComboBox_Partial.cpp
- https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/ScrollView/ScrollBarController.cpp
- https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/ScrollPresenter/ScrollPresenter.cpp
- https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/Repeater/ViewportManager.cpp
- https://learn.microsoft.com/en-us/windows/apps/develop/composition/interaction-tracker-manipulations

- Expose read-only ToggleWidget::Animating() to the integration tests. The
  switch's own motion is checked without conflating it with other window
  animations or requiring trace events when reduced motion is enabled.
