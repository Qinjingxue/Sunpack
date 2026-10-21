# Core UI in SunPack

Upstream: https://github.com/ghboke/core-ui

Imported commit: `126330eefdefe724ec96eb543681f715bd6be252`.
The tracked upstream source files, including its bundled LunaSVG and PlutoVG,
are vendored here. Git metadata, downloaded dependencies and build outputs are
excluded. SunPack builds this directory directly; it does not fetch Core UI or
apply a patch at configure time. Core UI's own upstream version metadata is
preserved.

Local changes:

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

- Expose read-only ToggleWidget::Animating() to the integration tests. The
  switch's own motion is checked without conflating it with other window
  animations or requiring trace events when reduced motion is enabled.
