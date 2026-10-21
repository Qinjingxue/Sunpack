# Animation Architecture Plan

目标：把控件动画从分散的 timer/dt 推进改成统一 frame-driven 架构。事件和绑定只更新目标状态；窗口统一调度帧；每帧开始统一采样动画，按需布局，然后绘制只读取 presentation value。

## Step 0: Baseline Current Input Animation Fixes

Purpose:
- Preserve the already validated fast-click fixes for `ToggleWidget`, `CheckBoxWidget`, and `RadioButtonWidget`.
- Keep the current demo-buildable state before deeper architecture changes.

Files:
- `demo/ui_demo_uix.cpp`
- `src/ui/controls.h`
- `src/ui/controls.cpp`
- `src/ui/debug_trace.h`
- `src/ui/page/page_state.cpp`
- `src/ui/trace.cpp`
- `src/ui/ui_window.h`
- `src/ui/ui_window.cpp`

Expected changes:
- Keep frame-sampled scalar transitions currently used by toggle-like controls.
- Keep the temporary animation timer active-list optimization.
- Keep bounce easing warning cleanup.
- Keep trace helpers used by the temporary timer diagnostics.
- Keep binding no-op guards that avoid restarting animations for unchanged state.

Validation:
- Build `ui-demo-uix`.
- Manually verify rapid clicking for toggle, checkbox, and radio.

Commit:
- `fix(animation): stabilize rapid state-control retargeting`

## Step 1: Extract Animation Core

Purpose:
- Move easing and scalar transition primitives out of control-specific code.
- Make animation primitives reusable by every control and the future property animation system.

Files:
- Add `src/ui/easing.h`
- Add `src/ui/easing.cpp`
- Update `src/ui/animation.h`
- Update `src/ui/animation.cpp`
- Update `src/ui/controls.h`
- Update `src/ui/controls.cpp`
- Update root `CMakeLists.txt`

Expected changes:
- Move `EasingFunction` and easing evaluation out of `ToggleWidget`.
- Replace `FloatTransition` with `AnimatedFloat` in animation core.
- Keep compatibility wrappers only where needed during migration.

Validation:
- Build `ui-demo-uix`.
- Confirm existing toggle/checkbox/radio behavior remains unchanged.

Commit:
- `refactor(animation): extract easing and animated float`

## Step 2: Introduce Per-Window Animation Host

Purpose:
- Stop discovering active animations by scanning the widget tree.
- Let animations register themselves with the owning window when active.

Files:
- Add `src/ui/animation_host.h`
- Add `src/ui/animation_host.cpp`
- Update `src/ui/ui_window.h`
- Update `src/ui/ui_window.cpp`
- Update `src/ui/widget.h`
- Update `src/ui/widget.cpp`
- Update root `CMakeLists.txt`

Expected changes:
- Add per-window `AnimationHost`.
- Add active animation registration/unregistration.
- Add invalidation classification: paint, layout, hit-test, native-window.
- Keep the old timer entry point temporarily, but route it through the host.

Validation:
- Build `ui-demo-uix`.
- Trace active animation count and timer lifecycle.

Commit:
- `refactor(animation): add per-window animation host`

## Step 3: Establish Unified Frame Flow

Purpose:
- Ensure all animations are sampled before layout and paint.
- Make timer/message handling only request frames, never mutate control animation state directly.

Files:
- Update `src/ui/ui_window.h`
- Update `src/ui/ui_window.cpp`
- Update `src/ui/ui_context.h`
- Update `src/ui/ui_context.cpp`
- Update `src/ui/debug_trace.h`
- Update `src/ui/trace.cpp`

Expected changes:
- Add `BeginFrame(now)`.
- Run `AnimationHost::SampleAll(now)` before layout and paint.
- Coalesce layout and paint invalidation per frame.
- Replace `UpdateToggleAnimTimer()` semantics with general frame scheduling.

Validation:
- Build `ui-demo-uix`.
- Verify no animation progression happens from mouse/key/binding handlers.
- Verify frame trace shows one sample pass per frame.

Commit:
- `refactor(animation): sample animations in unified frame flow`

## Step 4: Migrate Paint-Only Control Animations

Purpose:
- Move low-risk paint-only control animations to `AnimatedFloat`.

Files:
- Update `src/ui/controls.h`
- Update `src/ui/controls.cpp`
- Update `src/ui/ui_window.cpp`

Controls:
- `ToggleWidget`
- `CheckBoxWidget`
- `RadioButtonWidget`
- `SliderWidget` thumb scale
- `ProgressBarWidget` determinate value

Expected changes:
- Remove per-control `lastTick_`, `animLastTick_`, and local dt-based animation code.
- Controls retarget animated values and request a frame.
- Paint reads sampled presentation values.

Validation:
- Build `ui-demo-uix`.
- Rapid click/drag stress for all migrated controls.

Commit:
- `refactor(animation): migrate paint-only controls`

## Step 5: Migrate Layout-Affecting Control Animations

Purpose:
- Move layout-affecting animations into the same frame lifecycle.

Files:
- Update `src/ui/controls.h`
- Update `src/ui/controls.cpp`
- Update `src/ui/ui_window.cpp`
- Update `src/ui/widget.h` if layout invalidation ownership needs an API.

Controls:
- `ExpanderWidget`
- `SplitViewWidget`

Expected changes:
- Sample their animated progress before layout.
- Mark layout dirty only while needed.
- Avoid repeated layout during one timer/message pass.

Validation:
- Build `ui-demo-uix`.
- Rapid expand/collapse and pane open/close stress.
- Confirm hit testing follows current layout.

Commit:
- `refactor(animation): migrate layout controls`

## Step 6: Replace Global Property Animation Manager

Purpose:
- Merge the existing global `AnimationManager` into the per-window animation architecture.

Files:
- Update `src/ui/animation.h`
- Update `src/ui/animation.cpp`
- Update `src/ui/ui_window.h`
- Update `src/ui/ui_window.cpp`
- Update `src/ui/page/page_state.cpp`
- Update `src/ui/page/widget_factory.cpp`

Expected changes:
- Remove or deprecate global `Animations()`.
- Animate by `(window, widget, property)`.
- Retarget same property from current presentation value.
- Widget destruction cancels related animations.
- Layout properties request layout through invalidation classification.

Validation:
- Build `ui-demo-uix`.
- Verify page transitions and markup-defined transitions.

Commit:
- `refactor(animation): move property animations per window`

## Step 7: Add Stress Demo And Metrics

Purpose:
- Make animation regressions reproducible and measurable.

Files:
- Update `demo/ui_demo_uix.cpp`
- Update demo UIX assets used by `ui-demo-uix`
- Update `src/ui/debug_trace.h`
- Update `src/ui/trace.cpp`

Expected changes:
- Add rapid-toggle, checkbox, progress, expander, splitview, and many-animations stress cases.
- Trace frame interval, animation count, sample cost, layout cost, paint cost, and dropped-frame estimate.

Validation:
- Build `ui-demo-uix`.
- Run stress page manually with trace enabled.

Commit:
- `test(animation): add demo stress metrics`

## Out Of Scope For First Pass

These should stay out of the first migration unless they block architecture work:
- GIF frame animation.
- Caret blink.
- Indeterminate progress.
- Toast/window open-close native-window animations.

They can be migrated later using timeline/repeating/native animation primitives.
