#pragma once

#ifndef UI_API
  #if defined(UI_CORE_STATIC)
    #define UI_API
  #elif defined(UI_CORE_BUILDING)
    #define UI_API __declspec(dllexport)
  #else
    #define UI_API __declspec(dllimport)
  #endif
#endif

namespace ui {

enum class EasingFunction {
    Linear,
    EaseInQuad,
    EaseOutQuad,
    EaseInOutQuad,
    EaseInCubic,
    EaseOutCubic,
    EaseInOutCubic,
    EaseInElastic,
    EaseOutElastic,
    EaseInBounce,
    EaseOutBounce,
    EaseOutBack,
    FluentEnter,     // cubic-bezier(0, 0, 0, 1)
    FluentStandard,  // cubic-bezier(0.55, 0.55, 0, 1)
    MaterialEnter,   // cubic-bezier(0, 0, 0.2, 1)
    MaterialExit,    // cubic-bezier(0.4, 0, 1, 1)
    MaterialStandard // cubic-bezier(0.4, 0, 0.2, 1)
};

UI_API float ApplyEasing(EasingFunction func, float t);

}  // namespace ui
