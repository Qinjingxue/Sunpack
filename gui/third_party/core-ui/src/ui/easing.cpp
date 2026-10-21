#include "easing.h"

#include <algorithm>
#include <cmath>

namespace ui {

float ApplyEasing(EasingFunction func, float t) {
    t = std::clamp(t, 0.0f, 1.0f);

    switch (func) {
        case EasingFunction::FluentEnter:
            return 3.0f * std::pow(t, 2.0f / 3.0f) - 2.0f * t;
        case EasingFunction::FluentStandard: {
            if (t == 0.0f || t == 1.0f) return t;
            float lo = 0, hi = 1, s = t;
            for (int i = 0; i < 14; ++i) {
                s = (lo + hi) * 0.5f;
                float x = 1.65f * (1-s) * (1-s) * s + s*s*s;
                if (x < t) lo = s; else hi = s;
            }
            return 1.65f*(1-s)*(1-s)*s + 3*(1-s)*s*s + s*s*s;
        }
        case EasingFunction::Linear:
            return t;
        case EasingFunction::EaseInQuad:
            return t * t;
        case EasingFunction::EaseOutQuad:
            return 1 - (1 - t) * (1 - t);
        case EasingFunction::EaseInOutQuad:
            return t < 0.5f ? 2 * t * t : 1 - std::pow(-2 * t + 2, 2) / 2;
        case EasingFunction::EaseInCubic:
            return t * t * t;
        case EasingFunction::EaseOutCubic:
            return 1 - std::pow(1 - t, 3);
        case EasingFunction::EaseInOutCubic:
            return t < 0.5f ? 4 * t * t * t : 1 - std::pow(-2 * t + 2, 3) / 2;
        case EasingFunction::EaseInElastic:
            return t == 0 ? 0 : t == 1 ? 1 :
                -std::pow(2, 10 * t - 10) * std::sin((t * 10 - 10.75) * (2 * 3.14159 / 3));
        case EasingFunction::EaseOutElastic:
            return t == 0 ? 0 : t == 1 ? 1 :
                std::pow(2, -10 * t) * std::sin((t * 10 - 0.75) * (2 * 3.14159 / 3)) + 1;
        case EasingFunction::EaseInBounce: {
            float x = 1 - t;
            if (x < 1/2.75f) return 1 - (7.5625f * x * x);
            if (x < 2/2.75f) {
                x -= 1.5f/2.75f;
                return 1 - (7.5625f * x * x + 0.75f);
            }
            if (x < 2.5f/2.75f) {
                x -= 2.25f/2.75f;
                return 1 - (7.5625f * x * x + 0.9375f);
            }
            x -= 2.625f/2.75f;
            return 1 - (7.5625f * x * x + 0.984375f);
        }
        case EasingFunction::EaseOutBounce: {
            if (t < 1/2.75f) return 7.5625f * t * t;
            if (t < 2/2.75f) {
                t -= 1.5f/2.75f;
                return 7.5625f * t * t + 0.75f;
            }
            if (t < 2.5f/2.75f) {
                t -= 2.25f/2.75f;
                return 7.5625f * t * t + 0.9375f;
            }
            t -= 2.625f/2.75f;
            return 7.5625f * t * t + 0.984375f;
        }
        default:
            return t;
    }
}

}  // namespace ui
