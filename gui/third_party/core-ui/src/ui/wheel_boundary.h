#pragma once
#include <algorithm>
#include <cmath>

namespace ui {

// An amount-only resistance budget, in raw Win32 wheel units. Two notches are a
// SunPack UX choice, not a framework-standard scroll-chaining threshold. Keep
// it independent of DPI, SPI_GETWHEELSCROLLLINES and event packet size.
class WheelBoundaryGate {
public:
    float Consume(float delta, float extent) {
        if (delta == 0) return 0;
        const int direction = delta > 0 ? 1 : -1;
        // Layout may shift an extent by a float ULP while the parent moves.
        // Rearm for a changed range, not numerical jitter at the same edge.
        if (direction != direction_ || std::abs(extent - extent_) > 0.5f) {
            Reset(); direction_ = direction; extent_ = extent;
        }
        const float consumed = std::min(std::abs(delta), remaining_);
        remaining_ -= consumed;
        // Once exhausted, remain open. Never replay previously swallowed input
        // or refund the consumed part of the packet that crosses the threshold.
        return delta - direction * consumed;
    }
    void Reset() { direction_ = 0; remaining_ = kResistance; }

private:
    static constexpr float kResistance = 240.0f; // 2 * WHEEL_DELTA: two wheel notches
    int direction_ = 0;
    float extent_ = 0;
    float remaining_ = kResistance;
};

} // namespace ui
