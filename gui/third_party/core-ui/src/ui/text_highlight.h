#pragma once
#include <cstdint>

namespace ui {
// UTF-16 ranges independent of selection/caret. Recording expands these to
// ordinary geometry/text; mutable layouts never cross the render thread.
struct TextHighlight {
    uint32_t start = 0, length = 0;
    bool active = false;
};
}
