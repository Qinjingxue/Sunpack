#pragma once
#include <ui_core.h>
#include <functional>

namespace spg::motion {
class VisualBatch {
    UiWindow window_;
public:
    explicit VisualBatch(UiWindow window):window_(window) { if(window_) ui_window_begin_canvas_visual_transaction(window_); }
    ~VisualBatch() { if(window_) ui_window_end_canvas_visual_transaction(window_); }
    VisualBatch(const VisualBatch&) = delete;
    VisualBatch& operator=(const VisualBatch&) = delete;
};
void enter(UiWindow window, const char* id, float x = 0, float y = 16);
void finish(UiWindow window, const char* id);
void popup(UiWindow window, bool opening, std::function<void()> complete = {});
void select(UiWindow window, const char* indicator, const char* target);
}
