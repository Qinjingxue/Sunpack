#pragma once
#include <ui_core.h>
#include <functional>

namespace spg::motion {
void enter(UiWindow window, const char* id, float x = 0, float y = 16);
void finish(UiWindow window, const char* id);
void popup(UiWindow window, bool opening, std::function<void()> complete = {});
void select(UiWindow window, const char* indicator, const char* target);
}
