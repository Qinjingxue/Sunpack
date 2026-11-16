#pragma once

#include <cstring>
#include <initializer_list>
#include <windows.h>

#include "ui_core.h"

#ifndef UI_CORE_ENABLE_TRACE
#define UI_CORE_ENABLE_TRACE 0
#endif

namespace ui {

#if UI_CORE_ENABLE_TRACE
void EmitTrace(const char* source,
               const char* category,
               const char* name,
               const UiTraceField* fields,
               uint32_t field_count);
bool IsTraceEnabled();

inline UiTraceField TraceI64(const char* key, int64_t value) {
    return UiTraceField{key, UI_TRACE_FIELD_I64, value, 0, 0.0, 0, nullptr};
}

inline UiTraceField TraceU64(const char* key, uint64_t value) {
    return UiTraceField{key, UI_TRACE_FIELD_U64, 0, value, 0.0, 0, nullptr};
}

inline UiTraceField TraceF64(const char* key, double value) {
    return UiTraceField{key, UI_TRACE_FIELD_F64, 0, 0, value, 0, nullptr};
}

inline UiTraceField TraceBool(const char* key, bool value) {
    return UiTraceField{key, UI_TRACE_FIELD_BOOL, 0, 0, 0.0, value ? 1 : 0, nullptr};
}

inline const char* TraceCategoryForSource(const char* source) {
    if (source && std::strcmp(source, "core_window") == 0) return "window";
    if (source && std::strcmp(source, "core_renderer") == 0) return "render";
    if (source && std::strcmp(source, "gh_img_view") == 0) return "render";
    return "ui";
}

inline void TraceEvent(const char* source, const char* name) {
    EmitTrace(source, TraceCategoryForSource(source), name, nullptr, 0);
}

inline void TraceEvent(const char* source,
                       const char* name,
                       std::initializer_list<UiTraceField> fields) {
    EmitTrace(source,
              TraceCategoryForSource(source),
              name,
              fields.begin(),
              static_cast<uint32_t>(fields.size()));
}
#else
constexpr bool IsTraceEnabled() { return false; }
#endif

class TraceScope {
public:
#if UI_CORE_ENABLE_TRACE
    TraceScope(const char* source, const char* name)
        : source_(source), name_(name), enabled_(IsTraceEnabled()) {
        if (enabled_) QueryPerformanceCounter(&start_);
    }

    ~TraceScope() {
        if (!enabled_) return;
        LARGE_INTEGER now{};
        LARGE_INTEGER freq{};
        QueryPerformanceCounter(&now);
        QueryPerformanceFrequency(&freq);
        double ms = 0.0;
        if (freq.QuadPart > 0) {
            ms = (double)(now.QuadPart - start_.QuadPart) * 1000.0 /
                 (double)freq.QuadPart;
        }
        TraceEvent(source_, name_, {TraceF64("duration_ms", ms)});
    }

private:
    const char* source_;
    const char* name_;
    bool enabled_;
    LARGE_INTEGER start_{};
#else
    constexpr TraceScope(const char*, const char*) noexcept {}
#endif
};

}  // namespace ui

// A no-op function would still evaluate the field expressions at the call site.
#if UI_CORE_ENABLE_TRACE
#define UI_TRACE_EVENT(...) do { if (::ui::IsTraceEnabled()) ::ui::TraceEvent(__VA_ARGS__); } while (false)
#else
#define UI_TRACE_EVENT(...) ((void)0)
#endif
