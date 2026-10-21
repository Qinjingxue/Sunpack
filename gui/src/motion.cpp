#include "motion.hpp"
// This adapter is the only GUI code using Core UI's pinned animation API.
// Both motion and controls share the window's finite frame scheduler.
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <algorithm>

namespace spg::motion {
namespace {
// The window owns this wrapper and its original page tree. Animate alpha with
// the existing presentation clock, including the popup's background/border.
// A widget opacity layer alone would leave an opaque window flashing behind it.
class PopupSurface final : public ui::Widget {
    HWND hwnd_;
public:
    explicit PopupSurface(HWND hwnd) : hwnd_(hwnd) { id = "datePopupSurface"; }
    void DrawTree(ui::Renderer& renderer) override {
        SetLayeredWindowAttributes(hwnd_,0,BYTE(std::clamp(opacity,0.0f,1.0f)*255),LWA_ALPHA);
        for(auto& child:Children()) child->DrawTree(renderer);
    }
};
bool enabled() {
    BOOL value = TRUE;
    SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &value, 0);
    return value != FALSE;
}
ui::Widget* find(ui::UiWindowImpl* window, const char* id) {
    return window && window->Root() ? window->Root()->FindById(id) : nullptr;
}
void reset(ui::UiWindowImpl* window, ui::Widget* widget) {
    for(auto property : {ui::AnimProperty::Opacity, ui::AnimProperty::TranslateX, ui::AnimProperty::TranslateY})
        window->CancelPropertyAnimation(widget, property);
    widget->opacity = 1; widget->animationX = widget->animationY = 0;
}
}
void finish(UiWindow handle, const char* id) {
    auto* window = ui::GetContext().GetWindow(handle);
    if(auto* widget = find(window, id)) reset(window, widget);
}
void enter(UiWindow handle, const char* id, float x, float y) {
    auto* window = ui::GetContext().GetWindow(handle);
    auto* widget = find(window, id);
    if(!widget) return;
    reset(window, widget);
    for(auto* parent = widget; parent; parent = parent->Parent()) if(!parent->visible) return;
    if(!enabled()) { window->Invalidate(); return; }
    // Fluent entrance: commit the new data/layout before fading and translating.
    // Translation affects paint, never control sizes or scroll offsets.
    widget->opacity = 0; widget->animationX = x; widget->animationY = y;
    window->AnimateProperty(widget, ui::AnimProperty::Opacity, 0, 1, 167, ui::EasingFunction::Linear);
    if(x) window->AnimateProperty(widget, ui::AnimProperty::TranslateX, x, 0, 250, ui::EasingFunction::FluentEnter);
    if(y) window->AnimateProperty(widget, ui::AnimProperty::TranslateY, y, 0, 250, ui::EasingFunction::FluentEnter);
}
void select(UiWindow handle, const char* id, const char* targetId) {
    auto* window = ui::GetContext().GetWindow(handle);
    auto* indicator = find(window, id); auto* target = find(window, targetId);
    if(!indicator || !target) return;
    float offset = (target->rect.top + target->rect.bottom - (indicator->rect.bottom - indicator->rect.top)) / 2 - indicator->rect.top;
    if(!enabled()) {
        window->CancelPropertyAnimation(indicator, ui::AnimProperty::TranslateY);
        indicator->animationY = offset; window->Invalidate(); return;
    }
    window->AnimateProperty(indicator, ui::AnimProperty::TranslateY, indicator->animationY, offset, 170, ui::EasingFunction::FluentStandard);
}
void popup(UiWindow handle, bool opening, std::function<void()> complete) {
    auto* window = ui::GetContext().GetWindow(handle);
    if(!window || !window->Root()) { if(complete) complete(); return; }
    auto* surface = dynamic_cast<PopupSurface*>(window->Root().get());
    if(!surface) {
        auto frame=std::make_shared<PopupSurface>(window->Handle());
        auto contents=window->Root();
        frame->opacity=opening?0.0f:1.0f;
        frame->AddChild(contents);
        SetWindowLongPtrW(window->Handle(),GWL_EXSTYLE,GetWindowLongPtrW(window->Handle(),GWL_EXSTYLE)|WS_EX_LAYERED);
        SetLayeredWindowAttributes(window->Handle(),0,opening?0:255,LWA_ALPHA);
        surface=frame.get();
        window->SetRoot(std::move(frame));
    }
    const float target=opening?1.0f:0.0f;
    if(!enabled()) {
        window->CancelPropertyAnimation(surface,ui::AnimProperty::Opacity);
        surface->opacity=target; window->Invalidate();
        if(complete) complete();
        return;
    }
    window->AnimateProperty(surface,ui::AnimProperty::Opacity,surface->opacity,target,opening?167.0f:83.0f,ui::EasingFunction::Linear,std::move(complete));
}
}
