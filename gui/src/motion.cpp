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
    int alpha_=-1;
public:
    explicit PopupSurface(HWND hwnd) : hwnd_(hwnd) { id = "datePopupSurface"; }
    void DrawTree(ui::Renderer& renderer) override {
        int alpha=int(std::clamp(opacity,0.0f,1.0f)*255);
        if(alpha!=alpha_) {
            SetLayeredWindowAttributes(hwnd_,0,BYTE(alpha),LWA_ALPHA);
            alpha_=alpha;
        }
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
void enter(UiWindow handle, const char* id) {
    auto* window = ui::GetContext().GetWindow(handle);
    auto* widget = find(window, id);
    if(!widget) return;
    for(auto* parent = widget; parent; parent = parent->Parent()) if(!parent->visible) {
        reset(window, widget); return;
    }
    if(!enabled()) { reset(window, widget); window->Invalidate(); return; }
    // Repeated requests join the existing finite clock. Only navigation calls
    // this adapter; filtering and snapshot updates never start an entrance.
    if(widget->animationY!=0) return;
    reset(window, widget);
    // Keep text and surfaces opaque throughout. This short paint-only move
    // needs neither an opacity layer nor an outgoing-page snapshot or layout.
    widget->animationY=6;
    window->AnimateProperty(widget,ui::AnimProperty::TranslateY,6,0,260,ui::EasingFunction::EaseOutCubic);
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
    window->AnimateProperty(surface,ui::AnimProperty::Opacity,surface->opacity,target,opening?100.0f:67.0f,ui::EasingFunction::Linear,std::move(complete));
}
}
