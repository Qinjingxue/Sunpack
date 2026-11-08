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
    ui::UiWindowImpl& window_; // This wrapper belongs to the window's root tree.
    int alpha_=-1;
public:
    explicit PopupSurface(ui::UiWindowImpl& window) : window_(window) { id = "datePopupSurface"; }
    void DrawTree(ui::Renderer& renderer) override {
        int alpha=int(std::clamp(opacity,0.0f,1.0f)*255);
        if(alpha!=alpha_) {
            window_.SetWindowAlpha(BYTE(alpha));
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
        auto frame=std::make_shared<PopupSurface>(*window);
        auto contents=window->Root();
        frame->opacity=opening?0.0f:1.0f;
        frame->AddChild(contents);
        window->SetWindowAlpha(opening?0:255);
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
