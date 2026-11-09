#pragma once
#include <ui/ui_window.h>
#include <cassert>
#include <cmath>

namespace gui_test {
inline void same_color(D2D1_COLOR_F actual,D2D1_COLOR_F expected) {
    assert(std::abs(actual.r-expected.r)<0.001f && std::abs(actual.g-expected.g)<0.001f &&
        std::abs(actual.b-expected.b)<0.001f && std::abs(actual.a-expected.a)<0.001f);
}

// Ordinary screenshots hide a wrong Clear behind the opaque page. Inspect the
// actual recording that RenderWindow uses for both Clear and DXGI resize fill.
// Move it out and back without copying owned resources or changing commands.
inline void clear_color(ui::UiWindowImpl& window,D2D1_COLOR_F expected) {
    struct Probe final : ui::Widget {
        bool painted=false;
        D2D1_COLOR_F color{};
        void DrawTree(ui::Renderer& renderer) override {
            auto* recorder=renderer.DisplayListRecorderTarget(); assert(recorder);
            auto list=recorder->Finish();
            assert(!list.commands.empty() && list.commands.front().type==ui::DrawCommandType::Clear);
            color=list.commands.front().color;
            painted=true;
            recorder->Reset(std::move(list));
        }
    };
    auto root=window.Root(); assert(root);
    auto probe=std::make_shared<Probe>(); probe->positionAbsolute=true;
    root->AddChild(probe);
    window.InvalidateNow();
    root->RemoveChild(probe.get());
    assert(probe->painted);
    same_color(probe->color,expected);
}
}
