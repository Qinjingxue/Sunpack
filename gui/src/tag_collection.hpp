#pragma once
#include <ui/controls.h>
#include <ui/measure_context.h>

namespace spg {
// One native surface per array, with cached flow geometry and visible-only
// painting. Tags do not allocate individual widgets or JS event closures.
class TagCollection final : public ui::Widget {
    struct Tag { std::wstring value; float width=-1; D2D1_RECT_F bounds{}; };
    std::vector<Tag> tags_;
    std::string source_;
    std::wstring empty_,none_;
    float width_=-1, height_=28;
    int hovered_=-1, pressed_=-1;
    std::wstring label(const Tag& tag) const;
    int tag_at(float x,float y,bool close_only) const;
    D2D1_RECT_F bounds(size_t index) const;
public:
    std::function<void(size_t,const std::wstring&)> onRemove;
    bool SetItems(const std::string& source,const std::wstring& empty,const std::wstring& none);
    D2D1_SIZE_F SizeHint() const override { return {0,height_}; }
    void DoLayout() override;
    void OnDraw(ui::Renderer& renderer) override;
    bool OnMouseMove(const ui::MouseEvent& event) override;
    bool OnMouseDown(const ui::MouseEvent& event) override;
    bool OnMouseUp(const ui::MouseEvent& event) override;
};
}
