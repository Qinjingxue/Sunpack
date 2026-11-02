#pragma once
#include <ui/controls.h>
#include <ui/measure_context.h>
#include <map>

namespace spg {
// One native surface per array, with cached flow geometry and visible-only
// painting. Tags do not allocate individual widgets or JS event closures.
class TagCollection final : public ui::Widget {
    struct Tag { std::wstring value; bool regex=false; float width=-1; D2D1_RECT_F bounds{}; };
    std::vector<Tag> tags_;
    std::string source_;
    float width_=-1, height_=28;
    int hovered_=-1, pressed_=-1;
    bool hovered_close_=false, pressed_close_=false;
    std::map<size_t,std::vector<ui::TextHighlight>> highlights_;
    std::vector<float> markers_;
    mutable std::vector<float> ticks_;
    mutable float tick_height_=-1;
    int active_tag_=-1;
    void rebuild_markers();
    std::wstring label(const Tag& tag) const;
    int tag_at(float x,float y) const;
    D2D1_RECT_F bounds(size_t index) const;
public:
    std::function<void(size_t,const std::wstring&,bool)> onRemove, onEdit;
    bool SetItems(const std::string& source);
    void SetHighlights(std::map<size_t,std::vector<ui::TextHighlight>> highlights);
    void SetActiveHighlight(size_t tag,size_t range,bool active);
    D2D1_RECT_F TagBounds(size_t index) const { return index<tags_.size()?bounds(index):rect; }
    void DrawSearchMarkers(ui::Renderer& renderer,const ui::ScrollViewWidget& scroll) const;
    D2D1_SIZE_F SizeHint() const override { return {0,height_}; }
    void DoLayout() override;
    void OnDraw(ui::Renderer& renderer) override;
    bool OnMouseMove(const ui::MouseEvent& event) override;
    bool OnMouseDown(const ui::MouseEvent& event) override;
    bool OnMouseUp(const ui::MouseEvent& event) override;
};
}
