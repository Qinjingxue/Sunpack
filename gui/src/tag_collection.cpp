#include "tag_collection.hpp"
#include "model.hpp"
#include <ui/event.h>

namespace spg {
namespace { constexpr float font=13, chipHeight=26, gap=4, closeWidth=22; }
std::wstring TagCollection::label(const Tag& tag) const {
    if(tag.value.empty()) return empty_;
    auto text=tag.value;
    for(auto& c:text) { if(c==L'\r') c=L'␍'; else if(c==L'\n') c=L'↵'; }
    return text;
}
bool TagCollection::SetItems(const std::string& source,const std::wstring& empty,const std::wstring& none) {
    if(source_==source && empty_==empty && none_==none) return false;
    auto values=parse_json(source);
    std::vector<Tag> next; next.reserve(values.size());
    for(const auto& value:values) next.push_back({wide(value.get_ref<const std::string&>())});
    tags_=std::move(next); source_=source; empty_=empty; none_=none; width_=-1;
    hovered_=pressed_=-1; tooltip.clear();
    ui::RequestLayout();
    return true;
}
void TagCollection::DoLayout() {
    const float width=std::max(1.0f,rect.right-rect.left);
    if(width_!=width) {
        float x=0,y=0;
        for(auto& tag:tags_) {
            if(tag.width<0) {
                auto text=label(tag);
                tag.width=ui::g_activeMeasureContext?ui::g_activeMeasureContext->MeasureTextWidth(text,font)+8+closeWidth:float(text.size())*7+8+closeWidth;
            }
            float w=std::min(width,std::min(240.0f,std::max(38.0f,tag.width)));
            if(x>0 && x+w>width) { x=0; y+=chipHeight+gap; }
            tag.bounds={x,y,x+w,y+chipHeight}; x+=w+gap;
        }
        height_=tags_.empty()?chipHeight:y+chipHeight; width_=width;
    }
    rect.bottom=rect.top+height_;
}
D2D1_RECT_F TagCollection::bounds(size_t index) const {
    auto r=tags_[index].bounds;
    r.left+=rect.left; r.right+=rect.left; r.top+=rect.top; r.bottom+=rect.top;
    return r;
}
int TagCollection::tag_at(float x,float y,bool close_only) const {
    auto it=std::lower_bound(tags_.begin(),tags_.end(),y-rect.top,[](const Tag& tag,float y){return tag.bounds.bottom<y;});
    for(;it!=tags_.end() && it->bounds.top<=y-rect.top;++it) {
        auto r=bounds(size_t(it-tags_.begin()));
        if(x>=r.left && x<=r.right && (!close_only || x>=r.right-closeWidth)) return int(it-tags_.begin());
    }
    return -1;
}
void TagCollection::OnDraw(ui::Renderer& r) {
    auto fg=theme::kBtnText();
    if(tags_.empty()) {
        r.DrawText(none_,{rect.left+4,rect.top,rect.right,rect.top+chipHeight},theme::kContentText(),font);
        return;
    }
    // Intersect scroll ancestors before searching the first visible row.
    float top=rect.top,bottom=rect.bottom;
    for(auto* p=Parent();p;p=p->Parent()) if(dynamic_cast<ui::ScrollViewWidget*>(p)) { top=std::max(top,p->rect.top); bottom=std::min(bottom,p->rect.bottom); }
    auto first=std::lower_bound(tags_.begin(),tags_.end(),top-rect.top-chipHeight,[](const Tag& tag,float y){return tag.bounds.bottom<y;});
    for(auto it=first;it!=tags_.end() && it->bounds.top<=bottom-rect.top+chipHeight;++it) {
        auto index=size_t(it-tags_.begin()); auto box=bounds(index);
        if(r.IsCulled(box)) continue;
        auto bg=theme::IsDark()?theme::Rgba(255,255,255,0.08f):theme::Rgba(0,0,0,0.055f);
        r.FillRoundedRect(box,4,4,bg);
        if(int(index)==hovered_) r.FillRoundedRect({box.right-closeWidth,box.top,box.right,box.bottom},4,4,theme::IsDark()?theme::Rgba(255,255,255,0.12f):theme::Rgba(0,0,0,0.08f));
        r.DrawText(label(*it),{box.left+8,box.top,box.right-closeWidth,box.bottom},fg,font);
        float cx=box.right-closeWidth/2,cy=(box.top+box.bottom)/2;
        r.DrawLine(cx-3,cy-3,cx+3,cy+3,fg,1); r.DrawLine(cx+3,cy-3,cx-3,cy+3,fg,1);
    }
}
bool TagCollection::OnMouseMove(const ui::MouseEvent& e) {
    hovered_=tag_at(e.x,e.y,true); cursor=hovered_>=0?ui::CursorKind::Pointer:ui::CursorKind::Default;
    int index=tag_at(e.x,e.y,false); tooltip=index>=0?tags_[index].value:std::wstring();
    return Contains(e.x,e.y);
}
bool TagCollection::OnMouseDown(const ui::MouseEvent& e) { pressed_=tag_at(e.x,e.y,true); return pressed_>=0; }
bool TagCollection::OnMouseUp(const ui::MouseEvent& e) {
    int pressed=pressed_; pressed_=-1;
    if(pressed<0 || pressed!=tag_at(e.x,e.y,true) || !onRemove) return false;
    auto remove=onRemove; auto value=tags_[pressed].value;
    remove(size_t(pressed),value); return true;
}
}
