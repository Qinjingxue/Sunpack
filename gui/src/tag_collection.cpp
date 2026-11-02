#include "tag_collection.hpp"
#include "model.hpp"
#include <ui/event.h>
#include <cmath>

namespace spg {
namespace { constexpr float font=13, chipHeight=26, gap=4, closeWidth=22, textInset=8, closeGap=3; }
std::wstring TagCollection::label(const Tag& tag) const {
    auto text=tag.value;
    for(auto& c:text) { if(c==L'\r') c=L'␍'; else if(c==L'\n') c=L'↵'; }
    return text;
}
bool TagCollection::SetItems(const std::string& source) {
    if(source_==source) return false;
    auto values=parse_json(source);
    std::vector<Tag> next; next.reserve(values.size());
    for(const auto& value:values) next.push_back({wide(value.at("value").get_ref<const std::string&>()),value.at("regex").get<bool>()});
    tags_=std::move(next); source_=source; width_=-1;
    highlights_.clear(); markers_.clear(); active_tag_=-1;
    hovered_=pressed_=-1;
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
                tag.width=(ui::g_activeMeasureContext?ui::g_activeMeasureContext->MeasureTextWidth(text,font):float(text.size())*7)+textInset+closeGap+closeWidth;
            }
            float w=std::min(width,std::min(240.0f,std::max(38.0f,tag.width)));
            if(x>0 && x+w>width) { x=0; y+=chipHeight+gap; }
            tag.bounds={x,y,x+w,y+chipHeight}; x+=w+gap;
        }
        height_=tags_.empty()?chipHeight:y+chipHeight; width_=width;
        rebuild_markers();
    }
    rect.bottom=rect.top+height_;
}
D2D1_RECT_F TagCollection::bounds(size_t index) const {
    auto r=tags_[index].bounds;
    r.left+=rect.left; r.right+=rect.left; r.top+=rect.top; r.bottom+=rect.top;
    return r;
}
int TagCollection::tag_at(float x,float y) const {
    auto it=std::lower_bound(tags_.begin(),tags_.end(),y-rect.top,[](const Tag& tag,float y){return tag.bounds.bottom<y;});
    for(;it!=tags_.end() && it->bounds.top<=y-rect.top;++it) {
        auto r=bounds(size_t(it-tags_.begin()));
        if(x>=r.left && x<=r.right) return int(it-tags_.begin());
    }
    return -1;
}
void TagCollection::OnDraw(ui::Renderer& r) {
    if(tags_.empty()) return;
    // Intersect scroll ancestors before searching the first visible row.
    float top=rect.top,bottom=rect.bottom;
    for(auto* p=Parent();p;p=p->Parent()) if(dynamic_cast<ui::ScrollViewWidget*>(p)) { top=std::max(top,p->rect.top); bottom=std::min(bottom,p->rect.bottom); }
    auto first=std::lower_bound(tags_.begin(),tags_.end(),top-rect.top-chipHeight,[](const Tag& tag,float y){return tag.bounds.bottom<y;});
    for(auto it=first;it!=tags_.end() && it->bounds.top<=bottom-rect.top+chipHeight;++it) {
        auto index=size_t(it-tags_.begin()); auto box=bounds(index);
        if(r.IsCulled(box)) continue;
        auto bg=theme::IsDark()?theme::Rgba(255,255,255,0.08f):theme::Rgba(0,0,0,0.055f);
        auto fg=theme::kBtnText();
        if(it->regex) {
            bg=theme::IsDark()?theme::Rgba(65,160,220,0.22f):theme::Rgba(0,103,192,0.11f);
            fg=theme::IsDark()?theme::Rgba(140,219,255,1):theme::Rgba(0,82,145,1);
        }
        r.FillRoundedRect(box,4,4,bg);
        if(int(index)==hovered_ && hovered_close_) r.FillRoundedRect({box.right-closeWidth,box.top,box.right,box.bottom},4,4,theme::IsDark()?theme::Rgba(255,255,255,0.12f):theme::Rgba(0,0,0,0.08f));
        auto match=highlights_.find(index);
        auto* previous=r.textHighlights;
        r.textHighlights=match==highlights_.end()?nullptr:&match->second;
        r.DrawText(label(*it),{box.left+textInset,box.top,box.right-closeWidth-closeGap,box.bottom},fg,font);
        r.textHighlights=previous;
        float cx=box.right-closeWidth/2,cy=(box.top+box.bottom)/2;
        r.DrawLine(cx-3,cy-3,cx+3,cy+3,fg,1); r.DrawLine(cx+3,cy-3,cx-3,cy+3,fg,1);
    }
}
void TagCollection::SetHighlights(std::map<size_t,std::vector<ui::TextHighlight>> highlights) {
    highlights_=std::move(highlights); rebuild_markers();
    if(highlights_.empty()) decltype(markers_)().swap(markers_);
}
void TagCollection::SetActiveHighlight(size_t tag,size_t range,bool active) {
    auto found=highlights_.find(tag);
    if(found==highlights_.end() || range>=found->second.size()) return;
    found->second[range].active=active;
    active_tag_=active?int(tag):-1;
}
void TagCollection::rebuild_markers() {
    markers_.clear(); tick_height_=-1; active_tag_=-1;
    for(auto& item:highlights_) if(item.first<tags_.size()) {
        const float y=tags_[item.first].bounds.top+chipHeight/2;
        if(markers_.empty() || markers_.back()!=y) markers_.push_back(y);
        for(auto& h:item.second) if(h.active) active_tag_=int(item.first);
    }
}
void TagCollection::DrawSearchMarkers(ui::Renderer& r,const ui::ScrollViewWidget& scroll) const {
    const auto box=scroll.ScrollbarTrackRect();
    const float height=box.bottom-box.top;
    if(tick_height_!=height) {
        tick_height_=height; ticks_.clear();
        for(float y:markers_) {
            float at=std::floor(y/std::max(1.0f,height_)*(height-2));
            if(ticks_.empty() || ticks_.back()!=at) ticks_.push_back(at);
        }
    }
    for(float at:ticks_) r.FillRoundedRect({box.left,box.top+at,box.right,box.top+at+2},1,1,D2D1::ColorF(0xd2ad22));
    if(active_tag_>=0) {
        float at=box.top+(tags_[active_tag_].bounds.top+chipHeight/2)/std::max(1.0f,height_)*(box.bottom-box.top-3);
        r.FillRoundedRect({box.left,at,box.right,at+3},1,1,D2D1::ColorF(0xef8c22));
    }
}
bool TagCollection::OnMouseMove(const ui::MouseEvent& e) {
    hovered_=tag_at(e.x,e.y); cursor=hovered_>=0?ui::CursorKind::Pointer:ui::CursorKind::Default;
    hovered_close_=hovered_>=0 && e.x>=bounds(size_t(hovered_)).right-closeWidth;
    return Contains(e.x,e.y);
}
bool TagCollection::OnMouseDown(const ui::MouseEvent& e) { pressed_=tag_at(e.x,e.y); pressed_close_=pressed_>=0 && e.x>=bounds(size_t(pressed_)).right-closeWidth; return pressed_>=0; }
bool TagCollection::OnMouseUp(const ui::MouseEvent& e) {
    int pressed=pressed_; pressed_=-1;
    if(pressed<0 || pressed!=tag_at(e.x,e.y) || pressed_close_!=(e.x>=bounds(size_t(pressed)).right-closeWidth)) return false;
    auto action=pressed_close_?onRemove:onEdit;
    if(!action) return false;
    auto value=tags_[pressed].value; bool regex=tags_[pressed].regex;
    action(size_t(pressed),value,regex); return true;
}
}
