#include "find_controller.hpp"
#include "tag_collection.hpp"
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <cmath>

namespace spg {
namespace {
Json value(UiPage page,const char* key) {
    char* data=ui_page_get_json(page,key);
    if(!data) return Json();
    auto result=parse_json(data); ui_page_free(data); return result;
}
bool shown(ui::Widget* widget) {
    for(auto* p=widget;p;p=p->Parent()) if(!p->visible) return false;
    return widget!=nullptr;
}
}
ui::Widget* FindController::root() const { return ui::GetContext().GetWindow(window_)->Root().get(); }
bool FindController::visible(const Search& s) const { return shown(root()->FindById(s.scroll)); }
FindController::FindController(UiPage page,UiWindow window):page_(page),window_(window) {
    auto* owner=ui::GetContext().GetWindow(window_);
    owner->onAfterLayout=[this]{Decorate();};
    for(auto& s:searches_) {
        if(auto* list=dynamic_cast<ui::VirtualListWidget*>(root()->FindById(s.list))) {
            hooks_.push_back({std::static_pointer_cast<ui::VirtualListWidget>(list->shared_from_this()),list->onRangeChanged});
            auto previous=list->onRangeChanged;
            list->onRangeChanged=[this,previous]{if(previous) previous(); Decorate();};
        }
        if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll)))
            scroll->onDrawSearchMarkers=[this,&s](ui::Renderer& r){markers(s,r);};
    }
}
FindController::~FindController() {
    auto* owner=ui::GetContext().GetWindow(window_);
    if(!owner) return;
    owner->onAfterLayout={};
    for(auto& hook:hooks_) if(auto list=hook.list.lock()) list->onRangeChanged=std::move(hook.previous);
    for(auto& s:searches_) if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll))) scroll->onDrawSearchMarkers={};
}
void FindController::Refresh() { for(auto& s:searches_) if(visible(s)) refresh(s); }
void FindController::refresh(Search& s) {
    std::string oldId; int oldTag=-1; uint32_t oldStart=0;
    if(!s.hits.empty()) { auto h=s.hits[s.current]; auto& t=s.targets[h.target]; oldId=t.id; oldTag=t.tag; oldStart=t.ranges[h.range].start; }
    auto argument=Json(s.scope).dump();
    if(ui_page_call_json(page_,"searchSources",argument.c_str())!=0) throw std::runtime_error("uiBindingFailed");
    auto snapshot=value(page_,"searchSnapshot");
    ui_page_set_json(page_,"searchSnapshot","null"); // Never retain a duplicate of the reactive rows.
    auto query=fold_search(snapshot.at("query").get_ref<const std::string&>());
    bool changed=s.query!=query;
    if(changed) s.pending=0;
    s.before=snapshot.value("before",false); s.after=snapshot.value("after",false);
    s.query=std::move(query); s.targets.clear(); s.hits.clear(); s.byId.clear(); s.rows.clear(); s.ticks.clear();
    s.current=0; s.geometry=~uint64_t(0); s.extent=-1; s.revision=++revision_;
    if(s.query.empty()) {
        decltype(s.targets)().swap(s.targets); decltype(s.hits)().swap(s.hits);
        decltype(s.rows)().swap(s.rows); decltype(s.ticks)().swap(s.ticks); s.byId.rehash(0);
    }
    if(!s.query.empty()) for(auto& source:snapshot.at("targets")) {
        auto text=fold_search(source.at("text").get_ref<const std::string&>());
        Target target{source.at("id").get<std::string>(),source.at("row").get<int>(),source.at("tag").get<int>()};
        size_t at=0;
        while((at=text.find(s.query,at))!=std::wstring::npos) {
            if(!changed && target.id==oldId && target.tag==oldTag && at==oldStart) s.current=s.hits.size();
            target.ranges.push_back({uint32_t(at),uint32_t(s.query.size()),false});
            s.hits.push_back({s.targets.size(),target.ranges.size()-1}); at+=s.query.size();
        }
        if(!target.ranges.empty()) { s.byId[target.id].push_back(s.targets.size()); s.targets.push_back(std::move(target)); }
    }
    for(auto& t:s.targets) if(s.rows.empty() || s.rows.back()!=t.row) s.rows.push_back(t.row);
    if(!s.hits.empty()) {
        if(s.pending) s.current=s.pending>0?std::min(s.current+1,s.hits.size()-1):(s.current?s.current-1:0);
        auto h=s.hits[s.current]; s.targets[h.target].ranges[h.range].active=true;
    }
    const bool locate=changed || s.pending!=0;
    s.pending=0;
    decorate(s);
    if(locate && !s.hits.empty()) reveal(s);
}
void FindController::Decorate() { for(auto& s:searches_) if(visible(s)) decorate(s); }
void FindController::decorate(Search& s) {
    auto* area=root()->FindById(s.scroll); if(!area) return;
    std::function<void(ui::Widget*)> visit=[&](ui::Widget* w) {
        if(!w->visible) return;
        if(w->textHighlightRevision!=s.revision) {
            w->textHighlightRevision=s.revision; w->textHighlights.clear();
            std::map<size_t,std::vector<ui::TextHighlight>> tags;
            auto found=s.byId.find(w->id);
            if(found!=s.byId.end()) for(size_t index:found->second) {
                auto& t=s.targets[index];
                if(t.tag>=0) tags[size_t(t.tag)]=t.ranges; else w->textHighlights=t.ranges;
            }
            if(auto* collection=dynamic_cast<TagCollection*>(w)) {
                collection->SetHighlights(std::move(tags));
                auto* parent=collection->Parent();
                while(parent && !dynamic_cast<ui::ScrollViewWidget*>(parent)) parent=parent->Parent();
                if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(parent)) {
                    std::weak_ptr<TagCollection> weak=std::static_pointer_cast<TagCollection>(collection->shared_from_this());
                    scroll->onDrawSearchMarkers=[weak,scroll](ui::Renderer& r){if(auto item=weak.lock()) item->DrawSearchMarkers(r,*scroll);};
                }
            }
        }
        for(auto& child:w->Children()) visit(child.get());
    };
    visit(area);
}
void FindController::reveal(Search& s) {
    auto* owner=ui::GetContext().GetWindow(window_);
    if(ui::LayoutDirtyFlag()) owner->LayoutRoot();
    const auto& hit=s.hits[s.current]; const auto& target=s.targets[hit.target];
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll));
    auto* list=dynamic_cast<ui::VirtualListWidget*>(root()->FindById(s.list));
    if(scroll && list && target.row>=0 && size_t(target.row)<list->RowCount()) {
        float top=list->rect.top+list->padT+list->RowOffset(size_t(target.row));
        if(top<scroll->rect.top || top>=scroll->rect.bottom)
            owner->ScrollWithMeasureContext(scroll,scroll->ScrollY()+top-scroll->rect.top);
    }
    auto* widget=root()->FindById(target.id);
    if(!widget) return;
    auto box=[&]{auto* tags=dynamic_cast<TagCollection*>(widget);return tags && target.tag>=0?tags->TagBounds(size_t(target.tag)):widget->rect;};
    // Inner to outer; clamp the exposed rectangle to each inner viewport before
    // locating it in the next ancestor. A long TAG cloud cannot move its entire
    // offscreen extent into the outer page.
    auto bounds=box();
    for(auto* p=widget->Parent();p;p=p->Parent()) if(auto* ancestor=dynamic_cast<ui::ScrollViewWidget*>(p)) {
        float delta=bounds.top<ancestor->rect.top?bounds.top-ancestor->rect.top:
            bounds.bottom>ancestor->rect.bottom?std::min(bounds.bottom-ancestor->rect.bottom,bounds.top-ancestor->rect.top):0;
        const float before=ancestor->ScrollY();
        owner->ScrollWithMeasureContext(ancestor,before+delta);
        float moved=ancestor->ScrollY()-before; bounds.top-=moved; bounds.bottom-=moved;
        bounds.top=std::max(bounds.top,ancestor->rect.top); bounds.bottom=std::min(bounds.bottom,ancestor->rect.bottom);
    }
    decorate(s); owner->Invalidate();
}
void FindController::Move(const std::string& scope,int direction) {
    auto found=std::find_if(searches_.begin(),searches_.end(),[&](auto& s){return scope==s.scope;});
    if(found==searches_.end() || !visible(*found) || found->hits.empty()) return;
    auto& s=*found;
    if(auto* input=root()->FindById(scope+"Search")) ui::GetContext().GetWindow(window_)->FocusWidget(input,false);
    if(scope=="task" && ((direction>0 && s.current+1==s.hits.size() && s.after) ||
                         (direction<0 && s.current==0 && s.before))) {
        s.pending=direction; auto encoded=Json(direction).dump(); ui_page_call_json(page_,"searchTaskPage",encoded.c_str()); return;
    }
    activate(s,s.hits[s.current],false);
    s.current=direction>0?(s.current+1)%s.hits.size():(s.current+s.hits.size()-1)%s.hits.size();
    activate(s,s.hits[s.current],true);
    reveal(s);
}
void FindController::activate(Search& s,const Hit& h,bool active) {
    auto& t=s.targets[h.target]; t.ranges[h.range].active=active;
    auto* widget=root()->FindById(t.id);
    if(auto* tags=dynamic_cast<TagCollection*>(widget)) tags->SetActiveHighlight(size_t(t.tag),h.range,active);
    else if(widget && h.range<widget->textHighlights.size()) widget->textHighlights[h.range].active=active;
}
bool FindController::Key(int vk) {
    auto* focused=ui::GetContext().GetWindow(window_)->FocusedWidget();
    if(!focused || (GetKeyState(VK_CONTROL)&0x8000) || (GetKeyState(VK_MENU)&0x8000)) return false;
    for(auto& s:searches_) if(focused->id==std::string(s.scope)+"Search") {
        if(vk==VK_UP || vk==VK_DOWN || vk==VK_RETURN || vk==VK_F3) {
            Move(s.scope,vk==VK_UP || (GetKeyState(VK_SHIFT)&0x8000)?-1:1); return true;
        }
    }
    return false;
}
void FindController::markers(Search& s,ui::Renderer& r) {
    if(s.hits.empty()) return;
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll));
    auto* list=dynamic_cast<ui::VirtualListWidget*>(root()->FindById(s.list));
    if(!scroll || !list) return;
    const float extent=std::max(1.0f,scroll->ContentHeight()),height=scroll->rect.bottom-scroll->rect.top;
    const float offset=list->rect.top-scroll->rect.top+scroll->ScrollY()+list->padT;
    auto position=[&](int row){return row<0?0.0f:(offset+list->RowOffset(size_t(row)))/extent*(height-3);};
    if(s.geometry!=list->GeometryRevision() || s.extent!=extent || std::abs(s.offset-offset)>0.5f || s.height!=height) {
        s.geometry=list->GeometryRevision(); s.extent=extent; s.offset=offset; s.height=height; s.ticks.clear();
        float last=-10;
        for(int row:s.rows) {float at=std::floor(position(row));if(at!=last) {s.ticks.push_back(at);last=at;}}
    }
    const auto b=scroll->ScrollbarTrackRect();
    for(float tick:s.ticks) r.FillRoundedRect({b.left,b.top+tick,b.right,b.top+tick+2},1,1,D2D1::ColorF(0xd2ad22));
    float at=b.top+position(s.targets[s.hits[s.current].target].row);
    r.FillRoundedRect({b.left,at,b.right,at+3},1,1,D2D1::ColorF(0xef8c22));
}
}
