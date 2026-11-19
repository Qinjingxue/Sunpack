#include "find_controller.hpp"
#include "page_value.hpp"
#include "tag_collection.hpp"
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <cmath>

namespace spg {
namespace {
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
            s.hooked_list=std::static_pointer_cast<ui::VirtualListWidget>(list->shared_from_this());
            s.previous_on_range_changed=std::move(list->onRangeChanged);
            list->onRangeChanged=[this,&s]{if(s.previous_on_range_changed) s.previous_on_range_changed(); Decorate();};
        }
        if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll)))
            scroll->onDrawSearchMarkers=[this,&s](ui::Renderer& r){markers(s,r);};
    }
}
FindController::~FindController() {
    auto* owner=ui::GetContext().GetWindow(window_);
    if(owner) owner->onAfterLayout={};
    for(auto& s:searches_) {
        if(auto list=s.hooked_list.lock()) list->onRangeChanged=std::move(s.previous_on_range_changed);
        if(owner) if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll))) scroll->onDrawSearchMarkers={};
    }
}
void FindController::Refresh(const char* scope) {
    for(auto& s:searches_) {
        if(scope && std::string_view(scope)!=s.scope) continue;
        if(visible(s)) {
            refresh(s);
            continue;
        }
        if(!s.matches.empty()) clear_matches(s);
        if(!s.targets.empty()) {
            s.saved=selection(s);
            release_results(s);
            s.revision=++revision_;
            decorate(s);
        }
    }
}
FindController::Selection FindController::selection(const Search& s) {
    const auto& hit=s.current;
    const auto& target=s.targets[hit.target];
    return {target.widget->first,target.tag,target.ranges[hit.range].start};
}
bool FindController::at_edge(const Search& s,int direction) {
    const auto [target,range]=s.current;
    return direction>0 ? target+1==s.targets.size() && range+1==s.targets.back().ranges.size() : target==0 && range==0;
}
void FindController::advance(Search& s,int direction) {
    auto& [target,range]=s.current;
    if(direction>0) {
        if(++range==s.targets[target].ranges.size()) {
            target=(target+1)%s.targets.size();
            range=0;
        }
    } else if(range) --range;
    else {
        target=target?target-1:s.targets.size()-1;
        range=s.targets[target].ranges.size()-1;
    }
}
void FindController::release_results(Search& s) {
    decltype(s.targets)().swap(s.targets);
    decltype(s.ticks)().swap(s.ticks);
    decltype(s.byId)().swap(s.byId);
}
void FindController::clear_matches(Search& s) {
    decltype(s.matchIndex)().swap(s.matchIndex);
    s.matches.clear(); s.matchBytes=0;
}
std::vector<ui::TextHighlight> FindController::match(Search& s,const std::string& text) {
    auto found=s.matchIndex.find(text);
    if(found!=s.matchIndex.end()) {
        s.matches.splice(s.matches.begin(),s.matches,found->second);
        return found->second->ranges;
    }
    auto folded=fold_search(text);
    std::vector<ui::TextHighlight> ranges;
    size_t at=0;
    while((at=folded.find(s.query,at))!=std::wstring::npos) {
        ranges.push_back({uint32_t(at),uint32_t(s.query.size()),false}); at+=s.query.size();
    }
    constexpr size_t budget=256*1024;
    // Include list/hash node and bucket overhead in the acceleration budget.
    const size_t bytes=sizeof(Match)+text.size()+1+ranges.size()*sizeof(ui::TextHighlight)+96;
    if(bytes<=budget) {
        while(s.matchBytes+bytes>budget) {
            auto& old=s.matches.back(); s.matchBytes-=old.bytes;
            s.matchIndex.erase(old.text); s.matches.pop_back();
        }
        s.matches.push_front({text,ranges,bytes}); s.matchBytes+=bytes;
        s.matchIndex.emplace(s.matches.front().text,s.matches.begin());
    }
    return ranges;
}
void FindController::refresh(Search& s) {
    if(s.query.empty() && page_value(page_,(std::string(s.scope)+"Query").c_str())=="") return;
    auto argument=Json(s.scope).dump();
    if(ui_page_call_json(page_,"searchSources",argument.c_str())!=0) throw std::runtime_error("uiBindingFailed");
    auto snapshot=page_value(page_,"searchSnapshot",true);
    ui_page_set_json(page_,"searchSnapshot","null"); // Never retain a duplicate of the reactive rows.
    auto query=fold_search(snapshot.at("query").get_ref<const std::string&>());
    const bool changed=s.query!=query;
    if(!changed && query.empty()) return;
    const bool had_results=!s.targets.empty();
    auto old=changed?Selection{}:s.targets.empty()?std::move(s.saved):selection(s);
    s.saved={};
    if(changed) clear_matches(s);
    if(changed) s.pending=0;
    s.before=snapshot.value("before",false); s.after=snapshot.value("after",false);
    s.query=std::move(query); s.targets.clear(); s.byId.clear(); s.ticks.clear();
    s.current={}; s.geometry=~uint64_t(0); s.extent=-1; s.revision=++revision_;
    if(!s.query.empty()) for(auto& source:snapshot.at("targets")) {
        auto ranges=match(s,source.at("text").get_ref<const std::string&>());
        if(ranges.empty()) continue;
        const auto& id=source.at("id").get_ref<const std::string&>();
        auto [widget,inserted]=s.byId.try_emplace(id,s.targets.size());
        if(!inserted) widget->second.remaining.push_back(s.targets.size());
        Target target{&*widget,source.at("row").get<int>(),source.at("tag").get<int>(),std::move(ranges)};
        if(!changed && id==old.id && target.tag==old.tag) {
            const auto found=std::lower_bound(target.ranges.begin(),target.ranges.end(),old.start,
                [](const ui::TextHighlight& range,uint32_t start){return range.start<start;});
            if(found!=target.ranges.end() && found->start==old.start)
                s.current={s.targets.size(),size_t(found-target.ranges.begin())};
        }
        s.targets.push_back(std::move(target));
    }
    if(!s.targets.empty()) {
        if(s.pending && !at_edge(s,s.pending)) advance(s,s.pending);
        s.targets[s.current.target].ranges[s.current.range].active=true;
        if(s.targets.capacity()/4>std::max<size_t>(64,s.targets.size())) s.targets.shrink_to_fit();
        if(s.byId.bucket_count()/4>std::max<size_t>(64,s.byId.size())) {
            decltype(s.byId) compact;
            compact.reserve(s.byId.size());
            compact.merge(s.byId);
            s.byId.swap(compact);
        }
    } else if(had_results) release_results(s);
    const bool locate=changed || s.pending!=0;
    s.pending=0;
    if(had_results || !s.targets.empty()) decorate(s);
    if(locate && !s.targets.empty()) reveal(s);
}
void FindController::Decorate() { for(auto& s:searches_) if(!s.targets.empty() && visible(s)) decorate(s); }
void FindController::decorate(Search& s) {
    auto* area=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll)); if(!area) return;
    auto* list=root()->FindById(s.list);
    auto visit=[&](auto&& self,ui::Widget* w,ui::Widget* row) -> void {
        // Clear earlier highlights on hidden editors and tabs once as well.
        if(!w->visible && !s.targets.empty()) return;
        if(w->Parent()==list) row=w;
        auto found=s.byId.find(w->id);
        if(found!=s.byId.end()) {
            // Keep only row-local geometry, never owning virtual widgets. Pure
            // scrolling translates both rectangles equally. A nested scroller
            // occupies one place in the outer document; its own markers locate
            // individual TAGs without projecting their hidden extent outside it.
            auto box=w->rect;
            for(auto* p=w->Parent();p && p!=area;p=p->Parent())
                if(dynamic_cast<ui::ScrollViewWidget*>(p)) box=p->rect;
            const float offset=(box.top+box.bottom)/2-(row?row->rect.top:area->rect.top-area->ScrollY());
            if(std::abs(found->second.offset-offset)>0.5f) {
                found->second.offset=offset;
                s.geometry=~uint64_t(0);
            }
        }
        if(w->textHighlightRevision!=s.revision) {
            w->textHighlightRevision=s.revision;
            if(auto* collection=dynamic_cast<TagCollection*>(w)) {
                std::map<size_t,std::vector<ui::TextHighlight>> tags;
                int active_tag=-1;
                if(found!=s.byId.end()) {
                    const auto& active=s.targets[s.current.target];
                    if(active.widget==&*found) active_tag=active.tag;
                    auto add=[&](size_t index) {
                        const auto& target=s.targets[index];
                        if(target.tag>=0) tags.insert_or_assign(size_t(target.tag),target.ranges);
                    };
                    add(found->second.first);
                    for(size_t index:found->second.remaining) add(index);
                }
                const bool has_tags=!tags.empty();
                collection->SetHighlights(std::move(tags),active_tag);
                if(has_tags) {
                    auto* parent=collection->Parent();
                    while(parent && !dynamic_cast<ui::ScrollViewWidget*>(parent)) parent=parent->Parent();
                    if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(parent)) {
                        std::weak_ptr<TagCollection> weak=std::static_pointer_cast<TagCollection>(collection->shared_from_this());
                        scroll->onDrawSearchMarkers=[weak,scroll](ui::Renderer& r){if(auto item=weak.lock()) item->DrawSearchMarkers(r,*scroll);};
                    }
                }
            } else if(found!=s.byId.end()) {
                const auto& source=found->second;
                w->textHighlights=s.targets[source.remaining.empty()?source.first:source.remaining.back()].ranges;
            }
            else if(w->textHighlights.capacity()) decltype(w->textHighlights)().swap(w->textHighlights);
        }
        for(auto& child:w->Children()) self(self,child.get(),row);
    };
    visit(visit,area,nullptr);
}
void FindController::reveal(Search& s) {
    auto* owner=ui::GetContext().GetWindow(window_);
    if(ui::LayoutDirtyFlag()) owner->LayoutRoot();
    const auto& target=s.targets[s.current.target];
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll));
    auto* list=dynamic_cast<ui::VirtualListWidget*>(root()->FindById(s.list));
    if(scroll && list && target.row>=0 && size_t(target.row)<list->RowCount()) {
        float top=list->rect.top+list->padT+list->RowOffset(size_t(target.row));
        if(top<scroll->rect.top || top>=scroll->rect.bottom)
            owner->ScrollWithMeasureContext(scroll,scroll->ScrollY()+top-scroll->rect.top);
    }
    auto* widget=root()->FindById(target.widget->first);
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
    if(found==searches_.end() || !visible(*found) || found->targets.empty()) return;
    auto& s=*found;
    if(auto* input=root()->FindById(scope+"Search")) ui::GetContext().GetWindow(window_)->FocusWidget(input,false);
    if(scope=="task" && (direction>0?s.after:s.before) && at_edge(s,direction)) {
        s.pending=direction; auto encoded=Json(direction).dump(); ui_page_call_json(page_,"searchTaskPage",encoded.c_str()); return;
    }
    activate(s,s.current,false);
    advance(s,direction);
    activate(s,s.current,true);
    reveal(s);
}
void FindController::activate(Search& s,const Hit& h,bool active) {
    auto& t=s.targets[h.target]; t.ranges[h.range].active=active;
    auto* widget=root()->FindById(t.widget->first);
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
    if(s.targets.empty()) return;
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root()->FindById(s.scroll));
    auto* list=dynamic_cast<ui::VirtualListWidget*>(root()->FindById(s.list));
    if(!scroll || !list) return;
    const auto b=scroll->ScrollbarTrackRect();
    const float extent=std::max(1.0f,scroll->ContentHeight()),height=b.bottom-b.top;
    const float offset=list->rect.top-scroll->rect.top+scroll->ScrollY()+list->padT;
    auto position=[&](const Source& source) {
        const auto row=s.targets[source.first].row;
        return std::clamp((row<0?0.0f:offset+list->RowOffset(size_t(row)))+source.offset,0.0f,extent)/extent*std::max(0.0f,height-3);
    };
    if(s.geometry!=list->GeometryRevision() || s.extent!=extent || std::abs(s.offset-offset)>0.5f || s.height!=height) {
        s.geometry=list->GeometryRevision(); s.extent=extent; s.offset=offset; s.height=height; s.ticks.clear();
        // Pixel deduplication bounds paint cost by track height even when a
        // large virtual list has many more matching widgets than screen pixels.
        std::vector<bool> occupied(size_t(std::ceil(std::max(0.0f,height))),false);
        // All matches in one widget share its outer-document location. A TAG
        // cloud with thousands of hits still contributes only one outer tick.
        for(const auto& source:s.byId) {
            float at=std::floor(position(source.second));
            const auto pixel=size_t(at);
            if(pixel<occupied.size() && !occupied[pixel]) {occupied[pixel]=true;s.ticks.push_back(at);}
        }
    }
    for(float tick:s.ticks) r.FillRoundedRect({b.left,b.top+tick,b.right,b.top+tick+2},1,1,D2D1::ColorF(0xd2ad22));
    float at=b.top+position(s.targets[s.current.target].widget->second);
    r.FillRoundedRect({b.left,at,b.right,at+3},1,1,D2D1::ColorF(0xef8c22));
}
}
