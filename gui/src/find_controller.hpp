#pragma once
#include "model.hpp"
#include <ui_core.h>
#include <ui/controls.h>
#include <array>
#include <list>
#include <string_view>
#include <unordered_map>

namespace spg {
class FindController {
    struct Target { std::string id; int row=-1, tag=-1; std::vector<ui::TextHighlight> ranges; };
    struct Source { std::vector<size_t> targets; float offset=0; };
    struct Hit { size_t target, range; };
    struct Selection { std::string id; int tag=-1; uint32_t start=0; };
    struct Match { std::string text; std::vector<ui::TextHighlight> ranges; size_t bytes; };
    struct Search {
        const char *scope, *list, *scroll;
        std::wstring query;
        std::vector<Target> targets;
        std::vector<Hit> hits;
        std::unordered_map<std::string,Source> byId;
        std::vector<float> ticks;
        size_t current=0;
        Selection saved;
        uint64_t revision=0, geometry=~uint64_t(0);
        float extent=-1, offset=-1, height=-1;
        int pending=0;
        bool before=false, after=false;
        // Bounded, query-local LRU. Keys view list-owned text; cached ranges
        // never own the active-hit state or reactive rows/widgets.
        std::list<Match> matches;
        std::unordered_map<std::string_view,std::list<Match>::iterator> matchIndex;
        size_t matchBytes=0;
    };
    UiPage page_;
    UiWindow window_;
    uint64_t revision_=0;
    std::array<Search,5> searches_{{{"directory","directoryItems","directoryListScroll"},{"task","taskItems","taskListScroll"},{"config","configItems","configListScroll"},{"root","rootItems","rootListScroll"},{"password","passwordItems","passwordListScroll"}}};
    struct Hook { std::weak_ptr<ui::VirtualListWidget> list; std::function<void()> previous; };
    std::vector<Hook> hooks_;
    ui::Widget* root() const;
    bool visible(const Search& search) const;
    void refresh(Search& search);
    static Selection selection(const Search& search);
    static void release_results(Search& search);
    void clear_matches(Search& search);
    std::vector<ui::TextHighlight> match(Search& search,const std::string& text);
    void decorate(Search& search);
    void reveal(Search& search);
    void activate(Search& search,const Hit& hit,bool active);
    void markers(Search& search,ui::Renderer& renderer);
    void Move(const std::string& scope,int direction);
public:
    FindController(UiPage page,UiWindow window);
    ~FindController();
    void Refresh(const char* scope=nullptr);
    void Decorate();
    bool Key(int vk);
};
}
