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
    struct Source {
        size_t first;
        std::vector<size_t> remaining;
        float offset=0;
        explicit Source(size_t index):first(index) {}
    };
    using Sources=std::unordered_map<std::string,Source>;
    struct Target {
        // A map node owns the widget ID for all its targets and survives rehashing.
        const Sources::value_type* widget;
        int row, tag;
        std::vector<ui::TextHighlight> ranges;
    };
    struct Hit { size_t target=0, range=0; };
    struct Selection { std::string id; int tag=-1; uint32_t start=0; };
    struct Match { std::string text; std::vector<ui::TextHighlight> ranges; size_t bytes; };
    struct Search {
        const char *scope, *list, *scroll;
        std::wstring query;
        std::vector<Target> targets;
        Sources byId;
        std::vector<float> ticks;
        Hit current;
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
        std::weak_ptr<ui::VirtualListWidget> hooked_list;
        std::function<void()> previous_on_range_changed;
    };
    UiPage page_;
    UiWindow window_;
    uint64_t revision_=0;
    std::array<Search,5> searches_{{{"directory","directoryItems","directoryListScroll"},{"task","taskItems","taskListScroll"},{"config","configItems","configListScroll"},{"root","rootItems","rootListScroll"},{"password","passwordItems","passwordListScroll"}}};
    ui::Widget* root() const;
    bool visible(const Search& search) const;
    void refresh(Search& search);
    static Selection selection(const Search& search);
    static bool at_edge(const Search& search,int direction);
    static void advance(Search& search,int direction);
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
    FindController(const FindController&)=delete;
    FindController& operator=(const FindController&)=delete;
    ~FindController();
    void Refresh(const char* scope=nullptr);
    void Decorate();
    bool Key(int vk);
};
}
