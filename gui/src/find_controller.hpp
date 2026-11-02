#pragma once
#include "model.hpp"
#include <ui_core.h>
#include <ui/controls.h>
#include <array>
#include <unordered_map>

namespace spg {
class FindController {
    struct Target { std::string id; int row=-1, tag=-1; std::vector<ui::TextHighlight> ranges; };
    struct Hit { size_t target, range; };
    struct Search {
        const char *scope, *list, *scroll;
        std::wstring query;
        std::vector<Target> targets;
        std::vector<Hit> hits;
        std::unordered_map<std::string,std::vector<size_t>> byId;
        std::vector<int> rows;
        std::vector<float> ticks;
        size_t current=0;
        uint64_t revision=0, geometry=~uint64_t(0);
        float extent=-1, offset=-1, height=-1;
        int pending=0;
        bool before=false, after=false;
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
    void decorate(Search& search);
    void reveal(Search& search);
    void activate(Search& search,const Hit& hit,bool active);
    void markers(Search& search,ui::Renderer& renderer);
    void Move(const std::string& scope,int direction);
public:
    FindController(UiPage page,UiWindow window);
    ~FindController();
    void Refresh();
    void Decorate();
    bool Key(int vk);
};
}
