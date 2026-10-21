#pragma once
#include "range_editor.hpp"
#include <ui_core.h>

namespace spg {
// UI-thread owned. Completion is posted to the owner so no callback destroys
// its own Core UI tree. A generation distinguishes messages from retired popups.
class DatePopup {
    UiPage page_ = 0;
    UiWindow window_ = 0;
    HWND hwnd_ = nullptr, owner_ = nullptr;
    UINT message_;
    UINT_PTR generation_;
    RECT anchor_;
    SYSTEMTIME date_{};
    DYNAMIC_TIME_ZONE_INFORMATION zone_{};
    std::string language_;
    bool cancelled_ = false, confirming_ = false, positioning_ = false;
    bool closing_ = false, closed_ = false;
    void render();
    void focus_day();
    void move_days(int days);
    void move_months(int months);
    void dispatch();
    void notify(bool cancel);
    void position();
    static LRESULT CALLBACK subclass(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
public:
    const std::string field, side;
    DatePopup(UiWindow owner, UINT message, UINT_PTR generation, RECT anchor,
              std::string field, std::string side, const std::string& initial,
              const std::string& language, const std::string& appearance);
    ~DatePopup();
    DatePopup(const DatePopup&) = delete;
    DatePopup& operator=(const DatePopup&) = delete;
    void show();
    void close();
    bool closed() const { return closed_; }
    bool cancelled() const { return cancelled_; }
    bool confirming() const { return confirming_; }
    std::string value() const;
    const DYNAMIC_TIME_ZONE_INFORMATION* zone() const { return &zone_; }
    void error(const std::string& key);
};
}
