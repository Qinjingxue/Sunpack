#include "date_popup.hpp"
#include "presentation.hpp"
#include "motion.hpp"
#include "date_popup_uix.h"
#include <commctrl.h>
#include <dwmapi.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <algorithm>

namespace spg {
namespace {
constexpr UINT DispatchDate = WM_APP + 0x404;
Json state(UiPage page, const char* key) {
    char* text=ui_page_get_json(page,key);
    if(!text) throw std::runtime_error("uiBindingFailed");
    std::string value(text); ui_page_free(text); return parse_json(value);
}
void set(UiPage page,const char* key,const Json& value) {
    auto text=value.dump();
    if(ui_page_set_json(page,key,text.c_str())!=0) throw std::runtime_error("uiBindingFailed");
}
int64_t first_day(SYSTEMTIME date) {
    date.wDay=1; date.wHour=date.wMinute=date.wSecond=date.wMilliseconds=0;
    return range_calendar_seconds(date)/86400;
}
int weekday(int64_t day) { return int((day+3)%7+7)%7; } // Monday first, including pre-1970.
}
DatePopup::DatePopup(UiWindow owner,UINT message,UINT_PTR generation,RECT anchor,
                     std::string id,std::string bound,const std::string& initial,
                     const std::string& language,const std::string& appearance)
    : owner_(static_cast<HWND>(ui_window_hwnd(owner))), message_(message), generation_(generation),
      anchor_(anchor), language_(language), field(std::move(id)), side(std::move(bound)) {
    try {
        if(GetDynamicTimeZoneInformation(&zone_)==TIME_ZONE_ID_INVALID) win_error("opRangeDate");
        if(!range_datetime(initial,date_)) GetLocalTime(&date_);
        date_.wSecond=date_.wMilliseconds=0;
        page_=ui_page_load_string(kDatePopupUix);
        if(!page_) throw std::runtime_error("layoutLoadFailed");
        set(page_,"appearance",appearance); set(page_,"texts",interface_texts(language));
        set(page_,"weekdays",language=="zh"?Json::array({"一","二","三","四","五","六","日"}):Json::array({"Mo","Tu","We","Th","Fr","Sa","Su"}));
        set(page_,"time",range_datetime_text(date_).substr(11));
        render();
        UiWindowConfig config{}; config.owner=owner; config.tool_window=1; config.skip_animation=1;
        MONITORINFO monitor{sizeof(monitor)};
        if(!GetMonitorInfoW(MonitorFromRect(&anchor_,MONITOR_DEFAULTTONEAREST),&monitor)) win_error("opRangeDate");
        // Start on the anchor's monitor even if the field straddles two screens.
        config.x=std::clamp<LONG>(anchor.left,monitor.rcWork.left,monitor.rcWork.right-1);
        config.y=std::clamp<LONG>(anchor.top,monitor.rcWork.top,monitor.rcWork.bottom-1);
        window_=ui_page_prepare_window(page_,&config);
        if(!window_) throw std::runtime_error("opRangeDate");
        hwnd_=static_cast<HWND>(ui_window_hwnd(window_));
        ui_window_set_title(window_,wide(tr("rangeChoose",language)).c_str());
        if(!SetWindowSubclass(hwnd_,subclass,1,reinterpret_cast<DWORD_PTR>(this))) win_error("opWindowEvents");
        auto corners=DWMWCP_ROUND;
        DwmSetWindowAttribute(hwnd_,DWMWA_WINDOW_CORNER_PREFERENCE,&corners,sizeof(corners));
        ui_page_on_widget_mount(page_,"dateDispatch",[](UiPage,UiWidget,void* data) {
            PostMessageW(static_cast<DatePopup*>(data)->hwnd_,DispatchDate,0,0);
        },this);
        ui_page_on_widget_unmount(page_,"dateDispatch",[](UiPage,UiWidget widget,void*) { ui_widget_destroy(widget); },nullptr);
        position();
    } catch(...) {
        if(hwnd_) RemoveWindowSubclass(hwnd_,subclass,1);
        if(window_) ui_window_destroy(window_);
        if(page_) ui_page_destroy(page_);
        throw;
    }
}
DatePopup::~DatePopup() {
    if(hwnd_ && IsWindow(hwnd_)) { RemoveWindowSubclass(hwnd_,subclass,1); ui_window_destroy(window_); }
    if(page_) ui_page_destroy(page_);
}
void DatePopup::show() {
    motion::popup(window_,true);
    ui_window_show_immediate(window_);
    // Core UI deliberately shows tool windows without activation. This popup
    // accepts keyboard input, so activate it explicitly within the owner thread.
    SetActiveWindow(hwnd_); SetFocus(hwnd_); focus_day();
}
void DatePopup::close() {
    if(closing_) return;
    closing_=true;
    confirming_=false; // Ignore duplicate queued confirmations during exit.
    // Cancellation has no value to validate; a successful confirmation has
    // already been handed to the owner's existing atomic save path.
    motion::popup(window_,false,[this] {
        closed_=true;
        PostMessageW(owner_,message_,generation_,0);
    });
}
void DatePopup::position() {
    if(positioning_) return;
    positioning_=true;
    MONITORINFO monitor{sizeof(monitor)};
    if(!GetMonitorInfoW(MonitorFromRect(&anchor_,MONITOR_DEFAULTTONEAREST),&monitor)) { positioning_=false; win_error("opRangeDate"); }
    auto work=monitor.rcWork;
    int dpi=ui_window_dpi(window_),gap=MulDiv(6,dpi,96);
    int width=std::min(352,int(int64_t(work.right-work.left)*96/dpi));
    int height=std::min(504,int(int64_t(work.bottom-work.top)*96/dpi));
    int w=MulDiv(width,dpi,96),h=MulDiv(height,dpi,96);
    int x=std::clamp<int>(anchor_.left,work.left,std::max(work.left,work.right-w));
    int y=anchor_.bottom+gap;
    if(y+h>work.bottom) y=anchor_.top-gap-h;
    y=std::clamp<int>(y,work.top,std::max(work.top,work.bottom-h));
    set(page_,"cellWidth",std::max(1.0,(width-64.0)/7)); // Seven columns at every DPI/work-area width.
    ui_window_set_rect(window_,x,y,width,height);
    positioning_=false;
    if(ui_window_dpi(window_)!=dpi) position(); // SetWindowPos may cross a DPI boundary synchronously.
}
void DatePopup::render() {
    auto text=range_datetime_text(date_);
    set(page_,"month",text.substr(0,7)); set(page_,"selected",text.substr(0,10));
    set(page_,"previous",date_.wYear>1 || date_.wMonth>1);
    set(page_,"next",date_.wYear<9999 || date_.wMonth<12);
    auto first=first_day(date_),start=first-weekday(first);
    SYSTEMTIME today{}; GetLocalTime(&today);
    auto todayText=range_datetime_text(today).substr(0,10);
    Json days=Json::array();
    for(int index=0;index<42;++index) {
        Json day={{"index",index},{"text",""},{"valid",false},{"other",false},{"today",false},{"selected",false}};
        try {
            auto value=range_calendar_time((start+index)*86400);
            auto key=range_datetime_text(value).substr(0,10);
            day.update({{"text",std::to_string(value.wDay)},{"valid",true},{"other",value.wMonth!=date_.wMonth},
                        {"today",key==todayText},{"selected",key==text.substr(0,10)}});
        } catch(const std::runtime_error&) {} // Empty cells outside years 1..9999.
        days.push_back(std::move(day));
    }
    set(page_,"days",days); set(page_,"error","");
}
void DatePopup::focus_day() {
    ui_window_relayout(window_);
    auto root=ui_page_root(page_);
    auto id="date-day-"+std::to_string(weekday(first_day(date_))+date_.wDay-1);
    auto widget=ui_widget_find_by_id(root,id.c_str());
    if(widget) { ui_window_focus_widget(window_,widget); ui_widget_destroy(widget); }
    ui_widget_destroy(root);
}
void DatePopup::move_days(int days) {
    try { date_=range_calendar_time(range_calendar_seconds(date_)+int64_t(days)*86400); }
    catch(const std::runtime_error&) { return; }
    render(); focus_day();
}
void DatePopup::move_months(int months) {
    int month=int(date_.wYear-1)*12+date_.wMonth-1+months;
    if(month<0 || month>=9999*12) return;
    auto value=date_; value.wYear=WORD(month/12+1); value.wMonth=WORD(month%12+1);
    // Clamp the selected day for short months, using the shared calendar math.
    while(!range_datetime(range_datetime_text(value),value)) --value.wDay;
    date_=value; render(); focus_day();
}
void DatePopup::notify(bool cancel) {
    if(cancelled_ || closing_) return;
    cancelled_=cancel; confirming_=!cancel;
    if(cancel) close();
    else PostMessageW(owner_,message_,generation_,0);
}
void DatePopup::dispatch() {
    auto requests=state(page_,"requests"); set(page_,"requests",Json::array()); ui_page_set_bool(page_,"dispatch",false);
    if(cancelled_ || closing_) return;
    for(auto& request:requests) {
        auto op=request.at("op").get<std::string>();
        if(op=="cancel") { notify(true); return; }
        if(op=="confirm") { notify(false); return; }
        if(op=="month") move_months(request.at("value").get<int>());
        if(op=="day") {
            int index=request.at("value").get<int>();
            if(index<0 || index>=42) continue;
            auto day=range_calendar_time((first_day(date_)-weekday(first_day(date_))+index)*86400);
            date_=day; render(); focus_day();
        }
        if(op=="today") { GetLocalTime(&date_); render(); focus_day(); }
    }
}
std::string DatePopup::value() const {
    auto text=range_datetime_text(date_).substr(0,10)+" "+state(page_,"time").get<std::string>();
    SYSTEMTIME parsed{};
    if(!range_datetime(text,parsed)) throw std::runtime_error("rangeDate");
    return text;
}
void DatePopup::error(const std::string& key) { confirming_=false; set(page_,"error",tr(key,language_)); }
LRESULT CALLBACK DatePopup::subclass(HWND hwnd,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR data) {
    auto* self=reinterpret_cast<DatePopup*>(data);
    try {
        if(self->closing_ && (message==WM_KEYDOWN || message==WM_CHAR || message==WM_LBUTTONDOWN || message==WM_LBUTTONUP || message==WM_MOUSEWHEEL)) return 0;
        if(message==DispatchDate) { self->dispatch(); return 0; }
        if(message==WM_CLOSE || (message==WM_ACTIVATE && LOWORD(wp)==WA_INACTIVE)) { self->notify(true); return 0; }
        if(message==WM_KEYDOWN) {
            if(wp==VK_ESCAPE) { self->notify(true); return 0; }
            auto* window=ui::GetContext().GetWindow(self->window_);
            auto* focused=window->FocusedWidget();
            // The calendar is a single Tab stop. Arrow keys move a day/week;
            // PageUp/Down moves a month (Ctrl: year). Inputs retain caret keys.
            bool day=focused && focused->id.rfind("date-day-",0)==0;
            if(wp==VK_TAB) {
                std::vector<std::string> ids={"datePrevious","dateNext","date-day-"+std::to_string(weekday(first_day(self->date_))+self->date_.wDay-1),"dateTime","dateToday","dateCancel","dateConfirm"};
                auto it=std::find(ids.begin(),ids.end(),focused?focused->id:"");
                int at=it==ids.end()?-1:int(it-ids.begin()),step=(GetKeyState(VK_SHIFT)&0x8000)?-1:1;
                for(size_t i=0;i<ids.size();++i) {
                    at=(at+step+int(ids.size()))%int(ids.size());
                    auto* target=window->Root()->FindById(ids[at]);
                    if(target && target->enabled) { window->FocusWidget(target,true); break; }
                }
                return 0;
            }
            if(day) {
                if(wp==VK_LEFT || wp==VK_RIGHT || wp==VK_UP || wp==VK_DOWN) {
                    self->move_days(wp==VK_LEFT?-1:wp==VK_RIGHT?1:wp==VK_UP?-7:7); return 0;
                }
                if(wp==VK_PRIOR || wp==VK_NEXT) { self->move_months((wp==VK_PRIOR?-1:1)*((GetKeyState(VK_CONTROL)&0x8000)?12:1)); return 0; }
                if(wp==VK_RETURN) { self->notify(false); return 0; }
            }
        }
        if(message==WM_DPICHANGED) {
            auto result=DefSubclassProc(hwnd,message,wp,lp); self->position(); return result;
        }
    } catch(const std::exception& e) { self->error(e.what()); return 0; }
    return DefSubclassProc(hwnd,message,wp,lp);
}
}
