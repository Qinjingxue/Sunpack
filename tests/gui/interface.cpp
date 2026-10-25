#include "event_publication.hpp"
#include "application.hpp"
#include "presentation.hpp"
#include "range_editor.hpp"
#include "motion.hpp"
#include "ui_defaults_json.h"
#include <cassert>
#include <iostream>
#include <dwmapi.h>
#include <cstring>
#include <commctrl.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/uix/script_runtime.h>
#include <ui/controls.h>
#include <ui/ui_debug.h>
using namespace spg;
void rendering_contracts();
namespace {
constexpr int virtualTaskCount=96, virtualPasswordCount=80, virtualHistoryCount=96;
struct AnimationFrames {
    bool finished=false, layout=false, started=false, stopped=false;
    unsigned frames=0, submitted=0, rootLayouts=0;
    std::vector<double> intervals;
    AnimationFrames() {
        ui_trace_set_sink([](const UiTraceEvent* event,void* data){
            auto& self=*static_cast<AnimationFrames*>(data);
            if(!std::strcmp(event->name,"motion_started")) self.started=true;
            if(!std::strcmp(event->name,"motion_stopped")) self.stopped=true;
            if(!std::strcmp(event->name,"frame_job_submitted")) ++self.submitted;
            if(!std::strcmp(event->name,"layout_root_duration")) ++self.rootLayouts;
            if(std::strcmp(event->name,"animation_frame")) return;
            ++self.frames;
            for(uint32_t i=0;i<event->field_count;++i) {
                const auto& f=event->fields[i];
                if(!std::strcmp(f.key,"remaining_count") && f.i64==0) self.finished=true;
                if(!std::strcmp(f.key,"needs_layout") && (f.boolean || f.i64)) self.layout=true;
                if(!std::strcmp(f.key,"frame_interval_ms") && f.f64>0) self.intervals.push_back(f.f64);
            }
        },this);
    }
    ~AnimationFrames() {
        ui_trace_set_sink(nullptr,nullptr);
        if(GetEnvironmentVariableW(L"SUNPACK_GUI_MOTION_DIAGNOSTICS",nullptr,0)) {
            std::sort(intervals.begin(),intervals.end());
            if(!intervals.empty()) std::cerr<<"Motion: frames="<<frames<<"; interval median="<<intervals[intervals.size()/2]<<"ms; max="<<intervals.back()<<"ms; layout="<<layout<<"; stopped="<<stopped<<'\n';
        }
    }
};
Json state(UiPage page,const char* key) { char* text=ui_page_get_json(page,key); if(!text) throw std::runtime_error(std::string("UI state unavailable: ")+key); auto j=parse_json(text); ui_page_free(text); return j; }
UiRect rect(Application& app,const std::string& id) {
    auto* widget=ui::GetContext().GetWindow(app.window())->Root()->FindById(id);
    if(!widget) throw std::runtime_error("Widget missing: "+id);
    const auto& r=widget->rect; return {r.left,r.top,r.right,r.bottom};
}
Json rendered_widget(Application& app,const std::string& id) {
    auto* window=ui::GetContext().GetWindow(app.window());
    auto* widget=window->Root()->FindById(id);
    if(!widget) throw std::runtime_error("Missing rendered widget: "+id+"; configQuery="+state(app.page(),"configQuery").dump());
    return parse_json(ui::DebugDumpTree(widget,&window->GetRenderer()));
}
void pump(const std::function<bool()>& condition, const char* phase="UI event", bool allow_timers=true) {
    auto deadline=GetTickCount64()+10000;
    for(;;) {
        MSG message;
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) { if(message.message==WM_QUIT || (!allow_timers && message.message==WM_TIMER)) continue; TranslateMessage(&message); DispatchMessageW(&message); }
        try { if(condition()) return; }
        catch(const WinError& error) {
            // Test-side reads can overlap ReplaceFile's rename/share window.
            // Wait for the actual queued UI/file event, with the same deadline.
            if(error.code!=ERROR_FILE_NOT_FOUND && error.code!=ERROR_PATH_NOT_FOUND && error.code!=ERROR_SHARING_VIOLATION) throw;
        }
        DWORD left=DWORD(deadline>GetTickCount64()?deadline-GetTickCount64():0);
        if(!left) throw std::runtime_error(std::string(phase)+" timed out");
        MsgWaitForMultipleObjectsEx(0,nullptr,left,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    }
}
// Print a state snapshot only if a UI wait fails; successful waits retain the
// original message pump, timeout and scheduling behavior.
void pump_diagnostic(Application& app,const std::function<bool()>& condition,const char* phase) {
    try { pump(condition,phase); }
    catch(...) {
        std::cerr<<"UI wait diagnostic ["<<phase<<"]";
        for(const char* key:{"tab","taskQuery","taskRoot","taskStatus","requests","dispatch",
                             "errors","logPath","actionError","busy","lastCommand",
                             "saving","pendingFields","saveErrors","drafts","tagInputs"}) {
            try { std::cerr<<" "<<key<<"="<<state(app.page(),key).dump(); }
            catch(const std::exception& e) { std::cerr<<" "<<key<<"=<unavailable: "<<e.what()<<">"; }
        }
        try {
            auto tasks=state(app.page(),"tasks");
            std::cerr<<" tasks.total="<<tasks.value("total",-1)
                     <<" tasks.malformed="<<tasks.value("malformed",0);
        } catch(const std::exception& e) { std::cerr<<" tasks=<unavailable: "<<e.what()<<">"; }
        std::cerr<<'\n';
        throw;
    }
}
// Wait on the switch that was changed, rather than on all window animations
// (a different view may still be animating). Reduced-motion environments are
// allowed to change the value immediately with no animation trace at all.
void await_toggle_motion(Application& app,const char* id,bool animations,
                         const AnimationFrames& trace,const char* phase,
                         bool requireMultipleFrames=false) {
    auto* window=ui::GetContext().GetWindow(app.window());
    auto current=[&] { return dynamic_cast<ui::ToggleWidget*>(window->Root()->FindById(id)); };
    auto diagnostics=[&] {
        auto* toggle=current();
        std::cerr<<"Toggle diagnostic ["<<phase<<"] id="<<id
                 <<" clientAnimations="<<animations
                 <<" found="<<(toggle!=nullptr)
                 <<" on="<<(toggle?int(toggle->On()):-1)
                 <<" animating="<<(toggle?int(toggle->Animating()):-1)
                 <<" trace.started="<<trace.started
                 <<" trace.finished="<<trace.finished
                 <<" trace.stopped="<<trace.stopped
                 <<" trace.frames="<<trace.frames
                 <<" trace.layout="<<trace.layout;
        try {
            std::cerr<<" drafts="<<state(app.page(),"toggleDrafts").dump()
                     <<" pending="<<state(app.page(),"pendingFields").dump()
                     <<" saving="<<state(app.page(),"saving").dump()
                     <<" errors="<<state(app.page(),"saveErrors").dump();
        } catch(const std::exception& e) { std::cerr<<" diagnosticError="<<e.what(); }
        std::cerr<<'\n';
    };
    try {
        pump([&]{auto* toggle=current(); return toggle && (!animations || !toggle->Animating());},phase);
        // A 167 ms switch slide should take more than one frame; 83 ms hover
        // feedback can complete in a single frame on a loaded CI runner.
        if(animations && (trace.layout || (requireMultipleFrames && trace.frames<2)))
            throw std::runtime_error(std::string(phase)+": unexpected paint-frame trace");
    } catch(...) {
        diagnostics();
        throw;
    }
}
void settle_motion(Application& app) {
    Json pending;
    try { pump([&] {
        pending=Json::array();
        auto root=ui::GetContext().GetWindow(app.window())->Root();
        std::function<bool(ui::Widget*)> settled=[&](ui::Widget* widget) {
            if(!widget->visible) return true;
            if(auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(widget); scroll && scroll->ScrollAnimating()) return false;
            // A visual epsilon can return before the finite clock ends. The
            // next update deliberately joins that clock instead of restarting.
            if(widget->opacity!=1 || widget->animationX!=0) { pending.push_back({widget->id,widget->opacity,widget->animationX}); return false; }
            if(widget->id=="navIndicator") {
                auto tab=state(app.page(),"tab").get<std::string>();
                auto* target=root->FindById(tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":tab=="roots"?"tabRoots":"tabPasswords");
                if(std::abs(widget->rect.top+widget->animationY+(widget->rect.bottom-widget->rect.top)/2-(target->rect.top+target->rect.bottom)/2)>0.01f) { pending.push_back({widget->id,widget->rect.top,widget->animationY,target->rect.top,target->rect.bottom}); return false; }
            } else if(widget->animationY!=0) { pending.push_back({widget->id,widget->animationY}); return false; }
            for(auto& child:widget->Children()) if(!settled(child.get())) return false;
            return true;
        };
        return settled(root.get());
    }); } catch(...) { std::cerr<<"Unfinished motion: "<<pending<<'\n'; throw; }
}
void click(Application& app,const char* id) {
    // Conditional editor views mount during the UI event turn. Drain the
    // preceding input's events before locating the next click target.
    ui_debug_pump();
    ui_window_relayout(app.window());
    // Scroll the containing pane as a person would before clicking an action
    // in a long inline form. Never click through a clipped viewport.
    auto* window=ui::GetContext().GetWindow(app.window());
    auto* target=window->Root()->FindById(id); assert(target);
    std::vector<std::string> ancestors;
    for(auto* parent=target->Parent();parent;parent=parent->Parent())
        if(dynamic_cast<ui::ScrollViewWidget*>(parent)) ancestors.push_back(parent->id);
    for(auto& pane:ancestors) {
        auto bounds=rect(app,id);
        auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(window->Root()->FindById(pane)); assert(scroll);
        auto viewport=scroll->rect;
        float top=viewport.top, bottom=viewport.bottom, center=(bounds.top+bounds.bottom)/2;
        if(center<top+4 || center>bottom-4) {
            window->ScrollWithMeasureContext(scroll,scroll->ScrollY()+center-(top+bottom)/2);
            ui_window_relayout(app.window());
        }
    }
    // FindById can return Application's owned selector handle. Create our own
    // temporary handle so the click helper never invalidates that ownership.
    target=window->Root()->FindById(id); assert(target);
    auto widget=ui::GetContext().handles.Insert(target->shared_from_this());
    if(ui_debug_widget_is_visible(widget)!=1) {
        char* info=ui_debug_dump_widget(widget); std::cerr<<id<<": "<<(info?info:"")<<"\n"; ui_debug_free(info);
    }
    assert(ui_debug_widget_is_visible(widget)==1);
    auto clicked=ui_debug_click(app.window(),widget);
    if(clicked!=0) {
        std::cerr<<"Click failed: "<<id<<" "<<rendered_widget(app,id)<<'\n';
        for(auto key:{"taskRoot","rootCell","rootPart","rootDrafts","saveErrors"}) std::cerr<<key<<"="<<state(app.page(),key)<<'\n';
    }
    assert(clicked==0);
    ui_widget_destroy(widget);
}
void search_config(Application& app,const wchar_t* query) {
    // Use the real search input: its handler also resets the virtual viewport.
    // Setting configQuery directly skips that command and assumes rows outside
    // the old viewport already have widgets before the next layout.
    click(app,"configSearch");
    assert(ui_debug_key_mod(app.window(),'A',1,0,0)==0);
    assert(ui_debug_type_char(app.window(),8)==0);
    if(*query) assert(ui_debug_type_text(app.window(),query)==0);
    pump([&]{return state(app.page(),"configQuery")==utf8(query) &&
        state(app.page(),"requests").empty() && !state(app.page(),"dispatch").get<bool>();},"Configuration search");
    ui_window_relayout(app.window());
}
// Existing edit scenarios locate controls through their translated labels.
void search_setting(Application& app,const std::string& id) {
    for(auto& field:state(app.page(),"fields")) if(field["id"]==id || field["module"]==id) {
        auto label=wide(field["label"].get<std::string>());
        search_config(app,label.c_str()); return;
    }
    throw std::runtime_error("Setting not found: "+id);
}
void edit_password(Application& app,const std::string& id,const wchar_t* value) {
    click(app,("password-text-"+id).c_str());
    pump([&]{auto* f=ui::GetContext().GetWindow(app.window())->FocusedWidget(); return f&&f->id=="password-input-"+id;},"Password cell focus");
    assert(ui_debug_key_mod(app.window(),'A',1,0,0)==0);
    assert(ui_debug_type_char(app.window(),8)==0);
    assert(ui_debug_type_text(app.window(),value)==0);
}
std::string root_row_id(Application& app,const fs::path& path) {
    for(auto& r:state(app.page(),"rootRows")) if(path_key(wide(r["input"].get<std::string>()))==path_key(path)) return r["id"].get<std::string>();
    throw std::runtime_error("Root row missing: "+utf8(path.wstring()));
}
void edit_root_cell(Application& app,const std::string& id,const char* part,const wchar_t* value) {
    click(app,("root-"+std::string(part)+"-text-"+id).c_str());
    auto input="root-"+std::string(part)+"-input-"+id;
    try { pump([&]{auto* focused=ui::GetContext().GetWindow(app.window())->FocusedWidget();return focused&&focused->id==input;},"Root cell focus"); }
    catch(...) {
        auto* focused=ui::GetContext().GetWindow(app.window())->FocusedWidget();
        std::cerr<<"Root focus diagnostic: expected="<<input<<" focused="<<(focused?focused->id:"<none>")<<'\n';
        for(auto key:{"rootCell","rootPart","rootDrafts","requests","dispatch","saving","saveErrors"})
            std::cerr<<key<<"="<<state(app.page(),key)<<'\n';
        throw;
    }
    assert(ui_debug_key_mod(app.window(),'A',1,0,0)==0);
    assert(ui_debug_type_char(app.window(),8)==0);
    if(*value) assert(ui_debug_type_text(app.window(),value)==0);
}
void paste_password(Application& app,const wchar_t* value) {
    // Exercise the actual Ctrl+V path, including its single multi-line input
    // event. Restore the user's clipboard formats after the synchronous paste.
    auto owner=ui::GetContext().GetWindow(app.window())->Handle();
    // Clipboard listeners can briefly own this system-wide resource. Use the
    // existing event wait, without a retry timer or fixed sleep.
    pump([&]{return OpenClipboard(owner)!=FALSE;},"Clipboard ownership");
    // Eager copies are essential: OleGetClipboard's wrapper refers to the live
    // clipboard and cannot restore its old contents after EmptyClipboard.
    std::vector<std::pair<UINT,HANDLE>> previous;
    for(UINT format=0;(format=EnumClipboardFormats(format))!=0;) {
        if(auto original=GetClipboardData(format))
            if(auto copy=OleDuplicateData(original,format,0)) previous.emplace_back(format,copy);
    }
    EmptyClipboard();
    size_t bytes=(wcslen(value)+1)*sizeof(wchar_t);
    auto memory=GlobalAlloc(GMEM_MOVEABLE,bytes); assert(memory);
    auto data=GlobalLock(memory); assert(data); memcpy(data,value,bytes); GlobalUnlock(memory);
    assert(SetClipboardData(CF_UNICODETEXT,memory)); CloseClipboard();
    assert(ui_debug_key_mod(app.window(),'V',1,0,0)==0);
    pump([&]{return OpenClipboard(owner)!=FALSE;},"Clipboard restoration"); EmptyClipboard();
    for(auto [format,copy]:previous) assert(SetClipboardData(format,copy));
    CloseClipboard();
}
void search_hints(Application& app) {
    auto* root=ui::GetContext().GetWindow(app.window())->Root().get();
    for(auto pair:{std::pair<const char*,const char*>{"directorySearch","searchDirectory"},
                   {"taskSearch","taskSearch"},{"configSearch","settingSearch"},{"passwordSearch","passwordSearch"}}) {
        auto* input=dynamic_cast<ui::TextInputWidget*>(root->FindById(pair.first));
        assert(input && input->Placeholder()==wide(state(app.page(),"texts")[pair.second].get<std::string>()));
    }
}
void button_texts(Application& app,bool relayout=true) {
    if(relayout) ui_window_relayout(app.window());
    auto* window=ui::GetContext().GetWindow(app.window());
    std::function<void(ui::Widget*)> check=[&](ui::Widget* widget) {
        if(!widget->visible) return;
        if(auto* button=dynamic_cast<ui::ButtonWidget*>(widget);button && !button->Text().empty()) {
            auto font=button->css.fontSize>0?button->css.fontSize:theme::kFontSizeNormal;
            if(window->GetRenderer().MeasureTextWidth(button->Text(),font)>button->rect.right-button->rect.left-24+0.5f)
                throw std::runtime_error("Truncated action: "+ui::DebugDumpTree(button,&window->GetRenderer()));
        }
        for(auto& child:widget->Children()) check(child.get());
    };
    check(window->Root().get());
}
void finish_input(Application& app) {
    ui_window_focus_widget(app.window(),0);
    ui_debug_pump();
    pump([&]{return state(app.page(),"requests").empty() && state(app.page(),"dispatch")==false && state(app.page(),"saving")==false && state(app.page(),"pendingFields").empty();},"Automatic writes");
    auto errors=state(app.page(),"saveErrors");
    if(!errors.empty()) throw std::runtime_error(errors.dump());
}
void screenshot(Application& app,const wchar_t* name) {
    wchar_t path[32768];
    auto n=GetEnvironmentVariableW(L"SUNPACK_GUI_SCREENSHOTS",path,32768);
    if(!n || n>=32768) return;
    fs::create_directories(path); settle_motion(app); ui_debug_pump(); ui_window_relayout(app.window());
    char* tree=ui_debug_dump_tree(app.window());
    if(tree) { atomic_write(fs::path(path)/(std::wstring(name)+L".json"),tree); ui_debug_free(tree); }
    assert(ui_debug_screenshot(app.window(),(fs::path(path)/name).c_str())==0);
}
void popup_motion(Application& app,const char* id,bool upward=false) {
    settle_motion(app);
    auto* combo=dynamic_cast<ui::ComboBoxWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById(id));
    assert(combo);
    BOOL animations=TRUE; SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0);
    AnimationFrames animation;
    auto open=[&] {
        if(!upward) { click(app,id); return; }
        // Open a partially visible control at the lower scroll edge without
        // the click helper first scrolling its center into the viewport.
        float x=(combo->rect.left+combo->rect.right)/2,y=combo->rect.top+4;
        assert(ui_debug_mouse_down(app.window(),x,y)==0);
        assert(ui_debug_mouse_up(app.window(),x,y)==0);
    };
    open();
    assert(combo->IsOpen());
    // Input helpers synchronously present. ASan (or a busy desktop) can finish
    // the finite animation before they return; assert its lifecycle rather
    // than requiring an intermediate value at that arbitrary instant.
    if(animations) assert(animation.started &&
        (combo->PopupAnimating() || (animation.stopped && combo->PopupOpacity()==1 && combo->PopupProgress()==1)));
    // Motion must advance from presented frames, without depending on a
    // low-frequency WM_TIMER. Completion-only checks with timers miss that.
    pump([&]{return !combo->PopupAnimating() && (!animations || animation.stopped);},"Render-paced popup entrance",false);
    auto bounds=combo->rect, drop=combo->DropdownRect();
    if(combo->PopupOpacity()!=1 || combo->PopupProgress()!=1) {
        std::cerr<<"Popup entrance endpoint: id="<<id<<" open="<<combo->IsOpen()<<" opacity="<<combo->PopupOpacity()<<" progress="<<combo->PopupProgress()<<'\n';
        throw std::runtime_error("Popup entrance endpoint missing");
    }
    if(upward && drop.bottom>bounds.top) {
        std::cerr<<"Popup geometry: "<<rendered_widget(app,id)<<"; scroll="<<rendered_widget(app,"configListScroll").at("rect")
                 <<"; viewport="<<ui::Viewport().top<<","<<ui::Viewport().bottom<<"; popup="<<drop.top<<","<<drop.bottom<<'\n';
        throw std::runtime_error("Expected popup to open upward");
    }
    if(animations) assert(animation.frames>0 && !animation.layout);
    const int visibleRows=static_cast<int>((drop.bottom-drop.top)/combo->ItemHeight());
    const float padding=((drop.bottom-drop.top)-visibleRows*combo->ItemHeight())/2;
    float hoverX=(drop.left+drop.right)/2;
    assert(ui_debug_mouse_move(app.window(),hoverX,drop.top+padding+combo->ItemHeight()/2)==0);
    screenshot(app,upward?L"dropdown-up.png":L"dropdown-down.png");
    assert(ui_debug_mouse_move(app.window(),hoverX,drop.bottom-padding-combo->ItemHeight()/2)==0);
    screenshot(app,upward?L"dropdown-up-last.png":L"dropdown-down-last.png");
    animation.stopped=false;
    assert(ui_debug_key(app.window(),VK_ESCAPE)==0);
    assert(!combo->IsOpen());
    if(animations) assert(combo->PopupAnimating() || (animation.stopped && combo->PopupOpacity()==0));
    // Reopen during exit; it must resume from its current visual state.
    open();
    assert(combo->IsOpen());
    pump([&]{return !combo->PopupAnimating() && (!animations || animation.stopped);},"Popup reversal");
    drop=combo->DropdownRect();
    float x=(drop.left+drop.right)/2,y=drop.top+padding+(combo->SelectedIndex()+0.5f)*combo->ItemHeight();
    int selected=combo->DropdownItemAt(x,y); assert(selected==combo->SelectedIndex());
    animation.stopped=false;
    assert(ui_debug_mouse_down(app.window(),x,y)==0);
    assert(ui_debug_mouse_up(app.window(),x,y)==0);
    assert(!combo->IsOpen());
    pump([&]{return !combo->PopupAnimating() && (!animations || animation.stopped);},"Popup exit");
    assert(combo->PopupOpacity()==0 && combo->PopupProgress()==0 && !animation.layout);
    assert(combo->SelectedIndex()==selected);
    assert(combo->rect.left==bounds.left && combo->rect.right==bounds.right);
}
// All records must be reachable without retaining widgets for previously
// visited rows. The same check covers variable config blocks, dense passwords,
// and task/directory lists; no wall-clock performance threshold.
void virtual_tail(Application& app,const char* list_id,const char* scroll_id,size_t total) {
    ui_window_focus_widget(app.window(),0);
    ui_window_relayout(app.window());
    auto* list=dynamic_cast<ui::VirtualListWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById(list_id));
    assert(list && total>0 && list->Children().size()<40);
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById(scroll_id)); assert(scroll);
    auto scroll_to=[&](float y) {
        // Programmatic scroll must use the window's renderer-backed measurer,
        // exactly like the production scroll command, including newly mounted rows.
        ui::GetContext().GetWindow(app.window())->ScrollWithMeasureContext(scroll,y);
        ui_debug_pump(); // Observe production refill/layout; do not repair it.
    };
    // Estimated heights settle when the last variable-height rows mount.
    for(int pass=0;pass<3;++pass) scroll_to(1e9f);
    if(list->Indices().empty() || list->Indices().back()!=total-1)
        std::cerr<<"Virtual tail "<<list_id<<" expected="<<total<<" last="<<(list->Indices().empty()?0:list->Indices().back())<<" scroll="<<scroll->ScrollY()<<"\n";
    assert(!list->Indices().empty() && list->Indices().back()==total-1);
    assert(list->Children().size()<40);
    const auto& last=list->Children().back()->rect;
    auto viewport=scroll->rect;
    assert(last.top<viewport.bottom && last.bottom<=viewport.bottom+2);
    // A file watcher/save receipt replaces arrays even when row keys
    // and geometry are unchanged. Check the scrolled view, not only
    // reachability after resetting it to the top.
    auto before=scroll->ScrollY(), height=list->SizeHint().height;
    auto anchor=list->Children().back()->id;
    auto top=list->Children().back()->rect.top;
    const char* data_key=!std::strcmp(list_id,"configItems")?"fields":
        !std::strcmp(list_id,"directoryItems")?"directories":
        !std::strcmp(list_id,"passwordItems")?"passwords":
        !std::strcmp(list_id,"rootItems")?"rootRows":"tasks";
    auto replacement=state(app.page(),data_key).dump();
    assert(ui_page_set_json(app.page(),data_key,replacement.c_str())==0);
    ui_window_relayout(app.window());
    auto* row=list->FindById(anchor);
    if(!row || std::abs(scroll->ScrollY()-before)>0.5f ||
       std::abs(list->SizeHint().height-height)>0.5f || std::abs(row->rect.top-top)>0.5f)
        throw std::runtime_error(std::string("Data refresh moved virtual view: ")+list_id);
    if(!std::strcmp(list_id,"taskItems")) {
        auto reordered=state(app.page(),data_key);
        auto first=reordered["rows"][0];
        reordered["rows"].erase(reordered["rows"].begin());
        reordered["rows"].push_back(first);
        auto encoded=reordered.dump();
        assert(ui_page_set_json(app.page(),data_key,encoded.c_str())==0);
        ui_window_relayout(app.window());
        row=list->FindById(anchor);
        assert(row && std::abs(row->rect.top-top)<0.5f && scroll->ScrollY()<before);
        assert(ui_page_set_json(app.page(),data_key,replacement.c_str())==0);
        ui_window_relayout(app.window());
        row=list->FindById(anchor);
        assert(row && std::abs(row->rect.top-top)<0.5f && std::abs(scroll->ScrollY()-before)<0.5f);
    }
    scroll_to(0);
    if(list->Indices().empty() || list->Indices().front()!=0 || list->Children().size()>=40) {
        std::cerr<<"Virtual top "<<list_id<<" indices="; for(auto index:list->Indices()) std::cerr<<index<<","; std::cerr<<" rect="<<list->rect.top<<","<<list->rect.bottom<<" scroll="<<rendered_widget(app,scroll_id)<<"\n";
    }
    assert(!list->Indices().empty() && list->Indices().front()==0 && list->Children().size()<40);
}
void scrolled_config_edits(Application& app) {
    auto* window=ui::GetContext().GetWindow(app.window());
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(window->Root()->FindById("configListScroll")); assert(scroll);
    for(auto id:{"/filesystem/scan_filters/0/enabled","/filesystem/scan_filters/0/prune_dir_globs","/runtime/process_mode"}) {
        const std::string pointer=id;
        const std::string control=(pointer.find("enabled")!=std::string::npos?"toggle-":
            pointer.find("prune_dir_globs")!=std::string::npos?"tag-input-":"select-")+pointer;
        window->ScrollWithMeasureContext(scroll,0);
        // Visit preceding rows through the real measured scrolling path.
        for(int pass=0;pass<200 && !window->Root()->FindById(control);++pass) {
            window->ScrollWithMeasureContext(scroll,scroll->ScrollY()+200);
            ui_window_relayout(app.window());
        }
        click(app,control.c_str());
        ui_window_relayout(app.window());
        assert(scroll->ScrollY()>0);
        const auto before=scroll->ScrollY(), top=rect(app,"field-"+pointer).top;
        auto unchanged=[&] {
            ui_window_relayout(app.window());
            if(std::abs(scroll->ScrollY()-before)>0.5f || std::abs(rect(app,"field-"+pointer).top-top)>0.5f) {
                std::cerr<<"Config viewport: before="<<before<<" after="<<scroll->ScrollY()<<" top="<<top<<" afterTop="<<rect(app,"field-"+pointer).top<<'\n';
                throw std::runtime_error("Editing moved configuration viewport: "+pointer);
            }
        };
        auto handle=ui_widget_find_by_id(ui_page_root(app.page()),control.c_str()); assert(handle);
        if(control.find("toggle-")==0) assert(ui_debug_toggle_set(app.window(),handle,0)==0);
        else if(control.find("tag-input-")==0) {
            assert(ui_debug_type_text(app.window(),L"skipped-directory")==0);
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
        } else {
            assert(ui_debug_key(app.window(),VK_ESCAPE)==0);
            assert(ui_debug_combo_select(app.window(),handle,2)==0);
        }
        ui_widget_destroy(handle);
        unchanged(); // Includes typing before blur or a save acknowledgement.
        finish_input(app);
        pump([&] {
            for(auto& field:state(app.page(),"fields")) if(field["id"]==pointer) {
                if(control.find("toggle-")==0) return field["boolean"]==false;
                if(control.find("tag-input-")==0) return field["items"].back()=="skipped-directory";
                return field["text"]=="high";
            }
            return false;
        },"Scrolled configuration save notification");
        unchanged();
    }
    window->ScrollWithMeasureContext(scroll,0);
    ui_window_relayout(app.window());
}
// One real-window scenario covers lossless collection editing, virtual rows,
// cancel and concurrent-file conflict. Scalar/record tests cannot detect these
// failures; sharing their fixture avoids another process/window startup.
// Locate the actual owned Core UI HWND; no test-only production API.
ui::UiWindowImpl* date_popup(Application& app) {
    struct Search { HWND owner; ui::UiWindowImpl* result=nullptr; unsigned count=0; } search{static_cast<HWND>(ui_window_hwnd(app.window()))};
    EnumThreadWindows(GetCurrentThreadId(),[](HWND hwnd,LPARAM data)->BOOL {
        auto& s=*reinterpret_cast<Search*>(data);
        wchar_t name[64]{}; GetClassNameW(hwnd,name,64);
        if(GetWindow(hwnd,GW_OWNER)==s.owner && !std::wcscmp(name,L"UiCore_Window")) {
            auto* w=reinterpret_cast<ui::UiWindowImpl*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
            if(w && w->Root() && w->Root()->FindById("datePopup")) { s.result=w; ++s.count; }
        }
        return TRUE;
    },reinterpret_cast<LPARAM>(&search));
    assert(search.count<=1); return search.result;
}
void popup_click(ui::UiWindowImpl* popup,const char* id) {
    auto window=popup->windowId;
    auto* widget=popup->Root()->FindById(id); assert(widget);
    auto handle=ui::GetContext().handles.Insert(widget->shared_from_this());
    assert(ui_debug_click(popup->windowId,handle)==0); ui_widget_destroy(handle); ui_debug_pump();
    if(std::strcmp(id,"dateCancel") && std::strcmp(id,"dateConfirm") && ui::GetContext().GetWindow(window)!=popup)
        throw std::runtime_error("Date popup lost activation during pointer operation");
}
void popup_key(ui::UiWindowImpl* popup,int key) {
    // Real HWND dispatch includes the popup's keyboard routing subclass.
    auto window=popup->windowId;
    SendMessageW(popup->Handle(),WM_KEYDOWN,key,0); ui_debug_pump();
    // External desktop activation legitimately cancels the popup. Never retain
    // a raw test-driver pointer across a message pump without checking its ID.
    if(key!=VK_ESCAPE && key!=VK_RETURN && ui::GetContext().GetWindow(window)!=popup)
        throw std::runtime_error("Date popup lost activation during keyboard operation");
}
// One shared-window scenario covers translated search sources that control-edit
// tests never query: options, hints, values and the two standalone settings.
void localized_config_search(Application& app) {
    auto matches=[&](const std::string& query,const std::string& id) {
        auto text=wide(query); search_config(app,text.c_str());
        for(auto& block:state(app.page(),"matchingBlocks"))
            for(auto& f:block["fields"]) if(f["id"]==id) return;
        throw std::runtime_error("Translated search missed "+id+": "+query);
    };
    for(auto language:{"en","zh"}) {
        search_setting(app,"/cli/language");
        auto selector=ui_widget_find_by_id(ui_page_root(app.page()),"select-/cli/language"); assert(selector);
        assert(ui_debug_combo_select(app.window(),selector,std::strcmp(language,"zh")==0?0:1)==0);
        ui_widget_destroy(selector); finish_input(app);
        pump([&]{return state(app.page(),"language")==language;},"Search language changed");
        auto fields=state(app.page(),"fields"),texts=state(app.page(),"texts");
        for(auto& f:fields) {
            if(f["id"]=="/runtime/process_mode") matches(f["options"][0]["label"],f["id"]);
            if(f["id"]=="/watch/enabled") matches(f["description"],f["id"]);
            if(f["id"]=="/watch/state_dir") matches(f["text"],f["id"]);
            if(f["editor"]=="datetime_range") matches(texts["rangeEnd"],f["id"]);
            if(f["editor"]=="size_range") matches("GiB",f["id"]);
        }
        search_config(app,wide(texts["dark"].get<std::string>()).c_str());
        assert(state(app.page(),"showThemeSetting")==true);
        search_config(app,wide(texts["startup"].get<std::string>()).c_str());
        assert(state(app.page(),"showStartupSetting")==true);
        search_config(app,L"max_pending_stage_jobs");
        assert(state(app.page(),"matchingBlocks").empty());
    }
    search_config(app,L"");
}
// Real pointer clicks plus reversible typing distinguish a positioned caret
// from focus-only behavior; tail paths cover the display's ellipsis transform.
void inline_cell_caret(Application& app) {
    
    ui_window_set_size(app.window(),850,560);
    auto* window=ui::GetContext().GetWindow(app.window());
    auto check=[&](const std::string& display,const std::string& labelId,const std::string& editor,bool tail) {
        ui_window_relayout(app.window());
        auto* label=dynamic_cast<ui::LabelWidget*>(window->Root()->FindById(labelId)); assert(label);
        auto text=label->Text(),shown=text;
        float font=label->css.fontSize>0?label->css.fontSize:theme::kFontSizeNormal;
        auto& renderer=window->GetRenderer();
        if(tail) shown=renderer.EllipsizeStart(text,label->ContentWidth(),font);
        size_t hidden=shown==text?0:text.size()-(shown.size()-1);
        size_t index=shown.size()/2;
        if(hidden) index=std::max(size_t(1),index);
        size_t expected=hidden?hidden+index-1:index;
        float x=label->ContentLeft()+renderer.MeasureTextWidth(shown.substr(0,index),font);
        auto bounds=rect(app,display);
        float y=(bounds.top+bounds.bottom)/2;
        assert(ui_debug_mouse_down(app.window(),x,y)==0);
        assert(ui_debug_mouse_up(app.window(),x,y)==0);
        pump([&]{auto* f=window->FocusedWidget();return f&&f->id==editor;},"Pointer-positioned cell");
        assert(ui_debug_type_char(app.window(),L'X')==0);
        auto* input=dynamic_cast<ui::TextInputWidget*>(window->FocusedWidget()); assert(input);
        auto edited=text; edited.insert(expected,1,L'X');
        if(input->Text()!=edited) throw std::runtime_error("Caret did not follow cell click: "+editor+
            " expected="+utf8(edited)+" actual="+utf8(input->Text())+" x="+std::to_string(x)+
            " pointer="+state(app.page(),"cellPointer").dump()+" requests="+state(app.page(),"requests").dump());
        assert(ui_debug_type_char(app.window(),8)==0);
        if(input->Text()!=text) throw std::runtime_error("Caret moved while rebinding cell: "+editor+
            " expected="+utf8(text)+" actual="+utf8(input->Text()));
    };
    click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";}); settle_motion(app);
    auto rows=state(app.page(),"passwords")["rows"]; assert(!rows.empty());
    auto id=rows[0]["id"].get<std::string>();
    check("password-text-"+id,"password-value-"+id,"password-input-"+id,false);
    click(app,"passwordSearch"); finish_input(app);
    click(app,"tabRoots"); pump([&]{return state(app.page(),"tab")=="roots";}); settle_motion(app);
    auto roots=state(app.page(),"rootRows"); assert(!roots.empty());
    id=roots[0]["id"].get<std::string>();
    check("root-input-text-"+id,"root-input-value-"+id,"root-input-input-"+id,true);
    click(app,"rootSearch"); finish_input(app);
    edit_root_cell(app,id,"output",L"C:/输出/long-folder-name/another-folder/last-folder");
    click(app,"rootSearch"); finish_input(app);
    check("root-output-text-"+id,"root-output-value-"+id,"root-output-input-"+id,true);
    click(app,"rootSearch"); finish_input(app);
    click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";}); settle_motion(app);
}
void page_motion(Application& app) {
    settle_motion(app);
    auto* window=ui::GetContext().GetWindow(app.window());
    auto* page=window->Root()->FindById("page-tasks");
    auto* body=window->Root()->FindById("taskBody");
    assert(page && body);
    const auto bounds=body->rect;
    BOOL animations=TRUE; SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0);
    {
        motion::VisualBatch visual(app.window());
        motion::enter(app.window(),"page-tasks");
        assert(page->opacity==1 && page->animationX==0);
        if(animations) {
            assert(page->animationY>0 && page->animationY<=8);
            // Seed an intermediate frame without a machine-speed assumption.
            // A repeated entrance must keep its position and finite clock.
            window->CancelPropertyAnimation(page,ui::AnimProperty::TranslateY);
            page->animationY=3;
            window->AnimateProperty(page,ui::AnimProperty::TranslateY,3,0,260,ui::EasingFunction::EaseOutCubic);
            motion::enter(app.window(),"page-tasks");
            assert(page->animationY==3 && page->opacity==1);
        } else assert(page->animationY==0);
    }
    settle_motion(app);
    // Observe actual frames, not just final values: every page stays opaque,
    // subview data never moves, and the shared directory pane stays put.
    struct PairedEntrances {
        ui::UiWindowImpl* window; bool shared=true,mismatch=false; unsigned frames=0;
        explicit PairedEntrances(ui::UiWindowImpl* w):window(w) {
            ui_trace_set_sink([](const UiTraceEvent* event,void* context) {
                if(std::strcmp(event->name,"property_animation_frame")) return;
                auto& self=*static_cast<PairedEntrances*>(context);
                ++self.frames;
                auto* root=self.window->Root().get();
                for(const char* tab:{"tasks","config","roots","passwords"}) {
                    auto* page=root->FindById(std::string("page-")+tab);
                    if(page && page->visible && (page->opacity!=1 || page->animationX!=0)) self.mismatch=true;
                }
                for(const char* id:{"taskBody","configBlocks","passwordBody"}) {
                    auto* body=root->FindById(id);
                    if(body && (body->opacity!=1 || body->animationX!=0 || body->animationY!=0)) self.mismatch=true;
                }
                for(const char* id:{"configSidebar","directoryPane"}) {
                    auto* sidebar=root->FindById(id);
                    if(sidebar && sidebar->opacity!=1) self.mismatch=true;
                }
                auto* directory=root->FindById("directoryPane");
                if(self.shared && directory->animationY!=0) self.mismatch=true;
                auto* config=root->FindById("page-config"),*sidebar=root->FindById("configSidebar");
                if(config->visible && config->animationY>1 && sidebar->animationY==0) self.mismatch=true;
            },this);
        }
        ~PairedEntrances() { ui_trace_set_sink(nullptr,nullptr); }
    } paired(window);
    const auto navigation=rect(app,"navItems"),monitor=rect(app,"monitorControls");
    click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
    settle_motion(app);
    assert(!paired.mismatch);
    paired.shared=false;
    // Exercise both lower content types and rapid reversal in the same fixture.
    click(app,"tabConfig"); click(app,"tabPasswords"); click(app,"tabTasks");
    pump([&]{return state(app.page(),"tab")=="tasks" && state(app.page(),"requests").empty() && state(app.page(),"dispatch")==false;},"Subview motion cancellation");
    assert(body->opacity==1 && body->animationY==0);
    settle_motion(app);
    assert(!paired.mismatch);
    if(animations) assert(paired.frames>0);
    for(const char* id:{"configSidebar","directoryPane"}) {
        auto* sidebar=window->Root()->FindById(id); assert(sidebar);
        assert(sidebar->opacity==1 && sidebar->animationY==0);
    }
    assert(rect(app,"navItems").top==navigation.top && rect(app,"monitorControls").top==monitor.top);
    assert(body->rect.left==bounds.left && body->rect.top==bounds.top &&
        body->rect.right==bounds.right && body->rect.bottom==bounds.bottom);
}
void config_categories(Application& app) {
    search_config(app,L"");
    auto categories=state(app.page(),"categories"); assert(categories.size()>2);
    const std::vector<std::string> choices={categories.front()["id"],categories.back()["id"],"",categories[1]["id"],""};
    for(const auto& category:choices) {
        settle_motion(app);
        struct Trace {
            ui::Widget* blocks; bool moved=false;
            Trace(Application& a):blocks(ui::GetContext().GetWindow(a.window())->Root()->FindById("configBlocks")) {
                ui_trace_set_sink([](const UiTraceEvent* event,void* data) {
                    auto& t=*static_cast<Trace*>(data);
                    if(!std::strcmp(event->name,"frame_job_submitted") &&
                       (t.blocks->opacity!=1 || t.blocks->animationX!=0 || t.blocks->animationY!=0)) t.moved=true;
                },this);
            }
            ~Trace() { ui_trace_set_sink(nullptr,nullptr); }
        } trace(app);
        click(app,category.empty()?"category-all":("category-"+category).c_str());
        pump([&]{return state(app.page(),"configCategory")==category && state(app.page(),"requests").empty();},"Configuration category transaction");
        assert(!trace.moved && trace.blocks->opacity==1 && trace.blocks->animationX==0 && trace.blocks->animationY==0);
        auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById("configListScroll"));
        assert(scroll && scroll->ScrollY()==0);
        auto blocks=state(app.page(),"matchingBlocks"); assert(!blocks.empty());
        if(!category.empty()) for(auto& block:blocks) assert(block["category"]==category);
    }
}
void range_config(Application& app,const fs::path& dir) {
    config_categories(app);
    auto field=[&](const std::string& module) { for(auto& f:state(app.page(),"fields")) if(f["module"]==module && f["type"]=="object") return f; return Json(); };
    auto size=field("size_range"),time=field("mtime_range"); assert(!size.is_null() && !time.is_null());
    auto id=size["id"].get<std::string>(),tid=time["id"].get<std::string>();
    auto input=[&](const std::string& control,const wchar_t* value) {
        click(app,control.c_str()); assert(ui_debug_key_mod(app.window(),'A',1,0,0)==0);
        assert(ui_debug_type_char(app.window(),8)==0); if(*value) assert(ui_debug_type_text(app.window(),value)==0);
    };
    auto layout=[&](const std::string& pointer,bool datetime) {
        auto lowerId="range-lower-group-"+pointer,upperId="range-upper-group-"+pointer;
        ui_window_set_size(app.window(),1120,720); ui_window_relayout(app.window());
        auto lower=rect(app,lowerId),upper=rect(app,upperId);
        assert(std::abs(lower.top-upper.top)<0.1f && upper.left>=lower.right);
        assert(!ui_widget_find_by_id(ui_page_root(app.page()),("range-mode-"+pointer).c_str()));
        assert(!ui_widget_find_by_id(ui_page_root(app.page()),("range-expression-"+pointer).c_str()));
        assert(!ui_widget_find_by_id(ui_page_root(app.page()),("range-lower-op-"+pointer).c_str()));
        auto value=rect(app,"range-lower-"+pointer);
        assert(value.right-value.left<(datetime?180:130));
        button_texts(app);
        screenshot(app,datetime?L"range-time-wide.png":L"range-size-wide.png");
        ui_window_set_size(app.window(),850,560); ui_window_relayout(app.window());
        lower=rect(app,lowerId); upper=rect(app,upperId);
        assert(upper.top>=lower.bottom || (upper.left>=lower.right && std::abs(upper.top-lower.top)<0.1f));
        for(auto side:{"lower","upper"}) {
            auto group=rect(app,"range-"+std::string(side)+"-group-"+pointer);
            auto inputBounds=rect(app,"range-"+std::string(side)+"-"+pointer);
            auto last=rect(app,"range-"+std::string(side)+(datetime?"-pick-":"-unit-")+pointer);
            assert(inputBounds.left>=group.left && last.right<=group.right+0.1f && last.bottom<=group.bottom+0.1f);
        }
        button_texts(app);
    };
    search_setting(app,"size_range");
    layout(id,false);
    auto bound=[&](const std::string& module,const std::string& key) {return parse_json(field(module)["text"])[key];};
    assert(field("size_range")["range"]["enabled"]==true);
    input("range-lower-"+id,L"9007199254740993"); finish_input(app);
    pump([&]{return bound("size_range","min_bytes")==uint64_t(9007199254740993);},"Exact size range save");
    input("range-upper-"+id,L"1"); ui_window_focus_widget(app.window(),0);
    pump([&]{return state(app.page(),"saveErrors").contains(id);},"Range ordering validation");
    assert(read_json(dir/"sunpack_config.json")[Json::json_pointer(id)]["min_bytes"]==uint64_t(9007199254740993));
    input("range-upper-"+id,L""); finish_input(app);
    input("range-lower-"+id,L"2"); finish_input(app);
    auto unit=ui_widget_find_by_id(ui_page_root(app.page()),("range-lower-unit-"+id).c_str()); assert(unit);
    assert(ui_debug_combo_select(app.window(),unit,2)==0); ui_widget_destroy(unit); finish_input(app);
    try { pump([&]{return bound("size_range","min_bytes")==2097152;},"Size unit conversion"); }
    catch(...) { std::cerr<<"Range unit: field="<<field("size_range")<<" drafts="<<state(app.page(),"drafts")<<" errors="<<state(app.page(),"saveErrors")<<'\n'; throw; }
    // Unit-first editing has no persistent effect while the corresponding
    // bound is empty, including blur and an unrelated save acknowledgement.
    input("range-lower-"+id,L""); finish_input(app);
    assert(bound("size_range","min_bytes").is_null());
    auto chooseUnit=[&](const std::string& side,int index) {
        auto combo=ui_widget_find_by_id(ui_page_root(app.page()),("range-"+side+"-unit-"+id).c_str()); assert(combo);
        assert(ui_debug_combo_select(app.window(),combo,index)==0);
        ui_widget_destroy(combo); finish_input(app);
    };
    auto configPath=dir/"sunpack_config.json";
    auto unchanged=read_file(configPath);
    auto unchangedTime=fs::last_write_time(configPath);
    chooseUnit("lower",3); // GiB, before typing a number.
    chooseUnit("upper",2); // MiB, before typing a number.
    assert(read_file(configPath)==unchanged && fs::last_write_time(configPath)==unchangedTime);
    assert(state(app.page(),"rangeUnitDrafts")[id]["lowerUnit"]==3);
    assert(state(app.page(),"rangeUnitDrafts")[id]["upperUnit"]==2);
    click(app,("range-enabled-"+id).c_str()); finish_input(app);
    pump([&]{return bound("size_range","enabled")==false;},"Empty size units after disable acknowledgement");
    click(app,("range-enabled-"+id).c_str()); finish_input(app);
    pump([&]{return bound("size_range","enabled")==true;},"Empty size units after enable acknowledgement");
    input("range-lower-"+id,L"2"); finish_input(app);
    pump([&]{return bound("size_range","min_bytes")==uint64_t(2)*1024*1024*1024;},"Preserved GiB unit after acknowledgement");
    input("range-upper-"+id,L"3072"); finish_input(app);
    pump([&]{return bound("size_range","max_bytes")==uint64_t(3)*1024*1024*1024;},"Preserved MiB unit after other bound saved");
    chooseUnit("lower",2); // Restore the range used by the remaining tests.
    pump([&]{return bound("size_range","min_bytes")==2097152;},"Restore MiB lower bound");
    input("range-upper-"+id,L""); finish_input(app);
    assert(bound("size_range","max_bytes").is_null());
    click(app,("range-enabled-"+id).c_str()); finish_input(app);
    pump([&]{return bound("size_range","enabled")==false;},"Range disable save");
    click(app,("range-enabled-"+id).c_str()); finish_input(app);
    pump([&]{return bound("size_range","enabled")==true;},"Range enable save");
    {
        FileMutex hold(dir/"sunpack_config.json");
        input("range-lower-"+id,L"3"); click(app,"configSearch"); ui_debug_pump();
        input("range-lower-"+id,L"4");
    }
    pump([&]{return bound("size_range","min_bytes")==3145728 && !state(app.page(),"saving").get<bool>();},"Range acknowledgement during typing");
    assert(state(app.page(),"drafts")[id]["range"]["lower"]=="4");
    finish_input(app);
    pump([&]{return bound("size_range","min_bytes")==4194304;},"Continued range edit");
    screenshot(app,L"range-size-small.png");
    input("range-lower-"+id,L"5");
    auto config=read_json(dir/"sunpack_config.json"); config[Json::json_pointer(id)]["min_bytes"]=8388608;
    atomic_write(dir/"sunpack_config.json",config.dump());
    pump([&]{return bound("size_range","min_bytes")==8388608;},"Range reload");
    click(app,"configSearch");
    pump([&]{return state(app.page(),"saveErrors").contains(id);},"Range external conflict");
    assert(state(app.page(),"drafts")[id]["range"]["lower"]=="5");
    assert(read_json(dir/"sunpack_config.json")[Json::json_pointer(id)]["min_bytes"]==8388608);
    input("range-lower-"+id,L"6"); finish_input(app);
    assert(read_json(dir/"sunpack_config.json")[Json::json_pointer(id)]["min_bytes"]==6291456);
    search_setting(app,"mtime_range");
    input("range-lower-"+tid,L"2023-02-29 00:00"); ui_window_focus_widget(app.window(),0);
    pump([&]{return state(app.page(),"saveErrors").contains(tid);},"Leap date validation");
    input("range-lower-"+tid,L"2024-01-31 12:34"); finish_input(app);
    auto before=read_file(dir/"sunpack_config.json");
    auto open=[&](const std::string& side) {
        settle_motion(app);
        AnimationFrames animation;
        click(app,("range-"+side+"-pick-"+tid).c_str()); ui_debug_pump();
        auto* popup=date_popup(app); assert(popup);
        auto* surface=popup->Root().get();
        assert(surface->id=="datePopupSurface");
        pump([&]{return surface->opacity==1;},"Date popup entrance",false);
        BYTE alpha=0; DWORD flags=0;
        assert(GetLayeredWindowAttributes(popup->Handle(),nullptr,&alpha,&flags) && alpha==255 && (flags&LWA_ALPHA));
        auto* picker=ui::GetContext().GetWindow(app.window())->Root()->FindById("range-"+side+"-pick-"+tid);
        assert(picker && picker->focusIndicator==ui::Widget::FocusIndicator::Underline);
        assert(GetWindow(popup->Handle(),GW_OWNER)==ui_window_hwnd(app.window()));
        assert(!(GetWindowLongPtrW(popup->Handle(),GWL_STYLE)&WS_CAPTION));
        RECT bounds{}; GetWindowRect(popup->Handle(),&bounds);
        MONITORINFO monitor{sizeof(monitor)}; GetMonitorInfoW(MonitorFromWindow(popup->Handle(),MONITOR_DEFAULTTONEAREST),&monitor);
        assert(bounds.left>=monitor.rcWork.left && bounds.right<=monitor.rcWork.right);
        assert(bounds.top>=monitor.rcWork.top && bounds.bottom<=monitor.rcWork.bottom);
        auto focused=popup->FocusedWidget();
        if(focused) assert(focused->focusIndicator==ui::Widget::FocusIndicator::None && focused->css.borderWidth==0);
        if(!focused || focused->id.rfind("date-day-",0)!=0) {
            char* tree=ui_debug_dump_tree(popup->windowId);
            std::cerr<<"Popup focus="<<(focused?focused->id:"none")<<" tree="<<(tree?tree:"")<<'\n'; ui_debug_free(tree);
            throw std::runtime_error("Calendar initial focus missing");
        }
        return popup;
    };
    auto* popup=open("lower");
    std::weak_ptr<ui::Widget> oldTree=popup->Root();
    popup_key(popup,VK_NEXT); // Jan 31 -> Feb 29 in a leap year.
    auto* label=dynamic_cast<ui::LabelWidget*>(popup->Root()->FindById("dateSelected"));
    assert(label && label->Text()==L"2024-02-29");
    popup_key(popup,VK_RIGHT);
    assert(label->Text()==L"2024-03-01");
    popup_key(popup,VK_LEFT);
    wchar_t shots[MAX_PATH]{};
    if(GetEnvironmentVariableW(L"SUNPACK_GUI_SCREENSHOTS",shots,MAX_PATH))
        assert(ui_debug_screenshot(popup->windowId,(fs::path(shots)/L"date-popup.png").c_str())==0);
    popup_key(popup,VK_TAB);
    assert(popup->FocusedWidget()->id=="dateTime"); // One calendar Tab stop.
    assert(ui_debug_key_mod(popup->windowId,'A',1,0,0)==0);
    assert(ui_debug_type_text(popup->windowId,L"25:70")==0);
    popup_key(popup,VK_RETURN);
    popup=date_popup(app); assert(popup);
    auto* error=dynamic_cast<ui::LabelWidget*>(popup->Root()->FindById("dateError"));
    assert(error && !error->Text().empty() && date_popup(app)==popup);
    assert(read_file(dir/"sunpack_config.json")==before);
    assert(ui_debug_key_mod(popup->windowId,'A',1,0,0)==0);
    assert(ui_debug_type_text(popup->windowId,L"12:34")==0);
    popup_key(popup,VK_TAB); // Remove the input selection before visual QA.
    ui_window_relayout(popup->windowId);
    assert(dynamic_cast<ui::TextInputWidget*>(popup->Root()->FindById("dateTime"))->Text()==L"12:34");
    popup_click(popup,"dateConfirm");
    pump([&]{return field("mtime_range")["range"]["lower"]=="2024-02-29 12:34";},"Core UI date selection");
    pump([&]{return !date_popup(app);},"Date confirmation exit");
    assert(!date_popup(app) && oldTree.expired());
    // Model a timezone change between popup validation and the queued save.
    // The UI handoff must retain the confirmed UTC rather than reinterpret the
    // displayed local minute in the current zone. No machine timezone change.
    auto confirmedUtc=range_utc_text(range_utc_minutes(bound("mtime_range","start_utc"))+60);
    auto confirmed=Json{{"id",tid},{"side","lower"},{"value","2024-02-29 12:34"},{"utc",confirmedUtc}}.dump();
    assert(ui_page_call_json(app.page(),"pickedRange",confirmed.c_str())==0);
    finish_input(app);
    assert(bound("mtime_range","start_utc")==confirmedUtc);
    before=read_file(dir/"sunpack_config.json");
    // Cancel, outside activation, settings switch and superseded completion
    // exercise different lifetime paths, sharing the existing real window.
    popup=open("upper"); oldTree=popup->Root();
    popup_click(popup,"dateToday");
    popup_key(popup,VK_RIGHT);
    // Selection is the only accent. A formerly selected 'today' must return
    // to the same text color as the other ordinary days. File saves cannot
    // detect that visual state, so reuse this popup before its existing cancel.
    auto normal=popup->Root()->FindById("datePopup")->css.fg;
    int selectedDays=0;
    for(int index=0;index<42;++index) {
        auto* day=popup->Root()->FindById("date-day-"+std::to_string(index)); assert(day);
        auto has=[&](const char* name){return std::find(day->dynamicClasses.begin(),day->dynamicClasses.end(),name)!=day->dynamicClasses.end();};
        if(has("selected")) { ++selectedDays; assert(day==popup->FocusedWidget()); }
        else if(!has("other")) assert(std::abs(day->css.fg.r-normal.r)<0.001f &&
            std::abs(day->css.fg.g-normal.g)<0.001f && std::abs(day->css.fg.b-normal.b)<0.001f);
    }
    assert(selectedDays==1);
    if(*shots) assert(ui_debug_screenshot(popup->windowId,(fs::path(shots)/L"date-popup-selection.png").c_str())==0);
    popup_click(popup,"datePrevious");
    popup_key(popup,VK_ESCAPE);
    pump([&]{return !date_popup(app);},"Date cancellation exit");
    assert(!date_popup(app) && oldTree.expired());
    popup=open("lower"); oldTree=popup->Root();
    SendMessageW(popup->Handle(),WM_ACTIVATE,WA_INACTIVE,0); ui_debug_pump();
    pump([&]{return !date_popup(app);},"Date deactivation exit");
    assert(!date_popup(app) && oldTree.expired());
    popup=open("lower"); oldTree=popup->Root();
    // Replace before draining the old Esc completion. The generation prevents
    // a queued result from closing the newly opened upper-bound popup.
    SendMessageW(popup->Handle(),WM_KEYDOWN,VK_ESCAPE,0);
    auto request=Json{{"op","pickRangeDate"},{"payload",{{"id",tid},{"side","upper"},{"value","2024-03-01 00:00"}}}};
    auto queued=Json::array({request}).dump(); ui_page_set_json(app.page(),"requests",queued.c_str());
    SendMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_APP+0x401,0,0); ui_debug_pump();
    assert(date_popup(app) && oldTree.expired());
    search_setting(app,"size_range");
    pump([&]{return !date_popup(app);},"Date settings switch exit");
    assert(!date_popup(app));
    assert(read_file(dir/"sunpack_config.json")==before);
    search_setting(app,"mtime_range");
    auto theme=ui_widget_find_by_id(ui_page_root(app.page()),"themeSelector"); assert(theme);
    auto choice=state(app.page(),"themeChoice").get<int>();
    auto otherTheme=state(app.page(),"appearance")=="dark"?1:2;
    assert(ui_debug_combo_select(app.window(),theme,otherTheme)==0);
    popup=open("lower");
    if(*shots) assert(ui_debug_screenshot(popup->windowId,(fs::path(shots)/L"date-popup-other-theme.png").c_str())==0);
    popup_key(popup,VK_ESCAPE);
    pump([&]{return !date_popup(app);},"Date theme exit");
    assert(ui_debug_combo_select(app.window(),theme,choice)==0); ui_widget_destroy(theme);
    // Exercise placement on each attached monitor, including negative screen
    // coordinates and its real DPI. No desktop resolution or scaling changes.
    std::vector<RECT> workAreas;
    EnumDisplayMonitors(nullptr,nullptr,[](HMONITOR monitor,HDC,LPRECT,LPARAM context)->BOOL {
        MONITORINFO info{sizeof(info)}; assert(GetMonitorInfoW(monitor,&info));
        reinterpret_cast<std::vector<RECT>*>(context)->push_back(info.rcWork); return TRUE;
    },reinterpret_cast<LPARAM>(&workAreas));
    for(auto work:workAreas) for(bool bottom:{false,true}) {
        LONG y=bottom?work.bottom-40:work.top+10;
        RECT anchor{work.left+20,y,work.left+180,y+24};
        std::weak_ptr<ui::Widget> tree;
        {
            DatePopup placed(app.window(),WM_APP+0x403,0,anchor,tid,"lower","2024-02-29 12:34",
                             state(app.page(),"language"),state(app.page(),"appearance"));
            auto* actual=date_popup(app); assert(actual); tree=actual->Root();
            RECT bounds{}; GetWindowRect(actual->Handle(),&bounds);
            assert(bounds.left>=work.left && bounds.right<=work.right && bounds.top>=work.top && bounds.bottom<=work.bottom);
            if(bottom && bounds.bottom-bounds.top<anchor.top-work.top) assert(bounds.bottom<anchor.top);
            if(!bottom && bounds.bottom-bounds.top<work.bottom-anchor.bottom) assert(bounds.top>anchor.bottom);
            auto* first=actual->Root()->FindById("date-day-0"),*seventh=actual->Root()->FindById("date-day-6"),*eighth=actual->Root()->FindById("date-day-7");
            assert(first && seventh && eighth && std::abs(first->rect.top-seventh->rect.top)<0.1f && eighth->rect.top>first->rect.bottom);
        }
        assert(tree.expired());
    }
    assert(read_file(dir/"sunpack_config.json")==before);
    layout(tid,true);
    screenshot(app,L"range-time-small.png");
}
// Enter/delete are explicit writes; blur, scrolling and snapshot refreshes
// must preserve unsubmitted text. This shares the existing configuration fixture.
void tag_config(Application& app,const fs::path& dir) {
    const std::string pointer="/filesystem/scan_filters/0/prune_dir_globs",inputId="tag-input-"+pointer;
    auto config=read_json(dir/"sunpack_config.json");
    Json values=Json::array({"",std::string("a")+char(10)+"b","  spaced  ","duplicate","duplicate"});
    for(int i=0;i<180;++i) values.push_back("rule-"+std::to_string(i));
    auto disk=[&]{return read_json(dir/"sunpack_config.json")[Json::json_pointer(pointer)];};
    auto current=[&]{for(auto& f:state(app.page(),"fields")) if(f["id"]==pointer) return f;return Json();};
    config[Json::json_pointer(pointer)]=values; atomic_write(dir/"sunpack_config.json",config.dump());
    pump_diagnostic(app,[&]{return current().value("items",Json())==values;},"TAG fixture reload");
    search_setting(app,pointer);
    auto* window=ui::GetContext().GetWindow(app.window());
    assert(!window->Root()->FindById("listManager") && !window->Root()->FindById("list-"+pointer));
    auto scroll=[&]{return dynamic_cast<ui::ScrollViewWidget*>(window->Root()->FindById("tag-scroll-"+pointer));};
    auto input=[&]{return dynamic_cast<ui::TextInputWidget*>(window->Root()->FindById(inputId));};
    assert(scroll() && scroll()->NeedsScrollbar());
    auto* cloud=window->Root()->FindById("tags-"+pointer); assert(cloud && cloud->Children().empty());
    auto region=rect(app,"tag-scroll-"+pointer),left=rect(app,inputId);
    assert(region.left>=left.right && region.bottom-region.top<=114);
    auto* copy=input()->Parent(); auto* row=copy->Parent(); auto* item=row->Parent();
    assert(std::abs(copy->rect.top+copy->rect.bottom-region.top-region.bottom)<0.2f);
    assert(std::abs(region.top-row->rect.top-row->rect.bottom+region.bottom)<0.2f);
    assert(row->rect.top-item->rect.top<=1.1f && std::abs(item->rect.bottom-row->rect.bottom)<0.1f);
    click(app,inputId.c_str()); assert(ui_debug_type_text(app.window(),L"unsubmitted")==0);
    click(app,"configSearch");
    assert(disk()==values && state(app.page(),"tagInputs")[pointer]=="unsubmitted");
    // Hover the second, nonempty TAG's close button before the existing scroll.
    // It must not publish an out-of-viewport tooltip on the collection surface.
    float firstWidth=std::clamp(window->GetRenderer().MeasureTextWidth(wide(state(app.page(),"texts")["emptyEntry"].get<std::string>()),13)+33,38.0f,240.0f);
    float closeX=cloud->rect.left+firstWidth+4+window->GetRenderer().MeasureTextWidth(L"a↵b",13)+25;
    assert(ui_debug_mouse_move(app.window(),closeX,cloud->rect.top+13)==0);
    assert(cloud->cursor==ui::CursorKind::Pointer && cloud->tooltip.empty());
    window->ScrollWithMeasureContext(scroll(),1000000); ui_window_relayout(app.window());
    assert(scroll()->ScrollY()>0 && disk()==values && cloud->tooltip.empty());
    screenshot(app,L"tag-config-tail.png");
    search_config(app,L"");
    virtual_tail(app,"configItems","configListScroll",state(app.page(),"matchingBlocks").size());
    search_setting(app,pointer);
    assert(input() && input()->Text()==L"unsubmitted" && disk()==values);
    // A different category and a different main page both discard input only.
    click(app,"category-watch"); pump([&]{return state(app.page(),"configCategory")=="watch";});
    assert(state(app.page(),"tagInputs").empty());
    click(app,"category-all"); pump([&]{return state(app.page(),"configCategory")=="";});
    search_setting(app,pointer);
    click(app,inputId.c_str()); assert(ui_debug_type_text(app.window(),L"discard me")==0);
    click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
    assert(state(app.page(),"tagInputs").empty() && disk()==values);
    click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
    search_setting(app,pointer); assert(input()->Text().empty());
    auto add=[&](const wchar_t* value) {
        click(app,inputId.c_str()); assert(ui_debug_type_text(app.window(),value)==0);
        assert(ui_debug_key(app.window(),VK_RETURN)==0); ui_debug_pump();
    };
    add(L"  new tag #  "); finish_input(app); values.push_back("  new tag #  ");
    assert(disk()==values && input()->Text().empty());
    {
        FileMutex hold(dir/"sunpack_config.json");
        add(L"first"); add(L"second");
        click(app,inputId.c_str()); assert(ui_debug_type_text(app.window(),L"still unsubmitted")==0);
    }
    finish_input(app); values.push_back("first"); values.push_back("second");
    assert(disk()==values && input()->Text()==L"still unsubmitted");
    window->ScrollWithMeasureContext(scroll(),0); ui_window_relayout(app.window());
    // Remove just the first empty-string tag through its actual close affordance.
    cloud=window->Root()->FindById("tags-"+pointer);
    auto label=wide(state(app.page(),"texts")["emptyEntry"].get<std::string>());
    float x=cloud->rect.left+window->GetRenderer().MeasureTextWidth(label,13)+25,y=cloud->rect.top+13;
    assert(ui_debug_mouse_down(app.window(),x,y)==0); assert(ui_debug_mouse_up(app.window(),x,y)==0);
    finish_input(app); values.erase(values.begin());
    assert(disk()==values && input()->Text()==L"still unsubmitted");
    screenshot(app,L"tag-config-inline.png");
    // Conflict must preserve our submitted collection and keep the external file.
    click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
    click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
    search_setting(app,pointer);
    {
        FileMutex hold(dir/"sunpack_config.json");
        // Capture the local baseline before publishing the external version.
        // Otherwise the file notification can win during add()'s message pump
        // and turn this intended conflict into a successful, rebased save.
        add(L"local");
        pump_diagnostic(app,[&]{
            auto pending=state(app.page(),"pendingFields");
            return std::find(pending.begin(),pending.end(),pointer)!=pending.end() &&
                state(app.page(),"saving").get<bool>();
        },"TAG local save queued");
        config=read_json(dir/"sunpack_config.json");config[Json::json_pointer(pointer)]=Json::array({"external"});
        atomic_write(dir/"sunpack_config.json",config.dump());
    }
    pump_diagnostic(app,[&]{return state(app.page(),"saveErrors").contains(pointer)&&!state(app.page(),"saving").get<bool>();},"TAG external conflict");
    values.push_back("local");
    assert(disk()==Json::array({"external"}) && parse_json(state(app.page(),"drafts")[pointer]["text"])==values);
    pump_diagnostic(app,[&]{return current()["items"]==Json::array({"external"});},"TAG external reload");
    // One explicit follow-up write rebases against the newest snapshot.
    add(L"retry"); finish_input(app);values.push_back("retry");assert(disk()==values);
    search_config(app,L"");
}
void resize_tasks(Application& app) {
    settle_motion(app);
    std::vector<double> layouts;
    ui_trace_set_sink([](const UiTraceEvent* event,void* data) {
        if(std::strcmp(event->name,"layout_root_duration")) return;
        for(uint32_t i=0;i<event->field_count;++i)
            if(!std::strcmp(event->fields[i].key,"duration_ms"))
                static_cast<std::vector<double>*>(data)->push_back(event->fields[i].f64);
    },&layouts);
    for(int width:{1110,1080,1040,1000,960,920,880,850,880,920,960,1000,1040,1080,1120})
        ui_window_set_size(app.window(),width,720);
    ui_trace_set_sink(nullptr,nullptr);
    if(!layouts.empty()) {
        std::sort(layouts.begin(),layouts.end());
        std::cerr<<"Virtual task resize layout: median="<<layouts[layouts.size()/2]<<"ms; max="<<layouts.back()<<"ms\n";
    }
    button_texts(app);
    screenshot(app,L"tasks-many.png");
    auto theme=ui_widget_find_by_id(ui_page_root(app.page()),"themeSelector"); assert(theme);
    auto choice=state(app.page(),"themeChoice").get<int>();
    assert(ui_debug_combo_select(app.window(),theme,1)==0);
    screenshot(app,L"tasks-many-light.png");
    assert(ui_debug_combo_select(app.window(),theme,2)==0);
    screenshot(app,L"tasks-many-dark.png");
    assert(ui_debug_combo_select(app.window(),theme,choice)==0);
    // Application owns the selector handle, as with the existing theme checks.
}
void drag_after_wheel(Application& app) {
    // Keep a full task list mounted behind the configuration page. Its stale
    // scrollbar overlaps the visible page, but must never receive pointer input.
    ui_window_set_size(app.window(),850,560);
    click(app,"tabConfig");
    pump_diagnostic(app,[&]{return state(app.page(),"tab")=="config";},"Scrollbar test: navigate to settings");
    settle_motion(app);
    auto root=ui::GetContext().GetWindow(app.window())->Root();
    auto* active=dynamic_cast<ui::ScrollViewWidget*>(root->FindById("configListScroll"));
    auto* hidden=dynamic_cast<ui::ScrollViewWidget*>(root->FindById("taskListScroll"));
    assert(active && hidden && active->NeedsScrollbar() && hidden->NeedsScrollbar());
    auto scroll=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll"); assert(scroll);
    const float hidden_y=hidden->ScrollY();
    auto* window=ui::GetContext().GetWindow(app.window());
    const auto hwnd=static_cast<HWND>(ui_window_hwnd(app.window()));
    const float dpi=GetDpiForWindow(hwnd)/96.0f;
    auto move=[&](float x,float y) {
        SendMessageW(hwnd,WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(int(std::lround(x*dpi)),int(std::lround(y*dpi))));
    };
    auto wheel=[&](short delta) {
        const auto bounds=active->rect;
        POINT pt{int((bounds.left+20)*dpi),int((bounds.top+20)*dpi)};
        ClientToScreen(hwnd,&pt);
        SendMessageW(hwnd,WM_MOUSEWHEEL,MAKEWPARAM(0,delta),MAKELPARAM(pt.x,pt.y));
    };
    {
        // Real wheel motion must advance and stop without a timer or global
        // layout; programmatic virtual-tail checks cannot cover its scheduler.
        AnimationFrames animation;
        assert(ui_debug_wheel(app.window(),scroll,-360)==0);
        pump([&]{return !active->ScrollAnimating() && (!animation.started || animation.stopped);},"Smooth wheel completion",false);
        if(!(active->ScrollY()>0 && hidden->ScrollY()==hidden_y && !animation.layout))
            std::cerr<<"Wheel: active="<<active->ScrollY()<<" hidden="<<hidden->ScrollY()<<" beforeHidden="<<hidden_y<<" layout="<<animation.layout<<" frames="<<animation.frames<<'\n';
        assert(active->ScrollY()>0 && hidden->ScrollY()==hidden_y && !animation.layout);
    }
    {
        // Multiple physical wheel packets before presentation must coalesce;
        // neither a view mutation nor synchronous rendering belongs in input.
        AnimationFrames animation;
        const float before=active->ScrollY();
        for(int delta:{-30,-30,-30,-30}) wheel(short(delta));
        assert(active->ScrollY()==before && animation.submitted==0);
        pump([&]{return !active->ScrollAnimating() && animation.finished;},"Coalesced wheel",false);
        assert(active->ScrollY()>before && hidden->ScrollY()==hidden_y);
        // One submitted display list is enough for each paced animation
        // frame; queued WM_PAINTs must not create superseded jobs.
        assert(animation.submitted<=animation.frames+1);
    }
    for(int delta:{-120,120,-120,120}) {
        const float before_wheel=active->ScrollY();
        assert(ui_debug_wheel(app.window(),scroll,delta)==0);
        pump([&]{return std::abs(active->ScrollY()-before_wheel)>0.1f;},"Wheel before thumb drag");
        // No relayout between wheel and press: that can hide routing failures.
        const auto bounds=active->rect;
        float height=bounds.bottom-bounds.top;
        const auto content=active->Children().front()->rect;
        float extent=content.bottom-content.top;
        float thumb=std::max(20.0f,height*height/extent);
        float x=bounds.right-4;
        float y=bounds.top+active->ScrollY()/(extent-height)*(height-thumb)+thumb/2;
        float dy=delta<0?12.0f:-12.0f;
        assert(ui_debug_mouse_move(app.window(),x,y)==0);
        // Hover may queue an in-flight wheel frame. Press the thumb at the
        // latest visual position, without a forced layout or synchronous paint.
        y=bounds.top+active->ScrollY()/(extent-height)*(height-thumb)+thumb/2;
        float from=active->ScrollY();
        assert(ui_debug_mouse_down(app.window(),x,y)==0);
        assert(GetCapture()==static_cast<HWND>(ui_window_hwnd(app.window())));
        assert(std::abs(active->ScrollY()-from)<0.1f);
        {
            AnimationFrames animation;
            // A burst ending at the original pointer position must not walk
            // through intermediate ranges or create frames for every packet.
            for(int i=0;i<16;++i) move(x,y+dy*(i%2?1:3));
            move(x,y);
            assert(active->ScrollY()==from && animation.submitted==0 && animation.rootLayouts==0);
            pump([&]{return !active->ScrollAnimating() && animation.finished;},"Coalesced thumb packets",false);
            // Physical pointer positions have pixel precision at fractional DPI.
            const float tolerance=(extent-height)/(height-thumb)/dpi+0.2f;
            assert(std::abs(active->ScrollY()-from)<=tolerance);
            from=active->ScrollY();
            move(x,y+dy);
            // A watcher/save snapshot may commit while pointer input is queued.
            // Its visual transaction must not strand the pending scroll frame.
            auto fields=state(app.page(),"fields").dump();
            ui_window_begin_canvas_visual_transaction(app.window());
            assert(ui_page_set_json(app.page(),"fields",fields.c_str())==0);
            window->Invalidate();
            ui_window_end_canvas_visual_transaction(app.window());
            try { pump([&]{return !active->ScrollAnimating() && active->ScrollY()!=from;},"Thumb presentation",false); }
            catch(...) {
                std::cerr<<"Thumb diagnostic: from="<<from<<" current="<<active->ScrollY()<<" x="<<x<<" y="<<y<<" dy="<<dy
                    <<" extent="<<extent<<" capture="<<(GetCapture()==hwnd)<<" frames="<<animation.frames
                    <<" submitted="<<animation.submitted<<" stopped="<<animation.stopped<<" finished="<<animation.finished
                    <<" tree="<<rendered_widget(app,"configListScroll")<<'\n';
                throw;
            }
        }
        assert(ui_debug_mouse_up(app.window(),x,y+dy)==0);
        assert(!active->ScrollAnimating());
        if((active->ScrollY()-from)*dy<=0 || hidden->ScrollY()!=hidden_y)
            throw std::runtime_error("Scrollbar drag after wheel was lost or sent to the hidden task page");
        assert(GetCapture()!=static_cast<HWND>(ui_window_hwnd(app.window())));
        float released=active->ScrollY();
        assert(ui_debug_mouse_move(app.window(),x,y+dy*2)==0);
        assert(active->ScrollY()==released && hidden->ScrollY()==hidden_y);
    }
    window->ScrollWithMeasureContext(active,0);
    window->InvalidateNow(); settle_motion(app);
    UpdateWindow(hwnd);
    {
        AnimationFrames animation;
        // The debug wheel helper unconditionally invalidates the window. Use
        // real input here to observe the production no-op redraw behavior.
        for(int i=0;i<20;++i) wheel(120);
        assert(!active->ScrollAnimating() && active->ScrollY()==0 && animation.submitted==0);
        assert(!GetUpdateRect(hwnd,nullptr,FALSE));
        // Ignoring the outward impulse must not strand the next inward one.
        wheel(-120);
        pump([&]{return !active->ScrollAnimating() && active->ScrollY()>0;},"Reverse at scroll boundary",false);
    }
    ui_widget_destroy(scroll);
    click(app,"tabTasks"); pump_diagnostic(app,[&]{return state(app.page(),"tab")=="tasks";},"Scrollbar test: navigate to tasks");
    settle_motion(app);
    ui_window_set_size(app.window(),1120,720);
}
void scalar_reactivity_noop() {
    ui::uix::ScriptRuntime runtime;
    auto* ctx=runtime.ctx();
    JSValue target=JS_NewObject(ctx);
    JS_SetPropertyStr(ctx,target,"label",JS_NewString(ctx,"idle"));
    JSValue state=runtime.MakeReactive(target);
    unsigned evaluations=0;
    runtime.WatchEffect([&] {
        ++evaluations;
        JSValue value=JS_GetPropertyStr(ctx,state,"label");
        JS_FreeValue(ctx,value);
    });
    assert(evaluations==1);
    assert(JS_SetPropertyStr(ctx,state,"label",JS_NewString(ctx,"idle"))==1);
    assert(evaluations==1); // Identical string content must not invalidate.
    assert(JS_SetPropertyStr(ctx,state,"label",JS_NewString(ctx,"active"))==1);
    assert(evaluations==2);
    assert(JS_SetPropertyStr(ctx,state,"label",JS_NewString(ctx,"active"))==1);
    assert(evaluations==2);
    JS_FreeValue(ctx,state);
    JS_FreeValue(ctx,target);
}
void bound_style_updates() {
    // Task cards keep their ID. They cannot detect stale descendant selectors
    // when an ID changes while the bound class stays equal. This one in-memory
    // page covers that independent behavior without another window or waits.
    auto page=ui_page_load_string(R"(
        <script>export default {data(){return {item:{id:'before',tone:'good',text:'same'}};}};</script>
        <template><div :id="item.id" :class="item.tone"><label id="sample">{{ item.text }}</label></div></template>
        <style>.good label {color:#00ff00;} #after label {background-color:#0000ff;} .bad label {color:#ff0000;}</style>
    )"); assert(page);
    auto handle=ui_page_root(page);
    auto root=ui::GetContext().handles.Lookup(handle); assert(root);
    auto* label=dynamic_cast<ui::LabelWidget*>(root->FindById("sample")); assert(label);
    assert(label->css.hasFg && label->css.fg.g==1 && label->Text()==L"same");
    assert(ui_page_set_json(page,"item",R"({"id":"after","tone":"good","text":"same"})")==0);
    assert(label->bgColor.b==1 && label->bgColor.a==1);
    assert(ui_page_set_json(page,"item",R"({"id":"after","tone":"bad","text":"changed"})")==0);
    assert(label->css.hasFg && label->css.fg.r==1 && label->Text()==L"changed");
    ui_widget_destroy(handle);
    ui_page_destroy(page);
}
}
int wmain(int argc,wchar_t** argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    if(argc>1 && std::wstring(argv[1])==L"--fake-cli") {
        Json args=Json::array(); for(int i=3;i<argc;++i) args.push_back(utf8(argv[i])); atomic_write(fs::current_path()/"cli-arguments.json",args.dump());
        Handle gate(OpenEventW(SYNCHRONIZE,FALSE,argv[2])); assert(gate.value);
        assert(WaitForSingleObject(gate,10000)==WAIT_OBJECT_0);
        std::cout<<args.dump(); return 0;
    }
    const bool rangesOnly=argc==2 && std::wstring(argv[1])==L"--ranges";
    const bool acceptance=argc==2 && std::wstring(argv[1])==L"--acceptance";
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    auto dir=fs::temp_directory_path()/(L"sunpack-gui-ui-"+std::to_wstring(GetCurrentProcessId())); fs::create_directory(dir);
    auto gate_name=L"Local\\SunPack.GUI.TestCommand."+std::to_wstring(GetCurrentProcessId());
    Handle gate(CreateEventW(nullptr,TRUE,TRUE,gate_name.c_str()));
    try {
        scalar_reactivity_noop();
        rendering_contracts();
        atomic_write(dir/"sunpack_config.json",R"({"cli":{"language":"zh"},"runtime":{"process_mode":"normal"},"recursive_extract":"*","watch":{"state_dir":".sunpack_watch","out_dir":".","toast_enabled":true},"unknown":9007199254740993})");
        if(rangesOnly || acceptance) {
            auto config=parse_json(kUiDefaultsJson); config["watch"]["state_dir"]=".sunpack_watch";
            atomic_write(dir/"sunpack_config.json",config.dump());
        }
        atomic_write(dir/"builtin_passwords.json",R"({"passwords":[{"value":"  #中文  "}],"clipboard_history":["history"]})");
        atomic_write(dir/"sunpack_watch_roots.txt",utf8(dir.wstring())+"\n");
        atomic_write(dir/".sunpack_watch"/"events.jsonl",published_events(Json({{"event","done"},{"path",utf8((dir/"carrier.001").wstring())}}).dump()+"\n"));
        {
            Options options; options.data_dir=dir; options.allow_cli=true;
            options.cli={executable_path(),dir,{L"--fake-cli",gate_name}};
            Application app(options); std::cerr<<"Opening UI\n"; app.open(); std::cerr<<"UI opened\n";
            // The old show-before-load path flashed an incomplete first page.
            assert(!IsWindowVisible(static_cast<HWND>(ui_window_hwnd(app.window()))));
            pump_diagnostic(app,[&]{return state(app.page(),"ready")==true;},"Initial snapshot");
            assert(IsWindowVisible(static_cast<HWND>(ui_window_hwnd(app.window()))));
            assert(state(app.page(),"errors").empty() && state(app.page(),"actionError")=="");
            screenshot(app,L"startup.png");
                page_motion(app);
            if(rangesOnly || acceptance) {
                pump_diagnostic(app,[&]{return state(app.page(),"fields").size()>100;},"Configuration fields loaded");
                click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
                if(acceptance) {
                    settle_motion(app);
                    auto* native=ui::GetContext().GetWindow(app.window());
                    auto heading=native->Root()->FindById("page-config")->Children().front()->rect;
                    native->SimMouseMove(heading.left+10,heading.top+10);
                    pump([&]{return !GetUpdateRect(native->Handle(),nullptr,FALSE);});
                    // Pumping may deliver WM_MOUSELEAVE if the physical cursor
                    // is outside this test window. Establish hover again, finish
                    // that legitimate paint, then observe only unchanged packets.
                    native->SimMouseMove(heading.left+10,heading.top+10);
                    UpdateWindow(native->Handle());
                    assert(!GetUpdateRect(native->Handle(),nullptr,FALSE));
                    {
                        AnimationFrames unchanged;
                        for(int packet=0;packet<10;++packet)
                            native->SimMouseMove(heading.left+10+float(packet%2),heading.top+10);
                        assert(!GetUpdateRect(native->Handle(),nullptr,FALSE));
                        assert(unchanged.submitted==0);
                    }
                localized_config_search(app);
                inline_cell_caret(app);
                    virtual_tail(app,"configItems","configListScroll",state(app.page(),"matchingBlocks").size());
                scrolled_config_edits(app);
                tag_config(app,dir);
                resize_tasks(app);
                    popup_motion(app,"themeSelector");
                }
                range_config(app,dir);
                // Same range scenario as the full suite, with the real owner
                // close path and none of the unrelated animation timing checks.
                std::string timeId;
                for(auto& f:state(app.page(),"fields")) if(f["module"]=="mtime_range" && f["type"]=="object") timeId=f["id"];
                click(app,("range-lower-pick-"+timeId).c_str()); ui_debug_pump();
                assert(date_popup(app));
                PostMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_CLOSE,0,0);
                pump([&]{return !IsWindow(static_cast<HWND>(ui_window_hwnd(app.window())));});
            } else {
            bound_style_updates();
            // Direct QuickJS JSON parsing must reject malformed input without
            // replacing an existing reactive list.
            auto initial_tasks=state(app.page(),"tasks");
            assert(ui_page_set_json(app.page(),"tasks","{invalid")!=0);
            assert(state(app.page(),"tasks")==initial_tasks);
            assert(ui_page_set_json(app.page(),"tasks",initial_tasks.dump().c_str())==0);
            pump([&]{return state(app.page(),"runtime")["known"]==true;});
            {
                // One lifecycle scenario catches orphaned property motion after
                // prepared presents and hide/restore. Ordinary popup completion
                // cannot detect these paths. It adds only three short animations
                // to this existing real-window fixture, with no FPS threshold.
                settle_motion(app);
                auto* window=ui::GetContext().GetWindow(app.window());
                auto* target=window->Root()->FindById("page-tasks"); assert(target);
                bool complete=false;
                auto start=[&] {
                    complete=false;
                    target->opacity=0.6f;
                    window->AnimateProperty(target,ui::AnimProperty::Opacity,0.6f,1,120,
                        ui::EasingFunction::Linear,[&]{complete=true;});
                };
                start();
                pump([&]{return complete;},"Render-paced property animation",false);
                int x=0,y=0,width=0,height=0;
                window->GetWindowRectScreen(&x,&y,&width,&height);
                start();
                window->BeginCanvasVisualTransaction();
                window->SetWindowRect(x,y,width-1,height);
                window->EndCanvasVisualTransaction();
                pump([&]{return complete;},"Motion after prepared present",false);
                window->SetWindowRect(x,y,width,height);
                start(); window->Hide(); window->ShowImmediate(false);
                pump([&]{return complete;},"Motion after hide and restore",false);
                assert(target->opacity==1);
            }
            BOOL disabled=TRUE;
            if(SUCCEEDED(DwmGetWindowAttribute(static_cast<HWND>(ui_window_hwnd(app.window())),DWMWA_TRANSITIONS_FORCEDISABLED,&disabled,sizeof(disabled)))) assert(!disabled);
            std::cerr<<"Initial files loaded\n";
            assert(state(app.page(),"tasks")["total"]==1);
            std::string many;
            const char* phases[]={"processing_started","failed_terminal","suspended_missing_volume","done"};
            for(int i=0;i<virtualTaskCount;++i) many+=Json({{"event",phases[i%4]},{"path",utf8((dir/"history"/("task-"+std::to_string(i)+".001")).wstring())},{"time","2026-10-19T09:15:42.731112+00:00"},{"output_dirs",{utf8(dir.wstring())}}}).dump()+"\n";
            atomic_write(dir/".sunpack_watch"/"events.jsonl",published_events(many));
            pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==virtualTaskCount;},"Load virtual tasks");
            virtual_tail(app,"taskItems","taskListScroll",virtualTaskCount);
            auto tail=state(app.page(),"tasks")["rows"][virtualTaskCount-1];
            tail["sortTimestamp"]=1e12;
            auto delta_json=Json{{"changes",Json::array({Json{{"id",tail["id"]},{"row",tail}}})},{"malformed",0}}.dump();
            assert(ui_page_call_json(app.page(),"applyTaskDelta",delta_json.c_str())==0);
            assert(state(app.page(),"tasks")["rows"][0]["id"]==tail["id"]);
            // Reordering alone misses stale ID indexes, removals and coalesced
            // changes. Exercise those together in the existing mounted list;
            // compare against an independent full snapshot after each batch.
            auto saved_tasks=state(app.page(),"tasks");
            auto expected=saved_tasks;
            auto apply_changes=[&](const Json& changes) {
                std::map<std::string,Json> by_id;
                for(auto& row:expected["rows"]) by_id[row["id"].get<std::string>()]=row;
                for(auto& change:changes) {
                    auto id=change["id"].get<std::string>();
                    if(change.contains("row")) by_id[id]=change["row"]; else by_id.erase(id);
                }
                std::vector<Json> rows;
                for(auto& pair:by_id) rows.push_back(pair.second);
                std::sort(rows.begin(),rows.end(),[](const Json& a,const Json& b) {
                    if(a["sortTimestamp"]!=b["sortTimestamp"]) return a["sortTimestamp"]>b["sortTimestamp"];
                    return a["sortSequence"]>b["sortSequence"];
                });
                expected={{"rows",rows},{"total",rows.size()},{"malformed",7}};
                auto patch=Json{{"changes",changes},{"malformed",7}}.dump();
                assert(ui_page_call_json(app.page(),"applyTaskDelta",patch.c_str())==0);
                auto actual=state(app.page(),"tasks");
                if(!Json::diff(expected,actual).empty()) {
                    std::cerr<<"Task delta mismatch ("<<changes.size()<<" changes): "<<Json::diff(expected,actual).dump()<<'\n';
                }
                assert(Json::diff(expected,actual).empty());
            };
            apply_changes(Json::array()); // malformed count with no changed rows
            // Retained item bindings must still observe global text changes.
            auto saved_texts=state(app.page(),"texts"),changed_texts=saved_texts;
            changed_texts["taskFolder"]="folder-after-delta: ";
            assert(ui_page_set_json(app.page(),"texts",changed_texts.dump().c_str())==0);
            assert(rendered_widget(app,"taskRoot-"+tail["id"].get<std::string>())["text"]==
                "folder-after-delta: "+tail["directory"].get<std::string>());
            assert(ui_page_set_json(app.page(),"texts",saved_texts.dump().c_str())==0);
            auto moved=tail; moved["sortTimestamp"]=2e12; moved["statusText"]="updated";
            apply_changes(Json::array({Json{{"id",moved["id"]},{"row",moved}}}));
            assert(rendered_widget(app,"task-"+moved["id"].get<std::string>()).dump().find("updated")!=std::string::npos);
            auto newcomer=moved; newcomer["id"]="delta-new"; newcomer["sortTimestamp"]=3e12;
            apply_changes(Json::array({Json{{"id",moved["id"]}},Json{{"id",newcomer["id"]},{"row",newcomer}},
                Json{{"id",newcomer["id"]}},Json{{"id",moved["id"]},{"row",tail}}}));
            Json bulk=Json::array();
            for(size_t i=0;i<70;++i) {
                auto row=expected["rows"][i]; row["sortTimestamp"]=4e12+double(i);
                bulk.push_back(Json{{"id",row["id"]},{"row",row}});
            }
            bulk.push_back(Json{{"id",tail["id"]}}); apply_changes(bulk);
            apply_changes(Json::array({Json{{"id",newcomer["id"]},{"row",newcomer}}}));
            assert(ui_page_set_json(app.page(),"tasks",saved_tasks.dump().c_str())==0);
            expected=saved_tasks;
            apply_changes(Json::array({Json{{"id",tail["id"]},{"row",moved}}}));
            assert(ui_page_set_json(app.page(),"tasks",saved_tasks.dump().c_str())==0);
            virtual_tail(app,"taskItems","taskListScroll",virtualTaskCount);
            auto task=state(app.page(),"tasks")["rows"][0];
            assert(task["time"].get<std::string>().size()==19);
                resize_tasks(app);
            auto task_id=task["id"].get<std::string>();
            auto card_bounds=rect(app,"task-"+task_id), name_bounds=rect(app,"taskName-"+task_id);
            assert(card_bounds.bottom-card_bounds.top<=80);
            assert(name_bounds.right-name_bounds.left<(card_bounds.right-card_bounds.left)/2);
            assert(rendered_widget(app,"taskRoot-"+task_id)["text"]=="监控目录："+utf8((dir/"history").wstring()));
            for(auto prefix:{"task-","taskRoot-"}) {
                click(app,(prefix+task["id"].get<std::string>()).c_str());
                assert(state(app.page(),"requests").empty());
            }
            assert(ui_debug_mouse_move(app.window(),(name_bounds.left+name_bounds.right)/2,(name_bounds.top+name_bounds.bottom)/2)==0);
            auto* task_name=ui::GetContext().GetWindow(app.window())->Root()->FindById(("taskName-"+task_id).c_str());
            assert(task_name && task_name->css.hasFg && task_name->css.fg.b>task_name->css.fg.r);
            screenshot(app,L"task-name-hover.png");
            click(app,("taskName-"+task_id).c_str());
            assert(state(app.page(),"requests")==Json::array({Json{{"op","openTask"},{"payload",{{"task",task}}}}}));
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"taskDetails"));
            // Consume the real command before dispatch; never open Explorer.
            ui_page_set_json(app.page(),"requests","[]");
            ui_debug_pump();
            drag_after_wheel(app);
            atomic_write(dir/".sunpack_watch"/"events.jsonl",published_events(Json({{"event","done"},{"path",utf8((dir/"carrier.001").wstring())}}).dump()+"\n"));
            pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==1;},"Log replacement");
            assert(!state(app.page(),"texts").contains("otherTasks"));
            assert(rect(app,"allRoots").top>=rect(app,"directorySearch").bottom);
            click(app,"taskSearch"); ui_debug_type_text(app.window(),L"missing");
            try { pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==0;},"Task search filter"); }
            catch(...) { std::cerr<<"Search tasks: "<<state(app.page(),"taskQuery")<<" requests="<<state(app.page(),"requests")<<" error="<<ui_page_last_error(app.page())<<"\n"; screenshot(app,L"search-failed.png"); throw; }
            for(int i=0;i<7;++i) ui_debug_type_char(app.window(),8);
            try { pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==1;},"Clear task search"); }
            catch(...) { std::cerr<<"Clear tasks: "<<state(app.page(),"taskQuery")<<"\n"; throw; }
            auto status=ui_widget_find_by_id(ui_page_root(app.page()),"taskStatus"); assert(status);
            assert(ui_debug_combo_select(app.window(),status,1)==0);
            pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==0;},"Task status filter");
            assert(ui_debug_combo_select(app.window(),status,0)==0);
            pump_diagnostic(app,[&]{return state(app.page(),"tasks")["total"]==1;},"Clear status filter");
            // The status selector handle belongs to Application, like themeSelector.
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"filterTasks"));
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"saveAll"));
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"discardAll"));
            auto error=ui_page_last_error(app.page()); if(error && *error) std::cerr<<error<<"\n";
            screenshot(app,L"tasks.png");
            auto navigation_bounds=rect(app,"navigation"), monitor_bounds=rect(app,"monitorControls"), nav_bounds=rect(app,"navItems");
            auto directory_bounds=rect(app,"directoryPane"), task_bounds=rect(app,"page-tasks");
            auto identity_bounds=rect(app,"identity"), status_bounds=rect(app,"runtimeStatus");
            assert(status_bounds.left>=rect(app,"brand").right && status_bounds.right<=navigation_bounds.right);
            assert(status_bounds.top>=identity_bounds.top && status_bounds.bottom<=identity_bounds.bottom);
            assert(monitor_bounds.bottom<=nav_bounds.top && nav_bounds.bottom<=directory_bounds.top);
            assert(directory_bounds.left>=navigation_bounds.left && directory_bounds.right<=navigation_bounds.right);
            assert(task_bounds.left>=navigation_bounds.right);
            click(app,"watchStart");
            pump_diagnostic(app,[&]{return state(app.page(),"lastCommand").value("action",std::string())=="start";},"Watch start command");
            assert(read_json(dir/"cli-arguments.json")==Json::array({"watch","start"}));
            assert(state(app.page(),"actionError")=="");
            pump_diagnostic(app,[&]{return state(app.page(),"runtime")["known"]==true;},"Runtime status");
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"refresh"));
            auto stable_commands=[&](const char* id,const std::string& action,const Json& args) {
                auto tab=state(app.page(),"tab").get<std::string>();
                auto page=ui_widget_find_by_id(ui_page_root(app.page()),("page-"+tab).c_str());
                auto rect=ui_widget_get_rect(page);
                fs::remove(dir/"cli-arguments.json");
                ResetEvent(gate);
                click(app,id);
                // The dispatch signal is mounted before its posted message is
                // handled. Force this intermediate layout to catch page jumps.
                ui_window_relayout(app.window());
                auto during=ui_widget_get_rect(page);
                assert(during.left==rect.left && during.top==rect.top && during.right==rect.right && during.bottom==rect.bottom);
                pump_diagnostic(app,[&]{return state(app.page(),"busy")==true && read_json(dir/"cli-arguments.json")==args;},"CLI request dispatch");
                if(ui_widget_get_opacity(page)<0.999f || ui_debug_widget_is_visible(page)!=1) {
                    std::cerr<<"Command visibility: "<<id<<" opacity="<<ui_widget_get_opacity(page)<<" visible="<<ui_debug_widget_is_visible(page)<<"\n";
                    screenshot(app,L"command-visibility.png");
                    throw std::runtime_error("Command changed page visibility");
                }
                SetEvent(gate);
                pump_diagnostic(app,[&]{return state(app.page(),"lastCommand").value("action",std::string())==action && state(app.page(),"busy")==false;},"CLI command completion");
                assert(read_json(dir/"cli-arguments.json")==args);
                assert(state(app.page(),"actionError")=="");
                auto after=ui_widget_get_rect(page);
                assert(after.left==rect.left && after.top==rect.top && after.right==rect.right && after.bottom==rect.bottom);
                assert(ui_widget_get_opacity(page)>=0.999f && ui_debug_widget_is_visible(page)==1);
                ui_widget_destroy(page);
            };
            click(app,"tabPasswords"); pump_diagnostic(app,[&]{return state(app.page(),"tab")=="passwords";},"Navigate to passwords");
            settle_motion(app);
            assert(rect(app,"monitorControls").top==monitor_bounds.top);
            stable_commands("watchStop","stop",Json::array({"watch","stop"}));
            click(app,"tabConfig"); pump_diagnostic(app,[&]{return state(app.page(),"tab")=="config";},"Navigate to settings");
            settle_motion(app);
            assert(rect(app,"monitorControls").top==monitor_bounds.top);
            stable_commands("watchStart","start",Json::array({"watch","start"}));
            click(app,"tabConfig"); pump_diagnostic(app,[&]{return state(app.page(),"tab")=="config";},"Navigate to settings");
            auto content=ui_widget_find_by_id(ui_page_root(app.page()),"page-config");
            assert(content && ui_widget_get_opacity(content)>0); // No blank incoming frame.
            pump_diagnostic(app,[&]{return ui_widget_get_opacity(content)>=0.999f;},"Settings page opacity"); ui_widget_destroy(content);
            {
                // Navigation must finish at the latest selection even when
                // interrupted; the indicator travels rather than blinking.
                AnimationFrames animation;
                click(app,"tabPasswords"); click(app,"tabTasks"); click(app,"tabConfig");
                // The last requested tab equals the starting tab: wait for
                // queued navigation to dispatch before checking its animation.
                pump_diagnostic(app,[&]{return state(app.page(),"tab")=="config" && state(app.page(),"requests").empty() && state(app.page(),"dispatch")==false;},"Rapid navigation dispatch");
                // An accessibility/CI environment may disable Windows client-area
                // animations. No motion lifecycle event is emitted unless one starts.
                // Visual settling and the indicator target are verified either way.
                settle_motion(app);
                BOOL animations=TRUE;
                SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0);
                if(animations && animation.started) {
                    try { pump_diagnostic(app,[&]{return animation.stopped;},"Rapid navigation motion"); }
                    catch(...) {
                        std::cerr<<"Rapid navigation animation: enabled="<<animations
                                 <<" started="<<animation.started<<" stopped="<<animation.stopped
                                 <<" frames="<<animation.frames<<" finished="<<animation.finished<<'\n';
                        throw;
                    }
                }
                auto* indicator=ui::GetContext().GetWindow(app.window())->Root()->FindById("navIndicator");
                assert(indicator->animationY>0);
            }
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"watchReload"));
            auto startup_enabled=state(app.page(),"startup")["enabled"].get<bool>();
            stable_commands("startupToggle",startup_enabled?"startupDisable":"startupEnable",Json::array({"watch","startup",startup_enabled?"disable":"enable"}));
            auto alternate=Json{{"enabled",!startup_enabled},{"command",""}}.dump();
            ui_page_set_json(app.page(),"startup",alternate.c_str());
            stable_commands("startupToggle",startup_enabled?"startupEnable":"startupDisable",Json::array({"watch","startup",startup_enabled?"enable":"disable"}));
            auto original_startup=Json{{"enabled",startup_enabled},{"command",""}}.dump();
            ui_page_set_json(app.page(),"startup",original_startup.c_str());
            std::cerr<<"Configuration view mounted\n";
            auto selector_host=ui_widget_find_by_id(ui_page_root(app.page()),"choice-/runtime/process_mode");
            char* selector_tree=ui_debug_dump_widget(selector_host); assert(selector_tree);
            auto selector_info=parse_json(selector_tree); ui_debug_free(selector_tree); ui_widget_destroy(selector_host);
            assert(selector_info["children"].size()==1);
            screenshot(app,L"configuration.png");
            auto system_appearance=state(app.page(),"appearance");
            auto theme=ui_widget_find_by_id(ui_page_root(app.page()),"themeSelector"); assert(theme);
            assert(ui_debug_combo_select(app.window(),theme,1)==0);
            pump([&]{return state(app.page(),"appearance")=="light";});
            screenshot(app,L"configuration-light.png");
            assert(ui_debug_combo_select(app.window(),theme,2)==0);
            pump([&]{return state(app.page(),"appearance")=="dark";});
            assert(ui_debug_combo_select(app.window(),theme,0)==0);
            assert(state(app.page(),"appearance")==system_appearance);
            popup_motion(app,"themeSelector");
            {
                auto* root=ui::GetContext().GetWindow(app.window())->Root().get();
                auto* combo=dynamic_cast<ui::ComboBoxWidget*>(root->FindById("themeSelector"));
                auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(root->FindById("configListScroll"));
                assert(combo && scroll);
                BOOL animations=TRUE; SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0);
                for(bool fading:{false,true}) {
                    click(app,"themeSelector");
                    pump([&]{return !combo->PopupAnimating();},"Popup before wheel");
                    auto selected=combo->SelectedIndex();
                    auto drop=combo->DropdownRect();
                    float before=scroll->ScrollY();
                    // The overlay consumes its own wheel, without scrolling
                    // the settings behind it or changing the selected value.
                    assert(ui_debug_wheel_at(app.window(),(drop.left+drop.right)/2,(drop.top+drop.bottom)/2,-120)==0);
                    assert(combo->IsOpen() && scroll->ScrollY()==before && combo->SelectedIndex()==selected);
                    AnimationFrames exit;
                    if(fading) assert(ui_debug_key(app.window(),VK_ESCAPE)==0);
                    assert(ui_debug_wheel_at(app.window(),scroll->rect.left+12,scroll->rect.top+12,-120)==0);
                    assert(!combo->IsOpen());
                    if(animations && combo->PopupAnimating()) {
                        assert(combo->PopupOpacity()>0);
                        auto frozen=combo->DropdownRect();
                        assert(frozen.left==drop.left && frozen.top==drop.top && frozen.right==drop.right && frozen.bottom==drop.bottom);
                    }
                    pump([&]{return !combo->PopupAnimating() && !scroll->ScrollAnimating() && (!animations || exit.stopped);},"Popup wheel exit");
                    assert(scroll->ScrollY()>before);
                    assert(combo->PopupOpacity()==0 && combo->PopupProgress()==0 && combo->SelectedIndex()==selected);
                    ui::GetContext().GetWindow(app.window())->ScrollWithMeasureContext(scroll,0);
                }
                screenshot(app,L"dropdown-scrolled-closed.png");
            }
            ui_window_set_size(app.window(),850,560); ui_window_relayout(app.window());
            auto popup_scroll=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll"); assert(popup_scroll);
            auto viewport=rect(app,"configListScroll"), recursive=rect(app,"select-/recursive_extract");
            ui_debug_scroll_set(popup_scroll,recursive.top-viewport.bottom+18);
            popup_motion(app,"select-/recursive_extract",true);
            ui_debug_scroll_set(popup_scroll,0); ui_widget_destroy(popup_scroll);
            ui_window_set_size(app.window(),1120,720); ui_window_relayout(app.window());
            // FindById reuses Application's owned theme handle, rather than
            // adding a reference. Its owner releases it during locale changes.
            // Native enum control writes a constrained value inline.
            auto priority=ui_widget_find_by_id(ui_page_root(app.page()),"select-/runtime/process_mode"); assert(priority);
            assert(ui_debug_combo_select(app.window(),priority,2)==0);
            assert(ui_debug_combo_select(app.window(),priority,1)==0);
            assert(ui_debug_combo_select(app.window(),priority,2)==0);
            ui_widget_destroy(priority);
            finish_input(app);
            pump([&]{return read_json(dir/"sunpack_config.json")["runtime"]["process_mode"]=="high";});
            search_setting(app,"/watch/toast_enabled");
            auto toast=ui_widget_find_by_id(ui_page_root(app.page()),"toggle-/watch/toast_enabled"); assert(toast);
            assert(ui_debug_toggle_set(app.window(),toast,0)==0);
            assert(state(app.page(),"toggleDrafts").size()==1 && state(app.page(),"drafts").empty());
            assert(ui_debug_toggle_set(app.window(),toast,1)==0);
            {
                BOOL animations=TRUE;
                if(!SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0))
                    throw std::runtime_error("Cannot query Windows client-area animation setting");
                auto* native=dynamic_cast<ui::ToggleWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById("toggle-/watch/toast_enabled"));
                assert(native && native->On()); // A no-op SetOn(false) cannot start motion.
                AnimationFrames animation;
                assert(ui_debug_toggle_set(app.window(),toast,0)==0);
                native=dynamic_cast<ui::ToggleWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById("toggle-/watch/toast_enabled"));
                assert(native && !native->On());
                await_toggle_motion(app,"toggle-/watch/toast_enabled",animations!=FALSE,animation,"Toggle motion",true);
            }
            finish_input(app);
            // Auto-save can refresh the filtered field while the pointer is
            // stationary. Start the hover check from outside the control.
            assert(ui_debug_mouse_move(app.window(),0,0)==0);
            toast=ui_widget_find_by_id(ui_page_root(app.page()),"toggle-/watch/toast_enabled"); assert(toast);
            {
                AnimationFrames animation;
                auto bounds=ui_widget_get_rect(toast);
                float x=(bounds.left+bounds.right)/2,y=(bounds.top+bounds.bottom)/2;
                BOOL animations=TRUE;
                if(!SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION,0,&animations,0))
                    throw std::runtime_error("Cannot query Windows client-area animation setting");
                assert(ui_debug_mouse_move(app.window(),x,y)==0);
                await_toggle_motion(app,"toggle-/watch/toast_enabled",animations!=FALSE,animation,"Toggle hover");
                animation.finished=animation.stopped=false; animation.frames=0; animation.layout=false;
                assert(ui_debug_mouse_down(app.window(),x,y)==0);
                await_toggle_motion(app,"toggle-/watch/toast_enabled",animations!=FALSE,animation,"Toggle press");
                assert(ui_debug_mouse_up(app.window(),x,y)==0);
                assert(ui_debug_key(app.window(),VK_SPACE)==0);
                animation.finished=animation.stopped=false; animation.frames=0; animation.layout=false;
                assert(ui_debug_mouse_move(app.window(),0,0)==0);
                await_toggle_motion(app,"toggle-/watch/toast_enabled",animations!=FALSE,animation,"Toggle release");
            }
            ui_widget_destroy(toast);
            click(app,"tabTasks"); // Rapid navigation must not overwrite automatic writes.
            pump([&]{return read_json(dir/"sunpack_config.json")["watch"]["toast_enabled"]==false;},"Toggle saved after navigation");
            pump([&]{return state(app.page(),"tab")=="tasks";});
            pump([&]{return state(app.page(),"saving")==false;});
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_setting(app,"/watch/out_dir");
            ui_window_set_size(app.window(),850,560);
            auto output=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir"); assert(output);
            ui_text_input_set_text(output,L""); click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"输出目录");
            ui_widget_destroy(output);
            assert(state(app.page(),"drafts")["/watch/out_dir"]["text"]=="输出目录");
            screenshot(app,L"configuration-inline-small.png");
            {
                // Hold the real writer lock to exercise new input arriving while
                // a completed field edit is being persisted. No timing sleeps.
                FileMutex hold(dir/"sunpack_config.json");
                click(app,"configSearch"); ui_debug_pump();
                click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"后续");
            }
            try { pump([&]{return read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="输出目录" && !state(app.page(),"saving").get<bool>();},"Completed edit before continued typing"); }
            catch(...) { std::cerr<<"Automatic config: file="<<read_json(dir/"sunpack_config.json")<<" drafts="<<state(app.page(),"drafts")<<" errors="<<state(app.page(),"saveErrors")<<" ui="<<ui_page_last_error(app.page())<<"\n"; throw; }
            assert(state(app.page(),"drafts")["/watch/out_dir"]["text"]=="输出目录后续");
            finish_input(app);
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="输出目录后续");
            assert(!state(app.page(),"drafts").contains("/watch/out_dir"));
            // Keep unsaved input when an external writer changes the same field;
            // the save must report a conflict without overwriting that writer.
            output=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir");
            ui_text_input_set_text(output,L""); click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"unsaved");
            ui_widget_destroy(output);
            auto changed=read_json(dir/"sunpack_config.json"); changed["watch"]["out_dir"]="external"; atomic_write(dir/"sunpack_config.json",changed.dump());
            pump([&]{for(auto& field:state(app.page(),"fields")) if(field["id"]=="/watch/out_dir") return field["text"]=="external"; return false;});
            click(app,"configSearch"); pump([&]{return state(app.page(),"saveErrors").contains("/watch/out_dir");});
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="external");
            assert(state(app.page(),"drafts")["/watch/out_dir"]["text"]=="unsaved");
            auto conflict=state(app.page(),"saveErrors")["/watch/out_dir"];
            assert(conflict["source"]=="settingChanged");
            assert(conflict["text"]==tr("settingChanged","zh"));
            changed["cli"]["language"]="en"; atomic_write(dir/"sunpack_config.json",changed.dump());
            pump([&]{return state(app.page(),"saveErrors")["/watch/out_dir"]["text"]==tr("settingChanged","en");});
            // The translated search label no longer matches after a language
            // replacement. Locate the field using its current visible label.
            search_setting(app,"/watch/out_dir");
            screenshot(app,L"error-english.png");
            assert(rendered_widget(app,"field-/watch/out_dir").dump().find("Default output folder")!=std::string::npos);
            changed["cli"]["language"]="zh"; atomic_write(dir/"sunpack_config.json",changed.dump());
            pump([&]{return state(app.page(),"saveErrors")["/watch/out_dir"]["text"]==tr("settingChanged","zh");});
            search_setting(app,"/watch/out_dir");

            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L" corrected");
            finish_input(app);
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="unsaved corrected");
            // External language replacement updates visible and generated controls.
            auto conf=read_json(dir/"sunpack_config.json"); conf["cli"]["language"]="en"; atomic_write(dir/"sunpack_config.json",conf.dump());
            pump([&]{return state(app.page(),"language")=="en";});
            assert(state(app.page(),"texts")["config"]=="Settings");
            assert(state(app.page(),"fields")[0]["label"]=="Language");
            search_hints(app);
            search_config(app,L"");
            screenshot(app,L"configuration-english.png");
            button_texts(app);
            search_setting(app,"/cli/language");
            auto language=ui_widget_find_by_id(ui_page_root(app.page()),"select-/cli/language"); assert(language);
            assert(ui_debug_combo_select(app.window(),language,0)==0);
            ui_widget_destroy(language);
            finish_input(app);
            pump([&]{return state(app.page(),"language")=="zh";});
            search_hints(app);
            ui_window_set_size(app.window(),1120,720);
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            std::cerr<<"Password view mounted\n";
            assert(state(app.page(),"passwords")["rows"][0]["value"]=="  #中文  ");
            assert(state(app.page(),"passwordScope")=="@all");
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"globalPasswords"));
            auto add_bounds=rect(app,"newPassword"), saved_bounds=rect(app,"savedPasswords");
            assert(rect(app,"passwordSearch").right<add_bounds.left);
            assert(add_bounds.left<saved_bounds.left && add_bounds.top==saved_bounds.top);
            assert(state(app.page(),"texts")["back"]=="返回");
            click(app,"newPassword");
            auto new_id=state(app.page(),"passwordCell").get<std::string>();
            pump([&]{auto* f=ui::GetContext().GetWindow(app.window())->FocusedWidget(); return f&&f->id=="password-input-"+new_id;},"New password focus");
            auto* empty=dynamic_cast<ui::TextInputWidget*>(ui::GetContext().GetWindow(app.window())->FocusedWidget());
            assert(empty && empty->Placeholder()==L"可粘贴多行内容");
            assert(empty->focused && !ui::ShowFocusRing());
            screenshot(app,L"passwords.png");
            ui_window_set_size(app.window(),850,560);
            screenshot(app,L"password-editor-small.png");
            assert(read_json(dir/"builtin_passwords.json")["passwords"].size()==1);
            paste_password(app,L"添加的密码\r\n  #批量  \n\n添加的密码");
            finish_input(app);
            try { pump([&]{return state(app.page(),"passwords")["total"]==3;},"Pasted password batch"); }
            catch(...) {
                for(auto key:{"passwords","passwordCell","passwordDrafts","requests","saving","actionError","errors"}) std::cerr<<key<<"="<<state(app.page(),key)<<'\n';
                std::cerr<<"disk="<<read_json(dir/"builtin_passwords.json")<<'\n'; throw;
            }
            assert(state(app.page(),"passwordCell")=="");
            assert(state(app.page(),"passwordNew").empty());
            assert(state(app.page(),"passwordDrafts").empty());
            assert(read_json(dir/"builtin_passwords.json")["passwords"][2]["value"]=="  #批量  ");
            std::cerr<<"Password paste saved\n";
            auto before_blank=read_json(dir/"builtin_passwords.json");
            click(app,"newPassword"); ui_debug_pump(); click(app,"passwordSearch"); finish_input(app);
            assert(state(app.page(),"passwordNew").empty() && state(app.page(),"passwordDrafts").empty());
            assert(read_json(dir/"builtin_passwords.json")==before_blank);
            std::cerr<<"Blank password removed\n";
            // Creation actions persist immediately. Unrelated incomplete forms
            // never join another field or record's automatic write.
            auto pending_root=dir/L"pending-root", pending_second=dir/L"pending-second"; fs::create_directory(pending_root); fs::create_directory(pending_second);
            auto disk_roots=read_file(dir/"sunpack_watch_roots.txt");
            click(app,"tabRoots"); pump([&]{return state(app.page(),"tab")=="roots";});
            click(app,"addRoot");
            auto new_root_id=state(app.page(),"rootCell").get<std::string>();
            pump([&]{auto* focused=ui::GetContext().GetWindow(app.window())->FocusedWidget();return focused&&focused->id=="root-input-input-"+new_root_id;});
            paste_password(app,(pending_root.wstring()+L"\n"+pending_second.wstring()+L"\n"+pending_root.wstring()).c_str());
            finish_input(app);
            button_texts(app); screenshot(app,L"root-inline-batch-small.png");
            assert(state(app.page(),"rootCell")=="");
            assert(state(app.page(),"rootRows").size()==3 && state(app.page(),"rootDrafts").empty());
            for(auto& entry:read_roots(dir/"sunpack_watch_roots.txt").entries)
                if(entry.input==pending_root || entry.input==pending_second) assert(entry.output==utf8(entry.input.wstring()));
            assert(read_file(dir/"sunpack_watch_roots.txt")!=disk_roots);
            auto first_root_id=root_row_id(app,pending_root),second_root_id=root_row_id(app,pending_second);
            edit_root_cell(app,first_root_id,"output",L"");
            paste_password(app,L"batch-output-a\nbatch-output-b"); finish_input(app);
            for(auto& entry:read_roots(dir/"sunpack_watch_roots.txt").entries) {
                if(entry.input==pending_root) assert(entry.output=="batch-output-a");
                if(entry.input==pending_second) assert(entry.output=="batch-output-b");
            }
            {
                FileMutex hold(dir/"sunpack_watch_roots.txt",L"SunPackWatchRoots");
                edit_root_cell(app,first_root_id,"output",L"receipt");
                assert(ui_debug_key(app.window(),VK_RETURN)==0); ui_debug_pump();
                edit_root_cell(app,first_root_id,"output",L"receipt latest");
            }
            pump([&]{return !state(app.page(),"saving").get<bool>();},"Root receipt while editing");
            assert(state(app.page(),"rootDrafts")[first_root_id]["output"]=="receipt latest");
            auto root_display=rect(app,"root-output-value-"+first_root_id);
            auto root_input_bounds=rect(app,"root-output-input-"+first_root_id);
            assert(root_display.top==root_input_bounds.top && root_display.bottom==root_input_bounds.bottom);
            auto* root_editor=dynamic_cast<ui::TextInputWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById("root-output-input-"+first_root_id));
            assert(root_editor && root_editor->focused && !ui::ShowFocusRing());
            click(app,("root-output-text-"+second_root_id).c_str());
            pump([&]{auto* focused=ui::GetContext().GetWindow(app.window())->FocusedWidget();return focused&&focused->id=="root-output-input-"+second_root_id;}); finish_input(app);
            assert(root_row_id(app,pending_root)==first_root_id && root_row_id(app,pending_second)==second_root_id);
            if(!state(app.page(),"rootDrafts").empty()) std::cerr<<"Root drafts: "<<state(app.page(),"rootDrafts")<<"; cell="<<state(app.page(),"rootCell")<<'\n';
            assert(state(app.page(),"rootDrafts").empty());
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            assert(rendered_widget(app,"directoryPane").value("visible",true));
            for(const char* action:{"newRoot","editSelectedRoot","deleteSelectedRoot","rootForm","manageRoots"})
                assert(!ui::GetContext().GetWindow(app.window())->Root()->FindById(action));
            auto choose_password_root=[&](const fs::path& path,size_t count) {
                click(app,path.empty()?"allRoots":("directory-"+utf8(path_key(path))).c_str());
                auto selected=path.empty()?std::string("@all"):utf8(path.wstring());
                pump([&]{auto p=state(app.page(),"passwords");return p.value("scope","")==selected && p["total"]==count;},"Password directory projection");
                assert(state(app.page(),"passwordRoot")== (path.empty()?"":utf8(path.wstring())));
            };
            auto password_id=[&](const std::string& value) {
                auto rows=state(app.page(),"passwords")["rows"];
                for(auto& row:rows) if(row["value"]==value) return row["id"].get<std::string>();
                throw std::runtime_error("Password row missing: "+value);
            };
            auto has_password=[&](const std::string& value) {
                auto passwords=read_json(dir/"builtin_passwords.json")["passwords"];
                return std::any_of(passwords.begin(),passwords.end(),[&](const Json& row){return row["value"]==value;});
            };
            auto unchanged_task_root=state(app.page(),"taskRoot");
            choose_password_root(pending_root,0);
            assert(state(app.page(),"taskRoot")==unchanged_task_root);
            click(app,"newPassword"); ui_debug_pump();
            auto scoped_id=state(app.page(),"passwordCell").get<std::string>();
            {
                FileMutex hold(dir/"builtin_passwords.json");
                ui_debug_type_text(app.window(),L"pending scoped");
                assert(ui_debug_key(app.window(),VK_RETURN)==0); ui_debug_pump();
                assert(state(app.page(),"passwordCell")=="");
                // Switch while the writer is blocked: the job retains the
                // directory where editing began, not the next selection.
                click(app,("directory-"+utf8(path_key(pending_second))).c_str());
                assert(state(app.page(),"passwordRoot")==utf8(pending_second.wstring()));
                assert(state(app.page(),"shownPasswords").empty());
            }
            finish_input(app);
            choose_password_root(pending_second,0);
            auto scoped_file=read_json(dir/"builtin_passwords.json");
            assert(scoped_file["passwords"].back()==Json({{"value","pending scoped"},{"scopes",{utf8(pending_root.wstring())}}}));
            choose_password_root(pending_root,1);
            scoped_id=password_id("pending scoped");
            // An own receipt arriving while typing must preserve the editor.
            {
                FileMutex hold(dir/"builtin_passwords.json");
                edit_password(app,scoped_id,L"scoped receipt"); click(app,"passwordSearch"); ui_debug_pump();
                edit_password(app,scoped_id,L"scoped receipt latest");
            }
            pump([&]{return !state(app.page(),"saving").get<bool>();},"Scoped receipt while typing");
            assert(state(app.page(),"passwordCell")==scoped_id);
            assert(state(app.page(),"passwordDrafts")[scoped_id]["value"]=="scoped receipt latest");
            click(app,"passwordSearch"); finish_input(app);
            assert(has_password("scoped receipt latest") && !has_password("pending scoped"));
            choose_password_root(fs::path(),3);
            assert(state(app.page(),"taskRoot")==unchanged_task_root);
            // Search is confined to this exact scope; globals do not include
            // scoped passwords and scoped views do not include globals/parents.
            click(app,"passwordSearch"); ui_debug_type_text(app.window(),L"scoped receipt");
            pump([&]{return state(app.page(),"passwords")["total"]==0;});
            screenshot(app,L"passwords-empty.png");
            assert(ui_debug_key_mod(app.window(),'A',1,0,0)==0); ui_debug_type_char(app.window(),8);
            pump([&]{return state(app.page(),"passwords")["total"]==3;});
            auto saved_rows=state(app.page(),"passwords")["rows"];
            auto id=saved_rows[0]["id"].get<std::string>();
            float narrow=rect(app,"password-text-"+id).right-rect(app,"password-text-"+id).left;
            ui_window_set_size(app.window(),1120,720); ui_window_relayout(app.window());
            assert(rect(app,"password-text-"+id).right-rect(app,"password-text-"+id).left>narrow+20);
            ui_window_set_size(app.window(),850,560); ui_window_relayout(app.window());
            auto* password_window=ui::GetContext().GetWindow(app.window());
            assert(!password_window->Root()->FindById("passwordTableHeader"));
            auto* password_scroll=password_window->Root()->FindById("passwordListScroll");
            auto* password_card=password_window->Root()->FindById("password-"+id);
            assert(password_scroll->Parent()->css.borderWidth<=0 && password_card && password_card->css.borderWidth>0);
            auto password_theme=ui_widget_find_by_id(ui_page_root(app.page()),"themeSelector"); assert(password_theme);
            for(int mode:{2,1}) {
                assert(ui_debug_combo_select(app.window(),password_theme,mode)==0);
                auto value=rect(app,"password-text-"+id);
                assert(ui_debug_mouse_move(app.window(),(value.left+value.right)/2,(value.top+value.bottom)/2)==0);
                auto* line=password_window->Root()->FindById("password-hover-"+id);
                auto* text=password_window->Root()->FindById("password-text-"+id);
                assert(line && line->bgColor.a>0 && line->bgColor.r==(mode==2?1.0f:0.0f));
                assert(text->cursor==ui::CursorKind::Text);
                assert(text->css.hasFg && (mode==2?text->css.fg.r>0.8f:text->css.fg.r<0.2f));
                auto displayed=rect(app,"password-value-"+id);
                click(app,("password-text-"+id).c_str());
                pump([&]{auto* f=password_window->FocusedWidget();return f&&f->id=="password-input-"+id;});
                auto editor=rect(app,"password-input-"+id);
                auto* label=password_window->Root()->FindById("password-value-"+id);
                assert(std::abs(displayed.left+label->padL-editor.left-11)<0.1f);
                assert(std::abs(displayed.top-editor.top)<0.1f && std::abs(displayed.bottom-editor.bottom)<0.1f);
                auto* input=dynamic_cast<ui::TextInputWidget*>(password_window->FocusedWidget());
                assert(input && input->focused && !ui::ShowFocusRing());
                assert(input->css.borderWidth<0 && !input->css.hasBorderColor);
                screenshot(app,mode==2?L"password-focus-dark.png":L"password-focus-light.png");
                if(mode==2) { assert(ui_debug_key(app.window(),VK_RETURN)==0); pump([&]{return !password_window->FocusedWidget();}); }
                else click(app,"passwordSearch");
                assert(!text->hovered && line->bgColor.a==0);
                assert(!password_window->Root()->FindById("password-scope-"+id));
            }
            assert(ui_debug_combo_select(app.window(),password_theme,0)==0); ui_widget_destroy(password_theme);
            auto& path_renderer=password_window->GetRenderer();
            auto long_directory=L"C:\\很长的父目录\\another-parent\\final-folder-\U0001F600";
            for(float width:{95.0f,160.0f,210.0f}) {
                auto clipped=path_renderer.EllipsizeStart(long_directory,width,14);
                assert(clipped.front()==L'…' && clipped.back()==long_directory[wcslen(long_directory)-1]);
                assert(wide(utf8(clipped))==clipped && path_renderer.MeasureTextWidth(clipped,14)<=width);
            }
            auto other_id=saved_rows[1]["id"].get<std::string>();
            {
                FileMutex hold(dir/"builtin_passwords.json");
                edit_password(app,id,L"edited password"); click(app,"passwordSearch"); ui_debug_pump();
                edit_password(app,id,L"edited password latest");
                auto bounds=rect(app,"passwordListScroll");
                POINT point{int((bounds.left+bounds.right)*password_window->DpiScale()/2),int((bounds.top+bounds.bottom)*password_window->DpiScale()/2)};
                ClientToScreen(password_window->Handle(),&point);
                SendMessageW(password_window->Handle(),WM_MOUSEWHEEL,MAKEWPARAM(0,-WHEEL_DELTA),MAKELPARAM(point.x,point.y));
                assert(state(app.page(),"passwordCell")=="");
                edit_password(app,other_id,L"second edited"); click(app,"passwordSearch"); ui_debug_pump();
            }
            finish_input(app);
            assert(has_password("edited password latest") && has_password("second edited"));
            assert(state(app.page(),"passwordDrafts").empty());
            auto global_value=state(app.page(),"passwords")["rows"][0]["value"].get<std::string>();
            // Merge an edited row into an existing global, including when a
            // dedup receipt arrives while the same row is being edited again.
            click(app,"newPassword"); ui_debug_pump();
            auto continuing_id=state(app.page(),"passwordCell").get<std::string>();
            ui_debug_type_text(app.window(),L"merge source"); click(app,"passwordSearch"); finish_input(app);
            {
                FileMutex hold(dir/"builtin_passwords.json");
                edit_password(app,continuing_id,wide(global_value).c_str()); click(app,"passwordSearch"); ui_debug_pump();
                edit_password(app,continuing_id,L"continue after merge");
            }
            pump([&]{return !state(app.page(),"saving").get<bool>();},"Dedup receipt while typing");
            assert(state(app.page(),"passwordDrafts")[continuing_id]["value"]=="continue after merge");
            click(app,"passwordSearch"); finish_input(app);
            assert(has_password(global_value) && has_password("continue after merge"));
            edit_password(app,continuing_id,L""); click(app,"passwordSearch"); finish_input(app);
            assert(!has_password("continue after merge") && !password_window->Root()->FindById("password-"+continuing_id));
            // Exact-directory filtering and legacy multi-scope edits/deletes.
            auto legacy=Json{{"value","legacy\nliteral"},{"scopes",{utf8(pending_root.wstring()),utf8(pending_second.wstring())}}};
            auto legacy_file=read_json(dir/"builtin_passwords.json"); legacy_file["passwords"].push_back(legacy);
            { FileMutex lock(dir/"builtin_passwords.json"); atomic_write(dir/"builtin_passwords.json",legacy_file.dump()); }
            choose_password_root(pending_root,2);
            auto legacy_id=password_id("legacy\nliteral");
            click(app,("password-text-"+legacy_id).c_str()); ui_debug_pump(); click(app,"passwordSearch"); finish_input(app);
            assert(read_json(dir/"builtin_passwords.json")["passwords"].back()==legacy);
            edit_password(app,legacy_id,L""); paste_password(app,L"first #\r\n  second  \nfirst #"); finish_input(app);
            assert(state(app.page(),"passwords")["total"]==3);
            assert(has_password("first #") && has_password("  second  ") && has_password("legacy\nliteral"));
            choose_password_root(pending_second,1);
            auto remaining_id=password_id("legacy\nliteral");
            edit_password(app,remaining_id,L""); click(app,"passwordSearch"); finish_input(app);
            assert(state(app.page(),"passwords")["total"]==0 && !has_password("legacy\nliteral"));
            choose_password_root(pending_root,3);
            auto first_id=password_id("first #");
            edit_password(app,first_id,L"conflicting draft");
            auto scoped_conflict=read_json(dir/"builtin_passwords.json");
            for(auto& row:scoped_conflict["passwords"]) if(row["value"]=="first #") row["value"]="external replacement";
            { FileMutex lock(dir/"builtin_passwords.json"); atomic_write(dir/"builtin_passwords.json",scoped_conflict.dump()); }
            pump([&]{auto rows=state(app.page(),"passwords")["rows"];for(auto& row:rows) if(row["value"]=="external replacement") return true; return false;},"External scoped replacement");
            click(app,"passwordSearch");
            pump([&]{return state(app.page(),"saveErrors").contains("@password:"+first_id) && !state(app.page(),"saving").get<bool>();},"Scoped password conflict");
            assert(state(app.page(),"passwordDrafts")[first_id]["value"]=="conflicting draft" && has_password("external replacement"));
            click(app,("discard-password-"+first_id).c_str()); finish_input(app);
            assert(state(app.page(),"passwordDrafts").empty());
            screenshot(app,L"passwords-directory.png");
            // Copying/adding in a folder stays local; a duplicate of a global
            // value is discarded rather than creating a redundant local copy.
            auto before_duplicate=read_json(dir/"builtin_passwords.json");
            click(app,"newPassword"); ui_debug_pump(); ui_debug_type_text(app.window(),wide(global_value).c_str());
            assert(ui_debug_key(app.window(),VK_RETURN)==0); finish_input(app);
            assert(read_json(dir/"builtin_passwords.json")==before_duplicate);
            // The same visible password in two directories is one JSON record.
            // Its merged baseline must remain usable while typing continues.
            choose_password_root(pending_second,0);
            click(app,"newPassword"); ui_debug_pump();
            auto shared_id=state(app.page(),"passwordCell").get<std::string>();
            {
                FileMutex hold(dir/"builtin_passwords.json");
                ui_debug_type_text(app.window(),L"scoped receipt latest"); click(app,"passwordSearch"); ui_debug_pump();
                edit_password(app,shared_id,L"shared next");
            }
            pump([&]{return !state(app.page(),"saving").get<bool>();},"Merged scope receipt while typing");
            assert(state(app.page(),"passwordCell")==shared_id && state(app.page(),"passwordDrafts")[shared_id]["value"]=="shared next");
            auto merged_file=read_json(dir/"builtin_passwords.json")["passwords"];
            auto shared=std::find_if(merged_file.begin(),merged_file.end(),[](const Json& row){return row["value"]=="scoped receipt latest";});
            assert(shared!=merged_file.end() && (*shared)["scopes"].size()==2);
            assert(std::count_if(merged_file.begin(),merged_file.end(),[](const Json& row){return row["value"]=="scoped receipt latest";})==1);
            click(app,"passwordSearch"); finish_input(app);
            assert(has_password("shared next") && has_password("scoped receipt latest"));
            edit_password(app,shared_id,L"scoped receipt latest"); click(app,"passwordSearch"); finish_input(app);
            assert(!has_password("shared next"));
            edit_password(app,shared_id,L""); click(app,"passwordSearch"); finish_input(app);
            assert(state(app.page(),"passwords")["total"]==0 && has_password("scoped receipt latest"));
            choose_password_root(pending_root,3);
            assert(password_id("scoped receipt latest").size()>0);
            choose_password_root(fs::path(),3);
            screenshot(app,L"passwords-unified.png");
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            click(app,("directory-"+utf8(path_key(pending_second))).c_str());
            for(const char* action:{"newRoot","editSelectedRoot","deleteSelectedRoot","rootForm"})
                assert(!ui_widget_find_by_id(ui_page_root(app.page()),action));
            click(app,"tabRoots"); pump([&]{return state(app.page(),"tab")=="roots";});
            button_texts(app);
            {
                FileMutex lock(dir/"builtin_passwords.json");
                auto document=read_json(dir/"builtin_passwords.json");
                document["passwords"].push_back({{"value","deleted-root-only"},{"scopes",{utf8(pending_second.wstring())}}});
                document["passwords"].push_back({{"value","deleted-root-shared"},{"scopes",{utf8(pending_second.wstring()),utf8(pending_root.wstring())}}});
                document["passwords"].push_back({{"value","deletion-global"}});
                atomic_write(dir/"builtin_passwords.json",document.dump());
            }
            click(app,("delete-root-"+root_row_id(app,pending_second)).c_str()); finish_input(app);
            auto after_root_delete=read_json(dir/"builtin_passwords.json")["passwords"];
            assert(std::none_of(after_root_delete.begin(),after_root_delete.end(),[](const Json& p){return p["value"]=="deleted-root-only";}));
            auto shared_after=std::find_if(after_root_delete.begin(),after_root_delete.end(),[](const Json& p){return p["value"]=="deleted-root-shared";});
            assert(shared_after!=after_root_delete.end() && (*shared_after)["scopes"]==Json::array({utf8(pending_root.wstring())}));
            assert(std::any_of(after_root_delete.begin(),after_root_delete.end(),[](const Json& p){return p["value"]=="deletion-global" && !p.contains("scopes");}));
            assert(state(app.page(),"taskRoot")=="");
            assert(read_roots(dir/"sunpack_watch_roots.txt").entries.size()==2);
            assert(fs::is_directory(pending_second));
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            click(app,("directory-"+utf8(path_key(pending_root))).c_str());
            pump([&]{return state(app.page(),"taskRoot")==utf8(pending_root.wstring());});
            click(app,"tabRoots"); pump([&]{return state(app.page(),"tab")=="roots";});
            auto root_edit_id=root_row_id(app,pending_root);
            edit_root_cell(app,root_edit_id,"output",L"automatic-output");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            finish_input(app);
            auto deep=ui_widget_find_by_id(ui_page_root(app.page()),("root-deep-"+root_edit_id).c_str()); assert(deep);
            assert(ui_debug_toggle_set(app.window(),deep,1)==0); ui_widget_destroy(deep);
            finish_input(app);
            assert(root_row_id(app,pending_root)==root_edit_id && state(app.page(),"rootCell")=="");
            bool updated=false;
            auto root_snapshot=read_roots(dir/"sunpack_watch_roots.txt");
            for(auto& entry:root_snapshot.entries)
                if(path_key(entry.input)==path_key(pending_root)) { updated=entry.output=="automatic-output" && entry.deep; }
            assert(updated);
            click(app,("delete-root-"+root_edit_id).c_str()); finish_input(app);
            assert(read_roots(dir/"sunpack_watch_roots.txt").entries.size()==1);
            assert(fs::is_directory(pending_root));
            pump([&]{return state(app.page(),"taskRoot")=="";});

            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            auto main=utf8((dir/"carrier.001").wstring()), sibling=utf8((dir/"disguised.blob").wstring());
            atomic_write(dir/".sunpack_watch"/"events.jsonl",published_events(
                Json{{"event","pipeline_sources_claimed"},{"path",sibling},{"groups",Json::array({
                    Json{{"path",main},{"name","movie.7z"},{"members",{main,sibling}}}})}}.dump()+"\n"+
                Json{{"event","failed_password"},{"path",sibling}}.dump()+"\n"));
            try { pump([&]{return state(app.page(),"tasks")["rows"][0]["status"]=="taskWaiting";}); }
            catch(...) { std::cerr<<"Log model: "<<state(app.page(),"tasks")<<" errors="<<state(app.page(),"errors")<<"\n"; throw; }
            auto grouped=state(app.page(),"tasks")["rows"][0];
            assert(grouped["name"]=="carrier.001");
            assert(state(app.page(),"statusNames")==Json::array({"","taskProcessing","taskWaiting","taskSucceeded","taskFailed"}));
            assert(rendered_widget(app,"taskRoot-"+grouped["id"].get<std::string>())["text"]==
                "监控目录："+utf8(dir.wstring()));
            screenshot(app,L"grouped-waiting.png");
            std::cerr<<"Log replacement observed\n";
            atomic_write(dir/"sunpack_config.json","{");
            pump([&]{return state(app.page(),"errors").contains("sunpack_config.json");});
            std::cerr<<"Invalid configuration retained\n";
            assert(!state(app.page(),"fields").empty());
            atomic_write(dir/"elsewhere"/"events.jsonl",published_events(Json({{"event","done"},{"path",utf8((dir/"other.fake").wstring())}}).dump()+"\n"));
            atomic_write(dir/"sunpack_config.json",R"({"watch":{"state_dir":"elsewhere"}})");
            try { pump([&]{return state(app.page(),"tasks")["rows"][0]["name"]=="other.fake";}); }
            catch(...) { std::cerr<<"Rebound log: "<<state(app.page(),"tasks")<<" errors="<<state(app.page(),"errors")<<" log="<<state(app.page(),"logPath")<<" fields="<<state(app.page(),"fields")<<"\n"; throw; }
            // Exercise an ordinary config containing all advanced settings.
            auto complete=parse_json(kUiDefaultsJson); complete["watch"]["state_dir"]="elsewhere";
            atomic_write(dir/"sunpack_config.json",complete.dump());
            pump([&]{return state(app.page(),"fields").size()>100;});
            std::cerr<<"Advanced configuration loaded\n";
            ui_page_set_json(app.page(),"drafts","{}");
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_config(app,L"");
            ui_window_relayout(app.window());
            button_texts(app);
            auto startup_before=rect(app,"startupToggle");
            auto config_scroll=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll"); assert(config_scroll);
            std::cerr<<"Validating configuration viewport\n";
            virtual_tail(app,"configItems","configListScroll",state(app.page(),"matchingBlocks").size());
            std::cerr<<"Configuration viewport validated\n";
                scrolled_config_edits(app);
            std::cerr<<"Scrolled configuration edits validated\n";
            ui_window_relayout(app.window()); button_texts(app);
            auto startup_after=rect(app,"startupToggle");
            assert(startup_before.right-startup_before.left==startup_after.right-startup_after.left);
            ui_debug_scroll_set(config_scroll,0);
            // Inspect the actual wheel result before any forced relayout can
            // repair a width computed without the window's text measurer.
            ui_debug_wheel(app.window(),config_scroll,-120);
            auto* smooth_config=dynamic_cast<ui::ScrollViewWidget*>(ui::GetContext().GetWindow(app.window())->Root()->FindById("configListScroll"));
            pump([&]{return !smooth_config->ScrollAnimating();},"Scrolled settings measurement");
            auto startup_wheel=rect(app,"startupToggle");
            if(std::abs((startup_before.right-startup_before.left)-(startup_wheel.right-startup_wheel.left))>0.1f)
                throw std::runtime_error("Wheel changed startup button width");
            button_texts(app,false);
            ui_debug_wheel(app.window(),config_scroll,120);
            pump([&]{return !smooth_config->ScrollAnimating();},"Reverse settings wheel");
            button_texts(app,false);
            auto scroll_bounds=ui_widget_get_rect(config_scroll);
            float bar_x=scroll_bounds.right-4,bar_y=scroll_bounds.top+8;
            ui_debug_mouse_down(app.window(),bar_x,bar_y);
            ui_debug_mouse_move(app.window(),bar_x,bar_y+12);
            ui_debug_mouse_up(app.window(),bar_x,bar_y+12);
            auto startup_drag=rect(app,"startupToggle");
            assert(std::abs((startup_before.right-startup_before.left)-(startup_drag.right-startup_drag.left))<0.1f);
            button_texts(app,false);
            ui_debug_scroll_set(config_scroll,0); ui_widget_destroy(config_scroll); ui_window_relayout(app.window());
            for(auto pair:{std::pair<const char*,const char*>{"categoryScroll","category-cli"},{"configListScroll","field-/cli/language"}}) {
                auto scroll=ui_widget_find_by_id(ui_page_root(app.page()),pair.first);
                auto item=ui_widget_find_by_id(ui_page_root(app.page()),pair.second);
                assert(scroll && item);
                assert(ui_widget_get_rect(scroll).right-ui_widget_get_rect(item).right>=17.0f);
                ui_widget_destroy(item); ui_widget_destroy(scroll);
            }
            screenshot(app,L"advanced-settings-small.png");
            search_config(app,L"白名单");
            auto blocks=state(app.page(),"matchingBlocks");
            if(blocks.size()!=1 || blocks[0]["fields"].size()!=5) std::cerr<<"Whitelist groups: "<<blocks<<"\n";
            assert(blocks.size()==1 && blocks[0]["fields"].size()==5);
            assert(blocks[0]["primary"]==true && blocks[0]["fields"][0]["label"]=="白名单");
            auto block=ui_widget_find_by_id(ui_page_root(app.page()),"block-/filesystem/scan_filters/1"); assert(block);
            for(auto& f:blocks[0]["fields"]) {
                auto item=ui_widget_find_by_id(block,("field-"+f["id"].get<std::string>()).c_str()); assert(item); ui_widget_destroy(item);
            }
            ui_widget_destroy(block);
            screenshot(app,L"whitelist-block-small.png");
                range_config(app,dir);
                tag_config(app,dir);
            // Dense views must remain usable with many folders/history items,
            // including after the directory scrollbar becomes active.
            std::string many_roots=utf8(dir.wstring())+"\n";
            for(int i=0;i<72;++i) many_roots+=utf8((dir/(L"Archive folder "+std::to_wstring(i))).wstring())+"\n";
            atomic_write(dir/"sunpack_watch_roots.txt",many_roots);
            pump([&]{size_t count=0; for(auto& d:state(app.page(),"directories")) if(d["watch"]==true) ++count; return count==73;});
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            ui_window_relayout(app.window());
            auto list_rect=rect(app,"directoryListScroll");
            screenshot(app,L"directories-small.png");
            auto list=ui_widget_find_by_id(ui_page_root(app.page()),"directoryListScroll");
            assert(ui_debug_scroll_set(list,100000)==0); ui_widget_destroy(list); ui_window_relayout(app.window());
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"newRoot"));
            virtual_tail(app,"directoryItems","directoryListScroll",73);
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"moreDirectories"));
            list=ui_widget_find_by_id(ui_page_root(app.page()),"directoryListScroll");
            assert(ui_debug_scroll_set(list,0)==0); ui_widget_destroy(list); ui_window_relayout(app.window());
            size_t visible=0;
            for(auto& directory:state(app.page(),"shownDirectories")) {
                auto handle=ui_widget_find_by_id(ui_page_root(app.page()),("directory-"+directory["id"].get<std::string>()).c_str());
                if(!handle) continue;
                auto bounds=ui_widget_get_rect(handle); ui_widget_destroy(handle);
                // Fractional DPI can put a fully visible bottom edge a few
                // float units beyond the viewport after flex division.
                if(bounds.top>=list_rect.top-0.5f && bounds.bottom<=list_rect.bottom+0.5f) ++visible;
            }
            // Padded two-line directory cards still leave two complete rows
            // in the minimum window, instead of squeezing text into 32 px.
            assert(visible>=2);
            auto first=state(app.page(),"shownDirectories")[1];
            click(app,("directory-"+first["id"].get<std::string>()).c_str());
            pump([&]{return state(app.page(),"tasks")["total"]==0;});
            assert(state(app.page(),"taskRoot")==first["path"]);
            {
                auto card=rendered_widget(app,"directory-"+first["id"].get<std::string>());
                auto bounds=card["rect"], copy=card["children"][0]["rect"];
                assert(copy[1].get<float>()-bounds[1].get<float>()>=7);
                assert(bounds[3].get<float>()-copy[3].get<float>()>=7);
            }
            screenshot(app,L"directories-small.png");
            click(app,"allRoots");
            click(app,"tabRoots"); pump([&]{return state(app.page(),"tab")=="roots";});
            auto root_header_before=rect(app,"rootTableHeader");
            assert(std::abs((root_header_before.right-root_header_before.left)-
                (rect(app,"rootListScroll").right-rect(app,"rootListScroll").left-20))<0.5f);
            virtual_tail(app,"rootItems","rootListScroll",73);
            auto root_header_after=rect(app,"rootTableHeader");
            assert(root_header_before.top==root_header_after.top && root_header_before.bottom==root_header_after.bottom);
            auto root_search=rect(app,"rootSearch");
            assert(std::abs(root_search.right-root_search.left-220)<0.5f);
            auto* first_root=ui::GetContext().GetWindow(app.window())->Root()->FindById("root-row-"+state(app.page(),"shownRootRows")[0]["id"].get<std::string>());
            assert(first_root && first_root->css.borderWidth>0);
            screenshot(app,L"roots-table-small.png");
            auto roots_before_blank=read_file(dir/"sunpack_watch_roots.txt");
            click(app,"addRoot");
            pump([&]{auto* focused=ui::GetContext().GetWindow(app.window())->FocusedWidget();return focused&&focused->id=="root-input-input-"+state(app.page(),"rootCell").get<std::string>();});
            click(app,"rootSearch"); finish_input(app);
            assert(state(app.page(),"rootNew").empty() && state(app.page(),"rootDrafts").empty());
            assert(read_file(dir/"sunpack_watch_roots.txt")==roots_before_blank);
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            ui_window_set_size(app.window(),1120,720); screenshot(app,L"directories.png");
            auto history=read_json(dir/"builtin_passwords.json"); history["clipboard_history"]=Json::array();
            for(int i=0;i<virtualHistoryCount;++i) history["clipboard_history"].push_back("candidate-"+std::to_string(i));
            history["clipboard_history"][0]="  #history value  ";
            history["clipboard_history"][1]=std::string(180,'x');
            history["clipboard_history"][2]="first line\nsecond line\nthird line";
            for(int i=0;i<virtualPasswordCount;++i) history["passwords"].push_back({{"value","virtual-password-"+std::to_string(i)},
                {"scopes",Json::array({utf8(dir.wstring()),utf8((dir/"nested").wstring())})}});
            atomic_write(dir/"builtin_passwords.json",history.dump());
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            click(app,("directory-"+utf8(path_key(dir))).c_str());
            click(app,"savedPasswords"); pump([&]{return state(app.page(),"passwords")["total"]==virtualPasswordCount;});
            virtual_tail(app,"passwordItems","passwordListScroll",virtualPasswordCount);
            virtual_tail(app,"directoryItems","directoryListScroll",73);
            // Inspect the event boundary before dispatching the async request:
            // populated saved rows must retain their layout until history arrives.
            auto previous_passwords=state(app.page(),"passwords");
            assert(ui_page_call_json(app.page(),"selectPasswordView","true")==0);
            assert(state(app.page(),"passwordHistoryTarget")==true && state(app.page(),"passwordHistory")==false);
            assert(state(app.page(),"passwords")==previous_passwords && state(app.page(),"shownPasswords").size()==virtualPasswordCount);
            // Reverse before the worker receives either request; latest intent wins.
            assert(ui_page_call_json(app.page(),"selectPasswordView","false")==0);
            assert(ui_page_call_json(app.page(),"selectPasswordView","true")==0);
            click(app,"clipboardHistory"); pump([&]{return state(app.page(),"passwords")["total"]==virtualHistoryCount;});
            assert(state(app.page(),"passwordHistory")==true);
            ui_window_set_size(app.window(),850,560); ui_window_relayout(app.window());
            virtual_tail(app,"passwordItems","passwordListScroll",virtualHistoryCount);
            auto history_view=rect(app,"passwordListScroll"); visible=0;
            auto history_rows=state(app.page(),"passwords")["rows"];
            for(auto& entry:history_rows) {
                auto handle=ui_widget_find_by_id(ui_page_root(app.page()),("password-"+entry["id"].get<std::string>()).c_str());
                if(!handle) continue;
                auto bounds=ui_widget_get_rect(handle); ui_widget_destroy(handle);
                if(entry["id"]!="1" && entry["id"]!="2") assert(bounds.bottom-bounds.top<=56);
                if(bounds.top>=history_view.top && bounds.bottom<=history_view.bottom) ++visible;
            }
            assert(visible>=3);
            auto history_action=rendered_widget(app,"save-history-0");
            assert(history_action["text"]==state(app.page(),"texts")["saveHistoryToDirectory"]);
            assert(history_action["textWidth"].get<float>()<=history_action["availWidth"].get<float>());
            for(int i:{1,2}) {
                auto history_text=rendered_widget(app,"history-value-"+std::to_string(i));
                auto history_button=rect(app,("save-history-"+std::to_string(i)).c_str());
                auto history_bounds=rect(app,("password-"+std::to_string(i)).c_str());
                auto text_bounds=history_text["rect"];
                assert(text_bounds[3].get<float>()-text_bounds[1].get<float>()>32);
                assert(text_bounds[0].get<float>()>=history_bounds.left);
                assert(text_bounds[2].get<float>()+11<=history_button.left);
                assert(text_bounds[1].get<float>()>=history_bounds.top+3);
                assert(text_bounds[3].get<float>()<=history_bounds.bottom-3);
                assert(history_text["text"]==history["clipboard_history"][i]);
                auto* history_label=dynamic_cast<ui::LabelWidget*>(password_window->Root()->FindById("history-value-"+std::to_string(i)));
                assert(history_label);
                auto history_font=history_label->css.fontSize>0?history_label->css.fontSize:theme::kFontSizeNormal;
                auto history_height=path_renderer.MeasureTextHeight(history_label->Text(),
                    history_label->ContentWidth(),history_font);
                assert(history_height<=history_label->rect.bottom-history_label->rect.top+0.5f);
                if(i==1) assert(history_text["textWidth"].get<float>()>history_text["availWidth"].get<float>());
            }
            screenshot(app,L"clipboard-history-small.png");
            button_texts(app);
            auto reject_history_save=[&] {
                auto path=dir/"builtin_passwords.json";
                auto before=read_file(path);
                std::string failed_id;
                {
                    Handle held(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
                    assert(held.value!=INVALID_HANDLE_VALUE);
                    click(app,"save-history-0");
                    pump([&] {
                        auto drafts=state(app.page(),"passwordDrafts");
                        for(auto& draft:drafts.items()) {
                            auto& d=draft.value();
                            if(d.value("historyValue",std::string())==history["clipboard_history"][0] &&
                               !d["pending"].get<bool>() && !d["error"].empty()) failed_id=draft.key();
                        }
                        return !failed_id.empty() && state(app.page(),"saving")==false;
                    },"Rejected history save");
                    assert(read_file(path)==before);
                }
                click(app,"savedPasswords"); pump([&]{return state(app.page(),"passwordHistory")==false;});
                for(auto& row:state(app.page(),"shownPasswords")) assert(row["id"]!=failed_id);
                click(app,"clipboardHistory"); pump([&]{return state(app.page(),"passwordHistory")==true;});
                assert(!state(app.page(),"passwordDrafts")[failed_id]["error"].empty());
            };
            reject_history_save();
            for(int i:{0,1,2}) {
                click(app,("save-history-"+std::to_string(i)).c_str()); finish_input(app);
                assert(state(app.page(),"passwordHistory")==true && state(app.page(),"passwordCell")=="");
                auto history_saved=read_json(dir/"builtin_passwords.json");
                assert(history_saved["passwords"].back()["value"]==history["clipboard_history"][i]);
                assert(history_saved["passwords"].back()["scopes"]==Json::array({utf8(dir.wstring())}));
                assert(history_saved["clipboard_history"]==history["clipboard_history"]);
                assert(state(app.page(),"passwordDrafts").empty());
            }
            click(app,"allRoots");
            assert(state(app.page(),"passwordHistory")==true && state(app.page(),"passwordRoot")=="");
            assert(rendered_widget(app,"save-history-0")["text"]==state(app.page(),"texts")["saveHistoryGlobally"]);
            button_texts(app);
            reject_history_save();
            click(app,"save-history-0"); finish_input(app);
            click(app,"save-history-0"); finish_input(app);
            auto history_global=read_json(dir/"builtin_passwords.json"); size_t history_matches=0;
            for(auto& record:history_global["passwords"]) if(record["value"]==history["clipboard_history"][0]) {
                ++history_matches; assert(record["scopes"].empty());
            }
            assert(history_matches==1 && state(app.page(),"passwordDrafts").empty());
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_setting(app,"/watch/max_folders");
            auto invalid_input=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/max_folders"); assert(invalid_input);
            ui_text_input_set_text(invalid_input,L""); ui_widget_destroy(invalid_input);
            click(app,"input-/watch/max_folders"); ui_debug_type_text(app.window(),L"0");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            pump([&]{return state(app.page(),"saveErrors").contains("/watch/max_folders") && !state(app.page(),"saving").get<bool>();});
            assert(read_json(dir/"sunpack_config.json")["watch"]["max_folders"]==16);
            search_setting(app,"/watch/out_dir");
            auto independent=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir"); assert(independent);
            ui_text_input_set_text(independent,L""); ui_widget_destroy(independent);
            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"independent");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            pump([&]{return read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="independent" && !state(app.page(),"saving").get<bool>();});
            assert(state(app.page(),"saveErrors").contains("/watch/max_folders"));
            search_setting(app,"mtime_range");
            std::string closingDate;
            for(auto& f:state(app.page(),"fields")) if(f["module"]=="mtime_range" && f["type"]=="object") closingDate=f["id"];
            assert(!closingDate.empty());
            click(app,("range-lower-pick-"+closingDate).c_str()); ui_debug_pump();
            auto* closingPopup=date_popup(app); assert(closingPopup);
            std::weak_ptr<ui::Widget> closingTree=closingPopup->Root();
            // Closing abandons drafts and must not be blocked by another field's save error.
            PostMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_CLOSE,0,0);
            pump([&]{return !IsWindow(static_cast<HWND>(ui_window_hwnd(app.window())));});
            assert(!date_popup(app) && closingTree.expired());
            }
        }
        fs::remove_all(dir); std::cout<<"GUI interface and observation passed\n";
    } catch(const std::exception& e) { std::cerr<<e.what()<<"\n"; std::error_code ec; fs::remove_all(dir,ec); return 1; }
    CoUninitialize(); return 0;
}
