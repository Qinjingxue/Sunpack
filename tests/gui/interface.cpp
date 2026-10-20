#include "application.hpp"
#include "presentation.hpp"
#include "ui_defaults_json.h"
#include <cassert>
#include <iostream>
#include <dwmapi.h>
#include <cstring>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/uix/script_runtime.h>
#include <ui/controls.h>
using namespace spg;
namespace {
struct AnimationFrames {
    bool finished=false, layout=false, stopped=false;
    unsigned frames=0;
    std::vector<double> intervals;
    AnimationFrames() {
        ui_trace_set_sink([](const UiTraceEvent* event,void* data){
            auto& self=*static_cast<AnimationFrames*>(data);
            if(!std::strcmp(event->name,"motion_stopped")) self.stopped=true;
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
    auto widget=ui_widget_find_by_id(ui_page_root(app.page()),id.c_str());
    if(!widget) throw std::runtime_error("Widget missing: "+id);
    auto result=ui_widget_get_rect(widget); ui_widget_destroy(widget); return result;
}
Json rendered_widget(Application& app,const std::string& id) {
    char* dump=ui_debug_dump_tree(app.window()); assert(dump);
    auto tree=parse_json(dump); ui_debug_free(dump);
    std::function<const Json*(const Json&)> find=[&](const Json& node)->const Json* {
        if(node.value("id",std::string())==id) return &node;
        if(node.contains("children")) for(auto& child:node["children"]) if(auto* result=find(child)) return result;
        return nullptr;
    };
    auto* found=find(tree); assert(found); return *found;
}
void pump(const std::function<bool()>& condition, const char* phase="UI event", bool allow_timers=true) {
    auto deadline=GetTickCount64()+10000;
    for(;;) {
        try { if(condition()) return; }
        catch(const WinError& error) {
            // Test-side reads can overlap ReplaceFile's rename/share window.
            // Wait for the actual queued UI/file event, with the same deadline.
            if(error.code!=ERROR_FILE_NOT_FOUND && error.code!=ERROR_PATH_NOT_FOUND && error.code!=ERROR_SHARING_VIOLATION) throw;
        }
        DWORD left=DWORD(deadline>GetTickCount64()?deadline-GetTickCount64():0);
        if(!left) throw std::runtime_error(std::string(phase)+" timed out");
        MsgWaitForMultipleObjectsEx(0,nullptr,left,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
        MSG message;
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) { if(message.message==WM_QUIT || (!allow_timers && message.message==WM_TIMER)) continue; TranslateMessage(&message); DispatchMessageW(&message); }
    }
}
void settle_motion(Application& app) {
    Json pending;
    try { pump([&] {
        pending=Json::array();
        auto root=ui::GetContext().GetWindow(app.window())->Root();
        std::function<bool(ui::Widget*)> settled=[&](ui::Widget* widget) {
            if(!widget->visible) return true;
            if(widget->opacity<0.999f || std::abs(widget->animationX)>0.01f) { pending.push_back({widget->id,widget->opacity,widget->animationX}); return false; }
            if(widget->id=="navIndicator") {
                auto tab=state(app.page(),"tab").get<std::string>();
                auto* target=root->FindById(tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":"tabPasswords");
                if(std::abs(widget->rect.top+widget->animationY+(widget->rect.bottom-widget->rect.top)/2-(target->rect.top+target->rect.bottom)/2)>0.01f) { pending.push_back({widget->id,widget->rect.top,widget->animationY,target->rect.top,target->rect.bottom}); return false; }
            } else if(std::abs(widget->animationY)>0.01f) { pending.push_back({widget->id,widget->animationY}); return false; }
            for(auto& child:widget->Children()) if(!settled(child.get())) return false;
            return true;
        };
        return settled(root.get());
    }); } catch(...) { std::cerr<<"Unfinished motion: "<<pending<<'\n'; throw; }
}
void click(Application& app,const char* id) {
    ui_window_relayout(app.window());
    // Scroll the containing pane as a person would before clicking an action
    // in a long inline form. Never click through a clipped viewport.
    char* dump=ui_debug_dump_tree(app.window()); assert(dump);
    auto tree=parse_json(dump); ui_debug_free(dump);
    std::vector<Json> ancestors;
    std::function<bool(const Json&)> path=[&](const Json& node) {
        if(node.value("id",std::string())==id) return true;
        if(node.contains("children")) for(auto& child:node["children"]) if(path(child)) {
            if(node.value("type",std::string())=="ScrollView") ancestors.push_back(node);
            return true;
        }
        return false;
    };
    path(tree);
    for(auto& pane:ancestors) {
        auto bounds=rect(app,id); auto viewport=pane["rect"];
        float top=viewport[1], bottom=viewport[3], center=(bounds.top+bounds.bottom)/2;
        if(center<top+4 || center>bottom-4) {
            auto scroll=ui_widget_find_by_id(ui_page_root(app.page()),pane["id"].get<std::string>().c_str()); assert(scroll);
            ui_debug_scroll_set(scroll,pane["scrollY"].get<float>()+center-(top+bottom)/2);
            ui_widget_destroy(scroll); ui_window_relayout(app.window());
        }
    }
    auto widget=ui_widget_find_by_id(ui_page_root(app.page()),id); assert(widget);
    if(ui_debug_widget_is_visible(widget)!=1) {
        char* info=ui_debug_dump_widget(widget); std::cerr<<id<<": "<<(info?info:"")<<"\n"; ui_debug_free(info);
    }
    assert(ui_debug_widget_is_visible(widget)==1);
    assert(ui_debug_click(app.window(),widget)==0);
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
    char* dump=ui_debug_dump_tree(app.window()); assert(dump);
    auto tree=parse_json(dump); ui_debug_free(dump);
    std::function<void(const Json&)> check=[&](const Json& node) {
        if(!node.value("visible",true)) return;
        if(node.value("type",std::string())=="Button" && node.contains("textWidth")) {
            if(node["textWidth"].get<float>()>node["availWidth"].get<float>()+0.5f)
                throw std::runtime_error("Truncated action: "+node.dump());
        }
        if(node.contains("children")) for(auto& child:node["children"]) check(child);
    };
    check(tree);
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
    if(animations) assert(combo->PopupAnimating() && combo->PopupOpacity()<1 && combo->PopupProgress()<1);
    // Motion must advance from presented frames, without depending on a
    // low-frequency WM_TIMER. Completion-only checks with timers miss that.
    pump([&]{return !combo->PopupAnimating() && (!animations || animation.stopped);},"Render-paced popup entrance",false);
    auto bounds=combo->rect, drop=combo->DropdownRect();
    assert(combo->PopupOpacity()==1 && combo->PopupProgress()==1);
    if(upward && drop.bottom>bounds.top) {
        std::cerr<<"Popup geometry: "<<rendered_widget(app,id)<<"; scroll="<<rendered_widget(app,"configListScroll").at("rect")
                 <<"; viewport="<<ui::Viewport().top<<","<<ui::Viewport().bottom<<"; popup="<<drop.top<<","<<drop.bottom<<'\n';
        throw std::runtime_error("Expected popup to open upward");
    }
    if(animations) assert(animation.frames>1 && !animation.layout);
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
    if(animations) assert(combo->PopupAnimating() && combo->PopupOpacity()>0);
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
        ui_window_relayout(app.window());
    };
    for(int visit=0;visit<3;++visit) {
        // Estimated heights settle when the last variable-height rows mount.
        for(int pass=0;pass<3;++pass) scroll_to(1e9f);
        if(list->Indices().empty() || list->Indices().back()!=total-1)
            std::cerr<<"Virtual tail "<<list_id<<" expected="<<total<<" last="<<(list->Indices().empty()?0:list->Indices().back())<<" scroll="<<scroll->ScrollY()<<"\n";
        assert(!list->Indices().empty() && list->Indices().back()==total-1);
        assert(list->Children().size()<40);
        const auto& last=list->Children().back()->rect;
        auto viewport=scroll->rect;
        assert(last.top<viewport.bottom && last.bottom<=viewport.bottom+2);
        scroll_to(0);
        if(list->Indices().empty() || list->Indices().front()!=0 || list->Children().size()>=40) {
            std::cerr<<"Virtual top "<<list_id<<" indices="; for(auto index:list->Indices()) std::cerr<<index<<","; std::cerr<<" rect="<<list->rect.top<<","<<list->rect.bottom<<" scroll="<<rendered_widget(app,scroll_id)<<"\n";
        }
        assert(!list->Indices().empty() && list->Indices().front()==0 && list->Children().size()<40);
    }
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
    pump([&]{return state(app.page(),"tab")=="config";});
    settle_motion(app);
    auto root=ui::GetContext().GetWindow(app.window())->Root();
    auto* active=dynamic_cast<ui::ScrollViewWidget*>(root->FindById("configListScroll"));
    auto* hidden=dynamic_cast<ui::ScrollViewWidget*>(root->FindById("taskListScroll"));
    assert(active && hidden && active->NeedsScrollbar() && hidden->NeedsScrollbar());
    auto scroll=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll"); assert(scroll);
    const float hidden_y=hidden->ScrollY();
    for(int delta:{-120,120,-120,120}) {
        const float before_wheel=active->ScrollY();
        assert(ui_debug_wheel(app.window(),scroll,delta)==0);
        assert(std::abs(active->ScrollY()-before_wheel)>0.1f);
        // No relayout between wheel and press: that can hide routing failures.
        const auto bounds=active->rect;
        float height=bounds.bottom-bounds.top;
        const auto content=active->Children().front()->rect;
        float extent=content.bottom-content.top;
        float thumb=std::max(20.0f,height*height/extent);
        float x=bounds.right-4;
        float y=bounds.top+active->ScrollY()/(extent-height)*(height-thumb)+thumb/2;
        float from=active->ScrollY(),dy=delta<0?12.0f:-12.0f;
        assert(ui_debug_mouse_move(app.window(),x,y)==0);
        assert(ui_debug_mouse_down(app.window(),x,y)==0);
        assert(GetCapture()==static_cast<HWND>(ui_window_hwnd(app.window())));
        assert(std::abs(active->ScrollY()-from)<0.1f);
        assert(ui_debug_mouse_move(app.window(),x,y+dy)==0);
        assert(ui_debug_mouse_up(app.window(),x,y+dy)==0);
        if((active->ScrollY()-from)*dy<=0 || hidden->ScrollY()!=hidden_y)
            throw std::runtime_error("Scrollbar drag after wheel was lost or sent to the hidden task page");
        assert(GetCapture()!=static_cast<HWND>(ui_window_hwnd(app.window())));
        float released=active->ScrollY();
        assert(ui_debug_mouse_move(app.window(),x,y+dy*2)==0);
        assert(active->ScrollY()==released && hidden->ScrollY()==hidden_y);
    }
    ui_widget_destroy(scroll);
    click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
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
}
int wmain(int argc,wchar_t** argv) {
    if(argc>1 && std::wstring(argv[1])==L"--fake-cli") {
        Json args=Json::array(); for(int i=3;i<argc;++i) args.push_back(utf8(argv[i])); atomic_write(fs::current_path()/"cli-arguments.json",args.dump());
        Handle gate(OpenEventW(SYNCHRONIZE,FALSE,argv[2])); assert(gate.value);
        assert(WaitForSingleObject(gate,10000)==WAIT_OBJECT_0);
        std::cout<<args.dump(); return 0;
    }
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    auto dir=fs::temp_directory_path()/(L"sunpack-gui-ui-"+std::to_wstring(GetCurrentProcessId())); fs::create_directory(dir);
    auto gate_name=L"Local\\SunPack.GUI.TestCommand."+std::to_wstring(GetCurrentProcessId());
    Handle gate(CreateEventW(nullptr,TRUE,TRUE,gate_name.c_str()));
    try {
        scalar_reactivity_noop();
        atomic_write(dir/"sunpack_config.json",R"({"cli":{"language":"zh"},"runtime":{"process_mode":"normal"},"recursive_extract":"*","watch":{"state_dir":".sunpack_watch","out_dir":".","toast_enabled":true},"unknown":9007199254740993})");
        atomic_write(dir/"builtin_passwords.json",R"({"passwords":[{"value":"  #中文  "}],"clipboard_history":["history"]})");
        atomic_write(dir/"sunpack_watch_roots.txt",utf8(dir.wstring())+"\n");
        atomic_write(dir/".sunpack_watch"/"events.jsonl",Json({{"event","done"},{"path",utf8((dir/"carrier.001").wstring())}}).dump()+"\n");
        {
            Options options; options.data_dir=dir; options.allow_cli=true;
            options.cli={executable_path(),dir,{L"--fake-cli",gate_name}};
            Application app(options); std::cerr<<"Opening UI\n"; app.open(); std::cerr<<"UI opened\n";
            pump([&]{return state(app.page(),"ready")==true;});
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
            for(int i=0;i<512;++i) many+=Json({{"event",phases[i%4]},{"path",utf8((dir/"history"/("task-"+std::to_string(i)+".001")).wstring())},{"time","2026-10-19T09:15:42.731112+00:00"},{"output_dirs",{utf8(dir.wstring())}}}).dump()+"\n";
            atomic_write(dir/".sunpack_watch"/"events.jsonl",many);
            pump([&]{return state(app.page(),"tasks")["total"]==512;});
            virtual_tail(app,"taskItems","taskListScroll",512);
            auto tail=state(app.page(),"tasks")["rows"][511];
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
            virtual_tail(app,"taskItems","taskListScroll",512);
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
            atomic_write(dir/".sunpack_watch"/"events.jsonl",Json({{"event","done"},{"path",utf8((dir/"carrier.001").wstring())}}).dump()+"\n");
            pump([&]{return state(app.page(),"tasks")["total"]==1;});
            assert(!state(app.page(),"texts").contains("otherTasks"));
            assert(rect(app,"allRoots").top>=rect(app,"directorySearch").bottom);
            click(app,"taskSearch"); ui_debug_type_text(app.window(),L"missing");
            try { pump([&]{return state(app.page(),"tasks")["total"]==0;}); }
            catch(...) { std::cerr<<"Search tasks: "<<state(app.page(),"taskQuery")<<" requests="<<state(app.page(),"requests")<<" error="<<ui_page_last_error(app.page())<<"\n"; screenshot(app,L"search-failed.png"); throw; }
            for(int i=0;i<7;++i) ui_debug_type_char(app.window(),8);
            try { pump([&]{return state(app.page(),"tasks")["total"]==1;}); }
            catch(...) { std::cerr<<"Clear tasks: "<<state(app.page(),"taskQuery")<<"\n"; throw; }
            auto status=ui_widget_find_by_id(ui_page_root(app.page()),"taskStatus"); assert(status);
            assert(ui_debug_combo_select(app.window(),status,1)==0);
            pump([&]{return state(app.page(),"tasks")["total"]==0;});
            assert(ui_debug_combo_select(app.window(),status,0)==0);
            pump([&]{return state(app.page(),"tasks")["total"]==1;});
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
            pump([&]{return state(app.page(),"lastCommand").value("action",std::string())=="start";});
            assert(read_json(dir/"cli-arguments.json")==Json::array({"watch","start"}));
            assert(state(app.page(),"actionError")=="");
            pump([&]{return state(app.page(),"runtime")["known"]==true;});
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
                pump([&]{return state(app.page(),"busy")==true && read_json(dir/"cli-arguments.json")==args;});
                if(ui_widget_get_opacity(page)<0.999f || ui_debug_widget_is_visible(page)!=1) {
                    std::cerr<<"Command visibility: "<<id<<" opacity="<<ui_widget_get_opacity(page)<<" visible="<<ui_debug_widget_is_visible(page)<<"\n";
                    screenshot(app,L"command-visibility.png");
                    throw std::runtime_error("Command changed page visibility");
                }
                SetEvent(gate);
                pump([&]{return state(app.page(),"lastCommand").value("action",std::string())==action && state(app.page(),"busy")==false;});
                assert(read_json(dir/"cli-arguments.json")==args);
                assert(state(app.page(),"actionError")=="");
                auto after=ui_widget_get_rect(page);
                assert(after.left==rect.left && after.top==rect.top && after.right==rect.right && after.bottom==rect.bottom);
                assert(ui_widget_get_opacity(page)>=0.999f && ui_debug_widget_is_visible(page)==1);
                ui_widget_destroy(page);
            };
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            settle_motion(app);
            assert(rect(app,"monitorControls").top==monitor_bounds.top);
            stable_commands("watchStop","stop",Json::array({"watch","stop"}));
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            settle_motion(app);
            assert(rect(app,"monitorControls").top==monitor_bounds.top);
            stable_commands("watchStart","start",Json::array({"watch","start"}));
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            auto content=ui_widget_find_by_id(ui_page_root(app.page()),"page-config");
            assert(content && ui_widget_get_opacity(content)>0); // No blank incoming frame.
            pump([&]{return ui_widget_get_opacity(content)>=0.999f;}); ui_widget_destroy(content);
            {
                // Navigation must finish at the latest selection even when
                // interrupted; the indicator travels rather than blinking.
                AnimationFrames animation;
                click(app,"tabPasswords"); click(app,"tabTasks"); click(app,"tabConfig");
                // The last requested tab equals the starting tab: wait for
                // queued navigation to dispatch before checking its animation.
                pump([&]{return state(app.page(),"tab")=="config" && state(app.page(),"requests").empty() && state(app.page(),"dispatch")==false;});
                settle_motion(app); pump([&]{return animation.stopped;});
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
                    assert(scroll->ScrollY()>before && !combo->IsOpen());
                    if(animations) {
                        assert(combo->PopupAnimating() && combo->PopupOpacity()>0);
                        auto frozen=combo->DropdownRect();
                        assert(frozen.left==drop.left && frozen.top==drop.top && frozen.right==drop.right && frozen.bottom==drop.bottom);
                    }
                    pump([&]{return !combo->PopupAnimating() && (!animations || exit.stopped);},"Popup wheel exit");
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
            search_config(app,L"toast_enabled");
            auto toast=ui_widget_find_by_id(ui_page_root(app.page()),"toggle-/watch/toast_enabled"); assert(toast);
            assert(ui_debug_toggle_set(app.window(),toast,0)==0);
            assert(state(app.page(),"toggleDrafts").size()==1 && state(app.page(),"drafts").empty());
            assert(ui_debug_toggle_set(app.window(),toast,1)==0);
            {
            AnimationFrames animation;
            assert(ui_debug_toggle_set(app.window(),toast,0)==0);
            pump([&]{return animation.finished && animation.stopped;},"Toggle motion");
            assert(animation.frames>1 && !animation.layout);
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
                assert(ui_debug_mouse_move(app.window(),x,y)==0);
                pump([&]{return animation.finished && animation.stopped;},"Toggle hover");
                animation.finished=animation.stopped=false;
                assert(ui_debug_mouse_down(app.window(),x,y)==0);
                pump([&]{return animation.finished && animation.stopped;},"Toggle press");
                assert(ui_debug_mouse_up(app.window(),x,y)==0);
                    assert(ui_debug_key(app.window(),VK_SPACE)==0);
                    animation.finished=animation.stopped=false;
                assert(ui_debug_mouse_move(app.window(),0,0)==0);
                pump([&]{return animation.finished && animation.stopped;},"Toggle release");
                assert(!animation.layout);
            }
            ui_widget_destroy(toast);
            click(app,"tabTasks"); // Rapid navigation must not overwrite automatic writes.
            pump([&]{return read_json(dir/"sunpack_config.json")["watch"]["toast_enabled"]==false;},"Toggle saved after navigation");
            pump([&]{return state(app.page(),"tab")=="tasks";});
            pump([&]{return state(app.page(),"saving")==false;});
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_config(app,L"out_dir");
            if(state(app.page(),"configQuery")!="out_dir")
                throw std::runtime_error("Config search: "+state(app.page(),"configQuery").dump()+" error="+ui_page_last_error(app.page()));
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
            screenshot(app,L"error-english.png");
            assert(rendered_widget(app,"field-/watch/out_dir").dump().find("Default output folder")!=std::string::npos);
            changed["cli"]["language"]="zh"; atomic_write(dir/"sunpack_config.json",changed.dump());
            pump([&]{return state(app.page(),"saveErrors")["/watch/out_dir"]["text"]==tr("settingChanged","zh");});

            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L" corrected");
            finish_input(app);
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="unsaved corrected");
            // External language replacement updates visible and generated controls.
            auto conf=read_json(dir/"sunpack_config.json"); conf["cli"]["language"]="en"; atomic_write(dir/"sunpack_config.json",conf.dump());
            pump([&]{return state(app.page(),"language")=="en";});
            assert(state(app.page(),"texts")["config"]=="Settings");
            assert(state(app.page(),"fields")[0]["label"]=="Language");
            search_hints(app);
            screenshot(app,L"configuration-english.png");
            button_texts(app);
            search_config(app,L"language");
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
            click(app,"newPassword"); assert(state(app.page(),"passwordEditor")==true);
            click(app,"passwordValue"); ui_debug_type_text(app.window(),L"添加的密码\n  #批量  \n\n添加的密码");
            assert(state(app.page(),"passwordValue")=="添加的密码\n  #批量  \n\n添加的密码");
            screenshot(app,L"passwords.png");
            ui_window_set_size(app.window(),850,560);
            screenshot(app,L"password-editor-small.png");
            assert(read_json(dir/"builtin_passwords.json")["passwords"].size()==1);
            click(app,"finishPassword"); finish_input(app);
            try { pump([&]{return read_json(dir/"builtin_passwords.json")["passwords"].size()==3;}); }
            catch(...) { std::cerr<<"Save password: "<<state(app.page(),"actionError")<<"\n"; throw; }
            assert(read_json(dir/"builtin_passwords.json")["passwords"][2]["value"]=="  #批量  ");
            std::cerr<<"Password saved\n";
            try { pump([&]{return state(app.page(),"passwords")["total"]==3;}); }
            catch(...) { std::cerr<<"Password model: "<<state(app.page(),"passwords")<<" errors="<<state(app.page(),"errors")<<"\n"; throw; }
            std::cerr<<"Password model updated\n";
            // Creation actions persist immediately. Unrelated incomplete forms
            // never join another field or record's automatic write.
            auto pending_root=dir/L"pending-root", pending_second=dir/L"pending-second"; fs::create_directory(pending_root); fs::create_directory(pending_second);
            auto disk_roots=read_file(dir/"sunpack_watch_roots.txt");
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            click(app,"newRoot");
            assert(rendered_widget(app,"directoryPane").value("visible",true));
            click(app,"rootInput"); ui_debug_type_text(app.window(),(pending_root.wstring()+L"\n"+pending_second.wstring()+L"\n"+pending_root.wstring()).c_str());
            button_texts(app); screenshot(app,L"root-inline-batch-small.png");
            click(app,"finishRoot"); finish_input(app);
            assert(read_file(dir/"sunpack_watch_roots.txt")!=disk_roots);
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            click(app,"newPassword"); click(app,"passwordValue"); ui_debug_type_text(app.window(),L"pending scoped");
            click(app,"passwordScopes"); ui_debug_type_text(app.window(),pending_root.c_str());
            click(app,"finishPassword"); finish_input(app);
            click(app,"newPassword"); click(app,"passwordValue"); ui_debug_type_text(app.window(),L"pending global");
            click(app,"finishPassword"); finish_input(app);
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_config(app,L"out_dir");
            output=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir"); ui_text_input_set_text(output,L""); ui_widget_destroy(output);
            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"batch-output");
            auto background=read_json(dir/"builtin_passwords.json"); assert(background["passwords"].size()==5);
            background["clipboard_history"].push_back("external while editing"); atomic_write(dir/"builtin_passwords.json",background.dump());
            screenshot(app,L"automatic-save.png");
            finish_input(app);
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="batch-output");
            assert(read_roots(dir/"sunpack_watch_roots.txt").entries.size()==3);
            auto committed=read_json(dir/"builtin_passwords.json"); assert(committed["passwords"].size()==5);
            assert(committed["passwords"][3]["scopes"][0]==utf8(pending_root.wstring()));
            assert(committed["clipboard_history"].back()=="external while editing");
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            click(app,"passwordSearch"); ui_debug_type_text(app.window(),L"pending scoped");
            pump([&]{return state(app.page(),"passwords")["total"]==1;});
            assert(state(app.page(),"passwords")["rows"][0]["scopes"]==utf8(pending_root.wstring()));
            ui_debug_type_text(app.window(),L" no match");
            pump([&]{return state(app.page(),"passwords")["total"]==0;});
            screenshot(app,L"passwords-empty.png");
            for(int i=0;i<9;++i) ui_debug_type_char(app.window(),8);
            for(int i=0;i<14;++i) ui_debug_type_char(app.window(),8);
            pump([&]{return state(app.page(),"passwords")["total"]==5;});
            ui_window_relayout(app.window());
            auto saved_rows=state(app.page(),"passwords")["rows"];
            for(auto& entry:saved_rows) {
                auto id=entry["id"].get<std::string>();
                auto row=rect(app,"password-"+id), edit=rect(app,"edit-password-"+id);
                assert(std::abs((row.top+row.bottom-1)/2-(edit.top+edit.bottom)/2)<=1);
                auto remove=rect(app,"delete-password-"+id);
                assert(edit.top==remove.top && edit.bottom==remove.bottom && edit.right<remove.left);
            }
            screenshot(app,L"passwords-unified.png");
            // Existing records auto-save on blur and retain their editor. A
            // second completed edit while the first owns the writer lock must
            // rebase onto our own saved record rather than conflict with it.
            auto record=state(app.page(),"passwords")["rows"][0];
            click(app,("edit-password-"+record["id"].get<std::string>()).c_str());
            screenshot(app,L"passwords-edit.png");
            assert(!ui::GetContext().GetWindow(app.window())->Root()->FindById("password-"+record["id"].get<std::string>()));
            auto password_input=ui_widget_find_by_id(ui_page_root(app.page()),"passwordValue"); assert(password_input);
            ui_text_area_set_text(password_input,L""); ui_widget_destroy(password_input);
            click(app,"passwordValue"); ui_debug_type_text(app.window(),L"edited password");
            {
                FileMutex hold(dir/"builtin_passwords.json");
                click(app,"passwordScopes"); ui_debug_pump();
                click(app,"passwordValue"); assert(ui_debug_key(app.window(),VK_END)==0); ui_debug_type_text(app.window(),L" latest");
                ui_window_focus_widget(app.window(),0); ui_debug_pump();
            }
            finish_input(app);
            assert(state(app.page(),"passwordEditor")==true);
            assert(parse_json(state(app.page(),"passwordOriginal").get<std::string>())["value"]=="edited password latest");
            assert(read_json(dir/"builtin_passwords.json")["passwords"][0]["value"]=="edited password latest");
            auto projected_after_edit=state(app.page(),"passwords")["rows"];
            assert(projected_after_edit.size()==saved_rows.size());
            assert(projected_after_edit[0]["value"]=="edited password latest");
            assert(projected_after_edit[0]["id"]==projected_after_edit[0]["original"].get<std::string>()+"#0");
            assert(projected_after_edit[1]==saved_rows[1]); // untouched row retained by delta
            auto other=state(app.page(),"passwords")["rows"][1];
            auto history_before_delete=read_json(dir/"builtin_passwords.json")["clipboard_history"];
            click(app,("delete-password-"+other["id"].get<std::string>()).c_str()); finish_input(app);
            assert(read_json(dir/"builtin_passwords.json")["passwords"].size()==4);
            assert(state(app.page(),"passwordEditor")==true);
            assert(state(app.page(),"passwordValue")=="edited password latest");
            assert(read_json(dir/"builtin_passwords.json")["clipboard_history"]==history_before_delete);
            click(app,"deletePassword"); finish_input(app);
            assert(read_json(dir/"builtin_passwords.json")["passwords"].size()==3);
            assert(state(app.page(),"passwordEditor")==false);
            click(app,"tabTasks"); pump([&]{return state(app.page(),"tab")=="tasks";});
            click(app,("directory-"+utf8(path_key(pending_second))).c_str());
            auto edit_root_bounds=rect(app,"editSelectedRoot"), delete_root_bounds=rect(app,"deleteSelectedRoot");
            assert(edit_root_bounds.top==delete_root_bounds.top && edit_root_bounds.bottom==delete_root_bounds.bottom);
            button_texts(app);
            click(app,"deleteSelectedRoot"); finish_input(app);
            assert(state(app.page(),"taskRoot")=="");
            assert(read_roots(dir/"sunpack_watch_roots.txt").entries.size()==2);
            assert(fs::is_directory(pending_second));
            click(app,("directory-"+utf8(path_key(pending_root))).c_str());
            pump([&]{return state(app.page(),"taskRoot")==utf8(pending_root.wstring());});
            click(app,"editSelectedRoot"); ui_debug_pump();
            click(app,"rootOutput"); ui_debug_type_text(app.window(),L"automatic-output");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            finish_input(app);
            auto deep=ui_widget_find_by_id(ui_page_root(app.page()),"rootDeepToggle"); assert(deep);
            assert(ui_debug_toggle_set(app.window(),deep,1)==0); ui_widget_destroy(deep);
            finish_input(app);
            assert(state(app.page(),"rootEditor")==true);
            bool updated=false;
            auto root_snapshot=read_roots(dir/"sunpack_watch_roots.txt");
            for(auto& entry:root_snapshot.entries)
                if(path_key(entry.input)==path_key(pending_root)) { updated=entry.output=="automatic-output" && entry.deep; }
            assert(updated);
            click(app,"deleteSelectedRoot"); finish_input(app);
            assert(state(app.page(),"rootEditor")==false);
            assert(read_roots(dir/"sunpack_watch_roots.txt").entries.size()==1);
            assert(fs::is_directory(pending_root));
            pump([&]{return state(app.page(),"taskRoot")=="";});

            auto main=utf8((dir/"carrier.001").wstring()), sibling=utf8((dir/"disguised.blob").wstring());
            atomic_write(dir/".sunpack_watch"/"events.jsonl",
                Json{{"event","pipeline_sources_claimed"},{"path",sibling},{"groups",Json::array({
                    Json{{"path",main},{"name","movie.7z"},{"members",{main,sibling}}}})}}.dump()+"\n"+
                Json{{"event","failed_password"},{"path",sibling}}.dump()+"\n");
            try { pump([&]{return state(app.page(),"tasks")["rows"][0]["status"]=="taskWaiting";}); }
            catch(...) { std::cerr<<"Log model: "<<state(app.page(),"tasks")<<" errors="<<state(app.page(),"errors")<<"\n"; throw; }
            auto grouped=state(app.page(),"tasks")["rows"][0];
            assert(grouped["name"]=="movie.7z" && grouped["partCount"]==2);
            assert(state(app.page(),"statusNames")==Json::array({"","taskProcessing","taskWaiting","taskSucceeded","taskFailed"}));
            assert(rendered_widget(app,"taskRoot-"+grouped["id"].get<std::string>())["text"]==
                "已识别 2 个分卷 · 监控目录："+utf8(dir.wstring()));
            screenshot(app,L"grouped-waiting.png");
            std::cerr<<"Log replacement observed\n";
            atomic_write(dir/"sunpack_config.json","{");
            pump([&]{return state(app.page(),"errors").contains("sunpack_config.json");});
            std::cerr<<"Invalid configuration retained\n";
            assert(!state(app.page(),"fields").empty());
            atomic_write(dir/"elsewhere"/"events.jsonl",Json({{"event","done"},{"path",utf8((dir/"other.fake").wstring())}}).dump()+"\n");
            atomic_write(dir/"sunpack_config.json",R"({"watch":{"state_dir":"elsewhere"}})");
            try { pump([&]{return state(app.page(),"tasks")["rows"][0]["name"]=="other.fake";}); }
            catch(...) { std::cerr<<"Rebound log: "<<state(app.page(),"tasks")<<" errors="<<state(app.page(),"errors")<<" log="<<state(app.page(),"logPath")<<" fields="<<state(app.page(),"fields")<<"\n"; throw; }
            // Exercise an ordinary config containing all advanced settings.
            auto complete=parse_json(kUiDefaultsJson); complete["watch"]["state_dir"]="elsewhere";
            atomic_write(dir/"sunpack_config.json",complete.dump());
            pump([&]{return state(app.page(),"fields").size()>100;});
            ui_page_set_json(app.page(),"drafts","{}");
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_config(app,L"");
            ui_window_relayout(app.window());
            button_texts(app);
            auto startup_before=rect(app,"startupToggle");
            auto config_scroll=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll"); assert(config_scroll);
            virtual_tail(app,"configItems","configListScroll",state(app.page(),"matchingBlocks").size());
            ui_window_relayout(app.window()); button_texts(app);
            auto startup_after=rect(app,"startupToggle");
            assert(startup_before.right-startup_before.left==startup_after.right-startup_after.left);
            ui_debug_scroll_set(config_scroll,0);
            // Inspect the actual wheel result before any forced relayout can
            // repair a width computed without the window's text measurer.
            ui_debug_wheel(app.window(),config_scroll,-120);
            auto startup_wheel=rect(app,"startupToggle");
            if(std::abs((startup_before.right-startup_before.left)-(startup_wheel.right-startup_wheel.left))>0.1f)
                throw std::runtime_error("Wheel changed startup button width");
            button_texts(app,false);
            ui_debug_wheel(app.window(),config_scroll,120);
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
            assert(list_rect.bottom-list_rect.top>=132);
            auto button_before=rect(app,"newRoot");
            auto list=ui_widget_find_by_id(ui_page_root(app.page()),"directoryListScroll");
            assert(ui_debug_scroll_set(list,100000)==0); ui_widget_destroy(list); ui_window_relayout(app.window());
            auto button_after=rect(app,"newRoot");
            assert(button_before.left==button_after.left && button_before.right==button_after.right && button_before.top==button_after.top);
            auto button_info=rendered_widget(app,"newRoot");
            assert(button_info["textWidth"].get<float>()<=button_info["availWidth"].get<float>());
            virtual_tail(app,"directoryItems","directoryListScroll",73);
            assert(!ui_widget_find_by_id(ui_page_root(app.page()),"moreDirectories"));
            list=ui_widget_find_by_id(ui_page_root(app.page()),"directoryListScroll");
            assert(ui_debug_scroll_set(list,0)==0); ui_widget_destroy(list); ui_window_relayout(app.window());
            size_t visible=0;
            for(auto& directory:state(app.page(),"shownDirectories")) {
                auto handle=ui_widget_find_by_id(ui_page_root(app.page()),("directory-"+directory["id"].get<std::string>()).c_str());
                if(!handle) continue;
                auto bounds=ui_widget_get_rect(handle); ui_widget_destroy(handle);
                if(bounds.top>=list_rect.top && bounds.bottom<=list_rect.bottom) ++visible;
            }
            // Padded two-line directory cards still leave two complete rows
            // in the minimum window, instead of squeezing text into 32 px.
            assert(visible>=2);
            auto first=state(app.page(),"shownDirectories")[1];
            click(app,("directory-"+first["id"].get<std::string>()).c_str());
            pump([&]{return state(app.page(),"tasks")["total"]==0;});
            assert(state(app.page(),"chosenDirectory")["path"]==first["path"]);
            {
                auto card=rendered_widget(app,"directory-"+first["id"].get<std::string>());
                auto bounds=card["rect"], copy=card["children"][0]["rect"];
                assert(copy[1].get<float>()-bounds[1].get<float>()>=7);
                assert(bounds[3].get<float>()-copy[3].get<float>()>=7);
            }
            screenshot(app,L"directories-small.png");
            click(app,"editSelectedRoot");
            assert(state(app.page(),"rootInput")==first["path"]);
            click(app,"closeRootEditor"); click(app,"allRoots");
            click(app,"newRoot"); assert(state(app.page(),"rootEditor")==true);
            click(app,"closeRootEditor");
            ui_window_set_size(app.window(),1120,720); screenshot(app,L"directories.png");
            auto history=read_json(dir/"builtin_passwords.json"); history["clipboard_history"]=Json::array();
            for(int i=0;i<320;++i) history["clipboard_history"].push_back("candidate-"+std::to_string(i));
            history["clipboard_history"][0]="  #history value  ";
            for(int i=0;i<240;++i) history["passwords"].push_back({{"value","virtual-password-"+std::to_string(i)},
                {"scopes",Json::array({utf8(dir.wstring()),utf8((dir/"nested").wstring())})}});
            atomic_write(dir/"builtin_passwords.json",history.dump());
            click(app,"tabPasswords"); pump([&]{return state(app.page(),"tab")=="passwords";});
            click(app,"savedPasswords"); pump([&]{return state(app.page(),"passwords")["total"]==history["passwords"].size();});
            virtual_tail(app,"passwordItems","passwordListScroll",history["passwords"].size());
            click(app,"clipboardHistory"); pump([&]{return state(app.page(),"passwords")["total"]==320;});
            ui_window_set_size(app.window(),850,560); ui_window_relayout(app.window());
            virtual_tail(app,"passwordItems","passwordListScroll",320);
            auto history_view=rect(app,"passwordListScroll"); visible=0;
            auto history_rows=state(app.page(),"passwords")["rows"];
            for(auto& entry:history_rows) {
                auto handle=ui_widget_find_by_id(ui_page_root(app.page()),("password-"+entry["id"].get<std::string>()).c_str());
                if(!handle) continue;
                auto bounds=ui_widget_get_rect(handle); ui_widget_destroy(handle);
                if(bounds.bottom-bounds.top>44) std::cerr<<"History row: "<<rendered_widget(app,"password-"+entry["id"].get<std::string>())<<'\n';
                assert(bounds.bottom-bounds.top<=44);
                if(bounds.top>=history_view.top && bounds.bottom<=history_view.bottom) ++visible;
            }
            assert(visible>=6);
            auto copy_info=rendered_widget(app,"copy-history-0");
            assert(copy_info["textWidth"].get<float>()<=copy_info["availWidth"].get<float>());
            screenshot(app,L"clipboard-history-small.png");
            button_texts(app);
            click(app,"copy-history-0");
            assert(state(app.page(),"passwordValue")=="  #history value  ");
            assert(state(app.page(),"passwordOriginal")=="");
            assert(read_json(dir/"builtin_passwords.json")["clipboard_history"]==history["clipboard_history"]);
            click(app,"closePasswordEditor");
            click(app,"tabConfig"); pump([&]{return state(app.page(),"tab")=="config";});
            search_config(app,L"max_folders");
            auto invalid_input=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/max_folders"); assert(invalid_input);
            ui_text_input_set_text(invalid_input,L""); ui_widget_destroy(invalid_input);
            click(app,"input-/watch/max_folders"); ui_debug_type_text(app.window(),L"0");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            pump([&]{return state(app.page(),"saveErrors").contains("/watch/max_folders") && !state(app.page(),"saving").get<bool>();});
            assert(read_json(dir/"sunpack_config.json")["watch"]["max_folders"]==16);
            search_config(app,L"out_dir");
            auto independent=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir"); assert(independent);
            ui_text_input_set_text(independent,L""); ui_widget_destroy(independent);
            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"independent");
            assert(ui_debug_key(app.window(),VK_RETURN)==0);
            pump([&]{return read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="independent" && !state(app.page(),"saving").get<bool>();});
            assert(state(app.page(),"saveErrors").contains("/watch/max_folders"));
            PostMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_CLOSE,0,0);
            pump([&]{return state(app.page(),"closeError")!="" && !state(app.page(),"saving").get<bool>();});
            assert(IsWindow(static_cast<HWND>(ui_window_hwnd(app.window()))));
            search_config(app,L"max_folders");
            invalid_input=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/max_folders"); assert(invalid_input);
            ui_text_input_set_text(invalid_input,L""); ui_widget_destroy(invalid_input);
            click(app,"input-/watch/max_folders"); ui_debug_type_text(app.window(),L"17");
            finish_input(app);
            assert(read_json(dir/"sunpack_config.json")["watch"]["max_folders"]==17);
            search_config(app,L"out_dir");
            auto closing_input=ui_widget_find_by_id(ui_page_root(app.page()),"input-/watch/out_dir"); assert(closing_input);
            ui_text_input_set_text(closing_input,L""); ui_widget_destroy(closing_input);
            click(app,"input-/watch/out_dir"); ui_debug_type_text(app.window(),L"close-flush");
            PostMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_CLOSE,0,0);
            pump([&]{return !IsWindow(static_cast<HWND>(ui_window_hwnd(app.window())));});
            assert(read_json(dir/"sunpack_config.json")["watch"]["out_dir"]=="close-flush");
        }
        fs::remove_all(dir); std::cout<<"GUI interface and observation passed\n";
    } catch(const std::exception& e) { std::cerr<<e.what()<<"\n"; std::error_code ec; fs::remove_all(dir,ec); return 1; }
    CoUninitialize(); return 0;
}
