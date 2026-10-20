#include "application.hpp"
#include "gui_perf_defaults.h"
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/controls.h>
#include <ui/debug_trace.h>
#include <psapi.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <sstream>
#include <vector>

using namespace spg;
namespace {
using Clock=std::chrono::steady_clock;
struct CpuTime { uint64_t ticks=0; };
struct Samples { std::vector<double> wall,cpu_ms,cpu_mcycles; };
std::map<std::string,Samples> samples;
std::map<std::string,std::vector<double>> trace_samples;
std::mutex trace_mutex;
std::string trace_phase;
std::string active_action;
std::atomic<uint64_t> motion_stop_count{0}, paint_count{0}, animation_frame_count{0}, property_frame_count{0};
LARGE_INTEGER qpc_frequency{};

double now_ms() { LARGE_INTEGER v{}; QueryPerformanceCounter(&v); return 1000.0*v.QuadPart/qpc_frequency.QuadPart; }
CpuTime process_cpu() {
    FILETIME created{},exit{},kernel{},user{};
    if(!GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user)) return {};
    ULARGE_INTEGER k{},u{}; k.LowPart=kernel.dwLowDateTime; k.HighPart=kernel.dwHighDateTime;
    u.LowPart=user.dwLowDateTime; u.HighPart=user.dwHighDateTime;
    return {k.QuadPart+u.QuadPart};
}
uint64_t process_cycles() {
    ULONG64 cycles=0; QueryProcessCycleTime(GetCurrentProcess(),&cycles); return cycles;
}
uint64_t working_set() {
    PROCESS_MEMORY_COUNTERS_EX m{}; m.cb=sizeof(m);
    return GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&m),sizeof(m))
        ? m.WorkingSetSize : 0;
}
void trace_sink(const UiTraceEvent* e,void*) {
    if(!e) return;
    if(e->name && !std::strcmp(e->name,"motion_stopped")) motion_stop_count.fetch_add(1,std::memory_order_relaxed);
    if(e->name && !std::strcmp(e->name,"paint_and_validate")) paint_count.fetch_add(1,std::memory_order_relaxed);
    if(e->name && !std::strcmp(e->name,"animation_frame")) animation_frame_count.fetch_add(1,std::memory_order_relaxed);
    if(e->name && !std::strcmp(e->name,"property_animation_frame")) property_frame_count.fetch_add(1,std::memory_order_relaxed);
    bool has_duration=false,has_frame_interval=false;
    double duration=0,frame_interval=0;
    for(uint32_t i=0;i<e->field_count;++i) {
        const auto& f=e->fields[i];
        if(f.key && !std::strcmp(f.key,"duration_ms") && f.type==UI_TRACE_FIELD_F64) {
            duration=f.f64; has_duration=true;
        } else if(f.key && !std::strcmp(f.key,"frame_interval_ms") && f.type==UI_TRACE_FIELD_F64) {
            frame_interval=f.f64; has_frame_interval=true;
        }
    }
    if(!has_duration&&!has_frame_interval) return;
    std::lock_guard<std::mutex> lock(trace_mutex);
    const std::string name=e->name?e->name:"";
    if(has_duration) {
        trace_samples["all::"+name].push_back(duration);
        if(!trace_phase.empty()) trace_samples[trace_phase+"::"+name].push_back(duration);
    }
    if(has_frame_interval) {
        trace_samples["all::animation_frame_interval_ms"].push_back(frame_interval);
        if(!trace_phase.empty()) trace_samples[trace_phase+"::animation_frame_interval_ms"].push_back(frame_interval);
    }
}
template<class F> void measure(const std::string& name,F&& fn) {
    { std::lock_guard<std::mutex> lock(trace_mutex); trace_phase=name; }
    active_action=name;
    const double wall=now_ms(); const auto cycles=process_cycles(); const auto cpu=process_cpu();
    fn();
    const auto cpu_after=process_cpu(); const auto cycles_after=process_cycles(); const double elapsed=now_ms()-wall;
    { std::lock_guard<std::mutex> lock(trace_mutex); trace_phase.clear(); }
    active_action.clear();
    auto& out=samples[name]; out.wall.push_back(elapsed);
    out.cpu_ms.push_back(double(cpu_after.ticks-cpu.ticks)/10000.0);
    out.cpu_mcycles.push_back(double(cycles_after-cycles)/1000000.0);
    if(elapsed>1000) std::cerr<<"slow GUI sample: "<<name<<" took "<<std::fixed<<std::setprecision(1)<<elapsed<<" ms\n";
}
Json distribution(std::vector<double> values) {
    if(values.empty()) return {{"count",0}};
    std::sort(values.begin(),values.end());
    auto percentile=[&](double q) { return values[std::min(values.size()-1,size_t(std::ceil(q*values.size())-1))]; };
    double mean=std::accumulate(values.begin(),values.end(),0.0)/values.size();
    return {{"count",values.size()},{"mean",mean},{"p50",percentile(.50)},{"p95",percentile(.95)},{"max",values.back()}};
}
Json summarize() {
    Json actions=Json::object();
    for(auto& [name,s]:samples) {
        actions[name]={{"wall_ms",distribution(s.wall)},
            {"process_cpu_million_cycles",distribution(s.cpu_mcycles)}};
        if(name=="idle_5s") actions[name]["process_cpu_ms"]=distribution(s.cpu_ms);
    }
    Json traces=Json::object();
    std::lock_guard<std::mutex> lock(trace_mutex);
    for(auto& [name,values]:trace_samples) traces[name]=distribution(values);
    if(trace_samples.find("all::animation_frame_interval_ms")!=trace_samples.end()) {
        const auto& frames=trace_samples.at("all::animation_frame_interval_ms");
        traces["animation_frame_interval_ms"]["over_16_7ms"] = std::count_if(frames.begin(),frames.end(),[](double x){return x>16.7;});
        traces["animation_frame_interval_ms"]["over_33_3ms"] = std::count_if(frames.begin(),frames.end(),[](double x){return x>33.3;});
    }
    return {{"actions",actions},{"core_ui_trace",traces}};
}
Json page_state(UiPage page,const char* key) {
    char* raw=ui_page_get_json(page,key);
    if(!raw) throw std::runtime_error(std::string("Missing UI state: ")+key);
    Json value=Json::parse(raw); ui_page_free(raw); return value;
}
void pump_messages() {
    MSG m{};
    while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)) {
        if(m.message==WM_QUIT) continue;
        TranslateMessage(&m); DispatchMessageW(&m);
    }
}
template<class F> void wait_for(F&& ready,const char* phase,DWORD timeout=30000,DWORD max_slice=INFINITE) {
    const ULONGLONG end=GetTickCount64()+timeout;
    for(;;) {
        // Drain queued work before sampling state. Sampling first and pumping
        // afterwards meant a notification that had already been delivered
        // satisfied the predicate only when the next unrelated message (caret
        // blink, paint) arrived, inflating latency by up to a timer period.
        pump_messages();
        if(ready()) return;
        if(GetTickCount64()>=end) throw std::runtime_error(std::string("Timed out: ")+phase+
            (active_action.empty()?"":" during "+active_action));
        const DWORD left=DWORD(std::min<ULONGLONG>(end-GetTickCount64(),max_slice));
        MsgWaitForMultipleObjectsEx(0,nullptr,left,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    }
}
ui::Widget* widget(Application& app,const char* id) {
    auto window=ui::GetContext().GetWindow(app.window());
    auto root=window?window->Root():ui::WidgetPtr{};
    return root?root->FindById(id):nullptr;
}
size_t widget_count(const ui::Widget* w) {
    if(!w) return 0;
    size_t count=1;
    for(auto& c:w->Children()) count+=widget_count(c.get());
    return count;
}
size_t widget_count(Application& app) {
    auto window=ui::GetContext().GetWindow(app.window());
    return window?widget_count(window->Root().get()):0;
}
void click(Application& app,const char* id) {
    auto* w=widget(app,id); if(!w) throw std::runtime_error(std::string("Missing widget: ")+id);
    const auto r=w->rect;
    if(ui_debug_click_at(app.window(),(r.left+r.right)/2,(r.top+r.bottom)/2)!=0)
        throw std::runtime_error(std::string("Click failed: ")+id);
}
bool settled(ui::Widget* w,Application& app,ui::Widget* root) {
    if(!w->visible) return true;
    if(w->opacity<.999f || std::abs(w->animationX)>.02f) return false;
    if(w->id=="navIndicator") {
        auto tab=page_state(app.page(),"tab").get<std::string>();
        auto* target=root->FindById(tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":"tabPasswords");
        if(target && std::abs(w->rect.top+w->animationY+(w->rect.bottom-w->rect.top)/2-
            (target->rect.top+target->rect.bottom)/2)>.02f) return false;
    } else if(std::abs(w->animationY)>.02f) return false;
    for(auto& c:w->Children()) if(!settled(c.get(),app,root)) return false;
    return true;
}
// First widget that keeps the settle predicate false, for diagnosing stalls.
void describe_unsettled(ui::Widget* w,Application& app,ui::Widget* root,std::string& out) {
    if(!out.empty() || !w->visible) return;
    bool bad=w->opacity<.999f || std::abs(w->animationX)>.02f || std::abs(w->animationY)>.02f;
    if(w->id=="navIndicator") {
        auto tab=page_state(app.page(),"tab").get<std::string>();
        auto* target=root->FindById(tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":"tabPasswords");
        if(target && std::abs(w->rect.top+w->animationY+(w->rect.bottom-w->rect.top)/2-
            (target->rect.top+target->rect.bottom)/2)>.02f) bad=true;
    }
    if(bad) {
        std::ostringstream text;
        text<<"id="<<(w->id.empty()?"<none>":w->id)<<" opacity="<<w->opacity
            <<" x="<<w->animationX<<" y="<<w->animationY;
        if(w->id=="navIndicator") {
            auto tab=page_state(app.page(),"tab").get<std::string>();
            auto* target=root->FindById(tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":"tabPasswords");
            text<<" tab="<<tab<<" center="<<(w->rect.top+w->animationY+(w->rect.bottom-w->rect.top)/2)
                <<" target="<<(target?(target->rect.top+target->rect.bottom)/2:-1);
        }
        out=text.str();
        return;
    }
    for(auto& c:w->Children()) describe_unsettled(c.get(),app,root,out);
}
void wait_settled(Application& app) {
    auto root=ui::GetContext().GetWindow(app.window())->Root();
    const ULONGLONG start=GetTickCount64();
    ULONGLONG next_report=1000;
    uint64_t last_paint=paint_count.load(), last_anim=animation_frame_count.load(), last_prop=property_frame_count.load();
    wait_for([&]{
        if(settled(root.get(),app,root.get())) return true;
        const auto elapsed=GetTickCount64()-start;
        if(elapsed>=next_report) {
            next_report=elapsed+1000;
            std::string detail; describe_unsettled(root.get(),app,root.get(),detail);
            const uint64_t paints=paint_count.load(), anims=animation_frame_count.load(), props=property_frame_count.load();
            std::cerr<<"slow settle ("<<elapsed<<" ms): "<<detail
                     <<" paints=+"<<(paints-last_paint)<<" anim_frames=+"<<(anims-last_anim)
                     <<" prop_frames=+"<<(props-last_prop)<<'\n';
            last_paint=paints; last_anim=anims; last_prop=props;
        }
        return false;
    },"motion settle",5000,100);
}
void pump_for(DWORD duration_ms) {
    const auto end=GetTickCount64()+duration_ms;
    do {
        pump_messages();
        const auto now=GetTickCount64();
        if(now>=end) break;
        MsgWaitForMultipleObjectsEx(0,nullptr,DWORD(end-now),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    } while(GetTickCount64()<end);
    pump_messages();
}
void idle_sample(DWORD duration_ms) {
    const auto wall_start=now_ms(); const auto cpu_start=process_cpu(); const auto cycle_start=process_cycles();
    const auto end=GetTickCount64()+duration_ms;
    while(GetTickCount64()<end) {
        const DWORD remaining=DWORD(end-GetTickCount64());
        MsgWaitForMultipleObjectsEx(0,nullptr,remaining,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
        pump_messages();
    }
    const auto cpu_end=process_cpu(); const auto cycle_end=process_cycles(); const auto elapsed=now_ms()-wall_start;
    samples["idle_5s"].wall.push_back(elapsed);
    samples["idle_5s"].cpu_ms.push_back(double(cpu_end.ticks-cpu_start.ticks)/10000.0);
    samples["idle_5s"].cpu_mcycles.push_back(double(cycle_end-cycle_start)/1000000.0);
}
constexpr UINT kBenchmarkWakeMessage=WM_APP+0x3f0;
void ensure(bool ok,const char* message);
void scroll_list(Application& app,const char* scroll_id,const char* list_id,size_t rounds,Json& report) {
    auto handle=ui_widget_find_by_id(ui_page_root(app.page()),scroll_id);
    if(!handle) return;
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(widget(app,scroll_id));
    auto* list=dynamic_cast<ui::VirtualListWidget*>(widget(app,list_id));
    if(!scroll || !list || !scroll->NeedsScrollbar()) { ui_widget_destroy(handle); return; }
    ui_debug_scroll_set(handle,1000000.0f);
    const auto bounds=scroll->rect;
    for(size_t i=0;i<rounds;i++) measure(std::string("scroll_")+scroll_id,[&]{
        // Alternate between the middle and tail so each sample moves real rows.
        ensure(ui_debug_wheel_at(app.window(),(bounds.left+bounds.right)/2,(bounds.top+bounds.bottom)/2,
            (i%2)?-120.0f:120.0f)==0,"wheel failed");
        pump_messages();
    });
    report[std::string("mounted_")+scroll_id]=list->Children().size();
    ui_widget_destroy(handle);
}
void ensure(bool ok,const char* message) { if(!ok) throw std::runtime_error(message); }
void write_utf8(const fs::path& path,const std::string& data) { atomic_write(path,data); }
struct RunOptions { size_t tasks=5000,passwords=3000,history=3000,roots=250,rounds=30; };
RunOptions parse_args(int argc,wchar_t** argv) {
    RunOptions o;
    for(int i=1;i<argc;i+=2) {
        if(i+1>=argc) throw std::runtime_error("Each option requires a value");
        size_t v=std::stoull(argv[i+1]);
        if(std::wstring(argv[i])==L"--tasks") o.tasks=v;
        else if(std::wstring(argv[i])==L"--passwords") o.passwords=v;
        else if(std::wstring(argv[i])==L"--history") o.history=v;
        else if(std::wstring(argv[i])==L"--roots") o.roots=v;
        else if(std::wstring(argv[i])==L"--rounds") o.rounds=v;
        else throw std::runtime_error("Unknown option");
    }
    o.rounds=std::clamp<size_t>(o.rounds,5,100);
    return o;
}
void seed(const fs::path& dir,const RunOptions& o) {
    fs::create_directories(dir/".sunpack_watch");
    auto monitored=dir/"monitored"; fs::create_directories(monitored);
    Json config=Json::parse(kGuiPerfDefaultsJson);
    config["cli"]["language"]="en";
    config["watch"]["state_dir"]=".sunpack_watch";
    config["watch"]["out_dir"]=".";
    write_utf8(dir/"sunpack_config.json",config.dump(2)+"\n");
    std::string roots;
    roots+=utf8(monitored.wstring())+"\n";
    for(size_t i=0;i<o.roots;i++) {
        auto path=dir/(L"folder-"+std::to_wstring(i)); fs::create_directories(path);
        roots+=utf8(path.wstring())+"\n";
    }
    write_utf8(dir/"sunpack_watch_roots.txt",roots);
    std::string log; log.reserve(o.tasks*220);
    for(size_t i=0;i<o.tasks;i++) {
        std::ostringstream name; name<<"task-"<<std::setw(8)<<std::setfill('0')<<i<<".zip";
        Json row={{"event",i%5==0?"failed_terminal":"done"},
            {"path",utf8((monitored/name.str()).wstring())},
            {"time","2026-10-19T09:15:42.731112+00:00"},
            {"ts",static_cast<double>(i+1)},
            {"output_dirs",Json::array({"."})}};
        log+=row.dump()+"\n";
    }
    write_utf8(dir/".sunpack_watch"/"events.jsonl",log);
    Json passwords=Json::array(),history=Json::array();
    for(size_t i=0;i<o.passwords;i++) passwords.push_back({{"value","saved-password-"+std::to_string(i)},{"scopes",Json::array({utf8(monitored.wstring())})}});
    for(size_t i=0;i<o.history;i++) history.push_back("clipboard-password-"+std::to_string(i));
    write_utf8(dir/"builtin_passwords.json",Json{{"passwords",passwords},{"clipboard_history",history}}.dump(2)+"\n");
}
}

int wmain(int argc,wchar_t** argv) {
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    fs::path dir;
    try {
        QueryPerformanceFrequency(&qpc_frequency);
        const auto options=parse_args(argc,argv);
        dir=fs::temp_directory_path()/(L"sunpack-gui-perf-"+std::to_wstring(GetCurrentProcessId()));
        fs::remove_all(dir); fs::create_directories(dir); seed(dir,options);
        Json report={{"build","Release"},{"window_dip",{1120,720}},
            {"list_counts",{{"tasks",options.tasks},{"passwords",options.passwords},{"clipboard_history",options.history},{"roots",options.roots+1}}},
            {"rounds",options.rounds}};
        PROCESS_MEMORY_COUNTERS_EX memory{}; memory.cb=sizeof(memory);
        GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),sizeof(memory));
        report["memory_mib_before_ui"] = double(memory.WorkingSetSize)/1048576.0;
        ui_trace_set_sink(trace_sink,nullptr);
        {
            spg::Options app_options; app_options.data_dir=dir; app_options.allow_cli=false;
            Application app(app_options);
            const double open_start=now_ms(); app.open();
            report["app_open_ms"]=now_ms()-open_start;
            report["memory_mib_after_open"]=double(working_set())/1048576.0;
            measure("initial_data_load",[&]{
                // `ready` is published in the same patch as the first task and
                // password projections, so it is both a sufficient gate and a
                // cheap one: serializing 5000 rows per poll would tax the
                // harness more than the app.
                wait_for([&]{return page_state(app.page(),"ready")==true;},"initial data load");
            });
            report["open_to_ready_ms"]=now_ms()-open_start;
            report["memory_mib_after_data"]=double(working_set())/1048576.0;
            ensure(page_state(app.page(),"tasks").value("total",0)==options.tasks,"initial task count");
            ensure(page_state(app.page(),"passwords").value("total",0)==options.passwords,"initial password count");
            report["widgets_after_load"]=widget_count(app);
            ui_window_set_size(app.window(),1120,720); ui_window_relayout(app.window());
            wait_settled(app);

            // Apply/query cost of the two large projections in their production
            // form: JSON text -> page state (QuickJS) and page state -> JSON.
            auto state_text=[&](const char* key) {
                char* raw=ui_page_get_json(app.page(),key);
                if(!raw) throw std::runtime_error(std::string("Missing UI state: ")+key);
                std::string text(raw); ui_page_free(raw); return text;
            };
            auto tasks_text=state_text("tasks"), passwords_text=state_text("passwords");
            measure("state_query_tasks",[&]{ensure(page_state(app.page(),"tasks").value("total",0)==options.tasks,"task state query");});
            measure("state_apply_tasks",[&]{ensure(ui_page_set_json(app.page(),"tasks",tasks_text.c_str())==0,"task state apply");});
            measure("state_apply_tasks_commit",[&]{pump_messages();});
            measure("state_query_passwords",[&]{ensure(page_state(app.page(),"passwords").value("total",0)==options.passwords,"password state query");});
            measure("state_apply_passwords",[&]{ensure(ui_page_set_json(app.page(),"passwords",passwords_text.c_str())==0,"password state apply");});
            measure("state_apply_passwords_commit",[&]{pump_messages();});
            auto tasks_document=Json::parse(tasks_text);
            measure("json_dump_tasks",[&]{ensure(!tasks_document.dump().empty(),"task dump");});

            auto nav=[&](const char* button,const char* page,const char* tag="page_switch") {
                measure(std::string(tag)+"_dispatch",[&]{
                    click(app,button);
                    wait_for([&]{return page_state(app.page(),"tab")==page;},"page switch");
                });
                measure(std::string(tag)+"_settled",[&]{wait_settled(app);});
            };
            scroll_list(app,"taskListScroll","taskItems",options.rounds,report);
            scroll_list(app,"directoryListScroll","directoryItems",options.rounds,report);
            for(size_t i=0;i<std::min<size_t>(options.rounds,12);++i) {
                const int width=(i%3==0)?900:(i%3==1)?1320:1120;
                measure("resize_and_relayout",[&]{
                    ui_window_set_size(app.window(),width,720);
                    ui_window_relayout(app.window());
                    pump_messages();
                });
            }
            ui_window_set_size(app.window(),1120,720); ui_window_relayout(app.window());

            nav("tabConfig","config");
            scroll_list(app,"configListScroll","configItems",options.rounds,report);
            auto config_fields=page_state(app.page(),"fields");
            report["config_field_count"]=config_fields.size();
            // Same interaction at both ends of the session: a per-switch cost
            // that grows here means state (widgets, JS heap) accumulates.
            for(size_t i=0;i<5;i++) { nav("tabConfig","config","page_switch_baseline"); nav("tabTasks","tasks","page_switch_baseline"); }
            for(size_t i=0;i<options.rounds;i++) {
                nav("tabConfig","config"); nav("tabPasswords","passwords"); nav("tabTasks","tasks");
            }
            report["widgets_after_nav"]=widget_count(app);
            report["memory_mib_after_nav"]=double(working_set())/1048576.0;

            nav("tabConfig","config");
            const std::string combo_id="themeSelector";
            auto config_scroll_handle=ui_widget_find_by_id(ui_page_root(app.page()),"configListScroll");
            if(config_scroll_handle) { ui_debug_scroll_set(config_scroll_handle,0); ui_widget_destroy(config_scroll_handle); ui_window_relayout(app.window()); }
            auto* combo=dynamic_cast<ui::ComboBoxWidget*>(widget(app,combo_id.c_str()));
            ensure(combo,"theme selector unavailable");
            auto combo_handle=ui_widget_find_by_id(ui_page_root(app.page()),combo_id.c_str());
            auto* config_scroll=dynamic_cast<ui::ScrollViewWidget*>(widget(app,"configListScroll"));
            ensure(combo_handle&&config_scroll,"dropdown test controls unavailable");
            const float dismiss_x=config_scroll->rect.left+16.0f;
            const float dismiss_y=(config_scroll->rect.top+config_scroll->rect.bottom)/2;
            size_t popup_open_completed=0,popup_scroll_close_completed=0;
            for(size_t i=0;i<std::min<size_t>(options.rounds,20);i++) {
                measure("dropdown_open_dispatch",[&]{
                    click(app,combo_id.c_str());
                    ensure(combo->IsOpen(),"dropdown did not open");
                });
                measure("dropdown_open_animation_window_220ms",[&]{pump_for(220);});
                if(!combo->PopupAnimating()) ++popup_open_completed;
                measure("dropdown_scroll_dismiss_dispatch",[&]{
                    ensure(ui_debug_wheel_at(app.window(),dismiss_x,dismiss_y,120.0f)==0,"dropdown wheel failed");
                    pump_messages(); ensure(!combo->IsOpen(),"wheel did not dismiss dropdown");
                });
                measure("dropdown_scroll_close_animation_window_120ms",[&]{pump_for(120);});
                if(!combo->PopupAnimating()) ++popup_scroll_close_completed;
            }
            report["popup_open_completed_within_220ms"]=popup_open_completed;
            report["popup_scroll_close_completed_within_120ms"]=popup_scroll_close_completed;
            report["motion_stopped_events"]=motion_stop_count.load(std::memory_order_relaxed);
            ui_widget_destroy(combo_handle);

            nav("tabPasswords","passwords");
            scroll_list(app,"passwordListScroll","passwordItems",options.rounds,report);
            auto password_scroll=ui_widget_find_by_id(ui_page_root(app.page()),"passwordListScroll");
            if(password_scroll) { ui_debug_scroll_set(password_scroll,0); ui_widget_destroy(password_scroll); ui_window_relayout(app.window()); }
            std::atomic<bool> password_file_changed{false};
            DirectoryWatcher password_watcher(dir,[&](const fs::path& changed){
                if(changed.filename()==L"builtin_passwords.json") {
                    password_file_changed.store(true,std::memory_order_release);
                    PostMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),kBenchmarkWakeMessage,0,0);
                }
            });
            auto rows=page_state(app.page(),"passwords").at("rows");
            auto edit_id="edit-password-"+rows.at(0).at("id").get<std::string>();
            for(size_t i=0;i<options.rounds;i++) {
                measure("password_edit_open",[&]{click(app,edit_id.c_str()); wait_for([&]{return page_state(app.page(),"passwordEditor")==true;},"password editor");});
                measure("password_edit_close",[&]{click(app,"closePasswordEditor"); wait_for([&]{return page_state(app.page(),"passwordEditor")==false;},"password editor close");});
            }
            for(size_t i=0;i<std::min<size_t>(options.rounds,1);i++) {
                auto current=page_state(app.page(),"passwords").at("rows").at(0);
                auto current_edit_id="edit-password-"+current.at("id").get<std::string>();
                auto replacement="perf-edited-"+std::to_string(i);
                measure("password_edit_form_open",[&]{
                    click(app,current_edit_id.c_str());
                    wait_for([&]{return page_state(app.page(),"passwordEditor")==true;},"password editor open");
                });
                measure("password_edit_input",[&]{
                    click(app,"passwordValue");
                    ensure(ui_debug_key_mod(app.window(),'A',1,0,0)==0,"select password failed");
                    ensure(ui_debug_type_char(app.window(),8)==0,"clear password failed");
                    ensure(ui_debug_type_text(app.window(),wide(replacement).c_str())==0,"edit password failed");
                });
                measure("password_edit_commit_dispatch",[&]{
                    click(app,"closePasswordEditor");
                });
                measure("password_edit_file_replace_wait",[&]{
                    wait_for([&]{return password_file_changed.load(std::memory_order_acquire);},"password file replace");
                });
                measure("password_edit_ui_ack_wait",[&]{
                    wait_for([&]{
                        // Cheap flags first: only the final poll pays for a full
                        // password-list serialization.
                        if(page_state(app.page(),"passwordEditor").get<bool>()) return false;
                        if(page_state(app.page(),"recordSaving").value("passwords",false)) return false;
                        auto state=page_state(app.page(),"passwords");
                        return !state.at("rows").empty() && state.at("rows").at(0).value("value",std::string())==replacement;
                    },"password auto-save");
                });
                // Harness cost of a full password-state serialization, taken after
                // the ack so it cannot shorten the measured save latency.
                measure("password_state_query",[&]{page_state(app.page(),"passwords");});
            }
            click(app,"clipboardHistory");
            wait_for([&]{return page_state(app.page(),"passwords").value("total",0)==options.history;},"clipboard history");
            scroll_list(app,"passwordListScroll","passwordItems",options.rounds,report);

            nav("tabTasks","tasks");
            click(app,"taskSearch");
            ui_debug_key_mod(app.window(),'A',1,0,0); ui_debug_type_char(app.window(),8);
            const size_t target=options.tasks-1;
            std::ostringstream query; query<<"task-"<<std::setw(8)<<std::setfill('0')<<target;
            measure("task_search_input",[&]{
                ensure(ui_debug_type_text(app.window(),wide(query.str()).c_str())==0,"search input failed");
            });
            measure("task_search_result_wait",[&]{
                wait_for([&]{return page_state(app.page(),"tasks").value("total",0)==1;},"task search result");
            });
            ui_debug_key_mod(app.window(),'A',1,0,0); ui_debug_type_char(app.window(),8);
            wait_for([&]{return page_state(app.page(),"tasks").value("total",0)==options.tasks;},"clear task search");
            wait_settled(app);
            report["widgets_after_ui"]=widget_count(app);
            for(size_t i=0;i<5;i++) { nav("tabConfig","config","page_switch_end"); nav("tabTasks","tasks","page_switch_end"); }
            const uint64_t idle_paint_start=paint_count.load(), idle_anim_start=animation_frame_count.load(),
                idle_prop_start=property_frame_count.load();
            idle_sample(5000);
            // Idle must stay quiet: a lingering animation timer shows up here as
            // one paint/animation frame per timer tick.
            report["idle_paints"]=paint_count.load()-idle_paint_start;
            report["idle_animation_frames"]=animation_frame_count.load()-idle_anim_start;
            report["idle_property_frames"]=property_frame_count.load()-idle_prop_start;
            ui_trace_set_sink(nullptr,nullptr);
            report["memory_mib_after_ui"] = double(working_set())/1048576.0;
        }
        auto password_document=read_json(dir/"builtin_passwords.json");
        auto original=password_document["passwords"].at(0);
        Json edit={{"operation","replace"},{"original",original.dump()},{"value","perf-direct-file-write"},{"scopes",original.value("scopes",Json::array())}};
        measure("password_model_write_existing_3000_records",[&]{
            auto result=save_changes(dir,Json::array(),Json::array({edit}),Json::array());
            ensure(result.value("error",std::string()).empty(),"direct password write failed");
        });
        report["password_file_bytes"]=fs::file_size(dir/"builtin_passwords.json");
        // Backend projection cost for one full refresh, measured without the UI
        // so the startup budget can be split into file->model vs model->pixels.
        auto backend_config=read_json(dir/"sunpack_config.json");
        auto backend_config_text=read_file(dir/"sunpack_config.json");
        auto backend_roots=read_roots(dir/"sunpack_watch_roots.txt");
        auto backend_passwords=read_json(dir/"builtin_passwords.json");
        EventLog backend_log; backend_log.set_path(dir/".sunpack_watch"/"events.jsonl");
        measure("model_log_refresh",[&]{
            ensure(backend_log.refresh(true),"event log refresh failed");
            ensure(backend_log.tasks.size()==options.tasks,"event log task count");
        });
        View backend_view;
        measure("model_task_rows",[&]{
            ensure(task_rows(backend_log,backend_roots,backend_view,"en").value("total",0)==options.tasks,"task projection count");
        });
        measure("model_password_rows",[&]{
            ensure(password_rows(backend_passwords,backend_view,"en").value("total",0)==options.passwords,"password projection count");
        });
        measure("model_config_fields",[&]{
            ensure(config_fields(backend_config,backend_config_text,"en").size()==report["config_field_count"].get<size_t>(),"config projection count");
        });
        measure("model_directory_rows",[&]{
            ensure(directory_rows(backend_roots,backend_config).size()==options.roots+1,"directory projection count");
        });
        report.update(summarize());
        fs::remove_all(dir);
        std::cout<<report.dump(2)<<'\n';
        CoUninitialize();
        return 0;
    } catch(const std::exception& e) {
        ui_trace_set_sink(nullptr,nullptr);
        if(!dir.empty() && dir.parent_path()==fs::temp_directory_path() && dir.filename().wstring().find(L"sunpack-gui-perf-")==0) {
            std::error_code ec; fs::remove_all(dir,ec);
        }
        std::cerr<<"GUI performance run failed: "<<e.what()<<'\n';
        CoUninitialize();
        return 1;
    }
}
