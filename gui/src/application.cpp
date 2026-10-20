#include "application.hpp"
#include "motion.hpp"
#include "presentation.hpp"
#include "main_uix.h"
#include <commctrl.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <sstream>
#include <chrono>
#include <map>

namespace spg {
namespace {
// Keep host messages outside Core UI's startup/render message range.
constexpr UINT Dispatch = WM_APP + 0x401, Update = WM_APP + 0x402;
constexpr unsigned Config = 1, Passwords = 2, Roots = 4, Log = 8, Startup = 16;
using Clock=std::chrono::steady_clock;
struct VisualBatch {
    UiWindow window;
    explicit VisualBatch(UiWindow w):window(w) { ui_window_begin_canvas_visual_transaction(w); }
    ~VisualBatch() { ui_window_end_canvas_visual_transaction(window); }
};
struct ReadRetry {
    unsigned attempts=0;
    Clock::time_point due=Clock::time_point::max();
};
UiThemeMode system_theme() {
    DWORD light=1, size=sizeof(light);
    RegGetValueW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme",RRF_RT_REG_DWORD,nullptr,&light,&size);
    return light?UI_THEME_LIGHT:UI_THEME_DARK;
}
Json page_value(UiPage page,const char* name) {
    char* value=ui_page_get_json(page,name);
    if(!value) return Json();
    std::string text(value); ui_page_free(value); return parse_json(text);
}
void set_text(UiPage page,const char* name,const std::string& value) {
    auto encoded=Json(value).dump(); ui_page_set_json(page,name,encoded.c_str());
}
void style_frame(HWND hwnd,UiThemeMode mode) {
    BOOL dark=mode==UI_THEME_DARK;
    BOOL disable_transitions=FALSE;
    DwmSetWindowAttribute(hwnd,DWMWA_TRANSITIONS_FORCEDISABLED,&disable_transitions,sizeof(disable_transitions));
    COLORREF background=dark?RGB(32,32,32):RGB(243,243,243);
    COLORREF foreground=dark?RGB(255,255,255):RGB(26,26,26);
    auto corners=DWMWCP_ROUND;
    // These optional Win11 attributes fail harmlessly on older Windows builds.
    DwmSetWindowAttribute(hwnd,DWMWA_USE_IMMERSIVE_DARK_MODE,&dark,sizeof(dark));
    DwmSetWindowAttribute(hwnd,DWMWA_CAPTION_COLOR,&background,sizeof(background));
    DwmSetWindowAttribute(hwnd,DWMWA_TEXT_COLOR,&foreground,sizeof(foreground));
    DwmSetWindowAttribute(hwnd,DWMWA_WINDOW_CORNER_PREFERENCE,&corners,sizeof(corners));
}
void apply_theme(UiPage page,UiThemeMode mode,HWND hwnd=nullptr) {
    auto appearance=mode==UI_THEME_DARK?"dark":"light";
    if(page_value(page,"appearance")==appearance) return;
    ui_theme_set_mode(mode);
    set_text(page,"appearance",appearance);
    if(hwnd) style_frame(hwnd,mode);
}
}
Options parse_options(const std::vector<std::wstring>& args) {
    Options result; auto exe=executable_path().parent_path();
    bool custom=false;
    for(size_t i=0;i<args.size();++i) {
        if(args[i]==L"--data-dir" && i+1<args.size()) { result.data_dir=resolve_path(args[++i]); custom=true; }
        else if(args[i]==L"--cli" && i+1<args.size()) result.cli.executable=resolve_path(args[++i]);
        else if(args[i]==L"--cli-prefix" && i+1<args.size()) result.cli.prefix.push_back(args[++i]);
        else throw std::runtime_error("guiArguments");
    }
    if(result.data_dir.empty()) {
        PWSTR dir=nullptr;
        if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData,0,nullptr,&dir))) throw std::runtime_error("programDataUnavailable");
        result.data_dir=fs::path(dir)/"SunPack"; CoTaskMemFree(dir);
    }
    // A fixture data directory cannot control the installed runtime accidentally.
    result.allow_cli=!custom || !result.cli.executable.empty();
    if(result.cli.executable.empty()) result.cli.executable=exe/"bin"/"sunpack.exe";
    result.cli.cwd=result.data_dir;
    return result;
}
void Application::changed(unsigned flags) {
    { std::lock_guard<std::mutex> lock(mutex_); if(stopping_) return; dirty_|=flags; }
    cv_.notify_one();
}
void Application::publish(Json patch) {
    std::lock_guard<std::mutex> lock(mutex_);
    if(stopping_) return;
    // Preserve all deltas while an earlier UI update is still pending.
    // A later full snapshot supersedes previous incremental updates.
    if(patch.contains("tasks")) pending_.erase("taskDelta");
    if(patch.contains("passwords")) pending_.erase("passwordDelta");
    if(patch.contains("passwordDelta") && pending_.contains("passwords")) patch.erase("passwordDelta");
    if(patch.contains("taskDelta") && pending_.contains("taskDelta")) {
        for(auto& change:patch["taskDelta"]["changes"])
            pending_["taskDelta"]["changes"].push_back(std::move(change));
        pending_["taskDelta"]["malformed"]=patch["taskDelta"]["malformed"];
        patch.erase("taskDelta");
    }
    for(auto it=patch.begin();it!=patch.end();++it) pending_[it.key()]=std::move(it.value());
    if(!notified_) { notified_=true; PostMessageW(hwnd_,Update,0,0); }
}
void Application::set_error(const char* field,const std::string& message) {
    Json value="";
    if(!message.empty()) value={{"source",message},{"text",translated_error(message,page_value(page_,"language").get<std::string>())}};
    auto encoded=value.dump(); ui_page_set_json(page_,field,encoded.c_str());
}
void Application::save_error(const std::string& key,const std::string& message) {
    auto errors=page_value(page_,"saveErrors");
    if(message.empty()) errors.erase(key);
    else errors[key]={{"source",message},{"text",translated_error(message,page_value(page_,"language").get<std::string>())}};
    auto encoded=errors.dump(); ui_page_set_json(page_,"saveErrors",encoded.c_str());
}
void Application::refresh_error_texts() {
    auto language=page_value(page_,"language").get<std::string>();
    auto refresh=[&](Json& error) {
        if(error.is_object() && error.contains("source")) error["text"]=translated_error(error["source"].get<std::string>(),language);
    };
    auto errors=page_value(page_,"saveErrors");
    for(auto& error:errors) refresh(error);
    auto encoded=errors.dump(); ui_page_set_json(page_,"saveErrors",encoded.c_str());
    for(auto field:{"actionError","closeError"}) {
        auto error=page_value(page_,field); refresh(error);
        encoded=error.dump(); ui_page_set_json(page_,field,encoded.c_str());
    }
}
bool Application::field_pending(const std::string& id) const {
    auto match=[&](const Json& job){return job.is_object() && job.value("kind",std::string())=="config" && job.value("key",std::string())==id;};
    return match(active_save_) || std::any_of(saves_.begin(),saves_.end(),match);
}
void Application::save_field(const std::string& id,Json draft) {
    try {
        if(draft.is_null()) {
            auto drafts=page_value(page_,"drafts"), toggles=page_value(page_,"toggleDrafts");
            if(drafts.contains(id)) draft=drafts[id];
            else if(toggles.contains(id)) draft=toggles[id];
            else return;
        }
        auto fields=page_value(page_,"fields");
        auto field=std::find_if(fields.begin(),fields.end(),[&](const Json& f){return f["id"]==id;});
        if(field==fields.end()) throw std::runtime_error("configConflict");
        auto text=draft.at("text").get<std::string>();
        if((*field)["editor"]=="lines") {
            Json lines=Json::array(); std::istringstream input(text); std::string line;
            while(std::getline(input,line)) { if(!line.empty() && line.back()=='\r') line.pop_back(); if(!line.empty()) lines.push_back(line); }
            text=lines.dump();
        }
        Json edit={{"pointer",id},{"label",(*field)["label"]},{"original",draft["original"]},
            {"type",(*field)["editor"]=="recursive"?Json("string"):(*field)["type"]},
            {"text",text},{"boolean",draft["boolean"]},{"draft",draft}};
        queue_save(Json{{"kind","config"},{"key",id},{"fields",Json::array({edit})}});
    } catch(const std::exception& e) { save_error(id,e.what()); }
}
void Application::queue_save(Json job) {
    const auto kind=job.at("kind").get<std::string>();
    if(kind!="config" && kind!="passwords" && kind!="roots") return;
    auto key=job.at("key");
    set_text(page_,"closeError","");
    save_error(kind=="config"?key.get<std::string>():"@"+kind,"");
    auto previous=std::find_if(saves_.begin(),saves_.end(),[&](const Json& queued){return queued["kind"]==kind && queued["key"]==key;});
    if(previous!=saves_.end()) *previous=std::move(job); else saves_.push_back(std::move(job));
    start_save();
}
void Application::start_save() {
    if(active_save_.is_null() && !saves_.empty()) {
        active_save_=std::move(saves_.front()); saves_.pop_front();
        { std::lock_guard<std::mutex> lock(mutex_); commands_.push_back(Json{{"op","commit"},{"payload",active_save_}}); }
        cv_.notify_one();
    }
    Json pending=Json::array(), records={{"passwords",false},{"roots",false}};
    auto include=[&](const Json& job) {
        if(job.is_null()) return;
        auto kind=job.at("kind").get<std::string>();
        if(kind=="config") pending.push_back(job["key"]); else records[kind]=true;
    };
    include(active_save_); for(auto& job:saves_) include(job);
    auto text=pending.dump(); ui_page_set_json(page_,"pendingFields",text.c_str());
    text=records.dump(); ui_page_set_json(page_,"recordSaving",text.c_str());
    ui_page_set_bool(page_,"saving",!active_save_.is_null());
}
void Application::acknowledge_save(const Json& ack) {
    const auto& job=ack.at("job"); auto kind=job.at("kind").get<std::string>();
    bool ok=ack.at("ok").get<bool>();
    save_error(kind=="config"?job["key"].get<std::string>():"@"+kind,ack.at("error"));
    if(ok && kind=="config") {
        const auto& edit=job["fields"][0]; auto id=edit["pointer"].get<std::string>();
        auto original=edit["type"]=="string"?Json(edit["text"]).dump():edit["type"]=="boolean"?Json(edit["boolean"]).dump():edit["text"].get<std::string>();
        for(auto name:{"drafts","toggleDrafts"}) {
            auto drafts=page_value(page_,name);
            if(drafts.contains(id)) {
                auto& current=drafts[id];
                if(current["original"]==edit["original"]) {
                    bool same=edit["type"]=="boolean"?current["boolean"]==edit["boolean"]:current["text"]==edit["draft"]["text"];
                    if(same) drafts.erase(id);
                    else { current["original"]=original; current["baselineText"]=edit["draft"]["text"]; current["baselineBoolean"]=edit["draft"]["boolean"]; }
                }
            }
            auto text=drafts.dump(); ui_page_set_json(page_,name,text.c_str());
        }
        for(auto& queued:saves_) if(queued["kind"]==kind && queued["key"]==job["key"] && queued["fields"][0]["original"]==edit["original"]) {
            queued["fields"][0]["original"]=original; queued["fields"][0]["draft"]["original"]=original;
        }
    } else if(ok) {
        bool password=kind=="passwords";
        auto session=password?"passwordSession":"rootSession";
        const auto& edit=job.at("edit");
        if(!password && edit["operation"]=="delete" && page_value(page_,"taskRoot")==edit["original"]) {
            set_text(page_,"taskRoot","");
            auto statuses=page_value(page_,"statusNames"); auto index=page_value(page_,"taskStatus").get<size_t>();
            handle_command(Json{{"op","filterTasks"},{"payload",{{"query",page_value(page_,"taskQuery")},{"root",""},{"status",statuses.at(index)}}}});
        }
        const bool replace=password?edit["operation"]=="replace":edit["operation"]=="save";
        Json baseline, expected; std::string original;
        if(replace && password) {
            Json record={{"value",edit["value"]}};
            std::string scopes;
            if(!edit["scopes"].empty()) record["scopes"]=edit["scopes"];
            for(auto& scope:edit["scopes"]) { if(!scopes.empty()) scopes+='\n'; scopes+=scope.get<std::string>(); }
            original=record.dump(); baseline={{"value",edit["value"]},{"scopes",scopes}};
        } else if(replace) {
            original=utf8(resolve_path(wide(edit["input"].get<std::string>()),options_.data_dir).wstring());
            auto output=edit["output"].get<std::string>(); auto first=output.find_first_not_of(" \t\r\n");
            output=first==std::string::npos?"":output.substr(first,output.find_last_not_of(" \t\r\n")-first+1);
            baseline={{"input",original},{"output",output},{"deep",edit["deep"]}};
            expected={{"output",output},{"deep",edit["deep"]}};
        }
        if(replace) for(auto& queued:saves_) if(queued["kind"]==kind && queued["key"]==job["key"]) {
            queued["edit"]["original"]=original;
            if(!password) queued["edit"]["expected"]=expected;
        }
        if(page_value(page_,session)==job["key"]) {
            Json current=password?Json{{"value",page_value(page_,"passwordValue")},{"scopes",page_value(page_,"scopeText")}}:
                Json{{"input",page_value(page_,"rootInput")},{"output",page_value(page_,"rootOutput")},{"deep",page_value(page_,"rootDeep")}};
            bool unchanged=current==job["snapshot"];
            if(replace) {
                set_text(page_,password?"passwordOriginal":"rootOriginal",original);
                set_text(page_,password?"passwordBaseline":"rootBaseline",baseline.dump());
                if(!password) { auto text=expected.dump(); ui_page_set_json(page_,"rootExpected",text.c_str()); }
                if(unchanged) {
                    set_text(page_,password?"passwordValue":"rootInput",baseline[password?"value":"input"]);
                    set_text(page_,password?"scopeText":"rootOutput",baseline[password?"scopes":"output"]);
                }
            }
            if(unchanged && job.contains("nextState")) {
                for(auto it=job["nextState"].begin();it!=job["nextState"].end();++it) { auto text=it.value().dump(); ui_page_set_json(page_,it.key().c_str(),text.c_str()); }
                if(job["nextState"].value(password?"passwordEditor":"rootEditor",false)) reveal_form(password);
                if(job["nextState"].contains(password?"passwordEditor":"rootEditor") && !job["nextState"][password?"passwordEditor":"rootEditor"].get<bool>()) {
                    if(password) for(auto name:{"passwordOriginal","passwordValue","scopeText","passwordBaseline"}) set_text(page_,name,"");
                    else for(auto name:{"rootOriginal","rootInput","rootOutput","rootBaseline"}) set_text(page_,name,"");
                }
                if(job["nextState"].contains("passwordScope")) handle_command(Json{{"op","filterPasswords"},{"payload",{{"query",page_value(page_,"passwordQuery")},{"scope",page_value(page_,"passwordScope")}}}});
                if(job["nextState"].contains("taskRoot")) {
                    auto statuses=page_value(page_,"statusNames"); auto index=page_value(page_,"taskStatus").get<size_t>();
                    handle_command(Json{{"op","filterTasks"},{"payload",{{"query",page_value(page_,"taskQuery")},{"root",page_value(page_,"taskRoot")},{"status",statuses.at(index)}}}});
                }
            }
        }
    }
    active_save_=Json();
}
void Application::apply_pending() {
    Json patch;
    { std::lock_guard<std::mutex> lock(mutex_); patch=std::move(pending_); pending_=Json::object(); notified_=false; }
    auto transition=patch.value("viewTransition",Json::object()); patch.erase("viewTransition");
    auto reset_scroll=patch.value("resetScroll",Json::array()); patch.erase("resetScroll");
    auto task_delta_patch=patch.value("taskDelta",Json()); patch.erase("taskDelta");
    auto password_delta_patch=patch.value("passwordDelta",Json()); patch.erase("passwordDelta");
    VisualBatch visual(window_);
    auto ack=patch.value("saveAck",Json()); patch.erase("saveAck");
    if(patch.contains("fields")) bind_controls(patch["fields"]);
    auto action=patch.value("actionError",Json()); patch.erase("actionError");
    for(auto it=patch.begin();it!=patch.end();++it) {
        auto text=it.value().dump();
        if(ui_page_set_json(page_,it.key().c_str(),text.c_str())!=0) throw std::runtime_error("uiBindingFailed");
    }
    if(!task_delta_patch.is_null()) {
        auto encoded=task_delta_patch.dump();
        if(ui_page_call_json(page_,"applyTaskDelta",encoded.c_str())!=0)
            throw std::runtime_error("taskBindingFailed");
    }
    if(!password_delta_patch.is_null()) {
        auto encoded=password_delta_patch.dump();
        if(ui_page_call_json(page_,"applyPasswordDelta",encoded.c_str())!=0)
            throw std::runtime_error("passwordBindingFailed");
    }
    if(patch.contains("fields")) {
        auto drafts=page_value(page_,"drafts");
        for(auto it=controls_.begin();it!=controls_.end();) {
            bool exists=std::any_of(patch["fields"].begin(),patch["fields"].end(),[&](const Json& f){return f["id"]==it->first;});
            if(!exists) {
                auto host=(it->second->field["editor"]=="toggle"?"toggle-host-":"choice-")+it->first;
                ui_page_on_widget_mount(page_,host.c_str(),nullptr,nullptr);
                ui_page_on_widget_unmount(page_,host.c_str(),nullptr,nullptr);
                it=controls_.erase(it); continue;
            }
            if(it->second->field["editor"]=="toggle") { ++it; continue; }
            auto widget=ui_widget_find_by_id(ui_page_root(page_),("select-"+it->first).c_str());
            if(widget) {
                if(!drafts.contains(it->first)) ui_combobox_set_selected(widget,it->second->field["choice"].get<int>());
                ui_widget_destroy(widget);
            }
            ++it;
        }
    }
    if(!action.is_null()) set_error("actionError",action.get<std::string>());
    if(!ack.is_null()) acknowledge_save(ack);
    if(patch.contains("fields") || !ack.is_null()) sync_toggles();
    for(auto& id:reset_scroll) {
        auto widget=ui_widget_find_by_id(ui_page_root(page_),id.get<std::string>().c_str());
        if(widget) { ui_debug_scroll_set(widget,0); ui_widget_destroy(widget); }
    }
    start_save();
    if(closing_ && active_save_.is_null() && saves_.empty()) PostMessageW(hwnd_,WM_CLOSE,0,0);
    if(!transition.empty()) {
        ui_window_relayout(window_);
        motion::enter(window_,transition.at("id").get<std::string>().c_str(),transition.value("x",0.0f),transition.value("y",0.0f));
    }
    if(patch.contains("language")) {
        auto language=patch["language"].get<std::string>();
        refresh_error_texts();
        ui_window_set_title(window_,wide(tr("title",language)).c_str());
        rebuild_theme(language);
    }
}
void Application::navigate(const std::string& tab) {
    if(tab!="tasks" && tab!="config" && tab!="passwords") return;
    if(page_value(page_,"tab")==tab) return;
    ui_window_focus_widget(window_,0);
    VisualBatch visual(window_);
    motion::finish(window_,("page-"+page_value(page_,"tab").get<std::string>()).c_str());
    set_text(page_,"tab",tab);
    set_text(page_,"actionError","");
    // Tab targets retain fixed sidebar geometry; reactive tab visibility already
    // schedules layout. Avoid forcing an extra full-tree layout on every switch.
    motion::enter(window_,("page-"+tab).c_str());
    motion::select(window_,"navIndicator",tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":"tabPasswords");
}
void Application::sync_toggles() {
    auto drafts=page_value(page_,"toggleDrafts");
    for(auto& pair:controls_) if(pair.second->field["editor"]=="toggle") {
        auto widget=ui_widget_find_by_id(ui_page_root(page_),("toggle-"+pair.first).c_str());
        if(!widget) continue;
        bool on=drafts.contains(pair.first)?drafts[pair.first]["boolean"].get<bool>():pair.second->field["boolean"].get<bool>();
        ui_toggle_set_on(widget,on); ui_widget_destroy(widget);
    }
}
void Application::reveal_form(bool password) {
    ui_window_relayout(window_);
    auto scroll=ui_widget_find_by_id(ui_page_root(page_),password?"passwordListScroll":"taskListScroll");
    // Core UI exposes programmatic scrolling through this public entry point;
    // it only adjusts the viewport and does not start a debug server.
    if(scroll) { ui_debug_scroll_set(scroll,0); ui_widget_destroy(scroll); }
    auto input=ui_widget_find_by_id(ui_page_root(page_),password?"passwordValue":"rootInput");
    if(input) { ui_window_focus_widget(window_,input); ui_widget_destroy(input); }
    motion::enter(window_,password?"passwordForm":"rootForm",0,12);
}
void Application::bind_controls(const Json& fields) {
    for(auto& field:fields) {
        auto editor=field.value("editor",std::string());
        if(editor!="choice" && editor!="recursive" && editor!="toggle") continue;
        auto id=field["id"].get<std::string>();
        auto& binding=controls_[id];
        if(!binding) binding=std::make_unique<ControlBinding>(ControlBinding{this,field});
        else binding->field=field;
        auto host=(editor=="toggle"?"toggle-host-":"choice-")+id;
        ui_page_on_widget_mount(page_,host.c_str(),[](UiPage,UiWidget parent,void* context){
            auto* binding=static_cast<ControlBinding*>(context); auto* self=binding->owner;
            auto id=binding->field["id"].get<std::string>();
            bool toggle=binding->field["editor"]=="toggle";
            // Nested scope mounting visits descendants again when its parent
            // mounts. One native selector belongs to each host for its lifetime.
            auto existing=ui_widget_find_by_id(parent,((toggle?"toggle-":"select-")+id).c_str());
            if(existing) { ui_widget_destroy(existing); return; }
            if(toggle) {
                auto widget=ui_toggle(L""); ui_widget_set_id(widget,("toggle-"+id).c_str());
                ui_widget_set_width(widget,44); ui_widget_set_height(widget,26);
                auto drafts=page_value(self->page_,"toggleDrafts");
                ui_toggle_set_on_immediate(widget,drafts.contains(id)?drafts[id]["boolean"].get<bool>():binding->field["boolean"].get<bool>());
                ui_toggle_on_changed(widget,[](UiWidget,int value,void* context){
                    auto* binding=static_cast<ControlBinding*>(context); auto* self=binding->owner;
                    try {
                    auto id=binding->field["id"].get<std::string>();
                    // A switch owns its finite animation. Keep its draft channel
                    // separate so a click doesn't rebind every text/list control.
                    auto drafts=page_value(self->page_,"toggleDrafts");
                    if(page_value(self->page_,"saveErrors").contains(id) && !self->field_pending(id)) drafts.erase(id);
                    Json draft=drafts.contains(id)?drafts[id]:Json{{"original",binding->field["original"]},{"text",binding->field["text"]},{"boolean",binding->field["boolean"]},{"baselineText",binding->field["text"]},{"baselineBoolean",binding->field["boolean"]}};
                    draft["boolean"]=value!=0;
                    if(draft["boolean"]==draft["baselineBoolean"] && !self->field_pending(id)) drafts.erase(id); else drafts[id]=std::move(draft);
                    auto encoded=drafts.dump(); ui_page_set_json(self->page_,"toggleDrafts",encoded.c_str());
                    self->save_error(id,"");
                    self->save_field(id);
                    } catch(const std::exception& e) { self->save_error(binding->field["id"],e.what()); }
                },binding);
                ui_widget_add_child(parent,widget); ui_widget_destroy(widget); return;
            }
            std::vector<std::wstring> labels; std::vector<const wchar_t*> texts;
            for(auto& option:binding->field["options"]) labels.push_back(wide(option["label"].get<std::string>()));
            for(auto& label:labels) texts.push_back(label.c_str());
            auto combo=ui_combobox(texts.data(),int(texts.size()));
            ui_widget_set_id(combo,("select-"+id).c_str()); ui_widget_set_expand(combo,true); ui_widget_set_height(combo,32);
            auto drafts=page_value(self->page_,"drafts");
            int selected=drafts.contains(id)?drafts[id].value("choice",binding->field["choice"].get<int>()):binding->field["choice"].get<int>();
            ui_combobox_set_selected(combo,selected);
            ui_combobox_on_changed(combo,[](UiWidget,int index,void* context){
                auto* binding=static_cast<ControlBinding*>(context); auto* self=binding->owner;
                try {
                    auto id=binding->field["id"].get<std::string>();
                    auto drafts=page_value(self->page_,"drafts");
                    if(page_value(self->page_,"saveErrors").contains(id) && !self->field_pending(id)) drafts.erase(id);
                    Json draft=drafts.contains(id)?drafts[id]:Json{{"original",binding->field["original"]},{"text",binding->field["text"]},{"boolean",binding->field["boolean"]},{"choice",binding->field["choice"]},{"baselineText",binding->field["text"]},{"baselineBoolean",binding->field["boolean"]}};
                    if(index<0 || size_t(index)>=binding->field["options"].size()) return;
                    auto value=binding->field["options"][index]["value"].get<std::string>();
                    draft["choice"]=index; draft["text"]=value=="#"?"1":value;
                    if(draft["text"]==draft["baselineText"] && !self->field_pending(id)) drafts.erase(id); else drafts[id]=std::move(draft);
                    auto encoded=drafts.dump(); ui_page_set_json(self->page_,"drafts",encoded.c_str());
                    self->save_error(id,"");
                    self->save_field(id);
                } catch(const std::exception& e) { self->set_error("actionError",e.what()); }
            },binding);
            ui_widget_add_child(parent,combo); ui_widget_destroy(combo);
        },binding.get());
        ui_page_on_widget_unmount(page_,host.c_str(),[](UiPage,UiWidget widget,void*){ui_widget_destroy(widget);},nullptr);
    }
}
void Application::rebuild_theme(const std::string& language) {
    auto host=ui_widget_find_by_id(ui_page_root(page_),"themeHost");
    if(!host) return;
    if(theme_widget_) { ui_widget_remove_child(host,theme_widget_); ui_widget_destroy(theme_widget_); theme_widget_=0; }
    std::wstring labels[]={wide(tr("system",language)),wide(tr("light",language)),wide(tr("dark",language))};
    const wchar_t* texts[]={labels[0].c_str(),labels[1].c_str(),labels[2].c_str()};
    theme_widget_=ui_combobox(texts,3); ui_widget_set_id(theme_widget_,"themeSelector"); ui_widget_set_width(theme_widget_,180); ui_widget_set_height(theme_widget_,32);
    ui_combobox_set_selected(theme_widget_,page_value(page_,"themeChoice").get<int>());
    ui_combobox_on_changed(theme_widget_,[](UiWidget,int index,void* context){
        auto* self=static_cast<Application*>(context);
        ui_page_set_int(self->page_,"themeChoice",index);
        set_text(self->page_,"theme",index==1?"light":index==2?"dark":"system");
        apply_theme(self->page_,index==1?UI_THEME_LIGHT:index==2?UI_THEME_DARK:system_theme(),self->hwnd_);
    },this);
    ui_widget_add_child(host,theme_widget_); ui_widget_destroy(host);
    host=ui_widget_find_by_id(ui_page_root(page_),"taskStatusHost");
    if(!host) return;
    if(status_widget_) { ui_widget_remove_child(host,status_widget_); ui_widget_destroy(status_widget_); }
    std::vector<std::wstring> statuses={wide(tr("allStatus",language))};
    for(auto& status:page_value(page_,"statusNames")) if(status!="") statuses.push_back(wide(tr(status.get<std::string>(),language)));
    std::vector<const wchar_t*> status_texts; for(auto& status:statuses) status_texts.push_back(status.c_str());
    status_widget_=ui_combobox(status_texts.data(),int(status_texts.size()));
    ui_widget_set_id(status_widget_,"taskStatus"); ui_widget_set_expand(status_widget_,true); ui_widget_set_height(status_widget_,32);
    ui_combobox_set_selected(status_widget_,page_value(page_,"taskStatus").get<int>());
    ui_combobox_on_changed(status_widget_,[](UiWidget,int index,void* context){
        auto* self=static_cast<Application*>(context);
        ui_page_set_int(self->page_,"taskStatus",index);
        auto statuses=page_value(self->page_,"statusNames");
        self->handle_command(Json{{"op","filterTasks"},{"payload",{{"query",page_value(self->page_,"taskQuery")},{"root",page_value(self->page_,"taskRoot")},{"status",index>=0 && size_t(index)<statuses.size()?statuses[index]:Json("")}}}});
    },this);
    ui_widget_add_child(host,status_widget_); ui_widget_destroy(host);
}
void Application::dispatch() {
    VisualBatch visual(window_);
    auto commands=page_value(page_,"requests");
    ui_page_set_json(page_,"requests","[]");
    ui_page_set_bool(page_,"dispatch",false);
    if(commands.is_array()) for(auto& command:commands) {
        try { handle_command(std::move(command)); }
        catch(const std::exception& e) { set_error("actionError",e.what()); }
    }
}
void Application::handle_command(Json command) {
    if(!command.is_object()) return;
    auto op=command.value("op",std::string());
    auto p=command.value("payload",Json::object());
    if(op=="navigate") { navigate(p.value("tab",std::string())); return; }
    if(op=="scrollTop" || op=="animateView") {
        const auto id=p.value("id",std::string());
        const char* scroll=id=="configBlocks"?"configListScroll":id=="directoryItems"?"directoryListScroll":nullptr;
        if(scroll) {
            auto widget=ui_widget_find_by_id(ui_page_root(page_),scroll);
            if(widget) { ui_debug_scroll_set(widget,0); ui_widget_destroy(widget); }
        }
        if(op=="scrollTop") return;
    }
    if(op=="animateView") {
        auto id=p.value("id",std::string());
        if(id=="configBlocks") { VisualBatch visual(window_); ui_window_relayout(window_); motion::enter(window_,id.c_str(),0,12); }
        return;
    }
    if(op=="revealForm") { reveal_form(p.value("kind",std::string())=="password"); return; }
    if(op=="browse") {
        auto selected=choose_directory(hwnd_);
        if(!selected.empty()) {
            auto target=p.value("target",std::string());
            if(target=="scopeText" || (target=="rootInput" && page_value(page_,"rootOriginal")=="")) {
                auto text=page_value(page_,target.c_str()).get<std::string>();
                if(!text.empty() && text.back()!='\n') text+='\n';
                text+=utf8(selected.wstring()); set_text(page_,target.c_str(),text);
            } else if(target=="rootInput" || target=="rootOutput") set_text(page_,target.c_str(),utf8(selected.wstring()));
            // Folder selection completes an edit without another keystroke.
            // Reuse the input's bound commit callback, including new-form guards.
            auto root=ui::GetContext().GetWindow(window_)->Root();
            auto* input=root->FindById(target=="scopeText"?"passwordScopes":target);
            if(input && input->onBlurHook) { auto commit=input->onBlurHook; commit(); }
        }
        return;
    }
    if(op=="saveField") { save_field(p.at("id"),p.value("draft",Json())); return; }
    if(op=="saveRecord") { queue_save(std::move(p)); return; }
    if(op=="openTask") {
        // Use the already-mounted task, not the full reactive history.
        if(!p.contains("task") || !p["task"].is_object()) return;
        p=Json{{"path",utf8(task_directory(p["task"]).wstring())}};
        op="openPath";
    }
    if(op=="openPath") {
        auto path=wide(p.value("path",std::string()));
        if(!path.empty() && fs::exists(path)) {
            if(fs::is_directory(path)) {
                auto result=ShellExecuteW(hwnd_,L"explore",path.c_str(),nullptr,nullptr,SW_SHOWNORMAL);
                if(reinterpret_cast<INT_PTR>(result)<=32) throw std::runtime_error("explorerFailed");
                return;
            }
            auto folder=fs::path(path).parent_path();
            PIDLIST_ABSOLUTE parent=ILCreateFromPathW(folder.c_str()), item=ILCreateFromPathW(path.c_str());
            HRESULT result=E_FAIL;
            if(parent && item) {
                PCUITEMID_CHILD child=ILFindLastID(item);
                result=SHOpenFolderAndSelectItems(parent,1,&child,0);
            }
            CoTaskMemFree(item); CoTaskMemFree(parent);
            if(FAILED(result)) throw std::runtime_error("explorerFailed");
        } else throw std::runtime_error("pathMissing");
        return;
    }
    { std::lock_guard<std::mutex> lock(mutex_); commands_.push_back(std::move(command)); }
    cv_.notify_one();
}
LRESULT CALLBACK Application::subclass(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam,UINT_PTR,DWORD_PTR data) {
    auto* self=reinterpret_cast<Application*>(data);
    try {
        if(message==WM_CLOSE && !self->stopping_) {
            if(!self->closing_ || (self->active_save_.is_null() && self->saves_.empty() && page_value(self->page_,"saveErrors").empty())) {
                self->closing_=true;
                ui_window_focus_widget(self->window_,0); // Commit the focused input through its blur handler.
                self->dispatch();
                for(auto name:{"drafts","toggleDrafts"}) {
                    auto drafts=page_value(self->page_,name);
                    for(auto it=drafts.begin();it!=drafts.end();++it) self->save_field(it.key(),it.value());
                }
            }
            if(!self->active_save_.is_null() || !self->saves_.empty()) return 0;
            auto errors=page_value(self->page_,"saveErrors");
            if(!errors.empty()) { self->closing_=false; auto encoded=errors.begin().value().dump(); ui_page_set_json(self->page_,"closeError",encoded.c_str()); return 0; }
        }
        if(message==Dispatch) { self->dispatch(); return 0; }
        if(message==Update) { self->apply_pending(); return 0; }
        if(message==WM_ACTIVATE && LOWORD(wparam)!=WA_INACTIVE) { self->changed(Startup); SetEvent(self->service_refresh_); }
        if(message==WM_SETTINGCHANGE && page_value(self->page_,"theme")=="system") apply_theme(self->page_,system_theme(),self->hwnd_);
    } catch(const std::exception& e) { self->set_error("actionError",e.what()); }
    return DefSubclassProc(hwnd,message,wparam,lparam);
}
void Application::open() {
    auto language=startup_language(options_.data_dir);
    const char* stage="stageRenderer";
    try {
    ui_init_with_theme(system_theme());
    stage="stageLogo";
    auto module=GetModuleHandleW(nullptr);
    auto resource=FindResourceW(module,MAKEINTRESOURCEW(2),RT_RCDATA);
    if(!resource) win_error("opFindLogo");
    auto logo=LoadResource(module,resource);
    auto bytes=LockResource(logo); auto size=SizeofResource(module,resource);
    if(!bytes || !size) throw std::runtime_error("logoLoadFailed");
    ui_asset_register_blob("sunpack.png",bytes,size);
    stage="stageFonts";
    ui_theme_set_cjk_font(L"Segoe UI Variable Text",L"Microsoft YaHei UI");
    stage="stageLayout";
    page_=ui_page_load_string(kMainUix);
    if(!page_) throw std::runtime_error("layoutLoadFailed");
    auto texts=interface_texts(language).dump(); ui_page_set_json(page_,"texts",texts.c_str());
    set_text(page_,"language",language);
    apply_theme(page_,system_theme());
    stage="stageWindow";
    UiWindowConfig window_config{}; window_config.skip_animation=1;
    window_=ui_page_prepare_window(page_,&window_config);
    if(!window_) throw std::runtime_error(ui_page_last_error(page_));
    stage="stageEvents";
    hwnd_=static_cast<HWND>(ui_window_hwnd(window_));
    ui_window_set_title(window_,wide(tr("title",language)).c_str());
    style_frame(hwnd_,system_theme());
    auto icon=LoadIconW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(1));
    SendMessageW(hwnd_,WM_SETICON,ICON_BIG,reinterpret_cast<LPARAM>(icon));
    SendMessageW(hwnd_,WM_SETICON,ICON_SMALL,reinterpret_cast<LPARAM>(icon));
    SetPropW(hwnd_,mutex_name(options_.data_dir,L"SunPack.GUI").c_str(),reinterpret_cast<HANDLE>(1));
    if(!SetWindowSubclass(hwnd_,subclass,1,reinterpret_cast<DWORD_PTR>(this))) win_error("opWindowEvents");
    if(!service_refresh_.value) win_error("opServiceRefresh");
    ui_page_on_widget_mount(page_,"dispatch",[](UiPage,UiWidget,void* context){
        auto* self=static_cast<Application*>(context); PostMessageW(self->hwnd_,Dispatch,0,0);
    },this);
    ui_page_on_widget_unmount(page_,"dispatch",[](UiPage,UiWidget widget,void*){
        // The lifecycle API registers an owning handle; release it on every dispatch.
        if(widget) ui_widget_destroy(widget);
    },nullptr);
    rebuild_theme(language);
    ui_window_on_close(window_,[](UiWindow,void* context){
        auto* self=static_cast<Application*>(context);
        { std::lock_guard<std::mutex> lock(self->mutex_); self->stopping_=true; }
        SetEvent(self->stop_); self->cv_.notify_all(); ui_quit(0);
    },this);
    ui_page_set_bool(page_,"cliAllowed",options_.allow_cli);
    ui_window_show_immediate(window_);
    // Keep native maximize/minimize transitions enabled after preparation/show.
    style_frame(hwnd_,system_theme());
    stage="stageWatchers";
    worker_=std::thread([this]{ work(); });
    registry_=std::thread([this]{
        HKEY key{};
        // Observe the existing Run key; do not create startup entries merely by opening the UI.
        RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_NOTIFY,&key);
        Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
        bool watching=key && RegNotifyChangeKeyValue(key,FALSE,REG_NOTIFY_CHANGE_LAST_SET,event,TRUE)==ERROR_SUCCESS;
        ServiceMonitor broker;
        Json previous;
        bool refresh=true;
        for(;;) {
            if(refresh || broker.changed()) {
                Json status;
                try { status={{"known",true},{"running",broker.running()}}; }
                catch(...) { status={{"known",false},{"running",false}}; }
                if(status!=previous) { publish({{"runtime",status}}); previous=std::move(status); }
                refresh=false;
            }
            // SCM RPC may already have delivered an APC while subscribing.
            if(broker.changed()) continue;
            HANDLE waits[]={stop_,service_refresh_,event};
            auto signal=WaitForMultipleObjectsEx(watching?3:2,waits,FALSE,INFINITE,TRUE);
            if(signal==WAIT_OBJECT_0 || signal==WAIT_FAILED) break;
            if(signal==WAIT_IO_COMPLETION) continue;
            if(signal==WAIT_OBJECT_0+1) refresh=true;
            if(watching && signal==WAIT_OBJECT_0+2) {
                ResetEvent(event); changed(Startup);
                watching=RegNotifyChangeKeyValue(key,FALSE,REG_NOTIFY_CHANGE_LAST_SET,event,TRUE)==ERROR_SUCCESS;
            }
        }
        if(key) RegCloseKey(key);
    });
    } catch(const std::exception& e) { throw std::runtime_error(error_text("startupFailure",{{"stage",{{"source",stage}}},{"detail",{{"source",e.what()}}}})); }
}
int Application::run() { open(); return ui_run(); }
Application::~Application() {
    { std::lock_guard<std::mutex> lock(mutex_); stopping_=true; }
    SetEvent(stop_); cv_.notify_all();
    if(worker_.joinable()) worker_.join();
    if(registry_.joinable()) registry_.join();
    if(hwnd_ && IsWindow(hwnd_)) { RemoveWindowSubclass(hwnd_,subclass,1); ui_window_destroy(window_); }
    if(page_) ui_page_destroy(page_);
    if(theme_widget_) ui_widget_destroy(theme_widget_);
    if(status_widget_) ui_widget_destroy(status_widget_);
    ui_shutdown();
}
void Application::work() {
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    std::string language="en";
    try {
        Json config=Json::object(), passwords={{"passwords",Json::array()}};
        WatchRoots roots; EventLog log; View view;
        Json errors=Json::object();
        auto dir=options_.data_dir;
        auto dir_key=path_key(dir);
        auto on_data=[this,dir_key](const fs::path& path){
            auto name=path.filename().wstring(); CharLowerBuffW(name.data(),DWORD(name.size()));
            if(path.empty() || is_under(dir_key,path_key(path))) {
                changed(Config|Passwords|Roots); return;
            }
            if(name.empty() || name==L"sunpack_config.json") changed(Config);
            if(name.empty() || name==L"builtin_passwords.json") changed(Passwords);
            if(name.empty() || name==L"sunpack_watch_roots.txt") changed(Roots);
        };
        std::unique_ptr<DirectoryWatcher> data_watcher;
        std::unique_ptr<DirectoryWatcher> log_watcher;
        std::string last_config,last_passwords,last_roots;
        bool config_read=false,passwords_read=false,roots_read=false;
        Json previous_patch=Json::object();
        // Only store sorted task IDs, never a second 5000-row JSON snapshot.
        // A source change or incremental task patch invalidates this shortcut.
        std::vector<std::wstring> last_visible_tasks;
        bool task_selection_known=false;
        std::map<unsigned,ReadRetry> retries;
        auto retry_io=[&](unsigned bit,const WinError& error) {
            if(error.code!=ERROR_SHARING_VIOLATION && error.code!=ERROR_LOCK_VIOLATION && error.code!=ERROR_FILE_NOT_FOUND && error.code!=ERROR_PATH_NOT_FOUND) return;
            auto& retry=retries[bit];
            // A rename notification can precede the writer releasing its sharing lock.
            // Bounded one-shot deadlines exist only after an observed I/O failure.
            constexpr unsigned delays[]={5,20,80};
            if(retry.attempts<3) retry.due=Clock::now()+std::chrono::milliseconds(delays[retry.attempts++]);
        };
        for(;;) {
            unsigned flags; std::deque<Json> commands;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                auto deadline=Clock::time_point::max();
                for(auto& retry:retries) deadline=std::min(deadline,retry.second.due);
                auto awake=[&]{return stopping_ || dirty_ || !commands_.empty();};
                if(deadline==Clock::time_point::max()) cv_.wait(lock,awake);
                else cv_.wait_until(lock,deadline,awake);
                if(stopping_) break;
                flags=dirty_; dirty_=0; commands.swap(commands_);
            }
            for(auto& retry:retries) {
                if(flags&retry.first) { retry.second=ReadRetry{}; }
                else if(retry.second.due<=Clock::now()) { flags|=retry.first; retry.second.due=Clock::time_point::max(); }
            }
            bool tasks_changed=false,passwords_changed=false,dirs_changed=false,config_changed=false;
            bool task_delta_eligible=true;
            bool task_filter_requested=false, task_source_changed=false;
            Json password_delta;
            Json edit_feedback=Json::object();
            if(!data_watcher || !data_watcher->alive() || (!data_watcher->direct() && fs::is_directory(dir))) {
                try {
                    data_watcher=std::make_unique<DirectoryWatcher>(dir,on_data); errors.erase("fileObserver");
                }
                catch(const std::exception& e) { errors["fileObserver"]=e.what(); }
            }
            for(auto& command:commands) {
                auto op=command.value("op",std::string()); auto p=command.value("payload",Json::object());
                try {
                    if(op=="filterTasks") {
                        task_delta_eligible=false;
                        auto query=p.value("query",std::string()), root=p.value("root",std::string());
                        auto status=p.value("status",std::string());
                        if(view.task_query!=query || view.task_root!=root || view.task_status!=status) {
                            if(!edit_feedback.contains("resetScroll")) edit_feedback["resetScroll"]=Json::array();
                            edit_feedback["resetScroll"].push_back("taskListScroll");
                            bool switch_root=view.task_root!=root;
                            view.task_query=std::move(query); view.task_root=std::move(root);
                            view.task_status=std::move(status);
                            tasks_changed=task_filter_requested=true;
                            if(switch_root) edit_feedback["viewTransition"]={{"id","taskBody"},{"y",12}};
                        }
                    } else if(op=="filterPasswords") {
                        password_delta=Json(); // Filter changes require the whole result set.
                        if(!edit_feedback.contains("resetScroll")) edit_feedback["resetScroll"]=Json::array();
                        edit_feedback["resetScroll"].push_back("passwordListScroll");
                        auto scope=p.value("scope",std::string("@all"));
                        if(view.password_scope!=scope) edit_feedback["viewTransition"]={{"id","passwordBody"},{"x",scope=="@history"?20:-20}};
                        view.password_query=p.value("query",std::string()); view.password_scope=p.value("scope",std::string("@all"));
                        passwords_changed=true;
                    } else if(op=="commit") {
                        auto kind=p.at("kind").get<std::string>();
                        PasswordSaveSnapshot saved_passwords;
                        auto result=save_changes(dir,p.value("fields",Json::array()),
                            kind=="passwords"?Json::array({p.at("edit")}):Json::array(),
                            kind=="roots"?Json::array({p.at("edit")}):Json::array(),
                            kind=="passwords"?&saved_passwords:nullptr);
                        for(auto& section:result["saved"]) {
                            if(section=="config") flags|=Config;
                            if(section=="passwords") {
                                // The atomic write already validated and built this snapshot.
                                // Under the single-writer GUI contract there is no need to
                                // parse the same file again after our own rename notification.
                                passwords=std::move(saved_passwords.document);
                                last_passwords=std::move(saved_passwords.file_text);
                                passwords_read=true;
                                flags&=~Passwords;
                                retries.erase(Passwords);
                                // A single replacement preserves ordering and filtered count
                                // in the unfiltered saved-password view.
                                const auto& edit=p.at("edit");
                                if(edit.value("operation",std::string())=="replace" &&
                                   view.password_query.empty() && view.password_scope=="@all" &&
                                   !passwords_changed && previous_patch.contains("passwords")) {
                                    Json record={{"value",edit.value("value",std::string())}};
                                    auto scopes=edit.value("scopes",Json::array());
                                    if(!scopes.empty()) record["scopes"]=std::move(scopes);
                                    auto projected=password_rows(Json{{"passwords",Json::array({std::move(record)})}},view,language);
                                    if(!projected["rows"].empty())
                                        password_delta={{"original",edit.at("original")},{"row",projected["rows"][0]}};
                                } else password_delta=Json();
                                passwords_changed=true;
                            }
                            if(section=="roots") { flags|=Roots; tasks_changed=dirs_changed=true; task_delta_eligible=false; }
                        }
                        auto message=result["error"].get<std::string>();
                        edit_feedback["saveAck"]={{"job",p},{"ok",message.empty()},{"error",message}};
                    } else if(op=="cli") {
                        if(!options_.allow_cli) throw std::runtime_error("cliUnbound");
                        auto action=p.value("action",std::string());
                        std::vector<std::wstring> args={L"watch"};
                        if(action=="start" || action=="stop") args.push_back(wide(action));
                        else if(action=="startupEnable" || action=="startupDisable") { args.push_back(L"startup"); args.push_back(action=="startupEnable"?L"enable":L"disable"); }
                        else throw std::runtime_error("cliOperationUnknown");
                        auto result=run_cli(options_.cli,args,stop_);
                        SetEvent(service_refresh_);
                        Json feedback={{"busy",false},{"lastCommand",{{"action",action},{"code",result.code}}}};
                        if(result.code!=0) {
                            Json output;
                            try { wide(result.output); output=std::move(result.output); }
                            catch(...) { output={{"source","cliEncoding"}}; }
                            feedback["actionError"]=error_text("cliFailureOutput",{
                                {"failure",{{"source",error_text("cliFailed",{{"code",result.code}})}}},{"output",output}});
                        }
                        publish(std::move(feedback)); flags|=Startup;
                    } else throw std::runtime_error("uiOperationUnknown");
                } catch(const std::exception& e) {
                    auto message=std::string(e.what());
                    if(op=="commit") edit_feedback["saveAck"]={{"job",p},{"ok",false},{"error",message}};
                    else publish({{"busy",false},{"actionError",message}});
                }
            }
            auto read=[&](unsigned bit,const char* file,std::string& previous,bool& loaded,auto apply) {
                if(!(flags&bit)) return;
                try {
                    auto text=read_file(dir/file);
                    if(!loaded || text!=previous) { apply(text); previous=std::move(text); loaded=true; }
                    errors.erase(file);
                    retries.erase(bit);
                } catch(const WinError& e) {
                    if(bit==Roots && (e.code==ERROR_FILE_NOT_FOUND || e.code==ERROR_PATH_NOT_FOUND) && retries.count(bit) && retries.at(bit).attempts>=3) {
                        apply(std::string()); previous.clear(); loaded=true; errors.erase(file); retries.erase(bit);
                    } else { errors[file]=e.what(); retry_io(bit,e); }
                }
                catch(const std::exception& e) { errors[file]=e.what(); }
            };
            read(Config,"sunpack_config.json",last_config,config_read,[&](const std::string& text){
                auto value=parse_json(text); if(!value.is_object()) throw std::runtime_error("configObjectRequired");
                config=std::move(value); config_changed=dirs_changed=true;
            });
            read(Passwords,"builtin_passwords.json",last_passwords,passwords_read,[&](const std::string& text){
                auto value=parse_json(text); validate_passwords(value); passwords=std::move(value); passwords_changed=dirs_changed=true;
            });
            if(flags&Roots) {
                read(Roots,"sunpack_watch_roots.txt",last_roots,roots_read,[&](const std::string& text){roots=parse_roots(text,dir); tasks_changed=dirs_changed=true; task_delta_eligible=false; task_source_changed=true;});
            }
            auto log_dir=log_directory(dir,config);
            if(log.path()!=log_dir/"events.jsonl" || !log_watcher || !log_watcher->alive() || (!log_watcher->direct() && fs::is_directory(log_dir))) {
                log_watcher.reset();
                try {
                    log_watcher=std::make_unique<DirectoryWatcher>(log_dir,[this](const fs::path& path){
                        auto name=path.filename().wstring(); CharLowerBuffW(name.data(),DWORD(name.size()));
                        std::error_code ec;
                        if(path.empty() || name==L"events.jsonl" || fs::is_directory(path,ec)) changed(Log);
                    }); errors.erase("logObserver");
                } catch(const std::exception& e) { errors["logObserver"]=e.what(); }
                log.set_path(log_dir/"events.jsonl"); flags|=Log; tasks_changed=true; task_delta_eligible=false; task_source_changed=true;
            }
            if(flags&Log) {
                try {
                    bool refreshed=log.refresh(retries.count(Log) && retries.at(Log).attempts>=3);
                    tasks_changed|=refreshed; task_source_changed|=refreshed;
                    if(log.retry_required) changed(Log);
                    errors.erase("events.jsonl"); retries.erase(Log);
                }
                catch(const WinError& e){ errors["events.jsonl"]=e.what(); retry_io(Log,e); }
                catch(const std::exception& e){ errors["events.jsonl"]=e.what(); }
            }
            Json patch=Json::object();
            auto next_language=gui_language(config);
            bool language_changed=language!=next_language || !previous_patch.contains("language");
            language=std::move(next_language);
            if(language_changed) { patch["language"]=language; patch["texts"]=interface_texts(language); }
            if(tasks_changed || language_changed || !previous_patch.contains("tasks")) {
                if(task_delta_eligible && !language_changed && previous_patch.contains("tasks") &&
                   !log.rebuilt && !log.changed_overflow) {
                    patch["taskDelta"]=task_delta(log,roots,view,language);
                    task_selection_known=false;
                } else {
                    std::vector<std::wstring> selected;
                    const auto* previous=(task_filter_requested && !task_source_changed &&
                        !language_changed && task_selection_known)?&last_visible_tasks:nullptr;
                    auto projected=task_rows(log,roots,view,language,&selected,previous);
                    last_visible_tasks=std::move(selected);
                    task_selection_known=true;
                    if(!projected.is_null()) patch["tasks"]=std::move(projected);
                }
            }
            if(passwords_changed || language_changed || !previous_patch.contains("passwords")) {
                if(!password_delta.is_null() && !language_changed && previous_patch.contains("passwords"))
                    patch["passwordDelta"]=std::move(password_delta);
                else patch["passwords"]=password_rows(passwords,view,language);
            }
            if(config_changed || language_changed || !previous_patch.contains("fields")) patch["fields"]=config_fields(config,last_config,language);
            if(dirs_changed || !previous_patch.contains("directories")) patch["directories"]=directory_rows(roots,config);
            if(flags&Startup || !previous_patch.contains("startup")) {
                try { auto state=read_startup(); patch["startup"]={{"enabled",state.enabled},{"command",state.command}}; errors.erase("startup"); }
                catch(const std::exception& e){errors["startup"]=e.what();}
            }
            auto displayed_errors=Json::object();
            for(auto it=errors.begin();it!=errors.end();++it) displayed_errors[tr(it.key(),language)]=translated_error(it.value().get<std::string>(),language);
            patch["errors"]=std::move(displayed_errors); patch["logPath"]=utf8(log.path().wstring()); patch["ready"]=true;
            Json changed_patch=Json::object();
            for(auto it=patch.begin();it!=patch.end();++it) if(!previous_patch.contains(it.key()) || it.key()=="tasks" || it.key()=="passwords" || it.key()=="taskDelta" || it.key()=="passwordDelta" || previous_patch[it.key()]!=it.value()) {
                // These projections are generated only after source/filter
                // changes. Keep an initialization marker, not a second full
                // resident copy of the task/password list.
                previous_patch[it.key()]=(it.key()=="tasks" || it.key()=="passwords" || it.key()=="taskDelta" || it.key()=="passwordDelta")?Json():it.value();
                changed_patch[it.key()]=std::move(it.value());
            }
            changed_patch.update(edit_feedback);
            if(!changed_patch.empty()) publish(std::move(changed_patch));
        }
    } catch(const std::exception& e) { publish({{"actionError",e.what()},{"ready",true}}); }
    CoUninitialize();
}
}
