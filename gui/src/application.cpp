#include "application.hpp"
#include "motion.hpp"
#include "presentation.hpp"
#include "range_editor.hpp"
#include "tag_collection.hpp"
#include "main_uix.h"
#include <commctrl.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/controls.h>
#include <ui/measure_context.h>
#include <chrono>
#include <cmath>
#include <map>

namespace spg {
namespace {
void update_tags(TagCollection& tags,const Json& field,const Json& drafts,const std::string& language) {
    auto id=field["id"].get<std::string>();
    tags.SetItems((drafts.contains(id)?drafts[id]["text"]:field["text"]).get_ref<const std::string&>(),wide(tr("emptyEntry",language)),wide(tr("noTags",language)));
}
// Keep host messages outside Core UI's startup/render message range.
constexpr UINT Dispatch = WM_APP + 0x401, Update = WM_APP + 0x402, DateResult = WM_APP + 0x403;
constexpr unsigned Config = 1, Passwords = 2, Roots = 4, Log = 8, Startup = 16;
using Clock=std::chrono::steady_clock;
using motion::VisualBatch;
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
    if(patch.contains("passwords")) pending_.erase("passwordDelta");
    if(patch.contains("passwordDelta") && pending_.contains("passwords")) patch.erase("passwordDelta");
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
    for(auto field:{"actionError"}) {
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
        if(draft.contains("range")) text=range_configuration(draft["range"],(*field)["editor"]=="datetime_range").dump();
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
    if(kind=="roots") for(auto& edit:job.at("edits")) save_error("@root:"+edit.at("row").get<std::string>(),"");
    else save_error(kind=="passwords"?"@password:"+key.get<std::string>():key.get<std::string>(),"");
    auto previous=std::find_if(saves_.begin(),saves_.end(),[&](const Json& queued){return queued["kind"]==kind && queued["key"]==key;});
    if(previous!=saves_.end() && kind=="roots") {
        // A later edit to the first row must not drop the other rows of an
        // already queued atomic paste. Replace only overlapping row values.
        for(auto pair:{std::pair<const char*,const char*>{"edits","row"},{"snapshot","id"}}) for(auto& item:job[pair.first]) {
            auto& items=(*previous)[pair.first];
            auto found=std::find_if(items.begin(),items.end(),[&](const Json& old){return old[pair.second]==item[pair.second];});
            if(found==items.end()) items.push_back(item); else *found=item;
        }
    } else if(previous!=saves_.end()) *previous=std::move(job); else saves_.push_back(std::move(job));
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
    if(kind=="roots") {
        Json records=Json::array(),pending=Json::array();
        Json removed_scopes=Json::array();
        if(ok) {
            std::unordered_set<std::wstring> removed;
            for(auto& edit:job.at("edits")) if(edit.at("operation")=="delete") {
                auto path=edit.at("original").get<std::string>();
                removed_scopes.push_back(path); removed.insert(path_key(wide(path)));
            }
            std::unordered_map<std::string,std::string> rebased;
            if(ack.contains("passwordRebases") && ack["passwordRebases"].is_array())
                for(auto& group:ack["passwordRebases"]) if(!group["record"].is_null())
                    for(auto& previous:group["originals"]) rebased.emplace(previous.get<std::string>(),group["record"].dump());
            for(auto it=saves_.begin();it!=saves_.end();) {
                if((*it)["kind"]!="passwords") { ++it; continue; }
                auto& edit=(*it)["edit"];
                auto scope=edit.value("scope",std::string());
                if(!scope.empty() && removed.count(path_key(wide(scope)))) {
                    save_error("@password:"+(*it)["key"].get<std::string>(),"");
                    it=saves_.erase(it); continue;
                }
                auto found=rebased.find(edit.value("original",std::string()));
                if(found!=rebased.end()) edit["original"]=found->second;
                ++it;
            }
        }
        for(auto& edit:job.at("edits")) {
            auto id=edit.at("row").get<std::string>();
            save_error("@root:"+id,ack.at("error"));
            if(!ok) continue;
            bool remove=edit.at("operation")=="delete";
            auto input=remove?std::string():utf8(resolve_path(wide(edit.at("input").get<std::string>()),options_.data_dir).wstring());
            auto output=edit.at("output").get<std::string>(); auto first=output.find_first_not_of(" \t\r\n");
            output=first==std::string::npos?"":output.substr(first,output.find_last_not_of(" \t\r\n")-first+1);
            records.push_back({{"id",id},{"input",input},{"identity",remove?std::string():utf8(path_key(wide(input)))},{"output",output},{"deep",edit.at("deep")},{"recursive",edit.value("recursive",false)},{"remove",remove}});
            for(auto& queued:saves_) if(queued["kind"]==kind) for(auto& next:queued["edits"]) if(next["row"]==id) {
                next["original"]=input;
                next["expected"]=remove?Json():Json{{"output",output},{"deep",edit["deep"]},{"recursive",edit.value("recursive",false)}};
                if(next["operation"]=="delete") next["input"]=input;
                else next["operation"]=remove?"addMany":"save";
            }
        }
        for(auto& queued:saves_) if(queued["kind"]==kind) for(auto& edit:queued["edits"]) pending.push_back(edit["row"]);
        auto reply=Json{{"snapshot",job.at("snapshot")},{"ok",ok},{"error",ack.at("error")},{"records",std::move(records)},{"pending",std::move(pending)}};
        reply["removedPasswordScopes"]=std::move(removed_scopes);
        reply["passwordRebases"]=ack.value("passwordRebases",Json::array());
        if(!ok) reply["error"]=page_value(page_,"saveErrors")["@root:"+job["edits"][0]["row"].get<std::string>()];
        auto encoded=reply.dump();
        if(ui_page_call_json(page_,"rootSaved",encoded.c_str())!=0) throw std::runtime_error("uiBindingFailed");
        active_save_=Json(); return;
    }
    save_error(kind=="passwords"?"@password:"+job["key"].get<std::string>():job["key"].get<std::string>(),ack.at("error"));
    if(kind=="passwords") {
        const auto& edit=job.at("edit");
        const bool removed=ok && ack.at("passwordOriginal").get<std::string>().empty();
        std::string original;
        Json rebases=Json::array(),row_rebases=Json::array();
        if(ok) {
            struct Rebase { const Json* record; std::string original; };
            std::vector<Rebase> records;
            std::unordered_map<std::string,size_t> changed;
            for(auto& group:ack.at("passwordRebases")) {
                const auto& record=group.at("record");
                const auto index=records.size();
                records.push_back({&record,record.is_null()?std::string():record.dump()});
                for(auto& previous:group.at("originals")) changed.emplace(previous.get<std::string>(),index);
            }
            // Merging another directory into a shared password also changes
            // the baseline of already queued edits in its other directories.
            for(auto it=saves_.begin();it!=saves_.end();) {
                auto& queued=*it;
                if(queued["kind"]!=kind || queued["key"]==job["key"]) { ++it; continue; }
                auto found=changed.find(queued["edit"]["original"].get<std::string>());
                if(found==changed.end()) { ++it; continue; }
                auto& rebase=records[found->second];
                bool missing=!password_matches_scope(*rebase.record,queued["edit"].value("scope",std::string()));
                auto& operation=queued["edit"]["operation"];
                if(missing && (operation=="delete" || operation=="removeScope")) { it=saves_.erase(it); continue; }
                queued["edit"]["original"]=missing?std::string():rebase.original;
                if(missing) operation="addMany";
                ++it;
            }
            auto drafts=page_value(page_,"passwordDrafts");
            for(auto it=drafts.begin();it!=drafts.end();++it) {
                if(it.key()==job["key"].get<std::string>()) continue;
                auto previous=it.value().at("original").get<std::string>();
                auto found=changed.find(previous); if(found==changed.end()) continue;
                auto& rebase=records[found->second];
                bool missing=!password_matches_scope(*rebase.record,it.value().value("scope",std::string()));
                bool pending=std::any_of(saves_.begin(),saves_.end(),[&](const Json& queued){return queued["kind"]==kind && queued["key"]==it.key();});
                rebases.push_back({{"key",it.key()},{"previous",previous},{"original",missing?std::string():rebase.original},{"removed",missing},{"pending",pending}});
            }
            auto scope=page_value(page_,"passwordScope").get<std::string>();
            if(scope!="@history") for(size_t i=0;i<records.size();++i) if(password_matches_scope(*records[i].record,scope))
                row_rebases.push_back({{"originals",ack["passwordRebases"][i]["originals"]},{"original",records[i].original}});
            original=ack.at("passwordOriginal").get<std::string>();
            if(removed) saves_.erase(std::remove_if(saves_.begin(),saves_.end(),[&](const Json& queued) {
                return queued["kind"]==kind && queued["key"]==job["key"] && (queued["edit"]["operation"]=="delete" || queued["edit"]["operation"]=="removeScope");
            }),saves_.end());
            for(auto& queued:saves_) if(queued["kind"]==kind && queued["key"]==job["key"] && queued["edit"]["original"]==edit["original"]) {
                queued["edit"]["original"]=original;
                if(removed) queued["edit"]["operation"]="addMany";
                else if(queued["edit"]["operation"]=="addMany") queued["edit"]["operation"]="replace";
                if(queued["edit"]["values"]==edit["values"] && edit["values"].size()>1)
                    queued["edit"]["values"]=Json::array({edit["value"]});
            }
        }
        bool pending=std::any_of(saves_.begin(),saves_.end(),[&](const Json& queued){return queued["kind"]==kind && queued["key"]==job["key"];});
        auto reply=Json{{"key",job["key"]},{"snapshot",job["snapshot"]},{"ok",ok},{"error",ack["error"]},
            {"original",original},{"pending",pending},{"removed",removed},{"rebases",std::move(rebases)},{"rowRebases",std::move(row_rebases)}};
        if(!ok) reply["error"]=page_value(page_,"saveErrors")["@password:"+job["key"].get<std::string>()];
        auto encoded=reply.dump();
        if(ui_page_call_json(page_,"passwordSaved",encoded.c_str())!=0) throw std::runtime_error("passwordBindingFailed");
        active_save_=Json();
        return;
    }
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
    }
    active_save_=Json();
}
void Application::apply_pending() {
    Json patch;
    { std::lock_guard<std::mutex> lock(mutex_); patch=std::move(pending_); pending_=Json::object(); notified_=false; }
    auto reset_scroll=patch.value("resetScroll",Json::array()); patch.erase("resetScroll");
    auto password_delta_patch=patch.value("passwordDelta",Json()); patch.erase("passwordDelta");
    VisualBatch visual(window_);
    auto ack=patch.value("saveAck",Json()); patch.erase("saveAck");
    const bool cell_ack=!ack.is_null() && (ack["job"]["kind"]=="passwords" || ack["job"]["kind"]=="roots");
    if(cell_ack) acknowledge_save(ack);
    Json password_snapshot;
    if(patch.contains("passwords")) { password_snapshot=std::move(patch["passwords"]); patch.erase("passwords"); }
    Json directory_snapshot;
    if(patch.contains("directories")) { directory_snapshot=std::move(patch["directories"]); patch.erase("directories"); }
    if(patch.contains("fields")) bind_controls(patch["fields"]);
    auto action=patch.value("actionError",Json()); patch.erase("actionError");
    for(auto it=patch.begin();it!=patch.end();++it) {
        auto text=it.value().dump();
        if(ui_page_set_json(page_,it.key().c_str(),text.c_str())!=0) throw std::runtime_error("uiBindingFailed");
    }
    if(!directory_snapshot.is_null()) {
        auto encoded=directory_snapshot.dump();
        if(ui_page_call_json(page_,"applyDirectories",encoded.c_str())!=0) throw std::runtime_error("uiBindingFailed");
    }
    if(!password_snapshot.is_null()) {
        auto encoded=password_snapshot.dump();
        if(ui_page_call_json(page_,"applyPasswords",encoded.c_str())!=0) throw std::runtime_error("passwordBindingFailed");
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
                auto host=(it->second->field["editor"]=="toggle"?"toggle-host-":it->second->field["editor"]=="list"?"tags-host-":"choice-")+it->first;
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
    if(!ack.is_null() && !cell_ack) acknowledge_save(ack);
    if(!ack.is_null()) ui_page_call_json(page_,"prunePasswordDrafts","{}");
    if(!ack.is_null() || !directory_snapshot.is_null()) ui_page_call_json(page_,"pruneRootDrafts","{}");
    if(patch.contains("fields") || !ack.is_null()) sync_toggles();
    if(patch.contains("fields") || !ack.is_null()) sync_tags();
    for(auto& id:reset_scroll) {
        auto widget=ui_widget_find_by_id(ui_page_root(page_),id.get<std::string>().c_str());
        if(widget) { ui_debug_scroll_set(widget,0); ui_widget_destroy(widget); }
    }
    // Only an acknowledgement advances the save queue. Data/log publishes
    // must not rewrite recordSaving/pendingFields and rebind hidden editors.
    if(!ack.is_null()) start_save();
    if(patch.contains("language")) {
        date_popup_.reset();
        auto language=patch["language"].get<std::string>();
        refresh_error_texts();
        ui_window_set_title(window_,wide(tr("title",language)).c_str());
        rebuild_theme(language);
    }
}
void Application::reveal() {
    if(shown_) return;
    shown_=true;
    ui_window_show_immediate(window_);
    style_frame(hwnd_,system_theme());
}
void Application::navigate(const std::string& tab) {
    date_popup_.reset();
    if(tab!="tasks" && tab!="config" && tab!="roots" && tab!="passwords") return;
    if(page_value(page_,"tab")==tab) return;
    // Focus loss may publish its own input/blur repaint. Begin the visual
    // transaction first, so that repaint coalesces with the page switch.
    VisualBatch visual(window_);
    ui_window_focus_widget(window_,0);
    ui_page_set_json(page_,"tagInputs","{}");
    const auto previous=page_value(page_,"tab").get<std::string>();
    auto sidebar=[](const std::string& section)->const char* {
        return section=="config"?"configSidebar":section=="tasks" || section=="passwords"?"directoryPane":nullptr;
    };
    const auto* previous_sidebar=sidebar(previous);
    const auto* next_sidebar=sidebar(tab);
    const bool sidebar_changed=previous_sidebar!=next_sidebar;
    motion::finish(window_,("page-"+previous).c_str());
    // Tasks and passwords share this retained directory pane. Preserve its
    // current position and clock unless the lower content type changes.
    if(sidebar_changed && previous_sidebar) motion::finish(window_,previous_sidebar);
    set_text(page_,"tab",tab);
    set_text(page_,"actionError","");
    // Tab targets retain fixed sidebar geometry; reactive tab visibility already
    // schedules layout. Avoid forcing an extra full-tree layout on every switch.
    motion::enter(window_,("page-"+tab).c_str());
    if(sidebar_changed && next_sidebar) motion::enter(window_,next_sidebar);
    motion::select(window_,"navIndicator",tab=="tasks"?"tabTasks":tab=="config"?"tabConfig":tab=="roots"?"tabRoots":"tabPasswords");
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
void Application::sync_tags(const std::string& id) {
    auto drafts=page_value(page_,"drafts");
    auto language=page_value(page_,"language").get<std::string>();
    auto* root=ui::GetContext().GetWindow(window_)->Root().get();
    for(auto& pair:controls_) if((id.empty() || pair.first==id) && pair.second->field["editor"]=="list") {
        if(auto* tags=dynamic_cast<TagCollection*>(root->FindById("tags-"+pair.first))) update_tags(*tags,pair.second->field,drafts,language);
    }
}
void Application::bind_controls(const Json& fields) {
    for(auto& field:fields) {
        auto editor=field.value("editor",std::string());
        if(editor!="choice" && editor!="recursive" && editor!="toggle" && editor!="list") continue;
        auto id=field["id"].get<std::string>();
        auto& binding=controls_[id];
        if(!binding) binding=std::make_unique<ControlBinding>(ControlBinding{this,field});
        else binding->field=field;
        auto host=(editor=="toggle"?"toggle-host-":editor=="list"?"tags-host-":"choice-")+id;
        ui_page_on_widget_mount(page_,host.c_str(),[](UiPage,UiWidget parent,void* context){
            auto* binding=static_cast<ControlBinding*>(context); auto* self=binding->owner;
            auto id=binding->field["id"].get<std::string>();
            bool toggle=binding->field["editor"]=="toggle";
            if(binding->field["editor"]=="list") {
                auto* host=ui::GetContext().handles.LookupRaw(parent);
                if(!host || host->FindById("tags-"+id)) return;
                auto tags=std::make_shared<TagCollection>(); tags->id="tags-"+id;
                tags->onRemove=[self,id](size_t index,const std::wstring& value) {
                    auto payload=Json{{"id",id},{"index",index},{"value",utf8(value)}}.dump();
                    if(ui_page_call_json(self->page_,"removeTag",payload.c_str())!=0) self->set_error("actionError","uiBindingFailed");
                };
                update_tags(*tags,binding->field,page_value(self->page_,"drafts"),page_value(self->page_,"language").get<std::string>());
                host->AddChild(tags); return;
            }
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
        ui_page_on_widget_unmount(page_,host.c_str(),[](UiPage,UiWidget widget,void*){
            auto* host=ui::GetContext().handles.LookupRaw(widget);
            if(host) for(auto& child:host->Children()) if(auto* tags=dynamic_cast<TagCollection*>(child.get())) tags->onRemove={};
            ui_widget_destroy(widget);
        },nullptr);
    }
}
void Application::rebuild_theme(const std::string& language) {
    auto host=ui_widget_find_by_id(ui_page_root(page_),"themeHost");
    if(!host) return;
    if(theme_widget_) { ui_widget_remove_child(host,theme_widget_); ui_widget_destroy(theme_widget_); theme_widget_=0; }
    std::wstring labels[]={wide(tr("system",language)),wide(tr("light",language)),wide(tr("dark",language))};
    const wchar_t* texts[]={labels[0].c_str(),labels[1].c_str(),labels[2].c_str()};
    theme_widget_=ui_combobox(texts,3); ui_widget_set_id(theme_widget_,"themeSelector"); ui_widget_set_height(theme_widget_,32);
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
    ui_widget_set_id(status_widget_,"taskStatus"); ui_widget_set_height(status_widget_,32);
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
    if(op=="syncTags") { sync_tags(p.at("id").get<std::string>()); return; }
    if(op=="scrollTop") {
        if(p.contains("category") && page_value(page_,"configCategory")==p["category"]) return;
        if(p.value("id",std::string())=="configBlocks") date_popup_.reset();
        const auto id=p.value("id",std::string());
        if(id=="configBlocks" && p.contains("category")) {
            // Commit category and viewport together. Filtering updates the
            // contents directly, including while a main-page move is active.
            ui_page_set_json(page_,"tagInputs","{}");
            set_text(page_,"configCategory",p.at("category").get<std::string>());
        }
        const char* scroll=id=="configBlocks"?"configListScroll":id=="directoryItems"?"directoryListScroll":nullptr;
        if(scroll) {
            auto widget=ui_widget_find_by_id(ui_page_root(page_),scroll);
            if(widget) { ui_debug_scroll_set(widget,0); ui_widget_destroy(widget); }
        }
        return;
    }
    if(op=="clearRootError") { save_error("@root:"+p.at("id").get<std::string>(),""); return; }
    if(op=="blurRoot") {
        if(choosing_directory_ || page_value(page_,"rootCell")!=p.at("id") || page_value(page_,"rootPart")!=p.at("part")) return;
        auto* focused=ui::GetContext().GetWindow(window_)->FocusedWidget();
        auto suffix=p.at("part").get<std::string>()+"-"+p.at("id").get<std::string>();
        if(focused && focused->id=="browse-root-"+suffix) return;
        ui_page_call_json(page_,"finishRootCell","{}"); return;
    }
    if(op=="clearPasswordError") { save_error("@password:"+p.at("id").get<std::string>(),""); return; }
    if(op=="discardPassword") {
        auto encoded=p.at("id").dump();
        if(ui_page_call_json(page_,"discardPassword",encoded.c_str())!=0) throw std::runtime_error("passwordBindingFailed");
        return;
    }
    if(op=="focusPassword" || op=="focusRoot") {
        auto id=p.at("id").get<std::string>(), part=p.at("part").get<std::string>();
        auto* window=ui::GetContext().GetWindow(window_);
        bool root=op=="focusRoot";
        if(part=="none") {
            auto* focused=window->FocusedWidget();
            if(focused && (root?(focused->id=="root-input-input-"+id || focused->id=="root-output-input-"+id):focused->id=="password-input-"+id)) window->FocusWidget(nullptr,false);
            return;
        }
        if(root) { if((part!="input" && part!="output") || page_value(page_,"rootCell")!=id || page_value(page_,"rootPart")!=part) return; }
        else if(part!="value" || page_value(page_,"passwordCell")!=id) return;
        if(p.value("top",false)) {
            auto scroll=ui_widget_find_by_id(ui_page_root(page_),root?"rootListScroll":"passwordListScroll");
            if(scroll) { ui_debug_scroll_set(scroll,0); ui_widget_destroy(scroll); }
        }
        ui_window_relayout(window_);
        auto* target=window->Root()->FindById(root?"root-"+part+"-input-"+id:"password-input-"+id);
        if(target) {
            window->FocusWidget(target,false);
            if(p.contains("pointerX") && p["pointerX"].is_number()) {
                if(auto* input=dynamic_cast<ui::TextInputWidget*>(target)) {
                    ui::MeasureContext measure; measure.BindRenderer(&window->GetRenderer());
                    float offset=0;
                    if(root && !input->Text().empty()) {
                        auto* label=window->Root()->FindById("root-"+part+"-value-"+id);
                        if(label) {
                            float font=label->css.fontSize>0?label->css.fontSize:theme::kFontSizeNormal;
                            auto shown=window->GetRenderer().EllipsizeStart(input->Text(),label->ContentWidth(),font);
                            if(shown!=input->Text() && !shown.empty()) {
                                auto hidden=input->Text().size()-(shown.size()-1);
                                offset=measure.MeasureTextWidth(input->Text().substr(0,hidden),font)-measure.MeasureTextWidth(L"\u2026",font);
                            }
                        }
                    }
                    input->PlaceCaretFromX(measure,target->rect.left+p["pointerX"].get<float>(),offset);
                }
            }
        }
        return;
    }
    if(op=="browseRoot") {
        auto part=p.at("part").get<std::string>(); if(part!="input" && part!="output") return;
        auto value=p.at("value").get<std::string>();
        auto base=options_.data_dir;
        if(part=="output" && !p.at("input").get<std::string>().empty()) base=resolve_path(wide(p.at("input").get<std::string>()),base);
        choosing_directory_=true;
        fs::path selected;
        try { selected=choose_directory(hwnd_,value.empty()?fs::path():resolve_path(wide(value),base)); }
        catch(...) { choosing_directory_=false; throw; }
        choosing_directory_=false;
        auto picked=Json{{"id",p.at("id")},{"part",part},{"value",utf8(selected.wstring())}}.dump();
        if(ui_page_call_json(page_,"rootPicked",picked.c_str())!=0) throw std::runtime_error("uiBindingFailed");
        return;
    }
    if(op=="pickRangeDate") {
        auto side=p.at("side").get<std::string>();
        if(side!="lower" && side!="upper") return;
        date_popup_.reset();
        auto id=p.at("id").get<std::string>();
        if(page_value(page_,"tab")!="config") return;
        ui_window_relayout(window_);
        auto root=ui_page_root(page_);
        auto anchor=ui_widget_find_by_id(root,("range-"+side+"-"+id).c_str());
        ui_widget_destroy(root);
        if(!anchor) return; // The virtual row may have been filtered/unmounted.
        auto rect=ui_widget_get_rect(anchor); ui_widget_destroy(anchor);
        auto dpi=ui_window_dpi(window_);
        POINT start{LONG(std::lround(rect.left*dpi/96)),LONG(std::lround(rect.top*dpi/96))};
        POINT end{LONG(std::lround(rect.right*dpi/96)),LONG(std::lround(rect.bottom*dpi/96))};
        ClientToScreen(hwnd_,&start); ClientToScreen(hwnd_,&end);
        RECT screen{start.x,start.y,end.x,end.y};
        date_popup_=std::make_unique<DatePopup>(window_,DateResult,++date_generation_,screen,id,side,
            p.at("value"),page_value(page_,"language"),page_value(page_,"appearance"));
        date_popup_->show();
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
    if(op=="filterTasks") ui_page_call_json(page_,"resetTaskPages","{}");
    if(op=="filterTasks" || op=="taskPage") ++task_query_generation_;
    { std::lock_guard<std::mutex> lock(mutex_);
      if(op=="filterTasks" || op=="taskPage") commands_.erase(std::remove_if(commands_.begin(),commands_.end(),[](const auto& pending){
          auto op=pending.value("op",std::string()); return op=="filterTasks" || op=="taskPage";
      }),commands_.end());
      commands_.push_back(std::move(command)); }
    cv_.notify_one();
}
void Application::finish_date_popup(UINT_PTR generation) {
    if(!date_popup_ || generation!=date_generation_) return;
    if(date_popup_->closed()) { date_popup_.reset(); return; }
    if(date_popup_->cancelled()) return;
    if(!date_popup_->confirming()) return;
    try {
        auto id=date_popup_->field, side=date_popup_->side, value=date_popup_->value();
        auto fields=page_value(page_,"fields"),drafts=page_value(page_,"drafts");
        auto field=std::find_if(fields.begin(),fields.end(),[&](const Json& f){return f["id"]==id;});
        if(field==fields.end()) { date_popup_.reset(); return; }
        auto form=drafts.contains(id) && drafts[id].contains("range")?drafts[id]["range"]:field->at("range");
        form[side]=value;
        auto module=range_configuration(form,true,date_popup_->zone());
        auto utc=module.at(side=="lower"?"start_utc":"end_utc");
        auto reply=Json{{"id",id},{"side",side},{"value",value},{"utc",utc}}.dump();
        if(ui_page_call_json(page_,"pickedRange",reply.c_str())!=0) throw std::runtime_error("uiBindingFailed");
        date_popup_->close();
    } catch(const std::exception& e) {
        if(date_popup_) date_popup_->error(e.what());
        else throw;
    }
}
LRESULT CALLBACK Application::subclass(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam,UINT_PTR,DWORD_PTR data) {
    auto* self=reinterpret_cast<Application*>(data);
    try {
        if(message==DateResult) { self->finish_date_popup(wparam); return 0; }
        if(message==WM_CLOSE || message==WM_LBUTTONDOWN || message==WM_RBUTTONDOWN || message==WM_NCLBUTTONDOWN ||
           message==WM_MOUSEWHEEL || message==WM_MOUSEHWHEEL || message==WM_MOVE || message==WM_SIZE ||
           message==WM_DPICHANGED || message==WM_DISPLAYCHANGE || message==WM_TIMECHANGE || message==WM_SETTINGCHANGE) {
            if(message==WM_CLOSE) self->date_popup_.reset();
            else if(self->date_popup_) self->date_popup_->close();
        }
        if((message==WM_MOUSEWHEEL || message==WM_MOUSEHWHEEL || message==WM_KILLFOCUS) && !self->choosing_directory_ &&
           (page_value(self->page_,"passwordCell")!="" || page_value(self->page_,"rootCell")!="")) {
            ui_window_focus_widget(self->window_,0);
            ui_page_call_json(self->page_,"finishRootCell","{}");
            self->dispatch();
        }
        if(message==Dispatch) { self->dispatch(); return 0; }
        if(message==Update) {
            self->apply_pending();
            // Reveal after committing the first data/layout transaction.
            // Service notifications may precede the data snapshot.
            if(page_value(self->page_,"ready")==true) self->reveal();
            return 0;
        }
        if(message==WM_ACTIVATE && LOWORD(wparam)!=WA_INACTIVE) { self->changed(Startup); SetEvent(self->service_refresh_); }
        if(message==WM_SETTINGCHANGE && page_value(self->page_,"theme")=="system") apply_theme(self->page_,system_theme(),self->hwnd_);
    } catch(const std::exception& e) {
        self->set_error("actionError",e.what());
        self->reveal(); // A binding failure must remain visible and closable.
    }
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
    date_popup_.reset();
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
        // Retry only after an observed publication race; no history cache.
        bool task_query_pending=true;
        std::map<unsigned,ReadRetry> retries;
        bool initial_load_complete=false;
        auto retry_io=[&](unsigned bit,const WinError& error) {
            if(error.code!=ERROR_SHARING_VIOLATION && error.code!=ERROR_LOCK_VIOLATION && error.code!=ERROR_FILE_NOT_FOUND && error.code!=ERROR_PATH_NOT_FOUND) return;
            auto& retry=retries[bit];
            // A rename notification can precede the writer releasing its sharing lock.
            // Bounded one-shot deadlines exist only after an observed I/O failure.
            constexpr unsigned delays[]={5,20,80};
            if(retry.attempts<3) retry.due=Clock::now()+std::chrono::milliseconds(delays[retry.attempts++]);
        };
        for(;;) {
            unsigned flags; std::deque<Json> commands; uint64_t query_generation;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                auto deadline=Clock::time_point::max();
                for(auto& retry:retries) deadline=std::min(deadline,retry.second.due);
                auto awake=[&]{return stopping_ || dirty_ || !commands_.empty();};
                if(deadline==Clock::time_point::max()) cv_.wait(lock,awake);
                else cv_.wait_until(lock,deadline,awake);
                if(stopping_) break;
                flags=dirty_; dirty_=0; commands.swap(commands_); query_generation=task_query_generation_.load();
            }
            for(auto& retry:retries) {
                if(flags&retry.first) { retry.second=ReadRetry{}; }
                else if(retry.second.due<=Clock::now()) { flags|=retry.first; retry.second.due=Clock::time_point::max(); }
            }
            bool tasks_changed=false,passwords_changed=false,dirs_changed=false,config_changed=false;
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
                    if(op=="taskPage") {
                        view.task_cursor=p.value("cursor",std::string()); tasks_changed=true;
                        if(!edit_feedback.contains("resetScroll")) edit_feedback["resetScroll"]=Json::array();
                        edit_feedback["resetScroll"].push_back("taskListScroll");
                    } else if(op=="filterTasks") {
                        auto query=p.value("query",std::string()), root=p.value("root",std::string());
                        auto status=p.value("status",std::string());
                        if(view.task_query!=query || view.task_root!=root || view.task_status!=status) {
                            if(!edit_feedback.contains("resetScroll")) edit_feedback["resetScroll"]=Json::array();
                            edit_feedback["resetScroll"].push_back("taskListScroll");
                            view.task_cursor.clear();
                            view.task_query=std::move(query); view.task_root=std::move(root);
                            view.task_status=std::move(status);
                            tasks_changed=true;
                        }
                    } else if(op=="filterPasswords") {
                        password_delta=Json(); // Filter changes require the whole result set.
                        if(!edit_feedback.contains("resetScroll")) edit_feedback["resetScroll"]=Json::array();
                        edit_feedback["resetScroll"].push_back("passwordListScroll");
                        view.password_query=p.value("query",std::string()); view.password_scope=p.value("scope",std::string("@all"));
                        passwords_changed=true;
                    } else if(op=="commit") {
                        auto kind=p.at("kind").get<std::string>();
                        PasswordSaveSnapshot saved_passwords;
                        Json password_edits=Json::array();
                        if(kind=="passwords") {
                            password_edits.push_back(p.at("edit"));
                            const auto& edit=p.at("edit");
                            if(edit["operation"]=="replace" && edit["values"].size()>1) {
                                auto tail=edit["values"]; tail.erase(tail.begin());
                                password_edits.push_back({{"operation","addMany"},{"values",std::move(tail)},{"scopes",edit["scopes"]}});
                            }
                        }
                        auto result=save_changes(dir,p.value("fields",Json::array()),
                            password_edits,
                            kind=="roots"?p.at("edits"):Json::array(),
                            &saved_passwords);
                        std::string password_original;
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
                                const auto& edit=kind=="passwords"?p.at("edit"):Json::object();
                                if(!saved_passwords.record.is_null()) password_original=saved_passwords.record.dump();
                                if(edit.value("operation",std::string())=="replace" &&
                                   !saved_passwords.count_changed && !saved_passwords.record.is_null() &&
                                   edit["values"].size()<=1 && view.password_query.empty() && view.password_scope=="@all" &&
                                   !passwords_changed && previous_patch.contains("passwords")) {
                                    Json record={{"value",edit.value("value",std::string())}};
                                    auto scopes=edit.value("scopes",Json::array());
                                    if(!scopes.empty()) record["scopes"]=std::move(scopes);
                                    auto projected=password_rows(Json{{"passwords",Json::array({std::move(record)})}},view,language);
                                    if(!projected["rows"].empty())
                                        password_delta={{"scope",view.password_scope},{"original",edit.at("original")},{"row",projected["rows"][0]}};
                                } else password_delta=Json();
                                passwords_changed=true;
                            }
                            if(section=="roots") { flags|=Roots; tasks_changed=dirs_changed=true; }
                        }
                        auto message=result["error"].get<std::string>();
                        edit_feedback["saveAck"]={{"job",p},{"ok",message.empty()},{"error",message}};
                        if(kind=="passwords") {
                            edit_feedback["saveAck"]["passwordOriginal"]=password_original;
                            edit_feedback["saveAck"]["passwordRebases"]=std::move(saved_passwords.rebases);
                        }
                        if(kind=="roots") edit_feedback["saveAck"]["passwordRebases"]=std::move(saved_passwords.rebases);
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
                read(Roots,"sunpack_watch_roots.txt",last_roots,roots_read,[&](const std::string& text){roots=parse_roots(text,dir); tasks_changed=dirs_changed=true;});
            }
            auto log_dir=log_directory(dir,config);
            if(log.path()!=log_dir/"events.json" || !log_watcher || !log_watcher->alive() || (!log_watcher->direct() && fs::is_directory(log_dir))) {
                log_watcher.reset();
                try {
                    log_watcher=std::make_unique<DirectoryWatcher>(log_dir,[this](const fs::path& path){
                        auto name=path.filename().wstring(); CharLowerBuffW(name.data(),DWORD(name.size()));
                        std::error_code ec;
                        if(path.empty() || name==L"events.json" || fs::is_directory(path,ec)) changed(Log);
                    }); errors.erase("logObserver");
                } catch(const std::exception& e) { errors["logObserver"]=e.what(); }
                log.set_path(log_dir/"events.json"); flags|=Log; tasks_changed=true;
            }
            if(flags&Log) {
                try {
                    bool refreshed=log.refresh(retries.count(Log) && retries.at(Log).attempts>=3);
                    tasks_changed|=refreshed || task_query_pending;
                    errors.erase("events.json");
                    if(!task_query_pending) retries.erase(Log);
                }
                catch(const WinError& e){
                    const bool transient=e.code==ERROR_SHARING_VIOLATION || e.code==ERROR_LOCK_VIOLATION || e.code==ERROR_FILE_NOT_FOUND || e.code==ERROR_PATH_NOT_FOUND;
                    if(transient) errors.erase("events.json"); else errors["events.json"]=e.what();
                    tasks_changed=true; retry_io(Log,e);
                }
                catch(const std::exception& e){ errors["events.json"]=e.what(); tasks_changed=true; }
            }
            Json patch=Json::object();
            auto next_language=gui_language(config);
            bool language_changed=language!=next_language || !previous_patch.contains("language");
            language=std::move(next_language);
            if(language_changed) { patch["language"]=language; patch["texts"]=interface_texts(language); }
            if(tasks_changed || language_changed || !previous_patch.contains("tasks")) {
                log.cancelled=[this,query_generation]{return task_query_generation_.load()!=query_generation || WaitForSingleObject(stop_,0)==WAIT_OBJECT_0;};
                try {
                    auto projected=task_rows(log,roots,view,language);
                    if(!projected.is_null()) { patch["tasks"]=std::move(projected); task_query_pending=false; retries.erase(Log); }
                    errors.erase("events.json");
                } catch(const WinError& e) {
                    task_query_pending=true;
                    const bool transient=e.code==ERROR_SHARING_VIOLATION || e.code==ERROR_LOCK_VIOLATION || e.code==ERROR_FILE_NOT_FOUND || e.code==ERROR_PATH_NOT_FOUND;
                    if(transient) errors.erase("events.json"); else errors["events.json"]=e.what();
                    retry_io(Log,e);
                }
                  catch(const std::exception& e) { task_query_pending=true; errors["events.json"]=e.what(); }
                log.cancelled={};
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
            // Reuse observed I/O retries before revealing the initial snapshot.
            // Permanent failures still reveal their error after retries finish.
            initial_load_complete|=std::none_of(retries.begin(),retries.end(),[](const auto& retry){return retry.second.due!=Clock::time_point::max();});
            patch["errors"]=std::move(displayed_errors); patch["logPath"]=utf8(log.path().wstring()); patch["ready"]=initial_load_complete;
            Json changed_patch=Json::object();
            for(auto it=patch.begin();it!=patch.end();++it) if(!previous_patch.contains(it.key()) || it.key()=="tasks" || it.key()=="passwords" || it.key()=="passwordDelta" || previous_patch[it.key()]!=it.value()) {
                // These projections are generated only after source/filter
                // changes. Keep an initialization marker, not a second full
                // resident copy of the task/password list.
                previous_patch[it.key()]=(it.key()=="tasks" || it.key()=="passwords" || it.key()=="passwordDelta")?Json():it.value();
                changed_patch[it.key()]=std::move(it.value());
            }
            changed_patch.update(edit_feedback);
            if(!changed_patch.empty()) publish(std::move(changed_patch));
        }
    } catch(const std::exception& e) { publish({{"actionError",e.what()},{"ready",true}}); }
    CoUninitialize();
}
}
