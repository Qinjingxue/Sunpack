#include "event_publication.hpp"
#include "application.hpp"
#include "ui_defaults_json.h"
#include "registry_fixture.hpp"
#include <algorithm>
#include <cassert>
#include <cwchar>
#include <fstream>
#include <iostream>
#include <memory>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/controls.h>
#include <ui/ui_debug.h>

using namespace spg;

void rendering_contracts();
int theme_contracts(int argc,wchar_t** argv);
int startup_failure_contract();

namespace {
// The live TAG fixture is two levels deep and cannot expose replay of a
// partially consumed packet across several ancestors. This in-memory route
// also catches stale/owning gate entries without another rendered UI fixture.
void wheel_chain_contracts() {
    struct ObservedArea : ui::TextAreaWidget {
        int calls=0;
        float received=0;
        bool OnMouseWheel(const ui::MouseEvent& event) override {
            ++calls; received=event.delta;
            return TextAreaWidget::OnMouseWheel(event);
        }
    };
    ui::UiWindowImpl window;
    auto outer=std::make_shared<ObservedArea>(); outer->rect={0,0,300,100};
    auto middle=std::make_shared<ObservedArea>(); middle->rect={0,0,220,90};
    auto empty=std::make_shared<ui::ScrollViewWidget>(); empty->rect={0,0,200,80};
    auto inner=std::make_shared<ObservedArea>(); inner->rect=empty->rect;
    const std::wstring longText(40,L'\n');
    for(auto* area:{outer.get(),middle.get(),inner.get()}) area->SetText(longText);
    outer->OnMouseWheel({20,20,-12000}); outer->calls=0;
    outer->AddChild(middle); middle->AddChild(empty); empty->AddChild(inner);
    window.SetRoot(outer);
    auto wheel=[&](int delta,float x=20) { window.SimMouseWheel(x,20,float(delta)); };
    for(int i=0;i<12;++i) wheel(30);
    assert(inner->calls==12 && middle->calls==0 && outer->calls==0);
    wheel(330); // Inner is open; the middle spends its own budget.
    assert(middle->received==330 && outer->calls==0);
    wheel(60); // Only 30 remains after the middle finishes its 360 units.
    assert(outer->calls==1 && outer->received==30);
    wheel(1);
    assert(outer->calls==2 && outer->received==1); // Stay open, no backlog.

    const int middleCalls=middle->calls, outerCalls=outer->calls;
    wheel(-30); wheel(30); // Reverse inward immediately, then return to the edge.
    assert(middle->calls==middleCalls && outer->calls==outerCalls);
    wheel(360); assert(middle->calls==middleCalls);
    wheel(360); assert(outer->calls==outerCalls); // Both gates rearmed.

    // No overflow means no resistance, even after a formerly scrolling range.
    inner->SetText(L"short");
    wheel(60); assert(outer->received==60 && outer->calls==outerCalls+1);
    middle->SetText(L"short");
    wheel(30); assert(outer->received==30 && outer->calls==outerCalls+2);

    inner->SetText(longText);
    wheel(60); // Partial budget; visiting another route must discard it.
    wheel(30,250);
    const int afterSwitch=outer->calls;
    wheel(120); wheel(120); wheel(120); assert(outer->calls==afterSwitch);
    wheel(1); assert(outer->calls==afterSwitch+1 && outer->received==1);
}

Json state(UiPage page,const char* key) {
    std::unique_ptr<char,decltype(&ui_page_free)> text(ui_page_get_json(page,key),ui_page_free);
    if(!text) throw std::runtime_error(std::string("UI state unavailable: ")+key);
    return parse_json(text.get());
}
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
void pump(const std::function<bool()>& condition, const std::string& phase="UI event") {
    auto deadline=GetTickCount64()+10000;
    for(;;) {
        MSG message;
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) {
            if(message.message==WM_QUIT) continue;
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        try { if(condition()) return; }
        catch(const WinError& error) {
            // Test-side reads can overlap ReplaceFile's rename/share window.
            // Wait for the actual queued UI/file event, with the same deadline.
            if(error.code!=ERROR_FILE_NOT_FOUND && error.code!=ERROR_PATH_NOT_FOUND && error.code!=ERROR_SHARING_VIOLATION) throw;
        }
        auto now=GetTickCount64();
        if(now>=deadline) throw std::runtime_error(phase+" timed out");
        MsgWaitForMultipleObjectsEx(0,nullptr,DWORD(deadline-now),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    }
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
        for(auto key:{"directorySelection","rootCell","rootPart","rootDrafts","saveErrors"}) std::cerr<<key<<"="<<state(app.page(),key)<<'\n';
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

void finish_input(Application& app) {
    ui_window_focus_widget(app.window(),0);
    ui_debug_pump();
    pump([&]{return state(app.page(),"requests").empty() && state(app.page(),"dispatch")==false && state(app.page(),"saving")==false && state(app.page(),"pendingFields").empty();},"Automatic writes");
    auto errors=state(app.page(),"saveErrors");
    if(!errors.empty()) throw std::runtime_error(errors.dump());
}

ui::UiWindowImpl& window(Application& app) {
    return *ui::GetContext().GetWindow(app.window());
}

void navigate(Application& app,const char* button,const char* tab) {
    click(app,button);
    pump([&]{return state(app.page(),"tab")==tab;},"Navigate to "+std::string(tab));
    ui_window_relayout(app.window());
}

void replace_text(UiWindow window,const wchar_t* value) {
    assert(ui_debug_key_mod(window,'A',1,0,0)==0);
    assert(ui_debug_type_char(window,8)==0);
    if(*value) assert(ui_debug_type_text(window,value)==0);
}

void edit_text(Application& app,const std::string& id,const wchar_t* value) {
    click(app,id.c_str());
    replace_text(app.window(),value);
}

void focus(Application& app,const std::string& id) {
    pump([&]{
        auto* focused=window(app).FocusedWidget();
        return focused && focused->id==id;
    },"Focus "+id);
}

void select_option(Application& app,const std::string& id,int option) {
    ui_window_relayout(app.window());
    auto* widget=window(app).Root()->FindById(id);
    assert(widget);
    auto handle=ui::GetContext().handles.Insert(widget->shared_from_this());
    assert(ui_debug_combo_select(app.window(),handle,option)==0);
    ui_widget_destroy(handle);
}

Json setting(Application& app,const std::string& id) {
    for(auto& field:state(app.page(),"fields"))
        if(field["id"]==id || field["module"]==id) return field;
    throw std::runtime_error("Setting not found: "+id);
}

void search_setting(Application& app,const std::string& id) {
    auto label=wide(setting(app,id)["label"].get<std::string>());
    search_config(app,label.c_str());
}

void screenshot(UiWindow window,const wchar_t* name) {
    wchar_t path[32768];
    auto n=GetEnvironmentVariableW(L"SUNPACK_GUI_SCREENSHOTS",path,32768);
    if(!n || n>=32768) return;
    fs::create_directories(path);
    ui_window_relayout(window);
    assert(ui_debug_screenshot(window,(fs::path(path)/name).c_str())==0);
}

ui::UiWindowImpl* date_popup_window(HWND hwnd) {
    wchar_t name[64]{};
    GetClassNameW(hwnd,name,64);
    if(std::wcscmp(name,L"UiCore_Window")!=0) return nullptr;
    auto* popup=reinterpret_cast<ui::UiWindowImpl*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
    return popup && popup->Root() && popup->Root()->id=="datePopupSurface"?popup:nullptr;
}

ui::UiWindowImpl* date_popup(Application& app) {
    struct Search { HWND owner; ui::UiWindowImpl* popup=nullptr; } search{window(app).Handle()};
    EnumThreadWindows(GetCurrentThreadId(),[](HWND hwnd,LPARAM data)->BOOL {
        auto& search=*reinterpret_cast<Search*>(data);
        if(GetWindow(hwnd,GW_OWNER)==search.owner) {
            if(auto* popup=date_popup_window(hwnd)) {
                assert(!search.popup);
                search.popup=popup;
            }
        }
        return TRUE;
    },reinterpret_cast<LPARAM>(&search));
    return search.popup;
}

class DateTestActivation {
public:
    DateTestActivation()
        : hook_(SetWindowsHookExW(WH_CBT,filter,nullptr,GetCurrentThreadId())) {
        assert(hook_);
    }
    ~DateTestActivation() { UnhookWindowsHookEx(hook_); }
    DateTestActivation(const DateTestActivation&)=delete;
    DateTestActivation& operator=(const DateTestActivation&)=delete;
private:
    static LRESULT CALLBACK filter(int code,WPARAM wp,LPARAM lp) {
        // The test drives the popup HWND directly. Keep it out of desktop
        // activation so a foreground switch cannot cancel a synthetic edit.
        if(code==HCBT_ACTIVATE && date_popup_window(reinterpret_cast<HWND>(wp))) return 1;
        return CallNextHookEx(nullptr,code,wp,lp);
    }
    HHOOK hook_;
};

ui::UiWindowImpl* open_date(Application& app,const std::string& id,const char* side) {
    click(app,("range-"+std::string(side)+"-pick-"+id).c_str());
    ui::UiWindowImpl* popup=nullptr;
    pump([&]{popup=date_popup(app); return popup!=nullptr;},"Open date picker");
    return popup;
}

class DateTestModifiers {
public:
    explicit DateTestModifiers(bool pressed=false) {
        assert(GetKeyboardState(saved_));
        BYTE keys[256];
        std::copy_n(saved_,256,keys);
        for(int modifier:{VK_CONTROL,VK_LCONTROL,VK_RCONTROL,VK_SHIFT,VK_LSHIFT,VK_RSHIFT})
            keys[modifier]=pressed?0x80:0;
        assert(SetKeyboardState(keys));
    }
    ~DateTestModifiers() { assert(SetKeyboardState(saved_)); }
    DateTestModifiers(const DateTestModifiers&)=delete;
    DateTestModifiers& operator=(const DateTestModifiers&)=delete;
private:
    BYTE saved_[256];
};

void popup_key(ui::UiWindowImpl& popup,int key) {
    // Route through the real subclass, with modifiers scoped to this message.
    DateTestModifiers unmodified;
    SendMessageW(popup.Handle(),WM_KEYDOWN,key,0);
}

void popup_click(ui::UiWindowImpl& popup,const char* id) {
    ui_window_relayout(popup.windowId);
    auto* widget=popup.Root()->FindById(id);
    assert(widget);
    auto handle=ui::GetContext().handles.Insert(widget->shared_from_this());
    assert(ui_debug_click(popup.windowId,handle)==0);
    ui_widget_destroy(handle);
}

std::wstring popup_text(ui::UiWindowImpl& popup,const char* id) {
    auto* label=dynamic_cast<ui::LabelWidget*>(popup.Root()->FindById(id));
    assert(label);
    return label->Text();
}

void range_config(Application& app,const fs::path& config_path) {
    const auto size=setting(app,"size_range")["id"].get<std::string>();
    const auto date=setting(app,"mtime_range")["id"].get<std::string>();
    auto persisted=[&](const std::string& id) {return read_json(config_path)[Json::json_pointer(id)];};
    auto rejected=[&](const std::string& id) {
        ui_window_focus_widget(app.window(),0);
        pump([&]{return state(app.page(),"saveErrors").contains(id);},"Range validation");
    };
    auto lower_bytes=[&](const Json& expected) {
        pump([&]{return parse_json(setting(app,size)["text"])["min_bytes"]==expected;},
            "Reload saved size bound");
        assert(persisted(size)["min_bytes"]==expected);
    };

    search_setting(app,size);
    edit_text(app,"range-lower-"+size,L"9007199254740993");
    finish_input(app);
    lower_bytes(uint64_t(9007199254740993));
    edit_text(app,"range-lower-"+size,L"");
    finish_input(app);
    lower_bytes(nullptr);
    select_option(app,"range-lower-unit-"+size,2); // MiB before entering a bound.
    edit_text(app,"range-lower-"+size,L"2");
    finish_input(app);
    lower_bytes(2097152);
    const auto valid_size=persisted(size);
    edit_text(app,"range-upper-"+size,L"1");
    rejected(size);
    assert(persisted(size)==valid_size);
    edit_text(app,"range-upper-"+size,L"");
    finish_input(app);

    search_setting(app,date);
    edit_text(app,"range-lower-"+date,L"2023-02-29 00:00");
    rejected(date);
    edit_text(app,"range-lower-"+date,L"2024-01-31 12:34");
    finish_input(app);

    DateTestActivation activation;
    auto* popup=open_date(app,date,"lower");
    auto popup_hwnd=popup->Handle();
    pump([&]{
        BYTE alpha=0;
        DWORD flags=0;
        return GetLayeredWindowAttributes(popup_hwnd,nullptr,&alpha,&flags) && alpha==255 && (flags&LWA_ALPHA);
    },"Date picker first frame");
    assert(GetActiveWindow()!=popup_hwnd);
    assert(popup_text(*popup,"dateSelected")==L"2024-01-31");
    {
        // Reproduce a held modifier without changing the desktop's input.
        DateTestModifiers held(true);
        popup_key(*popup,VK_NEXT);
    }
    auto selected=popup_text(*popup,"dateSelected");
    if(selected!=L"2024-02-29") throw std::runtime_error("Date picker Page Down selected "+utf8(selected));
    screenshot(popup->windowId,L"date-popup.png");

    auto before=read_file(config_path);
    popup_key(*popup,VK_TAB);
    assert(popup->FocusedWidget() && popup->FocusedWidget()->id=="dateTime");
    replace_text(popup->windowId,L"25:70");
    popup_key(*popup,VK_RETURN);
    pump([&]{return !popup_text(*popup,"dateError").empty();},"Invalid popup time");
    assert(read_file(config_path)==before);
    replace_text(popup->windowId,L"12:34");
    popup_click(*popup,"dateConfirm");
    pump([&]{
        return !date_popup(app) && setting(app,date)["range"]["lower"]=="2024-02-29 12:34";
    },"Save selected date");
    assert(persisted(date).contains("start_utc"));

    // Send deactivation explicitly to cover cancellation through the real
    // HWND handler, independent of whatever is active on the desktop.
    before=read_file(config_path);
    popup=open_date(app,date,"upper");
    SendMessageW(popup->Handle(),WM_ACTIVATE,WA_INACTIVE,0);
    pump([&]{return !date_popup(app);},"Cancel date picker on deactivation");
    assert(read_file(config_path)==before);

    popup=open_date(app,date,"lower");
    std::weak_ptr<ui::Widget> tree=popup->Root();
    auto owner=window(app).Handle();
    SendMessageW(owner,WM_CLOSE,0,0);
    pump([&]{return !IsWindow(owner);},"Close date picker with its owner");
    assert(tree.expired());
}

void config_edits(Application& app,const fs::path& dir) {
    const auto config_path=dir/"sunpack_config.json";
    navigate(app,"tabConfig","config");
    click(app,"category-watch");
    pump([&]{return state(app.page(),"configCategory")=="watch";},"Filter settings by category");
    assert(!state(app.page(),"matchingBlocks").empty());
    click(app,"category-all");
    pump([&]{return state(app.page(),"configCategory")=="";},"Restore settings categories");

    const std::string priority="/runtime/process_mode";
    auto options=setting(app,priority)["options"];
    search_config(app,wide(options[2]["label"].get<std::string>()).c_str());
    select_option(app,"select-"+priority,2);
    finish_input(app);
    assert(read_json(config_path)["runtime"]["process_mode"]=="high");

    search_setting(app,"/watch/toast_enabled");
    click(app,"toggle-/watch/toast_enabled");
    finish_input(app);
    assert(read_json(config_path)["watch"]["toast_enabled"]==false);

    const std::string output="/watch/out_dir", input="input-"+output;
    search_setting(app,output);
    edit_text(app,input,L"local output");
    auto external=read_json(config_path);
    external["watch"]["out_dir"]="external output";
    atomic_write(config_path,external.dump());
    pump([&]{return setting(app,output)["text"]=="external output";},"Reload changed setting");
    click(app,"configSearch");
    pump([&]{return state(app.page(),"saveErrors").contains(output);},"Report a settings conflict");
    assert(read_json(config_path)["watch"]["out_dir"]=="external output");
    assert(state(app.page(),"drafts")[output]["text"]=="local output");
    edit_text(app,input,L"resolved output");
    finish_input(app);
    assert(read_json(config_path)["watch"]["out_dir"]=="resolved output");

    search_setting(app,"/cli/language");
    select_option(app,"select-/cli/language",1);
    finish_input(app);
    pump([&]{return state(app.page(),"language")=="en";},"Switch interface language");
    assert(state(app.page(),"texts")["config"]=="Settings");
    search_config(app,L"");
    screenshot(app.window(),L"configuration.png");
}

void tag_config(Application& app,const fs::path& dir) {
    const std::string id="/filesystem/scan_filters/0/paths", input="tag-input-"+id;
    auto disk=[&]{return read_json(dir/"sunpack_config.json")[Json::json_pointer(id)];};
    search_setting(app,id);
    auto before=disk();
    click(app,input.c_str());
    assert(ui_debug_type_text(app.window(),L"  literal[0]  ")==0);
    click(app,"configSearch");
    assert(disk()==before); // Blur must not submit a rule.
    click(app,input.c_str());
    assert(ui_debug_key(app.window(),VK_RETURN)==0);
    finish_input(app);
    auto saved=disk();
    assert((saved.back()==Json{{"value","  literal[0]  "},{"regex",false}}));

    auto edit_first=[&] {
        auto* tags=window(app).Root()->FindById("tags-"+id);
        assert(tags);
        auto bounds=tags->rect;
        assert(ui_debug_mouse_down(app.window(),bounds.left+10,bounds.top+13)==0);
        assert(ui_debug_mouse_up(app.window(),bounds.left+10,bounds.top+13)==0);
        pump([&]{return state(app.page(),"tagEdits").contains(id);},"Edit saved rule");
    };
    edit_first();
    click(app,("tag-regex-"+id).c_str());
    edit_text(app,input,L"(");
    assert(ui_debug_key(app.window(),VK_RETURN)==0);
    pump([&]{return state(app.page(),"saveErrors").contains(id);},"Reject invalid regular expression");
    assert(disk()==saved);
    edit_first();
    edit_text(app,input,L"^cache/[0-9]+$");
    assert(ui_debug_key(app.window(),VK_RETURN)==0);
    finish_input(app);
    saved=disk();
    assert((saved.back()==Json{{"value","^cache/[0-9]+$"},{"regex",true}}));
    assert(read_json(dir/"cli-validation-input.json")["paths"]==saved);
    search_config(app,L"");
}


void watch_commands(Application& app,const fs::path& dir) {
    auto args_path=dir/"cli-arguments.json";
    auto command=[&](const char* button,const Json& args) {
        fs::remove(args_path);
        click(app,button);
        pump([&]{
            return fs::exists(args_path) && read_json(args_path)==args &&
                   state(app.page(),"busy")==false;
        },std::string("Run ")+button);
        assert(state(app.page(),"actionError")=="");
    };
    command("watchStart",Json::array({"watch","start"}));
    command("watchStop",Json::array({"watch","stop"}));
    navigate(app,"tabConfig","config");
    auto enabled=state(app.page(),"startupEnabled").get<bool>();
    command("startupToggle",Json::array({"watch","startup",enabled?"disable":"enable"}));
}

void recover_task_log(Application& app,const fs::path& dir) {
    auto log=dir/".sunpack_watch"/"events.json", args=dir/"cli-arguments.json";
    fs::remove(args);
    // Keep the manifest path in place while corrupting its contents, so the
    // watcher sees a bad log rather than an unrelated rename-sharing conflict.
    { std::ofstream broken(log,std::ios::binary|std::ios::trunc); broken<<"{"; }
    pump([&]{
        auto rows=state(app.page(),"tasks")["rows"];
        return fs::exists(args) && read_json(args)==Json::array({"watch","rebuild-log"}) &&
               rows.size()==1 && rows[0]["name"]=="recovered.001" &&
               state(app.page(),"errors").empty() && state(app.page(),"busy")==false;
    },"Recover corrupt task log");
}

void task_card(Application& app) {
    auto saved=state(app.page(),"tasks");
    auto data=saved;
    auto& row=data["rows"][0];
    auto id=row["id"].get<std::string>();
    row["parts"]=Json::array({"disguised.001","unrelated.bin"});
    row["error"]="CRC mismatch";
    row["errorType"]="Damaged archive";
    row["status"]="taskFailed";
    assert(ui_page_set_json(app.page(),"tasks",data.dump().c_str())==0);
    ui_window_set_size(app.window(),850,560);
    ui_window_relayout(app.window());
    auto& native=window(app);
    auto* part=dynamic_cast<ui::LabelWidget*>(native.Root()->FindById("taskPart-"+id+"-1"));
    auto* error=dynamic_cast<ui::LabelWidget*>(native.Root()->FindById("taskErrorMessage-"+id));
    assert(part && part->Text()==L"unrelated.bin");
    assert(error && error->Text().find(L"CRC mismatch")!=std::wstring::npos);
    screenshot(app.window(),L"task-details.png");
    assert(ui_page_set_json(app.page(),"tasks",saved.dump().c_str())==0);
    ui_window_set_size(app.window(),1120,720);
}

std::string root_row_id(Application& app,const fs::path& path) {
    for(auto& row:state(app.page(),"rootRows"))
        if(path_key(wide(row["input"].get<std::string>()))==path_key(path))
            return row["id"].get<std::string>();
    throw std::runtime_error("Root row missing: "+utf8(path.wstring()));
}

void roots_and_passwords(Application& app,const fs::path& dir) {
    const auto root=dir/"new-root";
    fs::create_directory(root);
    const auto root_path=dir/"sunpack_watch_roots.txt", passwords_path=dir/"builtin_passwords.json";
    const auto scope=utf8(root.wstring());
    const auto directory="directory-"+utf8(path_key(root));
    auto disk_root=[&](const std::string& output) {
        auto roots=read_roots(root_path);
        return std::any_of(roots.entries.begin(),roots.entries.end(),[&](const auto& entry){
            return entry.input==root && entry.output==output;
        });
    };

    navigate(app,"tabRoots","roots");
    click(app,"addRoot");
    auto new_root=state(app.page(),"rootCell").get<std::string>();
    focus(app,"root-input-input-"+new_root);
    assert(ui_debug_type_text(app.window(),root.c_str())==0);
    finish_input(app);
    assert(disk_root({}));

    auto root_id=root_row_id(app,root);
    click(app,("root-output-text-"+root_id).c_str());
    focus(app,"root-output-input-"+root_id);
    replace_text(app.window(),L"relative-output");
    finish_input(app);
    assert(disk_root("relative-output"));

    navigate(app,"tabTasks","tasks");
    click(app,directory.c_str());
    pump([&]{
        auto pages=state(app.page(),"taskPages");
        return !pages.empty() && pages[0]["root"]==scope && state(app.page(),"tasks")["rows"].empty();
    },"Filter tasks by monitored directory");

    navigate(app,"tabPasswords","passwords");
    pump([&]{return state(app.page(),"passwords")["scope"]==scope;},"Share directory with password view");
    assert(state(app.page(),"passwords")["rows"].empty());
    click(app,"newPassword");
    auto new_password=state(app.page(),"passwordCell").get<std::string>();
    focus(app,"password-input-"+new_password);
    assert(ui_debug_type_text(app.window(),L"  #局部密码  ")==0);
    finish_input(app);
    auto saved=read_json(passwords_path)["passwords"];
    assert((saved.back()==Json{{"value","  #局部密码  "},{"scopes",{scope}}}));

    auto password_id=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    click(app,("password-text-"+password_id).c_str());
    focus(app,"password-input-"+password_id);
    replace_text(app.window(),L"edited password");
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].back()["value"]=="edited password");
    password_id=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    click(app,("delete-password-"+password_id).c_str());
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].size()==1);

    click(app,"allRoots");
    pump([&]{return state(app.page(),"passwords")["scope"]=="@all";},"Show global passwords");
    click(app,"clipboardHistory");
    pump([&]{return state(app.page(),"passwordHistory")==true;},"Show clipboard history");
    click(app,"save-history-0");
    finish_input(app);
    auto history=read_json(passwords_path);
    assert(history["passwords"].back()["value"]=="history" && history["clipboard_history"]==Json::array({"history"}));
    screenshot(app.window(),L"clipboard-history.png");

    navigate(app,"tabRoots","roots");
    click(app,("delete-root-"+root_id).c_str());
    finish_input(app);
    assert(read_roots(root_path).entries.size()==1);
}

ui::Widget* active_find_widget(ui::Widget* root) {
    if(!root || !root->visible) return nullptr;
    for(const auto& range:root->textHighlights) if(range.active) return root;
    for(const auto& child:root->Children())
        if(auto* found=active_find_widget(child.get())) return found;
    return nullptr;
}

void task_history(Application& app,const fs::path& dir) {
    constexpr int total=201;
    auto history_path=dir/".sunpack_watch"/"events.json";
    std::string events;
    for(int i=0;i<total;++i)
        events+=Json{{"event","done"},{"path",utf8((dir/"history"/("task-"+std::to_string(i)+".001")).wstring())},
            {"ts",1792401342+i}}.dump()+"\n";
    publish_events(history_path,events);

    auto rows=[&]{return state(app.page(),"tasks")["rows"];};
    auto search=[&](const std::string& query) {
        assert(ui_page_call_json(app.page(),"searchTasks",Json(query).dump().c_str())==0);
    };
    search("");
    pump([&]{return rows().size()==100;},"Load first task page");
    const auto first=rows()[0]["id"];
    auto& native=window(app);
    auto* list=dynamic_cast<ui::VirtualListWidget*>(native.Root()->FindById("taskItems"));
    auto* scroll=dynamic_cast<ui::ScrollViewWidget*>(native.Root()->FindById("taskListScroll"));
    assert(list && scroll);
    auto scroll_to=[&](float y){native.ScrollWithMeasureContext(scroll,y);};

    scroll_to(1e9f);
    pump([&]{return rows().size()==200;},"Append task page");
    scroll_to(1e9f);
    pump([&]{
        return state(app.page(),"taskPending").is_null() && state(app.page(),"tasks")["hasMore"]==false;
    },"Reach end of task history");
    assert(rows().size()<total && rows()[0]["id"]!=first && list->Children().size()<40);
    scroll_to(0);
    pump([&]{return rows()[0]["id"]==first;},"Reload evicted task page");

    auto manifest=read_json(history_path);
    auto boundary=rows()[99]["id"];
    publish_events(history_path,Json{{"event","done"},{"path",utf8((dir/"newest.001").wstring())},
        {"ts",1792402000}}.dump()+"\n",manifest["runs"]);
    pump([&]{return !rows().empty() && rows()[0]["name"]=="newest.001";},"Refresh loaded history");
    assert(rows().size()==200 && rows()[100]["id"]==boundary);

    search("task-0");
    pump([&]{
        auto visible=rows();
        return visible.size()==1 && visible[0]["name"]=="task-0.001" &&
               active_find_widget(list)!=nullptr;
    },"Find and highlight a task outside the loaded window");

    // Follow one grouped card through actual file notifications and page
    // updates. Static projection cannot catch stale virtualized member chips.
    search("");
    const auto head=dir/"shared.jpg", tail=dir/"shared.chunk3.opaque";
    const std::array<std::pair<const char*,const char*>,4> phases={{{"failed_password","taskWaiting"},
        {"suspended_missing_volume","taskWaiting"},{"processing_started","taskProcessing"},{"done","taskSucceeded"}}};
    for(size_t phase=0;phase<phases.size();++phase) {
        const auto path=phase?head:tail;
        Json members={utf8(head.wstring()),utf8(tail.wstring())};
        if(phase>=2) members.push_back(utf8((dir/"shared.chunk2.opaque").wstring()));
        Json value={{"event",phases[phase].first},{"task_id","encrypted-group"},{"path",utf8(path.wstring())},
            {"ts",1792403000+phase},{"group",{{"path",utf8(path.wstring())},{"members",members},{"multipart",true}}}};
        publish_events(history_path,value.dump()+"\n");
        pump([&]{
            const auto visible=rows();
            return visible.size()==1 && visible[0]["id"]=="encrypted-group" &&
                visible[0]["status"]==phases[phase].second && visible[0]["path"]==utf8(path.wstring()) &&
                visible[0]["parts"].size()==members.size();
        },"Refresh encrypted volume status");
        ui_window_relayout(app.window());
        auto* chip=dynamic_cast<ui::LabelWidget*>(window(app).Root()->FindById(
            "taskPart-encrypted-group-"+std::to_string(members.size()-1)));
        assert(chip && chip->Text()==(phase>=2?L"shared.chunk2.opaque":L"shared.chunk3.opaque"));
    }
}


void acceptance_contracts(Application& app,const fs::path& dir) {
    assert(state(app.page(),"tasks")["rows"][0]["name"]=="carrier.001");
    screenshot(app.window(),L"startup.png");
    task_card(app);
    select_option(app,"taskStatus",1);
    pump([&]{return state(app.page(),"tasks")["rows"].empty();},"Filter tasks by status");
    select_option(app,"taskStatus",0);
    pump([&]{return state(app.page(),"tasks")["rows"].size()==1;},"Clear status filter");
    recover_task_log(app,dir);
    watch_commands(app,dir);
    roots_and_passwords(app,dir);
    config_edits(app,dir);
    tag_config(app,dir);
    range_config(app,dir/"sunpack_config.json");
}

int fake_cli(int argc,wchar_t** argv) {
    Json args=Json::array();
    for(int i=2;i<argc;++i) args.push_back(utf8(argv[i]));
    const auto dir=fs::current_path();
    atomic_write(dir/"cli-arguments.json",args.dump());
    if(args==Json::array({"config","validate","--scan-rule-stdin","--json"})) {
        std::string input((std::istreambuf_iterator<char>(std::cin)),{});
        auto rules=parse_json(input);
        atomic_write(dir/"cli-validation-input.json",rules.dump());
        for(const auto& list:rules) for(const auto& entry:list) if(entry["regex"]==true && entry["value"]=="(") {
            std::cout<<R"({"errors":["unclosed group"]})";
            return 2;
        }
        std::cout<<R"({"errors":[]})";
        return 0;
    }
    if(args==Json::array({"watch","rebuild-log"}))
        publish_events(dir/".sunpack_watch"/"events.json",
            Json{{"event","done"},{"path",utf8((dir/"recovered.001").wstring())}}.dump()+"\n");
    std::cout<<args.dump();
    return 0;
}
}

int wmain(int argc,wchar_t** argv) {
    const auto source_root=fs::temp_directory_path()/L"SunPack source root";
    const auto native_cli=source_root/L"native"/L"sunpack_launcher.exe";
    const auto native_options=parse_options({L"--data-dir",source_root.wstring(),
        L"--cli",native_cli.wstring(),L"--app-root",source_root.wstring()});
    assert(native_options.allow_cli && native_options.cli.prefix.empty());
    assert(native_options.cli.app_root==source_root && native_options.cli.executable==native_cli);
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
    const std::wstring mode=argc>1?argv[1]:L"--acceptance";
    if(mode==L"--startup-failure") return startup_failure_contract();
    if(mode==L"--theme" || mode==L"--theme-session") return theme_contracts(argc,argv);
    if(mode==L"--fake-cli") return fake_cli(argc,argv);

    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    RegistryFixture registry;
    auto dir=fs::temp_directory_path()/(L"sunpack-gui-ui-"+std::to_wstring(GetCurrentProcessId()));
    int result=0;
    try {
        if(mode==L"--acceptance") {
            const auto package=dir/"package";
            fs::create_directories(package/"bin");
            const auto packaged_cli=package/"sunpack.exe";
            atomic_write(packaged_cli,"");
            const std::vector<std::wstring> package_args{L"--app-root",package.wstring()};
            assert(parse_options(package_args).cli.executable==packaged_cli);
            const auto installed_cli=package/"bin"/"sunpack.exe";
            atomic_write(installed_cli,"");
            assert(parse_options(package_args).cli.executable==installed_cli);
            wheel_chain_contracts();
            rendering_contracts();
        }
        fs::create_directory(dir);
        auto config=parse_json(kUiDefaultsJson);
        config["cli"]["language"]="zh";
        config["watch"]["out_dir"]=".";
        atomic_write(dir/"sunpack_config.json",config.dump());
        atomic_write(dir/"builtin_passwords.json",R"({"passwords":[{"value":"  #中文  "}],"clipboard_history":["history"]})");
        atomic_write(dir/"sunpack_watch_roots.txt",utf8(dir.wstring())+"\n");
        publish_events(dir/".sunpack_watch"/"events.json",
            Json{{"event","done"},{"path",utf8((dir/"carrier.001").wstring())}}.dump()+"\n");

        Options options;
        options.data_dir=dir;
        options.allow_cli=true;
        options.cli={executable_path(),dir,{L"--fake-cli"}};
        Application app(options);
        app.open();
        auto hwnd=window(app).Handle();
        assert(!IsWindowVisible(hwnd));
        pump([&]{return state(app.page(),"ready")==true;},"Load management panel");
        assert(IsWindowVisible(hwnd) && state(app.page(),"errors").empty());
        if(mode==L"--history") {
            task_history(app,dir);
        } else if(mode==L"--ranges") {
            navigate(app,"tabConfig","config");
            range_config(app,dir/"sunpack_config.json");
        } else {
            acceptance_contracts(app,dir);
        }
    } catch(const std::exception& error) {
        std::cerr<<error.what()<<'\n';
        result=1;
    }
    std::error_code cleanup_error;
    fs::remove_all(dir,cleanup_error);
    CoUninitialize();
    return result;
}
