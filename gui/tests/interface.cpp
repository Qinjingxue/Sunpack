#include "event_publication.hpp"
#include "application.hpp"
#include "background.hpp"
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
#include <ui/uix/script_runtime.h>

using namespace spg;

void rendering_contracts();
int theme_contracts(int argc,wchar_t** argv);
int startup_failure_contract();

namespace {
// The live TAG fixture is two levels deep and cannot expose replay of a
// partially consumed packet across several ancestors. This in-memory route
// also catches stale/owning gate entries without another rendered UI fixture.
void wheel_chain_contracts() {
    UINT lines=3;
    SystemParametersInfoW(SPI_GETWHEELSCROLLLINES,0,&lines,0);
    if(lines==0) return; // Windows has disabled wheel scrolling.

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

    // Shrinking a viewport at the bottom leaves a known distance to scroll.
    // At 96 DIP, two notches should cover a gap of one and a half steps.
    const float step=lines==WHEEL_PAGESCROLL ? 96.0f : 8.0f*std::min(lines,12u);
    ui::TextAreaWidget area;
    area.rect={0,0,200,96.0f+1.5f*step};
    area.SetText(longText);
    assert(area.OnMouseWheel({20,20,-12000}));
    area.rect.bottom=96;
    const ui::MouseEvent down{20,20,-WHEEL_DELTA};
    assert(area.OnMouseWheel(down));
    assert(area.OnMouseWheel(down));
    assert(!area.OnMouseWheel(down));
}

Json state(UiPage page,const char* key) {
    std::unique_ptr<char,decltype(&ui_page_free)> text(ui_page_get_json(page,key),ui_page_free);
    if(!text) throw std::runtime_error(std::string("UI state unavailable: ")+key);
    return parse_json(text.get());
}

void script_error_contracts() {
    for(const auto* source:{
        R"(<script>
          export default {data() {return {ready: true};}};
          try {throw new InternalError("module failed");} catch (error) {}
        </script><template><div/></template>)",
        R"(<script>
          export default {get data() {throw new InternalError("data failed");}};
        </script><template><div/></template>)",
        R"(<script>
          export default {
            methods: {ok() {}, get broken() {throw new InternalError("methods failed");}}
          };
        </script><template><div/></template>)",
        R"(<script>
          export default {
            computed: {ok() {return {};}, broken() {throw new InternalError("eager computed failed");}}
          };
        </script><template><div/></template>)"
    }) {
        UiPage page=ui_page_load_string(source);
        assert(page);
        const std::string error=ui_page_last_error(page);
        assert(error.find("InternalError: ")!=std::string::npos);
        assert(ui_page_root(page)==0 && ui_page_prepare_window(page,nullptr)==0);
        assert(ui_page_reload(page)==0);
        ui_page_destroy(page);
    }

    UiPage page=ui_page_load_string(R"(<script>
      export default {
        data() {return {broken: false, continued: false, caught: false};},
        computed: {
          derived() {
            if(this.broken) throw new InternalError("computed failed");
            return 7;
          }
        },
        methods: {
          fail() {
            this.broken=true;
            try {void this.derived;} catch (error) {this.caught=true;}
            this.continued=true;
          },
          recover() {this.broken=false;}
        }
      };
    </script><template><div/></template>)");
    assert(page && state(page,"derived")==7);
    assert(ui_page_call_json(page,"fail","null")==-1);
    assert(std::string(ui_page_last_error(page)).find("computed failed")!=std::string::npos);
    assert(state(page,"continued")==false && state(page,"caught")==false);
    assert(ui_page_call_json(page,"recover","null")==0 && state(page,"derived")==7);
    ui_page_destroy(page);

    ui::uix::ScriptRuntime runtime;
    JSMemoryUsage usage{};
    JS_ComputeMemoryUsage(runtime.rt(),&usage);
    JS_SetMemoryLimit(runtime.rt(),static_cast<size_t>(usage.malloc_size)+64*1024);
    assert(!runtime.Eval("try { new ArrayBuffer(1024 * 1024); } catch (error) {}"));
    assert(runtime.lastError().find("out of memory")!=std::string::npos);
    assert(!JS_HasException(runtime.ctx()));
    JS_SetMemoryLimit(runtime.rt(),static_cast<size_t>(-1));
    assert(!runtime.Eval("throw { toString() { throw new InternalError('secondary'); } }"));
    assert(!JS_HasException(runtime.ctx()) && runtime.Eval("1 + 1;"));
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
    pump([&]{
        if(!state(app.page(),"requests").empty() || state(app.page(),"dispatch")==true ||
            !state(app.page(),"pendingFields").empty() || state(app.page(),"collectionPending")==true) return false;
        for(auto kind:{"rootDrafts","passwordDrafts"}) for(const auto& draft:state(app.page(),kind))
            if(draft.value("pending",false)) return false;
        return true;
    },"Automatic writes");
    auto errors=state(app.page(),"saveErrors");
    if(!errors.empty()) throw std::runtime_error(errors.dump());
    for(const auto& draft:state(app.page(),"passwordDrafts")) {
        auto error=draft.find("error");
        if(error!=draft.end() && *error!="") throw std::runtime_error(error->dump());
    }
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
    BYTE alpha=0;
    DWORD flags=0;
    bool has_alpha=false;
    try {
        pump([&]{
            has_alpha=GetLayeredWindowAttributes(popup_hwnd,nullptr,&alpha,&flags) && (flags&LWA_ALPHA);
            if(!has_alpha && !IsWindow(popup_hwnd))
                throw std::runtime_error("Date picker closed before fade-in completed");
            return has_alpha && alpha==255;
        },"Date picker fade-in");
    } catch(const std::runtime_error& error) {
        auto* live=date_popup_window(popup_hwnd);
        if(live!=popup) throw;
        throw std::runtime_error(std::string(error.what())+
            " (window visible="+std::to_string(IsWindowVisible(popup_hwnd)!=FALSE)+
            ", alpha="+(has_alpha?std::to_string(alpha):"unavailable")+
            ", root opacity="+std::to_string(live->Root()->opacity)+")");
    }
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

    const std::string deduplication="/watch/deduplication";
    search_setting(app,deduplication);
    select_option(app,"select-"+deduplication,2);
    finish_input(app);
    assert(read_json(config_path)["watch"]["deduplication"]=="hash");
    const std::string deduplication_scope="/watch/deduplication_scope";
    search_setting(app,deduplication_scope);
    select_option(app,"select-"+deduplication_scope,1);
    finish_input(app);
    assert(read_json(config_path)["watch"]["deduplication_scope"]=="global");

    search_setting(app,"/watch/toast_enabled");
    click(app,"toggle-/watch/toast_enabled");
    finish_input(app);
    assert(read_json(config_path)["watch"]["toast_enabled"]==false);

    const std::string recursion="/recursive_extract", rounds="rounds-"+recursion;
    search_setting(app,recursion);
    edit_text(app,rounds,L"3");
    auto external=read_json(config_path);
    external["recursive_extract"]="4";
    atomic_write(config_path,external.dump());
    pump([&]{return setting(app,recursion)["text"]=="4";},"Reload changed setting");
    click(app,"configSearch");
    pump([&]{return state(app.page(),"saveErrors").contains(recursion);},"Report a settings conflict");
    assert(read_json(config_path)["recursive_extract"]=="4");
    assert(state(app.page(),"drafts")[recursion]["text"]=="3");
    edit_text(app,rounds,L"5");
    finish_input(app);
    assert(read_json(config_path)["recursive_extract"]=="5");

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
    const auto config_path=dir/"sunpack_config.json";
    auto disk=[&]{return read_json(config_path)[Json::json_pointer(id)];};
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
    const auto source=read_file(config_path);
    const auto filters=parse_json(source)["filesystem"]["scan_filters"];
    assert(source.find(filters[0].dump())!=std::string::npos);
    assert(source.find(filters[1].dump())!=std::string::npos);
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
    command("watchStart",Json::array({"watch","enable"}));
    command("watchStop",Json::array({"watch","disable"}));
    navigate(app,"tabConfig","config");
    auto enabled=state(app.page(),"startupEnabled").get<bool>();
    command("startupToggle",Json::array({"daemon","startup",enabled?"disable":"enable"}));
}

void recover_task_log(Application& app,const fs::path& dir) {
    auto log=dir/".sunpack_watch"/"events.json", args=dir/"cli-arguments.json";
    fs::remove(args);
    // Keep the manifest path in place while corrupting its contents, so the
    // watcher sees a bad log rather than an unrelated rename-sharing conflict.
    { std::ofstream broken(log,std::ios::binary|std::ios::trunc); broken<<"{"; }
    pump([&]{
        auto rows=state(app.page(),"tasks")["rows"];
        return fs::exists(args) && read_json(args)==Json::array({"watch","relog"}) &&
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
    auto resize_toolbar=[&](const char* search,const char* record,const char* below,int width) {
        ui_window_set_size(app.window(),width,560);
        // Inspect the resize layout itself: another layout would mask a stale row count.
        auto* button=window(app).Root()->FindById(record);
        const auto bounds=button->rect;
        assert((bounds.top>=rect(app,search).bottom)==(width==850));
        assert(std::abs(button->Parent()->rect.bottom-bounds.bottom)<1);
        const float gap=rect(app,below).top-bounds.bottom;
        assert(gap>0 && gap<bounds.bottom-bounds.top);
        auto* hit=window(app).Root()->HitTest((bounds.left+bounds.right)/2,bounds.bottom-2);
        while(hit && hit!=button) hit=hit->Parent();
        assert(hit==button);
    };
    const auto root=dir/"new-root";
    const auto root_path=dir/"sunpack_watch_roots.txt", passwords_path=dir/"builtin_passwords.json";
    const auto scope=utf8(root.wstring());
    const auto directory="directory-"+utf8(path_key(root));
    auto disk_root=[&](const std::string& output) {
        auto roots=read_roots(root_path);
        return std::any_of(roots.begin(),roots.end(),[&](const auto& entry){
            return entry.input==root && entry.output==output;
        });
    };

    navigate(app,"tabRoots","roots");
    click(app,"batchAddRoot");
    auto new_root=state(app.page(),"rootCell").get<std::string>();
    auto* new_card=window(app).Root()->FindById("root-row-"+new_root);
    assert(new_card);
    gui_test::same_color(new_card->bgColor,window(app).Root()->FindById("rootTableHeader")->bgColor);
    focus(app,"root-input-input-"+new_root);
    assert(ui_debug_type_text(app.window(),root.c_str())==0);
    finish_input(app);
    assert(disk_root({}) && !fs::exists(root));

    // Exercise the observer's missing-file path after a successful GUI add.
    // Keeping the name absent also checks the settled empty-list behavior.
    const auto staged_roots=dir/"staged-roots.txt";
    fs::rename(root_path,staged_roots);
    pump([&]{
        auto errors=state(app.page(),"errors");
        if(!errors.empty()) throw std::runtime_error("Unexpected file warning: "+errors.dump());
        return state(app.page(),"rootRows").empty();
    },"Observe absent optional roots file");
    atomic_write(root_path,"invalid root record");
    pump([&]{return state(app.page(),"errors").contains("sunpack_watch_roots.txt");},"Report invalid roots file");
    atomic_write(root_path,read_file(staged_roots));
    pump([&]{return state(app.page(),"rootRows").size()==2 && state(app.page(),"errors").empty();},"Observe republished roots");

    auto root_id=root_row_id(app,root);
    click(app,("root-output-text-"+root_id).c_str());
    focus(app,"root-output-input-"+root_id);
    replace_text(app.window(),L"relative-output");
    finish_input(app);
    assert(disk_root("relative-output"));

    navigate(app,"tabTasks","tasks");
    click(app,directory.c_str());
    pump([&]{
        return state(app.page(),"directorySelection")==scope && state(app.page(),"taskDirectoryDirty")==false &&
            !state(app.page(),"taskPages").empty() && state(app.page(),"tasks")["rows"].empty();
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
    assert((saved.back()==Json{{"value","  #局部密码  "},{"enabled",true},{"scopes",{scope}}}));

    auto password_id=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    click(app,("password-text-"+password_id).c_str());
    focus(app,"password-input-"+password_id);
    replace_text(app.window(),L"edited password");
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].back()["value"]=="edited password");
    password_id=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    click(app,("enabled-password-"+password_id).c_str());
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].back().at("enabled")==false);
    click(app,("delete-password-"+password_id).c_str());
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].size()==1);

    click(app,"allRoots");
    pump([&]{return state(app.page(),"passwords")["scope"]=="@all";},"Show global passwords");
    auto card_color=[&](const std::string& id) {
        ui_window_relayout(app.window());
        auto* card=window(app).Root()->FindById("password-"+id);
        assert(card && card->visible);
        return card->bgColor;
    };
    auto saved_card_color=[&] {
        return card_color(state(app.page(),"passwords")["rows"][0]["id"].get<std::string>());
    };
    const auto expected=ui_theme_get_mode()==UI_THEME_DARK?D2D1::ColorF(0x2b2b2b):theme::Current().cardBg;
    gui_test::same_color(saved_card_color(),expected);
    const auto select_all=rect(app,"selectAllPasswords");
    click(app,"clipboardHistory");
    // Click before the native event loop delivers the new list.
    assert(state(app.page(),"passwordHistory")==false);
    assert(window(app).Root()->FindById("selectAllPasswords")->enabled);
    assert(ui_debug_click_at(app.window(),(select_all.left+select_all.right)/2,(select_all.top+select_all.bottom)/2)==0);
    assert(state(app.page(),"passwordChecked").empty());
    pump([&]{return state(app.page(),"passwordHistory")==true;},"Show clipboard history");
    auto selected_history=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    assert(state(app.page(),"passwordChecked")==Json({{selected_history,true}}));
    auto* select_all_button=dynamic_cast<ui::ButtonWidget*>(window(app).Root()->FindById("selectAllPasswords"));
    assert(select_all_button && select_all_button->Text()==L"取消全选");
    click(app,"selectAllPasswords");
    assert(state(app.page(),"passwordChecked").empty());
    assert(select_all_button->Text()==L"全选");
    gui_test::same_color(saved_card_color(),expected);
    click(app,"savedPasswords");
    pump([&]{return state(app.page(),"passwordHistory")==false;},"Return to saved passwords");
    gui_test::same_color(saved_card_color(),expected);
    click(app,"clipboardHistory");
    pump([&]{return state(app.page(),"passwordHistory")==true;},"Show clipboard history");
    click(app,("save-history-"+state(app.page(),"passwords")["rows"][0]["id"].get<std::string>()).c_str());
    finish_input(app);
    auto history=read_json(passwords_path);
    assert(history["passwords"].back()["value"]=="history" && history["clipboard_history"]==Json::array({"history"}));
    assert(read_file(passwords_path)=="{\n  \"passwords\": "+history["passwords"].dump()+
        ",\n  \"clipboard_history\": "+history["clipboard_history"].dump()+"\n}\n");
    auto history_id=state(app.page(),"passwords")["rows"][0]["id"].get<std::string>();
    assert(rect(app,"history-value-"+history_id).right<=rect(app,"save-history-"+history_id).left);
    assert(rect(app,"savedPasswords").top>=rect(app,"passwordSearch").bottom);
    assert(std::abs(rect(app,"savedPasswords").left-rect(app,"passwordSearch").left)<1);
    screenshot(app.window(),L"clipboard-history.png");
    resize_toolbar("passwordSearch","openPasswordsRecord","savedPasswords",850);
    resize_toolbar("passwordSearch","openPasswordsRecord","savedPasswords",1120);
    click(app,"selectAllPasswords");
    click(app,"deleteSelectedPasswords");
    finish_input(app);
    assert(read_json(passwords_path).at("clipboard_history").empty());

    click(app,"newPassword");
    const auto empty_password=state(app.page(),"passwordCell").get<std::string>();
    focus(app,"password-input-"+empty_password);
    // Let the saved-list refresh complete while the new editor is still open.
    pump([&]{return state(app.page(),"passwords")["scope"]=="@all";},"Refresh saved passwords with an empty editor");
    click(app,"passwordSearch");
    ui_debug_pump();
    ui_window_relayout(app.window());
    assert(state(app.page(),"passwordCell")=="" && !state(app.page(),"passwordDrafts").contains(empty_password));
    assert(!window(app).Root()->FindById("password-"+empty_password));

    assert(ui_page_call_json(app.page(),"searchPasswords",R"("HISTORY")")==0);
    pump([&]{return state(app.page(),"passwords")["rows"].size()==1;},"Filter saved password");
    click(app,"selectAllPasswords");
    click(app,"deleteSelectedPasswords");
    finish_input(app);
    assert(read_json(passwords_path)["passwords"].size()==1);
    navigate(app,"tabRoots","roots");
    resize_toolbar("rootSearch","openRootsRecord","rootTableHeader",850);
    click(app,("enabled-root-"+root_id).c_str());
    finish_input(app);
    ui_window_relayout(app.window());
    const auto card=rect(app,"root-row-"+root_id), remove=rect(app,"delete-root-"+root_id);
    const auto aligned_center=[&](const char* heading_id,const std::string& toggle_id) {
        const auto heading=rect(app,heading_id), toggle=rect(app,toggle_id);
        const float center=(heading.left+heading.right)/2;
        // The unlabeled switch paints its 40-DIP track two DIPs from the left.
        assert(std::abs(center-(toggle.left+22))<1);
        return center;
    };
    const float deep=aligned_center("rootDeepHeading","root-deep-"+root_id);
    const float recursive=aligned_center("rootRecursiveHeading","root-recursive-"+root_id);
    const float enabled=aligned_center("rootEnabledHeading","enabled-root-"+root_id);
    assert(std::abs((recursive-deep)-(enabled-recursive))<1);
    assert(remove.right<=card.right-12);
    auto* hit=window(app).Root()->HitTest(remove.right-2,(remove.top+remove.bottom)/2);
    assert(hit && hit->id=="delete-root-"+root_id);
    screenshot(app.window(),L"roots-narrow.png");
    assert(!read_roots(root_path).back().enabled);
    assert(ui_page_call_json(app.page(),"searchRoots",R"("new-root")")==0);
    assert(state(app.page(),"shownRootRows").size()==1);
    click(app,"selectAllRoots");
    const auto check=rect(app,"selectAllRoots");
    const float middle=(check.top+check.bottom)/2;
    assert(ui_debug_mouse_move(app.window(),check.right+1,middle)==0);
    assert(!window(app).Root()->FindById("selectAllRoots")->hovered);
    click(app,"deleteSelectedRoots");
    finish_input(app);
    ui_window_set_size(app.window(),1120,720);
    assert(read_roots(root_path).size()==1);
    // Both editors keep a single draft until focus leaves. InsertText is the
    // native Ctrl+V insertion path, without touching the user's clipboard.
    click(app,"batchAddRoot");
    auto root_editor="root-input-input-"+state(app.page(),"rootCell").get<std::string>();
    focus(app,root_editor);
    auto* area=dynamic_cast<ui::TextAreaWidget*>(window(app).FocusedWidget());
    assert(area);
    area->InsertText(root.wstring());
    const auto single=rect(app,root_editor);
    assert(ui_debug_type_char(app.window(),L'\r')==0);
    const auto second_root=dir/"second-root";
    fs::create_directory(second_root);
    auto root_id_edit=state(app.page(),"rootCell").get<std::string>();
    auto* browse=window(app).Root()->FindById("browse-editor-input-"+root_id_edit);
    const auto icon=browse->Children().front()->rect;
    assert(std::abs(icon.left+icon.right-browse->rect.left-browse->rect.right)<2);
    assert(std::abs(icon.top+icon.bottom-browse->rect.top-browse->rect.bottom)<2);
    window(app).FocusWidget(browse,false);
    ui_debug_pump();
    auto picked=Json{{"id",root_id_edit},{"part","input"},{"value",utf8(second_root.wstring())}}.dump();
    assert(ui_page_call_json(app.page(),"rootPicked",picked.c_str())==0);
    ui_debug_pump();
    focus(app,root_editor);
    assert(area->Text()==root.wstring()+L"\n"+second_root.wstring());
    auto two=rect(app,root_editor);
    assert(two.bottom-two.top>single.bottom-single.top+5);
    assert(window(app).FocusedWidget()==area && read_roots(root_path).size()==1);
    assert(ui_debug_key_mod(app.window(),'S',1,0,0)==0);
    pump([&]{return state(app.page(),"rootCell")=="" && disk_root({});},"Save directory draft with Ctrl+S");
    finish_input(app);
    auto roots=read_roots(root_path);
    assert(roots.size()==3 && disk_root({}) && std::any_of(roots.begin(),roots.end(),[&](const auto& r){return r.input==second_root;}));

    navigate(app,"tabPasswords","passwords");
    click(app,"newPassword");
    auto id=state(app.page(),"passwordCell").get<std::string>();
    focus(app,"password-input-"+id);
    area=dynamic_cast<ui::TextAreaWidget*>(window(app).FocusedWidget());
    assert(area);
    auto before=read_json(passwords_path)["passwords"];
    std::wstring batch=L"  #first  ";
    for(int i=0;i<100;++i) batch+=L"\r\nline "+std::to_wstring(i);
    area->InsertText(batch);
    ui_debug_pump();
    const auto view=rect(app,"passwordListScroll"),editing_card=rect(app,"password-"+id);
    assert(area->NeedsScrollbar() && editing_card.bottom<=view.bottom+1 && editing_card.top>=view.top-1);
    assert(editing_card.bottom-editing_card.top>view.bottom-view.top-40);
    POINT point={LONG((area->rect.left+area->rect.right)/2),LONG((area->rect.top+area->rect.bottom)/2)};
    ClientToScreen(window(app).Handle(),&point);
    SendMessageW(window(app).Handle(),WM_MOUSEWHEEL,MAKEWPARAM(0,WHEEL_DELTA),MAKELPARAM(point.x,point.y));
    ui_debug_pump();
    assert(window(app).FocusedWidget()==area && read_json(passwords_path)["passwords"]==before);
    click(app,"passwordSearch");
    finish_input(app);
    saved=read_json(passwords_path)["passwords"];
    assert(saved.size()==before.size()+101 && saved[before.size()]["value"]=="  #first  " && saved.back()["value"]=="line 99");

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
    for(int i=0;i<total;++i) {
        auto path=utf8((dir/"history"/(i?"task-"+std::to_string(i)+".001":"task-0-task-0.001")).wstring());
        Json event={{"event","done"},{"path",path},{"ts",1792401342+i}};
        if(!i) event["group"]={{"multipart",true},{"members",{utf8((dir/"history"/"task-0-volume.002").wstring())}}};
        events+=event.dump()+"\n";
    }
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
        return visible.size()==1 && visible[0]["name"]=="task-0-task-0.001" &&
               active_find_widget(list)!=nullptr;
    },"Find and highlight a task outside the loaded window");
    const auto id=rows()[0]["id"].get<std::string>();
    auto check_hit=[&](const std::string& target,uint32_t start) {
        auto* active=active_find_widget(list);
        assert(active && active->id==target);
        const auto match=std::find_if(active->textHighlights.begin(),active->textHighlights.end(),
            [](const auto& range){return range.active;});
        assert(match!=active->textHighlights.end() && match->start==start);
    };
    click(app,"taskSearch");
    check_hit("taskName-"+id,0);
    SendMessageW(native.Handle(),WM_KEYDOWN,VK_DOWN,0);
    check_hit("taskName-"+id,7);
    SendMessageW(native.Handle(),WM_KEYDOWN,VK_DOWN,0);
    check_hit("taskPart-"+id+"-0",0);
    SendMessageW(native.Handle(),WM_KEYDOWN,VK_DOWN,0);
    check_hit("taskName-"+id,0);
    SendMessageW(native.Handle(),WM_KEYDOWN,VK_UP,0);
    check_hit("taskPart-"+id+"-0",0);

    // Follow one grouped card through actual file notifications and page
    // updates. Static projection cannot catch stale virtualized member chips.
    auto highlighted=active_find_widget(list)->shared_from_this();
    search("");
    pump([&]{return highlighted->textHighlights.empty();},"Clear task search highlights");
    highlighted.reset();
    const auto head=dir/"shared.jpg", tail=dir/"shared.chunk3.opaque";
    const std::array<std::pair<const char*,const char*>,4> phases={{{"failed_password","waiting"},
        {"suspended_missing_volume","waiting"},{"processing_started","info"},{"done","success"}}};
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
                visible[0]["statusTone"]==phases[phase].second && visible[0]["path"]==utf8(path.wstring()) &&
                visible[0]["parts"].size()==members.size();
        },"Refresh encrypted volume status");
        ui_window_relayout(app.window());
        auto* chip=dynamic_cast<ui::LabelWidget*>(window(app).Root()->FindById(
            "taskPart-encrypted-group-"+std::to_string(members.size()-1)));
        assert(chip && chip->Text()==(phase>=2?L"shared.chunk2.opaque":L"shared.chunk3.opaque"));
    }
}


void runtime_badge(Application& app,bool known,bool running,bool enabled,bool stable=true) {
    pump([&]{
        const auto value=state(app.page(),"runtime");
        return value.value("known",false)==known && (!known ||
            (value.value("running",false)==running && value.value("enabled",false)==enabled));
    },"Synchronize runtime badge");
    const auto texts=state(app.page(),"texts");
    const auto expected=(!known || !stable)?std::wstring():wide(texts[!running?"runtimeStopped":!enabled?"runtimeDisabled":"runtimeRunning"].get<std::string>());
    const auto expected_color=D2D1::ColorF(known && stable && running && enabled?0x6ccb5f:0x8a8a8a);
    pump([&]{
        ui_window_relayout(app.window());
        auto* root=window(app).Root().get();
        auto* label=dynamic_cast<ui::LabelWidget*>(root->FindById("runtimeState"));
        auto* dot=root->FindById("runtimeDot");
        if(!label || !dot || label->visible!=(known && stable) || (known && stable && label->Text()!=expected)) return false;
        const auto color=dot->bgColorFn?dot->bgColorFn():dot->bgColor;
        return std::abs(color.r-expected_color.r)<0.001f && std::abs(color.g-expected_color.g)<0.001f && std::abs(color.b-expected_color.b)<0.001f;
    },"Render runtime label and color "+state(app.page(),"runtime").dump()+" expected="+utf8(expected));
}

int runtime_status_contract(const fs::path& directory,const fs::path& launcher) {
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    int result=0;
    try {
        Options options; options.data_dir=directory; options.allow_cli=true;
        options.cli={launcher,directory,{},launcher.parent_path().parent_path()};
        Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));
        auto command=[&](std::initializer_list<std::wstring> args){
            auto reply=run_cli(options.cli,std::vector<std::wstring>(args),stop);
            if(reply.code) throw std::runtime_error(reply.output);
        };
        command({L"daemon",L"stop"});
        {
            Application app(options); app.open();
            pump([&]{return state(app.page(),"ready")==true;});
            runtime_badge(app,true,false,false);
            command({L"config",L"show"});
            runtime_badge(app,true,false,false);
            command({L"daemon",L"start",L"-nt"});
            runtime_badge(app,true,true,true);
            command({L"watch",L"disable"});
            runtime_badge(app,true,true,false);
        }
        {
            // Closing/reopening must fetch persisted disabled intent, not SCM state.
            Application app(options); app.open();
            pump([&]{return state(app.page(),"ready")==true;});
            runtime_badge(app,true,true,false);
            command({L"daemon",L"stop"});
            runtime_badge(app,true,false,false);
            command({L"daemon",L"start",L"-nt"});
            runtime_badge(app,true,true,false);
            command({L"watch",L"enable"});
            runtime_badge(app,true,true,true);

        }
        {
            Application app(options); app.open();
            pump([&]{return state(app.page(),"ready")==true;});
            runtime_badge(app,true,true,true);
        }
        command({L"daemon",L"stop"});
        {
            options.allow_cli=false;
            Application app(options); app.open();
            pump([&]{return state(app.page(),"ready")==true;});
            runtime_badge(app,false,false,false);
            Json snapshot={{"known",true},{"running",true},{"enabled",true},{"phase","running"},{"syncError",false}};
            ui_page_set_json(app.page(),"runtime",snapshot.dump().c_str());
            runtime_badge(app,true,true,true);
            // A stale connected snapshot must never remain a green status.
            for(auto phase:{"starting","enabling","disabling","stopping","error"}) {
                auto transition=snapshot; transition["phase"]=phase;
                ui_page_set_json(app.page(),"runtime",transition.dump().c_str());
                runtime_badge(app,true,true,true,false);
            }
            auto stale=snapshot; stale["known"]=false; stale["syncError"]=true;
            ui_page_set_json(app.page(),"runtime",stale.dump().c_str());
            runtime_badge(app,false,true,true);
            ui_page_set_json(app.page(),"runtime",snapshot.dump().c_str());
            runtime_badge(app,true,true,true);
        }
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; result=1; }
    CoUninitialize(); return result;
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
    if(args==Json::array({"--watch-status-follow"})) {
        std::cout<<R"({"running":false,"enabled":true,"phase":"disabled"})"<<std::endl;
        return 0;
    }
    atomic_write(dir/"cli-arguments.json",args.dump());
    if(args==Json::array({"config","validate","-srs","-j"})) {
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
    if(args==Json::array({"watch","relog"}))
        publish_events(dir/".sunpack_watch"/"events.json",
            Json{{"event","done"},{"path",utf8((dir/"recovered.001").wstring())}}.dump()+"\n");
    std::cout<<args.dump();
    return 0;
}
}

int wmain(int argc,wchar_t** argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
    const std::wstring mode=argc>1?argv[1]:L"--acceptance";
    if(mode==L"--script-errors") { script_error_contracts(); return 0; }
    if(mode==L"--startup-failure") return startup_failure_contract();
    if(mode==L"--theme" || mode==L"--theme-session") return theme_contracts(argc,argv);
    if(mode==L"--fake-cli") return fake_cli(argc,argv);
    if(mode==L"--runtime-status" && argc==4) return runtime_status_contract(argv[2],argv[3]);

    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    RegistryFixture registry;
    auto dir=fs::temp_directory_path()/(L"sunpack-gui-ui-"+std::to_wstring(GetCurrentProcessId()));
    int result=0;
    try {
        if(mode==L"--acceptance") {
            const auto source_root=fs::temp_directory_path()/L"SunPack source root";
            const auto native_cli=source_root/L"sunpack"/L"sunpack_launcher.exe";
            const auto native_options=parse_options({L"--data-dir",source_root.wstring(),
                L"--cli",native_cli.wstring(),L"--app-root",source_root.wstring()});
            assert(native_options.allow_cli && native_options.cli.prefix.empty());
            assert(native_options.cli.app_root==source_root && native_options.cli.executable==native_cli);
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
        if(mode==L"--acceptance") config["recursive_extract"]="2";
        atomic_write(dir/"sunpack_config.json",config.dump());
        atomic_write(dir/"builtin_passwords.json",R"({"passwords":[{"value":"  #中文  ","enabled":true}],"clipboard_history":["history"]})");
        atomic_write(dir/"sunpack_watch_roots.txt",utf8(dir.wstring())+" | | false | false | false | true\n");
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
