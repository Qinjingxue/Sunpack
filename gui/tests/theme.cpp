#include "application.hpp"
#include "page_value.hpp"
#include "registry_fixture.hpp"
#include "background.hpp"
#include <dwmapi.h>
#include <process.h>
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <ui/controls.h>
#include <ui/ui_debug.h>
#include <cassert>
#include <iostream>

using namespace spg;
namespace {
constexpr wchar_t ThemeKey[]=L"Software\\SunPack\\GUI";
constexpr wchar_t SystemThemeKey[]=L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
void write_value(const wchar_t* path,const wchar_t* name,DWORD type,const void* value,DWORD bytes) {
    HKEY key=nullptr;
    assert(RegCreateKeyExW(HKEY_CURRENT_USER,path,0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr)==ERROR_SUCCESS);
    assert(RegSetValueExW(key,name,0,type,static_cast<const BYTE*>(value),bytes)==ERROR_SUCCESS);
    RegCloseKey(key);
}
void system_light(bool light) {
    const DWORD value=light;
    write_value(SystemThemeKey,L"AppsUseLightTheme",REG_DWORD,&value,sizeof(value));
}
DWORD saved_theme() {
    DWORD value=99,bytes=sizeof(value);
    assert(RegGetValueW(HKEY_CURRENT_USER,ThemeKey,L"Theme",RRF_RT_REG_DWORD,nullptr,&value,&bytes)==ERROR_SUCCESS);
    assert(bytes==sizeof(value)); return value;
}
class DeniedThemeAccess {
    HKEY key_=nullptr;
    std::vector<BYTE> previous_;
    SECURITY_INFORMATION restore_=DACL_SECURITY_INFORMATION;
public:
    DeniedThemeAccess() {
        assert(RegOpenKeyExW(HKEY_CURRENT_USER,ThemeKey,0,READ_CONTROL|WRITE_DAC,&key_)==ERROR_SUCCESS);
        DWORD bytes=0;
        assert(RegGetKeySecurity(key_,DACL_SECURITY_INFORMATION,nullptr,&bytes)==ERROR_INSUFFICIENT_BUFFER);
        previous_.resize(bytes);
        assert(RegGetKeySecurity(key_,DACL_SECURITY_INFORMATION,previous_.data(),&bytes)==ERROR_SUCCESS);
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision=0;
        assert(GetSecurityDescriptorControl(previous_.data(),&control,&revision));
        restore_|=(control&SE_DACL_PROTECTED)?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION;
        ACL acl{}; assert(InitializeAcl(&acl,sizeof(acl),ACL_REVISION));
        SECURITY_DESCRIPTOR descriptor{};
        assert(InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION));
        assert(SetSecurityDescriptorDacl(&descriptor,TRUE,&acl,FALSE));
        assert(RegSetKeySecurity(key_,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,&descriptor)==ERROR_SUCCESS);
    }
    ~DeniedThemeAccess() {
        // Restore through the already-open WRITE_DAC handle even after denial.
        assert(RegSetKeySecurity(key_,restore_,previous_.data())==ERROR_SUCCESS);
        RegCloseKey(key_);
    }
};
void wait_ready(Application& app) {
    auto deadline=GetTickCount64()+10000;
    for(;;) {
        MSG message;
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) {
            if(message.message==WM_QUIT) continue;
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        auto hwnd=static_cast<HWND>(ui_window_hwnd(app.window()));
        if(page_value(app.page(),"ready")==true && IsWindowVisible(hwnd)) {
            BYTE alpha=255; DWORD flags=0;
            // The first-frame gate makes the HWND compositable at alpha 0.
            // Wait for actual reveal, not just the Win32 visible style bit.
            if(!GetLayeredWindowAttributes(hwnd,nullptr,&alpha,&flags) || !(flags&LWA_ALPHA) || alpha>0) return;
        }
        auto now=GetTickCount64();
        if(now>=deadline) throw std::runtime_error("Theme startup timed out");
        MsgWaitForMultipleObjectsEx(0,nullptr,DWORD(deadline-now),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    }
}
void check_theme(Application& app,int choice,bool light) {
    assert(page_value(app.page(),"themeChoice")==choice);
    assert(page_value(app.page(),"theme")==(choice==1?"light":choice==2?"dark":"system"));
    assert(page_value(app.page(),"appearance")== (light?"light":"dark"));
    assert(ui_theme_get_mode()==(light?UI_THEME_LIGHT:UI_THEME_DARK));
    auto* window=ui::GetContext().GetWindow(app.window());
    auto* root=window->Root().get();
    const auto background=light?theme::kWindowBg():D2D1::ColorF(0x202020);
    gui_test::same_color(root->bgColorFn?root->bgColorFn():root->bgColor,background);
    if(IsWindowVisible(window->Handle())) gui_test::clear_color(*window,background);
    auto* selector=dynamic_cast<ui::ComboBoxWidget*>(root->FindById("themeSelector"));
    assert(selector && selector->SelectedIndex()==choice);
    BOOL dark=FALSE;
    if(SUCCEEDED(DwmGetWindowAttribute(static_cast<HWND>(ui_window_hwnd(app.window())),
        DWMWA_USE_IMMERSIVE_DARK_MODE,&dark,sizeof(dark)))) assert(bool(dark)==!light);
}
void select_theme(Application& app,int choice) {
    auto selector=ui_widget_find_by_id(ui_page_root(app.page()),"themeSelector"); assert(selector);
    assert(ui_debug_combo_select(app.window(),selector,choice)==0);
    ui_widget_destroy(selector);
}
void notify_system_theme(Application& app,bool light) {
    system_light(light);
    SendMessageW(static_cast<HWND>(ui_window_hwnd(app.window())),WM_SETTINGCHANGE,0,reinterpret_cast<LPARAM>(L"ImmersiveColorSet"));
}
int session(const std::wstring& registry,const fs::path& dir,int expected,int next) {
    RegistryFixture fixture(registry);
    // Every persisted explicit choice starts opposite to Windows. This catches
    // restoring it too late as well as reveal resetting only the native frame.
    bool light=expected==2;
    system_light(light);
    Options options; options.data_dir=dir; options.allow_cli=false;
    Application app(options); app.open();
    assert(!IsWindowVisible(static_cast<HWND>(ui_window_hwnd(app.window()))));
    check_theme(app,expected,expected==0?light:expected==1);
    wait_ready(app);
    assert(IsWindowVisible(static_cast<HWND>(ui_window_hwnd(app.window()))));
    check_theme(app,expected,expected==0?light:expected==1);
    // Exercise the real selector callback, then exit without pumping a save.
    select_theme(app,next);
    check_theme(app,next,next==0?light:next==1);
    assert(saved_theme()==DWORD(next));
    notify_system_theme(app,!light);
    check_theme(app,next,next==0?!light:next==1);
    assert(saved_theme()==DWORD(next)); // system appearance is never persisted
    if(expected==0 && next==0) {
        {
            DeniedThemeAccess denied;
            assert(load_theme_choice()==ThemeChoice::System);
            select_theme(app,2);
            check_theme(app,2,false);
            assert(page_value(app.page(),"saveErrors").contains("@theme"));
        }
        assert(saved_theme()==0); // rejected persistence does not alter storage
        select_theme(app,1);
        check_theme(app,1,true);
        assert(saved_theme()==1 && !page_value(app.page(),"saveErrors").contains("@theme"));
        select_theme(app,0);
    }
    return 0;
}
void contracts() {
    RegistryFixture fixture;
    auto dir=fs::temp_directory_path()/(L"sunpack gui theme "+std::to_wstring(GetCurrentProcessId()));
    fs::create_directory(dir);
    try {
        atomic_write(dir/"sunpack_config.json",R"({"cli":{"language":"en"}})");
        assert(load_theme_choice()==ThemeChoice::System);
        HKEY absent=nullptr;
        assert(RegOpenKeyExW(HKEY_CURRENT_USER,ThemeKey,0,KEY_READ,&absent)==ERROR_FILE_NOT_FOUND);
        // Malformed and future values fall back without rewriting user data.
        const wchar_t text[]=L"dark";
        write_value(ThemeKey,L"Theme",REG_SZ,text,sizeof(text));
        assert(load_theme_choice()==ThemeChoice::System);
        DWORD invalid=99;
        write_value(ThemeKey,L"Theme",REG_DWORD,&invalid,sizeof(invalid));
        assert(load_theme_choice()==ThemeChoice::System && saved_theme()==99);
        assert(RegDeleteTreeW(HKEY_CURRENT_USER,ThemeKey)==ERROR_SUCCESS);
        const auto executable=executable_path().wstring();
        // MS CRT spawn concatenates argv without quoting embedded spaces.
        const auto executable_arg=quote_arg(executable), registry_arg=quote_arg(fixture.path), directory_arg=quote_arg(dir.wstring());
        for(auto choices:{std::pair{0,1},std::pair{1,2},std::pair{2,0},std::pair{0,0}}) {
            auto expected=std::to_wstring(choices.first), next=std::to_wstring(choices.second);
            const wchar_t* args[]={executable_arg.c_str(),L"--theme-session",registry_arg.c_str(),directory_arg.c_str(),expected.c_str(),next.c_str(),nullptr};
            // A fresh process proves persistence is not retained UI/global state.
            // Do not use the CLI launch helper: its SW_HIDE startup contract is
            // intentional for CLI tools but suppresses a GUI's first ShowWindow.
            assert(_wspawnv(_P_WAIT,executable.c_str(),args)==0);
            assert(saved_theme()==DWORD(choices.second));
        }
        fs::remove_all(dir);
    } catch(...) { std::error_code error; fs::remove_all(dir,error); throw; }
}
}
int theme_contracts(int argc,wchar_t** argv) {
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    try {
        if(argc==6) session(argv[2],argv[3],std::stoi(argv[4]),std::stoi(argv[5]));
        else contracts();
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; CoUninitialize(); return 1; }
    CoUninitialize(); return 0;
}
