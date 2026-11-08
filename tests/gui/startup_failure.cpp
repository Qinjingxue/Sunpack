#include "application.hpp"
#include "presentation.hpp"
#include "registry_fixture.hpp"
#include <ui/ui_context.h>
#include <ui/ui_window.h>
#include <cassert>
#include <iostream>

using namespace spg;
namespace {
constexpr wchar_t InjectorClass[]=L"SunPack.GUI.StartupFailureTest";
constexpr UINT InjectFailure=WM_APP+700;
LRESULT CALLBACK inject(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam) {
    if(message==WM_NCCREATE)
        SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams));
    if(message==InjectFailure) {
        auto* app=reinterpret_cast<Application*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
        auto* window=ui::GetContext().GetWindow(app->window()); assert(window && window->onRenderFailure);
        // Core rendering tests cover failure-message handling/token validation.
        // This covers the host boundary without requiring a GPU to malfunction:
        // a UI-thread callback followed by the core's normal close sequence.
        auto notify=window->onRenderFailure;
        auto target=static_cast<HWND>(ui_window_hwnd(app->window()));
        notify();
        SendMessageW(target,WM_CLOSE,0,0);
        return 0;
    }
    return DefWindowProcW(hwnd,message,wparam,lparam);
}
}
int startup_failure_contract() {
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    RegistryFixture registry;
    auto dir=fs::temp_directory_path()/(L"sunpack-startup-failure-"+std::to_wstring(GetCurrentProcessId()));
    fs::create_directory(dir);
    auto module=GetModuleHandleW(nullptr);
    WNDCLASSW cls{}; cls.hInstance=module; cls.lpszClassName=InjectorClass; cls.lpfnWndProc=inject;
    assert(RegisterClassW(&cls));
    HWND injector=nullptr;
    int result=0;
    try {
        atomic_write(dir/"sunpack_config.json",R"({"cli":{"language":"en"}})");
        Options options; options.data_dir=dir; options.allow_cli=false;
        Application app(options);
        injector=CreateWindowExW(0,InjectorClass,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,module,&app);
        assert(injector && PostMessageW(injector,InjectFailure,0,0));
        bool reported=false;
        try { app.run(); }
        catch(const std::exception& error) {
            for(const char* language:{"en","zh"}) {
                auto message=translated_error(error.what(),language);
                assert(message.find(tr("stageRenderer",language))!=std::string::npos);
                assert(message.find(tr("firstFrameFailed",language))!=std::string::npos);
            }
            reported=true;
        }
        assert(reported); // onClose's ordinary exit code 0 must not hide failure.
        DestroyWindow(injector); injector=nullptr;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; result=1; }
    if(injector) DestroyWindow(injector);
    UnregisterClassW(InjectorClass,module);
    std::error_code error; fs::remove_all(dir,error);
    CoUninitialize(); return result;
}
