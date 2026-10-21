#include "application.hpp"
#include "presentation.hpp"
#include <shellapi.h>

int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    int result=1;
    spg::fs::path data_dir;
    try {
        int count=0; auto** argv=CommandLineToArgvW(GetCommandLineW(),&count);
        if(!argv) spg::win_error("opCommandLine");
        std::vector<std::wstring> args(argv+1,argv+count); LocalFree(argv);
        auto options=spg::parse_options(args); data_dir=options.data_dir;
        auto name=spg::mutex_name(options.data_dir,L"SunPack.GUI");
        spg::Handle instance(CreateMutexW(nullptr,FALSE,name.c_str()));
        if(!instance.value) spg::win_error("opGuiInstance");
        if(GetLastError()==ERROR_ALREADY_EXISTS) {
            EnumWindows([](HWND hwnd,LPARAM param)->BOOL {
                if(GetPropW(hwnd,reinterpret_cast<const wchar_t*>(param))) {
                    ShowWindow(hwnd,SW_RESTORE); SetForegroundWindow(hwnd); return FALSE;
                }
                return TRUE;
            },reinterpret_cast<LPARAM>(name.c_str()));
            result=0;
        } else {
            spg::Application app(std::move(options)); result=app.run();
        }
    } catch(const std::exception& e) {
        auto language=data_dir.empty()?"en":spg::startup_language(data_dir);
        auto message=spg::wide(spg::translated_error(e.what(),language));
        MessageBoxW(nullptr,message.c_str(),spg::wide(spg::tr("title",language)).c_str(),MB_ICONERROR|MB_OK);
    }
    if(SUCCEEDED(com)) CoUninitialize();
    return result;
}
