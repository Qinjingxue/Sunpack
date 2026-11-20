#include "application.hpp"
#include "presentation.hpp"
#include <algorithm>
#include <shellapi.h>

int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    int result=1;
    bool context_menu_command=false;
    spg::fs::path data_dir;
    try {
        int count=0; auto** argv=CommandLineToArgvW(GetCommandLineW(),&count);
        if(!argv) spg::win_error("opCommandLine");
        std::vector<std::wstring> args(argv+1,argv+count); LocalFree(argv);
        context_menu_command=std::find(args.begin(),args.end(),L"--context-menu")!=args.end();
        auto options=spg::parse_options(args); data_dir=options.data_dir;
        // Shell actions are one-shot clients, independent of the manager window.
        // Dispatch before the GUI singleton so an open manager cannot swallow them.
        if(options.context_menu) {
            if(!options.allow_cli) throw std::runtime_error("cliUnbound");
            auto language=*options.context_menu==spg::ContextMenuAction::Enable
                ?spg::startup_language(data_dir):std::string{};
            spg::change_context_menu(options.cli,*options.context_menu,language);
            if(SUCCEEDED(com)) CoUninitialize();
            return 0;
        }
        if(!options.shell_watch.empty()) {
            if(!options.allow_cli) throw std::runtime_error("cliMissing");
            options.cli.cwd=options.cli.app_root;
            spg::Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));
            if(!stop.value) spg::win_error("opLaunchCli");
            auto command=spg::run_cli(options.cli,options.shell_watch,stop);
            if(command.code==0 && options.shell_watch[1]==L"add")
                command=spg::run_cli(options.cli,{L"daemon",L"start"},stop);
            if(command.code && !command.output.empty()) throw std::runtime_error(command.output);
            if(SUCCEEDED(com)) CoUninitialize();
            return int(command.code);
        }
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
        if(context_menu_command) {
            if(const auto* error=dynamic_cast<const spg::WinError*>(&e)) result=int(error->code);
        } else {
            auto language=data_dir.empty()?"en":spg::startup_language(data_dir);
            auto message=spg::wide(spg::translated_error(e.what(),language));
            MessageBoxW(nullptr,message.c_str(),spg::wide(spg::tr("title",language)).c_str(),MB_ICONERROR|MB_OK);
        }
    }
    if(SUCCEEDED(com)) CoUninitialize();
    return result;
}
