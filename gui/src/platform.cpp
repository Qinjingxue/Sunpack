#include "platform.hpp"
#include "presentation.hpp"
#include <shobjidl.h>
#include <shlobj.h>
#include <xxhash.h>
#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <memory>

extern "C" NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR);
namespace spg {
std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n) win_error("opEncodeUtf8");
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), int(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring wide(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0);
    if (!n) win_error("opDecodeUtf8");
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), out.data(), n);
    return out;
}
void win_error(const char* op) {
    DWORD code = GetLastError();
    throw WinError(code,error_text("windowsFailure",{{"operation",{{"source",op}}},{"code",code}}));
}
namespace {
constexpr wchar_t GuiPreferencesKey[] = L"Software\\SunPack\\GUI";
}
ThemeChoice load_theme_choice() noexcept {
    DWORD value=0, bytes=sizeof(value);
    if(RegGetValueW(HKEY_CURRENT_USER,GuiPreferencesKey,L"Theme",RRF_RT_REG_DWORD,
        nullptr,&value,&bytes)!=ERROR_SUCCESS || bytes!=sizeof(value) || value>DWORD(ThemeChoice::Dark))
        return ThemeChoice::System;
    return static_cast<ThemeChoice>(value);
}
void save_theme_choice(ThemeChoice choice) {
    HKEY key=nullptr;
    auto result=RegCreateKeyExW(HKEY_CURRENT_USER,GuiPreferencesKey,0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr);
    if(result==ERROR_SUCCESS) {
        const DWORD value=DWORD(choice);
        result=RegSetValueExW(key,L"Theme",0,REG_DWORD,reinterpret_cast<const BYTE*>(&value),sizeof(value));
        RegCloseKey(key);
    }
    if(result!=ERROR_SUCCESS) { SetLastError(result); win_error("opSaveTheme"); }
}
fs::path resolve_path(const fs::path& path, const fs::path& base) {
    fs::path p = path;
    auto s = p.wstring();
    if (s == L"~" || s.rfind(L"~\\", 0) == 0 || s.rfind(L"~/", 0) == 0) {
        wchar_t* home = nullptr; size_t length = 0;
        _wdupenv_s(&home, &length, L"USERPROFILE");
        if (home) { p = fs::path(home) / s.substr(std::min<size_t>(2, s.size())); free(home); }
    }
    if (p.is_relative() && !base.empty()) p = base / p;
    auto normalized=fs::absolute(p).lexically_normal();
    if(!normalized.has_filename() && normalized!=normalized.root_path()) {
        bool unc=normalized.root_name().wstring().rfind(L"\\\\",0)==0;
        size_t parts=0; for(auto& part:normalized.relative_path()) if(!part.empty()) ++parts;
        if(!unc || parts>1) normalized=normalized.parent_path();
    }
    return normalized;
}
std::wstring path_key(const fs::path& p) {
    auto s = resolve_path(p).wstring();
    for (size_t i = 0; i < s.size(); ++i) {
        auto& c = s[i];
        if (c == L'/') c = L'\\';
        // Match Rust: preserve supplementary code points, NT-map each BMP unit.
        else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.size() && s[i+1] >= 0xDC00 && s[i+1] <= 0xDFFF) ++i;
        else c = RtlDowncaseUnicodeChar(c);
    }
    return s;
}
bool is_under(const std::wstring& p, const std::wstring& root) {
    const auto end = root.find_last_not_of(L"\\/");
    const auto length = end == std::wstring::npos ? 0 : end + 1;
    return p == root || (p.size() > length && p.compare(0, length, root, 0, length) == 0 && p[length] == L'\\');
}
std::wstring mutex_name(const fs::path& p, const std::wstring& prefix) {
    auto bytes = utf8(path_key(p));
    std::wostringstream s;
    s << L"Local\\" << prefix << L"-" << std::hex << std::setfill(L'0') << std::setw(16) << XXH64(bytes.data(), bytes.size(), 0);
    return s.str();
}
MutexLock::MutexLock(const std::wstring& name) : handle(CreateMutexW(nullptr, FALSE, name.c_str())) {
    if (!handle.value) win_error("opCreateMutex");
    auto status = WaitForSingleObject(handle, INFINITE);
    if (status != WAIT_OBJECT_0 && status != WAIT_ABANDONED) win_error("opWaitMutex");
}
MutexLock::~MutexLock() { ReleaseMutex(handle); }
std::string read_file(const fs::path& p, size_t limit) {
    Handle f(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (f.value == INVALID_HANDLE_VALUE) win_error("opReadFile");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size)) win_error("opFileSize");
    if (size.QuadPart > static_cast<LONGLONG>(limit)) throw std::runtime_error("fileTooLarge");
    std::string out; out.reserve(size_t(size.QuadPart));
    char buffer[65536]; DWORD count;
    for (;;) {
        if (!ReadFile(f, buffer, sizeof(buffer), &count, nullptr)) win_error("opReadFile");
        if (!count) break;
        if (out.size() + count > limit) throw std::runtime_error("fileTooLarge");
        out.append(buffer, count);
    }
    return out;
}
void atomic_write(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    GUID id{}; CoCreateGuid(&id);
    wchar_t token[40]; StringFromGUID2(id, token, 40);
    fs::path temp = p.parent_path() / (L"." + p.filename().wstring() + token + L".tmp");
    try {
        {
            Handle f(CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (f.value == INVALID_HANDLE_VALUE) win_error("opCreateTemp");
            size_t at = 0;
            while (at < content.size()) {
                DWORD count = 0;
                if (!WriteFile(f, content.data() + at, DWORD(std::min<size_t>(65536, content.size()-at)), &count, nullptr) || !count)
                    win_error("opWriteFile");
                at += count;
            }
            if (!FlushFileBuffers(f)) win_error("opFlushFile");
        }
        // ReplaceFile preserves target ACL, but it requires DELETE_CHILD on the
        // parent directory. Installed data directories intentionally grant the
        // user Modify, which is enough for MoveFileEx replacement but can still
        // make ReplaceFileW fail with ERROR_UNABLE_TO_REMOVE_REPLACED (1175).
        // Keep ReplaceFile as the first choice and fall back to the rename path
        // so the same atomic writer works with the packaged ACLs.
        if (!ReplaceFileW(p.c_str(), temp.c_str(), nullptr, 0, nullptr, nullptr)) {
            DWORD replace_error = GetLastError();
            DWORD flags = MOVEFILE_WRITE_THROUGH;
            if (replace_error != ERROR_FILE_NOT_FOUND) flags |= MOVEFILE_REPLACE_EXISTING;
            if (!MoveFileExW(temp.c_str(), p.c_str(), flags)) {
                SetLastError(replace_error);
                win_error("opReplaceFile");
            }
        }
    } catch (...) { std::error_code ec; fs::remove(temp, ec); throw; }
}
namespace {
Handle directory_watch_event() {
    const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) win_error("opWatchDirectory");
    return Handle(event);
}
bool same_filename(std::wstring_view name, std::wstring_view expected) {
    return name.size()==expected.size() &&
        CompareStringOrdinal(name.data(),int(name.size()),expected.data(),int(expected.size()),TRUE)==CSTR_EQUAL;
}
}
DirectoryWatcher::DirectoryWatcher(const fs::path& directory, std::function<unsigned(const fs::path&)> classify,
    std::function<void(unsigned)> notify)
    : stop_(directory_watch_event()) {
    auto target = resolve_path(directory), ancestor = target;
    while (!fs::is_directory(ancestor) && ancestor != ancestor.parent_path()) ancestor = ancestor.parent_path();
    bool subtree = ancestor != target;
    direct_=!subtree;
    Handle dir(CreateFileW(ancestor.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
    if (dir == INVALID_HANDLE_VALUE) win_error("opWatchDirectory");
    const auto ready = directory_watch_event();
    thread_ = std::thread([this, dir = std::move(dir), done = directory_watch_event(), ready = ready.value,
        ancestor = std::move(ancestor), subtree, classify = std::move(classify), notify = std::move(notify)] {
        alignas(DWORD) char buffer[16384];
        bool armed=false;
        const auto failed=[&] {
            alive_=false;
            if(!armed) SetEvent(ready);
            else if(auto flags=classify({})) notify(flags);
        };
        for (;;) {
            OVERLAPPED ov{}; ov.hEvent = done;
            ResetEvent(done);
            if (!ReadDirectoryChangesW(dir, buffer, sizeof(buffer), subtree,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                nullptr, &ov, nullptr)) { failed(); break; }
            if (!armed) { armed=true; SetEvent(ready); }
            HANDLE waits[] = {stop_, done};
            DWORD signal = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (signal != WAIT_OBJECT_0 + 1) {
                CancelIoEx(dir, &ov); WaitForSingleObject(done, INFINITE); break;
            }
            DWORD count = 0;
            if (!GetOverlappedResult(dir, &ov, &count, FALSE)) { failed(); break; }
            unsigned flags=count?0:classify({});
            for (DWORD offset = 0; count && offset < count;) {
                auto* item = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer + offset);
                const std::wstring_view name(item->FileName,item->FileNameLength / sizeof(wchar_t));
                // Missing target directories are observed through their existing ancestor.
                if (subtree || same_filename(name,L"sunpack_config.json") || same_filename(name,L"builtin_passwords.json") ||
                    same_filename(name,L"sunpack_watch_roots.txt") || same_filename(name,L"events.json") ||
                    (name.size()>=14 && same_filename(name.substr(0,8),L"runtime-") && name.substr(name.size()-6)==L".state"))
                    flags|=classify(ancestor / name);
                if (!item->NextEntryOffset) break;
                offset += item->NextEntryOffset;
            }
            // A single write can emit several records for the same file.
            if(flags) notify(flags);
        }
    });
    WaitForSingleObject(ready,INFINITE);
    if(!alive_) { thread_.join(); throw std::runtime_error("watchNotificationsUnsupported"); }
}
DirectoryWatcher::~DirectoryWatcher() { SetEvent(stop_); if (thread_.joinable()) thread_.join(); }
bool startup_enabled() {
    HKEY key{};
    auto rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &key);
    if (rc == ERROR_FILE_NOT_FOUND) return false;
    if (rc != ERROR_SUCCESS) { SetLastError(rc); win_error("opReadStartupRegistry"); }
    DWORD type{}, bytes{};
    rc = RegQueryValueExW(key, L"SunPackWatchService", nullptr, &type, nullptr, &bytes);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) { SetLastError(rc); win_error("opReadStartupValue"); }
    return rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ);
}
fs::path choose_directory(HWND owner, const fs::path& initial) {
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        throw std::runtime_error("folderPickerFailed");
    dialog->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    std::error_code ec;
    if(!initial.empty() && fs::is_directory(initial,ec)) {
        IShellItem* folder=nullptr;
        if(SUCCEEDED(SHCreateItemFromParsingName(initial.c_str(),nullptr,IID_PPV_ARGS(&folder)))) {
            dialog->SetFolder(folder); folder->Release();
        }
    }
    fs::path result;
    if (SUCCEEDED(dialog->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR text = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &text))) { result = text; CoTaskMemFree(text); }
            item->Release();
        }
    }
    dialog->Release(); return result;
}
std::wstring quote_arg(const std::wstring& arg) {
    std::wstring out = L"\""; size_t slash = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slash; continue; }
        out.append(c == L'"' ? slash * 2 + 1 : slash, L'\\'); slash = 0; out += c;
    }
    out.append(slash * 2, L'\\'); out += L'"'; return out;
}
fs::path executable_path() { std::wstring s(32768, 0); auto n = GetModuleFileNameW(nullptr, s.data(), DWORD(s.size())); s.resize(n); return s; }
namespace {
HANDLE launch_cli(const CliCommand& cli,std::wstring command,HANDLE writer,HANDLE reader) {
    STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.StartupInfo.hStdOutput = writer; si.StartupInfo.hStdError = writer; si.StartupInfo.hStdInput = reader;
    SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> attributes(bytes);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytes)) win_error("opCliAttributes");
    HANDLE inherited[] = {writer, reader};
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(si.lpAttributeList); win_error("opCliHandles");
    }
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(cli.executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, cli.cwd.c_str(), &si.StartupInfo, &pi);
    auto error = GetLastError(); DeleteProcThreadAttributeList(si.lpAttributeList);
    if (!ok) { SetLastError(error); win_error("opLaunchCli"); }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}
}
CliResult run_cli(const CliCommand& cli, const std::vector<std::wstring>& args, HANDLE stop,const std::string* input) {
    if (!fs::is_regular_file(cli.executable)) throw std::runtime_error("cliMissing");
    std::wstring command = quote_arg(cli.executable.wstring());
    for (auto& arg : cli.prefix) command += L" " + quote_arg(arg);
    for (auto& arg : args) command += L" " + quote_arg(arg);
    // A delete-on-close temporary handle captures CLI output without a reader thread,
    // pipe backpressure, or a shutdown join that could outlive the manager window.
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    GUID id{}; CoCreateGuid(&id); wchar_t token[40]; StringFromGUID2(id,token,40);
    auto output_path=fs::temp_directory_path()/(std::wstring(L"sunpack-cli-")+token+L".tmp");
    Handle writer(CreateFileW(output_path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_DELETE,
        &sa,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,nullptr));
    if(writer.value==INVALID_HANDLE_VALUE) win_error("opCaptureCli");
    auto input_path=input?output_path.wstring()+L".input":L"NUL";
    Handle reader(CreateFileW(input_path.c_str(),input?GENERIC_READ|GENERIC_WRITE:GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,&sa,input?CREATE_NEW:OPEN_EXISTING,
        input?FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE:0,nullptr));
    if(reader.value==INVALID_HANDLE_VALUE) win_error("opCaptureCli");
    if(input) {
        DWORD written=0;
        if(!WriteFile(reader,input->data(),DWORD(input->size()),&written,nullptr) || written!=input->size()) win_error("opCaptureCli");
        LARGE_INTEGER start{}; if(!SetFilePointerEx(reader,start,nullptr,FILE_BEGIN)) win_error("opCaptureCli");
    }
    Handle process(launch_cli(cli,std::move(command),writer,reader));
    HANDLE waits[] = {stop, process};
    auto signal = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if(signal==WAIT_FAILED) win_error("opReadCliOutput");
    DWORD code = 0; if(!GetExitCodeProcess(process, &code)) win_error("opReadCliOutput");
    std::string output;
    if(signal==WAIT_OBJECT_0+1 && code!=0) {
        LARGE_INTEGER size{};
        if(!GetFileSizeEx(writer,&size)) win_error("opReadCliOutput");
        LARGE_INTEGER start{};
        if(!SetFilePointerEx(writer,start,nullptr,FILE_BEGIN)) win_error("opReadCliOutput");
        output.resize(size_t(std::min<LONGLONG>(size.QuadPart,65536)));
        DWORD count=0;
        if(!ReadFile(writer,output.data(),DWORD(output.size()),&count,nullptr)) win_error("opReadCliOutput");
        output.resize(count);
    }

    return {code, std::move(output)};
}
DWORD follow_watch_status(const CliCommand& cli,HANDLE stop,const std::function<void(const std::string&)>& received) {
    if(!fs::is_regular_file(cli.executable)) throw std::runtime_error("cliMissing");
    GUID id{}; CoCreateGuid(&id); wchar_t token[40]; StringFromGUID2(id,token,40);
    const auto name=std::wstring(L"\\\\.\\pipe\\SunPack-GUI-status-")+token;
    Handle reader(CreateNamedPipeW(name.c_str(),PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,0,4096,0,nullptr));
    if(reader.value==INVALID_HANDLE_VALUE) win_error("opCaptureCli");
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    Handle writer(CreateFileW(name.c_str(),GENERIC_WRITE,0,&sa,OPEN_EXISTING,0,nullptr));
    if(writer.value==INVALID_HANDLE_VALUE) win_error("opCaptureCli");
    Handle input(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr));
    if(input.value==INVALID_HANDLE_VALUE) win_error("opCaptureCli");
    std::wstring command=quote_arg(cli.executable.wstring());
    for(const auto& arg:cli.prefix) command+=L" "+quote_arg(arg);
    command+=L" --watch-status-follow";
    Handle ready(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!ready.value) win_error("opCaptureCli");
    Handle process(launch_cli(cli,std::move(command),writer,input));
    CloseHandle(writer.value); writer.value=INVALID_HANDLE_VALUE;
    std::string pending;
    try {
        for(;;) {
            char buffer[4096]; DWORD size=0;
            OVERLAPPED operation{}; operation.hEvent=ready;
            ResetEvent(ready);
            if(!ReadFile(reader,buffer,sizeof(buffer),&size,&operation)) {
                auto error=GetLastError();
                if(error==ERROR_BROKEN_PIPE) break;
                if(error!=ERROR_IO_PENDING) win_error("opReadCliOutput");
                HANDLE waits[]={stop,ready};
                if(WaitForMultipleObjects(2,waits,FALSE,INFINITE)!=WAIT_OBJECT_0+1) {
                    CancelIoEx(reader,&operation);
                    GetOverlappedResult(reader,&operation,&size,TRUE);
                    break;
                }
                if(!GetOverlappedResult(reader,&operation,&size,FALSE)) {
                    if(GetLastError()==ERROR_BROKEN_PIPE) break;
                    win_error("opReadCliOutput");
                }
            }
            if(!size) break;
            pending.append(buffer,size);
            size_t consumed=0;
            for(size_t end;(end=pending.find('\n',consumed))!=std::string::npos;consumed=end+1)
                received(pending.substr(consumed,end-consumed));
            pending.erase(0,consumed);
        }
    } catch(...) {
        TerminateProcess(process,1); WaitForSingleObject(process,INFINITE); throw;
    }
    // This is only our disposable launcher, never the runtime or an extraction worker.
    HANDLE waits[]={stop,process};
    const auto signal=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
    if(signal==WAIT_OBJECT_0) {
        TerminateProcess(process,ERROR_CANCELLED);
        WaitForSingleObject(process,INFINITE);
    } else if(signal==WAIT_FAILED) win_error("opReadCliOutput");
    DWORD code=0; GetExitCodeProcess(process,&code);
    return code;
}

}
