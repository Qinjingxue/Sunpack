#include "platform.hpp"
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
    if (!n) win_error("UTF-8 encode");
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), int(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0);
    if (!n) win_error("UTF-8 decode");
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), out.data(), n);
    return out;
}
void win_error(const char* op) {
    DWORD code = GetLastError();
    wchar_t* message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::string detail = message ? utf8(message) : std::to_string(code);
    LocalFree(message);
    throw WinError(code,std::string(op) + ": " + detail);
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
    auto r = root;
    while (!r.empty() && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
    return p == root || (p.size() > r.size() && p.compare(0, r.size(), r) == 0 && p[r.size()] == L'\\');
}
std::wstring mutex_name(const fs::path& p, const std::wstring& prefix) {
    auto bytes = utf8(path_key(p));
    std::wostringstream s;
    s << L"Local\\" << prefix << L"-" << std::hex << std::setfill(L'0') << std::setw(16) << XXH64(bytes.data(), bytes.size(), 0);
    return s.str();
}
FileMutex::FileMutex(const fs::path& p, const std::wstring& prefix)
    : handle(CreateMutexW(nullptr, FALSE, mutex_name(p, prefix).c_str())) {
    if (!handle.value) win_error("CreateMutex");
    auto status = WaitForSingleObject(handle, INFINITE);
    if (status != WAIT_OBJECT_0 && status != WAIT_ABANDONED) win_error("WaitForMutex");
}
FileMutex::~FileMutex() { ReleaseMutex(handle); }
std::string read_file(const fs::path& p, size_t limit) {
    Handle f(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (f.value == INVALID_HANDLE_VALUE) win_error("Read file");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size)) win_error("File size");
    if (size.QuadPart > static_cast<LONGLONG>(limit)) throw std::runtime_error("文件超过可编辑大小限制");
    std::string out; out.reserve(size_t(size.QuadPart));
    char buffer[65536]; DWORD count;
    for (;;) {
        if (!ReadFile(f, buffer, sizeof(buffer), &count, nullptr)) win_error("Read file");
        if (!count) break;
        if (out.size() + count > limit) throw std::runtime_error("文件超过可编辑大小限制");
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
            if (f.value == INVALID_HANDLE_VALUE) win_error("Create temporary file");
            size_t at = 0;
            while (at < content.size()) {
                DWORD count = 0;
                if (!WriteFile(f, content.data() + at, DWORD(std::min<size_t>(65536, content.size()-at)), &count, nullptr) || !count)
                    win_error("Write file");
                at += count;
            }
            if (!FlushFileBuffers(f)) win_error("Flush file");
        }
        // ReplaceFile preserves target ACL; MoveFile covers a newly created file.
        if (!ReplaceFileW(p.c_str(), temp.c_str(), nullptr, 0, nullptr, nullptr)) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND ||
                !MoveFileExW(temp.c_str(), p.c_str(), MOVEFILE_WRITE_THROUGH)) win_error("Replace file");
        }
    } catch (...) { std::error_code ec; fs::remove(temp, ec); throw; }
}
DirectoryWatcher::DirectoryWatcher(const fs::path& directory, std::function<void(const fs::path&)> changed) {
    auto target = resolve_path(directory), ancestor = target;
    while (!fs::is_directory(ancestor) && ancestor != ancestor.parent_path()) ancestor = ancestor.parent_path();
    bool subtree = ancestor != target;
    direct_=!subtree;
    auto h = CreateFileW(ancestor.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (h == INVALID_HANDLE_VALUE) win_error("Watch directory");
    thread_ = std::thread([this, h, target, ancestor, subtree, changed = std::move(changed)] {
        Handle dir(h), done(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        alignas(DWORD) char buffer[16384];
        bool armed=false;
        for (;;) {
            OVERLAPPED ov{}; ov.hEvent = done;
            ResetEvent(done);
            if (!ReadDirectoryChangesW(dir, buffer, sizeof(buffer), subtree,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                nullptr, &ov, nullptr)) { alive_=false; SetEvent(ready_); if(armed) changed({}); break; }
            armed=true;
            SetEvent(ready_);
            HANDLE waits[] = {stop_, done};
            DWORD signal = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (signal != WAIT_OBJECT_0 + 1) {
                CancelIoEx(dir, &ov); WaitForSingleObject(done, INFINITE); break;
            }
            DWORD count = 0;
            if (!GetOverlappedResult(dir, &ov, &count, FALSE)) { alive_=false; changed({}); break; }
            if (!count) changed({});
            for (DWORD offset = 0; count && offset < count;) {
                auto* item = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer + offset);
                auto path = ancestor / std::wstring(item->FileName, item->FileNameLength / sizeof(wchar_t));
                auto name = path.filename().wstring();
                CharLowerBuffW(name.data(),DWORD(name.size()));
                // Missing target directories are observed through their existing ancestor.
                if (subtree || name == L"sunpack_config.json" || name == L"builtin_passwords.json" ||
                    name == L"sunpack_watch_roots.txt" || name == L"events.jsonl") changed(path);
                if (!item->NextEntryOffset) break;
                offset += item->NextEntryOffset;
            }
        }
    });
    WaitForSingleObject(ready_,INFINITE);
    if(!alive_) { thread_.join(); throw std::runtime_error("目录不支持文件变化通知"); }
}
DirectoryWatcher::~DirectoryWatcher() { SetEvent(stop_); if (thread_.joinable()) thread_.join(); }
StartupInfo read_startup() {
    HKEY key{}; StartupInfo result;
    auto rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &key);
    if (rc == ERROR_FILE_NOT_FOUND) return result;
    if (rc != ERROR_SUCCESS) { SetLastError(rc); win_error("Read startup registry"); }
    DWORD type{}, bytes{};
    rc = RegQueryValueExW(key, L"SunPackWatchService", nullptr, &type, nullptr, &bytes);
    if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        std::wstring value(bytes / sizeof(wchar_t) + 1, 0);
        rc = RegQueryValueExW(key, L"SunPackWatchService", nullptr, &type, reinterpret_cast<BYTE*>(value.data()), &bytes);
        if (rc == ERROR_SUCCESS) { value.resize(wcsnlen(value.data(), value.size())); result = {true, utf8(value)}; }
    }
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) { SetLastError(rc); win_error("Read startup value"); }
    return result;
}
fs::path choose_directory(HWND owner) {
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        throw std::runtime_error("无法打开目录选择器");
    dialog->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
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
void CALLBACK ServiceMonitor::Subscription::notified(void* parameter) {
    auto* notification=static_cast<SERVICE_NOTIFYW*>(parameter);
    auto* self=static_cast<Subscription*>(notification->pContext);
    self->pending=false;
    self->changed=true;
    // SCM calls may themselves perform alertable RPC waits. Never query,
    // close or rearm here; the waiting thread consumes the result afterwards.
    if(notification->pszServiceNames) {
        LocalFree(notification->pszServiceNames); notification->pszServiceNames=nullptr;
    }
}
void ServiceMonitor::Subscription::arm(DWORD mask) {
    notification={};
    notification.dwVersion=SERVICE_NOTIFY_STATUS_CHANGE;
    notification.pfnNotifyCallback=notified; notification.pContext=this;
    changed=false; pending=true; // A callback can run inside the RPC below.
    auto error=NotifyServiceStatusChangeW(handle,mask,&notification);
    if(error!=ERROR_SUCCESS) { pending=false; SetLastError(error); win_error("Subscribe service status"); }
}
void ServiceMonitor::Subscription::close() {
    if(handle) {
        CloseServiceHandle(handle); handle=nullptr;
        // Cancellation prevents new APCs. Drain already queued callbacks while
        // their buffer/context is still alive, before reusing or destroying it.
        while(SleepEx(0,TRUE)==WAIT_IO_COMPLETION) {}
    }
    pending=changed=false; notification={};
}
bool ServiceMonitor::running() {
    if(service_.pending) return running_;
    for(unsigned attempt=0;;++attempt) {
        try {
            auto error=service_.changed?service_.notification.dwNotificationStatus:
                database_.changed?database_.notification.dwNotificationStatus:ERROR_SUCCESS;
            if(error==ERROR_SERVICE_NOTIFY_CLIENT_LAGGING) {
                service_.close(); database_.close();
            } else if(error==ERROR_SERVICE_MARKED_FOR_DELETE ||
                (service_.changed && (service_.notification.dwNotificationTriggered&SERVICE_NOTIFY_DELETE_PENDING))) {
                service_.close();
            } else if(error!=ERROR_SUCCESS) { SetLastError(error); win_error("Service status notification"); }
            if(!service_.handle) {
                if(!database_.handle) {
                    database_.handle=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE);
                    if(!database_.handle) win_error("Open service manager");
                }
                // Arm before opening: installation/removal in this gap cannot
                // be lost, even when the service is not installed at GUI start.
                if(!database_.pending) database_.arm(SERVICE_NOTIFY_CREATED|SERVICE_NOTIFY_DELETED);
                service_.handle=OpenServiceW(database_.handle,name_.c_str(),SERVICE_QUERY_STATUS);
                if(!service_.handle) {
                    error=GetLastError();
                    if(error==ERROR_SERVICE_DOES_NOT_EXIST || error==ERROR_SERVICE_MARKED_FOR_DELETE) return running_=false;
                    win_error("Open Watch Broker service");
                }
                database_.close();
            }
            SERVICE_STATUS_PROCESS status{}; DWORD bytes=0;
            if(!QueryServiceStatusEx(service_.handle,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&bytes))
                win_error("Query Watch Broker status");
            constexpr DWORD states=SERVICE_NOTIFY_STOPPED|SERVICE_NOTIFY_START_PENDING|SERVICE_NOTIFY_STOP_PENDING|
                SERVICE_NOTIFY_RUNNING|SERVICE_NOTIFY_CONTINUE_PENDING|SERVICE_NOTIFY_PAUSE_PENDING|SERVICE_NOTIFY_PAUSED;
            // Excluding the queried state also covers a transition between the
            // query and subscription: SCM queues an APC for the new state.
            service_.arm((states&~(1u<<(status.dwCurrentState-1)))|SERVICE_NOTIFY_DELETE_PENDING);
            return running_=status.dwCurrentState==SERVICE_RUNNING;
        } catch(const WinError& error) {
            service_.close(); database_.close();
            // One immediate reconnect after an observed lag, never idle retries.
            if(attempt==0 && (error.code==ERROR_SERVICE_NOTIFY_CLIENT_LAGGING ||
                error.code==ERROR_SERVICE_MARKED_FOR_DELETE || error.code==ERROR_SERVICE_DOES_NOT_EXIST)) continue;
            throw;
        }
    }
}
CliResult run_cli(const CliCommand& cli, const std::vector<std::wstring>& args, HANDLE stop) {
    if (!fs::is_regular_file(cli.executable)) throw std::runtime_error("未找到 SunPack CLI；请安装完整发行包或传入 --cli");
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
    if(writer.value==INVALID_HANDLE_VALUE) win_error("CLI output capture");
    Handle nullInput(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr));
    STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.StartupInfo.hStdOutput = writer; si.StartupInfo.hStdError = writer; si.StartupInfo.hStdInput = nullInput;
    SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> attributes(bytes);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytes)) win_error("CLI attributes");
    HANDLE inherited[] = {writer, nullInput};
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(si.lpAttributeList); win_error("CLI handles");
    }
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(cli.executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, cli.cwd.c_str(), &si.StartupInfo, &pi);
    auto error = GetLastError(); DeleteProcThreadAttributeList(si.lpAttributeList);
    if (!ok) { SetLastError(error); win_error("Launch CLI"); }
    Handle process(pi.hProcess), processThread(pi.hThread);
    HANDLE waits[] = {stop, process};
    auto signal = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    DWORD code = 0; GetExitCodeProcess(process, &code);
    std::string output;
    if(signal==WAIT_OBJECT_0+1) {
        LARGE_INTEGER start{}; SetFilePointerEx(writer,start,nullptr,FILE_BEGIN);
        output.resize(65536); DWORD count=0;
        if(!ReadFile(writer,output.data(),DWORD(output.size()),&count,nullptr)) win_error("Read CLI output");
        output.resize(count);
    }

    return {code, output};
}
}
