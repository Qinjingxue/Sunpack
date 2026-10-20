#pragma once
#include <windows.h>
#include <objbase.h>
#include <atomic>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <stdexcept>

namespace spg {
namespace fs = std::filesystem;
struct WinError : std::runtime_error {
    DWORD code;
    WinError(DWORD code, const std::string& message):std::runtime_error(message),code(code) {}
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    operator HANDLE() const { return value; }
};
std::string utf8(const std::wstring& value);
std::wstring wide(const std::string& value);
[[noreturn]] void win_error(const char* operation);
std::string read_file(const fs::path& path, size_t limit = 16 * 1024 * 1024);
void atomic_write(const fs::path& path, const std::string& content);
std::wstring path_key(const fs::path& path);
bool is_under(const std::wstring& candidate, const std::wstring& root);
fs::path resolve_path(const fs::path& path, const fs::path& base = {});
std::wstring mutex_name(const fs::path& path, const std::wstring& prefix = L"SunPack.EditableFile");
struct FileMutex {
    Handle handle;
    FileMutex(const fs::path& path, const std::wstring& prefix = L"SunPack.EditableFile");
    ~FileMutex();
};
// One outstanding overlapped request; cancellation joins before handles are closed.
class DirectoryWatcher {
    Handle stop_{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle ready_{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic<bool> alive_{true};
    bool direct_ = false;
    std::thread thread_;
public:
    DirectoryWatcher(const fs::path& directory, std::function<void(const fs::path&)> changed);
    ~DirectoryWatcher();
    DirectoryWatcher(const DirectoryWatcher&) = delete;
    bool alive() const { return alive_; }
    bool direct() const { return direct_; }
};
struct StartupInfo { bool enabled = false; std::string command; };
StartupInfo read_startup();
fs::path choose_directory(HWND owner);
std::wstring quote_arg(const std::wstring& arg);
struct CliCommand { fs::path executable, cwd; std::vector<std::wstring> prefix; };
struct CliResult { DWORD code; std::string output; };
CliResult run_cli(const CliCommand& cli, const std::vector<std::wstring>& args, HANDLE stop);
fs::path executable_path();
// Owned and destroyed on the thread that performs the alertable SCM wait.
class ServiceMonitor {
    struct Subscription {
        SC_HANDLE handle = nullptr;
        SERVICE_NOTIFYW notification{};
        bool pending = false, changed = false;
        static void CALLBACK notified(void* parameter);
        void arm(DWORD mask);
        void close();
        ~Subscription() { close(); }
    } database_, service_;
    std::wstring name_;
    bool running_ = false;
public:
    explicit ServiceMonitor(const wchar_t* name = L"SunPackWatchBroker") : name_(name) {}
    ServiceMonitor(const ServiceMonitor&) = delete;
    ServiceMonitor& operator=(const ServiceMonitor&) = delete;
    bool changed() const { return database_.changed || service_.changed; }
    bool running();
};
}
