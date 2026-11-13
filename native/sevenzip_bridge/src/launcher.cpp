#ifdef _WIN32

#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>

namespace {

constexpr char kRequestMagic[] = "SPK2";
constexpr char kStreamMagic[] = "SPS2";
constexpr char kRuntimeIdentityArgumentPrefix[] = "--_sunpack-runtime-id=";
constexpr char kTerminalSizeArgumentPrefix[] = "--_sunpack-terminal-size=";
constexpr std::size_t kMaxFieldBytes = 16u * 1024u * 1024u;
constexpr std::uint32_t kResizeControl = 0xfffffffeu;

std::wstring current_executable_path() {
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    std::wstring path(buffer.data(), size);
    CharLowerBuffW(path.data(), static_cast<DWORD>(path.size()));
    return path;
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring current_directory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetCurrentDirectoryW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (size == 0 || size >= buffer.size()) return {};
    return std::wstring(buffer.data(), size);
}

std::wstring wide_utf8(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        result.data(), size);
    return result;
}

std::string fnv1a_hex(const std::string& value) {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    std::array<char, 17> text{};
    std::snprintf(text.data(), text.size(), "%016llx", static_cast<unsigned long long>(hash));
    return std::string(text.data());
}

std::string runtime_binary_stamp(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA metadata{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &metadata)) return {};
    const std::uint64_t size =
        (static_cast<std::uint64_t>(metadata.nFileSizeHigh) << 32) | metadata.nFileSizeLow;
    const std::uint64_t windows_ticks =
        (static_cast<std::uint64_t>(metadata.ftLastWriteTime.dwHighDateTime) << 32) |
        metadata.ftLastWriteTime.dwLowDateTime;
    constexpr std::uint64_t unix_epoch_ticks = 116444736000000000ULL;
    const std::uint64_t unix_nanoseconds = windows_ticks >= unix_epoch_ticks
        ? (windows_ticks - unix_epoch_ticks) * 100ULL
        : 0;
    std::ostringstream value;
    value << std::hex << size << '-' << unix_nanoseconds;
    return value.str();
}

bool file_exists(const std::wstring& path);
std::wstring program_data_dir();

struct InstallContext {
    std::wstring directory;
    std::string runtime_id;
    std::wstring runtime;
    std::wstring data_dir;
};

InstallContext install_context(const std::wstring& executable) {
    namespace fs = std::filesystem;
    fs::path directory = fs::path(executable).parent_path();
    if (directory.filename() == L"bin") directory = directory.parent_path();
    fs::path runtime = directory / L"sunpack-runtime.exe";
    fs::path data_dir = program_data_dir();
    // Official source builds keep the launcher and Rust artifacts in their
    // native build directories. Do not stage a fake package beside the runtime.
    if (!file_exists(runtime.wstring()) && fs::path(executable).stem() == L"sunpack_launcher") {
        const auto build = directory.parent_path();
        const auto root = build.parent_path().parent_path().parent_path();
        const auto name = build.filename().wstring();
        const bool ci = name.size() >= 3 && name.compare(name.size() - 3, 3, L"-ci") == 0;
        const auto arch = ci ? name.substr(0, name.size() - 3) : name;
        if ((arch == L"build-x64" || arch == L"build-arm64") &&
            file_exists((root / L"native" / L"Cargo.toml").wstring()) &&
            file_exists((root / L"sunpack_advanced_config.json").wstring())) {
            const auto target = arch == L"build-arm64"
                ? L"aarch64-pc-windows-msvc" : L"x86_64-pc-windows-msvc";
            const auto platform = arch == L"build-arm64" ? L"arm64" : L"x64";
            runtime = root / L".cache" / L"rust-target" / platform / target / (ci ? L"ci" : L"release") / L"sunpack-runtime.exe";
            directory = root;
            data_dir = root;
        }
    }
    return {directory.wstring(), "v2-" + fnv1a_hex(utf8(executable)), runtime.wstring(), data_dir.wstring()};
}

InstallContext install_context() {
    return install_context(current_executable_path());
}

bool file_exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string read_text_file(const std::wstring& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return {};
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

// Minimal JSON string helpers, mirroring the same helpers in worker.cpp.
std::size_t skip_ws(const std::string& json, std::size_t pos) {
    while (pos < json.size() && static_cast<unsigned char>(json[pos]) <= 0x20) {
        ++pos;
    }
    return pos;
}

std::string parse_json_string_at(const std::string& json, std::size_t quote_pos, std::size_t* out_next = nullptr) {
    std::string out;
    if (quote_pos >= json.size() || json[quote_pos] != '"') {
        return out;
    }
    for (std::size_t i = quote_pos + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (ch == '"') {
            if (out_next) {
                *out_next = i + 1;
            }
            return out;
        }
        if (ch == '\\' && i + 1 < json.size()) {
            const char escaped = json[++i];
            switch (escaped) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            default: out.push_back(escaped); break;
            }
            continue;
        }
        out.push_back(ch);
    }
    return out;
}

// Reads the string value of field_key inside the object_key object. This avoids
// matching an unrelated "language" field elsewhere in the config document.
std::string json_string_field_in_object(const std::string& json, const std::string& object_key,
                                        const std::string& field_key) {
    const std::string object_needle = "\"" + object_key + "\"";
    const std::size_t object_pos = json.find(object_needle);
    if (object_pos == std::string::npos) return {};
    const std::size_t object_colon = json.find(':', object_pos + object_needle.size());
    if (object_colon == std::string::npos) return {};
    const std::size_t open_brace = skip_ws(json, object_colon + 1);
    if (open_brace >= json.size() || json[open_brace] != '{') return {};

    const std::string field_needle = "\"" + field_key + "\"";
    std::size_t depth = 1;
    std::size_t index = open_brace + 1;
    while (index < json.size() && depth != 0) {
        const char ch = json[index];
        if (depth != 0 && json.compare(index, field_needle.size(), field_needle) == 0) {
            std::size_t before = index;
            while (before > 0 && (json[before - 1] == ' ' || json[before - 1] == '\t' ||
                                  json[before - 1] == '\r' || json[before - 1] == '\n')) {
                --before;
            }
            const bool is_key = before > 0 && (json[before - 1] == '{' || json[before - 1] == ',');
            if (is_key) {
                const std::size_t colon = json.find(':', index + field_needle.size());
                if (colon != std::string::npos) {
                    const std::size_t quote = skip_ws(json, colon + 1);
                    return parse_json_string_at(json, quote);
                }
            }
        }
        if (ch == '"') {
            std::size_t next = 0;
            parse_json_string_at(json, index, &next);
            if (next == 0) return {};
            index = next;
            continue;
        }
        if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) break;
        }
        ++index;
    }
    return {};
}

std::string config_language(const std::wstring& path) {
    return json_string_field_in_object(read_text_file(path), "cli", "language");
}

std::wstring join_config_path(const std::wstring& directory, const wchar_t* filename) {
    if (directory.empty()) return filename;
    return directory + L"\\" + filename;
}

std::wstring program_data_dir() {
    std::array<wchar_t, 32768> program_data{};
    const DWORD length = GetEnvironmentVariableW(L"PROGRAMDATA", program_data.data(), static_cast<DWORD>(program_data.size()));
    if (length == 0 || length >= program_data.size()) return {};
    return std::wstring(program_data.data(), length) + L"\\SunPack";
}

std::wstring first_existing_config(const std::vector<std::wstring>& roots, const wchar_t* filename) {
    for (const auto& root : roots) {
        const std::wstring path = join_config_path(root, filename);
        if (file_exists(path)) return path;
    }
    return {};
}

// Mirrors sunpack.core.i18n.context.normalize_language: only "zh" selects Chinese.
std::string normalize_language(const std::string& raw) {
    const std::size_t begin = raw.find_first_not_of(" \t\r\n");
    const std::size_t end = raw.find_last_not_of(" \t\r\n");
    std::string value = begin == std::string::npos ? std::string() : raw.substr(begin, end - begin + 1);
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    }
    return value == "zh" ? "zh" : "en";
}

// Resolves cli.language the same way the Python config layer does for an
// installed or source build: writable config and advanced config use the same
// data/application roots as the runtime. Missing or
// unreadable config falls back to English, matching the Python default.
std::string cli_language_from_config(const InstallContext& context) {
    const std::wstring simple_path = context.data_dir.empty() ? std::wstring()
        : first_existing_config({context.data_dir}, L"sunpack_config.json");
    const std::wstring advanced_path = first_existing_config({context.directory}, L"sunpack_advanced_config.json");
    std::string language;
    if (!simple_path.empty()) language = config_language(simple_path);
    if (language.empty() && !advanced_path.empty()) language = config_language(advanced_path);
    return normalize_language(language);
}

std::wstring state_path(const InstallContext& context) {
    if (context.data_dir.empty()) return {};
    return join_config_path(context.data_dir, (L"runtime-" + wide_utf8(context.runtime_id) + L".state").c_str());
}

// Serialize only endpoint startup, never command execution. A readiness event
// replaces polling and is signalled after the server has armed its first pipe.
struct RuntimeStartup {
    HANDLE mutex = nullptr;
    HANDLE ready = nullptr;
    bool held = false;

    explicit RuntimeStartup(const InstallContext& context) {
        const std::wstring prefix = L"Global\\SunPack-" + wide_utf8(context.runtime_id);
        mutex = CreateMutexW(nullptr, FALSE, (prefix + L"-startup").c_str());
        ready = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"-ready").c_str());
        if (mutex && ready) {
            const DWORD result = WaitForSingleObject(mutex, INFINITE);
            held = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
        }
    }
    void release() {
        if (held) { ReleaseMutex(mutex); held = false; }
    }
    ~RuntimeStartup() {
        release();
        if (ready) CloseHandle(ready);
        if (mutex) CloseHandle(mutex);
    }
};

bool parse_state(const InstallContext& context, std::wstring& pipe_name,
                 std::array<unsigned char, 32>& token, std::string& runtime_build_id) {
    std::ifstream stream(state_path(context));
    std::string pipe_text;
    std::string token_text;
    std::string build_id;
    std::string pid_text;
    std::string binary_stamp;
    if (!std::getline(stream, pipe_text) || !std::getline(stream, token_text) ||
        !std::getline(stream, build_id) || !std::getline(stream, pid_text) ||
        !std::getline(stream, binary_stamp) || token_text.size() != 64 ||
        build_id.size() != 16 || pid_text.empty() ||
        binary_stamp != runtime_binary_stamp(context.runtime)) return false;
    try {
        runtime_build_id = build_id;
        pipe_name = wide_utf8(pipe_text);
        if (pipe_name.rfind(L"\\\\.\\pipe\\SunPack-", 0) != 0) return false;
        for (std::size_t index = 0; index < token.size(); ++index) {
            token[index] = static_cast<unsigned char>(std::stoul(token_text.substr(index * 2, 2), nullptr, 16));
        }
        return true;
    } catch (...) {
        return false;
    }
}

HANDLE connect_pipe(const std::wstring& pipe_name) {
    for (;;) {
        HANDLE pipe = CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_OVERLAPPED, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            if (SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) return pipe;
            CloseHandle(pipe);
            return INVALID_HANDLE_VALUE;
        }
        if (GetLastError() != ERROR_PIPE_BUSY ||
            !WaitNamedPipeW(pipe_name.c_str(), NMPWAIT_WAIT_FOREVER)) {
            return INVALID_HANDLE_VALUE;
        }
    }
}

struct PipeIoEvent {
    HANDLE handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ~PipeIoEvent() { if (handle) CloseHandle(handle); }
};

HANDLE pipe_io_event() {
    thread_local PipeIoEvent event;
    return event.handle;
}

template <typename Buffer, typename Transfer>
bool transfer_all(HANDLE pipe, Buffer* data, std::size_t size, Transfer transfer) {
    const HANDLE event = pipe_io_event();
    if (!event) return false;
    while (size != 0) {
        OVERLAPPED operation{};
        operation.hEvent = event;
        ResetEvent(event);
        DWORD processed = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size, 0x7fffffff));
        if (!transfer(pipe, data, chunk, &processed, &operation) && GetLastError() != ERROR_IO_PENDING) return false;
        if (!GetOverlappedResult(pipe, &operation, &processed, TRUE) || processed == 0) return false;
        data += processed;
        size -= processed;
    }
    return true;
}

bool write_all(HANDLE pipe, const char* data, std::size_t size) {
    return transfer_all(pipe, data, size, WriteFile);
}

bool read_all(HANDLE pipe, char* data, std::size_t size) {
    return transfer_all(pipe, data, size, ReadFile);
}

void append_u32(std::string& target, std::uint32_t value) {
    target.push_back(static_cast<char>((value >> 24) & 0xff));
    target.push_back(static_cast<char>((value >> 16) & 0xff));
    target.push_back(static_cast<char>((value >> 8) & 0xff));
    target.push_back(static_cast<char>(value & 0xff));
}

std::uint32_t read_u32(const char* source) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(source[0])) << 24)
           | (static_cast<std::uint32_t>(static_cast<unsigned char>(source[1])) << 16)
           | (static_cast<std::uint32_t>(static_cast<unsigned char>(source[2])) << 8)
           | static_cast<std::uint32_t>(static_cast<unsigned char>(source[3]));
}

void write_stream(DWORD handle_id, const std::string& text);

std::string read_input_line() {
    HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return {};
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        std::array<wchar_t, 4096> buffer{};
        DWORD read = 0;
        if (!ReadConsoleW(handle, buffer.data(), static_cast<DWORD>(buffer.size() - 1), &read, nullptr)) return {};
        return utf8(std::wstring(buffer.data(), read));
    }
    std::array<char, 4096> buffer{};
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) return {};
    return std::string(buffer.data(), read);
}

// Only NotDelivered may be retried: once the whole request reached the runtime
// it may already be executing, and resending it could run the command twice.
enum class RequestOutcome { NotDelivered, Completed, DeliveryUncertain };

bool supports_cancellation(const std::vector<std::wstring>& arguments) {
    if (arguments.empty()) return false;
    if (arguments[0] == L"extract" || arguments[0] == L"e" || arguments[0] == L"scan" || arguments[0] == L"s") return true;
    return (arguments[0] == L"watch" || arguments[0] == L"w") &&
        std::find(arguments.begin(), arguments.end(), L"--once") != arguments.end();
}

class ConsoleCancellation {
    inline static std::mutex active_mutex_;
    inline static ConsoleCancellation* active_ = nullptr;
    HANDLE pipe_, input_ = INVALID_HANDLE_VALUE, output_ = INVALID_HANDLE_VALUE, stop_ = nullptr, main_thread_ = nullptr;
    bool enabled_, window_input_added_ = false;
    SHORT last_columns_ = 0, last_rows_ = 0;
    std::thread listener_;
    std::mutex write_mutex_;
    std::atomic<bool> sent_{false}, prompt_{false};

    static BOOL WINAPI control(DWORD kind) {
        if (kind != CTRL_C_EVENT && kind != CTRL_BREAK_EVENT) return FALSE;
        std::lock_guard lock(active_mutex_);
        if (!active_) return FALSE;
        active_->cancel();
        if (active_->prompt_ && active_->main_thread_) CancelSynchronousIo(active_->main_thread_);
        return TRUE;
    }
    void listen() {
        const HANDLE handles[] = {stop_, input_};
        while (WaitForMultipleObjects(2, handles, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
            INPUT_RECORD record{};
            DWORD count = 0;
            if (!ReadConsoleInputW(input_, &record, 1, &count)) return;
            if (count && record.EventType == WINDOW_BUFFER_SIZE_EVENT) {
                resized();
            } else if (enabled_ && count && record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) {
                const wchar_t key = record.Event.KeyEvent.uChar.UnicodeChar;
                if (key == L'q' || key == L'Q') cancel();
            }
        }
    }
    void start() {
        if (stop_) {
            ResetEvent(stop_);
            listener_ = std::thread([this] { listen(); });
            resized();
        }
    }
    void join() {
        if (listener_.joinable()) {
            SetEvent(stop_);
            listener_.join();
        }
    }
public:
    ConsoleCancellation(HANDLE pipe, bool enabled, bool terminal_resize) : pipe_(pipe), enabled_(enabled) {
        if (!enabled && !terminal_resize) return;
        input_ = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (!GetConsoleMode(input_, &mode)) return;
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_) return;
        if (terminal_resize) {
            output_ = GetStdHandle(STD_OUTPUT_HANDLE);
            if (!(mode & ENABLE_WINDOW_INPUT) && SetConsoleMode(input_, mode | ENABLE_WINDOW_INPUT)) {
                window_input_added_ = true;
            }
        }
        if (enabled_) {
            main_thread_ = OpenThread(THREAD_TERMINATE, FALSE, GetCurrentThreadId());
            std::lock_guard lock(active_mutex_);
            active_ = this;
            SetConsoleCtrlHandler(control, TRUE);
        }
        try {
            start();
        } catch (...) {
            close();
            throw;
        }
    }
    void resized() {
        if (output_ == INVALID_HANDLE_VALUE) return;
        std::lock_guard lock(write_mutex_);
        CONSOLE_SCREEN_BUFFER_INFO screen{};
        if (!GetConsoleScreenBufferInfo(output_, &screen)) return;
        const SHORT columns = screen.srWindow.Right - screen.srWindow.Left + 1;
        const SHORT rows = screen.srWindow.Bottom - screen.srWindow.Top + 1;
        if (columns <= 0 || rows <= 0) return;
        if (columns == last_columns_ && rows == last_rows_) return;
        std::string frame;
        append_u32(frame, kResizeControl);
        append_u32(frame, static_cast<std::uint32_t>(columns));
        append_u32(frame, static_cast<std::uint32_t>(rows));
        if (write_all(pipe_, frame.data(), frame.size())) {
            last_columns_ = columns;
            last_rows_ = rows;
        }
    }
    void cancel() {
        if (!sent_.exchange(true)) {
            const char frame[] = {'\xff', '\xff', '\xff', '\xff'};
            send(frame, sizeof(frame));
        }
    }
    bool send(const char* data, std::size_t size) {
        std::lock_guard lock(write_mutex_);
        return write_all(pipe_, data, size);
    }
    void pause() { join(); prompt_ = true; }
    void resume() { prompt_ = false; start(); }
    void close() {
        join();
        {
            std::lock_guard lock(active_mutex_);
            if (active_ == this) {
                active_ = nullptr;
                SetConsoleCtrlHandler(control, FALSE);
            }
        }
        if (window_input_added_) {
            DWORD mode = 0;
            if (GetConsoleMode(input_, &mode)) SetConsoleMode(input_, mode & ~ENABLE_WINDOW_INPUT);
            window_input_added_ = false;
        }
        if (stop_) { CloseHandle(stop_); stop_ = nullptr; }
        if (main_thread_) { CloseHandle(main_thread_); main_thread_ = nullptr; }
    }
    ~ConsoleCancellation() { close(); }
};

RequestOutcome request(const InstallContext& context, const std::vector<std::wstring>& arguments, bool shutdown,
                       int& exit_code, const std::wstring& request_cwd, std::string& exit_prompt,
                       RuntimeStartup* startup = nullptr) {
    std::wstring pipe_name;
    std::array<unsigned char, 32> token{};
    std::string runtime_build_id;
    if (!parse_state(context, pipe_name, token, runtime_build_id)) return RequestOutcome::NotDelivered;
    const HANDLE pipe = connect_pipe(pipe_name);
    if (pipe == INVALID_HANDLE_VALUE) return RequestOutcome::NotDelivered;
    const std::unique_ptr<void, decltype(&CloseHandle)> pipe_owner(pipe, CloseHandle);
    if (startup) startup->release();

    const std::string cwd = utf8(request_cwd);
    if (cwd.empty() || cwd.size() > kMaxFieldBytes) {
        return RequestOutcome::NotDelivered;
    }
    std::string wire(kRequestMagic, 4);
    wire.append(runtime_build_id);
    wire.append(reinterpret_cast<const char*>(token.data()), token.size());
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD console_mode = 0;
    const bool stdout_tty = GetConsoleMode(output, &console_mode) &&
        ((console_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) ||
         SetConsoleMode(output, console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING));
    std::string terminal_size;
    CONSOLE_SCREEN_BUFFER_INFO screen{};
    if (stdout_tty && GetConsoleScreenBufferInfo(output, &screen)) {
        terminal_size = kTerminalSizeArgumentPrefix +
            std::to_string(screen.srWindow.Right - screen.srWindow.Left + 1) + "x" +
            std::to_string(screen.srWindow.Bottom - screen.srWindow.Top + 1);
    }
    DWORD input_mode = 0;
    const bool stdin_tty = GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &input_mode) != 0;
    const bool terminal_resize = stdout_tty && stdin_tty;
    append_u32(wire, (shutdown ? 1u : 0u) | (stdout_tty ? 2u : 0u) | (stdin_tty ? 4u : 0u) |
                     (terminal_resize ? 8u : 0u) | 16u | (!terminal_size.empty() ? 32u : 0u));
    // Bit 16 advertises WriteConsoleW or redirected UTF-8, independent of VT.
    // Bit 32 marks the final field as terminal metadata rather than a user argument.
    append_u32(wire, static_cast<std::uint32_t>(cwd.size()));
    append_u32(wire, static_cast<std::uint32_t>(arguments.size() + !terminal_size.empty()));
    wire.append(cwd);
    auto append_argument = [&](const std::string& encoded) {
        append_u32(wire, static_cast<std::uint32_t>(encoded.size()));
        wire.append(encoded);
    };
    // Windows bounds argv and the working directory. Send one request buffer
    // so the server can read the fixed header without waiting for three more writes.
    for (const auto& argument : arguments) {
        append_argument(utf8(argument));
    }
    if (!terminal_size.empty()) append_argument(terminal_size);
    if (!write_all(pipe, wire.data(), wire.size())) {
        return RequestOutcome::DeliveryUncertain;
    }
    std::array<char, 20> handshake{};
    if (!read_all(pipe, handshake.data(), handshake.size()) ||
        memcmp(handshake.data(), kStreamMagic, 4) != 0 ||
        memcmp(handshake.data() + 4, runtime_build_id.data(), 16) != 0) {
        return RequestOutcome::DeliveryUncertain;
    }
    ConsoleCancellation controls(pipe, supports_cancellation(arguments), terminal_resize);
    while (true) {
        std::array<char, 5> header{};
        if (!read_all(pipe, header.data(), header.size())) break;
        const unsigned char kind = static_cast<unsigned char>(header[0]);
        const std::uint32_t size = read_u32(header.data() + 1);
        if (size > kMaxFieldBytes) break;
        std::string payload(size, '\0');
        if (!read_all(pipe, payload.data(), payload.size())) break;
        if (kind == 0) {
            if (size != 4) break;
            exit_code = static_cast<std::int32_t>(read_u32(payload.data()));
            return RequestOutcome::Completed;
        }
        if (kind == 1) write_stream(STD_OUTPUT_HANDLE, payload);
        else if (kind == 2) write_stream(STD_ERROR_HANDLE, payload);
        else if (kind == 3) {
            controls.pause();
            const std::string input = read_input_line();
            controls.resume();
            std::string response;
            append_u32(response, static_cast<std::uint32_t>(input.size()));
            response.append(input);
            if (!controls.send(response.data(), response.size())) break;
        } else if (kind == 4) {
            exit_prompt = std::move(payload);
        }
    }
    return RequestOutcome::DeliveryUncertain;
}

std::wstring quote_argument(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
        } else if (ch == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(ch);
            slashes = 0;
        } else {
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(ch);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

bool spawn_runtime(const InstallContext& context, const std::vector<std::wstring>& arguments, bool detached,
                   DWORD* exit_code = nullptr, DWORD* spawn_error = nullptr,
                   HANDLE* detached_process = nullptr) {
    const std::wstring runtime = context.runtime;
    std::wstring command = quote_argument(runtime);
    for (const auto& argument : arguments) command += L" " + quote_argument(argument);
    command += L" " + quote_argument(wide_utf8(std::string(kRuntimeIdentityArgumentPrefix) + context.runtime_id));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (spawn_error) *spawn_error = ERROR_SUCCESS;
    if (detached_process) *detached_process = nullptr;
    const DWORD flags = detached ? CREATE_NO_WINDOW : 0;
    const wchar_t* child_cwd = context.directory.empty() ? nullptr : context.directory.c_str();
    const BOOL created = CreateProcessW(runtime.c_str(), command.data(), nullptr, nullptr, FALSE, flags,
                                        nullptr, child_cwd, &startup, &process);
    const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
    if (!created) {
        if (spawn_error) *spawn_error = create_error;
        return false;
    }
    CloseHandle(process.hThread);
    if (detached) {
        if (detached_process) {
            *detached_process = process.hProcess;
        } else {
            CloseHandle(process.hProcess);
        }
        return true;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    if (exit_code) *exit_code = code;
    return true;
}

void write_stream(DWORD handle_id, const std::string& text) {
    if (text.empty()) return;
    HANDLE handle = GetStdHandle(handle_id);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        const std::wstring wide = wide_utf8(text);
        DWORD written = 0;
        WriteConsoleW(handle, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
    } else {
        DWORD written = 0;
        WriteFile(handle, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    }
}

constexpr wchar_t kPersistentUnavailableEn[] = L"SunPack persistent process is unavailable";
constexpr wchar_t kPersistentUnavailableZh[] = L"SunPack 持久进程不可用";
constexpr wchar_t kRuntimeLaunchFailedEn[] = L"sunpack runtime failed to launch (Win32 error {error})";
constexpr wchar_t kRuntimeLaunchFailedZh[] = L"sunpack 运行时启动失败（Win32 错误 {error}）";
constexpr wchar_t kRuntimeExitedEn[] = L"sunpack runtime exited before becoming ready, exit code {code}";
constexpr wchar_t kRuntimeExitedZh[] = L"sunpack 运行时尚未就绪便已退出，退出码为 {code}";
constexpr wchar_t kDeliveryUncertainEn[] = L"SunPack persistent process disconnected after the command was submitted; it was not retried to avoid running it twice";
constexpr wchar_t kDeliveryUncertainZh[] = L"SunPack 持久进程在命令提交后断开连接；为避免重复执行，未重试该命令";

std::string localized(const std::string& language, const wchar_t* english, const wchar_t* chinese) {
    return utf8(language == "zh" ? chinese : english);
}

std::string localized_value(
    const std::string& language,
    const wchar_t* english,
    const wchar_t* chinese,
    const std::string& placeholder,
    const std::string& value
) {
    std::string text = localized(language, english, chinese);
    const std::size_t offset = text.find(placeholder);
    if (offset != std::string::npos) text.replace(offset, placeholder.size(), value);
    return text;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::wstring invocation_cwd = current_directory();
    const InstallContext context = install_context();
    const std::wstring& launcher_cwd = context.directory;
    if (!launcher_cwd.empty()) SetCurrentDirectoryW(launcher_cwd.c_str());
    // COM activation needs this install's identity before it registers the
    // callback, so it runs outside the resident Watch server.
    if (argc >= 2 && wcscmp(argv[1], L"--toast-activated") == 0) {
        DWORD exit_code = 1;
        if (!spawn_runtime(context, {L"--toast-activated"}, false, &exit_code)) return 1;
        return static_cast<int>(exit_code);
    }
    const bool shutdown_request = argc >= 2 && wcscmp(argv[1], L"--persistent-shutdown") == 0;
    const bool shutdown = shutdown_request;
    const int first_request_argument = shutdown ? 2 : 1;
    const std::vector<std::wstring> request_arguments(argv + first_request_argument, argv + argc);
    int code = 1;
    std::string exit_prompt;
    RequestOutcome outcome = request(context, request_arguments, shutdown, code, invocation_cwd, exit_prompt);
    if (outcome == RequestOutcome::NotDelivered && !shutdown) {
        RuntimeStartup startup(context);
        if (startup.held) {
            // Another launcher may have completed startup while we waited.
            outcome = request(context, request_arguments, false, code, invocation_cwd, exit_prompt, &startup);
        }
        DWORD spawn_error = ERROR_SUCCESS;
        HANDLE runtime_process = nullptr;
        DWORD runtime_exit_code = STILL_ACTIVE;
        bool runtime_failed = false;
        if (outcome == RequestOutcome::NotDelivered && startup.held) {
            ResetEvent(startup.ready);
            if (spawn_runtime(context, {L"--persistent-server"}, true, nullptr, &spawn_error, &runtime_process)) {
                const HANDLE handles[] = {startup.ready, runtime_process};
                const DWORD ready = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                outcome = request(context, request_arguments, false, code, invocation_cwd, exit_prompt, &startup);
                if (outcome == RequestOutcome::NotDelivered && ready == WAIT_OBJECT_0 + 1) {
                    GetExitCodeProcess(runtime_process, &runtime_exit_code);
                    runtime_failed = true;
                }
                CloseHandle(runtime_process);
            }
        }
        if (spawn_error != ERROR_SUCCESS) {
            std::string startup_error = localized_value(
                cli_language_from_config(context),
                kRuntimeLaunchFailedEn,
                kRuntimeLaunchFailedZh,
                "{error}",
                std::to_string(static_cast<unsigned long>(spawn_error))
            ) + "\n";
            write_stream(STD_ERROR_HANDLE, startup_error);
        }
        if (runtime_failed) {
            write_stream(
                STD_ERROR_HANDLE,
                localized_value(
                    cli_language_from_config(context),
                    kRuntimeExitedEn,
                    kRuntimeExitedZh,
                    "{code}",
                    std::to_string(static_cast<unsigned long>(runtime_exit_code))
                ) + "\n"
            );
        }
    }
    const bool ok = outcome == RequestOutcome::Completed;
    if (!ok) code = shutdown ? 0 : 1;
    std::string language;
    if (!ok && !shutdown) {
        language = cli_language_from_config(context);
    }
    if (outcome == RequestOutcome::NotDelivered && !shutdown) {
        write_stream(STD_ERROR_HANDLE, localized(language, kPersistentUnavailableEn, kPersistentUnavailableZh) + "\n");
    } else if (outcome == RequestOutcome::DeliveryUncertain && !shutdown) {
        write_stream(STD_ERROR_HANDLE, localized(language, kDeliveryUncertainEn, kDeliveryUncertainZh) + "\n");
    }
    if (ok && !exit_prompt.empty()) {
        DWORD output_mode = 0;
        const DWORD prompt_stream = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &output_mode)
            ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE;
        write_stream(prompt_stream, exit_prompt);
        read_input_line();
    }
    return code;
}

#endif
