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
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr char kRequestMagic[] = "SPK2";
constexpr char kStreamMagic[] = "SPS2";
constexpr char kRuntimeIdentityArgumentPrefix[] = "--_sunpack-runtime-id=";
constexpr std::size_t kMaxFieldBytes = 16u * 1024u * 1024u;

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

struct InstallContext {
    std::wstring directory;
    std::string runtime_id;
};

InstallContext install_context() {
    const std::wstring executable = current_executable_path();
    std::wstring directory = executable;
    const auto slash = directory.find_last_of(L"\\/");
    directory.resize(slash == std::wstring::npos ? 0 : slash);
    return {directory, "v2-" + fnv1a_hex(utf8(executable))};
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

std::vector<std::wstring> program_data_roots() {
    std::array<wchar_t, 32768> program_data{};
    const DWORD length = GetEnvironmentVariableW(L"PROGRAMDATA", program_data.data(), static_cast<DWORD>(program_data.size()));
    if (length == 0 || length >= program_data.size()) return {};
    return {std::wstring(program_data.data(), length) + L"\\SunPack"};
}

std::wstring first_existing_config(const std::vector<std::wstring>& roots, const wchar_t* filename) {
    for (const auto& root : roots) {
        const std::wstring path = join_config_path(root, filename);
        if (file_exists(path)) return path;
    }
    return {};
}

// Mirrors sunpack.i18n.context.normalize_language: only "zh" selects Chinese.
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
// installed build: sunpack_config.json comes from %ProgramData%\SunPack and
// sunpack_advanced_config.json from the install directory. Missing or
// unreadable config falls back to English, matching the Python default.
std::string cli_language_from_config(const std::wstring& launcher_dir) {
    const std::wstring simple_path = first_existing_config(program_data_roots(), L"sunpack_config.json");
    const std::wstring advanced_path = first_existing_config({launcher_dir}, L"sunpack_advanced_config.json");
    std::string language;
    if (!simple_path.empty()) language = config_language(simple_path);
    if (language.empty() && !advanced_path.empty()) language = config_language(advanced_path);
    return normalize_language(language);
}

std::wstring state_path(const InstallContext& context) {
    std::array<wchar_t, 32768> program_data{};
    DWORD length = GetEnvironmentVariableW(L"PROGRAMDATA", program_data.data(), static_cast<DWORD>(program_data.size()));
    if (length == 0 || length >= program_data.size()) {
        return {};
    }
    return std::wstring(program_data.data(), length) + L"\\SunPack\\runtime-" + wide_utf8(context.runtime_id) + L".state";
}

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
        binary_stamp != runtime_binary_stamp(context.directory + L"\\sunpack-runtime.exe")) return false;
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
    if (!WaitNamedPipeW(pipe_name.c_str(), 2000)) return INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 4; ++attempt) {
        HANDLE pipe = CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            if (SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) return pipe;
            CloseHandle(pipe);
            return INVALID_HANDLE_VALUE;
        }
        if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(pipe_name.c_str(), 500)) break;
    }
    return INVALID_HANDLE_VALUE;
}

bool write_all(HANDLE pipe, const char* data, std::size_t size) {
    while (size != 0) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size, 0x7fffffff));
        if (!WriteFile(pipe, data, chunk, &written, nullptr) || written == 0) return false;
        data += written;
        size -= written;
    }
    return true;
}

bool read_all(HANDLE pipe, char* data, std::size_t size) {
    while (size != 0) {
        DWORD read = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size, 0x7fffffff));
        if (!ReadFile(pipe, data, chunk, &read, nullptr) || read == 0) return false;
        data += read;
        size -= read;
    }
    return true;
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

bool request(const InstallContext& context, const std::vector<std::wstring>& arguments, bool shutdown, int& exit_code,
             const std::wstring& request_cwd) {
    std::wstring pipe_name;
    std::array<unsigned char, 32> token{};
    std::string runtime_build_id;
    if (!parse_state(context, pipe_name, token, runtime_build_id)) return false;
    HANDLE pipe = connect_pipe(pipe_name);
    if (pipe == INVALID_HANDLE_VALUE) return false;

    const std::string cwd = utf8(request_cwd);
    if (cwd.size() > kMaxFieldBytes || arguments.size() > 4096) {
        CloseHandle(pipe);
        return false;
    }
    std::string wire(kRequestMagic, 4);
    wire.append(runtime_build_id);
    wire.append(reinterpret_cast<const char*>(token.data()), token.size());
    DWORD console_mode = 0;
    const bool stdout_tty = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &console_mode) != 0;
    DWORD input_mode = 0;
    const bool stdin_tty = GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &input_mode) != 0;
    append_u32(wire, (shutdown ? 1u : 0u) | (stdout_tty ? 2u : 0u) | (stdin_tty ? 4u : 0u));
    append_u32(wire, static_cast<std::uint32_t>(cwd.size()));
    append_u32(wire, static_cast<std::uint32_t>(arguments.size()));
    wire.append(cwd);
    for (const auto& argument : arguments) {
        const std::string encoded = utf8(argument);
        if (encoded.size() > kMaxFieldBytes) {
            CloseHandle(pipe);
            return false;
        }
        append_u32(wire, static_cast<std::uint32_t>(encoded.size()));
        wire.append(encoded);
    }
    if (!write_all(pipe, wire.data(), wire.size())) {
        CloseHandle(pipe);
        return false;
    }
    std::array<char, 4> magic{};
    if (!read_all(pipe, magic.data(), magic.size()) || memcmp(magic.data(), kStreamMagic, 4) != 0) {
        CloseHandle(pipe);
        return false;
    }
    std::array<char, 16> build_id{};
    if (!read_all(pipe, build_id.data(), build_id.size()) ||
        memcmp(build_id.data(), runtime_build_id.data(), build_id.size()) != 0) {
        CloseHandle(pipe);
        return false;
    }
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
            CloseHandle(pipe);
            return true;
        }
        if (kind == 1) write_stream(STD_OUTPUT_HANDLE, payload);
        else if (kind == 2) write_stream(STD_ERROR_HANDLE, payload);
        else if (kind == 3) {
            const std::string input = read_input_line();
            std::string response;
            append_u32(response, static_cast<std::uint32_t>(input.size()));
            response.append(input);
            if (!write_all(pipe, response.data(), response.size())) break;
        }
    }
    CloseHandle(pipe);
    return false;
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
    const std::wstring runtime = context.directory + L"\\sunpack-runtime.exe";
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

// Localized strings printed directly by this launcher. Keep in sync with the
// sunpack/i18n/catalog.py keys cli.press_enter, cli.persistent_start_timeout,
// cli.native_runtime_launch_failed, and cli.native_runtime_exited.
constexpr wchar_t kPressEnterEn[] = L"Press Enter to continue...";
constexpr wchar_t kPressEnterZh[] = L"按回车键继续...";
constexpr wchar_t kPersistentTimeoutEn[] = L"SunPack persistent process did not start in time.";
constexpr wchar_t kPersistentTimeoutZh[] = L"SunPack 持久进程未能及时启动。";
constexpr wchar_t kRuntimeLaunchFailedEn[] = L"sunpack runtime failed to launch (Win32 error {error}).";
constexpr wchar_t kRuntimeLaunchFailedZh[] = L"sunpack 运行时启动失败（Win32 错误 {error}）。";
constexpr wchar_t kRuntimeExitedEn[] = L"sunpack runtime exited before becoming ready, exit code {code}.";
constexpr wchar_t kRuntimeExitedZh[] = L"sunpack 运行时尚未就绪便已退出，退出码为 {code}。";

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
    const bool shutdown_request = argc >= 2 && wcscmp(argv[1], L"--persistent-shutdown") == 0;
    const bool shutdown = shutdown_request;
    bool pause = false;
    std::vector<std::wstring> request_arguments;
    const int first_request_argument = shutdown ? 2 : 1;
    for (int index = first_request_argument; index < argc; ++index) {
        if (wcscmp(argv[index], L"--pause") == 0) {
            pause = true;
        } else {
            request_arguments.emplace_back(argv[index]);
        }
    }
    if (pause && std::find(request_arguments.begin(), request_arguments.end(), L"--no-pause") == request_arguments.end()) {
        request_arguments.emplace_back(L"--no-pause");
    }
    int code = 1;
    bool ok = request(context, request_arguments, shutdown, code, invocation_cwd);
    if (!ok && !shutdown) {
        const std::string language = cli_language_from_config(launcher_cwd);
        DWORD spawn_error = ERROR_SUCCESS;
        HANDLE runtime_process = nullptr;
        DWORD runtime_exit_code = STILL_ACTIVE;
        bool runtime_failed = false;
        if (spawn_runtime(context, {L"--persistent-server"}, true, nullptr, &spawn_error, &runtime_process)) {
            for (int attempt = 0; attempt < 400 && !ok; ++attempt) {
                if (runtime_process != nullptr && WaitForSingleObject(runtime_process, 0) == WAIT_OBJECT_0) {
                    GetExitCodeProcess(runtime_process, &runtime_exit_code);
                    runtime_failed = true;
                    break;
                }
                Sleep(25);
                ok = request(context, request_arguments, false, code, invocation_cwd);
            }
            if (runtime_process != nullptr) CloseHandle(runtime_process);
        } else {
            std::string startup_error = localized_value(
                language,
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
                    language,
                    kRuntimeExitedEn,
                    kRuntimeExitedZh,
                    "{code}",
                    std::to_string(static_cast<unsigned long>(runtime_exit_code))
                ) + "\n"
            );
        }
    }
    if (!ok && shutdown) code = 0;
    std::string language;
    if (pause || (!ok && !shutdown)) {
        language = cli_language_from_config(launcher_cwd);
    }
    if (!ok && !shutdown) {
        write_stream(STD_ERROR_HANDLE, localized(language, kPersistentTimeoutEn, kPersistentTimeoutZh) + "\n");
    }
    if (pause && GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR) {
        write_stream(STD_OUTPUT_HANDLE, localized(language, kPressEnterEn, kPressEnterZh));
        wchar_t buffer[2]{};
        DWORD read = 0;
        ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buffer, 1, &read, nullptr);
    }
    return code;
}

#endif
