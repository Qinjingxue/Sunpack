// Exercise the actual packaged launcher control path, not a Python stand-in.
// The private console and local pipe require no resident runtime or fixtures.
#include <windows.h>

#include <algorithm>
#include <array>
#include <string_view>

namespace {
// Change the reported dimensions only while the console listener is stopped.
SMALL_RECT test_viewport{0, 0, 79, 24};
const std::array<std::wstring_view, 3>* test_console_chunks = nullptr;
std::size_t test_console_read = 0;

BOOL read_test_viewport(HANDLE output, CONSOLE_SCREEN_BUFFER_INFO* screen) {
    if (!GetConsoleScreenBufferInfo(output, screen)) return FALSE;
    screen->srWindow = test_viewport;
    return TRUE;
}

BOOL read_test_console(HANDLE input, void* buffer, DWORD capacity, DWORD* read,
                       CONSOLE_READCONSOLE_CONTROL* control) {
    if (!test_console_chunks) return ReadConsoleW(input, buffer, capacity, read, control);
    if (test_console_read == test_console_chunks->size()) return FALSE;
    const auto chunk = (*test_console_chunks)[test_console_read++];
    if (chunk.size() > capacity) return FALSE;
    std::copy(chunk.begin(), chunk.end(), static_cast<wchar_t*>(buffer));
    *read = static_cast<DWORD>(chunk.size());
    return TRUE;
}
}

#define GetConsoleScreenBufferInfo read_test_viewport
#define ReadConsoleW read_test_console
#define wmain sunpack_launcher_main
#include "../src/launcher.cpp"
#undef wmain
#undef ReadConsoleW
#undef GetConsoleScreenBufferInfo

#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void expect_split_surrogate() {
    // Force the high unit to end the first read independently of conhost.
    std::wstring prefix(4094, L'x');
    prefix.push_back(L'\xd83d');
    const std::array<std::wstring_view, 3> chunks{prefix, L"\xde00", L"\r\n"};
    test_console_chunks = &chunks;
    test_console_read = 0;
    const auto text = read_input_line();
    const auto terminator = read_input_line();
    test_console_chunks = nullptr;
    require(text == std::string(4094, 'x') + "\xf0\x9f\x98\x80",
            "preserve a surrogate pair across console reads");
    require(terminator == "\r\n", "read the subsequent line terminator");
}

void development_entrypoint_contract() {
    namespace fs = std::filesystem;
    wchar_t temporary[MAX_PATH];
    require(GetTempPathW(MAX_PATH, temporary) != 0, "temporary directory");
    const auto root = fs::path(temporary) / (L"SunPack-launch-layout-" + std::to_wstring(GetCurrentProcessId()));
    fs::create_directories(root / L"sunpack");
    std::ofstream(root / L"sunpack" / L"Cargo.toml") << "[workspace]";
    std::ofstream(root / L"sunpack_advanced_config.json") << "{}";
    for (const auto* arch : {L"x64", L"arm64"}) {
        for (const auto* profile : {L"ci", L"release"}) {
            const auto executable = root / L".cache" / L"native" / arch / profile / L"sevenzip_bridge" / L"Release" / L"sunpack_launcher.exe";
            const auto context = install_context(executable.wstring());
            const auto target = std::wstring(arch) == L"arm64" ? L"aarch64-pc-windows-msvc" : L"x86_64-pc-windows-msvc";
            const auto expected = root / L".cache" / L"rust-target" / target / profile / L"sunpack-runtime.exe";
            require(context.directory == root.wstring() && context.runtime == expected.wstring() &&
                    context.data_dir == root.wstring(), "native source layout");
            require(state_path(context) == (root / (L"runtime-" + wide_utf8(context.runtime_id) + L".state")).wstring(),
                    "source launcher and runtime share the state directory");
            std::ofstream(root / L"sunpack_config.json") << "{\"cli\":{\"language\":\"zh\"}}";
            require(cli_language_from_config(context) == "zh", "source writable config language");
        }
    }
    const auto installed = root / L"package";
    fs::create_directories(installed / L"bin");
    std::ofstream(installed / L"sunpack-runtime.exe") << "runtime";
    const auto context = install_context((installed / L"bin" / L"sunpack.exe").wstring());
    require(context.directory == installed.wstring() && context.runtime == (installed / L"sunpack-runtime.exe").wstring(), "packaged layout unchanged");
    require(context.data_dir == program_data_dir(), "packaged writable data remains ProgramData");
    fs::remove_all(root);
}

void key(HANDLE input, wchar_t value) {
    INPUT_RECORD record{};
    record.EventType = KEY_EVENT;
    record.Event.KeyEvent.bKeyDown = TRUE;
    record.Event.KeyEvent.wRepeatCount = 1;
    const SHORT virtual_key = VkKeyScanW(value);
    record.Event.KeyEvent.wVirtualKeyCode = value == L'\r' ? VK_RETURN : virtual_key == -1 ? 0 : virtual_key & 0xff;
    record.Event.KeyEvent.uChar.UnicodeChar = value;
    DWORD written = 0;
    require(WriteConsoleInputW(input, &record, 1, &written) && written == 1, "inject key");
}

void expect_empty(HANDLE pipe) {
    DWORD available = 0;
    require(PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) && available == 0,
            "unexpected control bytes");
}

void expect_resize(HANDLE pipe, SHORT columns, SHORT rows) {
    std::array<char, 12> frame{};
    // The launcher checks dimensions synchronously on construction and resume.
    DWORD available = 0;
    require(PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) &&
            available >= frame.size(), "missing resize frame");
    require(read_all(pipe, frame.data(), frame.size()), "read resize");
    require(read_u32(frame.data()) == kResizeControl &&
            read_u32(frame.data() + 4) == static_cast<std::uint32_t>(columns) &&
            read_u32(frame.data() + 8) == static_cast<std::uint32_t>(rows), "resize dimensions");
}
}

int main() {
    try {
        development_entrypoint_contract();
        for (auto arguments : std::vector<std::vector<std::wstring>>{
                {L"extract", L"archive.zip", L"-pa"},
                {L"extract", L"-j", L"-pa"},
                {L"watch", L"list", L"-pa"}}) {
            require(consume_pause(arguments), "client owns pause regardless of command result");
        }
        for (auto arguments : std::vector<std::vector<std::wstring>>{
                {L"extract", L"--", L"-pa"},
                {L"extract", L"-p", L"-pa"},
                {L"extract", L"-p", L"-npa"},
                {L"extract", L"-p", L"--", L"-p", L"-pa"},
                {L"extract", L"-npa"}}) {
            require(!consume_pause(arguments), "do not reinterpret operands or option values");
        }

        for (auto arguments : std::vector<std::vector<std::wstring>>{
                {L"scan", L"archive.zip", L"-pa", L"-npa"},
                {L"scan", L"archive.zip", L"-npa", L"-pa"},
                {L"scan", L"archive.zip", L"-pa"}}) {
            require(consume_pause(arguments), "explicit pause belongs to launcher");
            require(arguments == std::vector<std::wstring>{L"scan", L"archive.zip", L"-npa"},
                    "both pause flag orders run without runtime conflict");
        }
        std::vector<std::wstring> operands{L"scan", L"-pa", L"--", L"-pa", L"-npa"};
        require(consume_pause(operands) && operands == std::vector<std::wstring>{
                L"scan", L"-npa", L"--", L"-pa", L"-npa"},
                "insert runtime suppression before delimiter without consuming operands");
        std::vector<std::wstring> password{L"scan", L"-p", L"--", L"-pa", L"--", L"-pa"};
        require(consume_pause(password) && password == std::vector<std::wstring>{
                L"scan", L"-p", L"--", L"-npa", L"--", L"-pa"},
                "a password delimiter is data, not the end of options");
        std::vector<std::wstring> missing_password{L"scan", L"-pa", L"archive.zip", L"-p"};
        require(consume_pause(missing_password) && missing_password == std::vector<std::wstring>{
                L"scan", L"-npa", L"archive.zip", L"-p"},
                "pause suppression must not supply a missing password");
        require(supports_cancellation({L"scan"}) && supports_cancellation({L"s"}) &&
                supports_cancellation({L"extract"}) && supports_cancellation({L"e"}) &&
                !supports_cancellation({L"watch", L"status"}) && !supports_cancellation({}),
                "workload cancellation aliases");
        FreeConsole();
        require(AllocConsole() != 0, "allocate console");
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        const HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        const HANDLE output = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        require(input != INVALID_HANDLE_VALUE && output != INVALID_HANDLE_VALUE, "open console");
        require(SetStdHandle(STD_INPUT_HANDLE, input) && SetStdHandle(STD_OUTPUT_HANDLE, output), "set console handles");
        DWORD mode = 0;
        require(GetConsoleMode(input, &mode) && SetConsoleMode(input, mode & ~ENABLE_WINDOW_INPUT), "initial input mode");
        mode &= ~ENABLE_WINDOW_INPUT;
        const std::wstring name = L"\\\\.\\pipe\\SunPack-launcher-console-test-" + std::to_wstring(GetCurrentProcessId());
        const HANDLE server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        require(server != INVALID_HANDLE_VALUE, "create pipe");
        const HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        require(client != INVALID_HANDLE_VALUE, "open pipe");
        OVERLAPPED connected{};
        connected.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        require(connected.hEvent != nullptr, "connection event");
        require(ConnectNamedPipe(server, &connected) || GetLastError() == ERROR_PIPE_CONNECTED, "connect pipe");
        CloseHandle(connected.hEvent);
        {
            ConsoleCancellation controls(client, supports_cancellation({L"scan"}), true);
            DWORD active_mode = 0;
            require(GetConsoleMode(input, &active_mode) && (active_mode & ENABLE_WINDOW_INPUT), "resize input enabled");
            expect_resize(server, 80, 25);
            controls.pause();
            test_viewport = {0, 0, 39, 9};
            for (wchar_t value : std::wstring(L"quietQpassword\r")) key(input, value);
            require(read_input_line().find("quietQpassword") != std::string::npos, "prompt owns Q keys");
            expect_split_surrogate();
            expect_empty(server);
            controls.resume(); // Recheck even if line input consumed the event.
            expect_resize(server, 40, 10);
            key(input, L'Q');
            std::array<char, 4> stop{};
            require(read_all(server, stop.data(), stop.size()) && read_u32(stop.data()) == 0xffffffffu,
                    "scan Q cancellation");
            controls.cancel();
            controls.pause();
            expect_empty(server); // Cancellation remains idempotent.
        }
        // This is the same final client boundary for success, cancellation and
        // startup/transport failure: no runtime response is needed to pause.
        key(input, L'\r');
        pause_on_exit(true, "en");
        key(input, L'\r');
        pause_on_exit(true, "zh");
        DWORD restored = 0;
        require(GetConsoleMode(input, &restored) && restored == mode, "restore input mode");
        CloseHandle(client);
        CloseHandle(server);
        CloseHandle(input);
        CloseHandle(output);
        FreeConsole();
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
