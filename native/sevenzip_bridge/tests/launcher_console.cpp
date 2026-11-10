// Exercise the actual packaged launcher control path, not a Python stand-in.
// The private console and local pipe require no resident runtime or fixtures.
#define wmain sunpack_launcher_main
#include "../src/launcher.cpp"
#undef wmain

#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void key(HANDLE input, wchar_t value) {
    INPUT_RECORD record{};
    record.EventType = KEY_EVENT;
    record.Event.KeyEvent.bKeyDown = TRUE;
    record.Event.KeyEvent.wRepeatCount = 1;
    record.Event.KeyEvent.wVirtualKeyCode = value == L'\r' ? VK_RETURN : static_cast<WORD>(VkKeyScanW(value) & 0xff);
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
    require(read_all(pipe, frame.data(), frame.size()), "read resize");
    require(read_u32(frame.data()) == kResizeControl &&
            read_u32(frame.data() + 4) == static_cast<std::uint32_t>(columns) &&
            read_u32(frame.data() + 8) == static_cast<std::uint32_t>(rows), "resize dimensions");
}
}

int main() {
    try {
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
        CONSOLE_SCREEN_BUFFER_INFO screen{};
        require(GetConsoleScreenBufferInfo(output, &screen), "initial viewport");

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
            expect_resize(server, screen.srWindow.Right - screen.srWindow.Left + 1,
                          screen.srWindow.Bottom - screen.srWindow.Top + 1);
            controls.pause();
            SMALL_RECT window{0, 0, 39, 9};
            require(SetConsoleWindowInfo(output, TRUE, &window) != 0, "shrink viewport");
            for (wchar_t value : std::wstring(L"quietQpassword\r")) key(input, value);
            require(read_input_line().find("quietQpassword") != std::string::npos, "prompt owns Q keys");
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
