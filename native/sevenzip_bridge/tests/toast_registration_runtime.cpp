#include <cwchar>
#include <string_view>

// A real child process catches registration being routed to the persistent
// server, identity loss, and swallowed exit status. No registry is modified.
int wmain(int argc, wchar_t** argv) {
    constexpr std::wstring_view prefix = L"--_sunpack-runtime-id=v2-";
    if (argc != 3 || std::wcscmp(argv[1], L"--register-toast") != 0) return 1;
    const std::wstring_view identity(argv[2]);
    if (identity.size() != prefix.size() + 16 || identity.substr(0, prefix.size()) != prefix) return 2;
    for (const wchar_t ch : identity.substr(prefix.size())) {
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return 3;
    }
    return 37;
}
