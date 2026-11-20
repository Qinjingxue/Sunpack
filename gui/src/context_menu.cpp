#include "platform.hpp"
#include "presentation.hpp"
#include <shlobj.h>

namespace spg {
namespace {
constexpr wchar_t classes[] = L"Software\\Classes\\";
struct Menu {
    const wchar_t* parent;
    const wchar_t* verbs;
    const wchar_t* target;
    const char* extract_label;
    const char* prompt_label;
    const char* recursive_label;
    bool directory;
};
// A drive or UNC root can end in a backslash. Appending \. keeps that
// backslash away from the closing quote after Explorer expands the token.
constexpr Menu menus[] = {
    {L"Directory\\shell\\SunPack", L"SunPack.FolderContextMenu", L"%1\\.",
        "shellExtractFolder", "shellPromptFolder", "shellRecursiveFolder", true},
    {L"Directory\\Background\\shell\\SunPack", L"SunPack.BackgroundContextMenu", L"%V\\.",
        "shellExtractBackground", "shellPromptBackground", "shellRecursiveBackground", true},
    {L"*\\shell\\SunPack", L"SunPack.FileContextMenu", L"%1",
        "shellExtractFile", "shellPromptFile", nullptr, false},
};

bool missing(LSTATUS result) {
    return result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND;
}

void check_registry(LSTATUS result, const char* operation) {
    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        win_error(operation);
    }
}

struct MenuKey {
    HKEY handle{};
    MenuKey(HKEY parent, const std::wstring& path) {
        check_registry(RegCreateKeyExW(parent, path.c_str(), 0, nullptr, 0,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY, nullptr, &handle, nullptr), "opChangeContextMenu");
    }
    ~MenuKey() { RegCloseKey(handle); }
    MenuKey(const MenuKey&) = delete;

    void set(const wchar_t* name, const std::wstring& value) const {
        check_registry(RegSetValueExW(handle, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()), DWORD((value.size() + 1) * sizeof(wchar_t))),
            "opChangeContextMenu");
    }
    void label(const std::wstring& text, const std::wstring& icon) const {
        set(nullptr, text);
        set(L"MUIVerb", text);
        set(L"Icon", icon);
    }
};

void write_command(HKEY shell, const wchar_t* name, const std::wstring& label,
    const std::wstring& icon, const std::wstring& command) {
    MenuKey verb(shell, name);
    MenuKey(verb.handle, L"command").set(nullptr, command);
    verb.label(label, icon);
}

void write_menu_commands(const Menu& menu, const std::wstring& extract,
    const std::wstring& watch, const std::wstring& icon, const std::string& language) {
    const auto label = [&](const char* key) { return wide(tr(key,language)); };
    const auto target = quote_arg(menu.target);
    const auto command = extract + target + (menu.directory ? L" -o " + target : L" -d");
    MenuKey shell(HKEY_CURRENT_USER, std::wstring(classes) + menu.verbs + L"\\shell");
    write_command(shell.handle, L"DirectExtract", label(menu.extract_label), icon, command + L" -pa");
    const auto prompt = menu.directory ? command + L" -a -pa" : extract + target + L" -a -d -pa";
    write_command(shell.handle, L"PromptPassword", label(menu.prompt_label), icon, prompt);
    if (!menu.directory) return;
    write_command(shell.handle, L"RecursiveExtract", label(menu.recursive_label), icon, command + L" -R -pa");
    write_command(shell.handle, L"WatchFolder", label("shellWatchFolder"), icon, watch + L"add " + target);
    write_command(shell.handle, L"WatchFolderRecursive", label("shellWatchRecursive"), icon, watch + L"add " + target + L" -R");
    write_command(shell.handle, L"UnwatchFolder", label("shellUnwatchFolder"), icon, watch + L"remove " + target);
}

bool delete_menu_tree(const wchar_t* path) {
    const auto result = RegDeleteTreeW(HKEY_CURRENT_USER, (std::wstring(classes) + path).c_str());
    if (missing(result)) return false;
    check_registry(result, "opChangeContextMenu");
    return true;
}
}

bool context_menu_enabled() {
    // A surviving entry is enough to offer removal of a partial registration.
    for (const auto& menu : menus) {
        HKEY key{};
        const auto result = RegOpenKeyExW(HKEY_CURRENT_USER, (std::wstring(classes) + menu.parent).c_str(),
            0, KEY_QUERY_VALUE, &key);
        if (result == ERROR_SUCCESS) { RegCloseKey(key); return true; }
        if (!missing(result)) check_registry(result, "opReadContextMenu");
    }
    return false;
}

void change_context_menu(const CliCommand& cli, ContextMenuAction action, const std::string& language) {
    MutexLock lock(L"Local\\SunPack.ContextMenu");
    if (action == ContextMenuAction::Refresh && !context_menu_enabled()) return;
    if (action == ContextMenuAction::Disable) {
        bool changed = false;
        for (const auto& menu : menus) changed |= delete_menu_tree(menu.parent);
        for (const auto& menu : menus) changed |= delete_menu_tree(menu.verbs);
        if (!changed) return;
    } else {
        std::error_code error;
        if (!fs::is_regular_file(cli.executable, error)) throw std::runtime_error("cliMissing");
        const auto icon_path = cli.app_root / L"sunpack.ico";
        const auto icon = (fs::is_regular_file(icon_path, error) ? icon_path : cli.executable).wstring();
        const auto launcher = quote_arg(cli.executable.wstring());
        const auto extract = launcher + L" extract ";
        const auto watch = quote_arg(executable_path().wstring()) + L" --cli " + launcher
            + L" --app-root " + quote_arg(cli.app_root.wstring()) + L" --shell-watch ";
        // Publish the Explorer parents after all their commands are ready.
        for (const auto& menu : menus) write_menu_commands(menu, extract, watch, icon, language);
        for (const auto& menu : menus) {
            MenuKey parent(HKEY_CURRENT_USER, std::wstring(classes) + menu.parent);
            parent.set(L"ExtendedSubCommandsKey", menu.verbs);
            parent.label(L"sunpack", icon);
        }
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
}
}
