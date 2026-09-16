#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <NotificationActivationCallback.h>

#include <winrt/base.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.UI.Notifications.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <cmath>
#include "toast.h"
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

using winrt::Windows::Data::Xml::Dom::XmlDocument;
using winrt::Windows::UI::Notifications::NotificationData;
using winrt::Windows::UI::Notifications::NotificationUpdateResult;
using winrt::Windows::UI::Notifications::ToastDismissalReason;
using winrt::Windows::UI::Notifications::ToastDismissedEventArgs;
using winrt::Windows::UI::Notifications::ToastNotification;
using winrt::Windows::UI::Notifications::ToastNotificationManager;

constexpr wchar_t kAppId[] = L"SunPack.Watch.Toast";
constexpr wchar_t kProgressToastTag[] = L"watch-progress";
constexpr wchar_t kFinalToastTag[] = L"watch-final";
constexpr wchar_t kToastGroup[] = L"SunPack";
constexpr wchar_t kClsidText[] = L"{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}";
constexpr wchar_t kToastDisplayName[] = L"SunPack";
constexpr wchar_t kToastIconBackgroundColor[] = L"FF0078D4";
constexpr CLSID kToastActivatorClsid = {
    0xc5a6b4e9, 0x3184, 0x44e2, {0x9f, 0x15, 0x6a, 0x71, 0x80, 0x4f, 0x7a, 0x36}
};

constexpr std::uint32_t kMaximumSnapshotBytes = 64 * 1024 - 20;

std::mutex g_activation_mutex;
std::condition_variable g_activation_condition;
bool g_activated = false;

class WinrtApartmentScope {
public:
    WinrtApartmentScope() {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
    }

    ~WinrtApartmentScope() {
        winrt::clear_factory_cache();
        winrt::uninit_apartment();
    }

    WinrtApartmentScope(const WinrtApartmentScope&) = delete;
    WinrtApartmentScope& operator=(const WinrtApartmentScope&) = delete;
};

enum class SnapshotKind : std::uint8_t {
    progress = 1,
    success = 2,
    failure = 3,
    mixed = 4,
};

enum class ProgressMode : std::uint8_t {
    none = 0,
    determinate = 1,
    indeterminate = 2,
};

enum class ActionKind : std::uint8_t {
    open_directory = 1,
    open_log = 2,
};

struct Action {
    ActionKind kind{};
    std::wstring label;
    std::wstring target;
};

struct Snapshot {
    SnapshotKind kind{};
    ProgressMode progress_mode{};
    double progress_value{};
    std::uint32_t ttl_ms{};
    std::wstring batch_id;
    std::wstring title;
    std::wstring body;
    std::wstring progress_title;
    std::wstring progress_status;
    std::wstring progress_value_text;
    std::vector<Action> actions;
};

std::wstring quote_argument(std::wstring_view value) {
    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(ch);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

void set_registry_string(HKEY root, const std::wstring& subkey,
                         const wchar_t* value_name, const std::wstring& value) {
    HKEY key = nullptr;
    const LSTATUS created = RegCreateKeyExW(
        root,
        subkey.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr
    );
    if (created != ERROR_SUCCESS) {
        winrt::check_hresult(HRESULT_FROM_WIN32(created));
    }
    const LSTATUS written = RegSetValueExW(
        key,
        value_name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))
    );
    RegCloseKey(key);
    if (written != ERROR_SUCCESS) {
        winrt::check_hresult(HRESULT_FROM_WIN32(written));
    }
}

std::optional<std::wstring> get_registry_string(
    HKEY root, const std::wstring& subkey, const wchar_t* value_name
) {
    DWORD bytes = 0;
    if (RegGetValueW(
        root, subkey.c_str(), value_name, RRF_RT_REG_SZ,
        nullptr, nullptr, &bytes
    ) != ERROR_SUCCESS || bytes < sizeof(wchar_t)) {
        return std::nullopt;
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    if (RegGetValueW(
        root, subkey.c_str(), value_name, RRF_RT_REG_SZ,
        nullptr, value.data(), &bytes
    ) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    value.resize(std::wcslen(value.c_str()));
    return value;
}

std::wstring toast_app_id_registry_path() {
    return std::wstring(L"Software\\Classes\\AppUserModelId\\") + kAppId;
}

std::wstring toast_icon_path(const std::wstring& executable) {
    return (std::filesystem::path(executable).parent_path() / L"sunpack.ico").wstring();
}

void register_toast_identity(const std::wstring& executable, const std::wstring& arguments) {
    const std::wstring com_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText + L"\\LocalServer32";
    set_registry_string(
        HKEY_LOCAL_MACHINE, com_path, nullptr, quote_argument(executable) + L" " + arguments
    );

    const std::wstring app_id_path = toast_app_id_registry_path();
    set_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"DisplayName", kToastDisplayName);
    set_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"IconUri", toast_icon_path(executable));
    set_registry_string(
        HKEY_LOCAL_MACHINE, app_id_path, L"IconBackgroundColor", kToastIconBackgroundColor
    );
    set_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"CustomActivator", kClsidText);
}

bool toast_identity_registered(const std::wstring& executable, const std::wstring& arguments) noexcept {
    try {
        const std::wstring com_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText + L"\\LocalServer32";
        const std::wstring app_id_path = toast_app_id_registry_path();
        return get_registry_string(HKEY_LOCAL_MACHINE, com_path, nullptr) ==
                   quote_argument(executable) + L" " + arguments &&
               get_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"DisplayName") ==
                   kToastDisplayName &&
               get_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"IconUri") ==
                   toast_icon_path(executable) &&
               get_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"IconBackgroundColor") ==
                   kToastIconBackgroundColor &&
               get_registry_string(HKEY_LOCAL_MACHINE, app_id_path, L"CustomActivator") ==
                   kClsidText;
    } catch (...) {
        return false;
    }
}

void unregister_toast_identity() noexcept {
    try {
        const std::wstring com_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText;
        const std::wstring app_id_path = toast_app_id_registry_path();
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, com_path.c_str());
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, app_id_path.c_str());
    } catch (...) {
    }
}

std::wstring xml_escape(std::wstring_view text) {
    std::wstring result;
    result.reserve(text.size());
    for (const wchar_t ch : text) {
        switch (ch) {
        case L'&': result += L"&amp;"; break;
        case L'<': result += L"&lt;"; break;
        case L'>': result += L"&gt;"; break;
        case L'\"': result += L"&quot;"; break;
        case L'\'': result += L"&apos;"; break;
        default:
            if (ch >= 0x20 || ch == L'\t' || ch == L'\n' || ch == L'\r') {
                result.push_back(ch);
            }
        }
    }
    return result;
}

std::wstring utf8_to_utf16(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return {};
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("UTF-8 field is too large");
    }
    const int required = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(data),
        static_cast<int>(size),
        nullptr,
        0
    );
    if (required <= 0) {
        winrt::throw_last_error();
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(data),
        static_cast<int>(size),
        result.data(),
        required
    ) != required) {
        winrt::throw_last_error();
    }
    return result;
}

std::string utf16_to_utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (required <= 0) {
        winrt::throw_last_error();
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr
    ) != required) {
        winrt::throw_last_error();
    }
    return result;
}

std::string_view dismissal_reason_name(ToastDismissalReason reason) noexcept {
    switch (reason) {
    case ToastDismissalReason::TimedOut:
        return "TimedOut";
    case ToastDismissalReason::UserCanceled:
        return "UserCanceled";
    case ToastDismissalReason::ApplicationHidden:
        return "ApplicationHidden";
    default:
        return "Unknown";
    }
}

void append_dismissal_event(
    const std::wstring& log_path,
    std::string_view kind,
    ToastDismissalReason reason
) noexcept {
    if (log_path.empty()) return;
    HANDLE file = CreateFileW(
        log_path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart > 512 * 1024) {
        CloseHandle(file);
        file = CreateFileW(
            log_path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (file == INVALID_HANDLE_VALUE) return;
    }
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char timestamp[32]{};
    const int timestamp_length = std::snprintf(
        timestamp,
        sizeof(timestamp),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds
    );
    std::string line = "{\"time\":\"";
    if (timestamp_length > 0) {
        line.append(timestamp, static_cast<std::size_t>(timestamp_length));
    }
    line += "\",\"event\":\"toast_dismissed\",\"kind\":\"";
    line += kind;
    line += "\",\"reason\":\"";
    line += dismissal_reason_name(reason);
    line += "\"}\r\n";
    DWORD written = 0;
    WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(file);
}

std::wstring hex_encode(std::wstring_view value) {
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    const std::string utf8 = utf16_to_utf8(value);
    std::wstring result;
    result.reserve(utf8.size() * 2);
    for (const unsigned char byte : utf8) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

std::optional<std::wstring> hex_decode(std::wstring_view value) {
    if (value.empty() || value.size() % 2 != 0 || value.size() > 65534) {
        return std::nullopt;
    }
    auto digit = [](wchar_t ch) -> int {
        if (ch >= L'0' && ch <= L'9') return ch - L'0';
        if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
        if (ch >= L'A' && ch <= L'F') return ch - L'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> bytes(value.size() / 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const int high = digit(value[index * 2]);
        const int low = digit(value[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    try {
        return utf8_to_utf16(bytes.data(), bytes.size());
    } catch (...) {
        return std::nullopt;
    }
}

bool absolute_existing_target(const std::wstring& path, bool directory) {
    if (path.empty() || !std::filesystem::path(path).is_absolute()) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return directory
        ? (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        : (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

void activate_action(std::wstring_view arguments) noexcept {
    try {
        const std::size_t separator = arguments.find(L'|');
        if (separator == std::wstring_view::npos) {
            return;
        }
        const std::wstring_view kind = arguments.substr(0, separator);
        const auto decoded = hex_decode(arguments.substr(separator + 1));
        if (!decoded) {
            return;
        }
        bool directory = false;
        if (kind == L"dir") {
            directory = true;
        } else if (kind == L"log") {
            const std::filesystem::path path(*decoded);
            if (path.extension() != L".txt") {
                return;
            }
        } else {
            return;
        }
        if (!absolute_existing_target(*decoded, directory)) {
            return;
        }
        ShellExecuteW(nullptr, L"open", decoded->c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } catch (...) {
    }
}

class ActivationCallback final : public INotificationActivationCallback {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) noexcept override {
        if (object == nullptr) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(INotificationActivationCallback)) {
            *object = static_cast<INotificationActivationCallback*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override {
        return ++references_;
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override {
        const ULONG value = --references_;
        if (value == 0) delete this;
        return value;
    }

    HRESULT STDMETHODCALLTYPE Activate(
        LPCWSTR app_user_model_id,
        LPCWSTR invoked_args,
        const NOTIFICATION_USER_INPUT_DATA*,
        ULONG
    ) noexcept override {
        if (app_user_model_id != nullptr && std::wstring_view(app_user_model_id) == kAppId) {
            activate_action(invoked_args == nullptr ? std::wstring_view{} : std::wstring_view(invoked_args));
        }
        {
            std::lock_guard lock(g_activation_mutex);
            g_activated = true;
        }
        g_activation_condition.notify_all();
        return S_OK;
    }

private:
    std::atomic<ULONG> references_{1};
};

class ActivationFactory final : public IClassFactory {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) noexcept override {
        if (object == nullptr) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) {
            *object = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() noexcept override {
        const ULONG value = --references_;
        if (value == 0) delete this;
        return value;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** object) noexcept override {
        if (outer != nullptr) return CLASS_E_NOAGGREGATION;
        auto* callback = new (std::nothrow) ActivationCallback();
        if (callback == nullptr) return E_OUTOFMEMORY;
        const HRESULT result = callback->QueryInterface(iid, object);
        callback->Release();
        return result;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL) noexcept override { return S_OK; }

private:
    std::atomic<ULONG> references_{1};
};

class ActivationRegistration {
public:
    explicit ActivationRegistration(const CLSID& clsid = kToastActivatorClsid) {
        winrt::com_ptr<IClassFactory> factory;
        factory.attach(new ActivationFactory());
        winrt::check_hresult(CoRegisterClassObject(
            clsid, factory.get(), CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE, &cookie_));
    }
    ~ActivationRegistration() { CoRevokeClassObject(cookie_); }
    ActivationRegistration(const ActivationRegistration&) = delete;
    ActivationRegistration& operator=(const ActivationRegistration&) = delete;
private:
    DWORD cookie_{};
};

template <typename T>
T read_little_endian(const std::uint8_t* data) {
    T value{};
    std::memcpy(&value, data, sizeof(T));
    return value;
}

class PayloadReader {
public:
    explicit PayloadReader(const std::vector<std::uint8_t>& payload) : payload_(payload) {}

    std::uint8_t byte() {
        require(1);
        return payload_[offset_++];
    }

    std::uint32_t uint32() {
        require(4);
        const auto value = read_little_endian<std::uint32_t>(payload_.data() + offset_);
        offset_ += 4;
        return value;
    }

    double floating() {
        require(8);
        const auto value = read_little_endian<double>(payload_.data() + offset_);
        offset_ += 8;
        return value;
    }

    std::wstring string() {
        const std::uint32_t length = uint32();
        require(length);
        std::wstring result = utf8_to_utf16(payload_.data() + offset_, length);
        offset_ += length;
        return result;
    }

    bool finished() const noexcept { return offset_ == payload_.size(); }

private:
    void require(std::size_t count) const {
        if (count > payload_.size() - offset_) {
            throw std::runtime_error("truncated Toast payload");
        }
    }

    const std::vector<std::uint8_t>& payload_;
    std::size_t offset_{};
};

Snapshot parse_snapshot(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);
    Snapshot result;
    result.kind = static_cast<SnapshotKind>(reader.byte());
    result.progress_mode = static_cast<ProgressMode>(reader.byte());
    const std::uint8_t action_count = reader.byte();
    if (reader.byte() != 0 || action_count > 2) {
        throw std::runtime_error("invalid Toast snapshot header");
    }
    const double progress = reader.floating();
    result.progress_value = std::isfinite(progress) ? std::clamp(progress, 0.0, 1.0) : 0.0;
    result.ttl_ms = reader.uint32();
    result.batch_id = reader.string();
    result.title = reader.string();
    result.body = reader.string();
    result.progress_title = reader.string();
    result.progress_status = reader.string();
    result.progress_value_text = reader.string();
    if (result.progress_mode < ProgressMode::none || result.progress_mode > ProgressMode::indeterminate) {
        throw std::runtime_error("invalid Toast progress mode");
    }
    for (std::uint8_t index = 0; index < action_count; ++index) {
        Action action;
        action.kind = static_cast<ActionKind>(reader.byte());
        action.label = reader.string();
        action.target = reader.string();
        if (action.kind != ActionKind::open_directory && action.kind != ActionKind::open_log) {
            throw std::runtime_error("invalid Toast action kind");
        }
        result.actions.push_back(std::move(action));
    }
    if (!reader.finished()) {
        throw std::runtime_error("trailing Toast snapshot data");
    }
    if (result.kind < SnapshotKind::progress || result.kind > SnapshotKind::mixed) {
        throw std::runtime_error("invalid Toast snapshot kind");
    }
    return result;
}

std::wstring action_arguments(const Action& action) {
    return std::wstring(action.kind == ActionKind::open_directory ? L"dir|" : L"log|") + hex_encode(action.target);
}

class ToastPresenter {
public:
    explicit ToastPresenter(std::wstring diagnostic_log_path)
        : notifier_(ToastNotificationManager::CreateToastNotifier(kAppId)),
          diagnostic_log_path_(std::move(diagnostic_log_path)) {}

    ~ToastPresenter() {
        clear();
    }

    void show(const Snapshot& snapshot, std::uint64_t sequence) {
        if (snapshot.kind == SnapshotKind::progress) {
            show_progress(snapshot, sequence);
        } else {
            show_final(snapshot);
        }
    }

    void clear() noexcept {
        remove(kProgressToastTag);
        remove(kFinalToastTag);
        progress_shown_ = false;
    }

private:
    void remove(std::wstring_view tag) noexcept {
        try {
            ToastNotificationManager::History().Remove(tag, kToastGroup, kAppId);
        } catch (...) {
        }
    }

    void observe_dismissal(const ToastNotification& toast, std::string_view kind) {
        if (diagnostic_log_path_.empty()) return;
        const auto log_path = diagnostic_log_path_;
        const std::string kind_name(kind);
        toast.Dismissed([log_path, kind_name](
            const ToastNotification&,
            const ToastDismissedEventArgs& args
        ) noexcept {
            append_dismissal_event(log_path, kind_name, args.Reason());
        });
    }

    void show_progress(const Snapshot& snapshot, std::uint64_t sequence) {
        NotificationData data;
        const auto values = data.Values();
        values.Insert(L"title", snapshot.title);
        values.Insert(L"body", snapshot.body);
        values.Insert(L"progressTitle", snapshot.progress_title);
        values.Insert(L"progressStatus", snapshot.progress_status);
        values.Insert(L"progressValueString", snapshot.progress_value_text);
        if (snapshot.progress_mode == ProgressMode::indeterminate) {
            values.Insert(L"progressValue", L"indeterminate");
        } else {
            values.Insert(L"progressValue", winrt::to_hstring(snapshot.progress_value));
        }
        data.SequenceNumber(static_cast<std::uint32_t>(sequence & 0xffffffff));
        if (progress_shown_) {
            const auto updated = notifier_.Update(data, kProgressToastTag, kToastGroup);
            if (updated == NotificationUpdateResult::Succeeded) {
                return;
            }
        }
        remove(kFinalToastTag);
        XmlDocument document;
        document.LoadXml(
            LR"(<toast duration="long" launch="noop"><visual><binding template="ToastGeneric"><text>{title}</text><text>{body}</text><progress title="{progressTitle}" value="{progressValue}" valueStringOverride="{progressValueString}" status="{progressStatus}"/></binding></visual></toast>)"
        );
        ToastNotification toast(document);
        toast.Tag(kProgressToastTag);
        toast.Group(kToastGroup);
        toast.Data(data);
        observe_dismissal(toast, "progress");
        notifier_.Show(toast);
        progress_shown_ = true;
    }

    void show_final(const Snapshot& snapshot) {
        remove(kProgressToastTag);
        progress_shown_ = false;
        std::wstring xml = L"<toast duration=\"long\" launch=\"noop\"><visual><binding template=\"ToastGeneric\"><text>";
        xml += xml_escape(snapshot.title);
        xml += L"</text>";
        if (!snapshot.body.empty()) {
            xml += L"<text>" + xml_escape(snapshot.body) + L"</text>";
        }
        xml += L"</binding></visual>";
        if (!snapshot.actions.empty()) {
            xml += L"<actions>";
            for (const auto& action : snapshot.actions) {
                xml += L"<action activationType=\"background\" content=\"";
                xml += xml_escape(action.label);
                xml += L"\" arguments=\"";
                xml += xml_escape(action_arguments(action));
                xml += L"\"/>";
            }
            xml += L"</actions>";
        }
        xml += L"</toast>";
        XmlDocument document;
        document.LoadXml(xml);
        ToastNotification toast(document);
        toast.Tag(kFinalToastTag);
        toast.Group(kToastGroup);
        observe_dismissal(toast, "final");
        notifier_.Show(toast);
    }

    winrt::Windows::UI::Notifications::ToastNotifier notifier_{nullptr};
    std::wstring diagnostic_log_path_;
    bool progress_shown_{};
};

struct ToastContext {
    explicit ToastContext(const CLSID& clsid = kToastActivatorClsid) : activation(clsid) {}
    WinrtApartmentScope apartment;
    ActivationRegistration activation;
    std::wstring diagnostic_log_path;
    std::unique_ptr<ToastPresenter> presenter;
    DWORD owner_thread = GetCurrentThreadId();
};

template <typename Work>
HRESULT protect(Work&& work) noexcept {
    try {
        work();
        return S_OK;
    } catch (const winrt::hresult_error& error) {
        return error.code();
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_INVALIDARG;
    }
}

ToastContext& context_on_owner_thread(void* raw) {
    if (!raw) winrt::throw_hresult(E_INVALIDARG);
    auto& context = *static_cast<ToastContext*>(raw);
    if (context.owner_thread != GetCurrentThreadId()) winrt::throw_hresult(RPC_E_WRONG_THREAD);
    return context;
}

int self_test() {
    const std::wstring original = L"C:\\测试\\failed & log.txt";
    const auto decoded = hex_decode(hex_encode(original));
    if (!decoded || *decoded != original) return 1;
    if (xml_escape(L"<&\"'>") != L"&lt;&amp;&quot;&apos;&gt;") return 2;
    std::vector<std::uint8_t> payload(40, 0);
    payload[0] = static_cast<std::uint8_t>(SnapshotKind::success);
    payload[1] = static_cast<std::uint8_t>(ProgressMode::determinate);
    const double progress = 0.25;
    std::memcpy(payload.data() + 4, &progress, sizeof(progress));
    if (parse_snapshot(payload).progress_value != progress) return 3;
    for (std::size_t size = 0; size < payload.size(); ++size) {
        bool rejected = false;
        try { parse_snapshot(std::vector<std::uint8_t>(payload.begin(), payload.begin() + size)); }
        catch (...) { rejected = true; }
        if (!rejected) return 4;
    }
    {
        CLSID test_clsid{};
        winrt::check_hresult(CoCreateGuid(&test_clsid));
        ToastContext context(test_clsid);
        XmlDocument first;
        first.LoadXml(L"<root><value>first</value></root>");
        XmlDocument second;
        second.LoadXml(L"<root><value>second</value></root>");
        if (&context_on_owner_thread(&context) != &context) return 5;
        HRESULT wrong_thread = S_OK;
        std::thread other([&] {
            wrong_thread = protect([&] { context_on_owner_thread(&context); });
        });
        other.join();
        if (wrong_thread != RPC_E_WRONG_THREAD) return 6;
        winrt::com_ptr<IClassFactory> factory;
        winrt::check_hresult(CoGetClassObject(test_clsid, CLSCTX_LOCAL_SERVER, nullptr, IID_PPV_ARGS(factory.put())));
        winrt::com_ptr<INotificationActivationCallback> callback;
        winrt::check_hresult(factory->CreateInstance(nullptr, IID_PPV_ARGS(callback.put())));
        winrt::check_hresult(callback->Activate(kAppId, L"noop", nullptr, 0));
    }
    return 0;
}

} // namespace

HRESULT sunpack_toast_create(const wchar_t* executable, const wchar_t* arguments,
                             const wchar_t* log_path, void** output) noexcept {
    if (!output) return E_POINTER;
    *output = nullptr;
    return protect([&] {
        if (!executable || !arguments) winrt::throw_hresult(E_INVALIDARG);
        auto context = std::make_unique<ToastContext>();
        if (!toast_identity_registered(executable, arguments)) {
            register_toast_identity(executable, arguments);
        }
        context->diagnostic_log_path = log_path ? log_path : L"";
        *output = context.release();
    });
}

HRESULT sunpack_toast_show(void* raw, const std::uint8_t* data,
                           std::uint32_t size, std::uint64_t sequence) noexcept {
    return protect([&] {
        auto& context = context_on_owner_thread(raw);
        if (!data || size > kMaximumSnapshotBytes) winrt::throw_hresult(E_INVALIDARG);
        const auto snapshot = parse_snapshot(std::vector<std::uint8_t>(data, data + size));
        if (!context.presenter) {
            context.presenter = std::make_unique<ToastPresenter>(context.diagnostic_log_path);
        }
        context.presenter->show(snapshot, sequence);
    });
}

HRESULT sunpack_toast_clear(void* raw) noexcept {
    return protect([&] { context_on_owner_thread(raw).presenter.reset(); });
}

HRESULT sunpack_toast_destroy(void* raw) noexcept {
    return protect([&] { delete &context_on_owner_thread(raw); });
}

HRESULT sunpack_toast_register(const wchar_t* executable, const wchar_t* arguments) noexcept {
    return protect([&] {
        if (!executable || !arguments) winrt::throw_hresult(E_INVALIDARG);
        WinrtApartmentScope apartment;
        register_toast_identity(executable, arguments);
    });
}

HRESULT sunpack_toast_unregister() noexcept {
    return protect([] { unregister_toast_identity(); });
}

HRESULT sunpack_toast_activate() noexcept {
    return protect([] {
        WinrtApartmentScope apartment;
        {
            std::lock_guard lock(g_activation_mutex);
            g_activated = false;
        }
        ActivationRegistration activation;
        std::unique_lock lock(g_activation_mutex);
        g_activation_condition.wait_for(lock, std::chrono::seconds(30), [] { return g_activated; });
    });
}

HRESULT sunpack_toast_self_test() noexcept {
    return protect([] {
        if (self_test() != 0) winrt::throw_hresult(E_FAIL);
    });
}