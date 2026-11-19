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
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <cmath>
#include "toast.h"
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using winrt::Windows::Data::Xml::Dom::XmlDocument;
using winrt::Windows::UI::Notifications::NotificationData;
using winrt::Windows::UI::Notifications::NotificationUpdateResult;
using winrt::Windows::UI::Notifications::ToastNotification;
using winrt::Windows::UI::Notifications::ToastNotificationManager;

constexpr wchar_t kAppId[] = L"SunPack.Watch.Toast";
constexpr wchar_t kToastGroup[] = L"SunPack";
constexpr CLSID kToastActivatorClsid = {
    0xc5a6b4e9, 0x3184, 0x44e2, {0x9f, 0x15, 0x6a, 0x71, 0x80, 0x4f, 0x7a, 0x36}
};


std::mutex g_activation_mutex;
std::condition_variable g_activation_condition;
bool g_activated = false;
std::wstring g_cancel_batch;

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
    cancel_batch = 3,
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
    std::wstring batch_id;
    std::wstring title;
    std::wstring body;
    std::wstring progress_title;
    std::wstring progress_status;
    std::wstring progress_value_text;
    std::vector<Action> actions;
};

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
        if (kind == L"cancel") {
            if (decoded->size() != 32 || decoded->find_first_not_of(L"0123456789abcdef") != std::wstring::npos) return;
            std::lock_guard lock(g_activation_mutex);
            g_cancel_batch = *decoded;
            return;
        } else if (kind == L"dir") {
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
    explicit PayloadReader(std::span<const std::uint8_t> payload) : payload_(payload) {}

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

    std::span<const std::uint8_t> payload_;
    std::size_t offset_{};
};

Snapshot parse_snapshot(std::span<const std::uint8_t> payload) {
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
        if (action.kind != ActionKind::open_directory && action.kind != ActionKind::open_log && action.kind != ActionKind::cancel_batch) {
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
    return std::wstring(action.kind == ActionKind::cancel_batch ? L"cancel|" : action.kind == ActionKind::open_directory ? L"dir|" : L"log|") + hex_encode(action.target);
}

void append_actions_xml(std::wstring& xml, const std::vector<Action>& actions, bool progress) {
    if (actions.empty()) return;
    xml += L"<actions>";
    for (const auto& action : actions) {
        if (progress && action.kind != ActionKind::cancel_batch) continue;
        xml += L"<action activationType=\"background\" content=\"";
        xml += xml_escape(action.label);
        xml += L"\" arguments=\"";
        xml += action_arguments(action); // Fixed prefix and a hex-encoded target.
        xml += L"\"/>";
    }
    xml += L"</actions>";
}

std::wstring progress_xml(const Snapshot& snapshot) {
    std::wstring xml = LR"(<toast launch="noop"><visual><binding template="ToastGeneric"><text>{title}</text><text>{body}</text><progress title="{progressTitle}" value="{progressValue}" valueStringOverride="{progressValueString}" status="{progressStatus}"/></binding></visual>)";
    append_actions_xml(xml, snapshot.actions, true);
    xml += L"</toast>";
    return xml;
}

class ToastPresenter {
public:
    ToastPresenter() : notifier_(ToastNotificationManager::CreateToastNotifier(kAppId)) {}

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

    // Explicit clear only cancels a currently active progress notification.
    // Terminal notifications belong to Windows notification history and must
    // survive presenter teardown, watch reloads, and later batches.
    void clear() noexcept {
        hide_progress_popup();
        if (!progress_tag_.empty()) {
            remove(progress_tag_);
            progress_tag_.clear();
        }
    }

private:
    static std::wstring toast_tag(const Snapshot& snapshot, std::wstring_view suffix) {
        if (snapshot.batch_id.empty() || snapshot.batch_id.size() + suffix.size() > 64) {
            throw std::runtime_error("invalid Toast batch id");
        }
        return snapshot.batch_id + std::wstring(suffix);
    }

    void remove(std::wstring_view tag) noexcept {
        try {
            ToastNotificationManager::History().Remove(tag, kToastGroup, kAppId);
        } catch (...) {
        }
    }

    void hide_progress_popup() noexcept {
        if (progress_popup_) {
            try {
                notifier_.Hide(progress_popup_);
            } catch (...) {
            }
            progress_popup_ = nullptr;
        }
    }

    void show_progress(const Snapshot& snapshot, std::uint64_t sequence) {
        const std::wstring tag = toast_tag(snapshot, L"-p");
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
        // Keep the original controls throughout a batch. NotificationData
        // cannot change buttons; replacing XML just to hide Stop would show
        // another popup. Late clicks are checked against the active batch.
        const bool same_batch = progress_tag_ == tag;
        if (same_batch) {
            const auto updated = notifier_.Update(data, tag, kToastGroup);
            if (updated == NotificationUpdateResult::Succeeded) {
                return;
            }
        } else if (!progress_tag_.empty()) {
            // A new batch arrived while an older progress notification was
            // still active. The old progress is stale and may be removed.
            clear();
        }

        XmlDocument document;
        document.LoadXml(progress_xml(snapshot));
        ToastNotification toast(document);
        toast.Tag(tag);
        toast.Group(kToastGroup);
        toast.Data(data);
        toast.SuppressPopup(false);
        // A silent replacement can leave the old banner alive while changing
        // its history entry. Hide the owned object before replacing its XML.
        hide_progress_popup();
        notifier_.Show(toast);
        progress_popup_ = toast;
        progress_tag_ = tag;
    }

    void show_final(const Snapshot& snapshot) {
        const std::wstring progress_tag = toast_tag(snapshot, L"-p");
        const std::wstring final_tag = toast_tag(snapshot, L"-f");

        // History.Remove alone leaves the on-screen banner alive. Hide it
        // before Show so Windows need not queue completion behind that banner.
        const bool current_batch = progress_tag_ == progress_tag;
        clear();
        if (!current_batch) {
            remove(progress_tag);
        }

        // Terminal notifications intentionally use their own per-batch tag.
        // Windows owns their banner lifetime and keeps them in Notification Center.
        std::wstring xml = L"<toast launch=\"noop\"><visual><binding template=\"ToastGeneric\"><text>";
        xml += xml_escape(snapshot.title);
        xml += L"</text>";
        if (!snapshot.body.empty()) {
            xml += L"<text>" + xml_escape(snapshot.body) + L"</text>";
        }
        xml += L"</binding></visual>";
        append_actions_xml(xml, snapshot.actions, false);
        xml += L"</toast>";
        XmlDocument document;
        document.LoadXml(xml);
        ToastNotification toast(document);
        toast.Tag(final_tag);
        toast.Group(kToastGroup);
        toast.SuppressPopup(false);
        notifier_.Show(toast);
    }

    winrt::Windows::UI::Notifications::ToastNotifier notifier_{nullptr};
    ToastNotification progress_popup_{nullptr};
    std::wstring progress_tag_;
};

struct ToastContext {
    WinrtApartmentScope apartment;
    // Only the activation helper registers the COM callback. A presenter in
    // the resident runtime must not consume an activation that only the
    // helper forwards through the existing command pipe.
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

} // namespace

HRESULT sunpack_toast_create(void** output) noexcept {
    if (!output) return E_POINTER;
    *output = nullptr;
    return protect([&] {
        *output = new ToastContext();
    });
}

HRESULT sunpack_toast_show(void* raw, const std::uint8_t* data,
                           std::uint32_t size, std::uint64_t sequence) noexcept {
    return protect([&] {
        auto& context = context_on_owner_thread(raw);
        if (!data) winrt::throw_hresult(E_INVALIDARG);
        const auto snapshot = parse_snapshot(std::span<const std::uint8_t>(data, size));
        if (!context.presenter) {
            context.presenter = std::make_unique<ToastPresenter>();
        }
        context.presenter->show(snapshot, sequence);
    });
}

HRESULT sunpack_toast_clear(void* raw) noexcept {
    return protect([&] {
        auto& context = context_on_owner_thread(raw);
        if (context.presenter) {
            context.presenter->clear();
        }
    });
}

HRESULT sunpack_toast_destroy(void* raw) noexcept {
    return protect([&] { delete &context_on_owner_thread(raw); });
}

HRESULT sunpack_toast_activate() noexcept {
    return protect([] {
        WinrtApartmentScope apartment;
        {
            std::lock_guard lock(g_activation_mutex);
            g_activated = false;
            g_cancel_batch.clear();
        }
        ActivationRegistration activation;
        std::unique_lock lock(g_activation_mutex);
        g_activation_condition.wait_for(lock, std::chrono::seconds(30), [] { return g_activated; });
    });
}

HRESULT sunpack_toast_self_test() noexcept {
    return protect([] {
        WinrtApartmentScope apartment;
        // Probe COM activation without registering the extension's live CLSID.
        CLSID probe_clsid{};
        winrt::check_hresult(CoCreateGuid(&probe_clsid));
        ActivationRegistration activation(probe_clsid);
        winrt::com_ptr<IClassFactory> factory;
        winrt::check_hresult(CoGetClassObject(probe_clsid, CLSCTX_LOCAL_SERVER, nullptr, IID_PPV_ARGS(factory.put())));
        winrt::com_ptr<INotificationActivationCallback> callback;
        winrt::check_hresult(factory->CreateInstance(nullptr, IID_PPV_ARGS(callback.put())));
        winrt::check_hresult(callback->Activate(kAppId, L"noop", nullptr, 0));
        XmlDocument document;
        document.LoadXml(L"<toast/>");
    });
}

HRESULT sunpack_toast_cancel_batch(wchar_t* target, std::uint32_t capacity) noexcept {
    return protect([&] {
        std::lock_guard lock(g_activation_mutex);
        if (!target || capacity <= g_cancel_batch.size()) winrt::throw_hresult(E_INVALIDARG);
        std::copy(g_cancel_batch.begin(), g_cancel_batch.end(), target);
        target[g_cancel_batch.size()] = L'\0';
        g_cancel_batch.clear();
    });
}
