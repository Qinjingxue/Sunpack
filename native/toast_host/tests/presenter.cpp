// Snapshot/ABI tests never exercise the native presenter's banner lifecycle.
// Run the real presenter against an in-memory Windows notification surface:
// this catches queued completion, stale controls and deleted final history
// in one lifecycle without desktop notifications, polling or timing limits.
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.UI.Notifications.h>
#include <map>
#include <stdexcept>
#include <string>

namespace toast_test {
using namespace winrt::Windows::UI::Notifications;
using Key = std::pair<std::wstring, std::wstring>;
std::map<Key, ToastNotification> history;
ToastNotification banner{nullptr};
unsigned shows = 0;
unsigned hides = 0;

void require(bool condition) {
    if (!condition) throw std::runtime_error("Toast presenter lifecycle regression");
}

Key key(const ToastNotification& toast) {
    return {std::wstring(toast.Tag()), std::wstring(toast.Group())};
}
}

// Substitute only the OS presentation boundary. All production snapshot,
// XML, action and presenter code below is compiled unchanged.
namespace winrt::Windows::UI::Notifications {
struct TestToastNotifier {
    TestToastNotifier(std::nullptr_t = nullptr) {}

    void Show(const ToastNotification& toast) const {
        toast_test::history.insert_or_assign(toast_test::key(toast), toast);
        ++toast_test::shows;
        if (!toast.SuppressPopup()) {
            // A separate popup would be queued behind an existing banner.
            toast_test::require(!toast_test::banner);
            toast_test::banner = toast;
        }
    }

    void Hide(const ToastNotification& toast) const {
        ++toast_test::hides;
        if (toast == toast_test::banner) toast_test::banner = nullptr;
    }

    NotificationUpdateResult Update(const NotificationData& data, std::wstring_view tag, std::wstring_view group) const {
        const auto found = toast_test::history.find({std::wstring(tag), std::wstring(group)});
        if (found == toast_test::history.end()) return NotificationUpdateResult::NotificationNotFound;
        found->second.Data(data);
        return NotificationUpdateResult::Succeeded;
    }
};

struct TestToastHistory {
    void Remove(std::wstring_view tag, std::wstring_view group, std::wstring_view) const {
        // History removal deliberately does not dismiss the visible banner.
        toast_test::history.erase({std::wstring(tag), std::wstring(group)});
    }
};

struct TestToastNotificationManager {
    static TestToastNotifier CreateToastNotifier(std::wstring_view) { return {}; }
    static TestToastHistory History() { return {}; }
};
}

#define ToastNotifier TestToastNotifier
#define ToastNotificationManager TestToastNotificationManager
#include "../src/main.cpp"
#undef ToastNotificationManager
#undef ToastNotifier

int main() {
    try {
        WinrtApartmentScope apartment;
        Snapshot snapshot;
        snapshot.kind = SnapshotKind::progress;
        snapshot.batch_id = L"first";
        snapshot.title = L"Extracting";
        snapshot.progress_mode = ProgressMode::determinate;
        snapshot.actions.push_back({ActionKind::cancel_batch, L"Stop", L"first"});
        {
            ToastPresenter presenter(nullptr);
            presenter.show(snapshot, 1);
            const auto original = toast_test::banner;
            snapshot.progress_value = 0.5;
            presenter.show(snapshot, 2);
            toast_test::require(toast_test::banner == original && toast_test::shows == 1 && toast_test::hides == 0);

            // Stop removes controls; a concurrent new arrival restores them.
            snapshot.actions.clear();
            presenter.show(snapshot, 3);
            toast_test::require(toast_test::banner != original);
            toast_test::require(toast_test::banner.Content().GetElementsByTagName(L"action").Length() == 0);
            snapshot.actions.push_back({ActionKind::cancel_batch, L"Stop", L"first"});
            presenter.show(snapshot, 4);
            toast_test::require(toast_test::banner.Content().GetElementsByTagName(L"action").Length() == 1);

            // Draining removes Stop before the debounce publishes completion.
            snapshot.actions.clear();
            snapshot.progress_value = 1;
            presenter.show(snapshot, 5);
            snapshot.kind = SnapshotKind::success;
            presenter.show(snapshot, 6);
            toast_test::require(toast_test::banner.Tag() == L"first-f");
            toast_test::require(!toast_test::history.contains({L"first-p", kToastGroup}));
            presenter.clear();
            toast_test::require(toast_test::history.contains({L"first-f", kToastGroup}));

            // Windows dismisses the final banner; its history survives batches.
            toast_test::banner = nullptr;
            snapshot.kind = SnapshotKind::progress;
            snapshot.batch_id = L"second";
            presenter.show(snapshot, 7);
            snapshot.batch_id = L"third";
            presenter.show(snapshot, 8);
            toast_test::require(!toast_test::history.contains({L"second-p", kToastGroup}));
            // User dismissal makes Update fail: recreate a working progress UI.
            toast_test::banner = nullptr;
            toast_test::history.erase({L"third-p", kToastGroup});
            presenter.show(snapshot, 9);
            toast_test::require(toast_test::banner.Tag() == L"third-p");
        }
        toast_test::require(!toast_test::banner && toast_test::history.size() == 1);
        toast_test::require(toast_test::history.contains({L"first-f", kToastGroup}));
        toast_test::history.clear();
        return 0;
    } catch (...) {
        return 1;
    }
}
