#pragma once
#include "model.hpp"
#include "date_popup.hpp"
#include <ui_core.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <atomic>
#include <map>

namespace spg {
struct Options {
    fs::path data_dir;
    CliCommand cli;
    bool allow_cli = true;
};
class Application {
    Options options_;
    UiPage page_ = 0;
    UiWindow window_ = 0;
    HWND hwnd_ = nullptr;
    HICON large_icon_ = nullptr, small_icon_ = nullptr;
    void update_icons(UINT dpi);
    Handle stop_{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle service_refresh_{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Json> commands_;
    Json pending_ = Json::object();
    bool notified_ = false, stopping_ = false, choosing_directory_ = false, shown_ = false;
    bool task_range_pending_ = false;
    void schedule_task_range();
    unsigned dirty_ = 15;
    std::atomic<uint64_t> task_query_generation_{0};
    std::thread worker_, registry_;
    struct ControlBinding { Application* owner; Json field; };
    std::map<std::string,std::unique_ptr<ControlBinding>> controls_;
    UiWidget theme_widget_ = 0;
    UiWidget status_widget_ = 0;
    void bind_controls(const Json& fields);
    void sync_toggles();
    void sync_tags(const std::string& id = {});
    void rebuild_theme(const std::string& language);
    void navigate(const std::string& tab);
    void work();
    void publish(Json patch);
    void changed(unsigned flags);
    void dispatch();
    void handle_command(Json command);
    void apply_pending();
    void reveal();
    // UI-thread queue: one write in flight, latest completed edit per key.
    std::deque<Json> saves_;
    Json active_save_;
    std::unique_ptr<DatePopup> date_popup_;
    UINT_PTR date_generation_ = 0;
    void finish_date_popup(UINT_PTR generation);
    bool field_pending(const std::string& id) const;
    void save_field(const std::string& id, Json draft = Json());
    void queue_save(Json job);
    void start_save();
    void acknowledge_save(const Json& ack);
    void save_error(const std::string& key, const std::string& message);
    void set_error(const char* field, const std::string& message);
    void refresh_error_texts();
    static LRESULT CALLBACK subclass(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
public:
    explicit Application(Options options) : options_(std::move(options)) {}
    ~Application();
    void open();
    int run();
    UiPage page() const { return page_; }
    UiWindow window() const { return window_; }
};
Options parse_options(const std::vector<std::wstring>& args);
}
