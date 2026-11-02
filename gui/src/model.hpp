#pragma once
#include "platform.hpp"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <unordered_set>

namespace spg {
using Json = nlohmann::ordered_json;
std::wstring fold_search(const std::string& text);
Json parse_json(const std::string& text);
Json read_json(const fs::path& path);
void validate_passwords(const Json& document);
bool password_matches_scope(const Json& record, const std::string& scope);
void save_config_field(const fs::path& path, const std::string& pointer, const std::string& original,
    const std::string& type, const std::string& text, bool boolean);
// original is the exact selected record, not an index that external edits can move.
void edit_password(const fs::path& path, const std::string& operation, const Json& original,
    const Json& replacement, const std::string& scope = {});
struct WatchRoot { fs::path input; std::string output; bool deep = false; bool initial_scanned = false; bool recursive = false; };
struct WatchRoots { std::vector<WatchRoot> entries; std::vector<std::string> comments; };
WatchRoots parse_roots(const std::string& text, const fs::path& base);
WatchRoots read_roots(const fs::path& path);
void edit_root(const fs::path& path, const std::string& operation, const std::string& original,
    const std::string& input, const std::string& output, bool deep);
Json apply_password_changes(Json document, const Json& edits, Json* saved_record = nullptr);
WatchRoots apply_root_changes(WatchRoots roots, const fs::path& base, const Json& edits);
// The saved document is already parsed while validating the write; return it
// to the GUI instead of immediately re-reading and re-projecting the file.
struct PasswordSaveSnapshot { Json document; std::string file_text; Json record, rebases; bool count_changed = false; };
// Preflight every file under the existing locks, then replace each file once.
// A write failure reports completed sections so remaining drafts can be retried.
Json save_changes(const fs::path& directory, const Json& fields, const Json& passwords,
    const Json& roots, PasswordSaveSnapshot* password_snapshot = nullptr);
std::string root_for(const fs::path& path, const WatchRoots& roots);
struct Task {
    std::string path, name, status, waiting_reason;
    // Backend order and original filename spelling; one contiguous collection
    // serves alias retirement, search and display (no resident duplicate set).
    struct Member { std::wstring key; std::string filename; };
    std::vector<Member> members;
    std::string error, error_kind;
    bool multipart = false;
    double timestamp = 0;
    bool has_timestamp = false;
    uint64_t sequence = 0;
    std::vector<std::string> outputs;
    // Lazy path/time display data: validated against source values on every
    // projection, so regrouping and reused Task objects cannot show stale data.
    struct DisplayCache {
        std::string path, directory, filename;
        std::string time;
        double timestamp = 0;
        bool has_timestamp = false, time_valid = false;
    };
    mutable DisplayCache display;
};
class EventLog {
    fs::path path_;
    uint64_t sequence_ = 0;
public:
    Json manifest;
    std::function<bool()> cancelled;
    Json query(const WatchRoots& roots, const struct View& view, const std::string& language) const;
    std::unordered_map<std::wstring, Task> tasks;
    void set_path(const fs::path& path);
    bool refresh(bool missing_is_final = false);
    void accept(const Json& event);
    const fs::path& path() const { return path_; }
};
struct View {
    std::string task_query, task_root, task_status, password_query, password_scope = "@all";
    std::string task_cursor;
};
struct TaskProjectionStats {
    double filter_ms = 0, sort_ms = 0, project_ms = 0;
    size_t selected = 0;
    bool reused = false;
};
// When previous_ids matches the newly selected and sorted IDs, returning null
// means the caller can keep its existing full UI state; only use when the
// underlying tasks, watch roots and language have NOT changed.
Json task_rows(const EventLog& log, const WatchRoots& roots, const View& view,
    const std::string& language = "zh",
    std::vector<std::wstring>* selected_ids = nullptr,
    const std::vector<std::wstring>* previous_ids = nullptr,
    TaskProjectionStats* stats = nullptr);
// Resolve only on activation so removed/moved output directories fall back then.
fs::path task_directory(const Json& row);
Json password_rows(const Json& passwords, const View& view, const std::string& language = "zh");
Json config_fields(const Json& config, const std::string& source, const std::string& language = "zh");
Json directory_rows(const WatchRoots& roots, const Json& config);
fs::path log_directory(const fs::path& data_dir, const Json& config);
}
