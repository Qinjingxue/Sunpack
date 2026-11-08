#pragma once
#include "platform.hpp"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <unordered_set>

namespace spg {
using Json = nlohmann::ordered_json;
std::wstring fold_search(const std::string& text);
std::string task_time(double timestamp);
// Empty means the query cannot occur in the displayed local timestamp.
std::string task_time_query(const std::wstring& query);
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
class EventLog {
    fs::path path_;
public:
    Json manifest;
    std::function<bool()> cancelled;
    Json query(const WatchRoots& roots, const struct View& view, const std::string& language = "zh") const;
    void set_path(const fs::path& path);
    bool refresh(bool missing_is_final = false);
    const fs::path& path() const { return path_; }
};
struct View {
    std::string task_query, task_root, task_status, password_query, password_scope = "@all";
    std::string task_cursor;
};
// Resolve only on activation so removed/moved output directories fall back then.
fs::path task_directory(const Json& row);
Json password_rows(const Json& passwords, const View& view, const std::string& language = "zh");
Json config_fields(const Json& config, const std::string& source, const std::string& language = "zh");
Json directory_rows(const WatchRoots& roots, const Json& config);
fs::path log_directory(const fs::path& data_dir);
}
