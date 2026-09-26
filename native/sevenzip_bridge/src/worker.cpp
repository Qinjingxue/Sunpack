#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <deque>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "internal/sevenzip_status.hpp"
#include "internal/archive_operations.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/sevenzip_sdk.hpp"
#include "internal/native_memory_guard.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/native_worker_sizing.hpp"
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
#include "internal/worker_pipeline_timing.hpp"
#endif
#ifdef _WIN32
#include "internal/sevenzip_async_output.hpp"
#include "internal/sevenzip_space_monitor.hpp"
#include "internal/sevenzip_volume_registry.hpp"
#endif

namespace {

bool read_file_timing_enabled() noexcept {
    static const bool enabled = [] {
        const char* value = std::getenv("SUNPACK_SEVENZIP_PROFILE_READS");
        return value && value[0] == '1';
    }();
    return enabled;
}

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const unsigned char ch : value) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                std::ostringstream escaped;
                escaped << "\\u"
                        << std::uppercase << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch);
                out += escaped.str();
            } else {
                out += static_cast<char>(ch);
            }
            break;
        }
    }
    return out;
}

std::wstring utf8_to_wide(const std::string& value) {
#ifdef _WIN32
    if (value.empty()) {
        return L"";
    }
    const int chars = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (chars <= 0) {
        return std::wstring(value.begin(), value.end());
    }
    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), wide.data(), chars);
    return wide;
#else
    return std::wstring(value.begin(), value.end());
#endif
}

std::string wide_to_utf8(const std::wstring& value) {
#ifdef _WIN32
    if (value.empty()) {
        return "";
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) {
        return "";
    }
    std::string out(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), bytes, nullptr, nullptr);
    return out;
#else
    return std::string(value.begin(), value.end());
#endif
}

std::size_t skip_ws(std::string_view json, std::size_t pos) {
    while (pos < json.size() && static_cast<unsigned char>(json[pos]) <= 0x20) {
        ++pos;
    }
    return pos;
}

std::size_t json_string_end(std::string_view json, std::size_t quote_pos) {
    if (quote_pos >= json.size() || json[quote_pos] != '"') {
        return quote_pos;
    }
    bool escaped = false;
    for (std::size_t pos = quote_pos + 1; pos < json.size(); ++pos) {
        const char ch = json[pos];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            return pos + 1;
        }
    }
    return json.size();
}

std::size_t json_composite_end(std::string_view json, std::size_t start) {
    int object_depth = 0;
    int array_depth = 0;
    for (std::size_t pos = start; pos < json.size();) {
        const char ch = json[pos];
        if (ch == '"') {
            pos = json_string_end(json, pos);
            continue;
        }
        if (ch == '{') {
            ++object_depth;
        } else if (ch == '}') {
            --object_depth;
        } else if (ch == '[') {
            ++array_depth;
        } else if (ch == ']') {
            --array_depth;
        }
        ++pos;
        if (object_depth == 0 && array_depth == 0) {
            return pos;
        }
    }
    return json.size();
}

std::size_t json_value_end(std::string_view json, std::size_t start) {
    start = skip_ws(json, start);
    if (start >= json.size()) {
        return start;
    }
    if (json[start] == '"') {
        return json_string_end(json, start);
    }
    if (json[start] == '{' || json[start] == '[') {
        return json_composite_end(json, start);
    }
    std::size_t pos = start;
    while (pos < json.size()) {
        const char ch = json[pos];
        if (ch == ',' || ch == '}' || ch == ']' || static_cast<unsigned char>(ch) <= 0x20) {
            break;
        }
        ++pos;
    }
    return pos;
}

std::string decode_json_string(std::string_view token) {
    if (token.size() < 2 || token.front() != '"' || token.back() != '"') {
        return {};
    }
    std::string out;
    out.reserve(token.size() - 2);
    for (std::size_t pos = 1; pos + 1 < token.size(); ++pos) {
        const char ch = token[pos];
        if (ch != '\\' || pos + 2 >= token.size()) {
            out.push_back(ch);
            continue;
        }
        const char escaped = token[++pos];
        switch (escaped) {
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        default:
            // Python sends worker requests with ensure_ascii=False. Preserve the
            // previous protocol behaviour for uncommon escape forms instead of
            // adding a second general-purpose JSON decoder here.
            out.push_back(escaped);
            break;
        }
    }
    return out;
}

std::vector<std::string_view> json_array_values(std::string_view array_json) {
    std::vector<std::string_view> values;
    std::size_t pos = skip_ws(array_json, 0);
    if (pos >= array_json.size() || array_json[pos] != '[') {
        return values;
    }
    ++pos;
    while (pos < array_json.size()) {
        pos = skip_ws(array_json, pos);
        if (pos >= array_json.size() || array_json[pos] == ']') {
            break;
        }
        const std::size_t end = json_value_end(array_json, pos);
        if (end <= pos) {
            break;
        }
        values.push_back(array_json.substr(pos, end - pos));
        pos = skip_ws(array_json, end);
        if (pos < array_json.size() && array_json[pos] == ',') {
            ++pos;
        } else if (pos < array_json.size() && array_json[pos] != ']') {
            break;
        }
    }
    return values;
}

class JsonObjectView {
public:
    JsonObjectView() = default;

    explicit JsonObjectView(std::string_view json) {
        reset(json);
    }

    bool valid() const noexcept {
        return valid_;
    }

    std::string string_field(
        std::string_view key,
        std::string_view fallback = {}
    ) const {
        const auto value = raw_field(key);
        if (!value || value->size() < 2 || value->front() != '"') {
            return std::string(fallback);
        }
        return decode_json_string(*value);
    }

    bool uint_field(std::string_view key, unsigned long long* value) const {
        const auto raw = raw_field(key);
        if (!raw) {
            return false;
        }
        std::size_t pos = skip_ws(*raw, 0);
        unsigned long long parsed = 0;
        bool any = false;
        while (pos < raw->size() && (*raw)[pos] >= '0' && (*raw)[pos] <= '9') {
            any = true;
            parsed = parsed * 10 + static_cast<unsigned long long>((*raw)[pos] - '0');
            ++pos;
        }
        if (any && value) {
            *value = parsed;
        }
        return any;
    }

    bool bool_field(std::string_view key, bool fallback = false) const {
        const auto raw = raw_field(key);
        if (!raw) {
            return fallback;
        }
        const std::size_t pos = skip_ws(*raw, 0);
        if (raw->substr(pos, 4) == "true") {
            return true;
        }
        if (raw->substr(pos, 5) == "false") {
            return false;
        }
        if (pos < raw->size() && (*raw)[pos] == '"') {
            const std::string text = decode_json_string(raw->substr(pos));
            return text == "true" || text == "1" || text == "yes";
        }
        return fallback;
    }

    JsonObjectView object_field(std::string_view key) const {
        const auto raw = raw_field(key);
        if (!raw) {
            return {};
        }
        const std::size_t pos = skip_ws(*raw, 0);
        if (pos >= raw->size() || (*raw)[pos] != '{') {
            return {};
        }
        return JsonObjectView(raw->substr(pos));
    }

    std::vector<std::string> string_array_field(std::string_view key) const {
        std::vector<std::string> values;
        const auto raw = raw_field(key);
        if (!raw) {
            return values;
        }
        for (const auto item : json_array_values(*raw)) {
            if (item.size() >= 2 && item.front() == '"' && item.back() == '"') {
                values.push_back(decode_json_string(item));
            }
        }
        return values;
    }

    std::vector<std::string_view> object_array_field(std::string_view key) const {
        std::vector<std::string_view> values;
        const auto raw = raw_field(key);
        if (!raw) {
            return values;
        }
        for (const auto item : json_array_values(*raw)) {
            if (!item.empty() && item.front() == '{') {
                values.push_back(item);
            }
        }
        return values;
    }

private:
    struct Field {
        std::string_view key;
        std::string_view value;
    };

    void reset(std::string_view json) {
        source_ = json;
        fields_.clear();
        valid_ = false;

        std::size_t pos = skip_ws(source_, 0);
        if (pos >= source_.size() || source_[pos] != '{') {
            return;
        }
        ++pos;
        while (pos < source_.size()) {
            pos = skip_ws(source_, pos);
            if (pos < source_.size() && source_[pos] == '}') {
                valid_ = true;
                return;
            }
            if (pos >= source_.size() || source_[pos] != '"') {
                return;
            }
            const std::size_t key_end = json_string_end(source_, pos);
            if (key_end <= pos + 1 || key_end > source_.size()) {
                return;
            }
            const std::string_view key = source_.substr(pos + 1, key_end - pos - 2);
            pos = skip_ws(source_, key_end);
            if (pos >= source_.size() || source_[pos] != ':') {
                return;
            }
            pos = skip_ws(source_, pos + 1);
            const std::size_t value_end = json_value_end(source_, pos);
            if (value_end <= pos) {
                return;
            }
            fields_.push_back(Field{key, source_.substr(pos, value_end - pos)});
            pos = skip_ws(source_, value_end);
            if (pos < source_.size() && source_[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < source_.size() && source_[pos] == '}') {
                valid_ = true;
                return;
            }
            return;
        }
    }

    std::optional<std::string_view> raw_field(std::string_view key) const {
        for (const auto& field : fields_) {
            if (field.key == key) {
                return field.value;
            }
        }
        return std::nullopt;
    }

    std::string_view source_;
    std::vector<Field> fields_;
    bool valid_ = false;
};

struct WorkerArchiveInput {
    std::wstring archive_path;
    std::wstring format_hint;
    std::wstring open_mode;
    std::vector<std::wstring> part_paths;
    std::vector<std::wstring> canonical_names;
    std::vector<int> volume_numbers;
    std::string analyzed_missing_volume_evidence;
    std::string validation_error;
    std::vector<sunpack::sevenzip::ExtractInputRange> ranges;
};

sunpack::sevenzip::PasswordTestResult run_password_candidate_probe(
    const WorkerArchiveInput& archive_input,
    const std::vector<std::wstring>& candidates
) {
    using namespace sunpack::sevenzip;
    std::vector<const wchar_t*> password_ptrs;
    password_ptrs.reserve(candidates.size());
    for (const auto& password : candidates) {
        password_ptrs.push_back(password.c_str());
    }
    if (!archive_input.ranges.empty()) {
        return test_passwords_with_ranges(
            archive_input.archive_path,
            archive_input.ranges,
            archive_input.format_hint,
            password_ptrs.data(),
            static_cast<int>(password_ptrs.size()));
    }
    return test_passwords_with_parts(
        archive_input.archive_path,
        archive_input.part_paths,
        password_ptrs.data(),
        static_cast<int>(password_ptrs.size()),
        archive_input.canonical_names,
        archive_input.format_hint);
}

sunpack::sevenzip::ExtractArchiveResult password_candidate_failure(
    const WorkerArchiveInput& archive_input,
    const sunpack::sevenzip::PasswordTestResult& probe,
    std::size_t candidate_count
) {
    using namespace sunpack::sevenzip;
    ExtractArchiveResult result;
    result.status = probe.status;
    result.backend_available = probe.backend_available;
    result.archive_type = probe.archive_type.empty()
        ? archive_type_for_path(archive_input.archive_path)
        : probe.archive_type;
    result.password_candidate_batch = true;
    result.password_candidate_count = static_cast<unsigned int>(candidate_count);
    result.password_attempts = probe.attempts;
    result.matched_index = probe.matched_index;
    result.password_candidates_all_rejected = probe.status == PasswordTestStatus::WrongPassword;
    result.encrypted = probe.status == PasswordTestStatus::WrongPassword;
    result.wrong_password = probe.status == PasswordTestStatus::WrongPassword;
    result.password_rejected = result.wrong_password;
    result.damaged = probe.status == PasswordTestStatus::Damaged;
    result.missing_volume = probe.status == PasswordTestStatus::NeedsVolumeOrTailDamaged;
    result.unsupported_method = probe.status == PasswordTestStatus::Unsupported;
    result.failure_stage = "password_probe";
    switch (probe.status) {
    case PasswordTestStatus::WrongPassword:
        result.failure_kind = "wrong_password";
        result.operation_result = kOpWrongPassword;
        break;
    case PasswordTestStatus::Damaged:
        result.failure_kind = "data_error";
        result.operation_result = kOpDataError;
        break;
    case PasswordTestStatus::NeedsVolumeOrTailDamaged:
        result.failure_kind = "missing_volume_or_tail";
        break;
    case PasswordTestStatus::Unsupported:
        result.failure_kind = "unsupported_method";
        break;
    case PasswordTestStatus::BackendUnavailable:
        result.failure_kind = "backend_unavailable";
        break;
    default:
        result.failure_kind = "password_probe";
        break;
    }
    result.message = probe.message;
    return result;
}

std::vector<sunpack::sevenzip::ExtractInputRange> parse_input_ranges(
    const JsonObjectView& request,
    const std::string& archive_path
) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    const std::string kind = request.string_field("kind", "file");
    if (kind == "file_range") {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start =
            request.uint_field("start", &start) ||
            request.uint_field("start_offset", &start);
        const bool has_end =
            request.uint_field("end", &end) ||
            request.uint_field("end_offset", &end);
        const std::string path = request.string_field("path", archive_path);
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? archive_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
        return ranges;
    }
    if (kind != "concat_ranges") {
        return ranges;
    }
    for (const auto object_json : request.object_array_field("ranges")) {
        const JsonObjectView object(object_json);
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start =
            object.uint_field("start", &start) ||
            object.uint_field("start_offset", &start);
        const bool has_end =
            object.uint_field("end", &end) ||
            object.uint_field("end_offset", &end);
        const std::string path = object.string_field("path", archive_path);
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? archive_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
    }
    return ranges;
}

std::vector<sunpack::sevenzip::ExtractInputRange> parse_ranges_from_objects(
    const std::vector<std::string_view>& objects,
    const std::string& default_path
) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    ranges.reserve(objects.size());
    for (const auto object_json : objects) {
        const JsonObjectView object(object_json);
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start =
            object.uint_field("start", &start) ||
            object.uint_field("start_offset", &start);
        const bool has_end =
            object.uint_field("end", &end) ||
            object.uint_field("end_offset", &end);
        const std::string path = object.string_field("path", default_path);
        if (path.empty() && default_path.empty()) {
            continue;
        }
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? default_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
    }
    return ranges;
}

WorkerArchiveInput parse_archive_input_descriptor(
    const JsonObjectView& request,
    const std::wstring& fallback_archive_path,
    const std::wstring& fallback_format_hint,
    const std::vector<std::wstring>& fallback_part_paths
) {
    WorkerArchiveInput input;
    input.archive_path = fallback_archive_path;
    input.format_hint = fallback_format_hint;
    input.open_mode = L"file";
    input.part_paths = fallback_part_paths;

    const JsonObjectView descriptor = request.object_field("archive_input");
    if (!descriptor.valid()) {
        const std::string archive_path = request.string_field("archive_path", "");
        input.ranges = parse_input_ranges(request, archive_path);
        if (!input.ranges.empty()) {
            input.open_mode = utf8_to_wide(request.string_field("kind", "concat_ranges"));
        }
        return input;
    }

    const std::string request_archive_path = request.string_field("archive_path", "");
    const std::string entry_path = descriptor.string_field("entry_path", request_archive_path);
    if (!entry_path.empty()) {
        input.archive_path = utf8_to_wide(entry_path);
    }
    const std::string mode = descriptor.string_field(
        "open_mode",
        descriptor.string_field("kind", "file")
    );
    input.open_mode = utf8_to_wide(mode.empty() ? "file" : mode);
    const std::string format_hint = descriptor.string_field(
        "format_hint",
        request.string_field("format_hint", "")
    );
    input.format_hint = utf8_to_wide(format_hint);

    const JsonObjectView analysis = descriptor.object_field("analysis");
    const JsonObjectView execution_analysis = analysis.object_field("execution");
    input.analyzed_missing_volume_evidence =
        execution_analysis.string_field("missing_volume_evidence", "");

    struct ParsedPart {
        int number;
        std::wstring path;
        std::wstring canonical_name;
        unsigned long long start = 0;
        bool has_start = false;
    };
    const auto part_objects = descriptor.object_array_field("parts");
    std::vector<ParsedPart> structured_parts;
    std::vector<std::wstring> parts;
    parts.reserve(part_objects.size());
    for (const auto object_json : part_objects) {
        const JsonObjectView object(object_json);
        const std::string path = object.string_field("path", "");
        if (!path.empty()) {
            parts.push_back(utf8_to_wide(path));
            unsigned long long number = 0;
            const std::string canonical_name = object.string_field("canonical_name", "");
            if (mode == "native_volumes" || mode == "sfx_with_volumes") {
                if (!object.uint_field("volume_number", &number) || number == 0 || canonical_name.empty()) {
                    input.validation_error = "structured volume part requires volume_number and canonical_name";
                } else {
                    unsigned long long start = 0;
                    const bool has_start =
                        object.uint_field("start", &start) ||
                        object.uint_field("start_offset", &start);
                    structured_parts.push_back({
                        static_cast<int>(number),
                        utf8_to_wide(path),
                        utf8_to_wide(canonical_name),
                        start,
                        has_start,
                    });
                }
            }
        }
    }
    if (mode == "native_volumes" || mode == "sfx_with_volumes") {
        std::sort(structured_parts.begin(), structured_parts.end(), [](const ParsedPart& left, const ParsedPart& right) {
            return left.number < right.number;
        });
        parts.clear();
        for (std::size_t index = 0; index < structured_parts.size(); ++index) {
            if (structured_parts[index].number != static_cast<int>(index + 1)) {
                input.validation_error = "structured volume sequence must be contiguous and start at 1";
                break;
            }
            parts.push_back(structured_parts[index].path);
            input.canonical_names.push_back(structured_parts[index].canonical_name);
            input.volume_numbers.push_back(structured_parts[index].number);
        }
        if (parts.empty()) {
            input.validation_error = "structured volume descriptor has no parts";
        }
    }
    if (!parts.empty()) {
        input.part_paths = parts;
    }

    if (mode == "file_range") {
        input.ranges = parse_ranges_from_objects(part_objects, entry_path);
        if (input.ranges.empty()) {
            input.validation_error = "file_range descriptor requires canonical parts with extents";
        }
    } else if (mode == "concat_ranges") {
        const auto range_objects = descriptor.object_array_field("ranges");
        input.ranges = parse_ranges_from_objects(range_objects, entry_path);
        if (input.ranges.empty()) {
            input.ranges = parse_ranges_from_objects(part_objects, entry_path);
        }
    }
    return input;
}

struct WorkerRequest {
    std::string worker_command;
    std::string job_id;
    std::string request_id;
    std::string origin = "foreground";
    std::string output_volume_key;
    std::string process_mode = "normal";
    std::wstring archive_path;
    std::wstring output_dir;
    std::wstring password;
    std::wstring format_hint;
    std::wstring codepage;
    bool dry_run = false;
    unsigned long long job_buffer_budget = 0;
    std::vector<std::wstring> password_candidates;
    std::vector<std::wstring> part_paths;
    WorkerArchiveInput archive_input;
};

WorkerRequest parse_worker_request(const std::string& request_json) {
    const JsonObjectView json(request_json);
    WorkerRequest request;
    request.worker_command = json.string_field("worker_command", "");
    request.job_id = json.string_field("job_id", "");
    request.request_id = json.string_field("request_id", "");
    request.origin = json.string_field("origin", "foreground");
    request.output_volume_key = json.string_field("output_volume_key", "");
    request.process_mode = json.string_field("mode", "normal");

    if (
        request.worker_command == "cancel" ||
        request.worker_command == "set_process_mode" ||
        request.worker_command == "shutdown"
    ) {
        return request;
    }

    request.archive_path = utf8_to_wide(json.string_field("archive_path", ""));
    request.output_dir = utf8_to_wide(json.string_field("output_dir", ""));
    request.password = utf8_to_wide(json.string_field("password", ""));
    request.format_hint = utf8_to_wide(json.string_field("format_hint", ""));
    request.codepage = utf8_to_wide(json.string_field("codepage", ""));
    request.dry_run = json.bool_field("dry_run", false);
    json.uint_field("job_buffer_budget_bytes", &request.job_buffer_budget);

    for (const auto& candidate : json.string_array_field("password_candidates")) {
        request.password_candidates.push_back(utf8_to_wide(candidate));
    }
    for (const auto& part : json.string_array_field("part_paths")) {
        request.part_paths.push_back(utf8_to_wide(part));
    }
    request.archive_input = parse_archive_input_descriptor(
        json,
        request.archive_path,
        request.format_hint,
        request.part_paths
    );
    return request;
}

std::mutex g_output_mutex;

void print_json_line(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    std::cout << json << "\n";
    std::cout.flush();
}

void print_json_lines(
    const std::string& first,
    const std::string& second
) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    std::cout << first << "\n" << second << "\n";
    std::cout.flush();
}

std::string status_to_string(sunpack::sevenzip::PasswordTestStatus status) {
    return sunpack::sevenzip::status_name(status);
}

std::string hresult_hex(int value) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
           << static_cast<unsigned int>(value);
    return stream.str();
}

std::string bytes_hex(const std::vector<unsigned char>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const unsigned char value : bytes) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

std::string input_trace_json(const sunpack::sevenzip::ExtractInputTrace& trace) {
    return std::string("{") +
        "\"mode\":\"" + json_escape(wide_to_utf8(trace.mode)) +
        "\",\"virtual_size\":" + std::to_string(trace.virtual_size) +
        ",\"position\":" + std::to_string(trace.position) +
        ",\"max_position_seen\":" + std::to_string(trace.max_position_seen) +
        ",\"total_bytes_returned\":" + std::to_string(trace.total_bytes_returned) +
        ",\"read_file_call_count\":" + std::to_string(trace.read_file_call_count) +
        ",\"read_file_wall_ns\":" + std::to_string(trace.read_file_wall_ns) +
        ",\"read_file_max_wall_ns\":" + std::to_string(trace.read_file_max_wall_ns) +
        ",\"logical_read_call_count\":" + std::to_string(trace.logical_read_call_count) +
        ",\"sequential_read_bytes\":" + std::to_string(trace.sequential_read_bytes) +
        ",\"nonsequential_read_bytes\":" + std::to_string(trace.nonsequential_read_bytes) +
        ",\"sequential_run_count\":" + std::to_string(trace.sequential_run_count) +
        ",\"max_sequential_run_bytes\":" + std::to_string(trace.max_sequential_run_bytes) +
        ",\"seek_count\":" + std::to_string(trace.seek_count) +
        ",\"seek_forward_bytes\":" + std::to_string(trace.seek_forward_bytes) +
        ",\"seek_backward_bytes\":" + std::to_string(trace.seek_backward_bytes) +
        ",\"prefetch_enabled\":" + std::string(trace.prefetch_enabled ? "true" : "false") +
        ",\"prefetch_hit_count\":" + std::to_string(trace.prefetch_hit_count) +
        ",\"prefetch_miss_count\":" + std::to_string(trace.prefetch_miss_count) +
        ",\"prefetch_invalidation_count\":" + std::to_string(trace.prefetch_invalidation_count) +
        ",\"prefetch_consumer_wait_ns\":" + std::to_string(trace.prefetch_consumer_wait_ns) +
        ",\"read_error\":" + std::string(trace.read_error ? "true" : "false") +
        ",\"last_hresult\":" + std::to_string(trace.last_hresult) +
        ",\"last_hresult_hex\":\"" + hresult_hex(trace.last_hresult) +
        "\",\"last_win32_error\":" + std::to_string(trace.last_win32_error) +
        ",\"last_read\":{\"virtual_offset\":" + std::to_string(trace.last_read_virtual_offset) +
        ",\"source_path\":\"" + json_escape(wide_to_utf8(trace.last_source_path)) +
        "\",\"source_offset\":" + std::to_string(trace.last_read_source_offset) +
        ",\"range_index\":" + std::to_string(trace.last_range_index) +
        ",\"requested\":" + std::to_string(trace.last_read_requested) +
        ",\"returned\":" + std::to_string(trace.last_read_returned) +
        "},\"last_seek\":{\"origin\":" + std::to_string(trace.last_seek_origin) +
        ",\"offset\":" + std::to_string(trace.last_seek_offset) +
        ",\"new_position\":" + std::to_string(trace.last_seek_new_position) +
        "}}";
}

std::string output_item_traces_json(const std::vector<sunpack::sevenzip::ExtractOutputItemTrace>& items) {
    std::string out = "[";
    for (std::size_t index = 0; index < items.size(); ++index) {
        const auto& item = items[index];
        if (index) {
            out += ",";
        }
        out += "{\"index\":" + std::to_string(item.index) +
            ",\"path\":\"" + json_escape(wide_to_utf8(item.path)) +
            "\",\"output_path\":\"" + json_escape(wide_to_utf8(item.output_path)) +
            "\",\"is_dir\":" + std::string(item.is_dir ? "true" : "false") +
            ",\"encrypted\":" + std::string(item.encrypted ? "true" : "false") +
            ",\"bytes_written\":" + std::to_string(item.bytes_written) +
            ",\"expected_size\":" + std::to_string(item.expected_size) +
            ",\"has_expected_size\":" + std::string(item.has_expected_size ? "true" : "false") +
            ",\"source_crc32\":" + std::to_string(item.source_crc32) +
            ",\"has_source_crc32\":" + std::string(item.has_source_crc32 ? "true" : "false") +
            ",\"output_crc32\":" + std::to_string(item.output_crc32) +
            ",\"has_output_crc32\":" + std::string(item.has_output_crc32 ? "true" : "false") +
            ",\"crc_verified\":" + std::string(item.crc_verified ? "true" : "false") +
            ",\"operation_result\":" + std::to_string(item.operation_result) +
            ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(item.operation_result)) +
            "\",\"hresult\":" + std::to_string(item.hresult) +
            ",\"hresult_hex\":\"" + hresult_hex(item.hresult) +
            "\",\"win32_error\":" + std::to_string(item.win32_error) +
            ",\"done\":" + std::string(item.done ? "true" : "false") +
            ",\"failed\":" + std::string(item.failed ? "true" : "false") +
            "}";
    }
    out += "]";
    return out;
}

std::string output_trace_json(const sunpack::sevenzip::ExtractOutputTrace& trace) {
    return std::string("{") +
        "\"total_bytes_written\":" + std::to_string(trace.total_bytes_written) +
        ",\"current_item_index\":" + std::to_string(trace.current_item_index) +
        ",\"current_item_path\":\"" + json_escape(wide_to_utf8(trace.current_item_path)) +
        "\",\"current_item_bytes_written\":" + std::to_string(trace.current_item_bytes_written) +
        ",\"last_write_size\":" + std::to_string(trace.last_write_size) +
        ",\"last_hresult\":" + std::to_string(trace.last_hresult) +
        ",\"last_hresult_hex\":\"" + hresult_hex(trace.last_hresult) +
        "\",\"last_win32_error\":" + std::to_string(trace.last_win32_error) +
        ",\"items\":" + output_item_traces_json(trace.items) +
        "}";
}

#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
std::string pipeline_timing_json(const sunpack::sevenzip::ExtractPipelineTiming& timing) {
    return std::string("{") +
        "\"pipeline_wall_ns\":" + std::to_string(timing.pipeline_wall_ns) +
        ",\"input_active_ns\":" + std::to_string(timing.input_active_ns) +
        ",\"compute_active_ns\":" + std::to_string(timing.compute_active_ns) +
        ",\"compute_cpu_ns\":" + std::to_string(timing.compute_cpu_ns) +
        ",\"output_active_ns\":" + std::to_string(timing.output_active_ns) +
        ",\"input_compute_overlap_ns\":" + std::to_string(timing.input_compute_overlap_ns) +
        ",\"input_output_overlap_ns\":" + std::to_string(timing.input_output_overlap_ns) +
        ",\"compute_output_overlap_ns\":" + std::to_string(timing.compute_output_overlap_ns) +
        ",\"all_overlap_ns\":" + std::to_string(timing.all_overlap_ns) +
        ",\"any_overlap_ns\":" + std::to_string(timing.any_overlap_ns) +
        ",\"idle_ns\":" + std::to_string(timing.idle_ns) +
        ",\"prepare_output_directory_ns\":" + std::to_string(timing.prepare_output_directory_ns) +
        ",\"prepare_format_candidates_ns\":" + std::to_string(timing.prepare_format_candidates_ns) +
         ",\"prepare_handler_create_ns\":" + std::to_string(timing.prepare_handler_create_ns) +
        ",\"prepare_stream_open_ns\":" + std::to_string(timing.prepare_stream_open_ns) +
        ",\"prepare_archive_open_ns\":" + std::to_string(timing.prepare_archive_open_ns) +
        ",\"prepare_item_probe_ns\":" + std::to_string(timing.prepare_item_probe_ns) +
        ",\"prepare_callback_setup_ns\":" + std::to_string(timing.prepare_callback_setup_ns) +
        ",\"prepare_output_finalize_ns\":" + std::to_string(timing.prepare_output_finalize_ns) +
        ",\"prepare_archive_close_ns\":" + std::to_string(timing.prepare_archive_close_ns) +
        "}";
}
#endif

std::string verified_manifest_json(const sunpack::sevenzip::ExtractArchiveResult& result, bool validated) {
    std::string rows = "[";
    rows.reserve(result.output_trace.items.size() * 96);
    bool first = true;
    unsigned int file_count = 0;
    unsigned long long total_size = 0;
    bool identity_paths = true;
    std::unordered_set<std::wstring> directories;
    for (const auto& item : result.output_trace.items) {
        const std::filesystem::path output_path(item.output_path);
        if (item.is_dir) {
            if (!item.output_path.empty()) {
                directories.insert(output_path.lexically_normal().generic_wstring());
            }
            continue;
        }
        for (auto parent = output_path.parent_path(); !parent.empty(); parent = parent.parent_path()) {
            directories.insert(parent.lexically_normal().generic_wstring());
        }
        if (!first) {
            rows += ",";
        }
        first = false;
        ++file_count;
        total_size += item.bytes_written;
        const bool identity_path =
            std::filesystem::path(item.path).lexically_normal().generic_wstring() == output_path.lexically_normal().generic_wstring();
        identity_paths = identity_paths && identity_path;
        rows += "[" + std::to_string(item.index) +
            ",\"" + json_escape(wide_to_utf8(item.path)) +
            "\",\"" + (identity_path ? std::string() : json_escape(wide_to_utf8(item.output_path))) +
            "\"," + std::to_string(item.has_expected_size ? item.expected_size : item.bytes_written) +
            "," + std::to_string(item.bytes_written) +
            "," + std::string(item.has_source_crc32 ? "1" : "0") +
            "," + std::to_string(item.source_crc32) +
            "," + std::string(item.has_output_crc32 ? "1" : "0") +
            "," + std::to_string(item.output_crc32) +
            "," + std::string(item.crc_verified ? "1" : "0") +
            "," + std::string(item.done ? "1" : item.failed ? "2" : "0") +
            "," + std::string(item.has_mtime_ns ? "1" : "0") +
            "," + std::to_string(item.mtime_ns) +
            ",\"" + bytes_hex(item.magic) + "\"]";
    }
    rows += "]";
    const bool inventory_complete = validated && result.output_inventory_complete && file_count == result.files_written;
    return std::string("{") +
        "\"version\":3,\"source\":\"sevenzip_worker_extract\"" +
        ",\"validated\":" + std::string(validated ? "true" : "false") +
        ",\"item_count\":" + std::to_string(result.item_count) +
        ",\"file_count\":" + std::to_string(file_count) +
        ",\"inventory\":[" + std::string(inventory_complete ? "1" : "0") +
        "," + std::to_string(file_count) +
        "," + std::to_string(directories.size()) +
        "," + std::to_string(total_size) +
        "," + std::string(identity_paths ? "1" : "0") + "]" +
        ",\"rows\":" + rows + "}";
}

std::string handler_attempts_json(const std::vector<sunpack::sevenzip::ExtractHandlerAttempt>& attempts) {
    std::string out = "[";
    for (std::size_t index = 0; index < attempts.size(); ++index) {
        const auto& attempt = attempts[index];
        if (index) {
            out += ",";
        }
        out += "{\"format\":\"" + json_escape(wide_to_utf8(attempt.format)) +
            "\",\"created\":" + std::string(attempt.created ? "true" : "false") +
            ",\"opened\":" + std::string(attempt.opened ? "true" : "false") +
            ",\"create_hresult\":" + std::to_string(attempt.create_hresult) +
            ",\"create_hresult_hex\":\"" + hresult_hex(attempt.create_hresult) +
            "\",\"open_hresult\":" + std::to_string(attempt.open_hresult) +
            ",\"open_hresult_hex\":\"" + hresult_hex(attempt.open_hresult) + "\"}";
    }
    out += "]";
    return out;
}

std::string failed_item_json(const sunpack::sevenzip::ExtractArchiveResult& result) {
    return std::string("{") +
        "\"index\":" + std::to_string(result.failed_item_index) +
        ",\"path\":\"" + json_escape(wide_to_utf8(result.failed_item)) +
        "\",\"bytes_written\":" + std::to_string(result.failed_item_bytes_written) +
        ",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        "\"}";
}

std::string diagnostics_json(const sunpack::sevenzip::ExtractArchiveResult& result) {
    return std::string("{") +
        "\"failure_stage\":\"" + json_escape(result.failure_stage) +
        "\",\"failure_kind\":\"" + json_escape(result.failure_kind) +
        "\",\"hresult\":" + std::to_string(result.hresult) +
        ",\"hresult_hex\":\"" + hresult_hex(result.hresult) +
        "\",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        "\",\"missing_volume_suspected\":" + std::string(result.missing_volume_suspected ? "true" : "false") +
        ",\"missing_volume_evidence\":\"" + json_escape(result.missing_volume_evidence) +
        "\",\"missing_volume_name\":\"" + json_escape(wide_to_utf8(result.missing_volume_name)) +
        "\",\"password_candidate_batch\":" + std::string(result.password_candidate_batch ? "true" : "false") +
        ",\"password_candidate_direct\":" + std::string(result.password_candidate_direct ? "true" : "false") +
        ",\"password_candidates_all_rejected\":" + std::string(result.password_candidates_all_rejected ? "true" : "false") +
        ",\"password_candidate_count\":" + std::to_string(result.password_candidate_count) +
        ",\"password_attempts\":" + std::to_string(result.password_attempts) +
        ",\"matched_index\":" + std::to_string(result.matched_index) +
        ",\"handler_attempts\":" + handler_attempts_json(result.handler_attempts) +
        ",\"input_trace\":" + input_trace_json(result.input_trace) +
        ",\"output_trace\":" + output_trace_json(result.output_trace) +
        ",\"failed_item\":" + failed_item_json(result) +
        "}";
}

}  // namespace

int run_request(
    const WorkerRequest& request,
    // The job's output-volume write facility, borrowed from the registry lease held by worker_loop; null for dry runs.
    const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& shared_writer = nullptr,
    const std::shared_ptr<std::atomic<bool>>& cancel_token = nullptr
) {
    using namespace sunpack::sevenzip;

    const std::string& job_id = request.job_id;
    const std::string& command = request.worker_command;
    if (command == "shutdown") {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"ok\",\"native_status\":\"ok\",\"message\":\"worker shutdown\"}");
        return 0;
    }
    if (cancel_token && cancel_token->load(std::memory_order_acquire)) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"failed\",\"native_status\":\"cancelled\","
            "\"failure_stage\":\"native_cancel\",\"failure_kind\":\"cancelled\","
            "\"message\":\"native job was cancelled before extraction started\"}");
        return -101;
    }

    const std::wstring& archive_path = request.archive_path;
    const std::wstring& output_dir = request.output_dir;
    const std::wstring& password = request.password;
    const std::wstring& format_hint = request.format_hint;
    const std::wstring& codepage = request.codepage;
    const bool dry_run = request.dry_run;
    const unsigned long long job_buffer_budget = request.job_buffer_budget;
    const std::vector<std::wstring>& password_candidates = request.password_candidates;
    const std::vector<std::wstring>& part_paths = request.part_paths;
    if (archive_path.empty() || (!dry_run && output_dir.empty())) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"archive_path is required; output_dir is required unless dry_run is true\"}");
        return 2;
    }

    auto last_progress_emit = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    unsigned int coalesced_progress_events = 0;
    bool extract_started = false;
    auto progress_mutex = std::make_shared<std::mutex>();
    auto *cpu_job_context = sunpack::sevenzip::current_native_cpu_job_context();
    auto progress = [job_id, last_progress_emit, coalesced_progress_events, extract_started, progress_mutex, cpu_job_context](const ExtractProgressEvent& event) mutable {
            std::lock_guard<std::mutex> lock(*progress_mutex);
            const auto now = std::chrono::steady_clock::now();
            if (!extract_started && event.completed_bytes > 0) {
                extract_started = true;
                print_json_line(
                    "{\"type\":\"progress\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"event\":\"extract_started\"" +
                    ",\"completed_bytes\":" + std::to_string(event.completed_bytes) +
                    ",\"total_bytes\":" + std::to_string(event.total_bytes) +
                    ",\"item_index\":" + std::to_string(event.item_index) +
                    ",\"item_path\":\"" + json_escape(wide_to_utf8(event.item_path)) +
                    "\",\"coalesced_events\":" + std::to_string(coalesced_progress_events) + "}");
                const auto cpu = cpu_job_context
                    ? cpu_job_context->snapshot()
                    : sunpack::sevenzip::NativeCpuJobSnapshot{};
                print_json_line(
                    "{\"type\":\"native_cpu\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"event\":\"decoder_started\"" +
                    ",\"decoder_cpu_credits\":" + std::to_string(1 + cpu.current_extra_credits) +
                    ",\"current_decoder_extra_credits\":" + std::to_string(cpu.current_extra_credits) +
                    ",\"peak_decoder_extra_credits\":" + std::to_string(cpu.peak_extra_credits) +
                    ",\"decoder_parallel\":" + std::string(cpu.current_extra_credits ? "true" : "false") +
                    "}");
            }
            const bool failure = event.event == "item_failed";
            const bool boundary = event.event == "total" ||
                (event.event == "item_start" && event.item_index == 0) ||
                (event.event == "item_done" && event.item_index % 128 == 0);
            const bool interval_elapsed = now - last_progress_emit >= std::chrono::milliseconds(100);
            if (!failure && !boundary && !interval_elapsed) {
                ++coalesced_progress_events;
                return;
            }
            print_json_line(
                "{\"type\":\"progress\",\"job_id\":\"" + json_escape(job_id) +
                "\",\"event\":\"" + json_escape(event.event) +
                "\",\"completed_bytes\":" + std::to_string(event.completed_bytes) +
                ",\"total_bytes\":" + std::to_string(event.total_bytes) +
                ",\"item_index\":" + std::to_string(event.item_index) +
                ",\"item_path\":\"" + json_escape(wide_to_utf8(event.item_path)) +
                "\",\"coalesced_events\":" + std::to_string(coalesced_progress_events) + "}");
            last_progress_emit = now;
            coalesced_progress_events = 0;
    };

    const auto& archive_input = request.archive_input;
    if (!archive_input.validation_error.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"" +
            json_escape(archive_input.validation_error) + "\"}");
        return 2;
    }
    auto extract_with_password = [&](const std::wstring& selected_password) {
        return archive_input.ranges.empty()
            ? extract_archive_with_parts(archive_input.archive_path, archive_input.part_paths, archive_input.format_hint, selected_password, output_dir, codepage, progress, dry_run, archive_input.canonical_names, archive_input.open_mode == L"native_volumes", shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token)
            : extract_archive_with_ranges(archive_input.archive_path, archive_input.ranges, archive_input.format_hint, selected_password, output_dir, codepage, progress, dry_run, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token);
    };

    ExtractArchiveResult result;
    if (password_candidates.empty()) {
        result = extract_with_password(password);
    } else if (password_candidates.size() == 1) {
        // Single candidate: extract directly; the bounded probe runs once only as a failure diagnostic to preserve the all-candidates-rejected contract.
        result = extract_with_password(password_candidates.front());
        const bool direct_ok = result.status == PasswordTestStatus::Ok && result.command_ok;
        if (!direct_ok) {
            const auto probe = run_password_candidate_probe(archive_input, password_candidates);
            result.password_attempts = probe.attempts;
            if (probe.status == PasswordTestStatus::WrongPassword) {
                result.status = PasswordTestStatus::WrongPassword;
                result.encrypted = true;
                result.wrong_password = true;
                result.password_rejected = true;
                result.password_candidates_all_rejected = true;
                result.failure_stage = "password_probe";
                result.failure_kind = "wrong_password";
                result.operation_result = kOpWrongPassword;
                result.message = probe.message;
            }
        }
        result.password_candidate_direct = true;
        result.password_candidate_count = 1;
        result.matched_index = direct_ok ? 0 : -1;
        result.password_candidates_all_rejected =
            result.password_candidates_all_rejected || result.wrong_password || result.password_rejected;
    } else {
        const auto probe = run_password_candidate_probe(archive_input, password_candidates);
        if (probe.status != PasswordTestStatus::Ok ||
            probe.matched_index < 0 ||
            static_cast<std::size_t>(probe.matched_index) >= password_candidates.size()) {
            result = password_candidate_failure(archive_input, probe, password_candidates.size());
        } else {
            result = extract_with_password(password_candidates[probe.matched_index]);
            result.password_candidate_batch = true;
            result.password_candidate_count = static_cast<unsigned int>(password_candidates.size());
            result.password_attempts = probe.attempts;
            result.matched_index = probe.matched_index;
        }
    }

    if (!archive_input.analyzed_missing_volume_evidence.empty()) {
        if (result.missing_volume && result.missing_volume_evidence.empty()) {
            result.missing_volume_evidence = archive_input.analyzed_missing_volume_evidence;
        }

        const bool execution_input_failure =
            (result.failure_stage == "archive_open" || result.failure_stage == "item_extract") &&
            !result.wrong_password &&
            !result.password_rejected &&
            !result.unsupported_method &&
            result.status != PasswordTestStatus::BackendUnavailable &&
            result.status != PasswordTestStatus::Error &&
            !(result.status == PasswordTestStatus::Ok && result.command_ok);
        if (execution_input_failure) {
            // Python already proved this split tail from the same structural
            // analysis that produced ArchiveInputDescriptor. Do not perform a
            // second native scan: execute first, then use the analysis fact only
            // to classify a real backend failure. A later-completed archive can
            // therefore still succeed.
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.missing_volume = true;
            result.missing_volume_suspected = false;
            result.missing_volume_evidence = archive_input.analyzed_missing_volume_evidence;
            result.failure_kind = "missing_volume";
            result.message = "archive split volume appears incomplete";
        }
    }

    const bool ok = result.status == PasswordTestStatus::Ok && result.command_ok;
    const std::string failure_fields = ok ? "" :
        ",\"failure_stage\":\"" + json_escape(result.failure_stage) +
        "\",\"failure_kind\":\"" + json_escape(result.failure_kind) +
        "\",\"hresult\":" + std::to_string(result.hresult) +
        ",\"hresult_hex\":\"" + hresult_hex(result.hresult) + "\"";
    const std::string diagnostic_fields = (!ok || dry_run) ?
        ",\"diagnostics\":" + diagnostics_json(result) : "";
    const std::string input_trace_field = read_file_timing_enabled() ?
        ",\"input_trace\":" + input_trace_json(result.input_trace) : "";
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
    const std::string pipeline_timing_field = pipeline_timing_enabled() ?
        ",\"pipeline_timing\":" + pipeline_timing_json(result.pipeline_timing) : "";
#endif
    print_json_line(
        "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
        "\",\"status\":\"" + std::string(ok ? "ok" : "failed") +
        "\",\"native_status\":\"" + json_escape(status_to_string(result.status)) +
        "\",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(operation_result_name(result.operation_result)) +
        "\"" +
        ",\"encrypted\":" + std::string(result.encrypted ? "true" : "false") +
        ",\"damaged\":" + std::string(result.damaged ? "true" : "false") +
        ",\"checksum_error\":" + std::string(result.checksum_error ? "true" : "false") +
        ",\"missing_volume\":" + std::string(result.missing_volume ? "true" : "false") +
        ",\"missing_volume_suspected\":" + std::string(result.missing_volume_suspected ? "true" : "false") +
        ",\"missing_volume_evidence\":\"" + json_escape(result.missing_volume_evidence) +
        "\",\"missing_volume_name\":\"" + json_escape(wide_to_utf8(result.missing_volume_name)) +
        "\",\"wrong_password\":" + std::string(result.wrong_password ? "true" : "false") +
        ",\"password_rejected\":" + std::string(result.password_rejected ? "true" : "false") +
        ",\"password_crc_proven\":" + std::string(result.password_crc_proven ? "true" : "false") +
        ",\"password_crc_proven_items\":" + std::to_string(result.password_crc_proven_items) +
        ",\"password_candidate_batch\":" + std::string(result.password_candidate_batch ? "true" : "false") +
        ",\"password_candidate_direct\":" + std::string(result.password_candidate_direct ? "true" : "false") +
        ",\"password_candidates_all_rejected\":" + std::string(result.password_candidates_all_rejected ? "true" : "false") +
        ",\"password_candidate_count\":" + std::to_string(result.password_candidate_count) +
        ",\"password_attempts\":" + std::to_string(result.password_attempts) +
        ",\"matched_index\":" + std::to_string(result.matched_index) +
        ",\"unsupported_method\":" + std::string(result.unsupported_method ? "true" : "false") +
        ",\"item_count\":" + std::to_string(result.item_count) +
        ",\"files_written\":" + std::to_string(result.files_written) +
        ",\"dirs_written\":" + std::to_string(result.dirs_written) +
        ",\"bytes_written\":" + std::to_string(result.bytes_written) +
        ",\"dry_run\":" + std::string(dry_run ? "true" : "false") +
        ",\"open_mode\":\"" + json_escape(wide_to_utf8(archive_input.open_mode)) +
        "\",\"archive_type\":\"" + json_escape(wide_to_utf8(result.archive_type)) +
        "\",\"requested_codepage\":\"" + json_escape(wide_to_utf8(result.requested_codepage)) +
        "\",\"applied_codepage\":\"" + json_escape(wide_to_utf8(result.applied_codepage)) +
        "\",\"filename_decoder\":\"" + json_escape(wide_to_utf8(result.filename_decoder)) +
        "\",\"verified_manifest\":" + verified_manifest_json(result, ok && !dry_run) +
        ",\"failed_item\":\"" + json_escape(wide_to_utf8(result.failed_item)) +
        "\",\"message\":\"" + json_escape(result.message) + "\"" +
        failure_fields + input_trace_field
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        + pipeline_timing_field
#endif
        + diagnostic_fields + "}");
    return ok ? 0 : 1;
}

std::size_t configured_native_queue_capacity() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_MAX_QUEUE_JOBS");
    if (!value || !*value) {
        return 4096;
    }
    char* end = nullptr;
    const unsigned long long configured = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return 0;
    }
    return (std::min)(static_cast<std::size_t>(configured), std::size_t{1'000'000});
}

std::size_t configured_native_size(
    const char* name,
    std::size_t fallback,
    std::size_t minimum = 1,
    std::size_t maximum = (std::numeric_limits<std::size_t>::max)()
) noexcept {
    const char* value = std::getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    char* end = nullptr;
    const unsigned long long configured = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return fallback;
    }
    const auto bounded = (std::min)(
        configured,
        static_cast<unsigned long long>(maximum));
    return (std::max)(minimum, static_cast<std::size_t>(bounded));
}

double configured_native_double(
    const char* name,
    double fallback,
    double minimum,
    double maximum
) noexcept {
    const char* value = std::getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    char* end = nullptr;
    const double configured = std::strtod(value, &end);
    if (end == value || *end != '\0' || !std::isfinite(configured)) {
        return fallback;
    }
    return (std::max)(minimum, (std::min)(maximum, configured));
}

sunpack::sevenzip::NativeMachineResources native_machine_resources() noexcept {
    sunpack::sevenzip::NativeMachineResources resources;
    const unsigned hardware = std::thread::hardware_concurrency();
    resources.logical_processors = hardware == 0 ? std::size_t{2} : hardware;
#ifdef _WIN32
    const DWORD active_processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (active_processors != 0) {
        resources.logical_processors = static_cast<std::size_t>(active_processors);
    }
#endif
    return resources;
}

std::string requested_native_process_mode() {
    const char* configured = std::getenv("SUNPACK_NATIVE_PROCESS_MODE");
    const std::string mode = configured ? std::string(configured) : "normal";
    return mode == "background" || mode == "high" ? mode : "normal";
}

sunpack::sevenzip::NativeSizingOverrides configured_native_sizing_overrides() noexcept {
    sunpack::sevenzip::NativeSizingOverrides overrides;
    overrides.thread_capacity = configured_native_size(
        "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY", 0, 0, 32);
    return overrides;
}

bool apply_native_process_mode(const std::string& mode) noexcept {
#ifdef _WIN32
    HANDLE process = GetCurrentProcess();
    if (mode == "background") {
        SetPriorityClass(process, NORMAL_PRIORITY_CLASS);
        if (SetPriorityClass(process, PROCESS_MODE_BACKGROUND_BEGIN) != 0) {
            return true;
        }
        return SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS) != 0;
    }
    SetPriorityClass(process, PROCESS_MODE_BACKGROUND_END);
    const DWORD requested = mode == "high"
        ? HIGH_PRIORITY_CLASS
        : NORMAL_PRIORITY_CLASS;
    return SetPriorityClass(process, requested) != 0;
#else
    return mode != "background";
#endif
}

sunpack::sevenzip::NativeMemoryGuardConfig configured_native_memory_guard_config() noexcept {
    sunpack::sevenzip::NativeMemoryGuardConfig config;
    config.minimum_available_ratio = configured_native_double(
        "SUNPACK_NATIVE_MIN_AVAILABLE_MEMORY_RATIO",
        config.minimum_available_ratio,
        0.01,
        0.95);
    return config;
}

class NativeJobExecutor final {
public:
    NativeJobExecutor(
        const sunpack::sevenzip::NativeSizingPlan& sizing,
        sunpack::sevenzip::NativeMemoryGuardConfig memory_guard_config
    )
        : writer_meters_(std::make_shared<sunpack::sevenzip::WriterMeters>()),
          // The sink is owned solely by the executor and the long-lived gates: AsyncFileWriter never holds or resets it.
          space_change_sink_(
              [this](const sunpack::sevenzip::VolumeSpaceTransition &transition) {
                  on_space_transition(transition);
              }),
          // One environment snapshot supplies the base config; the registry may adjust
          // threads_per_volume for a specific volume when its facility is first created.
          writer_config_(sunpack::sevenzip::configured_async_writer_config()),
          writer_registry_(std::make_shared<sunpack::sevenzip::VolumeWriterRegistry>(
              writer_meters_,
              writer_config_,
              space_change_sink_)),
          worker_count_((std::max)(std::size_t{1}, sizing.thread_capacity)),
          queue_capacity_(configured_native_queue_capacity()),
          cpu_budget_(
              worker_count_,
              &NativeJobExecutor::on_cpu_capacity_available,
              this),
          memory_guard_(
              worker_count_,
              memory_guard_config) {
        // tick() must be called with the executor mutex_ released; the monitor keeps no membership and pulls blocked volumes from the registry.
        space_monitor_ = std::make_unique<sunpack::sevenzip::VolumeSpaceMonitor>(
            sunpack::sevenzip::VolumeSpaceMonitor::Options{
                writer_config_.space_poll_interval,
                writer_config_.space_status_report_interval},
            [this] { return writer_registry_->blocked_volumes(); },
            [this](const sunpack::sevenzip::VolumeStatePtr &state,
                   std::uint64_t free_bytes,
                   std::uint64_t pending_bytes,
                   bool query_ok,
                   unsigned long query_error) {
                print_volume_space_status(state, free_bytes, pending_bytes, query_ok, query_error);
            });
        workers_.reserve(worker_count_);
        for (std::size_t index = 0; index < worker_count_; ++index) {
            workers_.emplace_back([this] { worker_loop(); });
        }
        monitor_thread_ = std::thread([this] { monitor_loop(); });
    }

    ~NativeJobExecutor() { stop(); }

    NativeJobExecutor(const NativeJobExecutor&) = delete;
    NativeJobExecutor& operator=(const NativeJobExecutor&) = delete;

    void submit(WorkerRequest request) {
        auto cancel_token = std::make_shared<std::atomic<bool>>(false);
        JobMetadata metadata = metadata_from_request(request);
        const std::string queued_event =
            metadata.job_id.empty()
                ? std::string{}
                : worker_event_json("job_queued", metadata, 0);
        const std::string job_id = metadata.job_id;
        bool rejected_for_capacity = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            if (queue_capacity_ != 0 && queued_job_count_locked() >= queue_capacity_) {
                any_job_failed_ = true;
                rejected_for_capacity = true;
            } else {
                if (!job_id.empty()) {
                    std::lock_guard<std::mutex> cancel_lock(cancel_mutex_);
                    cancel_tokens_.insert_or_assign(
                        job_id,
                        JobControl{cancel_token});
                }
                Job job{
                    std::move(request),
                    std::move(cancel_token),
                    std::move(metadata),
                };
                if (metadata.foreground) {
                    foreground_queue_.push_back(std::move(job));
                } else {
                    background_queue_.push_back(std::move(job));
                }
            }
        }

        if (rejected_for_capacity) {
            print_json_line(
                "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
                "\",\"status\":\"failed\",\"native_status\":\"backpressure\","
                "\"retryable\":true,\"failure_stage\":\"native_admission\","
                "\"failure_kind\":\"queue_capacity\",\"message\":\"native job queue is full\"}");
            print_worker_event(job_id, "job_finished", metadata);
            return;
        }

        if (!queued_event.empty()) {
            print_json_line(queued_event);
        }
        condition_.notify_one();
    }

    bool cancel(const std::string& job_id) noexcept {
        std::shared_ptr<std::atomic<bool>> token;
        std::shared_ptr<sunpack::sevenzip::AsyncFileWriter> writer_to_wake;
        {
            std::lock_guard<std::mutex> lock(cancel_mutex_);
            const auto found = cancel_tokens_.find(job_id);
            if (found == cancel_tokens_.end()) {
                return false;
            }
            token = found->second.cancel_token;
            // Locked only for this call: the token carries the cancel, the writer is just the thing to wake.
            writer_to_wake = found->second.writer.lock();
        }
        if (!token) {
            return false;
        }
        token->store(true, std::memory_order_release);
#ifdef _WIN32
        // Wake only the facility this job writes to, whose producer may be parked in that backpressure wait; a reclaimed facility leaves an expired weak_ptr.
        if (writer_to_wake) {
            writer_to_wake->wake_waiters();
        }
#endif
        // One canceled queued job needs at most one execution lane. Baton
        // passing handles any additional ready work without a wake-all storm.
        condition_.notify_one();
        return true;
    }

    bool had_job_failure() const noexcept { return any_job_failed_; }

    // Waits for the queue and all active jobs to finish; only used on the stdin EOF drain path, where the monitor and space gate must still be alive.
    void wait_for_pending_jobs_to_drain() noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        drain_condition_.wait(
            lock,
            [this] { return queues_empty_locked() && active_jobs_ == 0; });
    }

    // cancel_pending_jobs: true (explicit shutdown) cancels every unfinished job, false (stdin EOF) drains first.
    // Terminal conditions must be set before waking, otherwise a worker parked on a volume space gate never sees the stop and join blocks forever.
    void stop(bool cancel_pending_jobs = true) noexcept {
        if (!cancel_pending_jobs) {
            // Draining must not set stopping_ yet: the monitor exits on stopping_ and is the only driver of space_monitor_->tick(), so a job blocked on a full disk would never be polled again and join would hang forever.
            wait_for_pending_jobs_to_drain();
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            stopping_ = true;
        }
        if (cancel_pending_jobs) {
            std::lock_guard<std::mutex> cancel_lock(cancel_mutex_);
            for (auto& entry : cancel_tokens_) {
                if (entry.second.cancel_token) {
                    entry.second.cancel_token->store(true, std::memory_order_release);
                }
            }
        }
        {
            std::lock_guard<std::mutex> monitor_lock(monitor_mutex_);
            monitor_stopping_ = true;
            monitor_recheck_ = true;
        }
        condition_.notify_all();
        monitor_condition_.notify_all();
#ifdef _WIN32
        // Must run before join(): gate waiters would otherwise never see the terminal conditions set above. It only broadcasts and changes no gate state.
        writer_registry_->abort_all_space_gates();
#endif
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
#ifdef _WIN32
        // All leases are released by now (worker threads joined, a lease never outlives its job); the registry mutex is not held here.
        writer_registry_->shutdown();
#endif
    }

private:
    struct JobMetadata {
        std::string job_id;
        std::string request_id;
        bool foreground = true;
        // Routing key for the per-volume write facility, resolved by the caller before submission; never empty in practice.
        std::string volume_key;
        // False only for dry runs, which write nothing and need no facility, writer threads or readiness gate.
        bool requires_writer = true;

        // Lifecycle events reuse these fields four times per job. Escaping them
        // once at submission avoids repeated allocations/string walks on the
        // admission and completion hot paths.
        std::string escaped_job_id;
        std::string lifecycle_context_json;
    };

    struct Job {
        WorkerRequest request;
        std::shared_ptr<std::atomic<bool>> cancel_token;
        JobMetadata metadata;
    };

    // The writer reference is deliberately weak: a strong one would keep a facility alive past its lease and could run ~AsyncFileWriter under the executor mutex.
    struct JobControl {
        explicit JobControl(std::shared_ptr<std::atomic<bool>> token)
            : cancel_token(std::move(token)) {}

        std::shared_ptr<std::atomic<bool>> cancel_token;
        std::weak_ptr<sunpack::sevenzip::AsyncFileWriter> writer;
    };

    static JobMetadata metadata_from_request(const WorkerRequest& request) noexcept {
        JobMetadata metadata;
        metadata.job_id = request.job_id;
        metadata.request_id = request.request_id;
        if (metadata.request_id.empty()) {
            metadata.request_id = metadata.job_id;
        }
        metadata.foreground = request.origin != "watch";
        metadata.volume_key = request.output_volume_key;
        metadata.requires_writer = !request.dry_run;
        metadata.escaped_job_id = json_escape(metadata.job_id);
        metadata.lifecycle_context_json =
            ",\"request_id\":\"" + json_escape(metadata.request_id) +
            "\",\"origin\":\"" + std::string(metadata.foreground ? "foreground" : "watch") +
            "\",\"output_volume_key\":\"" + json_escape(metadata.volume_key) +
            "\",\"requires_writer\":" + std::string(metadata.requires_writer ? "true" : "false");
        return metadata;
    }

    bool queues_empty_locked() const noexcept {
        return foreground_queue_.empty() && background_queue_.empty();
    }

    std::size_t queued_job_count_locked() const noexcept {
        return foreground_queue_.size() + background_queue_.size();
    }

    Job pop_next_job_locked() {
        std::deque<Job>& selected =
            foreground_queue_.empty() ? background_queue_ : foreground_queue_;
        Job job = std::move(selected.front());
        selected.pop_front();
        return job;
    }

    static void on_cpu_capacity_available(void *context) noexcept {
        auto *self = static_cast<NativeJobExecutor *>(context);
        if (self) {
            // NativeCpuBudget calls this only on a saturated->available edge,
            // so no per-release queue hint is needed here.
            self->condition_.notify_one();
        }
    }

    void request_monitor_recheck() noexcept {
        {
            std::lock_guard<std::mutex> lock(monitor_mutex_);
            monitor_recheck_ = true;
        }
        monitor_condition_.notify_one();
    }

    std::string worker_event_json(
        const char* event,
        const JobMetadata& metadata,
        std::size_t active_jobs = 0
    ) const {
        return
            "{\"type\":\"native_event\",\"job_id\":\"" + metadata.escaped_job_id +
            "\",\"event\":\"" + event +
            "\"" + metadata.lifecycle_context_json +
            ",\"active_jobs\":" + std::to_string(active_jobs) +
            "}";
    }

    void print_worker_event(
        const std::string& job_id,
        const char* event,
        const JobMetadata& metadata,
        std::size_t active_jobs = 0
    ) const noexcept {
        if (job_id.empty()) {
            return;
        }
        print_json_line(worker_event_json(
            event, metadata, active_jobs));
    }

    void print_job_start_events(
        const Job& job,
        std::size_t active_jobs
    ) const noexcept {
        if (job.metadata.job_id.empty()) {
            return;
        }
        print_json_lines(
            worker_event_json(
                "job_admitted",
                job.metadata,
                active_jobs),
            worker_event_json(
                "job_started",
                job.metadata,
                active_jobs));
    }

    void print_active_event(
        const Job& job,
        const char* event,
        std::size_t active_jobs
    ) const noexcept {
        print_worker_event(
            job.metadata.job_id,
            event,
            job.metadata,
            active_jobs);
    }

    void print_memory_guard_event(
        const sunpack::sevenzip::NativeMemoryGuardSnapshot& snapshot
    ) const noexcept {
        const auto budget = cpu_budget_.snapshot();
        print_json_line(
            "{\"type\":\"native_memory\",\"event\":\"" +
            std::string(snapshot.under_pressure ? "budget_reduced" : "budget_restored") +
            "\",\"nominal_cpu_budget\":" + std::to_string(snapshot.nominal_cpu_budget) +
            ",\"effective_cpu_budget\":" + std::to_string(snapshot.effective_cpu_budget) +
            ",\"budget_step\":" + std::to_string(snapshot.budget_step) +
            ",\"reserved_cpu_credits\":" + std::to_string(budget.reserved_credits) +
            ",\"total_physical_bytes\":" + std::to_string(snapshot.total_physical_bytes) +
            ",\"available_physical_bytes\":" + std::to_string(snapshot.available_physical_bytes) +
            ",\"available_ratio\":" + std::to_string(snapshot.available_ratio) +
            ",\"minimum_available_ratio\":" + std::to_string(snapshot.minimum_available_ratio) +
            "}");
    }

    // Facility lifecycle, so an empty `live_facilities` count can be told apart from a volume key that never reached the writer.
    static void print_writer_facility_event(
        const char* event,
        const std::string& volume_key
    ) noexcept {
        print_json_line(
            "{\"type\":\"native_writer\",\"event\":\"" + std::string(event) +
            "\",\"volume_key\":\"" + json_escape(volume_key) + "\"}");
    }

    // Space events go out on the `progress` channel, one per affected job, with a real job_id: both dispatchers drop events whose job_id is empty or unknown.
    static const char* space_event_name(
        sunpack::sevenzip::VolumeSpaceTransition::Kind kind
    ) noexcept {
        switch (kind) {
            case sunpack::sevenzip::VolumeSpaceTransition::Kind::Blocked:
                return "space_blocked";
            case sunpack::sevenzip::VolumeSpaceTransition::Kind::Resumed:
                return "space_resumed";
            case sunpack::sevenzip::VolumeSpaceTransition::Kind::Status:
            default:
                return "space_status";
        }
    }

    static std::string space_event_payload(
        const char* event,
        const std::string& job_id,
        const std::string& volume_key,
        std::uint64_t episode_id,
        unsigned long win32_error,
        std::uint64_t free_bytes,
        std::uint64_t pending_bytes,
        double blocked_seconds,
        bool query_ok,
        unsigned long query_error
    ) {
        std::string payload =
            "{\"type\":\"progress\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"event\":\"" + event +
            "\",\"volume_key\":\"" + json_escape(volume_key) +
            "\",\"episode_id\":" + std::to_string(episode_id) +
            ",\"win32_error\":" + std::to_string(win32_error) +
            ",\"free_bytes\":" + std::to_string(free_bytes) +
            ",\"pending_bytes\":" + std::to_string(pending_bytes) +
            ",\"blocked_seconds\":" + std::to_string(blocked_seconds) +
            ",\"volume_query_ok\":" + (query_ok ? "true" : "false") +
            ",\"volume_query_error\":" + std::to_string(query_error) + "}";
        return payload;
    }

    static void print_volume_space_event(
        const sunpack::sevenzip::VolumeSpaceTransition& transition
    ) noexcept {
        const char* event = space_event_name(transition.kind);
        for (const auto& job_id : transition.job_ids) {
            print_json_line(space_event_payload(
                event,
                job_id,
                transition.volume_key,
                transition.episode_id,
                transition.win32_error,
                transition.free_bytes,
                transition.pending_bytes,
                transition.blocked_seconds,
                transition.query_ok,
                transition.query_error));
        }
    }

    void print_volume_space_status(
        const sunpack::sevenzip::VolumeStatePtr& state,
        std::uint64_t free_bytes,
        std::uint64_t pending_bytes,
        bool query_ok,
        unsigned long query_error
    ) noexcept {
        if (!state || !state->space_gate) {
            return;
        }
        // Low-frequency diagnostic (default 15s); Python's space_waiting is driven only by space_blocked/space_resumed, not by this.
        const auto& gate = *state->space_gate;
        const auto job_ids = gate.affected_job_ids();
        if (job_ids.empty()) {
            return;
        }
        const std::uint64_t episode_id = gate.episode_id();
        for (const auto& job_id : job_ids) {
            print_json_line(space_event_payload(
                "space_status",
                job_id,
                transition_volume_key(state),
                episode_id,
                query_ok ? 0UL : query_error,
                free_bytes,
                pending_bytes,
                0.0,
                query_ok,
                query_error));
        }
    }

    static std::string transition_volume_key(
        const sunpack::sevenzip::VolumeStatePtr& state
    ) {
        return state ? state->key : std::string{};
    }

    // ChangeSink landing: keeps the volume-space monitor active and fans the event out to affected jobs.
    void on_space_transition(
        const sunpack::sevenzip::VolumeSpaceTransition& transition
    ) noexcept {
        using Kind = sunpack::sevenzip::VolumeSpaceTransition::Kind;
        switch (transition.kind) {
            case Kind::Blocked:
            case Kind::Resumed:
                if (transition.kind == Kind::Blocked) {
                    // A blocked volume is itself a controller event. Wake the
                    // monitor directly instead of relying on unrelated job
                    // admission/completion notifications.
                    space_monitor_->note_blocked();
                    request_monitor_recheck();
                }
                break;
            case Kind::Status:
            default:
                break;
        }
        print_volume_space_event(transition);
    }

    static constexpr std::chrono::milliseconds kMemoryPollInterval{1000};

#ifdef _WIN32
    static bool query_physical_memory(
        std::uint64_t& total_bytes,
        std::uint64_t& available_bytes
    ) noexcept {
        MEMORYSTATUSEX status{};
        status.dwLength = sizeof(status);
        if (!GlobalMemoryStatusEx(&status)) {
            return false;
        }
        total_bytes = status.ullTotalPhys;
        available_bytes = status.ullAvailPhys;
        return total_bytes != 0;
    }
#endif

    void monitor_loop() noexcept {
        std::optional<std::chrono::steady_clock::time_point> next_memory_poll;
        std::uint64_t observed_activity_epoch = 0;

        while (true) {
            std::unique_lock<std::mutex> wait_lock(monitor_mutex_);
            const auto now = std::chrono::steady_clock::now();
            const bool has_active_jobs =
                monitor_has_active_jobs_.load(std::memory_order_acquire);
            const std::uint64_t activity_epoch =
                monitor_activity_epoch_.load(std::memory_order_acquire);

            if (has_active_jobs) {
                if (activity_epoch != observed_activity_epoch) {
                    // Every 0->1 active transition is a new activity episode.
                    // Force its first memory sample immediately even if the
                    // previous episode ended less than one poll interval ago.
                    observed_activity_epoch = activity_epoch;
                    next_memory_poll = now;
                } else if (!next_memory_poll) {
                    next_memory_poll = now;
                }
            } else {
                // No active extraction means no system-memory polling.
                next_memory_poll.reset();
            }

            std::optional<std::chrono::steady_clock::time_point> deadline =
                next_memory_poll;
#ifdef _WIN32
            if (space_monitor_->sampling() &&
                writer_config_.space_poll_interval > std::chrono::milliseconds::zero()) {
                const auto space_deadline = now + writer_config_.space_poll_interval;
                if (!deadline || space_deadline < *deadline) {
                    deadline = space_deadline;
                }
            }
            if (const auto reap_deadline = writer_registry_->next_reap_deadline()) {
                if (!deadline || *reap_deadline < *deadline) {
                    deadline = *reap_deadline;
                }
            }
#endif

            if (deadline && *deadline > now) {
                monitor_condition_.wait_until(
                    wait_lock,
                    *deadline,
                    [this] { return monitor_stopping_ || monitor_recheck_; });
            } else if (!deadline) {
                monitor_condition_.wait(
                    wait_lock,
                    [this] { return monitor_stopping_ || monitor_recheck_; });
            }

            if (monitor_stopping_) {
                break;
            }

            monitor_recheck_ = false;
            const auto wake_time = std::chrono::steady_clock::now();
            wait_lock.unlock();

#ifdef _WIN32
            for (const auto& volume : writer_registry_->reap_idle()) {
                print_writer_facility_event("writer_facility_reaped", volume);
            }
            space_monitor_->tick(wake_time);
#endif

            const bool active_after_tick =
                monitor_has_active_jobs_.load(std::memory_order_acquire);
            const bool should_poll_memory =
                active_after_tick &&
                next_memory_poll &&
                wake_time >= *next_memory_poll;
            if (!active_after_tick) {
                next_memory_poll.reset();
            } else if (should_poll_memory) {
                next_memory_poll = wake_time + kMemoryPollInterval;
            }

            if (!should_poll_memory) {
                continue;
            }

#ifdef _WIN32
            std::uint64_t total_bytes = 0;
            std::uint64_t available_bytes = 0;
            if (query_physical_memory(total_bytes, available_bytes)) {
                const bool changed =
                    memory_guard_.observe(total_bytes, available_bytes);
                if (changed) {
                    const auto snapshot = memory_guard_.snapshot();
                    cpu_budget_.set_effective_capacity(
                        snapshot.effective_cpu_budget);
                    // NativeCpuBudget emits at most one admission wake when
                    // an effective-capacity increase changes the budget from
                    // saturated to available; reductions need no wakeup.
                    print_memory_guard_event(snapshot);
                }
            }
#endif
        }
    }

    // Fallback routing key: an unknown volume gets its own isolated facility rather than sharing another volume's writer.
    static std::string synthetic_volume_key(const std::string& job_id) {
        return job_id.empty() ? std::string("job:unidentified") : "job:" + job_id;
    }

    // Binds the facility so a cancel wakes only that volume's writer; the lease held by worker_loop stays the only owner.
    void register_cancel_writer(
        const std::string& job_id,
        const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& writer
    ) noexcept {
        if (!writer || job_id.empty()) {
            return;
        }
        std::lock_guard<std::mutex> lock(cancel_mutex_);
        const auto found = cancel_tokens_.find(job_id);
        if (found != cancel_tokens_.end()) {
            found->second.writer = writer;
        }
    }

    void worker_loop() noexcept {
        for (;;) {
            Job job;
            std::size_t admitted_jobs = 0;
            bool wake_next_job = false;
            bool monitor_became_active = false;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] {
                    const bool empty = queues_empty_locked();
                    return (!empty && cpu_budget_.can_acquire_base()) ||
                        (stopping_ && empty);
                });
                if (stopping_ && queues_empty_locked()) {
                    break;
                }
                if (!cpu_budget_.try_acquire_base()) {
                    continue;
                }

                job = pop_next_job_locked();
                active_jobs_ += 1;
                admitted_jobs = active_jobs_;
                monitor_became_active = active_jobs_ == 1;
                if (monitor_became_active) {
                    monitor_has_active_jobs_.store(
                        true, std::memory_order_release);
                    monitor_activity_epoch_.fetch_add(
                        1, std::memory_order_release);
                }
                wake_next_job =
                    !queues_empty_locked() && cpu_budget_.can_acquire_base();
            }

            // Hand admission forward one worker at a time when multiple
            // credits are available, avoiding a notify-all thundering herd.
            if (wake_next_job) {
                condition_.notify_one();
            }
            if (monitor_became_active) {
                request_monitor_recheck();
            }

            print_job_start_events(job, admitted_jobs);
            int code = -100;
            const std::string& job_id = job.metadata.job_id;
            {
                sunpack::sevenzip::NativeCpuJobContext cpu_job_context(cpu_budget_);
                sunpack::sevenzip::NativeCpuContextScope cpu_scope(&cpu_job_context);
                try {
                if (job.metadata.requires_writer) {
                    // The lease is released before the job is reported finished, so active_jobs_ == 0 implies every finished job's lease is gone.
                    const std::string key = job.metadata.volume_key.empty()
                        ? synthetic_volume_key(job_id)
                        : job.metadata.volume_key;
                    auto lease = writer_registry_->acquire(key);
                    if (lease.created_facility()) {
                        print_writer_facility_event("writer_facility_created", key);
                    }
                    register_cancel_writer(job_id, lease.writer_pointer());
                    // Registered inside the volume lease scope and declared after it: root output dir creation can fill the disk before make_job, and reverse destruction must deregister before the lease is released.
                    sunpack::sevenzip::SpaceJobRegistration space_registration(lease, job_id);
                    code = run_request(job.request, lease.writer_pointer(), job.cancel_token);
                } else {
                    code = run_request(job.request, nullptr, job.cancel_token);
                }
                } catch (...) {
                    code = -100;
                }
            }
            cpu_budget_.release(1);

            std::size_t remaining_jobs = 0;
            bool drained = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                active_jobs_ = active_jobs_ > 0 ? active_jobs_ - 1 : 0;
                remaining_jobs = active_jobs_;
                if (active_jobs_ == 0) {
                    monitor_has_active_jobs_.store(
                        false, std::memory_order_release);
                }
                drained = queues_empty_locked() && active_jobs_ == 0;
                any_job_failed_ = any_job_failed_ || code != 0;
            }
            if (!job_id.empty()) {
                std::lock_guard<std::mutex> cancel_lock(cancel_mutex_);
                cancel_tokens_.erase(job_id);
            }

            // cpu_budget_.release(1) wakes at most one queued admission waiter.
            // Drain waiters use a separate condition variable, while the
            // low-frequency monitor is touched only on active/idle edges.
            if (drained) {
                drain_condition_.notify_all();
            }
            print_active_event(job, "job_finished", remaining_jobs);
        }
    }

    std::vector<std::thread> workers_;
    std::thread monitor_thread_;
    // Declaration order is destruction order reversed: meters, sink and config outlive writer_registry_, and space_monitor_ holds writer_registry_ and is destroyed before it.
    sunpack::sevenzip::WriterMetersPtr writer_meters_;
    sunpack::sevenzip::VolumeSpaceChangeSink space_change_sink_;
    sunpack::sevenzip::AsyncWriterConfig writer_config_;
    sunpack::sevenzip::VolumeWriterRegistryPtr writer_registry_;
    std::unique_ptr<sunpack::sevenzip::VolumeSpaceMonitor> space_monitor_;

    // Scheduler hot state: foreground/background queues preserve the existing
    // foreground-first policy without an O(n) scan or middle erase.
    std::deque<Job> foreground_queue_;
    std::deque<Job> background_queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::condition_variable drain_condition_;

    // Cancellation bookkeeping is not scheduler state and must not contend
    // with admission or queue selection.
    std::unordered_map<std::string, JobControl> cancel_tokens_;
    std::mutex cancel_mutex_;

    // The controller has its own wait domain. Worker admission never takes
    // this mutex except on the 0->1 / 1->0 activity edges.
    std::mutex monitor_mutex_;
    std::condition_variable monitor_condition_;
    std::atomic<bool> monitor_has_active_jobs_{false};
    std::atomic<std::uint64_t> monitor_activity_epoch_{0};
    bool monitor_recheck_ = false;
    bool monitor_stopping_ = false;

    const std::size_t worker_count_;
    const std::size_t queue_capacity_;
    sunpack::sevenzip::NativeCpuBudget cpu_budget_;
    sunpack::sevenzip::NativeMemoryGuard memory_guard_;
    std::size_t active_jobs_ = 0;
    bool any_job_failed_ = false;
    bool stopping_ = false;
};

int run_message(
    WorkerRequest request,
    NativeJobExecutor& executor
) {
    const std::string& command = request.worker_command;
    if (command == "cancel") {
        const std::string& job_id = request.job_id;
        const bool accepted = executor.cancel(job_id);
        print_json_line("{\"type\":\"cancel_ack\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"accepted\":" + std::string(accepted ? "true" : "false") + "}");
        return accepted ? 0 : 1;
    }
    if (command == "set_process_mode") {
        std::string mode = request.process_mode;
        if (mode != "background" && mode != "high") {
            mode = "normal";
        }
        const bool applied = apply_native_process_mode(mode);
        print_json_line("{\"type\":\"process_mode_ack\",\"mode\":\"" + mode +
            "\",\"applied\":" + std::string(applied ? "true" : "false") + "}");
        return applied ? 0 : 1;
    }
    if (command == "shutdown") {
        return 0;
    }
    // Native owns queued work and completion is reported through native events/results.
    executor.submit(std::move(request));
    return 0;
}

int main() {
    const std::string requested_process_mode = requested_native_process_mode();
    const bool process_mode_applied = apply_native_process_mode(requested_process_mode);
    const auto resources = native_machine_resources();
    const auto sizing = sunpack::sevenzip::derive_native_sizing_plan(
        resources,
        configured_native_sizing_overrides());
    const auto memory_guard_config = configured_native_memory_guard_config();
    NativeJobExecutor executor(sizing, memory_guard_config);
    const bool sizing_overridden = sizing.thread_capacity_overridden;
    print_json_line(
        "{\"type\":\"worker_ready\",\"sizing_mode\":\"" +
        std::string(sizing_overridden ? "overridden" : "dynamic") +
        "\",\"logical_processors\":" + std::to_string(resources.logical_processors) +
        ",\"thread_capacity\":" + std::to_string(sizing.thread_capacity) +
        ",\"nominal_cpu_budget\":" + std::to_string(sizing.thread_capacity) +
        ",\"memory_poll_interval_ms\":1000" +
        ",\"minimum_available_memory_ratio\":" +
            std::to_string(memory_guard_config.minimum_available_ratio) +
        ",\"process_mode\":\"" + requested_process_mode +
        "\",\"process_mode_applied\":" + (process_mode_applied ? "true" : "false") + "}");
    std::string line;
    while (std::getline(std::cin, line)) {
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
            return ch > 0x20;
        }));
        if (line.empty()) {
            continue;
        }
        WorkerRequest request = parse_worker_request(line);
        const bool shutdown = request.worker_command == "shutdown";
        const int code = run_message(std::move(request), executor);
        if (shutdown) {
            executor.stop();
            return code;
        }
    }
    executor.stop(/*cancel_pending_jobs=*/false);
    return executor.had_job_failure() ? 1 : 0;
}
