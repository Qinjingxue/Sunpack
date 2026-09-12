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
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <deque>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "internal/sevenzip_status.hpp"
#include "internal/archive_operations.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/native_runtime_control.hpp"
#include "internal/native_worker_sizing.hpp"
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

std::size_t skip_ws(const std::string& json, std::size_t pos) {
    while (pos < json.size() && static_cast<unsigned char>(json[pos]) <= 0x20) {
        ++pos;
    }
    return pos;
}

std::string parse_json_string_at(const std::string& json, std::size_t quote_pos, std::size_t* out_next = nullptr) {
    std::string out;
    if (quote_pos >= json.size() || json[quote_pos] != '"') {
        return out;
    }
    for (std::size_t i = quote_pos + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (ch == '"') {
            if (out_next) {
                *out_next = i + 1;
            }
            return out;
        }
        if (ch == '\\' && i + 1 < json.size()) {
            const char escaped = json[++i];
            switch (escaped) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            default: out.push_back(escaped); break;
            }
            continue;
        }
        out.push_back(ch);
    }
    return out;
}

std::string json_string_field(const std::string& json, const std::string& key, const std::string& fallback = "") {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return fallback;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return fallback;
    }
    const std::size_t quote = skip_ws(json, colon + 1);
    if (quote >= json.size() || json[quote] != '"') {
        return fallback;
    }
    return parse_json_string_at(json, quote);
}

std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return values;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return values;
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '[') {
        return values;
    }
    ++pos;
    while (pos < json.size()) {
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ']') {
            break;
        }
        if (pos >= json.size() || json[pos] != '"') {
            break;
        }
        std::size_t next = pos;
        values.push_back(parse_json_string_at(json, pos, &next));
        pos = skip_ws(json, next);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
        }
    }
    return values;
}

unsigned long long parse_uint_at(const std::string& json, std::size_t pos, bool* ok = nullptr) {
    if (ok) {
        *ok = false;
    }
    pos = skip_ws(json, pos);
    unsigned long long value = 0;
    bool any = false;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        any = true;
        value = value * 10 + static_cast<unsigned long long>(json[pos] - '0');
        ++pos;
    }
    if (ok) {
        *ok = any;
    }
    return value;
}

bool json_uint_field_in_object(const std::string& object_json, const std::string& key, unsigned long long* value) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = object_json.find(needle);
    if (key_pos == std::string::npos) {
        return false;
    }
    const std::size_t colon = object_json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return false;
    }
    bool ok = false;
    const unsigned long long parsed = parse_uint_at(object_json, colon + 1, &ok);
    if (ok && value) {
        *value = parsed;
    }
    return ok;
}

bool json_bool_field(const std::string& json, const std::string& key, bool fallback = false) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return fallback;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return fallback;
    }
    const std::size_t pos = skip_ws(json, colon + 1);
    if (json.compare(pos, 4, "true") == 0) {
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        return false;
    }
    if (pos < json.size() && json[pos] == '"') {
        const std::string text = parse_json_string_at(json, pos);
        return text == "true" || text == "1" || text == "yes";
    }
    return fallback;
}

std::vector<std::string> json_object_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return objects;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return objects;
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '[') {
        return objects;
    }
    ++pos;
    while (pos < json.size()) {
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ']') {
            break;
        }
        if (pos >= json.size() || json[pos] != '{') {
            break;
        }
        const std::size_t start = pos;
        int depth = 0;
        bool in_string = false;
        for (; pos < json.size(); ++pos) {
            const char ch = json[pos];
            if (ch == '"' && (pos == 0 || json[pos - 1] != '\\')) {
                in_string = !in_string;
            }
            if (in_string) {
                continue;
            }
            if (ch == '{') {
                ++depth;
            } else if (ch == '}') {
                --depth;
                if (depth == 0) {
                    objects.push_back(json.substr(start, pos - start + 1));
                    ++pos;
                    break;
                }
            }
        }
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
        }
    }
    return objects;
}

std::string json_object_field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return "";
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return "";
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '{') {
        return "";
    }
    const std::size_t start = pos;
    int depth = 0;
    bool in_string = false;
    for (; pos < json.size(); ++pos) {
        const char ch = json[pos];
        if (ch == '"' && (pos == 0 || json[pos - 1] != '\\')) {
            in_string = !in_string;
        }
        if (in_string) {
            continue;
        }
        if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                return json.substr(start, pos - start + 1);
            }
        }
    }
    return "";
}

struct WorkerArchiveInput {
    std::wstring archive_path;
    std::wstring format_hint;
    std::wstring open_mode;
    std::vector<std::wstring> part_paths;
    std::vector<std::wstring> canonical_names;
    std::vector<int> volume_numbers;
    std::string validation_error;
    std::vector<sunpack::sevenzip::ExtractInputRange> ranges;
    std::vector<sunpack::sevenzip::ExtractPatchOperation> patches;
};

sunpack::sevenzip::PasswordTestResult run_password_candidate_probe(
    const std::wstring& dll_path,
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
            dll_path,
            archive_input.archive_path,
            archive_input.ranges,
            archive_input.format_hint,
            password_ptrs.data(),
            static_cast<int>(password_ptrs.size()));
    }
    return test_passwords_with_parts(
        dll_path,
        archive_input.archive_path,
        archive_input.part_paths,
        password_ptrs.data(),
        static_cast<int>(password_ptrs.size()),
        archive_input.canonical_names);
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

std::vector<unsigned char> base64_decode(const std::string& text) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> out;
    int value = 0;
    int bits = -8;
    for (const unsigned char ch : text) {
        if (ch == '=') {
            break;
        }
        const auto index = alphabet.find(static_cast<char>(ch));
        if (index == std::string::npos) {
            continue;
        }
        value = (value << 6) + static_cast<int>(index);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::vector<sunpack::sevenzip::ExtractInputRange> parse_input_ranges(const std::string& request, const std::string& archive_path) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    const std::string kind = json_string_field(request, "kind", "file");
    if (kind == "file_range") {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(request, "start", &start) || json_uint_field_in_object(request, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(request, "end", &end) || json_uint_field_in_object(request, "end_offset", &end);
        const std::string path = json_string_field(request, "path", archive_path);
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
    for (const auto& object_json : json_object_array_field(request, "ranges")) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(object_json, "start", &start) || json_uint_field_in_object(object_json, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(object_json, "end", &end) || json_uint_field_in_object(object_json, "end_offset", &end);
        const std::string path = json_string_field(object_json, "path", archive_path);
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
    const std::vector<std::string>& objects,
    const std::string& default_path
) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    for (const auto& object_json : objects) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(object_json, "start", &start) || json_uint_field_in_object(object_json, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(object_json, "end", &end) || json_uint_field_in_object(object_json, "end_offset", &end);
        const std::string path = json_string_field(object_json, "path", default_path);
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

std::vector<sunpack::sevenzip::ExtractPatchOperation> parse_patch_operations_from_state(const std::string& request);

WorkerArchiveInput parse_archive_input_descriptor(
    const std::string& request,
    const std::wstring& fallback_archive_path,
    const std::wstring& fallback_format_hint,
    const std::vector<std::wstring>& fallback_part_paths
) {
    WorkerArchiveInput input;
    input.archive_path = fallback_archive_path;
    input.format_hint = fallback_format_hint;
    input.open_mode = L"file";
    input.part_paths = fallback_part_paths;

    std::string descriptor = json_object_field(request, "archive_input");
    const std::string state = json_object_field(request, "archive_state");
    if (!state.empty()) {
        const std::string state_source = json_object_field(state, "source");
        if (!state_source.empty()) {
            descriptor = state_source;
        }
    }
    if (descriptor.empty()) {
        input.ranges = parse_input_ranges(request, json_string_field(request, "archive_path", ""));
        if (!input.ranges.empty()) {
            input.open_mode = utf8_to_wide(json_string_field(request, "kind", "concat_ranges"));
        }
        input.patches = parse_patch_operations_from_state(request);
        return input;
    }

    const std::string entry_path = json_string_field(descriptor, "entry_path", json_string_field(request, "archive_path", ""));
    if (!entry_path.empty()) {
        input.archive_path = utf8_to_wide(entry_path);
    }
    const std::string mode = json_string_field(descriptor, "open_mode", json_string_field(descriptor, "kind", "file"));
    input.open_mode = utf8_to_wide(mode.empty() ? "file" : mode);
    const std::string format_hint = json_string_field(descriptor, "format_hint", json_string_field(request, "format_hint", ""));
    input.format_hint = utf8_to_wide(format_hint);

    struct ParsedPart { int number; std::wstring path; std::wstring canonical_name; };
    std::vector<ParsedPart> structured_parts;
    std::vector<std::wstring> parts;
    for (const auto& object_json : json_object_array_field(descriptor, "parts")) {
        const std::string path = json_string_field(object_json, "path", "");
        if (!path.empty()) {
            parts.push_back(utf8_to_wide(path));
            unsigned long long number = 0;
            const std::string canonical_name = json_string_field(object_json, "canonical_name", "");
            if (mode == "native_volumes" || mode == "sfx_with_volumes") {
                if (!json_uint_field_in_object(object_json, "volume_number", &number) || number == 0 || canonical_name.empty()) {
                    input.validation_error = "structured volume part requires volume_number and canonical_name";
                } else {
                    structured_parts.push_back({static_cast<int>(number), utf8_to_wide(path), utf8_to_wide(canonical_name)});
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
        if (parts.empty()) input.validation_error = "structured volume descriptor has no parts";
    }
    if (!parts.empty()) {
        input.part_paths = parts;
    }

    if (mode == "file_range") {
        input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "parts"), entry_path);
        if (input.ranges.empty()) {
            const std::string segment = json_object_field(descriptor, "segment");
            unsigned long long start = 0;
            unsigned long long end = 0;
            const bool has_start = json_uint_field_in_object(segment, "start", &start) || json_uint_field_in_object(segment, "start_offset", &start);
            const bool has_end = json_uint_field_in_object(segment, "end", &end) || json_uint_field_in_object(segment, "end_offset", &end);
            sunpack::sevenzip::ExtractInputRange range;
            range.path = utf8_to_wide(entry_path.empty() ? json_string_field(request, "archive_path", "") : entry_path);
            range.start = has_start ? start : 0;
            range.end = end;
            range.has_end = has_end;
            input.ranges.push_back(range);
        }
    } else if (mode == "concat_ranges") {
        input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "ranges"), entry_path);
        if (input.ranges.empty()) {
            input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "parts"), entry_path);
        }
    }
    input.patches = parse_patch_operations_from_state(request);
    return input;
}

std::vector<sunpack::sevenzip::ExtractPatchOperation> parse_patch_operations_from_state(const std::string& request) {
    using sunpack::sevenzip::ExtractPatchOperation;
    std::vector<ExtractPatchOperation> operations;
    const std::string state = json_object_field(request, "archive_state");
    if (state.empty()) {
        return operations;
    }
    for (const auto& patch_json : json_object_array_field(state, "patches")) {
        for (const auto& operation_json : json_object_array_field(patch_json, "operations")) {
            ExtractPatchOperation operation;
            operation.op = utf8_to_wide(json_string_field(operation_json, "op", ""));
            operation.target = utf8_to_wide(json_string_field(operation_json, "target", "logical"));
            unsigned long long offset = 0;
            if (json_uint_field_in_object(operation_json, "offset", &offset)) {
                operation.offset = offset;
            }
            unsigned long long size = 0;
            if (json_uint_field_in_object(operation_json, "size", &size)) {
                operation.size = size;
                operation.has_size = true;
            }
            operation.data = base64_decode(json_string_field(operation_json, "data_b64", ""));
            if (!operation.op.empty()) {
                operations.push_back(std::move(operation));
            }
        }
    }
    return operations;
}

std::mutex g_output_mutex;

void print_json_line(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    std::cout << json << "\n";
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
    const std::string& request,
    // The write facility for this job's output volume, borrowed from the
    // registry lease held by worker_loop.  Null for dry runs, which write
    // nothing.  The historical parameter name says "shared_writer"; the
    // semantics are now per-volume, not process-wide.
    const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& shared_writer = nullptr,
    const std::shared_ptr<std::atomic<bool>>& cancel_token = nullptr
) {
    using namespace sunpack::sevenzip;

    const std::string job_id = json_string_field(request, "job_id", "");
    const std::string command = json_string_field(request, "worker_command", "");
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

    const std::wstring dll_path = utf8_to_wide(json_string_field(request, "seven_zip_dll_path", "tools\\7z.dll"));
    const std::wstring archive_path = utf8_to_wide(json_string_field(request, "archive_path", ""));
    const std::wstring output_dir = utf8_to_wide(json_string_field(request, "output_dir", ""));
    const std::wstring password = utf8_to_wide(json_string_field(request, "password", ""));
    const std::wstring format_hint = utf8_to_wide(json_string_field(request, "format_hint", ""));
    const std::wstring codepage = utf8_to_wide(json_string_field(request, "codepage", ""));
    const bool dry_run = json_bool_field(request, "dry_run", false);
    unsigned long long job_buffer_budget = 0;
    json_uint_field_in_object(request, "job_buffer_budget_bytes", &job_buffer_budget);

    std::vector<std::wstring> password_candidates;
    for (const auto& candidate : json_string_array_field(request, "password_candidates")) {
        password_candidates.push_back(utf8_to_wide(candidate));
    }

    std::vector<std::wstring> part_paths;
    for (const auto& part : json_string_array_field(request, "part_paths")) {
        part_paths.push_back(utf8_to_wide(part));
    }
    std::vector<std::wstring> decoded_names;
    for (const auto& name : json_string_array_field(request, "decoded_names")) {
        decoded_names.push_back(utf8_to_wide(name));
    }
    if (!codepage.empty() && decoded_names.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\","
            "\"failure_stage\":\"filename_encoding\",\"failure_kind\":\"decoded_names_required\","
            "\"message\":\"decoded_names is required when codepage is set\"}");
        return 2;
    }

    if (archive_path.empty() || (!dry_run && output_dir.empty())) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"archive_path is required; output_dir is required unless dry_run is true\"}");
        return 2;
    }

    auto last_progress_emit = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    unsigned int coalesced_progress_events = 0;
    auto progress_mutex = std::make_shared<std::mutex>();
    auto progress = [job_id, last_progress_emit, coalesced_progress_events, progress_mutex](const ExtractProgressEvent& event) mutable {
            std::lock_guard<std::mutex> lock(*progress_mutex);
            const auto now = std::chrono::steady_clock::now();
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

    const auto archive_input = parse_archive_input_descriptor(request, archive_path, format_hint, part_paths);
    if (!archive_input.validation_error.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"" +
            json_escape(archive_input.validation_error) + "\"}");
        return 2;
    }
    auto extract_with_password = [&](const std::wstring& selected_password) {
        return !archive_input.patches.empty()
            ? extract_archive_with_patches(dll_path, archive_input.archive_path, archive_input.part_paths, archive_input.ranges, archive_input.patches, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token)
            : archive_input.ranges.empty()
            ? extract_archive_with_parts(dll_path, archive_input.archive_path, archive_input.part_paths, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, archive_input.canonical_names, archive_input.open_mode == L"native_volumes", shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token)
            : extract_archive_with_ranges(dll_path, archive_input.archive_path, archive_input.ranges, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token);
    };

    ExtractArchiveResult result;
    if (password_candidates.empty()) {
        result = extract_with_password(password);
    } else if (!archive_input.patches.empty()) {
        result.status = PasswordTestStatus::Error;
        result.failure_stage = "password_probe";
        result.failure_kind = "patched_input_candidates_unsupported";
        result.message = "password candidate batches are not supported for patched input";
    } else if (password_candidates.size() == 1) {
        // A fast verifier has already reduced the search space to one
        // candidate. Running the bounded password probe again would duplicate
        // work immediately before the real extraction transaction. On failure,
        // run it once as a diagnostic so weak ZipCrypto header matches preserve
        // the retryable all-candidates-rejected contract.
        result = extract_with_password(password_candidates.front());
        const bool direct_ok = result.status == PasswordTestStatus::Ok && result.command_ok;
        if (!direct_ok) {
            const auto probe = run_password_candidate_probe(dll_path, archive_input, password_candidates);
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
        const auto probe = run_password_candidate_probe(dll_path, archive_input, password_candidates);
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
        failure_fields + input_trace_field + diagnostic_fields + "}");
    return ok ? 0 : 1;
}

std::size_t configured_native_queue_capacity() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_MAX_QUEUE_JOBS");
    if (!value || !*value) {
        return 0;
    }
    char* end = nullptr;
    const unsigned long long configured = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return 0;
    }
    return (std::min)(static_cast<std::size_t>(configured), std::size_t{1'000'000});
}

bool configured_native_bool(const char* name, bool fallback) noexcept {
    const char* value = std::getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    return std::string(value) != "0" && std::string(value) != "false" && std::string(value) != "False";
}

sunpack::sevenzip::NativeExplorationStrategy configured_native_exploration_strategy() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_EXPLORATION_STRATEGY");
    if (!value) {
        return sunpack::sevenzip::NativeExplorationStrategy::Calibrated;
    }
    const std::string strategy(value);
    if (strategy == "calibrated") {
        return sunpack::sevenzip::NativeExplorationStrategy::Calibrated;
    }
    if (strategy == "full") {
        return sunpack::sevenzip::NativeExplorationStrategy::Full;
    }
    if (strategy == "rapid") {
        return sunpack::sevenzip::NativeExplorationStrategy::Rapid;
    }
    return sunpack::sevenzip::NativeExplorationStrategy::Calibrated;
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
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        resources.total_memory_bytes = status.ullTotalPhys;
        resources.available_memory_bytes = status.ullAvailPhys;
    }
#endif
    return resources;
}

std::string requested_native_process_mode() {
    const char* configured = std::getenv("SUNPACK_NATIVE_PROCESS_MODE");
    return configured && std::string(configured) == "background" ? "background" : "normal";
}

sunpack::sevenzip::NativeSizingOverrides configured_native_sizing_overrides() noexcept {
    sunpack::sevenzip::NativeSizingOverrides overrides;
    overrides.thread_capacity = configured_native_size(
        "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY", 0, 0, 32);
    overrides.initial_active_jobs = configured_native_size(
        "SUNPACK_NATIVE_INITIAL_ACTIVE_JOBS", 0, 0, 32);
    overrides.memory_budget_bytes = configured_native_size(
        "SUNPACK_NATIVE_MEMORY_BUDGET_BYTES", 0, 0);
    return overrides;
}

bool apply_native_process_mode(const std::string& mode) noexcept {
#ifdef _WIN32
    const DWORD requested = mode == "background"
        ? PROCESS_MODE_BACKGROUND_BEGIN
        : PROCESS_MODE_BACKGROUND_END;
    if (SetPriorityClass(GetCurrentProcess(), requested) != 0) {
        return true;
    }
    const DWORD fallback = mode == "background"
        ? BELOW_NORMAL_PRIORITY_CLASS
        : NORMAL_PRIORITY_CLASS;
    return SetPriorityClass(GetCurrentProcess(), fallback) != 0;
#else
    return mode != "background";
#endif
}

sunpack::sevenzip::NativeRuntimeConfig configured_native_runtime_config(
    const sunpack::sevenzip::NativeSizingPlan& sizing
) noexcept {
    sunpack::sevenzip::NativeRuntimeConfig config;
    config.adaptive_enabled = configured_native_bool("SUNPACK_NATIVE_ADAPTIVE_ENABLED", true);
    config.resource_diagnostics_enabled = configured_native_bool(
        "SUNPACK_NATIVE_RESOURCE_DIAGNOSTICS", false);
    config.initial_active_jobs = sizing.initial_active_jobs;
    config.exploration_strategy = configured_native_exploration_strategy();
    if (config.exploration_strategy == sunpack::sevenzip::NativeExplorationStrategy::Full) {
        config.initial_active_jobs = sizing.thread_capacity;
    }
    config.minimum_window_seconds = configured_native_double(
        "SUNPACK_NATIVE_MINIMUM_WINDOW_SECONDS", config.minimum_window_seconds, 0.05, 60.0);
    config.maximum_window_seconds = configured_native_double(
        "SUNPACK_NATIVE_MAXIMUM_WINDOW_SECONDS", config.maximum_window_seconds, 0.05, 60.0);
    config.settle_seconds = configured_native_double(
        "SUNPACK_NATIVE_SETTLE_SECONDS", config.settle_seconds, 0.0, 10.0);
    config.large_window_bytes = configured_native_size(
        "SUNPACK_NATIVE_LARGE_WINDOW_BYTES", config.large_window_bytes);
    config.small_window_jobs = configured_native_size(
        "SUNPACK_NATIVE_SMALL_WINDOW_JOBS", config.small_window_jobs);
    config.small_window_files = configured_native_size(
        "SUNPACK_NATIVE_SMALL_WINDOW_FILES", config.small_window_files);
    config.improvement_ratio = configured_native_double(
        "SUNPACK_NATIVE_IMPROVEMENT_RATIO", config.improvement_ratio, 1.0, 2.0);
    config.regression_ratio = configured_native_double(
        "SUNPACK_NATIVE_REGRESSION_RATIO", config.regression_ratio, 0.01, 1.0);
    config.aggressive_step = configured_native_size(
        "SUNPACK_NATIVE_AGGRESSIVE_STEP", config.aggressive_step, 1, 32);
    config.cooldown_windows = configured_native_size(
        "SUNPACK_NATIVE_COOLDOWN_WINDOWS", config.cooldown_windows);
    config.hold_windows = configured_native_size(
        "SUNPACK_NATIVE_HOLD_WINDOWS", config.hold_windows);
    config.warm_start_decay_seconds = configured_native_double(
        "SUNPACK_NATIVE_WARM_START_DECAY_SECONDS",
        config.warm_start_decay_seconds,
        0.0,
        86400.0);
    config.warm_start_confirmations = configured_native_size(
        "SUNPACK_NATIVE_WARM_START_CONFIRMATIONS",
        config.warm_start_confirmations,
        1,
        64);
    config.memory_pause_available = configured_native_size(
        "SUNPACK_NATIVE_MEMORY_PAUSE_AVAILABLE_BYTES", config.memory_pause_available);
    config.memory_resume_available = configured_native_size(
        "SUNPACK_NATIVE_MEMORY_RESUME_AVAILABLE_BYTES", config.memory_resume_available);
    return config;
}

class NativeJobExecutor final {
public:
    NativeJobExecutor(
        const sunpack::sevenzip::NativeSizingPlan& sizing,
        sunpack::sevenzip::NativeRuntimeConfig runtime_config
    )
        : writer_meters_(std::make_shared<sunpack::sevenzip::WriterMeters>()),
          // ★ ChangeSink 的唯一所有者链（§4.7.4.1）：
          //     NativeJobExecutor（本处，捕获 this）
          //       → VolumeWriterRegistry(meters, config, sink)
          //         → VolumeSpaceGate(volume_key, query_root_hint, sink)
          //   gate 的生命周期长于 writer facility，因此 AsyncFileWriter **绝不**
          //   持有或重设 sink（否则 facility 被 reap / 重建时会覆盖 persistent
          //   gate 的回调）。这也要求 executor 的生命周期长于所有 gate ——
          //   由"registry 在 executor 成员里、且 ~NativeJobExecutor → stop() →
          //   registry->shutdown() 先于 executor 析构完成"保证。
          space_change_sink_(
              [this](const sunpack::sevenzip::VolumeSpaceTransition &transition) {
                  on_space_transition(transition);
              }),
          // One environment snapshot for every volume facility: the writers must
          // be identical by construction, not by all happening to read the same
          // variables (§3.4).
          writer_config_(sunpack::sevenzip::configured_async_writer_config()),
          writer_registry_(std::make_shared<sunpack::sevenzip::VolumeWriterRegistry>(
              writer_meters_,
              writer_config_,
              space_change_sink_)),
          worker_count_((std::max)(std::size_t{1}, sizing.thread_capacity)),
          memory_budget_(sizing.memory_budget_bytes),
          queue_capacity_(configured_native_queue_capacity()),
          runtime_controller_(
              worker_count_,
              memory_budget_,
              std::move(runtime_config)) {
        // ★ monitor 不维护自己的 membership：每个 tick 直接从 registry 拉 blocked
        //   volumes。tick() **必须**在 executor mutex_ 之外调用（见 controller_loop）。
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
        controller_thread_ = std::thread([this] { controller_loop(); });
    }

    ~NativeJobExecutor() { stop(); }

    NativeJobExecutor(const NativeJobExecutor&) = delete;
    NativeJobExecutor& operator=(const NativeJobExecutor&) = delete;

    std::future<int> submit(std::string request) {
        auto promise = std::make_shared<std::promise<int>>();
        auto future = promise->get_future();
        auto cancel_token = std::make_shared<std::atomic<bool>>(false);
        const std::string job_id = json_string_field(request, "job_id", "");
        JobMetadata metadata = metadata_from_request(request);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                promise->set_value(-100);
                return future;
            }
            if (memory_budget_ != 0 && metadata.memory_reserve > memory_budget_) {
                any_job_failed_ = true;
                promise->set_value(-1);
                print_json_line(
                    "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"status\":\"failed\",\"native_status\":\"resource_limit\","
                    "\"failure_stage\":\"native_admission\",\"failure_kind\":\"memory_budget\","
                    "\"message\":\"job memory reservation exceeds native hard budget\"}");
                print_worker_event(job_id, "job_finished", metadata);
                return future;
            }
            if (queue_capacity_ != 0 && queue_.size() >= queue_capacity_) {
                any_job_failed_ = true;
                promise->set_value(-2);
                print_json_line(
                    "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"status\":\"failed\",\"native_status\":\"backpressure\","
                    "\"retryable\":true,\"failure_stage\":\"native_admission\","
                    "\"failure_kind\":\"queue_capacity\",\"message\":\"native job queue is full\"}");
                print_worker_event(job_id, "job_finished", metadata);
                return future;
            }
            if (!job_id.empty()) {
                cancel_tokens_[job_id] = std::make_shared<JobControl>(cancel_token, nullptr);
            }
            queue_.push_back(Job{
                std::move(request),
                std::move(promise),
                std::move(cancel_token),
                metadata,
            });
            controller_recheck_ = true;
        }
        print_worker_event(job_id, "job_queued", metadata);
        condition_.notify_one();
        controller_condition_.notify_one();
        return future;
    }

    bool cancel(const std::string& job_id) noexcept {
        std::shared_ptr<std::atomic<bool>> token;
        std::shared_ptr<sunpack::sevenzip::AsyncFileWriter> writer_to_wake;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = cancel_tokens_.find(job_id);
            if (found == cancel_tokens_.end()) {
                return false;
            }
            token = found->second->cancel_token;
            // Upgrade the weak reference while the entry is still alive, but only
            // for the duration of this call: the token is what carries the cancel,
            // the writer is only the thing that has to be woken.
            writer_to_wake = found->second->writer.lock();
        }
        if (!token) {
            return false;
        }
        token->store(true, std::memory_order_release);
#ifdef _WIN32
        // Only the facility this job is actually writing to needs waking: its
        // producer may be parked in that facility's backpressure wait.  A job that
        // has not acquired a lease yet (or a dry run) has no writer and needs only
        // the token.  A facility already reclaimed leaves an expired weak_ptr.
        if (writer_to_wake) {
            writer_to_wake->wake_waiters();
        }
#endif
        condition_.notify_all();
        return true;
    }

    bool had_job_failure() const noexcept { return any_job_failed_; }

    // 等待队列与在跑的 job 全部结束。**只用于 stdin EOF 的排空路径**。
    //
    // 此时控制器线程与 space monitor 必须仍然存活 —— 排空期间才出现的"满盘"
    // 否则没有任何线程会 query/poll（见 stop(false) 的注释）。
    // 完成后由调用方走正常的 stop() 路径：置 stopping_ → notify → join。
    void wait_for_pending_jobs_to_drain() noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return queue_.empty() && active_jobs_ == 0; });
    }

    // cancel_pending_jobs：
    //   true  —— 显式 {"worker_command":"shutdown"}：等价于"取消所有尚未完成的 job"。
    //            必须先置 terminal 条件再 wake，否则阻塞在卷空间 gate 上的 worker
    //            永远看不到停止请求，join 永久阻塞（T-WIN-11 / T-WIN-20）。
    //   false —— stdin EOF：**先排空、再停止**。
    void stop(bool cancel_pending_jobs = true) noexcept {
        if (!cancel_pending_jobs) {
            // ★★ EOF 的"排空"绝不能等价于"立刻 stopping_=true 然后 join"。
            //
            //   controller_loop() 一看到 stopping_ 就 break，而
            //   space_monitor_->tick() **只由这个 controller 驱动**。若在这里提前
            //   结束 controller，就存在这条闭环（T-WIN-24 钉死它）：
            //
            //     echo job | worker.exe → stdin EOF → 排空开始
            //       → 随后 WriteFile 遇到 ERROR_DISK_FULL → gate 进入 Blocked
            //       → 用户释放空间，但**没有任何线程再 query/poll**
            //       → job 永久挂住，而本函数正卡在 join(worker) 上
            //       ⇒ 整个进程永久不退出
            //
            //   abort_all_space_gates() 救不了：EOF 模式故意没有置真 cancel token，
            //   被唤醒的 waiter 重新求值 terminal 仍是 false，于是继续睡。
            //
            //   所以 EOF 的正确模型是「draining ≠ stopping」：先等 queue 空且
            //   active_jobs == 0（此时 controller / monitor / workers 全部还活着，
            //   满盘仍然能被 poll 到并恢复），**然后**才真正进入 stopping 并 join。
            //   这也保留了"一次性调用不取消刚提交的 job"这条既有语义。
            wait_for_pending_jobs_to_drain();
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            stopping_ = true;
            // ★ 关键顺序：**先把所有 job 的 terminal 条件置位，再 wake。**
            //
            //   只 wake 而不改变任何 terminal 条件是没有意义的 —— 被唤醒的 writer
            //   会重新求值为 false 并继续睡，join() 永久阻塞。
            //
            //   cancel_tokens_ 已经持有每个 active job 的共享 cancel token，因此
            //   置真它们即覆盖**全部有 job 的 writer**；没有 job 的 writer 由
            //   AsyncFileWriter::finish()（registry shutdown 时）置自己的 stopping_。
            //   两者合起来覆盖每一个 gate waiter。
            //
            //   ⚠️ 只在**显式 shutdown 命令**上置位；stdin EOF 走"排空"语义（见
            //      stop() 的参数说明）。
            if (cancel_pending_jobs) {
                for (auto& entry : cancel_tokens_) {
                    if (entry.second && entry.second->cancel_token) {
                        entry.second->cancel_token->store(true, std::memory_order_release);
                    }
                }
            }
        }
        condition_.notify_all();
        controller_condition_.notify_all();
#ifdef _WIN32
        // ★ 必须在 join() **之前**：否则卡在 volume gate 上的 worker 永远看不到
        //   上面已置位的 terminal 条件，join 永久阻塞。
        //   因为 gate 没有 aborted_ 永久闩锁，这一步只是 wake_waiters() 的广播，
        //   **不改变任何 gate 状态**（persistent volume 的 gate 不会被毒死）。
        writer_registry_->abort_all_space_gates();
#endif
        if (controller_thread_.joinable()) {
            controller_thread_.join();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
#ifdef _WIN32
        // Every remaining writer finishes and joins here, with the registry mutex
        // released.  Reaching this point implies all leases were released: the
        // worker threads are joined, and a lease never outlives its job.
        writer_registry_->shutdown();
#endif
    }

private:
    struct JobMetadata {
        std::string request_id;
        bool foreground = true;
        std::size_t memory_reserve = 64U << 20;
        std::size_t dictionary_reserve = 0;
        // Routing key for the per-volume write facility, resolved by the caller
        // before submission (the worker does not link the Rust volume resolver).
        // Always non-empty in practice: the producer substitutes a synthetic
        // "job:<id>" key when resolution fails, so a job never silently shares
        // another volume's writer.
        std::string volume_key;
        // False only for dry runs, which write nothing: no facility, no writer
        // threads, and no volume readiness gate should apply to them.
        bool requires_writer = true;
    };

    struct Job {
        std::string request;
        std::shared_ptr<std::promise<int>> promise;
        std::shared_ptr<std::atomic<bool>> cancel_token;
        JobMetadata metadata;
    };

    // Per-job cancellation control.  ``writer`` is bound once the job holds a
    // facility lease, so a cancel wakes exactly one volume's writer instead of
    // every facility (§6.3).  It stays empty for queued and dry-run jobs, which
    // only need the token.
    //
    // The writer reference is deliberately WEAK: it exists only so cancel() can
    // reach the right backpressure wait.  Keeping it strong would add a third
    // owner next to the registry and the lease and break the §12 invariant that
    // the lease is the only thing keeping a facility alive -- worse, erasing the
    // entry under the executor mutex could then run ~AsyncFileWriter (and its
    // thread joins) while that mutex is held.
    struct JobControl {
        JobControl() = default;
        JobControl(
            std::shared_ptr<std::atomic<bool>> token,
            std::shared_ptr<sunpack::sevenzip::AsyncFileWriter> bound_writer)
            : cancel_token(std::move(token)), writer(std::move(bound_writer)) {}

        std::shared_ptr<std::atomic<bool>> cancel_token;
        std::weak_ptr<sunpack::sevenzip::AsyncFileWriter> writer;
    };

    static JobMetadata metadata_from_request(const std::string& request) noexcept {
        JobMetadata metadata;
        unsigned long long value = 0;
        metadata.request_id = json_string_field(request, "request_id", "");
        if (metadata.request_id.empty()) {
            metadata.request_id = json_string_field(request, "job_id", "");
        }
        metadata.foreground = json_string_field(request, "origin", "foreground") != "watch";
        metadata.volume_key = json_string_field(request, "output_volume_key", "");
        metadata.requires_writer = !json_bool_field(request, "dry_run", false);
        if (json_uint_field_in_object(request, "native_memory_reserve_bytes", &value)) {
            metadata.memory_reserve = (std::max)(
                std::size_t{1}, static_cast<std::size_t>((std::min)(
                    value,
                    static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)()))));
        }
        if (json_uint_field_in_object(request, "native_dictionary_reserve_bytes", &value)) {
            metadata.dictionary_reserve = static_cast<std::size_t>((std::min)(
                value,
                static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())));
            constexpr std::size_t decoder_scratch = 32U << 20;
            const std::size_t dictionary_memory = metadata.dictionary_reserve >
                    (std::numeric_limits<std::size_t>::max)() - decoder_scratch
                ? (std::numeric_limits<std::size_t>::max)()
                : metadata.dictionary_reserve + decoder_scratch;
            metadata.memory_reserve = (std::max)(metadata.memory_reserve, dictionary_memory);
        }
        return metadata;
    }

    bool can_admit_locked(const Job& job) const noexcept {
        if (!runtime_controller_.can_admit(
                active_jobs_,
                active_memory_,
                job.metadata.memory_reserve)) {
            return false;
        }
        return true;
    }

    std::size_t select_job_locked() const noexcept {
        for (std::size_t index = 0; index < queue_.size(); ++index) {
            if (queue_[index].metadata.foreground && can_admit_locked(queue_[index])) {
                return index;
            }
        }
        for (std::size_t index = 0; index < queue_.size(); ++index) {
            if (can_admit_locked(queue_[index])) {
                return index;
            }
        }
        return queue_.size();
    }

    void print_worker_event(
        const std::string& job_id,
        const char* event,
        const JobMetadata& metadata,
        std::size_t active_jobs = 0,
        std::size_t active_memory = 0
    ) const noexcept {
        if (job_id.empty()) {
            return;
        }
        print_json_line(
            "{\"type\":\"native_event\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"event\":\"" + event +
            "\",\"request_id\":\"" + json_escape(metadata.request_id) +
            "\",\"origin\":\"" + std::string(metadata.foreground ? "foreground" : "watch") +
            "\",\"output_volume_key\":\"" + json_escape(metadata.volume_key) +
            "\",\"requires_writer\":" + std::string(metadata.requires_writer ? "true" : "false") +
            ",\"memory_reserve_bytes\":" + std::to_string(metadata.memory_reserve) +
            ",\"dictionary_reserve_bytes\":" + std::to_string(metadata.dictionary_reserve) +
            ",\"active_jobs\":" + std::to_string(active_jobs) +
            ",\"active_memory_bytes\":" + std::to_string(active_memory) +
            "}");
    }

    void print_active_event(
        const Job& job,
        const char* event,
        std::size_t active_jobs,
        std::size_t active_memory
    ) const noexcept {
        print_worker_event(
            json_string_field(job.request, "job_id", ""),
            event,
            job.metadata,
            active_jobs,
            active_memory);
    }

    static const char* controller_phase_name(
        sunpack::sevenzip::NativeControllerPhase phase
    ) noexcept {
        using sunpack::sevenzip::NativeControllerPhase;
        switch (phase) {
        case NativeControllerPhase::Baseline: return "baseline";
        case NativeControllerPhase::Probe: return "probe";
        case NativeControllerPhase::Cooldown: return "cooldown";
        case NativeControllerPhase::Hold: return "hold";
        }
        return "baseline";
    }

    static const char* controller_decision_name(
        sunpack::sevenzip::NativeControllerDecision decision
    ) noexcept {
        using sunpack::sevenzip::NativeControllerDecision;
        switch (decision) {
        case NativeControllerDecision::None: return "none";
        case NativeControllerDecision::ActivityStarted: return "activity_started";
        case NativeControllerDecision::ActivityEnded: return "activity_ended";
        case NativeControllerDecision::SegmentStarted: return "segment_started";
        case NativeControllerDecision::SegmentInterrupted: return "segment_interrupted";
        case NativeControllerDecision::BaselineReady: return "baseline_ready";
        case NativeControllerDecision::ProbeUp: return "probe_up";
        case NativeControllerDecision::ProbeDown: return "probe_down";
        case NativeControllerDecision::Accepted: return "accepted";
        case NativeControllerDecision::RolledBack: return "rolled_back";
        case NativeControllerDecision::Holding: return "holding";
        case NativeControllerDecision::MemoryPaused: return "memory_paused";
        case NativeControllerDecision::MemoryResumed: return "memory_resumed";
        }
        return "none";
    }

    static const char* controller_load_state_name(
        sunpack::sevenzip::NativeLoadState state
    ) noexcept {
        using sunpack::sevenzip::NativeLoadState;
        switch (state) {
        case NativeLoadState::Idle: return "idle";
        case NativeLoadState::Unsaturated: return "unsaturated";
        case NativeLoadState::Saturated: return "saturated";
        }
        return "idle";
    }

    static const char* throughput_mode_name(
        sunpack::sevenzip::NativeThroughputMode mode
    ) noexcept {
        using sunpack::sevenzip::NativeThroughputMode;
        switch (mode) {
        case NativeThroughputMode::None: return "none";
        case NativeThroughputMode::Bytes: return "bytes";
        case NativeThroughputMode::Jobs: return "jobs";
        case NativeThroughputMode::Files: return "files";
        }
        return "none";
    }

    static void print_controller_event(
        const sunpack::sevenzip::NativeRuntimeSnapshot& snapshot,
        std::size_t queued_jobs,
        unsigned sampled_interval_ms,
        unsigned next_interval_ms,
        std::uint64_t discarded_write_bytes = 0,
        bool writer_idle = true
    ) noexcept {
        print_json_line(
            "{\"type\":\"native_controller\",\"queued_jobs\":" + std::to_string(queued_jobs) +
            ",\"active_limit\":" + std::to_string(snapshot.active_limit) +
            ",\"active_jobs\":" + std::to_string(snapshot.active_jobs) +
            ",\"active_memory_bytes\":" + std::to_string(snapshot.active_memory) +
            ",\"memory_budget_bytes\":" + std::to_string(snapshot.memory_budget) +
            ",\"memory_admission_paused\":" +
                std::string(snapshot.memory_admission_paused ? "true" : "false") +
            ",\"load_state\":\"" + controller_load_state_name(snapshot.load_state) + "\"" +
            ",\"phase\":\"" + controller_phase_name(snapshot.phase) + "\"" +
            ",\"decision\":\"" + controller_decision_name(snapshot.decision) + "\"" +
            ",\"throughput_mode\":\"" + throughput_mode_name(snapshot.throughput_mode) + "\"" +
            ",\"written_bytes_per_second\":" + std::to_string(snapshot.written_bytes_per_second) +
            ",\"completed_jobs_per_second\":" + std::to_string(snapshot.completed_jobs_per_second) +
            ",\"completed_files_per_second\":" + std::to_string(snapshot.completed_files_per_second) +
            ",\"pending_write_bytes\":" + std::to_string(snapshot.pending_write_bytes) +
            ",\"discarded_write_bytes\":" + std::to_string(discarded_write_bytes) +
            ",\"writer_idle\":" + std::string(writer_idle ? "true" : "false") +
            ",\"activity_session\":" + std::to_string(snapshot.activity_session) +
            ",\"saturated_segment\":" + std::to_string(snapshot.saturated_segment) +
            ",\"warm_start_used\":" + std::string(snapshot.warm_start_used ? "true" : "false") +
            ",\"resource_diagnostics_enabled\":" +
                std::string(snapshot.resource_diagnostics_enabled ? "true" : "false") +
            ",\"cpu_percent_valid\":" + std::string(snapshot.cpu_percent_valid ? "true" : "false") +
            ",\"cpu_percent\":" + std::to_string(snapshot.cpu_percent) +
            ",\"io_read_bytes_per_second\":" + std::to_string(snapshot.io_read_bytes_per_second) +
            ",\"io_write_bytes_per_second\":" + std::to_string(snapshot.io_write_bytes_per_second) +
            ",\"sampled_interval_ms\":" + std::to_string(sampled_interval_ms) +
            ",\"next_sample_interval_ms\":" + std::to_string(next_interval_ms) + "}");
    }

    static void print_controller_lifecycle_event(const char* event) noexcept {
        print_json_line(
            "{\"type\":\"native_controller\",\"event\":\"" +
            std::string(event) + "\"}");
    }

    // Facility lifecycle, so an empty `live_facilities` count can be told apart
    // from "the volume key never reached the writer".
    static void print_writer_facility_event(
        const char* event,
        const std::string& volume_key
    ) noexcept {
        print_json_line(
            "{\"type\":\"native_writer\",\"event\":\"" + std::string(event) +
            "\",\"volume_key\":\"" + json_escape(volume_key) + "\"}");
    }

    // ---------------------------------------------------------------------
    // 卷空间事件（§4.7）。
    //
    // ★ 通道必须是 `progress` + **真实 job_id** + 逐 job 发送：
    //   两条 dispatcher 都会丢弃 job_id 为空或查不到的事件，而
    //   `native_event_callback` 在生产代码里从未接线（死代码）。
    //
    // ★ 事件名与 Python 内部状态名**刻意不同名**：
    //      native: space_blocked / space_status / space_resumed
    //      Python: state["space_waiting"]
    //   避免"space_waiting 到底是状态转换、心跳还是诊断"的语义混乱。
    //
    // ★ 扇出对象是 `affected_jobs_`（job 集合），**不是** waiters_（线程集合）：
    //   probe owner 抢到许可后会从 waiters_ 移除，遍历 waiters_ 会让它永远收不到
    //   space_resumed；而卡在 producer backpressure 的 job 根本不会有 writer 线程
    //   进入 gate->wait()。
    // ---------------------------------------------------------------------
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
        // 低频诊断（默认 15s）。**不是**看门狗保活：Python 的 space_waiting 只由
        // space_blocked / space_resumed 驱动。
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

    // gate 的 ChangeSink 落地：既驱动 controller 的 discontinuity generation，
    // 又把事件扇出给每个 affected job。
    void on_space_transition(
        const sunpack::sevenzip::VolumeSpaceTransition& transition
    ) noexcept {
        using Kind = sunpack::sevenzip::VolumeSpaceTransition::Kind;
        switch (transition.kind) {
            case Kind::Blocked:
            case Kind::Resumed:
                // ★ 只有**真实的卷可写性变化**才推进 generation。
                //   `register_job()` 对新 job 的补发通知同样是 Kind::Blocked，但那只是
                //   事件补齐（磁盘可写环境没变）；若也算进去，"blocked 卷持续进入新
                //   job"会让自适应控制器反复 reset learning。
                //   Probing -> Blocked（probe 失败 / inconclusive）同样不推进。
                if (transition.discontinuity) {
                    space_epoch_.fetch_add(1, std::memory_order_acq_rel);
                }
                break;
            case Kind::Status:
            default:
                break;
        }
        print_volume_space_event(transition);
    }

#ifdef _WIN32
    static std::uint64_t filetime_ticks(const FILETIME& value) noexcept {
        ULARGE_INTEGER combined{};
        combined.LowPart = value.dwLowDateTime;
        combined.HighPart = value.dwHighDateTime;
        return combined.QuadPart;
    }
#endif

    static unsigned native_sample_interval_ms() noexcept {
        const char* value = std::getenv("SUNPACK_NATIVE_SAMPLE_INTERVAL_MS");
        if (!value || !*value) {
            return 500;
        }
        char* end = nullptr;
        const unsigned long configured = std::strtoul(value, &end, 10);
        if (end == value || *end != '\0' || configured == 0) {
            return 500;
        }
        return static_cast<unsigned>((std::max)(100UL, (std::min)(configured, 5000UL)));
    }

    sunpack::sevenzip::NativeRuntimeSample read_runtime_sample(
        bool include_resource_diagnostics
    ) noexcept {
        sunpack::sevenzip::NativeRuntimeSample sample;
#ifdef _WIN32
        MEMORYSTATUSEX memory_status{};
        memory_status.dwLength = sizeof(memory_status);
        if (GlobalMemoryStatusEx(&memory_status)) {
            sample.available_memory = static_cast<std::size_t>(
                (std::min)(
                    memory_status.ullAvailPhys,
                    static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())));
        }

        FILETIME idle_time{}, kernel_time{}, user_time{};
        if (include_resource_diagnostics &&
            GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
            const std::uint64_t idle = filetime_ticks(idle_time);
            const std::uint64_t kernel = filetime_ticks(kernel_time);
            const std::uint64_t user = filetime_ticks(user_time);
            if (has_system_cpu_sample_) {
                const std::uint64_t idle_delta = idle >= previous_idle_time_
                    ? idle - previous_idle_time_ : 0;
                const std::uint64_t total_delta =
                    (kernel >= previous_kernel_time_ ? kernel - previous_kernel_time_ : 0) +
                    (user >= previous_user_time_ ? user - previous_user_time_ : 0);
                if (total_delta > 0 && idle_delta <= total_delta) {
                    sample.cpu_percent = 100.0 * static_cast<double>(total_delta - idle_delta) /
                        static_cast<double>(total_delta);
                    sample.cpu_percent_valid = true;
                }
            }
            previous_idle_time_ = idle;
            previous_kernel_time_ = kernel;
            previous_user_time_ = user;
            has_system_cpu_sample_ = true;
        }

        IO_COUNTERS io_counters{};
        if (include_resource_diagnostics &&
            GetProcessIoCounters(GetCurrentProcess(), &io_counters)) {
            sample.io_read_bytes = io_counters.ReadTransferCount;
            sample.io_write_bytes = io_counters.WriteTransferCount;
            sample.io_counters_valid = true;
        }
#endif
        return sample;
    }

    void reset_system_cpu_sample() noexcept {
#ifdef _WIN32
        has_system_cpu_sample_ = false;
        previous_idle_time_ = 0;
        previous_kernel_time_ = 0;
        previous_user_time_ = 0;
#endif
    }

    unsigned controller_interval_ms(
        const sunpack::sevenzip::NativeRuntimeSnapshot& snapshot,
        std::size_t queued_jobs
    ) const noexcept {
        const unsigned configured = native_sample_interval_ms();
        if (queued_jobs == 0) {
            return (std::min)(5000U, (std::max)(1000U, configured));
        }
        if (queued_jobs > (std::max)(std::size_t{1}, snapshot.active_limit) * 2 &&
            snapshot.active_limit < worker_count_) {
            return 100;
        }
        return (std::min)(configured, 250U);
    }

    void controller_loop() noexcept {
        constexpr unsigned minimum_sample_interval_ms = 100;
        // Upper bound on a parked sleep: reclamation has to keep running while the
        // adaptive controller is idle, and a facility can appear from a worker
        // thread that never touches this condition variable (§5.5).
        constexpr auto parked_wait_cap = std::chrono::milliseconds(1000);
        unsigned next_interval_ms = native_sample_interval_ms();
        auto last_sample_at = std::chrono::steady_clock::now();
        auto idle_since = last_sample_at;
        bool monitor_parked = true;
        while (true) {
            std::unique_lock<std::mutex> wait_lock(mutex_);
            if (monitor_parked) {
                auto parked_wait = parked_wait_cap;
#ifdef _WIN32
                // ★ sticky hint：一旦进程出现过 blocked 卷，parked 睡眠上限就降到
                //   poll_interval。它**不是精确状态**（绝不能用 has_blocked_ +
                //   note_ready() 那种写法：多卷场景下"A 恢复 → 清零 → 仍 Blocked 的
                //   B 永远不再被 poll"）。它也绝不参与"要不要 poll 哪些 gate"——
                //   那个决定每个 tick 都从 registry.blocked_volumes() 重新拉。
                if (space_monitor_->ever_had_blocked() &&
                    writer_config_.space_poll_interval > std::chrono::milliseconds::zero()) {
                    parked_wait = (std::min)(parked_wait, writer_config_.space_poll_interval);
                }
                if (const auto deadline = writer_registry_->next_reap_deadline()) {
                    const auto now = std::chrono::steady_clock::now();
                    parked_wait = (std::min)(
                        parked_wait,
                        *deadline > now
                            ? std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now) +
                                std::chrono::milliseconds(1)
                            : std::chrono::milliseconds(1));
                }
#endif
                controller_condition_.wait_for(
                    wait_lock,
                    parked_wait,
                    [this] { return stopping_ || controller_recheck_; });
            } else {
                controller_condition_.wait_for(
                    wait_lock,
                    std::chrono::milliseconds(next_interval_ms),
                    [this] { return stopping_ || controller_recheck_; });
            }
            if (stopping_) {
                break;
            }
            controller_recheck_ = false;
            const auto now = std::chrono::steady_clock::now();
            // ★ 关键：**把 reap 和 space monitor 都移出 executor 的锁**。
            //
            //   reap_idle() 自己取 registry mutex_，不需要 executor mutex_
            //   （顺带修掉一个既有的"持锁过久"问题）。
            //
            //   space_monitor_->tick() 会通过 blocked_volumes() 取 registry mutex_，
            //   并可能执行一次很慢的 GetDiskFreeSpaceExW（离线 UNC / 坏盘可能卡几秒）。
            //   若在 mutex_ 内调用，submit() / cancel() / admission 会被全部堵住；
            //   锁序也会变成 executor → registry → gate，与 worker_loop 的
            //   executor → registry 叠加后，任何 gate → executor 的回调都会死锁。
            wait_lock.unlock();
#ifdef _WIN32
            // Driven from this thread rather than a reaper thread of its own: the
            // parked path above already wakes on the earliest reclaim deadline.
            for (const auto& volume : writer_registry_->reap_idle()) {
                print_writer_facility_event("writer_facility_reaped", volume);
            }
            // 采样器只在"进程曾经出现过 blocked 卷"之后才真正工作（sticky hint），
            // 因此在没有磁盘满的正常运行中这一行几乎零成本。
            space_monitor_->tick(now);
#endif
            wait_lock.lock();

            if (monitor_parked) {
                if (queue_.empty() && active_jobs_ == 0) {
                    continue;
                }
                sunpack::sevenzip::NativeThroughputCounters counters;
                std::uint64_t discarded_write_bytes = 0;
                bool writer_idle = true;
#ifdef _WIN32
                {
                    const auto metrics = writer_registry_->snapshot();
                    counters.accepted_bytes = metrics.meters.accepted_bytes;
                    counters.written_bytes = metrics.meters.written_bytes;
                    counters.completed_files = metrics.meters.completed_files;
                    counters.completed_jobs = metrics.meters.completed_jobs;
                    discarded_write_bytes = metrics.meters.discarded_bytes;
                    writer_idle = metrics.meters.pending_bytes == 0 && !metrics.any_active_jobs;
                }
#endif
                const double idle_seconds = std::chrono::duration<double>(
                    now - idle_since).count();
                runtime_controller_.begin_activity(counters, idle_seconds);
                // 刚从 parked 进入 active：begin_activity 已经 prime + reset 了
                // 学习状态，因此把 generation 基线对齐，避免多触发一次无用 rebase。
                last_seen_space_epoch_ = space_epoch_.load(std::memory_order_acquire);
                monitor_parked = false;
                last_sample_at = now - std::chrono::milliseconds(minimum_sample_interval_ms);
                reset_system_cpu_sample();
                const auto snapshot = runtime_controller_.snapshot(active_jobs_, active_memory_);
                const std::size_t queued_jobs = queue_.size();
                wait_lock.unlock();
                print_controller_lifecycle_event("activity_started");
                print_controller_event(
                    snapshot,
                    queued_jobs,
                    0,
                    controller_interval_ms(snapshot, queued_jobs),
                    discarded_write_bytes,
                    writer_idle);
            } else {
                wait_lock.unlock();
            }

            const double elapsed_seconds = std::chrono::duration<double>(now - last_sample_at).count();
            if (elapsed_seconds * 1000.0 < minimum_sample_interval_ms) {
                next_interval_ms = (std::max)(
                    1U,
                    minimum_sample_interval_ms - static_cast<unsigned>(elapsed_seconds * 1000.0));
                std::unique_lock<std::mutex> cooldown_lock(mutex_);
                if (controller_condition_.wait_for(
                        cooldown_lock,
                        std::chrono::milliseconds(next_interval_ms),
                        [this] { return stopping_; })) {
                    break;
                }
                continue;
            }
            const unsigned sampled_interval_ms = static_cast<unsigned>(elapsed_seconds * 1000.0);
            last_sample_at = now;
            const auto sample = read_runtime_sample(
                runtime_controller_.resource_diagnostics_enabled());
            sunpack::sevenzip::NativeThroughputCounters throughput;
            std::uint64_t discarded_write_bytes = 0;
            std::uint64_t pending_write_bytes = 0;
            bool writer_has_active_jobs = false;
#ifdef _WIN32
            {
                const auto metrics = writer_registry_->snapshot();
                throughput.accepted_bytes = metrics.meters.accepted_bytes;
                throughput.written_bytes = metrics.meters.written_bytes;
                throughput.completed_files = metrics.meters.completed_files;
                throughput.completed_jobs = metrics.meters.completed_jobs;
                discarded_write_bytes = metrics.meters.discarded_bytes;
                pending_write_bytes = metrics.meters.pending_bytes;
                writer_has_active_jobs = metrics.any_active_jobs;
            }
#endif
            // accepted == written is NOT an idle signal: a cancelled or failed
            // buffer leaves a permanent gap that never closes.  The pending gauge
            // is the correct byte-level source, but it can legitimately read zero
            // between chunks or after a cancelled job abandoned its staging, so a
            // writer is only idle when no job is registered either.
            const bool writer_idle = pending_write_bytes == 0 && !writer_has_active_jobs;
            bool parked = false;
            sunpack::sevenzip::NativeRuntimeSnapshot parked_snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (queue_.empty() && active_jobs_ == 0 && writer_idle) {
                    runtime_controller_.end_activity(throughput);
                    parked_snapshot = runtime_controller_.snapshot(0, 0);
                    controller_recheck_ = false;
                    monitor_parked = true;
                    idle_since = now;
                    parked = true;
                }
            }
            if (parked) {
                reset_system_cpu_sample();
                print_controller_event(
                    parked_snapshot, 0, sampled_interval_ms, 0, discarded_write_bytes, writer_idle);
                print_controller_lifecycle_event("activity_parked");
                continue;
            }
            bool changed = false;
            std::size_t queued_jobs = 0;
            sunpack::sevenzip::NativeRuntimeSnapshot snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_) {
                    break;
                }
                // ★ 外部不连续（卷可写集合变化）后的重建：必须在 observe() **之前**。
                //   last_seen_space_epoch_ 是**赋值**而不是自增，因此一个 tick 内
                //   17 → 19 只会 rebase 一次（对"累加多次"天然幂等）。
                //   rebase 必须带 current_counters：prime_counters() 是唯一更新
                //   previous_counters_ 的地方，缺它则第一个新 baseline 的 delta
                //   会跨越 discontinuity，学习仍被污染。
                const std::uint64_t space_epoch = space_epoch_.load(std::memory_order_acquire);
                if (space_epoch != last_seen_space_epoch_) {
                    last_seen_space_epoch_ = space_epoch;
                    changed = runtime_controller_.rebase_after_external_discontinuity(throughput);
                }
                queued_jobs = queue_.size();
                changed = runtime_controller_.observe(
                                sample,
                                throughput,
                                queued_jobs,
                                active_jobs_,
                                active_memory_,
                                elapsed_seconds) ||
                          changed;
                snapshot = runtime_controller_.snapshot(
                    active_jobs_, active_memory_);
            }
            next_interval_ms = controller_interval_ms(snapshot, queued_jobs);
            if (changed || snapshot.resource_diagnostics_enabled) {
                print_controller_event(snapshot, queued_jobs, sampled_interval_ms, next_interval_ms,
                    discarded_write_bytes, writer_idle);
            }
            if (changed) {
                condition_.notify_all();
            }
        }
    }

    // Fallback routing key when the request carried none.  Never share a fallback
    // bucket: a job whose volume is unknown gets its own isolated facility rather
    // than silently sharing another volume's writer (§2.3).
    static std::string synthetic_volume_key(const std::string& request) {
        const std::string job_id = json_string_field(request, "job_id", "");
        return job_id.empty() ? std::string("job:unidentified") : "job:" + job_id;
    }

    // Bind the facility to the job so a cancel wakes only that volume's writer
    // (§6.3).  Called before run_request, so the weak reference is valid for the
    // whole extraction.  Assigning a strong pointer into the weak field does not
    // extend the facility's lifetime: the lease held by worker_loop is the only
    // owner, and it outlives every cancel() that can observe this binding.
    void register_cancel_writer(
        const std::string& request,
        const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& writer
    ) noexcept {
        if (!writer) {
            return;
        }
        const std::string job_id = json_string_field(request, "job_id", "");
        if (job_id.empty()) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = cancel_tokens_.find(job_id);
        if (found != cancel_tokens_.end()) {
            found->second->writer = writer;
        }
    }

    void worker_loop() noexcept {
#ifdef _WIN32
        const HRESULT com_status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
#endif
        for (;;) {
            Job job;
            std::size_t admitted_jobs = 0;
            std::size_t admitted_memory = 0;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] {
                    return select_job_locked() < queue_.size() || (stopping_ && queue_.empty());
                });
                const std::size_t selected = select_job_locked();
                if (selected == queue_.size()) {
                    if (stopping_ && queue_.empty()) {
                        break;
                    }
                    continue;
                }
                auto iterator = queue_.begin() + static_cast<std::ptrdiff_t>(selected);
                job = std::move(*iterator);
                queue_.erase(iterator);
                active_jobs_ += 1;
                active_memory_ += job.metadata.memory_reserve;
                admitted_jobs = active_jobs_;
                admitted_memory = active_memory_;
            }
            print_active_event(job, "job_admitted", admitted_jobs, admitted_memory);
            print_active_event(job, "job_started", admitted_jobs, admitted_memory);
            int code = -100;
            try {
                if (job.metadata.requires_writer) {
                    // The lease lives in an explicit scope so it is released before
                    // the job is reported finished below.  That ordering gives the
                    // invariant the controller and the reaper rely on:
                    //   active_jobs_ == 0  =>  every finished job's lease is gone
                    // (§6.4)
                    const std::string key = job.metadata.volume_key.empty()
                        ? synthetic_volume_key(job.request)
                        : job.metadata.volume_key;
                    auto lease = writer_registry_->acquire(key);
                    if (lease.created_facility()) {
                        print_writer_facility_event("writer_facility_created", key);
                    }
                    register_cancel_writer(job.request, lease.writer_pointer());
                    // ★ affected_jobs_ 的注册点在 **volume lease scope**，不是
                    //   make_job / finish_job —— 根输出目录创建（满盘最常见的入口）
                    //   发生在 make_job 之前，否则那次满盘会开启 episode 却通知 0 个 job，
                    //   Python 看门狗会把"合法暂停"当成 no-progress 杀掉。
                    //
                    //   ⚠️ 必须声明在 lease **之后**：C++ 逆序析构保证
                    //      registration 先于 lease 析构 → 注销发生在 lease 释放之前。
                    //   job_id 此时已经可用（下面 job_finished 用的就是它）。
                    const std::string scope_job_id = json_string_field(job.request, "job_id", "");
                    sunpack::sevenzip::SpaceJobRegistration space_registration(lease, scope_job_id);
                    code = run_request(job.request, lease.writer_pointer(), job.cancel_token);
                } else {
                    // Dry runs write nothing: no facility, no writer threads, no
                    // buffers and no volume readiness gate (§6.2).
                    code = run_request(job.request, nullptr, job.cancel_token);
                }
            } catch (...) {
                code = -100;
            }
            const std::string job_id = json_string_field(job.request, "job_id", "");
            std::size_t remaining_jobs = 0;
            std::size_t remaining_memory = 0;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!job_id.empty()) {
                    cancel_tokens_.erase(job_id);
                }
                active_jobs_ = active_jobs_ > 0 ? active_jobs_ - 1 : 0;
                active_memory_ = active_memory_ >= job.metadata.memory_reserve
                    ? active_memory_ - job.metadata.memory_reserve : 0;
                remaining_jobs = active_jobs_;
                remaining_memory = active_memory_;
                any_job_failed_ = any_job_failed_ || code != 0;
                controller_recheck_ = true;
            }
            condition_.notify_all();
            controller_condition_.notify_one();
            print_active_event(job, "job_finished", remaining_jobs, remaining_memory);
            try {
                job.promise->set_value(code);
            } catch (...) {
            }
        }
#ifdef _WIN32
        if (com_status == S_OK || com_status == S_FALSE) {
            CoUninitialize();
        }
#endif
    }

    std::vector<std::thread> workers_;
    std::thread controller_thread_;
    // Process-wide write meters and the per-volume facilities.  The meters are
    // declared first so they outlive every writer: a reclaimed facility must never
    // take the aggregate counters with it (§3.1).
    //
    // ★ 声明顺序即析构顺序的逆序，这三项的顺序是**有约束的**：
    //     space_change_sink_ 捕获 this 并被 gate 长期持有
    //       ⇒ 必须在 writer_registry_ **之前**声明（后析构）
    //     writer_config_ 被 writer_registry_ 与 space_monitor_ 使用
    //       ⇒ 必须在两者之前声明
    //     space_monitor_ 的 BlockedProvider 捕获 this 并调用 writer_registry_
    //       ⇒ 必须在 writer_registry_ **之后**声明（先析构）
    sunpack::sevenzip::WriterMetersPtr writer_meters_;
    sunpack::sevenzip::VolumeSpaceChangeSink space_change_sink_;
    sunpack::sevenzip::AsyncWriterConfig writer_config_;
    sunpack::sevenzip::VolumeWriterRegistryPtr writer_registry_;
    std::unique_ptr<sunpack::sevenzip::VolumeSpaceMonitor> space_monitor_;
    // throughput environment discontinuity generation：任何可能让吞吐比较失真的
    // 空间状态变化都让它前进一次。controller 只问"自上次采样以来有没有发生过"，
    // 不关心发生了一次还是三次（因此 controller 侧是**赋值**而不是自增）。
    std::atomic<std::uint64_t> space_epoch_{0};
    std::uint64_t last_seen_space_epoch_ = 0;
    std::deque<Job> queue_;
    std::unordered_map<std::string, std::shared_ptr<JobControl>> cancel_tokens_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::condition_variable controller_condition_;
    const std::size_t worker_count_;
    const std::size_t memory_budget_;
    const std::size_t queue_capacity_;
    sunpack::sevenzip::NativeRuntimeControl runtime_controller_;
    std::size_t active_jobs_ = 0;
    std::size_t active_memory_ = 0;
    bool controller_recheck_ = false;
    bool any_job_failed_ = false;
    bool stopping_ = false;
#ifdef _WIN32
    bool has_system_cpu_sample_ = false;
    std::uint64_t previous_idle_time_ = 0;
    std::uint64_t previous_kernel_time_ = 0;
    std::uint64_t previous_user_time_ = 0;
#endif
};

int run_message(
    const std::string& request,
    NativeJobExecutor& executor
) {
    const std::string command = json_string_field(request, "worker_command", "");
    if (command == "cancel") {
        const std::string job_id = json_string_field(request, "job_id", "");
        const bool accepted = executor.cancel(job_id);
        print_json_line("{\"type\":\"cancel_ack\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"accepted\":" + std::string(accepted ? "true" : "false") + "}");
        return accepted ? 0 : 1;
    }
    if (command == "set_process_mode") {
        const std::string mode = json_string_field(request, "mode", "normal") == "background"
            ? "background"
            : "normal";
        const bool applied = apply_native_process_mode(mode);
        print_json_line("{\"type\":\"process_mode_ack\",\"mode\":\"" + mode +
            "\",\"applied\":" + std::string(applied ? "true" : "false") + "}");
        return applied ? 0 : 1;
    }
    if (command == "shutdown") {
        return 0;
    }
    // Native owns queued work. Keeping one future per accepted message would
    // reintroduce a Python-independent caller-side queue in the worker main.
    executor.submit(request);
    return 0;
}

int main() {
    const std::string requested_process_mode = requested_native_process_mode();
    const bool process_mode_applied = apply_native_process_mode(requested_process_mode);
    const auto resources = native_machine_resources();
    const auto sizing = sunpack::sevenzip::derive_native_sizing_plan(
        resources,
        configured_native_sizing_overrides());
    const auto runtime_config = configured_native_runtime_config(sizing);
    NativeJobExecutor executor(sizing, runtime_config);
    const bool sizing_overridden = sizing.thread_capacity_overridden ||
        sizing.initial_active_jobs_overridden || sizing.memory_budget_overridden;
    const char* exploration_strategy = runtime_config.exploration_strategy ==
            sunpack::sevenzip::NativeExplorationStrategy::Calibrated
        ? "calibrated"
        : runtime_config.exploration_strategy == sunpack::sevenzip::NativeExplorationStrategy::Full
            ? "full"
            : "rapid";
    print_json_line(
        "{\"type\":\"worker_ready\",\"sizing_mode\":\"" +
        std::string(sizing_overridden ? "overridden" : "dynamic") +
        "\",\"logical_processors\":" + std::to_string(resources.logical_processors) +
        ",\"total_memory_bytes\":" + std::to_string(resources.total_memory_bytes) +
        ",\"available_memory_bytes\":" + std::to_string(resources.available_memory_bytes) +
        ",\"memory_budget_bytes\":" + std::to_string(sizing.memory_budget_bytes) +
        ",\"thread_capacity\":" + std::to_string(sizing.thread_capacity) +
        ",\"initial_active_limit\":" + std::to_string(runtime_config.initial_active_jobs) +
        ",\"exploration_strategy\":\"" + exploration_strategy + "\"" +
        ",\"resource_diagnostics_enabled\":" +
            std::string(runtime_config.resource_diagnostics_enabled ? "true" : "false") +
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
        const bool shutdown = json_string_field(line, "worker_command", "") == "shutdown";
        const int code = run_message(line, executor);
        if (shutdown) {
            // 显式 shutdown：取消所有尚未完成的 job（这也是打破"满盘暂停"闭环的
            // 最小改动：满盘阻塞的 worker 必须先看到 terminal 条件才能被 join）。
            executor.stop();
            return code;
        }
    }
    // stdin EOF：一次性调用（`echo request | worker.exe`）的正常结束。
    // **排空**队列后再退出，不取消任何 job —— 与改动前逐字节一致。
    executor.stop(/*cancel_pending_jobs=*/false);
    return executor.had_job_failure() ? 1 : 0;
}
