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
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <new>
#include <mutex>
#include <deque>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "internal/sevenzip_status.hpp"
#include "internal/worker_wire.hpp"
#include <fcntl.h>
#include <io.h>
#include "internal/archive_operations.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/sevenzip_sdk.hpp"
#include "internal/native_memory.hpp"
#include "internal/extraction_replay.hpp"
#include "internal/native_cpu_budget.hpp"
#ifdef SUP7Z_DEBUG
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

std::wstring utf8_to_wide(std::string_view value) {
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

struct WorkerArchiveInput {
    sunpack::sevenzip::VolumeAttemptPlan volume_attempts;
    std::wstring archive_path;
    std::wstring format_hint;
    std::string open_mode;
    std::vector<std::wstring> part_paths;
    std::vector<std::wstring> canonical_names;
    std::string analyzed_missing_volume_evidence;
    // First absent number of a structured volume sequence (0 = contiguous).
    int missing_volume_number = 0;
    std::string validation_error;
    std::vector<sunpack::sevenzip::ExtractInputRange> ranges;
};

sunpack::sevenzip::ExtractArchiveResult password_candidate_failure(
    const sunpack::sevenzip::PasswordTestResult& probe,
    std::size_t candidate_count
) {
    using namespace sunpack::sevenzip;
    ExtractArchiveResult result;
    result.status = probe.status;
    result.backend_available = probe.backend_available;
    result.archive_type = probe.archive_type;
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

std::vector<sunpack::sevenzip::ExtractInputRange> parse_ranges_from_objects(
    const std::vector<std::string_view>& objects,
    std::string_view default_path
) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    ranges.reserve(objects.size());
    for (const auto object_frame : objects) {
        const wire::ObjectView object(object_frame);
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start =
            object.uint_field("start", &start);
        const bool has_end =
            object.uint_field("end", &end);
        const std::string_view path = object.string_field("path", default_path);
        if (path.empty() && default_path.empty()) {
            continue;
        }
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? default_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(std::move(range));
    }
    return ranges;
}

WorkerArchiveInput parse_archive_input_descriptor(const wire::ObjectView& request) {
    WorkerArchiveInput input;
    const wire::ObjectView descriptor = request.object_field("archive_input");
    if (!descriptor.valid()) {
        input.validation_error = "archive_input descriptor is required";
        return input;
    }
    const std::string_view entry_path = descriptor.string_field("entry_path", "");
    input.archive_path = utf8_to_wide(entry_path);
    const std::string_view mode = descriptor.string_field("open_mode", "file");
    input.open_mode = mode;
    input.format_hint = utf8_to_wide(descriptor.string_field("format_hint", ""));

    const auto attempts = descriptor.object_field("volume_attempts");
    if (attempts.valid()) {
        auto& plan = input.volume_attempts;
        attempts.uint_field("head_size_from_total", &plan.head_size_from_total);
        attempts.uint_field("minimum_size", &plan.minimum_size);
        plan.sources = parse_ranges_from_objects(attempts.array_field("sources"), "");
        for (auto raw : attempts.array_field("domains")) {
            std::vector<std::size_t> choices;
            if (!wire::ObjectView(raw).index_array_field("choices", choices) ||
                std::any_of(choices.begin(), choices.end(), [&](auto i) { return i >= plan.sources.size(); })) {
                input.validation_error = "invalid volume attempt domain"; return input;
            }
            plan.domains.push_back(std::move(choices));
        }
        for (auto raw : attempts.array_field("tail_totals")) {
            unsigned long long source = 0, total = 0;
            const wire::ObjectView entry(raw);
            if (!entry.uint_field("source", &source) || source >= plan.sources.size() ||
                !entry.uint_field("total", &total) || !total) {
                input.validation_error = "invalid volume tail total"; return input;
            }
            if (plan.tail_totals.empty()) plan.tail_totals.resize(plan.sources.size());
            plan.tail_totals[source] = total;
        }
        for (auto raw_layout : attempts.array_field("layouts")) {
            std::vector<sunpack::sevenzip::VolumeAttemptSlot> slots;
            unsigned long long previous = 0;
            std::unordered_set<std::wstring> names;
            const wire::ObjectView layout(raw_layout);
            for (auto raw_slot : layout.array_field("slots")) {
                const wire::ObjectView slot(raw_slot);
                unsigned long long number = 0;
                sunpack::sevenzip::VolumeAttemptSlot parsed;
                parsed.name = utf8_to_wide(slot.string_field("canonical_name", ""));
                unsigned long long domain = 0;
                if (!slot.uint_field("number", &number) || number <= previous || number > INT_MAX ||
                    (slots.empty() && number != 1) || parsed.name.empty() || !names.insert(parsed.name).second ||
                    !slot.uint_field("domain", &domain) || domain >= plan.domains.size()) {
                    input.validation_error = "invalid volume attempt slot"; return input;
                }
                parsed.number = static_cast<unsigned int>(number);
                parsed.domain = static_cast<std::size_t>(domain);
                previous = number;
                slots.push_back(std::move(parsed));
            }
            if (slots.empty()) { input.validation_error = "empty volume attempt layout"; return input; }
            unsigned long long minimum = 0;
            layout.uint_field("minimum_slots", &minimum);
            if (minimum && (minimum < 2 || minimum > slots.size() ||
                    slots.back().number != slots.size())) {
                input.validation_error = "invalid variable volume layout"; return input;
            }
            plan.minimum_slots.push_back(static_cast<std::size_t>(minimum));
            plan.layouts.push_back(std::move(slots));
        }
        if (plan.sources.empty() || plan.layouts.empty() ||
            std::any_of(plan.sources.begin(), plan.sources.end(), [](const auto& source) {
                return source.path.empty() || (source.has_end && source.end < source.start);
            })) { input.validation_error = "invalid volume attempt sources"; return input; }
        plan.prepare();
        // A composition plan supplies every range and canonical name used
        // during execution. The descriptor's fixed composition is redundant.
        return input;
    }

    const wire::ObjectView analysis = descriptor.object_field("analysis");
    const wire::ObjectView execution_analysis = analysis.object_field("execution");
    input.analyzed_missing_volume_evidence =
        execution_analysis.string_field("missing_volume_evidence", "");

    struct ParsedPart {
        int number;
        std::wstring path;
        std::wstring canonical_name;
        unsigned long long start = 0;
        unsigned long long end = 0;
        bool has_end = false;
    };
    if (mode == "concat_ranges") {
        input.ranges = parse_ranges_from_objects(descriptor.array_field("ranges"), entry_path);
        if (input.ranges.empty()) input.validation_error = "concat_ranges descriptor requires ranges";
        return input;
    }
    const auto part_objects = descriptor.array_field("parts");
    if (mode == "file_range") {
        input.ranges = parse_ranges_from_objects(part_objects, entry_path);
        if (input.ranges.empty()) {
            input.validation_error = "file_range descriptor requires canonical parts with extents";
        }
        return input;
    }
    const bool structured = mode == "native_volumes" || mode == "sfx_with_volumes";
    std::vector<ParsedPart> structured_parts;
    if (structured) structured_parts.reserve(part_objects.size());
    else input.part_paths.reserve(part_objects.size());
    for (const auto object_frame : part_objects) {
        const wire::ObjectView object(object_frame);
        const std::string_view path = object.string_field("path", "");
        if (path.empty()) continue;
        if (!structured) {
            input.part_paths.push_back(utf8_to_wide(path));
            continue;
        }
        unsigned long long number = 0;
        const std::string_view canonical_name = object.string_field("canonical_name", "");
        if (!object.uint_field("volume_number", &number) || number == 0 || number > INT_MAX ||
            canonical_name.empty()) {
            input.validation_error = "structured volume part requires volume_number and canonical_name";
            continue;
        }
        unsigned long long start = 0, end = 0;
        object.uint_field("start", &start);
        const bool has_end = object.uint_field("end", &end);
        if (has_end && end < start) input.validation_error = "structured volume extent is reversed";
        structured_parts.push_back({static_cast<int>(number), utf8_to_wide(path),
                                    utf8_to_wide(canonical_name), start, end, has_end});
    }
    if (structured) {
        const bool has_ranges = std::any_of(structured_parts.begin(), structured_parts.end(),
            [](const ParsedPart &part) { return part.start != 0 || part.has_end; });
        if (has_ranges) input.ranges.reserve(structured_parts.size());
        else input.part_paths.reserve(structured_parts.size());
        input.canonical_names.reserve(structured_parts.size());
        for (std::size_t index = 0; index < structured_parts.size(); ++index) {
            // Volume numbers are the Relations contract, so a gap is a proven
            // missing volume rather than a malformed request.  It is reported
            // before any stream is opened: concatenating the remaining parts
            // would shift every later byte and misreport the set as damaged.
            const bool head_ok = index != 0 || structured_parts[index].number == 1;
            const bool ordered = index == 0 || structured_parts[index].number > structured_parts[index - 1].number;
            if (!head_ok) input.missing_volume_number = 1;
            if (!ordered) {
                input.validation_error = "structured volume sequence must be ordered and unique";
                break;
            }
            if (input.missing_volume_number == 0 && index > 0 &&
                structured_parts[index].number != structured_parts[index - 1].number + 1) {
                input.missing_volume_number = structured_parts[index - 1].number + 1;
            }
            auto& part = structured_parts[index];
            if (has_ranges) input.ranges.push_back({std::move(part.path), part.start, part.end, part.has_end});
            else input.part_paths.push_back(std::move(part.path));
            input.canonical_names.push_back(std::move(part.canonical_name));
        }
        if (input.canonical_names.empty()) {
            input.validation_error = "structured volume descriptor has no parts";
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
    std::wstring output_dir;
    std::wstring password;
    std::wstring codepage;
    bool dry_run = false;
    bool password_verified = false;
    std::vector<std::wstring> password_candidates;
    WorkerArchiveInput archive_input;
};

WorkerRequest parse_worker_request(const std::string& request_frame) {
    const wire::ObjectView fields(request_frame);
    WorkerRequest request;
    request.worker_command = fields.string_field("worker_command", "");
    request.job_id = fields.string_field("job_id", "");
    request.request_id = fields.string_field("request_id", "");
    request.origin = fields.string_field("origin", "foreground");
    request.output_volume_key = fields.string_field("output_volume_key", "");
    request.process_mode = fields.string_field("mode", "normal");

    if (
        request.worker_command == "cancel" ||
        request.worker_command == "set_process_mode" ||
        request.worker_command == "shutdown"
    ) {
        return request;
    }

    request.output_dir = utf8_to_wide(fields.string_field("output_dir", ""));
    request.password = utf8_to_wide(fields.string_field("password", ""));
    request.codepage = utf8_to_wide(fields.string_field("codepage", ""));
    request.dry_run = fields.bool_field("dry_run", false);
    request.password_verified = fields.bool_field("password_verified", false);

    const auto candidates = fields.array_field("password_candidates");
    request.password_candidates.reserve(candidates.size());
    for (const auto candidate : candidates) {
        request.password_candidates.push_back(utf8_to_wide(wire::Reader(candidate).text()));
    }
    request.archive_input = parse_archive_input_descriptor(fields);
    return request;
}

std::mutex g_output_mutex;

void print_frame(const std::string& payload) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    wire::write(std::cout, payload);
    std::cout.flush();
}

void print_frames(const std::string& first, const std::string& second) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    wire::write(std::cout, first);
    wire::write(std::cout, second);
    std::cout.flush();
}

std::string status_to_string(sunpack::sevenzip::PasswordTestStatus status) {
    return sunpack::sevenzip::status_name(status);
}

std::string input_trace_wire(const sunpack::sevenzip::ExtractInputTrace& trace) {
    return wire::object() +
        wire::key("mode") + wire::text(wide_to_utf8(trace.mode)) +
        wire::key("virtual_size") + wire::number(trace.virtual_size) +
        wire::key("position") + wire::number(trace.position) +
        wire::key("max_position_seen") + wire::number(trace.max_position_seen) +
        wire::key("total_bytes_returned") + wire::number(trace.total_bytes_returned) +
        wire::key("read_file_call_count") + wire::number(trace.read_file_call_count) +
        wire::key("read_file_wall_ns") + wire::number(trace.read_file_wall_ns) +
        wire::key("read_file_max_wall_ns") + wire::number(trace.read_file_max_wall_ns) +
        wire::key("logical_read_call_count") + wire::number(trace.logical_read_call_count) +
        wire::key("sequential_read_bytes") + wire::number(trace.sequential_read_bytes) +
        wire::key("nonsequential_read_bytes") + wire::number(trace.nonsequential_read_bytes) +
        wire::key("sequential_run_count") + wire::number(trace.sequential_run_count) +
        wire::key("max_sequential_run_bytes") + wire::number(trace.max_sequential_run_bytes) +
        wire::key("seek_count") + wire::number(trace.seek_count) +
        wire::key("seek_forward_bytes") + wire::number(trace.seek_forward_bytes) +
        wire::key("seek_backward_bytes") + wire::number(trace.seek_backward_bytes) +
        wire::key("prefetch_enabled") + wire::boolean(trace.prefetch_enabled) +
        wire::key("prefetch_hit_count") + wire::number(trace.prefetch_hit_count) +
        wire::key("prefetch_miss_count") + wire::number(trace.prefetch_miss_count) +
        wire::key("prefetch_invalidation_count") + wire::number(trace.prefetch_invalidation_count) +
        wire::key("prefetch_consumer_wait_ns") + wire::number(trace.prefetch_consumer_wait_ns) +
        wire::key("read_error") + wire::boolean(trace.read_error) +
        wire::key("last_hresult") + wire::number(trace.last_hresult) +
        wire::key("last_win32_error") + wire::number(trace.last_win32_error) +
        (wire::key("last_read") + wire::object() + wire::key("virtual_offset")) + wire::number(trace.last_read_virtual_offset) +
        wire::key("source_path") + wire::text(wide_to_utf8(trace.last_source_path)) +
        wire::key("source_offset") + wire::number(trace.last_read_source_offset) +
        wire::key("range_index") + wire::number(trace.last_range_index) +
        wire::key("requested") + wire::number(trace.last_read_requested) +
        wire::key("returned") + wire::number(trace.last_read_returned) +
        (wire::end() + wire::key("last_seek") + wire::object() + wire::key("origin")) + wire::number(trace.last_seek_origin) +
        wire::key("offset") + wire::number(trace.last_seek_offset) +
        wire::key("new_position") + wire::number(trace.last_seek_new_position) +
        (wire::end() + wire::end());
}

// Bound each serialized event by bytes, including its routing envelope. The
// retained buffer is reused; no result-sized intermediate string is built.
class WorkerChunks {
public:
    WorkerChunks(const std::string& job_id, const char* type, const char* field)
        : prefix_((wire::object() + wire::key("type")) + wire::text(type) + wire::key("job_id") + wire::text(job_id) + wire::key("seq")),
          field_(field) {}

    void append(const std::string& row) {
        // A single large row is its own frame; chunk size is a batching target.
        if (count_ && buffer_.size() + 1 + row.size() + 2 > kChunkBytes) {
            flush();
        }
        if (!count_) {
            buffer_ += prefix_;
            buffer_ += wire::number(seq_);
            buffer_ += wire::key(field_);
            buffer_ += wire::array();
        }
        buffer_ += row;
        ++count_;
    }

    std::size_t finish() {
        flush();
        return seq_;
    }

private:
    void flush() {
        if (!count_) { return; }
        buffer_ += (wire::end() + wire::end());
        print_frame(buffer_);
        ++seq_;
        count_ = 0;
        buffer_.clear();
    }

    static constexpr std::size_t kChunkBytes = 512 * 1024;
    std::string prefix_;
    std::string_view field_;
    std::string buffer_;
    std::size_t seq_ = 0;
    std::size_t count_ = 0;
};

void append_output_item_trace(std::string& row, const sunpack::sevenzip::ExtractOutputItemTrace& item) {
    row.clear();
    row += wire::array();
    wire::append_number(row, item.index);
    wire::append_text(row, wide_to_utf8(item.path));
    wire::append_text(row, wide_to_utf8(item.output_path));
    row.push_back(item.is_dir ? wire::kTrue : wire::kFalse);
    row.push_back(item.encrypted ? wire::kTrue : wire::kFalse);
    wire::append_number(row, item.bytes_written);
    wire::append_number(row, item.expected_size);
    row.push_back(item.has_expected_size ? wire::kTrue : wire::kFalse);
    wire::append_number(row, item.source_crc32);
    row.push_back(item.has_source_crc32 ? wire::kTrue : wire::kFalse);
    wire::append_number(row, item.output_crc32);
    row.push_back(item.has_output_crc32 ? wire::kTrue : wire::kFalse);
    row.push_back(item.crc_verified ? wire::kTrue : wire::kFalse);
    wire::append_number(row, item.operation_result);
    wire::append_text(row, sunpack::sevenzip::operation_result_name(item.operation_result));
    wire::append_number(row, item.hresult);
    wire::append_number(row, item.win32_error);
    row.push_back(item.done ? wire::kTrue : wire::kFalse);
    row.push_back(item.failed ? wire::kTrue : wire::kFalse);
    row += wire::end();
}

std::size_t emit_output_trace_chunks(const std::string& job_id, const sunpack::sevenzip::ExtractOutputTrace& trace) {
    WorkerChunks chunks(job_id, "trace_chunk", "items");
    std::string row;
    row.reserve(256);
    for (const auto& item : trace.items) {
        append_output_item_trace(row, item);
        chunks.append(row);
    }
    return chunks.finish();
}

std::string output_trace_wire(const sunpack::sevenzip::ExtractOutputTrace& trace, std::size_t chunk_count) {
    return wire::object() +
        wire::key("total_bytes_written") + wire::number(trace.total_bytes_written) +
        wire::key("current_item_index") + wire::number(trace.current_item_index) +
        wire::key("current_item_path") + wire::text(wide_to_utf8(trace.current_item_path)) +
        wire::key("current_item_bytes_written") + wire::number(trace.current_item_bytes_written) +
        wire::key("last_write_size") + wire::number(trace.last_write_size) +
        wire::key("last_hresult") + wire::number(trace.last_hresult) +
        wire::key("last_win32_error") + wire::number(trace.last_win32_error) +
        wire::key("item_count") + wire::number(trace.items.size()) +
        wire::key("chunk_count") + wire::number(chunk_count) +
        wire::end();
}

#ifdef SUP7Z_DEBUG
std::string pipeline_timing_wire(const sunpack::sevenzip::ExtractPipelineTiming& timing) {
    return wire::object() +
        wire::key("pipeline_wall_ns") + wire::number(timing.pipeline_wall_ns) +
        wire::key("input_active_ns") + wire::number(timing.input_active_ns) +
        wire::key("compute_active_ns") + wire::number(timing.compute_active_ns) +
        wire::key("compute_cpu_ns") + wire::number(timing.compute_cpu_ns) +
        wire::key("output_active_ns") + wire::number(timing.output_active_ns) +
        wire::key("input_compute_overlap_ns") + wire::number(timing.input_compute_overlap_ns) +
        wire::key("input_output_overlap_ns") + wire::number(timing.input_output_overlap_ns) +
        wire::key("compute_output_overlap_ns") + wire::number(timing.compute_output_overlap_ns) +
        wire::key("all_overlap_ns") + wire::number(timing.all_overlap_ns) +
        wire::key("any_overlap_ns") + wire::number(timing.any_overlap_ns) +
        wire::key("idle_ns") + wire::number(timing.idle_ns) +
        wire::key("prepare_output_directory_ns") + wire::number(timing.prepare_output_directory_ns) +
        wire::key("prepare_format_candidates_ns") + wire::number(timing.prepare_format_candidates_ns) +
         wire::key("prepare_handler_create_ns") + wire::number(timing.prepare_handler_create_ns) +
        wire::key("prepare_stream_open_ns") + wire::number(timing.prepare_stream_open_ns) +
        wire::key("prepare_archive_open_ns") + wire::number(timing.prepare_archive_open_ns) +
        wire::key("prepare_item_probe_ns") + wire::number(timing.prepare_item_probe_ns) +
        wire::key("prepare_callback_setup_ns") + wire::number(timing.prepare_callback_setup_ns) +
        wire::key("prepare_output_finalize_ns") + wire::number(timing.prepare_output_finalize_ns) +
        wire::key("prepare_archive_close_ns") + wire::number(timing.prepare_archive_close_ns) +
        wire::end();
}
#endif

std::string verified_manifest_wire(const std::string& job_id, const sunpack::sevenzip::ExtractArchiveResult& result, bool validated) {
    WorkerChunks chunks(job_id, "manifest_chunk", "rows");
    unsigned int file_count = 0;
    unsigned long long total_size = 0;
    bool identity_paths = true;
    // The writer already supplies safe relative paths with generic separators.
    // Directory keys borrow that storage for the lifetime of this summary.
    // A file implies all its parents, but an explicit directory only counts itself.
    std::unordered_map<std::wstring_view, bool> directories;
    std::string row;
    row.reserve(256);
    for (const auto& item : result.output_trace.items) {
        const std::wstring_view output_path(item.output_path);
        if (item.is_dir) {
            if (!output_path.empty()) directories.try_emplace(output_path, false);
            continue;
        }
        auto parent = output_path;
        for (auto separator = parent.rfind(L'/'); separator != std::wstring_view::npos;
             separator = parent.rfind(L'/')) {
            parent = parent.substr(0, separator);
            auto& parents_counted = directories.try_emplace(parent, false).first->second;
            if (parents_counted) break;
            parents_counted = true;
        }
        ++file_count;
        total_size += item.bytes_written;
        const bool identity_path = item.path == item.output_path ||
            std::filesystem::path(item.path).lexically_normal().generic_wstring() == output_path;
        identity_paths = identity_paths && identity_path;
        row.clear();
        row += wire::array();
        wire::append_number(row, item.index);
        wire::append_text(row, wide_to_utf8(item.path));
        wire::append_text(row, identity_path ? std::string() : wide_to_utf8(item.output_path));
        wire::append_number(row, item.has_expected_size ? item.expected_size : item.bytes_written);
        wire::append_number(row, item.bytes_written);
        wire::append_number(row, item.has_source_crc32 ? 1 : 0);
        wire::append_number(row, item.source_crc32);
        wire::append_number(row, item.has_output_crc32 ? 1 : 0);
        wire::append_number(row, item.output_crc32);
        wire::append_number(row, item.crc_verified ? 1 : 0);
        wire::append_number(row, item.done ? 1 : item.failed ? 2 : 0);
        wire::append_number(row, item.has_mtime_ns ? 1 : 0);
        wire::append_number(row, item.mtime_ns);
        wire::append_text(row, std::string_view(reinterpret_cast<const char*>(item.magic.data()), item.magic.size()), wire::kBytes);
        row += wire::end();
        chunks.append(row);
    }
    const auto chunk_count = chunks.finish();
    const bool inventory_complete = validated && result.output_inventory_complete && file_count == result.files_written;
    return wire::object() +
        (wire::key("source") + wire::text("sevenzip_worker_extract")) +
        wire::key("validated") + wire::boolean(validated) +
        wire::key("item_count") + wire::number(result.item_count) +
        wire::key("file_count") + wire::number(file_count) +
        (wire::key("inventory") + wire::array()) + wire::number(inventory_complete ? 1 : 0) +
        wire::number(file_count) +
        wire::number(directories.size()) +
        wire::number(total_size) +
        wire::number(identity_paths ? 1 : 0) + wire::end() +
        wire::key("chunk_count") + wire::number(chunk_count) + wire::end();
}

std::string handler_attempts_wire(const std::vector<sunpack::sevenzip::ExtractHandlerAttempt>& attempts) {
    std::string out = wire::array();
    for (std::size_t index = 0; index < attempts.size(); ++index) {
        const auto& attempt = attempts[index];
        out += (wire::object() + wire::key("format")) + wire::text(wide_to_utf8(attempt.format)) +
            wire::key("created") + wire::boolean(attempt.created) +
            wire::key("opened") + wire::boolean(attempt.opened) +
            wire::key("create_hresult") + wire::number(attempt.create_hresult) +
            wire::key("open_hresult") + wire::number(attempt.open_hresult) + wire::end();
    }
    out += wire::end();
    return out;
}

std::string failed_item_wire(const sunpack::sevenzip::ExtractArchiveResult& result) {
    return wire::object() +
        wire::key("index") + wire::number(result.failed_item_index) +
        wire::key("path") + wire::text(wide_to_utf8(result.failed_item)) +
        wire::key("bytes_written") + wire::number(result.failed_item_bytes_written) +
        wire::key("operation_result") + wire::number(result.operation_result) +
        wire::key("operation_result_name") + wire::text(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        wire::end();
}

std::string diagnostics_wire(const sunpack::sevenzip::ExtractArchiveResult& result, std::size_t trace_chunks) {
    return wire::object() +
        wire::key("failure_stage") + wire::text(result.failure_stage) +
        wire::key("failure_kind") + wire::text(result.failure_kind) +
        wire::key("hresult") + wire::number(result.hresult) +
        wire::key("operation_result") + wire::number(result.operation_result) +
        wire::key("operation_result_name") + wire::text(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        wire::key("missing_volume_suspected") + wire::boolean(result.missing_volume_suspected) +
        wire::key("missing_volume_evidence") + wire::text(result.missing_volume_evidence) +
        wire::key("missing_volume_name") + wire::text(wide_to_utf8(result.missing_volume_name)) +
        wire::key("password_candidate_batch") + wire::boolean(result.password_candidate_batch) +
        wire::key("password_candidate_direct") + wire::boolean(result.password_candidate_direct) +
        wire::key("password_candidates_all_rejected") + wire::boolean(result.password_candidates_all_rejected) +
        wire::key("password_candidate_count") + wire::number(result.password_candidate_count) +
        wire::key("password_attempts") + wire::number(result.password_attempts) +
        wire::key("matched_index") + wire::number(result.matched_index) +
        wire::key("handler_attempts") + handler_attempts_wire(result.handler_attempts) +
        wire::key("input_trace") + input_trace_wire(result.input_trace) +
        wire::key("output_trace") + output_trace_wire(result.output_trace, trace_chunks) +
        wire::key("failed_item") + failed_item_wire(result) +
        wire::end();
}

}  // namespace

constexpr int kMemoryRetry = -102;

bool extraction_rejects_password(const sunpack::sevenzip::ExtractArchiveResult& result) {
    // With a complete callback inventory, rejection by every eligible encrypted
    // member also proves rejection by whichever member the fallback would test.
    // Reuse decoder receipts; do not parse or rediscover the archive here.
    if (!result.item_count || result.output_trace.items.size() != result.item_count) return false;
    bool tested = false;
    for (const auto& item : result.output_trace.items) {
        if (!item.encrypted || item.is_dir || (item.has_expected_size && item.expected_size == 0)) continue;
        tested = true;
        if (!sunpack::sevenzip::looks_wrong_password(S_OK, item.operation_result, true)) return false;
    }
    return tested;
}

int interrupted_result(const std::string& job_id) {
    // The attempt token also stops work for memory reclamation. Only the
    // executor's persistent user token decides whether a parked job is canceled.
    const auto* memory = sunpack::sevenzip::current_native_memory_job();
    if (memory && memory->revoked.load(std::memory_order_acquire)) return kMemoryRetry;
    print_frame(
        (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
        (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("cancelled") + wire::key("failure_stage") + wire::text("native_cancel") + wire::key("failure_kind") + wire::text("cancelled") + wire::key("message") + wire::text("native job was cancelled") + wire::end()));
    return -101;
}

// Called only for a candidate transaction whose output was initially empty.
// Extraction has already drained and closed every writer before this point.
std::error_code discard_candidate_output(const std::wstring& output_dir) {
    const std::filesystem::path root(sunpack::sevenzip::win32_extended_path(output_dir));
    std::error_code error;
    std::filesystem::remove_all(root, error);
    if (!error || error != std::errc::permission_denied) return error;
    // Archive metadata can make a successfully written plain sibling readonly.
    // Match the ordinary output cleanup policy, without following reparse dirs.
    const auto writable = [](const std::filesystem::path& path) {
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
    };
    writable(root);
    std::filesystem::recursive_directory_iterator it(root, error), end;
    while (!error && it != end) {
        writable(it->path());
        it.increment(error);
    }
    if (!error) std::filesystem::remove_all(root, error);
    return error;
}

void select_volume_attempt(const WorkerArchiveInput& source,
                           const sunpack::sevenzip::VolumeAttemptCursor& cursor,
                           WorkerArchiveInput& input) {
    const auto& slots = source.volume_attempts.layouts[cursor.layout];
    const auto count = cursor.selected.size();
    input.ranges.resize(count);
    input.canonical_names.resize(count);
    input.missing_volume_number = 0;
    unsigned int previous = 0;
    for (std::size_t i = 0; i < count; ++i) {
        input.ranges[i] = source.volume_attempts.sources[cursor.selected[i]];
        input.canonical_names[i] = slots[i].name;
        if (!input.missing_volume_number && slots[i].number != previous + 1)
            input.missing_volume_number = static_cast<int>(previous + 1);
        previous = slots[i].number;
    }
    input.archive_path = input.ranges.front().path;
    if (input.missing_volume_number) return;
    const auto total = source.volume_attempts.tail_totals.empty()
        ? source.volume_attempts.head_size_from_total
        : source.volume_attempts.tail_totals[cursor.selected.back()];
    if (total) {
        auto length = total;
        for (std::size_t i = 1; i < input.ranges.size(); ++i) {
            const auto& range = input.ranges[i];
            if (!range.has_end || range.end - range.start >= length) { input.missing_volume_number = 1; return; }
            length -= range.end - range.start;
        }
        auto& head = input.ranges.front();
        if (!head.has_end || length > head.end - head.start) { input.missing_volume_number = 1; return; }
        head.end = head.start + length;
    }
}

bool uncertain_volume_password(const sunpack::sevenzip::ExtractArchiveResult& result,
                               const sunpack::sevenzip::ExtractionReplay& replay) {
    using namespace sunpack::sevenzip;
    return result.encrypted && !result.password_crc_proven &&
        !result.input_trace.read_error && result.status != PasswordTestStatus::Error &&
        (result.failure_stage == "item_extract" || result.failure_stage == "archive_open") &&
        (result.password_rejected || result.operation_result == kOpWrongPassword ||
         result.operation_result == kOpCrcError || result.operation_result == kOpDataError ||
         result.operation_result == kOpUnexpectedEnd || result.operation_result == kOpHeadersError) &&
        replay.uncertain_read.load(std::memory_order_relaxed);
}

bool volume_composition_failure(const sunpack::sevenzip::ExtractArchiveResult& result,
                                const sunpack::sevenzip::ExtractionReplay& replay,
                                bool password_verified) {
    using namespace sunpack::sevenzip;
    if ((result.status == PasswordTestStatus::Ok && result.command_ok) ||
        ((result.wrong_password || result.password_rejected) && !password_verified &&
         !result.password_crc_proven && !uncertain_volume_password(result, replay)) ||
        (result.encrypted && !result.password_crc_proven && !password_verified && !uncertain_volume_password(result, replay)) ||
        result.unsupported_method || result.status == PasswordTestStatus::BackendUnavailable ||
        result.status == PasswordTestStatus::Error ||
        (result.input_trace.read_error && result.missing_volume_evidence != "open_volume_file_missing")) return false;
    if (result.missing_volume) return true;
    if (result.failure_stage != "archive_open" && result.failure_stage != "item_extract") return false;
    if (result.failure_kind != "structure_recognition" && result.failure_kind != "checksum_error" &&
        result.failure_kind != "data_error" && result.failure_kind != "corrupted_data" && result.failure_kind != "headers_error" &&
        !((password_verified || result.password_crc_proven || uncertain_volume_password(result, replay)) && result.failure_kind == "encrypted_or_wrong_password") &&
        result.failure_kind != "unexpected_end" && result.failure_kind != "missing_volume_or_tail") return false;
    // Binary readers record whether a variable source/range participated.
    // Seeks, fixed tails and failures confined to the fixed head are not proof.
    return replay.uncertain_read.load(std::memory_order_relaxed);
}

int run_request(
    const WorkerRequest& request,
    // The job's output-volume write facility, borrowed from the registry lease held by worker_loop; null for dry runs.
    const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& shared_writer = nullptr,
    const std::shared_ptr<std::atomic<bool>>& cancel_token = nullptr
) {
    using namespace sunpack::sevenzip;

    const std::string& job_id = request.job_id;
    if (auto *memory = current_native_memory_job(); memory && memory->revoked.load(std::memory_order_acquire))
        return kMemoryRetry;
    if (cancel_token && cancel_token->load(std::memory_order_acquire)) {
        return interrupted_result(job_id);
    }

    const std::wstring& archive_path = request.archive_input.archive_path;
    const std::wstring& output_dir = request.output_dir;
    const std::wstring& password = request.password;
    const std::wstring& format_hint = request.archive_input.format_hint;
    const std::string& open_mode = request.archive_input.open_mode;
    const std::wstring& codepage = request.codepage;
    const bool dry_run = request.dry_run;
    const std::vector<std::wstring>& password_candidates = request.password_candidates;
    if (archive_path.empty() || (!dry_run && output_dir.empty())) {
        print_frame(
            (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
            (wire::key("status") + wire::text("error") + wire::key("category") + wire::text("invalid_request") + wire::key("message") + wire::text("archive_path is required; output_dir is required unless dry_run is true") + wire::end()));
        return 2;
    }

    auto last_progress_emit = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    unsigned int coalesced_progress_events = 0;
    bool extract_started = false;
    auto *cpu_job_context = sunpack::sevenzip::current_native_cpu_job_context();
    const bool volume_trials = !request.archive_input.volume_attempts.layouts.empty();
    auto progress = [&job_id, last_progress_emit, coalesced_progress_events, extract_started, cpu_job_context, volume_trials](const ExtractProgressEvent& event) mutable {
            if (volume_trials && event.event == "item_failed") return;
            const auto now = std::chrono::steady_clock::now();
            if (!extract_started && event.completed_bytes > 0) {
                extract_started = true;
                print_frame(
                    (wire::object() + wire::key("type") + wire::text("progress") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("event") + wire::text("extract_started")) +
                    wire::key("completed_bytes") + wire::number(event.completed_bytes) +
                    wire::key("total_bytes") + wire::number(event.total_bytes) +
                    wire::key("item_index") + wire::number(event.item_index) +
                    wire::key("item_path") + wire::text(wide_to_utf8(event.item_path)) +
                    wire::key("coalesced_events") + wire::number(coalesced_progress_events) + wire::end());
                const auto cpu = cpu_job_context
                    ? cpu_job_context->snapshot()
                    : sunpack::sevenzip::NativeCpuJobSnapshot{};
                print_frame(
                    (wire::object() + wire::key("type") + wire::text("native_cpu") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("event") + wire::text("decoder_started")) +
                    wire::key("decoder_cpu_credits") + wire::number(1 + cpu.current_extra_credits) +
                    wire::key("current_decoder_extra_credits") + wire::number(cpu.current_extra_credits) +
                    wire::key("peak_decoder_extra_credits") + wire::number(cpu.peak_extra_credits) +
                    wire::key("decoder_parallel") + wire::boolean(cpu.current_extra_credits) +
                    wire::end());
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
            print_frame(
                (wire::object() + wire::key("type") + wire::text("progress") + wire::key("job_id")) + wire::text(job_id) +
                wire::key("event") + wire::text(event.event) +
                wire::key("completed_bytes") + wire::number(event.completed_bytes) +
                wire::key("total_bytes") + wire::number(event.total_bytes) +
                wire::key("item_index") + wire::number(event.item_index) +
                wire::key("item_path") + wire::text(wide_to_utf8(event.item_path)) +
                wire::key("coalesced_events") + wire::number(coalesced_progress_events) + wire::end());
            last_progress_emit = now;
            coalesced_progress_events = 0;
    };

    if (!request.archive_input.validation_error.empty()) {
        print_frame(
            (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
            (wire::key("status") + wire::text("error") + wire::key("category") + wire::text("invalid_request") + wire::key("message")) +
            wire::text(request.archive_input.validation_error) + wire::end());
        return 2;
    }
    auto* volume_replay = current_extraction_replay;
    WorkerArchiveInput selected_input;
    if (volume_trials) {
        auto& cursor = volume_replay->volumes;
        if (!cursor.started) {
            cursor.reserve(request.archive_input.volume_attempts);
            std::error_code error;
            const auto root = std::filesystem::path(win32_extended_path(output_dir));
            const bool output_owned = dry_run ||
                ((!std::filesystem::exists(root, error) || std::filesystem::is_empty(root, error)) && !error);
            if (!output_owned) {
                print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("status") + wire::text("failed") + wire::key("failure_stage") + wire::text("output_prepare") + wire::key("failure_kind") + wire::text("output_filesystem") + wire::key("message") + wire::text("volume composition trials require an empty output directory") + wire::end()));
                return 2;
            }
            cursor.started = true;
        }
    }
    const auto& archive_input = volume_trials ? selected_input : request.archive_input;
    auto extract_with_password = [&](const std::wstring& selected_password) {
        // The callback is synchronous and its emit() serializes calls. Each
        // password/composition keeps its own progress counters on this stack.
        auto attempt_progress = progress;
        return extract_archive(archive_input.archive_path, archive_input.part_paths, archive_input.ranges,
            format_hint, selected_password, output_dir, codepage, std::ref(attempt_progress), dry_run,
            archive_input.canonical_names, open_mode == "native_volumes", shared_writer, cancel_token);
    };

    ExtractArchiveResult result;
    for (;;) {
        if (volume_trials) {
            auto& cursor = volume_replay->volumes;
            if (cursor.needs_next) {
                if (!cursor.next(request.archive_input.volume_attempts, cancel_token.get())) {
                    if (cancel_token && cancel_token->load(std::memory_order_acquire)) return interrupted_result(job_id);
                    result.status = PasswordTestStatus::Damaged;
                    const bool ambiguous = volume_replay->volume_password_ambiguous;
                    result.missing_volume = !ambiguous;
                    result.damaged = true;
                    result.wrong_password = result.password_rejected = result.password_candidates_all_rejected = false;
                    result.missing_volume_suspected = false;
                    result.missing_volume_evidence = ambiguous ? "" : "volume_attempts_exhausted";
                    if (result.failure_stage.empty()) result.failure_stage = "archive_open";
                    result.failure_kind = ambiguous ? "password_or_volume_inconclusive" : "missing_volume";
                    result.message = ambiguous ? "password or volume composition remains unconfirmed" :
                        "no supplied volume composition completed the archive";
                    break;
                }
                cursor.discard_pending = cursor.attempts > 1;
                result = ExtractArchiveResult{};
            }
            if (cursor.discard_pending) {
                if (!dry_run) {
                    const auto error = discard_candidate_output(output_dir);
                    if (error) {
                        result.status = PasswordTestStatus::Error;
                        result.failure_stage = "candidate_cleanup";
                        result.failure_kind = "output_filesystem";
                        result.message = error.message();
                        break;
                    }
                }
                volume_replay->clear_output();
                volume_replay->uncertain_read.store(false, std::memory_order_relaxed);
                volume_replay->candidate_index = 0;
                volume_replay->volume_password_uncertain = false;
                volume_replay->candidates_started = volume_replay->candidate_output_owned = volume_replay->candidate_discard_pending = false;
                cursor.discard_pending = false;
            }
            select_volume_attempt(request.archive_input, cursor, selected_input);
            volume_replay->uncertain_ranges.clear();
            volume_replay->uncertain_paths.clear();
            unsigned long long offset = 0;
            bool variable_offset = false;
            for (std::size_t i = 0; i < selected_input.ranges.size(); ++i) {
                const auto& range = selected_input.ranges[i];
                const auto length = range.has_end ? (std::min)(range.end - range.start, UINT64_MAX - offset) : UINT64_MAX - offset;
                const auto& variation = request.archive_input.volume_attempts.variation[i];
                const bool variable = variation.variable;
                const bool variable_length = variation.variable_length || variation.length != length;
                if (variable || variable_offset)
                    volume_replay->uncertain_ranges.emplace_back(offset, offset + length);
                if (variable)
                    volume_replay->uncertain_paths.insert(range.path);
                variable_offset |= variable_length;
                offset += length;
            }
        }
        if (archive_input.missing_volume_number > 0) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.missing_volume = true;
            result.missing_volume_suspected = false;
            result.missing_volume_evidence = "structured_volume_gap";
            result.failure_stage = "archive_open";
            result.failure_kind = "missing_volume";
            result.message = "structured volume " + std::to_string(archive_input.missing_volume_number) + " is missing";
        } else if (password_candidates.empty()) {
            result = extract_with_password(password);
        } else {
            auto *replay = current_extraction_replay;
            if (password_candidates.size() > 1 && replay && !replay->candidates_started) {
                replay->candidates_started = true;
                std::error_code error;
                const auto root = std::filesystem::path(win32_extended_path(output_dir));
                replay->candidate_output_owned = !dry_run &&
                    (!std::filesystem::exists(root, error) || std::filesystem::is_empty(root, error)) && !error;
            }
            // Existing outputs belong to a continuation/user. Keep the read-only
            // diagnostic fallback there; fresh outputs can confirm by extracting.
            const bool direct_candidates = password_candidates.size() == 1 ||
                (replay && replay->candidate_output_owned);
            if (!direct_candidates) {
                const auto probe = test_password_batch(archive_input.archive_path, archive_input.part_paths, archive_input.ranges,
                    format_hint, password_candidates.data(), password_candidates.size(), archive_input.canonical_names);
                if (probe.status != PasswordTestStatus::Ok || probe.matched_index < 0 ||
                    static_cast<std::size_t>(probe.matched_index) >= password_candidates.size()) {
                    result = password_candidate_failure(probe, password_candidates.size());
                } else {
                    result = extract_with_password(password_candidates[probe.matched_index]);
                    result.password_candidate_batch = true;
                    result.password_candidate_count = static_cast<unsigned int>(password_candidates.size());
                    result.password_attempts = probe.attempts;
                    result.matched_index = probe.matched_index;
                }
            } else {
                std::size_t index = replay ? replay->candidate_index : 0;
                while (index < password_candidates.size() || (replay && replay->candidate_discard_pending)) {
                    if (replay && replay->candidate_discard_pending) {
                        const auto error = discard_candidate_output(output_dir);
                        if (error) {
                            result = ExtractArchiveResult{};
                            result.backend_available = true;
                            result.status = PasswordTestStatus::Error;
                            result.failure_stage = "candidate_cleanup";
                            result.failure_kind = "output_filesystem";
                            result.message = error.message();
                            break;
                        }
                        replay->clear_output();
                        replay->candidate_discard_pending = false;
                        replay->candidate_index = ++index;
                        continue;
                    }
                    if (cancel_token && cancel_token->load(std::memory_order_acquire)) break;
                    // Confirmation shares the real extraction and its CRC receipts.
                    // Only ambiguous failures need the existing read-only probe.
                    result = extract_with_password(password_candidates[index]);
                    const bool direct_ok = result.status == PasswordTestStatus::Ok && result.command_ok;
                    const bool uncertain_password = volume_trials && uncertain_volume_password(result, *volume_replay);
                    if (uncertain_password) volume_replay->volume_password_uncertain = true;
                    // ENC authenticates the password during Open; later MAC/CRC failures are data damage.
                    if (!direct_ok && !uncertain_password && result.encrypted && result.archive_type != L"enc" &&
                        !result.password_crc_proven &&
                        !(cancel_token && cancel_token->load(std::memory_order_acquire)) &&
                        result.status != PasswordTestStatus::Error && result.failure_kind != "resource_unavailable" &&
                        !(current_native_memory_job() && current_native_memory_job()->revoked.load(std::memory_order_acquire)) &&
                        !(current_native_memory_job() && current_native_memory_job()->denied.load(std::memory_order_acquire)) &&
                        !(result.status == PasswordTestStatus::WrongPassword && result.operation_result == kOpWrongPassword)) {
                        if (extraction_rejects_password(result) ||
                            test_password_batch(archive_input.archive_path, archive_input.part_paths, archive_input.ranges,
                                format_hint, &password_candidates[index], 1, archive_input.canonical_names).status == PasswordTestStatus::WrongPassword) {
                            result.status = PasswordTestStatus::WrongPassword;
                            result.encrypted = true;
                            result.wrong_password = true;
                            result.password_rejected = true;
                            result.password_candidates_all_rejected = true;
                            result.failure_stage = "password_probe";
                            result.failure_kind = "wrong_password";
                            result.operation_result = kOpWrongPassword;
                            result.message = "wrong password";
                        }
                    }
                    result.password_candidate_direct = true;
                    result.password_candidate_count = static_cast<unsigned int>(password_candidates.size());
                    result.password_attempts = password_candidates.size() == 1 && direct_ok ? 0 : static_cast<int>(index + 1);
                    result.matched_index = direct_ok ? static_cast<int>(index) : -1;
                    result.password_candidates_all_rejected =
                        result.password_candidates_all_rejected || result.wrong_password || result.password_rejected;
                    if (direct_ok || (!result.password_candidates_all_rejected && !uncertain_password) || password_candidates.size() == 1 ||
                        (cancel_token && cancel_token->load(std::memory_order_acquire))) break;
                    result.password_candidates_all_rejected = false;
                    replay->candidate_discard_pending = true;
                }
                if (index == password_candidates.size()) {
                    PasswordTestResult rejected;
                    rejected.status = PasswordTestStatus::WrongPassword;
                    rejected.backend_available = true;
                    rejected.attempts = static_cast<int>(password_candidates.size());
                    rejected.message = "wrong password";
                    result = password_candidate_failure(rejected, password_candidates.size());
                }
            }
        }

        if (auto *memory = current_native_memory_job()) {
            if ((result.failure_kind == "resource_unavailable" ||
                 (memory->denied.load(std::memory_order_acquire) && !(result.status == PasswordTestStatus::Ok && result.command_ok))) &&
                !memory->revoked.load(std::memory_order_acquire))
                memory->owner.retry(*memory);
            // An interrupted attempt is internal. Never publish its provisional
            // damage/password/output errors or a final result to the caller.
            if (memory->revoked.load(std::memory_order_acquire) && !(result.status == PasswordTestStatus::Ok && result.command_ok)) return kMemoryRetry;
        }

        if (cancel_token && cancel_token->load(std::memory_order_acquire)) return interrupted_result(job_id);

        if (volume_trials && (uncertain_volume_password(result, *volume_replay) ||
            (volume_replay->volume_password_uncertain && result.password_candidates_all_rejected))) {
            if (!request.password_verified) volume_replay->volume_password_ambiguous = true;
            result.status = PasswordTestStatus::Damaged;
            result.wrong_password = result.password_rejected = result.password_candidates_all_rejected = false;
            result.failure_stage = "item_extract";
            result.failure_kind = "encrypted_or_wrong_password";
            result.operation_result = kOpDataError;
        }
        if (!volume_trials || !volume_composition_failure(result, *volume_replay, request.password_verified)) break;
        if (archive_input.missing_volume_number > 0 &&
            std::none_of(request.archive_input.volume_attempts.layouts.begin(), request.archive_input.volume_attempts.layouts.end(),
                [&](const auto& layout) { return std::any_of(layout.begin(), layout.end(), [&](const auto& slot) {
                    return slot.number == static_cast<unsigned int>(archive_input.missing_volume_number);
                }); })) break;
        auto& cursor = volume_replay->volumes;
        // Every composition of a sparse layout is missing the same slot.
        // Slot 1 instead denotes a candidate-dependent carrier trim failure.
        if (archive_input.missing_volume_number > 1) cursor.skip_layout();
        cursor.needs_next = true;
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
    std::string volume_attempt_fields;
    if (volume_trials) {
        const auto& cursor = volume_replay->volumes;
        volume_attempt_fields = wire::key("volume_attempts") + wire::number(cursor.attempts);
        if (ok) {
            volume_attempt_fields += (wire::key("volume_selection") + wire::object() + wire::key("layout")) + wire::number(cursor.layout) + (wire::key("sources") + wire::array());
            for (std::size_t i = 0; i < cursor.selected.size(); ++i) {
                volume_attempt_fields += wire::number(cursor.selected[i]);
            }
            volume_attempt_fields += (wire::end() + wire::end());
        }
    }
    const auto manifest_summary = verified_manifest_wire(job_id, result, ok && !dry_run);
    const auto trace_chunks = (!ok || dry_run) ? emit_output_trace_chunks(job_id, result.output_trace) : 0;
    const std::string failure_fields = ok ? "" :
        wire::key("failure_stage") + wire::text(result.failure_stage) +
        wire::key("failure_kind") + wire::text(result.failure_kind) +
        wire::key("hresult") + wire::number(result.hresult);
    const std::string diagnostic_fields = (!ok || dry_run) ?
        wire::key("diagnostics") + diagnostics_wire(result, trace_chunks) : "";
    const auto &sr = result.stream_receipt;
    const std::string stream_receipt_field = result.has_stream_receipt ?
        (wire::key("stream_receipt") + wire::object() + wire::key("format")) + wire::text(sr.format) + wire::key("input_bytes") + wire::number(sr.input_bytes) +
        wire::key("output_bytes") + wire::number(sr.output_bytes) + wire::key("frames") + wire::number(sr.frames) +
        wire::key("skippable_frames") + wire::number(sr.skippable_frames) +
        wire::key("content_checked_frames") + wire::number(sr.content_checked_frames) + wire::key("block_checked_frames") + wire::number(sr.block_checked_frames) +
        wire::key("error") + wire::number(sr.error) + wire::end() : "";
    const std::string input_trace_field = read_file_timing_enabled() ?
        wire::key("input_trace") + input_trace_wire(result.input_trace) : "";
    const auto &output_trace = result.output_trace;
    const std::string metadata_warning_field = (output_trace.metadata_failed_files || output_trace.metadata_failed_directories) ?
        (wire::key("metadata_warning") + wire::object() + wire::key("file_count")) + wire::number(output_trace.metadata_failed_files) +
        wire::key("directory_count") + wire::number(output_trace.metadata_failed_directories) +
        wire::key("time_failure_count") + wire::number(output_trace.metadata_failed_times) +
        wire::key("attribute_failure_count") + wire::number(output_trace.metadata_failed_attributes) +
        wire::key("operation") + wire::text((output_trace.metadata_first_is_attributes ? "attributes" : "time")) +
        wire::key("first_item_index") + wire::number(output_trace.metadata_first_item_index) +
        wire::key("first_item") + wire::text(wide_to_utf8(output_trace.metadata_first_item)) +
        wire::key("win32_error") + wire::number(output_trace.metadata_first_win32_error) + wire::end() : "";
#ifdef SUP7Z_DEBUG
    const std::string pipeline_timing_field = pipeline_timing_enabled() ?
        wire::key("pipeline_timing") + pipeline_timing_wire(result.pipeline_timing) : "";
#endif
    print_frame(
        (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
        wire::key("status") + wire::text(ok ? "ok" : "failed") +
        wire::key("native_status") + wire::text(status_to_string(result.status)) +
        wire::key("operation_result") + wire::number(result.operation_result) +
        wire::key("operation_result_name") + wire::text(operation_result_name(result.operation_result)) +
        wire::key("encrypted") + wire::boolean(result.encrypted) +
        wire::key("damaged") + wire::boolean(result.damaged) +
        wire::key("checksum_error") + wire::boolean(result.checksum_error) +
        wire::key("missing_volume") + wire::boolean(result.missing_volume) +
        wire::key("missing_volume_suspected") + wire::boolean(result.missing_volume_suspected) +
        wire::key("missing_volume_evidence") + wire::text(result.missing_volume_evidence) +
        wire::key("missing_volume_name") + wire::text(wide_to_utf8(result.missing_volume_name)) +
        wire::key("wrong_password") + wire::boolean(result.wrong_password) +
        wire::key("password_rejected") + wire::boolean(result.password_rejected) +
        wire::key("password_crc_proven") + wire::boolean(result.password_crc_proven) +
        wire::key("password_crc_proven_items") + wire::number(result.password_crc_proven_items) +
        wire::key("password_candidate_batch") + wire::boolean(result.password_candidate_batch) +
        wire::key("password_candidate_direct") + wire::boolean(result.password_candidate_direct) +
        wire::key("password_candidates_all_rejected") + wire::boolean(result.password_candidates_all_rejected) +
        wire::key("password_candidate_count") + wire::number(result.password_candidate_count) +
        wire::key("password_attempts") + wire::number(result.password_attempts) +
        wire::key("matched_index") + wire::number(result.matched_index) +
        wire::key("unsupported_method") + wire::boolean(result.unsupported_method) +
        wire::key("item_count") + wire::number(result.item_count) +
        wire::key("files_written") + wire::number(result.files_written) +
        wire::key("dirs_written") + wire::number(result.dirs_written) +
        wire::key("bytes_written") + wire::number(result.bytes_written) +
        volume_attempt_fields +
        wire::key("dry_run") + wire::boolean(dry_run) +
        wire::key("open_mode") + wire::text(open_mode) +
        wire::key("archive_type") + wire::text(wide_to_utf8(result.archive_type)) +
        wire::key("requested_codepage") + wire::text(wide_to_utf8(result.requested_codepage)) +
        wire::key("applied_codepage") + wire::text(wide_to_utf8(result.applied_codepage)) +
        wire::key("filename_decoder") + wire::text(wide_to_utf8(result.filename_decoder)) +
        wire::key("verified_manifest") + manifest_summary +
        wire::key("failed_item") + wire::text(wide_to_utf8(result.failed_item)) +
        wire::key("message") + wire::text(result.message) + metadata_warning_field +
        failure_fields + input_trace_field
#ifdef SUP7Z_DEBUG
        + pipeline_timing_field
#endif
        + diagnostic_fields + stream_receipt_field + wire::end());
    return ok ? 0 : 1;
}

std::size_t native_logical_processor_count() noexcept {
#ifdef _WIN32
    const DWORD active_processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (active_processors != 0) {
        return static_cast<std::size_t>(active_processors);
    }
#endif
    const unsigned hardware = std::thread::hardware_concurrency();
    return hardware == 0 ? std::size_t{2} : hardware;
}

std::string requested_native_process_mode() {
    const char* configured = std::getenv("SUNPACK_NATIVE_PROCESS_MODE");
    const std::string mode = configured ? std::string(configured) : "normal";
    return mode == "background" || mode == "high" ? mode : "normal";
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

class NativeJobExecutor final {
public:
    NativeJobExecutor(
        std::size_t worker_count,
        std::uint64_t memory_reserve_bytes
    )
        : writer_config_(sunpack::sevenzip::configured_async_writer_config()),
          writer_registry_(std::make_shared<sunpack::sevenzip::VolumeWriterRegistry>(
              nullptr,
              writer_config_,
              [this](const sunpack::sevenzip::VolumeSpaceTransition &transition) {
                  on_space_transition(transition);
              })),
          memory_(memory_reserve_bytes, {}, [this] { writer_registry_->reclaim_idle_memory(); }),
          worker_count_(worker_count),
          queue_capacity_(4096),
          cpu_budget_(
              worker_count_,
              &NativeJobExecutor::on_cpu_capacity_available,
              this) {
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
        try {
            for (std::size_t index = 0; index < worker_count_; ++index) {
                workers_.emplace_back([this] { worker_loop(); });
            }
            monitor_thread_ = std::thread([this] { monitor_loop(); });
        } catch (...) {
            // A failed constructor does not run ~NativeJobExecutor. Drain
            // threads already started before their joinable handles unwind.
            stop();
            throw;
        }
    }

    ~NativeJobExecutor() { stop(); }

    NativeJobExecutor(const NativeJobExecutor&) = delete;
    NativeJobExecutor& operator=(const NativeJobExecutor&) = delete;

    void submit(WorkerRequest request) {
        auto cancel_token = std::make_shared<std::atomic<bool>>(false);
        JobMetadata metadata = metadata_from_request(request);
        const std::string queued_event =
            request.job_id.empty()
                ? std::string{}
                : worker_event_wire("job_queued", metadata, 0);
        const std::string job_id = request.job_id;
        bool rejected_for_capacity = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            if (queued_job_count_locked() >= queue_capacity_) {
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
                if (job.request.origin != "watch") {
                    foreground_queue_.push_back(std::move(job));
                } else {
                    background_queue_.push_back(std::move(job));
                }
            }
        }

        if (rejected_for_capacity) {
            print_frame(
                (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("backpressure") + wire::key("retryable") + wire::boolean(true) + wire::key("failure_stage") + wire::text("native_admission") + wire::key("failure_kind") + wire::text("queue_capacity") + wire::key("message") + wire::text("native job queue is full") + wire::end()));
            print_worker_event(job_id, "job_finished", metadata);
            return;
        }

        if (!queued_event.empty()) {
            print_frame(queued_event);
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
            token->store(true, std::memory_order_release);
            if (auto attempt = found->second.attempt_cancel.lock()) attempt->store(true, std::memory_order_release);
            // Locked only for this call: the token carries the cancel, the writer is just the thing to wake.
            writer_to_wake = found->second.writer.lock();
        }
        memory_.changed();
        // Cancellation is rare: withdraw queued jobs here rather than making
        // them wait for a CPU credit just to acknowledge their terminal state.
        std::optional<Job> withdrawn;
        bool drained = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto* queue : {&foreground_queue_, &background_queue_}) {
                const auto found = std::find_if(queue->begin(), queue->end(), [&](const Job& job) {
                    return job.cancel_token == token;
                });
                if (found == queue->end()) continue;
                withdrawn.emplace(std::move(*found));
                queue->erase(found);
                drained = queues_empty_locked() && active_jobs_ == 0 && parked_jobs_ == 0;
                break;
            }
        }
        if (withdrawn) {
            if (withdrawn->execution) memory_.end(withdrawn->execution->memory);
            {
                std::lock_guard<std::mutex> lock(cancel_mutex_);
                cancel_tokens_.erase(job_id);
            }
            print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                (wire::key("status") + wire::text("cancelled") + wire::key("native_status") + wire::text("cancelled") + wire::key("hresult") + wire::number(-2147467260) + wire::end()));
            print_worker_event(job_id, "job_finished", withdrawn->metadata);
            if (drained) drain_condition_.notify_all();
            return true;
        }
#ifdef _WIN32
        // Wake only the facility this job writes to, whose producer may be parked in that backpressure wait; a reclaimed facility leaves an expired weak_ptr.
        if (writer_to_wake) {
            writer_to_wake->wake_waiters();
        }
#endif
        // One canceled queued job needs at most one execution lane. Baton
        // passing handles any additional ready work without a wake-all storm.
        condition_.notify_all(); // cancellation must also wake a parked retry
        return true;
    }

    bool had_job_failure() const noexcept { return any_job_failed_; }

    // Waits for the queue and all active jobs to finish while the monitor and space gate remain alive.
    void wait_for_pending_jobs_to_drain() noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        drain_condition_.wait(
            lock,
            [this] { return queues_empty_locked() && active_jobs_ == 0 && parked_jobs_ == 0; });
    }

    // Normal shutdown and stdin EOF drain first; destructor fallback cancels.
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
            std::vector<std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>> writers;
            {
                std::lock_guard<std::mutex> cancel_lock(cancel_mutex_);
                for (auto& entry : cancel_tokens_) {
                    if (entry.second.cancel_token) {
                        entry.second.cancel_token->store(true, std::memory_order_release);
                        if (auto attempt = entry.second.attempt_cancel.lock()) attempt->store(true, std::memory_order_release);
                        if (auto writer = entry.second.writer.lock()) writers.push_back(std::move(writer));
                    }
                }
            }
            for (const auto &writer : writers) writer->wake_waiters();
        }
        {
            std::lock_guard<std::mutex> monitor_lock(monitor_mutex_);
            monitor_stopping_ = true;
            monitor_recheck_ = true;
        }
        condition_.notify_all();
        memory_.stop();
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
        // WorkerRequest owns identity and routing; retain only encoded events.
        // Lifecycle events reuse these fields four times per job. Encoding them
        // once at submission avoids repeated allocations on the
        // admission and completion hot paths.
        std::string encoded_job_id;
        std::string lifecycle_context_wire;
    };

    struct JobExecution {
        struct InputStamp {
            std::wstring path;
            WIN32_FILE_ATTRIBUTE_DATA data{};
            bool present = false;
        };
        JobExecution(sunpack::sevenzip::NativeMemoryManager &manager, const WorkerRequest &request) : memory(manager) {
            std::unordered_set<std::wstring_view> seen;
            const auto remember = [&](const std::wstring &path) {
                if (path.empty() || !seen.insert(path).second) return;
                InputStamp stamp;
                stamp.path = sunpack::sevenzip::win32_extended_path(path);
                stamp.present = GetFileAttributesExW(stamp.path.c_str(), GetFileExInfoStandard, &stamp.data) != FALSE;
                inputs.push_back(std::move(stamp));
            };
            remember(request.archive_input.archive_path);
            for (const auto &path : request.archive_input.part_paths) remember(path);
            for (const auto &range : request.archive_input.ranges) remember(range.path);
            for (const auto &range : request.archive_input.volume_attempts.sources) remember(range.path);
        }
        bool inputs_unchanged() const {
            for (const auto &stamp : inputs) {
                WIN32_FILE_ATTRIBUTE_DATA data{};
                const bool present = GetFileAttributesExW(stamp.path.c_str(), GetFileExInfoStandard, &data) != FALSE;
                if (present != stamp.present || (present &&
                    (data.nFileSizeHigh != stamp.data.nFileSizeHigh || data.nFileSizeLow != stamp.data.nFileSizeLow ||
                     CompareFileTime(&data.ftLastWriteTime, &stamp.data.ftLastWriteTime) != 0 ||
                     CompareFileTime(&data.ftCreationTime, &stamp.data.ftCreationTime) != 0))) return false;
            }
            return true;
        }
        sunpack::sevenzip::NativeMemoryJob memory;
        sunpack::sevenzip::ExtractionReplay replay;
        std::vector<InputStamp> inputs;
        std::uint64_t memory_episode = 0;
    };

    struct Job {
        WorkerRequest request;
        std::shared_ptr<std::atomic<bool>> cancel_token;
        JobMetadata metadata;
        std::unique_ptr<JobExecution> execution;
    };

    // The writer reference is deliberately weak: a strong one would keep a facility alive past its lease and could run ~AsyncFileWriter under the executor mutex.
    struct JobControl {
        explicit JobControl(std::shared_ptr<std::atomic<bool>> token)
            : cancel_token(std::move(token)) {}

        std::shared_ptr<std::atomic<bool>> cancel_token;
        std::weak_ptr<std::atomic<bool>> attempt_cancel;
        std::weak_ptr<sunpack::sevenzip::AsyncFileWriter> writer;
    };

    static JobMetadata metadata_from_request(const WorkerRequest& request) noexcept {
        JobMetadata metadata;
        const auto &request_id = request.request_id.empty() ? request.job_id : request.request_id;
        metadata.encoded_job_id = wire::text(request.job_id);
        metadata.lifecycle_context_wire =
            wire::key("request_id") + wire::text(request_id) +
            wire::key("origin") + wire::text(request.origin != "watch" ? "foreground" : "watch") +
            wire::key("output_volume_key") + wire::text(request.output_volume_key) +
            wire::key("requires_writer") + wire::boolean(!request.dry_run);
        return metadata;
    }

    bool queues_empty_locked() const noexcept {
        return foreground_queue_.empty() && background_queue_.empty();
    }

    std::size_t queued_job_count_locked() const noexcept {
        return foreground_queue_.size() + background_queue_.size() + parked_jobs_;
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
            // and its atomic update is outside the queue mutex. Synchronize
            // with the waiter's predicate check before delivering that edge.
            std::lock_guard<std::mutex> lock(self->mutex_);
            if (!self->queues_empty_locked()) self->condition_.notify_one();
        }
    }

    void request_monitor_recheck() noexcept {
        {
            std::lock_guard<std::mutex> lock(monitor_mutex_);
            monitor_recheck_ = true;
        }
        monitor_condition_.notify_one();
    }

    std::string worker_event_wire(
        const char* event,
        const JobMetadata& metadata,
        std::size_t active_jobs = 0
    ) const {
        return
            (wire::object() + wire::key("type") + wire::text("native_event") + wire::key("job_id")) + metadata.encoded_job_id +
            wire::key("event") + wire::text(event) +
            metadata.lifecycle_context_wire +
            wire::key("active_jobs") + wire::number(active_jobs) +
            wire::end();
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
        print_frame(worker_event_wire(
            event, metadata, active_jobs));
    }

    void print_job_start_events(
        const Job& job,
        std::size_t active_jobs
    ) const noexcept {
        if (job.request.job_id.empty()) {
            return;
        }
        print_frames(
            worker_event_wire(
                "job_admitted",
                job.metadata,
                active_jobs),
            worker_event_wire(
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
            job.request.job_id,
            event,
            job.metadata,
            active_jobs);
    }

    // Facility lifecycle, so an empty `live_facilities` count can be told apart from a volume key that never reached the writer.
    static void print_writer_facility_event(
        const char* event,
        const std::string& volume_key
    ) noexcept {
        print_frame(
            (wire::object() + wire::key("type") + wire::text("native_writer") + wire::key("event")) + wire::text(event) +
            wire::key("volume_key") + wire::text(volume_key) + wire::end());
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
            (wire::object() + wire::key("type") + wire::text("progress") + wire::key("job_id")) + wire::text(job_id) +
            wire::key("event") + wire::text(event) +
            wire::key("volume_key") + wire::text(volume_key) +
            wire::key("episode_id") + wire::number(episode_id) +
            wire::key("win32_error") + wire::number(win32_error) +
            wire::key("free_bytes") + wire::number(free_bytes) +
            wire::key("pending_bytes") + wire::number(pending_bytes) +
            wire::key("blocked_seconds") + wire::number(blocked_seconds) +
            wire::key("volume_query_ok") + wire::boolean(query_ok) +
            wire::key("volume_query_error") + wire::number(query_error) + wire::end();
        return payload;
    }

    static void print_volume_space_event(
        const sunpack::sevenzip::VolumeSpaceTransition& transition
    ) noexcept {
        const char* event = space_event_name(transition.kind);
        for (const auto& job_id : transition.job_ids) {
            print_frame(space_event_payload(
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
            print_frame(space_event_payload(
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

    void monitor_loop() noexcept {
        // Disk-space monitoring retains its existing active-only schedule.
        // Memory notifications and commitment checks belong to memory_.
        for (;;) {
            std::unique_lock<std::mutex> lock(monitor_mutex_);
            const auto now = std::chrono::steady_clock::now();
            auto deadline = writer_registry_->next_reap_deadline();
            if (space_monitor_->sampling()) {
                const auto space = now + writer_config_.space_poll_interval;
                if (!deadline || space < *deadline) deadline = space;
            }
            if (deadline) monitor_condition_.wait_until(lock, *deadline,
                [this] { return monitor_stopping_ || monitor_recheck_; });
            else monitor_condition_.wait(lock,
                [this] { return monitor_stopping_ || monitor_recheck_; });
            if (monitor_stopping_) return;
            monitor_recheck_ = false;
            lock.unlock();
            for (const auto &volume : writer_registry_->reap_idle())
                print_writer_facility_event("writer_facility_reaped", volume);
            space_monitor_->tick(std::chrono::steady_clock::now());
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
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] {
                    const bool empty = queues_empty_locked();
                    return (!empty && cpu_budget_.can_acquire_base()) ||
                        (stopping_ && empty && parked_jobs_ == 0);
                });
                if (stopping_ && queues_empty_locked() && parked_jobs_ == 0) {
                    break;
                }
                if (!cpu_budget_.try_acquire_base()) {
                    continue;
                }

                job = pop_next_job_locked();
                active_jobs_ += 1;
                admitted_jobs = active_jobs_;
                if (queues_empty_locked()) {
                    // On canceling shutdown the first broadcast can reach
                    // idle workers before a parked job is requeued. Removing
                    // that last job makes the exit predicate true for all.
                    if (stopping_ && parked_jobs_ == 0) condition_.notify_all();
                } else {
                    wake_next_job = cpu_budget_.can_acquire_base();
                }
            }

            // Hand admission forward one worker at a time when multiple
            // credits are available, avoiding a notify-all thundering herd.
            if (wake_next_job) {
                condition_.notify_one();
            }

            const bool replaying = job.execution != nullptr;
            if (!job.execution) {
                print_job_start_events(job, admitted_jobs);
                job.execution = std::make_unique<JobExecution>(memory_, job.request);
            }
            int code = -100;
            const std::string& job_id = job.request.job_id;
            auto &memory_job = job.execution->memory;
            memory_.begin(memory_job);
            {
                std::lock_guard<std::mutex> lock(cancel_mutex_);
                const auto found = cancel_tokens_.find(job_id);
                if (found != cancel_tokens_.end()) found->second.attempt_cancel = memory_job.cancel;
                if (job.cancel_token->load(std::memory_order_acquire)) memory_job.cancel->store(true, std::memory_order_release);
            }
            {
                sunpack::sevenzip::NativeCpuJobContext cpu_job_context(cpu_budget_);
                sunpack::sevenzip::NativeCpuContextScope cpu_scope(&cpu_job_context);
                sunpack::sevenzip::NativeMemoryScope memory_scope(&memory_job);
                sunpack::sevenzip::ExtractionReplayScope replay_scope(&job.execution->replay);
                try {
                    if (replaying && !job.cancel_token->load(std::memory_order_acquire) && !job.execution->inputs_unchanged()) {
                        code = 1;
                        print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                            (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("error") + wire::key("failure_kind") + wire::text("input_changed") + wire::key("failure_stage") + wire::text("native_replay") + wire::key("message") + wire::text("archive input changed while waiting for memory; rescan required") + wire::end()));
                    } else if (!job.request.dry_run) {
                        const std::string key = job.request.output_volume_key.empty() ? synthetic_volume_key(job_id) : job.request.output_volume_key;
                        auto lease = writer_registry_->acquire(key);
                        if (lease.created_facility()) print_writer_facility_event("writer_facility_created", key);
                        register_cancel_writer(job_id, lease.writer_pointer());
                        const auto weak = std::weak_ptr<sunpack::sevenzip::AsyncFileWriter>(lease.writer_pointer());
                        memory_.set_wake(memory_job, [weak] { if (auto writer = weak.lock()) writer->wake_waiters(); });
                        if (job.cancel_token->load(std::memory_order_acquire)) memory_job.cancel->store(true, std::memory_order_release);
                        sunpack::sevenzip::SpaceJobRegistration registration(lease, job_id);
                        code = run_request(job.request, lease.writer_pointer(), memory_job.cancel);
                    } else code = run_request(job.request, nullptr, memory_job.cancel);
                } catch (const std::bad_alloc&) {
                    memory_.retry(memory_job);
                    code = kMemoryRetry;
                } catch (const std::system_error &error) {
                    // MSVC std::thread reports _beginthreadex exhaustion as
                    // EAGAIN, including a failed small stack/CRT allocation.
                    // Writer-facility threads do not use the SDK allocator.
                    if (error.code() == std::errc::resource_unavailable_try_again) {
                        memory_.retry(memory_job);
                        code = kMemoryRetry;
                        print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + wire::text(job_id) +
                            (wire::key("event") + wire::text("memory_thread_resource_retry") + wire::key("error_code")) +
                            wire::number(error.code().value()) + wire::end());
                    }
                } catch (...) { code = -100; }
            }
            if (code == -100) {
                print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("error") + wire::key("failure_kind") + wire::text("native_exception") + wire::key("failure_stage") + wire::text("native_execution") + wire::key("message") + wire::text("unexpected native execution exception") + wire::end()));
            }
            // Pending output and decoder threads have drained. Parked tasks
            // retain neither dictionaries, writer leases nor execution threads.
            cpu_budget_.release(1);
            memory_.end(memory_job);
            request_monitor_recheck();
            if (code == kMemoryRetry) {
                print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("event") + wire::text("memory_reclaimed") + wire::key("required_bytes")) + wire::number(memory_job.required) + wire::end());
                auto parked = std::make_shared<Job>(std::move(job));
                const auto notice = [parked](bool blocked, std::int64_t headroom, std::uint64_t needed) {
                    auto &episode = parked->execution->memory_episode;
                    if (blocked) ++episode;
                    print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + parked->metadata.encoded_job_id +
                        wire::key("event") + wire::text((blocked ? "memory_blocked" : "memory_resumed")) +
                        wire::key("episode_id") + wire::number(episode) +
                        wire::key("required_bytes") + wire::number(needed) +
                        wire::key("available_bytes") + wire::number((std::max)(headroom, std::int64_t{0})) + wire::end());
                };
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    --active_jobs_;
                    ++parked_jobs_;
                }
                memory_.park(memory_job, *parked->cancel_token, [this, parked](bool ready) {
                    if (!ready) parked->cancel_token->store(true, std::memory_order_release);
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        --parked_jobs_;
                        auto &queue = parked->request.origin != "watch" ? foreground_queue_ : background_queue_;
                        queue.push_front(std::move(*parked));
                    }
                    condition_.notify_one();
                }, notice);
                continue;
            }

            std::size_t remaining_jobs = 0;
            bool drained = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                active_jobs_ = active_jobs_ > 0 ? active_jobs_ - 1 : 0;
                remaining_jobs = active_jobs_;
                drained = queues_empty_locked() && active_jobs_ == 0 && parked_jobs_ == 0;
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
    sunpack::sevenzip::AsyncWriterConfig writer_config_;
    sunpack::sevenzip::VolumeWriterRegistryPtr writer_registry_;
    // The memory manager can reclaim idle writer buffers from the registry.
    sunpack::sevenzip::NativeMemoryManager memory_;
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
    bool monitor_recheck_ = false;
    bool monitor_stopping_ = false;

    const std::size_t worker_count_;
    const std::size_t queue_capacity_;
    sunpack::sevenzip::NativeCpuBudget cpu_budget_;
    std::size_t active_jobs_ = 0;
    std::size_t parked_jobs_ = 0;
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
        print_frame((wire::object() + wire::key("type") + wire::text("cancel_ack") + wire::key("job_id")) + wire::text(job_id) +
            wire::key("accepted") + wire::boolean(accepted) + wire::end());
        return accepted ? 0 : 1;
    }
    if (command == "set_process_mode") {
        std::string mode = request.process_mode;
        if (mode != "background" && mode != "high") {
            mode = "normal";
        }
        const bool applied = apply_native_process_mode(mode);
        print_frame((wire::object() + wire::key("type") + wire::text("process_mode_ack") + wire::key("mode")) + wire::text(mode) +
            wire::key("applied") + wire::boolean(applied) + wire::end());
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
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cerr.tie(nullptr);
    const std::string requested_process_mode = requested_native_process_mode();
    const bool process_mode_applied = apply_native_process_mode(requested_process_mode);
    const auto worker_count = native_logical_processor_count();
    const auto memory_reserve_bytes = sunpack::sevenzip::NativeMemoryManager::default_reserve_bytes(worker_count);
    NativeJobExecutor executor(worker_count, memory_reserve_bytes);
    print_frame(
        (wire::object() + wire::key("type") + wire::text("worker_ready") + wire::key("sizing_mode") + wire::text("dynamic") + wire::key("logical_processors")) + wire::number(worker_count) +
        wire::key("thread_capacity") + wire::number(worker_count) +
        (wire::key("memory_management") + wire::text("commitment_replay")) +
        wire::key("memory_reserve_bytes") +
            wire::number(memory_reserve_bytes) +
        wire::key("process_mode") + wire::text(requested_process_mode) +
        wire::key("process_mode_applied") + wire::boolean(process_mode_applied) + wire::end());
    std::string frame;
    try {
        while (wire::read(std::cin, frame)) {
            WorkerRequest request = parse_worker_request(frame);
            std::string().swap(frame);
            const bool shutdown = request.worker_command == "shutdown";
            const int code = run_message(std::move(request), executor);
            if (shutdown) {
                executor.stop(/*cancel_pending_jobs=*/false);
                return code;
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "worker protocol: " << error.what() << "\n";
        executor.stop(/*cancel_pending_jobs=*/true);
        return 2;
    }
    executor.stop(/*cancel_pending_jobs=*/false);
    return executor.had_job_failure() ? 1 : 0;
}
