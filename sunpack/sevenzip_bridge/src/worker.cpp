#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32
#include <windows.h>

// Exported by OleAut32 but omitted from current Windows SDK headers.
extern "C" __declspec(dllimport) void __cdecl SetOaNoCache();
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
#include "internal/sevenzip_paths.hpp"
#include "internal/native_memory.hpp"
#include "internal/extraction_replay.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/password_parallel.hpp"
#include "internal/sevenzip_streams.hpp"
#include "7zip/Crypto/7zAes.h"
#include "7zip/Crypto/Rar5Aes.h"
#ifdef SUP7Z_DEBUG
#include "internal/worker_pipeline_timing.hpp"
#endif
#ifdef _WIN32
#include "internal/sevenzip_async_output.hpp"
#include "internal/sevenzip_space_monitor.hpp"
#include "internal/sevenzip_volume_registry.hpp"
#endif

namespace {

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
    bool native_volume_input = false;
    std::vector<std::wstring> part_paths;
    std::vector<std::wstring> canonical_names;
    std::string analyzed_missing_volume_evidence;
    // First absent number of a structured volume sequence (0 = contiguous).
    int missing_volume_number = 0;
    std::string validation_error;
    std::vector<sunpack::sevenzip::ExtractInputRange> ranges;
};

sunpack::sevenzip::ExtractArchiveResult password_candidate_failure(
    const sunpack::sevenzip::PasswordTestResult& probe
) {
    using namespace sunpack::sevenzip;
    ExtractArchiveResult result;
    // An apparently successful probe with no usable match is still a failure.
    result.status = probe.status == PasswordTestStatus::Ok ? PasswordTestStatus::Error : probe.status;
    result.archive_type = probe.archive_type;
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

template<class Field>
void read_object(wire::RequestReader& reader, Field field) {
    reader.object();
    while (reader.next()) {
        const auto key = reader.text();
        field(key);
    }
}

template<class Item>
void read_array(wire::RequestReader& reader, Item item) {
    reader.array();
    while (reader.next()) item();
}

bool read_extent_field(wire::RequestReader& reader, std::string_view key,
                       sunpack::sevenzip::ExtractInputRange& range) {
    if (key == "path") range.path = utf8_to_wide(reader.text());
    else if (key == "start") range.start = reader.number();
    else if (key == "end") {
        range.end = reader.number();
        range.has_end = true;
    } else return false;
    return true;
}

sunpack::sevenzip::ExtractInputRange read_range(wire::RequestReader& reader) {
    sunpack::sevenzip::ExtractInputRange range;
    read_object(reader, [&](auto key) {
        if (!read_extent_field(reader, key, range)) reader.skip();
    });
    return range;
}

void read_volume_plan(wire::RequestReader& reader, WorkerArchiveInput& input) {
    auto& plan = input.volume_attempts;
    read_object(reader, [&](auto key) {
        if (key == "head_size_from_total") plan.head_size_from_total = reader.number();
        else if (key == "minimum_size") plan.minimum_size = reader.number();
        else if (key == "sources") {
            read_array(reader, [&] { plan.sources.push_back(read_range(reader)); });
        } else if (key == "domains") {
            read_array(reader, [&] {
                auto& choices = plan.domains.emplace_back();
                read_object(reader, [&](auto field) {
                    if (field != "choices") { reader.skip(); return; }
                    read_array(reader, [&] { choices.push_back(static_cast<std::size_t>(reader.number())); });
                });
            });
        } else if (key == "tail_totals") {
            read_array(reader, [&] {
                std::uint64_t source = UINT64_MAX, total = 0;
                read_object(reader, [&](auto field) {
                    if (field == "source") source = reader.number();
                    else if (field == "total") total = reader.number();
                    else reader.skip();
                });
                if (source >= plan.sources.size() || !total) {
                    input.validation_error = "invalid volume tail total";
                    return;
                }
                if (plan.tail_totals.empty()) plan.tail_totals.resize(plan.sources.size());
                plan.tail_totals[static_cast<std::size_t>(source)] = total;
            });
        } else if (key == "layouts") {
            read_array(reader, [&] {
                auto& slots = plan.layouts.emplace_back();
                std::uint64_t minimum = 0, previous = 0;
                std::unordered_set<std::wstring> names;
                read_object(reader, [&](auto field) {
                    if (field == "minimum_slots") minimum = reader.number();
                    else if (field == "slots") {
                        read_array(reader, [&] {
                            sunpack::sevenzip::VolumeAttemptSlot slot;
                            std::uint64_t number = 0, domain = UINT64_MAX;
                            read_object(reader, [&](auto member) {
                                if (member == "number") number = reader.number();
                                else if (member == "domain") domain = reader.number();
                                else if (member == "canonical_name") slot.name = utf8_to_wide(reader.text());
                                else reader.skip();
                            });
                            if (number <= previous || number > INT_MAX || (slots.empty() && number != 1) ||
                                slot.name.empty() || !names.insert(slot.name).second || domain == UINT64_MAX) {
                                input.validation_error = "invalid volume attempt slot";
                                return;
                            }
                            slot.number = static_cast<unsigned int>(number);
                            slot.domain = static_cast<std::size_t>(domain);
                            previous = number;
                            slots.push_back(std::move(slot));
                        });
                    } else reader.skip();
                });
                if (slots.empty() || (minimum && (minimum < 2 || minimum > slots.size() ||
                    slots.back().number != slots.size()))) input.validation_error = "invalid volume attempt layout";
                plan.minimum_slots.push_back(static_cast<std::size_t>(minimum));
            });
        } else reader.skip();
    });
    if (!input.validation_error.empty()) return;
    if (plan.sources.empty() || plan.layouts.empty() ||
        std::any_of(plan.sources.begin(), plan.sources.end(), [](const auto& source) {
            return source.path.empty() || (source.has_end && source.end < source.start);
        })) input.validation_error = "invalid volume attempt sources";
    else if (std::any_of(plan.domains.begin(), plan.domains.end(), [&](const auto& choices) {
        return choices.empty() || std::any_of(choices.begin(), choices.end(),
            [&](auto source) { return source >= plan.sources.size(); });
    })) input.validation_error = "invalid volume attempt domain";
    else if (std::any_of(plan.layouts.begin(), plan.layouts.end(), [&](const auto& slots) {
        return std::any_of(slots.begin(), slots.end(), [&](const auto& slot) { return slot.domain >= plan.domains.size(); });
    })) input.validation_error = "invalid volume attempt slot";
}

enum class InputMode { File, FileRange, NativeVolumes, SfxWithVolumes };

InputMode read_input_mode(std::string_view mode) {
    if (mode == "file_range") return InputMode::FileRange;
    if (mode == "native_volumes") return InputMode::NativeVolumes;
    if (mode == "sfx_with_volumes") return InputMode::SfxWithVolumes;
    return InputMode::File;
}

void read_input_parts(wire::RequestReader& reader, WorkerArchiveInput& input, InputMode mode) {
    const bool structured = mode == InputMode::NativeVolumes || mode == InputMode::SfxWithVolumes;
    bool has_ranges = false;
    std::uint64_t previous = 0;
    read_array(reader, [&] {
        sunpack::sevenzip::ExtractInputRange range;
        std::uint64_t number = 0;
        std::wstring name;
        read_object(reader, [&](auto key) {
            if (structured && key == "volume_number") number = reader.number();
            else if (structured && key == "canonical_name") name = utf8_to_wide(reader.text());
            else if (!read_extent_field(reader, key, range)) reader.skip();
        });
        if (mode == InputMode::FileRange) {
            if (range.path.empty()) range.path = input.archive_path;
            if (!range.path.empty()) input.ranges.push_back(std::move(range));
        } else if (range.path.empty()) return;
        else if (!structured) input.part_paths.push_back(std::move(range.path));
        else {
            if (!number || number > INT_MAX || name.empty()) {
                input.validation_error = "structured volume part requires volume_number and canonical_name";
                return;
            }
            if (number <= previous) {
                input.validation_error = "structured volume sequence must be ordered and unique";
                return;
            }
            if (range.has_end && range.end < range.start)
                input.validation_error = "structured volume extent is reversed";
            if (!input.missing_volume_number && number != previous + 1)
                input.missing_volume_number = static_cast<int>(previous + 1);
            previous = number;
            has_ranges |= range.start != 0 || range.has_end;
            input.ranges.push_back(std::move(range));
            input.canonical_names.push_back(std::move(name));
        }
    });
    if (structured && !has_ranges) {
        input.part_paths.reserve(input.ranges.size());
        for (auto& range : input.ranges) input.part_paths.push_back(std::move(range.path));
        std::vector<sunpack::sevenzip::ExtractInputRange>().swap(input.ranges);
    }
}

WorkerArchiveInput read_archive_input(wire::RequestReader& reader) {
    WorkerArchiveInput input;
    InputMode mode = InputMode::File;
    bool attempts = false;
    read_object(reader, [&](auto key) {
        if (key == "entry_path") input.archive_path = utf8_to_wide(reader.text());
        else if (key == "open_mode") mode = read_input_mode(reader.text());
        else if (key == "format_hint") input.format_hint = utf8_to_wide(reader.text());
        else if (key == "parts") read_input_parts(reader, input, mode);
        else if (key == "volume_attempts") {
            attempts = true;
            read_volume_plan(reader, input);
        } else if (key == "analysis") {
            read_object(reader, [&](auto field) {
                if (field != "execution") { reader.skip(); return; }
                read_object(reader, [&](auto finding) {
                    if (finding == "missing_volume_evidence") input.analyzed_missing_volume_evidence = reader.text();
                    else reader.skip();
                });
            });
        } else reader.skip();
    });
    input.native_volume_input = mode == InputMode::NativeVolumes;
    if (!attempts && input.validation_error.empty()) {
        if (mode == InputMode::FileRange && input.ranges.empty())
            input.validation_error = "file_range descriptor requires canonical parts with extents";
        else if ((mode == InputMode::NativeVolumes || mode == InputMode::SfxWithVolumes) && input.canonical_names.empty())
            input.validation_error = "structured volume descriptor has no parts";
    }
    return input;
}

struct WorkerRequest {
    std::string worker_command;
    std::string job_id;
    bool from_watch = false;
    std::string output_volume_key;
    std::string process_mode = "normal";
    std::wstring output_dir;
    std::wstring password;
    std::wstring codepage;
    bool report_progress = false;
    bool output_inventory = true;
    bool password_verified = false;
    bool scan_only = false;
    int encrypted = -1;
    std::vector<std::wstring> password_candidates;
    std::vector<std::vector<std::size_t>> password_domains;
    WorkerArchiveInput archive_input;

    const std::vector<std::size_t>* passwords_for_layout(std::size_t layout) const {
        const auto& indices = archive_input.volume_attempts.layout_password_domains;
        return indices.empty() ? nullptr : &password_domains[indices[layout]];
    }
    std::size_t password_count(const std::vector<std::size_t>* domain) const {
        return domain ? domain->size() : password_candidates.size();
    }
};

WorkerRequest parse_worker_request(wire::RequestReader& reader) {
    WorkerRequest request;
    bool has_archive_input = false;
    std::vector<std::size_t> layout_password_domains;
    auto read_indices = [&](std::vector<std::size_t>& indices) {
        read_array(reader, [&] { indices.push_back(static_cast<std::size_t>(reader.number())); });
    };
    read_object(reader, [&](auto key) {
        if (key == "worker_command") request.worker_command = reader.text();
        else if (key == "job_id") request.job_id = reader.text();
        else if (key == "origin") request.from_watch = reader.text() == "watch";
        else if (key == "output_volume_key") request.output_volume_key = reader.text();
        else if (key == "mode") request.process_mode = reader.text();
        else if (key == "output_dir") request.output_dir = utf8_to_wide(reader.text());
        else if (key == "password") request.password = utf8_to_wide(reader.text());
        else if (key == "codepage") request.codepage = utf8_to_wide(reader.text());
        else if (key == "report_progress") request.report_progress = reader.boolean();
        else if (key == "output_inventory") request.output_inventory = reader.boolean();
        else if (key == "password_verified") request.password_verified = reader.boolean();
        else if (key == "operation") request.scan_only = reader.text() == "scan";
        else if (key == "encrypted") request.encrypted = reader.boolean() ? 1 : 0;
        else if (key == "password_candidates") {
            read_array(reader, [&] { request.password_candidates.push_back(utf8_to_wide(reader.text())); });
        } else if (key == "password_domains") {
            read_array(reader, [&] { read_indices(request.password_domains.emplace_back()); });
        } else if (key == "layout_password_domains") {
            read_indices(layout_password_domains);
        } else if (key == "archive_input") {
            request.archive_input = read_archive_input(reader);
            has_archive_input = true;
        }
        else reader.skip();
    });
    reader.finish();
    if (!layout_password_domains.empty() || !request.password_domains.empty()) {
        auto& plan = request.archive_input.volume_attempts;
        const bool valid = layout_password_domains.size() == plan.layouts.size() &&
            std::all_of(layout_password_domains.begin(), layout_password_domains.end(),
                [&](auto index) { return index < request.password_domains.size(); }) &&
            std::all_of(request.password_domains.begin(), request.password_domains.end(), [&](const auto& domain) {
                return !domain.empty() && domain.back() < request.password_candidates.size() &&
                    std::adjacent_find(domain.begin(), domain.end(), std::greater_equal<>()) == domain.end();
            });
        if (!valid) request.archive_input.validation_error = "invalid layout password domain";
        plan.layout_password_domains = std::move(layout_password_domains);
    }
    if (!has_archive_input && request.worker_command.empty())
        request.archive_input.validation_error = "archive_input descriptor is required";
    return request;
}

std::mutex g_output_mutex;

void print_frame(const std::string& payload) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    wire::write(std::cout, payload);
    std::cout.flush();
}

void print_job_event(const std::string& job_id, const char* event) {
    if (job_id.empty()) return;
    print_frame(wire::object() + wire::key("type") + wire::text("native_event") +
        wire::key("job_id") + wire::text(job_id) + wire::key("event") + wire::text(event) + wire::end());
}

std::string input_trace_wire(const sunpack::sevenzip::ExtractInputTrace& trace) {
    const auto win32_error = HRESULT_FACILITY(trace.read_hresult) == FACILITY_WIN32 ? HRESULT_CODE(trace.read_hresult) : 0;
    return wire::object() +
        wire::key("read_error") + wire::boolean(true) +
        wire::key("last_win32_error") + wire::number(win32_error) +
        (wire::key("last_read") + wire::object() + wire::key("virtual_offset")) + wire::number(trace.last_read_virtual_offset) +
        wire::key("source_path") + wire::text(wide_to_utf8(trace.last_source_path)) +
        wire::key("source_offset") + wire::number(trace.last_read_source_offset) +
        wire::key("requested") + wire::number(trace.last_read_requested) +
        wire::end() + wire::end();
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

std::string verified_manifest_wire(const std::string& job_id, const sunpack::sevenzip::ExtractArchiveResult& result, bool include_rows) {
    std::optional<WorkerChunks> chunks;
    if (include_rows && result.output_inventory_complete) {
        chunks.emplace(job_id, "manifest_chunk", "rows");
    }
    unsigned int file_count = 0;
    unsigned long long total_size = 0;
    bool complete = result.output_inventory_complete;
    std::string row;
    if (chunks) row.reserve(256);
    for (const auto& item : result.output_trace.items) {
        if (item.is_dir) continue;
        ++file_count;
        total_size += item.bytes_written;
        complete = complete && item.done;
        if (!chunks) continue;
        row.clear();
        row += wire::array();
        wire::append_text(row, wide_to_utf8(item.output_path));
        wire::append_number(row, item.has_expected_size ? item.expected_size : item.bytes_written);
        wire::append_number(row, item.done ? 1 : item.failed ? 2 : 0);
        if (item.has_mtime_ns) wire::append_number(row, item.mtime_ns);
        else row.push_back(wire::kNull);
        wire::append_text(row, std::string_view(reinterpret_cast<const char*>(item.magic.data()), item.magic.size()), wire::kBytes);
        row += wire::end();
        chunks->append(row);
    }
    const std::string chunk_count = chunks
        ? wire::key("chunk_count") + wire::number(chunks->finish()) : "";
    return wire::object() +
        wire::key("complete") + wire::boolean(complete && file_count == result.files_written) +
        wire::key("file_count") + wire::number(file_count) +
        wire::key("total_size") + wire::number(total_size) +
        chunk_count + wire::end();
}

}  // namespace

constexpr int kMemoryRetry = -102;

struct RequestOutcome {
    int code;
    // IPC storage has no job charge and survives destruction of JobExecution.
    std::string response;
};

bool extraction_rejects_password(const sunpack::sevenzip::ExtractArchiveResult& result) {
    // Only a complete callback inventory can establish that every eligible
    // encrypted member rejected the candidate.
    if (!result.item_count || result.output_trace.items.size() != result.item_count) return false;
    bool tested = false;
    for (const auto& item : result.output_trace.items) {
        if (!item.encrypted || item.is_dir || (item.has_expected_size && item.expected_size == 0)) continue;
        tested = true;
        if (!sunpack::sevenzip::looks_wrong_password(S_OK, item.operation_result, true)) return false;
    }
    return tested;
}

RequestOutcome interrupted_result(const std::string& job_id) {
    // The attempt token also stops work for memory reclamation. Only the
    // executor's persistent user token decides whether a parked job is canceled.
    const auto* memory = sunpack::sevenzip::current_native_memory_job();
    if (memory && memory->revoked.load(std::memory_order_acquire)) return {kMemoryRetry, {}};
    sunpack::sevenzip::NativeMemoryScope response_memory(nullptr);
    return {-101,
        (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
        (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("cancelled") + wire::key("failure_stage") + wire::text("native_cancel") + wire::key("failure_kind") + wire::text("cancelled") + wire::key("message") + wire::text("native job was cancelled") + wire::end())};
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
                           std::size_t layout, const std::vector<std::size_t>& choices,
                           WorkerArchiveInput& input) {
    const auto& slots = source.volume_attempts.layouts[layout];
    const auto count = choices.size();
    input.ranges.resize(count);
    input.canonical_names.resize(count);
    input.missing_volume_number = 0;
    unsigned int previous = 0;
    for (std::size_t i = 0; i < count; ++i) {
        input.ranges[i] = source.volume_attempts.sources[choices[i]];
        input.canonical_names[i] = slots[i].name;
        if (!input.missing_volume_number && slots[i].number != previous + 1)
            input.missing_volume_number = static_cast<int>(previous + 1);
        previous = slots[i].number;
    }
    input.archive_path = input.ranges.front().path;
    if (input.missing_volume_number) return;
    const auto tail_total = source.volume_attempts.tail_totals.empty()
        ? 0 : source.volume_attempts.tail_totals[choices.back()];
    const auto total = tail_total ? tail_total : source.volume_attempts.head_size_from_total;
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

struct PreparedAttempt {
    std::size_t layout = 0;
    std::vector<std::size_t> sources;
    std::optional<sunpack::sevenzip::PasswordTestResult> probe;
};

// A logical stream clamps every slice to physical EOF. Confirm its geometry
// before extending a decoder rejection to untouched slots of the same layout.
class CompleteVolumeGeometry {
    std::optional<std::size_t> checked_;
    bool complete_ = false;
public:
#ifdef SUP7Z_DEBUG
    std::size_t inspected_choices = 0;
    std::size_t file_size_queries = 0;
#endif
    bool known(const sunpack::sevenzip::VolumeAttemptPlan& plan, std::size_t layout) {
        if (plan.minimum_slots_for(layout) != plan.layouts[layout].size()) return false;
        if (checked_ == layout) return complete_;
        checked_ = layout;
        complete_ = false;
        const auto source_offset = plan.domains.size();
        std::vector<bool> checked(source_offset + plan.sources.size());
        std::unordered_map<std::wstring_view, std::uintmax_t> file_sizes;
        for (const auto& slot : plan.layouts[layout]) {
            if (checked[slot.domain]) continue;
            checked[slot.domain] = true;
            for (auto id : plan.domains[slot.domain]) {
#ifdef SUP7Z_DEBUG
                ++inspected_choices;
#endif
                if (checked[source_offset + id]) continue;
                checked[source_offset + id] = true;
                const auto& source = plan.sources[id];
                if (sunpack::sevenzip::native_job_cancelled() || !source.has_end) return false;
                auto [size, inserted] = file_sizes.try_emplace(source.path);
                if (inserted) {
                    std::error_code error;
#ifdef SUP7Z_DEBUG
                    ++file_size_queries;
#endif
                    size->second = std::filesystem::file_size(source.path, error);
                    if (error) return false;
                }
                if (size->second < source.end) return false;
            }
        }
        complete_ = true;
        return true;
    }
};

bool fixed_volume_geometry(const sunpack::sevenzip::VolumeAttemptPlan& plan) {
    return std::none_of(plan.variation.begin(), plan.variation.end(),
        [](const auto& slot) { return slot.variable_length; });
}

// Keep one wave's worth of decoder results. Equal declared geometry and
// the same sources at every observed slot imply identical decoder input.
class VolumeProbeCache {
    struct Entry {
        std::size_t layout;
        std::vector<std::pair<std::size_t, std::size_t>> sources;
        sunpack::sevenzip::PasswordTestResult result;
        std::vector<unsigned long long> sizes;
        unsigned long long trim_total = 0;
    };
    std::deque<Entry> entries_;
    bool fixed_;

    static unsigned long long trim_total(const sunpack::sevenzip::VolumeAttemptPlan& plan, const PreparedAttempt& attempt) {
        const auto tail_total = plan.tail_totals.empty() ? 0 : plan.tail_totals[attempt.sources.back()];
        return tail_total ? tail_total : plan.head_size_from_total;
    }
    static unsigned long long size_of(const sunpack::sevenzip::VolumeAttemptPlan& plan, std::size_t source) {
        const auto& range = plan.sources[source];
        return range.end - range.start;
    }
public:
    explicit VolumeProbeCache(const sunpack::sevenzip::VolumeAttemptPlan& plan) : fixed_(fixed_volume_geometry(plan)) {}
    CompleteVolumeGeometry geometry;
#ifdef SUP7Z_DEBUG
    std::size_t scheduled_probes = 0;
#endif

    bool can_skip_suffix(const sunpack::sevenzip::VolumeAttemptPlan& plan, std::size_t layout) {
        return fixed_ && geometry.known(plan, layout);
    }

    const sunpack::sevenzip::PasswordTestResult* find(
        const sunpack::sevenzip::VolumeAttemptPlan& plan, const PreparedAttempt& attempt) const {
        for (auto it = entries_.rbegin(); it != entries_.rend(); ++it)
            if (it->layout == attempt.layout && std::all_of(it->sources.begin(), it->sources.end(),
                [&](const auto& source) { return attempt.sources[source.first] == source.second; }) &&
                (fixed_ || (it->trim_total == trim_total(plan, attempt) &&
                    std::equal(it->sizes.begin(), it->sizes.end(), attempt.sources.begin(), attempt.sources.end(),
                        [&](auto size, auto source) { return size == size_of(plan, source); })))) return &it->result;
        return nullptr;
    }

    void remember(const sunpack::sevenzip::VolumeAttemptPlan& plan, const PreparedAttempt& attempt, std::size_t capacity) {
        if (!attempt.probe) return;
        const auto& observed = attempt.probe->observed_volume_slots;
        if (!observed || find(plan, attempt) || !geometry.known(plan, attempt.layout)) return;
        while (entries_.size() >= capacity) entries_.pop_front();
        Entry entry{attempt.layout, {}, *attempt.probe, {}, 0};
        entry.sources.reserve(observed->size());
        for (const auto slot : *observed) entry.sources.emplace_back(slot, attempt.sources[slot]);
        if (!fixed_) {
            entry.trim_total = trim_total(plan, attempt);
            entry.sizes.reserve(attempt.sources.size());
            for (const auto source : attempt.sources) entry.sizes.push_back(size_of(plan, source));
        }
        entries_.push_back(std::move(entry));
    }
};

sunpack::sevenzip::PasswordTestResult probe_input(const WorkerRequest& request, WorkerArchiveInput& input,
    const std::vector<std::size_t>* domain = nullptr, bool final_volume_choice = false) {
    using namespace sunpack::sevenzip;
    const auto gap = input.missing_volume_number;
    if (gap) {
        // A later disk cannot be concatenated across a hole. Complete members
        // in the contiguous prefix still carry their original checksums.
        if (gap == 1 || !request.scan_only) {
            PasswordTestResult missing;
            missing.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
            missing.missing_volume = true;
            return missing;
        }
        const auto prefix = static_cast<std::size_t>(gap - 1);
        auto truncate = [prefix](auto& parts) { if (parts.size() > prefix) parts.resize(prefix); };
        truncate(input.ranges);
        truncate(input.part_paths);
        truncate(input.canonical_names);
    }
    const auto& candidates = request.password_candidates;
    const auto count = (std::max)(request.password_count(domain), std::size_t{1});
    const auto& plan = request.archive_input.volume_attempts;
    auto proof = test_password_batch(input.archive_path, input.part_paths, input.ranges, request.archive_input.format_hint,
        candidates.empty() ? &request.password : candidates.data(), count, input.canonical_names, request.scan_only, false,
        domain ? domain->data() : nullptr, plan.layouts.empty() ? nullptr : &plan, final_volume_choice);
    if (gap) {
        proof.missing_volume = true;
        proof.rejects_fixed_geometry = false;
        proof.observed_volume_slots.reset();
        if (proof.status != PasswordTestStatus::Ok) proof.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
    }
    return proof;
}

std::size_t rejected_prefix_size(const sunpack::sevenzip::PasswordTestResult& probe, std::size_t slots) {
    const auto& observed = probe.observed_volume_slots;
    if (!observed || observed->empty()) return 0;
    const auto count = observed->back() + 1;
    return count < slots ? count : 0;
}

std::deque<PreparedAttempt> probe_volume_wave(const WorkerRequest& request,
    sunpack::sevenzip::VolumeAttemptCursor& next, const std::atomic<bool>* cancel, VolumeProbeCache& cache) {
    using namespace sunpack::sevenzip;
    const auto& plan = request.archive_input.volume_attempts;
    std::deque<PreparedAttempt> prepared_attempts;
    PasswordParallelism parallel((std::max)(std::thread::hardware_concurrency(), 1u));
    std::vector<std::size_t> pending;
    bool exhausted = false;

    for (std::size_t i = 0; i < parallel.size(); ++i) {
        if (!next.next(plan, cancel)) { exhausted = true; break; }
        if (cancel && cancel->load()) break;
        prepared_attempts.push_back({next.layout, next.selected, {}});
        auto& prepared = prepared_attempts.back();
        if (const auto* cached = cache.find(plan, prepared)) {
            prepared.probe = *cached;
            // An earlier uncached composition can still win. Nothing after
            // this confirmed one is needed, including cursor advancement.
            if (cached->status == PasswordTestStatus::Ok) break;
            if (cached->status == PasswordTestStatus::WrongPassword) {
                const auto prefix = rejected_prefix_size(*cached, prepared.sources.size());
                if ((cached->rejects_fixed_geometry || prefix) && cache.can_skip_suffix(plan, prepared.layout)) {
                    // Keep the witness in the wave for the scan report and
                    // the extraction cursor. The lookahead need not copy or
                    // dispatch any composition under its rejected branch.
                    if (cached->rejects_fixed_geometry) next.skip_layout();
                    else next.skip_suffix(plan, prefix - 1);
                }
            }
        } else pending.push_back(i);
    }
    if (request.scan_only && request.password_verified && next.attempts == 1 && pending.size() == 1) {
        // Check uniqueness before the first member probe. A single-CPU wave
        // must keep its cursor unchanged when a second composition exists.
        if (!exhausted) {
            auto lookahead = next;
            exhausted = !lookahead.next(plan, cancel);
        }
        if (exhausted && (!cancel || !cancel->load(std::memory_order_relaxed))) return prepared_attempts;
    }
    std::optional<std::size_t> final_choice;
    if (!request.scan_only && !pending.empty() && pending.back() + 1 == prepared_attempts.size() &&
        (!cancel || !cancel->load(std::memory_order_relaxed)) && (exhausted || !next.next(plan, cancel))) {
        // Nothing after this composition can benefit from a rejection. Its
        // last viable password belongs to the extraction, including when
        // injectivity or size constraints left only one actual composition.
        const auto* domain = request.passwords_for_layout(prepared_attempts.back().layout);
        final_choice = pending.back();
        if (request.password_count(domain) <= 1) pending.pop_back();
    }
    const auto capacity = parallel.size();
    parallel.limit(pending.size());
#ifdef SUP7Z_DEBUG
    cache.scheduled_probes += pending.size();
#endif
    std::atomic<std::size_t> earliest{prepared_attempts.size()};
    parallel.run(pending.size(), [&](std::size_t task, std::size_t) {
        const auto lane = pending[task];
        if (lane > earliest.load()) return;
        auto& prepared = prepared_attempts[lane];
        WorkerArchiveInput input;
        select_volume_attempt(request.archive_input, prepared.layout, prepared.sources, input);
        prepared.probe = probe_input(request, input, request.passwords_for_layout(prepared.layout), final_choice == lane);
        if (prepared.probe->status == PasswordTestStatus::Ok) {
            auto old = earliest.load();
            while (lane < old && !earliest.compare_exchange_weak(old, lane)) {}
        }
    });
    if (earliest.load() < prepared_attempts.size()) prepared_attempts.resize(earliest.load() + 1);
    if (!native_job_cancelled()) for (const auto lane : pending) {
        if (lane >= prepared_attempts.size()) break;
        cache.remember(plan, prepared_attempts[lane], capacity);
    }
    return prepared_attempts;
}

// Scan returns transient observations in request coordinates. Rust reduces
// the ordinary plan before exposing it to scan callers.
void append_volume_selection(std::string& fields, std::size_t layout,
    const std::vector<std::size_t>& sources, std::size_t count = SIZE_MAX) {
    fields += wire::object() + wire::key("layout") + wire::number(layout) + wire::key("sources") + wire::array();
    for (std::size_t i = 0; i < (std::min)(count, sources.size()); ++i) wire::append_number(fields, sources[i]);
    fields += wire::end() + wire::end();
}

bool same_volume_prefix(const std::vector<std::size_t>& left, const std::vector<std::size_t>& right, std::size_t size) {
    return right.size() >= size && std::equal(left.begin(), left.begin() + size, right.begin());
}

RequestOutcome scan_request(WorkerRequest& request, const std::atomic<bool>* cancel) {
    using namespace sunpack::sevenzip;
    const auto& input = request.archive_input;
    const bool ambiguous = !input.volume_attempts.layouts.empty();
    PasswordTestResult probe;
    bool tested = false;
    bool verified = request.password_verified;
    bool ok = true;
    std::string fields;
    if (input.missing_volume_number) {
        ok = false;
        fields += wire::key("missing_volume") + wire::boolean(true) +
            wire::key("missing_volume_evidence") + wire::text("structured_volume_gap") +
            wire::key("failure_kind") + wire::text("missing_volume");
    }
    if ((!verified || ambiguous) && request.encrypted != 0) {
        const auto& candidates = request.password_candidates;
        if (ambiguous) {
            auto& plan = request.archive_input.volume_attempts;
            { NativeMemoryScope owned(nullptr); plan.prepare(); }
            VolumeAttemptCursor cursor;
            cursor.reserve(plan);
            bool rejected_prefix = false;
            bool frontier_found = false;
            std::string discarded_paths;
            std::string discarded_prefixes;
            std::string discarded_layouts;
            VolumeProbeCache proof_cache(plan);
            std::optional<std::size_t> skipped_layout;
            while (!tested) {
                auto wave = probe_volume_wave(request, cursor, cancel, proof_cache);
                if (wave.empty()) break;
                const PreparedAttempt* skipped_prefix = nullptr;
                std::size_t skipped_slots = 0;
                for (auto& candidate : wave) {
                    if (!candidate.probe && verified) {
                        fields += wire::key("volume_selection");
                        append_volume_selection(fields, candidate.layout, candidate.sources);
                        tested = true;
                        break;
                    }
                    if (skipped_layout == candidate.layout) continue;
                    if (skipped_prefix && skipped_prefix->layout == candidate.layout &&
                        same_volume_prefix(skipped_prefix->sources, candidate.sources, skipped_slots)) continue;
                    probe = std::move(*candidate.probe);
                    const bool rejected = probe.status == PasswordTestStatus::WrongPassword;
                    const auto prefix = rejected ? rejected_prefix_size(probe, candidate.sources.size()) : 0;
                    if (probe.rejects_fixed_geometry && proof_cache.can_skip_suffix(plan, candidate.layout)) {
                        skipped_layout = candidate.layout;
                        if (frontier_found) wire::append_number(discarded_layouts, candidate.layout);
                        if (cursor.layout == candidate.layout && !cursor.searching) cursor.skip_layout();
                    } else if (prefix && proof_cache.can_skip_suffix(plan, candidate.layout)) {
                        skipped_prefix = &candidate;
                        skipped_slots = prefix;
                        if (frontier_found) append_volume_selection(discarded_prefixes, candidate.layout, candidate.sources, prefix);
                        if (cursor.layout == candidate.layout && !cursor.searching &&
                            same_volume_prefix(candidate.sources, cursor.selected, prefix))
                            cursor.skip_suffix(plan, prefix - 1);
                    } else if (rejected && frontier_found) {
                        append_volume_selection(discarded_paths, candidate.layout, candidate.sources);
                    }
                    if (!frontier_found && rejected) rejected_prefix = true;
                    if (!frontier_found && !rejected) {
                        frontier_found = true;
                        if (rejected_prefix) {
                            fields += wire::key("first_remaining_volume");
                            append_volume_selection(fields, candidate.layout, candidate.sources);
                        }
                    }
                    if (probe.status == PasswordTestStatus::Ok) { tested = true; break; }
                }
                if (native_job_cancelled()) return interrupted_result(request.job_id);
            }
            if (!discarded_paths.empty())
                fields += wire::key("discarded_volume_paths") + wire::array() + discarded_paths + wire::end();
            if (!discarded_prefixes.empty())
                fields += wire::key("discarded_volume_prefixes") + wire::array() + discarded_prefixes + wire::end();
            if (!discarded_layouts.empty())
                fields += wire::key("discarded_volume_layouts") + wire::array() + discarded_layouts + wire::end();
            // Unavailable evidence leaves the corresponding scan input pending.
            if (!tested && !frontier_found && rejected_prefix) {
                ok = false;
                fields += wire::key("failure_kind") + wire::text(verified ? "missing_volume" : "password_or_volume_inconclusive") +
                    wire::key("volume_candidates_exhausted") + wire::boolean(true);
            }
        } else {
            probe = probe_input(request, request.archive_input);
            tested = true;
        }
        {
            if (auto* memory = current_native_memory_job()) {
                if (memory->denied.load(std::memory_order_acquire) && !memory->revoked.load(std::memory_order_acquire))
                    memory->owner.retry(*memory);
                if (memory->revoked.load(std::memory_order_acquire)) return {kMemoryRetry, {}};
            }
            if (native_job_cancelled()) return interrupted_result(request.job_id);
            verified |= probe.status == PasswordTestStatus::Ok && probe.encrypted;
            ok = ok && (probe.status == PasswordTestStatus::Ok || probe.weak_match || ambiguous);
            if (!ambiguous && !input.missing_volume_number && probe.status == PasswordTestStatus::Ok && probe.missing_volume) {
                ok = false;
                fields += wire::key("missing_volume") + wire::boolean(true) + wire::key("failure_kind") + wire::text("missing_volume") +
                    wire::key("missing_volume_evidence") + wire::text("open_volume_callback_not_found");
            } else if (!ok && !ambiguous && !input.missing_volume_number) {
                fields += wire::key("native_status") + wire::text(status_name(probe.status)) +
                    wire::key("message") + wire::text(probe.message) +
                    wire::key("password_candidates_all_rejected") + wire::boolean(probe.status == PasswordTestStatus::WrongPassword);
                if (probe.missing_volume)
                    fields += wire::key("missing_volume_suspected") + wire::boolean(true);
                if (probe.status == PasswordTestStatus::Error && probe.encrypted)
                    fields += wire::key("failure_kind") + wire::text("password_or_volume_inconclusive");
            }
            if (probe.status == PasswordTestStatus::Ok && !candidates.empty())
                fields += wire::key("matched_index") + wire::number(probe.matched_index);
        }
    }
    if (request.encrypted >= 0 || verified || (tested && (probe.encrypted || probe.status == PasswordTestStatus::Ok)))
        fields += wire::key("encrypted") + wire::boolean(request.encrypted == 1 || verified || probe.encrypted);
    NativeMemoryScope response_memory(nullptr);
    return {ok ? 0 : 1, wire::object() + wire::key("type") + wire::text("result") +
        wire::key("job_id") + wire::text(request.job_id) + wire::key("status") + wire::text(ok ? "ok" : "failed") +
        wire::key("operation") + wire::text("scan") + wire::key("password_verified") + wire::boolean(verified) +
        wire::key("archive_type") + wire::text(wide_to_utf8(probe.archive_type.empty() ? input.format_hint : probe.archive_type)) +
        fields + wire::end()};
}

bool uncertain_volume_password(const sunpack::sevenzip::ExtractArchiveResult& result,
                               const sunpack::sevenzip::ExtractionReplay& replay) {
    using namespace sunpack::sevenzip;
    return result.encrypted && result.password_crc_proven_items == 0 &&
        !FAILED(result.input_trace.read_hresult) && result.status != PasswordTestStatus::Error &&
        (result.failure_stage == "item_extract" || result.failure_stage == "archive_open") &&
        // Header decryption can fail during Open without an item callback,
        // so no operation_result/password_rejected receipt exists yet. A
        // password diagnosis from bytes actually read in a variable member
        // belongs to this composition, not to every remaining composition.
        (result.wrong_password || result.password_rejected || result.operation_result == kOpWrongPassword ||
         result.operation_result == kOpCrcError || result.operation_result == kOpDataError ||
         result.operation_result == kOpUnexpectedEnd || result.operation_result == kOpHeadersError) &&
        replay.uncertain_read.load(std::memory_order_relaxed);
}

bool volume_composition_failure(const sunpack::sevenzip::ExtractArchiveResult& result,
                                const sunpack::sevenzip::ExtractionReplay& replay,
                                bool password_verified) {
    using namespace sunpack::sevenzip;
    if (result.status == PasswordTestStatus::Ok ||
        result.unsupported_method || result.status == PasswordTestStatus::BackendUnavailable ||
        result.status == PasswordTestStatus::Error ||
        (FAILED(result.input_trace.read_hresult) && result.missing_volume_evidence != "open_volume_file_missing")) return false;
    const bool can_attribute_to_volume = password_verified || result.password_crc_proven_items != 0 ||
        uncertain_volume_password(result, replay);
    if (!can_attribute_to_volume && (result.encrypted || result.wrong_password || result.password_rejected)) return false;
    if (result.missing_volume) return true;
    if (result.failure_stage != "archive_open" && result.failure_stage != "item_extract") return false;
    if (result.failure_kind != "structure_recognition" && result.failure_kind != "checksum_error" &&
        result.failure_kind != "data_error" && result.failure_kind != "corrupted_data" && result.failure_kind != "headers_error" &&
        !(can_attribute_to_volume && result.failure_kind == "encrypted_or_wrong_password") &&
        result.failure_kind != "unexpected_end" && result.failure_kind != "missing_volume_or_tail") return false;
    // Binary readers record whether a variable source/range participated.
    // Seeks, fixed tails and failures confined to the fixed head are not proof.
    return replay.uncertain_read.load(std::memory_order_relaxed);
}

RequestOutcome run_request(
    WorkerRequest& request,
    // The registry lease in worker_loop covers the output-volume writer.
    const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& shared_writer = nullptr,
    const std::shared_ptr<std::atomic<bool>>& cancel_token = nullptr,
    const std::function<void()>& release_writer = {}
) {
    using namespace sunpack::sevenzip;

    const std::string& job_id = request.job_id;
    if (auto *memory = current_native_memory_job(); memory && memory->revoked.load(std::memory_order_acquire))
        return {kMemoryRetry, {}};
    if (cancel_token && cancel_token->load(std::memory_order_acquire)) {
        return interrupted_result(job_id);
    }

    const std::wstring& archive_path = request.archive_input.archive_path;
    const std::wstring& output_dir = request.output_dir;
    const std::wstring& password = request.password;
    const std::wstring& format_hint = request.archive_input.format_hint;
    const std::wstring& codepage = request.codepage;
    const std::vector<std::wstring>& password_candidates = request.password_candidates;
    if (archive_path.empty() || (!request.scan_only && output_dir.empty())) {
        NativeMemoryScope response_memory(nullptr);
        return {2,
            (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
            (wire::key("status") + wire::text("error") + wire::key("category") + wire::text("invalid_request") + wire::key("message") + wire::text("archive_path is required; extraction also requires output_dir") + wire::end())};
    }

    const bool volume_trials = !request.archive_input.volume_attempts.layouts.empty();
    auto progress = [&job_id, last_progress_emit = std::chrono::steady_clock::time_point{},
                     reported_bytes = false, volume_trials](const ExtractProgressEvent& event) mutable {
            if (volume_trials && event.event == "item_failed") return;
            const auto now = std::chrono::steady_clock::now();
            const bool first_bytes = !reported_bytes && event.completed_bytes > 0;
            const bool boundary = event.event == "total" || event.event == "item_failed" ||
                (event.event == "item_start" && event.item_index == 0) ||
                (event.event == "item_done" && event.item_index % 128 == 0);
            if (!first_bytes && !boundary && now - last_progress_emit < std::chrono::milliseconds(100)) return;
            print_frame(
                (wire::object() + wire::key("type") + wire::text("progress") + wire::key("job_id")) + wire::text(job_id) +
                wire::key("completed_bytes") + wire::number(event.completed_bytes) +
                wire::key("total_bytes") + wire::number(event.total_bytes) + wire::end());
            reported_bytes |= first_bytes;
            last_progress_emit = now;
    };

    if (!request.archive_input.validation_error.empty()) {
        NativeMemoryScope response_memory(nullptr);
        return {2,
            (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
            (wire::key("status") + wire::text("error") + wire::key("category") + wire::text("invalid_request") + wire::key("message")) +
            wire::text(request.archive_input.validation_error) + wire::end()};
    }
    if (request.scan_only) return scan_request(request, cancel_token.get());
    auto* volume_replay = current_extraction_replay;
    WorkerArchiveInput selected_input;
    if (volume_trials) {
        auto& cursor = volume_replay->volumes;
        if (!cursor.started) {
            const auto root = std::filesystem::path(win32_extended_path(output_dir));
            const bool output_owned = directory_is_empty_or_missing(root);
            if (!output_owned) {
                NativeMemoryScope response_memory(nullptr);
                return {2, (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("status") + wire::text("failed") + wire::key("failure_stage") + wire::text("output_prepare") + wire::key("failure_kind") + wire::text("output_filesystem") + wire::key("message") + wire::text("volume composition trials require an empty output directory") + wire::end())};
            }
            auto& plan = request.archive_input.volume_attempts;
            {
                // The derived tables have the same lifetime as the queued request.
                // Keep them on the request allocator even though only extraction needs them.
                NativeMemoryScope request_memory(nullptr);
                plan.prepare();
            }
            cursor.reserve(plan);
            cursor.started = true;
        }
    }
    const auto& archive_input = volume_trials ? selected_input : request.archive_input;
    std::deque<PreparedAttempt> prepared_attempts;
    const bool unique_volume_choice = volume_trials && request.archive_input.volume_attempts.layouts.size() == 1 &&
        request.archive_input.volume_attempts.minimum_slots_for(0) == request.archive_input.volume_attempts.layouts[0].size() &&
        std::all_of(request.archive_input.volume_attempts.layouts[0].begin(), request.archive_input.volume_attempts.layouts[0].end(),
            [&](const auto& slot) { return request.archive_input.volume_attempts.domains[slot.domain].size() == 1; });
    std::optional<PasswordTestResult> selected_probe;
    VolumeProbeCache proof_cache(request.archive_input.volume_attempts);
    auto extract_with_password = [&](const std::wstring& selected_password) {
        if (volume_trials) volume_replay->volume_output_started = true;
        // The callback is synchronous and its emit() serializes calls. Each
        // password/composition keeps its own progress counters on this stack.
        auto attempt_progress = progress;
        return extract_archive(archive_input.archive_path, archive_input.part_paths, archive_input.ranges,
            format_hint, selected_password, output_dir, codepage,
            request.report_progress ? ExtractProgressCallback{std::ref(attempt_progress)} : ExtractProgressCallback{},
            archive_input.canonical_names, request.archive_input.native_volume_input, shared_writer, cancel_token,
            request.output_inventory);
    };

    ExtractArchiveResult result;
    for (;;) {
        if (volume_trials) {
            auto& cursor = volume_replay->volumes;
            if (cursor.needs_next) {
                if (prepared_attempts.empty() && !(unique_volume_choice &&
                    request.password_count(request.passwords_for_layout(0)) <= 1)) {
                    if (request.report_progress) progress({"total", 0, 0, 0});
                    auto lookahead = cursor;
                    prepared_attempts = probe_volume_wave(request, lookahead, cancel_token.get(), proof_cache);
                }
                const bool found = cursor.next(request.archive_input.volume_attempts, cancel_token.get());
                if (!found) {
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
                selected_probe.reset();
                if (!prepared_attempts.empty() && prepared_attempts.front().layout == cursor.layout &&
                    prepared_attempts.front().sources == cursor.selected) {
                    selected_probe = std::move(prepared_attempts.front().probe);
                    prepared_attempts.pop_front();
                } else prepared_attempts.clear();
            }
            if (cursor.discard_pending) {
                const auto error = volume_replay->volume_output_started ? discard_candidate_output(output_dir) : std::error_code{};
                if (error) {
                    result.status = PasswordTestStatus::Error;
                    result.failure_stage = "candidate_cleanup";
                    result.failure_kind = "output_filesystem";
                    result.message = error.message();
                    break;
                }
                volume_replay->clear_output();
                volume_replay->volume_output_started = false;
                volume_replay->uncertain_read.store(false, std::memory_order_relaxed);
                volume_replay->candidate_index = 0;
                volume_replay->confirmed_candidate_index = -1;
                volume_replay->screened_candidates.clear();
                volume_replay->password_probe_done = false;
                volume_replay->volume_password_uncertain = false;
                volume_replay->candidates_started = volume_replay->candidate_output_owned = volume_replay->candidate_discard_pending = false;
                cursor.discard_pending = false;
            }
        }
        if (!volume_trials && password_candidates.size() > 1 &&
            (!volume_replay || !volume_replay->password_probe_done)) {
            if (request.report_progress) progress({"total", 0, 0, 0});
            selected_probe = test_password_batch(archive_input.archive_path, archive_input.part_paths,
                archive_input.ranges, format_hint, password_candidates.data(), password_candidates.size(), archive_input.canonical_names,
                false, false, nullptr, nullptr, true);
        }
        // Probe lanes share the job budget. An interrupted decoder cannot
        // establish a password/volume rejection; replay the same cursor.
        if (auto* memory = current_native_memory_job()) {
            if (memory->denied.load(std::memory_order_acquire) && !memory->revoked.load(std::memory_order_acquire))
                memory->owner.retry(*memory);
            if (memory->revoked.load(std::memory_order_acquire)) return {kMemoryRetry, {}};
        }
        if (cancel_token && cancel_token->load(std::memory_order_acquire)) return interrupted_result(job_id);
        if (selected_probe && selected_probe->status == PasswordTestStatus::WrongPassword) {
            if (volume_trials) {
#ifdef SUP7Z_DEBUG
                ++volume_replay->rejected_compositions;
#endif
                volume_replay->volume_password_ambiguous |= !request.password_verified;
                auto& cursor = volume_replay->volumes;
                const auto& plan = request.archive_input.volume_attempts;
                const auto prefix = rejected_prefix_size(*selected_probe, cursor.selected.size());
                if ((selected_probe->rejects_fixed_geometry || prefix) && proof_cache.can_skip_suffix(plan, cursor.layout)) {
                    if (selected_probe->rejects_fixed_geometry) {
                        while (!prepared_attempts.empty() && prepared_attempts.front().layout == cursor.layout)
                            prepared_attempts.pop_front();
                        cursor.skip_layout();
                    } else {
                        while (!prepared_attempts.empty() && prepared_attempts.front().layout == cursor.layout &&
                            same_volume_prefix(cursor.selected, prepared_attempts.front().sources, prefix))
                            prepared_attempts.pop_front();
                        cursor.skip_suffix(plan, prefix - 1);
                    }
                }
                volume_replay->volumes.needs_next = true;
                continue;
            }
            result = password_candidate_failure(*selected_probe);
            break;
        }
        // Publish completed screening before the extraction-side allocations
        // so a retry keeps the same confirmed or narrowed candidate domain.
        if (volume_replay && volume_replay->confirmed_candidate_index < 0 && selected_probe &&
            selected_probe->status == PasswordTestStatus::Ok && selected_probe->encrypted && !selected_probe->weak_match) {
            volume_replay->confirmed_candidate_index = selected_probe->matched_index;
        }
        if (volume_replay && selected_probe && !volume_replay->password_probe_done) {
            volume_replay->screened_candidates = std::move(selected_probe->possible_candidates);
            volume_replay->password_probe_done = true;
        }
        if (volume_trials) {
            const auto& cursor = volume_replay->volumes;
            const auto& plan = request.archive_input.volume_attempts;
#ifdef SUP7Z_DEBUG
            ++volume_replay->prepared_compositions;
#endif
            select_volume_attempt(request.archive_input, cursor.layout, cursor.selected, selected_input);
            auto& uncertainty = volume_replay->uncertain_ranges;
            uncertainty.clear();
            volume_replay->uncertain_paths.clear();
            unsigned long long offset = 0;
            bool variable_offset = false;
            for (std::size_t i = 0; i < selected_input.ranges.size(); ++i) {
                const auto& range = selected_input.ranges[i];
                const auto length = range.has_end ? (std::min)(range.end - range.start, UINT64_MAX - offset) : UINT64_MAX - offset;
                const auto& variation = plan.variation[i];
                if (variation.variable || variable_offset) {
                    if (!uncertainty.empty() && uncertainty.back().second == offset)
                        uncertainty.back().second += length;
                    else uncertainty.emplace_back(offset, offset + length);
                }
                if (variation.variable)
                    volume_replay->uncertain_paths.insert(plan.sources[cursor.selected[i]].path);
                variable_offset |= variation.variable_length || variation.length != length;
                offset += length;
            }
        }
        const auto* domain = volume_trials ? request.passwords_for_layout(volume_replay->volumes.layout) : nullptr;
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
        } else if (volume_replay && volume_replay->confirmed_candidate_index >= 0) {
            const auto index = volume_replay->confirmed_candidate_index;
            result = extract_with_password(password_candidates[index]);
            result.matched_index = index;
        } else {
            auto *replay = current_extraction_replay;
            // Existing outputs belong to a continuation/user. Keep the read-only
            // diagnostic fallback there; fresh outputs can confirm by extracting.
            const auto* remaining = replay && !replay->screened_candidates.empty() ? &replay->screened_candidates :
                selected_probe && !selected_probe->possible_candidates.empty() ? &selected_probe->possible_candidates : domain;
            const auto count = request.password_count(remaining);
            if (count > 1 && replay && !replay->candidates_started) {
                const auto root = std::filesystem::path(win32_extended_path(output_dir));
                replay->candidate_output_owned = directory_is_empty_or_missing(root);
                replay->candidates_started = true;
            }
            const bool direct_candidates = count == 1 ||
                (replay && replay->candidate_output_owned);
            if (!direct_candidates) {
                const auto probe = selected_probe && (selected_probe->status == PasswordTestStatus::Ok ||
                    (selected_probe->password_independent_failure && selected_probe->status == PasswordTestStatus::Error)) ?
                    std::move(*selected_probe) :
                    test_password_batch(archive_input.archive_path, archive_input.part_paths, archive_input.ranges,
                        format_hint, password_candidates.data(), count, archive_input.canonical_names, false, true,
                        remaining ? remaining->data() : nullptr);
                if (probe.status != PasswordTestStatus::Ok || probe.matched_index < 0 ||
                    static_cast<std::size_t>(probe.matched_index) >= password_candidates.size()) {
                    result = password_candidate_failure(probe);
                } else {
                    if (replay && probe.encrypted && !(current_native_memory_job() &&
                        current_native_memory_job()->revoked.load(std::memory_order_acquire)))
                        replay->confirmed_candidate_index = probe.matched_index;
                    result = extract_with_password(password_candidates[probe.matched_index]);
                    result.matched_index = probe.matched_index;
                }
            } else {
                const auto next_candidate = [&](std::size_t first) {
                    if (!remaining) return first;
                    const auto it = std::lower_bound(remaining->begin(), remaining->end(), first);
                    return it == remaining->end() ? password_candidates.size() : *it;
                };
                std::size_t index = replay ? replay->candidate_index : 0;
                if (!replay || !replay->candidate_discard_pending) index = next_candidate(index);
                while (index < password_candidates.size() || (replay && replay->candidate_discard_pending)) {
                    if (replay && replay->candidate_discard_pending) {
                        const auto error = discard_candidate_output(output_dir);
                        if (error) {
                            result = ExtractArchiveResult{};
                            result.status = PasswordTestStatus::Error;
                            result.failure_stage = "candidate_cleanup";
                            result.failure_kind = "output_filesystem";
                            result.message = error.message();
                            break;
                        }
                        replay->clear_output();
                        replay->candidate_discard_pending = false;
                        replay->candidate_index = index = next_candidate(index + 1);
                        continue;
                    }
                    if (cancel_token && cancel_token->load(std::memory_order_acquire)) break;
                    // A complete member proof skips earlier rejected passwords.
                    if (selected_probe && selected_probe->status == PasswordTestStatus::Ok &&
                        selected_probe->matched_index > static_cast<int>(index)) {
                        index = static_cast<std::size_t>(selected_probe->matched_index);
                        if (replay) replay->candidate_index = index;
                    }
                    // Confirmation uses the real extraction and its CRC receipts.
                    if (replay) replay->candidate_index = index;
                    result = extract_with_password(password_candidates[index]);
                    const bool direct_ok = result.status == PasswordTestStatus::Ok;
                    const bool uncertain_password = volume_trials && uncertain_volume_password(result, *volume_replay);
                    if (uncertain_password) volume_replay->volume_password_uncertain = true;
                    // ENC authenticates the password during Open; later MAC/CRC failures are data damage.
                    if (!direct_ok && !uncertain_password && result.encrypted && result.archive_type != L"enc" &&
                        result.password_crc_proven_items == 0 &&
                        !(cancel_token && cancel_token->load(std::memory_order_acquire)) &&
                        result.status != PasswordTestStatus::Error && result.failure_kind != "resource_unavailable" &&
                        !(current_native_memory_job() && current_native_memory_job()->revoked.load(std::memory_order_acquire)) &&
                        !(current_native_memory_job() && current_native_memory_job()->denied.load(std::memory_order_acquire)) &&
                        !(result.status == PasswordTestStatus::WrongPassword && result.operation_result == kOpWrongPassword)) {
                        if (extraction_rejects_password(result)) {
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
                    result.matched_index = direct_ok || result.password_crc_proven_items != 0 ? static_cast<int>(index) : -1;
                    if (result.password_crc_proven_items && replay && replay->confirmed_candidate_index < 0) {
                        replay->confirmed_candidate_index = static_cast<int>(index);
                    }
                    result.password_candidates_all_rejected =
                        result.password_candidates_all_rejected || result.wrong_password || result.password_rejected;
                    if (direct_ok || (replay && replay->confirmed_candidate_index >= 0) || (!result.password_candidates_all_rejected && !uncertain_password) || count == 1 ||
                        (cancel_token && cancel_token->load(std::memory_order_acquire))) break;
                    // The rejected attempt has no consumers after this point.
                    // Drop its item inventory before cleanup and the next decoder.
                    result = ExtractArchiveResult{};
                    replay->candidate_discard_pending = true;
                }
                if (index == password_candidates.size()) {
                    PasswordTestResult rejected;
                    rejected.status = PasswordTestStatus::WrongPassword;
                    rejected.message = "wrong password";
                    result = password_candidate_failure(rejected);
                }
            }
        }

        if (auto *memory = current_native_memory_job()) {
            if ((result.failure_kind == "resource_unavailable" ||
                 (memory->denied.load(std::memory_order_acquire) && result.status != PasswordTestStatus::Ok)) &&
                !memory->revoked.load(std::memory_order_acquire))
                memory->owner.retry(*memory);
            // An interrupted attempt is internal. Never publish its provisional
            // damage/password/output errors or a final result to the caller.
            if (memory->revoked.load(std::memory_order_acquire) && result.status != PasswordTestStatus::Ok) return {kMemoryRetry, {}};
        }

        if (cancel_token && cancel_token->load(std::memory_order_acquire)) return interrupted_result(job_id);

        const bool password_verified = request.password_verified || (volume_replay && volume_replay->confirmed_candidate_index >= 0);
        if (volume_trials && (uncertain_volume_password(result, *volume_replay) ||
            (volume_replay->volume_password_uncertain && result.password_candidates_all_rejected))) {
            if (!password_verified) volume_replay->volume_password_ambiguous = true;
            result.status = PasswordTestStatus::Damaged;
            result.wrong_password = result.password_rejected = result.password_candidates_all_rejected = false;
            result.failure_stage = "item_extract";
            result.failure_kind = "encrypted_or_wrong_password";
            result.operation_result = kOpDataError;
        }
        if (!volume_trials || !volume_composition_failure(result, *volume_replay, password_verified)) break;
        if (archive_input.missing_volume_number > 0 &&
            std::none_of(request.archive_input.volume_attempts.layouts.begin(), request.archive_input.volume_attempts.layouts.end(),
                [&](const auto& layout) { return std::any_of(layout.begin(), layout.end(), [&](const auto& slot) {
                    return slot.number == static_cast<unsigned int>(archive_input.missing_volume_number);
                }); })) break;
        auto& cursor = volume_replay->volumes;
        // Every composition of a sparse layout is missing the same slot.
        // Slot 1 instead denotes a candidate-dependent carrier trim failure.
        if (archive_input.missing_volume_number > 1) { cursor.skip_layout(); prepared_attempts.clear(); }
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
            result.status != PasswordTestStatus::Ok;
        if (execution_input_failure) {
            // Rust already proved this split tail from the same structural
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

    const bool ok = result.status == PasswordTestStatus::Ok;
    // Output handles have drained. Streaming the manifest needs the result
    // inventory and the retry state, but can block without holding the writer.
    if (release_writer) release_writer();
    std::string volume_selection;
    if (volume_trials && ok) {
        const auto& cursor = volume_replay->volumes;
        volume_selection = wire::key("volume_selection") + wire::object() +
            wire::key("layout") + wire::number(cursor.layout) + wire::key("sources") + wire::array();
        for (const auto source : cursor.selected) wire::append_number(volume_selection, source);
        volume_selection += wire::end() + wire::end();
    }
    const std::string manifest_field = ok
        ? wire::key("verified_manifest") + verified_manifest_wire(job_id, result, request.output_inventory) : "";
    const auto complete_files = !ok ? std::count_if(
        result.output_trace.items.begin(), result.output_trace.items.end(),
        [](const ExtractOutputItemTrace& item) {
            return !item.is_dir && item.done && !item.failed && item.operation_result == 0;
        }) : 0;
    const std::string failure_fields = ok ? "" :
        wire::key("failure_stage") + wire::text(result.failure_stage) +
        wire::key("failure_kind") + wire::text(result.failure_kind) +
        wire::key("hresult") + wire::number(result.hresult) +
        wire::key("operation_result_name") + wire::text(operation_result_name(result.operation_result));
    const std::string input_trace_field = FAILED(result.input_trace.read_hresult) ?
        wire::key("input_trace") + input_trace_wire(result.input_trace) : "";
#ifdef SUP7Z_DEBUG
    const std::string pipeline_timing_field = pipeline_timing_enabled() ?
        wire::key("pipeline_timing") + pipeline_timing_wire(result.pipeline_timing) : "";
#endif
    // The serialized frame is transport-owned and outlives the managed job.
    NativeMemoryScope response_memory(nullptr);
    return {ok ? 0 : 1,
        (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
        wire::key("status") + wire::text(ok ? "ok" : "failed") +
        wire::key("native_status") + wire::text(status_name(result.status)) +
        wire::key("encrypted") + wire::boolean(result.encrypted) +
        wire::key("damaged") + wire::boolean(result.damaged) +
        wire::key("checksum_error") + wire::boolean(result.checksum_error) +
        wire::key("missing_volume") + wire::boolean(result.missing_volume) +
        wire::key("missing_volume_suspected") + wire::boolean(result.missing_volume_suspected) +
        wire::key("missing_volume_evidence") + wire::text(result.missing_volume_evidence) +
        wire::key("missing_volume_name") + wire::text(wide_to_utf8(result.missing_volume_name)) +
        wire::key("wrong_password") + wire::boolean(result.wrong_password) +
        wire::key("password_rejected") + wire::boolean(result.password_rejected) +
        wire::key("password_crc_proven_items") + wire::number(result.password_crc_proven_items) +
        wire::key("password_candidates_all_rejected") + wire::boolean(result.password_candidates_all_rejected) +
        wire::key("matched_index") + wire::number(result.matched_index) +
        wire::key("unsupported_method") + wire::boolean(result.unsupported_method) +
        wire::key("recovered_complete_files") + wire::number(complete_files) +
        volume_selection +
        wire::key("archive_type") + wire::text(wide_to_utf8(result.archive_type)) +
        manifest_field +
        wire::key("message") + wire::text(result.message) +
        failure_fields + input_trace_field
#ifdef SUP7Z_DEBUG
        + pipeline_timing_field
#endif
        + wire::end()};
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
                   bool query_ok,
                   unsigned long query_error) {
                print_volume_space_status(state, free_bytes, query_ok, query_error);
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
                auto cancel_token = std::make_shared<std::atomic<bool>>(false);
                if (!job_id.empty()) {
                    std::lock_guard<std::mutex> cancel_lock(cancel_mutex_);
                    cancel_tokens_.insert_or_assign(
                        job_id,
                        JobControl{cancel_token});
                }
                Job job{
                    std::move(request),
                    std::move(cancel_token),
                };
                if (!job.request.from_watch) {
                    foreground_queue_.push_back(std::move(job), warm_queue_capacity());
                } else {
                    background_queue_.push_back(std::move(job), warm_queue_capacity());
                }
            }
        }

        if (rejected_for_capacity) {
            request = {};
            print_frame(
                (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("backpressure") + wire::key("retryable") + wire::boolean(true) + wire::key("failure_stage") + wire::text("native_admission") + wire::key("failure_kind") + wire::text("queue_capacity") + wire::key("message") + wire::text("native job queue is full") + wire::end()));
            print_job_event(job_id, "job_finished");
            return;
        }

        condition_.notify_one();
        // Native now owns the request. Send outside the scheduler lock, even
        // if a worker has already begun or completed this accepted job.
        print_job_event(job_id, "job_accepted");
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
        std::deque<Job> retired_queue;
        bool drained = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto* queue : {&foreground_queue_, &background_queue_}) {
                auto& jobs = queue->jobs;
                const auto found = std::find_if(jobs.begin(), jobs.end(), [&](const Job& job) {
                    return job.cancel_token == token;
                });
                if (found == jobs.end()) continue;
                withdrawn.emplace(std::move(*found));
                jobs.erase(found);
                queue->retire_if_drained(retired_queue);
                drained = queues_empty_locked() && active_jobs_ == 0 && parked_jobs_ == 0;
                break;
            }
        }
        retired_queue.clear();
        if (withdrawn) {
            if (withdrawn->execution) memory_.end(withdrawn->execution->memory);
            erase_cancel_token(job_id);
            withdrawn.reset();
            writer_to_wake.reset();
            print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                (wire::key("status") + wire::text("cancelled") + wire::key("native_status") + wire::text("cancelled") + wire::key("hresult") + wire::number(-2147467260) + wire::end()));
            print_job_event(job_id, "job_finished");
            if (drained) drain_condition_.notify_all();
            return true;
        }
#ifdef _WIN32
        // Wake only the facility this job writes to, whose producer may be parked in that backpressure wait; a reclaimed facility leaves an expired weak_ptr.
        if (writer_to_wake) {
            writer_to_wake->wake_waiters();
        }
#endif
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
    struct JobExecution {
        struct InputStamp {
            std::wstring path;
            WIN32_FILE_ATTRIBUTE_DATA data{};
            bool present = false;
        };
        JobExecution(sunpack::sevenzip::NativeMemoryManager &manager, const WorkerRequest &request) : memory(manager) {
            std::wstring_view first_path;
            std::optional<std::unordered_set<std::wstring_view>> additional_paths;
            const auto remember = [&](const std::wstring &path) {
                if (path.empty() || path == first_path) return;
                if (first_path.empty()) {
                    first_path = path;
                } else {
                    if (!additional_paths) additional_paths.emplace();
                    if (!additional_paths->insert(path).second) return;
                }
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
        std::unique_ptr<JobExecution> execution;
    };

    struct JobQueue {
        std::deque<Job> jobs;
        bool oversized = false;

        void push_back(Job&& job, std::size_t warm_capacity) {
            jobs.push_back(std::move(job));
            oversized |= jobs.size() > warm_capacity;
        }

        void push_front(Job&& job, std::size_t warm_capacity) {
            jobs.push_front(std::move(job));
            oversized |= jobs.size() > warm_capacity;
        }

        void retire_if_drained(std::deque<Job>& retired) noexcept {
            // MSVC retains the deque's raw blocks after pop/erase. Keep one
            // worker wave warm; detach larger drained piles before freeing.
            if (oversized && jobs.empty()) {
                jobs.swap(retired);
                oversized = false;
            }
        }
    };

    // The writer reference is deliberately weak: a strong one would keep a facility alive past its lease and could run ~AsyncFileWriter under the executor mutex.
    struct JobControl {
        explicit JobControl(std::shared_ptr<std::atomic<bool>> token)
            : cancel_token(std::move(token)) {}

        std::shared_ptr<std::atomic<bool>> cancel_token;
        std::weak_ptr<std::atomic<bool>> attempt_cancel;
        std::weak_ptr<sunpack::sevenzip::AsyncFileWriter> writer;
    };

    void erase_cancel_token(const std::string& job_id) noexcept {
        std::optional<decltype(cancel_tokens_)> retired;
        {
            std::lock_guard<std::mutex> lock(cancel_mutex_);
            cancel_tokens_.erase(job_id);
            if (cancel_tokens_.empty() && cancel_tokens_.bucket_count() > (std::max)(std::size_t{16}, worker_count_ * 4)) {
                try {
                    // A default map owns a small bucket array on MSVC.
                    retired.emplace();
                    cancel_tokens_.swap(*retired);
                } catch (const std::bad_alloc&) {
                    // Keep the reusable empty map if the allocator is under pressure.
                }
            }
        }
    }

    bool queues_empty_locked() const noexcept {
        return foreground_queue_.jobs.empty() && background_queue_.jobs.empty();
    }

    std::size_t warm_queue_capacity() const noexcept {
        return (std::max)(std::size_t{8}, worker_count_);
    }

    std::size_t queued_job_count_locked() const noexcept {
        return foreground_queue_.jobs.size() + background_queue_.jobs.size() + parked_jobs_;
    }

    Job pop_next_job_locked(std::deque<Job>& retired) {
        auto& selected = foreground_queue_.jobs.empty() ? background_queue_ : foreground_queue_;
        Job job = std::move(selected.jobs.front());
        selected.jobs.pop_front();
        selected.retire_if_drained(retired);
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

    static std::string space_event_payload(
        const char* event,
        const std::string& job_id,
        std::uint64_t episode_id,
        bool query_ok,
        unsigned long query_error
#ifdef SUP7Z_DEBUG
        , const std::string& volume_key,
        unsigned long win32_error,
        std::uint64_t free_bytes
#endif
    ) {
        return
            (wire::object() + wire::key("type") + wire::text("progress") + wire::key("job_id")) + wire::text(job_id) +
            wire::key("event") + wire::text(event) +
            wire::key("episode_id") + wire::number(episode_id) +
            wire::key("volume_query_ok") + wire::boolean(query_ok) +
            wire::key("volume_query_error") + wire::number(query_error)
#ifdef SUP7Z_DEBUG
            + wire::key("volume_key") + wire::text(volume_key) +
            wire::key("win32_error") + wire::number(win32_error) +
            wire::key("free_bytes") + wire::number(free_bytes)
#endif
            + wire::end();
    }

    void print_volume_space_status(
        const sunpack::sevenzip::VolumeStatePtr& state,
        [[maybe_unused]] std::uint64_t free_bytes,
        bool query_ok,
        unsigned long query_error
    ) noexcept {
        if (!state || !state->space_gate) {
            return;
        }
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
                episode_id,
                query_ok,
                query_error
#ifdef SUP7Z_DEBUG
                , state->key, query_ok ? 0UL : query_error, free_bytes
#endif
            ));
        }
    }

    // ChangeSink landing: keeps the volume-space monitor active and fans the event out to affected jobs.
    void on_space_transition(
        const sunpack::sevenzip::VolumeSpaceTransition& transition
    ) noexcept {
        const bool blocked = transition.kind == sunpack::sevenzip::VolumeSpaceTransition::Kind::Blocked;
        if (blocked) {
            space_monitor_->note_blocked();
            request_monitor_recheck();
        }
        for (const auto& job_id : transition.job_ids) {
            print_frame(space_event_payload(
                blocked ? "space_blocked" : "space_resumed",
                job_id,
                transition.episode_id,
                transition.query_ok,
                transition.query_error
#ifdef SUP7Z_DEBUG
                , transition.volume_key, transition.win32_error, transition.free_bytes
#endif
            ));
        }
    }

    void monitor_loop() noexcept {
        // Disk-space monitoring retains its existing active-only schedule.
        // Memory notifications and commitment checks belong to memory_.
        for (;;) {
            std::unique_lock<std::mutex> lock(monitor_mutex_);
            const auto now = std::chrono::steady_clock::now();
            auto deadline = writer_registry_->next_reap_deadline();
            {
                std::lock_guard<std::mutex> jobs_lock(mutex_);
                if (key_cache_deadline_ && now >= *key_cache_deadline_) {
                    NCrypto::N7z::ClearGlobalKeyCache();
                    NCrypto::NRar5::ClearGlobalKeyCache();
                    key_cache_deadline_.reset();
                }
                if (key_cache_deadline_ && (!deadline || *key_cache_deadline_ < *deadline)) {
                    deadline = key_cache_deadline_;
                }
            }
            if (const auto space = space_monitor_->next_poll_deadline();
                space && (!deadline || *space < *deadline)) deadline = space;
            if (deadline) monitor_condition_.wait_until(lock, *deadline,
                [this] { return monitor_stopping_ || monitor_recheck_; });
            else monitor_condition_.wait(lock,
                [this] { return monitor_stopping_ || monitor_recheck_; });
            if (monitor_stopping_) return;
            monitor_recheck_ = false;
            lock.unlock();
            writer_registry_->reap_idle();
            space_monitor_->tick(std::chrono::steady_clock::now());
        }
    }

    bool finish_attempt_locked() noexcept {
        if (--active_jobs_ == 0 && (NCrypto::N7z::HasGlobalKeyCache() || NCrypto::NRar5::HasGlobalKeyCache())) {
            key_cache_deadline_ = std::chrono::steady_clock::now() + writer_config_.idle_timeout;
            return true;
        }
        return false;
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
        std::deque<Job> retired_queue;
        for (;;) {
            Job job;
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

                job = pop_next_job_locked(retired_queue);
                if (active_jobs_++ == 0) key_cache_deadline_.reset();
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
            retired_queue.clear();

            const bool replaying = job.execution != nullptr;
            if (!job.execution) {
                if (job.request.report_progress) print_job_event(job.request.job_id, "job_started");
                job.execution = std::make_unique<JobExecution>(memory_, job.request);
            }
            RequestOutcome outcome{-100, {}};
            bool monitor_recheck_needed = false;
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
                    const bool interrupted = memory_job.cancel->load(std::memory_order_acquire);
                    if (replaying && !interrupted && !job.execution->inputs_unchanged()) {
                        sunpack::sevenzip::NativeMemoryScope response_memory(nullptr);
                        outcome = {1, (wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(job_id) +
                            (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("error") + wire::key("failure_kind") + wire::text("input_changed") + wire::key("failure_stage") + wire::text("native_replay") + wire::key("message") + wire::text("archive input changed while waiting for memory; rescan required") + wire::end())};
                    } else if (!job.request.scan_only && !interrupted) {
                        const std::string key = job.request.output_volume_key.empty() ? synthetic_volume_key(job_id) : job.request.output_volume_key;
                        auto lease = writer_registry_->acquire(key);
                        monitor_recheck_needed = true;
                        register_cancel_writer(job_id, lease.writer_pointer());
                        const auto weak = std::weak_ptr<sunpack::sevenzip::AsyncFileWriter>(lease.writer_pointer());
                        memory_.set_wake(memory_job, [weak] { if (auto writer = weak.lock()) writer->wake_waiters(); });
                        if (job.cancel_token->load(std::memory_order_acquire)) memory_job.cancel->store(true, std::memory_order_release);
                        std::optional<sunpack::sevenzip::SpaceJobRegistration> registration(std::in_place, lease, job_id);
                        auto writer = lease.writer_pointer();
                        outcome = run_request(job.request, writer, memory_job.cancel, [&] {
                            registration.reset();
                            writer.reset();
                            lease.reset();
                            request_monitor_recheck();
                            monitor_recheck_needed = false;
                        });
                    } else outcome = run_request(job.request, nullptr, memory_job.cancel);
                    if (outcome.response.size() > UINT32_MAX) {
                        outcome = {-100, {}};
                    }
                } catch (const std::bad_alloc&) {
                    memory_.retry(memory_job);
                    outcome.code = kMemoryRetry;
                } catch (const std::system_error &error) {
                    // MSVC std::thread reports _beginthreadex exhaustion as
                    // EAGAIN, including a failed small stack/CRT allocation.
                    // Writer-facility threads do not use the SDK allocator.
                    if (error.code() == std::errc::resource_unavailable_try_again) {
                        memory_.retry(memory_job);
                        outcome.code = kMemoryRetry;
#ifdef SUP7Z_DEBUG
                        print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + wire::text(job_id) +
                            (wire::key("event") + wire::text("memory_thread_resource_retry") + wire::key("error_code")) +
                            wire::number(error.code().value()) + wire::end());
#endif
                    }
                } catch (...) { outcome.code = -100; }
            }
            // Pending output and decoder threads have drained. Parked tasks
            // retain neither dictionaries, writer leases nor execution threads.
            cpu_budget_.release(1);
            memory_.end(memory_job);
            if (outcome.code == kMemoryRetry) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    monitor_recheck_needed = finish_attempt_locked() || monitor_recheck_needed;
                    ++parked_jobs_;
                }
                if (monitor_recheck_needed) request_monitor_recheck();
#ifdef SUP7Z_DEBUG
                print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + wire::text(job_id) +
                    (wire::key("event") + wire::text("memory_reclaimed") + wire::key("required_bytes")) + wire::number(memory_job.required) + wire::end());
#endif
                auto parked = std::make_shared<Job>(std::move(job));
                const auto notice = [parked](bool blocked, [[maybe_unused]] std::int64_t headroom, [[maybe_unused]] std::uint64_t needed) {
                    auto &episode = parked->execution->memory_episode;
                    if (blocked) ++episode;
                    print_frame((wire::object() + wire::key("type") + wire::text("native_memory") + wire::key("job_id")) + wire::text(parked->request.job_id) +
                        wire::key("event") + wire::text((blocked ? "memory_blocked" : "memory_resumed")) +
                        wire::key("episode_id") + wire::number(episode)
#ifdef SUP7Z_DEBUG
                        + wire::key("required_bytes") + wire::number(needed) +
                        wire::key("available_bytes") + wire::number((std::max)(headroom, std::int64_t{0}))
#endif
                        + wire::end());
                };
                memory_.park(memory_job, *parked->cancel_token, [this, parked](bool ready) {
                    if (!ready) parked->cancel_token->store(true, std::memory_order_release);
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        --parked_jobs_;
                        auto &queue = !parked->request.from_watch ? foreground_queue_ : background_queue_;
                        queue.push_front(std::move(*parked), warm_queue_capacity());
                    }
                    condition_.notify_one();
                }, notice);
                continue;
            }

            bool drained = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                monitor_recheck_needed = finish_attempt_locked() || monitor_recheck_needed;
                drained = queues_empty_locked() && active_jobs_ == 0 && parked_jobs_ == 0;
                any_job_failed_ = any_job_failed_ || outcome.code != 0;
            }
            if (!job_id.empty()) erase_cancel_token(job_id);
            const auto finished_job_id = std::move(job.request.job_id);
            job = {};
            if (monitor_recheck_needed) request_monitor_recheck();

            // cpu_budget_.release(1) wakes at most one queued admission waiter.
            // Drain waiters use a separate condition variable, while the
            // low-frequency monitor is touched only on active/idle edges.
            if (drained) {
                drain_condition_.notify_all();
            }
            if (outcome.code == -100) {
                print_frame((wire::object() + wire::key("type") + wire::text("result") + wire::key("job_id")) + wire::text(finished_job_id) +
                    (wire::key("status") + wire::text("failed") + wire::key("native_status") + wire::text("error") + wire::key("failure_kind") + wire::text("native_exception") + wire::key("failure_stage") + wire::text("native_execution") + wire::key("message") + wire::text("unexpected native execution exception") + wire::end()));
            } else {
                const auto response = std::move(outcome.response);
                print_frame(response);
            }
            print_job_event(finished_job_id, "job_finished");
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
    JobQueue foreground_queue_;
    JobQueue background_queue_;
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
    // Armed only when the last executing attempt leaves a populated cache.
    std::optional<std::chrono::steady_clock::time_point> key_cache_deadline_;
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
    // Return the SDK's temporary BSTR allocations to the heap on SysFreeString.
    SetOaNoCache();
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
        (wire::object() + wire::key("type") + wire::text("worker_ready")) +
        wire::key("thread_capacity") + wire::number(worker_count) +
#ifdef SUP7Z_DEBUG
        (wire::key("memory_management") + wire::text("commitment_replay")) +
        wire::key("memory_reserve_bytes") + wire::number(memory_reserve_bytes) +
#endif
        wire::key("process_mode") + wire::text(requested_process_mode) +
        wire::key("process_mode_applied") + wire::boolean(process_mode_applied) + wire::end());
    wire::RequestReader reader(std::cin);
    try {
        while (reader.start()) {
            WorkerRequest request;
            try {
                request = parse_worker_request(reader);
            } catch (const wire::AbandonedRequest&) {
                reader.retire_request();
                continue;
            }
            const bool shutdown = request.worker_command == "shutdown";
            const int code = run_message(std::move(request), executor);
            if (shutdown) {
                executor.stop(/*cancel_pending_jobs=*/false);
                return code;
            }
        }
    } catch (const std::exception& error) {
        try {
            print_frame(wire::object() + wire::key("type") + wire::text("worker_fatal") +
                wire::key("message") + wire::text(error.what()) + wire::end());
        } catch (...) {
            // The stdout transport itself can fail.
            std::cerr << "worker protocol: " << error.what() << "\n";
        }
        executor.stop(/*cancel_pending_jobs=*/true);
        return 2;
    }
    executor.stop(/*cancel_pending_jobs=*/false);
    return executor.had_job_failure() ? 1 : 0;
}
