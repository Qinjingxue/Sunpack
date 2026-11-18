#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include <optional>

namespace sunpack::sevenzip {

class AsyncFileWriter;
#ifdef SUP7Z_DEBUG
class PipelineTiming;

struct ExtractPipelineTiming {
    unsigned long long pipeline_wall_ns = 0;
    unsigned long long input_active_ns = 0;
    unsigned long long compute_active_ns = 0;
    unsigned long long compute_cpu_ns = 0;
    unsigned long long output_active_ns = 0;
    unsigned long long input_compute_overlap_ns = 0;
    unsigned long long input_output_overlap_ns = 0;
    unsigned long long compute_output_overlap_ns = 0;
    unsigned long long all_overlap_ns = 0;
    unsigned long long any_overlap_ns = 0;
    unsigned long long idle_ns = 0;
    unsigned long long prepare_output_directory_ns = 0;
    unsigned long long prepare_format_candidates_ns = 0;
    unsigned long long prepare_handler_create_ns = 0;
    unsigned long long prepare_stream_open_ns = 0;
    unsigned long long prepare_archive_open_ns = 0;
    unsigned long long prepare_item_probe_ns = 0;
    unsigned long long prepare_callback_setup_ns = 0;
    unsigned long long prepare_output_finalize_ns = 0;
    unsigned long long prepare_archive_close_ns = 0;
};
#endif

enum class PasswordTestStatus {
    Ok,
    WrongPassword,
    Damaged,
    Unsupported,
    BackendUnavailable,
    Error,
    NeedsVolumeOrTailDamaged,
};

// For shorter plaintext a CRC match carries at most eight bits per byte.
inline constexpr bool strong_member_crc(unsigned long long bytes) { return bytes >= 4; }

struct PasswordTestResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool encrypted = false;
    bool missing_volume = false;
    bool weak_match = false;
    bool password_independent_failure = false;
    bool rejects_fixed_geometry = false;
    std::optional<std::vector<std::size_t>> observed_volume_slots;
    std::vector<std::size_t> possible_candidates;
    int matched_index = -1;
    int operation_result = 0;
    std::wstring archive_type;
    std::string message;
};

struct ExtractProgressEvent {
    std::string_view event;
    unsigned long long completed_bytes = 0;
    unsigned long long total_bytes = 0;
    unsigned int item_index = 0;
};

struct ExtractInputTrace {
#ifdef SUP7Z_DEBUG
    PipelineTiming *pipeline_timing = nullptr;
#endif
    unsigned long long last_read_virtual_offset = 0;
    unsigned long long last_read_source_offset = 0;
    unsigned int last_read_requested = 0;
    int read_hresult = 0;
    std::wstring last_source_path;
};

struct ExtractOutputItemTrace {
    unsigned int index = 0;
    unsigned long long bytes_written = 0;
    unsigned long long expected_size = 0;
    int operation_result = 0;
    bool is_dir = false;
    bool encrypted = false;
    bool has_expected_size = false;
    bool strong_password_proof = false;
    bool done = false;
    bool failed = false;
    bool has_mtime_ns = false;
    unsigned long long mtime_ns = 0;
    std::vector<unsigned char> magic;
    std::wstring output_path;
};

struct ExtractOutputTrace {
    int last_hresult = 0;
    std::vector<ExtractOutputItemTrace> items;
};

struct ExtractArchiveResult {
#ifdef SUP7Z_DEBUG
    ExtractPipelineTiming pipeline_timing;
#endif
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool encrypted = false;
    bool damaged = false;
    bool checksum_error = false;
    bool missing_volume = false;
    bool missing_volume_suspected = false;
    bool wrong_password = false;
    bool password_rejected = false;
    bool password_candidates_all_rejected = false;
    bool unsupported_method = false;
    bool output_inventory_complete = false;
    int operation_result = 0;
    unsigned int item_count = 0;
    unsigned int files_written = 0;
    unsigned int password_crc_proven_items = 0;
    int hresult = 0;
    int matched_index = -1;
    std::wstring archive_type;
    std::wstring missing_volume_name;
    std::string failure_stage;
    std::string failure_kind;
    std::string missing_volume_evidence;
    std::string message;
    ExtractInputTrace input_trace;
    ExtractOutputTrace output_trace;
};

using ExtractProgressCallback = std::function<void(const ExtractProgressEvent&)>;

struct ExtractInputRange {
    std::wstring path;
    unsigned long long start = 0;
    unsigned long long end = 0;
    bool has_end = false;
};

struct VolumeAttemptPlan;
PasswordTestResult test_password_batch(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<ExtractInputRange>& input_ranges,
    const std::wstring& format_hint,
    const std::wstring* candidates,
    std::size_t candidate_count,
    const std::vector<std::wstring>& canonical_names,
    bool scan_only = false, bool final_read_only = false,
    const std::size_t* candidate_indices = nullptr,
    const VolumeAttemptPlan* volume_plan = nullptr
);

ExtractArchiveResult extract_archive(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<ExtractInputRange>& input_ranges,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    const std::wstring& codepage,
    ExtractProgressCallback progress = {},
    const std::vector<std::wstring>& canonical_names = {},
    bool native_volume_input = false,
    std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,
    std::shared_ptr<std::atomic<bool>> cancel_token = nullptr,
    bool output_inventory = true
);

const char* status_name(PasswordTestStatus status);

}  // namespace sunpack::sevenzip
