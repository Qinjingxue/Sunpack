#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>

namespace sunpack::sevenzip {

class AsyncFileWriter;

enum class PasswordTestStatus {
    Ok,
    WrongPassword,
    Damaged,
    Unsupported,
    BackendUnavailable,
    Error,
    NeedsVolumeOrTailDamaged,
};

struct PasswordTestResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool backend_available = false;
    bool is_archive = false;
    bool encrypted = false;
    bool password_required = false;
    bool missing_volume = false;
    bool missing_volume_suspected = false;
    bool missing_stub = false;
    bool volume_open_failed = false;
    bool wrong_password = false;
    bool damaged = false;
    int matched_index = -1;
    int attempts = 0;
    unsigned long long archive_offset = 0;
    int operation_result = 0;
    std::wstring archive_type;
    std::wstring missing_volume_name;
    std::string missing_volume_evidence;
    std::string message;
};

struct ExtractProgressEvent {
    std::string event;
    unsigned long long completed_bytes = 0;
    unsigned long long total_bytes = 0;
    unsigned int item_index = 0;
    std::wstring item_path;
};

struct ExtractHandlerAttempt {
    std::wstring format;
    int create_hresult = 0;
    int open_hresult = 0;
    bool created = false;
    bool opened = false;
};

struct ExtractInputTrace {
    std::wstring mode;
    unsigned long long virtual_size = 0;
    unsigned long long position = 0;
    unsigned long long max_position_seen = 0;
    unsigned long long total_bytes_returned = 0;
    // Populated only when SUNPACK_SEVENZIP_PROFILE_READS=1 in the worker
    // environment. This is wall time spent in synchronous input ReadFile calls.
    unsigned long long read_file_call_count = 0;
    unsigned long long read_file_wall_ns = 0;
    unsigned long long read_file_max_wall_ns = 0;
    // Logical IInStream access pattern, populated only when input-read
    // profiling is enabled, describing the access requested by 7z.dll.
    unsigned long long logical_read_call_count = 0;
    unsigned long long sequential_read_bytes = 0;
    unsigned long long nonsequential_read_bytes = 0;
    unsigned long long sequential_run_count = 0;
    unsigned long long max_sequential_run_bytes = 0;
    unsigned long long current_sequential_run_bytes = 0;
    unsigned long long seek_count = 0;
    unsigned long long seek_forward_bytes = 0;
    unsigned long long seek_backward_bytes = 0;
    // Prefetch state and counters, populated only when input-read profiling
    // is enabled.
    bool prefetch_enabled = false;
    unsigned long long prefetch_hit_count = 0;
    unsigned long long prefetch_miss_count = 0;
    unsigned long long prefetch_invalidation_count = 0;
    unsigned long long prefetch_consumer_wait_ns = 0;
    unsigned long long last_logical_read_end = 0;
    bool has_last_logical_read_end = false;
    unsigned long long last_read_virtual_offset = 0;
    unsigned long long last_read_source_offset = 0;
    unsigned long long last_seek_new_position = 0;
    unsigned int last_read_requested = 0;
    unsigned int last_read_returned = 0;
    unsigned int last_seek_origin = 0;
    unsigned int last_range_index = 0;
    long long last_seek_offset = 0;
    int last_hresult = 0;
    int last_win32_error = 0;
    bool read_error = false;
    std::wstring last_source_path;
};

struct ExtractOutputItemTrace {
    unsigned int index = 0;
    unsigned long long bytes_written = 0;
    unsigned long long expected_size = 0;
    unsigned int source_crc32 = 0;
    unsigned int output_crc32 = 0;
    int operation_result = 0;
    int hresult = 0;
    int win32_error = 0;
    bool is_dir = false;
    bool encrypted = false;
    bool has_expected_size = false;
    bool has_source_crc32 = false;
    bool has_output_crc32 = false;
    bool crc_verified = false;
    bool done = false;
    bool failed = false;
    bool has_mtime_ns = false;
    unsigned long long mtime_ns = 0;
    std::vector<unsigned char> magic;
    std::wstring path;
    std::wstring output_path;
};

struct ExtractOutputTrace {
    unsigned long long total_bytes_written = 0;
    unsigned long long current_item_bytes_written = 0;
    unsigned long long last_write_size = 0;
    unsigned int current_item_index = 0;
    int last_hresult = 0;
    int last_win32_error = 0;
    std::wstring current_item_path;
    std::vector<ExtractOutputItemTrace> items;
};

struct ExtractArchiveResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool backend_available = false;
    bool command_ok = false;
    bool encrypted = false;
    bool damaged = false;
    bool checksum_error = false;
    bool missing_volume = false;
    bool missing_volume_suspected = false;
    bool wrong_password = false;
    bool password_rejected = false;
    bool password_crc_proven = false;
    bool password_candidate_batch = false;
    bool password_candidate_direct = false;
    bool password_candidates_all_rejected = false;
    bool unsupported_method = false;
    bool output_inventory_complete = false;
    int operation_result = 0;
    unsigned int item_count = 0;
    unsigned int files_written = 0;
    unsigned int dirs_written = 0;
    unsigned int password_crc_proven_items = 0;
    unsigned int password_candidate_count = 0;
    unsigned long long bytes_written = 0;
    unsigned int failed_item_index = 0;
    unsigned long long failed_item_bytes_written = 0;
    int hresult = 0;
    int matched_index = -1;
    int password_attempts = 0;
    std::wstring archive_type;
    std::wstring failed_item;
    std::wstring missing_volume_name;
    std::wstring requested_codepage;
    std::wstring applied_codepage;
    std::wstring filename_decoder;
    std::string failure_stage;
    std::string failure_kind;
    std::string missing_volume_evidence;
    std::string message;
    ExtractInputTrace input_trace;
    ExtractOutputTrace output_trace;
    std::vector<ExtractHandlerAttempt> handler_attempts;
};

using ExtractProgressCallback = std::function<void(const ExtractProgressEvent&)>;

struct ExtractInputRange {
    std::wstring path;
    unsigned long long start = 0;
    unsigned long long end = 0;
    bool has_end = false;
};

struct ExtractPatchOperation {
    std::wstring op;
    std::wstring target = L"logical";
    unsigned long long offset = 0;
    unsigned long long size = 0;
    bool has_size = false;
    std::vector<unsigned char> data;
};

bool is_backend_available(const std::wstring& seven_zip_dll_path);

PasswordTestResult test_password(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::wstring& password
);

PasswordTestResult test_password_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password,
    const std::vector<std::wstring>& canonical_names = {}
);

PasswordTestResult test_passwords(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const wchar_t* const* passwords,
    int password_count
);

PasswordTestResult test_passwords_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const wchar_t* const* passwords,
    int password_count,
    const std::vector<std::wstring>& canonical_names = {}
);

PasswordTestResult test_passwords_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const wchar_t* const* passwords,
    int password_count
);

ExtractArchiveResult extract_archive_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    const std::wstring& codepage,
    const std::vector<std::wstring>& decoded_names,
    ExtractProgressCallback progress = nullptr,
    bool dry_run = false,
    const std::vector<std::wstring>& canonical_names = {},
    bool native_volume_input = false,
    std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,
    std::size_t job_buffer_budget = 0,
    std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
);

ExtractArchiveResult extract_archive_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    const std::wstring& codepage,
    const std::vector<std::wstring>& decoded_names,
    ExtractProgressCallback progress = {},
    bool dry_run = false,
    std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,
    std::size_t job_buffer_budget = 0,
    std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
);

ExtractArchiveResult extract_archive_with_patches(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<ExtractInputRange>& ranges,
    const std::vector<ExtractPatchOperation>& patches,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    const std::wstring& codepage,
    const std::vector<std::wstring>& decoded_names,
    ExtractProgressCallback progress = {},
    bool dry_run = false,
    std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,
    std::size_t job_buffer_budget = 0,
    std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
);

const char* status_name(PasswordTestStatus status);

}  // namespace sunpack::sevenzip

#ifdef _WIN32
#ifdef SUP7Z_BUILD_DLL
#define SUP7Z_API extern "C" __declspec(dllexport)
#else
#define SUP7Z_API extern "C" __declspec(dllimport)
#endif

SUP7Z_API int sup7z_try_passwords(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_try_passwords_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_test_archive(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    int* command_ok,
    int* encrypted,
    int* checksum_error,
    wchar_t* archive_type,
    int archive_type_chars,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_test_archive_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int* command_ok,
    int* encrypted,
    int* checksum_error,
    wchar_t* archive_type,
    int archive_type_chars,
    wchar_t* message,
    int message_chars
);

struct Sup7zArchiveResourceAnalysis {
    int status;
    int is_archive;
    int is_encrypted;
    int is_broken;
    int solid;
    int item_count;
    int file_count;
    int dir_count;
    unsigned long long archive_size;
    unsigned long long total_unpacked_size;
    unsigned long long total_packed_size;
    unsigned long long largest_item_size;
    unsigned long long largest_dictionary_size;
    wchar_t archive_type[32];
    wchar_t dominant_method[128];
};

enum Sup7zOperationKind {
    SUP7Z_OPERATION_PROBE = 1,
    SUP7Z_OPERATION_TEST = 2,
    SUP7Z_OPERATION_TRY_PASSWORDS = 3,
};

struct Sup7zInputRange {
    const wchar_t* path;
    unsigned long long start;
    unsigned long long end;
    int has_end;
};

struct Sup7zOperationRequest {
    int operation;
    const wchar_t* seven_zip_dll_path;
    const wchar_t* archive_path;
    const wchar_t* const* part_paths;
    int part_count;
    const wchar_t* const* canonical_names;
    const int* volume_numbers;
    const Sup7zInputRange* ranges;
    int range_count;
    const wchar_t* format_hint;
    const wchar_t* password;
    const wchar_t* const* passwords;
    int password_count;
};

struct Sup7zOperationResult {
    int status;
    int command_ok;
    int is_archive;
    int is_encrypted;
    int is_broken;
    int checksum_error;
    int matched_index;
    int attempts;
    unsigned long long archive_offset;
    int item_count;
    int operation_result;
    int password_required;
    int missing_volume;
    int missing_volume_suspected;
    int missing_stub;
    int volume_open_failed;
    wchar_t archive_type[64];
    wchar_t missing_volume_name[260];
    wchar_t missing_volume_evidence[64];
    wchar_t message[512];
};

SUP7Z_API int sup7z_run_operation(
    const Sup7zOperationRequest* request,
    Sup7zOperationResult* result
);

SUP7Z_API int sup7z_analyze_archive_resources(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_analyze_archive_resources_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_read_archive_crc_manifest(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
);

SUP7Z_API int sup7z_read_archive_crc_manifest_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
);
#endif
