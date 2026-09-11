#pragma once

#include "sevenzip_bridge/bridge.hpp"

#include <string>
#include <vector>

namespace sunpack::sevenzip
{

    struct ArchiveOperationRequest
    {
        Sup7zOperationKind operation = SUP7Z_OPERATION_PROBE;
        std::wstring seven_zip_dll_path;
        std::wstring archive_path;
        std::vector<std::wstring> part_paths;
        std::vector<std::wstring> canonical_names;
        std::vector<int> volume_numbers;
        std::vector<ExtractInputRange> ranges;
        std::wstring format_hint;
        std::wstring password;
        std::vector<std::wstring> passwords;
    };

    struct ArchiveOperationResult
    {
        PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
        bool command_ok = false;
        bool is_archive = false;
        bool is_encrypted = false;
        bool password_required = false;
        bool is_broken = false;
        bool checksum_error = false;
        bool missing_volume = false;
        bool missing_volume_suspected = false;
        bool missing_stub = false;
        bool volume_open_failed = false;
        int matched_index = -1;
        int attempts = 0;
        unsigned long long archive_offset = 0;
        int item_count = 0;
        int operation_result = 0;
        std::wstring archive_type;
        std::wstring missing_volume_name;
        std::string missing_volume_evidence;
        std::string message;
    };

    ArchiveOperationResult run_archive_operation(const ArchiveOperationRequest &request);

} // namespace sunpack::sevenzip
