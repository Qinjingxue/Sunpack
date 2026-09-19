#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"

SUP7Z_API int sup7z_try_passwords(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (matched_index) {
        *matched_index = -1;
    }
    if (attempts) {
        *attempts = 0;
    }
    if (!archive_path) {
        copy_message(message, message_chars, "missing required path");
        return status_code(PasswordTestStatus::Error);
    }

    const auto result = test_passwords(seven_zip_dll_path, archive_path, passwords, password_count);
    if (matched_index) {
        *matched_index = result.matched_index;
    }
    if (attempts) {
        *attempts = result.attempts;
    }
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

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
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (matched_index) {
        *matched_index = -1;
    }
    if (attempts) {
        *attempts = 0;
    }
    if (!archive_path) {
        copy_message(message, message_chars, "missing required path");
        return status_code(PasswordTestStatus::Error);
    }

    const auto result = test_passwords_with_parts(
        seven_zip_dll_path,
        archive_path,
        collect_part_paths(archive_path, part_paths, part_count),
        passwords,
        password_count);
    if (matched_index) {
        *matched_index = result.matched_index;
    }
    if (attempts) {
        *attempts = result.attempts;
    }
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

#endif
