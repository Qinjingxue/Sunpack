#include "sevenzip_paths.hpp"

#ifdef _WIN32

#include <algorithm>

#include <filesystem>

extern "C" __declspec(dllimport) WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR source);

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool directory_is_empty_or_missing(const std::filesystem::path &path)
    {
        std::error_code error;
        if (!std::filesystem::exists(path, error))
        {
            return !error;
        }
        const bool empty = std::filesystem::is_empty(path, error);
        return !error && empty;
    }

    std::wstring lower_text(std::wstring value)
    {

        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
                       { return ch < 128 ? ((ch >= L'A' && ch <= L'Z') ? ch + (L'a' - L'A') : ch)
                                         : RtlDowncaseUnicodeChar(ch); });

        return value;
    }

    std::wstring filename_lower(const std::wstring &path)
    {

        return lower_text(std::filesystem::path(path).filename().wstring());
    }

#endif

} // namespace sunpack::sevenzip
