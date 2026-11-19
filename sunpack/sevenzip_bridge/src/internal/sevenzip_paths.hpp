#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <filesystem>

#include <string>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    std::wstring lower_text(std::wstring value);

    std::wstring filename_lower(const std::wstring &path);

    bool directory_is_empty_or_missing(const std::filesystem::path &path);

#endif

}
