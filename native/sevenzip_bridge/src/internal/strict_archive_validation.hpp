#pragma once

#include "sevenzip_bridge/bridge.hpp"
#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool seven_zip_parts_prove_missing_tail(const std::vector<std::wstring> &part_paths, bool structured_order = false);

    bool zip_parts_require_unavailable_tail(const std::vector<std::wstring> &part_paths, bool structured_order = false);

#endif

}
