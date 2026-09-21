#pragma once

#include "sevenzip_bridge/bridge.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace sunpack::sevenzip {

using UInt32 = std::uint32_t;
using UInt64 = std::uint64_t;
using Int32 = std::int32_t;

std::wstring archive_type_for_path(const std::wstring& path);

}  // namespace sunpack::sevenzip
