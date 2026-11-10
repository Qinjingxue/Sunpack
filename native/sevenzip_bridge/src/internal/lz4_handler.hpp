#pragma once
#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip {
inline constexpr unsigned char kLz4FormatId = 0xFA;
// Private archive properties: never expose XXH32 as the SDK's CRC32 property.
}
