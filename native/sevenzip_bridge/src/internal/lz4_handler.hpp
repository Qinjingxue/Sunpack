#pragma once
#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip {
inline constexpr unsigned char kLz4FormatId = 0xFA;
// Private archive properties: never expose XXH32 as the SDK's CRC32 property.
inline constexpr PROPID kLz4ReceiptBase = 0x10000;
HRESULT configure_lz4(IInArchive *archive, const Lz4Options &options);
void read_lz4_receipt(IInArchive *archive, ExtractArchiveResult &result);
}
