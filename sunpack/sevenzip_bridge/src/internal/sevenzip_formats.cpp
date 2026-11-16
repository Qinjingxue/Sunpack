#include "sevenzip_formats.hpp"

#include "lz4_handler.hpp"
#include "sevenzip_bridge/enc.h"
#include "sevenzip_paths.hpp"

#ifdef _WIN32
#include "7zip/Common/RegisterCodec.h"
#include "7zip/Compress/ZstdDecoder.h"

namespace {
    // The standalone Zstandard and ZIP handlers already use this decoder.
    // 7-Zip-Zstandard archives refer to it by their own 7z method ID.
    REGISTER_CODEC_CREATE(CreateSevenZipZstdDecoder, NCompress::NZstd::CDecoder)
    REGISTER_CODEC_2(SunpackSevenZipZstd, CreateSevenZipZstdDecoder, nullptr, 0x04F71101, "ZSTD")
}
#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    ExtractionFormats extraction_formats_for_hint(const std::wstring &format_hint)
    {
        auto hint = lower_text(format_hint);
        if (!hint.empty() && hint.front() == L'.') hint.erase(hint.begin());

        if (hint == L"enc") return {{format_guid(kEncFormatId)}};
        if (hint == L"zip" || hint == L"zipx") return {{format_guid(0x01)}};
        if (hint == L"7z" || hint == L"sevenzip" || hint == L"seven_zip") return {{format_guid(0x07)}, true};
        if (hint == L"rar4") return {{format_guid(0x03), format_guid(0xCC)}, true};
        if (hint == L"rar" || hint == L"rar5") return {{format_guid(0xCC), format_guid(0x03)}, true};
        if (hint == L"tar") return {{format_guid(0xEE)}};
        if (hint == L"gz" || hint == L"gzip" || hint == L"tgz") return {{format_guid(0xEF)}};
        if (hint == L"bz2" || hint == L"bzip2" || hint == L"tbz2" || hint == L"tbz") return {{format_guid(0x02)}};
        if (hint == L"xz" || hint == L"txz") return {{format_guid(0x0C)}};
        if (hint == L"lz4") return {{format_guid(kLz4FormatId)}};
        if (hint == L"zst" || hint == L"zstd" || hint == L"tzst") return {{format_guid(0x0E)}};
        return {{format_guid(0x07), format_guid(0x01), format_guid(0xCC), format_guid(0x03), format_guid(0xEE),
                 format_guid(0xEF), format_guid(0x02), format_guid(0x0C), format_guid(0x0E), format_guid(kLz4FormatId)}};
    }

    std::wstring canonical_archive_type_for_guid(const GUID &format)
    {
        switch (format.Data4[5])
        {
        case 0x01: return L"zip";
        case 0x02: return L"bzip2";
        case 0x03: return L"rar4";
        case 0x07: return L"7z";
        case 0x0C: return L"xz";
        case 0x0E: return L"zstd";
        case 0x0F:
        case 0xEF: return L"gzip";
        case 0xCC: return L"rar5";
        case 0xEE: return L"tar";
        case kLz4FormatId: return L"lz4";
        case kEncFormatId: return L"enc";
        default: return L"";
        }
    }

#endif

} // namespace sunpack::sevenzip
