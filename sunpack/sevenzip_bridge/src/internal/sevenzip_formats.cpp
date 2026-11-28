#include "sevenzip_formats.hpp"

#include "lz4_handler.hpp"
#include "sevenzip_bridge/enc.h"
#include <array>
#include <iterator>
#include <utility>

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

    namespace
    {
        struct Handler {
            std::wstring_view name;
            unsigned char ids[2];
            std::wstring_view aliases[3]{};
            bool encrypted_headers = false;
            bool auto_detect = true;
        };

        // Physical fallback order is significant. ENC requires an explicit hint.
        constexpr Handler handlers[] = {
            {L"7z", {0x07}, {L"sevenzip", L"seven_zip"}, true},
            {L"zip", {0x01}, {L"zipx"}},
            {L"rar5", {0xCC, 0x03}, {L"rar"}, true},
            {L"rar4", {0x03, 0xCC}, {}, true},
            {L"tar", {0xEE}},
            {L"gzip", {0xEF}, {L"gz", L"tgz"}},
            {L"bzip2", {0x02}, {L"bz2", L"tbz2", L"tbz"}},
            {L"xz", {0x0C}, {L"txz"}},
            {L"zstd", {0x0E}, {L"zst", L"tzst"}},
            {L"lz4", {kLz4FormatId}},
            {L"enc", {kEncFormatId}, {}, false, false},
        };
        constexpr auto fallbacks = [] {
            std::array<unsigned char, std::size(handlers)> ids{};
            std::size_t count = 0;
            for (const auto& h : handlers)
                if (h.auto_detect) ids[count++] = h.ids[0];
            return std::pair{ids, count};
        }();

        bool matches(std::wstring_view hint, std::wstring_view name) noexcept {
            if (hint.size() != name.size()) return false;
            for (std::size_t i = 0; i < name.size(); ++i) {
                const auto c = hint[i];
                if ((c >= L'A' && c <= L'Z' ? c + (L'a' - L'A') : c) != name[i]) return false;
            }
            return true;
        }
    }

    ExtractionFormats extraction_formats_for_hint(std::wstring_view hint) noexcept
    {
        if (!hint.empty() && hint.front() == L'.') hint.remove_prefix(1);
        if (!hint.empty()) {
            for (const auto& handler : handlers) {
                const ExtractionFormats formats{handler.ids, handler.ids[1] ? 2u : 1u, handler.encrypted_headers};
                if (matches(hint, handler.name)) return formats;
                for (auto alias : handler.aliases) {
                    if (alias.empty()) break;
                    if (matches(hint, alias)) return formats;
                }
            }
        }
        return {fallbacks.first.data(), fallbacks.second, false};
    }

    std::wstring canonical_archive_type_for_guid(const GUID &format)
    {
        const auto id = format.Data4[5];
        for (const auto& handler : handlers)
            if (handler.ids[0] == id) return std::wstring(handler.name);
        return {};
    }

#endif

} // namespace sunpack::sevenzip
