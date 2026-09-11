#include "embedded_7z.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <limits>

namespace sunpack::sevenzip
{

    namespace
    {

        using UInt32 = std::uint32_t;
        using UInt64 = std::uint64_t;

        std::wstring win32_extended_path(const std::wstring &path)
        {
            if (path.empty())
            {
                return path;
            }
            if (path.rfind(LR"(\\?\)", 0) == 0 || path.rfind(LR"(\\.\)", 0) == 0)
            {
                return path;
            }
            if (path.rfind(LR"(\\)", 0) == 0)
            {
                return LR"(\\?\UNC\)" + path.substr(2);
            }
            if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'))
            {
                return LR"(\\?\)" + path;
            }
            return path;
        }

        std::wstring lower_text(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
                           { return static_cast<wchar_t>(::towlower(ch)); });
            return value;
        }

        std::wstring lower_extension(const std::wstring &path)
        {
            return lower_text(std::filesystem::path(path).extension().wstring());
        }

        std::wstring filename_lower(const std::wstring &path)
        {
            return lower_text(std::filesystem::path(path).filename().wstring());
        }

        UInt64 file_size_or_zero(const std::wstring &path)
        {
            try
            {
                return static_cast<UInt64>(std::filesystem::file_size(path));
            }
            catch (...)
            {
                return 0;
            }
        }

        UInt32 le32_at(const std::vector<unsigned char> &data, std::size_t offset)
        {
            if (offset + 4 > data.size())
            {
                return 0;
            }
            return static_cast<UInt32>(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }

        UInt64 le64_at(const std::vector<unsigned char> &data, std::size_t offset)
        {
            return static_cast<UInt64>(le32_at(data, offset)) |
                   (static_cast<UInt64>(le32_at(data, offset + 4)) << 32);
        }

        UInt32 crc32_bytes(const unsigned char *bytes, std::size_t size)
        {
            UInt32 crc = 0xFFFF'FFFFu;
            for (std::size_t i = 0; i < size; ++i)
            {
                crc ^= bytes[i];
                for (int bit = 0; bit < 8; ++bit)
                {
                    const UInt32 mask = (crc & 1u) ? 0xEDB8'8320u : 0u;
                    crc = (crc >> 1) ^ mask;
                }
            }
            return ~crc;
        }

        bool read_file_range_exact(
            const std::wstring &path,
            UInt64 offset,
            UInt64 size,
            std::vector<unsigned char> &data)
        {
#ifdef _WIN32
            data.clear();
            if (size > static_cast<UInt64>(std::numeric_limits<DWORD>::max()))
            {
                return false;
            }
            data.resize(static_cast<std::size_t>(size));
            HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            LARGE_INTEGER distance{};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN))
            {
                CloseHandle(handle);
                return false;
            }
            DWORD read = 0;
            const BOOL ok = data.empty() || ReadFile(handle, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
            CloseHandle(handle);
            return ok && read == data.size();
#else
            (void)path;
            (void)offset;
            (void)size;
            (void)data;
            return false;
#endif
        }

        bool seven_zip_header_ok_at(const std::wstring &path, UInt64 offset, UInt64 file_size)
        {
            if (offset + 32u > file_size)
            {
                return false;
            }
            std::vector<unsigned char> header;
            if (!read_file_range_exact(path, offset, 32, header))
            {
                return false;
            }
            const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
            if (!std::equal(std::begin(signature), std::end(signature), header.begin()))
            {
                return false;
            }
            const UInt32 stored_start_crc = le32_at(header, 8);
            if (crc32_bytes(header.data() + 12, 20) != stored_start_crc)
            {
                return false;
            }
            const UInt64 next_offset = le64_at(header, 12);
            const UInt64 next_size = le64_at(header, 20);
            if (next_offset > file_size || next_size > file_size)
            {
                return false;
            }
            const UInt64 next_start = offset + 32u + next_offset;
            if (next_start < offset || next_start > file_size || next_start + next_size < next_start || next_start + next_size > file_size)
            {
                return false;
            }
            if (next_size == 0)
            {
                return true;
            }
            constexpr UInt64 kMaxNextHeaderCrcBytes = 64ull * 1024ull * 1024ull;
            if (next_size > kMaxNextHeaderCrcBytes)
            {
                return true;
            }
            std::vector<unsigned char> next_header;
            if (!read_file_range_exact(path, next_start, next_size, next_header))
            {
                return false;
            }
            return crc32_bytes(next_header.data(), static_cast<std::size_t>(next_header.size())) == le32_at(header, 28);
        }

        struct EmbeddedSignature
        {
            const unsigned char *bytes = nullptr;
            std::size_t size = 0;
            unsigned char format_id = 0;
            const wchar_t *archive_type = L"";
        };

        bool zip_local_header_plausible_at(const std::wstring &path, UInt64 offset, UInt64 file_size)
        {
            if (offset + 30u > file_size)
            {
                return false;
            }
            std::vector<unsigned char> header;
            if (!read_file_range_exact(path, offset, 30, header))
            {
                return false;
            }
            if (le32_at(header, 0) != 0x04034B50u)
            {
                return false;
            }
            const UInt32 compressed_size = le32_at(header, 18);
            const UInt32 name_len = static_cast<UInt32>(header[26] | (header[27] << 8));
            const UInt32 extra_len = static_cast<UInt32>(header[28] | (header[29] << 8));
            const UInt64 payload_offset = offset + 30u + name_len + extra_len;
            if (name_len == 0 || payload_offset > file_size)
            {
                return false;
            }
            if (compressed_size != 0 && payload_offset + compressed_size > file_size)
            {
                return false;
            }
            return true;
        }

        bool candidate_header_ok_at(const std::wstring &path, const EmbeddedSignature &signature, UInt64 offset, UInt64 file_size)
        {
            if (offset == 0)
            {
                return false;
            }
            if (signature.format_id == 0x07)
            {
                return seven_zip_header_ok_at(path, offset, file_size);
            }
            if (signature.format_id == 0x01)
            {
                return zip_local_header_plausible_at(path, offset, file_size);
            }
            return offset + signature.size <= file_size;
        }

        std::vector<EmbeddedArchiveCandidate> find_embedded_signature_candidates(
            const std::wstring &path,
            std::size_t max_candidates = 32)
        {
            std::vector<EmbeddedArchiveCandidate> candidates;
#ifdef _WIN32
            const UInt64 file_size = file_size_or_zero(path);
            if (file_size <= 8)
            {
                return candidates;
            }
            HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                return candidates;
            }

            static constexpr unsigned char seven_zip[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
            static constexpr unsigned char rar4[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
            static constexpr unsigned char rar5[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
            static constexpr unsigned char zip[] = {'P', 'K', 0x03, 0x04};
            static constexpr unsigned char gzip[] = {0x1F, 0x8B};
            static constexpr unsigned char bzip2[] = {'B', 'Z', 'h'};
            static constexpr unsigned char xz[] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
            static constexpr unsigned char zstd[] = {0x28, 0xB5, 0x2F, 0xFD};
            const std::array<EmbeddedSignature, 8> signatures{{
                {seven_zip, sizeof(seven_zip), 0x07, L"7z"},
                {rar5, sizeof(rar5), 0xCC, L"rar"},
                {rar4, sizeof(rar4), 0x03, L"rar"},
                {zip, sizeof(zip), 0x01, L"zip"},
                {xz, sizeof(xz), 0x0C, L"xz"},
                {zstd, sizeof(zstd), 0x0E, L"zstd"},
                {bzip2, sizeof(bzip2), 0x02, L"bzip2"},
                {gzip, sizeof(gzip), 0x0F, L"gzip"},
            }};
            std::size_t longest_signature = 0;
            for (const auto &signature : signatures)
            {
                longest_signature = std::max(longest_signature, signature.size);
            }

            constexpr DWORD kChunkSize = 4u * 1024u * 1024u;
            std::vector<unsigned char> carry;
            UInt64 file_offset = 0;
            while (file_offset < file_size && candidates.size() < max_candidates)
            {
                const UInt64 remaining = file_size - file_offset;
                const DWORD want = static_cast<DWORD>(std::min<UInt64>(remaining, kChunkSize));
                std::vector<unsigned char> buffer(carry.size() + want);
                std::copy(carry.begin(), carry.end(), buffer.begin());
                DWORD read = 0;
                const BOOL ok = ReadFile(handle, buffer.data() + carry.size(), want, &read, nullptr);
                if (!ok || read == 0)
                {
                    break;
                }
                buffer.resize(carry.size() + read);
                const UInt64 scan_base = file_offset - carry.size();
                for (std::size_t index = 0; index < buffer.size(); ++index)
                {
                    for (const auto &signature : signatures)
                    {
                        if (index + signature.size > buffer.size())
                        {
                            continue;
                        }
                        if (!std::equal(signature.bytes, signature.bytes + signature.size, buffer.begin() + index))
                        {
                            continue;
                        }
                        const UInt64 absolute = scan_base + index;
                        if (!candidate_header_ok_at(path, signature, absolute, file_size))
                        {
                            continue;
                        }
                        candidates.push_back(EmbeddedArchiveCandidate{path, absolute, signature.format_id, signature.archive_type});
                        if (candidates.size() >= max_candidates)
                        {
                            break;
                        }
                    }
                    if (candidates.size() >= max_candidates)
                    {
                        break;
                    }
                }
                file_offset += read;
                const std::size_t keep = std::min<std::size_t>(longest_signature - 1, buffer.size());
                carry.assign(buffer.end() - keep, buffer.end());
            }
            CloseHandle(handle);
#else
            (void)path;
            (void)max_candidates;
#endif
            return candidates;
        }

        std::vector<std::wstring> unique_paths(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
        {
            std::vector<std::wstring> input = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
            if (std::find(input.begin(), input.end(), archive_path) == input.end())
            {
                input.push_back(archive_path);
            }
            std::vector<std::wstring> result;
            std::vector<std::wstring> seen;
            for (const auto &path : input)
            {
                if (path.empty())
                {
                    continue;
                }
                const std::wstring key = lower_text(std::filesystem::path(path).wstring());
                if (std::find(seen.begin(), seen.end(), key) != seen.end())
                {
                    continue;
                }
                seen.push_back(key);
                result.push_back(path);
            }
            return result;
        }

    } // namespace

    bool is_standard_seven_zip_path(const std::wstring &path)
    {
        const std::wstring ext = lower_extension(path);
        if (ext == L".7z")
        {
            return true;
        }
        const std::wstring name = filename_lower(path);
        return name.size() >= 7 && name.compare(name.size() - 7, 7, L".7z.001") == 0;
    }

    std::vector<EmbeddedArchiveCandidate> find_embedded_archive_candidates(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths)
    {
        std::vector<EmbeddedArchiveCandidate> candidates;
        for (const auto &path : unique_paths(archive_path, part_paths))
        {
            auto path_candidates = find_embedded_signature_candidates(path);
            candidates.insert(candidates.end(), path_candidates.begin(), path_candidates.end());
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto &left, const auto &right)
                  {
        if (left.offset != right.offset) {
            return left.offset < right.offset;
        }
        return left.format_id < right.format_id; });
        return candidates;
    }

    std::vector<EmbeddedSevenZipCandidate> find_embedded_seven_zip_candidates(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths)
    {
        std::vector<EmbeddedSevenZipCandidate> candidates;
        for (const auto &candidate : find_embedded_archive_candidates(archive_path, part_paths))
        {
            if (candidate.format_id == 0x07)
            {
                candidates.push_back(candidate);
            }
        }
        return candidates;
    }

} // namespace sunpack::sevenzip
