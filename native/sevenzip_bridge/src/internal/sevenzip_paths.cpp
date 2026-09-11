#include "sevenzip_paths.hpp"

#ifdef _WIN32

#include <algorithm>

#include <cwctype>

#include <filesystem>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {

        bool is_zip_numbered_volume_name(const std::wstring &name)
        {
            constexpr std::size_t suffix_length = 4;
            constexpr std::size_t marker_length = 5; // ".zip."
            if (name.size() < marker_length + suffix_length ||
                name.compare(name.size() - marker_length - suffix_length, marker_length, L".zip.") != 0)
            {
                return false;
            }
            for (std::size_t index = name.size() - suffix_length; index < name.size(); ++index)
            {
                if (!iswdigit(name[index]))
                {
                    return false;
                }
            }
            return true;
        }

        int zip_numbered_volume(const std::wstring &name)
        {
            int number = 0;
            for (std::size_t index = name.size() - 4; index < name.size(); ++index)
            {
                number = number * 10 + (name[index] - L'0');
            }
            return number;
        }

    } // namespace

    std::wstring lower_text(std::wstring value)
    {

        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
                       { return static_cast<wchar_t>(::towlower(ch)); });

        return value;
    }

    std::wstring filename_lower(const std::wstring &path)
    {

        return lower_text(std::filesystem::path(path).filename().wstring());
    }

    bool ends_with(const std::wstring &value, const std::wstring &suffix)
    {

        return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    bool is_sfx_path(const std::wstring &path)
    {

        std::wstring ext = std::filesystem::path(path).extension().wstring();

        ext = lower_text(std::move(ext));

        return ext == L".exe" || ext == L".dll";
    }

    std::optional<int> parse_volume_number(const std::wstring &path)
    {

        const std::wstring name = filename_lower(path);

        if (is_zip_numbered_volume_name(name))
        {
            return zip_numbered_volume(name);
        }

        if (name.size() >= 4 && name[name.size() - 4] == L'.')
        {

            const wchar_t a = name[name.size() - 3];

            const wchar_t b = name[name.size() - 2];

            const wchar_t c = name[name.size() - 1];

            if (iswdigit(a) && iswdigit(b) && iswdigit(c))
            {

                return ((a - L'0') * 100) + ((b - L'0') * 10) + (c - L'0');
            }
        }

        const std::wstring marker = L".part";

        const std::size_t part_pos = name.rfind(marker);

        if (part_pos != std::wstring::npos && (ends_with(name, L".rar") || ends_with(name, L".exe")))
        {

            const std::size_t start = part_pos + marker.size();

            const std::size_t end = name.size() - 4;

            if (start < end)
            {

                int number = 0;

                for (std::size_t index = start; index < end; ++index)
                {

                    if (!iswdigit(name[index]))
                    {

                        return std::nullopt;
                    }

                    number = (number * 10) + (name[index] - L'0');
                }

                return number;
            }
        }

        if (name.size() >= 4 && name[name.size() - 4] == L'.' && name[name.size() - 3] == L'r')
        {

            const wchar_t a = name[name.size() - 2];

            const wchar_t b = name[name.size() - 1];

            if (iswdigit(a) && iswdigit(b))
            {

                return ((a - L'0') * 10) + (b - L'0') + 2;
            }
        }

        if (name.size() >= 4 && name[name.size() - 4] == L'.' && name[name.size() - 3] == L'z')
        {
            const wchar_t a = name[name.size() - 2];
            const wchar_t b = name[name.size() - 1];
            if (iswdigit(a) && iswdigit(b))
            {
                return ((a - L'0') * 10) + (b - L'0');
            }
        }

        if (ends_with(name, L".rar"))
        {

            return 1;
        }

        return std::nullopt;
    }

    std::vector<std::wstring> unique_existing_paths(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
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

    std::vector<std::wstring> sorted_data_volume_paths(const std::vector<std::wstring> &paths)
    {

        std::vector<std::wstring> volumes;

        for (const auto &path : paths)
        {

            const auto volume_number = parse_volume_number(path);

            if (volume_number.has_value())
            {

                volumes.push_back(path);
            }
        }

        std::sort(volumes.begin(), volumes.end(), [](const std::wstring &left, const std::wstring &right)
                  {
                      const int left_number = parse_volume_number(left).value_or(0);

                      const int right_number = parse_volume_number(right).value_or(0);

                      if (left_number != right_number)
                      {

                          return left_number < right_number;
                      }

                      return lower_text(left) < lower_text(right);
                  });

        return volumes;
    }

    std::wstring lower_extension(const std::wstring &path)
    {

        std::wstring ext = std::filesystem::path(path).extension().wstring();

        std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch)
                       { return static_cast<wchar_t>(::towlower(ch)); });

        return ext;
    }

    bool looks_missing_volume(const std::wstring &archive_path, Int32 op_res)
    {

        if (op_res != kOpUnexpectedEnd && op_res != kOpUnavailable && op_res != kOpHeadersError)
        {

            return false;
        }

        const std::wstring lower = filename_lower(archive_path);

        return lower.find(L".001") != std::wstring::npos ||

               is_zip_numbered_volume_name(lower) ||

               lower.find(L".part") != std::wstring::npos ||

               (lower.size() >= 4 && lower[lower.size() - 4] == L'.' && lower[lower.size() - 3] == L'z' &&
                iswdigit(lower[lower.size() - 2]) && iswdigit(lower[lower.size() - 1])) ||

               lower.find(L".r00") != std::wstring::npos ||

               lower.find(L".r01") != std::wstring::npos;
    }

    UInt64 file_size_or_zero(const std::wstring &path);

    bool has_numbered_split_head(const std::vector<std::wstring> &part_paths)
    {

        for (const auto &path : sorted_data_volume_paths(part_paths))
        {

            std::wstring name = filename_lower(path);

            if (name.size() >= 4 && name.compare(name.size() - 4, 4, L".001") == 0)
            {

                return true;
            }

            if (is_zip_numbered_volume_name(name) && zip_numbered_volume(name) == 0)
            {

                return true;
            }

            if (name.find(L".part") != std::wstring::npos && parse_volume_number(path).value_or(0) == 1)
            {

                return true;
            }

            if (name.size() >= 4 && name.compare(name.size() - 4, 4, L".z01") == 0)
            {
                return true;
            }
        }

        return false;
    }

    bool has_split_volume_evidence(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {

        const auto volumes = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));

        if (volumes.size() > 1)
        {

            return true;
        }

        return looks_missing_volume(archive_path, kOpHeadersError);
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

    UInt64 archive_input_size(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {

        const auto paths = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;

        UInt64 total = 0;

        for (const auto &path : paths)
        {

            total += file_size_or_zero(path);
        }

        return total;
    }

#endif

} // namespace sunpack::sevenzip
