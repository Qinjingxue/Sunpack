#include "sevenzip_paths.hpp"

#ifdef _WIN32

#include <algorithm>

#include <cwctype>

#include <filesystem>

#include <unordered_set>

extern "C" __declspec(dllimport) WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR source);

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
                       { return ch < 128 ? ((ch >= L'A' && ch <= L'Z') ? ch + (L'a' - L'A') : ch)
                                         : RtlDowncaseUnicodeChar(ch); });

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
        std::vector<std::wstring> result;
        result.reserve(part_paths.size() + 1);
        std::unordered_set<std::wstring> seen;
        seen.reserve(part_paths.size() + 1);

        const auto append = [&](const std::wstring &path)
        {
            if (path.empty())
            {
                return;
            }
            if (seen.insert(lower_text(std::filesystem::path(path).wstring())).second)
            {
                result.push_back(path);
            }
        };
        for (const auto &path : part_paths)
        {
            append(path);
        }
        append(archive_path);
        return result;
    }

    std::vector<std::wstring> sorted_data_volume_paths(const std::vector<std::wstring> &paths)
    {

        struct Volume
        {
            const std::wstring *path;
            int number;
        };
        std::vector<Volume> ordered;
        ordered.reserve(paths.size());

        for (const auto &path : paths)
        {

            const auto volume_number = parse_volume_number(path);

            if (volume_number.has_value())
            {

                ordered.push_back(Volume{&path, *volume_number});
            }
        }

        std::sort(ordered.begin(), ordered.end(), [](const Volume &left, const Volume &right)
                  {
                      if (left.number != right.number)
                      {
                          return left.number < right.number;
                      }
                      return lower_text(*left.path) < lower_text(*right.path);
                  });
        std::vector<std::wstring> volumes;
        volumes.reserve(ordered.size());
        for (const auto &volume : ordered)
        {
            volumes.push_back(*volume.path);
        }
        return volumes;
    }

    std::wstring lower_extension(const std::wstring &path)
    {

        return lower_text(std::filesystem::path(path).extension().wstring());
    }


#endif

} // namespace sunpack::sevenzip
