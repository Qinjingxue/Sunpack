#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    CMyComPtr<IInStream> open_archive_stream(

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        bool &opened,

        ExtractInputTrace *trace,

        bool structured_order,

        InputPrefetchConfig prefetch_config,
        const std::vector<ExtractInputRange> &input_ranges)
    {
        const auto opened_stream = [&](auto *stream) {
            opened = stream->is_open();
            return CMyComPtr<IInStream>(stream);
        };
        if (!input_ranges.empty())
        {
            return opened_stream(new MultiRangeInStream(input_ranges, trace, prefetch_config));
        }
        const bool sfx = is_sfx_path(archive_path);
        if (part_paths.empty() || (part_paths.size() == 1 && part_paths.front() == archive_path))
        {
            const bool sfx_volume = sfx && (structured_order || parse_volume_number(archive_path).has_value());
            return opened_stream(new FileInStream(archive_path, trace, sfx_volume ? L"sfx_file" : L"file", prefetch_config));
        }
        std::vector<std::wstring> paths = unique_existing_paths(archive_path, part_paths);
        if (!structured_order)
        {
            paths = sorted_data_volume_paths(paths);
        }
        if (sfx && !paths.empty() && is_sfx_path(paths.front()))
        {
            return opened_stream(new FileInStream(paths.front(), trace, L"sfx_file", prefetch_config));
        }
        if (paths.size() > 1)
        {
            return opened_stream(new MultiRangeInStream(std::move(paths), trace, prefetch_config));
        }
        const auto &single_path = sfx && !paths.empty() ? paths.front() : archive_path;
        return opened_stream(new FileInStream(single_path, trace, L"file", prefetch_config));
    }

    std::wstring callback_archive_path(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {

        if (!part_paths.empty() && !(part_paths.size() == 1 && part_paths.front() == archive_path) &&
            is_sfx_path(archive_path))
        {

            const auto volumes = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));

            if (!volumes.empty() && is_sfx_path(volumes.front()))
            {

                return volumes.front();
            }
        }

        return archive_path;
    }

#endif

} // namespace sunpack::sevenzip
