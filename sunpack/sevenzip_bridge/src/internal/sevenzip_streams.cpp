#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    OpenedArchiveStream open_archive_stream(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths,
        ExtractInputTrace *trace,
        const std::vector<std::wstring> &canonical_names,
        InputPrefetchConfig prefetch_config,
        const std::vector<ExtractInputRange> &input_ranges, VolumeReadUncertainty* probe_reads)
    {
        const bool multipart = !part_paths.empty() && !(part_paths.size() == 1 && part_paths.front() == archive_path);
        const bool structured_order = !canonical_names.empty();
        const bool use_ranges = !input_ranges.empty();
        const bool sfx = multipart && (!use_ranges || !structured_order) && is_sfx_path(archive_path);
        std::vector<std::wstring> paths;
        if (multipart && (!use_ranges || sfx))
        {
            paths = unique_existing_paths(archive_path, part_paths);
            if (!structured_order) paths = sorted_data_volume_paths(paths);
        }
        const bool sfx_first = sfx && !paths.empty() && is_sfx_path(paths.front());
        // Reuse the selected fallback head for the callback name.
        // Structured callback names still come from the Rust input plan.
        const auto &callback_path = structured_order ? canonical_names.front() : sfx_first ? paths.front() : archive_path;
        const auto opened_stream = [&](auto *stream) {
            const bool opened = stream->is_open();
            return OpenedArchiveStream{CMyComPtr<IInStream>(stream), opened ? callback_path : std::wstring{}, opened};
        };
        if (use_ranges)
        {
            return opened_stream(new MultiRangeInStream(input_ranges, trace, prefetch_config, false, probe_reads));
        }
        if (sfx_first)
        {
            return opened_stream(new FileInStream(paths.front(), trace, prefetch_config));
        }
        if (paths.size() > 1)
        {
            return opened_stream(new MultiRangeInStream(std::move(paths), trace, prefetch_config));
        }
        const auto &single_path = sfx && !paths.empty() ? paths.front() : archive_path;
        return opened_stream(new FileInStream(single_path, trace, prefetch_config));
    }

#endif

} // namespace sunpack::sevenzip
