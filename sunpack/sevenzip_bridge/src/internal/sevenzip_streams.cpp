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
        const std::vector<ExtractInputRange> &input_ranges, VolumeReadUncertainty* probe_reads, ArchiveOpenMode mode)
    {
        const auto &callback_path = canonical_names.empty() ? archive_path : canonical_names.front();
        const auto opened_stream = [&](auto *stream) {
            const bool opened = stream->is_open();
            return OpenedArchiveStream{CMyComPtr<IInStream>(stream), opened ? callback_path : std::wstring{}, opened};
        };
        if (!input_ranges.empty())
        {
            return opened_stream(new MultiRangeInStream(input_ranges, trace, prefetch_config, probe_reads, mode));
        }
        // Ordinal byte splits share one stream. A named-volume handler opens
        // each following volume through its callback.
        if (mode == ArchiveOpenMode::NativeVolumes && part_paths.size() > 1)
        {
            return opened_stream(new MultiRangeInStream(part_paths, trace, prefetch_config));
        }
        const auto &single_path = part_paths.empty() ? archive_path : part_paths.front();
        return opened_stream(new FileInStream(single_path, trace, prefetch_config));
    }

#endif

} // namespace sunpack::sevenzip
