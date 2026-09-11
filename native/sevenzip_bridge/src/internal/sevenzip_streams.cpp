#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    ComPtr<IInStream> open_archive_stream(

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        bool &opened,

        ExtractInputTrace *trace,

        bool structured_order,

        InputPrefetchConfig prefetch_config

    )
    {

        opened = false;

        if (is_sfx_path(archive_path))
        {

            std::vector<std::wstring> volumes = unique_existing_paths(archive_path, part_paths);

            if (!structured_order)
            {

                volumes = sorted_data_volume_paths(volumes);
            }

            if (!volumes.empty() && is_sfx_path(volumes.front()))
            {

                auto *stream = new FileInStream(volumes.front(), trace, L"sfx_file", prefetch_config);

                opened = stream->is_open();

                return ComPtr<IInStream>(stream);
            }

            if (volumes.size() > 1)
            {

                auto *stream = new MultiFileInStream(std::move(volumes), trace, prefetch_config);

                opened = stream->is_open();

                return ComPtr<IInStream>(stream);
            }

            if (volumes.size() == 1)
            {

                auto *stream = new FileInStream(volumes.front(), trace, L"file", prefetch_config);

                opened = stream->is_open();

                return ComPtr<IInStream>(stream);
            }

            auto *stream = new FileInStream(archive_path, trace, L"file", prefetch_config);

            opened = stream->is_open();

            return ComPtr<IInStream>(stream);
        }

        std::vector<std::wstring> paths = unique_existing_paths(archive_path, part_paths);

        if (!structured_order)
        {

            paths = sorted_data_volume_paths(paths);
        }

        if (paths.empty())
        {

            paths = std::vector<std::wstring>{archive_path};
        }

        if (paths.size() > 1)
        {

            auto *stream = new MultiFileInStream(std::move(paths), trace, prefetch_config);

            opened = stream->is_open();

            return ComPtr<IInStream>(stream);
        }

        auto *stream = new FileInStream(archive_path, trace, L"file", prefetch_config);

        opened = stream->is_open();

        return ComPtr<IInStream>(stream);
    }

    std::wstring callback_archive_path(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {

        if (is_sfx_path(archive_path))
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
