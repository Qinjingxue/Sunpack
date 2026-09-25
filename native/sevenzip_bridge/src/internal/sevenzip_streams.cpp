#include "sevenzip_streams.hpp"
#include "decoder_input_access.h"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    CMyComPtr<IInStream> open_archive_stream(

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

                CMyComPtr<IInStream> owner(stream);

                return owner;
            }

            if (volumes.size() > 1)
            {

                auto *stream = new MultiFileInStream(std::move(volumes), trace, prefetch_config);

                opened = stream->is_open();

                CMyComPtr<IInStream> owner(stream);

                return owner;
            }

            if (volumes.size() == 1)
            {

                auto *stream = new FileInStream(volumes.front(), trace, L"file", prefetch_config);

                opened = stream->is_open();

                CMyComPtr<IInStream> owner(stream);

                return owner;
            }

            auto *stream = new FileInStream(archive_path, trace, L"file", prefetch_config);

            opened = stream->is_open();

            CMyComPtr<IInStream> owner(stream);

            return owner;
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

            CMyComPtr<IInStream> owner(stream);

            return owner;
        }

        auto *stream = new FileInStream(archive_path, trace, L"file", prefetch_config);

        opened = stream->is_open();

        CMyComPtr<IInStream> owner(stream);

        return owner;
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

extern "C"
{

int sunpack_input_random_access_size(
    void *stream,
    unsigned long long *size)
{
#ifdef _WIN32
    if (!stream || !size)
        return 0;

    auto *sequential = static_cast<ISequentialInStream *>(stream);
    auto *source =
        dynamic_cast<sunpack::sevenzip::RandomAccessInStreamSource *>(sequential);
    if (!source)
        return 0;

    *size = static_cast<unsigned long long>(source->random_access_size());
    return 1;
#else
    (void)stream;
    (void)size;
    return 0;
#endif
}

long sunpack_input_read_at(
    void *stream,
    unsigned long long offset,
    void *data,
    unsigned long size,
    unsigned long *processed)
{
#ifdef _WIN32
    if (processed)
        *processed = 0;
    if (!stream)
        return E_INVALIDARG;

    auto *sequential = static_cast<ISequentialInStream *>(stream);
    auto *source =
        dynamic_cast<sunpack::sevenzip::RandomAccessInStreamSource *>(sequential);
    if (!source)
        return E_NOINTERFACE;

    UInt32 read = 0;
    const HRESULT result = source->random_read_at(
        static_cast<UInt64>(offset),
        data,
        static_cast<UInt32>(size),
        &read);
    if (processed)
        *processed = static_cast<unsigned long>(read);
    return result;
#else
    (void)stream;
    (void)offset;
    (void)data;
    (void)size;
    (void)processed;
    return -1;
#endif
}

} // extern "C"
