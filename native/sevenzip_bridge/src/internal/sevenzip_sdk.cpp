#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <memory>

#include <mutex>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {

        struct CreateObjectCache
        {
            std::mutex mutex;
            std::wstring path;
            std::unique_ptr<ComModule> module;
        };

        CreateObjectCache &create_object_cache()
        {
            static CreateObjectCache cache;
            return cache;
        }

    } // namespace

    const GUID IID_ISequentialInStream = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00}};

    const GUID IID_ISequentialOutStream = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00}};

    const GUID IID_IInStream = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00}};

    const GUID IID_IProgress = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00}};

    const GUID IID_ICryptoGetTextPassword = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00}};

    const GUID IID_IArchiveOpenCallback = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x10, 0x00, 0x00}};

    const GUID IID_IArchiveExtractCallback = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00}};

    const GUID IID_IArchiveOpenVolumeCallback = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x30, 0x00, 0x00}};

    const GUID IID_IInArchive = {

        0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x00, 0x00}};

    GUID format_guid(unsigned char format_id)
    {

        return {0x23170F69, 0x40C1, 0x278A, {0x10, 0x00, 0x00, 0x01, 0x10, format_id, 0x00, 0x00}};
    }

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

    CreateObjectFunc cached_create_object(const std::wstring &seven_zip_dll_path)
    {

        auto &cache = create_object_cache();
        std::lock_guard<std::mutex> lock(cache.mutex);

        if (!cache.module || cache.path != seven_zip_dll_path)
        {

            cache.module = std::make_unique<ComModule>(seven_zip_dll_path);

            cache.path = seven_zip_dll_path;
        }

        return cache.module ? cache.module->create_object() : nullptr;
    }

    void release_cached_create_object() noexcept
    {
        auto &cache = create_object_cache();
        std::lock_guard<std::mutex> lock(cache.mutex);
        cache.module.reset();
        cache.path.clear();
    }

#endif

} // namespace sunpack::sevenzip
