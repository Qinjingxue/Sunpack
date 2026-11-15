#include "sevenzip_sdk.hpp"

#ifdef _WIN32

// Upstream's archive factory, provided by the bundled sources
// (CPP/7zip/Archive/ArchiveExports.cpp) linked into the same image.
//
// The DLL export layer (DllExports2.cpp) and its codec factory
// (Compress/CodecExports.cpp) have been trimmed: SunPack only ever creates
// IInArchive, and CreateObject() additionally dispatched coder/hasher requests
// that were never made here. GUID ownership moved to sevenzip_guid_defs.cpp.
STDAPI CreateArchiver(const GUID *clsid, const GUID *iid, void **outObject);

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    // The IID definitions that used to live here — a hand-copied mirror of
    // 7-Zip's interface identities — are gone. They now come from upstream
    // (CPP/7zip/Guid.txt via the interface headers), so they cannot drift from
    // the handler implementation they are matched against.

    GUID format_guid(unsigned char format_id)
    {

        return {0x23170F69, 0x40C1, 0x278A, {0x10, 0x00, 0x00, 0x01, 0x10, format_id, 0x00, 0x00}};
    }

    HRESULT create_in_archive(const GUID &format, IInArchive **archive)
    {

        if (!archive)
        {

            return E_POINTER;
        }

        *archive = nullptr;

        // CreateArchiver is upstream's real entry point; the old CreateObject()
        // wrapper additionally dispatched coder and hasher requests that SunPack
        // never made.
        return ::CreateArchiver(&format, &IID_IInArchive, reinterpret_cast<void **>(archive));
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

#endif

} // namespace sunpack::sevenzip
