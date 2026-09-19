#pragma once


#define SUP7Z_NOEXCEPT noexcept

#define Z7_COM_USE_ATOMIC

#include "archive_operations.hpp"

#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include <objbase.h>

#include <oleauto.h>

#include <windows.h>

#include "7zip/Archive/IArchive.h"
#include "7zip/IPassword.h"
#include "7zip/IProgress.h"
#include "7zip/IStream.h"
#include "7zip/PropID.h"


#include "Common/MyCom.h"

#endif

#include <cstdint>

#include <string>

namespace sunpack::sevenzip
{

#ifdef _WIN32

    using ::IID_IArchiveExtractCallback;
    using ::IID_IArchiveOpenCallback;
    using ::IID_IArchiveOpenVolumeCallback;
    using ::IID_ICryptoGetTextPassword;
    using ::IID_IInArchive;
    using ::IID_IInStream;
    using ::IID_IProgress;
    using ::IID_ISequentialInStream;
    using ::IID_ISequentialOutStream;

    using UInt16 = std::uint16_t;

    using Int64 = std::int64_t;

    using ::kpidCRC;
    using ::kpidDictionarySize;
    using ::kpidEncrypted;
    using ::kpidIsDir;
    using ::kpidMethod;
    using ::kpidName;
    using ::kpidPackSize;
    using ::kpidPath;
    using ::kpidSize;
    using ::kpidSolid;

    inline constexpr Int32 kAllItems = -1;

    // Ask modes and operation results are upstream enums; the bridge keeps the
    // short spellings so the extraction logic reads the same way it always did.
    inline constexpr Int32 kExtractMode = NArchive::NExtract::NAskMode::kExtract;

    inline constexpr Int32 kTestMode = NArchive::NExtract::NAskMode::kTest;

    inline constexpr Int32 kOpOk = NArchive::NExtract::NOperationResult::kOK;

    inline constexpr Int32 kOpUnsupportedMethod = NArchive::NExtract::NOperationResult::kUnsupportedMethod;

    inline constexpr Int32 kOpDataError = NArchive::NExtract::NOperationResult::kDataError;

    inline constexpr Int32 kOpCrcError = NArchive::NExtract::NOperationResult::kCRCError;

    inline constexpr Int32 kOpUnavailable = NArchive::NExtract::NOperationResult::kUnavailable;

    inline constexpr Int32 kOpUnexpectedEnd = NArchive::NExtract::NOperationResult::kUnexpectedEnd;

    inline constexpr Int32 kOpDataAfterEnd = NArchive::NExtract::NOperationResult::kDataAfterEnd;

    inline constexpr Int32 kOpIsNotArc = NArchive::NExtract::NOperationResult::kIsNotArc;

    inline constexpr Int32 kOpHeadersError = NArchive::NExtract::NOperationResult::kHeadersError;

    inline constexpr Int32 kOpWrongPassword = NArchive::NExtract::NOperationResult::kWrongPassword;

    GUID format_guid(unsigned char format_id);

    std::wstring win32_extended_path(const std::wstring &path);

    using ::IArchiveExtractCallback;
    using ::IArchiveOpenCallback;
    using ::IArchiveOpenVolumeCallback;
    using ::ICryptoGetTextPassword;
    using ::IInArchive;
    using ::IInStream;
    using ::IProgress;
    using ::ISequentialInStream;
    using ::ISequentialOutStream;


    HRESULT create_in_archive(const GUID &format, IInArchive **archive);

#endif

} // namespace sunpack::sevenzip
