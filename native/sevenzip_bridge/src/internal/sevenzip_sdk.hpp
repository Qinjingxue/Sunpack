#pragma once

#include "archive_operations.hpp"

#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include <objbase.h>

#include <oleauto.h>

#include <windows.h>

// The bridge is now a source-level consumer of the bundled 7-Zip rather than a
// 7z.dll client, so it uses upstream's declarations instead of a hand-copied
// ABI mirror. These must come after the Windows COM headers above: the SunPack
// targets build with WIN32_LEAN_AND_MEAN, which leaves <Windows.h> without the
// COM/ole types 7-Zip's headers rely on.
#include "7zip/Archive/IArchive.h"
#include "7zip/IPassword.h"
#include "7zip/IProgress.h"
#include "7zip/IStream.h"
#include "7zip/PropID.h"

#endif

#include <cstdint>

#include <string>

namespace sunpack::sevenzip
{

#ifdef _WIN32

    // The declared signature is the same one the external 7z.dll exposed, and
    // the bridge keeps its own mirror of the archive interfaces so that the
    // implementation files stay unchanged. What matters for correctness is the
    // IIDs, property ids and operation-result codes below: those now come from
    // upstream, so they can no longer drift from the handler implementation.
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

    struct ISequentialInStream : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) = 0;
    };

    struct IInStream : public ISequentialInStream
    {

        virtual HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) = 0;
    };

    struct IProgress : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *completeValue) = 0;
    };

    struct IArchiveOpenCallback : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE SetTotal(const UInt64 *files, const UInt64 *bytes) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *files, const UInt64 *bytes) = 0;
    };

    struct IArchiveOpenVolumeCallback : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 propID, PROPVARIANT *value) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetStream(const wchar_t *name, IInStream **inStream) = 0;
    };

    struct ISequentialOutStream : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE Write(const void *data, UInt32 size, UInt32 *processedSize) = 0;
    };

    struct IArchiveExtractCallback : public IProgress
    {

        virtual HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream **outStream, Int32 askExtractMode) = 0;

        virtual HRESULT STDMETHODCALLTYPE PrepareOperation(Int32 askExtractMode) = 0;

        virtual HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) = 0;
    };

    struct ICryptoGetTextPassword : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR *password) = 0;
    };

    struct IInArchive : public IUnknown
    {

        virtual HRESULT STDMETHODCALLTYPE Open(IInStream *stream, const UInt64 *maxCheckStartPosition, IArchiveOpenCallback *openCallback) = 0;

        virtual HRESULT STDMETHODCALLTYPE Close() = 0;

        virtual HRESULT STDMETHODCALLTYPE GetNumberOfItems(UInt32 *numItems) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 index, UInt32 propID, PROPVARIANT *value) = 0;

        virtual HRESULT STDMETHODCALLTYPE Extract(const UInt32 *indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback *extractCallback) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetArchiveProperty(UInt32 propID, PROPVARIANT *value) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetNumberOfProperties(UInt32 *numProps) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetPropertyInfo(UInt32 index, BSTR *name, UInt32 *propID, VARTYPE *varType) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetNumberOfArchiveProperties(UInt32 *numProps) = 0;

        virtual HRESULT STDMETHODCALLTYPE GetArchivePropertyInfo(UInt32 index, BSTR *name, UInt32 *propID, VARTYPE *varType) = 0;
    };

    template <typename T>

    class ComPtr
    {

    public:
        ComPtr() = default;

        explicit ComPtr(T *ptr) : ptr_(ptr) {}

        ~ComPtr() { reset(); }

        ComPtr(const ComPtr &) = delete;

        ComPtr &operator=(const ComPtr &) = delete;

        T *get() const { return ptr_; }

        T **out()
        {

            reset();

            return &ptr_;
        }

        T *operator->() const { return ptr_; }

        explicit operator bool() const { return ptr_ != nullptr; }

        void reset()
        {

            if (ptr_)
            {

                ptr_->Release();

                ptr_ = nullptr;
            }
        }

    private:
        T *ptr_ = nullptr;
    };

    // Upstream's archive factory, taken straight from the bundled sources
    // (CPP/7zip/Archive/ArchiveExports.cpp). SunPack only ever creates
    // IInArchive, so the old CreateObject() DLL entry point — which also
    // dispatched coder and hasher requests — is not needed.
    HRESULT create_in_archive(const GUID &format, IInArchive **archive);

#endif

} // namespace sunpack::sevenzip
