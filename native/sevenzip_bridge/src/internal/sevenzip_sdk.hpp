#pragma once

#include "archive_operations.hpp"

#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include <objbase.h>

#include <oleauto.h>

#include <windows.h>

#endif

#include <cstdint>

#include <string>

namespace sunpack::sevenzip
{

#ifdef _WIN32

    using UInt16 = std::uint16_t;

    using Int64 = std::int64_t;

    inline constexpr Int32 kAllItems = -1;

    inline constexpr Int32 kTestMode = 1;

    inline constexpr Int32 kExtractMode = 0;

    inline constexpr Int32 kOpOk = 0;

    inline constexpr Int32 kOpUnsupportedMethod = 1;

    inline constexpr Int32 kOpDataError = 2;

    inline constexpr Int32 kOpCrcError = 3;

    inline constexpr Int32 kOpUnavailable = 4;

    inline constexpr Int32 kOpUnexpectedEnd = 5;

    inline constexpr Int32 kOpDataAfterEnd = 6;

    inline constexpr Int32 kOpIsNotArc = 7;

    inline constexpr Int32 kOpHeadersError = 8;

    inline constexpr Int32 kOpWrongPassword = 9;

    inline constexpr UInt32 kpidPath = 3;

    inline constexpr UInt32 kpidName = 4;

    inline constexpr UInt32 kpidIsDir = 6;

    inline constexpr UInt32 kpidSize = 7;

    inline constexpr UInt32 kpidPackSize = 8;

    inline constexpr UInt32 kpidSolid = 13;

    inline constexpr UInt32 kpidEncrypted = 15;

    inline constexpr UInt32 kpidDictionarySize = 18;

    inline constexpr UInt32 kpidCRC = 19;

    inline constexpr UInt32 kpidMethod = 22;

    extern const GUID IID_ISequentialInStream;

    extern const GUID IID_ISequentialOutStream;

    extern const GUID IID_IInStream;

    extern const GUID IID_IProgress;

    extern const GUID IID_ICryptoGetTextPassword;

    extern const GUID IID_IArchiveOpenCallback;

    extern const GUID IID_IArchiveExtractCallback;

    extern const GUID IID_IArchiveOpenVolumeCallback;

    extern const GUID IID_IInArchive;

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

    using CreateObjectFunc = HRESULT(WINAPI *)(const GUID *clsid, const GUID *iid, void **outObject);

    class ComModule
    {

    public:
        explicit ComModule(const std::wstring &path) : module_(LoadLibraryW(path.c_str())) {}

        ~ComModule()
        {

            if (module_)
            {

                FreeLibrary(module_);
            }
        }

        HMODULE get() const { return module_; }

        CreateObjectFunc create_object() const
        {

            if (!module_)
            {

                return nullptr;
            }

            return reinterpret_cast<CreateObjectFunc>(GetProcAddress(module_, "CreateObject"));
        }

    private:
        HMODULE module_ = nullptr;
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

    CreateObjectFunc cached_create_object(const std::wstring &seven_zip_dll_path);

#endif

} // namespace sunpack::sevenzip
