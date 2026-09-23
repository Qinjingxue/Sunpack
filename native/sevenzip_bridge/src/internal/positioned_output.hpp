#pragma once

#include "../../7z2603-src/CPP/7zip/IStream.h"

#include <memory>

/*
  Internal SunPack capabilities are COM-queryable instead of relying on C++ RTTI.
  The GUIDs live outside the upstream 7-Zip interface number space.
*/
Z7_DEFINE_GUID(IID_ISunpackRandomAccessInStream,
    0x8A1D8E91, 0xD5D8, 0x4C42, 0xA5, 0x78, 0x9B, 0x03, 0xDA, 0xF1, 0x80, 0x21);
Z7_DEFINE_GUID(IID_ISunpackPositionedOutStream,
    0xD9A9F0E4, 0xA3B6, 0x45FC, 0x9B, 0x75, 0x68, 0x18, 0x76, 0x9F, 0xE1, 0x12);
Z7_DEFINE_GUID(IID_ISunpackPositionedExtractCallback,
    0x7E7D8D0B, 0xBE2C, 0x41EF, 0x87, 0x2F, 0x5C, 0x40, 0x7F, 0xB4, 0x14, 0x73);

namespace sunpack::sevenzip
{

class RandomAccessReader
{
public:
    virtual ~RandomAccessReader() = default;
    virtual HRESULT read_at(
        UInt64 offset,
        void *data,
        UInt32 size,
        UInt32 *processed_size) noexcept = 0;
};

} // namespace sunpack::sevenzip

class ISunpackRandomAccessInStream : public IUnknown
{
public:
    virtual std::unique_ptr<sunpack::sevenzip::RandomAccessReader>
    open_random_reader() noexcept = 0;
};

class ISunpackPositionedOutStream : public IUnknown
{
public:
    virtual bool positioned_available() const noexcept = 0;

    virtual HRESULT write_at(
        UInt64 offset,
        const void *data,
        UInt32 size,
        UInt32 *processed_size) noexcept = 0;
};

class ISunpackPositionedExtractCallback : public IUnknown
{
public:
    virtual bool positioned_extract_available() const noexcept = 0;

    virtual HRESULT get_positioned_stream(
        UInt32 index,
        ISequentialOutStream **stream,
        Int32 ask_mode) noexcept = 0;

    virtual HRESULT set_positioned_operation_result(
        UInt32 index,
        Int32 operation_result) noexcept = 0;
};

namespace sunpack::sevenzip
{

using RandomAccessInStream = ISunpackRandomAccessInStream;
using PositionedOutStream = ISunpackPositionedOutStream;
using PositionedExtractCallback = ISunpackPositionedExtractCallback;

template <class T>
inline T *query_capability(IUnknown *object, REFGUID iid) noexcept
{
    if (!object)
        return nullptr;

    T *capability = nullptr;
    if (object->QueryInterface(iid, reinterpret_cast<void **>(&capability)) != S_OK ||
        !capability)
        return nullptr;

    /*
      The caller already owns another COM interface on the same object for the
      lifetime of the returned raw capability pointer. Drop the temporary QI
      reference immediately so capability discovery doesn't alter ownership.
    */
    capability->Release();
    return capability;
}

inline RandomAccessInStream *random_access_in_stream(IInStream *stream) noexcept
{
    return query_capability<RandomAccessInStream>(
        stream, IID_ISunpackRandomAccessInStream);
}

inline RandomAccessInStream *random_access_in_stream(
    ISequentialInStream *stream) noexcept
{
    return query_capability<RandomAccessInStream>(
        stream, IID_ISunpackRandomAccessInStream);
}

inline PositionedOutStream *positioned_out_stream(
    ISequentialOutStream *stream) noexcept
{
    return query_capability<PositionedOutStream>(
        stream, IID_ISunpackPositionedOutStream);
}

inline PositionedExtractCallback *positioned_extract_callback(
    IUnknown *callback) noexcept
{
    return query_capability<PositionedExtractCallback>(
        callback, IID_ISunpackPositionedExtractCallback);
}

} // namespace sunpack::sevenzip
