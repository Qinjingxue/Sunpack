#pragma once

#include "../../7z2603-src/CPP/7zip/IStream.h"

#include <memory>

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

class RandomAccessInStream
{
public:
    virtual ~RandomAccessInStream() = default;
    virtual std::unique_ptr<RandomAccessReader> open_random_reader() noexcept = 0;
};

inline RandomAccessInStream *random_access_in_stream(IInStream *stream) noexcept
{
    return dynamic_cast<RandomAccessInStream *>(stream);
}

class PositionedOutStream
{
public:
    virtual ~PositionedOutStream() = default;

    virtual bool positioned_available() const noexcept = 0;

    virtual HRESULT write_at(
        UInt64 offset,
        const void *data,
        UInt32 size,
        UInt32 *processed_size) noexcept = 0;
};

class PositionedExtractCallback
{
public:
    virtual ~PositionedExtractCallback() = default;

    virtual bool positioned_extract_available() const noexcept = 0;

    virtual HRESULT get_positioned_stream(
        UInt32 index,
        ISequentialOutStream **stream,
        Int32 ask_mode) noexcept = 0;

    virtual HRESULT set_positioned_operation_result(
        UInt32 index,
        Int32 operation_result) noexcept = 0;
};

inline PositionedOutStream *positioned_out_stream(ISequentialOutStream *stream) noexcept
{
    return dynamic_cast<PositionedOutStream *>(stream);
}

} // namespace sunpack::sevenzip
