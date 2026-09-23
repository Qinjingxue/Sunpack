#pragma once

#include "../../7z2603-src/CPP/7zip/IStream.h"

namespace sunpack::sevenzip
{

class PositionedOutStream
{
public:
    virtual ~PositionedOutStream() = default;

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
