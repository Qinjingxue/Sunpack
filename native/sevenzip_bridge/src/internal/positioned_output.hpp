#pragma once

#include "../../../7z2603-src/CPP/7zip/IStream.h"

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

inline PositionedOutStream *positioned_out_stream(ISequentialOutStream *stream) noexcept
{
    return dynamic_cast<PositionedOutStream *>(stream);
}

} // namespace sunpack::sevenzip
