#include "zlib_ng_deflate_decoder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

#include <zlib-ng.h>

#include "Common/MyCom.h"
#include "7zip/Common/StreamUtils.h"

namespace {

constexpr std::size_t kBufferSize = 512u * 1024u;

HRESULT MapZlibNgError(int code)
{
    if (code == Z_MEM_ERROR)
        return E_OUTOFMEMORY;
    if (code == Z_DATA_ERROR || code == Z_NEED_DICT || code == Z_BUF_ERROR)
        return S_FALSE;
    return E_FAIL;
}

class CZlibNgDeflateDecoder final:
    public ICompressCoder,
    public ICompressSetFinishMode,
    public ICompressGetInStreamProcessedSize,
    public ICompressReadUnusedFromInBuf,
    public CMyUnknownImp
{
    Z7_COM_QI_BEGIN2(ICompressCoder)
    Z7_COM_QI_ENTRY(ICompressSetFinishMode)
    Z7_COM_QI_ENTRY(ICompressGetInStreamProcessedSize)
    Z7_COM_QI_ENTRY(ICompressReadUnusedFromInBuf)
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE

    Z7_IFACE_COM7_IMP(ICompressCoder)
    Z7_IFACE_COM7_IMP(ICompressSetFinishMode)
    Z7_IFACE_COM7_IMP(ICompressGetInStreamProcessedSize)
    Z7_IFACE_COM7_IMP(ICompressReadUnusedFromInBuf)

    zng_stream _stream{};
    std::vector<Byte> _input;
    std::vector<Byte> _output;
    UInt64 _processed = 0;
    std::size_t _unusedOffset = 0;
    std::size_t _unusedSize = 0;
    bool _initialized = false;
    bool _finishMode = false;

public:
    CZlibNgDeflateDecoder():
        _input(kBufferSize),
        _output(kBufferSize)
    {
    }

    ~CZlibNgDeflateDecoder()
    {
        if (_initialized)
            zng_inflateEnd(&_stream);
    }

private:
    HRESULT Reset()
    {
        _processed = 0;
        _unusedOffset = 0;
        _unusedSize = 0;

        int code;
        if (_initialized)
            code = zng_inflateReset2(&_stream, -15);
        else
        {
            std::memset(&_stream, 0, sizeof(_stream));
            code = zng_inflateInit2(&_stream, -15);
            if (code == Z_OK)
                _initialized = true;
        }
        if (code != Z_OK)
            return MapZlibNgError(code);

        // inflateReset2() resets decoder state and counters, but it does not
        // promise to clear the caller-owned input/output pointers.  This coder
        // is cached and reused across ZIP entries, so trailing bytes retained
        // for Strong Encryption padding validation must never become the next
        // entry's initial Deflate input.
        _stream.next_in = nullptr;
        _stream.avail_in = 0;
        _stream.next_out = nullptr;
        _stream.avail_out = 0;
        return S_OK;
    }

    void SaveUnused()
    {
        _processed = static_cast<UInt64>(_stream.total_in);
        _unusedSize = static_cast<std::size_t>(_stream.avail_in);
        _unusedOffset = 0;
        if (_unusedSize != 0 && _stream.next_in)
        {
            const auto *begin = reinterpret_cast<const Byte *>(_stream.next_in);
            const auto *base = _input.data();
            if (begin >= base && begin <= base + _input.size())
                _unusedOffset = static_cast<std::size_t>(begin - base);
            else
                _unusedSize = 0;
        }
    }
};

Z7_COM7F_IMF(CZlibNgDeflateDecoder::SetFinishMode(UInt32 finishMode))
{
    _finishMode = finishMode != 0;
    return S_OK;
}

Z7_COM7F_IMF(CZlibNgDeflateDecoder::GetInStreamProcessedSize(UInt64 *value))
{
    if (!value)
        return E_INVALIDARG;
    *value = _processed;
    return S_OK;
}

Z7_COM7F_IMF(CZlibNgDeflateDecoder::ReadUnusedFromInBuf(
    void *data, UInt32 size, UInt32 *processedSize))
{
    if (processedSize)
        *processedSize = 0;
    if (size == 0 || _unusedSize == 0)
        return S_OK;
    if (!data)
        return E_INVALIDARG;

    const std::size_t amount = std::min<std::size_t>(size, _unusedSize);
    std::memcpy(data, _input.data() + _unusedOffset, amount);
    _unusedOffset += amount;
    _unusedSize -= amount;
    if (processedSize)
        *processedSize = static_cast<UInt32>(amount);
    return S_OK;
}

Z7_COM7F_IMF(CZlibNgDeflateDecoder::Code(
    ISequentialInStream *inStream,
    ISequentialOutStream *outStream,
    const UInt64 * /* inSize */,
    const UInt64 *outSize,
    ICompressProgressInfo *progress))
{
    if (!inStream || !outStream)
        return E_INVALIDARG;

    HRESULT hres;
    try
    {
        hres = Reset();
    }
    catch (const std::bad_alloc &)
    {
        return E_OUTOFMEMORY;
    }
    if (hres != S_OK)
        return hres;

    bool inputFinished = false;
    UInt64 outputProcessed = 0;
    UInt64 lastProgressInput = 0;
    UInt64 lastProgressOutput = 0;

    for (;;)
    {
        if (_stream.avail_in == 0 && !inputFinished)
        {
            UInt32 readSize = 0;
            hres = inStream->Read(
                _input.data(),
                static_cast<UInt32>(_input.size()),
                &readSize);
            if (hres != S_OK)
            {
                SaveUnused();
                return hres;
            }

            _stream.next_in = reinterpret_cast<const uint8_t *>(_input.data());
            _stream.avail_in = readSize;
            inputFinished = readSize == 0;
        }

        bool verifyingExactEnd = false;
        std::size_t outputCapacity = _output.size();
        if (outSize)
        {
            if (outputProcessed > *outSize)
            {
                SaveUnused();
                return S_FALSE;
            }
            const UInt64 remaining = *outSize - outputProcessed;
            if (remaining == 0)
            {
                if (!_finishMode)
                {
                    SaveUnused();
                    return S_OK;
                }
                // Keep one byte of space so inflate can consume the final
                // end-of-block marker. Producing that byte means the archive's
                // declared output size was too small.
                outputCapacity = 1;
                verifyingExactEnd = true;
            }
            else if (remaining < outputCapacity)
                outputCapacity = static_cast<std::size_t>(remaining);
        }

        _stream.next_out = reinterpret_cast<uint8_t *>(_output.data());
        _stream.avail_out = static_cast<uint32_t>(outputCapacity);

        const uint32_t beforeIn = _stream.avail_in;
        const uint32_t beforeOut = _stream.avail_out;
        const int code = zng_inflate(&_stream, Z_NO_FLUSH);
        const std::size_t consumed =
            static_cast<std::size_t>(beforeIn - _stream.avail_in);
        const std::size_t produced =
            static_cast<std::size_t>(beforeOut - _stream.avail_out);

        if (verifyingExactEnd && produced != 0)
        {
            SaveUnused();
            return S_FALSE;
        }

        if (produced != 0)
        {
            hres = WriteStream(outStream, _output.data(), produced);
            if (hres != S_OK)
            {
                SaveUnused();
                return hres;
            }
            outputProcessed += static_cast<UInt64>(produced);
        }

        _processed = static_cast<UInt64>(_stream.total_in);

        if (progress &&
            ((_processed - lastProgressInput) >= (1u << 21) ||
             (outputProcessed - lastProgressOutput) >= (1u << 21)))
        {
            hres = progress->SetRatioInfo(&_processed, &outputProcessed);
            if (hres != S_OK)
            {
                SaveUnused();
                return hres;
            }
            lastProgressInput = _processed;
            lastProgressOutput = outputProcessed;
        }

        if (code == Z_STREAM_END)
        {
            SaveUnused();
            if (outSize && outputProcessed != *outSize)
                return S_FALSE;
            return S_OK;
        }

        if (code != Z_OK && code != Z_BUF_ERROR)
        {
            SaveUnused();
            return MapZlibNgError(code);
        }

        const bool madeProgress = consumed != 0 || produced != 0;
        if (!madeProgress)
        {
            if (inputFinished && _stream.avail_in == 0)
            {
                SaveUnused();
                return S_FALSE;
            }
            if (code == Z_BUF_ERROR)
            {
                SaveUnused();
                return S_FALSE;
            }
        }
    }
}

}  // namespace

ICompressCoder *SunpackCreateZlibNgDeflateDecoder()
{
    try
    {
        return new CZlibNgDeflateDecoder();
    }
    catch (const std::bad_alloc &)
    {
        return nullptr;
    }
}
