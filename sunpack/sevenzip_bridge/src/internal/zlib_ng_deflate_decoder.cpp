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
#include "7zip/Compress/DeflateDecoder.h"

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


class CAdaptiveDeflateDecoder final:
    public ICompressCoder,
    public ICompressSetFinishMode,
    public ICompressGetInStreamProcessedSize,
    public ICompressReadUnusedFromInBuf,
    public ICompressSetInStream,
    public ICompressSetOutStreamSize,
#ifndef Z7_NO_READ_FROM_CODER
    public ISequentialInStream,
#endif
    public CMyUnknownImp
{
    Z7_COM_QI_BEGIN2(ICompressCoder)
    Z7_COM_QI_ENTRY(ICompressSetFinishMode)
    Z7_COM_QI_ENTRY(ICompressGetInStreamProcessedSize)
    Z7_COM_QI_ENTRY(ICompressReadUnusedFromInBuf)
    Z7_COM_QI_ENTRY(ICompressSetInStream)
    Z7_COM_QI_ENTRY(ICompressSetOutStreamSize)
#ifndef Z7_NO_READ_FROM_CODER
    Z7_COM_QI_ENTRY(ISequentialInStream)
#endif
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE

    Z7_IFACE_COM7_IMP(ICompressCoder)
    Z7_IFACE_COM7_IMP(ICompressSetFinishMode)
    Z7_IFACE_COM7_IMP(ICompressGetInStreamProcessedSize)
    Z7_IFACE_COM7_IMP(ICompressReadUnusedFromInBuf)
    Z7_IFACE_COM7_IMP(ICompressSetInStream)
    Z7_IFACE_COM7_IMP(ICompressSetOutStreamSize)
#ifndef Z7_NO_READ_FROM_CODER
    Z7_IFACE_COM7_IMP(ISequentialInStream)
#endif

    CMyComPtr2<ICompressCoder, NCompress::NDeflate::NDecoder::CCOMCoder> _sevenZip;
    CMyComPtr<ICompressCoder> _zlibNg;
    ICompressCoder *_activeCoder = nullptr;
    UInt32 _finishMode = 0;

    HRESULT EnsureSevenZip()
    {
        try
        {
            _sevenZip.Create_if_Empty();
        }
        catch (const std::bad_alloc &)
        {
            return E_OUTOFMEMORY;
        }
        return S_OK;
    }

    HRESULT EnsureZlibNg()
    {
        if (_zlibNg)
            return S_OK;
        ICompressCoder *coder = SunpackCreateZlibNgDeflateDecoder();
        if (!coder)
            return E_OUTOFMEMORY;
        _zlibNg = coder;
        return S_OK;
    }

    HRESULT ApplyFinishMode(ICompressCoder *coder)
    {
        if (!coder)
            return E_FAIL;
        CMyComPtr<ICompressSetFinishMode> finish;
        coder->QueryInterface(IID_ICompressSetFinishMode, (void **)&finish);
        return finish ? finish->SetFinishMode(_finishMode) : S_OK;
    }

    HRESULT ActivateSevenZip()
    {
        RINOK(EnsureSevenZip())
        _activeCoder = _sevenZip.Interface();
        return ApplyFinishMode(_activeCoder);
    }

    IUnknown *ActiveUnknown() const
    {
        return _activeCoder;
    }

public:
    CAdaptiveDeflateDecoder() = default;
};

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::SetFinishMode(UInt32 finishMode))
{
    _finishMode = finishMode;

    if (_sevenZip.IsDefined())
    {
        RINOK(ApplyFinishMode(_sevenZip.Interface()))
    }

    if (_zlibNg)
    {
        CMyComPtr<ICompressSetFinishMode> finish;
        _zlibNg.QueryInterface(IID_ICompressSetFinishMode, &finish);
        if (finish)
            RINOK(finish->SetFinishMode(finishMode))
    }

    return S_OK;
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::Code(
    ISequentialInStream *inStream,
    ISequentialOutStream *outStream,
    const UInt64 *inSize,
    const UInt64 *outSize,
    ICompressProgressInfo *progress))
{
    // Keep partial/resumable decoding on upstream 7-Zip. In that mode
    // outSize can describe only the requested prefix of a larger 7z coder
    // stream, so it is not a valid whole-stream compression-ratio signal.
    if (_finishMode != 0 && inSize && outSize &&
        SunpackShouldUseZlibNgDeflate(*inSize, *outSize))
    {
        HRESULT hres = EnsureZlibNg();
        if (hres == S_OK)
        {
            _activeCoder = _zlibNg;
            RINOK(ApplyFinishMode(_activeCoder))
            return _activeCoder->Code(inStream, outStream, inSize, outSize, progress);
        }

        // The routing optimization is optional. If its decoder cannot even be
        // allocated before consuming input, preserve functionality by using the
        // upstream decoder instead.
        if (hres != E_OUTOFMEMORY)
            return hres;
    }

    RINOK(ActivateSevenZip())
    return _activeCoder->Code(inStream, outStream, inSize, outSize, progress);
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::GetInStreamProcessedSize(UInt64 *value))
{
    if (!value)
        return E_INVALIDARG;
    if (!_activeCoder)
    {
        *value = (UInt64)(Int64)-1;
        return S_OK;
    }

    CMyComPtr<ICompressGetInStreamProcessedSize> processed;
    ActiveUnknown()->QueryInterface(
        IID_ICompressGetInStreamProcessedSize, (void **)&processed);
    if (!processed)
    {
        *value = (UInt64)(Int64)-1;
        return S_OK;
    }
    return processed->GetInStreamProcessedSize(value);
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::ReadUnusedFromInBuf(
    void *data, UInt32 size, UInt32 *processedSize))
{
    if (processedSize)
        *processedSize = 0;
    if (!_activeCoder)
        return S_OK;

    CMyComPtr<ICompressReadUnusedFromInBuf> unused;
    ActiveUnknown()->QueryInterface(
        IID_ICompressReadUnusedFromInBuf, (void **)&unused);
    if (!unused)
        return S_OK;
    return unused->ReadUnusedFromInBuf(data, size, processedSize);
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::SetInStream(ISequentialInStream *inStream))
{
    RINOK(ActivateSevenZip())
    CMyComPtr<ICompressSetInStream> setStream;
    _activeCoder->QueryInterface(IID_ICompressSetInStream, (void **)&setStream);
    return setStream ? setStream->SetInStream(inStream) : E_NOTIMPL;
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::ReleaseInStream())
{
    if (!_sevenZip.IsDefined())
        return S_OK;
    _activeCoder = _sevenZip.Interface();
    CMyComPtr<ICompressSetInStream> setStream;
    _activeCoder->QueryInterface(IID_ICompressSetInStream, (void **)&setStream);
    return setStream ? setStream->ReleaseInStream() : E_NOTIMPL;
}

Z7_COM7F_IMF(CAdaptiveDeflateDecoder::SetOutStreamSize(const UInt64 *outSize))
{
    RINOK(ActivateSevenZip())
    CMyComPtr<ICompressSetOutStreamSize> setSize;
    _activeCoder->QueryInterface(IID_ICompressSetOutStreamSize, (void **)&setSize);
    return setSize ? setSize->SetOutStreamSize(outSize) : E_NOTIMPL;
}

#ifndef Z7_NO_READ_FROM_CODER
Z7_COM7F_IMF(CAdaptiveDeflateDecoder::Read(
    void *data, UInt32 size, UInt32 *processedSize))
{
    RINOK(ActivateSevenZip())
    CMyComPtr<ISequentialInStream> stream;
    _activeCoder->QueryInterface(IID_ISequentialInStream, (void **)&stream);
    return stream ? stream->Read(data, size, processedSize) : E_NOTIMPL;
}
#endif

}  // namespace

bool SunpackShouldUseZlibNgDeflate(UInt64 packedSize, UInt64 unpackedSize)
{
    const UInt64 kMinUnpackSize = (UInt64)64 << 10;
    if (unpackedSize < kMinUnpackSize)
        return false;
    const UInt64 minSavings = unpackedSize / 10;
    return packedSize <= unpackedSize - minSavings;
}

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

ICompressCoder *SunpackCreateAdaptiveDeflateDecoder()
{
    try
    {
        return new CAdaptiveDeflateDecoder();
    }
    catch (const std::bad_alloc &)
    {
        return nullptr;
    }
}



HRESULT SunpackDecodeGzipWithZlibNg(
    ISequentialInStream *inStream,
    ISequentialOutStream *outStream,
    ICompressProgressInfo *progress,
    SunpackGzipDecodeResult &result)
{
    result = SunpackGzipDecodeResult{};
    if (!inStream || !outStream)
        return E_INVALIDARG;

    std::vector<Byte> input;
    std::vector<Byte> output;
    try
    {
        input.resize(kBufferSize);
        output.resize(kBufferSize);
    }
    catch (const std::bad_alloc &)
    {
        return E_OUTOFMEMORY;
    }

    zng_stream stream{};
    int code = zng_inflateInit2(&stream, 31);
    if (code != Z_OK)
        return MapZlibNgError(code);

    const auto finish = [&](HRESULT hres) -> HRESULT {
        zng_inflateEnd(&stream);
        return hres;
    };

    bool inputFinished = false;
    bool memberStarted = false;
    UInt64 completedInput = 0;
    UInt64 totalOutput = 0;
    UInt64 lastProgressInput = 0;
    UInt64 lastProgressOutput = 0;

    const auto reportProgress = [&]() -> HRESULT {
        if (!progress)
            return S_OK;
        const UInt64 currentInput =
            completedInput + static_cast<UInt64>(stream.total_in);
        if ((currentInput - lastProgressInput) < (1u << 21) &&
            (totalOutput - lastProgressOutput) < (1u << 21))
            return S_OK;
        const HRESULT hres = progress->SetRatioInfo(&currentInput, &totalOutput);
        if (hres == S_OK)
        {
            lastProgressInput = currentInput;
            lastProgressOutput = totalOutput;
        }
        return hres;
    };

    for (;;)
    {
        if (stream.avail_in == 0 && !inputFinished)
        {
            UInt32 readSize = 0;
            const HRESULT hres = inStream->Read(
                input.data(),
                static_cast<UInt32>(input.size()),
                &readSize);
            if (hres != S_OK)
                return finish(hres);
            stream.next_in = reinterpret_cast<const uint8_t *>(input.data());
            stream.avail_in = readSize;
            inputFinished = readSize == 0;
        }

        if (stream.avail_in == 0 && inputFinished)
        {
            result.status = SunpackGzipDecodeStatus::kUnexpectedEnd;
            return finish(S_OK);
        }

        if (!memberStarted)
        {
            ++result.numStreams;
            memberStarted = true;
        }

        stream.next_out = reinterpret_cast<uint8_t *>(output.data());
        stream.avail_out = static_cast<uint32_t>(output.size());

        const uint32_t beforeIn = stream.avail_in;
        const uint32_t beforeOut = stream.avail_out;
        code = zng_inflate(&stream, Z_NO_FLUSH);
        const std::size_t consumed =
            static_cast<std::size_t>(beforeIn - stream.avail_in);
        const std::size_t produced =
            static_cast<std::size_t>(beforeOut - stream.avail_out);

        if (produced != 0)
        {
            const HRESULT hres = WriteStream(outStream, output.data(), produced);
            if (hres != S_OK)
                return finish(hres);
            totalOutput += static_cast<UInt64>(produced);
        }

        {
            const HRESULT hres = reportProgress();
            if (hres != S_OK)
                return finish(hres);
        }

        if (code == Z_STREAM_END)
        {
            completedInput += static_cast<UInt64>(stream.total_in);

            std::size_t pending = static_cast<std::size_t>(stream.avail_in);
            if (pending != 0)
                std::memmove(input.data(), stream.next_in, pending);

            // A gzip member can end exactly at our input-buffer boundary.
            // Read only enough to decide whether another member follows.
            while (pending < 2 && !inputFinished)
            {
                UInt32 readSize = 0;
                const HRESULT hres = inStream->Read(
                    input.data() + pending,
                    static_cast<UInt32>(input.size() - pending),
                    &readSize);
                if (hres != S_OK)
                    return finish(hres);
                pending += readSize;
                if (readSize == 0)
                    inputFinished = true;
            }

            if (pending == 0 && inputFinished)
            {
                result.status = SunpackGzipDecodeStatus::kOk;
                return finish(S_OK);
            }

            if (pending < 2 ||
                input[0] != 0x1f ||
                input[1] != 0x8b)
            {
                result.status = SunpackGzipDecodeStatus::kDataAfterEnd;
                return finish(S_OK);
            }

            code = zng_inflateReset2(&stream, 31);
            if (code != Z_OK)
                return finish(MapZlibNgError(code));

            // inflateReset2() does not own these caller buffers. Restore the
            // bytes that were already read beyond the previous member.
            stream.next_in = reinterpret_cast<const uint8_t *>(input.data());
            stream.avail_in = static_cast<uint32_t>(pending);
            memberStarted = false;
            stream.next_out = nullptr;
            stream.avail_out = 0;
            continue;
        }

        if (code == Z_DATA_ERROR || code == Z_NEED_DICT)
        {
            const char *msg = stream.msg;
            if (msg &&
                (std::strcmp(msg, "incorrect data check") == 0 ||
                 std::strcmp(msg, "incorrect length check") == 0))
                result.status = SunpackGzipDecodeStatus::kCrcError;
            else
                result.status = SunpackGzipDecodeStatus::kDataError;
            return finish(S_OK);
        }

        if (code != Z_OK && code != Z_BUF_ERROR)
            return finish(MapZlibNgError(code));

        if (consumed == 0 && produced == 0)
        {
            if (stream.avail_in == 0 && !inputFinished)
                continue;
            if (stream.avail_in == 0 && inputFinished)
            {
                result.status = SunpackGzipDecodeStatus::kUnexpectedEnd;
                return finish(S_OK);
            }
            result.status = SunpackGzipDecodeStatus::kDataError;
            return finish(S_OK);
        }
    }
}
