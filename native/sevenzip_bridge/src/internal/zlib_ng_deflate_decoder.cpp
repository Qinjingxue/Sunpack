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


constexpr UInt64 kAdaptiveMinUnpackSize = (UInt64)64 << 10;

bool ShouldUseZlibNgAdaptive(const UInt64 *inSize, const UInt64 *outSize)
{
    if (!inSize || !outSize || *outSize < kAdaptiveMinUnpackSize)
        return false;
    const UInt64 minSavings = *outSize / 10;
    return *inSize <= *outSize - minSavings;
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
    if (_finishMode != 0 && ShouldUseZlibNgAdaptive(inSize, outSize))
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

