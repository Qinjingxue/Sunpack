#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "Common/MyCom.h"
#include "internal/zlib_ng_deflate_decoder.h"

namespace {

static const Byte kRawDeflate[] = {
    0xed,0xc9,0xb1,0x09,0x80,0x30,0x10,0x00,0xc0,0xde,0x5d,0x7e,0xa8,0x28,0x41,0x82,
    0x12,0xc5,0x8f,0x8d,0xd3,0xeb,0x1e,0x5e,0x75,0xc5,0xe5,0xdd,0xcf,0xb2,0x6c,0xf1,
    0xec,0x6d,0x8e,0xbe,0x46,0x8e,0xeb,0xf8,0x28,0x35,0x63,0xd4,0x1c,0x53,0x7a,0xef,
    0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,
    0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,
    0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,
    0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,
    0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,
    0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,
    0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,
    0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xf7,0xde,
    0x7b,0xef,0xbd,0xf7,0xde,0x7b,0xef,0xbd,0xff,0xc5,0xbf
};

static const Byte kTrailingPadding[] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};


static const Byte kGzipMemberA[] = {
    0x1f,0x8b,0x08,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0x2b,0x2e,0xcd,0x2b,0x48,0x4c,
    0xce,0xd6,0x4d,0xaf,0xca,0x2c,0xd0,0xcd,0x4d,0xcd,0x4d,0x4a,0x2d,0xd2,0x4d,0xe4,
    0x2a,0x1e,0xb4,0xa2,0x00,0x5f,0x1f,0x8f,0xbd,0xb0,0x00,0x00,0x00
};

static const Byte kGzipMemberB[] = {
    0x1f,0x8b,0x08,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0x2b,0x2e,0xcd,0x2b,0x48,0x4c,
    0xce,0xd6,0x4d,0xaf,0xca,0x2c,0xd0,0xcd,0x4d,0xcd,0x4d,0x4a,0x2d,0xd2,0x4d,0xe2,
    0x2a,0xa6,0x91,0x28,0x00,0xa3,0xc5,0x54,0x7f,0x6e,0x00,0x00,0x00
};

Z7_CLASS_IMP_COM_1(
    CMemoryInStream
    , ISequentialInStream
)
    const std::vector<Byte> &_data;
    std::size_t _pos = 0;
public:
    explicit CMemoryInStream(const std::vector<Byte> &data): _data(data) {}
};

Z7_COM7F_IMF(CMemoryInStream::Read(void *data, UInt32 size, UInt32 *processedSize))
{
    if (processedSize)
        *processedSize = 0;
    if (size == 0 || _pos >= _data.size())
        return S_OK;
    const std::size_t amount = std::min<std::size_t>(size, _data.size() - _pos);
    std::memcpy(data, _data.data() + _pos, amount);
    _pos += amount;
    if (processedSize)
        *processedSize = static_cast<UInt32>(amount);
    return S_OK;
}

Z7_CLASS_IMP_COM_1(
    CVectorOutStream
    , ISequentialOutStream
)
public:
    std::vector<Byte> Data;
};

Z7_COM7F_IMF(CVectorOutStream::Write(const void *data, UInt32 size, UInt32 *processedSize))
{
    if (processedSize)
        *processedSize = 0;
    const Byte *bytes = static_cast<const Byte *>(data);
    Data.insert(Data.end(), bytes, bytes + size);
    if (processedSize)
        *processedSize = size;
    return S_OK;
}

bool Check(bool condition, const char *message)
{
    if (!condition)
        std::fprintf(stderr, "zlib-ng decoder contract failed: %s\n", message);
    return condition;
}

}  // namespace

int main()
{
    if (!Check(!SunpackShouldUseZlibNgDeflate(32 * 1024, 63 * 1024),
               "adaptive policy keeps small streams on 7-Zip"))
        return 1;
    if (!Check(SunpackShouldUseZlibNgDeflate(90 * 1024, 100 * 1024),
               "adaptive policy accepts 10 percent savings"))
        return 1;
    if (!Check(!SunpackShouldUseZlibNgDeflate(91 * 1024, 100 * 1024),
               "adaptive policy rejects near-store streams"))
        return 1;

    const std::string unit = "sunpack-zlib-ng-strong-aes-test\n";
    std::vector<Byte> expected;
    expected.reserve(unit.size() * 2048);
    for (unsigned i = 0; i < 2048; ++i)
        expected.insert(expected.end(), unit.begin(), unit.end());

    std::vector<Byte> packed(std::begin(kRawDeflate), std::end(kRawDeflate));
    packed.insert(packed.end(), std::begin(kTrailingPadding), std::end(kTrailingPadding));

    CMyComPtr<ICompressCoder> coder = SunpackCreateZlibNgDeflateDecoder();
    if (!Check(!!coder, "decoder allocation"))
        return 1;

    CMyComPtr<ICompressSetFinishMode> finishMode;
    if (!Check(coder.QueryInterface(IID_ICompressSetFinishMode, &finishMode) == S_OK && !!finishMode,
               "ICompressSetFinishMode"))
        return 1;
    if (!Check(finishMode->SetFinishMode(1) == S_OK, "SetFinishMode"))
        return 1;

    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> inStream(packed);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> outStream;

    const UInt64 inSize = static_cast<UInt64>(packed.size());
    const UInt64 outSize = static_cast<UInt64>(expected.size());
    if (!Check(coder->Code(inStream, outStream, &inSize, &outSize, nullptr) == S_OK, "Code"))
        return 1;

    if (!Check(outStream->Data == expected, "decoded bytes"))
        return 1;

    CMyComPtr<ICompressGetInStreamProcessedSize> processed;
    if (!Check(coder.QueryInterface(IID_ICompressGetInStreamProcessedSize, &processed) == S_OK && !!processed,
               "ICompressGetInStreamProcessedSize"))
        return 1;
    UInt64 consumed = 0;
    if (!Check(processed->GetInStreamProcessedSize(&consumed) == S_OK, "GetInStreamProcessedSize"))
        return 1;
    if (!Check(consumed == sizeof(kRawDeflate), "consumed size excludes trailing encryption bytes"))
        return 1;

    CMyComPtr<ICompressReadUnusedFromInBuf> unused;
    if (!Check(coder.QueryInterface(IID_ICompressReadUnusedFromInBuf, &unused) == S_OK && !!unused,
               "ICompressReadUnusedFromInBuf"))
        return 1;

    std::array<Byte, 32> padding{};
    UInt32 paddingSize = 0;
    if (!Check(unused->ReadUnusedFromInBuf(
                   padding.data(), static_cast<UInt32>(padding.size()), &paddingSize) == S_OK,
               "ReadUnusedFromInBuf"))
        return 1;
    if (!Check(paddingSize == sizeof(kTrailingPadding), "unused byte count"))
        return 1;
    if (!Check(std::memcmp(padding.data(), kTrailingPadding, sizeof(kTrailingPadding)) == 0,
               "unused bytes preserve Strong Encryption padding"))
        return 1;

    UInt32 secondRead = 123;
    if (!Check(unused->ReadUnusedFromInBuf(
                   padding.data(), static_cast<UInt32>(padding.size()), &secondRead) == S_OK &&
               secondRead == 0,
               "unused bytes drain exactly once"))
        return 1;

    // ZipHandler caches the coder by method, so the same zlib-ng instance can
    // decode the next entry immediately after a Strong Encryption entry.  The
    // previous stream's prefetched padding must not survive inflateReset2().
    std::vector<Byte> packedAgain(std::begin(kRawDeflate), std::end(kRawDeflate));
    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> inStreamAgain(packedAgain);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> outStreamAgain;
    const UInt64 inSizeAgain = static_cast<UInt64>(packedAgain.size());
    if (!Check(
            coder->Code(inStreamAgain, outStreamAgain, &inSizeAgain, &outSize, nullptr) == S_OK,
            "cached coder reuse after trailing padding"))
        return 1;
    if (!Check(outStreamAgain->Data == expected, "cached coder reuse decoded bytes"))
        return 1;

    // The generic 0x40108 registry decoder uses the same fast backend when
    // packed/unpacked sizes clearly indicate useful compression.
    CMyComPtr<ICompressCoder> adaptive = SunpackCreateAdaptiveDeflateDecoder();
    if (!Check(!!adaptive, "adaptive decoder allocation"))
        return 1;

    CMyComPtr<ICompressSetFinishMode> adaptiveFinish;
    if (!Check(
            adaptive.QueryInterface(IID_ICompressSetFinishMode, &adaptiveFinish) == S_OK &&
                !!adaptiveFinish,
            "adaptive ICompressSetFinishMode"))
        return 1;
    if (!Check(adaptiveFinish->SetFinishMode(1) == S_OK, "adaptive SetFinishMode"))
        return 1;

    CMyComPtr<ICompressSetInStream> adaptiveSetIn;
    if (!Check(
            adaptive.QueryInterface(IID_ICompressSetInStream, &adaptiveSetIn) == S_OK &&
                !!adaptiveSetIn,
            "adaptive ICompressSetInStream"))
        return 1;

    CMyComPtr<ICompressSetOutStreamSize> adaptiveSetOutSize;
    if (!Check(
            adaptive.QueryInterface(IID_ICompressSetOutStreamSize, &adaptiveSetOutSize) == S_OK &&
                !!adaptiveSetOutSize,
            "adaptive ICompressSetOutStreamSize"))
        return 1;

#ifndef Z7_NO_READ_FROM_CODER
    CMyComPtr<ISequentialInStream> adaptiveRead;
    if (!Check(
            adaptive.QueryInterface(IID_ISequentialInStream, &adaptiveRead) == S_OK &&
                !!adaptiveRead,
            "adaptive ISequentialInStream"))
        return 1;
#endif

    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> adaptiveIn(packedAgain);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> adaptiveOut;
    if (!Check(
            adaptive->Code(adaptiveIn, adaptiveOut, &inSizeAgain, &outSize, nullptr) == S_OK,
            "adaptive Code"))
        return 1;
    if (!Check(adaptiveOut->Data == expected, "adaptive decoded bytes"))
        return 1;

    const std::string gzipUnitA = "sunpack-gzip-member-a\n";
    const std::string gzipUnitB = "sunpack-gzip-member-b\n";
    std::vector<Byte> gzipExpected;
    for (unsigned i = 0; i < 8; ++i)
        gzipExpected.insert(gzipExpected.end(), gzipUnitA.begin(), gzipUnitA.end());
    for (unsigned i = 0; i < 5; ++i)
        gzipExpected.insert(gzipExpected.end(), gzipUnitB.begin(), gzipUnitB.end());

    std::vector<Byte> gzipConcat(std::begin(kGzipMemberA), std::end(kGzipMemberA));
    gzipConcat.insert(gzipConcat.end(), std::begin(kGzipMemberB), std::end(kGzipMemberB));
    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> gzipIn(gzipConcat);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> gzipOut;
    SunpackGzipDecodeResult gzipResult;
    if (!Check(
            SunpackDecodeGzipWithZlibNg(gzipIn, gzipOut, nullptr, gzipResult) == S_OK,
            "gzip helper call"))
        return 1;
    if (!Check(gzipResult.status == SunpackGzipDecodeStatus::kOk,
               "concatenated gzip status"))
        return 1;
    if (!Check(gzipResult.numStreams == 2, "concatenated gzip member count"))
        return 1;
    if (!Check(gzipOut->Data == gzipExpected, "concatenated gzip decoded bytes"))
        return 1;

    std::vector<Byte> gzipBadCrc(std::begin(kGzipMemberA), std::end(kGzipMemberA));
    gzipBadCrc[gzipBadCrc.size() - 8] ^= 0x01;
    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> gzipBadCrcIn(gzipBadCrc);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> gzipBadCrcOut;
    SunpackGzipDecodeResult gzipBadCrcResult;
    if (!Check(
            SunpackDecodeGzipWithZlibNg(
                gzipBadCrcIn, gzipBadCrcOut, nullptr, gzipBadCrcResult) == S_OK,
            "gzip CRC helper call"))
        return 1;
    if (!Check(gzipBadCrcResult.status == SunpackGzipDecodeStatus::kCrcError,
               "gzip CRC mismatch classification"))
        return 1;

    std::vector<Byte> gzipTruncated(std::begin(kGzipMemberA), std::end(kGzipMemberA) - 3);
    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> gzipTruncatedIn(gzipTruncated);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> gzipTruncatedOut;
    SunpackGzipDecodeResult gzipTruncatedResult;
    if (!Check(
            SunpackDecodeGzipWithZlibNg(
                gzipTruncatedIn, gzipTruncatedOut, nullptr, gzipTruncatedResult) == S_OK,
            "gzip truncated helper call"))
        return 1;
    if (!Check(gzipTruncatedResult.status == SunpackGzipDecodeStatus::kUnexpectedEnd,
               "gzip truncated classification"))
        return 1;

    std::vector<Byte> gzipTrailing(std::begin(kGzipMemberA), std::end(kGzipMemberA));
    gzipTrailing.push_back(0x42);
    gzipTrailing.push_back(0x43);
    CMyComPtr2_Create<ISequentialInStream, CMemoryInStream> gzipTrailingIn(gzipTrailing);
    CMyComPtr2_Create<ISequentialOutStream, CVectorOutStream> gzipTrailingOut;
    SunpackGzipDecodeResult gzipTrailingResult;
    if (!Check(
            SunpackDecodeGzipWithZlibNg(
                gzipTrailingIn, gzipTrailingOut, nullptr, gzipTrailingResult) == S_OK,
            "gzip trailing helper call"))
        return 1;
    if (!Check(gzipTrailingResult.status == SunpackGzipDecodeStatus::kDataAfterEnd,
               "gzip trailing-data classification"))
        return 1;

    return 0;
}
