#pragma once

#ifdef _WIN32
// The SunPack bridge targets intentionally use WIN32_LEAN_AND_MEAN, while
// upstream 7-Zip's COM interface headers normally get these declarations
// transitively from the full Windows.h include set. Pull in the required COM,
// stream, property, and BSTR declarations explicitly before ICoder.h.
#include <Unknwn.h>
#include <wtypes.h>
#include <objidl.h>
#include <OleAuto.h>
#endif

#include "7zip/ICoder.h"

// Shared metadata-only routing policy used by ZIP and generic method 0x40108.
// It performs no stream reads or probe decoding.
bool SunpackShouldUseZlibNgDeflate(UInt64 packedSize, UInt64 unpackedSize);

// Creates the direct zlib-ng raw-Deflate decoder used by the ZIP metadata fast
// path.  The returned object implements ICompressCoder plus the 7-Zip
// interfaces needed for finish-mode, consumed-input accounting, and unread
// buffered bytes (Strong Encryption padding checks).
ICompressCoder *SunpackCreateZlibNgDeflateDecoder();

// Creates the generic RFC1951 decoder registered as method 0x40108.
// Code() chooses zlib-ng only when both packed/unpacked sizes are known and
// clearly compressible; streaming/read interfaces remain backed by upstream
// 7-Zip so partial 7z decoding keeps the original state-machine semantics.
ICompressCoder *SunpackCreateAdaptiveDeflateDecoder();


enum class SunpackGzipDecodeStatus
{
    kOk,
    kUnexpectedEnd,
    kDataError,
    kCrcError,
    kDataAfterEnd
};

struct SunpackGzipDecodeResult
{
    SunpackGzipDecodeStatus status = SunpackGzipDecodeStatus::kDataError;
    UInt64 numStreams = 0;
};

// Decode a complete seekable gzip stream, including concatenated members.
// zlib-ng validates each member's gzip header, CRC32, and ISIZE. The caller
// keeps sequential/non-seekable inputs on the upstream 7-Zip GZip state machine.
HRESULT SunpackDecodeGzipWithZlibNg(
    ISequentialInStream *inStream,
    ISequentialOutStream *outStream,
    ICompressProgressInfo *progress,
    SunpackGzipDecodeResult &result);
