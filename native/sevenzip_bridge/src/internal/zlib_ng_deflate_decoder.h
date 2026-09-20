#pragma once

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
