#pragma once

#include "7zip/ICoder.h"

// Creates the SunPack ZIP Deflate decoder backed by zlib-ng.
// The returned object implements ICompressCoder plus the 7-Zip interfaces
// needed by ZipHandler for finish-mode, consumed-input accounting, and
// unread buffered bytes (Strong Encryption padding checks).
ICompressCoder *SunpackCreateZlibNgDeflateDecoder();
