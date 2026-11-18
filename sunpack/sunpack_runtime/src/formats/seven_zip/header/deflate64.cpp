#include "Common/MyInitGuid.h"
#include "7zip/Compress/DeflateDecoder.h"
#include "Alloc.h"
#include <stdlib.h>
#include <string.h>

// The vendor decoder allocates only its input and history buffers here.
// These symbols are renamed for this small stand-alone decoder library.
void *MidAlloc(size_t size) { return malloc(size); }
void MidFree(void *buffer) { free(buffer); }

namespace {
using WriteCallback = int (*)(void *, const Byte *, size_t);

// The SDK borrows these streams only while Code runs.
template<class Interface>
class LocalStream : public Interface {
    Z7_COM7F_IMF(QueryInterface(REFIID, void **result)) {
        *result = nullptr;
        return E_NOINTERFACE;
    }
    Z7_COM7F_IMF2(ULONG, AddRef()) { return 1; }
    Z7_COM7F_IMF2(ULONG, Release()) { return 1; }
};

class Input final : public LocalStream<ISequentialInStream> {
    const Byte *current;
    size_t remaining;
public:
    Input(const Byte *data, size_t size) : current(data), remaining(size) {}
    Z7_COM7F_IMF(Read(void *buffer, UInt32 size, UInt32 *processed)) {
        if (size > remaining) size = static_cast<UInt32>(remaining);
        memcpy(buffer, current, size);
        current += size;
        remaining -= size;
        if (processed) *processed = size;
        return S_OK;
    }
};

class Output final : public LocalStream<ISequentialOutStream> {
    void *context;
    WriteCallback callback;
public:
    Output(void *context, WriteCallback write) : context(context), callback(write) {}
    Z7_COM7F_IMF(Write(const void *buffer, UInt32 size, UInt32 *processed)) {
        const bool failed = callback(context, static_cast<const Byte *>(buffer), size) != 0;
        if (processed) *processed = failed ? 0 : size;
        return failed ? E_ABORT : S_OK;
    }
};

class Progress final : public LocalStream<ICompressProgressInfo> {
    void *context;
    WriteCallback callback;
public:
    Progress(void *context, WriteCallback write) : context(context), callback(write) {}
    Z7_COM7F_IMF(SetRatioInfo(const UInt64 *, const UInt64 *)) {
        // A zero-length call checks cancellation on streams with empty blocks.
        return callback(context, reinterpret_cast<const Byte *>(""), 0) ? E_ABORT : S_OK;
    }
};
}

extern "C" int sunpack_decode_deflate64_header(
    const Byte *data, size_t size, UInt64 output_size, void *context, WriteCallback write
) {
    Input input(data, size);
    Output output(context, write);
    Progress progress(context, write);
    NCompress::NDeflate::NDecoder::CCOMCoder64 decoder;
    decoder.Set_NeedFinishInput(true);
    const UInt64 input_size = size;
    // Code is public on the interface and dispatches to the vendor decoder.
    const HRESULT status = static_cast<ICompressCoder &>(decoder).Code(
        &input, &output, &input_size, &output_size, &progress);
    if (status == S_OK) return SZ_OK;
    return status == E_OUTOFMEMORY ? SZ_ERROR_MEM : SZ_ERROR_DATA;
}
