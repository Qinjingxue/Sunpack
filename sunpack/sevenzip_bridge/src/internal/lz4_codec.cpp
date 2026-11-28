// 7-Zip-Zstandard method 0x04F71104 stores standard LZ4 frames, optionally
// separated by skippable chunk metadata. Reuse the standalone execution decoder.
#include "7zip/Archive/StdAfx.h"
#include <Unknwn.h>
#include <wtypes.h>
#include <objidl.h>
#include <OleAuto.h>
#include "Common/MyCom.h"
#include "7zip/Common/RegisterCodec.h"
#include "7zip/Common/StreamUtils.h"
#include "stream.h"
#include "decoder_memory.h"
#include <algorithm>
#include <memory>

namespace NCompress { namespace NSunpackLz4 {
struct Context {
    ISequentialInStream *input;
    ISequentialOutStream *output;
    ICompressProgressInfo *progress;
    const UInt64 *input_limit, *output_limit;
    bool finish, cut = false;
    UInt64 read = 0, written = 0;
    HRESULT status = S_OK;
};
class CDecoder final : public ICompressCoder, public ICompressSetDecoderProperties2,
    public ICompressSetFinishMode, public ICompressGetInStreamProcessedSize,
    public ICompressSetInStream, public ICompressSetOutStreamSize, public ISequentialInStream,
    public CMyUnknownImp {
    bool finish = false;
    UInt64 processed = 0;
    CMyComPtr<ISequentialInStream> pull_input;
    Context pull_context{};
    sup_lz4_result pull_result{};
    std::unique_ptr<sup_lz4_reader, decltype(&sup_lz4_reader_close)> pull{nullptr, sup_lz4_reader_close};
    UInt64 output_limit = 0;
    bool has_limit = false, pull_eof = false;
    HRESULT pull_status = S_OK;
public:
    Z7_COM_QI_BEGIN2(ICompressCoder)
    Z7_COM_QI_ENTRY(ICompressSetDecoderProperties2)
    Z7_COM_QI_ENTRY(ICompressSetFinishMode)
    Z7_COM_QI_ENTRY(ICompressGetInStreamProcessedSize)
    Z7_COM_QI_ENTRY(ICompressSetInStream)
    Z7_COM_QI_ENTRY(ICompressSetOutStreamSize)
    Z7_COM_QI_ENTRY(ISequentialInStream)
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE
    Z7_IFACE_COM7_IMP(ICompressCoder)
    Z7_IFACE_COM7_IMP(ICompressSetDecoderProperties2)
    Z7_IFACE_COM7_IMP(ICompressSetFinishMode)
    Z7_IFACE_COM7_IMP(ICompressGetInStreamProcessedSize)
    Z7_IFACE_COM7_IMP(ICompressSetInStream)
    Z7_IFACE_COM7_IMP(ICompressSetOutStreamSize)
    Z7_IFACE_COM7_IMP(ISequentialInStream)
};
static ptrdiff_t read(void *opaque, void *buffer, size_t size) {
    auto &c = *static_cast<Context *>(opaque);
    if (c.input_limit) size = static_cast<size_t>(std::min<UInt64>(size, *c.input_limit - c.read));
    UInt32 count = 0;
    c.status = c.input->Read(buffer, static_cast<UInt32>(size), &count);
    if (c.status != S_OK) return -1;
    c.read += count;
    return count;
}
static int write(void *opaque, const void *buffer, size_t size) {
    auto &c = *static_cast<Context *>(opaque);
    size_t take = size;
    if (c.output_limit) take = static_cast<size_t>(std::min<UInt64>(take, *c.output_limit - c.written));
    if (c.finish && take != size) { c.status = S_FALSE; return 1; }
    const auto *data = static_cast<const Byte *>(buffer);
    while (take) {
        UInt32 count = 0;
        c.status = c.output->Write(data, static_cast<UInt32>(take), &count);
        c.written += count;
        if (c.status == k_My_HRESULT_WritingWasCut && !c.finish) { c.cut = true; return 1; }
        if (c.status != S_OK) return 1;
        if (!count) { c.status = E_FAIL; return 1; }
        data += count; take -= count;
    }
    if (!c.finish && c.output_limit && c.written == *c.output_limit) { c.cut = true; return 1; }
    return 0;
}
static int progress(void *opaque, uint64_t in, uint64_t out) {
    auto &c = *static_cast<Context *>(opaque);
    if (!c.progress) return 0;
    const UInt64 input = in, output = out;
    c.status = c.progress->SetRatioInfo(&input, &output);
    return c.status != S_OK;
}
static HRESULT decode_status(const Context &context, int error) {
    if (context.status != S_OK) return context.status;
    if (error == SUP_LZ4_UNSUPPORTED) return E_NOTIMPL;
    if (error == SUP_LZ4_MEMORY) return E_OUTOFMEMORY;
    return error ? S_FALSE : S_OK;
}
Z7_COM7F_IMF(CDecoder::SetDecoderProperties2(const Byte *properties, UInt32 size)) {
    // Upstream's five bytes are encoder version/level/reserved hints. Frames
    // carry all decoding parameters; reject malformed properties, not versions.
    return size == 5 && properties ? S_OK : E_INVALIDARG;
}
Z7_COM7F_IMF(CDecoder::SetFinishMode(UInt32 mode)) { finish = mode != 0; return S_OK; }
Z7_COM7F_IMF(CDecoder::GetInStreamProcessedSize(UInt64 *size)) {
    if (!size) return E_INVALIDARG;
    *size = processed; return S_OK;
}
// The single-thread mixer pulls the bonded input streams on demand. Reuse
// the frame decoder without staging a whole member or spawning a helper.
Z7_COM7F_IMF(CDecoder::SetInStream(ISequentialInStream *input)) {
    pull.reset();
    pull_input = input;
    return SetOutStreamSize(nullptr);
}
Z7_COM7F_IMF(CDecoder::ReleaseInStream()) {
    pull.reset();
    pull_input.Release();
    return S_OK;
}
Z7_COM7F_IMF(CDecoder::SetOutStreamSize(const UInt64 *size)) {
    pull.reset();
    processed = 0;
    has_limit = size != nullptr;
    output_limit = size ? *size : 0;
    pull_eof = false;
    pull_status = S_OK;
    return S_OK;
}
Z7_COM7F_IMF(CDecoder::Read(void *data, UInt32 size, UInt32 *processed_size)) {
    if (processed_size) *processed_size = 0;
    if (pull_status != S_OK || pull_eof) return pull_status;
    if (size && !data) return E_INVALIDARG;
    if (!pull_input) return E_INVALIDARG;
    if (!size && !(finish && has_limit && !output_limit)) return S_OK;
    if (!pull) {
        pull_context = Context{pull_input, nullptr, nullptr, nullptr, nullptr, finish};
        pull.reset(sup_lz4_reader_open(&pull_context, read, &pull_result,
            sunpack_decoder_allocate, sunpack_decoder_free));
        if (!pull) return pull_status = E_OUTOFMEMORY;
    }
    const auto read_next = [&](void *out, size_t cap, size_t &n) {
        const auto error = sup_lz4_reader_read(pull.get(), out, cap, &n);
        processed = pull_result.input_bytes;
        return decode_status(pull_context, error);
    };
    if (has_limit) {
        size = static_cast<UInt32>(std::min<UInt64>(size, output_limit - pull_result.output_bytes));
    }
    auto *out = static_cast<Byte *>(data);
    UInt32 total = 0;
    while (total < size) {
        size_t n = 0;
        pull_status = read_next(out + total, size - total, n);
        if (pull_status != S_OK) break;
        if (!n) {
            pull_eof = true;
            if (has_limit && pull_result.output_bytes != output_limit) pull_status = S_FALSE;
            break;
        }
        total += static_cast<UInt32>(n);
    }
    if (pull_status == S_OK && !pull_eof && has_limit && pull_result.output_bytes == output_limit) {
        // Validate the frame footer even when the caller asks for exactly the
        // known output size and never issues a separate EOF read.
        if (finish) {
            Byte extra;
            size_t n = 0;
            pull_status = read_next(&extra, 1, n);
            if (pull_status == S_OK && n) pull_status = S_FALSE;
        }
        pull_eof = true;
    }
    if (processed_size) *processed_size = total;
    if (pull_eof || pull_status != S_OK) pull.reset();
    return pull_status;
}
Z7_COM7F_IMF(CDecoder::Code(ISequentialInStream *input, ISequentialOutStream *output,
    const UInt64 *input_size, const UInt64 *output_size, ICompressProgressInfo *report)) {
    processed = 0;
    if (!input || !output) return E_INVALIDARG;
    if (!finish && output_size && !*output_size) return S_OK;
    Context context{input, output, report, input_size, output_size, finish};
    sup_lz4_result result{};
    const int error = sup_lz4_decode_with_memory(&context, read, nullptr, write, progress, &result,
        sunpack_decoder_allocate, sunpack_decoder_free);
    processed = result.input_bytes;
    if (context.cut) return S_OK;
    const auto status = decode_status(context, error);
    if (status != S_OK) return status;
    if ((output_size && result.output_bytes != *output_size) ||
        (finish && input_size && result.input_bytes != *input_size)) return S_FALSE;
    return S_OK;
}
REGISTER_CODEC_CREATE(CreateDecoder, CDecoder)
REGISTER_CODEC_2(SunpackLz4, CreateDecoder, nullptr, 0x04F71104, "LZ4")
}}
