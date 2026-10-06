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
#include <algorithm>

namespace NCompress { namespace NSunpackLz4 {
class CDecoder final : public ICompressCoder, public ICompressSetDecoderProperties2,
    public ICompressSetFinishMode, public ICompressGetInStreamProcessedSize, public CMyUnknownImp {
    bool finish = false;
    UInt64 processed = 0;
public:
    Z7_COM_QI_BEGIN2(ICompressCoder)
    Z7_COM_QI_ENTRY(ICompressSetDecoderProperties2)
    Z7_COM_QI_ENTRY(ICompressSetFinishMode)
    Z7_COM_QI_ENTRY(ICompressGetInStreamProcessedSize)
    Z7_COM_QI_END
    Z7_COM_ADDREF_RELEASE
    Z7_IFACE_COM7_IMP(ICompressCoder)
    Z7_IFACE_COM7_IMP(ICompressSetDecoderProperties2)
    Z7_IFACE_COM7_IMP(ICompressSetFinishMode)
    Z7_IFACE_COM7_IMP(ICompressGetInStreamProcessedSize)
};
struct Context {
    ISequentialInStream *input;
    ISequentialOutStream *output;
    ICompressProgressInfo *progress;
    const UInt64 *input_limit, *output_limit;
    bool finish, cut = false;
    UInt64 read = 0, written = 0;
    HRESULT status = S_OK;
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
Z7_COM7F_IMF(CDecoder::Code(ISequentialInStream *input, ISequentialOutStream *output,
    const UInt64 *input_size, const UInt64 *output_size, ICompressProgressInfo *report)) {
    processed = 0;
    if (!input || !output) return E_INVALIDARG;
    if (!finish && output_size && !*output_size) return S_OK;
    Context context{input, output, report, input_size, output_size, finish};
    sup_lz4_result result{};
    const int error = sup_lz4_decode(&context, read, nullptr, write, nullptr, progress, &result);
    processed = result.input_bytes;
    if (context.cut) return S_OK;
    if (context.status != S_OK) return context.status;
    if (error == SUP_LZ4_MEMORY) return E_OUTOFMEMORY;
    if (error) return S_FALSE;
    if ((output_size && result.output_bytes != *output_size) ||
        (finish && input_size && result.input_bytes != *input_size)) return S_FALSE;
    return S_OK;
}
REGISTER_CODEC_CREATE(CreateDecoder, CDecoder)
REGISTER_CODEC_2(SunpackLz4, CreateDecoder, nullptr, 0x04F71104, "LZ4")
}}
