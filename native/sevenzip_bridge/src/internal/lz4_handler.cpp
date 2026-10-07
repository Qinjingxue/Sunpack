// Execution adapter only. Archive structure and carrier boundaries belong to Rust.
#include "7zip/Archive/StdAfx.h"
#include "lz4_handler.hpp"
#include "Common/ComTry.h"
#include "Windows/PropVariant.h"
#include "7zip/Common/RegisterArc.h"
#include "7zip/Common/StreamUtils.h"
#include "stream.h"
#include <algorithm>
namespace NArchive { namespace NSunpackLz4 {
Z7_CLASS_IMP_CHandler_IInArchive_0
    CMyComPtr<IInStream> stream;
    sup_lz4_result receipt{};
    bool decoded = false;
    UInt64 packed = 0;
};
static const Byte kProps[] = {kpidSize, kpidPackSize};
static const Byte kArcProps[] = {kpidNumStreams};
IMP_IInArchive_Props
IMP_IInArchive_ArcProps
Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *n)) { *n = 1; return S_OK; }
Z7_COM7F_IMF(CHandler::GetProperty(UInt32, PROPID id, PROPVARIANT *value)) {
    NWindows::NCOM::CPropVariant prop;
    if (id == kpidPackSize) prop = packed;
    if (id == kpidSize && decoded) prop = static_cast<UInt64>(receipt.output_bytes);
    prop.Detach(value); return S_OK;
}
Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID id, PROPVARIANT *value)) {
    NWindows::NCOM::CPropVariant prop;
    if (decoded) {
        const UInt64 fields[] = {receipt.input_bytes, receipt.output_bytes, receipt.frames,
            receipt.skippable_frames, receipt.content_checked_frames, receipt.block_checked_frames,
            static_cast<UInt64>(receipt.error)};
        if (id >= sunpack::sevenzip::kLz4ReceiptBase && id < sunpack::sevenzip::kLz4ReceiptBase + 7)
            prop = fields[id - sunpack::sevenzip::kLz4ReceiptBase];
        else if (id == kpidNumStreams) prop = static_cast<UInt64>(receipt.frames);
    }
    prop.Detach(value); return S_OK;
}
Z7_COM7F_IMF(CHandler::Open(IInStream *input, const UInt64 *, IArchiveOpenCallback *)) {
    COM_TRY_BEGIN
    Close();
    Byte magic[4];
    RINOK(InStream_SeekToBegin(input))
    RINOK(ReadStream_FALSE(input, magic, 4))
    const UInt32 v = UInt32(magic[0]) | UInt32(magic[1]) << 8 | UInt32(magic[2]) << 16 | UInt32(magic[3]) << 24;
    if (v != 0x184d2204 && (v & 0xfffffff0) != 0x184d2a50) return S_FALSE;
    RINOK(input->Seek(0, STREAM_SEEK_END, &packed))
    stream = input; return S_OK;
    COM_TRY_END
}
Z7_COM7F_IMF(CHandler::Close()) { stream.Release(); decoded = false; receipt = {}; packed = 0; return S_OK; }
struct Context {
    IInStream *input;
    ISequentialOutStream *output;
    IArchiveExtractCallback *progress;
    HRESULT error = S_OK;
    UInt64 packed;
};
static ptrdiff_t read(void *p, void *dst, size_t n) {
    auto &c = *static_cast<Context *>(p); UInt32 got = 0;
    c.error = c.input->Read(dst, static_cast<UInt32>(n), &got);
    return c.error == S_OK ? static_cast<ptrdiff_t>(got) : -1;
}
static int skip(void *p, uint64_t n) {
    auto &c = *static_cast<Context *>(p); UInt64 position = 0;
    c.error = c.input->Seek(0, STREAM_SEEK_CUR, &position);
    if (c.error != S_OK) return -1;
    if (n > c.packed - (std::min)(position, c.packed)) return 1;
    c.error = c.input->Seek(static_cast<Int64>(n), STREAM_SEEK_CUR, nullptr);
    return c.error == S_OK ? 0 : -1;
}
static int write(void *p, const void *src, size_t n) {
    auto &c = *static_cast<Context *>(p);
    if (!c.output) return 0;
    c.error = WriteStream(c.output, src, n);
    return c.error == S_OK ? 0 : -1;
}
static int progress(void *p, uint64_t in, uint64_t) {
    auto &c = *static_cast<Context *>(p); const UInt64 completed = in;
    c.error = c.progress->SetCompleted(&completed); return c.error == S_OK ? 0 : -1;
}
Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 count, Int32 test, IArchiveExtractCallback *callback)) {
    COM_TRY_BEGIN
    if (!count) return S_OK;
    if (count != UInt32(-1) && (count != 1 || indices[0])) return E_INVALIDARG;
    RINOK(callback->SetTotal(packed))
    CMyComPtr<ISequentialOutStream> output;
    const Int32 ask = test ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
    RINOK(callback->GetStream(0, &output, ask))
    if (!test && !output) return S_OK;
    RINOK(callback->PrepareOperation(ask))
    RINOK(InStream_SeekToBegin(stream))
    Context c{stream, output, callback, S_OK, packed};
    const int rc = sup_lz4_decode(&c, read, skip, write, progress, &receipt);
    decoded = true;
    output.Release();
    if (c.error != S_OK) return c.error;
    if (rc == SUP_LZ4_MEMORY) return E_OUTOFMEMORY;
    const Int32 op = rc == SUP_LZ4_OK ? NExtract::NOperationResult::kOK :
        rc == SUP_LZ4_CHECKSUM ? NExtract::NOperationResult::kCRCError :
        rc == SUP_LZ4_TRUNCATED ? NExtract::NOperationResult::kUnexpectedEnd :
        rc == SUP_LZ4_UNSUPPORTED ? NExtract::NOperationResult::kUnsupportedMethod : NExtract::NOperationResult::kDataError;
    return callback->SetOperationResult(op);
    COM_TRY_END
}
static const Byte k_Signature[] = {4, 0x22, 0x4d, 0x18};
REGISTER_ARC_I("lz4", "lz4", "*", 0xFA, k_Signature, 0, NArcInfoFlags::kKeepName, nullptr)
}}

namespace sunpack::sevenzip {
void read_lz4_receipt(IInArchive *archive, ExtractArchiveResult &result) {
    UInt64 fields[7]{};
    for (unsigned int i = 0; i != 7; ++i) {
        NWindows::NCOM::CPropVariant prop;
        if (archive->GetArchiveProperty(kLz4ReceiptBase + i, &prop) != S_OK || prop.vt != VT_UI8) return;
        fields[i] = prop.uhVal.QuadPart;
    }
    result.has_stream_receipt = true;
    result.stream_receipt = {fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
        static_cast<unsigned int>(fields[6])};
    result.stream_receipt.format = "lz4";
    for (auto &item : result.output_trace.items) item.crc_verified = false;
}
}
