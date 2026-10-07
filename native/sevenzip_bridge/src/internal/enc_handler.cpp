// Execution adapter only; container/KDF/cipher/authentication all live in Rust.
#include "7zip/Archive/StdAfx.h"
#include "sevenzip_sdk.hpp"
#include "sevenzip_bridge/enc.h"
#include "decoder_cpu_budget.h"
#include "Common/ComTry.h"
#include "Windows/PropVariant.h"
#include "7zip/Common/RegisterArc.h"
#include "7zip/Common/StreamUtils.h"
#include <limits>
namespace NArchive { namespace NSunpackEnc {
Z7_CLASS_IMP_CHandler_IInArchive_0
    CMyComPtr<IInStream> stream;
    sup_enc_decoder *decoder = nullptr;
    UInt64 packed = 0;
    uint64_t unpacked = 0;
    bool wrong_password = false;
public:
    ~CHandler() { sup_enc_close(decoder); }
};
static const Byte kProps[] = {kpidSize, kpidPackSize, kpidEncrypted};
static const Byte kArcProps[] = {kpidEncrypted};
IMP_IInArchive_Props
IMP_IInArchive_ArcProps
Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *n)) { *n = 1; return S_OK; }
Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID id, PROPVARIANT *value)) {
    if (index != 0) return E_INVALIDARG;
    NWindows::NCOM::CPropVariant prop;
    if (id == kpidPackSize) prop = packed;
    if (id == kpidSize && decoder) prop = static_cast<UInt64>(unpacked);
    if (id == kpidEncrypted) prop = true;
    prop.Detach(value); return S_OK;
}
Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID id, PROPVARIANT *value)) {
    NWindows::NCOM::CPropVariant prop;
    if (id == kpidEncrypted) prop = true;
    prop.Detach(value); return S_OK;
}
struct Context {
    IInStream *input;
    ISequentialOutStream *output = nullptr;
    IArchiveExtractCallback *callback = nullptr;
    HRESULT error = S_OK;
    void *cpu_context = sunpack_cpu_current_job_context();
};
static uint32_t acquire_cpu(void *p, uint32_t wanted) {
    auto &c = *static_cast<Context *>(p);
    return c.cpu_context && wanted ? sunpack_cpu_acquire_extra_for_context(c.cpu_context, wanted, 1) : 0;
}
static void release_cpu(void *p, uint32_t count) {
    auto &c = *static_cast<Context *>(p);
    sunpack_cpu_release_extra_for_context(c.cpu_context, count);
}
static ptrdiff_t read(void *p, uint8_t *dst, size_t n) {
    auto &c = *static_cast<Context *>(p); UInt32 got = 0;
    c.error = c.input->Read(dst, static_cast<UInt32>(n), &got);
    return c.error == S_OK ? static_cast<ptrdiff_t>(got) : -1;
}
static int seek(void *p, uint64_t n) {
    auto &c = *static_cast<Context *>(p);
    if (n > static_cast<uint64_t>((std::numeric_limits<Int64>::max)())) return -1;
    c.error = c.input->Seek(static_cast<Int64>(n), STREAM_SEEK_SET, nullptr);
    return c.error == S_OK ? 0 : -1;
}
static int write(void *p, const uint8_t *src, size_t n) {
    auto &c = *static_cast<Context *>(p);
    c.error = c.output ? WriteStream(c.output, src, n) : S_OK;
    return c.error == S_OK ? 0 : -1;
}
static int progress(void *p, uint64_t n) {
    auto &c = *static_cast<Context *>(p); const UInt64 done = n;
    c.error = c.callback->SetCompleted(&done); return c.error == S_OK ? 0 : -1;
}
Z7_COM7F_IMF(CHandler::Open(IInStream *input, const UInt64 *, IArchiveOpenCallback *callback)) {
    COM_TRY_BEGIN
    Close();
    RINOK(input->Seek(0, STREAM_SEEK_END, &packed))
    CMyComPtr<ICryptoGetTextPassword> crypto;
    if (callback) callback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&crypto);
    if (!crypto) return E_NOTIMPL;
    BSTR password = nullptr;
    RINOK(crypto->CryptoGetTextPassword(&password))
    Context c{input};
    const int rc = sup_enc_open(&c, read, seek, packed,
        reinterpret_cast<const uint16_t *>(password), SysStringLen(password), &decoder, &unpacked);
    SysFreeString(password);
    if (c.error != S_OK) return c.error;
    if (rc == 5) return E_OUTOFMEMORY;
    if (rc != 0 && rc != 1) return S_FALSE;
    // Keep wrong-password classification in the existing operation-result path.
    // An ENC password proof never causes 7-Zip's signature-search retry.
    wrong_password = rc == 1; stream = input; return S_OK;
    COM_TRY_END
}
Z7_COM7F_IMF(CHandler::Close()) {
    sup_enc_close(decoder); decoder = nullptr; stream.Release();
    packed = 0; unpacked = 0; wrong_password = false; return S_OK;
}
Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 count, Int32 test, IArchiveExtractCallback *callback)) {
    COM_TRY_BEGIN
    if (!count) return S_OK;
    if (count != UInt32(-1) && (count != 1 || indices[0])) return E_INVALIDARG;
    RINOK(callback->SetTotal(packed))
    CMyComPtr<ISequentialOutStream> output;
    const Int32 ask = test ? NExtract::NAskMode::kTest : NExtract::NAskMode::kExtract;
    RINOK(callback->GetStream(0, &output, ask))
    RINOK(callback->PrepareOperation(ask))
    if (wrong_password) return callback->SetOperationResult(NExtract::NOperationResult::kWrongPassword);
    if (!decoder) return E_FAIL;
    if (test) return callback->SetOperationResult(NExtract::NOperationResult::kOK);
    if (!output) return S_OK;
    Context c{stream, output, callback};
    const int rc = sup_enc_decrypt(decoder, &c, read, seek, write, progress, acquire_cpu, release_cpu);
    output.Release();
    if (c.error != S_OK) return c.error;
    if (rc == 5) return E_OUTOFMEMORY;
    const Int32 op = rc == 0 ? NExtract::NOperationResult::kOK :
        rc == 2 ? NExtract::NOperationResult::kCRCError :
        rc == 8 ? NExtract::NOperationResult::kHeadersError :
        rc == 3 ? NExtract::NOperationResult::kUnexpectedEnd : NExtract::NOperationResult::kDataError;
    return callback->SetOperationResult(op);
    COM_TRY_END
}
static const Byte kSignature[] = {'S','S','E','F','E',4};
REGISTER_ARC_I("enc", "enc", "*", 0xFB, kSignature, 0, NArcInfoFlags::kKeepName, nullptr)
}}
