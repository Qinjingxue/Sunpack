// Execution adapter only. Archive structure and carrier boundaries belong to Rust.
#include "7zip/Archive/StdAfx.h"
#include "lz4_handler.hpp"
#include "sevenzip_paths.hpp"
#include "Common/ComTry.h"
#include "Windows/PropVariant.h"
#include "7zip/Common/RegisterArc.h"
#include "7zip/Common/StreamUtils.h"
#include "stream.h"
#include <algorithm>
#include <array>
#include <vector>

namespace NArchive { namespace NSunpackLz4 {
Z7_CLASS_IMP_CHandler_IInArchive_1(ISetProperties)
    CMyComPtr<IInStream> stream;
    sunpack::sevenzip::Lz4Options options;
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
            receipt.legacy_frames, static_cast<UInt64>(receipt.error), receipt.dictionary_id};
        if (id >= sunpack::sevenzip::kLz4ReceiptBase && id < sunpack::sevenzip::kLz4ReceiptBase + 9)
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
    if (v != 0x184d2204 && v != 0x184c2102 && (v & 0xfffffff0) != 0x184d2a50) return S_FALSE;
    RINOK(input->Seek(0, STREAM_SEEK_END, &packed))
    stream = input; return S_OK;
    COM_TRY_END
}
Z7_COM7F_IMF(CHandler::Close()) { stream.Release(); decoded = false; receipt = {}; packed = 0; return S_OK; }
Z7_COM7F_IMF(CHandler::SetProperties(const wchar_t * const *names, const PROPVARIANT *values, UInt32 count)) {
    COM_TRY_BEGIN
    options = {};
    for (UInt32 i = 0; i < count; ++i) {
        if (values[i].vt != VT_BSTR || !names[i] || names[i][0] != L'd') return E_INVALIDARG;
        if (!names[i][1]) options.default_dictionary = values[i].bstrVal;
        else {
            wchar_t *end = nullptr;
            const auto id = std::wcstoull(names[i] + 1, &end, 10);
            if (!end || *end || id > 0xffffffffULL) return E_INVALIDARG;
            options.dictionaries.emplace_back(static_cast<unsigned int>(id), values[i].bstrVal);
        }
    }
    std::sort(options.dictionaries.begin(), options.dictionaries.end(),
        [](const auto &left, const auto &right) { return left.first < right.first; });
    return S_OK;
    COM_TRY_END
}
struct Context {
    IInStream *input;
    ISequentialOutStream *output;
    IArchiveExtractCallback *progress;
    const sunpack::sevenzip::Lz4Options *options;
    HRESULT error = S_OK;
    std::vector<Byte> dictionary;
    UInt64 packed;
    const std::wstring *dictionary_path = nullptr;
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
static int dictionary(void *p, uint32_t id, int has_id, const void **data, size_t *size) {
    auto &c = *static_cast<Context *>(p);
    const std::wstring *path = &c.options->default_dictionary;
    if (has_id) {
        auto it = std::lower_bound(c.options->dictionaries.begin(), c.options->dictionaries.end(), id,
            [](const auto &entry, auto value) { return entry.first < value; });
        if (it != c.options->dictionaries.end() && it->first == id) path = &it->second;
        else return 0;
    }
    if (path->empty()) return 0;
    if (c.dictionary_path == path) { *data=c.dictionary.data(); *size=c.dictionary.size(); return 1; }
    HANDLE file = CreateFileW(sunpack::sevenzip::win32_extended_path(*path).c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) { c.error = HRESULT_FROM_WIN32(GetLastError()); return -1; }
    LARGE_INTEGER length{};
    bool ok = GetFileSizeEx(file, &length) && length.QuadPart >= 0;
    const auto tail = static_cast<DWORD>((std::min)(length.QuadPart, LONGLONG{65536}));
    if (ok) { LARGE_INTEGER start{}; start.QuadPart = length.QuadPart - tail;
        ok = SetFilePointerEx(file, start, nullptr, FILE_BEGIN) != FALSE; }
    try { c.dictionary.resize(tail); } catch (const std::bad_alloc &) { CloseHandle(file); c.error=E_OUTOFMEMORY; return -1; }
    DWORD got = 0;
    if (ok && tail) ok = ReadFile(file, c.dictionary.data(), tail, &got, nullptr) && got == tail;
    if (!ok) c.error = HRESULT_FROM_WIN32(GetLastError());
    CloseHandle(file);
    if (!ok) return -1;
    c.dictionary_path = path;
    *data = c.dictionary.data(); *size = c.dictionary.size(); return 1;
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
    Context c{stream, output, callback, &options, S_OK, {}, packed};
    const int rc = sup_lz4_decode(&c, read, skip, write, dictionary, progress, &receipt);
    decoded = true;
    output.Release();
    if (c.error != S_OK) return c.error;
    if (rc == SUP_LZ4_MEMORY) return E_OUTOFMEMORY;
    const Int32 op = rc == SUP_LZ4_OK ? NExtract::NOperationResult::kOK :
        rc == SUP_LZ4_CHECKSUM ? NExtract::NOperationResult::kCRCError :
        rc == SUP_LZ4_TRUNCATED ? NExtract::NOperationResult::kUnexpectedEnd :
        rc == SUP_LZ4_DICTIONARY ? NExtract::NOperationResult::kUnsupportedMethod : NExtract::NOperationResult::kDataError;
    return callback->SetOperationResult(op);
    COM_TRY_END
}
static const Byte k_Signature[] = {4, 0x22, 0x4d, 0x18};
REGISTER_ARC_I("lz4", "lz4", "*", 0xFA, k_Signature, 0, NArcInfoFlags::kKeepName, nullptr)
}}

namespace sunpack::sevenzip {
HRESULT configure_lz4(IInArchive *archive, const Lz4Options &options) {
    if (options.default_dictionary.empty() && options.dictionaries.empty()) return S_OK;
    CMyComPtr<ISetProperties> setter;
    RINOK(archive->QueryInterface(IID_ISetProperties, reinterpret_cast<void **>(&setter)))
    std::vector<std::wstring> owned_names;
    std::vector<NWindows::NCOM::CPropVariant> values;
    if (!options.default_dictionary.empty()) { owned_names.push_back(L"d"); values.emplace_back(options.default_dictionary.c_str()); }
    for (const auto &entry : options.dictionaries) {
        owned_names.push_back(L"d" + std::to_wstring(entry.first)); values.emplace_back(entry.second.c_str());
    }
    std::vector<const wchar_t *> names; std::vector<PROPVARIANT> props;
    for (size_t i = 0; i < values.size(); ++i) { names.push_back(owned_names[i].c_str()); props.push_back(values[i]); }
    return setter->SetProperties(names.data(), props.data(), static_cast<UInt32>(props.size()));
}
void read_lz4_receipt(IInArchive *archive, ExtractArchiveResult &result) {
    UInt64 fields[9]{};
    for (unsigned int i = 0; i != 9; ++i) {
        NWindows::NCOM::CPropVariant prop;
        if (archive->GetArchiveProperty(kLz4ReceiptBase + i, &prop) != S_OK || prop.vt != VT_UI8) return;
        fields[i] = prop.uhVal.QuadPart;
    }
    result.has_stream_receipt = true;
    result.stream_receipt = {fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
        static_cast<unsigned int>(fields[7]), static_cast<unsigned int>(fields[8])};
    for (auto &item : result.output_trace.items) item.crc_verified = false;
}
}
