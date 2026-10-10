// QueryInterface contract for the bridge's callback and stream objects.
//
// These objects are handed to 7-Zip, which resolves interfaces by IID. The
// upstream Z7_COM_UNKNOWN_IMP_N macro only generates an entry for the IIDs it is
// given -- it does NOT walk the C++ base classes. So a parent interface such as
// IProgress must be listed explicitly, and this test is what keeps a future
// macro edit from silently dropping it again.

#include "internal/sevenzip_callbacks.hpp"
#include "internal/sevenzip_streams.hpp"
#include "../7z2604-src/C/7zCrc.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace sunpack::sevenzip;

namespace {

int g_failures = 0;

void check(bool condition, const char *what)
{
    if (condition)
    {
        std::printf("  ok   %s\n", what);
        return;
    }
    std::printf("  FAIL %s\n", what);
    ++g_failures;
}

// The generated QueryInterface/AddRef/Release are private (the macro opens with
// `private:`), so the contract is exercised through IUnknown -- which is exactly
// how a 7-Zip handler reaches it anyway.
bool queries_as(IUnknown *object, REFIID iid)
{
    void *out = nullptr;
    const HRESULT hr = object->QueryInterface(iid, &out);
    const bool ok = (hr == S_OK && out != nullptr);
    if (ok)
    {
        // QueryInterface must have handed back an owned reference.
        static_cast<IUnknown *>(out)->Release();
    }
    return ok;
}

// A callback must not answer for an unrelated interface.
bool rejects(IUnknown *object, REFIID iid)
{
    void *out = nullptr;
    const HRESULT hr = object->QueryInterface(iid, &out);
    return hr == E_NOINTERFACE && out == nullptr;
}

IUnknown *as_unknown(IArchiveExtractCallback *callback) { return static_cast<IUnknown *>(callback); }
IUnknown *as_unknown(IArchiveOpenCallback *callback) { return static_cast<IUnknown *>(callback); }
IUnknown *as_unknown(IInStream *stream) { return static_cast<IUnknown *>(stream); }

void check_extract_callback()
{
    std::printf("ExtractCallback\n");
    auto *raw = new ExtractCallback(L"");
    CMyComPtr<IArchiveExtractCallback> callback(raw);
    auto *probe = raw;

    check(queries_as(as_unknown(probe), IID_IUnknown), "QI(IUnknown) == S_OK");
    check(queries_as(as_unknown(probe), IID_IProgress), "QI(IProgress) == S_OK");
    check(queries_as(as_unknown(probe), IID_IArchiveExtractCallback), "QI(IArchiveExtractCallback) == S_OK");
    check(queries_as(as_unknown(probe), IID_ICryptoGetTextPassword), "QI(ICryptoGetTextPassword) == S_OK");
    check(rejects(as_unknown(probe), IID_IInStream), "QI(foreign IID) == E_NOINTERFACE");

    // The IProgress pointer must be usable as the base of the callback.
    IProgress *progress = nullptr;
    if (as_unknown(probe)->QueryInterface(IID_IProgress, reinterpret_cast<void **>(&progress)) == S_OK && progress)
    {
        check(progress->SetTotal(0) == S_OK, "IProgress::SetTotal callable through the QI result");
        progress->Release();
    }
    else
    {
        check(false, "IProgress usable through the QI result");
    }
}

void check_extract_to_disk_callback()
{
    std::printf("ExtractToDiskCallback\n");
    ExtractOutputTrace trace;
    auto *raw = new ExtractToDiskCallback(
        nullptr, L"", L"",
        ExtractProgressCallback{}, true, &trace, 0);
    CMyComPtr<IArchiveExtractCallback> callback(raw);
    auto *probe = raw;

    check(queries_as(as_unknown(probe), IID_IUnknown), "QI(IUnknown) == S_OK");
    check(queries_as(as_unknown(probe), IID_IProgress), "QI(IProgress) == S_OK");
    check(queries_as(as_unknown(probe), IID_IArchiveExtractCallback), "QI(IArchiveExtractCallback) == S_OK");
    check(queries_as(as_unknown(probe), IID_ICryptoGetTextPassword), "QI(ICryptoGetTextPassword) == S_OK");
    check(rejects(as_unknown(probe), IID_IInStream), "QI(foreign IID) == E_NOINTERFACE");
}

// Supply raw item properties so handler name rewriting cannot mask callback
// path validation, particularly Windows backslash and drive-root cases.
class EntryArchive final : public CMyUnknownImp, public IInArchive
{
    Z7_COM_UNKNOWN_IMP_1(IInArchive)
public:
    EntryArchive(const wchar_t *name, bool is_dir) : name_(name), is_dir_(is_dir) {}
    HRESULT STDMETHODCALLTYPE GetProperty(UInt32, PROPID prop, PROPVARIANT *value) SUP7Z_NOEXCEPT override
    {
        PropVariantInit(value);
        if (prop == kpidPath)
        {
            value->bstrVal = SysAllocString(name_.c_str());
            if (!value->bstrVal) { return E_OUTOFMEMORY; }
            value->vt = VT_BSTR;
        }
        else if (prop == kpidIsDir)
        {
            value->vt = VT_BOOL;
            value->boolVal = is_dir_ ? VARIANT_TRUE : VARIANT_FALSE;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Open(IInStream *, const UInt64 *, IArchiveOpenCallback *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Close() SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNumberOfItems(UInt32 *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Extract(const UInt32 *, UInt32, Int32, IArchiveExtractCallback *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetArchiveProperty(PROPID, PROPVARIANT *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNumberOfProperties(UInt32 *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyInfo(UInt32, BSTR *, PROPID *, VARTYPE *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNumberOfArchiveProperties(UInt32 *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetArchivePropertyInfo(UInt32, BSTR *, PROPID *, VARTYPE *) SUP7Z_NOEXCEPT override { return E_NOTIMPL; }
private:
    const std::wstring name_;
    const bool is_dir_;
};

void check_archive_root_directory_entries()
{
    std::printf("Archive root directory entries\n");
    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-root-entry-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(root);
    struct EntryCase {
        const wchar_t *name;
        bool is_dir;
        bool accepted;
    };
    const EntryCase cases[] = {
        {L".", true, true}, {L"./", true, true}, {L".\\", true, true},
        {L".", false, false}, {L"./", false, false}, {L".\\", false, false},
        {L"../", true, false}, {L"../x", false, false},
        {L"../../foo", true, false}, {L"C:\\", true, false},
        {L"\\foo", true, false}, {L"/foo", true, false},
    };
    unsigned index = 0;
    for (const auto &entry : cases)
    {
        std::printf("  %s %ls\n", entry.is_dir ? "directory" : "file", entry.name);
        CMyComPtr<IInArchive> archive(new EntryArchive(entry.name, entry.is_dir));
        ++index;
        for (const bool dry_run : {false, true})
        {
            const auto output = root / (std::to_wstring(index) + (dry_run ? L"-dry" : L"-disk"));
            std::vector<std::string> events;
            ExtractOutputTrace trace;
            auto *raw = new ExtractToDiskCallback(
                archive.Interface(), L"", output.wstring(),
                [&events](const ExtractProgressEvent &event) { events.push_back(event.event); }, dry_run, &trace, 1);
            CMyComPtr<IArchiveExtractCallback> callback(raw);
            CMyComPtr<ISequentialOutStream> stream;
            const HRESULT hr = callback->GetStream(0, &stream, kExtractMode);
            check(!stream && trace.items.size() == 1, "callback records the member without an output stream");
            if (entry.accepted)
            {
                check(hr == S_OK && callback->SetOperationResult(kOpOk) == S_OK,
                      "root directory entry succeeds as a no-op");
                check(raw->dirs_written() == 1 && raw->files_written() == 0 && raw->bytes_written() == 0 &&
                      !raw->output_error() && raw->failed_item().empty(),
                      "root directory entry only increments the directory count");
                check(!std::filesystem::exists(output) || std::filesystem::is_empty(output),
                      "root directory entry creates no child output");
                check(events == std::vector<std::string>{"item_start", "item_done"},
                      "root directory entry reports start and completion");
                if (trace.items.size() == 1)
                {
                    const auto &item = trace.items.front();
                    check(item.is_dir && item.done && !item.failed && item.output_path.empty(),
                          "root directory trace completes without an output path");
                }
            }
            else
            {
                check(hr == E_INVALIDARG && raw->output_error() && raw->failed_item() == entry.name &&
                      raw->dirs_written() == 0 && raw->files_written() == 0,
                      "unsafe output path is rejected");
                check(trace.items.size() == 1 && trace.items.front().failed &&
                      trace.items.front().hresult == E_INVALIDARG,
                      "unsafe output path retains its failure trace");
            }
        }
    }
    std::filesystem::remove_all(root);
}

void check_open_callback()
{
    std::printf("OpenCallback\n");
    auto *raw = new OpenCallback(L"", L"", std::vector<std::wstring>{});
    CMyComPtr<IArchiveOpenCallback> callback(raw);
    auto *probe = raw;

    check(queries_as(as_unknown(probe), IID_IUnknown), "QI(IUnknown) == S_OK");
    check(queries_as(as_unknown(probe), IID_IArchiveOpenCallback), "QI(IArchiveOpenCallback) == S_OK");
    check(queries_as(as_unknown(probe), IID_IArchiveOpenVolumeCallback), "QI(IArchiveOpenVolumeCallback) == S_OK");
    check(queries_as(as_unknown(probe), IID_ICryptoGetTextPassword), "QI(ICryptoGetTextPassword) == S_OK");
    check(rejects(as_unknown(probe), IID_IProgress), "QI(foreign IID) == E_NOINTERFACE");
}

void check_open_callback_volume_prefetch()
{
    std::printf("OpenCallback volume prefetch\n");

    wchar_t executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    check(length != 0 && length < MAX_PATH, "test executable path is available");
    if (length == 0 || length >= MAX_PATH)
    {
        return;
    }

    const std::wstring path(executable, length);
    const std::wstring name = std::filesystem::path(path).filename().wstring();
    InputPrefetchConfig prefetch;
    prefetch.enabled = false;

    auto *raw = new OpenCallback(
        L"", path, std::vector<std::wstring>{path}, std::vector<std::wstring>{}, prefetch);
    CMyComPtr<IArchiveOpenCallback> callback(raw);

    CMyComPtr<IInStream> stream;
    const HRESULT hr = raw->GetStream(name.c_str(), &stream);
    check(hr == S_OK && stream, "volume callback opens configured stream");
    if (hr == S_OK && stream)
    {
        auto *file = static_cast<FileInStream *>(stream.Interface());
        check(!file->prefetch_enabled(), "volume callback preserves disabled prefetch policy");
    }
}

void check_open_archive_stream_ownership()
{
    std::printf("open_archive_stream ownership\n");

    bool opened = false;
    CMyComPtr<IInStream> stream = open_archive_stream(
        L"", std::vector<std::wstring>{}, opened);

    IUnknown *unknown = as_unknown(stream.Interface());
    const ULONG after_add_ref = unknown->AddRef();
    const ULONG after_release = unknown->Release();

    check(after_add_ref == 2 && after_release == 1,
          "open_archive_stream returns exactly one owned COM reference");
}

void check_streams()
{
    std::printf("Streams\n");
    auto *file_raw = new FileInStream(L"");
    CMyComPtr<IInStream> file(file_raw);
    check(queries_as(as_unknown(file_raw), IID_IUnknown), "FileInStream QI(IUnknown) == S_OK");
    check(queries_as(as_unknown(file_raw), IID_ISequentialInStream), "FileInStream QI(ISequentialInStream) == S_OK");
    check(queries_as(as_unknown(file_raw), IID_IInStream), "FileInStream QI(IInStream) == S_OK");
    check(rejects(as_unknown(file_raw), IID_IProgress), "FileInStream QI(foreign IID) == E_NOINTERFACE");

    auto *multi_raw = new MultiRangeInStream(std::vector<ExtractInputRange>{});
    CMyComPtr<IInStream> multi(multi_raw);
    check(queries_as(as_unknown(multi_raw), IID_ISequentialInStream), "MultiRangeInStream QI(ISequentialInStream) == S_OK");
    check(queries_as(as_unknown(multi_raw), IID_IInStream), "MultiRangeInStream QI(IInStream) == S_OK");
}

void check_crc32_incremental_contract()
{
    check(CrcCalc("123456789", 9) == 0xCBF43926u, "CRC32 IEEE known vector");
    check(CrcUpdate(0x13579BDFu, nullptr, 0) == 0x13579BDFu, "empty CRC preserves arbitrary incremental state");
    std::vector<unsigned char> data(131072 + 64);
    UInt32 random = 0x9E3779B9u;
    for (auto &byte : data)
    {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        byte = static_cast<unsigned char>(random);
    }
    bool correct = true;
    for (unsigned alignment : {0u, 1u, 3u, 15u, 31u})
    for (unsigned length : {0u, 1u, 7u, 15u, 16u, 31u, 32u, 63u, 64u, 511u, 4096u, 65536u, 131072u})
    for (UInt32 initial : {0u, 0xFFFFFFFFu, 0x13579BDFu})
    {
        UInt32 expected = initial;
        for (unsigned i = 0; i < length; ++i)
        {
            expected ^= data[alignment + i];
            for (unsigned bit = 0; bit < 8; ++bit)
                expected = (expected >> 1) ^ (0xEDB88320u & (0u - (expected & 1)));
        }
        correct &= CrcUpdate(initial, data.data() + alignment, length) == expected;
        UInt32 incremental = initial;
        for (unsigned offset = 0; offset < length; offset += 43)
            incremental = CrcUpdate(incremental, data.data() + alignment + offset, (std::min)(43u, length - offset));
        correct &= incremental == expected;
        const auto update = z7_GetFunc_CrcUpdate(0);
        correct &= update && update(initial, data.data() + alignment, length) == expected;
    }
    check(correct, "CRC32 matches independent bitwise oracle for alignment, arbitrary seeds and chunk boundaries");
}

void check_archive_open_start_and_carrier_fallback()
{
    // A valid empty RAR4 with a large carrier tail: the RAR5 candidate must
    // fail at the logical start instead of scanning that tail first.
    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-open-contract-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    std::vector<unsigned char> rar = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};
    for (unsigned type : {0x73u, 0x7bu}) {
        std::vector<unsigned char> header(type == 0x73 ? 13 : 7, 0);
        header[2] = static_cast<unsigned char>(type);
        header[5] = static_cast<unsigned char>(header.size());
        const UInt32 crc = CrcCalc(header.data() + 2, header.size() - 2);
        header[0] = static_cast<unsigned char>(crc);
        header[1] = static_cast<unsigned char>(crc >> 8);
        rar.insert(rar.end(), header.begin(), header.end());
    }
    const std::vector<char> tail(4u << 20, 'x');
    const char *prefetch_env = std::getenv("SUNPACK_SEVENZIP_PREFETCH");
    const std::string previous_prefetch = prefetch_env ? prefetch_env : "";
    _putenv_s("SUNPACK_SEVENZIP_PREFETCH", "0");
    for (unsigned prefix : {0u, 103u}) {
        const auto path = root / (prefix ? L"carrier.payload" : L"disguised.payload");
        {
            std::ofstream output(path, std::ios::binary);
            const std::string padding(prefix, 'p');
            output.write(padding.data(), padding.size());
            output.write(reinterpret_cast<const char *>(rar.data()), rar.size());
            output.write(tail.data(), tail.size());
        }
        const auto result = extract_archive_with_parts(path.wstring(), {path.wstring()}, L"rar", L"", root.wstring(), L"", {}, true);
        check(result.status == PasswordTestStatus::Ok, "RAR4 opens with a generic family hint, including carrier prefix fallback");
        if (!prefix) {
            check(result.handler_attempts.size() == 2 && result.handler_attempts.back().opened,
                  "generic RAR reaches RAR4 on the initial handler pass");
            check(result.input_trace.total_bytes_returned < (512u << 10),
                  "wrong RAR handler does not consume the large carrier tail");
        } else {
            check(result.handler_attempts.size() == 4 && result.handler_attempts.back().opened,
                  "carrier prefix uses the existing signature search after the start-only pass");
            const std::vector<ExtractInputRange> ranges = {{path.wstring(), prefix, prefix + rar.size(), true}};
            const auto carved = extract_archive_with_ranges(path.wstring(), ranges, L"rar", L"", root.wstring(), L"", {}, true);
            check(carved.status == PasswordTestStatus::Ok && carved.handler_attempts.size() == 2,
                  "canonical carrier range opens without searching the underlying prefix");
        }
    }
    _putenv_s("SUNPACK_SEVENZIP_PREFETCH", previous_prefetch.c_str());
    std::filesystem::remove_all(root);
}

void check_prefetch_lifetime_and_seek()
{
    std::printf("Prefetch seek\n");
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false, release = false;
    SequentialPrefetcher prefetch({true, 64, 2}, 1024,
        [&](UInt64 offset, void *data, UInt32 size, UInt32 *read) {
            if (offset == 1)
            {
                std::unique_lock lock(mutex);
                entered = true;
                cv.notify_one();
                cv.wait(lock, [&] { return release; });
            }
            std::memset(data, static_cast<int>(offset % 251), size);
            *read = size;
            return S_OK;
        });
    prefetch.after_sync_read(1);
    {
        std::unique_lock lock(mutex);
        cv.wait(lock, [&] { return entered; });
    }
    prefetch.invalidate(400, nullptr);
    prefetch.after_sync_read(400);
    {
        std::lock_guard lock(mutex);
        release = true;
    }
    cv.notify_one();
    unsigned char bytes[64]{};
    check(prefetch.consume(400, bytes, 64, nullptr) && bytes[0] == 400 % 251 && bytes[63] == 400 % 251,
          "seek during a blocked read discards its completion without reusing its live buffer");

    SequentialPrefetcher failed({true, 64, 1}, 256,
        [](UInt64, void *, UInt32, UInt32 *read) { *read = 0; return S_FALSE; });
    failed.after_sync_read(64);
    check(!failed.consume(64, bytes, 64, nullptr), "short/error prefetch reads fall back without publishing bytes");

    wchar_t executable[MAX_PATH]{};
    GetModuleFileNameW(nullptr, executable, MAX_PATH);
    auto *raw = new FileInStream(executable, nullptr, L"file", {true, 64, 2});
    CMyComPtr<IInStream> stream(raw);
    UInt32 read = 0;
    check(stream->Read(bytes, 64, &read) == S_OK && read == 64, "file stream starts with direct read");
    check(stream->Read(bytes, 64, &read) == S_OK && read == 64, "file stream reads the prefetched next window");
    UInt64 position = 0;
    check(stream->Seek(0, FILE_CURRENT, &position) == S_OK && position == 128,
          "relative Seek uses logical cursor after cached reads");
    check(stream->Seek(-65, FILE_CURRENT, &position) == S_OK && position == 63,
          "backward relative Seek recalibrates the decoder handle");
    unsigned char expected[65]{};
    InputPrefetchConfig disabled{false, 64, 2};
    auto *direct_raw = new FileInStream(executable, nullptr, L"file", disabled);
    CMyComPtr<IInStream> direct(direct_raw);
    direct->Read(expected, 65, &read);
    check(stream->Read(bytes, 1, &read) == S_OK && read == 1 && bytes[0] == expected[63],
          "fallback after seek reads from the logical file offset");
}

void check_prefetch_virtual_inputs()
{
    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-prefetch-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    const auto first = root / L"disguised-a.bin";
    const auto second = root / L"disguised-b.bin";
    unsigned char payload[513];
    for (unsigned i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<unsigned char>(i % 251);
    {
        std::ofstream a(first, std::ios::binary), b(second, std::ios::binary);
        a.write(reinterpret_cast<const char *>(payload), 257);
        b.write(reinterpret_cast<const char *>(payload + 257), 256);
    }
    {
        auto *raw = new MultiFileInStream({first.wstring(), second.wstring()}, nullptr, {true, 64, 2});
        CMyComPtr<IInStream> stream(raw);
        unsigned char bytes[513]{};
        bool correct = true;
        UInt32 read = 0;
        for (unsigned offset = 0; offset < sizeof(bytes); offset += 17)
        {
            const UInt32 size = (std::min)(17u, static_cast<unsigned>(sizeof(bytes) - offset));
            correct &= stream->Read(bytes + offset, size, &read) == S_OK && read == size;
        }
        check(correct && !std::memcmp(bytes, payload, sizeof(bytes)),
              "prefetch and direct fallback preserve bytes across unaligned volume/window boundaries");
        UInt64 position = 0;
        stream->Seek(-33, FILE_END, &position);
        correct = position == 480 && stream->Read(bytes, 33, &read) == S_OK && read == 33;
        check(correct && !std::memcmp(bytes, payload + 480, 33), "volume seek discards prior prefetched windows");
    }
    {
        // Same physical inputs represent an embedded payload whose prefix and
        // tail must not leak into the decoder's virtual stream.
        ExtractInputRange a, b;
        a.path = first.wstring(); a.start = 3; a.has_end = true; a.end = 251;
        b.path = second.wstring(); b.start = 7; b.has_end = true; b.end = 250;
        auto *raw = new MultiRangeInStream({a, b}, nullptr, {true, 64, 2});
        CMyComPtr<IInStream> stream(raw);
        unsigned char bytes[491]{};
        bool correct = true;
        UInt32 read = 0;
        for (unsigned offset = 0; offset < sizeof(bytes); offset += 17)
        {
            const UInt32 size = (std::min)(17u, static_cast<unsigned>(sizeof(bytes) - offset));
            correct &= stream->Read(bytes + offset, size, &read) == S_OK && read == size;
        }
        check(correct && !std::memcmp(bytes, payload + 3, 248) && !std::memcmp(bytes + 248, payload + 264, 243),
              "range prefetch respects embedded payload offsets and clipped range ends");
    }
    std::filesystem::remove_all(root);
}

void check_output_path_reservations()
{
    std::printf("Async output path reservations\n");
    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-reserved-paths-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    OutputPathAllocator paths;
    const auto original = root / L"entry.txt";
    check(paths.allocate(original, true) == original, "first output keeps original name");
    check(paths.allocate(root / L"ENTRY.txt", true) == root / L"ENTRY(1).txt", "pending case-insensitive collision advances without a disk file");
    check(paths.allocate(root / L"entry(1).txt", true) == root / L"entry(1)(1).txt", "explicit names cannot take a pending numbered output");
    check(paths.allocate(original, true) == root / L"entry(2).txt", "numbered reservations advance monotonically");

    OutputPathAllocator failed_paths;
    const auto invalid = root / (std::wstring(260, L'a') + L".txt");
    check(failed_paths.allocate(invalid, true) == invalid, "reserve a name whose async create will fail");
    check(failed_paths.allocate(invalid, true) == root / (std::wstring(260, L'a') + L"(1).txt"), "failed create cannot spin on the same name");

    OutputPathAllocator many;
    many.reserve(10001);
    many.allocate(original, true);
    std::filesystem::path last;
    for (int index = 0; index < 10000; ++index) { last = many.allocate(original, true); }
    check(last == root / L"entry(10000).txt", "large duplicate group advances without rescanning prior reservations");
    many.clear();
    check(many.allocate(original, true) == original, "released reservations do not survive the output lifetime");
}

} // namespace

int main()
{
    check_extract_callback();
    check_extract_to_disk_callback();
    check_archive_root_directory_entries();
    check_open_callback();
    check_open_callback_volume_prefetch();
    check_streams();
    check_crc32_incremental_contract();
    check_archive_open_start_and_carrier_fallback();
    check_prefetch_lifetime_and_seek();
    check_prefetch_virtual_inputs();
    check_open_archive_stream_ownership();
    check_output_path_reservations();

    if (g_failures != 0)
    {
        std::printf("\n%d QueryInterface contract check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("\nall QueryInterface contract checks passed\n");
    return 0;
}
