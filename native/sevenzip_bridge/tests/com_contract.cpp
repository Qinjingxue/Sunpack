// QueryInterface contract for the bridge's callback and stream objects.
//
// These objects are handed to 7-Zip, which resolves interfaces by IID. The
// upstream Z7_COM_UNKNOWN_IMP_N macro only generates an entry for the IIDs it is
// given -- it does NOT walk the C++ base classes. So a parent interface such as
// IProgress must be listed explicitly, and this test is what keeps a future
// macro edit from silently dropping it again.

#include "internal/sevenzip_callbacks.hpp"
#include "internal/sevenzip_streams.hpp"

#include <cstdio>
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
        nullptr, L"", L"", std::vector<std::wstring>{},
        ExtractProgressCallback{}, true, &trace, 0);
    CMyComPtr<IArchiveExtractCallback> callback(raw);
    auto *probe = raw;

    check(queries_as(as_unknown(probe), IID_IUnknown), "QI(IUnknown) == S_OK");
    check(queries_as(as_unknown(probe), IID_IProgress), "QI(IProgress) == S_OK");
    check(queries_as(as_unknown(probe), IID_IArchiveExtractCallback), "QI(IArchiveExtractCallback) == S_OK");
    check(queries_as(as_unknown(probe), IID_ICryptoGetTextPassword), "QI(ICryptoGetTextPassword) == S_OK");
    check(rejects(as_unknown(probe), IID_IInStream), "QI(foreign IID) == E_NOINTERFACE");
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
    check(queries_as(as_unknown(file_raw), IID_IStreamSetReadPlan), "FileInStream QI(IStreamSetReadPlan) == S_OK");
    {
        CMyComPtr<IStreamSetReadPlan> plan;
        const HRESULT hr = as_unknown(file_raw)->QueryInterface(IID_IStreamSetReadPlan, (void **)&plan);
        check(hr == S_OK && plan && plan->SetReadPlanConsumer(0x100000001ULL) == S_OK,
              "FileInStream accepts planned consumer identity");
    }
    check(rejects(as_unknown(file_raw), IID_IProgress), "FileInStream QI(foreign IID) == E_NOINTERFACE");

    auto *multi_raw = new MultiRangeInStream(std::vector<ExtractInputRange>{});
    CMyComPtr<IInStream> multi(multi_raw);
    check(queries_as(as_unknown(multi_raw), IID_ISequentialInStream), "MultiRangeInStream QI(ISequentialInStream) == S_OK");
    check(queries_as(as_unknown(multi_raw), IID_IInStream), "MultiRangeInStream QI(IInStream) == S_OK");
    check(queries_as(as_unknown(multi_raw), IID_IStreamSetReadPlan), "MultiRangeInStream QI(IStreamSetReadPlan) == S_OK");
}

} // namespace

int main()
{
    check_extract_callback();
    check_extract_to_disk_callback();
    check_open_callback();
    check_open_callback_volume_prefetch();
    check_streams();
    check_open_archive_stream_ownership();

    if (g_failures != 0)
    {
        std::printf("\n%d QueryInterface contract check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("\nall QueryInterface contract checks passed\n");
    return 0;
}
