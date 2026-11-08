// Exercise the real request boundary, not just the allocator or DFS in
// isolation. Inject withdrawal at the cursor's first shared-domain allocation.
// No timing window, low-memory machine or production test hook is required.
#define main sunpack_worker_main
#include "../src/worker.cpp"
#undef main
#include <fstream>
#include <future>

using namespace sunpack::sevenzip;
namespace {
thread_local VolumeAttemptCursor* withdrawing_cursor = nullptr;
thread_local NativeMemoryJob* withdrawing_job = nullptr;
thread_local std::size_t withdrawing_domain = 0;
bool injected = false;
void require(bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(2); }
}
}

void* operator new(std::size_t size) {
    void* value = std::malloc(size ? size : 1);
    if (!value) throw std::bad_alloc();
    if (withdrawing_cursor && size == sizeof(std::size_t) &&
        withdrawing_cursor->shared_domains.empty() && withdrawing_cursor->domain_remaining.size() > withdrawing_domain &&
        withdrawing_cursor->domain_remaining[withdrawing_domain] == 2) {
        withdrawing_cursor = nullptr;
        injected = true;
        withdrawing_job->owner.retry(*withdrawing_job);
    }
    return value;
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }


void request_recovery(const std::filesystem::path& archive, bool after_failure, bool user_cancel) {
    NativeMemoryManager manager(0, [] { return 1LL << 30; });
    NativeMemoryJob job(manager);
    manager.begin(job);
    NativeMemoryScope memory(&job);
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "enumeration-withdrawal";
    request.dry_run = true;
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources.resize(3);
    for (auto& source : plan.sources) { source.path = archive.wstring(); source.has_end = true; }
    plan.sources[0].end = 40;
    plan.sources[1].start = 40; plan.sources[1].end = std::filesystem::file_size(archive);
    plan.sources[2].start = 40; plan.sources[2].end = 41; // Recognizably wrong first composition.
    plan.domains = {{2}, {0, 1}};
    if (after_failure) plan.layouts.push_back({{1, L"v1", 0}});
    plan.layouts.push_back({{1, L"v1", 1}, {2, L"v2", 1}});
    plan.prepare();
    injected = false;
    withdrawing_cursor = &replay.volumes;
    withdrawing_domain = 1;
    withdrawing_job = &job;
    std::ostringstream output;
    auto* previous = std::cout.rdbuf(output.rdbuf());
    auto code = run_request(request, nullptr, job.cancel);
    std::cout.rdbuf(previous);
    require(injected, "did not reach cursor enumeration");
    require(code == kMemoryRetry && output.str().find("\"type\":\"result\"") == std::string::npos,
            "withdrawal emitted a final cancellation");
    require(replay.volumes.attempts == (after_failure ? 1 : 0), "withdrawal counted an unfinished candidate");
    manager.end(job);
    std::atomic<bool> canceled{user_cancel};
    std::promise<bool> admission;
    auto ready = admission.get_future();
    manager.park(job, canceled, [&](bool resume) { admission.set_value(resume); });
    require(ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready, "parked cursor did not resume");
    require(ready.get() != user_cancel, "memory admission lost user cancellation");
    manager.begin(job);
    if (user_cancel) job.cancel->store(true); // Same persistent-token projection as the executor.
    output.str("");
    previous = std::cout.rdbuf(output.rdbuf());
    code = run_request(request, nullptr, job.cancel);
    std::cout.rdbuf(previous);
    if (user_cancel) {
        require(code == -101 && output.str().find("\"native_status\":\"cancelled\"") != std::string::npos,
                "user cancellation was mistaken for resource retry");
    } else {
        if (code != 0) std::cerr << output.str();
        require(code == 0 && replay.volumes.selected == std::vector<std::size_t>{0, 1}, "replay lost the valid composition");
        require(replay.volumes.attempts == (after_failure ? 2 : 1), "replay repeated a rejected composition");
    }
    const auto result = output.str().find("\"type\":\"result\"");
    require(result != std::string::npos && output.str().find("\"type\":\"result\"", result + 1) == std::string::npos,
            "request emitted more than one final result");
    manager.end(job);
}

int main() {
    // Tiny stored ZIP: ok.txt contains "cursor replay". Split through the
    // member's data so success requires both chosen ranges in the right order.
    static constexpr char zip[] =
        "\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x61\x87\x68\x5d\x0a\x67\x73\x71\x0d\x00\x00\x00\x0d\x00\x00\x00\x06\x00\x00\x00\x6f\x6b\x2e\x74\x78\x74\x63\x75\x72\x73\x6f\x72\x20\x72\x65\x70\x6c\x61\x79"
        "\x50\x4b\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x61\x87\x68\x5d\x0a\x67\x73\x71\x0d\x00\x00\x00\x0d\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x6f\x6b\x2e\x74\x78\x74"
        "\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x34\x00\x00\x00\x31\x00\x00\x00\x00\x00";
    const auto archive = std::filesystem::temp_directory_path() /
        (L"sunpack-volume-replay-" + std::to_wstring(GetCurrentProcessId()) + L".zip");
    { std::ofstream file(archive, std::ios::binary); file.write(zip, sizeof(zip) - 1); }
    for (bool after_failure : {false, true}) for (bool cancel : {false, true})
        request_recovery(archive, after_failure, cancel);
    std::filesystem::remove(archive);
    std::cout << "enumeration withdrawal, replay and user cancellation passed\n";
}
