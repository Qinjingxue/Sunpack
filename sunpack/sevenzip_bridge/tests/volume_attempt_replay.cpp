// Exercise the real request boundary, not just the allocator or DFS in
// isolation. Inject withdrawal at the cursor's first shared-domain allocation.
// No timing window, low-memory machine or production test hook is required.
#define main sunpack_worker_main
#include "../src/worker.cpp"
#undef main
#include <fstream>
#include <future>
#include <sstream>

using namespace sunpack::sevenzip;
namespace {
thread_local VolumeAttemptCursor* withdrawing_cursor = nullptr;
thread_local NativeMemoryJob* withdrawing_job = nullptr;
thread_local std::size_t withdrawing_domain = 0;
bool injected = false;
void require(bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(2); }
}

void check_final_results(const std::ostringstream& output, unsigned expected_count, std::string_view expected_status = {}) {
    std::istringstream frames(output.str());
    wire::RequestReader reader(frames);
    unsigned count = 0;
    while (reader.start()) {
        std::string type, status;
        read_object(reader, [&](auto key) {
            if (key == "type") type = reader.text();
            else if (key == "native_status") status = reader.text();
            else reader.skip();
        });
        reader.finish();
        if (type != "result") continue;
        ++count;
        if (!expected_status.empty()) {
            require(status == expected_status, "request emitted an unexpected final status");
        }
    }
    require(count == expected_count, "request emitted an unexpected number of final results");
}

void check_chunked_request(const std::filesystem::path& archive) {
    const auto path = wide_to_utf8(archive.wstring());
    auto slot = [](unsigned number, const char* name) {
        return wire::object() + wire::key("number") + wire::number(number) +
            wire::key("domain") + wire::number(0) + wire::key("canonical_name") + wire::text(name) + wire::end();
    };
    auto extent = [&](std::uint64_t start, std::uint64_t end) {
        return wire::object() + wire::key("path") + wire::text(path) +
            wire::key("start") + wire::number(start) + wire::key("end") + wire::number(end) + wire::end();
    };
    const auto body = wire::object() + wire::key("job_id") + wire::text("chunked") +
        wire::key("archive_input") + wire::object() +
        wire::key("entry_path") + wire::text(path) +
        wire::key("open_mode") + wire::text("native_volumes") +
        wire::key("format_hint") + wire::text("zip") +
        wire::key("volume_attempts") + wire::object() +
        wire::key("sources") + wire::array() + extent(0, 40) + extent(40, std::filesystem::file_size(archive)) + wire::end() +
        wire::key("layouts") + wire::array() + wire::object() +
        wire::key("slots") + wire::array() + slot(1, "one") + slot(2, "two") + wire::end() +
        wire::key("minimum_slots") + wire::number(2) + wire::end() + wire::end() +
        wire::key("domains") + wire::array() + wire::object() +
        wire::key("choices") + wire::array() + wire::number(0) + wire::number(1) + wire::end() +
        wire::end() + wire::end() +
        wire::key("tail_totals") + wire::array() + wire::object() + wire::key("source") + wire::number(1) +
        wire::key("total") + wire::number(UINT64_C(0x123456789)) + wire::end() + wire::end() +
        wire::end() + wire::end() +
        wire::key("password_candidates") + wire::array() + wire::text("\xe8\xb7\xaf") + wire::end() + wire::end();
    std::string frames;
    auto fragment = [&](std::string_view bytes, bool more) {
        frames += "SPBF";
        wire::little(frames, bytes.size() | (more ? wire::kMore : 0), 4);
        frames += bytes;
    };
    const std::string_view payload(body);
    fragment(payload.substr(0, payload.size() / 2), true);
    fragment({}, false);
    // Small fragments force numeric fields, strings and collection records
    // to cross boundaries in a real request, with no huge test fixture.
    for (std::size_t offset = 0; offset < payload.size(); offset += 3) {
        fragment(payload.substr(offset, 3), offset + 3 < payload.size());
    }
    fragment(wire::object() + wire::key("worker_command") + wire::text("shutdown") + wire::end(), false);

    std::istringstream input(std::move(frames));
    wire::RequestReader reader(input);
    require(reader.start(), "missing cancelled request");
    bool abandoned = false;
    try { parse_worker_request(reader); } catch (const wire::AbandonedRequest&) { abandoned = true; }
    require(abandoned, "partial request was admitted");
    require(reader.start(), "cancelled request consumed the following transaction");
    const auto request = parse_worker_request(reader);
    const auto& plan = request.archive_input.volume_attempts;
    require(request.job_id == "chunked" && request.archive_input.validation_error.empty() &&
            request.archive_input.archive_path == archive.wstring() && plan.sources.size() == 2 &&
            plan.sources[1].start == 40 && plan.layouts.size() == 1 && plan.layouts[0][1].name == L"two" &&
            plan.domains == std::vector<std::vector<std::size_t>>{{0, 1}} &&
            plan.minimum_slots[0] == 2 && plan.tail_totals[1] == UINT64_C(0x123456789) &&
            request.password_candidates == std::vector<std::wstring>{L"\u8def"},
            "chunk boundary corrupted the request");
    require(reader.start() && parse_worker_request(reader).worker_command == "shutdown" && !reader.start(),
        "chunked request consumed the following control frame");
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


void request_recovery(const std::filesystem::path& archive, const std::filesystem::path& destination,
                      bool after_failure, bool user_cancel) {
    NativeMemoryManager manager(0, [] { return 1LL << 30; });
    NativeMemoryJob job(manager);
    manager.begin(job);
    NativeMemoryScope memory(&job);
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "enumeration-withdrawal";
    request.output_dir = destination.wstring();
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
    injected = false;
    withdrawing_cursor = &replay.volumes;
    withdrawing_domain = 1;
    withdrawing_job = &job;
    std::ostringstream output;
    auto* previous = std::cout.rdbuf(output.rdbuf());
    auto outcome = run_request(request, nullptr, job.cancel);
    std::cout.rdbuf(previous);
    require(injected, "did not reach cursor enumeration");
    require(outcome.code == kMemoryRetry && outcome.response.empty(), "withdrawal did not request a retry");
    check_final_results(output, 0);
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
    outcome = run_request(request, nullptr, job.cancel);
    std::cout.rdbuf(previous);
    if (user_cancel) {
        require(outcome.code == -101, "user cancellation was mistaken for resource retry");
    } else {
        require(outcome.code == 0 && replay.volumes.selected == std::vector<std::size_t>{0, 1}, "replay lost the valid composition");
        require(replay.volumes.attempts == (after_failure ? 2 : 1), "replay repeated a rejected composition");
        require(replay.uncertain_ranges.size() == 1 && replay.uncertain_ranges.front().first == 0 &&
            replay.uncertain_ranges.front().second == std::filesystem::file_size(archive),
            "adjacent uncertain ranges were not coalesced over the selected input");
        std::ifstream member(destination / L"ok.txt", std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(member)), {});
        require(contents == "cursor replay", "replayed composition wrote incorrect output");
    }
    check_final_results(output, 0);
    wire::write(output, outcome.response);
    check_final_results(output, 1, user_cancel ? "cancelled" : "ok");
    manager.end(job);
}

void rejected_composition_is_not_prepared(const std::filesystem::path& archive,
                                          const std::filesystem::path& destination) {
    // ZipCrypto stored member. The two candidate keys both fail its check byte.
    static constexpr char encrypted_zip[] =
        "\x50\x4b\x03\x04\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x0a\x67\x73\x71\x19\x00\x00\x00\x0d\x00\x00\x00\x06\x00"
        "\x00\x00\x6f\x6b\x2e\x74\x78\x74\xcc\xa7\x97\xbd\x1f\xcf\x6f\x92\xf9\xa6\xcf\xb2\xbf\xec\x58\x0f\x12\xe6\x0f\xef"
        "\xa3\x45\xb3\xb4\xcb\x50\x4b\x01\x02\x3f\x00\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x0a\x67\x73\x71\x19\x00\x00"
        "\x00\x0d\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x6f\x6b\x2e\x74\x78"
        "\x74\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x34\x00\x00\x00\x3d\x00\x00\x00\x00\x00";
    { std::ofstream file(archive, std::ios::binary); file.write(encrypted_zip, sizeof(encrypted_zip) - 1); }
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "rejected-composition";
    request.output_dir = destination.wstring();
    request.password_candidates = {L"incorrect", L"also wrong"};
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources = {{archive.wstring(), 0, 45, true}, {archive.wstring(), 45, sizeof(encrypted_zip) - 1, true}};
    plan.domains = {{0}, {1}};
    plan.layouts = {{{1, L"v1", 0}, {2, L"v2", 1}}};
    const auto outcome = run_request(request);
    require(outcome.code == 1 && replay.rejected_compositions == 1 && replay.prepared_compositions == 0 &&
        !std::filesystem::exists(destination), "a composition rejected by the member probe reached extraction setup");
}

int main() {
    // Tiny stored ZIP: ok.txt contains "cursor replay". Split through the
    // member's data so success requires both chosen ranges in the right order.
    static constexpr char zip[] =
        "\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x61\x87\x68\x5d\x0a\x67\x73\x71\x0d\x00\x00\x00\x0d\x00\x00\x00\x06\x00\x00\x00\x6f\x6b\x2e\x74\x78\x74\x63\x75\x72\x73\x6f\x72\x20\x72\x65\x70\x6c\x61\x79"
        "\x50\x4b\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x61\x87\x68\x5d\x0a\x67\x73\x71\x0d\x00\x00\x00\x0d\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x6f\x6b\x2e\x74\x78\x74"
        "\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x34\x00\x00\x00\x31\x00\x00\x00\x00\x00";
    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-volume-replay-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(root);
    const auto archive = root / L"input.zip";
    { std::ofstream file(archive, std::ios::binary); file.write(zip, sizeof(zip) - 1); }
    check_chunked_request(archive);
    rejected_composition_is_not_prepared(root / L"encrypted.zip", root / L"rejected");
    unsigned index = 0;
    for (bool after_failure : {false, true}) for (bool cancel : {false, true})
        request_recovery(archive, root / std::to_wstring(++index), after_failure, cancel);
    std::filesystem::remove_all(root);
    std::cout << "enumeration withdrawal, replay and user cancellation passed\n";
}
