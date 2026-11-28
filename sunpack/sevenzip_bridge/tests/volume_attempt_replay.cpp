// Exercise the real request boundary, not just the allocator or DFS in
// isolation. Inject withdrawal at the cursor's first shared-domain allocation.
// No timing window, low-memory machine or production test hook is required.
#define main sunpack_worker_main
#include "../src/worker.cpp"
#undef main
#include <cstring>
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
    NativeMemoryManager manager(0, {}, [] { return 1LL << 30; });
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
    // ZipCrypto stored member with key "fixture-known". Both trial keys fail.
    static constexpr char encrypted_zip[] =
        "\x50\x4b\x03\x04\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x0a\x67\x73\x71\x19\x00\x00\x00\x0d\x00\x00\x00\x06\x00"
        "\x00\x00\x6f\x6b\x2e\x74\x78\x74\xca\x7e\xe7\xd0\xd3\x19\xa3\x6b\xc5\xf0\x69\x84\xfc\x4f\x90\x86\x6f\x57\xfe\x76"
        "\x5c\xb8\x05\x5d\xfd\x50\x4b\x01\x02\x3f\x00\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x0a\x67\x73\x71\x19\x00\x00"
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
    const std::vector<VolumeAttemptSlot> slots = {{1, L"v1", 0}, {2, L"v2", 1}};
    plan.layouts = {slots, slots};
    request.password_domains = {{0, 1}, {1}};
    plan.layout_password_domains = {0, 1};
    const auto outcome = run_request(request);
    require(outcome.code == 1 && replay.rejected_compositions == 1 && replay.prepared_compositions == 1 &&
        replay.volumes.layout == 1 && !replay.password_probe_done,
        "the rejected composition reached extraction or the sole remaining pair was probed again");
}

void sole_injective_composition_skips_member_probe(const std::filesystem::path& archive,
                                                  const std::filesystem::path& destination) {
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "sole-composition";
    request.output_dir = destination.wstring();
    request.password_candidates = {L"unused by this layout", L"remaining"};
    request.password_domains = {{1}};
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources = {{archive.wstring(), 0, 40, true},
                    {archive.wstring(), 40, std::filesystem::file_size(archive), true}};
    // Source 1 appears in both slot domains, so injectivity leaves only {0, 1}.
    plan.domains = {{0, 1}, {1}};
    plan.layouts = {{{1, L"v1", 0}, {2, L"v2", 1}}};
    plan.layout_password_domains = {0};
    const auto outcome = run_request(request);
    std::ifstream member(destination / L"ok.txt", std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(member)), {});
    require(outcome.code == 0 && replay.volumes.attempts == 1 && replay.prepared_compositions == 1 &&
        replay.scheduled_volume_probes == 0 && !replay.password_probe_done &&
        replay.candidate_index == 1 && contents == "cursor replay",
        "the sole viable password and composition did not go directly to real extraction");
}

void sparse_layout_skips_password_probe(const std::filesystem::path& archive,
                                        const std::filesystem::path& destination) {
    NativeCpuBudget budget(2);
    NativeCpuJobContext job(budget);
    NativeCpuContextScope cpu(&job);
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "sparse-layout";
    request.output_dir = destination.wstring();
    request.password_candidates = {L"incorrect", L"fixture-known"};
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources = {{archive.wstring(), 0, 45, true},
                    {archive.wstring(), 45, std::filesystem::file_size(archive), true},
                    {archive.wstring(), 45, 46, true}};
    plan.domains = {{0}, {1, 2}, {1}};
    plan.layouts = {{{1, L"v1", 0}, {3, L"v3", 1}}, {{1, L"v1", 0}, {2, L"v2", 2}}};
    const auto outcome = run_request(request);
    std::ifstream member(destination / L"ok.txt", std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(member)), {});
    require(outcome.code == 0 && replay.volumes.attempts == 2 && replay.volumes.layout == 1 &&
        replay.scheduled_volume_probes == 1 && replay.screened_candidates == std::vector<std::size_t>{1} &&
        contents == "cursor replay", "a sparse layout spent a probe or invalidated the next layout's proof");
}

void last_password_extracts_into_existing_destination(const std::filesystem::path& archive,
                                                       const std::filesystem::path& destination) {
    std::filesystem::create_directories(destination);
    { std::ofstream sentinel(destination / L"keep.txt"); sentinel << "existing output"; }
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "sole-password-in-existing-output";
    request.output_dir = destination.wstring();
    request.password_candidates = {L"incorrect", L"fixture-known"};
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    const auto outcome = run_request(request);
    require(outcome.code == 0 && replay.screened_candidates == std::vector<std::size_t>{1} &&
        replay.candidate_index == 1 && !replay.candidates_started,
        "the last password repeated read-only confirmation before extraction");
    require(outcome.response.find(wire::key("verified_manifest")) == std::string::npos,
        "existing output returned a manifest that excludes preexisting files");
    std::ifstream member(destination / L"ok.txt", std::ios::binary), sentinel(destination / L"keep.txt");
    require(std::string((std::istreambuf_iterator<char>(member)), {}) == "cursor replay" &&
        std::string((std::istreambuf_iterator<char>(sentinel)), {}) == "existing output",
        "sole-password extraction changed existing output");

    ExtractionReplay gap_replay;
    ExtractionReplayScope gap_scope(&gap_replay);
    request.archive_input.missing_volume_number = 2;
    const auto missing = run_request(request);
    require(missing.code == 1 && !gap_replay.password_probe_done &&
        missing.response.find(wire::key("missing_volume_evidence") + wire::text("structured_volume_gap")) != std::string::npos,
        "fixed missing volume repeated password work before returning the known gap");
}

void scan_confirms_only_unproven_password(const std::filesystem::path& archive) {
    NativeCpuBudget budget(1);
    NativeCpuJobContext job(budget);
    NativeCpuContextScope cpu(&job);
    WorkerRequest request;
    request.job_id = "scan-sole-composition";
    request.scan_only = true;
    request.encrypted = 1;
    request.password = L"fixture-known";
    request.password_candidates = {request.password};
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources = {{archive.wstring(), 0, 45, true},
                    {archive.wstring(), 45, std::filesystem::file_size(archive), true}};
    plan.domains = {{0, 1}, {1}};
    plan.layouts = {{{1, L"v1", 0}, {2, L"v2", 1}}};

    request.password_verified = true;
    const auto verified = run_request(request);
    auto selected = wire::key("volume_selection");
    append_volume_selection(selected, 0, {0, 1});
    const auto confirmed = wire::key("password_verified") + wire::boolean(true);
    const auto matched = wire::key("matched_index") + wire::number(0);
    require(verified.code == 0 && verified.response.find(selected) != std::string::npos &&
        verified.response.find(confirmed) != std::string::npos && verified.response.find(matched) == std::string::npos,
        "Scan probed the proven password again or lost the sole composition");

    plan.layouts[0][1].number = 3;
    const auto incomplete = run_request(request);
    require(incomplete.code == 1 && incomplete.response.find(wire::text("structured_volume_gap")) != std::string::npos &&
        incomplete.response.find(selected) == std::string::npos,
        "Scan reported a gapped singleton as a complete composition");
    plan.layouts[0][1].number = 2;

    request.password_verified = false;
    const auto unverified = run_request(request);
    require(unverified.code == 0 && unverified.response.find(confirmed) != std::string::npos &&
        unverified.response.find(matched) != std::string::npos,
        "Scan failed to verify its last unproven password with the member CRC");
}

void warm_volume_waves_reuse_proofs(const std::filesystem::path& archive) {
    WorkerRequest request;
    request.scan_only = true;
    auto& plan = request.archive_input.volume_attempts;
    for (std::size_t i = 0; i < 8; ++i) plan.sources.push_back({archive.wstring(), i, i + 1, true});
    plan.domains = {{0, 1, 2, 3}, {4, 5, 6, 7}};
    plan.layouts = {{{1, L"one", 0}, {2, L"two", 0}, {3, L"three", 1}}};
    plan.prepare();

    auto interleaved = plan;
    interleaved.domains.push_back({0, 1});
    interleaved.layouts.push_back({{1, L"one", 2}, {2, L"two", 0}, {3, L"three", 1}});
    CompleteVolumeGeometry geometry;
    require(geometry.known(interleaved, 0) && geometry.known(interleaved, 1) &&
        geometry.known(interleaved, 0) && geometry.inspected_choices == 10 &&
        geometry.file_size_queries == 1,
        "interleaved layouts read shared geometry more than once");

    // Same physical EOF, but the selected logical slice runs past its view.
    auto short_view = std::make_shared<ReadView>();
    short_view->physical_size = std::filesystem::file_size(archive);
    short_view->spans.push_back({2, 4, true});
    interleaved.sources.back().view = short_view;
    require(!CompleteVolumeGeometry{}.known(interleaved, 0),
        "a range beyond restored EOF admitted a reusable rejection");

    VolumeProbeCache cache(plan);
    PasswordTestResult rejection;
    rejection.status = PasswordTestStatus::WrongPassword;
    rejection.observed_volume_slots = std::vector<std::size_t>{2};
    const auto attempt = [&](std::size_t tail) { return PreparedAttempt{0, {0, 1, tail}, rejection}; };
    for (std::size_t tail : {4, 5, 6}) cache.remember(plan, attempt(tail), 4);
    // A concurrent job can claim credits between waves. A smaller wave must
    // shrink the cache even if it already holds more than its new capacity.
    cache.remember(plan, attempt(7), 1);
    require(cache.find(plan, attempt(4)) == nullptr && cache.find(plan, attempt(6)) == nullptr &&
        cache.find(plan, attempt(7)) != nullptr, "probe cache grew after losing CPU credits");
    require(cache.geometry.inspected_choices == 8, "geometry rechecked the shared choice domain for each slot");
    require(cache.geometry.file_size_queries == 1, "geometry re-queried the same carrier for each extent");
    for (std::size_t tail : {4, 5, 6}) cache.remember(plan, attempt(tail), 4);

    NativeCpuBudget budget(8);
    NativeCpuJobContext job(budget);
    NativeCpuContextScope cpu(&job);
    VolumeAttemptCursor cursor, expected;
    cursor.reserve(plan);
    expected.reserve(plan);
    for (;;) {
        auto wave = probe_volume_wave(request, cursor, nullptr, cache);
        if (wave.empty()) break;
        for (const auto& item : wave) {
            require(expected.next(plan) && item.sources == expected.selected &&
                item.probe->status == PasswordTestStatus::WrongPassword &&
                item.probe->observed_volume_slots == rejection.observed_volume_slots,
                "cached volume wave changed relation order or lost its proof");
        }
    }
    require(expected.attempts == 48 && cache.scheduled_probes == 0,
        "known volume proof was dispatched as a decoder task");

    VolumeProbeCache accepted(plan);
    accepted.remember(plan, attempt(4), 4);
    auto match = attempt(5);
    match.probe->status = PasswordTestStatus::Ok;
    accepted.remember(plan, match, 4);
    VolumeAttemptCursor first_match;
    first_match.reserve(plan);
    while (first_match.attempts < 2) {
        auto wave = probe_volume_wave(request, first_match, nullptr, accepted);
        require(!wave.empty() && (first_match.attempts != 2 || wave.back().probe->status == PasswordTestStatus::Ok),
            "cached winner did not terminate its ordered wave");
    }
    require(first_match.attempts == 2 && accepted.scheduled_probes == 0,
        "cached winner advanced the cursor past its proof");

    VolumeProbeCache prefixes(plan);
    rejection.observed_volume_slots = std::vector<std::size_t>{0};
    for (std::size_t head = 0; head < 4; ++head)
        prefixes.remember(plan, {0, {head, (head + 1) % 4, 4}, rejection}, 4);
    VolumeAttemptCursor prefix_cursor;
    prefix_cursor.reserve(plan);
    std::size_t head = 0;
    for (;;) {
        auto wave = probe_volume_wave(request, prefix_cursor, nullptr, prefixes);
        if (wave.empty()) break;
        for (const auto& item : wave) {
            require(item.sources.front() == head++ && item.probe->status == PasswordTestStatus::WrongPassword,
                "cached prefix did not retain its first representative in relation order");
        }
    }
    require(head == 4 && prefix_cursor.attempts == 4 && prefixes.scheduled_probes == 0,
        "known rejected suffixes were reconstructed by the wave");

    VolumeProbeCache unavailable(plan);
    PasswordTestResult unsupported;
    unsupported.status = PasswordTestStatus::Unsupported;
    unsupported.password_independent_failure = true;
    unsupported.observed_volume_slots.emplace();
    require(unavailable.remember(plan, {0, {0, 1, 4}, unsupported}, 4), "could not cache an unavailable probe");
    VolumeAttemptCursor unresolved;
    unresolved.reserve(plan);
    const auto wave = probe_volume_wave(request, unresolved, nullptr, unavailable);
    require(wave.size() == 1 && wave.front().sources == std::vector<std::size_t>{0, 1, 4} &&
        wave.front().probe && wave.front().probe->status == PasswordTestStatus::Unsupported &&
        !rejects_volume_attempt(*wave.front().probe) && !unresolved.next(plan) && unresolved.attempts == 1 &&
        unavailable.scheduled_probes == 0, "unavailable proof re-enumerated equivalent candidates or lost its witness");
}

void carrier_slices_share_open_file(const std::filesystem::path& archive) {
    std::vector<ExtractInputRange> parts;
    // Noncontiguous and reversed slices must still seek correctly while
    // sharing the same handle. Read all extents in one decoder request.
    for (auto index : {5, 2, 1, 3, 0, 4})
        parts.push_back({archive.wstring(), static_cast<UInt64>(index), static_cast<UInt64>(index + 1), true});
    observed_range_size_queries = observed_range_handle_opens = 0;
    auto* stream = new MultiRangeInStream(parts);
    CMyComPtr<IInStream> owner(stream);
    std::array<char, 6> data{};
    UInt32 read = 0;
    std::ifstream file(archive, std::ios::binary);
    std::array<char, 6> original{};
    file.read(original.data(), original.size());
    require(stream->Read(data.data(), data.size(), &read) == S_OK && read == data.size() &&
        data == std::array<char, 6>{original[5], original[2], original[1], original[3], original[0], original[4]},
        "sharing a carrier handle changed the logical byte order");
    require(observed_range_size_queries == 1 && observed_range_handle_opens == 1,
        "each carrier slice reopened or re-statted its file");
}

void unavailable_member_is_not_reprobed_for_an_unread_slice(
    const std::filesystem::path& archive, const std::filesystem::path& carrier) {
    std::ifstream original(archive, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(original)), {});
    const auto directory = bytes.find("\x50\x4b\x01\x02");
    require(directory != std::string::npos, "unsupported ZIP fixture has no central directory");
    bytes[8] = bytes[directory + 10] = 97; // Unknown member compression method.
    constexpr std::size_t padding = 1024 * 1024;
    bytes.insert(directory, 2 * padding + 1, '\0');
    const auto offset = directory + 2 * padding + 1;
    std::string encoded;
    wire::little(encoded, offset, 4);
    bytes.replace(bytes.size() - 6, 4, encoded);
    { std::ofstream file(carrier, std::ios::binary); file.write(bytes.data(), bytes.size()); }
    const auto middle = directory + padding;

    WorkerRequest request;
    request.password_candidates = {L"candidate one", L"candidate two"};
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    const auto path = carrier.wstring();
    plan.sources = {{path, 0, middle, true}, {path, middle, middle + 1, true},
                    {path, middle - 1, middle, true}, {path, middle + 1, bytes.size(), true}};
    plan.domains = {{0}, {1, 2}, {3}};
    plan.layouts = {{{1, L"one", 0}, {2, L"two", 1}, {3, L"three", 2}}};
    plan.prepare();

    VolumeAttemptCursor cursor;
    cursor.reserve(plan);
    VolumeProbeCache cache(plan);
    auto lookahead = cursor;
    std::vector<PreparedAttempt> cold;
    {
        // CPU credits collect both compositions. The memory arbiter defers
        // thread creation so the second lane observes the completed first.
        NativeMemoryManager manager(0, {}, [] { return -1; });
        NativeMemoryJob memory(manager);
        NativeCpuBudget budget(2);
        NativeCpuJobContext job(budget);
        NativeCpuContextScope cpu_scope(&job);
        NativeMemoryScope memory_scope(&memory);
        cold = probe_volume_wave(request, lookahead, nullptr, cache);
        require(cold.size() == (std::thread::hardware_concurrency() > 1 ? 2 : 1) &&
            (cold.size() == 1 || (memory.denied.load() && cold.front().sources != cold.back().sources)) &&
            cache.scheduled_probes == 1,
            "a deferred lane repeated the finished proof in the same wave");
    }
    for (const auto& attempt : cold)
        require(attempt.probe && attempt.probe->status == PasswordTestStatus::Unsupported &&
            attempt.probe->password_independent_failure &&
            attempt.probe->observed_volume_slots && attempt.probe->observed_volume_slots->empty(),
            "unavailable ZIP member did not preserve its read dependencies");
    require(cursor.next(plan) && cursor.selected == cold.front().sources, "unexpected first slice choice");
    lookahead = cursor;
    const auto warm = probe_volume_wave(request, lookahead, nullptr, cache);
    require(warm.size() == 1 && warm.front().sources != cold.front().sources && warm.front().probe &&
        warm.front().probe->status == PasswordTestStatus::Unsupported &&
        !warm.front().probe->rejects_fixed_geometry && cache.scheduled_probes == 1,
        "the unread slice reran an unavailable method or was falsely rejected");

    request.scan_only = true;
    request.archive_input.archive_path = path;
    const auto scan = run_request(request);
    require(scan.code == 0 && scan.response.find(wire::key("discarded_volume_paths")) == std::string::npos &&
        scan.response.find(wire::key("discarded_volume_prefixes")) == std::string::npos &&
        scan.response.find(wire::key("discarded_volume_layouts")) == std::string::npos &&
        scan.response.find(wire::key("password_verified") + wire::boolean(false)) != std::string::npos,
        "Scan discarded a composition when its member proof was unavailable");

    if (std::thread::hardware_concurrency() > 1) {
        request.password_verified = true;
        request.password_candidates.resize(1);
        NativeCpuBudget budget(2);
        NativeCpuJobContext job(budget);
        NativeCpuContextScope cpu(&job);
        VolumeAttemptCursor verified;
        verified.reserve(plan);
        VolumeProbeCache verified_cache(plan);
        const auto wave = probe_volume_wave(request, verified, nullptr, verified_cache);
        require(wave.size() == 2 && wave.back().probe && unavailable_volume_probe(*wave.back().probe) &&
            verified_cache.scheduled_probes == 1,
            "verified Scan repeated an unavailable proof on its reserved last composition");
    }
}

void member_crc_rejects_a_bad_volume(const std::filesystem::path& carrier) {
    // ZipCrypto, key "fixture-known". The smaller entry is entirely fixed,
    // while the second entry's CRC can distinguish the two middle slices.
    static constexpr char zip[] =
        "\x50\x4b\x03\x04\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x32\xce\xc9\x9e\x11\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00"
        "\x61\xc8\x0f\xe5\x81\x51\xb7\xf4\xb3\x47\x87\x4b\x13\x42\x4a\x9f\x33\xc3\x50\x4b\x03\x04\x14\x00\x01\x00\x00\x00\x00\x00"
        "\x21\x00\x80\x5a\xa4\x17\x13\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x62\xc8\x0f\xe5\x81\x51\xb7\xf4\xb3\x47\x87\x4b"
        "\x9a\x53\x75\x80\xab\xf6\x92\xa3\x50\x4b\x01\x02\x14\x00\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x32\xce\xc9\x9e\x11\x00"
        "\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x50\x4b\x01\x02\x14"
        "\x00\x14\x00\x01\x00\x00\x00\x00\x00\x21\x00\x80\x5a\xa4\x17\x13\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00\x62\x50\x4b\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00\x5e\x00\x00\x00\x62\x00"
        "\x00\x00\x00\x00";
    constexpr auto length = sizeof(zip) - 1;
    constexpr std::size_t start = 48, end = 98;
    std::string damaged(zip + start, zip + end);
    damaged.back() ^= 1;
    std::string conflicting(zip + start, zip + end);
    conflicting[8] = 8; // The second local entry declares Deflate, while its CD says Stored.
    { std::ofstream file(carrier, std::ios::binary); file.write(zip, length); file << damaged << conflicting; }

    const auto path = carrier.wstring();
    const std::vector<ExtractInputRange> ranges = {
        {path, 0, start, true}, {path, start, end, true}, {path, end, length, true}
    };
    VolumeAttemptPlan plan;
    plan.sources = ranges;
    plan.sources.push_back({path, length, length + damaged.size(), true});
    plan.domains = {{0}, {3, 1}, {2}};
    plan.layouts = {{{1, L"one", 0}, {2, L"two", 1}, {3, L"three", 2}}};
    plan.prepare();
    const std::wstring password = L"fixture-known";
    auto wrong = ranges;
    wrong[1] = plan.sources.back();
    const auto rejected = test_password_batch(path, {}, wrong, L"zip", &password, 1, {}, true, false, nullptr, &plan);
    const auto accepted = test_password_batch(path, {}, ranges, L"zip", &password, 1, {}, true, false, nullptr, &plan);
    require(rejected.status == PasswordTestStatus::WrongPassword && !rejected.rejects_fixed_geometry &&
        accepted.status == PasswordTestStatus::Ok && accepted.matched_index == 0,
        "the fixed member masked a bad volume that the second CRC can reject");

    const std::wstring candidates[]{L"incorrect", password};
    wrong[1] = {path, length + damaged.size(), length + damaged.size() + conflicting.size(), true};
    plan.sources[3] = wrong[1];
    plan.prepare();
    const auto header_conflict = test_password_batch(
        path, {}, wrong, L"zip", candidates, 2, {}, true, false, nullptr, &plan);
    require(header_conflict.status == PasswordTestStatus::Damaged &&
        header_conflict.operation_result == kSunpackZipLocalHeaderConflict &&
        header_conflict.password_independent_failure && header_conflict.possible_candidates.empty() &&
        header_conflict.matched_index == -1 && !header_conflict.rejects_fixed_geometry &&
        header_conflict.observed_volume_slots == std::optional(std::vector<std::size_t>{1}),
        "the ZIP local/CD contradiction was not returned as a scoped layout failure");

    const auto fixed = carrier.parent_path() / L"damaged-local.zip";
    std::string fixed_zip(zip, length);
    fixed_zip.replace(start, conflicting.size(), conflicting);
    // The first entry is clear and leaves the corrupt local header of the
    // second entry as the only available encrypted member check.
    fixed_zip[6] = fixed_zip[end + 8] = 0;
    fixed_zip[22] = fixed_zip[end + 24] = 17;
    { std::ofstream file(fixed, std::ios::binary); file << fixed_zip; }
    observed_logical_read_bytes = 0;
    const auto single = test_password_batch(fixed.wstring(), {}, {}, L"zip", candidates, 1, {}, true);
    const auto one_read = observed_logical_read_bytes;
    observed_logical_read_bytes = 0;
    const auto batch = test_password_batch(fixed.wstring(), {}, {}, L"zip", candidates, 2, {}, true);
    require(single.status == PasswordTestStatus::Damaged && batch.status == PasswordTestStatus::Damaged &&
        one_read > 0 && observed_logical_read_bytes < one_read * 2,
        "inconclusive member forced the same ZIP directory to reopen for a second key");

    WorkerRequest scan;
    scan.scan_only = true;
    scan.encrypted = 1;
    scan.password_candidates = {candidates[0], candidates[1]};
    scan.archive_input.archive_path = path;
    scan.archive_input.format_hint = L"zip";
    scan.archive_input.volume_attempts = plan;
    scan.archive_input.volume_attempts.layouts[0][0].name = L"carrier.zip";
    auto remaining = wire::key("first_remaining_volume");
    append_volume_selection(remaining, 0, {0, 1, 2});
    const auto scanned = run_request(scan);
    require(scanned.code == 0 && scanned.response.find(remaining) != std::string::npos &&
        scanned.response.find(wire::key("matched_index") + wire::number(1)) != std::string::npos,
        "Scan kept the contradictory ZIP composition or lost the correct password");

    auto verified_scan = scan;
    verified_scan.password_candidates = {password};
    verified_scan.password_verified = true;
    auto& verified_plan = verified_scan.archive_input.volume_attempts;
    verified_plan.prepare();
    for (const std::size_t credits : {1, 2}) {
        NativeCpuBudget budget(credits);
        NativeCpuJobContext job(budget);
        NativeCpuContextScope cpu(&job);
        VolumeProbeCache cache(verified_plan);
        VolumeAttemptCursor cursor;
        cursor.reserve(verified_plan);
        auto wave = probe_volume_wave(verified_scan, cursor, nullptr, cache);
        require(!wave.empty() && wave.front().probe && rejects_volume_attempt(*wave.front().probe) &&
            cache.geometry.file_size_queries == 0,
            "verified Scan failed to discard the contradictory first composition");
        if (wave.size() == 1) wave = probe_volume_wave(verified_scan, cursor, nullptr, cache);
        require(!wave.empty() && wave.back().sources == std::vector<std::size_t>({0, 1, 2}) &&
            !wave.back().probe && cache.scheduled_probes == 1,
            "verified Scan decoded the last composition after rejecting every earlier one");

        VolumeProbeCache pending(verified_plan);
        PasswordTestResult unavailable;
        unavailable.status = PasswordTestStatus::Unsupported;
        unavailable.observed_volume_slots = std::vector<std::size_t>{1};
        require(pending.remember(verified_plan, {0, {0, 3, 2}, unavailable}, credits),
            "could not prepare an inconclusive preceding scan layout");
        VolumeAttemptCursor unresolved;
        unresolved.reserve(verified_plan);
        wave = probe_volume_wave(verified_scan, unresolved, nullptr, pending);
        if (wave.size() == 1) wave = probe_volume_wave(verified_scan, unresolved, nullptr, pending, false);
        require(!wave.empty() && wave.back().probe && pending.scheduled_probes == 1,
            "verified Scan skipped the final composition despite an earlier unresolved one");
    }

    auto& failed_plan = scan.archive_input.volume_attempts;
    failed_plan.sources.push_back({path, length, length + damaged.size(), true});
    failed_plan.domains[1] = {3, 4};
    auto conflict_prefix = wire::key("discarded_volume_prefixes") + wire::array();
    append_volume_selection(conflict_prefix, 0, {0, 3});
    const auto mixed = run_request(scan);
    require(mixed.code == 1 && mixed.response.find(conflict_prefix) != std::string::npos &&
        mixed.response.find(wire::key("failure_kind") + wire::text("password_or_volume_inconclusive")) != std::string::npos,
        "an inconclusive scan restored a proven ZIP contradiction or discarded a password alternative");

    // Place the second local record away from both Open's head read and the
    // central directory. It can be indexed but its member data cannot open.
    constexpr std::size_t gap = 1024 * 1024;
    constexpr std::size_t second = gap, directory = 2 * gap + end - start;
    const auto blocked = carrier.parent_path() / L"locked-volume.bin";
    {
        std::string central(zip + end, zip + length);
        std::string encoded;
        wire::little(encoded, second, 4);
        central.replace(47 + 42, 4, encoded); // Second central record's local offset.
        encoded.clear();
        wire::little(encoded, directory, 4);
        central.replace(central.size() - 6, 4, encoded);
        std::ofstream file(carrier, std::ios::binary | std::ios::trunc);
        file.write(zip, start);
        file.seekp(2 * gap - 1);
        file.put('\0');
        file.write(central.data(), central.size());
        std::ofstream part(blocked, std::ios::binary);
        part.write(zip + start, end - start);
    }
    const auto handle = CreateFileW(blocked.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    require(handle != INVALID_HANDLE_VALUE, "could not lock the ZIP member volume");
    const std::vector<ExtractInputRange> locked_ranges{
        {path, 0, gap, true}, {blocked.wstring(), 0, end - start, true},
        {path, gap, 2 * gap + length - end, true}
    };
    plan.sources = locked_ranges;
    plan.sources.push_back({path, gap, gap + end - start, true});
    plan.prepare();
    const auto recovered = test_password_batch(
        path, {}, locked_ranges, L"zip", candidates, 2, {}, true, false, nullptr, &plan);
    const auto inconclusive_volume = test_password_batch(
        path, {}, locked_ranges, L"zip", candidates, 1, {}, true, false, nullptr, &plan);
    CloseHandle(handle);
    require(recovered.status == PasswordTestStatus::Ok && recovered.matched_index == 1 &&
        recovered.observed_volume_slots && *recovered.observed_volume_slots == std::vector<std::size_t>{1} &&
        !inconclusive_volume.observed_volume_slots && !inconclusive_volume.rejects_fixed_geometry,
        "a failed ZIP read poisoned the successful fallback proof or made a rejection reusable");
}

void short_copy_crc_skips_unverifiable_items(const std::filesystem::path& archive) {
    // One solid AES folder: a matching byte, a directory, a stream without
    // a CRC, and a byte whose CRC mismatches. Only the last read can reject.
    static constexpr char seven_zip[] =
        "\x37\x7a\xbc\xaf\x27\x1c\x00\x04\xea\x3c\x22\x5c\x20\x00\x00\x00\x00\x00\x00\x00\x31\x00\x00\x00\x00"
        "\x00\x00\x00\xa8\x5e\x48\x9a\x2d\x79\x30\xc8\x7b\xc5\xd9\x5e\x39\x47\x26\x12\x63\xd1\x62\x76\x07\x44"
        "\xee\xf8\x9f\x51\x81\x9b\x3c\xba\x11\x1e\x58\x81\xd5\x40\x01\x04\x06\x00\x01\x09\x20\x00\x07\x0b\x01"
        "\x00\x01\x24\x06\xf1\x07\x01\x01\x3f\x0c\x11\x00\x08\x0d\x03\x09\x01\x0f\x0a\x00\xa0\x8b\x9e\xd9\xd3"
        "\xa7\xff\xd7\x3d\x00\x00\x05\x04\x0e\x01\x40\x00\x00";
    { std::ofstream file(archive, std::ios::binary); file.write(seven_zip, sizeof(seven_zip) - 1); }
    const std::wstring password = L"fixture-known";
    const auto result = test_password_batch(archive.wstring(), {}, {}, L"7z", &password, 1, {}, true);
    require(result.status == PasswordTestStatus::WrongPassword,
        "AES/Copy follow-up missed the next verifiable member past empty or unchecksummed items");
}

void solid_aes_copy_crc_checks_the_uncertain_block(const std::filesystem::path& carrier) {
    // The first CRC covers four bytes in the fixed block. The next member
    // starts in that same block but ends in the uncertain one. A trailing
    // stream without a CRC makes the second member a partial solid proof.
    static constexpr char seven_zip[] =
        "\x37\x7a\xbc\xaf\x27\x1c\x00\x04\xb4\x3d\xe1\xee\x20\x00\x00\x00\x00\x00\x00\x00\x2e\x00\x00\x00\x00"
        "\x00\x00\x00\x6e\xce\xac\xa7\xde\x41\xc7\xaf\x93\x22\x9d\x33\x00\x13\x4d\x1b\x9e\xe3\xe1\x13\xd8\xdf"
        "\x80\x57\xfd\x65\x26\xb2\x0e\x33\x1d\xf4\xb4\xf5\x5a\x61\x01\x04\x06\x00\x01\x09\x20\x00\x07\x0b\x01"
        "\x00\x01\x24\x06\xf1\x07\x01\x01\x3f\x0c\x18\x00\x08\x0d\x03\x09\x04\x10\x0a\x00\xc0\xc9\x97\xb8\x50"
        "\xe0\x9c\xe8\x4a\x00\x00\x05\x03\x00\x00";
    constexpr auto length = sizeof(seven_zip) - 1;
    constexpr std::size_t start = 48, end = 64;
    std::string damaged(seven_zip + start, seven_zip + end);
    damaged.back() ^= 1;
    { std::ofstream file(carrier, std::ios::binary); file.write(seven_zip, length); file << damaged; }

    const auto path = carrier.wstring();
    const std::vector<ExtractInputRange> ranges = {
        {path, 0, start, true}, {path, start, end, true}, {path, end, length, true}
    };
    VolumeAttemptPlan plan;
    plan.sources = ranges;
    plan.sources.push_back({path, length, length + damaged.size(), true});
    plan.domains = {{0}, {3, 1}, {2}};
    plan.layouts = {{{1, L"one", 0}, {2, L"two", 1}, {3, L"three", 2}}};
    plan.prepare();
    const std::wstring password = L"fixture-known";
    auto wrong = ranges;
    wrong[1] = plan.sources.back();
    const auto rejected = test_password_batch(path, {}, wrong, L"7z", &password, 1, {}, true, false, nullptr, &plan);
    const auto accepted = test_password_batch(path, {}, ranges, L"7z", &password, 1, {}, true, false, nullptr, &plan);
    require(rejected.status == PasswordTestStatus::WrongPassword && !rejected.rejects_fixed_geometry &&
        accepted.status == PasswordTestStatus::Ok && accepted.matched_index == 0,
        "the fixed member masked an uncertain block in an early AES/Copy substream");
}

void disjoint_layouts_do_not_repeat_comparisons() {
    constexpr std::size_t layouts = 512;
    VolumeAttemptPlan plan;
    plan.sources.resize(layouts + 1);
    plan.domains.push_back({0});
    for (std::size_t source = 1; source <= layouts; ++source) {
        plan.domains.push_back({source});
        plan.layouts.push_back({{1, L"first", 0}, {2, L"tail", source}});
    }
    plan.layouts.push_back(plan.layouts.back());
    plan.prepare();
    VolumeAttemptCursor cursor;
    cursor.reserve(plan);
    for (std::size_t source = 1; source <= layouts; ++source)
        require(cursor.next(plan) && cursor.layout + 1 == source && cursor.selected.back() == source,
            "indexed layout membership changed candidate order");
    require(!cursor.next(plan) && cursor.previous_layout_checks == 1,
        "complete layouts still scanned disjoint predecessors or missed a duplicate");
}

FILE_ID_INFO output_directory_id(const std::filesystem::path& path) {
    const auto handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    require(handle != INVALID_HANDLE_VALUE, "could not open output directory for identity check");
    FILE_ID_INFO id{};
    const auto ok = GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id));
    CloseHandle(handle);
    require(ok, "could not read output directory identity");
    return id;
}

bool same_directory(const FILE_ID_INFO& before, const FILE_ID_INFO& after) {
    return before.VolumeSerialNumber == after.VolumeSerialNumber &&
        std::memcmp(before.FileId.Identifier, after.FileId.Identifier, sizeof(before.FileId.Identifier)) == 0;
}

void rollback_keeps_registered_root(const std::filesystem::path& destination) {
    require(!discard_candidate_output(destination.wstring()), "missing output rollback is not idempotent");
    const auto nested = destination / L"nested";
    std::filesystem::create_directories(nested);
    const auto id = output_directory_id(destination);
    const auto readonly = nested / L"readonly";
    { std::ofstream file(readonly); file << "failed attempt"; }
    { std::ofstream file(destination / L"plain"); file << "failed attempt"; }
    require(SetFileAttributesW(readonly.c_str(), FILE_ATTRIBUTE_READONLY), "could not mark fixture readonly");
    require(!discard_candidate_output(destination.wstring()), "rollback could not remove candidate children");
    require(same_directory(id, output_directory_id(destination)), "rollback replaced the registered root");
    require(std::filesystem::is_empty(destination), "rollback left candidate output behind");
    require(!discard_candidate_output(destination.wstring()), "empty output rollback is not idempotent");
}

void competing_volume_keeps_registered_root(const std::filesystem::path& archive,
                                            const std::filesystem::path& destination) {
    // Keep the stored ZIP structure and sizes valid, but corrupt one member
    // byte in the first composition so real extraction reaches rollback.
    std::string decoy;
    {
        std::ifstream file(archive, std::ios::binary);
        decoy.assign(std::istreambuf_iterator<char>(file), {});
    }
    constexpr std::size_t split = 40;
    const auto length = decoy.size();
    decoy[split] ^= 1;
    const auto alternate = archive.parent_path() / L"volume-decoy.zip";
    { std::ofstream file(alternate, std::ios::binary); file.write(decoy.data(), decoy.size()); }

    std::filesystem::create_directory(destination);
    const auto id = output_directory_id(destination);
    ExtractionReplay replay;
    ExtractionReplayScope scope(&replay);
    WorkerRequest request;
    request.job_id = "competing-volume-root-identity";
    request.output_dir = destination.wstring();
    request.archive_input.archive_path = archive.wstring();
    request.archive_input.format_hint = L"zip";
    auto& plan = request.archive_input.volume_attempts;
    plan.sources = {{archive.wstring(), 0, split, true}, {alternate.wstring(), split, length, true},
        {archive.wstring(), split, length, true}};
    plan.domains = {{0}, {1, 2}};
    plan.layouts = {{{1, L"v1", 0}, {2, L"v2", 1}}};

    const auto result = run_request(request);
    require(result.code == 0 && replay.volumes.attempts == 2 &&
        replay.volumes.selected == std::vector<std::size_t>{0, 2}, "worker did not replace the damaged candidate");
    require(same_directory(id, output_directory_id(destination)), "candidate switch replaced the registered root");
    std::ifstream member(destination / L"ok.txt", std::ios::binary);
    require(std::string(std::istreambuf_iterator<char>(member), {}) == "cursor replay",
        "successful fallback wrote incorrect output");
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
    rollback_keeps_registered_root(root / L"rollback");
    competing_volume_keeps_registered_root(archive, root / L"competing");
    warm_volume_waves_reuse_proofs(archive);
    carrier_slices_share_open_file(archive);
    unavailable_member_is_not_reprobed_for_an_unread_slice(archive, root / L"unsupported-carrier.zip");
    member_crc_rejects_a_bad_volume(root / L"encrypted-carrier.zip");
    short_copy_crc_skips_unverifiable_items(root / L"solid-aes-copy.7z");
    solid_aes_copy_crc_checks_the_uncertain_block(root / L"solid-aes-carrier.7z");
    disjoint_layouts_do_not_repeat_comparisons();
    rejected_composition_is_not_prepared(root / L"encrypted.zip", root / L"rejected");
    sparse_layout_skips_password_probe(root / L"encrypted.zip", root / L"sparse");
    scan_confirms_only_unproven_password(root / L"encrypted.zip");
    sole_injective_composition_skips_member_probe(archive, root / L"direct");
    last_password_extracts_into_existing_destination(root / L"encrypted.zip", root / L"existing");
    unsigned index = 0;
    for (bool after_failure : {false, true}) for (bool cancel : {false, true})
        request_recovery(archive, root / std::to_wstring(++index), after_failure, cancel);
    std::filesystem::remove_all(root);
    std::cout << "enumeration withdrawal, replay and user cancellation passed\n";
}
