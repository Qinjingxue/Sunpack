// Independent coverage: real large-allocation admission/revocation, sparse
// replay without repeated writes, and cancellation across a disk-space wait.
// Existing codec/space tests do not exercise these resource combinations.
#include "internal/native_memory.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/sevenzip_callbacks.hpp"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <vector>

using namespace sunpack::sevenzip;
using namespace std::chrono_literals;
constexpr std::uint64_t MiB = 1 << 20;
void require(bool value, const char *message) {
    if (!value) { std::cerr << message << '\n'; ExitProcess(2); }
}
template<class T> T ready(std::future<T> &future) {
    require(future.wait_for(5s) == std::future_status::ready, "resource wait did not finish");
    return future.get();
}

void admission_and_recovery() {
    std::atomic<std::int64_t> capacity{64 * MiB};
    std::vector<NativeMemoryJob *> jobs;
    NativeMemoryManager manager(.10, [&] {
        auto room = capacity.load();
        for (auto *job : jobs) room -= job->committed;
        return NativeMemoryStatus{room, static_cast<std::uint64_t>((std::max)(room, std::int64_t{0})), 0};
    });
    NativeMemoryJob large(manager), light(manager);
    jobs = {&large, &light};
    std::promise<bool> revoked;
    auto revoke = revoked.get_future();
    std::mutex producer_mutex;
    std::unique_lock<std::mutex> producer(producer_mutex);
    manager.begin(large, [&] {
        revoked.set_value(true);
        std::lock_guard<std::mutex> lock(producer_mutex);
    });
    manager.begin(light);
    void *metadata = manager.allocate(large, 8 * MiB);
    void *a = manager.allocate(large, 32 * MiB), *b = manager.allocate(light, 16 * MiB);
    require(metadata && a && b, "normal capacity must admit simultaneous dictionaries");
    capacity = 48 * MiB;
    manager.changed();
    require(ready(revoke) && large.revoked && !light.revoked, "reclaim one large victim first");
    // A writer-side allocation/free must still reach the arbitrator while
    // the wake callback waits for that writer. This detects lock inversion.
    auto released = std::async(std::launch::async, [&] {
        sunpack_memory_free(a);
        manager.end(large);
        return true;
    });
    require(ready(released), "writer wake held the memory arbitration mutex");
    producer.unlock();
    capacity = 32 * MiB;
    std::atomic<bool> cancel{false};
    std::promise<bool> blocked;
    auto notice = blocked.get_future();
    std::promise<bool> resumed;
    auto waiting = resumed.get_future();
    manager.park(large, cancel, [&](bool value) { resumed.set_value(value); },
        [&](bool pause, const auto &, auto) { if (pause) blocked.set_value(true); });
    sunpack_memory_free(b);
    manager.end(light);
    require(ready(notice), "a single unfit task must announce a memory wait");
    capacity = 48 * MiB;
    manager.changed();
    require(ready(waiting), "increased capacity must automatically resume the task");
    manager.begin(large);
    a = manager.allocate(large, 32 * MiB);
    require(a, "resumed admission must fund the actual dictionary");
    manager.begin(light);
    b = manager.allocate(light, 8 * MiB);
    require(b, "retained replay state was charged twice and suppressed useful concurrency");
    sunpack_memory_free(b);
    manager.end(light);
    sunpack_memory_free(metadata);
    sunpack_memory_free(a);
    manager.end(large);
    require(!large.committed && !light.committed, "large allocations leaked");
    manager.stop();
    // A revoked decoder may finish its output drain after shutdown. That late
    // park must be canceled too; otherwise worker shutdown joins forever.
    std::promise<bool> stopped;
    auto late = stopped.get_future();
    manager.park(large, cancel, [&](bool value) { stopped.set_value(value); });
    require(!ready(late), "shutdown stranded a late memory waiter");
}

void simultaneous_scaled_machine_budgets() {
    // 1:256 scale models 8/16/32 GiB with the existing 10% reserve. This
    // exercises simultaneous commitments against one budget while committing
    // at most 112 MiB on the development machine, without touching its RAM.
    for (const auto gib : {8, 16, 32}) {
        const auto total = static_cast<std::uint64_t>(gib) * 4 * MiB;
        const auto budget = total - total / 10;
        std::vector<std::unique_ptr<NativeMemoryJob>> jobs;
        NativeMemoryManager manager(.10, [&] {
            std::int64_t room = budget;
            for (const auto &job : jobs) room -= job->committed;
            return NativeMemoryStatus{room, 0, total / 10};
        });
        for (int i = 0; i < 8; ++i) jobs.push_back(std::make_unique<NativeMemoryJob>(manager));
        for (const auto &job : jobs) manager.begin(*job);
        std::vector<std::future<void *>> allocations;
        for (const auto &job : jobs) allocations.push_back(std::async(std::launch::async,
            [&, job = job.get()] { return manager.allocate(*job, 16 * MiB); }));
        std::size_t granted = 0;
        std::vector<void *> pointers;
        for (auto &allocation : allocations) { auto *p = ready(allocation); pointers.push_back(p); if (p) ++granted; }
        require(granted == budget / (16 * MiB), "concurrent allocation exceeded or underused the reserved budget");
        for (auto *p : pointers) sunpack_memory_free(p);
        for (const auto &job : jobs) manager.end(*job);
        manager.stop();
    }
}

void sparse_replay(const std::filesystem::path &directory) {
    ReplayFile receipt;
    receipt.path = (directory / L"holes.bin").native();
    receipt.created = true;
    receipt.written.add(128 * 1024, 192 * 1024); // out-of-order success
    receipt.written.add(0, 64 * 1024);
    std::vector<unsigned char> expected(256 * 1024), initial(expected.size(), 0xCC);
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<unsigned char>(i * 17 + i / 997);
    for (std::size_t i = 0; i < initial.size(); ++i) if (receipt.written.next(i, 1).first) initial[i] = expected[i];
    { std::ofstream out(receipt.path, std::ios::binary); out.write(reinterpret_cast<const char *>(initial.data()), initial.size()); }
    auto writer = std::make_shared<AsyncFileWriter>();
    writer->set_max_write_chunk_for_test(4093);
    auto job = writer->make_job();
    auto file = writer->make_file(job, receipt.path, L"holes.bin", 0, 0, {}
#ifdef SUP7Z_ENABLE_WRITER_PROBE
        , 0
#endif
        , &receipt);
    {
        CMyComPtr<ISequentialOutStream> stream(new AsyncFileOutStream(writer, file));
        for (std::size_t offset = 0; offset < expected.size();) {
            const auto count = static_cast<UInt32>((std::min)(std::size_t{31991}, expected.size() - offset));
            UInt32 done = 0;
            require(stream->Write(expected.data() + offset, count, &done) == S_OK && done == count, "replay write failed");
            offset += done;
        }
        writer->record_operation_result(file, 0);
    }
    require(writer->finish_job(job) == S_OK, "replay completion failed");
    writer->capture_replay(file);
    std::ifstream input(receipt.path, std::ios::binary);
    const std::vector<unsigned char> actual((std::istreambuf_iterator<char>(input)), {});
    require(actual == expected, "replayed holes have incorrect data or offsets");
    require(writer->snapshot_metrics().written_bytes == 128 * 1024, "confirmed ranges were written twice");
    require(receipt.complete && receipt.written.bytes() == expected.size(), "replay receipt lost a completed interval");
}

void disk_and_memory(const std::filesystem::path &directory, bool memory_first) {
    std::atomic<std::int64_t> capacity{64 * MiB};
    NativeMemoryJob *active = nullptr;
    NativeMemoryManager manager(.10, [&] { return NativeMemoryStatus{capacity.load() - static_cast<std::int64_t>(active ? active->committed : 0), 0, 0}; });
    NativeMemoryJob memory(manager);
    active = &memory;
    auto state = make_volume_state("memory-disk", true);
    std::promise<bool> full;
    auto blocked = full.get_future();
    std::atomic<bool> reported{false};
    state->space_gate = std::make_shared<VolumeSpaceGate>(state->key, "", [&](const auto &event) {
        if (event.kind == VolumeSpaceTransition::Kind::Blocked && !reported.exchange(true)) full.set_value(true);
    });
    auto writer = std::make_shared<AsyncFileWriter>(std::make_shared<WriterMeters>(), state);
    state->space_gate->register_job("combined");
    writer->set_write_fault_for_test(ERROR_DISK_FULL, 1000, 1);
    manager.begin(memory, [writer] { writer->wake_waiters(); });
    void *dictionary = manager.allocate(memory, 16 * MiB);
    require(dictionary, "test dictionary was not admitted");
    ReplayFile receipt;
    receipt.path = (directory / (memory_first ? L"memory-first.bin" : L"disk-first.bin")).native();
    NativeCpuBudget cpu(2);
    require(cpu.try_acquire_base(), "base credit unavailable");
    auto decode = std::async(std::launch::async, [&] {
        NativeCpuJobContext credits(cpu);
        credits.acquire_extra(1);
        const auto job = writer->make_job(2 * MiB, memory.cancel);
        auto file = writer->make_file(job, receipt.path, L"combined.bin", 0, 0, {}
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            , 0
#endif
            , &receipt);
        std::vector<unsigned char> payload(MiB, 0x5A);
        for (int i = 0; i < 16; ++i) {
            UInt32 done = 0;
            if (writer->write(file, payload.data(), payload.size(), &done) != S_OK) break;
        }
        writer->close_file(file, {});
        const auto result = writer->finish_job(job);
        writer->capture_replay(file);
        return result;
    });
    require(ready(blocked), "disk wait was not established");
    capacity = 8 * MiB; manager.changed();
    require(ready(decode) == E_ABORT, "memory revoke did not break the disk wait");
    sunpack_memory_free(dictionary);
    cpu.release(1);
    manager.end(memory);
    require(cpu.reserved_credits() == 0, "a memory waiter retained CPU credits");
    require(writer->snapshot_metrics().pending_bytes == 0, "disk retry retained output buffers after revoke");
    // One outstanding space failure enters the existing probe path. Normal
    // successful IO deliberately bypasses gate bookkeeping altogether.
    writer->set_write_fault_for_test(ERROR_DISK_FULL, 1);
    if (memory_first) { capacity = 64 * MiB; manager.changed(); }
    std::atomic<bool> cancel{false};
    std::promise<bool> resume;
    auto available = resume.get_future();
    manager.park(memory, cancel, [&](bool value) { resume.set_value(value); });
    if (!memory_first) {
        state->space_gate->poll(64 * MiB);
        require(cpu.reserved_credits() == 0, "disk recovery revived a memory waiter prematurely");
        capacity = 64 * MiB; manager.changed();
    }
    require(ready(available), "memory did not recover while disk remained full");
    manager.begin(memory, [writer] { writer->wake_waiters(); });
    // Disk recovers independently; its real successful write settles the probe.
    state->space_gate->poll(64 * MiB);
    {
        auto job = writer->make_job(0, memory.cancel);
        auto file = writer->make_file(job, receipt.path, L"combined.bin", 0, 0, {}
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            , 0
#endif
            , &receipt);
        CMyComPtr<ISequentialOutStream> stream(new AsyncFileOutStream(writer, file));
        std::vector<unsigned char> bytes(4 * MiB, 0x5A);
        UInt32 done = 0;
        require(stream->Write(bytes.data(), bytes.size(), &done) == S_OK && done == bytes.size(), "combined replay failed");
        writer->record_operation_result(file, 0);
        stream.Release();
        require(writer->finish_job(job) == S_OK, "recovered resources did not finish output");
        writer->capture_replay(file);
    }
    require(!state->space_gate->blocked() && receipt.complete, "resource gates failed to recover independently");
    state->space_gate->unregister_job("combined");
    manager.end(memory);
    manager.stop();
}

int main() {
    auto directory = std::filesystem::temp_directory_path() / (L"sunpack-memory-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    admission_and_recovery();
    simultaneous_scaled_machine_budgets();
    sparse_replay(directory);
    disk_and_memory(directory, true);
    disk_and_memory(directory, false);
    std::filesystem::remove_all(directory);
    std::cout << "memory admission, sparse replay and combined pressure passed\n";
}
