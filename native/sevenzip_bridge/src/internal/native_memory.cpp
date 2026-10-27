#include "native_memory.hpp"
#include <Psapi.h>
#include <algorithm>
#include <limits>
#include <unordered_map>
#include <cstdlib>

namespace {
thread_local void *context = nullptr;
thread_local bool bookkeeping = false;
struct BookkeepingScope {
    BookkeepingScope() { bookkeeping = true; }
    ~BookkeepingScope() { bookkeeping = false; }
};
struct Allocation { sunpack::sevenzip::NativeMemoryJob *job; std::size_t size; };
std::mutex allocations_mutex;
std::unordered_map<void *, Allocation> allocations;
constexpr std::uint64_t quantum = SUNPACK_LARGE_ALLOCATION;
std::int64_t difference(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? static_cast<std::int64_t>((std::min)(a - b, std::uint64_t{INT64_MAX}))
                  : -static_cast<std::int64_t>((std::min)(b - a, std::uint64_t{INT64_MAX}));
}
}

namespace sunpack::sevenzip {
NativeMemoryStatus NativeMemoryManager::query_windows(double ratio) noexcept {
    MEMORYSTATUSEX memory{sizeof(memory)};
    if (!GlobalMemoryStatusEx(&memory)) return {INT64_MAX, 0, 0};
    // EX2 is available on current Windows 10/11. Retain the EX fallback for
    // older installations without assuming that shared mappings are private.
    struct Counters { PROCESS_MEMORY_COUNTERS_EX process; SIZE_T private_working_set, shared_commit; } counters{};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters), sizeof(counters)))
        GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters), sizeof(counters.process));
    const auto &process = counters.process;
    // Commit that has not become resident must still fit when the decoder
    // touches it. WorkingSetSize includes shared pages; the physical reserve
    // also covers this conservative fallback's small accounting uncertainty.
    const auto resident = counters.private_working_set ? counters.private_working_set : process.WorkingSetSize;
    const auto debt = process.PrivateUsage > resident ? process.PrivateUsage - resident : 0;
    const auto reserve = static_cast<std::uint64_t>(memory.ullTotalPhys * ratio);
    auto room = (std::min)(difference(memory.ullAvailPhys, reserve + debt),
                          difference(memory.ullAvailPageFile, 0));
    // Keep the same physical reserve available as system commit, too. The
    // process-specific AvailPageFile can be constrained by a much smaller Job,
    // so subtracting the machine reserve from it would block valid small Jobs.
    PERFORMANCE_INFORMATION system{sizeof(system)};
    if (GetPerformanceInfo(&system, sizeof(system)))
        room = (std::min)(room, difference(system.CommitLimit * system.PageSize,
            system.CommitTotal * system.PageSize + reserve));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    if (QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr)) {
        const auto flags = limits.BasicLimitInformation.LimitFlags;
        if (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)
            room = (std::min)(room, difference(static_cast<std::uint64_t>(limits.ProcessMemoryLimit * (1 - ratio)), process.PrivateUsage));
        if (flags & JOB_OBJECT_LIMIT_JOB_MEMORY) {
            // This worker normally has no child processes. The job's memory
            // usage query includes siblings when the host grouped them together.
            struct Usage { ULONG64 total, peak; } usage{};
            if (!QueryInformationJobObject(nullptr, static_cast<JOBOBJECTINFOCLASS>(28), &usage, sizeof(usage), nullptr))
                usage.total = process.PrivateUsage;
            room = (std::min)(room, difference(static_cast<std::uint64_t>(limits.JobMemoryLimit * (1 - ratio)), usage.total));
        }
    }
    return {room, memory.ullAvailPhys, reserve};
}

NativeMemoryManager::NativeMemoryManager(double ratio, Query query, std::function<void()> reclaim)
    : reserve_ratio_(ratio), query_(std::move(query)), reclaim_(std::move(reclaim)) {
    change_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!change_) throw std::bad_alloc();
    low_ = CreateMemoryResourceNotification(LowMemoryResourceNotification);
    high_ = CreateMemoryResourceNotification(HighMemoryResourceNotification);
    try { thread_ = std::thread([this] { monitor(); }); }
    catch (...) {
        CloseHandle(change_);
        if (low_) CloseHandle(low_);
        if (high_) CloseHandle(high_);
        throw;
    }
}
NativeMemoryManager::~NativeMemoryManager() {
    stop();
    CloseHandle(change_);
    if (low_) CloseHandle(low_);
    if (high_) CloseHandle(high_);
}
void NativeMemoryManager::stop() noexcept {
    { std::lock_guard<std::mutex> lock(mutex_); stopping_ = true; }
    changed();
    if (thread_.joinable()) thread_.join();
}
void NativeMemoryManager::changed() noexcept {
    SetEvent(change_);
}
NativeMemoryStatus NativeMemoryManager::sample_locked() const {
    auto status = query_ ? query_() : query_windows(reserve_ratio_);
    for (const auto *job : jobs_) status.headroom -= static_cast<std::int64_t>(job->admission);
    status.available = static_cast<std::uint64_t>((std::max)(status.headroom, std::int64_t{0}));
    return status;
}
void NativeMemoryManager::begin(NativeMemoryJob &job, std::function<void()> wake) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.running = true;
    job.wake_pending = false;
    job.failed_headroom = -1;
    job.revoked.store(false, std::memory_order_release);
    job.denied.store(false, std::memory_order_release);
    job.cancel->store(false, std::memory_order_release);
    job.wake = std::move(wake);
    if (std::find(jobs_.begin(), jobs_.end(), &job) == jobs_.end()) jobs_.push_back(&job);
    changed();
}
void NativeMemoryManager::end(NativeMemoryJob &job) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.running = false;
    job.wake_pending = false;
    job.admission = 0;
    job.wake = {};
    jobs_.erase(std::remove(jobs_.begin(), jobs_.end(), &job), jobs_.end());
    changed();
}
void NativeMemoryManager::set_wake(NativeMemoryJob &job, std::function<void()> wake) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.wake = std::move(wake);
    if (job.revoked.load(std::memory_order_acquire)) {
        job.wake_pending = true;
        changed();
    }
}
void NativeMemoryManager::revoke_locked(NativeMemoryJob &job) {
    if (job.revoked.exchange(true, std::memory_order_acq_rel)) return;
    job.cancel->store(true, std::memory_order_release);
    // Producers can enter this allocator while holding a writer mutex. Never
    // take a writer/registry lock under the arbitrator or on that same stack.
    job.wake_pending = true;
}
void NativeMemoryManager::retry(NativeMemoryJob &job) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.peak = (std::max)(job.peak, job.committed + quantum);
    revoke_locked(job);
    changed();
}
void *NativeMemoryManager::allocate(NativeMemoryJob &job, std::size_t size) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (job.revoked.load(std::memory_order_acquire)) return nullptr;
        const auto wanted = static_cast<std::uint64_t>(size);
        job.peak = (std::max)(job.peak, job.committed + wanted);
        const auto status = sample_locked();
        const auto credit = (std::min)(wanted, job.admission);
        if (status.headroom < static_cast<std::int64_t>(wanted - credit)) {
            // Let existing codec fallbacks (e.g. MT -> serial) work first.
            // Only an unsuccessful attempt is replayed for this denial.
            // Reclaim on the monitor: global-new callers may already hold a
            // writer/registry mutex, so inline cache reclaim can deadlock.
            reclaim_requested_ = true;
            job.denied.store(true, std::memory_order_release);
            changed();
            return nullptr;
        }
        // Serialize only large commitments: no stale availability snapshot can
        // admit several simultaneous dictionaries against the same free bytes.
        void *result = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!result) {
            // Freeing this attempt is not evidence of external recovery. Wait
            // for capacity beyond its fully-refunded budget, avoiding a rapid
            // fail/replay loop when Windows rejects an optimistic sample.
            job.failed_headroom = status.headroom + static_cast<std::int64_t>(job.committed + job.admission);
            job.denied.store(true, std::memory_order_release);
            changed();
            return nullptr;
        }
        try {
            std::lock_guard<std::mutex> allocation_lock(allocations_mutex);
            BookkeepingScope bookkeeping_scope;
            allocations.emplace(result, Allocation{&job, size});
        } catch (...) { VirtualFree(result, 0, MEM_RELEASE); throw; }
        job.admission -= credit;
        job.committed += wanted;
        return result;
    } catch (...) { retry(job); return nullptr; }
}
void NativeMemoryManager::released(NativeMemoryJob &job, std::size_t size) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    job.committed -= size;
    changed();
}
bool NativeMemoryManager::may_start_thread(NativeMemoryJob &job) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (job.revoked.load(std::memory_order_acquire)) return false;
    if (sample_locked().headroom + static_cast<std::int64_t>(job.admission) >= 0) return true;
    // No per-thread memory accounting. Avoid entering the Windows loader while
    // already under pressure; its initial stack growth cannot run our callbacks.
    job.denied.store(true, std::memory_order_release);
    job.peak = (std::max)(job.peak, job.committed + quantum);
    changed();
    return false;
}
void NativeMemoryManager::park(NativeMemoryJob &job, const std::atomic<bool> &cancel,
                               std::function<void(bool)> ready, WaitNotice notice) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!stopping_) {
            if (job.failed_headroom >= 0) job.failed_headroom -= static_cast<std::int64_t>(job.committed);
            waiters_.push_back({&job, &cancel, std::move(ready), std::move(notice)});
            changed();
            return;
        }
    }
    // An already-revoked decoder can finish draining after the monitor stops.
    // Return it to the executor to acknowledge cancellation, never strand it.
    ready(false);
}
void NativeMemoryManager::monitor() {
    bool low_seen = false;
    for (;;) {
        bool active;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            active = !jobs_.empty() || !waiters_.empty() || stopping_;
        }
        HANDLE handles[2]{change_, low_seen ? high_ : low_};
        const DWORD count = active && handles[1] ? 2 : 1;
        // Windows notifications have a middle zone and cannot express our
        // reserve. Sampling is active-only; every large allocation also checks
        // synchronously. Idle workers have no timer or polling activity.
        WaitForMultipleObjects(count, handles, FALSE, active ? 250 : INFINITE);
        BOOL low = FALSE;
        if (low_) QueryMemoryResourceNotification(low_, &low);
        low_seen = low != FALSE;
        bool pressure;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Refund forecasts before reclaiming real memory. An unconsumed
            // restart reservation is not a working dictionary to protect.
            if (sample_locked().headroom < 0)
                for (auto *job : jobs_) job->admission = 0;
            pressure = !stopping_ && (reclaim_requested_ || sample_locked().headroom < 0);
            reclaim_requested_ = false;
        }
        if (pressure && reclaim_) reclaim_();
        std::vector<std::function<void()>> callbacks;
        bool stopped;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped = stopping_;
            const auto status = sample_locked();
            if (!stopped && status.headroom < 0) {
                std::uint64_t retiring = 0;
                NativeMemoryJob *victim = nullptr;
                for (auto *job : jobs_) {
                    if (job->revoked.load(std::memory_order_acquire)) retiring += job->committed;
                    else if (job->running && job->committed && (!victim || victim->committed < job->committed)) victim = job;
                }
                if (victim && retiring < static_cast<std::uint64_t>(-status.headroom)) revoke_locked(*victim);
            }
            for (auto *job : jobs_) if (job->wake_pending && job->wake) {
                callbacks.push_back(job->wake);
                job->wake_pending = false;
            }
            for (auto it = waiters_.begin(); it != waiters_.end();) {
                auto &waiter = *it;
                auto &job = *waiter.job;
                const bool canceled = stopped || waiter.cancel->load(std::memory_order_acquire);
                const auto available = sample_locked();
                // Retained replay metadata is already in process commitment;
                // reserve only the additional workspace, never charge it twice.
                const auto needed = job.peak - job.committed;
                const bool fits = available.headroom >= static_cast<std::int64_t>(needed) &&
                    (job.failed_headroom < 0 || available.headroom > job.failed_headroom);
                if (canceled || fits) {
                    if (!canceled) { job.admission = needed; jobs_.push_back(&job); }
                    callbacks.push_back([waiter = std::move(waiter), available, canceled]() mutable {
                        if (waiter.announced && waiter.notice) waiter.notice(false, available, waiter.job->peak);
                        waiter.ready(!canceled);
                    });
                    it = waiters_.erase(it);
                } else {
                    const bool progressing = std::any_of(jobs_.begin(), jobs_.end(), [](const auto *other) {
                        return other->running || other->admission != 0;
                    });
                    if (!waiter.announced && !progressing && waiter.notice) {
                        waiter.announced = true;
                        callbacks.push_back([notice = waiter.notice, available, needed = job.peak] { notice(true, available, needed); });
                    }
                    ++it;
                }
            }
        }
        for (auto &callback : callbacks) callback();
        if (stopped) return;
    }
}
}

extern "C" {
void *sunpack_decoder_allocate(void *, size_t size) {
    if (size >= SUNPACK_LARGE_ALLOCATION && context) return sunpack_memory_alloc(size);
    return std::malloc(size);
}
void sunpack_decoder_free(void *, void *address) { if (!sunpack_memory_free(address)) std::free(address); }
void *sunpack_memory_current_context() { return bookkeeping ? nullptr : context; }
void *sunpack_memory_exchange_context(void *value) { auto previous = context; context = value; return previous; }
int sunpack_memory_may_start_thread(void *value) {
    auto *job = static_cast<sunpack::sevenzip::NativeMemoryJob *>(value);
    return !job || job->owner.may_start_thread(*job);
}
void *sunpack_memory_alloc(size_t size) {
    auto *job = static_cast<sunpack::sevenzip::NativeMemoryJob *>(context);
    return job ? job->owner.allocate(*job, size) : nullptr;
}
size_t sunpack_memory_size(void *address) {
    if ((reinterpret_cast<std::uintptr_t>(address) & 65535) != 0 || !address) return 0;
    std::lock_guard<std::mutex> lock(allocations_mutex);
    const auto found = allocations.find(address);
    return found == allocations.end() ? 0 : found->second.size;
}
int sunpack_memory_free(void *address) {
    if ((reinterpret_cast<std::uintptr_t>(address) & 65535) != 0 || !address || bookkeeping) return 0;
    Allocation allocation{};
    {
        std::lock_guard<std::mutex> lock(allocations_mutex);
        BookkeepingScope bookkeeping_scope;
        const auto found = allocations.find(address);
        if (found == allocations.end()) return 0;
        allocation = found->second;
        allocations.erase(found);
    }
    VirtualFree(address, 0, MEM_RELEASE);
    allocation.job->owner.released(*allocation.job, allocation.size);
    return 1;
}
}
