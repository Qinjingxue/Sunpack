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
std::atomic<bool> allocations_ready{false};
std::mutex allocations_mutex;
std::unordered_map<void *, Allocation> allocations;
// Global new/delete can run in other static constructors/destructors. A CRT
// address can also be 64 KiB aligned: never probe the table outside its life.
// Declared last, this guard disables lookups before the table frees its own
// storage, and enables them only after the table and mutex are constructed.
struct AllocationLifetime {
    AllocationLifetime() { allocations_ready.store(true, std::memory_order_release); }
    ~AllocationLifetime() { allocations_ready.store(false, std::memory_order_release); }
} allocation_lifetime;
constexpr std::uint64_t quantum = SUNPACK_LARGE_ALLOCATION;
std::uint64_t commitment(std::size_t size) noexcept {
    if (size > UINT64_MAX - 4095) return UINT64_MAX;
    return (static_cast<std::uint64_t>(size) + 4095) & ~std::uint64_t{4095};
}
bool can_fit(std::int64_t headroom, std::uint64_t bytes) noexcept {
    return headroom >= 0 && bytes <= static_cast<std::uint64_t>(headroom);
}
std::int64_t difference(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? static_cast<std::int64_t>((std::min)(a - b, std::uint64_t{INT64_MAX}))
                  : -static_cast<std::int64_t>((std::min)(b - a, std::uint64_t{INT64_MAX}));
}
}

namespace sunpack::sevenzip {
NativeMemoryStatus NativeMemoryManager::query_windows(std::uint64_t reserve) noexcept {
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
    auto room = (std::min)(difference(memory.ullAvailPhys, reserve + debt),
                          difference(memory.ullAvailPageFile, 0));
    // Keep the same reserve against system commit, too. AvailPageFile remains
    // process-specific; host/test Job limits need no separate policy here.
    PERFORMANCE_INFORMATION system{sizeof(system)};
    if (GetPerformanceInfo(&system, sizeof(system)))
        room = (std::min)(room, difference(system.CommitLimit * system.PageSize,
            system.CommitTotal * system.PageSize + reserve));
    return {room, memory.ullAvailPhys, reserve};
}

NativeMemoryManager::NativeMemoryManager(std::uint64_t reserve, Query query, std::function<void()> reclaim)
    : reserve_bytes_(reserve), query_(std::move(query)), reclaim_(std::move(reclaim)) {
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
    resample_.store(true, std::memory_order_release);
    SetEvent(change_);
}
NativeMemoryStatus NativeMemoryManager::sample_locked(bool fresh) {
    const auto now = GetTickCount64();
    // Reconcile external changes on the existing active-only observation
    // interval. Between samples every managed commit/free debits/refunds this
    // ledger under the same mutex; concurrent dictionaries cannot spend it twice.
    const bool requested = resample_.exchange(false, std::memory_order_acq_rel);
    if (fresh || requested || now - sampled_at_ >= 250) {
        cached_ = query_ ? query_() : query_windows(reserve_bytes_);
        sampled_at_ = now;
    }
    auto status = cached_;
    for (const auto *job : jobs_) status.headroom -= static_cast<std::int64_t>(job->admission);
    status.available = static_cast<std::uint64_t>((std::max)(status.headroom, std::int64_t{0}));
    return status;
}
void NativeMemoryManager::begin(NativeMemoryJob &job, std::function<void()> wake) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.running = true;
    job.wake_pending = false;
    job.failed_headroom = -1;
    job.retry_headroom = INT64_MAX;
    if (!job.revoked.load(std::memory_order_acquire)) job.required = 0;
    job.peak = job.committed;
    job.revoked.store(false, std::memory_order_release);
    job.denied.store(false, std::memory_order_release);
    job.cancel->store(false, std::memory_order_release);
    job.wake = std::move(wake);
    if (std::find(jobs_.begin(), jobs_.end(), &job) == jobs_.end()) jobs_.push_back(&job);
    SetEvent(change_);
}
void NativeMemoryManager::end(NativeMemoryJob &job) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.running = false;
    job.wake_pending = false;
    job.admission = 0;
    job.wake = {};
    jobs_.erase(std::remove(jobs_.begin(), jobs_.end(), &job), jobs_.end());
    SetEvent(change_);
}
void NativeMemoryManager::set_wake(NativeMemoryJob &job, std::function<void()> wake) {
    std::lock_guard<std::mutex> lock(mutex_);
    job.wake = std::move(wake);
    if (job.revoked.load(std::memory_order_acquire)) {
        job.wake_pending = true;
        SetEvent(change_);
    }
}
void NativeMemoryManager::revoke_locked(NativeMemoryJob &job) {
    if (job.revoked.exchange(true, std::memory_order_acq_rel)) return;
    job.cancel->store(true, std::memory_order_release);
    // Producers can enter this allocator while holding a writer mutex. Never
    // take a writer/registry lock under the arbitrator or on that same stack.
    job.wake_pending = true;
}
void NativeMemoryManager::failed_locked(NativeMemoryJob &job, std::uint64_t required, const NativeMemoryStatus &status) {
    // A replay can be withdrawn before it reaches the allocation that failed
    // last time. Keep that observed workspace instead of relearning a smaller
    // prefix forever under contention. Real capacity growth still permits the
    // existing bounded probe below this requirement.
    job.required = (std::max)(job.required, required);
    // Compare external capacity after refunding this attempt, not the extra
    // room produced merely by freeing its own dictionaries/admission.
    job.retry_headroom = status.headroom + static_cast<std::int64_t>(job.committed + job.admission);
}
void NativeMemoryManager::retry(NativeMemoryJob &job) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!job.revoked.load(std::memory_order_acquire) && !job.denied.load(std::memory_order_acquire))
        failed_locked(job, (std::max)(job.peak, job.committed + quantum), sample_locked(true));
    revoke_locked(job);
    SetEvent(change_);
}
void *NativeMemoryManager::allocate(NativeMemoryJob &job, std::size_t size) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (job.revoked.load(std::memory_order_acquire)) return nullptr;
        const auto wanted = commitment(size);
        const auto total = wanted > UINT64_MAX - job.committed ? UINT64_MAX : job.committed + wanted;
        job.peak = (std::max)(job.peak, total);
        const auto credit = (std::min)(wanted, job.admission);
        auto status = sample_locked();
        // Do not deny a legal allocation on an old external snapshot. A low
        // Windows notification also bypasses the ledger's normal fast path.
        if (!can_fit(status.headroom, wanted - credit) ||
            (low_ && WaitForSingleObject(low_, 0) == WAIT_OBJECT_0)) status = sample_locked(true);
        if (!can_fit(status.headroom, wanted - credit)) {
            // Let existing codec fallbacks (e.g. MT -> serial) work first.
            // Only an unsuccessful attempt is replayed for this denial.
            // Reclaim on the monitor: global-new callers may already hold a
            // writer/registry mutex, so inline cache reclaim can deadlock.
            reclaim_requested_ = true;
            failed_locked(job, total, status);
            job.denied.store(true, std::memory_order_release);
            SetEvent(change_);
            return nullptr;
        }
        // Serialize only large commitments: no stale availability snapshot can
        // admit several simultaneous dictionaries against the same free bytes.
        void *result = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!result) {
            // Freeing this attempt is not evidence of external recovery. Wait
            // for capacity beyond its fully-refunded budget, avoiding a rapid
            // fail/replay loop when Windows rejects an optimistic sample.
            // External commit may have shrunk since the ledger's last sample.
            // Its old optimistic value must not become a permanent retry gate.
            status = sample_locked(true);
            job.failed_headroom = status.headroom + static_cast<std::int64_t>(job.committed + job.admission);
            failed_locked(job, total, status);
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
        cached_.headroom -= static_cast<std::int64_t>(wanted);
        if (job.admission && job.committed >= job.required) {
            // The observed dictionary workspace is now funded. Reconcile the
            // small allocations made while rebuilding it, then return the
            // temporary cushion so it cannot suppress useful concurrency.
            job.admission = 0;
            sample_locked(true);
        }
        return result;
    } catch (...) { retry(job); return nullptr; }
}
void NativeMemoryManager::released(NativeMemoryJob &job, void *address, std::size_t size) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    // Keep the OS release and ledger refund indivisible with respect to a
    // fresh sample; otherwise an intervening query could refund it twice.
    if (!VirtualFree(address, 0, MEM_RELEASE)) return;
    const auto bytes = commitment(size);
    job.committed -= bytes;
    cached_.headroom += static_cast<std::int64_t>(bytes);
    SetEvent(change_);
}
bool NativeMemoryManager::may_start_thread(NativeMemoryJob &job) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (job.revoked.load(std::memory_order_acquire)) return false;
    auto status = sample_locked();
    if (status.headroom + static_cast<std::int64_t>(job.admission) < 0) status = sample_locked(true);
    if (status.headroom + static_cast<std::int64_t>(job.admission) >= 0) return true;
    // No per-thread memory accounting. Avoid entering the Windows loader while
    // already under pressure; its initial stack growth cannot run our callbacks.
    job.denied.store(true, std::memory_order_release);
    failed_locked(job, job.committed + quantum, status);
    SetEvent(change_);
    return false;
}
void NativeMemoryManager::park(NativeMemoryJob &job, const std::atomic<bool> &cancel,
                               std::function<void(bool)> ready, WaitNotice notice) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!stopping_) {
            if (job.failed_headroom >= 0) job.failed_headroom -= static_cast<std::int64_t>(job.committed);
            if (job.retry_headroom != INT64_MAX) job.retry_headroom -= static_cast<std::int64_t>(job.committed);
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
        // reserve. Sampling is active-only; low-memory events bypass the cached
        // ledger immediately. Idle workers have no timer or polling activity.
        const auto event = WaitForMultipleObjects(count, handles, FALSE, active ? 250 : INFINITE);
        BOOL low = FALSE;
        if (low_) QueryMemoryResourceNotification(low_, &low);
        low_seen = low != FALSE;
        bool pressure;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sample_locked(event == WAIT_OBJECT_0 + 1 || event == WAIT_TIMEOUT);
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
            const auto status = sample_locked(pressure);
            if (!stopped && status.headroom < 0) {
                std::uint64_t retiring = 0;
                NativeMemoryJob *victim = nullptr;
                for (auto *job : jobs_) {
                    if (job->revoked.load(std::memory_order_acquire)) retiring += job->committed;
                    else if (job->running && job->committed && (!victim || victim->committed < job->committed)) victim = job;
                }
                if (victim && retiring < static_cast<std::uint64_t>(-status.headroom)) {
                    failed_locked(*victim, victim->committed, status);
                    revoke_locked(*victim);
                }
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
                const auto needed = job.required > job.committed ? job.required - job.committed : 0;
                // Replays also recreate their small codec/IO workspace. Do not
                // wake a whole wave using dictionary bytes alone. This is the
                // same coarse, measured per-credit cushion as the reserve;
                // ordinary task admission and CPU credits are unchanged.
                const auto reservation = needed > UINT64_MAX - small_workspace_bytes_per_credit
                    ? UINT64_MAX : needed + small_workspace_bytes_per_credit;
                const bool progressing = std::any_of(jobs_.begin(), jobs_.end(), [](const auto *other) {
                    return other->running || other->admission != 0;
                });
                // A failed mandatory allocation includes the dictionaries still
                // live at that point. An unclassified withdrawal may include
                // optional parallel storage: allow a budgeted probe after real
                // capacity grows by one managed-allocation quantum.
                const bool growth = available.headroom >= static_cast<std::int64_t>(quantum) &&
                    job.retry_headroom <= available.headroom - static_cast<std::int64_t>(quantum);
                // Always permit one otherwise-fitting task even if the extra
                // cushion cannot fit; the fixed reserve protects that probe.
                const bool fits = (can_fit(available.headroom, reservation) ||
                    (!progressing && can_fit(available.headroom, needed)) || growth) &&
                    (job.failed_headroom < 0 || available.headroom > job.failed_headroom);
                if (canceled || fits) {
                    if (!canceled) {
                        job.admission = (std::min)(reservation, static_cast<std::uint64_t>((std::max)(available.headroom, std::int64_t{0})));
                        jobs_.push_back(&job);
                    }
                    callbacks.push_back([waiter = std::move(waiter), available, canceled]() mutable {
                        if (waiter.announced && waiter.notice) waiter.notice(false, available, waiter.job->required);
                        waiter.ready(!canceled);
                    });
                    it = waiters_.erase(it);
                } else {
                    if (!waiter.announced && !progressing && waiter.notice) {
                        waiter.announced = true;
                        callbacks.push_back([notice = waiter.notice, available, needed = job.required] { notice(true, available, needed); });
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
    if ((reinterpret_cast<std::uintptr_t>(address) & 65535) != 0 || !address ||
        !allocations_ready.load(std::memory_order_acquire)) return 0;
    std::lock_guard<std::mutex> lock(allocations_mutex);
    const auto found = allocations.find(address);
    return found == allocations.end() ? 0 : found->second.size;
}
int sunpack_memory_free(void *address) {
    if ((reinterpret_cast<std::uintptr_t>(address) & 65535) != 0 || !address || bookkeeping ||
        !allocations_ready.load(std::memory_order_acquire)) return 0;
    Allocation allocation{};
    {
        std::lock_guard<std::mutex> lock(allocations_mutex);
        BookkeepingScope bookkeeping_scope;
        const auto found = allocations.find(address);
        if (found == allocations.end()) return 0;
        allocation = found->second;
        allocations.erase(found);
    }
    allocation.job->owner.released(*allocation.job, address, allocation.size);
    return 1;
}
}
