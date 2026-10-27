#pragma once
#include "decoder_memory.h"
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sunpack::sevenzip {

struct NativeMemoryStatus {
    std::int64_t headroom = 0; // after the worker reserve and unresident commit
    std::uint64_t available = 0;
    std::uint64_t reserve = 0;
};

class NativeMemoryManager;
struct NativeMemoryJob final {
    explicit NativeMemoryJob(NativeMemoryManager &owner) : owner(owner) {}
    NativeMemoryManager &owner;
    std::shared_ptr<std::atomic<bool>> cancel = std::make_shared<std::atomic<bool>>(false);
    std::atomic<bool> revoked{false};
    std::atomic<bool> denied{false};
    std::function<void()> wake;
    // The manager mutex protects all non-atomic fields.
    std::uint64_t committed = 0, peak = 0, admission = 0;
    std::uint64_t required = 0; // observed failed workspace, retained across early replay withdrawals
    std::int64_t failed_headroom = -1;
    std::int64_t retry_headroom = INT64_MAX;
    bool running = false, wake_pending = false;
};

// One arbitrator per worker. No Python scheduling or per-codec memory policy.
class NativeMemoryManager final {
public:
    using Query = std::function<NativeMemoryStatus()>;
    using WaitNotice = std::function<void(bool, const NativeMemoryStatus &, std::uint64_t)>;
    static constexpr std::uint64_t small_workspace_bytes_per_credit = 16ULL << 20;
    // Fixed recovery room plus the measured small-workspace growth per CPU
    // credit. Use nominal capacity, not live credits: releasing an attempt
    // must not lower its own recovery threshold or cause reserve oscillation.
    static constexpr std::uint64_t default_reserve_bytes(std::size_t cpu_credits = 1) noexcept {
        constexpr std::uint64_t base = 128ULL << 20, per_credit = small_workspace_bytes_per_credit;
        const auto credits = cpu_credits == 0 ? std::size_t{1} : cpu_credits;
        const auto maximum = (std::uint64_t{INT64_MAX} - base) / per_credit;
        return base + (credits > maximum ? maximum : credits) * per_credit;
    }
    explicit NativeMemoryManager(std::uint64_t reserve_bytes = default_reserve_bytes(), Query query = {},
                                 std::function<void()> reclaim = {});
    ~NativeMemoryManager();
    NativeMemoryManager(const NativeMemoryManager &) = delete;
    NativeMemoryManager &operator=(const NativeMemoryManager &) = delete;

    void begin(NativeMemoryJob &job, std::function<void()> wake = {});
    void set_wake(NativeMemoryJob &job, std::function<void()> wake);
    void end(NativeMemoryJob &job);
    void retry(NativeMemoryJob &job); // explicit allocation failure at the task boundary
    // Park without occupying an execution thread. The manager calls ready
    // outside its mutex; a resumed job already owns its next admission credit.
    void park(NativeMemoryJob &job, const std::atomic<bool> &cancel,
              std::function<void(bool)> ready, WaitNotice notice = {});
    void changed() noexcept;
    void stop() noexcept;
    void *allocate(NativeMemoryJob &job, std::size_t size) noexcept;
    bool may_start_thread(NativeMemoryJob &job) noexcept;
    void released(NativeMemoryJob &job, void *address, std::size_t size) noexcept;
    static NativeMemoryStatus query_windows(std::uint64_t reserve_bytes) noexcept;

private:
    NativeMemoryStatus sample_locked(bool fresh = false);
    void failed_locked(NativeMemoryJob &job, std::uint64_t required, const NativeMemoryStatus &status);
    void revoke_locked(NativeMemoryJob &job);
    void monitor();
    const std::uint64_t reserve_bytes_;
    Query query_;
    std::function<void()> reclaim_;
    std::mutex mutex_;
    std::vector<NativeMemoryJob *> jobs_;
    struct Waiter {
        NativeMemoryJob *job;
        const std::atomic<bool> *cancel;
        std::function<void(bool)> ready;
        WaitNotice notice;
        bool announced = false;
    };
    std::vector<Waiter> waiters_;
    HANDLE change_ = nullptr, low_ = nullptr, high_ = nullptr;
    std::thread thread_;
    bool stopping_ = false;
    bool reclaim_requested_ = false;
    NativeMemoryStatus cached_{};
    ULONGLONG sampled_at_ = 0;
    std::atomic<bool> resample_{true};
};

class NativeMemoryScope final {
public:
    explicit NativeMemoryScope(NativeMemoryJob *job) : previous_(sunpack_memory_exchange_context(job)) {}
    ~NativeMemoryScope() { sunpack_memory_exchange_context(previous_); }
private:
    void *previous_;
};
inline NativeMemoryJob *current_native_memory_job() noexcept {
    return static_cast<NativeMemoryJob *>(sunpack_memory_current_context());
}
}
