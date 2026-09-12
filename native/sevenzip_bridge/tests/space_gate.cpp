// L1：VolumeSpaceGate 纯逻辑单测（无文件系统、无满盘）。
//
// 用例编号与《SunPack Worker 磁盘空间不足自动暂停与恢复实现文档.md》§10.2 的
// G-1..G-26 一一对应。文档里没有的额外断言会标注 [附加]。
//
// 两个关键脚手架：
//   * unresolved_failed_path() —— 让 "Ready -> Blocked 时的新鲜查询" 确定性地失败，
//     从而可以精确控制 watermark_valid_ 与"第一次成功观测即 baseline"的语义。
//   * current_volume_key()    —— 本机临时目录所在物理卷的真实身份键，
//     覆盖 "resolved 卷" 一侧（尾反斜杠、构造时解析查询根）。

#include "internal/sevenzip_space_gate.hpp"
#include "internal/sevenzip_space_monitor.hpp"
#include "internal/sevenzip_volume_registry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32

namespace {

using sunpack::sevenzip::AsyncWriterConfig;
using sunpack::sevenzip::ProbeLease;
using sunpack::sevenzip::SpaceJobRegistration;
using sunpack::sevenzip::TerminalPredicate;
using sunpack::sevenzip::VolumeSpaceGate;
using sunpack::sevenzip::VolumeSpaceMonitor;
using sunpack::sevenzip::VolumeSpacePhase;
using sunpack::sevenzip::VolumeSpaceTransition;
using sunpack::sevenzip::VolumeStatePtr;
using sunpack::sevenzip::VolumeWriterRegistry;

using namespace std::chrono_literals;

std::atomic<int> g_failures{0};

bool check(bool condition, const std::string &what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << "\n";
        g_failures.fetch_add(1);
    }
    return condition;
}

constexpr std::uint64_t kMib = 1024ULL * 1024ULL;
constexpr std::uint64_t kGiB = 1024ULL * kMib;

// "没有可用的失败路径" —— 让 Ready→Blocked 时的**新鲜查询确定性地失败**，
// 从而可以精确控制 watermark_valid_ 与"第一次成功观测即 baseline"的语义。
//
// ⚠️ 不要用"随机不存在的 volume GUID 路径"来做这件事：本机实测
//    GetVolumePathNameW(`\\?\Volume{<随机 GUID>}\x.bin`) 有时会**成功**并返回
//    当前卷的挂载根（于是新鲜查询成功、watermark 变成真实可用空间），
//    测试会变成不确定的。空路径是唯一确定的做法。
std::wstring unresolved_failed_path() {
    return std::wstring{};
}

// 本机临时目录所在物理卷的身份键，形状与 Rust 的 volume_key_from() 一致
// （\\?\volume{...} 小写、无尾反斜杠）。
std::wstring current_volume_key() {
    wchar_t temp[MAX_PATH + 1]{};
    if (GetTempPathW(MAX_PATH, temp) == 0) {
        return {};
    }
    std::vector<wchar_t> mount(32768, L'\0');
    if (!GetVolumePathNameW(temp, mount.data(), static_cast<DWORD>(mount.size()))) {
        return {};
    }
    std::vector<wchar_t> name(32768, L'\0');
    if (!GetVolumeNameForVolumeMountPointW(mount.data(), name.data(),
                                           static_cast<DWORD>(name.size()))) {
        return {};
    }
    std::wstring key(name.data());
    while (!key.empty() && key.back() == L'\\') {
        key.pop_back();
    }
    std::transform(key.begin(), key.end(), key.begin(),
                   [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
    return key;
}

std::string to_ascii(const std::wstring &text) {
    std::string ascii;
    ascii.reserve(text.size());
    for (const wchar_t value : text) {
        ascii.push_back(static_cast<char>(value & 0x7F));
    }
    return ascii;
}

struct SinkLog {
    void record(const VolumeSpaceTransition &transition) {
        std::lock_guard<std::mutex> lock(mutex);
        transitions.push_back(transition);
    }
    std::vector<VolumeSpaceTransition> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex);
        return transitions;
    }
    std::size_t count(VolumeSpaceTransition::Kind kind) const {
        std::lock_guard<std::mutex> lock(mutex);
        return static_cast<std::size_t>(
            std::count_if(transitions.begin(), transitions.end(),
                          [kind](const VolumeSpaceTransition &item) { return item.kind == kind; }));
    }
    std::size_t total() const {
        std::lock_guard<std::mutex> lock(mutex);
        return transitions.size();
    }
    // 某个 job 在某一类事件里收到的条数。
    std::size_t count_for(VolumeSpaceTransition::Kind kind, const std::string &job_id) const {
        std::lock_guard<std::mutex> lock(mutex);
        std::size_t found = 0;
        for (const auto &item : transitions) {
            if (item.kind != kind) {
                continue;
            }
            if (std::find(item.job_ids.begin(), item.job_ids.end(), job_id) != item.job_ids.end()) {
                ++found;
            }
        }
        return found;
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mutex);
        transitions.clear();
    }

    mutable std::mutex mutex;
    std::vector<VolumeSpaceTransition> transitions;
};

std::shared_ptr<VolumeSpaceGate> make_gate(const std::string &key,
                                           const std::shared_ptr<SinkLog> &log,
                                           std::chrono::milliseconds wait_tick = 20ms) {
    return std::make_shared<VolumeSpaceGate>(
        key, std::string{},
        [log](const VolumeSpaceTransition &transition) { log->record(transition); },
        wait_tick);
}

bool wait_until(const std::function<bool()> &predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(2ms);
    }
    return predicate();
}

// 测试自身写错时应当**失败**而不是挂死：主线程里所有"期待 Probe"的 wait 都带上
// 一个到期即放弃的谓词。注意 wait() 先查 terminal、再查 Ready，所以只用在期待
// Probe 的场合（期待 Ready 的场合必须传空谓词，见 G-15）。
VolumeSpaceGate::WaitResult wait_bounded(const std::shared_ptr<VolumeSpaceGate> &gate,
                                         std::chrono::milliseconds timeout = 3s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    return gate->wait([deadline] { return std::chrono::steady_clock::now() >= deadline; });
}

// 让 lease 能在测试线程之间安全传递：lease 本身归 mutex，观察量用 atomic。
struct LeaseSlot {
    std::mutex mutex;
    ProbeLease lease;
    std::atomic<bool> taken{false};
    std::atomic<bool> ready{false};
    std::atomic<bool> terminal{false};
    std::atomic<int> probes{0};
};

void wait_and_keep(const std::shared_ptr<VolumeSpaceGate> &gate,
                   const std::shared_ptr<LeaseSlot> &slot) {
    // 线程内阻塞等待：**不加超时谓词**，否则会假造出 Terminal。
    const TerminalPredicate no_termination{};
    auto result = gate->wait(no_termination);
    switch (result.kind) {
    case VolumeSpaceGate::WaitResult::Kind::Probe: {
        std::lock_guard<std::mutex> lock(slot->mutex);
        if (!slot->taken.load()) {
            slot->lease = std::move(result.lease);
            slot->taken.store(true);
        }
        slot->probes.fetch_add(1);
        break;
    }
    case VolumeSpaceGate::WaitResult::Kind::Ready:
        slot->ready.store(true);
        break;
    case VolumeSpaceGate::WaitResult::Kind::Terminal:
        slot->terminal.store(true);
        break;
    }
}

// ---------------------------------------------------------------------------
// G-1 初始状态
// ---------------------------------------------------------------------------
void g1_initial_state() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g1", log);

    check(gate->phase() == VolumeSpacePhase::Ready, "G-1: 初始 phase 必须是 Ready");
    check(gate->episode_id() == 0, "G-1: 初始 episode_id 必须是 0");
    check(!gate->blocked(), "G-1: 初始 blocked() 必须为 false");
    check(!gate->watermark_valid(), "G-1: 初始 watermark_valid() 必须为 false");

    const auto result = gate->wait(TerminalPredicate{});
    check(result.kind == VolumeSpaceGate::WaitResult::Kind::Ready,
          "G-1: Ready 卷上的 wait() 必须返回 Kind::Ready（不是 Terminal）");
    check(!result.lease.valid(), "G-1: Ready 不持有 probe 许可");
    check(log->total() == 0, "G-1: 初始不应产生任何事件");
}

// ---------------------------------------------------------------------------
// G-2 首次失败
// ---------------------------------------------------------------------------
void g2_first_failure_opens_episode() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g2", log);

    check(gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path()),
          "G-2: 首次空间失败必须开启新 episode");
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-2: 首次失败后必须是 Blocked");
    check(gate->episode_id() == 1, "G-2: episode_id 必须是 1");
    check(gate->blocked(), "G-2: blocked() 必须为 true");
    check(log->count(VolumeSpaceTransition::Kind::Blocked) == 1,
          "G-2: 必须发出 1 条 space_blocked");
    const auto transitions = log->snapshot();
    check(!transitions.empty() && transitions.front().episode_id == 1,
          "G-2: space_blocked 必须携带当前 episode_id");
    check(!transitions.empty() && transitions.front().win32_error == ERROR_DISK_FULL,
          "G-2: space_blocked 必须携带原始 Win32 错误码");
    check(!transitions.empty() && transitions.front().volume_key == "job:g2",
          "G-2: space_blocked 必须携带卷身份键");
}

// ---------------------------------------------------------------------------
// G-3 水位不足不 probe
// ---------------------------------------------------------------------------
void g3_no_probe_below_watermark() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g3", log);
    const auto unresolvable = unresolved_failed_path();

    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    check(gate->poll(200 * kMib), "G-3: watermark 无效时第一次 poll 必须发放许可");
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-3: 应拿到 probe 许可");
        result.lease.report_inconclusive(); // → Blocked，watermark 保持 200 MiB
    }
    check(gate->failed_free_watermark() == 200 * kMib, "G-3: baseline 必须是 200 MiB");

    check(!gate->poll(100 * kMib), "G-3: 低于 watermark 时不得发放许可");
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-3: 仍必须是 Blocked");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0, "G-3: 不得发出 space_resumed");
}

// ---------------------------------------------------------------------------
// G-4 水位改善 → probe（两个等待线程只有一个拿到有效 lease）
// ---------------------------------------------------------------------------
void g4_improved_watermark_issues_single_probe() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g4", log);
    const auto unresolvable = unresolved_failed_path();

    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->poll(200 * kMib); // baseline = 200 MiB
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-4: 需先占住第一次许可");
        result.lease.report_inconclusive();
    }

    check(!gate->poll(200 * kMib), "G-4: 水位没改善时不得发放许可");
    check(gate->poll(300 * kMib), "G-4: 水位改善后必须发放许可");
    check(gate->phase() == VolumeSpacePhase::Probing, "G-4: 必须进入 Probing");

    auto slot = std::make_shared<LeaseSlot>();
    std::thread first(wait_and_keep, gate, slot);
    std::thread second(wait_and_keep, gate, slot);
    check(wait_until([&] { return slot->probes.load() >= 1; }, 2s),
          "G-4: 必须有一个线程拿到许可");
    check(wait_until([&] { return gate->waiter_count() >= 1; }, 2s),
          "G-4: 另一个线程必须留在 waiters_ 里");
    check(slot->probes.load() == 1, "G-4: 只能有一个等待线程拿到有效 lease");

    {
        std::lock_guard<std::mutex> lock(slot->mutex);
        slot->lease.report_success();
    }
    first.join();
    second.join();
    check(gate->phase() == VolumeSpacePhase::Ready, "G-4: probe 成功后必须 Ready");
    check(gate->waiter_count() == 0, "G-4: 全部等待者必须离开");
    check(slot->ready.load(), "G-4: 另一个线程必须被唤醒并返回 Ready");
}

// ---------------------------------------------------------------------------
// G-5 probe 成功
// ---------------------------------------------------------------------------
void g5_probe_success_resumes_everyone() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g5", log);
    const auto unresolvable = unresolved_failed_path();

    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->register_job("J");
    gate->poll(500 * kMib);

    // 主线程先抢到许可，保证另一个线程只能等待"恢复"。
    auto slot = std::make_shared<LeaseSlot>();
    ProbeLease owner;
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-5: 主线程必须拿到许可");
        owner = std::move(result.lease);
    }

    std::atomic<int> ready_count{0};
    std::thread waiter([&] {
        auto result = wait_bounded(gate);
        if (result.kind == VolumeSpaceGate::WaitResult::Kind::Ready) {
            ready_count.fetch_add(1);
        }
    });
    check(wait_until([&] { return gate->waiter_count() >= 1; }, 2s), "G-5: 等待者必须进入 waiters_");

    const std::uint64_t episode_before = gate->episode_id();
    owner.report_success();
    waiter.join();

    check(gate->phase() == VolumeSpacePhase::Ready, "G-5: 必须回到 Ready");
    check(ready_count.load() == 1, "G-5: 全部等待者必须被唤醒并返回 Ready");
    check(gate->episode_id() == episode_before, "G-5: probe 成功不得改变 episode_id");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 1,
          "G-5: 必须发出 1 条 space_resumed");
    check(log->count_for(VolumeSpaceTransition::Kind::Resumed, "J") == 1,
          "G-5: space_resumed 必须扇出给 affected job");
}

// ---------------------------------------------------------------------------
// G-6 probe 失败 → 水位单调（仅本 episode）
// ---------------------------------------------------------------------------
void g6_failed_probe_keeps_watermark_monotonic() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g6", log);
    const auto unresolvable = unresolved_failed_path();

    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->poll(500 * kMib); // baseline = 500 MiB
    const std::size_t blocked_before = log->count(VolumeSpaceTransition::Kind::Blocked);
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-6: 必须拿到许可");
        // 新鲜查询在本次仍会失败（同一不可解析路径）→ watermark 必须保持不变。
        result.lease.report_space_failure(ERROR_DISK_FULL, unresolvable);
    }

    check(gate->phase() == VolumeSpacePhase::Blocked, "G-6: probe 失败必须回到 Blocked");
    check(gate->failed_free_watermark() == 500 * kMib,
          "G-6: 新鲜查询失败时 watermark 必须保持不变");
    check(gate->watermark_valid(), "G-6: watermark 必须仍然有效");
    check(log->count(VolumeSpaceTransition::Kind::Blocked) == blocked_before,
          "G-6: 同一 episode 内的 probe 失败不得产生新事件");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-6: probe 失败绝不得发出 space_resumed");

    // [附加] resolved 卷上的 probe 失败会做一次成功的新鲜查询 → watermark 取 max。
    auto resolved_log = std::make_shared<SinkLog>();
    auto resolved = make_gate(to_ascii(current_volume_key()), resolved_log);
    check(resolved->query_root_resolved(), "G-6[附加]: resolved 卷的查询根必须已在构造时解析");
    resolved->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(resolved->watermark_valid(), "G-6[附加]: resolved 卷的新鲜查询应成功");
    const std::uint64_t baseline = resolved->failed_free_watermark();
    check(resolved->poll(baseline + 1), "G-6[附加]: 高于水位必须发放许可");
    {
        auto result = wait_bounded(resolved);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-6[附加]: 必须拿到许可");
        result.lease.report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    }
    check(resolved->failed_free_watermark() >= baseline,
          "G-6[附加]: probe 失败后 watermark 只能单调不减");
}

// ---------------------------------------------------------------------------
// G-7 前次 lease 未结算时不得再发放许可
// ---------------------------------------------------------------------------
void g7_no_second_permit_while_probing() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g7", log);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(gate->poll(100 * kMib), "G-7: 第一次 poll 必须发放许可");
    check(!gate->poll(100 * kGiB), "G-7: 许可未结算时不得发放第二个许可");
    check(gate->phase() == VolumeSpacePhase::Probing, "G-7: 仍必须是 Probing");

    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-7: 拿到许可");
        result.lease.report_inconclusive();
    }
    check(gate->poll(100 * kGiB), "G-7: 许可结算后必须能再次发放");
}

// ---------------------------------------------------------------------------
// G-8 幂等上报
// ---------------------------------------------------------------------------
void g8_concurrent_failures_open_one_episode() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g8", log);
    const auto unresolvable = unresolved_failed_path();

    std::vector<std::thread> threads;
    for (int index = 0; index < 4; ++index) {
        threads.emplace_back([gate, unresolvable] {
            gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    check(gate->episode_id() == 1, "G-8: 4 个线程并发的失败只能推进一次 episode");
    check(log->count(VolumeSpaceTransition::Kind::Blocked) == 1,
          "G-8: sink 只能被调用一次");
}

// ---------------------------------------------------------------------------
// G-9 wake_waiters()
// ---------------------------------------------------------------------------
void g9_wake_waiters_does_not_change_state() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g9", log, 20ms);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());

    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::atomic<bool> returned_terminal{false};
    std::thread waiter([&] {
        auto result = gate->wait([stop] { return stop->load(std::memory_order_acquire); });
        if (result.kind == VolumeSpaceGate::WaitResult::Kind::Terminal) {
            returned_terminal.store(true);
        }
    });
    check(wait_until([&] { return gate->waiter_count() >= 1; }, 2s),
          "G-9: 等待者必须进入 waiters_");

    gate->wake_waiters();
    std::this_thread::sleep_for(100ms);
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-9: wake_waiters 不得改变状态");
    check(gate->waiter_count() >= 1, "G-9: predicate 为假的等待者必须继续等待");
    check(!returned_terminal.load(), "G-9: predicate 为假时不得返回 Terminal");

    stop->store(true, std::memory_order_release);
    gate->wake_waiters();
    waiter.join();
    check(returned_terminal.load(), "G-9: predicate 为真后必须返回 Terminal");
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-9: 等待者离开后仍必须是 Blocked");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-9: 等待者离开绝不等于已恢复");
    check(gate->waiter_count() == 0, "G-9: waiters_ 必须清空");
}

// ---------------------------------------------------------------------------
// G-10 terminal predicate
// ---------------------------------------------------------------------------
void g10_terminal_predicate_is_honoured() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g10", log, 20ms);
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());

    auto flag = std::make_shared<std::atomic<bool>>(false);
    std::atomic<bool> saw_terminal{false};
    const auto started = std::chrono::steady_clock::now();
    std::thread waiter([&] {
        auto result = gate->wait([flag] { return flag->load(std::memory_order_acquire); });
        saw_terminal.store(result.kind == VolumeSpaceGate::WaitResult::Kind::Terminal);
    });
    check(wait_until([&] { return gate->waiter_count() >= 1; }, 2s),
          "G-10: 等待者必须先阻塞");
    std::this_thread::sleep_for(60ms);
    flag->store(true, std::memory_order_release);
    gate->wake_waiters();
    waiter.join();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    check(saw_terminal.load(), "G-10: 谓词为真时必须返回 Terminal");
    check(elapsed < 1s, "G-10: 必须在 poll_interval 量级内返回");
}

// ---------------------------------------------------------------------------
// G-11 lease 析构兜底
// ---------------------------------------------------------------------------
void g11_lease_destructor_is_inconclusive() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g11", log, 20ms);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    gate->poll(100 * kMib);
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-11: 必须拿到许可");
        // 什么都不做，直接析构。
    }
    check(gate->phase() == VolumeSpacePhase::Blocked,
          "G-11: 未结算的 lease 析构后必须是 Blocked（不是 Ready）");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-11: 未结算的 lease 析构不得发出 space_resumed");
    check(gate->poll(200 * kMib), "G-11: 许可必须已释放，下一个 poll 能再发放");
}

// ---------------------------------------------------------------------------
// G-12 waiter 全部离开 ≠ Ready
// ---------------------------------------------------------------------------
void g12_all_waiters_leaving_is_not_ready() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g12", log, 20ms);
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());

    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::vector<std::thread> waiters;
    for (int index = 0; index < 3; ++index) {
        waiters.emplace_back(
            [&] { gate->wait([stop] { return stop->load(std::memory_order_acquire); }); });
    }
    check(wait_until([&] { return gate->waiter_count() == 3; }, 2s),
          "G-12: 3 个等待者必须全部阻塞");
    stop->store(true, std::memory_order_release);
    gate->wake_waiters();
    for (auto &thread : waiters) {
        thread.join();
    }

    check(gate->phase() == VolumeSpacePhase::Blocked, "G-12: 等待者全部离开后仍必须是 Blocked");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-12: 不得发出 space_resumed");
    check(gate->episode_id() == 1, "G-12: episode_id 不得变化");
}

// ---------------------------------------------------------------------------
// G-13 affected_jobs_ 与 waiters_ 分离
// ---------------------------------------------------------------------------
void g13_event_fanout_uses_affected_jobs() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g13", log);

    // ① 注册 job 后**没有**任何 waiter 时报满 → 该 job 仍必须收到 space_blocked。
    gate->register_job("A");
    check(gate->waiter_count() == 0, "G-13: 此时不应有任何 waiter");
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "A") == 1,
          "G-13: 没有 waiter 时 affected job 仍必须收到 space_blocked");

    // ② job 抢到 probe 并成功 → 它**仍必须**收到 space_resumed
    //    （它已经从 waiters_ 里被移除，所以遍历 waiters_ 会漏掉它）。
    gate->poll(500 * kMib);
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-13: 必须拿到许可");
        result.lease.report_success();
    }
    check(log->count_for(VolumeSpaceTransition::Kind::Resumed, "A") == 1,
          "G-13: probe owner 必须收到 space_resumed");
}

// ---------------------------------------------------------------------------
// G-14 注册时补发
// ---------------------------------------------------------------------------
void g14_registration_on_blocked_volume_replays() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g14", log);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(gate->register_job("B"), "G-14: 注册必须成功");
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "B") == 1,
          "G-14: 卷已 Blocked 时注册必须立即补发一条 space_blocked");
    const auto transitions = log->snapshot();
    check(!transitions.empty() && transitions.back().episode_id == gate->episode_id(),
          "G-14: 补发的事件必须携带当前 episode_id");

    // Probing 也必须补发（UI 要知道 job 已被卷状态影响）。
    log->clear();
    gate->poll(500 * kMib);
    check(gate->phase() == VolumeSpacePhase::Probing, "G-14: 必须进入 Probing");
    gate->register_job("C");
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "C") == 1,
          "G-14: Probing 期间注册同样必须补发");
}

// ---------------------------------------------------------------------------
// G-15 Ready/Terminal 可区分（R7 的数据正确性 bug）
// ---------------------------------------------------------------------------
void g15_ready_and_terminal_are_distinguishable() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g15", log);

    // 复现：writer A 报满 → 在 A 真正进入 wait() 之前，writer B 完成 probe → Ready
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    gate->poll(500 * kMib);
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-15: B 拿到许可");
        result.lease.report_success();
    }
    check(gate->phase() == VolumeSpacePhase::Ready, "G-15: B 已把卷恢复");

    // A 现在才进入 wait()：必须得到 Ready（可重试），**绝不能**被误判为取消。
    auto late = gate->wait(TerminalPredicate{});
    check(late.kind == VolumeSpaceGate::WaitResult::Kind::Ready,
          "G-15: 迟到的等待者必须拿到 Kind::Ready，不是 Terminal");
    check(!late.lease.valid(), "G-15: Ready 不携带许可");

    // 同一个 gate，在谓词为真时必须是 Terminal —— 两者可区分。
    auto terminal = gate->wait([] { return true; });
    check(terminal.kind == VolumeSpaceGate::WaitResult::Kind::Terminal,
          "G-15: 谓词为真时必须返回 Kind::Terminal");
}

// ---------------------------------------------------------------------------
// G-16 report_inconclusive()
// ---------------------------------------------------------------------------
void g16_inconclusive_probe_never_resumes() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g16", log);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    gate->poll(500 * kMib);
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-16: 必须拿到许可");
        result.lease.report_inconclusive();
    }
    check(gate->phase() == VolumeSpacePhase::Blocked,
          "G-16: 非空间错误不能证明卷可写 → 必须回 Blocked");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-16: 绝不发 space_resumed");
    check(gate->episode_id() == 1, "G-16: episode_id 不得变化");
}

// ---------------------------------------------------------------------------
// G-17 episode 切换重置 watermark（R9）
// ---------------------------------------------------------------------------
void g17_episode_switch_resets_watermark() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g17", log);
    const auto unresolvable = unresolved_failed_path();

    // ep1：水位 500 MiB（初期查询失败 → 第一次 poll 建立 baseline）。
    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->poll(500 * kMib);
    check(gate->failed_free_watermark() == 500 * kMib, "G-17: ep1 水位 500 MiB");
    {
        auto result = wait_bounded(gate);
        result.lease.report_success(); // 恢复
    }
    check(gate->phase() == VolumeSpacePhase::Ready, "G-17: ep1 已恢复");

    // ep2：失败时 free = 10 MiB → 水位必须是 10 MiB，**不是** 500 MiB。
    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    check(gate->episode_id() == 2, "G-17: 必须是第 2 个 episode");
    check(!gate->watermark_valid() && gate->failed_free_watermark() == 0,
          "G-17: 新 episode 开启时必须先作废旧水位");
    check(gate->poll(10 * kMib),
          "G-17: 新 episode 的第一次成功观测必须建立 baseline 并发放许可");
    check(gate->failed_free_watermark() == 10 * kMib,
          "G-17: ep2 水位必须是 10 MiB（不是 500 MiB）");
}

// ---------------------------------------------------------------------------
// G-18 新鲜查询失败则 watermark 无效（R9）
// ---------------------------------------------------------------------------
void g18_failed_fresh_query_leaves_watermark_invalid() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g18", log);
    const auto unresolvable = unresolved_failed_path();

    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    check(!gate->watermark_valid(), "G-18: Ready→Blocked 时查询失败 → watermark 无效");
    check(!gate->query_root_resolved(), "G-18: 查询路径必须仍未解析");
    check(gate->last_query_error() != 0, "G-18: 必须记录查询错误码供诊断");

    // 此时 poll 不做水位比较；第一次成功观测即 baseline，并允许一次 probe。
    check(gate->poll(100 * kMib), "G-18: watermark 无效时第一次 poll 必须发放许可");
    check(gate->watermark_valid(), "G-18: 该次观测成为 baseline");
    check(gate->failed_free_watermark() == 100 * kMib, "G-18: baseline 必须是该观测值");

    // 再 poll 同样的值：不再是"首次"，必须拒绝。
    {
        auto result = wait_bounded(gate);
        result.lease.report_inconclusive();
    }
    check(!gate->poll(100 * kMib), "G-18: 相同观测值不得再次发放许可");
}

// ---------------------------------------------------------------------------
// G-19 query_root 解析
// ---------------------------------------------------------------------------
void g19_query_root_resolution() {
    // ① resolved 卷：查询路径就是 key + "\"。
    const std::wstring volume_key = current_volume_key();
    if (volume_key.empty()) {
        check(false, "G-19: 无法取得本机卷身份键");
        return;
    }
    auto resolved = make_gate(to_ascii(volume_key), std::make_shared<SinkLog>());
    check(resolved->query_root_resolved(), "G-19: resolved 卷的查询根必须已在构造时解析");

    std::uint64_t free_bytes = 0;
    std::uint64_t total_bytes = 0;
    check(resolved->query_free_bytes(&free_bytes, &total_bytes),
          "G-19: resolved 卷必须可直接查询");
    check(total_bytes > 0, "G-19: 卷总容量必须为正");
    check(free_bytes <= total_bytes, "G-19: 可用空间不得超过总容量");

    // ★ 尾反斜杠不是装饰：去掉它 GetDiskFreeSpaceExW 会以 ERROR_INVALID_FUNCTION 失败。
    //   （§16.1 的真机实测结论，这里作为回归防线固定下来。）
    std::uint64_t ignored_free = 0;
    std::uint64_t ignored_total = 0;
    check(!sunpack::sevenzip::query_volume_free_bytes(volume_key, &ignored_free, &ignored_total),
          "G-19: 身份键本身（无尾反斜杠）不得可查询 —— 否则 space_query_path 就是多余的");
    check(sunpack::sevenzip::query_volume_free_bytes(
              sunpack::sevenzip::space_query_path(volume_key), &ignored_free, &ignored_total),
          "G-19: space_query_path(key) 必须可查询");
    check(sunpack::sevenzip::is_volume_guid_key(volume_key),
          "G-19: 小写的 \\\\?\\volume{...} 必须被识别为卷 GUID 键（前缀比较须大小写不敏感）");

    // ② synthetic 卷：首次 report_space_failure(err, failed_path) 后就地解析并缓存。
    auto synthetic = make_gate("job:g19", std::make_shared<SinkLog>());
    check(!synthetic->query_root_resolved(), "G-19: synthetic 卷构造时不得有查询根");
    check(!synthetic->query_free_bytes(&free_bytes, &total_bytes),
          "G-19: 未解析前查询必须失败（→ monitor 走 B5 分支）");

    wchar_t temp[MAX_PATH + 1]{};
    const DWORD temp_length = GetTempPathW(MAX_PATH, temp);
    std::wstring probe_path = temp;
    probe_path += L"sunpack-space-gate-probe.bin";
    synthetic->report_space_failure(ERROR_DISK_FULL, probe_path);
    check(synthetic->query_root_resolved(), "G-19: synthetic 卷必须在首次失败时就地解析");
    const bool synthetic_query_ok = synthetic->query_free_bytes(&free_bytes, &total_bytes);
    if (!synthetic_query_ok) {
        std::cerr << "DEBUG G-19: temp_length=" << temp_length << " probe=" << to_ascii(probe_path)
                  << " last_query_error=" << synthetic->last_query_error() << "\n";
    }
    check(synthetic_query_ok, "G-19: 解析后必须可查询");
}

// ---------------------------------------------------------------------------
// G-20 只有真实成功才 Ready
// ---------------------------------------------------------------------------
void g20_only_real_success_resumes() {
    auto log = std::make_shared<SinkLog>();
    // 用 resolved 卷：新鲜查询成功 → watermark 立即有效，因此
    // "反复 poll 但水位不改善" 才是可构造的（watermark 无效时第一次 poll 必发许可）。
    auto gate = make_gate(to_ascii(current_volume_key()), log, 20ms);

    gate->register_job("A");
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(gate->watermark_valid(), "G-20: resolved 卷的新鲜查询应成功建立水位");
    const std::uint64_t baseline = gate->failed_free_watermark();

    // 组合一：反复 poll 但水位不改善。
    for (int index = 0; index < 3; ++index) {
        gate->poll(0);
        gate->poll(1);
    }
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-20: 水位不改善时不得发放许可");

    // 组合二：真实探测给出非空间结论（report_inconclusive）。
    check(gate->poll(baseline + 2), "G-20: 高于水位必须发放一次许可");
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-20: 必须拿到许可");
        result.lease.report_inconclusive();
    }
    check(gate->phase() == VolumeSpacePhase::Blocked, "G-20: inconclusive 必须回 Blocked");

    // 组合三：取消最后一个 waiter。
    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread waiter(
        [&] { gate->wait([stop] { return stop->load(std::memory_order_acquire); }); });
    check(wait_until([&] { return gate->waiter_count() >= 1; }, 2s), "G-20: 等待者必须阻塞");
    stop->store(true, std::memory_order_release);
    gate->wake_waiters();
    waiter.join();

    check(gate->phase() != VolumeSpacePhase::Ready,
          "G-20: 任何组合都不得把卷推进到 Ready");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "G-20: 全程不得发出 space_resumed");
}

// ---------------------------------------------------------------------------
// G-21 lease token 所有权
// ---------------------------------------------------------------------------
void g21_lease_token_ownership() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g21", log);
    const auto unresolvable = unresolved_failed_path();

    // ① 结算过的 lease 再次结算必须是 no-op（不得把状态改回去、不得重复发事件）。
    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->poll(500 * kMib);
    ProbeLease owner;
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-21: 必须拿到许可");
        owner = std::move(result.lease);
    }
    check(owner.valid(), "G-21: 结算前 lease 必须有效");
    owner.report_success();
    check(gate->phase() == VolumeSpacePhase::Ready, "G-21: 合法 owner 的结算推进到 Ready");
    check(!owner.valid(), "G-21: 结算后 lease 必须失效");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 1, "G-21: 只产生 1 条 resumed");

    // stale lease 的重复结算：状态与事件都不得变化。
    owner.report_success();
    owner.report_space_failure(ERROR_DISK_FULL, unresolvable);
    owner.report_inconclusive();
    check(gate->phase() == VolumeSpacePhase::Ready, "G-21: stale lease 重复结算必须是 no-op");
    check(log->count(VolumeSpaceTransition::Kind::Resumed) == 1, "G-21: 不得重复发事件");
    check(log->count(VolumeSpaceTransition::Kind::Blocked) == 1, "G-21: 不得发新的 blocked");

    // ② move 之后原对象持有的许可必须已转移（原对象不可再结算）。
    gate->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate->poll(600 * kMib);
    ProbeLease first_owner;
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-21: 第二个许可");
        first_owner = std::move(result.lease);
    }
    ProbeLease moved = std::move(first_owner);
    check(!first_owner.valid(), "G-21: move 之后原对象必须失效");
    first_owner.report_success();
    check(gate->phase() == VolumeSpacePhase::Probing,
          "G-21: 已被 move 走的 lease 不得结算");
    moved.report_success();
    check(gate->phase() == VolumeSpacePhase::Ready, "G-21: 新 holder 才能结算");

    // ③ Probing 期间旁路 report_space_failure 不得夺走 ownership。
    auto log2 = std::make_shared<SinkLog>();
    auto gate2 = make_gate("job:g21b", log2);
    gate2->report_space_failure(ERROR_DISK_FULL, unresolvable);
    gate2->poll(500 * kMib);
    ProbeLease late_owner;
    {
        auto result = wait_bounded(gate2);
        late_owner = std::move(result.lease);
    }
    const std::size_t blocked_before = log2->count(VolumeSpaceTransition::Kind::Blocked);
    gate2->report_space_failure(ERROR_DISK_FULL, unresolvable); // 旁路 late failure
    check(gate2->phase() == VolumeSpacePhase::Probing,
          "G-21: 旁路失败不得改变 Probing 状态");
    check(log2->count(VolumeSpaceTransition::Kind::Blocked) == blocked_before,
          "G-21: 旁路失败不得产生事件");
    late_owner.report_success();
    check(gate2->phase() == VolumeSpacePhase::Ready,
          "G-21: 旁路 late failure 不得把 owner 的成功打成 Blocked");
}

// ---------------------------------------------------------------------------
// G-22 affected_jobs_ set 语义
// ---------------------------------------------------------------------------
void g22_affected_jobs_set_semantics() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g22", log);

    // ① 空 job_id 不注册。
    check(!gate->register_job(""), "G-22: 空 job_id 不得注册");
    check(gate->affected_job_ids().empty(), "G-22: 集合必须仍为空");

    // ② 同一 id 注册两次 → 集合只有一项。
    gate->register_job("J");
    check(!gate->register_job("J"), "G-22: 重复注册必须是 no-op");
    check(gate->affected_job_ids().size() == 1, "G-22: 集合只能有一项");

    // 已 Blocked 时重复注册也只补发一条。
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "J") == 1,
          "G-22: Blocked 后首次注册补发一条");
    check(!gate->register_job("J"), "G-22: 再次注册仍是 no-op");
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "J") == 1,
          "G-22: 重复注册绝不产生第二条 space_blocked");

    // ③ unregister 清空该 id 的全部匹配项。
    gate->register_job("K");
    check(gate->affected_job_ids().size() == 2, "G-22: 现在应为 2 项");
    gate->unregister_job("J");
    const auto remaining = gate->affected_job_ids();
    check(remaining.size() == 1 && remaining.front() == "K",
          "G-22: unregister 必须清空该 id 的全部匹配项");
    gate->unregister_job("K");
    check(gate->affected_job_ids().empty(), "G-22: 全部注销后集合为空");
}

// ---------------------------------------------------------------------------
// G-23 poll() 独占水位逻辑
// ---------------------------------------------------------------------------
void g23_poll_owns_all_watermark_logic() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g23", log);

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(!gate->watermark_valid(), "G-23: 初期查询失败 → watermark 无效");

    // 第一次 poll(100 MiB) 必须发放许可（不能因为 100 > 100 为假而卡住）。
    check(gate->poll(100 * kMib), "G-23: 第一次 poll 必须立即建立 baseline 并发放许可");
    check(gate->failed_free_watermark() == 100 * kMib, "G-23: baseline 必须是 100 MiB");
    // 紧接着第二次 poll(100 MiB) 不得再发放。
    check(!gate->poll(100 * kMib), "G-23: 第二次 poll 不得再发放许可");
}

// ---------------------------------------------------------------------------
// G-24 sticky hint
// ---------------------------------------------------------------------------
void g24_sticky_hint_survives_recovery() {
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g24", log);

    auto states = std::make_shared<std::vector<VolumeStatePtr>>();
    auto state = sunpack::sevenzip::make_volume_state("job:g24", false);
    state->space_gate = gate;
    states->push_back(state);

    VolumeSpaceMonitor monitor(VolumeSpaceMonitor::Options{5ms, 5ms},
                               [states] { return *states; },
                               VolumeSpaceMonitor::StatusSink{});
    check(!monitor.ever_had_blocked(), "G-24: 初始必须是 false");

    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    const auto now = std::chrono::steady_clock::now();
    monitor.tick(now);
    check(monitor.ever_had_blocked(), "G-24: 观测到 blocked 卷后必须点亮");

    // A 卷恢复 → sticky hint **必须仍为 true**（否则多卷场景下 B 永不再被 poll）。
    gate->poll(500 * kMib);
    {
        auto result = wait_bounded(gate);
        result.lease.report_success();
    }
    check(gate->phase() == VolumeSpacePhase::Ready, "G-24: 卷已恢复");
    states->clear(); // 恢复后不再出现在 blocked_volumes() 里
    monitor.tick(now + 100ms);
    check(monitor.ever_had_blocked(), "G-24: sticky hint 在卷恢复后必须仍为 true");
}

// ---------------------------------------------------------------------------
// G-25 双卷恢复独立性（sticky 替换精确 bool 的直接回归测试）
// ---------------------------------------------------------------------------
void g25_two_volumes_recover_independently() {
    auto log_a = std::make_shared<SinkLog>();
    auto log_b = std::make_shared<SinkLog>();
    auto gate_a = make_gate("job:g25-a", log_a);
    auto gate_b = make_gate("job:g25-b", log_b);

    auto state_a = sunpack::sevenzip::make_volume_state("job:g25-a", false);
    auto state_b = sunpack::sevenzip::make_volume_state("job:g25-b", false);
    state_a->space_gate = gate_a;
    state_b->space_gate = gate_b;

    auto blocked = std::make_shared<std::vector<VolumeStatePtr>>();
    blocked->push_back(state_a);
    blocked->push_back(state_b);

    auto status_seen_b = std::make_shared<std::atomic<bool>>(false);
    auto status_calls = std::make_shared<std::atomic<int>>(0);
    VolumeSpaceMonitor monitor(
        VolumeSpaceMonitor::Options{5ms, 5ms},
        [blocked] { return *blocked; },
        [status_seen_b, status_calls](const VolumeStatePtr &state, std::uint64_t, std::uint64_t,
                                      bool, unsigned long) {
            status_calls->fetch_add(1);
            if (state && state->key == "job:g25-b") {
                status_seen_b->store(true);
            }
        });

    gate_a->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    gate_b->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());

    auto now = std::chrono::steady_clock::now();
    monitor.tick(now);
    // 采样器只提供数值；这里直接驱动 gate 的许可，模拟"水位已改善"。
    check(gate_a->poll(100 * kMib), "G-25: A 必须能发放许可");
    check(gate_b->poll(100 * kMib), "G-25: B 必须能发放许可");

    {
        auto result = wait_bounded(gate_a);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-25: A 必须先拿到许可");
        result.lease.report_success(); // A 先恢复
    }
    check(gate_a->phase() == VolumeSpacePhase::Ready, "G-25: A 已恢复");
    check(gate_b->phase() == VolumeSpacePhase::Probing, "G-25: B 仍有待结算的许可");

    // A 离开 blocked 集合，只剩 B。
    blocked->clear();
    blocked->push_back(state_b);
    status_seen_b->store(false);
    status_calls->store(0);

    // 旧设计会在这里因为 has_blocked_ 被清零而直接 return → B 永远不再被 poll。
    check(monitor.ever_had_blocked(), "G-25: A 恢复后 sticky hint 必须仍为 true");
    monitor.tick(now + 100ms);
    check(status_seen_b->load(), "G-25: A 恢复之后 B 必须仍被采样");
    check(status_calls->load() >= 1, "G-25: monitor 必须仍在工作");

    // B 之后释放空间必须仍能恢复。
    {
        auto result = wait_bounded(gate_b);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-25: B 必须仍可结算");
        result.lease.report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    }
    check(gate_b->poll(999 * kMib), "G-25: B 水位改善后必须能再发放许可");
    {
        auto result = wait_bounded(gate_b);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-25: B 拿到许可");
        result.lease.report_success();
    }
    check(gate_b->phase() == VolumeSpacePhase::Ready, "G-25: B 后释放空间时必须仍能恢复");
}

// ---------------------------------------------------------------------------
// G-26 registration 覆盖根目录创建
// ---------------------------------------------------------------------------
void g26_registration_covers_root_directory_creation() {
    // 「不创建任何 JobState」：直接按 volume lease scope 的方式注册。
    auto log = std::make_shared<SinkLog>();
    auto gate = make_gate("job:g26", log);

    check(gate->register_job("J"), "G-26: 注册必须成功");
    gate->report_space_failure(ERROR_DISK_FULL, unresolved_failed_path());
    check(log->count_for(VolumeSpaceTransition::Kind::Blocked, "J") == 1,
          "G-26: 根目录创建期间的满盘必须能送达 job J");

    // 注销后同一 episode 的新事件不再发给 J。
    gate->unregister_job("J");
    log->clear();
    check(gate->poll(500 * kMib), "G-26: 水位改善后必须发放许可");
    {
        auto result = wait_bounded(gate);
        check(result.kind == VolumeSpaceGate::WaitResult::Kind::Probe, "G-26: 拿到许可");
        result.lease.report_success();
    }
    check(log->count_for(VolumeSpaceTransition::Kind::Resumed, "J") == 0,
          "G-26: 注销后不得再收到事件");

    // SpaceJobRegistration 的 RAII 语义（含"lease 之后声明 ⇒ 先析构"的约束）。
    AsyncWriterConfig config;
    config.space_gate_enabled = true;
    config.threads_per_volume = 1;
    config.buffer_count = 4;
    auto registry = std::make_shared<VolumeWriterRegistry>(
        std::make_shared<sunpack::sevenzip::WriterMeters>(), config,
        VolumeSpaceGate::ChangeSink{});
    {
        auto lease = registry->acquire("job:g26-lease");
        SpaceJobRegistration registration(lease, "R");
        check(registration.registered(), "G-26: guard 必须已注册");
        check(lease.volume()->space_gate->affected_job_ids().size() == 1,
              "G-26: gate 里必须有 R");
    }
    check(registry->blocked_volumes().empty(),
          "G-26: 未 blocked 的卷不出现在 blocked_volumes()");

    // [附加] 功能关闭时 gate 必须保持 nullptr（§7.3 的短路前提）。
    AsyncWriterConfig off_config;
    off_config.space_gate_enabled = false;
    off_config.threads_per_volume = 1;
    off_config.buffer_count = 4;
    auto off_registry = std::make_shared<VolumeWriterRegistry>(
        std::make_shared<sunpack::sevenzip::WriterMeters>(), off_config,
        VolumeSpaceGate::ChangeSink{});
    {
        auto lease = off_registry->acquire("volume-off");
        check(!lease.volume()->space_gate,
              "G-26[附加]: space_gate_enabled=false 时不得创建 gate");
    }
    off_registry->shutdown();
    registry->shutdown();
}

}  // namespace

#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    struct Case {
        const char *name;
        void (*test)();
    };
    const Case cases[] = {
        {"G-1  initial state", g1_initial_state},
        {"G-2  first failure opens episode", g2_first_failure_opens_episode},
        {"G-3  no probe below watermark", g3_no_probe_below_watermark},
        {"G-4  improved watermark -> single probe", g4_improved_watermark_issues_single_probe},
        {"G-5  probe success resumes everyone", g5_probe_success_resumes_everyone},
        {"G-6  failed probe keeps watermark monotonic", g6_failed_probe_keeps_watermark_monotonic},
        {"G-7  no second permit while probing", g7_no_second_permit_while_probing},
        {"G-8  concurrent failures open one episode", g8_concurrent_failures_open_one_episode},
        {"G-9  wake_waiters does not change state", g9_wake_waiters_does_not_change_state},
        {"G-10 terminal predicate is honoured", g10_terminal_predicate_is_honoured},
        {"G-11 lease destructor is inconclusive", g11_lease_destructor_is_inconclusive},
        {"G-12 all waiters leaving is not ready", g12_all_waiters_leaving_is_not_ready},
        {"G-13 event fanout uses affected jobs", g13_event_fanout_uses_affected_jobs},
        {"G-14 registration on blocked volume replays",
         g14_registration_on_blocked_volume_replays},
        {"G-15 ready and terminal are distinguishable",
         g15_ready_and_terminal_are_distinguishable},
        {"G-16 inconclusive probe never resumes", g16_inconclusive_probe_never_resumes},
        {"G-17 episode switch resets watermark", g17_episode_switch_resets_watermark},
        {"G-18 failed fresh query leaves watermark invalid",
         g18_failed_fresh_query_leaves_watermark_invalid},
        {"G-19 query root resolution", g19_query_root_resolution},
        {"G-20 only real success resumes", g20_only_real_success_resumes},
        {"G-21 lease token ownership", g21_lease_token_ownership},
        {"G-22 affected jobs set semantics", g22_affected_jobs_set_semantics},
        {"G-23 poll owns all watermark logic", g23_poll_owns_all_watermark_logic},
        {"G-24 sticky hint survives recovery", g24_sticky_hint_survives_recovery},
        {"G-25 two volumes recover independently", g25_two_volumes_recover_independently},
        {"G-26 registration covers root directory creation",
         g26_registration_covers_root_directory_creation},
    };
    constexpr int kCaseCount = static_cast<int>(std::size(cases));

    // 可选范围过滤：argv[1] = "7" 或 "7-12"（按 1 起的用例序号）。
    // 逐个用例打印进度：某个用例内部挂死时，最后一行就是定位点。
    int first = 1;
    int last = kCaseCount;
    if (argc > 1) {
        const std::string range = argv[1];
        const auto dash = range.find('-');
        try {
            first = std::stoi(range.substr(0, dash));
            last = dash == std::string::npos ? first : std::stoi(range.substr(dash + 1));
        } catch (...) {
            first = 1;
            last = kCaseCount;
        }
        first = (std::max)(1, first);
        last = (std::min)(kCaseCount, last);
    }

    for (int index = first; index <= last; ++index) {
        std::cerr << "[run] " << cases[index - 1].name << std::endl;
        cases[index - 1].test();
    }

    if (g_failures.load() != 0) {
        std::cerr << "space gate check failed: " << g_failures.load() << " assertion(s)\n";
        return 1;
    }
    std::cerr << "space gate check passed\n";
#endif
    return 0;
}
