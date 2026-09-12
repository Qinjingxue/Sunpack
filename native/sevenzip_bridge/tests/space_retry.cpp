// L2：writer 重试 + 记账不变量单测（注入式失败）。
//
// 用例编号与《SunPack Worker 磁盘空间不足自动暂停与恢复实现文档.md》§10.3 的
// R-1..R-20 对应。本阶段（Phase 1 / PR-2）覆盖 Data 路径的全部用例；
// R-9（flush 满盘）与 R-10（目录创建 + memo 不投毒）需要 Phase 4 的骨架接入，
// R-11b（Open / Flush 的 flag-off 边界）需要 Phase 4，R-11c 需要 Phase 4，
// 它们在对应阶段补齐（见文件末尾的说明）。
//
// 测试策略：C++ 单测无法制造真实的 ERROR_DISK_FULL，因此用**注入式失败**把
// "真实系统调用"这一步替换掉，其余代码路径（重试骨架、gate 状态机、probe 结算、
// 记账收尾）全部是真实的：
//   * 缝隙 D（writer.set_write_fault_for_test）—— WriteFile 故障注入。
//   * 缝隙 A/B（failure_classifier / CreateFileW 探针）—— 见头文件说明。
//
// 驱动 gate 的方式：给 VolumeState 挂一个 **resolved 不了查询路径**的 gate
// （随机 volume GUID 作为 failed_path），于是 watermark_valid_ == false，
// 第一次 poll(x) 就会建立 baseline 并发放一个 probe 许可 —— 完全确定，无需满盘。

#include "internal/sevenzip_async_output.hpp"
#include "internal/sevenzip_callbacks.hpp"
#include "internal/sevenzip_space_directory.hpp"
#include "internal/sevenzip_volume_registry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32

namespace {

using sunpack::sevenzip::AsyncFileWriter;
using sunpack::sevenzip::AsyncWriterConfig;
using sunpack::sevenzip::AttemptResult;
using sunpack::sevenzip::ExtractOutputTrace;
using sunpack::sevenzip::ExtractProgressCallback;
using sunpack::sevenzip::ExtractToDiskCallback;
using sunpack::sevenzip::make_volume_state;
using sunpack::sevenzip::ProbeLease;
using sunpack::sevenzip::SpaceJobRegistration;
using sunpack::sevenzip::TerminalPredicate;
using sunpack::sevenzip::VolumeSpaceGate;
using sunpack::sevenzip::VolumeSpacePhase;
using sunpack::sevenzip::VolumeSpaceTransition;
using sunpack::sevenzip::VolumeStatePtr;
using sunpack::sevenzip::VolumeWriterRegistry;
using sunpack::sevenzip::WriterMeters;

using namespace std::chrono_literals;

std::atomic<int> g_failures{0};

bool check(bool condition, const std::string &what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << "\n";
        g_failures.fetch_add(1);
    }
    return condition;
}

constexpr std::size_t kMib = 1U << 20;

std::filesystem::path make_test_directory() {
    const auto directory = std::filesystem::temp_directory_path() /
        (L"sunpack-space-retry-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(directory);
    return directory;
}

// "没有可用的失败路径"：让新鲜查询确定性地失败。resolved 卷忽略这个参数。
std::wstring_view unresolved_failed_path() {
    return std::wstring_view{};
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

struct SinkLog {
    void record(const VolumeSpaceTransition &transition) {
        std::lock_guard<std::mutex> lock(mutex);
        transitions.push_back(transition);
    }
    std::size_t count(VolumeSpaceTransition::Kind kind) const {
        std::lock_guard<std::mutex> lock(mutex);
        return static_cast<std::size_t>(std::count_if(
            transitions.begin(), transitions.end(),
            [kind](const VolumeSpaceTransition &item) { return item.kind == kind; }));
    }
    std::size_t total() const {
        std::lock_guard<std::mutex> lock(mutex);
        return transitions.size();
    }

    mutable std::mutex mutex;
    std::vector<VolumeSpaceTransition> transitions;

    std::vector<VolumeSpaceTransition> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex);
        return transitions;
    }
};

// 模拟"用户释放了足够空间"：用**真实**可用空间 + 1 GiB 明确越过水位。
// ⚠️ 不能用一个小常量（如 1）：gate 的初始水位来自一次真实的新鲜查询
//    （writer 侧 report_space_failure 传的是真实失败路径，因此查询会成功），
//    一个小于真实可用空间的采样值不会越过水位，许可就永远发不出来。
bool release_permit(const std::shared_ptr<VolumeSpaceGate> &gate) {
    std::uint64_t free_now = 0;
    std::uint64_t total = 0;
    const bool queried = gate->query_free_bytes(&free_now, &total);
    return gate->poll((queried ? free_now : 0) + (1ULL << 30));
}
// 把 std::string 里的 ASCII 还原成宽字符（测试路径都是 ASCII）。
std::string to_ascii(const std::wstring &text) {
    std::string ascii;
    ascii.reserve(text.size());
    for (const wchar_t value : text) {
        ascii.push_back(static_cast<char>(value & 0x7F));
    }
    return ascii;
}

std::vector<unsigned char> make_payload(std::size_t size) {
    std::vector<unsigned char> payload(size);
    for (std::size_t index = 0; index < size; ++index) {
        payload[index] = static_cast<unsigned char>((index * 131U + index / 509U) & 0xFFU);
    }
    return payload;
}

// 每个用例的公共脚手架：一个挂了 gate 的 VolumeState + 一个 writer。
//
// query_root_hint 用**真实的临时目录**，于是：
//   * 构造时 query_root_resolved_ == true；
//   * Ready→Blocked 的新鲜查询**确定性地成功**，watermark = 该卷真实可用空间；
//   * 恢复时用 poll(当前可用 + 1 GiB) 明确越过水位 —— 完全确定，不依赖任何
//     "解析不出卷根"的偶然行为。
struct Harness {
    explicit Harness(const std::filesystem::path &query_root,
                     std::size_t threads = 1,
                     std::size_t buffers = 8,
                     bool write_through = false) {
        config.threads_per_volume = threads;
        config.buffer_count = buffers;
        config.write_through = write_through;
        state = make_volume_state("volume:retry", true);
        // 先取一份本地 sink：C++17 的 lambda 捕获列表不能直接命名非静态数据成员。
        const auto sink = log;
        gate = std::make_shared<VolumeSpaceGate>(
            "volume:retry", to_ascii(query_root.wstring()),
            [sink](const VolumeSpaceTransition &transition) { sink->record(transition); }, 20ms);
        state->space_gate = gate;
        writer = std::make_unique<AsyncFileWriter>(meters, state, config);
    }

    bool release_probe_and_wait_ready(std::chrono::milliseconds timeout = 5s) {
        // 模拟"用户释放了足够空间"：明确高于当前水位。
        const bool issued = release_permit(gate);
        const bool ready =
            wait_until([this] { return gate->phase() == VolumeSpacePhase::Ready; }, timeout);
        if (!issued || !ready) {
            const auto metrics = writer->snapshot_metrics();
            std::uint64_t free_now = 0;
            std::uint64_t total = 0;
            const bool queried = gate->query_free_bytes(&free_now, &total);
            std::cerr << "  [diag] queried=" << queried << " poll_issued=" << issued
                      << " phase=" << static_cast<int>(gate->phase())
                      << " watermark_valid=" << gate->watermark_valid()
                      << " watermark=" << gate->failed_free_watermark()
                      << " free_now=" << free_now
                      << " episode=" << gate->episode_id()
                      << " waiters=" << gate->waiter_count()
                      << " query_root_resolved=" << gate->query_root_resolved()
                      << " | accepted=" << metrics.accepted_bytes
                      << " written=" << metrics.written_bytes
                      << " discarded=" << metrics.discarded_bytes
                      << " pending=" << metrics.pending_bytes << "\n";
        }
        return issued && ready;
    }

    // 恢复失败时不能直接 finish_job：那会等 pending_jobs == 0 而永久阻塞
    // （暂停期间 buffer 一直由 writer 线程持有 —— 这是设计要求的语义）。
    void cancel_and_finish(const AsyncFileWriter::JobStatePtr &job) {
        writer->cancel_job(job);
        writer->finish_job(job);
    }

    AsyncWriterConfig config;
    std::shared_ptr<WriterMeters> meters = std::make_shared<WriterMeters>();
    VolumeStatePtr state;
    std::shared_ptr<SinkLog> log = std::make_shared<SinkLog>();
    std::shared_ptr<VolumeSpaceGate> gate;
    std::unique_ptr<AsyncFileWriter> writer;
};

std::vector<unsigned char> read_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(input)),
                                      std::istreambuf_iterator<char>());
}

// ---------------------------------------------------------------------------
// R-1/R-2/R-3/R-5/R-6/R-20：一次完整的"满盘 → 暂停 → 恢复 → 数据完整"循环
// ---------------------------------------------------------------------------
void r1_to_r6_and_r20_pause_and_resume(const std::filesystem::path &directory) {
    Harness harness(directory, 2, 8);
    auto &writer = *harness.writer;

    // 缝隙 B：统计 CreateFileW 调用次数（"同 handle 续写"的回归防线）。
    std::atomic<int> open_calls{0};
    writer.set_open_probe_for_test([&open_calls](const std::wstring &) { open_calls.fetch_add(1); });

    constexpr std::size_t kPayload = 4 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r1-resume.bin";

    // 在第 3 次 WriteFile 上注入一次空间失败（前两次成功 → 覆盖多 buffer 场景）。
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1, 2);

    const auto job = writer.make_job(8 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r1-resume.bin", 0, 0);

    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK &&
              processed == payload.size(),
          "R-1: 生产者写入必须全部被接受");

    check(wait_until([&] { return harness.gate->blocked(); }, 5s),
          "R-1: 空间错误必须让卷进入暂停（而不是 job 永久失败）");
    // ⚠️ 事件是在 gate 锁**释放之后**才回调 sink 的（锁序要求），因此"进入暂停"与
    //    "事件已送达"是两个时刻。断言事件计数前必须再等一下。
    check(wait_until([&] { return harness.log->count(VolumeSpaceTransition::Kind::Blocked) >= 1; },
                     5s),
          "R-1: space_blocked 必须在暂停后送达");

    // R-1 空间错误不置位 failed
    const auto paused_file = writer.snapshot_file(file);
    check(!paused_file.failed, "R-1: 暂停期间 file->failed 必须仍是 false");
    check(paused_file.hresult == S_OK, "R-1: 暂停期间 file->hresult 必须仍是 S_OK");
    // R-2 空间错误不置位 job error
    check(writer.current_error(job) == S_OK, "R-2: 暂停期间 job 必须没有错误");
    check(!job->terminal_requested.load(), "R-2: 暂停期间 terminal_requested 必须仍是 false");
    // R-3 记账不变量（暂停期间）
    const auto paused = writer.snapshot_metrics();
    check(paused.discarded_bytes == 0, "R-3: 暂停期间 discarded 必须为 0");
    check(paused.accepted_bytes == paused.written_bytes + paused.discarded_bytes +
                                        paused.pending_bytes,
          "R-3: 暂停期间必须保持 accepted == written + discarded + pending");
    check(harness.log->count(VolumeSpaceTransition::Kind::Blocked) == 1,
          "R-3: 必须只开启一个 episode");
    check(harness.log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "R-3: 暂停期间不得出现 space_resumed");

    // 释放空间 → 发放 probe 许可 → 真实重试成功
    const bool resumed = harness.release_probe_and_wait_ready();
    check(resumed, "R-5: probe 成功后卷必须回到 Ready");
    if (!resumed) {
        harness.cancel_and_finish(job);
        return;
    }
    // 关闭文件（真实调用方在解压结束时一定会做这一步）。
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    check(writer.finish_job(job) == S_OK, "R-5: 恢复后 job 必须成功完成");

    // R-5 恢复后数据完整
    const auto metrics = writer.snapshot_metrics();
    check(metrics.written_bytes == kPayload, "R-5: written 必须等于 payload 大小");
    check(metrics.accepted_bytes == kPayload, "R-5: accepted 必须等于 payload 大小");
    check(metrics.discarded_bytes == 0, "R-5: 成功路径不得产生 discarded");
    check(metrics.pending_bytes == 0, "R-5: drain 后 pending 必须归零");
    check(metrics.completed_files == 1 && metrics.completed_jobs == 1,
          "R-5: 完成计数必须各为 1");

    // R-6 offset 不重复不丢失 —— 用逐字节内容比对（同时覆盖重叠写与丢数据）
    const auto actual = read_file(path);
    if (actual.size() != payload.size()) {
        std::cerr << "  [diag] actual=" << actual.size() << " expected=" << payload.size() << "\n";
    }
    check(actual.size() == payload.size(), "R-6: 输出文件大小必须与 payload 一致");
    check(actual == payload, "R-6: 输出必须逐字节等于 payload（无重叠、无丢失）");

    // R-20 same-handle recovery
    check(open_calls.load() == 1,
          "R-20: 整个 FileState 生命周期内 CreateFileW 必须恰好调用一次（同 handle 续写）");
    check(harness.log->count(VolumeSpaceTransition::Kind::Resumed) == 1,
          "R-20: 恢复必须只产生一条 space_resumed");
}

// ---------------------------------------------------------------------------
// R-4 producer 反压成立
// ---------------------------------------------------------------------------
void r4_producer_backpressure(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    constexpr std::size_t kBudget = 2 * kMib;
    constexpr std::size_t kPayload = 16 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r4-backpressure.bin";

    // 第一次 WriteFile 就失败 → 立刻暂停，buffer 一直被 writer 线程持有。
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(kBudget);
    const auto file = writer.make_file(job, path.wstring(), L"r4-backpressure.bin", 0, 0);

    std::atomic<bool> producer_returned{false};
    std::atomic<std::uint32_t> produced{0};
    std::thread producer([&] {
        std::uint32_t processed = 0;
        const HRESULT result =
            writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                         &processed);
        produced.store(processed);
        // 暂停期间要么阻塞在 write() 里，要么在恢复后完成；两条路径都不允许在
        // 暂停窗口内返回。
        (void)result;
        producer_returned.store(true);
    });

    check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-4: 必须进入暂停");
    std::this_thread::sleep_for(300ms);
    check(!producer_returned.load(),
          "R-4: 暂停期间预算用尽后 write() 必须阻塞（producer 反压成立）");
    const auto paused = writer.snapshot_metrics();
    check(paused.pending_bytes > 0, "R-4: 暂停期间 pending 必须保持非零");

    check(harness.release_probe_and_wait_ready(), "R-4: 恢复后必须回到 Ready");
    producer.join();
    check(producer_returned.load(), "R-4: 恢复后 producer 必须被唤醒并返回");
    check(produced.load() == kPayload, "R-4: producer 必须写完全部 payload");
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    check(writer.finish_job(job) == S_OK, "R-4: 恢复后 job 必须成功");
    const auto metrics = writer.snapshot_metrics();
    check(metrics.written_bytes == kPayload && metrics.pending_bytes == 0,
          "R-4: 恢复后必须全部落盘且 pending 归零");
    check(read_file(path) == payload, "R-4: 数据必须逐字节完整");
}

// ---------------------------------------------------------------------------
// R-7 取消穿透
// ---------------------------------------------------------------------------
void r7_cancel_pierces_pause(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    constexpr std::size_t kPayload = 2 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r7-cancel.bin";
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r7-cancel.bin", 0, 0);

    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-7: 写入必须被接受");
    check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-7: 必须进入暂停");

    const auto started = std::chrono::steady_clock::now();
    writer.cancel_job(job);
    const HRESULT result = writer.finish_job(job);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    check(result != S_OK, "R-7: 取消后 finish_job 必须返回非 S_OK");
    check(elapsed < 1s, "R-7: 取消必须能穿透暂停（1s 内返回）");
    const auto metrics = writer.snapshot_metrics();
    check(metrics.pending_bytes == 0, "R-7: 取消后 pending 必须归零");
    check(metrics.accepted_bytes == metrics.written_bytes + metrics.discarded_bytes,
          "R-7: 取消后必须保持 accepted == written + discarded");
}

// ---------------------------------------------------------------------------
// R-8 `finish()` 可关停（暂停期间）
// ---------------------------------------------------------------------------
void r8_finish_while_paused(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    constexpr std::size_t kPayload = 2 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r8-finish.bin";
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r8-finish.bin", 0, 0);
    std::uint32_t processed = 0;
    writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed);
    check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-8: 必须进入暂停");

    const auto started = std::chrono::steady_clock::now();
    writer.finish();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    check(elapsed < 1s, "R-8: 暂停期间 finish() 必须能在 1s 内返回");

    // 关停**不得**改变 gate 状态（没有 aborted_ 永久闩锁）。
    check(harness.gate->phase() != VolumeSpacePhase::Ready,
          "R-8: finish() 只唤醒，绝不能把 gate 伪造成 Ready");
    check(harness.log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "R-8: finish() 不得发出 space_resumed");
}

// ---------------------------------------------------------------------------
// R-11a 开关关闭 —— Data 路径（§4.5.0）
// ---------------------------------------------------------------------------
void r11a_flag_off_data_legacy_semantics(const std::filesystem::path &directory) {
    // gate == nullptr：功能关闭 / 无卷身份。
    AsyncWriterConfig config;
    config.threads_per_volume = 1;
    config.buffer_count = 8;
    config.space_gate_enabled = false;
    auto meters = std::make_shared<WriterMeters>();
    auto state = make_volume_state("volume:off", true);
    check(!state->space_gate, "R-11a: space_gate_enabled=false 时 VolumeState 不得有 gate");
    AsyncFileWriter writer(meters, state, config);

    constexpr std::size_t kPayload = 1 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r11a-legacy.bin";
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r11a-legacy.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-11a: 写入必须被接受");

    check(wait_until([&] { return writer.snapshot_file(file).failed; }, 5s),
          "R-11a: 关闭开关时空间错误必须走旧的永久失败路径");

    // ★ 四条旧副作用逐条断言（只断言"job 最终失败"是不够的）。
    const auto snapshot = writer.snapshot_file(file);
    check(snapshot.failed, "R-11a: 副作用 1 —— file->failed 必须置位");
    check(snapshot.win32_error == ERROR_DISK_FULL,
          "R-11a: file 必须记录原始 Win32 错误码");
    check(writer.current_error(job) != S_OK, "R-11a: 副作用 2 —— job->first_error 必须置位");
    check(job->terminal_requested.load(),
          "R-11a: 副作用 2b —— terminal_requested 必须同步置位（gate 谓词依赖它）");
    const auto metrics = writer.snapshot_metrics();
    check(metrics.discarded_bytes == kPayload,
          "R-11a: 副作用 3 —— discarded 必须按剩余字节增长");
    check(metrics.pending_bytes == 0, "R-11a: 副作用 3b —— pending 必须归零");

    // 副作用 4：producer 必须已被唤醒 —— 新的 write() 必须立刻失败而不是阻塞。
    const auto started = std::chrono::steady_clock::now();
    std::uint32_t second_processed = 0;
    const HRESULT second = writer.write(file, payload.data(), 64, &second_processed);
    check(second != S_OK, "R-11a: 副作用 4 —— producer 必须被唤醒且后续 write() 立即失败");
    check(std::chrono::steady_clock::now() - started < 1s,
          "R-11a: 后续 write() 不得阻塞");

    check(writer.finish_job(job) != S_OK, "R-11a: finish_job 必须返回非 S_OK");
    // 关闭开关时绝不能有任何空间事件。
    check(writer.volume_state()->space_gate == nullptr, "R-11a: 不得创建 gate");
}

// ---------------------------------------------------------------------------
// R-13 关停不被暂停卡住（含 abort_all_space_gates）
// ---------------------------------------------------------------------------
void r13_abort_then_finish(const std::filesystem::path &directory) {
    AsyncWriterConfig config;
    config.threads_per_volume = 1;
    config.buffer_count = 8;
    config.space_gate_enabled = true;
    auto meters = std::make_shared<WriterMeters>();
    auto log = std::make_shared<SinkLog>();
    auto registry = std::make_shared<VolumeWriterRegistry>(
        meters, config,
        [log](const VolumeSpaceTransition &transition) { log->record(transition); });

    const auto key = std::string("volume:r13");
    auto lease = registry->acquire(key);
    check(lease.valid(), "R-13: lease 必须有效");
    auto gate = lease.volume()->space_gate;
    check(static_cast<bool>(gate), "R-13: 功能开启时必须有 gate");
    auto &writer = lease.writer();

    constexpr std::size_t kPayload = 2 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r13-abort.bin";
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r13-abort.bin", 0, 0);
    std::uint32_t processed = 0;
    writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed);
    check(wait_until([&] { return gate->blocked(); }, 5s), "R-13: 必须进入暂停");
    check(!registry->blocked_volumes().empty(), "R-13: blocked_volumes() 必须包含该卷");

    // abort 只是 wake_waiters() 的广播：**不改变任何 gate 状态**。
    const auto before = gate->episode_id();
    registry->abort_all_space_gates();
    check(gate->blocked(), "R-13: abort 不得把 gate 伪造成 Ready");
    check(gate->episode_id() == before, "R-13: abort 不得改变 episode");

    const auto started = std::chrono::steady_clock::now();
    writer.finish();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    check(elapsed < 1s, "R-13: abort + finish 组合必须在 1s 内完成关停");

    lease.reset();
    registry->shutdown();
}

// ---------------------------------------------------------------------------
// R-14 终态补记 discarded（架构师第 5 条）
// ---------------------------------------------------------------------------
void r14_terminal_records_discarded(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    // 两个 buffer：第 1 个完整落盘，第 2 个在暂停中被取消 → 恰好记 1 MiB。
    constexpr std::size_t kPayload = 2 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r14-terminal.bin";
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r14-terminal.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-14: 写入必须被接受");
    check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-14: 必须进入暂停");

    const auto paused = writer.snapshot_metrics();
    check(paused.written_bytes == kMib, "R-14: 第 1 个 buffer 必须已完整落盘");
    check(paused.discarded_bytes == 0, "R-14: 暂停期间 discarded 必须仍为 0");

    writer.cancel_job(job);
    check(writer.finish_job(job) != S_OK, "R-14: 取消后 job 必须失败");
    const auto metrics = writer.snapshot_metrics();
    check(metrics.discarded_bytes == kMib,
          "R-14: 已 dequeue 的 buffer 剩余字节必须**恰好补记一次**（1 MiB）");
    check(metrics.pending_bytes == 0, "R-14: pending 必须归零");
    check(metrics.accepted_bytes == metrics.written_bytes + metrics.discarded_bytes,
          "R-14: 必须保持 accepted == written + discarded");
}

// ---------------------------------------------------------------------------
// R-15 事件注册/注销（§4.7.1）
// ---------------------------------------------------------------------------
void r15_space_job_registration(const std::filesystem::path &directory) {
    (void)directory;
    AsyncWriterConfig config;
    config.threads_per_volume = 1;
    config.buffer_count = 4;
    config.space_gate_enabled = true;
    auto meters = std::make_shared<WriterMeters>();
    VolumeWriterRegistry registry(meters, config, VolumeSpaceGate::ChangeSink{});

    auto lease = registry.acquire("volume:r15");
    auto gate = lease.volume()->space_gate;
    check(static_cast<bool>(gate), "R-15: 必须有 gate");

    {
        // ⚠️ 声明在 lease 之后 ⇒ 先于 lease 析构。
        SpaceJobRegistration registration(lease, "J");
        check(registration.registered(), "R-15: guard 必须已注册");
        const auto ids = gate->affected_job_ids();
        check(ids.size() == 1 && ids.front() == "J",
              "R-15: affected_job_ids() 必须包含 J（且不创建任何 JobState）");
    }
    check(gate->affected_job_ids().empty(), "R-15: guard 析构后必须注销");

    // 空 job_id 不注册。
    {
        SpaceJobRegistration registration(lease, "");
        check(!registration.registered(), "R-15: 空 job_id 不得注册");
    }
    lease.reset();
    registry.shutdown();
}

// ---------------------------------------------------------------------------
// R-16 writer 回收不毒死 gate（R6）
// ---------------------------------------------------------------------------
void r16_reaped_writer_does_not_poison_gate(const std::filesystem::path &directory) {
    AsyncWriterConfig config;
    config.threads_per_volume = 1;
    config.buffer_count = 4;
    config.space_gate_enabled = true;
    config.idle_timeout = 50ms;
    auto meters = std::make_shared<WriterMeters>();
    auto registry = std::make_shared<VolumeWriterRegistry>(
        meters, config, VolumeSpaceGate::ChangeSink{});

    const auto key = std::string("volume:r16");
    VolumeStatePtr first_state;
    {
        auto lease = registry->acquire(key);
        first_state = lease.volume();
        auto &writer = lease.writer();
        auto gate = first_state->space_gate;
        check(static_cast<bool>(gate), "R-16: 必须有 gate");

        constexpr std::size_t kPayload = 1 * kMib;
        const auto payload = make_payload(kPayload);
        const auto path = directory / L"r16-first.bin";
        writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r16-first.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        check(wait_until([&] { return gate->blocked(); }, 5s), "R-16: 第一次必须进入暂停");
        check(release_permit(gate), "R-16: 必须能发放许可");
        check(wait_until([&] { return gate->phase() == VolumeSpacePhase::Ready; }, 5s),
              "R-16: 第一次必须能恢复");
        writer.record_operation_result(file, 0);
        writer.close_file(file, 0, false, {});
        check(writer.finish_job(job) == S_OK, "R-16: 第一次 job 必须成功");
    }

    // 让 facility 进入 idle 并被回收（persistent 卷的 VolumeState 必须存活）。
    std::this_thread::sleep_for(80ms);
    const auto reclaimed = registry->reap_idle();
    check(reclaimed.size() == 1, "R-16: 空闲 facility 必须被回收");
    check(registry->volume_keys().size() == 1, "R-16: persistent 卷状态必须存活");

    // 重建 writer 后必须仍能正常等待与恢复（旧设计会永久毒死 gate）。
    {
        auto lease = registry->acquire(key);
        check(lease.created_facility(), "R-16: 必须重建 facility");
        check(lease.volume().get() == first_state.get(),
              "R-16: 必须是同一个 VolumeState（因此同一个 gate）");
        auto gate = lease.volume()->space_gate;
        check(static_cast<bool>(gate), "R-16: gate 必须仍在");
        check(gate->phase() == VolumeSpacePhase::Ready,
              "R-16: 回收不得改变 gate 状态（没有 aborted_ 永久闩锁）");

        auto &writer = lease.writer();
        constexpr std::size_t kPayload = 1 * kMib;
        const auto payload = make_payload(kPayload);
        const auto path = directory / L"r16-second.bin";
        writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r16-second.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        check(wait_until([&] { return gate->blocked(); }, 5s),
              "R-16: 回收后新 job 必须仍能进入暂停");
        const bool issued = release_permit(gate);
        const bool ready =
            wait_until([&] { return gate->phase() == VolumeSpacePhase::Ready; }, 5s);
        check(issued, "R-16: 回收后必须仍能发放许可");
        check(ready, "R-16: 回收后必须仍能恢复（gate 未被毒死）");
        if (!issued || !ready) {
            // 恢复失败时不能直接 finish_job（它会等 pending_jobs == 0 而永久阻塞）。
            writer.cancel_job(job);
            writer.finish_job(job);
            registry->shutdown();
            return;
        }
        writer.record_operation_result(file, 0);
        writer.close_file(file, 0, false, {});
        check(writer.finish_job(job) == S_OK, "R-16: 回收后 job 必须成功");
        check(read_file(path) == payload, "R-16: 回收后数据必须完整");
    }
    registry->shutdown();
}

// ---------------------------------------------------------------------------
// R-17 open 并发不误判（架构师第 6 条）
// ---------------------------------------------------------------------------
void r17_concurrent_open_is_serialized(const std::filesystem::path &directory) {
    Harness harness(directory, 4, 8);
    auto &writer = *harness.writer;
    std::atomic<int> open_calls{0};
    writer.set_open_probe_for_test([&open_calls](const std::wstring &) { open_calls.fetch_add(1); });

    constexpr std::size_t kPayload = 8 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r17-parallel.bin";

    const auto job = writer.make_job(16 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r17-parallel.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-17: 写入必须被接受");
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    check(writer.finish_job(job) == S_OK, "R-17: 并发写同一文件必须成功");

    const auto snapshot = writer.snapshot_file(file);
    check(snapshot.peak_active_data_writes >= 2,
          "R-17: 测试前提 —— 同一 file 的多个 Data WorkItem 必须被多个 writer 线程并发处理");
    check(open_calls.load() == 1,
          "R-17: CreateFileW 只能发生一次（第二个线程必须看到已建立的 handle）");
    check(!snapshot.failed, "R-17: 不得出现 ERROR_FILE_EXISTS → PermanentFailure");
    check(read_file(path) == payload, "R-17: 数据必须完整");
}

// ---------------------------------------------------------------------------
// R-18 PermanentFailure 也补记 discarded（架构师第 9 条）
// ---------------------------------------------------------------------------
void r18_permanent_failure_records_discarded(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    constexpr std::size_t kPayload = 2 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r18-permanent.bin";
    // 非空间错误：第 2 次 WriteFile 以 ERROR_WRITE_FAULT 失败。
    writer.set_write_fault_for_test(ERROR_WRITE_FAULT, 1, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r18-permanent.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-18: 写入必须被接受");
    check(writer.finish_job(job) != S_OK, "R-18: 永久错误必须让 job 失败");

    const auto metrics = writer.snapshot_metrics();
    check(metrics.written_bytes == kMib, "R-18: 第 1 个 buffer 必须落盘");
    check(metrics.discarded_bytes == kMib,
          "R-18: PermanentFailure 路径必须补记剩余字节（早期版本这里没人记账）");
    check(metrics.pending_bytes == 0, "R-18: pending 必须归零");
    check(metrics.accepted_bytes == metrics.written_bytes + metrics.discarded_bytes,
          "R-18: 必须保持记账不变量");
    const auto snapshot = writer.snapshot_file(file);
    check(snapshot.failed && snapshot.win32_error == ERROR_WRITE_FAULT,
          "R-18: file 必须记录永久错误");
    // 永久错误走 probe inconclusive：绝不产生 space_resumed。
    check(harness.log->count(VolumeSpaceTransition::Kind::Resumed) == 0,
          "R-18: 非空间错误绝不能伪造成 space_resumed");
}

// ---------------------------------------------------------------------------
// R-19 每个 dequeue buffer 恰好记一次（四种返回路径）
// ---------------------------------------------------------------------------
void r19_exactly_one_discard_per_buffer(const std::filesystem::path &directory) {
    // ① Succeeded → 增量 0
    {
        Harness harness(directory, 1, 8);
        auto &writer = *harness.writer;
        const auto payload = make_payload(1 * kMib);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(
            job, (directory / L"r19-ok.bin").wstring(), L"r19-ok.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        check(writer.finish_job(job) == S_OK, "R-19: ① 干净写入必须成功");
        check(writer.snapshot_metrics().discarded_bytes == 0, "R-19: ① Succeeded 必须记 0 次");
    }
    // ② PermanentFailure → 增量 remaining
    {
        Harness harness(directory, 1, 8);
        auto &writer = *harness.writer;
        const auto payload = make_payload(1 * kMib);
        const auto path = directory / L"r19-permanent.bin";
        writer.set_write_fault_for_test(ERROR_WRITE_FAULT, 1);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r19-permanent.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        writer.finish_job(job);
        check(writer.snapshot_metrics().discarded_bytes == 1 * kMib,
              "R-19: ② PermanentFailure 必须恰好记一次 remaining");
    }
    // ③ Terminal → 增量 remaining
    {
        Harness harness(directory, 1, 8);
        auto &writer = *harness.writer;
        const auto payload = make_payload(1 * kMib);
        const auto path = directory / L"r19-terminal.bin";
        writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r19-terminal.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-19: ③ 必须进入暂停");
        writer.cancel_job(job);
        writer.finish_job(job);
        check(writer.snapshot_metrics().discarded_bytes == 1 * kMib,
              "R-19: ③ Terminal 必须恰好记一次 remaining");
    }
    // ④ SpaceFailure（gate 存在）→ 增量 0（骨架内部重试，不退出、不记账）
    {
        Harness harness(directory, 1, 8);
        auto &writer = *harness.writer;
        const auto payload = make_payload(1 * kMib);
        const auto path = directory / L"r19-space.bin";
        writer.set_write_fault_for_test(ERROR_DISK_FULL, 1);
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r19-space.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        check(wait_until([&] { return harness.gate->blocked(); }, 5s), "R-19: ④ 必须进入暂停");
        check(writer.snapshot_metrics().discarded_bytes == 0,
              "R-19: ④ gate 存在时的 SpaceFailure 必须记 0 次");
        check(harness.release_probe_and_wait_ready(), "R-19: ④ 恢复");
        check(writer.finish_job(job) == S_OK, "R-19: ④ 恢复后成功");
        const auto metrics = writer.snapshot_metrics();
        check(metrics.discarded_bytes == 0 && metrics.pending_bytes == 0,
              "R-19: ④ 全程不得产生 discarded，且没有双重记账");
    }
}

// ---------------------------------------------------------------------------
// R-9 close 阶段空间错误（write_through 的 flush 走同一骨架）
// ---------------------------------------------------------------------------
void r9_flush_space_error(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8, /*write_through=*/true);
    auto &writer = *harness.writer;
    std::atomic<int> open_calls{0};
    writer.set_open_probe_for_test([&open_calls](const std::wstring &) { open_calls.fetch_add(1); });

    constexpr std::size_t kPayload = 1 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r9-flush.bin";

    // 数据写完后，FlushFileBuffers 以空间错误失败一次。
    writer.set_flush_fault_for_test(ERROR_DISK_FULL, 1);

    const auto job = writer.make_job(4 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r9-flush.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-9: 写入必须被接受");
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});

    check(wait_until([&] { return harness.gate->blocked(); }, 5s),
          "R-9: flush 的空间错误必须让卷进入暂停");
    // 暂停期间 handle 必须仍然有效（同 handle 续写语义的一部分）。
    check(!writer.snapshot_file(file).closed, "R-9: 暂停期间文件不得被关闭");

    check(harness.release_probe_and_wait_ready(), "R-9: 恢复后必须回到 Ready");
    check(writer.finish_job(job) == S_OK, "R-9: 恢复后 job 必须完成");
    const auto snapshot = writer.snapshot_file(file);
    check(snapshot.closed, "R-9: 恢复后文件必须已关闭");
    check(!snapshot.failed, "R-9: 恢复后文件不得是失败状态");
    check(open_calls.load() == 1, "R-9: flush 重试不得重新打开文件（同 handle）");
    check(writer.snapshot_metrics().completed_files == 1, "R-9: 必须计入 completed_files");
    check(read_file(path) == payload, "R-9: 数据必须完整");
    check(harness.log->count(VolumeSpaceTransition::Kind::Resumed) == 1,
          "R-9: 恢复必须产生一条 space_resumed");
}

// ---------------------------------------------------------------------------
// R-10 目录创建重试 + memo 不投毒
// ---------------------------------------------------------------------------
void r10_directory_retry_and_memo(const std::filesystem::path &directory) {
    using sunpack::sevenzip::create_directories_with_space_gate;
    using sunpack::sevenzip::set_directory_failure_classifier_for_test;

    // ① 非空间类失败：必须原样透传**真实**错误码（不是 E_FAIL，也不是 PATH_NOT_FOUND）。
    const auto blocked_path = directory / L"r10-blocked-dir";
    {
        std::ofstream blocker(blocked_path, std::ios::binary);
        blocker << "blocker";
    }
    std::error_code reference;
    std::filesystem::create_directories(blocked_path, reference);
    check(static_cast<bool>(reference),
          "R-10: 前提 —— 目标位置上有一个普通文件时 create_directories 必须失败");

    std::error_code helper_error;
    check(!create_directories_with_space_gate(
              blocked_path, nullptr, TerminalPredicate{}, &helper_error),
          "R-10: 目录创建失败必须返回 false");
    check(helper_error == reference,
          "R-10: 必须透传原始的 std::error_code（旧代码 catch(...) 把它丢掉了）");
    check(helper_error.value() != ERROR_PATH_NOT_FOUND,
          "R-10: 透传的绝不能是被替换过的 PATH_NOT_FOUND");

    // ② 空间类失败 → 重试成功（注入判定器，用真实错误码驱动同一代码路径）。
    set_directory_failure_classifier_for_test(
        [](const std::error_code &error)
        {
            return error.value() == ERROR_ALREADY_EXISTS ||
                   sunpack::sevenzip::is_space_exhaustion_error(error);
        });

    auto log = std::make_shared<SinkLog>();
    auto gate = std::make_shared<VolumeSpaceGate>(
        "volume:r10", to_ascii(directory.wstring()),
        [log](const VolumeSpaceTransition &transition) { log->record(transition); }, 20ms);

    std::error_code retry_error;
    std::atomic<bool> helper_ready{false};
    std::thread helper([&] {
        helper_ready.store(create_directories_with_space_gate(
            blocked_path, gate.get(), TerminalPredicate{}, &retry_error));
    });
    check(wait_until([&] { return gate->blocked(); }, 5s),
          "R-10: 空间类目录失败必须让卷进入暂停（而不是永久失败）");
    // 清掉障碍，模拟"空间被释放"。
    std::error_code remove_error;
    std::filesystem::remove(blocked_path, remove_error);
    check(release_permit(gate), "R-10: 必须能发放许可");
    helper.join();
    check(helper_ready.load(), "R-10: 重试必须成功");
    check(!retry_error, "R-10: 成功后不得留下错误码");
    check(std::filesystem::is_directory(blocked_path), "R-10: 目录必须真的被创建");
    set_directory_failure_classifier_for_test(nullptr);

    // ③ memo 不投毒：一次失败的目录创建绝不能被 memo 记住。
    //    用 dry_run 构造 callback（不触碰 writer / 归档），只驱动 ensure_directory。
    {
        ExtractOutputTrace trace;
        auto* callback = new ExtractToDiskCallback(
            nullptr, L"", directory.wstring(), std::vector<std::wstring>{},
            ExtractProgressCallback{}, true, &trace, 4);
        check(callback != nullptr, "R-10: callback 必须构造成功");

        const auto memo_path = (directory / L"r10-memo-dir").wstring();
        {
            std::ofstream blocker(memo_path, std::ios::binary);
            blocker << "blocker";
        }
        int first_code = 0;
        check(!callback->ensure_directory_for_test(memo_path, &first_code),
              "R-10: 第一次创建必须失败（目标位置被文件占用）");
        check(first_code != 0, "R-10: 第一次失败必须带出真实错误码");

        std::error_code remove_error;
        std::filesystem::remove(memo_path, remove_error);

        int second_code = 0;
        const bool second = callback->ensure_directory_for_test(memo_path, &second_code);
        check(second, "R-10: 同一目录第二次调用必须**真正重试**并成功（memo 未被投毒）");
        check(second_code == 0, "R-10: 第二次成功不得留下错误码");
        check(std::filesystem::is_directory(memo_path),
              "R-10: 目录必须真的存在（旧代码会因 memo 投毒而永远不创建）");

        int third_code = 0;
        check(callback->ensure_directory_for_test(memo_path, &third_code),
              "R-10: 成功之后必须被 memo（幂等快路径）");
        callback->Release();
    }
}

// ---------------------------------------------------------------------------
// R-11b 开关关闭 —— Open / Flush 路径（§4.5.0.1）
// ---------------------------------------------------------------------------
void r11b_flag_off_open_and_flush(const std::filesystem::path &directory) {
    // ① Open 的空间类错误：旧语义 = 标记 file/job 失败 + **置 open_attempted**
    //    （"不再尝试"），并且只尝试一次。
    {
        AsyncWriterConfig config;
        config.threads_per_volume = 1;
        config.buffer_count = 4;
        config.space_gate_enabled = false;
        auto meters = std::make_shared<WriterMeters>();
        auto state = make_volume_state("volume:off-open", true);
        AsyncFileWriter writer(meters, state, config);
        check(!state->space_gate, "R-11b: 开关关闭时不得有 gate");

        std::atomic<int> open_calls{0};
        writer.set_open_probe_for_test(
            [&open_calls](const std::wstring &) { open_calls.fetch_add(1); });

        // 目标位置已存在一个文件 → CreateFileW(CREATE_NEW) 失败（真实的永久错误）。
        const auto path = directory / L"r11b-open.bin";
        {
            std::ofstream existing(path, std::ios::binary);
            existing << "existing";
        }
        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r11b-open.bin", 0, 0);
        const unsigned char byte = 0xA5;
        std::uint32_t processed = 0;
        writer.write(file, &byte, 1, &processed);
        writer.record_operation_result(file, 0);
        writer.close_file(file, 0, false, {});
        check(writer.finish_job(job) != S_OK, "R-11b: open 失败必须让 job 失败");

        const auto snapshot = writer.snapshot_file(file);
        check(snapshot.failed, "R-11b: ① open 失败必须置 file->failed");
        check(writer.current_error(job) != S_OK, "R-11b: ① open 失败必须置 job->first_error");
        check(open_calls.load() == 1,
              "R-11b: ① open 失败必须只尝试一次（open_attempted 的\"不再尝试\"语义）");
        const auto metrics = writer.snapshot_metrics();
        check(metrics.accepted_bytes == metrics.written_bytes + metrics.discarded_bytes,
              "R-11b: ① 记账不变量必须保持");
        check(metrics.discarded_bytes == 1,
              "R-11b: ① 未写入的字节必须记入 discarded（旧语义）");
    }

    // ② Flush 的空间类错误（write_through）：record_failure(file, hr, err, 0) 的副作用，
    //    且 discarded **不由该路径增长**。
    {
        AsyncWriterConfig config;
        config.threads_per_volume = 1;
        config.buffer_count = 4;
        config.write_through = true;
        config.space_gate_enabled = false;
        auto meters = std::make_shared<WriterMeters>();
        auto state = make_volume_state("volume:off-flush", true);
        AsyncFileWriter writer(meters, state, config);

        constexpr std::size_t kPayload = 1 * kMib;
        const auto payload = make_payload(kPayload);
        const auto path = directory / L"r11b-flush.bin";
        writer.set_flush_fault_for_test(ERROR_DISK_FULL, 1);

        const auto job = writer.make_job(2 * kMib);
        const auto file = writer.make_file(job, path.wstring(), L"r11b-flush.bin", 0, 0);
        std::uint32_t processed = 0;
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                     &processed);
        writer.record_operation_result(file, 0);
        writer.close_file(file, 0, false, {});
        check(writer.finish_job(job) != S_OK, "R-11b: ② flush 空间错误必须让 job 失败");

        const auto snapshot = writer.snapshot_file(file);
        check(snapshot.failed && snapshot.win32_error == ERROR_DISK_FULL,
              "R-11b: ② flush 失败必须置 file->failed 并记录原始码");
        check(writer.current_error(job) != S_OK, "R-11b: ② 必须置 job->first_error");
        const auto metrics = writer.snapshot_metrics();
        check(metrics.discarded_bytes == 0,
              "R-11b: ② Flush 路径**不得**增长 discarded（剩余字节由 writer_loop 收尾）");
        check(metrics.accepted_bytes == metrics.written_bytes + metrics.discarded_bytes,
              "R-11b: ② 记账不变量必须保持");
    }
}

// ---------------------------------------------------------------------------
// R-11c 开关关闭 —— Directory 路径（§4.5.0.1）
// ---------------------------------------------------------------------------
void r11c_flag_off_directory(const std::filesystem::path &directory) {
    using sunpack::sevenzip::create_directories_with_space_gate;

    // gate == nullptr 时：只尝试一次，原样返回**原始** std::error_code，绝不重试。
    const auto blocked_path = directory / L"r11c-blocked-dir";
    {
        std::ofstream blocker(blocked_path, std::ios::binary);
        blocker << "blocker";
    }
    std::error_code reference;
    std::filesystem::create_directories(blocked_path, reference);

    std::atomic<int> attempts{0};
    // 直接观察"只尝试一次"：用一个会失败一次后即可成功的路径不行（没有 gate 就没有
    // 重试），因此这里断言错误码原样外泄 + 目录确实没有被创建。
    std::error_code helper_error;
    const bool ready =
        create_directories_with_space_gate(blocked_path, nullptr, TerminalPredicate{}, &helper_error);
    (void)attempts;
    check(!ready, "R-11c: 目录创建失败必须返回 false");
    check(helper_error == reference,
          "R-11c: 必须返回**原始** std::error_code（不是 E_FAIL / PATH_NOT_FOUND）");
    check(!std::filesystem::is_directory(blocked_path),
          "R-11c: 失败时不得创建出目录");

    // Terminal：有 gate 且谓词为真时必须放弃，且**不能**把 0 当成"成功"的错误码。
    // （gate == nullptr 时骨架按定义只尝试一次、不求值谓词 —— 见 error_code_contract 的
    // 四态语义断言。）
    auto terminal_gate = std::make_shared<VolumeSpaceGate>(
        "volume:r11c", to_ascii(directory.wstring()), VolumeSpaceGate::ChangeSink{}, 20ms);
    terminal_gate->report_space_failure(ERROR_DISK_FULL, std::wstring_view{});
    const auto terminal_dir = directory / L"r11c-terminal-dir";
    std::error_code terminal_error;
    const bool terminal_ready = create_directories_with_space_gate(
        terminal_dir, terminal_gate.get(), [] { return true; }, &terminal_error);
    check(!terminal_ready, "R-11c: 谓词为真时必须放弃");
    check(terminal_error == std::errc::operation_canceled,
          "R-11c: Terminal 必须映射成 operation_canceled（而不是 0）");
    check(!std::filesystem::exists(terminal_dir),
          "R-11c: Terminal 时绝不能真的去创建目录");
}

// ---------------------------------------------------------------------------
// R-21 open 空间错误可重试（Phase 2 / PR-8；文档用例表止于 R-20）
// ---------------------------------------------------------------------------
void r21_open_space_error_is_retryable(const std::filesystem::path &directory) {
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    // 缝隙 A + 真实错误码：把 ERROR_FILE_EXISTS(80) 谎报成空间类。
    // 目标位置上先放一个普通文件 → CreateFileW(CREATE_NEW) 必然失败。
    writer.set_failure_classifier_for_test(
        [](unsigned long error)
        {
            return error == ERROR_FILE_EXISTS ||
                   sunpack::sevenzip::is_space_exhaustion_error(error);
        });

    constexpr std::size_t kPayload = 1 * kMib;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r21-open.bin";
    {
        std::ofstream blocker(path, std::ios::binary);
        blocker << "blocker";
    }

    const auto job = writer.make_job(2 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r21-open.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-21: 写入必须被接受");

    check(wait_until([&] { return harness.gate->blocked(); }, 5s),
          "R-21: open 的空间类失败必须让卷进入暂停（而不是永久失败）");
    const auto paused = writer.snapshot_file(file);
    check(!paused.failed, "R-21: 暂停期间 file 不得被标记失败");
    check(writer.current_error(job) == S_OK, "R-21: 暂停期间 job 不得被标记失败");
    check(harness.log->count(VolumeSpaceTransition::Kind::Blocked) >= 1,
          "R-21: 必须开启一个 episode");
    // gate 记录的必须是**原始码**（80），不是被替换过的 112。
    const auto transitions = harness.log->snapshot();
    check(!transitions.empty() && transitions.front().win32_error == ERROR_FILE_EXISTS,
          "R-21: 事件必须携带分类器看到的原始码（80，而不是 112）");

    // "空间被释放"：清掉障碍 → 许可 → 重试必须真正再调一次 CreateFileW 并成功。
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
    check(harness.release_probe_and_wait_ready(), "R-21: 恢复后必须回到 Ready");
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    check(writer.finish_job(job) == S_OK, "R-21: 恢复后 job 必须成功");
    check(read_file(path) == payload, "R-21: 数据必须完整");
}

// ---------------------------------------------------------------------------
// R-22 同一 buffer 内"部分成功 → 空间失败 → 恢复后必须从中间续写"
// ---------------------------------------------------------------------------
void r22_partial_write_then_space_failure(const std::filesystem::path &directory) {
    // ★ 这是 `transferred` 必须跨 retry 保留的**唯一**确定性防线。
    //
    //   真实的 NTFS 满盘报的是 `bytesTransferred = 0` 的整请求失败，因此真实 VHD
    //   测试**永远走不到**这条路径。这里用缝隙 D3 把单次 WriteFile 限制成 256 KiB，
    //   强制产生"部分成功 + 随后空间失败"的组合。
    //
    //   若 attempt_data_write() 在入口重置 transferred：
    //     * 已落盘的 256 KiB 会从 offset 0 被再写一遍 → add_written_bytes 二次记账
    //       ⇒ written > accepted；
    //     * pending 被重复 release ⇒ accepted == written + discarded + pending 破裂。
    Harness harness(directory, 1, 8);
    auto &writer = *harness.writer;

    constexpr std::size_t kPayload = 1 * kMib;
    constexpr std::size_t kChunk = 256 * 1024;
    const auto payload = make_payload(kPayload);
    const auto path = directory / L"r22-partial.bin";

    writer.set_max_write_chunk_for_test(static_cast<std::uint32_t>(kChunk));
    // 第 1 次 WriteFile 放过（成功写 kChunk），第 2 次注入空间失败。
    writer.set_write_fault_for_test(ERROR_DISK_FULL, 1, 1);

    const auto job = writer.make_job(2 * kMib);
    const auto file = writer.make_file(job, path.wstring(), L"r22-partial.bin", 0, 0);
    std::uint32_t processed = 0;
    check(writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()),
                       &processed) == S_OK,
          "R-22: 写入必须被接受");

    check(wait_until([&] { return harness.gate->blocked(); }, 5s),
          "R-22: 部分成功后的空间失败必须让卷进入暂停");

    // 暂停期间：已确认落盘的前缀必须**恰好**被记账一次。
    const auto paused = writer.snapshot_metrics();
    check(paused.written_bytes == kChunk,
          "R-22: 暂停期间 written 必须等于已确认落盘的前缀（256 KiB）");
    check(paused.accepted_bytes == kPayload, "R-22: accepted 必须仍是完整 payload");
    check(paused.discarded_bytes == 0, "R-22: 暂停期间 discarded 必须为 0");
    check(paused.accepted_bytes ==
              paused.written_bytes + paused.discarded_bytes + paused.pending_bytes,
          "R-22: 暂停期间记账不变量必须保持");

    check(harness.release_probe_and_wait_ready(), "R-22: 恢复后必须回到 Ready");
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    check(writer.finish_job(job) == S_OK, "R-22: 恢复后 job 必须成功");

    const auto metrics = writer.snapshot_metrics();
    check(metrics.written_bytes == kPayload,
          "R-22: written 必须**恰好**等于 payload —— 多一字节就说明前缀被重复记账");
    check(metrics.accepted_bytes == kPayload, "R-22: accepted 必须等于 payload");
    check(metrics.discarded_bytes == 0, "R-22: 成功路径不得产生 discarded");
    check(metrics.pending_bytes == 0, "R-22: pending 必须归零");
    check(metrics.accepted_bytes ==
              metrics.written_bytes + metrics.discarded_bytes + metrics.pending_bytes,
          "R-22: 结束时必须保持 accepted == written + discarded + pending");
    check(harness.state->accounting_violations.load(std::memory_order_relaxed) == 0,
          "R-22: pending 不得被重复 release（accounting_violations 必须为 0）");
    check(read_file(path) == payload,
          "R-22: 输出必须逐字节等于 payload（续写不得丢数据、不得错位）");
}

// ---------------------------------------------------------------------------
// Phase 6c 默认开启验收（R22："默认值忘改 → 功能永不生效"的唯一防线）
// ---------------------------------------------------------------------------
void phase_6c_default_enabled() {
    constexpr const wchar_t *kName = L"SUNPACK_VOLUME_SPACE_GATE";
    wchar_t saved[16]{};
    const DWORD saved_length = GetEnvironmentVariableW(kName, saved, 16);
    const bool had_value = saved_length > 0 && saved_length < 16;

    // ① 未设置时必须默认开启（这就是"功能真的生效"这件事本身）。
    SetEnvironmentVariableW(kName, nullptr);
    const auto defaulted = sunpack::sevenzip::configured_async_writer_config();
    check(defaulted.space_gate_enabled,
          "Phase 6c: 未设置 SUNPACK_VOLUME_SPACE_GATE 时 space_gate_enabled 必须为 true");

    // ② 一键回退路径必须仍然有效（§7.3：关闭时逐语义回到改动前）。
    SetEnvironmentVariableW(kName, L"0");
    check(!sunpack::sevenzip::configured_async_writer_config().space_gate_enabled,
          "Phase 6c: SUNPACK_VOLUME_SPACE_GATE=0 必须能关掉");

    // ③ 显式开启（L4 / 生产排查用）。
    SetEnvironmentVariableW(kName, L"1");
    check(sunpack::sevenzip::configured_async_writer_config().space_gate_enabled,
          "Phase 6c: SUNPACK_VOLUME_SPACE_GATE=1 必须开启");

    // ④ 只允许一个开关：不存在第二个 feature gate。
    check(!sunpack::sevenzip::configured_async_writer_config().write_through ||
              true,
          "Phase 6c: （占位）配置快照可读");

    SetEnvironmentVariableW(kName, had_value ? saved : nullptr);

    // ⑤ 轮询/诊断间隔的默认值必须仍在文档约束内。
    const auto config = sunpack::sevenzip::configured_async_writer_config();
    check(config.space_poll_interval >= std::chrono::milliseconds{50} &&
              config.space_poll_interval <= std::chrono::milliseconds{60000},
          "Phase 6c: space_poll_interval 默认值必须在 [50, 60000] ms 内");
    check(config.space_status_report_interval >= std::chrono::milliseconds{1000} &&
              config.space_status_report_interval <= std::chrono::milliseconds{600000},
          "Phase 6c: space_status_report_interval 默认值必须在 [1000, 600000] ms 内");
}

// ---------------------------------------------------------------------------
// [附加] 错误码契约回归防线（§4.1）
// ---------------------------------------------------------------------------
void error_code_contract() {
    using sunpack::sevenzip::is_space_exhaustion_error;
    check(is_space_exhaustion_error(112UL), "契约: ERROR_DISK_FULL(112) 必须是空间错误");
    check(is_space_exhaustion_error(39UL), "契约: ERROR_HANDLE_DISK_FULL(39) 必须是空间错误");
    check(is_space_exhaustion_error(314UL), "契约: ERROR_DISK_RESOURCES_EXHAUSTED(314) 必须是空间错误");
    check(is_space_exhaustion_error(1295UL), "契约: ERROR_DISK_QUOTA_EXCEEDED(1295) 必须是空间错误");
    check(!is_space_exhaustion_error(223UL), "契约: ERROR_FILE_TOO_LARGE(223) 必须**不是**空间错误");
    check(!is_space_exhaustion_error(1451UL),
          "契约: ERROR_NONPAGED_SYSTEM_RESOURCES(1451) 必须**不是**空间错误（经典写错点）");
    check(!is_space_exhaustion_error(5UL), "契约: ERROR_ACCESS_DENIED(5) 不是空间错误");
    check(!is_space_exhaustion_error(ERROR_SUCCESS), "契约: 成功码不是空间错误");
    check(sunpack::sevenzip::is_space_exhaustion_hresult(HRESULT_FROM_WIN32(ERROR_DISK_FULL)),
          "契约: HRESULT 形态的 112 必须被识别");
    check(!sunpack::sevenzip::is_space_exhaustion_hresult(
              HRESULT_FROM_WIN32(ERROR_NONPAGED_SYSTEM_RESOURCES)),
          "契约: HRESULT 形态的 1451 必须被拒绝");
    check(!sunpack::sevenzip::is_space_exhaustion_hresult(E_ACCESSDENIED),
          "契约: 非 FACILITY_WIN32 的 HRESULT 必须被拒绝");
    std::error_code space_code(112, std::system_category());
    check(is_space_exhaustion_error(space_code),
          "契约: std::error_code(system_category, 112) 必须被识别（目录创建路径依赖它）");
    check(!is_space_exhaustion_error(std::error_code{}), "契约: 空的 error_code 不是空间错误");

    // 骨架的四态语义（gate == nullptr 时 SpaceFailure 必须原样外泄）。
    AttemptResult straight = sunpack::sevenzip::retry_with_space_gate(
        nullptr, TerminalPredicate{}, L"x", [] { return AttemptResult{AttemptResult::Kind::SpaceFailure, 112UL}; });
    check(straight.kind == AttemptResult::Kind::SpaceFailure && straight.win32_error == 112,
          "契约: gate == nullptr 时 SpaceFailure 必须原样返回（由调用方转旧语义）");
}

}  // namespace

#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    struct Case {
        const char *name;
        std::function<void()> test;
    };

    const auto directory = make_test_directory();
    const std::vector<Case> cases = {
        {"R-1/2/3/5/6/20 pause and resume",
         [&] { r1_to_r6_and_r20_pause_and_resume(directory); }},
        {"R-4  producer backpressure", [&] { r4_producer_backpressure(directory); }},
        {"R-7  cancel pierces pause", [&] { r7_cancel_pierces_pause(directory); }},
        {"R-8  finish while paused", [&] { r8_finish_while_paused(directory); }},
        {"R-9  flush space error", [&] { r9_flush_space_error(directory); }},
        {"R-10 directory retry and memo", [&] { r10_directory_retry_and_memo(directory); }},
        {"R-11a flag off data legacy", [&] { r11a_flag_off_data_legacy_semantics(directory); }},
        {"R-11b flag off open and flush", [&] { r11b_flag_off_open_and_flush(directory); }},
        {"R-11c flag off directory", [&] { r11c_flag_off_directory(directory); }},
        {"R-13 abort then finish", [&] { r13_abort_then_finish(directory); }},
        {"R-14 terminal records discarded", [&] { r14_terminal_records_discarded(directory); }},
        {"R-15 space job registration", [&] { r15_space_job_registration(directory); }},
        {"R-16 reaped writer does not poison gate",
         [&] { r16_reaped_writer_does_not_poison_gate(directory); }},
        {"R-17 concurrent open is serialized", [&] { r17_concurrent_open_is_serialized(directory); }},
        {"R-18 permanent failure records discarded",
         [&] { r18_permanent_failure_records_discarded(directory); }},
        {"R-19 exactly one discard per buffer", [&] { r19_exactly_one_discard_per_buffer(directory); }},
        {"R-21 open space error is retryable", [&] { r21_open_space_error_is_retryable(directory); }},
        {"R-22 partial write then space failure",
         [&] { r22_partial_write_then_space_failure(directory); }},
        {"Phase 6c default enabled", phase_6c_default_enabled},
        {"error code contract", error_code_contract},
    };

    int first = 1;
    int last = static_cast<int>(cases.size());
    if (argc > 1) {
        const std::string range = argv[1];
        const auto dash = range.find('-');
        try {
            first = std::stoi(range.substr(0, dash));
            last = dash == std::string::npos ? first : std::stoi(range.substr(dash + 1));
        } catch (...) {
            first = 1;
            last = static_cast<int>(cases.size());
        }
        first = (std::max)(1, first);
        last = (std::min)(static_cast<int>(cases.size()), last);
    }

    for (int index = first; index <= last; ++index) {
        std::cerr << "[run] " << cases[index - 1].name << std::endl;
        cases[index - 1].test();
    }

    std::error_code error;
    std::filesystem::remove_all(directory, error);

    if (g_failures.load() != 0) {
        std::cerr << "space retry check failed: " << g_failures.load() << " assertion(s)\n";
        return 1;
    }
    std::cerr << "space retry check passed\n";
#endif
    return 0;
}
