#pragma once

#include "sevenzip_space_error.hpp"

#ifdef _WIN32

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace sunpack::sevenzip
{
    // ---------------------------------------------------------------------
    // 卷级空间状态。**唯一状态定义**。
    //
    // 曾经存在于 sevenzip_writer_meters.hpp 的
    //     enum class VolumeSpaceState { Ready, SpaceBlocked };
    // 与 VolumeState::space_state 原子量已删除（零使用，保留会造成"两个真相"）。
    // ---------------------------------------------------------------------
    enum class VolumeSpacePhase
    {
        Ready = 0,   // 正常
        Blocked = 1, // 有过一次确凿的空间失败，等待空间改善
        Probing = 2, // 空间已改善，已发放一个 probe 许可，等待真实 I/O 裁决
    };

    // 每次 wait 都传入当前 writer 的终态谓词。gate **不保存**任何 writer 状态。
    //
    // ★ 谓词只能读 atomic（非 atomic 的 JobState::cancelled / first_error 由 writer
    //   mutex_ 保护，而 wait() 不持那把锁 —— 直接读它们是 data race / UB）。
    using TerminalPredicate = std::function<bool()>;

    // gate 在锁内生成、锁外回调的转换描述。job_ids 是 affected_jobs_ 的快照。
    struct VolumeSpaceTransition
    {
        enum class Kind
        {
            Blocked, // space_blocked
            Status,  // space_status（**只由 monitor 生成**，gate 从不产生）
            Resumed, // space_resumed
        };

        Kind kind = Kind::Blocked;
        std::string volume_key;
        std::uint64_t episode_id = 0;
        unsigned long win32_error = 0;
        std::uint64_t free_bytes = 0;
        std::uint64_t pending_bytes = 0;
        double blocked_seconds = 0.0;
        bool query_ok = true;
        unsigned long query_error = 0;
        // ★ 这是否是一次**真实的卷可写性变化**（Ready→Blocked / Probing→Ready）。
        //
        //   `register_job()` 对新注册 job 的**补发通知**也发 Kind::Blocked，但那只是
        //   事件补齐，磁盘可写环境根本没变。controller 的 discontinuity generation
        //   只能由真实转换推进 —— 否则"blocked 卷持续进入新 job"会让自适应控制器
        //   反复 reset learning（与"只有真实转换才是 throughput discontinuity"不符）。
        bool discontinuity = false;
        std::vector<std::string> job_ids;
    };

    using VolumeSpaceChangeSink = std::function<void(const VolumeSpaceTransition &)>;

    // ---------------------------------------------------------------------
    // 把"卷身份"翻译成"可作为根目录访问的 Win32 路径"。
    //
    //   \\?\Volume{GUID}      是身份键（map key、日志、去重）
    //   \\?\Volume{GUID}\     是同一信息的可查询形态
    //
    // ⚠️ 两者只差一个尾反斜杠（§16.1 实测：无尾反斜杠 → err=1 ERROR_INVALID_FUNCTION）。
    // ⚠️ 前缀比较**必须大小写不敏感**：Rust 的 volume_key_from() 会把整个字符串
    //    转成小写，实际传入的是 \\?\volume{...}。用 L"\\\\?\\Volume{" 直接比较会
    //    永远不匹配 → 查询路径永远解析不出来 → 该卷永不恢复。
    //
    // 返回空字符串表示"这个键不是路径"（synthetic key），由调用方改用
    // GetVolumePathNameW 从真实失败路径就地解析。
    // ---------------------------------------------------------------------
    inline bool is_volume_guid_key(const std::wstring &volume_key) noexcept
    {
        constexpr wchar_t kPrefix[] = L"\\\\?\\Volume{";
        constexpr std::size_t kPrefixLength = (sizeof(kPrefix) / sizeof(wchar_t)) - 1;
        if (volume_key.size() < kPrefixLength)
        {
            return false;
        }
        for (std::size_t index = 0; index < kPrefixLength; ++index)
        {
            wchar_t left = volume_key[index];
            if (left >= L'A' && left <= L'Z')
            {
                left = static_cast<wchar_t>(left - L'A' + L'a');
            }
            wchar_t right = kPrefix[index];
            if (right >= L'A' && right <= L'Z')
            {
                right = static_cast<wchar_t>(right - L'A' + L'a');
            }
            if (left != right)
            {
                return false;
            }
        }
        return true;
    }

    inline std::wstring space_query_path(const std::wstring &volume_key) noexcept
    {
        if (!is_volume_guid_key(volume_key))
        {
            return std::wstring{};
        }
        if (!volume_key.empty() && volume_key.back() == L'\\')
        {
            return volume_key;
        }
        return volume_key + L'\\';
    }

    // synthetic / unknown 卷：用引致失败的实际路径就地解析查询根。
    // 内部就是 GetVolumePathNameW —— 权威 API，天然跟随 junction / mounted folder，
    // 且**路径不存在也能解析**（§16.2 实测）。
    inline bool resolve_query_root_from_path(
        const std::wstring &failed_path,
        std::wstring *query_root) noexcept
    {
        if (query_root)
        {
            query_root->clear();
        }
        if (failed_path.empty())
        {
            return false;
        }

        // 单次调用就够：32768 覆盖 \\?\ 长路径上限，不需要两段式探测。
        std::vector<wchar_t> buffer(32768, L'\0');
        const DWORD written = GetVolumePathNameW(
            failed_path.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (written == 0)
        {
            return false;
        }
        // ⚠️ 成功时返回值只是"非零"（本机实测恒为 1），**不是**字符串长度。
        //    把它当长度会得到 "C" 这样的半个路径 → GetDiskFreeSpaceExW 报
        //    ERROR_PATH_NOT_FOUND(3)，于是 synthetic 卷永远无法查询、永不恢复。
        //    长度必须从缓冲区里量（API 保证以 NUL 结尾）。
        const auto terminator = std::find(buffer.begin(), buffer.end(), L'\0');
        std::wstring resolved(buffer.begin(), terminator);
        if (resolved.empty())
        {
            return false;
        }
        // GetVolumePathNameW 返回的挂载根自带尾反斜杠；这里只做防御性补齐。
        if (resolved.back() != L'\\')
        {
            resolved.push_back(L'\\');
        }
        if (query_root)
        {
            *query_root = std::move(resolved);
        }
        return true;
    }

    inline bool query_volume_free_bytes(
        const std::wstring &path,
        std::uint64_t *free_bytes,
        std::uint64_t *total_bytes) noexcept
    {
        if (free_bytes)
        {
            *free_bytes = 0;
        }
        if (total_bytes)
        {
            *total_bytes = 0;
        }
        if (path.empty())
        {
            return false;
        }

        ULARGE_INTEGER available{};
        ULARGE_INTEGER total{};
        ULARGE_INTEGER total_free{};
        if (!GetDiskFreeSpaceExW(path.c_str(), &available, &total, &total_free))
        {
            return false;
        }
        if (free_bytes)
        {
            *free_bytes = static_cast<std::uint64_t>(available.QuadPart);
        }
        if (total_bytes)
        {
            *total_bytes = static_cast<std::uint64_t>(total.QuadPart);
        }
        return true;
    }

    class VolumeSpaceGate;

    // ---------------------------------------------------------------------
    // probe 许可的 RAII 结算句柄。**结算语义有四种**：
    //     report_success()           真实成功            → Probing -> Ready
    //     report_space_failure(...)  仍然空间不足        → Probing -> Blocked
    //     report_inconclusive()      非空间错误/无法判定  → Probing -> Blocked
    //     析构时未结算                等同 report_inconclusive()
    //
    // ⚠️ report_inconclusive() 不是防御性代码：ERROR_ACCESS_DENIED / FILE_EXISTS /
    //    PATH_NOT_FOUND / sharing violation **都不能证明卷已恢复可写**。
    //    早期文档写的 "PermanentFailure → report_success()" 是错的，会让一个永久
    //    失败的探测假冒成 space_resumed。
    //
    // ⚠️ 析构兜底的必要性：一次真实尝试有多条返回路径。任何一条漏结算都会让该卷
    //    **永久停在 Probing**。RAII 把"漏调用"从"永久挂起"降级为"回 Blocked 下轮重试"。
    // ---------------------------------------------------------------------
    class ProbeLease final
    {
    public:
        ProbeLease() = default;

        ProbeLease(ProbeLease &&other) noexcept
            : gate_(std::move(other.gate_)), token_(other.token_), settled_(other.settled_)
        {
            other.token_ = 0;
            other.settled_ = true;
        }

        ProbeLease &operator=(ProbeLease &&other) noexcept
        {
            if (this != &other)
            {
                settle_unfinished();
                gate_ = std::move(other.gate_);
                token_ = other.token_;
                settled_ = other.settled_;
                other.token_ = 0;
                other.settled_ = true;
            }
            return *this;
        }

        ProbeLease(const ProbeLease &) = delete;
        ProbeLease &operator=(const ProbeLease &) = delete;

        // 未结算 → 等同 report_inconclusive()（→ Blocked，绝不 Ready，不发事件）
        ~ProbeLease() { settle_unfinished(); }

        void report_success() noexcept;
        void report_space_failure(unsigned long win32_error, std::wstring_view failed_path) noexcept;
        void report_inconclusive() noexcept;

        // 持有有效许可（尚未结算）。骨架用它在 attempt 之后决定是否结算。
        bool valid() const noexcept { return gate_ != nullptr && !settled_; }

    private:
        friend class VolumeSpaceGate;

        ProbeLease(std::shared_ptr<VolumeSpaceGate> gate, std::uint64_t token) noexcept
            : gate_(std::move(gate)), token_(token), settled_(false) {}

        void settle_unfinished() noexcept;

        std::shared_ptr<VolumeSpaceGate> gate_;
        std::uint64_t token_ = 0;
        bool settled_ = true;
    };

    // ---------------------------------------------------------------------
    // 卷级空间 gate。**只保留三种职责**：
    //     Ready/Blocked/Probing + episode + watermark + probe 许可 + query root
    //
    // 明确**不存在**的东西（不要重新引入）：
    //     ✗ aborted_ 永久闩锁 / set_abort_ref() / set_cancel_predicate()
    //     ✗ weak_ptr<JobState>（gate 不依赖 AsyncFileWriter —— 单向依赖）
    //     ✗ set_change_sink()（sink 由构造函数注入，"只能初始化一次"由类型系统保证）
    //     ✗ set_wake_monitor() / monitor membership / re-arm
    //     ✗ waiters_ 参与事件 fan-out（两个集合职责分离）
    //
    // ⚠️ 生命周期：gate 的存活期 = VolumeState 的存活期，**长于 writer facility**。
    //    因此 gate 里绝不能保存任何指向 writer 成员的指针/引用。
    // ⚠️ 本类必须由 shared_ptr 持有（wait() 需要 shared_from_this 来构造 ProbeLease）。
    //    栈上构造会让 wait() 走"生命周期不变量被破坏"的降级路径。
    // ---------------------------------------------------------------------
    class VolumeSpaceGate final : public std::enable_shared_from_this<VolumeSpaceGate>
    {
    public:
        using ChangeSink = VolumeSpaceChangeSink;

        // volume_key：身份键（= \\?\Volume{GUID}，小写无尾反斜杠）。
        // query_root_hint：resolved 卷可省略（构造时自动补尾反斜杠）；
        //                  synthetic 卷留空，首次空间失败时用 failed_path 就地解析。
        // wait_tick：wait() 重新求值 terminal predicate 的周期（默认 poll_interval）。
        VolumeSpaceGate(std::string volume_key,
                        std::string query_root_hint,
                        ChangeSink sink,
                        std::chrono::milliseconds wait_tick = std::chrono::milliseconds{1000})
            : volume_key_(std::move(volume_key)),
              query_root_(widen_ascii(query_root_hint)),
              wait_tick_(wait_tick > std::chrono::milliseconds::zero()
                             ? wait_tick
                             : std::chrono::milliseconds{1000}),
              sink_(std::move(sink))
        {
            if (!query_root_.empty())
            {
                query_root_resolved_ = true;
            }
            else
            {
                std::wstring derived = space_query_path(widen_ascii(volume_key_));
                if (!derived.empty())
                {
                    query_root_ = std::move(derived);
                    query_root_resolved_ = true;
                }
            }
        }

        // ---- 1) 事件注册（job 生命周期，与线程无关）------------------------
        // ★ 由 NativeJobExecutor 的 volume lease scope 调用（SpaceJobRegistration），
        //   **不是** make_job / finish_job —— 后者在根输出目录创建之前还没发生，
        //   而根目录创建正是最常见的满盘入口（那样 space_blocked 会发给 0 个 job）。
        //
        // set 语义（写死，避免 accidental double register 产生幽灵事件）：
        //     空 job_id      → 不注册，返回 false
        //     已存在的 id    → no-op，返回 false（绝不产生第二条 event）
        //     注册时若卷非 Ready → **立即**给该 job 补发一条 space_blocked
        bool register_job(const std::string &job_id) noexcept;
        void unregister_job(const std::string &job_id) noexcept;

        // ---- 2) 空间失败上报 ----------------------------------------------
        // failed_path：引致失败的实际路径。resolved 卷忽略；synthetic 卷用它
        //              首次就地解析查询根。**必须传**，否则 synthetic 卷永久不可查询。
        //
        // 行为按当前 phase 分派（§4.2.8.1）：
        //     Ready   → 开启新 episode（episode_id++、新鲜查询 watermark、发 space_blocked）
        //     Blocked → 只更新失败证据（不改 phase、不发事件）
        //     Probing → 只更新失败证据，**绝不夺走现有 probe ownership**
        // 返回 true 表示本次调用开启了新 episode。
        bool report_space_failure(unsigned long win32_error,
                                  std::wstring_view failed_path) noexcept;

        // ---- 3) probe 许可与等待（**三态**）--------------------------------
        struct WaitResult
        {
            enum class Kind
            {
                Ready,    // 可以正常重试一次（未持有许可，无需结算）
                Probe,    // 持有 probe 许可，**必须**结算（lease 有效）
                Terminal, // job 取消 / writer draining → 放弃并走既有失败路径
            } kind = Kind::Ready;
            ProbeLease lease; // 仅 kind == Probe 时有效
        };

        // ⚠️ Ready 与 Terminal **必须可区分**。早期版本让两者都返回无效 lease、
        //    而 writer_loop 把"无效"当成 Terminal，于是"A 报满后延迟进入 wait()，
        //    期间 B 完成 probe"会让 A 误认为取消 → buffer 被释放 → 数据丢失。
        //
        // terminal：**每次调用传入**的终态谓词。gate 不保存 writer 指针，也不保存
        //           全局 cancel predicate。
        WaitResult wait(const TerminalPredicate &terminal) noexcept;

        // ---- 4) monitor 接口 ----------------------------------------------
        // ★ 全项目唯一一处把"卷身份"翻译成"可查询路径"的地方。
        //   query_root_ 未解析（synthetic 卷首次失败前）时返回 false。
        bool query_free_bytes(std::uint64_t *free_bytes, std::uint64_t *total_bytes) noexcept;
        unsigned long last_query_error() const noexcept;
        // B5：卷暂时不可查询（拔盘 / UNC 断开 / 权限变化 / query_root 未解析）。
        // **只记录诊断，不改变状态**。
        void note_query_failure(unsigned long win32_error) noexcept;

        // 空间改善则发放一个 probe 许可并进入 Probing。**独占全部水位逻辑**：
        // monitor 只负责采样，不做任何比较。
        //     !watermark_valid_          → 首次成功观测，设为 baseline 并立即发放许可
        //     free > failed_watermark_   → 发放许可
        //     否则                        → 无新证据，保持 Blocked
        bool poll(std::uint64_t free_bytes_now) noexcept;

        // ---- 5) 唤醒（**不改变状态、不永久闩锁**）---------------------------
        // 唯一用途：让阻塞在 cv_ 上的线程重新求值自己的 terminal predicate。
        // 没有 aborted_ 永久标志，没有 set_abort_ref()，没有 writer 指针。
        void wake_waiters() noexcept;

        // ---- 6) 只读观测 ---------------------------------------------------
        VolumeSpacePhase phase() const noexcept;
        bool blocked() const noexcept; // Blocked || Probing
        std::uint64_t failed_free_watermark() const noexcept;
        std::uint64_t episode_id() const noexcept;
        bool watermark_valid() const noexcept;
        std::vector<std::string> affected_job_ids() const;
        std::size_t waiter_count() const noexcept;
        const std::string &volume_key() const noexcept { return volume_key_; }
        bool query_root_resolved() const noexcept;

    private:
        friend class ProbeLease;

        // ---- ProbeLease 的结算入口（**只有 ProbeLease 能调用**）--------------
        // 全部结算都先校验 token 所有权：
        //     仅当 phase_ == Probing && probe_owner_token_ == token 才允许改变状态，
        //     否则 no-op（stale lease）。比"用过期 token 把状态改回去"安全得多。
        void settle_success(std::uint64_t token) noexcept;
        void settle_space_failure(std::uint64_t token,
                                  unsigned long win32_error,
                                  std::wstring_view failed_path) noexcept;
        void settle_inconclusive(std::uint64_t token) noexcept;

        struct Waiter
        {
            std::uint64_t token = 0;
        };

        static std::wstring widen_ascii(const std::string &text)
        {
            std::wstring wide;
            wide.reserve(text.size());
            for (const char value : text)
            {
                wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(value)));
            }
            return wide;
        }

        bool owns_probe_locked(std::uint64_t token) const noexcept
        {
            return phase_ == VolumeSpacePhase::Probing && token != 0 &&
                   probe_owner_token_ == token;
        }

        void remove_waiter_locked(std::uint64_t token) noexcept;
        VolumeSpaceTransition make_transition_locked(VolumeSpaceTransition::Kind kind,
                                                     bool discontinuity) const;
        void emit_transitions(const std::vector<VolumeSpaceTransition> &transitions) noexcept;
        // Ready → Blocked 时的一次【新鲜】查询 + 提交。**必须在 mutex_ 之外调用**。
        //
        // ⚠️ 已接受的 v1 限制（架构师第三轮）：这次查询虽然不在 gate 锁内，但仍然由
        //    **当前 writer 线程同步执行**。若输出是失联 UNC / 坏网络盘 / 某些过滤驱动，
        //    `GetDiskFreeSpaceExW` 可能长时间不返回，于是这个 writer 线程被卡住，
        //    shutdown 最终仍要等它 —— T-WIN-20 用的是本地 VHD，测不到这一种。
        //
        //    架构上唯一**必须**非阻塞的是 monitor 侧的查询（§4.4.2：绝不在 executor
        //    mutex_ 内查询，否则 submit/cancel/admission 全被堵住），那一条已经满足。
        //
        //    彻底解法（需要改冻结架构，未采纳）：**所有 free-space query 都只让 monitor
        //    做** —— 首次失败直接 `watermark_valid=false → Blocked → 立即发事件`，
        //    monitor 第一次成功采样即 baseline 并允许一次 probe；这样可以删掉
        //    commit_fresh_watermark()，writer 永不调用空间查询。
        void commit_fresh_watermark(std::uint64_t episode_token,
                                    const std::wstring &query_path) noexcept;

        mutable std::mutex mutex_;
        std::condition_variable cv_;

        // --- 卷状态（本 gate 的全部持久状态）---
        VolumeSpacePhase phase_ = VolumeSpacePhase::Ready;
        std::uint64_t episode_id_ = 0;            // 每次 Ready→Blocked 递增
        bool watermark_valid_ = false;            // 初期查询失败则不猜
        // 当前 episode 的 `space_blocked` **是否已经生成**（transition 已经发给 sink）。
        //
        // ⚠️ Ready→Blocked 的流程是：先在锁内进入 Blocked，再在锁外做新鲜查询，
        //    最后才生成并发送 transition。如果新 job 恰好落在"已 Blocked 但事件还没发"
        //    的窗口里，`register_job()` 的补发会与随后的初始 transition **重复**投递
        //    同 episode 的 blocked（Python 只对 stale-resumed 去重，不重复去重 blocked）。
        //    用这个标志把补发限制在"初始事件已经发出"之后。
        bool blocked_event_emitted_ = false;
        std::uint64_t failed_free_watermark_ = 0; // **仅在当前 episode 内单调**
        std::uint64_t probe_owner_token_ = 0;     // 0 = 许可待领取
        std::uint64_t next_token_ = 1;
        unsigned long last_win32_error_ = 0;
        std::chrono::steady_clock::time_point blocked_since_{};
        std::uint64_t last_free_bytes_ = 0; // 最近一次成功查询/采样值（仅诊断与展示）
        bool last_query_ok_ = true;
        unsigned long last_query_error_ = 0;

        // --- 查询路径（唯一的私有缓存）---
        std::string volume_key_;   // 身份键：\\?\Volume{GUID} 小写无尾反斜杠 / job:<id>
        std::wstring query_root_;  // 身份键的"可查询形态"（补回尾反斜杠）或就地解析结果
        bool query_root_resolved_ = false;

        // --- 两种集合，职责分离 ---
        std::vector<Waiter> waiters_;            // 线程：只做 probe 许可仲裁
        std::vector<std::string> affected_jobs_; // job：只做事件 fan-out

        std::chrono::milliseconds wait_tick_{1000};
        ChangeSink sink_;
        std::uint64_t next_waiter_token_ = 1;
    };

    inline void ProbeLease::settle_unfinished() noexcept
    {
        if (gate_ && !settled_)
        {
            settled_ = true;
            gate_->settle_inconclusive(token_);
        }
        gate_.reset();
    }

    inline void ProbeLease::report_success() noexcept
    {
        if (!gate_ || settled_)
        {
            return;
        }
        settled_ = true;
        gate_->settle_success(token_);
        gate_.reset();
    }

    inline void ProbeLease::report_space_failure(
        unsigned long win32_error, std::wstring_view failed_path) noexcept
    {
        if (!gate_ || settled_)
        {
            return;
        }
        settled_ = true;
        gate_->settle_space_failure(token_, win32_error, failed_path);
        gate_.reset();
    }

    inline void ProbeLease::report_inconclusive() noexcept
    {
        if (!gate_ || settled_)
        {
            return;
        }
        settled_ = true;
        gate_->settle_inconclusive(token_);
        gate_.reset();
    }

    inline bool VolumeSpaceGate::register_job(const std::string &job_id) noexcept
    {
        if (job_id.empty())
        {
            return false;
        }

        std::vector<VolumeSpaceTransition> transitions;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (std::find(affected_jobs_.begin(), affected_jobs_.end(), job_id) !=
                affected_jobs_.end())
            {
                return false;
            }
            affected_jobs_.push_back(job_id);
            if (phase_ != VolumeSpacePhase::Ready && blocked_event_emitted_)
            {
                // 补发：解决"job 卡在 producer backpressure，永远没有 writer 线程
                // 进入 gate->wait()"的情形 —— 它已经注册，所以照样收到通知。
                //
                // ⚠️ 两个刻意的限定：
                //   1) `discontinuity = false` —— 这只是事件补齐，磁盘可写环境没变，
                //      绝不能推进 controller 的 discontinuity generation；
                //   2) 只在初始 blocked 事件**已经发出**之后补发 —— 否则它会和随即
                //      生成的初始 transition 重复投递同 episode 的 blocked。
                VolumeSpaceTransition transition =
                    make_transition_locked(VolumeSpaceTransition::Kind::Blocked,
                                           /*discontinuity=*/false);
                transition.job_ids.clear();
                transition.job_ids.push_back(job_id);
                transitions.push_back(std::move(transition));
            }
        }
        emit_transitions(transitions);
        return true;
    }

    inline void VolumeSpaceGate::unregister_job(const std::string &job_id) noexcept
    {
        if (job_id.empty())
        {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        affected_jobs_.erase(
            std::remove(affected_jobs_.begin(), affected_jobs_.end(), job_id),
            affected_jobs_.end());
    }

    inline bool VolumeSpaceGate::report_space_failure(
        unsigned long win32_error, std::wstring_view failed_path) noexcept
    {
        std::vector<VolumeSpaceTransition> transitions;
        bool opened_episode = false;
        std::uint64_t episode_token = 0;
        std::wstring query_path;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            last_win32_error_ = win32_error;

            // synthetic 卷：首次空间错误时就用真实失败路径就地解析查询根。
            if (!query_root_resolved_ && !failed_path.empty())
            {
                std::wstring resolved;
                if (resolve_query_root_from_path(std::wstring(failed_path), &resolved))
                {
                    query_root_ = std::move(resolved);
                    query_root_resolved_ = true;
                }
            }

            if (phase_ == VolumeSpacePhase::Ready)
            {
                ++episode_id_;
                phase_ = VolumeSpacePhase::Blocked;
                // 水位必须**按 episode 重新建立**：跨 episode 永久单调会让
                // "ep1 失败于 500 MiB、ep2 失败于 10 MiB"的用户即使释放到 200 MiB
                // 也永远不 probe。
                watermark_valid_ = false;
                failed_free_watermark_ = 0;
                probe_owner_token_ = 0;
                blocked_event_emitted_ = false; // 初始 blocked 事件还没生成
                blocked_since_ = std::chrono::steady_clock::now();
                opened_episode = true;
                episode_token = episode_id_;
                query_path = query_root_;
            }
            // Blocked / Probing：只更新失败证据（last_win32_error_ 已记录）。
            // ★ Probing 期间绝不夺走现有 probe ownership —— "盘是否已恢复"的裁决权
            //   属于当前 probe owner 的真实操作；旁路 late failure 只说明"那一刻盘
            //   还是满的"，是有效证据但不推翻正在进行的 probe。
        }

        if (opened_episode)
        {
            // ★ 新鲜查询在 gate mutex_ **之外**执行（§4.2.4.1）。
            //   wait() / wake_waiters() 是取消与关停的必经路径，让它们被一次慢查询
            //   （离线 UNC 可能卡几秒）堵住是不可接受的。校验成本只是一个 uint64 比较。
            commit_fresh_watermark(episode_token, query_path);

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (episode_id_ == episode_token)
                {
                    transitions.push_back(make_transition_locked(
                        VolumeSpaceTransition::Kind::Blocked, /*discontinuity=*/true));
                    blocked_event_emitted_ = true;
                }
            }
        }

        cv_.notify_all();
        emit_transitions(transitions);
        return opened_episode;
    }

    inline void VolumeSpaceGate::commit_fresh_watermark(
        std::uint64_t episode_token, const std::wstring &query_path) noexcept
    {
        std::uint64_t free_bytes = 0;
        std::uint64_t total_bytes = 0;
        bool queried = false;
        // 空路径不调用 API，因此**不能**读 GetLastError()（那是别的调用留下的陈旧值）。
        unsigned long query_error = ERROR_PATH_NOT_FOUND;
        if (!query_path.empty())
        {
            queried = query_volume_free_bytes(query_path, &free_bytes, &total_bytes);
            query_error = queried ? 0UL : GetLastError();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (episode_id_ != episode_token)
        {
            // 期间 episode 已被他人改动 → 丢弃本次结果，不修改任何状态。
            return;
        }
        last_query_ok_ = queried;
        last_query_error_ = queried ? 0UL : query_error;
        if (queried)
        {
            last_free_bytes_ = free_bytes;
            // "first evidence wins"：若 monitor 已经用一次同样新鲜的成功采样建立了
            // baseline，就不要用更旧的值覆盖它。
            if (!watermark_valid_)
            {
                failed_free_watermark_ = free_bytes;
                watermark_valid_ = true;
            }
        }
        // 查询失败 → 保持 watermark_valid_ = false（不猜）。此时 poll() 会把第一次
        // 成功观测设为 baseline 并立即发放一次许可。
    }

    inline VolumeSpaceGate::WaitResult VolumeSpaceGate::wait(
        const TerminalPredicate &terminal) noexcept
    {
        // ProbeLease 持有 shared_ptr<VolumeSpaceGate>；本类必须由 shared_ptr 持有。
        const std::shared_ptr<VolumeSpaceGate> self = weak_from_this().lock();
        if (!self)
        {
            // 生命周期不变量被破坏（gate 不是 shared_ptr 持有）。
            // ⚠️ 必须返回 **Terminal**（而不是默认构造的 `WaitResult{}`，那是 Ready）：
            //    Ready 会让调用方"未持有许可地重试一次"，在 gate 已经不可用的前提下
            //    会变成无许可的忙重试。Terminal 让它走既有失败路径、不丢数据地放弃。
            return {WaitResult::Kind::Terminal, ProbeLease{}};
        }

        std::unique_lock<std::mutex> lock(mutex_);
        const std::uint64_t waiter_token = next_waiter_token_++;
        bool registered = false;

        for (;;)
        {
            if (terminal && terminal())
            {
                if (registered)
                {
                    remove_waiter_locked(waiter_token);
                }
                return WaitResult{WaitResult::Kind::Terminal, ProbeLease{}};
            }
            if (phase_ == VolumeSpacePhase::Ready)
            {
                // ★ 与 Terminal **可区分**：未持有许可，直接重试一次。
                if (registered)
                {
                    remove_waiter_locked(waiter_token);
                }
                return WaitResult{WaitResult::Kind::Ready, ProbeLease{}};
            }
            if (phase_ == VolumeSpacePhase::Probing && probe_owner_token_ == 0)
            {
                const std::uint64_t token = next_token_++;
                probe_owner_token_ = token;
                if (registered)
                {
                    remove_waiter_locked(waiter_token);
                }
                return WaitResult{WaitResult::Kind::Probe, ProbeLease(self, token)};
            }

            if (!registered)
            {
                // 只在真正要睡下时才进入 waiters_，保证它精确表示"当前阻塞的线程"。
                waiters_.push_back(Waiter{waiter_token});
                registered = true;
            }
            cv_.wait_for(lock, wait_tick_);
        }
    }

    inline bool VolumeSpaceGate::query_free_bytes(
        std::uint64_t *free_bytes, std::uint64_t *total_bytes) noexcept
    {
        std::wstring path;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            path = query_root_;
        }
        if (path.empty())
        {
            // → monitor 走 B5 诊断分支，保持 Blocked。
            std::lock_guard<std::mutex> lock(mutex_);
            last_query_ok_ = false;
            last_query_error_ = ERROR_PATH_NOT_FOUND;
            return false;
        }

        std::uint64_t local_free = 0;
        std::uint64_t local_total = 0;
        const bool queried = query_volume_free_bytes(path, &local_free, &local_total);
        const unsigned long query_error = queried ? 0UL : GetLastError();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            last_query_ok_ = queried;
            last_query_error_ = queried ? 0UL : query_error;
            if (queried)
            {
                last_free_bytes_ = local_free;
            }
        }
        if (queried)
        {
            if (free_bytes)
            {
                *free_bytes = local_free;
            }
            if (total_bytes)
            {
                *total_bytes = local_total;
            }
        }
        return queried;
    }

    inline unsigned long VolumeSpaceGate::last_query_error() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_query_error_;
    }

    inline void VolumeSpaceGate::note_query_failure(unsigned long win32_error) noexcept
    {
        // B5：只记录诊断，不改变状态（不转 Ready、不转 Probing、不新增状态）。
        std::lock_guard<std::mutex> lock(mutex_);
        last_query_ok_ = false;
        last_query_error_ = win32_error;
    }

    inline bool VolumeSpaceGate::poll(std::uint64_t free_bytes_now) noexcept
    {
        bool issued = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            last_free_bytes_ = free_bytes_now;
            if (phase_ == VolumeSpacePhase::Ready || phase_ == VolumeSpacePhase::Probing)
            {
                // Probing：许可已发出但尚未结算 → 绝不再发放第二个（G-7）。
                return false;
            }

            if (!watermark_valid_)
            {
                // 初期查询失败过；这是第一次成功观测 → 立即设为 baseline 并允许一次
                // 真实 probe。**不是**"先比较再决定"（`free > 0` 为假会让这个卷永久卡住）。
                failed_free_watermark_ = free_bytes_now;
                watermark_valid_ = true;
                issued = true;
            }
            else if (free_bytes_now > failed_free_watermark_)
            {
                issued = true;
            }

            if (issued)
            {
                phase_ = VolumeSpacePhase::Probing;
                probe_owner_token_ = 0; // 许可"待领取"
            }
        }
        if (issued)
        {
            cv_.notify_all(); // 唤醒等待者；只有一个能拿到许可
        }
        return issued;
    }

    inline void VolumeSpaceGate::wake_waiters() noexcept
    {
        // **只唤醒，不改变任何状态、不永久闩锁。**
        // 被唤醒的线程用自己传入的 terminal predicate 决定去留。
        cv_.notify_all();
    }

    inline void VolumeSpaceGate::settle_success(std::uint64_t token) noexcept
    {
        std::vector<VolumeSpaceTransition> transitions;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!owns_probe_locked(token))
            {
                return; // stale lease：静默失效，比"用过期 token 把状态改回去"安全得多
            }
            // 铁律一：Probing -> Ready 的**唯一**合法原因是一次真实成功。
            phase_ = VolumeSpacePhase::Ready;
            probe_owner_token_ = 0;
            last_win32_error_ = 0;
            blocked_event_emitted_ = false;
            blocked_since_ = std::chrono::steady_clock::time_point{};
            transitions.push_back(make_transition_locked(
                VolumeSpaceTransition::Kind::Resumed, /*discontinuity=*/true));
        }
        cv_.notify_all(); // 全部等待者恢复
        emit_transitions(transitions);
    }

    inline void VolumeSpaceGate::settle_space_failure(
        std::uint64_t token, unsigned long win32_error, std::wstring_view failed_path) noexcept
    {
        std::uint64_t episode_token = 0;
        std::wstring query_path;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!owns_probe_locked(token))
            {
                return;
            }
            phase_ = VolumeSpacePhase::Blocked;
            probe_owner_token_ = 0;
            last_win32_error_ = win32_error;
            if (!query_root_resolved_ && !failed_path.empty())
            {
                std::wstring resolved;
                if (resolve_query_root_from_path(std::wstring(failed_path), &resolved))
                {
                    query_root_ = std::move(resolved);
                    query_root_resolved_ = true;
                }
            }
            episode_token = episode_id_;
            query_path = query_root_;
        }

        // 同 episode 内 probe 失败：再做一次【新鲜】查询（同样在锁外），
        // watermark = max(watermark, fresh)。**sink 不上报**（同一 episode 内去重）。
        std::uint64_t free_bytes = 0;
        std::uint64_t total_bytes = 0;
        bool queried = false;
        unsigned long query_error = ERROR_PATH_NOT_FOUND;
        if (!query_path.empty())
        {
            queried = query_volume_free_bytes(query_path, &free_bytes, &total_bytes);
            query_error = queried ? 0UL : GetLastError();
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (episode_id_ == episode_token)
            {
                last_query_ok_ = queried;
                last_query_error_ = queried ? 0UL : query_error;
                if (queried)
                {
                    last_free_bytes_ = free_bytes;
                    failed_free_watermark_ = (std::max)(failed_free_watermark_, free_bytes);
                    watermark_valid_ = true;
                }
            }
        }
        cv_.notify_all();
    }

    inline void VolumeSpaceGate::settle_inconclusive(std::uint64_t token) noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!owns_probe_locked(token))
            {
                return;
            }
            // 非空间错误**不能证明卷可写** → 绝不进入 Ready → 不发 space_resumed。
            phase_ = VolumeSpacePhase::Blocked;
            probe_owner_token_ = 0;
        }
        cv_.notify_all(); // 若仍有 affected job，等待者会重新裁决并重选一个 probe
    }

    inline VolumeSpacePhase VolumeSpaceGate::phase() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return phase_;
    }

    inline bool VolumeSpaceGate::blocked() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return phase_ != VolumeSpacePhase::Ready;
    }

    inline std::uint64_t VolumeSpaceGate::failed_free_watermark() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return failed_free_watermark_;
    }

    inline std::uint64_t VolumeSpaceGate::episode_id() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return episode_id_;
    }

    inline bool VolumeSpaceGate::watermark_valid() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return watermark_valid_;
    }

    inline std::vector<std::string> VolumeSpaceGate::affected_job_ids() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return affected_jobs_;
    }

    inline std::size_t VolumeSpaceGate::waiter_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return waiters_.size();
    }

    inline bool VolumeSpaceGate::query_root_resolved() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return query_root_resolved_;
    }

    inline void VolumeSpaceGate::remove_waiter_locked(std::uint64_t token) noexcept
    {
        for (auto it = waiters_.begin(); it != waiters_.end(); ++it)
        {
            if (it->token == token)
            {
                waiters_.erase(it);
                return;
            }
        }
    }

    inline VolumeSpaceTransition VolumeSpaceGate::make_transition_locked(
        VolumeSpaceTransition::Kind kind, bool discontinuity) const
    {
        VolumeSpaceTransition transition;
        transition.kind = kind;
        transition.discontinuity = discontinuity;
        transition.volume_key = volume_key_;
        transition.episode_id = episode_id_;
        transition.win32_error = last_win32_error_;
        transition.free_bytes = last_free_bytes_;
        transition.query_ok = last_query_ok_;
        transition.query_error = last_query_error_;
        // pending_bytes 由 VolumeWriterRegistry 侧的 sink 包装补齐
        // （gate 不认识 VolumeState —— 依赖方向必须单向）。
        transition.job_ids = affected_jobs_;
        if (blocked_since_ != std::chrono::steady_clock::time_point{})
        {
            transition.blocked_seconds =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - blocked_since_)
                    .count();
        }
        return transition;
    }

    inline void VolumeSpaceGate::emit_transitions(
        const std::vector<VolumeSpaceTransition> &transitions) noexcept
    {
        // ⚠️ sink 必须在 gate 锁**释放之后**调用：sink 会取 g_output_mutex 并做 IO。
        //    锁序审查因此只需看 executor/registry/writer/gate 四把锁。
        if (!sink_)
        {
            return;
        }
        for (const auto &transition : transitions)
        {
            try
            {
                sink_(transition);
            }
            catch (...)
            {
                // 诊断输出失败绝不能破坏 gate 状态（这些函数都是 noexcept）。
            }
        }
    }

}

#endif
