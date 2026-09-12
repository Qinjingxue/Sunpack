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
    // 卷级空间状态的唯一定义。
    enum class VolumeSpacePhase
    {
        Ready = 0,   // 正常
        Blocked = 1, // 有过一次确凿的空间失败，等待空间改善
        Probing = 2, // 已发放一个 probe 许可，等待真实 I/O 裁决
    };

    // 每次 wait 都传入当前 writer 的终态谓词；gate 不保存任何 writer 状态。
    // 谓词只能读 atomic：非 atomic 的 JobState 字段由 writer mutex_ 保护，而 wait() 不持
    // 那把锁，直接读它们是 data race / UB。
    using TerminalPredicate = std::function<bool()>;

    // gate 在锁内生成、锁外回调的转换描述；job_ids 是 affected_jobs_ 的快照。
    struct VolumeSpaceTransition
    {
        enum class Kind
        {
            Blocked, // space_blocked
            Status,  // space_status（只由 monitor 生成）
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
        // 仅真实的卷可写性变化（Ready→Blocked / Probing→Ready）为 true；register_job() 的
        // 补发只是事件补齐，必须保持 false，否则会反复 reset controller 的自适应学习。
        bool discontinuity = false;
        std::vector<std::string> job_ids;
    };

    using VolumeSpaceChangeSink = std::function<void(const VolumeSpaceTransition &)>;

    // 把"卷身份"翻译成"可作为根目录访问的 Win32 路径"：
    //     \\?\Volume{GUID}   是身份键（map key、日志、去重）
    //     \\?\Volume{GUID}\  是同一信息的可查询形态
    //
    // 两者只差一个尾反斜杠，无尾反斜杠的查询会得到 ERROR_INVALID_FUNCTION。
    // 前缀比较必须大小写不敏感，Rust 侧传入的是全小写 \\?\volume{...}。
    // 返回空字符串表示"这个键不是路径"（synthetic key），此时由调用方改用
    // GetVolumePathNameW 从真实失败路径就地解析。
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
    // GetVolumePathNameW 会跟随 junction / mounted folder，且路径不存在也能解析。
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

        // 32768 覆盖 \\?\ 长路径上限，单次调用足够。
        std::vector<wchar_t> buffer(32768, L'\0');
        const DWORD written = GetVolumePathNameW(
            failed_path.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (written == 0)
        {
            return false;
        }
        // GetVolumePathNameW 成功时返回非零值而非长度，长度必须从缓冲区量
        // （API 保证 NUL 结尾）。
        const auto terminator = std::find(buffer.begin(), buffer.end(), L'\0');
        std::wstring resolved(buffer.begin(), terminator);
        if (resolved.empty())
        {
            return false;
        }
        // API 返回的挂载根自带尾反斜杠，这里只做防御性补齐。
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

    // probe 许可的 RAII 结算句柄：
    //     report_success()           真实成功           → Probing -> Ready
    //     report_space_failure(...)  仍然空间不足        → Probing -> Blocked
    //     report_inconclusive()      非空间错误/无法判定  → Probing -> Blocked
    //     析构时未结算                等同 report_inconclusive()
    //
    // 非空间错误（ERROR_ACCESS_DENIED / FILE_EXISTS / PATH_NOT_FOUND / sharing violation）
    // 不能证明卷已恢复可写，绝不能当成功结算。
    // 析构兜底：一次真实尝试有多条返回路径，漏结算会让该卷永久停在 Probing。
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

        // 未结算 → 等同 report_inconclusive()（→ Blocked，绝不 Ready）
        ~ProbeLease() { settle_unfinished(); }

        void report_success() noexcept;
        void report_space_failure(unsigned long win32_error, std::wstring_view failed_path) noexcept;
        void report_inconclusive() noexcept;

        // 尚未结算的有效许可。
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

    // 卷级空间 gate：Ready/Blocked/Probing + episode + watermark + probe 许可 + query root。
    //
    // 生命周期：gate 的存活期 = VolumeState 的存活期，长于 writer facility，因此 gate 里
    // 绝不能保存任何指向 writer 成员的指针/引用。本类必须由 shared_ptr 持有（wait() 需要
    // shared_from_this 来构造 ProbeLease），栈上构造会让 wait() 走生命周期降级路径。
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

        // 由 job 的 volume lease scope 调用（不是 make_job / finish_job）：根输出目录创建
        // 是最常见的满盘入口，那时它还没发生，space_blocked 会发给 0 个 job。
        //
        // set 语义：空 job_id 或已存在的 id → 不注册、返回 false、绝不产生第二条事件；
        //           注册时若卷非 Ready → 立即给该 job 补发一条 space_blocked。
        bool register_job(const std::string &job_id) noexcept;
        void unregister_job(const std::string &job_id) noexcept;

        // failed_path：引致失败的实际路径；synthetic 卷首次用它就地解析查询根，必须传。
        //
        // 按当前 phase 分派：
        //     Ready   → 开启新 episode（episode_id++、重置水位、发 space_blocked）
        //     Blocked → 只更新失败证据（不改 phase、不发事件）
        //     Probing → 只更新失败证据，绝不夺走现有 probe ownership
        // 返回 true 表示本次调用开启了新 episode。
        bool report_space_failure(unsigned long win32_error,
                                  std::wstring_view failed_path) noexcept;

        struct WaitResult
        {
            enum class Kind
            {
                Ready,    // 可以正常重试一次（未持有许可，无需结算）
                Probe,    // 持有 probe 许可，必须结算（lease 有效）
                Terminal, // job 取消 / writer draining → 放弃并走既有失败路径
            } kind = Kind::Ready;
            ProbeLease lease; // 仅 kind == Probe 时有效
        };

        // Ready 与 Terminal 必须可区分：把无效 lease 当成 Terminal 会让"报满后延迟进入
        // wait()"误判为取消、释放 buffer 并丢数据。
        //
        // terminal：每次调用传入的终态谓词；gate 不保存它。
        WaitResult wait(const TerminalPredicate &terminal) noexcept;

        // 全项目唯一的卷空间查询入口，只允许 monitor 调用：writer / probe owner 线程从不
        // 查询磁盘空间，GetDiskFreeSpaceExW 因此不会阻塞写路径。
        // query_root_ 未解析（synthetic 卷首次失败前）时返回 false。
        bool query_free_bytes(std::uint64_t *free_bytes, std::uint64_t *total_bytes) noexcept;
        unsigned long last_query_error() const noexcept;
        // 卷暂时不可查询（拔盘 / UNC 断开 / 权限变化 / query_root 未解析）：只记录诊断，
        // 不改变状态。
        void note_query_failure(unsigned long win32_error) noexcept;

        // 空间改善则发放一个 probe 许可并进入 Probing；全部水位规则在这里，monitor 只采样：
        //     !watermark_valid_          → 首次成功观测，设为 baseline 并立即发放许可
        //     free > failed_watermark_   → 发放许可
        //     否则                        → 无新证据，保持 Blocked
        bool poll(std::uint64_t free_bytes_now) noexcept;

        // 唯一用途：让阻塞在 cv_ 上的线程重新求值自己的 terminal predicate；不改变状态。
        void wake_waiters() noexcept;

        VolumeSpacePhase phase() const noexcept;
        bool blocked() const noexcept; // Blocked || Probing
        std::uint64_t failed_free_watermark() const noexcept;
        std::uint64_t episode_id() const noexcept;
        bool watermark_valid() const noexcept;
        std::vector<std::string> affected_job_ids() const;
        std::size_t waiter_count() const noexcept;
        // wait() 被调用的累计次数（只读），供测试证明正常写路径从不进入 gate。
        std::uint64_t wait_call_count() const noexcept;
        const std::string &volume_key() const noexcept { return volume_key_; }
        bool query_root_resolved() const noexcept;

    private:
        friend class ProbeLease;

        // 只有 ProbeLease 能调用；仅当 phase_ == Probing && probe_owner_token_ == token 时
        // 才允许改变状态，否则 no-op（stale lease）。
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

        // synthetic 卷的查询根解析：锁外做 Win32 调用，锁内只提交结果。
        // GetVolumePathNameW 绝不能在 gate mutex_ 内执行：对失联 UNC / 坏盘的一次慢解析会
        // 堵住同卷的 wait() / wake_waiters()，而那是取消与关停的必经路径。
        void resolve_query_root_outside_lock(const std::wstring &failed_path) noexcept
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (query_root_resolved_)
                {
                    return;
                }
            }
            if (failed_path.empty())
            {
                return;
            }
            std::wstring resolved;
            if (!resolve_query_root_from_path(failed_path, &resolved))
            {
                return;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            if (!query_root_resolved_) // 别人先解析了就保留先到的结果
            {
                query_root_ = std::move(resolved);
                query_root_resolved_ = true;
            }
        }

        mutable std::mutex mutex_;
        std::condition_variable cv_;

        VolumeSpacePhase phase_ = VolumeSpacePhase::Ready;
        std::uint64_t episode_id_ = 0;            // 每次 Ready→Blocked 递增
        bool watermark_valid_ = false;            // 初期查询失败则不猜
        // 当前 episode 的 space_blocked 是否已经生成（transition 已发给 sink）：把
        // register_job() 的补发限制在初始事件发出之后，避免同 episode 重复投递 blocked。
        bool blocked_event_emitted_ = false;
        std::uint64_t failed_free_watermark_ = 0; // 仅在当前 episode 内单调
        std::uint64_t probe_owner_token_ = 0;     // 0 = 许可待领取
        std::uint64_t next_token_ = 1;
        unsigned long last_win32_error_ = 0;
        std::chrono::steady_clock::time_point blocked_since_{};
        std::uint64_t last_free_bytes_ = 0; // 最近一次成功采样值（仅诊断与展示）
        bool last_query_ok_ = true;
        unsigned long last_query_error_ = 0;

        std::string volume_key_;   // 身份键：\\?\Volume{GUID} 小写无尾反斜杠 / job:<id>
        std::wstring query_root_;  // 身份键的可查询形态（补回尾反斜杠）或就地解析结果
        bool query_root_resolved_ = false;

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
                // 事件补齐：job 已注册，却因 producer backpressure 没有任何 writer 线程
                // 进入 gate->wait()。
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

        resolve_query_root_outside_lock(std::wstring(failed_path));

        {
            std::lock_guard<std::mutex> lock(mutex_);
            last_win32_error_ = win32_error;

            if (phase_ == VolumeSpacePhase::Ready)
            {
                ++episode_id_;
                phase_ = VolumeSpacePhase::Blocked;
                // 水位按 episode 重新建立，由 monitor 的第一次成功采样确立 baseline。
                watermark_valid_ = false;
                failed_free_watermark_ = 0;
                probe_owner_token_ = 0;
                blocked_event_emitted_ = false;
                blocked_since_ = std::chrono::steady_clock::now();
                opened_episode = true;

                // blocked 事件必须在同一把锁内生成：否则"进入 Blocked"与"事件可见"之间
                // 会出现可插队窗口（新 job 收到迟到 blocked、或与补发重复投递）。
                if (phase_ != VolumeSpacePhase::Ready)
                {
                    transitions.push_back(make_transition_locked(
                        VolumeSpaceTransition::Kind::Blocked, /*discontinuity=*/true));
                    blocked_event_emitted_ = true;
                }
                else
                {
                    blocked_event_emitted_ = false;
                }
            }
            // Blocked / Probing：只更新失败证据；Probing 期间绝不夺走现有 probe ownership，
            // "盘是否已恢复"的裁决权属于当前 probe owner 的真实操作。
        }

        cv_.notify_all();
        emit_transitions(transitions);
        return opened_episode;
    }

    inline VolumeSpaceGate::WaitResult VolumeSpaceGate::wait(
        const TerminalPredicate &terminal) noexcept
    {
        const std::shared_ptr<VolumeSpaceGate> self = weak_from_this().lock();
        if (!self)
        {
            // 生命周期不变量被破坏：必须返回 Terminal，返回 Ready 会变成无许可的忙重试。
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
                // 只在真正要睡下时才进入 waiters_，使它精确表示当前阻塞的线程。
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
            // 没有查询根：保持 Blocked，只记录诊断。
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
                // Probing：许可已发出但尚未结算 → 绝不再发放第二个。
                return false;
            }

            if (!watermark_valid_)
            {
                // 首次成功观测 → 立即设为 baseline 并发放许可（不是先比较再决定）。
                failed_free_watermark_ = free_bytes_now;
                watermark_valid_ = true;
                failed_free_watermark_ = free_bytes_now;
                issued = true;
            }
            else if (free_bytes_now > failed_free_watermark_)
            {

                // 授权 probe 的这次采样立即成为新的 failure watermark：否则 probe 失败后
                // 水位不变，会每个 poll 周期重复一次真实 probe。
                failed_free_watermark_ = free_bytes_now;
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
        cv_.notify_all();
    }

    inline void VolumeSpaceGate::settle_success(std::uint64_t token) noexcept
    {
        std::vector<VolumeSpaceTransition> transitions;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!owns_probe_locked(token))
            {
                return; // stale lease：静默失效
            }
            // Probing → Ready 的唯一合法原因是一次真实成功。
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
        resolve_query_root_outside_lock(std::wstring(failed_path));

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!owns_probe_locked(token))
            {
                return;
            }
            phase_ = VolumeSpacePhase::Blocked;
            probe_owner_token_ = 0;
            last_win32_error_ = win32_error;
            // 不做新鲜查询：水位已由 poll() 在发放许可时推进，下一次许可要求一次严格更高的
            // monitor 采样。
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

    inline std::uint64_t VolumeSpaceGate::wait_call_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return next_waiter_token_ - 1; // token 从 1 开始
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
        // pending_bytes 由 VolumeWriterRegistry 侧的 sink 包装补齐（gate 不认识 VolumeState）。
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
        // sink 必须在 gate 锁释放之后调用：sink 会取 g_output_mutex 并做 IO。
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
                // 诊断输出失败绝不能破坏 gate 状态。
            }
        }
    }

}

#endif
