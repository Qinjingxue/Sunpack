#pragma once

// Benchmark-only instrumentation and IO ablations. Never compiled into the
// ordinary worker; memory sinks intentionally do not produce extraction output.
#ifdef SUP7Z_ENABLE_WRITER_PROBE
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace sunpack::sevenzip {
enum class WriterProbePhase : unsigned {
    Producer, FileLock, SetupLock, CapacityWait, Copy, CommitLock, Queue,
    Dispatch, OpenLock, Open, Preallocate, WriteFile, Completion,
    ReleaseLock, Close, FinishLock, FinishWait, Count
};
inline const char *writer_probe_mode() noexcept {
    static const char *mode = std::getenv("SUNPACK_WRITER_PROBE_MODE");
    return mode ? mode : "real";
}
inline bool writer_probe_memory() noexcept {
    return std::strncmp(writer_probe_mode(), "memory", 6) == 0;
}
inline unsigned long long writer_probe_clock() noexcept {
    return static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
struct WriterProbe {
    static constexpr unsigned kCount = static_cast<unsigned>(WriterProbePhase::Count);
    const bool enabled = [] { const char *p = std::getenv("SUNPACK_WRITER_PROBE"); return p && p[0] == '1'; }();
    std::array<std::atomic<unsigned long long>, kCount> ns{}, calls{}, peak{};
    std::atomic<unsigned long long> file_full{0}, job_full{0}, buffers_empty{0};
    void add(WriterProbePhase phase, unsigned long long elapsed) noexcept {
        const unsigned i = static_cast<unsigned>(phase);
        ns[i].fetch_add(elapsed, std::memory_order_relaxed);
        calls[i].fetch_add(1, std::memory_order_relaxed);
        auto old = peak[i].load(std::memory_order_relaxed);
        while (old < elapsed && !peak[i].compare_exchange_weak(old, elapsed, std::memory_order_relaxed)) {}
    }
    void dump() const {
        if (!enabled) return;
        static const char *names[kCount] = {"producer", "file_lock", "setup_lock", "capacity_wait", "copy", "commit_lock", "queue", "dispatch", "open_lock", "open", "preallocate", "writefile", "completion", "release_lock", "close", "finish_lock", "finish_wait"};
        std::ostringstream out;
        out << "WRITER_PROBE {\"mode\":\"" << writer_probe_mode() << "\",\"phases\":{";
        for (unsigned i = 0; i < kCount; ++i) {
            if (i) out << ',';
            out << '"' << names[i] << "\":{\"ns\":" << ns[i].load()
                << ",\"calls\":" << calls[i].load() << ",\"max_ns\":" << peak[i].load() << '}';
        }
        out << "},\"file_full\":" << file_full.load() << ",\"job_full\":" << job_full.load()
            << ",\"buffers_empty\":" << buffers_empty.load() << "}\n";
        const auto line = out.str();
        std::fwrite(line.data(), 1, line.size(), stderr);
    }
};
class WriterProbeSpan {
    WriterProbe *probe_;
    WriterProbePhase phase_;
    unsigned long long started_;
public:
    WriterProbeSpan(WriterProbe &probe, WriterProbePhase phase) noexcept
        : WriterProbeSpan(&probe, phase) {}
    WriterProbeSpan(WriterProbe *probe, WriterProbePhase phase) noexcept
        : probe_(probe && probe->enabled ? probe : nullptr), phase_(phase), started_(probe_ ? writer_probe_clock() : 0) {}
    ~WriterProbeSpan() { finish(); }
    void finish() noexcept { if (probe_) { probe_->add(phase_, writer_probe_clock() - started_); probe_ = nullptr; } }
};
}
#endif
