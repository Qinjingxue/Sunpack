#pragma once
#include "native_cpu_budget.hpp"
#include "native_memory.hpp"
#include "extraction_replay.hpp"
#include <algorithm>
#include <exception>
#include <thread>
#include <vector>

namespace sunpack::sevenzip {
// Decoder lanes borrow the existing job's CPU and allocation budgets. No
// executor, decoder, or scratch allocation survives this synchronous scope.
class PasswordParallelism {
    NativeCpuJobContext* cpu_ = current_native_cpu_job_context();
    NativeMemoryJob* memory_ = current_native_memory_job();
    std::size_t extra_ = 0;
public:
    explicit PasswordParallelism(std::size_t wanted) {
        if (cpu_ && wanted > 1) extra_ = cpu_->acquire_extra(wanted - 1);
    }
    ~PasswordParallelism() { if (cpu_) cpu_->release_extra(extra_); }
    void limit(std::size_t tasks) {
        const auto needed = tasks ? tasks - 1 : 0;
        if (extra_ > needed) { cpu_->release_extra(extra_ - needed); extra_ = needed; }
    }
    std::size_t size() const { return extra_ + 1; }
    template<class Function> void run(std::size_t count, Function&& function) {
        count = (std::min)(count, size());
        if (count <= 1) {
            if (count) {
                ExtractionReplayScope replay(nullptr);
                function(0, count);
            }
            return;
        }
        std::vector<std::exception_ptr> failures(count);
        std::vector<std::thread> threads;
        threads.reserve(count ? count - 1 : 0);
        auto invoke = [&](std::size_t lane) {
            NativeMemoryScope memory(memory_);
            NativeCpuContextScope cpu(cpu_);
            ExtractionReplayScope replay(nullptr);
            try { function(lane, count); } catch (...) { failures[lane] = std::current_exception(); }
        };
        std::size_t spawned = 1;
        std::exception_ptr launch_failure;
        try {
            for (; spawned < count; ++spawned) {
                if (memory_ && !memory_->owner.may_start_thread(*memory_)) break;
                threads.emplace_back(invoke, spawned);
            }
        } catch (const std::system_error&) { /* Use the already admitted lanes. */ }
        catch (...) { launch_failure = std::current_exception(); }
        // Logical lanes that run on the calling thread need no extra credit.
        limit(spawned);
        if (!launch_failure) {
            if (count) invoke(0);
            for (auto lane = spawned; lane < count; ++lane) invoke(lane);
        }
        for (auto& thread : threads) thread.join();
        if (launch_failure) std::rethrow_exception(launch_failure);
        for (auto& failure : failures) if (failure) std::rethrow_exception(failure);
    }
};
}
