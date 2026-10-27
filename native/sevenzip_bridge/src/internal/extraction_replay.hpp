#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <filesystem>
#include <unordered_map>
#include <string>
#include <utility>
#include <vector>

namespace sunpack::sevenzip {
// Successful IOCP completions can have holes. Coalescing intervals normally
// stays at one element; storage grows with outstanding holes, not output size.
class WrittenRanges {
public:
    using Range = std::pair<std::uint64_t, std::uint64_t>;
    void add(std::uint64_t begin, std::uint64_t end) {
        if (begin == end) return;
        if (begin <= prefix_) {
            prefix_ = (std::max)(prefix_, end);
            auto last = ranges_.begin();
            while (last != ranges_.end() && last->first <= prefix_) { prefix_ = (std::max)(prefix_, last->second); ++last; }
            ranges_.erase(ranges_.begin(), last);
            return;
        }
        auto first = std::lower_bound(ranges_.begin(), ranges_.end(), begin,
            [](const Range &range, auto offset) { return range.second < offset; });
        auto last = first;
        while (last != ranges_.end() && last->first <= end) {
            begin = (std::min)(begin, last->first); end = (std::max)(end, last->second); ++last;
        }
        if (first == last) ranges_.insert(first, {begin, end});
        else { first->first = begin; first->second = end; ranges_.erase(first + 1, last); }
    }
    // Next homogeneous run: covered bytes or a hole.
    std::pair<bool, std::uint64_t> next(std::uint64_t offset, std::uint64_t size) const {
        if (offset < prefix_) return {true, (std::min)(size, prefix_ - offset)};
        auto it = std::upper_bound(ranges_.begin(), ranges_.end(), offset,
            [](auto value, const Range &range) { return value < range.second; });
        if (it == ranges_.end()) return {false, size};
        if (offset < it->first) return {false, (std::min)(size, it->first - offset)};
        return {true, (std::min)(size, it->second - offset)};
    }
    std::uint64_t bytes() const noexcept {
        std::uint64_t result = prefix_; for (auto range : ranges_) result += range.second - range.first; return result;
    }
private:
    std::vector<Range> ranges_;
    std::uint64_t prefix_ = 0;
};

struct ReplayFile {
    std::wstring path;
    WrittenRanges written;
    bool created = false, complete = false, has_mtime = false;
    std::uint64_t mtime = 0;
};
struct ExtractionReplay {
    // Only output identity and confirmed byte intervals survive an attempt.
    // No archive handler, dictionary, output buffer or CPU credit is retained.
    std::map<std::uint32_t, ReplayFile> files;
    std::unordered_map<std::wstring, std::filesystem::path> directories;
    std::array<std::uint8_t, 16> handler{};
    bool root_was_empty = false, initialized = false;
};
inline thread_local ExtractionReplay *current_extraction_replay = nullptr;
class ExtractionReplayScope {
public:
    explicit ExtractionReplayScope(ExtractionReplay *value) : previous_(current_extraction_replay) { current_extraction_replay = value; }
    ~ExtractionReplayScope() { current_extraction_replay = previous_; }
private:
    ExtractionReplay *previous_;
};
}
