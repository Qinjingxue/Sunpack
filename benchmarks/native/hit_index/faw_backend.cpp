#include "index.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
static int quiet_printf(const char *, ...) { return 0; }
#define printf quiet_printf
// clang-format off
#include <faw_encoding.h>
#include "faw_repaired.hpp"
// clang-format on
#undef printf

class FawIndex final : public Index {
  struct Entry {
    uint32_t word, rank, first;
  };
  struct Frame {
    uint32_t first, count, next, bits;
    unsigned kind;
  };
  std::unique_ptr<unsigned, decltype(&std::free)> words_{nullptr, &std::free};
  std::vector<Entry> directory_;
  TypeColumn types_;
  size_t word_count_ = 0, n_;
  uint64_t base_ = 0, last_ = 0;
  bool transformed_ = false;
  Frame frame(size_t at) const {
    unsigned w = words_.get()[at], kind = w >> 30;
    if (kind < 2)
      return {w, 1, uint32_t(at + 1), 0, kind};
    if (at + 1 >= word_count_)
      throw std::runtime_error("invalid FAW frame");
    unsigned payload = words_.get()[at + 1];
    return {w & 0x3fffffff,
            kind == 2 ? uint32_t(1 + __builtin_popcount(payload)) : payload + 1,
            uint32_t(at + 2), payload, kind};
  }
  uint32_t select(const Frame &f, size_t local) const {
    if (!local)
      return f.first;
    if (f.kind == 3)
      return f.first + uint32_t(local);
    unsigned bitmap = f.bits;
    for (size_t i = 1; i < local; ++i)
      bitmap &= bitmap - 1;
    return f.first + 1 + unsigned(__builtin_ctz(bitmap));
  }
  uint64_t pos(size_t rank) const {
    auto it =
        std::upper_bound(directory_.begin(), directory_.end(), rank,
                         [](size_t r, const Entry &e) { return r < e.rank; });
    --it;
    size_t at = it->word, begin = it->rank;
    for (;;) {
      auto f = frame(at);
      if (rank < begin + f.count)
        return base_ + select(f, rank - begin) - 1 - (transformed_ ? rank : 0);
      begin += f.count;
      at = f.next;
    }
  }
  size_t lb(uint64_t target) const {
    if (!n_ || target <= base_)
      return 0;
    if (target > last_)
      return n_;
    if (transformed_) {
      size_t a = 0, b = n_;
      while (a < b) {
        size_t m = (a + b) / 2;
        if (pos(m) < target)
          a = m + 1;
        else
          b = m;
      }
      return a;
    }
    uint64_t key = target - base_ + 1;
    if (key > 0x3fffffff)
      return n_;
    auto it = std::upper_bound(
        directory_.begin(), directory_.end(), key,
        [](uint64_t k, const Entry &e) { return k < e.first; });
    if (it != directory_.begin())
      --it;
    size_t at = it->word, rank = it->rank;
    while (at < word_count_) {
      auto f = frame(at);
      if (f.first >= key)
        return rank;
      uint64_t last = select(f, f.count - 1);
      if (last >= key) {
        if (f.kind == 3)
          return rank + size_t(key - f.first);
        unsigned delta = unsigned(key - f.first - 1);
        unsigned below = delta >= 32 ? f.bits : f.bits & ((1u << delta) - 1);
        return rank + 1 + __builtin_popcount(below);
      }
      rank += f.count;
      at = f.next;
    }
    return n_;
  }
  template <class Emit> void each(Emit emit) const {
    size_t rank = 0;
    for (size_t at = 0; at < word_count_;) {
      auto f = frame(at);
      for (size_t j = 0; j < f.count; ++j) {
        emit(rank, base_ + select(f, j) - 1 - (transformed_ ? rank : 0));
        ++rank;
      }
      at = f.next;
    }
  }

public:
  FawIndex(const std::vector<Hit> &h, const Config &config)
      : types_(h), n_(h.size()) {
    if (!n_)
      return;
    base_ = h.front().offset;
    last_ = h.back().offset;
    for (size_t i = 1; i < n_; ++i)
      transformed_ |= h[i].offset == h[i - 1].offset;
    words_.reset(static_cast<unsigned *>(std::malloc(n_ * sizeof(unsigned))));
    if (!words_)
      throw std::bad_alloc();
    for (size_t i = 0; i < n_; ++i) {
      uint64_t k = h[i].offset - base_ + 1 + (transformed_ ? i : 0);
      if (k > 0x3fffffff)
        throw std::runtime_error("unsupported: FAW 30-bit positive key");
      words_.get()[i] = unsigned(k);
    }
    int count = int(n_);
    auto *raw = words_.release();
    words_.reset(config.algorithm == "faw-repaired"
                     ? faw_repaired_encode(raw, &count)
                     : encode(raw, &count));
    if (!words_)
      throw std::bad_alloc();
    word_count_ = size_t(count);
    size_t rank = 0, next_entry = 0;
    for (size_t at = 0; at < word_count_;) {
      auto f = frame(at);
      if (!f.count || rank + f.count > n_)
        throw std::runtime_error(
            "invalid: original FAW encode does not preserve input cardinality");
      if (rank >= next_entry) {
        directory_.push_back({uint32_t(at), uint32_t(rank), f.first});
        next_entry = rank + 128;
      }
      rank += f.count;
      at = f.next;
    }
    if (rank != n_)
      throw std::runtime_error("invalid: original FAW encoded cardinality");
    directory_.shrink_to_fit();
  }
  uint64_t bytes() const override {
    return word_count_ * 4 + directory_.size() * sizeof(Entry) +
           types_.bytes() + encoded_header_bytes;
  }
  uint64_t capacity() const override {
    return word_count_ * 4 + directory_.capacity() * sizeof(Entry) +
           types_.capacity() + sizeof(*this);
  }
  std::string adaptation() const override {
    return transformed_ ? "positive-offset-plus-rank; sparse-frame-directory"
                        : "positive-offset; sparse-frame-directory";
  }
  void dump(std::vector<Hit> &out) const override {
    out.resize(n_);
    each([&](size_t i, uint64_t p) { out[i] = {p, types_.get(i)}; });
  }
  uint64_t sequential(uint16_t mask) const override {
    uint64_t sum = 0;
    each([&](size_t i, uint64_t p) {
      uint8_t tag = types_.get(i);
      if (mask & (1u << tag))
        sum += consume_hit({p, tag});
    });
    return sum;
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &out) const override {
    out.resize(r.size());
    for (size_t i = 0; i < r.size(); ++i)
      out[i] = {pos(size_t(r[i])), types_.get(size_t(r[i]))};
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &out) const override {
    out.resize(q.size());
    for (size_t i = 0; i < q.size(); ++i)
      out[i] = lb(q[i]);
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t mask) const override {
    size_t next = 0;
    uint64_t sum = 0;
    for (auto t : q) {
      if (next >= n_)
        break;
      next = std::max(next, lb(t));
      while (next < n_) {
        uint8_t tag = types_.get(next);
        Hit h{pos(next), tag};
        ++next;
        if (mask & (1u << tag)) {
          sum += consume_hit(h);
          break;
        }
      }
    }
    return sum;
  }
};
std::unique_ptr<Index> make_faw(const std::vector<Hit> &h, const Config &c) {
  return std::make_unique<FawIndex>(h, c);
}
