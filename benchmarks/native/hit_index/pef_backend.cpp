#include "index.hpp"
#include <cassert>
#include <compact_elias_fano.hpp>
#include <cstring>
#include <ctime>
#include <partitioned_sequence.hpp>
#include <succinct/bit_vector.hpp>
#include <uniform_partitioned_sequence.hpp>

// The encoder, partitioner and query enumerators are the pinned author's
// implementation. compat/ only replaces Boost ownership/range plumbing and
// unused POSIX diagnostic clocks, not compression or select algorithms.
template <class Sequence> class PefIndex final : public Index {
  quasi_succinct::global_parameters params_;
  std::unique_ptr<succinct::bit_vector> bits_;
  TypeColumn types_;
  uint64_t base_ = 0, universe_ = 0;
  size_t n_;
  bool rank_transform_ = false;
  using Enumerator = typename Sequence::enumerator;
  Enumerator cursor() const {
    return Enumerator(*bits_, 0, universe_, n_, params_);
  }
  uint64_t corrected(const typename Enumerator::value_type &v) const {
    return base_ + v.second - (rank_transform_ ? v.first : 0);
  }
  size_t lb(uint64_t target, Enumerator &e) const {
    if (target <= base_)
      return 0;
    if (!rank_transform_) {
      if (target - base_ >= universe_)
        return n_;
      return size_t(e.next_geq(target - base_).first);
    }
    size_t a = 0, b = n_;
    while (a < b) {
      size_t m = (a + b) / 2;
      if (corrected(e.move(m)) < target)
        a = m + 1;
      else
        b = m;
    }
    return a;
  }

public:
  PefIndex(const std::vector<Hit> &h, const Config &c)
      : types_(h), n_(h.size()) {
    params_.log_partition_size = uint8_t(__builtin_ctzll(c.block));
    if (!n_)
      return;
    base_ = h.front().offset;
    if (c.algorithm != "ef")
      for (size_t i = 1; i < n_; ++i)
        rank_transform_ |= h[i].offset == h[i - 1].offset;
    std::vector<uint64_t> keys;
    keys.reserve(n_);
    for (size_t i = 0; i < n_; ++i) {
      uint64_t key = h[i].offset - base_;
      if (rank_transform_)
        key += i;
      keys.push_back(key);
    }
    universe_ = keys.back() + 1;
    succinct::bit_vector_builder builder;
    Sequence::write(builder, keys.begin(), universe_, n_, params_);
    bits_ = std::make_unique<succinct::bit_vector>(&builder);
  }
  uint64_t bytes() const override {
    return (bits_ ? (bits_->size() + 63) / 64 * 8 : 0) + types_.bytes() +
           encoded_header_bytes;
  }
  uint64_t capacity() const override { return UINT64_MAX; }
  std::string adaptation() const override {
    return rank_transform_ ? "offset-plus-rank; corrected-access/binary-search"
                           : "native-nondecreasing";
  }
  void dump(std::vector<Hit> &out) const override {
    out.resize(n_);
    if (!n_)
      return;
    auto e = cursor();
    auto p = e.move(0);
    for (size_t i = 0; i < n_; ++i) {
      if (i)
        p = e.next();
      out[i] = {corrected(p), types_.get(i)};
    }
  }
  uint64_t sequential(uint16_t mask) const override {
    if (!n_)
      return 0;
    uint64_t sum = 0;
    auto e = cursor();
    auto p = e.move(0);
    for (size_t i = 0; i < n_; ++i) {
      if (i)
        p = e.next();
      uint8_t tag = types_.get(i);
      if (mask & (1u << tag))
        sum += consume_hit({corrected(p), tag});
    }
    return sum;
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &out) const override {
    out.resize(r.size());
    if (r.empty())
      return;
    auto e = cursor();
    for (size_t i = 0; i < r.size(); ++i)
      out[i] = {corrected(e.move(r[i])), types_.get(size_t(r[i]))};
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &out) const override {
    out.resize(q.size());
    if (!n_) {
      std::fill(out.begin(), out.end(), 0);
      return;
    }
    auto e = cursor();
    for (size_t i = 0; i < q.size(); ++i)
      out[i] = lb(q[i], e);
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t mask) const override {
    if (!n_)
      return 0;
    size_t next = 0;
    uint64_t sum = 0;
    auto e = cursor();
    for (auto t : q) {
      if (next >= n_)
        break;
      next = std::max(next, lb(t, e));
      while (next < n_) {
        auto p = e.move(next);
        uint8_t tag = types_.get(next++);
        if (mask & (1u << tag)) {
          sum += consume_hit({corrected(p), tag});
          break;
        }
      }
    }
    return sum;
  }
};
std::unique_ptr<Index> make_pef(const std::vector<Hit> &h, const Config &c) {
  using namespace quasi_succinct;
  if (c.algorithm == "ef")
    return std::make_unique<PefIndex<compact_elias_fano>>(h, c);
  if (c.algorithm == "pef-uniform")
    return std::make_unique<PefIndex<uniform_partitioned_sequence<>>>(h, c);
  return std::make_unique<PefIndex<partitioned_sequence<>>>(h, c);
}
