#define NOMINMAX
#include <windows.h>
// FastPFOR's MSVC compatibility macros affect __attribute__; include CRoaring
// before FastPFOR so its runtime-dispatch declarations keep their attributes.
#include <roaring/roaring.h>
#include "compositecodec.h"
#include "deltautil.h"
#include "index.hpp"
#include "optpfor.h"
#include "simdbinarypacking.h"
#include "simdfastpfor.h"
#include "simple8b.h"
#include "variablebyte.h"
#include "vsencoding.h"
#include <cstring>
#include <filesystem>
#include <limits>
#include <numeric>
#include <streamvbyte.h>
#include <streamvbytedelta.h>

static uint32_t width(uint32_t x) { return x ? 32 - __builtin_clz(x) : 0; }
static uint8_t select_tag(uint16_t mask, unsigned rank) {
  while (rank--) {
    mask &= mask - 1;
  }
  return uint8_t(__builtin_ctz(unsigned(mask)));
}
TypeColumn::TypeColumn(const std::vector<Hit> &h) {
  if (!h.empty() && std::all_of(h.begin(), h.end(), [&](const Hit &hit) {
        return hit.tag == h.front().tag;
      })) {
    uniform_tag = h.front().tag;
    return;
  }
  blocks.reserve((h.size() + 127) / 128);
  data.reserve((h.size() + 1) / 2);
  for (size_t at = 0; at < h.size(); at += 128) {
    size_t n = std::min<size_t>(128, h.size() - at);
    uint16_t mask = 0;
    for (size_t j = 0; j < n; ++j)
      mask |= 1u << h[at + j].tag;
    unsigned b = width(__builtin_popcount(unsigned(mask)) - 1);
    size_t offset = data.size();
    data.resize(offset + (n * b + 7) / 8, 0);
    blocks.push_back({uint32_t(offset), mask, uint8_t(b), 0});
    for (size_t j = 0; j < n && b; ++j) {
      unsigned tag = h[at + j].tag;
      unsigned code =
          b == 4 ? tag : __builtin_popcount(unsigned(mask & ((1u << tag) - 1)));
      size_t bit = j * b;
      uint16_t v = uint16_t(code << (bit % 8));
      data[offset + bit / 8] |= uint8_t(v);
      if (bit % 8 + b > 8)
        data[offset + bit / 8 + 1] |= uint8_t(v >> 8);
    }
  }
  data.shrink_to_fit();
}
uint8_t TypeColumn::get(size_t rank) const {
  if (uniform_tag < 14)
    return uniform_tag;
  const auto &b = blocks[rank / 128];
  if (!b.width)
    return select_tag(b.tags, 0);
  size_t bit = (rank % 128) * b.width;
  unsigned v = data[b.offset + bit / 8];
  if (bit % 8 + b.width > 8)
    v |= unsigned(data[b.offset + bit / 8 + 1]) << 8;
  v = (v >> (bit % 8)) & ((1u << b.width) - 1);
  return b.width == 4 ? uint8_t(v) : select_tag(b.tags, v);
}

class RawIndex final : public Index {
  std::vector<uint8_t> data_;
  uint64_t base_ = 0;
  size_t n_ = 0;
  bool packed_;
  Hit get(size_t i) const {
    if (packed_) {
      uint32_t v;
      std::memcpy(&v, data_.data() + i * 4, 4);
      return {base_ + (v >> 4), uint8_t(v & 15)};
    }
    uint64_t o;
    std::memcpy(&o, data_.data() + i * 9, 8);
    return {o, data_[i * 9 + 8]};
  }
  size_t lower_one(uint64_t t) const {
    size_t a = 0, b = n_;
    while (a < b) {
      size_t m = (a + b) / 2;
      if (get(m).offset < t)
        a = m + 1;
      else
        b = m;
    }
    return a;
  }

public:
  RawIndex(const std::vector<Hit> &h, bool packed)
      : n_(h.size()), packed_(packed) {
    if (!h.empty())
      base_ = h.front().offset;
    if (packed && !h.empty() && h.back().offset - base_ >= (1ull << 28))
      throw std::runtime_error("unsupported: packed-u28 span");
    data_.resize(n_ * (packed ? 4 : 9));
    for (size_t i = 0; i < n_; ++i) {
      if (packed) {
        uint32_t v = uint32_t((h[i].offset - base_) << 4) | h[i].tag;
        std::memcpy(data_.data() + i * 4, &v, 4);
      } else {
        std::memcpy(data_.data() + i * 9, &h[i].offset, 8);
        data_[i * 9 + 8] = h[i].tag;
      }
    }
  }
  uint64_t bytes() const override {
    return data_.size() + encoded_header_bytes;
  }
  uint64_t capacity() const override {
    return data_.capacity() + sizeof(*this);
  }
  void dump(std::vector<Hit> &o) const override {
    o.resize(n_);
    for (size_t i = 0; i < n_; ++i)
      o[i] = get(i);
  }
  uint64_t sequential(uint16_t mask) const override {
    uint64_t sum = 0;
    for (size_t i = 0; i < n_; ++i) {
      auto h = get(i);
      if (mask & (1u << h.tag))
        sum += consume_hit(h);
    }
    return sum;
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &o) const override {
    o.resize(r.size());
    for (size_t i = 0; i < r.size(); ++i)
      o[i] = get(r[i]);
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &o) const override {
    o.resize(q.size());
    for (size_t i = 0; i < q.size(); ++i)
      o[i] = lower_one(q[i]);
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t mask) const override {
    size_t next = 0;
    uint64_t sum = 0;
    for (auto t : q) {
      if (next == n_)
        break;
      next = std::max(next, lower_one(t));
      while (next < n_) {
        auto h = get(next++);
        if (mask & (1u << h.tag)) {
          sum += consume_hit(h);
          break;
        }
      }
    }
    return sum;
  }
};

class BlockIndex final : public Index {
  struct Block {
    uint32_t offset, base, last, length;
  };
  std::vector<Block> blocks_;
  std::vector<uint8_t> data_;
  TypeColumn types_;
  uint64_t base_ = 0;
  size_t n_, block_;
  std::string kind_;
  std::unique_ptr<FastPForLib::IntegerCODEC> codec_;
  mutable std::vector<uint32_t, FastPForLib::cacheallocator> scratch_;
  size_t count(size_t bi) const { return std::min(block_, n_ - bi * block_); }
  void decode(size_t bi) const {
    const auto &b = blocks_[bi];
    const auto *p = data_.data() + b.offset;
    if (kind_ == "svb")
      streamvbyte_delta_decode(p, scratch_.data(), uint32_t(count(bi)), b.base);
    else if (kind_ == "svb0124") {
      streamvbyte_decode_0124(p, scratch_.data(), uint32_t(count(bi)));
      scratch_[0] += b.base;
      FastPForLib::Delta::fastinverseDelta2(scratch_.data(), count(bi));
    } else {
      size_t decoded = count(bi);
      codec_->decodeArray(reinterpret_cast<const uint32_t *>(p), b.length / 4,
                          scratch_.data(), decoded);
      if (decoded != count(bi))
        throw std::runtime_error("upstream decoded count differs");
      scratch_[0] += b.base;
      FastPForLib::Delta::fastinverseDelta2(scratch_.data(), count(bi));
    }
  }
  size_t lower_one(uint64_t target) const {
    if (!n_)
      return 0;
    if (target <= base_)
      return 0;
    if (target > base_ + blocks_.back().last)
      return n_;
    uint32_t t = uint32_t(target - base_);
    auto it =
        std::lower_bound(blocks_.begin(), blocks_.end(), t,
                         [](const Block &b, uint32_t x) { return b.last < x; });
    size_t bi = size_t(it - blocks_.begin());
    if (t <= it->base)
      return bi * block_;
    decode(bi);
    return bi * block_ +
           size_t(std::lower_bound(scratch_.begin(),
                                   scratch_.begin() + count(bi), t) -
                  scratch_.begin());
  }

public:
  BlockIndex(const std::vector<Hit> &h, const Config &c)
      : types_(h), n_(h.size()), block_(c.block), kind_(c.algorithm) {
    using namespace FastPForLib;
    if (kind_ == "bp128")
      codec_ =
          std::make_unique<CompositeCodec<SIMDBinaryPacking, VariableByte>>();
    else if (kind_ == "fastpfor128")
      codec_ =
          std::make_unique<CompositeCodec<SIMDFastPFor<4>, VariableByte>>();
    else if (kind_ == "optpfor")
      codec_ = std::make_unique<CompositeCodec<OPTPFor<4>, VariableByte>>();
    else if (kind_ == "simple8b")
      codec_ = std::make_unique<Simple8b<false>>();
    else if (kind_ == "vse")
      codec_ = std::make_unique<vsencoding::VSEncodingBlocks>(uint32_t(block_));
    if (!n_)
      return;
    base_ = h.front().offset;
    if (h.back().offset - base_ > UINT32_MAX)
      throw std::runtime_error("unsupported: u32 relative span");
    blocks_.reserve((n_ + block_ - 1) / block_);
    data_.reserve(n_ * 4 + (n_ + block_ - 1) / block_ * 32 + 16);
    scratch_.resize(block_ + 1024);
    std::vector<uint32_t, cacheallocator> values(block_),
        encoded(block_ * 2 + 1024);
    for (size_t at = 0; at < n_; at += block_) {
      size_t n = std::min(block_, n_ - at);
      uint32_t first = uint32_t(h[at].offset - base_), prev = first;
      for (size_t j = 0; j < n; ++j) {
        uint32_t v = uint32_t(h[at + j].offset - base_);
        values[j] = kind_ == "svb" ? v : v - prev;
        prev = v;
      }
      size_t aligned = (data_.size() + 15) / 16 * 16;
      data_.resize(aligned + block_ * 8 + 4096, 0);
      size_t len = 0;
      if (kind_ == "svb")
        len = streamvbyte_delta_encode(values.data(), uint32_t(n),
                                       data_.data() + aligned, first);
      else if (kind_ == "svb0124")
        len = streamvbyte_encode_0124(values.data(), uint32_t(n),
                                      data_.data() + aligned);
      else {
        size_t words = encoded.size();
        codec_->encodeArray(values.data(), n, encoded.data(), words);
        len = words * 4;
        std::memcpy(data_.data() + aligned, encoded.data(), len);
      }
      blocks_.push_back({uint32_t(aligned), first,
                         uint32_t(h[at + n - 1].offset - base_),
                         uint32_t(len)});
      data_.resize(aligned + len);
    }
    data_.resize(data_.size() + 16, 0);
    data_.shrink_to_fit();
  }
  uint64_t bytes() const override {
    return data_.size() + blocks_.size() * sizeof(Block) + types_.bytes() +
           encoded_header_bytes;
  }
  uint64_t capacity() const override {
    return data_.capacity() + blocks_.capacity() * sizeof(Block) +
           types_.capacity() + scratch_.capacity() * 4 + sizeof(*this);
  }
  void dump(std::vector<Hit> &o) const override {
    o.clear();
    o.reserve(n_);
    for (size_t bi = 0; bi < blocks_.size(); ++bi) {
      decode(bi);
      for (size_t j = 0; j < count(bi); ++j)
        o.push_back({base_ + scratch_[j], types_.get(bi * block_ + j)});
    }
  }
  uint64_t sequential(uint16_t mask) const override {
    uint64_t sum = 0;
    for (size_t bi = 0; bi < blocks_.size(); ++bi) {
      bool any = false;
      for (size_t j = 0; j < count(bi); j += 128)
        any |= bool(types_.block_tags((bi * block_ + j) / 128) & mask);
      if (!any)
        continue;
      decode(bi);
      for (size_t j = 0; j < count(bi); ++j) {
        auto tag = types_.get(bi * block_ + j);
        if (mask & (1u << tag))
          sum += consume_hit({base_ + scratch_[j], tag});
      }
    }
    return sum;
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &o) const override {
    o.resize(r.size());
    size_t cached = SIZE_MAX;
    for (size_t i = 0; i < r.size(); ++i) {
      size_t b = size_t(r[i] / block_);
      if (b != cached) {
        decode(b);
        cached = b;
      }
      o[i] = {base_ + scratch_[r[i] % block_], types_.get(size_t(r[i]))};
    }
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &o) const override {
    o.resize(q.size());
    for (size_t i = 0; i < q.size(); ++i)
      o[i] = lower_one(q[i]);
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t mask) const override {
    size_t next = 0, cached = SIZE_MAX;
    uint64_t sum = 0;
    for (auto t : q) {
      if (next >= n_)
        break;
      if (t > base_ + blocks_.back().last)
        break;
      size_t bi = next / block_;
      if (base_ + blocks_[bi].last < t) {
        auto it = std::lower_bound(
            blocks_.begin() + bi, blocks_.end(), t - base_,
            [](const Block &b, uint64_t x) { return b.last < x; });
        bi = size_t(it - blocks_.begin());
        next = bi * block_;
      }
      if (cached != bi) {
        decode(bi);
        cached = bi;
      }
      uint32_t rel = t <= base_ ? 0 : uint32_t(t - base_);
      size_t local =
          size_t(std::lower_bound(scratch_.begin(),
                                  scratch_.begin() + count(bi), rel) -
                 scratch_.begin());
      next = std::max(next, bi * block_ + local);
      while (next < n_) {
        bi = next / block_;
        if (cached != bi) {
          decode(bi);
          cached = bi;
        }
        uint8_t tag = types_.get(next);
        Hit h{base_ + scratch_[next % block_], tag};
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

class RoaringIndex final : public Index {
  roaring_bitmap_t *bitmap_ = nullptr;
  TypeColumn types_;
  uint64_t base_ = 0;
  size_t n_;
  bool transformed_ = false, packed_ = false;
  Hit get(size_t i) const {
    uint32_t value;
    if (!roaring_bitmap_select(bitmap_, uint32_t(i), &value))
      throw std::runtime_error("roaring select");
    if (packed_) {
      uint8_t order = value & 15;
      static constexpr uint8_t inverse[14] = {2, 6, 5,  10, 11, 3, 4,
                                              9, 7, 13, 12, 1,  0, 8};
      return {base_ + (value >> 4), inverse[order]};
    }
    return {base_ + value - (transformed_ ? i : 0), types_.get(i)};
  }
  size_t lb(uint64_t t) const {
    if (!n_ || t <= base_)
      return 0;
    if (packed_) {
      if (t - base_ > (UINT32_MAX >> 4))
        return n_;
      uint64_t v = (t - base_) << 4;
      return size_t(roaring_bitmap_rank(bitmap_, uint32_t(v - 1)));
    }
    if (!transformed_) {
      uint64_t v = t - base_;
      return v > UINT32_MAX
                 ? n_
                 : size_t(roaring_bitmap_rank(bitmap_, uint32_t(v - 1)));
    }
    size_t a = 0, b = n_;
    while (a < b) {
      size_t m = (a + b) / 2;
      if (get(m).offset < t)
        a = m + 1;
      else
        b = m;
    }
    return a;
  }

public:
  RoaringIndex(const std::vector<Hit> &h, bool packed)
      : types_(packed ? std::vector<Hit>{} : h), n_(h.size()), packed_(packed) {
    if (n_)
      base_ = h[0].offset;
    for (size_t i = 1; i < n_; ++i)
      transformed_ |= h[i].offset == h[i - 1].offset;
    std::unique_ptr<roaring_bitmap_t, decltype(&roaring_bitmap_free)> owned(
        roaring_bitmap_create(), &roaring_bitmap_free);
    if (!owned)
      throw std::bad_alloc();
    bitmap_ = owned.get();
    for (size_t i = 0; i < n_; ++i) {
      uint64_t v = h[i].offset - base_;
      if (packed) {
        if (v >= (1ull << 28))
          throw std::runtime_error("unsupported: packed roaring span");
        v = (v << 4) | tag_order(h[i].tag);
      } else if (transformed_)
        v += i;
      if (v > UINT32_MAX)
        throw std::runtime_error("unsupported: roaring u32 key");
      roaring_bitmap_add(bitmap_, uint32_t(v));
    }
    roaring_bitmap_run_optimize(bitmap_);
    roaring_bitmap_shrink_to_fit(bitmap_);
    if (roaring_bitmap_get_cardinality(bitmap_) != n_)
      throw std::runtime_error(
          "unsupported: exact duplicate tuples for roaring-packed");
    owned.release();
  }
  ~RoaringIndex() { roaring_bitmap_free(bitmap_); }
  uint64_t bytes() const override {
    return roaring_bitmap_portable_size_in_bytes(bitmap_) + types_.bytes() +
           encoded_header_bytes;
  }
  uint64_t capacity() const override { return UINT64_MAX; }
  std::string adaptation() const override {
    return packed_        ? "packed-offset-and-type"
           : transformed_ ? "offset-plus-rank; corrected-access/binary-search"
                          : "native-distinct-offsets";
  }
  void dump(std::vector<Hit> &o) const override {
    o.clear();
    o.reserve(n_);
    roaring_uint32_iterator_t it;
    roaring_iterator_init(bitmap_, &it);
    size_t i = 0;
    while (it.has_value) {
      if (packed_) {
        static constexpr uint8_t inverse[14] = {2, 6, 5,  10, 11, 3, 4,
                                                9, 7, 13, 12, 1,  0, 8};
        o.push_back(
            {base_ + (it.current_value >> 4), inverse[it.current_value & 15]});
      } else {
        o.push_back(
            {base_ + it.current_value - (transformed_ ? i : 0), types_.get(i)});
      }
      ++i;
      roaring_uint32_iterator_advance(&it);
    }
  }
  uint64_t sequential(uint16_t mask) const override {
    uint64_t sum = 0;
    roaring_uint32_iterator_t it;
    roaring_iterator_init(bitmap_, &it);
    size_t i = 0;
    static constexpr uint8_t inv[14] = {2, 6, 5,  10, 11, 3, 4,
                                        9, 7, 13, 12, 1,  0, 8};
    while (it.has_value) {
      Hit h = packed_ ? Hit{base_ + (it.current_value >> 4),
                            inv[it.current_value & 15]}
                      : Hit{base_ + it.current_value - (transformed_ ? i : 0),
                            types_.get(i)};
      if (mask & (1u << h.tag))
        sum += consume_hit(h);
      ++i;
      roaring_uint32_iterator_advance(&it);
    }
    return sum;
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &o) const override {
    o.resize(r.size());
    for (size_t i = 0; i < r.size(); ++i)
      o[i] = get(size_t(r[i]));
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &o) const override {
    o.resize(q.size());
    for (size_t i = 0; i < q.size(); ++i)
      o[i] = lb(q[i]);
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t mask) const override {
    size_t next = 0;
    uint64_t sum = 0;
    for (auto t : q) {
      if (next >= n_)
        break;
      next = std::max(next, lb(t));
      while (next < n_) {
        auto h = get(next++);
        if (mask & (1u << h.tag)) {
          sum += consume_hit(h);
          break;
        }
      }
    }
    return sum;
  }
};

struct RustStats {
  uint64_t bytes, capacity, heap, mapped, prepare_ns, collect_ns, finish_ns;
};
class RustIndex final : public Index {
  HMODULE module_ = nullptr;
  void *handle_ = nullptr;
  RustStats stats_{};
  size_t n_;
  void *(__cdecl *build_)(const Hit *, size_t, uint32_t, uint64_t, size_t,
                          size_t, uint32_t);
  void(__cdecl *statsfn_)(void *, RustStats *);
  size_t(__cdecl *dump_)(void *, Hit *);
  uint64_t(__cdecl *seq_)(void *, uint16_t);
  void(__cdecl *get_)(void *, const uint64_t *, size_t, Hit *);
  void(__cdecl *lower_)(void *, const uint64_t *, size_t, uint64_t *);
  uint64_t(__cdecl *seek_)(void *, const uint64_t *, size_t, uint16_t);
  void(__cdecl *free_)(void *);
  size_t(__cdecl *mask_dump_)(void *, uint16_t, Hit *);
  size_t(__cdecl *seek_dump_)(void *, const uint64_t *, size_t, uint16_t,
                              Hit *);
  template <class T> T symbol(const char *n) {
    auto p = GetProcAddress(module_, n);
    if (!p)
      throw std::runtime_error(std::string("missing Rust export ") + n);
    return reinterpret_cast<T>(p);
  }

public:
  RustIndex(const std::vector<Hit> &h, const Config &c) : n_(h.size()) {
    module_ = LoadLibraryW(std::filesystem::u8path(c.bridge).c_str());
    if (!module_)
      throw std::runtime_error("cannot load Rust bridge, Win32=" +
                               std::to_string(GetLastError()));
    try {
      build_ = symbol<decltype(build_)>("sp_build");
      statsfn_ = symbol<decltype(statsfn_)>("sp_stats");
      dump_ = symbol<decltype(dump_)>("sp_dump");
      seq_ = symbol<decltype(seq_)>("sp_seq");
      get_ = symbol<decltype(get_)>("sp_get");
      lower_ = symbol<decltype(lower_)>("sp_lower");
      seek_ = symbol<decltype(seek_)>("sp_seek");
      free_ = symbol<decltype(free_)>("sp_free");
      mask_dump_ = symbol<decltype(mask_dump_)>("sp_mask_dump");
      seek_dump_ = symbol<decltype(seek_dump_)>("sp_seek_dump");
      handle_ = build_(h.data(), h.size(), 0, 0, 0, 0, 0);
      if (!handle_)
        throw std::runtime_error("SunPack build failed");
      statsfn_(handle_, &stats_);
    } catch (...) {
      FreeLibrary(module_);
      throw;
    }
  }
  ~RustIndex() {
    if (handle_)
      free_(handle_);
    if (module_)
      FreeLibrary(module_);
  }
  uint64_t bytes() const override {
    return stats_.bytes + encoded_header_bytes;
  }
  uint64_t capacity() const override { return stats_.capacity; }
  void dump(std::vector<Hit> &o) const override {
    o.resize(n_);
    if (dump_(handle_, o.data()) != n_)
      throw std::runtime_error("SunPack dump size");
  }
  uint64_t sequential(uint16_t m) const override {
#ifdef SP_BENCH_AUDIT
    if (audit_target_) {
      std::vector<Hit> out(n_);
      out.resize(mask_dump_(handle_, m, out.data()));
      audit_target_->insert(audit_target_->end(), out.begin(), out.end());
    }
#endif
    return seq_(handle_, m);
  }
  void access(const std::vector<uint64_t> &r,
              std::vector<Hit> &o) const override {
    o.resize(r.size());
    get_(handle_, r.data(), r.size(), o.data());
  }
  void lower(const std::vector<uint64_t> &q,
             std::vector<uint64_t> &o) const override {
    o.resize(q.size());
    lower_(handle_, q.data(), q.size(), o.data());
  }
  uint64_t seek(const std::vector<uint64_t> &q, uint16_t m) const override {
#ifdef SP_BENCH_AUDIT
    if (audit_target_) {
      std::vector<Hit> out(q.size());
      out.resize(seek_dump_(handle_, q.data(), q.size(), m, out.data()));
      audit_target_->insert(audit_target_->end(), out.begin(), out.end());
    }
#endif
    return seek_(handle_, q.data(), q.size(), m);
  }
};
std::unique_ptr<Index> make_index(const std::vector<Hit> &h, const Config &c) {
  if (c.algorithm == "sunpack")
    return std::make_unique<RustIndex>(h, c);
  if (c.algorithm == "raw-packed" || c.algorithm == "raw64")
    return std::make_unique<RawIndex>(h, c.algorithm == "raw-packed");
  if (c.algorithm == "ef" || c.algorithm == "pef-uniform" ||
      c.algorithm == "pef-opt")
    return make_pef(h, c);
  if (c.algorithm == "faw" || c.algorithm == "faw-repaired")
    return make_faw(h, c);
  if (c.algorithm == "roaring" || c.algorithm == "roaring-packed")
    return std::make_unique<RoaringIndex>(h, c.algorithm == "roaring-packed");
  if (c.algorithm == "svb" || c.algorithm == "svb0124" ||
      c.algorithm == "bp128" || c.algorithm == "fastpfor128" ||
      c.algorithm == "optpfor" || c.algorithm == "simple8b" ||
      c.algorithm == "vse")
    return std::make_unique<BlockIndex>(h, c);
  throw std::runtime_error("unknown algorithm " + c.algorithm);
}
