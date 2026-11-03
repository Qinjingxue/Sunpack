#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct Hit {
  uint64_t offset;
  uint8_t tag;
  uint8_t padding[3]{};
  uint32_t owner = 0;
};
static_assert(sizeof(Hit) == 16, "Rust/trace hit ABI");
// Common accounting envelope: eight u64 fields for schema/codec, count, base,
// universe, parameters and stream lengths. This is an accounting convention,
// not a claim that native runtime objects are serialized in this format.
inline constexpr uint64_t encoded_header_bytes = 64;
inline bool operator==(const Hit &a, const Hit &b) {
  return a.offset == b.offset && a.tag == b.tag;
}
// The production tie order is lexical hit_name, not numerical pattern id.
inline uint8_t tag_order(uint8_t tag) {
  static constexpr uint8_t r[14] = {12, 11, 0, 5, 6, 2,  1,
                                    8,  13, 7, 3, 4, 10, 9};
  return r[tag];
}
inline bool hit_less(const Hit &a, const Hit &b) {
  return a.offset < b.offset ||
         (a.offset == b.offset && tag_order(a.tag) < tag_order(b.tag));
}
inline uint64_t consume(const Hit &h) { return h.offset * 17 + h.tag; }

// One batch call per timed operation. No virtual or FFI call per emitted hit.
struct Index {
  virtual ~Index() = default;
  virtual uint64_t bytes() const = 0;
  virtual uint64_t capacity() const = 0;
  virtual void dump(std::vector<Hit> &out) const = 0;
  virtual uint64_t sequential(uint16_t mask) const = 0;
  virtual void access(const std::vector<uint64_t> &ranks,
                      std::vector<Hit> &out) const = 0;
  virtual void lower(const std::vector<uint64_t> &targets,
                     std::vector<uint64_t> &out) const = 0;
  virtual uint64_t seek(const std::vector<uint64_t> &targets,
                        uint16_t mask) const = 0;
  virtual std::string adaptation() const { return "native-nondecreasing"; }
  void audit_to(std::vector<Hit> *out) const {
#ifdef SP_BENCH_AUDIT
    audit_target_ = out;
#else
    (void)out;
#endif
  }

protected:
#ifdef SP_BENCH_AUDIT
  mutable std::vector<Hit> *audit_target_ = nullptr;
#endif
  uint64_t consume_hit(const Hit &h) const {
#ifdef SP_BENCH_AUDIT
    if (audit_target_)
      audit_target_->push_back(h);
#endif
    return consume(h);
  }
};
struct TypeColumn {
  struct Block {
    uint32_t offset;
    uint16_t tags;
    uint8_t width;
    uint8_t pad;
  };
  std::vector<uint8_t> data;
  std::vector<Block> blocks;
  uint8_t uniform_tag = 0xff;
  explicit TypeColumn(const std::vector<Hit> &);
  uint8_t get(size_t rank) const;
  uint16_t block_tags(size_t index) const {
    return uniform_tag < 14 ? uint16_t(1u << uniform_tag) : blocks[index].tags;
  }
  uint64_t bytes() const {
    return uniform_tag < 14 ? 1 : data.size() + blocks.size() * sizeof(Block);
  }
  uint64_t capacity() const {
    return data.capacity() + blocks.capacity() * sizeof(Block);
  }
};
struct Config {
  size_t block = 128;
  std::string algorithm;
  std::string bridge;
};
std::unique_ptr<Index> make_index(const std::vector<Hit> &, const Config &);
std::unique_ptr<Index> make_pef(const std::vector<Hit> &, const Config &);
std::unique_ptr<Index> make_faw(const std::vector<Hit> &, const Config &);
