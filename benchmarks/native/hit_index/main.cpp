#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include "index.hpp"
#include "synthetic.h"
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>

using Clock = std::chrono::steady_clock;
volatile uint64_t benchmark_sink = 0;
static uint64_t ns(Clock::duration d) {
  return uint64_t(
      std::chrono::duration_cast<std::chrono::nanoseconds>(d).count());
}
static uint64_t filetime(FILETIME t) {
  return (uint64_t(t.dwHighDateTime) << 32) | t.dwLowDateTime;
}
static uint64_t cpu_ns() {
  FILETIME c, e, k, u;
  GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
  return (filetime(k) + filetime(u)) * 100;
}
static std::string quote(const std::string &s) {
  std::string o = "\"";
  for (unsigned char c : s) {
    if (c == '\\' || c == '\"') {
      o += '\\';
      o += char(c);
    } else if (c == '\n')
      o += "\\n";
    else if (c == '\r')
      o += "\\r";
    else if (c == '\t')
      o += "\\t";
    else if (c >= 32)
      o += char(c);
  }
  return o + '\"';
}
struct Snapshot {
  uint64_t working, private_bytes, peak_working, peak_private, read_bytes,
      write_bytes, handles;
};
static Snapshot snapshot() {
  PROCESS_MEMORY_COUNTERS_EX m{};
  m.cb = sizeof(m);
  GetProcessMemoryInfo(GetCurrentProcess(),
                       reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&m),
                       sizeof(m));
  IO_COUNTERS io{};
  GetProcessIoCounters(GetCurrentProcess(), &io);
  DWORD handles = 0;
  GetProcessHandleCount(GetCurrentProcess(), &handles);
  return {m.WorkingSetSize,
          m.PrivateUsage,
          m.PeakWorkingSetSize,
          m.PeakPagefileUsage,
          io.ReadTransferCount,
          io.WriteTransferCount,
          handles};
}
static std::string json(const Snapshot &s) {
  std::ostringstream o;
  o << "{\"working_set\":" << s.working
    << ",\"private_bytes\":" << s.private_bytes
    << ",\"peak_working_set\":" << s.peak_working
    << ",\"peak_private_bytes\":" << s.peak_private
    << ",\"read_transfer_bytes\":" << s.read_bytes
    << ",\"write_transfer_bytes\":" << s.write_bytes
    << ",\"handles\":" << s.handles << '}';
  return o.str();
}
struct Args {
  std::map<std::string, std::string> a;
  Args(int n, char **v) {
    for (int i = 1; i < n; ++i) {
      std::string k = v[i];
      if (k.rfind("--", 0) != 0 || i + 1 == n)
        throw std::runtime_error("arguments require --key value");
      a[k.substr(2)] = v[++i];
    }
  }
  std::string str(const std::string &k, const std::string &d = "") const {
    auto i = a.find(k);
    return i == a.end() ? d : i->second;
  }
  uint64_t number(const std::string &k, uint64_t d) const {
    auto v = str(k);
    return v.empty() ? d : std::stoull(v);
  }
};
static uint64_t below(std::mt19937_64 &r, uint64_t bound) {
  if (!bound)
    return r();
  uint64_t threshold = uint64_t(-bound) % bound;
  for (;;) {
    auto v = r();
    if (v >= threshold)
      return v % bound;
  }
}
static void require(bool ok, const char *message) {
  if (!ok)
    throw std::runtime_error(std::string("invalid: ") + message);
}
struct Data {
  std::vector<Hit> hits;
  std::vector<uint32_t> arrival;
  uint64_t logical_size = 0, chunk = 2097152;
  std::string origin = "synthetic";
};

static Data read_trace(const std::string &path) {
  std::ifstream f(std::filesystem::u8path(path), std::ios::binary);
  if (!f)
    throw std::runtime_error("cannot open trace " + path);
  char magic[8];
  uint64_t header[4];
  f.read(magic, 8);
  f.read(reinterpret_cast<char *>(header), 32);
  require(bool(f) && std::memcmp(magic, "SPHITS\0\0", 8) == 0, "trace header");
  Data d;
  d.logical_size = header[0];
  d.chunk = header[3];
  d.origin = "captured-hit-trace";
  d.hits.resize(size_t(header[1]));
  uint32_t previous = UINT32_MAX;
  for (auto &h : d.hits) {
    f.read(reinterpret_cast<char *>(&h.offset), 8);
    f.read(reinterpret_cast<char *>(&h.tag), 1);
    f.read(reinterpret_cast<char *>(h.padding), 3);
    f.read(reinterpret_cast<char *>(&h.owner), 4);
    if (h.owner != previous) {
      d.arrival.push_back(h.owner);
      previous = h.owner;
    }
  }
  require(bool(f), "truncated hit trace");
  require(f.peek() == EOF, "trailing trace bytes");
  std::sort(d.hits.begin(), d.hits.end(), hit_less);
  return d;
}
static void write_trace(const std::string &path, const Data &d) {
  std::ofstream f(std::filesystem::u8path(path), std::ios::binary);
  f.write("SPHITS\0\0", 8);
  uint64_t header[4] = {d.logical_size, d.hits.size(), 0, d.chunk};
  f.write(reinterpret_cast<const char *>(header), 32);
  for (const auto &h : d.hits) {
    f.write(reinterpret_cast<const char *>(&h.offset), 8);
    f.write(reinterpret_cast<const char *>(&h.tag), 1);
    const char zero[3] = {};
    f.write(zero, 3);
    f.write(reinterpret_cast<const char *>(&h.owner), 4);
  }
  if (!f)
    throw std::runtime_error("trace write failed");
}
static Data posting(const Args &a) {
  std::ifstream f(std::filesystem::u8path(a.str("postings")), std::ios::binary);
  if (!f)
    throw std::runtime_error("cannot open PISA .docs");
  uint32_t one = 0, universe = 0;
  f.read(reinterpret_cast<char *>(&one), 4);
  f.read(reinterpret_cast<char *>(&universe), 4);
  require(one == 1 && universe > 0,
          "PISA .docs universe record must be [1, document_count]");
  uint64_t list = a.number("posting-list", 0);
  uint32_t n = 0;
  for (uint64_t i = 0; i <= list; ++i) {
    f.read(reinterpret_cast<char *>(&n), 4);
    require(bool(f), "posting list absent");
    if (i != list) {
      f.seekg(std::streamoff(uint64_t(n) * 4), std::ios::cur);
      require(bool(f), "posting seek");
    }
  }
  Data d;
  d.origin = "external-pisa-docs";
  d.logical_size = universe;
  d.hits.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    uint32_t x;
    f.read(reinterpret_cast<char *>(&x), 4);
    require(bool(f) && x < universe, "posting value outside universe");
    if (i)
      require(d.hits.back().offset < x,
              "posting list must be strictly increasing");
    d.hits.push_back({x, 0});
  }
  return d;
}
static Data integer_set(const Args &a) {
  std::ifstream f(std::filesystem::u8path(a.str("integer-set")));
  if (!f)
    throw std::runtime_error("cannot open integer set");
  Data d;
  d.origin = "public-integer-set";
  uint64_t v;
  while (f >> v) {
    require(v <= UINT32_MAX, "set key outside u32");
    d.hits.push_back({v, 0});
    if (f.peek() == ',')
      f.get();
  }
  require(f.eof(), "invalid token in integer set");
  require(std::is_sorted(d.hits.begin(), d.hits.end(), hit_less),
          "public integer set is not sorted");
  for (size_t i = 1; i < d.hits.size(); ++i)
    require(d.hits[i].offset > d.hits[i - 1].offset,
            "public integer set is not distinct");
  d.logical_size = d.hits.empty() ? 1 : d.hits.back().offset + 512;
  return d;
}
static Data generate(const Args &a) {
  if (!a.str("trace").empty())
    return read_trace(a.str("trace"));
  if (!a.str("postings").empty())
    return posting(a);
  if (!a.str("integer-set").empty())
    return integer_set(a);
  Data d;
  size_t n = size_t(a.number("n", 65536));
  uint64_t universe = a.number("universe", 2097152), base = a.number("base", 0);
  d.chunk = a.number("chunk", 2097152);
  require(universe > 0 && universe <= uint64_t(UINT32_MAX),
          "synthetic universe must fit positive u32");
  require(base <= UINT64_MAX - universe - 512, "absolute offset overflow");
  std::string profile = a.str("profile", "uniform"),
              types = a.str("types", "one");
  uint64_t seed = a.number("seed", 1729);
  std::mt19937_64 offsets(seed), tags(seed ^ 0xa0761d6478bd642full);
  std::vector<uint64_t> positions;
  positions.reserve(n);
  if (profile == "uniform" || profile == "clustered") {
    require(n <= universe && n <= UINT32_MAX,
            "distinct generator n exceeds universe");
    std::vector<uint32_t, FastPForLib::cacheallocator> v;
    if (profile == "uniform")
      v = FastPForLib::UniformDataGenerator(uint32_t(seed))
              .generateUniform(uint32_t(n), uint32_t(universe));
    else
      v = FastPForLib::ClusteredDataGenerator(uint32_t(seed))
              .generateClustered(uint32_t(n), uint32_t(universe));
    positions.assign(v.begin(), v.end());
  } else if (profile == "arithmetic" || profile == "contiguous" ||
             profile == "constant" || profile == "duplicates") {
    for (size_t i = 0; i < n; ++i) {
      uint64_t p =
          profile == "constant" ? 0
          : profile == "duplicates"
              ? (i / 14) * std::max<uint64_t>(
                               1, universe / std::max<size_t>(1, (n + 13) / 14))
          : profile == "contiguous"
              ? i
              : uint64_t(i) *
                    std::max<uint64_t>(1, universe / std::max<size_t>(1, n));
      positions.push_back(p);
    }
    if (!positions.empty())
      require(positions.back() < universe,
              "deterministic positions exceed universe");
  } else if (profile == "bit-boundaries") {
    for (size_t i = 0; i < n; ++i)
      positions.push_back((uint64_t(1) << (i % 28)) + ((i / 28) % 3));
    std::sort(positions.begin(), positions.end());
    if (!positions.empty())
      require(positions.back() < universe, "bit-boundary universe too small");
  } else {
    uint64_t p = 0;
    size_t phase = size_t(a.number("phase", 127)),
           every = size_t(a.number("exception-every", 128));
    require(every > 0, "exception period");
    for (size_t i = 0; i < n; ++i) {
      uint64_t gap = 0;
      if (profile == "outliers")
        gap = i % every == phase % every
                  ? a.number("exception-gap", 1024)
                  : below(offsets, a.number("small-gap", 4));
      else if (profile == "geometric") {
        uint64_t x = offsets();
        while ((x & 1) == 0 && gap < 63) {
          ++gap;
          x >>= 1;
        }
      } else if (profile == "runs")
        gap = i % 256 < 240 ? 1 : 256 + below(offsets, 4096);
      else if (profile == "piecewise")
        gap = below(offsets, i < n / 2 ? 4 : 4096);
      else if (profile == "gaps")
        gap = below(offsets, a.number("small-gap", 32));
      else
        throw std::runtime_error("unknown profile " + profile);
      p += gap;
      positions.push_back(p);
    }
    if (p >= universe) {
      require(a.str("fit") == "scale",
              "gap recipe exceeds universe; choose a feasible universe or "
              "explicitly request --fit scale");
      for (auto &v : positions)
        v = uint64_t((static_cast<long double>(v) * (universe - 1)) /
                     std::max<uint64_t>(1, p));
    }
  }
  d.hits.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    uint8_t t = 0;
    if (types == "one")
      t = 0;
    else if (types == "uniform")
      t = uint8_t(below(tags, 14));
    else if (types == "palette3") {
      constexpr uint8_t pal[3] = {1, 5, 9};
      t = pal[below(tags, 3)];
    } else if (types == "skew")
      t = below(tags, 1000) < 990 ? 0 : uint8_t(1 + below(tags, 13));
    else if (types == "runs")
      t = uint8_t((i / 256) % 14);
    else if (types == "periodic" || types == "coincident") {
      constexpr uint8_t inv[14] = {2, 6, 5,  10, 11, 3, 4,
                                   9, 7, 13, 12, 1,  0, 8};
      t = inv[i % 14];
    } else
      throw std::runtime_error("unknown types " + types);
    uint64_t p = positions[i];
    uint64_t marker = p + (t == 9 ? 257 : t == 11 ? 1 : 0);
    d.hits.push_back({base + p, t, {0, 0, 0}, uint32_t(marker / d.chunk)});
  }
  std::sort(d.hits.begin(), d.hits.end(), hit_less);
  d.logical_size = universe + 512;
  return d;
}

struct Queries {
  std::vector<uint64_t> ranks, present, absent, mixed, forward;
  uint64_t actual_present = 0, actual_absent = 0;
};
static size_t oracle_lower(const std::vector<Hit> &h, uint64_t t) {
  return size_t(
      std::lower_bound(h.begin(), h.end(), t,
                       [](const Hit &x, uint64_t v) { return x.offset < v; }) -
      h.begin());
}
static Queries queries(const std::vector<Hit> &h, size_t count, uint64_t seed) {
  Queries q;
  std::mt19937_64 r(seed ^ 0xe7037ed1a0b428dbull);
  for (size_t i = 0; i < count; ++i) {
    if (!h.empty()) {
      size_t rank = size_t(below(r, h.size()));
      q.ranks.push_back(rank);
      q.present.push_back(h[rank].offset);
    }
    uint64_t t = h.empty()
                     ? r()
                     : h.front().offset +
                           below(r, h.back().offset - h.front().offset + 1);
    size_t j = oracle_lower(h, t);
    if (j < h.size() && h[j].offset == t) {
      while (j < h.size() && h[j].offset == t)
        ++j;
      if (j < h.size() && h[j].offset > t + 1)
        ++t;
      else
        t = h.back().offset < UINT64_MAX ? h.back().offset + 1
                                         : h.front().offset - 1;
    }
    q.absent.push_back(t);
    q.mixed.push_back(i % 2 && !h.empty() ? q.present.back() : t);
  }
  q.mixed.push_back(0);
  q.mixed.push_back(UINT64_MAX);
  if (!h.empty()) {
    q.mixed.push_back(h.front().offset);
    q.mixed.push_back(h.back().offset);
  }
  q.forward = q.mixed;
  std::sort(q.forward.begin(), q.forward.end());
  q.forward.erase(std::unique(q.forward.begin(), q.forward.end()),
                  q.forward.end());
  for (auto t : q.mixed) {
    size_t j = oracle_lower(h, t);
    if (j < h.size() && h[j].offset == t)
      ++q.actual_present;
    else
      ++q.actual_absent;
  }
  return q;
}
static uint64_t oracle_seq(const std::vector<Hit> &h, uint16_t mask) {
  uint64_t s = 0;
  for (const auto &v : h)
    if (mask & (1u << v.tag))
      s += consume(v);
  return s;
}
static uint64_t oracle_seek(const std::vector<Hit> &h,
                            const std::vector<uint64_t> &q, uint16_t mask) {
  size_t next = 0;
  uint64_t sum = 0;
  for (auto t : q) {
    next = std::max(next, oracle_lower(h, t));
    while (next < h.size()) {
      auto v = h[next++];
      if (mask & (1u << v.tag)) {
        sum += consume(v);
        break;
      }
    }
  }
  return sum;
}
static uint64_t sum_hits(const std::vector<Hit> &h) {
  uint64_t s = 0;
  for (auto v : h)
    s += consume(v);
  return s;
}
static uint64_t equal_groups(const Index &i, const std::vector<uint64_t> &q) {
  std::vector<uint64_t> ends, points;
  points.reserve(q.size() * 2);
  for (auto t : q) {
    points.push_back(t);
    points.push_back(t == UINT64_MAX ? t : t + 1);
  }
  i.lower(points, ends);
  std::vector<uint64_t> ranks;
  std::vector<Hit> out;
  uint64_t sum = 0;
  for (size_t j = 0; j < q.size(); ++j) {
    uint64_t a = ends[j * 2], b = ends[j * 2 + 1];
    if (q[j] == UINT64_MAX) { // max-offset equality is uncommon; the canonical
                              // trace carries no value beyond max.
      std::vector<Hit> all;
      i.dump(all);
      b = all.size();
    }
    while (a < b) {
      ranks.clear();
      for (size_t k = 0; k < 128 && a < b; ++k)
        ranks.push_back(a++);
      i.access(ranks, out);
      sum += sum_hits(out);
    }
  }
  return sum;
}

struct Operation {
  std::string name;
  std::function<uint64_t()> call;
};
struct Sample {
  std::string op;
  size_t sample, repeats;
  double wall_ns, cpu_ns;
};
static std::vector<Sample> measure(const std::vector<Operation> &ops,
                                   size_t samples, size_t warmups,
                                   double target_ms) {
  std::vector<Sample> out;
  for (const auto &op : ops) {
    for (size_t i = 0; i < warmups; ++i)
      benchmark_sink ^= op.call();
    auto t = Clock::now();
    benchmark_sink ^= op.call();
    uint64_t first = std::max<uint64_t>(1, ns(Clock::now() - t));
    size_t repeats = std::max<size_t>(
        1, size_t(std::ceil(target_ms * 1000000.0 / double(first))));
    for (size_t s = 0; s < samples; ++s) {
      auto c = cpu_ns();
      auto w = Clock::now();
      uint64_t sum = 0;
      for (size_t r = 0; r < repeats; ++r)
        sum += op.call();
      benchmark_sink ^= sum;
      uint64_t wall = ns(Clock::now() - w), cpu = cpu_ns() - c;
      out.push_back(
          {op.name, s, repeats, double(wall) / repeats, double(cpu) / repeats});
    }
  }
  return out;
}
static void verify(const Index &i, const std::vector<Hit> &h,
                   const Queries &q) {
  std::vector<Hit> decoded;
  i.dump(decoded);
  require(decoded == h, "complete typed multiset differs");
  std::vector<Hit> selected;
  i.access(q.ranks, selected);
  require(selected.size() == q.ranks.size(), "access count");
  for (size_t j = 0; j < selected.size(); ++j)
    require(selected[j] == h[q.ranks[j]], "random access differs");
  std::vector<uint64_t> got;
  for (const auto *targets : {&q.present, &q.absent, &q.mixed}) {
    i.lower(*targets, got);
    require(got.size() == targets->size(), "lower count");
    for (size_t j = 0; j < got.size(); ++j)
      require(got[j] == oracle_lower(h, (*targets)[j]), "lower_bound differs");
  }
  for (uint16_t mask :
       {uint16_t(0x3fff), uint16_t(1), uint16_t(2), uint16_t(0x8000)}) {
    require(i.sequential(mask) == oracle_seq(h, mask),
            "masked consumption differs");
    require(i.seek(q.forward, mask) == oracle_seek(h, q.forward, mask),
            "forward seek consumption differs");
  }
#ifdef SP_BENCH_AUDIT
  for (uint16_t mask :
       {uint16_t(0x3fff), uint16_t(1), uint16_t(2), uint16_t(0x8000)}) {
    std::vector<Hit> actual, expected;
    for (auto hit : h)
      if (mask & (1u << hit.tag))
        expected.push_back(hit);
    i.audit_to(&actual);
    i.sequential(mask);
    i.audit_to(nullptr);
    require(actual == expected, "exact masked tuple sequence differs");
    actual.clear();
    expected.clear();
    size_t next = 0;
    for (auto t : q.forward) {
      next = std::max(next, oracle_lower(h, t));
      while (next < h.size()) {
        auto hit = h[next++];
        if (mask & (1u << hit.tag)) {
          expected.push_back(hit);
          break;
        }
      }
    }
    i.audit_to(&actual);
    i.seek(q.forward, mask);
    i.audit_to(nullptr);
    require(actual == expected, "exact seek tuple sequence differs");
  }
#endif
}

static std::string run_builder(const Args &a, Data &d) {
  struct Stats {
    uint64_t bytes, capacity, heap, mapped, prepare_ns, collect_ns, finish_ns;
  };
  struct Library {
    HMODULE h = nullptr;
    ~Library() {
      if (h)
        FreeLibrary(h);
    }
  } lib;
  lib.h = LoadLibraryW(std::filesystem::u8path(a.str("bridge")).c_str());
  if (!lib.h)
    throw std::runtime_error("Rust builder DLL load failed");
  // Match the production extension's process lifetime. Its global Rayon pool
  // can still execute DLL code after an index has been dropped.
  HMODULE pinned = nullptr;
  require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(lib.h), &pinned) != 0,
          "pin Rust runtime for process lifetime");
  auto build =
      reinterpret_cast<void *(__cdecl *)(const Hit *, size_t, uint32_t,
                                         uint64_t, size_t, size_t, uint32_t)>(
          GetProcAddress(lib.h, "sp_build"));
  auto stats = reinterpret_cast<void(__cdecl *)(void *, Stats *)>(
      GetProcAddress(lib.h, "sp_stats"));
  auto dump = reinterpret_cast<size_t(__cdecl *)(void *, Hit *)>(
      GetProcAddress(lib.h, "sp_dump"));
  auto release = reinterpret_cast<void(__cdecl *)(void *)>(
      GetProcAddress(lib.h, "sp_free"));
  require(build && stats && dump && release, "builder exports");
  SetEnvironmentVariableA("RAYON_NUM_THREADS", a.str("workers", "4").c_str());
  auto grouped = d.hits;
  if (a.number("order", 0) == 3 && !d.arrival.empty()) {
    std::map<uint32_t, size_t> rank;
    for (auto owner : d.arrival)
      if (!rank.count(owner))
        rank[owner] = rank.size();
    std::stable_sort(grouped.begin(), grouped.end(),
                     [&](const Hit &x, const Hit &y) {
                       return rank.at(x.owner) < rank.at(y.owner);
                     });
  } else
    std::stable_sort(
        grouped.begin(), grouped.end(),
        [](const Hit &x, const Hit &y) { return x.owner < y.owner; });
  auto before = snapshot();
  auto start = Clock::now();
  auto cpu = cpu_ns();
  void *p =
      build(grouped.data(), grouped.size(), 1, d.logical_size, size_t(d.chunk),
            size_t(a.number("window", 6)), uint32_t(a.number("order", 0)));
  if (!p)
    throw std::runtime_error("invalid: SunPack Builder failed");
  uint64_t elapsed = ns(Clock::now() - start), cpu_elapsed = cpu_ns() - cpu;
  Stats s{};
  stats(p, &s);
  auto built = snapshot();
  std::vector<Hit> actual(d.hits.size());
  size_t n = dump(p, actual.data());
  bool exact = n == d.hits.size() && actual == d.hits;
  start = Clock::now();
  release(p);
  uint64_t drop = ns(Clock::now() - start);
  auto after = snapshot();
  require(exact, "Builder typed multiset/order differs");
  std::ostringstream o;
  o << "{\"status\":\"ok\",\"layer\":\"production-builder\",\"n\":"
    << d.hits.size() << ",\"bytes\":" << s.bytes
    << ",\"reported_capacity_bytes\":" << s.capacity
    << ",\"heap_bytes\":" << s.heap << ",\"mapped_bytes\":" << s.mapped
    << ",\"build_ns\":" << elapsed << ",\"build_cpu_ns\":" << cpu_elapsed
    << ",\"prepare_ns\":" << s.prepare_ns << ",\"collect_ns\":" << s.collect_ns
    << ",\"finish_ns\":" << s.finish_ns << ",\"drop_ns\":" << drop
    << ",\"memory\":{\"initialized\":" << json(before)
    << ",\"built\":" << json(built) << ",\"dropped\":" << json(after) << "}}";
  return o.str();
}

static std::string inventory(const Args &a) {
  std::vector<std::filesystem::path> paths;
  for (const auto &e : std::filesystem::directory_iterator(
           std::filesystem::u8path(a.str("directory"))))
    if (e.is_regular_file() && e.path().extension() == ".txt")
      paths.push_back(e.path());
  std::sort(paths.begin(), paths.end());
  std::ostringstream o;
  o << "{\"status\":\"ok\",\"sets\":[";
  bool first = true;
  for (const auto &p : paths) {
    Args request = a;
    request.a["integer-set"] = p.u8string();
    Data d = integer_set(request);
    if (!first)
      o << ',';
    first = false;
    o << "{\"path\":" << quote(p.u8string()) << ",\"n\":" << d.hits.size()
      << ",\"span\":"
      << (d.hits.empty() ? 0 : d.hits.back().offset - d.hits.front().offset)
      << '}';
  }
  o << "]}";
  return o.str();
}
static std::string capabilities() {
  int leaf[4];
  __cpuid(leaf, 1);
  unsigned ecx = unsigned(leaf[2]);
  __cpuidex(leaf, 7, 0);
  unsigned ebx = unsigned(leaf[1]);
  DWORD_PTR process = 0, system = 0;
  GetProcessAffinityMask(GetCurrentProcess(), &process, &system);
  LARGE_INTEGER frequency;
  QueryPerformanceFrequency(&frequency);
  std::ostringstream o;
  o << "{\"status\":\"ok\",\"cpuid_sse41\":" << bool(ecx & (1u << 19))
    << ",\"cpuid_sse42\":" << bool(ecx & (1u << 20))
    << ",\"cpuid_avx2\":" << bool(ebx & (1u << 5))
    << ",\"cpuid_bmi2\":" << bool(ebx & (1u << 8))
    << ",\"process_affinity_mask\":" << process
    << ",\"system_affinity_mask\":" << system << ",\"active_processors\":"
    << GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
    << ",\"qpc_frequency\":" << frequency.QuadPart
    << ",\"priority_class\":" << GetPriorityClass(GetCurrentProcess()) << "}";
  return o.str();
}
static std::string run(const Args &a) {
  if (a.str("mode") == "inventory")
    return inventory(a);
  if (a.str("mode") == "capabilities")
    return capabilities();
  auto initial = snapshot();
  Data data = generate(a);
  auto &h = data.hits;
  require(std::is_sorted(h.begin(), h.end(), hit_less),
          "input not in canonical order");
  for (auto x : h)
    require(x.tag < 14, "unknown tag");
  if (!a.str("dump-trace").empty())
    write_trace(a.str("dump-trace"), data);
  if (a.str("mode") == "generate" || a.str("mode") == "describe")
    return "{\"status\":\"generated\",\"n\":" + std::to_string(h.size()) +
           ",\"span\":" +
           std::to_string(h.empty() ? 0 : h.back().offset - h.front().offset) +
           "}";
  if (a.str("mode") == "builder")
    return run_builder(a, data);
  if (a.str("mode") == "lifetime") {
    std::ostringstream o;
    o << "{\"status\":\"ok\",\"layer\":\"production-builder-lifetime\","
         "\"cycles\":[";
    auto count = a.number("cycles", 12);
    require(count > 0, "lifetime cycle count");
    for (size_t cycle = 0; cycle < count; ++cycle) {
      if (cycle)
        o << ',';
      o << run_builder(a, data);
    }
    o << "]}";
    return o.str();
  }
  Config c{size_t(a.number("block", 128)), a.str("algorithm", "sunpack"),
           a.str("bridge")};
  require(c.block >= 128 && (c.block & (c.block - 1)) == 0,
          "block must be a power of two >=128");
  Queries q =
      queries(h, size_t(a.number("queries", 4096)), a.number("seed", 1729));
  auto ready = snapshot();
  // Resolve DLL/static initialization before the construction timer,
  // identically for all algorithms. First-process startup is retained as a
  // separate metric.
  struct Library {
    HMODULE handle = nullptr;
    ~Library() {
      if (handle)
        FreeLibrary(handle);
    }
  } library;
  auto init_start = Clock::now();
  if (c.algorithm == "sunpack") {
    library.handle = LoadLibraryW(std::filesystem::u8path(c.bridge).c_str());
    if (!library.handle)
      throw std::runtime_error("Rust DLL preload failed, Win32=" +
                               std::to_string(GetLastError()));
  }
  {
    auto warm = make_index({}, c);
  }
  auto init_ns = ns(Clock::now() - init_start);
  auto initialized = snapshot();
  auto start = Clock::now();
  auto cpu_start = cpu_ns();
  auto index = make_index(h, c);
  uint64_t build_ns = ns(Clock::now() - start),
           build_cpu = cpu_ns() - cpu_start;
  auto built = snapshot();
  verify(*index, h, q);
  auto verified = snapshot();
  std::vector<Hit> selected;
  std::vector<uint64_t> located;
  std::vector<uint64_t> equal = q.present;
  if (equal.size() > 32)
    equal.resize(32);
  uint64_t equal_expected = 0;
  for (auto t : equal) {
    size_t j = oracle_lower(h, t);
    while (j < h.size() && h[j].offset == t)
      equal_expected += consume(h[j++]);
  }
  require(equal_groups(*index, equal) == equal_expected,
          "equal_offset differs");
  std::vector<Operation> ops = {
      {"sequential_all", [&] { return index->sequential(0x3fff); }},
      {"mask_common", [&] { return index->sequential(1); }},
      {"mask_rare", [&] { return index->sequential(2); }},
      {"mask_absent", [&] { return index->sequential(0x8000); }},
      {"access_random",
       [&] {
         index->access(q.ranks, selected);
         return sum_hits(selected);
       }},
      {"lower_present",
       [&] {
         index->lower(q.present, located);
         return std::accumulate(located.begin(), located.end(), uint64_t(0));
       }},
      {"lower_absent",
       [&] {
         index->lower(q.absent, located);
         return std::accumulate(located.begin(), located.end(), uint64_t(0));
       }},
      {"lower_mixed",
       [&] {
         index->lower(q.mixed, located);
         return std::accumulate(located.begin(), located.end(), uint64_t(0));
       }},
      {"seek_forward", [&] { return index->seek(q.forward, 0x3fff); }},
      {"equal_offset", [&] { return equal_groups(*index, equal); }}};
  if (!ops.empty())
    std::rotate(ops.begin(),
                ops.begin() + a.number("op-rotation", 0) % ops.size(),
                ops.end());
  auto rows = a.str("mode") == "verify"
                  ? std::vector<Sample>{}
                  : measure(ops, size_t(a.number("samples", 5)),
                            size_t(a.number("warmups", 1)),
                            double(a.number("target-ms", 10)));
  auto queried = snapshot();
  uint64_t size = index->bytes(), capacity = index->capacity();
  std::string adaptation = index->adaptation();
  start = Clock::now();
  index.reset();
  uint64_t drop_ns = ns(Clock::now() - start);
  auto dropped = snapshot();
  uint64_t duplicate_offsets = 0, duplicate_tuples = 0;
  std::array<uint64_t, 14> counts{};
  for (size_t j = 0; j < h.size(); ++j) {
    ++counts[h[j].tag];
    if (j) {
      duplicate_offsets += h[j].offset == h[j - 1].offset;
      duplicate_tuples += h[j] == h[j - 1];
    }
  }
  std::ostringstream o;
  o << std::setprecision(12)
    << "{\"status\":\"ok\",\"algorithm\":" << quote(c.algorithm)
    << ",\"adaptation\":" << quote(adaptation) << ",\"n\":" << h.size()
    << ",\"origin\":" << quote(data.origin)
    << ",\"span\":" << (h.empty() ? 0 : h.back().offset - h.front().offset)
    << ",\"duplicate_offsets\":" << duplicate_offsets
    << ",\"duplicate_tuples\":" << duplicate_tuples << ",\"type_counts\":[";
  for (size_t j = 0; j < 14; ++j) {
    if (j)
      o << ',';
    o << counts[j];
  }
  o << "],\"bytes\":" << size << ",\"reported_capacity_bytes\":";
  if (capacity == UINT64_MAX)
    o << "null";
  else
    o << capacity;
  o << ",\"init_ns\":" << init_ns << ",\"build_ns\":" << build_ns
    << ",\"build_cpu_ns\":" << build_cpu << ",\"drop_ns\":" << drop_ns
    << ",\"query_present\":" << q.actual_present
    << ",\"query_absent\":" << q.actual_absent
    << ",\"operation_inputs\":{\"sequential_all\":" << h.size()
    << ",\"mask_common\":" << h.size() << ",\"mask_rare\":" << h.size()
    << ",\"mask_absent\":" << h.size() << ",\"access_random\":" << q.ranks.size()
    << ",\"lower_present\":" << q.present.size() << ",\"lower_absent\":" << q.absent.size()
    << ",\"lower_mixed\":" << q.mixed.size() << ",\"seek_forward\":" << q.forward.size()
    << ",\"equal_offset\":" << equal.size() << "}"
    << ",\"memory\":{\"initial\":" << json(initial)
    << ",\"input_ready\":" << json(ready)
    << ",\"initialized\":" << json(initialized) << ",\"built\":" << json(built)
    << ",\"verified\":" << json(verified) << ",\"queried\":" << json(queried)
    << ",\"dropped\":" << json(dropped) << "},\"samples\":[";
  for (size_t j = 0; j < rows.size(); ++j) {
    if (j)
      o << ',';
    const auto &r = rows[j];
    o << "{\"op\":" << quote(r.op) << ",\"sample\":" << r.sample
      << ",\"repeats\":" << r.repeats << ",\"wall_ns\":" << r.wall_ns
      << ",\"cpu_ns\":" << r.cpu_ns << '}';
  }
  o << "]}";
  return o.str();
}
int wmain(int argc, wchar_t **wide) {
  std::vector<std::string> strings;
  for (int i = 0; i < argc; ++i) {
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, nullptr, 0,
                                    nullptr, nullptr);
    std::string s(size_t(bytes), 0);
    WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, s.data(), bytes, nullptr,
                        nullptr);
    s.pop_back();
    strings.push_back(std::move(s));
  }
  std::vector<char *> argv;
  for (auto &s : strings)
    argv.push_back(s.data());
  try {
    Args args(argc, argv.data());
    auto result = run(args);
    if (!args.str("json-out").empty()) {
      std::ofstream f(std::filesystem::u8path(args.str("json-out")));
      f << result;
    } else
      std::cout << result << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::string error = e.what();
    std::cout << "{\"status\":"
              << quote(error.rfind("unsupported:", 0) == 0 ? "unsupported"
                                                           : "invalid")
              << ",\"error\":" << quote(error) << "}\n";
    return 2;
  }
}
