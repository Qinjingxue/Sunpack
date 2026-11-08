#pragma once

// Worker pipe format: SPBF + little-endian u32 payload length, followed by
// typed values. Containers end with kEnd; strings/bytes carry u32 lengths.
// No textual number conversion, escaping, or intermediate object tree.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <istream>
#include <ostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace wire {
enum Tag : unsigned char { kEnd, kNull, kFalse, kTrue, kU64, kI64, kF64, kText, kBytes, kArray, kObject, kU8, kU32 };
inline std::string tag(Tag t) { return std::string(1, static_cast<char>(t)); }
inline std::string object() { return tag(kObject); }
inline std::string array() { return tag(kArray); }
inline std::string end() { return tag(kEnd); }
inline void little(std::string& out, std::uint64_t value, unsigned bytes) {
    for (unsigned i = 0; i < bytes; ++i) out.push_back(static_cast<char>(value >> (8 * i)));
}
inline void append_text(std::string& out, std::string_view value, Tag type = kText) {
    if (value.size() > UINT32_MAX) throw std::length_error("worker string exceeds u32 length");
    out.push_back(static_cast<char>(type)); little(out, value.size(), 4); out.append(value);
}
inline std::string text(std::string_view value) { std::string out; out.reserve(value.size()+5); append_text(out, value); return out; }
inline std::string key(std::string_view value) { return text(value); }
inline std::string boolean(bool value) { return tag(value ? kTrue : kFalse); }
template<class T> inline void append_number(std::string& out, T value) {
    if constexpr (std::is_floating_point_v<T>) {
        double d = value; std::uint64_t bits; std::memcpy(&bits, &d, 8);
        out.push_back(kF64); little(out, bits, 8);
    } else {
        if constexpr (std::is_signed_v<T>) {
            if (value < 0) { out.push_back(kI64); little(out, static_cast<std::uint64_t>(value), 8); return; }
        }
        const auto n = static_cast<std::uint64_t>(value);
        out.push_back(n <= UINT8_MAX ? kU8 : n <= UINT32_MAX ? kU32 : kU64);
        little(out, n, n <= UINT8_MAX ? 1 : n <= UINT32_MAX ? 4 : 8);
    }
}
template<class T> inline std::string number(T value) { std::string out; append_number(out, value); return out; }
inline void write(std::ostream& stream, const std::string& payload) {
    if (payload.size() > UINT32_MAX) throw std::length_error("worker frame exceeds u32 length");
    std::string header("SPBF"); little(header, payload.size(), 4);
    stream.write(header.data(), header.size()); stream.write(payload.data(), payload.size());
    if (!stream) throw std::runtime_error("worker frame write failed");
}
class Reader {
public:
    explicit Reader(std::string_view value) : data(value) {}
    std::string_view take(std::size_t n) {
        if (n > data.size()) throw std::runtime_error("truncated worker value");
        auto result = data.substr(0, n); data.remove_prefix(n); return result;
    }
    unsigned char byte() { return static_cast<unsigned char>(take(1)[0]); }
    std::uint64_t integer(unsigned bytes) {
        const auto raw = take(bytes); std::uint64_t n = 0;
        for (unsigned i = 0; i < bytes; ++i) n |= static_cast<std::uint64_t>(static_cast<unsigned char>(raw[i])) << (8*i);
        return n;
    }
    std::string_view text() {
        if (byte() != kText) throw std::runtime_error("worker text expected");
        return take(static_cast<std::size_t>(integer(4)));
    }
    void skip(unsigned depth = 0) {
        if (depth > 64) throw std::runtime_error("worker value nesting exceeds schema");
        switch (byte()) {
        case kNull: case kFalse: case kTrue: return;
        case kU8: take(1); return;
        case kU32: take(4); return;
        case kU64: case kI64: case kF64: take(8); return;
        case kText: case kBytes: take(static_cast<std::size_t>(integer(4))); return;
        case kArray: while (!data.empty() && data.front() != kEnd) skip(depth+1); break;
        case kObject: while (!data.empty() && data.front() != kEnd) { text(); skip(depth+1); } break;
        default: throw std::runtime_error("invalid worker value tag");
        }
        if (byte() != kEnd) throw std::runtime_error("worker container end expected");
    }
    std::string_view data;
};
inline bool read(std::istream& stream, std::string& payload) {
    char header[8]; stream.read(header, 8);
    if (!stream.gcount() && stream.eof()) return false;
    if (stream.gcount() != 8 || std::memcmp(header, "SPBF", 4)) throw std::runtime_error("invalid worker frame header");
    Reader reader(std::string_view(header+4, 4)); const auto size = reader.integer(4);
    payload.clear();
    // Grow only as bytes arrive; a damaged length cannot preallocate gigabytes.
    char block[65536]; std::uint64_t remaining = size;
    while (remaining) {
        const auto count = static_cast<std::streamsize>((std::min)(remaining, std::uint64_t{sizeof(block)}));
        stream.read(block, count);
        if (stream.gcount() != count) throw std::runtime_error("truncated worker frame");
        payload.append(block, static_cast<std::size_t>(count)); remaining -= count;
    }
    return true;
}

class ObjectView {
    struct Field { std::string_view key, value; };
    std::vector<Field> fields_;
    bool valid_ = false;
    std::optional<std::string_view> raw_field(std::string_view key) const {
        for (const auto& field : fields_) if (field.key == key) return field.value;
        return std::nullopt;
    }
    std::vector<std::string_view> array_field(std::string_view key) const {
        std::vector<std::string_view> out; const auto raw = raw_field(key);
        if (!raw) return out;
        Reader reader(*raw); if (reader.byte() != kArray) throw std::runtime_error("worker array expected");
        while (!reader.data.empty() && reader.data.front() != kEnd) {
            const auto before = reader.data; reader.skip(); out.push_back(before.substr(0, before.size()-reader.data.size()));
        }
        return out;
    }
public:
    ObjectView() = default;
    explicit ObjectView(std::string_view data) {
        Reader reader(data); if (reader.byte() != kObject) throw std::runtime_error("worker object expected");
        while (!reader.data.empty() && reader.data.front() != kEnd) {
            const auto key = reader.text(); const auto before = reader.data; reader.skip();
            fields_.push_back({key, before.substr(0, before.size()-reader.data.size())});
        }
        if (reader.byte() != kEnd || !reader.data.empty()) throw std::runtime_error("invalid worker object end");
        valid_ = true;
    }
    bool valid() const noexcept { return valid_; }
    std::string string_field(std::string_view key, std::string_view fallback = {}) const {
        auto raw = raw_field(key); return raw ? std::string(Reader(*raw).text()) : std::string(fallback);
    }
    bool uint_field(std::string_view key, unsigned long long* out) const {
        auto raw = raw_field(key); if (!raw || raw->front() == kNull) return false;
        Reader reader(*raw); const auto tag = reader.byte();
        if (tag != kU8 && tag != kU32 && tag != kU64) throw std::runtime_error("worker unsigned integer expected");
        *out = reader.integer(tag == kU8 ? 1 : tag == kU32 ? 4 : 8); return true;
    }
    bool bool_field(std::string_view key, bool fallback = false) const {
        auto raw = raw_field(key); if (!raw) return fallback;
        if (raw->front() != kTrue && raw->front() != kFalse) throw std::runtime_error("worker boolean expected");
        return raw->front() == kTrue;
    }
    ObjectView object_field(std::string_view key) const {
        auto raw = raw_field(key); return raw && raw->front() != kNull ? ObjectView(*raw) : ObjectView();
    }
    std::vector<std::string_view> object_array_field(std::string_view key) const { return array_field(key); }
    std::vector<std::string> string_array_field(std::string_view key) const {
        std::vector<std::string> out; for (auto raw : array_field(key)) out.emplace_back(Reader(raw).text()); return out;
    }
    bool index_array_field(std::string_view key, std::vector<std::size_t>& out) const {
        for (auto raw : array_field(key)) {
            Reader reader(raw); auto tag = reader.byte();
            if (tag != kU8 && tag != kU32 && tag != kU64) return false;
            auto value = reader.integer(tag == kU8 ? 1 : tag == kU32 ? 4 : 8);
            if (value > SIZE_MAX) return false; out.push_back(static_cast<std::size_t>(value));
        }
        return !out.empty();
    }
};
} // namespace wire
