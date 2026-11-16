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
inline std::uint64_t read_integer(std::string_view bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[i])) << (8 * i);
    return value;
}

inline std::optional<std::uint32_t> read_size(std::istream& stream) {
    char header[8]; stream.read(header, 8);
    if (!stream.gcount() && stream.eof()) return std::nullopt;
    if (stream.gcount() != 8 || std::memcmp(header, "SPBF", 4)) throw std::runtime_error("invalid worker frame header");
    return static_cast<std::uint32_t>(read_integer(std::string_view(header + 4, 4)));
}
inline constexpr std::uint32_t kMore = 1u << 31;
inline constexpr std::uint32_t kRequestChunkBytes = 512 * 1024;
struct AbandonedRequest {};

// One typed object may span any number of SPBF frames. Parse values directly
// into the job. Only a scalar that crosses a frame boundary needs scratch space.
class RequestReader {
    std::istream& input_;
    std::string buffer_, split_;
    std::string_view data_;
    bool more_ = false;

    void load(std::uint32_t size) {
        more_ = (size & kMore) != 0;
        size &= ~kMore;
        if (size == 0 || size > kRequestChunkBytes)
            throw std::runtime_error("invalid worker request fragment size");
        buffer_.resize(size);
        input_.read(buffer_.data(), size);
        if (input_.gcount() != size) throw std::runtime_error("truncated worker request fragment");
        data_ = buffer_;
    }

    void require_data() {
        if (!data_.empty()) return;
        if (!more_) throw std::runtime_error("truncated worker request value");
        const auto size = read_size(input_);
        if (!size) throw std::runtime_error("truncated worker request fragments");
        if (*size == 0) throw AbandonedRequest{};
        load(*size);
    }

    unsigned char peek() {
        require_data();
        return static_cast<unsigned char>(data_.front());
    }

    unsigned char byte() {
        const auto tag = peek();
        data_.remove_prefix(1);
        return tag;
    }

    std::string_view take(std::size_t count) {
        if (count <= data_.size()) {
            const auto value = data_.substr(0, count);
            data_.remove_prefix(count);
            return value;
        }
        split_.clear();
        while (count != 0) {
            require_data();
            const auto size = (std::min)(count, data_.size());
            split_.append(data_.data(), size);
            data_.remove_prefix(size);
            count -= size;
        }
        return split_;
    }

    void discard(std::size_t count) {
        while (count != 0) {
            require_data();
            const auto size = (std::min)(count, data_.size());
            data_.remove_prefix(size);
            count -= size;
        }
    }

    void expect(Tag tag) {
        if (byte() != tag) throw std::runtime_error("unexpected worker request value tag");
    }

    std::uint64_t integer(unsigned width) { return read_integer(take(width)); }

public:
    explicit RequestReader(std::istream& input) : input_(input) {}
    bool start() {
        const auto size = read_size(input_);
        if (size) load(*size);
        return size.has_value();
    }
    void finish() {
        if (!data_.empty() || more_) throw std::runtime_error("trailing worker request data");
        retire_request();
    }
    void retire_request() noexcept {
        // The job owns its parsed fields. Only the ordinary fragment
        // buffer is worth keeping warm for unrelated requests.
        constexpr std::size_t retained_bytes = 32 * 1024;
        data_ = {};
        more_ = false;
        if (buffer_.capacity() > retained_bytes) std::string().swap(buffer_);
        std::string().swap(split_);
    }
    std::string_view text() {
        expect(kText);
        const auto size = static_cast<std::size_t>(integer(4));
        return take(size);
    }
    std::uint64_t number() {
        const auto tag = byte();
        if (tag == kU8) return integer(1);
        if (tag == kU32) return integer(4);
        if (tag == kU64) return integer(8);
        throw std::runtime_error("worker unsigned integer expected");
    }
    bool boolean() {
        const auto tag = byte();
        if (tag != kTrue && tag != kFalse) throw std::runtime_error("worker boolean expected");
        return tag == kTrue;
    }
    void object() { expect(kObject); }
    void array() { expect(kArray); }
    bool next() {
        if (peek() != kEnd) return true;
        byte();
        return false;
    }
    void skip(unsigned depth = 0) {
        if (depth == 64) throw std::runtime_error("worker value nesting exceeds schema");
        switch (byte()) {
        case kNull: case kFalse: case kTrue: return;
        case kU8: discard(1); return;
        case kU32: discard(4); return;
        case kU64: case kI64: case kF64: discard(8); return;
        case kText: case kBytes: discard(static_cast<std::size_t>(integer(4))); return;
        case kArray: while (next()) skip(depth + 1); return;
        case kObject:
            while (next()) {
                expect(kText);
                discard(static_cast<std::size_t>(integer(4)));
                skip(depth + 1);
            }
            return;
        default: throw std::runtime_error("invalid worker request tag");
        }
    }
};

} // namespace wire
