// Minimal decoder microbenchmark for comparing streaming backends without
// involving archive parsing, disk I/O, prefetch, or SunPack's async writer.
//
// Build exactly one backend per build directory. See CMake options:
//   SUP7Z_CODEC_BENCH_BACKEND
//   SUP7Z_CODEC_BENCH_INCLUDE_DIRS
//   SUP7Z_CODEC_BENCH_LIBRARIES

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(SUP7Z_CODEC_BENCH_7Z)
#include "7zip/Compress/DeflateDecoder.h"
#include "7zip/Compress/Lzma2Decoder.h"
#include "7zip/Compress/ZstdDecoder.h"
#elif defined(SUP7Z_CODEC_BENCH_ZLIB)
#include <zlib.h>
#elif defined(SUP7Z_CODEC_BENCH_ISAL)
#include <igzip_lib.h>
#elif defined(SUP7Z_CODEC_BENCH_ZSTD)
#include <zstd.h>
#elif defined(SUP7Z_CODEC_BENCH_LZMA)
#include <lzma.h>
#elif defined(SUP7Z_CODEC_BENCH_FASTLZMA2)
#include <fast-lzma2.h>
#else
#error "codec benchmark backend was not selected"
#endif

namespace {

constexpr std::size_t kDefaultChunkSize = 512u * 1024u;
constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

struct Options {
    std::string codec;
    std::string input_path;
    std::size_t chunk_size = kDefaultChunkSize;
    int warmups = 1;
    int runs = 5;
    unsigned threads = 1;
    int lzma2_prop = -1;
};

struct DecodeResult {
    std::uint64_t output_bytes = 0;
    std::uint64_t hash = kFnvOffset;
};

class Sink {
public:
    explicit Sink(bool hash_enabled) : hash_enabled_(hash_enabled) {}

    void consume(const void* data, std::size_t size) {
        output_bytes_ += static_cast<std::uint64_t>(size);
        if (!hash_enabled_) {
            return;
        }
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        for (std::size_t i = 0; i < size; ++i) {
            hash_ ^= bytes[i];
            hash_ *= kFnvPrime;
        }
    }

    DecodeResult result() const {
        return {output_bytes_, hash_};
    }

private:
    bool hash_enabled_;
    std::uint64_t output_bytes_ = 0;
    std::uint64_t hash_ = kFnvOffset;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

std::uint64_t parse_u64(const char* text, const char* name) {
    if (!text || !*text) {
        fail(std::string("missing value for ") + name);
    }
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (!end || *end != '\0') {
        fail(std::string("invalid integer for ") + name + ": " + text);
    }
    return static_cast<std::uint64_t>(value);
}

Options parse_options(int argc, char** argv) {
    if (argc < 3) {
        fail(
            "usage: sunpack_codec_bench <deflate|zstd|lzma2> <compressed-file> "
            "[--chunk-kib N] [--warmup N] [--runs N] [--threads N] "
            "[--lzma2-prop 0..40]");
    }

    Options options;
    options.codec = argv[1];
    options.input_path = argv[2];

    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](const char* name) -> const char* {
            if (++i >= argc) {
                fail(std::string("missing value after ") + name);
            }
            return argv[i];
        };

        if (arg == "--chunk-kib") {
            const auto kib = parse_u64(require_value("--chunk-kib"), "--chunk-kib");
            if (kib == 0 || kib > (std::numeric_limits<std::size_t>::max() / 1024u)) {
                fail("--chunk-kib is out of range");
            }
            options.chunk_size = static_cast<std::size_t>(kib * 1024u);
        } else if (arg == "--warmup") {
            options.warmups = static_cast<int>(
                parse_u64(require_value("--warmup"), "--warmup"));
        } else if (arg == "--runs") {
            options.runs = static_cast<int>(
                parse_u64(require_value("--runs"), "--runs"));
        } else if (arg == "--threads") {
            options.threads = static_cast<unsigned>(
                parse_u64(require_value("--threads"), "--threads"));
        } else if (arg == "--lzma2-prop") {
            options.lzma2_prop = static_cast<int>(
                parse_u64(require_value("--lzma2-prop"), "--lzma2-prop"));
        } else {
            fail("unknown argument: " + arg);
        }
    }

    if (options.runs <= 0 || options.warmups < 0) {
        fail("--runs must be > 0 and --warmup must be >= 0");
    }
    if (options.threads == 0) {
        fail("--threads must be >= 1");
    }
    if (options.chunk_size == 0 ||
        options.chunk_size > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        fail("chunk size must fit in 32 bits");
    }
    if (options.codec == "lzma2" &&
        (options.lzma2_prop < 0 || options.lzma2_prop > 40)) {
        fail("raw LZMA2 requires --lzma2-prop 0..40");
    }
    return options;
}

std::vector<std::uint8_t> load_file(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        fail("cannot open input: " + path);
    }
    const std::streamoff length = stream.tellg();
    if (length < 0) {
        fail("cannot determine input size: " + path);
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(length));
    stream.seekg(0, std::ios::beg);
    if (!data.empty() &&
        !stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(length))) {
        fail("cannot read input: " + path);
    }
    return data;
}

const char* backend_name() {
#if defined(SUP7Z_CODEC_BENCH_7Z)
    return "7z";
#elif defined(SUP7Z_CODEC_BENCH_ZLIB)
    return "zlib-compatible";
#elif defined(SUP7Z_CODEC_BENCH_ISAL)
    return "isa-l";
#elif defined(SUP7Z_CODEC_BENCH_ZSTD)
    return "libzstd";
#elif defined(SUP7Z_CODEC_BENCH_LZMA)
    return "liblzma";
#elif defined(SUP7Z_CODEC_BENCH_FASTLZMA2)
    return "fast-lzma2";
#endif
}

void validate_codec_for_backend(const std::string& codec) {
#if defined(SUP7Z_CODEC_BENCH_7Z)
    if (codec != "deflate" && codec != "zstd" && codec != "lzma2") {
        fail("7z benchmark supports deflate, zstd, and lzma2");
    }
#elif defined(SUP7Z_CODEC_BENCH_ZLIB) || defined(SUP7Z_CODEC_BENCH_ISAL)
    if (codec != "deflate") {
        fail(std::string(backend_name()) + " benchmark supports only deflate");
    }
#elif defined(SUP7Z_CODEC_BENCH_ZSTD)
    if (codec != "zstd") {
        fail("libzstd benchmark supports only zstd");
    }
#elif defined(SUP7Z_CODEC_BENCH_LZMA) || defined(SUP7Z_CODEC_BENCH_FASTLZMA2)
    if (codec != "lzma2") {
        fail(std::string(backend_name()) + " benchmark supports only lzma2");
    }
#endif
}

#if defined(SUP7Z_CODEC_BENCH_7Z)

Z7_CLASS_IMP_COM_1(
    ChunkedMemoryInStream
    , ISequentialInStream
)
    const Byte* data_;
    std::size_t size_;
    std::size_t pos_;
    UInt32 chunk_size_;
public:
    ChunkedMemoryInStream(
        const std::vector<std::uint8_t>& data,
        std::size_t chunk_size)
        : data_(reinterpret_cast<const Byte*>(data.data())),
          size_(data.size()),
          pos_(0),
          chunk_size_(static_cast<UInt32>(chunk_size)) {}
};

Z7_COM7F_IMF(ChunkedMemoryInStream::Read(
    void* data,
    UInt32 size,
    UInt32* processedSize))
{
    if (processedSize) {
        *processedSize = 0;
    }
    if (size == 0 || pos_ >= size_) {
        return S_OK;
    }
    const std::size_t remaining = size_ - pos_;
    const std::size_t wanted = std::min<std::size_t>(
        std::min<std::size_t>(remaining, size),
        chunk_size_);
    std::memcpy(data, data_ + pos_, wanted);
    pos_ += wanted;
    if (processedSize) {
        *processedSize = static_cast<UInt32>(wanted);
    }
    return S_OK;
}

Z7_CLASS_IMP_COM_1(
    SinkOutStream
    , ISequentialOutStream
)
    Sink* sink_;
public:
    explicit SinkOutStream(Sink* sink) : sink_(sink) {}
};

Z7_COM7F_IMF(SinkOutStream::Write(
    const void* data,
    UInt32 size,
    UInt32* processedSize))
{
    if (processedSize) {
        *processedSize = 0;
    }
    if (size != 0) {
        sink_->consume(data, size);
    }
    if (processedSize) {
        *processedSize = size;
    }
    return S_OK;
}

void require_hresult(HRESULT result, const char* operation) {
    if (result != S_OK) {
        char buffer[160];
        std::snprintf(
            buffer,
            sizeof(buffer),
            "%s failed with HRESULT 0x%08lx",
            operation,
            static_cast<unsigned long>(result));
        fail(buffer);
    }
}

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    CMyComPtr<ICompressCoder> coder;
    if (options.codec == "deflate") {
        coder = new NCompress::NDeflate::NDecoder::CCOMCoder();
    } else if (options.codec == "zstd") {
        coder = new NCompress::NZstd::CDecoder();
    } else if (options.codec == "lzma2") {
        coder = new NCompress::NLzma2::CDecoder();
    } else {
        fail("unsupported 7z codec");
    }

    CMyComPtr<ICompressSetFinishMode> finish_mode;
    if (coder.QueryInterface(IID_ICompressSetFinishMode, &finish_mode) == S_OK &&
        finish_mode) {
        require_hresult(finish_mode->SetFinishMode(1), "SetFinishMode");
    }

    if (options.codec == "lzma2") {
        CMyComPtr<ICompressSetDecoderProperties2> properties;
        require_hresult(
            coder.QueryInterface(IID_ICompressSetDecoderProperties2, &properties),
            "QueryInterface(ICompressSetDecoderProperties2)");
        const Byte prop = static_cast<Byte>(options.lzma2_prop);
        require_hresult(
            properties->SetDecoderProperties2(&prop, 1),
            "SetDecoderProperties2");

        CMyComPtr<ICompressSetCoderMt> coder_mt;
        if (coder.QueryInterface(IID_ICompressSetCoderMt, &coder_mt) == S_OK &&
            coder_mt) {
            require_hresult(
                coder_mt->SetNumberOfThreads(options.threads),
                "SetNumberOfThreads");
        }
    }

    Sink sink(hash_enabled);
    CMyComPtr<ISequentialInStream> in_stream =
        new ChunkedMemoryInStream(input, options.chunk_size);
    CMyComPtr<ISequentialOutStream> out_stream = new SinkOutStream(&sink);
    const UInt64 input_size = static_cast<UInt64>(input.size());
    require_hresult(
        coder->Code(in_stream, out_stream, &input_size, nullptr, nullptr),
        "ICompressCoder::Code");
    return sink.result();
}

#elif defined(SUP7Z_CODEC_BENCH_ZLIB)

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    z_stream stream{};
    const int init = inflateInit2(&stream, -MAX_WBITS);
    if (init != Z_OK) {
        fail("inflateInit2 failed: " + std::to_string(init));
    }

    Sink sink(hash_enabled);
    std::vector<std::uint8_t> output(options.chunk_size);
    std::size_t input_pos = 0;
    int code = Z_OK;

    while (code != Z_STREAM_END) {
        if (stream.avail_in == 0 && input_pos < input.size()) {
            const std::size_t amount =
                std::min(options.chunk_size, input.size() - input_pos);
            stream.next_in = const_cast<Bytef*>(
                reinterpret_cast<const Bytef*>(input.data() + input_pos));
            stream.avail_in = static_cast<uInt>(amount);
            input_pos += amount;
        }

        stream.next_out = reinterpret_cast<Bytef*>(output.data());
        stream.avail_out = static_cast<uInt>(output.size());
        const uInt before_in = stream.avail_in;
        code = inflate(&stream, Z_NO_FLUSH);
        const std::size_t produced = output.size() - stream.avail_out;
        sink.consume(output.data(), produced);

        if (code != Z_OK && code != Z_STREAM_END) {
            inflateEnd(&stream);
            fail("inflate failed: " + std::to_string(code));
        }
        if (code != Z_STREAM_END &&
            input_pos == input.size() &&
            stream.avail_in == 0 &&
            before_in == 0 &&
            produced == 0) {
            inflateEnd(&stream);
            fail("deflate stream ended before Z_STREAM_END");
        }
    }

    const std::size_t consumed = input_pos - stream.avail_in;
    inflateEnd(&stream);
    if (consumed != input.size()) {
        fail("deflate decoder left trailing input");
    }
    return sink.result();
}

#elif defined(SUP7Z_CODEC_BENCH_ISAL)

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    inflate_state state{};
    isal_inflate_init(&state);
    state.crc_flag = ISAL_DEFLATE;

    Sink sink(hash_enabled);
    std::vector<std::uint8_t> output(options.chunk_size);
    std::size_t input_pos = 0;

    while (state.block_state != ISAL_BLOCK_FINISH) {
        if (state.avail_in == 0 && input_pos < input.size()) {
            const std::size_t amount =
                std::min(options.chunk_size, input.size() - input_pos);
            state.next_in = const_cast<std::uint8_t*>(input.data() + input_pos);
            state.avail_in = static_cast<std::uint32_t>(amount);
            input_pos += amount;
        }

        state.next_out = output.data();
        state.avail_out = static_cast<std::uint32_t>(output.size());
        const std::uint32_t before_in = state.avail_in;
        const int code = isal_inflate(&state);
        const std::size_t produced = output.size() - state.avail_out;
        sink.consume(output.data(), produced);

        if (code != ISAL_DECOMP_OK && code != ISAL_END_INPUT) {
            fail("isal_inflate failed: " + std::to_string(code));
        }
        if (state.block_state != ISAL_BLOCK_FINISH &&
            input_pos == input.size() &&
            state.avail_in == 0 &&
            before_in == 0 &&
            produced == 0) {
            fail("deflate stream ended before ISAL_BLOCK_FINISH");
        }
    }

    const std::size_t consumed = input_pos - state.avail_in;
    if (consumed != input.size()) {
        fail("ISA-L decoder left trailing input");
    }
    return sink.result();
}

#elif defined(SUP7Z_CODEC_BENCH_ZSTD)

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    ZSTD_DStream* stream = ZSTD_createDStream();
    if (!stream) {
        fail("ZSTD_createDStream failed");
    }
    const size_t init = ZSTD_initDStream(stream);
    if (ZSTD_isError(init)) {
        ZSTD_freeDStream(stream);
        fail(std::string("ZSTD_initDStream failed: ") + ZSTD_getErrorName(init));
    }

    Sink sink(hash_enabled);
    std::vector<std::uint8_t> output(options.chunk_size);
    std::size_t input_pos = 0;
    ZSTD_inBuffer in_buffer{nullptr, 0, 0};
    size_t remaining = 1;

    while (remaining != 0) {
        if (in_buffer.pos == in_buffer.size && input_pos < input.size()) {
            const std::size_t amount =
                std::min(options.chunk_size, input.size() - input_pos);
            in_buffer.src = input.data() + input_pos;
            in_buffer.size = amount;
            in_buffer.pos = 0;
            input_pos += amount;
        }

        ZSTD_outBuffer out_buffer{output.data(), output.size(), 0};
        const std::size_t before_in = in_buffer.pos;
        remaining = ZSTD_decompressStream(stream, &out_buffer, &in_buffer);
        if (ZSTD_isError(remaining)) {
            const std::string error = ZSTD_getErrorName(remaining);
            ZSTD_freeDStream(stream);
            fail("ZSTD_decompressStream failed: " + error);
        }
        sink.consume(output.data(), out_buffer.pos);

        if (remaining != 0 &&
            before_in == in_buffer.pos &&
            out_buffer.pos == 0) {
            const bool no_more_input =
                input_pos == input.size() && in_buffer.pos == in_buffer.size;
            ZSTD_freeDStream(stream);
            fail(no_more_input
                     ? "zstd frame ended before decoder reached frame end"
                     : "zstd decoder made no progress");
        }
    }

    const std::size_t consumed =
        input_pos - (in_buffer.size - in_buffer.pos);
    ZSTD_freeDStream(stream);
    if (consumed != input.size()) {
        fail("zstd decoder left trailing input");
    }
    return sink.result();
}

#elif defined(SUP7Z_CODEC_BENCH_LZMA)

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_filter filters[2] = {
        {LZMA_FILTER_LZMA2, nullptr},
        {LZMA_VLI_UNKNOWN, nullptr},
    };
    const std::uint8_t prop = static_cast<std::uint8_t>(options.lzma2_prop);
    lzma_ret code = lzma_properties_decode(
        &filters[0], nullptr, &prop, 1);
    if (code != LZMA_OK) {
        fail("lzma_properties_decode failed: " + std::to_string(code));
    }

    code = lzma_raw_decoder(&stream, filters);
    if (code != LZMA_OK) {
        lzma_filters_free(filters, nullptr);
        fail("lzma_raw_decoder failed: " + std::to_string(code));
    }

    Sink sink(hash_enabled);
    std::vector<std::uint8_t> output(options.chunk_size);
    std::size_t input_pos = 0;

    while (code != LZMA_STREAM_END) {
        if (stream.avail_in == 0 && input_pos < input.size()) {
            const std::size_t amount =
                std::min(options.chunk_size, input.size() - input_pos);
            stream.next_in = input.data() + input_pos;
            stream.avail_in = amount;
            input_pos += amount;
        }

        stream.next_out = output.data();
        stream.avail_out = output.size();
        const std::size_t before_in = stream.avail_in;
        const lzma_action action =
            (input_pos == input.size() && stream.avail_in == 0)
                ? LZMA_FINISH
                : LZMA_RUN;
        code = lzma_code(&stream, action);
        const std::size_t produced = output.size() - stream.avail_out;
        sink.consume(output.data(), produced);

        if (code != LZMA_OK && code != LZMA_STREAM_END) {
            lzma_end(&stream);
            lzma_filters_free(filters, nullptr);
            fail("lzma_code failed: " + std::to_string(code));
        }
        if (code != LZMA_STREAM_END &&
            input_pos == input.size() &&
            stream.avail_in == 0 &&
            before_in == 0 &&
            produced == 0) {
            lzma_end(&stream);
            lzma_filters_free(filters, nullptr);
            fail("LZMA2 stream ended before LZMA_STREAM_END");
        }
    }

    const std::size_t consumed = input_pos - stream.avail_in;
    lzma_end(&stream);
    lzma_filters_free(filters, nullptr);
    if (consumed != input.size()) {
        fail("liblzma decoder left trailing input");
    }
    return sink.result();
}

#elif defined(SUP7Z_CODEC_BENCH_FASTLZMA2)

DecodeResult decode_backend(
    const std::vector<std::uint8_t>& input,
    const Options& options,
    bool hash_enabled)
{
    FL2_DStream* stream =
        options.threads == 1
            ? FL2_createDStream()
            : FL2_createDStreamMt(options.threads);
    if (!stream) {
        fail("FL2_createDStream failed");
    }

    size_t code = FL2_initDStream_withProp(
        stream, static_cast<unsigned char>(options.lzma2_prop));
    if (FL2_isError(code)) {
        const std::string error = FL2_getErrorName(code);
        FL2_freeDStream(stream);
        fail("FL2_initDStream_withProp failed: " + error);
    }

    Sink sink(hash_enabled);
    std::vector<std::uint8_t> output(options.chunk_size);
    std::size_t input_pos = 0;
    FL2_inBuffer in_buffer{nullptr, 0, 0};
    code = 1;

    while (code != 0) {
        if (in_buffer.pos == in_buffer.size && input_pos < input.size()) {
            const std::size_t amount =
                std::min(options.chunk_size, input.size() - input_pos);
            in_buffer.src = input.data() + input_pos;
            in_buffer.size = amount;
            in_buffer.pos = 0;
            input_pos += amount;
        }

        FL2_outBuffer out_buffer{output.data(), output.size(), 0};
        const std::size_t before_in = in_buffer.pos;
        code = FL2_decompressStream(stream, &out_buffer, &in_buffer);
        if (FL2_isError(code)) {
            const std::string error = FL2_getErrorName(code);
            FL2_freeDStream(stream);
            fail("FL2_decompressStream failed: " + error);
        }
        sink.consume(output.data(), out_buffer.pos);

        if (code != 0 &&
            before_in == in_buffer.pos &&
            out_buffer.pos == 0) {
            const bool no_more_input =
                input_pos == input.size() && in_buffer.pos == in_buffer.size;
            FL2_freeDStream(stream);
            fail(no_more_input
                     ? "LZMA2 stream ended before Fast LZMA2 reached terminator"
                     : "Fast LZMA2 decoder made no progress");
        }
    }

    const std::size_t consumed =
        input_pos - (in_buffer.size - in_buffer.pos);
    FL2_freeDStream(stream);
    if (consumed != input.size()) {
        fail("Fast LZMA2 decoder left trailing input");
    }
    return sink.result();
}

#endif

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const std::size_t mid = values.size() / 2;
    if ((values.size() & 1u) != 0) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2.0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse_options(argc, argv);
        validate_codec_for_backend(options.codec);
        const std::vector<std::uint8_t> input = load_file(options.input_path);

        const DecodeResult validation =
            decode_backend(input, options, true);

        for (int i = 0; i < options.warmups; ++i) {
            const DecodeResult result =
                decode_backend(input, options, false);
            if (result.output_bytes != validation.output_bytes) {
                fail("warmup output size changed");
            }
        }

        std::vector<double> elapsed_ms;
        elapsed_ms.reserve(static_cast<std::size_t>(options.runs));
        for (int i = 0; i < options.runs; ++i) {
            const auto started = std::chrono::steady_clock::now();
            const DecodeResult result =
                decode_backend(input, options, false);
            const auto finished = std::chrono::steady_clock::now();
            if (result.output_bytes != validation.output_bytes) {
                fail("measured output size changed");
            }
            elapsed_ms.push_back(
                std::chrono::duration<double, std::milli>(
                    finished - started).count());
        }

        const double median_ms = median(elapsed_ms);
        const double mib =
            static_cast<double>(validation.output_bytes) / (1024.0 * 1024.0);
        const double mib_per_second =
            median_ms > 0.0 ? mib / (median_ms / 1000.0) : 0.0;

        std::printf("codec    : %s\n", options.codec.c_str());
        std::printf("backend  : %s\n", backend_name());
        std::printf(
            "input    : %.2f MiB\n",
            static_cast<double>(input.size()) / (1024.0 * 1024.0));
        std::printf("output   : %.2f MiB\n", mib);
        std::printf("chunk    : %.0f KiB\n", options.chunk_size / 1024.0);
        std::printf("threads  : %u\n", options.threads);
        if (options.codec == "lzma2") {
            std::printf("lzma2prop: %d\n", options.lzma2_prop);
        }
        std::printf(
            "validate : bytes=%llu fnv1a64=%016llx\n",
            static_cast<unsigned long long>(validation.output_bytes),
            static_cast<unsigned long long>(validation.hash));
        std::printf("runs     :");
        for (double value : elapsed_ms) {
            std::printf(" %.3fms", value);
        }
        std::printf("\n");
        std::printf("median   : %.3f ms\n", median_ms);
        std::printf("throughput: %.2f MiB/s\n", mib_per_second);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "codec bench error: %s\n", error.what());
        return 2;
    }
}
