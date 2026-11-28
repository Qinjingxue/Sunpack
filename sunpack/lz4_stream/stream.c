/* Execution adapter only. Archive identity, boundaries and extraction policy
   belong to the Rust analysis layer. Library validation is never disabled. */
#include "stream.h"
#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE (256 * 1024)
#define FRAME_MAGIC 0x184d2204U

struct sup_lz4_reader {
    void *opaque;
    sup_lz4_read read;
    sup_lz4_skip skip;
    sup_lz4_progress progress;
    sup_lz4_result *result;
    sup_lz4_allocate allocate;
    sup_lz4_free release;
    LZ4F_dctx *decoder;
    unsigned char *input;
    size_t pos, size;
    uint64_t start_out;
    int declared_empty, in_frame, saw_skippable, eof;
};
typedef struct sup_lz4_reader stream;

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static int is_skip(uint32_t magic) { return (magic & 0xfffffff0U) == 0x184d2a50U; }
static int tick(stream *s) {
    return s->progress && s->progress(s->opaque, s->result->input_bytes, s->result->output_bytes)
        ? SUP_LZ4_CANCELLED : SUP_LZ4_OK;
}
/* Small lookahead and consumption share one buffer. Never discard unread tail
   at the end of a frame, including when the next frame fits in this buffer. */
static int need(stream *s, size_t n) {
    while (s->size - s->pos < n) {
        ptrdiff_t got;
        int rc = tick(s);
        if (rc) return rc;
        if (s->pos) {
            memmove(s->input, s->input+s->pos, s->size-s->pos);
            s->size -= s->pos;
            s->pos = 0;
        }
        got = s->read(s->opaque, s->input+s->size, BUFFER_SIZE-s->size);
        if (got < 0 || (size_t)got > BUFFER_SIZE-s->size) return SUP_LZ4_IO;
        if (!got) return SUP_LZ4_TRUNCATED;
        s->size += (size_t)got;
    }
    return SUP_LZ4_OK;
}
static void consume(stream *s, size_t n) {
    s->pos += n;
    s->result->input_bytes += n;
}
static int skip_bytes(stream *s, uint64_t n) {
    size_t available = s->size-s->pos;
    size_t take = n < available ? (size_t)n : available;
    consume(s, take);
    n -= take;
    if (n && s->skip) {
        int error = s->skip(s->opaque, n);
        if (error) return error == 1 ? SUP_LZ4_TRUNCATED : SUP_LZ4_IO;
        s->result->input_bytes += n;
        return tick(s);
    }
    while (n) {
        int rc = need(s, 1);
        if (rc) return rc;
        available = s->size-s->pos;
        take = n < available ? (size_t)n : available;
        consume(s, take);
        n -= take;
    }
    return SUP_LZ4_OK;
}
static int library_error(size_t rc) {
    LZ4F_errorCodes error = LZ4F_getErrorCode(rc);
    if (error == LZ4F_ERROR_contentChecksum_invalid || error == LZ4F_ERROR_blockChecksum_invalid ||
        error == LZ4F_ERROR_headerChecksum_invalid) return SUP_LZ4_CHECKSUM;
    if (error == LZ4F_ERROR_allocation_failed) return SUP_LZ4_MEMORY;
    return SUP_LZ4_DATA;
}
static int start_frame(stream *s) {
    size_t header_size, hint, source_size;
    LZ4F_frameInfo_t info;
    unsigned char flags;
    int rc = need(s, 7);
    if (rc) return rc;
    flags = s->input[s->pos+4];
    header_size = LZ4F_headerSize(s->input+s->pos, s->size-s->pos);
    if (LZ4F_isError(header_size)) return library_error(header_size);
    rc = need(s, header_size);
    if (rc) return rc;
    // A completed frame resets the decoder state while keeping its buffers.
    if (!s->decoder) {
        if (s->allocate) {
            const LZ4F_CustomMem memory = {s->allocate, NULL, s->release, s->opaque};
            s->decoder = LZ4F_createDecompressionContext_advanced(memory, LZ4F_VERSION);
            if (!s->decoder) return SUP_LZ4_MEMORY;
        } else {
            hint = LZ4F_createDecompressionContext(&s->decoder, LZ4F_VERSION);
            if (LZ4F_isError(hint)) return library_error(hint);
        }
    }
    source_size = header_size;
    hint = LZ4F_getFrameInfo(s->decoder, &info, s->input+s->pos, &source_size);
    if (LZ4F_isError(hint)) return library_error(hint);
    consume(s, source_size);
    if (flags & 1) return SUP_LZ4_UNSUPPORTED;
    s->declared_empty = (flags & 8) && !info.contentSize;
    s->start_out = s->result->output_bytes;
    s->in_frame = 1;
    return SUP_LZ4_OK;
}

static int read_chunk(stream *s, void *out, size_t capacity, size_t *written) {
    *written = 0;
    while (!s->eof && capacity) {
        int rc;
        if (!s->in_frame) {
            uint32_t magic;
            rc = need(s, 4);
            if (rc == SUP_LZ4_TRUNCATED && s->pos == s->size &&
                (s->result->frames || s->saw_skippable)) {
                s->eof = 1;
                return SUP_LZ4_OK;
            }
            if (rc) return rc;
            magic = le32(s->input+s->pos);
            if (is_skip(magic)) {
                uint32_t size;
                rc = need(s, 8);
                if (rc) return rc;
                size = le32(s->input+s->pos+4);
                consume(s, 8);
                rc = skip_bytes(s, size);
                if (rc) return rc;
                s->saw_skippable = 1;
                continue;
            }
            if (magic != FRAME_MAGIC) return SUP_LZ4_DATA;
            rc = start_frame(s);
            if (rc) return rc;
        }
        {
            size_t hint, source_size, dst_size = capacity;
            rc = need(s, 1);
            if (rc) return rc;
            source_size = s->size-s->pos;
            hint = LZ4F_decompress(s->decoder, out, &dst_size,
                s->input+s->pos, &source_size, NULL);
            if (LZ4F_isError(hint)) return library_error(hint);
            if (hint && !source_size && !dst_size) return SUP_LZ4_DATA;
            consume(s, source_size);
            if (UINT64_MAX-s->result->output_bytes < dst_size) return SUP_LZ4_DATA;
            s->result->output_bytes += dst_size;
            if (!hint) {
                // An explicitly declared zero length must also be checked.
                if (s->declared_empty && s->result->output_bytes != s->start_out) return SUP_LZ4_DATA;
                s->in_frame = 0;
                ++s->result->frames;
            }
            if (dst_size) {
                *written = dst_size;
                return SUP_LZ4_OK;
            }
            rc = tick(s);
            if (rc) return rc;
        }
    }
    return SUP_LZ4_OK;
}

static int init(stream *s, void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_progress progress, sup_lz4_result *result, sup_lz4_allocate allocate,
    sup_lz4_free release) {
    memset(result, 0, sizeof(*result));
    memset(s, 0, sizeof(*s));
    s->opaque=opaque; s->read=read; s->skip=skip; s->progress=progress;
    s->result=result; s->allocate=allocate; s->release=release;
    s->input=(unsigned char *)malloc(BUFFER_SIZE);
    if (!s->input) return SUP_LZ4_MEMORY;
    return SUP_LZ4_OK;
}
static void close_stream(stream *s) {
    LZ4F_freeDecompressionContext(s->decoder);
    free(s->input);
}

sup_lz4_reader *sup_lz4_reader_open(void *opaque, sup_lz4_read read, sup_lz4_result *result,
    sup_lz4_allocate allocate, sup_lz4_free release) {
    stream *s=(stream *)malloc(sizeof(*s));
    if (!s) return NULL;
    if (init(s, opaque, read, NULL, NULL, result, allocate, release)) {
        free(s);
        return NULL;
    }
    return s;
}
int sup_lz4_reader_read(sup_lz4_reader *s, void *out, size_t capacity, size_t *written) {
    return read_chunk(s, out, capacity, written);
}
void sup_lz4_reader_close(sup_lz4_reader *s) {
    if (s) { close_stream(s); free(s); }
}

int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result) {
    return sup_lz4_decode_with_memory(opaque, read, skip, write, progress, result, NULL, NULL);
}
int sup_lz4_decode_with_memory(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result,
    sup_lz4_allocate allocate, sup_lz4_free release) {
    stream s;
    int rc = init(&s, opaque, read, skip, progress, result, allocate, release);
    unsigned char *out = rc ? NULL : (unsigned char *)malloc(BUFFER_SIZE);
    if (!out) rc=SUP_LZ4_MEMORY;
    while (!rc) {
        size_t written;
        rc=read_chunk(&s, out, BUFFER_SIZE, &written);
        if (rc || !written) break;
        rc=write(s.opaque, out, written) ? SUP_LZ4_IO : tick(&s);
    }
    close_stream(&s);
    free(out);
    return rc;
}
