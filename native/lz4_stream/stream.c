/* Execution adapter only. Archive identity, boundaries and extraction policy
   belong to the Rust analysis layer. Library validation is never disabled. */
#include "stream.h"
#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE (256 * 1024)
#define FRAME_MAGIC 0x184d2204U

typedef struct {
    void *opaque;
    sup_lz4_read read;
    sup_lz4_skip skip;
    sup_lz4_write write;
    sup_lz4_progress progress;
    sup_lz4_result *result;
    sup_lz4_allocate allocate;
    sup_lz4_free release;
    LZ4F_dctx *decoder;
    unsigned char *input, *output;
    size_t pos, size;
} stream;

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
static int emit(stream *s, const void *data, size_t n) {
    if (UINT64_MAX-s->result->output_bytes < n) return SUP_LZ4_DATA;
    if (n && s->write(s->opaque, data, n)) return SUP_LZ4_IO;
    s->result->output_bytes += n;
    return tick(s);
}
static int library_error(size_t rc) {
    LZ4F_errorCodes error = LZ4F_getErrorCode(rc);
    if (error == LZ4F_ERROR_contentChecksum_invalid || error == LZ4F_ERROR_blockChecksum_invalid ||
        error == LZ4F_ERROR_headerChecksum_invalid) return SUP_LZ4_CHECKSUM;
    if (error == LZ4F_ERROR_allocation_failed) return SUP_LZ4_MEMORY;
    return SUP_LZ4_DATA;
}
static int modern(stream *s) {
    LZ4F_frameInfo_t info;
    size_t header_size, hint, source_size;
    const uint64_t start_out = s->result->output_bytes;
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
    do {
        size_t dst_size = BUFFER_SIZE;
        rc = need(s, 1);
        if (rc) return rc;
        source_size = s->size-s->pos;
        hint = LZ4F_decompress(s->decoder, s->output, &dst_size,
            s->input+s->pos, &source_size, NULL);
        if (LZ4F_isError(hint)) return library_error(hint);
        consume(s, source_size);
        rc = emit(s, s->output, dst_size);
        if (rc) return rc;
        if (hint && !source_size && !dst_size) return SUP_LZ4_DATA;
    } while (hint);
    // LZ4F validates nonzero content sizes itself. An explicit zero also
    // promises an empty payload, even though LZ4F treats it like an absent size.
    if ((flags & 8) && !info.contentSize && s->result->output_bytes != start_out) return SUP_LZ4_DATA;
    ++s->result->frames;
    if (info.contentChecksumFlag) ++s->result->content_checked_frames;
    if (info.blockChecksumFlag) ++s->result->block_checked_frames;
    return SUP_LZ4_OK;
}
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result) {
    return sup_lz4_decode_with_memory(opaque, read, skip, write, progress, result, NULL, NULL);
}
int sup_lz4_decode_with_memory(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result,
    sup_lz4_allocate allocate, sup_lz4_free release) {
    stream s;
    int rc = SUP_LZ4_OK;
    memset(result, 0, sizeof(*result));
    memset(&s, 0, sizeof(s));
    s.opaque=opaque; s.read=read; s.skip=skip; s.write=write;
    s.progress=progress; s.result=result;
    s.allocate=allocate; s.release=release;
    s.input=(unsigned char *)malloc(BUFFER_SIZE);
    s.output=(unsigned char *)malloc(BUFFER_SIZE);
    if (!s.input || !s.output) { rc=SUP_LZ4_MEMORY; goto done; }
    for (;;) {
        uint32_t magic;
        rc = need(&s, 4);
        if (rc == SUP_LZ4_TRUNCATED && s.pos == s.size && (result->frames || result->skippable_frames)) {
            rc=SUP_LZ4_OK; break;
        }
        if (rc) break;
        magic = le32(s.input+s.pos);
        if (magic == FRAME_MAGIC) rc=modern(&s);
        else if (is_skip(magic)) {
            rc=need(&s, 8);
            if (!rc) {
                uint32_t size=le32(s.input+s.pos+4);
                consume(&s, 8);
                rc=skip_bytes(&s, size);
                if (!rc) ++result->skippable_frames;
            }
        } else rc=SUP_LZ4_DATA;
        if (rc) break;
    }
done:
    LZ4F_freeDecompressionContext(s.decoder);
    free(s.input); free(s.output);
    result->error=rc;
    return rc;
}
