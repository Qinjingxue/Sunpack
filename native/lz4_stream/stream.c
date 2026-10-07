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
    unsigned char *input, *output;
    size_t pos, size;
} stream;

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t le64(const unsigned char *p) {
    return (uint64_t)le32(p) | ((uint64_t)le32(p+4)<<32);
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
    LZ4F_dctx *ctx = NULL;
    LZ4F_frameInfo_t info;
    size_t header_size, hint, source_size;
    uint64_t expected = 0, start_out = s->result->output_bytes;
    unsigned char flags;
    int rc = need(s, 7), has_size;
    if (rc) return rc;
    flags = s->input[s->pos+4];
    has_size = (flags & 8) != 0;
    header_size = 7 + (has_size ? 8 : 0) + ((flags & 1) ? 4 : 0);
    rc = need(s, header_size);
    if (rc) return rc;
    if (has_size) expected = le64(s->input+s->pos+6);
    hint = LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
    if (LZ4F_isError(hint)) return library_error(hint);
    source_size = header_size;
    hint = LZ4F_getFrameInfo(ctx, &info, s->input+s->pos, &source_size);
    if (LZ4F_isError(hint)) { rc = library_error(hint); goto done; }
    consume(s, source_size);
    if (flags & 1) { rc = SUP_LZ4_UNSUPPORTED; goto done; }
    do {
        size_t dst_size = BUFFER_SIZE;
        rc = need(s, 1);
        if (rc) goto done;
        source_size = s->size-s->pos;
        hint = LZ4F_decompress(ctx, s->output, &dst_size,
            s->input+s->pos, &source_size, NULL);
        if (LZ4F_isError(hint)) { rc = library_error(hint); goto done; }
        consume(s, source_size);
        rc = emit(s, s->output, dst_size);
        if (rc) goto done;
        if (hint && !source_size && !dst_size) { rc = SUP_LZ4_DATA; goto done; }
    } while (hint);
    if (has_size && s->result->output_bytes-start_out != expected) { rc = SUP_LZ4_DATA; goto done; }
    ++s->result->frames;
    if (info.contentChecksumFlag) ++s->result->content_checked_frames;
    if (info.blockChecksumFlag) ++s->result->block_checked_frames;
done:
    LZ4F_freeDecompressionContext(ctx);
    return rc;
}
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result) {
    stream s;
    int rc = SUP_LZ4_OK;
    memset(result, 0, sizeof(*result));
    memset(&s, 0, sizeof(s));
    s.opaque=opaque; s.read=read; s.skip=skip; s.write=write;
    s.progress=progress; s.result=result;
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
    free(s.input); free(s.output);
    result->error=rc;
    return rc;
}
