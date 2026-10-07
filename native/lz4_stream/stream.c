/* Execution adapter only. Archive identity, boundaries and extraction policy
   belong to the Rust analysis layer. Library validation is never disabled. */
#include "stream.h"
#include "lz4.h"
#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE (256 * 1024)
#define LEGACY_SIZE (8 * 1024 * 1024)
#define FRAME_MAGIC 0x184d2204U
#define LEGACY_MAGIC 0x184c2102U

typedef struct {
    void *opaque;
    sup_lz4_read read;
    sup_lz4_skip skip;
    sup_lz4_write write;
    sup_lz4_dictionary dictionary;
    sup_lz4_progress progress;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
    sup_lz4_timing_hook compute_begin, compute_end;
#endif
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
static int exact(stream *s, unsigned char *dst, size_t n) {
    while (n) {
        size_t take;
        int rc = need(s, 1);
        if (rc) return rc;
        take = s->size-s->pos;
        if (take > n) take = n;
        memcpy(dst, s->input+s->pos, take);
        consume(s, take);
        dst += take;
        n -= take;
    }
    return SUP_LZ4_OK;
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
    const void *dict = NULL;
    size_t dict_size = 0, header_size, hint, source_size;
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
    if (s->dictionary) {
        int found = s->dictionary(s->opaque, info.dictID, (flags&1)!=0, &dict, &dict_size);
        if (found < 0) { s->result->dictionary_id=info.dictID; rc = SUP_LZ4_DICTIONARY_IO; goto done; }
        if (!found && (flags & 1)) {
            s->result->dictionary_id = info.dictID;
            rc = SUP_LZ4_DICTIONARY; goto done;
        }
    } else if (flags & 1) {
        s->result->dictionary_id = info.dictID;
        rc = SUP_LZ4_DICTIONARY; goto done;
    }
    do {
        size_t dst_size = BUFFER_SIZE;
        rc = need(s, 1);
        if (rc) goto done;
        source_size = s->size-s->pos;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        if (s->compute_begin) s->compute_begin(s->opaque);
#endif
        hint = LZ4F_decompress_usingDict(ctx, s->output, &dst_size,
            s->input+s->pos, &source_size, dict, dict_size, NULL);
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        if (s->compute_end) s->compute_end(s->opaque);
#endif
        if (LZ4F_isError(hint)) {
            rc = library_error(hint);
            /* A frame can reference an external dictionary without a Dict-ID.
               Without that context, a failed block cannot prove source damage. */
            if (!(flags & 1) && !dict_size && LZ4F_getErrorCode(hint) == LZ4F_ERROR_decompressionFailed)
                rc = SUP_LZ4_DICTIONARY_OR_DATA;
            goto done;
        }
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
static int legacy(stream *s) {
    unsigned char *input = NULL, *output = NULL;
    const uint32_t max_packed = (uint32_t)LZ4_compressBound(LEGACY_SIZE);
    int rc = SUP_LZ4_OK;
    consume(s, 4);
    input = (unsigned char *)malloc(max_packed);
    output = (unsigned char *)malloc(LEGACY_SIZE);
    if (!input || !output) { rc = SUP_LZ4_MEMORY; goto done; }
    for (;;) {
        uint32_t size;
        int decoded;
        rc = need(s, 4);
        if (rc == SUP_LZ4_TRUNCATED && s->pos == s->size) { rc = SUP_LZ4_OK; break; }
        if (rc) goto done;
        size = le32(s->input+s->pos);
        if (size == FRAME_MAGIC || size == LEGACY_MAGIC || is_skip(size)) break;
        if (!size) { consume(s, 4); break; } /* Linux legacy end marker */
        if (size > max_packed) { rc = SUP_LZ4_DATA; goto done; }
        consume(s, 4);
        rc = exact(s, input, size);
        if (rc) goto done;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        if (s->compute_begin) s->compute_begin(s->opaque);
#endif
        decoded = LZ4_decompress_safe((const char *)input, (char *)output, (int)size, LEGACY_SIZE);
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        if (s->compute_end) s->compute_end(s->opaque);
#endif
        if (decoded < 0) { rc = SUP_LZ4_DATA; goto done; }
        rc = emit(s, output, (size_t)decoded);
        if (rc) goto done;
    }
    ++s->result->frames;
    ++s->result->legacy_frames;
done:
    free(input); free(output);
    return rc;
}
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
int sup_lz4_decode_profiled(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_dictionary dictionary,
    sup_lz4_progress progress, sup_lz4_timing_hook compute_begin,
    sup_lz4_timing_hook compute_end, sup_lz4_result *result) {
#else
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_dictionary dictionary,
    sup_lz4_progress progress, sup_lz4_result *result) {
#endif
    stream s;
    int rc = SUP_LZ4_OK;
    memset(result, 0, sizeof(*result));
    memset(&s, 0, sizeof(s));
    s.opaque=opaque; s.read=read; s.skip=skip; s.write=write;
    s.dictionary=dictionary; s.progress=progress;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
    s.compute_begin=compute_begin; s.compute_end=compute_end; s.result=result;
#else
    s.result=result;
#endif
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
        else if (magic == LEGACY_MAGIC) rc=legacy(&s);
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
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_dictionary dictionary,
    sup_lz4_progress progress, sup_lz4_result *result) {
    return sup_lz4_decode_profiled(opaque, read, skip, write, dictionary,
        progress, NULL, NULL, result);
}
#endif
