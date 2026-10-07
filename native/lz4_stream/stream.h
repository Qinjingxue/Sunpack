#ifndef SUNPACK_LZ4_STREAM_H
#define SUNPACK_LZ4_STREAM_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum sup_lz4_error {
    SUP_LZ4_OK, SUP_LZ4_IO, SUP_LZ4_TRUNCATED, SUP_LZ4_DATA,
    SUP_LZ4_CHECKSUM, SUP_LZ4_DICTIONARY, SUP_LZ4_MEMORY, SUP_LZ4_CANCELLED,
    SUP_LZ4_DICTIONARY_IO, SUP_LZ4_DICTIONARY_OR_DATA
};
typedef struct {
    uint64_t input_bytes, output_bytes, frames, skippable_frames;
    uint64_t content_checked_frames, block_checked_frames, legacy_frames;
    uint32_t dictionary_id;
    int error;
} sup_lz4_result;

/* All callbacks belong to one invocation; no process-global decoder state.
   read: actual count, -1 for failure. skip: 0 success, 1 range exhausted, -1 IO failure; optional.
   write: 0 success, nonzero failure. dictionary: 1 found, 0 absent, -1 IO.
   progress: nonzero cancels. A dictionary remains valid to the end of a frame. */
typedef ptrdiff_t (*sup_lz4_read)(void *, void *, size_t);
typedef int (*sup_lz4_skip)(void *, uint64_t);
typedef int (*sup_lz4_write)(void *, const void *, size_t);
typedef int (*sup_lz4_dictionary)(void *, uint32_t, int, const void **, size_t *);
typedef int (*sup_lz4_progress)(void *, uint64_t, uint64_t);
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_dictionary dictionary,
    sup_lz4_progress progress, sup_lz4_result *result);
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
typedef void (*sup_lz4_timing_hook)(void *);
int sup_lz4_decode_profiled(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_dictionary dictionary,
    sup_lz4_progress progress, sup_lz4_timing_hook compute_begin,
    sup_lz4_timing_hook compute_end, sup_lz4_result *result);
#endif

#ifdef __cplusplus
}
#endif
#endif
