#ifndef SUNPACK_LZ4_STREAM_H
#define SUNPACK_LZ4_STREAM_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum sup_lz4_error {
    SUP_LZ4_OK, SUP_LZ4_IO, SUP_LZ4_TRUNCATED, SUP_LZ4_DATA,
    SUP_LZ4_CHECKSUM, SUP_LZ4_UNSUPPORTED, SUP_LZ4_MEMORY, SUP_LZ4_CANCELLED
};
typedef struct {
    uint64_t input_bytes, output_bytes, frames, skippable_frames;
    uint64_t content_checked_frames, block_checked_frames;
    int error;
} sup_lz4_result;

/* All callbacks belong to one invocation; no process-global decoder state.
   read: actual count, -1 for failure. skip: 0 success, 1 range exhausted, -1 IO failure; optional.
   write: 0 success, nonzero failure. progress: nonzero cancels. */
typedef ptrdiff_t (*sup_lz4_read)(void *, void *, size_t);
typedef int (*sup_lz4_skip)(void *, uint64_t);
typedef int (*sup_lz4_write)(void *, const void *, size_t);
typedef int (*sup_lz4_progress)(void *, uint64_t, uint64_t);
int sup_lz4_decode(void *opaque, sup_lz4_read read, sup_lz4_skip skip,
    sup_lz4_write write, sup_lz4_progress progress, sup_lz4_result *result);
#ifdef __cplusplus
}
#endif
#endif
