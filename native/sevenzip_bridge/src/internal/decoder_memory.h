#pragma once
#include <stddef.h>

/* A dispatch threshold, never a format/dictionary size limit. Small buffers
   keep the SDK allocator and do not participate in arbitration. */
/* Includes LZ4's legal 4 MiB block buffers (plus checksum/history), while
   leaving the fixed 1 MiB output and smaller IO buffers on the original path.
   LZMA's variable dictionaries use a dedicated 2 MiB entry in LzmaDec.c. */
#define SUNPACK_LARGE_ALLOCATION ((size_t)4 << 20)

#ifdef __cplusplus
extern "C" {
#endif
void *sunpack_memory_current_context(void);
void *sunpack_memory_exchange_context(void *context);
int sunpack_memory_may_start_thread(void *context);
void *sunpack_memory_alloc(size_t size);
int sunpack_memory_free(void *address);
size_t sunpack_memory_size(void *address);
void *sunpack_decoder_allocate(void *opaque, size_t size);
void sunpack_decoder_free(void *opaque, void *address);
#ifdef __cplusplus
}
#endif
