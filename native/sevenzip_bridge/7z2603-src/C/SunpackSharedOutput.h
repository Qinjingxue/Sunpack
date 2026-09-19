/* SunpackSharedOutput.h -- private borrowed-output bridge for embedded 7-Zip */

#ifndef SUNPACK_C_SHARED_OUTPUT_H
#define SUNPACK_C_SHARED_OUTPUT_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#if SUP7Z_USE_SHARED_OUTPUT

typedef struct
{
  void *ctx;

  /*
    SubmitBorrowed() accepts immutable decoder-owned output and returns a token
    that pins that memory until WaitBorrowed(). The bridge may consume less than
    requested, but a successful call always consumes at least one byte.
  */
  SRes (*SubmitBorrowed)(void *ctx, const Byte *data, size_t size,
      size_t *processed, UInt64 *token, BoolInt *borrowed);

  SRes (*WaitBorrowed)(void *ctx, UInt64 token);
} CSunpackSharedOutput;

#endif

EXTERN_C_END

#endif
