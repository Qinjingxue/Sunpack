/* SunpackSharedInput.h -- private borrowed-input bridge for embedded 7-Zip */

#ifndef SUNPACK_C_SHARED_INPUT_H
#define SUNPACK_C_SHARED_INPUT_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#if SUP7Z_USE_SHARED_INPUT

typedef struct
{
  void *ctx;

  /*
    On SZ_OK:
      (*borrowed != 0) => data/size/token describe an immutable borrowed span.
      (*borrowed == 0) => caller must use its normal ISeqInStream read path.
    A borrowed span remains valid until Release(ctx, token).
  */
  SRes (*Borrow)(void *ctx, size_t maxSize,
      const Byte **data, size_t *size, UInt64 *token, BoolInt *borrowed);

  void (*Release)(void *ctx, UInt64 token);
} CSunpackSharedInput;

#endif

EXTERN_C_END

#endif
