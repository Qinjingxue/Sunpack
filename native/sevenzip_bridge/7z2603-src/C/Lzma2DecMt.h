/* Lzma2DecMt.h -- LZMA2 Decoder Multi-thread
2023-04-13 : Igor Pavlov : Public domain */

#ifndef ZIP7_INC_LZMA2_DEC_MT_H
#define ZIP7_INC_LZMA2_DEC_MT_H

#include "7zTypes.h"

EXTERN_C_BEGIN

/*
  Optional random-access output callback used by SunPack's MT fast path.
  The callback receives final logical offsets for independently decodable
  LZMA2 reset-runs. A NULL callback preserves the upstream ordered stream path.
*/
typedef SRes (*Lzma2DecMt_WriteAt_Func)(
    void *opaque,
    UInt64 offset,
    const Byte *data,
    size_t size);

typedef struct
{
  size_t inBufSize_ST;
  size_t outStep_ST;
  
  #ifndef Z7_ST
  unsigned numThreads;
  size_t inBufSize_MT;
  size_t outBlockMax;
  size_t inBlockMax;

  Lzma2DecMt_WriteAt_Func writeAt;
  void *writeAtOpaque;
  size_t writeAtStep;
  #endif
} CLzma2DecMtProps;

/* init to single-thread mode */
void Lzma2DecMtProps_Init(CLzma2DecMtProps *p);


/* ---------- CLzma2DecMtHandle Interface ---------- */

/* Lzma2DecMt_ * functions can return the following exit codes:
SRes:
  SZ_OK           - OK
  SZ_ERROR_MEM    - Memory allocation error
  SZ_ERROR_PARAM  - Incorrect paramater in props
  SZ_ERROR_WRITE  - ISeqOutStream write callback error
  // SZ_ERROR_OUTPUT_EOF - output buffer overflow - version with (Byte *) output
  SZ_ERROR_PROGRESS - some break from progress callback
  SZ_ERROR_THREAD - error in multithreading functions (only for Mt version)
*/

typedef struct CLzma2DecMt CLzma2DecMt;
typedef CLzma2DecMt * CLzma2DecMtHandle;
// Z7_DECLARE_HANDLE(CLzma2DecMtHandle)

typedef struct
{
  void *context;
  size_t (*WriteAt)(void *context, UInt64 offset, const void *data, size_t size);
} ISunpackPositionedOutStream;

CLzma2DecMtHandle Lzma2DecMt_Create(ISzAllocPtr alloc, ISzAllocPtr allocMid);
void Lzma2DecMt_Destroy(CLzma2DecMtHandle p);

SRes Lzma2DecMt_DecodePositioned(CLzma2DecMtHandle p,
    Byte prop,
    const CLzma2DecMtProps *props,
    ISeqOutStreamPtr outStream,
    const ISunpackPositionedOutStream *positionedOutStream,
    const UInt64 *outDataSize,
    int finishMode,
    ISeqInStreamPtr inStream,
    UInt64 *inProcessed,
    int *isMT,
    ICompressProgressPtr progress);

SRes Lzma2DecMt_Decode(CLzma2DecMtHandle p,
    Byte prop,
    const CLzma2DecMtProps *props,
    ISeqOutStreamPtr outStream,
    const UInt64 *outDataSize, // NULL means undefined
    int finishMode,            // 0 - partial unpacking is allowed, 1 - if lzma2 stream must be finished
    // Byte *outBuf, size_t *outBufSize,
    ISeqInStreamPtr inStream,
    // const Byte *inData, size_t inDataSize,
    
    // out variables:
    UInt64 *inProcessed,
    int *isMT,  /* out: (*isMT == 0), if single thread decoding was used */

    // UInt64 *outProcessed,
    ICompressProgressPtr progress);


/* ---------- Read from CLzma2DecMtHandle Interface ---------- */

SRes Lzma2DecMt_Init(CLzma2DecMtHandle pp,
    Byte prop,
    const CLzma2DecMtProps *props,
    const UInt64 *outDataSize, int finishMode,
    ISeqInStreamPtr inStream);

SRes Lzma2DecMt_Read(CLzma2DecMtHandle pp,
    Byte *data, size_t *outSize,
    UInt64 *inStreamProcessed);


EXTERN_C_END

#endif
