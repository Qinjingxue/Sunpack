// Lzma2Decoder.cpp

#include "StdAfx.h"

// #include <stdio.h>

#include "../../../C/Alloc.h"
// #include "../../../C/CpuTicks.h"

#include "../Common/StreamUtils.h"
#if SUP7Z_USE_SHARED_INPUT
#include "../Common/SunpackSharedInput.h"
#endif
#if SUP7Z_USE_SHARED_OUTPUT
#include "../Common/SunpackSharedOutput.h"
#endif

#include "Lzma2Decoder.h"

namespace NCompress {
namespace NLzma2 {

#if SUP7Z_USE_SHARED_INPUT
static SRes SharedInput_Borrow(void *ctx, size_t maxSize,
    const Byte **data, size_t *size, UInt64 *token, BoolInt *borrowed)
{
  *data = NULL;
  *size = 0;
  *token = 0;
  *borrowed = False;

  if (!ctx || maxSize == 0)
    return SZ_OK;

  ISunpackSharedInput *source = (ISunpackSharedInput *)ctx;
  const UInt32 request = maxSize > (size_t)0xFFFFFFFFu
      ? 0xFFFFFFFFu : (UInt32)maxSize;
  UInt32 borrowedSize = 0;
  const HRESULT hres = source->Borrow(request, data, &borrowedSize, token);
  if (hres == S_FALSE)
    return SZ_OK;
  if (hres != S_OK)
    return HRESULT_To_SRes(hres, SZ_ERROR_READ);
  if (!*data || borrowedSize == 0 || borrowedSize > request || *token == 0)
  {
    if (*token)
      source->ReleaseBorrowed(*token);
    *data = NULL;
    *token = 0;
    return SZ_ERROR_FAIL;
  }

  *size = borrowedSize;
  *borrowed = True;
  return SZ_OK;
}

static void SharedInput_Release(void *ctx, UInt64 token)
{
  if (ctx && token)
    ((ISunpackSharedInput *)ctx)->ReleaseBorrowed(token);
}
#endif

#if SUP7Z_USE_SHARED_OUTPUT
struct CSharedOutputBridge
{
  ISunpackSharedOutput *Output;
  HRESULT Result;
  UInt64 Processed;
};

static SRes SharedOutput_SubmitBorrowed(void *ctx, const Byte *data, size_t size,
    size_t *processed, UInt64 *token, BoolInt *borrowed)
{
  CSharedOutputBridge *bridge = (CSharedOutputBridge *)ctx;
  *processed = 0;
  *token = 0;
  *borrowed = False;
  if (!bridge || !bridge->Output || !data || size == 0)
    return SZ_OK;

  const UInt32 request = size > (size_t)0xFFFFFFFFu
      ? 0xFFFFFFFFu : (UInt32)size;
  UInt32 accepted = 0;
  UInt64 lease = 0;
  const HRESULT hres = bridge->Output->SubmitBorrowed(
      data, request, &accepted, &lease);
  if (hres == S_FALSE)
    return SZ_OK;
  if (hres != S_OK)
  {
    bridge->Result = hres;
    return HRESULT_To_SRes(hres, SZ_ERROR_WRITE);
  }
  if (accepted == 0 || accepted > request || lease == 0)
  {
    bridge->Result = E_FAIL;
    return SZ_ERROR_FAIL;
  }

  bridge->Processed += accepted;
  *processed = accepted;
  *token = lease;
  *borrowed = True;
  return SZ_OK;
}

static SRes SharedOutput_WaitBorrowed(void *ctx, UInt64 token)
{
  CSharedOutputBridge *bridge = (CSharedOutputBridge *)ctx;
  if (!bridge || !bridge->Output || token == 0)
    return SZ_ERROR_PARAM;

  const HRESULT hres = bridge->Output->WaitBorrowed(token);
  if (hres != S_OK)
  {
    bridge->Result = hres;
    return HRESULT_To_SRes(hres, SZ_ERROR_WRITE);
  }
  return SZ_OK;
}
#endif

CDecoder::CDecoder():
      _dec(NULL)
    , _inProcessed(0)
    , _prop(0xFF)
    , _finishMode(false)
    , _inBufSize(1 << 20)
    , _outStep(1 << 20)
    #ifndef Z7_ST
    , _tryMt(1)
    , _numThreads(1)
    , _memUsage((UInt64)(sizeof(size_t)) << 28)
    #endif
{}

CDecoder::~CDecoder()
{
  if (_dec)
    Lzma2DecMt_Destroy(_dec);
}

Z7_COM7F_IMF(CDecoder::SetInBufSize(UInt32 , UInt32 size)) { _inBufSize = size; return S_OK; }
Z7_COM7F_IMF(CDecoder::SetOutBufSize(UInt32 , UInt32 size)) { _outStep = size; return S_OK; }

Z7_COM7F_IMF(CDecoder::SetDecoderProperties2(const Byte *prop, UInt32 size))
{
  if (size != 1)
    return E_NOTIMPL;
  if (prop[0] > 40)
    return E_NOTIMPL;
  _prop = prop[0];
  return S_OK;
}


Z7_COM7F_IMF(CDecoder::SetFinishMode(UInt32 finishMode))
{
  _finishMode = (finishMode != 0);
  return S_OK;
}



#ifndef Z7_ST

static UInt64 Get_ExpectedBlockSize_From_Dict(UInt32 dictSize)
{
  const UInt32 kMinSize = (UInt32)1 << 20;
  const UInt32 kMaxSize = (UInt32)1 << 28;
  UInt64 blockSize = (UInt64)dictSize << 2;
  if (blockSize < kMinSize) blockSize = kMinSize;
  if (blockSize > kMaxSize) blockSize = kMaxSize;
  if (blockSize < dictSize) blockSize = dictSize;
  blockSize += (kMinSize - 1);
  blockSize &= ~(UInt64)(kMinSize - 1);
  return blockSize;
}

#define LZMA2_DIC_SIZE_FROM_PROP_FULL(p) ((p) == 40 ? 0xFFFFFFFF : (((UInt32)2 | ((p) & 1)) << ((p) / 2 + 11)))

#endif

#define RET_IF_WRAP_ERROR_CONFIRMED(wrapRes, sRes, sResErrorCode) \
  if (wrapRes != S_OK && sRes == sResErrorCode) return wrapRes;

#define RET_IF_WRAP_ERROR(wrapRes, sRes, sResErrorCode) \
  if (wrapRes != S_OK /* && (sRes == SZ_OK || sRes == sResErrorCode) */) return wrapRes;

Z7_COM7F_IMF(CDecoder::Code(ISequentialInStream *inStream, ISequentialOutStream *outStream,
    const UInt64 *inSize, const UInt64 *outSize, ICompressProgressInfo *progress))
{
  _inProcessed = 0;

  if (!_dec)
  {
    _dec = Lzma2DecMt_Create(
      // &g_AlignedAlloc,
      &g_Alloc,
      &g_MidAlloc);
    if (!_dec)
      return E_OUTOFMEMORY;
  }

  CLzma2DecMtProps props;
  Lzma2DecMtProps_Init(&props);

  props.inBufSize_ST = _inBufSize;
  props.outStep_ST = _outStep;

  #ifndef Z7_ST
  {
    props.numThreads = 1;
    UInt32 numThreads = _numThreads;

    if (_tryMt && numThreads >= 1)
    {
      const UInt64 useLimit = _memUsage;
      const UInt32 dictSize = LZMA2_DIC_SIZE_FROM_PROP_FULL(_prop);
      const UInt64 expectedBlockSize64 = Get_ExpectedBlockSize_From_Dict(dictSize);
      const size_t expectedBlockSize = (size_t)expectedBlockSize64;
      const size_t inBlockMax = expectedBlockSize + expectedBlockSize / 16;
      if (expectedBlockSize == expectedBlockSize64 && inBlockMax >= expectedBlockSize)
      {
        props.outBlockMax = expectedBlockSize;
        props.inBlockMax = inBlockMax;
        const size_t kOverheadSize = props.inBufSize_MT + (1 << 16);
        const UInt64 okThreads = useLimit / (props.outBlockMax + props.inBlockMax + kOverheadSize);
        if (numThreads > okThreads)
          numThreads = (UInt32)okThreads;
        if (numThreads == 0)
          numThreads = 1;
        props.numThreads = numThreads;
      }
    }
  }
  #endif

  CSeqInStreamWrap inWrap;
  CSeqOutStreamWrap outWrap;
  CCompressProgressWrap progressWrap;

  inWrap.Init(inStream);
  outWrap.Init(outStream);
  progressWrap.Init(progress);

#if SUP7Z_USE_SHARED_INPUT
  CMyComPtr<ISunpackSharedInput> sharedInput;
  inStream->QueryInterface(IID_ISunpackSharedInput, (void **)&sharedInput);
  CSunpackSharedInput sharedInputBridge = {};
  if (sharedInput)
  {
    sharedInputBridge.ctx = sharedInput;
    sharedInputBridge.Borrow = SharedInput_Borrow;
    sharedInputBridge.Release = SharedInput_Release;
  }
#endif

#if SUP7Z_USE_SHARED_OUTPUT
  CMyComPtr<ISunpackSharedOutput> sharedOutput;
  if (outStream)
    outStream->QueryInterface(IID_ISunpackSharedOutput, (void **)&sharedOutput);
  CSharedOutputBridge sharedOutputContext = { sharedOutput.Interface(), S_OK, 0 };
  CSunpackSharedOutput sharedOutputBridge = {};
  if (sharedOutput)
  {
    sharedOutputBridge.ctx = &sharedOutputContext;
    sharedOutputBridge.SubmitBorrowed = SharedOutput_SubmitBorrowed;
    sharedOutputBridge.WaitBorrowed = SharedOutput_WaitBorrowed;
  }
#endif

  SRes res;

  UInt64 inProcessed = 0;
  int isMT = False;

  #ifndef Z7_ST
  isMT = _tryMt;
  #endif

  // UInt64 cpuTicks = GetCpuTicks();

  res = Lzma2DecMt_Decode(_dec, _prop, &props,
      &outWrap.vt,
#if SUP7Z_USE_SHARED_OUTPUT
      sharedOutput ? &sharedOutputBridge : NULL,
#endif
      outSize, _finishMode,
      &inWrap.vt,
#if SUP7Z_USE_SHARED_INPUT
      sharedInput ? &sharedInputBridge : NULL,
#endif
      &inProcessed,
      &isMT,
      progress ? &progressWrap.vt : NULL);

  /*
  cpuTicks = GetCpuTicks() - cpuTicks;
  printf("\n             ticks = %10I64u\n", cpuTicks / 1000000);
  */


  #ifndef Z7_ST
  /* we reset _tryMt, only if p->props.numThreads was changed */
  if (props.numThreads > 1)
    _tryMt = isMT;
  #endif

  _inProcessed = inProcessed;

  RET_IF_WRAP_ERROR(progressWrap.Res, res, SZ_ERROR_PROGRESS)
  RET_IF_WRAP_ERROR(outWrap.Res, res, SZ_ERROR_WRITE)
#if SUP7Z_USE_SHARED_OUTPUT
  RET_IF_WRAP_ERROR(sharedOutputContext.Result, res, SZ_ERROR_WRITE)
#endif
  RET_IF_WRAP_ERROR_CONFIRMED(inWrap.Res, res, SZ_ERROR_READ)

  if (res == SZ_OK && _finishMode)
  {
    if (inSize && *inSize != inProcessed)
      res = SZ_ERROR_DATA;
    if (outSize
#if SUP7Z_USE_SHARED_OUTPUT
        && *outSize != outWrap.Processed + sharedOutputContext.Processed
#else
        && *outSize != outWrap.Processed
#endif
        )
      res = SZ_ERROR_DATA;
  }

  return SResToHRESULT(res);
}


Z7_COM7F_IMF(CDecoder::GetInStreamProcessedSize(UInt64 *value))
{
  *value = _inProcessed;
  return S_OK;
}


#ifndef Z7_ST

Z7_COM7F_IMF(CDecoder::SetNumberOfThreads(UInt32 numThreads))
{
  _numThreads = numThreads;
  return S_OK;
}

Z7_COM7F_IMF(CDecoder::SetMemLimit(UInt64 memUsage))
{
  _memUsage = memUsage;
  return S_OK;
}

#endif


#ifndef Z7_NO_READ_FROM_CODER

Z7_COM7F_IMF(CDecoder::SetOutStreamSize(const UInt64 *outSize))
{
  CLzma2DecMtProps props;
  Lzma2DecMtProps_Init(&props);
  props.inBufSize_ST = _inBufSize;
  props.outStep_ST = _outStep;

  _inProcessed = 0;

  if (!_dec)
  {
    _dec = Lzma2DecMt_Create(&g_AlignedAlloc, &g_MidAlloc);
    if (!_dec)
      return E_OUTOFMEMORY;
  }

  _inWrap.Init(_inStream);

  const SRes res = Lzma2DecMt_Init(_dec, _prop, &props, outSize, _finishMode, &_inWrap.vt
#if SUP7Z_USE_SHARED_INPUT
      , NULL
#endif
      );

  if (res != SZ_OK)
    return SResToHRESULT(res);
  return S_OK;
}


Z7_COM7F_IMF(CDecoder::SetInStream(ISequentialInStream *inStream))
  { _inStream = inStream; return S_OK; }
Z7_COM7F_IMF(CDecoder::ReleaseInStream())
  { _inStream.Release(); return S_OK; }
  

Z7_COM7F_IMF(CDecoder::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  if (processedSize)
    *processedSize = 0;

  size_t size2 = size;
  UInt64 inProcessed = 0;

  const SRes res = Lzma2DecMt_Read(_dec, (Byte *)data, &size2, &inProcessed);

  _inProcessed += inProcessed;
  if (processedSize)
    *processedSize = (UInt32)size2;
  if (res != SZ_OK)
    return SResToHRESULT(res);
  return S_OK;
}

#endif

}}
