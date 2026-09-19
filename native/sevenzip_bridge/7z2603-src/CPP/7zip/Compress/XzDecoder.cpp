// XzDecoder.cpp

#include "StdAfx.h"

#include "../../../C/Alloc.h"

#include "../Common/CWrappers.h"
#if SUP7Z_USE_SHARED_INPUT
#include "../Common/SunpackSharedInput.h"
#endif

#include "XzDecoder.h"

namespace NCompress {
namespace NXz {

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

#define RET_IF_WRAP_ERROR_CONFIRMED(wrapRes, sRes, sResErrorCode) \
  if (wrapRes != S_OK && sRes == sResErrorCode) return wrapRes;

#define RET_IF_WRAP_ERROR(wrapRes, sRes, sResErrorCode) \
  if (wrapRes != S_OK /* && (sRes == SZ_OK || sRes == sResErrorCode) */) return wrapRes;

static HRESULT SResToHRESULT_Code(SRes res) throw()
{
  if (res < 0)
    return res;
  switch (res)
  {
    case SZ_OK: return S_OK;
    case SZ_ERROR_MEM: return E_OUTOFMEMORY;
    case SZ_ERROR_UNSUPPORTED: return E_NOTIMPL;
    default: break;
  }
  return S_FALSE;
}


HRESULT CDecoder::Decode(ISequentialInStream *seqInStream, ISequentialOutStream *outStream,
    const UInt64 *outSizeLimit, bool finishStream, ICompressProgressInfo *progress)
{
  MainDecodeSRes = SZ_OK;
  MainDecodeSRes_wasUsed = false;
  XzStatInfo_Clear(&Stat);

  if (!xz)
  {
    xz = XzDecMt_Create(&g_Alloc, &g_MidAlloc);
    if (!xz)
      return E_OUTOFMEMORY;
  }

  CXzDecMtProps props;
  XzDecMtProps_Init(&props);

  int isMT = False;

  #ifndef Z7_ST
  {
    props.numThreads = 1;
    const UInt32 numThreads = _numThreads;

    if (_tryMt && numThreads > 1)
    {
      size_t memUsage = (size_t)_memUsage;
      if (memUsage != _memUsage)
        memUsage = (size_t)0 - 1;
      props.memUseMax = memUsage;
      isMT = (numThreads > 1);
    }

    props.numThreads = numThreads;
  }
  #endif

  CSeqInStreamWrap inWrap;
  CSeqOutStreamWrap outWrap;
  CCompressProgressWrap progressWrap;

  inWrap.Init(seqInStream);
  outWrap.Init(outStream);
  progressWrap.Init(progress);

#if SUP7Z_USE_SHARED_INPUT
  CMyComPtr<ISunpackSharedInput> sharedInput;
  seqInStream->QueryInterface(IID_ISunpackSharedInput, (void **)&sharedInput);
  CSunpackSharedInput sharedInputBridge = {};
  if (sharedInput)
  {
    sharedInputBridge.ctx = sharedInput;
    sharedInputBridge.Borrow = SharedInput_Borrow;
    sharedInputBridge.Release = SharedInput_Release;
  }
#endif

  SRes res = XzDecMt_Decode(xz,
      &props,
      outSizeLimit, finishStream,
      &outWrap.vt,
      &inWrap.vt,
#if SUP7Z_USE_SHARED_INPUT
      sharedInput ? &sharedInputBridge : NULL,
#endif
      &Stat,
      &isMT,
      progress ? &progressWrap.vt : NULL);

  MainDecodeSRes = res;

  #ifndef Z7_ST
  // _tryMt = isMT;
  #endif

  RET_IF_WRAP_ERROR(outWrap.Res, res, SZ_ERROR_WRITE)
  RET_IF_WRAP_ERROR(progressWrap.Res, res, SZ_ERROR_PROGRESS)
  RET_IF_WRAP_ERROR_CONFIRMED(inWrap.Res, res, SZ_ERROR_READ)

  // return E_OUTOFMEMORY; // for debug check

  MainDecodeSRes_wasUsed = true;

  if (res == SZ_OK && finishStream)
  {
    /*
    if (inSize && *inSize != Stat.PhySize)
      res = SZ_ERROR_DATA;
    */
    if (outSizeLimit && *outSizeLimit != outWrap.Processed)
      res = SZ_ERROR_DATA;
  }

  return SResToHRESULT_Code(res);
}


Z7_COM7F_IMF(CComDecoder::Code(ISequentialInStream *inStream, ISequentialOutStream *outStream,
    const UInt64 * /* inSize */, const UInt64 *outSize, ICompressProgressInfo *progress))
{
  return Decode(inStream, outStream, outSize, _finishStream, progress);
}

Z7_COM7F_IMF(CComDecoder::SetFinishMode(UInt32 finishMode))
{
  _finishStream = (finishMode != 0);
  return S_OK;
}

Z7_COM7F_IMF(CComDecoder::GetInStreamProcessedSize(UInt64 *value))
{
  *value = Stat.InSize;
  return S_OK;
}

#ifndef Z7_ST

Z7_COM7F_IMF(CComDecoder::SetNumberOfThreads(UInt32 numThreads))
{
  _numThreads = numThreads;
  return S_OK;
}

Z7_COM7F_IMF(CComDecoder::SetMemLimit(UInt64 memUsage))
{
  _memUsage = memUsage;
  return S_OK;
}

#endif

}}
