// Lzma2Decoder.cpp

#include "StdAfx.h"

// #include <stdio.h>

#include "../../../C/Alloc.h"
#include "internal/decoder_cpu_budget.h"
#include "internal/positioned_output.hpp"

#include <atomic>
// #include "../../../C/CpuTicks.h"

#include "../Common/StreamUtils.h"

#include "Lzma2Decoder.h"

namespace NCompress {
namespace NLzma2 {

namespace {

struct CPositionedOutWrap
{
  ISunpackPositionedOutStream vt;
  sunpack::sevenzip::PositionedOutStream *stream;
  std::atomic<HRESULT> res;
  std::atomic<UInt64> processed;

  static size_t WriteAt(void *context, UInt64 offset, const void *data, size_t size)
  {
    CPositionedOutWrap *p = static_cast<CPositionedOutWrap *>(context);
    if (!p || !p->stream)
      return 0;
    if (p->res.load(std::memory_order_acquire) != S_OK)
      return 0;

    const Byte *src = static_cast<const Byte *>(data);
    size_t total = 0;
    while (total < size)
    {
      const size_t rem = size - total;
      const UInt32 chunk =
          rem > (size_t)0xFFFFFFFF ? 0xFFFFFFFFu : (UInt32)rem;
      UInt32 written = 0;
      const HRESULT hres = p->stream->write_at(
          offset + total, src + total, chunk, &written);
      total += written;
      if (hres != S_OK || written != chunk)
      {
        HRESULT expected = S_OK;
        const HRESULT error = hres != S_OK ? hres : E_FAIL;
        p->res.compare_exchange_strong(
            expected, error,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
        break;
      }
    }

    p->processed.fetch_add(total, std::memory_order_relaxed);
    return total;
  }

  void Init(sunpack::sevenzip::PositionedOutStream *value)
  {
    stream = value;
    res.store(S_OK, std::memory_order_relaxed);
    processed.store(0, std::memory_order_relaxed);
    vt.context = this;
    vt.WriteAt = WriteAt;
  }
};

} // namespace

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
    const bool creditManaged =
        sunpack_cpu_current_job_context() != NULL;
    UInt32 numThreads =
        creditManaged ? SUNPACK_CPU_MANAGED_THREAD_HINT : _numThreads;

    if (creditManaged || (_tryMt && numThreads >= 1))
    {
      const UInt32 dictSize = LZMA2_DIC_SIZE_FROM_PROP_FULL(_prop);
      const UInt64 expectedBlockSize64 = Get_ExpectedBlockSize_From_Dict(dictSize);
      const size_t expectedBlockSize = (size_t)expectedBlockSize64;
      const size_t inBlockMax = expectedBlockSize + expectedBlockSize / 16;
      if (expectedBlockSize == expectedBlockSize64 && inBlockMax >= expectedBlockSize)
      {
        props.outBlockMax = expectedBlockSize;
        props.inBlockMax = inBlockMax;

        if (!creditManaged)
        {
          const UInt64 useLimit = _memUsage;
          const size_t kOverheadSize = props.inBufSize_MT + (1 << 16);
          const UInt64 okThreads =
              useLimit / (props.outBlockMax + props.inBlockMax + kOverheadSize);
          if (numThreads > okThreads)
            numThreads = (UInt32)okThreads;
          if (numThreads == 0)
            numThreads = 1;
        }

        props.numThreads = numThreads;
      }
    }
  }
  #endif

  CSeqInStreamWrap inWrap;
  CSeqOutStreamWrap outWrap;
  CCompressProgressWrap progressWrap;
  CPositionedOutWrap positionedWrap;

  inWrap.Init(inStream);
  outWrap.Init(outStream);
  progressWrap.Init(progress);

  sunpack::sevenzip::PositionedOutStream *positionedOut =
      sunpack::sevenzip::positioned_out_stream(outStream);
  positionedWrap.Init(positionedOut);

  SRes res;

  UInt64 inProcessed = 0;
  int isMT = False;

  #ifndef Z7_ST
  isMT = sunpack_cpu_current_job_context() ? True : _tryMt;
  #endif

  // UInt64 cpuTicks = GetCpuTicks();

  if (positionedOut && props.numThreads > 1)
    res = Lzma2DecMt_DecodePositioned(_dec, _prop, &props,
        &outWrap.vt, &positionedWrap.vt,
        outSize, _finishMode,
        &inWrap.vt,
        &inProcessed,
        &isMT,
        progress ? &progressWrap.vt : NULL);
  else
    res = Lzma2DecMt_Decode(_dec, _prop, &props,
        &outWrap.vt, outSize, _finishMode,
        &inWrap.vt,
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
  {
    const HRESULT positionedRes =
        positionedWrap.res.load(std::memory_order_acquire);
    if (positionedRes != S_OK)
      return positionedRes;
  }
  RET_IF_WRAP_ERROR_CONFIRMED(inWrap.Res, res, SZ_ERROR_READ)

  if (res == SZ_OK && _finishMode)
  {
    if (inSize && *inSize != inProcessed)
      res = SZ_ERROR_DATA;
    if (outSize)
    {
      const UInt64 written =
          positionedOut && isMT ?
              positionedWrap.processed.load(std::memory_order_relaxed) :
              outWrap.Processed;
      if (*outSize != written)
        res = SZ_ERROR_DATA;
    }
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

  const SRes res = Lzma2DecMt_Init(_dec, _prop, &props, outSize, _finishMode, &_inWrap.vt);

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
