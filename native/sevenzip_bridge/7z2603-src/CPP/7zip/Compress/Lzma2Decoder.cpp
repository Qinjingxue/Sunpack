// Lzma2Decoder.cpp

#include "StdAfx.h"

// #include <stdio.h>

#include "../../../C/Alloc.h"
#include "../../../C/Lzma2Dec.h"
#include "internal/decoder_cpu_budget.h"
#include "internal/positioned_output.hpp"

#include <atomic>
#include <algorithm>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
// #include "../../../C/CpuTicks.h"

#include "../Common/StreamUtils.h"

#include "Lzma2Decoder.h"

namespace NCompress {
namespace NLzma2 {

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

namespace {

struct CPositionedLzma2Run
{
  UInt64 PackOffset = 0;
  UInt64 PackSize = 0;
  UInt64 OutOffset = 0;
  UInt64 OutSize = 0;
  bool Final = false;
};

static bool AddNoOverflow(UInt64 a, UInt64 b, UInt64 &sum)
{
  sum = a + b;
  return sum >= a;
}

static HRESULT ScanPositionedLzma2Runs(
    sunpack::sevenzip::RandomAccessReader &reader,
    UInt64 packedSize,
    UInt64 expectedOutSize,
    std::vector<CPositionedLzma2Run> &runs)
{
  runs.clear();
  if (packedSize == 0)
    return E_NOTIMPL;

  UInt64 pos = 0;
  UInt64 outPos = 0;
  UInt64 runPackStart = 0;
  UInt64 runOutStart = 0;
  bool haveRun = false;

  while (pos < packedSize)
  {
    Byte header[6] = {};
    const UInt32 ask = (UInt32)(std::min<UInt64>)(sizeof(header), packedSize - pos);
    UInt32 got = 0;
    const HRESULT readRes = reader.read_at(pos, header, ask, &got);
    if (readRes != S_OK || got == 0)
      return E_NOTIMPL;

    const Byte control = header[0];

    if (control == 0)
    {
      if (!haveRun)
      {
        if (expectedOutSize == 0 && pos + 1 == packedSize)
          return S_OK;
        return E_NOTIMPL;
      }

      CPositionedLzma2Run run;
      run.PackOffset = runPackStart;
      run.PackSize = pos + 1 - runPackStart;
      run.OutOffset = runOutStart;
      run.OutSize = outPos - runOutStart;
      run.Final = true;
      try
      {
        runs.push_back(run);
      }
      catch (...)
      {
        return E_OUTOFMEMORY;
      }

      pos++;
      if (pos != packedSize || outPos != expectedOutSize)
      {
        runs.clear();
        return E_NOTIMPL;
      }
      return S_OK;
    }

    bool resetDictionary = false;
    UInt64 headerSize = 0;
    UInt64 payloadSize = 0;
    UInt64 unpackSize = 0;

    if (control == 1 || control == 2)
    {
      if (got < 3)
        return E_NOTIMPL;
      resetDictionary = (control == 1);
      unpackSize = ((UInt64)header[1] << 8) | header[2];
      unpackSize++;
      headerSize = 3;
      payloadSize = unpackSize;
    }
    else if (control >= 0x80)
    {
      const bool hasProps = control >= 0xC0;
      const UInt32 need = hasProps ? 6 : 5;
      if (got < need)
        return E_NOTIMPL;

      resetDictionary = control >= 0xE0;
      unpackSize =
          ((UInt64)(control & 0x1F) << 16) |
          ((UInt64)header[1] << 8) |
          header[2];
      unpackSize++;

      payloadSize = ((UInt64)header[3] << 8) | header[4];
      payloadSize++;
      headerSize = need;
    }
    else
      return E_NOTIMPL;

    if (!haveRun)
    {
      if (!resetDictionary)
        return E_NOTIMPL;
      haveRun = true;
      runPackStart = pos;
      runOutStart = outPos;
    }
    else if (resetDictionary)
    {
      CPositionedLzma2Run run;
      run.PackOffset = runPackStart;
      run.PackSize = pos - runPackStart;
      run.OutOffset = runOutStart;
      run.OutSize = outPos - runOutStart;
      if (run.PackSize == 0)
        return E_NOTIMPL;
      try
      {
        runs.push_back(run);
      }
      catch (...)
      {
        return E_OUTOFMEMORY;
      }
      if (runs.size() > (1u << 20))
        return E_NOTIMPL;
      runPackStart = pos;
      runOutStart = outPos;
    }

    UInt64 chunkSize;
    if (!AddNoOverflow(headerSize, payloadSize, chunkSize) ||
        chunkSize > packedSize - pos)
      return E_NOTIMPL;

    UInt64 nextOut;
    if (!AddNoOverflow(outPos, unpackSize, nextOut) ||
        nextOut > expectedOutSize)
      return E_NOTIMPL;

    pos += chunkSize;
    outPos = nextOut;
  }

  runs.clear();
  return E_NOTIMPL;
}


struct CPositionedLzma2Worker
{
  CLzma2Dec Dec;
  Byte *Dict = NULL;
  size_t DictSize = 0;
  std::vector<Byte> Input;

  CPositionedLzma2Worker()
  {
    Lzma2Dec_CONSTRUCT(&Dec)
  }

  ~CPositionedLzma2Worker()
  {
    Lzma2Dec_FreeProbs(&Dec, &g_Alloc);
    MidFree(Dict);
    Dec.decoder.dic = NULL;
    Dec.decoder.dicBufSize = 0;
  }

  SRes Prepare(Byte prop, size_t inputSize)
  {
    RINOK(Lzma2Dec_AllocateProbs(&Dec, prop, &g_Alloc))

    const UInt32 dictSize = Dec.decoder.prop.dicSize;
    size_t mask = ((size_t)1 << 12) - 1;
    if (dictSize >= ((UInt32)1 << 30))
      mask = ((size_t)1 << 22) - 1;
    else if (dictSize >= ((UInt32)1 << 22))
      mask = ((size_t)1 << 20) - 1;

    const size_t rounded = ((size_t)dictSize + mask) & ~mask;
    if (rounded < dictSize || rounded == 0)
      return SZ_ERROR_MEM;

    Dict = (Byte *)MidAlloc(rounded);
    if (!Dict)
      return SZ_ERROR_MEM;
    DictSize = rounded;
    Dec.decoder.dic = Dict;
    Dec.decoder.dicBufSize = (SizeT)DictSize;

    try
    {
      Input.resize(inputSize);
    }
    catch (...)
    {
      return SZ_ERROR_MEM;
    }
    return SZ_OK;
  }
};


static HRESULT DecodePositionedLzma2Run(
    CPositionedLzma2Worker &worker,
    sunpack::sevenzip::RandomAccessReader &reader,
    const CPositionedLzma2Run &run,
    sunpack::sevenzip::PositionedOutStream &outStream,
    size_t outStep,
    std::atomic<bool> &stop,
    std::atomic<UInt64> &totalIn,
    std::atomic<UInt64> &totalOut,
    std::atomic<UInt64> &nextProgress,
    std::mutex &progressMutex,
    ICompressProgressInfo *progress)
{
  Lzma2Dec_Init(&worker.Dec);

  UInt64 readPos = run.PackOffset;
  UInt64 readRem = run.PackSize;
  UInt64 runOut = 0;
  size_t inPos = 0;
  size_t inLim = 0;
  bool finishedWithMark = false;

  if (outStep == 0)
    outStep = (size_t)1 << 20;

  for (;;)
  {
    if (stop.load(std::memory_order_acquire))
      return E_ABORT;

    if (runOut == run.OutSize && readRem == 0 && inPos == inLim)
    {
      if (run.Final && !finishedWithMark)
        return SResToHRESULT(SZ_ERROR_DATA);
      return S_OK;
    }

    if (inPos == inLim && readRem != 0)
    {
      const UInt32 ask = (UInt32)(std::min<UInt64>)(
          readRem, (UInt64)worker.Input.size());
      UInt32 got = 0;
      const HRESULT readRes =
          reader.read_at(readPos, worker.Input.data(), ask, &got);
      if (readRes != S_OK)
        return readRes;
      if (got == 0)
        return SResToHRESULT(SZ_ERROR_INPUT_EOF);
      readPos += got;
      readRem -= got;
      inPos = 0;
      inLim = got;
    }

    if (worker.Dec.decoder.dicPos == worker.Dec.decoder.dicBufSize)
      worker.Dec.decoder.dicPos = 0;

    const SizeT dicPos = worker.Dec.decoder.dicPos;
    const UInt64 remOut64 = run.OutSize - runOut;
    SizeT dicLimit = dicPos;

    if (remOut64 != 0)
    {
      SizeT step = worker.Dec.decoder.dicBufSize - dicPos;
      if (step > outStep)
        step = (SizeT)outStep;
      if ((UInt64)step > remOut64)
        step = (SizeT)remOut64;
      if (step == 0)
        return E_FAIL;
      dicLimit += step;
    }

    SizeT srcProcessed = (SizeT)(inLim - inPos);
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    const ELzmaFinishMode finishMode =
        ((UInt64)(dicLimit - dicPos) == remOut64)
          ? LZMA_FINISH_END
          : LZMA_FINISH_ANY;

    const SRes decodeRes = Lzma2Dec_DecodeToDic(
        &worker.Dec,
        dicLimit,
        worker.Input.data() + inPos,
        &srcProcessed,
        finishMode,
        &status);

    inPos += srcProcessed;
    if (srcProcessed != 0)
      totalIn.fetch_add(srcProcessed, std::memory_order_relaxed);

    const SizeT produced = worker.Dec.decoder.dicPos - dicPos;
    if (produced != 0)
    {
      UInt32 written = 0;
      const HRESULT writeRes = outStream.write_at(
          run.OutOffset + runOut,
          worker.Dec.decoder.dic + dicPos,
          (UInt32)produced,
          &written);
      if (writeRes != S_OK)
        return writeRes;
      if (written != produced)
        return E_FAIL;

      runOut += produced;
      const UInt64 outNow =
          totalOut.fetch_add(produced, std::memory_order_relaxed) + produced;

      if (progress)
      {
        UInt64 threshold = nextProgress.load(std::memory_order_relaxed);
        if (outNow >= threshold &&
            nextProgress.compare_exchange_strong(
                threshold,
                threshold + ((UInt64)16 << 20),
                std::memory_order_relaxed))
        {
          std::lock_guard<std::mutex> lock(progressMutex);
          const UInt64 inNow = totalIn.load(std::memory_order_relaxed);
          const UInt64 currentOut = totalOut.load(std::memory_order_relaxed);
          const HRESULT progressRes =
              progress->SetRatioInfo(&inNow, &currentOut);
          if (progressRes != S_OK)
            return progressRes;
        }
      }
    }

    if (status == LZMA_STATUS_FINISHED_WITH_MARK)
      finishedWithMark = true;

    if (decodeRes != SZ_OK)
      return SResToHRESULT(decodeRes);

    if (srcProcessed == 0 && produced == 0)
    {
      if (inPos == inLim && readRem != 0)
        continue;
      if (runOut < run.OutSize)
        return SResToHRESULT(SZ_ERROR_INPUT_EOF);
      if (run.Final && !finishedWithMark)
        return SResToHRESULT(SZ_ERROR_DATA);
      return (inPos == inLim && readRem == 0) ? S_OK : E_FAIL;
    }
  }
}


static HRESULT TryDecodePositionedLzma2Runs(
    ISequentialInStream *inStream,
    sunpack::sevenzip::PositionedOutStream *outStream,
    Byte prop,
    UInt32 requestedThreads,
    size_t inputBufferSize,
    size_t outStep,
    const UInt64 *inSize,
    const UInt64 *outSize,
    ICompressProgressInfo *progress,
    UInt64 &inProcessed,
    UInt64 &outProcessed,
    int &isMT)
{
  inProcessed = 0;
  outProcessed = 0;
  isMT = False;

  if (!inStream || !outStream || !inSize || !outSize ||
      !outStream->positioned_available())
    return E_NOTIMPL;

  sunpack::sevenzip::RandomAccessInStream *randomInput =
      sunpack::sevenzip::random_access_in_stream(inStream);
  if (!randomInput)
    return E_NOTIMPL;

  std::unique_ptr<sunpack::sevenzip::RandomAccessReader> scanner =
      randomInput->open_random_reader();
  if (!scanner)
    return E_NOTIMPL;

  std::vector<CPositionedLzma2Run> runs;
  const HRESULT scanRes =
      ScanPositionedLzma2Runs(*scanner, *inSize, *outSize, runs);
  if (scanRes != S_OK)
    return scanRes;
  if (runs.empty() && *outSize != 0)
    return E_NOTIMPL;

  unsigned desiredThreads =
      (unsigned)(std::min<size_t>)(
          runs.empty() ? 1 : runs.size(),
          requestedThreads ? requestedThreads : 1);
  if (desiredThreads == 0)
    desiredThreads = 1;

  void *cpuContext = NULL;
  unsigned extraCredits = 0;
  #ifndef Z7_ST
  cpuContext = sunpack_cpu_current_job_context();
  if (cpuContext && desiredThreads > 1)
  {
    extraCredits = sunpack_cpu_acquire_extra_for_context(
        cpuContext, desiredThreads - 1, 1);
    desiredThreads = 1 + extraCredits;
  }
  #else
  desiredThreads = 1;
  #endif

  const size_t inBuffer =
      (std::max<size_t>)(inputBufferSize, (size_t)1 << 16);

  std::vector<std::unique_ptr<CPositionedLzma2Worker>> workers;
  try
  {
    workers.reserve(desiredThreads);
    for (unsigned i = 0; i < desiredThreads; ++i)
    {
      auto worker = std::make_unique<CPositionedLzma2Worker>();
      const SRes prep = worker->Prepare(prop, inBuffer);
      if (prep != SZ_OK)
      {
        #ifndef Z7_ST
        if (cpuContext && extraCredits)
          sunpack_cpu_release_extra_for_context(cpuContext, extraCredits);
        #endif
        return SResToHRESULT(prep);
      }
      workers.push_back(std::move(worker));
    }
  }
  catch (...)
  {
    #ifndef Z7_ST
    if (cpuContext && extraCredits)
      sunpack_cpu_release_extra_for_context(cpuContext, extraCredits);
    #endif
    return E_OUTOFMEMORY;
  }

  std::atomic<size_t> nextRun(0);
  std::atomic<bool> stop(false);
  std::atomic<UInt64> totalIn(0);
  std::atomic<UInt64> totalOut(0);
  std::atomic<UInt64> nextProgress((UInt64)16 << 20);
  std::mutex resultMutex;
  std::mutex progressMutex;
  HRESULT firstError = S_OK;

  auto publishError = [&](HRESULT error)
  {
    if (error == S_OK)
      return;
    std::lock_guard<std::mutex> lock(resultMutex);
    if (firstError == S_OK)
    {
      firstError = error;
      stop.store(true, std::memory_order_release);
    }
  };

  auto runWorker = [&](unsigned workerIndex)
  {
    void *previousContext = NULL;
    #ifndef Z7_ST
    if (cpuContext)
      previousContext = sunpack_cpu_exchange_current_job_context(cpuContext);
    #endif

    std::unique_ptr<sunpack::sevenzip::RandomAccessReader> reader =
        randomInput->open_random_reader();
    if (!reader)
      publishError(E_FAIL);
    else
    {
      for (;;)
      {
        if (stop.load(std::memory_order_acquire))
          break;
        const size_t runIndex =
            nextRun.fetch_add(1, std::memory_order_relaxed);
        if (runIndex >= runs.size())
          break;

        const HRESULT hres = DecodePositionedLzma2Run(
            *workers[workerIndex],
            *reader,
            runs[runIndex],
            *outStream,
            outStep,
            stop,
            totalIn,
            totalOut,
            nextProgress,
            progressMutex,
            progress);
        if (hres != S_OK)
        {
          publishError(hres);
          break;
        }
      }
    }

    #ifndef Z7_ST
    if (cpuContext)
      sunpack_cpu_exchange_current_job_context(previousContext);
    #endif
  };

  std::vector<std::thread> threads;
  try
  {
    threads.reserve(desiredThreads > 0 ? desiredThreads - 1 : 0);
    for (unsigned i = 1; i < desiredThreads; ++i)
      threads.emplace_back(runWorker, i);

    runWorker(0);

    for (auto &thread : threads)
      thread.join();
  }
  catch (...)
  {
    stop.store(true, std::memory_order_release);
    for (auto &thread : threads)
      if (thread.joinable())
        thread.join();
    publishError(E_OUTOFMEMORY);
  }

  #ifndef Z7_ST
  if (cpuContext && extraCredits)
    sunpack_cpu_release_extra_for_context(cpuContext, extraCredits);
  #endif

  {
    std::lock_guard<std::mutex> lock(resultMutex);
    if (firstError != S_OK)
      return firstError;
  }

  inProcessed = totalIn.load(std::memory_order_relaxed);
  outProcessed = totalOut.load(std::memory_order_relaxed);
  isMT = desiredThreads > 1 ? True : False;

  if (inProcessed != *inSize || outProcessed != *outSize)
    return SResToHRESULT(SZ_ERROR_DATA);

  if (progress)
  {
    const HRESULT progressRes =
        progress->SetRatioInfo(&inProcessed, &outProcessed);
    if (progressRes != S_OK)
      return progressRes;
  }

  return S_OK;
}

} // namespace

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

  inWrap.Init(inStream);
  outWrap.Init(outStream);
  progressWrap.Init(progress);

  sunpack::sevenzip::PositionedOutStream *positionedOut =
      sunpack::sevenzip::positioned_out_stream(outStream);
  if (positionedOut && !positionedOut->positioned_available())
    positionedOut = NULL;

  /*
    Preferred SunPack path: discover LZMA2 dictionary-reset runs by reading
    only their headers, then let each lane read its own packed range. This
    avoids both legacy full decoded-run buffers and MtDec's compressed-run
    staging lists. Nothing is committed until the complete run plan has been
    validated against the coder's packed/unpacked sizes.
  */
  if (positionedOut && inSize && outSize && _finishMode)
  {
    UInt64 directIn = 0;
    UInt64 directOut = 0;
    int directIsMT = False;
    UInt32 directThreads = 1;
    #ifndef Z7_ST
    directThreads = props.numThreads;
    #endif

    const HRESULT directRes = TryDecodePositionedLzma2Runs(
        inStream,
        positionedOut,
        _prop,
        directThreads,
        _inBufSize,
        _outStep,
        inSize,
        outSize,
        progress,
        directIn,
        directOut,
        directIsMT);

    if (directRes != E_NOTIMPL)
    {
      _inProcessed = directIn;
      return directRes;
    }
  }

  SRes res;

  UInt64 inProcessed = 0;
  int isMT = False;

  #ifndef Z7_ST
  isMT = sunpack_cpu_current_job_context() ? True : _tryMt;
  #endif

  // UInt64 cpuTicks = GetCpuTicks();

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
  RET_IF_WRAP_ERROR_CONFIRMED(inWrap.Res, res, SZ_ERROR_READ)

  if (res == SZ_OK && _finishMode)
  {
    if (inSize && *inSize != inProcessed)
      res = SZ_ERROR_DATA;
    if (outSize && *outSize != outWrap.Processed)
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
