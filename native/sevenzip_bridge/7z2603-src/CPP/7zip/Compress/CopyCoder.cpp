// Compress/CopyCoder.cpp

#include "StdAfx.h"

#include "../../../C/Alloc.h"
#if SUP7Z_USE_SHARED_INPUT
#include "../Common/SunpackSharedInput.h"
#endif
#if SUP7Z_USE_SHARED_OUTPUT
#include "../Common/SunpackSharedOutput.h"
#endif

#include "CopyCoder.h"

namespace NCompress {

static const UInt32 kBufSize = 1 << 17;

CCopyCoder::~CCopyCoder()
{
  ::MidFree(_buf);
}

Z7_COM7F_IMF(CCopyCoder::SetFinishMode(UInt32 /* finishMode */))
{
  return S_OK;
}

Z7_COM7F_IMF(CCopyCoder::Code(ISequentialInStream *inStream,
    ISequentialOutStream *outStream,
    const UInt64 * /* inSize */, const UInt64 *outSize,
    ICompressProgressInfo *progress))
{
#if SUP7Z_USE_SHARED_INPUT
  CMyComPtr<ISunpackSharedInput> sharedInput;
  inStream->QueryInterface(IID_ISunpackSharedInput, (void **)&sharedInput);

  struct CLeaseGuard
  {
    ISunpackSharedInput *Source;
    UInt64 Token;
    CLeaseGuard(): Source(NULL), Token(0) {}
    ~CLeaseGuard()
    {
      if (Source && Token)
        Source->ReleaseBorrowed(Token);
    }
  };
#else
  if (!_buf)
  {
    _buf = (Byte *)::MidAlloc(kBufSize);
    if (!_buf)
      return E_OUTOFMEMORY;
  }
#endif

  TotalSize = 0;

#if SUP7Z_USE_SHARED_OUTPUT
  CMyComPtr<ISunpackSharedOutput> sharedOutput;
  if (outStream)
    outStream->QueryInterface(IID_ISunpackSharedOutput, (void **)&sharedOutput);

#if SUP7Z_USE_SHARED_INPUT
  if (sharedInput && sharedOutput)
  {
    struct CTransitLeaseRing
    {
      struct CPair { UInt64 Input; UInt64 Output; };
      ISunpackSharedInput *In;
      ISunpackSharedOutput *Out;
      CPair Leases[16];
      unsigned Head;
      unsigned Count;

      CTransitLeaseRing(ISunpackSharedInput *in, ISunpackSharedOutput *out):
          In(in), Out(out), Head(0), Count(0) {}

      ~CTransitLeaseRing() { Drain(); }

      bool Empty() const { return Count == 0; }

      HRESULT RetireOne()
      {
        if (Count == 0)
          return S_OK;
        const CPair pair = Leases[Head];
        const HRESULT waitRes = Out->WaitBorrowed(pair.Output);
        const HRESULT releaseRes = In->ReleaseBorrowed(pair.Input);
        Head = (Head + 1) & 15;
        --Count;
        return waitRes != S_OK ? waitRes : releaseRes;
      }

      HRESULT Push(UInt64 inputToken, UInt64 outputToken)
      {
        HRESULT res = S_OK;
        if (Count == 16)
          res = RetireOne();
        const unsigned tail = (Head + Count) & 15;
        Leases[tail].Input = inputToken;
        Leases[tail].Output = outputToken;
        ++Count;
        return res;
      }

      HRESULT Drain()
      {
        HRESULT first = S_OK;
        while (Count != 0)
        {
          const HRESULT res = RetireOne();
          if (first == S_OK && res != S_OK)
            first = res;
        }
        return first;
      }
    } transit(sharedInput.Interface(), sharedOutput.Interface());

    const auto finishTransit = [&](HRESULT result) -> HRESULT
    {
      const HRESULT drainRes = transit.Drain();
      return result == S_OK ? drainRes : result;
    };

    for (;;)
    {
      // Shared input can hand us the full prefetch slot (typically 512 KiB);
      // don't artificially chop it to CopyCoder's legacy 128 KiB buffer size.
      UInt32 request = 1u << 20;
      if (outSize)
      {
        const UInt64 rem = *outSize - TotalSize;
        if (request > rem)
          request = (UInt32)rem;
        if (request == 0)
          return finishTransit(S_OK);
      }

      const Byte *borrowed = NULL;
      UInt32 borrowedSize = 0;
      UInt64 inputToken = 0;
      HRESULT borrowRes = S_FALSE;

      for (;;)
      {
        borrowRes = sharedInput->Borrow(
            request, &borrowed, &borrowedSize, &inputToken);
        if (borrowRes != S_FALSE || transit.Empty())
          break;
        const HRESULT retireRes = transit.RetireOne();
        if (retireRes != S_OK)
          return finishTransit(retireRes);
      }

      if (borrowRes == S_FALSE)
      {
        const HRESULT drainRes = transit.Drain();
        if (drainRes != S_OK)
          return drainRes;
        break; // continue below with the writer-owned buffer path
      }
      if (borrowRes != S_OK)
        return finishTransit(borrowRes);
      if (!borrowed || borrowedSize == 0 || borrowedSize > request || inputToken == 0)
      {
        if (inputToken)
          sharedInput->ReleaseBorrowed(inputToken);
        return finishTransit(E_FAIL);
      }

      UInt32 accepted = 0;
      UInt64 outputToken = 0;
      HRESULT submitRes = S_FALSE;
      for (;;)
      {
        submitRes = sharedOutput->SubmitBorrowed(
            borrowed, borrowedSize, &accepted, &outputToken);
        if (submitRes != S_FALSE || transit.Empty())
          break;
        const HRESULT retireRes = transit.RetireOne();
        if (retireRes != S_OK)
        {
          sharedInput->ReleaseBorrowed(inputToken);
          return finishTransit(retireRes);
        }
        accepted = 0;
        outputToken = 0;
      }

      if (submitRes == S_FALSE)
      {
        const HRESULT writeRes = WriteStream(outStream, borrowed, borrowedSize);
        const HRESULT releaseRes = sharedInput->ReleaseBorrowed(inputToken);
        if (writeRes != S_OK)
          return finishTransit(writeRes);
        if (releaseRes != S_OK)
          return finishTransit(releaseRes);
      }
      else
      {
        if (submitRes != S_OK)
        {
          sharedInput->ReleaseBorrowed(inputToken);
          return finishTransit(submitRes);
        }
        if (accepted == 0 || accepted > borrowedSize || outputToken == 0)
        {
          if (outputToken)
            sharedOutput->WaitBorrowed(outputToken);
          sharedInput->ReleaseBorrowed(inputToken);
          return finishTransit(E_FAIL);
        }

        // A solid folder boundary can shorten one borrowed output span. The
        // remainder is copied only on that cold boundary; the common path is
        // input-prefetch memory -> async WriteFile with no intermediate memcpy.
        if (accepted != borrowedSize)
        {
          const HRESULT writeRes = WriteStream(
              outStream, borrowed + accepted, borrowedSize - accepted);
          if (writeRes != S_OK)
          {
            sharedOutput->WaitBorrowed(outputToken);
            sharedInput->ReleaseBorrowed(inputToken);
            return finishTransit(writeRes);
          }
        }

        const HRESULT pushRes = transit.Push(inputToken, outputToken);
        if (pushRes != S_OK)
          return finishTransit(pushRes);
      }

      TotalSize += borrowedSize;
      if (outSize && TotalSize == *outSize)
        return finishTransit(S_OK);

      if (progress && (TotalSize & (((UInt32)1 << 22) - 1)) == 0)
        RINOK(progress->SetRatioInfo(&TotalSize, &TotalSize))
    }
  }
#endif

  if (sharedOutput)
  {
    const UInt32 kSharedOutputSize = 1u << 20;
    for (;;)
    {
      UInt32 request = kSharedOutputSize;
      if (outSize)
      {
        const UInt64 rem = *outSize - TotalSize;
        if (request > rem)
          request = (UInt32)rem;
        if (request == 0)
          return S_OK;
      }

      Byte *dest = NULL;
      UInt32 capacity = 0;
      UInt64 token = 0;
      const HRESULT acquireRes = sharedOutput->Acquire(
          request, &dest, &capacity, &token);

      if (acquireRes == S_OK)
      {
        if (!dest || capacity == 0 || capacity > request || token == 0)
          return E_FAIL;

        UInt32 filled = 0;
        HRESULT readRes = S_OK;
        while (filled < capacity)
        {
          UInt32 cur = capacity - filled;
          if (cur > kBufSize)
            cur = kBufSize;
          UInt32 processed = 0;
          readRes = inStream->Read(dest + filled, cur, &processed);
          if (processed > cur)
          {
            UInt32 ignored = 0;
            sharedOutput->Commit(token, 0, &ignored);
            return E_FAIL;
          }
          filled += processed;
          if (readRes != S_OK || processed == 0)
            break;
        }

        UInt32 committed = 0;
        const HRESULT writeRes = sharedOutput->Commit(
            token, filled, &committed);
        if (writeRes != S_OK)
          return writeRes;
        if (committed != filled)
          return E_FAIL;
        TotalSize += committed;

        RINOK(readRes)
        if (filled == 0 || filled < capacity)
          return S_OK;
      }
      else if (acquireRes == S_FALSE)
      {
        // A folder stream can temporarily have no real output stream for a
        // skipped member. Keep the exact legacy behavior for that member and
        // retry the shared capability on the next chunk/file.
        if (!_buf)
        {
          _buf = (Byte *)::MidAlloc(kBufSize);
          if (!_buf)
            return E_OUTOFMEMORY;
        }

        UInt32 cur = request < kBufSize ? request : kBufSize;
        UInt32 processed = 0;
        const HRESULT readRes = inStream->Read(_buf, cur, &processed);
        if (processed > cur)
          return E_FAIL;
        if (processed != 0)
        {
          RINOK(WriteStream(outStream, _buf, processed))
          TotalSize += processed;
        }
        RINOK(readRes)
        if (processed == 0 || processed < cur)
          return S_OK;
      }
      else
        return acquireRes;

      if (outSize && TotalSize == *outSize)
        return S_OK;

      if (progress && (TotalSize & (((UInt32)1 << 22) - 1)) == 0)
        RINOK(progress->SetRatioInfo(&TotalSize, &TotalSize))
    }
  }
#endif
  
  for (;;)
  {
    UInt32 request = kBufSize;
    if (outSize)
    {
      const UInt64 rem = *outSize - TotalSize;
      if (request > rem)
      {
        request = (UInt32)rem;
        if (request == 0)
          return S_OK;
      }
    }

    HRESULT readRes = S_OK;
    UInt32 size = 0;
    const Byte *source = NULL;
#if SUP7Z_USE_SHARED_INPUT
    bool borrowedInput = false;
    CLeaseGuard lease;

    if (sharedInput)
    {
      UInt64 token = 0;
      const Byte *borrowed = NULL;
      UInt32 borrowedSize = 0;
      const HRESULT borrowRes = sharedInput->Borrow(request, &borrowed, &borrowedSize, &token);
      if (borrowRes == S_OK)
      {
        if (!borrowed || borrowedSize == 0 || borrowedSize > request || token == 0)
        {
          if (token)
            sharedInput->ReleaseBorrowed(token);
          return E_FAIL;
        }
        lease.Source = sharedInput;
        lease.Token = token;
        source = borrowed;
        size = borrowedSize;
        borrowedInput = true;
      }
      else if (borrowRes != S_FALSE)
        return borrowRes;
    }

    if (!borrowedInput)
    {
      if (!_buf)
      {
        _buf = (Byte *)::MidAlloc(kBufSize);
        if (!_buf)
          return E_OUTOFMEMORY;
      }
#endif
      {
        UInt32 pos = 0;
        do
        {
          const UInt32 curSize = request - pos;
          UInt32 processed = 0;
          readRes = inStream->Read(_buf + pos, curSize, &processed);
          if (processed > curSize)
            return E_FAIL;
          pos += processed;
          if (readRes != S_OK || processed == 0)
            break;
        }
        while (pos < request);
        size = pos;
        source = _buf;
      }
#if SUP7Z_USE_SHARED_INPUT
    }
#endif

    if (size == 0)
      return readRes;

    if (outStream)
    {
      UInt32 pos = 0;
      do
      {
        const UInt32 curSize = size - pos;
        UInt32 processed = 0;
        const HRESULT res = outStream->Write(source + pos, curSize, &processed);
        if (processed > curSize)
          return E_FAIL;
        pos += processed;
        TotalSize += processed;
        RINOK(res)
        if (processed == 0)
          return E_FAIL;
      }
      while (pos < size);
    }
    else
      TotalSize += size;

    RINOK(readRes)

    if (outSize && TotalSize == *outSize)
      return S_OK;

#if SUP7Z_USE_SHARED_INPUT
    if (!borrowedInput && size != request)
      return S_OK;
#else
    if (size != kBufSize)
      return S_OK;
#endif

    if (progress && (TotalSize & (((UInt32)1 << 22) - 1)) == 0)
    {
      RINOK(progress->SetRatioInfo(&TotalSize, &TotalSize))
    }
  }
}

Z7_COM7F_IMF(CCopyCoder::SetInStream(ISequentialInStream *inStream))
{
  _inStream = inStream;
  TotalSize = 0;
  return S_OK;
}

Z7_COM7F_IMF(CCopyCoder::ReleaseInStream())
{
  _inStream.Release();
  return S_OK;
}

Z7_COM7F_IMF(CCopyCoder::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  UInt32 realProcessedSize = 0;
  HRESULT res = _inStream->Read(data, size, &realProcessedSize);
  TotalSize += realProcessedSize;
  if (processedSize)
    *processedSize = realProcessedSize;
  return res;
}

Z7_COM7F_IMF(CCopyCoder::GetInStreamProcessedSize(UInt64 *value))
{
  *value = TotalSize;
  return S_OK;
}

HRESULT CopyStream(ISequentialInStream *inStream, ISequentialOutStream *outStream, ICompressProgressInfo *progress)
{
  CMyComPtr<ICompressCoder> copyCoder = new CCopyCoder;
  return copyCoder->Code(inStream, outStream, NULL, NULL, progress);
}

HRESULT CopyStream_ExactSize(ISequentialInStream *inStream, ISequentialOutStream *outStream, UInt64 size, ICompressProgressInfo *progress)
{
  NCompress::CCopyCoder *copyCoderSpec = new NCompress::CCopyCoder;
  CMyComPtr<ICompressCoder> copyCoder = copyCoderSpec;
  RINOK(copyCoder->Code(inStream, outStream, NULL, &size, progress))
  return copyCoderSpec->TotalSize == size ? S_OK : E_FAIL;
}

}
