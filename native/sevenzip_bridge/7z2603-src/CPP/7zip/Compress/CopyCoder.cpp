// Compress/CopyCoder.cpp

#include "StdAfx.h"

#include "../../../C/Alloc.h"
#if SUP7Z_USE_SHARED_INPUT
#include "../Common/SunpackSharedInput.h"
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
