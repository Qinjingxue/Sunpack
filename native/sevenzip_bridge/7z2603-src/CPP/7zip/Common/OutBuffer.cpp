// OutBuffer.cpp

#include "StdAfx.h"

#include "../../../C/Alloc.h"

#include "OutBuffer.h"

bool COutBuffer::Create(UInt32 bufSize) throw()
{
  const UInt32 kMinBlockSize = 1;
  if (bufSize < kMinBlockSize)
    bufSize = kMinBlockSize;
  if (_buf && _bufSize == bufSize)
    return true;
  Free();
  _bufSize = bufSize;
  _buf = (Byte *)::MidAlloc(bufSize);
  return (_buf != NULL);
}

void COutBuffer::Free() throw()
{
#if SUP7Z_USE_SHARED_OUTPUT
  _outputLeases.Drain();
#endif
  ::MidFree(_buf);
  _buf = NULL;
}

void COutBuffer::Init() throw()
{
#if SUP7Z_USE_SHARED_OUTPUT
  _outputLeases.Drain();
#endif
  _streamPos = 0;
#if SUP7Z_USE_SHARED_OUTPUT
  _limitPos = (_sharedOutput && _sharedChunkSize && _sharedChunkSize < _bufSize)
      ? _sharedChunkSize : _bufSize;
#else
  _limitPos = _bufSize;
#endif
  _pos = 0;
  _processedSize = 0;
  _overDict = false;
  #ifdef Z7_NO_EXCEPTIONS
  ErrorCode = S_OK;
  #endif
}

#if SUP7Z_USE_SHARED_OUTPUT
void COutBuffer::SetStream(ISequentialOutStream *stream)
{
  if (_stream == stream)
    return;
  _outputLeases.Drain();
  _sharedOutput.Release();
  _stream = stream;
  if (stream)
    stream->QueryInterface(IID_ISunpackSharedOutput, (void **)&_sharedOutput);
}
#endif

UInt64 COutBuffer::GetProcessedSize() const throw()
{
  UInt64 res = _processedSize + _pos - _streamPos;
  if (_streamPos > _pos)
    res += _bufSize;
  return res;
}


HRESULT COutBuffer::FlushPart() throw()
{
  // _streamPos < _bufSize
  UInt32 size = (_streamPos >= _pos) ? (_bufSize - _streamPos) : (_pos - _streamPos);
  HRESULT result = S_OK;
  #ifdef Z7_NO_EXCEPTIONS
  result = ErrorCode;
  #endif
  if (_buf2)
  {
    memcpy(_buf2, _buf + _streamPos, size);
    _buf2 += size;
  }

  if (_stream
      #ifdef Z7_NO_EXCEPTIONS
      && (ErrorCode == S_OK)
      #endif
     )
  {
#if SUP7Z_USE_SHARED_OUTPUT
    if (_sharedOutput && _sharedChunkSize && !_buf2 && size != 0)
    {
      const Byte *data = _buf + _streamPos;
      UInt32 remain = size;
      UInt32 total = 0;
      while (remain != 0)
      {
        UInt32 accepted = 0;
        UInt64 token = 0;
        HRESULT submitRes = S_FALSE;
        for (;;)
        {
          submitRes = _sharedOutput->SubmitBorrowed(
              data, remain, &accepted, &token);
          if (submitRes != S_FALSE || _outputLeases.Empty())
            break;
          const HRESULT retireRes = _outputLeases.RetireOne();
          if (retireRes != S_OK)
          {
            result = retireRes;
            break;
          }
          accepted = 0;
          token = 0;
        }

        if (result != S_OK)
          break;

        if (submitRes == S_FALSE)
        {
          UInt32 processed = 0;
          result = _stream->Write(data, remain, &processed);
          total += processed;
          remain -= processed;
          data += processed;
          if (result != S_OK || processed == 0)
            break;
          continue;
        }

        if (submitRes != S_OK)
        {
          result = submitRes;
          break;
        }
        if (accepted == 0 || accepted > remain || token == 0)
        {
          result = E_FAIL;
          break;
        }

        result = _outputLeases.Push(token);
        if (result != S_OK)
          break;
        total += accepted;
        remain -= accepted;
        data += accepted;
      }
      size = total;
    }
    else
#endif
    {
      UInt32 processedSize = 0;
      result = _stream->Write(_buf + _streamPos, size, &processedSize);
      size = processedSize;
    }
  }

  _streamPos += size;
  if (_streamPos == _bufSize)
    _streamPos = 0;

  if (_pos == _bufSize)
  {
#if SUP7Z_USE_SHARED_OUTPUT
    if (_sharedOutput && _sharedChunkSize)
    {
      const HRESULT drainRes = _outputLeases.Drain();
      if (result == S_OK)
        result = drainRes;
      if (result != S_OK)
        return result;
    }
#endif
    _overDict = true;
    _pos = 0;
  }

#if SUP7Z_USE_SHARED_OUTPUT
  if (_sharedOutput && _sharedChunkSize && _streamPos == _pos)
  {
    UInt32 next = _pos + _sharedChunkSize;
    if (next < _pos || next > _bufSize)
      next = _bufSize;
    _limitPos = next;
  }
  else
#endif
    _limitPos = (_streamPos > _pos) ? _streamPos : _bufSize;

  _processedSize += size;
  return result;
}

HRESULT COutBuffer::Flush() throw()
{
  #ifdef Z7_NO_EXCEPTIONS
  if (ErrorCode != S_OK)
    return ErrorCode;
  #endif

  while (_streamPos != _pos)
  {
    const HRESULT result = FlushPart();
    if (result != S_OK)
      return result;
  }
  return S_OK;
}

void COutBuffer::FlushWithCheck()
{
  const HRESULT result = Flush();
  #ifdef Z7_NO_EXCEPTIONS
  ErrorCode = result;
  #else
  if (result != S_OK)
    throw COutBufferException(result);
  #endif
}
