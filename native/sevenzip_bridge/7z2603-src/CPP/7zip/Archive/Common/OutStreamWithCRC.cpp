// OutStreamWithCRC.cpp

#include "StdAfx.h"

#include "OutStreamWithCRC.h"

Z7_COM7F_IMF(COutStreamWithCRC::Write(const void *data, UInt32 size, UInt32 *processedSize))
{
  HRESULT result = S_OK;
  if (_stream)
    result = _stream->Write(data, size, &size);
  if (_calculate)
    _crc = CrcUpdate(_crc, data, size);
  _size += size;
  if (processedSize)
    *processedSize = size;
  return result;
}

#if SUP7Z_USE_SHARED_OUTPUT

void COutStreamWithCRC::SetStream(ISequentialOutStream *stream)
{
  ReleaseStream();
  _stream = stream;
  if (stream)
    stream->QueryInterface(IID_ISunpackSharedOutput, (void **)&_sharedOutput);
}

void COutStreamWithCRC::ReleaseStream()
{
  if (_leaseToken && _sharedOutput)
  {
    UInt32 ignored = 0;
    _sharedOutput->Commit(_leaseToken, 0, &ignored);
  }
  _leaseData = NULL;
  _leaseCapacity = 0;
  _leaseToken = 0;
  _sharedOutput.Release();
  _stream.Release();
}

Z7_COM7F_IMF(COutStreamWithCRC::Acquire(
    UInt32 desiredSize, Byte **data, UInt32 *capacity, UInt64 *token))
{
  if (data) *data = NULL;
  if (capacity) *capacity = 0;
  if (token) *token = 0;
  if (!_sharedOutput || _leaseToken)
    return S_FALSE;

  Byte *p = NULL;
  UInt32 cap = 0;
  UInt64 t = 0;
  const HRESULT res = _sharedOutput->Acquire(desiredSize, &p, &cap, &t);
  if (res != S_OK)
    return res;
  if (!p || cap == 0 || t == 0)
    return E_FAIL;

  _leaseData = p;
  _leaseCapacity = cap;
  _leaseToken = t;
  *data = p;
  *capacity = cap;
  *token = t;
  return S_OK;
}

Z7_COM7F_IMF(COutStreamWithCRC::Commit(
    UInt64 token, UInt32 size, UInt32 *processedSize))
{
  if (processedSize) *processedSize = 0;
  if (!_sharedOutput || token == 0 || token != _leaseToken ||
      !_leaseData || size > _leaseCapacity)
    return E_INVALIDARG;

  const UInt32 nextCrc = (_calculate && size)
      ? CrcUpdate(_crc, _leaseData, size)
      : _crc;

  UInt32 committed = 0;
  const HRESULT res = _sharedOutput->Commit(token, size, &committed);
  _leaseData = NULL;
  _leaseCapacity = 0;
  _leaseToken = 0;

  if (res == S_OK && committed != size)
    return E_FAIL;
  if (committed == size)
  {
    if (_calculate && size)
      _crc = nextCrc;
    _size += committed;
  }
  if (processedSize)
    *processedSize = committed;
  return res;
}

Z7_COM7F_IMF(COutStreamWithCRC::SubmitBorrowed(
    const Byte *data, UInt32 size, UInt32 *processedSize, UInt64 *token))
{
  if (processedSize) *processedSize = 0;
  if (token) *token = 0;
  if (!_sharedOutput || !data || size == 0 || _leaseToken)
    return S_FALSE;

  UInt32 accepted = 0;
  UInt64 t = 0;
  const HRESULT res = _sharedOutput->SubmitBorrowed(
      data, size, &accepted, &t);
  if (res != S_OK)
    return res;
  if (accepted == 0 || accepted > size || t == 0)
    return E_FAIL;

  if (_calculate)
    _crc = CrcUpdate(_crc, data, accepted);
  _size += accepted;
  *processedSize = accepted;
  *token = t;
  return S_OK;
}

Z7_COM7F_IMF(COutStreamWithCRC::WaitBorrowed(UInt64 token))
{
  if (!_sharedOutput)
    return E_NOINTERFACE;
  return _sharedOutput->WaitBorrowed(token);
}

#endif
