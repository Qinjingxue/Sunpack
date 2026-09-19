// 7zExtract.cpp

#include "StdAfx.h"

#include "../../../../C/7zCrc.h"

#include "../../../Common/ComTry.h"

#include "../../Common/ProgressUtils.h"
#if SUP7Z_USE_SHARED_OUTPUT
#include "../../Common/SunpackSharedOutput.h"
#endif

#include "7zDecode.h"
#include "7zHandler.h"

// EXTERN_g_ExternalCodecs

namespace NArchive {
namespace N7z {

#if SUP7Z_USE_SHARED_OUTPUT
Z7_CLASS_IMP_COM_2(
  CFolderOutStream
  , ISequentialOutStream
  , ISunpackSharedOutput
)
#else
Z7_CLASS_IMP_COM_1(
  CFolderOutStream
  , ISequentialOutStream
)
#endif
  CMyComPtr<ISequentialOutStream> _stream;
#if SUP7Z_USE_SHARED_OUTPUT
  CMyComPtr<ISunpackSharedOutput> _sharedOutput;
  const Byte *_sharedLeaseData;
  UInt32 _sharedLeaseCapacity;
  UInt64 _sharedLeaseToken;
#endif
public:
  bool TestMode;
  bool CheckCrc;
private:
  bool _fileIsOpen;
  bool _calcCrc;
  UInt32 _crc;
  UInt64 _rem;

  const UInt32 *_indexes;
  // unsigned _startIndex;
  unsigned _numFiles;
  unsigned _fileIndex;

  HRESULT OpenFile(bool isCorrupted = false);
  HRESULT CloseFile_and_SetResult(Int32 res);
  HRESULT CloseFile();
  HRESULT ProcessEmptyFiles();

public:
  const CDbEx *_db;
  CMyComPtr<IArchiveExtractCallback> ExtractCallback;

  bool ExtraWriteWasCut;

  CFolderOutStream():
      TestMode(false),
      CheckCrc(true)
#if SUP7Z_USE_SHARED_OUTPUT
      , _sharedLeaseData(NULL)
      , _sharedLeaseCapacity(0)
      , _sharedLeaseToken(0)
#endif
      {}

  HRESULT Init(unsigned startIndex, const UInt32 *indexes, unsigned numFiles);
  HRESULT FlushCorrupted(Int32 callbackOperationResult);

  bool WasWritingFinished() const { return _numFiles == 0; }
};


HRESULT CFolderOutStream::Init(unsigned startIndex, const UInt32 *indexes, unsigned numFiles)
{
  // _startIndex = startIndex;
  _fileIndex = startIndex;
  _indexes = indexes;
  _numFiles = numFiles;
  
  _fileIsOpen = false;
  ExtraWriteWasCut = false;
  
  return ProcessEmptyFiles();
}

HRESULT CFolderOutStream::OpenFile(bool isCorrupted)
{
  const CFileItem &fi = _db->Files[_fileIndex];
  const UInt32 nextFileIndex = (_indexes ? *_indexes : _fileIndex);
  Int32 askMode = (_fileIndex == nextFileIndex) ? TestMode ?
      NExtract::NAskMode::kTest :
      NExtract::NAskMode::kExtract :
      NExtract::NAskMode::kSkip;

  if (isCorrupted
      && askMode == NExtract::NAskMode::kExtract
      && !_db->IsItemAnti(_fileIndex)
      && !fi.IsDir)
    askMode = NExtract::NAskMode::kTest;
  
  CMyComPtr<ISequentialOutStream> realOutStream;
  RINOK(ExtractCallback->GetStream(_fileIndex, &realOutStream, askMode))
  
  _stream = realOutStream;
#if SUP7Z_USE_SHARED_OUTPUT
  _sharedOutput.Release();
  if (realOutStream)
    realOutStream->QueryInterface(IID_ISunpackSharedOutput, (void **)&_sharedOutput);
#endif
  _crc = CRC_INIT_VAL;
  _calcCrc = (CheckCrc && fi.CrcDefined && !fi.IsDir);

  _fileIsOpen = true;
  _rem = fi.Size;
  
  if (askMode == NExtract::NAskMode::kExtract
      && !realOutStream
      && !_db->IsItemAnti(_fileIndex)
      && !fi.IsDir)
    askMode = NExtract::NAskMode::kSkip;
  return ExtractCallback->PrepareOperation(askMode);
}

HRESULT CFolderOutStream::CloseFile_and_SetResult(Int32 res)
{
#if SUP7Z_USE_SHARED_OUTPUT
  if (_sharedLeaseToken)
  {
    UInt32 ignored = 0;
    if (_sharedOutput)
      _sharedOutput->Commit(_sharedLeaseToken, 0, &ignored);
    _sharedLeaseData = NULL;
    _sharedLeaseCapacity = 0;
    _sharedLeaseToken = 0;
  }
  _sharedOutput.Release();
#endif
  _stream.Release();
  _fileIsOpen = false;
  
  if (!_indexes)
    _numFiles--;
  else if (*_indexes == _fileIndex)
  {
    _indexes++;
    _numFiles--;
  }

  _fileIndex++;
  return ExtractCallback->SetOperationResult(res);
}

HRESULT CFolderOutStream::CloseFile()
{
  const CFileItem &fi = _db->Files[_fileIndex];
  return CloseFile_and_SetResult((!_calcCrc || fi.Crc == CRC_GET_DIGEST(_crc)) ?
      NExtract::NOperationResult::kOK :
      NExtract::NOperationResult::kCRCError);
}

HRESULT CFolderOutStream::ProcessEmptyFiles()
{
  while (_numFiles != 0 && _db->Files[_fileIndex].Size == 0)
  {
    RINOK(OpenFile())
    RINOK(CloseFile())
  }
  return S_OK;
}

Z7_COM7F_IMF(CFolderOutStream::Write(const void *data, UInt32 size, UInt32 *processedSize))
{
  if (processedSize)
    *processedSize = 0;
  
  while (size != 0)
  {
    if (_fileIsOpen)
    {
      UInt32 cur = (size < _rem ? size : (UInt32)_rem);
      if (_calcCrc)
      {
        const UInt32 k_Step = (UInt32)1 << 20;
        if (cur > k_Step)
          cur = k_Step;
      }
      HRESULT result = S_OK;
      if (_stream)
        result = _stream->Write(data, cur, &cur);
      if (_calcCrc)
        _crc = CrcUpdate(_crc, data, cur);
      if (processedSize)
        *processedSize += cur;
      data = (const Byte *)data + cur;
      size -= cur;
      _rem -= cur;
      if (_rem == 0)
      {
        RINOK(CloseFile())
        RINOK(ProcessEmptyFiles())
      }
      RINOK(result)
      if (cur == 0)
        break;
      continue;
    }
  
    RINOK(ProcessEmptyFiles())
    if (_numFiles == 0)
    {
      // we support partial extracting
      /*
      if (processedSize)
        *processedSize += size;
      break;
      */
      ExtraWriteWasCut = true;
      // return S_FALSE;
      return k_My_HRESULT_WritingWasCut;
    }
    RINOK(OpenFile())
  }
  
  return S_OK;
}

#if SUP7Z_USE_SHARED_OUTPUT

Z7_COM7F_IMF(CFolderOutStream::Acquire(
    UInt32 desiredSize, Byte **data, UInt32 *capacity, UInt64 *token))
{
  if (data) *data = NULL;
  if (capacity) *capacity = 0;
  if (token) *token = 0;
  if (!data || !capacity || !token || desiredSize == 0 || _sharedLeaseToken != 0)
    return E_INVALIDARG;

  for (;;)
  {
    if (!_fileIsOpen)
    {
      RINOK(ProcessEmptyFiles())
      if (_numFiles == 0)
      {
        ExtraWriteWasCut = true;
        return k_My_HRESULT_WritingWasCut;
      }
      RINOK(OpenFile())
    }

    if (!_sharedOutput)
      return S_FALSE;

    UInt32 request = desiredSize;
    if ((UInt64)request > _rem)
      request = (UInt32)_rem;
    if (request == 0)
    {
      RINOK(CloseFile())
      continue;
    }

    Byte *leased = NULL;
    UInt32 leasedCapacity = 0;
    UInt64 leasedToken = 0;
    const HRESULT res = _sharedOutput->Acquire(
        request, &leased, &leasedCapacity, &leasedToken);
    if (res != S_OK)
      return res;
    if (!leased || leasedCapacity == 0 || leasedCapacity > request || leasedToken == 0)
      return E_FAIL;

    _sharedLeaseData = leased;
    _sharedLeaseCapacity = leasedCapacity;
    _sharedLeaseToken = leasedToken;
    *data = leased;
    *capacity = leasedCapacity;
    *token = leasedToken;
    return S_OK;
  }
}

Z7_COM7F_IMF(CFolderOutStream::Commit(
    UInt64 token, UInt32 size, UInt32 *processedSize))
{
  if (processedSize) *processedSize = 0;
  if (!_sharedOutput || token == 0 || token != _sharedLeaseToken ||
      !_sharedLeaseData || size > _sharedLeaseCapacity)
    return E_INVALIDARG;

  const UInt32 nextCrc = (_calcCrc && size)
      ? CrcUpdate(_crc, _sharedLeaseData, size)
      : _crc;

  UInt32 committed = 0;
  const HRESULT res = _sharedOutput->Commit(token, size, &committed);
  _sharedLeaseData = NULL;
  _sharedLeaseCapacity = 0;
  _sharedLeaseToken = 0;

  if (committed > size || (res == S_OK && committed != size))
    return E_FAIL;
  if (_calcCrc && committed == size)
    _crc = nextCrc;
  if (processedSize)
    *processedSize = committed;
  _rem -= committed;

  if (_rem == 0)
  {
    RINOK(CloseFile())
    RINOK(ProcessEmptyFiles())
  }
  return res;
}

Z7_COM7F_IMF(CFolderOutStream::SubmitBorrowed(
    const Byte *data, UInt32 size, UInt32 *processedSize, UInt64 *token))
{
  if (processedSize) *processedSize = 0;
  if (token) *token = 0;
  if (!data || size == 0 || !processedSize || !token || _sharedLeaseToken != 0)
    return E_INVALIDARG;

  for (;;)
  {
    if (!_fileIsOpen)
    {
      RINOK(ProcessEmptyFiles())
      if (_numFiles == 0)
      {
        ExtraWriteWasCut = true;
        return k_My_HRESULT_WritingWasCut;
      }
      RINOK(OpenFile())
    }

    if (!_sharedOutput)
      return S_FALSE;

    UInt32 request = size;
    if ((UInt64)request > _rem)
      request = (UInt32)_rem;
    if (request == 0)
    {
      RINOK(CloseFile())
      continue;
    }

    UInt32 accepted = 0;
    UInt64 lease = 0;
    const HRESULT res = _sharedOutput->SubmitBorrowed(
        data, request, &accepted, &lease);
    if (res != S_OK)
      return res;
    if (accepted == 0 || accepted > request || lease == 0)
      return E_FAIL;

    if (_calcCrc)
      _crc = CrcUpdate(_crc, data, accepted);

    *processedSize = accepted;
    *token = lease;
    _rem -= accepted;
    if (_rem == 0)
    {
      RINOK(CloseFile())
      RINOK(ProcessEmptyFiles())
    }
    return S_OK;
  }
}

Z7_COM7F_IMF(CFolderOutStream::WaitBorrowed(UInt64 token))
{
  return SunpackSharedOutput_WaitToken(token);
}

#endif

HRESULT CFolderOutStream::FlushCorrupted(Int32 callbackOperationResult)
{
  while (_numFiles != 0)
  {
    if (_fileIsOpen)
    {
      RINOK(CloseFile_and_SetResult(callbackOperationResult))
    }
    else
    {
      RINOK(OpenFile(true))
    }
  }
  return S_OK;
}

/*
Z7_COM7F_IMF(CFolderOutStream::GetSubStreamSize(UInt64 subStream, UInt64 *value))
{
  *value = 0;
  // const unsigned numFiles_Original = _numFiles + _fileIndex - _startIndex;
  const unsigned numFiles_Original = _numFiles;
  if (subStream >= numFiles_Original)
    return S_FALSE; // E_FAIL;
  *value = _db->Files[_startIndex + (unsigned)subStream].Size;
  return S_OK;
}
*/


Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testModeSpec, IArchiveExtractCallback *extractCallbackSpec))
{
  // for GCC
  // CFolderOutStream *folderOutStream = new CFolderOutStream;
  // CMyComPtr<ISequentialOutStream> outStream(folderOutStream);

  COM_TRY_BEGIN
  
  CMyComPtr<IArchiveExtractCallback> extractCallback = extractCallbackSpec;
  
  UInt64 importantTotalUnpacked = 0;

  // numItems = (UInt32)(Int32)-1;

  const bool allFilesMode = (numItems == (UInt32)(Int32)-1);
  if (allFilesMode)
    numItems = _db.Files.Size();

  if (numItems == 0)
    return S_OK;

  {
    CNum prevFolder = kNumNoIndex;
    UInt32 nextFile = 0;
    
    UInt32 i;
    
    for (i = 0; i < numItems; i++)
    {
      const UInt32 fileIndex = allFilesMode ? i : indices[i];
      const CNum folderIndex = _db.FileIndexToFolderIndexMap[fileIndex];
      if (folderIndex == kNumNoIndex)
        continue;
      if (folderIndex != prevFolder || fileIndex < nextFile)
        nextFile = _db.FolderStartFileIndex[folderIndex];
      for (CNum index = nextFile; index <= fileIndex; index++)
        importantTotalUnpacked += _db.Files[index].Size;
      nextFile = fileIndex + 1;
      prevFolder = folderIndex;
    }
  }

  RINOK(extractCallback->SetTotal(importantTotalUnpacked))

  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
  lps->Init(extractCallback, false);

  CDecoder decoder(
    #if !defined(USE_MIXER_MT)
      false
    #elif !defined(USE_MIXER_ST)
      true
    #elif !defined(Z7_7Z_SET_PROPERTIES)
      #ifdef Z7_ST
        false
      #else
        true
      #endif
    #else
      _useMultiThreadMixer
    #endif
    );

  UInt64 curPacked, curUnpacked;

  CMyComPtr<IArchiveExtractCallbackMessage2> callbackMessage;
  extractCallback.QueryInterface(IID_IArchiveExtractCallbackMessage2, &callbackMessage);

  CFolderOutStream *folderOutStream = new CFolderOutStream;
  CMyComPtr<ISequentialOutStream> outStream(folderOutStream);

  folderOutStream->_db = &_db;
  folderOutStream->ExtractCallback = extractCallback;
  folderOutStream->TestMode = (testModeSpec != 0);
  folderOutStream->CheckCrc = (_crcSize != 0);

  for (UInt32 i = 0;; lps->OutSize += curUnpacked, lps->InSize += curPacked)
  {
    RINOK(lps->SetCur())

    if (i >= numItems)
      break;

    curUnpacked = 0;
    curPacked = 0;

    UInt32 fileIndex = allFilesMode ? i : indices[i];
    const CNum folderIndex = _db.FileIndexToFolderIndexMap[fileIndex];

    UInt32 numSolidFiles = 1;

    if (folderIndex != kNumNoIndex)
    {
      curPacked = _db.GetFolderFullPackSize(folderIndex);
      UInt32 nextFile = fileIndex + 1;
      fileIndex = _db.FolderStartFileIndex[folderIndex];
      UInt32 k;

      for (k = i + 1; k < numItems; k++)
      {
        const UInt32 fileIndex2 = allFilesMode ? k : indices[k];
        if (_db.FileIndexToFolderIndexMap[fileIndex2] != folderIndex
            || fileIndex2 < nextFile)
          break;
        nextFile = fileIndex2 + 1;
      }
      
      numSolidFiles = k - i;
      
      for (k = fileIndex; k < nextFile; k++)
        curUnpacked += _db.Files[k].Size;
    }

    {
      const HRESULT result = folderOutStream->Init(fileIndex,
          allFilesMode ? NULL : indices + i,
          numSolidFiles);

      i += numSolidFiles;

      RINOK(result)
    }

    if (folderOutStream->WasWritingFinished())
    {
      // for debug: to test zero size stream unpacking
      // if (folderIndex == kNumNoIndex)  // enable this check for debug
      continue;
    }

    if (folderIndex == kNumNoIndex)
      return E_FAIL;

    #ifndef Z7_NO_CRYPTO
    CMyComPtr<ICryptoGetTextPassword> getTextPassword;
    if (extractCallback)
      extractCallback.QueryInterface(IID_ICryptoGetTextPassword, &getTextPassword);
    #endif

    try
    {
      #ifndef Z7_NO_CRYPTO
        bool isEncrypted = false;
        bool passwordIsDefined = false;
        UString_Wipe password;
      #endif

      bool dataAfterEnd_Error = false;

      const HRESULT result = decoder.Decode(
          EXTERNAL_CODECS_VARS
          _inStream,
          _db.ArcInfo.DataStartPosition,
          _db, folderIndex,
          &curUnpacked,

          outStream,
          lps,
          NULL // *inStreamMainRes
          , dataAfterEnd_Error
          
          Z7_7Z_DECODER_CRYPRO_VARS
          #if !defined(Z7_ST)
            , true, _numThreads, _memUsage_Decompress
          #endif
          );

      if (result == S_FALSE || result == E_NOTIMPL || dataAfterEnd_Error)
      {
        const bool wasFinished = folderOutStream->WasWritingFinished();

        int resOp = NExtract::NOperationResult::kDataError;
        
        if (result != S_FALSE)
        {
          if (result == E_NOTIMPL)
            resOp = NExtract::NOperationResult::kUnsupportedMethod;
          else if (wasFinished && dataAfterEnd_Error)
            resOp = NExtract::NOperationResult::kDataAfterEnd;
        }

        RINOK(folderOutStream->FlushCorrupted(resOp))

        if (wasFinished)
        {
          // we don't show error, if it's after required files
          if (/* !folderOutStream->ExtraWriteWasCut && */ callbackMessage)
          {
            RINOK(callbackMessage->ReportExtractResult(NEventIndexType::kBlockIndex, folderIndex, resOp))
          }
        }
        continue;
      }
      
      if (result != S_OK)
        return result;

      RINOK(folderOutStream->FlushCorrupted(NExtract::NOperationResult::kDataError))
      continue;
    }
    catch(...)
    {
      RINOK(folderOutStream->FlushCorrupted(NExtract::NOperationResult::kDataError))
      // continue;
      // return E_FAIL;
      throw;
    }
  }

  return S_OK;

  COM_TRY_END
}

}}
