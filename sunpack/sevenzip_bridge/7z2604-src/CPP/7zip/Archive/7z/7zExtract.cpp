// 7zExtract.cpp

#include "StdAfx.h"

#include "../../../../C/7zCrc.h"

#include "../../../Common/ComTry.h"

#include "../../Common/ProgressUtils.h"
#include "../../Common/StreamUtils.h"
#include "../../Crypto/7zAes.h"
#include "internal/password_proof_property.hpp"

#include "7zDecode.h"
#include "7zHandler.h"

// EXTERN_g_ExternalCodecs

namespace NArchive {
namespace N7z {

Z7_CLASS_IMP_COM_1(
  CFolderOutStream
  , ISequentialOutStream
  /* , ICompressGetSubStreamSize */
)
  CMyComPtr<ISequentialOutStream> _stream;
public:
  bool TestMode;
  bool CheckCrc;
private:
  bool _fileIsOpen;
  bool _calcCrc;
  UInt32 _crc;
  UInt64 _rem;
  bool _checkFolderCrc;
  UInt32 _folderCrc, _expectedFolderCrc;
  UInt64 _folderRemaining;

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
      {}

  HRESULT Init(unsigned startIndex, const UInt32 *indexes, unsigned numFiles, CNum folder, UInt64 outputSize);
  HRESULT FlushCorrupted(Int32 callbackOperationResult);

  bool WasWritingFinished() const { return _numFiles == 0; }
};


HRESULT CFolderOutStream::Init(unsigned startIndex, const UInt32 *indexes, unsigned numFiles, CNum folder, UInt64 outputSize)
{
  // _startIndex = startIndex;
  _fileIndex = startIndex;
  _indexes = indexes;
  _numFiles = numFiles;
  
  _fileIsOpen = false;
  ExtraWriteWasCut = false;
  // A single-substream folder digest is already exposed as the file CRC.
  // Only a complete multi-substream decode can validate the folder digest.
  _checkFolderCrc = CheckCrc && folder != kNumNoIndex && _db->NumUnpackStreamsVector[folder] > 1 &&
      _db->FolderCRCs.ValidAndDefined(folder) && outputSize == _db->GetFolderUnpackSize(folder);
  if (_checkFolderCrc)
  {
    _folderRemaining = outputSize;
    _folderCrc = CRC_INIT_VAL;
    _expectedFolderCrc = _db->FolderCRCs.Vals[folder];
  }
  
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
  bool valid = !_calcCrc || fi.Crc == CRC_GET_DIGEST(_crc);
  if (_checkFolderCrc && _folderRemaining == 0)
  {
    valid = valid && _expectedFolderCrc == CRC_GET_DIGEST(_folderCrc);
    _checkFolderCrc = false;
  }
  return CloseFile_and_SetResult(valid ?
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
      if (_checkFolderCrc)
      {
        _folderCrc = CrcUpdate(_folderCrc, data, cur);
        _folderRemaining -= cur;
      }
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


// CBC can enter an AES/Copy folder at any ciphertext block using the previous
// block for chaining. A substream CRC covers just this file's plaintext.
static HRESULT TestCopySubstream(const CDbEx &db, IInStream *stream, UInt32 index,
    IArchiveExtractCallback *callback, bool &handled)
{
  const auto &file = db.Files[index];
  const CNum folderIndex = db.FileIndexToFolderIndexMap[index];
  if (!file.CrcDefined || !file.Size || folderIndex == kNumNoIndex ||
      db.FolderStartFileIndex[folderIndex] == index ||
      (db.FolderCRCs.ValidAndDefined(folderIndex) &&
       (index + 1 == db.Files.Size() || db.FileIndexToFolderIndexMap[index + 1] != folderIndex)))
    return S_OK;
  CFolder folder;
  const int coder = db.GetSeekableAesCoder(folderIndex, folder);
  if (coder < 0) return S_OK;

  UInt64 offset = 0;
  for (auto i = db.FolderStartFileIndex[folderIndex]; i < index; ++i)
    offset += db.Files[i].Size;
  if (offset < 16) return S_OK;
  const UInt64 start = (offset & ~(UInt64)15) - 16;
  const UInt64 packSize = db.GetFolderFullPackSize(folderIndex);
  if (offset > packSize || file.Size > packSize - offset) return S_OK;
  handled = true;

  CMyComPtr<ICryptoGetTextPassword> crypto;
  RINOK(callback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&crypto))
  CMyComBSTR_Wipe password;
  BSTR *passwordValue = &password;
  RINOK(crypto->CryptoGetTextPassword(passwordValue))
  CMyComPtr2_Create<ICompressFilter, NCrypto::N7z::CDecoder> aes;
  const auto &props = folder.Coders[(unsigned)coder].Props;
  RINOK(static_cast<ICompressSetDecoderProperties2 *>(aes.ClsPtr())->SetDecoderProperties2(props, (UInt32)props.Size()))
  RINOK(static_cast<ICryptoSetPassword *>(aes.ClsPtr())->CryptoSetPassword(
      (const Byte *)*passwordValue, SysStringByteLen(*passwordValue)))
  RINOK(aes.Interface()->Init())
  RINOK(InStream_SeekSet(stream, db.GetFolderStreamPos(folderIndex, 0) + start))
  RINOK(callback->SetTotal(file.Size))
  CMyComPtr<ISequentialOutStream> unused;
  RINOK(callback->GetStream(index, &unused, NExtract::NAskMode::kTest))
  RINOK(callback->PrepareOperation(NExtract::NAskMode::kTest))
  alignas(16) Byte buffer[1 << 15];
  UInt64 remaining = file.Size;
  UInt32 skip = (UInt32)(offset - start), crc = CRC_INIT_VAL;
  while (remaining)
  {
    const UInt32 take = (UInt32)MyMin((UInt64)sizeof(buffer) - skip, remaining);
    const UInt32 size = (take + skip + 15) & ~(UInt32)15;
    size_t read = size;
    RINOK(ReadStream(stream, buffer, &read))
    if (read != size)
      return callback->SetOperationResult(NExtract::NOperationResult::kUnexpectedEnd);
    if (aes.Interface()->Filter(buffer, size) != size) return E_FAIL;
    crc = CrcUpdate(crc, buffer + skip, take);
    skip = 0;
    remaining -= take;
    const UInt64 done = file.Size - remaining;
    RINOK(callback->SetCompleted(&done))
  }
  return callback->SetOperationResult(CRC_GET_DIGEST(crc) == file.Crc ?
      NExtract::NOperationResult::kOK : NExtract::NOperationResult::kCRCError);
}

Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testModeSpec, IArchiveExtractCallback *extractCallbackSpec))
{
  // for GCC
  // CFolderOutStream *folderOutStream = new CFolderOutStream;
  // CMyComPtr<ISequentialOutStream> outStream(folderOutStream);

  COM_TRY_BEGIN
  
  CMyComPtr<IArchiveExtractCallback> extractCallback = extractCallbackSpec;
  if (testModeSpec == kSunpackVerifyMember && numItems == 1 && indices && _crcSize)
  {
    bool handled = false;
    RINOK(TestCopySubstream(_db, _inStream, indices[0], extractCallback, handled))
    if (handled) return S_OK;
  }
  
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
          numSolidFiles, folderIndex, curUnpacked);

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
