// 7zExtract.cpp

#include "StdAfx.h"

#include "../../../../C/7zCrc.h"

#include "internal/positioned_output.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <vector>

#include "../../../Common/ComTry.h"

#include "../../Common/ProgressUtils.h"

#include "7zDecode.h"
#include "7zHandler.h"

// EXTERN_g_ExternalCodecs

namespace NArchive {
namespace N7z {

namespace {

struct CPositionedCrcSegment
{
  UInt64 Offset;
  UInt32 Size;
  UInt32 Crc;
};

static UInt32 CrcGf2MatrixTimes(const UInt32 *matrix, UInt32 vector)
{
  UInt32 sum = 0;
  while (vector)
  {
    if (vector & 1)
      sum ^= *matrix;
    vector >>= 1;
    matrix++;
  }
  return sum;
}

static void CrcGf2MatrixSquare(UInt32 *square, const UInt32 *matrix)
{
  for (unsigned i = 0; i < 32; ++i)
    square[i] = CrcGf2MatrixTimes(matrix, matrix[i]);
}

static UInt32 CrcCombine(UInt32 crc1, UInt32 crc2, UInt64 len2)
{
  if (len2 == 0)
    return crc1;

  UInt32 even[32];
  UInt32 odd[32];

  odd[0] = 0xEDB88320;
  UInt32 row = 1;
  for (unsigned i = 1; i < 32; ++i)
  {
    odd[i] = row;
    row <<= 1;
  }

  CrcGf2MatrixSquare(even, odd);
  CrcGf2MatrixSquare(odd, even);

  do
  {
    CrcGf2MatrixSquare(even, odd);
    if (len2 & 1)
      crc1 = CrcGf2MatrixTimes(even, crc1);
    len2 >>= 1;
    if (len2 == 0)
      break;

    CrcGf2MatrixSquare(odd, even);
    if (len2 & 1)
      crc1 = CrcGf2MatrixTimes(odd, crc1);
    len2 >>= 1;
  }
  while (len2 != 0);

  return crc1 ^ crc2;
}

} // namespace

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

  struct CPositionedFile
  {
    UInt32 Index = 0;
    UInt64 Start = 0;
    UInt64 Size = 0;
    CMyComPtr<ISequentialOutStream> Stream;
    sunpack::sevenzip::PositionedOutStream *Positioned = NULL;
    std::mutex CrcMutex;
    std::vector<CPositionedCrcSegment> CrcSegments;
  };

  bool _positionedMode;
  UInt64 _positionedSize;
  sunpack::sevenzip::PositionedExtractCallback *_positionedCallback;
  std::vector<std::unique_ptr<CPositionedFile> > _positionedFiles;
  std::vector<CPositionedFile *> _positionedRanges;

  const UInt32 *_indexes;
  // unsigned _startIndex;
  unsigned _numFiles;
  unsigned _fileIndex;

  HRESULT OpenFile(bool isCorrupted = false);
  HRESULT CloseFile_and_SetResult(Int32 res);
  HRESULT CloseFile();
  HRESULT ProcessEmptyFiles();
  HRESULT InitPositioned(unsigned startIndex, unsigned numFiles);

public:
  const CDbEx *_db;
  CMyComPtr<IArchiveExtractCallback> ExtractCallback;

  bool ExtraWriteWasCut;

  CFolderOutStream():
      TestMode(false),
      CheckCrc(true),
      _positionedMode(false),
      _positionedSize(0),
      _positionedCallback(NULL)
      {}

  HRESULT Init(unsigned startIndex, const UInt32 *indexes, unsigned numFiles, bool allowPositioned);
  HRESULT WriteAt(UInt64 offset, const void *data, UInt32 size, UInt32 *processedSize);
  HRESULT FinishPositioned(Int32 callbackOperationResult);
  void ResetPositionedCrcForReplay();
  bool IsPositionedMode() const { return _positionedMode; }
  HRESULT FlushCorrupted(Int32 callbackOperationResult);

  bool WasWritingFinished() const { return _numFiles == 0; }
};


HRESULT CFolderOutStream::Init(
    unsigned startIndex,
    const UInt32 *indexes,
    unsigned numFiles,
    bool allowPositioned)
{
  _fileIndex = startIndex;
  _indexes = indexes;
  _numFiles = numFiles;

  _fileIsOpen = false;
  ExtraWriteWasCut = false;

  _positionedMode = false;
  _positionedSize = 0;
  _positionedCallback = NULL;
  _positionedRanges.clear();
  _positionedFiles.clear();

  if (allowPositioned && !indexes && !TestMode)
  {
    const HRESULT positionedResult = InitPositioned(startIndex, numFiles);
    if (positionedResult == S_OK && _positionedMode)
      return S_OK;
    if (positionedResult != E_NOTIMPL)
      return positionedResult;
  }

  return ProcessEmptyFiles();
}

HRESULT CFolderOutStream::InitPositioned(unsigned startIndex, unsigned numFiles)
{
  _positionedCallback =
      dynamic_cast<sunpack::sevenzip::PositionedExtractCallback *>(
          ExtractCallback.Interface());

  if (!_positionedCallback ||
      !_positionedCallback->positioned_extract_available())
  {
    _positionedCallback = NULL;
    return E_NOTIMPL;
  }

  UInt64 logicalPos = 0;

  try
  {
    _positionedFiles.reserve(numFiles);
    _positionedRanges.reserve(numFiles);

    for (unsigned k = 0; k < numFiles; ++k)
    {
      const UInt32 index = startIndex + k;
      const CFileItem &fi = _db->Files[index];

      std::unique_ptr<CPositionedFile> state(new CPositionedFile);
      state->Index = index;
      state->Start = logicalPos;
      state->Size = fi.Size;

      CMyComPtr<ISequentialOutStream> realOutStream;
      const HRESULT getResult = _positionedCallback->get_positioned_stream(
          index,
          &realOutStream,
          NExtract::NAskMode::kExtract);
      if (getResult != S_OK)
        return getResult;

      state->Stream = realOutStream;

      if (fi.Size != 0 && !fi.IsDir)
      {
        state->Positioned =
            sunpack::sevenzip::positioned_out_stream(realOutStream);
        if (!state->Positioned)
          return E_NOINTERFACE;
        _positionedRanges.push_back(state.get());
      }

      if (logicalPos > (UInt64)(Int64)-1 - fi.Size)
        return E_FAIL;
      logicalPos += fi.Size;
      _positionedFiles.push_back(std::move(state));
    }
  }
  catch (...)
  {
    return E_OUTOFMEMORY;
  }

  _positionedSize = logicalPos;
  _positionedMode = true;

  if (_positionedSize == 0)
    return FinishPositioned(NExtract::NOperationResult::kOK);

  return S_OK;
}


HRESULT CFolderOutStream::WriteAt(
    UInt64 offset,
    const void *data,
    UInt32 size,
    UInt32 *processedSize)
{
  if (processedSize)
    *processedSize = 0;

  if (!_positionedMode || (size != 0 && !data))
    return E_FAIL;
  if (size == 0)
    return S_OK;
  if (offset > _positionedSize || size > _positionedSize - offset)
    return E_FAIL;

  const Byte *src = (const Byte *)data;
  UInt32 total = 0;

  while (total < size)
  {
    const UInt64 pos = offset + total;
    const auto it = std::lower_bound(
        _positionedRanges.begin(),
        _positionedRanges.end(),
        pos,
        [](const CPositionedFile *state, UInt64 value)
        {
          return state->Start + state->Size <= value;
        });

    if (it == _positionedRanges.end())
      return E_FAIL;

    CPositionedFile *state = *it;
    if (pos < state->Start || pos >= state->Start + state->Size ||
        !state->Positioned)
      return E_FAIL;

    const UInt64 fileOffset = pos - state->Start;
    const UInt64 fileRem = state->Size - fileOffset;
    UInt32 cur = size - total;
    if (cur > fileRem)
      cur = (UInt32)fileRem;

    UInt32 written = 0;
    const HRESULT result = state->Positioned->write_at(
        fileOffset, src + total, cur, &written);

    if (written != 0 && CheckCrc)
    {
      CPositionedCrcSegment segment;
      segment.Offset = fileOffset;
      segment.Size = written;
      segment.Crc = CrcCalc(src + total, written);
      std::lock_guard<std::mutex> lock(state->CrcMutex);
      state->CrcSegments.push_back(segment);
    }

    total += written;
    if (result != S_OK || written != cur)
    {
      if (processedSize)
        *processedSize = total;
      return result != S_OK ? result : E_FAIL;
    }
  }

  if (processedSize)
    *processedSize = total;
  return S_OK;
}


void CFolderOutStream::ResetPositionedCrcForReplay()
{
  if (!_positionedMode)
    return;

  for (const auto &holder : _positionedFiles)
  {
    CPositionedFile &state = *holder;
    std::lock_guard<std::mutex> lock(state.CrcMutex);
    state.CrcSegments.clear();
  }
}


HRESULT CFolderOutStream::FinishPositioned(Int32 callbackOperationResult)
{
  if (!_positionedMode)
    return S_OK;

  HRESULT firstError = S_OK;

  for (const auto &holder : _positionedFiles)
  {
    CPositionedFile &state = *holder;
    const CFileItem &fi = _db->Files[state.Index];
    Int32 result = callbackOperationResult;

    if (result == NExtract::NOperationResult::kOK &&
        CheckCrc && fi.CrcDefined && !fi.IsDir)
    {
      bool coverageOk = true;
      UInt32 combined = 0;
      UInt64 cursor = 0;

      {
        std::lock_guard<std::mutex> lock(state.CrcMutex);
        std::sort(
            state.CrcSegments.begin(),
            state.CrcSegments.end(),
            [](const CPositionedCrcSegment &a, const CPositionedCrcSegment &b)
            {
              return a.Offset < b.Offset;
            });

        bool haveCrc = false;
        for (const CPositionedCrcSegment &segment : state.CrcSegments)
        {
          if (segment.Offset != cursor)
          {
            coverageOk = false;
            break;
          }

          if (!haveCrc)
          {
            combined = segment.Crc;
            haveCrc = true;
          }
          else
            combined = CrcCombine(combined, segment.Crc, segment.Size);

          cursor += segment.Size;
        }

        if (cursor != state.Size)
          coverageOk = false;
        if (!haveCrc)
          combined = 0;
      }

      if (!coverageOk)
        result = NExtract::NOperationResult::kDataError;
      else if (combined != fi.Crc)
        result = NExtract::NOperationResult::kCRCError;
    }

    state.Stream.Release();

    const HRESULT callbackResult =
        _positionedCallback->set_positioned_operation_result(
            state.Index, result);
    if (firstError == S_OK && callbackResult != S_OK)
      firstError = callbackResult;
  }

  _positionedRanges.clear();
  _positionedFiles.clear();
  _positionedCallback = NULL;
  _positionedMode = false;
  _positionedSize = 0;
  _numFiles = 0;
  _fileIsOpen = false;

  return firstError;
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

HRESULT CFolderOutStream::FlushCorrupted(Int32 callbackOperationResult)
{
  if (_positionedMode)
    return FinishPositioned(callbackOperationResult);

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

class CFolderPositionedOutStream final :
  public CMyUnknownImp,
  public ISequentialOutStream,
  public sunpack::sevenzip::PositionedOutStream
{
  Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)

  CMyComPtr<ISequentialOutStream> _sequential;
  CFolderOutStream *_folder;
  UInt64 _sequentialPos;
  bool _replayStarted;

public:
  CFolderPositionedOutStream(
      ISequentialOutStream *sequential,
      CFolderOutStream *folder):
      _sequential(sequential),
      _folder(folder),
      _sequentialPos(0),
      _replayStarted(false)
  {}

  Z7_COM7F_IMF(Write(const void *data, UInt32 size, UInt32 *processedSize))
  {
    if (!_replayStarted)
    {
      _folder->ResetPositionedCrcForReplay();
      _replayStarted = true;
      _sequentialPos = 0;
    }

    UInt32 processed = 0;
    const HRESULT result =
        _folder->WriteAt(_sequentialPos, data, size, &processed);
    _sequentialPos += processed;
    if (processedSize)
      *processedSize = processed;
    return result;
  }

  bool positioned_available() const noexcept override
  {
    return _folder && _folder->IsPositionedMode();
  }

  HRESULT write_at(
      UInt64 offset,
      const void *data,
      UInt32 size,
      UInt32 *processedSize) noexcept override
  {
    return _folder->WriteAt(offset, data, size, processedSize);
  }
};


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
      bool allowPositioned = false;
      if (allFilesMode && testModeSpec == 0 && folderIndex != kNumNoIndex)
      {
        CFolderEx folderInfo;
        _db.ParseFolderEx(folderIndex, folderInfo);
        allowPositioned =
            folderInfo.UnpackCoder < folderInfo.Coders.Size() &&
            folderInfo.Coders[folderInfo.UnpackCoder].MethodID == k_LZMA2;
      }

      const HRESULT result = folderOutStream->Init(
          fileIndex,
          allFilesMode ? NULL : indices + i,
          numSolidFiles,
          allowPositioned);

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

      CMyComPtr<ISequentialOutStream> decoderOutStream = outStream;
      if (folderOutStream->IsPositionedMode())
      {
        CFolderPositionedOutStream *positionedSpec =
            new CFolderPositionedOutStream(outStream, folderOutStream);
        decoderOutStream = positionedSpec;
      }

      const HRESULT result = decoder.Decode(
          EXTERNAL_CODECS_VARS
          _inStream,
          _db.ArcInfo.DataStartPosition,
          _db, folderIndex,
          &curUnpacked,

          decoderOutStream,
          lps,
          NULL // *inStreamMainRes
          , dataAfterEnd_Error
          
          Z7_7Z_DECODER_CRYPRO_VARS
          #if !defined(Z7_ST)
            , true, _numThreads, _memUsage_Decompress
          #endif
          );

      if (result == S_OK && folderOutStream->IsPositionedMode())
        RINOK(folderOutStream->FinishPositioned(NExtract::NOperationResult::kOK))

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
