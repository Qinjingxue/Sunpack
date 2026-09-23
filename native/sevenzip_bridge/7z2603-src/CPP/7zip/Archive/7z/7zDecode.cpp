// 7zDecode.cpp

#include "StdAfx.h"

#include "../../Common/LimitedStreams.h"
#include "../../Common/ProgressUtils.h"
#include "../../Common/StreamObjects.h"
#include "../../Common/StreamUtils.h"
#include "../../Compress/Lzma2Decoder.h"

#include "../../../../C/Bra.h"
#include "../../../../C/CpuArch.h"
#include "../../../../C/SwapBytes.h"
#include "internal/positioned_output.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "7zDecode.h"

namespace NArchive {
namespace N7z {

namespace {

static unsigned PositionedFilterAlignment(CMethodId method)
{
  switch (method)
  {
    case k_ARM64:
    case k_ARM:
    case k_PPC:
    case k_SPARC:
      return 4;
    case k_ARMT:
    case k_RISCV:
      return 2;
    case k_IA64:
      return 16;
    case k_SWAP2:
      return 2;
    case k_SWAP4:
      return 4;
    default:
      return 0;
  }
}

static bool PositionedFilterProps(
    const CCoderInfo &coder,
    UInt32 &pcInit)
{
  pcInit = 0;
  const CMethodId method = coder.MethodID;
  const unsigned alignment = PositionedFilterAlignment(method);
  if (alignment == 0)
    return false;

  if (method == k_ARM64 || method == k_RISCV)
  {
    if (coder.Props.Size() == 0)
      return true;
    if (coder.Props.Size() != 4)
      return false;
    pcInit = GetUi32((const Byte *)coder.Props);
    return (pcInit & (alignment - 1)) == 0;
  }

  return coder.Props.Size() == 0;
}

static unsigned PositionedFilterLookAhead(CMethodId method)
{
  switch (method)
  {
    case k_ARMT: return 2;
    case k_RISCV: return 6;
    default: return 0;
  }
}

static size_t ProcessPositionedFilter(
    CMethodId method,
    Byte *data,
    size_t size,
    UInt32 pc)
{
  if (size == 0)
    return 0;

  switch (method)
  {
    case k_ARM64:
      return (size_t)(Z7_BRANCH_CONV_DEC(ARM64)(data, size, pc) - data);
    case k_ARM:
      return (size_t)(Z7_BRANCH_CONV_DEC(ARM)(data, size, pc) - data);
    case k_ARMT:
      return (size_t)(Z7_BRANCH_CONV_DEC(ARMT)(data, size, pc) - data);
    case k_PPC:
      return (size_t)(Z7_BRANCH_CONV_DEC(PPC)(data, size, pc) - data);
    case k_SPARC:
      return (size_t)(Z7_BRANCH_CONV_DEC(SPARC)(data, size, pc) - data);
    case k_IA64:
      return (size_t)(Z7_BRANCH_CONV_DEC(IA64)(data, size, pc) - data);
    case k_RISCV:
      return (size_t)(Z7_BRANCH_CONV_DEC(RISCV)(data, size, pc) - data);
    case k_SWAP2:
      z7_SwapBytes2((UInt16 *)(void *)data, size >> 1);
      return size & ~(size_t)1;
    case k_SWAP4:
      z7_SwapBytes4((UInt32 *)(void *)data, size >> 2);
      return size & ~(size_t)3;
    default:
      return 0;
  }
}

static bool ApplyPositionedFilter(
    CMethodId method,
    Byte *data,
    size_t size,
    UInt32 pc)
{
  if (size == 0)
    return true;

  return ProcessPositionedFilter(method, data, size, pc) == size;
}

class CPositionedAlignedFilterOutStream final :
  public CMyUnknownImp,
  public ISequentialOutStream,
  public sunpack::sevenzip::PositionedOutStream
{
  Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)

  struct CPartialCell
  {
    std::array<Byte, 16> Bytes{};
    UInt32 Mask = 0;
  };

  CMyComPtr<ISequentialOutStream> _sequential;
  sunpack::sevenzip::PositionedOutStream *_positioned;
  CMethodId _method;
  UInt32 _pcInit;
  UInt64 _totalSize;
  unsigned _alignment;

  std::mutex _partialMutex;
  std::map<UInt64, CPartialCell> _partials;

  std::mutex _sequentialMutex;
  std::vector<Byte> _sequentialPending;
  UInt64 _sequentialPos;
  bool _sequentialUsed;

  HRESULT WriteFilteredAt(UInt64 offset, const Byte *data, UInt32 size)
  {
    if (size == 0)
      return S_OK;

    thread_local std::vector<Byte> scratch;
    try
    {
      scratch.assign(data, data + size);
    }
    catch (...)
    {
      return E_OUTOFMEMORY;
    }

    if (!ApplyPositionedFilter(
            _method,
            scratch.data(),
            scratch.size(),
            _pcInit + (UInt32)offset))
      return E_FAIL;

    UInt32 written = 0;
    const HRESULT hres = _positioned->write_at(
        offset, scratch.data(), size, &written);
    return hres == S_OK && written == size ? S_OK :
        (hres != S_OK ? hres : E_FAIL);
  }

  HRESULT AddPartial(
      UInt64 cellStart,
      unsigned cellOffset,
      const Byte *data,
      unsigned size)
  {
    std::array<Byte, 16> completed{};
    bool ready = false;

    {
      std::lock_guard<std::mutex> lock(_partialMutex);
      CPartialCell &cell = _partials[cellStart];
      for (unsigned i = 0; i < size; ++i)
      {
        const unsigned index = cellOffset + i;
        if (index >= _alignment)
          return E_FAIL;
        cell.Bytes[index] = data[i];
        cell.Mask |= (UInt32)1 << index;
      }

      const UInt32 completeMask =
          _alignment == 32 ? 0xFFFFFFFFu :
          (((UInt32)1 << _alignment) - 1);
      if (cell.Mask == completeMask)
      {
        completed = cell.Bytes;
        _partials.erase(cellStart);
        ready = true;
      }
    }

    if (!ready)
      return S_OK;

    return WriteFilteredAt(
        cellStart, completed.data(), (UInt32)_alignment);
  }

public:
  CPositionedAlignedFilterOutStream(
      ISequentialOutStream *stream,
      CMethodId method,
      UInt32 pcInit,
      UInt64 totalSize):
      _sequential(stream),
      _positioned(sunpack::sevenzip::positioned_out_stream(stream)),
      _method(method),
      _pcInit(pcInit),
      _totalSize(totalSize),
      _alignment(PositionedFilterAlignment(method)),
      _sequentialPos(0),
      _sequentialUsed(false)
  {}

  bool IsUsable() const
  {
    return _positioned && _positioned->positioned_available() &&
        _alignment != 0 && _alignment <= 16;
  }

  bool positioned_available() const noexcept override
  {
    return !_sequentialUsed && _positioned &&
        _positioned->positioned_available();
  }

  HRESULT write_at(
      UInt64 offset,
      const void *data,
      UInt32 size,
      UInt32 *processedSize) noexcept override
  {
    if (processedSize)
      *processedSize = 0;
    if (_sequentialUsed || !IsUsable() ||
        (size != 0 && !data) ||
        offset > _totalSize ||
        size > _totalSize - offset)
      return E_FAIL;
    if (size == 0)
      return S_OK;

    const Byte *src = (const Byte *)data;
    UInt32 consumed = 0;

    try
    {
      const UInt64 firstAligned =
          (offset + (_alignment - 1)) & ~(UInt64)(_alignment - 1);
      const UInt64 end = offset + size;
      const UInt64 alignedEnd = end & ~(UInt64)(_alignment - 1);

      if (offset < firstAligned)
      {
        const UInt32 cur = (UInt32)(std::min<UInt64>)(
            end - offset, firstAligned - offset);
        RINOK(AddPartial(
            offset & ~(UInt64)(_alignment - 1),
            (unsigned)(offset & (_alignment - 1)),
            src, cur))
        consumed += cur;
      }

      const UInt64 middleStart = offset + consumed;
      if (middleStart < alignedEnd)
      {
        UInt64 middle = alignedEnd - middleStart;
        while (middle != 0)
        {
          const UInt32 cur = (UInt32)(std::min<UInt64>)(
              middle, (UInt64)1 << 20);
          RINOK(WriteFilteredAt(
              middleStart + (alignedEnd - middleStart - middle),
              src + consumed,
              cur))
          consumed += cur;
          middle -= cur;
        }
      }

      if (consumed < size)
      {
        const UInt64 pos = offset + consumed;
        const UInt32 cur = size - consumed;
        RINOK(AddPartial(
            pos & ~(UInt64)(_alignment - 1),
            (unsigned)(pos & (_alignment - 1)),
            src + consumed, cur))
        consumed += cur;
      }
    }
    catch (...)
    {
      if (processedSize)
        *processedSize = consumed;
      return E_OUTOFMEMORY;
    }

    if (processedSize)
      *processedSize = consumed;
    return S_OK;
  }

  Z7_COM7F_IMF(Write(
      const void *data,
      UInt32 size,
      UInt32 *processedSize))
  {
    if (processedSize)
      *processedSize = 0;
    if (size != 0 && !data)
      return E_POINTER;

    std::lock_guard<std::mutex> lock(_sequentialMutex);

    if (!_sequentialUsed)
    {
      _sequentialUsed = true;
      {
        std::lock_guard<std::mutex> partialLock(_partialMutex);
        _partials.clear();
      }
      _sequentialPending.clear();
      _sequentialPos = 0;
    }

    const Byte *src = (const Byte *)data;
    try
    {
      _sequentialPending.insert(
          _sequentialPending.end(), src, src + size);
    }
    catch (...)
    {
      return E_OUTOFMEMORY;
    }

    const size_t processSize =
        _sequentialPending.size() & ~(size_t)(_alignment - 1);
    if (processSize != 0)
    {
      std::vector<Byte> converted(
          _sequentialPending.begin(),
          _sequentialPending.begin() + processSize);
      if (!ApplyPositionedFilter(
              _method, converted.data(), converted.size(),
              _pcInit + (UInt32)_sequentialPos))
        return E_FAIL;

      UInt32 written = 0;
      const HRESULT hres = _sequential->Write(
          converted.data(), (UInt32)converted.size(), &written);
      if (hres != S_OK || written != converted.size())
        return hres != S_OK ? hres : E_FAIL;

      _sequentialPos += written;
      _sequentialPending.erase(
          _sequentialPending.begin(),
          _sequentialPending.begin() + processSize);
    }

    if (processedSize)
      *processedSize = size;
    return S_OK;
  }

  HRESULT Finish()
  {
    std::lock_guard<std::mutex> seqLock(_sequentialMutex);

    if (_sequentialUsed)
    {
      if (!_sequentialPending.empty())
      {
        UInt32 written = 0;
        const HRESULT hres = _sequential->Write(
            _sequentialPending.data(),
            (UInt32)_sequentialPending.size(),
            &written);
        if (hres != S_OK || written != _sequentialPending.size())
          return hres != S_OK ? hres : E_FAIL;
        _sequentialPos += written;
        _sequentialPending.clear();
      }
      return _sequentialPos == _totalSize ? S_OK : E_FAIL;
    }

    std::array<Byte, 16> tail{};
    UInt32 tailSize = 0;
    UInt64 tailStart = 0;

    {
      std::lock_guard<std::mutex> lock(_partialMutex);
      if (!_partials.empty())
      {
        if (_partials.size() != 1)
          return E_FAIL;

        const auto &entry = *_partials.begin();
        tailStart = entry.first;
        if (tailStart >= _totalSize ||
            tailStart + _alignment <= _totalSize)
          return E_FAIL;

        tailSize = (UInt32)(_totalSize - tailStart);
        const UInt32 expectedMask =
            ((UInt32)1 << tailSize) - 1;
        if ((entry.second.Mask & expectedMask) != expectedMask ||
            (entry.second.Mask & ~expectedMask) != 0)
          return E_FAIL;
        tail = entry.second.Bytes;
        _partials.clear();
      }
    }

    if (tailSize != 0)
    {
      UInt32 written = 0;
      const HRESULT hres = _positioned->write_at(
          tailStart, tail.data(), tailSize, &written);
      if (hres != S_OK || written != tailSize)
        return hres != S_OK ? hres : E_FAIL;
    }

    return S_OK;
  }
};


class CPositionedLookAheadFilterOutStream final :
  public CMyUnknownImp,
  public ISequentialOutStream,
  public sunpack::sevenzip::PositionedOutStream
{
  Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)

  static const UInt64 kTileSize = (UInt64)1 << 20;

  struct CTile
  {
    std::vector<Byte> Data;
    std::vector<std::pair<UInt32, UInt32>> Ranges;
  };

  CMyComPtr<ISequentialOutStream> _sequential;
  sunpack::sevenzip::PositionedOutStream *_positioned;
  CMethodId _method;
  UInt32 _pcInit;
  UInt64 _totalSize;
  unsigned _alignment;
  unsigned _lookAhead;

  std::mutex _tileMutex;
  std::map<UInt64, CTile> _tiles;

  std::mutex _sequentialMutex;
  std::vector<Byte> _sequentialPending;
  UInt64 _sequentialPos;
  bool _sequentialUsed;

  static void AddCoverage(
      std::vector<std::pair<UInt32, UInt32>> &ranges,
      UInt32 begin,
      UInt32 end)
  {
    if (begin >= end)
      return;
    ranges.emplace_back(begin, end);
    std::sort(ranges.begin(), ranges.end());
    size_t out = 0;
    for (const auto &range : ranges)
    {
      if (out == 0 || ranges[out - 1].second < range.first)
        ranges[out++] = range;
      else if (ranges[out - 1].second < range.second)
        ranges[out - 1].second = range.second;
    }
    ranges.resize(out);
  }

  HRESULT ProcessTile(UInt64 tileStart, CTile tile)
  {
    const UInt64 core64 =
        (std::min<UInt64>)(kTileSize, _totalSize - tileStart);
    const UInt32 coreSize = (UInt32)core64;
    const bool finalTile = tileStart + core64 == _totalSize;

    const size_t processed = ProcessPositionedFilter(
        _method,
        tile.Data.data(),
        tile.Data.size(),
        _pcInit + (UInt32)tileStart);

    if (!finalTile && processed < coreSize)
      return E_FAIL;

    UInt32 written = 0;
    const HRESULT hres = _positioned->write_at(
        tileStart, tile.Data.data(), coreSize, &written);
    return hres == S_OK && written == coreSize ? S_OK :
        (hres != S_OK ? hres : E_FAIL);
  }

  HRESULT FeedTile(
      UInt64 tileStart,
      UInt64 offset,
      const Byte *data,
      UInt32 size)
  {
    if (tileStart >= _totalSize)
      return S_OK;

    const UInt64 needEnd =
        (std::min<UInt64>)(
            _totalSize,
            tileStart + kTileSize + _lookAhead);
    const UInt64 writeEnd = offset + size;
    const UInt64 overlapStart = (std::max)(tileStart, offset);
    const UInt64 overlapEnd = (std::min)(needEnd, writeEnd);
    if (overlapStart >= overlapEnd)
      return S_OK;

    CTile ready;
    bool isReady = false;

    {
      std::lock_guard<std::mutex> lock(_tileMutex);
      CTile &tile = _tiles[tileStart];
      const UInt32 needSize = (UInt32)(needEnd - tileStart);
      if (tile.Data.empty())
      {
        try
        {
          tile.Data.resize(needSize);
        }
        catch (...)
        {
          return E_OUTOFMEMORY;
        }
      }

      const UInt32 dst = (UInt32)(overlapStart - tileStart);
      const UInt32 src = (UInt32)(overlapStart - offset);
      const UInt32 len = (UInt32)(overlapEnd - overlapStart);
      memcpy(tile.Data.data() + dst, data + src, len);
      AddCoverage(tile.Ranges, dst, dst + len);

      if (tile.Ranges.size() == 1 &&
          tile.Ranges[0].first == 0 &&
          tile.Ranges[0].second == needSize)
      {
        ready = std::move(tile);
        _tiles.erase(tileStart);
        isReady = true;
      }
    }

    return isReady ? ProcessTile(tileStart, std::move(ready)) : S_OK;
  }

public:
  CPositionedLookAheadFilterOutStream(
      ISequentialOutStream *stream,
      CMethodId method,
      UInt32 pcInit,
      UInt64 totalSize):
      _sequential(stream),
      _positioned(sunpack::sevenzip::positioned_out_stream(stream)),
      _method(method),
      _pcInit(pcInit),
      _totalSize(totalSize),
      _alignment(PositionedFilterAlignment(method)),
      _lookAhead(PositionedFilterLookAhead(method)),
      _sequentialPos(0),
      _sequentialUsed(false)
  {}

  bool IsUsable() const
  {
    return _positioned && _positioned->positioned_available() &&
        _alignment != 0 && _lookAhead != 0;
  }

  bool positioned_available() const noexcept override
  {
    return !_sequentialUsed && IsUsable();
  }

  HRESULT write_at(
      UInt64 offset,
      const void *data,
      UInt32 size,
      UInt32 *processedSize) noexcept override
  {
    if (processedSize)
      *processedSize = 0;
    if (_sequentialUsed || !IsUsable() ||
        (size != 0 && !data) ||
        offset > _totalSize ||
        size > _totalSize - offset)
      return E_FAIL;
    if (size == 0)
      return S_OK;

    const Byte *src = (const Byte *)data;
    const UInt64 end = offset + size;
    UInt64 firstTile = offset / kTileSize;
    if (firstTile != 0)
      firstTile--;

    const UInt64 lastTile = (end - 1) / kTileSize;
    for (UInt64 tileIndex = firstTile; tileIndex <= lastTile; ++tileIndex)
    {
      const UInt64 tileStart = tileIndex * kTileSize;
      RINOK(FeedTile(tileStart, offset, src, size))
    }

    if (processedSize)
      *processedSize = size;
    return S_OK;
  }

  Z7_COM7F_IMF(Write(
      const void *data,
      UInt32 size,
      UInt32 *processedSize))
  {
    if (processedSize)
      *processedSize = 0;
    if (size != 0 && !data)
      return E_POINTER;

    std::lock_guard<std::mutex> lock(_sequentialMutex);
    if (!_sequentialUsed)
    {
      _sequentialUsed = true;
      {
        std::lock_guard<std::mutex> tileLock(_tileMutex);
        _tiles.clear();
      }
      _sequentialPending.clear();
      _sequentialPos = 0;
    }

    const Byte *src = (const Byte *)data;
    try
    {
      _sequentialPending.insert(
          _sequentialPending.end(), src, src + size);
    }
    catch (...)
    {
      return E_OUTOFMEMORY;
    }

    for (;;)
    {
      const size_t processed = ProcessPositionedFilter(
          _method,
          _sequentialPending.data(),
          _sequentialPending.size(),
          _pcInit + (UInt32)_sequentialPos);
      if (processed == 0)
        break;

      UInt32 written = 0;
      const HRESULT hres = _sequential->Write(
          _sequentialPending.data(),
          (UInt32)processed,
          &written);
      if (hres != S_OK || written != processed)
        return hres != S_OK ? hres : E_FAIL;

      _sequentialPos += written;
      _sequentialPending.erase(
          _sequentialPending.begin(),
          _sequentialPending.begin() + processed);

      if (_sequentialPending.size() <= _lookAhead)
        break;
    }

    if (processedSize)
      *processedSize = size;
    return S_OK;
  }

  HRESULT Finish()
  {
    std::lock_guard<std::mutex> seqLock(_sequentialMutex);

    if (_sequentialUsed)
    {
      if (!_sequentialPending.empty())
      {
        ProcessPositionedFilter(
            _method,
            _sequentialPending.data(),
            _sequentialPending.size(),
            _pcInit + (UInt32)_sequentialPos);

        UInt32 written = 0;
        const HRESULT hres = _sequential->Write(
            _sequentialPending.data(),
            (UInt32)_sequentialPending.size(),
            &written);
        if (hres != S_OK || written != _sequentialPending.size())
          return hres != S_OK ? hres : E_FAIL;
        _sequentialPos += written;
        _sequentialPending.clear();
      }
      return _sequentialPos == _totalSize ? S_OK : E_FAIL;
    }

    std::lock_guard<std::mutex> tileLock(_tileMutex);
    return _tiles.empty() ? S_OK : E_FAIL;
  }
};


static bool GetSimplePositionedFilterChain(
    const CFolderEx &folder,
    unsigned &lzma2Index,
    unsigned &filterIndex,
    UInt32 &filterPc)
{
  if (folder.Coders.Size() != 2 ||
      folder.Bonds.Size() != 1 ||
      folder.PackStreams.Size() != 1)
    return false;

  filterIndex = folder.UnpackCoder;
  if (filterIndex >= folder.Coders.Size())
    return false;

  lzma2Index = filterIndex == 0 ? 1 : 0;

  const CCoderInfo &lzma = folder.Coders[lzma2Index];
  const CCoderInfo &filter = folder.Coders[filterIndex];

  if (!lzma.IsSimpleCoder() ||
      !filter.IsSimpleCoder() ||
      lzma.MethodID != k_LZMA2 ||
      !PositionedFilterProps(filter, filterPc))
    return false;

  /*
    For two one-input/one-output coders, input stream indexes and output coder
    indexes are both 0/1. Require the exact LZMA2 -> filter topology and one
    external packed stream feeding LZMA2.
  */
  const CBond &bond = folder.Bonds[0];
  if (bond.UnpackIndex != lzma2Index ||
      bond.PackIndex != filterIndex ||
      folder.PackStreams[0] != lzma2Index)
    return false;

  return true;
}


namespace {

class CLimitedRandomReader final : public sunpack::sevenzip::RandomAccessReader
{
  std::unique_ptr<sunpack::sevenzip::RandomAccessReader> _base;
  UInt64 _start;
  UInt64 _size;

public:
  CLimitedRandomReader(
      std::unique_ptr<sunpack::sevenzip::RandomAccessReader> base,
      UInt64 start,
      UInt64 size):
      _base(std::move(base)),
      _start(start),
      _size(size)
  {}

  HRESULT read_at(
      UInt64 offset,
      void *data,
      UInt32 size,
      UInt32 *processedSize) noexcept override
  {
    if (processedSize)
      *processedSize = 0;
    if (!_base || (size != 0 && !data))
      return E_POINTER;
    if (offset >= _size || size == 0)
      return S_OK;

    const UInt64 rem = _size - offset;
    if (size > rem)
      size = (UInt32)rem;
    if (_start > (UInt64)(Int64)-1 - offset)
      return E_FAIL;
    return _base->read_at(_start + offset, data, size, processedSize);
  }
};


class CRandomLimitedSequentialInStream final :
  public CMyUnknownImp,
  public ISequentialInStream,
  public sunpack::sevenzip::RandomAccessInStream
{
  Z7_COM_UNKNOWN_IMP_1(ISequentialInStream)

  CMyComPtr<ISequentialInStream> _stream;
  CMyComPtr<IInStream> _randomOwner;
  sunpack::sevenzip::RandomAccessInStream *_random = NULL;
  UInt64 _start = 0;
  UInt64 _size = 0;
  UInt64 _pos = 0;
  bool _wasFinished = false;

public:
  void Init(
      ISequentialInStream *stream,
      IInStream *randomOwner,
      UInt64 start,
      UInt64 size)
  {
    _stream = stream;
    _randomOwner = randomOwner;
    _random = sunpack::sevenzip::random_access_in_stream(randomOwner);
    _start = start;
    _size = size;
    _pos = 0;
    _wasFinished = false;
  }

  Z7_COM7F_IMF(Read(void *data, UInt32 size, UInt32 *processedSize))
  {
    UInt32 realProcessedSize = 0;
    if (_pos < _size)
    {
      const UInt64 rem = _size - _pos;
      if (size > rem)
        size = (UInt32)rem;
    }
    else
      size = 0;

    HRESULT result = S_OK;
    if (size != 0)
    {
      result = _stream->Read(data, size, &realProcessedSize);
      _pos += realProcessedSize;
      if (realProcessedSize == 0)
        _wasFinished = true;
    }

    if (processedSize)
      *processedSize = realProcessedSize;
    return result;
  }

  std::unique_ptr<sunpack::sevenzip::RandomAccessReader>
  open_random_reader() noexcept override
  {
    if (!_random)
      return {};

    try
    {
      std::unique_ptr<sunpack::sevenzip::RandomAccessReader> base =
          _random->open_random_reader();
      if (!base)
        return {};
      return std::make_unique<CLimitedRandomReader>(
          std::move(base), _start, _size);
    }
    catch (...)
    {
      return {};
    }
  }
};

} // namespace

static HRESULT TryDecodeSimplePositionedFilter(
    IInStream *inStream,
    UInt64 startPos,
    const UInt64 *packPositions,
    const CFolderEx &folder,
    const UInt64 *coderUnpackSizes,
    ISequentialOutStream *outStream,
    ICompressProgressInfo *progress
    #if !defined(Z7_ST)
    , bool mtMode, UInt32 numThreads, UInt64 memUsage
    #endif
    )
{
  if (!inStream || !outStream)
    return E_NOTIMPL;

  sunpack::sevenzip::PositionedOutStream *positioned =
      sunpack::sevenzip::positioned_out_stream(outStream);
  if (!positioned || !positioned->positioned_available())
    return E_NOTIMPL;

  unsigned lzmaIndex = 0;
  unsigned filterIndex = 0;
  UInt32 filterPc = 0;
  if (!GetSimplePositionedFilterChain(
          folder, lzmaIndex, filterIndex, filterPc))
    return E_NOTIMPL;

  const CCoderInfo &lzma = folder.Coders[lzmaIndex];
  if (lzma.Props.Size() != 1)
    return E_NOTIMPL;

  const UInt64 packSize = packPositions[1] - packPositions[0];
  const UInt64 outSize = coderUnpackSizes[lzmaIndex];

  const UInt64 packedStart = startPos + packPositions[0];
  RINOK(InStream_SeekSet(inStream, packedStart))

  CMyComPtr<ISequentialInStream> limited;
  if (sunpack::sevenzip::random_access_in_stream(inStream))
  {
    CRandomLimitedSequentialInStream *spec =
        new CRandomLimitedSequentialInStream;
    spec->Init(inStream, inStream, packedStart, packSize);
    limited = spec;
  }
  else
  {
    CLimitedSequentialInStream *spec =
        new CLimitedSequentialInStream;
    spec->SetStream(inStream);
    spec->Init(packSize);
    limited = spec;
  }

  CMyComPtr<ICompressCoder> coder =
      new NCompress::NLzma2::CDecoder;

  {
    Z7_DECL_CMyComPtr_QI_FROM(
        ICompressSetDecoderProperties2,
        setProps, coder)
    if (!setProps)
      return E_NOTIMPL;
    RINOK(setProps->SetDecoderProperties2(
        (const Byte *)lzma.Props, (UInt32)lzma.Props.Size()))
  }

  {
    Z7_DECL_CMyComPtr_QI_FROM(
        ICompressSetFinishMode,
        setFinish, coder)
    if (setFinish)
      RINOK(setFinish->SetFinishMode(1))
  }

  #if !defined(Z7_ST)
  if (mtMode)
  {
    Z7_DECL_CMyComPtr_QI_FROM(
        ICompressSetCoderMt,
        setMt, coder)
    if (setMt)
      RINOK(setMt->SetNumberOfThreads(numThreads))

    Z7_DECL_CMyComPtr_QI_FROM(
        ICompressSetMemLimit,
        setMemLimit, coder)
    if (setMemLimit)
      RINOK(setMemLimit->SetMemLimit(memUsage))
  }
  #endif

  const CMethodId filterMethod =
      folder.Coders[filterIndex].MethodID;
  CMyComPtr<ISequentialOutStream> filtered;
  CPositionedAlignedFilterOutStream *alignedSpec = NULL;
  CPositionedLookAheadFilterOutStream *lookAheadSpec = NULL;

  if (PositionedFilterLookAhead(filterMethod) != 0)
  {
    lookAheadSpec = new CPositionedLookAheadFilterOutStream(
        outStream, filterMethod, filterPc, outSize);
    filtered = lookAheadSpec;
    if (!lookAheadSpec->IsUsable())
      return E_NOTIMPL;
  }
  else
  {
    alignedSpec = new CPositionedAlignedFilterOutStream(
        outStream, filterMethod, filterPc, outSize);
    filtered = alignedSpec;
    if (!alignedSpec->IsUsable())
      return E_NOTIMPL;
  }

  const HRESULT hres = coder->Code(
      limited, filtered, &packSize, &outSize, progress);
  if (hres != S_OK)
    return hres;

  return lookAheadSpec ? lookAheadSpec->Finish() : alignedSpec->Finish();
}

} // namespace



Z7_CLASS_IMP_COM_1(
  CDecProgress
  , ICompressProgressInfo
)
  CMyComPtr<ICompressProgressInfo> _progress;
public:
  CDecProgress(ICompressProgressInfo *progress): _progress(progress) {}
};

Z7_COM7F_IMF(CDecProgress::SetRatioInfo(const UInt64 * /* inSize */, const UInt64 *outSize))
{
  return _progress->SetRatioInfo(NULL, outSize);
}

static void Convert_FolderInfo_to_BindInfo(const CFolderEx &folder, CBindInfoEx &bi)
{
  bi.Clear();
  
  bi.Bonds.ClearAndSetSize(folder.Bonds.Size());
  unsigned i;
  for (i = 0; i < folder.Bonds.Size(); i++)
  {
    NCoderMixer2::CBond &bond = bi.Bonds[i];
    const N7z::CBond &folderBond = folder.Bonds[i];
    bond.PackIndex = folderBond.PackIndex;
    bond.UnpackIndex = folderBond.UnpackIndex;
  }

  bi.Coders.ClearAndSetSize(folder.Coders.Size());
  bi.CoderMethodIDs.ClearAndSetSize(folder.Coders.Size());
  for (i = 0; i < folder.Coders.Size(); i++)
  {
    const CCoderInfo &coderInfo = folder.Coders[i];
    bi.Coders[i].NumStreams = coderInfo.NumStreams;
    bi.CoderMethodIDs[i] = coderInfo.MethodID;
  }
  
  /*
  if (!bi.SetUnpackCoder())
    throw 1112;
  */
  bi.UnpackCoder = folder.UnpackCoder;
  bi.PackStreams.ClearAndSetSize(folder.PackStreams.Size());
  for (i = 0; i < folder.PackStreams.Size(); i++)
    bi.PackStreams[i] = folder.PackStreams[i];
}

static inline bool AreCodersEqual(
    const NCoderMixer2::CCoderStreamsInfo &a1,
    const NCoderMixer2::CCoderStreamsInfo &a2)
{
  return (a1.NumStreams == a2.NumStreams);
}

static inline bool AreBondsEqual(
    const NCoderMixer2::CBond &a1,
    const NCoderMixer2::CBond &a2)
{
  return
    (a1.PackIndex == a2.PackIndex) &&
    (a1.UnpackIndex == a2.UnpackIndex);
}

static bool AreBindInfoExEqual(const CBindInfoEx &a1, const CBindInfoEx &a2)
{
  if (a1.Coders.Size() != a2.Coders.Size())
    return false;
  unsigned i;
  for (i = 0; i < a1.Coders.Size(); i++)
    if (!AreCodersEqual(a1.Coders[i], a2.Coders[i]))
      return false;
  
  if (a1.Bonds.Size() != a2.Bonds.Size())
    return false;
  for (i = 0; i < a1.Bonds.Size(); i++)
    if (!AreBondsEqual(a1.Bonds[i], a2.Bonds[i]))
      return false;
  
  for (i = 0; i < a1.CoderMethodIDs.Size(); i++)
    if (a1.CoderMethodIDs[i] != a2.CoderMethodIDs[i])
      return false;
  
  if (a1.PackStreams.Size() != a2.PackStreams.Size())
    return false;
  for (i = 0; i < a1.PackStreams.Size(); i++)
    if (a1.PackStreams[i] != a2.PackStreams[i])
      return false;

  /*
  if (a1.UnpackCoder != a2.UnpackCoder)
    return false;
  */
  return true;
}

CDecoder::CDecoder(bool useMixerMT):
    _bindInfoPrev_Defined(false)
{
  #if defined(USE_MIXER_ST) && defined(USE_MIXER_MT)
  _useMixerMT = useMixerMT;
  #else
  UNUSED_VAR(useMixerMT)
  #endif
}


Z7_CLASS_IMP_COM_0(
  CLockedInStream
)
public:
  CMyComPtr<IInStream> Stream;
  UInt64 Pos;

  #ifdef USE_MIXER_MT
  NWindows::NSynchronization::CCriticalSection CriticalSection;
  #endif
};


#ifdef USE_MIXER_MT

Z7_CLASS_IMP_COM_1(
  CLockedSequentialInStreamMT
  , ISequentialInStream
)
  CLockedInStream *_glob;
  UInt64 _pos;
  CMyComPtr<IUnknown> _globRef;
public:
  void Init(CLockedInStream *lockedInStream, UInt64 startPos)
  {
    _globRef = lockedInStream;
    _glob = lockedInStream;
    _pos = startPos;
  }
};

Z7_COM7F_IMF(CLockedSequentialInStreamMT::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  NWindows::NSynchronization::CCriticalSectionLock lock(_glob->CriticalSection);

  if (_pos != _glob->Pos)
  {
    RINOK(InStream_SeekSet(_glob->Stream, _pos))
    _glob->Pos = _pos;
  }

  UInt32 realProcessedSize = 0;
  const HRESULT res = _glob->Stream->Read(data, size, &realProcessedSize);
  _pos += realProcessedSize;
  _glob->Pos = _pos;
  if (processedSize)
    *processedSize = realProcessedSize;
  return res;
}

#endif


#ifdef USE_MIXER_ST

Z7_CLASS_IMP_COM_1(
  CLockedSequentialInStreamST
  , ISequentialInStream
)
  CLockedInStream *_glob;
  UInt64 _pos;
  CMyComPtr<IUnknown> _globRef;
public:
  void Init(CLockedInStream *lockedInStream, UInt64 startPos)
  {
    _globRef = lockedInStream;
    _glob = lockedInStream;
    _pos = startPos;
  }
};

Z7_COM7F_IMF(CLockedSequentialInStreamST::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  if (_pos != _glob->Pos)
  {
    RINOK(InStream_SeekSet(_glob->Stream, _pos))
    _glob->Pos = _pos;
  }

  UInt32 realProcessedSize = 0;
  const HRESULT res = _glob->Stream->Read(data, size, &realProcessedSize);
  _pos += realProcessedSize;
  _glob->Pos = _pos;
  if (processedSize)
    *processedSize = realProcessedSize;
  return res;
}

#endif



HRESULT CDecoder::Decode(
    DECL_EXTERNAL_CODECS_LOC_VARS
    IInStream *inStream,
    UInt64 startPos,
    const CFolders &folders, unsigned folderIndex,
    const UInt64 *unpackSize

    , ISequentialOutStream *outStream
    , ICompressProgressInfo *compressProgress
    
    , ISequentialInStream **
        #ifdef USE_MIXER_ST
        inStreamMainRes
        #endif

    , bool &dataAfterEnd_Error
    
    Z7_7Z_DECODER_CRYPRO_VARS_DECL

    #if !defined(Z7_ST)
    , bool mtMode, UInt32 numThreads, UInt64 memUsage
    #endif
    )
{
  dataAfterEnd_Error = false;

  const UInt64 *packPositions = &folders.PackPositions[folders.FoStartPackStreamIndex[folderIndex]];
  CFolderEx folderInfo;
  folders.ParseFolderEx(folderIndex, folderInfo);

  if (!folderInfo.IsDecodingSupported())
    return E_NOTIMPL;

  CBindInfoEx bindInfo;
  Convert_FolderInfo_to_BindInfo(folderInfo, bindInfo);
  if (!bindInfo.CalcMapsAndCheck())
    return E_NOTIMPL;
  
  UInt64 folderUnpackSize = folders.GetFolderUnpackSize(folderIndex);
  bool fullUnpack = true;
  if (unpackSize)
  {
    if (*unpackSize > folderUnpackSize)
      return E_FAIL;
    fullUnpack = (*unpackSize == folderUnpackSize);
  }

  /*
    Simple LZMA2 -> position-only filters can stay fully parallel without an
    intermediate full run buffer. The filter is applied to independently
    addressable aligned cells and the final bytes are committed by logical
    offset. Stateful filters (x86 BCJ, Delta, BCJ2) deliberately remain on the
    legacy mixer path. ARMT/RISCV use bounded look-ahead tiles.
  */
  if (fullUnpack && outStream && !folderInfo.IsEncrypted())
  {
    const UInt32 unpackStreamIndexStart =
        folders.FoToCoderUnpackSizes[folderIndex];
    const HRESULT positionedFilterResult =
        TryDecodeSimplePositionedFilter(
            inStream,
            startPos,
            packPositions,
            folderInfo,
            &folders.CoderUnpackSizes[unpackStreamIndexStart],
            outStream,
            compressProgress
            #if !defined(Z7_ST)
            , mtMode, numThreads, memUsage
            #endif
            );
    if (positionedFilterResult != E_NOTIMPL)
      return positionedFilterResult;
  }

  /*
  We don't need to init isEncrypted and passwordIsDefined
  We must upgrade them only
  
  #ifndef Z7_NO_CRYPTO
  isEncrypted = false;
  passwordIsDefined = false;
  #endif
  */
  
  if (!_bindInfoPrev_Defined || !AreBindInfoExEqual(bindInfo, _bindInfoPrev))
  {
    _bindInfoPrev_Defined = false;
    _mixerRef.Release();

    #ifdef USE_MIXER_MT
    #ifdef USE_MIXER_ST
    if (_useMixerMT)
    #endif
    {
      _mixerMT = new NCoderMixer2::CMixerMT(false);
      _mixerRef = _mixerMT;
      _mixer = _mixerMT;
    }
    #ifdef USE_MIXER_ST
    else
    #endif
    #endif
    {
      #ifdef USE_MIXER_ST
      _mixerST = new NCoderMixer2::CMixerST(false);
      _mixerRef = _mixerST;
      _mixer = _mixerST;
      #endif
    }
    
    RINOK(_mixer->SetBindInfo(bindInfo))
    
    FOR_VECTOR(i, folderInfo.Coders)
    {
      const CCoderInfo &coderInfo = folderInfo.Coders[i];

      #ifndef Z7_SFX
      // we don't support RAR codecs here
      if ((coderInfo.MethodID >> 8) == 0x403)
        return E_NOTIMPL;
      #endif
  
      CCreatedCoder cod;
      RINOK(CreateCoder_Id(
          EXTERNAL_CODECS_LOC_VARS
          coderInfo.MethodID, false, cod))
    
      if (coderInfo.IsSimpleCoder())
      {
        if (!cod.Coder)
          return E_NOTIMPL;
        // CMethodId m = coderInfo.MethodID;
        // isFilter = (IsFilterMethod(m) || m == k_AES);
      }
      else
      {
        if (!cod.Coder2 || cod.NumStreams != coderInfo.NumStreams)
          return E_NOTIMPL;
      }
      _mixer->AddCoder(cod);
      
      // now there is no codec that uses another external codec
      /*
      #ifdef Z7_EXTERNAL_CODECS
      CMyComPtr<ISetCompressCodecsInfo> setCompressCodecsInfo;
      decoderUnknown.QueryInterface(IID_ISetCompressCodecsInfo, (void **)&setCompressCodecsInfo);
      if (setCompressCodecsInfo)
      {
        // we must use g_ExternalCodecs also
        RINOK(setCompressCodecsInfo->SetCompressCodecsInfo(_externalCodecs->GetCodecs));
      }
      #endif
      */
    }
    
    _bindInfoPrev = bindInfo;
    _bindInfoPrev_Defined = true;
  }

  RINOK(_mixer->ReInit2())
  
  UInt32 packStreamIndex = 0;
  UInt32 unpackStreamIndexStart = folders.FoToCoderUnpackSizes[folderIndex];

  unsigned i;

  #if !defined(Z7_ST)
  bool mt_wasUsed = false;
  #endif

  for (i = 0; i < folderInfo.Coders.Size(); i++)
  {
    const CCoderInfo &coderInfo = folderInfo.Coders[i];
    IUnknown *decoder = _mixer->GetCoder(i).GetUnknown();

    // now there is no codec that uses another external codec
    /*
    #ifdef Z7_EXTERNAL_CODECS
    {
      Z7_DECL_CMyComPtr_QI_FROM(ISetCompressCodecsInfo,
          setCompressCodecsInfo, decoder)
      if (setCompressCodecsInfo)
      {
        // we must use g_ExternalCodecs also
        RINOK(setCompressCodecsInfo->SetCompressCodecsInfo(_externalCodecs->GetCodecs))
      }
    }
    #endif
    */

    #if !defined(Z7_ST)
    if (!mt_wasUsed)
    {
      if (mtMode)
      {
        Z7_DECL_CMyComPtr_QI_FROM(ICompressSetCoderMt,
            setCoderMt, decoder)
        if (setCoderMt)
        {
          mt_wasUsed = true;
          RINOK(setCoderMt->SetNumberOfThreads(numThreads))
        }
      }
      // if (memUsage != 0)
      {
        Z7_DECL_CMyComPtr_QI_FROM(ICompressSetMemLimit,
            setMemLimit, decoder)
        if (setMemLimit)
        {
          mt_wasUsed = true;
          RINOK(setMemLimit->SetMemLimit(memUsage))
        }
      }
    }
    #endif

    {
      Z7_DECL_CMyComPtr_QI_FROM(
          ICompressSetDecoderProperties2,
          setDecoderProperties, decoder)
      const CByteBuffer &props = coderInfo.Props;
      const UInt32 size32 = (UInt32)props.Size();
      if (props.Size() != size32)
        return E_NOTIMPL;
      if (setDecoderProperties)
      {
        HRESULT res = setDecoderProperties->SetDecoderProperties2((const Byte *)props, size32);
        if (res == E_INVALIDARG)
          res = E_NOTIMPL;
        RINOK(res)
      }
      else if (size32 != 0)
      {
        // v23: we fail, if decoder doesn't support properties
        return E_NOTIMPL;
      }
    }

    #ifndef Z7_NO_CRYPTO
    {
      Z7_DECL_CMyComPtr_QI_FROM(
          ICryptoSetPassword,
          cryptoSetPassword, decoder)
      if (cryptoSetPassword)
      {
        isEncrypted = true;
        if (!getTextPassword)
          return E_NOTIMPL;
        CMyComBSTR_Wipe passwordBSTR;
        RINOK(getTextPassword->CryptoGetTextPassword(&passwordBSTR))
        passwordIsDefined = true;
        password.Wipe_and_Empty();
        size_t len = 0;
        if (passwordBSTR)
        {
          password = passwordBSTR;
          len = password.Len();
        }
        CByteBuffer_Wipe buffer(len * 2);
        const LPCOLESTR psw = passwordBSTR;
        for (size_t k = 0; k < len; k++)
        {
          const wchar_t c = psw[k];
          ((Byte *)buffer)[k * 2] = (Byte)c;
          ((Byte *)buffer)[k * 2 + 1] = (Byte)(c >> 8);
        }
        RINOK(cryptoSetPassword->CryptoSetPassword((const Byte *)buffer, (UInt32)buffer.Size()))
      }
    }
    #endif

    bool finishMode = false;
    {
      Z7_DECL_CMyComPtr_QI_FROM(
          ICompressSetFinishMode,
          setFinishMode, decoder)
      if (setFinishMode)
      {
        finishMode = fullUnpack;
        RINOK(setFinishMode->SetFinishMode(BoolToUInt(finishMode)))
      }
    }
    
    UInt32 numStreams = (UInt32)coderInfo.NumStreams;
    
    CObjArray<UInt64> packSizes(numStreams);
    CObjArray<const UInt64 *> packSizesPointers(numStreams);
       
    for (UInt32 j = 0; j < numStreams; j++, packStreamIndex++)
    {
      int bond = folderInfo.FindBond_for_PackStream(packStreamIndex);
      
      if (bond >= 0)
        packSizesPointers[j] = &folders.CoderUnpackSizes[unpackStreamIndexStart + folderInfo.Bonds[(unsigned)bond].UnpackIndex];
      else
      {
        int index = folderInfo.Find_in_PackStreams(packStreamIndex);
        if (index < 0)
          return E_NOTIMPL;
        packSizes[j] = packPositions[(unsigned)index + 1] - packPositions[(unsigned)index];
        packSizesPointers[j] = &packSizes[j];
      }
    }

    const UInt64 *unpackSizesPointer =
        (unpackSize && i == bindInfo.UnpackCoder) ?
            unpackSize :
            &folders.CoderUnpackSizes[unpackStreamIndexStart + i];
    
    _mixer->SetCoderInfo(i, unpackSizesPointer, packSizesPointers, finishMode);
  }

  if (outStream)
  {
    _mixer->SelectMainCoder(!fullUnpack);
  }

  CObjectVector< CMyComPtr<ISequentialInStream> > inStreams;
  
  CMyComPtr2_Create<IUnknown, CLockedInStream> lockedInStream;

  #ifdef USE_MIXER_MT
  #ifdef USE_MIXER_ST
  bool needMtLock = _useMixerMT;
  #endif
  #endif

  if (folderInfo.PackStreams.Size() > 1)
  {
    // lockedInStream.Pos = (UInt64)(Int64)-1;
    // RINOK(InStream_GetPos(inStream, lockedInStream.Pos))
    RINOK(inStream->Seek((Int64)(startPos + packPositions[0]), STREAM_SEEK_SET, &lockedInStream->Pos))
    lockedInStream->Stream = inStream;

    #ifdef USE_MIXER_MT
    #ifdef USE_MIXER_ST
    /*
      For ST-mixer mode:
      If parallel input stream reading from pack streams is possible,
      we must use MT-lock for packed streams.
      Internal decoders in 7-Zip will not read pack streams in parallel in ST-mixer mode.
      So we force to needMtLock mode only if there is unknown (external) decoder.
    */
    if (!needMtLock && _mixer->IsThere_ExternalCoder_in_PackTree(_mixer->MainCoderIndex))
      needMtLock = true;
    #endif
    #endif
  }

  for (unsigned j = 0; j < folderInfo.PackStreams.Size(); j++)
  {
    CMyComPtr<ISequentialInStream> packStream;
    const UInt64 packPos = startPos + packPositions[j];

    if (folderInfo.PackStreams.Size() == 1)
    {
      RINOK(InStream_SeekSet(inStream, packPos))
      packStream = inStream;
    }
    else
    {
      #ifdef USE_MIXER_MT
      #ifdef USE_MIXER_ST
      if (needMtLock)
      #endif
      {
        CLockedSequentialInStreamMT *lockedStreamImpSpec = new CLockedSequentialInStreamMT;
        packStream = lockedStreamImpSpec;
        lockedStreamImpSpec->Init(lockedInStream.ClsPtr(), packPos);
      }
      #ifdef USE_MIXER_ST
      else
      #endif
      #endif
      {
        #ifdef USE_MIXER_ST
        CLockedSequentialInStreamST *lockedStreamImpSpec = new CLockedSequentialInStreamST;
        packStream = lockedStreamImpSpec;
        lockedStreamImpSpec->Init(lockedInStream.ClsPtr(), packPos);
        #endif
      }
    }

    const UInt64 packSize = packPositions[j + 1] - packPositions[j];
    if (sunpack::sevenzip::random_access_in_stream(inStream))
    {
      CRandomLimitedSequentialInStream *streamSpec =
          new CRandomLimitedSequentialInStream;
      inStreams.AddNew() = streamSpec;
      streamSpec->Init(packStream, inStream, packPos, packSize);
    }
    else
    {
      CLimitedSequentialInStream *streamSpec = new CLimitedSequentialInStream;
      inStreams.AddNew() = streamSpec;
      streamSpec->SetStream(packStream);
      streamSpec->Init(packSize);
    }
  }
  
  const unsigned num = inStreams.Size();
  CObjArray<ISequentialInStream *> inStreamPointers(num);
  for (i = 0; i < num; i++)
    inStreamPointers[i] = inStreams[i];

  if (outStream)
  {
    CMyComPtr<ICompressProgressInfo> progress2;
    if (compressProgress && !_mixer->Is_PackSize_Correct_for_Coder(_mixer->MainCoderIndex))
      progress2 = new CDecProgress(compressProgress);

    ISequentialOutStream *outStreamPointer = outStream;
    return _mixer->Code(inStreamPointers, &outStreamPointer,
        progress2 ? (ICompressProgressInfo *)progress2 : compressProgress,
        dataAfterEnd_Error);
  }
  
  #ifdef USE_MIXER_ST
    return _mixerST->GetMainUnpackStream(inStreamPointers, inStreamMainRes);
  #else
    return E_FAIL;
  #endif
}

}}
