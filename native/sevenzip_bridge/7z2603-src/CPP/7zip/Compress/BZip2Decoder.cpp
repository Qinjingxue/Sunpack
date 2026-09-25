// BZip2Decoder.cpp

#include "StdAfx.h"

#ifndef Z7_ST
#include <algorithm>
#include <array>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <vector>
#endif

// #include "CopyCoder.h"

/*
#include <stdio.h>
#include "../../../C/CpuTicks.h"
*/
#define TICKS_START
#define TICKS_UPDATE(n)


/*
#define PRIN(s) printf(s "\n"); fflush(stdout);
#define PRIN_VAL(s, val) printf(s " = %u \n", val); fflush(stdout);
*/

#define PRIN(s)
#define PRIN_VAL(s, val)


#include "../../../C/Alloc.h"

#include "../Common/StreamUtils.h"

#include "BZip2Decoder.h"
#include "internal/decoder_cpu_budget.h"


namespace NCompress {
namespace NBZip2 {

// #undef NO_INLINE
#define NO_INLINE Z7_NO_INLINE

#define BZIP2_BYTE_MODE


static const UInt32 kInBufSize = (UInt32)1 << 17;
static const size_t kOutBufSize = (size_t)1 << 20;

static const UInt32 kProgressStep = (UInt32)1 << 16;

MY_ALIGN(64)
static const UInt16 kRandNums[512] = {
   619, 720, 127, 481, 931, 816, 813, 233, 566, 247,
   985, 724, 205, 454, 863, 491, 741, 242, 949, 214,
   733, 859, 335, 708, 621, 574, 73, 654, 730, 472,
   419, 436, 278, 496, 867, 210, 399, 680, 480, 51,
   878, 465, 811, 169, 869, 675, 611, 697, 867, 561,
   862, 687, 507, 283, 482, 129, 807, 591, 733, 623,
   150, 238, 59, 379, 684, 877, 625, 169, 643, 105,
   170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
   73, 122, 335, 530, 442, 853, 695, 249, 445, 515,
   909, 545, 703, 919, 874, 474, 882, 500, 594, 612,
   641, 801, 220, 162, 819, 984, 589, 513, 495, 799,
   161, 604, 958, 533, 221, 400, 386, 867, 600, 782,
   382, 596, 414, 171, 516, 375, 682, 485, 911, 276,
   98, 553, 163, 354, 666, 933, 424, 341, 533, 870,
   227, 730, 475, 186, 263, 647, 537, 686, 600, 224,
   469, 68, 770, 919, 190, 373, 294, 822, 808, 206,
   184, 943, 795, 384, 383, 461, 404, 758, 839, 887,
   715, 67, 618, 276, 204, 918, 873, 777, 604, 560,
   951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
   652, 934, 970, 447, 318, 353, 859, 672, 112, 785,
   645, 863, 803, 350, 139, 93, 354, 99, 820, 908,
   609, 772, 154, 274, 580, 184, 79, 626, 630, 742,
   653, 282, 762, 623, 680, 81, 927, 626, 789, 125,
   411, 521, 938, 300, 821, 78, 343, 175, 128, 250,
   170, 774, 972, 275, 999, 639, 495, 78, 352, 126,
   857, 956, 358, 619, 580, 124, 737, 594, 701, 612,
   669, 112, 134, 694, 363, 992, 809, 743, 168, 974,
   944, 375, 748, 52, 600, 747, 642, 182, 862, 81,
   344, 805, 988, 739, 511, 655, 814, 334, 249, 515,
   897, 955, 664, 981, 649, 113, 974, 459, 893, 228,
   433, 837, 553, 268, 926, 240, 102, 654, 459, 51,
   686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
   946, 670, 656, 610, 738, 392, 760, 799, 887, 653,
   978, 321, 576, 617, 626, 502, 894, 679, 243, 440,
   680, 879, 194, 572, 640, 724, 926, 56, 204, 700,
   707, 151, 457, 449, 797, 195, 791, 558, 945, 679,
   297, 59, 87, 824, 713, 663, 412, 693, 342, 606,
   134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
   343, 97, 430, 751, 497, 314, 983, 374, 822, 928,
   140, 206, 73, 263, 980, 736, 876, 478, 430, 305,
   170, 514, 364, 692, 829, 82, 855, 953, 676, 246,
   369, 970, 294, 750, 807, 827, 150, 790, 288, 923,
   804, 378, 215, 828, 592, 281, 565, 555, 710, 82,
   896, 831, 547, 261, 524, 462, 293, 465, 502, 56,
   661, 821, 976, 991, 658, 869, 905, 758, 745, 193,
   768, 550, 608, 933, 378, 286, 215, 979, 792, 961,
   61, 688, 793, 644, 986, 403, 106, 366, 905, 644,
   372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
   780, 773, 635, 389, 707, 100, 626, 958, 165, 504,
   920, 176, 193, 713, 857, 265, 203, 50, 668, 108,
   645, 990, 626, 197, 510, 357, 358, 850, 858, 364,
   936, 638
};



enum EState
{
  STATE_STREAM_SIGNATURE,
  STATE_BLOCK_SIGNATURE,

  STATE_BLOCK_START,
  STATE_ORIG_BITS,
  STATE_IN_USE,
  STATE_IN_USE2,
  STATE_NUM_TABLES,
  STATE_NUM_SELECTORS,
  STATE_SELECTORS,
  STATE_LEVELS,
  
  STATE_BLOCK_SYMBOLS,

  STATE_STREAM_FINISHED
};


#define UPDATE_VAL_2(val, num_bits) { \
  val |= (UInt32)(*_buf) << (24 - num_bits); \
  num_bits += 8; \
 _buf++; \
}

#define UPDATE_VAL  UPDATE_VAL_2(VAL, NUM_BITS)

#define READ_BITS(res, num) { \
  while (_numBits < num) { \
    if (_buf == _lim) return SZ_OK; \
    UPDATE_VAL_2(_value, _numBits) } \
  res = _value >> (32 - num); \
  _value <<= num; \
  _numBits -= num; \
}

#define READ_BITS_8(res, num) { \
  if (_numBits < num) { \
    if (_buf == _lim) return SZ_OK; \
    UPDATE_VAL_2(_value, _numBits) } \
  res = _value >> (32 - num); \
  _value <<= num; \
  _numBits -= num; \
}

#define READ_BIT(res) READ_BITS_8(res, 1)



#define VAL _value2
// #define NUM_BITS _numBits2
#define NUM_BITS _numBits
#define BLOCK_SIZE blockSize2
#define RUN_COUNTER runCounter2

#define LOAD_LOCAL \
    UInt32 VAL = this->_value; \
    /* unsigned NUM_BITS = this->_numBits; */ \
    UInt32 BLOCK_SIZE = this->blockSize; \
    UInt32 RUN_COUNTER = this->runCounter; \

#define SAVE_LOCAL \
    this->_value = VAL; \
    /* this->_numBits = NUM_BITS; */ \
    this->blockSize = BLOCK_SIZE; \
    this->runCounter = RUN_COUNTER; \



SRes CBitDecoder::ReadByte(int &b)
{
  b = -1;
  READ_BITS_8(b, 8)
  return SZ_OK;
}


NO_INLINE
SRes CBase::ReadStreamSignature2()
{
  for (;;)
  {
    unsigned b;
    READ_BITS_8(b, 8)

    if (   (state2 == 0 && b != kArSig0)
        || (state2 == 1 && b != kArSig1)
        || (state2 == 2 && b != kArSig2)
        || (state2 == 3 && (b <= kArSig3 || b > kArSig3 + kBlockSizeMultMax)))
      return SZ_ERROR_DATA;
    state2++;

    if (state2 == 4)
    {
      blockSizeMax = (UInt32)(b - kArSig3) * kBlockSizeStep;
      CombinedCrc.Init();
      state = STATE_BLOCK_SIGNATURE;
      state2 = 0;
      return SZ_OK;
    }
  }
}


bool IsEndSig(const Byte *p) throw()
{
  return
    p[0] == kFinSig0 &&
    p[1] == kFinSig1 &&
    p[2] == kFinSig2 &&
    p[3] == kFinSig3 &&
    p[4] == kFinSig4 &&
    p[5] == kFinSig5;
}

bool IsBlockSig(const Byte *p) throw()
{
  return
    p[0] == kBlockSig0 &&
    p[1] == kBlockSig1 &&
    p[2] == kBlockSig2 &&
    p[3] == kBlockSig3 &&
    p[4] == kBlockSig4 &&
    p[5] == kBlockSig5;
}


NO_INLINE
SRes CBase::ReadBlockSignature2()
{
  while (state2 < 10)
  {
    unsigned b;
    READ_BITS_8(b, 8)
    temp[state2] = (Byte)b;
    state2++;
  }

  crc = 0;
  for (unsigned i = 0; i < 4; i++)
  {
    crc <<= 8;
    crc |= temp[6 + i];
  }

  if (IsBlockSig(temp))
  {
    if (!IsBz)
      NumStreams++;
    NumBlocks++;
    IsBz = true;
    CombinedCrc.Update(crc);
    state = STATE_BLOCK_START;
    return SZ_OK;
  }
  
  if (!IsEndSig(temp))
    return SZ_ERROR_DATA;

  if (!IsBz)
    NumStreams++;
  IsBz = true;

  if (_value != 0)
    MinorError = true;

  AlignToByte();

  state = STATE_STREAM_FINISHED;
  if (crc != CombinedCrc.GetDigest())
  {
    StreamCrcError = true;
    return SZ_ERROR_DATA;
  }
  return SZ_OK;
}


NO_INLINE
SRes CBase::ReadBlock2()
{
  if (state != STATE_BLOCK_SYMBOLS) {
  PRIN("ReadBlock2")

  if (state == STATE_BLOCK_START)
  {
    if (Props.randMode)
    {
      READ_BIT(Props.randMode)
    }
    state = STATE_ORIG_BITS;
    // g_Tick = GetCpuTicks();
  }

  if (state == STATE_ORIG_BITS)
  {
    READ_BITS(Props.origPtr, kNumOrigBits)
    if (Props.origPtr >= blockSizeMax)
      return SZ_ERROR_DATA;
    state = STATE_IN_USE;
  }
  
  // why original code compares origPtr to (UInt32)(10 + blockSizeMax)) ?

  if (state == STATE_IN_USE)
  {
    READ_BITS(state2, 16)
    state = STATE_IN_USE2;
    state3 = 0;
    numInUse = 0;
    mtf.StartInit();
  }

  if (state == STATE_IN_USE2)
  {
    for (; state3 < 256; state3++)
      if (state2 & ((UInt32)0x8000 >> (state3 >> 4)))
      {
        unsigned b;
        READ_BIT(b)
        if (b)
          mtf.Add(numInUse++, (Byte)state3);
      }
    if (numInUse == 0)
      return SZ_ERROR_DATA;
    state = STATE_NUM_TABLES;
  }

  
  if (state == STATE_NUM_TABLES)
  {
    READ_BITS_8(numTables, kNumTablesBits)
    state = STATE_NUM_SELECTORS;
    if (numTables < kNumTablesMin || numTables > kNumTablesMax)
      return SZ_ERROR_DATA;
  }
  
  if (state == STATE_NUM_SELECTORS)
  {
    READ_BITS(numSelectors, kNumSelectorsBits)
    state = STATE_SELECTORS;
    state2 = 0x543210;
    state3 = 0;
    state4 = 0;
    // lbzip2 can write small number of additional selectors,
    // 20.01: we allow big number of selectors here like bzip2-1.0.8
    if (numSelectors == 0
      // || numSelectors > kNumSelectorsMax_Decoder
      )
      return SZ_ERROR_DATA;
  }

  if (state == STATE_SELECTORS)
  {
    const unsigned kMtfBits = 4;
    const UInt32 kMtfMask = (1 << kMtfBits) - 1;
    do
    {
      for (;;)
      {
        unsigned b;
        READ_BIT(b)
        if (!b)
          break;
        if (++state4 >= numTables)
          return SZ_ERROR_DATA;
      }
      const UInt32 tmp = (state2 >> (kMtfBits * state4)) & kMtfMask;
      const UInt32 mask = ((UInt32)1 << ((state4 + 1) * kMtfBits)) - 1;
      state4 = 0;
      state2 = ((state2 << kMtfBits) & mask) | (state2 & ~mask) | tmp;
      // 20.01: here we keep compatibility with bzip2-1.0.8 decoder:
      if (state3 < kNumSelectorsMax)
        selectors[state3] = (Byte)tmp;
    }
    while (++state3 < numSelectors);

    // we allowed additional dummy selector records filled above to support lbzip2's archives.
    // but we still don't allow to use these additional dummy selectors in the code bellow
    // bzip2 1.0.8 decoder also has similar restriction.

    if (numSelectors > kNumSelectorsMax)
      numSelectors = kNumSelectorsMax;

    state = STATE_LEVELS;
    state2 = 0;
    state3 = 0;
  }

  if (state == STATE_LEVELS)
  {
    do
    {
      if (state3 == 0)
      {
        READ_BITS_8(state3, kNumLevelsBits)
        state4 = 0;
        state5 = 0;
      }
      const unsigned alphaSize = numInUse + 2;
      for (; state4 < alphaSize; state4++)
      {
        for (;;)
        {
          if (state3 < 1 || state3 > kMaxHuffmanLen)
            return SZ_ERROR_DATA;
          
          if (state5 == 0)
          {
            unsigned b;
            READ_BIT(b)
            if (!b)
              break;
          }

          state5 = 1;
          unsigned b;
          READ_BIT(b)

          state5 = 0;
          state3++;
          state3 -= (b << 1);
        }
        lens[state4] = (Byte)state3;
        state5 = 0;
      }
      
      // 19.03: we use non-full Build() to support lbzip2 archives.
      // lbzip2 2.5 can produce dummy tree, where lens[i] = kMaxHuffmanLen
      for (unsigned i = state4; i < kMaxAlphaSize; i++)
        lens[i] = 0;
      if (!huffs[state2].Build(lens)) // k_BuildMode_Partial
        return SZ_ERROR_DATA;
      state3 = 0;
    }
    while (++state2 < numTables);

    {
      UInt32 *counters = this->Counters;
      for (unsigned i = 0; i < 256; i++)
        counters[i] = 0;
    }

    state = STATE_BLOCK_SYMBOLS;

    groupIndex = 0;
    groupSize = kGroupSize;
    runPower = 0;
    runCounter = 0;
    blockSize = 0;
  }
  
  if (state != STATE_BLOCK_SYMBOLS)
    return SZ_ERROR_DATA;

  // g_Ticks[3] += GetCpuTicks() - g_Tick;

  }

  {
    LOAD_LOCAL
    const CHuffmanDecoder *huf = &huffs[selectors[groupIndex]];

    for (;;)
    {
      if (groupSize == 0)
      {
        if (++groupIndex >= numSelectors)
          return SZ_ERROR_DATA;
        huf = &huffs[selectors[groupIndex]];
        groupSize = kGroupSize;
      }

      if (NUM_BITS < kMaxHuffmanLen && _buf != _lim) { UPDATE_VAL
      if (NUM_BITS < kMaxHuffmanLen && _buf != _lim) { UPDATE_VAL
      if (NUM_BITS < kMaxHuffmanLen && _buf != _lim) { UPDATE_VAL }}}

      unsigned sym;

      #define MOV_POS(bs, len) \
      { \
        if (NUM_BITS < len) \
        { \
          SAVE_LOCAL \
          return SZ_OK; \
        } \
        VAL <<= len; \
        NUM_BITS -= (unsigned)len; \
      }

      Z7_HUFF_DECODE_VAL_IN_HIGH32(sym, huf, kMaxHuffmanLen, kNumTableBits,
          VAL,
          Z7_HUFF_DECODE_ERROR_SYM_CHECK_YES,
          { return SZ_ERROR_DATA; },
          MOV_POS, {}, bs)

      groupSize--;

      if (sym < 2)
      {
        RUN_COUNTER += (UInt32)(sym + 1) << runPower;
        runPower++;
        if (blockSizeMax - BLOCK_SIZE < RUN_COUNTER)
          return SZ_ERROR_DATA;
        continue;
      }

      UInt32 *counters = this->Counters;
      if (RUN_COUNTER != 0)
      {
        UInt32 b = (UInt32)(mtf.Buf[0] & 0xFF);
        counters[b] += RUN_COUNTER;
        runPower = 0;
        #ifdef BZIP2_BYTE_MODE
          Byte *dest = (Byte *)(&counters[256 + kBlockSizeMax]) + BLOCK_SIZE;
          const Byte *limit = dest + RUN_COUNTER;
          BLOCK_SIZE += RUN_COUNTER;
          RUN_COUNTER = 0;
          do
          {
            dest[0] = (Byte)b;
            dest[1] = (Byte)b;
            dest[2] = (Byte)b;
            dest[3] = (Byte)b;
            dest += 4;
          }
          while (dest < limit);
        #else
          UInt32 *dest = &counters[256 + BLOCK_SIZE];
          const UInt32 *limit = dest + RUN_COUNTER;
          BLOCK_SIZE += RUN_COUNTER;
          RUN_COUNTER = 0;
          do
          {
            dest[0] = b;
            dest[1] = b;
            dest[2] = b;
            dest[3] = b;
            dest += 4;
          }
          while (dest < limit);
        #endif
      }
      
      sym -= 1;
      if (sym < numInUse)
      {
        if (BLOCK_SIZE >= blockSizeMax)
          return SZ_ERROR_DATA;

        // UInt32 b = (UInt32)mtf.GetAndMove((unsigned)sym);

        const unsigned lim = sym >> Z7_MTF_MOVS;
        const unsigned pos = (sym & Z7_MTF_MASK) << 3;
        CMtfVar next = mtf.Buf[lim];
        CMtfVar prev = (next >> pos) & 0xFF;
        
        #ifdef BZIP2_BYTE_MODE
          ((Byte *)(counters + 256 + kBlockSizeMax))[BLOCK_SIZE++] = (Byte)prev;
        #else
          (counters + 256)[BLOCK_SIZE++] = (UInt32)prev;
        #endif
        counters[prev]++;

        CMtfVar *m = mtf.Buf;
        CMtfVar *mLim = m + lim;
        if (lim != 0)
        {
          do
          {
            CMtfVar n0 = *m;
            *m = (n0 << 8) | prev;
            prev = (n0 >> (Z7_MTF_MASK << 3));
          }
          while (++m != mLim);
        }

        CMtfVar mask = (((CMtfVar)0x100 << pos) - 1);
        *mLim = (next & ~mask) | (((next << 8) | prev) & mask);
        continue;
      }
      
      if (sym != numInUse)
        return SZ_ERROR_DATA;
      break;
    }

    // we write additional item that will be read in DecodeBlock1 for prefetching
    #ifdef BZIP2_BYTE_MODE
      ((Byte *)(Counters + 256 + kBlockSizeMax))[BLOCK_SIZE] = 0;
    #else
      (counters + 256)[BLOCK_SIZE] = 0;
    #endif

    SAVE_LOCAL
    Props.blockSize = blockSize;
    state = STATE_BLOCK_SIGNATURE;
    state2 = 0;

    PRIN_VAL("origPtr", Props.origPtr);
    PRIN_VAL("blockSize", Props.blockSize);

    return (Props.origPtr < Props.blockSize) ? SZ_OK : SZ_ERROR_DATA;
  }
}


NO_INLINE
static void DecodeBlock1(UInt32 *counters, UInt32 blockSize)
{
  {
    UInt32 sum = 0;
    for (UInt32 i = 0; i < 256; i++)
    {
      const UInt32 v = counters[i];
      counters[i] = sum;
      sum += v;
    }
  }
  
  UInt32 *tt = counters + 256;
  // Compute the T^(-1) vector

  // blockSize--;

  #ifdef BZIP2_BYTE_MODE

  unsigned c = ((const Byte *)(tt + kBlockSizeMax))[0];
  
  for (UInt32 i = 0; i < blockSize; i++)
  {
    unsigned c1 = c;
    const UInt32 pos = counters[c];
    c = ((const Byte *)(tt + kBlockSizeMax))[(size_t)i + 1];
    counters[c1] = pos + 1;
    tt[pos] = (i << 8) | ((const Byte *)(tt + kBlockSizeMax))[pos];
  }

  /*
  // last iteration without next character prefetching
  {
    const UInt32 pos = counters[c];
    counters[c] = pos + 1;
    tt[pos] = (blockSize << 8) | ((const Byte *)(tt + kBlockSizeMax))[pos];
  }
  */

  #else

  unsigned c = (unsigned)(tt[0] & 0xFF);
  
  for (UInt32 i = 0; i < blockSize; i++)
  {
    unsigned c1 = c;
    const UInt32 pos = counters[c];
    c = (unsigned)(tt[(size_t)i + 1] & 0xFF);
    counters[c1] = pos + 1;
    tt[pos] |= (i << 8);
  }

  /*
  {
    const UInt32 pos = counters[c];
    counters[c] = pos + 1;
    tt[pos] |= (blockSize << 8);
  }
  */

  #endif


  /*
  for (UInt32 i = 0; i < blockSize; i++)
  {
    #ifdef BZIP2_BYTE_MODE
      const unsigned c = ((const Byte *)(tt + kBlockSizeMax))[i];
      const UInt32 pos = counters[c]++;
      tt[pos] = (i << 8) | ((const Byte *)(tt + kBlockSizeMax))[pos];
    #else
      const unsigned c = (unsigned)(tt[i] & 0xFF);
      const UInt32 pos = counters[c]++;
      tt[pos] |= (i << 8);
    #endif
  }
  */
}


void CSpecState::Init(UInt32 origPtr, unsigned randMode) throw()
{
  _tPos = _tt[_tt[origPtr] >> 8];
   _prevByte = (unsigned)(_tPos & 0xFF);
  _reps = 0;
  _randIndex = 0;
  _randToGo = -1;
  if (randMode)
  {
    _randIndex = 1;
    _randToGo = kRandNums[0] - 2;
  }
  _crc.Init();
}



NO_INLINE
Byte * CSpecState::Decode(Byte *data, size_t size) throw()
{
  if (size == 0)
    return data;

  unsigned prevByte = _prevByte;
  int reps = _reps;
  CBZip2Crc crc = _crc;
  const Byte *lim = data + size;

  while (reps > 0)
  {
    reps--;
    *data++ = (Byte)prevByte;
    crc.UpdateByte(prevByte);
    if (data == lim)
      break;
  }

  UInt32 tPos = _tPos;
  UInt32 blockSize = _blockSize;
  const UInt32 *tt = _tt;

  if (data != lim && blockSize)

  for (;;)
  {
    unsigned b = (unsigned)(tPos & 0xFF);
    tPos = tt[tPos >> 8];
    blockSize--;

    if (_randToGo >= 0)
    {
      if (_randToGo == 0)
      {
        b ^= 1;
        _randToGo = kRandNums[_randIndex];
        _randIndex++;
        _randIndex &= 0x1FF;
      }
      _randToGo--;
    }

    if (reps != -(int)kRleModeRepSize)
    {
      if (b != prevByte)
        reps = 0;
      reps--;
      prevByte = b;
      *data++ = (Byte)b;
      crc.UpdateByte(b);
      if (data == lim || blockSize == 0)
        break;
      continue;
    }

    reps = (int)b;
    while (reps)
    {
      reps--;
      *data++ = (Byte)prevByte;
      crc.UpdateByte(prevByte);
      if (data == lim)
        break;
    }
    if (data == lim)
      break;
    if (blockSize == 0)
      break;
  }

  if (blockSize == 1 && reps == -(int)kRleModeRepSize)
  {
    unsigned b = (unsigned)(tPos & 0xFF);
    tPos = tt[tPos >> 8];
    blockSize--;

    if (_randToGo >= 0)
    {
      if (_randToGo == 0)
      {
        b ^= 1;
        _randToGo = kRandNums[_randIndex];
        _randIndex++;
        _randIndex &= 0x1FF;
      }
      _randToGo--;
    }

    reps = (int)b;
  }

  _tPos = tPos;
  _prevByte = prevByte;
  _reps = reps;
  _crc = crc;
  _blockSize = blockSize;
  
  return data;
}


#ifndef Z7_ST

static const unsigned kStreamingBZipMaxLanes = 4;
static const size_t kStreamingBZipReadChunk = (size_t)1 << 18;  // 256 KiB.
static const size_t kStreamingBZipCommitChunk = (size_t)1 << 18;
static const UInt64 kStreamingBZipBlockMagic = UINT64_C(0x314159265359);
static const UInt64 kStreamingBZipEndMagic = UINT64_C(0x177245385090);
static const UInt64 kStreamingBZipMagicMask = UINT64_C(0x0000FFFFFFFFFFFF);
// A valid block contains at most kBlockSizeMax decoded Huffman symbols and
// each symbol is at most kMaxHuffmanLen bits. Leave generous metadata slack.
static const UInt64 kStreamingBZipEncodedLookahead =
    ((UInt64)kBlockSizeMax * kMaxHuffmanLen + 7) / 8 + ((UInt64)1 << 16);


struct CStreamingBZipMarker
{
  UInt64 BitOffset;
  bool IsEnd;

  CStreamingBZipMarker(UInt64 bitOffset, bool isEnd):
      BitOffset(bitOffset),
      IsEnd(isEnd)
  {}
};


static const std::array<Byte, 1u << 16> &StreamingBZipPrefixTable()
{
  static const std::array<Byte, 1u << 16> table = []()
  {
    std::array<Byte, 1u << 16> t = {};

    for (unsigned word = 0; word < (1u << 16); word++)
    {
      Byte shifts = 0;
      for (unsigned shift = 0; shift < 8; shift++)
      {
        const unsigned bits = 16 - shift;
        const unsigned mask = (1u << bits) - 1;
        const unsigned actual = word & mask;
        const UInt64 blockPrefix =
            kStreamingBZipBlockMagic >> (48 - bits);
        const UInt64 endPrefix =
            kStreamingBZipEndMagic >> (48 - bits);
        if (actual == blockPrefix || actual == endPrefix)
          shifts |= (Byte)(1u << shift);
      }
      t[word] = shifts;
    }

    return t;
  }();

  return table;
}


class CStreamingBZipInput
{
  ISequentialInStream *_stream;
  UInt64 &_processed;
  bool &_inputFinished;
  HRESULT &_inputRes;

  std::vector<Byte> _data;
  UInt64 _baseByte;
  UInt64 _scanByte;
  bool _eof;
  std::vector<CStreamingBZipMarker> _markers;

  static UInt64 Load56(const Byte *p)
  {
    UInt64 value = 0;
    for (unsigned i = 0; i < 7; i++)
      value = (value << 8) | p[i];
    return value;
  }

  void ScanNew()
  {
    if (_data.size() < 7)
      return;

    const UInt64 firstPossible = _baseByte;
    const UInt64 lastPossible =
        _baseByte + (UInt64)_data.size() - 7;

    if (_scanByte < firstPossible)
      _scanByte = firstPossible;

    const auto &prefix = StreamingBZipPrefixTable();

    while (_scanByte <= lastPossible)
    {
      const size_t local = (size_t)(_scanByte - _baseByte);
      const unsigned word =
          ((unsigned)_data[local] << 8) |
          (unsigned)_data[local + 1];

      Byte shifts = prefix[word];
      if (shifts != 0)
      {
        const UInt64 window = Load56(_data.data() + local);
        while (shifts != 0)
        {
          unsigned shift = 0;
          while (((shifts >> shift) & 1u) == 0)
            shift++;
          shifts = (Byte)(shifts & (Byte)(shifts - 1));

          const UInt64 marker =
              (window >> (8 - shift)) &
              kStreamingBZipMagicMask;
          if (marker == kStreamingBZipBlockMagic ||
              marker == kStreamingBZipEndMagic)
          {
            _markers.emplace_back(
                _scanByte * 8 + shift,
                marker == kStreamingBZipEndMagic);
          }
        }
      }

      _scanByte++;
    }
  }

public:
  CStreamingBZipInput(
      ISequentialInStream *stream,
      UInt64 &processed,
      bool &inputFinished,
      HRESULT &inputRes):
      _stream(stream),
      _processed(processed),
      _inputFinished(inputFinished),
      _inputRes(inputRes),
      _baseByte(0),
      _scanByte(0),
      _eof(false)
  {
    try
    {
      _data.reserve((size_t)8 << 20);
    }
    catch (...) {}
  }

  const std::vector<Byte> &Data() const { return _data; }
  UInt64 BaseByte() const { return _baseByte; }
  UInt64 EndByte() const { return _baseByte + (UInt64)_data.size(); }
  bool Eof() const { return _eof; }
  const std::vector<CStreamingBZipMarker> &Markers() const { return _markers; }

  HRESULT ReadMore()
  {
    if (_eof)
      return S_OK;

    const size_t oldSize = _data.size();
    try
    {
      _data.resize(oldSize + kStreamingBZipReadChunk);
    }
    catch (const std::bad_alloc &)
    {
      return E_OUTOFMEMORY;
    }

    UInt32 size = 0;
    const HRESULT result = _stream->Read(
        _data.data() + oldSize,
        (UInt32)kStreamingBZipReadChunk,
        &size);
    if (result != S_OK)
    {
      _data.resize(oldSize);
      _inputRes = result;
      return result;
    }

    _data.resize(oldSize + size);
    _processed += size;
    _inputFinished = (size == 0);
    if (size == 0)
      _eof = true;

    ScanNew();
    return S_OK;
  }

  HRESULT EnsureByte(UInt64 endExclusive)
  {
    if (endExclusive < _baseByte)
      return E_FAIL;

    while (EndByte() < endExclusive && !_eof)
      RINOK(ReadMore())

    return EndByte() >= endExclusive ? S_OK : S_FALSE;
  }

  HRESULT EnsureBit(UInt64 endExclusiveBit)
  {
    return EnsureByte((endExclusiveBit + 7) >> 3);
  }

  bool ReadBits32(UInt64 bitOffset, UInt32 &value) const
  {
    if (bitOffset < _baseByte * 8)
      return false;

    const UInt64 localBit = bitOffset - _baseByte * 8;
    const UInt64 byteOffset = localBit >> 3;
    const unsigned shift = (unsigned)(localBit & 7);
    const unsigned need = (shift + 32 + 7) >> 3;
    if (byteOffset + need > _data.size())
      return false;

    value = 0;
    for (unsigned i = 0; i < 32; i++)
    {
      const UInt64 bit = localBit + i;
      const size_t byteIndex = (size_t)(bit >> 3);
      value = (value << 1) |
          ((_data[byteIndex] >> (7 - (bit & 7))) & 1);
    }
    return true;
  }

  const CStreamingBZipMarker *FindMarker(UInt64 bitOffset) const
  {
    const auto it = std::lower_bound(
        _markers.begin(),
        _markers.end(),
        bitOffset,
        [](const CStreamingBZipMarker &marker, UInt64 value)
        {
          return marker.BitOffset < value;
        });
    if (it == _markers.end() || it->BitOffset != bitOffset)
      return NULL;
    return &*it;
  }

  void TrimBeforeBit(UInt64 bitOffset)
  {
    const UInt64 keepByte = bitOffset >> 3;
    if (keepByte <= _baseByte)
      return;

    const UInt64 drop64 =
        (std::min)(keepByte - _baseByte, (UInt64)_data.size());
    const size_t drop = (size_t)drop64;
    if (drop != 0)
      _data.erase(_data.begin(), _data.begin() + drop);
    _baseByte += drop64;

    _markers.erase(
        _markers.begin(),
        std::lower_bound(
            _markers.begin(),
            _markers.end(),
            bitOffset,
            [](const CStreamingBZipMarker &marker, UInt64 value)
            {
              return marker.BitOffset < value;
            }));

    if (_scanByte < _baseByte)
      _scanByte = _baseByte;
  }
};


struct CStreamingParallelBlockJob
{
  UInt32 *Counters;
  bool OwnCounters;
  std::unique_ptr<Byte[]> Compact;
  UInt32 CompactSize;

  const Byte *Input;
  size_t InputSize;
  UInt64 InputBaseByte;
  UInt64 StartBit;
  UInt64 EndBit;
  UInt32 BlockSizeMax;
  UInt32 ExpectedCrc;
  UInt32 CalculatedCrc;
  CBlockProps Props;
  HRESULT Result;

  std::mutex Mutex;
  std::condition_variable FinishedEvent;
  bool Done;

  CStreamingParallelBlockJob():
      Counters(NULL),
      OwnCounters(false),
      CompactSize(0),
      Input(NULL),
      InputSize(0),
      InputBaseByte(0),
      StartBit(0),
      EndBit(0),
      BlockSizeMax(0),
      ExpectedCrc(0),
      CalculatedCrc(0),
      Result(S_OK),
      Done(false)
  {}

  ~CStreamingParallelBlockJob()
  {
    if (OwnCounters)
      BigFree(Counters);
  }

  bool Allocate(UInt32 *borrowedCounters = NULL)
  {
    if (borrowedCounters)
    {
      Counters = borrowedCounters;
      OwnCounters = false;
    }
    else
    {
      const size_t size =
          (256 + kBlockSizeMax) * sizeof(UInt32)
        #ifdef BZIP2_BYTE_MODE
          + kBlockSizeMax
        #endif
          + 256;
      Counters = (UInt32 *)::BigAlloc(size);
      OwnCounters = true;
      if (!Counters)
        return false;
    }

    Compact.reset(new (std::nothrow) Byte[kBlockSizeMax]);
    return Compact.get() != NULL;
  }

  void Reset(
      const Byte *input,
      size_t inputSize,
      UInt64 inputBaseByte,
      UInt64 startBit,
      UInt32 blockSizeMax,
      UInt32 expectedCrc)
  {
    Input = input;
    InputSize = inputSize;
    InputBaseByte = inputBaseByte;
    StartBit = startBit;
    EndBit = 0;
    BlockSizeMax = blockSizeMax;
    ExpectedCrc = expectedCrc;
    CalculatedCrc = 0;
    CompactSize = 0;
    Props = CBlockProps();
    Result = S_OK;

    std::lock_guard<std::mutex> lock(Mutex);
    Done = false;
  }

  HRESULT BuildCompact()
  {
    DecodeBlock1(Counters, Props.blockSize);

    UInt32 *tt = Counters + 256;
    UInt32 tPos = tt[tt[Props.origPtr] >> 8];

    int randToGo = -1;
    unsigned randIndex = 0;
    if (Props.randMode)
    {
      randIndex = 1;
      randToGo = kRandNums[0] - 2;
    }

    CBZip2Crc crc;
    unsigned previous = 0;
    unsigned runLength = 0;

    for (UInt32 i = 0; i < Props.blockSize; i++)
    {
      unsigned b = (unsigned)(tPos & 0xFF);
      tPos = tt[tPos >> 8];

      if (randToGo >= 0)
      {
        if (randToGo == 0)
        {
          b ^= 1;
          randToGo = kRandNums[randIndex];
          randIndex = (randIndex + 1) & 0x1FF;
        }
        randToGo--;
      }

      Compact[i] = (Byte)b;

      if (runLength == kRleModeRepSize)
      {
        for (unsigned repeat = 0; repeat < b; repeat++)
          crc.UpdateByte(previous);
        runLength = 0;
        continue;
      }

      crc.UpdateByte(b);
      if (runLength != 0 && b == previous)
        runLength++;
      else
      {
        previous = b;
        runLength = 1;
      }
    }

    CompactSize = Props.blockSize;
    CalculatedCrc = crc.GetDigest();
    return S_OK;
  }

  void Process()
  {
    HRESULT result = S_OK;

    try
    {
      if (!Input || !Counters || !Compact)
      {
        result = E_FAIL;
      }
      else if (StartBit < InputBaseByte * 8)
      {
        result = E_FAIL;
      }
      else
      {
        const UInt64 localBit = StartBit - InputBaseByte * 8;
        const size_t byteOffset = (size_t)(localBit >> 3);
        const unsigned bitShift = (unsigned)(localBit & 7);

        if (byteOffset >= InputSize)
          result = S_FALSE;
        else
        {
          CBase base;
          base.Counters = Counters;
          base.blockSizeMax = BlockSizeMax;
          base.state = STATE_BLOCK_SIGNATURE;
          base.state2 = 0;
          base.IsBz = false;
          base.InitBitDecoder();
          base._buf = Input + byteOffset;
          base._lim = Input + InputSize;

          if (bitShift != 0)
          {
            base._value = (UInt32)(*base._buf++) << 24;
            base._numBits = 8;
            base._value <<= bitShift;
            base._numBits -= bitShift;
          }

          const SRes signatureRes = base.ReadBlockSignature2();
          if (signatureRes != SZ_OK || base.state != STATE_BLOCK_START)
            result = S_FALSE;
          else if (base.crc != ExpectedCrc)
            result = S_FALSE;
          else
          {
            base.Props.randMode = 1;
            const SRes blockRes = base.ReadBlock2();
            if (blockRes != SZ_OK || base.state != STATE_BLOCK_SIGNATURE)
              result = S_FALSE;
            else
            {
              EndBit =
                  InputBaseByte * 8 +
                  (UInt64)(base._buf - Input) * 8 -
                  base._numBits;
              Props = base.Props;

              if (EndBit <= StartBit ||
                  Props.blockSize == 0 ||
                  Props.blockSize > BlockSizeMax)
                result = S_FALSE;
              else
                result = BuildCompact();
            }
          }
        }
      }
    }
    catch (...)
    {
      result = E_FAIL;
    }

    {
      std::lock_guard<std::mutex> lock(Mutex);
      Result = result;
      Done = true;
    }
    FinishedEvent.notify_one();
  }

  HRESULT Wait()
  {
    std::unique_lock<std::mutex> lock(Mutex);
    FinishedEvent.wait(lock, [this] { return Done; });
    return Result;
  }
};


class CStreamingParallelBlockPool
{
  std::vector<std::thread> _threads;
  std::deque<CStreamingParallelBlockJob *> _queue;
  std::mutex _mutex;
  std::condition_variable _workEvent;
  bool _stop;
  void *_cpuContext;

  void WorkerLoop()
  {
    for (;;)
    {
      CStreamingParallelBlockJob *job = NULL;
      {
        std::unique_lock<std::mutex> lock(_mutex);
        _workEvent.wait(lock, [this] { return _stop || !_queue.empty(); });
        if (_stop && _queue.empty())
          return;
        job = _queue.front();
        _queue.pop_front();
      }

      job->Process();

      if (_cpuContext)
        sunpack_cpu_release_extra_for_context(_cpuContext, 1);
    }
  }

public:
  CStreamingParallelBlockPool():
      _stop(false),
      _cpuContext(NULL)
  {}

  ~CStreamingParallelBlockPool()
  {
    Stop();
  }

  bool Start(unsigned numThreads, void *cpuContext)
  {
    _cpuContext = cpuContext;
    try
    {
      _threads.reserve(numThreads);
      for (unsigned i = 0; i < numThreads; i++)
        _threads.emplace_back([this] { WorkerLoop(); });
    }
    catch (...)
    {
      Stop();
      return false;
    }
    return true;
  }

  void Submit(CStreamingParallelBlockJob *job)
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _queue.push_back(job);
    }
    _workEvent.notify_one();
  }

  void Stop()
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _stop = true;
    }
    _workEvent.notify_all();

    for (std::thread &thread: _threads)
      if (thread.joinable())
        thread.join();

    _threads.clear();
  }
};

#endif

HRESULT CDecoder::Flush()
{
  if (_writeRes == S_OK)
  {
    _writeRes = WriteStream(_outStream, _outBuf, _outPos);
    _outWritten += _outPos;
    _outPos = 0;
  }
  return _writeRes;
}


NO_INLINE
HRESULT CDecoder::DecodeBlock(const CBlockProps &props)
{
  _calcedBlockCrc = 0;
  _blockFinished = false;

  CSpecState block;

  block._blockSize = props.blockSize;
  block._tt = _counters + 256;

  block.Init(props.origPtr, props.randMode);

  for (;;)
  {
    Byte *data = _outBuf + _outPos;
    size_t size = kOutBufSize - _outPos;
    
    if (_outSizeDefined)
    {
      const UInt64 rem = _outSize - _outPosTotal;
      if (size >= rem)
      {
        size = (size_t)rem;
        if (size == 0)
          return FinishMode ? S_FALSE : S_OK;
      }
    }

    TICKS_START
    const size_t processed = (size_t)(block.Decode(data, size) - data);
    TICKS_UPDATE(2)

    _outPosTotal += processed;
    _outPos += processed;
    
    if (processed >= size)
    {
      RINOK(Flush())
    }
    
    if (block.Finished())
    {
      _blockFinished = true;
      _calcedBlockCrc = block._crc.GetDigest();
      return S_OK;
    }
  }
}


CDecoder::CDecoder():
    _outBuf(NULL),
    FinishMode(false),
    _outSizeDefined(false),
    _counters(NULL)
  #ifndef Z7_ST
    , NumThreads(1),
      _sunpackScoutCpuContext(NULL),
      _sunpackScoutCpuCredit(0)
  #endif
    , _inBuf(NULL),
    _inProcessed(0)
{
  #ifndef Z7_ST
  MtMode = false;
  NeedWaitScout = false;
  // ScoutRes = S_OK;
  #endif
}


CDecoder::~CDecoder()
{
  PRIN("\n~CDecoder()");

  #ifndef Z7_ST
  
  if (Thread.IsCreated())
  {
    WaitScout();

    _block.StopScout = true;

    PRIN("\nScoutEvent.Set()");
    ScoutEvent.Set();

    PRIN("\nThread.Wait()()");
    Thread.Wait_Close();
    PRIN("\n after Thread.Wait()()");

    // if (ScoutRes != S_OK) throw ScoutRes;
  }
  if (_sunpackScoutCpuContext && _sunpackScoutCpuCredit)
  {
    sunpack_cpu_release_extra_for_context(
        _sunpackScoutCpuContext, _sunpackScoutCpuCredit);
    _sunpackScoutCpuCredit = 0;
  }
  _sunpackScoutCpuContext = NULL;
  
  #endif

  BigFree(_counters);
  MidFree(_outBuf);
  MidFree(_inBuf);
}


HRESULT CDecoder::ReadInput()
{
  if (Base._buf != Base._lim || _inputFinished || _inputRes != S_OK)
    return _inputRes;

  _inProcessed += (size_t)(Base._buf - _inBuf);
  Base._buf = _inBuf;
  Base._lim = _inBuf;
  UInt32 size = 0;
  _inputRes = Base.InStream->Read(_inBuf, kInBufSize, &size);
  _inputFinished = (size == 0);
  Base._lim = _inBuf + size;
  return _inputRes;
}


void CDecoder::StartNewStream()
{
  Base.state = STATE_STREAM_SIGNATURE;
  Base.state2 = 0;
  Base.IsBz = false;
}


HRESULT CDecoder::ReadStreamSignature()
{
  for (;;)
  {
    RINOK(ReadInput())
    SRes res = Base.ReadStreamSignature2();
    if (res != SZ_OK)
      return S_FALSE;
    if (Base.state == STATE_BLOCK_SIGNATURE)
      return S_OK;
    if (_inputFinished)
    {
      Base.NeedMoreInput = true;
      return S_FALSE;
    }
  }
}


HRESULT CDecoder::StartRead()
{
  StartNewStream();
  return ReadStreamSignature();
}


HRESULT CDecoder::ReadBlockSignature()
{
  for (;;)
  {
    RINOK(ReadInput())
    
    SRes res = Base.ReadBlockSignature2();
    
    if (Base.state == STATE_STREAM_FINISHED)
      Base.FinishedPackSize = GetInputProcessedSize();
    if (res != SZ_OK)
      return S_FALSE;
    if (Base.state != STATE_BLOCK_SIGNATURE)
      return S_OK;
    if (_inputFinished)
    {
      Base.NeedMoreInput = true;
      return S_FALSE;
    }
  }
}


HRESULT CDecoder::ReadBlock()
{
  for (;;)
  {
    RINOK(ReadInput())

    SRes res = Base.ReadBlock2();

    if (res != SZ_OK)
      return S_FALSE;
    if (Base.state == STATE_BLOCK_SIGNATURE)
      return S_OK;
    if (_inputFinished)
    {
      Base.NeedMoreInput = true;
      return S_FALSE;
    }
  }
}



HRESULT CDecoder::DecodeStreams(ICompressProgressInfo *progress)
{
  {
    #ifndef Z7_ST
    _block.StopScout = false;
    #endif
  }

  RINOK(StartRead())

  UInt64 inPrev = 0;
  UInt64 outPrev = 0;

  {
    #ifndef Z7_ST
    CWaitScout_Releaser waitScout_Releaser(this);

    bool useMt = false;
    #endif

    bool wasFinished = false;

    UInt32 crc = 0;
    UInt32 nextCrc = 0;
    HRESULT nextRes = S_OK;

    UInt64 packPos = 0;

    CBlockProps props;

    props.blockSize = 0;

    for (;;)
    {
      if (progress)
      {
        const UInt64 outCur = GetOutProcessedSize();
        if (packPos - inPrev >= kProgressStep || outCur - outPrev >= kProgressStep)
        {
          RINOK(progress->SetRatioInfo(&packPos, &outCur))
          inPrev = packPos;
          outPrev = outCur;
        }
      }

      if (props.blockSize == 0)
        if (wasFinished || nextRes != S_OK)
          return nextRes;

      if (
          #ifndef Z7_ST
          !useMt &&
          #endif
          !wasFinished && Base.state == STATE_BLOCK_SIGNATURE)
      {
        nextRes = ReadBlockSignature();
        nextCrc = Base.crc;
        packPos = GetInputProcessedSize();

        wasFinished = true;

        if (nextRes != S_OK)
          continue;

        if (Base.state == STATE_STREAM_FINISHED)
        {
          if (!Base.DecodeAllStreams)
          {
            wasFinished = true;
            continue;
          }
          
          nextRes = StartRead();
         
          if (Base.NeedMoreInput)
          {
            if (Base.state2 == 0)
              Base.NeedMoreInput = false;
            wasFinished = true;
            nextRes = S_OK;
            continue;
          }
          
          if (nextRes != S_OK)
            continue;

          wasFinished = false;
          continue;
        }

        wasFinished = false;

        #ifndef Z7_ST
        if (MtMode)
        if (props.blockSize != 0)
        {
          // we start multithreading, if next block is big enough.
          const UInt32 k_Mt_BlockSize_Threshold = (1 << 12);  // (1 << 13)
          if (props.blockSize > k_Mt_BlockSize_Threshold)
          {
            if (!Thread.IsCreated())
            {
              PRIN("=== MT_MODE");
              const HRESULT createRes = CreateThread();
              if (createRes != S_OK && createRes != S_FALSE)
                return createRes;
            }
            if (Thread.IsCreated())
              useMt = true;
          }
        }
        #endif
      }

      if (props.blockSize == 0)
      {
        crc = nextCrc;
        
        #ifndef Z7_ST
        if (useMt)
        {
          PRIN("DecoderEvent.Lock()");
          {
            WRes wres = DecoderEvent.Lock();
            if (wres != 0)
              return HRESULT_FROM_WIN32(wres);
          }
          NeedWaitScout = false;
          PRIN("-- DecoderEvent.Lock()");
          props = _block.Props;
          nextCrc = _block.NextCrc;
          if (_block.Crc_Defined)
            crc = _block.Crc;
          packPos = _block.PackPos;
          wasFinished = _block.WasFinished;
          RINOK(_block.Res)
        }
        else
        #endif
        {
          if (Base.state != STATE_BLOCK_START)
            return E_FAIL;

          TICKS_START
          Base.Props.randMode = 1;
          RINOK(ReadBlock())
          TICKS_UPDATE(0)
          
          props = Base.Props;
          continue;
        }
      }

      if (props.blockSize != 0)
      {
        TICKS_START
        DecodeBlock1(_counters, props.blockSize);
        TICKS_UPDATE(1)
      }
      
      #ifndef Z7_ST
      if (useMt && !wasFinished)
      {
        /*
        if (props.blockSize == 0)
        {
          // this codes switches back to single-threadMode
          useMt = false;
          PRIN("=== ST_MODE");
          continue;
          }
        */
        
        PRIN("ScoutEvent.Set()");
        {
          WRes wres = ScoutEvent.Set();
          if (wres != 0)
            return HRESULT_FROM_WIN32(wres);
        }
        NeedWaitScout = true;
      }
      #endif
        
      if (props.blockSize == 0)
        continue;

      RINOK(DecodeBlock(props))

      if (!_blockFinished)
        return nextRes;

      props.blockSize = 0;
      if (_calcedBlockCrc != crc)
      {
        BlockCrcError = true;
        return S_FALSE;
      }
    }
  }
}



#ifndef Z7_ST

HRESULT CDecoder::DecodeStreamsParallel(ICompressProgressInfo *progress)
{
  void *cpuContext = sunpack_cpu_current_job_context();

  unsigned maxLanes = kStreamingBZipMaxLanes;
  if (!cpuContext)
  {
    if (NumThreads < 2)
      return DecodeStreams(progress);
    maxLanes = (unsigned)std::min<UInt32>(
        NumThreads,
        kStreamingBZipMaxLanes);
  }

  CStreamingParallelBlockPool pool;
  if (maxLanes > 1 &&
      !pool.Start(maxLanes - 1, cpuContext))
    return E_FAIL;

  std::array<std::unique_ptr<CStreamingParallelBlockJob>,
      kStreamingBZipMaxLanes> jobs;

  for (unsigned i = 0; i < maxLanes; i++)
  {
    jobs[i].reset(new (std::nothrow) CStreamingParallelBlockJob());
    if (!jobs[i])
      return E_OUTOFMEMORY;

    if (!jobs[i]->Allocate(i == 0 ? _counters : NULL))
      return E_OUTOFMEMORY;
  }

  std::unique_ptr<Byte[]> commitBuffer(
      new (std::nothrow) Byte[kStreamingBZipCommitChunk]);
  if (!commitBuffer)
    return E_OUTOFMEMORY;

  CStreamingBZipInput input(
      Base.InStream,
      _inProcessed,
      _inputFinished,
      _inputRes);

  UInt64 inPrev = 0;
  UInt64 outPrev = 0;
  UInt64 expectedBit = 0;
  UInt32 combinedCrc = 0;
  UInt32 streamBlockSizeMax = 0;

  auto ensureHeaderAt =
      [&](UInt64 byteOffset, bool initial) -> HRESULT
  {
    const HRESULT ensureRes = input.EnsureByte(byteOffset + 4);
    if (ensureRes != S_OK)
    {
      if (!initial &&
          input.Eof() &&
          input.EndByte() == byteOffset)
        return S_OK;
      Base.NeedMoreInput = true;
      return S_FALSE;
    }

    const size_t local = (size_t)(byteOffset - input.BaseByte());
    const auto &data = input.Data();

    if (data[local] != kArSig0 ||
        data[local + 1] != kArSig1 ||
        data[local + 2] != kArSig2 ||
        data[local + 3] <= kArSig3 ||
        data[local + 3] > kArSig3 + kBlockSizeMultMax)
    {
      if (initial)
        return S_FALSE;
      return S_OK;
    }

    streamBlockSizeMax =
        (UInt32)(data[local + 3] - kArSig3) *
        kBlockSizeStep;
    Base.NumStreams++;
    Base.IsBz = true;
    combinedCrc = 0;
    expectedBit = (byteOffset + 4) * 8;
    return S_OK;
  };

  auto writeCompact =
      [&](const CStreamingParallelBlockJob &job) -> HRESULT
  {
    size_t outPos = 0;

    auto flush = [&]() -> HRESULT
    {
      if (outPos == 0)
        return S_OK;
      const HRESULT result =
          WriteStream(_outStream, commitBuffer.get(), outPos);
      if (result != S_OK)
      {
        _writeRes = result;
        return result;
      }
      _outWritten += outPos;
      _outPosTotal += outPos;
      outPos = 0;
      return S_OK;
    };

    auto emit = [&](Byte value) -> HRESULT
    {
      commitBuffer[outPos++] = value;
      if (outPos == kStreamingBZipCommitChunk)
        return flush();
      return S_OK;
    };

    unsigned previous = 0;
    unsigned runLength = 0;

    for (UInt32 i = 0; i < job.CompactSize; i++)
    {
      const Byte value = job.Compact[i];

      if (runLength == kRleModeRepSize)
      {
        for (unsigned repeat = 0; repeat < value; repeat++)
          RINOK(emit((Byte)previous))
        runLength = 0;
        continue;
      }

      RINOK(emit(value))

      if (runLength != 0 && value == previous)
        runLength++;
      else
      {
        previous = value;
        runLength = 1;
      }
    }

    return flush();
  };

  HRESULT result = ensureHeaderAt(0, true);
  if (result != S_OK)
    return result;

  for (;;)
  {
    // Ensure the current authoritative marker has been scanned. New input is
    // read exactly once and remains in this bounded window for both scanning
    // and full-block decode.
    while (!input.FindMarker(expectedBit) && !input.Eof())
      RINOK(input.ReadMore())

    const CStreamingBZipMarker *authoritative =
        input.FindMarker(expectedBit);
    if (!authoritative)
    {
      Base.NeedMoreInput = true;
      return S_FALSE;
    }

    if (authoritative->IsEnd)
    {
      RINOK(input.EnsureBit(expectedBit + 80))

      UInt32 storedCombined = 0;
      if (!input.ReadBits32(expectedBit + 48, storedCombined))
      {
        Base.NeedMoreInput = true;
        return S_FALSE;
      }

      if (storedCombined != combinedCrc)
      {
        Base.StreamCrcError = true;
        return S_FALSE;
      }

      const UInt64 afterEndBit = expectedBit + 80;
      const unsigned padding =
          (unsigned)((8 - (afterEndBit & 7)) & 7);
      if (padding != 0)
      {
        const UInt64 paddingStart = afterEndBit;
        for (unsigned i = 0; i < padding; i++)
        {
          const UInt64 bit = paddingStart + i;
          const UInt64 localBit =
              bit - input.BaseByte() * 8;
          const size_t byteIndex =
              (size_t)(localBit >> 3);
          const unsigned bitInByte =
              (unsigned)(localBit & 7);
          if ((input.Data()[byteIndex] &
               (1u << (7 - bitInByte))) != 0)
          {
            Base.MinorError = true;
            break;
          }
        }
      }

      const UInt64 finishedPackSize =
          (afterEndBit + 7) >> 3;
      Base.FinishedPackSize = finishedPackSize;
      Base.IsBz = false;

      // Probe one possible concatenated-stream header. This mirrors the serial
      // decoder's StartRead() behavior and also lets the handler distinguish
      // clean EOF from trailing data without consuming the input twice.
      RINOK(input.EnsureByte(finishedPackSize + 4))

      if (input.EndByte() == finishedPackSize && input.Eof())
        return S_OK;

      const HRESULT headerRes =
          ensureHeaderAt(finishedPackSize, false);
      if (headerRes != S_OK)
        return headerRes;

      if (!Base.IsBz)
        return S_OK;

      input.TrimBeforeBit(expectedBit);
      continue;
    }

    // Gather a small speculative batch. The last candidate gets enough
    // compressed lookahead for the maximum legal Huffman-coded block, so a
    // worker can parse a complete block without seeking or rereading input.
    for (;;)
    {
      unsigned blockCandidates = 0;
      UInt64 lastCandidateBit = expectedBit;
      bool sawEnd = false;

      for (const CStreamingBZipMarker &marker: input.Markers())
      {
        if (marker.BitOffset < expectedBit)
          continue;
        if (marker.IsEnd)
        {
          sawEnd = true;
          break;
        }
        blockCandidates++;
        lastCandidateBit = marker.BitOffset;
        if (blockCandidates >= maxLanes)
          break;
      }

      if (sawEnd)
      {
        const CStreamingBZipMarker *endMarker = NULL;
        for (const CStreamingBZipMarker &marker: input.Markers())
          if (marker.BitOffset >= expectedBit && marker.IsEnd)
          {
            endMarker = &marker;
            break;
          }
        if (endMarker)
        {
          RINOK(input.EnsureBit(endMarker->BitOffset + 80))
          break;
        }
      }

      if (blockCandidates >= maxLanes)
      {
        const UInt64 requiredByte =
            (lastCandidateBit >> 3) +
            kStreamingBZipEncodedLookahead;
        if (input.EndByte() >= requiredByte || input.Eof())
          break;
      }

      if (input.Eof())
        break;

      RINOK(input.ReadMore())
    }

    std::array<UInt64, kStreamingBZipMaxLanes> starts = {};
    unsigned candidateCount = 0;
    for (const CStreamingBZipMarker &marker: input.Markers())
    {
      if (marker.BitOffset < expectedBit)
        continue;
      if (marker.IsEnd)
        break;
      if (candidateCount == maxLanes)
        break;
      starts[candidateCount++] = marker.BitOffset;
    }

    if (candidateCount == 0 || starts[0] != expectedBit)
      return S_FALSE;

    unsigned extraWorkers = 0;
    if (candidateCount > 1)
    {
      if (cpuContext)
      {
        extraWorkers =
            sunpack_cpu_acquire_extra_for_context(
                cpuContext,
                candidateCount - 1,
                1);
      }
      else
      {
        extraWorkers =
            (std::min)(
                candidateCount - 1,
                maxLanes - 1);
      }
    }

    const unsigned activeJobs = 1 + extraWorkers;

    // All job pointers refer to input.Data(). No reads or vector growth are
    // allowed until the batch has completed.
    for (unsigned i = 0; i < activeJobs; i++)
    {
      UInt32 expectedCrc = 0;
      if (!input.ReadBits32(starts[i] + 48, expectedCrc))
      {
        if (cpuContext && extraWorkers)
          sunpack_cpu_release_extra_for_context(
              cpuContext,
              extraWorkers);
        Base.NeedMoreInput = true;
        return S_FALSE;
      }

      jobs[i]->Reset(
          input.Data().data(),
          input.Data().size(),
          input.BaseByte(),
          starts[i],
          streamBlockSizeMax,
          expectedCrc);
    }

    for (unsigned i = 1; i < activeJobs; i++)
      pool.Submit(jobs[i].get());

    jobs[0]->Process();

    // Extra-job credits are returned by the helper threads at exact block
    // completion. The caller's base credit covers job 0.
    for (unsigned i = 1; i < activeJobs; i++)
      jobs[i]->Wait();

    bool advanced = false;

    for (;;)
    {
      CStreamingParallelBlockJob *job = NULL;
      for (unsigned i = 0; i < activeJobs; i++)
        if (jobs[i]->StartBit == expectedBit)
        {
          job = jobs[i].get();
          break;
        }

      if (!job)
        break;

      const HRESULT jobRes = job->Wait();
      if (jobRes != S_OK)
      {
        if (input.Eof())
          Base.NeedMoreInput = true;
        return jobRes;
      }

      if (job->CalculatedCrc != job->ExpectedCrc)
      {
        BlockCrcError = true;
        return S_FALSE;
      }

      const CStreamingBZipMarker *nextMarker =
          input.FindMarker(job->EndBit);
      if (!nextMarker)
        return S_FALSE;

      RINOK(writeCompact(*job))

      Base.NumBlocks++;
      combinedCrc =
          ((combinedCrc << 1) |
           (combinedCrc >> 31)) ^
          job->ExpectedCrc;

      expectedBit = job->EndBit;
      advanced = true;

      if (progress)
      {
        const UInt64 inCur =
            (expectedBit + 7) >> 3;
        const UInt64 outCur =
            GetOutProcessedSize();
        if (inCur - inPrev >= kProgressStep ||
            outCur - outPrev >= kProgressStep)
        {
          RINOK(progress->SetRatioInfo(
              &inCur,
              &outCur))
          inPrev = inCur;
          outPrev = outCur;
        }
      }

      if (nextMarker->IsEnd)
        break;
    }

    if (!advanced)
      return E_FAIL;

    input.TrimBeforeBit(expectedBit);
  }
}

#endif


bool CDecoder::CreateInputBufer()
{
  if (!_inBuf)
  {
    _inBuf = (Byte *)MidAlloc(kInBufSize);
    if (!_inBuf)
      return false;
    Base._buf = _inBuf;
    Base._lim = _inBuf;
  }
  if (!_counters)
  {
    const size_t size = (256 + kBlockSizeMax) * sizeof(UInt32)
      #ifdef BZIP2_BYTE_MODE
        + kBlockSizeMax
      #endif
        + 256;
    _counters = (UInt32 *)::BigAlloc(size);
    if (!_counters)
      return false;
    Base.Counters = _counters;
  }
  return true;
}


void CDecoder::InitOutSize(const UInt64 *outSize)
{
  _outPosTotal = 0;
  
  _outSizeDefined = false;
  _outSize = 0;
  if (outSize)
  {
    _outSize = *outSize;
    _outSizeDefined = true;
  }
  
  BlockCrcError = false;
  
  Base.InitNumStreams2();
}


Z7_COM7F_IMF(CDecoder::Code(ISequentialInStream *inStream, ISequentialOutStream *outStream,
    const UInt64 * /* inSize */, const UInt64 *outSize, ICompressProgressInfo *progress))
{
  /*
  {
    RINOK(SetInStream(inStream));
    RINOK(SetOutStreamSize(outSize));

    RINOK(CopyStream(this, outStream, progress));
    return ReleaseInStream();
  }
  */

  _inputFinished = false;
  _inputRes = S_OK;
  _writeRes = S_OK;

  try {

  InitOutSize(outSize);
  
  // we can request data from InputBuffer after Code().
  // so we init InputBuffer before any function return.

  InitInputBuffer();

  if (!CreateInputBufer())
    return E_OUTOFMEMORY;

  #ifndef Z7_ST
  const bool useParallelBlocks =
      (sunpack_cpu_current_job_context() || NumThreads > 1) &&
      !_outSizeDefined &&
      Base.DecodeAllStreams;
  #else
  const bool useParallelBlocks = false;
  #endif

  if (!useParallelBlocks && !_outBuf)
  {
    _outBuf = (Byte *)MidAlloc(kOutBufSize);
    if (!_outBuf)
      return E_OUTOFMEMORY;
  }

  Base.InStream = inStream;
  
  // InitInputBuffer();
  
  _outStream = outStream;
  _outWritten = 0;
  _outPos = 0;

  HRESULT res;
  #ifndef Z7_ST
  if (useParallelBlocks)
    res = DecodeStreamsParallel(progress);
  else
  #endif
    res = DecodeStreams(progress);

  if (!useParallelBlocks)
    Flush();

  Base.InStream = NULL;
  _outStream = NULL;

  /*
  if (res == S_OK)
    if (FinishMode && inSize && *inSize != GetInputProcessedSize())
      res = S_FALSE;
  */

  if (res != S_OK)
    return res;

  } catch(...) { return E_FAIL; }

  return _writeRes;
}


Z7_COM7F_IMF(CDecoder::SetFinishMode(UInt32 finishMode))
{
  FinishMode = (finishMode != 0);
  return S_OK;
}


Z7_COM7F_IMF(CDecoder::GetInStreamProcessedSize(UInt64 *value))
{
  *value = GetInStreamSize();
  return S_OK;
}


Z7_COM7F_IMF(CDecoder::ReadUnusedFromInBuf(void *data, UInt32 size, UInt32 *processedSize))
{
  Base.AlignToByte();
  UInt32 i;
  for (i = 0; i < size; i++)
  {
    int b;
    Base.ReadByte(b);
    if (b < 0)
      break;
    ((Byte *)data)[i] = (Byte)b;
  }
  if (processedSize)
    *processedSize = i;
  return S_OK;
}


#ifndef Z7_ST

#define PRIN_MT(s) PRIN("    " s)

// #define RINOK_THREAD(x) { WRes __result_ = (x); if (__result_ != 0) return __result_; }

static THREAD_FUNC_DECL RunScout2(void *p) { ((CDecoder *)p)->RunScout(); return 0; }

HRESULT CDecoder::CreateThread()
{
  if (Thread.IsCreated())
    return S_OK;

  if (!_sunpackScoutCpuContext)
    _sunpackScoutCpuContext = sunpack_cpu_current_job_context();

  unsigned granted = 1;
  if (_sunpackScoutCpuContext)
    granted = sunpack_cpu_acquire_extra_for_context(
        _sunpackScoutCpuContext, 1, 1);
  if (granted == 0)
    return S_FALSE;

  WRes wres = DecoderEvent.CreateIfNotCreated_Reset();
  if (wres == 0) { wres = ScoutEvent.CreateIfNotCreated_Reset();
  if (wres == 0) { wres = Thread.Create(RunScout2, this); }}
  if (wres != 0)
  {
    if (_sunpackScoutCpuContext)
      sunpack_cpu_release_extra_for_context(
          _sunpackScoutCpuContext, granted);
    return HRESULT_FROM_WIN32(wres);
  }

  if (_sunpackScoutCpuContext)
    _sunpackScoutCpuCredit = granted;
  return S_OK;
}

void CDecoder::RunScout()
{
  for (;;)
  {
    {
      PRIN_MT("ScoutEvent.Lock()")
      WRes wres = ScoutEvent.Lock();
      PRIN_MT("-- ScoutEvent.Lock()")
      if (wres != 0)
      {
        // ScoutRes = wres;
        return;
      }
    }

    CBlock &block = _block;

    if (block.StopScout)
    {
      // ScoutRes = S_OK;
      return;
    }

    block.Res = S_OK;
    block.WasFinished = false;

    HRESULT res = S_OK;

    try
    {
      UInt64 packPos = GetInputProcessedSize();

      block.Props.blockSize = 0;
      block.Crc_Defined = false;
      // block.NextCrc_Defined = false;
      block.NextCrc = 0;
      
      for (;;)
      {
        if (Base.state == STATE_BLOCK_SIGNATURE)
        {
          res = ReadBlockSignature();

          if (res != S_OK)
            break;
          
          if (block.Props.blockSize == 0)
          {
            block.Crc = Base.crc;
            block.Crc_Defined = true;
          }
          else
          {
            block.NextCrc = Base.crc;
            // block.NextCrc_Defined = true;
          }

          continue;
        }

        if (Base.state == STATE_BLOCK_START)
        {
          if (block.Props.blockSize != 0)
            break;

          Base.Props.randMode = 1;

          res = ReadBlock();
          
          PRIN_MT("-- Base.ReadBlock")
          if (res != S_OK)
            break;
          block.Props = Base.Props;
          continue;
        }

        if (Base.state == STATE_STREAM_FINISHED)
        {
          if (!Base.DecodeAllStreams)
          {
            block.WasFinished = true;
            break;
          }
          
          res = StartRead();
          
          if (Base.NeedMoreInput)
          {
            if (Base.state2 == 0)
              Base.NeedMoreInput = false;
            block.WasFinished = true;
            res = S_OK;
            break;
          }
          
          if (res != S_OK)
            break;
          
          if (GetInputProcessedSize() - packPos > 0) // kProgressStep
            break;
          continue;
        }
        
        // throw 1;
        res = E_FAIL;
        break;
      }
    }
      
    catch (...) { res = E_FAIL; }
      
    if (res != S_OK)
    {
      PRIN_MT("error")
      block.Res = res;
      block.WasFinished = true;
    }

    block.PackPos = GetInputProcessedSize();
    PRIN_MT("DecoderEvent.Set()")
    WRes wres = DecoderEvent.Set();
    if (wres != 0)
    {
      // ScoutRes = wres;
      return;
    }
  }
}


Z7_COM7F_IMF(CDecoder::SetNumberOfThreads(UInt32 numThreads))
{
  const bool creditManaged =
      sunpack_cpu_current_job_context() != NULL;
  if (!creditManaged)
    NumThreads = numThreads == 0 ? 1 : numThreads;
  MtMode = creditManaged || NumThreads > 1;

  #ifndef BZIP2_BYTE_MODE
  MtMode = false;
  #endif

  // MtMode = false;
  return S_OK;
}

#endif



#ifndef Z7_NO_READ_FROM_CODER


Z7_COM7F_IMF(CDecoder::SetInStream(ISequentialInStream *inStream))
{
  Base.InStreamRef = inStream;
  Base.InStream = inStream;
  return S_OK;
}


Z7_COM7F_IMF(CDecoder::ReleaseInStream())
{
  Base.InStreamRef.Release();
  Base.InStream = NULL;
  return S_OK;
}



Z7_COM7F_IMF(CDecoder::SetOutStreamSize(const UInt64 *outSize))
{
  InitOutSize(outSize);

  InitInputBuffer();
  
  if (!CreateInputBufer())
    return E_OUTOFMEMORY;

  // InitInputBuffer();

  StartNewStream();

  _blockFinished = true;

  ErrorResult = S_OK;

  _inputFinished = false;
  _inputRes = S_OK;

  return S_OK;
}



Z7_COM7F_IMF(CDecoder::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  *processedSize = 0;

  try {

  if (ErrorResult != S_OK)
    return ErrorResult;

  for (;;)
  {
    if (Base.state == STATE_STREAM_FINISHED)
    {
      if (!Base.DecodeAllStreams)
        return ErrorResult;
      StartNewStream();
      continue;
    }

    if (Base.state == STATE_STREAM_SIGNATURE)
    {
      ErrorResult = ReadStreamSignature();

      if (Base.NeedMoreInput)
        if (Base.state2 == 0 && Base.NumStreams != 0)
        {
          Base.NeedMoreInput = false;
          ErrorResult = S_OK;
          return S_OK;
        }
      if (ErrorResult != S_OK)
        return ErrorResult;
      continue;
    }
    
    if (_blockFinished && Base.state == STATE_BLOCK_SIGNATURE)
    {
      ErrorResult = ReadBlockSignature();
      
      if (ErrorResult != S_OK)
        return ErrorResult;
      
      continue;
    }

    if (_outSizeDefined)
    {
      const UInt64 rem = _outSize - _outPosTotal;
      if (size >= rem)
        size = (UInt32)rem;
    }
    if (size == 0)
      return S_OK;
    
    if (_blockFinished)
    {
      if (Base.state != STATE_BLOCK_START)
      {
        ErrorResult = E_FAIL;
        return ErrorResult;
      }
      
      Base.Props.randMode = 1;
      ErrorResult = ReadBlock();
      
      if (ErrorResult != S_OK)
        return ErrorResult;
      
      DecodeBlock1(_counters, Base.Props.blockSize);
      
      _spec._blockSize = Base.Props.blockSize;
      _spec._tt = _counters + 256;
      _spec.Init(Base.Props.origPtr, Base.Props.randMode);

      _blockFinished = false;
    }

    {
      Byte *ptr = _spec.Decode((Byte *)data, size);
      
      const UInt32 processed = (UInt32)(ptr - (Byte *)data);
      data = ptr;
      size -= processed;
      (*processedSize) += processed;
      _outPosTotal += processed;
      
      if (_spec.Finished())
      {
        _blockFinished = true;
        if (Base.crc != _spec._crc.GetDigest())
        {
          BlockCrcError = true;
          ErrorResult = S_FALSE;
          return ErrorResult;
        }
      }
    }
  }

  } catch(...) { ErrorResult = S_FALSE; return S_FALSE; }
}



// ---------- NSIS ----------

Z7_COM7F_IMF(CNsisDecoder::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  *processedSize = 0;

  try {

  if (ErrorResult != S_OK)
    return ErrorResult;
    
  if (Base.state == STATE_STREAM_FINISHED)
    return S_OK;

  if (Base.state == STATE_STREAM_SIGNATURE)
  {
    Base.blockSizeMax = 9 * kBlockSizeStep;
    Base.state = STATE_BLOCK_SIGNATURE;
    // Base.state2 = 0;
  }

  for (;;)
  {
    if (_blockFinished && Base.state == STATE_BLOCK_SIGNATURE)
    {
      ErrorResult = ReadInput();
      if (ErrorResult != S_OK)
        return ErrorResult;
      
      int b;
      Base.ReadByte(b);
      if (b < 0)
      {
        ErrorResult = S_FALSE;
        return ErrorResult;
      }
      
      if (b == kFinSig0)
      {
        /*
        if (!Base.AreRemainByteBitsEmpty())
          ErrorResult = S_FALSE;
        */
        Base.state = STATE_STREAM_FINISHED;
        return ErrorResult;
      }
      
      if (b != kBlockSig0)
      {
        ErrorResult = S_FALSE;
        return ErrorResult;
      }
      
      Base.state = STATE_BLOCK_START;
    }

    if (_outSizeDefined)
    {
      const UInt64 rem = _outSize - _outPosTotal;
      if (size >= rem)
        size = (UInt32)rem;
    }
    if (size == 0)
      return S_OK;
    
    if (_blockFinished)
    {
      if (Base.state != STATE_BLOCK_START)
      {
        ErrorResult = E_FAIL;
        return ErrorResult;
      }

      Base.Props.randMode = 0;
      ErrorResult = ReadBlock();
      
      if (ErrorResult != S_OK)
        return ErrorResult;
      
      DecodeBlock1(_counters, Base.Props.blockSize);
      
      _spec._blockSize = Base.Props.blockSize;
      _spec._tt = _counters + 256;
      _spec.Init(Base.Props.origPtr, Base.Props.randMode);
      
      _blockFinished = false;
    }
    
    {
      Byte *ptr = _spec.Decode((Byte *)data, size);
      
      const UInt32 processed = (UInt32)(ptr - (Byte *)data);
      data = ptr;
      size -= processed;
      (*processedSize) += processed;
      _outPosTotal += processed;
      
      if (_spec.Finished())
        _blockFinished = true;
    }
  }

  } catch(...) { ErrorResult = S_FALSE; return S_FALSE; }
}

#endif

}}
