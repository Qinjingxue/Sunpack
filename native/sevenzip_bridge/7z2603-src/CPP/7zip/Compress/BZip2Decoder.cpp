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
#include "internal/decoder_input_access.h"


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

struct CParallelMarker
{
  UInt64 BitOffset;
  UInt32 ExpectedCrc;
  bool IsEnd;

  CParallelMarker(UInt64 bitOffset, UInt32 expectedCrc, bool isEnd):
      BitOffset(bitOffset),
      ExpectedCrc(expectedCrc),
      IsEnd(isEnd)
  {}
};


static const UInt64 kBZip2BlockMagic48 = UINT64_CONST(0x314159265359);
static const UInt64 kBZip2EndMagic48 = UINT64_CONST(0x177245385090);
static const UInt64 kBZip2MagicMask48 = UINT64_CONST(0x0000FFFFFFFFFFFF);
static const UInt64 kBZip2WindowMask56 = UINT64_CONST(0x00FFFFFFFFFFFFFF);
static const size_t kBZip2ScanChunk = (size_t)1 << 20;
static const unsigned kMaxBZip2ParallelDecoders = 8;


static HRESULT ParallelReadAt(
    void *stream,
    UInt64 offset,
    void *data,
    UInt32 size,
    UInt32 &processed)
{
  unsigned long read = 0;
  const long result = sunpack_input_read_at(
      stream,
      (unsigned long long)offset,
      data,
      (unsigned long)size,
      &read);
  processed = (UInt32)read;
  return (HRESULT)result;
}


static HRESULT ParallelReadExact(
    void *stream,
    UInt64 inputSize,
    UInt64 offset,
    void *data,
    UInt32 size)
{
  if (offset > inputSize || (UInt64)size > inputSize - offset)
    return S_FALSE;

  UInt32 total = 0;
  while (total < size)
  {
    UInt32 read = 0;
    const HRESULT result = ParallelReadAt(
        stream,
        offset + total,
        (Byte *)data + total,
        size - total,
        read);
    if (result != S_OK)
      return result;
    if (read == 0)
      return S_FALSE;
    total += read;
  }
  return S_OK;
}


static bool ParallelReadBits32(
    void *stream,
    UInt64 inputSize,
    UInt64 bitOffset,
    UInt32 &value)
{
  if (bitOffset > inputSize * 8 ||
      inputSize * 8 - bitOffset < 32)
    return false;

  const UInt64 byteOffset = bitOffset >> 3;
  const unsigned shift = (unsigned)(bitOffset & 7);
  const unsigned numBytes = (shift + 32 + 7) >> 3;
  Byte bytes[8] = {};
  if (ParallelReadExact(
          stream,
          inputSize,
          byteOffset,
          bytes,
          numBytes) != S_OK)
    return false;

  value = 0;
  for (unsigned i = 0; i < 32; i++)
  {
    const unsigned bit = shift + i;
    value = (value << 1) |
        ((bytes[bit >> 3] >> (7 - (bit & 7))) & 1);
  }
  return true;
}


static bool ParallelReadStreamHeader(
    void *stream,
    UInt64 inputSize,
    UInt64 byteOffset,
    unsigned &level)
{
  Byte header[4];
  if (ParallelReadExact(
          stream,
          inputSize,
          byteOffset,
          header,
          4) != S_OK)
    return false;

  if (header[0] != kArSig0 ||
      header[1] != kArSig1 ||
      header[2] != kArSig2 ||
      header[3] <= kArSig3 ||
      header[3] > kArSig3 + kBlockSizeMultMax)
    return false;

  level = (unsigned)(header[3] - kArSig3);
  return true;
}


static bool ParallelLooksLikeTruncatedHeader(
    void *stream,
    UInt64 inputSize,
    UInt64 byteOffset)
{
  if (byteOffset >= inputSize)
    return false;

  const UInt64 remaining = inputSize - byteOffset;
  if (remaining >= 4)
    return false;

  Byte bytes[3] = {};
  if (ParallelReadExact(
          stream,
          inputSize,
          byteOffset,
          bytes,
          (UInt32)remaining) != S_OK)
    return false;

  const Byte expected[3] = {
      kArSig0, kArSig1, kArSig2 };
  for (UInt64 i = 0; i < remaining; i++)
    if (bytes[i] != expected[i])
      return false;
  return true;
}


static bool ParallelPaddingBitsNonZero(
    void *stream,
    UInt64 inputSize,
    UInt64 bitOffset)
{
  const unsigned shift =
      (unsigned)(bitOffset & 7);
  if (shift == 0)
    return false;

  const UInt64 byteOffset = bitOffset >> 3;
  Byte value = 0;
  if (ParallelReadExact(
          stream,
          inputSize,
          byteOffset,
          &value,
          1) != S_OK)
    return false;

  const Byte mask =
      (Byte)(((unsigned)1 << (8 - shift)) - 1);
  return (value & mask) != 0;
}


static const std::array<Byte, 256> &ParallelPrefixTable(UInt64 magic)
{
  static const std::array<Byte, 256> blockTable = []()
  {
    std::array<Byte, 256> table = {};
    for (unsigned byte = 0; byte < 256; byte++)
      for (unsigned shift = 0; shift < 8; shift++)
      {
        const Byte wanted = (Byte)(kBZip2BlockMagic48 >> (40 + shift));
        const Byte kept = (Byte)(((unsigned)1 << (8 - shift)) - 1);
        if (((Byte)byte & kept) == wanted)
          table[byte] |= (Byte)((unsigned)1 << shift);
      }
    return table;
  }();

  static const std::array<Byte, 256> endTable = []()
  {
    std::array<Byte, 256> table = {};
    for (unsigned byte = 0; byte < 256; byte++)
      for (unsigned shift = 0; shift < 8; shift++)
      {
        const Byte wanted = (Byte)(kBZip2EndMagic48 >> (40 + shift));
        const Byte kept = (Byte)(((unsigned)1 << (8 - shift)) - 1);
        if (((Byte)byte & kept) == wanted)
          table[byte] |= (Byte)((unsigned)1 << shift);
      }
    return table;
  }();

  return magic == kBZip2BlockMagic48 ? blockTable : endTable;
}


static HRESULT ScanParallelMarkers(
    void *stream,
    UInt64 inputSize,
    std::vector<CParallelMarker> &markers)
{
  markers.clear();
  if (inputSize < 10)
    return S_FALSE;

  const std::array<Byte, 256> &blockPrefix =
      ParallelPrefixTable(kBZip2BlockMagic48);
  const std::array<Byte, 256> &endPrefix =
      ParallelPrefixTable(kBZip2EndMagic48);

  std::vector<Byte> bytes;
  try
  {
    bytes.resize(kBZip2ScanChunk + 16);
  }
  catch (const std::bad_alloc &)
  {
    return E_OUTOFMEMORY;
  }

  for (UInt64 chunkStart = 0; chunkStart < inputSize; )
  {
    const UInt64 remaining = inputSize - chunkStart;
    const size_t payload =
        (size_t)std::min<UInt64>(remaining, kBZip2ScanChunk);
    const size_t wanted =
        (size_t)std::min<UInt64>(remaining, payload + 16);

    UInt32 read = 0;
    const HRESULT readRes = ParallelReadAt(
        stream,
        chunkStart,
        bytes.data(),
        (UInt32)wanted,
        read);
    if (readRes != S_OK)
      return readRes;
    if (read < payload)
      return S_FALSE;

    UInt64 window = 0;
    for (unsigned i = 0; i < 7; i++)
      window = (window << 8) |
          (i < read ? (UInt64)bytes[i] : 0);

    for (size_t local = 0; local < payload; local++)
    {
      Byte shifts =
          (Byte)(blockPrefix[(Byte)(window >> 48)] |
                 endPrefix[(Byte)(window >> 48)]);
      while (shifts != 0)
      {
        unsigned shift = 0;
        while (((shifts >> shift) & 1) == 0)
          shift++;
        shifts = (Byte)(shifts & (Byte)(shifts - 1));

        const UInt64 marker =
            (window >> (8 - shift)) & kBZip2MagicMask48;
        const UInt64 bitOffset =
            (chunkStart + local) * 8 + shift;
        UInt32 crc = 0;
        if (ParallelReadBits32(
                stream,
                inputSize,
                bitOffset + 48,
                crc))
        {
          if (marker == kBZip2BlockMagic48)
            markers.emplace_back(bitOffset, crc, false);
          else if (marker == kBZip2EndMagic48)
            markers.emplace_back(bitOffset, crc, true);
        }
      }

      const size_t next = local + 7;
      const UInt64 nextByte =
          next < read ? (UInt64)bytes[next] : 0;
      window =
          ((window << 8) & kBZip2WindowMask56) |
          nextByte;
    }

    if (markers.size() >
        (size_t)(inputSize / 16 + 64))
      return S_FALSE;

    chunkStart += payload;
  }

  std::sort(
      markers.begin(),
      markers.end(),
      [](const CParallelMarker &a, const CParallelMarker &b)
      {
        return a.BitOffset < b.BitOffset;
      });
  markers.erase(
      std::unique(
          markers.begin(),
          markers.end(),
          [](const CParallelMarker &a, const CParallelMarker &b)
          {
            return a.BitOffset == b.BitOffset;
          }),
      markers.end());

  return S_OK;
}


static size_t FindParallelMarker(
    const std::vector<CParallelMarker> &markers,
    UInt64 bitOffset)
{
  const auto it = std::lower_bound(
      markers.begin(),
      markers.end(),
      bitOffset,
      [](const CParallelMarker &marker, UInt64 value)
      {
        return marker.BitOffset < value;
      });
  if (it == markers.end() || it->BitOffset != bitOffset)
    return (size_t)-1;
  return (size_t)(it - markers.begin());
}


struct CParallelBlockJob
{
  size_t MarkerIndex;
  UInt64 StartBit;
  UInt64 EndBit;
  UInt32 ExpectedCrc;
  UInt32 CalculatedCrc;
  CBlockProps Props;
  HRESULT Result;
  std::vector<Byte> Compact;

  std::mutex Mutex;
  std::condition_variable FinishedEvent;
  bool Done;

  CParallelBlockJob():
      MarkerIndex((size_t)-1),
      StartBit(0),
      EndBit(0),
      ExpectedCrc(0),
      CalculatedCrc(0),
      Result(S_OK),
      Done(false)
  {}

  void Reset(
      size_t markerIndex,
      UInt64 startBit,
      UInt32 expectedCrc)
  {
    MarkerIndex = markerIndex;
    StartBit = startBit;
    EndBit = 0;
    ExpectedCrc = expectedCrc;
    CalculatedCrc = 0;
    Props = CBlockProps();
    Result = S_OK;
    Compact.clear();

    std::lock_guard<std::mutex> lock(Mutex);
    Done = false;
  }

  void Finish(HRESULT result)
  {
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


class CParallelBlockWorkspace
{
  UInt32 *_counters;
  bool _ownsCounters;
  std::unique_ptr<Byte[]> _input;

  HRESULT FillInput(
      void *stream,
      UInt64 inputSize,
      UInt64 offset,
      CBase &base,
      UInt64 &bufferStart,
      UInt64 &nextOffset)
  {
    if (!_input)
    {
      _input.reset(new (std::nothrow) Byte[kInBufSize]);
      if (!_input)
        return E_OUTOFMEMORY;
    }

    if (offset >= inputSize)
      return S_FALSE;

    const UInt32 wanted = (UInt32)std::min<UInt64>(
        inputSize - offset,
        kInBufSize);
    UInt32 read = 0;
    const HRESULT result = ParallelReadAt(
        stream,
        offset,
        _input.get(),
        wanted,
        read);
    if (result != S_OK)
      return result;
    if (read == 0)
      return S_FALSE;

    bufferStart = offset;
    nextOffset = offset + read;
    base._buf = _input.get();
    base._lim = _input.get() + read;
    return S_OK;
  }

  HRESULT BuildCompactResult(
      CParallelBlockJob &job)
  {
    DecodeBlock1(_counters, job.Props.blockSize);

    UInt32 *tt = _counters + 256;
    UInt32 tPos =
        tt[tt[job.Props.origPtr] >> 8];

    int randToGo = -1;
    unsigned randIndex = 0;
    if (job.Props.randMode)
    {
      randIndex = 1;
      randToGo = kRandNums[0] - 2;
    }

    try
    {
      job.Compact.resize(job.Props.blockSize);
    }
    catch (const std::bad_alloc &)
    {
      return E_OUTOFMEMORY;
    }

    CBZip2Crc crc;
    unsigned previous = 0;
    unsigned runLength = 0;

    for (UInt32 i = 0; i < job.Props.blockSize; i++)
    {
      unsigned b = (unsigned)(tPos & 0xFF);
      tPos = tt[tPos >> 8];

      if (randToGo >= 0)
      {
        if (randToGo == 0)
        {
          b ^= 1;
          randToGo = kRandNums[randIndex];
          randIndex++;
          randIndex &= 0x1FF;
        }
        randToGo--;
      }

      job.Compact[i] = (Byte)b;

      if (runLength == 4)
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

    job.CalculatedCrc = crc.GetDigest();
    return S_OK;
  }

public:
  explicit CParallelBlockWorkspace(UInt32 *externalCounters = NULL):
      _counters(externalCounters),
      _ownsCounters(externalCounters == NULL)
  {}

  ~CParallelBlockWorkspace()
  {
    if (_ownsCounters)
      BigFree(_counters);
  }

  bool Allocate()
  {
    if (_counters)
      return true;

    const size_t size =
        (256 + kBlockSizeMax) * sizeof(UInt32)
      #ifdef BZIP2_BYTE_MODE
        + kBlockSizeMax
      #endif
        + 256;

    _counters = (UInt32 *)::BigAlloc(size);
    return _counters != NULL;
  }

  void Process(
      void *stream,
      UInt64 inputSize,
      CParallelBlockJob &job)
  {
    HRESULT result = S_OK;
    try
    {
      if (!Allocate())
      {
        job.Finish(E_OUTOFMEMORY);
        return;
      }

      const UInt64 payloadBit = job.StartBit + 80;
      if (payloadBit < job.StartBit ||
          payloadBit > inputSize * 8)
      {
        job.Finish(S_FALSE);
        return;
      }

      CBase base;
      base.Counters = _counters;
      base.blockSizeMax = kBlockSizeMax;
      base.state = STATE_BLOCK_START;
      base.state2 = 0;
      base.state3 = 0;
      base.state4 = 0;
      base.state5 = 0;
      base.Props = CBlockProps();
      base.Props.randMode = 1;
      base.InitBitDecoder();

      const UInt64 byteOffset = payloadBit >> 3;
      const unsigned bitShift =
          (unsigned)(payloadBit & 7);
      UInt64 bufferStart = 0;
      UInt64 nextOffset = 0;
      result = FillInput(
          stream,
          inputSize,
          byteOffset,
          base,
          bufferStart,
          nextOffset);
      if (result != S_OK)
      {
        job.Finish(result);
        return;
      }

      if (bitShift != 0)
      {
        if (base._buf == base._lim)
        {
          job.Finish(S_FALSE);
          return;
        }
        base._value =
            (UInt32)(*base._buf) << 24;
        base._numBits = 8;
        base._buf++;
        base._value <<= bitShift;
        base._numBits -= bitShift;
      }

      for (;;)
      {
        const SRes readRes = base.ReadBlock2();
        if (readRes != SZ_OK)
        {
          result = S_FALSE;
          break;
        }
        if (base.state == STATE_BLOCK_SIGNATURE)
          break;
        if (base._buf != base._lim)
        {
          result = E_FAIL;
          break;
        }
        if (nextOffset >= inputSize)
        {
          result = S_FALSE;
          break;
        }

        result = FillInput(
            stream,
            inputSize,
            nextOffset,
            base,
            bufferStart,
            nextOffset);
        if (result != S_OK)
          break;
      }

      if (result == S_OK)
      {
        const UInt64 consumedBytes =
            bufferStart +
            (UInt64)(base._buf - _input.get());
        const UInt64 consumedBits =
            consumedBytes * 8;
        if (consumedBits < base._numBits)
          result = E_FAIL;
        else
        {
          job.EndBit =
              consumedBits - base._numBits;
          job.Props = base.Props;
          if (job.EndBit <= job.StartBit ||
              job.Props.blockSize == 0 ||
              job.Props.blockSize > kBlockSizeMax)
            result = S_FALSE;
        }
      }

      if (result == S_OK)
        result = BuildCompactResult(job);
    }
    catch (const std::bad_alloc &)
    {
      result = E_OUTOFMEMORY;
    }
    catch (...)
    {
      result = E_FAIL;
    }

    job.Finish(result);
  }
};


class CParallelBlockPool
{
  std::vector<std::thread> _threads;
  std::deque<CParallelBlockJob *> _queue;
  std::mutex _mutex;
  std::condition_variable _workEvent;
  std::condition_variable _idleEvent;
  size_t _pending;
  unsigned _activeWorkers;
  unsigned _runningWorkers;
  bool _stop;
  void *_stream;
  UInt64 _inputSize;

  void WorkerLoop()
  {
    CParallelBlockWorkspace workspace;

    for (;;)
    {
      CParallelBlockJob *job = NULL;
      {
        std::unique_lock<std::mutex> lock(_mutex);
        _workEvent.wait(
            lock,
            [this]
            {
              return _stop ||
                  (!_queue.empty() &&
                   _runningWorkers < _activeWorkers);
            });
        if (_stop && _queue.empty())
          return;
        if (_queue.empty() ||
            (!_stop &&
             _runningWorkers >= _activeWorkers))
          continue;

        job = _queue.front();
        _queue.pop_front();
        _runningWorkers++;
      }

      workspace.Process(
          _stream,
          _inputSize,
          *job);

      {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_runningWorkers != 0)
          _runningWorkers--;
        if (_pending != 0)
          _pending--;
        if (_pending == 0)
          _idleEvent.notify_all();
        else if (!_queue.empty() &&
                 (_stop ||
                  _runningWorkers < _activeWorkers))
          _workEvent.notify_one();
      }
    }
  }

public:
  CParallelBlockPool(
      void *stream,
      UInt64 inputSize):
      _pending(0),
      _activeWorkers(0),
      _runningWorkers(0),
      _stop(false),
      _stream(stream),
      _inputSize(inputSize)
  {}

  ~CParallelBlockPool()
  {
    Stop();
  }

  bool EnsureWorkerCount(unsigned numWorkers)
  {
    try
    {
      _threads.reserve(numWorkers);
      while (_threads.size() < numWorkers)
        _threads.emplace_back(
            [this] { WorkerLoop(); });
    }
    catch (...)
    {
      return false;
    }
    return true;
  }

  void SetActiveWorkers(unsigned numWorkers)
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _activeWorkers =
          (std::min)(
              numWorkers,
              (unsigned)_threads.size());
    }
    _workEvent.notify_all();
  }

  void Submit(CParallelBlockJob *job)
  {
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _pending++;
      _queue.push_back(job);
    }
    _workEvent.notify_one();
  }

  void WaitIdle()
  {
    std::unique_lock<std::mutex> lock(_mutex);
    _idleEvent.wait(
        lock,
        [this] { return _pending == 0; });
  }

  void Stop()
  {
    WaitIdle();
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
  unsigned long long rawInputSize = 0;
  if (!sunpack_input_random_access_size(
          Base.InStream,
          &rawInputSize))
    return E_NOTIMPL;

  const UInt64 inputSize = (UInt64)rawInputSize;
  if (inputSize < 4)
    return S_FALSE;

  unsigned firstLevel = 0;
  if (!ParallelReadStreamHeader(
          Base.InStream,
          inputSize,
          0,
          firstLevel))
    return S_FALSE;

  std::vector<CParallelMarker> markers;
  RINOK(ScanParallelMarkers(
      Base.InStream,
      inputSize,
      markers))

  const size_t firstMarker =
      FindParallelMarker(markers, 32);
  if (firstMarker == (size_t)-1)
    return S_FALSE;

  void *cpuContext =
      sunpack_cpu_current_job_context();

  const unsigned standaloneLanes =
      cpuContext ? 0 :
      (NumThreads == 0 ? 1 :
       (unsigned)std::min<UInt32>(
           NumThreads,
           kMaxBZip2ParallelDecoders));

  CParallelBlockPool pool(
      Base.InStream,
      inputSize);
  CParallelBlockWorkspace callerWorkspace(
      _counters);

  std::vector<Byte> commitBuffer;
  try
  {
    commitBuffer.resize(kOutBufSize);
  }
  catch (const std::bad_alloc &)
  {
    return E_OUTOFMEMORY;
  }

  UInt64 inPrev = 0;
  UInt64 outPrev = 0;

  auto writeCompact =
      [&](const CParallelBlockJob &job) -> HRESULT
  {
    size_t outPos = 0;

    auto flush = [&]() -> HRESULT
    {
      if (outPos == 0)
        return S_OK;
      const HRESULT result =
          WriteStream(
              _outStream,
              commitBuffer.data(),
              outPos);
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
      if (outPos == commitBuffer.size())
        return flush();
      return S_OK;
    };

    unsigned previous = 0;
    unsigned runLength = 0;

    for (Byte value: job.Compact)
    {
      if (runLength == 4)
      {
        for (unsigned repeat = 0;
             repeat < value;
             repeat++)
          RINOK(emit((Byte)previous))
        runLength = 0;
        continue;
      }

      RINOK(emit(value))
      if (runLength != 0 &&
          value == previous)
        runLength++;
      else
      {
        previous = value;
        runLength = 1;
      }
    }

    return flush();
  };

  auto finishInputState =
      [&](UInt64 finishedPackSize)
  {
    _inProcessed = inputSize;
    Base._buf = _inBuf;
    Base._lim = _inBuf;
    Base._numBits = 0;
    Base._value = 0;
    Base.FinishedPackSize = finishedPackSize;
    // DecodeAllStreams probes for the next concatenated stream after EOS.
    // Leaving IsBz false matches the serial path after that probe.
    Base.IsBz = false;
  };

  UInt64 headerByte = 0;
  unsigned level = firstLevel;
  size_t markerIndex = firstMarker;
  UInt64 lastFinishedPackSize = 0;

  for (;;)
  {
    UInt32 combinedCrc = 0;

    for (;;)
    {
      if (markerIndex >= markers.size())
        return S_FALSE;

      const CParallelMarker &marker =
          markers[markerIndex];

      if (marker.IsEnd)
      {
        if (marker.ExpectedCrc != combinedCrc)
        {
          Base.StreamCrcError = true;
          return S_FALSE;
        }

        Base.NumStreams++;

        const UInt64 afterEndBit =
            marker.BitOffset + 80;
        if (afterEndBit < marker.BitOffset)
          return E_FAIL;

        if (ParallelPaddingBitsNonZero(
                Base.InStream,
                inputSize,
                afterEndBit))
          Base.MinorError = true;

        lastFinishedPackSize =
            (afterEndBit + 7) >> 3;
        Base.FinishedPackSize =
            lastFinishedPackSize;

        if (lastFinishedPackSize >= inputSize)
        {
          if (lastFinishedPackSize > inputSize)
          {
            Base.NeedMoreInput = true;
            return S_FALSE;
          }

          finishInputState(
              lastFinishedPackSize);
          return S_OK;
        }

        unsigned nextLevel = 0;
        if (!ParallelReadStreamHeader(
                Base.InStream,
                inputSize,
                lastFinishedPackSize,
                nextLevel))
        {
          if (ParallelLooksLikeTruncatedHeader(
                  Base.InStream,
                  inputSize,
                  lastFinishedPackSize))
            Base.NeedMoreInput = true;

          finishInputState(
              lastFinishedPackSize);
          return S_OK;
        }

        headerByte = lastFinishedPackSize;
        level = nextLevel;
        const UInt64 nextBit =
            headerByte * 8 + 32;
        markerIndex =
            FindParallelMarker(
                markers,
                nextBit);
        if (markerIndex == (size_t)-1)
          return S_FALSE;
        break;
      }

      std::vector<size_t> batchMarkerIndices;
      batchMarkerIndices.reserve(
          kMaxBZip2ParallelDecoders);
      for (size_t i = markerIndex;
           i < markers.size() &&
           batchMarkerIndices.size() <
               kMaxBZip2ParallelDecoders;
           i++)
      {
        if (!markers[i].IsEnd)
          batchMarkerIndices.push_back(i);
      }
      if (batchMarkerIndices.empty() ||
          batchMarkerIndices.front() != markerIndex)
        return S_FALSE;

      unsigned extraWorkers = 0;
      const unsigned wantedExtra =
          (unsigned)batchMarkerIndices.size() - 1;
      if (cpuContext)
      {
        if (wantedExtra != 0)
          extraWorkers =
              sunpack_cpu_acquire_extra_for_context(
                  cpuContext,
                  wantedExtra,
                  1);
      }
      else if (standaloneLanes > 1)
      {
        extraWorkers =
            (std::min)(
                wantedExtra,
                standaloneLanes - 1);
      }

      const size_t batchSize =
          (size_t)extraWorkers + 1;
      batchMarkerIndices.resize(batchSize);

      if (extraWorkers != 0)
      {
        if (!pool.EnsureWorkerCount(
                extraWorkers))
        {
          if (cpuContext)
            sunpack_cpu_release_extra_for_context(
                cpuContext,
                extraWorkers);
          return E_FAIL;
        }
        pool.SetActiveWorkers(
            extraWorkers);
      }

      std::vector<std::unique_ptr<CParallelBlockJob>>
          jobs;
      try
      {
        jobs.reserve(batchSize);
        for (size_t i = 0;
             i < batchSize;
             i++)
        {
          const size_t index =
              batchMarkerIndices[i];
          const CParallelMarker &candidate =
              markers[index];
          std::unique_ptr<CParallelBlockJob> job(
              new CParallelBlockJob());
          job->Reset(
              index,
              candidate.BitOffset,
              candidate.ExpectedCrc);
          jobs.push_back(std::move(job));
        }
      }
      catch (const std::bad_alloc &)
      {
        pool.SetActiveWorkers(0);
        if (cpuContext && extraWorkers)
          sunpack_cpu_release_extra_for_context(
              cpuContext,
              extraWorkers);
        return E_OUTOFMEMORY;
      }

      for (size_t i = 1;
           i < jobs.size();
           i++)
        pool.Submit(jobs[i].get());

      callerWorkspace.Process(
          Base.InStream,
          inputSize,
          *jobs[0]);

      pool.WaitIdle();
      pool.SetActiveWorkers(0);
      if (cpuContext && extraWorkers)
        sunpack_cpu_release_extra_for_context(
            cpuContext,
            extraWorkers);

      bool advanced = false;

      for (;;)
      {
        CParallelBlockJob *currentJob = NULL;
        for (const auto &job: jobs)
          if (job->MarkerIndex == markerIndex)
          {
            currentJob = job.get();
            break;
          }

        if (!currentJob)
          break;

        const HRESULT jobRes =
            currentJob->Wait();
        if (jobRes != S_OK)
          return jobRes;

        if (currentJob->CalculatedCrc !=
            currentJob->ExpectedCrc)
        {
          BlockCrcError = true;
          return S_FALSE;
        }

        if (currentJob->Props.blockSize >
            (UInt32)level * kBlockSizeStep)
          return S_FALSE;

        const size_t endIndex =
            FindParallelMarker(
                markers,
                currentJob->EndBit);
        if (endIndex == (size_t)-1 ||
            endIndex <= markerIndex)
          return S_FALSE;

        RINOK(writeCompact(*currentJob))

        Base.NumBlocks++;
        combinedCrc =
            ((combinedCrc << 1) |
             (combinedCrc >> 31)) ^
            currentJob->ExpectedCrc;

        markerIndex = endIndex;
        advanced = true;

        if (progress)
        {
          const UInt64 inCur =
              (currentJob->EndBit + 7) >> 3;
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

        if (markerIndex >= markers.size() ||
            markers[markerIndex].IsEnd)
          break;
      }

      if (!advanced)
        return E_FAIL;
    }
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
  unsigned long long randomAccessInputSize = 0;
  const bool useParallelBlocks =
      (sunpack_cpu_current_job_context() || NumThreads > 1) &&
      !_outSizeDefined &&
      Base.DecodeAllStreams &&
      sunpack_input_random_access_size(
          inStream,
          &randomAccessInputSize) != 0;
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
