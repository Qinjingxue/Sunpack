// BZip2Crc.cpp

#include "StdAfx.h"

#include "BZip2Crc.h"

MY_ALIGN(64)
UInt32 CBZip2Crc::Table[256];
MY_ALIGN(64)
UInt32 CBZip2Crc::RepeatTables[3][256];

static const UInt32 kBZip2CrcPoly = 0x04c11db7;  /* AUTODIN II, Ethernet, & FDDI */

void CBZip2Crc::InitTable()
{
  for (UInt32 i = 0; i < 256; i++)
  {
    UInt32 r = i << 24;
    for (unsigned j = 0; j < 8; j++)
      r = (r << 1) ^ (kBZip2CrcPoly & ((UInt32)0 - (r >> 31)));
    Table[i] = r;
  }
  for (unsigned slice = 0; slice < 3; slice++)
  {
    const UInt32 *previous = slice == 0 ? Table : RepeatTables[slice - 1];
    for (unsigned i = 0; i < 256; i++)
    {
      const UInt32 r = previous[i];
      RepeatTables[slice][i] = Table[r >> 24] ^ (r << 8);
    }
  }
}

void CBZip2Crc::UpdateRepeat(Byte value, unsigned size)
{
  // Advance the existing big-endian CRC four equal output bytes at a time.
  const UInt32 word = (UInt32)value * 0x01010101;
  while (size >= 4)
  {
    const UInt32 r = _value ^ word;
    _value = RepeatTables[2][r >> 24] ^ RepeatTables[1][(r >> 16) & 0xff] ^
        RepeatTables[0][(r >> 8) & 0xff] ^ Table[r & 0xff];
    size -= 4;
  }
  while (size--)
    UpdateByte(value);
}

static
class CBZip2CrcTableInit
{
public:
  CBZip2CrcTableInit() { CBZip2Crc::InitTable(); }
} g_BZip2CrcTableInit;
