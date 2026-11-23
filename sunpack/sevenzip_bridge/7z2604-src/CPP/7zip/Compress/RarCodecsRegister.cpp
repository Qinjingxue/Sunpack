// RarCodecsRegister.cpp
// SunPack modifications recorded on 2026-11-18.

#include "StdAfx.h"

#include "../Common/RegisterCodec.h"

#include "Rar3Decoder.h"
#include "Rar5Decoder.h"

namespace NCompress {

#define CREATE_CODEC(x) REGISTER_CODEC_CREATE(CreateCodec ## x, NRar ## x::CDecoder())

CREATE_CODEC(3)
CREATE_CODEC(5)

#define RAR_CODEC(x, name) { CreateCodec ## x, NULL, 0x40300 + x, "Rar" name, 1, false }

REGISTER_CODECS_VAR
{
  RAR_CODEC(3, "3"),
  RAR_CODEC(5, "5"),
};

REGISTER_CODECS(Rar)

}
