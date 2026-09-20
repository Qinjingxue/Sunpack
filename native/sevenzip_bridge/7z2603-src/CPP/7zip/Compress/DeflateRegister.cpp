// DeflateRegister.cpp
//
// Modified by SunPack, 2026-09-20:
// route generic RFC1951 decoder creation through the adaptive SunPack backend.

#include "StdAfx.h"

#include "../Common/RegisterCodec.h"

#include "DeflateDecoder.h"
#include "internal/zlib_ng_deflate_decoder.h"
#if !defined(Z7_EXTRACT_ONLY) && !defined(Z7_DEFLATE_EXTRACT_ONLY)
#include "DeflateEncoder.h"
#endif

namespace NCompress {
namespace NDeflate {

static void *CreateDec()
{
  return (void *)(ICompressCoder *)SunpackCreateAdaptiveDeflateDecoder();
}

#if !defined(Z7_EXTRACT_ONLY) && !defined(Z7_DEFLATE_EXTRACT_ONLY)
REGISTER_CODEC_CREATE(CreateEnc, NEncoder::CCOMCoder)
#else
#define CreateEnc NULL
#endif

REGISTER_CODEC_2(Deflate, CreateDec, CreateEnc, 0x40108, "Deflate")

}}
