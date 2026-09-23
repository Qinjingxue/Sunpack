// 7-Zip GUID definitions.
//
// Upstream requires every GUID to be initialised exactly once per project, and
// MyInitGuid.h must be included *before* the interface declarations so that
// INITGUID is set when Z7_DEFINE_GUID expands (see Common/MyInitGuid.h).
//
// This used to be an accident of DllExports2.cpp — the 7z.dll entry point file
// that SunPack no longer calls into. Making it an explicit translation unit
// means the GUID ownership is stated instead of inherited, and lets the DLL
// export layer be trimmed away.

// The Windows COM headers must come first: MyInitGuid.h immediately declares the
// Z7_DEFINE_GUID macro, and everything after it is expanded with INITGUID set,
// so IUnknown / PROPID / BSTR have to be available by then. The SunPack targets
// build with WIN32_LEAN_AND_MEAN, which leaves <Windows.h> without them.
#include <objbase.h>
#include <oleauto.h>

#include "Common/MyInitGuid.h"

// Every interface header whose IIDs 7-Zip references internally must be listed
// here, because with INITGUID set the Z7_DEFINE_GUID macros in these headers are
// what actually define the symbols. ICoder.h in particular is needed even though
// SunPack never creates a coder directly: the decode path and the coder mixer
// QueryInterface for IID_ICompressCoder / IID_ICompressCoder2 / IID_ICompressFilter.
#include "7zip/ICoder.h"
#include "7zip/Archive/IArchive.h"
#include "7zip/IPassword.h"
#include "7zip/IProgress.h"
#include "7zip/IStream.h"

#include "internal/positioned_output.hpp"

Z7_DEFINE_GUID(CLSID_CArchiveHandler,
               k_7zip_GUID_Data1,
               k_7zip_GUID_Data2,
               k_7zip_GUID_Data3_Common,
               0x10, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00);
