// SunpackSharedInput.h
//
// Private zero-copy input extension used only by the embedded SunPack/7-Zip build.
// It deliberately sits beside ISequentialInStream instead of changing the public
// 7-Zip stream ABI. Capability discovery happens once; decoder hot loops cache
// the returned interface pointer.

#ifndef SUNPACK_7ZIP_SHARED_INPUT_H
#define SUNPACK_7ZIP_SHARED_INPUT_H

#include "../IStream.h"

// Z7_CLASS_IMP_COM_N expands Z7_IFACE_COM7_IMP(interface) for every listed
// interface. Project-private interfaces therefore need the same method-list
// macro that upstream 7-Zip interfaces provide in IStream.h / IPassword.h.
#define Z7_IFACEM_ISunpackSharedInput(x) \
    x(Borrow(UInt32 maxSize, const Byte **data, UInt32 *size, UInt64 *token)) \
    x(ReleaseBorrowed(UInt64 token))

struct ISunpackSharedInput : public IUnknown
{
    Z7_IFACE_COM7_PURE(ISunpackSharedInput)
};

// Project-private IID. It is intentionally not an upstream 7-Zip interface.
inline const IID IID_ISunpackSharedInput =
{ 0x4d51fa91, 0x5a24, 0x4f6e, { 0x91, 0xf2, 0xf7, 0x33, 0x63, 0x7b, 0x9e, 0xa1 } };

#endif
