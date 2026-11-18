#pragma once

#include "7zip/PropID.h"

// Size of the complete plaintext covered by a handler-verified checksum.
// Kept separate from kpidCRC, which is returned to callers as a plaintext CRC.
inline constexpr PROPID kpidSunpackProofSize = kpidUserDefined + 256;
inline constexpr PROPID kpidSunpackMacPackedSize = kpidUserDefined + 257;
// The selected item's packed offset (7z logical stream, ZIP disk-relative)
// and the packed bytes required there. RAR exposes its two inclusive disks.
inline constexpr PROPID kpidSunpackProofOffset = kpidUserDefined + 258;
inline constexpr PROPID kpidSunpackProofPackedSize = kpidUserDefined + 259;
inline constexpr PROPID kpidSunpackProofDisks = kpidUserDefined + 260;
inline constexpr PROPID kpidSunpackAesCopyStart = kpidUserDefined + 261;
inline constexpr Int32 kSunpackVerifyMember = 2;
