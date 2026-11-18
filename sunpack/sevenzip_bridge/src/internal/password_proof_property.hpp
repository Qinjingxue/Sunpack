#pragma once

#include "7zip/PropID.h"

// Size of the complete plaintext covered by a handler-verified checksum.
// The sentinel requires counting the decoded bytes during the member test.
inline constexpr PROPID kpidSunpackProofSize = kpidUserDefined + 256;
inline constexpr UInt64 kSunpackUnknownProofSize = static_cast<UInt64>(-1);
// Packed bytes needed for an independently authenticated member. A keyed
// checksum can authenticate an empty plaintext, so zero is a valid span.
inline constexpr PROPID kpidSunpackMacPackedSize = kpidUserDefined + 257;
// The selected item's packed offset (7z logical stream, ZIP disk-relative)
// and the packed bytes required there. RAR exposes its two inclusive disks.
inline constexpr PROPID kpidSunpackProofOffset = kpidUserDefined + 258;
inline constexpr PROPID kpidSunpackProofPackedSize = kpidUserDefined + 259;
inline constexpr PROPID kpidSunpackProofDisks = kpidUserDefined + 260;
inline constexpr PROPID kpidSunpackAesCopyStart = kpidUserDefined + 261;
inline constexpr Int32 kSunpackVerifyMember = 2;
