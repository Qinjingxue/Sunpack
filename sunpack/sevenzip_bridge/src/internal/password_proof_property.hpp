#pragma once

#include "7zip/PropID.h"

// Size of the complete plaintext covered by a handler-verified checksum.
// The sentinel requires counting the decoded bytes during the member test.
inline constexpr PROPID kpidSunpackProofSize = kpidUserDefined + 256;
inline constexpr UInt64 kSunpackUnknownProofSize = static_cast<UInt64>(-1);
// Packed bytes needed for an independently authenticated member. A keyed
// checksum can authenticate an empty plaintext, so zero is a valid span.
inline constexpr PROPID kpidSunpackMacPackedSize = kpidUserDefined + 257;
// The proof's packed span (7z folder in the logical stream, ZIP member
// relative to its disk). RAR exposes its two inclusive disks.
inline constexpr PROPID kpidSunpackProofOffset = kpidUserDefined + 258;
inline constexpr PROPID kpidSunpackProofPackedSize = kpidUserDefined + 259;
inline constexpr PROPID kpidSunpackProofDisks = kpidUserDefined + 260;
inline constexpr PROPID kpidSunpackAesCopyStart = kpidUserDefined + 261;
// Start at the first ciphertext block or include the prior block for CBC.
inline constexpr UInt64 SunpackAesCopyReadStart(UInt64 offset) {
    return offset < 16 ? 0 : (offset & ~UInt64{15}) - 16;
}
// Archive-open callback property for a bounded member proof.
inline constexpr PROPID kpidSunpackBoundedPasswordProbe = kpidUserDefined + 262;
inline constexpr Int32 kSunpackVerifyMember = 2;
// The bounded ZIP handler read a local header that contradicts its directory.
inline constexpr Int32 kSunpackZipLocalHeaderConflict = 0x100;
