#pragma once

#include <cstdint>

namespace sunpack::sevenzip
{

    enum class EmptyBoundedPasswordProbeDisposition
    {
        RejectInconclusive,
        TestAllItems,
        AcceptOpenProof,
    };

    inline EmptyBoundedPasswordProbeDisposition empty_bounded_password_probe_disposition(
        bool item_count_known,
        std::uint32_t item_count,
        bool encryption_evidence)
    {
        if (!item_count_known)
        {
            return EmptyBoundedPasswordProbeDisposition::RejectInconclusive;
        }
        if (item_count != 0)
        {
            return EmptyBoundedPasswordProbeDisposition::TestAllItems;
        }
        return encryption_evidence
            ? EmptyBoundedPasswordProbeDisposition::AcceptOpenProof
            : EmptyBoundedPasswordProbeDisposition::RejectInconclusive;
    }

} // namespace sunpack::sevenzip
