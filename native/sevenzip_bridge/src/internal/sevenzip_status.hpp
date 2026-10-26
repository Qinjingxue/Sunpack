#pragma once

#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    inline bool is_memory_hresult(HRESULT hr) noexcept
    {
        return hr == E_OUTOFMEMORY ||
               hr == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY) ||
               hr == HRESULT_FROM_WIN32(ERROR_COMMITMENT_LIMIT);
    }

    bool looks_wrong_password(HRESULT hr, Int32 op_res, bool encryption_evidence);

    bool looks_damaged(Int32 op_res);

    const char *operation_result_name(Int32 op_res);

#endif

}
