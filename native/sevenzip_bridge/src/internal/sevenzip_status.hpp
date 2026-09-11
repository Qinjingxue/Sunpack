#pragma once

#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool looks_wrong_password(HRESULT hr, Int32 op_res, bool encryption_evidence);

    bool looks_damaged(Int32 op_res);

    bool looks_damaged_probe_result(const std::wstring &password, Int32 op_res);

    const char *operation_result_name(Int32 op_res);

#endif

}
