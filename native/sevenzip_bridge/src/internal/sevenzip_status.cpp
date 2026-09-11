#include "sevenzip_status.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool looks_wrong_password(HRESULT hr, Int32 op_res, bool encryption_evidence)
    {

        if (op_res == kOpWrongPassword)
        {
            return true;
        }
        return encryption_evidence &&
               (op_res == kOpDataError || op_res == kOpCrcError || hr == S_FALSE);
    }

    bool looks_damaged(Int32 op_res)
    {

        return op_res == kOpUnexpectedEnd || op_res == kOpHeadersError || op_res == kOpIsNotArc || op_res == kOpUnavailable;
    }

    bool looks_damaged_probe_result(const std::wstring &password, Int32 op_res)
    {

        return looks_damaged(op_res) || (password.empty() && (op_res == kOpDataError || op_res == kOpCrcError));
    }

    const char *operation_result_name(Int32 op_res)
    {

        switch (op_res)
        {

        case kOpOk:

            return "ok";

        case kOpUnsupportedMethod:

            return "unsupported_method";

        case kOpDataError:

            return "data_error";

        case kOpCrcError:

            return "crc_error";

        case kOpUnavailable:

            return "unavailable";

        case kOpUnexpectedEnd:

            return "unexpected_end";

        case kOpDataAfterEnd:

            return "data_after_end";

        case kOpIsNotArc:

            return "is_not_archive";

        case kOpHeadersError:

            return "headers_error";

        case kOpWrongPassword:

            return "wrong_password";
        }

        return "unknown";
    }

#endif

    const char *status_name(PasswordTestStatus status)
    {

        switch (status)
        {

        case PasswordTestStatus::Ok:

            return "ok";

        case PasswordTestStatus::WrongPassword:

            return "wrong_password";

        case PasswordTestStatus::Damaged:

            return "damaged";

        case PasswordTestStatus::Unsupported:

            return "unsupported";

        case PasswordTestStatus::BackendUnavailable:

            return "backend_unavailable";

        case PasswordTestStatus::Error:

            return "error";

        case PasswordTestStatus::NeedsVolumeOrTailDamaged:

            return "needs_volume_or_tail_damaged";
        }

        return "unknown";
    }

} // namespace sunpack::sevenzip
