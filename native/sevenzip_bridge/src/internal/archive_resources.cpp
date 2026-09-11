#include "archive_operations.hpp"

#include "sevenzip_callbacks.hpp"
#include "sevenzip_formats.hpp"
#include "sevenzip_paths.hpp"
#include "sevenzip_properties.hpp"
#include "sevenzip_status.hpp"
#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    ResourceAnalysisResult analyze_archive_resources_internal(

        CreateObjectFunc create_object,

        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths

    )
    {

        ResourceAnalysisResult result;

        result.archive_size = archive_input_size(archive_path, part_paths);

        bool any_format_created = false;

        HRESULT last_hr = E_FAIL;
        bool last_encryption_evidence = false;

        for (const GUID &format : candidate_formats(archive_path, part_paths))
        {

            ComPtr<IInArchive> archive;

            HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void **>(archive.out()));

            if (hr != S_OK || !archive)
            {

                last_hr = hr;

                continue;
            }

            any_format_created = true;

            bool stream_opened = false;

            ComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened);

            if (!stream_opened)
            {

                result.status = PasswordTestStatus::Error;

                result.message = "archive file could not be opened";

                return result;
            }

            auto *raw_open_callback = new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths);
            ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

            hr = archive->Open(stream.get(), nullptr, open_callback.get());
            last_encryption_evidence = raw_open_callback->password_requested();

            if (hr != S_OK)
            {

                last_hr = hr;

                continue;
            }

            const bool ok = fill_resource_analysis_from_open_archive(archive.get(), result);

            archive->Close();

            if (!ok)
            {

                return result;
            }

            return result;
        }

        if (!any_format_created)
        {

            result.status = PasswordTestStatus::Unsupported;

            result.message = "7z.dll did not create a supported archive handler";
        }
        else if (looks_wrong_password(last_hr, kOpOk, last_encryption_evidence))
        {

            result.status = PasswordTestStatus::WrongPassword;

            result.encrypted = true;

            result.message = "archive is encrypted or password is wrong";
        }
        else
        {

            result.status = PasswordTestStatus::Unsupported;

            result.message = "archive could not be opened by supported handlers";
        }

        return result;
    }

#endif

    ResourceAnalysisResult analyze_archive_resources_with_parts(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        const std::wstring &password

    )
    {

#ifdef _WIN32

        ComModule module(seven_zip_dll_path);

        auto create_object = module.create_object();

        if (!create_object)
        {

            ResourceAnalysisResult result;

            result.status = PasswordTestStatus::BackendUnavailable;

            result.message = "7z.dll could not be loaded";

            return result;
        }

        return analyze_archive_resources_internal(create_object, archive_path, password, part_paths);

#else

        (void)seven_zip_dll_path;

        (void)archive_path;

        (void)part_paths;

        (void)password;

        ResourceAnalysisResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        result.message = "native archive resource analysis is only implemented on Windows";

        return result;

#endif
    }

} // namespace sunpack::sevenzip
