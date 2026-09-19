#include "archive_operations.hpp"

#include "sevenzip_callbacks.hpp"
#include "sevenzip_formats.hpp"
#include "sevenzip_paths.hpp"
#include "sevenzip_properties.hpp"
#include "sevenzip_status.hpp"
#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip {


#ifdef _WIN32

CrcManifestResult read_archive_crc_manifest_internal(

    CreateObjectFunc create_object,

    const std::wstring& archive_path,

    const std::wstring& password,

    const std::vector<std::wstring>& part_paths,

    UInt32 max_items

) {

    CrcManifestResult result;

    bool any_format_created = false;

    HRESULT last_hr = E_FAIL;

    Int32 last_op_res = kOpOk;
    bool last_encryption_evidence = false;



    for (const GUID& format : candidate_formats(archive_path, part_paths)) {

        ComPtr<IInArchive> archive;

        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));

        if (hr != S_OK || !archive) {

            last_hr = hr;

            continue;

        }

        any_format_created = true;



        bool stream_opened = false;

        ComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened);

        if (!stream_opened) {

            result.status = PasswordTestStatus::Error;

            result.message = "archive file could not be opened";

            return result;

        }



        auto* raw_open_callback = new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths);
        ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        last_encryption_evidence = raw_open_callback->password_requested();

        if (hr != S_OK) {

            last_hr = hr;

            continue;

        }



        result.is_archive = true;

        UInt32 num_items = 0;

        if (archive->GetNumberOfItems(&num_items) != S_OK) {

            archive->Close();

            result.status = PasswordTestStatus::Error;

            result.message = "archive item list could not be read";

            return result;

        }

        result.item_count = num_items;



        const UInt32 limit = max_items == 0 ? num_items : std::min(max_items, num_items);

        for (UInt32 index = 0; index < limit; ++index) {

            PROPVARIANT value{};

            const bool is_dir = get_item_property(archive.get(), index, kpidIsDir, value) ? prop_bool(value) : false;

            clear_prop(value);



            bool encrypted = false;

            if (get_item_property(archive.get(), index, kpidEncrypted, value)) {

                encrypted = prop_bool(value);

            }

            clear_prop(value);

            result.encrypted = result.encrypted || encrypted;



            if (is_dir) {

                continue;

            }



            CrcManifestItem item;

            if (get_item_property(archive.get(), index, kpidName, value)) {

                item.path = prop_text(value);

            }

            clear_prop(value);

            if (item.path.empty()) {

                item.path = L"#" + std::to_wstring(index);

            }



            if (get_item_property(archive.get(), index, kpidSize, value)) {

                item.size = prop_u64(value);

            }

            clear_prop(value);



            if (get_item_property(archive.get(), index, kpidCRC, value)) {

                item.crc32 = prop_u32(value);

                item.has_crc = true;

            }

            clear_prop(value);



            result.file_count += 1;

            result.files.push_back(std::move(item));

        }



        auto* raw_extract_callback = new ExtractCallback(password);

        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);

        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());

        last_hr = hr;

        last_op_res = raw_extract_callback->operation_result();
        last_encryption_evidence = last_encryption_evidence ||
            raw_extract_callback->password_requested() || result.encrypted;

        archive->Close();



        if (hr == S_OK && last_op_res == kOpOk) {

            result.status = PasswordTestStatus::Ok;

            result.message = "archive CRC manifest read";

            return result;

        }

        result.checksum_error = last_op_res == kOpCrcError;

        if (looks_wrong_password(hr, last_op_res, last_encryption_evidence)) {

            result.status = PasswordTestStatus::WrongPassword;

            result.encrypted = true;

            result.message = "archive is encrypted or password is wrong";

            return result;

        }

        if (looks_damaged(last_op_res) || result.checksum_error) {

            result.status = PasswordTestStatus::Damaged;

            result.damaged = true;

            result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

            return result;

        }

    }



    if (!any_format_created) {

        result.status = PasswordTestStatus::Unsupported;

        result.message = "7z.dll did not create a supported archive handler";

    } else if (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence)) {

        result.status = PasswordTestStatus::WrongPassword;

        result.encrypted = true;

        result.message = "archive is encrypted or password is wrong";

    } else if (looks_damaged(last_op_res)) {

        result.status = PasswordTestStatus::Damaged;

        result.damaged = true;

        result.message = "archive appears damaged";

    } else {

        result.status = PasswordTestStatus::Unsupported;

        result.message = "archive could not be opened by supported handlers";

    }

    return result;

}

#endif

CrcManifestResult read_archive_crc_manifest_with_parts(

    const std::wstring& seven_zip_dll_path,

    const std::wstring& archive_path,

    const std::vector<std::wstring>& part_paths,

    const std::wstring& password,

    UInt32 max_items

) {

#ifdef _WIN32

    const CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);

    if (!create_object) {

        CrcManifestResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        result.message = "7z backend could not be loaded";

        return result;

    }

    return read_archive_crc_manifest_internal(create_object, archive_path, password, part_paths, max_items);

#else

    (void)seven_zip_dll_path;

    (void)archive_path;

    (void)part_paths;

    (void)password;

    (void)max_items;

    CrcManifestResult result;

    result.status = PasswordTestStatus::BackendUnavailable;

    result.message = "native archive CRC manifest is only implemented on Windows";

    return result;

#endif

}


}  // namespace sunpack::sevenzip
