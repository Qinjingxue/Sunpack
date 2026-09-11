#pragma once

#include <string>
#include <vector>

namespace sunpack::sevenzip
{

    struct EmbeddedArchiveCandidate
    {
        std::wstring path;
        unsigned long long offset = 0;
        unsigned char format_id = 0;
        std::wstring archive_type;
    };

    std::vector<EmbeddedArchiveCandidate> find_embedded_archive_candidates(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths);

    using EmbeddedSevenZipCandidate = EmbeddedArchiveCandidate;

    std::vector<EmbeddedSevenZipCandidate> find_embedded_seven_zip_candidates(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths);

    bool is_standard_seven_zip_path(const std::wstring &path);

} // namespace sunpack::sevenzip
