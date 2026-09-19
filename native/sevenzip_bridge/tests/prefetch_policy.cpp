#include "../src/internal/sevenzip_streams.hpp"

#include <cstdlib>
#include <iostream>

namespace
{
    using sunpack::sevenzip::InputPrefetchConfig;
    using sunpack::sevenzip::input_prefetch_config_for_archive;

    bool check(
        const wchar_t *format_hint,
        bool native_volume_input,
        UInt32 expected_window_kib,
        std::size_t expected_depth,
        const char *label)
    {
        const InputPrefetchConfig config =
            input_prefetch_config_for_archive(format_hint, native_volume_input);
        const UInt32 expected_window_bytes = expected_window_kib * 1024;
        if (!config.enabled ||
            config.window_bytes != expected_window_bytes ||
            config.depth != expected_depth)
        {
            std::cerr << label
                      << ": expected " << expected_window_kib << " KiB x" << expected_depth
                      << ", got " << (config.window_bytes / 1024) << " KiB x" << config.depth
                      << ", enabled=" << config.enabled << "\n";
            return false;
        }
        return true;
    }
}

int main()
{
#ifdef _WIN32
    // Environment overrides tune the generic default only. The format-specific
    // production choices below must still win.
    _putenv_s("SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB", "768");
    _putenv_s("SUNPACK_SEVENZIP_PREFETCH_DEPTH", "3");
#endif

    bool ok = true;
    ok &= check(L"", false, 768, 3, "empty/default");
    ok &= check(L"7z", false, 768, 3, "7z/default");
    ok &= check(L"bz2", false, 768, 3, "bz2/default");
    ok &= check(L"gz", false, 768, 3, "gz/default");
    ok &= check(L"rar", false, 768, 3, "rar/default");
    ok &= check(L"tgz", false, 768, 3, "tgz/default");
    ok &= check(L"tbz2", false, 768, 3, "tbz2/default");
    ok &= check(L"txz", false, 768, 3, "txz/default");
    ok &= check(L"zst", false, 768, 3, "zst/default");

    ok &= check(L"zip", false, 128, 2, "zip");
    ok &= check(L"ZIP", false, 128, 2, "zip/case-normalization");
    ok &= check(L"tar", false, 2048, 2, "tar");
    ok &= check(L"rar", true, 256, 4, "rar/native-volumes");
    ok &= check(L"rar5", true, 256, 4, "rar5/native-volumes");
    ok &= check(L"xz", false, 1024, 4, "xz");
    ok &= check(L"tzst", false, 512, 1, "tzst");
    ok &= check(L"tar.zst", false, 512, 1, "tar.zst");

    return ok ? 0 : 1;
}
