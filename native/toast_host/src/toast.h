#pragma once
#include <windows.h>
#include <cstdint>

#ifdef SUNPACK_TOAST_EXPORTS
#define SUNPACK_TOAST_API extern "C" __declspec(dllexport)
#else
#define SUNPACK_TOAST_API extern "C" __declspec(dllimport)
#endif

// create/show/clear/destroy must run on the same thread. No exception crosses
// this ABI; successful create owns one MTA apartment until destroy succeeds.
SUNPACK_TOAST_API HRESULT sunpack_toast_create(const wchar_t*, const wchar_t*, const wchar_t*, void**) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_show(void*, const std::uint8_t*, std::uint32_t, std::uint64_t) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_clear(void*) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_destroy(void*) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_register(const wchar_t*, const wchar_t*) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_unregister() noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_activate() noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_cancel_batch(wchar_t*, std::uint32_t) noexcept;
SUNPACK_TOAST_API HRESULT sunpack_toast_self_test() noexcept;
