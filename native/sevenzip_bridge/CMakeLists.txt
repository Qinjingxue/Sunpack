cmake_minimum_required(VERSION 3.20)

# The retained 7-Zip subset contains plenty of C sources, so C must be enabled.
project(sunpack_sevenzip LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

function(apply_release_optimizations target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/O2 /Oi /Ot /GL /Gy /Gw /GF>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
        )
    else()
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-O3 -flto -ffunction-sections -fdata-sections>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-flto -Wl,--gc-sections>
        )
    endif()
endfunction()

# Sources are UTF-8; without /utf-8 MSVC decodes them with the system code page and
# can fail to parse multi-byte sequences.
function(apply_source_charset target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /utf-8)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Bundled 7-Zip backend
#
# 7z2603-src is physically trimmed so that "what is in the tree" is exactly
# "what gets compiled" (see docs/zh-CN/sevenzip_source_trimming.md). The list
# therefore comes from the tree itself instead of a second hand-maintained
# manifest.
#
# It is an OBJECT library on purpose: 7-Zip registers archive handlers and
# codecs through file-local static initialisers that export no referenced
# symbol. A STATIC library would let the linker discard those objects and every
# CreateObject() call would fail with CLASS_E_CLASSNOTAVAILABLE. Object files
# placed straight into the final PE cannot be dropped that way.
#
# Compile configuration is deliberately NOT shared with the SunPack targets:
# WIN32_LEAN_AND_MEAN strips the Windows/COM types 7-Zip itself needs
# (LPCOLESTR, IUnknown, PROPID), so it must stay off here.
# ---------------------------------------------------------------------------
set(SUP7Z_7Z_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/7z2603-src")

file(GLOB_RECURSE SUP7Z_BUNDLED_7Z_SOURCES CONFIGURE_DEPENDS
    "${SUP7Z_7Z_ROOT}/C/*.c"
    "${SUP7Z_7Z_ROOT}/CPP/*.cpp"
)

list(LENGTH SUP7Z_BUNDLED_7Z_SOURCES SUP7Z_BUNDLED_7Z_SOURCE_COUNT)
if(NOT SUP7Z_BUNDLED_7Z_SOURCE_COUNT EQUAL 230)
    message(FATAL_ERROR
        "Trimmed 7-Zip tree must contribute exactly 230 translation units, found "
        "${SUP7Z_BUNDLED_7Z_SOURCE_COUNT}. Re-derive the keep set (regenerate "
        "docs/zh-CN/sevenzip_retained_sources.txt) or fix the tree.")
endif()

add_library(sunpack_7zip_objects OBJECT ${SUP7Z_BUNDLED_7Z_SOURCES})

# PRIVATE: the 7-Zip include root must not leak into the bridge sources, or
# bridge headers such as internal/sevenzip_sdk.hpp get shadowed by 7-Zip's.
target_include_directories(sunpack_7zip_objects PRIVATE ${SUP7Z_7Z_ROOT})

target_compile_definitions(sunpack_7zip_objects PRIVATE NOMINMAX)
apply_release_optimizations(sunpack_7zip_objects)
apply_source_charset(sunpack_7zip_objects)

if(WIN32)
    target_compile_definitions(sunpack_7zip_objects PRIVATE UNICODE _UNICODE)
    target_link_libraries(sunpack_7zip_objects PUBLIC OleAut32 Ole32 User32 AdvApi32)
endif()

# NOTE: assembly hot paths (Asm/x86/LzmaDecOpt.asm, 7zCrcOpt.asm, ...) are kept
# in the tree on purpose but are NOT wired into this target yet. This milestone
# only swaps the backend's link origin, so the portable C/C++ paths are used
# first; restoring the arch-optimised assembly is a separate change.

# Attaches the bundled 7-Zip to a target that needs it.
#
#   * the OBJECT files must go into the final PE (see the note above), and
#   * the bridge is now a source-level consumer of 7-Zip, so it also needs the
#     official headers that declare the interfaces, IIDs, property ids and
#     operation-result codes it used to hand-copy.
#
# The include directory is PRIVATE and scoped to the CPP subtree: exporting
# ${SUP7Z_7Z_ROOT} publicly would shadow the bridge's own internal/*.hpp
# headers, and nothing outside the bridge should see 7-Zip's headers at all.
function(sup7z_attach_bundled_7z target_name)
    if(WIN32 AND TARGET sunpack_7zip_objects)
        target_sources(${target_name} PRIVATE
            $<TARGET_OBJECTS:sunpack_7zip_objects>)
        target_include_directories(${target_name} PRIVATE ${SUP7Z_7Z_ROOT}/CPP)
    endif()
endfunction()


set(SUP7Z_INTERNAL_SOURCES
    src/internal/archive_extract.cpp
    src/internal/archive_crc_manifest.cpp
    src/internal/archive_open_probe.cpp
    src/internal/archive_open_plan.cpp
    src/internal/archive_resources.cpp
    src/internal/embedded_7z.cpp
    src/internal/operation_dispatch.cpp
    src/internal/password_testing.cpp
    src/internal/sevenzip_engine.cpp
    src/internal/sevenzip_formats.cpp
    src/internal/sevenzip_paths.cpp
    src/internal/sevenzip_properties.cpp
    src/internal/sevenzip_sdk.cpp
    src/internal/sevenzip_status.cpp
    src/internal/sevenzip_streams.cpp
    src/internal/sevenzip_volume_registry.cpp
    src/internal/sevenzip_writer_meters.cpp
    src/internal/strict_archive_validation.cpp
)

add_library(sunpack_sevenzip_core STATIC
    ${SUP7Z_INTERNAL_SOURCES}
)
apply_release_optimizations(sunpack_sevenzip_core)
apply_source_charset(sunpack_sevenzip_core)

target_include_directories(sunpack_sevenzip_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    # Headers only: the 7-Zip OBJECT files are deliberately NOT attached here.
    # core is a STATIC library, so archiving them would re-introduce the
    # "registrar object dropped" failure. Callers attach the objects themselves.
    target_include_directories(sunpack_sevenzip_core PRIVATE ${SUP7Z_7Z_ROOT}/CPP)
endif()

if(WIN32)
    target_compile_definitions(sunpack_sevenzip_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX SUP7Z_BUILD_DLL)
    target_link_libraries(sunpack_sevenzip_core PUBLIC OleAut32 Ole32)
endif()

add_library(sunpack_sevenzip SHARED
    src/archive_test.cpp
    src/c_api_operation.cpp
    src/c_api_passwords.cpp
    src/c_api_crc_manifest.cpp
    src/c_api_resources.cpp
    ${SUP7Z_INTERNAL_SOURCES}
)
apply_release_optimizations(sunpack_sevenzip)
apply_source_charset(sunpack_sevenzip)

target_include_directories(sunpack_sevenzip
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX SUP7Z_BUILD_DLL)
    target_link_libraries(sunpack_sevenzip PRIVATE OleAut32 Ole32)

    # Bundled 7-Zip objects plus the official headers the bridge now includes.
    # The objects are NOT routed through sunpack_sevenzip_core: that is a STATIC
    # library, and its archive members would be dropped again for the same
    # "no referenced symbol" reason the OBJECT library exists to avoid.
    sup7z_attach_bundled_7z(sunpack_sevenzip)
endif()

add_executable(sunpack_sevenzip_smoke
    tests/smoke.cpp
)
apply_release_optimizations(sunpack_sevenzip_smoke)
apply_source_charset(sunpack_sevenzip_smoke)

target_link_libraries(sunpack_sevenzip_smoke
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_smoke)

target_include_directories(sunpack_sevenzip_smoke
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(sunpack_sevenzip_async_output
    tests/async_output.cpp
)
apply_release_optimizations(sunpack_sevenzip_async_output)
apply_source_charset(sunpack_sevenzip_async_output)

target_link_libraries(sunpack_sevenzip_async_output
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_async_output)

target_include_directories(sunpack_sevenzip_async_output
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(sunpack_sevenzip_space_gate
    tests/space_gate.cpp
)
apply_release_optimizations(sunpack_sevenzip_space_gate)
apply_source_charset(sunpack_sevenzip_space_gate)

target_link_libraries(sunpack_sevenzip_space_gate
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_space_gate)

target_include_directories(sunpack_sevenzip_space_gate
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip_space_gate PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# L2: writer 重试 + 记账不变量单测（注入式失败）。
add_executable(sunpack_sevenzip_space_retry
    tests/space_retry.cpp
)
apply_release_optimizations(sunpack_sevenzip_space_retry)
apply_source_charset(sunpack_sevenzip_space_retry)

target_link_libraries(sunpack_sevenzip_space_retry
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_space_retry)

target_include_directories(sunpack_sevenzip_space_retry
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip_space_retry PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_executable(sunpack_sevenzip_writer_cost
    tests/writer_construction_cost.cpp
)
apply_release_optimizations(sunpack_sevenzip_writer_cost)
apply_source_charset(sunpack_sevenzip_writer_cost)

target_link_libraries(sunpack_sevenzip_writer_cost
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_writer_cost)

target_include_directories(sunpack_sevenzip_writer_cost
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(sunpack_sevenzip_worker
    src/worker.cpp
)
apply_release_optimizations(sunpack_sevenzip_worker)
apply_source_charset(sunpack_sevenzip_worker)

target_link_libraries(sunpack_sevenzip_worker
    PRIVATE sunpack_sevenzip_core
)

sup7z_attach_bundled_7z(sunpack_sevenzip_worker)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip_worker PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

    add_executable(sunpack_launcher src/launcher.cpp)
    apply_release_optimizations(sunpack_launcher)
    apply_source_charset(sunpack_launcher)
    target_compile_definitions(sunpack_launcher PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_link_libraries(sunpack_launcher PRIVATE Shell32)
endif()

enable_testing()
add_test(NAME sunpack_sevenzip_smoke COMMAND sunpack_sevenzip_smoke)
add_test(NAME sunpack_sevenzip_async_output COMMAND sunpack_sevenzip_async_output)
add_test(NAME sunpack_sevenzip_space_gate COMMAND sunpack_sevenzip_space_gate)
add_test(NAME sunpack_sevenzip_space_retry COMMAND sunpack_sevenzip_space_retry)
