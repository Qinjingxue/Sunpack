cmake_minimum_required(VERSION 3.20)

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


function(apply_source_charset target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /utf-8)
    endif()
endfunction()

set(SUP7Z_7Z_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/7z2603-src")

# zlib-ng is used only for selected ZIP Deflate entries. Keep the exact
# benchmarked 2.3.3 sources in-tree so native builds remain deterministic and
# fully offline, like the bundled 7-Zip backend.
set(SUP7Z_ZLIB_NG_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/zlib-ng-2.3.3")
if(NOT EXISTS "${SUP7Z_ZLIB_NG_ROOT}/CMakeLists.txt")
    message(FATAL_ERROR "Vendored zlib-ng 2.3.3 source tree is missing")
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static third-party libraries" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable third-party tests" FORCE)
set(WITH_GTEST OFF CACHE BOOL "Disable zlib-ng gtest targets" FORCE)
set(WITH_FUZZERS OFF CACHE BOOL "Disable zlib-ng fuzz targets" FORCE)
set(WITH_BENCHMARKS OFF CACHE BOOL "Disable zlib-ng benchmark targets" FORCE)
set(WITH_BENCHMARK_APPS OFF CACHE BOOL "Disable zlib-ng benchmark apps" FORCE)
set(WITH_GZFILEOP OFF CACHE BOOL "SunPack only needs in-memory inflate" FORCE)
set(ZLIB_COMPAT OFF CACHE BOOL "Use the collision-free zlib-ng native API" FORCE)
set(ZLIB_ALIASES OFF CACHE BOOL "Do not publish zlib compatibility aliases" FORCE)
set(WITH_OPTIM ON CACHE BOOL "Enable zlib-ng optimized inflate paths" FORCE)
set(WITH_RUNTIME_CPU_DETECTION ON CACHE BOOL "Dispatch zlib-ng SIMD at runtime" FORCE)
set(WITH_NATIVE_INSTRUCTIONS OFF CACHE BOOL "Keep release binaries CPU-portable" FORCE)
set(INSTALL_UTILS OFF CACHE BOOL "Do not build zlib-ng utilities" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "Do not install embedded zlib-ng separately" FORCE)
add_subdirectory(
    "${SUP7Z_ZLIB_NG_ROOT}"
    "${CMAKE_CURRENT_BINARY_DIR}/zlib-ng"
    EXCLUDE_FROM_ALL)

option(SUP7Z_USE_X64_ASM
    "Use upstream 7-Zip x64 assembly hot paths (LZMA decoder, CRC32/CRC64, AES, SHA)"
    ON)
option(SUP7Z_USE_ARM64_ASM
    "Use upstream 7-Zip ARM64 LZMA decoder assembly hot path"
    ON)
option(SUP7Z_ENABLE_PIPELINE_TIMING
    "Build the benchmark-only worker pipeline timing instrumentation"
    OFF)

set(SUP7Z_TARGET_UARCH "unknown")
if(MSVC)
    if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID)
        set(SUP7Z_TARGET_UARCH "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}")
    elseif(CMAKE_C_COMPILER_ARCHITECTURE_ID)
        set(SUP7Z_TARGET_UARCH "${CMAKE_C_COMPILER_ARCHITECTURE_ID}")
    elseif(CMAKE_GENERATOR_PLATFORM)
        set(SUP7Z_TARGET_UARCH "${CMAKE_GENERATOR_PLATFORM}")
    else()
        set(SUP7Z_TARGET_UARCH "unknown")
    endif()
endif()

set(SUP7Z_X64_ASM_ENABLED OFF)
if(SUP7Z_USE_X64_ASM AND
   (SUP7Z_TARGET_UARCH STREQUAL "x64" OR SUP7Z_TARGET_UARCH STREQUAL "AMD64"))
    set(SUP7Z_X64_ASM_ENABLED ON)
endif()

set(SUP7Z_ARM64_ASM_ENABLED OFF)
if(SUP7Z_USE_ARM64_ASM AND
   (SUP7Z_TARGET_UARCH STREQUAL "ARM64" OR SUP7Z_TARGET_UARCH STREQUAL "arm64"))
    set(SUP7Z_ARM64_ASM_ENABLED ON)
endif()

# Keep the existing x64 selection guard stable so existing build-x64 directories
# do not need a one-time clean after this change. ARM64 gets its own guard file:
# old ARM64 build directories did not have this file, so the first optimized
# configure is a normal migration; later ON/OFF flips are rejected for clean A/B.
set(SUP7Z_ASM_LAST_SELECTION_FILE "${CMAKE_BINARY_DIR}/sup7z_asm_last_selection.txt")
if(EXISTS "${SUP7Z_ASM_LAST_SELECTION_FILE}")
    file(READ "${SUP7Z_ASM_LAST_SELECTION_FILE}" SUP7Z_ASM_LAST_SELECTION)
    string(STRIP "${SUP7Z_ASM_LAST_SELECTION}" SUP7Z_ASM_LAST_SELECTION)
    if(NOT SUP7Z_ASM_LAST_SELECTION STREQUAL "${SUP7Z_X64_ASM_ENABLED}")
        message(FATAL_ERROR
            "SUP7Z_USE_X64_ASM changed from "
            "'${SUP7Z_ASM_LAST_SELECTION}' to '${SUP7Z_X64_ASM_ENABLED}' in the same build "
            "directory (${CMAKE_BINARY_DIR}). Delete that directory, or configure the other "
            "setting into its own build directory (e.g. build-asm-off), so objects left over "
            "from the previous run cannot be reused.")
    endif()
endif()
file(WRITE "${SUP7Z_ASM_LAST_SELECTION_FILE}" "${SUP7Z_X64_ASM_ENABLED}")

set(SUP7Z_ARM64_ASM_LAST_SELECTION_FILE
    "${CMAKE_BINARY_DIR}/sup7z_arm64_asm_last_selection.txt")
if(EXISTS "${SUP7Z_ARM64_ASM_LAST_SELECTION_FILE}")
    file(READ "${SUP7Z_ARM64_ASM_LAST_SELECTION_FILE}" SUP7Z_ARM64_ASM_LAST_SELECTION)
    string(STRIP "${SUP7Z_ARM64_ASM_LAST_SELECTION}" SUP7Z_ARM64_ASM_LAST_SELECTION)
    if(NOT SUP7Z_ARM64_ASM_LAST_SELECTION STREQUAL "${SUP7Z_ARM64_ASM_ENABLED}")
        message(FATAL_ERROR
            "SUP7Z_USE_ARM64_ASM changed from "
            "'${SUP7Z_ARM64_ASM_LAST_SELECTION}' to '${SUP7Z_ARM64_ASM_ENABLED}' in the same "
            "build directory (${CMAKE_BINARY_DIR}). Delete that directory, or configure the "
            "other setting into its own build directory (e.g. build-arm64-asm-off), so the "
            "LzmaDec object cannot be accidentally reused across A/B builds.")
    endif()
endif()
file(WRITE "${SUP7Z_ARM64_ASM_LAST_SELECTION_FILE}" "${SUP7Z_ARM64_ASM_ENABLED}")

set(SUP7Z_X64_ASM_SOURCES
    "${SUP7Z_7Z_ROOT}/Asm/x86/LzmaDecOpt.asm"
    "${SUP7Z_7Z_ROOT}/Asm/x86/7zCrcOpt.asm"
    "${SUP7Z_7Z_ROOT}/Asm/x86/XzCrc64Opt.asm"
    "${SUP7Z_7Z_ROOT}/Asm/x86/AesOpt.asm"
    "${SUP7Z_7Z_ROOT}/Asm/x86/Sha1Opt.asm"
    "${SUP7Z_7Z_ROOT}/Asm/x86/Sha256Opt.asm"
)
set(SUP7Z_ARM64_LZMA_ASM_SOURCE
    "${SUP7Z_7Z_ROOT}/Asm/arm64/LzmaDecOpt.S")
set(SUP7Z_ARM64_LZMA_ASM_INCLUDE
    "${SUP7Z_7Z_ROOT}/Asm/arm64/7zAsm.S")


file(GLOB_RECURSE SUP7Z_BUNDLED_7Z_SOURCES CONFIGURE_DEPENDS
    "${SUP7Z_7Z_ROOT}/C/*.c"
    "${SUP7Z_7Z_ROOT}/CPP/*.cpp"
)

list(LENGTH SUP7Z_BUNDLED_7Z_SOURCES SUP7Z_BUNDLED_7Z_SOURCE_COUNT)
if(NOT SUP7Z_BUNDLED_7Z_SOURCE_COUNT EQUAL 228)
    message(FATAL_ERROR
        "Trimmed 7-Zip tree must contribute exactly 228 translation units, found "
        "${SUP7Z_BUNDLED_7Z_SOURCE_COUNT}. Re-derive the keep set (regenerate "
        "docs/zh-CN/sevenzip_retained_sources.txt) or fix the tree.")
endif()


if(SUP7Z_X64_ASM_ENABLED)
    set(SUP7Z_C_IMPLEMENTATIONS_REPLACED_BY_ASM
        7zCrcOpt.c
        XzCrc64Opt.c
        AesOpt.c
        Sha1Opt.c
        Sha256Opt.c)

    set(SUP7Z_BUNDLED_7Z_SOURCES_WITHOUT_ASM_TWINS ${SUP7Z_BUNDLED_7Z_SOURCES})
    foreach(SUP7Z_C_NAME IN LISTS SUP7Z_C_IMPLEMENTATIONS_REPLACED_BY_ASM)
        list(FILTER SUP7Z_BUNDLED_7Z_SOURCES_WITHOUT_ASM_TWINS
            EXCLUDE REGEX "/C/${SUP7Z_C_NAME}$")
    endforeach()

    list(LENGTH SUP7Z_BUNDLED_7Z_SOURCES_WITHOUT_ASM_TWINS
        SUP7Z_BUNDLED_7Z_SOURCE_COUNT_WITHOUT_ASM_TWINS)
    math(EXPR SUP7Z_BUNDLED_7Z_ASM_SWAP_REMOVED
        "${SUP7Z_BUNDLED_7Z_SOURCE_COUNT} - ${SUP7Z_BUNDLED_7Z_SOURCE_COUNT_WITHOUT_ASM_TWINS}")
    if(NOT SUP7Z_BUNDLED_7Z_SOURCE_COUNT_WITHOUT_ASM_TWINS EQUAL 223)
        message(FATAL_ERROR
            "x64 assembly swap must remove exactly 5 C fallbacks "
            "(7zCrcOpt.c, XzCrc64Opt.c, AesOpt.c, Sha1Opt.c, Sha256Opt.c), but "
            "removed ${SUP7Z_BUNDLED_7Z_ASM_SWAP_REMOVED} and left "
            "${SUP7Z_BUNDLED_7Z_SOURCE_COUNT_WITHOUT_ASM_TWINS} translation units. "
            "Leaving a C twin in place would link-fail on duplicate symbols.")
    endif()

    set(SUP7Z_BUNDLED_7Z_SOURCES ${SUP7Z_BUNDLED_7Z_SOURCES_WITHOUT_ASM_TWINS})

endif()

if(SUP7Z_X64_ASM_ENABLED OR SUP7Z_ARM64_ASM_ENABLED)
    # Both optimized LZMA paths replace only LzmaDec_DecodeReal_3; the rest of
    # LzmaDec.c stays compiled by the normal C compiler.
    set_source_files_properties(
        "${SUP7Z_7Z_ROOT}/C/LzmaDec.c"
        PROPERTIES
        COMPILE_DEFINITIONS Z7_LZMA_DEC_OPT)
endif()

if(SUP7Z_X64_ASM_ENABLED)
    message(STATUS
        "7-Zip asm: enabled (x64 MASM) - LzmaDecOpt, 7zCrcOpt, XzCrc64Opt, "
        "AesOpt, Sha1Opt, Sha256Opt; Sort/LzFindOpt intentionally omitted")
elseif(SUP7Z_ARM64_ASM_ENABLED)
    message(STATUS
        "7-Zip asm: enabled (ARM64 clang-cl) - LzmaDecOpt.S; "
        "CRC/AES/SHA keep upstream C/intrinsics")
else()
    message(STATUS
        "7-Zip asm: disabled (target arch '${SUP7Z_TARGET_UARCH}', "
        "x64=${SUP7Z_USE_X64_ASM}, ARM64=${SUP7Z_USE_ARM64_ASM}) - "
        "using upstream C/intrinsics")
endif()


add_library(sunpack_7zip_objects OBJECT ${SUP7Z_BUNDLED_7Z_SOURCES})


target_include_directories(sunpack_7zip_objects PRIVATE
    ${SUP7Z_7Z_ROOT}
    ${SUP7Z_7Z_ROOT}/CPP
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(sunpack_7zip_objects PRIVATE NOMINMAX)
apply_release_optimizations(sunpack_7zip_objects)
apply_source_charset(sunpack_7zip_objects)

if(WIN32)
    target_compile_definitions(sunpack_7zip_objects PRIVATE UNICODE _UNICODE)
    target_link_libraries(sunpack_7zip_objects PUBLIC OleAut32 User32 AdvApi32)
endif()


if(SUP7Z_X64_ASM_ENABLED)

    foreach(SUP7Z_ASM_SOURCE IN LISTS SUP7Z_X64_ASM_SOURCES)
        if(NOT EXISTS "${SUP7Z_ASM_SOURCE}")
            message(FATAL_ERROR
                "x64 assembly is enabled but ${SUP7Z_ASM_SOURCE} is missing. "
                "Either restore it from upstream or configure with "
                "-DSUP7Z_USE_X64_ASM=OFF - do not build a half-swapped tree.")
        endif()
    endforeach()

    enable_language(ASM_MASM)

    add_library(sunpack_7zip_asm_objects OBJECT ${SUP7Z_X64_ASM_SOURCES})

    target_include_directories(sunpack_7zip_asm_objects
        PRIVATE ${SUP7Z_7Z_ROOT}/Asm/x86)
endif()

if(SUP7Z_ARM64_ASM_ENABLED)
    if(NOT EXISTS "${SUP7Z_ARM64_LZMA_ASM_SOURCE}" OR
       NOT EXISTS "${SUP7Z_ARM64_LZMA_ASM_INCLUDE}")
        message(FATAL_ERROR
            "ARM64 LZMA assembly is enabled but the upstream Asm/arm64 sources are missing. "
            "Restore LzmaDecOpt.S + 7zAsm.S or configure with "
            "-DSUP7Z_USE_ARM64_ASM=OFF.")
    endif()

    if(NOT SUP7Z_CLANG_CL_EXECUTABLE)
        # Do not pre-create this cache entry as an empty string: find_program()
        # skips searching when its result variable is already defined. A user
        # supplied -DSUP7Z_CLANG_CL_EXECUTABLE=<path> therefore wins; otherwise
        # we discover the host clang-cl from the selected VS instance or PATH.
        unset(SUP7Z_CLANG_CL_EXECUTABLE CACHE)
        find_program(SUP7Z_CLANG_CL_EXECUTABLE
            NAMES clang-cl.exe clang-cl
            HINTS
                "${CMAKE_GENERATOR_INSTANCE}/VC/Tools/Llvm/x64/bin"
                "${CMAKE_GENERATOR_INSTANCE}/VC/Tools/Llvm/ARM64/bin"
                "$ENV{VCINSTALLDIR}/Tools/Llvm/x64/bin"
                "$ENV{VCINSTALLDIR}/Tools/Llvm/ARM64/bin"
            DOC "clang-cl executable used only to assemble upstream 7-Zip ARM64 LzmaDecOpt.S"
            NO_CMAKE_FIND_ROOT_PATH)
    endif()
    if(NOT SUP7Z_CLANG_CL_EXECUTABLE)
        message(FATAL_ERROR
            "ARM64 LZMA assembly requires clang-cl, matching upstream 7-Zip. "
            "Install the Visual Studio 'C++ Clang tools for Windows' component, put "
            "clang-cl on PATH, set -DSUP7Z_CLANG_CL_EXECUTABLE=<path>, or deliberately "
            "configure -DSUP7Z_USE_ARM64_ASM=OFF.")
    endif()

    set(SUP7Z_ARM64_ASM_OUTPUT_DIR
        "${CMAKE_CURRENT_BINARY_DIR}/sunpack_7zip_arm64_asm")
    set(SUP7Z_ARM64_LZMA_OBJECT
        "${SUP7Z_ARM64_ASM_OUTPUT_DIR}/LzmaDecOpt.obj")

    # This is the same compilation model used by upstream Windows ARM64 builds:
    # clang-cl preprocesses the GNU-style .S file and emits an ARM64 COFF object,
    # while all normal SunPack/7-Zip C and C++ translation units remain MSVC.
    add_custom_command(
        OUTPUT "${SUP7Z_ARM64_LZMA_OBJECT}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${SUP7Z_ARM64_ASM_OUTPUT_DIR}"
        COMMAND "${SUP7Z_CLANG_CL_EXECUTABLE}"
            --target=arm64-pc-windows-msvc
            -nologo
            -c
            "-Fo${SUP7Z_ARM64_LZMA_OBJECT}"
            -Wall
            -WX
            "${SUP7Z_ARM64_LZMA_ASM_SOURCE}"
        DEPENDS
            "${SUP7Z_ARM64_LZMA_ASM_SOURCE}"
            "${SUP7Z_ARM64_LZMA_ASM_INCLUDE}"
        COMMENT "Assembling upstream 7-Zip ARM64 LzmaDecOpt.S with clang-cl"
        VERBATIM)

    add_custom_target(sunpack_7zip_arm64_asm_objects
        DEPENDS "${SUP7Z_ARM64_LZMA_OBJECT}")
    set_source_files_properties("${SUP7Z_ARM64_LZMA_OBJECT}"
        PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
endif()


function(sup7z_attach_bundled_7z target_name)
    if(WIN32 AND TARGET sunpack_7zip_objects)
        target_sources(${target_name} PRIVATE
            $<TARGET_OBJECTS:sunpack_7zip_objects>)
        target_include_directories(${target_name} PRIVATE ${SUP7Z_7Z_ROOT}/CPP)
    endif()
    if(WIN32 AND TARGET sunpack_7zip_asm_objects)
        target_sources(${target_name} PRIVATE
            $<TARGET_OBJECTS:sunpack_7zip_asm_objects>)
    endif()
    if(WIN32 AND SUP7Z_ARM64_ASM_ENABLED)
        target_sources(${target_name} PRIVATE "${SUP7Z_ARM64_LZMA_OBJECT}")
        add_dependencies(${target_name} sunpack_7zip_arm64_asm_objects)
    endif()
endfunction()


set(SUP7Z_INTERNAL_SOURCES
    src/internal/archive_extract.cpp
    src/internal/archive_open_plan.cpp
    src/internal/embedded_7z.cpp
    src/internal/password_testing.cpp
    src/internal/sevenzip_engine.cpp
    src/internal/sevenzip_formats.cpp
    src/internal/sevenzip_guid_defs.cpp
    src/internal/sevenzip_paths.cpp
    src/internal/sevenzip_properties.cpp
    src/internal/sevenzip_sdk.cpp
    src/internal/sevenzip_status.cpp
    src/internal/sevenzip_streams.cpp
    src/internal/sevenzip_volume_registry.cpp
    src/internal/sevenzip_writer_meters.cpp
    src/internal/zlib_ng_deflate_decoder.cpp
)

if(SUP7Z_ENABLE_PIPELINE_TIMING)
    list(APPEND SUP7Z_INTERNAL_SOURCES
        src/worker_pipeline_timing.cpp)
endif()

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
    target_compile_definitions(sunpack_sevenzip_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(sunpack_sevenzip_core PUBLIC OleAut32)
endif()
target_link_libraries(sunpack_sevenzip_core PRIVATE zlib-ng::zlibstatic)
if(SUP7Z_ENABLE_PIPELINE_TIMING)
    target_compile_definitions(sunpack_sevenzip_core PRIVATE SUP7Z_ENABLE_PIPELINE_TIMING=1)
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
    if(SUP7Z_ENABLE_PIPELINE_TIMING)
        target_compile_definitions(sunpack_sevenzip_worker PRIVATE SUP7Z_ENABLE_PIPELINE_TIMING=1)
    endif()

    add_executable(sunpack_launcher src/launcher.cpp)
    apply_release_optimizations(sunpack_launcher)
    apply_source_charset(sunpack_launcher)
    target_compile_definitions(sunpack_launcher PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_link_libraries(sunpack_launcher PRIVATE Shell32)
endif()

# QueryInterface contract for the callback/stream objects handed to 7-Zip.
# Upstream's Z7_COM_UNKNOWN_IMP_N macro emits an entry only for the IIDs it is
# given -- it does not walk the C++ base classes -- so a parent interface such
# as IProgress has to be listed explicitly. This test is what stops a future
# macro edit from silently dropping it.
add_executable(sunpack_sevenzip_com_contract
    tests/com_contract.cpp
)
apply_release_optimizations(sunpack_sevenzip_com_contract)
apply_source_charset(sunpack_sevenzip_com_contract)
target_link_libraries(sunpack_sevenzip_com_contract PRIVATE sunpack_sevenzip_core)
sup7z_attach_bundled_7z(sunpack_sevenzip_com_contract)
target_include_directories(sunpack_sevenzip_com_contract
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
    target_compile_definitions(sunpack_sevenzip_com_contract PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# Contract tests for SunPack's zlib-ng decode paths. This covers the raw
# Deflate adapter (including Strong Encryption unused-input semantics), the
# generic adaptive registry decoder, and the seekable gzip wrapper fast path.
add_executable(sunpack_zlib_ng_deflate_contract
    tests/zlib_ng_deflate_decoder.cpp
)
apply_release_optimizations(sunpack_zlib_ng_deflate_contract)
apply_source_charset(sunpack_zlib_ng_deflate_contract)
target_link_libraries(sunpack_zlib_ng_deflate_contract
    PRIVATE sunpack_sevenzip_core)
sup7z_attach_bundled_7z(sunpack_zlib_ng_deflate_contract)
target_include_directories(sunpack_zlib_ng_deflate_contract
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
    target_compile_definitions(sunpack_zlib_ng_deflate_contract PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

enable_testing()
add_test(NAME sunpack_sevenzip_smoke COMMAND sunpack_sevenzip_smoke)
add_test(NAME sunpack_sevenzip_async_output COMMAND sunpack_sevenzip_async_output)
add_test(NAME sunpack_sevenzip_space_gate COMMAND sunpack_sevenzip_space_gate)
add_test(NAME sunpack_sevenzip_space_retry COMMAND sunpack_sevenzip_space_retry)
add_test(NAME sunpack_sevenzip_com_contract COMMAND sunpack_sevenzip_com_contract)
add_test(NAME sunpack_zlib_ng_deflate_contract COMMAND sunpack_zlib_ng_deflate_contract)
