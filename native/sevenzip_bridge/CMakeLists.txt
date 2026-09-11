cmake_minimum_required(VERSION 3.20)

project(sunpack_sevenzip LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
    src/internal/strict_archive_validation.cpp
)

add_library(sunpack_sevenzip_core STATIC
    ${SUP7Z_INTERNAL_SOURCES}
)
apply_release_optimizations(sunpack_sevenzip_core)

target_include_directories(sunpack_sevenzip_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

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

target_include_directories(sunpack_sevenzip
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX SUP7Z_BUILD_DLL)
    target_link_libraries(sunpack_sevenzip PRIVATE OleAut32 Ole32)
endif()

add_executable(sunpack_sevenzip_smoke
    tests/smoke.cpp
)
apply_release_optimizations(sunpack_sevenzip_smoke)

target_link_libraries(sunpack_sevenzip_smoke
    PRIVATE sunpack_sevenzip_core
)

target_include_directories(sunpack_sevenzip_smoke
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(sunpack_sevenzip_async_output
    tests/async_output.cpp
)
apply_release_optimizations(sunpack_sevenzip_async_output)

target_link_libraries(sunpack_sevenzip_async_output
    PRIVATE sunpack_sevenzip_core
)

target_include_directories(sunpack_sevenzip_async_output
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(sunpack_sevenzip_worker
    src/worker.cpp
)
apply_release_optimizations(sunpack_sevenzip_worker)

target_link_libraries(sunpack_sevenzip_worker
    PRIVATE sunpack_sevenzip_core
)

if(WIN32)
    target_compile_definitions(sunpack_sevenzip_worker PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

    add_executable(sunpack_launcher src/launcher.cpp)
    apply_release_optimizations(sunpack_launcher)
    target_compile_definitions(sunpack_launcher PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    if(MSVC)
        # launcher.cpp contains UTF-8 string literals (localized messages).
        target_compile_options(sunpack_launcher PRIVATE /utf-8)
    endif()
    target_link_libraries(sunpack_launcher PRIVATE Shell32)
endif()

enable_testing()
add_test(NAME sunpack_sevenzip_smoke COMMAND sunpack_sevenzip_smoke)
add_test(NAME sunpack_sevenzip_async_output COMMAND sunpack_sevenzip_async_output)
