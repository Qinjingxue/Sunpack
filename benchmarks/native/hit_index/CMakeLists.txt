cmake_minimum_required(VERSION 3.20)
project(sunpack_hit_index_benchmark LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
if(NOT DEFINED BASELINE_ROOT)
  message(FATAL_ERROR "BASELINE_ROOT must point at the pinned source cache")
endif()
set(FP "${BASELINE_ROOT}/fastpfor")
add_library(fastpfor_core STATIC
  "${FP}/src/bitpacking.cpp" "${FP}/src/bitpackingaligned.cpp"
  "${FP}/src/bitpackingunaligned.cpp" "${FP}/src/horizontalbitpacking.cpp"
  "${FP}/src/simdunalignedbitpacking.cpp" "${FP}/src/simdbitpacking.cpp")
target_include_directories(fastpfor_core PUBLIC "${FP}/headers")
target_compile_options(fastpfor_core PRIVATE /O2 /clang:-msse4.2)
set(ENABLE_ROARING_TESTS OFF CACHE BOOL "" FORCE)
set(ENABLE_ROARING_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(ENABLE_ROARING_MICROBENCHMARKS OFF CACHE BOOL "" FORCE)
set(ROARING_USE_CPM OFF CACHE BOOL "" FORCE)
set(ROARING_BUILD_STATIC ON CACHE BOOL "" FORCE)
add_subdirectory("${BASELINE_ROOT}/croaring" roaring EXCLUDE_FROM_ALL)
add_library(svb_core STATIC
  "${BASELINE_ROOT}/streamvbyte/src/streamvbyte_encode.c"
  "${BASELINE_ROOT}/streamvbyte/src/streamvbyte_decode.c"
  "${BASELINE_ROOT}/streamvbyte/src/streamvbytedelta_encode.c"
  "${BASELINE_ROOT}/streamvbyte/src/streamvbytedelta_decode.c"
  "${BASELINE_ROOT}/streamvbyte/src/streamvbyte_0124_encode.c"
  "${BASELINE_ROOT}/streamvbyte/src/streamvbyte_0124_decode.c")
target_include_directories(svb_core PUBLIC "${BASELINE_ROOT}/streamvbyte/include")
target_compile_options(svb_core PRIVATE /O2)
foreach(bench_target hit_index_benchmark hit_index_validate)
add_executable(${bench_target} main.cpp backends.cpp pef_backend.cpp faw_backend.cpp)
target_include_directories(${bench_target} PRIVATE
  "${BASELINE_ROOT}" "${BASELINE_ROOT}/pef" "${BASELINE_ROOT}/faw"
  "${CMAKE_CURRENT_SOURCE_DIR}/compat" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_options(${bench_target} PRIVATE /O2 /clang:-msse4.2 /EHsc)
target_link_libraries(${bench_target} PRIVATE fastpfor_core svb_core roaring psapi)
endforeach()
target_compile_definitions(hit_index_validate PRIVATE SP_BENCH_AUDIT=1)
