# MSBuild --parallel schedules projects; these settings also schedule files in
# the large bundled 7-Zip target, with one compiler budget across all projects.
set(SUNPACK_BUILD_JOBS 4 CACHE STRING "Maximum concurrent native compilation processes")
if(MSVC AND CMAKE_GENERATOR MATCHES "Visual Studio")
    list(APPEND CMAKE_VS_GLOBALS
        "UseMultiToolTask=true"
        "EnforceProcessCountAcrossBuilds=true"
        "CL_MPCount=${SUNPACK_BUILD_JOBS}")
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/MP${SUNPACK_BUILD_JOBS}>)
endif()
