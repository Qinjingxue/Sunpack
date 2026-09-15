cmake_minimum_required(VERSION 3.20)

project(sunpack_toast LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "sunpack_toast is Windows-only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

add_library(sunpack_toast SHARED src/main.cpp)
target_compile_definitions(sunpack_toast PRIVATE
    SUNPACK_TOAST_EXPORTS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
if(MSVC)
    set_property(TARGET sunpack_toast PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    target_compile_options(sunpack_toast PRIVATE
        /utf-8 /permissive- /W4
        $<$<CONFIG:Release>:/O2 /Oi /Ot /GL /Gy /Gw /GF>
    )
    target_link_options(sunpack_toast PRIVATE
        $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
    )
endif()
target_link_libraries(sunpack_toast PRIVATE
    windowsapp
    runtimeobject
    ole32
    shell32
    advapi32
)

enable_testing()
add_executable(sunpack_toast_self_test src/self_test.cpp)
target_link_libraries(sunpack_toast_self_test PRIVATE sunpack_toast)
add_test(NAME sunpack_toast_self_test COMMAND sunpack_toast_self_test)
