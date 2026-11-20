cmake_minimum_required(VERSION 3.25)
project(SunPackGUI LANGUAGES C CXX)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "SunPackGUI requires Windows and MSVC/clang-cl")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_options(/utf-8 /Gy /Gw)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
option(SUNPACK_GUI_ASAN "Enable native memory diagnostics" OFF)
if(SUNPACK_GUI_ASAN)
  add_compile_options(/fsanitize=address /Zi)
  add_link_options(/DEBUG /INCREMENTAL:NO)
endif()
include(FetchContent)
set(UI_CORE_STATIC ON CACHE BOOL "" FORCE)
set(UI_CORE_MSVC_STATIC_CRT ON CACHE BOOL "" FORCE)
set(UI_CORE_BUILD_INTERNAL_TESTS OFF CACHE BOOL "" FORCE)
set(core_ui_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/core-ui")
add_subdirectory("${core_ui_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/_deps/core_ui-build" EXCLUDE_FROM_ALL)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(json URL https://codeload.github.com/nlohmann/json/tar.gz/65ee68451d8eb2b5f3a30b410476ab83deb3289b
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(json)
add_library(sunpack_gui_data STATIC src/platform.cpp src/context_menu.cpp src/model.cpp src/presentation.cpp src/range_editor.cpp src/display_history.cpp
  ../sunpack/third_party/lz4/xxhash.c ../sunpack/third_party/lz4/lz4.c)
target_include_directories(sunpack_gui_data PUBLIC src ../sunpack/third_party/lz4)
# Enable MSVC /GL for the GUI data library in Release builds only.
set_property(TARGET sunpack_gui_data PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
target_link_libraries(sunpack_gui_data PUBLIC nlohmann_json::nlohmann_json
  shell32 ole32 advapi32 ntdll)
ui_core_embed_text(sunpack_gui_data FILE resources/catalog.json OUT catalog_json.h VAR kCatalogJson)
# Compile the application implementation only once for the shipping executable,
# UI integration tests and optional performance benchmark. It owns main_uix.h,
# so the parallel consumers never race to regenerate the same header.
add_library(sunpack_gui_app OBJECT src/application.cpp src/motion.cpp src/date_popup.cpp src/tag_collection.cpp src/find_controller.cpp)
target_include_directories(sunpack_gui_app PRIVATE "${core_ui_SOURCE_DIR}/src")
target_link_libraries(sunpack_gui_app PRIVATE sunpack_gui_data core-ui shlwapi)
set_property(TARGET sunpack_gui_app PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
ui_core_embed_text(sunpack_gui_app FILE resources/main.uix OUT main_uix.h VAR kMainUix)
ui_core_embed_text(sunpack_gui_app FILE resources/date_popup.uix OUT date_popup_uix.h VAR kDatePopupUix)

add_executable(SunPackGUI WIN32 src/main.cpp resources/app.rc)
target_include_directories(SunPackGUI PRIVATE "${core_ui_SOURCE_DIR}/src")
# Keep Release /GL + /LTCG enabled on shipped application code.
set_property(TARGET SunPackGUI PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
target_link_libraries(SunPackGUI PRIVATE sunpack_gui_app sunpack_gui_data core-ui comctl32)
target_link_options(SunPackGUI PRIVATE /OPT:REF /OPT:ICF
  "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/../sunpack.manifest")
enable_testing()
add_executable(sunpack_gui_tests tests/manager.cpp)
target_link_libraries(sunpack_gui_tests PRIVATE sunpack_gui_data)
target_compile_options(sunpack_gui_tests PRIVATE /UNDEBUG)
# sunpack_gui_data contains /GL objects: request LTCG up front rather than
# letting LINK restart automatically after encountering the static library.
target_link_options(sunpack_gui_tests PRIVATE "$<$<CONFIG:Release>:/LTCG>")
add_test(NAME gui_file_contracts COMMAND sunpack_gui_tests)
add_executable(sunpack_gui_ui_tests tests/interface.cpp tests/rendering.cpp tests/theme.cpp
  tests/startup_failure.cpp resources/app.rc)
target_include_directories(sunpack_gui_ui_tests PRIVATE "${core_ui_SOURCE_DIR}/src")
ui_core_embed_text(sunpack_gui_ui_tests FILE ../sunpack_advanced_config.json OUT ui_defaults_json.h VAR kUiDefaultsJson)
target_link_libraries(sunpack_gui_ui_tests PRIVATE sunpack_gui_app sunpack_gui_data core-ui comctl32)
target_compile_options(sunpack_gui_ui_tests PRIVATE /UNDEBUG)
target_link_options(sunpack_gui_ui_tests PRIVATE "$<$<CONFIG:Release>:/LTCG>")
add_test(NAME gui_interface COMMAND sunpack_gui_ui_tests --acceptance)
add_test(NAME gui_history_window COMMAND sunpack_gui_ui_tests --history)
add_test(NAME gui_theme_preferences COMMAND sunpack_gui_ui_tests --theme)
add_test(NAME gui_startup_failure COMMAND sunpack_gui_ui_tests --startup-failure)
add_test(NAME gui_script_errors COMMAND sunpack_gui_ui_tests --script-errors)
if(SUNPACK_GUI_ASAN)
  target_sources(sunpack_gui_tests PRIVATE tests/asan_options.cpp)
  target_sources(sunpack_gui_ui_tests PRIVATE tests/asan_options.cpp)
endif()
set_tests_properties(gui_file_contracts gui_interface gui_history_window gui_theme_preferences gui_startup_failure gui_script_errors PROPERTIES TIMEOUT 60)

# One MSBuild invocation can schedule all independent targets in parallel.
add_custom_target(sunpack_gui_checks DEPENDS SunPackGUI sunpack_gui_tests sunpack_gui_ui_tests)
add_executable(sunpack_gui_performance EXCLUDE_FROM_ALL ../benchmarks/gui/performance.cpp resources/app.rc)
target_include_directories(sunpack_gui_performance PRIVATE "${core_ui_SOURCE_DIR}/src")
ui_core_embed_text(sunpack_gui_performance FILE ../sunpack_advanced_config.json OUT gui_perf_defaults.h VAR kGuiPerfDefaultsJson)
target_link_libraries(sunpack_gui_performance PRIVATE sunpack_gui_app sunpack_gui_data core-ui comctl32 psapi)
target_link_options(sunpack_gui_performance PRIVATE "$<$<CONFIG:Release>:/LTCG>")
# Only the manager is shipped; no debug server or demo is started by this host.
install(TARGETS SunPackGUI RUNTIME DESTINATION .)
FetchContent_GetProperties(quickjs)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/licenses")
configure_file("${core_ui_SOURCE_DIR}/LICENSE" licenses/core-ui.txt COPYONLY)
configure_file("${json_SOURCE_DIR}/LICENSE.MIT" licenses/nlohmann-json.txt COPYONLY)
configure_file("${quickjs_SOURCE_DIR}/LICENSE" licenses/quickjs.txt COPYONLY)
configure_file("${core_ui_SOURCE_DIR}/third_party/lunasvg/LICENSE" licenses/lunasvg.txt COPYONLY)
configure_file("${core_ui_SOURCE_DIR}/third_party/lunasvg/plutovg/LICENSE" licenses/plutovg.txt COPYONLY)
configure_file("${core_ui_SOURCE_DIR}/third_party/lunasvg/plutovg/source/FTL.TXT" licenses/freetype.txt COPYONLY)
# PlutoVG embeds stb and FreeType code under their own licenses.
# Keep the full dual-license grant, not the implementation or a license summary.
set(plutovg_source_dir "${core_ui_SOURCE_DIR}/third_party/lunasvg/plutovg/source")
set(stb_license "")
foreach(stb_component image image-write truetype)
  set(stb_header "${plutovg_source_dir}/plutovg-stb-${stb_component}.h")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${stb_header}")
  file(READ "${stb_header}" stb_source)
  string(FIND "${stb_source}" "This software is available under 2 licenses" stb_license_start)
  if(stb_license_start EQUAL -1)
    message(FATAL_ERROR "Missing embedded stb license: ${stb_header}")
  endif()
  string(SUBSTRING "${stb_source}" ${stb_license_start} -1 stb_component_license)
  if(NOT stb_component_license MATCHES "\\*/[ \t\r\n]*$")
    message(FATAL_ERROR "Unexpected embedded stb license ending: ${stb_header}")
  endif()
  string(REGEX REPLACE "\\*/[ \t\r\n]*$" "" stb_component_license "${stb_component_license}")
  if(NOT stb_license STREQUAL "" AND NOT stb_license STREQUAL stb_component_license)
    message(FATAL_ERROR "Embedded stb licenses differ; stage each license separately")
  endif()
  set(stb_license "${stb_component_license}")
endforeach()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/licenses/stb.txt"
  "stb_image, stb_image_write and stb_truetype, embedded by PlutoVG.\n"
  "Source: https://github.com/nothings/stb\n\n${stb_license}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/licenses/freetype-attribution.txt"
  "PlutoVG incorporates FreeType math, raster and stroker code.\n"
  "Portions of this software are copyright (c) 1996-2014 The FreeType Project\n"
  "(https://www.freetype.org). All rights reserved.\n"
  "Authors: David Turner, Robert Wilhelm, and Werner Lemberg.\n"
  "The accompanying FreeType Project License applies to these portions.\n")
