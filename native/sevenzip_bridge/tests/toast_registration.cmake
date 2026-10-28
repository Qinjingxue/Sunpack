# Exercise the installer layout, including spaces in executable paths.
set(fixture "${WORK_DIR}/toast registration fixture")
file(MAKE_DIRECTORY "${fixture}/bin")
configure_file("${LAUNCHER}" "${fixture}/bin/sunpack.exe" COPYONLY)
configure_file("${RUNTIME}" "${fixture}/sunpack-runtime.exe" COPYONLY)
execute_process(
    COMMAND "${fixture}/bin/sunpack.exe" --register-toast
    WORKING_DIRECTORY "${WORK_DIR}"
    RESULT_VARIABLE result)
if(NOT result STREQUAL "37")
    message(FATAL_ERROR "Toast registration did not preserve runtime identity/exit status: ${result}")
endif()
