# Inspect the emitted PE instead of relying on the build machine's installed
# runtimes. link.exe /dump works for both x64 and ARM64 without running the PE.
if(NOT DEFINED LINKER OR NOT DEFINED BINARY)
    message(FATAL_ERROR "LINKER and BINARY are required")
endif()
execute_process(
    COMMAND "${LINKER}" /dump /dependents "${BINARY}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE dependencies
    ERROR_VARIABLE errors)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect ${BINARY}: ${result}\n${errors}")
endif()
string(TOLOWER "${dependencies}" dependencies)
if(dependencies MATCHES "(msvcp[0-9][a-z0-9_]*|vcruntime[0-9][a-z0-9_]*|concrt[0-9][a-z0-9_]*|vcomp[0-9][a-z0-9_]*|ucrtbase[d]?)\\.dll")
    message(FATAL_ERROR "${BINARY} requires a dynamic CRT: ${CMAKE_MATCH_0}")
endif()
message(STATUS "Standalone CRT dependency check passed: ${BINARY}")
