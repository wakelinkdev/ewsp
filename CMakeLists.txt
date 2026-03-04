# ============================================================================
# EWSP Core Library - CMake Build Configuration
# ============================================================================
#
# Build options:
#   -DEWSP_BUILD_TESTS=ON      Build tests
#   -DEWSP_BUILD_SHARED=ON     Build shared library
#   -DEWSP_BUILD_STATIC=ON     Build static library (default)
#   -DCMAKE_BUILD_TYPE=Debug   Debug build
#
# Usage:
#   mkdir build && cd build
#   cmake .. -DEWSP_BUILD_TESTS=ON
#   cmake --build .
#   ctest
#
# ============================================================================

cmake_minimum_required(VERSION 3.14)

project(ewsp_core
    VERSION 1.0.0
    DESCRIPTION "EWSP Core Library - Unified WakeLink Protocol Implementation"
    LANGUAGES C
)

# ============================================================================
# Options
# ============================================================================

option(EWSP_BUILD_TESTS "Build tests" OFF)
option(EWSP_BUILD_SHARED "Build shared library" ON)
option(EWSP_BUILD_STATIC "Build static library" ON)
option(EWSP_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# ============================================================================
# Compiler Settings
# ============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Position independent code for shared library
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4)
    if(EWSP_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(EWSP_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
endif()

# ============================================================================
# Source Files
# ============================================================================

set(EWSP_SOURCES
    src/ewsp.c
    src/ewsp_crypto.c
    src/ewsp_errors.c
    src/ewsp_chain.c
    src/ewsp_json.c
    src/ewsp_models.c
    src/ewsp_packet.c
    src/ewsp_commands.c
    src/ewsp_session.c
)

set(EWSP_HEADERS
    include/ewsp.h
    include/ewsp_types.h
    include/ewsp_errors.h
    include/ewsp_crypto.h
    include/ewsp_models.h
    include/ewsp_chain.h
    include/ewsp_json.h
    include/ewsp_packet.h
    include/ewsp_commands.h
    include/ewsp_session.h
)

# ============================================================================
# Libraries
# ============================================================================

# Static library
if(EWSP_BUILD_STATIC)
    add_library(ewsp_core_static STATIC ${EWSP_SOURCES})
    target_include_directories(ewsp_core_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )
    set_target_properties(ewsp_core_static PROPERTIES
        OUTPUT_NAME ewsp_core
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
endif()

# Shared library
if(EWSP_BUILD_SHARED)
    add_library(ewsp_core_shared SHARED ${EWSP_SOURCES})
    target_include_directories(ewsp_core_shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )
    set_target_properties(ewsp_core_shared PROPERTIES
        OUTPUT_NAME ewsp_core
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    
    # Windows DLL export
    if(WIN32)
        target_compile_definitions(ewsp_core_shared PRIVATE EWSP_BUILD_DLL)
    endif()
endif()

# Alias for easy use
if(EWSP_BUILD_SHARED)
    add_library(ewsp::core ALIAS ewsp_core_shared)
elseif(EWSP_BUILD_STATIC)
    add_library(ewsp::core ALIAS ewsp_core_static)
endif()

# ============================================================================
# Platform-specific
# ============================================================================

if(WIN32)
    # Windows: Use CryptGenRandom
    if(EWSP_BUILD_SHARED)
        target_link_libraries(ewsp_core_shared PRIVATE advapi32)
    endif()
    if(EWSP_BUILD_STATIC)
        target_link_libraries(ewsp_core_static PRIVATE advapi32)
    endif()
elseif(APPLE)
    # macOS: Use SecRandomCopyBytes
    if(EWSP_BUILD_SHARED)
        target_link_libraries(ewsp_core_shared PRIVATE "-framework Security")
    endif()
    if(EWSP_BUILD_STATIC)
        target_link_libraries(ewsp_core_static PRIVATE "-framework Security")
    endif()
endif()

# ============================================================================
# Tests
# ============================================================================

if(EWSP_BUILD_TESTS)
    enable_testing()
    
    # Test executable
    add_executable(ewsp_tests
        tests/test_main.c
        tests/test_crypto.c
        tests/test_packet.c
        tests/test_json.c
        tests/test_chain.c
        tests/test_session.c
        tests/test_commands.c
        tests/test_errors.c
        tests/test_models.c
    )
    
    if(EWSP_BUILD_STATIC)
        target_link_libraries(ewsp_tests PRIVATE ewsp_core_static)
    else()
        target_link_libraries(ewsp_tests PRIVATE ewsp_core_shared)
    endif()
    
    target_include_directories(ewsp_tests PRIVATE include)
    
    # Register tests
    add_test(NAME ewsp_crypto_tests COMMAND ewsp_tests crypto)
    add_test(NAME ewsp_packet_tests COMMAND ewsp_tests packet)
    add_test(NAME ewsp_json_tests COMMAND ewsp_tests json)
    add_test(NAME ewsp_chain_tests COMMAND ewsp_tests chain)
    add_test(NAME ewsp_session_tests COMMAND ewsp_tests session)
    add_test(NAME ewsp_commands_tests COMMAND ewsp_tests commands)
    add_test(NAME ewsp_errors_tests COMMAND ewsp_tests errors)
    add_test(NAME ewsp_models_tests COMMAND ewsp_tests models)
    add_test(NAME ewsp_all_tests COMMAND ewsp_tests)
endif()

# ============================================================================
# Installation
# ============================================================================

include(GNUInstallDirs)

# Install libraries
if(EWSP_BUILD_STATIC)
    install(TARGETS ewsp_core_static
        EXPORT ewsp_core-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(EWSP_BUILD_SHARED)
    install(TARGETS ewsp_core_shared
        EXPORT ewsp_core-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# Install headers
install(FILES ${EWSP_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ewsp
)

# Install CMake config
install(EXPORT ewsp_core-targets
    FILE ewsp_core-config.cmake
    NAMESPACE ewsp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ewsp_core
)

# ============================================================================
# Package Config
# ============================================================================

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ewsp_core-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ewsp_core-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ewsp_core
)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "EWSP Core Library v${PROJECT_VERSION}")
message(STATUS "  Build static library: ${EWSP_BUILD_STATIC}")
message(STATUS "  Build shared library: ${EWSP_BUILD_SHARED}")
message(STATUS "  Build tests: ${EWSP_BUILD_TESTS}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
