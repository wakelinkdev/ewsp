# EWSP Core JNI Binding - CMake Build
# ====================================
# 
# Builds native library for Kotlin/Android.
# 
# Desktop build:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
# 
# Android NDK build:
#   cmake -B build-android \
#     -DANDROID_ABI=arm64-v8a \
#     -DANDROID_PLATFORM=android-21 \
#     -DCMAKE_TOOLCHAIN_FILE=$NDK_HOME/build/cmake/android.toolchain.cmake
#   cmake --build build-android

cmake_minimum_required(VERSION 3.14)
project(ewsp_core_jni VERSION 1.0.0 LANGUAGES C)

# === Options ===
option(BUILD_SHARED_LIBS "Build shared library" ON)

# === Sources ===
set(JNI_SOURCES
    ewsp_core_jni.c
)

# === ewsp-core library ===
# Add parent ewsp-core as dependency
get_filename_component(EWSP_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

# Include ewsp-core headers
include_directories(${EWSP_CORE_DIR}/include)

# Link to ewsp-core library
# First try to find it in build directory
find_library(EWSP_CORE_LIB
    NAMES ewsp_core libewsp_core
    PATHS 
        ${EWSP_CORE_DIR}/build
        ${EWSP_CORE_DIR}/build/Release
        ${EWSP_CORE_DIR}/build/Debug
        ${EWSP_CORE_DIR}/build/lib
    NO_DEFAULT_PATH
)

if(NOT EWSP_CORE_LIB)
    # Build ewsp-core from source
    message(STATUS "ewsp-core library not found, building from source...")
    add_subdirectory(${EWSP_CORE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/ewsp-core EXCLUDE_FROM_ALL)
    set(EWSP_CORE_LIB ewsp_core)
endif()

# === JNI ===
find_package(JNI)

if(JNI_FOUND)
    message(STATUS "JNI found: ${JNI_INCLUDE_DIRS}")
    include_directories(${JNI_INCLUDE_DIRS})
elseif(ANDROID)
    message(STATUS "Building for Android (JNI headers provided by NDK)")
else()
    message(WARNING "JNI not found and not building for Android")
endif()

# === Library ===
add_library(ewsp_core_jni ${JNI_SOURCES})

target_link_libraries(ewsp_core_jni PRIVATE ${EWSP_CORE_LIB})

# Platform-specific settings
if(ANDROID)
    # Android: link against log library
    find_library(LOG_LIB log)
    target_link_libraries(ewsp_core_jni PRIVATE ${LOG_LIB})
    
    # Set Android library name
    set_target_properties(ewsp_core_jni PROPERTIES
        OUTPUT_NAME "ewsp_core"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/libs/${ANDROID_ABI}"
    )
elseif(WIN32)
    set_target_properties(ewsp_core_jni PROPERTIES
        OUTPUT_NAME "ewsp_core"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )
else()
    set_target_properties(ewsp_core_jni PROPERTIES
        OUTPUT_NAME "ewsp_core"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )
endif()

# === Installation ===
if(ANDROID)
    # Install to gradle's jniLibs directory structure
    install(TARGETS ewsp_core_jni
        LIBRARY DESTINATION "jniLibs/${ANDROID_ABI}"
        ARCHIVE DESTINATION "jniLibs/${ANDROID_ABI}"
    )
else()
    install(TARGETS ewsp_core_jni
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()
