# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

cmake_minimum_required(VERSION 3.1)
project(aws-nitro-enclaves-sdk-c C)

if (POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler, see AwsCFlags
endif()

if (DEFINED CMAKE_PREFIX_PATH)
    file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
endif()

if (DEFINED CMAKE_INSTALL_PREFIX)
    file(TO_CMAKE_PATH "${CMAKE_INSTALL_PREFIX}" CMAKE_INSTALL_PREFIX)
endif()


if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

# This is required in order to append /lib/cmake to each element in CMAKE_PREFIX_PATH
set(AWS_MODULE_DIR "/${CMAKE_INSTALL_LIBDIR}/cmake")
string(REPLACE ";" "${AWS_MODULE_DIR};" AWS_MODULE_PATH "${CMAKE_PREFIX_PATH}${AWS_MODULE_DIR}")
# Append that generated list to the module search path
list(APPEND CMAKE_MODULE_PATH ${AWS_MODULE_PATH})

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(AwsFindPackage)
include(CTest)

option(BUILD_RELOCATABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)

file(GLOB AWS_NITRO_ENCLAVES_HEADERS
        "include/aws/nitro_enclaves/*.h"
        )

file(GLOB AWS_NITRO_ENCLAVES_TESTING_HEADERS
        "include/aws/testing/*.h"
        )

file(GLOB AWS_NITRO_ENCLAVES_SRC
        "source/*.c"
        )

execute_process(COMMAND git describe
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	OUTPUT_STRIP_TRAILING_WHITESPACE
	OUTPUT_VARIABLE VERSION)
if ("${VERSION}" STREQUAL "")
        set(VERSION "v0.2.1-unknown")
endif()
message(STATUS "Version=" ${VERSION})
add_definitions(-DVERSION="${VERSION}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
find_package(LibJsonC REQUIRED)
if (NOT WIN32)
    find_library(LibNSM NAMES nsm REQUIRED)
    set(PLATFORM_LIBS LibJsonC::Json "${LibNSM}")
else()
    set(PLATFORM_LIBS LibJsonC::Json)
    include_directories(AFTER "${CMAKE_CURRENT_SOURCE_DIR}/include/aws/vsock")
endif()

aws_use_package(aws-c-common)
aws_use_package(aws-c-io)
aws_use_package(aws-c-http)
aws_use_package(aws-c-auth)

add_subdirectory(bin/kmstool-instance)

if (NOT WIN32)
    add_library(${PROJECT_NAME} ${LIBTYPE} ${AWS_NITRO_ENCLAVES_HEADERS} ${AWS_NITRO_ENCLAVES_SRC})
    aws_set_common_properties(${PROJECT_NAME})
    aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_NITRO_ENCLAVES")
    aws_check_headers(${PROJECT_NAME} ${AWS_NITRO_ENCLAVES_HEADERS})

    aws_add_sanitizers(${PROJECT_NAME})

    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION "${VERSION}")
    set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 0unstable)

    target_compile_definitions(${PROJECT_NAME} PUBLIC)
    target_compile_options(${PROJECT_NAME} PRIVATE "-Wall" "-Werror" "-Wpedantic")

    if (BUILD_RELOCATABLE_BINARIES)
        target_compile_definitions(${PROJECT_NAME} PRIVATE "-DCOMPAT_MODE")
    endif()

    target_include_directories(${PROJECT_NAME} PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>)
    
    target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS} ${PLATFORM_LIBS})
    aws_prepare_shared_lib_exports(${PROJECT_NAME})

    install(FILES ${AWS_NITRO_ENCLAVES_HEADERS} DESTINATION "include/aws/nitro_enclaves" COMPONENT Development)
    install(FILES ${AWS_NITRO_ENCLAVES_TESTING_HEADERS} DESTINATION "include/aws/testing" COMPONENT Development)
    if (BUILD_SHARED_LIBS)
       set (TARGET_DIR "shared")
    else()
       set (TARGET_DIR "static")
    endif()

    install(EXPORT "${PROJECT_NAME}-targets"
            DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/${TARGET_DIR}"
            NAMESPACE AWS::
            COMPONENT Development)

    configure_file("cmake/${PROJECT_NAME}-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
            @ONLY)

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
            DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/"
            COMPONENT Development)

    if (NOT CMAKE_CROSSCOMPILING)
        if (BUILD_TESTING)
            add_subdirectory(tests/kmstool-enclaves)
        endif()
    endif()
        
    if (NOT CMAKE_CROSSCOMPILING)
        add_subdirectory(bin/kmstool-enclave)
        add_subdirectory(bin/kmstool-enclave-cli)
    endif()
    
    find_package(Doxygen OPTIONAL_COMPONENTS dot mscgen dia)

    if (DOXYGEN_FOUND) 
        set(DOXYGEN_GENERATE_HTML YES)
        set(DOXYGEN_GENERATE_MAN YES)
        set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
        doxygen_add_docs(docs ALL ${AWS_NITRO_ENCLAVES_HEADERS})
    endif()
endif()
