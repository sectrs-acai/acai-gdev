CMAKE_MINIMUM_REQUIRED(VERSION 3.20)

SET(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
SET(CMAKE_C_FLAGS_DEBUG "-g")
SET(CMAKE_BUILD_TYPE Release)

set(BUILD_SHARED_LIBS off)

PROJECT(Gdev)
SET(serial "1.0.0")
SET(soserial "1")

## Option
OPTION(driver "select GPU driver. must set driver name in the user-space mode" nouveau)
OPTION(user "user mode(default off)" OFF)
OPTION(runtime "enable CUDA runtime API(default on)" ON)
OPTION(usched "enable user mode scheduler(default off)" OFF)
OPTION(use_as "use assembler(default off)" OFF)
OPTION(use_llvm "use LLVM compiler(default off)" OFF)
OPTION(use_open64 "use Open64(nvopencc) compiler(default off)" OFF)
OPTION(build_cuda_only "build only cuda runtime without gdev" OFF)
OPTION(install_name "name to distinguish between cuda-rt and cuda" gdev)

MACRO(INCLUDE_DIRECTORY_IF_EXISTS DIR)
    IF(EXISTS "${DIR}/")
        INCLUDE_DIRECTORIES(${DIR})
    ENDIF()
ENDMACRO()

MACRO(LINK_DIRECTORY_IF_EXISTS DIR)
    if(EXISTS "${DIR}/")
        LINK_DIRECTORIES(${DIR})
    endif()
ENDMACRO()

## Generate gdev_autogen.h
STRING(TOUPPER "${driver}" DRIVER_NAME)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/common/gdev_autogen.h.in ${CMAKE_CURRENT_BINARY_DIR}/common/gdev_autogen.h)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/util)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/common)

message($ENV{STAGING_DIR} @bean staging dir 2)
IF(user)
    IF(CMAKE_CROSSCOMPILING)
        message(STATUS "is cross compiling")
    ELSE()
        message(STATUS "is not cross compiling")

    ENDIF()
    INCLUDE_DIRECTORY_IF_EXISTS($ENV{STAGING_DIR}/usr/local/include/libdrm)
    INCLUDE_DIRECTORY_IF_EXISTS($ENV{STAGING_DIR}/usr/local/include/libdrm/nouveau)
    LINK_DIRECTORY_IF_EXISTS($ENV{STAGING_DIR}/usr/local/lib)
    LINK_DIRECTORY_IF_EXISTS($ENV{STAGING_DIR}/usr/local/lib64)
    LINK_DIRECTORY_IF_EXISTS($ENV{STAGING_DIR}/usr/lib)
ENDIF()

INCLUDE_DIRECTORIES(util)
INCLUDE_DIRECTORIES(common)

FIND_PACKAGE(Doxygen)
include(UseDoxygen OPTIONAL)

IF(build_cuda_only)
    message ("building cuda only")
    ADD_SUBDIRECTORY(cuda)
ELSE()
    ADD_SUBDIRECTORY(cuda)
    ADD_SUBDIRECTORY(lib)

    IF(NOT user)
        #ADD_SUBDIRECTORY(mod)
    ENDIF(NOT user)

    IF(use_as)
        ADD_SUBDIRECTORY(compiler/as)
    ENDIF(use_as)

    IF(use_llvm)
        ADD_SUBDIRECTORY(compiler/llvm)
    ENDIF(use_llvm)

    IF(use_open64)
        ADD_SUBDIRECTORY(compiler/open64)
    ENDIF(use_open64)

ENDIF(build_cuda_only)

