cmake_minimum_required(VERSION 3.5)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(xquic_masque_fuzz C)
endif()

option(XQC_FUZZ_ENABLE_LIBFUZZER "Build libFuzzer target for MASQUE helpers" ON)

if(NOT XQC_FUZZ_ENABLE_LIBFUZZER)
    message(STATUS "XQC_FUZZ_ENABLE_LIBFUZZER=OFF, skip fuzz targets")
    return()
endif()

if(NOT (CMAKE_C_COMPILER_ID MATCHES "Clang"))
    message(WARNING "libFuzzer target expects clang/AppleClang (-fsanitize=fuzzer)")
endif()

set(XQC_FUZZ_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")
set(xquic_VERSION_MAJOR 0)
set(xquic_VERSION_MINOR 1)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/xquic")
configure_file(
    "${XQC_FUZZ_ROOT_DIR}/xqc_configure.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/xquic/xqc_configure.h"
    @ONLY
)

set(XQC_FUZZ_MASQUE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_masque_libfuzzer.c"
    "${XQC_FUZZ_ROOT_DIR}/src/http3/xqc_h3_ext_masque.c"
    "${XQC_FUZZ_ROOT_DIR}/src/common/utils/vint/xqc_variable_len_int.c"
)

add_executable(fuzz_masque_libfuzzer ${XQC_FUZZ_MASQUE_SOURCES})

target_include_directories(fuzz_masque_libfuzzer PRIVATE
    "${XQC_FUZZ_ROOT_DIR}"
    "${XQC_FUZZ_ROOT_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/include"
)

target_compile_definitions(fuzz_masque_libfuzzer PRIVATE
    FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
)

target_compile_options(fuzz_masque_libfuzzer PRIVATE
    -O1
    -g
    -fno-omit-frame-pointer
    -fsanitize=fuzzer,address,undefined
)

if(COMMAND target_link_options)
    target_link_options(fuzz_masque_libfuzzer PRIVATE
        -fsanitize=fuzzer,address,undefined
    )
else()
    set_property(TARGET fuzz_masque_libfuzzer APPEND_STRING PROPERTY
        LINK_FLAGS " -fsanitize=fuzzer,address,undefined")
endif()

