cmake_minimum_required(VERSION 3.0.0)

project(aes VERSION 0.1 LANGUAGES CXX)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC  ${ROOT}/src)
set(TEST ${ROOT}/test)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${ROOT}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ROOT}/build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${ROOT}/build)

include_directories(${SRC})

add_library(aes
    src/main.cpp
    src/picosha2.h
    src/base64.h
    src/plusaes.h
    src/aescipher.h
    src/aescipher.cpp
)

################################################################################
# gtest exe
add_executable(test_aes
    test/test_aescipher.cpp
    lib/gtest/gtest-all.cc
    lib/gtest/gtest_main.cc
)
target_include_directories(test_aes PRIVATE  lib)
if (WIN32)
    target_link_libraries(test_aes aes)
else()
    target_link_libraries(test_aes aes pthread)
endif()
