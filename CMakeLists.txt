cmake_minimum_required(VERSION 3.0.0)

project(aes VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5Core)

add_executable(${PROJECT_NAME}
    "src/main.cpp"
    "src/picosha2.h"
    "src/base64.h"
    "src/plusaes.h"
    )

target_link_libraries(${PROJECT_NAME} Qt5::Core)
