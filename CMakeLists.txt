cmake_minimum_required(VERSION 3.13)

project(dns-server-starter-cpp)

find_program(CLANGPP clang++)
if(CLANGPP)
    set(CMAKE_CXX_COMPILER "${CLANGPP}")
endif()

set(CMAKE_CXX_STANDARD 20) # Enable the C++23 standard

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

add_executable(server ${SOURCE_FILES})
