cmake_minimum_required(VERSION 3.20)
project(TrayApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TrayApp WIN32
    src/main.cpp
    src/resource.h
    src/resource.rc
)

target_link_libraries(TrayApp PRIVATE comctl32)
