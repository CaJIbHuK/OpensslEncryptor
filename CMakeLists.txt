cmake_minimum_required(VERSION 3.6)
project(encFabric)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES  main.cpp encFabric.cpp encFabric.h)
link_libraries(crypto)
#add_library(encFabric ${SOURCE_FILES})
add_executable(encFabric ${SOURCE_FILES})
