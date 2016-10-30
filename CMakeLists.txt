cmake_minimum_required(VERSION 3.6)
project(encFabric)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES encFabric.cpp encFabric.h)
add_library(encFabric ${SOURCE_FILES})