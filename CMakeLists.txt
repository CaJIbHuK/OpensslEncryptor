cmake_minimum_required(VERSION 3.6)
project(encFabric)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES BaseEncryptor.h DerivedEncryptor.h Fabric.h BaseEncryptor.cpp DerivedEncryptor.cpp Fabric.cpp)
add_library(encFabric ${SOURCE_FILES})
target_link_libraries(encFabric crypto)

