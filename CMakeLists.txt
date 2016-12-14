cmake_minimum_required(VERSION 3.6)
project(encFabric)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES BaseEncryptor.h RC4Encryptor.h Fabric.h BaseEncryptor.cpp RC4Encryptor.cpp Fabric.cpp ContentProviders.h ContentProviders.cpp AESEncryptor.h AESEncryptor.cpp common_openssl.h DESEncryptor.h DESEncryptor.cpp OTPEncryptor.h OTPEncryptor.cpp common.h)
add_library(encFabric ${SOURCE_FILES})
target_link_libraries(encFabric crypto)

