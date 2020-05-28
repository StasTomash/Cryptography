cmake_minimum_required(VERSION 3.14)
project(Crypto)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(BigInteger)
add_library(Crypto Crypto.h)
target_link_libraries(Crypto BigInteger)

add_executable(Server server.cpp CommonUtils.h ServerUtils.h)
target_link_libraries(Server Crypto ws2_32 wsock32)
