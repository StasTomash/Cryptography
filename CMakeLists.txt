cmake_minimum_required(VERSION 3.13)
project(Crypto)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(BigInteger)
add_library(Crypto Crypto.h)
target_link_libraries(Crypto BigInteger)

add_executable(Server server.cpp CommonUtils.h ServerUtils.h)
target_link_libraries(Server Crypto)

add_executable(Client client.cpp CommonUtils.h ClientUtils.h)
target_link_libraries(Client Crypto)
