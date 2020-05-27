cmake_minimum_required(VERSION 3.14)
project(Crypto)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(BigInteger)
add_executable(Crypto Crypto.h main.cpp)
target_link_libraries(Crypto BigInteger)