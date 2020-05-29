cmake_minimum_required(VERSION 3.13)
project(Crypto)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(BigInteger)
add_library(Crypto Crypto.h)
target_link_libraries(Crypto BigInteger)

add_library(Blockchain Blockchain/Blockchain.h Blockchain/ext/json.h Blockchain/Block.h Blockchain/MerkleTree.h Blockchain/Transaction.h Blockchain/ext/sha256.h Blockchain/ext/sha256.cpp)
target_link_libraries(Blockchain Crypto)

add_executable(BlockchainProcessor Blockchain/Scenario.cpp)
target_link_libraries(BlockchainProcessor Blockchain)

add_executable(BlockchainLoader Blockchain/Load.cpp)
target_link_libraries(BlockchainLoader Blockchain)

add_executable(Server Chat/server.cpp Chat/CommonUtils.h Chat/ServerUtils.h)
target_link_libraries(Server Crypto)

add_executable(Client Chat/client.cpp Chat/CommonUtils.h Chat/ClientUtils.h)
target_link_libraries(Client Crypto)
