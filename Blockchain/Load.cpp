//
// Created by stanislav_tomash on 29.05.2020.
//

#include "Block.h"
#include "Blockchain.h"
#include "MerkleTree.h"

int main() {
    Blockchain blockchain;
    if (!blockchain.Load("dump.json")) {
        exit(EXIT_FAILURE);
    }
    blockchain.GetUsersWithMoney();
    blockchain.FindTransactions(20);
}