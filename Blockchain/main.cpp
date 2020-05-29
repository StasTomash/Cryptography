//
// Created by stanislav_tomash on 29.05.2020.
//

#include "Block.h"
#include "Blockchain.h"
#include "MerkleTree.h"

int main() {
    Blockchain blockchain;
    blockchain.RegisterName(1, "giraffeh");
    blockchain.RegisterName(2, "harvester");
    blockchain.RegisterName(3, "sorrow");

    Block block({}, 1, blockchain.GetEndHash());
    block.AddTransaction(Transaction(20, 0, 1));
    block.AddTransaction(Transaction(10, 1, 2));
    block.AddTransaction(Transaction(5, 1, 3));
    block.Finalize();
    blockchain.AddBlock(block);

    blockchain.Save("dump.json");
    blockchain = Blockchain();
    blockchain.Load("dump.json");
    blockchain.Save("dump.json");
}