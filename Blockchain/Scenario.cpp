//
// Created by stanislav_tomash on 29.05.2020.
//

#include "Block.h"
#include "Blockchain.h"
#include "MerkleTree.h"

int main() {
    RSAKeyPair rootKeys = CryptoProcessor::RSAGenKeyPair();
    User root("root", rootKeys.publicKey);

    Blockchain blockchain(root, 100, rootKeys.privateKey);

    RSAKeyPair keys[3];
    for (auto & key : keys) {
        key = CryptoProcessor::RSAGenKeyPair();
    }
    blockchain.RegisterUser(1, "giraffeh", keys[0].publicKey);
    blockchain.RegisterUser(2, "harvester", keys[1].publicKey);
    blockchain.RegisterUser(3, "sorrow", keys[2].publicKey);

    Block block({}, 1, blockchain.GetEndHash());

    Transaction transaction;
    transaction = Transaction(20, 0, 1);
    transaction.Sign(rootKeys.privateKey);
    block.AddTransaction(transaction);

    transaction = Transaction(10, 1, 2);
    transaction.Sign(keys[0].privateKey);
    block.AddTransaction(transaction);

    transaction = Transaction(5, 1, 3);
    transaction.Sign(keys[1].privateKey);
    block.AddTransaction(transaction);

    block.Finalize();
    blockchain.AddBlock(block);

    blockchain.GetUsersWithMoney();

    block = Block({}, 2, blockchain.GetEndHash());

    transaction = Transaction(20, 0, 2);
    transaction.Sign(rootKeys.privateKey);
    block.AddTransaction(transaction);

    transaction = Transaction(30, 2, 3);
    transaction.Sign(keys[1].privateKey);
    block.AddTransaction(transaction);

    transaction = Transaction(100, 3, 1);
    transaction.Sign(keys[2].privateKey);
    block.AddTransaction(transaction);

    block.Finalize();
    blockchain.AddBlock(block);

    blockchain.GetUsersWithMoney();
    blockchain.FindTransactions(20);

    blockchain.Save("dump.json");
}