#include <utility>

//
// Created by stanislav_tomash on 29.05.2020.
//

#ifndef CRYPTO_BLOCK_H
#define CRYPTO_BLOCK_H

#include "ext/json.h"
#include "../Crypto.h"
#include "Transaction.h"
#include "MerkleTree.h"

#define DIFFICULTY 2

typedef nlohmann::json JSON;

class Block {
private:
    std::vector<Transaction> transactions;
    size_t id{};
    std::string prevHash;
    std::string hash;
    MerkleTree tree;
    bool finalized{};
    size_t nonce{};

    std::hash<size_t> hashFunc;

public:
    Block() = default;
    void AddTransaction(const Transaction& transaction) {
        transactions.push_back(transaction);
    }
    Block(const std::vector<Transaction>& _transactions, int _id, const std::string& _prevHash) {
        transactions = _transactions;
        id = _id,
        prevHash = _prevHash;
    }
    std::vector<const Transaction*> GetTransactions() const {
        std::vector<const Transaction*> ans;
        for (const auto &transaction : transactions) {
            ans.push_back(&transaction);
        }
        return ans;
    }
    size_t GetID() { return id; }
    std::vector<std::string> GetHashes() {
        std::vector<std::string> hashes;
        for (const auto& transaction : transactions) {
            hashes.push_back(transaction.GetHash());
        }
        return hashes;
    }
    std::string GetRootHash() const {
        assert (finalized);
        return tree.GetRootHash();
    }
    std::string GetPrevHash() const { return prevHash; }
    bool isFinalized() const { return finalized; }
    void Finalize() {
        std::vector<std::string> hashes = GetHashes();
        tree = MerkleTree(hashes);
        while (true) {
            std::string guess = sha256(tree.GetRootHash() + prevHash + std::to_string(nonce));
            bool found = true;
            for (int i = 0; i < DIFFICULTY; i++) {
                if (guess[i] != '0') { found = false; }
            }
            if (found) {
                hash = guess;
                break;
            }
            nonce++;
        }
        finalized = true;
    }
    bool CheckProof() {
        return hash == sha256(tree.GetRootHash() + prevHash + std::to_string(nonce));
    }
    explicit Block(const JSON& json) : Block() {
        std::vector<JSON> transactionJSONs = json.at("transactions").get<std::vector<JSON>>();
        for (auto transactionJSON : transactionJSONs) {
            transactions.emplace_back(transactionJSON);
        }
        tree = MerkleTree(json.at("tree"));

        json.at("id").get_to(id);
        json.at("prevHash").get_to(prevHash);
        json.at("hash").get_to(hash);
        json.at("finalized").get_to(finalized);
        json.at("nonce").get_to(nonce);
    }
    JSON ToJSON() {
        std::vector<JSON> transactionJSONs;
        for (auto transaction : transactions) {
            transactionJSONs.push_back(transaction.ToJSON());
        }
        return {
                {"transactions", transactionJSONs},
                {"id", id},
                {"prevHash", prevHash},
                {"hash", hash},
                {"tree", tree.ToJSON()},
                {"finalized", finalized},
                {"nonce", nonce}
        };
    }
};

#endif //CRYPTO_BLOCK_H
