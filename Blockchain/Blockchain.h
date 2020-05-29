#include <utility>

#ifndef CRYPTO_BLOCKCHAIN_H
#define CRYPTO_BLOCKCHAIN_H

#include "Block.h"
#include "ext/sha256.h"
#include <map>
#include <fstream>
#include <iomanip>

class Blockchain {
private:
    std::vector<Block> chain;
    std::map<size_t, int> wallet;
    std::map<size_t, std::string> names;
    bool ProcessTransaction(Transaction transaction) {
        if (wallet[transaction.GetSenderID()] >= transaction.GetAmount()) {
            wallet[transaction.GetSenderID()] -= transaction.GetAmount();
            wallet[transaction.GetReceiverID()] += transaction.GetAmount();
            return true;
        }
        return false;
    }
    static Block CreateGenesis() {
        Block genesis = Block({Transaction(0, 0, 0)}, 0, sha256(""));
        genesis.Finalize();
        return genesis;
    }
public:
    Blockchain() {
        chain.push_back(CreateGenesis());
        names[0] = "root";
        wallet[0] = 10000;
    }
    bool AddBlock(Block block) {
        if (!block.isFinalized()) {
            fprintf(stdout, "ERROR: Block is not finalized\n");
            return false;
        }
        chain.push_back(block);
        for (auto transaction : block.GetTransactions()) {
            if (names.find(transaction.GetSenderID()) == names.end()) {
                RegisterName(transaction.GetSenderID(), "anonymous");
            }
            if (names.find(transaction.GetReceiverID()) == names.end()) {
                RegisterName(transaction.GetReceiverID(), "anonymous");
            }
            if (ProcessTransaction(transaction)) {
                printf("Applied transaction from %s(#%d) to %s(#%d) for %d coins\n",
                        names[transaction.GetSenderID()].c_str(), transaction.GetSenderID(),
                        names[transaction.GetReceiverID()].c_str(), transaction.GetReceiverID(),
                        transaction.GetAmount());
            } else {
                printf("Skipped transaction from %s(#%d) to %s(#%d) for %d coins\n",
                       names[transaction.GetSenderID()].c_str(), transaction.GetSenderID(),
                       names[transaction.GetReceiverID()].c_str(), transaction.GetReceiverID(),
                       transaction.GetAmount());
            }
        }
        return true;
    }

    bool Check() {
        for (size_t i = 0; i < chain.size(); i++) {
            std::vector<std::string> hashes = chain[i].GetHashes();
            if (MerkleTree(hashes).GetRootHash() != chain[i].GetRootHash()) {
                fprintf(stdout, "Block %d is corrupted\n", i);
                return false;
            }
            if (i > 0 && chain[i].GetPrevHash() != chain[i-1].GetRootHash()) {
                fprintf(stdout, "Incorrect previous for %d\n", i);
                return false;
            }
        }
        return true;
    }

    bool RegisterName(size_t _id, std::string _name) {
        if (names.find(_id) != names.end()) {
            return false;
        }
        names[_id] = std::move(_name);
        return true;
    }

    std::string GetEndHash() {
        return chain.back().GetRootHash();
    }

    bool Save(const std::string& path) {
        std::ofstream file(path);
        if (file.fail()) { return false; }
        file << std::setw(4) << ToJSON() << std::endl;
        file.close();
        return true;
    }

    bool Load(const std::string& path) {
        std::ifstream file(path);
        if (file.fail()) { return false; }
        JSON json;
        file >> json;
        *this = Blockchain(json);
        file.close();
        return true;
    }

    explicit Blockchain(const JSON& json) {
        std::vector<JSON> chainJSON = json.at("chain");
        for (const auto& blockJSON : chainJSON) {
            chain.emplace_back(blockJSON);
        }
        json.at("wallet").get_to(wallet);
        json.at("names").get_to(names);
    }
    JSON ToJSON() {
        std::vector<JSON> chainJSON;
        for (auto block : chain) {
            chainJSON.push_back(block.ToJSON());
        }
        return {
                {"chain", chainJSON},
                {"wallet", wallet},
                {"names", names}
        };
    }
};

#endif //CRYPTO_BLOCKCHAIN_H
