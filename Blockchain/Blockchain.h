#include <utility>

#include <utility>

#include <utility>

#ifndef CRYPTO_BLOCKCHAIN_H
#define CRYPTO_BLOCKCHAIN_H

#include "Block.h"
#include "ext/sha256.h"
#include <map>
#include <set>
#include <fstream>
#include <iomanip>

#define STARTING_AMOUNT 1000

struct User {
    std::string name;
    RSAPublicKey publicKey;
    bool operator < (const User& other) {
        return name < other.name;
    }
    User() = default;
    User(std::string _name, RSAPublicKey  _publicKey) : name(std::move(_name)), publicKey(std::move(_publicKey)) {}
    explicit User (const JSON& json) {
        json.at("name").get_to(name);
        std::string e, n;
        json.at("publicKey.E").get_to(e);
        json.at("publicKey.N").get_to(n);
        publicKey = RSAPublicKey{BigInt::BigInteger(n), BigInt::BigInteger(e)};
    }
    JSON ToJSON() {
        return {
                {"name", name},
                {"publicKey.E", publicKey.e.toString()},
                {"publicKey.N", publicKey.n.toString()}
        };
    }
};

class Blockchain {
private:
    std::vector<Block> chain;
    std::map<size_t, User> users;
    std::map<size_t, int> wallet;
    std::map<std::pair<size_t, size_t>, bool> valid;

    static bool CheckSignature(const Transaction& transaction, const RSAPublicKey& publicKey) {
        return transaction.VerifySignature(publicKey);
    }

    bool ProcessTransaction(const Transaction& transaction) {
        if (!CheckSignature(transaction, users[transaction.GetSenderID()].publicKey)) {
            return false;
        }
        if (wallet[transaction.GetSenderID()] >= transaction.GetAmount()) {
            wallet[transaction.GetSenderID()] -= transaction.GetAmount();
            wallet[transaction.GetReceiverID()] += transaction.GetAmount();
            return true;
        }
        return false;
    }

    static Block CreateGenesis(const RSAPrivateKey& rootKey) {
        Transaction transaction(0, 0, 0);
        transaction.Sign(rootKey);
        Block genesis = Block({transaction}, 0, sha256(""));
        genesis.Finalize();
        return genesis;
    }

    void RestoreWallets() {
        wallet[0] = STARTING_AMOUNT;

        size_t blockNum = 0;
        for (const auto& block : chain) {
            size_t transactionNum = 0;
            for (auto transaction : block.GetTransactions()) {
                if (ProcessTransaction(*transaction)) {
                    valid[{blockNum, transactionNum}] = true;
                }
                transactionNum++;
            }
            blockNum++;
        }
    }

    bool IsValidTransaction(size_t blockNum, size_t transactionNum) {
        return valid[{blockNum, transactionNum}];
    }

public:
    Blockchain() = default;

    Blockchain(User root, const RSAPrivateKey& rootKey) {
        chain.push_back(CreateGenesis(rootKey));
        users[0] = std::move(root);
        wallet[0] = STARTING_AMOUNT;
    }

    bool AddBlock(Block block) {
        fprintf(stdout, "\nAdding block %d to blockchain\n", block.GetID());
        if (!block.isFinalized()) {
            fprintf(stdout, "ERROR: Block is not finalized\n");
            return false;
        }
        if (block.GetPrevHash() != GetEndHash()) {
            fprintf(stdout, "ERROR: PrevHash in block is incorrect\n");
            return false;
        }
        size_t blockNum = chain.size();
        chain.push_back(block);
        size_t transactionNum = 0;
        for (auto transaction : block.GetTransactions()) {
            if (users.find(transaction->GetSenderID()) == users.end()) {
                fprintf(stdout, "User %d is not registered\n", transaction->GetSenderID());
                transactionNum++;
                continue;
            }
            if (users.find(transaction->GetReceiverID()) == users.end()) {
                fprintf(stdout, "User %d is not registered\n", transaction->GetReceiverID());
                transactionNum++;
                continue;
            }
            if (ProcessTransaction(*transaction)) {
                printf("Applied transaction from %s(#%d) to %s(#%d) for %d coins\n",
                        users[transaction->GetSenderID()].name.c_str(), transaction->GetSenderID(),
                        users[transaction->GetReceiverID()].name.c_str(), transaction->GetReceiverID(),
                        transaction->GetAmount());
                valid[{blockNum, transactionNum}] = true;
            } else {
                printf("Skipped transaction from %s(#%d) to %s(#%d) for %d coins\n",
                       users[transaction->GetSenderID()].name.c_str(), transaction->GetSenderID(),
                       users[transaction->GetReceiverID()].name.c_str(), transaction->GetReceiverID(),
                       transaction->GetAmount());
            }
            transactionNum++;
        }
        fprintf(stdout, "SUCCESS\n\n");
        return true;
    }

    bool Check() {
        for (size_t i = 0; i < chain.size(); i++) {
            std::vector<std::string> hashes = chain[i].GetHashes();
            if (MerkleTree(hashes).GetRootHash() != chain[i].GetRootHash() || !chain[i].CheckProof()) {
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

    bool RegisterUser(size_t _id, const std::string& _name, const RSAPublicKey& publicKey) {
        if (users.find(_id) != users.end()) {
            return false;
        }
        users[_id] = User(_name, publicKey);
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
        if (!this->Check()) { return false; }
        RestoreWallets();
        return true;
    }

    void GetUsersWithMoney() {
        fprintf(stdout, "\nChecking users balance\n");
        for (auto card : wallet) {
            if (card.second > 0) {
                User user = users[card.first];
                fprintf(stdout, "User %s(#%d) currently has %d coins\n", user.name.c_str(), card.first, card.second);
            }
        }
        fprintf(stdout, "Balanced checked\n\n");
    }

    void FindTransactions(int minAmount) {
        fprintf(stdout, "\nLooking for transactions with at least %d coins...\n", minAmount);
        size_t blockNum = 0;
        for (auto block : chain) {
            size_t transactionNum = 0;
            for (auto transaction : block.GetTransactions()) {
                if (IsValidTransaction(blockNum, transactionNum) && transaction->GetAmount() >= minAmount) {
                    User sender = users[transaction->GetSenderID()];
                    User receiver = users[transaction->GetReceiverID()];
                    fprintf(stdout, "Found transaction from %s(#%d) to %s(#%d) for %d coins in block %d\n",
                            sender.name.c_str(), transaction->GetSenderID(),
                            receiver.name.c_str(), transaction->GetReceiverID(),
                            transaction->GetAmount(), block.GetID());
                }
                transactionNum++;
            }
            blockNum++;
        }
        fprintf(stdout, "Finished search\n\n");
    }

    explicit Blockchain(const JSON& json) {
        std::vector<JSON> chainJSON = json.at("chain");
        for (const auto& blockJSON : chainJSON) {
            chain.emplace_back(blockJSON);
        }
        std::map<size_t, JSON> usersJSON;
        json.at("users").get_to(usersJSON);
        for (const auto& userJSON: usersJSON) {
            users[userJSON.first] = User(userJSON.second);
        }
    }

    JSON ToJSON() {
        std::vector<JSON> chainJSON;
        for (auto block : chain) {
            chainJSON.push_back(block.ToJSON());
        }
        std::map<size_t, JSON> usersJSON;
        for (auto user : users) {
            usersJSON[user.first] = user.second.ToJSON();
        }
        return {
                {"chain", chainJSON},
                {"users", usersJSON}
        };
    }
};

#endif //CRYPTO_BLOCKCHAIN_H
