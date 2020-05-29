#include <utility>

//
// Created by stanislav_tomash on 29.05.2020.
//

#ifndef CRYPTO_MERKLETREE_H
#define CRYPTO_MERKLETREE_H

#include <vector>
#include "ext/json.h"
#include "ext/sha256.h"

typedef nlohmann::json JSON;

class MerkleTree {
private:
    struct MerkleNode {
        MerkleNode* left{};
        MerkleNode* right{};
        std::string hashValue;
        MerkleNode() = default;
        explicit MerkleNode(std::string hash) : left(nullptr), right(nullptr), hashValue(std::move(hash)) {}
        explicit MerkleNode(MerkleNode* l, MerkleNode* r, std::string hash) : left(l), right(r), hashValue(std::move(hash)) {}
    };
    MerkleNode* root{};
    std::vector<std::string> leafHashes;
    MerkleNode* Build() {
        std::vector<MerkleNode*> currentLevel;
        currentLevel.reserve(leafHashes.size());
        for (const auto& hash : leafHashes) {
            currentLevel.emplace_back(new MerkleNode(hash));
        }
        while (currentLevel.size() > 1) {
            if (currentLevel.size() % 2) {
                currentLevel.emplace_back(currentLevel.back());
            }
            std::vector<MerkleNode*> nextLevel;
            nextLevel.reserve(currentLevel.size() / 2);
            for (int i = 0; i < currentLevel.size(); i += 2) {
                nextLevel.push_back(new MerkleNode(currentLevel[i], currentLevel[i+1],
                        sha256(currentLevel[i]->hashValue + currentLevel[i+1]->hashValue)));
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }
public:
    MerkleTree() = default;
    explicit MerkleTree(const std::vector<std::string>& hashes) {
        leafHashes = hashes;
        root = Build();
    }
    explicit MerkleTree(const JSON& json) : MerkleTree(json.get<std::vector<std::string>>()) {}
    std::string GetRootHash() const { return root->hashValue; }
    JSON ToJSON() {
        return JSON(leafHashes);
    }
    MerkleTree GetExtended(const std::string& hash) {
        auto extendedLeafHashes = leafHashes;
        extendedLeafHashes.push_back(hash);
        return MerkleTree(extendedLeafHashes);
    }

    bool operator == (const MerkleTree& other) const {
        if (!root && !other.root) { return true; }
        if (!root || !other.root) { return false; }

        return root->hashValue == other.root->hashValue;
    }
};

#endif //CRYPTO_MERKLETREE_H
