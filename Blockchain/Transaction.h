//
// Created by stanislav_tomash on 29.05.2020.
//

#ifndef CRYPTO_TRANSACTION_H
#define CRYPTO_TRANSACTION_H

#include "ext/json.h"
#include "../Crypto.h"
#include "ext/sha256.h"

typedef nlohmann::json JSON;

class Transaction {
private:
    int amount;
    size_t senderId;
    size_t receiverId;

public:
    Transaction() = default;
    Transaction(int _amount, size_t _sender, size_t _receiver) : amount(_amount), senderId(_sender), receiverId(_receiver) {}
    explicit Transaction(const JSON& json) : Transaction() {
        json.at("amount").get_to(amount);
        json.at("senderId").get_to(senderId);
        json.at("receiverId").get_to(receiverId);
    }
    int GetAmount() const { return amount; }
    size_t GetSenderID() const { return senderId; }
    size_t GetReceiverID() const { return receiverId; }
    std::string GetHash() const {
        std::string str = std::to_string(amount) + ":" + std::to_string(senderId) + ":" + std::to_string(receiverId);
        return sha256(str);
    }
    JSON ToJSON() {
        return JSON {
                {"amount", amount},
                {"senderId", senderId},
                {"receiverId", receiverId}
        };
    }
};

#endif //CRYPTO_TRANSACTION_H
