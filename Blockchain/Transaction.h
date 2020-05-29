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
    int amount{};
    size_t senderId{};
    size_t receiverId{};
    BigInt::BigInteger signature{1};

public:
    Transaction() = default;
    Transaction(int _amount, size_t _sender, size_t _receiver) : amount(_amount), senderId(_sender), receiverId(_receiver) {}
    int GetAmount() const { return amount; }
    size_t GetSenderID() const { return senderId; }
    size_t GetReceiverID() const { return receiverId; }
    void Sign(const RSAPrivateKey& privateKey) {
        signature = CryptoProcessor::Sign(GetHashForSign(), privateKey);
    }
    bool VerifySignature(const RSAPublicKey& publicKey) const {
        return CryptoProcessor::VerifySignature(GetHashForSign(), publicKey, signature);
    }
    std::string GetHash() const {
        std::string str = std::to_string(amount);
        str += ":" + std::to_string(senderId);
        str += ":" + std::to_string(receiverId);
        str += ":" + signature.toString();
        return sha256(str);
    }
    std::string GetHashForSign() const {
        std::string str = std::to_string(amount);
        str += ":" + std::to_string(senderId);
        str += ":" + std::to_string(receiverId);
        return sha256(str);
    }
    explicit Transaction(const JSON& json) : Transaction() {
        json.at("amount").get_to(amount);
        json.at("senderId").get_to(senderId);
        json.at("receiverId").get_to(receiverId);
        std::string signatureStr;
        json.at("signature").get_to(signatureStr);
        signature = BigInt::BigInteger(signatureStr);
    }
    JSON ToJSON() {
        return JSON {
                {"amount", amount},
                {"senderId", senderId},
                {"receiverId", receiverId},
                {"signature", signature.toString()}
        };
    }
};

#endif //CRYPTO_TRANSACTION_H
