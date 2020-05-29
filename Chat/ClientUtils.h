//
// Created by stanislav_tomash on 28.05.2020.
//

#ifndef CRYPTO_CLIENTUTILS_H
#define CRYPTO_CLIENTUTILS_H

#include "../Crypto.h"
#include "CommonUtils.h"
#include <string>
#include <map>

class ClientInfo {
private:
    std::map<std::string, std::string> openMessages;
    RSAKeyPair keyPair;
    RSAPublicKey serverKey;
    std::string login;
public:
    ClientInfo() {
        keyPair = CryptoProcessor::RSAGenKeyPair();
    }
    void addToMessage(const std::string& author, const std::string& addition) {
        openMessages[author] += addition;
    }
    void closeMessage(const std::string& author) {
        openMessages.erase(author);
    }
    std::string getMessage(const std::string& author) const { return openMessages.at(author); }

    RSAPublicKey getPublicKey() const { return keyPair.publicKey; }
    RSAPrivateKey getPrivateKey() const { return keyPair.privateKey; }
    std::string getLogin() const { return login; }
    void setLogin(const std::string& _login) { login = _login; }
    RSAPublicKey getServerKey() const { return serverKey; }
    void setServerKey(const RSAPublicKey& pk) { serverKey = pk; }
};

class ClientMessageProcessor {
private:
    static bool ParseToBigInts(const char* msg, int msgLen, std::vector<BigInt::BigInteger>& ans) {
        std::string curStr;
        for (int i = 0; i < msgLen; i++) {
            if (msg[i] == ' ') {
                ans.emplace_back(curStr);
                curStr = "";
            } else if (std::isdigit(msg[i])) {
                curStr += msg[i];
            } else {
                return false;
            }
        }
        if (!curStr.empty()) {
            ans.emplace_back(curStr);
        }
        return true;
    }
public:
    static bool PrepareRegistration(std::string& msg, int& messageType, const std::string& login, ClientInfo& ci) {
        msg = login + " ";
        msg += ci.getPublicKey().e.toString() + " ";
        msg += ci.getPublicKey().n.toString();
        messageType = C_REGISTRATION;
        return true;
    }
    static bool ParseServerKeyDistribution(char* msg, size_t msgLen, ClientInfo& ci) {
        if (msgLen == 0) {
            return false;
        }
        int type = msg[0] - '0';
        if (type != S_DISTRIBUTE_KEY) {
            return false;
        }
        std::vector<BigInt::BigInteger> key;
        if (!ParseToBigInts(msg+1, (int)msgLen-1, key)) {
            return false;
        }
        if (key.size() != 2) {
            return false;
        }
        ci.setServerKey(RSAPublicKey{key[1], key[0]});
        return true;
    }
    static bool ParseChatMessage(const char* msg, int msgLen, ClientInfo& ci, std::string& /* out */ completeMessage, std::string& /* out */ sender) {
        int type = msg[0] - '0';
        if (type != S_CHAT_MESSAGE && type != S_CHAT_MESSAGE_FINISHED) {
            return false;
        }
        bool readingLogin = true;
        std::string login;
        for (int i = 1; i < msgLen; i++) {
            if (readingLogin) {
                if (msg[i] == ' ') {
                    readingLogin = false;
                } else if (std::isalnum(msg[i])) {
                    login += msg[i];
                } else {
                    return false;
                }
            } else {
                std::vector<BigInt::BigInteger> codes;
                if (!ParseToBigInts(msg+i, msgLen-i, codes)) {
                    return false;
                }
                BigInt::BigInteger signature;
                if (type == S_CHAT_MESSAGE_FINISHED) {
                    signature = codes.back();
                    codes.pop_back();
                }
                ci.addToMessage(login, CryptoProcessor::RSADecrypt(codes, ci.getPrivateKey()));
                if (type == S_CHAT_MESSAGE_FINISHED) {
                    completeMessage = ci.getMessage(login);
                    sender = login;
                    ci.closeMessage(login);
                    if (!CryptoProcessor::VerifySignature(completeMessage, ci.getServerKey(), signature)) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }
    static bool PrepareChatMessage(std::vector<std::string>& msgs, const std::string& text, const ClientInfo& ci) {
        std::string login = ci.getLogin();
//        std::cout << "Encrypting with " << ci.getServerKey().e << " " << ci.getServerKey().n << "\n";
        std::vector<BigInt::BigInteger> codes = CryptoProcessor::RSAEncrypt(text, ci.getServerKey());
        std::vector<std::string> words;
        words.reserve(codes.size());
        for (const auto& code : codes) {
            words.emplace_back(code.toString());
        }
        BigInt::BigInteger signature = CryptoProcessor::Sign(text, ci.getPrivateKey());
//        std::cout << "Signature " << signature << " for " << text << "\n";
//        std::cout << "Key used " << ci.getPrivateKey().d << " " << ci.getPrivateKey().n << "\n";
//        std::cout << "Corresponding public " << ci.getPublicKey().e << " " << ci.getPublicKey().n << "\n";

        words.emplace_back(signature.toString());

        std::string curStr = words[0] + " ";
        for (int i = 1; i < words.size(); i++) {
//            if (i % 5 == 0) {
//                msgs.emplace_back(curStr);
//                curStr = "";
//            }
            curStr += words[i] + " ";
        }
        if (!curStr.empty()) {
            msgs.emplace_back(curStr);
        }
//        std::cout << "Prepared " << msgs.size() << " messages\n";
        return true;
    }
};

#endif //CRYPTO_CLIENTUTILS_H
