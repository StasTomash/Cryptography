#ifndef CRYPTO_SERVERUTILS_H
#define CRYPTO_SERVERUTILS_H

#include "Crypto.h"
#include "CommonUtils.h"
#include <string>
#include <map>
#include <set>

class ServerInfo {
private:
    std::map<int, PersonInfo> conn;
    std::set<PersonInfo> users;
    std::map<int, std::string> openMessages;
    RSAKeyPair keyPair;
public:
    ServerInfo() {
        keyPair = CryptoProcessor::RSAGenKeyPair();
    }
    bool closeConnection(int socket) {
        conn.erase(socket);
        return true;
    }
    bool registerConnection(int socket, const PersonInfo& info) {
        if (users.find(info) != users.end()) {
            if (!(users.find(info) -> publicKey == info.publicKey)) {
                return false;
            }
        }
        conn[socket] = info;
        users.insert(info);
        return true;
    }
    bool isRegistered(int socket) {
        return conn.find(socket) != conn.end();
    }
    void addToMessage(int socket, const std::string& addition) {
        openMessages[socket] += addition;
    }
    std::string getMessage(int socket) const { return openMessages.at(socket); }
    PersonInfo getPerson(int socket) const { return conn.at(socket); }
    RSAPublicKey getPublicKey() const { return keyPair.publicKey; }
    RSAPrivateKey getPrivateKey() const { return keyPair.privateKey; }
};

class ServerMessageProcessor {
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
    static bool ParseRegistrationMessage(const char* msg, int msgLen, PersonInfo& info) {
        std::string login;
        std::string key;
        if (!std::isdigit(msg[0]) || (msg[0] - '0') != C_REGISTRATION) {
            return false;
        }
        bool readingLogin = true;
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
                if (std::isdigit(msg[i])) {
                    key += msg[i];
                } else {
                    return false;
                }
            }
        }
        info = PersonInfo{login, BigInt::BigInteger(key)};
        return true;
    }
    static bool PreparePublicKeyToSend(std::string& msg, int& messageType, ServerInfo& si) {
        msg = std::to_string(si.getPublicKey().e.toInt());
        messageType = S_DISTRIBUTE_KEY;
        return true;
    }
    static bool ParseChatMessage(int socket, const char* msg, int msgLen, ServerInfo& si, bool& /* out */ distribute) {
        int type = (msg[0] - '0');
        if (type != C_CHAT_MESSAGE_FINISHED && type != C_CHAT_MESSAGE) {
            return false;
        }
        std::vector<BigInt::BigInteger> codes;
        if (!ParseToBigInts(msg+1, msgLen-1, codes)) {
            return false;
        }
        BigInt::BigInteger signature;
        if (type == C_CHAT_MESSAGE_FINISHED) {
            signature = codes.back();
            codes.pop_back();
        }
        PersonInfo pi = si.getPerson(socket);
        si.addToMessage(socket, CryptoProcessor::RSADecrypt(codes, si.getPrivateKey()));
        if (type == C_CHAT_MESSAGE_FINISHED) {
            if (!CryptoProcessor::VerifySignature(si.getMessage(socket), pi.publicKey, signature)) {
                return false;
            }
            distribute = true;
        }
        return true;
    }
    static bool PrepareChatMessage(int socket, std::vector<std::string>& msgs, const std::string& text, const ServerInfo& si, const std::string& login) {
        PersonInfo pi = si.getPerson(socket);
        std::vector<BigInt::BigInteger> codes = CryptoProcessor::RSAEncrypt(text, pi.publicKey);
        std::vector<std::string> words;
        for (const auto& code : codes) {
            words.emplace_back(code.toString());
        }
        BigInt::BigInteger signature = CryptoProcessor::Sign(text, si.getPrivateKey());
        words.emplace_back(signature.toString());

        std::string curStr = login + " " + words[0];
        for (int i = 1; i < words.size(); i++) {
            if (i % 3 == 0) {
                msgs.emplace_back(curStr);
                curStr = login;
            }
            curStr += " " + words[i];
        }
        if (curStr != login) {
            msgs.emplace_back(curStr);
        }

        return true;
    }
};

#endif //CRYPTO_SERVERUTILS_H
