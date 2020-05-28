//
// Created by stanislav_tomash on 28.05.2020.
//

#ifndef CRYPTO_CLIENTUTILS_H
#define CRYPTO_CLIENTUTILS_H

#include "Crypto.h"
#include "CommonUtils.h"
#include <string>
#include <map>

class ServerInfo {
private:
    std::map<int, PersonInfo> conn;
public:
    void closeConnection(int socket) {
        conn.erase(socket);
    }
    void registerConnection(int socket, const PersonInfo& info) {
        conn[socket] = info;
    }
};

class ServerMessageProcessor {
public:
    static bool PrepareRegistrationMessage(char* msg, int maxLen, PersonInfo& info) {
        std::string login;
        std::string key;
        bool readingLogin = true;
        for (int i = 0; i < msgLen; i++) {
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
    static bool PrepareRegistrationPrompt(char* msg, )
};

#endif //CRYPTO_CLIENTUTILS_H
