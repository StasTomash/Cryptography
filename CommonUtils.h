//
// Created by stanislav_tomash on 28.05.2020.
//

#ifndef CRYPTO_COMMONUTILS_H
#define CRYPTO_COMMONUTILS_H

#define S_PLANE_TEXT 0
#define C_REGISTRATION 1
#define C_CHAT_MESSAGE 2
#define C_CHAT_MESSAGE_FINISHED 3
#define S_CHAT_MESSAGE 4
#define S_CHAT_MESSAGE_FINISHED 5
#define S_DISTRIBUTE_KEY 6

struct PersonInfo {
    std::string login;
    RSAPublicKey publicKey;
    bool operator < (const PersonInfo& other) const {
        return login < other.login;
    }
};

#endif //CRYPTO_COMMONUTILS_H
