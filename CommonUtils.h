//
// Created by stanislav_tomash on 28.05.2020.
//

#ifndef CRYPTO_COMMONUTILS_H
#define CRYPTO_COMMONUTILS_H

#define S_ERROR 0
#define S_CONFIRM 1
#define S_CHAT_MESSAGE 2
#define S_CHAT_MESSAGE_FINISHED 3
#define S_DISTRIBUTE_KEY 4
#define C_REGISTRATION 5
#define C_CHAT_MESSAGE 6
#define C_CHAT_MESSAGE_FINISHED 7

#define EMPTY_STMT 0
#define CHECK(x, err) if ((x) < 0) { perror(err); exit(EXIT_FAILURE); } EMPTY_STMT

struct PersonInfo {
    std::string login;
    RSAPublicKey publicKey;
    bool operator < (const PersonInfo& other) const {
        return login < other.login;
    }
};

#endif //CRYPTO_COMMONUTILS_H
