//
// Created by stanislav_tomash on 05.05.2020.
//

#ifndef CRYPTO_CRYPTO_H
#define CRYPTO_CRYPTO_H

#include "BigInteger/BigIntegerAlgorithm.h"
#include <random>
#include <algorithm>

struct RSAPrivateKey {
    BigInt::BigInteger n;
    BigInt::BigInteger d;
};

struct RSAPublicKey {
    BigInt::BigInteger n;
    BigInt::BigInteger e;
    bool operator == (const RSAPublicKey& other) const {
        return (n == other.n && e == other.e);
    }
};

struct RSAKeyPair {
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
};

class CryptoProcessor {
private:
    static const size_t KEY_LEN = 80;
    static const int DIVERSITY = 8;
    static const int DEFAULT_E = 65537;

    static BigInt::BigInteger GenPrimeOfBitLen(size_t bitLen){
        while (true) {
            BigInt::BigInteger randNum = BigInt::BigInteger::getRandOfBitLen(bitLen);
            if (BigInt::isPrime(randNum)) {
                return randNum;
            }
        }
    }
    static BigInt::BigInteger RSAEncryptInternal(size_t msg, const RSAPublicKey& key) {
        return BigInt::BigInteger(std::to_string(msg)).pow(key.e, key.n);
    }
    static std::string RSADecryptInternal(const BigInt::BigInteger& msg, const RSAPrivateKey& key) {
        size_t decr = msg.pow(key.d, key.n).toInt();
        std::string ans;
        while (decr) {
            ans += char(decr % 256);
            decr /= 256;
        }
        std::reverse(ans.begin(), ans.end());
        return ans;
    }
    static std::vector<size_t> SplitMsg(const std::string& msg) {
        std::vector<size_t> ans;
        size_t cur = 0;
        for (int i = 0; i < msg.size(); i++) {
            if (i && (i % 4 == 0)) {
                ans.push_back(cur);
                cur = 0;
            }
            cur *= 256;
            cur += msg[i];
        }
        if (cur) {
            ans.push_back(cur);
        }
        return ans;
    }
public:
    static RSAKeyPair RSAGenKeyPair(int _e = DEFAULT_E) {
        std::uniform_int_distribution<int> distribution(-DIVERSITY, DIVERSITY);
        static std::random_device randomDevice;
        int d1 = distribution(randomDevice);
        int d2 = DIVERSITY - d1;
        BigInt::BigInteger p = GenPrimeOfBitLen(KEY_LEN / 2 + d1);
        BigInt::BigInteger q = GenPrimeOfBitLen(KEY_LEN / 2 + d2);

        BigInt::BigInteger n = p * q;
        BigInt::BigInteger l = (p - BigInt::BigInteger(1)) * (q - BigInt::BigInteger(1));
        BigInt::BigInteger e = BigInt::BigInteger(_e);
        BigInt::BigInteger d = BigInt::inverseInCircle(e, l);

        return RSAKeyPair{RSAPrivateKey{n, d}, RSAPublicKey{n, e}};
    }
    static std::vector<BigInt::BigInteger> RSAEncrypt(const std::string& msg, const RSAPublicKey& key) {
        size_t msgLen = msg.length();
        std::vector<size_t> batches = SplitMsg(msg);
        std::vector<BigInt::BigInteger> ans;
        for (auto batch : batches) {
            ans.push_back(RSAEncryptInternal(batch, key));
        }
        return ans;
    }
    static std::string RSADecrypt(const std::vector<BigInt::BigInteger>& msg, const RSAPrivateKey& key) {
        size_t msgLen = msg.size();
        std::string ans;
        for (int i = 0; i < msgLen; i++) {
            ans += RSADecryptInternal(msg[i], key);
        }
        return ans;
    }
    static BigInt::BigInteger ProduceHash(const std::string& msg) {
        int h = ((int)std::hash<std::string>{}(msg));
        h = abs(h);
        return BigInt::BigInteger(h);
    }
    static BigInt::BigInteger Sign(const std::string& msg, const RSAPrivateKey& key) {
        BigInt::BigInteger h = ProduceHash(msg);
        return h.pow(key.d, key.n);
    }
    static bool VerifySignature(const std::string& msg, const RSAPublicKey& key, const BigInt::BigInteger& signature) {
        BigInt::BigInteger h = ProduceHash(msg);
        BigInt::BigInteger expected = signature.pow(key.e, key.n);
        return (h == expected);
    }
};

#endif // CRYPTO_CRYPTO_H
