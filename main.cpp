#include <iostream>
#include "Crypto.h"

int main() {
    RSAKeyPair kp = CryptoProcessor::RSAGenKeyPair();
    std::cout << kp.privateKey.d << "\n";
    std::cout << BigInt::BigInteger("2222222222222222222").pow(kp.privateKey.d, kp.privateKey.n).pow(kp.publicKey.e, kp.publicKey.n) << "\n";
    std::cout << BigInt::BigInteger("2222222222222222222").pow(kp.publicKey.e, kp.publicKey.n).pow(kp.privateKey.d, kp.privateKey.n) << "\n";
    BigInt::BigInteger sign = CryptoProcessor::Sign("Message", kp.privateKey);
    bool cert = CryptoProcessor::VerifySignature("Message", kp.publicKey, sign);
    std::cout << cert;
    return 0;
}