#include <iostream>
#include "Crypto.h"

int main() {
    RSAKeyPair kp = CryptoProcessor::RSAGenKeyPair();
    std::cout << kp.privateKey.d << "\n";
    std::vector<BigInt::BigInteger> code = CryptoProcessor::RSAEncrypt("Hello", kp.privateKey);
    std::string ans = CryptoProcessor::RSADecrypt(code, kp.publicKey);
    std::cout << ans;
    return 0;
}