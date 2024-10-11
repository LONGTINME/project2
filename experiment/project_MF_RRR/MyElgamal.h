#ifndef MyELGAMAL_H
#define MyELGAMAL_H

#include <elgamal.h>
#include <string>

using namespace CryptoPP;

std::string ElgamalEncrypt(const std::string& message, const ElGamal::PublicKey& publicKey);
std::string ElgamalDecrypt(const std::string& cipher, const ElGamal::PrivateKey& privateKey);

#endif // ELGAMAL_H
