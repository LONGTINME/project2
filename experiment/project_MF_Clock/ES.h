#ifndef ES_H
#define ES_H

#include <string>
#include <elgamal.h>
#include <cryptlib.h>

class RSU;

class ES {
public:
    ES(const CryptoPP::ElGamal::PublicKey &esPublicKey, const CryptoPP::ElGamal::PrivateKey &esPrivateKey);
    void ReceiveTask(const std::string &encryptedPseudonymAndTime, const std::string &encryptedTask);
    void SendResponseToRSU(RSU &rsu);
    CryptoPP::ElGamal::PublicKey getPublicKey() const;

private:
    CryptoPP::ElGamal::PublicKey esPublicKey_;
    CryptoPP::ElGamal::PrivateKey esPrivateKey_;
    std::string currentPseudonymAndTime_;
    std::string currentTask_;
    std::string currentResponse_;
};

#endif // ES_H
