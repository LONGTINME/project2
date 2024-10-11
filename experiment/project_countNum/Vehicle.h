#ifndef VEHICLE_H
#define VEHICLE_H

#include <string>
#include <elgamal.h>
#include <cryptlib.h>

class RSU;

class Vehicle {
public:
    Vehicle(int id, const CryptoPP::ElGamal::PublicKey &rsuPublicKey, const CryptoPP::ElGamal::PublicKey &esPublicKey, const CryptoPP::ElGamal::PublicKey &vehiclePublicKey, const CryptoPP::ElGamal::PrivateKey &privateKey);
    void GenerateTask();
    void SendTaskToRSU(RSU &rsu);
    void ReceiveResponseFromRSU(const std::string &encryptedResponse);
    std::string RemoveNoise(const std::string &VR, const std::string &noise);

    CryptoPP::ElGamal::PublicKey getPublicKey() const;
    int getID() const;

private:
    int id_;
    int taskCounter_;
    CryptoPP::ElGamal::PublicKey rsuPublicKey_;
    CryptoPP::ElGamal::PublicKey esPublicKey_;
    CryptoPP::ElGamal::PublicKey vehiclePublicKey_;
    CryptoPP::ElGamal::PrivateKey privateKey_;
    std::string currentTask_;
    std::string randomNoise_;
};

#endif // VEHICLE_H
