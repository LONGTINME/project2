#ifndef RSU_H
#define RSU_H

#include "MyElgamal.h"
#include "Vehicle.h"
#include "ES.h"
#include "FN_Allocation.h"
#include <cryptlib.h>
#include <string>
#include <unordered_map>
#include <vector>

class RSU {
public:
    RSU(const CryptoPP::ElGamal::PublicKey &rsuPublicKey, const CryptoPP::ElGamal::PrivateKey &rsuPrivateKey, const CryptoPP::ElGamal::PublicKey &esPublicKey);
    void ReceiveTaskFromVehicle(const std::string &encryptedIdentity, const std::string &encryptedTaskAndNoise, const CryptoPP::ElGamal::PublicKey &vehiclePublicKey);
     void PrepareDataForES(std::string &encryptedPseudonymAndTime, std::string &encryptedTask);
         // 新方法用于处理ES接收到的任务
    void ProcessTaskWithES(ES &es, const std::string &encryptedPseudonymAndTime, const std::string &encryptedTask);

    void SendTaskToES(ES &es);
    void ReceiveResponseFromES(const std::string &encryptedResponse);
    void RegisterVehicle(int id, Vehicle &vehicle);
    void PrintMTable() const;
    CryptoPP::ElGamal::PublicKey getPublicKey() const;

private:
    void SendResponseToVehicle(Vehicle &vehicle, const std::string &response);

    CryptoPP::ElGamal::PublicKey rsuPublicKey_;
    CryptoPP::ElGamal::PrivateKey rsuPrivateKey_;
    CryptoPP::ElGamal::PublicKey esPublicKey_;
    std::unordered_map<int, CryptoPP::ElGamal::PublicKey> vehiclePublicKeys_;
    std::unordered_map<int, Vehicle*> vehicleMap_;
    MTable mTable_;
    int currentIdx_;
    std::string currentTask_;
    std::string currentIdentity_;
    std::string currentFN_;
    std::string currentTime_;
    std::string currentResponse_;
};

#endif // RSU_H
