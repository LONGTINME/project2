#ifndef RSU_H
#define RSU_H

#include "MyElgamal.h"
#include "Vehicle.h"
#include "ES.h"
#include "FN_Allocation.h"
#include "CS.h"
#include "SP.h"
#include <cryptlib.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "paillier1.h"

// RSU类型枚举
enum class RSUType {
    HighCapacity,   // 高容量
    MediumCapacity, // 中容量
    LowCapacity     // 低容量
};

class RSU {
public:
    RSU(const CryptoPP::ElGamal::PublicKey &rsuPublicKey, const CryptoPP::ElGamal::PrivateKey &rsuPrivateKey,
        const CryptoPP::ElGamal::PublicKey &esPublicKey, const Paillier &spPublicKey, RSUType type); // 构造函数增加RSUType
    
    void ReceiveTaskFromVehicle(const std::string &encryptedIdentity, const std::string &encryptedTaskAndNoise, const CryptoPP::ElGamal::PublicKey &vehiclePublicKey);
    void SendTaskToES(ES &es);
    void ReceiveResponseFromES(const std::string &encryptedResponse);
    void RegisterVehicle(int id, Vehicle &vehicle);
    void PrintMTable(std::ofstream &logfile) const;
    
    std::vector<std::pair<std::string, std::string>> CountAndEncryptTasks(const CryptoPP::ElGamal::PublicKey &csPublicKey, std::ofstream &logfile);
    void SendDataToCS(CS &cs, const std::vector<std::pair<std::string, std::string>> &encryptedData, std::ofstream &logfile);

    CryptoPP::ElGamal::PublicKey getPublicKey() const;
    RSUType getType() const;  // 获取RSU类型
     void SendResponseToVehicle(Vehicle &vehicle, const std::string &response);

private:
   
    void RemoveNodeFromList(ANode *&list, ANode *node);

    CryptoPP::ElGamal::PublicKey rsuPublicKey_;
    CryptoPP::ElGamal::PrivateKey rsuPrivateKey_;
    CryptoPP::ElGamal::PublicKey esPublicKey_;
    Paillier spPublicKey_;
    RSUType type_;  // 新增类型属性

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
