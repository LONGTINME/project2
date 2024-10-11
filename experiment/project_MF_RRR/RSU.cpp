#include "RSU.h"
#include "FN_Allocation.h"
#include "MyElgamal.h"
#include <cryptlib.h>
#include <osrng.h>
#include <base64.h>
#include <iostream>
#include <ctime>

using namespace CryptoPP;

RSU::RSU(const ElGamal::PublicKey &rsuPublicKey, const ElGamal::PrivateKey &rsuPrivateKey, const ElGamal::PublicKey &esPublicKey)
    : rsuPublicKey_(rsuPublicKey), rsuPrivateKey_(rsuPrivateKey), esPublicKey_(esPublicKey) {
    initMTable(&mTable_, MAX);
}

void RSU::ReceiveTaskFromVehicle(const std::string &encryptedIdentity, const std::string &encryptedTaskAndNoise, const ElGamal::PublicKey &vehiclePublicKey) {
    currentIdentity_ = ElgamalDecrypt(encryptedIdentity, rsuPrivateKey_);
    currentTask_ = encryptedTaskAndNoise;

    int vehicleID = std::stoi(currentIdentity_);
    vehiclePublicKeys_[vehicleID] = vehiclePublicKey;

    std::string FN;
    std::string currentTime = getCurrentTime();
    FN_Allocation(&mTable_, vehicleID, &FN, &currentTime, availableFNIndexes);

    currentFN_ = FN;
    currentTime_ = currentTime;
}

void RSU::SendTaskToES(ES &es) {
    std::string pseudonymAndTime = currentFN_ + "||" + currentTime_;
    std::string encryptedPseudonymAndTime = ElgamalEncrypt(pseudonymAndTime, esPublicKey_);

    es.ReceiveTask(encryptedPseudonymAndTime, currentTask_);
}

void RSU::ReceiveResponseFromES(const std::string &encryptedResponse) {
    std::string decryptedResponse = ElgamalDecrypt(encryptedResponse, rsuPrivateKey_);

    size_t pos1 = decryptedResponse.find("||");
    std::string FN = decryptedResponse.substr(0, pos1);
    size_t pos2 = decryptedResponse.find("||", pos1 + 2);
    std::string time = decryptedResponse.substr(pos1 + 2, pos2 - pos1 - 2);
    std::string VR = decryptedResponse.substr(pos2 + 2);

    for (int i = 0; i < mTable_.size; ++i) {
        if (mTable_.FNA[i].FN == FN) {
            ANode *node = mTable_.FNA[i].list;
            while (node != nullptr) {
                if (node->ID == std::stoi(currentIdentity_)) {
                    currentResponse_ = ElgamalEncrypt(VR, vehiclePublicKeys_[node->ID]);

                    RemoveTimestampFromMTable(&mTable_, FN, time);
                    SendResponseToVehicle(*(vehicleMap_[node->ID]), currentResponse_);
                    return;
                }
                node = node->next;
            }
        }
    }
    std::cerr << "Matching ID not found for FN: " << FN << " and Time: " << time << std::endl;
}

void RSU::SendResponseToVehicle(Vehicle &vehicle, const std::string &response) {
    vehicle.ReceiveResponseFromRSU(response);
}

CryptoPP::ElGamal::PublicKey RSU::getPublicKey() const {
    return rsuPublicKey_;
}

void RSU::RegisterVehicle(int id, Vehicle &vehicle) {
    vehicleMap_[id] = &vehicle;
}

void RSU::PrintMTable() const {
    for (int i = 0; i < mTable_.size; ++i) {
        std::cout << "FN: " << mTable_.FNA[i].FN << std::endl;
        ANode *node = mTable_.FNA[i].list;
        while (node != nullptr) {
            std::cout << "  ID: " << node->ID << ", Num: " << node->num << ", Time List:";
            TNode *timeNode = node->Tseq;
            while (timeNode != nullptr) {
                std::cout << " " << timeNode->time;
                timeNode = timeNode->next;
            }
            std::cout << std::endl;
            node = node->next;
        }
    }
}
