#include "Vehicle.h"
#include "RSU.h"
#include "MyElgamal.h"
#include <cryptlib.h>
#include <osrng.h>
#include <secblock.h>
#include <base64.h>
#include <iostream>

using namespace CryptoPP;

Vehicle::Vehicle(int id, const ElGamal::PublicKey &rsuPublicKey, const ElGamal::PublicKey &esPublicKey, const ElGamal::PublicKey &vehiclePublicKey, const ElGamal::PrivateKey &privateKey)
    : id_(id), taskCounter_(0), rsuPublicKey_(rsuPublicKey), esPublicKey_(esPublicKey), vehiclePublicKey_(vehiclePublicKey), privateKey_(privateKey) {}

void Vehicle::GenerateTask() {
    taskCounter_++;
    currentTask_ = "task_data_" + std::to_string(id_) + "_" + std::to_string(taskCounter_);
    randomNoise_ = "random_noise_" + std::to_string(id_) + "_" + std::to_string(taskCounter_);
    std::cout << "Generated task: " << currentTask_ << " || " << randomNoise_ << std::endl;
}

void Vehicle::SendTaskToRSU(RSU &rsu) {
    std::cout << "Encrypting identity and task..." << std::endl;

    std::string identity = std::to_string(id_);
    std::string encryptedIdentity = ElgamalEncrypt(identity, rsu.getPublicKey());

    std::string taskAndNoise = currentTask_ + "||" + randomNoise_;
    std::string encryptedTaskAndNoise = ElgamalEncrypt(taskAndNoise, esPublicKey_);

    std::cout << "Sending encrypted task and identity to RSU" << std::endl;
    rsu.ReceiveTaskFromVehicle(encryptedIdentity, encryptedTaskAndNoise, getPublicKey());
}

void Vehicle::ReceiveResponseFromRSU(const std::string &encryptedResponse) {
    try {
        std::cout << "Decrypting response from RSU..." << std::endl;
        std::string decryptedResponse = ElgamalDecrypt(encryptedResponse, privateKey_);

        std::cout << "Decrypted response from RSU: " << decryptedResponse << std::endl;

        size_t delimiterPos = decryptedResponse.find("||");
        if (delimiterPos != std::string::npos) {
            std::string FN = decryptedResponse.substr(0, delimiterPos);
            std::string VR = decryptedResponse.substr(delimiterPos + 2);

            std::string originalR = RemoveNoise(VR, randomNoise_);
            std::cout << "Received response: " << originalR << std::endl;
        } else {
            throw std::runtime_error("Invalid response format");
        }
    } catch (const CryptoPP::Exception &e) {
        std::cerr << "Error decrypting response: " << e.what() << std::endl;
    }
}

std::string Vehicle::RemoveNoise(const std::string &VR, const std::string &noise) {
    return VR; 
}

ElGamal::PublicKey Vehicle::getPublicKey() const {
    return vehiclePublicKey_;
}

int Vehicle::getID() const {
    return id_;
}
