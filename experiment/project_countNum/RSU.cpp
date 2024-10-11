#include "RSU.h"
#include "MyElgamal.h"
#include "paillier1.h"
#include <cryptlib.h>
#include <osrng.h>
#include <base64.h>
#include <iostream>
#include <ctime>
#include "CS.h"
#include <gmp.h>
#include "FN_Allocation.h"
#include <files.h>
#include <fstream>

using namespace CryptoPP;


RSU::RSU(const CryptoPP::ElGamal::PublicKey &rsuPublicKey, const CryptoPP::ElGamal::PrivateKey &rsuPrivateKey,
         const CryptoPP::ElGamal::PublicKey &esPublicKey, const Paillier &spPublicKey, RSUType type)
    : rsuPublicKey_(rsuPublicKey), rsuPrivateKey_(rsuPrivateKey), esPublicKey_(esPublicKey),
      spPublicKey_(spPublicKey), type_(type), currentIdx_(0) {
    
    

    try {
        // 初始化 MTable
        initMTable(&mTable_, MAX);
    } catch (const std::bad_alloc &e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return;
    }
}


RSUType RSU::getType() const {
    return type_;
}


std::string mpz_to_string(const mpz_t& mpz_value) {
    char* temp_str = mpz_get_str(nullptr, 10, mpz_value);  
    std::string result(temp_str);
    free(temp_str);  
    return result;
}


std::vector<std::pair<std::string, std::string>> RSU::CountAndEncryptTasks(const CryptoPP::ElGamal::PublicKey& csPublicKey,  std::ofstream& logfile) {
    logfile << "CountAndEncryptTasks started for RSU..." << std::endl;
    logfile.flush();

    std::vector<std::pair<std::string, std::string>> encryptedData;
    std::vector<int> ids;  
    std::vector<int> sums; 

    int ni = 0;  

    
    ANode* item = mTable_.FNA[0].list;
    while (item != nullptr) {
        ni++;  
        ids.push_back(item->ID); 
        int len = 0;  
        TNode* timeNode = item->Tseq;
        while (timeNode != nullptr) {
            len++;
            timeNode = timeNode->next;
        }
        sums.push_back(item->num - len); 

        if (len != 0) {
            item->num = len; 
        } else {
            RemoveNodeFromList(mTable_.FNA[0].list, item);  
        }
        item = item->next;
    }

    logfile << "IDs and sums collected for first list. Total IDs: " << ids.size() << std::endl;
    logfile.flush();

    
    for (int k = 1; k < mTable_.size; ++k) {
        std::vector<int> Lab(ni, 0);  

        ANode* node_k = mTable_.FNA[k].list;
        while (node_k != nullptr) {
            bool matched = false;

            for (int j = 0; j < ni; ++j) {
                if (Lab[j] == 0 && ids[j] == node_k->ID) {
                    int len = 0;
                    TNode* timeNode = node_k->Tseq;
                    while (timeNode != nullptr) {
                        len++;
                        timeNode = timeNode->next;
                    }

                    sums[j] += node_k->num - len;  
                    if (len != 0) {
                        node_k->num = len;  
                    } else {
                        RemoveNodeFromList(mTable_.FNA[k].list, node_k);  
                    }

                    Lab[j] = 1;
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                ni++;  
                ids.push_back(node_k->ID);  
                int len = 0;
                TNode* timeNode = node_k->Tseq;
                while (timeNode != nullptr) {
                    len++;
                    timeNode = timeNode->next;
                }
                sums.push_back(node_k->num - len);  

                if (len != 0) {
                    node_k->num = len;  
                } else {
                    RemoveNodeFromList(mTable_.FNA[k].list, node_k);  
                }
            }

            node_k = node_k->next;
        }
    }

    logfile << "Finished counting tasks for all lists. Total vehicles: " << ids.size() << std::endl;
    logfile.flush();

   
    for (size_t i = 0; i < ids.size(); ++i) {
  
    std::string encryptedID = ElgamalEncrypt(std::to_string(ids[i]), csPublicKey);
    
    mpz_t plaintext, ciphertext;
     mpz_init_set_str(plaintext, std::to_string(sums[i]).c_str(), 10);  
     mpz_init(ciphertext);  



  
    spPublicKey_.Encrypt(ciphertext, plaintext, logfile);  
    

   
    std::string encryptedSum = mpz_to_string(ciphertext);
    encryptedData.emplace_back(encryptedID, encryptedSum);

  

    mpz_clear(plaintext);
    mpz_clear(ciphertext);
}

logfile << "Finished encryption for RSU tasks." << std::endl;
logfile.flush();
    return encryptedData;
}




void RSU::RemoveNodeFromList(ANode*& list, ANode* node) {
    if (list == nullptr || node == nullptr) {
        std::cerr << "Error: Attempt to delete from an empty list or delete a null node." << std::endl;
        return;
    }

    if (list == node) {
      
        list = node->next;
        delete node;
    } else {
        
        ANode* prev = list;
        while (prev->next != nullptr && prev->next != node) {
            prev = prev->next;
        }

        if (prev->next == nullptr) {
          
            std::cerr << "Error: Node not found in the list." << std::endl;
            return;
        }

    
        prev->next = node->next;
        delete node;
    }
}



void RSU::SendDataToCS(CS& cs, const std::vector<std::pair<std::string, std::string>>& encryptedData,std::ofstream& logfile) {
    
    logfile << "Sending encrypted data to CS..." << std::endl;
    logfile.flush();
    std::cout << "Sending encrypted data to CS..." << std::endl;
    if (encryptedData.empty()) {
        std::cout << "No data to send to CS." << std::endl;
    } else {
        std::cout << "Sending " << encryptedData.size() << " encrypted data items to CS." << std::endl;
        for (const auto& item : encryptedData) {
            std::cout << "Encrypted ID: " << item.first << ", Encrypted Sum: " << item.second << std::endl;
        }
    }
    cs.receiveData(encryptedData);  
    std::cout << "Encrypted data sent to CS successfully." << std::endl;
}


void RSU::ReceiveTaskFromVehicle(const std::string &encryptedIdentity, const std::string &encryptedTaskAndNoise, const ElGamal::PublicKey &vehiclePublicKey) {
    currentIdentity_ = ElgamalDecrypt(encryptedIdentity, rsuPrivateKey_);
    currentTask_ = encryptedTaskAndNoise;

    int vehicleID = std::stoi(currentIdentity_);
    vehiclePublicKeys_[vehicleID] = vehiclePublicKey;

    std::string FN;
    std::string currentTime = getCurrentTime();
    FN_Allocation(&mTable_, &currentIdx_, vehicleID, &FN, &currentTime);

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


void RSU::PrintMTable(std::ofstream& logfile) const {
    for (int i = 0; i < mTable_.size; ++i) {
        if (mTable_.FNA[i].list != nullptr) {  
            logfile << "FN: " << mTable_.FNA[i].FN << std::endl;
            ANode *node = mTable_.FNA[i].list;
            while (node != nullptr) {
                logfile << "  ID: " << node->ID << ", Num: " << node->num << ", Time List:";
                TNode *timeNode = node->Tseq;
                while (timeNode != nullptr) {
                    logfile << " " << timeNode->time;
                    timeNode = timeNode->next;
                }
                logfile << std::endl;
                node = node->next;
            }
        }
    }
    logfile.flush();  
}
