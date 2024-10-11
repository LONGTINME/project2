#include "CS.h"
#include "MyElgamal.h"
#include "SP.h"
#include <iostream>

CS::CS(const CryptoPP::ElGamal::PrivateKey& csPrivateKey)
    : csPrivateKey_(csPrivateKey) {}


void CS::receiveData(const std::vector<std::pair<std::string, std::string>>& encryptedData) {
    for (const auto& [encryptedID, sum] : encryptedData) {
       
        std::string decryptedID = ElgamalDecrypt(encryptedID, csPrivateKey_);

       
        mpz_t sumValue;
        mpz_init(sumValue);
        mpz_set_str(sumValue, sum.c_str(), 10);  

        
        auto it = aggregatedData_.find(decryptedID);
        if (it != aggregatedData_.end()) {
            
            mpz_mul(it->second.value, it->second.value, sumValue);
        } else {
           
            MpzWrapper newSum;
            mpz_set(newSum.value, sumValue); 
            aggregatedData_[decryptedID] = newSum;
        }

        mpz_clear(sumValue);
    }
}


void CS::AggregateAndSendToSP(SP& sp) {
    std::vector<std::pair<std::string, std::string>> aggregatedDataToSend;

    for (const auto& [id, sum] : aggregatedData_) {
        
        char* sumStr = mpz_get_str(nullptr, 10, sum.value);
        aggregatedDataToSend.emplace_back(id, std::string(sumStr));
        free(sumStr); 
    }

    
    sp.receiveData(aggregatedDataToSend);
}

std::map<std::string, MpzWrapper> CS::getAggregatedData() const {
    return aggregatedData_;
}
