#include "SP.h"
#include <iostream>
#include "paillier1.h"


SP::SP(const Paillier& spPrivateKey)
    : spPrivateKey_(spPrivateKey) {}


void SP::receiveData(const std::vector<std::pair<std::string, std::string>>& encryptedData) {
    for (const auto& pair : encryptedData) {
        std::string id = pair.first;
        std::string encryptedSum = pair.second;

        mpz_t ciphertext, plaintext;
        mpz_init(ciphertext);
        mpz_set_str(ciphertext, encryptedSum.c_str(), 10);  
        mpz_init(plaintext);

        
        spPrivateKey_.Decrypt(plaintext, ciphertext);

       
        if (decryptedData_.find(id) == decryptedData_.end()) {
            decryptedData_[id] = MpzWrapper();  
        }

        
        mpz_add(decryptedData_[id].value, decryptedData_[id].value, plaintext);

        
        mpz_clear(ciphertext);
        mpz_clear(plaintext);
    }
}


void SP::calculateCharges(double pricePerTask) {
    for (const auto& pair : decryptedData_) {
        std::string id = pair.first;
        const mpz_t& sum = pair.second.value;

        mpz_t totalCost;
        mpz_init(totalCost);

        
        mpz_mul_ui(totalCost, sum, static_cast<unsigned long>(pricePerTask));

        std::cout << "ID: " << id << ", Total Cost: ";
        mpz_out_str(stdout, 10, totalCost);
        std::cout << std::endl;

        mpz_clear(totalCost);
    }
}


SP::~SP() {
    
}
