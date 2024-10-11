#ifndef CS_H
#define CS_H

#include <string>
#include <vector>
#include <map>
#include <gmp.h>
#include "MyElgamal.h"
#include "paillier1.h"
#include "MpzWrapper.h" 
#include "SP.h"

class CS {
public:
    CS(const CryptoPP::ElGamal::PrivateKey& csPrivateKey);

  
    void receiveData(const std::vector<std::pair<std::string, std::string>>& encryptedData);
    
   
    void AggregateAndSendToSP(SP& sp);

   
    std::map<std::string, MpzWrapper> getAggregatedData() const;

private:
    CryptoPP::ElGamal::PrivateKey csPrivateKey_;
    std::map<std::string, MpzWrapper> aggregatedData_;
};

#endif // CS_H
