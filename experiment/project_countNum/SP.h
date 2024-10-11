#ifndef SP_H
#define SP_H

#include <string>
#include <map>
#include <vector>
#include <gmp.h>
#include "paillier1.h"
#include "MpzWrapper.h" // 使用 MpzWrapper 的定义

class SP {
public:
    SP(const Paillier& spPrivateKey);

    void receiveData(const std::vector<std::pair<std::string, std::string>>& encryptedData);
    void calculateCharges(double pricePerTask);

    ~SP(); // 析构函数

private:
    Paillier spPrivateKey_;
    std::map<std::string, MpzWrapper> decryptedData_; // 使用 MpzWrapper 封装 mpz_t
};

#endif // SP_H
