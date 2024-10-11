#ifndef __PAILLIER1_H__
#define __PAILLIER1_H__

#include <gmp.h>
#include <iostream>

class Paillier {
public:
    // 大数变量：p, q 是密钥生成使用的两个大素数；g, n 是公钥；lambda 和 lmdInv 是私钥相关参数
    mpz_t p, q, g, n, nsquare;  // nsquare = n^2
    mpz_t lambda, lmdInv;       // lmdInv = lambda^{-1} mod n

    // 构造函数，初始化所有的 mpz_t 变量
    Paillier() {
        mpz_inits(p, q, g, n, nsquare, lambda, lmdInv, NULL);
    }

    // 深拷贝构造函数
    Paillier(const Paillier& other) {
        mpz_inits(p, q, g, n, nsquare, lambda, lmdInv, NULL);
        mpz_set(n, other.n);
        mpz_set(g, other.g);
        mpz_set(lambda, other.lambda);
        mpz_set(lmdInv, other.lmdInv);
        mpz_set(p, other.p);
        mpz_set(q, other.q);
        mpz_set(nsquare, other.nsquare);
    }

    // 深拷贝赋值运算符
    Paillier& operator=(const Paillier& other) {
        if (this != &other) {
            mpz_set(n, other.n);
            mpz_set(g, other.g);
            mpz_set(lambda, other.lambda);
            mpz_set(lmdInv, other.lmdInv);
            mpz_set(p, other.p);
            mpz_set(q, other.q);
            mpz_set(nsquare, other.nsquare);
        }
        return *this;
    }

    // 析构函数，清理所有的 mpz_t 变量
    ~Paillier() {
        mpz_clears(p, q, g, n, nsquare, lambda, lmdInv, NULL);
        std::cout << "Paillier: Memory release completed." << std::endl;
    }

    // 密钥生成函数，生成 p, q, n, g, lambda, lmdInv，bitLen 是密钥长度
    void KeyGen(unsigned long bitLen);

    // 加密函数，使用公钥 n 和 g 加密明文 m，生成密文 c
    void Encrypt(mpz_t c, mpz_t m, std::ofstream& logfile) const;

    // 解密函数，使用私钥 lambda 和 lmdInv 解密密文 c，恢复明文 m
    void Decrypt(mpz_t m, mpz_t c);

    // 同态加法操作：对两个加密值 c1 和 c2 进行同态加法，结果保存在 res 中
    void Add(mpz_t res, mpz_t c1, mpz_t c2);

    // 同态标量乘法：对加密值 c 和一个明文 e 进行同态乘法，结果保存在 resc 中
    void Mul(mpz_t resc, mpz_t c, mpz_t e);
};

#endif // __PAILLIER1_H__
