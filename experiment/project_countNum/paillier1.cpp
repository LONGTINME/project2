#include "paillier1.h"
#include <gmp.h>
#include <files.h>
#include <fstream>

extern gmp_randstate_t gmp_rand;
gmp_randstate_t gmp_rand;

void Paillier::KeyGen(unsigned long bitLen)
{
    gmp_randinit_default(gmp_rand);
    mpz_t r;
    mpz_init(r);
    mpz_rrandomb(r, gmp_rand, bitLen); // r <--- rand
    mpz_nextprime(p, r);               // p是大素数
    mpz_set(r, p);
    mpz_nextprime(q, r); // q是大素数

    mpz_mul(n, p, q);       // n = p*q
    mpz_add_ui(g, n, 1);    // g = n+1
    mpz_mul(nsquare, n, n); // nsqaure = n * n;

    mpz_sub_ui(p, p, 1); // p = p-1
    mpz_sub_ui(q, q, 1); // q = q-1
    // mpz_lcm(lambda, p, q);         // lambda = lcm(p-1, q-1)
    mpz_mul(lambda, p, q);
    mpz_invert(lmdInv, lambda, n); // lmdInv = lambda^{-1} mod n

    mpz_clear(r);
}

void Paillier::Encrypt(mpz_t c, mpz_t m, std::ofstream& logfile) const 
{
    

    // 检查明文是否小于 n，Paillier 加密要求明文 m 必须小于 n
    if (mpz_cmp(m, n) >= 0)
    {
        logfile << "Error: m must be less than n" << std::endl;
        throw std::invalid_argument("m must be less than n");
    }

    // 初始化随机数 r
    mpz_t r;
    mpz_init(r);
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // 生成随机数 r (小于 n)
    mpz_urandomm(r, state, n); // r <--- 随机数 mod n
    logfile << "Generated random r: " << mpz_get_str(nullptr, 10, r) << std::endl;

    // Paillier 加密公式: c = (g^m mod n^2) * (r^n mod n^2) mod n^2
    mpz_powm(c, g, m, nsquare); // 计算 g^m mod n^2
    logfile << "g^m mod n^2: " << mpz_get_str(nullptr, 10, c) << std::endl;

    mpz_powm(r, r, n, nsquare); // 计算 r^n mod n^2
    logfile << "r^n mod n^2: " << mpz_get_str(nullptr, 10, r) << std::endl;

    // 乘积操作，并取模 nsquare
    mpz_mul(c, c, r);           // c = (g^m * r^n)
    mpz_mod(c, c, nsquare);     // c = c mod n^2
    logfile << "Final ciphertext: " << mpz_get_str(nullptr, 10, c) << std::endl;

    // 清理
    mpz_clear(r);
    gmp_randclear(state);
}


void Paillier::Decrypt(mpz_t m, mpz_t c)
{
    if (mpz_cmp(c, nsquare) >= 0)
    {
        throw("ciphertext must be less than n^2");
        return;
    }
    mpz_powm(m, c, lambda, nsquare); // c = c^lambda mod n^2
    // m = (c - 1) / n * lambda^(-1) mod n

    mpz_sub_ui(m, m, 1);   // c=c-1
    mpz_fdiv_q(m, m, n);   // c=(c-1)/n
    mpz_mul(m, m, lmdInv); // c=c*lambda^(-1)
    mpz_mod(m, m, n);      // m=c mod n
}

void Paillier::Add(mpz_t res, mpz_t c1, mpz_t c2)
{

    if (mpz_cmp(c1, nsquare) >= 0)
    {
        throw("ciphertext must be less than n^2");
        return;
    }
    if (mpz_cmp(c2, nsquare) >= 0)
    {
        throw("ciphertext must be less than n^2");
        return;
    }
    mpz_mul(res, c1, c2);
    mpz_mod(res, res, nsquare);
}

// 只能是同态标量乘
void Paillier::Mul(mpz_t res, mpz_t c, mpz_t e)
{
    if (mpz_cmp(c, nsquare) >= 0)
    {
        throw("ciphertext must be less than n^2");
        return;
    }
    if (mpz_cmp(e, n) >= 0)
    {
        throw("exponent must be less than n");
    }
    mpz_powm(res, c, e, nsquare);
}