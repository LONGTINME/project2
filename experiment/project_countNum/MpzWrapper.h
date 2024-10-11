#ifndef MPZ_WRAPPER_H
#define MPZ_WRAPPER_H

#include <gmp.h>

// MpzWrapper 用于封装 mpz_t 以便在 STL 容器中使用
struct MpzWrapper {
    mpz_t value;

    MpzWrapper() {
        mpz_init(value);
    }

    MpzWrapper(const MpzWrapper& other) {
        mpz_init_set(value, other.value);
    }

    MpzWrapper& operator=(const MpzWrapper& other) {
        if (this != &other) {
            mpz_set(value, other.value);
        }
        return *this;
    }

    ~MpzWrapper() {
        mpz_clear(value);
    }
};

#endif // MPZ_WRAPPER_H
