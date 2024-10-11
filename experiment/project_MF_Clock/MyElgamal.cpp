#include "MyElgamal.h"
#include <iostream>
#include <osrng.h>
#include <elgamal.h>
#include <base64.h>
#include <files.h>

using namespace CryptoPP;

std::string ElgamalEncrypt(const std::string& message, const ElGamal::PublicKey& publicKey) {
    std::cout << "ElgamalEncrypt: Starting encryption with message length: " << message.length() << std::endl;
    AutoSeededRandomPool rng;

    std::string cipher;
    std::string encoded;

    try {
        ElGamal::Encryptor encryptor(publicKey);
        StringSource ss1(message, true, 
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(cipher)
            )
        );

        
        StringSource ss2(cipher, true,
            new Base64Encoder(
                new StringSink(encoded)
            )
        );

        std::cout << "ElgamalEncrypt: Encryption successful. Encoded Cipher: " << encoded << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "ElgamalEncrypt: CryptoPP Exception: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "ElgamalEncrypt: Standard Exception: " << e.what() << std::endl;
        throw;
    }

    return encoded;
}

std::string ElgamalDecrypt(const std::string& encoded, const ElGamal::PrivateKey& privateKey) {
    std::cout << "ElgamalDecrypt: Starting decryption with encoded cipher: " << encoded << std::endl;
    AutoSeededRandomPool rng;

    std::string cipher;
    std::string recovered;

    try {
      
        StringSource ss1(encoded, true,
            new Base64Decoder(
                new StringSink(cipher)
            )
        );

        ElGamal::Decryptor decryptor(privateKey);
        StringSource ss2(cipher, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(recovered)
            )
        );

        std::cout << "ElgamalDecrypt: Decryption successful. Recovered: " << recovered << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "ElgamalDecrypt: CryptoPP Exception: " << e.what() << std::endl;
        throw;
    } catch (const std::exception& e) {
        std::cerr << "ElgamalDecrypt: Standard Exception: " << e.what() << std::endl;
        throw;
    }

    return recovered;
}
