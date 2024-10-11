#include <gmp.h>
#include <iostream>
#include <fstream>  
#include <filesystem>
#include "paillier1.h"  

void SavePaillierKey(const std::string& filename, Paillier& key) {
    std::cout << "Attempting to save Paillier keys to: " << filename << std::endl;

    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

   
    char* n_str = mpz_get_str(nullptr, 10, key.n);
    char* g_str = mpz_get_str(nullptr, 10, key.g);
    char* lambda_str = mpz_get_str(nullptr, 10, key.lambda);
    char* lmdInv_str = mpz_get_str(nullptr, 10, key.lmdInv);
    char* nsquare_str = mpz_get_str(nullptr, 10, key.nsquare);  

    std::cout << "Saving n: " << n_str << std::endl;
    std::cout << "Saving g: " << g_str << std::endl;
    std::cout << "Saving lambda: " << lambda_str << std::endl;
    std::cout << "Saving lmdInv: " << lmdInv_str << std::endl;
    std::cout << "Saving nsquare: " << nsquare_str << std::endl;  

   
    file << "n: " << n_str << std::endl;
    file << "g: " << g_str << std::endl;
    file << "lambda: " << lambda_str << std::endl;
    file << "lmdInv: " << lmdInv_str << std::endl;
    file << "nsquare: " << nsquare_str << std::endl;  
    free(n_str);
    free(g_str);
    free(lambda_str);
    free(lmdInv_str);
    free(nsquare_str);

    file.close();
    std::cout << "Paillier keys saved to file successfully." << std::endl;
}


int main() {
    std::cout << "Program started..." << std::endl;

    std::string keyDir = "keys";
    
    if (!std::filesystem::exists(keyDir)) {
        std::cout << "Creating directory: " << keyDir << std::endl;
        std::filesystem::create_directory(keyDir);
    }

    
    Paillier spKey;
    std::cout << "Generating Paillier keys..." << std::endl;
    spKey.KeyGen(512);  
    std::cout << "Paillier keys generated." << std::endl;


    SavePaillierKey(keyDir + "/sp_public_private.key", spKey);
    std::cout << "Paillier keys saved." << std::endl;

    std::cout << "Paillier keys generated and saved successfully in 'keys' directory." << std::endl;

  

    std::cout << "Program finished." << std::endl;

    return 0;
}
