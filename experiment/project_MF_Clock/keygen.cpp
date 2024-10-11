#include <elgamal.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <iostream>
#include <string>
#include <filesystem>

using namespace CryptoPP;

void SaveKey(const std::string& filename, const BufferedTransformation& bt) {
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePrivateKey(const std::string& filename, const ElGamalKeys::PrivateKey& key) {
    ByteQueue queue;
    key.Save(queue);
    SaveKey(filename, queue);
}

void SavePublicKey(const std::string& filename, const ElGamalKeys::PublicKey& key) {
    ByteQueue queue;
    key.Save(queue);
    SaveKey(filename, queue);
}

int main() {
    AutoSeededRandomPool rnd;

    std::string keyDir = "keys";
    std::filesystem::create_directory(keyDir);

    // 设置生成车辆密钥对的数量
    int numVehicles = 100; // 例如生成100辆车的密钥

    // 生成车辆密钥对
    for (int i = 1; i <= numVehicles; ++i) {
        ElGamalKeys::PrivateKey vehiclePrivateKey;
        vehiclePrivateKey.Initialize(rnd, 512);
        ElGamalKeys::PublicKey vehiclePublicKey;
        vehiclePrivateKey.MakePublicKey(vehiclePublicKey);

        SavePrivateKey(keyDir + "/vehicle" + std::to_string(i) + "_private.key", vehiclePrivateKey);
        SavePublicKey(keyDir + "/vehicle" + std::to_string(i) + "_public.key", vehiclePublicKey);
    }

    // 生成 RSU 密钥对
    ElGamalKeys::PrivateKey rsuPrivateKey;
    rsuPrivateKey.Initialize(rnd, 512);
    ElGamalKeys::PublicKey rsuPublicKey;
    rsuPrivateKey.MakePublicKey(rsuPublicKey);

    SavePrivateKey(keyDir + "/rsu_private.key", rsuPrivateKey);
    SavePublicKey(keyDir + "/rsu_public.key", rsuPublicKey);

    // 生成 ES 密钥对
    ElGamalKeys::PrivateKey esPrivateKey;
    esPrivateKey.Initialize(rnd, 512);
    ElGamalKeys::PublicKey esPublicKey;
    esPrivateKey.MakePublicKey(esPublicKey);

    SavePrivateKey(keyDir + "/es_private.key", esPrivateKey);
    SavePublicKey(keyDir + "/es_public.key", esPublicKey);

    std::cout << "Keys generated and saved successfully in 'keys' directory." << std::endl;

    return 0;
}
