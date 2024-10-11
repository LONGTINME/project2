#include "Vehicle.h"
#include "RSU.h"
#include "ES.h"
#include "MyElgamal.h"
#include "paillier1.h"  
#include "CS.h"
#include "SP.h"
#include <cryptlib.h>
#include <files.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <numeric>
#include <string>
#include <random>

using namespace CryptoPP;


std::mutex mtx;
std::mutex fileMutex;


const double migrationProbability = 0.2; 


void LoadKey(const std::string& filename, BufferedTransformation& bt) {
    FileSource file(filename.c_str(), true);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPrivateKey(const std::string& filename, ElGamal::PrivateKey& key) {
    ByteQueue queue;
    LoadKey(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const std::string& filename, ElGamal::PublicKey& key) {
    ByteQueue queue;
    LoadKey(filename, queue);
    key.Load(queue);
}

void LoadPaillierPublicKey(const std::string& filename, Paillier& key, std::ofstream& logfile) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    std::string line;
    std::string n_str, g_str, lambda_str, lmdInv_str, nsquare_str;

    while (std::getline(file, line)) {
        if (line.find("n: ") == 0) {
            n_str = line.substr(3);
        } else if (line.find("g: ") == 0) {
            g_str = line.substr(3);
        } else if (line.find("lambda: ") == 0) {
            lambda_str = line.substr(8);
        } else if (line.find("lmdInv: ") == 0) {
            lmdInv_str = line.substr(8);
        } else if (line.find("nsquare: ") == 0) {
            nsquare_str = line.substr(9);
        }
    }

    if (n_str.empty() || g_str.empty() || lambda_str.empty() || lmdInv_str.empty()) {
        std::cerr << "Failed to find required key components in file: " << filename << std::endl;
        return;
    }

    mpz_init_set_str(key.n, n_str.c_str(), 10);
    mpz_init_set_str(key.g, g_str.c_str(), 10);
    mpz_init_set_str(key.lambda, lambda_str.c_str(), 10);
    mpz_init_set_str(key.lmdInv, lmdInv_str.c_str(), 10);
    mpz_init_set_str(key.nsquare, nsquare_str.c_str(), 10);

    file.close();
    logfile << "Loaded Paillier public key n: " << n_str << std::endl;
    logfile << "Loaded Paillier public key g: " << g_str << std::endl;
    logfile.flush();
}


void safeWriteToFile(std::ofstream& logfile, const std::string& message) {
    std::lock_guard<std::mutex> lock(fileMutex);
    logfile << message << std::endl;
    logfile.flush();
}


void vehicleMigration(std::vector<RSU>& rsus, Vehicle& vehicle, std::ofstream& logfile) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);

    if (dis(gen) < migrationProbability) {  
        int newRSUIndex = std::uniform_int_distribution<>(0, rsus.size() - 1)(gen);  
        
        rsus[newRSUIndex].RegisterVehicle(vehicle.getID(), vehicle);  
    }
}


void vehicleTask(Vehicle& vehicle, RSU& rsu, std::vector<RSU>& rsus, ES& es, int taskFrequency, int experimentDuration, std::ofstream& logfile) {
    auto experimentStart = std::chrono::high_resolution_clock::now();
    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = now - experimentStart;

        if (elapsed.count() >= experimentDuration) {
            break;
        }

        try {
            {
                std::lock_guard<std::mutex> guard(mtx);
                
                vehicle.GenerateTask();

            
                vehicle.SendTaskToRSU(rsu);
                rsu.SendTaskToES(es);
                es.SendResponseToRSU(rsu);  
                
               
            }

            vehicleMigration(rsus, vehicle, logfile); 

            std::this_thread::sleep_for(std::chrono::seconds(taskFrequency)); 
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> guard(mtx);
            std::cerr << "Standard Exception: " << e.what() << std::endl;
        }
    }
}


void RSUSendDataToCS(RSU& rsu, CS& cs, std::vector<double>& rsuTimes, const CryptoPP::ElGamal::PublicKey& csPublicKey, const Paillier& spPublicKey, std::ofstream& logfile) {
    auto start = std::chrono::high_resolution_clock::now(); 
    logfile << "RSUSendDataToCS started for RSU..." << std::endl;
    logfile.flush();

  
    logfile << "Calling CountAndEncryptTasks for RSU..." << std::endl;
    std::vector<std::pair<std::string, std::string>> encryptedData = rsu.CountAndEncryptTasks(csPublicKey, logfile);
    safeWriteToFile(logfile, "CountAndEncryptTasks completed.");

    if (encryptedData.empty()) {
        logfile << "No encrypted data generated in RSU." << std::endl;
        std::cout << "No encrypted data generated in RSU." << std::endl;
        logfile.flush();
        return;
    } else {
        logfile << "Encrypted data generated for RSU, sending to CS..." << std::endl;
        std::cout << "Encrypted data generated for RSU, sending to CS..." << std::endl;
        logfile.flush();
    }

    rsu.SendDataToCS(cs, encryptedData, logfile);
    logfile << "Encrypted data successfully sent to CS." << std::endl;
    logfile.flush();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    rsuTimes.push_back(duration.count());

    logfile << "RSU to CS time: " + std::to_string(duration.count()) + " seconds." << std::endl;
    logfile.flush();
}


void CSAggregateAndSendToSP(CS& cs, SP& sp, std::vector<double>& csTimes, std::ofstream& logfile) {
    auto start = std::chrono::high_resolution_clock::now();

    cs.AggregateAndSendToSP(sp);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    csTimes.push_back(duration.count());
    safeWriteToFile(logfile, "CS to SP time: " + std::to_string(duration.count()) + " seconds.");
}


void runVehicleTasks(int totalVehicles, int highCapacityVehicles, int mediumCapacityVehicles, int lowCapacityVehicles, int experimentDuration, std::vector<RSU>& rsus, std::vector<Vehicle>& vehicles, ES& es, std::ofstream& logfile) {
    std::vector<std::thread> threads;

    int vehicleIndex = 0;

    
    for (auto& rsu : rsus) {
        if (rsu.getType() == RSUType::HighCapacity) {
            int vehiclesPerRSU = highCapacityVehicles / std::count_if(rsus.begin(), rsus.end(), [](RSU& rsu) { return rsu.getType() == RSUType::HighCapacity; });
            for (int i = 0; i < vehiclesPerRSU; ++i) {
                threads.emplace_back(vehicleTask, std::ref(vehicles[vehicleIndex]), std::ref(rsu), std::ref(rsus), std::ref(es), 5, experimentDuration, std::ref(logfile));
                ++vehicleIndex;
            }
        }
    }

   
    for (auto& rsu : rsus) {
        if (rsu.getType() == RSUType::MediumCapacity) {
            int vehiclesPerRSU = mediumCapacityVehicles / std::count_if(rsus.begin(), rsus.end(), [](RSU& rsu) { return rsu.getType() == RSUType::MediumCapacity; });
            for (int i = 0; i < vehiclesPerRSU; ++i) {
                threads.emplace_back(vehicleTask, std::ref(vehicles[vehicleIndex]), std::ref(rsu), std::ref(rsus), std::ref(es), 10, experimentDuration, std::ref(logfile));
                ++vehicleIndex;
            }
        }
    }

    
    for (auto& rsu : rsus) {
        if (rsu.getType() == RSUType::LowCapacity) {
            int vehiclesPerRSU = lowCapacityVehicles / std::count_if(rsus.begin(), rsus.end(), [](RSU& rsu) { return rsu.getType() == RSUType::LowCapacity; });
            for (int i = 0; i < vehiclesPerRSU; ++i) {
                threads.emplace_back(vehicleTask, std::ref(vehicles[vehicleIndex]), std::ref(rsu), std::ref(rsus), std::ref(es), 15, experimentDuration, std::ref(logfile));
                ++vehicleIndex;
            }
        }
    }

    
    for (auto& thread : threads) {
        thread.join();
    }
}


void processAndSendData(std::vector<RSU>& rsus, CS& cs, SP& sp, const ElGamal::PublicKey& csPublicKey, const Paillier& spPublicKey, std::ofstream& logfile) {
    std::vector<double> rsuTimes, csTimes;

    safeWriteToFile(logfile, "RSU to CS Times:");
    for (auto& rsu : rsus) {
        RSUSendDataToCS(rsu, cs, rsuTimes, csPublicKey, spPublicKey, logfile);
    }

    safeWriteToFile(logfile, "CS to SP Times:");
    CSAggregateAndSendToSP(cs, sp, csTimes, logfile);

    double totalRSUTime = std::accumulate(rsuTimes.begin(), rsuTimes.end(), 0.0);
    double avgRSUTime = totalRSUTime / rsuTimes.size();
    safeWriteToFile(logfile, "Total RSU to CS Time: " + std::to_string(totalRSUTime) + " seconds");
    safeWriteToFile(logfile, "Average RSU to CS Time: " + std::to_string(avgRSUTime) + " seconds");

    double totalCSTime = std::accumulate(csTimes.begin(), csTimes.end(), 0.0);
    double avgCSTime = totalCSTime / csTimes.size();
    safeWriteToFile(logfile, "Total CS to SP Time: " + std::to_string(totalCSTime) + " seconds");
    safeWriteToFile(logfile, "Average CS to SP Time: " + std::to_string(avgCSTime) + " seconds");
}

int main() {
    int totalVehicles =300;
    int experimentDuration = 30;
    std::string keyDir = "keys";

    std::ofstream logfile("experiment_results.txt");
    if (!logfile.is_open()) {
        std::cerr << "Error opening file for writing." << std::endl;
        return 1;
    }

    ElGamal::PublicKey esPublicKey, csPublicKey;
    ElGamal::PrivateKey esPrivateKey, csPrivateKey;
    LoadPublicKey(keyDir + "/es_public.key", esPublicKey);
    LoadPrivateKey(keyDir + "/es_private.key", esPrivateKey);
    LoadPublicKey(keyDir + "/cs_public.key", csPublicKey);
    LoadPrivateKey(keyDir + "/cs_private.key", csPrivateKey);

    Paillier spPublicKey;
    LoadPaillierPublicKey(keyDir + "/sp_public_private.key", spPublicKey, logfile);

    
    ES es(esPublicKey, esPrivateKey);
    CS cs(csPrivateKey);
    SP sp(spPublicKey);

    
    int numberOfRSUs;
    std::cout << "Enter the number of RSUs: ";
    std::cin >> numberOfRSUs;

    float highCapacityRatio, mediumCapacityRatio, lowCapacityRatio;
    std::cout << "Enter the percentage of High Capacity RSUs (0-1): ";
    std::cin >> highCapacityRatio;
    std::cout << "Enter the percentage of Medium Capacity RSUs (0-1): ";
    std::cin >> mediumCapacityRatio;
    std::cout << "Enter the percentage of Low Capacity RSUs (0-1): ";
    std::cin >> lowCapacityRatio;

    int highCapacityCount = numberOfRSUs * highCapacityRatio;
    int mediumCapacityCount = numberOfRSUs * mediumCapacityRatio;
    int lowCapacityCount = numberOfRSUs - highCapacityCount - mediumCapacityCount;

    std::vector<RSU> rsus;
    for (int i = 0; i < highCapacityCount; ++i) {
        ElGamal::PublicKey rsuPublicKey;
        ElGamal::PrivateKey rsuPrivateKey;
        LoadPublicKey(keyDir + "/rsu" + std::to_string(i + 1) + "_public.key", rsuPublicKey);
        LoadPrivateKey(keyDir + "/rsu" + std::to_string(i + 1) + "_private.key", rsuPrivateKey);
        rsus.emplace_back(rsuPublicKey, rsuPrivateKey, esPublicKey, spPublicKey, RSUType::HighCapacity);
    }

    for (int i = highCapacityCount; i < highCapacityCount + mediumCapacityCount; ++i) {
        ElGamal::PublicKey rsuPublicKey;
        ElGamal::PrivateKey rsuPrivateKey;
        LoadPublicKey(keyDir + "/rsu" + std::to_string(i + 1) + "_public.key", rsuPublicKey);
        LoadPrivateKey(keyDir + "/rsu" + std::to_string(i + 1) + "_private.key", rsuPrivateKey);
        rsus.emplace_back(rsuPublicKey, rsuPrivateKey, esPublicKey, spPublicKey, RSUType::MediumCapacity);
    }

    for (int i = highCapacityCount + mediumCapacityCount; i < numberOfRSUs; ++i) {
        ElGamal::PublicKey rsuPublicKey;
        ElGamal::PrivateKey rsuPrivateKey;
        LoadPublicKey(keyDir + "/rsu" + std::to_string(i + 1) + "_public.key", rsuPublicKey);
        LoadPrivateKey(keyDir + "/rsu" + std::to_string(i + 1) + "_private.key", rsuPrivateKey);
        rsus.emplace_back(rsuPublicKey, rsuPrivateKey, esPublicKey, spPublicKey, RSUType::LowCapacity);
    }

    
    int highCapacityVehicles = totalVehicles * 0.33;
    int mediumCapacityVehicles = totalVehicles * 0.33;
    int lowCapacityVehicles = totalVehicles * 0.33;

    std::vector<Vehicle> vehicles;
    for (int i = 0; i < totalVehicles; ++i) {
        ElGamal::PublicKey vehiclePublicKey;
        ElGamal::PrivateKey vehiclePrivateKey;
        LoadPublicKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_public.key", vehiclePublicKey);
        LoadPrivateKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_private.key", vehiclePrivateKey);
        vehicles.emplace_back(i + 1, rsus[0].getPublicKey(), esPublicKey, vehiclePublicKey, vehiclePrivateKey);
    }

    
    for (auto& rsu : rsus) {
        for (auto& vehicle : vehicles) {
            rsu.RegisterVehicle(vehicle.getID(), vehicle);
        }
    }

    
    safeWriteToFile(logfile, "Starting vehicle tasks...");
    runVehicleTasks(totalVehicles, highCapacityVehicles, mediumCapacityVehicles, lowCapacityVehicles, experimentDuration, rsus, vehicles, es, logfile);

    
    safeWriteToFile(logfile, "Processing data and sending to CS and SP...");
    processAndSendData(rsus, cs, sp, csPublicKey, spPublicKey, logfile);

    

    safeWriteToFile(logfile, "Experiment finished.");
    logfile.close();
    return 0;
}
