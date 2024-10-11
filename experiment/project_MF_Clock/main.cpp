#include "Vehicle.h"
#include "RSU.h"
#include "ES.h"
#include "MyElgamal.h"
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <thread>
#include <mutex>
#include <fstream>

using namespace CryptoPP;

std::mutex mtx; 

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

void vehicleTask(Vehicle& vehicle, RSU& rsu, ES& es, int taskFrequency, int experimentDuration, std::vector<double>& times) {
    auto experimentStart = std::chrono::high_resolution_clock::now(); // 记录实验开始时间

    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = now - experimentStart;

        if (elapsed.count() >= experimentDuration) {
            break; 
        }

        try {
            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "Vehicle " << vehicle.getID() << " generating task..." << std::endl;
            }
            vehicle.GenerateTask();

            auto start = std::chrono::high_resolution_clock::now(); // 记录开始时间

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "Vehicle " << vehicle.getID() << " sending task to RSU..." << std::endl;
            }
             std::string encryptedIdentity;
            std::string encryptedTaskAndNoise;
             vehicle.PrepareDataForRSU(encryptedIdentity, encryptedTaskAndNoise);

            vehicle.SendTaskToRSU(rsu);

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "RSU processing task and sending to ES..." << std::endl;
            }
           
             std::string encryptedPseudonymAndTime;
             std::string encryptedTask;

              
             rsu.PrepareDataForES(encryptedPseudonymAndTime, encryptedTask);
            rsu.SendTaskToES(es);

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "ES processing task and sending response to RSU..." << std::endl;
            }
            es.SendResponseToRSU(rsu);

            auto end = std::chrono::high_resolution_clock::now(); 
            std::chrono::duration<double> duration = end - start;

            {
                std::lock_guard<std::mutex> guard(mtx);
                times.push_back(duration.count());
            }

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "RSU sending response to vehicle " << vehicle.getID() << "..." << std::endl;
                std::cout << "Vehicle " << vehicle.getID() << " received response successfully." << std::endl;
            }

            std::this_thread::sleep_for(std::chrono::seconds(taskFrequency)); 
           
            now = std::chrono::high_resolution_clock::now();
            elapsed = now - experimentStart;
            if (elapsed.count() >= experimentDuration) {
                break; 
            }
        } catch (const CryptoPP::Exception &e) {
            std::lock_guard<std::mutex> guard(mtx);
            std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
        } catch (const std::exception &e) {
            std::lock_guard<std::mutex> guard(mtx);
            std::cerr << "Standard Exception: " << e.what() << std::endl;
        } catch (...) {
            std::lock_guard<std::mutex> guard(mtx);
            std::cerr << "Unknown Exception occurred!" << std::endl;
        }
    }
}

void runExperiment(int numVehicles, int taskFrequency, int experimentDuration, RSU& rsu, std::ofstream& logfile) {
    std::string keyDir = "keys";
    {
        std::lock_guard<std::mutex> guard(mtx);
        std::cout << "Initializing keys..." << std::endl;
    }

    ElGamal::PublicKey rsuPublicKey, esPublicKey;
    ElGamal::PrivateKey rsuPrivateKey, esPrivateKey;

    LoadPublicKey(keyDir + "/rsu_public.key", rsuPublicKey);
    LoadPrivateKey(keyDir + "/rsu_private.key", rsuPrivateKey);
    LoadPublicKey(keyDir + "/es_public.key", esPublicKey);
    LoadPrivateKey(keyDir + "/es_private.key", esPrivateKey);

    std::vector<Vehicle> vehicles;

   
    for (int i = 1; i <= numVehicles; ++i) {
        ElGamal::PublicKey vehiclePublicKey;
        ElGamal::PrivateKey vehiclePrivateKey;

        LoadPublicKey(keyDir + "/vehicle" + std::to_string(i) + "_public.key", vehiclePublicKey);
        LoadPrivateKey(keyDir + "/vehicle" + std::to_string(i) + "_private.key", vehiclePrivateKey);

        vehicles.emplace_back(i, rsuPublicKey, esPublicKey, vehiclePublicKey, vehiclePrivateKey);
    }

    {
        std::lock_guard<std::mutex> guard(mtx);
        std::cout << "Keys loaded successfully." << std::endl;
    }

    ES es(esPublicKey, esPrivateKey);

    for (auto& vehicle : vehicles) {
        rsu.RegisterVehicle(vehicle.getID(), vehicle);
    }

    std::vector<double> times; 

    std::vector<std::thread> threads;
    for (auto& vehicle : vehicles) {
        threads.emplace_back(vehicleTask, std::ref(vehicle), std::ref(rsu), std::ref(es), taskFrequency, experimentDuration, std::ref(times));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    
    double averageTime = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    {
        std::lock_guard<std::mutex> guard(mtx);
        std::cout << "Number of vehicles: " << numVehicles << ", Task frequency: " << taskFrequency << " seconds" << std::endl;
        std::cout << "Average time per task: " << averageTime << " seconds" << std::endl;
        
        
        logfile << "Number of vehicles: " << numVehicles << ", Task frequency: " << taskFrequency << " seconds" << std::endl;
        logfile << "Average time per task: " << averageTime << " seconds" << std::endl;
    }

    
    {
        std::lock_guard<std::mutex> guard(mtx);
        std::cout << "MTable contents at the end of the experiment:" << std::endl;
        rsu.PrintMTable();
        
        
        std::streambuf* coutBuf = std::cout.rdbuf();
        std::cout.rdbuf(logfile.rdbuf());
        rsu.PrintMTable();
        std::cout.rdbuf(coutBuf);
    }
}

int main() {
    
    std::ofstream logfile("experiment_results.log");
    if (!logfile.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
        return 1;
    }

   
    std::cout << "Logging to file: experiment_results.log" << std::endl;

   
      std::vector<int> numVehicles = {30}; 
    std::vector<int> taskFrequencies = {60}; 
    int experimentDuration = 300; 

    // 初始化RSU
    std::string keyDir = "keys";
    ElGamal::PublicKey rsuPublicKey, esPublicKey;
    ElGamal::PrivateKey rsuPrivateKey, esPrivateKey;

    LoadPublicKey(keyDir + "/rsu_public.key", rsuPublicKey);
    LoadPrivateKey(keyDir + "/rsu_private.key", rsuPrivateKey);
    LoadPublicKey(keyDir + "/es_public.key", esPublicKey);
    LoadPrivateKey(keyDir + "/es_private.key", esPrivateKey);

    RSU rsu(rsuPublicKey, rsuPrivateKey, esPublicKey);

    // 运行实验
    for (int nv : numVehicles) {
        for (int tf : taskFrequencies) {
            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "Running experiment with " << nv << " vehicles and " << tf << " seconds task frequency for " << experimentDuration << " seconds." << std::endl;
                logfile << "Running experiment with " << nv << " vehicles and " << tf << " seconds task frequency for " << experimentDuration << " seconds." << std::endl;
            }
            runExperiment(nv, tf, experimentDuration, rsu, logfile);
        }
    }

    logfile.close();
    return 0;
}
