#include "Vehicle.h"
#include "RSU.h"
#include "ES.h"
#include "MyElgamal.h"
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
                std::cout << "Vehicle " << vehicle.getID() << " generating task..." << std::endl;
            }
            vehicle.GenerateTask();

            auto start = std::chrono::high_resolution_clock::now();

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "Vehicle " << vehicle.getID() << " sending task to RSU..." << std::endl;
            }
            vehicle.SendTaskToRSU(rsu);

            {
                std::lock_guard<std::mutex> guard(mtx);
                std::cout << "RSU processing task and sending to ES..." << std::endl;
            }
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


void runExperiment(int totalVehicles, double a, double b, double c, int taskFrequency1, int taskFrequency2, int taskFrequency3, int experimentDuration, std::ofstream& logfile) {
    std::string keyDir = "keys";
    
 
    ElGamal::PublicKey rsuPublicKey, esPublicKey;
    ElGamal::PrivateKey rsuPrivateKey, esPrivateKey;

    LoadPublicKey(keyDir + "/rsu_public.key", rsuPublicKey);
    LoadPrivateKey(keyDir + "/rsu_private.key", rsuPrivateKey);
    LoadPublicKey(keyDir + "/es_public.key", esPublicKey);
    LoadPrivateKey(keyDir + "/es_private.key", esPrivateKey);

    
    RSU rsu(rsuPublicKey, rsuPrivateKey, esPublicKey);
    ES es(esPublicKey, esPrivateKey);

    std::vector<Vehicle> vehicles;

    std::vector<Vehicle>::size_type numVehicles1 = static_cast<std::vector<Vehicle>::size_type>(totalVehicles * a);
    std::vector<Vehicle>::size_type numVehicles2 = static_cast<std::vector<Vehicle>::size_type>(totalVehicles * b);

    
    for (std::vector<Vehicle>::size_type i = 0; i < numVehicles1; ++i) {
        ElGamal::PublicKey vehiclePublicKey;
        ElGamal::PrivateKey vehiclePrivateKey;

        LoadPublicKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_public.key", vehiclePublicKey);
        LoadPrivateKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_private.key", vehiclePrivateKey);

        vehicles.emplace_back(i + 1, rsuPublicKey, esPublicKey, vehiclePublicKey, vehiclePrivateKey);
    }

    for (std::vector<Vehicle>::size_type i = numVehicles1; i < numVehicles1 + numVehicles2; ++i) {
        ElGamal::PublicKey vehiclePublicKey;
        ElGamal::PrivateKey vehiclePrivateKey;

        LoadPublicKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_public.key", vehiclePublicKey);
        LoadPrivateKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_private.key", vehiclePrivateKey);

        vehicles.emplace_back(i + 1, rsuPublicKey, esPublicKey, vehiclePublicKey, vehiclePrivateKey);
    }

    for (std::vector<Vehicle>::size_type i = numVehicles1 + numVehicles2; i < static_cast<std::vector<Vehicle>::size_type>(totalVehicles); ++i) {
        ElGamal::PublicKey vehiclePublicKey;
        ElGamal::PrivateKey vehiclePrivateKey;

        LoadPublicKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_public.key", vehiclePublicKey);
        LoadPrivateKey(keyDir + "/vehicle" + std::to_string(i + 1) + "_private.key", vehiclePrivateKey);

        vehicles.emplace_back(i + 1, rsuPublicKey, esPublicKey, vehiclePublicKey, vehiclePrivateKey);
    }

    for (auto& vehicle : vehicles) {
        rsu.RegisterVehicle(vehicle.getID(), vehicle);
    }

    std::vector<double> times;

    std::vector<std::thread> threads;
    for (std::vector<Vehicle>::size_type i = 0; i < numVehicles1; ++i) {
        threads.emplace_back(vehicleTask, std::ref(vehicles[i]), std::ref(rsu), std::ref(es), taskFrequency1, experimentDuration, std::ref(times));
    }
    for (std::vector<Vehicle>::size_type i = numVehicles1; i < numVehicles1 + numVehicles2; ++i) {
        threads.emplace_back(vehicleTask, std::ref(vehicles[i]), std::ref(rsu), std::ref(es), taskFrequency2, experimentDuration, std::ref(times));
    }
    for (std::vector<Vehicle>::size_type i = numVehicles1 + numVehicles2; i < static_cast<std::vector<Vehicle>::size_type>(totalVehicles); ++i) {
        threads.emplace_back(vehicleTask, std::ref(vehicles[i]), std::ref(rsu), std::ref(es), taskFrequency3, experimentDuration, std::ref(times));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    double totalTime = std::accumulate(times.begin(), times.end(), 0.0);
    double averageTime = totalTime / times.size();

    logfile << "Total Time: " << totalTime << " seconds\n";
    logfile << "Average Time: " << averageTime << " seconds\n";
    
    logfile << "MTable contents at the end of the experiment:" << std::endl;
    std::streambuf* coutBuf = std::cout.rdbuf();
    std::cout.rdbuf(logfile.rdbuf());
    rsu.PrintMTable();
    std::cout.rdbuf(coutBuf);

    // Ensure the logfile is flushed

    logfile.flush();
}

int main() {
    int totalVehicles = 60; // 总车辆数
    double a = 0.6; // 第一类车辆占比
    double b = 0.2; // 第二类车辆占比
    double c = 0.2; // 第三类车辆占比
    int taskFrequency1 = 30; // 第一类车辆的任务频率（秒）
    int taskFrequency2 = 60; // 第二类车辆的任务频率（秒）
    int taskFrequency3 = 90; // 第三类车辆的任务频率（秒）
    int experimentDuration = 300; // 实验总时长（秒）

    std::ofstream logfile("experiment_results.txt");

    if (!logfile.is_open()) {
        std::cerr << "Error opening file for writing." << std::endl;
        return 1;
    }

    logfile << "Starting experiment...\n"; // Add initial log

    runExperiment(totalVehicles, a, b, c, taskFrequency1, taskFrequency2, taskFrequency3, experimentDuration, logfile);

    logfile << "Experiment finished.\n"; // Add final log

    logfile.close();
    return 0;
}
