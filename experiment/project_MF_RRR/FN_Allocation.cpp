#include "FN_Allocation.h"
#include <ctime>
#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>
#include <set>
#include <iomanip>
#include <chrono>
#include <vector>
#include <algorithm>
#include <random>

std::string getCurrentTime() {
    using namespace std::chrono;
    
    
    auto now = system_clock::now();
    auto now_ms = time_point_cast<milliseconds>(now);
    auto epoch = now_ms.time_since_epoch();
    auto value = duration_cast<milliseconds>(epoch);
    
   
    std::time_t now_time_t = system_clock::to_time_t(now);
    std::tm now_tm = *std::localtime(&now_time_t);

    std::ostringstream oss;
    oss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << (value.count() % 1000);

    std::string timeString = oss.str();

    return timeString;
}

void FN_Allocation(MTable *MT, int id, std::string *FN, std::string *T, std::vector<int> &availableFNIndexes) {
    std::cout << "Inside FN_Allocation..." << std::endl;
    
    
    for (int i = 0; i < MT->size; ++i) {
        ANode *p = MT->FNA[i].list;
        while (p != nullptr) {
            if (p->ID == id) {
                
                std::cout << "ID found in MTable, adding new TNode..." << std::endl;
                TNode *TN = new TNode;
                TN->time = *T;
                TN->next = p->Tseq;
                p->Tseq = TN;
                p->num += 1;
                std::cout << "New TNode added with time: " << *T << std::endl;
                
                *FN = MT->FNA[i].FN;
                return;
            }
            p = p->next;
        }
    }
    
   
    if (availableFNIndexes.empty()) {
        for (int i = 0; i < MT->size; ++i) {
            availableFNIndexes.push_back(i);
        }
        std::shuffle(availableFNIndexes.begin(), availableFNIndexes.end(), std::mt19937{std::random_device{}()});
    }
    
    int fnIndex = availableFNIndexes.back();
    availableFNIndexes.pop_back();

    ANode *newNode = new ANode;
    newNode->ID = id;
    newNode->num = 1;
    TNode *newTNode = new TNode;
    newTNode->time = *T;
    newTNode->next = nullptr;
    newNode->Tseq = newTNode;
    newNode->next = MT->FNA[fnIndex].list;
    MT->FNA[fnIndex].list = newNode;
    *FN = MT->FNA[fnIndex].FN;
    
    std::cout << "New ANode created with ID: " << id << " and FN: " << *FN << std::endl;
    std::cout << "New TNode added with time: " << *T << std::endl;
    std::cout << "FN_Allocation completed. Current FN index is now: " << fnIndex << std::endl;
}

void initRandomSeed() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
}

std::string generateUniqueNumericFN(int numDigits, const std::set<std::string>& existingFNs) {
    std::ostringstream oss;
    bool unique = false;

    while (!unique) {
        oss.str("");
        for (int i = 0; i < numDigits; ++i) {
            if (i == 0) {
                oss << (std::rand() % 9 + 1); 
            } else {
                oss << (std::rand() % 10); 
            }
        }
        std::string newFN = oss.str();
        if (existingFNs.find(newFN) == existingFNs.end()) {
            return newFN;
        }
    }

    return "";
}

void initMTable(MTable *MT, int max) {
    MT->size = max;
    std::set<std::string> existingFNs;
    for (int i = 0; i < max; ++i) {
        std::string newFN = generateUniqueNumericFN(12, existingFNs);
        MT->FNA[i].FN = newFN;
        existingFNs.insert(newFN);
        MT->FNA[i].list = nullptr;
        std::cout << "MTable initialized with " << newFN  << std::endl;
    }
    std::cout << "MTable initialized with " << max << " entries." << std::endl;
}

void RemoveTimestampFromMTable(MTable *MT, const std::string &FN, const std::string &time) {
    for (int i = 0; i < MT->size; ++i) {
        if (MT->FNA[i].FN == FN) {
            ANode *currentANode = MT->FNA[i].list;
            while (currentANode != nullptr) {
                TNode *prevTNode = nullptr;
                TNode *currentTNode = currentANode->Tseq;
                while (currentTNode != nullptr) {
                    if (currentTNode->time == time) {
                        if (prevTNode == nullptr) {
                            currentANode->Tseq = currentTNode->next;
                        } else {
                            prevTNode->next = currentTNode->next;
                        }
                        delete currentTNode;
                        std::cout << "Timestamp " << time << " removed from MTable." << std::endl;
                        return;
                    }
                    prevTNode = currentTNode;
                    currentTNode = currentTNode->next;
                }
                currentANode = currentANode->next;
            }
        }
    }
    std::cerr << "Timestamp " << time << " not found in MTable." << std::endl;
}
