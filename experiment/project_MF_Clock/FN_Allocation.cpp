#include "FN_Allocation.h"
#include <ctime>
#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>
#include <set>

std::string getCurrentTime() {
    auto now = std::time(nullptr);
    std::string timeString = std::ctime(&now);
    if (!timeString.empty() && timeString[timeString.length() - 1] == '\n') {
        timeString.erase(timeString.length() - 1);
    }
    return timeString;
}

void FN_Allocation(MTable *MT, int *cur, int id, std::string *FN, std::string *T) {
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
    
    
    ANode *newNode = new ANode;
    newNode->ID = id;
    newNode->num = 1;
    TNode *newTNode = new TNode;
    newTNode->time = *T;
    newTNode->next = nullptr;
    newNode->Tseq = newTNode;
    newNode->next = MT->FNA[*cur].list;
    MT->FNA[*cur].list = newNode;
    *FN = MT->FNA[*cur].FN;
    
    *cur = (*cur + 1) % MT->size;
    std::cout << "New ANode created with ID: " << id << " and FN: " << *FN << std::endl;
    std::cout << "New TNode added with time: " << *T << std::endl;
    std::cout << "FN_Allocation completed. Current index is now: " << *cur << std::endl;
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
    (*MT).size = max;
    std::set<std::string> existingFNs;
    for (int i = 0; i < max; ++i) {
        std::string newFN = generateUniqueNumericFN(12, existingFNs);
        (*MT).FNA[i].FN = newFN;
        existingFNs.insert(newFN);
        (*MT).FNA[i].list = nullptr;
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
