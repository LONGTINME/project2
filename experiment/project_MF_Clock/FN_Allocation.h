#ifndef FN_ALLOCATION_H
#define FN_ALLOCATION_H

#include <string>
#include <set>

#define MAX 10

struct TNode {
    std::string time;
    TNode* next;
};

struct ANode {
    int ID;
    int num;
    TNode* Tseq;
    ANode* next;
};

struct MNode {
    std::string FN;
    ANode* list;
};

struct MTable {
    int size;
    MNode FNA[MAX];
};

std::string getCurrentTime();

void FN_Allocation(MTable *MT, int *cur, int id, std::string *FN, std::string *T);

void initRandomSeed();

std::string generateUniqueNumericFN(int numDigits, const std::set<std::string>& existingFNs);

void initMTable(MTable *MT, int max);

void RemoveTimestampFromMTable(MTable *MT, const std::string &FN, const std::string &time);

#endif // FN_ALLOCATION_H
