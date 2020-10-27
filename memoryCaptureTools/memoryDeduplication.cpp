#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

using namespace std;

struct hashNode{
    u_char hash[SHA256_DIGEST_LENGTH];
    friend bool operator < (const hashNode& n1, const hashNode& n2)
    {
        return memcmp(n1.hash, n2.hash, SHA256_DIGEST_LENGTH) < 0;
    }

};

set<hashNode> hashList;
uint64_t totalPageNumber = 0;

int main(int argc, char **argv) {


    char memFilename[1024];
    sprintf(memFilename, "%s", argv[1]);
    FILE* pMemFile = fopen(memFilename, "r");
    char hashFilename[1024];
    sprintf(hashFilename, "%s.hash", argv[1]);
    FILE* pHashFile = fopen(hashFilename, "w");

    u_char page[4096];
    while (fgets((char*)page, 4096, pMemFile) != NULL)
    {
        fprintf(pHashFile, "Page hash fingreprint is : ");
        hashNode hash;
        SHA256(page, 4096, hash.hash);
        for (int i = 0; i < SHA256_DIGEST_LENGTH - 1; i++) {
            fprintf(pHashFile, "%x:", hash.hash[i]);
        }
        fprintf(pHashFile, "%x\n", hash.hash[SHA256_DIGEST_LENGTH-1]);
        totalPageNumber++;
        hashList.insert(hash);
    }
    cerr << "Total page number = " << totalPageNumber << endl;
    cerr << "Unique page number = " << hashList.size() << endl;
}
