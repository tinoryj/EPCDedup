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

void PRINT_BYTE_ARRAY(FILE* file, void* mem, uint32_t len, uint address)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "Address %u\n%u bytes:{\n", address, len);
    
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 16 == 15)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void dump_memory_region(FILE* pMemFile,FILE* pHashFile, unsigned long start_address, long length)
{
    unsigned long address;
    int pageLength = 4096;
    unsigned char page[pageLength];
    fseeko(pMemFile, start_address, SEEK_SET);

    for (address=start_address; address < start_address + length; address += pageLength)
    {
        fread(page, 1, pageLength, pMemFile);
        // write to stdout
        // fwrite(page, 1, pageLength, stderr);
        PRINT_BYTE_ARRAY(stdout, page, pageLength, address);
        fprintf(pHashFile, "Page hash fingreprint is : ");
        hashNode hash;
        SHA256(page, pageLength, hash.hash);
        for (int i = 0; i < SHA256_DIGEST_LENGTH - 1; i++) {
            fprintf(pHashFile, "%x:", hash.hash[i]);
        }
        fprintf(pHashFile, "%x\n", hash.hash[SHA256_DIGEST_LENGTH-1]);
        totalPageNumber++;
        hashList.insert(hash);
    }
}

int main(int argc, char **argv) {

    if (argc == 2 || argc == 4)
    {
        int pid = atoi(argv[1]);
        long ptraceResult = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if (ptraceResult < 0)
        {
            printf("Unable to attach to the pid specified\n");
            return 0;
        }

        char mapsFilename[1024];
        sprintf(mapsFilename, "/proc/%s/maps", argv[1]);
        FILE* pMapsFile = fopen(mapsFilename, "r");
        char memFilename[1024];
        sprintf(memFilename, "/proc/%s/mem", argv[1]);
        FILE* pMemFile = fopen(memFilename, "r");
        char hashFilename[1024];
        sprintf(hashFilename, "%s.mem.hash", argv[1]);
        FILE* pHashFile = fopen(hashFilename, "w");
        char line[256];
        while (fgets(line, 256, pMapsFile) != NULL)
        {
            unsigned long start_address;
            unsigned long end_address;
            sscanf(line, "%08lx-%08lx\n", &start_address, &end_address);
            dump_memory_region(pMemFile,pHashFile, start_address, end_address - start_address);
        }
        fclose(pMapsFile);
        fclose(pMemFile);
        cerr << "Total page number = " << totalPageNumber << endl;
        cerr << "Unique page number = " << hashList.size() << endl;
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    else
    {
        printf("%s <pid>\n", argv[0]);
        exit(0);
    }
}
