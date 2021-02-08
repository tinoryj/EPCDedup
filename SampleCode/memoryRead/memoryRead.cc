#include <bits/stdc++.h>
#include <openssl/sha.h>

using namespace std;
#define PAGE_SIZE 4096

void PRINT_BYTE_ARRAY(
    FILE* file, void* mem, uint32_t len)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

bool getOneMemoryPage(unsigned long startAddress){
    int* page = (int*)startAddress;
    cout << "Content first 8 byte = " << endl;
    PRINT_BYTE_ARRAY(stdout, page, 8);
    char hash[SHA256_DIGEST_LENGTH];
    SHA256((u_char*)page, PAGE_SIZE, (u_char*)hash);
    PRINT_BYTE_ARRAY(stdout, hash, SHA256_DIGEST_LENGTH);
}

int main()
{
    unsigned long addressStart = 0x50200000;
    unsigned long addressEnd = 0x55f80000;
    for (int i = 0; i < (addressEnd - addressStart) / PAGE_SIZE;i++){
        cout << "Current page  address = " << addressStart + i * PAGE_SIZE << endl;
        getOneMemoryPage(addressStart + i * PAGE_SIZE);
    }
}