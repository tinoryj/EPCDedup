#!/bin/bash
rm -rf *.mem
rm -rf *.mem.hash
clang++ memdump.cpp -O3 -o memdump -lssl -lcrypto
sudo ./memdump $1 > "$1.mem"