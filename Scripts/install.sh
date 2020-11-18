#!/bin/bash
cd ../linux-sgx-driver-sgx_driver_2.11/src/
mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
/sbin/depmod
/sbin/modprobe isgx
cd ..