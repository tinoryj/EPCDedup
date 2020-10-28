# EPCDedup
Code &amp; reference repository for EPC memory deduplication

## Update Logs

### Memory pages analysis :

| Application      | Total page number       | Unique page number      | Deduplication ratio  | 
| ---------------- | ----------------------- | ----------------------- | -------------------- | 
| frpc             | 2475                    | 2440                    | 1.41%                | 
| Docker host      | 3777654                 | 3568768                 | 5.53%                | 
| snap             | 84642                   | 18661                   | 77.95%               | 
| chrome           | 274745                  | 199111                  | 27.53%               | 
| mongodb          | 3606262                 | 3489657                 | 3.23%                | 
| vscode           | 633605                  | 493202                  | 22.16%               | 
| qv2ray           | 79422                   | 33257                   | 58.13%               | 


### New problems :

* All enclave pages are encrypted with AES-GCM, so they need to be deduplicated in the CPU cache.

## Base Linux SGX Driver

### Version : 
  * Release : 2.11 
  * commit ID : 75bf89f7d6dd4598b9f8148bd6374a407f37105c

### Analysis




## Related Tools & Method

* Memory capture : `memoryCaptureTools/dumpMemory.sh`, read memory for some application.

## Reference

* Memory capture memthod : https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
* Core file generate for any thread : gcore pid

