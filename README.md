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


### New problems & Solutions:

* All enclave pages are encrypted with AES-GCM, so they need to be deduplicated in the CPU cache.
  * Deduplication inside CPU cache (compute plaintext page fingreprint for each page for deduplication).
  * Modify AES-GCM encrypt counter:
    * Use enclave ID as the counter to support deduplication inside each enclave.
    * Use page hash as the counter to support deduplication between pages with same content.
* The pages after deduplication need to retain the support for permissions management (the same content but different permissions pages may appear).
  * Modify `sgx_pageinfo` data structure in `sgx_arch.h`, use some additional flags to record different permissions.


## Base Linux SGX Driver

### Version : 
  * Release : 2.11 
  * commit ID : 75bf89f7d6dd4598b9f8148bd6374a407f37105c

### Reference : 

* [Intel Instruction Set Guide](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
* [Intel SGX-1 Instruction](https://www.eit.lth.se/fileadmin/eit/courses/eitn50/Literature/hasp-2013-innovative-instructions-and-software-model-for-isolated-execution.pdf)
* [Intel SGX-2 Instruction](https://caslab.csl.yale.edu/workshops/hasp2016/HASP16-16.pdf)

### Analysis

#### Pages

* Page type:

```c++
enum sgx_page_type {
	SGX_PAGE_TYPE_SECS	= 0x00, // Meta data for each enclave
	SGX_PAGE_TYPE_TCS	= 0x01, // Meta data for each thread
	SGX_PAGE_TYPE_REG	= 0x02, // The general memory allocated by the system
	SGX_PAGE_TYPE_VA	= 0x03, // Version Array of evicted pages
	SGX_PAGE_TYPE_TRIM	= 0x04, // remove a page from the enclave and reclaim the linear address for future use
};
```

* 


<!-- | Functions family | Functions        | Description             | Define location         | Realization position | 
| ---------------- | ---------------- | ----------------------- | ----------------------- | -------------------- | 
| ENCLS ()         | encls            | Add a regular read/write accessible page of zeros to an already initialized enclave |                     |                |  -->



## Related Tools & Method

* Memory capture : `memoryCaptureTools/dumpMemory.sh`, read memory for some application.

## Reference

* Memory capture memthod : https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
* Core file generate for any thread : gcore pid

