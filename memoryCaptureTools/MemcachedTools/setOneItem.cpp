#include <iostream>
#include <fstream>
#include <string.h>
#include <libmemcached/memcached.h>
// compile with -lmemcached -lpthread
using namespace std;

int main(int argc, char *argv[])
{
    memcached_st *client = NULL;
    memcached_return cache_return;
    memcached_server_st *server = NULL;
    
    client = memcached_create(NULL);
    server = memcached_server_list_append(server, "127.0.0.1", 11211, &cache_return);//管理中心，单击“NoSQL高速存储”，在NoSQL高速存储“管理视图”，可以看到系统分配的IP:Port
    cache_return = memcached_server_push(client, server);
    
    if(MEMCACHED_SUCCESS != cache_return){
        cout<<"memcached server push failed! cache return:"<<cache_return<<endl;
        return -1;
    }
    
    string key(argv[1]);
    char buffer[1024 * 1024];
    fstream in(argv[2]);
    if (!in.is_open()){ 
        cout << "Error opening file"; 
        return -1; 
    }
    in>>buffer;
    string val(buffer);
    size_t key_len = key.length();
    size_t val_len = val.length();
    int expiration = 0;
    uint32_t flags = 0;
    cache_return = memcached_set(client, key.c_str(), key_len, val.c_str(), val_len, expiration, flags);
    if(MEMCACHED_SUCCESS == cache_return){
        cout<<"set success"<<endl;
    }else{
        cout<<"set failed! cache return:"<<cache_return<<endl;
    }
    return 0;
}