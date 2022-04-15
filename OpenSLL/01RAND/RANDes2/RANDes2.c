#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX 16

void handle_errors(){
	ERR_print_errors_fp(stderr);
	abort();
}

int main(){

    unsigned char key[MAX];
    unsigned char iv[MAX];

    if (RAND_load_file("/dev/random", 64) != 64){
        handle_errors();
    }
    

    if(RAND_priv_bytes(key,MAX) != 1){
        handle_errors();
    }

    if(RAND_priv_bytes(iv,MAX) != 1){
        handle_errors();
    }

    printf("Key generated: ");
		for (int i = 0; i < MAX; i++){
			printf("%02x-", key[i]);
		}
		printf("\n");
    

    printf("IV generated: ");
		for (int i = 0; i < MAX; i++){
			printf("%02x-", iv[i]);
		}
		printf("\n");
    

    return 0;
}