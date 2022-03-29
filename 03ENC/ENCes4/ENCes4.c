#include <stdio.h>
#include <string.h>


#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024
#define MAX_ENC_LEN 1000000




void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();



    unsigned char *key; 
    unsigned char *iv;
    int iv_len, key_len;
    unsigned char *plaintext = argv[1];
    unsigned char ciphertext = malloc(sizeof(char) * strlen(plaintext));






    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    printf("key len: ");
    if(!(key_len = EVP_CIPHER_key_length(EVP_chacha20())))
        handle_errors();
    printf("%d\n", key_len);

    key = malloc(sizeof(unsigned char) * EVP_CIPHER_key_length(EVP_chacha20()));

    if(RAND_bytes(key, key_len) != 1){
		handle_errors();
	}


    printf("iv len: ");
    if(!(iv_len = EVP_CIPHER_iv_length(EVP_chacha20())))
        iv = 0;
    else{
        iv = malloc(sizeof(unsigned char) * EVP_CIPHER_iv_length(EVP_chacha20()));
        if(RAND_bytes(iv, iv_len) != 1){
		    handle_errors();
	    }
    }

    printf("%d\n", iv_len);


















    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0;
}