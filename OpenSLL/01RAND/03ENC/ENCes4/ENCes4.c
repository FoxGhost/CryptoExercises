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
    unsigned char ciphertext[MAX_ENC_LEN];
    int update_len = 0;
    int final_len = 0;
    int ciphertext_len = 0;






    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    //create a random key 
    printf("key len: ");
    if(!(key_len = EVP_CIPHER_key_length(EVP_aes_128_cbc())))
        handle_errors();
    printf("%d\n", key_len);

    key = malloc(sizeof(unsigned char) * EVP_CIPHER_key_length(EVP_aes_128_cbc()));

    if(RAND_bytes(key, key_len) != 1){
		handle_errors();
	}

    //create a random iv if needed
    printf("iv len: ");
    if(!(iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc())))
        iv = 0;
    else{
        iv = malloc(sizeof(unsigned char) * EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
        if(RAND_bytes(iv, iv_len) != 1){
		    handle_errors();
	    }
    }

    printf("%d\n", iv_len);

    //ctx initialization
    EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING);
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    //ctx update
    if(!EVP_CipherUpdate(ctx, ciphertext, &update_len, argv[1], strlen(argv[1])))
        handle_errors();

    ciphertext_len+=update_len;
    
    if (!EVP_CipherFinal_ex(ctx, ciphertext+ciphertext_len, &final_len))
        handle_errors();

    
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");














    
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0;
}