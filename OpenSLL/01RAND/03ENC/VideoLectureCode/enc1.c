#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();//check null

    unsigned char key[] = "123456789abcdef";//ascii  char 
    unsigned char iv[] = "abcdef123456789";//ascii char

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char plaintext[] = "This variable contains the data to encrypt";//44bytes
    
    unsigned char ciphertext[48];//c'è padding

    int lenght;
    int ciphertext_len = 0;

    if(!EVP_CipherUpdate(ctx, ciphertext, &lenght, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After update: %d\n", lenght);
    ciphertext_len += lenght;

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &lenght))
        handle_errors();
    
    printf("After final: %d\n", lenght);
    ciphertext_len += lenght;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext = %d\n", ciphertext_len);

    for (int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
   
    return 0;
}