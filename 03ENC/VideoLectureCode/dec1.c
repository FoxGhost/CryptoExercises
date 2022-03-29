#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main(){

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[] = "123456789abcdef";//ascii  char 
    unsigned char iv[] = "abcdef123456789";//ascii char
    unsigned char ciphertext[] = "6a9833f75fbc453159abb074ff41cf398b033beb92361ab7fb6bd531707c2e89e0838b7204cbb4662a118bd34b1cf986";

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);

    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for (int i = 0; i < strlen(ciphertext)/2; i++){
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);
    }
    
    
    int lenght;
    int plaintext_len = 0;

    EVP_CipherUpdate(ctx, plaintext, &lenght, ciphertext_bin, strlen(ciphertext)/2);

    printf("After update: %d\n", lenght);
    plaintext_len += lenght;

    EVP_CipherFinal(ctx, plaintext+plaintext_len, &lenght);
    
    printf("After final: %d\n", lenght);
    plaintext_len += lenght;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len]='\0';

    printf("Plaintext = %s\n", plaintext);
    
   
    return 0;
}