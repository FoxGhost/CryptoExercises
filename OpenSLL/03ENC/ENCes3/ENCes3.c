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
    FILE *f_in;
//  unsigned char *mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    unsigned char *mask = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    int n_read;
    unsigned char buffer[MAXSIZE];
    unsigned char ciphertext[MAXSIZE + 16];
    unsigned char plaintext[MAXSIZE + 16];
    int len;
    int ciphertext_len = 0;
    int plaintext_len = 0;


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    /*
        Creazione della chiave
        ne ottengo la lunghezza in base all'algoritmo scelto
        alloco la chiave
        genero la chiave con numeri casuali
    */


    printf("key len: ");
    if(!(key_len = EVP_CIPHER_key_length(EVP_chacha20())))
        handle_errors();
    printf("%d\n", key_len);

    key = malloc(sizeof(unsigned char) * EVP_CIPHER_key_length(EVP_chacha20()));

    if(RAND_bytes(key, key_len) != 1){
		handle_errors();
	}



    
    
    /*
        Creazione del iv
        se presente nell'algoritmo
            ne ottengo la lunghezza in base all'algoritmo scelto
            altrimenti = 0 
        alloco iv
        genero iv con numeri casuali
    */

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

    if ((f_in = fopen(argv[1], "r")) == NULL){
       fprintf(stderr, "Errors opening the input file\n", argv[0]);
       exit(1);
   }

   if(!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, ENCRYPT))
        handle_errors();

    printf("Plaintext:\n");
    while ((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0 ){
        printf("%s", buffer);
    }
    printf("\n");
    fclose(f_in);

    if ((f_in = fopen(argv[1], "r")) == NULL){
       fprintf(stderr, "Errors opening the input file\n", argv[0]);
       exit(1);
    }
    
    while ((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0 ){
        
        if(ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+
            fprintf(stderr,"The file to cipher is larger than I can\n");
            abort();
        }

        if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
            handle_errors();
        
        ciphertext_len += len;

    }

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &len))
        handle_errors();
    
    ciphertext_len += len;

    printf("Encryption completed\n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);


    printf("Size of the ciphertext = %d\n", ciphertext_len);
    printf("Ciphertext:\n");

    for (int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Now xor the ciphertext\n");
    int j;
    for (int i = 0, j = 0; i < ciphertext_len; i++, j++){
        ciphertext[i] = ciphertext[i] ^ 1;
        printf("%02x", ciphertext[i]);
    }
    printf("\nXor end\n");

//DECRYPTION PART------------------------------------------------------------------------------------------

    printf("New ctx\n");

    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    if (ctx1 == NULL){
        fprintf(stderr, "Error creating new ctx");
    }
 
   

    if(!EVP_CipherInit(ctx1, EVP_chacha20(), key, iv, DECRYPT))
        handle_errors();
    //after this, segmentation fault, why???
 


    len = 0;
    unsigned char new_buffer[MAXSIZE];


    //for (int i = 0; i < ciphertext_len; i++){

        if(!EVP_CipherUpdate(ctx1, plaintext, &len, ciphertext, ciphertext_len))
            handle_errors();
        
        plaintext_len += len;

   // }

    if(!EVP_CipherFinal(ctx1, plaintext+plaintext_len, &len))
        handle_errors();
    
    plaintext_len += len;

    printf("Decryption completed\n");

    printf("Decrypted text:\n");
    //for (int i = 0; i < plaintext_len; i++){
        printf("%s", plaintext/*[i]*/);
    //}
    printf("\n");


    printf("Now xor the plaintext\n");

    for (int i = 0; i < ciphertext_len; i++){
        plaintext[i] = plaintext[i] ^ 1;
    }

    printf("\nXor end\n");

    printf("Plaintext:\n");
    printf("%s", plaintext);
    printf("\n");

    EVP_CIPHER_CTX_free(ctx1);

    printf("END");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}