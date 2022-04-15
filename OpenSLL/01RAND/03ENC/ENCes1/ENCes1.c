#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();//check null

    unsigned char *key; 
    unsigned char *iv;
    int len;
    int ciphertext_len = 0;
    int n_read;
    unsigned char buffer[MAXSIZE];
    int iv_len, key_len;
    unsigned char ciphertext[MAXSIZE + 16];

    FILE *f_in;

    if(RAND_load_file("/dev/random", 64) != 64){
		handle_errors();
	}

    

    
    /*
        Creazione della chiave
        ne ottengo la lunghezza in base all'algoritmo scelto
        alloco la chiave
        genero la chiave con numeri casuali
    */


    printf("key len: ");
    if(!(key_len = EVP_CIPHER_key_length(EVP_get_cipherbyname(argv[2]))))
        handle_errors();
    printf("%d\n", key_len);

    key = malloc(sizeof(unsigned char) * EVP_CIPHER_key_length(EVP_get_cipherbyname(argv[2])));

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
    if(!(iv_len = EVP_CIPHER_iv_length(EVP_get_cipherbyname(argv[2]))))
        iv = 0;
    else{
        iv = malloc(sizeof(unsigned char) * EVP_CIPHER_iv_length(EVP_get_cipherbyname(argv[2])));
        if(RAND_bytes(iv, iv_len) != 1){
		    handle_errors();
	}
    }

    printf("%d\n", iv_len);
    

    

    if ((f_in = fopen(argv[1], "r")) == NULL){
       fprintf(stderr, "Errors opening the input file\n", argv[0]);
       exit(1);
   }

   if(!EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[2]), key, iv, ENCRYPT))
        handle_errors();

  while ((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0 ){

        if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
            handle_errors();
        
        ciphertext_len += len;

    }

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &len))
        handle_errors();
    
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext = %d\n", ciphertext_len);

    for (int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    fclose(f_in);
   
    return 0;
}