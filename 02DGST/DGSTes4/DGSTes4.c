#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    EVP_MD_CTX *md256;
    EVP_MD_CTX *md512;
    FILE *fp;
    unsigned char  buffer[MAXBUF];
    int n_read;
    unsigned char md_256value[EVP_MD_size(EVP_sha256())];
    unsigned char md_512value[EVP_MD_size(EVP_sha512())];
    unsigned char md_256result[EVP_MD_size(EVP_sha256())];

    int md_len;
    int limit = 0;

    //arguments check
    if (argc != 2){
        fprintf(stderr,"Invalid parameters num. Usage: %s file to hash\n", argv[0]);
        exit(-1);
    }
    
   
    //file check
    if((fp = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Cannot open file\n");
        exit(-2);
    }

    //new context 
    md256 = EVP_MD_CTX_new();

    //context initialization
    if(!EVP_DigestInit(md256, EVP_sha256()))
        handle_errors();

    while ((n_read = fread(buffer, 1, MAXBUF, fp)) > 0){
        if(!EVP_DigestUpdate(md256, buffer, n_read))
            handle_errors();
    }

    if(!EVP_DigestFinal(md256, md_256value, &md_len))
        handle_errors();
    
    EVP_MD_CTX_free(md256);

    

    printf("The digest 256 is: ");
    for (int i = 0; i < md_len; i++){
        printf("%02x", md_256value[i]);
    }
    printf("\n");

    limit = md_len;

    md512 = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md512, EVP_sha512()))
        handle_errors();

    while ((n_read = fread(buffer, 1, MAXBUF, fp)) > 0){
        if(!EVP_DigestUpdate(md512, buffer, n_read))
            handle_errors();
    }

    if (!EVP_DigestFinal(md512, md_512value, &md_len))
        handle_errors();

    printf("The digest 512 is: ");
    for (int i = 0; i < md_len; i++){
        printf("%02x", md_512value[i]);
    }
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The final digest 256 is: ");

    for (int i = 0; i < limit; i++){
        md_256result[i] = md_256value[i] ^ (md_512value[i] && md_512value[limit+i]);
        printf("%02x", md_256result[i]);

    }
    
    
    return 0;
}