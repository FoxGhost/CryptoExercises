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
    EVP_MD_CTX *md;
    FILE *fp;
    unsigned char  buffer[MAXBUF];
    int n_read;
    unsigned char md_value[EVP_MD_size(EVP_sha3_512())];
    int md_len;

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
    md = EVP_MD_CTX_new();

    //context initialization
    if(!EVP_DigestInit(md, EVP_sha3_512()))
        handle_errors();

    while ((n_read = fread(buffer, 1, MAXBUF, fp)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    if(!EVP_DigestFinal(md, md_value, &md_len))
        handle_errors();
    
    EVP_MD_CTX_free(md);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The digest is: ");
    for (int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }
    printf("\n");
    
    return 0;
}