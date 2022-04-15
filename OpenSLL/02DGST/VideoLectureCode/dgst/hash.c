#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    //char message[] = "This is the message to hash!!!";
    //the first parameter is the name of the file to hash

    if (argc != 2){
        fprintf(stderr,"Invalid parameters num. Usage: %s string_to_hash\n", argv[0]);
        exit(-1);
    }
    
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL){
        printf("Couldn't open the input file, try again\n");
        exit(1);
    }
    


    EVP_MD_CTX *md;
    //pedantic mode, also check if md == null

    //best practice
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //create new context
    md = EVP_MD_CTX_new();
    
    //plug the algo to performe computation
    if(!EVP_DigestInit(md, EVP_sha1()))
        handle_errors();

    unsigned char  buffer[MAXBUF];
    int n_read;
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }
    

    //feed the context with data
    //EVP_DigestUpdate(md, argv[1]/*message*/, strlen(argv[1]/*message*/));
                        //size of the algo we want to use
    unsigned char md_value[EVP_MD_size(EVP_sha1())/*20*/];
    int md_len;
    //compute the diget
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