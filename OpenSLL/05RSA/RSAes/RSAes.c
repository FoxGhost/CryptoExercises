/*
* Exercise on RSA 
* take as input the signature file and call again the DigestSing Primitive 
* in order to perform the verification that is actually made with the 
* command:
*
* openssl dgst -sha256 -signature signature.bin -verify public.pem signed_file
*
*
*
*/

#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAXBUFFER 1024


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();


    if(argc != 4){
        fprintf(stderr,"Invalid parameters. Usage: %s file sign key\n",argv[0]);
        exit(1);
    }

    //signed file
    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the file, try again\n");
        exit(1);
    }

    //signature to verify
    FILE *f_sign;
    if((f_sign = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the signature file, try again\n");
        exit(1);
    }

    //read public key from file
    FILE *f_key;
    if((f_key = fopen(argv[3],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file with the public key, try again\n");
        exit(1);
    }
    RSA *public_key = PEM_read_RSAPublicKey(f_key,NULL,NULL,NULL);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    
    int n_read;
    unsigned char signature[MAXBUFFER];

    //leggo la firma
    while ((n_read = fread(signature, 1, MAXBUFFER, f_sign)) > 0 );
    
    //leggo il file firmato
    unsigned char msg[MAXBUFFER];
    while ((n_read = fread(msg, 1, MAXBUFFER, f_in)) > 0 );



    if(!RSA_verify(NID_sha256, msg, strlen(msg), signature, strlen(signature), public_key)){
        handle_errors();
        abort();
    }
    
    printf("Sign OK\n");
    
    return 0;

}
