/*
* Exercise on RSA 
* take as input the signature file and call again the DigestSign Primitive 
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

#define MAXBUFFER 2048


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

    //open signed file
    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the file, try again\n");
        exit(1);
    }

    //open signature to verify
    FILE *f_sign;
    if((f_sign = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the signature file, try again\n");
        exit(1);
    }

    //open public key file
    FILE *f_key;
    if((f_key = fopen(argv[3],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file with the public key, try again\n");
        exit(1);
    }

    //reading the public key from file
    EVP_PKEY *public_key = PEM_read_PUBKEY(f_key, NULL, NULL, NULL);
    fclose(f_key);

    //context for thr verification
    EVP_MD_CTX *ver_ctx = EVP_MD_CTX_new();

    //Initializing the verification 
    if(!EVP_DigestVerifyInit(ver_ctx, NULL, EVP_sha256(), NULL, public_key))
        handle_errors();
//    printf("Verify Init Ok\n");

    size_t n_read;
    unsigned char buffer[MAXBUFFER];
//Updating the verification with chunk of the file
    while((n_read = fread(buffer,1,MAXBUFFER,f_in)) > 0){
        if(!EVP_DigestVerifyUpdate(ver_ctx, buffer, n_read))
            handle_errors();
    }
//    printf("Verify Update Ok\n");


    unsigned char signature[EVP_PKEY_size(public_key)];
    size_t sig_len = 0;
    size_t digest_len;

// read the given signature
    while((n_read = fread(signature,1,MAXBUFFER,f_sign)) > 0){
        sig_len += n_read;
    }
    fclose(f_in);
    fclose(f_sign);

//  Performing the verification
    if(EVP_VerifyFinal(ver_ctx, signature, sig_len, public_key))
        printf("Signature OK");
    else
        printf("Signature NOT OK");
    
    return 0;

}
