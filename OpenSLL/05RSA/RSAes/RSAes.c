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

    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key, NULL, NULL, NULL);
    fclose(f_key);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    unsigned char buffer[MAXBUFFER];

    size_t n_read;

    while ((n_read = fread(buffer, 1, MAXBUFFER, f_in)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f_in);

    unsigned char signature[EVP_PKEY_size(private_key)];

    size_t signature_len;
    size_t dgst_len;

    if(!EVP_DigestSignFinal(sign_ctx, NULL, &dgst_len))
        handle_errors();

    if(!EVP_DigestSignFinal(sign_ctx, signature, &signature_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);

    unsigned char old_signature[EVP_PKEY_size(private_key)];

    //read the given sign
    while ((n_read = fread(old_signature, 1, signature_len, f_sign)) > 0);

    for (int i = 0; i < signature_len; i++){
        if (signature[i] != old_signature[i]){
            printf("Sign NOT OK");
        }
    }

    printf("Sign OK");
    
    


    return 0;

}
