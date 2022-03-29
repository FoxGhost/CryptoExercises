#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>//ok
#include <openssl/pem.h>
#include <openssl/bn.h>



int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, 
                char *key, int keylenght, char* result);
                
int main(int argc, char **argv){

    return 0;
}

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, 
                char *key, int keylenght, char* result){


    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

    EVP_MD_CTX *md;
    md = EVP_MD_CTX_new();//ok

    if(!EVP_DigestInit(md, EVP_sha256()))//ok
        return 1;

    if(!EVP_DigestUpdate(md, message, message_len))//ok
        return 1;

    if(!EVP_DigestUpdate(md, key, keylenght))//ok
        return 1;

    if(!EVP_DigestFinal(md, md_value, &md_len))//ok
        return 1;

    EVP_MD_CTX_free(md);

    unsigned char md_value_final[EVP_MD_size(EVP_sha256())];
    int md_len2;
    EVP_MD_CTX *md;
    md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
        return 1;

    if(!EVP_DigestUpdate(md, md_value, md_len))
        return 1;


    if(!EVP_DigestFinal(md, md_value_final, &md_len2))
        return 1;

    EVP_MD_CTX_free(md);


    int encrypted_data_len;


    if((encrypted_data_len = RSA_public_encrypt(md_len2+1, md_value_final, result, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            return 1;

//PROF SOLUTION



    return 0;

}