/*
    2. Using OpenSSL, write a C program that 
    implements all the operations that are performed by 
    both the parties of a DH key exchange 
    (no need to exchange data, just perform the mathematical operations).
*/

#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define MAX 32

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //Now create the BN variables
    BIGNUM *p = BN_new();//prime number used for calculating the mod
    BIGNUM *g = BN_new();//base of the exponential
    BIGNUM *a = BN_new();//esponent of Alix
    BIGNUM *b = BN_new();//esponent of Bob
    BIGNUM *A = BN_new();//Alix half key = g^a (mod p)
    BIGNUM *B = BN_new();//Bob half key = g^b (mod p)
    BIGNUM *K1 = BN_new();//Complete key = B^a = A^b = g ^ (a*b) (mod p)
    BIGNUM *K2 = BN_new();//Complete key = B^a = A^b = g ^ (a*b) (mod p)

    BN_CTX *ctx = BN_CTX_new(); 

    if(!BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL))
        handle_errors();
    
    if(!BN_is_prime_ex(p, 16, NULL, NULL)){
        printf("This isn't a prime\n");
        abort();
    }

    //seed the rand
    if(RAND_load_file("/dev/random", 64) != 64)
        handle_errors(); 

    BN_rand(g, 512, 0, 1);
    printf("g:\n");
    BN_print_fp(stdout, g);
    printf("\n");

    BN_rand(a, 512, 0, 1);
    printf("a:\n");
    BN_print_fp(stdout, a);
    printf("\n");

    BN_rand(b, 512, 0, 1);
    printf("b:\n");
    BN_print_fp(stdout, b);
    printf("\n");

    BN_mod_exp(A, g, a, p, ctx);
    printf("A:\n");
    BN_print_fp(stdout, A);
    printf("\n");

    BN_mod_exp(B, g, b, p, ctx);
    printf("B:\n");
    BN_print_fp(stdout, B);
    printf("\n");

    BN_mod_exp(K1, A, b, p, ctx);// = BN_mod_exp(K, B, a, p, ctx);
    printf("K1:\n");
    BN_print_fp(stdout, K1);
    printf("\n");

    BN_mod_exp(K2, B, a, p, ctx);
    printf("K2:\n");
    BN_print_fp(stdout, K2);
    printf("\n");

    if(!BN_cmp(K1, K2)){
        printf("This is the Key:\n");
        BN_print_fp(stdout, K1);
    }
    else{
        fprintf(stderr, "Error with the key\n");
        abort();
    }
    
    

    //remember to free the variables
    BN_free(p);
    BN_free(g); 
    BN_free(a);
    BN_free(b);
    BN_free(A);
    BN_free(B);
    BN_free(K1);
    BN_free(K2);
    BN_CTX_free(ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}