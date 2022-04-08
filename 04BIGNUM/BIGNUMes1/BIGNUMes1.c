/*
1.  Write a program that, using OpenSSL, 
    generates three random strings of 32 bytes each, 
    convert them into Big Numbers bn1,bn2,bn3, then computes:
        - sum (bn1+bn2)
        - difference (bn1-bn3)
        - multiplication (bn1*bn2*bn3)
        - integer division (bn3/bn1)
        - modulus (bn1 mod bn2)
        - modulus-exponentiation (bn1^bn3 mod bn2)
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

    unsigned char random_string1[MAX];
	unsigned char random_string2[MAX];
	unsigned char random_string3[MAX];


    /*
    seed the rand not necessary on many win and unix systems
    needed on basic system
    */
    if(RAND_load_file("/dev/random", 64) != 64)
		handle_errors();

    //generating the three random 32 bytes strings
    if(RAND_bytes(random_string1, MAX) != 1)
	    handle_errors();

    if(RAND_bytes(random_string2, MAX) != 1)
        handle_errors();

    if(RAND_bytes(random_string3, MAX) != 1)
        handle_errors();

    //Now create the BN variables
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();
    BIGNUM *bn3 = BN_new();
    BIGNUM *res = BN_new();

    //we have hex digit in the strings so we need to create BN from hex
    BN_bin2bn(random_string1, MAX, bn1);
    BN_bin2bn(random_string2, MAX, bn2);
    BN_bin2bn(random_string3, MAX, bn3);

    /*
    CHECK (unnecessary)
    print the BN and strigs to check the are the same
    */
    printf("String1:\n");
	for (int i = 0; i < MAX; i++){
		printf("%02X", random_string1[i]);
	}
    printf("\nBN1:\n");
    BN_print_fp(stdout,bn1);

    printf("\nString2:\n");
	for (int i = 0; i < MAX; i++){
		printf("%02X", random_string2[i]);
	}
    printf("\nBN2:\n");
    BN_print_fp(stdout,bn2);

    printf("\nString3:\n");
	for (int i = 0; i < MAX; i++){
		printf("%02X", random_string3[i]);
	}
    printf("\nBN3:\n");
    BN_print_fp(stdout,bn3);

    /*
        Let's do the operations required:
        - sum (bn1+bn2)
        - difference (bn1-bn3)
        - multiplication (bn1*bn2*bn3)
        - integer division (bn3/bn1)
        - modulus (bn1 mod bn2)
        - modulus-exponentiation (bn1^bn3 mod bn2)
    */

    // res = bn1 + bn2
    if(!BN_add(res, bn1, bn2))
        handle_errors();
    
    printf("\nSum:\n");
    BN_print_fp(stdout,res);
    
    // res = bn1 - bn3
    if(!BN_sub(res, bn1, bn3))
        handle_errors();
    printf("\nSub:\n");
    BN_print_fp(stdout,res);
    /*
        the multiplication wants a context
        - Creation of the context and initializaion
    */
    BN_CTX *ctx = BN_CTX_new();

    // res = bn1 * bn2
    if(!BN_mul(res, bn1, bn2, ctx))
        handle_errors();
    // res = res * bn3 = bn1 * bn2 * bn3
    if(!BN_mul(res, res, bn3, ctx))
        handle_errors();
    printf("\nMul:\n");
    BN_print_fp(stdout,res);

    /*
        The division wants a BN for the reminder 
        and wants the context too
    */
    BIGNUM *rem = BN_new();
    // bn3/bn1 = res + rem
    if(!BN_div(res, rem, bn3, bn1, ctx))
        handle_errors();
    printf("\nDiv:\n");
    BN_print_fp(stdout,res);

    // rem = bn1/bn2 when res = 0
    // rem = bn1%bn2
    if(!BN_mod(rem, bn1, bn2, ctx))
        handle_errors();
    printf("\nMod:\n");
    BN_print_fp(stdout,rem);

    // res = bn1 ^ bn3 (mod bn2)
    if(!BN_mod_exp(res, bn1, bn3, bn2, ctx))
        handle_errors();
    printf("\nMod Exp:\n");
    BN_print_fp(stdout,res);
    
    //remember to free the variables
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    BN_CTX_free(ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}