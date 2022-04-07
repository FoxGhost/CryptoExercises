#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    char num_string[] = "1234512345123451234512345123451234512345";
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    /*  
    For version 3.0
    BN_generate_prime_ex2(); same parameters + context 

    For version 1.1.1 but deprecated in 3.0
    BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, 
                         const BIGNUM *add, const BIGNUM rem, BN_GENCB *cb);

    ret -> where to store the prime
    bits -> lenght in bits of the prime number
    safe -> if (p-1)/2 is also a prime 
    add, rem ->? p
    p % add == rem
    if rem is null -> rem = 1
    if rem is null and safe is true rem = 3, add must be a multiple of 4


*/

    if (!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    printf("Prime 1:\n");
    BN_print_fp(stdout, prime1);
    printf("\n");

    if (BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("It's a prime\n");
    else
        printf("It isn't a prime\n");

    /*
    In openssl 3.0
    BN_check_prime(prime1, ctx, cb);
    */

    printf("\n");


    BN_set_word(prime2, 16);

    printf("Prime 2:\n");
    BN_print_fp(stdout, prime2);
    printf("\n");

    if (BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("It's a prime\n");
    else
        printf("It isn't a prime\n");


    printf("\n");


    printf("Prime 1 bytes: %d\n", BN_num_bytes(prime1));
    /*
    In this case with ask for a prime of 1024 bit 
    but if we add more constraints like safe, add and rem
    we get at least 1024 bits so if we want to store the number 
    we need to know the exact number of bits to allocate a proper variable
    */

    printf("Prime 2 bytes: %d\n", BN_num_bytes(prime2));

    BN_free(prime1);
    BN_free(prime2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}