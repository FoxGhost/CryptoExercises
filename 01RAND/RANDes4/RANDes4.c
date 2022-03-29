#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#define N 8

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void bin(unsigned n)
{
    unsigned i;
    for (i = 1 << 31; i > 0; i = i / 2)
        (n & i) ? printf("1") : printf("0");
}

int main()
{

    // first number
    unsigned long long int n11 = 0; // 64
    unsigned long long int n12 = 0; // 128
    unsigned long long int n13 = 0; // 192
    unsigned long long int n14 = 0; // 256

    // second number
    unsigned long long int n21 = 0; // 64
    unsigned long long int n22 = 0; // 128
    unsigned long long int n23 = 0; // 192
    unsigned long long int n24 = 0; // 256

    //result
    unsigned long long int res1 = 0; // 64
    unsigned long long int res2 = 0; // 128
    unsigned long long int res3 = 0; // 192
    unsigned long long int res4 = 0; // 256

    unsigned char c1[N];
    unsigned char c2[N];

    unsigned long long int num;
    int i = 0;
    int k = 0;
    int j = 0;
    

    if (RAND_load_file("/dev/random", 64) != 64){
        handle_errors();
    }

    if (RAND_bytes(c1, N) != 1){
        handle_errors();
    }

    if (RAND_bytes(c2, N) != 1){
        handle_errors();
    }

    for (i = 0; i < N; i++){
        num = (int)c1[i];
        n11 += num << i * 8;
        num = (int)c2[i];
        n21 += num << i * 8;
    }
    printf("Num11: %08x\nNum21: %08x\n", n11, n21);

    if (RAND_bytes(c1, N) != 1){
        handle_errors();
    }

    if (RAND_bytes(c2, N) != 1){
        handle_errors();
    }

    for (i=0; i < N; i++){
        num = (int)c1[i];
        n12 += num << i * 8;
        num = (int)c2[i];
        n22 += num << i * 8;
    }
    printf("Num12: %08x\nNum22: %08x\n", n12, n22);

    if (RAND_bytes(c1, N) != 1){
        handle_errors();
    }

    if (RAND_bytes(c2, N) != 1){
        handle_errors();
    }
    
    for (i=0; i < N; i++){

        num = (int)c1[i];
        n13 += num << i * 8;
        num = (int)c2[i];
        n23 += num << i * 8;
    }
    printf("Num13: %08x\nNum23: %08x\n", n13, n23);

    if (RAND_bytes(c1, N) != 1){
        handle_errors();
    }

    if (RAND_bytes(c2, N) != 1){
        handle_errors();
    }
    
    
    for (i=0; i < N; i++){

        num = (int)c1[i];
        n14 += num << i * 8;
        num = (int)c2[i];
        n24 += num << i * 8;
    }
    printf("Num14: %08x\nNum24: %08x\n", n14, n24);

    res1 = n11 + n21;
    printf("First  64 bit: %08x\n", res1);
    
    res2 = n12 + n22;
    printf("Second 64 bit: %08x\n", res2);

    res3 = n13 + n23;
    printf("Third  64 bit: %08x\n", res3);

    res4 = n14 + n24;
    printf("Fourth 64 bit: %08x\n", res4);

    printf("The 256 bit number is:\n%08x%08x%08x%08x", res1,res2,res3,res4);

    //printf("First  64 bit: %x\nSecond 64 bit: %x\nThird  64 bit: %x\nFourth 64 bit: %x\n", res1, res2, res3, res4);

    //res = (n1 * n2) /*%32*/;
    //printf("res: %ud\n", res);
    //bin(res);
    return 0;
}
