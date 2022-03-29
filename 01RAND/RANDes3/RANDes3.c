#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#define N 4

void handle_errors(){
	ERR_print_errors_fp(stderr);
	abort();
}

void bin(unsigned n)
{
    unsigned i;
    for (i = 1 << 31; i > 0; i = i / 2)
        (n & i) ? printf("1") : printf("0");
}

int main(){

    unsigned int n1 = 0;
    unsigned int n2 = 0;
    unsigned long long int res = 0;
    unsigned char c1[N];
    unsigned char c2[N];
    unsigned int num;
    unsigned long long int twoto32 = ((unsigned long) 1<<32);


    if (RAND_load_file("/dev/random", 64) != 64){
        handle_errors();
    }
     
    if (RAND_bytes(c1,N) != 1){
        handle_errors();
    }

    if (RAND_bytes(c2,N) != 1){
        handle_errors();
    }

    for (int i = 0; i < N; i++){

        num = (int) c1[i];
        n1 += num << i*8;
        num = (int) c2[i];
        n2 += num << i*8;
    }

    res = (unsigned long long)(n1 * n2)%twoto32;
    printf("res: %ud\n", (unsigned int)res); 
    bin(res);   

     
}