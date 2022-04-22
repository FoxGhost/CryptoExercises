#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX 128

void handle_errors(){
	ERR_print_errors_fp(stderr);
	abort();
}

int main(int argc, char const *argv[])
{
	unsigned char random_string[MAX];
	
	if(RAND_load_file("/dev/random",64) != 64){
		//ERR_print_errors_fp(stderr);
		//fprintf(stderr, "Error with the initialization of the PRNG\n");
		handle_errors();
	}

//  RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure
	if(RAND_bytes(random_string, MAX) != 1){
		//ERR_print_errors_fp(stderr);
		//fprintf(stderr, "Error with the generation\n";
		handle_errors();
	}

	printf("Sequence generated: ")
	for (int i = 0; i < MAX; i++){
		printf("%02x-", random_string[i]);
	}
	printf("\n");

	return 0;
}