/*
they choose a Generator G and a prime p 1 <= G <= p-1 
C -> G^c -> S
C <- G^s <- S
C compute (G^s)^c
S compute (G^c)*(G^s)
Final key = G^(c*s)
*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


int int main(int argc, char const *argv[]){
	
	OpenSSL_add_all_algorithms();

	BN_CTX *ctx = BN_CTX_new(); 

	BIGNUM *p = BN_new();
	RAND_load_file("/dev/random", 64);
	
	BN_generate_prime_ex(p, 16, 0, NULL, NULL, NULL);
	
	if (!BN_is_prime_ex(p,8,NULL,NULL)){
		while(!BN_is_prime_ex(p,8,NULL,NULL)){
			BN_generate_prime_ex(p, 16, 0, NULL, NULL, NULL);
		}
	}

	BIGNUM *G = BN_new();
	BN_rand_ex(G, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, ctx);
	BN_mod(G, G, p, ctx);


	send_to_sara(p);
	send_to_sara(G);

	BIGNUM *c = BN_new();
	BN_rand_ex(c, 16, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, ctx);
	BN_mod(c, c, p, ctx);
	BIGNUM *gc = BN_new();
	BN_mod_ex(gc, G, c, p, ctx);

	send_to_sara(gc)

	BIGNUM *gs = BN_new();
	gs = receive_from_sara();

	BIGNUM *key = BN_new();
	BN_mod_mul(key, gc, gs, p, cts);

	/*
		I suppose that the client safely store the key before freeing it
	*/

	BN_free(ctx);
	BN_free(p);
	BN_free(G);
	BN_free(c);
	BN_free(gc);
	BN_free(gs);
	BN_free(key);
	CRYPTO_cleanup_all_ex_data();


	return 0;
}

/*
	Carl and Sara to securely share an AES256 key should use RSA to share it over an insecure channel
	one of them generate the key, encrypt it with the public certificate of the other, 
	so the receiver can decrypt it with his private key
*/