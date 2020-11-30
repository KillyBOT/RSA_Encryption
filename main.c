#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "rsa.h"

int main(int argc, char **argv){

	rsa_key_t* key;

	key = rsa_make_keys(2048);

	gmp_printf("N:\t%Zd\n\ne:\t%Zd\n\nd:\t%Zd\n",key->n,key->e,key->d);

	mpz_clear(key->n);
	mpz_clear(key->e);
	mpz_clear(key->d);
	free(key);

	printf("Test\n");
}