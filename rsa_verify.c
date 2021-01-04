#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>

#include "rsa.h"

int main(int argc, char** argv){
	FILE* msgToCheck;
	FILE* signature;
	FILE* output;

	unsigned char msgBlock[512];
	unsigned char hashToCheck[32];
	unsigned char hashReal[32];

	int error = 0;

	rsa_key_t* key;

	int byteLen = MSG_SIZE / 8;

	key = malloc(sizeof(rsa_key_t));
	key->bitlen = MSG_SIZE;
	mpz_inits(key->n,key->e,key->d,NULL);

	rsa_read_public_key(key,argv[1]);
	msgToCheck = fopen(argv[2],"r");

	if(argc > 3) signature = fopen(argv[3],"r");
	else signature = stdin;

	output = stdout;

	SHA256_byte(hashReal, msgToCheck);

	fread(msgBlock,1,byteLen,signature);

	rsa_verify(hashToCheck,msgBlock,&error,key);

	//fwrite(msgEncodedBlock,1,byteLen,output);

	if(error){
		printf("Signature does not match\n");
		return 0;
	}

	
	if(compare_hashes(hashToCheck,hashReal)) printf("Signature verified\n");
	else printf("Signature does not match\n");

	free_key(key);
	fclose(msgToCheck);
	if(argc > 3) fclose(signature);

	return 0;

}