#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>

#include "rsa.h"

int main(int argc, char** argv){
	FILE* msg;
	FILE* output;

	unsigned char msgBlock[512];
	unsigned char msgEncodedBlock[512];
	unsigned char hash[32];

	rsa_key_t* key;

	int byteLen = MSG_SIZE / 8;

	unsigned char paddingBytes[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

	key = malloc(sizeof(rsa_key_t));
	key->bitlen = MSG_SIZE;
	mpz_inits(key->n,key->e,key->d,NULL);

	rsa_read_private_key(key,argv[1]);

	if(argc > 2) {
		msg = fopen(argv[2],"r");
		output = fopen(argv[3],"w");
	}
	else {
		msg = stdin;
		output = stdout;
	}

	SHA256_byte(hash, msg);

	rsa_sign(msgEncodedBlock,hash,key);

	fwrite(msgEncodedBlock,1,byteLen,output);

	free_key(key);
	if(argc > 2) {
		fclose(msg);
		fclose(output);
	}

	return 0;

}