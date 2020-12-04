#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "rsa.h"

int main(int argc, char** argv){

	FILE* msg;
	FILE* msgEncoded;
	unsigned char* msgEncodedFilename;
	unsigned char* msgBlock;
	unsigned char* msgEncodedBlock;

	int running, readSize, byteSize;

	rsa_key_t* key;

	if(argc != 3){
		printf("Invalid use! Type ./rsa_encrypt [name of file to encrypt] [public key file]\n");
		return 1;
	}

	key = malloc(sizeof(rsa_key_t));
	key->bitlen = MSG_SIZE;
	mpz_inits(key->n,key->e,key->d,NULL);

	rsa_read_public_key(key,argv[2]);
	//print_key_ned(key);

	//print_public_key(key);


	msgEncodedFilename = malloc(512);
	strcpy(msgEncodedFilename,argv[1]);
	strcat(msgEncodedFilename,".rsa");

	msg = fopen(argv[1],"r");
	msgEncoded = fopen(msgEncodedFilename,"w+");

	running = 1;
	byteSize = MSG_SIZE / 8;

	msgBlock = malloc(byteSize);
	msgEncodedBlock = malloc(byteSize);

	while(running){
		readSize = 0;

		readSize = fread(msgBlock,1,byteSize-11,msg);
		if(readSize != byteSize-11) {
			for(int n = readSize; n < byteSize-11; n++) msgBlock[n] = 0;
			running = 0;
		}

		block_encrypt(msgEncodedBlock,msgBlock,readSize,key);

		//printf("\n");
		//for(int n = 0; n < byteSize; n++)printf("%2.2X",(unsigned char)msgEncodedBlock[n]);
		//printf("\n\n");

		fwrite(msgEncodedBlock,1,byteSize,msgEncoded);

	}

	fclose(msg);
	fclose(msgEncoded);

	free_key(key);
	free(msgEncodedFilename);
	free(msgBlock);
	free(msgEncodedBlock);

	return 0;
}