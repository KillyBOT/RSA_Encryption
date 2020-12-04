#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "rsa.h"

int main(int argc, char** argv){

	FILE* msg;
	FILE* msgDecoded;
	unsigned char* msgBlock;
	unsigned char* msgDecodedBlock;

	char* msgDecodedFilename;

	int filenameLen, running, readSize, byteSize;

	rsa_key_t* key;

	if(argc != 3){
		printf("Invalid use! Type ./rsa_decrypt [name of file to decrypt] [private key file]\n");
		return 1;
	}

	key = malloc(sizeof(rsa_key_t));
	key->bitlen = MSG_SIZE;
	mpz_inits(key->n,key->e,key->d,NULL);
	rsa_read_private_key(key,argv[2]);

	//print_key_ned(key);

	msgDecodedFilename = malloc(512);

	filenameLen = strlen(argv[1]);

	if(filenameLen < 5 || strstr(argv[1],".rsa") == NULL) {
		printf("Wrong file type!\n");
		return 1;
	}

	strncpy(msgDecodedFilename,argv[1],filenameLen-4);
	msgDecodedFilename[filenameLen-4] = '\0';

	msg = fopen(argv[1],"r");
	msgDecoded = fopen(msgDecodedFilename,"w+");

	running = 1;
	byteSize = MSG_SIZE / 8;

	msgBlock = malloc(byteSize);
	msgDecodedBlock = calloc(byteSize,1);

	while(fread(msgBlock,1,byteSize,msg)){
		//printf("%s\n", msgBlock);

		block_decrypt(msgDecodedBlock,msgBlock,key);

		//printf("\n");
		//for(int n = 0; n < byteSize; n++)printf("%2.2X",(unsigned char)msgDecodedBlock[n]);
		//printf("\n\n");

		fputs(msgDecodedBlock,msgDecoded);
		memset(msgBlock,0,byteSize);

	}

	fclose(msg);
	fclose(msgDecoded);

	free_key(key);
	free(msgDecodedFilename);
	free(msgBlock);
	free(msgDecodedBlock);

	return 0;
}