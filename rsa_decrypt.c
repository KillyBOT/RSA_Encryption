#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>

#include "rsa.h"

int main(int argc, char** argv){

	FILE* msg;
	FILE* msgDecoded;
	unsigned char* msgBlock;
	unsigned char* msgDecodedBlock;

	char* msgDecodedFilename;

	int filenameLen, running, readSize, byteSize;

	rsa_key_t* key;

	/*if(argc != 3){
		printf("Invalid use! Type ./rsa_decrypt [name of file to decrypt] [private key file]\n");
		return 1;
	}*/

	key = malloc(sizeof(rsa_key_t));

	key->bitlen = MSG_SIZE;
	mpz_inits(key->n,key->e,key->d,NULL);
	rsa_read_private_key(key,argv[1]);

	//print_key_ned(key);

	if(argc > 2) {
		msgDecodedFilename = malloc(512);

		filenameLen = strlen(argv[2]);

		if(filenameLen < 5 || strstr(argv[2],".rsa") == NULL) {
			printf("Wrong file type!\n");
			return 1;
		}

		strncpy(msgDecodedFilename,argv[2],filenameLen-4);
		msgDecodedFilename[filenameLen-4] = '\0';

		msg = fopen(argv[2],"r");
		msgDecoded = fopen(msgDecodedFilename,"w+");

		free(msgDecodedFilename);

	} else {
		msg = stdin;
		msgDecoded = stdout;
	}

	running = 1;
	byteSize = MSG_SIZE / 8;

	msgBlock = malloc(byteSize);
	msgDecodedBlock = calloc(byteSize,1);

	while(fread(msgBlock,1,byteSize,msg)){
		//printf("%s\n", msgBlock);
		readSize = 0;

		block_decrypt(msgDecodedBlock,&readSize, msgBlock,key);

		//printf("\n");
		//for(int n = 0; n < byteSize; n++)printf("%2.2X",(unsigned char)msgDecodedBlock[n]);
		//printf("\n\n");

		//fputs(msgDecodedBlock,msgDecoded);
		fwrite(msgDecodedBlock,1,readSize,msgDecoded);
		memset(msgBlock,0,byteSize);

	}

	if(argc > 2){
		fclose(msg);
		fclose(msgDecoded);
	}

	free_key(key);
	free(msgBlock);
	free(msgDecodedBlock);

	return 0;
}