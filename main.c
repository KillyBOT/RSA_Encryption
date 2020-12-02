#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rsa.h"

#define MSG_SIZE 256

int main(int argc, char **argv){

	rsa_key_t* key;
	char* msg;
	char* msgEncoded;
	char* msgDecoded;

	msg = malloc(MSG_SIZE/8);
	msgEncoded = malloc(MSG_SIZE/8);
	msgDecoded = malloc(MSG_SIZE/8);
	strcpy(msg, "This is a secret message!");
	// char c, d;

	// c = -10;

	// printf("%d\n%ld\n%d\n", c, (unsigned long int)(unsigned char)c, (char)((unsigned long int)(unsigned char)c + 256));

	key = rsa_make_keys(MSG_SIZE);

	print_public_key(key);
	print_private_key(key);
	printf("\n");

	block_encrypt(msgEncoded,msg,sizeof(msg),key);

	for(int n = 0; n < MSG_SIZE/8; n++)printf("%.2X",(unsigned char)msgEncoded[n]);
	printf("\n\n");

	block_decrypt(msgDecoded,msgEncoded,sizeof(msgEncoded),key);

	for(int n = 0; n < MSG_SIZE/8; n++)printf("%.2X",(unsigned char)msgDecoded[n]);
	printf("\n\n");

	printf("Decrypted: [%s]\n",msgDecoded);

	free_key(key);

	free(msg);
	free(msgEncoded);
	free(msgDecoded);
}