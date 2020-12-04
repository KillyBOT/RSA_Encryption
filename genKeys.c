#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "rsa.h"

int main(int argc, char** argv){

	if(argc < 2){
		printf("Enter a name for the file first!\n");
		return 1;
	}

	rsa_key_t* key;

	key = rsa_make_keys(MSG_SIZE);
	print_key_ned(key);

	rsa_save_key(key,argv[1]);

	printf("Keys successfully generated!\n");

	free_key(key);

	return 0;
}