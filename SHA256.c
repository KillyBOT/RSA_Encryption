#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "rsa.h"

word k[] = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

char* getWordBits(word w){
	char* toRet;
	toRet = malloc(sizeof(word) * 8);
	word currentWord = w;
	for(int x = 0; x < (sizeof(word) * 8); x++){
		if(currentWord & 1 == 1) toRet[((sizeof(word)*8)-x-1)] = '1';
		else toRet[((sizeof(word)*8)-x-1)] = '0';
		currentWord = currentWord >> 1;
	}

	return toRet;
}

void printMessage(word* message){
	for(int x = 0; x < MESSAGE_SIZE; x++){
		printf("%08X ",message[x]);
	}
	printf("\n");
}

word rotateRight(word toRotate, int amount){
    word temp;
    word toRet = toRotate;
    for(int b = 0; b < amount; b++){
        temp = toRet & 0x01;
        temp = temp << 31;
        toRet = toRet >> 1;
        toRet = toRet & 0x7fffffff;
        toRet = toRet | temp;
    }

    return toRet;
}

unsigned char getByte(word w, int p){
	w >>= (3 - p) * 8;
	w &= 0x000000ff;
	return (unsigned char)w;
}

word Ch(word x, word y, word z){
	return (x & y) ^ ((~x) & z);
}

word Maj(word x, word y, word z){
	return (x & y) ^ (x & z) ^ (y & z);
}

word sigma0(word x){
	return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

word sigma1(word x){
	return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

word sigmoid0(word x){
	return rotateRight(x, 7) ^ rotateRight(x, 18) ^ ((x >> 3) & 0x1fffffff);
}

word sigmoid1(word x){
	return rotateRight(x, 17) ^ rotateRight(x, 19) ^ ((x >> 10) & 0x003fffff);
}

word flipBytes(word toFlip){
	word flipped = 0;
	word remainder = toFlip;
	word temp;

	for(int x = 0; x < 3; x++){
		temp = remainder & 0xff000000;
		flipped |= temp;

		flipped >>= 8;
		flipped &= 0x00ffffff;
		remainder <<= 8;

	}

	temp = remainder & 0xff000000;

	flipped |= temp;

	return flipped;
}

void SHA256_init_hash(word* hash){
	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;
}

void SHA256_message(word* hash, word* msg){

	word addToHash[HASH_SIZE];
	word block[BLOCK_SIZE];

	for(int x = 0; x < MESSAGE_SIZE; x++) block[x] = msg[x];


	for(int x = MESSAGE_SIZE; x < BLOCK_SIZE; x++){
		block[x] = sigmoid1(block[x-2]) + block[x - 7] + sigmoid0(block[x-15]) + block[x-16];
	}

	//Now, we need to do BLOCK_SIZE rounds of just switching stuff around.
	//This is the main loop!


	//We create new variables that we will add to the hash later
	//We initalize these variables currently to the current hash's values

	for(int x = 0; x < HASH_SIZE; x++){
		addToHash[x] = hash[x];
	}

	//For BLOCK_SIZE rounds, we do some operations that involve shifting and setting new values

	for(int j = 0; j < BLOCK_SIZE; j++){

		word t1 = addToHash[7] + sigma1(addToHash[4]) + Ch(addToHash[4],addToHash[5],addToHash[6]) + k[j] + block[j];

		word t2 = sigma0(addToHash[0]) + Maj(addToHash[0],addToHash[1],addToHash[2]);

		addToHash[7] = addToHash[6];
		addToHash[6] = addToHash[5];
		addToHash[5] = addToHash[4];
		addToHash[4] = addToHash[3] + t1;
		addToHash[3] = addToHash[2];
		addToHash[2] = addToHash[1];
		addToHash[1] = addToHash[0];
		addToHash[0] = t1 + t2;

		//This is just for printing the hash as it goes through the main loop

		/*printf("j = %d\t",j);
		for(int x = 0; x < HASH_SIZE; x++){
			printf("%x\t", addToHash[x]);
		}
		printf("\n");*/
	}

	for(int x = 0; x < HASH_SIZE; x++){
		hash[x] += addToHash[x];
	}
}

void SHA256_string(char* dest, char* src){
	int running = 1;
	int sp = 0;
	int doPadding = 0;
	int64_t fileSize;

	word msg[MESSAGE_SIZE];
	word paddedMsg[MESSAGE_SIZE];
	word hash[HASH_SIZE];

	memset(paddedMsg,0,sizeof(word) * MESSAGE_SIZE);

	SHA256_init_hash(hash);

	while(running){

		memset(msg,0,sizeof(word) * MESSAGE_SIZE);

		if(doPadding) running = 0;
		else {
			for(int x = 0; x < MESSAGE_SIZE*sizeof(word); x++){
				((char*)msg)[x] = src[sp];
				if(src[sp] == '\0') {

					fileSize = sp * 8;
					((char*)msg)[x] = 0x80;

					if(x > ((MESSAGE_SIZE-2) * sizeof(word))) {
						paddedMsg[MESSAGE_SIZE-2] = fileSize >> 32;
						paddedMsg[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
					}
					else{
						msg[MESSAGE_SIZE-2] = fileSize >> 32;
						msg[MESSAGE_SIZE-2] = flipBytes(msg[MESSAGE_SIZE-2]);
						msg[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
						msg[MESSAGE_SIZE-1] = flipBytes(msg[MESSAGE_SIZE-1]);
						running = 0;
					}

					break;
				}
				sp++;
			}
			for(int x = 0; x < MESSAGE_SIZE; x++) msg[x] = flipBytes(msg[x]);
		}

		//printMessage(msg);

		if(doPadding) SHA256_message(hash,paddedMsg);
		else SHA256_message(hash,msg);

		if(paddedMsg[MESSAGE_SIZE-1]) doPadding = 1;
	}
	sprintf(dest,"%08X%08X%08X%08X%08X%08X%08X%08X",hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7]);
}

void SHA256_byte(unsigned char* dest, FILE* f){

	int continueReading = 1;
	int paddingNext = 0;
	int64_t fileSize = 0;
	int fileSizeToAdd;
	//Why these values? They're the first fractional part of the square root of the first 8 prime numbers, I think...
	word hash[HASH_SIZE];
	word messageBuffer[MESSAGE_SIZE];
	//This is when you can't fit the padding into the last 2 words, so you need a whole new message, which is annoying.
	word paddingMessageBuffer[MESSAGE_SIZE];
	memset(paddingMessageBuffer,0,MESSAGE_SIZE*WORD_SIZE);

	SHA256_init_hash(hash);

	while( continueReading ){

		//First, we read the text in 512 bit blocks, and if we reach the end we pad the text out so that it is 512 bits

		fileSizeToAdd = 0;

		memset(messageBuffer,0,MESSAGE_SIZE*WORD_SIZE);

		fileSizeToAdd = fread(messageBuffer,1,sizeof(word)*MESSAGE_SIZE,f);
		for(int x = 0; x < MESSAGE_SIZE; x++) messageBuffer[x] = flipBytes(messageBuffer[x]);

		fileSize += fileSizeToAdd * 8;

		if(fileSizeToAdd != WORD_SIZE*MESSAGE_SIZE){

			word temp;
			int fileQuo,fileRem;

			if(!paddingNext){
				fileQuo = fileSizeToAdd / WORD_SIZE;
				fileRem = fileSizeToAdd % WORD_SIZE;

				temp = 0xffffffff;

				temp <<= (WORD_SIZE-fileRem)*8;
				messageBuffer[fileQuo] &= temp;

				temp = 0x80000000;

				temp = rotateRight(temp,fileRem*8);
				messageBuffer[fileQuo] |= temp;
			}

			//printMessage(messageBuffer);


			if(fileSizeToAdd <= ((MESSAGE_SIZE - 2) * WORD_SIZE)){
				messageBuffer[MESSAGE_SIZE-2] = fileSize >> 32;
				messageBuffer[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
				continueReading = 0;
			} else {
				paddingMessageBuffer[MESSAGE_SIZE-2] = fileSize >> 32;
				paddingMessageBuffer[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
			}
		}
		//printMessage(messageBuffer);

		//Now, we set the first 16 blocks to the message blocks
		//Sometimes we need an extra "padded message buffer" since we don't have enough space in the previous buffer to include the size of the file.

		if(paddingNext){
			SHA256_message(hash,paddingMessageBuffer);
			continueReading = 0;
		}
		else{
			SHA256_message(hash,messageBuffer);
		}

		if(paddingMessageBuffer[MESSAGE_SIZE - 1] != 0){
			paddingNext = 1;
		}

	}

	//This is for printing the hash

	/*printf("This is your finished hash: ");

	for(int x = 0; x < HASH_SIZE; x++){
		printf("%08X", hash[x]);
	}

	printf("\n"); */

	//if(fp != stdout)fclose(fp);

	//sprintf(dest,"%08X%08X%08X%08X%08X%08X%08X%08X",hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7]);
	for(int x = 0; x < HASH_SIZE * WORD_SIZE; x++) dest[x] = getByte(hash[x / WORD_SIZE], x % WORD_SIZE);
}

void SHA256_file(char* dest, FILE* f){

	int continueReading = 1;
	int paddingNext = 0;
	int64_t fileSize = 0;
	int fileSizeToAdd;
	//Why these values? They're the first fractional part of the square root of the first 8 prime numbers, I think...
	word hash[HASH_SIZE];
	word messageBuffer[MESSAGE_SIZE];
	//This is when you can't fit the padding into the last 2 words, so you need a whole new message, which is annoying.
	word paddingMessageBuffer[MESSAGE_SIZE];
	memset(paddingMessageBuffer,0,MESSAGE_SIZE*WORD_SIZE);

	SHA256_init_hash(hash);

	while( continueReading ){

		//First, we read the text in 512 bit blocks, and if we reach the end we pad the text out so that it is 512 bits

		fileSizeToAdd = 0;

		memset(messageBuffer,0,MESSAGE_SIZE*WORD_SIZE);

		fileSizeToAdd = fread(messageBuffer,1,sizeof(word)*MESSAGE_SIZE,f);
		for(int x = 0; x < MESSAGE_SIZE; x++) messageBuffer[x] = flipBytes(messageBuffer[x]);

		fileSize += fileSizeToAdd * 8;

		if(fileSizeToAdd != WORD_SIZE*MESSAGE_SIZE){

			word temp;
			int fileQuo,fileRem;

			if(!paddingNext){
				fileQuo = fileSizeToAdd / WORD_SIZE;
				fileRem = fileSizeToAdd % WORD_SIZE;

				temp = 0xffffffff;

				temp <<= (WORD_SIZE-fileRem)*8;
				messageBuffer[fileQuo] &= temp;

				temp = 0x80000000;

				temp = rotateRight(temp,fileRem*8);
				messageBuffer[fileQuo] |= temp;
			}

			//printMessage(messageBuffer);


			if(fileSizeToAdd <= ((MESSAGE_SIZE - 2) * WORD_SIZE)){
				messageBuffer[MESSAGE_SIZE-2] = fileSize >> 32;
				messageBuffer[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
				continueReading = 0;
			} else {
				paddingMessageBuffer[MESSAGE_SIZE-2] = fileSize >> 32;
				paddingMessageBuffer[MESSAGE_SIZE-1] = fileSize & 0xffffffff;
			}
		}
		//printMessage(messageBuffer);

		//Now, we set the first 16 blocks to the message blocks
		//Sometimes we need an extra "padded message buffer" since we don't have enough space in the previous buffer to include the size of the file.

		if(paddingNext){
			SHA256_message(hash,paddingMessageBuffer);
			continueReading = 0;
		}
		else{
			SHA256_message(hash,messageBuffer);
		}

		if(paddingMessageBuffer[MESSAGE_SIZE - 1] != 0){
			paddingNext = 1;
		}

	}

	//This is for printing the hash

	/*printf("This is your finished hash: ");

	for(int x = 0; x < HASH_SIZE; x++){
		printf("%08X", hash[x]);
	}

	printf("\n"); */

	//if(fp != stdout)fclose(fp);

	sprintf(dest,"%08X%08X%08X%08X%08X%08X%08X%08X",hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7]);
}