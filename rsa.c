#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

#include "rsa.h"

#define E_CONST 65537

void gcd(mpz_t rop, const mpz_t a, const mpz_t b){
	if(!mpz_cmp_ui(b,0)){
		mpz_set(rop,a);
	}
	else {
		mpz_t newA;
		mpz_init(newA);
		mpz_fdiv_r(newA,a,b);
		gcd(rop, b, newA);
		mpz_clear(newA);
	}
}

void lcm(mpz_t rop, const mpz_t a, const mpz_t b){
	mpz_t p, v;
	mpz_inits(p, v, NULL);
	mpz_mul(p,a,b);
	gcd(v,a,b);
	mpz_cdiv_q(rop, p, v);
}

void modinv(mpz_t rop, const mpz_t aInit, const mpz_t mInit){
	mpz_t a, m, x, y, q, t;

	mpz_inits(a,m,q,t,NULL);
	mpz_init_set_ui(x,1);
	mpz_init(y);
	mpz_init_set(a,aInit);
	mpz_init_set(m,mInit);

	if(!mpz_cmp_ui(mInit,1)){
		mpz_clears(a,m,x,y,q,t,NULL);
		mpz_set_ui(rop,0);
	}

	//gmp_printf("a %Zd\tm: %Zd\tx: %Zd\ty: %Zd\tq: %Zd\tt: %Zd\n",a,m,x,y,q,t);
	while(mpz_cmp_ui(a,1) > 0){
		mpz_fdiv_q(q,a,m);
		mpz_set(t,m);

		mpz_mod(m,a,m);
		mpz_set(a,t);
		mpz_set(t,y);

		mpz_submul(x,q,y);
		mpz_set(y,x);
		mpz_set(x,t);

		//gmp_printf("a %Zd\tm: %Zd\tx: %Zd\ty: %Zd\tq: %Zd\tt: %Zd\n",a,m,x,y,q,t);
	}

	if(mpz_cmp_ui(x,0) < 0) mpz_add(x,x,mInit);

	mpz_set(rop,x);

	mpz_clears(a,m,x,y,q,t,NULL);

}

int miller_rabin(mpz_t n, int k){

	int r, temp;
	mpz_t x, a, d, nm1;
	gmp_randstate_t randState;

	mpz_init(x);
	mpz_init(a);
	mpz_init(d);
	mpz_init_set(nm1,n);

	gmp_randinit_default(randState);
	gmp_randseed_ui(randState, (unsigned long int)time(NULL) + 11);

	mpz_init_set(d,n);
	mpz_sub_ui(d,d,1);

	mpz_sub_ui(nm1,nm1,1);

	r = 0;
	temp = 0;

	do {
		mpz_cdiv_q_ui(d,d,2);
		r++;
	} while (!mpz_fdiv_ui(d,2));


	for(int iter = 0; iter < k; iter++){
		mpz_sub_ui(n,n,4);
		mpz_urandomm(a, randState, n);
		mpz_add_ui(n,n,4);
		mpz_add_ui(a,a,2);

		mpz_powm(x,a,d,n);

		//gmp_printf("n:\n%Zd\n\na:\n%Zd\n\nd:\n%Zd\n\nx:\n%Zd\n",n,a,d,x);

		if(!mpz_cmp_ui(x,1) || !mpz_cmp(x,nm1)) {
			continue;
		}


		for(int iter2 = 0; iter2 < r - 1; iter2++){
			mpz_powm_ui(x,x,2,n);
			if(!mpz_cmp(x,nm1)){
				continue;
			}
		}

		gmp_randclear(randState);
		mpz_clear(x);
		mpz_clear(a);
		mpz_clear(d);

		return 0;

		//gmp_printf("%Zd\n",n);
	}
	//printf("r: %d\n",r);

	gmp_randclear(randState);

	mpz_clear(x);
	mpz_clear(a);
	mpz_clear(d);

	return 1;
}

int compare_hashes(unsigned char* h1, unsigned char* h2){
	for(int x = 0; x < WORD_SIZE * HASH_SIZE; x++){
		//printf("%02X %02X\n", hashToCheck[x], hashReal[x]);
		if(h1[x] != h2[x]){
			return 0;
		}
	}
	return 1;
}

rsa_key_t* rsa_make_keys(int bitlen){

	rsa_key_t *kFinal;
	int bp, bq;
	mpz_t p, q, n, l, e, d;
	gmp_randstate_t randState;

	gmp_randinit_default(randState);
	gmp_randseed_ui(randState,(unsigned long int)time(NULL));
	srand((unsigned int)time(NULL));

	mpz_inits(p,q,n,l,e,d,NULL);

	bp = bitlen/2;
	bq = bitlen - bitlen/2;

	while( (!mpz_fdiv_ui(p,3)) 
		|| (!mpz_fdiv_ui(p,5)) 
		|| (!mpz_fdiv_ui(p,7))
		|| (!mpz_fdiv_ui(p,11))
		|| (!mpz_fdiv_ui(p,13))
		|| (!mpz_fdiv_ui(p,17))
		|| (!mpz_fdiv_ui(p,19))
		|| !miller_rabin(p,1024)
		|| (mpz_fdiv_ui(p,E_CONST) == 1)){
		mpz_urandomb(p,randState,bp);
		mpz_setbit(p,0);
		mpz_setbit(p,bp-1);
		mpz_setbit(p,bp-2);
	}

	while( (!mpz_fdiv_ui(q,3)) 
		|| (!mpz_fdiv_ui(q,5)) 
		|| (!mpz_fdiv_ui(q,7))
		|| (!mpz_fdiv_ui(q,11))
		|| (!mpz_fdiv_ui(q,13))
		|| (!mpz_fdiv_ui(q,17))
		|| (!mpz_fdiv_ui(q,19))
		|| !miller_rabin(q,1024)
		|| (mpz_fdiv_ui(q,E_CONST) == 1)){
		mpz_urandomb(q,randState,bq);
		mpz_setbit(q,0);
		mpz_setbit(q,bq-1);
		mpz_setbit(q,bq-2);
	}

	//gmp_printf("p:\n%Zd\n\nq:\n%Zd\n",p,q);

	mpz_mul(n,p,q);

	mpz_sub_ui(p,p,1);
	mpz_sub_ui(q,q,1);

	lcm(l,p,q);

	mpz_add_ui(p,p,1);
	mpz_add_ui(q,q,1);

	mpz_init_set_ui(e, E_CONST);

	modinv(d,e,l);

	//dLen = mpz_sizeinbase(d,2);
	//if(mpz_sizeinbase(d,2) < bitlen) mpz_mul_2exp(d,d,bitlen-dLen);

	kFinal = malloc(sizeof(rsa_key_t));

	mpz_init_set(kFinal->n,n);
	mpz_init_set(kFinal->e,e);
	mpz_init_set(kFinal->d,d);
	kFinal->bitlen = bitlen;

	gmp_randclear(randState);
	mpz_clears(p,q,n,l,e,d,NULL);

	return kFinal;
}

void print_key_ned(rsa_key_t* key){
	gmp_printf("n:\n%ZX\ne:\n%Zx\nd:\n%ZX\n",key->n,key->e,key->d);
}

void print_public_key(rsa_key_t* key){
	gmp_printf("Public key:\n%ZX\n",key->n);
}

void print_private_key(rsa_key_t* key){
	gmp_printf("Private key:\n%ZX\n",key->d);
}

void free_key(rsa_key_t* key){
	mpz_clears(key->n, key->e, key->d, NULL);
	free(key);
}

void rsa_save_key(rsa_key_t* key, char* filename){
	char* public_key_name;
	char* private_key_name;

	FILE* public_file;
	FILE* private_file;

	public_key_name = malloc(512);
	private_key_name = malloc(512);

	strcpy(public_key_name, filename);
	strcat(public_key_name, ".pub");
	strcpy(private_key_name, filename);

	public_file = fopen(public_key_name,"w+");
	private_file = fopen(private_key_name,"w+");

	mpz_out_str(public_file, 16, key->n);
	mpz_out_str(public_file, 16, key->e);

	mpz_out_str(private_file, 16, key->n);
	mpz_out_str(private_file, 16, key->d);

	fclose(public_file);
	fclose(private_file);

	free(public_key_name);
	free(private_key_name);
}

void rsa_read_public_key(rsa_key_t* key, char* filename){

	FILE* key_file;
	char* n;

	key_file = fopen(filename,"r");

	n = malloc(MSG_SIZE / 4 + 1);

	fgets(n,MSG_SIZE/4+1,key_file);

	//printf("%s\n", n);

	mpz_set_str(key->n, n, 16);
	mpz_inp_str(key->e, key_file, 16);

	fclose(key_file);
	free(n);

}

void rsa_read_private_key(rsa_key_t* key, char* filename){

	FILE* key_file;
	unsigned char* n;

	key_file = fopen(filename,"r");

	n = malloc(MSG_SIZE/4 + 1);

	fgets(n,MSG_SIZE/4 + 1,key_file);

	mpz_set_str(key->n, n, 16);
	mpz_inp_str(key->d, key_file, 16);

	fclose(key_file);
	free(n);

}

void block_encrypt(unsigned char* dest, unsigned char* str, size_t len, rsa_key_t* key){
	int strLen, byteLen;
	mpz_t strNum;
	srand(time(NULL));

	mpz_init(strNum);

	byteLen = key->bitlen/8;

	//printf("%ld\t%d\n", len,byteLen);

	if(byteLen-11 < len) return;

	dest[0] = 0x00;
	dest[1] = 0x02;

	for(int n = 0; n < byteLen - len - 3; n++) dest[n+2] = (rand() % 255) + 1;

	dest[byteLen - len-1] = 0x00;

	for(int n = 0; n < len; n++){
		dest[byteLen-len+n] = str[n];
	}

	//for(int n = 0; n < byteLen; n++)printf("%2.2X",dest[n]);
	//printf("\n");

	/*strncpy(dest,str,byteLen);
	if(strLen != byteLen) {
		for(int n = strLen; n < byteLen; n++) dest[n] = (rand() % 255) + 1;
		//for(int n = strLen; n < byteLen; n++) dest[n] = 0;
	}*/

	mpz_import(strNum,byteLen,1,1,0,0,dest);
	//gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->e,key->n);
	//gmp_printf("%ZX\n\n",strNum);

	mpz_export(dest,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);
}
void block_decrypt(unsigned char* dest, int* destLen, unsigned char* str, rsa_key_t* key) {
	int byteLen;
	mpz_t strNum;
	unsigned char* d;
	int p;

	mpz_init(strNum);

	byteLen = key->bitlen/8;
	d = malloc(byteLen);
	p = 0;

	mpz_import(strNum,byteLen,1,1,0,0,str);
	//gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->d,key->n);
	//gmp_printf("%ZX\n",strNum);
	mpz_export(d,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);

	while (d[p] != 0x00) p++;
	p++;

	for(int n = 0; n < byteLen; n++) dest[n] = 0;
	for(int n = 0; n < byteLen-p-1; n++){
		dest[n] = d[p+n];
	}

	*destLen = byteLen-p-1;
	
	//for(int n = 0; n < byteLen-p-1; n++)printf("%2.2X",(unsigned char)dest[n]);
	//printf("\n\n");


	free(d);
}

void rsa_sign(unsigned char* dest, unsigned char* hash, rsa_key_t* key){
	unsigned char digestPadding[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

	int byteLen;
	mpz_t strNum;

	byteLen = key->bitlen/8;

	mpz_init(strNum);

	dest[0] = 0x00;
	dest[1] = 0x01;

	for(int n = 0; n < byteLen - 54; n++) dest[n+2] = 0xFF;

	dest[byteLen-53] = 0x00;

	for(int n = 0; n < 19; n++) dest[byteLen-52+n] = digestPadding[n];
	for(int n = 0; n < 32; n++) dest[byteLen-33+n] = hash[n];

	mpz_import(strNum, byteLen,1,1,0,0,dest);
	//gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->d,key->n);
	//gmp_printf("%ZX\n\n",strNum);

	mpz_export(dest,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);

}

void rsa_verify(unsigned char* dest, unsigned char* src, int* errorFlag, rsa_key_t* key) {
	int byteLen;
	mpz_t strNum;
	unsigned char* d;
	int p;

	mpz_init(strNum);

	byteLen = key->bitlen/8;
	d = malloc(byteLen);
	p = 0;

	mpz_import(strNum,byteLen,1,1,0,0,src);
	//gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->e,key->n);
	//gmp_printf("%ZX\n",strNum);
	mpz_export(d,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);

	while (p < byteLen - 1 && d[p] != 0x20) p++;
	p++;

	if(p != 478) *errorFlag = 1;

	for(int n = 0; n < WORD_SIZE * HASH_SIZE; n++){
		dest[n] = d[p+n];
	}
	
	//for(int n = 0; n < byteLen-p-1; n++)printf("%2.2X",(unsigned char)dest[n]);
	//printf("\n\n");


	free(d);
}