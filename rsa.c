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

rsa_key_t* rsa_make_keys(int bitlen){

	rsa_key_t *kFinal;
	int b1, b2;
	mpz_t p, q, n, l, e, d;
	gmp_randstate_t randState;

	gmp_randinit_default(randState);
	gmp_randseed_ui(randState,(unsigned long int)time(NULL));
	srand((unsigned int)time(NULL));

	mpz_inits(p,q,n,l,e,d,NULL);

	b1 = bitlen/2;
	b2 = bitlen - bitlen/2;

	while((!mpz_fdiv_ui(p,2)) 
		|| (!mpz_fdiv_ui(p,3)) 
		|| (!mpz_fdiv_ui(p,5)) 
		|| (!mpz_fdiv_ui(p,7))
		|| (!mpz_fdiv_ui(p,11))
		|| (!mpz_fdiv_ui(p,13))
		|| (!mpz_fdiv_ui(p,17))
		|| (!mpz_fdiv_ui(p,19))
		|| !miller_rabin(p,512)
		|| (mpz_fdiv_ui(q,E_CONST) == 1)){
		mpz_rrandomb(p,randState,b1);
	}

	while((!mpz_fdiv_ui(q,2)) 
		|| (!mpz_fdiv_ui(q,3)) 
		|| (!mpz_fdiv_ui(q,5)) 
		|| (!mpz_fdiv_ui(q,7))
		|| (!mpz_fdiv_ui(q,11))
		|| (!mpz_fdiv_ui(q,13))
		|| (!mpz_fdiv_ui(q,17))
		|| (!mpz_fdiv_ui(q,19))
		|| !miller_rabin(q,512)
		|| (mpz_fdiv_ui(q,E_CONST) == 1)){
		mpz_rrandomb(q,randState,b2);
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

void print_public_key(rsa_key_t* key){
	gmp_printf("Public key:\n%ZX\n",key->n);
}

void print_private_key(rsa_key_t* key){
	gmp_printf("Private key:\n%ZX\n",key->d);
}

void block_encrypt(unsigned char* dest, unsigned char* str, size_t blockLen, rsa_key_t* key){
	int strLen, byteLen;
	mpz_t strNum;
	srand(time(NULL));

	mpz_init(strNum);

	strLen = strlen(str) + 1;
	byteLen = key->bitlen/8;

	strncpy(dest,str,byteLen);
	if(strLen != byteLen) {
		//for(int n = strLen; n < byteLen; n++) dest[n] = (rand() % 255) + 1;
		for(int n = strLen; n < byteLen; n++) dest[n] = 0;
	} 

	mpz_import(strNum,byteLen,1,1,0,0,dest);
	gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->e,key->n);
	gmp_printf("%ZX\n",strNum);

	mpz_export(dest,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);

}
void block_decrypt(unsigned char* dest, unsigned char* str, size_t blockLen, rsa_key_t* key) {
	int byteLen;
	mpz_t strNum;

	mpz_init(strNum);

	byteLen = key->bitlen/8;

	mpz_import(strNum,byteLen,1,1,0,0,str);
	gmp_printf("%ZX\n",strNum);

	mpz_powm(strNum,strNum,key->d,key->n);
	gmp_printf("%ZX\n",strNum);

	mpz_export(dest,NULL,1,1,0,0,strNum);

	mpz_clear(strNum);
}

void free_key(rsa_key_t* key){
	mpz_clears(key->n, key->e, key->d, NULL);
	free(key);
}