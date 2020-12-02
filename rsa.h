#ifndef RSA_H
#define RSA_H

#include <gmp.h>

typedef struct rsa_key_t {
	mpz_t n, e, d;
	int bitlen;
} rsa_key_t;

int miller_rabin(mpz_t n, int k);
void gcd(mpz_t rop, const mpz_t a, const mpz_t b);
void lcm(mpz_t rop, const mpz_t a, const mpz_t b);
void modinv(mpz_t rop, const mpz_t aInit, const mpz_t mInit);

rsa_key_t* rsa_make_keys(int bitlen);
void print_public_key(rsa_key_t* key);
void print_private_key(rsa_key_t* key);
void block_encrypt(unsigned char* dest, unsigned char* str, size_t blockLen, rsa_key_t* key);
void block_decrypt(unsigned char* dest, unsigned char* str, size_t blockLen, rsa_key_t* key);
void free_key(rsa_key_t* key);

#endif