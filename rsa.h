#ifndef RSA_H
#define RSA_H

#include <gmp.h>

#define MSG_SIZE 4096
#define MESSAGE_SIZE 16
#define BLOCK_SIZE 64
#define HASH_SIZE 8
#define WORD_SIZE 4

typedef struct rsa_key_t {
	mpz_t n, e, d;
	int bitlen;
} rsa_key_t;

int miller_rabin(mpz_t n, int k);
void gcd(mpz_t rop, const mpz_t a, const mpz_t b);
void lcm(mpz_t rop, const mpz_t a, const mpz_t b);
void modinv(mpz_t rop, const mpz_t aInit, const mpz_t mInit);
int compare_hashes(unsigned char* h1, unsigned char* h2);

rsa_key_t* rsa_make_keys(int bitlen);
void print_key_ned(rsa_key_t* key);
void print_public_key(rsa_key_t* key);
void print_private_key(rsa_key_t* key);
void free_key(rsa_key_t* key);

void rsa_save_key(rsa_key_t* key, char* filename);
void rsa_read_public_key(rsa_key_t* key, char* filename);
void rsa_read_private_key(rsa_key_t* key, char* filename);

void block_encrypt(unsigned char* dest, unsigned char* str, size_t len, rsa_key_t* key);
void block_decrypt(unsigned char* dest, int* destLen, unsigned char* str, rsa_key_t* key);
void rsa_sign(unsigned char* dest, unsigned char* hash, rsa_key_t* key);
void rsa_verify(unsigned char* dest, unsigned char* src, int* errorFlag, rsa_key_t* key);

//For SHA256

typedef int word;

char* getWordBits(word w);
void printMessage(word* message);

word rotateRight(word input, int amount);
//I might work on this later, but I'm not sure
//word fracCubeRoot(word n);
void fixMessage(word* message, int size, int endPlaceWord, int endPlaceChar);
word flipBytes(word toFlip);
unsigned char getByte(word w, int p);

word Ch(word x, word y, word z);
word Maj(word x, word y, word z);
word sigma0(word x);
word sigma1(word x);
word sigmoid0(word x);
word sigmoid1(word x);

void SHA256_init_hash(word* hash);
void SHA256_message(word* hash, word* msg);
void SHA256_byte(unsigned char* dest, FILE* f);
void SHA256_string(char* dest, char* src);
void SHA256_file(char* dest, FILE* f);
#endif