CC = gcc

all: genKeys rsa_encrypt rsa_decrypt rsa_sign rsa_verify

genKeys: genKeys.o rsa.o
	$(CC) -o generate_keys genKeys.o rsa.o -lm -lgmp

rsa_encrypt: rsa_encrypt.o rsa.o
	$(CC) -o rsa_encrypt rsa_encrypt.o rsa.o -lm -lgmp

rsa_decrypt: rsa_decrypt.o rsa.o
	$(CC) -o rsa_decrypt rsa_decrypt.o rsa.o -lm -lgmp

rsa_sign: rsa_sign.o rsa.o SHA256.o
	$(CC) -o rsa_sign rsa_sign.o rsa.o SHA256.o -lm -lgmp

rsa_verify: rsa_verify.o rsa.o SHA256.o
	$(CC) -o rsa_verify rsa_verify.o rsa.o SHA256.o -lm -lgmp

genKeys.o: genKeys.c rsa.h
	$(CC) -c genKeys.c -lm -lgmp

rsa_encrypt.o: rsa_encrypt.c rsa.h
	$(CC) -c rsa_encrypt.c -lm -lgmp

rsa_decrypt.o: rsa_decrypt.c rsa.h
	$(CC) -c rsa_decrypt.c -lm -lgmp

rsa_sign.o: rsa_sign.c rsa.h
	$(CC) -c rsa_sign.c -lm -lgmp

rsa_verify.o: rsa_verify.c rsa.h
	$(CC) -c rsa_verify.c -lm -lgmp

rsa.o: rsa.c rsa.h
	$(CC) -c rsa.c -lm -lgmp

SHA256.o: SHA256.c rsa.h
	$(CC) -c SHA256.c -lm

clean:
	rm *.o