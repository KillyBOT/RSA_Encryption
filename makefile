CC = gcc

all: genKeys rsa_encrypt rsa_decrypt

genKeys: genKeys.o rsa.o
	$(CC) -o generate_keys genKeys.o rsa.o -lm -lgmp

rsa_encrypt: rsa_encrypt.o rsa.o
	$(CC) -o rsa_encrypt rsa_encrypt.o rsa.o -lm -lgmp

rsa_decrypt: rsa_decrypt.o rsa.o
	$(CC) -o rsa_decrypt rsa_decrypt.o rsa.o -lm -lgmp

genKeys.o: genKeys.c rsa.h
	$(CC) -c genKeys.c -lm -lgmp

rsa_encrypt.o: rsa_encrypt.c rsa.h
	$(CC) -c rsa_encrypt.c -lm -lgmp

rsa_decrypt.o: rsa_decrypt.c rsa.h
	$(CC) -c rsa_decrypt.c -lm -lgmp

rsa.o: rsa.c rsa.h
	$(CC) -c rsa.c -lm -lgmp

run:
	./RSA

clean:
	rm *.o