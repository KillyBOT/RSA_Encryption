cc = gcc

all: main.o rsa.o
	$(CC) -o RSA main.o rsa.o -lm -lgmp

main.o: main.c rsa.h
	$(CC) -c main.c -lm -lgmp

rsa.o: rsa.c rsa.h
	$(CC) -c rsa.c -lm -lgmp