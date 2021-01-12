CC=gcc
CFLAGS=-c -Wall
OFLAGS=-o2 -o

all: AES_TEST

AES_TEST: utils.o aes_test.o
	$(CC)  $^ $(OFLAGS) $@

aes_test.o: aes_test.c
	$(CC) $(CFLAGS) $^ $(OFLAGS) $@

utils.o: utils.c
	$(CC) $(CFLAGS) $^ $(OFLAGS) $@

clean:
	rm -vf ./*.o ./*.out
