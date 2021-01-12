CC=gcc
CFLAGS=-c -Wall
OFLAGS=-o2 -o

all: AES_TEST

AES_TEST: utils.o exercise1.o
	$(CC)  $^ $(OFLAGS) $@

exercise1.o: exercise1.c
	$(CC) $(CFLAGS) $^ $(OFLAGS) $@

utils.o: utils.c
	$(CC) $(CFLAGS) $^ $(OFLAGS) $@

clean:
	rm -vf ./*.o ./*.out
