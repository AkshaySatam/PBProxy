CC=gcc

hellomake: pbproxy.o
	$(CC) -o pbproxy pbproxy.c -lm -lcrypto -lssl -lpthread

