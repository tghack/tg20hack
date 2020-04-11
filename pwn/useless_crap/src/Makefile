CC=gcc
CFLAGS=-Wall -Wextra
CFLAGS+=-Wl,-z,relro,-z,now
LDFLAGS=-Wl,--dynamic-linker=/usr/local/lib/ld-linux-x86-64.so.2

.PHONY: all clean

all: main

main: main.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lseccomp

main.lol: main.c
	$(CC) $(CFLAGS) -Wl,--dynamic-linker=./usr/local/lib/ld-linux-x86-64.so.2 $^ -o $@ -lseccomp


clean:
	rm -f main
