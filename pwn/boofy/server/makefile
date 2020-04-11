CC=gcc -m32
CFLAGS=-Wall -Wextra
CFLAGS+=-fno-stack-protector # disable stack cookies
CFLAGS+=-no-pie # disable randomising of addresses
CFLAGS+=-Wl,-z,norelro # disable RELRO (GOT is writeable)
CFLAGS+=-g

.PHONY: all, run, clean
all: boofy

flip: boofy.c
	$(CC) $(CFLAGS) $^ -o $@

run: boofy
	./$^

clean:
	rm -vf boofy
