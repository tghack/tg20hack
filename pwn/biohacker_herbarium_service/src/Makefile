CC=gcc
CFLAGS=-Wall -Wextra

all: chall

chall: main.c
	$(CC) $(CFLAGS) $^ -o $@

run: chall
	./$^

clean:
	rm -f chall
