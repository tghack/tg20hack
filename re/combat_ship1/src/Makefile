CC=gcc
CFLAGS=-Wall -Wextra

.PHONY: all, run, clean
all: re_noob1

re_noob1: re_noob1.c
	$(CC) $(CFLAGS) $^ -o $@

run: re_noob1
	./$^

clean:
	rm -vf re_noob1
