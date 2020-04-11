CC=gcc
CFLAGS=-Wall -Wextra -static

.PHONY: all, run, clean
all: re_noob3

re_noob3: re_noob3.c
	$(CC) $(CFLAGS) $^ -o $@

run: re_noob3
	./$^

clean:
	rm -vf re_noob3
