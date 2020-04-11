CC=gcc
CFLAGS=-Wall -Wextra

.PHONY: all, run, clean
all: re_noob2

re_noob2: re_noob2.c
	$(CC) $(CFLAGS) $^ -o $@

run: re_noob2
	./$^

clean:
	rm -vf re_noob2
