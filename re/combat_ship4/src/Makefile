CC=gcc
CFLAGS=-Wall -Wextra

.PHONY: all, run, clean
all: re_noob4

re_noob4: re_noob4.c
	$(CC) $(CFLAGS) $^ -o $@

run: re_noob4
	./$^

clean:
	rm -vf re_noob4

