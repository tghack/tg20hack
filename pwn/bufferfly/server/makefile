CC=gcc -m32
CFLAGS=-Wall -Wextra
CFLAGS+=-fno-stack-protector # disble stack cookies  ("f" instead of "fno-" to enable)
CFLAGS+=-pie -fPIE # enable PIE
CFLAGS+=-g


.PHONY: all, run, clean
all: bufferfly

bufferfly: bufferfly.c
	$(CC) $(CFLAGS) $^ -o $@

run: bufferfly
	./$^

clean:
	rm -vf bufferfly
