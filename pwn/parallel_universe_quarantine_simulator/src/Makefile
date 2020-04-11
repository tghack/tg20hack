CC=clang-8
CFLAGS=-Wall -Wextra -O1 -fPIC -pie

.PHONY: all clean

all: quarantine quarantine32

quarantine: quarantine.c
	$(CC) $(CFLAGS) $^ -o $@

quarantine32: quarantine.c
	$(CC) $(CFLAGS) -m32 $^ -o $@

clean:
	rm -f quarantine quarantine32
