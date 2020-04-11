CC = g++
CCOPTS = -O3 -Wall -Wextra -std=c++17 -g -fsanitize=address
CCLIBS = -lstdc++fs `pkg-config --cflags --libs libcrypto++`

BIN = ransom_decryptor

.PHONY: all clean
all: $(BIN)

$(BIN): $(BIN).o key_gen.o
	$(CC) -o $@ $(CCOPTS) $^ $(CCLIBS)

%.o: %.cpp
	$(CC) -c -o $@ $(CCOPTS) $<

clean:
	@rm -rfv $(BIN) *.o
