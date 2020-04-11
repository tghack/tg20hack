CC = g++
CCOPTS = -Wall -Wextra -std=c++17
CCLIBS = -lstdc++fs `pkg-config --cflags --libs libcrypto++`

BIN = ransom_decryptor

.PHONY: all clean
all: $(BIN)

$(BIN): $(BIN).o
	$(CC) -o $@ $(CCOPTS) $^ $(CCLIBS)

%.o: %.cpp
	$(CC) -c -o $@ $(CCOPTS) $<

clean:
	@rm -rfv $(BIN) *.o
