CC = g++
CCOPTS = -O3 -Wall -Wextra -std=c++17
CCLIBS = -lstdc++fs `pkg-config --cflags --libs libcrypto++` `curl-config --cflags --libs`

BIN = ransomware

.PHONY: all clean
all: $(BIN)

$(BIN): ransomware.o key_gen.o
	$(CC) -o $@ $(CCOPTS) $^ $(CCLIBS)

%.o: %.cpp
	$(CC) -c -o $@ $(CCOPTS) $<

clean:
	@rm -rfv $(BIN) *.o
