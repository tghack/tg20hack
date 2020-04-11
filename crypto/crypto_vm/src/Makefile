CC = gcc
CCOPTS = -O3 -std=c18 -Wall -Wextra -fsanitize=address# -g

BIN = vm
ASSEMBLY = encrypt_flag.assembly
DUMMY_ASSEMBLY = dummy_encrypt_flag.assembly

.PHONY: all clean
all: $(BIN) $(ASSEMBLY).out $(DUMMY_ASSEMBLY).out

$(ASSEMBLY).out: $(ASSEMBLY)
	python3 ./assembler.py $<

$(DUMMY_ASSEMBLY).out: $(DUMMY_ASSEMBLY)
	python3 ./assembler.py $<

$(BIN): vm.o instructions.o engine.o
	$(CC) -o $@ $(CCOPTS) $^

%.o: %.c %.h
	$(CC) -c -o $@ $(CCOPTS) $<

clean:
	@rm -rfv $(BIN) $(ASSEMBLY).out $(DUMMY_ASSEMBLY).out *.o
