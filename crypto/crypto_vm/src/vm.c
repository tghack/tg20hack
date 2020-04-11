#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "instructions.h"
#include "engine.h"
#include "vm.h"

/*
 * Fetch and decrypt next instruction using the previous instruction.
 */
void fetch(struct vm *vm)
{
	vm->instruction ^= fgetc(vm->f);
}

/*
 * Decode instruction and fetch potential arguments.
 */
void decode(struct vm *vm)
{
	switch (vm->instruction) {
		// No arguments
		case COMPILE_ENCRYPTION_ENGINE:
		case LOAD_ENCRYPTION_ENGINE:
		case GET_ENTROPY:
		case SET_SHIFTL_TMP:
		case SET_SHIFTR_TMP:
		case SET_XOR_TMP:
		case SET_ADD_TMP:
		case SET_SUB_TMP:
			break;
		// Register number for init data (1 arg)
		// ENCRYPT_DATA: Register number with memory address to plaintext and
		//               number of bytes ot encrypt (2 args)
		case ENCRYPT_DATA:
		case INIT_ENCRYPTION_ENGINE:
			vm->reg_num1 = fgetc(vm->f);
			break;
		// Registers number with memory address
		// to URL and DATA (2 args)
		case CONNECT_AND_SEND:
			vm->reg_num1 = fgetc(vm->f);
			vm->reg_num2 = fgetc(vm->f);
			break;
		// LOAD_DATA: Register number to load data to, number of bytes to load
		//            and the actual bytes following directly (3 args)
		case LOAD_DATA:
			vm->reg_num1 = fgetc(vm->f);
			/* FALLTHRU */
		// Only read the argument immediate value (1 arg)
		case SET_SHIFTL_SET_TMP:
		case SET_SHIFTR_SET_TMP:
		case SET_XOR_SET_TMP:
		case SET_ADD_SET_TMP:
		case SET_SUB_SET_TMP:
		case SET_SHIFTL:
		case SET_SHIFTR:
		case SET_XOR:
		case SET_ADD:
		case SET_SUB:
			fread(&vm->imm_val, sizeof(vm->imm_val), 1, vm->f);
			break;
		default:
			break;
	}
}

/*
 * Execute instruction.
 */
void execute(struct vm *vm)
{
	switch (vm->instruction) {
		case COMPILE_ENCRYPTION_ENGINE:
			compile_encryption_engine(vm->engine);
			break;
		case LOAD_ENCRYPTION_ENGINE:
			load_encryption_engine(&vm->engine);
			break;
		// Register number for init data (1 arg)
		case INIT_ENCRYPTION_ENGINE:
			init_encryption_engine(vm->engine, vm->regs[vm->reg_num1]);
			break;
		// Registers number with memory address
		// to URL and DATA (2 args)
		case CONNECT_AND_SEND:
			connect_and_send((const char*)vm->regs[vm->reg_num1],
					 (const char*)vm->regs[vm->reg_num2]);
			break;
		// Register number with memory address to plaintext and
		// number of bytes ot encrypt (2 args)
		case ENCRYPT_DATA:
			encrypt_data(vm->engine, vm->regs[vm->reg_num1]);
			break;
		// Register number to load data to, number of bytes to load
		// and the actual bytes following directly (3 args)
		case LOAD_DATA:
			load_data(vm->f, vm->regs[vm->reg_num1], vm->imm_val);
			break;
		case GET_ENTROPY:
			get_entropy(vm->entropy);
			break;
		case SET_SHIFTL_SET_TMP:
			set_shiftl_set_tmp(vm->engine, vm->imm_val);
			break;
		case SET_SHIFTR_SET_TMP:
			set_shiftr_set_tmp(vm->engine, vm->imm_val);
			break;
		case SET_XOR_SET_TMP:
			set_xor_set_tmp(vm->engine, vm->imm_val);
			break;
		case SET_ADD_SET_TMP:
			set_add_set_tmp(vm->engine, vm->imm_val);
			break;
		case SET_SUB_SET_TMP:
			set_sub_set_tmp(vm->engine, vm->imm_val);
			break;
		case SET_SHIFTL_TMP:
			set_shiftl_tmp(vm->engine);
			break;
		case SET_SHIFTR_TMP:
			set_shiftr_tmp(vm->engine);
			break;
		case SET_XOR_TMP:
			set_xor_tmp(vm->engine);
			break;
		case SET_ADD_TMP:
			set_add_tmp(vm->engine);
			break;
		case SET_SUB_TMP:
			set_sub_tmp(vm->engine);
			break;
		case SET_SHIFTL:
			set_shiftl(vm->engine, vm->imm_val);
			break;
		case SET_SHIFTR:
			set_shiftr(vm->engine, vm->imm_val);
			break;
		case SET_XOR:
			set_xor(vm->engine, vm->imm_val);
			break;
		case SET_ADD:
			set_add(vm->engine, vm->imm_val);
			break;
		case SET_SUB:
			set_sub(vm->engine, vm->imm_val);
			break;
		case VM_STOP:
			vm->should_continue = false;
			break;
		case ILLEGAL_START_ONLY:
			// This is a NO-OP
			break;
		default:
			printf("WARN: Unknown instruction: %02x\n", vm->instruction);
			break;
	}
	vm->cycles++;
}

struct vm *vm_new(const char *bytecode)
{
	struct vm *vm = calloc(sizeof(*vm), 1);
	uint8_t magic[6] = {'C','R','Y','P','T','O'};
	uint8_t file_magic[6] = { 0 };

	vm->f = fopen(bytecode, "rb");
	fread(file_magic, sizeof(file_magic), 1, vm->f);
	if (memcmp(file_magic, magic, sizeof(magic)) != 0) {
		free(vm);
		return NULL;
	}

	vm->imm_val = 0;
	vm->reg_num1 = 0;
	vm->reg_num2 = 0;
	vm->engine = NULL;
	// Allocate all register pointers
	for (size_t i = 0; i < UINT8_MAX; i++) {
		vm->regs[i] = calloc(128, 1);
	}
	vm->entropy = vm->regs[0];
	vm->should_continue = true;
	vm->instruction = 0;
	vm->cycles = 0;

	return vm;
}

void vm_del(struct vm *vm)
{
	for (size_t i = 0; i < UINT8_MAX; i++) {
		free(vm->regs[i]);
	}
	engine_del(vm->engine);
	fclose(vm->f);
	free(vm);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s <bytecode>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	struct vm *vm = vm_new(argv[1]);
	if (vm == NULL) {
		printf("Unable to verify magic signature in file \"%s\".\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	// VM main loop
	while (vm->should_continue) {
		fetch(vm);
		decode(vm);
		execute(vm);
	}
	printf("CYCLE COUNT:\n\tVM:\t%3zu\n\tEngine:\t%3zu\n",
			vm->cycles, vm->engine->cycles);
	vm_del(vm);

	return 0;
}
