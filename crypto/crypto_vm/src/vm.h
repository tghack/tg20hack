#ifndef VM_H
#define VM_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "instructions.h"

struct vm {
	FILE *f;
	struct engine *engine;
	size_t imm_val;
	uint8_t reg_num1;
	uint8_t reg_num2;
	uint8_t *entropy;
	uint8_t *regs[256];
	bool should_continue;
	enum instruction instruction;
	size_t cycles;
};
#endif // VM_H
